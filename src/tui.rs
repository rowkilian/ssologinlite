use anyhow::{anyhow, Result};
use chrono::Local;
use crossterm::event::{
    self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEvent, KeyEventKind,
    KeyModifiers,
};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ini::Ini;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::{Frame, Terminal};
use std::io::{self, BufRead, BufReader, Stdout};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use crate::aws_profile::{AssumeSsoProfile, Profile, Profiles, SsoProfile};
use crate::config::ProgramConfig;
use crate::constants::{CONFIG_FILE, PROFILES, PROGRAM_FOLDER};
use crate::file_helper::{
    get_aws_config, get_exe_path, get_home_os_string, restrict_file_permissions,
};

type Term = Terminal<CrosstermBackend<Stdout>>;

const SSO_FIELD_LABELS: [&str; 7] = [
    "Profile name",
    "SSO start URL",
    "SSO region",
    "SSO account ID",
    "SSO role name",
    "Default region",
    "Duration (sec)",
];

const ASSUME_FIELD_LABELS: [&str; 4] = ["Profile name", "Source profile", "Role ARN", "Region"];

#[derive(Clone, Copy, PartialEq, Eq)]
enum ProfileKind {
    Sso,
    AssumeSso,
}

impl ProfileKind {
    fn label(self) -> &'static str {
        match self {
            ProfileKind::Sso => "SSO",
            ProfileKind::AssumeSso => "Assume Role",
        }
    }
    fn toggle(self) -> Self {
        match self {
            ProfileKind::Sso => ProfileKind::AssumeSso,
            ProfileKind::AssumeSso => ProfileKind::Sso,
        }
    }
}

enum NewProfile {
    Sso(SsoProfile),
    Assume(AssumeSsoProfile),
}

impl NewProfile {
    fn name(&self) -> &str {
        match self {
            NewProfile::Sso(p) => &p.profile_name,
            NewProfile::Assume(p) => &p.profile_name,
        }
    }
    fn into_profile(self) -> Profile {
        match self {
            NewProfile::Sso(p) => Profile::SsoProfile(p),
            NewProfile::Assume(p) => Profile::AssumeSsoProfile(p),
        }
    }
}

// Form layout: focused == 0 is the type toggle; focused 1..=N indexes the
// active kind's field array. SSO and assume-role values are kept in
// independent buffers so flipping the type back and forth doesn't lose
// what the user has already typed.
// Index into ASSUME_FIELD_LABELS for the source-profile slot. The slot is
// rendered as a picker over existing SSO profiles rather than a free-text
// input — an Assume Role profile chains off an SSO profile, so the source
// must already exist in profiles.json.
const ASSUME_SOURCE_FIELD: usize = 1;

#[derive(Clone)]
enum FormMode {
    Add,
    // original_name is the profile's key in profiles.json at the moment the
    // edit form was opened. It can differ from the form's current "Profile
    // name" field if the user is renaming, in which case save_form removes
    // the old entry from profiles.json and ~/.aws/config.
    Edit { original_name: String },
}

impl FormMode {
    fn is_edit(&self) -> bool {
        matches!(self, FormMode::Edit { .. })
    }
}

struct AddForm {
    mode: FormMode,
    kind: ProfileKind,
    sso_values: [String; 7],
    assume_values: [String; 4],
    focused: usize,
    available_sources: Vec<String>,
}

impl AddForm {
    fn new(available_sources: Vec<String>) -> Self {
        let mut assume_values: [String; 4] = Default::default();
        if let Some(first) = available_sources.first() {
            assume_values[ASSUME_SOURCE_FIELD] = first.clone();
        }
        AddForm {
            mode: FormMode::Add,
            kind: ProfileKind::Sso,
            sso_values: Default::default(),
            assume_values,
            focused: 0,
            available_sources,
        }
    }

    // Build a pre-populated form from an existing profile. Returns None for
    // OtherProfile because we have no fields to edit on that variant.
    fn new_for_edit(
        profile: &Profile,
        original_name: &str,
        available_sources: Vec<String>,
    ) -> Option<Self> {
        let (kind, sso_values, assume_values) = match profile {
            Profile::SsoProfile(p) => {
                let values: [String; 7] = [
                    p.profile_name.clone(),
                    p.sso_start_url.clone(),
                    p.sso_region.clone(),
                    p.sso_account_id.clone(),
                    p.sso_role_name.clone(),
                    p.region.clone().unwrap_or_default(),
                    p.duration_seconds
                        .map(|d| d.to_string())
                        .unwrap_or_default(),
                ];
                (ProfileKind::Sso, values, Default::default())
            }
            Profile::AssumeSsoProfile(p) => {
                let values: [String; 4] = [
                    p.profile_name.clone(),
                    p.source_profile.clone(),
                    p.role_arn.clone(),
                    p.region.clone(),
                ];
                (ProfileKind::AssumeSso, Default::default(), values)
            }
            Profile::OtherProfile => return None,
        };
        Some(AddForm {
            mode: FormMode::Edit {
                original_name: original_name.to_string(),
            },
            kind,
            sso_values,
            assume_values,
            // Skip past the (locked) type slot and land on the first editable
            // field so the user can start typing immediately.
            focused: 1,
            available_sources,
        })
    }

    fn field_labels(&self) -> &'static [&'static str] {
        match self.kind {
            ProfileKind::Sso => &SSO_FIELD_LABELS,
            ProfileKind::AssumeSso => &ASSUME_FIELD_LABELS,
        }
    }

    fn slots(&self) -> usize {
        // 1 type toggle + N field slots
        self.field_labels().len() + 1
    }

    fn next(&mut self) {
        self.focused = (self.focused + 1) % self.slots();
    }

    fn prev(&mut self) {
        self.focused = (self.focused + self.slots() - 1) % self.slots();
    }

    fn focused_field_index(&self) -> Option<usize> {
        if self.focused == 0 {
            None
        } else {
            Some(self.focused - 1)
        }
    }

    fn focused_field_value(&self, i: usize) -> &str {
        match self.kind {
            ProfileKind::Sso => &self.sso_values[i],
            ProfileKind::AssumeSso => &self.assume_values[i],
        }
    }

    fn focused_field_mut(&mut self) -> Option<&mut String> {
        let i = self.focused_field_index()?;
        // The Assume-Role source slot is a picker, not a free-text input —
        // refuse mutable access so Char/Backspace handlers can't corrupt it.
        if self.is_source_picker_focused() {
            return None;
        }
        match self.kind {
            ProfileKind::Sso => self.sso_values.get_mut(i),
            ProfileKind::AssumeSso => self.assume_values.get_mut(i),
        }
    }

    fn is_source_picker_focused(&self) -> bool {
        self.kind == ProfileKind::AssumeSso && self.focused == ASSUME_SOURCE_FIELD + 1
    }

    fn cycle_source(&mut self, forward: bool) {
        if self.available_sources.is_empty() {
            return;
        }
        let n = self.available_sources.len();
        let current = &self.assume_values[ASSUME_SOURCE_FIELD];
        let current_idx = self
            .available_sources
            .iter()
            .position(|s| s == current)
            .unwrap_or(0);
        let new_idx = if forward {
            (current_idx + 1) % n
        } else {
            (current_idx + n - 1) % n
        };
        self.assume_values[ASSUME_SOURCE_FIELD] = self.available_sources[new_idx].clone();
    }

    fn toggle_kind(&mut self) {
        // Switching type on an existing profile would change the field set
        // out from under the user and the on-disk record — disallow it. To
        // change type, delete and re-add.
        if self.mode.is_edit() {
            return;
        }
        self.kind = self.kind.toggle();
        // Stay parked on the type slot after a toggle so the user sees the
        // change before stepping into the now-different field list.
        self.focused = 0;
    }

    fn validate(&self) -> Result<NewProfile> {
        match self.kind {
            ProfileKind::Sso => self.validate_sso().map(NewProfile::Sso),
            ProfileKind::AssumeSso => self.validate_assume().map(NewProfile::Assume),
        }
    }

    fn validate_sso(&self) -> Result<SsoProfile> {
        let name = self.sso_values[0].trim();
        let url = self.sso_values[1].trim();
        let sso_region = self.sso_values[2].trim();
        let account = self.sso_values[3].trim();
        let role = self.sso_values[4].trim();
        let region = self.sso_values[5].trim();
        let duration = self.sso_values[6].trim();

        if name.is_empty() {
            return Err(anyhow!("Profile name is required"));
        }
        if url.is_empty() {
            return Err(anyhow!("SSO start URL is required"));
        }
        if sso_region.is_empty() {
            return Err(anyhow!("SSO region is required"));
        }
        if account.chars().count() != 12 || !account.chars().all(|c| c.is_ascii_digit()) {
            return Err(anyhow!("Account ID must be 12 digits"));
        }
        if role.is_empty() {
            return Err(anyhow!("Role name is required"));
        }
        let duration_seconds = if duration.is_empty() {
            None
        } else {
            Some(
                duration
                    .parse::<u16>()
                    .map_err(|_| anyhow!("Duration must be a positive integer"))?,
            )
        };

        Ok(SsoProfile {
            profile_name: name.to_string(),
            sso_start_url: url.to_string(),
            sso_region: sso_region.to_string(),
            sso_account_id: account.to_string(),
            sso_role_name: role.to_string(),
            region: if region.is_empty() {
                None
            } else {
                Some(region.to_string())
            },
            duration_seconds,
        })
    }

    fn validate_assume(&self) -> Result<AssumeSsoProfile> {
        let name = self.assume_values[0].trim();
        let source = self.assume_values[ASSUME_SOURCE_FIELD].trim();
        let arn = self.assume_values[2].trim();
        let region = self.assume_values[3].trim();

        if name.is_empty() {
            return Err(anyhow!("Profile name is required"));
        }
        if self.available_sources.is_empty() {
            return Err(anyhow!(
                "no SSO profiles to assume from — add an SSO profile first"
            ));
        }
        if !self.available_sources.iter().any(|s| s == source) {
            return Err(anyhow!(
                "source profile must be one of the existing SSO profiles"
            ));
        }
        if arn.is_empty() {
            return Err(anyhow!("Role ARN is required"));
        }
        if !arn.starts_with("arn:aws:iam::") {
            return Err(anyhow!("Role ARN must start with 'arn:aws:iam::'"));
        }
        if region.is_empty() {
            return Err(anyhow!("Region is required"));
        }

        Ok(AssumeSsoProfile {
            profile_name: name.to_string(),
            source_profile: source.to_string(),
            role_arn: arn.to_string(),
            region: region.to_string(),
        })
    }
}

enum Screen {
    List,
    Detail,
    Add,
    Config(ConfigForm),
    Test(TestRun),
}

const CONFIG_FIELD_LABELS: [&str; 2] = ["browser", "default_sso_url"];

// Edits the persistent program config at ~/.config/ssologinlite.toml. The
// file has two optional string keys (browser, default_sso_url); we treat an
// empty input string as Option::None on save.
struct ConfigForm {
    fields: [String; 2],
    focused: usize,
    error: Option<String>,
}

impl ConfigForm {
    fn from_disk() -> Self {
        let loaded = read_program_config_toml().unwrap_or_default();
        ConfigForm {
            fields: [
                loaded.browser.unwrap_or_default(),
                loaded.default_sso_url.unwrap_or_default(),
            ],
            focused: 0,
            error: None,
        }
    }

    fn next(&mut self) {
        self.focused = (self.focused + 1) % CONFIG_FIELD_LABELS.len();
    }

    fn prev(&mut self) {
        self.focused = (self.focused + CONFIG_FIELD_LABELS.len() - 1) % CONFIG_FIELD_LABELS.len();
    }

    fn focused_mut(&mut self) -> &mut String {
        &mut self.fields[self.focused]
    }

    fn to_program_config(&self) -> ProgramConfig {
        let some_or_none = |s: &str| -> Option<String> {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        };
        ProgramConfig {
            browser: some_or_none(&self.fields[0]),
            default_sso_url: some_or_none(&self.fields[1]),
        }
    }
}

// Output from the spawned `aws sts get-caller-identity` subprocess. Reader
// threads forward each line over a channel; the main loop drains the channel
// each frame and appends to TestRun.output so the user sees streaming output
// inside the TUI.
enum TestEvent {
    Stdout(String),
    Stderr(String),
}

struct TestRun {
    profile_name: String,
    output: String,
    finished: Option<bool>,
    rx: mpsc::Receiver<TestEvent>,
    // Held so we can poll exit status with try_wait() and kill on cancel.
    // Cleared once the child has exited.
    child: Option<Child>,
    started_at: std::time::Instant,
}

struct App {
    profiles: Profiles,
    profile_names: Vec<String>,
    list_state: ListState,
    screen: Screen,
    form: AddForm,
    status: Option<(String, bool)>,
}

impl App {
    fn new() -> Self {
        let mut app = App {
            profiles: Profiles::default(),
            profile_names: Vec::new(),
            list_state: ListState::default(),
            screen: Screen::List,
            form: AddForm::new(Vec::new()),
            status: None,
        };
        app.refresh();
        app
    }

    fn refresh(&mut self) {
        self.profiles = Profiles::from_file().unwrap_or_default();
        self.profile_names = self.profiles.profiles.keys().cloned().collect();
        self.profile_names.sort();
        let n = self.profile_names.len();
        match self.list_state.selected() {
            None if n > 0 => self.list_state.select(Some(0)),
            Some(i) if i >= n => self
                .list_state
                .select(if n == 0 { None } else { Some(n - 1) }),
            _ => {}
        }
    }

    fn sso_profile_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .profiles
            .profiles
            .iter()
            .filter_map(|(name, p)| match p {
                Profile::SsoProfile(_) => Some(name.clone()),
                _ => None,
            })
            .collect();
        names.sort();
        names
    }

    fn selected_name(&self) -> Option<String> {
        let i = self.list_state.selected()?;
        self.profile_names.get(i).cloned()
    }

    fn selected_profile(&self) -> Option<&Profile> {
        let name = self.profile_names.get(self.list_state.selected()?)?;
        self.profiles.profiles.get(name)
    }

    fn handle_key(&mut self, key: KeyEvent) -> Result<bool> {
        if key.kind != KeyEventKind::Press {
            return Ok(false);
        }
        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            return Ok(true);
        }
        // Status messages clear on the next key press from the same screen, except
        // in the Add form where validation errors should persist until corrected.
        if !matches!(self.screen, Screen::Add) {
            self.status = None;
        }
        match self.screen {
            Screen::List => self.handle_list(key),
            Screen::Detail => self.handle_detail(key),
            Screen::Add => self.handle_add(key),
            Screen::Config(_) => self.handle_config(key),
            Screen::Test(_) => self.handle_test(key),
        }
    }

    fn handle_list(&mut self, key: KeyEvent) -> Result<bool> {
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => return Ok(true),
            KeyCode::Down | KeyCode::Char('j') => {
                if let Some(i) = self.list_state.selected() {
                    if i + 1 < self.profile_names.len() {
                        self.list_state.select(Some(i + 1));
                    }
                }
            }
            KeyCode::Up | KeyCode::Char('k') => {
                if let Some(i) = self.list_state.selected() {
                    if i > 0 {
                        self.list_state.select(Some(i - 1));
                    }
                }
            }
            KeyCode::Enter => {
                if self.selected_profile().is_some() {
                    self.screen = Screen::Detail;
                }
            }
            KeyCode::Char('a') => {
                self.form = AddForm::new(self.sso_profile_names());
                self.status = None;
                self.screen = Screen::Add;
            }
            KeyCode::Char('e') => {
                self.start_edit_selected();
            }
            KeyCode::Char('c') => {
                self.screen = Screen::Config(ConfigForm::from_disk());
                self.status = None;
            }
            KeyCode::Char('x') => match export_aws_config(&self.profiles) {
                Ok(path) => {
                    self.status = Some((format!("exported to {}", path.display()), false));
                }
                Err(e) => {
                    self.status = Some((format!("export failed: {e}"), true));
                }
            },
            KeyCode::Char('r') => {
                self.refresh();
                self.status = Some(("refreshed".to_string(), false));
            }
            KeyCode::Char('t') => {
                if let Some(name) = self.selected_name() {
                    self.run_test(&name);
                }
            }
            _ => {}
        }
        Ok(false)
    }

    fn handle_detail(&mut self, key: KeyEvent) -> Result<bool> {
        match key.code {
            KeyCode::Char('q') => return Ok(true),
            KeyCode::Esc => self.screen = Screen::List,
            KeyCode::Char('t') => {
                if let Some(name) = self.selected_name() {
                    self.run_test(&name);
                }
            }
            KeyCode::Char('e') => {
                self.start_edit_selected();
            }
            _ => {}
        }
        Ok(false)
    }

    fn start_edit_selected(&mut self) {
        let Some(name) = self.selected_name() else {
            return;
        };
        // Sources for the picker exclude the profile being edited so an
        // assume-role profile can't accidentally pick itself as its own
        // source mid-rename.
        let sources: Vec<String> = self
            .sso_profile_names()
            .into_iter()
            .filter(|n| n != &name)
            .collect();
        let Some(profile) = self.profiles.profiles.get(&name) else {
            return;
        };
        match AddForm::new_for_edit(profile, &name, sources) {
            Some(form) => {
                self.form = form;
                self.status = None;
                self.screen = Screen::Add;
            }
            None => {
                self.status = Some((
                    format!("'{name}' is an unknown profile type — cannot edit"),
                    true,
                ));
            }
        }
    }

    fn handle_add(&mut self, key: KeyEvent) -> Result<bool> {
        match key.code {
            KeyCode::Esc => {
                self.status = None;
                self.screen = Screen::List;
            }
            KeyCode::Tab | KeyCode::Down => self.form.next(),
            KeyCode::BackTab | KeyCode::Up => self.form.prev(),
            KeyCode::Left => {
                if self.form.focused == 0 {
                    self.form.toggle_kind();
                } else if self.form.is_source_picker_focused() {
                    self.form.cycle_source(false);
                }
            }
            KeyCode::Right => {
                if self.form.focused == 0 {
                    self.form.toggle_kind();
                } else if self.form.is_source_picker_focused() {
                    self.form.cycle_source(true);
                }
            }
            KeyCode::Backspace => {
                if let Some(field) = self.form.focused_field_mut() {
                    field.pop();
                }
            }
            KeyCode::Enter => {
                let was_edit = self.form.mode.is_edit();
                match self.save_form() {
                    Ok(name) => {
                        self.refresh();
                        if let Some(i) = self.profile_names.iter().position(|n| n == &name) {
                            self.list_state.select(Some(i));
                        }
                        let verb = if was_edit { "updated" } else { "saved" };
                        self.status = Some((
                            format!("{verb} profile '{name}' — press 't' to test it"),
                            false,
                        ));
                        self.screen = Screen::List;
                    }
                    Err(e) => {
                        self.status = Some((format!("{e}"), true));
                    }
                }
            }
            KeyCode::Char(' ') if self.form.focused == 0 => self.form.toggle_kind(),
            KeyCode::Char(' ') if self.form.is_source_picker_focused() => {
                self.form.cycle_source(true);
            }
            KeyCode::Char(c) => {
                if let Some(field) = self.form.focused_field_mut() {
                    field.push(c);
                }
            }
            _ => {}
        }
        Ok(false)
    }

    fn handle_config(&mut self, key: KeyEvent) -> Result<bool> {
        let Screen::Config(form) = &mut self.screen else {
            return Ok(false);
        };
        match key.code {
            KeyCode::Esc => {
                self.screen = Screen::List;
            }
            KeyCode::Tab | KeyCode::Down => form.next(),
            KeyCode::BackTab | KeyCode::Up => form.prev(),
            KeyCode::Backspace => {
                form.focused_mut().pop();
            }
            KeyCode::Enter => {
                let cfg = form.to_program_config();
                match write_program_config_toml(&cfg) {
                    Ok(()) => {
                        self.status = Some((
                            "config saved to ~/.config/ssologinlite.toml".to_string(),
                            false,
                        ));
                        self.screen = Screen::List;
                    }
                    Err(e) => {
                        form.error = Some(format!("{e}"));
                    }
                }
            }
            KeyCode::Char(c) => {
                form.focused_mut().push(c);
            }
            _ => {}
        }
        Ok(false)
    }

    fn handle_test(&mut self, key: KeyEvent) -> Result<bool> {
        let running = matches!(&self.screen, Screen::Test(r) if r.finished.is_none());
        match key.code {
            KeyCode::Char('q') if !running => return Ok(true),
            KeyCode::Esc => {
                // While the subprocess is still running, kill it before
                // navigating away. Reader threads will exit naturally as the
                // pipes close.
                if let Screen::Test(run) = &mut self.screen {
                    if let Some(child) = run.child.as_mut() {
                        let _ = child.kill();
                    }
                }
                self.screen = Screen::List;
            }
            KeyCode::Enter if !running => self.screen = Screen::List,
            _ => {}
        }
        Ok(false)
    }

    // Drain any subprocess output produced since the last frame and check
    // whether the child has exited. Called from the main loop on every tick
    // when a test is running so the output panel updates in real time.
    fn poll_test(&mut self) -> Result<()> {
        let Screen::Test(run) = &mut self.screen else {
            return Ok(());
        };
        if run.finished.is_some() {
            return Ok(());
        }
        while let Ok(ev) = run.rx.try_recv() {
            match ev {
                TestEvent::Stdout(line) | TestEvent::Stderr(line) => {
                    run.output.push_str(&line);
                    run.output.push('\n');
                }
            }
        }
        if let Some(child) = run.child.as_mut() {
            if let Some(status) = child.try_wait()? {
                run.finished = Some(status.success());
                run.child = None;
            }
        }
        Ok(())
    }

    fn is_test_running(&self) -> bool {
        matches!(&self.screen, Screen::Test(r) if r.finished.is_none())
    }

    fn save_form(&mut self) -> Result<String> {
        let new_profile = self.form.validate()?;
        let new_name = new_profile.name().to_string();
        let mut profiles = self.profiles.clone();
        let mut renamed_from: Option<String> = None;

        match &self.form.mode {
            FormMode::Add => {
                if profiles.profiles.contains_key(&new_name) {
                    return Err(anyhow!("a profile named '{new_name}' already exists"));
                }
            }
            FormMode::Edit { original_name } => {
                if &new_name != original_name && profiles.profiles.contains_key(&new_name) {
                    return Err(anyhow!("a profile named '{new_name}' already exists"));
                }
                profiles.profiles.remove(original_name);
                if &new_name != original_name {
                    renamed_from = Some(original_name.clone());
                }
            }
        }

        // Source profile must exist after the in-memory edits — but check
        // against `profiles` (post-removal) so an assume-role profile being
        // renamed doesn't accidentally find its old self as a valid source.
        if let NewProfile::Assume(p) = &new_profile {
            if !profiles.profiles.contains_key(&p.source_profile) {
                return Err(anyhow!(
                    "source profile '{}' does not exist — add it first",
                    p.source_profile
                ));
            }
        }

        profiles
            .profiles
            .insert(new_name.clone(), new_profile.into_profile());
        save_profiles_to_file(&profiles)?;
        // Drop the old entry from ~/.aws/config so a renamed profile doesn't
        // leave a stale credential_process line pointing at a dead key.
        if let Some(old) = renamed_from {
            let _ = remove_profile_from_aws_config(&old);
        }
        write_profile_to_aws_config(&new_name)?;
        Ok(new_name)
    }

    // Spawn `aws sts get-caller-identity --profile <name>` with piped stdio
    // and stream its output into a TUI pane (Screen::Test). Reader threads
    // forward each stdout/stderr line over a channel; the main loop drains
    // the channel each tick via poll_test() so the user sees output appear
    // live without dropping back to the shell.
    fn run_test(&mut self, profile_name: &str) {
        let run = match spawn_test(profile_name) {
            Ok(run) => run,
            Err(e) => {
                // The spawn itself failed (e.g. `aws` not on PATH). Show
                // a one-shot finished TestRun so the user sees the error.
                let (_dummy_tx, rx) = mpsc::channel();
                TestRun {
                    profile_name: profile_name.to_string(),
                    output: format!("failed to launch `aws` CLI: {e}\n"),
                    finished: Some(false),
                    rx,
                    child: None,
                    started_at: std::time::Instant::now(),
                }
            }
        };
        self.screen = Screen::Test(run);
    }
}

fn spawn_test(profile_name: &str) -> Result<TestRun> {
    let mut child = Command::new("aws")
        .args(["sts", "get-caller-identity", "--profile", profile_name])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("failed to capture stdout"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| anyhow!("failed to capture stderr"))?;

    let (tx, rx) = mpsc::channel();

    // Reader threads end naturally when the pipes close (i.e. when the child
    // exits). They take ownership of the pipe so we don't need to join.
    let tx_out = tx.clone();
    thread::spawn(move || {
        let reader = BufReader::new(stdout);
        for line in reader.lines().map_while(Result::ok) {
            if tx_out.send(TestEvent::Stdout(line)).is_err() {
                break;
            }
        }
    });
    thread::spawn(move || {
        let reader = BufReader::new(stderr);
        for line in reader.lines().map_while(Result::ok) {
            if tx.send(TestEvent::Stderr(line)).is_err() {
                break;
            }
        }
    });

    Ok(TestRun {
        profile_name: profile_name.to_string(),
        output: String::new(),
        finished: None,
        rx,
        child: Some(child),
        started_at: std::time::Instant::now(),
    })
}

// === Rendering ===

fn render(app: &mut App, f: &mut Frame) {
    match &app.screen {
        Screen::List => render_list(app, f),
        Screen::Detail => render_detail(app, f),
        Screen::Add => render_add(app, f),
        Screen::Config(form) => render_config(form, f),
        Screen::Test(run) => render_test(run, f),
    }
}

fn render_config(form: &ConfigForm, f: &mut Frame) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(3), Constraint::Length(3)].as_ref())
        .split(f.area());

    let mut lines: Vec<Line> = Vec::with_capacity(CONFIG_FIELD_LABELS.len() + 4);
    lines.push(Line::from(""));
    lines.push(Line::from(vec![Span::styled(
        "  ~/.config/ssologinlite.toml",
        Style::default().fg(Color::DarkGray),
    )]));
    lines.push(Line::from(""));
    for (i, label) in CONFIG_FIELD_LABELS.iter().enumerate() {
        let value = &form.fields[i];
        let is_focused = form.focused == i;
        let display = if is_focused {
            format!("{value}█")
        } else if value.is_empty() {
            "(unset)".to_string()
        } else {
            value.clone()
        };
        let label_style = if is_focused {
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::DarkGray)
        };
        let value_style = if value.is_empty() && !is_focused {
            Style::default().fg(Color::DarkGray)
        } else {
            Style::default()
        };
        lines.push(Line::from(vec![
            Span::styled(format!("  {label:<18} "), label_style),
            Span::styled(display, value_style),
        ]));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(vec![Span::styled(
        "  empty value clears the key on save",
        Style::default().fg(Color::DarkGray),
    )]));

    f.render_widget(
        Paragraph::new(lines).block(Block::default().title(" config ").borders(Borders::ALL)),
        chunks[0],
    );

    let help = match &form.error {
        Some(e) => Line::from(Span::styled(
            format!("✗ {e}"),
            Style::default().fg(Color::Red),
        )),
        None => Line::from("[Tab / ↑↓] field  [Enter] save  [Esc] cancel"),
    };
    f.render_widget(
        Paragraph::new(help).block(Block::default().borders(Borders::ALL).title(" help ")),
        chunks[1],
    );
}

fn render_list(app: &mut App, f: &mut Frame) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(3), Constraint::Length(3)].as_ref())
        .split(f.area());
    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(35), Constraint::Min(0)].as_ref())
        .split(chunks[0]);

    let items: Vec<ListItem> = app
        .profile_names
        .iter()
        .map(|name| {
            let kind = match app.profiles.profiles.get(name) {
                Some(Profile::SsoProfile(_)) => "SSO",
                Some(Profile::AssumeSsoProfile(_)) => "AssumeRole",
                _ => "?",
            };
            ListItem::new(format!("{kind:>10}  {name}"))
        })
        .collect();
    let list = List::new(items)
        .block(
            Block::default()
                .title(format!(" profiles ({}) ", app.profile_names.len()))
                .borders(Borders::ALL),
        )
        .highlight_style(
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        );
    f.render_stateful_widget(list, body[0], &mut app.list_state);

    let detail_lines = match app.selected_profile() {
        Some(Profile::SsoProfile(p)) => sso_profile_lines(p),
        Some(Profile::AssumeSsoProfile(p)) => assume_profile_lines(p),
        Some(Profile::OtherProfile) => vec![Line::from("(other profile)")],
        None => vec![Line::from("(no profile — press 'a' to add one)")],
    };
    let detail = Paragraph::new(detail_lines)
        .block(Block::default().title(" details ").borders(Borders::ALL))
        .wrap(Wrap { trim: false });
    f.render_widget(detail, body[1]);

    let help = match &app.status {
        Some((m, true)) => Line::from(Span::styled(
            format!("✗ {m}"),
            Style::default().fg(Color::Red),
        )),
        Some((m, false)) => Line::from(Span::styled(
            format!("✓ {m}"),
            Style::default().fg(Color::Green),
        )),
        None => Line::from(
            "[↑↓/jk] nav  [Enter] details  [a]dd  [e]dit  [t]est  [x] export  [c]onfig  [r]efresh  [q]uit",
        ),
    };
    f.render_widget(
        Paragraph::new(help).block(Block::default().borders(Borders::ALL).title(" help ")),
        chunks[1],
    );
}

fn render_detail(app: &mut App, f: &mut Frame) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(3), Constraint::Length(3)].as_ref())
        .split(f.area());
    let title = format!(" {} ", app.selected_name().unwrap_or_default());
    let lines = match app.selected_profile() {
        Some(Profile::SsoProfile(p)) => sso_profile_lines(p),
        Some(Profile::AssumeSsoProfile(p)) => assume_profile_lines(p),
        _ => vec![Line::from("(unavailable)")],
    };
    f.render_widget(
        Paragraph::new(lines)
            .block(Block::default().title(title).borders(Borders::ALL))
            .wrap(Wrap { trim: false }),
        chunks[0],
    );
    f.render_widget(
        Paragraph::new("[Esc] back  [e] edit  [t] test  [q] quit")
            .block(Block::default().borders(Borders::ALL).title(" help ")),
        chunks[1],
    );
}

fn render_add(app: &mut App, f: &mut Frame) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(3), Constraint::Length(3)].as_ref())
        .split(f.area());

    let labels = app.form.field_labels();
    let mut lines: Vec<Line> = Vec::with_capacity(labels.len() + 3);
    lines.push(Line::from(""));

    // Type-toggle slot. In edit mode the type is locked to whatever the
    // existing profile is, since changing it would change the field set
    // and the on-disk record incompatibly.
    let is_edit = app.form.mode.is_edit();
    let type_focused = app.form.focused == 0;
    let kind_label = app.form.kind.label();
    let kind_display = if is_edit {
        format!("{kind_label} (locked)")
    } else if type_focused {
        format!("‹ {kind_label} ›")
    } else {
        kind_label.to_string()
    };
    let type_label_style = if is_edit {
        Style::default().fg(Color::DarkGray)
    } else if type_focused {
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::DarkGray)
    };
    let kind_value_style = if is_edit {
        Style::default().fg(Color::DarkGray)
    } else if type_focused {
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default()
    };
    lines.push(Line::from(vec![
        Span::styled(format!("  {:<18} ", "Profile type"), type_label_style),
        Span::styled(kind_display, kind_value_style),
    ]));
    lines.push(Line::from(""));

    // Field slots for the active kind.
    let kind = app.form.kind;
    let sources_empty = app.form.available_sources.is_empty();
    for (i, label) in labels.iter().enumerate() {
        let value = app.form.focused_field_value(i);
        let is_focused = app.form.focused == i + 1;
        let is_source_picker = kind == ProfileKind::AssumeSso && i == ASSUME_SOURCE_FIELD;
        let display = if is_source_picker {
            if sources_empty {
                "(no SSO profiles available)".to_string()
            } else if is_focused {
                format!("‹ {value} ›")
            } else {
                value.to_string()
            }
        } else if is_focused {
            format!("{value}█")
        } else {
            value.to_string()
        };
        let label_style = if is_focused {
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::DarkGray)
        };
        let value_style = if is_source_picker && sources_empty {
            Style::default().fg(Color::Red)
        } else if is_source_picker && is_focused {
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        };
        lines.push(Line::from(vec![
            Span::styled(format!("  {label:<18} "), label_style),
            Span::styled(display, value_style),
        ]));
    }

    let form_title = match &app.form.mode {
        FormMode::Add => " add profile ".to_string(),
        FormMode::Edit { original_name } => format!(" edit profile: {original_name} "),
    };
    f.render_widget(
        Paragraph::new(lines).block(Block::default().title(form_title).borders(Borders::ALL)),
        chunks[0],
    );

    let default_help = if type_focused && !is_edit {
        "[← →] toggle type  [Tab / ↑↓] next field  [Enter] save  [Esc] cancel"
    } else if app.form.is_source_picker_focused() {
        "[← →] cycle source  [Tab / ↑↓] field  [Enter] save  [Esc] cancel"
    } else if is_edit {
        "[Tab / ↑↓] field  [Enter] save changes  [Esc] cancel"
    } else {
        "[Tab / ↑↓] field  [Enter] save  [Esc] cancel"
    };
    let help = match &app.status {
        Some((m, true)) => Line::from(Span::styled(
            format!("✗ {m}"),
            Style::default().fg(Color::Red),
        )),
        Some((m, false)) => Line::from(Span::styled(
            format!("✓ {m}"),
            Style::default().fg(Color::Green),
        )),
        None => Line::from(default_help),
    };
    f.render_widget(
        Paragraph::new(help).block(Block::default().borders(Borders::ALL).title(" help ")),
        chunks[1],
    );
}

fn render_test(run: &TestRun, f: &mut Frame) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(
            [
                Constraint::Length(3),
                Constraint::Min(3),
                Constraint::Length(3),
            ]
            .as_ref(),
        )
        .split(f.area());

    // Header reflects the running / done state. While the subprocess is
    // alive we show a simple animated marker and the elapsed time so the
    // user can tell the TUI hasn't frozen during a long SSO browser flow.
    let header = match run.finished {
        None => {
            let frames = ["◐", "◓", "◑", "◒"];
            let tick = run.started_at.elapsed().as_millis() / 200;
            let spinner = frames[(tick as usize) % frames.len()];
            let elapsed_secs = run.started_at.elapsed().as_secs();
            Line::from(vec![
                Span::styled(
                    format!("{spinner} "),
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(format!(
                    "running aws sts get-caller-identity --profile {} ({elapsed_secs}s)",
                    run.profile_name
                )),
            ])
        }
        Some(true) => Line::from(vec![
            Span::styled(
                "✓ ",
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!(
                "aws sts get-caller-identity --profile {} succeeded",
                run.profile_name
            )),
        ]),
        Some(false) => Line::from(vec![
            Span::styled(
                "✗ ",
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!(
                "aws sts get-caller-identity --profile {} failed",
                run.profile_name
            )),
        ]),
    };

    let title = match run.finished {
        None => " test (running) ",
        Some(_) => " test result ",
    };
    f.render_widget(
        Paragraph::new(header).block(Block::default().borders(Borders::ALL).title(title)),
        chunks[0],
    );

    let body_text = if run.output.is_empty() && run.finished.is_none() {
        "(no output yet — waiting for the AWS CLI)\n\
         If SSO login is required, the browser flow will be triggered by the credential_process.\n"
            .to_string()
    } else {
        run.output.clone()
    };
    f.render_widget(
        Paragraph::new(body_text)
            .block(Block::default().borders(Borders::ALL).title(" output "))
            .wrap(Wrap { trim: false }),
        chunks[1],
    );

    let help_text = match run.finished {
        None => "[Esc] cancel and back",
        Some(_) => "[Esc / Enter] back  [q] quit",
    };
    f.render_widget(
        Paragraph::new(help_text).block(Block::default().borders(Borders::ALL).title(" help ")),
        chunks[2],
    );
}

fn sso_profile_lines(p: &SsoProfile) -> Vec<Line<'static>> {
    vec![
        kv_line("Type", "SSO"),
        kv_line("Profile name", &p.profile_name),
        kv_line("SSO start URL", &p.sso_start_url),
        kv_line("SSO region", &p.sso_region),
        kv_line("Account ID", &p.sso_account_id),
        kv_line("Role name", &p.sso_role_name),
        kv_line("Default region", p.region.as_deref().unwrap_or("(none)")),
        kv_line(
            "Duration",
            &p.duration_seconds
                .map_or("(default)".to_string(), |d| format!("{d} seconds")),
        ),
    ]
}

fn assume_profile_lines(p: &AssumeSsoProfile) -> Vec<Line<'static>> {
    vec![
        kv_line("Type", "Assume Role (via SSO)"),
        kv_line("Profile name", &p.profile_name),
        kv_line("Source profile", &p.source_profile),
        kv_line("Role ARN", &p.role_arn),
        kv_line("Region", &p.region),
    ]
}

fn kv_line(key: &str, value: &str) -> Line<'static> {
    Line::from(vec![
        Span::styled(
            format!("  {key:<16} "),
            Style::default().fg(Color::DarkGray),
        ),
        Span::raw(value.to_string()),
    ])
}

// === I/O helpers ===
//
// Note: this POC bypasses Profiles::to_file because that helper calls
// restrict_file_permissions before writing, which errors when the file does
// not yet exist (separate fix in PR #3). We write directly here and chmod
// best-effort so a fresh install can save its first profile from the TUI.

fn save_profiles_to_file(profiles: &Profiles) -> Result<()> {
    let path = get_home_os_string(format!("{PROGRAM_FOLDER}/{PROFILES}").as_str())?;
    if let Some(parent) = std::path::Path::new(&path).parent() {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(profiles)?;
    std::fs::write(&path, json)?;
    let _ = restrict_file_permissions(&path);
    Ok(())
}

fn write_profile_to_aws_config(profile_name: &str) -> Result<()> {
    let aws_config = get_aws_config()?;
    let exe_path_os = get_exe_path()?;
    let exe_path = exe_path_os
        .to_str()
        .ok_or_else(|| anyhow!("exe path is not valid UTF-8"))?;

    if let Some(parent) = std::path::Path::new(&aws_config).parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut conf = Ini::load_from_file(aws_config.as_os_str()).unwrap_or_default();
    let section = if profile_name == "default" {
        "default".to_string()
    } else {
        format!("profile {profile_name}")
    };
    let credential_process = format!("{exe_path} token --profile {profile_name}");
    conf.with_section(Some(&section))
        .set("credential_process", credential_process.as_str())
        .set("output", "json");
    conf.write_to_file(aws_config.as_os_str())?;
    Ok(())
}

// Read ~/.config/ssologinlite.toml directly (no env-var overrides) so the
// form shows what's actually persisted to disk. The `config` crate's
// ProgramConfig::new() merges env vars on top, which would surprise the user
// when they edit and re-save.
fn read_program_config_toml() -> Result<ProgramConfig> {
    let path = config_toml_path()?;
    let raw = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(ProgramConfig::default()),
        Err(e) => return Err(e.into()),
    };
    Ok(toml::from_str(&raw)?)
}

fn write_program_config_toml(cfg: &ProgramConfig) -> Result<()> {
    let path = config_toml_path()?;
    if let Some(parent) = std::path::Path::new(&path).parent() {
        std::fs::create_dir_all(parent)?;
    }
    let serialised = toml::to_string_pretty(cfg)?;
    std::fs::write(&path, serialised)?;
    Ok(())
}

fn config_toml_path() -> Result<std::ffi::OsString> {
    // CONFIG_FILE is ".config/ssologinlite" (no extension) because the config
    // crate's File::with_name auto-resolves the extension on read. For
    // writing, we pin to .toml since that's the format we serialise.
    let mut path = std::path::PathBuf::from(get_home_os_string(CONFIG_FILE)?);
    path.set_extension("toml");
    Ok(path.into_os_string())
}

// Serialise the in-memory Profiles to a vanilla AWS CLI config file —
// SSO and assume-role sections written with their native keys, no
// credential_process line. Useful as a portable backup or for switching
// off ssologinlite without losing the profile catalogue.
//
// Writes to ~/.aws/ssologinlite/config.exported.<YYYYMMDDTHHMMSS> at 0o600.
// Returns the path so the TUI can show it in the status bar.
fn export_aws_config(profiles: &Profiles) -> Result<std::path::PathBuf> {
    let timestamp = Local::now().format("%Y%m%dT%H%M%S").to_string();
    let path_os =
        get_home_os_string(format!("{PROGRAM_FOLDER}/config.exported.{timestamp}").as_str())?;
    let path = std::path::PathBuf::from(&path_os);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let mut conf = Ini::new();
    // Sort by name so re-running export with the same profile set gives
    // diffable output, which makes the file useful as a snapshot.
    let mut sorted: Vec<(&String, &Profile)> = profiles.profiles.iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(b.0));

    for (name, profile) in sorted {
        // The default profile uses [default], not [profile default], in
        // ~/.aws/config.
        let section = if name == "default" {
            "default".to_string()
        } else {
            format!("profile {name}")
        };
        match profile {
            Profile::SsoProfile(p) => {
                let mut sec = conf.with_section(Some(&section));
                sec.set("sso_start_url", p.sso_start_url.as_str())
                    .set("sso_region", p.sso_region.as_str())
                    .set("sso_account_id", p.sso_account_id.as_str())
                    .set("sso_role_name", p.sso_role_name.as_str());
                if let Some(r) = &p.region {
                    sec.set("region", r.as_str());
                }
                if let Some(d) = p.duration_seconds {
                    sec.set("duration_seconds", d.to_string().as_str());
                }
                sec.set("output", "json");
            }
            Profile::AssumeSsoProfile(p) => {
                conf.with_section(Some(&section))
                    .set("source_profile", p.source_profile.as_str())
                    .set("role_arn", p.role_arn.as_str())
                    .set("region", p.region.as_str())
                    .set("output", "json");
            }
            Profile::OtherProfile => {
                // No fields to round-trip — skip.
                continue;
            }
        }
    }

    conf.write_to_file(&path)?;
    let _ = restrict_file_permissions(&path_os);
    Ok(path)
}

fn remove_profile_from_aws_config(profile_name: &str) -> Result<()> {
    let aws_config = get_aws_config()?;
    let mut conf = match Ini::load_from_file(aws_config.as_os_str()) {
        Ok(c) => c,
        Err(_) => return Ok(()), // nothing to remove
    };
    let section = if profile_name == "default" {
        "default".to_string()
    } else {
        format!("profile {profile_name}")
    };
    conf.delete(Some(section.as_str()));
    conf.write_to_file(aws_config.as_os_str())?;
    Ok(())
}

// === TUI lifecycle ===

fn setup_tui() -> Result<Term> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    Terminal::new(CrosstermBackend::new(stdout)).map_err(Into::into)
}

fn teardown_tui(terminal: &mut Term) -> Result<()> {
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;
    Ok(())
}

pub fn run() -> Result<()> {
    let mut terminal = setup_tui()?;
    let mut app = App::new();
    let result = run_loop(&mut app, &mut terminal);
    teardown_tui(&mut terminal)?;
    result
}

fn run_loop(app: &mut App, terminal: &mut Term) -> Result<()> {
    loop {
        terminal.draw(|f| render(app, f))?;
        // Drain subprocess output produced since the last draw before we
        // block on the keyboard, so the user sees test output between
        // keystrokes too.
        app.poll_test()?;
        // While a test is running we want frequent ticks (output streaming
        // and the spinner). Otherwise block for longer to keep CPU at 0
        // when the user is reading the screen.
        let timeout = if app.is_test_running() {
            Duration::from_millis(80)
        } else {
            Duration::from_secs(60)
        };
        if event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                if app.handle_key(key)? {
                    break;
                }
            }
        }
    }
    Ok(())
}
