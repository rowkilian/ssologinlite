use anyhow::{anyhow, Result};
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
use std::io::{self, Stdout};
use std::process::Command;

use crate::aws_profile::{AssumeSsoProfile, Profile, Profiles, SsoProfile};
use crate::constants::{PROFILES, PROGRAM_FOLDER};
use crate::file_helper::{
    get_aws_config, get_exe_path, get_home_os_string, restrict_file_permissions,
};

type Term = Terminal<CrosstermBackend<Stdout>>;

const FIELD_LABELS: [&str; 7] = [
    "Profile name",
    "SSO start URL",
    "SSO region",
    "SSO account ID",
    "SSO role name",
    "Default region",
    "Duration (sec)",
];

#[derive(Default)]
struct AddForm {
    fields: [String; 7],
    focused: usize,
}

impl AddForm {
    fn focused_mut(&mut self) -> &mut String {
        &mut self.fields[self.focused]
    }
    fn next(&mut self) {
        self.focused = (self.focused + 1) % FIELD_LABELS.len();
    }
    fn prev(&mut self) {
        self.focused = (self.focused + FIELD_LABELS.len() - 1) % FIELD_LABELS.len();
    }
    fn validate(&self) -> Result<SsoProfile> {
        let name = self.fields[0].trim();
        let url = self.fields[1].trim();
        let sso_region = self.fields[2].trim();
        let account = self.fields[3].trim();
        let role = self.fields[4].trim();
        let region = self.fields[5].trim();
        let duration = self.fields[6].trim();

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
}

enum Screen {
    List,
    Detail,
    Add,
    TestResult {
        success: bool,
        output: String,
        profile_name: String,
    },
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
            form: AddForm::default(),
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

    fn selected_name(&self) -> Option<String> {
        let i = self.list_state.selected()?;
        self.profile_names.get(i).cloned()
    }

    fn selected_profile(&self) -> Option<&Profile> {
        let name = self.profile_names.get(self.list_state.selected()?)?;
        self.profiles.profiles.get(name)
    }

    fn handle_key(&mut self, key: KeyEvent, terminal: &mut Term) -> Result<bool> {
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
            Screen::List => self.handle_list(key, terminal),
            Screen::Detail => self.handle_detail(key, terminal),
            Screen::Add => self.handle_add(key),
            Screen::TestResult { .. } => self.handle_test(key),
        }
    }

    fn handle_list(&mut self, key: KeyEvent, terminal: &mut Term) -> Result<bool> {
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
                self.form = AddForm::default();
                self.status = None;
                self.screen = Screen::Add;
            }
            KeyCode::Char('r') => {
                self.refresh();
                self.status = Some(("refreshed".to_string(), false));
            }
            KeyCode::Char('t') => {
                if let Some(name) = self.selected_name() {
                    self.run_test(&name, terminal)?;
                }
            }
            _ => {}
        }
        Ok(false)
    }

    fn handle_detail(&mut self, key: KeyEvent, terminal: &mut Term) -> Result<bool> {
        match key.code {
            KeyCode::Char('q') => return Ok(true),
            KeyCode::Esc => self.screen = Screen::List,
            KeyCode::Char('t') => {
                if let Some(name) = self.selected_name() {
                    self.run_test(&name, terminal)?;
                }
            }
            _ => {}
        }
        Ok(false)
    }

    fn handle_add(&mut self, key: KeyEvent) -> Result<bool> {
        match key.code {
            KeyCode::Esc => {
                self.status = None;
                self.screen = Screen::List;
            }
            KeyCode::Tab | KeyCode::Down => self.form.next(),
            KeyCode::BackTab | KeyCode::Up => self.form.prev(),
            KeyCode::Backspace => {
                self.form.focused_mut().pop();
            }
            KeyCode::Enter => match self.save_form() {
                Ok(name) => {
                    self.refresh();
                    if let Some(i) = self.profile_names.iter().position(|n| n == &name) {
                        self.list_state.select(Some(i));
                    }
                    self.status = Some((
                        format!("saved profile '{name}' — press 't' to test it"),
                        false,
                    ));
                    self.screen = Screen::List;
                }
                Err(e) => {
                    self.status = Some((format!("{e}"), true));
                }
            },
            KeyCode::Char(c) => {
                self.form.focused_mut().push(c);
            }
            _ => {}
        }
        Ok(false)
    }

    fn handle_test(&mut self, key: KeyEvent) -> Result<bool> {
        match key.code {
            KeyCode::Char('q') => return Ok(true),
            KeyCode::Esc | KeyCode::Enter => self.screen = Screen::List,
            _ => {}
        }
        Ok(false)
    }

    fn save_form(&mut self) -> Result<String> {
        let new_profile = self.form.validate()?;
        let name = new_profile.profile_name.clone();
        if self.profiles.profiles.contains_key(&name) {
            return Err(anyhow!("a profile named '{}' already exists", name));
        }
        let mut profiles = self.profiles.clone();
        profiles
            .profiles
            .insert(name.clone(), Profile::SsoProfile(new_profile));
        save_profiles_to_file(&profiles)?;
        write_profile_to_aws_config(&name)?;
        Ok(name)
    }

    fn run_test(&mut self, profile_name: &str, terminal: &mut Term) -> Result<()> {
        // Suspend the alt screen so a possible interactive SSO browser flow,
        // and any output produced by the AWS CLI, render normally on the user's
        // terminal. We resume the TUI afterwards and show the captured output.
        suspend_tui(terminal)?;
        println!("running: aws sts get-caller-identity --profile {profile_name}");
        println!("(if SSO login is required, complete it in the browser)\n");
        let outcome = Command::new("aws")
            .args(["sts", "get-caller-identity", "--profile", profile_name])
            .output();
        let (success, output_str) = match outcome {
            Ok(o) => {
                let stdout = String::from_utf8_lossy(&o.stdout).to_string();
                let stderr = String::from_utf8_lossy(&o.stderr).to_string();
                let success = o.status.success();
                let combined = if success {
                    stdout
                } else {
                    format!("STDOUT:\n{stdout}\n\nSTDERR:\n{stderr}")
                };
                (success, combined)
            }
            Err(e) => (false, format!("failed to launch `aws` CLI: {e}")),
        };
        resume_tui(terminal)?;
        self.screen = Screen::TestResult {
            success,
            output: output_str,
            profile_name: profile_name.to_string(),
        };
        Ok(())
    }
}

// === Rendering ===

fn render(app: &mut App, f: &mut Frame) {
    match &app.screen {
        Screen::List => render_list(app, f),
        Screen::Detail => render_detail(app, f),
        Screen::Add => render_add(app, f),
        Screen::TestResult {
            success,
            output,
            profile_name,
        } => render_test(*success, output, profile_name, f),
    }
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
            "[↑↓ / jk] navigate  [Enter] details  [a] add  [t] test  [r] refresh  [q] quit",
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
        Paragraph::new("[Esc] back  [t] test with `aws sts get-caller-identity`  [q] quit")
            .block(Block::default().borders(Borders::ALL).title(" help ")),
        chunks[1],
    );
}

fn render_add(app: &mut App, f: &mut Frame) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(3), Constraint::Length(3)].as_ref())
        .split(f.area());

    let mut lines: Vec<Line> = Vec::with_capacity(FIELD_LABELS.len() + 2);
    lines.push(Line::from(""));
    for (i, label) in FIELD_LABELS.iter().enumerate() {
        let value = &app.form.fields[i];
        let display = if i == app.form.focused {
            format!("{value}█")
        } else {
            value.clone()
        };
        let label_style = if i == app.form.focused {
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::DarkGray)
        };
        lines.push(Line::from(vec![
            Span::styled(format!("  {label:<18} "), label_style),
            Span::raw(display),
        ]));
    }
    f.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .title(" add profile ")
                .borders(Borders::ALL),
        ),
        chunks[0],
    );

    let help = match &app.status {
        Some((m, true)) => Line::from(Span::styled(
            format!("✗ {m}"),
            Style::default().fg(Color::Red),
        )),
        Some((m, false)) => Line::from(Span::styled(
            format!("✓ {m}"),
            Style::default().fg(Color::Green),
        )),
        None => Line::from("[Tab / ↑↓] field  [Enter] save  [Esc] cancel"),
    };
    f.render_widget(
        Paragraph::new(help).block(Block::default().borders(Borders::ALL).title(" help ")),
        chunks[1],
    );
}

fn render_test(success: bool, output: &str, profile_name: &str, f: &mut Frame) {
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
    let header = if success {
        Line::from(vec![
            Span::styled(
                "✓ ",
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!(
                "aws sts get-caller-identity --profile {profile_name} succeeded"
            )),
        ])
    } else {
        Line::from(vec![
            Span::styled(
                "✗ ",
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!(
                "aws sts get-caller-identity --profile {profile_name} failed"
            )),
        ])
    };
    f.render_widget(
        Paragraph::new(header).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" test result "),
        ),
        chunks[0],
    );
    f.render_widget(
        Paragraph::new(output)
            .block(Block::default().borders(Borders::ALL).title(" output "))
            .wrap(Wrap { trim: false }),
        chunks[1],
    );
    f.render_widget(
        Paragraph::new("[Esc / Enter] back  [q] quit")
            .block(Block::default().borders(Borders::ALL).title(" help ")),
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

fn suspend_tui(terminal: &mut Term) -> Result<()> {
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;
    Ok(())
}

fn resume_tui(terminal: &mut Term) -> Result<()> {
    enable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        EnterAlternateScreen,
        EnableMouseCapture
    )?;
    terminal.clear()?;
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
        if let Event::Key(key) = event::read()? {
            if app.handle_key(key, terminal)? {
                break;
            }
        }
    }
    Ok(())
}
