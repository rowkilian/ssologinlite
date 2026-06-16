use crate::aws_credentials::AWScredentials;
use crate::constants::{PROFILES, PROGRAM_FOLDER};
use crate::file_helper::{
    backup_config, get_aws_config, get_exe_path, get_home_os_string, restrict_file_permissions,
    write_atomic,
};
use anyhow::{anyhow, Result};
use ini::Ini;
use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct Profiles {
    pub profiles: HashMap<String, Profile>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub enum Profile {
    SsoProfile(SsoProfile),
    AssumeSsoProfile(AssumeSsoProfile),
    OtherProfile,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct SsoProfile {
    pub profile_name: String,
    pub sso_start_url: String,
    pub sso_region: String,
    pub sso_account_id: String,
    pub sso_role_name: String,
    pub region: Option<String>,
    pub duration_seconds: Option<u16>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct AssumeSsoProfile {
    pub source_profile: String,
    pub profile_name: String,
    pub role_arn: String,
    pub region: String,
    // Optional STS AssumeRole session duration. Unlike SSO get_role_credentials
    // (whose duration is fixed by the permission set), the STS AssumeRole call
    // honors a requested duration, so this is wired through to it.
    #[serde(default)]
    pub duration_seconds: Option<i32>,
}

impl Profiles {
    pub fn get_profile(profile_name: String) -> Result<Profile> {
        let profiles = Profiles::from_file()?;
        match profiles.profiles.get(&profile_name) {
            Some(profile) => Ok(profile.clone()),
            None => Err(anyhow!(MyErrors::ProfileFileNotFound)),
        }
    }

    pub fn from_existing_config() -> Result<Profiles> {
        info!("Reading existing AWS config file");
        let mut profiles = HashMap::new();
        let aws_config = get_aws_config()?;
        let conf = match Ini::load_from_file(aws_config.as_os_str()) {
            Ok(conf) => conf,
            Err(_) => {
                return Err(anyhow!(MyErrors::ProfileFileNotFound));
            }
        };

        for (profile_name, profile) in conf.iter() {
            debug!(
                "aws_profile.Profiles.from_existing_config looping into {:?}",
                profile_name
            );

            match profile_name {
                Some(profile_name) => {
                    if profile.contains_key("sso_start_url")
                        && profile.contains_key("sso_region")
                        && profile.contains_key("sso_account_id")
                        && profile.contains_key("sso_role_name")
                    {
                        let sso_start_url = match profile.get("sso_start_url") {
                            Some(sso_start_url) => sso_start_url.to_string(),
                            None => {
                                error!(
                                    "aws_profiles.Profiles.from_existing_config sso_start_url not in profile"
                                );
                                return Err(anyhow!("sso_start_url not in profile"));
                            }
                        };
                        let sso_region = match profile.get("sso_region") {
                            Some(sso_region) => sso_region.to_string(),
                            None => {
                                error!("aws_profiles.Profiles.from_existing_config sso_region not in profile");
                                return Err(anyhow!("sso_region not in profile"));
                            }
                        };
                        let sso_account_id = match profile.get("sso_account_id") {
                            Some(sso_account_id) => sso_account_id.to_string(),
                            None => {
                                error!(
                                    "aws_profiles.Profiles.from_existing_config sso_account_id not in profile"
                                );
                                return Err(anyhow!("sso_account_id not in profile"));
                            }
                        };
                        let sso_role_name = match profile.get("sso_role_name") {
                            Some(sso_role_name) => sso_role_name.to_string(),
                            None => {
                                error!(
                                    "aws_profiles.Profiles.from_existing_config sso_role_name not in profile"
                                );
                                return Err(anyhow!("sso_role_name not in profile"));
                            }
                        };
                        let duration_seconds: Option<u16> = match profile.get("duration_seconds") {
                            Some(duration_seconds) => match duration_seconds.to_string().parse() {
                                Ok(duration_seconds) => Some(duration_seconds),
                                Err(_) => {
                                    error!("aws_profiles.Profiles.from_existing_config duration_seconds not in profile");
                                    return Err(anyhow!("duration_seconds not in profile"));
                                }
                            },
                            None => None,
                        };
                        debug!("Inserting {}", profile_name);
                        let key: String = profile_name
                            .strip_prefix("profile ")
                            .unwrap_or(profile_name)
                            .to_string();
                        profiles.insert(
                            key.clone(),
                            Profile::SsoProfile(SsoProfile {
                                profile_name: key,
                                sso_start_url,
                                sso_region,
                                sso_account_id,
                                sso_role_name,
                                region: profile.get("region").map(|region| region.to_string()),
                                duration_seconds,
                            }),
                        );
                    } else if profile.contains_key("source_profile")
                        && profile.contains_key("role_arn")
                        && profile.contains_key("region")
                    {
                        let source_profile = match profile.get("source_profile") {
                            Some(source_profile) => source_profile.to_string(),
                            None => {
                                error!(
                                    "aws_profiles.Profiles.from_existing_config source_profile not in profile"
                                );
                                return Err(anyhow!("source_profile not in profile"));
                            }
                        };
                        let role_arn = match profile.get("role_arn") {
                            Some(role_arn) => role_arn.to_string(),
                            None => {
                                error!("aws_profiles.Profiles.from_existing_config role_arn not in profile");
                                return Err(anyhow!("role_arn not in profile"));
                            }
                        };
                        let region = match profile.get("region") {
                            Some(region) => region.to_string(),
                            None => {
                                error!("aws_profiles.Profiles.from_existing_config region not in profile");
                                return Err(anyhow!("region not in profile"));
                            }
                        };
                        let duration_seconds: Option<i32> = match profile.get("duration_seconds") {
                            Some(d) => match d.parse() {
                                Ok(d) => Some(d),
                                Err(_) => {
                                    error!("aws_profiles.Profiles.from_existing_config duration_seconds not a number");
                                    return Err(anyhow!("duration_seconds is not a valid integer"));
                                }
                            },
                            None => None,
                        };
                        let key: String = profile_name
                            .strip_prefix("profile ")
                            .unwrap_or(profile_name)
                            .to_string();
                        debug!("Inserting {}", profile_name);
                        profiles.insert(
                            key.clone(),
                            Profile::AssumeSsoProfile(AssumeSsoProfile {
                                profile_name: key,
                                source_profile,
                                role_arn,
                                region,
                                duration_seconds,
                            }),
                        );
                    } else if profile.contains_key("source_profile")
                        && profile.contains_key("role_arn")
                    {
                        // Looks like an assume-role profile but is missing the
                        // required `region` key — warn rather than dropping it
                        // silently, since the omission is almost always a typo.
                        warn!(
                            "aws_profiles.Profiles.from_existing_config: profile {:?} has source_profile and role_arn but no 'region'; skipping",
                            profile_name
                        );
                    };
                }
                None => {
                    continue;
                }
            }
        }
        Ok(Profiles { profiles })
    }

    pub fn from_file() -> Result<Profiles> {
        info!("Reading profiles from my own managed file");
        let profile_json = get_home_os_string(format!("{}/{}", PROGRAM_FOLDER, PROFILES).as_str())?;
        debug!("from_file.profile_json = {:?}", profile_json);
        restrict_file_permissions(&profile_json)?;
        let file = File::open(profile_json)?;
        debug!("from_file.file = {:?}", file);
        let profiles: Profiles = serde_json::from_reader(file)?;
        debug!("from_file.profiles = {:?}", profiles);
        Ok(profiles)
    }

    pub fn setup_file() -> Result<()> {
        info!("Setting up profiles file");
        backup_config()?;

        let existing_profiles = Profiles::from_existing_config()?;

        let profile_json = get_home_os_string(format!("{}/{}", PROGRAM_FOLDER, PROFILES).as_str())?;
        let data: String = match serde_json::to_string(&existing_profiles) {
            Ok(data) => data,
            Err(e) => {
                error!("aws_profiles.Profiles.setup_file {:?}", e);
                return Err(anyhow!("Error serializing profile file"));
            }
        };
        write_atomic(profile_json.as_os_str(), data.as_bytes())?;

        let exe_path_os_str = get_exe_path()?;
        let exe_path = match exe_path_os_str.as_os_str().to_str() {
            Some(exe_path) => exe_path,
            None => {
                return Err(anyhow!(MyErrors::ExePathError));
            }
        };

        debug!("aws_profiles.Profiles.setup_file writing config");
        let aws_config = get_aws_config()?;
        let mut conf = match Ini::load_from_file(aws_config.as_os_str()) {
            Ok(conf) => conf,
            Err(_) => {
                return Err(anyhow!(MyErrors::ProfileFileNotFound));
            }
        };
        for profile in existing_profiles.profiles.keys() {
            debug!(
                "aws_profiles.Profiles.setup_file writing profile {}",
                profile
            );
            let ini_profile = match profile == "default" {
                true => "default".to_string(),
                _ => format!("profile {}", profile),
            };
            // let ini_profile = format!("profile {}", profile);
            let common_args = ["--profile".to_string(), profile.clone()];
            let section = match conf.section(Some(&ini_profile)) {
                Some(section) => section.clone(),
                None => {
                    return Err(anyhow!("Section '{}' not found", ini_profile));
                }
            };
            for (k, _) in section.iter() {
                match conf.section_mut(Some(&ini_profile)) {
                    Some(section) => {
                        section.remove(k);
                    }
                    None => {
                        return Err(anyhow!(MyErrors::ProfileFileNotFound));
                    }
                };
            }
            // Quote the exe path: the AWS CLI shlex-splits credential_process, so
            // a path containing spaces would be parsed as multiple arguments.
            let credential_process =
                format!(r#""{exe_path}" token {args}"#, args = common_args.join(" "));
            conf.with_section(Some(&ini_profile))
                .set("credential_process", credential_process.as_str())
                .set("output", "json");
        }
        let mut buf = Vec::new();
        conf.write_to(&mut buf)?;
        write_atomic(aws_config.as_os_str(), &buf)?;
        Ok(())
    }
}

impl SsoProfile {
    pub fn get(profile_name: String) -> Result<SsoProfile> {
        info!("get SsoProfile {}", &profile_name);
        let profiles = Profiles::from_file()?;
        match profiles.profiles.get(&profile_name) {
            Some(Profile::SsoProfile(sso_profile)) => Ok(sso_profile.clone()),
            _ => Err(anyhow!("Profile not found")),
        }
    }
    pub async fn get_token(&self) -> Result<String> {
        info!("get SsoProfile token");
        let credentials = AWScredentials::get_role_credentials(self.clone()).await?;
        credentials.as_json()
    }
    pub async fn get_credentials(&self) -> Result<AWScredentials> {
        info!("get SsoProfile credentials");
        AWScredentials::get_role_credentials(self.clone()).await
    }
}

impl AssumeSsoProfile {
    pub fn get(profile_name: String) -> Result<AssumeSsoProfile> {
        info!("get AssumeSsoProfile {}", &profile_name);
        let profiles = Profiles::from_file()?;
        match profiles.profiles.get(&profile_name) {
            Some(Profile::AssumeSsoProfile(assume_profile)) => Ok(assume_profile.clone()),
            _ => Err(anyhow!("Profile {} not found", &profile_name)),
        }
    }
    pub fn get_sso_profile(&self) -> Result<SsoProfile> {
        let profiles = Profiles::from_file()?;
        info!(
            "get SsoProfile {} for AssumedRoleProfile",
            &self.source_profile
        );
        match profiles.profiles.get(&self.source_profile) {
            Some(Profile::SsoProfile(sso_profile)) => Ok(sso_profile.clone()),
            _ => Err(anyhow!(
                "Associated sso profile for {} not found",
                &self.source_profile
            )),
        }
    }
    pub async fn get_token(&self) -> Result<String> {
        info!("get AssumeSsoProfile token");
        let sso_profile = self.get_sso_profile()?;
        let credentials = AWScredentials::get_assume_role(self.clone(), sso_profile).await?;
        credentials.as_json()
    }
    pub async fn get_credentials(&self) -> Result<AWScredentials> {
        info!("get AssumeSsoProfile token");
        let sso_profile = self.get_sso_profile()?;
        AWScredentials::get_assume_role(self.clone(), sso_profile).await
    }
}

#[derive(Debug)]
enum MyErrors {
    ProfileFileNotFound,
    ExePathError,
}

impl std::fmt::Display for MyErrors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ProfileFileNotFound => write!(f, "Could not find aws config file"),
            Self::ExePathError => write!(f, "Could not get exe path"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_sso_profile(name: &str, url: &str) -> SsoProfile {
        SsoProfile {
            profile_name: name.to_string(),
            sso_start_url: url.to_string(),
            sso_region: "us-west-2".to_string(),
            sso_account_id: "123456789012".to_string(),
            sso_role_name: "AdminRole".to_string(),
            region: Some("us-west-2".to_string()),
            duration_seconds: Some(3600),
        }
    }

    fn make_assume_profile(name: &str) -> AssumeSsoProfile {
        AssumeSsoProfile {
            source_profile: "dev".to_string(),
            profile_name: name.to_string(),
            role_arn: "arn:aws:iam::123456789012:role/MyRole".to_string(),
            region: "us-east-1".to_string(),
            duration_seconds: Some(3600),
        }
    }

    fn make_profiles() -> Profiles {
        let mut profiles = HashMap::new();
        profiles.insert(
            "dev".to_string(),
            Profile::SsoProfile(make_sso_profile("dev", "https://my-sso.awsapps.com/start")),
        );
        profiles.insert(
            "staging".to_string(),
            Profile::SsoProfile(make_sso_profile(
                "staging",
                "https://other-sso.awsapps.com/start",
            )),
        );
        profiles.insert(
            "assume-prod".to_string(),
            Profile::AssumeSsoProfile(make_assume_profile("assume-prod")),
        );
        Profiles { profiles }
    }

    // --- Serde round-trips ---

    #[test]
    fn test_profiles_serde_round_trip() {
        let profiles = make_profiles();
        let json = serde_json::to_string(&profiles).unwrap();
        let deser: Profiles = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.profiles.len(), profiles.profiles.len());
    }

    #[test]
    fn test_sso_profile_serde_round_trip() {
        let profile = make_sso_profile("dev", "https://my-sso.awsapps.com/start");
        let json = serde_json::to_string(&profile).unwrap();
        let deser: SsoProfile = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.profile_name, "dev");
        assert_eq!(deser.sso_start_url, "https://my-sso.awsapps.com/start");
        assert_eq!(deser.sso_region, "us-west-2");
        assert_eq!(deser.sso_account_id, "123456789012");
        assert_eq!(deser.sso_role_name, "AdminRole");
        assert_eq!(deser.region, Some("us-west-2".to_string()));
        assert_eq!(deser.duration_seconds, Some(3600));
    }

    #[test]
    fn test_assume_sso_profile_serde_round_trip() {
        let profile = make_assume_profile("assume-prod");
        let json = serde_json::to_string(&profile).unwrap();
        let deser: AssumeSsoProfile = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.profile_name, "assume-prod");
        assert_eq!(deser.source_profile, "dev");
        assert_eq!(deser.role_arn, "arn:aws:iam::123456789012:role/MyRole");
        assert_eq!(deser.region, "us-east-1");
        assert_eq!(deser.duration_seconds, Some(3600));
    }

    #[test]
    fn test_assume_sso_profile_deserialize_without_duration() {
        // Older profiles.json predates duration_seconds; #[serde(default)] must
        // let it deserialize to None rather than erroring.
        let json = r#"{"source_profile":"dev","profile_name":"p","role_arn":"arn:aws:iam::1:role/r","region":"us-east-1"}"#;
        let p: AssumeSsoProfile = serde_json::from_str(json).unwrap();
        assert!(p.duration_seconds.is_none());
    }

    #[test]
    fn test_profile_enum_sso_variant_serde() {
        let profile = Profile::SsoProfile(make_sso_profile("test", "https://url"));
        let json = serde_json::to_string(&profile).unwrap();
        let deser: Profile = serde_json::from_str(&json).unwrap();
        match deser {
            Profile::SsoProfile(p) => assert_eq!(p.profile_name, "test"),
            _ => panic!("expected SsoProfile"),
        }
    }

    #[test]
    fn test_profile_enum_assume_variant_serde() {
        let profile = Profile::AssumeSsoProfile(make_assume_profile("ap"));
        let json = serde_json::to_string(&profile).unwrap();
        let deser: Profile = serde_json::from_str(&json).unwrap();
        match deser {
            Profile::AssumeSsoProfile(p) => assert_eq!(p.profile_name, "ap"),
            _ => panic!("expected AssumeSsoProfile"),
        }
    }

    #[test]
    fn test_profile_enum_other_variant_serde() {
        let profile = Profile::OtherProfile;
        let json = serde_json::to_string(&profile).unwrap();
        let deser: Profile = serde_json::from_str(&json).unwrap();
        assert!(matches!(deser, Profile::OtherProfile));
    }

    // --- Optional fields ---

    #[test]
    fn test_sso_profile_optional_region_none() {
        let mut profile = make_sso_profile("test", "https://url");
        profile.region = None;
        let json = serde_json::to_string(&profile).unwrap();
        let deser: SsoProfile = serde_json::from_str(&json).unwrap();
        assert!(deser.region.is_none());
    }

    #[test]
    fn test_sso_profile_optional_duration_none() {
        let mut profile = make_sso_profile("test", "https://url");
        profile.duration_seconds = None;
        let json = serde_json::to_string(&profile).unwrap();
        let deser: SsoProfile = serde_json::from_str(&json).unwrap();
        assert!(deser.duration_seconds.is_none());
    }

    // --- Default ---

    #[test]
    fn test_profiles_default() {
        let p = Profiles::default();
        assert!(p.profiles.is_empty());
    }

    #[test]
    fn test_sso_profile_default() {
        let p = SsoProfile::default();
        assert_eq!(p.profile_name, "");
        assert_eq!(p.sso_start_url, "");
        assert!(p.region.is_none());
        assert!(p.duration_seconds.is_none());
    }

    #[test]
    fn test_assume_sso_profile_default() {
        let p = AssumeSsoProfile::default();
        assert_eq!(p.source_profile, "");
        assert_eq!(p.profile_name, "");
        assert_eq!(p.role_arn, "");
        assert_eq!(p.region, "");
    }

    // --- MyErrors Display ---

    #[test]
    fn test_error_display_profile_not_found() {
        assert_eq!(
            format!("{}", MyErrors::ProfileFileNotFound),
            "Could not find aws config file"
        );
    }

    #[test]
    fn test_error_display_exe_path() {
        assert_eq!(
            format!("{}", MyErrors::ExePathError),
            "Could not get exe path"
        );
    }
}
