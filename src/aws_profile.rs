use crate::aws_credentials::AWScredentials;
use crate::constants::{PROFILES, PROGRAM_FOLDER};
use crate::file_helper::{
    backup_config, get_aws_config, get_exe_path, get_home_os_string, restrict_file_permissions,
};
use anyhow::{anyhow, Result};
use ini::Ini;
use log::{debug, error, info};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::io::Write;

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
                        // let region = match profile.get("region") {
                        //     Some(region) => region.to_string(),
                        //     None => {
                        //         error!("aws_profiles.Profiles.from_existing_config region not in profile");
                        //         return Err(anyhow!("region not in profile"));
                        //     }
                        // };

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
                        let key: String = profile_name.replace("profile ", "");
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
                        let key: String = profile_name.replace("profile ", "");
                        debug!("Inserting {}", profile_name);
                        profiles.insert(
                            key.clone(),
                            Profile::AssumeSsoProfile(AssumeSsoProfile {
                                profile_name: key,
                                source_profile,
                                role_arn,
                                region,
                            }),
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

    pub fn from_url(&self, url: &str) -> Option<&Profile> {
        info!("Searching first found profile for url");
        for (_, profile) in self.profiles.iter() {
            match profile {
                Profile::SsoProfile(sso_profile) => {
                    if sso_profile.sso_start_url == *url {
                        return Some(profile);
                    }
                }
                Profile::AssumeSsoProfile(_) => {}
                _ => {
                    error!("aws_profiles.Profiles.from_url profile not found");
                }
            }
        }
        None
    }

    pub fn to_file(&self) -> Result<()> {
        info!("Writing profiles to my own managed file");
        let profile_json = get_home_os_string(format!("{}/{}", PROGRAM_FOLDER, PROFILES).as_str())?;
        restrict_file_permissions(&profile_json)?;
        let mut file = match File::create(profile_json.clone()) {
            Ok(file) => file,
            Err(e) => {
                error!("aws_profiles.Profiles.to_file {:?}", e);
                return Err(anyhow!("Error creating profile file"));
            }
        };
        let data: String = match serde_json::to_string(self) {
            Ok(data) => data,
            Err(e) => {
                error!("aws_profiles.Profiles.to_file {:?}", e);
                return Err(anyhow!("Error serializing profile"));
            }
        };
        match file.write(data.as_bytes()) {
            Ok(_) => {}
            Err(e) => {
                error!("aws_profiles.Profiles.to_file {:?}", e);
                return Err(anyhow!("Error writing to profile file"));
            }
        };
        restrict_file_permissions(&profile_json)?;
        Ok(())
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
        let _ = File::create(&profile_json)?;

        let mut file = match File::create(&profile_json) {
            Ok(file) => file,
            Err(e) => {
                error!("aws_profiles.Profiles.setup_file {:?}", e);
                return Err(anyhow!("Error creating profile file"));
            }
        };
        restrict_file_permissions(&profile_json)?;
        let data: String = match serde_json::to_string(&existing_profiles) {
            Ok(data) => data,
            Err(e) => {
                error!("aws_profiles.Profiles.setup_file {:?}", e);
                return Err(anyhow!("Error serializing profile file"));
            }
        };
        match file.write(data.as_bytes()) {
            Ok(_) => {}
            Err(e) => {
                error!("aws_profiles.Profiles.setup_file {:?}", e);
                return Err(anyhow!("Error writing to profile file"));
            }
        };

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
            let credential_process =
                format!(r#"{exe_path} token {args}"#, args = common_args.join(" "));
            conf.with_section(Some(&ini_profile))
                .set("credential_process", credential_process.as_str())
                .set("output", "json");
        }
        // debug!("{:?}", conf);
        conf.write_to_file(aws_config.as_os_str())?;
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
        Ok(serde_json::to_string(&credentials)?)
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
        Ok(serde_json::to_string(&credentials)?)
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
