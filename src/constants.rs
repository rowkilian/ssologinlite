pub const CREDS_CACHE: &str = ".ssologinlite_cache";
pub const PROGRAM_FOLDER: &str = ".aws/ssologinlite";
pub const PROGRAM_NAME: &str = "ssologinlite";
pub const PROFILES: &str = "profiles.json";
pub const CONFIG_FILE: &str = ".config/ssologinlite";
pub const AWS_CONFIG: &str = ".aws/config";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_creds_cache() {
        assert_eq!(CREDS_CACHE, ".ssologinlite_cache");
    }

    #[test]
    fn test_conf_cache() {
        assert_eq!(CONF_CACHE, ".conf_cache");
    }

    #[test]
    fn test_program_folder() {
        assert_eq!(PROGRAM_FOLDER, ".aws/ssologinlite");
    }

    #[test]
    fn test_program_name() {
        assert_eq!(PROGRAM_NAME, "ssologinlite");
    }

    #[test]
    fn test_profiles() {
        assert_eq!(PROFILES, "profiles.json");
    }

    #[test]
    fn test_config_file() {
        assert_eq!(CONFIG_FILE, ".config/ssologinlite");
    }

    #[test]
    fn test_aws_config() {
        assert_eq!(AWS_CONFIG, ".aws/config");
    }
}
