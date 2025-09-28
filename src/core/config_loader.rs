use crate::core::{config::*, error::ConfigError};
use serde::de::DeserializeOwned;
use std::{fs, path::Path};
use tracing::{debug, info};

pub struct ConfigLoader;

impl ConfigLoader {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<ServerConfig, ConfigError> {
        info!("Loading configuration from {}", path.as_ref().display());
        let content = fs::read_to_string(path).map_err(ConfigError::FileError)?;
        Self::parse_toml(&content)
    }

    pub fn parse_toml(content: &str) -> Result<ServerConfig, ConfigError> {
        let config: ServerConfig = toml::from_str(content).map_err(|e| ConfigError::ParseError(e.to_string()))?;
        debug!("Parsed configuration: {:?}", config);
        Self::validate_config(&config)?;
        Ok(config)
    }

    fn validate_config(config: &ServerConfig) -> Result<(), ConfigError> {
        // Validate listening addresses
        if config.listen.socks5_addr.is_none()
            && config.listen.socks4_addr.is_none()
            && config.listen.http_addr.is_none()
            && config.listen.https_addr.is_none()
            && config.listen.transparent_addr.is_none()
        {
            return Err(ConfigError::MissingField(
                "At least one listening address must be configured".into(),
            ));
        }

        // Validate auth configuration
        if config.auth.reload_interval == 0 {
            return Err(ConfigError::InvalidValue {
                field: "auth.reload_interval".into(),
                message: "Must be greater than 0".into(),
            });
        }

        // Validate rate limits
        if config.rate_limit.global_rps == 0 {
            return Err(ConfigError::InvalidValue {
                field: "rate_limit.global_rps".into(),
                message: "Must be greater than 0".into(),
            });
        }

        if config.rate_limit.user_rps == 0 {
            return Err(ConfigError::InvalidValue {
                field: "rate_limit.user_rps".into(),
                message: "Must be greater than 0".into(),
            });
        }

        // Validate TLS configuration if enabled
        if let Some(tls) = &config.tls {
            if tls.enable_acme && tls.domains.is_empty() {
                return Err(ConfigError::InvalidValue {
                    field: "tls.domains".into(),
                    message: "Domains must be specified when ACME is enabled".into(),
                });
            }

            if !tls.enable_acme {
                if !tls.cert_path.exists() {
                    return Err(ConfigError::InvalidValue {
                        field: "tls.cert_path".into(),
                        message: "Certificate file does not exist".into(),
                    });
                }

                if !tls.key_path.exists() {
                    return Err(ConfigError::InvalidValue {
                        field: "tls.key_path".into(),
                        message: "Private key file does not exist".into(),
                    });
                }
            }
        }

        Ok(())
    }

    pub fn save<P: AsRef<Path>>(config: &ServerConfig, path: P) -> Result<(), ConfigError> {
        let content = toml::to_string_pretty(config).map_err(|e| ConfigError::ParseError(e.to_string()))?;
        fs::write(path, content).map_err(ConfigError::FileError)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use tempfile::NamedTempFile;

    fn create_test_config() -> ServerConfig {
        ServerConfig {
            listen: ListenConfig {
                socks5_addr: Some("127.0.0.1:1080".parse().unwrap()),
                socks4_addr: None,
                http_addr: Some("127.0.0.1:8080".parse().unwrap()),
                https_addr: None,
                transparent_addr: None,
            },
            auth: AuthConfig {
                backend: "csv".to_string(),
                source: "users.csv".to_string(),
                reload_interval: 300,
            },
            metrics: MetricsConfig {
                prometheus_addr: "127.0.0.1:9090".parse().unwrap(),
                user_metrics: true,
                ip_metrics: true,
            },
            admin: AdminConfig {
                api_addr: "127.0.0.1:8081".parse().unwrap(),
                jwt_secret: "test-secret".to_string(),
                admins: vec![],
            },
            rate_limit: RateLimitConfig {
                global_rps: 10000,
                user_rps: 100,
                ip_rps: 50,
                max_concurrent_per_user: 100,
            },
            tls: None,
            ip_rotation: IpRotationConfig {
                strategy: IpRotationStrategy::Random,
                ipv4_pool: vec![],
                ipv6_subnets: vec![],
                sticky_session_ttl: 3600,
            },
        }
    }

    #[test]
    fn test_config_serialization() {
        let config = create_test_config();
        let toml = toml::to_string_pretty(&config).unwrap();
        let parsed: ServerConfig = toml::from_str(&toml).unwrap();

        assert_eq!(
            config.listen.socks5_addr.unwrap(),
            parsed.listen.socks5_addr.unwrap()
        );
        assert_eq!(config.auth.backend, parsed.auth.backend);
        assert_eq!(config.rate_limit.global_rps, parsed.rate_limit.global_rps);
    }

    #[test]
    fn test_config_validation() {
        // Test valid config
        let config = create_test_config();
        assert!(ConfigLoader::validate_config(&config).is_ok());

        // Test invalid config - no listening addresses
        let mut invalid_config = config.clone();
        invalid_config.listen = ListenConfig {
            socks5_addr: None,
            socks4_addr: None,
            http_addr: None,
            https_addr: None,
            transparent_addr: None,
        };
        assert!(ConfigLoader::validate_config(&invalid_config).is_err());

        // Test invalid rate limits
        let mut invalid_config = config.clone();
        invalid_config.rate_limit.global_rps = 0;
        assert!(ConfigLoader::validate_config(&invalid_config).is_err());
    }

    #[test]
    fn test_config_file_operations() {
        let config = create_test_config();
        let file = NamedTempFile::new().unwrap();
        let path = file.path();

        // Test saving
        assert!(ConfigLoader::save(&config, path).is_ok());

        // Test loading
        let loaded = ConfigLoader::load(path).unwrap();
        assert_eq!(
            config.listen.socks5_addr.unwrap(),
            loaded.listen.socks5_addr.unwrap()
        );
    }

    #[test]
    fn test_toml_parsing() {
        let toml_str = r#"
            [listen]
            socks5_addr = "127.0.0.1:1080"
            http_addr = "127.0.0.1:8080"

            [auth]
            backend = "csv"
            source = "users.csv"
            reload_interval = 300

            [metrics]
            prometheus_addr = "127.0.0.1:9090"
            user_metrics = true
            ip_metrics = true

            [admin]
            api_addr = "127.0.0.1:8081"
            jwt_secret = "test-secret"
            admins = [
                { username = "admin", password_hash = "test-hash" }
            ]

            [rate_limit]
            global_rps = 10000
            user_rps = 100
            ip_rps = 50
            max_concurrent_per_user = 100

            [ip_rotation]
            strategy = "random"
            sticky_session_ttl = 3600
            ipv4_pool = ["192.168.1.1", "192.168.1.2"]
            ipv6_subnets = ["2001:db8::/64"]
        "#;

        let config = ConfigLoader::parse_toml(toml_str).unwrap();
        assert_eq!(
            config.listen.socks5_addr.unwrap().to_string(),
            "127.0.0.1:1080"
        );
        assert_eq!(config.auth.backend, "csv");
        assert_eq!(config.rate_limit.global_rps, 10000);
    }
}