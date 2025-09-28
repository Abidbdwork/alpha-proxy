#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use tempfile::NamedTempFile;

    fn create_test_config() -> ServerConfig {
        ServerConfig {
            listen: ListenConfig {
                socks5_addr: Some(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                    1080,
                )),
                socks4_addr: None,
                http_addr: Some(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                    8080,
                )),
                https_addr: Some(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                    8443,
                )),
                transparent_addr: None,
            },
            auth: AuthConfig {
                backend: "mongodb".to_string(),
                source: "mongodb://localhost:27017/proxy".to_string(),
                reload_interval: 300,
            },
            metrics: MetricsConfig {
                prometheus_addr: SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                    9090,
                ),
                user_metrics: true,
                ip_metrics: true,
            },
            admin: AdminConfig {
                api_addr: SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                    8081,
                ),
                jwt_secret: "test-secret".to_string(),
                admins: vec![],
            },
            rate_limit: RateLimitConfig {
                global_rps: 10000,
                user_rps: 100,
                ip_rps: 50,
                max_concurrent_per_user: 100,
            },
            tls: Some(TlsConfig {
                enable_acme: true,
                domains: vec!["example.com".to_string()],
                cert_path: PathBuf::from("certs/server.crt"),
                key_path: PathBuf::from("certs/server.key"),
            }),
            ip_rotation: IpRotationConfig {
                strategy: IpRotationStrategy::RoundRobin,
                ipv4_pool: vec!["192.168.1.10".to_string()],
                ipv6_subnets: vec!["2001:db8::/64".to_string()],
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
        let config = create_test_config();
        assert!(ConfigLoader::validate_config(&config).is_ok());

        // Test invalid cases
        let mut invalid_config = config.clone();
        invalid_config.listen.socks5_addr = None;
        invalid_config.listen.http_addr = None;
        invalid_config.listen.https_addr = None;
        invalid_config.listen.transparent_addr = None;
        assert!(matches!(
            ConfigLoader::validate_config(&invalid_config),
            Err(ConfigError::MissingField(_))
        ));

        let mut invalid_config = config.clone();
        invalid_config.auth.reload_interval = 0;
        assert!(matches!(
            ConfigLoader::validate_config(&invalid_config),
            Err(ConfigError::InvalidValue { .. })
        ));

        let mut invalid_config = config;
        invalid_config.rate_limit.global_rps = 0;
        assert!(matches!(
            ConfigLoader::validate_config(&invalid_config),
            Err(ConfigError::InvalidValue { .. })
        ));
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
        assert_eq!(config.auth.backend, loaded.auth.backend);
    }

    #[test]
    fn test_config_defaults() {
        let minimal_toml = r#"
            [listen]
            http_addr = "127.0.0.1:8080"

            [auth]
            backend = "csv"
            source = "users.csv"
            reload_interval = 300

            [metrics]
            prometheus_addr = "127.0.0.1:9090"

            [admin]
            api_addr = "127.0.0.1:8081"
            jwt_secret = "test-secret"

            [rate_limit]
            global_rps = 10000
            user_rps = 100
            ip_rps = 50
            max_concurrent_per_user = 100

            [ip_rotation]
            strategy = "round_robin"
            sticky_session_ttl = 3600
        "#;

        let config: ServerConfig = toml::from_str(minimal_toml).unwrap();
        
        // Check defaults
        assert!(config.listen.socks5_addr.is_none());
        assert!(config.listen.transparent_addr.is_none());
        assert!(config.tls.is_none());
        assert!(config.ip_rotation.ipv4_pool.is_empty());
        assert!(config.ip_rotation.ipv6_subnets.is_empty());
    }

    #[test]
    fn test_invalid_toml_format() {
        let invalid_toml = r#"
            [listen]
            http_addr = 12345  # Should be a string
        "#;

        let result = ConfigLoader::parse_toml(invalid_toml);
        assert!(matches!(result, Err(ConfigError::ParseError(_))));
    }

    #[test]
    fn test_ip_rotation_strategy_serialization() {
        let strategies = vec![
            IpRotationStrategy::Sequential,
            IpRotationStrategy::Random,
            IpRotationStrategy::RoundRobin,
            IpRotationStrategy::LeastUsed,
        ];

        for strategy in strategies {
            let serialized = toml::to_string(&strategy).unwrap();
            let deserialized: IpRotationStrategy = toml::from_str(&serialized).unwrap();
            assert!(matches!(&strategy, &deserialized));
        }
    }

    #[test]
    fn test_nonexistent_config_file() {
        let result = ConfigLoader::load("nonexistent.toml");
        assert!(matches!(result, Err(ConfigError::FileError(_))));
    }
}