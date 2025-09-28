use alpha_proxy::{
    auth::types::{AuthProvider, Credentials, Session, User},
    core::{config::*, error::AuthError},
};
use async_trait::async_trait;
use std::{sync::Arc, time::SystemTime};

#[derive(Clone)]
pub struct MockAuthProvider {
    allow_auth: bool,
}

impl MockAuthProvider {
    pub fn new(allow_auth: bool) -> Self {
        Self { allow_auth }
    }
}

#[async_trait]
impl AuthProvider for MockAuthProvider {
    fn name(&self) -> &'static str {
        "mock"
    }

    async fn init(&mut self) -> Result<(), AuthError> {
        Ok(())
    }

    async fn authenticate(&self, credentials: &Credentials) -> Result<User, AuthError> {
        if self.allow_auth {
            Ok(User {
                username: credentials.username.clone(),
                password_hash: "hash".to_string(),
                enabled: true,
                expires_at: None,
                max_connections: 10,
                bandwidth_limit: None,
                allowed_ips: vec![],
            })
        } else {
            Err(AuthError::InvalidCredentials)
        }
    }

    async fn validate_session(&self, _session: &Session) -> Result<bool, AuthError> {
        Ok(self.allow_auth)
    }

    async fn update_user(&mut self, _user: &User) -> Result<(), AuthError> {
        Ok(())
    }

    async fn delete_user(&mut self, _username: &str) -> Result<(), AuthError> {
        Ok(())
    }

    async fn list_users(&self) -> Result<Vec<User>, AuthError> {
        Ok(vec![])
    }
}

pub async fn setup_test_environment() -> (Arc<ServerConfig>, Arc<MockAuthProvider>) {
    let config = ServerConfig {
        listen: ListenConfig {
            http_addr: Some("127.0.0.1:0".parse().unwrap()),
            https_addr: Some("127.0.0.1:0".parse().unwrap()),
            socks5_addr: Some("127.0.0.1:0".parse().unwrap()),
            socks4_addr: None,
            transparent_addr: Some("127.0.0.1:0".parse().unwrap()),
        },
        auth: AuthConfig {
            backend: "mock".to_string(),
            source: "".to_string(),
            reload_interval: 300,
        },
        metrics: MetricsConfig {
            prometheus_addr: "127.0.0.1:0".parse().unwrap(),
            user_metrics: true,
            ip_metrics: true,
        },
        admin: AdminConfig {
            api_addr: "127.0.0.1:0".parse().unwrap(),
            jwt_secret: "test-secret".to_string(),
            admins: vec![],
        },
        rate_limit: RateLimitConfig {
            global_rps: 1000,
            user_rps: 100,
            ip_rps: 50,
            max_concurrent_per_user: 10,
        },
        tls: None,
        ip_rotation: IpRotationConfig {
            strategy: IpRotationStrategy::RoundRobin,
            ipv4_pool: vec![],
            ipv6_subnets: vec![],
            sticky_session_ttl: 3600,
        },
    };

    let auth_backend = Arc::new(MockAuthProvider::new(true));
    
    (Arc::new(config), auth_backend)
}