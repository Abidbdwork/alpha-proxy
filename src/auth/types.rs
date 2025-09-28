use crate::core::error::AuthError;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::time::SystemTime;

/// User credentials for authentication
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Credentials {
    pub username: String,
    pub password: String,
}

/// User information including account status and limits
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub username: String,
    #[serde(skip_serializing, skip_deserializing)]
    pub password_hash: String,
    pub enabled: bool,
    pub expires_at: Option<SystemTime>,
    pub max_connections: u32,
    pub bandwidth_limit: Option<u64>, // bytes per second
    pub allowed_ips: Vec<String>,
}

/// Represents an authenticated user session
#[derive(Debug, Clone)]
pub struct Session {
    pub user: User,
    pub created_at: SystemTime,
    pub last_activity: SystemTime,
}

/// Authentication provider trait that must be implemented by all auth backends
#[async_trait]
pub trait AuthProvider: Send + Sync + 'static {
    /// Get the name of the auth provider
    fn name(&self) -> &'static str;

    /// Initialize the auth provider
    async fn init(&mut self) -> Result<(), AuthError>;

    /// Authenticate a user with the given credentials
    async fn authenticate(&self, credentials: &Credentials) -> Result<User, AuthError>;

    /// Update user information
    async fn update_user(&mut self, user: &User) -> Result<(), AuthError>;

    /// Delete a user
    async fn delete_user(&mut self, username: &str) -> Result<(), AuthError>;

    /// List all users
    async fn list_users(&self) -> Result<Vec<User>, AuthError>;

    /// Validate user's session is still valid
    async fn validate_session(&self, session: &Session) -> Result<bool, AuthError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, SystemTime};

    #[test]
    fn test_credentials() {
        let creds = Credentials {
            username: "testuser".to_string(),
            password: "testpass".to_string(),
        };
        assert_eq!(creds.username, "testuser");
        assert_eq!(creds.password, "testpass");
    }

    #[test]
    fn test_user_serialization() {
        let user = User {
            username: "testuser".to_string(),
            password_hash: "hashedpass".to_string(),
            enabled: true,
            expires_at: Some(SystemTime::now() + Duration::from_secs(3600)),
            max_connections: 10,
            bandwidth_limit: Some(1024 * 1024), // 1 MB/s
            allowed_ips: vec!["192.168.1.0/24".to_string()],
        };

        let json = serde_json::to_string(&user).unwrap();
        let deserialized: User = serde_json::from_str(&json).unwrap();

        assert_eq!(user.username, deserialized.username);
        assert_eq!(user.enabled, deserialized.enabled);
        assert_eq!(user.max_connections, deserialized.max_connections);
        assert_eq!(user.bandwidth_limit, deserialized.bandwidth_limit);
        assert_eq!(user.allowed_ips, deserialized.allowed_ips);
    }

    #[test]
    fn test_session() {
        let user = User {
            username: "testuser".to_string(),
            password_hash: "hashedpass".to_string(),
            enabled: true,
            expires_at: None,
            max_connections: 10,
            bandwidth_limit: None,
            allowed_ips: vec![],
        };

        let now = SystemTime::now();
        let session = Session {
            user,
            created_at: now,
            last_activity: now,
        };

        assert_eq!(session.user.username, "testuser");
        assert_eq!(session.created_at, now);
        assert_eq!(session.last_activity, now);
    }
}