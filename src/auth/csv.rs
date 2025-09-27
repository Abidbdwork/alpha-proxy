use crate::auth::types::{AuthProvider, Credentials, Session, User};
use crate::core::error::AuthError;
use async_trait::async_trait;
use std::{
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, Write},
    path::PathBuf,
    time::SystemTime,
};
use tokio::sync::RwLock;
use tracing::{debug, error, info};

pub struct CsvAuthProvider {
    file_path: PathBuf,
    users: RwLock<Vec<User>>,
    last_reload: RwLock<SystemTime>,
    reload_interval: u64,
}

impl CsvAuthProvider {
    pub fn new(file_path: PathBuf, reload_interval: u64) -> Self {
        Self {
            file_path,
            users: RwLock::new(Vec::new()),
            last_reload: RwLock::new(SystemTime::now()),
            reload_interval,
        }
    }

    async fn reload_if_needed(&self) -> Result<(), AuthError> {
        let last_reload = *self.last_reload.read().await;
        let now = SystemTime::now();
        if now
            .duration_since(last_reload)
            .map(|d| d.as_secs() >= self.reload_interval)
            .unwrap_or(true)
        {
            self.reload_users().await?;
        }
        Ok(())
    }

    async fn reload_users(&self) -> Result<(), AuthError> {
        debug!("Reloading users from CSV file");
        let file = File::open(&self.file_path).map_err(|e| AuthError::BackendError(e.to_string()))?;
        let reader = BufReader::new(file);
        let mut users = Vec::new();

        for line in reader.lines() {
            let line = line.map_err(|e| AuthError::BackendError(e.to_string()))?;
            if line.trim().is_empty() || line.starts_with('#') {
                continue;
            }

            let parts: Vec<&str> = line.split(',').collect();
            if parts.len() < 2 {
                error!("Invalid CSV line format: {}", line);
                continue;
            }

            users.push(User {
                username: parts[0].to_string(),
                password_hash: parts[1].to_string(),
                enabled: parts.get(2).map(|&s| s == "1").unwrap_or(true),
                expires_at: parts.get(3).and_then(|&s| {
                    if s.is_empty() {
                        None
                    } else {
                        SystemTime::now()
                            .checked_add(std::time::Duration::from_secs(s.parse().unwrap_or(0)))
                    }
                }),
                max_connections: parts
                    .get(4)
                    .and_then(|&s| s.parse().ok())
                    .unwrap_or(10),
                bandwidth_limit: parts.get(5).and_then(|&s| s.parse().ok()),
                allowed_ips: parts
                    .get(6)
                    .map(|&s| s.split(';').map(String::from).collect())
                    .unwrap_or_default(),
            });
        }

        *self.users.write().await = users;
        *self.last_reload.write().await = SystemTime::now();
        info!("Successfully reloaded {} users from CSV", users.len());
        Ok(())
    }
}

#[async_trait]
impl AuthProvider for CsvAuthProvider {
    fn name(&self) -> &'static str {
        "csv"
    }

    async fn init(&mut self) -> Result<(), AuthError> {
        // Create file if it doesn't exist
        if !self.file_path.exists() {
            File::create(&self.file_path)
                .map_err(|e| AuthError::BackendError(e.to_string()))?;
        }
        self.reload_users().await
    }

    async fn authenticate(&self, credentials: &Credentials) -> Result<User, AuthError> {
        self.reload_if_needed().await?;
        let users = self.users.read().await;

        if let Some(user) = users.iter().find(|u| u.username == credentials.username) {
            if !user.enabled {
                return Err(AuthError::AccountDisabled);
            }

            if let Some(expires_at) = user.expires_at {
                if SystemTime::now() > expires_at {
                    return Err(AuthError::AccountExpired);
                }
            }

            // In a real implementation, you would use proper password hashing
            if user.password_hash == credentials.password {
                Ok(user.clone())
            } else {
                Err(AuthError::InvalidCredentials)
            }
        } else {
            Err(AuthError::InvalidCredentials)
        }
    }

    async fn update_user(&mut self, user: &User) -> Result<(), AuthError> {
        let mut users = self.users.write().await;
        if let Some(index) = users.iter().position(|u| u.username == user.username) {
            users[index] = user.clone();
        } else {
            users.push(user.clone());
        }

        // Write all users back to the CSV file
        let mut file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&self.file_path)
            .map_err(|e| AuthError::BackendError(e.to_string()))?;

        for user in users.iter() {
            writeln!(
                file,
                "{},{},{},{},{},{},{}",
                user.username,
                user.password_hash,
                if user.enabled { "1" } else { "0" },
                user.expires_at
                    .map(|t| t.duration_since(SystemTime::now())
                        .unwrap_or_default()
                        .as_secs()
                        .to_string())
                    .unwrap_or_default(),
                user.max_connections,
                user.bandwidth_limit.unwrap_or_default(),
                user.allowed_ips.join(";")
            )
            .map_err(|e| AuthError::BackendError(e.to_string()))?;
        }

        Ok(())
    }

    async fn delete_user(&mut self, username: &str) -> Result<(), AuthError> {
        let mut users = self.users.write().await;
        if let Some(index) = users.iter().position(|u| u.username == username) {
            users.remove(index);

            // Write remaining users back to the CSV file
            let mut file = OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(&self.file_path)
                .map_err(|e| AuthError::BackendError(e.to_string()))?;

            for user in users.iter() {
                writeln!(
                    file,
                    "{},{},{},{},{},{},{}",
                    user.username,
                    user.password_hash,
                    if user.enabled { "1" } else { "0" },
                    user.expires_at
                        .map(|t| t.duration_since(SystemTime::now())
                            .unwrap_or_default()
                            .as_secs()
                            .to_string())
                        .unwrap_or_default(),
                    user.max_connections,
                    user.bandwidth_limit.unwrap_or_default(),
                    user.allowed_ips.join(";")
                )
                .map_err(|e| AuthError::BackendError(e.to_string()))?;
            }

            Ok(())
        } else {
            Err(AuthError::BackendError("User not found".to_string()))
        }
    }

    async fn list_users(&self) -> Result<Vec<User>, AuthError> {
        self.reload_if_needed().await?;
        Ok(self.users.read().await.clone())
    }

    async fn validate_session(&self, session: &Session) -> Result<bool, AuthError> {
        self.reload_if_needed().await?;
        let users = self.users.read().await;

        if let Some(user) = users.iter().find(|u| u.username == session.user.username) {
            if !user.enabled {
                return Ok(false);
            }

            if let Some(expires_at) = user.expires_at {
                if SystemTime::now() > expires_at {
                    return Ok(false);
                }
            }

            Ok(true)
        } else {
            Ok(false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    use tokio;

    async fn create_test_provider() -> (CsvAuthProvider, NamedTempFile) {
        let file = NamedTempFile::new().unwrap();
        let provider = CsvAuthProvider::new(file.path().to_owned(), 60);
        provider.init().await.unwrap();
        (provider, file)
    }

    #[tokio::test]
    async fn test_authenticate_user() {
        let (mut provider, _file) = create_test_provider().await;

        // Add a test user
        let test_user = User {
            username: "testuser".to_string(),
            password_hash: "testpass".to_string(),
            enabled: true,
            expires_at: None,
            max_connections: 10,
            bandwidth_limit: None,
            allowed_ips: vec![],
        };
        provider.update_user(&test_user).await.unwrap();

        // Test valid credentials
        let credentials = Credentials {
            username: "testuser".to_string(),
            password: "testpass".to_string(),
        };
        let result = provider.authenticate(&credentials).await;
        assert!(result.is_ok());

        // Test invalid password
        let credentials = Credentials {
            username: "testuser".to_string(),
            password: "wrongpass".to_string(),
        };
        let result = provider.authenticate(&credentials).await;
        assert!(matches!(result, Err(AuthError::InvalidCredentials)));

        // Test non-existent user
        let credentials = Credentials {
            username: "nonexistent".to_string(),
            password: "testpass".to_string(),
        };
        let result = provider.authenticate(&credentials).await;
        assert!(matches!(result, Err(AuthError::InvalidCredentials)));
    }

    #[tokio::test]
    async fn test_user_management() {
        let (mut provider, _file) = create_test_provider().await;

        // Add user
        let test_user = User {
            username: "testuser".to_string(),
            password_hash: "testpass".to_string(),
            enabled: true,
            expires_at: None,
            max_connections: 10,
            bandwidth_limit: None,
            allowed_ips: vec![],
        };
        provider.update_user(&test_user).await.unwrap();

        // List users
        let users = provider.list_users().await.unwrap();
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].username, "testuser");

        // Update user
        let mut updated_user = test_user.clone();
        updated_user.max_connections = 20;
        provider.update_user(&updated_user).await.unwrap();

        // Verify update
        let users = provider.list_users().await.unwrap();
        assert_eq!(users[0].max_connections, 20);

        // Delete user
        provider.delete_user("testuser").await.unwrap();

        // Verify deletion
        let users = provider.list_users().await.unwrap();
        assert_eq!(users.len(), 0);
    }

    #[tokio::test]
    async fn test_session_validation() {
        let (mut provider, _file) = create_test_provider().await;

        // Add a test user
        let test_user = User {
            username: "testuser".to_string(),
            password_hash: "testpass".to_string(),
            enabled: true,
            expires_at: None,
            max_connections: 10,
            bandwidth_limit: None,
            allowed_ips: vec![],
        };
        provider.update_user(&test_user).await.unwrap();

        // Create a valid session
        let session = Session {
            user: test_user,
            created_at: SystemTime::now(),
            last_activity: SystemTime::now(),
        };

        // Test valid session
        let result = provider.validate_session(&session).await.unwrap();
        assert!(result);

        // Test session for deleted user
        provider.delete_user("testuser").await.unwrap();
        let result = provider.validate_session(&session).await.unwrap();
        assert!(!result);
    }
}