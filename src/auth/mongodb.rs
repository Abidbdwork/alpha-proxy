use crate::core::{auth::*, error::AuthError};
use async_trait::async_trait;
use cached::proc_macro::cached;
use mongodb::{
    bson::{doc, Document},
    options::{ClientOptions, Credential},
    Client, Collection,
};
use std::{sync::Arc, time::Duration};
use tokio::sync::RwLock;
use tracing::{debug, error, info};

const CACHE_TTL: u64 = 300; // 5 minutes

pub struct MongoAuthBackend {
    client: Client,
    users_collection: Collection<Document>,
    cache: Arc<RwLock<()>>, // Placeholder for actual cache implementation
}

impl MongoAuthBackend {
    pub async fn new(connection_string: &str, database: &str) -> Result<Self, AuthError> {
        let mut client_options = ClientOptions::parse(connection_string)
            .await
            .map_err(|e| AuthError::BackendError(format!("Failed to parse MongoDB URL: {}", e)))?;

        // Set up connection pool
        client_options.min_pool_size = Some(5);
        client_options.max_pool_size = Some(20);
        client_options.connect_timeout = Some(Duration::from_secs(5));

        let client = Client::with_options(client_options)
            .map_err(|e| AuthError::BackendError(format!("Failed to create MongoDB client: {}", e)))?;

        // Test connection
        client
            .database("admin")
            .run_command(doc! { "ping": 1 }, None)
            .await
            .map_err(|e| AuthError::BackendError(format!("Failed to connect to MongoDB: {}", e)))?;

        let users_collection = client.database(database).collection("users");

        info!("Successfully connected to MongoDB");

        Ok(Self {
            client,
            users_collection,
            cache: Arc::new(RwLock::new(())),
        })
    }

    #[cached(
        time = CACHE_TTL,
        key = "String",
        convert = r#"{ format!("{}", username) }"#
    )]
    async fn get_cached_user(&self, username: &str) -> Option<Document> {
        match self.users_collection
            .find_one(doc! { "username": username }, None)
            .await
        {
            Ok(Some(user)) => {
                debug!("User {} found in database", username);
                Some(user)
            }
            Ok(None) => {
                debug!("User {} not found in database", username);
                None
            }
            Err(e) => {
                error!("Error querying user {}: {}", username, e);
                None
            }
        }
    }
}

#[async_trait]
impl AuthBackend for MongoAuthBackend {
    async fn authenticate(&self, username: &str, password: &str) -> Result<AuthInfo, AuthError> {
        let user_doc = self.get_cached_user(username)
            .await
            .ok_or(AuthError::InvalidCredentials)?;

        let stored_password = user_doc
            .get_str("password_hash")
            .map_err(|_| AuthError::BackendError("Invalid user document format".into()))?;

        // Verify password using Argon2
        if !verify_password(password, stored_password) {
            return Err(AuthError::InvalidCredentials);
        }

        // Check if account is enabled
        if !user_doc.get_bool("enabled").unwrap_or(true) {
            return Err(AuthError::AccountDisabled);
        }

        // Check if account is expired
        if let Some(expires_at) = user_doc.get_datetime("expires_at") {
            if expires_at.to_chrono() < chrono::Utc::now() {
                return Err(AuthError::AccountExpired);
            }
        }

        // Build auth info from document
        Ok(AuthInfo {
            username: username.to_string(),
            max_connections: user_doc.get_i32("max_connections").unwrap_or(10) as u32,
            rate_limit_rps: user_doc.get_i32("rate_limit_rps").unwrap_or(100) as u32,
            allowed_ips: user_doc
                .get_array("allowed_ips")
                .map(|ips| {
                    ips.iter()
                        .filter_map(|ip| ip.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default(),
        })
    }

    async fn reload(&self) -> Result<(), AuthError> {
        // Clear the cache
        cached::clear!();
        Ok(())
    }
}

// Helper function to verify password using Argon2
fn verify_password(password: &str, hash: &str) -> bool {
    match argon2::verify_encoded(hash, password.as_bytes()) {
        Ok(valid) => valid,
        Err(e) => {
            error!("Error verifying password: {}", e);
            false
        }
    }
}