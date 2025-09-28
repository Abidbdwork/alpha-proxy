use mongodb::{
    bson::{doc, Document},
    Collection, Database,
};
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use std::sync::Arc;
use tracing::{debug, error};

#[derive(Debug, Serialize, Deserialize)]
pub struct User {
    pub username: String,
    pub password_hash: String,
    pub max_connections: u32,
    pub rate_limit_rps: u32,
    pub allowed_ips: Vec<String>,
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

pub struct UserRepository {
    collection: Collection<Document>,
}

impl UserRepository {
    pub fn new(db: Arc<Database>) -> Self {
        Self {
            collection: db.collection("users"),
        }
    }

    pub async fn list_users(&self) -> Result<Vec<User>, mongodb::error::Error> {
        let mut users = Vec::new();
        let mut cursor = self.collection.find(None, None).await?;

        while cursor.advance().await? {
            if let Ok(doc) = cursor.deserialize_current() {
                users.push(doc);
            }
        }

        Ok(users)
    }

    pub async fn create_user(&self, user: &User) -> Result<(), mongodb::error::Error> {
        let doc = mongodb::bson::to_document(user)?;
        self.collection.insert_one(doc, None).await?;
        debug!("Created user: {}", user.username);
        Ok(())
    }

    pub async fn get_user(&self, username: &str) -> Result<Option<User>, mongodb::error::Error> {
        let filter = doc! { "username": username };
        let result = self.collection.find_one(filter, None).await?;
        
        match result {
            Some(doc) => Ok(Some(mongodb::bson::from_document(doc)?)),
            None => Ok(None),
        }
    }

    pub async fn update_user(&self, user: &User) -> Result<bool, mongodb::error::Error> {
        let filter = doc! { "username": &user.username };
        let update = doc! {
            "$set": {
                "password_hash": &user.password_hash,
                "max_connections": user.max_connections,
                "rate_limit_rps": user.rate_limit_rps,
                "allowed_ips": &user.allowed_ips,
                "enabled": user.enabled,
                "expires_at": user.expires_at,
                "updated_at": Utc::now(),
            }
        };

        let result = self.collection.update_one(filter, update, None).await?;
        debug!("Updated user {}: matched {}", user.username, result.matched_count);
        Ok(result.matched_count > 0)
    }

    pub async fn delete_user(&self, username: &str) -> Result<bool, mongodb::error::Error> {
        let filter = doc! { "username": username };
        let result = self.collection.delete_one(filter, None).await?;
        debug!("Deleted user {}: deleted {}", username, result.deleted_count);
        Ok(result.deleted_count > 0)
    }
}