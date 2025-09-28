#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::auth::AuthBackend;
    use mongodb::Client;
    use tokio;

    // Helper function to create test database
    async fn setup_test_db() -> (Client, String) {
        let client = Client::with_uri_str("mongodb://localhost:27017")
            .await
            .expect("Failed to create client");
        
        let db_name = format!("test_db_{}", uuid::Uuid::new_v4());
        let db = client.database(&db_name);
        
        // Create test user
        let collection = db.collection("users");
        let user_doc = doc! {
            "username": "test_user",
            "password_hash": argon2::hash_encoded(
                "test_password".as_bytes(),
                b"salt1234",
                &argon2::Config::default()
            ).unwrap(),
            "enabled": true,
            "max_connections": 10,
            "rate_limit_rps": 100,
            "allowed_ips": ["127.0.0.1"],
            "created_at": chrono::Utc::now(),
            "updated_at": chrono::Utc::now(),
        };
        collection.insert_one(user_doc, None).await.unwrap();

        (client, db_name)
    }

    // Helper function to cleanup test database
    async fn cleanup_test_db(client: Client, db_name: &str) {
        client.database(db_name)
            .drop(None)
            .await
            .expect("Failed to drop test database");
    }

    #[tokio::test]
    async fn test_auth_success() {
        let (client, db_name) = setup_test_db().await;
        let connection_string = format!("mongodb://localhost:27017/{}", db_name);

        let backend = MongoAuthBackend::new(&connection_string, &db_name)
            .await
            .expect("Failed to create auth backend");

        let result = backend.authenticate("test_user", "test_password").await;
        assert!(result.is_ok());

        let auth_info = result.unwrap();
        assert_eq!(auth_info.username, "test_user");
        assert_eq!(auth_info.max_connections, 10);
        assert_eq!(auth_info.rate_limit_rps, 100);
        assert_eq!(auth_info.allowed_ips, vec!["127.0.0.1"]);

        cleanup_test_db(client, &db_name).await;
    }

    #[tokio::test]
    async fn test_auth_invalid_credentials() {
        let (client, db_name) = setup_test_db().await;
        let connection_string = format!("mongodb://localhost:27017/{}", db_name);

        let backend = MongoAuthBackend::new(&connection_string, &db_name)
            .await
            .expect("Failed to create auth backend");

        let result = backend.authenticate("test_user", "wrong_password").await;
        assert!(matches!(result, Err(AuthError::InvalidCredentials)));

        cleanup_test_db(client, &db_name).await;
    }

    #[tokio::test]
    async fn test_auth_nonexistent_user() {
        let (client, db_name) = setup_test_db().await;
        let connection_string = format!("mongodb://localhost:27017/{}", db_name);

        let backend = MongoAuthBackend::new(&connection_string, &db_name)
            .await
            .expect("Failed to create auth backend");

        let result = backend.authenticate("nonexistent", "test_password").await;
        assert!(matches!(result, Err(AuthError::InvalidCredentials)));

        cleanup_test_db(client, &db_name).await;
    }

    #[tokio::test]
    async fn test_auth_disabled_account() {
        let (client, db_name) = setup_test_db().await;
        let connection_string = format!("mongodb://localhost:27017/{}", db_name);

        // Disable test user
        client.database(&db_name)
            .collection("users")
            .update_one(
                doc! { "username": "test_user" },
                doc! { "$set": { "enabled": false } },
                None,
            )
            .await
            .unwrap();

        let backend = MongoAuthBackend::new(&connection_string, &db_name)
            .await
            .expect("Failed to create auth backend");

        let result = backend.authenticate("test_user", "test_password").await;
        assert!(matches!(result, Err(AuthError::AccountDisabled)));

        cleanup_test_db(client, &db_name).await;
    }

    #[tokio::test]
    async fn test_auth_expired_account() {
        let (client, db_name) = setup_test_db().await;
        let connection_string = format!("mongodb://localhost:27017/{}", db_name);

        // Set expiration to past date
        client.database(&db_name)
            .collection("users")
            .update_one(
                doc! { "username": "test_user" },
                doc! { "$set": { "expires_at": chrono::Utc::now() - chrono::Duration::days(1) } },
                None,
            )
            .await
            .unwrap();

        let backend = MongoAuthBackend::new(&connection_string, &db_name)
            .await
            .expect("Failed to create auth backend");

        let result = backend.authenticate("test_user", "test_password").await;
        assert!(matches!(result, Err(AuthError::AccountExpired)));

        cleanup_test_db(client, &db_name).await;
    }
}