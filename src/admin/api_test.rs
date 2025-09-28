#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use mongodb::Client;
    use tower::ServiceExt;

    async fn setup_test_api() -> (Router, Client, String) {
        let (client, db_name) = setup_test_db().await;
        let connection_string = format!("mongodb://localhost:27017/{}", db_name);
        
        let auth_backend = Arc::new(MongoAuthBackend::new(&connection_string, &db_name).await.unwrap());
        let config = Arc::new(ServerConfig::default());
        let api = AdminApi::new(auth_backend, config);
        
        (api.router(), client, db_name)
    }

    async fn setup_test_db() -> (Client, String) {
        let client = Client::with_uri_str("mongodb://localhost:27017")
            .await
            .expect("Failed to create client");
        
        let db_name = format!("test_db_{}", uuid::Uuid::new_v4());
        client.database(&db_name);
        
        (client, db_name)
    }

    async fn cleanup_test_db(client: Client, db_name: &str) {
        client.database(db_name)
            .drop(None)
            .await
            .expect("Failed to drop test database");
    }

    #[tokio::test]
    async fn test_create_user() {
        let (app, client, db_name) = setup_test_api().await;

        let create_user = CreateUserRequest {
            username: "testuser".into(),
            password: "testpass".into(),
            max_connections: Some(20),
            rate_limit_rps: Some(200),
            allowed_ips: Some(vec!["127.0.0.1".into()]),
            expires_at: None,
        };

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/users")
                    .header("Content-Type", "application/json")
                    .body(Body::from(serde_json::to_string(&create_user).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let user_response: UserResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(user_response.username, "testuser");
        assert_eq!(user_response.max_connections, 20);

        cleanup_test_db(client, &db_name).await;
    }

    #[tokio::test]
    async fn test_get_user() {
        let (app, client, db_name) = setup_test_api().await;

        // First create a user
        let create_user = CreateUserRequest {
            username: "testuser".into(),
            password: "testpass".into(),
            max_connections: Some(20),
            rate_limit_rps: Some(200),
            allowed_ips: Some(vec!["127.0.0.1".into()]),
            expires_at: None,
        };

        app.oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/users")
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_string(&create_user).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

        // Then get the user
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/users/testuser")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let user_response: UserResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(user_response.username, "testuser");
        assert_eq!(user_response.max_connections, 20);

        cleanup_test_db(client, &db_name).await;
    }

    #[tokio::test]
    async fn test_list_users() {
        let (app, client, db_name) = setup_test_api().await;

        // Create some users
        for i in 1..=3 {
            let create_user = CreateUserRequest {
                username: format!("user{}", i),
                password: "testpass".into(),
                max_connections: Some(20),
                rate_limit_rps: Some(200),
                allowed_ips: Some(vec!["127.0.0.1".into()]),
                expires_at: None,
            };

            app.clone().oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/users")
                    .header("Content-Type", "application/json")
                    .body(Body::from(serde_json::to_string(&create_user).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        }

        // List all users
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/users")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let users: Vec<UserResponse> = serde_json::from_slice(&body).unwrap();
        assert_eq!(users.len(), 3);

        cleanup_test_db(client, &db_name).await;
    }

    #[tokio::test]
    async fn test_delete_user() {
        let (app, client, db_name) = setup_test_api().await;

        // First create a user
        let create_user = CreateUserRequest {
            username: "testuser".into(),
            password: "testpass".into(),
            max_connections: Some(20),
            rate_limit_rps: Some(200),
            allowed_ips: Some(vec!["127.0.0.1".into()]),
            expires_at: None,
        };

        app.clone().oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/users")
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_string(&create_user).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

        // Then delete the user
        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/api/users/testuser")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        // Verify user is gone
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/users/testuser")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        cleanup_test_db(client, &db_name).await;
    }
}