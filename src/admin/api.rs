use crate::core::{AuthBackend, AuthInfo, ConfigError, ProxyError, ServerConfig};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use prometheus::{Encoder, TextEncoder};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use tracing::{error, info};

// API types
#[derive(Debug, Serialize)]
struct ApiError {
    error: String,
}

#[derive(Debug, Deserialize)]
struct CreateUserRequest {
    username: String,
    password: String,
    max_connections: Option<u32>,
    rate_limit_rps: Option<u32>,
    allowed_ips: Option<Vec<String>>,
    expires_at: Option<String>,
}

#[derive(Debug, Serialize)]
struct UserResponse {
    username: String,
    max_connections: u32,
    rate_limit_rps: u32,
    allowed_ips: Vec<String>,
    expires_at: Option<String>,
}

#[derive(Debug, Serialize)]
struct MetricsResponse {
    total_connections: u64,
    active_connections: u64,
    bytes_transferred: u64,
    requests_per_second: f64,
}

// API state
pub struct AdminApi {
    auth_backend: Arc<dyn AuthBackend>,
    config: Arc<ServerConfig>,
}

impl AdminApi {
    pub fn new(auth_backend: Arc<dyn AuthBackend>, config: Arc<ServerConfig>) -> Self {
        Self {
            auth_backend,
            config,
        }
    }

    pub fn router(self) -> Router {
        Router::new()
            .route("/api/users", get(Self::list_users).post(Self::create_user))
            .route("/api/users/:username", 
                get(Self::get_user)
                .put(Self::update_user)
                .delete(Self::delete_user))
            .route("/api/metrics", get(Self::get_metrics))
            .route("/metrics", get(Self::prometheus_metrics))
            .layer(CorsLayer::permissive())
            .with_state(Arc::new(self))
    }

    // User management endpoints
    async fn list_users(
        State(state): State<Arc<AdminApi>>,
    ) -> Result<Json<Vec<UserResponse>>, ApiError> {
        let users = state.user_repository.list_users().await
            .map_err(|e| ApiError::from(ProxyError::Database(e.to_string())))?;

        let responses: Vec<UserResponse> = users.into_iter()
            .map(|user| UserResponse {
                username: user.username,
                max_connections: user.max_connections,
                rate_limit_rps: user.rate_limit_rps,
                allowed_ips: user.allowed_ips,
                expires_at: user.expires_at.map(|dt| dt.to_rfc3339()),
            })
            .collect();

        Ok(Json(responses))
    }

    async fn create_user(
        State(state): State<Arc<AdminApi>>,
        Json(req): Json<CreateUserRequest>,
    ) -> Result<Json<UserResponse>, ApiError> {
        // Hash password
        let password_hash = hash_password(&req.password)
            .map_err(|e| ApiError::from(ProxyError::Internal(e.to_string())))?;

        let user = User {
            username: req.username,
            password_hash,
            max_connections: req.max_connections.unwrap_or(10),
            rate_limit_rps: req.rate_limit_rps.unwrap_or(100),
            allowed_ips: req.allowed_ips.unwrap_or_default(),
            enabled: true,
            expires_at: req.expires_at
                .and_then(|s| DateTime::parse_from_rfc3339(&s).ok())
                .map(|dt| dt.with_timezone(&Utc)),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        state.user_repository.create_user(&user).await
            .map_err(|e| ApiError::from(ProxyError::Database(e.to_string())))?;

        Ok(Json(UserResponse {
            username: user.username,
            max_connections: user.max_connections,
            rate_limit_rps: user.rate_limit_rps,
            allowed_ips: user.allowed_ips,
            expires_at: user.expires_at.map(|dt| dt.to_rfc3339()),
        }))
    }

    async fn get_user(
        State(state): State<Arc<AdminApi>>,
        Path(username): Path<String>,
    ) -> Result<Json<UserResponse>, ApiError> {
        let user = state.user_repository.get_user(&username).await
            .map_err(|e| ApiError::from(ProxyError::Database(e.to_string())))?
            .ok_or_else(|| ApiError { error: "User not found".into() })?;

        Ok(Json(UserResponse {
            username: user.username,
            max_connections: user.max_connections,
            rate_limit_rps: user.rate_limit_rps,
            allowed_ips: user.allowed_ips,
            expires_at: user.expires_at.map(|dt| dt.to_rfc3339()),
        }))
    }

    async fn update_user(
        State(state): State<Arc<AdminApi>>,
        Path(username): Path<String>,
        Json(req): Json<CreateUserRequest>,
    ) -> Result<Json<UserResponse>, ApiError> {
        let mut user = state.user_repository.get_user(&username).await
            .map_err(|e| ApiError::from(ProxyError::Database(e.to_string())))?
            .ok_or_else(|| ApiError { error: "User not found".into() })?;

        // Update fields
        if let Some(password) = req.password {
            user.password_hash = hash_password(&password)
                .map_err(|e| ApiError::from(ProxyError::Internal(e.to_string())))?;
        }
        if let Some(max_conn) = req.max_connections {
            user.max_connections = max_conn;
        }
        if let Some(rps) = req.rate_limit_rps {
            user.rate_limit_rps = rps;
        }
        if let Some(ips) = req.allowed_ips {
            user.allowed_ips = ips;
        }
        if let Some(expires) = req.expires_at {
            user.expires_at = DateTime::parse_from_rfc3339(&expires)
                .map(|dt| dt.with_timezone(&Utc))
                .ok();
        }
        user.updated_at = Utc::now();

        state.user_repository.update_user(&user).await
            .map_err(|e| ApiError::from(ProxyError::Database(e.to_string())))?;

        Ok(Json(UserResponse {
            username: user.username,
            max_connections: user.max_connections,
            rate_limit_rps: user.rate_limit_rps,
            allowed_ips: user.allowed_ips,
            expires_at: user.expires_at.map(|dt| dt.to_rfc3339()),
        }))
    }

    async fn delete_user(
        State(state): State<Arc<AdminApi>>,
        Path(username): Path<String>,
    ) -> Result<StatusCode, ApiError> {
        let deleted = state.user_repository.delete_user(&username).await
            .map_err(|e| ApiError::from(ProxyError::Database(e.to_string())))?;

        if deleted {
            Ok(StatusCode::NO_CONTENT)
        } else {
            Err(ApiError { error: "User not found".into() })
        }
    }

    // Metrics endpoints
    async fn get_metrics(
        State(state): State<Arc<AdminApi>>,
    ) -> Result<Json<MetricsResponse>, ApiError> {
        // TODO: Implement metrics gathering
        Ok(Json(MetricsResponse {
            total_connections: 0,
            active_connections: 0,
            bytes_transferred: 0,
            requests_per_second: 0.0,
        }))
    }

    async fn prometheus_metrics(
        State(state): State<Arc<AdminApi>>,
    ) -> Result<String, ApiError> {
        let encoder = TextEncoder::new();
        let metric_families = prometheus::gather();
        let mut buffer = vec![];
        encoder.encode(&metric_families, &mut buffer).unwrap();
        
        Ok(String::from_utf8(buffer).unwrap())
    }
}

// Error handling
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (StatusCode::BAD_REQUEST, Json(self)).into_response()
    }
}

impl From<ProxyError> for ApiError {
    fn from(err: ProxyError) -> Self {
        Self {
            error: err.to_string(),
        }
    }
}

impl From<ConfigError> for ApiError {
    fn from(err: ConfigError) -> Self {
        Self {
            error: err.to_string(),
        }
    }
}