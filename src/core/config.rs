use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, path::PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Server listening addresses for different protocols
    pub listen: ListenConfig,
    /// Authentication configuration
    pub auth: AuthConfig,
    /// Metrics configuration
    pub metrics: MetricsConfig,
    /// Admin API configuration
    pub admin: AdminConfig,
    /// Global rate limiting configuration
    pub rate_limit: RateLimitConfig,
    /// TLS configuration
    pub tls: Option<TlsConfig>,
    /// IP rotation configuration
    pub ip_rotation: IpRotationConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListenConfig {
    /// SOCKS5 proxy listening address
    pub socks5_addr: Option<SocketAddr>,
    /// SOCKS4 proxy listening address
    pub socks4_addr: Option<SocketAddr>,
    /// HTTP proxy listening address
    pub http_addr: Option<SocketAddr>,
    /// HTTPS proxy listening address
    pub https_addr: Option<SocketAddr>,
    /// Transparent proxy listening address
    pub transparent_addr: Option<SocketAddr>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    /// Authentication backend type (csv, mongodb, etc.)
    pub backend: String,
    /// Path to CSV file or connection string for DB
    pub source: String,
    /// How often to reload authentication data (in seconds)
    pub reload_interval: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsConfig {
    /// Prometheus metrics listening address
    pub prometheus_addr: SocketAddr,
    /// Enable detailed per-user metrics
    pub user_metrics: bool,
    /// Enable detailed per-IP metrics
    pub ip_metrics: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminConfig {
    /// Admin API listening address
    pub api_addr: SocketAddr,
    /// JWT secret for admin authentication
    pub jwt_secret: String,
    /// Admin usernames and hashed passwords
    pub admins: Vec<AdminUser>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Global requests per second
    pub global_rps: u32,
    /// Per-user requests per second
    pub user_rps: u32,
    /// Per-IP requests per second
    pub ip_rps: u32,
    /// Maximum concurrent connections per user
    pub max_concurrent_per_user: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Path to certificate file
    pub cert_path: PathBuf,
    /// Path to private key file
    pub key_path: PathBuf,
    /// Enable ACME for automatic certificate issuance
    pub enable_acme: bool,
    /// Domain names for certificates
    pub domains: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpRotationConfig {
    /// IP rotation strategy
    pub strategy: IpRotationStrategy,
    /// Available IPv4 addresses
    pub ipv4_pool: Vec<String>,
    /// Available IPv6 subnets
    pub ipv6_subnets: Vec<String>,
    /// Sticky session duration (seconds)
    pub sticky_session_ttl: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpRotationStrategy {
    /// Randomly select IP for each connection
    Random,
    /// Sequentially select next IP from the pool
    Sequential,
    /// Rotate through IPs in a circular fashion
    RoundRobin,
    /// Select IP with least active connections
    LeastUsed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminUser {
    pub username: String,
    pub password_hash: String,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: ListenConfig::default(),
            auth: AuthConfig::default(),
            metrics: MetricsConfig::default(),
            admin: AdminConfig::default(),
            rate_limit: RateLimitConfig::default(),
            tls: None,
            ip_rotation: IpRotationConfig::default(),
        }
    }
}

// Implement remaining Default traits for config structs
impl Default for ListenConfig {
    fn default() -> Self {
        Self {
            socks5_addr: None,
            socks4_addr: None,
            http_addr: None,
            https_addr: None,
            transparent_addr: None,
        }
    }
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            backend: "csv".to_string(),
            source: "users.csv".to_string(),
            reload_interval: 300,
        }
    }
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            prometheus_addr: "127.0.0.1:9090".parse().unwrap(),
            user_metrics: true,
            ip_metrics: true,
        }
    }
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            api_addr: "127.0.0.1:8080".parse().unwrap(),
            jwt_secret: "change-me-in-production".to_string(),
            admins: vec![],
        }
    }
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            global_rps: 10000,
            user_rps: 100,
            ip_rps: 50,
            max_concurrent_per_user: 100,
        }
    }
}

impl Default for IpRotationConfig {
    fn default() -> Self {
        Self {
            strategy: IpRotationStrategy::Random,
            ipv4_pool: vec![],
            ipv6_subnets: vec![],
            sticky_session_ttl: 3600,
        }
    }
}