use alpha_proxy::{
    auth::{AuthProvider, Credentials, User},
    core::error::AuthError,
    metrics::{ConnectionMetrics, MetricsServer},
    protocols::{
        socks::{Socks5Proxy, SOCKS5_VERSION},
        ProxyProtocol,
    },
};
use async_trait::async_trait;
use std::{net::SocketAddr, sync::Arc, time::SystemTime};
use tokio::net::{TcpListener, TcpStream};

// Mock authentication provider for testing
#[derive(Clone)]
struct MockAuthProvider {
    allow_auth: bool,
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
        if self.allow_auth && credentials.username == "testuser" {
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

    async fn update_user(&mut self, _user: &User) -> Result<(), AuthError> {
        Ok(())
    }

    async fn delete_user(&mut self, _username: &str) -> Result<(), AuthError> {
        Ok(())
    }

    async fn list_users(&self) -> Result<Vec<User>, AuthError> {
        Ok(vec![])
    }

    async fn validate_session(
        &self,
        _session: &alpha_proxy::auth::Session,
    ) -> Result<bool, AuthError> {
        Ok(self.allow_auth)
    }
}

// Helper function to create a test proxy server
async fn create_test_proxy(auth_required: bool) -> (Socks5Proxy, SocketAddr) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let auth_provider = Arc::new(MockAuthProvider { allow_auth: true }) as Arc<dyn AuthProvider>;

    let proxy = Socks5Proxy::new(Some(addr), if auth_required { Some(auth_provider) } else { None });

    (proxy, addr)
}

#[tokio::test]
async fn test_proxy_connection_without_auth() {
    let (proxy, addr) = create_test_proxy(false).await;

    // Start proxy server
    let listener = TcpListener::bind(addr).await.unwrap();
    tokio::spawn(async move {
        proxy.listen(listener).await.unwrap();
    });

    // Wait for server to start
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Connect to proxy
    let mut stream = TcpStream::connect(addr).await.unwrap();

    // Send SOCKS5 handshake
    let handshake = vec![
        SOCKS5_VERSION, // SOCKS5
        1,             // Number of auth methods
        0x00,         // NO AUTH
    ];
    use tokio::io::{AsyncWriteExt, AsyncReadExt};
    stream.write_all(&handshake).await.unwrap();

    // Read response
    let mut response = vec![0u8; 2];
    stream.read_exact(&mut response).await.unwrap();

    assert_eq!(response[0], SOCKS5_VERSION);
    assert_eq!(response[1], 0x00); // NO AUTH selected
}

#[tokio::test]
async fn test_proxy_connection_with_auth() {
    let (proxy, addr) = create_test_proxy(true).await;

    // Start proxy server
    let listener = TcpListener::bind(addr).await.unwrap();
    tokio::spawn(async move {
        proxy.listen(listener).await.unwrap();
    });

    // Wait for server to start
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Connect to proxy
    let mut stream = TcpStream::connect(addr).await.unwrap();

    // Send SOCKS5 handshake
    let handshake = vec![
        SOCKS5_VERSION, // SOCKS5
        1,             // Number of auth methods
        0x02,         // USERNAME/PASSWORD
    ];
    use tokio::io::{AsyncWriteExt, AsyncReadExt};
    stream.write_all(&handshake).await.unwrap();

    // Read response
    let mut response = vec![0u8; 2];
    stream.read_exact(&mut response).await.unwrap();

    assert_eq!(response[0], SOCKS5_VERSION);
    assert_eq!(response[1], 0x02); // USERNAME/PASSWORD selected

    // Send auth request
    let auth_request = vec![
        0x01,       // Auth version
        8,          // Username length
        b't', b'e', b's', b't', b'u', b's', b'e', b'r', // Username
        8,          // Password length
        b't', b'e', b's', b't', b'p', b'a', b's', b's', // Password
    ];
    stream.write_all(&auth_request).await.unwrap();

    // Read auth response
    let mut auth_response = vec![0u8; 2];
    stream.read_exact(&mut auth_response).await.unwrap();

    assert_eq!(auth_response[0], 0x01);
    assert_eq!(auth_response[1], 0x00); // Success
}

#[tokio::test]
async fn test_metrics_collection() {
    // Create a metrics server
    let addr = "127.0.0.1:0".parse::<SocketAddr>().unwrap();
    let mut server = MetricsServer::new(addr);

    // Start metrics server
    tokio::spawn(async move {
        server.start().await.unwrap();
    });

    // Create and use some metrics
    let metrics = ConnectionMetrics::new("test_protocol", "test_user");
    metrics.record_bytes_sent(1000);
    metrics.record_bytes_received(500);
    metrics.record_auth_success();
    metrics.record_rate_limit_hit("rps");
    metrics.record_error("test_error");

    // Allow metrics to be collected
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Verify metrics were recorded
    let metric_families = prometheus::gather();
    assert!(!metric_families.is_empty());

    // Clean up
    drop(metrics);
}

#[tokio::test]
async fn test_auth_provider() {
    let mut provider = MockAuthProvider { allow_auth: true };

    // Test initialization
    assert!(provider.init().await.is_ok());

    // Test successful authentication
    let credentials = Credentials {
        username: "testuser".to_string(),
        password: "testpass".to_string(),
    };
    let result = provider.authenticate(&credentials).await;
    assert!(result.is_ok());

    // Test failed authentication
    let bad_credentials = Credentials {
        username: "baduser".to_string(),
        password: "badpass".to_string(),
    };
    let result = provider.authenticate(&bad_credentials).await;
    assert!(result.is_err());

    // Test session validation
    let user = User {
        username: "testuser".to_string(),
        password_hash: "hash".to_string(),
        enabled: true,
        expires_at: None,
        max_connections: 10,
        bandwidth_limit: None,
        allowed_ips: vec![],
    };
    let session = alpha_proxy::auth::Session {
        user,
        created_at: SystemTime::now(),
        last_activity: SystemTime::now(),
    };
    let result = provider.validate_session(&session).await;
    assert!(result.is_ok());
    assert!(result.unwrap());
}