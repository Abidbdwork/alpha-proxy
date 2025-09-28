use crate::{
    auth::{AuthProvider, Credentials},
    core::error::ProxyError,
    metrics::ConnectionMetrics,
    protocols::ProxyProtocol,
};
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use bytes::{Buf, BytesMut};
use http::{
    header::{self, HeaderValue},
    Method, Request, Response, StatusCode, Uri, Version,
};
use hyper::{
    server::conn::Http,
    service::service_fn,
    upgrade::Upgraded,
    Body, Client,
};
use std::{net::SocketAddr, sync::Arc};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tracing::{debug, error, info, warn};

use std::collections::HashSet;
use tokio::sync::Mutex;

pub struct HttpProxy {
    listen_addr: Option<SocketAddr>,
    auth_provider: Option<Arc<dyn AuthProvider>>,
    client: Client<hyper::client::HttpConnector, Body>,
    active_connections: Arc<Mutex<HashSet<SocketAddr>>>,
    max_connections: usize,
}

impl HttpProxy {
    fn init(listen_addr: Option<SocketAddr>, max_connections: usize) -> Self {
        Self {
            listen_addr,
            auth_provider: None,
            client: Client::new(),
            active_connections: Arc::new(Mutex::new(HashSet::new())),
            max_connections,
        }
    }

    pub fn new(bind_addr: String) -> Self {
        Self::init(bind_addr.parse().ok(), 10)
    }

    pub fn set_max_connections(&mut self, max: usize) {
        self.max_connections = max;
    }

    async fn handle_connection(&self, stream: TcpStream, peer_addr: SocketAddr) -> anyhow::Result<()> {
        let metrics = ConnectionMetrics::new("http", "unknown");
        let mut http = Http::new();
        http.http1_keep_alive(true);

        // Check connection limit
        let mut connections = self.active_connections.lock().await;
        let current_connections = connections.len();
        debug!("Active connections: {}/{}", current_connections, self.max_connections);
        if current_connections >= self.max_connections {
            warn!("Connection limit reached: {}/{}", current_connections, self.max_connections);
            // Drop the lock immediately and return 503 error without trying to serve connection
            drop(connections);
            return Err(anyhow::anyhow!("Connection limit reached"));
        }

        // If we reach here, we are under the connection limit
        connections.insert(peer_addr);
        drop(connections);
        // Create connection cleanup handle
        let active_connections = self.active_connections.clone();
        
        let auth_provider = self.auth_provider.clone();
        let client = self.client.clone();

        let service = service_fn(move |mut req: Request<Body>| {
            let auth_provider = auth_provider.clone();
            let client = client.clone();
            let metrics = metrics.clone();

            async move {
                // Check authentication if required
                if let Some(auth) = auth_provider {
                    if let Some(credentials) = parse_proxy_auth_header(&req)? {
                        match auth.authenticate(&credentials).await {
                            Ok(user) => {
                                metrics.record_auth_success();
                                debug!("User {} authenticated successfully", user.username);
                            }
                            Err(e) => {
                                metrics.record_auth_failure();
                                error!("Authentication failed: {}", e);
                                return Ok(create_auth_required_response());
                            }
                        }
                    } else {
                        return Ok(create_auth_required_response());
                    }
                }

                if req.method() == Method::CONNECT {
                    // Handle HTTPS CONNECT
                    handle_connect(req).await
                } else {
                    // Handle HTTP requests
                    handle_http(req, client).await
                }
            }
        });

        let result = http.serve_connection(stream, service).await;
        
        // Always clean up the connection tracking
        let mut connections = active_connections.lock().await;
        connections.remove(&peer_addr);
        
        // Return the result
        result?;
        Ok(())
    }
}

#[async_trait]
impl ProxyProtocol for HttpProxy {
    fn name(&self) -> &'static str {
        "HTTP"
    }

    async fn init(&mut self) -> anyhow::Result<()> {
        Ok(())
    }

    async fn listen(&self, listener: TcpListener) -> anyhow::Result<()> {
        info!("HTTP proxy listening on {}", listener.local_addr()?);

        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    debug!("New connection from {}", addr);
                    let proxy = self.clone();
                    tokio::spawn(async move {
                        if let Err(e) = proxy.handle_connection(stream, addr).await {
                            error!("Connection error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    warn!("Failed to accept connection: {}", e);
                }
            }
        }
    }

    fn listen_addr(&self) -> Option<SocketAddr> {
        self.listen_addr
    }
}

impl Clone for HttpProxy {
    fn clone(&self) -> Self {
        Self {
            listen_addr: self.listen_addr,
            auth_provider: self.auth_provider.clone(),
            client: self.client.clone(),
            active_connections: self.active_connections.clone(),
            max_connections: self.max_connections,
        }
    }
}

// Parse Proxy-Authorization header
fn parse_proxy_auth_header(req: &Request<Body>) -> anyhow::Result<Option<Credentials>> {
    if let Some(auth_header) = req.headers().get(header::PROXY_AUTHORIZATION) {
        let auth_str = auth_header.to_str()?;
        if auth_str.starts_with("Basic ") {
            let credentials = auth_str[6..].trim();
            let decoded = BASE64.decode(credentials)?;
            let credentials_str = String::from_utf8(decoded)?;
            if let Some((username, password)) = credentials_str.split_once(':') {
                return Ok(Some(Credentials {
                    username: username.to_string(),
                    password: password.to_string(),
                }));
            }
        }
    }
    Ok(None)
}

// Create authentication required response
fn create_auth_required_response() -> Response<Body> {
    Response::builder()
        .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
        .header(
            header::PROXY_AUTHENTICATE,
            HeaderValue::from_static("Basic realm=\"Proxy\""),
        )
        .body(Body::empty())
        .unwrap()
}

// Handle HTTPS CONNECT requests
async fn handle_connect(req: Request<Body>) -> anyhow::Result<Response<Body>> {
    let addr = req.uri().authority().ok_or_else(|| {
        ProxyError::Protocol("CONNECT request missing authority".to_string())
    })?.to_string();

    // Create upgrade response
    let resp = Response::builder()
        .status(StatusCode::OK)
        .body(Body::empty())?;

    // Spawn tunnel task after upgrade
    tokio::spawn(async move {
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => {
                if let Err(e) = tunnel(upgraded, &addr).await {
                    error!("Tunnel error: {}", e);
                }
            }
            Err(e) => error!("Upgrade error: {}", e),
        }
    });

    Ok(resp)
}

// Handle HTTP requests
async fn handle_http(
    mut req: Request<Body>,
    client: Client<hyper::client::HttpConnector, Body>,
) -> anyhow::Result<Response<Body>> {
    // Remove proxy-specific headers
    req.headers_mut().remove(header::PROXY_AUTHORIZATION);
    
    // Forward the request
    let resp = client.request(req).await?;
    Ok(resp)
}

// Tunnel HTTPS connections
async fn tunnel<I>(upgraded: I, addr: &str) -> anyhow::Result<()>
where
    I: AsyncRead + AsyncWrite + Unpin,
{
    let mut server = TcpStream::connect(addr).await?;
    let mut upgraded = upgraded;

    let (mut server_rd, mut server_wr) = server.split();
    let (mut upgraded_rd, mut upgraded_wr) = tokio::io::split(upgraded);

    let client_to_server = tokio::io::copy(&mut upgraded_rd, &mut server_wr);
    let server_to_client = tokio::io::copy(&mut server_rd, &mut upgraded_wr);

    tokio::select! {
        res = client_to_server => {
            if let Ok(n) = res {
                debug!("Client to server: {} bytes transferred", n);
            }
        }
        res = server_to_client => {
            if let Ok(n) = res {
                debug!("Server to client: {} bytes transferred", n);
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::User;
    struct MockAuthProvider;

    #[async_trait]
    impl AuthProvider for MockAuthProvider {
        fn name(&self) -> &'static str {
            "mock"
        }

        async fn init(&mut self) -> Result<(), crate::core::error::AuthError> {
            Ok(())
        }

        async fn authenticate(
            &self,
            credentials: &Credentials,
        ) -> Result<User, crate::core::error::AuthError> {
            if credentials.username == "testuser" && credentials.password == "testpass" {
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
                Err(crate::core::error::AuthError::InvalidCredentials)
            }
        }

        async fn update_user(
            &mut self,
            _user: &User,
        ) -> Result<(), crate::core::error::AuthError> {
            Ok(())
        }

        async fn delete_user(
            &mut self,
            _username: &str,
        ) -> Result<(), crate::core::error::AuthError> {
            Ok(())
        }

        async fn list_users(&self) -> Result<Vec<User>, crate::core::error::AuthError> {
            Ok(vec![])
        }

        async fn validate_session(
            &self,
            _session: &crate::auth::Session,
        ) -> Result<bool, crate::core::error::AuthError> {
            Ok(true)
        }
    }

    #[tokio::test]
    async fn test_http_proxy_initialization() {
        let addr = "127.0.0.1:0".parse::<SocketAddr>().unwrap();
        let mut proxy = HttpProxy::init(Some(addr), 100);
        proxy.set_max_connections(100); // Set high limit for tests

        assert!(proxy.init().await.is_ok());
        assert_eq!(proxy.name(), "HTTP");
        assert_eq!(proxy.listen_addr(), Some(addr));
    }

    #[tokio::test]
    async fn test_proxy_auth_parsing() {
        let credentials = Credentials {
            username: "testuser".to_string(),
            password: "testpass".to_string(),
        };

        let auth_str = format!(
            "Basic {}",
            BASE64.encode(format!("{}:{}", credentials.username, credentials.password))
        );

        let req = Request::builder()
            .header(header::PROXY_AUTHORIZATION, auth_str)
            .body(Body::empty())
            .unwrap();

        let parsed = parse_proxy_auth_header(&req).unwrap().unwrap();
        assert_eq!(parsed.username, credentials.username);
        assert_eq!(parsed.password, credentials.password);
    }

    #[tokio::test]
    async fn test_auth_required_response() {
        let response = create_auth_required_response();
        assert_eq!(response.status(), StatusCode::PROXY_AUTHENTICATION_REQUIRED);
        assert!(response
            .headers()
            .contains_key(header::PROXY_AUTHENTICATE));
    }
}