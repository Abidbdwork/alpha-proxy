use crate::{
    auth::{AuthProvider, Credentials},
    core::error::ProxyError,
    protocols::ProxyProtocol,
};
use async_trait::async_trait;
use bytes::{Buf, BufMut, BytesMut};
use std::{net::SocketAddr, sync::Arc};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tracing::{debug, error, info, warn};

use super::protocol::*;

pub struct Socks5Proxy {
    listen_addr: Option<SocketAddr>,
    auth_provider: Option<Arc<dyn AuthProvider>>,
}

impl Socks5Proxy {
    pub fn new(listen_addr: Option<SocketAddr>, auth_provider: Option<Arc<dyn AuthProvider>>) -> Self {
        Self {
            listen_addr,
            auth_provider,
        }
    }

    async fn handle_connection(&self, mut stream: TcpStream) -> anyhow::Result<()> {
        // Read client greeting
        let mut buf = BytesMut::with_capacity(257);
        buf.resize(2, 0);
        stream.read_exact(&mut buf).await?;

        let version = buf[0];
        let nmethods = buf[1] as usize;

        if version != SOCKS5_VERSION {
            return Err(ProxyError::Protocol("Unsupported SOCKS version".into()).into());
        }

        buf.resize(2 + nmethods, 0);
        stream.read_exact(&mut buf[2..]).await?;

        // Check if password authentication is supported
        let auth_method = if self.auth_provider.is_some()
            && buf[2..].iter().any(|&m| m == AUTH_METHOD_PASSWORD)
        {
            AUTH_METHOD_PASSWORD
        } else if self.auth_provider.is_none() && buf[2..].iter().any(|&m| m == AUTH_METHOD_NONE) {
            AUTH_METHOD_NONE
        } else {
            AUTH_METHOD_UNACCEPTABLE
        };

        // Send auth method choice
        let mut response = BytesMut::with_capacity(2);
        response.put_u8(SOCKS5_VERSION);
        response.put_u8(auth_method);
        stream.write_all(&response).await?;

        if auth_method == AUTH_METHOD_UNACCEPTABLE {
            return Err(ProxyError::Auth("No acceptable auth method".into()).into());
        }

        // Handle authentication if required
        if auth_method == AUTH_METHOD_PASSWORD {
            self.handle_auth(&mut stream).await?;
        }

        // Read the connection request
        let request = self.read_request(&mut stream).await?;

        // Handle the request
        match request.command {
            COMMAND_CONNECT => {
                self.handle_connect(stream, request).await?;
            }
            COMMAND_BIND => {
                return Err(ProxyError::Protocol("BIND command not supported".into()).into());
            }
            COMMAND_UDP_ASSOCIATE => {
                return Err(ProxyError::Protocol("UDP ASSOCIATE not supported".into()).into());
            }
            _ => {
                return Err(ProxyError::Protocol("Unknown command".into()).into());
            }
        }

        Ok(())
    }

    async fn handle_auth(&self, stream: &mut TcpStream) -> anyhow::Result<()> {
        let mut buf = BytesMut::with_capacity(513);
        buf.resize(2, 0);
        stream.read_exact(&mut buf).await?;

        if buf[0] != 1 {
            return Err(ProxyError::Protocol("Invalid auth version".into()).into());
        }

        let ulen = buf[1] as usize;
        buf.resize(2 + ulen + 1, 0);
        stream.read_exact(&mut buf[2..]).await?;

        let plen = buf[2 + ulen] as usize;
        buf.resize(2 + ulen + 1 + plen, 0);
        stream.read_exact(&mut buf[2 + ulen + 1..]).await?;

        let username = String::from_utf8_lossy(&buf[2..2 + ulen]).to_string();
        let password = String::from_utf8_lossy(&buf[2 + ulen + 1..2 + ulen + 1 + plen]).to_string();

        let credentials = Credentials { username, password };

        if let Some(auth) = &self.auth_provider {
            match auth.authenticate(&credentials).await {
                Ok(_) => {
                    // Authentication successful
                    stream.write_all(&[0x01, 0x00]).await?;
                    Ok(())
                }
                Err(e) => {
                    // Authentication failed
                    stream.write_all(&[0x01, 0x01]).await?;
                    Err(e.into())
                }
            }
        } else {
            Err(ProxyError::Auth("No auth provider configured".into()).into())
        }
    }

    async fn read_request(&self, stream: &mut TcpStream) -> anyhow::Result<SocksRequest> {
        let mut buf = BytesMut::with_capacity(4);
        buf.resize(4, 0);
        stream.read_exact(&mut buf).await?;

        if buf[0] != SOCKS5_VERSION {
            return Err(ProxyError::Protocol("Invalid SOCKS version".into()).into());
        }

        let command = buf[1];
        // buf[2] is reserved

        let addr = match buf[3] {
            ADDR_TYPE_IPV4 => {
                let mut addr_buf = [0u8; 4];
                stream.read_exact(&mut addr_buf).await?;
                SocksAddr::Ipv4(addr_buf.into())
            }
            ADDR_TYPE_IPV6 => {
                let mut addr_buf = [0u8; 16];
                stream.read_exact(&mut addr_buf).await?;
                SocksAddr::Ipv6(addr_buf.into())
            }
            ADDR_TYPE_DOMAIN => {
                let mut len_buf = [0u8; 1];
                stream.read_exact(&mut len_buf).await?;
                let len = len_buf[0] as usize;
                let mut domain_buf = vec![0u8; len];
                stream.read_exact(&mut domain_buf).await?;
                SocksAddr::Domain(String::from_utf8_lossy(&domain_buf).to_string())
            }
            _ => {
                return Err(ProxyError::Protocol("Unsupported address type".into()).into());
            }
        };

        let mut port_buf = [0u8; 2];
        stream.read_exact(&mut port_buf).await?;
        let port = u16::from_be_bytes(port_buf);

        Ok(SocksRequest {
            command,
            address: addr,
            port,
        })
    }

    async fn handle_connect(
        &self,
        mut client_stream: TcpStream,
        request: SocksRequest,
    ) -> anyhow::Result<()> {
        // Resolve the target address
        let target_addr = match request.address {
            SocksAddr::Ipv4(addr) => SocketAddr::new(addr.into(), request.port),
            SocksAddr::Ipv6(addr) => SocketAddr::new(addr.into(), request.port),
            SocksAddr::Domain(domain) => {
                tokio::net::lookup_host(format!("{}:{}", domain, request.port))
                    .await?
                    .next()
                    .ok_or_else(|| ProxyError::Address("Could not resolve domain".into()))?
            }
        };

        // Connect to the target
        match TcpStream::connect(target_addr).await {
            Ok(mut target_stream) => {
                // Send success response
                let bind_addr = target_stream.local_addr()?;
                self.send_response(&mut client_stream, REPLY_SUCCESS, &bind_addr)
                    .await?;

                // Start proxying data
                self.proxy_data(client_stream, target_stream).await?;
                Ok(())
            }
            Err(e) => {
                // Send failure response
                let reply = match e.kind() {
                    std::io::ErrorKind::ConnectionRefused => REPLY_CONNECTION_REFUSED,
                    std::io::ErrorKind::AddrNotAvailable => REPLY_ADDRESS_TYPE_NOT_SUPPORTED,
                    std::io::ErrorKind::TimedOut => REPLY_TTL_EXPIRED,
                    _ => REPLY_GENERAL_FAILURE,
                };
                self.send_response(&mut client_stream, reply, &target_addr)
                    .await?;
                Err(e.into())
            }
        }
    }

    async fn send_response(
        &self,
        stream: &mut TcpStream,
        reply: u8,
        addr: &SocketAddr,
    ) -> anyhow::Result<()> {
        let mut response = BytesMut::with_capacity(22);
        response.put_u8(SOCKS5_VERSION);
        response.put_u8(reply);
        response.put_u8(0x00); // Reserved

        match addr {
            SocketAddr::V4(addr) => {
                response.put_u8(ADDR_TYPE_IPV4);
                response.put_slice(&addr.ip().octets());
                response.put_u16(addr.port());
            }
            SocketAddr::V6(addr) => {
                response.put_u8(ADDR_TYPE_IPV6);
                response.put_slice(&addr.ip().octets());
                response.put_u16(addr.port());
            }
        }

        stream.write_all(&response).await?;
        Ok(())
    }

    async fn proxy_data(
        &self,
        mut client_stream: TcpStream,
        mut target_stream: TcpStream,
    ) -> anyhow::Result<()> {
        let (mut client_read, mut client_write) = client_stream.split();
        let (mut target_read, mut target_write) = target_stream.split();

        let client_to_target = tokio::io::copy(&mut client_read, &mut target_write);
        let target_to_client = tokio::io::copy(&mut target_read, &mut client_write);

        tokio::select! {
            res = client_to_target => {
                if let Ok(n) = res {
                    debug!("Client to target: {} bytes transferred", n);
                }
            }
            res = target_to_client => {
                if let Ok(n) = res {
                    debug!("Target to client: {} bytes transferred", n);
                }
            }
        }

        Ok(())
    }
}

#[async_trait]
impl ProxyProtocol for Socks5Proxy {
    fn name(&self) -> &'static str {
        "SOCKS5"
    }

    async fn init(&mut self) -> anyhow::Result<()> {
        Ok(())
    }

    async fn listen(&self, listener: TcpListener) -> anyhow::Result<()> {
        info!("SOCKS5 proxy listening on {}", listener.local_addr()?);

        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    debug!("New connection from {}", addr);
                    let proxy = self.clone();
                    tokio::spawn(async move {
                        if let Err(e) = proxy.handle_connection(stream).await {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::Credentials;
    use std::net::Ipv4Addr;
    use tokio::net::TcpListener;

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
        ) -> Result<crate::auth::User, crate::core::error::AuthError> {
            if credentials.username == "testuser" && credentials.password == "testpass" {
                Ok(crate::auth::User {
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
            _user: &crate::auth::User,
        ) -> Result<(), crate::core::error::AuthError> {
            Ok(())
        }

        async fn delete_user(
            &mut self,
            _username: &str,
        ) -> Result<(), crate::core::error::AuthError> {
            Ok(())
        }

        async fn list_users(&self) -> Result<Vec<crate::auth::User>, crate::core::error::AuthError> {
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
    async fn test_socks5_proxy_initialization() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0);
        let auth_provider = Arc::new(MockAuthProvider);
        let mut proxy = Socks5Proxy::new(Some(addr), Some(auth_provider));

        assert!(proxy.init().await.is_ok());
        assert_eq!(proxy.name(), "SOCKS5");
        assert_eq!(proxy.listen_addr(), Some(addr));
    }

    #[tokio::test]
    async fn test_socks5_proxy_listener() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0);
        let listener = TcpListener::bind(addr).await.unwrap();
        let bound_addr = listener.local_addr().unwrap();

        let auth_provider = Arc::new(MockAuthProvider);
        let proxy = Socks5Proxy::new(Some(bound_addr), Some(auth_provider));

        // Spawn the listener in a separate task
        tokio::spawn(async move {
            proxy.listen(listener).await.unwrap();
        });

        // Allow some time for the listener to start
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Test connection
        let result = TcpStream::connect(bound_addr).await;
        assert!(result.is_ok());
    }
}