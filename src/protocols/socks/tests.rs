#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{auth::*, error::ProxyError};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use tokio::net::TcpStream;
    use std::sync::Arc;
    use mockall::predicate::*;
    use mockall::mock;

    mock! {
        AuthBackend {}
        #[async_trait]
        impl AuthBackend for AuthBackend {
            async fn authenticate(&self, username: &str, password: &str) -> Result<AuthInfo, AuthError>;
            async fn reload(&self) -> Result<(), AuthError>;
        }
    }

    #[tokio::test]
    async fn test_socks5_no_auth() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0);
        let mock_auth = Arc::new(MockAuthBackend::new());
        let proxy = SocksProxy::new(addr, mock_auth).await.unwrap();
        
        let addr = proxy.listener.local_addr().unwrap();
        let mut stream = TcpStream::connect(addr).await.unwrap();

        // SOCKS5 handshake with no auth
        let handshake = [0x05, 0x01, 0x00];
        stream.write_all(&handshake).await.unwrap();

        let mut response = [0u8; 2];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(response, [0x05, 0x00]); // Version 5, No auth required
    }

    #[tokio::test]
    async fn test_socks5_username_password_auth() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0);
        let mut mock_auth = MockAuthBackend::new();
        
        mock_auth
            .expect_authenticate()
            .with(eq("testuser"), eq("testpass"))
            .times(1)
            .returning(|_, _| Ok(AuthInfo {
                username: "testuser".to_string(),
                max_connections: 10,
                rate_limit_rps: 100,
                allowed_ips: vec![],
            }));

        let proxy = SocksProxy::new(addr, Arc::new(mock_auth)).await.unwrap();
        let addr = proxy.listener.local_addr().unwrap();
        let mut stream = TcpStream::connect(addr).await.unwrap();

        // SOCKS5 handshake with username/password auth
        let handshake = [0x05, 0x01, 0x02];
        stream.write_all(&handshake).await.unwrap();

        let mut response = [0u8; 2];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(response, [0x05, 0x02]); // Version 5, Username/password auth

        // Send auth details
        let auth = [
            0x01, // Auth version
            0x08, // Username length
            b't', b'e', b's', b't', b'u', b's', b'e', b'r',
            0x08, // Password length
            b't', b'e', b's', b't', b'p', b'a', b's', b's',
        ];
        stream.write_all(&auth).await.unwrap();

        let mut auth_response = [0u8; 2];
        stream.read_exact(&mut auth_response).await.unwrap();
        assert_eq!(auth_response, [0x01, 0x00]); // Auth successful
    }

    #[tokio::test]
    async fn test_socks5_connect_command() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0);
        let mock_auth = Arc::new(MockAuthBackend::new());
        let proxy = SocksProxy::new(addr, mock_auth).await.unwrap();
        
        let addr = proxy.listener.local_addr().unwrap();
        let mut stream = TcpStream::connect(addr).await.unwrap();

        // SOCKS5 handshake
        let handshake = [0x05, 0x01, 0x00];
        stream.write_all(&handshake).await.unwrap();

        let mut response = [0u8; 2];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(response, [0x05, 0x00]);

        // CONNECT command
        let connect = [
            0x05, // Version
            0x01, // CONNECT command
            0x00, // Reserved
            0x01, // IPv4 address type
            127, 0, 0, 1, // Address
            0x00, 0x50, // Port 80
        ];
        stream.write_all(&connect).await.unwrap();

        let mut connect_response = [0u8; 10];
        stream.read_exact(&mut connect_response).await.unwrap();
        assert_eq!(connect_response[0], 0x05); // Version
        assert_eq!(connect_response[1], 0x00); // Success
    }

    #[tokio::test]
    async fn test_socks5_bind_command() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0);
        let mock_auth = Arc::new(MockAuthBackend::new());
        let proxy = SocksProxy::new(addr, mock_auth).await.unwrap();
        
        let addr = proxy.listener.local_addr().unwrap();
        let mut stream = TcpStream::connect(addr).await.unwrap();

        // SOCKS5 handshake
        let handshake = [0x05, 0x01, 0x00];
        stream.write_all(&handshake).await.unwrap();

        let mut response = [0u8; 2];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(response, [0x05, 0x00]);

        // BIND command
        let bind = [
            0x05, // Version
            0x02, // BIND command
            0x00, // Reserved
            0x01, // IPv4 address type
            127, 0, 0, 1, // Address
            0x00, 0x50, // Port 80
        ];
        stream.write_all(&bind).await.unwrap();

        let mut bind_response = [0u8; 10];
        stream.read_exact(&mut bind_response).await.unwrap();
        assert_eq!(bind_response[0], 0x05); // Version
        assert_eq!(bind_response[1], 0x00); // Success
    }

    #[tokio::test]
    async fn test_socks4_connect() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0);
        let mock_auth = Arc::new(MockAuthBackend::new());
        let proxy = SocksProxy::new(addr, mock_auth).await.unwrap();
        
        let addr = proxy.listener.local_addr().unwrap();
        let mut stream = TcpStream::connect(addr).await.unwrap();

        // SOCKS4 request
        let request = [
            0x04, // Version
            0x01, // CONNECT command
            0x00, 0x50, // Port 80
            127, 0, 0, 1, // Address
            0x00, // Null byte
        ];
        stream.write_all(&request).await.unwrap();

        let mut response = [0u8; 8];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(response[0], 0x00); // Null byte
        assert_eq!(response[1], 0x5A); // Request granted
    }

    #[tokio::test]
    async fn test_socks4a_connect() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0);
        let mock_auth = Arc::new(MockAuthBackend::new());
        let proxy = SocksProxy::new(addr, mock_auth).await.unwrap();
        
        let addr = proxy.listener.local_addr().unwrap();
        let mut stream = TcpStream::connect(addr).await.unwrap();

        // SOCKS4A request
        let mut request = vec![
            0x04, // Version
            0x01, // CONNECT command
            0x00, 0x50, // Port 80
            0x00, 0x00, 0x00, 0x01, // Address (0.0.0.1 triggers SOCKS4A)
            0x00, // Null byte
        ];
        // Append hostname
        request.extend_from_slice(b"example.com");
        request.push(0x00);

        stream.write_all(&request).await.unwrap();

        let mut response = [0u8; 8];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(response[0], 0x00); // Null byte
        assert_eq!(response[1], 0x5A); // Request granted
    }
}