#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{auth::*, error::ProxyError};
    use hyper::{Body, Client, Request, StatusCode};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use tokio::net::TcpStream;
    use mockall::predicate::*;
    use mockall::mock;
    use native_tls::{Identity, TlsConnector};

    mock! {
        AuthBackend {}
        #[async_trait]
        impl AuthBackend for AuthBackend {
            async fn authenticate(&self, username: &str, password: &str) -> Result<AuthInfo, AuthError>;
            async fn reload(&self) -> Result<(), AuthError>;
        }
    }

    async fn setup_test_proxy() -> (HttpProxy, SocketAddr) {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0);
        let mock_auth = Arc::new(MockAuthBackend::new());
        let proxy = HttpProxy::new(addr, mock_auth).await.unwrap();
        let addr = proxy.listener.local_addr().unwrap();
        (proxy, addr)
    }

    #[tokio::test]
    async fn test_http_get_request() {
        let (proxy, addr) = setup_test_proxy().await;
        
        // Start proxy server
        tokio::spawn(async move {
            proxy.run().await.unwrap();
        });

        // Create client with proxy
        let client = Client::builder()
            .build::<_, hyper::Body>(HttpsConnector::new());

        // Make request through proxy
        let resp = client
            .get("http://example.com".parse().unwrap())
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_https_connect() {
        let (proxy, addr) = setup_test_proxy().await;
        
        // Start proxy server
        tokio::spawn(async move {
            proxy.run().await.unwrap();
        });

        // Create HTTPS client
        let mut connector = TlsConnector::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap();

        // Connect to proxy
        let stream = TcpStream::connect(addr).await.unwrap();
        
        // Send CONNECT request
        let connect_req = format!(
            "CONNECT example.com:443 HTTP/1.1\r\n\
             Host: example.com:443\r\n\
             \r\n"
        );
        stream.write_all(connect_req.as_bytes()).await.unwrap();

        // Read response
        let mut response = [0u8; 1024];
        let n = stream.read(&mut response).await.unwrap();
        let response = String::from_utf8_lossy(&response[..n]);
        assert!(response.starts_with("HTTP/1.1 200"));
    }

    #[tokio::test]
    async fn test_auth_required() {
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

        let proxy = HttpProxy::new(addr, Arc::new(mock_auth)).await.unwrap();
        let addr = proxy.listener.local_addr().unwrap();

        // Start proxy server
        tokio::spawn(async move {
            proxy.run().await.unwrap();
        });

        // Try without auth
        let client = Client::new();
        let resp = client
            .get(format!("http://{}/", addr).parse().unwrap())
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::PROXY_AUTHENTICATION_REQUIRED);
        assert!(resp.headers().contains_key("proxy-authenticate"));

        // Try with auth
        let auth = format!("Basic {}", base64::encode("testuser:testpass"));
        let resp = client
            .request(
                Request::builder()
                    .uri(format!("http://{}/", addr))
                    .header("proxy-authorization", auth)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_invalid_request() {
        let (proxy, addr) = setup_test_proxy().await;
        
        // Start proxy server
        tokio::spawn(async move {
            proxy.run().await.unwrap();
        });

        // Send invalid HTTP request
        let stream = TcpStream::connect(addr).await.unwrap();
        stream.write_all(b"INVALID REQUEST\r\n\r\n").await.unwrap();

        // Read response
        let mut response = [0u8; 1024];
        let n = stream.read(&mut response).await.unwrap();
        let response = String::from_utf8_lossy(&response[..n]);
        assert!(response.contains("400 Bad Request"));
    }

    #[tokio::test]
    async fn test_request_metrics() {
        let (proxy, addr) = setup_test_proxy().await;
        
        // Start proxy server
        tokio::spawn(async move {
            proxy.run().await.unwrap();
        });

        // Make multiple requests
        let client = Client::new();
        for _ in 0..5 {
            client
                .get(format!("http://{}/", addr).parse().unwrap())
                .await
                .unwrap();
        }

        // Check metrics
        let metrics = prometheus::gather();
        let has_requests = metrics.iter().any(|m| {
            m.get_name() == "proxy_requests_total" && 
            m.get_metric()[0].get_counter().get_value() >= 5.0
        });
        assert!(has_requests);
    }
}