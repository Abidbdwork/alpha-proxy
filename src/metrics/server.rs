use crate::core::error::ProxyError;
use hyper::{
    service::{make_service_fn, service_fn},
    Body, Request, Response, Server,
};
use prometheus::{Encoder, TextEncoder};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::oneshot;
use tracing::{error, info};

pub struct MetricsServer {
    addr: SocketAddr,
    shutdown_tx: Option<oneshot::Sender<()>>,
}

impl MetricsServer {
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            shutdown_tx: None,
        }
    }

    pub async fn start(&mut self) -> Result<(), ProxyError> {
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        self.shutdown_tx = Some(shutdown_tx);

        let service = make_service_fn(|_| async {
            Ok::<_, hyper::Error>(service_fn(|_req: Request<Body>| async {
                let encoder = TextEncoder::new();
                let metric_families = prometheus::gather();
                let mut buffer = Vec::new();
                encoder.encode(&metric_families, &mut buffer).unwrap();

                let response = Response::builder()
                    .status(200)
                    .header("Content-Type", encoder.format_type())
                    .body(Body::from(buffer))
                    .unwrap();

                Ok::<_, hyper::Error>(response)
            }))
        });

        let server = Server::bind(&self.addr).serve(service);
        let graceful = server.with_graceful_shutdown(async {
            shutdown_rx.await.ok();
        });

        info!("Metrics server listening on {}", self.addr);

        if let Err(e) = graceful.await {
            error!("Metrics server error: {}", e);
            return Err(ProxyError::Internal(format!("Metrics server error: {}", e)));
        }

        Ok(())
    }

    pub async fn shutdown(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::Client;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn test_metrics_server() {
        use tokio::net::TcpListener;

        // Bind a TCP listener to get a random port
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);  // Release the port

        // Start server
        let mut server = MetricsServer::new(addr);
        tokio::spawn(async move {
            server.start().await.unwrap();
        });

        // Wait for server to start
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

        // Test metrics endpoint
        let client = Client::new();
        let uri = format!("http://{}/metrics", addr)
            .parse()
            .unwrap();

        let response = client.get(uri).await.unwrap();
        assert_eq!(response.status(), 200);

        // Verify response contains prometheus metrics
        let body_bytes = hyper::body::to_bytes(response.into_body())
            .await
            .unwrap();
        let body = String::from_utf8(body_bytes.to_vec()).unwrap();
        assert!(body.contains("# HELP"));
    }
}