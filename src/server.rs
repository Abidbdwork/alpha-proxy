use crate::{
    admin::AdminApi,
    auth::{mongodb::MongoAuthBackend, repository::UserRepository},
    core::{ConfigLoader, ServerConfig},
    protocols::{http::HttpProxy, socks::SocksProxy, transparent::TransparentProxy},
};
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{error, info};

pub struct Server {
    config: Arc<ServerConfig>,
    auth_backend: Arc<dyn AuthBackend>,
    user_repository: Arc<UserRepository>,
}

impl Server {
    pub async fn new(config_path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        // Load configuration
        let config = Arc::new(ConfigLoader::load(config_path)?);
        
        // Set up MongoDB connection
        let mongo_client = Client::with_uri_str(&config.auth.source).await?;
        let db = mongo_client.database("proxy");
        let db = Arc::new(db);

        // Initialize auth backend
        let auth_backend = Arc::new(MongoAuthBackend::new(&config.auth.source, "proxy").await?);
        let user_repository = Arc::new(UserRepository::new(db.clone()));

        Ok(Self {
            config,
            auth_backend,
            user_repository,
        })
    }

    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        let config = self.config.clone();
        let auth_backend = self.auth_backend.clone();
        let user_repository = self.user_repository.clone();

        // Start HTTP proxy if configured
        if let Some(addr) = config.listen.http_addr {
            let proxy = HttpProxy::new(addr, auth_backend.clone()).await?;
            tokio::spawn(async move {
                if let Err(e) = proxy.run().await {
                    error!("HTTP proxy error: {}", e);
                }
            });
            info!("HTTP proxy listening on {}", addr);
        }

        // Start HTTPS proxy if configured
        if let Some(addr) = config.listen.https_addr {
            let proxy = HttpProxy::new_tls(addr, auth_backend.clone(), config.tls.as_ref().unwrap())?;
            tokio::spawn(async move {
                if let Err(e) = proxy.run().await {
                    error!("HTTPS proxy error: {}", e);
                }
            });
            info!("HTTPS proxy listening on {}", addr);
        }

        // Start SOCKS5 proxy if configured
        if let Some(addr) = config.listen.socks5_addr {
            let proxy = SocksProxy::new(addr, auth_backend.clone()).await?;
            tokio::spawn(async move {
                if let Err(e) = proxy.run().await {
                    error!("SOCKS5 proxy error: {}", e);
                }
            });
            info!("SOCKS5 proxy listening on {}", addr);
        }

        // Start transparent proxy if configured
        if let Some(addr) = config.listen.transparent_addr {
            let proxy = TransparentProxy::new(addr, auth_backend.clone()).await?;
            tokio::spawn(async move {
                if let Err(e) = proxy.run().await {
                    error!("Transparent proxy error: {}", e);
                }
            });
            info!("Transparent proxy listening on {}", addr);
        }

        // Start admin API if configured
        let admin_api = AdminApi::new(auth_backend.clone(), config.clone());
        let app = admin_api.router();
        let admin_addr = config.admin.api_addr;
        
        tokio::spawn(async move {
            info!("Admin API listening on {}", admin_addr);
            axum::Server::bind(&admin_addr)
                .serve(app.into_make_service())
                .await
                .unwrap();
        });

        // Start Prometheus metrics server if configured
        let metrics_addr = config.metrics.prometheus_addr;
        tokio::spawn(async move {
            let app = Router::new()
                .route("/metrics", get(|| async { 
                    let encoder = TextEncoder::new();
                    let metric_families = prometheus::gather();
                    let mut buffer = Vec::new();
                    encoder.encode(&metric_families, &mut buffer).unwrap();
                    String::from_utf8(buffer).unwrap()
                }));

            info!("Metrics server listening on {}", metrics_addr);
            axum::Server::bind(&metrics_addr)
                .serve(app.into_make_service())
                .await
                .unwrap();
        });

        // Keep the main task running
        tokio::signal::ctrl_c().await?;
        info!("Shutting down");
        Ok(())
    }
}