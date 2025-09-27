use crate::protocols::ProxyProtocol;
use async_trait::async_trait;
use std::net::SocketAddr;
use tokio::net::TcpListener;

pub struct HttpProxy {
    listen_addr: Option<SocketAddr>,
}

impl HttpProxy {
    pub fn new(listen_addr: Option<SocketAddr>) -> Self {
        Self { listen_addr }
    }
}

#[async_trait]
impl ProxyProtocol for HttpProxy {
    fn name(&self) -> &'static str {
        "HTTP"
    }

    async fn init(&mut self) -> anyhow::Result<()> {
        // TODO: Initialize HTTP specific resources
        Ok(())
    }

    async fn listen(&self, listener: TcpListener) -> anyhow::Result<()> {
        // TODO: Implement HTTP proxy connection handling
        Ok(())
    }

    fn listen_addr(&self) -> Option<SocketAddr> {
        self.listen_addr
    }
}