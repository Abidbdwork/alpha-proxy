use crate::protocols::ProxyProtocol;
use async_trait::async_trait;
use std::net::SocketAddr;
use tokio::net::TcpListener;

pub struct Socks4Proxy {
    listen_addr: Option<SocketAddr>,
}

impl Socks4Proxy {
    pub fn new(listen_addr: Option<SocketAddr>) -> Self {
        Self { listen_addr }
    }
}

#[async_trait]
impl ProxyProtocol for Socks4Proxy {
    fn name(&self) -> &'static str {
        "SOCKS4"
    }

    async fn init(&mut self) -> anyhow::Result<()> {
        // TODO: Initialize SOCKS4 specific resources
        Ok(())
    }

    async fn listen(&self, listener: TcpListener) -> anyhow::Result<()> {
        // TODO: Implement SOCKS4 connection handling
        Ok(())
    }

    fn listen_addr(&self) -> Option<SocketAddr> {
        self.listen_addr
    }
}