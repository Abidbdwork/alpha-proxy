use async_trait::async_trait;
use std::net::SocketAddr;
use tokio::net::TcpListener;

pub mod http;
pub mod socks;

pub use http::HttpProxy;
pub use socks::{Socks4Proxy, Socks5Proxy};

/// Trait that all proxy protocols must implement
#[async_trait]
pub trait ProxyProtocol: Send + Sync + 'static {
    /// Returns the name of the protocol
    fn name(&self) -> &'static str;

    /// Initialize the protocol with the given configuration
    async fn init(&mut self) -> anyhow::Result<()>;

    /// Start listening for connections
    async fn listen(&self, listener: TcpListener) -> anyhow::Result<()>;

    /// Get the listening address for this protocol
    fn listen_addr(&self) -> Option<SocketAddr>;
}