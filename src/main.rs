use anyhow::Result;
use tracing::info;

mod admin;
mod auth;
mod core;
mod metrics;
mod protocols;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    info!("Starting alpha-proxy server...");

    // TODO: Load configuration
    // TODO: Initialize protocols
    // TODO: Start admin API
    // TODO: Start metrics collection
    // TODO: Start proxy servers

    info!("alpha-proxy server is ready!");

    // Keep the server running
    tokio::signal::ctrl_c().await?;
    info!("Shutting down...");

    Ok(())
}
