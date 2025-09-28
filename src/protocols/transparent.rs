use crate::core::{error::ProxyError, AuthInfo};
use std::{net::SocketAddr, sync::Arc};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info, warn};

pub struct TransparentProxy {
    listener: TcpListener,
    auth_backend: Arc<dyn AuthBackend>,
}

impl TransparentProxy {
    pub async fn new(
        bind_addr: SocketAddr,
        auth_backend: Arc<dyn AuthBackend>,
    ) -> Result<Self, ProxyError> {
        // Set IP_TRANSPARENT socket option
        let socket = socket2::Socket::new(
            if bind_addr.is_ipv4() {
                socket2::Domain::IPV4
            } else {
                socket2::Domain::IPV6
            },
            socket2::Type::STREAM,
            None,
        )
        .map_err(|e| ProxyError::Internal(format!("Failed to create socket: {}", e)))?;

        socket
            .set_ip_transparent(true)
            .map_err(|e| ProxyError::Internal(format!("Failed to set IP_TRANSPARENT: {}", e)))?;

        socket
            .bind(&bind_addr.into())
            .map_err(|e| ProxyError::Internal(format!("Failed to bind: {}", e)))?;

        socket
            .listen(1024)
            .map_err(|e| ProxyError::Internal(format!("Failed to listen: {}", e)))?;

        let listener: TcpListener = socket.into();

        info!("Transparent proxy listening on {}", bind_addr);

        Ok(Self {
            listener,
            auth_backend,
        })
    }

    pub async fn run(&self) -> Result<(), ProxyError> {
        loop {
            match self.listener.accept().await {
                Ok((inbound, client_addr)) => {
                    debug!("New connection from {}", client_addr);
                    let auth_backend = self.auth_backend.clone();
                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_connection(inbound, client_addr, auth_backend).await {
                            error!("Connection error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    warn!("Failed to accept connection: {}", e);
                    continue;
                }
            }
        }
    }

    async fn handle_connection(
        mut inbound: TcpStream,
        client_addr: SocketAddr,
        auth_backend: Arc<dyn AuthBackend>,
    ) -> Result<(), ProxyError> {
        // Get original destination from SO_ORIGINAL_DST
        let orig_dst = unsafe {
            let fd = std::os::unix::io::AsRawFd::as_raw_fd(&inbound);
            let mut addr: libc::sockaddr_in = std::mem::zeroed();
            let mut len = std::mem::size_of::<libc::sockaddr_in>() as u32;
            if libc::getsockopt(
                fd,
                libc::SOL_IP,
                libc::SO_ORIGINAL_DST,
                &mut addr as *mut _ as *mut _,
                &mut len as *mut _,
            ) != 0
            {
                return Err(ProxyError::Internal("Failed to get original destination".into()));
            }
            SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::from(
                    u32::from_be(addr.sin_addr.s_addr),
                )),
                u16::from_be(addr.sin_port),
            )
        };

        debug!("Original destination: {}", orig_dst);

        // Connect to original destination
        let mut outbound = TcpStream::connect(orig_dst)
            .await
            .map_err(|e| ProxyError::Internal(format!("Failed to connect to {}: {}", orig_dst, e)))?;

        // Bidirectional copy
        let (mut ri, mut wi) = inbound.split();
        let (mut ro, mut wo) = outbound.split();

        let client_to_server = tokio::io::copy(&mut ri, &mut wo);
        let server_to_client = tokio::io::copy(&mut ro, &mut wi);

        tokio::try_join!(client_to_server, server_to_client)
            .map_err(|e| ProxyError::Internal(format!("Transfer error: {}", e)))?;

        Ok(())
    }
}