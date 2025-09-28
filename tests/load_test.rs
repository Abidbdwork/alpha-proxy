use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use alpha_proxy::protocols::{
    ProxyProtocol,
    http::HttpProxy,
    socks::Socks5Proxy,
};
use base64::Engine;
use futures::future::join_all;
use hyper::{Body, Client, Request, StatusCode};
use tokio::{net::{TcpListener, TcpStream}, time::Duration};
use tracing::{info, warn};

mod common;

const CONCURRENT_CONNECTIONS: usize = 1000;
const REQUEST_COUNT: usize = 10000;
const TEST_DURATION: Duration = Duration::from_secs(60);

#[tokio::test]
async fn test_http_proxy_load() {
    let (config, _) = common::setup_test_environment().await;

    // Start HTTP proxy
    let mut http_proxy = HttpProxy::new(config.listen.http_addr.unwrap().to_string());
    http_proxy.init().await.unwrap();
    let addr = http_proxy.listen_addr().unwrap();

    let listener = TcpListener::bind(addr).await.unwrap();
    let proxy_task = tokio::spawn(async move {
        http_proxy.listen(listener).await.unwrap()
    });

    // Create client pool
    let client = Client::new();
    let auth = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode("testuser:testpass")
    );

    let start = Instant::now();
    let mut success_count = 0;
    let mut error_count = 0;
    let mut total_latency = Duration::from_secs(0);
    let mut num_valid_latencies = 0;

    // Create connection pool
    let mut handles = Vec::new();
    for _ in 0..CONCURRENT_CONNECTIONS {
        let client = client.clone();
        let auth = auth.clone();
        
        let handle = tokio::spawn(async move {
            // Create request for this connection
            let request = Request::builder()
                .uri("http://example.com")
                .header("proxy-authorization", &auth)
                .body(Body::empty())
                .unwrap();

            let start = Instant::now();
            match client.request(request).await {
                Ok(resp) => {
                    if resp.status() == StatusCode::OK {
                        (true, start.elapsed())
                    } else {
                        (false, start.elapsed())
                    }
                }
                Err(_) => (false, start.elapsed()),
            }
        });
        handles.push(handle);
    }

    // Wait for all connections
    let results = join_all(handles).await;
    for result in results {
        match result {
            Ok((success, latency)) => {
                if success {
                    success_count += 1;
                    total_latency += latency;
                    num_valid_latencies += 1;
                } else {
                    error_count += 1;
                }
            }
            Err(_) => error_count += 1,
        }
    }

    let duration = start.elapsed();
    let rps = success_count as f64 / duration.as_secs_f64();
    let avg_latency = if num_valid_latencies > 0 {
        total_latency.as_millis() as f64 / num_valid_latencies as f64
    } else {
        0.0
    };

    info!(
        "Load test results:\n\
         Concurrent connections: {}\n\
         Success count: {}\n\
         Error count: {}\n\
         Duration: {:?}\n\
         Requests per second: {:.2}\n\
         Average latency: {:.2}ms",
        CONCURRENT_CONNECTIONS, success_count, error_count, duration, rps, avg_latency
    );

    assert!(success_count > 0);
    assert!(rps > 100.0);
    assert!(avg_latency < 1000.0);
}

#[tokio::test]
async fn test_memory_usage() {
    let (config, _) = common::setup_test_environment().await;

    // Start proxies
    let addr = config.listen.http_addr.unwrap();
    let mut http_proxy = HttpProxy::new(addr.to_string());
    http_proxy.init().await.unwrap();

    let addr = config.listen.socks5_addr.unwrap();
    let mut socks_proxy = Socks5Proxy::new(Some(addr), None);
    socks_proxy.init().await.unwrap();

    // Set up listeners
    let http_listener = TcpListener::bind(addr).await.unwrap();
    let socks_listener = TcpListener::bind(addr).await.unwrap();

    let http_addr = http_listener.local_addr().unwrap();
    let socks_addr = socks_listener.local_addr().unwrap();

    tokio::spawn(async move {
        http_proxy.listen(http_listener).await.unwrap();
    });
    tokio::spawn(async move {
        socks_proxy.listen(socks_listener).await.unwrap();
    });

    // Track initial memory
    let initial_memory = get_memory_usage();

    // Create many concurrent connections
    let mut connections = Vec::new();
    for _ in 0..1000 {
        match TcpStream::connect(socks_addr).await {
            Ok(stream) => connections.push(stream),
            Err(e) => warn!("Failed to create connection: {}", e),
        }
    }

    // Check memory usage
    let peak_memory = get_memory_usage();
    let memory_diff = if peak_memory > initial_memory {
        peak_memory - initial_memory
    } else {
        0
    };
    let memory_per_conn = memory_diff / connections.len() as u64;

    info!(
        "Memory usage:\n\
         Initial: {} KB\n\
         Peak: {} KB\n\
         Per connection: {} KB",
        initial_memory / 1024,
        peak_memory / 1024,
        memory_per_conn / 1024
    );

    assert!(memory_per_conn < 1024 * 1024); // Less than 1MB per connection
}

#[tokio::test]
async fn test_connection_limits() {
    let (config, _) = common::setup_test_environment().await;

    // Start proxy
    let mut http_proxy = HttpProxy::new(config.listen.http_addr.unwrap().to_string());
    http_proxy.set_max_connections(10); // Set the connection limit explicitly
    http_proxy.init().await.unwrap();
    let addr = http_proxy.listen_addr().unwrap();

    let listener = TcpListener::bind(addr).await.unwrap();
    let sync_wrapper = Arc::new(tokio::sync::Mutex::new(()));
    let sync = sync_wrapper.clone();
    tokio::spawn(async move {
        let _guard = sync.lock().await;
        http_proxy.listen(listener).await.unwrap();
    });

    let client = Client::new();
    let auth = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode("testuser:testpass")
    );

    // Wait for the proxy to lock the mutex
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    // Then wait for startup
    let _guard = sync_wrapper.lock().await;

    // Try to exceed connection limit
    let mut handles = Vec::new();
    for i in 0..20 {
        let client = client.clone();
        let auth = auth.clone();

        // Small delay between requests to ensure ordering
        tokio::time::sleep(Duration::from_millis(10)).await;
        
        let handle = tokio::spawn(async move {
            let request = Request::builder()
                .uri(format!("http://example.com/request/{}", i))
                .header("proxy-authorization", &auth)
                .body(Body::empty())
                .unwrap();

            client.request(request).await
        });
        handles.push(handle);
    }

    let results = join_all(handles).await;
    let mut success_count = 0;
    let mut service_unavailable_count = 0;
    let mut other_status_count = 0;
    let mut error_count = 0;
    let mut total_complete = 0;

    for result in results.iter() {
        total_complete += 1;
        match result {
            Err(e) => {
                error_count += 1;
                warn!("Request error: {}", e);
            }
            Ok(inner) => match inner {
                Ok(resp) => {
                    match resp.status() {
                        StatusCode::OK => success_count += 1,
                        StatusCode::SERVICE_UNAVAILABLE => service_unavailable_count += 1,
                        status => {
                            other_status_count += 1;
                            warn!("Unexpected status: {}", status);
                        }
                    }
                }
                Err(e) => {
                    error_count += 1;
                    warn!("Response error: {}", e);
                }
            }
        }
    }

    info!("Connection test results:");
    info!("  Success: {}", success_count);
    info!("  Service Unavailable: {}", service_unavailable_count);
    info!("  Other status codes: {}", other_status_count);
    info!("  Errors: {}", error_count);
    info!("  Total requests completed: {}", total_complete);
    for (i, result) in results.iter().enumerate() {
        if let Err(e) = result {
            warn!("Request {} failed: {}", i, e);
        } else if let Ok(Ok(resp)) = result {
            if resp.status() != StatusCode::OK && resp.status() != StatusCode::SERVICE_UNAVAILABLE {
                warn!("Request {} returned unexpected status: {}", i, resp.status());
            }
        }
    }
    
    // Should be limited to 10 successful connections
    assert!(success_count <= 10);
    // Should have at least some 503 responses
    assert!(service_unavailable_count > 0);
}

// Helper function to get process memory usage
fn get_memory_usage() -> u64 {
    use std::fs::File;
    use std::io::Read;

    let mut status = String::new();
    File::open("/proc/self/status")
        .unwrap()
        .read_to_string(&mut status)
        .unwrap();

    for line in status.lines() {
        if line.starts_with("VmRSS:") {
            return line
                .split_whitespace()
                .nth(1)
                .unwrap()
                .parse::<u64>()
                .unwrap();
        }
    }
    0
}