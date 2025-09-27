use lazy_static::lazy_static;
use prometheus::{
    register_histogram_vec, register_int_counter_vec, register_int_gauge_vec, HistogramVec,
    IntCounterVec, IntGaugeVec,
};

lazy_static! {
    // Connection metrics
    pub static ref ACTIVE_CONNECTIONS: IntGaugeVec = register_int_gauge_vec!(
        "proxy_active_connections",
        "Number of active connections",
        &["protocol", "user"]
    )
    .unwrap();

    pub static ref TOTAL_CONNECTIONS: IntCounterVec = register_int_counter_vec!(
        "proxy_total_connections",
        "Total number of connections handled",
        &["protocol", "user", "status"]
    )
    .unwrap();

    // Bandwidth metrics
    pub static ref BYTES_TRANSFERRED: IntCounterVec = register_int_counter_vec!(
        "proxy_bytes_transferred",
        "Total bytes transferred",
        &["protocol", "user", "direction"]
    )
    .unwrap();

    // Latency metrics
    pub static ref CONNECTION_DURATION: HistogramVec = register_histogram_vec!(
        "proxy_connection_duration_seconds",
        "Connection duration in seconds",
        &["protocol", "user"],
        vec![0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0]
    )
    .unwrap();

    // Authentication metrics
    pub static ref AUTH_ATTEMPTS: IntCounterVec = register_int_counter_vec!(
        "proxy_auth_attempts",
        "Number of authentication attempts",
        &["protocol", "status"]
    )
    .unwrap();

    // Rate limiting metrics
    pub static ref RATE_LIMIT_HITS: IntCounterVec = register_int_counter_vec!(
        "proxy_rate_limit_hits",
        "Number of rate limit hits",
        &["protocol", "user", "limit_type"]
    )
    .unwrap();

    // Protocol-specific metrics
    pub static ref PROTOCOL_ERRORS: IntCounterVec = register_int_counter_vec!(
        "proxy_protocol_errors",
        "Number of protocol-specific errors",
        &["protocol", "error_type"]
    )
    .unwrap();
}

/// Represents a connection metrics tracker
pub struct ConnectionMetrics {
    protocol: String,
    username: String,
    start_time: std::time::Instant,
}

impl ConnectionMetrics {
    pub fn new(protocol: &str, username: &str) -> Self {
        let metrics = Self {
            protocol: protocol.to_string(),
            username: username.to_string(),
            start_time: std::time::Instant::now(),
        };

        // Increment active connections
        ACTIVE_CONNECTIONS
            .with_label_values(&[&metrics.protocol, &metrics.username])
            .inc();

        // Record new connection
        TOTAL_CONNECTIONS
            .with_label_values(&[&metrics.protocol, &metrics.username, "connected"])
            .inc();

        metrics
    }

    pub fn record_bytes_sent(&self, bytes: u64) {
        BYTES_TRANSFERRED
            .with_label_values(&[&self.protocol, &self.username, "sent"])
            .inc_by(bytes);
    }

    pub fn record_bytes_received(&self, bytes: u64) {
        BYTES_TRANSFERRED
            .with_label_values(&[&self.protocol, &self.username, "received"])
            .inc_by(bytes);
    }

    pub fn record_auth_success(&self) {
        AUTH_ATTEMPTS
            .with_label_values(&[&self.protocol, "success"])
            .inc();
    }

    pub fn record_auth_failure(&self) {
        AUTH_ATTEMPTS
            .with_label_values(&[&self.protocol, "failure"])
            .inc();
    }

    pub fn record_rate_limit_hit(&self, limit_type: &str) {
        RATE_LIMIT_HITS
            .with_label_values(&[&self.protocol, &self.username, limit_type])
            .inc();
    }

    pub fn record_error(&self, error_type: &str) {
        PROTOCOL_ERRORS
            .with_label_values(&[&self.protocol, error_type])
            .inc();
    }
}

impl Drop for ConnectionMetrics {
    fn drop(&mut self) {
        // Decrement active connections
        ACTIVE_CONNECTIONS
            .with_label_values(&[&self.protocol, &self.username])
            .dec();

        // Record connection duration
        let duration = self.start_time.elapsed().as_secs_f64();
        CONNECTION_DURATION
            .with_label_values(&[&self.protocol, &self.username])
            .observe(duration);

        // Record disconnection
        TOTAL_CONNECTIONS
            .with_label_values(&[&self.protocol, &self.username, "disconnected"])
            .inc();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prometheus::Registry;

    #[test]
    fn test_connection_metrics() {
        let registry = Registry::new();

        let metrics = ConnectionMetrics::new("socks5", "testuser");

        // Test connection counting
        assert_eq!(
            1,
            ACTIVE_CONNECTIONS
                .with_label_values(&["socks5", "testuser"])
                .get()
        );

        // Test bytes tracking
        metrics.record_bytes_sent(1000);
        metrics.record_bytes_received(500);

        assert_eq!(
            1000,
            BYTES_TRANSFERRED
                .with_label_values(&["socks5", "testuser", "sent"])
                .get()
        );
        assert_eq!(
            500,
            BYTES_TRANSFERRED
                .with_label_values(&["socks5", "testuser", "received"])
                .get()
        );

        // Test auth metrics
        metrics.record_auth_success();
        assert_eq!(
            1,
            AUTH_ATTEMPTS.with_label_values(&["socks5", "success"]).get()
        );

        metrics.record_auth_failure();
        assert_eq!(
            1,
            AUTH_ATTEMPTS.with_label_values(&["socks5", "failure"]).get()
        );

        // Test rate limit metrics
        metrics.record_rate_limit_hit("rps");
        assert_eq!(
            1,
            RATE_LIMIT_HITS
                .with_label_values(&["socks5", "testuser", "rps"])
                .get()
        );

        // Test error recording
        metrics.record_error("protocol_version");
        assert_eq!(
            1,
            PROTOCOL_ERRORS
                .with_label_values(&["socks5", "protocol_version"])
                .get()
        );

        // Verify metrics are collected in the registry
        let metric_families = registry.gather();
        assert!(!metric_families.is_empty());

        // Drop the metrics and verify counters are updated
        drop(metrics);
        assert_eq!(
            0,
            ACTIVE_CONNECTIONS
                .with_label_values(&["socks5", "testuser"])
                .get()
        );
    }
}