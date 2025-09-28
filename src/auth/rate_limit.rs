use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::RwLock;

#[derive(Debug)]
struct RateLimitEntry {
    attempts: u32,
    first_attempt: Instant,
    last_attempt: Instant,
}

pub struct RateLimiter {
    attempts: Arc<RwLock<HashMap<String, RateLimitEntry>>>,
    max_attempts: u32,
    window_size: Duration,
}

impl RateLimiter {
    pub fn new(max_attempts: u32, window_size: Duration) -> Self {
        Self {
            attempts: Arc::new(RwLock::new(HashMap::new())),
            max_attempts,
            window_size,
        }
    }

    pub async fn check_rate_limit(&self, key: &str) -> bool {
        let now = Instant::now();
        let mut attempts = self.attempts.write().await;

        // Clean up old entries
        attempts.retain(|_, entry| {
            now.duration_since(entry.first_attempt) <= self.window_size
        });

        if let Some(entry) = attempts.get_mut(key) {
            if now.duration_since(entry.first_attempt) > self.window_size {
                // Reset if window has passed
                entry.attempts = 1;
                entry.first_attempt = now;
            } else if entry.attempts >= self.max_attempts {
                return false;
            } else {
                entry.attempts += 1;
            }
            entry.last_attempt = now;
        } else {
            attempts.insert(
                key.to_string(),
                RateLimitEntry {
                    attempts: 1,
                    first_attempt: now,
                    last_attempt: now,
                },
            );
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::sleep;

    #[tokio::test]
    async fn test_rate_limiter() {
        let limiter = RateLimiter::new(3, Duration::from_secs(1));
        let key = "test_user";

        // First three attempts should succeed
        assert!(limiter.check_rate_limit(key).await);
        assert!(limiter.check_rate_limit(key).await);
        assert!(limiter.check_rate_limit(key).await);

        // Fourth attempt should fail
        assert!(!limiter.check_rate_limit(key).await);

        // Wait for window to pass
        sleep(Duration::from_secs(1)).await;

        // Should succeed again
        assert!(limiter.check_rate_limit(key).await);
    }
}