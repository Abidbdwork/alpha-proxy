use crate::core::error::ProxyError;
use parking_lot::RwLock;
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::time;

#[derive(Debug)]
pub struct TokenBucket {
    capacity: u32,
    tokens: u32,
    refill_rate: f64,
    last_refill: Instant,
}

impl TokenBucket {
    pub fn new(capacity: u32, refill_rate: f64) -> Self {
        Self {
            capacity,
            tokens: capacity,
            refill_rate,
            last_refill: Instant::now(),
        }
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        let new_tokens = (elapsed * self.refill_rate) as u32;
        
        if new_tokens > 0 {
            self.tokens = (self.tokens + new_tokens).min(self.capacity);
            self.last_refill = now;
        }
    }

    pub fn try_acquire(&mut self, tokens: u32) -> bool {
        self.refill();
        
        if self.tokens >= tokens {
            self.tokens -= tokens;
            true
        } else {
            false
        }
    }
}

#[derive(Debug, Clone)]
pub struct RateLimiter {
    buckets: Arc<RwLock<HashMap<String, TokenBucket>>>,
    global_bucket: Arc<RwLock<TokenBucket>>,
    default_user_capacity: u32,
    default_user_rate: f64,
}

impl RateLimiter {
    pub fn new(
        global_capacity: u32,
        global_rate: f64,
        default_user_capacity: u32,
        default_user_rate: f64,
    ) -> Self {
        Self {
            buckets: Arc::new(RwLock::new(HashMap::new())),
            global_bucket: Arc::new(RwLock::new(TokenBucket::new(global_capacity, global_rate))),
            default_user_capacity,
            default_user_rate,
        }
    }

    pub fn add_limit(&self, key: &str, capacity: u32, rate: f64) {
        let mut buckets = self.buckets.write();
        buckets.insert(key.to_string(), TokenBucket::new(capacity, rate));
    }

    pub fn remove_limit(&self, key: &str) {
        let mut buckets = self.buckets.write();
        buckets.remove(key);
    }

    pub async fn acquire(&self, key: &str, tokens: u32) -> Result<(), ProxyError> {
        // First check global limit
        if !self.global_bucket.write().try_acquire(tokens) {
            return Err(ProxyError::RateLimit("Global rate limit exceeded".into()));
        }

        // Then check user-specific limit
        let mut buckets = self.buckets.write();
        let bucket = buckets
            .entry(key.to_string())
            .or_insert_with(|| TokenBucket::new(self.default_user_capacity, self.default_user_rate));

        if !bucket.try_acquire(tokens) {
            return Err(ProxyError::RateLimit(format!(
                "Rate limit exceeded for {}",
                key
            )));
        }

        Ok(())
    }

    pub async fn wait_for_tokens(&self, key: &str, tokens: u32) -> Result<(), ProxyError> {
        let max_attempts = 10;
        let mut attempts = 0;

        while attempts < max_attempts {
            match self.acquire(key, tokens).await {
                Ok(_) => return Ok(()),
                Err(ProxyError::RateLimit(_)) => {
                    attempts += 1;
                    time::sleep(Duration::from_millis(100)).await;
                }
                Err(e) => return Err(e),
            }
        }

        Err(ProxyError::RateLimit(format!(
            "Rate limit exceeded for {} after {} attempts",
            key, max_attempts
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_token_bucket() {
        let mut bucket = TokenBucket::new(10, 2.0); // 2 tokens per second
        assert!(bucket.try_acquire(5));
        assert_eq!(bucket.tokens, 5);
        assert!(!bucket.try_acquire(6));
        assert_eq!(bucket.tokens, 5);
    }

    #[test]
    fn test_token_bucket_refill() {
        let mut bucket = TokenBucket::new(10, 2.0);
        assert!(bucket.try_acquire(8));
        assert_eq!(bucket.tokens, 2);

        // Wait for tokens to refill
        std::thread::sleep(Duration::from_secs(1));
        bucket.refill();
        assert_eq!(bucket.tokens, 4); // 2 initially + 2 after 1 second
    }

    #[tokio::test]
    async fn test_rate_limiter() {
        let limiter = RateLimiter::new(20, 10.0, 10, 2.0);

        // Test global limit
        assert!(limiter.acquire("test", 5).await.is_ok());
        assert!(limiter.acquire("test", 5).await.is_ok());
        // Should fail since we've used 10 of 20 tokens and trying to take 15
        assert!(limiter.acquire("test", 15).await.is_err());

        // Test user limit
        let limiter = RateLimiter::new(100, 10.0, 5, 1.0);
        assert!(limiter.acquire("user1", 3).await.is_ok());
        assert!(limiter.acquire("user1", 3).await.is_err());
        assert!(limiter.acquire("user2", 3).await.is_ok());
    }

    #[tokio::test]
    async fn test_custom_limits() {
        let limiter = RateLimiter::new(100, 10.0, 10, 2.0);
        limiter.add_limit("premium_user", 20, 5.0);

        // Test premium user limit
        assert!(limiter.acquire("premium_user", 15).await.is_ok());
        assert!(limiter.acquire("premium_user", 10).await.is_err());

        // Test regular user limit
        assert!(limiter.acquire("regular_user", 8).await.is_ok());
        assert!(limiter.acquire("regular_user", 5).await.is_err());
    }

    #[tokio::test]
    async fn test_wait_for_tokens() {
        let limiter = RateLimiter::new(100, 100.0, 10, 10.0);

        // Consume all tokens from user bucket
        assert!(limiter.acquire("test", 10).await.is_ok());

        // Wait for tokens should quickly succeed with high refill rate
        assert!(limiter.wait_for_tokens("test", 1).await.is_ok());
    }
}