#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::time;

    #[tokio::test]
    async fn test_token_bucket_basic() {
        let bucket = TokenBucket::new(10, 2); // 10 tokens, 2 per second
        
        // Initial tokens should be full
        assert_eq!(bucket.tokens(), 10);
        
        // Consume 5 tokens
        assert!(bucket.try_consume(5));
        assert_eq!(bucket.tokens(), 5);
        
        // Try to consume too many tokens
        assert!(!bucket.try_consume(6));
        assert_eq!(bucket.tokens(), 5);
    }

    #[tokio::test]
    async fn test_token_bucket_refill() {
        let bucket = TokenBucket::new(10, 2); // 10 tokens, 2 per second
        
        // Consume all tokens
        assert!(bucket.try_consume(10));
        assert_eq!(bucket.tokens(), 0);
        
        // Wait for refill
        time::sleep(Duration::from_secs(1)).await;
        
        // Should have 2 new tokens
        assert_eq!(bucket.tokens(), 2);
        assert!(bucket.try_consume(2));
        assert!(!bucket.try_consume(1));
    }

    #[tokio::test]
    async fn test_rate_limiter_global() {
        let limiter = RateLimiter::new(100, 10);
        
        // Test within limit
        for _ in 0..10 {
            assert!(limiter.check_rate_limit_global().await.is_ok());
        }
        
        // Test exceeding limit
        assert!(limiter.check_rate_limit_global().await.is_err());
        
        // Wait for refill
        time::sleep(Duration::from_secs(1)).await;
        
        // Should work again
        assert!(limiter.check_rate_limit_global().await.is_ok());
    }

    #[tokio::test]
    async fn test_rate_limiter_per_user() {
        let limiter = RateLimiter::new(100, 10);
        let user = "test_user";
        
        // Test within limit
        for _ in 0..5 {
            assert!(limiter.check_rate_limit_user(user).await.is_ok());
        }
        
        // Test exceeding limit
        for _ in 0..6 {
            let result = limiter.check_rate_limit_user(user).await;
            assert!(result.is_err());
            assert!(matches!(result, Err(ProxyError::RateLimit(_))));
        }
    }

    #[tokio::test]
    async fn test_rate_limiter_multiple_users() {
        let limiter = RateLimiter::new(100, 10);
        
        // Test two users simultaneously
        for _ in 0..5 {
            assert!(limiter.check_rate_limit_user("user1").await.is_ok());
            assert!(limiter.check_rate_limit_user("user2").await.is_ok());
        }
        
        // Both users should be rate limited now
        assert!(limiter.check_rate_limit_user("user1").await.is_err());
        assert!(limiter.check_rate_limit_user("user2").await.is_err());
    }

    #[tokio::test]
    async fn test_rate_limiter_cleanup() {
        let limiter = RateLimiter::new(100, 10);
        
        // Add some users
        for i in 0..100 {
            let user = format!("user{}", i);
            assert!(limiter.check_rate_limit_user(&user).await.is_ok());
        }
        
        // Wait for cleanup interval
        time::sleep(Duration::from_secs(60)).await;
        
        // Internal map should be cleaned up
        assert!(limiter.user_buckets.read().await.len() < 100);
    }

    #[tokio::test]
    async fn test_concurrent_access() {
        let limiter = Arc::new(RateLimiter::new(1000, 100));
        let mut handles = vec![];
        
        // Spawn 10 tasks trying to consume tokens simultaneously
        for i in 0..10 {
            let limiter = limiter.clone();
            let handle = tokio::spawn(async move {
                let mut successes = 0;
                for _ in 0..20 {
                    if limiter.check_rate_limit_user(&format!("user{}", i)).await.is_ok() {
                        successes += 1;
                    }
                }
                successes
            });
            handles.push(handle);
        }
        
        // Wait for all tasks and count total successes
        let total_successes: u32 = futures::future::join_all(handles)
            .await
            .into_iter()
            .map(|r| r.unwrap())
            .sum();
        
        // Should have some successful and some failed attempts
        assert!(total_successes > 0);
        assert!(total_successes < 200);
    }

    #[tokio::test]
    async fn test_token_bucket_precision() {
        let bucket = TokenBucket::new(10, 10); // 10 tokens, 10 per second
        
        // Consume partial tokens
        assert!(bucket.try_consume_f64(0.5));
        assert_eq!(bucket.tokens(), 9.5);
        
        assert!(bucket.try_consume_f64(1.5));
        assert_eq!(bucket.tokens(), 8.0);
        
        // Wait for partial refill
        time::sleep(Duration::from_millis(500)).await;
        
        // Should have refilled approximately 5 tokens
        let tokens = bucket.tokens();
        assert!(tokens > 8.0 && tokens < 13.0);
    }
}