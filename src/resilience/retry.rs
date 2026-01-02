//! Retry with Exponential Backoff
//!
//! Automatic retry mechanism with configurable backoff strategies:
//! - Exponential backoff with jitter
//! - Linear backoff
//! - Constant delay
//! - Custom backoff functions

use log::{debug, warn};
use std::future::Future;
use std::marker::PhantomData;
use std::time::Duration;
use rand::Rng;

/// Backoff strategy for retry delays
#[derive(Debug, Clone)]
pub enum BackoffStrategy {
    /// Constant delay between retries
    Constant(Duration),
    /// Linear increase: base * attempt
    Linear {
        base: Duration,
        max: Duration,
    },
    /// Exponential increase: base * 2^attempt with jitter
    Exponential {
        base: Duration,
        max: Duration,
        jitter: bool,
    },
    /// Custom delays for each attempt
    Custom(Vec<Duration>),
}

impl BackoffStrategy {
    /// Calculate delay for given attempt (0-indexed)
    pub fn delay(&self, attempt: u32) -> Duration {
        match self {
            BackoffStrategy::Constant(d) => *d,
            BackoffStrategy::Linear { base, max } => {
                let delay = base.saturating_mul(attempt.saturating_add(1));
                std::cmp::min(delay, *max)
            }
            BackoffStrategy::Exponential { base, max, jitter } => {
                let multiplier = 2u64.saturating_pow(attempt);
                let mut delay = Duration::from_millis(
                    base.as_millis() as u64 * multiplier
                );
                delay = std::cmp::min(delay, *max);

                if *jitter {
                    // Add random jitter up to 25% of delay
                    let jitter_range = delay.as_millis() as u64 / 4;
                    if jitter_range > 0 {
                        let jitter_ms = rand::thread_rng().gen_range(0..jitter_range);
                        delay = delay.saturating_add(Duration::from_millis(jitter_ms));
                    }
                }
                delay
            }
            BackoffStrategy::Custom(delays) => {
                delays.get(attempt as usize).copied().unwrap_or_else(|| {
                    delays.last().copied().unwrap_or(Duration::from_secs(1))
                })
            }
        }
    }
}

/// Retry policy configuration
#[derive(Debug, Clone)]
pub struct RetryPolicy {
    /// Maximum number of retry attempts
    pub max_retries: u32,
    /// Backoff strategy
    pub backoff: BackoffStrategy,
    /// Whether to retry on timeout
    pub retry_on_timeout: bool,
    /// Total maximum duration for all retries
    pub total_timeout: Option<Duration>,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: 3,
            backoff: BackoffStrategy::Exponential {
                base: Duration::from_millis(100),
                max: Duration::from_secs(10),
                jitter: true,
            },
            retry_on_timeout: true,
            total_timeout: Some(Duration::from_secs(60)),
        }
    }
}

impl RetryPolicy {
    /// Create policy with no retries
    pub fn no_retry() -> Self {
        Self {
            max_retries: 0,
            ..Default::default()
        }
    }

    /// Create policy with constant delay
    pub fn constant(retries: u32, delay: Duration) -> Self {
        Self {
            max_retries: retries,
            backoff: BackoffStrategy::Constant(delay),
            ..Default::default()
        }
    }

    /// Create policy with exponential backoff
    pub fn exponential(retries: u32, base: Duration, max: Duration) -> Self {
        Self {
            max_retries: retries,
            backoff: BackoffStrategy::Exponential {
                base,
                max,
                jitter: true,
            },
            ..Default::default()
        }
    }

    /// Create policy with linear backoff
    pub fn linear(retries: u32, base: Duration, max: Duration) -> Self {
        Self {
            max_retries: retries,
            backoff: BackoffStrategy::Linear { base, max },
            ..Default::default()
        }
    }
}

/// Retry executor with backoff
#[derive(Debug)]
pub struct RetryWithBackoff<T, E> {
    policy: RetryPolicy,
    _phantom: PhantomData<(T, E)>,
}

impl<T, E> RetryWithBackoff<T, E> {
    /// Create new retry executor
    pub fn new(policy: RetryPolicy) -> Self {
        Self {
            policy,
            _phantom: PhantomData,
        }
    }

    /// Execute operation with retry
    pub async fn execute<F, Fut>(&self, mut operation: F) -> Result<T, E>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = Result<T, E>>,
        E: std::fmt::Display,
    {
        let start = std::time::Instant::now();
        let mut attempt = 0;

        loop {
            match operation().await {
                Ok(result) => return Ok(result),
                Err(e) => {
                    if attempt >= self.policy.max_retries {
                        warn!(
                            "All {} retry attempts exhausted, giving up",
                            self.policy.max_retries
                        );
                        return Err(e);
                    }

                    // Check total timeout
                    if let Some(total) = self.policy.total_timeout {
                        if start.elapsed() >= total {
                            warn!("Total retry timeout exceeded");
                            return Err(e);
                        }
                    }

                    let delay = self.policy.backoff.delay(attempt);
                    debug!(
                        "Attempt {} failed: {}. Retrying in {:?}",
                        attempt + 1,
                        e,
                        delay
                    );

                    tokio::time::sleep(delay).await;
                    attempt += 1;
                }
            }
        }
    }

    /// Execute with condition-based retry
    pub async fn execute_if<F, Fut, P>(&self, mut operation: F, should_retry: P) -> Result<T, E>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = Result<T, E>>,
        E: std::fmt::Display,
        P: Fn(&E) -> bool,
    {
        let start = std::time::Instant::now();
        let mut attempt = 0;

        loop {
            match operation().await {
                Ok(result) => return Ok(result),
                Err(e) => {
                    if !should_retry(&e) || attempt >= self.policy.max_retries {
                        return Err(e);
                    }

                    if let Some(total) = self.policy.total_timeout {
                        if start.elapsed() >= total {
                            return Err(e);
                        }
                    }

                    let delay = self.policy.backoff.delay(attempt);
                    debug!(
                        "Attempt {} failed: {}. Retrying in {:?}",
                        attempt + 1,
                        e,
                        delay
                    );

                    tokio::time::sleep(delay).await;
                    attempt += 1;
                }
            }
        }
    }
}

/// Convenience function for simple retry with defaults
pub async fn retry<F, Fut, T, E>(operation: F) -> Result<T, E>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, E>>,
    E: std::fmt::Display,
{
    RetryWithBackoff::new(RetryPolicy::default())
        .execute(operation)
        .await
}

/// Retry with specific number of attempts
pub async fn retry_n<F, Fut, T, E>(n: u32, operation: F) -> Result<T, E>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, E>>,
    E: std::fmt::Display,
{
    let policy = RetryPolicy {
        max_retries: n,
        ..Default::default()
    };
    RetryWithBackoff::new(policy).execute(operation).await
}

/// Retry result with metadata
#[derive(Debug)]
pub struct RetryResult<T, E> {
    /// The final result
    pub result: Result<T, E>,
    /// Number of attempts made
    pub attempts: u32,
    /// Total time spent including delays
    pub total_duration: Duration,
}

/// Execute operation with retry and return metadata
pub async fn retry_with_stats<F, Fut, T, E>(
    policy: RetryPolicy,
    mut operation: F,
) -> RetryResult<T, E>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, E>>,
    E: std::fmt::Display,
{
    let start = std::time::Instant::now();
    let mut attempt = 0;

    loop {
        attempt += 1;
        match operation().await {
            Ok(result) => {
                return RetryResult {
                    result: Ok(result),
                    attempts: attempt,
                    total_duration: start.elapsed(),
                }
            }
            Err(e) => {
                if attempt > policy.max_retries {
                    return RetryResult {
                        result: Err(e),
                        attempts: attempt,
                        total_duration: start.elapsed(),
                    };
                }

                if let Some(total) = policy.total_timeout {
                    if start.elapsed() >= total {
                        return RetryResult {
                            result: Err(e),
                            attempts: attempt,
                            total_duration: start.elapsed(),
                        };
                    }
                }

                let delay = policy.backoff.delay(attempt - 1);
                tokio::time::sleep(delay).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    #[test]
    fn test_exponential_backoff() {
        let strategy = BackoffStrategy::Exponential {
            base: Duration::from_millis(100),
            max: Duration::from_secs(10),
            jitter: false,
        };

        assert_eq!(strategy.delay(0), Duration::from_millis(100));
        assert_eq!(strategy.delay(1), Duration::from_millis(200));
        assert_eq!(strategy.delay(2), Duration::from_millis(400));
        assert_eq!(strategy.delay(3), Duration::from_millis(800));
    }

    #[test]
    fn test_linear_backoff() {
        let strategy = BackoffStrategy::Linear {
            base: Duration::from_millis(100),
            max: Duration::from_secs(1),
        };

        assert_eq!(strategy.delay(0), Duration::from_millis(100));
        assert_eq!(strategy.delay(1), Duration::from_millis(200));
        assert_eq!(strategy.delay(9), Duration::from_secs(1)); // capped at max
    }

    #[test]
    fn test_constant_backoff() {
        let strategy = BackoffStrategy::Constant(Duration::from_millis(500));

        assert_eq!(strategy.delay(0), Duration::from_millis(500));
        assert_eq!(strategy.delay(5), Duration::from_millis(500));
        assert_eq!(strategy.delay(100), Duration::from_millis(500));
    }

    #[tokio::test]
    async fn test_retry_succeeds_immediately() {
        let result: Result<i32, &str> = retry(|| async { Ok(42) }).await;
        assert_eq!(result.unwrap(), 42);
    }

    #[tokio::test]
    async fn test_retry_succeeds_after_failures() {
        let counter = AtomicU32::new(0);

        let result: Result<i32, &str> = retry(|| async {
            let count = counter.fetch_add(1, Ordering::SeqCst);
            if count < 2 {
                Err("not yet")
            } else {
                Ok(42)
            }
        })
        .await;

        assert_eq!(result.unwrap(), 42);
        assert_eq!(counter.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn test_retry_exhausted() {
        let policy = RetryPolicy {
            max_retries: 2,
            backoff: BackoffStrategy::Constant(Duration::from_millis(1)),
            ..Default::default()
        };

        let result: Result<i32, &str> = RetryWithBackoff::new(policy)
            .execute(|| async { Err("always fails") })
            .await;

        assert!(result.is_err());
    }
}
