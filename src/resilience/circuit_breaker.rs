//! Circuit Breaker Pattern Implementation
//!
//! Prevents cascading failures by stopping calls to failing services.
//! States: Closed (normal) → Open (failing) → Half-Open (testing recovery)

use log::info;
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Circuit breaker states
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CircuitState {
    /// Normal operation - requests flow through
    Closed = 0,
    /// Failure threshold exceeded - requests blocked
    Open = 1,
    /// Testing if service recovered - limited requests allowed
    HalfOpen = 2,
}

impl From<u8> for CircuitState {
    fn from(v: u8) -> Self {
        match v {
            0 => CircuitState::Closed,
            1 => CircuitState::Open,
            2 => CircuitState::HalfOpen,
            _ => CircuitState::Closed,
        }
    }
}

/// Circuit breaker configuration
#[derive(Debug, Clone)]
pub struct CircuitBreakerConfig {
    /// Number of failures before opening circuit
    pub failure_threshold: u32,
    /// Duration to stay open before testing
    pub open_duration: Duration,
    /// Number of successes in half-open before closing
    pub success_threshold: u32,
    /// Window for counting failures
    pub failure_window: Duration,
    /// Maximum concurrent requests in half-open state
    pub half_open_max_requests: u32,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            open_duration: Duration::from_secs(30),
            success_threshold: 3,
            failure_window: Duration::from_secs(60),
            half_open_max_requests: 3,
        }
    }
}

/// Thread-safe circuit breaker
#[derive(Debug, Clone)]
pub struct CircuitBreaker {
    inner: Arc<CircuitBreakerInner>,
}

#[derive(Debug)]
struct CircuitBreakerInner {
    state: AtomicU8,
    failure_count: AtomicU64,
    success_count: AtomicU64,
    half_open_requests: AtomicU64,
    last_failure_time: RwLock<Option<Instant>>,
    state_changed_at: RwLock<Instant>,
    config: CircuitBreakerConfig,
}

impl CircuitBreaker {
    /// Create new circuit breaker with config
    pub fn new(config: CircuitBreakerConfig) -> Self {
        Self {
            inner: Arc::new(CircuitBreakerInner {
                state: AtomicU8::new(CircuitState::Closed as u8),
                failure_count: AtomicU64::new(0),
                success_count: AtomicU64::new(0),
                half_open_requests: AtomicU64::new(0),
                last_failure_time: RwLock::new(None),
                state_changed_at: RwLock::new(Instant::now()),
                config,
            }),
        }
    }

    /// Get current state
    pub fn state(&self) -> CircuitState {
        CircuitState::from(self.inner.state.load(Ordering::SeqCst))
    }

    /// Check if request should be allowed
    pub fn allow_request(&self) -> bool {
        match self.state() {
            CircuitState::Closed => true,
            CircuitState::Open => {
                // Check if enough time has passed to try half-open
                let state_changed = *self.inner.state_changed_at.blocking_read();
                if state_changed.elapsed() >= self.inner.config.open_duration {
                    self.transition_to(CircuitState::HalfOpen);
                    true
                } else {
                    false
                }
            }
            CircuitState::HalfOpen => {
                // Allow limited requests in half-open
                let current = self.inner.half_open_requests.fetch_add(1, Ordering::SeqCst);
                current < self.inner.config.half_open_max_requests as u64
            }
        }
    }

    /// Check if request should be allowed (async version)
    pub async fn allow_request_async(&self) -> bool {
        match self.state() {
            CircuitState::Closed => true,
            CircuitState::Open => {
                let state_changed = *self.inner.state_changed_at.read().await;
                if state_changed.elapsed() >= self.inner.config.open_duration {
                    self.transition_to_async(CircuitState::HalfOpen).await;
                    true
                } else {
                    false
                }
            }
            CircuitState::HalfOpen => {
                let current = self.inner.half_open_requests.fetch_add(1, Ordering::SeqCst);
                current < self.inner.config.half_open_max_requests as u64
            }
        }
    }

    /// Record a successful operation
    pub fn record_success(&self) {
        match self.state() {
            CircuitState::Closed => {
                // Reset failure count on success
                self.inner.failure_count.store(0, Ordering::SeqCst);
            }
            CircuitState::HalfOpen => {
                let successes = self.inner.success_count.fetch_add(1, Ordering::SeqCst) + 1;
                if successes >= self.inner.config.success_threshold as u64 {
                    self.transition_to(CircuitState::Closed);
                }
            }
            CircuitState::Open => {
                // Shouldn't happen, but ignore
            }
        }
    }

    /// Record a failed operation
    pub fn record_failure(&self) {
        match self.state() {
            CircuitState::Closed => {
                let failures = self.inner.failure_count.fetch_add(1, Ordering::SeqCst) + 1;

                // Update last failure time
                if let Ok(mut last) = self.inner.last_failure_time.try_write() {
                    *last = Some(Instant::now());
                }

                if failures >= self.inner.config.failure_threshold as u64 {
                    self.transition_to(CircuitState::Open);
                }
            }
            CircuitState::HalfOpen => {
                // Any failure in half-open goes back to open
                self.transition_to(CircuitState::Open);
            }
            CircuitState::Open => {
                // Already open, ignore
            }
        }
    }

    /// Transition to new state
    fn transition_to(&self, new_state: CircuitState) {
        let old_state = self.inner.state.swap(new_state as u8, Ordering::SeqCst);

        if old_state != new_state as u8 {
            // Reset counters on state change
            self.inner.failure_count.store(0, Ordering::SeqCst);
            self.inner.success_count.store(0, Ordering::SeqCst);
            self.inner.half_open_requests.store(0, Ordering::SeqCst);

            if let Ok(mut changed_at) = self.inner.state_changed_at.try_write() {
                *changed_at = Instant::now();
            }

            info!(
                "Circuit breaker state transition: {:?} -> {:?}",
                CircuitState::from(old_state),
                new_state
            );
        }
    }

    /// Transition to new state (async version)
    async fn transition_to_async(&self, new_state: CircuitState) {
        let old_state = self.inner.state.swap(new_state as u8, Ordering::SeqCst);

        if old_state != new_state as u8 {
            self.inner.failure_count.store(0, Ordering::SeqCst);
            self.inner.success_count.store(0, Ordering::SeqCst);
            self.inner.half_open_requests.store(0, Ordering::SeqCst);

            let mut changed_at = self.inner.state_changed_at.write().await;
            *changed_at = Instant::now();

            info!(
                "Circuit breaker state transition: {:?} -> {:?}",
                CircuitState::from(old_state),
                new_state
            );
        }
    }

    /// Manually reset circuit breaker to closed state
    pub fn reset(&self) {
        self.transition_to(CircuitState::Closed);
    }

    /// Get failure count
    pub fn failure_count(&self) -> u64 {
        self.inner.failure_count.load(Ordering::SeqCst)
    }

    /// Get success count (relevant in half-open state)
    pub fn success_count(&self) -> u64 {
        self.inner.success_count.load(Ordering::SeqCst)
    }

    /// Check if circuit is open (failing)
    pub fn is_open(&self) -> bool {
        self.state() == CircuitState::Open
    }

    /// Check if circuit is closed (healthy)
    pub fn is_closed(&self) -> bool {
        self.state() == CircuitState::Closed
    }
}

/// Execute operation with circuit breaker protection
pub async fn with_circuit_breaker<F, Fut, T, E>(
    cb: &CircuitBreaker,
    operation: F,
) -> Result<T, CircuitBreakerError<E>>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<T, E>>,
{
    if !cb.allow_request_async().await {
        return Err(CircuitBreakerError::Open);
    }

    match operation().await {
        Ok(result) => {
            cb.record_success();
            Ok(result)
        }
        Err(e) => {
            cb.record_failure();
            Err(CircuitBreakerError::Operation(e))
        }
    }
}

/// Circuit breaker error wrapper
#[derive(Debug)]
pub enum CircuitBreakerError<E> {
    /// Circuit is open, request not attempted
    Open,
    /// Operation failed
    Operation(E),
}

impl<E: std::fmt::Display> std::fmt::Display for CircuitBreakerError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Open => write!(f, "Circuit breaker is open"),
            Self::Operation(e) => write!(f, "Operation failed: {}", e),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for CircuitBreakerError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Open => None,
            Self::Operation(e) => Some(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_circuit_breaker_closed_state() {
        let cb = CircuitBreaker::new(CircuitBreakerConfig::default());
        assert!(cb.is_closed());
        assert!(cb.allow_request());

        cb.record_success();
        assert!(cb.is_closed());
    }

    #[test]
    fn test_circuit_breaker_opens_on_failures() {
        let config = CircuitBreakerConfig {
            failure_threshold: 3,
            ..Default::default()
        };
        let cb = CircuitBreaker::new(config);

        cb.record_failure();
        cb.record_failure();
        assert!(cb.is_closed());

        cb.record_failure();
        assert!(cb.is_open());
    }

    #[test]
    fn test_circuit_breaker_blocks_when_open() {
        let config = CircuitBreakerConfig {
            failure_threshold: 1,
            open_duration: Duration::from_secs(60),
            ..Default::default()
        };
        let cb = CircuitBreaker::new(config);

        cb.record_failure();
        assert!(cb.is_open());
        assert!(!cb.allow_request());
    }

    #[test]
    fn test_circuit_breaker_reset() {
        let config = CircuitBreakerConfig {
            failure_threshold: 1,
            ..Default::default()
        };
        let cb = CircuitBreaker::new(config);

        cb.record_failure();
        assert!(cb.is_open());

        cb.reset();
        assert!(cb.is_closed());
    }
}
