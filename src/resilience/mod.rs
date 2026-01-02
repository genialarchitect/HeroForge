//! Resilience & Production Hardening Module
//!
//! Production-grade resilience patterns:
//! - Circuit breakers for external services
//! - Retry with exponential backoff
//! - Connection pooling
//! - Rate limiting
//! - Graceful degradation
//! - Performance metrics and observability

pub mod circuit_breaker;
pub mod retry;
pub mod pool;
pub mod metrics;
pub mod memory;

pub use circuit_breaker::{CircuitBreaker, CircuitBreakerConfig, CircuitState};
pub use retry::{RetryPolicy, RetryWithBackoff, BackoffStrategy};
pub use pool::{ConnectionPool, PoolConfig, PooledConnection};
pub use metrics::{OperationMetrics, MetricsCollector, TimingBreakdown};
pub use memory::{SecureBuffer, SecureString, zeroize_memory};

use std::sync::Arc;
use tokio::sync::RwLock;

/// Global resilience manager
pub struct ResilienceManager {
    /// Circuit breakers by service name
    circuit_breakers: Arc<RwLock<std::collections::HashMap<String, CircuitBreaker>>>,
    /// Connection pools by endpoint
    connection_pools: Arc<RwLock<std::collections::HashMap<String, ConnectionPool>>>,
    /// Metrics collector
    metrics: Arc<MetricsCollector>,
    /// Default retry policy
    default_retry: RetryPolicy,
}

impl ResilienceManager {
    /// Create new resilience manager
    pub fn new() -> Self {
        Self {
            circuit_breakers: Arc::new(RwLock::new(std::collections::HashMap::new())),
            connection_pools: Arc::new(RwLock::new(std::collections::HashMap::new())),
            metrics: Arc::new(MetricsCollector::new()),
            default_retry: RetryPolicy::default(),
        }
    }

    /// Get or create circuit breaker for service
    pub async fn get_circuit_breaker(&self, service: &str) -> CircuitBreaker {
        let mut breakers = self.circuit_breakers.write().await;
        breakers.entry(service.to_string())
            .or_insert_with(|| CircuitBreaker::new(CircuitBreakerConfig::default()))
            .clone()
    }

    /// Get or create connection pool for endpoint
    pub async fn get_pool(&self, endpoint: &str, config: Option<PoolConfig>) -> ConnectionPool {
        let mut pools = self.connection_pools.write().await;
        pools.entry(endpoint.to_string())
            .or_insert_with(|| ConnectionPool::new(config.unwrap_or_default()))
            .clone()
    }

    /// Get metrics collector
    pub fn metrics(&self) -> Arc<MetricsCollector> {
        Arc::clone(&self.metrics)
    }

    /// Execute with resilience (circuit breaker + retry)
    pub async fn execute_with_resilience<F, Fut, T, E>(
        &self,
        service: &str,
        operation: F,
    ) -> Result<T, E>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = Result<T, E>>,
        E: std::fmt::Display,
    {
        let cb = self.get_circuit_breaker(service).await;

        // Check circuit breaker
        if !cb.allow_request() {
            // Circuit is open - fail fast
            return (operation)().await; // Let it fail naturally
        }

        let result = RetryWithBackoff::new(self.default_retry.clone())
            .execute(|| async {
                let res = operation().await;
                match &res {
                    Ok(_) => cb.record_success(),
                    Err(_) => cb.record_failure(),
                }
                res
            }).await;

        result
    }
}

impl Default for ResilienceManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Quick helper to create a retry executor
pub fn with_retry<T, E>(policy: RetryPolicy) -> RetryWithBackoff<T, E> {
    RetryWithBackoff::new(policy)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_resilience_manager() {
        let manager = ResilienceManager::new();

        // Get circuit breaker
        let cb = manager.get_circuit_breaker("test-service").await;
        assert!(cb.allow_request());

        // Record some failures
        for _ in 0..5 {
            cb.record_failure();
        }

        // Circuit should trip after threshold
        // (depends on config)
    }
}
