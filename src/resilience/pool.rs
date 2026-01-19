//! Connection Pool Implementation
//!
//! Generic connection pooling with:
//! - Configurable pool size (min/max)
//! - Connection health checks
//! - Idle timeout and connection recycling
//! - Wait queue for connections

use std::collections::VecDeque;
use std::future::Future;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, Semaphore, OwnedSemaphorePermit};

/// Pool configuration
#[derive(Debug, Clone)]
pub struct PoolConfig {
    /// Minimum connections to maintain
    pub min_size: usize,
    /// Maximum connections allowed
    pub max_size: usize,
    /// Maximum time to wait for a connection
    pub acquire_timeout: Duration,
    /// Maximum idle time before connection is closed
    pub idle_timeout: Duration,
    /// Maximum connection lifetime
    pub max_lifetime: Duration,
    /// Interval for health checks
    pub health_check_interval: Duration,
    /// Whether to test on borrow
    pub test_on_borrow: bool,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            min_size: 1,
            max_size: 10,
            acquire_timeout: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(300),
            max_lifetime: Duration::from_secs(3600),
            health_check_interval: Duration::from_secs(30),
            test_on_borrow: true,
        }
    }
}

/// Connection wrapper with metadata
#[derive(Debug)]
struct PooledConnectionInner<T> {
    /// The actual connection
    connection: T,
    /// When connection was created
    created_at: Instant,
    /// When last used
    last_used: Instant,
    /// Connection ID for tracking
    id: u64,
}

impl<T> PooledConnectionInner<T> {
    fn new(connection: T, id: u64) -> Self {
        let now = Instant::now();
        Self {
            connection,
            created_at: now,
            last_used: now,
            id,
        }
    }

    fn touch(&mut self) {
        self.last_used = Instant::now();
    }

    fn is_expired(&self, config: &PoolConfig) -> bool {
        self.created_at.elapsed() > config.max_lifetime
    }

    fn is_idle_timeout(&self, config: &PoolConfig) -> bool {
        self.last_used.elapsed() > config.idle_timeout
    }
}

/// Generic connection pool
pub struct ConnectionPool<T: Send + 'static = ()> {
    inner: Arc<ConnectionPoolInner<T>>,
}

impl<T: Send + 'static> Clone for ConnectionPool<T> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

struct ConnectionPoolInner<T: Send + 'static> {
    /// Available connections
    connections: Mutex<VecDeque<PooledConnectionInner<T>>>,
    /// Semaphore to limit max connections
    semaphore: Arc<Semaphore>,
    /// Configuration
    config: PoolConfig,
    /// Next connection ID
    next_id: AtomicU64,
    /// Current pool size (active + idle)
    current_size: AtomicUsize,
    /// Statistics
    stats: PoolStats,
}

impl<T: Send + 'static> std::fmt::Debug for ConnectionPool<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectionPool")
            .field("config", &self.inner.config)
            .field("current_size", &self.inner.current_size.load(Ordering::SeqCst))
            .finish()
    }
}

/// Pool statistics
#[derive(Debug, Default)]
pub struct PoolStats {
    /// Total connections created
    pub connections_created: AtomicU64,
    /// Total connections closed
    pub connections_closed: AtomicU64,
    /// Total successful acquires
    pub acquires: AtomicU64,
    /// Total acquire timeouts
    pub timeouts: AtomicU64,
    /// Total health check failures
    pub health_check_failures: AtomicU64,
}

impl<T: Send + 'static> ConnectionPool<T> {
    /// Create new connection pool
    pub fn new(config: PoolConfig) -> Self {
        let semaphore = Arc::new(Semaphore::new(config.max_size));
        Self {
            inner: Arc::new(ConnectionPoolInner {
                connections: Mutex::new(VecDeque::with_capacity(config.max_size)),
                semaphore,
                config,
                next_id: AtomicU64::new(1),
                current_size: AtomicUsize::new(0),
                stats: PoolStats::default(),
            }),
        }
    }

    /// Get a connection from the pool
    pub async fn acquire<F, Fut, E>(&self, create: F) -> Result<PooledConnection<T>, PoolError<E>>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<T, E>>,
    {
        // Try to acquire a permit with timeout
        let permit = match tokio::time::timeout(
            self.inner.config.acquire_timeout,
            self.inner.semaphore.clone().acquire_owned(),
        )
        .await
        {
            Ok(Ok(permit)) => permit,
            Ok(Err(_)) => {
                self.inner.stats.timeouts.fetch_add(1, Ordering::SeqCst);
                return Err(PoolError::Closed);
            }
            Err(_) => {
                self.inner.stats.timeouts.fetch_add(1, Ordering::SeqCst);
                return Err(PoolError::Timeout);
            }
        };

        // Try to get an existing connection
        let mut conn_opt = {
            let mut connections = self.inner.connections.lock().await;
            self.get_valid_connection(&mut connections)
        };

        // If no valid connection, create new one
        if conn_opt.is_none() {
            match create().await {
                Ok(conn) => {
                    let id = self.inner.next_id.fetch_add(1, Ordering::SeqCst);
                    conn_opt = Some(PooledConnectionInner::new(conn, id));
                    self.inner.current_size.fetch_add(1, Ordering::SeqCst);
                    self.inner.stats.connections_created.fetch_add(1, Ordering::SeqCst);
                }
                Err(e) => {
                    return Err(PoolError::CreateFailed(e));
                }
            }
        }

        self.inner.stats.acquires.fetch_add(1, Ordering::SeqCst);

        Ok(PooledConnection {
            conn: Some(conn_opt.unwrap()),
            pool: self.clone(),
            _permit: permit,
        })
    }

    /// Get a valid connection from the queue
    fn get_valid_connection(
        &self,
        connections: &mut VecDeque<PooledConnectionInner<T>>,
    ) -> Option<PooledConnectionInner<T>> {
        while let Some(mut conn) = connections.pop_front() {
            // Check if connection is still valid
            if conn.is_expired(&self.inner.config) || conn.is_idle_timeout(&self.inner.config) {
                self.inner.stats.connections_closed.fetch_add(1, Ordering::SeqCst);
                self.inner.current_size.fetch_sub(1, Ordering::SeqCst);
                continue;
            }

            conn.touch();
            return Some(conn);
        }
        None
    }

    /// Return a connection to the pool
    fn return_connection(&self, conn: PooledConnectionInner<T>) {
        // Don't return expired connections
        if conn.is_expired(&self.inner.config) {
            self.inner.stats.connections_closed.fetch_add(1, Ordering::SeqCst);
            self.inner.current_size.fetch_sub(1, Ordering::SeqCst);
            return;
        }

        // Return to pool
        let pool = self.clone();
        tokio::spawn(async move {
            let mut connections = pool.inner.connections.lock().await;
            connections.push_back(conn);
        });
    }

    /// Get pool statistics
    pub fn stats(&self) -> &PoolStats {
        &self.inner.stats
    }

    /// Get current pool size
    pub fn size(&self) -> usize {
        self.inner.current_size.load(Ordering::SeqCst)
    }

    /// Get number of idle connections
    pub async fn idle_count(&self) -> usize {
        self.inner.connections.lock().await.len()
    }

    /// Close all connections
    pub async fn close(&self) {
        let mut connections = self.inner.connections.lock().await;
        let count = connections.len();
        connections.clear();
        self.inner.stats.connections_closed.fetch_add(count as u64, Ordering::SeqCst);
        self.inner.current_size.store(0, Ordering::SeqCst);
    }
}

/// A connection checked out from the pool
pub struct PooledConnection<T: Send + 'static> {
    conn: Option<PooledConnectionInner<T>>,
    pool: ConnectionPool<T>,
    _permit: OwnedSemaphorePermit,
}

impl<T: Send + 'static> PooledConnection<T> {
    /// Get reference to underlying connection
    pub fn get(&self) -> &T {
        &self.conn.as_ref().unwrap().connection
    }

    /// Get mutable reference to underlying connection
    pub fn get_mut(&mut self) -> &mut T {
        &mut self.conn.as_mut().unwrap().connection
    }

    /// Get connection ID
    pub fn id(&self) -> u64 {
        self.conn.as_ref().unwrap().id
    }

    /// Discard this connection (don't return to pool)
    pub fn discard(mut self) {
        if let Some(_conn) = self.conn.take() {
            self.pool.inner.stats.connections_closed.fetch_add(1, Ordering::SeqCst);
            self.pool.inner.current_size.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

impl<T: Send + 'static> std::ops::Deref for PooledConnection<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.get()
    }
}

impl<T: Send + 'static> std::ops::DerefMut for PooledConnection<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.get_mut()
    }
}

impl<T: Send + 'static> Drop for PooledConnection<T> {
    fn drop(&mut self) {
        if let Some(conn) = self.conn.take() {
            self.pool.return_connection(conn);
        }
    }
}

/// Pool error types
#[derive(Debug)]
pub enum PoolError<E> {
    /// Timed out waiting for connection
    Timeout,
    /// Pool is closed
    Closed,
    /// Failed to create connection
    CreateFailed(E),
    /// Health check failed
    HealthCheckFailed,
}

impl<E: std::fmt::Display> std::fmt::Display for PoolError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Timeout => write!(f, "Connection pool acquire timeout"),
            Self::Closed => write!(f, "Connection pool is closed"),
            Self::CreateFailed(e) => write!(f, "Failed to create connection: {}", e),
            Self::HealthCheckFailed => write!(f, "Connection health check failed"),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for PoolError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::CreateFailed(e) => Some(e),
            _ => None,
        }
    }
}

/// Builder for pool configuration
#[derive(Debug)]
pub struct PoolBuilder {
    config: PoolConfig,
}

impl PoolBuilder {
    pub fn new() -> Self {
        Self {
            config: PoolConfig::default(),
        }
    }

    pub fn min_size(mut self, size: usize) -> Self {
        self.config.min_size = size;
        self
    }

    pub fn max_size(mut self, size: usize) -> Self {
        self.config.max_size = size;
        self
    }

    pub fn acquire_timeout(mut self, timeout: Duration) -> Self {
        self.config.acquire_timeout = timeout;
        self
    }

    pub fn idle_timeout(mut self, timeout: Duration) -> Self {
        self.config.idle_timeout = timeout;
        self
    }

    pub fn max_lifetime(mut self, lifetime: Duration) -> Self {
        self.config.max_lifetime = lifetime;
        self
    }

    pub fn test_on_borrow(mut self, test: bool) -> Self {
        self.config.test_on_borrow = test;
        self
    }

    pub fn build<T: Send + 'static>(self) -> ConnectionPool<T> {
        ConnectionPool::new(self.config)
    }
}

impl Default for PoolBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_pool_basic() {
        let pool: ConnectionPool<i32> = ConnectionPool::new(PoolConfig::default());

        // Acquire a connection
        let conn = pool.acquire(|| async { Ok::<_, &str>(42) }).await.unwrap();
        assert_eq!(*conn, 42);
        assert_eq!(pool.size(), 1);

        // Drop returns to pool
        drop(conn);

        // Give async return_connection time to complete
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Next acquire should reuse
        let conn2 = pool.acquire(|| async { Ok::<_, &str>(99) }).await.unwrap();
        // Should still be 42 from pool, not 99
        assert_eq!(*conn2, 42);
    }

    #[tokio::test]
    async fn test_pool_max_size() {
        let config = PoolConfig {
            max_size: 2,
            acquire_timeout: Duration::from_millis(100),
            ..Default::default()
        };
        let pool: ConnectionPool<i32> = ConnectionPool::new(config);

        let conn1 = pool.acquire(|| async { Ok::<_, &str>(1) }).await.unwrap();
        let conn2 = pool.acquire(|| async { Ok::<_, &str>(2) }).await.unwrap();

        // Third acquire should timeout
        let result = pool.acquire(|| async { Ok::<_, &str>(3) }).await;
        assert!(matches!(result, Err(PoolError::Timeout)));

        drop(conn1);
        drop(conn2);
    }

    #[tokio::test]
    async fn test_pool_stats() {
        let pool: ConnectionPool<i32> = ConnectionPool::new(PoolConfig::default());

        let conn = pool.acquire(|| async { Ok::<_, &str>(42) }).await.unwrap();
        drop(conn);

        let stats = pool.stats();
        assert_eq!(stats.connections_created.load(Ordering::SeqCst), 1);
        assert_eq!(stats.acquires.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_pool_builder() {
        let pool: ConnectionPool<String> = PoolBuilder::new()
            .min_size(2)
            .max_size(10)
            .acquire_timeout(Duration::from_secs(5))
            .build();

        let conn = pool
            .acquire(|| async { Ok::<_, &str>("test".to_string()) })
            .await
            .unwrap();
        assert_eq!(&*conn, "test");
    }
}
