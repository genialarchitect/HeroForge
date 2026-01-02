//! Performance Metrics and Observability
//!
//! Comprehensive metrics collection for:
//! - Operation timing and latency percentiles
//! - Success/failure rates
//! - Throughput tracking
//! - Resource utilization

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Individual operation metrics
#[derive(Debug)]
pub struct OperationMetrics {
    /// Operation name
    pub name: String,
    /// Total invocations
    pub total_count: AtomicU64,
    /// Successful invocations
    pub success_count: AtomicU64,
    /// Failed invocations
    pub failure_count: AtomicU64,
    /// Total duration (nanoseconds)
    pub total_duration_ns: AtomicU64,
    /// Min duration (nanoseconds)
    pub min_duration_ns: AtomicU64,
    /// Max duration (nanoseconds)
    pub max_duration_ns: AtomicU64,
    /// Recent latencies for percentile calculation
    recent_latencies: RwLock<Vec<u64>>,
}

impl OperationMetrics {
    /// Create new metrics for operation
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            total_count: AtomicU64::new(0),
            success_count: AtomicU64::new(0),
            failure_count: AtomicU64::new(0),
            total_duration_ns: AtomicU64::new(0),
            min_duration_ns: AtomicU64::new(u64::MAX),
            max_duration_ns: AtomicU64::new(0),
            recent_latencies: RwLock::new(Vec::with_capacity(1000)),
        }
    }

    /// Record a successful operation
    pub async fn record_success(&self, duration: Duration) {
        self.record(duration, true).await;
    }

    /// Record a failed operation
    pub async fn record_failure(&self, duration: Duration) {
        self.record(duration, false).await;
    }

    /// Record operation timing
    async fn record(&self, duration: Duration, success: bool) {
        let nanos = duration.as_nanos() as u64;

        self.total_count.fetch_add(1, Ordering::SeqCst);
        self.total_duration_ns.fetch_add(nanos, Ordering::SeqCst);

        if success {
            self.success_count.fetch_add(1, Ordering::SeqCst);
        } else {
            self.failure_count.fetch_add(1, Ordering::SeqCst);
        }

        // Update min
        let mut current_min = self.min_duration_ns.load(Ordering::SeqCst);
        while nanos < current_min {
            match self.min_duration_ns.compare_exchange_weak(
                current_min,
                nanos,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => break,
                Err(v) => current_min = v,
            }
        }

        // Update max
        let mut current_max = self.max_duration_ns.load(Ordering::SeqCst);
        while nanos > current_max {
            match self.max_duration_ns.compare_exchange_weak(
                current_max,
                nanos,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => break,
                Err(v) => current_max = v,
            }
        }

        // Store for percentiles (keep last 1000)
        let mut latencies = self.recent_latencies.write().await;
        if latencies.len() >= 1000 {
            latencies.remove(0);
        }
        latencies.push(nanos);
    }

    /// Get average duration
    pub fn avg_duration(&self) -> Duration {
        let total = self.total_duration_ns.load(Ordering::SeqCst);
        let count = self.total_count.load(Ordering::SeqCst);
        if count == 0 {
            return Duration::ZERO;
        }
        Duration::from_nanos(total / count)
    }

    /// Get min duration
    pub fn min_duration(&self) -> Duration {
        let min = self.min_duration_ns.load(Ordering::SeqCst);
        if min == u64::MAX {
            return Duration::ZERO;
        }
        Duration::from_nanos(min)
    }

    /// Get max duration
    pub fn max_duration(&self) -> Duration {
        Duration::from_nanos(self.max_duration_ns.load(Ordering::SeqCst))
    }

    /// Get success rate (0.0 - 1.0)
    pub fn success_rate(&self) -> f64 {
        let total = self.total_count.load(Ordering::SeqCst);
        if total == 0 {
            return 1.0;
        }
        self.success_count.load(Ordering::SeqCst) as f64 / total as f64
    }

    /// Get percentile latency (async)
    pub async fn percentile(&self, p: f64) -> Duration {
        let latencies = self.recent_latencies.read().await;
        if latencies.is_empty() {
            return Duration::ZERO;
        }

        let mut sorted: Vec<_> = latencies.clone();
        sorted.sort_unstable();

        let idx = ((p / 100.0) * (sorted.len() - 1) as f64).round() as usize;
        Duration::from_nanos(sorted[idx])
    }

    /// Get summary statistics
    pub async fn summary(&self) -> MetricsSummary {
        MetricsSummary {
            name: self.name.clone(),
            total_count: self.total_count.load(Ordering::SeqCst),
            success_count: self.success_count.load(Ordering::SeqCst),
            failure_count: self.failure_count.load(Ordering::SeqCst),
            success_rate: self.success_rate(),
            avg_duration: self.avg_duration(),
            min_duration: self.min_duration(),
            max_duration: self.max_duration(),
            p50: self.percentile(50.0).await,
            p95: self.percentile(95.0).await,
            p99: self.percentile(99.0).await,
        }
    }

    /// Reset all metrics
    pub async fn reset(&self) {
        self.total_count.store(0, Ordering::SeqCst);
        self.success_count.store(0, Ordering::SeqCst);
        self.failure_count.store(0, Ordering::SeqCst);
        self.total_duration_ns.store(0, Ordering::SeqCst);
        self.min_duration_ns.store(u64::MAX, Ordering::SeqCst);
        self.max_duration_ns.store(0, Ordering::SeqCst);
        self.recent_latencies.write().await.clear();
    }
}

/// Summary of metrics
#[derive(Debug, Clone)]
pub struct MetricsSummary {
    pub name: String,
    pub total_count: u64,
    pub success_count: u64,
    pub failure_count: u64,
    pub success_rate: f64,
    pub avg_duration: Duration,
    pub min_duration: Duration,
    pub max_duration: Duration,
    pub p50: Duration,
    pub p95: Duration,
    pub p99: Duration,
}

/// Detailed timing breakdown for operations
#[derive(Debug, Clone)]
pub struct TimingBreakdown {
    /// Phase timings
    pub phases: Vec<(String, Duration)>,
    /// Total duration
    pub total: Duration,
}

impl TimingBreakdown {
    /// Create new timing breakdown
    pub fn new() -> Self {
        Self {
            phases: Vec::new(),
            total: Duration::ZERO,
        }
    }

    /// Add a phase timing
    pub fn add_phase(&mut self, name: impl Into<String>, duration: Duration) {
        self.phases.push((name.into(), duration));
        self.total += duration;
    }

    /// Get percentage of total for each phase
    pub fn percentages(&self) -> Vec<(String, f64)> {
        if self.total.is_zero() {
            return self.phases.iter().map(|(n, _)| (n.clone(), 0.0)).collect();
        }

        self.phases
            .iter()
            .map(|(name, dur)| {
                let pct = dur.as_nanos() as f64 / self.total.as_nanos() as f64 * 100.0;
                (name.clone(), pct)
            })
            .collect()
    }
}

impl Default for TimingBreakdown {
    fn default() -> Self {
        Self::new()
    }
}

/// Global metrics collector
#[derive(Debug)]
pub struct MetricsCollector {
    /// Metrics by operation name
    operations: RwLock<HashMap<String, Arc<OperationMetrics>>>,
    /// Global counters
    pub global_requests: AtomicU64,
    pub global_errors: AtomicU64,
    /// Start time for uptime calculation
    started_at: Instant,
}

impl MetricsCollector {
    /// Create new metrics collector
    pub fn new() -> Self {
        Self {
            operations: RwLock::new(HashMap::new()),
            global_requests: AtomicU64::new(0),
            global_errors: AtomicU64::new(0),
            started_at: Instant::now(),
        }
    }

    /// Get or create metrics for an operation
    pub async fn operation(&self, name: &str) -> Arc<OperationMetrics> {
        // Try read lock first
        {
            let ops = self.operations.read().await;
            if let Some(metrics) = ops.get(name) {
                return Arc::clone(metrics);
            }
        }

        // Need to create
        let mut ops = self.operations.write().await;
        ops.entry(name.to_string())
            .or_insert_with(|| Arc::new(OperationMetrics::new(name)))
            .clone()
    }

    /// Record a timed operation
    pub async fn record<F, Fut, T, E>(
        &self,
        operation_name: &str,
        operation: F,
    ) -> Result<T, E>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<T, E>>,
    {
        self.global_requests.fetch_add(1, Ordering::SeqCst);

        let metrics = self.operation(operation_name).await;
        let start = Instant::now();

        let result = operation().await;
        let duration = start.elapsed();

        match &result {
            Ok(_) => metrics.record_success(duration).await,
            Err(_) => {
                metrics.record_failure(duration).await;
                self.global_errors.fetch_add(1, Ordering::SeqCst);
            }
        }

        result
    }

    /// Get all operation summaries
    pub async fn all_summaries(&self) -> Vec<MetricsSummary> {
        let ops = self.operations.read().await;
        let mut summaries = Vec::with_capacity(ops.len());

        for metrics in ops.values() {
            summaries.push(metrics.summary().await);
        }

        summaries.sort_by(|a, b| a.name.cmp(&b.name));
        summaries
    }

    /// Get uptime
    pub fn uptime(&self) -> Duration {
        self.started_at.elapsed()
    }

    /// Get global error rate
    pub fn error_rate(&self) -> f64 {
        let total = self.global_requests.load(Ordering::SeqCst);
        if total == 0 {
            return 0.0;
        }
        self.global_errors.load(Ordering::SeqCst) as f64 / total as f64
    }

    /// Reset all metrics
    pub async fn reset_all(&self) {
        let ops = self.operations.read().await;
        for metrics in ops.values() {
            metrics.reset().await;
        }
        self.global_requests.store(0, Ordering::SeqCst);
        self.global_errors.store(0, Ordering::SeqCst);
    }
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// Timer guard for automatic timing
pub struct Timer {
    start: Instant,
    metrics: Arc<OperationMetrics>,
    success: bool,
}

impl Timer {
    /// Create new timer
    pub fn new(metrics: Arc<OperationMetrics>) -> Self {
        Self {
            start: Instant::now(),
            metrics,
            success: true,
        }
    }

    /// Mark as failed
    pub fn fail(&mut self) {
        self.success = false;
    }

    /// Get elapsed time
    pub fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }
}

impl Drop for Timer {
    fn drop(&mut self) {
        let duration = self.start.elapsed();
        let metrics = Arc::clone(&self.metrics);
        let success = self.success;

        // Spawn to avoid blocking
        tokio::spawn(async move {
            if success {
                metrics.record_success(duration).await;
            } else {
                metrics.record_failure(duration).await;
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_operation_metrics() {
        let metrics = OperationMetrics::new("test");

        metrics.record_success(Duration::from_millis(100)).await;
        metrics.record_success(Duration::from_millis(200)).await;
        metrics.record_failure(Duration::from_millis(50)).await;

        assert_eq!(metrics.total_count.load(Ordering::SeqCst), 3);
        assert_eq!(metrics.success_count.load(Ordering::SeqCst), 2);
        assert_eq!(metrics.failure_count.load(Ordering::SeqCst), 1);
        assert!(metrics.success_rate() > 0.66 && metrics.success_rate() < 0.67);
    }

    #[tokio::test]
    async fn test_metrics_collector() {
        let collector = MetricsCollector::new();

        let result: Result<i32, &str> = collector
            .record("op1", || async { Ok(42) })
            .await;
        assert_eq!(result.unwrap(), 42);

        let _: Result<i32, &str> = collector
            .record("op1", || async { Err("failed") })
            .await;

        let summaries = collector.all_summaries().await;
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].total_count, 2);
        assert_eq!(summaries[0].success_count, 1);
    }

    #[test]
    fn test_timing_breakdown() {
        let mut breakdown = TimingBreakdown::new();
        breakdown.add_phase("phase1", Duration::from_millis(100));
        breakdown.add_phase("phase2", Duration::from_millis(300));

        let pcts = breakdown.percentages();
        assert_eq!(pcts.len(), 2);
        assert!((pcts[0].1 - 25.0).abs() < 0.1);
        assert!((pcts[1].1 - 75.0).abs() < 0.1);
    }
}
