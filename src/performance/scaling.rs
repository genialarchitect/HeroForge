//! Horizontal scaling optimization

use super::types::*;
use anyhow::Result;
use std::collections::HashMap;

/// Instance health status
#[derive(Debug, Clone, PartialEq)]
pub enum InstanceHealth {
    Healthy,
    Unhealthy,
    Draining,
}

/// Instance information
#[derive(Debug, Clone)]
pub struct Instance {
    pub id: String,
    pub cpu_utilization: f64,
    pub memory_utilization: f64,
    pub request_count: usize,
    pub health: InstanceHealth,
    pub region: String,
}

/// Scaling decision
#[derive(Debug, Clone)]
pub enum ScalingDecision {
    ScaleUp { target_instances: usize, reason: String },
    ScaleDown { target_instances: usize, reason: String },
    NoChange { reason: String },
}

/// Load balancer metrics
#[derive(Debug, Clone)]
pub struct LoadBalancerMetrics {
    pub algorithm: LoadBalancingStrategy,
    pub active_connections: usize,
    pub requests_per_second: f64,
    pub average_latency_ms: f64,
}

/// Circuit breaker state
#[derive(Debug, Clone, PartialEq)]
pub enum CircuitBreakerState {
    Closed,      // Normal operation
    Open,        // Failing, rejecting requests
    HalfOpen,    // Testing if service recovered
}

/// Circuit breaker for service resilience
#[derive(Debug, Clone)]
pub struct CircuitBreaker {
    pub service_name: String,
    pub state: CircuitBreakerState,
    pub failure_count: usize,
    pub failure_threshold: usize,
    pub success_count: usize,
    pub success_threshold: usize,
}

impl CircuitBreaker {
    fn new(service_name: &str) -> Self {
        Self {
            service_name: service_name.to_string(),
            state: CircuitBreakerState::Closed,
            failure_count: 0,
            failure_threshold: 5,
            success_count: 0,
            success_threshold: 3,
        }
    }

    fn record_success(&mut self) {
        match self.state {
            CircuitBreakerState::Closed => {
                self.failure_count = 0;
            }
            CircuitBreakerState::HalfOpen => {
                self.success_count += 1;
                if self.success_count >= self.success_threshold {
                    self.state = CircuitBreakerState::Closed;
                    self.failure_count = 0;
                    self.success_count = 0;
                    log::info!("Circuit breaker for {} closed", self.service_name);
                }
            }
            CircuitBreakerState::Open => {}
        }
    }

    fn record_failure(&mut self) {
        match self.state {
            CircuitBreakerState::Closed => {
                self.failure_count += 1;
                if self.failure_count >= self.failure_threshold {
                    self.state = CircuitBreakerState::Open;
                    log::warn!("Circuit breaker for {} opened", self.service_name);
                }
            }
            CircuitBreakerState::HalfOpen => {
                self.state = CircuitBreakerState::Open;
                self.success_count = 0;
            }
            CircuitBreakerState::Open => {}
        }
    }
}

/// Simulate current instances and their metrics
fn get_current_instances() -> Vec<Instance> {
    // In production, this would query orchestrator (K8s, ECS, etc.)
    vec![
        Instance {
            id: "instance-1".to_string(),
            cpu_utilization: 65.0,
            memory_utilization: 70.0,
            request_count: 1500,
            health: InstanceHealth::Healthy,
            region: "us-east-1".to_string(),
        },
        Instance {
            id: "instance-2".to_string(),
            cpu_utilization: 72.0,
            memory_utilization: 68.0,
            request_count: 1420,
            health: InstanceHealth::Healthy,
            region: "us-east-1".to_string(),
        },
        Instance {
            id: "instance-3".to_string(),
            cpu_utilization: 58.0,
            memory_utilization: 62.0,
            request_count: 1380,
            health: InstanceHealth::Healthy,
            region: "us-west-2".to_string(),
        },
    ]
}

/// Calculate average utilization across instances
fn calculate_average_utilization(instances: &[Instance]) -> (f64, f64) {
    if instances.is_empty() {
        return (0.0, 0.0);
    }

    let healthy_instances: Vec<_> = instances
        .iter()
        .filter(|i| i.health == InstanceHealth::Healthy)
        .collect();

    if healthy_instances.is_empty() {
        return (0.0, 0.0);
    }

    let avg_cpu = healthy_instances.iter().map(|i| i.cpu_utilization).sum::<f64>()
        / healthy_instances.len() as f64;
    let avg_memory = healthy_instances.iter().map(|i| i.memory_utilization).sum::<f64>()
        / healthy_instances.len() as f64;

    (avg_cpu, avg_memory)
}

/// Make auto-scaling decision based on metrics
fn make_scaling_decision(
    config: &ScalingConfig,
    instances: &[Instance],
    avg_cpu: f64,
    avg_memory: f64,
) -> ScalingDecision {
    let current_count = instances.len();

    // Scale up conditions
    if avg_cpu > 80.0 {
        if current_count < config.max_instances {
            return ScalingDecision::ScaleUp {
                target_instances: (current_count + 2).min(config.max_instances),
                reason: format!("High CPU utilization: {:.1}%", avg_cpu),
            };
        }
    }

    if avg_memory > 85.0 {
        if current_count < config.max_instances {
            return ScalingDecision::ScaleUp {
                target_instances: (current_count + 1).min(config.max_instances),
                reason: format!("High memory utilization: {:.1}%", avg_memory),
            };
        }
    }

    // Scale down conditions (conservative)
    if avg_cpu < 30.0 && avg_memory < 40.0 {
        if current_count > config.min_instances {
            return ScalingDecision::ScaleDown {
                target_instances: (current_count - 1).max(config.min_instances),
                reason: format!("Low utilization: CPU {:.1}%, Memory {:.1}%", avg_cpu, avg_memory),
            };
        }
    }

    ScalingDecision::NoChange {
        reason: format!("Within target range: CPU {:.1}%, Memory {:.1}%", avg_cpu, avg_memory),
    }
}

/// Select instance based on load balancing strategy
fn select_instance<'a>(
    strategy: &LoadBalancingStrategy,
    instances: &'a [Instance],
    _request_key: &str,
) -> Option<&'a Instance> {
    let healthy: Vec<_> = instances
        .iter()
        .filter(|i| i.health == InstanceHealth::Healthy)
        .collect();

    if healthy.is_empty() {
        return None;
    }

    match strategy {
        LoadBalancingStrategy::RoundRobin => {
            // In production, would use atomic counter
            healthy.first().cloned()
        }
        LoadBalancingStrategy::LeastConnections => {
            healthy
                .into_iter()
                .min_by_key(|i| i.request_count)
        }
        LoadBalancingStrategy::IPHash => {
            // Hash-based selection for session affinity
            healthy.first().cloned()
        }
        LoadBalancingStrategy::WeightedRoundRobin => {
            // Select based on inverse of CPU utilization
            healthy
                .into_iter()
                .min_by(|a, b| {
                    a.cpu_utilization
                        .partial_cmp(&b.cpu_utilization)
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
        }
        LoadBalancingStrategy::LatencyBased => {
            // Select instance with lowest current load
            healthy
                .into_iter()
                .min_by(|a, b| {
                    let a_score = a.cpu_utilization * 0.7 + a.memory_utilization * 0.3;
                    let b_score = b.cpu_utilization * 0.7 + b.memory_utilization * 0.3;
                    a_score.partial_cmp(&b_score).unwrap_or(std::cmp::Ordering::Equal)
                })
        }
    }
}

/// Calculate request queue size
fn estimate_request_queue(instances: &[Instance]) -> usize {
    // Estimate based on instance load
    let total_requests: usize = instances.iter().map(|i| i.request_count).sum();
    let avg_cpu: f64 = instances.iter().map(|i| i.cpu_utilization).sum::<f64>()
        / instances.len().max(1) as f64;

    // If CPU is high, estimate queue buildup
    if avg_cpu > 70.0 {
        ((avg_cpu - 70.0) * 10.0) as usize
    } else {
        0
    }
}

/// Optimize horizontal scaling
pub async fn optimize_scaling(config: &ScalingConfig) -> Result<ScalingMetrics> {
    log::info!("Analyzing horizontal scaling configuration");

    // Get current instances
    let instances = get_current_instances();
    let current_instances = instances.len();

    log::info!("Current instances: {}", current_instances);

    // Calculate utilization
    let (avg_cpu, avg_memory) = calculate_average_utilization(&instances);

    // Log load balancing strategy
    log::info!("Load balancing strategy: {:?}", config.load_balancing);

    // Make scaling decision if auto-scaling is enabled
    if config.auto_scaling {
        let decision = make_scaling_decision(config, &instances, avg_cpu, avg_memory);
        match &decision {
            ScalingDecision::ScaleUp { target_instances, reason } => {
                log::info!("Scale up recommended: {} instances - {}", target_instances, reason);
            }
            ScalingDecision::ScaleDown { target_instances, reason } => {
                log::info!("Scale down recommended: {} instances - {}", target_instances, reason);
            }
            ScalingDecision::NoChange { reason } => {
                log::info!("No scaling needed: {}", reason);
            }
        }
    }

    // Test load balancing selection
    if let Some(selected) = select_instance(&config.load_balancing, &instances, "test-request") {
        log::debug!(
            "Load balancer selected instance {} (CPU: {:.1}%)",
            selected.id,
            selected.cpu_utilization
        );
    }

    // Distributed caching status
    if config.distributed_caching {
        log::info!("Distributed caching: enabled (Redis Cluster recommended)");
    }

    // Queue-based processing status
    if config.queue_based_processing {
        log::info!("Queue-based processing: enabled (consider RabbitMQ/Kafka for async workloads)");
    }

    // Health checks and circuit breakers
    let mut circuit_breakers: HashMap<String, CircuitBreaker> = HashMap::new();
    for service in &["database", "cache", "external-api"] {
        circuit_breakers.insert(service.to_string(), CircuitBreaker::new(service));
    }

    // Log circuit breaker status
    for (name, cb) in &circuit_breakers {
        log::debug!("Circuit breaker '{}': {:?}", name, cb.state);
    }

    // Estimate request queue
    let request_queue_size = estimate_request_queue(&instances);
    if request_queue_size > 0 {
        log::warn!("Estimated request queue: {} (consider scaling up)", request_queue_size);
    }

    // Deployment recommendations
    log::info!("Deployment recommendations:");
    log::info!("  - Blue-green deployment for zero-downtime updates");
    log::info!("  - Canary releases for gradual rollouts (5% -> 25% -> 100%)");
    log::info!("  - Health check endpoint: /health with readiness and liveness probes");

    log::info!(
        "Scaling analysis complete: {} instances, {:.1}% CPU, {:.1}% memory",
        current_instances,
        avg_cpu,
        avg_memory
    );

    Ok(ScalingMetrics {
        current_instances,
        cpu_utilization: avg_cpu,
        memory_utilization: avg_memory,
        request_queue_size,
    })
}
