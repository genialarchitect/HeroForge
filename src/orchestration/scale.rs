//! Scale Orchestration Module
//!
//! Provides distributed orchestration capabilities:
//! - Regional node distribution
//! - Horizontal scaling
//! - Global job coordination
//! - Resource optimization

use anyhow::Result;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

/// Regional node information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegionalNode {
    pub node_id: String,
    pub region: String,
    pub endpoint: String,
    pub status: NodeStatus,
    pub capacity: NodeCapacity,
    pub current_load: f64,
    pub last_heartbeat: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum NodeStatus {
    Online,
    Offline,
    Degraded,
    Draining,
    Maintenance,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeCapacity {
    pub max_concurrent_jobs: usize,
    pub active_jobs: usize,
    pub memory_mb: usize,
    pub cpu_cores: usize,
}

/// Scaling decision
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScalingDecision {
    pub current_instances: usize,
    pub recommended_instances: usize,
    pub action: ScalingAction,
    pub reason: String,
    pub estimated_cost_impact: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ScalingAction {
    ScaleUp,
    ScaleDown,
    NoChange,
}

/// Global job coordinator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalJobCoordinator {
    pub coordinator_id: String,
    pub active_jobs: Vec<DistributedJob>,
    pub node_registry: Vec<RegionalNode>,
    pub config: CoordinatorConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoordinatorConfig {
    pub max_retries: usize,
    pub timeout_seconds: u64,
    pub load_balancing_strategy: LoadBalancingStrategy,
    pub failover_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LoadBalancingStrategy {
    RoundRobin,
    LeastLoaded,
    GeographicProximity,
    WeightedRandom,
    ConsistentHashing,
}

/// Distributed job
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DistributedJob {
    pub job_id: String,
    pub job_type: String,
    pub payload: serde_json::Value,
    pub assigned_node: Option<String>,
    pub status: JobStatus,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub retry_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum JobStatus {
    Pending,
    Assigned,
    Running,
    Completed,
    Failed,
    Retrying,
    Cancelled,
}

/// Resource allocation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceAllocation {
    pub allocation_id: String,
    pub node_allocations: Vec<NodeAllocation>,
    pub total_capacity: usize,
    pub utilized_capacity: usize,
    pub efficiency_score: f64,
    pub recommendations: Vec<OptimizationRecommendation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeAllocation {
    pub node_id: String,
    pub allocated_jobs: usize,
    pub allocated_memory_mb: usize,
    pub allocated_cpu_percent: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimizationRecommendation {
    pub recommendation_type: RecommendationType,
    pub description: String,
    pub impact: String,
    pub priority: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RecommendationType {
    RebalanceLoad,
    ScaleUp,
    ScaleDown,
    MigrateJobs,
    DrainNode,
    AddRegion,
}

/// Distribute orchestration across regional nodes
pub async fn distributed_orchestration(job_id: &str, regional_nodes: Vec<String>) -> Result<DistributedJob> {
    log::info!("Distributing job {} across {} regional nodes", job_id, regional_nodes.len());

    // Validate we have nodes to distribute to
    if regional_nodes.is_empty() {
        anyhow::bail!("No regional nodes available for distribution");
    }

    // Create distributed job
    let mut job = DistributedJob {
        job_id: job_id.to_string(),
        job_type: "distributed_scan".to_string(),
        payload: serde_json::json!({
            "target_nodes": regional_nodes,
            "distribution_strategy": "parallel"
        }),
        assigned_node: None,
        status: JobStatus::Pending,
        created_at: Utc::now(),
        started_at: None,
        completed_at: None,
        retry_count: 0,
    };

    // Select primary coordinator node (first available)
    let coordinator_node = select_coordinator_node(&regional_nodes).await?;
    job.assigned_node = Some(coordinator_node.clone());
    job.status = JobStatus::Assigned;

    log::info!("Job {} assigned to coordinator node: {}", job_id, coordinator_node);

    // In production, this would:
    // 1. Connect to the coordinator node
    // 2. Send job distribution request
    // 3. Monitor job progress across all nodes
    // 4. Aggregate results

    job.status = JobStatus::Running;
    job.started_at = Some(Utc::now());

    Ok(job)
}

/// Select coordinator node based on load and availability
async fn select_coordinator_node(nodes: &[String]) -> Result<String> {
    // In production, query node health and select least loaded
    // For now, select first available node
    nodes.first()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("No nodes available"))
}

/// Calculate required horizontal scaling based on load
pub async fn horizontal_scaling(current_load: f64) -> Result<ScalingDecision> {
    log::info!("Calculating horizontal scaling for load: {:.2}%", current_load * 100.0);

    // Scaling thresholds
    const SCALE_UP_THRESHOLD: f64 = 0.75; // 75% load
    const SCALE_DOWN_THRESHOLD: f64 = 0.25; // 25% load
    const TARGET_LOAD: f64 = 0.70; // Target 70% utilization
    const MIN_INSTANCES: usize = 1;
    const MAX_INSTANCES: usize = 100;

    // Calculate required instances to achieve target load
    let current_instances = 1; // Assume single instance for now
    let required_instances = ((current_load / TARGET_LOAD) * current_instances as f64).ceil() as usize;

    // Clamp to valid range
    let recommended_instances = required_instances.clamp(MIN_INSTANCES, MAX_INSTANCES);

    // Determine scaling action
    let (action, reason) = if current_load >= SCALE_UP_THRESHOLD {
        (
            ScalingAction::ScaleUp,
            format!(
                "Load ({:.1}%) exceeds scale-up threshold ({:.1}%)",
                current_load * 100.0,
                SCALE_UP_THRESHOLD * 100.0
            ),
        )
    } else if current_load <= SCALE_DOWN_THRESHOLD && current_instances > MIN_INSTANCES {
        (
            ScalingAction::ScaleDown,
            format!(
                "Load ({:.1}%) below scale-down threshold ({:.1}%)",
                current_load * 100.0,
                SCALE_DOWN_THRESHOLD * 100.0
            ),
        )
    } else {
        (
            ScalingAction::NoChange,
            format!("Load ({:.1}%) within acceptable range", current_load * 100.0),
        )
    };

    // Estimate cost impact (simplified)
    let instance_cost_per_hour = 0.10; // $0.10/hour per instance
    let cost_diff = (recommended_instances as f64 - current_instances as f64) * instance_cost_per_hour;

    Ok(ScalingDecision {
        current_instances,
        recommended_instances,
        action,
        reason,
        estimated_cost_impact: cost_diff * 24.0 * 30.0, // Monthly estimate
    })
}

/// Coordinate jobs across global infrastructure
pub async fn global_coordination(jobs: Vec<String>) -> Result<GlobalJobCoordinator> {
    log::info!("Coordinating {} jobs globally", jobs.len());

    // Create job entries
    let distributed_jobs: Vec<DistributedJob> = jobs
        .iter()
        .map(|job_id| DistributedJob {
            job_id: job_id.clone(),
            job_type: "global_scan".to_string(),
            payload: serde_json::json!({}),
            assigned_node: None,
            status: JobStatus::Pending,
            created_at: Utc::now(),
            started_at: None,
            completed_at: None,
            retry_count: 0,
        })
        .collect();

    // Create regional node registry
    let node_registry = create_default_node_registry();

    // Create coordinator
    let coordinator = GlobalJobCoordinator {
        coordinator_id: uuid::Uuid::new_v4().to_string(),
        active_jobs: distributed_jobs,
        node_registry,
        config: CoordinatorConfig {
            max_retries: 3,
            timeout_seconds: 300,
            load_balancing_strategy: LoadBalancingStrategy::LeastLoaded,
            failover_enabled: true,
        },
    };

    log::info!(
        "Global coordinator {} created with {} jobs and {} nodes",
        coordinator.coordinator_id,
        coordinator.active_jobs.len(),
        coordinator.node_registry.len()
    );

    Ok(coordinator)
}

/// Create default node registry
fn create_default_node_registry() -> Vec<RegionalNode> {
    vec![
        RegionalNode {
            node_id: "us-east-1".to_string(),
            region: "US East (N. Virginia)".to_string(),
            endpoint: "https://us-east-1.heroforge.example.com".to_string(),
            status: NodeStatus::Online,
            capacity: NodeCapacity {
                max_concurrent_jobs: 100,
                active_jobs: 30,
                memory_mb: 16384,
                cpu_cores: 8,
            },
            current_load: 0.30,
            last_heartbeat: Utc::now(),
        },
        RegionalNode {
            node_id: "eu-west-1".to_string(),
            region: "EU (Ireland)".to_string(),
            endpoint: "https://eu-west-1.heroforge.example.com".to_string(),
            status: NodeStatus::Online,
            capacity: NodeCapacity {
                max_concurrent_jobs: 100,
                active_jobs: 45,
                memory_mb: 16384,
                cpu_cores: 8,
            },
            current_load: 0.45,
            last_heartbeat: Utc::now(),
        },
        RegionalNode {
            node_id: "ap-northeast-1".to_string(),
            region: "Asia Pacific (Tokyo)".to_string(),
            endpoint: "https://ap-northeast-1.heroforge.example.com".to_string(),
            status: NodeStatus::Online,
            capacity: NodeCapacity {
                max_concurrent_jobs: 50,
                active_jobs: 20,
                memory_mb: 8192,
                cpu_cores: 4,
            },
            current_load: 0.40,
            last_heartbeat: Utc::now(),
        },
    ]
}

/// Optimize resource allocation across nodes
pub async fn optimize_resource_allocation() -> Result<serde_json::Value> {
    log::info!("Optimizing resource allocation");

    let nodes = create_default_node_registry();
    let mut recommendations = Vec::new();

    // Analyze each node for optimization opportunities
    let mut total_capacity = 0;
    let mut utilized_capacity = 0;
    let mut node_allocations = Vec::new();

    for node in &nodes {
        total_capacity += node.capacity.max_concurrent_jobs;
        utilized_capacity += node.capacity.active_jobs;

        node_allocations.push(NodeAllocation {
            node_id: node.node_id.clone(),
            allocated_jobs: node.capacity.active_jobs,
            allocated_memory_mb: (node.capacity.memory_mb as f64 * node.current_load) as usize,
            allocated_cpu_percent: node.current_load * 100.0,
        });

        // Check for imbalanced load
        if node.current_load > 0.80 {
            recommendations.push(OptimizationRecommendation {
                recommendation_type: RecommendationType::RebalanceLoad,
                description: format!("Node {} is heavily loaded ({:.1}%)", node.node_id, node.current_load * 100.0),
                impact: "Reduce latency and prevent job failures".to_string(),
                priority: "High".to_string(),
            });
        } else if node.current_load < 0.20 && nodes.len() > 2 {
            recommendations.push(OptimizationRecommendation {
                recommendation_type: RecommendationType::ScaleDown,
                description: format!("Node {} is underutilized ({:.1}%)", node.node_id, node.current_load * 100.0),
                impact: "Reduce infrastructure costs".to_string(),
                priority: "Low".to_string(),
            });
        }
    }

    // Calculate efficiency score
    let efficiency_score = if total_capacity > 0 {
        (utilized_capacity as f64 / total_capacity as f64) * 100.0
    } else {
        0.0
    };

    // Overall recommendation based on aggregate load
    let avg_load = nodes.iter().map(|n| n.current_load).sum::<f64>() / nodes.len() as f64;
    if avg_load > 0.70 {
        recommendations.push(OptimizationRecommendation {
            recommendation_type: RecommendationType::ScaleUp,
            description: "Average cluster load is high".to_string(),
            impact: format!("Improve capacity headroom (current avg: {:.1}%)", avg_load * 100.0),
            priority: "Medium".to_string(),
        });
    }

    let allocation = ResourceAllocation {
        allocation_id: uuid::Uuid::new_v4().to_string(),
        node_allocations,
        total_capacity,
        utilized_capacity,
        efficiency_score,
        recommendations,
    };

    Ok(serde_json::to_value(allocation)?)
}

/// Assign job to optimal node based on strategy
pub fn assign_job_to_node(
    job: &mut DistributedJob,
    nodes: &[RegionalNode],
    strategy: &LoadBalancingStrategy,
) -> Result<String> {
    let available_nodes: Vec<&RegionalNode> = nodes
        .iter()
        .filter(|n| n.status == NodeStatus::Online && n.current_load < 0.90)
        .collect();

    if available_nodes.is_empty() {
        anyhow::bail!("No available nodes for job assignment");
    }

    let selected_node = match strategy {
        LoadBalancingStrategy::LeastLoaded => {
            available_nodes
                .iter()
                .min_by(|a, b| a.current_load.partial_cmp(&b.current_load).unwrap())
                .unwrap()
        }
        LoadBalancingStrategy::RoundRobin => {
            // In production, maintain round-robin state
            available_nodes.first().unwrap()
        }
        LoadBalancingStrategy::GeographicProximity => {
            // In production, select based on job source location
            available_nodes.first().unwrap()
        }
        LoadBalancingStrategy::WeightedRandom => {
            // Weight by available capacity
            let total_available: f64 = available_nodes
                .iter()
                .map(|n| 1.0 - n.current_load)
                .sum();

            let mut cumulative = 0.0;
            let random_value = 0.5; // In production, use actual random

            available_nodes
                .iter()
                .find(|n| {
                    cumulative += (1.0 - n.current_load) / total_available;
                    cumulative >= random_value
                })
                .unwrap_or(available_nodes.first().unwrap())
        }
        LoadBalancingStrategy::ConsistentHashing => {
            // Hash job ID to select node
            let hash = calculate_hash(&job.job_id);
            let index = (hash as usize) % available_nodes.len();
            available_nodes[index]
        }
    };

    job.assigned_node = Some(selected_node.node_id.clone());
    job.status = JobStatus::Assigned;

    log::info!(
        "Job {} assigned to node {} using {:?} strategy",
        job.job_id,
        selected_node.node_id,
        strategy
    );

    Ok(selected_node.node_id.clone())
}

/// Simple hash function for consistent hashing
fn calculate_hash(s: &str) -> u64 {
    let mut hash: u64 = 0;
    for byte in s.bytes() {
        hash = hash.wrapping_mul(31).wrapping_add(byte as u64);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_distributed_orchestration() {
        let nodes = vec!["node1".to_string(), "node2".to_string()];
        let result = distributed_orchestration("test-job", nodes).await.unwrap();

        assert_eq!(result.job_id, "test-job");
        assert!(result.assigned_node.is_some());
        assert_eq!(result.status, JobStatus::Running);
    }

    #[tokio::test]
    async fn test_horizontal_scaling_scale_up() {
        let result = horizontal_scaling(0.85).await.unwrap();
        assert_eq!(result.action, ScalingAction::ScaleUp);
    }

    #[tokio::test]
    async fn test_horizontal_scaling_no_change() {
        let result = horizontal_scaling(0.50).await.unwrap();
        assert_eq!(result.action, ScalingAction::NoChange);
    }

    #[tokio::test]
    async fn test_global_coordination() {
        let jobs = vec!["job1".to_string(), "job2".to_string()];
        let result = global_coordination(jobs).await.unwrap();

        assert_eq!(result.active_jobs.len(), 2);
        assert!(!result.node_registry.is_empty());
    }

    #[tokio::test]
    async fn test_optimize_resource_allocation() {
        let result = optimize_resource_allocation().await.unwrap();
        assert!(result.get("efficiency_score").is_some());
        assert!(result.get("node_allocations").is_some());
    }

    #[test]
    fn test_assign_job_to_node() {
        let nodes = create_default_node_registry();
        let mut job = DistributedJob {
            job_id: "test-job".to_string(),
            job_type: "scan".to_string(),
            payload: serde_json::json!({}),
            assigned_node: None,
            status: JobStatus::Pending,
            created_at: Utc::now(),
            started_at: None,
            completed_at: None,
            retry_count: 0,
        };

        let result = assign_job_to_node(&mut job, &nodes, &LoadBalancingStrategy::LeastLoaded);
        assert!(result.is_ok());
        assert!(job.assigned_node.is_some());
    }
}
