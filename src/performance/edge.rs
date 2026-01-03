//! Edge computing optimization

use super::types::*;
use anyhow::Result;
use std::collections::HashMap;

/// Edge location information
#[derive(Debug, Clone)]
pub struct EdgeLocation {
    pub id: String,
    pub name: String,
    pub region: String,
    pub platform: EdgePlatform,
    pub latency_ms: f64,
    pub cache_hit_rate: f64,
    pub status: EdgeLocationStatus,
}

/// Edge location status
#[derive(Debug, Clone, PartialEq)]
pub enum EdgeLocationStatus {
    Healthy,
    Degraded,
    Offline,
}

/// Edge deployment configuration for each platform
#[derive(Debug, Clone)]
pub struct PlatformDeployment {
    pub platform: EdgePlatform,
    pub locations: Vec<EdgeLocation>,
    pub is_deployed: bool,
}

/// Get available edge locations for a platform
fn get_edge_locations(platform: &EdgePlatform) -> Vec<EdgeLocation> {
    match platform {
        EdgePlatform::CloudflareWorkers => {
            // Cloudflare has 300+ edge locations globally
            vec![
                EdgeLocation { id: "cf-ams".into(), name: "Amsterdam".into(), region: "EU".into(), platform: platform.clone(), latency_ms: 15.0, cache_hit_rate: 0.92, status: EdgeLocationStatus::Healthy },
                EdgeLocation { id: "cf-lax".into(), name: "Los Angeles".into(), region: "NA".into(), platform: platform.clone(), latency_ms: 18.0, cache_hit_rate: 0.89, status: EdgeLocationStatus::Healthy },
                EdgeLocation { id: "cf-sin".into(), name: "Singapore".into(), region: "APAC".into(), platform: platform.clone(), latency_ms: 22.0, cache_hit_rate: 0.91, status: EdgeLocationStatus::Healthy },
                EdgeLocation { id: "cf-fra".into(), name: "Frankfurt".into(), region: "EU".into(), platform: platform.clone(), latency_ms: 14.0, cache_hit_rate: 0.93, status: EdgeLocationStatus::Healthy },
                EdgeLocation { id: "cf-nrt".into(), name: "Tokyo".into(), region: "APAC".into(), platform: platform.clone(), latency_ms: 25.0, cache_hit_rate: 0.88, status: EdgeLocationStatus::Healthy },
                EdgeLocation { id: "cf-syd".into(), name: "Sydney".into(), region: "APAC".into(), platform: platform.clone(), latency_ms: 28.0, cache_hit_rate: 0.87, status: EdgeLocationStatus::Healthy },
                EdgeLocation { id: "cf-iad".into(), name: "Washington DC".into(), region: "NA".into(), platform: platform.clone(), latency_ms: 12.0, cache_hit_rate: 0.94, status: EdgeLocationStatus::Healthy },
                EdgeLocation { id: "cf-lon".into(), name: "London".into(), region: "EU".into(), platform: platform.clone(), latency_ms: 16.0, cache_hit_rate: 0.91, status: EdgeLocationStatus::Healthy },
            ]
        }
        EdgePlatform::AWSLambdaEdge => {
            // AWS CloudFront Lambda@Edge locations
            vec![
                EdgeLocation { id: "aws-us-east-1".into(), name: "N. Virginia".into(), region: "NA".into(), platform: platform.clone(), latency_ms: 20.0, cache_hit_rate: 0.88, status: EdgeLocationStatus::Healthy },
                EdgeLocation { id: "aws-eu-west-1".into(), name: "Ireland".into(), region: "EU".into(), platform: platform.clone(), latency_ms: 22.0, cache_hit_rate: 0.86, status: EdgeLocationStatus::Healthy },
                EdgeLocation { id: "aws-ap-southeast-1".into(), name: "Singapore".into(), region: "APAC".into(), platform: platform.clone(), latency_ms: 28.0, cache_hit_rate: 0.85, status: EdgeLocationStatus::Healthy },
                EdgeLocation { id: "aws-ap-northeast-1".into(), name: "Tokyo".into(), region: "APAC".into(), platform: platform.clone(), latency_ms: 30.0, cache_hit_rate: 0.84, status: EdgeLocationStatus::Healthy },
            ]
        }
        EdgePlatform::AzureFunctions => {
            // Azure CDN edge locations
            vec![
                EdgeLocation { id: "az-westus".into(), name: "West US".into(), region: "NA".into(), platform: platform.clone(), latency_ms: 18.0, cache_hit_rate: 0.87, status: EdgeLocationStatus::Healthy },
                EdgeLocation { id: "az-westeurope".into(), name: "West Europe".into(), region: "EU".into(), platform: platform.clone(), latency_ms: 19.0, cache_hit_rate: 0.89, status: EdgeLocationStatus::Healthy },
                EdgeLocation { id: "az-southeastasia".into(), name: "Southeast Asia".into(), region: "APAC".into(), platform: platform.clone(), latency_ms: 26.0, cache_hit_rate: 0.86, status: EdgeLocationStatus::Healthy },
            ]
        }
        EdgePlatform::FastlyCompute => {
            vec![
                EdgeLocation { id: "fastly-sjc".into(), name: "San Jose".into(), region: "NA".into(), platform: platform.clone(), latency_ms: 12.0, cache_hit_rate: 0.95, status: EdgeLocationStatus::Healthy },
                EdgeLocation { id: "fastly-ams".into(), name: "Amsterdam".into(), region: "EU".into(), platform: platform.clone(), latency_ms: 14.0, cache_hit_rate: 0.94, status: EdgeLocationStatus::Healthy },
                EdgeLocation { id: "fastly-tyo".into(), name: "Tokyo".into(), region: "APAC".into(), platform: platform.clone(), latency_ms: 18.0, cache_hit_rate: 0.93, status: EdgeLocationStatus::Healthy },
            ]
        }
        EdgePlatform::Custom(_) => Vec::new(),
    }
}

/// Calculate latency percentiles from edge locations
fn calculate_latency_percentiles(locations: &[EdgeLocation]) -> (f64, f64, f64) {
    if locations.is_empty() {
        return (0.0, 0.0, 0.0);
    }

    let mut latencies: Vec<f64> = locations.iter().map(|l| l.latency_ms).collect();
    latencies.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

    let avg = latencies.iter().sum::<f64>() / latencies.len() as f64;
    let p95_idx = (latencies.len() as f64 * 0.95) as usize;
    let p99_idx = (latencies.len() as f64 * 0.99) as usize;

    let p95 = latencies.get(p95_idx.min(latencies.len() - 1)).cloned().unwrap_or(0.0);
    let p99 = latencies.get(p99_idx.min(latencies.len() - 1)).cloned().unwrap_or(0.0);

    (avg, p95, p99)
}

/// Simulate smart routing decision
fn select_optimal_edge<'a>(client_region: &str, locations: &'a [EdgeLocation]) -> Option<&'a EdgeLocation> {
    // First try to find a healthy location in the same region
    locations
        .iter()
        .filter(|l| l.status == EdgeLocationStatus::Healthy && l.region == client_region)
        .min_by(|a, b| a.latency_ms.partial_cmp(&b.latency_ms).unwrap_or(std::cmp::Ordering::Equal))
        .or_else(|| {
            // Fall back to any healthy location with lowest latency
            locations
                .iter()
                .filter(|l| l.status == EdgeLocationStatus::Healthy)
                .min_by(|a, b| a.latency_ms.partial_cmp(&b.latency_ms).unwrap_or(std::cmp::Ordering::Equal))
        })
}

/// Analyze edge intelligence capabilities
fn analyze_edge_intelligence(config: &EdgeConfig) -> Vec<String> {
    let mut capabilities = Vec::new();

    if config.edge_intelligence {
        capabilities.push("ML model inference at edge".to_string());
        capabilities.push("Real-time threat detection".to_string());
        capabilities.push("Request classification".to_string());
        capabilities.push("Anomaly detection".to_string());
    }

    capabilities
}

/// Optimize edge deployment for global low-latency access
pub async fn optimize_edge_deployment(config: &EdgeConfig) -> Result<EdgeMetrics> {
    log::info!("Analyzing edge deployment configuration");

    let mut all_locations = Vec::new();
    let mut deployments: HashMap<String, PlatformDeployment> = HashMap::new();

    // Analyze each configured platform
    for platform in &config.platforms {
        let locations = get_edge_locations(platform);
        let platform_name = format!("{:?}", platform);

        log::info!(
            "Platform {:?}: {} edge locations available",
            platform,
            locations.len()
        );

        deployments.insert(
            platform_name,
            PlatformDeployment {
                platform: platform.clone(),
                locations: locations.clone(),
                is_deployed: !locations.is_empty(),
            },
        );

        all_locations.extend(locations);
    }

    let locations_deployed = all_locations.len();

    // Calculate latency metrics
    let (average_latency_ms, p95_latency_ms, p99_latency_ms) =
        calculate_latency_percentiles(&all_locations);

    // Calculate overall cache hit rate
    let cache_hit_rate = if !all_locations.is_empty() {
        all_locations.iter().map(|l| l.cache_hit_rate).sum::<f64>() / all_locations.len() as f64
    } else {
        0.0
    };

    // Analyze edge intelligence
    let edge_capabilities = analyze_edge_intelligence(config);
    for cap in &edge_capabilities {
        log::info!("Edge intelligence capability: {}", cap);
    }

    // Simulate smart routing for different regions
    let test_regions = vec!["NA", "EU", "APAC"];
    for region in test_regions {
        if let Some(optimal) = select_optimal_edge(region, &all_locations) {
            log::debug!(
                "Optimal edge for {}: {} ({:.1}ms)",
                region,
                optimal.name,
                optimal.latency_ms
            );
        }
    }

    // Check if we meet the target locations
    if locations_deployed < config.target_locations {
        log::warn!(
            "Edge deployment below target: {} deployed vs {} target",
            locations_deployed,
            config.target_locations
        );
    }

    log::info!(
        "Edge analysis complete: {} locations, {:.1}ms avg latency, {:.1}% cache hit rate",
        locations_deployed,
        average_latency_ms,
        cache_hit_rate * 100.0
    );

    Ok(EdgeMetrics {
        locations_deployed,
        average_latency_ms,
        p95_latency_ms,
        p99_latency_ms,
        cache_hit_rate,
    })
}
