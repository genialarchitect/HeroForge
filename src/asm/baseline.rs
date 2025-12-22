//! Baseline creation and management

use chrono::Utc;
use uuid::Uuid;

use super::types::*;
use crate::types::HostInfo;

/// Manages baseline creation and comparison
pub struct BaselineManager;

impl BaselineManager {
    /// Create a new baseline from discovered hosts
    pub fn create_baseline(
        monitor_id: &str,
        hosts: &[HostInfo],
    ) -> AsmBaseline {
        let assets: Vec<BaselineAsset> = hosts
            .iter()
            .map(|host| Self::host_to_baseline_asset(host))
            .collect();

        let summary = Self::calculate_summary(&assets);

        AsmBaseline {
            id: Uuid::new_v4().to_string(),
            monitor_id: monitor_id.to_string(),
            assets,
            summary,
            is_active: true,
            created_at: Utc::now(),
        }
    }

    /// Create a new baseline from existing baseline assets (for API)
    pub fn create_baseline_from_assets(
        monitor_id: &str,
        existing_assets: Vec<BaselineAsset>,
    ) -> AsmBaseline {
        let now = Utc::now();

        // Update timestamps on the assets
        let assets: Vec<BaselineAsset> = existing_assets.into_iter()
            .map(|mut a| {
                a.last_seen = now;
                a
            })
            .collect();

        let summary = Self::calculate_summary(&assets);

        AsmBaseline {
            id: Uuid::new_v4().to_string(),
            monitor_id: monitor_id.to_string(),
            assets,
            summary,
            is_active: true,
            created_at: now,
        }
    }

    /// Convert a HostInfo to a BaselineAsset
    fn host_to_baseline_asset(host: &HostInfo) -> BaselineAsset {
        let now = Utc::now();

        // Extract ports
        let ports: Vec<BaselinePort> = host.ports.iter().map(|port| {
            BaselinePort {
                port: port.port,
                protocol: format!("{:?}", port.protocol).to_lowercase(),
                service: port.service.as_ref().map(|s| s.name.clone()),
                version: port.service.as_ref().and_then(|s| s.version.clone()),
            }
        }).collect();

        // Extract technologies from service banners/headers
        let mut technologies = Vec::new();
        for port in &host.ports {
            if let Some(service) = &port.service {
                if let Some(version) = &service.version {
                    technologies.push(format!("{} {}", service.name, version));
                }
            }
        }

        // Extract SSL info from first SSL-enabled port
        let ssl_info = host.ports.iter()
            .find(|p| p.service.as_ref().map_or(false, |s| s.ssl_info.is_some()))
            .and_then(|p| p.service.as_ref())
            .and_then(|s| s.ssl_info.as_ref())
            .map(|ssl| BaselineSslInfo {
                issuer: ssl.issuer.clone(),
                subject: ssl.subject.clone(),
                valid_from: chrono::DateTime::parse_from_rfc3339(&ssl.valid_from)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| now),
                valid_until: chrono::DateTime::parse_from_rfc3339(&ssl.valid_until)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| now),
                fingerprint: String::new(), // Would need to compute from cert
            });

        BaselineAsset {
            hostname: host.target.hostname.clone().unwrap_or_else(|| host.target.ip.to_string()),
            ip_addresses: vec![host.target.ip.to_string()],
            ports,
            technologies,
            ssl_info,
            first_seen: now,
            last_seen: now,
        }
    }

    /// Calculate summary statistics for a baseline
    fn calculate_summary(assets: &[BaselineAsset]) -> BaselineSummary {
        let total_assets = assets.len();
        let total_ports: usize = assets.iter().map(|a| a.ports.len()).sum();
        let total_services: usize = assets.iter()
            .flat_map(|a| &a.ports)
            .filter(|p| p.service.is_some())
            .count();
        let assets_with_ssl = assets.iter()
            .filter(|a| a.ssl_info.is_some())
            .count();

        let mut all_techs: Vec<&str> = assets.iter()
            .flat_map(|a| a.technologies.iter().map(|t| t.as_str()))
            .collect();
        all_techs.sort();
        all_techs.dedup();
        let unique_technologies = all_techs.len();

        BaselineSummary {
            total_assets,
            total_ports,
            total_services,
            assets_with_ssl,
            unique_technologies,
        }
    }

    /// Merge new assets into an existing baseline
    pub fn merge_assets(
        baseline: &mut AsmBaseline,
        new_hosts: &[HostInfo],
    ) {
        let now = Utc::now();

        for host in new_hosts {
            let hostname = host.target.hostname.clone()
                .unwrap_or_else(|| host.target.ip.to_string());
            let ip_str = host.target.ip.to_string();

            // Check if asset already exists
            if let Some(existing) = baseline.assets.iter_mut()
                .find(|a| a.hostname == hostname)
            {
                // Update existing asset
                existing.last_seen = now;

                // Update IP if changed
                if !existing.ip_addresses.contains(&ip_str) {
                    existing.ip_addresses.push(ip_str.clone());
                }

                // Merge ports
                for port in &host.ports {
                    let new_port = BaselinePort {
                        port: port.port,
                        protocol: format!("{:?}", port.protocol).to_lowercase(),
                        service: port.service.as_ref().map(|s| s.name.clone()),
                        version: port.service.as_ref().and_then(|s| s.version.clone()),
                    };

                    if !existing.ports.iter().any(|p| p.port == new_port.port) {
                        existing.ports.push(new_port);
                    }
                }
            } else {
                // Add new asset
                baseline.assets.push(Self::host_to_baseline_asset(host));
            }
        }

        // Recalculate summary
        baseline.summary = Self::calculate_summary(&baseline.assets);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Target, PortInfo, ServiceInfo};

    fn create_test_host(ip: &str, hostname: Option<&str>, ports: Vec<u16>) -> HostInfo {
        HostInfo {
            target: Target {
                ip: ip.to_string(),
                hostname: hostname.map(|h| h.to_string()),
            },
            is_alive: true,
            os_guess: None,
            ports: ports.into_iter().map(|p| PortInfo {
                port: p,
                protocol: "tcp".to_string(),
                state: "open".to_string(),
                service: Some(ServiceInfo {
                    name: "http".to_string(),
                    version: Some("1.0".to_string()),
                    banner: None,
                    ssl_info: None,
                }),
            }).collect(),
            vulnerabilities: vec![],
            scan_duration: std::time::Duration::from_secs(1),
        }
    }

    #[test]
    fn test_create_baseline() {
        let hosts = vec![
            create_test_host("192.168.1.1", Some("web.example.com"), vec![80, 443]),
            create_test_host("192.168.1.2", Some("api.example.com"), vec![8080]),
        ];

        let baseline = BaselineManager::create_baseline("monitor-1", &hosts);

        assert_eq!(baseline.assets.len(), 2);
        assert_eq!(baseline.summary.total_assets, 2);
        assert_eq!(baseline.summary.total_ports, 3);
        assert!(baseline.is_active);
    }
}
