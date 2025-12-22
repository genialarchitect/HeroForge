//! Change detection and comparison

use chrono::Utc;
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

use super::types::*;

/// Detects changes between baselines
pub struct ChangeDetector;

impl ChangeDetector {
    /// Compare current assets against baseline and detect changes
    pub fn detect_changes(
        monitor_id: &str,
        baseline: &AsmBaseline,
        current_assets: &[BaselineAsset],
        authorized_patterns: &[AuthorizedAsset],
    ) -> Vec<AsmChange> {
        let mut changes = Vec::new();
        let now = Utc::now();

        // Create lookup maps
        let baseline_map: HashMap<&str, &BaselineAsset> = baseline.assets
            .iter()
            .map(|a| (a.hostname.as_str(), a))
            .collect();

        let current_map: HashMap<&str, &BaselineAsset> = current_assets
            .iter()
            .map(|a| (a.hostname.as_str(), a))
            .collect();

        // Check for new assets (new subdomains)
        for current in current_assets {
            if !baseline_map.contains_key(current.hostname.as_str()) {
                let is_shadow_it = !Self::is_authorized(&current.hostname, &current.ip_addresses, authorized_patterns);

                let change_type = if is_shadow_it {
                    ChangeType::ShadowItDetected
                } else {
                    ChangeType::NewSubdomain
                };

                let severity = if is_shadow_it {
                    AlertSeverity::High
                } else {
                    AlertSeverity::Medium
                };

                changes.push(AsmChange {
                    id: Uuid::new_v4().to_string(),
                    monitor_id: monitor_id.to_string(),
                    baseline_id: baseline.id.clone(),
                    change_type,
                    severity,
                    hostname: current.hostname.clone(),
                    details: ChangeDetails {
                        description: format!(
                            "New {} discovered: {}",
                            if is_shadow_it { "unauthorized asset" } else { "subdomain" },
                            current.hostname
                        ),
                        old_value: None,
                        new_value: Some(current.ip_addresses.join(", ")),
                        affected_ports: current.ports.iter().map(|p| p.port).collect(),
                        metadata: HashMap::new(),
                    },
                    detected_at: now,
                    acknowledged: false,
                    acknowledged_by: None,
                    acknowledged_at: None,
                });
            }
        }

        // Check for removed assets
        for baseline_asset in &baseline.assets {
            if !current_map.contains_key(baseline_asset.hostname.as_str()) {
                changes.push(AsmChange {
                    id: Uuid::new_v4().to_string(),
                    monitor_id: monitor_id.to_string(),
                    baseline_id: baseline.id.clone(),
                    change_type: ChangeType::AssetRemoved,
                    severity: AlertSeverity::Medium,
                    hostname: baseline_asset.hostname.clone(),
                    details: ChangeDetails {
                        description: format!("Asset no longer detected: {}", baseline_asset.hostname),
                        old_value: Some(baseline_asset.ip_addresses.join(", ")),
                        new_value: None,
                        affected_ports: baseline_asset.ports.iter().map(|p| p.port).collect(),
                        metadata: HashMap::new(),
                    },
                    detected_at: now,
                    acknowledged: false,
                    acknowledged_by: None,
                    acknowledged_at: None,
                });
            }
        }

        // Check for changes in existing assets
        for current in current_assets {
            if let Some(baseline_asset) = baseline_map.get(current.hostname.as_str()) {
                // Check for IP changes
                let new_ips: Vec<&String> = current.ip_addresses.iter()
                    .filter(|ip| !baseline_asset.ip_addresses.contains(ip))
                    .collect();

                if !new_ips.is_empty() {
                    changes.push(AsmChange {
                        id: Uuid::new_v4().to_string(),
                        monitor_id: monitor_id.to_string(),
                        baseline_id: baseline.id.clone(),
                        change_type: ChangeType::IpAddressChange,
                        severity: AlertSeverity::Low,
                        hostname: current.hostname.clone(),
                        details: ChangeDetails {
                            description: format!("IP address changed for {}", current.hostname),
                            old_value: Some(baseline_asset.ip_addresses.join(", ")),
                            new_value: Some(current.ip_addresses.join(", ")),
                            affected_ports: vec![],
                            metadata: HashMap::new(),
                        },
                        detected_at: now,
                        acknowledged: false,
                        acknowledged_by: None,
                        acknowledged_at: None,
                    });
                }

                // Check for new ports
                let baseline_ports: HashSet<u16> = baseline_asset.ports.iter()
                    .map(|p| p.port)
                    .collect();

                let current_ports: HashSet<u16> = current.ports.iter()
                    .map(|p| p.port)
                    .collect();

                let new_ports: Vec<u16> = current_ports.difference(&baseline_ports).copied().collect();
                let closed_ports: Vec<u16> = baseline_ports.difference(&current_ports).copied().collect();

                for port in new_ports {
                    let severity = Self::port_severity(port);
                    changes.push(AsmChange {
                        id: Uuid::new_v4().to_string(),
                        monitor_id: monitor_id.to_string(),
                        baseline_id: baseline.id.clone(),
                        change_type: ChangeType::NewPort,
                        severity,
                        hostname: current.hostname.clone(),
                        details: ChangeDetails {
                            description: format!("New port {} opened on {}", port, current.hostname),
                            old_value: None,
                            new_value: Some(port.to_string()),
                            affected_ports: vec![port],
                            metadata: HashMap::new(),
                        },
                        detected_at: now,
                        acknowledged: false,
                        acknowledged_by: None,
                        acknowledged_at: None,
                    });
                }

                for port in closed_ports {
                    changes.push(AsmChange {
                        id: Uuid::new_v4().to_string(),
                        monitor_id: monitor_id.to_string(),
                        baseline_id: baseline.id.clone(),
                        change_type: ChangeType::PortClosed,
                        severity: AlertSeverity::Info,
                        hostname: current.hostname.clone(),
                        details: ChangeDetails {
                            description: format!("Port {} closed on {}", port, current.hostname),
                            old_value: Some(port.to_string()),
                            new_value: None,
                            affected_ports: vec![port],
                            metadata: HashMap::new(),
                        },
                        detected_at: now,
                        acknowledged: false,
                        acknowledged_by: None,
                        acknowledged_at: None,
                    });
                }

                // Check for SSL certificate changes
                if let (Some(old_ssl), Some(new_ssl)) = (&baseline_asset.ssl_info, &current.ssl_info) {
                    if old_ssl.fingerprint != new_ssl.fingerprint && !old_ssl.fingerprint.is_empty() {
                        changes.push(AsmChange {
                            id: Uuid::new_v4().to_string(),
                            monitor_id: monitor_id.to_string(),
                            baseline_id: baseline.id.clone(),
                            change_type: ChangeType::CertificateChange,
                            severity: AlertSeverity::Medium,
                            hostname: current.hostname.clone(),
                            details: ChangeDetails {
                                description: format!("SSL certificate changed for {}", current.hostname),
                                old_value: Some(old_ssl.issuer.clone()),
                                new_value: Some(new_ssl.issuer.clone()),
                                affected_ports: vec![443],
                                metadata: HashMap::new(),
                            },
                            detected_at: now,
                            acknowledged: false,
                            acknowledged_by: None,
                            acknowledged_at: None,
                        });
                    }

                    // Check for expiring certificates
                    let days_until_expiry = (new_ssl.valid_until - now).num_days();
                    if days_until_expiry <= 30 && days_until_expiry > 0 {
                        changes.push(AsmChange {
                            id: Uuid::new_v4().to_string(),
                            monitor_id: monitor_id.to_string(),
                            baseline_id: baseline.id.clone(),
                            change_type: ChangeType::CertificateExpiring,
                            severity: if days_until_expiry <= 7 {
                                AlertSeverity::Critical
                            } else {
                                AlertSeverity::High
                            },
                            hostname: current.hostname.clone(),
                            details: ChangeDetails {
                                description: format!(
                                    "SSL certificate for {} expires in {} days",
                                    current.hostname,
                                    days_until_expiry
                                ),
                                old_value: None,
                                new_value: Some(new_ssl.valid_until.to_rfc3339()),
                                affected_ports: vec![443],
                                metadata: HashMap::new(),
                            },
                            detected_at: now,
                            acknowledged: false,
                            acknowledged_by: None,
                            acknowledged_at: None,
                        });
                    }
                }

                // Check for technology changes
                let old_techs: HashSet<&str> = baseline_asset.technologies.iter()
                    .map(|t| t.as_str())
                    .collect();

                let new_techs: HashSet<&str> = current.technologies.iter()
                    .map(|t| t.as_str())
                    .collect();

                let added_techs: Vec<&&str> = new_techs.difference(&old_techs).collect();
                let removed_techs: Vec<&&str> = old_techs.difference(&new_techs).collect();

                if !added_techs.is_empty() || !removed_techs.is_empty() {
                    changes.push(AsmChange {
                        id: Uuid::new_v4().to_string(),
                        monitor_id: monitor_id.to_string(),
                        baseline_id: baseline.id.clone(),
                        change_type: ChangeType::TechnologyChange,
                        severity: AlertSeverity::Low,
                        hostname: current.hostname.clone(),
                        details: ChangeDetails {
                            description: format!("Technology stack changed for {}", current.hostname),
                            old_value: if removed_techs.is_empty() {
                                None
                            } else {
                                Some(removed_techs.iter().map(|t| **t).collect::<Vec<_>>().join(", "))
                            },
                            new_value: if added_techs.is_empty() {
                                None
                            } else {
                                Some(added_techs.iter().map(|t| **t).collect::<Vec<_>>().join(", "))
                            },
                            affected_ports: vec![],
                            metadata: HashMap::new(),
                        },
                        detected_at: now,
                        acknowledged: false,
                        acknowledged_by: None,
                        acknowledged_at: None,
                    });
                }

                // Check for service changes on same ports
                for current_port in &current.ports {
                    if let Some(baseline_port) = baseline_asset.ports.iter()
                        .find(|p| p.port == current_port.port)
                    {
                        if current_port.service != baseline_port.service ||
                           current_port.version != baseline_port.version
                        {
                            changes.push(AsmChange {
                                id: Uuid::new_v4().to_string(),
                                monitor_id: monitor_id.to_string(),
                                baseline_id: baseline.id.clone(),
                                change_type: ChangeType::ServiceChange,
                                severity: AlertSeverity::Low,
                                hostname: current.hostname.clone(),
                                details: ChangeDetails {
                                    description: format!(
                                        "Service changed on port {} for {}",
                                        current_port.port,
                                        current.hostname
                                    ),
                                    old_value: Some(format!(
                                        "{} {}",
                                        baseline_port.service.as_deref().unwrap_or("unknown"),
                                        baseline_port.version.as_deref().unwrap_or("")
                                    )),
                                    new_value: Some(format!(
                                        "{} {}",
                                        current_port.service.as_deref().unwrap_or("unknown"),
                                        current_port.version.as_deref().unwrap_or("")
                                    )),
                                    affected_ports: vec![current_port.port],
                                    metadata: HashMap::new(),
                                },
                                detected_at: now,
                                acknowledged: false,
                                acknowledged_by: None,
                                acknowledged_at: None,
                            });
                        }
                    }
                }
            }
        }

        changes
    }

    /// Check if a hostname/IP is authorized
    fn is_authorized(
        hostname: &str,
        ip_addresses: &[String],
        authorized_patterns: &[AuthorizedAsset],
    ) -> bool {
        for pattern in authorized_patterns {
            // Check hostname pattern (simple glob matching)
            if Self::matches_pattern(hostname, &pattern.hostname_pattern) {
                return true;
            }

            // Check IP ranges
            for ip in ip_addresses {
                for range in &pattern.ip_ranges {
                    if Self::ip_in_range(ip, range) {
                        return true;
                    }
                }
            }
        }

        // If no patterns defined, consider everything authorized
        authorized_patterns.is_empty()
    }

    /// Simple glob pattern matching
    fn matches_pattern(hostname: &str, pattern: &str) -> bool {
        if pattern == "*" {
            return true;
        }

        if pattern.starts_with("*.") {
            let suffix = &pattern[1..]; // Remove the *
            return hostname.ends_with(suffix) || hostname == &pattern[2..];
        }

        if pattern.ends_with(".*") {
            let prefix = &pattern[..pattern.len() - 2];
            return hostname.starts_with(prefix);
        }

        hostname == pattern
    }

    /// Check if IP is in CIDR range (simplified)
    fn ip_in_range(ip: &str, cidr: &str) -> bool {
        // Simple implementation - in production, use a proper IP library
        if !cidr.contains('/') {
            return ip == cidr;
        }

        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            return false;
        }

        // For now, just check if IP starts with the network portion
        // This is a simplified check
        ip.starts_with(parts[0].split('.').take(3).collect::<Vec<_>>().join(".").as_str())
    }

    /// Determine severity based on port number
    fn port_severity(port: u16) -> AlertSeverity {
        match port {
            // Critical: Remote access, databases
            22 | 3389 | 5900 | 1433 | 3306 | 5432 | 27017 | 6379 => AlertSeverity::High,
            // High risk: SMB, RDP, FTP
            21 | 23 | 445 | 135 | 139 => AlertSeverity::High,
            // Medium: Common services
            80 | 443 | 8080 | 8443 => AlertSeverity::Low,
            // Other ports
            _ => AlertSeverity::Medium,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pattern_matching() {
        assert!(ChangeDetector::matches_pattern("sub.example.com", "*.example.com"));
        assert!(ChangeDetector::matches_pattern("example.com", "*.example.com"));
        assert!(!ChangeDetector::matches_pattern("other.com", "*.example.com"));
        assert!(ChangeDetector::matches_pattern("anything", "*"));
    }

    #[test]
    fn test_detect_new_subdomain() {
        let baseline = AsmBaseline {
            id: "baseline-1".to_string(),
            monitor_id: "monitor-1".to_string(),
            assets: vec![
                BaselineAsset {
                    hostname: "www.example.com".to_string(),
                    ip_addresses: vec!["1.2.3.4".to_string()],
                    ports: vec![],
                    technologies: vec![],
                    ssl_info: None,
                    first_seen: Utc::now(),
                    last_seen: Utc::now(),
                },
            ],
            summary: BaselineSummary {
                total_assets: 1,
                total_ports: 0,
                total_services: 0,
                assets_with_ssl: 0,
                unique_technologies: 0,
            },
            is_active: true,
            created_at: Utc::now(),
        };

        let current = vec![
            BaselineAsset {
                hostname: "www.example.com".to_string(),
                ip_addresses: vec!["1.2.3.4".to_string()],
                ports: vec![],
                technologies: vec![],
                ssl_info: None,
                first_seen: Utc::now(),
                last_seen: Utc::now(),
            },
            BaselineAsset {
                hostname: "new.example.com".to_string(),
                ip_addresses: vec!["1.2.3.5".to_string()],
                ports: vec![],
                technologies: vec![],
                ssl_info: None,
                first_seen: Utc::now(),
                last_seen: Utc::now(),
            },
        ];

        let changes = ChangeDetector::detect_changes(
            "monitor-1",
            &baseline,
            &current,
            &[AuthorizedAsset {
                id: "auth-1".to_string(),
                user_id: "user-1".to_string(),
                hostname_pattern: "*.example.com".to_string(),
                ip_ranges: vec![],
                description: None,
                created_at: Utc::now(),
            }],
        );

        assert_eq!(changes.len(), 1);
        assert!(matches!(changes[0].change_type, ChangeType::NewSubdomain));
    }
}
