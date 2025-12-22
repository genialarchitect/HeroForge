//! Risk scoring for attack surface assets

use chrono::Utc;
use uuid::Uuid;

use super::types::*;

/// Calculates risk scores for assets
pub struct RiskScorer;

impl RiskScorer {
    /// High-risk ports that increase exposure
    const HIGH_RISK_PORTS: &'static [u16] = &[
        21,   // FTP
        22,   // SSH
        23,   // Telnet
        25,   // SMTP
        135,  // RPC
        139,  // NetBIOS
        445,  // SMB
        1433, // MSSQL
        1521, // Oracle
        3306, // MySQL
        3389, // RDP
        5432, // PostgreSQL
        5900, // VNC
        6379, // Redis
        27017, // MongoDB
    ];

    /// Critical ports that significantly increase risk
    const CRITICAL_PORTS: &'static [u16] = &[
        23,   // Telnet (unencrypted)
        139,  // NetBIOS
        445,  // SMB
        3389, // RDP
        5900, // VNC
    ];

    /// Calculate risk score for an asset
    pub fn calculate_score(
        asset: &BaselineAsset,
        is_authorized: bool,
    ) -> AssetRiskScore {
        let mut factors = Vec::new();
        let mut total_score = 0u32;

        // Factor 1: Exposed Ports (25% weight)
        let port_factor = Self::calculate_port_factor(asset);
        factors.push(port_factor.clone());
        total_score += (port_factor.score as f32 * port_factor.weight) as u32;

        // Factor 2: Technology Stack (20% weight)
        let tech_factor = Self::calculate_technology_factor(asset);
        factors.push(tech_factor.clone());
        total_score += (tech_factor.score as f32 * tech_factor.weight) as u32;

        // Factor 3: SSL/TLS (15% weight)
        let ssl_factor = Self::calculate_ssl_factor(asset);
        factors.push(ssl_factor.clone());
        total_score += (ssl_factor.score as f32 * ssl_factor.weight) as u32;

        // Factor 4: Internet Exposure (20% weight)
        let exposure_factor = Self::calculate_exposure_factor(asset);
        factors.push(exposure_factor.clone());
        total_score += (exposure_factor.score as f32 * exposure_factor.weight) as u32;

        // Factor 5: Visibility (10% weight)
        let visibility_factor = Self::calculate_visibility_factor(asset);
        factors.push(visibility_factor.clone());
        total_score += (visibility_factor.score as f32 * visibility_factor.weight) as u32;

        // Factor 6: Authorization (10% weight)
        let auth_factor = Self::calculate_authorization_factor(is_authorized);
        factors.push(auth_factor.clone());
        total_score += (auth_factor.score as f32 * auth_factor.weight) as u32;

        // Normalize to 0-100
        let overall_score = total_score.min(100);

        AssetRiskScore {
            id: Uuid::new_v4().to_string(),
            asset_id: None,
            hostname: asset.hostname.clone(),
            overall_score,
            factors,
            calculated_at: Utc::now(),
        }
    }

    /// Calculate risk from exposed ports
    fn calculate_port_factor(asset: &BaselineAsset) -> RiskFactor {
        let open_ports: Vec<u16> = asset.ports.iter().map(|p| p.port).collect();

        let high_risk_count = open_ports.iter()
            .filter(|p| Self::HIGH_RISK_PORTS.contains(p))
            .count();

        let critical_count = open_ports.iter()
            .filter(|p| Self::CRITICAL_PORTS.contains(p))
            .count();

        let score = if critical_count > 0 {
            70 + (critical_count as u32 * 10).min(30)
        } else if high_risk_count > 0 {
            40 + (high_risk_count as u32 * 10).min(30)
        } else if open_ports.len() > 10 {
            30 + ((open_ports.len() - 10) as u32 * 2).min(20)
        } else {
            (open_ports.len() as u32 * 3).min(30)
        };

        let description = if critical_count > 0 {
            format!("{} critical ports exposed", critical_count)
        } else if high_risk_count > 0 {
            format!("{} high-risk ports exposed", high_risk_count)
        } else {
            format!("{} ports exposed", open_ports.len())
        };

        RiskFactor {
            factor_type: RiskFactorType::ExposedPorts,
            weight: 0.25,
            score,
            description,
            details: Some(open_ports.iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(", ")),
        }
    }

    /// Calculate risk from technology stack
    fn calculate_technology_factor(asset: &BaselineAsset) -> RiskFactor {
        // Check for known risky technologies
        let risky_patterns = [
            ("php/5", 40),
            ("php/4", 60),
            ("apache/2.2", 30),
            ("apache/2.0", 50),
            ("iis/6", 60),
            ("iis/7", 30),
            ("tomcat/6", 40),
            ("tomcat/5", 60),
            ("wordpress", 20),
            ("joomla", 20),
            ("drupal/7", 30),
            ("struts", 50),
        ];

        let mut max_score = 0u32;
        let mut risky_tech = Vec::new();

        for tech in &asset.technologies {
            let tech_lower = tech.to_lowercase();
            for (pattern, score) in &risky_patterns {
                if tech_lower.contains(pattern) {
                    max_score = max_score.max(*score);
                    risky_tech.push(tech.clone());
                }
            }
        }

        // Base score for having detectable tech
        if asset.technologies.is_empty() {
            max_score = 10; // Unknown is slightly risky
        }

        RiskFactor {
            factor_type: RiskFactorType::TechnologyStack,
            weight: 0.20,
            score: max_score.min(100),
            description: if risky_tech.is_empty() {
                "No high-risk technologies detected".to_string()
            } else {
                format!("Potentially risky: {}", risky_tech.join(", "))
            },
            details: Some(asset.technologies.join(", ")),
        }
    }

    /// Calculate risk from SSL/TLS configuration
    fn calculate_ssl_factor(asset: &BaselineAsset) -> RiskFactor {
        let (score, description) = if let Some(ssl) = &asset.ssl_info {
            let now = Utc::now();
            let days_until_expiry = (ssl.valid_until - now).num_days();

            if days_until_expiry < 0 {
                (100, "Certificate is expired".to_string())
            } else if days_until_expiry < 7 {
                (80, format!("Certificate expires in {} days", days_until_expiry))
            } else if days_until_expiry < 30 {
                (50, format!("Certificate expires in {} days", days_until_expiry))
            } else {
                (10, "Valid SSL certificate".to_string())
            }
        } else {
            // Check if HTTPS ports are open without SSL info
            let has_ssl_ports = asset.ports.iter()
                .any(|p| p.port == 443 || p.port == 8443);

            if has_ssl_ports {
                (60, "HTTPS port open but no certificate info".to_string())
            } else {
                (30, "No HTTPS detected".to_string())
            }
        };

        RiskFactor {
            factor_type: RiskFactorType::SslTls,
            weight: 0.15,
            score,
            description,
            details: asset.ssl_info.as_ref().map(|s| {
                format!("Issuer: {}, Expires: {}", s.issuer, s.valid_until)
            }),
        }
    }

    /// Calculate risk from internet exposure
    fn calculate_exposure_factor(asset: &BaselineAsset) -> RiskFactor {
        // Check for internet-facing indicators
        let has_web_ports = asset.ports.iter()
            .any(|p| p.port == 80 || p.port == 443 || p.port == 8080 || p.port == 8443);

        let has_public_services = asset.ports.iter()
            .any(|p| {
                matches!(
                    p.service.as_deref(),
                    Some("http") | Some("https") | Some("nginx") | Some("apache")
                )
            });

        let score = if has_web_ports && has_public_services {
            60 // Clearly internet-facing
        } else if has_web_ports {
            40 // Likely internet-facing
        } else {
            20 // Less exposed
        };

        RiskFactor {
            factor_type: RiskFactorType::InternetExposure,
            weight: 0.20,
            score,
            description: if has_web_ports {
                "Internet-facing web services detected".to_string()
            } else {
                "Limited public exposure".to_string()
            },
            details: Some(format!("{} open ports", asset.ports.len())),
        }
    }

    /// Calculate risk from asset visibility
    fn calculate_visibility_factor(asset: &BaselineAsset) -> RiskFactor {
        // Assets with hostnames are more visible/discoverable
        let has_hostname = !asset.hostname.parse::<std::net::IpAddr>().is_ok();
        let has_multiple_ips = asset.ip_addresses.len() > 1;

        let score = if has_hostname && has_multiple_ips {
            50 // Highly visible
        } else if has_hostname {
            30 // Normal visibility
        } else {
            10 // Low visibility (IP only)
        };

        RiskFactor {
            factor_type: RiskFactorType::Visibility,
            weight: 0.10,
            score,
            description: if has_hostname {
                format!("DNS hostname: {}", asset.hostname)
            } else {
                "No DNS hostname".to_string()
            },
            details: Some(asset.ip_addresses.join(", ")),
        }
    }

    /// Calculate risk from authorization status
    fn calculate_authorization_factor(is_authorized: bool) -> RiskFactor {
        let score = if is_authorized { 0 } else { 100 };

        RiskFactor {
            factor_type: RiskFactorType::Authorization,
            weight: 0.10,
            score,
            description: if is_authorized {
                "Asset is authorized".to_string()
            } else {
                "Potential shadow IT - unauthorized asset".to_string()
            },
            details: None,
        }
    }

    /// Get risk level label from score
    pub fn risk_level(score: u32) -> &'static str {
        match score {
            0..=20 => "Low",
            21..=40 => "Medium",
            41..=60 => "High",
            61..=80 => "Critical",
            _ => "Severe",
        }
    }

    /// Calculate aggregate risk score for multiple assets
    pub fn calculate_aggregate_score(scores: &[AssetRiskScore]) -> f32 {
        if scores.is_empty() {
            return 0.0;
        }

        // Weighted average favoring higher scores
        let sum: f32 = scores.iter()
            .map(|s| s.overall_score as f32)
            .sum();

        let max: f32 = scores.iter()
            .map(|s| s.overall_score as f32)
            .fold(0.0, f32::max);

        // Blend average and max
        (sum / scores.len() as f32 * 0.7) + (max * 0.3)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_asset(
        hostname: &str,
        ports: Vec<u16>,
        has_ssl: bool,
    ) -> BaselineAsset {
        BaselineAsset {
            hostname: hostname.to_string(),
            ip_addresses: vec!["1.2.3.4".to_string()],
            ports: ports.into_iter().map(|p| BaselinePort {
                port: p,
                protocol: "tcp".to_string(),
                service: Some("http".to_string()),
                version: None,
            }).collect(),
            technologies: vec!["nginx/1.20".to_string()],
            ssl_info: if has_ssl {
                Some(BaselineSslInfo {
                    issuer: "Let's Encrypt".to_string(),
                    subject: hostname.to_string(),
                    valid_from: Utc::now(),
                    valid_until: Utc::now() + chrono::Duration::days(90),
                    fingerprint: "abc123".to_string(),
                })
            } else {
                None
            },
            first_seen: Utc::now(),
            last_seen: Utc::now(),
        }
    }

    #[test]
    fn test_low_risk_asset() {
        let asset = create_test_asset("www.example.com", vec![443], true);
        let score = RiskScorer::calculate_score(&asset, true);

        assert!(score.overall_score <= 40, "Low-risk asset should have low score");
        assert_eq!(RiskScorer::risk_level(score.overall_score), "Low");
    }

    #[test]
    fn test_high_risk_ports() {
        let asset = create_test_asset("db.example.com", vec![22, 3389, 3306], false);
        let score = RiskScorer::calculate_score(&asset, true);

        assert!(score.overall_score >= 40, "High-risk ports should increase score");
    }

    #[test]
    fn test_shadow_it() {
        let asset = create_test_asset("unknown.example.com", vec![80], false);
        let score = RiskScorer::calculate_score(&asset, false);

        // Should have higher score due to unauthorized status
        let authorized_score = RiskScorer::calculate_score(&asset, true);
        assert!(score.overall_score > authorized_score.overall_score);
    }
}
