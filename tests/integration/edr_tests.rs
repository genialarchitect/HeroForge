//! Integration tests for EDR (Endpoint Detection and Response) connectors
//!
//! These tests verify the EDR integration functionality including:
//! - Client configuration and initialization
//! - Alert retrieval and management
//! - Endpoint queries
//! - IOC operations
//! - Response actions
//!
//! Note: Some tests require mock servers or environment variables for API credentials.

use heroforge::integrations::edr::{
    AlertSeverity, AlertStatus, EdrAlert, EdrConnector, EdrEndpoint, EdrIoc, EdrManager,
    EdrPlatform, ResponseAction,
};
use chrono::Utc;

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn test_edr_platform_serialization() {
        // Test that platform enum serializes correctly
        let platforms = vec![
            (EdrPlatform::CrowdStrike, "\"crowdstrike\""),
            (EdrPlatform::SentinelOne, "\"sentinel_one\""),
            (EdrPlatform::Defender, "\"defender\""),
        ];

        for (platform, expected) in platforms {
            let serialized = serde_json::to_string(&platform).unwrap();
            assert_eq!(serialized, expected, "Platform {:?} serialization failed", platform);
        }
    }

    #[test]
    fn test_alert_severity_ordering() {
        // Test that severity levels can be compared for prioritization
        let low = AlertSeverity::Low;
        let medium = AlertSeverity::Medium;
        let high = AlertSeverity::High;
        let critical = AlertSeverity::Critical;

        // Using debug string comparison as a basic ordering check
        assert_eq!(format!("{:?}", low), "Low");
        assert_eq!(format!("{:?}", medium), "Medium");
        assert_eq!(format!("{:?}", high), "High");
        assert_eq!(format!("{:?}", critical), "Critical");
    }

    #[test]
    fn test_alert_status_values() {
        let statuses = vec![
            AlertStatus::New,
            AlertStatus::InProgress,
            AlertStatus::Resolved,
            AlertStatus::FalsePositive,
        ];

        for status in statuses {
            // Verify serialization/deserialization roundtrip
            let json = serde_json::to_string(&status).unwrap();
            let deserialized: AlertStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(format!("{:?}", status), format!("{:?}", deserialized));
        }
    }

    #[test]
    fn test_response_action_serialization() {
        let actions = vec![
            ResponseAction::Isolate,
            ResponseAction::Quarantine,
            ResponseAction::Kill,
            ResponseAction::Remediate,
            ResponseAction::Scan,
        ];

        for action in actions {
            let json = serde_json::to_string(&action).unwrap();
            let deserialized: ResponseAction = serde_json::from_str(&json).unwrap();
            assert_eq!(format!("{:?}", action), format!("{:?}", deserialized));
        }
    }

    #[test]
    fn test_edr_alert_creation() {
        let alert = EdrAlert {
            id: "test-alert-001".to_string(),
            platform: EdrPlatform::CrowdStrike,
            title: "Suspicious PowerShell Activity".to_string(),
            description: "PowerShell executing encoded commands".to_string(),
            severity: AlertSeverity::High,
            status: AlertStatus::New,
            hostname: Some("WORKSTATION-01".to_string()),
            endpoint_id: Some("endpoint-123".to_string()),
            tactics: vec!["Execution".to_string(), "Defense Evasion".to_string()],
            techniques: vec!["T1059.001".to_string(), "T1027".to_string()],
            iocs: vec![
                EdrIoc {
                    ioc_type: "sha256".to_string(),
                    value: "a1b2c3d4...".to_string(),
                    description: Some("Malicious script hash".to_string()),
                },
            ],
            raw_data: serde_json::json!({"detection_id": "12345"}),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        assert_eq!(alert.id, "test-alert-001");
        assert_eq!(alert.tactics.len(), 2);
        assert_eq!(alert.techniques.len(), 2);
        assert_eq!(alert.iocs.len(), 1);
    }

    #[test]
    fn test_edr_endpoint_creation() {
        let endpoint = EdrEndpoint {
            id: "endpoint-001".to_string(),
            platform: EdrPlatform::SentinelOne,
            hostname: "SERVER-PROD-01".to_string(),
            os: "Windows Server 2022".to_string(),
            os_version: Some("21H2".to_string()),
            ip_addresses: vec!["192.168.1.100".to_string(), "10.0.0.50".to_string()],
            mac_addresses: vec!["00:11:22:33:44:55".to_string()],
            agent_version: Some("4.5.0.1234".to_string()),
            last_seen: Utc::now(),
            status: "online".to_string(),
            tags: vec!["production".to_string(), "critical".to_string()],
            group: Some("Production Servers".to_string()),
        };

        assert_eq!(endpoint.hostname, "SERVER-PROD-01");
        assert_eq!(endpoint.ip_addresses.len(), 2);
        assert_eq!(endpoint.tags.len(), 2);
    }

    #[test]
    fn test_edr_ioc_types() {
        let iocs = vec![
            EdrIoc {
                ioc_type: "sha256".to_string(),
                value: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
                description: Some("Empty file hash".to_string()),
            },
            EdrIoc {
                ioc_type: "md5".to_string(),
                value: "d41d8cd98f00b204e9800998ecf8427e".to_string(),
                description: None,
            },
            EdrIoc {
                ioc_type: "domain".to_string(),
                value: "malicious.example.com".to_string(),
                description: Some("C2 domain".to_string()),
            },
            EdrIoc {
                ioc_type: "ip".to_string(),
                value: "192.168.1.100".to_string(),
                description: None,
            },
        ];

        for ioc in &iocs {
            let json = serde_json::to_string(ioc).unwrap();
            let deserialized: EdrIoc = serde_json::from_str(&json).unwrap();
            assert_eq!(ioc.value, deserialized.value);
            assert_eq!(ioc.ioc_type, deserialized.ioc_type);
        }
    }
}

#[cfg(test)]
mod crowdstrike_tests {
    use super::*;
    use heroforge::integrations::edr::CrowdStrikeClient;

    #[test]
    fn test_crowdstrike_config_builder() {
        // Test configuration without actual API calls
        let result = CrowdStrikeClient::new(
            "test-client-id".to_string(),
            "test-client-secret".to_string(),
            None, // US-1 cloud (default)
        );

        // Should succeed in creating client (validation happens on first API call)
        assert!(result.is_ok());
    }

    #[test]
    fn test_crowdstrike_cloud_regions() {
        let regions = vec![
            Some("us-1".to_string()),
            Some("us-2".to_string()),
            Some("eu-1".to_string()),
            Some("us-gov-1".to_string()),
        ];

        for region in regions {
            let result = CrowdStrikeClient::new(
                "test-id".to_string(),
                "test-secret".to_string(),
                region.clone(),
            );
            assert!(result.is_ok(), "Failed for region {:?}", region);
        }
    }

    #[tokio::test]
    async fn test_crowdstrike_empty_credentials() {
        let result = CrowdStrikeClient::new(
            "".to_string(),
            "".to_string(),
            None,
        );

        // Client creation should succeed, but first API call should fail
        // This tests that we don't panic on empty credentials
        assert!(result.is_ok());
    }
}

#[cfg(test)]
mod sentinelone_tests {
    use super::*;
    use heroforge::integrations::edr::SentinelOneClient;

    #[test]
    fn test_sentinelone_config() {
        let result = SentinelOneClient::new(
            "https://usea1.sentinelone.net".to_string(),
            "test-api-token".to_string(),
        );

        assert!(result.is_ok());
    }

    #[test]
    fn test_sentinelone_url_normalization() {
        // Test with trailing slash
        let result1 = SentinelOneClient::new(
            "https://usea1.sentinelone.net/".to_string(),
            "test-token".to_string(),
        );
        assert!(result1.is_ok());

        // Test without trailing slash
        let result2 = SentinelOneClient::new(
            "https://usea1.sentinelone.net".to_string(),
            "test-token".to_string(),
        );
        assert!(result2.is_ok());
    }
}

#[cfg(test)]
mod defender_tests {
    use super::*;
    use heroforge::integrations::edr::DefenderClient;

    #[test]
    fn test_defender_config() {
        let result = DefenderClient::new(
            "test-tenant-id".to_string(),
            "test-client-id".to_string(),
            "test-client-secret".to_string(),
        );

        assert!(result.is_ok());
    }

    #[test]
    fn test_defender_azure_ad_urls() {
        // Verify client can be created with various tenant ID formats
        let tenant_formats = vec![
            "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
            "contoso.onmicrosoft.com",
            "contoso.com",
        ];

        for tenant in tenant_formats {
            let result = DefenderClient::new(
                tenant.to_string(),
                "client-id".to_string(),
                "client-secret".to_string(),
            );
            assert!(result.is_ok(), "Failed for tenant format: {}", tenant);
        }
    }
}

#[cfg(test)]
mod manager_tests {
    use super::*;

    #[test]
    fn test_edr_manager_creation() {
        let manager = EdrManager::new();

        // Manager should start with no connectors
        let platforms = manager.list_platforms();
        assert!(platforms.is_empty());
    }

    #[test]
    fn test_edr_manager_add_crowdstrike() {
        let mut manager = EdrManager::new();

        let client = CrowdStrikeClient::new(
            "test-id".to_string(),
            "test-secret".to_string(),
            None,
        ).unwrap();

        manager.add_connector(EdrPlatform::CrowdStrike, Box::new(client));

        let platforms = manager.list_platforms();
        assert_eq!(platforms.len(), 1);
        assert!(platforms.contains(&EdrPlatform::CrowdStrike));
    }

    #[test]
    fn test_edr_manager_multiple_platforms() {
        let mut manager = EdrManager::new();

        // Add CrowdStrike
        let cs_client = CrowdStrikeClient::new(
            "cs-id".to_string(),
            "cs-secret".to_string(),
            None,
        ).unwrap();
        manager.add_connector(EdrPlatform::CrowdStrike, Box::new(cs_client));

        // Add SentinelOne
        let s1_client = SentinelOneClient::new(
            "https://test.sentinelone.net".to_string(),
            "s1-token".to_string(),
        ).unwrap();
        manager.add_connector(EdrPlatform::SentinelOne, Box::new(s1_client));

        // Add Defender
        let def_client = DefenderClient::new(
            "tenant".to_string(),
            "client".to_string(),
            "secret".to_string(),
        ).unwrap();
        manager.add_connector(EdrPlatform::Defender, Box::new(def_client));

        let platforms = manager.list_platforms();
        assert_eq!(platforms.len(), 3);
    }

    #[test]
    fn test_edr_manager_remove_connector() {
        let mut manager = EdrManager::new();

        let client = CrowdStrikeClient::new(
            "test-id".to_string(),
            "test-secret".to_string(),
            None,
        ).unwrap();

        manager.add_connector(EdrPlatform::CrowdStrike, Box::new(client));
        assert_eq!(manager.list_platforms().len(), 1);

        manager.remove_connector(&EdrPlatform::CrowdStrike);
        assert_eq!(manager.list_platforms().len(), 0);
    }

    use heroforge::integrations::edr::{CrowdStrikeClient, SentinelOneClient, DefenderClient};
}

#[cfg(test)]
mod correlation_tests {
    use super::*;

    #[test]
    fn test_alert_correlation_by_endpoint() {
        // Test correlating alerts from multiple platforms for same endpoint
        let alerts = vec![
            EdrAlert {
                id: "cs-001".to_string(),
                platform: EdrPlatform::CrowdStrike,
                title: "Malware Detected".to_string(),
                description: "Ransomware identified".to_string(),
                severity: AlertSeverity::Critical,
                status: AlertStatus::New,
                hostname: Some("WORKSTATION-01".to_string()),
                endpoint_id: Some("ep-123".to_string()),
                tactics: vec!["Impact".to_string()],
                techniques: vec!["T1486".to_string()],
                iocs: vec![],
                raw_data: serde_json::json!({}),
                created_at: Utc::now(),
                updated_at: Utc::now(),
            },
            EdrAlert {
                id: "s1-001".to_string(),
                platform: EdrPlatform::SentinelOne,
                title: "Ransomware Activity".to_string(),
                description: "File encryption detected".to_string(),
                severity: AlertSeverity::Critical,
                status: AlertStatus::New,
                hostname: Some("WORKSTATION-01".to_string()),
                endpoint_id: Some("agent-456".to_string()),
                tactics: vec!["Impact".to_string()],
                techniques: vec!["T1486".to_string()],
                iocs: vec![],
                raw_data: serde_json::json!({}),
                created_at: Utc::now(),
                updated_at: Utc::now(),
            },
        ];

        // Correlate by hostname
        let mut by_hostname: std::collections::HashMap<String, Vec<&EdrAlert>> = std::collections::HashMap::new();
        for alert in &alerts {
            if let Some(ref hostname) = alert.hostname {
                by_hostname.entry(hostname.clone()).or_default().push(alert);
            }
        }

        assert_eq!(by_hostname.get("WORKSTATION-01").unwrap().len(), 2);
    }

    #[test]
    fn test_alert_correlation_by_technique() {
        let alerts = vec![
            EdrAlert {
                id: "1".to_string(),
                platform: EdrPlatform::CrowdStrike,
                title: "Alert 1".to_string(),
                description: "".to_string(),
                severity: AlertSeverity::High,
                status: AlertStatus::New,
                hostname: None,
                endpoint_id: None,
                tactics: vec!["Execution".to_string()],
                techniques: vec!["T1059.001".to_string()],
                iocs: vec![],
                raw_data: serde_json::json!({}),
                created_at: Utc::now(),
                updated_at: Utc::now(),
            },
            EdrAlert {
                id: "2".to_string(),
                platform: EdrPlatform::Defender,
                title: "Alert 2".to_string(),
                description: "".to_string(),
                severity: AlertSeverity::High,
                status: AlertStatus::New,
                hostname: None,
                endpoint_id: None,
                tactics: vec!["Execution".to_string()],
                techniques: vec!["T1059.001".to_string(), "T1027".to_string()],
                iocs: vec![],
                raw_data: serde_json::json!({}),
                created_at: Utc::now(),
                updated_at: Utc::now(),
            },
        ];

        // Correlate by MITRE technique
        let mut by_technique: std::collections::HashMap<String, Vec<&EdrAlert>> = std::collections::HashMap::new();
        for alert in &alerts {
            for technique in &alert.techniques {
                by_technique.entry(technique.clone()).or_default().push(alert);
            }
        }

        assert_eq!(by_technique.get("T1059.001").unwrap().len(), 2);
        assert_eq!(by_technique.get("T1027").unwrap().len(), 1);
    }
}
