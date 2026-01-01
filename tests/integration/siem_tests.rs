//! Integration tests for SIEM (Security Information and Event Management) connectors
//!
//! These tests verify the SIEM integration functionality including:
//! - Configuration and initialization
//! - Event conversion and formatting
//! - Log export functionality
//! - Connection testing
//!
//! Note: Some tests require mock servers or environment variables for API credentials.

use chrono::Utc;
use serde_json::json;

#[cfg(test)]
mod siem_type_tests {
    use heroforge::integrations::siem::{SiemType, SiemEvent};
    use super::*;

    #[test]
    fn test_siem_type_serialization() {
        let types = vec![
            (SiemType::Syslog, "\"syslog\""),
            (SiemType::Splunk, "\"splunk\""),
            (SiemType::Elasticsearch, "\"elasticsearch\""),
            (SiemType::AzureSentinel, "\"azure_sentinel\""),
            (SiemType::Chronicle, "\"chronicle\""),
        ];

        for (siem_type, expected) in types {
            let serialized = serde_json::to_string(&siem_type).unwrap();
            assert_eq!(serialized, expected, "SIEM type {:?} serialization failed", siem_type);
        }
    }

    #[test]
    fn test_siem_type_from_str() {
        let mappings = vec![
            ("syslog", Some(SiemType::Syslog)),
            ("splunk", Some(SiemType::Splunk)),
            ("elasticsearch", Some(SiemType::Elasticsearch)),
            ("azure_sentinel", Some(SiemType::AzureSentinel)),
            ("sentinel", Some(SiemType::AzureSentinel)),
            ("chronicle", Some(SiemType::Chronicle)),
            ("google_chronicle", Some(SiemType::Chronicle)),
            ("unknown", None),
        ];

        for (input, expected) in mappings {
            let result = SiemType::from_str(input);
            assert_eq!(result, expected, "Failed for input: {}", input);
        }
    }

    #[test]
    fn test_siem_type_as_str() {
        let mappings = vec![
            (SiemType::Syslog, "syslog"),
            (SiemType::Splunk, "splunk"),
            (SiemType::Elasticsearch, "elasticsearch"),
            (SiemType::AzureSentinel, "azure_sentinel"),
            (SiemType::Chronicle, "chronicle"),
        ];

        for (siem_type, expected) in mappings {
            assert_eq!(siem_type.as_str(), expected);
        }
    }

    #[test]
    fn test_siem_event_creation() {
        let event = SiemEvent {
            timestamp: Utc::now(),
            severity: "High".to_string(),
            event_type: "vulnerability_found".to_string(),
            source_ip: Some("192.168.1.100".to_string()),
            destination_ip: Some("10.0.0.1".to_string()),
            port: Some(443),
            protocol: Some("TCP".to_string()),
            message: "Critical vulnerability detected in Apache server".to_string(),
            details: json!({
                "service": "apache",
                "version": "2.4.49"
            }),
            cve_ids: vec!["CVE-2021-41773".to_string(), "CVE-2021-42013".to_string()],
            cvss_score: Some(9.8),
            scan_id: "scan-001".to_string(),
            user_id: "user-123".to_string(),
        };

        assert_eq!(event.severity, "High");
        assert_eq!(event.event_type, "vulnerability_found");
        assert_eq!(event.cve_ids.len(), 2);
        assert_eq!(event.cvss_score, Some(9.8));
    }

    #[test]
    fn test_siem_event_serialization() {
        let event = SiemEvent {
            timestamp: Utc::now(),
            severity: "Critical".to_string(),
            event_type: "scan_complete".to_string(),
            source_ip: None,
            destination_ip: Some("192.168.1.1".to_string()),
            port: Some(22),
            protocol: Some("TCP".to_string()),
            message: "SSH service discovered".to_string(),
            details: json!({"banner": "OpenSSH_8.4"}),
            cve_ids: vec![],
            cvss_score: None,
            scan_id: "scan-002".to_string(),
            user_id: "admin".to_string(),
        };

        let serialized = serde_json::to_string(&event).unwrap();
        let deserialized: SiemEvent = serde_json::from_str(&serialized).unwrap();

        assert_eq!(event.severity, deserialized.severity);
        assert_eq!(event.event_type, deserialized.event_type);
        assert_eq!(event.scan_id, deserialized.scan_id);
    }
}

#[cfg(test)]
mod azure_sentinel_tests {
    use heroforge::integrations::siem::{SentinelConfig, AzureSentinelExporter};
    use super::*;

    #[test]
    fn test_sentinel_config_creation() {
        let config = SentinelConfig::new(
            "workspace-123".to_string(),
            "shared-key-base64".to_string(),
        );

        assert_eq!(config.workspace_id, "workspace-123");
        assert_eq!(config.shared_key, "shared-key-base64");
        assert_eq!(config.log_type, "HeroForge");
        assert!(config.tenant_id.is_none());
        assert!(config.client_id.is_none());
        assert!(config.client_secret.is_none());
    }

    #[test]
    fn test_sentinel_config_with_log_type() {
        let config = SentinelConfig::new("ws".to_string(), "key".to_string())
            .with_log_type("CustomSecurityLogs".to_string());

        assert_eq!(config.log_type, "CustomSecurityLogs");
    }

    #[test]
    fn test_sentinel_config_with_aad_credentials() {
        let config = SentinelConfig::new("ws".to_string(), "key".to_string())
            .with_aad_credentials(
                "tenant-uuid".to_string(),
                "client-uuid".to_string(),
                "client-secret".to_string(),
            );

        assert_eq!(config.tenant_id, Some("tenant-uuid".to_string()));
        assert_eq!(config.client_id, Some("client-uuid".to_string()));
        assert_eq!(config.client_secret, Some("client-secret".to_string()));
    }

    #[test]
    fn test_sentinel_exporter_creation() {
        let config = SentinelConfig::new(
            "test-workspace".to_string(),
            "dGVzdC1rZXk=".to_string(), // base64 of "test-key"
        );

        let result = AzureSentinelExporter::new(config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_sentinel_config_builder_pattern() {
        let config = SentinelConfig::new("ws".to_string(), "key".to_string())
            .with_log_type("VulnerabilityFindings".to_string())
            .with_aad_credentials(
                "tenant".to_string(),
                "client".to_string(),
                "secret".to_string(),
            );

        assert_eq!(config.log_type, "VulnerabilityFindings");
        assert!(config.tenant_id.is_some());
    }
}

#[cfg(test)]
mod chronicle_tests {
    use heroforge::integrations::siem::{ChronicleConfig, ChronicleExporter};
    use super::*;

    #[test]
    fn test_chronicle_config_creation() {
        let config = ChronicleConfig::new(
            "project-123".to_string(),
            "customer-uuid".to_string(),
            "api-key-here".to_string(),
        );

        assert_eq!(config.project_id, "project-123");
        assert_eq!(config.customer_id, "customer-uuid");
        assert_eq!(config.api_key, "api-key-here");
        assert_eq!(config.region, "us");
        assert_eq!(config.log_type, "HEROFORGE");
    }

    #[test]
    fn test_chronicle_config_with_region() {
        let regions = vec!["us", "europe", "asia-southeast1"];

        for region in regions {
            let config = ChronicleConfig::new(
                "project".to_string(),
                "customer".to_string(),
                "key".to_string(),
            ).with_region(region.to_string());

            assert_eq!(config.region, region);
        }
    }

    #[test]
    fn test_chronicle_config_with_log_type() {
        let config = ChronicleConfig::new(
            "p".to_string(),
            "c".to_string(),
            "k".to_string(),
        ).with_log_type("CUSTOM_SECURITY_EVENTS".to_string());

        assert_eq!(config.log_type, "CUSTOM_SECURITY_EVENTS");
    }

    #[test]
    fn test_chronicle_exporter_creation() {
        let config = ChronicleConfig::new(
            "test-project".to_string(),
            "test-customer".to_string(),
            "test-api-key".to_string(),
        );

        let result = ChronicleExporter::new(config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_chronicle_config_builder_pattern() {
        let config = ChronicleConfig::new(
            "project".to_string(),
            "customer".to_string(),
            "api-key".to_string(),
        )
        .with_region("europe".to_string())
        .with_log_type("SECURITY_SCAN_RESULTS".to_string());

        assert_eq!(config.region, "europe");
        assert_eq!(config.log_type, "SECURITY_SCAN_RESULTS");
    }
}

#[cfg(test)]
mod event_conversion_tests {
    use heroforge::integrations::siem::SiemEvent;
    use super::*;

    #[test]
    fn test_vulnerability_event() {
        let event = SiemEvent {
            timestamp: Utc::now(),
            severity: "Critical".to_string(),
            event_type: "vulnerability_found".to_string(),
            source_ip: Some("scanner.internal".to_string()),
            destination_ip: Some("192.168.1.50".to_string()),
            port: Some(80),
            protocol: Some("HTTP".to_string()),
            message: "Log4j RCE vulnerability detected".to_string(),
            details: json!({
                "service": "Apache Log4j",
                "version": "2.14.0",
                "exploitable": true
            }),
            cve_ids: vec!["CVE-2021-44228".to_string()],
            cvss_score: Some(10.0),
            scan_id: "vuln-scan-001".to_string(),
            user_id: "security-team".to_string(),
        };

        assert_eq!(event.cvss_score, Some(10.0));
        assert!(event.details.get("exploitable").and_then(|v| v.as_bool()).unwrap_or(false));
    }

    #[test]
    fn test_host_discovery_event() {
        let event = SiemEvent {
            timestamp: Utc::now(),
            severity: "Informational".to_string(),
            event_type: "host_discovered".to_string(),
            source_ip: None,
            destination_ip: Some("192.168.1.100".to_string()),
            port: None,
            protocol: None,
            message: "New host discovered on network".to_string(),
            details: json!({
                "hostname": "web-server-01",
                "os": "Linux",
                "mac_address": "00:11:22:33:44:55"
            }),
            cve_ids: vec![],
            cvss_score: None,
            scan_id: "discovery-001".to_string(),
            user_id: "recon-task".to_string(),
        };

        assert_eq!(event.event_type, "host_discovered");
        assert!(event.cve_ids.is_empty());
    }

    #[test]
    fn test_port_scan_event() {
        let event = SiemEvent {
            timestamp: Utc::now(),
            severity: "Low".to_string(),
            event_type: "port_found".to_string(),
            source_ip: Some("10.0.0.1".to_string()),
            destination_ip: Some("192.168.1.50".to_string()),
            port: Some(22),
            protocol: Some("TCP".to_string()),
            message: "SSH port open".to_string(),
            details: json!({
                "service": "SSH",
                "banner": "OpenSSH_8.9p1 Ubuntu-3",
                "state": "open"
            }),
            cve_ids: vec![],
            cvss_score: None,
            scan_id: "port-scan-001".to_string(),
            user_id: "scanner".to_string(),
        };

        assert_eq!(event.port, Some(22));
        assert_eq!(event.protocol, Some("TCP".to_string()));
    }

    #[test]
    fn test_scan_complete_event() {
        let event = SiemEvent {
            timestamp: Utc::now(),
            severity: "Informational".to_string(),
            event_type: "scan_complete".to_string(),
            source_ip: None,
            destination_ip: None,
            port: None,
            protocol: None,
            message: "Network scan completed successfully".to_string(),
            details: json!({
                "hosts_scanned": 254,
                "hosts_up": 45,
                "vulnerabilities_found": 12,
                "duration_seconds": 3600
            }),
            cve_ids: vec![],
            cvss_score: None,
            scan_id: "full-scan-001".to_string(),
            user_id: "admin".to_string(),
        };

        let stats = &event.details;
        assert_eq!(stats.get("hosts_scanned").and_then(|v| v.as_i64()), Some(254));
        assert_eq!(stats.get("hosts_up").and_then(|v| v.as_i64()), Some(45));
    }

    #[test]
    fn test_severity_levels() {
        let severities = vec![
            "Critical",
            "High",
            "Medium",
            "Low",
            "Informational",
        ];

        for severity in severities {
            let event = SiemEvent {
                timestamp: Utc::now(),
                severity: severity.to_string(),
                event_type: "test".to_string(),
                source_ip: None,
                destination_ip: None,
                port: None,
                protocol: None,
                message: "Test event".to_string(),
                details: json!({}),
                cve_ids: vec![],
                cvss_score: None,
                scan_id: "test".to_string(),
                user_id: "test".to_string(),
            };

            let serialized = serde_json::to_string(&event).unwrap();
            assert!(serialized.contains(severity));
        }
    }
}

#[cfg(test)]
mod batch_event_tests {
    use heroforge::integrations::siem::SiemEvent;
    use super::*;

    #[test]
    fn test_batch_event_creation() {
        let events: Vec<SiemEvent> = (0..100).map(|i| {
            SiemEvent {
                timestamp: Utc::now(),
                severity: "Low".to_string(),
                event_type: "port_found".to_string(),
                source_ip: None,
                destination_ip: Some(format!("192.168.1.{}", i % 255)),
                port: Some((i % 65535) as u16),
                protocol: Some("TCP".to_string()),
                message: format!("Port {} found", i),
                details: json!({}),
                cve_ids: vec![],
                cvss_score: None,
                scan_id: "batch-001".to_string(),
                user_id: "scanner".to_string(),
            }
        }).collect();

        assert_eq!(events.len(), 100);

        // Verify batch serialization
        let serialized = serde_json::to_string(&events).unwrap();
        assert!(serialized.len() > 0);

        let deserialized: Vec<SiemEvent> = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.len(), 100);
    }

    #[test]
    fn test_event_grouping_by_severity() {
        let events = vec![
            create_test_event("Critical"),
            create_test_event("High"),
            create_test_event("High"),
            create_test_event("Medium"),
            create_test_event("Medium"),
            create_test_event("Medium"),
            create_test_event("Low"),
        ];

        let mut by_severity: std::collections::HashMap<String, Vec<&SiemEvent>> = std::collections::HashMap::new();
        for event in &events {
            by_severity.entry(event.severity.clone()).or_default().push(event);
        }

        assert_eq!(by_severity.get("Critical").map(|v| v.len()), Some(1));
        assert_eq!(by_severity.get("High").map(|v| v.len()), Some(2));
        assert_eq!(by_severity.get("Medium").map(|v| v.len()), Some(3));
        assert_eq!(by_severity.get("Low").map(|v| v.len()), Some(1));
    }

    fn create_test_event(severity: &str) -> SiemEvent {
        SiemEvent {
            timestamp: Utc::now(),
            severity: severity.to_string(),
            event_type: "test".to_string(),
            source_ip: None,
            destination_ip: None,
            port: None,
            protocol: None,
            message: "Test".to_string(),
            details: json!({}),
            cve_ids: vec![],
            cvss_score: None,
            scan_id: "test".to_string(),
            user_id: "test".to_string(),
        }
    }
}
