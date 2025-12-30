//! Test fixtures for common test data

use crate::types::*;
use chrono::Utc;

/// Create a sample HostInfo for testing
pub fn sample_host_info() -> HostInfo {
    HostInfo {
        ip: "192.168.1.100".to_string(),
        hostname: Some("testhost.local".to_string()),
        ports: vec![
            sample_port_info(80, "http"),
            sample_port_info(443, "https"),
            sample_port_info(22, "ssh"),
        ],
        os: Some("Linux 5.10".to_string()),
        mac_address: Some("00:11:22:33:44:55".to_string()),
        vulnerabilities: vec![],
    }
}

/// Create a sample PortInfo for testing
pub fn sample_port_info(port: u16, service_name: &str) -> PortInfo {
    PortInfo {
        port,
        state: PortState::Open,
        service: Some(service_name.to_string()),
        version: Some("1.0.0".to_string()),
        extra_info: None,
    }
}

/// Create a sample ScanConfig for testing
pub fn sample_scan_config() -> ScanConfig {
    ScanConfig {
        targets: vec!["192.168.1.0/24".to_string()],
        port_range: (1, 1000),
        threads: 100,
        timeout: std::time::Duration::from_secs(3),
        scan_type: ScanType::TCPConnect,
        enable_os_detection: false,
        enable_service_detection: true,
        enable_vuln_scan: false,
        enable_enumeration: false,
        enum_depth: crate::scanner::enumeration::types::EnumDepth::Light,
        enum_wordlist_path: None,
        enum_services: Vec::new(),
        output_format: OutputFormat::Json,
        udp_port_range: None,
        udp_retries: 2,
        skip_host_discovery: false,
        service_detection_timeout: None,
        dns_timeout: None,
        syn_timeout: None,
        udp_timeout: None,
        vpn_config_id: None,
        exclusions: Vec::new(),
    }
}

/// Create sample vulnerability data
pub fn sample_vulnerability() -> Vulnerability {
    Vulnerability {
        id: uuid::Uuid::new_v4().to_string(),
        title: "Test Vulnerability".to_string(),
        description: "This is a test vulnerability".to_string(),
        severity: Severity::Medium,
        cvss_score: Some(5.5),
        cve_id: Some("CVE-2024-12345".to_string()),
        affected_component: "test-service".to_string(),
        remediation: Some("Update to latest version".to_string()),
        references: vec!["https://example.com/advisory".to_string()],
    }
}

/// Create sample scan result
pub fn sample_scan_result() -> crate::db::models::ScanResult {
    crate::db::models::ScanResult {
        id: uuid::Uuid::new_v4().to_string(),
        user_id: uuid::Uuid::new_v4().to_string(),
        name: "Test Scan".to_string(),
        targets: "192.168.1.0/24".to_string(),
        status: "completed".to_string(),
        results: Some("[]".to_string()),
        created_at: Utc::now(),
        started_at: Some(Utc::now()),
        completed_at: Some(Utc::now()),
        error_message: None,
        customer_id: None,
        engagement_id: None,
    }
}
