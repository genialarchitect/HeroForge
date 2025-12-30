//! Test fixtures for common test data

use crate::types::*;
use chrono::Utc;

/// Create a sample HostInfo for testing
pub fn sample_host_info() -> HostInfo {
    HostInfo {
        target: ScanTarget {
            ip: "192.168.1.100".parse().unwrap(),
            hostname: Some("testhost.local".to_string()),
        },
        is_alive: true,
        os_guess: Some(OsInfo {
            os_family: "Linux".to_string(),
            os_version: Some("5.10".to_string()),
            confidence: 85,
        }),
        ports: vec![
            sample_port_info(80, "http"),
            sample_port_info(443, "https"),
            sample_port_info(22, "ssh"),
        ],
        vulnerabilities: vec![],
        scan_duration: std::time::Duration::from_secs(10),
    }
}

/// Create a sample PortInfo for testing
pub fn sample_port_info(port: u16, service_name: &str) -> PortInfo {
    PortInfo {
        port,
        protocol: Protocol::TCP,
        state: PortState::Open,
        service: Some(ServiceInfo {
            name: service_name.to_string(),
            version: Some("1.0.0".to_string()),
            banner: None,
            cpe: None,
            enumeration: None,
            ssl_info: None,
        }),
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
        cve_id: Some("CVE-2024-12345".to_string()),
        title: "Test Vulnerability".to_string(),
        severity: Severity::Medium,
        description: "This is a test vulnerability".to_string(),
        affected_service: Some("test-service".to_string()),
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
        organization_id: None,
    }
}
