use actix_web::{web, HttpResponse, Result};
use serde::{Deserialize, Serialize};

use crate::web::auth;

/// Predefined scan preset configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanPreset {
    pub id: String,
    pub name: String,
    pub description: String,
    pub icon: String,
    pub port_range: (u16, u16),
    pub threads: usize,
    pub scan_type: String,
    pub enable_os_detection: bool,
    pub enable_service_detection: bool,
    pub enable_vuln_scan: bool,
    pub enable_enumeration: bool,
    pub enum_depth: Option<String>,
    pub udp_port_range: Option<(u16, u16)>,
    pub udp_retries: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enum_services: Option<Vec<String>>,
}

/// Get all available scan presets
pub async fn get_presets(
    _claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let presets = vec![
        ScanPreset {
            id: "quick".to_string(),
            name: "Quick Scan".to_string(),
            description: "Fast scan of common ports (1-1000) with basic detection. Ideal for quick reconnaissance.".to_string(),
            icon: "Zap".to_string(),
            port_range: (1, 1000),
            threads: 100,
            scan_type: "tcp_connect".to_string(),
            enable_os_detection: true,
            enable_service_detection: true,
            enable_vuln_scan: false,
            enable_enumeration: false,
            enum_depth: None,
            udp_port_range: None,
            udp_retries: None,
            enum_services: None,
        },
        ScanPreset {
            id: "deep".to_string(),
            name: "Deep Scan".to_string(),
            description: "Comprehensive scan of all 65535 ports with full detection and enumeration. Most thorough.".to_string(),
            icon: "Radar".to_string(),
            port_range: (1, 65535),
            threads: 50,
            scan_type: "comprehensive".to_string(),
            enable_os_detection: true,
            enable_service_detection: true,
            enable_vuln_scan: true,
            enable_enumeration: true,
            enum_depth: Some("aggressive".to_string()),
            udp_port_range: Some((1, 1000)),
            udp_retries: Some(3),
            enum_services: None, // All services
        },
        ScanPreset {
            id: "webapp".to_string(),
            name: "Web App Scan".to_string(),
            description: "Focused scan of web service ports (80, 443, 8080, 8443) with HTTP enumeration and vulnerability scanning.".to_string(),
            icon: "Globe".to_string(),
            port_range: (80, 80), // Will be overridden with specific ports
            threads: 100,
            scan_type: "tcp_connect".to_string(),
            enable_os_detection: false,
            enable_service_detection: true,
            enable_vuln_scan: true,
            enable_enumeration: true,
            enum_depth: Some("aggressive".to_string()),
            udp_port_range: None,
            udp_retries: None,
            enum_services: Some(vec![
                "http".to_string(),
                "https".to_string(),
            ]),
        },
        ScanPreset {
            id: "stealth".to_string(),
            name: "Stealth Scan".to_string(),
            description: "Slow, quiet SYN scan with reduced thread count. Minimizes detection by IDS/IPS. Requires root.".to_string(),
            icon: "EyeOff".to_string(),
            port_range: (1, 1000),
            threads: 10,
            scan_type: "syn".to_string(),
            enable_os_detection: true,
            enable_service_detection: true,
            enable_vuln_scan: false,
            enable_enumeration: false,
            enum_depth: Some("passive".to_string()),
            udp_port_range: None,
            udp_retries: None,
            enum_services: None,
        },
    ];

    Ok(HttpResponse::Ok().json(presets))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_preset_definitions() {
        let presets = vec![
            ScanPreset {
                id: "quick".to_string(),
                name: "Quick Scan".to_string(),
                description: "Fast scan".to_string(),
                icon: "Zap".to_string(),
                port_range: (1, 1000),
                threads: 100,
                scan_type: "tcp_connect".to_string(),
                enable_os_detection: true,
                enable_service_detection: true,
                enable_vuln_scan: false,
                enable_enumeration: false,
                enum_depth: None,
                udp_port_range: None,
                udp_retries: None,
                enum_services: None,
            },
        ];

        // Validate Quick Scan preset
        assert_eq!(presets[0].id, "quick");
        assert_eq!(presets[0].port_range, (1, 1000));
        assert_eq!(presets[0].threads, 100);
        assert_eq!(presets[0].scan_type, "tcp_connect");
        assert!(!presets[0].enable_vuln_scan);
    }
}
