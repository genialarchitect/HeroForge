//! IoT Device Profiling
//!
//! Provides device profiling capabilities:
//! - Behavioral baseline creation from traffic analysis
//! - Firmware fingerprinting
//! - Manufacturer identification from MAC OUI
//! - Communication pattern analysis

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IoTDeviceProfile {
    pub device_id: String,
    pub manufacturer: Option<String>,
    pub model: Option<String>,
    pub firmware_version: Option<String>,
    pub behavior_baseline: BehaviorBaseline,
    pub communication_patterns: Vec<CommunicationPattern>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorBaseline {
    pub normal_traffic_volume: f64,
    pub normal_destinations: Vec<String>,
    pub normal_protocols: Vec<String>,
    pub active_hours: Vec<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommunicationPattern {
    pub protocol: String,
    pub destination: String,
    pub frequency: f64,
    pub data_volume: f64,
}

/// MAC OUI (Organizationally Unique Identifier) database for manufacturer lookup
/// Format: First 6 hex chars of MAC -> Manufacturer name
static OUI_DATABASE: once_cell::sync::Lazy<HashMap<&'static str, &'static str>> =
    once_cell::sync::Lazy::new(|| {
        let mut oui = HashMap::new();
        // Smart Home / IoT Manufacturers
        oui.insert("ACCC8E", "Roku");
        oui.insert("B4E62D", "TP-Link");
        oui.insert("B09FBA", "TP-Link");
        oui.insert("50C7BF", "TP-Link");
        oui.insert("DCA632", "Raspberry Pi Foundation");
        oui.insert("B827EB", "Raspberry Pi Foundation");
        oui.insert("DC2632", "Raspberry Pi Foundation");
        oui.insert("E45F01", "Raspberry Pi Foundation");
        oui.insert("68C63A", "Espressif");
        oui.insert("CC50E3", "Espressif");
        oui.insert("240AC4", "Espressif");
        oui.insert("A4CF12", "Espressif");
        oui.insert("F412FA", "Amazon");
        oui.insert("4CEFC0", "Amazon");
        oui.insert("FCC2DE", "Amazon");
        oui.insert("D073D5", "Wyze Labs");
        oui.insert("2CF432", "Wyze Labs");
        oui.insert("001D63", "Philips");
        oui.insert("0017EB", "Philips");
        oui.insert("ECB5FA", "Philips");
        oui.insert("0026BB", "Apple");
        oui.insert("F0D1A9", "Apple");
        oui.insert("5CF7E6", "Apple");
        oui.insert("3C067C", "Apple");
        oui.insert("7C2F80", "Gigaset");
        oui.insert("94103E", "Belkin");
        oui.insert("C0C9E3", "Samsung");
        oui.insert("98B8E3", "Samsung");
        oui.insert("CC40D0", "Samsung");
        oui.insert("54BD79", "Samsung");
        oui.insert("001E8C", "Samsung");
        oui.insert("001599", "Samsung");
        oui.insert("B417A8", "LG Electronics");
        oui.insert("E8F2E2", "LG Electronics");
        oui.insert("001C62", "LG Electronics");
        oui.insert("5C5027", "Google");
        oui.insert("F88FCA", "Google");
        oui.insert("7C2EBD", "Google");
        oui.insert("A47733", "Google");
        oui.insert("20DF64", "Google");
        oui.insert("94EB2C", "Google");
        oui.insert("442C05", "Sonos");
        oui.insert("5CDAD4", "Sonos");
        oui.insert("78289E", "Sonos");
        oui.insert("B8E937", "Sonos");
        oui.insert("0004A3", "Ring");
        oui.insert("D4E8B2", "Ring");
        oui.insert("001EEB", "Ring");
        oui.insert("0004F3", "Nest Labs");
        oui.insert("18B430", "Nest Labs");
        oui.insert("64166D", "Nest Labs");
        // Camera manufacturers
        oui.insert("A4E992", "Hikvision");
        oui.insert("C0562D", "Hikvision");
        oui.insert("4CFC61", "Hikvision");
        oui.insert("BC3400", "Hikvision");
        oui.insert("54C4AE", "Hikvision");
        oui.insert("E00AF6", "Dahua");
        oui.insert("3C3F1C", "Dahua");
        oui.insert("D47C44", "Dahua");
        oui.insert("B0A7B9", "Axis Communications");
        oui.insert("00408C", "Axis Communications");
        oui.insert("ACCC8E", "Axis Communications");
        oui.insert("00C002", "Foscam");
        oui.insert("C46AB7", "Foscam");
        oui.insert("C02250", "Amcrest");
        // Network equipment
        oui.insert("0018E7", "Ubiquiti");
        oui.insert("788A20", "Ubiquiti");
        oui.insert("FC15B4", "Ubiquiti");
        oui.insert("F09FC2", "Ubiquiti");
        oui.insert("DC9FDB", "Ubiquiti");
        oui.insert("24A43C", "Ubiquiti");
        oui.insert("C4AD34", "Routerboard/MikroTik");
        oui.insert("B8A38A", "Routerboard/MikroTik");
        oui.insert("4C5E0C", "Routerboard/MikroTik");
        oui.insert("001A79", "D-Link");
        oui.insert("00179A", "D-Link");
        oui.insert("14D64D", "D-Link");
        oui.insert("288088", "D-Link");
        oui.insert("28107B", "Netgear");
        oui.insert("A042E0", "Netgear");
        oui.insert("C03F0E", "Netgear");
        oui.insert("000C41", "Cisco/Linksys");
        oui.insert("001217", "Cisco/Linksys");
        oui.insert("58D3FA", "Asus");
        oui.insert("AC9E17", "Asus");
        oui.insert("B06EBF", "Asus");
        oui
    });

/// Common IoT protocols by port
static IOT_PROTOCOLS_BY_PORT: once_cell::sync::Lazy<HashMap<u16, &'static str>> =
    once_cell::sync::Lazy::new(|| {
        let mut ports = HashMap::new();
        ports.insert(80, "HTTP");
        ports.insert(443, "HTTPS");
        ports.insert(1883, "MQTT");
        ports.insert(8883, "MQTT-TLS");
        ports.insert(5683, "CoAP");
        ports.insert(5684, "CoAP-DTLS");
        ports.insert(554, "RTSP");
        ports.insert(8554, "RTSP");
        ports.insert(5353, "mDNS");
        ports.insert(1900, "SSDP");
        ports.insert(8080, "HTTP-Alt");
        ports.insert(8443, "HTTPS-Alt");
        ports.insert(22, "SSH");
        ports.insert(23, "Telnet");
        ports.insert(21, "FTP");
        ports.insert(502, "Modbus");
        ports
    });

/// Known firmware signatures for identification
static FIRMWARE_SIGNATURES: once_cell::sync::Lazy<Vec<FirmwareSignature>> =
    once_cell::sync::Lazy::new(|| {
        vec![
            FirmwareSignature {
                pattern: "Server: Camera",
                vendor: "Generic IP Camera",
                model_pattern: None,
            },
            FirmwareSignature {
                pattern: "Server: Hikvision",
                vendor: "Hikvision",
                model_pattern: Some("DS-"),
            },
            FirmwareSignature {
                pattern: "Server: Dahua",
                vendor: "Dahua",
                model_pattern: Some("IPC-"),
            },
            FirmwareSignature {
                pattern: "Server: RTSP",
                vendor: "Generic RTSP Camera",
                model_pattern: None,
            },
            FirmwareSignature {
                pattern: "X-Powered-By: ESPhttpd",
                vendor: "ESP8266/ESP32",
                model_pattern: None,
            },
            FirmwareSignature {
                pattern: "Server: ESP",
                vendor: "ESP8266/ESP32",
                model_pattern: None,
            },
            FirmwareSignature {
                pattern: "Server: Tasmota",
                vendor: "Tasmota Firmware",
                model_pattern: None,
            },
            FirmwareSignature {
                pattern: "Server: MikroTik",
                vendor: "MikroTik",
                model_pattern: Some("RouterOS"),
            },
            FirmwareSignature {
                pattern: "Server: Ubiquiti",
                vendor: "Ubiquiti",
                model_pattern: None,
            },
            FirmwareSignature {
                pattern: "X-Philips-Hue",
                vendor: "Philips Hue",
                model_pattern: Some("Bridge"),
            },
            FirmwareSignature {
                pattern: "Server: homebridge",
                vendor: "Homebridge",
                model_pattern: None,
            },
            FirmwareSignature {
                pattern: "Server: Roku",
                vendor: "Roku",
                model_pattern: None,
            },
            FirmwareSignature {
                pattern: "WEMo",
                vendor: "Belkin WeMo",
                model_pattern: None,
            },
            FirmwareSignature {
                pattern: "SSDP/Sonos",
                vendor: "Sonos",
                model_pattern: None,
            },
        ]
    });

struct FirmwareSignature {
    pattern: &'static str,
    vendor: &'static str,
    model_pattern: Option<&'static str>,
}

/// Create a comprehensive device profile based on available information
pub async fn create_device_profile(device_id: &str) -> Result<IoTDeviceProfile> {
    log::info!("Creating device profile for: {}", device_id);

    // Parse device_id to extract IP if present
    let ip = device_id.split(':').next().unwrap_or(device_id);

    // Try to identify manufacturer from MAC if device_id looks like a MAC
    let manufacturer = if device_id.contains(':') && device_id.len() == 17 {
        identify_manufacturer(device_id).await.ok().flatten()
    } else {
        None
    };

    // Try to fingerprint via HTTP if it looks like an IP
    let (model, firmware_version) = if ip.parse::<std::net::IpAddr>().is_ok() {
        let fw = fingerprint_firmware(ip).await.ok().flatten();
        let model = fw.as_ref().and_then(|v| {
            if v.contains('/') {
                Some(v.split('/').next().unwrap_or("").to_string())
            } else {
                None
            }
        });
        (model, fw)
    } else {
        (None, None)
    };

    // Build baseline profile based on device type inference
    let behavior_baseline = infer_behavior_baseline(manufacturer.as_deref(), model.as_deref());

    // Build communication patterns
    let communication_patterns = infer_communication_patterns(manufacturer.as_deref());

    Ok(IoTDeviceProfile {
        device_id: device_id.to_string(),
        manufacturer,
        model,
        firmware_version,
        behavior_baseline,
        communication_patterns,
    })
}

/// Infer behavior baseline based on device type
fn infer_behavior_baseline(manufacturer: Option<&str>, model: Option<&str>) -> BehaviorBaseline {
    let mut baseline = BehaviorBaseline {
        normal_traffic_volume: 1000.0, // 1KB/day default
        normal_destinations: Vec::new(),
        normal_protocols: vec!["HTTP".to_string()],
        active_hours: (0..24).collect(), // Active all day by default
    };

    match manufacturer {
        Some("Hikvision") | Some("Dahua") | Some("Axis Communications") => {
            // Cameras typically have higher bandwidth and specific cloud destinations
            baseline.normal_traffic_volume = 500_000_000.0; // 500MB/day for HD streaming
            baseline.normal_protocols = vec![
                "HTTP".to_string(),
                "RTSP".to_string(),
                "HTTPS".to_string(),
            ];
            baseline.normal_destinations = vec![
                "cloud.hikvision.com".to_string(),
                "dahua-cloud.com".to_string(),
            ];
        }
        Some("Amazon") | Some("Ring") => {
            baseline.normal_traffic_volume = 50_000_000.0; // 50MB/day
            baseline.normal_protocols = vec![
                "HTTPS".to_string(),
                "MQTT-TLS".to_string(),
            ];
            baseline.normal_destinations = vec![
                "*.amazon.com".to_string(),
                "*.ring.com".to_string(),
            ];
        }
        Some("Google") | Some("Nest Labs") => {
            baseline.normal_traffic_volume = 20_000_000.0; // 20MB/day
            baseline.normal_protocols = vec![
                "HTTPS".to_string(),
                "mDNS".to_string(),
            ];
            baseline.normal_destinations = vec![
                "*.google.com".to_string(),
                "*.nest.com".to_string(),
            ];
        }
        Some("Philips") => {
            // Philips Hue uses local communication primarily
            baseline.normal_traffic_volume = 1_000_000.0; // 1MB/day
            baseline.normal_protocols = vec![
                "HTTP".to_string(),
                "mDNS".to_string(),
            ];
            baseline.normal_destinations = vec!["local".to_string()];
        }
        Some("Sonos") => {
            baseline.normal_traffic_volume = 100_000_000.0; // 100MB/day for music streaming
            baseline.normal_protocols = vec![
                "HTTP".to_string(),
                "SSDP".to_string(),
            ];
            baseline.normal_destinations = vec![
                "*.sonos.com".to_string(),
                "*.spotify.com".to_string(),
            ];
        }
        Some("ESP8266/ESP32") | Some("Espressif") => {
            // Low-power sensors typically have minimal traffic
            baseline.normal_traffic_volume = 100_000.0; // 100KB/day
            baseline.normal_protocols = vec![
                "MQTT".to_string(),
                "HTTP".to_string(),
            ];
        }
        Some("Roku") => {
            baseline.normal_traffic_volume = 1_000_000_000.0; // 1GB/day for streaming
            baseline.normal_protocols = vec![
                "HTTP".to_string(),
                "HTTPS".to_string(),
            ];
            baseline.normal_destinations = vec!["*.roku.com".to_string()];
        }
        _ => {}
    }

    baseline
}

/// Infer communication patterns based on manufacturer
fn infer_communication_patterns(manufacturer: Option<&str>) -> Vec<CommunicationPattern> {
    let mut patterns = Vec::new();

    match manufacturer {
        Some("Hikvision") | Some("Dahua") => {
            patterns.push(CommunicationPattern {
                protocol: "RTSP".to_string(),
                destination: "local_nvr".to_string(),
                frequency: 1.0, // Continuous
                data_volume: 100_000_000.0, // 100MB/hour
            });
            patterns.push(CommunicationPattern {
                protocol: "HTTP".to_string(),
                destination: "cloud_service".to_string(),
                frequency: 0.0167, // Once per minute
                data_volume: 10_000.0,
            });
        }
        Some("Amazon") | Some("Ring") => {
            patterns.push(CommunicationPattern {
                protocol: "MQTT-TLS".to_string(),
                destination: "iot.amazon.com".to_string(),
                frequency: 0.5, // Every 2 seconds for heartbeat
                data_volume: 500.0,
            });
        }
        Some("Google") | Some("Nest Labs") => {
            patterns.push(CommunicationPattern {
                protocol: "HTTPS".to_string(),
                destination: "google.com".to_string(),
                frequency: 0.1,
                data_volume: 1000.0,
            });
        }
        Some("ESP8266/ESP32") | Some("Espressif") => {
            patterns.push(CommunicationPattern {
                protocol: "MQTT".to_string(),
                destination: "mqtt_broker".to_string(),
                frequency: 0.0167, // Once per minute
                data_volume: 100.0,
            });
        }
        _ => {
            // Default pattern for unknown devices
            patterns.push(CommunicationPattern {
                protocol: "HTTP".to_string(),
                destination: "unknown".to_string(),
                frequency: 0.1,
                data_volume: 1000.0,
            });
        }
    }

    patterns
}

/// Fingerprint device firmware by probing HTTP headers and responses
pub async fn fingerprint_firmware(device_id: &str) -> Result<Option<String>> {
    log::info!("Fingerprinting firmware for device: {}", device_id);

    // Parse IP address
    let ip: std::net::IpAddr = device_id.parse()
        .map_err(|_| anyhow::anyhow!("Invalid IP address: {}", device_id))?;

    let timeout_dur = Duration::from_secs(5);

    // Try common IoT web ports
    let ports = [80, 8080, 443, 8443, 8000];

    for port in ports {
        let addr = SocketAddr::new(ip, port);

        if let Ok(Ok(mut stream)) = timeout(timeout_dur, TcpStream::connect(addr)).await {
            // Send HTTP request
            let request = format!(
                "GET / HTTP/1.1\r\nHost: {}\r\nUser-Agent: HeroForge-IoT-Scanner\r\nConnection: close\r\n\r\n",
                ip
            );

            if stream.write_all(request.as_bytes()).await.is_err() {
                continue;
            }

            let mut response = vec![0u8; 4096];
            if let Ok(Ok(n)) = timeout(timeout_dur, stream.read(&mut response)).await {
                response.truncate(n);
                let response_str = String::from_utf8_lossy(&response);

                // Check against known firmware signatures
                for sig in FIRMWARE_SIGNATURES.iter() {
                    if response_str.contains(sig.pattern) {
                        let version = extract_version_from_response(&response_str);
                        let firmware_info = if let Some(ver) = version {
                            format!("{}/{}", sig.vendor, ver)
                        } else {
                            sig.vendor.to_string()
                        };
                        log::info!("Identified firmware: {}", firmware_info);
                        return Ok(Some(firmware_info));
                    }
                }

                // Try to extract generic server info
                if let Some(server) = extract_header(&response_str, "Server") {
                    log::info!("Found server header: {}", server);
                    return Ok(Some(server));
                }
            }
        }
    }

    // Try RTSP fingerprinting for cameras
    let rtsp_port = 554;
    let addr = SocketAddr::new(ip, rtsp_port);

    if let Ok(Ok(mut stream)) = timeout(timeout_dur, TcpStream::connect(addr)).await {
        let request = format!(
            "OPTIONS rtsp://{}:{} RTSP/1.0\r\nCSeq: 1\r\n\r\n",
            ip, rtsp_port
        );

        if stream.write_all(request.as_bytes()).await.is_ok() {
            let mut response = vec![0u8; 1024];
            if let Ok(Ok(n)) = timeout(timeout_dur, stream.read(&mut response)).await {
                response.truncate(n);
                let response_str = String::from_utf8_lossy(&response);

                if let Some(server) = extract_header(&response_str, "Server") {
                    log::info!("Found RTSP server: {}", server);
                    return Ok(Some(format!("RTSP Camera: {}", server)));
                }
            }
        }
    }

    log::debug!("Could not fingerprint firmware for {}", device_id);
    Ok(None)
}

/// Extract version number from HTTP response
fn extract_version_from_response(response: &str) -> Option<String> {
    // Look for common version patterns
    let version_patterns = [
        r"[Vv]ersion[:\s]+(\d+\.\d+(?:\.\d+)?)",
        r"[Ff]irmware[:\s]+(\d+\.\d+(?:\.\d+)?)",
        r"[Bb]uild[:\s]+(\d+)",
        r"(\d+\.\d+\.\d+\.\d+)", // IP-like version numbers
    ];

    for pattern in &version_patterns {
        if let Ok(re) = regex::Regex::new(pattern) {
            if let Some(caps) = re.captures(response) {
                if let Some(ver) = caps.get(1) {
                    return Some(ver.as_str().to_string());
                }
            }
        }
    }

    None
}

/// Extract HTTP header value
fn extract_header(response: &str, header: &str) -> Option<String> {
    for line in response.lines() {
        if line.to_lowercase().starts_with(&format!("{}:", header.to_lowercase())) {
            return Some(line.split(':').skip(1).collect::<Vec<_>>().join(":").trim().to_string());
        }
    }
    None
}

/// Identify manufacturer from MAC address OUI (first 3 bytes / 6 hex chars)
pub async fn identify_manufacturer(mac_address: &str) -> Result<Option<String>> {
    log::info!("Identifying manufacturer for MAC: {}", mac_address);

    // Normalize MAC address
    let normalized = mac_address
        .to_uppercase()
        .replace([':', '-', '.'], "");

    if normalized.len() < 6 {
        return Err(anyhow::anyhow!("Invalid MAC address format: {}", mac_address));
    }

    // Get the OUI (first 6 characters)
    let oui = &normalized[..6];

    // Look up in database
    if let Some(&manufacturer) = OUI_DATABASE.get(oui) {
        log::info!("Found manufacturer for {}: {}", mac_address, manufacturer);
        return Ok(Some(manufacturer.to_string()));
    }

    // Try partial match (sometimes OUIs are registered with slight variations)
    let oui_3 = &normalized[..3];
    for (key, &value) in OUI_DATABASE.iter() {
        if key.starts_with(oui_3) {
            log::info!("Partial match found for {}: {}", mac_address, value);
            return Ok(Some(value.to_string()));
        }
    }

    log::debug!("No manufacturer found for MAC {}", mac_address);
    Ok(None)
}

/// Get all known manufacturers
pub fn get_known_manufacturers() -> Vec<String> {
    let mut manufacturers: Vec<String> = OUI_DATABASE
        .values()
        .map(|s| s.to_string())
        .collect();
    manufacturers.sort();
    manufacturers.dedup();
    manufacturers
}

/// Get OUI for a manufacturer
pub fn get_ouis_for_manufacturer(manufacturer: &str) -> Vec<String> {
    let manufacturer_lower = manufacturer.to_lowercase();
    OUI_DATABASE
        .iter()
        .filter(|(_, &v)| v.to_lowercase().contains(&manufacturer_lower))
        .map(|(k, _)| k.to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_identify_manufacturer_known() {
        let result = identify_manufacturer("B8:27:EB:12:34:56").await.unwrap();
        assert_eq!(result, Some("Raspberry Pi Foundation".to_string()));
    }

    #[tokio::test]
    async fn test_identify_manufacturer_hikvision() {
        let result = identify_manufacturer("A4-E9-92-AB-CD-EF").await.unwrap();
        assert_eq!(result, Some("Hikvision".to_string()));
    }

    #[tokio::test]
    async fn test_identify_manufacturer_unknown() {
        let result = identify_manufacturer("FF:FF:FF:00:00:00").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_identify_manufacturer_invalid() {
        let result = identify_manufacturer("XY").await;
        assert!(result.is_err());
    }

    #[test]
    fn test_get_known_manufacturers() {
        let manufacturers = get_known_manufacturers();
        assert!(manufacturers.len() > 10);
        assert!(manufacturers.contains(&"Hikvision".to_string()));
        assert!(manufacturers.contains(&"Amazon".to_string()));
    }

    #[test]
    fn test_infer_behavior_baseline_camera() {
        let baseline = infer_behavior_baseline(Some("Hikvision"), None);
        assert!(baseline.normal_traffic_volume > 100_000_000.0);
        assert!(baseline.normal_protocols.contains(&"RTSP".to_string()));
    }

    #[test]
    fn test_infer_behavior_baseline_iot_sensor() {
        let baseline = infer_behavior_baseline(Some("ESP8266/ESP32"), None);
        assert!(baseline.normal_traffic_volume < 1_000_000.0);
        assert!(baseline.normal_protocols.contains(&"MQTT".to_string()));
    }

    #[tokio::test]
    async fn test_create_device_profile_mac() {
        let profile = create_device_profile("B8:27:EB:12:34:56").await.unwrap();
        assert_eq!(profile.device_id, "B8:27:EB:12:34:56");
        assert_eq!(profile.manufacturer, Some("Raspberry Pi Foundation".to_string()));
    }
}
