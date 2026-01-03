//! IoT Device Discovery
//!
//! Discovers IoT devices using various protocols:
//! - mDNS/DNS-SD (Bonjour)
//! - SSDP/UPnP
//! - MQTT broker probing
//! - Common port scanning

use crate::iot::types::*;
use anyhow::Result;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::Semaphore;
use tokio::time::timeout;

/// IoT Discovery Engine
pub struct IotDiscoveryEngine {
    /// Timeout for each probe
    timeout: Duration,
    /// Maximum concurrent connections
    max_concurrent: usize,
}

impl IotDiscoveryEngine {
    pub fn new(timeout: Duration, max_concurrent: usize) -> Self {
        Self {
            timeout,
            max_concurrent,
        }
    }

    /// Discover IoT devices using multiple methods
    pub async fn discover(&self, config: &IotScanConfig) -> Result<Vec<DiscoveredIotDevice>> {
        let mut discovered: HashMap<String, DiscoveredIotDevice> = HashMap::new();

        // mDNS discovery
        if config.enable_mdns {
            if let Ok(devices) = self.discover_mdns().await {
                for device in devices {
                    let key = device.ip_address.clone().unwrap_or_default();
                    discovered.entry(key).or_insert(device);
                }
            }
        }

        // SSDP/UPnP discovery
        if config.enable_ssdp {
            if let Ok(devices) = self.discover_ssdp().await {
                for device in devices {
                    let key = device.ip_address.clone().unwrap_or_default();
                    if let Some(existing) = discovered.get_mut(&key) {
                        // Merge information
                        existing.merge(&device);
                    } else {
                        discovered.insert(key, device);
                    }
                }
            }
        }

        // MQTT broker discovery (on specified targets)
        if config.enable_mqtt {
            if let Some(range) = &config.target_range {
                if let Ok(targets) = parse_target_range(range) {
                    let devices = self.probe_mqtt(&targets).await?;
                    for device in devices {
                        let key = device.ip_address.clone().unwrap_or_default();
                        if let Some(existing) = discovered.get_mut(&key) {
                            existing.merge(&device);
                        } else {
                            discovered.insert(key, device);
                        }
                    }
                }
            }
        }

        Ok(discovered.into_values().collect())
    }

    /// Discover devices via mDNS/DNS-SD
    async fn discover_mdns(&self) -> Result<Vec<DiscoveredIotDevice>> {
        let mut devices = Vec::new();

        // Common mDNS service types to query
        let service_types = vec![
            ("_http._tcp.local", IotDeviceType::Unknown),
            ("_https._tcp.local", IotDeviceType::Unknown),
            ("_hap._tcp.local", IotDeviceType::Hub), // HomeKit
            ("_homekit._tcp.local", IotDeviceType::Hub),
            ("_airplay._tcp.local", IotDeviceType::Tv),
            ("_raop._tcp.local", IotDeviceType::Speaker), // AirPlay audio
            ("_googlecast._tcp.local", IotDeviceType::Tv),
            ("_ipp._tcp.local", IotDeviceType::Unknown), // Printers
            ("_mqtt._tcp.local", IotDeviceType::Hub),
            ("_coap._udp.local", IotDeviceType::Sensor),
            ("_rtsp._tcp.local", IotDeviceType::Camera),
            ("_nvr._tcp.local", IotDeviceType::Dvr),
            ("_axis-video._tcp.local", IotDeviceType::Camera),
            ("_daap._tcp.local", IotDeviceType::Speaker), // iTunes
        ];

        // Bind to mDNS port
        let socket = match UdpSocket::bind("0.0.0.0:0").await {
            Ok(s) => s,
            Err(_) => return Ok(devices),
        };

        let _ = socket.set_broadcast(true);

        // mDNS multicast address
        let mdns_addr: SocketAddr = "224.0.0.251:5353".parse().unwrap();

        for (service_type, device_type) in &service_types {
            // Build DNS query for PTR record
            let query = build_mdns_query(service_type);

            if let Err(_) = socket.send_to(&query, mdns_addr).await {
                continue;
            }

            // Collect responses with timeout
            let mut buffer = vec![0u8; 4096];
            if let Ok(Ok((n, from))) = timeout(self.timeout, socket.recv_from(&mut buffer)).await {
                buffer.truncate(n);

                if let Some(device) = parse_mdns_response(&buffer, from, device_type.clone()) {
                    devices.push(device);
                }
            }
        }

        Ok(devices)
    }

    /// Discover devices via SSDP/UPnP
    async fn discover_ssdp(&self) -> Result<Vec<DiscoveredIotDevice>> {
        let mut devices = Vec::new();

        let socket = match UdpSocket::bind("0.0.0.0:0").await {
            Ok(s) => s,
            Err(_) => return Ok(devices),
        };

        let _ = socket.set_broadcast(true);

        // SSDP multicast address
        let ssdp_addr: SocketAddr = "239.255.255.250:1900".parse().unwrap();

        // SSDP M-SEARCH request
        let search_request = b"M-SEARCH * HTTP/1.1\r\n\
            HOST: 239.255.255.250:1900\r\n\
            MAN: \"ssdp:discover\"\r\n\
            MX: 3\r\n\
            ST: ssdp:all\r\n\r\n";

        if let Err(_) = socket.send_to(search_request, ssdp_addr).await {
            return Ok(devices);
        }

        // Collect responses
        let mut buffer = vec![0u8; 4096];
        let start = std::time::Instant::now();

        while start.elapsed() < self.timeout {
            match timeout(Duration::from_secs(1), socket.recv_from(&mut buffer)).await {
                Ok(Ok((n, from))) => {
                    let response = String::from_utf8_lossy(&buffer[..n]);
                    if let Some(device) = parse_ssdp_response(&response, from) {
                        devices.push(device);
                    }
                }
                _ => break,
            }
        }

        Ok(devices)
    }

    /// Probe for MQTT brokers
    async fn probe_mqtt(&self, targets: &[IpAddr]) -> Result<Vec<DiscoveredIotDevice>> {
        let mut devices = Vec::new();
        let semaphore = Arc::new(Semaphore::new(self.max_concurrent));
        let mut handles = Vec::new();

        let mqtt_ports = [1883, 8883]; // Standard and TLS

        for &ip in targets {
            for &port in &mqtt_ports {
                let permit = semaphore.clone().acquire_owned().await?;
                let timeout_dur = self.timeout;

                let handle = tokio::spawn(async move {
                    let addr = SocketAddr::new(ip, port);
                    let result = probe_mqtt_broker(addr, timeout_dur).await;
                    drop(permit);
                    result
                });
                handles.push(handle);
            }
        }

        for handle in handles {
            let device_opt = handle.await?;
            if let Some(device) = device_opt {
                devices.push(device);
            }
        }

        Ok(devices)
    }
}

impl Default for IotDiscoveryEngine {
    fn default() -> Self {
        Self::new(Duration::from_secs(5), 20)
    }
}

/// Discovered IoT device during scanning
#[derive(Debug, Clone)]
pub struct DiscoveredIotDevice {
    pub ip_address: Option<String>,
    pub mac_address: Option<String>,
    pub hostname: Option<String>,
    pub device_type: IotDeviceType,
    pub vendor: Option<String>,
    pub model: Option<String>,
    pub protocols: Vec<IotProtocolType>,
    pub open_ports: Vec<u16>,
    pub discovery_method: String,
}

impl DiscoveredIotDevice {
    /// Merge information from another discovery
    pub fn merge(&mut self, other: &DiscoveredIotDevice) {
        if self.hostname.is_none() && other.hostname.is_some() {
            self.hostname = other.hostname.clone();
        }
        if self.vendor.is_none() && other.vendor.is_some() {
            self.vendor = other.vendor.clone();
        }
        if self.model.is_none() && other.model.is_some() {
            self.model = other.model.clone();
        }
        if self.device_type == IotDeviceType::Unknown && other.device_type != IotDeviceType::Unknown {
            self.device_type = other.device_type.clone();
        }

        // Merge protocols
        for proto in &other.protocols {
            if !self.protocols.contains(proto) {
                self.protocols.push(proto.clone());
            }
        }

        // Merge ports
        for port in &other.open_ports {
            if !self.open_ports.contains(port) {
                self.open_ports.push(*port);
            }
        }
    }
}

/// Build a simple mDNS PTR query
fn build_mdns_query(service_type: &str) -> Vec<u8> {
    let mut query = Vec::new();

    // Transaction ID
    query.extend_from_slice(&[0x00, 0x00]);
    // Flags: Standard query
    query.extend_from_slice(&[0x00, 0x00]);
    // Questions: 1
    query.extend_from_slice(&[0x00, 0x01]);
    // Answer RRs: 0
    query.extend_from_slice(&[0x00, 0x00]);
    // Authority RRs: 0
    query.extend_from_slice(&[0x00, 0x00]);
    // Additional RRs: 0
    query.extend_from_slice(&[0x00, 0x00]);

    // Question: service type
    for label in service_type.split('.') {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0x00); // End of name

    // Type: PTR (12)
    query.extend_from_slice(&[0x00, 0x0C]);
    // Class: IN (1)
    query.extend_from_slice(&[0x00, 0x01]);

    query
}

/// Parse mDNS response
fn parse_mdns_response(response: &[u8], from: SocketAddr, device_type: IotDeviceType) -> Option<DiscoveredIotDevice> {
    if response.len() < 12 {
        return None;
    }

    // Basic check: is this a response?
    let flags = ((response[2] as u16) << 8) | (response[3] as u16);
    if flags & 0x8000 == 0 {
        return None; // Not a response
    }

    Some(DiscoveredIotDevice {
        ip_address: Some(from.ip().to_string()),
        mac_address: None,
        hostname: extract_hostname_from_mdns(response),
        device_type,
        vendor: None,
        model: None,
        protocols: vec![IotProtocolType::Mdns],
        open_ports: Vec::new(),
        discovery_method: "mDNS".to_string(),
    })
}

/// Extract hostname from mDNS response (simplified)
fn extract_hostname_from_mdns(response: &[u8]) -> Option<String> {
    // Very simplified - just try to find readable strings
    let mut i = 12; // Skip header
    let mut name_parts = Vec::new();

    while i < response.len() {
        let len = response[i] as usize;
        if len == 0 || len > 63 || i + len + 1 > response.len() {
            break;
        }
        if let Ok(part) = String::from_utf8(response[i + 1..i + 1 + len].to_vec()) {
            if part.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
                name_parts.push(part);
            }
        }
        i += len + 1;
    }

    if !name_parts.is_empty() {
        Some(name_parts.join("."))
    } else {
        None
    }
}

/// Parse SSDP response
fn parse_ssdp_response(response: &str, from: SocketAddr) -> Option<DiscoveredIotDevice> {
    if !response.starts_with("HTTP/1.1 200") && !response.starts_with("NOTIFY") {
        return None;
    }

    let mut device = DiscoveredIotDevice {
        ip_address: Some(from.ip().to_string()),
        mac_address: None,
        hostname: None,
        device_type: IotDeviceType::Unknown,
        vendor: None,
        model: None,
        protocols: vec![IotProtocolType::Upnp],
        open_ports: Vec::new(),
        discovery_method: "SSDP".to_string(),
    };

    // Parse headers
    for line in response.lines() {
        let line_lower = line.to_lowercase();
        if line_lower.starts_with("server:") {
            let server = line[7..].trim();
            // Try to extract vendor/model from server string
            if server.contains("Roku") {
                device.device_type = IotDeviceType::Tv;
                device.vendor = Some("Roku".to_string());
            } else if server.contains("Philips") {
                device.vendor = Some("Philips".to_string());
                if server.contains("Hue") {
                    device.device_type = IotDeviceType::Light;
                }
            } else if server.contains("Sonos") {
                device.device_type = IotDeviceType::Speaker;
                device.vendor = Some("Sonos".to_string());
            } else if server.contains("Samsung") {
                device.vendor = Some("Samsung".to_string());
            } else if server.contains("Google") {
                device.vendor = Some("Google".to_string());
            }
        }

        if line_lower.starts_with("st:") || line_lower.starts_with("nt:") {
            let st = line[3..].trim();
            if st.contains("MediaRenderer") {
                device.device_type = IotDeviceType::Tv;
            } else if st.contains("Basic") {
                device.device_type = IotDeviceType::Hub;
            }
        }
    }

    Some(device)
}

/// Probe for MQTT broker
async fn probe_mqtt_broker(addr: SocketAddr, timeout_dur: Duration) -> Option<DiscoveredIotDevice> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    let mut stream = match timeout(timeout_dur, TcpStream::connect(addr)).await {
        Ok(Ok(s)) => s,
        _ => return None,
    };

    // Send MQTT CONNECT packet (simplified)
    let connect_packet = vec![
        0x10, // CONNECT packet type
        0x12, // Remaining length
        0x00, 0x04, // Protocol name length
        b'M', b'Q', b'T', b'T', // Protocol name
        0x04, // Protocol version (MQTT 3.1.1)
        0x02, // Connect flags (clean session)
        0x00, 0x3C, // Keep alive (60 seconds)
        0x00, 0x06, // Client ID length
        b'p', b'r', b'o', b'b', b'e', b'r', // Client ID
    ];

    if let Err(_) = stream.write_all(&connect_packet).await {
        return None;
    }

    let mut buffer = vec![0u8; 32];
    if let Ok(Ok(n)) = timeout(timeout_dur, stream.read(&mut buffer)).await {
        if n >= 2 && buffer[0] == 0x20 {
            // CONNACK received
            return Some(DiscoveredIotDevice {
                ip_address: Some(addr.ip().to_string()),
                mac_address: None,
                hostname: None,
                device_type: IotDeviceType::Hub,
                vendor: None,
                model: None,
                protocols: vec![IotProtocolType::Mqtt],
                open_ports: vec![addr.port()],
                discovery_method: "MQTT probe".to_string(),
            });
        }
    }

    None
}

/// Parse target range with support for:
/// - Single IPs: "192.168.1.1"
/// - Comma-separated IPs: "192.168.1.1, 192.168.1.2"
/// - CIDR notation: "192.168.1.0/24"
/// - IP ranges: "192.168.1.1-192.168.1.10"
fn parse_target_range(range: &str) -> Result<Vec<IpAddr>> {
    let mut ips = Vec::new();

    for part in range.split(',') {
        let part = part.trim();

        // Try parsing as single IP
        if let Ok(ip) = part.parse::<IpAddr>() {
            ips.push(ip);
            continue;
        }

        // Try parsing as CIDR notation
        if part.contains('/') {
            if let Ok(network) = part.parse::<ipnetwork::IpNetwork>() {
                // Limit to 256 IPs to prevent excessive scanning
                for ip in network.iter().take(256) {
                    ips.push(ip);
                }
                continue;
            }
        }

        // Try parsing as IP range (e.g., "192.168.1.1-192.168.1.10")
        if let Some((start_str, end_str)) = part.split_once('-') {
            if let (Ok(start_ip), Ok(end_ip)) = (
                start_str.trim().parse::<std::net::Ipv4Addr>(),
                end_str.trim().parse::<std::net::Ipv4Addr>(),
            ) {
                let start_u32 = u32::from(start_ip);
                let end_u32 = u32::from(end_ip);

                // Limit range to 256 IPs
                let actual_end = end_u32.min(start_u32 + 255);

                for ip_u32 in start_u32..=actual_end {
                    ips.push(IpAddr::V4(std::net::Ipv4Addr::from(ip_u32)));
                }
                continue;
            }
        }

        // If we get here, the format is not recognized - log a warning
        log::warn!("Unrecognized target format: {}", part);
    }

    Ok(ips)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_target_range() {
        let ips = parse_target_range("192.168.1.1, 192.168.1.2").unwrap();
        assert_eq!(ips.len(), 2);
    }

    #[test]
    fn test_merge_devices() {
        let mut device1 = DiscoveredIotDevice {
            ip_address: Some("192.168.1.1".to_string()),
            mac_address: None,
            hostname: None,
            device_type: IotDeviceType::Unknown,
            vendor: None,
            model: None,
            protocols: vec![IotProtocolType::Upnp],
            open_ports: vec![80],
            discovery_method: "SSDP".to_string(),
        };

        let device2 = DiscoveredIotDevice {
            ip_address: Some("192.168.1.1".to_string()),
            mac_address: None,
            hostname: Some("camera.local".to_string()),
            device_type: IotDeviceType::Camera,
            vendor: Some("Hikvision".to_string()),
            model: None,
            protocols: vec![IotProtocolType::Rtsp],
            open_ports: vec![554],
            discovery_method: "mDNS".to_string(),
        };

        device1.merge(&device2);

        assert_eq!(device1.hostname, Some("camera.local".to_string()));
        assert_eq!(device1.device_type, IotDeviceType::Camera);
        assert_eq!(device1.protocols.len(), 2);
        assert_eq!(device1.open_ports.len(), 2);
    }
}
