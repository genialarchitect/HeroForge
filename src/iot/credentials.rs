//! IoT Default Credentials Database
//!
//! Database of default credentials for common IoT devices.

use crate::iot::types::*;
use anyhow::Result;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::time::timeout;

/// Default credential entry
#[derive(Debug, Clone)]
pub struct DefaultCredential {
    pub device_type: String,
    pub vendor: Option<String>,
    pub model: Option<String>,
    pub protocol: String,
    pub username: String,
    pub password: String,
    pub port: u16,
    pub source: String, // "default", "leaked", "common"
}

/// IoT Credential Database
pub struct IotCredentialDatabase {
    credentials: Vec<DefaultCredential>,
    /// Index by device type
    by_type: HashMap<String, Vec<usize>>,
    /// Index by vendor
    by_vendor: HashMap<String, Vec<usize>>,
}

impl IotCredentialDatabase {
    /// Create a new credential database with built-in defaults
    pub fn new() -> Self {
        let mut db = Self {
            credentials: Vec::new(),
            by_type: HashMap::new(),
            by_vendor: HashMap::new(),
        };

        db.seed_defaults();
        db
    }

    /// Seed the database with common default credentials
    fn seed_defaults(&mut self) {
        // IP Cameras - General
        self.add_credentials(vec![
            ("camera", None, None, "http", "admin", "admin", 80, "default"),
            ("camera", None, None, "http", "admin", "", 80, "default"),
            ("camera", None, None, "http", "admin", "12345", 80, "default"),
            ("camera", None, None, "http", "admin", "123456", 80, "default"),
            ("camera", None, None, "http", "admin", "password", 80, "default"),
            ("camera", None, None, "http", "root", "root", 80, "default"),
            ("camera", None, None, "http", "root", "", 80, "default"),
            ("camera", None, None, "http", "user", "user", 80, "default"),
            ("camera", None, None, "telnet", "root", "root", 23, "default"),
            ("camera", None, None, "telnet", "admin", "admin", 23, "default"),
            ("camera", None, None, "ssh", "root", "root", 22, "default"),
        ]);

        // Hikvision Cameras
        self.add_credentials(vec![
            ("camera", Some("Hikvision"), None, "http", "admin", "12345", 80, "default"),
            ("camera", Some("Hikvision"), None, "http", "admin", "admin", 80, "default"),
            ("camera", Some("Hikvision"), None, "rtsp", "admin", "12345", 554, "default"),
        ]);

        // Dahua Cameras
        self.add_credentials(vec![
            ("camera", Some("Dahua"), None, "http", "admin", "admin", 80, "default"),
            ("camera", Some("Dahua"), None, "http", "admin", "", 80, "default"),
            ("camera", Some("Dahua"), None, "rtsp", "admin", "admin", 554, "default"),
        ]);

        // Axis Cameras
        self.add_credentials(vec![
            ("camera", Some("Axis"), None, "http", "root", "pass", 80, "default"),
            ("camera", Some("Axis"), None, "http", "root", "", 80, "default"),
        ]);

        // Foscam Cameras
        self.add_credentials(vec![
            ("camera", Some("Foscam"), None, "http", "admin", "", 80, "default"),
            ("camera", Some("Foscam"), None, "http", "admin", "admin", 80, "default"),
        ]);

        // DVR/NVR Systems
        self.add_credentials(vec![
            ("dvr", None, None, "http", "admin", "admin", 80, "default"),
            ("dvr", None, None, "http", "admin", "12345", 80, "default"),
            ("dvr", None, None, "http", "admin", "4321", 80, "default"),
            ("dvr", None, None, "http", "admin", "", 80, "default"),
            ("dvr", None, None, "telnet", "root", "root", 23, "default"),
            ("dvr", None, None, "telnet", "root", "vizxv", 23, "default"),
            ("dvr", None, None, "telnet", "root", "xc3511", 23, "default"),
        ]);

        // Routers - General
        self.add_credentials(vec![
            ("router", None, None, "http", "admin", "admin", 80, "default"),
            ("router", None, None, "http", "admin", "password", 80, "default"),
            ("router", None, None, "http", "admin", "1234", 80, "default"),
            ("router", None, None, "http", "admin", "", 80, "default"),
            ("router", None, None, "http", "root", "root", 80, "default"),
            ("router", None, None, "http", "user", "user", 80, "default"),
            ("router", None, None, "telnet", "admin", "admin", 23, "default"),
            ("router", None, None, "ssh", "admin", "admin", 22, "default"),
        ]);

        // TP-Link Routers
        self.add_credentials(vec![
            ("router", Some("TP-Link"), None, "http", "admin", "admin", 80, "default"),
        ]);

        // Netgear Routers
        self.add_credentials(vec![
            ("router", Some("Netgear"), None, "http", "admin", "password", 80, "default"),
            ("router", Some("Netgear"), None, "http", "admin", "1234", 80, "default"),
        ]);

        // D-Link Routers
        self.add_credentials(vec![
            ("router", Some("D-Link"), None, "http", "admin", "", 80, "default"),
            ("router", Some("D-Link"), None, "http", "admin", "admin", 80, "default"),
        ]);

        // Linksys Routers
        self.add_credentials(vec![
            ("router", Some("Linksys"), None, "http", "admin", "admin", 80, "default"),
            ("router", Some("Linksys"), None, "http", "", "admin", 80, "default"),
        ]);

        // Ubiquiti
        self.add_credentials(vec![
            ("router", Some("Ubiquiti"), None, "http", "ubnt", "ubnt", 80, "default"),
            ("router", Some("Ubiquiti"), None, "ssh", "ubnt", "ubnt", 22, "default"),
        ]);

        // MikroTik
        self.add_credentials(vec![
            ("router", Some("MikroTik"), None, "http", "admin", "", 80, "default"),
            ("router", Some("MikroTik"), None, "ssh", "admin", "", 22, "default"),
        ]);

        // Smart Home Hubs
        self.add_credentials(vec![
            ("hub", None, None, "http", "admin", "admin", 80, "default"),
            ("hub", None, None, "http", "admin", "", 80, "default"),
            ("hub", None, None, "mqtt", "admin", "admin", 1883, "default"),
            ("hub", None, None, "mqtt", "guest", "guest", 1883, "default"),
        ]);

        // MQTT Brokers
        self.add_credentials(vec![
            ("hub", None, None, "mqtt", "", "", 1883, "default"),
            ("hub", None, None, "mqtt", "admin", "public", 1883, "default"),
            ("hub", None, None, "mqtt", "guest", "guest", 1883, "default"),
            ("hub", None, None, "mqtt", "mqtt", "mqtt", 1883, "default"),
            ("hub", None, None, "mqtt", "user", "user", 1883, "default"),
            ("hub", None, None, "mqtt", "mosquitto", "mosquitto", 1883, "default"),
        ]);

        // Printers
        self.add_credentials(vec![
            ("printer", None, None, "http", "admin", "admin", 80, "default"),
            ("printer", None, None, "http", "admin", "", 80, "default"),
            ("printer", Some("HP"), None, "http", "admin", "admin", 80, "default"),
            ("printer", Some("Brother"), None, "http", "admin", "access", 80, "default"),
            ("printer", Some("Epson"), None, "http", "admin", "admin", 80, "default"),
        ]);

        // Smart TVs
        self.add_credentials(vec![
            ("tv", None, None, "http", "admin", "admin", 80, "default"),
            ("tv", Some("Samsung"), None, "http", "admin", "admin", 80, "default"),
            ("tv", Some("LG"), None, "http", "admin", "admin", 80, "default"),
        ]);

        // Building Automation
        self.add_credentials(vec![
            ("building_automation", None, None, "http", "admin", "admin", 80, "default"),
            ("building_automation", None, None, "http", "admin", "1234", 80, "default"),
            ("building_automation", Some("Honeywell"), None, "http", "admin", "admin", 80, "default"),
            ("building_automation", Some("Johnson Controls"), None, "http", "admin", "admin", 80, "default"),
            ("building_automation", Some("Tridium"), None, "http", "admin", "admin", 80, "default"),
        ]);

        // Industrial IoT
        self.add_credentials(vec![
            ("industrial", None, None, "http", "admin", "admin", 80, "default"),
            ("industrial", None, None, "telnet", "admin", "admin", 23, "default"),
            ("industrial", None, None, "ssh", "root", "root", 22, "default"),
        ]);

        // Common leaked/weak credentials (works on many devices)
        self.add_credentials(vec![
            ("unknown", None, None, "telnet", "root", "123456", 23, "common"),
            ("unknown", None, None, "telnet", "admin", "123456", 23, "common"),
            ("unknown", None, None, "telnet", "root", "password", 23, "common"),
            ("unknown", None, None, "ssh", "root", "123456", 22, "common"),
            ("unknown", None, None, "ssh", "admin", "123456", 22, "common"),
            ("unknown", None, None, "ftp", "anonymous", "", 21, "common"),
            ("unknown", None, None, "ftp", "ftp", "ftp", 21, "common"),
        ]);
    }

    /// Add credentials to the database
    fn add_credentials(&mut self, creds: Vec<(&str, Option<&str>, Option<&str>, &str, &str, &str, u16, &str)>) {
        for (device_type, vendor, model, protocol, username, password, port, source) in creds {
            let idx = self.credentials.len();
            let cred = DefaultCredential {
                device_type: device_type.to_string(),
                vendor: vendor.map(String::from),
                model: model.map(String::from),
                protocol: protocol.to_string(),
                username: username.to_string(),
                password: password.to_string(),
                port,
                source: source.to_string(),
            };

            self.credentials.push(cred);

            // Index by device type
            self.by_type
                .entry(device_type.to_lowercase())
                .or_default()
                .push(idx);

            // Index by vendor
            if let Some(v) = vendor {
                self.by_vendor
                    .entry(v.to_lowercase())
                    .or_default()
                    .push(idx);
            }
        }
    }

    /// Get credentials for a device type
    pub fn get_by_type(&self, device_type: &str) -> Vec<&DefaultCredential> {
        self.by_type
            .get(&device_type.to_lowercase())
            .map(|indices| indices.iter().map(|&i| &self.credentials[i]).collect())
            .unwrap_or_default()
    }

    /// Get credentials for a vendor
    pub fn get_by_vendor(&self, vendor: &str) -> Vec<&DefaultCredential> {
        self.by_vendor
            .get(&vendor.to_lowercase())
            .map(|indices| indices.iter().map(|&i| &self.credentials[i]).collect())
            .unwrap_or_default()
    }

    /// Search credentials
    pub fn search(&self, device_type: Option<&str>, vendor: Option<&str>, protocol: Option<&str>) -> Vec<&DefaultCredential> {
        self.credentials
            .iter()
            .filter(|c| {
                let type_match = device_type
                    .map(|t| c.device_type.to_lowercase() == t.to_lowercase() || c.device_type == "unknown")
                    .unwrap_or(true);

                let vendor_match = match (vendor, &c.vendor) {
                    (Some(v), Some(cv)) => cv.to_lowercase().contains(&v.to_lowercase()),
                    (Some(_), None) => true, // No vendor restriction
                    (None, _) => true,
                };

                let proto_match = protocol
                    .map(|p| c.protocol.to_lowercase() == p.to_lowercase())
                    .unwrap_or(true);

                type_match && vendor_match && proto_match
            })
            .collect()
    }

    /// Get all credentials
    pub fn all(&self) -> &[DefaultCredential] {
        &self.credentials
    }

    /// Get count
    pub fn count(&self) -> usize {
        self.credentials.len()
    }
}

impl Default for IotCredentialDatabase {
    fn default() -> Self {
        Self::new()
    }
}

/// Credential checker for IoT devices
pub struct IotCredentialChecker {
    database: IotCredentialDatabase,
    timeout: Duration,
}

impl IotCredentialChecker {
    pub fn new(timeout: Duration) -> Self {
        Self {
            database: IotCredentialDatabase::new(),
            timeout,
        }
    }

    /// Check credentials for a device
    pub async fn check_device(
        &self,
        device: &IotDevice,
        protocols_to_check: Option<&[IotProtocolType]>,
    ) -> Result<Vec<CredentialCheckResult>> {
        let mut results = Vec::new();

        let ip = match &device.ip_address {
            Some(ip) => ip.clone(),
            None => return Ok(results),
        };

        // Get credentials to try
        let device_type = device.device_type.to_string().to_lowercase();
        let mut creds = self.database.get_by_type(&device_type);

        // Add vendor-specific credentials
        if let Some(vendor) = &device.vendor {
            creds.extend(self.database.get_by_vendor(vendor));
        }

        // Filter by protocols if specified
        if let Some(protos) = protocols_to_check {
            let proto_strs: Vec<String> = protos.iter().map(|p| p.to_string().to_lowercase()).collect();
            creds.retain(|c| proto_strs.contains(&c.protocol.to_lowercase()));
        }

        // Check each credential
        for cred in creds {
            let port = if device.open_ports.contains(&cred.port) {
                cred.port
            } else {
                continue; // Port not open
            };

            let result = self.try_credential(&ip, port, cred).await;
            results.push(result);

            // Stop if we found valid credentials
            if results.last().map(|r| r.success).unwrap_or(false) {
                break;
            }
        }

        Ok(results)
    }

    /// Try a single credential
    async fn try_credential(
        &self,
        ip: &str,
        port: u16,
        cred: &DefaultCredential,
    ) -> CredentialCheckResult {
        let addr: SocketAddr = match format!("{}:{}", ip, port).parse() {
            Ok(a) => a,
            Err(_) => {
                return CredentialCheckResult {
                    device_id: String::new(),
                    ip_address: ip.to_string(),
                    protocol: cred.protocol.parse().unwrap_or(IotProtocolType::Http),
                    port,
                    success: false,
                    username: Some(cred.username.clone()),
                    is_default: true,
                    message: "Invalid address".to_string(),
                };
            }
        };

        let success = match cred.protocol.as_str() {
            "http" | "https" => self.try_http_auth(addr, &cred.username, &cred.password).await,
            "telnet" => self.try_telnet_auth(addr, &cred.username, &cred.password).await,
            "ssh" => self.try_ssh_auth(addr, &cred.username, &cred.password).await,
            "ftp" => self.try_ftp_auth(addr, &cred.username, &cred.password).await,
            "mqtt" => self.try_mqtt_auth(addr, &cred.username, &cred.password).await,
            _ => false,
        };

        CredentialCheckResult {
            device_id: String::new(),
            ip_address: ip.to_string(),
            protocol: cred.protocol.parse().unwrap_or(IotProtocolType::Http),
            port,
            success,
            username: Some(cred.username.clone()),
            is_default: cred.source == "default",
            message: if success {
                format!("Authentication successful with {}:{}", cred.username, if cred.password.is_empty() { "(empty)" } else { "***" })
            } else {
                "Authentication failed".to_string()
            },
        }
    }

    /// Try HTTP Basic Auth
    async fn try_http_auth(&self, addr: SocketAddr, username: &str, password: &str) -> bool {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;

        let mut stream = match timeout(self.timeout, TcpStream::connect(addr)).await {
            Ok(Ok(s)) => s,
            _ => return false,
        };

        let auth = STANDARD.encode(format!("{}:{}", username, password));
        let request = format!(
            "GET / HTTP/1.1\r\nHost: {}\r\nAuthorization: Basic {}\r\nConnection: close\r\n\r\n",
            addr, auth
        );

        if let Err(_) = stream.write_all(request.as_bytes()).await {
            return false;
        }

        let mut buffer = vec![0u8; 1024];
        if let Ok(Ok(n)) = timeout(self.timeout, stream.read(&mut buffer)).await {
            let response = String::from_utf8_lossy(&buffer[..n]);
            // Check for success (200) or redirect (301/302) - both indicate valid auth
            return response.starts_with("HTTP/1.1 200") ||
                   response.starts_with("HTTP/1.0 200") ||
                   response.contains("200 OK") ||
                   (response.starts_with("HTTP/1.1 30") && !response.contains("401"));
        }

        false
    }

    /// Try Telnet auth (simplified)
    async fn try_telnet_auth(&self, addr: SocketAddr, username: &str, password: &str) -> bool {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;

        let mut stream = match timeout(self.timeout, TcpStream::connect(addr)).await {
            Ok(Ok(s)) => s,
            _ => return false,
        };

        // Wait for login prompt
        let mut buffer = vec![0u8; 1024];
        let _ = timeout(self.timeout, stream.read(&mut buffer)).await;

        // Send username
        let _ = stream.write_all(format!("{}\r\n", username).as_bytes()).await;
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Wait for password prompt
        let _ = timeout(self.timeout, stream.read(&mut buffer)).await;

        // Send password
        let _ = stream.write_all(format!("{}\r\n", password).as_bytes()).await;
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Read response
        if let Ok(Ok(n)) = timeout(self.timeout, stream.read(&mut buffer)).await {
            let response = String::from_utf8_lossy(&buffer[..n]).to_lowercase();
            // Check for shell prompt or success indicators
            return response.contains("#") ||
                   response.contains("$") ||
                   response.contains(">") ||
                   response.contains("welcome") ||
                   response.contains("logged in") ||
                   !response.contains("login") && !response.contains("password") && !response.contains("incorrect") && !response.contains("failed");
        }

        false
    }

    /// Try SSH auth (simplified - just connection test)
    async fn try_ssh_auth(&self, _addr: SocketAddr, _username: &str, _password: &str) -> bool {
        // Note: Full SSH auth would require an SSH library
        // For now, we just return false (not implemented)
        // In production, use a library like russh or ssh2
        false
    }

    /// Try FTP auth
    async fn try_ftp_auth(&self, addr: SocketAddr, username: &str, password: &str) -> bool {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        use tokio::net::TcpStream;

        let stream = match timeout(self.timeout, TcpStream::connect(addr)).await {
            Ok(Ok(s)) => s,
            _ => return false,
        };

        let mut reader = BufReader::new(stream);
        let mut line = String::new();

        // Read banner
        let _ = timeout(self.timeout, reader.read_line(&mut line)).await;
        if !line.starts_with("220") {
            return false;
        }

        // Send USER command
        let stream = reader.into_inner();
        let (read_half, mut write_half) = stream.into_split();
        let mut reader = BufReader::new(read_half);

        let _ = write_half.write_all(format!("USER {}\r\n", username).as_bytes()).await;
        line.clear();
        let _ = timeout(self.timeout, reader.read_line(&mut line)).await;

        if !line.starts_with("331") && !line.starts_with("230") {
            return false;
        }

        if line.starts_with("230") {
            return true; // Logged in without password
        }

        // Send PASS command
        let _ = write_half.write_all(format!("PASS {}\r\n", password).as_bytes()).await;
        line.clear();
        let _ = timeout(self.timeout, reader.read_line(&mut line)).await;

        line.starts_with("230")
    }

    /// Try MQTT auth
    async fn try_mqtt_auth(&self, addr: SocketAddr, username: &str, password: &str) -> bool {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;

        let mut stream = match timeout(self.timeout, TcpStream::connect(addr)).await {
            Ok(Ok(s)) => s,
            _ => return false,
        };

        // Build MQTT CONNECT packet with auth
        let client_id = b"cred_check";
        let mut connect_packet = vec![
            0x10, // CONNECT packet type
            0x00, // Remaining length (to be set)
            0x00, 0x04, // Protocol name length
            b'M', b'Q', b'T', b'T',
            0x04, // Protocol version (MQTT 3.1.1)
            0xC2, // Connect flags: clean session + username + password
            0x00, 0x3C, // Keep alive (60 seconds)
        ];

        // Client ID
        connect_packet.push(0x00);
        connect_packet.push(client_id.len() as u8);
        connect_packet.extend_from_slice(client_id);

        // Username
        connect_packet.push(0x00);
        connect_packet.push(username.len() as u8);
        connect_packet.extend_from_slice(username.as_bytes());

        // Password
        connect_packet.push(0x00);
        connect_packet.push(password.len() as u8);
        connect_packet.extend_from_slice(password.as_bytes());

        // Set remaining length
        let remaining_len = connect_packet.len() - 2;
        connect_packet[1] = remaining_len as u8;

        if let Err(_) = stream.write_all(&connect_packet).await {
            return false;
        }

        let mut buffer = vec![0u8; 32];
        if let Ok(Ok(n)) = timeout(self.timeout, stream.read(&mut buffer)).await {
            if n >= 4 && buffer[0] == 0x20 {
                // CONNACK received, check return code
                let return_code = buffer[3];
                return return_code == 0; // 0 = Connection Accepted
            }
        }

        false
    }

    /// Get the credential database
    pub fn database(&self) -> &IotCredentialDatabase {
        &self.database
    }
}

impl Default for IotCredentialChecker {
    fn default() -> Self {
        Self::new(Duration::from_secs(5))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_credential_database() {
        let db = IotCredentialDatabase::new();
        assert!(db.count() > 50); // Should have many credentials

        let camera_creds = db.get_by_type("camera");
        assert!(!camera_creds.is_empty());

        let hikvision_creds = db.get_by_vendor("hikvision");
        assert!(!hikvision_creds.is_empty());
    }

    #[test]
    fn test_search_credentials() {
        let db = IotCredentialDatabase::new();

        let results = db.search(Some("camera"), Some("Hikvision"), Some("http"));
        assert!(!results.is_empty());

        let results = db.search(None, None, Some("mqtt"));
        assert!(!results.is_empty());
    }
}
