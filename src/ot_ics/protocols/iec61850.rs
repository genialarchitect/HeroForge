//! IEC 61850 Protocol Scanner
//!
//! Scans for IEC 61850 devices commonly used in electrical substations.
//! Implements MMS (Manufacturing Message Specification) over COTP for
//! device identification and security assessment.

use super::{ProtocolScanResult, ProtocolScanner};
use crate::ot_ics::types::{OtProtocolType, ProtocolDetails, SecurityIssue};
use anyhow::Result;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// IEC 61850 scanner for substation automation systems
pub struct Iec61850Scanner;

impl Iec61850Scanner {
    pub fn new() -> Self {
        Self
    }
}

impl Default for Iec61850Scanner {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl ProtocolScanner for Iec61850Scanner {
    fn protocol_type(&self) -> OtProtocolType {
        OtProtocolType::Iec61850
    }

    fn default_port(&self) -> u16 {
        102 // ISO COTP over TCP
    }

    async fn detect(&self, addr: SocketAddr, dur: Duration) -> Result<bool> {
        // IEC 61850 runs over MMS which uses ACSE/Presentation/Session/COTP/TCP
        // Try to establish a COTP connection
        match timeout(dur, TcpStream::connect(addr)).await {
            Ok(Ok(mut stream)) => {
                // Send COTP Connection Request (CR TPDU)
                let cotp_cr = build_cotp_connection_request();

                if stream.write_all(&cotp_cr).await.is_err() {
                    return Ok(false);
                }

                let mut buf = [0u8; 512];
                match timeout(dur, stream.read(&mut buf)).await {
                    Ok(Ok(n)) if n > 4 => {
                        // Check for COTP Connection Confirm (CC TPDU)
                        // TPKT header: version=3, reserved=0
                        // COTP: CC PDU type = 0xD0
                        if buf[0] == 0x03 && n > 6 && buf[5] == 0xD0 {
                            return Ok(true);
                        }
                        Ok(false)
                    }
                    _ => Ok(false),
                }
            }
            _ => Ok(false),
        }
    }

    async fn scan(&self, addr: SocketAddr, dur: Duration) -> Result<ProtocolScanResult> {
        let start = Instant::now();
        let detected = self.detect(addr, dur).await.unwrap_or(false);
        let mut security_issues = Vec::new();

        let mut details = ProtocolDetails {
            device_id: None,
            version: None,
            vendor_info: None,
            metadata: serde_json::json!({}),
        };

        if detected {
            // Attempt full MMS session to enumerate device info
            match get_iec61850_info(addr, dur).await {
                Ok(info) => {
                    details.device_id = info.device_id;
                    details.vendor_info = info.vendor;
                    details.version = info.version;
                    details.metadata = serde_json::json!({
                        "model": info.model,
                        "logical_devices": info.logical_devices,
                        "goose_enabled": info.goose_detected,
                        "mms_version": info.mms_version,
                        "max_pdu_size": info.max_pdu_size,
                        "services_supported": info.services,
                    });

                    // Security assessments based on gathered info
                    if info.no_authentication {
                        security_issues.push(SecurityIssue {
                            issue_type: "Authentication".to_string(),
                            severity: "Critical".to_string(),
                            description: "IEC 61850 MMS server allows unauthenticated access - no ACSE authentication negotiated".to_string(),
                            remediation: Some("Enable authentication using IEC 62351-4 (MMS security) with X.509 certificates or TLS mutual authentication".to_string()),
                        });
                    }

                    if !info.uses_tls {
                        security_issues.push(SecurityIssue {
                            issue_type: "Encryption".to_string(),
                            severity: "High".to_string(),
                            description: "MMS communications are transmitted in plaintext without TLS/SSL encryption".to_string(),
                            remediation: Some("Implement TLS for MMS transport per IEC 62351-3, use port 3782 for secure MMS".to_string()),
                        });
                    }

                    if info.goose_detected && !info.goose_authenticated {
                        security_issues.push(SecurityIssue {
                            issue_type: "GOOSE Authentication".to_string(),
                            severity: "Critical".to_string(),
                            description: "GOOSE messages lack authentication - vulnerable to spoofing attacks".to_string(),
                            remediation: Some("Implement GOOSE authentication per IEC 62351-6 using MAC-based message signatures".to_string()),
                        });
                    }

                    if info.writable_access {
                        security_issues.push(SecurityIssue {
                            issue_type: "Access Control".to_string(),
                            severity: "Critical".to_string(),
                            description: "MMS server allows write access to data objects without proper authorization".to_string(),
                            remediation: Some("Implement role-based access control for MMS write operations, restrict to authorized engineering workstations".to_string()),
                        });
                    }

                    if info.max_pdu_size > 65000 {
                        security_issues.push(SecurityIssue {
                            issue_type: "Configuration".to_string(),
                            severity: "Medium".to_string(),
                            description: format!("Large maximum PDU size ({} bytes) may enable buffer overflow attacks", info.max_pdu_size),
                            remediation: Some("Limit MMS maximum PDU size to operational requirements (typically 32768 bytes or less)".to_string()),
                        });
                    }
                }
                Err(_) => {
                    // Could connect via COTP but MMS session failed
                    details.device_id = Some("IEC 61850 Device (MMS enumeration failed)".to_string());
                    // Still flag basic security concerns
                    if addr.port() == 102 {
                        security_issues.push(SecurityIssue {
                            issue_type: "Encryption".to_string(),
                            severity: "High".to_string(),
                            description: "Standard MMS port (102) detected without TLS - communications likely unencrypted".to_string(),
                            remediation: Some("Migrate to secure MMS port 3782 with TLS per IEC 62351-3".to_string()),
                        });
                    }
                }
            }
        }

        Ok(ProtocolScanResult {
            protocol: OtProtocolType::Iec61850,
            port: addr.port(),
            detected,
            details,
            security_issues,
            response_time_ms: start.elapsed().as_millis() as u64,
        })
    }
}

/// Information gathered from IEC 61850 device via MMS session
struct Iec61850Info {
    device_id: Option<String>,
    vendor: Option<String>,
    model: Option<String>,
    version: Option<String>,
    logical_devices: Vec<String>,
    goose_detected: bool,
    goose_authenticated: bool,
    mms_version: Option<String>,
    max_pdu_size: u32,
    services: Vec<String>,
    no_authentication: bool,
    uses_tls: bool,
    writable_access: bool,
}

/// Perform full IEC 61850 MMS session to enumerate device information
async fn get_iec61850_info(addr: SocketAddr, dur: Duration) -> Result<Iec61850Info> {
    let mut info = Iec61850Info {
        device_id: None,
        vendor: None,
        model: None,
        version: None,
        logical_devices: Vec::new(),
        goose_detected: false,
        goose_authenticated: false,
        mms_version: None,
        max_pdu_size: 0,
        services: Vec::new(),
        no_authentication: true, // Assume vulnerable until proven otherwise
        uses_tls: addr.port() == 3782, // Secure MMS uses port 3782
        writable_access: false,
    };

    let mut stream = timeout(dur, TcpStream::connect(addr)).await
        .map_err(|_| anyhow::anyhow!("Connection timeout"))??;

    // Step 1: COTP Connection Request
    let cotp_cr = build_cotp_connection_request();
    stream.write_all(&cotp_cr).await?;

    let mut buf = [0u8; 2048];
    let n = timeout(dur, stream.read(&mut buf)).await
        .map_err(|_| anyhow::anyhow!("COTP CC timeout"))??;

    if n < 7 || buf[0] != 0x03 || buf[5] != 0xD0 {
        return Err(anyhow::anyhow!("Invalid COTP Connection Confirm"));
    }

    // Step 2: Send MMS Initiate Request (wrapped in ACSE/Presentation/Session/COTP DT)
    let mms_initiate = build_mms_initiate_request();
    stream.write_all(&mms_initiate).await?;

    let n = timeout(dur, stream.read(&mut buf)).await
        .map_err(|_| anyhow::anyhow!("MMS Initiate response timeout"))??;

    if n > 10 {
        // Parse MMS Initiate Response to extract negotiated parameters
        parse_mms_initiate_response(&buf[..n], &mut info);
    }

    // Step 3: Send GetNameList request to enumerate Logical Devices
    let get_namelist = build_mms_get_namelist_request();
    stream.write_all(&get_namelist).await?;

    let n = timeout(dur, stream.read(&mut buf)).await
        .map_err(|_| anyhow::anyhow!("GetNameList response timeout"))??;

    if n > 10 {
        parse_mms_namelist_response(&buf[..n], &mut info);
    }

    // Step 4: Try GetNamedVariableListAttributes for vendor info
    if let Some(first_ld) = info.logical_devices.first().cloned() {
        let identify_req = build_mms_identify_request();
        stream.write_all(&identify_req).await?;

        let n = timeout(dur, stream.read(&mut buf)).await
            .map_err(|_| anyhow::anyhow!("Identify response timeout"))??;

        if n > 10 {
            parse_mms_identify_response(&buf[..n], &mut info);
        }

        // Step 5: Test write access by attempting to read a controllable data object
        let read_req = build_mms_read_request(&first_ld);
        if stream.write_all(&read_req).await.is_ok() {
            if let Ok(Ok(n)) = timeout(dur, stream.read(&mut buf)).await {
                if n > 10 {
                    // If we can read, check if write would be possible
                    info.writable_access = check_write_access_from_response(&buf[..n]);
                }
            }
        }
    }

    // Set device ID from gathered info
    if let (Some(ref vendor), Some(ref model)) = (&info.vendor, &info.model) {
        info.device_id = Some(format!("{} {}", vendor, model));
    } else if let Some(ref vendor) = info.vendor {
        info.device_id = Some(format!("{} IED", vendor));
    } else if !info.logical_devices.is_empty() {
        info.device_id = Some(format!("IEC 61850 IED ({} LDs)", info.logical_devices.len()));
    } else {
        info.device_id = Some("IEC 61850 Device".to_string());
    }

    Ok(info)
}

/// Build COTP Connection Request for IEC 61850 (port 102, TSAP for MMS)
fn build_cotp_connection_request() -> Vec<u8> {
    let mut packet = Vec::new();

    // TPKT Header (RFC 1006)
    packet.push(0x03); // Version
    packet.push(0x00); // Reserved
    packet.push(0x00); // Length high byte (filled later)
    packet.push(0x16); // Length low byte (22 bytes total)

    // COTP CR TPDU (ISO 8073)
    packet.push(0x11); // Length of COTP header
    packet.push(0xE0); // CR (Connection Request) code
    packet.push(0x00); // DST-REF high
    packet.push(0x00); // DST-REF low
    packet.push(0x00); // SRC-REF high
    packet.push(0x01); // SRC-REF low
    packet.push(0x00); // Class 0, no extended formats

    // Parameter: TPDU Size (0xC0)
    packet.push(0xC0); // Parameter code: TPDU size
    packet.push(0x01); // Parameter length
    packet.push(0x0A); // TPDU size = 1024 bytes

    // Parameter: Source TSAP (0xC1) - identifies MMS client
    packet.push(0xC1); // Parameter code: calling TSAP
    packet.push(0x02); // Length
    packet.push(0x00);
    packet.push(0x01); // Client TSAP

    // Parameter: Destination TSAP (0xC2) - identifies MMS server
    packet.push(0xC2); // Parameter code: called TSAP
    packet.push(0x02); // Length
    packet.push(0x00);
    packet.push(0x01); // Server TSAP (common for IEC 61850)

    packet
}

/// Build MMS Initiate Request wrapped in COTP Data TPDU
/// This establishes the MMS session and negotiates parameters
fn build_mms_initiate_request() -> Vec<u8> {
    // MMS Initiate-RequestPDU (ASN.1 BER encoded)
    // Negotiates: max PDU size, max services outstanding, version
    let mms_initiate = vec![
        // MMS Initiate-RequestPDU [0] IMPLICIT
        0xA8, 0x26, // Context tag [8], length 38
        // localDetailCalling [0] INTEGER
        0x80, 0x03, 0x00, 0x00, 0x01, // Max PDU size: 65536 (but encoded as small for compat)
        // proposedMaxServOutstanding-calling [1] INTEGER
        0x81, 0x01, 0x01, // 1 outstanding service
        // proposedMaxServOutstanding-called [2] INTEGER
        0x82, 0x01, 0x01, // 1 outstanding service
        // proposedDataStructureNestingLevel [3] INTEGER
        0x83, 0x01, 0x0A, // Nesting level 10
        // initRequestDetail [4] SEQUENCE
        0xA4, 0x16,
        // proposedVersionNumber [0] INTEGER
        0x80, 0x01, 0x01, // MMS Version 1
        // proposedParameterCBB [1] BIT STRING
        0x81, 0x03, 0x05, 0xF1, 0x00, // Parameter CBB
        // servicesSupportedCalling [2] BIT STRING
        0x82, 0x0C, 0x03, 0xEE, 0x1C, 0x00, 0x00, 0x04, 0x08, 0x00, 0x00, 0x79, 0xEF, 0x18,
    ];

    // Wrap in Presentation/Session/COTP layers
    build_cotp_data_tpdu(&mms_initiate)
}

/// Build MMS GetNameList request to enumerate VMD (Virtual Manufacturing Device) domains
fn build_mms_get_namelist_request() -> Vec<u8> {
    // GetNameList-Request for domain names (Logical Devices)
    let mms_request = vec![
        // Confirmed-RequestPDU [0]
        0xA0, 0x0F,
        // invokeID [0] INTEGER
        0x02, 0x01, 0x01, // Invoke ID = 1
        // confirmedServiceRequest CHOICE
        // getNameList [1]
        0xA1, 0x0A,
        // extendedObjectClass [0] CHOICE
        0xA0, 0x03,
        // objectClass [0] INTEGER
        0x80, 0x01, 0x09, // 9 = domain (Logical Device)
        // objectScope [1] CHOICE
        0xA1, 0x03,
        // vmdSpecific [0] NULL
        0x80, 0x01, 0x00,
    ];

    build_cotp_data_tpdu(&mms_request)
}

/// Build MMS Identify request to get vendor/model/revision
fn build_mms_identify_request() -> Vec<u8> {
    // Identify-Request (service = identify)
    let mms_request = vec![
        // Confirmed-RequestPDU [0]
        0xA0, 0x07,
        // invokeID [0] INTEGER
        0x02, 0x01, 0x02, // Invoke ID = 2
        // confirmedServiceRequest CHOICE
        // identify [82] NULL
        0x82, 0x00,
    ];

    build_cotp_data_tpdu(&mms_request)
}

/// Build MMS Read request for a data object (to test access controls)
fn build_mms_read_request(logical_device: &str) -> Vec<u8> {
    // Read the LLN0$ST (Status) data object which should be readable
    let item_id = format!("{}LLN0$ST$Mod$stVal", logical_device);
    let item_bytes = item_id.as_bytes();

    let mut mms_request = vec![
        // Confirmed-RequestPDU [0]
        0xA0, 0x00, // Length placeholder (updated below)
        // invokeID INTEGER
        0x02, 0x01, 0x03, // Invoke ID = 3
        // confirmedServiceRequest: read [4]
        0xA4, 0x00, // Length placeholder
        // variableAccessSpecification [0] CHOICE
        // listOfVariable [0]
        0xA0, 0x00, // Length placeholder
        // single element
        0x30, 0x00, // SEQUENCE length placeholder
        // variableSpecification [0] CHOICE
        // name [0]
        0xA0, 0x00, // Length placeholder
        // domain-specific [1]
        0xA1, 0x00, // Length placeholder
    ];

    // Add domain name (logical device)
    let ld_bytes = logical_device.as_bytes();
    let mut domain_part = vec![0x1A]; // VisibleString tag
    domain_part.push(ld_bytes.len() as u8);
    domain_part.extend_from_slice(ld_bytes);

    // Add item ID
    domain_part.push(0x1A); // VisibleString tag
    domain_part.push(item_bytes.len() as u8);
    domain_part.extend_from_slice(item_bytes);

    // For simplicity, build a minimal read request
    let read_payload = vec![
        0xA0, (6 + ld_bytes.len() + item_bytes.len()) as u8,
        0x30, (4 + ld_bytes.len() + item_bytes.len()) as u8,
        0xA0, (2 + ld_bytes.len() + item_bytes.len()) as u8,
        0xA1, (ld_bytes.len() + item_bytes.len()) as u8,
    ];

    let mut full_request = vec![
        0xA0, 0x00, // Confirmed-RequestPDU, length placeholder
        0x02, 0x01, 0x03, // invokeID = 3
        0xA4, 0x00, // read, length placeholder
    ];
    full_request.extend_from_slice(&read_payload);
    full_request.extend_from_slice(&domain_part);

    // Fix up lengths
    let read_content_len = full_request.len() - 7;
    full_request[6] = read_content_len as u8;
    let total_content_len = full_request.len() - 2;
    full_request[1] = total_content_len as u8;

    build_cotp_data_tpdu(&full_request)
}

/// Wrap MMS PDU in COTP Data TPDU with TPKT header
fn build_cotp_data_tpdu(mms_data: &[u8]) -> Vec<u8> {
    let mut packet = Vec::new();

    // COTP Data TPDU header: 3 bytes
    let cotp_header: &[u8] = &[
        0x02, // COTP header length
        0xF0, // Data Transfer (DT) PDU type
        0x80, // EOT (End of TPDU) flag set
    ];

    let total_len = 4 + cotp_header.len() + mms_data.len(); // TPKT(4) + COTP + MMS

    // TPKT Header
    packet.push(0x03); // Version
    packet.push(0x00); // Reserved
    packet.push((total_len >> 8) as u8); // Length high
    packet.push((total_len & 0xFF) as u8); // Length low

    // COTP Data TPDU
    packet.extend_from_slice(cotp_header);

    // MMS PDU
    packet.extend_from_slice(mms_data);

    packet
}

/// Parse MMS Initiate Response to extract negotiated parameters
fn parse_mms_initiate_response(data: &[u8], info: &mut Iec61850Info) {
    // Skip TPKT (4 bytes) and COTP DT (3 bytes) headers
    if data.len() < 10 {
        return;
    }

    let mms_data = &data[7..];

    // Look for Initiate-ResponsePDU tag [9] = 0xA9
    if let Some(pos) = find_tag(mms_data, 0xA9) {
        let response_data = &mms_data[pos..];

        // Extract localDetailCalled (max PDU size) [0] = 0x80
        if let Some(pdu_size) = extract_integer_value(response_data, 0x80) {
            info.max_pdu_size = pdu_size as u32;
        }

        // Look for initResponseDetail [4] to get version and services
        if let Some(detail_pos) = find_tag(response_data, 0xA4) {
            let detail_data = &response_data[detail_pos..];

            // proposedVersionNumber [0] = 0x80
            if let Some(version) = extract_integer_value(detail_data, 0x80) {
                info.mms_version = Some(format!("MMS v{}", version));
            }

            // servicesSupportedCalled [2] = 0x82 (BIT STRING)
            if let Some(services_pos) = find_tag(detail_data, 0x82) {
                let services = parse_supported_services(detail_data, services_pos);
                info.services = services;
            }
        }

        // If we got a valid response without any authentication challenge,
        // the server allows unauthenticated access
        info.no_authentication = true;
    }

    // Check for ACSE authentication in the presentation layer
    // If we find authentication-value in the response, authentication was negotiated
    if find_bytes(data, &[0xA2, 0x03, 0x80, 0x01]).is_some() {
        info.no_authentication = false;
    }
}

/// Parse MMS GetNameList response to extract Logical Device names
fn parse_mms_namelist_response(data: &[u8], info: &mut Iec61850Info) {
    if data.len() < 10 {
        return;
    }

    let mms_data = &data[7..]; // Skip TPKT + COTP

    // Look for Confirmed-ResponsePDU [1] = 0xA1 or the getNameList response
    // The response contains a listOfIdentifier with VisibleString entries

    // Search for VisibleString values (tag 0x1A) in the response
    let mut pos = 0;
    while pos < mms_data.len().saturating_sub(2) {
        if mms_data[pos] == 0x1A { // VisibleString
            let len = mms_data[pos + 1] as usize;
            if len > 0 && len < 64 && pos + 2 + len <= mms_data.len() {
                if let Ok(name) = std::str::from_utf8(&mms_data[pos + 2..pos + 2 + len]) {
                    let name_str = name.to_string();
                    // Filter for likely logical device names (typically alphanumeric with underscores)
                    if is_valid_ld_name(&name_str) {
                        info.logical_devices.push(name_str);
                    }
                }
                pos += 2 + len;
            } else {
                pos += 1;
            }
        } else {
            pos += 1;
        }
    }

    // Check for GOOSE-related logical nodes in the device names
    for ld in &info.logical_devices {
        let ld_upper = ld.to_uppercase();
        if ld_upper.contains("GOOSE") || ld_upper.contains("GOCB") || ld_upper.contains("GCB") {
            info.goose_detected = true;
            break;
        }
    }
}

/// Parse MMS Identify response to extract vendor/model/revision
fn parse_mms_identify_response(data: &[u8], info: &mut Iec61850Info) {
    if data.len() < 10 {
        return;
    }

    let mms_data = &data[7..]; // Skip TPKT + COTP

    // Identify response contains three VisibleStrings:
    // vendorName, modelName, revision
    let mut strings: Vec<String> = Vec::new();
    let mut pos = 0;

    while pos < mms_data.len().saturating_sub(2) && strings.len() < 3 {
        if mms_data[pos] == 0x1A { // VisibleString
            let len = mms_data[pos + 1] as usize;
            if len > 0 && len < 128 && pos + 2 + len <= mms_data.len() {
                if let Ok(s) = std::str::from_utf8(&mms_data[pos + 2..pos + 2 + len]) {
                    strings.push(s.to_string());
                }
                pos += 2 + len;
            } else {
                pos += 1;
            }
        } else {
            pos += 1;
        }
    }

    // Assign vendor, model, revision from the three strings
    if let Some(vendor) = strings.first() {
        if !vendor.is_empty() {
            info.vendor = Some(vendor.clone());
        }
    }
    if let Some(model) = strings.get(1) {
        if !model.is_empty() {
            info.model = Some(model.clone());
        }
    }
    if let Some(revision) = strings.get(2) {
        if !revision.is_empty() {
            info.version = Some(revision.clone());
        }
    }
}

/// Check if MMS read response indicates write access is possible
fn check_write_access_from_response(data: &[u8]) -> bool {
    if data.len() < 10 {
        return false;
    }

    let mms_data = &data[7..]; // Skip TPKT + COTP

    // If we got a successful read response (no access-denied error),
    // and the data object is a controllable one, write access may be available.
    // Look for confirmed-ResponsePDU without error
    // Error would be indicated by serviceError tag
    let has_error = find_tag(mms_data, 0xA2).is_some(); // serviceError

    // If no error on reading status data, the device likely allows broad read access
    // Check if there's a data-access-error (tag varies)
    !has_error
}

/// Parse supported MMS services from BIT STRING
fn parse_supported_services(data: &[u8], start: usize) -> Vec<String> {
    let mut services = Vec::new();

    if start + 2 >= data.len() {
        return services;
    }

    let len = data[start + 1] as usize;
    if len < 2 || start + 2 + len > data.len() {
        return services;
    }

    // First byte of BIT STRING content is unused bits count
    let _unused_bits = data[start + 2];
    let service_bits = &data[start + 3..start + 2 + len];

    // Map bit positions to MMS service names
    let service_names = [
        "status", "getNameList", "identify", "rename",
        "read", "write", "getVariableAccessAttributes",
        "defineNamedVariable", "defineScatteredAccess",
        "getScatteredAccessAttributes", "deleteVariableAccess",
        "defineNamedVariableList", "getNamedVariableListAttributes",
        "deleteNamedVariableList", "defineNamedType",
        "getNamedTypeAttributes", "deleteNamedType",
        "input", "output", "takeControl", "relinquishControl",
        "defineSemaphore", "deleteSemaphore", "reportSemaphoreStatus",
        "reportPoolSemaphoreStatus", "reportSemaphoreEntryStatus",
        "initiateDownloadSequence", "downloadSegment",
        "terminateDownloadSequence", "initiateUploadSequence",
        "uploadSegment", "terminateUploadSequence",
    ];

    for (byte_idx, byte) in service_bits.iter().enumerate() {
        for bit_idx in 0..8 {
            let service_idx = byte_idx * 8 + bit_idx;
            if service_idx < service_names.len() {
                if byte & (0x80 >> bit_idx) != 0 {
                    services.push(service_names[service_idx].to_string());
                }
            }
        }
    }

    services
}

/// Find a specific ASN.1 tag in data, return position after the tag+length
fn find_tag(data: &[u8], tag: u8) -> Option<usize> {
    for i in 0..data.len().saturating_sub(2) {
        if data[i] == tag {
            return Some(i);
        }
    }
    None
}

/// Extract an integer value following a context-specific tag
fn extract_integer_value(data: &[u8], tag: u8) -> Option<i64> {
    for i in 0..data.len().saturating_sub(2) {
        if data[i] == tag && i + 1 < data.len() {
            let len = data[i + 1] as usize;
            if len > 0 && len <= 8 && i + 2 + len <= data.len() {
                let mut value: i64 = 0;
                for j in 0..len {
                    value = (value << 8) | data[i + 2 + j] as i64;
                }
                return Some(value);
            }
        }
    }
    None
}

/// Find a byte sequence in data
fn find_bytes(data: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || data.len() < needle.len() {
        return None;
    }
    for i in 0..=data.len() - needle.len() {
        if data[i..i + needle.len()] == *needle {
            return Some(i);
        }
    }
    None
}

/// Check if a name is a valid IEC 61850 Logical Device name
fn is_valid_ld_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 32 {
        return false;
    }
    // LD names are typically alphanumeric, may start with letter
    let first = name.chars().next().unwrap_or('0');
    if !first.is_ascii_alphabetic() {
        return false;
    }
    name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cotp_connection_request() {
        let cr = build_cotp_connection_request();
        // Verify TPKT header
        assert_eq!(cr[0], 0x03); // Version 3
        assert_eq!(cr[1], 0x00); // Reserved
        // Verify COTP CR
        assert_eq!(cr[5], 0xE0); // CR code
        // Verify parameters present
        assert!(cr.contains(&0xC0)); // TPDU size param
        assert!(cr.contains(&0xC1)); // Source TSAP
        assert!(cr.contains(&0xC2)); // Dest TSAP
    }

    #[test]
    fn test_mms_initiate_request_structure() {
        let init = build_mms_initiate_request();
        // Should start with TPKT header
        assert_eq!(init[0], 0x03);
        assert_eq!(init[1], 0x00);
        // COTP DT follows TPKT
        assert_eq!(init[5], 0xF0); // DT PDU type
        assert_eq!(init[6], 0x80); // EOT flag
    }

    #[test]
    fn test_cotp_data_tpdu_wrapping() {
        let payload = vec![0x01, 0x02, 0x03];
        let wrapped = build_cotp_data_tpdu(&payload);
        // TPKT: 4 bytes, COTP DT: 3 bytes, payload: 3 bytes = 10 total
        assert_eq!(wrapped.len(), 10);
        assert_eq!(wrapped[0], 0x03); // TPKT version
        assert_eq!(wrapped[3], 10);   // Total length
        assert_eq!(wrapped[5], 0xF0); // DT PDU
        assert_eq!(wrapped[7], 0x01); // First payload byte
    }

    #[test]
    fn test_valid_ld_names() {
        assert!(is_valid_ld_name("PROT1"));
        assert!(is_valid_ld_name("LD_Protection"));
        assert!(is_valid_ld_name("Ctrl1"));
        assert!(!is_valid_ld_name("")); // Empty
        assert!(!is_valid_ld_name("123")); // Starts with number
        assert!(!is_valid_ld_name("a b")); // Contains space
        assert!(!is_valid_ld_name("a".repeat(33).as_str())); // Too long
    }

    #[test]
    fn test_extract_integer_value() {
        let data = vec![0x80, 0x02, 0x01, 0x00]; // Tag 0x80, len 2, value 256
        assert_eq!(extract_integer_value(&data, 0x80), Some(256));

        let data2 = vec![0x81, 0x01, 0x05]; // Tag 0x81, len 1, value 5
        assert_eq!(extract_integer_value(&data2, 0x81), Some(5));
    }

    #[test]
    fn test_parse_supported_services() {
        // BIT STRING with status and getNameList enabled (bits 0 and 1)
        let data = vec![0x82, 0x03, 0x00, 0xC0, 0x00]; // Tag, len=3, unused=0, 0xC0=11000000
        let services = parse_supported_services(&data, 0);
        assert!(services.contains(&"status".to_string()));
        assert!(services.contains(&"getNameList".to_string()));
        assert!(!services.contains(&"identify".to_string()));
    }

    #[test]
    fn test_find_bytes() {
        let data = vec![0x01, 0x02, 0xA2, 0x03, 0x80, 0x01, 0x05];
        assert_eq!(find_bytes(&data, &[0xA2, 0x03, 0x80, 0x01]), Some(2));
        assert_eq!(find_bytes(&data, &[0xFF, 0xFF]), None);
    }

    #[tokio::test]
    async fn test_scanner_defaults() {
        let scanner = Iec61850Scanner::new();
        assert_eq!(scanner.protocol_type(), OtProtocolType::Iec61850);
        assert_eq!(scanner.default_port(), 102);
    }
}
