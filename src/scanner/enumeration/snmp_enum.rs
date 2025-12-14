//! SNMP enumeration module for SNMPv1/v2c services
//!
//! This module provides comprehensive SNMP enumeration including:
//! - Community string testing
//! - System information gathering (MIB-II)
//! - Network interface enumeration
//! - IP address and routing table extraction
//! - ARP table enumeration
//! - Active TCP/UDP connection enumeration

use super::types::{EnumDepth, EnumerationResult, Finding, FindingType, ServiceType};
use crate::types::{ScanProgressMessage, ScanTarget};
use anyhow::Result;
use log::{debug, info};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::path::PathBuf;
use std::time::{Duration, Instant};
use tokio::sync::broadcast::Sender;

/// SNMP version constants
const SNMP_VERSION_1: u8 = 0;
const SNMP_VERSION_2C: u8 = 1;

/// Light community string wordlist (embedded)
const SNMP_COMMUNITIES_LIGHT: &[&str] = &[
    "public",
    "private",
    "community",
    "snmp",
    "admin",
    "default",
];

/// Aggressive community string wordlist (embedded)
const SNMP_COMMUNITIES_AGGRESSIVE: &[&str] = &[
    "public",
    "private",
    "community",
    "snmp",
    "admin",
    "default",
    "cisco",
    "router",
    "switch",
    "monitor",
    "manager",
    "secret",
    "test",
    "guest",
    "read",
    "write",
    "readwrite",
    "cable-docsis",
    "internal",
    "ILMI",
    "netman",
    "freekevin",
    "apc",
    "snmpd",
    "0392a0",
    "all private",
    "all public",
    "network",
    "security",
    "system",
];

/// Key SNMP OIDs for system enumeration
const SYSTEM_OIDS: &[(&str, &str)] = &[
    ("1.3.6.1.2.1.1.1.0", "sysDescr"),
    ("1.3.6.1.2.1.1.2.0", "sysObjectID"),
    ("1.3.6.1.2.1.1.3.0", "sysUpTime"),
    ("1.3.6.1.2.1.1.4.0", "sysContact"),
    ("1.3.6.1.2.1.1.5.0", "sysName"),
    ("1.3.6.1.2.1.1.6.0", "sysLocation"),
    ("1.3.6.1.2.1.1.7.0", "sysServices"),
];

/// Interface table OID prefix
const IF_TABLE_OID: &str = "1.3.6.1.2.1.2.2.1";

/// IP address table OID prefix
const IP_ADDR_TABLE_OID: &str = "1.3.6.1.2.1.4.20.1";

/// IP route table OID prefix
const IP_ROUTE_TABLE_OID: &str = "1.3.6.1.2.1.4.21.1";

/// ARP table OID prefix
const ARP_TABLE_OID: &str = "1.3.6.1.2.1.4.22.1";

/// TCP connection table OID prefix
const TCP_CONN_TABLE_OID: &str = "1.3.6.1.2.1.6.13.1";

/// UDP listener table OID prefix
const UDP_TABLE_OID: &str = "1.3.6.1.2.1.7.5.1";

/// SNMP response data
#[derive(Debug)]
struct SnmpResponse {
    #[allow(dead_code)]
    version: u8,
    error_status: u8,
    varbinds: Vec<VarBind>,
}

/// Variable binding (OID-value pair)
#[derive(Debug)]
struct VarBind {
    oid: String,
    value: SnmpValue,
}

/// SNMP value types
#[derive(Debug)]
enum SnmpValue {
    Integer(i64),
    OctetString(Vec<u8>),
    ObjectId(String),
    IpAddress([u8; 4]),
    Counter(u64),
    Gauge(u32),
    TimeTicks(u32),
    Null,
    NoSuchObject,
    NoSuchInstance,
    EndOfMibView,
}

impl SnmpValue {
    fn as_string(&self) -> String {
        match self {
            SnmpValue::Integer(i) => i.to_string(),
            SnmpValue::OctetString(s) => {
                // Try UTF-8 first, fall back to hex
                String::from_utf8(s.clone())
                    .unwrap_or_else(|_| s.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(":"))
            }
            SnmpValue::ObjectId(oid) => oid.clone(),
            SnmpValue::IpAddress(ip) => format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]),
            SnmpValue::Counter(c) => c.to_string(),
            SnmpValue::Gauge(g) => g.to_string(),
            SnmpValue::TimeTicks(t) => {
                let secs = *t / 100;
                let days = secs / 86400;
                let hours = (secs % 86400) / 3600;
                let mins = (secs % 3600) / 60;
                format!("{}d {}h {}m", days, hours, mins)
            }
            SnmpValue::Null => "null".to_string(),
            SnmpValue::NoSuchObject => "noSuchObject".to_string(),
            SnmpValue::NoSuchInstance => "noSuchInstance".to_string(),
            SnmpValue::EndOfMibView => "endOfMibView".to_string(),
        }
    }
}

/// Main entry point for SNMP enumeration
pub async fn enumerate_snmp(
    target: &ScanTarget,
    port: u16,
    depth: EnumDepth,
    _wordlist_path: &Option<PathBuf>,
    timeout: Duration,
    progress_tx: Option<Sender<ScanProgressMessage>>,
) -> Result<EnumerationResult> {
    let start = Instant::now();
    info!(
        "Starting SNMP enumeration for {}:{} with depth: {:?}",
        target.ip, port, depth
    );

    let mut findings = Vec::new();
    let mut metadata = HashMap::new();
    let target_ip = target.ip;

    // Passive mode: Just return what we already know from service detection
    if matches!(depth, EnumDepth::Passive) {
        return Ok(EnumerationResult {
            service_type: ServiceType::Snmp,
            enumeration_depth: depth,
            findings,
            duration: start.elapsed(),
            metadata,
        });
    }

    // Get community wordlist based on depth
    let communities: Vec<String> = match depth {
        EnumDepth::Passive => vec![],
        EnumDepth::Light => SNMP_COMMUNITIES_LIGHT.iter().map(|s| s.to_string()).collect(),
        EnumDepth::Aggressive => SNMP_COMMUNITIES_AGGRESSIVE.iter().map(|s| s.to_string()).collect(),
    };

    // Step 1: Test community strings
    let valid_communities = test_community_strings(
        target_ip,
        port,
        &communities,
        timeout,
    ).await;

    if valid_communities.is_empty() {
        // No valid community strings found
        debug!("No valid SNMP community strings found for {}", target_ip);

        // Check if SNMPv3 might be required
        if check_snmpv3_required(target_ip, port, timeout).await {
            findings.push(
                Finding::with_confidence(
                    FindingType::SnmpV3Required,
                    "SNMP server may require SNMPv3 authentication".to_string(),
                    70,
                )
                .with_metadata("port".to_string(), port.to_string()),
            );
            metadata.insert("snmpv3_required".to_string(), "true".to_string());
        }

        return Ok(EnumerationResult {
            service_type: ServiceType::Snmp,
            enumeration_depth: depth,
            findings,
            duration: start.elapsed(),
            metadata,
        });
    }

    // Record valid community strings as findings
    for (community, version) in &valid_communities {
        let severity = if *community == "public" || *community == "private" {
            "High"
        } else if SNMP_COMMUNITIES_LIGHT.contains(&community.as_str()) {
            "Medium"
        } else {
            "Low"
        };

        findings.push(
            Finding::with_confidence(
                FindingType::SnmpCommunityString,
                format!("Community '{}' accepted (SNMPv{})", community, version + 1),
                95,
            )
            .with_metadata("community".to_string(), community.clone())
            .with_metadata("version".to_string(), format!("v{}", version + 1))
            .with_metadata("severity".to_string(), severity.to_string()),
        );

        send_progress(
            &progress_tx,
            &target_ip.to_string(),
            port,
            "SnmpCommunityString",
            &format!("Valid community: '{}'", community),
        );
    }

    metadata.insert(
        "valid_communities".to_string(),
        valid_communities.iter().map(|(c, _)| c.clone()).collect::<Vec<_>>().join(", "),
    );

    // Use first valid community for further enumeration
    let (community, version) = &valid_communities[0];

    // Step 2: Enumerate system information
    let system_findings = enumerate_system_info(
        target_ip, port, community, *version, timeout, &progress_tx,
    ).await;
    findings.extend(system_findings);

    // Step 3: Enumerate interfaces
    let interface_findings = enumerate_interfaces(
        target_ip, port, community, *version, timeout,
    ).await;
    findings.extend(interface_findings);

    // Step 4: Enumerate IP addresses
    let ip_findings = enumerate_ip_addresses(
        target_ip, port, community, *version, timeout,
    ).await;
    findings.extend(ip_findings);

    // Aggressive-only enumeration
    if matches!(depth, EnumDepth::Aggressive) {
        // Step 5: Enumerate routing table
        let route_findings = enumerate_routes(
            target_ip, port, community, *version, timeout,
        ).await;
        findings.extend(route_findings);

        // Step 6: Enumerate ARP table
        let arp_findings = enumerate_arp_table(
            target_ip, port, community, *version, timeout,
        ).await;
        findings.extend(arp_findings);

        // Step 7: Enumerate TCP connections
        let tcp_findings = enumerate_tcp_connections(
            target_ip, port, community, *version, timeout,
        ).await;
        findings.extend(tcp_findings);

        // Step 8: Enumerate UDP listeners
        let udp_findings = enumerate_udp_listeners(
            target_ip, port, community, *version, timeout,
        ).await;
        findings.extend(udp_findings);
    }

    metadata.insert("findings_count".to_string(), findings.len().to_string());

    info!(
        "SNMP enumeration for {}:{} completed with {} findings",
        target_ip, port, findings.len()
    );

    Ok(EnumerationResult {
        service_type: ServiceType::Snmp,
        enumeration_depth: depth,
        findings,
        duration: start.elapsed(),
        metadata,
    })
}

/// Test community strings and return valid ones with version
async fn test_community_strings(
    target: IpAddr,
    port: u16,
    communities: &[String],
    timeout: Duration,
) -> Vec<(String, u8)> {
    let mut valid = Vec::new();

    for community in communities {
        // Try SNMPv2c first, then v1
        for version in [SNMP_VERSION_2C, SNMP_VERSION_1] {
            let request = build_snmp_get_request(
                version,
                community,
                rand::random::<u32>(),
                &["1.3.6.1.2.1.1.1.0"], // sysDescr
            );

            if let Some(response) = send_snmp_request(target, port, &request, timeout).await {
                if let Some(parsed) = parse_snmp_response(&response) {
                    if parsed.error_status == 0 && !parsed.varbinds.is_empty() {
                        // Check for actual value (not noSuchObject)
                        let has_value = parsed.varbinds.iter().any(|vb| {
                            !matches!(vb.value, SnmpValue::NoSuchObject | SnmpValue::NoSuchInstance)
                        });
                        if has_value {
                            valid.push((community.clone(), version));
                            break; // Found working version, don't try v1
                        }
                    }
                }
            }
        }
    }

    valid
}

/// Check if SNMPv3 might be required (v1/v2c rejected)
async fn check_snmpv3_required(target: IpAddr, port: u16, timeout: Duration) -> bool {
    // Try to connect and see if we get any response at all
    let request = build_snmp_get_request(
        SNMP_VERSION_2C,
        "public",
        rand::random::<u32>(),
        &["1.3.6.1.2.1.1.1.0"],
    );

    if let Some(response) = send_snmp_request(target, port, &request, timeout).await {
        // Got a response - check if it's an error indicating auth required
        if let Some(parsed) = parse_snmp_response(&response) {
            // Error status 6 = authorization error in some implementations
            return parsed.error_status != 0;
        }
    }

    false
}

/// Enumerate system information
async fn enumerate_system_info(
    target: IpAddr,
    port: u16,
    community: &str,
    version: u8,
    timeout: Duration,
    progress_tx: &Option<Sender<ScanProgressMessage>>,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    for (oid, name) in SYSTEM_OIDS {
        let request = build_snmp_get_request(version, community, rand::random(), &[*oid]);

        if let Some(response) = send_snmp_request(target, port, &request, timeout).await {
            if let Some(parsed) = parse_snmp_response(&response) {
                if parsed.error_status == 0 {
                    for varbind in parsed.varbinds {
                        if !matches!(varbind.value, SnmpValue::NoSuchObject | SnmpValue::NoSuchInstance | SnmpValue::Null) {
                            let value_str = varbind.value.as_string();
                            if !value_str.is_empty() {
                                findings.push(
                                    Finding::new(
                                        FindingType::SnmpSystemInfo,
                                        format!("{}: {}", name, value_str),
                                    )
                                    .with_metadata("oid".to_string(), oid.to_string())
                                    .with_metadata("name".to_string(), name.to_string())
                                    .with_metadata("value".to_string(), value_str.clone()),
                                );

                                // Check for sensitive information disclosure
                                if *name == "sysDescr" {
                                    check_sensitive_info(&value_str, &mut findings);
                                }

                                send_progress(
                                    progress_tx,
                                    &target.to_string(),
                                    port,
                                    "SnmpSystemInfo",
                                    &format!("{}: {}", name, &value_str[..value_str.len().min(50)]),
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    findings
}

/// Check for sensitive information in sysDescr
fn check_sensitive_info(sys_descr: &str, findings: &mut Vec<Finding>) {
    let lower = sys_descr.to_lowercase();

    // Check for OS version disclosure
    let os_indicators = [
        ("linux", "Linux"),
        ("windows", "Windows"),
        ("cisco ios", "Cisco IOS"),
        ("junos", "JunOS"),
        ("freebsd", "FreeBSD"),
        ("ubuntu", "Ubuntu"),
        ("centos", "CentOS"),
        ("debian", "Debian"),
    ];

    for (indicator, os_name) in os_indicators {
        if lower.contains(indicator) {
            findings.push(
                Finding::with_confidence(
                    FindingType::InformationDisclosure,
                    format!("{} OS information disclosed via SNMP", os_name),
                    85,
                )
                .with_metadata("type".to_string(), "os_disclosure".to_string())
                .with_metadata("os".to_string(), os_name.to_string()),
            );
            break;
        }
    }

    // Check for version disclosure
    if lower.contains("version") || lower.contains("ver.") || lower.contains(" v") {
        findings.push(
            Finding::with_confidence(
                FindingType::InformationDisclosure,
                "Software version information disclosed via SNMP".to_string(),
                75,
            )
            .with_metadata("type".to_string(), "version_disclosure".to_string()),
        );
    }
}

/// Enumerate network interfaces
async fn enumerate_interfaces(
    target: IpAddr,
    port: u16,
    community: &str,
    version: u8,
    timeout: Duration,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Get number of interfaces first
    let request = build_snmp_get_request(version, community, rand::random(), &["1.3.6.1.2.1.2.1.0"]);
    let _if_count = if let Some(response) = send_snmp_request(target, port, &request, timeout).await {
        if let Some(parsed) = parse_snmp_response(&response) {
            if let Some(vb) = parsed.varbinds.first() {
                if let SnmpValue::Integer(n) = vb.value {
                    n as usize
                } else {
                    0
                }
            } else {
                0
            }
        } else {
            0
        }
    } else {
        0
    };

    // Walk interface descriptions
    let mut interfaces = Vec::new();
    let mut current_oid = format!("{}.2", IF_TABLE_OID); // ifDescr

    for _ in 0..50 {
        // Limit to 50 interfaces
        let request = build_snmp_getnext_request(version, community, rand::random(), &current_oid);

        if let Some(response) = send_snmp_request(target, port, &request, timeout).await {
            if let Some(parsed) = parse_snmp_response(&response) {
                if parsed.error_status != 0 || parsed.varbinds.is_empty() {
                    break;
                }

                let varbind = &parsed.varbinds[0];

                // Check if still in ifDescr subtree
                if !varbind.oid.starts_with(&format!("{}.2.", IF_TABLE_OID)) {
                    break;
                }

                if let SnmpValue::EndOfMibView = varbind.value {
                    break;
                }

                interfaces.push(varbind.value.as_string());
                current_oid = varbind.oid.clone();
            } else {
                break;
            }
        } else {
            break;
        }
    }

    for (idx, iface) in interfaces.iter().enumerate() {
        findings.push(
            Finding::new(
                FindingType::SnmpInterface,
                format!("Interface {}: {}", idx + 1, iface),
            )
            .with_metadata("index".to_string(), (idx + 1).to_string())
            .with_metadata("description".to_string(), iface.clone()),
        );
    }

    findings
}

/// Enumerate IP addresses
async fn enumerate_ip_addresses(
    target: IpAddr,
    port: u16,
    community: &str,
    version: u8,
    timeout: Duration,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut current_oid = format!("{}.1", IP_ADDR_TABLE_OID); // ipAdEntAddr

    for _ in 0..100 {
        let request = build_snmp_getnext_request(version, community, rand::random(), &current_oid);

        if let Some(response) = send_snmp_request(target, port, &request, timeout).await {
            if let Some(parsed) = parse_snmp_response(&response) {
                if parsed.error_status != 0 || parsed.varbinds.is_empty() {
                    break;
                }

                let varbind = &parsed.varbinds[0];

                if !varbind.oid.starts_with(&format!("{}.1.", IP_ADDR_TABLE_OID)) {
                    break;
                }

                if let SnmpValue::EndOfMibView = varbind.value {
                    break;
                }

                if let SnmpValue::IpAddress(ip) = varbind.value {
                    let ip_str = format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]);
                    findings.push(
                        Finding::new(
                            FindingType::SnmpIpAddress,
                            format!("IP Address: {}", ip_str),
                        )
                        .with_metadata("address".to_string(), ip_str),
                    );
                }

                current_oid = varbind.oid.clone();
            } else {
                break;
            }
        } else {
            break;
        }
    }

    findings
}

/// Enumerate routing table (aggressive mode)
async fn enumerate_routes(
    target: IpAddr,
    port: u16,
    community: &str,
    version: u8,
    timeout: Duration,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut current_oid = format!("{}.1", IP_ROUTE_TABLE_OID); // ipRouteDest

    for _ in 0..200 {
        let request = build_snmp_getnext_request(version, community, rand::random(), &current_oid);

        if let Some(response) = send_snmp_request(target, port, &request, timeout).await {
            if let Some(parsed) = parse_snmp_response(&response) {
                if parsed.error_status != 0 || parsed.varbinds.is_empty() {
                    break;
                }

                let varbind = &parsed.varbinds[0];

                if !varbind.oid.starts_with(&format!("{}.1.", IP_ROUTE_TABLE_OID)) {
                    break;
                }

                if let SnmpValue::EndOfMibView = varbind.value {
                    break;
                }

                if let SnmpValue::IpAddress(ip) = varbind.value {
                    let dest = format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]);
                    findings.push(
                        Finding::new(
                            FindingType::SnmpRoute,
                            format!("Route destination: {}", dest),
                        )
                        .with_metadata("destination".to_string(), dest),
                    );
                }

                current_oid = varbind.oid.clone();
            } else {
                break;
            }
        } else {
            break;
        }
    }

    if !findings.is_empty() {
        findings.insert(
            0,
            Finding::with_confidence(
                FindingType::InformationDisclosure,
                format!("Routing table exposed ({} routes)", findings.len()),
                80,
            )
            .with_metadata("type".to_string(), "network_topology".to_string()),
        );
    }

    findings
}

/// Enumerate ARP table (aggressive mode)
async fn enumerate_arp_table(
    target: IpAddr,
    port: u16,
    community: &str,
    version: u8,
    timeout: Duration,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut current_oid = format!("{}.3", ARP_TABLE_OID); // ipNetToMediaNetAddress

    for _ in 0..500 {
        let request = build_snmp_getnext_request(version, community, rand::random(), &current_oid);

        if let Some(response) = send_snmp_request(target, port, &request, timeout).await {
            if let Some(parsed) = parse_snmp_response(&response) {
                if parsed.error_status != 0 || parsed.varbinds.is_empty() {
                    break;
                }

                let varbind = &parsed.varbinds[0];

                if !varbind.oid.starts_with(&format!("{}.3.", ARP_TABLE_OID)) {
                    break;
                }

                if let SnmpValue::EndOfMibView = varbind.value {
                    break;
                }

                if let SnmpValue::IpAddress(ip) = varbind.value {
                    let ip_str = format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]);
                    findings.push(
                        Finding::new(
                            FindingType::SnmpArpEntry,
                            format!("ARP entry: {}", ip_str),
                        )
                        .with_metadata("ip".to_string(), ip_str),
                    );
                }

                current_oid = varbind.oid.clone();
            } else {
                break;
            }
        } else {
            break;
        }
    }

    if !findings.is_empty() {
        findings.insert(
            0,
            Finding::with_confidence(
                FindingType::InformationDisclosure,
                format!("ARP table exposed ({} entries)", findings.len()),
                75,
            )
            .with_metadata("type".to_string(), "network_hosts".to_string()),
        );
    }

    findings
}

/// Enumerate TCP connections (aggressive mode)
async fn enumerate_tcp_connections(
    target: IpAddr,
    port: u16,
    community: &str,
    version: u8,
    timeout: Duration,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut current_oid = format!("{}.1", TCP_CONN_TABLE_OID); // tcpConnState

    for _ in 0..200 {
        let request = build_snmp_getnext_request(version, community, rand::random(), &current_oid);

        if let Some(response) = send_snmp_request(target, port, &request, timeout).await {
            if let Some(parsed) = parse_snmp_response(&response) {
                if parsed.error_status != 0 || parsed.varbinds.is_empty() {
                    break;
                }

                let varbind = &parsed.varbinds[0];

                if !varbind.oid.starts_with(&format!("{}.1.", TCP_CONN_TABLE_OID)) {
                    break;
                }

                if let SnmpValue::EndOfMibView = varbind.value {
                    break;
                }

                // Extract connection info from OID (tcpConnState.localIP.localPort.remoteIP.remotePort)
                let parts: Vec<&str> = varbind.oid.split('.').collect();
                if parts.len() >= 13 {
                    let state = match &varbind.value {
                        SnmpValue::Integer(s) => match *s {
                            1 => "closed",
                            2 => "listen",
                            3 => "synSent",
                            4 => "synReceived",
                            5 => "established",
                            6 => "finWait1",
                            7 => "finWait2",
                            8 => "closeWait",
                            9 => "lastAck",
                            10 => "closing",
                            11 => "timeWait",
                            _ => "unknown",
                        },
                        _ => "unknown",
                    };

                    if state == "established" || state == "listen" {
                        findings.push(
                            Finding::new(
                                FindingType::SnmpTcpConnection,
                                format!("TCP connection state: {}", state),
                            )
                            .with_metadata("state".to_string(), state.to_string()),
                        );
                    }
                }

                current_oid = varbind.oid.clone();
            } else {
                break;
            }
        } else {
            break;
        }
    }

    findings
}

/// Enumerate UDP listeners (aggressive mode)
async fn enumerate_udp_listeners(
    target: IpAddr,
    port: u16,
    community: &str,
    version: u8,
    timeout: Duration,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut current_oid = format!("{}.1", UDP_TABLE_OID); // udpLocalAddress

    for _ in 0..100 {
        let request = build_snmp_getnext_request(version, community, rand::random(), &current_oid);

        if let Some(response) = send_snmp_request(target, port, &request, timeout).await {
            if let Some(parsed) = parse_snmp_response(&response) {
                if parsed.error_status != 0 || parsed.varbinds.is_empty() {
                    break;
                }

                let varbind = &parsed.varbinds[0];

                if !varbind.oid.starts_with(&format!("{}.1.", UDP_TABLE_OID)) {
                    break;
                }

                if let SnmpValue::EndOfMibView = varbind.value {
                    break;
                }

                if let SnmpValue::IpAddress(ip) = varbind.value {
                    let ip_str = format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]);
                    // Extract port from OID
                    let parts: Vec<&str> = varbind.oid.split('.').collect();
                    if let Some(udp_port) = parts.last().and_then(|p| p.parse::<u16>().ok()) {
                        findings.push(
                            Finding::new(
                                FindingType::SnmpUdpListener,
                                format!("UDP listener: {}:{}", ip_str, udp_port),
                            )
                            .with_metadata("address".to_string(), ip_str)
                            .with_metadata("port".to_string(), udp_port.to_string()),
                        );
                    }
                }

                current_oid = varbind.oid.clone();
            } else {
                break;
            }
        } else {
            break;
        }
    }

    findings
}

// ============================================================================
// SNMP Packet Construction and Parsing
// ============================================================================

/// Build an SNMP GetRequest packet
fn build_snmp_get_request(
    version: u8,
    community: &str,
    request_id: u32,
    oids: &[&str],
) -> Vec<u8> {
    build_snmp_request(version, community, request_id, oids, 0xA0) // GetRequest PDU tag
}

/// Build an SNMP GetNextRequest packet
fn build_snmp_getnext_request(
    version: u8,
    community: &str,
    request_id: u32,
    oid: &str,
) -> Vec<u8> {
    build_snmp_request(version, community, request_id, &[oid], 0xA1) // GetNextRequest PDU tag
}

/// Build SNMP request with specified PDU type
fn build_snmp_request(
    version: u8,
    community: &str,
    request_id: u32,
    oids: &[&str],
    pdu_tag: u8,
) -> Vec<u8> {
    let mut packet = Vec::new();

    // Build variable bindings
    let mut varbinds = Vec::new();
    for oid in oids {
        let oid_bytes = encode_oid(oid);
        let mut varbind = Vec::new();
        // OID
        varbind.push(0x06); // OBJECT IDENTIFIER tag
        encode_length_into(&mut varbind, oid_bytes.len());
        varbind.extend(&oid_bytes);
        // NULL value for request
        varbind.extend(&[0x05, 0x00]);

        // Wrap in SEQUENCE
        let mut varbind_seq = vec![0x30];
        encode_length_into(&mut varbind_seq, varbind.len());
        varbind_seq.extend(varbind);

        varbinds.extend(varbind_seq);
    }

    // Wrap varbinds in SEQUENCE
    let mut varbind_list = vec![0x30];
    encode_length_into(&mut varbind_list, varbinds.len());
    varbind_list.extend(varbinds);

    // Build PDU
    let mut pdu = Vec::new();
    // Request ID (INTEGER)
    pdu.push(0x02); // INTEGER tag
    let id_bytes = request_id.to_be_bytes();
    // Find first non-zero byte or use last byte
    let start = id_bytes.iter().position(|&b| b != 0).unwrap_or(3);
    let id_slice = &id_bytes[start..];
    pdu.push(id_slice.len() as u8);
    pdu.extend(id_slice);

    // Error status (INTEGER 0)
    pdu.extend(&[0x02, 0x01, 0x00]);
    // Error index (INTEGER 0)
    pdu.extend(&[0x02, 0x01, 0x00]);
    // Variable bindings
    pdu.extend(varbind_list);

    // Wrap PDU in GetRequest/GetNextRequest
    let mut pdu_wrapper = vec![pdu_tag];
    encode_length_into(&mut pdu_wrapper, pdu.len());
    pdu_wrapper.extend(pdu);

    // Build message
    let mut message = Vec::new();
    // Version (INTEGER)
    message.extend(&[0x02, 0x01, version]);
    // Community (OCTET STRING)
    message.push(0x04);
    encode_length_into(&mut message, community.len());
    message.extend(community.as_bytes());
    // PDU
    message.extend(pdu_wrapper);

    // Wrap in SEQUENCE
    packet.push(0x30);
    encode_length_into(&mut packet, message.len());
    packet.extend(message);

    packet
}

/// Encode OID string to bytes
fn encode_oid(oid: &str) -> Vec<u8> {
    let parts: Vec<u32> = oid
        .split('.')
        .filter(|s| !s.is_empty())
        .filter_map(|s| s.parse().ok())
        .collect();

    if parts.len() < 2 {
        return vec![];
    }

    let mut bytes = Vec::new();
    // First two components encoded as: first * 40 + second
    bytes.push((parts[0] * 40 + parts[1]) as u8);

    // Remaining components use variable-length encoding
    for &val in &parts[2..] {
        encode_oid_component(&mut bytes, val);
    }

    bytes
}

/// Encode a single OID component (variable-length integer)
fn encode_oid_component(bytes: &mut Vec<u8>, mut val: u32) {
    if val == 0 {
        bytes.push(0);
        return;
    }

    let mut temp = Vec::new();
    while val > 0 {
        temp.push((val & 0x7F) as u8);
        val >>= 7;
    }

    for (i, &b) in temp.iter().rev().enumerate() {
        if i == temp.len() - 1 {
            bytes.push(b);
        } else {
            bytes.push(b | 0x80);
        }
    }
}

/// Encode ASN.1 length into buffer
fn encode_length_into(buffer: &mut Vec<u8>, len: usize) {
    if len < 128 {
        buffer.push(len as u8);
    } else if len < 256 {
        buffer.push(0x81);
        buffer.push(len as u8);
    } else {
        buffer.push(0x82);
        buffer.push((len >> 8) as u8);
        buffer.push(len as u8);
    }
}

/// Send SNMP request and receive response
async fn send_snmp_request(
    target: IpAddr,
    port: u16,
    request: &[u8],
    timeout: Duration,
) -> Option<Vec<u8>> {
    tokio::task::spawn_blocking({
        let request = request.to_vec();
        let addr = SocketAddr::new(target, port);

        move || {
            let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
            socket.set_read_timeout(Some(timeout)).ok()?;
            socket.set_write_timeout(Some(timeout)).ok()?;

            socket.send_to(&request, addr).ok()?;

            let mut buf = vec![0u8; 65535];
            let (len, _) = socket.recv_from(&mut buf).ok()?;

            Some(buf[..len].to_vec())
        }
    })
    .await
    .ok()?
}

/// Parse SNMP response
fn parse_snmp_response(data: &[u8]) -> Option<SnmpResponse> {
    if data.len() < 10 || data[0] != 0x30 {
        return None;
    }

    let mut pos = 1;

    // Decode message length
    let (_msg_len, len_bytes) = decode_length(&data[pos..])?;
    pos += len_bytes;

    // Parse version
    if pos + 3 > data.len() || data[pos] != 0x02 {
        return None;
    }
    pos += 1;
    let ver_len = data[pos] as usize;
    pos += 1;
    let version = data[pos];
    pos += ver_len;

    // Parse community string
    if pos + 2 > data.len() || data[pos] != 0x04 {
        return None;
    }
    pos += 1;
    let (comm_len, comm_len_bytes) = decode_length(&data[pos..])?;
    pos += comm_len_bytes;
    pos += comm_len; // Skip community string

    // Parse PDU
    if pos >= data.len() {
        return None;
    }
    let pdu_type = data[pos];

    // Check for GetResponse (0xA2)
    if pdu_type != 0xA2 {
        return None;
    }
    pos += 1;

    // Skip PDU length
    let (_pdu_len, pdu_len_bytes) = decode_length(&data[pos..])?;
    pos += pdu_len_bytes;

    // Parse request-id
    if pos + 2 > data.len() || data[pos] != 0x02 {
        return None;
    }
    pos += 1;
    let (id_len, id_len_bytes) = decode_length(&data[pos..])?;
    pos += id_len_bytes + id_len;

    // Parse error-status
    if pos + 3 > data.len() || data[pos] != 0x02 {
        return None;
    }
    pos += 1;
    let err_len = data[pos] as usize;
    pos += 1;
    let error_status = data[pos];
    pos += err_len;

    // Parse error-index
    if pos + 3 > data.len() || data[pos] != 0x02 {
        return None;
    }
    pos += 1;
    let idx_len = data[pos] as usize;
    pos += 1 + idx_len;

    // Parse variable bindings
    if pos >= data.len() || data[pos] != 0x30 {
        return None;
    }

    let varbinds = parse_varbinds(&data[pos..])?;

    Some(SnmpResponse {
        version,
        error_status,
        varbinds,
    })
}

/// Decode ASN.1 length
fn decode_length(data: &[u8]) -> Option<(usize, usize)> {
    if data.is_empty() {
        return None;
    }

    if data[0] & 0x80 == 0 {
        // Short form
        Some((data[0] as usize, 1))
    } else {
        // Long form
        let num_bytes = (data[0] & 0x7F) as usize;
        if num_bytes == 0 || data.len() < 1 + num_bytes {
            return None;
        }

        let mut len = 0usize;
        for i in 0..num_bytes {
            len = (len << 8) | (data[1 + i] as usize);
        }

        Some((len, 1 + num_bytes))
    }
}

/// Parse variable bindings list
fn parse_varbinds(data: &[u8]) -> Option<Vec<VarBind>> {
    if data.is_empty() || data[0] != 0x30 {
        return None;
    }

    let mut pos = 1;
    let (list_len, len_bytes) = decode_length(&data[pos..])?;
    pos += len_bytes;

    let end = pos + list_len;
    let mut varbinds = Vec::new();

    while pos < end && pos < data.len() {
        if data[pos] != 0x30 {
            break;
        }
        pos += 1;

        let (vb_len, vb_len_bytes) = decode_length(&data[pos..])?;
        pos += vb_len_bytes;

        let vb_end = pos + vb_len;

        // Parse OID
        if pos >= data.len() || data[pos] != 0x06 {
            break;
        }
        pos += 1;

        let (oid_len, oid_len_bytes) = decode_length(&data[pos..])?;
        pos += oid_len_bytes;

        let oid_bytes = &data[pos..pos + oid_len.min(data.len() - pos)];
        let oid = decode_oid(oid_bytes);
        pos += oid_len;

        // Parse value
        if pos >= data.len() {
            break;
        }

        let value = parse_snmp_value(&data[pos..vb_end.min(data.len())])?;
        pos = vb_end;

        varbinds.push(VarBind { oid, value });
    }

    Some(varbinds)
}

/// Parse SNMP value
fn parse_snmp_value(data: &[u8]) -> Option<SnmpValue> {
    if data.is_empty() {
        return None;
    }

    let tag = data[0];
    if data.len() < 2 {
        return Some(SnmpValue::Null);
    }

    let (len, len_bytes) = decode_length(&data[1..])?;
    let value_start = 1 + len_bytes;
    let value_data = &data[value_start..value_start + len.min(data.len() - value_start)];

    match tag {
        0x02 => {
            // INTEGER
            let mut val: i64 = 0;
            for &b in value_data {
                val = (val << 8) | (b as i64);
            }
            // Handle sign extension for negative numbers
            if !value_data.is_empty() && value_data[0] & 0x80 != 0 {
                let shift = (8 - value_data.len()) * 8;
                val = (val << shift) >> shift;
            }
            Some(SnmpValue::Integer(val))
        }
        0x04 => {
            // OCTET STRING
            Some(SnmpValue::OctetString(value_data.to_vec()))
        }
        0x05 => {
            // NULL
            Some(SnmpValue::Null)
        }
        0x06 => {
            // OBJECT IDENTIFIER
            Some(SnmpValue::ObjectId(decode_oid(value_data)))
        }
        0x40 => {
            // IpAddress (APPLICATION 0)
            if value_data.len() >= 4 {
                Some(SnmpValue::IpAddress([
                    value_data[0],
                    value_data[1],
                    value_data[2],
                    value_data[3],
                ]))
            } else {
                Some(SnmpValue::Null)
            }
        }
        0x41 => {
            // Counter (APPLICATION 1)
            let mut val: u64 = 0;
            for &b in value_data {
                val = (val << 8) | (b as u64);
            }
            Some(SnmpValue::Counter(val))
        }
        0x42 => {
            // Gauge (APPLICATION 2)
            let mut val: u32 = 0;
            for &b in value_data {
                val = (val << 8) | (b as u32);
            }
            Some(SnmpValue::Gauge(val))
        }
        0x43 => {
            // TimeTicks (APPLICATION 3)
            let mut val: u32 = 0;
            for &b in value_data {
                val = (val << 8) | (b as u32);
            }
            Some(SnmpValue::TimeTicks(val))
        }
        0x80 => {
            // noSuchObject (context 0)
            Some(SnmpValue::NoSuchObject)
        }
        0x81 => {
            // noSuchInstance (context 1)
            Some(SnmpValue::NoSuchInstance)
        }
        0x82 => {
            // endOfMibView (context 2)
            Some(SnmpValue::EndOfMibView)
        }
        _ => Some(SnmpValue::Null),
    }
}

/// Decode OID bytes to string
fn decode_oid(data: &[u8]) -> String {
    if data.is_empty() {
        return String::new();
    }

    let mut parts = Vec::new();

    // First byte encodes first two components
    let first = data[0] as u32;
    parts.push(first / 40);
    parts.push(first % 40);

    // Remaining bytes use variable-length encoding
    let mut val: u32 = 0;
    for &b in &data[1..] {
        val = (val << 7) | ((b & 0x7F) as u32);
        if b & 0x80 == 0 {
            parts.push(val);
            val = 0;
        }
    }

    parts
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(".")
}

/// Send progress update
fn send_progress(
    tx: &Option<Sender<ScanProgressMessage>>,
    ip: &str,
    port: u16,
    finding_type: &str,
    value: &str,
) {
    if let Some(sender) = tx {
        let _ = sender.send(ScanProgressMessage::EnumerationFinding {
            ip: ip.to_string(),
            port,
            finding_type: finding_type.to_string(),
            value: value.to_string(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_oid() {
        // Test sysDescr OID: 1.3.6.1.2.1.1.1.0
        let encoded = encode_oid("1.3.6.1.2.1.1.1.0");
        assert_eq!(
            encoded,
            vec![0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00]
        );
    }

    #[test]
    fn test_decode_oid() {
        let oid_bytes = vec![0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00];
        let decoded = decode_oid(&oid_bytes);
        assert_eq!(decoded, "1.3.6.1.2.1.1.1.0");
    }

    #[test]
    fn test_encode_oid_large_component() {
        // Test OID with component > 127: 1.3.6.1.4.1.9.2.1.56.0 (Cisco)
        let encoded = encode_oid("1.3.6.1.4.1.9.2.1.56.0");
        let decoded = decode_oid(&encoded);
        assert_eq!(decoded, "1.3.6.1.4.1.9.2.1.56.0");
    }

    #[test]
    fn test_build_get_request() {
        let request = build_snmp_get_request(0, "public", 1, &["1.3.6.1.2.1.1.1.0"]);
        assert_eq!(request[0], 0x30); // SEQUENCE
        // Check that "public" is in the packet
        let public_bytes = b"public";
        assert!(request
            .windows(public_bytes.len())
            .any(|w| w == public_bytes));
    }

    #[test]
    fn test_decode_length_short() {
        let data = vec![50];
        let (len, bytes) = decode_length(&data).unwrap();
        assert_eq!(len, 50);
        assert_eq!(bytes, 1);
    }

    #[test]
    fn test_decode_length_long() {
        let data = vec![0x81, 200];
        let (len, bytes) = decode_length(&data).unwrap();
        assert_eq!(len, 200);
        assert_eq!(bytes, 2);
    }

    #[test]
    fn test_snmp_value_as_string() {
        assert_eq!(SnmpValue::Integer(42).as_string(), "42");
        assert_eq!(
            SnmpValue::IpAddress([192, 168, 1, 1]).as_string(),
            "192.168.1.1"
        );
        assert_eq!(
            SnmpValue::OctetString(b"test".to_vec()).as_string(),
            "test"
        );
    }
}
