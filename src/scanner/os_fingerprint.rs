use anyhow::Result;
use crate::types::{OsInfo, PortInfo, PortState, ScanConfig, ScanTarget};
use log::{debug, info};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// OS fingerprint data collected from network probes
#[derive(Debug, Default)]
struct OsFingerprintData {
    ttl: Option<u8>,
    tcp_window_size: Option<u16>,
    tcp_options: Vec<String>,
    banner_hints: Vec<String>,
}

pub async fn fingerprint_os(
    target: &ScanTarget,
    ports: &[PortInfo],
    config: &ScanConfig,
) -> Result<Option<OsInfo>, anyhow::Error> {
    debug!("Attempting OS fingerprinting for {}", target.ip);

    let mut fingerprint_data = OsFingerprintData::default();

    // 1. Get TTL from ICMP ping or TCP connection
    let timeout_ms = config.timeout.as_millis() as u64;
    if let Some(ttl) = get_ttl_from_tcp(&target.ip, ports, timeout_ms).await {
        fingerprint_data.ttl = Some(ttl);
        debug!("Got TTL: {} from {}", ttl, target.ip);
    }

    // 2. Get TCP characteristics from open ports
    if let Some(tcp_info) = get_tcp_characteristics(&target.ip, ports, timeout_ms).await {
        fingerprint_data.tcp_window_size = tcp_info.0;
        fingerprint_data.tcp_options = tcp_info.1;
    }

    // 3. Extract hints from service banners
    fingerprint_data.banner_hints = extract_banner_hints(ports);

    // 4. Combine all signals for OS detection
    let os_guess = analyze_fingerprint(&fingerprint_data, ports);

    if let Some(ref os) = os_guess {
        info!("OS fingerprint for {}: {} ({} confidence)",
            target.ip, os.os_family,
            os.confidence
        );
    }

    Ok(os_guess)
}

/// Get TTL value by establishing a TCP connection to an open port
/// This is more reliable than ICMP which may be blocked
async fn get_ttl_from_tcp(ip: &IpAddr, ports: &[PortInfo], timeout_ms: u64) -> Option<u8> {
    // Find an open port to connect to
    let open_port = ports.iter()
        .find(|p| p.state == PortState::Open)
        .map(|p| p.port)?;

    let addr = SocketAddr::new(*ip, open_port);
    let timeout = Duration::from_millis(timeout_ms);

    // Try to get TTL from socket options after connecting
    match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
        Ok(Ok(stream)) => {
            // Get the underlying socket and extract TTL
            // Note: This requires the socket2 crate for proper TTL access
            if let Ok(std_stream) = stream.into_std() {
                let socket = socket2::Socket::from(std_stream);
                // The TTL we receive is the peer's remaining TTL
                // We need to infer the original TTL
                if let Ok(ttl) = socket.ttl() {
                    return Some(ttl as u8);
                }
            }
            None
        }
        _ => None,
    }
}

/// Get TCP characteristics from SYN-ACK response
async fn get_tcp_characteristics(
    ip: &IpAddr,
    ports: &[PortInfo],
    timeout_ms: u64
) -> Option<(Option<u16>, Vec<String>)> {
    // Find an open port
    let open_port = ports.iter()
        .find(|p| p.state == PortState::Open)
        .map(|p| p.port)?;

    let addr = SocketAddr::new(*ip, open_port);
    let timeout = Duration::from_millis(timeout_ms);

    match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
        Ok(Ok(stream)) => {
            // Try to get socket info - window size requires raw sockets for accurate reading
            // For now, we can't easily get window size from userspace
            // Mark as None but keep the structure for future enhancement
            let _ = stream;
            Some((None, vec![]))
        }
        _ => None,
    }
}

/// Extract OS hints from service banners
fn extract_banner_hints(ports: &[PortInfo]) -> Vec<String> {
    let mut hints = Vec::new();

    for port in ports {
        if let Some(ref service) = port.service {
            if let Some(ref banner) = service.banner {
                let banner_lower = banner.to_lowercase();

                // SSH banners often contain OS info
                if banner_lower.contains("ubuntu") {
                    hints.push("Ubuntu".to_string());
                } else if banner_lower.contains("debian") {
                    hints.push("Debian".to_string());
                } else if banner_lower.contains("red hat") || banner_lower.contains("rhel") {
                    hints.push("Red Hat".to_string());
                } else if banner_lower.contains("centos") {
                    hints.push("CentOS".to_string());
                } else if banner_lower.contains("fedora") {
                    hints.push("Fedora".to_string());
                } else if banner_lower.contains("openssh") {
                    // OpenSSH version can hint at OS
                    if banner_lower.contains("freebsd") {
                        hints.push("FreeBSD".to_string());
                    }
                }

                // Windows-specific banners
                if banner_lower.contains("microsoft") || banner_lower.contains("windows") {
                    hints.push("Windows".to_string());
                }

                // Web server hints
                if banner_lower.contains("iis") {
                    hints.push("Windows IIS".to_string());
                }
                if banner_lower.contains("apache") {
                    if banner_lower.contains("win32") || banner_lower.contains("win64") {
                        hints.push("Windows Apache".to_string());
                    } else {
                        hints.push("Linux/Unix Apache".to_string());
                    }
                }

                // Version strings in banners
                if let Some(ref version) = service.version {
                    let version_lower = version.to_lowercase();
                    if version_lower.contains("windows") {
                        hints.push("Windows".to_string());
                    }
                }
            }
        }
    }

    hints
}

/// Analyze fingerprint data and port info to determine OS
fn analyze_fingerprint(data: &OsFingerprintData, ports: &[PortInfo]) -> Option<OsInfo> {
    let mut scores: std::collections::HashMap<&str, i32> = std::collections::HashMap::new();
    let mut total_signals = 0;

    // TTL-based detection (most reliable)
    if let Some(ttl) = data.ttl {
        total_signals += 1;
        let inferred_ttl = infer_initial_ttl(ttl);

        match inferred_ttl {
            128 => {
                *scores.entry("Windows").or_insert(0) += 30;
            }
            64 => {
                *scores.entry("Linux").or_insert(0) += 25;
                *scores.entry("macOS").or_insert(0) += 10;
                *scores.entry("FreeBSD").or_insert(0) += 10;
            }
            255 => {
                *scores.entry("Cisco").or_insert(0) += 25;
                *scores.entry("Solaris").or_insert(0) += 20;
                *scores.entry("Network Device").or_insert(0) += 15;
            }
            32 => {
                *scores.entry("Windows 95/98").or_insert(0) += 20;
            }
            _ => {}
        }
    }

    // Banner-based hints
    for hint in &data.banner_hints {
        total_signals += 1;
        let hint_lower = hint.to_lowercase();
        if hint_lower.contains("ubuntu") || hint_lower.contains("debian") ||
           hint_lower.contains("centos") || hint_lower.contains("red hat") ||
           hint_lower.contains("fedora") {
            *scores.entry("Linux").or_insert(0) += 20;
        } else if hint_lower.contains("windows") || hint_lower.contains("iis") {
            *scores.entry("Windows").or_insert(0) += 20;
        } else if hint_lower.contains("freebsd") {
            *scores.entry("FreeBSD").or_insert(0) += 20;
        }
    }

    // Port-based detection
    let open_ports: Vec<u16> = ports.iter()
        .filter(|p| p.state == PortState::Open)
        .map(|p| p.port)
        .collect();

    total_signals += 1;

    // Windows indicators
    if open_ports.contains(&445) { *scores.entry("Windows").or_insert(0) += 15; }
    if open_ports.contains(&3389) { *scores.entry("Windows").or_insert(0) += 15; }
    if open_ports.contains(&5985) || open_ports.contains(&5986) {
        *scores.entry("Windows").or_insert(0) += 10;
    }
    if open_ports.contains(&1433) { *scores.entry("Windows").or_insert(0) += 10; }
    if open_ports.contains(&135) { *scores.entry("Windows").or_insert(0) += 10; }

    // Linux indicators
    if open_ports.contains(&22) { *scores.entry("Linux").or_insert(0) += 5; }
    if open_ports.contains(&111) { *scores.entry("Linux").or_insert(0) += 10; } // rpcbind
    if open_ports.contains(&2049) { *scores.entry("Linux").or_insert(0) += 10; } // NFS

    // macOS indicators
    if open_ports.contains(&548) { *scores.entry("macOS").or_insert(0) += 20; } // AFP
    if open_ports.contains(&5009) { *scores.entry("macOS").or_insert(0) += 15; } // Airport
    if open_ports.contains(&5900) && open_ports.contains(&548) {
        *scores.entry("macOS").or_insert(0) += 10;
    }

    // Network device indicators
    if open_ports.contains(&23) && open_ports.contains(&161) {
        *scores.entry("Network Device").or_insert(0) += 15;
    }

    // Determine the winner
    if let Some((os_family, score)) = scores.iter().max_by_key(|&(_, score)| score) {
        if *score > 0 {
            // Calculate confidence based on score and number of signals
            let max_possible = total_signals * 30;
            let confidence = ((*score as f64 / max_possible as f64) * 100.0).min(95.0) as u8;

            // Determine version based on banners and ports
            let os_version = determine_version(*os_family, &data.banner_hints, &open_ports);

            return Some(OsInfo {
                os_family: os_family.to_string(),
                os_version,
                confidence: confidence.max(50), // Minimum 50% confidence if we have any signal
            });
        }
    }

    // Fallback to port-based only (original logic) if no TTL or banner data
    guess_os_from_ports(ports)
}

/// Infer the initial TTL from the observed TTL
/// Packets lose 1 TTL per hop, so we round up to common initial values
fn infer_initial_ttl(observed_ttl: u8) -> u8 {
    match observed_ttl {
        0..=32 => 32,      // Windows 95/98/ME
        33..=64 => 64,     // Linux, macOS, FreeBSD
        65..=128 => 128,   // Windows NT/2000/XP/Vista/7/8/10/11, Windows Server
        129..=255 => 255,  // Cisco, Solaris, some network devices
    }
}

/// Determine specific OS version from hints
fn determine_version(os_family: &str, hints: &[String], ports: &[u16]) -> Option<String> {
    match os_family {
        "Windows" => {
            // Try to determine Windows version from hints
            for hint in hints {
                if hint.contains("Server 2019") || hint.contains("Server 2022") {
                    return Some("Windows Server 2019/2022".to_string());
                }
                if hint.contains("Server 2016") {
                    return Some("Windows Server 2016".to_string());
                }
                if hint.contains("Server 2012") {
                    return Some("Windows Server 2012".to_string());
                }
                if hint.contains("10") || hint.contains("11") {
                    return Some("Windows 10/11".to_string());
                }
            }
            // Guess based on ports
            if ports.contains(&5985) {
                return Some("Windows Server (WinRM enabled)".to_string());
            }
            if ports.contains(&3389) && ports.contains(&445) {
                return Some("Windows Desktop/Server".to_string());
            }
            None
        }
        "Linux" => {
            for hint in hints {
                let hint_lower = hint.to_lowercase();
                if hint_lower.contains("ubuntu") {
                    return Some("Ubuntu".to_string());
                }
                if hint_lower.contains("debian") {
                    return Some("Debian".to_string());
                }
                if hint_lower.contains("centos") {
                    return Some("CentOS".to_string());
                }
                if hint_lower.contains("red hat") || hint_lower.contains("rhel") {
                    return Some("Red Hat Enterprise Linux".to_string());
                }
                if hint_lower.contains("fedora") {
                    return Some("Fedora".to_string());
                }
                if hint_lower.contains("alpine") {
                    return Some("Alpine Linux".to_string());
                }
            }
            // Generic Linux
            if ports.contains(&111) && ports.contains(&2049) {
                return Some("Linux (NFS server)".to_string());
            }
            None
        }
        "Network Device" => {
            if ports.contains(&22) && ports.contains(&23) && ports.contains(&161) {
                return Some("Router/Switch (Cisco-like)".to_string());
            }
            None
        }
        _ => None,
    }
}

fn guess_os_from_ports(ports: &[PortInfo]) -> Option<OsInfo> {
    let open_ports: Vec<u16> = ports.iter().map(|p| p.port).collect();

    // Windows indicators
    let has_smb = open_ports.contains(&445);
    let has_rdp = open_ports.contains(&3389);
    let has_winrm = open_ports.contains(&5985) || open_ports.contains(&5986);
    let has_ms_sql = open_ports.contains(&1433);

    if has_smb && has_rdp {
        return Some(OsInfo {
            os_family: "Windows".to_string(),
            os_version: Some("Windows Server or Desktop".to_string()),
            confidence: 85,
        });
    }

    if has_smb || has_rdp || has_winrm || has_ms_sql {
        return Some(OsInfo {
            os_family: "Windows".to_string(),
            os_version: None,
            confidence: 70,
        });
    }

    // Linux indicators
    let has_ssh = open_ports.contains(&22);
    let has_common_linux_ports = open_ports.contains(&111) // rpcbind
        || open_ports.contains(&2049); // NFS

    // Check for service banners that might indicate Linux
    let has_apache_nginx = ports.iter().any(|p| {
        if let Some(ref service) = p.service {
            service.name == "apache" || service.name == "nginx"
        } else {
            false
        }
    });

    if has_ssh && (has_common_linux_ports || has_apache_nginx) {
        // Try to determine distribution from SSH banner
        if let Some(ssh_version) = get_ssh_version(ports) {
            if ssh_version.to_lowercase().contains("ubuntu") {
                return Some(OsInfo {
                    os_family: "Linux".to_string(),
                    os_version: Some("Ubuntu".to_string()),
                    confidence: 75,
                });
            } else if ssh_version.to_lowercase().contains("debian") {
                return Some(OsInfo {
                    os_family: "Linux".to_string(),
                    os_version: Some("Debian".to_string()),
                    confidence: 75,
                });
            }
        }

        return Some(OsInfo {
            os_family: "Linux".to_string(),
            os_version: None,
            confidence: 65,
        });
    }

    // macOS indicators
    let has_afp = open_ports.contains(&548);
    let has_airport = open_ports.contains(&5009);

    if has_afp || has_airport {
        return Some(OsInfo {
            os_family: "macOS".to_string(),
            os_version: None,
            confidence: 70,
        });
    }

    // Unix-like indicators
    if has_ssh {
        return Some(OsInfo {
            os_family: "Unix-like".to_string(),
            os_version: None,
            confidence: 50,
        });
    }

    // Network device indicators
    let has_telnet = open_ports.contains(&23);
    let has_snmp = open_ports.contains(&161);

    if has_telnet && has_snmp {
        return Some(OsInfo {
            os_family: "Network Device".to_string(),
            os_version: Some("Router/Switch".to_string()),
            confidence: 60,
        });
    }

    // Database servers
    let has_mysql = open_ports.contains(&3306);
    let has_postgresql = open_ports.contains(&5432);
    let has_mongodb = open_ports.contains(&27017);
    let has_redis = open_ports.contains(&6379);

    if has_mysql || has_postgresql || has_mongodb || has_redis {
        // Likely Linux, but could be Windows
        return Some(OsInfo {
            os_family: "Linux".to_string(),
            os_version: Some("Database Server".to_string()),
            confidence: 55,
        });
    }

    None
}

fn get_ssh_version(ports: &[PortInfo]) -> Option<String> {
    for port in ports {
        if port.port == 22 {
            if let Some(ref service) = port.service {
                if let Some(ref banner) = service.banner {
                    return Some(banner.clone());
                }
            }
        }
    }
    None
}
