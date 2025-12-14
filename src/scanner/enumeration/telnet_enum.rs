//! Telnet Service Enumeration Module
//!
//! Performs analysis of Telnet services including:
//! - Banner grabbing and analysis
//! - OS/device fingerprinting from banner
//! - Login prompt detection
//! - Telnet option negotiation analysis

use super::types::{EnumDepth, EnumerationResult, Finding, FindingType, ServiceType};
use crate::types::{ScanProgressMessage, ScanTarget};
use anyhow::Result;
use log::{debug, info};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};
use tokio::sync::broadcast::Sender;

// Telnet command codes
const IAC: u8 = 255;  // Interpret As Command
const DONT: u8 = 254;
const DO: u8 = 253;
const WONT: u8 = 252;
const WILL: u8 = 251;
const SB: u8 = 250;   // Subnegotiation Begin
const SE: u8 = 240;   // Subnegotiation End

// Telnet option codes
const OPT_ECHO: u8 = 1;
const OPT_SUPPRESS_GO_AHEAD: u8 = 3;
const OPT_STATUS: u8 = 5;
const OPT_TIMING_MARK: u8 = 6;
const OPT_TERMINAL_TYPE: u8 = 24;
const OPT_WINDOW_SIZE: u8 = 31;
const OPT_TERMINAL_SPEED: u8 = 32;
const OPT_REMOTE_FLOW_CONTROL: u8 = 33;
const OPT_LINEMODE: u8 = 34;
const OPT_ENV_VARS: u8 = 36;
const OPT_NEW_ENV: u8 = 39;

/// Telnet server information
#[derive(Debug, Clone)]
struct TelnetInfo {
    banner: String,
    options_offered: Vec<u8>,
    os_hint: Option<String>,
    device_type: Option<String>,
    login_prompt: bool,
    #[allow(dead_code)]
    password_prompt: bool,
}

/// Main enumeration entry point for Telnet services
pub async fn enumerate_telnet(
    target: &ScanTarget,
    port: u16,
    depth: EnumDepth,
    timeout: Duration,
    progress_tx: Option<Sender<ScanProgressMessage>>,
) -> Result<EnumerationResult> {
    let start = Instant::now();
    info!(
        "Starting Telnet enumeration for {}:{} with depth: {:?}",
        target.ip, port, depth
    );

    let mut findings = Vec::new();
    let mut metadata = HashMap::new();
    let target_ip = target.ip.to_string();

    // Probe Telnet service
    match probe_telnet(&target_ip, port, timeout).await {
        Ok(Some(telnet_info)) => {
            // Report banner if found
            if !telnet_info.banner.is_empty() {
                let clean_banner = clean_banner(&telnet_info.banner);
                findings.push(
                    Finding::new(
                        FindingType::InformationDisclosure,
                        format!("Telnet banner: {}", truncate_string(&clean_banner, 200)),
                    )
                    .with_metadata("full_banner".to_string(), clean_banner.clone()),
                );
                metadata.insert("banner".to_string(), clean_banner.clone());

                send_progress(&progress_tx, &target_ip, port, "Banner", &truncate_string(&clean_banner, 100));
            }

            // Report OS/device hint if detected
            if let Some(ref os_hint) = telnet_info.os_hint {
                findings.push(
                    Finding::new(
                        FindingType::InformationDisclosure,
                        format!("OS detected: {}", os_hint),
                    )
                    .with_metadata("os".to_string(), os_hint.clone()),
                );
                metadata.insert("os".to_string(), os_hint.clone());

                send_progress(&progress_tx, &target_ip, port, "OS", os_hint);
            }

            // Report device type if detected
            if let Some(ref device_type) = telnet_info.device_type {
                findings.push(
                    Finding::new(
                        FindingType::InformationDisclosure,
                        format!("Device type: {}", device_type),
                    )
                    .with_metadata("device_type".to_string(), device_type.clone()),
                );
                metadata.insert("device_type".to_string(), device_type.clone());

                send_progress(&progress_tx, &target_ip, port, "DeviceType", device_type);
            }

            // Report telnet options
            if !telnet_info.options_offered.is_empty() && depth != EnumDepth::Passive {
                let options_str = telnet_info.options_offered
                    .iter()
                    .map(|&o| option_name(o))
                    .collect::<Vec<_>>()
                    .join(", ");

                findings.push(
                    Finding::new(
                        FindingType::SecurityConfig,
                        format!("Telnet options: {}", options_str),
                    )
                    .with_metadata("options".to_string(), options_str.clone()),
                );

                send_progress(&progress_tx, &target_ip, port, "TelnetOptions", &options_str);
            }

            // Security warning: Telnet is inherently insecure
            findings.push(
                Finding::with_confidence(
                    FindingType::Misconfiguration,
                    "Telnet transmits data in cleartext (including passwords)".to_string(),
                    100,
                )
                .with_metadata("severity".to_string(), "High".to_string())
                .with_metadata("recommendation".to_string(), "Replace Telnet with SSH".to_string()),
            );

            send_progress(&progress_tx, &target_ip, port, "Misconfiguration", "Cleartext protocol");

            // Check for login prompt
            if telnet_info.login_prompt {
                findings.push(
                    Finding::new(
                        FindingType::InformationDisclosure,
                        "Login prompt detected".to_string(),
                    )
                    .with_metadata("auth_required".to_string(), "true".to_string()),
                );
            } else if !telnet_info.banner.is_empty() {
                // No login prompt detected - might be open access
                findings.push(
                    Finding::with_confidence(
                        FindingType::Misconfiguration,
                        "No login prompt detected - possible unauthenticated access".to_string(),
                        70,
                    )
                    .with_metadata("severity".to_string(), "High".to_string()),
                );

                send_progress(&progress_tx, &target_ip, port, "Misconfiguration", "No login prompt");
            }

            // For aggressive depth, check for known vulnerable devices
            if depth == EnumDepth::Aggressive {
                check_telnet_vulnerabilities(&telnet_info, &mut findings, &progress_tx, &target_ip, port);
            }
        }
        Ok(None) => {
            debug!("No Telnet info retrieved from {}:{}", target_ip, port);
        }
        Err(e) => {
            debug!("Telnet probe failed for {}:{}: {}", target_ip, port, e);
        }
    }

    Ok(EnumerationResult {
        service_type: ServiceType::Http, // Will be changed when we add Telnet type
        enumeration_depth: depth,
        findings,
        duration: start.elapsed(),
        metadata,
    })
}

/// Probe Telnet server for banner and configuration
async fn probe_telnet(
    target_ip: &str,
    port: u16,
    timeout: Duration,
) -> Result<Option<TelnetInfo>> {
    let addr = format!("{}:{}", target_ip, port);

    // Connect with timeout
    let mut stream = match TcpStream::connect_timeout(
        &addr.parse().map_err(|e| anyhow::anyhow!("Invalid address: {}", e))?,
        timeout,
    ) {
        Ok(s) => s,
        Err(e) => {
            debug!("Failed to connect to Telnet at {}: {}", addr, e);
            return Ok(None);
        }
    };

    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;

    let mut buffer = [0u8; 4096];
    let mut full_response = Vec::new();
    let mut options_offered = Vec::new();

    // Read initial response (may include telnet negotiations)
    loop {
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => {
                let data = &buffer[..n];

                // Process telnet commands and extract options
                let (text, opts) = process_telnet_data(data, &mut stream)?;
                options_offered.extend(opts);
                full_response.extend_from_slice(&text);

                // If we got enough data, stop reading
                if full_response.len() > 2048 {
                    break;
                }

                // Check if we have a complete prompt
                let response_str = String::from_utf8_lossy(&full_response);
                if response_str.contains("login:") ||
                   response_str.contains("Login:") ||
                   response_str.contains("Username:") ||
                   response_str.contains("Password:") ||
                   response_str.contains(">") ||
                   response_str.contains("#") ||
                   response_str.contains("$") {
                    break;
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock ||
                         e.kind() == std::io::ErrorKind::TimedOut => {
                break;
            }
            Err(e) => {
                debug!("Error reading from Telnet: {}", e);
                break;
            }
        }
    }

    let banner = String::from_utf8_lossy(&full_response).to_string();
    let (os_hint, device_type) = analyze_banner(&banner);
    let login_prompt = banner.to_lowercase().contains("login") ||
                       banner.to_lowercase().contains("username");
    let password_prompt = banner.to_lowercase().contains("password");

    Ok(Some(TelnetInfo {
        banner,
        options_offered,
        os_hint,
        device_type,
        login_prompt,
        password_prompt,
    }))
}

/// Process telnet data, respond to negotiations, and extract text
fn process_telnet_data(
    data: &[u8],
    stream: &mut TcpStream,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut text = Vec::new();
    let mut options = Vec::new();
    let mut i = 0;

    while i < data.len() {
        if data[i] == IAC && i + 1 < data.len() {
            match data[i + 1] {
                WILL => {
                    if i + 2 < data.len() {
                        let option = data[i + 2];
                        options.push(option);
                        // Refuse most options (send DONT)
                        let response = [IAC, DONT, option];
                        let _ = stream.write_all(&response);
                        i += 3;
                        continue;
                    }
                }
                DO => {
                    if i + 2 < data.len() {
                        let option = data[i + 2];
                        // Refuse most options (send WONT)
                        let response = [IAC, WONT, option];
                        let _ = stream.write_all(&response);
                        i += 3;
                        continue;
                    }
                }
                WONT | DONT => {
                    if i + 2 < data.len() {
                        i += 3;
                        continue;
                    }
                }
                SB => {
                    // Skip subnegotiation
                    while i < data.len() && !(data[i] == IAC && i + 1 < data.len() && data[i + 1] == SE) {
                        i += 1;
                    }
                    i += 2; // Skip IAC SE
                    continue;
                }
                IAC => {
                    // Escaped IAC
                    text.push(IAC);
                    i += 2;
                    continue;
                }
                _ => {
                    i += 2;
                    continue;
                }
            }
        }
        text.push(data[i]);
        i += 1;
    }

    Ok((text, options))
}

/// Analyze banner for OS and device hints
fn analyze_banner(banner: &str) -> (Option<String>, Option<String>) {
    let lower = banner.to_lowercase();
    let mut os_hint = None;
    let mut device_type = None;

    // OS detection patterns
    if lower.contains("linux") {
        os_hint = Some("Linux".to_string());
    } else if lower.contains("ubuntu") {
        os_hint = Some("Ubuntu Linux".to_string());
    } else if lower.contains("debian") {
        os_hint = Some("Debian Linux".to_string());
    } else if lower.contains("centos") {
        os_hint = Some("CentOS Linux".to_string());
    } else if lower.contains("red hat") || lower.contains("rhel") {
        os_hint = Some("Red Hat Enterprise Linux".to_string());
    } else if lower.contains("freebsd") {
        os_hint = Some("FreeBSD".to_string());
    } else if lower.contains("openbsd") {
        os_hint = Some("OpenBSD".to_string());
    } else if lower.contains("solaris") || lower.contains("sunos") {
        os_hint = Some("Solaris".to_string());
    } else if lower.contains("aix") {
        os_hint = Some("IBM AIX".to_string());
    } else if lower.contains("hp-ux") {
        os_hint = Some("HP-UX".to_string());
    } else if lower.contains("windows") {
        os_hint = Some("Windows".to_string());
    } else if lower.contains("cisco") {
        os_hint = Some("Cisco IOS".to_string());
        device_type = Some("Network Device (Cisco)".to_string());
    } else if lower.contains("juniper") || lower.contains("junos") {
        os_hint = Some("JunOS".to_string());
        device_type = Some("Network Device (Juniper)".to_string());
    }

    // Device type detection
    if device_type.is_none() {
        if lower.contains("router") {
            device_type = Some("Router".to_string());
        } else if lower.contains("switch") {
            device_type = Some("Switch".to_string());
        } else if lower.contains("firewall") {
            device_type = Some("Firewall".to_string());
        } else if lower.contains("mikrotik") {
            device_type = Some("MikroTik Router".to_string());
            os_hint = Some("RouterOS".to_string());
        } else if lower.contains("busybox") {
            device_type = Some("Embedded Device".to_string());
            os_hint = Some("Linux (BusyBox)".to_string());
        } else if lower.contains("hp procurve") || lower.contains("aruba") {
            device_type = Some("Network Switch (HP/Aruba)".to_string());
        } else if lower.contains("printer") || lower.contains("laserjet") {
            device_type = Some("Printer".to_string());
        }
    }

    (os_hint, device_type)
}

fn check_telnet_vulnerabilities(
    telnet_info: &TelnetInfo,
    findings: &mut Vec<Finding>,
    progress_tx: &Option<Sender<ScanProgressMessage>>,
    target_ip: &str,
    port: u16,
) {
    let lower_banner = telnet_info.banner.to_lowercase();

    // Check for default/hardcoded credentials patterns
    if lower_banner.contains("default password") || lower_banner.contains("factory default") {
        findings.push(
            Finding::with_confidence(
                FindingType::DefaultCredentials,
                "Banner mentions default password".to_string(),
                80,
            )
            .with_metadata("severity".to_string(), "High".to_string()),
        );

        send_progress(progress_tx, target_ip, port, "DefaultCredentials", "Default password mentioned");
    }

    // Check for known vulnerable devices
    if lower_banner.contains("busybox") {
        findings.push(
            Finding::with_confidence(
                FindingType::Vulnerability,
                "BusyBox detected - check for Mirai botnet vulnerabilities".to_string(),
                70,
            )
            .with_metadata("cve".to_string(), "Multiple".to_string())
            .with_metadata("severity".to_string(), "High".to_string()),
        );

        send_progress(progress_tx, target_ip, port, "Vulnerability", "BusyBox - check for Mirai");
    }

    // Check for old Cisco IOS versions
    if lower_banner.contains("cisco") && lower_banner.contains("ios") {
        findings.push(
            Finding::new(
                FindingType::InformationDisclosure,
                "Cisco IOS detected - verify IOS version for known vulnerabilities".to_string(),
            )
            .with_metadata("recommendation".to_string(), "Check Cisco Security Advisories".to_string()),
        );
    }

    // Check for MikroTik vulnerabilities
    if lower_banner.contains("mikrotik") {
        findings.push(
            Finding::with_confidence(
                FindingType::Vulnerability,
                "MikroTik detected - check for CVE-2018-14847 (Winbox vulnerability)".to_string(),
                60,
            )
            .with_metadata("cve".to_string(), "CVE-2018-14847".to_string())
            .with_metadata("severity".to_string(), "Critical".to_string()),
        );

        send_progress(progress_tx, target_ip, port, "Vulnerability", "MikroTik - check CVE-2018-14847");
    }
}

fn option_name(option: u8) -> &'static str {
    match option {
        OPT_ECHO => "Echo",
        OPT_SUPPRESS_GO_AHEAD => "Suppress Go Ahead",
        OPT_STATUS => "Status",
        OPT_TIMING_MARK => "Timing Mark",
        OPT_TERMINAL_TYPE => "Terminal Type",
        OPT_WINDOW_SIZE => "Window Size",
        OPT_TERMINAL_SPEED => "Terminal Speed",
        OPT_REMOTE_FLOW_CONTROL => "Remote Flow Control",
        OPT_LINEMODE => "Linemode",
        OPT_ENV_VARS => "Environment Variables",
        OPT_NEW_ENV => "New Environment",
        _ => "Unknown",
    }
}

fn clean_banner(banner: &str) -> String {
    banner
        .chars()
        .filter(|c| c.is_ascii_graphic() || c.is_ascii_whitespace())
        .collect::<String>()
        .trim()
        .to_string()
}

fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len])
    }
}

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
    fn test_analyze_banner_linux() {
        let (os, device) = analyze_banner("Ubuntu 20.04 LTS\nlogin:");
        assert_eq!(os, Some("Ubuntu Linux".to_string()));
        assert_eq!(device, None);
    }

    #[test]
    fn test_analyze_banner_cisco() {
        let (os, device) = analyze_banner("Cisco IOS Software, C2960 Software");
        assert_eq!(os, Some("Cisco IOS".to_string()));
        assert_eq!(device, Some("Network Device (Cisco)".to_string()));
    }

    #[test]
    fn test_analyze_banner_mikrotik() {
        let (os, device) = analyze_banner("MikroTik v6.48");
        assert_eq!(os, Some("RouterOS".to_string()));
        assert_eq!(device, Some("MikroTik Router".to_string()));
    }

    #[test]
    fn test_clean_banner() {
        let dirty = "Hello\x00World\x1b[0m Test";
        let clean = clean_banner(dirty);
        assert!(!clean.contains('\x00'));
        assert!(clean.contains("Hello"));
    }

    #[test]
    fn test_truncate_string() {
        assert_eq!(truncate_string("hello", 10), "hello");
        assert_eq!(truncate_string("hello world", 5), "hello...");
    }
}
