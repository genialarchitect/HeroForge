use super::types::{EnumDepth, EnumerationResult, Finding, FindingType, ServiceType};
use crate::types::{ScanProgressMessage, ScanTarget};
use anyhow::Result;
use log::{debug, info};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};
use tokio::sync::broadcast::Sender;

/// Known SMTP servers with potential vulnerabilities
const VULNERABLE_SMTP_VERSIONS: &[(&str, &str, &str)] = &[
    ("Postfix", "2.5", "CVE-2011-1720: Memory corruption in Cyrus SASL"),
    ("Sendmail", "8.13", "CVE-2006-0058: Signal handling race condition"),
    ("Exim", "4.87", "CVE-2016-9963: DKIM verification bypass"),
    ("Exim", "4.89", "CVE-2017-16943: Use-after-free in BDAT"),
    ("Exim", "4.90", "CVE-2018-6789: Buffer overflow in base64 decode"),
    ("Exim", "4.92", "CVE-2019-15846: Remote code execution via SNI"),
    ("Microsoft", "6.0", "Various Exchange vulnerabilities"),
];

/// Common usernames to test with VRFY
const COMMON_USERS: &[&str] = &[
    "root", "admin", "administrator", "postmaster", "webmaster",
    "info", "support", "sales", "contact", "mail", "test", "guest",
];

/// Enumerate SMTP service
pub async fn enumerate_smtp(
    target: &ScanTarget,
    port: u16,
    depth: EnumDepth,
    timeout: Duration,
    progress_tx: Option<Sender<ScanProgressMessage>>,
) -> Result<EnumerationResult> {
    let start = Instant::now();
    info!(
        "Starting SMTP enumeration for {}:{} with depth: {:?}",
        target.ip, port, depth
    );

    let mut findings = Vec::new();
    let mut metadata = HashMap::new();
    let target_ip = target.ip.to_string();

    // Step 1: Get SMTP banner and capabilities
    match get_smtp_info(&target_ip, port, timeout).await {
        Ok(Some(smtp_info)) => {
            metadata.insert("banner".to_string(), smtp_info.banner.clone());

            // Add version finding
            findings.push(
                Finding::new(FindingType::Version, smtp_info.banner.clone())
                    .with_metadata("server".to_string(), smtp_info.server_type.clone()),
            );

            // Check for vulnerable versions
            for (server, version, cve) in VULNERABLE_SMTP_VERSIONS {
                if smtp_info.banner.to_lowercase().contains(&server.to_lowercase())
                    && smtp_info.banner.contains(version)
                {
                    findings.push(
                        Finding::with_confidence(
                            FindingType::Vulnerability,
                            format!("{}: {}", cve, server),
                            75,
                        )
                        .with_metadata("cve".to_string(), cve.to_string()),
                    );
                }
            }

            // Store capabilities
            if !smtp_info.capabilities.is_empty() {
                metadata.insert("capabilities".to_string(), smtp_info.capabilities.join(", "));

                // Check for STARTTLS
                let has_starttls = smtp_info.capabilities.iter()
                    .any(|c| c.to_uppercase().contains("STARTTLS"));

                if !has_starttls {
                    findings.push(
                        Finding::with_confidence(
                            FindingType::Misconfiguration,
                            "SMTP server does not advertise STARTTLS".to_string(),
                            80,
                        )
                        .with_metadata(
                            "recommendation".to_string(),
                            "Enable STARTTLS for encrypted communication".to_string(),
                        ),
                    );
                }

                // Check auth methods
                for cap in &smtp_info.capabilities {
                    if cap.to_uppercase().starts_with("AUTH") {
                        let methods: Vec<&str> = cap.split_whitespace().skip(1).collect();
                        metadata.insert("auth_methods".to_string(), methods.join(", "));

                        // Warn about plaintext auth without TLS
                        if (methods.contains(&"PLAIN") || methods.contains(&"LOGIN")) && !has_starttls {
                            findings.push(
                                Finding::with_confidence(
                                    FindingType::Misconfiguration,
                                    "Plaintext authentication without TLS".to_string(),
                                    90,
                                )
                                .with_metadata("severity".to_string(), "High".to_string()),
                            );
                        }
                    }
                }
            }
        }
        Ok(None) => {
            debug!("Could not retrieve SMTP info from {}", target_ip);
        }
        Err(e) => {
            debug!("SMTP info check failed: {}", e);
        }
    }

    // Passive mode stops here
    if matches!(depth, EnumDepth::Passive) {
        return Ok(EnumerationResult {
            service_type: ServiceType::Smtp,
            enumeration_depth: depth,
            findings,
            duration: start.elapsed(),
            metadata,
        });
    }

    // Step 2: Check for open relay
    match check_open_relay(&target_ip, port, timeout).await {
        Ok(Some(is_open)) => {
            if is_open {
                findings.push(
                    Finding::with_confidence(
                        FindingType::OpenRelay,
                        "Server may be an open relay".to_string(),
                        85,
                    )
                    .with_metadata(
                        "description".to_string(),
                        "Server accepted relaying to external domain without auth".to_string(),
                    )
                    .with_metadata("severity".to_string(), "Critical".to_string()),
                );
                send_progress(&progress_tx, &target_ip, port, "OpenRelay", "Open relay detected");
            } else {
                metadata.insert("open_relay".to_string(), "false".to_string());
            }
        }
        Ok(None) => {}
        Err(e) => {
            debug!("Open relay check failed: {}", e);
        }
    }

    // Step 3: VRFY/EXPN user enumeration
    match check_vrfy_expn(&target_ip, port, timeout).await {
        Ok(Some(enum_info)) => {
            if enum_info.vrfy_enabled {
                findings.push(
                    Finding::with_confidence(
                        FindingType::UserEnumeration,
                        "VRFY command enabled - user enumeration possible".to_string(),
                        90,
                    )
                    .with_metadata("command".to_string(), "VRFY".to_string()),
                );
                send_progress(&progress_tx, &target_ip, port, "UserEnumeration", "VRFY enabled");
            }

            if enum_info.expn_enabled {
                findings.push(
                    Finding::with_confidence(
                        FindingType::UserEnumeration,
                        "EXPN command enabled - mailing list enumeration possible".to_string(),
                        90,
                    )
                    .with_metadata("command".to_string(), "EXPN".to_string()),
                );
            }

            metadata.insert("vrfy_enabled".to_string(), enum_info.vrfy_enabled.to_string());
            metadata.insert("expn_enabled".to_string(), enum_info.expn_enabled.to_string());
        }
        Ok(None) => {}
        Err(e) => {
            debug!("VRFY/EXPN check failed: {}", e);
        }
    }

    // Aggressive mode: Enumerate users
    if matches!(depth, EnumDepth::Aggressive) {
        match enumerate_users(&target_ip, port, timeout).await {
            Ok(Some(valid_users)) => {
                if !valid_users.is_empty() {
                    findings.push(
                        Finding::with_confidence(
                            FindingType::User,
                            format!("Valid users: {}", valid_users.join(", ")),
                            80,
                        )
                        .with_metadata("users".to_string(), valid_users.join(",")),
                    );
                    send_progress(
                        &progress_tx,
                        &target_ip,
                        port,
                        "User",
                        &format!("{} valid users found", valid_users.len()),
                    );
                }
            }
            Ok(None) => {}
            Err(e) => {
                debug!("User enumeration failed: {}", e);
            }
        }
    }

    metadata.insert(
        "findings_count".to_string(),
        findings.len().to_string(),
    );

    Ok(EnumerationResult {
        service_type: ServiceType::Smtp,
        enumeration_depth: depth,
        findings,
        duration: start.elapsed(),
        metadata,
    })
}

struct SmtpInfo {
    banner: String,
    server_type: String,
    capabilities: Vec<String>,
}

struct VrfyExpnInfo {
    vrfy_enabled: bool,
    expn_enabled: bool,
}

async fn get_smtp_info(target_ip: &str, port: u16, timeout: Duration) -> Result<Option<SmtpInfo>> {
    let target_ip = target_ip.to_string();

    tokio::task::spawn_blocking(move || {
        let addr = format!("{}:{}", target_ip, port);
        let stream = TcpStream::connect_timeout(&addr.parse()?, timeout)?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;

        let mut stream = BufReader::new(stream);
        let mut banner = String::new();
        stream.read_line(&mut banner)?;
        let banner = banner.trim().to_string();

        // Detect server type
        let server_type = if banner.to_lowercase().contains("postfix") {
            "Postfix"
        } else if banner.to_lowercase().contains("sendmail") {
            "Sendmail"
        } else if banner.to_lowercase().contains("exim") {
            "Exim"
        } else if banner.to_lowercase().contains("microsoft") {
            "Microsoft Exchange"
        } else {
            "Unknown"
        }.to_string();

        // Send EHLO to get capabilities
        writeln!(stream.get_mut(), "EHLO enumtest.local")?;
        stream.get_mut().flush()?;

        let mut capabilities = Vec::new();
        loop {
            let mut line = String::new();
            if stream.read_line(&mut line)? == 0 {
                break;
            }
            let line = line.trim().to_string();

            if line.starts_with("250-") {
                capabilities.push(line[4..].to_string());
            } else if line.starts_with("250 ") {
                capabilities.push(line[4..].to_string());
                break;
            } else {
                break;
            }
        }

        // Send QUIT
        let _ = writeln!(stream.get_mut(), "QUIT");
        let _ = stream.get_mut().flush();

        Ok(Some(SmtpInfo {
            banner,
            server_type,
            capabilities,
        }))
    })
    .await?
}

async fn check_open_relay(target_ip: &str, port: u16, timeout: Duration) -> Result<Option<bool>> {
    let target_ip = target_ip.to_string();

    tokio::task::spawn_blocking(move || {
        let addr = format!("{}:{}", target_ip, port);
        let stream = TcpStream::connect_timeout(&addr.parse()?, timeout)?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;

        let mut stream = BufReader::new(stream);

        // Read banner
        let mut response = String::new();
        stream.read_line(&mut response)?;

        // Send HELO
        writeln!(stream.get_mut(), "HELO test.local")?;
        stream.get_mut().flush()?;
        response.clear();
        stream.read_line(&mut response)?;

        // Try MAIL FROM
        writeln!(stream.get_mut(), "MAIL FROM:<test@example.com>")?;
        stream.get_mut().flush()?;
        response.clear();
        stream.read_line(&mut response)?;

        if !response.starts_with("250") {
            let _ = writeln!(stream.get_mut(), "QUIT");
            return Ok(Some(false));
        }

        // Try RCPT TO with external domain
        writeln!(stream.get_mut(), "RCPT TO:<test@external-domain.org>")?;
        stream.get_mut().flush()?;
        response.clear();
        stream.read_line(&mut response)?;

        let is_open = response.starts_with("250");

        // RSET and QUIT
        let _ = writeln!(stream.get_mut(), "RSET");
        let _ = stream.get_mut().flush();
        let _ = writeln!(stream.get_mut(), "QUIT");
        let _ = stream.get_mut().flush();

        Ok(Some(is_open))
    })
    .await?
}

async fn check_vrfy_expn(target_ip: &str, port: u16, timeout: Duration) -> Result<Option<VrfyExpnInfo>> {
    let target_ip = target_ip.to_string();

    tokio::task::spawn_blocking(move || {
        let addr = format!("{}:{}", target_ip, port);
        let stream = TcpStream::connect_timeout(&addr.parse()?, timeout)?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;

        let mut stream = BufReader::new(stream);

        // Read banner
        let mut response = String::new();
        stream.read_line(&mut response)?;

        // Check VRFY
        writeln!(stream.get_mut(), "VRFY root")?;
        stream.get_mut().flush()?;
        response.clear();
        stream.read_line(&mut response)?;

        // 250, 251, 252 = enabled, 502, 500 = disabled
        let vrfy_enabled = !response.starts_with("502") && !response.starts_with("500");

        // Check EXPN
        writeln!(stream.get_mut(), "EXPN root")?;
        stream.get_mut().flush()?;
        response.clear();
        stream.read_line(&mut response)?;

        let expn_enabled = !response.starts_with("502") && !response.starts_with("500");

        let _ = writeln!(stream.get_mut(), "QUIT");
        let _ = stream.get_mut().flush();

        Ok(Some(VrfyExpnInfo {
            vrfy_enabled,
            expn_enabled,
        }))
    })
    .await?
}

async fn enumerate_users(target_ip: &str, port: u16, timeout: Duration) -> Result<Option<Vec<String>>> {
    let target_ip = target_ip.to_string();

    tokio::task::spawn_blocking(move || {
        let addr = format!("{}:{}", target_ip, port);
        let stream = TcpStream::connect_timeout(&addr.parse()?, timeout)?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;

        let mut stream = BufReader::new(stream);
        let mut valid_users = Vec::new();

        // Read banner
        let mut response = String::new();
        stream.read_line(&mut response)?;

        for user in COMMON_USERS {
            writeln!(stream.get_mut(), "VRFY {}", user)?;
            stream.get_mut().flush()?;

            response.clear();
            stream.read_line(&mut response)?;

            // 250, 251, 252 indicate valid user
            if response.starts_with("250") || response.starts_with("251") || response.starts_with("252") {
                valid_users.push(user.to_string());
            }

            // Small delay to avoid rate limiting
            std::thread::sleep(Duration::from_millis(50));
        }

        let _ = writeln!(stream.get_mut(), "QUIT");
        let _ = stream.get_mut().flush();

        if valid_users.is_empty() {
            Ok(None)
        } else {
            Ok(Some(valid_users))
        }
    })
    .await?
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
    fn test_vulnerable_versions() {
        assert!(VULNERABLE_SMTP_VERSIONS.len() >= 5);
    }
}
