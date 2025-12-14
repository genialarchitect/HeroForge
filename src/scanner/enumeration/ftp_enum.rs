use super::types::{EnumDepth, EnumerationResult, Finding, FindingType, ServiceType};
use crate::types::{ScanProgressMessage, ScanTarget};
use anyhow::Result;
use log::{debug, info};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};
use tokio::sync::broadcast::Sender;

/// Enumerate FTP service
pub async fn enumerate_ftp(
    target: &ScanTarget,
    port: u16,
    depth: EnumDepth,
    timeout: Duration,
    progress_tx: Option<Sender<ScanProgressMessage>>,
) -> Result<EnumerationResult> {
    let start = Instant::now();
    info!(
        "Starting FTP enumeration for {}:{} with depth: {:?}",
        target.ip, port, depth
    );

    let mut findings = Vec::new();
    let mut metadata = HashMap::new();

    let target_ip = target.ip.to_string();

    // Passive: Just banner info (already captured in service detection)
    if matches!(depth, EnumDepth::Passive) {
        return Ok(EnumerationResult {
            service_type: ServiceType::Ftp,
            enumeration_depth: depth,
            findings,
            duration: start.elapsed(),
            metadata,
        });
    }

    // Step 1: Check for anonymous FTP login
    info!("Checking for anonymous FTP login on {}", target_ip);
    match check_anonymous_ftp(&target_ip, port, timeout).await {
        Ok(Some(mut anon_findings)) => {
            send_progress(
                &progress_tx,
                &target_ip,
                port,
                "AnonymousLogin",
                "Anonymous FTP enabled",
            );

            findings.append(&mut anon_findings);
            metadata.insert("anonymous_login".to_string(), "true".to_string());
        }
        Ok(None) => {
            metadata.insert("anonymous_login".to_string(), "false".to_string());
        }
        Err(e) => {
            debug!("Anonymous FTP check failed: {}", e);
            metadata.insert("anonymous_login".to_string(), "error".to_string());
        }
    }

    // Step 2: Try common credentials (Light and Aggressive)
    if !matches!(depth, EnumDepth::Passive) && findings.is_empty() {
        info!("Trying common FTP credentials on {}", target_ip);
        if let Some(cred_findings) = try_common_credentials(&target_ip, port, timeout, depth).await
        {
            for finding in &cred_findings {
                send_progress(
                    &progress_tx,
                    &target_ip,
                    port,
                    "DefaultCredentials",
                    &finding.value,
                );
            }
            findings.extend(cred_findings);
        }
    }

    // Step 3: Check for FTP bounce (Aggressive only)
    if matches!(depth, EnumDepth::Aggressive) {
        info!("Checking for FTP bounce on {}", target_ip);
        if let Some(bounce_finding) = check_ftp_bounce(&target_ip, port, timeout).await {
            findings.push(bounce_finding);
        }
    }

    metadata.insert(
        "credentials_found".to_string(),
        findings
            .iter()
            .filter(|f| {
                matches!(
                    f.finding_type,
                    FindingType::AnonymousLogin | FindingType::DefaultCredentials
                )
            })
            .count()
            .to_string(),
    );

    Ok(EnumerationResult {
        service_type: ServiceType::Ftp,
        enumeration_depth: depth,
        findings,
        duration: start.elapsed(),
        metadata,
    })
}

/// Check for anonymous FTP login
async fn check_anonymous_ftp(
    target_ip: &str,
    port: u16,
    timeout: Duration,
) -> Result<Option<Vec<Finding>>> {
    // Convert to owned string for the async task
    let target_ip = target_ip.to_string();

    // Spawn blocking because FTP operations use std::net::TcpStream
    tokio::task::spawn_blocking(move || {
        let mut findings = Vec::new();

        let addr = format!("{}:{}", target_ip, port);
        let stream = TcpStream::connect_timeout(&addr.parse()?, timeout)?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;

        let mut stream = BufReader::new(stream);

        // Read banner
        let mut banner = String::new();
        stream.read_line(&mut banner)?;
        debug!("FTP Banner: {}", banner.trim());

        // Try anonymous login
        writeln!(stream.get_mut(), "USER anonymous")?;
        stream.get_mut().flush()?;

        let mut response = String::new();
        stream.read_line(&mut response)?;

        if response.starts_with("331") {
            // Password required
            writeln!(stream.get_mut(), "PASS anonymous@example.com")?;
            stream.get_mut().flush()?;

            response.clear();
            stream.read_line(&mut response)?;

            if response.starts_with("230") {
                // Login successful
                findings.push(
                    Finding::with_confidence(
                        FindingType::AnonymousLogin,
                        "Anonymous FTP login enabled".to_string(),
                        95,
                    )
                    .with_metadata("username".to_string(), "anonymous".to_string())
                    .with_metadata("password".to_string(), "anonymous@example.com".to_string()),
                );

                // Try to list directory
                if let Ok(dir_findings) = list_ftp_directory(&mut stream) {
                    findings.extend(dir_findings);
                }

                // Check for writable directories
                if let Ok(Some(write_finding)) = check_writable_directory(&mut stream) {
                    findings.push(write_finding);
                }
            }
        }

        // Send QUIT
        let _ = writeln!(stream.get_mut(), "QUIT");
        let _ = stream.get_mut().flush();

        if findings.is_empty() {
            Ok(None)
        } else {
            Ok(Some(findings))
        }
    })
    .await?
}

/// Try common FTP credentials
async fn try_common_credentials(
    target_ip: &str,
    port: u16,
    timeout: Duration,
    depth: EnumDepth,
) -> Option<Vec<Finding>> {
    let credentials = if matches!(depth, EnumDepth::Aggressive) {
        vec![
            ("ftp", "ftp"),
            ("admin", "admin"),
            ("user", "user"),
            ("test", "test"),
            ("guest", "guest"),
            ("root", "root"),
            ("administrator", "password"),
        ]
    } else {
        vec![("ftp", "ftp"), ("admin", "admin")]
    };

    for (username, password) in credentials {
        let target_ip = target_ip.to_string();
        let result = tokio::task::spawn_blocking(move || {
            let addr = format!("{}:{}", target_ip, port);
            let stream = TcpStream::connect_timeout(&addr.parse().ok()?, timeout).ok()?;
            stream.set_read_timeout(Some(timeout)).ok()?;
            stream.set_write_timeout(Some(timeout)).ok()?;

            let mut stream = BufReader::new(stream);

            // Read banner
            let mut banner = String::new();
            stream.read_line(&mut banner).ok()?;

            // Try login
            writeln!(stream.get_mut(), "USER {}", username).ok()?;
            stream.get_mut().flush().ok()?;

            let mut response = String::new();
            stream.read_line(&mut response).ok()?;

            if response.starts_with("331") {
                writeln!(stream.get_mut(), "PASS {}", password).ok()?;
                stream.get_mut().flush().ok()?;

                response.clear();
                stream.read_line(&mut response).ok()?;

                if response.starts_with("230") {
                    // Login successful
                    let _ = writeln!(stream.get_mut(), "QUIT");
                    return Some(
                        Finding::with_confidence(
                            FindingType::DefaultCredentials,
                            format!("FTP: {}:{}", username, password),
                            90,
                        )
                        .with_metadata("username".to_string(), username.to_string())
                        .with_metadata("password".to_string(), password.to_string()),
                    );
                }
            }

            let _ = writeln!(stream.get_mut(), "QUIT");
            None
        })
        .await;

        if let Ok(Some(finding)) = result {
            return Some(vec![finding]);
        }
    }

    None
}

/// List FTP directory
fn list_ftp_directory(stream: &mut BufReader<TcpStream>) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();

    // Send PWD to get current directory
    writeln!(stream.get_mut(), "PWD")?;
    stream.get_mut().flush()?;

    let mut response = String::new();
    stream.read_line(&mut response)?;

    // Send LIST command
    writeln!(stream.get_mut(), "PASV")?;
    stream.get_mut().flush()?;

    response.clear();
    stream.read_line(&mut response)?;

    if response.starts_with("227") {
        // Parse PASV response to get port
        // Format: 227 Entering Passive Mode (h1,h2,h3,h4,p1,p2)
        if let Some(port_info) = parse_pasv_response(&response) {
            findings.push(
                Finding::new(FindingType::Directory, "/".to_string())
                    .with_metadata("note".to_string(), "Anonymous directory access".to_string())
                    .with_metadata("pasv_port".to_string(), port_info.to_string()),
            );
        }
    }

    Ok(findings)
}

/// Parse PASV response to extract port
fn parse_pasv_response(response: &str) -> Option<String> {
    // Extract (h1,h2,h3,h4,p1,p2) from response
    let start = response.find('(')?;
    let end = response.find(')')?;
    let data = &response[start + 1..end];
    Some(data.to_string())
}

/// Check for writable directory
fn check_writable_directory(stream: &mut BufReader<TcpStream>) -> Result<Option<Finding>> {
    // Try to create a test directory
    let test_dir = format!("test_{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs());

    writeln!(stream.get_mut(), "MKD {}", test_dir)?;
    stream.get_mut().flush()?;

    let mut response = String::new();
    stream.read_line(&mut response)?;

    if response.starts_with("257") {
        // Directory created successfully - clean up
        writeln!(stream.get_mut(), "RMD {}", test_dir)?;
        stream.get_mut().flush()?;
        stream.read_line(&mut String::new())?; // Read response

        return Ok(Some(
            Finding::with_confidence(
                FindingType::WritableDirectory,
                "FTP root directory is writable".to_string(),
                90,
            )
            .with_metadata("tested_command".to_string(), "MKD".to_string()),
        ));
    }

    Ok(None)
}

/// Check for FTP bounce vulnerability
async fn check_ftp_bounce(target_ip: &str, port: u16, timeout: Duration) -> Option<Finding> {
    // FTP bounce attack uses PORT command to connect to arbitrary hosts
    // This is a dangerous vulnerability that should be checked carefully

    let target_ip = target_ip.to_string();
    tokio::task::spawn_blocking(move || {
        let addr = format!("{}:{}", target_ip, port);
        let stream = TcpStream::connect_timeout(&addr.parse().ok()?, timeout).ok()?;
        stream.set_read_timeout(Some(timeout)).ok()?;
        stream.set_write_timeout(Some(timeout)).ok()?;

        let mut stream = BufReader::new(stream);

        // Read banner
        let mut banner = String::new();
        stream.read_line(&mut banner).ok()?;

        // Try anonymous login first
        writeln!(stream.get_mut(), "USER anonymous").ok()?;
        stream.get_mut().flush().ok()?;

        let mut response = String::new();
        stream.read_line(&mut response).ok()?;

        if response.starts_with("331") {
            writeln!(stream.get_mut(), "PASS anonymous@example.com").ok()?;
            stream.get_mut().flush().ok()?;

            response.clear();
            stream.read_line(&mut response).ok()?;

            if response.starts_with("230") {
                // Try PORT command with a test address (127,0,0,1,0,80)
                writeln!(stream.get_mut(), "PORT 127,0,0,1,0,80").ok()?;
                stream.get_mut().flush().ok()?;

                response.clear();
                stream.read_line(&mut response).ok()?;

                // If PORT command is accepted, server might be vulnerable to bounce
                if response.starts_with("200") {
                    let _ = writeln!(stream.get_mut(), "QUIT");
                    return Some(
                        Finding::with_confidence(
                            FindingType::FtpBounce,
                            "FTP server may be vulnerable to bounce attack".to_string(),
                            75,
                        )
                        .with_metadata(
                            "description".to_string(),
                            "PORT command accepted - server may relay connections".to_string(),
                        ),
                    );
                }
            }
        }

        let _ = writeln!(stream.get_mut(), "QUIT");
        None
    })
    .await
    .ok()?
}

/// Helper to send progress messages
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
    fn test_parse_pasv_response() {
        let response = "227 Entering Passive Mode (192,168,1,1,234,56)";
        let result = parse_pasv_response(response);
        assert_eq!(result, Some("192,168,1,1,234,56".to_string()));
    }
}
