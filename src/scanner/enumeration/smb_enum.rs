use super::types::{EnumDepth, EnumerationResult, Finding, FindingType, ServiceType};
use crate::types::{ScanProgressMessage, ScanTarget};
use anyhow::Result;
use log::{debug, info};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::process::Command;
use tokio::sync::broadcast::Sender;

/// Enumerate SMB service
pub async fn enumerate_smb(
    target: &ScanTarget,
    port: u16,
    depth: EnumDepth,
    timeout: Duration,
    progress_tx: Option<Sender<ScanProgressMessage>>,
) -> Result<EnumerationResult> {
    let start = Instant::now();
    info!(
        "Starting SMB enumeration for {}:{} with depth: {:?}",
        target.ip, port, depth
    );

    let mut findings = Vec::new();
    let mut metadata = HashMap::new();

    let target_ip = target.ip.to_string();

    // Passive: Just return basic info (service detection already got version)
    if matches!(depth, EnumDepth::Passive) {
        return Ok(EnumerationResult {
            service_type: ServiceType::Smb,
            enumeration_depth: depth,
            findings,
            duration: start.elapsed(),
            metadata,
        });
    }

    // Step 1: Check for null session
    info!("Checking for SMB null session on {}", target_ip);
    if let Some(null_session_finding) = check_null_session(&target_ip, timeout).await {
        findings.push(null_session_finding.clone());

        send_progress(
            &progress_tx,
            &target_ip,
            port,
            "NullSession",
            "Null session available",
        );

        metadata.insert("null_session".to_string(), "true".to_string());
    } else {
        metadata.insert("null_session".to_string(), "false".to_string());
    }

    // Step 2: Enumerate shares
    info!("Enumerating SMB shares on {}", target_ip);
    let share_findings = enumerate_shares(&target_ip, timeout, depth).await;

    for share in &share_findings {
        send_progress(
            &progress_tx,
            &target_ip,
            port,
            "Share",
            &share.value,
        );
    }

    findings.extend(share_findings);

    // Step 3: Get domain information
    info!("Gathering domain information from {}", target_ip);
    if let Some(domain_findings) = get_domain_info(&target_ip, timeout).await {
        findings.extend(domain_findings);
    }

    // Step 4: User enumeration (Light and Aggressive only)
    if !matches!(depth, EnumDepth::Passive) {
        info!("Enumerating users on {}", target_ip);
        let user_findings = enumerate_users(&target_ip, timeout, depth).await;

        for user in &user_findings {
            send_progress(
                &progress_tx,
                &target_ip,
                port,
                "User",
                &user.value,
            );
        }

        findings.extend(user_findings);
    }

    // Step 5: Group enumeration (Aggressive only)
    if matches!(depth, EnumDepth::Aggressive) {
        info!("Enumerating groups on {}", target_ip);
        let group_findings = enumerate_groups(&target_ip, timeout).await;
        findings.extend(group_findings);
    }

    // Step 6: Policy information (Aggressive only)
    if matches!(depth, EnumDepth::Aggressive) {
        info!("Querying password policy on {}", target_ip);
        if let Some(policy_findings) = get_password_policy(&target_ip, timeout).await {
            findings.extend(policy_findings);
        }
    }

    metadata.insert("shares_found".to_string(), findings.iter().filter(|f| matches!(f.finding_type, FindingType::Share)).count().to_string());
    metadata.insert("users_found".to_string(), findings.iter().filter(|f| matches!(f.finding_type, FindingType::User)).count().to_string());

    Ok(EnumerationResult {
        service_type: ServiceType::Smb,
        enumeration_depth: depth,
        findings,
        duration: start.elapsed(),
        metadata,
    })
}

/// Check for SMB null session
async fn check_null_session(target_ip: &str, timeout: Duration) -> Option<Finding> {
    // Use smbclient to check for null session
    // smbclient -N -L //<target>
    let output = tokio::time::timeout(
        timeout,
        Command::new("smbclient")
            .args(&["-N", "-L", &format!("//{}", target_ip)])
            .output(),
    )
    .await;

    match output {
        Ok(Ok(result)) => {
            if result.status.success() {
                let stdout = String::from_utf8_lossy(&result.stdout);

                // Check if we got actual share information (indicates null session works)
                if stdout.contains("Sharename") || stdout.contains("IPC$") {
                    return Some(
                        Finding::with_confidence(
                            FindingType::NullSession,
                            "Null session enabled - anonymous access allowed".to_string(),
                            95,
                        )
                        .with_metadata("method".to_string(), "smbclient".to_string()),
                    );
                }
            }
        }
        Ok(Err(e)) => {
            debug!("Failed to execute smbclient: {}", e);
        }
        Err(_) => {
            debug!("SMB null session check timed out");
        }
    }

    None
}

/// Enumerate SMB shares
async fn enumerate_shares(target_ip: &str, timeout: Duration, depth: EnumDepth) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Try with null session first
    let output = tokio::time::timeout(
        timeout,
        Command::new("smbclient")
            .args(&["-N", "-L", &format!("//{}", target_ip)])
            .output(),
    )
    .await;

    if let Ok(Ok(result)) = output {
        if result.status.success() {
            let stdout = String::from_utf8_lossy(&result.stdout);
            findings.extend(parse_smbclient_shares(&stdout));
        }
    }

    // For aggressive scans, try common credentials
    if matches!(depth, EnumDepth::Aggressive) && findings.is_empty() {
        let common_creds = vec![
            ("guest", ""),
            ("administrator", ""),
            ("admin", "admin"),
            ("administrator", "password"),
        ];

        for (username, password) in common_creds {
            let auth_args = if password.is_empty() {
                format!("-U {}%", username)
            } else {
                format!("-U {}%{}", username, password)
            };

            let output = tokio::time::timeout(
                timeout,
                Command::new("smbclient")
                    .args(&[&auth_args, "-L", &format!("//{}", target_ip)])
                    .output(),
            )
            .await;

            if let Ok(Ok(result)) = output {
                if result.status.success() {
                    let stdout = String::from_utf8_lossy(&result.stdout);
                    findings.extend(parse_smbclient_shares(&stdout));

                    // Add finding for valid credentials
                    findings.push(
                        Finding::with_confidence(
                            FindingType::DefaultCredentials,
                            format!("SMB: {}:{}", username, if password.is_empty() { "(empty)" } else { password }),
                            90,
                        )
                        .with_metadata("username".to_string(), username.to_string())
                        .with_metadata("password".to_string(), password.to_string()),
                    );

                    break; // Found valid creds, stop trying
                }
            }
        }
    }

    findings
}

/// Parse smbclient share listing output
fn parse_smbclient_shares(output: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    for line in output.lines() {
        let line = line.trim();

        // Look for share lines (format: "ShareName    Type    Comment")
        // Skip header lines
        if line.contains("Sharename") || line.contains("---") || line.is_empty() {
            continue;
        }

        // Parse share information
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            let share_name = parts[0];
            let share_type = parts.get(1).unwrap_or(&"Unknown");

            // Determine if it's an interesting share
            let is_interesting = match share_name {
                "IPC$" | "ADMIN$" | "C$" => false, // Default administrative shares
                _ => true,
            };

            let confidence = if is_interesting { 90 } else { 70 };

            let mut finding = Finding::with_confidence(
                FindingType::Share,
                share_name.to_string(),
                confidence,
            )
            .with_metadata("share_type".to_string(), share_type.to_string());

            // Add comment if available
            if parts.len() >= 3 {
                let comment = parts[2..].join(" ");
                finding = finding.with_metadata("comment".to_string(), comment);
            }

            findings.push(finding);
        }
    }

    findings
}

/// Get domain information
async fn get_domain_info(target_ip: &str, timeout: Duration) -> Option<Vec<Finding>> {
    let mut findings = Vec::new();

    // Use rpcclient to get domain info
    let output = tokio::time::timeout(
        timeout,
        Command::new("rpcclient")
            .args(&[
                "-U", "%",  // Null session
                "-c", "lsaquery",
                target_ip,
            ])
            .output(),
    )
    .await;

    if let Ok(Ok(result)) = output {
        if result.status.success() {
            let stdout = String::from_utf8_lossy(&result.stdout);

            // Parse domain name
            for line in stdout.lines() {
                if line.contains("Domain Name:") {
                    if let Some(domain) = line.split(':').nth(1) {
                        let domain = domain.trim();
                        findings.push(
                            Finding::new(
                                FindingType::Domain,
                                domain.to_string(),
                            )
                            .with_metadata("source".to_string(), "lsaquery".to_string()),
                        );
                    }
                }

                if line.contains("Domain SID:") {
                    if let Some(sid) = line.split(':').nth(1) {
                        let sid = sid.trim();
                        findings.push(
                            Finding::new(
                                FindingType::InformationDisclosure,
                                format!("Domain SID: {}", sid),
                            )
                            .with_metadata("sid".to_string(), sid.to_string()),
                        );
                    }
                }
            }
        }
    }

    if findings.is_empty() {
        None
    } else {
        Some(findings)
    }
}

/// Enumerate users
async fn enumerate_users(target_ip: &str, timeout: Duration, depth: EnumDepth) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Use rpcclient to enumerate users
    let output = tokio::time::timeout(
        timeout,
        Command::new("rpcclient")
            .args(&[
                "-U", "%",  // Null session
                "-c", "enumdomusers",
                target_ip,
            ])
            .output(),
    )
    .await;

    if let Ok(Ok(result)) = output {
        if result.status.success() {
            let stdout = String::from_utf8_lossy(&result.stdout);

            // Parse user enumeration output
            // Format: user:[username] rid:[0xHEX]
            for line in stdout.lines() {
                if line.contains("user:[") {
                    if let Some(username_part) = line.split("user:[").nth(1) {
                        if let Some(username) = username_part.split(']').next() {
                            let mut finding = Finding::new(
                                FindingType::User,
                                username.to_string(),
                            );

                            // Extract RID if available
                            if let Some(rid_part) = line.split("rid:[").nth(1) {
                                if let Some(rid) = rid_part.split(']').next() {
                                    finding = finding.with_metadata("rid".to_string(), rid.to_string());
                                }
                            }

                            findings.push(finding);
                        }
                    }
                }
            }
        }
    }

    // For aggressive scans, also try with enum4linux if available
    if matches!(depth, EnumDepth::Aggressive) && findings.is_empty() {
        if let Some(enum4linux_findings) = enumerate_users_enum4linux(target_ip, timeout).await {
            findings.extend(enum4linux_findings);
        }
    }

    findings
}

/// Enumerate users using enum4linux
async fn enumerate_users_enum4linux(target_ip: &str, timeout: Duration) -> Option<Vec<Finding>> {
    let mut findings = Vec::new();

    let output = tokio::time::timeout(
        timeout * 2, // enum4linux can be slower
        Command::new("enum4linux")
            .args(&["-U", target_ip])
            .output(),
    )
    .await;

    if let Ok(Ok(result)) = output {
        let stdout = String::from_utf8_lossy(&result.stdout);

        // Parse enum4linux output for users
        let mut in_user_section = false;
        for line in stdout.lines() {
            if line.contains("Users on") || line.contains("user:") {
                in_user_section = true;
            }

            if in_user_section && line.trim().starts_with("user:[") {
                if let Some(username_part) = line.split("user:[").nth(1) {
                    if let Some(username) = username_part.split(']').next() {
                        findings.push(
                            Finding::new(
                                FindingType::User,
                                username.to_string(),
                            )
                            .with_metadata("source".to_string(), "enum4linux".to_string()),
                        );
                    }
                }
            }
        }
    }

    if findings.is_empty() {
        None
    } else {
        Some(findings)
    }
}

/// Enumerate groups
async fn enumerate_groups(target_ip: &str, timeout: Duration) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Use rpcclient to enumerate groups
    let output = tokio::time::timeout(
        timeout,
        Command::new("rpcclient")
            .args(&[
                "-U", "%",  // Null session
                "-c", "enumdomgroups",
                target_ip,
            ])
            .output(),
    )
    .await;

    if let Ok(Ok(result)) = output {
        if result.status.success() {
            let stdout = String::from_utf8_lossy(&result.stdout);

            // Parse group enumeration output
            // Format: group:[groupname] rid:[0xHEX]
            for line in stdout.lines() {
                if line.contains("group:[") {
                    if let Some(groupname_part) = line.split("group:[").nth(1) {
                        if let Some(groupname) = groupname_part.split(']').next() {
                            let mut finding = Finding::new(
                                FindingType::Group,
                                groupname.to_string(),
                            );

                            // Extract RID if available
                            if let Some(rid_part) = line.split("rid:[").nth(1) {
                                if let Some(rid) = rid_part.split(']').next() {
                                    finding = finding.with_metadata("rid".to_string(), rid.to_string());
                                }
                            }

                            findings.push(finding);
                        }
                    }
                }
            }
        }
    }

    findings
}

/// Get password policy
async fn get_password_policy(target_ip: &str, timeout: Duration) -> Option<Vec<Finding>> {
    let mut findings = Vec::new();

    let output = tokio::time::timeout(
        timeout,
        Command::new("rpcclient")
            .args(&[
                "-U", "%",
                "-c", "getdompwinfo",
                target_ip,
            ])
            .output(),
    )
    .await;

    if let Ok(Ok(result)) = output {
        if result.status.success() {
            let stdout = String::from_utf8_lossy(&result.stdout);

            let mut policy_info = HashMap::new();

            for line in stdout.lines() {
                if line.contains("min_password_length:") {
                    if let Some(value) = line.split(':').nth(1) {
                        policy_info.insert("min_length".to_string(), value.trim().to_string());
                    }
                }
                if line.contains("password_properties:") {
                    if let Some(value) = line.split(':').nth(1) {
                        policy_info.insert("properties".to_string(), value.trim().to_string());
                    }
                }
            }

            if !policy_info.is_empty() {
                let mut finding = Finding::new(
                    FindingType::Policy,
                    format!("Password Policy: {}",
                        policy_info.get("min_length").unwrap_or(&"unknown".to_string())
                    ),
                );

                for (key, value) in policy_info {
                    finding = finding.with_metadata(key, value);
                }

                findings.push(finding);
            }
        }
    }

    if findings.is_empty() {
        None
    } else {
        Some(findings)
    }
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
    fn test_parse_smbclient_shares() {
        let output = r#"
        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        SharedDocs      Disk      Company Documents
        "#;

        let findings = parse_smbclient_shares(output);
        assert!(findings.len() >= 3);

        // Check for shared docs (interesting share)
        let shared_docs = findings.iter().find(|f| f.value == "SharedDocs");
        assert!(shared_docs.is_some());
        assert_eq!(shared_docs.unwrap().confidence, 90);
    }
}
