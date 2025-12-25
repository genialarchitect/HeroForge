#![allow(dead_code)]

use anyhow::{anyhow, Result};
use log::{debug, info, warn};
use std::process::Command;
use std::time::Duration;
use tokio::time::timeout;

use super::types::WhoisInfo;

/// Perform WHOIS lookup for a domain
pub async fn lookup_whois(domain: &str, timeout_secs: u64) -> Result<WhoisInfo> {
    info!("Performing WHOIS lookup for: {}", domain);

    // Use system whois command
    let result = timeout(
        Duration::from_secs(timeout_secs),
        tokio::task::spawn_blocking({
            let domain = domain.to_string();
            move || run_whois_command(&domain)
        }),
    )
    .await??;

    result
}

/// Run the whois command and parse output
fn run_whois_command(domain: &str) -> Result<WhoisInfo> {
    let output = Command::new("whois")
        .arg(domain)
        .output()
        .map_err(|e| anyhow!("Failed to execute whois command: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        warn!("whois command failed: {}", stderr);
        return Err(anyhow!("whois command failed: {}", stderr));
    }

    let raw_data = String::from_utf8_lossy(&output.stdout).to_string();
    debug!("WHOIS raw output length: {} bytes", raw_data.len());

    parse_whois_output(domain, &raw_data)
}

/// Parse WHOIS output into structured data
fn parse_whois_output(domain: &str, raw_data: &str) -> Result<WhoisInfo> {
    let mut info = WhoisInfo {
        domain: domain.to_string(),
        registrar: None,
        registrant_name: None,
        registrant_org: None,
        registrant_email: None,
        creation_date: None,
        expiration_date: None,
        updated_date: None,
        nameservers: Vec::new(),
        status: Vec::new(),
        raw_data: raw_data.to_string(),
    };

    for line in raw_data.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('%') || line.starts_with('#') {
            continue;
        }

        // Parse key-value pairs (handle various formats)
        let parts: Vec<&str> = line.splitn(2, ':').collect();
        if parts.len() != 2 {
            continue;
        }

        let key = parts[0].trim().to_lowercase();
        let value = parts[1].trim();

        if value.is_empty() {
            continue;
        }

        match key.as_str() {
            "registrar" | "sponsoring registrar" | "registrar name" => {
                info.registrar = Some(value.to_string());
            }
            "registrant name" | "registrant" => {
                info.registrant_name = Some(value.to_string());
            }
            "registrant organization" | "registrant org" | "org" | "organization" => {
                info.registrant_org = Some(value.to_string());
            }
            "registrant email" | "admin email" | "tech email" => {
                if info.registrant_email.is_none() {
                    // Mask email for privacy
                    info.registrant_email = Some(mask_email(value));
                }
            }
            "creation date" | "created" | "registered" | "domain registration date" | "created on" => {
                info.creation_date = Some(value.to_string());
            }
            "expiration date" | "expiry date" | "expires" | "registry expiry date" | "registrar registration expiration date" => {
                info.expiration_date = Some(value.to_string());
            }
            "updated date" | "last updated" | "last modified" | "last update" => {
                info.updated_date = Some(value.to_string());
            }
            "name server" | "nameserver" | "nserver" | "ns" => {
                let ns = value.to_lowercase();
                if !info.nameservers.contains(&ns) {
                    info.nameservers.push(ns);
                }
            }
            "domain status" | "status" => {
                let status_value = value.split_whitespace().next().unwrap_or(value);
                if !info.status.contains(&status_value.to_string()) {
                    info.status.push(status_value.to_string());
                }
            }
            _ => {}
        }
    }

    info!(
        "Parsed WHOIS for {}: registrar={:?}, created={:?}, expires={:?}, {} nameservers",
        domain,
        info.registrar,
        info.creation_date,
        info.expiration_date,
        info.nameservers.len()
    );

    Ok(info)
}

/// Mask email address for privacy (show domain only)
fn mask_email(email: &str) -> String {
    if let Some(at_pos) = email.find('@') {
        let domain = &email[at_pos..];
        format!("***{}", domain)
    } else {
        "***".to_string()
    }
}

/// Check if whois command is available
pub fn is_whois_available() -> bool {
    Command::new("whois")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
        || Command::new("which")
            .arg("whois")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mask_email() {
        assert_eq!(mask_email("test@example.com"), "***@example.com");
        assert_eq!(mask_email("noemail"), "***");
    }

    #[test]
    fn test_parse_whois_output() {
        let raw = r#"
Domain Name: EXAMPLE.COM
Registrar: Example Registrar Inc.
Creation Date: 1995-08-14T04:00:00Z
Expiration Date: 2024-08-13T04:00:00Z
Updated Date: 2023-08-14T00:00:00Z
Name Server: NS1.EXAMPLE.COM
Name Server: NS2.EXAMPLE.COM
Domain Status: clientTransferProhibited
Registrant Email: admin@example.com
"#;
        let info = parse_whois_output("example.com", raw).unwrap();
        assert_eq!(info.registrar, Some("Example Registrar Inc.".to_string()));
        assert_eq!(info.nameservers.len(), 2);
        assert!(info.status.contains(&"clientTransferProhibited".to_string()));
    }
}
