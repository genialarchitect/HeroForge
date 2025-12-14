use super::types::{EnumDepth, EnumerationResult, Finding, FindingType, ServiceType};
use crate::types::{ScanProgressMessage, ScanTarget};
use anyhow::Result;
use log::{debug, info};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};
use tokio::sync::broadcast::Sender;

/// Enumerate LDAP service
pub async fn enumerate_ldap(
    target: &ScanTarget,
    port: u16,
    depth: EnumDepth,
    timeout: Duration,
    progress_tx: Option<Sender<ScanProgressMessage>>,
) -> Result<EnumerationResult> {
    let start = Instant::now();
    info!(
        "Starting LDAP enumeration for {}:{} with depth: {:?}",
        target.ip, port, depth
    );

    let mut findings = Vec::new();
    let mut metadata = HashMap::new();
    let target_ip = target.ip.to_string();

    // Step 1: Test anonymous bind
    match test_anonymous_bind(&target_ip, port, timeout).await {
        Ok(Some(anon_result)) => {
            if anon_result.success {
                findings.push(
                    Finding::with_confidence(
                        FindingType::AnonymousBind,
                        "LDAP anonymous bind allowed".to_string(),
                        95,
                    )
                    .with_metadata(
                        "description".to_string(),
                        "Server accepts anonymous LDAP connections".to_string(),
                    ),
                );
                send_progress(&progress_tx, &target_ip, port, "AnonymousBind", "Anonymous bind allowed");
                metadata.insert("anonymous_bind".to_string(), "true".to_string());
            } else {
                metadata.insert("anonymous_bind".to_string(), "false".to_string());
            }
        }
        Ok(None) => {
            debug!("Could not test anonymous bind on {}", target_ip);
        }
        Err(e) => {
            debug!("Anonymous bind test failed: {}", e);
        }
    }

    // Passive mode stops here
    if matches!(depth, EnumDepth::Passive) {
        return Ok(EnumerationResult {
            service_type: ServiceType::Ldap,
            enumeration_depth: depth,
            findings,
            duration: start.elapsed(),
            metadata,
        });
    }

    // Step 2: Query RootDSE for server info
    match query_rootdse(&target_ip, port, timeout).await {
        Ok(Some(rootdse)) => {
            if !rootdse.naming_contexts.is_empty() {
                metadata.insert("naming_contexts".to_string(), rootdse.naming_contexts.join(", "));

                for nc in &rootdse.naming_contexts {
                    findings.push(
                        Finding::new(FindingType::BaseDn, nc.clone())
                            .with_metadata("type".to_string(), "naming_context".to_string()),
                    );
                }
            }

            if !rootdse.supported_controls.is_empty() {
                metadata.insert("supported_controls".to_string(), rootdse.supported_controls.len().to_string());
            }

            if !rootdse.vendor_info.is_empty() {
                findings.push(
                    Finding::new(FindingType::Version, rootdse.vendor_info.clone())
                        .with_metadata("source".to_string(), "rootDSE".to_string()),
                );
                metadata.insert("vendor".to_string(), rootdse.vendor_info);
            }

            // Check for null base search capability
            if rootdse.null_base_search {
                findings.push(
                    Finding::with_confidence(
                        FindingType::Misconfiguration,
                        "Null base search allowed".to_string(),
                        80,
                    )
                    .with_metadata(
                        "description".to_string(),
                        "Server allows searching with empty base DN".to_string(),
                    ),
                );
            }
        }
        Ok(None) => {
            debug!("Could not query RootDSE on {}", target_ip);
        }
        Err(e) => {
            debug!("RootDSE query failed: {}", e);
        }
    }

    // Aggressive mode: Try user enumeration
    if matches!(depth, EnumDepth::Aggressive) {
        // Check if we can enumerate users (only if anon bind succeeded)
        if metadata.get("anonymous_bind") == Some(&"true".to_string()) {
            findings.push(
                Finding::with_confidence(
                    FindingType::Misconfiguration,
                    "Anonymous bind + accessible directory = potential user enumeration".to_string(),
                    75,
                )
                .with_metadata("severity".to_string(), "Medium".to_string()),
            );
        }
    }

    metadata.insert("findings_count".to_string(), findings.len().to_string());

    Ok(EnumerationResult {
        service_type: ServiceType::Ldap,
        enumeration_depth: depth,
        findings,
        duration: start.elapsed(),
        metadata,
    })
}

struct AnonBindResult {
    success: bool,
}

struct RootDSEInfo {
    naming_contexts: Vec<String>,
    supported_controls: Vec<String>,
    vendor_info: String,
    null_base_search: bool,
}

async fn test_anonymous_bind(target_ip: &str, port: u16, timeout: Duration) -> Result<Option<AnonBindResult>> {
    let target_ip = target_ip.to_string();

    tokio::task::spawn_blocking(move || {
        let addr = format!("{}:{}", target_ip, port);
        let mut stream = TcpStream::connect_timeout(&addr.parse()?, timeout)?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;

        // Build anonymous bind request
        let bind_request = build_ldap_bind_request(1, "", "");
        stream.write_all(&bind_request)?;
        stream.flush()?;

        // Read response
        let mut response = vec![0u8; 512];
        let n = stream.read(&mut response)?;

        if n > 10 {
            // Check for successful bind response
            // LDAPMessage { messageID, CHOICE { bindResponse [APPLICATION 1] ... }}
            // Success is resultCode = 0
            let _success = response.iter().skip(5).take(20).any(|&b| b == 0x61)  // BindResponse tag
                && response.iter().skip(10).take(10).any(|&b| b == 0x0a);  // ENUMERATED for resultCode

            return Ok(Some(AnonBindResult {
                success: n > 0 && !response[..n].iter().any(|&b| b == 49), // 49 = invalidCredentials
            }));
        }

        Ok(None)
    })
    .await?
}

async fn query_rootdse(target_ip: &str, port: u16, timeout: Duration) -> Result<Option<RootDSEInfo>> {
    let target_ip = target_ip.to_string();

    tokio::task::spawn_blocking(move || {
        let addr = format!("{}:{}", target_ip, port);
        let mut stream = TcpStream::connect_timeout(&addr.parse()?, timeout)?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;

        // Bind first
        let bind_request = build_ldap_bind_request(1, "", "");
        stream.write_all(&bind_request)?;
        stream.flush()?;

        let mut response = vec![0u8; 512];
        stream.read(&mut response)?;

        // Search RootDSE
        let search_request = build_ldap_search_request(2, "", "(objectClass=*)");
        stream.write_all(&search_request)?;
        stream.flush()?;

        let mut response = vec![0u8; 4096];
        let n = stream.read(&mut response)?;

        if n > 0 {
            // Parse response for naming contexts and other info
            let response_str = String::from_utf8_lossy(&response[..n]);

            let mut info = RootDSEInfo {
                naming_contexts: Vec::new(),
                supported_controls: Vec::new(),
                vendor_info: String::new(),
                null_base_search: false,
            };

            // Look for common attributes in response
            // This is a simplified parser - real LDAP parsing would use proper BER/DER decoding

            // Check for naming contexts
            if response_str.to_lowercase().contains("dc=") {
                // Extract DC components
                for word in response_str.split(|c: char| !c.is_alphanumeric() && c != '=' && c != ',') {
                    if word.starts_with("dc=") || word.starts_with("DC=") {
                        info.naming_contexts.push(word.to_string());
                        break; // Just get the first one for now
                    }
                }
            }

            // Check for vendor info
            if response_str.to_lowercase().contains("openldap") {
                info.vendor_info = "OpenLDAP".to_string();
            } else if response_str.to_lowercase().contains("microsoft") || response_str.contains("Active Directory") {
                info.vendor_info = "Microsoft Active Directory".to_string();
            } else if response_str.contains("389") {
                info.vendor_info = "389 Directory Server".to_string();
            }

            // Null base search worked if we got a response
            info.null_base_search = n > 20;

            return Ok(Some(info));
        }

        Ok(None)
    })
    .await?
}

/// Build LDAP BindRequest
fn build_ldap_bind_request(message_id: u32, name: &str, password: &str) -> Vec<u8> {
    let mut request = Vec::new();

    // Build bind request operation
    let mut bind_op = Vec::new();
    // Version (INTEGER 3)
    bind_op.extend(&[0x02, 0x01, 0x03]);
    // Name (OCTET STRING)
    bind_op.push(0x04);
    bind_op.push(name.len() as u8);
    bind_op.extend(name.as_bytes());
    // Simple authentication (context tag 0)
    bind_op.push(0x80);
    bind_op.push(password.len() as u8);
    bind_op.extend(password.as_bytes());

    // Wrap in BindRequest (APPLICATION 0)
    let mut bind_req = Vec::new();
    bind_req.push(0x60); // APPLICATION 0
    bind_req.push(bind_op.len() as u8);
    bind_req.extend(bind_op);

    // Build LDAPMessage
    let mut message = Vec::new();
    // Message ID
    message.push(0x02);
    message.push(0x01);
    message.push(message_id as u8);
    // BindRequest
    message.extend(bind_req);

    // Wrap in SEQUENCE
    request.push(0x30);
    request.push(message.len() as u8);
    request.extend(message);

    request
}

/// Build LDAP SearchRequest
fn build_ldap_search_request(message_id: u32, base_dn: &str, filter: &str) -> Vec<u8> {
    let mut request = Vec::new();

    // Build search request operation
    let mut search_op = Vec::new();

    // Base DN (OCTET STRING)
    search_op.push(0x04);
    search_op.push(base_dn.len() as u8);
    search_op.extend(base_dn.as_bytes());

    // Scope (ENUMERATED 0 = baseObject)
    search_op.extend(&[0x0a, 0x01, 0x00]);

    // DerefAliases (ENUMERATED 0 = neverDerefAliases)
    search_op.extend(&[0x0a, 0x01, 0x00]);

    // SizeLimit (INTEGER 100)
    search_op.extend(&[0x02, 0x01, 0x64]);

    // TimeLimit (INTEGER 10)
    search_op.extend(&[0x02, 0x01, 0x0a]);

    // TypesOnly (BOOLEAN FALSE)
    search_op.extend(&[0x01, 0x01, 0x00]);

    // Filter - present filter (objectClass=*)
    if filter == "(objectClass=*)" {
        search_op.push(0x87); // present filter tag
        let attr = "objectClass";
        search_op.push(attr.len() as u8);
        search_op.extend(attr.as_bytes());
    } else {
        // Default to present filter
        search_op.push(0x87);
        search_op.push(0x0b);
        search_op.extend(b"objectClass");
    }

    // Attributes (empty sequence = all)
    search_op.extend(&[0x30, 0x00]);

    // Wrap in SearchRequest (APPLICATION 3)
    let mut search_req = Vec::new();
    search_req.push(0x63); // APPLICATION 3
    search_req.push(search_op.len() as u8);
    search_req.extend(search_op);

    // Build LDAPMessage
    let mut message = Vec::new();
    // Message ID
    message.push(0x02);
    message.push(0x01);
    message.push(message_id as u8);
    // SearchRequest
    message.extend(search_req);

    // Wrap in SEQUENCE
    request.push(0x30);
    request.push(message.len() as u8);
    request.extend(message);

    request
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
    fn test_build_bind_request() {
        let request = build_ldap_bind_request(1, "", "");
        // Should start with SEQUENCE tag
        assert_eq!(request[0], 0x30);
    }

    #[test]
    fn test_build_search_request() {
        let request = build_ldap_search_request(1, "", "(objectClass=*)");
        assert_eq!(request[0], 0x30);
    }
}
