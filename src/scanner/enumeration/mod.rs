pub mod types;
pub mod wordlists;
pub mod http_enum;
pub mod dns_enum;
pub mod db_enum;
pub mod smb_enum;
pub mod ftp_enum;
pub mod ssh_enum;
pub mod smtp_enum;
pub mod ldap_enum;
pub mod ssl_enum;

use crate::types::{HostInfo, PortInfo, ScanConfig, ScanProgressMessage, ScanTarget};
use anyhow::Result;
use log::{debug, info};
use tokio::sync::broadcast::Sender;
use types::{EnumerationResult, ServiceType};

/// Main entry point for service enumeration
/// Called from the scanner pipeline after service detection
pub async fn enumerate_services(
    host_info: &mut HostInfo,
    config: &ScanConfig,
    progress_tx: Option<Sender<ScanProgressMessage>>,
) -> Result<()> {
    if !config.enable_enumeration {
        return Ok(());
    }

    info!(
        "Starting enumeration for {} with depth: {:?}",
        host_info.target.ip, config.enum_depth
    );

    let target = &host_info.target;

    // Iterate through all ports with detected services
    for port_info in &mut host_info.ports {
        if port_info.service.is_none() {
            continue;
        }

        // Clone port info data we need for enumeration
        let port = port_info.port;
        let service_name = port_info.service.as_ref().unwrap().name.clone();

        // Attempt enumeration for this service
        match enumerate_service_by_port(target, port, &service_name, config, progress_tx.clone()).await {
                Ok(Some(enum_result)) => {
                    debug!(
                        "Enumeration completed for {}:{} - {} findings",
                        target.ip,
                        port,
                        enum_result.findings.len()
                    );
                    // Store the result
                    if let Some(ref mut service) = port_info.service {
                        service.enumeration = Some(enum_result);
                    }
                }
                Ok(None) => {
                    debug!(
                        "No enumeration performed for {}:{} (service not supported or disabled)",
                        target.ip, port
                    );
                }
                Err(e) => {
                    debug!(
                        "Enumeration failed for {}:{}: {}",
                        target.ip, port, e
                    );
                    // Continue with other services even if one fails
                }
            }
    }

    Ok(())
}

/// Enumerate a specific service by port and service name
async fn enumerate_service_by_port(
    target: &ScanTarget,
    port: u16,
    service_name: &str,
    config: &ScanConfig,
    progress_tx: Option<Sender<ScanProgressMessage>>,
) -> Result<Option<EnumerationResult>> {
    // Determine service type from service name and port
    let service_type = determine_service_type(service_name, port);

    // Check if this service type should be enumerated
    if !config.enum_services.is_empty() && !config.enum_services.contains(&service_type) {
        return Ok(None);
    }

    // Send progress message
    send_progress(
        &progress_tx,
        ScanProgressMessage::EnumerationStarted {
            ip: target.ip.to_string(),
            port,
            service_type: service_type.to_string(),
        },
    );

    // Dispatch to appropriate enumeration module based on service type
    let result = match service_type {
        ServiceType::Http | ServiceType::Https => {
            http_enum::enumerate_http(
                target,
                port,
                service_type == ServiceType::Https,
                config.enum_depth,
                &config.enum_wordlist_path,
                config.timeout,
                progress_tx.clone(),
            )
            .await
        }
        ServiceType::Dns => {
            dns_enum::enumerate_dns(
                target,
                config.enum_depth,
                &config.enum_wordlist_path,
                config.timeout,
                progress_tx.clone(),
            )
            .await
        }
        ServiceType::Database(ref db_type) => {
            db_enum::enumerate_database(
                target,
                port,
                db_type.clone(),
                config.enum_depth,
                config.timeout,
                progress_tx.clone(),
            )
            .await
        }
        ServiceType::Smb => {
            smb_enum::enumerate_smb(
                target,
                port,
                config.enum_depth,
                config.timeout,
                progress_tx.clone(),
            )
            .await
        }
        ServiceType::Ftp => {
            ftp_enum::enumerate_ftp(
                target,
                port,
                config.enum_depth,
                config.timeout,
                progress_tx.clone(),
            )
            .await
        }
        ServiceType::Ssh => {
            ssh_enum::enumerate_ssh(
                target,
                port,
                config.enum_depth,
                config.timeout,
                progress_tx.clone(),
            )
            .await
        }
        ServiceType::Smtp => {
            smtp_enum::enumerate_smtp(
                target,
                port,
                config.enum_depth,
                config.timeout,
                progress_tx.clone(),
            )
            .await
        }
        ServiceType::Ldap => {
            ldap_enum::enumerate_ldap(
                target,
                port,
                config.enum_depth,
                config.timeout,
                progress_tx.clone(),
            )
            .await
        }
    };

    // Send completion message
    if let Ok(ref enum_result) = result {
        send_progress(
            &progress_tx,
            ScanProgressMessage::EnumerationCompleted {
                ip: target.ip.to_string(),
                port,
                findings_count: enum_result.findings.len(),
            },
        );

        // Send individual findings as progress messages
        for finding in &enum_result.findings {
            send_progress(
                &progress_tx,
                ScanProgressMessage::EnumerationFinding {
                    ip: target.ip.to_string(),
                    port,
                    finding_type: finding.finding_type.to_string(),
                    value: finding.value.clone(),
                },
            );
        }
    }

    result.map(Some)
}

/// Determine service type from service name and port
fn determine_service_type(service_name: &str, port: u16) -> ServiceType {
    let name_lower = service_name.to_lowercase();

    // Check for HTTP/HTTPS
    if name_lower.contains("http") {
        if name_lower.contains("https") || port == 443 || port == 8443 {
            return ServiceType::Https;
        }
        return ServiceType::Http;
    }

    // Check for SMB
    if name_lower.contains("smb") || name_lower.contains("microsoft-ds") || port == 445 || port == 139 {
        return ServiceType::Smb;
    }

    // Check for DNS
    if name_lower.contains("dns") || name_lower.contains("domain") || port == 53 {
        return ServiceType::Dns;
    }

    // Check for databases
    if name_lower.contains("mysql") || port == 3306 {
        return ServiceType::Database(types::DbType::MySQL);
    }
    if name_lower.contains("postgres") || port == 5432 {
        return ServiceType::Database(types::DbType::PostgreSQL);
    }
    if name_lower.contains("mongo") || port == 27017 {
        return ServiceType::Database(types::DbType::MongoDB);
    }
    if name_lower.contains("redis") || port == 6379 {
        return ServiceType::Database(types::DbType::Redis);
    }
    if name_lower.contains("elasticsearch") || port == 9200 {
        return ServiceType::Database(types::DbType::Elasticsearch);
    }

    // Check for FTP
    if name_lower.contains("ftp") || port == 21 || port == 2121 {
        return ServiceType::Ftp;
    }

    // Check for SSH
    if name_lower.contains("ssh") || port == 22 {
        return ServiceType::Ssh;
    }

    // Check for SMTP
    if name_lower.contains("smtp") || name_lower.contains("mail") || port == 25 || port == 587 {
        return ServiceType::Smtp;
    }

    // Check for LDAP
    if name_lower.contains("ldap") || port == 389 || port == 636 {
        return ServiceType::Ldap;
    }

    // Default to HTTPS for SSL ports
    if port == 443 || port == 8443 {
        return ServiceType::Https;
    }

    // Default to HTTP for web-related ports
    if port == 80 || port == 8080 || port == 8000 {
        return ServiceType::Http;
    }

    // If we can't determine, default to HTTP as a fallback
    ServiceType::Http
}

/// Helper function to send progress messages
fn send_progress(tx: &Option<Sender<ScanProgressMessage>>, msg: ScanProgressMessage) {
    if let Some(sender) = tx {
        let _ = sender.send(msg);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_determine_service_type() {
        assert_eq!(
            determine_service_type("http", 80),
            ServiceType::Http
        );
        assert_eq!(
            determine_service_type("https", 443),
            ServiceType::Https
        );
        assert_eq!(
            determine_service_type("apache", 443),
            ServiceType::Https
        );
        assert_eq!(
            determine_service_type("smb", 445),
            ServiceType::Smb
        );
        assert_eq!(
            determine_service_type("mysql", 3306),
            ServiceType::Database(types::DbType::MySQL)
        );
        assert_eq!(
            determine_service_type("postgresql", 5432),
            ServiceType::Database(types::DbType::PostgreSQL)
        );
    }
}
