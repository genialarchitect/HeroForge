use anyhow::Result;
use crate::scanner::secret_detection::{detect_secrets_in_banner, SecretDetectionConfig};
use crate::types::{HostInfo, PortState, ScanConfig, ServiceInfo, Vulnerability, Severity};
use log::{debug, info};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

pub async fn detect_services(
    host_info: &mut HostInfo,
    config: &ScanConfig,
) -> Result<()> {
    let secret_config = SecretDetectionConfig::default();

    for port_info in &mut host_info.ports {
        if matches!(port_info.state, PortState::Open) {
            debug!(
                "Detecting service on {}:{}",
                host_info.target.ip, port_info.port
            );

            let service = detect_service_on_port(
                host_info.target.ip.to_string().as_str(),
                port_info.port,
                config.timeout,
            )
            .await;

            port_info.service = service;

            // Check service banner for exposed secrets
            if let Some(ref svc) = port_info.service {
                if let Some(ref banner) = svc.banner {
                    let secrets = detect_secrets_in_banner(
                        banner,
                        port_info.port,
                        Some(&svc.name),
                        &secret_config,
                    );

                    if !secrets.is_empty() {
                        info!(
                            "Found {} exposed secret(s) in banner on {}:{}",
                            secrets.len(),
                            host_info.target.ip,
                            port_info.port
                        );

                        for secret in secrets {
                            let severity = match secret.severity {
                                crate::scanner::secret_detection::SecretSeverity::Critical => Severity::Critical,
                                crate::scanner::secret_detection::SecretSeverity::High => Severity::High,
                                crate::scanner::secret_detection::SecretSeverity::Medium => Severity::Medium,
                                crate::scanner::secret_detection::SecretSeverity::Low => Severity::Low,
                            };

                            host_info.vulnerabilities.push(Vulnerability {
                                cve_id: None,
                                title: format!("Exposed {} in Service Banner", secret.secret_type.display_name()),
                                description: format!(
                                    "A {} was detected in the service banner on port {}. \
                                     Exposed value (redacted): {}. Context: {}. \
                                     Remediation: {}",
                                    secret.secret_type.display_name(),
                                    port_info.port,
                                    secret.redacted_value,
                                    secret.context.as_deref().unwrap_or("N/A"),
                                    secret.remediation()
                                ),
                                severity,
                                affected_service: Some(svc.name.clone()),
                            });
                        }
                    }
                }
            }

            // If this is an HTTPS port, perform SSL/TLS scanning
            if is_https_port(port_info.port) {
                if let Some(ref mut svc) = port_info.service {
                    debug!("Scanning SSL/TLS for {}:{}", host_info.target.ip, port_info.port);

                    // Use hostname if available, otherwise use IP
                    let ip_string = host_info.target.ip.to_string();
                    let target_host = host_info
                        .target
                        .hostname
                        .as_ref()
                        .map(|h| h.as_str())
                        .unwrap_or(&ip_string);

                    if let Ok(ssl_info) =
                        crate::scanner::ssl_scanner::scan_ssl(target_host, port_info.port, config.timeout).await
                    {
                        svc.ssl_info = Some(ssl_info);
                    } else {
                        debug!("SSL scan failed for {}:{}", host_info.target.ip, port_info.port);
                    }
                }
            }
        }
    }

    Ok(())
}

/// Check if port is commonly used for HTTPS
fn is_https_port(port: u16) -> bool {
    matches!(port, 443 | 8443 | 9443 | 10443 | 8080 | 8000 | 9000)
}

async fn detect_service_on_port(
    ip: &str,
    port: u16,
    timeout_duration: Duration,
) -> Option<ServiceInfo> {
    // Try to grab banner
    let banner = grab_banner(ip, port, timeout_duration).await;

    // Start with common service name
    let service_name = crate::scanner::port_scanner::get_common_service(port)
        .unwrap_or("unknown")
        .to_string();

    let mut service_info = ServiceInfo {
        name: service_name.clone(),
        version: None,
        banner: banner.clone(),
        cpe: None,
        enumeration: None,
        ssl_info: None,
    };

    // Parse banner to extract service details
    if let Some(ref banner_text) = banner {
        parse_banner_for_service(&mut service_info, banner_text, port);
    }

    Some(service_info)
}

async fn grab_banner(ip: &str, port: u16, timeout_duration: Duration) -> Option<String> {
    let addr = format!("{}:{}", ip, port);

    match timeout(timeout_duration, tokio::net::TcpStream::connect(&addr)).await {
        Ok(Ok(mut stream)) => {
            // Try sending a probe based on the port
            let probe = get_service_probe(port);

            if let Some(probe_data) = probe {
                let _ = stream.write_all(probe_data.as_bytes()).await;
            }

            // Try to read response
            let mut buffer = vec![0u8; 1024];
            match timeout(timeout_duration, stream.read(&mut buffer)).await {
                Ok(Ok(n)) if n > 0 => {
                    let banner = String::from_utf8_lossy(&buffer[..n]).to_string();
                    Some(banner.trim().to_string())
                }
                _ => None,
            }
        }
        _ => None,
    }
}

fn get_service_probe(port: u16) -> Option<String> {
    match port {
        21 => None, // FTP sends banner first
        22 => None, // SSH sends banner first
        25 => None, // SMTP sends banner first
        80 | 8080 | 8443 => Some("GET / HTTP/1.0\r\n\r\n".to_string()),
        443 => None, // HTTPS requires TLS handshake
        110 => None, // POP3 sends banner first
        143 => None, // IMAP sends banner first
        3306 => None, // MySQL sends banner first
        5432 => None, // PostgreSQL sends banner first
        6379 => Some("INFO\r\n".to_string()),
        9200 => Some("GET / HTTP/1.0\r\n\r\n".to_string()),
        27017 => None, // MongoDB uses binary protocol
        _ => None,
    }
}

fn parse_banner_for_service(service_info: &mut ServiceInfo, banner: &str, port: u16) {
    let banner_lower = banner.to_lowercase();

    // HTTP/HTTPS detection
    if banner.contains("HTTP/") {
        service_info.name = if port == 443 || port == 8443 {
            "https".to_string()
        } else {
            "http".to_string()
        };

        // Extract server header
        for line in banner.lines() {
            if line.to_lowercase().starts_with("server:") {
                let server = line.split(':').nth(1).map(|s| s.trim().to_string());
                if let Some(server_str) = server {
                    service_info.version = Some(server_str.clone());

                    // Parse server string for more details
                    if server_str.to_lowercase().contains("apache") {
                        service_info.name = "apache".to_string();
                        extract_version(&mut service_info.version, &server_str, "Apache/");
                    } else if server_str.to_lowercase().contains("nginx") {
                        service_info.name = "nginx".to_string();
                        extract_version(&mut service_info.version, &server_str, "nginx/");
                    } else if server_str.to_lowercase().contains("microsoft-iis") {
                        service_info.name = "microsoft-iis".to_string();
                        extract_version(&mut service_info.version, &server_str, "Microsoft-IIS/");
                    }
                }
                break;
            }
        }
    }
    // SSH detection
    else if banner.starts_with("SSH-") {
        service_info.name = "ssh".to_string();
        let parts: Vec<&str> = banner.split('-').collect();
        if parts.len() >= 3 {
            service_info.version = Some(parts[2].split_whitespace().next().unwrap_or("").to_string());
        }
    }
    // FTP detection
    else if banner.starts_with("220") && (banner_lower.contains("ftp") || port == 21) {
        service_info.name = "ftp".to_string();
        if banner_lower.contains("filezilla") {
            service_info.version = Some("FileZilla".to_string());
        } else if banner_lower.contains("proftpd") {
            service_info.version = Some("ProFTPD".to_string());
        } else if banner_lower.contains("vsftpd") {
            service_info.version = Some("vsftpd".to_string());
        }
    }
    // SMTP detection
    else if banner.starts_with("220") && (banner_lower.contains("smtp") || port == 25) {
        service_info.name = "smtp".to_string();
        if banner_lower.contains("postfix") {
            service_info.version = Some("Postfix".to_string());
        } else if banner_lower.contains("exim") {
            service_info.version = Some("Exim".to_string());
        } else if banner_lower.contains("sendmail") {
            service_info.version = Some("Sendmail".to_string());
        }
    }
    // MySQL detection
    else if port == 3306 {
        service_info.name = "mysql".to_string();
        // MySQL banner parsing would require binary protocol parsing
    }
    // PostgreSQL detection
    else if port == 5432 {
        service_info.name = "postgresql".to_string();
    }
    // Redis detection
    else if banner.starts_with("$") || banner_lower.contains("redis") {
        service_info.name = "redis".to_string();
        if banner.contains("redis_version:") {
            for line in banner.lines() {
                if line.starts_with("redis_version:") {
                    service_info.version = Some(line.split(':').nth(1).unwrap_or("").trim().to_string());
                    break;
                }
            }
        }
    }
    // Elasticsearch detection
    else if port == 9200 && banner.contains("elasticsearch") {
        service_info.name = "elasticsearch".to_string();
    }
}

fn extract_version(version_field: &mut Option<String>, text: &str, prefix: &str) {
    if let Some(start) = text.find(prefix) {
        let version_start = start + prefix.len();
        let version_text = &text[version_start..];
        let version = version_text
            .split_whitespace()
            .next()
            .unwrap_or("")
            .to_string();
        *version_field = Some(version);
    }
}
