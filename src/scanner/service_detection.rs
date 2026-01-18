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
        // Services that send banners first (no probe needed)
        21 => None, // FTP sends banner first
        22 => None, // SSH sends banner first
        23 => None, // Telnet sends banner first
        25 => None, // SMTP sends banner first
        110 => None, // POP3 sends banner first
        143 => None, // IMAP sends banner first
        443 => None, // HTTPS requires TLS handshake
        3306 => None, // MySQL sends banner first
        5432 => None, // PostgreSQL sends banner first
        27017 => None, // MongoDB uses binary protocol

        // HTTP/Web services (generic probe)
        // Note: 8443, 8500, 9090 have specific probes below
        80 | 8000 | 8008 | 8080 | 8081 | 8082 | 9000 | 9001 | 3000 | 5000 | 5601 | 8200 | 7001 | 8983 | 7474 | 15672 | 16686 | 9411 => {
            Some("GET / HTTP/1.0\r\nHost: localhost\r\n\r\n".to_string())
        }

        // Elasticsearch/OpenSearch
        9200 | 9300 => Some("GET / HTTP/1.0\r\n\r\n".to_string()),

        // Redis
        6379 => Some("INFO\r\n".to_string()),

        // Memcached
        11211 => Some("stats\r\n".to_string()),

        // CouchDB
        5984 | 6984 => Some("GET / HTTP/1.0\r\n\r\n".to_string()),

        // Cassandra (native protocol version probe)
        9042 => None, // Binary protocol

        // MongoDB HTTP interface (deprecated but may exist)
        27080 | 28017 => Some("GET / HTTP/1.0\r\n\r\n".to_string()),

        // RabbitMQ AMQP (needs specific AMQP handshake)
        5672 => Some("AMQP\x00\x00\x09\x01".to_string()),

        // Docker API
        2375 | 2376 => Some("GET /version HTTP/1.0\r\nHost: localhost\r\n\r\n".to_string()),

        // Kubernetes API / HTTPS alternate
        6443 | 8443 => Some("GET /version HTTP/1.0\r\nHost: localhost\r\n\r\n".to_string()),

        // etcd
        2379 => Some("GET /version HTTP/1.0\r\nHost: localhost\r\n\r\n".to_string()),

        // Consul
        8500 | 8501 => Some("GET /v1/agent/self HTTP/1.0\r\nHost: localhost\r\n\r\n".to_string()),

        // Prometheus
        9090 => Some("GET /api/v1/status/buildinfo HTTP/1.0\r\nHost: localhost\r\n\r\n".to_string()),

        // InfluxDB
        8086 => Some("GET /ping HTTP/1.0\r\nHost: localhost\r\n\r\n".to_string()),

        // Zookeeper (four letter words)
        2181 => Some("stat".to_string()),

        // NATS
        4222 => None, // Sends INFO on connect

        // Jenkins
        50000 => None, // Jenkins agent protocol

        // MQTT
        1883 => None, // Binary protocol

        // LDAP (simple anonymous bind)
        389 | 636 => None, // Requires TLS or specific LDAP packet

        // SNMP
        161 => None, // UDP only, needs SNMP packet

        // Modbus (industrial)
        502 => None, // Binary protocol

        // S7comm (Siemens PLC)
        102 => None, // Binary protocol

        _ => None,
    }
}

fn parse_banner_for_service(service_info: &mut ServiceInfo, banner: &str, port: u16) {
    let banner_lower = banner.to_lowercase();

    // HTTP/HTTPS detection
    if banner.contains("HTTP/") {
        parse_http_banner(service_info, banner, &banner_lower, port);
    }
    // SSH detection
    else if banner.starts_with("SSH-") {
        service_info.name = "ssh".to_string();
        let parts: Vec<&str> = banner.split('-').collect();
        if parts.len() >= 3 {
            service_info.version = Some(parts[2].split_whitespace().next().unwrap_or("").to_string());
        }
        // Detect OpenSSH, Dropbear, etc.
        if banner_lower.contains("openssh") {
            extract_version(&mut service_info.version, banner, "OpenSSH_");
        } else if banner_lower.contains("dropbear") {
            extract_version(&mut service_info.version, banner, "dropbear_");
        }
    }
    // FTP detection
    else if banner.starts_with("220") && (banner_lower.contains("ftp") || port == 21) {
        parse_ftp_banner(service_info, &banner_lower);
    }
    // SMTP detection
    else if banner.starts_with("220") && (banner_lower.contains("smtp") || banner_lower.contains("mail") || port == 25 || port == 587) {
        parse_smtp_banner(service_info, &banner_lower);
    }
    // POP3 detection
    else if banner.starts_with("+OK") && (port == 110 || port == 995) {
        service_info.name = "pop3".to_string();
        if banner_lower.contains("dovecot") {
            service_info.version = Some("Dovecot".to_string());
        } else if banner_lower.contains("courier") {
            service_info.version = Some("Courier".to_string());
        }
    }
    // IMAP detection
    else if banner.starts_with("* OK") && (port == 143 || port == 993) {
        service_info.name = "imap".to_string();
        if banner_lower.contains("dovecot") {
            service_info.version = Some("Dovecot".to_string());
        } else if banner_lower.contains("courier") {
            service_info.version = Some("Courier".to_string());
        } else if banner_lower.contains("cyrus") {
            service_info.version = Some("Cyrus".to_string());
        }
    }
    // MySQL detection
    else if port == 3306 {
        service_info.name = "mysql".to_string();
        // MySQL banner parsing would require binary protocol parsing
        // But we can sometimes catch version from error messages
        if banner_lower.contains("mariadb") {
            service_info.name = "mariadb".to_string();
        }
    }
    // PostgreSQL detection
    else if port == 5432 || banner_lower.contains("postgresql") {
        service_info.name = "postgresql".to_string();
    }
    // Redis detection
    else if banner.starts_with("$") || banner.starts_with("-") || banner_lower.contains("redis") {
        parse_redis_banner(service_info, banner);
    }
    // Memcached detection
    else if banner_lower.contains("stat items") || banner_lower.contains("stat slabs") || (port == 11211 && banner.contains("STAT")) {
        service_info.name = "memcached".to_string();
        if banner.contains("version ") {
            if let Some(ver) = banner.split("version ").nth(1) {
                service_info.version = Some(ver.split_whitespace().next().unwrap_or("").to_string());
            }
        }
    }
    // Elasticsearch/OpenSearch detection
    else if banner_lower.contains("elasticsearch") || banner_lower.contains("opensearch") {
        parse_elasticsearch_banner(service_info, banner, &banner_lower);
    }
    // MongoDB detection
    else if port == 27017 || banner_lower.contains("mongodb") {
        service_info.name = "mongodb".to_string();
    }
    // CouchDB detection
    else if banner_lower.contains("couchdb") || (port == 5984 && banner.contains("couchdb")) {
        service_info.name = "couchdb".to_string();
        if let Some(version) = extract_json_version(banner, "version") {
            service_info.version = Some(version);
        }
    }
    // Docker API detection
    else if banner_lower.contains("docker") || (port == 2375 && banner.contains("ApiVersion")) {
        service_info.name = "docker".to_string();
        if let Some(version) = extract_json_version(banner, "Version") {
            service_info.version = Some(version);
        }
    }
    // Kubernetes API detection
    else if banner_lower.contains("kubernetes") || (port == 6443 && banner.contains("gitVersion")) {
        service_info.name = "kubernetes".to_string();
        if let Some(version) = extract_json_version(banner, "gitVersion") {
            service_info.version = Some(version);
        }
    }
    // etcd detection
    else if banner_lower.contains("etcd") || (port == 2379 && banner.contains("etcdserver")) {
        service_info.name = "etcd".to_string();
        if let Some(version) = extract_json_version(banner, "etcdserver") {
            service_info.version = Some(version);
        }
    }
    // Consul detection
    else if banner_lower.contains("consul") {
        service_info.name = "consul".to_string();
        if let Some(version) = extract_json_version(banner, "Config") {
            service_info.version = Some(version);
        }
    }
    // Prometheus detection
    else if banner_lower.contains("prometheus") {
        service_info.name = "prometheus".to_string();
        if let Some(version) = extract_json_version(banner, "version") {
            service_info.version = Some(version);
        }
    }
    // Grafana detection
    else if banner_lower.contains("grafana") {
        service_info.name = "grafana".to_string();
    }
    // InfluxDB detection
    else if banner_lower.contains("influxdb") || (port == 8086 && banner.contains("X-Influxdb-Version")) {
        service_info.name = "influxdb".to_string();
        for line in banner.lines() {
            if line.to_lowercase().starts_with("x-influxdb-version:") {
                service_info.version = Some(line.split(':').nth(1).unwrap_or("").trim().to_string());
                break;
            }
        }
    }
    // Zookeeper detection
    else if banner_lower.contains("zookeeper") || (port == 2181 && banner.contains("Zookeeper version:")) {
        service_info.name = "zookeeper".to_string();
        if banner.contains("Zookeeper version:") {
            if let Some(ver) = banner.split("version:").nth(1) {
                service_info.version = Some(ver.split(',').next().unwrap_or("").trim().to_string());
            }
        }
    }
    // RabbitMQ detection
    else if banner_lower.contains("rabbitmq") || banner.starts_with("AMQP") {
        service_info.name = "rabbitmq".to_string();
    }
    // Kafka detection
    else if port == 9092 && banner_lower.contains("kafka") {
        service_info.name = "kafka".to_string();
    }
    // NATS detection
    else if banner.starts_with("INFO") && banner.contains("server_id") {
        service_info.name = "nats".to_string();
        if let Some(version) = extract_json_version(banner, "version") {
            service_info.version = Some(version);
        }
    }
    // Cassandra detection
    else if port == 9042 || banner_lower.contains("cassandra") {
        service_info.name = "cassandra".to_string();
    }
    // Neo4j detection
    else if banner_lower.contains("neo4j") {
        service_info.name = "neo4j".to_string();
    }
    // Jenkins detection
    else if banner_lower.contains("jenkins") || banner_lower.contains("x-jenkins") {
        service_info.name = "jenkins".to_string();
        for line in banner.lines() {
            if line.to_lowercase().starts_with("x-jenkins:") {
                service_info.version = Some(line.split(':').nth(1).unwrap_or("").trim().to_string());
                break;
            }
        }
    }
    // GitLab detection
    else if banner_lower.contains("gitlab") {
        service_info.name = "gitlab".to_string();
    }
    // Kibana detection
    else if banner_lower.contains("kibana") || (port == 5601 && banner.contains("kbn-")) {
        service_info.name = "kibana".to_string();
        for line in banner.lines() {
            if line.to_lowercase().starts_with("kbn-version:") {
                service_info.version = Some(line.split(':').nth(1).unwrap_or("").trim().to_string());
                break;
            }
        }
    }
    // Solr detection
    else if banner_lower.contains("solr") {
        service_info.name = "solr".to_string();
    }
    // Splunk detection
    else if banner_lower.contains("splunk") {
        service_info.name = "splunk".to_string();
    }
    // WebLogic detection
    else if banner_lower.contains("weblogic") {
        service_info.name = "weblogic".to_string();
    }
    // Tomcat detection
    else if banner_lower.contains("tomcat") || banner_lower.contains("coyote") {
        service_info.name = "tomcat".to_string();
        if banner_lower.contains("apache-coyote") {
            extract_version(&mut service_info.version, banner, "Apache-Coyote/");
        }
    }
    // JBoss/WildFly detection
    else if banner_lower.contains("jboss") || banner_lower.contains("wildfly") {
        service_info.name = if banner_lower.contains("wildfly") { "wildfly" } else { "jboss" }.to_string();
    }
    // Telnet detection
    else if port == 23 && (banner_lower.contains("login:") || banner_lower.contains("telnet")) {
        service_info.name = "telnet".to_string();
    }
    // Vault detection
    else if banner_lower.contains("vault") || (port == 8200 && banner.contains("initialized")) {
        service_info.name = "vault".to_string();
    }
}

/// Parse HTTP response banner for detailed service info
fn parse_http_banner(service_info: &mut ServiceInfo, banner: &str, banner_lower: &str, port: u16) {
    service_info.name = if port == 443 || port == 8443 || port == 9443 {
        "https".to_string()
    } else {
        "http".to_string()
    };

    // Extract server header
    for line in banner.lines() {
        let line_lower = line.to_lowercase();
        if line_lower.starts_with("server:") {
            let server = line.split(':').nth(1).map(|s| s.trim().to_string());
            if let Some(server_str) = server {
                service_info.version = Some(server_str.clone());
                let server_lower = server_str.to_lowercase();

                // Parse server string for more details
                if server_lower.contains("apache") {
                    service_info.name = "apache".to_string();
                    extract_version(&mut service_info.version, &server_str, "Apache/");
                } else if server_lower.contains("nginx") {
                    service_info.name = "nginx".to_string();
                    extract_version(&mut service_info.version, &server_str, "nginx/");
                } else if server_lower.contains("microsoft-iis") {
                    service_info.name = "microsoft-iis".to_string();
                    extract_version(&mut service_info.version, &server_str, "Microsoft-IIS/");
                } else if server_lower.contains("lighttpd") {
                    service_info.name = "lighttpd".to_string();
                    extract_version(&mut service_info.version, &server_str, "lighttpd/");
                } else if server_lower.contains("openresty") {
                    service_info.name = "openresty".to_string();
                    extract_version(&mut service_info.version, &server_str, "openresty/");
                } else if server_lower.contains("caddy") {
                    service_info.name = "caddy".to_string();
                } else if server_lower.contains("cloudflare") {
                    service_info.name = "cloudflare".to_string();
                } else if server_lower.contains("gunicorn") {
                    service_info.name = "gunicorn".to_string();
                } else if server_lower.contains("uvicorn") {
                    service_info.name = "uvicorn".to_string();
                } else if server_lower.contains("werkzeug") {
                    service_info.name = "werkzeug".to_string();
                } else if server_lower.contains("express") {
                    service_info.name = "express".to_string();
                } else if server_lower.contains("kestrel") {
                    service_info.name = "kestrel".to_string();
                } else if server_lower.contains("jetty") {
                    service_info.name = "jetty".to_string();
                    extract_version(&mut service_info.version, &server_str, "Jetty(");
                }
            }
            break;
        }
    }

    // Check for specific web applications in headers
    for line in banner.lines() {
        let line_lower = line.to_lowercase();
        if line_lower.starts_with("x-powered-by:") {
            let powered_by = line.split(':').nth(1).unwrap_or("").trim();
            if !powered_by.is_empty() {
                // Detect PHP, ASP.NET, Express, etc.
                if powered_by.to_lowercase().contains("php") {
                    service_info.version = Some(format!("{} ({})", service_info.version.as_deref().unwrap_or("http"), powered_by));
                }
            }
        }
    }

    // Detect web applications from body content
    if banner_lower.contains("grafana") {
        service_info.name = "grafana".to_string();
    } else if banner_lower.contains("kibana") {
        service_info.name = "kibana".to_string();
    } else if banner_lower.contains("prometheus") {
        service_info.name = "prometheus".to_string();
    } else if banner_lower.contains("jenkins") {
        service_info.name = "jenkins".to_string();
    } else if banner_lower.contains("gitlab") {
        service_info.name = "gitlab".to_string();
    } else if banner_lower.contains("nexus") {
        service_info.name = "nexus".to_string();
    } else if banner_lower.contains("sonarqube") {
        service_info.name = "sonarqube".to_string();
    } else if banner_lower.contains("artifactory") {
        service_info.name = "artifactory".to_string();
    }
}

/// Parse FTP banner for service details
fn parse_ftp_banner(service_info: &mut ServiceInfo, banner_lower: &str) {
    service_info.name = "ftp".to_string();
    if banner_lower.contains("filezilla") {
        service_info.version = Some("FileZilla".to_string());
    } else if banner_lower.contains("proftpd") {
        service_info.version = Some("ProFTPD".to_string());
    } else if banner_lower.contains("vsftpd") {
        service_info.version = Some("vsftpd".to_string());
    } else if banner_lower.contains("pure-ftpd") {
        service_info.version = Some("Pure-FTPd".to_string());
    } else if banner_lower.contains("microsoft ftp") {
        service_info.version = Some("Microsoft FTP".to_string());
    }
}

/// Parse SMTP banner for service details
fn parse_smtp_banner(service_info: &mut ServiceInfo, banner_lower: &str) {
    service_info.name = "smtp".to_string();
    if banner_lower.contains("postfix") {
        service_info.version = Some("Postfix".to_string());
    } else if banner_lower.contains("exim") {
        service_info.version = Some("Exim".to_string());
    } else if banner_lower.contains("sendmail") {
        service_info.version = Some("Sendmail".to_string());
    } else if banner_lower.contains("microsoft") || banner_lower.contains("exchange") {
        service_info.version = Some("Microsoft Exchange".to_string());
    } else if banner_lower.contains("haraka") {
        service_info.version = Some("Haraka".to_string());
    } else if banner_lower.contains("qmail") {
        service_info.version = Some("qmail".to_string());
    }
}

/// Parse Redis banner for version info
fn parse_redis_banner(service_info: &mut ServiceInfo, banner: &str) {
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

/// Parse Elasticsearch banner for version info
fn parse_elasticsearch_banner(service_info: &mut ServiceInfo, banner: &str, banner_lower: &str) {
    if banner_lower.contains("opensearch") {
        service_info.name = "opensearch".to_string();
    } else {
        service_info.name = "elasticsearch".to_string();
    }
    if let Some(version) = extract_json_version(banner, "number") {
        service_info.version = Some(version);
    }
}

/// Extract version from JSON response
fn extract_json_version(banner: &str, key: &str) -> Option<String> {
    // Simple JSON parsing without a full JSON library
    // Looks for "key":"value" or "key": "value"
    let search_key = format!("\"{}\"", key);
    if let Some(pos) = banner.find(&search_key) {
        let rest = &banner[pos + search_key.len()..];
        // Skip colon and whitespace
        let rest = rest.trim_start_matches(':').trim_start();
        if rest.starts_with('"') {
            // String value
            if let Some(end) = rest[1..].find('"') {
                return Some(rest[1..end + 1].to_string());
            }
        }
    }
    None
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
