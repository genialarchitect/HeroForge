use super::types::{EnumDepth, EnumerationResult, Finding, FindingType, ServiceType};
use super::wordlists::WordlistManager;
use crate::scanner::secret_detection::{
    detect_secrets_in_http_response, detect_secrets_in_header, SecretDetectionConfig,
};
use crate::types::{ScanProgressMessage, ScanTarget};
use anyhow::Result;
use log::{debug, info};
use reqwest::header::HeaderMap;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{broadcast::Sender, Semaphore};

const MAX_CONCURRENT_REQUESTS: usize = 50;

/// Enumerate HTTP/HTTPS service
pub async fn enumerate_http(
    target: &ScanTarget,
    port: u16,
    is_https: bool,
    depth: EnumDepth,
    wordlist_path: &Option<PathBuf>,
    timeout: Duration,
    progress_tx: Option<Sender<ScanProgressMessage>>,
) -> Result<EnumerationResult> {
    let start = Instant::now();
    info!(
        "Starting HTTP enumeration for {}:{} with depth: {:?}",
        target.ip, port, depth
    );

    let mut findings = Vec::new();
    let mut metadata = HashMap::new();

    let base_url = format!(
        "{}://{}:{}",
        if is_https { "https" } else { "http" },
        target.ip,
        port
    );

    metadata.insert("base_url".to_string(), base_url.clone());

    // Create HTTP client with custom settings
    let client = create_http_client(timeout, is_https)?;

    // Passive enumeration: Just analyze what we already have
    if matches!(depth, EnumDepth::Passive) {
        debug!("Passive HTTP enumeration for {}", base_url);

        // Try to fetch the root page and analyze headers
        if let Ok(response) = client.get(&base_url).send().await {
            let headers = response.headers();
            findings.extend(analyze_headers(headers));

            // Try to detect technology from headers
            findings.extend(detect_technology_from_headers(headers));
        }

        return Ok(EnumerationResult {
            service_type: if is_https {
                ServiceType::Https
            } else {
                ServiceType::Http
            },
            enumeration_depth: depth,
            findings,
            duration: start.elapsed(),
            metadata,
        });
    }

    // Active enumeration starts here

    // Step 1: Check common files (robots.txt, sitemap.xml, etc.)
    info!("Checking common files for {}", base_url);
    findings.extend(check_common_files(&client, &base_url).await);

    // Step 2: Analyze headers from root request
    if let Ok(response) = client.get(&base_url).send().await {
        let headers = response.headers();
        findings.extend(analyze_headers(headers));
        findings.extend(detect_technology_from_headers(headers));

        // Store response time
        metadata.insert("response_time_ms".to_string(), "unknown".to_string());
    }

    // Step 3: Directory and file enumeration (light or aggressive)
    if !matches!(depth, EnumDepth::Passive) {
        let wordlist = if let Some(path) = wordlist_path {
            WordlistManager::load_custom_wordlist(path)?
        } else {
            let manager = WordlistManager::new();
            let mut combined = manager.get_http_dir_wordlist(depth).to_vec();
            combined.extend_from_slice(manager.get_http_file_wordlist(depth));
            combined
        };

        debug!("Starting directory/file enumeration with {} entries", wordlist.len());

        let dir_findings = enumerate_paths(
            &client,
            &base_url,
            &wordlist,
            progress_tx.clone(),
            target,
            port,
        )
        .await;

        findings.extend(dir_findings);
    }

    // Store metadata
    metadata.insert("paths_checked".to_string(), findings.len().to_string());

    Ok(EnumerationResult {
        service_type: if is_https {
            ServiceType::Https
        } else {
            ServiceType::Http
        },
        enumeration_depth: depth,
        findings,
        duration: start.elapsed(),
        metadata,
    })
}

/// Create HTTP client with appropriate settings
fn create_http_client(timeout: Duration, is_https: bool) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::limited(3))
        .user_agent("HeroForge/0.1.0");

    // For HTTPS, accept invalid certificates (common in pentesting)
    if is_https {
        builder = builder
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true);
    }

    Ok(builder.build()?)
}

/// Check for common files (robots.txt, sitemap.xml, etc.)
async fn check_common_files(client: &reqwest::Client, base_url: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let secret_config = SecretDetectionConfig::default();

    let common_files = vec![
        "robots.txt",
        "sitemap.xml",
        ".htaccess",
        ".env",
        "config.php",
        "wp-config.php",
        ".git/config",
        ".git/HEAD",
        "package.json",
        "composer.json",
        // Additional files that often contain secrets
        "config.js",
        "config.json",
        "settings.json",
        ".npmrc",
        ".dockerenv",
        "docker-compose.yml",
        "application.properties",
        "application.yml",
        "appsettings.json",
        "credentials.json",
    ];

    for file in common_files {
        let url = format!("{}/{}", base_url, file);

        if let Ok(response) = client.get(&url).send().await {
            if response.status().is_success() {
                let content_type = response
                    .headers()
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());

                let finding_type = match file {
                    "robots.txt" => FindingType::RobotsTxt,
                    "sitemap.xml" => FindingType::SitemapXml,
                    ".env" | "config.php" | "wp-config.php" | "config.js" | "config.json"
                    | "settings.json" | ".npmrc" | "application.properties" | "application.yml"
                    | "appsettings.json" | "credentials.json" | "docker-compose.yml" => {
                        FindingType::ConfigFile
                    }
                    ".git/config" | ".git/HEAD" | ".dockerenv" => FindingType::InformationDisclosure,
                    _ => FindingType::File,
                };

                let mut finding = Finding::new(finding_type, url.clone());
                finding.metadata.insert(
                    "status_code".to_string(),
                    response.status().as_u16().to_string(),
                );

                // Get response body for secret scanning
                if let Ok(body) = response.text().await {
                    // For robots.txt, try to extract interesting paths
                    if file == "robots.txt" && body.len() < 10000 {
                        finding.metadata.insert(
                            "preview".to_string(),
                            body.lines().take(5).collect::<Vec<_>>().join("\n"),
                        );
                    }

                    // Scan for secrets in the response body
                    let secrets = detect_secrets_in_http_response(
                        &body,
                        &url,
                        content_type.as_deref(),
                        &secret_config,
                    );

                    // Convert secret findings to enumeration findings
                    for secret in secrets {
                        let secret_type_name = format!("{:?}", secret.secret_type);
                        let mut secret_finding = Finding::with_confidence(
                            FindingType::ExposedSecret(secret_type_name.clone()),
                            secret.redacted_value.clone(),
                            (secret.confidence * 100.0) as u8,
                        );

                        secret_finding.metadata.insert(
                            "secret_type".to_string(),
                            secret.secret_type.to_string(),
                        );
                        secret_finding.metadata.insert(
                            "severity".to_string(),
                            secret.severity.to_string(),
                        );
                        secret_finding.metadata.insert(
                            "source_url".to_string(),
                            url.clone(),
                        );
                        secret_finding.metadata.insert(
                            "source_file".to_string(),
                            file.to_string(),
                        );
                        if let Some(line) = secret.line_number {
                            secret_finding.metadata.insert(
                                "line_number".to_string(),
                                line.to_string(),
                            );
                        }
                        secret_finding.metadata.insert(
                            "context".to_string(),
                            secret.context.clone(),
                        );
                        secret_finding.metadata.insert(
                            "remediation".to_string(),
                            secret.remediation().to_string(),
                        );

                        findings.push(secret_finding);
                    }
                }

                findings.push(finding);
            }
        }
    }

    findings
}

/// Enumerate directories and files from wordlist
async fn enumerate_paths(
    client: &reqwest::Client,
    base_url: &str,
    wordlist: &[String],
    progress_tx: Option<Sender<ScanProgressMessage>>,
    target: &ScanTarget,
    port: u16,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_REQUESTS));
    let mut tasks = Vec::new();

    for path in wordlist {
        let client = client.clone();
        let base_url = base_url.to_string();
        let path = path.clone();
        let semaphore = semaphore.clone();
        let progress_tx = progress_tx.clone();
        let target_ip = target.ip.to_string();

        let task = tokio::spawn(async move {
            let _permit = semaphore.acquire().await.ok()?;

            // Try both with and without leading slash
            let url = if path.starts_with('/') {
                format!("{}{}", base_url, path)
            } else {
                format!("{}/{}", base_url, path)
            };

            if let Ok(response) = client.get(&url).send().await {
                let status = response.status();

                // Consider 200, 204, 301, 302, 401, 403 as interesting
                if status.is_success()
                    || status.is_redirection()
                    || status.as_u16() == 401
                    || status.as_u16() == 403
                {
                    let finding_type = determine_finding_type(&path, status.as_u16());
                    let mut finding = Finding::with_confidence(
                        finding_type.clone(),
                        url.clone(),
                        if status.is_success() { 95 } else { 75 },
                    );

                    finding.metadata.insert("status_code".to_string(), status.as_u16().to_string());
                    finding.metadata.insert("method".to_string(), "GET".to_string());

                    // Get content length if available
                    if let Some(content_length) = response.headers().get("content-length") {
                        if let Ok(length) = content_length.to_str() {
                            finding.metadata.insert("content_length".to_string(), length.to_string());
                        }
                    }

                    // Send progress update
                    if let Some(tx) = progress_tx {
                        let _ = tx.send(ScanProgressMessage::EnumerationFinding {
                            ip: target_ip,
                            port,
                            finding_type: finding_type.to_string(),
                            value: path.clone(),
                        });
                    }

                    return Some(finding);
                }
            }

            None
        });

        tasks.push(task);
    }

    // Collect results
    for task in tasks {
        if let Ok(Some(finding)) = task.await {
            findings.push(finding);
        }
    }

    findings
}

/// Determine finding type based on path and status code
fn determine_finding_type(path: &str, _status_code: u16) -> FindingType {
    let path_lower = path.to_lowercase();

    // Check for admin panels
    if path_lower.contains("admin")
        || path_lower.contains("dashboard")
        || path_lower.contains("panel")
        || path_lower.contains("manage")
    {
        return FindingType::AdminPanel;
    }

    // Check for backup files
    if path_lower.contains("backup")
        || path_lower.contains(".bak")
        || path_lower.contains(".old")
        || path_lower.contains(".zip")
        || path_lower.contains(".tar")
    {
        return FindingType::BackupFile;
    }

    // Check for config files
    if path_lower.contains("config")
        || path_lower.contains(".env")
        || path_lower.contains("settings")
    {
        return FindingType::ConfigFile;
    }

    // Check if it looks like a file (has extension)
    if path.contains('.') && !path.ends_with('/') {
        return FindingType::File;
    }

    // Default to directory
    FindingType::Directory
}

/// Analyze HTTP response headers
fn analyze_headers(headers: &HeaderMap) -> Vec<Finding> {
    analyze_headers_with_url(headers, "")
}

/// Analyze HTTP response headers with URL context for secret scanning
fn analyze_headers_with_url(headers: &HeaderMap, url: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let secret_config = SecretDetectionConfig::default();

    // Check for Server header
    if let Some(server) = headers.get("server") {
        if let Ok(server_str) = server.to_str() {
            findings.push(
                Finding::new(FindingType::Header, format!("Server: {}", server_str))
                    .with_metadata("header_name".to_string(), "Server".to_string())
                    .with_metadata("header_value".to_string(), server_str.to_string()),
            );
        }
    }

    // Check for X-Powered-By header
    if let Some(powered_by) = headers.get("x-powered-by") {
        if let Ok(powered_str) = powered_by.to_str() {
            findings.push(
                Finding::new(FindingType::Technology, format!("X-Powered-By: {}", powered_str))
                    .with_metadata("header_name".to_string(), "X-Powered-By".to_string())
                    .with_metadata("technology".to_string(), powered_str.to_string()),
            );
        }
    }

    // Check security headers (or lack thereof)
    let security_headers = vec![
        "strict-transport-security",
        "x-frame-options",
        "x-content-type-options",
        "x-xss-protection",
        "content-security-policy",
    ];

    let mut missing_headers = Vec::new();
    for header in security_headers {
        if headers.get(header).is_none() {
            missing_headers.push(header);
        }
    }

    if !missing_headers.is_empty() {
        findings.push(
            Finding::with_confidence(
                FindingType::Misconfiguration,
                format!("Missing security headers: {}", missing_headers.join(", ")),
                60,
            )
            .with_metadata("missing_headers".to_string(), missing_headers.join(",")),
        );
    }

    // Scan headers for exposed secrets (Authorization, X-Api-Key, etc.)
    if !url.is_empty() {
        for (header_name, header_value) in headers.iter() {
            if let Ok(value_str) = header_value.to_str() {
                let header_name_str = header_name.as_str();

                // Check this header for secrets
                let secrets = detect_secrets_in_header(
                    value_str,
                    header_name_str,
                    url,
                    &secret_config,
                );

                for secret in secrets {
                    let secret_type_name = format!("{:?}", secret.secret_type);
                    let mut secret_finding = Finding::with_confidence(
                        FindingType::ExposedSecret(secret_type_name.clone()),
                        secret.redacted_value.clone(),
                        (secret.confidence * 100.0) as u8,
                    );

                    secret_finding.metadata.insert(
                        "secret_type".to_string(),
                        secret.secret_type.to_string(),
                    );
                    secret_finding.metadata.insert(
                        "severity".to_string(),
                        secret.severity.to_string(),
                    );
                    secret_finding.metadata.insert(
                        "source_header".to_string(),
                        header_name_str.to_string(),
                    );
                    secret_finding.metadata.insert(
                        "source_url".to_string(),
                        url.to_string(),
                    );
                    secret_finding.metadata.insert(
                        "remediation".to_string(),
                        secret.remediation().to_string(),
                    );

                    findings.push(secret_finding);
                }
            }
        }
    }

    findings
}

/// Detect technology from HTTP headers
fn detect_technology_from_headers(headers: &HeaderMap) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Check various headers for technology indicators
    let tech_headers = vec![
        ("server", vec!["apache", "nginx", "iis", "tomcat", "jetty"]),
        ("x-powered-by", vec!["php", "asp.net", "express", "django", "rails"]),
        ("x-aspnet-version", vec!["asp.net"]),
        ("x-generator", vec!["drupal", "wordpress", "joomla"]),
    ];

    for (header_name, technologies) in tech_headers {
        if let Some(header_value) = headers.get(header_name) {
            if let Ok(value_str) = header_value.to_str() {
                let value_lower = value_str.to_lowercase();

                for tech in technologies {
                    if value_lower.contains(tech) {
                        findings.push(
                            Finding::new(
                                FindingType::Technology,
                                format!("Detected: {}", tech),
                            )
                            .with_metadata("technology".to_string(), tech.to_string())
                            .with_metadata("source".to_string(), header_name.to_string())
                            .with_metadata("version".to_string(), value_str.to_string()),
                        );
                    }
                }
            }
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_determine_finding_type() {
        assert!(matches!(
            determine_finding_type("/admin", 200),
            FindingType::AdminPanel
        ));
        assert!(matches!(
            determine_finding_type("/backup.zip", 200),
            FindingType::BackupFile
        ));
        assert!(matches!(
            determine_finding_type("/config.php", 200),
            FindingType::ConfigFile
        ));
        assert!(matches!(
            determine_finding_type("/index.html", 200),
            FindingType::File
        ));
        assert!(matches!(
            determine_finding_type("/images/", 200),
            FindingType::Directory
        ));
    }
}
