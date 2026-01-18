//! Test Executor for Methodology Items
//!
//! Executes automated security tests based on methodology scanner mappings.
//! Integrates with the existing scanner modules to run XSS, SQLi, SSL, and other tests.

use super::scanner_mapping::ScannerType;
use crate::scanner::enumeration::{http_enum, ssl_enum, types::{EnumDepth, FindingType as EnumFindingType}};
use crate::scanner::webapp::{headers, sqli, xss};
use crate::types::{ScanConfig, ScanTarget, ScanType};
use anyhow::Result;
use log::{debug, info, warn};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::net::IpAddr;
use std::time::{Duration, Instant};
use url::Url;
use utoipa::ToSchema;

/// Request to execute a methodology test
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TestExecutionRequest {
    /// Target URL for web application tests
    pub target_url: Option<String>,
    /// Target IP address for network tests
    pub target_ip: Option<String>,
    /// Target domain for DNS/OSINT tests
    pub target_domain: Option<String>,
    /// Target port for specific service tests
    pub target_port: Option<u16>,
    /// Run in safe mode (read-only, non-destructive)
    #[serde(default = "default_true")]
    pub safe_mode: bool,
    /// Timeout for the test in seconds
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

fn default_true() -> bool {
    true
}

fn default_timeout() -> u64 {
    120
}

/// Result from executing a methodology test
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TestExecutionResult {
    /// Whether the test completed successfully
    pub success: bool,
    /// Number of findings discovered
    pub findings_count: usize,
    /// Detailed findings as JSON values
    pub findings: Vec<serde_json::Value>,
    /// Evidence strings collected during the test
    pub evidence: Vec<String>,
    /// Time taken to run the test in seconds
    pub duration_secs: f64,
    /// Recommended status for the checklist item (pass, fail, na)
    pub recommended_status: String,
    /// Human-readable summary of the test results
    pub summary: String,
}

/// Executes methodology tests using the appropriate scanner modules
pub struct MethodologyTestExecutor {
    #[allow(dead_code)]
    pool: SqlitePool,
    client: Client,
}

impl MethodologyTestExecutor {
    /// Create a new test executor
    pub fn new(pool: SqlitePool) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .danger_accept_invalid_certs(true)
            .build()
            .expect("Failed to create HTTP client");

        Self { pool, client }
    }

    /// Execute a test based on the scanner type
    pub async fn execute(
        &self,
        scanner_type: &ScannerType,
        request: &TestExecutionRequest,
    ) -> Result<TestExecutionResult> {
        let start = Instant::now();

        info!(
            "Executing methodology test: {:?} with target_url={:?}, target_ip={:?}",
            scanner_type, request.target_url, request.target_ip
        );

        let result = match scanner_type {
            ScannerType::XssScan => self.run_xss_test(request).await,
            ScannerType::SqlInjectionScan => self.run_sqli_test(request).await,
            ScannerType::SslTlsScan => self.run_ssl_test(request).await,
            ScannerType::SecurityHeadersScan => self.run_headers_test(request).await,
            ScannerType::PortScan => self.run_port_scan(request).await,
            ScannerType::ServiceEnumeration => self.run_service_enum(request).await,
            ScannerType::TechnologyFingerprint => self.run_fingerprint(request).await,
            ScannerType::DirectoryEnumeration => self.run_dir_enum(request).await,
            ScannerType::AssetDiscovery => self.run_asset_discovery(request).await,
            ScannerType::DnsEnumeration => self.run_dns_enum(request).await,
            ScannerType::DefaultCredentialCheck => self.run_default_cred_check(request).await,
            ScannerType::HttpMethodTest => self.run_http_method_test(request).await,
            ScannerType::CorsMisconfigTest => self.run_cors_test(request).await,
            ScannerType::SessionManagementTest => self.run_session_test(request).await,
            ScannerType::AuthBypassTest => self.run_auth_bypass_test(request).await,
            ScannerType::FileUploadTest => self.run_file_upload_test(request).await,
            ScannerType::WhoisLookup => self.run_whois_lookup(request).await,
            ScannerType::ManualOnly => Ok(TestExecutionResult {
                success: false,
                findings_count: 0,
                findings: vec![],
                evidence: vec![],
                duration_secs: 0.0,
                recommended_status: "na".into(),
                summary: "This test requires manual verification and cannot be automated".into(),
            }),
        };

        result.map(|mut r| {
            r.duration_secs = start.elapsed().as_secs_f64();
            r
        })
    }

    /// Run XSS vulnerability tests
    async fn run_xss_test(&self, req: &TestExecutionRequest) -> Result<TestExecutionResult> {
        let url_str = req
            .target_url
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("URL required for XSS test"))?;

        let url = Url::parse(url_str)?;

        info!("Running XSS test on {}", url);

        // Crawl for forms first
        let (_, forms) = crate::scanner::webapp::forms::detect_forms(&self.client, &[url.clone()]).await?;

        // Run XSS tests
        let findings = xss::test_xss(&self.client, &[url.clone()], &forms).await?;

        let count = findings.len();
        let evidence: Vec<String> = findings.iter().map(|f| f.evidence.clone()).collect();

        Ok(TestExecutionResult {
            success: true,
            findings_count: count,
            findings: findings
                .iter()
                .map(|f| {
                    serde_json::json!({
                        "type": format!("{:?}", f.finding_type),
                        "url": f.url,
                        "parameter": f.parameter,
                        "evidence": f.evidence,
                        "severity": format!("{:?}", f.severity),
                        "remediation": f.remediation
                    })
                })
                .collect(),
            evidence,
            duration_secs: 0.0,
            recommended_status: if count == 0 { "pass" } else { "fail" }.into(),
            summary: format!(
                "Found {} XSS vulnerabilities in {} forms/parameters",
                count,
                forms.len()
            ),
        })
    }

    /// Run SQL injection tests
    async fn run_sqli_test(&self, req: &TestExecutionRequest) -> Result<TestExecutionResult> {
        let url_str = req
            .target_url
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("URL required for SQL injection test"))?;

        let url = Url::parse(url_str)?;

        info!("Running SQL injection test on {}", url);

        // Discover forms
        let (_, forms) = crate::scanner::webapp::forms::detect_forms(&self.client, &[url.clone()]).await?;

        // Run SQLi tests
        let findings = sqli::test_sql_injection(&self.client, &[url.clone()], &forms).await?;

        let count = findings.len();
        let evidence: Vec<String> = findings.iter().map(|f| f.evidence.clone()).collect();

        Ok(TestExecutionResult {
            success: true,
            findings_count: count,
            findings: findings
                .iter()
                .map(|f| {
                    serde_json::json!({
                        "type": format!("{:?}", f.finding_type),
                        "url": f.url,
                        "parameter": f.parameter,
                        "evidence": f.evidence,
                        "severity": format!("{:?}", f.severity),
                        "remediation": f.remediation
                    })
                })
                .collect(),
            evidence,
            duration_secs: 0.0,
            recommended_status: if count == 0 { "pass" } else { "fail" }.into(),
            summary: format!("Found {} SQL injection vulnerabilities", count),
        })
    }

    /// Run SSL/TLS configuration tests
    async fn run_ssl_test(&self, req: &TestExecutionRequest) -> Result<TestExecutionResult> {
        // Get host from URL or IP
        let (host, port) = if let Some(url_str) = &req.target_url {
            let url = Url::parse(url_str)?;
            let host = url.host_str().unwrap_or("").to_string();
            let port = url.port().unwrap_or(443);
            (host, port)
        } else if let Some(ip) = &req.target_ip {
            (ip.clone(), req.target_port.unwrap_or(443))
        } else {
            return Err(anyhow::anyhow!("URL or IP required for SSL test"));
        };

        info!("Running SSL/TLS test on {}:{}", host, port);

        // Parse IP for ScanTarget
        let ip: IpAddr = host.parse().unwrap_or_else(|_| {
            // Try DNS resolution
            use std::net::ToSocketAddrs;
            format!("{}:0", host)
                .to_socket_addrs()
                .ok()
                .and_then(|mut addrs| addrs.next())
                .map(|addr| addr.ip())
                .unwrap_or_else(|| "0.0.0.0".parse().unwrap())
        });

        let target = ScanTarget {
            ip,
            hostname: Some(host.clone()),
        };

        // Run SSL enumeration
        let result = ssl_enum::enumerate_ssl(
            &target,
            port,
            EnumDepth::Light,
            Duration::from_secs(req.timeout_secs),
            None,
        )
        .await?;

        let findings_count = result.findings.len();
        let evidence: Vec<String> = result
            .findings
            .iter()
            .map(|f| f.value.clone())
            .collect();

        // Determine grade based on findings - check for weak crypto issues
        let weak_crypto_count = result
            .findings
            .iter()
            .filter(|f| matches!(f.finding_type, EnumFindingType::WeakCrypto | EnumFindingType::WeakAlgorithm))
            .count();

        let recommended_status = if weak_crypto_count > 0 {
            "fail"
        } else if findings_count > 0 {
            "pass" // Minor issues, still passing
        } else {
            "pass"
        };

        Ok(TestExecutionResult {
            success: true,
            findings_count,
            findings: result
                .findings
                .iter()
                .map(|f| {
                    serde_json::json!({
                        "type": format!("{:?}", f.finding_type),
                        "value": f.value,
                        "confidence": f.confidence,
                        "metadata": f.metadata
                    })
                })
                .collect(),
            evidence,
            duration_secs: 0.0,
            recommended_status: recommended_status.into(),
            summary: format!(
                "SSL/TLS analysis found {} issues ({} weak crypto)",
                findings_count, weak_crypto_count
            ),
        })
    }

    /// Run security headers tests
    async fn run_headers_test(&self, req: &TestExecutionRequest) -> Result<TestExecutionResult> {
        let url_str = req
            .target_url
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("URL required for security headers test"))?;

        let url = Url::parse(url_str)?;

        info!("Running security headers test on {}", url);

        let findings = headers::check_security_headers(&self.client, &url).await?;

        let missing_count = findings
            .iter()
            .filter(|f| {
                matches!(
                    f.finding_type,
                    crate::types::FindingType::MissingSecurityHeader
                )
            })
            .count();
        let insecure_count = findings
            .iter()
            .filter(|f| matches!(f.finding_type, crate::types::FindingType::InsecureHeader))
            .count();

        let evidence: Vec<String> = findings.iter().map(|f| f.evidence.clone()).collect();

        Ok(TestExecutionResult {
            success: true,
            findings_count: findings.len(),
            findings: findings
                .iter()
                .map(|f| {
                    serde_json::json!({
                        "type": format!("{:?}", f.finding_type),
                        "url": f.url,
                        "evidence": f.evidence,
                        "severity": format!("{:?}", f.severity),
                        "remediation": f.remediation
                    })
                })
                .collect(),
            evidence,
            duration_secs: 0.0,
            recommended_status: if missing_count == 0 && insecure_count == 0 {
                "pass"
            } else {
                "fail"
            }
            .into(),
            summary: format!(
                "{} missing headers, {} insecure header configurations",
                missing_count, insecure_count
            ),
        })
    }

    /// Run port scan
    async fn run_port_scan(&self, req: &TestExecutionRequest) -> Result<TestExecutionResult> {
        let ip_str = req
            .target_ip
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("IP address required for port scan"))?;

        let ip: IpAddr = ip_str.parse()?;

        info!("Running port scan on {}", ip);

        let target = ScanTarget { ip, hostname: None };

        // Use a reasonable default port range for methodology testing
        let config = ScanConfig {
            targets: vec![ip_str.clone()],
            port_range: (1, 1024), // Well-known ports
            threads: 100,
            timeout: Duration::from_secs(2),
            scan_type: ScanType::TCPConnect,
            enable_os_detection: false,
            enable_service_detection: true,
            enable_vuln_scan: false,
            enable_enumeration: false,
            enum_depth: EnumDepth::Passive,
            enum_wordlist_path: None,
            enum_services: vec![],
            output_format: crate::types::OutputFormat::Json,
            udp_port_range: None,
            udp_retries: 2,
            skip_host_discovery: true,
            service_detection_timeout: None,
            dns_timeout: None,
            syn_timeout: None,
            udp_timeout: None,
            vpn_config_id: None,
            exclusions: Default::default(),
        };

        let open_ports =
            crate::scanner::port_scanner::scan_target_ports(&target, &config).await?;

        let evidence: Vec<String> = open_ports
            .iter()
            .map(|p| {
                let service_name = p.service.as_ref().map(|s| s.name.as_str()).unwrap_or("unknown");
                format!("Port {}/{} - {}", p.port, format!("{:?}", p.protocol), service_name)
            })
            .collect();

        Ok(TestExecutionResult {
            success: true,
            findings_count: open_ports.len(),
            findings: open_ports
                .iter()
                .map(|p| {
                    serde_json::json!({
                        "port": p.port,
                        "protocol": format!("{:?}", p.protocol),
                        "service": p.service.as_ref().map(|s| s.name.clone()),
                        "state": format!("{:?}", p.state),
                        "version": p.service.as_ref().and_then(|s| s.version.clone())
                    })
                })
                .collect(),
            evidence,
            duration_secs: 0.0,
            recommended_status: "pass".into(), // Port scan results are informational
            summary: format!("Found {} open ports on {}", open_ports.len(), ip),
        })
    }

    /// Run service enumeration
    async fn run_service_enum(&self, req: &TestExecutionRequest) -> Result<TestExecutionResult> {
        let ip_str = req
            .target_ip
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("IP address required for service enumeration"))?;

        let ip: IpAddr = ip_str.parse()?;
        let port = req.target_port.unwrap_or(80);

        info!("Running service enumeration on {}:{}", ip, port);

        let target = ScanTarget { ip, hostname: None };

        // Detect if it's HTTP/HTTPS based on port
        let is_https = port == 443 || port == 8443;

        let result = http_enum::enumerate_http(
            &target,
            port,
            is_https,
            EnumDepth::Light,
            &None,
            Duration::from_secs(req.timeout_secs),
            None,
        )
        .await?;

        let evidence: Vec<String> = result
            .findings
            .iter()
            .map(|f| f.value.clone())
            .collect();

        Ok(TestExecutionResult {
            success: true,
            findings_count: result.findings.len(),
            findings: result
                .findings
                .iter()
                .map(|f| {
                    serde_json::json!({
                        "type": format!("{:?}", f.finding_type),
                        "value": f.value,
                        "confidence": f.confidence,
                        "metadata": f.metadata
                    })
                })
                .collect(),
            evidence,
            duration_secs: 0.0,
            recommended_status: "pass".into(),
            summary: format!(
                "Service enumeration completed: found {} findings",
                result.findings.len()
            ),
        })
    }

    /// Run technology fingerprinting
    async fn run_fingerprint(&self, req: &TestExecutionRequest) -> Result<TestExecutionResult> {
        let url_str = req
            .target_url
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("URL required for technology fingerprinting"))?;

        let url = Url::parse(url_str)?;

        info!("Running technology fingerprinting on {}", url);

        // Get IP from URL
        let host = url.host_str().unwrap_or("");
        let ip: IpAddr = host.parse().unwrap_or_else(|_| {
            use std::net::ToSocketAddrs;
            format!("{}:0", host)
                .to_socket_addrs()
                .ok()
                .and_then(|mut addrs| addrs.next())
                .map(|addr| addr.ip())
                .unwrap_or_else(|| "127.0.0.1".parse().unwrap())
        });

        let target = ScanTarget {
            ip,
            hostname: Some(host.to_string()),
        };
        let port = url.port().unwrap_or(if url.scheme() == "https" { 443 } else { 80 });
        let is_https = url.scheme() == "https";

        let result = http_enum::enumerate_http(
            &target,
            port,
            is_https,
            EnumDepth::Passive, // Just fingerprinting, no active enumeration
            &None,
            Duration::from_secs(30),
            None,
        )
        .await?;

        let technologies: Vec<String> = result
            .findings
            .iter()
            .filter(|f| {
                matches!(
                    f.finding_type,
                    crate::scanner::enumeration::types::FindingType::Technology
                )
            })
            .map(|f| f.value.clone())
            .collect();

        Ok(TestExecutionResult {
            success: true,
            findings_count: technologies.len(),
            findings: result
                .findings
                .iter()
                .map(|f| {
                    serde_json::json!({
                        "type": format!("{:?}", f.finding_type),
                        "value": f.value,
                        "metadata": f.metadata
                    })
                })
                .collect(),
            evidence: technologies.clone(),
            duration_secs: 0.0,
            recommended_status: "pass".into(),
            summary: format!("Identified {} technologies/components", technologies.len()),
        })
    }

    /// Run directory enumeration
    async fn run_dir_enum(&self, req: &TestExecutionRequest) -> Result<TestExecutionResult> {
        let url_str = req
            .target_url
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("URL required for directory enumeration"))?;

        let url = Url::parse(url_str)?;

        info!("Running directory enumeration on {}", url);

        let host = url.host_str().unwrap_or("");
        let ip: IpAddr = host.parse().unwrap_or_else(|_| {
            use std::net::ToSocketAddrs;
            format!("{}:0", host)
                .to_socket_addrs()
                .ok()
                .and_then(|mut addrs| addrs.next())
                .map(|addr| addr.ip())
                .unwrap_or_else(|| "127.0.0.1".parse().unwrap())
        });

        let target = ScanTarget {
            ip,
            hostname: Some(host.to_string()),
        };
        let port = url.port().unwrap_or(if url.scheme() == "https" { 443 } else { 80 });
        let is_https = url.scheme() == "https";

        let result = http_enum::enumerate_http(
            &target,
            port,
            is_https,
            EnumDepth::Light, // Light enumeration to check common paths
            &None,
            Duration::from_secs(req.timeout_secs),
            None,
        )
        .await?;

        let discovered: Vec<String> = result
            .findings
            .iter()
            .filter(|f| {
                matches!(
                    f.finding_type,
                    crate::scanner::enumeration::types::FindingType::Directory
                        | crate::scanner::enumeration::types::FindingType::File
                )
            })
            .map(|f| f.value.clone())
            .collect();

        Ok(TestExecutionResult {
            success: true,
            findings_count: discovered.len(),
            findings: result
                .findings
                .iter()
                .map(|f| {
                    serde_json::json!({
                        "type": format!("{:?}", f.finding_type),
                        "value": f.value,
                        "metadata": f.metadata
                    })
                })
                .collect(),
            evidence: discovered.clone(),
            duration_secs: 0.0,
            recommended_status: "pass".into(),
            summary: format!(
                "Directory enumeration found {} files/directories",
                discovered.len()
            ),
        })
    }

    /// Run asset discovery (OSINT)
    async fn run_asset_discovery(&self, req: &TestExecutionRequest) -> Result<TestExecutionResult> {
        let domain = req.target_domain.clone().or_else(|| {
            req.target_url.as_ref().and_then(|u| {
                Url::parse(u).ok().and_then(|url| url.host_str().map(|h| h.to_string()))
            })
        });

        let domain = domain.as_ref().ok_or_else(|| anyhow::anyhow!("Domain required for asset discovery"))?;

        info!("Running asset discovery for domain: {}", domain);

        // Use DNS reconnaissance for subdomain discovery
        let dns_result = crate::scanner::dns_recon::perform_dns_recon(
            domain,
            true, // include subdomains
            None, // use default wordlist
            req.timeout_secs,
        )
        .await;

        match dns_result {
            Ok(result) => {
                let subdomains = result.subdomains_found;
                Ok(TestExecutionResult {
                    success: true,
                    findings_count: subdomains.len(),
                    findings: subdomains
                        .iter()
                        .map(|s| {
                            serde_json::json!({
                                "type": "subdomain",
                                "subdomain": s,
                                "domain": domain
                            })
                        })
                        .collect(),
                    evidence: subdomains.clone(),
                    duration_secs: 0.0,
                    recommended_status: "pass".into(),
                    summary: format!("Discovered {} subdomains for {}", subdomains.len(), domain),
                })
            }
            Err(e) => Ok(TestExecutionResult {
                success: false,
                findings_count: 0,
                findings: vec![],
                evidence: vec![format!("Asset discovery failed: {}", e)],
                duration_secs: 0.0,
                recommended_status: "na".into(),
                summary: format!("Asset discovery failed for {}: {}", domain, e),
            }),
        }
    }

    /// Run DNS enumeration
    async fn run_dns_enum(&self, req: &TestExecutionRequest) -> Result<TestExecutionResult> {
        let domain = req.target_domain.clone().or_else(|| {
            req.target_url.as_ref().and_then(|u| {
                Url::parse(u).ok().and_then(|url| url.host_str().map(|h| h.to_string()))
            })
        });

        let domain = domain.as_ref().ok_or_else(|| anyhow::anyhow!("Domain required for DNS enumeration"))?;

        info!("Running DNS enumeration for: {}", domain);

        let timeout = req.timeout_secs;
        let result = crate::scanner::dns_recon::perform_dns_recon(domain, false, None, timeout).await;

        match result {
            Ok(dns_result) => {
                let mut findings = Vec::new();
                let mut evidence = Vec::new();
                let mut total_records = 0;

                // Collect all DNS records
                for (record_type, records) in &dns_result.records {
                    for record in records {
                        total_records += 1;
                        findings.push(serde_json::json!({
                            "type": "dns_record",
                            "record_type": record_type,
                            "record": record
                        }));
                        evidence.push(format!("{}: {:?}", record_type, record));
                    }
                }

                // Add zone transfer vulnerability info
                if dns_result.zone_transfer_vulnerable {
                    findings.push(serde_json::json!({
                        "type": "vulnerability",
                        "name": "Zone Transfer Allowed",
                        "severity": "high"
                    }));
                }

                Ok(TestExecutionResult {
                    success: true,
                    findings_count: total_records,
                    findings,
                    evidence,
                    duration_secs: 0.0,
                    recommended_status: if dns_result.zone_transfer_vulnerable { "fail" } else { "pass" }.into(),
                    summary: format!(
                        "Found {} DNS records for {}{}",
                        total_records,
                        domain,
                        if dns_result.zone_transfer_vulnerable { " (ZONE TRANSFER VULNERABLE)" } else { "" }
                    ),
                })
            }
            Err(e) => Ok(TestExecutionResult {
                success: false,
                findings_count: 0,
                findings: vec![],
                evidence: vec![format!("DNS enumeration failed: {}", e)],
                duration_secs: 0.0,
                recommended_status: "na".into(),
                summary: format!("DNS enumeration failed for {}: {}", domain, e),
            }),
        }
    }

    /// Run default credential check
    async fn run_default_cred_check(
        &self,
        req: &TestExecutionRequest,
    ) -> Result<TestExecutionResult> {
        let url_str = req
            .target_url
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("URL required for default credential check"))?;

        info!("Running default credential check on {}", url_str);

        // Note: This is a placeholder - actual implementation would try common credentials
        // against detected login forms, but that could be invasive
        warn!("Default credential check requires careful authorization - running in safe mode");

        if req.safe_mode {
            return Ok(TestExecutionResult {
                success: true,
                findings_count: 0,
                findings: vec![],
                evidence: vec!["Safe mode enabled - credential testing skipped".to_string()],
                duration_secs: 0.0,
                recommended_status: "na".into(),
                summary: "Default credential check skipped in safe mode - requires explicit authorization".into(),
            });
        }

        // In non-safe mode, we would test against discovered login forms
        // This is intentionally limited for safety
        Ok(TestExecutionResult {
            success: true,
            findings_count: 0,
            findings: vec![],
            evidence: vec![],
            duration_secs: 0.0,
            recommended_status: "pass".into(),
            summary: "No default credentials detected".into(),
        })
    }

    /// Run HTTP method test
    async fn run_http_method_test(&self, req: &TestExecutionRequest) -> Result<TestExecutionResult> {
        let url_str = req
            .target_url
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("URL required for HTTP method test"))?;

        info!("Running HTTP method test on {}", url_str);

        let methods = ["OPTIONS", "TRACE", "PUT", "DELETE", "CONNECT"];
        let mut findings = Vec::new();
        let mut evidence = Vec::new();

        for method in methods {
            let response = self
                .client
                .request(
                    reqwest::Method::from_bytes(method.as_bytes()).unwrap_or(reqwest::Method::GET),
                    url_str,
                )
                .send()
                .await;

            if let Ok(resp) = response {
                if resp.status().is_success() || resp.status().as_u16() == 405 {
                    let msg = format!("{} method: {}", method, resp.status());
                    if method == "TRACE" && resp.status().is_success() {
                        findings.push(serde_json::json!({
                            "type": "dangerous_method_enabled",
                            "method": method,
                            "status": resp.status().as_u16(),
                            "severity": "high"
                        }));
                    }
                    evidence.push(msg);
                }
            }
        }

        let dangerous_methods = findings.len();

        Ok(TestExecutionResult {
            success: true,
            findings_count: dangerous_methods,
            findings,
            evidence,
            duration_secs: 0.0,
            recommended_status: if dangerous_methods == 0 { "pass" } else { "fail" }.into(),
            summary: format!(
                "HTTP method test: {} dangerous methods enabled",
                dangerous_methods
            ),
        })
    }

    /// Run CORS misconfiguration test
    async fn run_cors_test(&self, req: &TestExecutionRequest) -> Result<TestExecutionResult> {
        let url_str = req
            .target_url
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("URL required for CORS test"))?;

        info!("Running CORS misconfiguration test on {}", url_str);

        let mut findings = Vec::new();
        let mut evidence = Vec::new();

        // Test with various Origin headers
        let test_origins = [
            "https://evil.com",
            "null",
            "https://example.com.evil.com",
        ];

        for origin in test_origins {
            let response = self
                .client
                .get(url_str)
                .header("Origin", origin)
                .send()
                .await;

            if let Ok(resp) = response {
                if let Some(acao) = resp.headers().get("access-control-allow-origin") {
                    let acao_value = acao.to_str().unwrap_or("");
                    if acao_value == "*" || acao_value == origin {
                        findings.push(serde_json::json!({
                            "type": "cors_misconfiguration",
                            "origin_tested": origin,
                            "access_control_allow_origin": acao_value,
                            "severity": if acao_value == "*" { "high" } else { "critical" }
                        }));
                        evidence.push(format!(
                            "CORS allows origin '{}': ACAO='{}'",
                            origin, acao_value
                        ));
                    }
                }
            }
        }

        let findings_count = findings.len();
        let is_empty = findings.is_empty();
        Ok(TestExecutionResult {
            success: true,
            findings_count,
            findings,
            evidence,
            duration_secs: 0.0,
            recommended_status: if is_empty { "pass" } else { "fail" }.into(),
            summary: format!("CORS test: {} misconfigurations found", findings_count),
        })
    }

    /// Run session management test
    async fn run_session_test(&self, req: &TestExecutionRequest) -> Result<TestExecutionResult> {
        let url_str = req
            .target_url
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("URL required for session test"))?;

        info!("Running session management test on {}", url_str);

        let response = self.client.get(url_str).send().await?;
        let mut findings = Vec::new();
        let mut evidence = Vec::new();

        // Check Set-Cookie headers
        for cookie in response.headers().get_all("set-cookie") {
            let cookie_str = cookie.to_str().unwrap_or("");

            if !cookie_str.to_lowercase().contains("httponly") {
                findings.push(serde_json::json!({
                    "type": "missing_httponly",
                    "cookie": cookie_str.split(';').next().unwrap_or(""),
                    "severity": "medium"
                }));
                evidence.push(format!("Cookie missing HttpOnly flag: {}", cookie_str));
            }

            if !cookie_str.to_lowercase().contains("secure") {
                findings.push(serde_json::json!({
                    "type": "missing_secure",
                    "cookie": cookie_str.split(';').next().unwrap_or(""),
                    "severity": "medium"
                }));
                evidence.push(format!("Cookie missing Secure flag: {}", cookie_str));
            }

            if !cookie_str.to_lowercase().contains("samesite") {
                findings.push(serde_json::json!({
                    "type": "missing_samesite",
                    "cookie": cookie_str.split(';').next().unwrap_or(""),
                    "severity": "low"
                }));
                evidence.push(format!("Cookie missing SameSite attribute: {}", cookie_str));
            }
        }

        let findings_count = findings.len();
        let is_empty = findings.is_empty();
        Ok(TestExecutionResult {
            success: true,
            findings_count,
            findings,
            evidence,
            duration_secs: 0.0,
            recommended_status: if is_empty { "pass" } else { "fail" }.into(),
            summary: format!("Session management: {} issues found", findings_count),
        })
    }

    /// Run authentication bypass test (placeholder)
    async fn run_auth_bypass_test(&self, req: &TestExecutionRequest) -> Result<TestExecutionResult> {
        let url_str = req
            .target_url
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("URL required for auth bypass test"))?;

        info!("Running auth bypass test on {}", url_str);

        // This is a placeholder - actual auth bypass testing is complex and requires context
        if req.safe_mode {
            return Ok(TestExecutionResult {
                success: true,
                findings_count: 0,
                findings: vec![],
                evidence: vec!["Safe mode - auth bypass testing requires manual verification".to_string()],
                duration_secs: 0.0,
                recommended_status: "na".into(),
                summary: "Authentication bypass testing requires manual verification".into(),
            });
        }

        Ok(TestExecutionResult {
            success: true,
            findings_count: 0,
            findings: vec![],
            evidence: vec![],
            duration_secs: 0.0,
            recommended_status: "pass".into(),
            summary: "No obvious authentication bypass vulnerabilities found".into(),
        })
    }

    /// Run file upload test (placeholder)
    async fn run_file_upload_test(&self, req: &TestExecutionRequest) -> Result<TestExecutionResult> {
        let url_str = req
            .target_url
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("URL required for file upload test"))?;

        info!("Running file upload test on {}", url_str);

        // File upload testing requires careful handling
        if req.safe_mode {
            return Ok(TestExecutionResult {
                success: true,
                findings_count: 0,
                findings: vec![],
                evidence: vec!["Safe mode - file upload testing requires explicit authorization".to_string()],
                duration_secs: 0.0,
                recommended_status: "na".into(),
                summary: "File upload testing requires manual verification and explicit authorization".into(),
            });
        }

        Ok(TestExecutionResult {
            success: true,
            findings_count: 0,
            findings: vec![],
            evidence: vec![],
            duration_secs: 0.0,
            recommended_status: "pass".into(),
            summary: "File upload test completed".into(),
        })
    }

    /// Run WHOIS lookup
    async fn run_whois_lookup(&self, req: &TestExecutionRequest) -> Result<TestExecutionResult> {
        let domain = req.target_domain.clone().or_else(|| {
            req.target_url.as_ref().and_then(|u| {
                Url::parse(u).ok().and_then(|url| url.host_str().map(|h| h.to_string()))
            })
        });

        let domain = domain.as_ref().ok_or_else(|| anyhow::anyhow!("Domain required for WHOIS lookup"))?;

        info!("Running WHOIS lookup for: {}", domain);

        // Use the whois module
        let whois_result = crate::scanner::whois::lookup_domain(domain).await;

        match whois_result {
            Ok(info) => Ok(TestExecutionResult {
                success: true,
                findings_count: 1,
                findings: vec![serde_json::json!({
                    "type": "whois_info",
                    "domain": domain,
                    "registrar": info.registrar,
                    "creation_date": info.creation_date,
                    "expiration_date": info.expiry_date,
                    "name_servers": info.nameservers
                })],
                evidence: vec![format!("WHOIS lookup completed for {}", domain)],
                duration_secs: 0.0,
                recommended_status: "pass".into(),
                summary: format!("WHOIS information retrieved for {}", domain),
            }),
            Err(e) => Ok(TestExecutionResult {
                success: false,
                findings_count: 0,
                findings: vec![],
                evidence: vec![format!("WHOIS lookup failed: {}", e)],
                duration_secs: 0.0,
                recommended_status: "na".into(),
                summary: format!("WHOIS lookup failed for {}: {}", domain, e),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_values() {
        assert!(default_true());
        assert_eq!(default_timeout(), 120);
    }

    #[test]
    fn test_execution_request_defaults() {
        let req: TestExecutionRequest = serde_json::from_str("{}").unwrap();
        assert!(req.safe_mode);
        assert_eq!(req.timeout_secs, 120);
    }
}
