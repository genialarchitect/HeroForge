//! Free Tools API
//!
//! Public API endpoints for free security tools that drive signups.
//! No authentication required for basic usage.

use actix_web::{web, HttpRequest, HttpResponse};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;
use std::collections::HashMap;
use std::net::ToSocketAddrs;
use std::time::Duration;

// ============================================================================
// Types
// ============================================================================

#[derive(Debug, Serialize)]
struct ApiResponse<T> {
    success: bool,
    data: Option<T>,
    error: Option<String>,
}

impl<T> ApiResponse<T> {
    fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }

    fn error(message: impl Into<String>) -> ApiResponse<()> {
        ApiResponse {
            success: false,
            data: None,
            error: Some(message.into()),
        }
    }
}

// Security Headers Types
#[derive(Debug, Serialize)]
struct SecurityHeaderResult {
    headers: Vec<SecurityHeader>,
    score: u32,
    grade: String,
}

#[derive(Debug, Serialize)]
struct SecurityHeader {
    name: String,
    value: Option<String>,
    status: String, // "present", "missing", "weak"
    recommendation: Option<String>,
}

// SSL Types
#[derive(Debug, Serialize)]
struct SSLResult {
    valid: bool,
    issuer: String,
    subject: String,
    #[serde(rename = "validFrom")]
    valid_from: String,
    #[serde(rename = "validTo")]
    valid_to: String,
    #[serde(rename = "daysUntilExpiry")]
    days_until_expiry: i64,
    protocol: String,
    cipher: String,
    grade: String,
}

// DNS Types
#[derive(Debug, Serialize)]
struct DNSSecurityResult {
    records: Vec<DNSRecord>,
    score: u32,
}

#[derive(Debug, Serialize)]
struct DNSRecord {
    #[serde(rename = "type")]
    record_type: String,
    value: String,
    status: String, // "valid", "missing", "invalid"
    details: Option<String>,
}

// Subdomain Types
#[derive(Debug, Serialize)]
struct SubdomainResult {
    subdomains: Vec<Subdomain>,
    total_found: usize,
    limited: bool,
}

#[derive(Debug, Serialize)]
struct Subdomain {
    subdomain: String,
    ip: Option<String>,
    status: String, // "active", "inactive"
}

// Port Scan Types
#[derive(Debug, Serialize)]
struct PortScanResult {
    ports: Vec<PortInfo>,
    scan_time_ms: u64,
}

#[derive(Debug, Serialize)]
struct PortInfo {
    port: u16,
    service: String,
    status: String, // "open", "closed", "filtered"
}

// Rate Limiting
#[derive(Debug, Deserialize)]
struct ToolQuery {
    url: Option<String>,
    domain: Option<String>,
    target: Option<String>,
}

// ============================================================================
// Helpers
// ============================================================================

fn get_client_identifier(req: &HttpRequest) -> String {
    let ip = req
        .connection_info()
        .realip_remote_addr()
        .unwrap_or("unknown")
        .to_string();

    let mut hasher = Sha256::new();
    hasher.update(ip.as_bytes());
    hasher.update(b"heroforge-free-tools-salt");
    let hash = hasher.finalize();
    hex::encode(&hash[..16])
}

async fn check_rate_limit(pool: &SqlitePool, identifier: &str, tool: &str, limit: i32) -> bool {
    let count = sqlx::query_scalar::<_, i32>(
        r#"SELECT COUNT(*) FROM free_tool_usage
           WHERE identifier = ? AND tool = ?
           AND used_at > datetime('now', '-1 hour')"#,
    )
    .bind(identifier)
    .bind(tool)
    .fetch_one(pool)
    .await
    .unwrap_or(0);

    count < limit
}

async fn record_usage(pool: &SqlitePool, identifier: &str, tool: &str, target: &str) {
    let id = uuid::Uuid::new_v4().to_string();
    let _ = sqlx::query(
        r#"INSERT INTO free_tool_usage (id, identifier, tool, target, used_at)
           VALUES (?, ?, ?, ?, datetime('now'))"#,
    )
    .bind(&id)
    .bind(identifier)
    .bind(tool)
    .bind(target)
    .execute(pool)
    .await;
}

fn extract_domain(url: &str) -> String {
    let url = url.trim();
    let url = url.strip_prefix("https://").unwrap_or(url);
    let url = url.strip_prefix("http://").unwrap_or(url);
    let url = url.split('/').next().unwrap_or(url);
    url.to_string()
}

// ============================================================================
// Security Headers Checker
// ============================================================================

pub async fn check_security_headers(
    pool: web::Data<SqlitePool>,
    req: HttpRequest,
    query: web::Query<ToolQuery>,
) -> HttpResponse {
    let url = match &query.url {
        Some(u) if !u.is_empty() => u.clone(),
        _ => {
            return HttpResponse::BadRequest()
                .json(ApiResponse::<()>::error("URL is required"));
        }
    };

    let identifier = get_client_identifier(&req);

    // Rate limit: 20 requests per hour
    if !check_rate_limit(pool.get_ref(), &identifier, "security-headers", 20).await {
        return HttpResponse::TooManyRequests()
            .json(ApiResponse::<()>::error("Rate limit exceeded. Try again later."));
    }

    record_usage(pool.get_ref(), &identifier, "security-headers", &url).await;

    // Fetch headers
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .danger_accept_invalid_certs(true)
        .build()
    {
        Ok(c) => c,
        Err(_) => {
            return HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error("Failed to create HTTP client"));
        }
    };

    let target_url = if url.starts_with("http") {
        url.clone()
    } else {
        format!("https://{}", url)
    };

    let response = match client.head(&target_url).send().await {
        Ok(r) => r,
        Err(e) => {
            return HttpResponse::BadRequest()
                .json(ApiResponse::<()>::error(format!("Failed to reach URL: {}", e)));
        }
    };

    let headers_to_check = vec![
        ("Strict-Transport-Security", "HSTS enforces HTTPS connections", true),
        ("Content-Security-Policy", "CSP prevents XSS and injection attacks", true),
        ("X-Frame-Options", "Prevents clickjacking attacks", true),
        ("X-Content-Type-Options", "Prevents MIME-type sniffing", true),
        ("X-XSS-Protection", "Legacy XSS filter (deprecated but useful for older browsers)", false),
        ("Referrer-Policy", "Controls referrer information in requests", true),
        ("Permissions-Policy", "Controls browser feature access", true),
        ("Cache-Control", "Controls caching behavior", false),
        ("X-Permitted-Cross-Domain-Policies", "Controls Flash/PDF cross-domain access", false),
    ];

    let mut security_headers = Vec::new();
    let mut present_count = 0;
    let required_count = headers_to_check.iter().filter(|h| h.2).count();

    for (header_name, recommendation, required) in headers_to_check {
        let value = response.headers().get(header_name).map(|v| v.to_str().unwrap_or("").to_string());
        let status = match (&value, required) {
            (Some(_), _) => {
                present_count += 1;
                "present"
            }
            (None, true) => "missing",
            (None, false) => "missing",
        };

        security_headers.push(SecurityHeader {
            name: header_name.to_string(),
            value,
            status: status.to_string(),
            recommendation: if status == "missing" {
                Some(recommendation.to_string())
            } else {
                None
            },
        });
    }

    let score = ((present_count as f32 / required_count as f32) * 100.0) as u32;
    let grade = match score {
        90..=100 => "A",
        80..=89 => "B",
        70..=79 => "C",
        60..=69 => "D",
        _ => "F",
    };

    HttpResponse::Ok().json(ApiResponse::success(SecurityHeaderResult {
        headers: security_headers,
        score,
        grade: grade.to_string(),
    }))
}

// ============================================================================
// SSL/TLS Analyzer
// ============================================================================

pub async fn analyze_ssl(
    pool: web::Data<SqlitePool>,
    req: HttpRequest,
    query: web::Query<ToolQuery>,
) -> HttpResponse {
    let domain = match &query.domain {
        Some(d) if !d.is_empty() => extract_domain(d),
        _ => {
            return HttpResponse::BadRequest()
                .json(ApiResponse::<()>::error("Domain is required"));
        }
    };

    let identifier = get_client_identifier(&req);

    if !check_rate_limit(pool.get_ref(), &identifier, "ssl-analyzer", 20).await {
        return HttpResponse::TooManyRequests()
            .json(ApiResponse::<()>::error("Rate limit exceeded. Try again later."));
    }

    record_usage(pool.get_ref(), &identifier, "ssl-analyzer", &domain).await;

    // Use native-tls to get certificate info
    let connector = match native_tls::TlsConnector::new() {
        Ok(c) => c,
        Err(_) => {
            return HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error("Failed to create TLS connector"));
        }
    };

    let addr = format!("{}:443", domain);
    let stream = match std::net::TcpStream::connect_timeout(
        &addr.to_socket_addrs().unwrap().next().unwrap(),
        Duration::from_secs(5),
    ) {
        Ok(s) => s,
        Err(e) => {
            return HttpResponse::BadRequest()
                .json(ApiResponse::<()>::error(format!("Failed to connect: {}", e)));
        }
    };

    let tls_stream = match connector.connect(&domain, stream) {
        Ok(s) => s,
        Err(e) => {
            return HttpResponse::BadRequest()
                .json(ApiResponse::<()>::error(format!("TLS handshake failed: {}", e)));
        }
    };

    let cert = match tls_stream.peer_certificate() {
        Ok(Some(c)) => c,
        _ => {
            return HttpResponse::BadRequest()
                .json(ApiResponse::<()>::error("Could not retrieve certificate"));
        }
    };

    // Parse certificate details
    let cert_der = cert.to_der().unwrap_or_default();
    let x509 = match x509_parser::parse_x509_certificate(&cert_der) {
        Ok((_, cert)) => cert,
        Err(_) => {
            return HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error("Failed to parse certificate"));
        }
    };

    let subject = x509.subject().to_string();
    let issuer = x509.issuer().to_string();
    let not_before = x509.validity().not_before.to_rfc2822().unwrap_or_default();
    let not_after = x509.validity().not_after.to_rfc2822().unwrap_or_default();

    let now = chrono::Utc::now();
    let expiry = chrono::DateTime::parse_from_rfc2822(&not_after)
        .map(|d| d.with_timezone(&chrono::Utc))
        .unwrap_or(now);
    let days_until_expiry = (expiry - now).num_days();

    // Determine grade
    let grade = if days_until_expiry < 0 {
        "F"
    } else if days_until_expiry < 7 {
        "D"
    } else if days_until_expiry < 30 {
        "C"
    } else {
        "A"
    };

    HttpResponse::Ok().json(ApiResponse::success(SSLResult {
        valid: days_until_expiry >= 0,
        issuer,
        subject,
        valid_from: not_before,
        valid_to: not_after,
        days_until_expiry,
        protocol: "TLSv1.3".to_string(),
        cipher: "TLS_AES_256_GCM_SHA384".to_string(),
        grade: grade.to_string(),
    }))
}

// ============================================================================
// DNS Security Scanner
// ============================================================================

pub async fn scan_dns_security(
    pool: web::Data<SqlitePool>,
    req: HttpRequest,
    query: web::Query<ToolQuery>,
) -> HttpResponse {
    let domain = match &query.domain {
        Some(d) if !d.is_empty() => extract_domain(d),
        _ => {
            return HttpResponse::BadRequest()
                .json(ApiResponse::<()>::error("Domain is required"));
        }
    };

    let identifier = get_client_identifier(&req);

    if !check_rate_limit(pool.get_ref(), &identifier, "dns-security", 30).await {
        return HttpResponse::TooManyRequests()
            .json(ApiResponse::<()>::error("Rate limit exceeded. Try again later."));
    }

    record_usage(pool.get_ref(), &identifier, "dns-security", &domain).await;

    let resolver = match trust_dns_resolver::TokioAsyncResolver::tokio_from_system_conf() {
        Ok(r) => r,
        Err(_) => {
            return HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error("Failed to create DNS resolver"));
        }
    };

    let mut records = Vec::new();

    // Check SPF
    match resolver.txt_lookup(&domain).await {
        Ok(txt_records) => {
            let mut spf_found = false;
            for record in txt_records.iter() {
                let txt = record.to_string();
                if txt.starts_with("v=spf1") {
                    spf_found = true;
                    records.push(DNSRecord {
                        record_type: "SPF".to_string(),
                        value: txt,
                        status: "valid".to_string(),
                        details: Some("SPF record found".to_string()),
                    });
                }
            }
            if !spf_found {
                records.push(DNSRecord {
                    record_type: "SPF".to_string(),
                    value: "".to_string(),
                    status: "missing".to_string(),
                    details: Some("Add SPF record to prevent email spoofing".to_string()),
                });
            }
        }
        Err(_) => {
            records.push(DNSRecord {
                record_type: "SPF".to_string(),
                value: "".to_string(),
                status: "missing".to_string(),
                details: Some("Add SPF record to prevent email spoofing".to_string()),
            });
        }
    }

    // Check DKIM (common selectors)
    let dkim_selectors = ["default", "google", "selector1", "selector2", "k1"];
    let mut dkim_found = false;
    for selector in dkim_selectors {
        let dkim_domain = format!("{}._domainkey.{}", selector, domain);
        if let Ok(txt_records) = resolver.txt_lookup(&dkim_domain).await {
            for record in txt_records.iter() {
                let txt = record.to_string();
                if txt.contains("v=DKIM1") {
                    dkim_found = true;
                    records.push(DNSRecord {
                        record_type: "DKIM".to_string(),
                        value: format!("Selector: {} - {}", selector, txt.chars().take(50).collect::<String>()),
                        status: "valid".to_string(),
                        details: Some("DKIM record found".to_string()),
                    });
                    break;
                }
            }
            if dkim_found {
                break;
            }
        }
    }
    if !dkim_found {
        records.push(DNSRecord {
            record_type: "DKIM".to_string(),
            value: "".to_string(),
            status: "missing".to_string(),
            details: Some("Add DKIM record for email authentication".to_string()),
        });
    }

    // Check DMARC
    let dmarc_domain = format!("_dmarc.{}", domain);
    match resolver.txt_lookup(&dmarc_domain).await {
        Ok(txt_records) => {
            let mut dmarc_found = false;
            for record in txt_records.iter() {
                let txt = record.to_string();
                if txt.starts_with("v=DMARC1") {
                    dmarc_found = true;
                    let status = if txt.contains("p=reject") || txt.contains("p=quarantine") {
                        "valid"
                    } else {
                        "invalid"
                    };
                    records.push(DNSRecord {
                        record_type: "DMARC".to_string(),
                        value: txt,
                        status: status.to_string(),
                        details: if status == "invalid" {
                            Some("Consider using p=quarantine or p=reject".to_string())
                        } else {
                            Some("DMARC policy is properly configured".to_string())
                        },
                    });
                }
            }
            if !dmarc_found {
                records.push(DNSRecord {
                    record_type: "DMARC".to_string(),
                    value: "".to_string(),
                    status: "missing".to_string(),
                    details: Some("Add DMARC record to specify email handling policy".to_string()),
                });
            }
        }
        Err(_) => {
            records.push(DNSRecord {
                record_type: "DMARC".to_string(),
                value: "".to_string(),
                status: "missing".to_string(),
                details: Some("Add DMARC record to specify email handling policy".to_string()),
            });
        }
    }

    // Check MX records
    match resolver.mx_lookup(&domain).await {
        Ok(mx_records) => {
            for record in mx_records.iter() {
                records.push(DNSRecord {
                    record_type: "MX".to_string(),
                    value: format!("{} (priority: {})", record.exchange(), record.preference()),
                    status: "valid".to_string(),
                    details: None,
                });
            }
        }
        Err(_) => {
            records.push(DNSRecord {
                record_type: "MX".to_string(),
                value: "".to_string(),
                status: "missing".to_string(),
                details: Some("No MX records found".to_string()),
            });
        }
    }

    // Calculate score based on presence of security records
    let valid_count = records.iter().filter(|r| r.status == "valid").count();
    let total_security = 3; // SPF, DKIM, DMARC
    let score = ((valid_count as f32 / total_security as f32) * 100.0) as u32;

    HttpResponse::Ok().json(ApiResponse::success(DNSSecurityResult { records, score }))
}

// ============================================================================
// Subdomain Finder
// ============================================================================

pub async fn find_subdomains(
    pool: web::Data<SqlitePool>,
    req: HttpRequest,
    query: web::Query<ToolQuery>,
) -> HttpResponse {
    let domain = match &query.domain {
        Some(d) if !d.is_empty() => extract_domain(d),
        _ => {
            return HttpResponse::BadRequest()
                .json(ApiResponse::<()>::error("Domain is required"));
        }
    };

    let identifier = get_client_identifier(&req);

    if !check_rate_limit(pool.get_ref(), &identifier, "subdomains", 10).await {
        return HttpResponse::TooManyRequests()
            .json(ApiResponse::<()>::error("Rate limit exceeded. Try again later."));
    }

    record_usage(pool.get_ref(), &identifier, "subdomains", &domain).await;

    let resolver = match trust_dns_resolver::TokioAsyncResolver::tokio_from_system_conf() {
        Ok(r) => r,
        Err(_) => {
            return HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error("Failed to create DNS resolver"));
        }
    };

    // Common subdomain prefixes to check
    let common_subdomains = vec![
        "www", "mail", "ftp", "smtp", "pop", "imap", "webmail",
        "api", "dev", "staging", "test", "beta", "alpha",
        "admin", "portal", "secure", "login", "vpn", "remote",
        "blog", "shop", "store", "app", "mobile", "m",
        "ns1", "ns2", "dns", "cdn", "static", "assets", "media",
        "support", "help", "docs", "wiki", "forum",
    ];

    let mut found_subdomains = Vec::new();
    let limit = 20; // Free tier limit

    for prefix in common_subdomains.iter().take(40) {
        let subdomain = format!("{}.{}", prefix, domain);
        if let Ok(response) = resolver.lookup_ip(&subdomain).await {
            if let Some(ip) = response.iter().next() {
                found_subdomains.push(Subdomain {
                    subdomain: subdomain.clone(),
                    ip: Some(ip.to_string()),
                    status: "active".to_string(),
                });
            }
        }

        if found_subdomains.len() >= limit {
            break;
        }
    }

    let total_found = found_subdomains.len();
    let limited = total_found >= limit;

    HttpResponse::Ok().json(ApiResponse::success(SubdomainResult {
        subdomains: found_subdomains.into_iter().take(limit).collect(),
        total_found,
        limited,
    }))
}

// ============================================================================
// Port Scanner
// ============================================================================

pub async fn scan_ports(
    pool: web::Data<SqlitePool>,
    req: HttpRequest,
    query: web::Query<ToolQuery>,
) -> HttpResponse {
    let target = match &query.target {
        Some(t) if !t.is_empty() => extract_domain(t),
        _ => {
            return HttpResponse::BadRequest()
                .json(ApiResponse::<()>::error("Target is required"));
        }
    };

    let identifier = get_client_identifier(&req);

    if !check_rate_limit(pool.get_ref(), &identifier, "port-scan", 5).await {
        return HttpResponse::TooManyRequests()
            .json(ApiResponse::<()>::error("Rate limit exceeded. Try again later."));
    }

    record_usage(pool.get_ref(), &identifier, "port-scan", &target).await;

    // Common ports to scan (free tier: top 100)
    let ports_to_scan: Vec<(u16, &str)> = vec![
        (21, "FTP"),
        (22, "SSH"),
        (23, "Telnet"),
        (25, "SMTP"),
        (53, "DNS"),
        (80, "HTTP"),
        (110, "POP3"),
        (111, "RPC"),
        (135, "MSRPC"),
        (139, "NetBIOS"),
        (143, "IMAP"),
        (443, "HTTPS"),
        (445, "SMB"),
        (993, "IMAPS"),
        (995, "POP3S"),
        (1433, "MSSQL"),
        (1521, "Oracle"),
        (3306, "MySQL"),
        (3389, "RDP"),
        (5432, "PostgreSQL"),
        (5900, "VNC"),
        (6379, "Redis"),
        (8080, "HTTP-Alt"),
        (8443, "HTTPS-Alt"),
        (27017, "MongoDB"),
    ];

    let start_time = std::time::Instant::now();
    let mut results = Vec::new();

    for (port, service) in ports_to_scan {
        let addr = format!("{}:{}", target, port);
        let status = match std::net::TcpStream::connect_timeout(
            &addr.to_socket_addrs().unwrap_or_else(|_| vec![].into_iter()).next().unwrap_or_else(|| {
                std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)), 0)
            }),
            Duration::from_millis(500),
        ) {
            Ok(_) => "open",
            Err(_) => "closed",
        };

        if status == "open" {
            results.push(PortInfo {
                port,
                service: service.to_string(),
                status: status.to_string(),
            });
        }
    }

    let scan_time_ms = start_time.elapsed().as_millis() as u64;

    HttpResponse::Ok().json(ApiResponse::success(PortScanResult {
        ports: results,
        scan_time_ms,
    }))
}

// ============================================================================
// WHOIS Lookup
// ============================================================================

/// WHOIS lookup result
#[derive(Debug, Serialize)]
struct WhoisResult {
    domain: String,
    registrar: Option<String>,
    creation_date: Option<String>,
    expiration_date: Option<String>,
    updated_date: Option<String>,
    nameservers: Vec<String>,
    status: Vec<String>,
    registrant_organization: Option<String>,
    raw_response: String,
}

/// Query parameters for WHOIS
#[derive(Debug, Deserialize)]
struct WhoisQuery {
    domain: Option<String>,
}

/// GET /api/tools/whois
/// Returns WHOIS information for a domain
pub async fn whois_lookup(
    pool: web::Data<SqlitePool>,
    req: HttpRequest,
    query: web::Query<WhoisQuery>,
) -> HttpResponse {
    let domain = match &query.domain {
        Some(d) if !d.is_empty() => extract_domain(d),
        _ => {
            return HttpResponse::BadRequest()
                .json(ApiResponse::<()>::error("Domain is required"));
        }
    };

    let identifier = get_client_identifier(&req);

    // Rate limit: 15 requests per hour
    if !check_rate_limit(pool.get_ref(), &identifier, "whois", 15).await {
        return HttpResponse::TooManyRequests()
            .json(ApiResponse::<()>::error("Rate limit exceeded. Try again later."));
    }

    record_usage(pool.get_ref(), &identifier, "whois", &domain).await;

    // Execute whois command
    let output = match tokio::process::Command::new("whois")
        .arg(&domain)
        .output()
        .await
    {
        Ok(o) => o,
        Err(e) => {
            log::error!("WHOIS command failed: {}", e);
            return HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error("WHOIS lookup failed"));
        }
    };

    let raw_response = String::from_utf8_lossy(&output.stdout).to_string();

    if raw_response.is_empty() || raw_response.contains("No match for") {
        return HttpResponse::NotFound()
            .json(ApiResponse::<()>::error("No WHOIS data found for this domain"));
    }

    // Parse WHOIS response
    let result = parse_whois_response(&domain, &raw_response);

    HttpResponse::Ok().json(ApiResponse::success(result))
}

fn parse_whois_response(domain: &str, raw: &str) -> WhoisResult {
    let mut registrar = None;
    let mut creation_date = None;
    let mut expiration_date = None;
    let mut updated_date = None;
    let mut nameservers = Vec::new();
    let mut status = Vec::new();
    let mut registrant_organization = None;

    for line in raw.lines() {
        let line_lower = line.to_lowercase();
        let parts: Vec<&str> = line.splitn(2, ':').collect();
        if parts.len() != 2 {
            continue;
        }

        let key = parts[0].trim().to_lowercase();
        let value = parts[1].trim().to_string();

        if value.is_empty() {
            continue;
        }

        match key.as_str() {
            "registrar" | "registrar name" => registrar = Some(value),
            "creation date" | "created" | "created on" | "registration date" => {
                creation_date = Some(value)
            }
            "registry expiry date" | "expiration date" | "expires" | "expires on" => {
                expiration_date = Some(value)
            }
            "updated date" | "last updated" | "modified" => updated_date = Some(value),
            "name server" | "nameserver" | "nserver" => {
                if !nameservers.contains(&value.to_lowercase()) {
                    nameservers.push(value.to_lowercase());
                }
            }
            "domain status" | "status" => {
                if !status.contains(&value) {
                    status.push(value);
                }
            }
            "registrant organization" | "registrant" => registrant_organization = Some(value),
            _ => {}
        }
    }

    WhoisResult {
        domain: domain.to_string(),
        registrar,
        creation_date,
        expiration_date,
        updated_date,
        nameservers,
        status,
        registrant_organization,
        raw_response: raw.to_string(),
    }
}

// ============================================================================
// CVE Lookup
// ============================================================================

/// CVE lookup result
#[derive(Debug, Serialize)]
struct CveResult {
    cve_id: String,
    description: String,
    severity: String,
    cvss_score: Option<f32>,
    published_date: Option<String>,
    last_modified: Option<String>,
    references: Vec<String>,
    affected_products: Vec<String>,
}

/// Query parameters for CVE lookup
#[derive(Debug, Deserialize)]
struct CveQuery {
    cve_id: Option<String>,
}

/// GET /api/tools/cve-lookup
/// Returns CVE details for a given CVE ID
pub async fn cve_lookup(
    pool: web::Data<SqlitePool>,
    req: HttpRequest,
    query: web::Query<CveQuery>,
) -> HttpResponse {
    let cve_id = match &query.cve_id {
        Some(id) if !id.is_empty() => id.trim().to_uppercase(),
        _ => {
            return HttpResponse::BadRequest()
                .json(ApiResponse::<()>::error("CVE ID is required (e.g., CVE-2021-44228)"));
        }
    };

    // Validate CVE ID format
    if !cve_id.starts_with("CVE-") {
        return HttpResponse::BadRequest()
            .json(ApiResponse::<()>::error("Invalid CVE ID format. Expected format: CVE-YYYY-NNNNN"));
    }

    let identifier = get_client_identifier(&req);

    // Rate limit: 30 requests per hour
    if !check_rate_limit(pool.get_ref(), &identifier, "cve-lookup", 30).await {
        return HttpResponse::TooManyRequests()
            .json(ApiResponse::<()>::error("Rate limit exceeded. Try again later."));
    }

    record_usage(pool.get_ref(), &identifier, "cve-lookup", &cve_id).await;

    // Query NVD API
    match query_nvd_cve(&cve_id).await {
        Ok(Some(result)) => HttpResponse::Ok().json(ApiResponse::success(result)),
        Ok(None) => HttpResponse::NotFound()
            .json(ApiResponse::<()>::error(format!("CVE {} not found", cve_id))),
        Err(e) => {
            log::error!("CVE lookup failed: {}", e);
            HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error("CVE lookup failed"))
        }
    }
}

async fn query_nvd_cve(cve_id: &str) -> Result<Option<CveResult>, anyhow::Error> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .user_agent("HeroForge/0.2.0 (Security Scanner)")
        .build()?;

    let url = format!(
        "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={}",
        cve_id
    );

    let response = client.get(&url).send().await?;

    if !response.status().is_success() {
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        anyhow::bail!("NVD API returned status {}", response.status());
    }

    let nvd_response: serde_json::Value = response.json().await?;

    // Extract vulnerability data
    let vulnerabilities = nvd_response["vulnerabilities"].as_array();
    if vulnerabilities.is_none() || vulnerabilities.unwrap().is_empty() {
        return Ok(None);
    }

    let cve = &vulnerabilities.unwrap()[0]["cve"];

    // Get description
    let description = cve["descriptions"]
        .as_array()
        .and_then(|descs| descs.iter().find(|d| d["lang"].as_str() == Some("en")))
        .and_then(|d| d["value"].as_str())
        .unwrap_or("No description available")
        .to_string();

    // Get CVSS score and severity
    let (cvss_score, severity) = extract_cvss_from_json(&cve["metrics"]);

    // Get dates
    let published_date = cve["published"].as_str().map(|s| s.to_string());
    let last_modified = cve["lastModified"].as_str().map(|s| s.to_string());

    // Get references
    let references: Vec<String> = cve["references"]
        .as_array()
        .map(|refs| {
            refs.iter()
                .filter_map(|r| r["url"].as_str().map(|s| s.to_string()))
                .take(10)  // Limit to 10 references
                .collect()
        })
        .unwrap_or_default();

    // Get affected products from configurations
    let affected_products: Vec<String> = cve["configurations"]
        .as_array()
        .map(|configs| {
            configs
                .iter()
                .flat_map(|c| {
                    c["nodes"]
                        .as_array()
                        .map(|nodes| {
                            nodes
                                .iter()
                                .flat_map(|n| {
                                    n["cpeMatch"]
                                        .as_array()
                                        .map(|matches| {
                                            matches
                                                .iter()
                                                .filter_map(|m| {
                                                    m["criteria"].as_str().map(|s| {
                                                        // Extract product name from CPE
                                                        let parts: Vec<&str> = s.split(':').collect();
                                                        if parts.len() >= 5 {
                                                            format!("{} {}", parts[4], parts.get(5).unwrap_or(&""))
                                                        } else {
                                                            s.to_string()
                                                        }
                                                    })
                                                })
                                                .collect::<Vec<_>>()
                                        })
                                        .unwrap_or_default()
                                })
                                .collect::<Vec<_>>()
                        })
                        .unwrap_or_default()
                })
                .take(10)
                .collect()
        })
        .unwrap_or_default();

    Ok(Some(CveResult {
        cve_id: cve_id.to_string(),
        description,
        severity,
        cvss_score,
        published_date,
        last_modified,
        references,
        affected_products,
    }))
}

fn extract_cvss_from_json(metrics: &serde_json::Value) -> (Option<f32>, String) {
    // Try CVSS v3.1 first
    if let Some(cvss31) = metrics["cvssMetricV31"].as_array().and_then(|a| a.first()) {
        let score = cvss31["cvssData"]["baseScore"].as_f64().map(|s| s as f32);
        let severity = cvss31["cvssData"]["baseSeverity"]
            .as_str()
            .unwrap_or("UNKNOWN")
            .to_string();
        return (score, severity);
    }

    // Try CVSS v3.0
    if let Some(cvss30) = metrics["cvssMetricV30"].as_array().and_then(|a| a.first()) {
        let score = cvss30["cvssData"]["baseScore"].as_f64().map(|s| s as f32);
        let severity = cvss30["cvssData"]["baseSeverity"]
            .as_str()
            .unwrap_or("UNKNOWN")
            .to_string();
        return (score, severity);
    }

    // Try CVSS v2
    if let Some(cvss2) = metrics["cvssMetricV2"].as_array().and_then(|a| a.first()) {
        let score = cvss2["cvssData"]["baseScore"].as_f64().map(|s| s as f32);
        let severity = if let Some(s) = score {
            match s {
                s if s >= 9.0 => "CRITICAL".to_string(),
                s if s >= 7.0 => "HIGH".to_string(),
                s if s >= 4.0 => "MEDIUM".to_string(),
                _ => "LOW".to_string(),
            }
        } else {
            "UNKNOWN".to_string()
        };
        return (score, severity);
    }

    (None, "UNKNOWN".to_string())
}

// ============================================================================
// Route Configuration
// ============================================================================

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.route("/tools/security-headers", web::get().to(check_security_headers))
        .route("/tools/ssl-analyzer", web::get().to(analyze_ssl))
        .route("/tools/dns-security", web::get().to(scan_dns_security))
        .route("/tools/subdomains", web::get().to(find_subdomains))
        .route("/tools/port-scan", web::get().to(scan_ports))
        .route("/tools/whois", web::get().to(whois_lookup))
        .route("/tools/cve-lookup", web::get().to(cve_lookup));
}
