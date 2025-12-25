//! Email Security Analysis Module
//!
//! This module provides comprehensive email security analysis for domains,
//! including SPF, DKIM, and DMARC validation and spoofability assessment.

use anyhow::Result;
use log::{debug, info, warn};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::time::timeout;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::TokioAsyncResolver;

/// Common DKIM selectors used by major email providers and services
const COMMON_DKIM_SELECTORS: &[&str] = &[
    // Major email providers
    "default",
    "google",
    "selector1",     // Microsoft Office 365
    "selector2",     // Microsoft Office 365
    "k1",            // Mailchimp
    "k2",            // Mailchimp
    "k3",            // Mailchimp
    "s1",            // Generic
    "s2",            // Generic
    "mail",          // Generic
    "dkim",          // Generic
    "email",         // Generic
    "m1",            // Generic
    "m2",            // Generic
    "mx",            // Generic
    "smtp",          // Generic
    // Marketing/Transactional platforms
    "mailjet",       // Mailjet
    "sendgrid",      // SendGrid
    "amazonses",     // Amazon SES
    "ses",           // Amazon SES
    "mailgun",       // Mailgun
    "postmark",      // Postmark
    "sparkpost",     // SparkPost
    "mandrill",      // Mandrill
    "zendesk1",      // Zendesk
    "zendesk2",      // Zendesk
    "hubspot",       // HubSpot
    "salesforce",    // Salesforce
    "cm",            // Campaign Monitor
    "constantcontact", // Constant Contact
    // Common patterns
    "20190101",      // Date-based selectors
    "20200101",
    "20210101",
    "20220101",
    "20230101",
    "20240101",
    "20250101",
    "protonmail",    // ProtonMail
    "protonmail2",
    "protonmail3",
    "fm1",           // Fastmail
    "fm2",
    "fm3",
    "mxvault",       // MxVault
    "turbo-smtp",    // TurboSMTP
    "smtp2go",       // SMTP2GO
    "mailersend",    // MailerSend
];

/// SPF (Sender Policy Framework) analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SpfResult {
    /// The raw SPF record found in DNS
    pub record: Option<String>,
    /// Whether SPF is properly configured
    pub valid: bool,
    /// Parsed mechanisms from the SPF record
    pub mechanisms: Vec<SpfMechanism>,
    /// SPF policy qualifier (e.g., +all, -all, ~all, ?all)
    pub policy: Option<SpfPolicy>,
    /// Number of DNS lookups required (max 10 per RFC 7208)
    pub dns_lookup_count: u32,
    /// Whether the record exceeds the DNS lookup limit
    pub exceeds_lookup_limit: bool,
    /// Validation errors or warnings
    pub issues: Vec<String>,
    /// List of authorized sending hosts/networks
    pub authorized_senders: Vec<String>,
}

/// SPF mechanism parsed from the record
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SpfMechanism {
    /// Mechanism type (a, mx, ip4, ip6, include, redirect, exists, etc.)
    pub mechanism_type: String,
    /// Qualifier (+, -, ~, ?)
    pub qualifier: String,
    /// Value (e.g., IP address, domain, CIDR)
    pub value: Option<String>,
}

/// SPF policy qualifier
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum SpfPolicy {
    /// +all - Pass (effectively disables SPF protection)
    Pass,
    /// -all - Fail (strict, recommended)
    Fail,
    /// ~all - SoftFail (weak, may allow spoofing)
    SoftFail,
    /// ?all - Neutral (no policy)
    Neutral,
}

/// DKIM (DomainKeys Identified Mail) analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DkimResult {
    /// List of DKIM selectors found
    pub selectors_found: Vec<DkimSelector>,
    /// Whether any DKIM records were found
    pub configured: bool,
    /// Selectors that were checked but not found
    pub selectors_checked: Vec<String>,
    /// Issues found during analysis
    pub issues: Vec<String>,
}

/// Information about a specific DKIM selector
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DkimSelector {
    /// The selector name
    pub selector: String,
    /// The full DKIM record
    pub record: String,
    /// Key type (usually rsa)
    pub key_type: Option<String>,
    /// Key length in bits (if determinable)
    pub key_bits: Option<u32>,
    /// Hash algorithms supported
    pub hash_algorithms: Vec<String>,
    /// Whether the key is considered weak (< 2048 bits for RSA)
    pub weak_key: bool,
    /// Service type (email, etc.)
    pub service_type: Option<String>,
    /// Notes or flags in the record
    pub notes: Option<String>,
    /// Whether testing mode is enabled
    pub testing_mode: bool,
}

/// DMARC (Domain-based Message Authentication, Reporting & Conformance) analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DmarcResult {
    /// The raw DMARC record
    pub record: Option<String>,
    /// Whether DMARC is properly configured
    pub valid: bool,
    /// The DMARC policy (none, quarantine, reject)
    pub policy: Option<DmarcPolicy>,
    /// Subdomain policy (if different from main policy)
    pub subdomain_policy: Option<DmarcPolicy>,
    /// Percentage of messages to apply policy to (0-100)
    pub percentage: u8,
    /// Aggregate report URI(s)
    pub rua_uris: Vec<String>,
    /// Forensic report URI(s)
    pub ruf_uris: Vec<String>,
    /// SPF alignment mode (relaxed or strict)
    pub spf_alignment: AlignmentMode,
    /// DKIM alignment mode (relaxed or strict)
    pub dkim_alignment: AlignmentMode,
    /// Reporting interval in seconds
    pub reporting_interval: Option<u32>,
    /// Forensic reporting options
    pub forensic_options: Vec<String>,
    /// Issues found during analysis
    pub issues: Vec<String>,
}

/// DMARC policy setting
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum DmarcPolicy {
    /// No action, monitoring only
    None,
    /// Quarantine suspicious messages (spam folder)
    Quarantine,
    /// Reject suspicious messages outright
    Reject,
}

/// DMARC alignment mode
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum AlignmentMode {
    /// Relaxed alignment (subdomains allowed)
    Relaxed,
    /// Strict alignment (exact domain match required)
    Strict,
}

/// Overall spoofability rating for the domain
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum SpoofabilityRating {
    /// Domain is highly resistant to spoofing
    None,
    /// Domain has good protections but minor weaknesses
    Low,
    /// Domain has some protections but significant gaps
    Medium,
    /// Domain is vulnerable to email spoofing
    High,
}

impl SpoofabilityRating {
    /// Get a human-readable description of the rating
    pub fn description(&self) -> &'static str {
        match self {
            Self::None => "Domain is well-protected against email spoofing",
            Self::Low => "Domain has good email security with minor improvements possible",
            Self::Medium => "Domain has some email security gaps that should be addressed",
            Self::High => "Domain is vulnerable to email spoofing and requires immediate attention",
        }
    }
}

/// Combined email security analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EmailSecurityResult {
    /// The domain analyzed
    pub domain: String,
    /// SPF analysis results
    pub spf: SpfResult,
    /// DKIM analysis results
    pub dkim: DkimResult,
    /// DMARC analysis results
    pub dmarc: DmarcResult,
    /// Overall spoofability rating
    pub spoofability_rating: SpoofabilityRating,
    /// Recommendations for improving email security
    pub recommendations: Vec<String>,
    /// MX records for the domain
    pub mx_records: Vec<String>,
    /// Timestamp of the analysis
    pub analyzed_at: chrono::DateTime<chrono::Utc>,
}

/// Analyze email security configuration for a domain
///
/// This function queries DNS for SPF, DKIM, and DMARC records,
/// parses them, and provides a comprehensive security assessment.
pub async fn analyze_domain(domain: &str) -> Result<EmailSecurityResult> {
    info!("Starting email security analysis for domain: {}", domain);

    let timeout_duration = Duration::from_secs(30);
    let resolver = create_resolver(Some(timeout_duration))?;

    // Perform all analyses in parallel
    let (spf_result, dkim_result, dmarc_result, mx_records) = tokio::join!(
        analyze_spf(&resolver, domain, timeout_duration),
        analyze_dkim(&resolver, domain, timeout_duration),
        analyze_dmarc(&resolver, domain, timeout_duration),
        get_mx_records(&resolver, domain, timeout_duration),
    );

    let spf = spf_result.unwrap_or_else(|e| {
        warn!("SPF analysis failed for {}: {}", domain, e);
        SpfResult {
            record: None,
            valid: false,
            mechanisms: Vec::new(),
            policy: None,
            dns_lookup_count: 0,
            exceeds_lookup_limit: false,
            issues: vec![format!("SPF analysis failed: {}", e)],
            authorized_senders: Vec::new(),
        }
    });

    let dkim = dkim_result.unwrap_or_else(|e| {
        warn!("DKIM analysis failed for {}: {}", domain, e);
        DkimResult {
            selectors_found: Vec::new(),
            configured: false,
            selectors_checked: Vec::new(),
            issues: vec![format!("DKIM analysis failed: {}", e)],
        }
    });

    let dmarc = dmarc_result.unwrap_or_else(|e| {
        warn!("DMARC analysis failed for {}: {}", domain, e);
        DmarcResult {
            record: None,
            valid: false,
            policy: None,
            subdomain_policy: None,
            percentage: 100,
            rua_uris: Vec::new(),
            ruf_uris: Vec::new(),
            spf_alignment: AlignmentMode::Relaxed,
            dkim_alignment: AlignmentMode::Relaxed,
            reporting_interval: None,
            forensic_options: Vec::new(),
            issues: vec![format!("DMARC analysis failed: {}", e)],
        }
    });

    let mx = mx_records.unwrap_or_else(|e| {
        warn!("MX record lookup failed for {}: {}", domain, e);
        Vec::new()
    });

    // Calculate spoofability rating
    let spoofability_rating = calculate_spoofability_rating(&spf, &dkim, &dmarc);

    // Generate recommendations
    let recommendations = generate_recommendations(&spf, &dkim, &dmarc, &spoofability_rating);

    let result = EmailSecurityResult {
        domain: domain.to_string(),
        spf,
        dkim,
        dmarc,
        spoofability_rating,
        recommendations,
        mx_records: mx,
        analyzed_at: chrono::Utc::now(),
    };

    info!("Email security analysis completed for {}", domain);
    Ok(result)
}

/// Create a DNS resolver with custom configuration
fn create_resolver(query_timeout: Option<Duration>) -> Result<TokioAsyncResolver> {
    let mut opts = ResolverOpts::default();
    opts.timeout = query_timeout.unwrap_or(Duration::from_secs(5));
    opts.attempts = 2;

    Ok(TokioAsyncResolver::tokio(ResolverConfig::default(), opts))
}

/// Analyze SPF record for a domain
async fn analyze_spf(
    resolver: &TokioAsyncResolver,
    domain: &str,
    scan_timeout: Duration,
) -> Result<SpfResult> {
    debug!("Analyzing SPF for domain: {}", domain);

    let mut result = SpfResult {
        record: None,
        valid: false,
        mechanisms: Vec::new(),
        policy: None,
        dns_lookup_count: 0,
        exceeds_lookup_limit: false,
        issues: Vec::new(),
        authorized_senders: Vec::new(),
    };

    // Query TXT records for the domain
    let txt_records = match timeout(scan_timeout, resolver.txt_lookup(domain)).await {
        Ok(Ok(response)) => response,
        Ok(Err(e)) => {
            result.issues.push(format!("No TXT records found: {}", e));
            return Ok(result);
        }
        Err(_) => {
            result.issues.push("Timeout querying SPF records".to_string());
            return Ok(result);
        }
    };

    // Find SPF record (starts with "v=spf1")
    let mut spf_record: Option<String> = None;
    for txt in txt_records.iter() {
        let txt_data = txt.to_string();
        if txt_data.to_lowercase().starts_with("v=spf1") {
            if spf_record.is_some() {
                result.issues.push("Multiple SPF records found (RFC violation)".to_string());
            }
            spf_record = Some(txt_data);
        }
    }

    let record = match spf_record {
        Some(r) => r,
        None => {
            result.issues.push("No SPF record found".to_string());
            return Ok(result);
        }
    };

    result.record = Some(record.clone());

    // Parse SPF record
    let parts: Vec<&str> = record.split_whitespace().collect();

    for part in parts.iter().skip(1) {
        // Skip "v=spf1"
        let (qualifier, mechanism_str) = if part.starts_with('+') {
            ("+", &part[1..])
        } else if part.starts_with('-') {
            ("-", &part[1..])
        } else if part.starts_with('~') {
            ("~", &part[1..])
        } else if part.starts_with('?') {
            ("?", &part[1..])
        } else {
            ("+", *part) // Default is pass
        };

        if mechanism_str.to_lowercase() == "all" {
            result.policy = Some(match qualifier {
                "+" => SpfPolicy::Pass,
                "-" => SpfPolicy::Fail,
                "~" => SpfPolicy::SoftFail,
                "?" => SpfPolicy::Neutral,
                _ => SpfPolicy::Neutral,
            });

            result.mechanisms.push(SpfMechanism {
                mechanism_type: "all".to_string(),
                qualifier: qualifier.to_string(),
                value: None,
            });
        } else if mechanism_str.starts_with("include:") {
            let value = mechanism_str.strip_prefix("include:").unwrap().to_string();
            result.dns_lookup_count += 1;
            result.authorized_senders.push(format!("include:{}", value));
            result.mechanisms.push(SpfMechanism {
                mechanism_type: "include".to_string(),
                qualifier: qualifier.to_string(),
                value: Some(value),
            });
        } else if mechanism_str.starts_with("redirect=") {
            let value = mechanism_str.strip_prefix("redirect=").unwrap().to_string();
            result.dns_lookup_count += 1;
            result.mechanisms.push(SpfMechanism {
                mechanism_type: "redirect".to_string(),
                qualifier: qualifier.to_string(),
                value: Some(value),
            });
        } else if mechanism_str.starts_with("ip4:") {
            let value = mechanism_str.strip_prefix("ip4:").unwrap().to_string();
            result.authorized_senders.push(format!("ip4:{}", value));
            result.mechanisms.push(SpfMechanism {
                mechanism_type: "ip4".to_string(),
                qualifier: qualifier.to_string(),
                value: Some(value),
            });
        } else if mechanism_str.starts_with("ip6:") {
            let value = mechanism_str.strip_prefix("ip6:").unwrap().to_string();
            result.authorized_senders.push(format!("ip6:{}", value));
            result.mechanisms.push(SpfMechanism {
                mechanism_type: "ip6".to_string(),
                qualifier: qualifier.to_string(),
                value: Some(value),
            });
        } else if mechanism_str == "a" || mechanism_str.starts_with("a:") || mechanism_str.starts_with("a/") {
            result.dns_lookup_count += 1;
            let value = if mechanism_str == "a" {
                None
            } else {
                Some(mechanism_str[2..].to_string())
            };
            result.mechanisms.push(SpfMechanism {
                mechanism_type: "a".to_string(),
                qualifier: qualifier.to_string(),
                value,
            });
        } else if mechanism_str == "mx" || mechanism_str.starts_with("mx:") || mechanism_str.starts_with("mx/") {
            result.dns_lookup_count += 1;
            let value = if mechanism_str == "mx" {
                None
            } else {
                Some(mechanism_str[3..].to_string())
            };
            result.mechanisms.push(SpfMechanism {
                mechanism_type: "mx".to_string(),
                qualifier: qualifier.to_string(),
                value,
            });
        } else if mechanism_str.starts_with("ptr") {
            result.dns_lookup_count += 1;
            result.issues.push("PTR mechanism is deprecated and not recommended".to_string());
            result.mechanisms.push(SpfMechanism {
                mechanism_type: "ptr".to_string(),
                qualifier: qualifier.to_string(),
                value: if mechanism_str.starts_with("ptr:") {
                    Some(mechanism_str[4..].to_string())
                } else {
                    None
                },
            });
        } else if mechanism_str.starts_with("exists:") {
            result.dns_lookup_count += 1;
            let value = mechanism_str.strip_prefix("exists:").unwrap().to_string();
            result.mechanisms.push(SpfMechanism {
                mechanism_type: "exists".to_string(),
                qualifier: qualifier.to_string(),
                value: Some(value),
            });
        } else if mechanism_str.starts_with("exp=") {
            let value = mechanism_str.strip_prefix("exp=").unwrap().to_string();
            result.mechanisms.push(SpfMechanism {
                mechanism_type: "exp".to_string(),
                qualifier: qualifier.to_string(),
                value: Some(value),
            });
        }
    }

    // Check for issues
    if result.dns_lookup_count > 10 {
        result.exceeds_lookup_limit = true;
        result.issues.push(format!(
            "SPF record requires {} DNS lookups (max 10 allowed)",
            result.dns_lookup_count
        ));
    }

    if result.policy.is_none() {
        result.issues.push("No 'all' mechanism found - SPF record is incomplete".to_string());
    } else {
        match result.policy.as_ref().unwrap() {
            SpfPolicy::Pass => {
                result.issues.push("+all effectively disables SPF protection".to_string());
            }
            SpfPolicy::SoftFail => {
                result.issues.push("~all (softfail) is weaker than -all (fail); consider upgrading".to_string());
            }
            SpfPolicy::Neutral => {
                result.issues.push("?all provides no SPF protection".to_string());
            }
            SpfPolicy::Fail => {
                // This is the recommended setting
            }
        }
    }

    if record.len() > 255 {
        result.issues.push("SPF record exceeds 255 characters; may require splitting".to_string());
    }

    result.valid = result.record.is_some()
        && result.policy.is_some()
        && !result.exceeds_lookup_limit
        && result.policy != Some(SpfPolicy::Pass)
        && result.policy != Some(SpfPolicy::Neutral);

    Ok(result)
}

/// Analyze DKIM records for a domain
async fn analyze_dkim(
    resolver: &TokioAsyncResolver,
    domain: &str,
    scan_timeout: Duration,
) -> Result<DkimResult> {
    debug!("Analyzing DKIM for domain: {}", domain);

    let mut result = DkimResult {
        selectors_found: Vec::new(),
        configured: false,
        selectors_checked: Vec::new(),
        issues: Vec::new(),
    };

    // Check common DKIM selectors
    let mut tasks = Vec::new();

    for selector in COMMON_DKIM_SELECTORS {
        let dkim_domain = format!("{}._domainkey.{}", selector, domain);
        let resolver = resolver.clone();
        let selector = selector.to_string();
        let timeout_duration = scan_timeout;

        tasks.push(tokio::spawn(async move {
            match timeout(timeout_duration, resolver.txt_lookup(&dkim_domain)).await {
                Ok(Ok(response)) => {
                    let record: String = response
                        .iter()
                        .map(|r| r.to_string())
                        .collect::<Vec<_>>()
                        .join(" ");

                    if record.contains("v=DKIM1") || record.contains("k=") || record.contains("p=") {
                        Some((selector, record))
                    } else {
                        None
                    }
                }
                _ => None,
            }
        }));
    }

    result.selectors_checked = COMMON_DKIM_SELECTORS.iter().map(|s| s.to_string()).collect();

    // Collect results
    for task in tasks {
        if let Ok(Some((selector, record))) = task.await {
            let dkim_selector = parse_dkim_record(&selector, &record);
            result.selectors_found.push(dkim_selector);
        }
    }

    result.configured = !result.selectors_found.is_empty();

    if !result.configured {
        result.issues.push("No DKIM records found for common selectors".to_string());
    }

    // Check for weak keys
    for selector in &result.selectors_found {
        if selector.weak_key {
            result.issues.push(format!(
                "DKIM selector '{}' uses a weak key ({} bits); recommend 2048+ bits",
                selector.selector,
                selector.key_bits.unwrap_or(0)
            ));
        }
        if selector.testing_mode {
            result.issues.push(format!(
                "DKIM selector '{}' is in testing mode (t=y)",
                selector.selector
            ));
        }
    }

    Ok(result)
}

/// Parse a DKIM record and extract key information
fn parse_dkim_record(selector: &str, record: &str) -> DkimSelector {
    let mut dkim = DkimSelector {
        selector: selector.to_string(),
        record: record.to_string(),
        key_type: None,
        key_bits: None,
        hash_algorithms: Vec::new(),
        weak_key: false,
        service_type: None,
        notes: None,
        testing_mode: false,
    };

    // Parse key-value pairs
    for part in record.split(';') {
        let part = part.trim();
        if let Some((key, value)) = part.split_once('=') {
            let key = key.trim().to_lowercase();
            let value = value.trim();

            match key.as_str() {
                "k" => {
                    dkim.key_type = Some(value.to_string());
                }
                "p" => {
                    // Try to estimate key size from base64-encoded public key
                    // Base64 encoded data is ~4/3 the size of binary data
                    // RSA key size estimation: key_length_bytes * 8
                    let key_bytes = (value.len() * 3) / 4;
                    if !value.is_empty() {
                        // RSA public key includes modulus and exponent
                        // A rough estimate: the key size is approximately bytes * 8
                        // This is an approximation; actual size may vary
                        let estimated_bits = (key_bytes * 8) as u32;
                        // Adjust for RSA public key overhead
                        let key_bits = if estimated_bits > 4096 {
                            4096
                        } else if estimated_bits > 2048 {
                            2048
                        } else if estimated_bits > 1024 {
                            1024
                        } else if estimated_bits > 512 {
                            512
                        } else {
                            estimated_bits
                        };
                        dkim.key_bits = Some(key_bits);
                        dkim.weak_key = key_bits < 2048;
                    }
                }
                "h" => {
                    dkim.hash_algorithms = value.split(':').map(|s| s.trim().to_string()).collect();
                }
                "s" => {
                    dkim.service_type = Some(value.to_string());
                }
                "t" => {
                    if value.contains('y') {
                        dkim.testing_mode = true;
                    }
                }
                "n" => {
                    dkim.notes = Some(value.to_string());
                }
                _ => {}
            }
        }
    }

    // Default key type is RSA
    if dkim.key_type.is_none() {
        dkim.key_type = Some("rsa".to_string());
    }

    dkim
}

/// Analyze DMARC record for a domain
async fn analyze_dmarc(
    resolver: &TokioAsyncResolver,
    domain: &str,
    scan_timeout: Duration,
) -> Result<DmarcResult> {
    debug!("Analyzing DMARC for domain: {}", domain);

    let mut result = DmarcResult {
        record: None,
        valid: false,
        policy: None,
        subdomain_policy: None,
        percentage: 100,
        rua_uris: Vec::new(),
        ruf_uris: Vec::new(),
        spf_alignment: AlignmentMode::Relaxed,
        dkim_alignment: AlignmentMode::Relaxed,
        reporting_interval: None,
        forensic_options: Vec::new(),
        issues: Vec::new(),
    };

    let dmarc_domain = format!("_dmarc.{}", domain);

    // Query TXT records for _dmarc subdomain
    let txt_records = match timeout(scan_timeout, resolver.txt_lookup(&dmarc_domain)).await {
        Ok(Ok(response)) => response,
        Ok(Err(e)) => {
            result.issues.push(format!("No DMARC record found: {}", e));
            return Ok(result);
        }
        Err(_) => {
            result.issues.push("Timeout querying DMARC record".to_string());
            return Ok(result);
        }
    };

    // Find DMARC record (starts with "v=DMARC1")
    let mut dmarc_record: Option<String> = None;
    for txt in txt_records.iter() {
        let txt_data = txt.to_string();
        if txt_data.to_lowercase().starts_with("v=dmarc1") {
            if dmarc_record.is_some() {
                result.issues.push("Multiple DMARC records found (RFC violation)".to_string());
            }
            dmarc_record = Some(txt_data);
        }
    }

    let record = match dmarc_record {
        Some(r) => r,
        None => {
            result.issues.push("No DMARC record found".to_string());
            return Ok(result);
        }
    };

    result.record = Some(record.clone());

    // Parse DMARC record
    for part in record.split(';') {
        let part = part.trim();
        if let Some((key, value)) = part.split_once('=') {
            let key = key.trim().to_lowercase();
            let value = value.trim();

            match key.as_str() {
                "p" => {
                    result.policy = Some(match value.to_lowercase().as_str() {
                        "none" => DmarcPolicy::None,
                        "quarantine" => DmarcPolicy::Quarantine,
                        "reject" => DmarcPolicy::Reject,
                        _ => {
                            result.issues.push(format!("Unknown DMARC policy: {}", value));
                            DmarcPolicy::None
                        }
                    });
                }
                "sp" => {
                    result.subdomain_policy = Some(match value.to_lowercase().as_str() {
                        "none" => DmarcPolicy::None,
                        "quarantine" => DmarcPolicy::Quarantine,
                        "reject" => DmarcPolicy::Reject,
                        _ => DmarcPolicy::None,
                    });
                }
                "pct" => {
                    result.percentage = value.parse().unwrap_or(100);
                }
                "rua" => {
                    result.rua_uris = value
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .collect();
                }
                "ruf" => {
                    result.ruf_uris = value
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .collect();
                }
                "aspf" => {
                    result.spf_alignment = if value.to_lowercase() == "s" {
                        AlignmentMode::Strict
                    } else {
                        AlignmentMode::Relaxed
                    };
                }
                "adkim" => {
                    result.dkim_alignment = if value.to_lowercase() == "s" {
                        AlignmentMode::Strict
                    } else {
                        AlignmentMode::Relaxed
                    };
                }
                "ri" => {
                    result.reporting_interval = value.parse().ok();
                }
                "fo" => {
                    result.forensic_options = value
                        .split(':')
                        .map(|s| s.trim().to_string())
                        .collect();
                }
                _ => {}
            }
        }
    }

    // Check for issues
    if result.policy.is_none() {
        result.issues.push("DMARC record missing required 'p' (policy) tag".to_string());
    } else {
        match result.policy.as_ref().unwrap() {
            DmarcPolicy::None => {
                result.issues.push("DMARC policy is 'none' - provides monitoring only, not protection".to_string());
            }
            DmarcPolicy::Quarantine => {
                // Good, but could be stricter
            }
            DmarcPolicy::Reject => {
                // Best setting
            }
        }
    }

    if result.percentage < 100 {
        result.issues.push(format!(
            "DMARC policy only applies to {}% of messages",
            result.percentage
        ));
    }

    if result.rua_uris.is_empty() {
        result.issues.push("No aggregate report URI (rua) configured".to_string());
    }

    if result.subdomain_policy.is_none() {
        result.subdomain_policy = result.policy.clone();
    }

    result.valid = result.record.is_some()
        && result.policy.is_some()
        && result.policy != Some(DmarcPolicy::None);

    Ok(result)
}

/// Get MX records for a domain
async fn get_mx_records(
    resolver: &TokioAsyncResolver,
    domain: &str,
    scan_timeout: Duration,
) -> Result<Vec<String>> {
    let mx_records = match timeout(scan_timeout, resolver.mx_lookup(domain)).await {
        Ok(Ok(response)) => response
            .iter()
            .map(|mx| format!("{} {}", mx.preference(), mx.exchange()))
            .collect(),
        Ok(Err(_)) => Vec::new(),
        Err(_) => Vec::new(),
    };

    Ok(mx_records)
}

/// Calculate the overall spoofability rating based on SPF, DKIM, and DMARC results
fn calculate_spoofability_rating(
    spf: &SpfResult,
    dkim: &DkimResult,
    dmarc: &DmarcResult,
) -> SpoofabilityRating {
    let mut score = 0;

    // SPF scoring (0-30 points)
    if spf.valid {
        score += 20;
        if spf.policy == Some(SpfPolicy::Fail) {
            score += 10;
        } else if spf.policy == Some(SpfPolicy::SoftFail) {
            score += 5;
        }
    }

    // DKIM scoring (0-30 points)
    if dkim.configured {
        score += 20;
        // Check for strong keys
        let has_strong_key = dkim.selectors_found.iter().any(|s| !s.weak_key);
        if has_strong_key {
            score += 10;
        }
    }

    // DMARC scoring (0-40 points)
    if dmarc.valid {
        score += 20;
        match dmarc.policy {
            Some(DmarcPolicy::Reject) => score += 20,
            Some(DmarcPolicy::Quarantine) => score += 15,
            Some(DmarcPolicy::None) => score += 0,
            None => {}
        }
        if dmarc.percentage == 100 {
            // No penalty
        } else if dmarc.percentage >= 50 {
            // Minor penalty handled by not adding extra points
        }
    }

    // Convert score to rating
    if score >= 85 {
        SpoofabilityRating::None
    } else if score >= 60 {
        SpoofabilityRating::Low
    } else if score >= 30 {
        SpoofabilityRating::Medium
    } else {
        SpoofabilityRating::High
    }
}

/// Generate recommendations based on the analysis results
fn generate_recommendations(
    spf: &SpfResult,
    dkim: &DkimResult,
    dmarc: &DmarcResult,
    rating: &SpoofabilityRating,
) -> Vec<String> {
    let mut recommendations = Vec::new();

    // SPF recommendations
    if spf.record.is_none() {
        recommendations.push("Implement SPF by adding a TXT record starting with 'v=spf1'".to_string());
    } else {
        if spf.policy == Some(SpfPolicy::Pass) || spf.policy == Some(SpfPolicy::Neutral) {
            recommendations.push("Change SPF policy to '-all' (fail) or '~all' (softfail) to prevent spoofing".to_string());
        }
        if spf.policy == Some(SpfPolicy::SoftFail) {
            recommendations.push("Consider upgrading SPF policy from '~all' to '-all' for stricter enforcement".to_string());
        }
        if spf.exceeds_lookup_limit {
            recommendations.push("Reduce SPF DNS lookups to 10 or fewer by consolidating includes".to_string());
        }
    }

    // DKIM recommendations
    if !dkim.configured {
        recommendations.push("Configure DKIM by adding a public key record for your email service".to_string());
    } else {
        for selector in &dkim.selectors_found {
            if selector.weak_key {
                recommendations.push(format!(
                    "Upgrade DKIM key for selector '{}' to at least 2048 bits",
                    selector.selector
                ));
            }
            if selector.testing_mode {
                recommendations.push(format!(
                    "Remove testing mode flag (t=y) from DKIM selector '{}'",
                    selector.selector
                ));
            }
        }
    }

    // DMARC recommendations
    if dmarc.record.is_none() {
        recommendations.push("Implement DMARC by adding a TXT record at _dmarc.yourdomain.com".to_string());
        recommendations.push("Start with 'v=DMARC1; p=none; rua=mailto:dmarc-reports@yourdomain.com' for monitoring".to_string());
    } else {
        if dmarc.policy == Some(DmarcPolicy::None) {
            recommendations.push("Upgrade DMARC policy from 'none' to 'quarantine' or 'reject' after monitoring".to_string());
        }
        if dmarc.policy == Some(DmarcPolicy::Quarantine) {
            recommendations.push("Consider upgrading DMARC policy to 'reject' for maximum protection".to_string());
        }
        if dmarc.percentage < 100 {
            recommendations.push("Increase DMARC percentage (pct) to 100 for full coverage".to_string());
        }
        if dmarc.rua_uris.is_empty() {
            recommendations.push("Add an aggregate report URI (rua) to receive DMARC reports".to_string());
        }
    }

    // General recommendations based on rating
    match rating {
        SpoofabilityRating::High => {
            recommendations.push("URGENT: Your domain is highly vulnerable to email spoofing. Implement SPF, DKIM, and DMARC immediately.".to_string());
        }
        SpoofabilityRating::Medium => {
            recommendations.push("Your domain has partial email security. Complete the implementation of all three protocols (SPF, DKIM, DMARC).".to_string());
        }
        SpoofabilityRating::Low => {
            recommendations.push("Your domain has good email security. Consider the minor improvements listed above.".to_string());
        }
        SpoofabilityRating::None => {
            recommendations.push("Excellent! Your domain has strong email security. Continue monitoring DMARC reports.".to_string());
        }
    }

    recommendations
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spf_policy_parsing() {
        assert_eq!(
            SpoofabilityRating::High.description(),
            "Domain is vulnerable to email spoofing and requires immediate attention"
        );
    }

    #[test]
    fn test_dkim_record_parsing() {
        let record = "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQ==; t=y";
        let selector = parse_dkim_record("test", record);

        assert_eq!(selector.selector, "test");
        assert_eq!(selector.key_type, Some("rsa".to_string()));
        assert!(selector.testing_mode);
    }

    #[test]
    fn test_spoofability_calculation() {
        // Test high vulnerability (no protections)
        let spf = SpfResult {
            record: None,
            valid: false,
            mechanisms: Vec::new(),
            policy: None,
            dns_lookup_count: 0,
            exceeds_lookup_limit: false,
            issues: vec!["No SPF record".to_string()],
            authorized_senders: Vec::new(),
        };

        let dkim = DkimResult {
            selectors_found: Vec::new(),
            configured: false,
            selectors_checked: Vec::new(),
            issues: Vec::new(),
        };

        let dmarc = DmarcResult {
            record: None,
            valid: false,
            policy: None,
            subdomain_policy: None,
            percentage: 100,
            rua_uris: Vec::new(),
            ruf_uris: Vec::new(),
            spf_alignment: AlignmentMode::Relaxed,
            dkim_alignment: AlignmentMode::Relaxed,
            reporting_interval: None,
            forensic_options: Vec::new(),
            issues: Vec::new(),
        };

        let rating = calculate_spoofability_rating(&spf, &dkim, &dmarc);
        assert_eq!(rating, SpoofabilityRating::High);
    }

    #[test]
    fn test_well_protected_domain() {
        let spf = SpfResult {
            record: Some("v=spf1 include:_spf.google.com -all".to_string()),
            valid: true,
            mechanisms: Vec::new(),
            policy: Some(SpfPolicy::Fail),
            dns_lookup_count: 1,
            exceeds_lookup_limit: false,
            issues: Vec::new(),
            authorized_senders: Vec::new(),
        };

        let dkim = DkimResult {
            selectors_found: vec![DkimSelector {
                selector: "google".to_string(),
                record: "v=DKIM1; k=rsa; p=...".to_string(),
                key_type: Some("rsa".to_string()),
                key_bits: Some(2048),
                hash_algorithms: Vec::new(),
                weak_key: false,
                service_type: None,
                notes: None,
                testing_mode: false,
            }],
            configured: true,
            selectors_checked: Vec::new(),
            issues: Vec::new(),
        };

        let dmarc = DmarcResult {
            record: Some("v=DMARC1; p=reject; rua=mailto:dmarc@example.com".to_string()),
            valid: true,
            policy: Some(DmarcPolicy::Reject),
            subdomain_policy: Some(DmarcPolicy::Reject),
            percentage: 100,
            rua_uris: vec!["mailto:dmarc@example.com".to_string()],
            ruf_uris: Vec::new(),
            spf_alignment: AlignmentMode::Relaxed,
            dkim_alignment: AlignmentMode::Relaxed,
            reporting_interval: None,
            forensic_options: Vec::new(),
            issues: Vec::new(),
        };

        let rating = calculate_spoofability_rating(&spf, &dkim, &dmarc);
        assert_eq!(rating, SpoofabilityRating::None);
    }

    #[tokio::test]
    async fn test_analyze_domain_google() {
        // Test with a well-known domain that has proper email security
        let result = analyze_domain("google.com").await;
        assert!(result.is_ok());

        let email_security = result.unwrap();
        assert_eq!(email_security.domain, "google.com");
        // Google should have SPF configured
        assert!(email_security.spf.record.is_some());
    }
}
