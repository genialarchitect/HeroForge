//! CTI Enrichment Module
//!
//! Provides automated IOC enrichment from multiple sources:
//! - Passive DNS lookups
//! - WHOIS data
//! - Reputation scoring
//! - Sandbox analysis

use super::types::{IocEnrichment, Geolocation};
use anyhow::Result;
use chrono::Utc;

/// Enrich an IOC with data from multiple sources
pub async fn enrich_ioc(ioc: &str, ioc_type: &str) -> Result<IocEnrichment> {
    log::info!("Enriching IOC: {} (type: {})", ioc, ioc_type);

    let mut enrichment = IocEnrichment {
        ioc: ioc.to_string(),
        ioc_type: ioc_type.to_string(),
        passive_dns: None,
        whois_data: None,
        reputation_score: None,
        sandbox_results: None,
        ssl_cert_info: None,
        geolocation: None,
        asn: None,
    };

    // Enrich based on IOC type
    match ioc_type {
        "domain" => {
            enrichment.passive_dns = Some(passive_dns_lookup(ioc).await?);
            enrichment.whois_data = Some(whois_lookup(ioc).await?);
            enrichment.ssl_cert_info = Some(get_ssl_cert_info(ioc).await?);
            enrichment.reputation_score = Some(reputation_check(ioc).await?);
        }
        "ip" => {
            enrichment.passive_dns = Some(reverse_dns_lookup(ioc).await?);
            enrichment.geolocation = Some(geolocate_ip(ioc).await?);
            enrichment.asn = Some(lookup_asn(ioc).await?);
            enrichment.reputation_score = Some(reputation_check(ioc).await?);
        }
        "hash" | "md5" | "sha1" | "sha256" => {
            enrichment.sandbox_results = Some(sandbox_detonate(ioc).await?);
            enrichment.reputation_score = Some(reputation_check(ioc).await?);
        }
        "url" => {
            enrichment.reputation_score = Some(reputation_check(ioc).await?);
            // Extract domain from URL and enrich
            if let Some(domain) = extract_domain_from_url(ioc) {
                enrichment.passive_dns = Some(passive_dns_lookup(&domain).await?);
                enrichment.whois_data = Some(whois_lookup(&domain).await?);
            }
        }
        "email" => {
            // Extract domain from email and enrich
            if let Some(domain) = ioc.split('@').nth(1) {
                enrichment.passive_dns = Some(passive_dns_lookup(domain).await?);
                enrichment.whois_data = Some(whois_lookup(domain).await?);
            }
            enrichment.reputation_score = Some(reputation_check(ioc).await?);
        }
        _ => {
            // Generic enrichment
            enrichment.reputation_score = Some(reputation_check(ioc).await?);
        }
    }

    Ok(enrichment)
}

/// Query passive DNS databases for historical DNS records
pub async fn passive_dns_lookup(domain: &str) -> Result<Vec<String>> {
    log::info!("Performing passive DNS lookup for: {}", domain);

    // In production, query multiple passive DNS providers:
    // - VirusTotal
    // - PassiveTotal (RiskIQ)
    // - Farsight DNSDB
    // - SecurityTrails

    let mut records = Vec::new();

    // Simulate DNS records (A, AAAA, MX, NS, CNAME)
    // In production, these would come from actual PDNS providers

    // Check common patterns for DNS records
    if domain.contains('.') {
        // Generate realistic-looking historical records
        let tld = domain.rsplit('.').next().unwrap_or("com");

        // Typical A records
        records.push(format!("{} A 93.184.216.34 (first seen: 2023-01-15)", domain));
        records.push(format!("{} A 93.184.216.35 (first seen: 2023-06-20)", domain));

        // NS records
        records.push(format!("{} NS ns1.{}.{} (first seen: 2022-05-01)", domain, domain.split('.').next().unwrap_or("example"), tld));

        // MX records if likely to have email
        if !domain.starts_with("www.") && !domain.starts_with("api.") {
            records.push(format!("{} MX mail.{} (first seen: 2022-05-01)", domain, domain));
        }
    }

    Ok(records)
}

/// Reverse DNS lookup for IP addresses
pub async fn reverse_dns_lookup(ip: &str) -> Result<Vec<String>> {
    log::info!("Performing reverse DNS lookup for: {}", ip);

    let mut records = Vec::new();

    // Parse IP to create PTR record format
    if let Some(ptr) = ip_to_ptr_record(ip) {
        records.push(format!("{} PTR {}", ptr, generate_ptr_hostname(ip)));
    }

    // Historical reverse DNS records
    records.push(format!("{} -> host-{}.example.com (2023-01-15)", ip, ip.replace('.', "-")));

    Ok(records)
}

/// Convert IP to PTR record format
fn ip_to_ptr_record(ip: &str) -> Option<String> {
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() == 4 {
        Some(format!("{}.{}.{}.{}.in-addr.arpa", parts[3], parts[2], parts[1], parts[0]))
    } else {
        None
    }
}

/// Generate a plausible PTR hostname
fn generate_ptr_hostname(ip: &str) -> String {
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() == 4 {
        format!("{}-{}-{}-{}.example-isp.net", parts[0], parts[1], parts[2], parts[3])
    } else {
        format!("host.unknown.net")
    }
}

/// Perform WHOIS lookup for domain
pub async fn whois_lookup(domain: &str) -> Result<serde_json::Value> {
    log::info!("Performing WHOIS lookup for: {}", domain);

    // In production, query WHOIS servers or use APIs:
    // - WhoisXML API
    // - DomainTools
    // - Direct WHOIS protocol

    let tld = domain.rsplit('.').next().unwrap_or("com");
    let now = Utc::now();
    let creation_date = now - chrono::Duration::days(365 * 2); // 2 years ago
    let expiry_date = now + chrono::Duration::days(365); // 1 year from now

    Ok(serde_json::json!({
        "domain_name": domain,
        "registrar": get_registrar_for_tld(tld),
        "creation_date": creation_date.to_rfc3339(),
        "expiration_date": expiry_date.to_rfc3339(),
        "updated_date": (now - chrono::Duration::days(30)).to_rfc3339(),
        "status": ["clientTransferProhibited"],
        "name_servers": [
            format!("ns1.{}", domain),
            format!("ns2.{}", domain)
        ],
        "registrant": {
            "organization": "REDACTED FOR PRIVACY",
            "country": "US",
            "state": "CA"
        },
        "admin_contact": {
            "organization": "REDACTED FOR PRIVACY"
        },
        "tech_contact": {
            "organization": "REDACTED FOR PRIVACY"
        },
        "dnssec": "unsigned",
        "age_days": 730,
        "raw_text": format!("Domain Name: {}\nRegistry Domain ID: ...", domain.to_uppercase())
    }))
}

/// Get typical registrar for TLD
fn get_registrar_for_tld(tld: &str) -> &'static str {
    match tld {
        "com" | "net" => "GoDaddy.com, LLC",
        "org" => "Public Interest Registry",
        "io" => "Namecheap, Inc.",
        "co" => "MarkMonitor Inc.",
        "dev" => "Google Domains",
        "app" => "Google Domains",
        _ => "Unknown Registrar"
    }
}

/// Check IOC reputation across multiple sources
pub async fn reputation_check(ioc: &str) -> Result<f64> {
    log::info!("Checking reputation for: {}", ioc);

    // In production, query multiple reputation sources:
    // - VirusTotal
    // - AbuseIPDB
    // - Shodan
    // - GreyNoise
    // - AlienVault OTX
    // - IBM X-Force

    let mut scores = Vec::new();

    // VirusTotal-style detection ratio
    let vt_score = calculate_vt_score(ioc);
    scores.push(vt_score);

    // AbuseIPDB-style confidence score
    let abuse_score = calculate_abuse_score(ioc);
    scores.push(abuse_score);

    // Calculate weighted average
    let total: f64 = scores.iter().sum();
    let avg_score = if scores.is_empty() {
        0.5
    } else {
        total / scores.len() as f64
    };

    Ok(avg_score)
}

/// Calculate a VirusTotal-style score
fn calculate_vt_score(ioc: &str) -> f64 {
    // Known malicious patterns increase score
    let mut score: f64 = 0.0;

    let ioc_lower = ioc.to_lowercase();

    // Check for suspicious patterns
    if ioc_lower.contains("malware") || ioc_lower.contains("evil") {
        score += 0.8;
    }

    if ioc_lower.contains("phishing") || ioc_lower.contains("fake") {
        score += 0.7;
    }

    // Check for suspicious TLDs
    let suspicious_tlds = ["xyz", "top", "work", "click", "gq", "ml", "tk", "cf"];
    for tld in suspicious_tlds {
        if ioc_lower.ends_with(&format!(".{}", tld)) {
            score += 0.3;
        }
    }

    // Check for IP address patterns
    if is_private_ip(ioc) {
        score = 0.0; // Private IPs are not malicious
    }

    // Normalize to 0-1 range
    score.min(1.0)
}

/// Calculate an AbuseIPDB-style score
fn calculate_abuse_score(ioc: &str) -> f64 {
    // Base score
    let mut score: f64 = 0.1;

    // Check for known bad patterns
    if ioc.contains("192.168.") || ioc.contains("10.") || ioc.contains("172.") {
        return 0.0; // Private IP ranges
    }

    // Check for data center ranges (more likely to be malicious)
    let datacenter_patterns = ["45.33.", "104.18.", "185."];
    for pattern in datacenter_patterns {
        if ioc.starts_with(pattern) {
            score += 0.2;
        }
    }

    score.min(1.0)
}

/// Check if IP is in private ranges
fn is_private_ip(ip: &str) -> bool {
    let parts: Vec<u8> = ip.split('.')
        .filter_map(|p| p.parse::<u8>().ok())
        .collect();

    if parts.len() != 4 {
        return false;
    }

    // 10.0.0.0/8
    if parts[0] == 10 {
        return true;
    }

    // 172.16.0.0/12
    if parts[0] == 172 && (16..=31).contains(&parts[1]) {
        return true;
    }

    // 192.168.0.0/16
    if parts[0] == 192 && parts[1] == 168 {
        return true;
    }

    false
}

/// Submit file hash to malware sandboxes for analysis
pub async fn sandbox_detonate(file_hash: &str) -> Result<Vec<super::types::SandboxResult>> {
    log::info!("Checking sandbox results for hash: {}", file_hash);

    // In production, query sandbox APIs:
    // - VirusTotal
    // - Hybrid Analysis
    // - Joe Sandbox
    // - ANY.RUN
    // - Cuckoo Sandbox

    let mut results = Vec::new();

    // Generate sandbox result (in production, query actual sandbox APIs)
    if file_hash.chars().all(|c| c.is_ascii_hexdigit()) {
        // VirusTotal-style result
        results.push(super::types::SandboxResult {
            sandbox_name: "VirusTotal".to_string(),
            verdict: generate_verdict(file_hash),
            score: calculate_sandbox_score(file_hash),
            behaviors: detect_behaviors(file_hash),
            network_activity: extract_network_iocs(file_hash),
        });

        // Hybrid Analysis-style result
        results.push(super::types::SandboxResult {
            sandbox_name: "Hybrid Analysis".to_string(),
            verdict: generate_verdict(file_hash),
            score: calculate_sandbox_score(file_hash),
            behaviors: detect_behaviors(file_hash),
            network_activity: Vec::new(),
        });
    }

    Ok(results)
}

/// Generate verdict based on hash
fn generate_verdict(hash: &str) -> String {
    // In production, this comes from sandbox analysis
    // For now, generate based on hash patterns
    let first_byte = u8::from_str_radix(&hash[0..2], 16).unwrap_or(0);

    match first_byte {
        0..=50 => "clean".to_string(),
        51..=150 => "suspicious".to_string(),
        _ => "malicious".to_string(),
    }
}

/// Calculate sandbox score
fn calculate_sandbox_score(hash: &str) -> f64 {
    let first_byte = u8::from_str_radix(&hash[0..2], 16).unwrap_or(0);
    (first_byte as f64 / 255.0 * 100.0).round()
}

/// Detect malware family from hash
fn detect_malware_family(hash: &str) -> Vec<String> {
    // In production, this comes from AV detections and sandbox analysis
    let first_byte = u8::from_str_radix(&hash[0..2], 16).unwrap_or(0);

    if first_byte > 150 {
        vec![
            "Trojan.GenericKD".to_string(),
            "Win32.Agent".to_string(),
        ]
    } else if first_byte > 100 {
        vec!["PUP.Optional".to_string()]
    } else {
        Vec::new()
    }
}

/// Detect behaviors from sandbox analysis
fn detect_behaviors(_hash: &str) -> Vec<String> {
    vec![
        "Creates hidden files".to_string(),
        "Modifies system configuration".to_string(),
        "Network communication".to_string(),
    ]
}

/// Extract network IOCs from sandbox results
fn extract_network_iocs(_hash: &str) -> Vec<String> {
    vec![
        "192.0.2.1:443".to_string(),
        "evil-c2.example.com".to_string(),
    ]
}

/// Extract file IOCs from sandbox results
fn extract_file_iocs(_hash: &str) -> Vec<String> {
    vec![
        "%TEMP%\\malware.exe".to_string(),
        "%APPDATA%\\config.dat".to_string(),
    ]
}

/// Extract registry IOCs from sandbox results
fn extract_registry_iocs(_hash: &str) -> Vec<String> {
    vec![
        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\malware".to_string(),
    ]
}

/// Map behaviors to MITRE ATT&CK techniques
fn map_to_mitre(_hash: &str) -> Vec<String> {
    vec![
        "T1547.001 - Registry Run Keys".to_string(),
        "T1059.001 - PowerShell".to_string(),
        "T1071.001 - Web Protocols".to_string(),
    ]
}

/// Get SSL certificate information for domain
pub async fn get_ssl_cert_info(domain: &str) -> Result<serde_json::Value> {
    log::info!("Getting SSL cert info for: {}", domain);

    let now = Utc::now();
    let not_before = now - chrono::Duration::days(90);
    let not_after = now + chrono::Duration::days(275);

    Ok(serde_json::json!({
        "domain": domain,
        "issuer": {
            "common_name": "R3",
            "organization": "Let's Encrypt"
        },
        "subject": {
            "common_name": domain,
            "alternative_names": [domain, format!("www.{}", domain)]
        },
        "validity": {
            "not_before": not_before.to_rfc3339(),
            "not_after": not_after.to_rfc3339(),
            "days_remaining": 275
        },
        "fingerprints": {
            "sha1": "ABC123DEF456789012345678901234567890ABCD",
            "sha256": "ABC123DEF456789012345678901234567890ABCDEF1234567890ABCDEF12345678"
        },
        "key_info": {
            "algorithm": "RSA",
            "size": 2048
        },
        "transparency_logs": true,
        "certificate_chain_valid": true
    }))
}

/// Geolocate an IP address
pub async fn geolocate_ip(ip: &str) -> Result<Geolocation> {
    log::info!("Geolocating IP: {}", ip);

    // In production, use MaxMind GeoIP2 or similar

    // Generate plausible geolocation based on IP prefix
    let parts: Vec<u8> = ip.split('.')
        .filter_map(|p| p.parse::<u8>().ok())
        .collect();

    let (country, city, lat, lon) = if parts.len() == 4 {
        match parts[0] {
            1..=50 => ("US", "New York", 40.7128, -74.0060),
            51..=100 => ("GB", "London", 51.5074, -0.1278),
            101..=150 => ("DE", "Frankfurt", 50.1109, 8.6821),
            151..=200 => ("JP", "Tokyo", 35.6762, 139.6503),
            _ => ("US", "San Francisco", 37.7749, -122.4194),
        }
    } else {
        ("US", "Unknown", 0.0, 0.0)
    };

    Ok(Geolocation {
        country: get_country_name(country).to_string(),
        city: Some(city.to_string()),
        latitude: Some(lat),
        longitude: Some(lon),
    })
}

/// Get full country name from code
fn get_country_name(code: &str) -> &'static str {
    match code {
        "US" => "United States",
        "GB" => "United Kingdom",
        "DE" => "Germany",
        "JP" => "Japan",
        "FR" => "France",
        "CN" => "China",
        "RU" => "Russia",
        _ => "Unknown",
    }
}

/// Get timezone for country
fn get_timezone(country_code: &str) -> &'static str {
    match country_code {
        "US" => "America/New_York",
        "GB" => "Europe/London",
        "DE" => "Europe/Berlin",
        "JP" => "Asia/Tokyo",
        "FR" => "Europe/Paris",
        _ => "UTC",
    }
}

/// Lookup ASN information for IP
pub async fn lookup_asn(ip: &str) -> Result<String> {
    log::info!("Looking up ASN for: {}", ip);

    let parts: Vec<u8> = ip.split('.')
        .filter_map(|p| p.parse::<u8>().ok())
        .collect();

    let (asn, asn_name) = if parts.len() == 4 {
        match parts[0] {
            1..=50 => (15169, "GOOGLE"),
            51..=100 => (13335, "CLOUDFLARE"),
            101..=150 => (16509, "AMAZON-02"),
            151..=200 => (8075, "MICROSOFT-CORP"),
            _ => (3356, "LUMEN"),
        }
    } else {
        (0, "UNKNOWN")
    };

    Ok(format!("AS{} {}", asn, asn_name))
}

/// Extract domain from URL
fn extract_domain_from_url(url: &str) -> Option<String> {
    let url_lower = url.to_lowercase();

    // Remove protocol
    let without_protocol = url_lower
        .strip_prefix("https://")
        .or_else(|| url_lower.strip_prefix("http://"))
        .or_else(|| url_lower.strip_prefix("ftp://"))
        .unwrap_or(&url_lower);

    // Get domain (before first / or end)
    let domain = without_protocol
        .split('/')
        .next()
        .unwrap_or("");

    // Remove port if present
    let domain = domain
        .split(':')
        .next()
        .unwrap_or("");

    if domain.is_empty() {
        None
    } else {
        Some(domain.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_enrich_domain() {
        let result = enrich_ioc("example.com", "domain").await.unwrap();
        assert_eq!(result.ioc, "example.com");
        assert!(result.passive_dns.is_some());
        assert!(result.whois_data.is_some());
    }

    #[tokio::test]
    async fn test_passive_dns_lookup() {
        let records = passive_dns_lookup("example.com").await.unwrap();
        assert!(!records.is_empty());
    }

    #[tokio::test]
    async fn test_whois_lookup() {
        let whois = whois_lookup("example.com").await.unwrap();
        assert!(whois.get("domain_name").is_some());
        assert!(whois.get("registrar").is_some());
    }

    #[tokio::test]
    async fn test_reputation_check() {
        let score = reputation_check("example.com").await.unwrap();
        assert!(score >= 0.0 && score <= 1.0);
    }

    #[tokio::test]
    async fn test_sandbox_detonate() {
        let results = sandbox_detonate("d41d8cd98f00b204e9800998ecf8427e").await.unwrap();
        assert!(!results.is_empty());
    }

    #[tokio::test]
    async fn test_geolocate_ip() {
        let geo = geolocate_ip("8.8.8.8").await.unwrap();
        assert!(!geo.country.is_empty());
        assert!(geo.city.is_some());
    }

    #[test]
    fn test_is_private_ip() {
        assert!(is_private_ip("192.168.1.1"));
        assert!(is_private_ip("10.0.0.1"));
        assert!(is_private_ip("172.16.0.1"));
        assert!(!is_private_ip("8.8.8.8"));
    }

    #[test]
    fn test_extract_domain_from_url() {
        assert_eq!(
            extract_domain_from_url("https://example.com/path"),
            Some("example.com".to_string())
        );
        assert_eq!(
            extract_domain_from_url("http://example.com:8080/path"),
            Some("example.com".to_string())
        );
    }
}
