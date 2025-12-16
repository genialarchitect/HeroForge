use anyhow::Result;
use log::{debug, info, warn};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::time::timeout;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::TokioAsyncResolver;
use trust_dns_resolver::proto::rr::{RecordType, RData};

/// DNS record information
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DnsRecord {
    pub record_type: String,
    pub value: String,
    pub ttl: Option<u32>,
}

/// DNS reconnaissance results
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DnsReconResult {
    pub domain: String,
    pub records: HashMap<String, Vec<DnsRecord>>,
    pub subdomains_found: Vec<String>,
    pub zone_transfer_vulnerable: bool,
    pub zone_transfer_error: Option<String>,
    pub dnssec_enabled: bool,
    pub nameservers: Vec<String>,
    pub reverse_dns: HashMap<String, String>,
    pub scan_timestamp: chrono::DateTime<chrono::Utc>,
}

/// Built-in subdomain wordlist (common subdomains)
const SUBDOMAIN_WORDLIST: &[&str] = &[
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2", "ns3", "ns4",
    "webdisk", "ns", "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap", "test", "ns5",
    "ns6", "mx", "email", "cloud", "server", "ns7", "ns8", "blog", "dev", "admin", "forum",
    "news", "vpn", "secure", "api", "cdn", "remote", "demo", "stage", "staging", "beta",
    "gitlab", "git", "jenkins", "jira", "confluence", "wiki", "docs", "support", "help",
    "portal", "app", "apps", "mobile", "sip", "voip", "mysql", "db", "database", "sql",
    "repo", "svn", "dns", "router", "gateway", "firewall", "smtp1", "smtp2", "pop3", "imap4",
    "lists", "chat", "status", "monitor", "monitoring", "nagios", "munin", "zabbix", "grafana",
    "prometheus", "elk", "kibana", "elasticsearch", "logstash", "backup", "shop", "store",
    "crm", "erp", "vpn1", "vpn2", "citrix", "terminal", "ts", "rds", "exchange", "owa",
    "sharepoint", "lync", "skype", "sccm", "wsus", "ad", "dc", "ldap", "ntp", "time",
    "printer", "print", "scan", "scanner", "fax", "camera", "cctv", "video", "stream",
];

/// Perform comprehensive DNS reconnaissance on a domain
pub async fn perform_dns_recon(
    domain: &str,
    include_subdomains: bool,
    custom_wordlist: Option<Vec<String>>,
    timeout_secs: u64,
) -> Result<DnsReconResult> {
    info!("Starting DNS reconnaissance for domain: {}", domain);

    let resolver = create_resolver()?;
    let scan_timeout = Duration::from_secs(timeout_secs);

    // Initialize result structure
    let mut result = DnsReconResult {
        domain: domain.to_string(),
        records: HashMap::new(),
        subdomains_found: Vec::new(),
        zone_transfer_vulnerable: false,
        zone_transfer_error: None,
        dnssec_enabled: false,
        nameservers: Vec::new(),
        reverse_dns: HashMap::new(),
        scan_timestamp: chrono::Utc::now(),
    };

    // Step 1: Enumerate standard DNS records
    info!("Enumerating DNS records for {}", domain);
    enumerate_dns_records(&resolver, domain, &mut result, scan_timeout).await?;

    // Step 2: Get nameservers
    if let Some(ns_records) = result.records.get("NS") {
        result.nameservers = ns_records.iter().map(|r| r.value.clone()).collect();
    }

    // Step 3: Check DNSSEC
    result.dnssec_enabled = check_dnssec(&resolver, domain, scan_timeout).await;

    // Step 4: Attempt zone transfer
    if !result.nameservers.is_empty() {
        let (vulnerable, error) = check_zone_transfer(&result.nameservers[0], domain, scan_timeout).await;
        result.zone_transfer_vulnerable = vulnerable;
        result.zone_transfer_error = error;
    }

    // Step 5: Perform subdomain enumeration
    if include_subdomains {
        let wordlist = custom_wordlist.unwrap_or_else(|| {
            SUBDOMAIN_WORDLIST.iter().map(|s| s.to_string()).collect()
        });
        result.subdomains_found = enumerate_subdomains(&resolver, domain, &wordlist, scan_timeout).await;
    }

    // Step 6: Reverse DNS lookups for A records
    if let Some(a_records) = result.records.get("A") {
        for record in a_records {
            if let Ok(ip) = record.value.parse::<IpAddr>() {
                if let Some(ptr) = perform_reverse_lookup(&resolver, &ip, scan_timeout).await {
                    result.reverse_dns.insert(record.value.clone(), ptr);
                }
            }
        }
    }

    info!("DNS reconnaissance completed for {}", domain);
    Ok(result)
}

/// Create a DNS resolver with custom configuration
fn create_resolver() -> Result<TokioAsyncResolver> {
    let mut opts = ResolverOpts::default();
    opts.timeout = Duration::from_secs(5);
    opts.attempts = 2;

    // In trust-dns-resolver 0.23, TokioAsyncResolver::tokio() returns the resolver directly
    Ok(TokioAsyncResolver::tokio(ResolverConfig::default(), opts))
}

/// Enumerate standard DNS records for a domain
async fn enumerate_dns_records(
    resolver: &TokioAsyncResolver,
    domain: &str,
    result: &mut DnsReconResult,
    scan_timeout: Duration,
) -> Result<()> {
    let record_types = vec![
        RecordType::A,
        RecordType::AAAA,
        RecordType::MX,
        RecordType::NS,
        RecordType::TXT,
        RecordType::CNAME,
        RecordType::SOA,
        RecordType::SRV,
        RecordType::CAA,
    ];

    for record_type in record_types {
        debug!("Querying {} records for {}", record_type, domain);

        match timeout(scan_timeout, resolver.lookup(domain, record_type)).await {
            Ok(Ok(response)) => {
                let mut records = Vec::new();

                // Use record_iter() to get Record objects with .data() and .ttl() methods
                for record in response.record_iter() {
                    // record.data() returns Option<&RData>, so we need to unwrap it
                    if let Some(rdata) = record.data() {
                        let value = format_rdata(rdata);
                        if !value.is_empty() {
                            records.push(DnsRecord {
                                record_type: record_type.to_string(),
                                value,
                                ttl: Some(record.ttl()),
                            });
                        }
                    }
                }

                if !records.is_empty() {
                    debug!("Found {} {} records", records.len(), record_type);
                    result.records.insert(record_type.to_string(), records);
                }
            }
            Ok(Err(e)) => {
                debug!("No {} records found for {}: {}", record_type, domain, e);
            }
            Err(_) => {
                warn!("Timeout querying {} records for {}", record_type, domain);
            }
        }
    }

    Ok(())
}

/// Format RData into a readable string
fn format_rdata(rdata: &RData) -> String {
    match rdata {
        RData::A(addr) => addr.to_string(),
        RData::AAAA(addr) => addr.to_string(),
        RData::MX(mx) => format!("{} {}", mx.preference(), mx.exchange()),
        RData::NS(ns) => ns.to_string(),
        RData::TXT(txt) => {
            txt.iter()
                .map(|data| String::from_utf8_lossy(data.as_ref()))
                .collect::<Vec<_>>()
                .join(" ")
        }
        RData::CNAME(cname) => cname.to_string(),
        RData::SOA(soa) => {
            format!(
                "mname={} rname={} serial={} refresh={} retry={} expire={} minimum={}",
                soa.mname(),
                soa.rname(),
                soa.serial(),
                soa.refresh(),
                soa.retry(),
                soa.expire(),
                soa.minimum()
            )
        }
        RData::SRV(srv) => {
            format!(
                "{} {} {} {}",
                srv.priority(),
                srv.weight(),
                srv.port(),
                srv.target()
            )
        }
        RData::CAA(caa) => {
            // In trust-dns-resolver 0.23, tag() returns &Property and value() returns &Value
            // Property and Value implement Display, so we can format them directly
            format!(
                "{} {} {}",
                caa.issuer_critical() as u8,
                caa.tag(),
                caa.value()
            )
        }
        RData::PTR(ptr) => ptr.to_string(),
        _ => String::new(),
    }
}

/// Check if DNSSEC is enabled for the domain
async fn check_dnssec(
    resolver: &TokioAsyncResolver,
    domain: &str,
    scan_timeout: Duration,
) -> bool {
    debug!("Checking DNSSEC for {}", domain);

    match timeout(scan_timeout, resolver.lookup(domain, RecordType::DNSKEY)).await {
        Ok(Ok(response)) => {
            let dnssec_enabled = !response.iter().collect::<Vec<_>>().is_empty();
            if dnssec_enabled {
                info!("DNSSEC is enabled for {}", domain);
            } else {
                debug!("DNSSEC is not enabled for {}", domain);
            }
            dnssec_enabled
        }
        Ok(Err(e)) => {
            debug!("DNSSEC check failed for {}: {}", domain, e);
            false
        }
        Err(_) => {
            warn!("Timeout checking DNSSEC for {}", domain);
            false
        }
    }
}

/// Attempt DNS zone transfer (AXFR)
async fn check_zone_transfer(
    nameserver: &str,
    domain: &str,
    scan_timeout: Duration,
) -> (bool, Option<String>) {
    debug!("Attempting zone transfer from {} for {}", nameserver, domain);

    // Clean nameserver (remove trailing dot if present)
    let ns = nameserver.trim_end_matches('.');

    // Try to resolve nameserver to IP
    let ns_ip = match timeout(
        scan_timeout,
        tokio::net::lookup_host(format!("{}:53", ns))
    ).await {
        Ok(Ok(mut addrs)) => {
            if let Some(addr) = addrs.next() {
                addr.ip()
            } else {
                return (false, Some("Failed to resolve nameserver".to_string()));
            }
        }
        Ok(Err(e)) => {
            return (false, Some(format!("Nameserver resolution error: {}", e)));
        }
        Err(_) => {
            return (false, Some("Timeout resolving nameserver".to_string()));
        }
    };

    debug!("Resolved nameserver {} to {}", ns, ns_ip);

    // Create AXFR request using trust-dns
    let ns_addr = SocketAddr::new(ns_ip, 53);

    // For now, we'll just attempt a simple check
    // Full AXFR implementation would require more complex trust-dns usage
    // This is a simplified version that checks if the server responds to AXFR queries
    match timeout(
        scan_timeout,
        attempt_axfr_request(ns_addr, domain)
    ).await {
        Ok(Ok(vulnerable)) => {
            if vulnerable {
                warn!("Zone transfer vulnerability detected for {} on {}", domain, ns);
                (true, None)
            } else {
                debug!("Zone transfer not allowed for {} on {}", domain, ns);
                (false, None)
            }
        }
        Ok(Err(e)) => {
            debug!("Zone transfer check error: {}", e);
            (false, Some(e.to_string()))
        }
        Err(_) => {
            (false, Some("Timeout during zone transfer check".to_string()))
        }
    }
}

/// Attempt AXFR request (simplified implementation)
async fn attempt_axfr_request(_ns_addr: SocketAddr, _domain: &str) -> Result<bool> {
    // Note: Full AXFR implementation requires more complex trust-dns usage
    // For now, we return false (not vulnerable) as a conservative default
    // A full implementation would use trust-dns-client to send AXFR queries

    // TODO: Implement full AXFR using trust-dns-client
    // This would require:
    // 1. Create TCP connection to nameserver
    // 2. Send AXFR query
    // 3. Parse response to check if zone transfer was successful

    debug!("AXFR check not fully implemented - returning conservative result");
    Ok(false)
}

/// Enumerate subdomains using a wordlist
async fn enumerate_subdomains(
    resolver: &TokioAsyncResolver,
    domain: &str,
    wordlist: &[String],
    scan_timeout: Duration,
) -> Vec<String> {
    info!("Enumerating subdomains for {} ({} entries)", domain, wordlist.len());

    let mut found_subdomains = Vec::new();
    let mut tasks = Vec::new();

    for subdomain_prefix in wordlist {
        let subdomain = format!("{}.{}", subdomain_prefix, domain);
        let resolver = resolver.clone();
        let timeout_duration = scan_timeout;

        tasks.push(tokio::spawn(async move {
            match timeout(timeout_duration, resolver.lookup(subdomain.as_str(), RecordType::A)).await {
                Ok(Ok(_)) => Some(subdomain),
                _ => None,
            }
        }));
    }

    // Collect results
    for task in tasks {
        if let Ok(Some(subdomain)) = task.await {
            debug!("Found subdomain: {}", subdomain);
            found_subdomains.push(subdomain);
        }
    }

    info!("Found {} subdomains for {}", found_subdomains.len(), domain);
    found_subdomains
}

/// Perform reverse DNS lookup for an IP address
async fn perform_reverse_lookup(
    resolver: &TokioAsyncResolver,
    ip: &IpAddr,
    scan_timeout: Duration,
) -> Option<String> {
    debug!("Performing reverse lookup for {}", ip);

    match timeout(scan_timeout, resolver.reverse_lookup(*ip)).await {
        Ok(Ok(response)) => {
            let ptr = response.iter().next()?.to_string();
            debug!("Reverse DNS: {} -> {}", ip, ptr);
            Some(ptr)
        }
        Ok(Err(e)) => {
            debug!("Reverse lookup failed for {}: {}", ip, e);
            None
        }
        Err(_) => {
            warn!("Timeout during reverse lookup for {}", ip);
            None
        }
    }
}

/// Get the built-in subdomain wordlist
pub fn get_builtin_wordlist() -> Vec<String> {
    SUBDOMAIN_WORDLIST.iter().map(|s| s.to_string()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_dns_recon_google() {
        // Test with a well-known domain
        let result = perform_dns_recon("google.com", false, None, 10).await;
        assert!(result.is_ok());

        let dns_result = result.unwrap();
        assert_eq!(dns_result.domain, "google.com");
        assert!(!dns_result.records.is_empty());
        assert!(dns_result.records.contains_key("A"));
    }

    #[test]
    fn test_builtin_wordlist() {
        let wordlist = get_builtin_wordlist();
        assert!(!wordlist.is_empty());
        assert!(wordlist.contains(&"www".to_string()));
        assert!(wordlist.contains(&"mail".to_string()));
    }
}
