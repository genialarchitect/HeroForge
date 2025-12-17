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

/// Attempt AXFR request using raw DNS protocol over TCP
async fn attempt_axfr_request(ns_addr: SocketAddr, domain: &str) -> Result<bool> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    debug!("Attempting AXFR request to {} for domain {}", ns_addr, domain);

    // Connect to the nameserver on port 53 via TCP
    let mut stream = TcpStream::connect(ns_addr).await?;

    // Build the AXFR query
    let query = build_axfr_query(domain)?;

    // DNS over TCP requires a 2-byte length prefix
    let length = (query.len() as u16).to_be_bytes();
    stream.write_all(&length).await?;
    stream.write_all(&query).await?;
    stream.flush().await?;

    // Read the response length (2 bytes)
    let mut length_buf = [0u8; 2];
    stream.read_exact(&mut length_buf).await?;
    let response_length = u16::from_be_bytes(length_buf) as usize;

    // Sanity check on response length
    if response_length < 12 || response_length > 65535 {
        debug!("Invalid response length: {}", response_length);
        return Ok(false);
    }

    // Read the response
    let mut response = vec![0u8; response_length];
    stream.read_exact(&mut response).await?;

    // Parse the response to check if zone transfer was successful
    let vulnerable = parse_axfr_response(&response);

    if vulnerable {
        info!("Zone transfer vulnerability detected for domain {}", domain);
    } else {
        debug!("Zone transfer not allowed for domain {}", domain);
    }

    Ok(vulnerable)
}

/// Build an AXFR DNS query packet
fn build_axfr_query(domain: &str) -> Result<Vec<u8>> {
    let mut query = Vec::new();

    // DNS Header (12 bytes)
    // Transaction ID (2 bytes) - random value
    let transaction_id: u16 = rand::random();
    query.extend_from_slice(&transaction_id.to_be_bytes());

    // Flags (2 bytes) - standard query (0x0000)
    // QR=0 (query), Opcode=0 (standard), AA=0, TC=0, RD=1, RA=0, Z=0, RCODE=0
    query.extend_from_slice(&[0x00, 0x00]);

    // QDCOUNT (2 bytes) - 1 question
    query.extend_from_slice(&[0x00, 0x01]);

    // ANCOUNT (2 bytes) - 0 answers
    query.extend_from_slice(&[0x00, 0x00]);

    // NSCOUNT (2 bytes) - 0 authority records
    query.extend_from_slice(&[0x00, 0x00]);

    // ARCOUNT (2 bytes) - 0 additional records
    query.extend_from_slice(&[0x00, 0x00]);

    // Question Section
    // QNAME - domain name in DNS label format
    encode_domain_name(domain, &mut query)?;

    // QTYPE (2 bytes) - 252 (AXFR)
    query.extend_from_slice(&[0x00, 0xFC]);

    // QCLASS (2 bytes) - 1 (IN - Internet)
    query.extend_from_slice(&[0x00, 0x01]);

    Ok(query)
}

/// Encode a domain name in DNS wire format (length-prefixed labels)
fn encode_domain_name(domain: &str, buffer: &mut Vec<u8>) -> Result<()> {
    // Split domain into labels and encode each with length prefix
    for label in domain.split('.') {
        let label_bytes = label.as_bytes();
        if label_bytes.is_empty() {
            continue;
        }
        if label_bytes.len() > 63 {
            return Err(anyhow::anyhow!("DNS label too long: {}", label));
        }
        buffer.push(label_bytes.len() as u8);
        buffer.extend_from_slice(label_bytes);
    }
    // Null byte to terminate the domain name
    buffer.push(0x00);
    Ok(())
}

/// Parse AXFR response to determine if zone transfer was successful
fn parse_axfr_response(response: &[u8]) -> bool {
    // Minimum DNS header size is 12 bytes
    if response.len() < 12 {
        debug!("Response too short: {} bytes", response.len());
        return false;
    }

    // Parse flags (bytes 2-3)
    let flags = u16::from_be_bytes([response[2], response[3]]);

    // Check QR bit (bit 15) - should be 1 for response
    if (flags & 0x8000) == 0 {
        debug!("Not a response (QR=0)");
        return false;
    }

    // Check RCODE (bits 0-3) - should be 0 for success
    let rcode = flags & 0x000F;
    if rcode != 0 {
        debug!("AXFR refused or error, RCODE: {}", rcode);
        // RCODE values:
        // 0 = No error
        // 1 = Format error
        // 2 = Server failure
        // 3 = Name error (NXDOMAIN)
        // 4 = Not implemented
        // 5 = Refused
        // 9 = Not authorized
        return false;
    }

    // Parse answer count (bytes 6-7)
    let ancount = u16::from_be_bytes([response[6], response[7]]);

    // A successful AXFR will have multiple answer records
    // The zone transfer starts and ends with SOA records
    // If we got any answer records with RCODE=0, the server allowed the transfer
    if ancount > 0 {
        debug!("AXFR response has {} answer records", ancount);

        // Try to verify this is actually zone data by looking for SOA record
        // A valid AXFR starts with an SOA record (type 6)
        if let Some(is_soa) = check_first_answer_is_soa(response) {
            if is_soa {
                debug!("First answer is SOA - zone transfer successful");
                return true;
            }
        }

        // Even if we can't parse the records, having answers with RCODE=0
        // for an AXFR query indicates the transfer was allowed
        return true;
    }

    debug!("AXFR response has no answer records");
    false
}

/// Check if the first answer record is an SOA record (AXFR always starts with SOA)
fn check_first_answer_is_soa(response: &[u8]) -> Option<bool> {
    // Skip the header (12 bytes)
    let mut offset = 12;

    // Skip the question section
    // QDCOUNT is at bytes 4-5
    let qdcount = u16::from_be_bytes([response[4], response[5]]) as usize;

    for _ in 0..qdcount {
        // Skip QNAME
        offset = skip_dns_name(response, offset)?;
        // Skip QTYPE (2) and QCLASS (2)
        offset += 4;
        if offset > response.len() {
            return None;
        }
    }

    // Now we're at the answer section
    // Skip the name of the first answer
    offset = skip_dns_name(response, offset)?;

    // Check we have enough bytes for TYPE
    if offset + 2 > response.len() {
        return None;
    }

    // Read TYPE (2 bytes)
    let rtype = u16::from_be_bytes([response[offset], response[offset + 1]]);

    // SOA record type is 6
    Some(rtype == 6)
}

/// Skip a DNS name in wire format (handles compression)
fn skip_dns_name(data: &[u8], mut offset: usize) -> Option<usize> {
    loop {
        if offset >= data.len() {
            return None;
        }

        let len = data[offset];

        // Check for compression pointer (top 2 bits set)
        if (len & 0xC0) == 0xC0 {
            // Compression pointer - 2 bytes total, we're done
            return Some(offset + 2);
        }

        // Check for end of name
        if len == 0 {
            return Some(offset + 1);
        }

        // Regular label - skip length byte + label bytes
        offset += 1 + (len as usize);
    }
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

    #[test]
    fn test_encode_domain_name() {
        let mut buffer = Vec::new();
        encode_domain_name("example.com", &mut buffer).unwrap();
        // Expected: \x07example\x03com\x00
        assert_eq!(buffer, vec![7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0]);
    }

    #[test]
    fn test_encode_domain_name_subdomain() {
        let mut buffer = Vec::new();
        encode_domain_name("www.example.com", &mut buffer).unwrap();
        // Expected: \x03www\x07example\x03com\x00
        assert_eq!(buffer, vec![3, b'w', b'w', b'w', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0]);
    }

    #[test]
    fn test_build_axfr_query() {
        let query = build_axfr_query("example.com").unwrap();
        // Check minimum length (12 byte header + domain + 4 bytes for type/class)
        assert!(query.len() >= 12 + 13 + 4);
        // Check QDCOUNT = 1
        assert_eq!(query[4], 0);
        assert_eq!(query[5], 1);
        // Check QTYPE = 252 (AXFR) at end of query
        assert_eq!(query[query.len() - 4], 0x00);
        assert_eq!(query[query.len() - 3], 0xFC);
        // Check QCLASS = 1 (IN) at end
        assert_eq!(query[query.len() - 2], 0x00);
        assert_eq!(query[query.len() - 1], 0x01);
    }

    #[test]
    fn test_parse_axfr_response_refused() {
        // Simulate a refused AXFR response (RCODE = 5)
        let response = vec![
            0x00, 0x01, // Transaction ID
            0x80, 0x05, // Flags: QR=1, RCODE=5 (refused)
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x00, // ANCOUNT = 0
            0x00, 0x00, // NSCOUNT = 0
            0x00, 0x00, // ARCOUNT = 0
        ];
        assert!(!parse_axfr_response(&response));
    }

    #[test]
    fn test_parse_axfr_response_success() {
        // Simulate a successful AXFR response with SOA record
        let mut response = vec![
            0x00, 0x01, // Transaction ID
            0x84, 0x00, // Flags: QR=1, AA=1, RCODE=0 (success)
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x01, // ANCOUNT = 1 (has answer)
            0x00, 0x00, // NSCOUNT = 0
            0x00, 0x00, // ARCOUNT = 0
            // Question section: example.com AXFR IN
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            0x03, b'c', b'o', b'm', 0x00,
            0x00, 0xFC, // QTYPE = AXFR
            0x00, 0x01, // QCLASS = IN
            // Answer section: SOA record
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            0x03, b'c', b'o', b'm', 0x00,
            0x00, 0x06, // TYPE = SOA (6)
            0x00, 0x01, // CLASS = IN
            0x00, 0x00, 0x00, 0x3C, // TTL = 60
            0x00, 0x10, // RDLENGTH = 16 (placeholder)
        ];
        // Add some placeholder RDATA for SOA (simplified)
        response.extend_from_slice(&[0; 16]);

        assert!(parse_axfr_response(&response));
    }

    #[test]
    fn test_parse_axfr_response_too_short() {
        let response = vec![0x00, 0x01, 0x80, 0x00]; // Only 4 bytes
        assert!(!parse_axfr_response(&response));
    }

    #[test]
    fn test_skip_dns_name_regular() {
        let data = vec![
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            0x03, b'c', b'o', b'm', 0x00,
            0xFF, 0xFF, // Extra bytes after name
        ];
        let result = skip_dns_name(&data, 0);
        assert_eq!(result, Some(13)); // Ends after null byte
    }

    #[test]
    fn test_skip_dns_name_compressed() {
        // Compression pointer: 0xC0 0x0C means pointer to offset 12
        let data = vec![
            0x03, b'w', b'w', b'w',
            0xC0, 0x0C, // Compression pointer
            0xFF, 0xFF, // Extra bytes
        ];
        let result = skip_dns_name(&data, 0);
        assert_eq!(result, Some(6)); // Ends after 2-byte pointer
    }
}
