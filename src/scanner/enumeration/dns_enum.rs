use super::types::{DnsRecordType, EnumDepth, EnumerationResult, Finding, FindingType, ServiceType};
use super::wordlists::WordlistManager;
use crate::types::{ScanProgressMessage, ScanTarget};
use anyhow::Result;
use log::{debug, info, warn};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{broadcast::Sender, Semaphore};
use trust_dns_resolver::config::*;
use trust_dns_resolver::proto::rr::RecordType;
use trust_dns_resolver::TokioAsyncResolver;

const MAX_CONCURRENT_QUERIES: usize = 100;

/// Common SRV service prefixes for service discovery
const SRV_SERVICE_PREFIXES: &[&str] = &[
    // Active Directory / Kerberos
    "_ldap._tcp",
    "_ldap._tcp.dc._msdcs",
    "_ldap._tcp.gc._msdcs",
    "_ldap._tcp.pdc._msdcs",
    "_kerberos._tcp",
    "_kerberos._tcp.dc._msdcs",
    "_kpasswd._tcp",
    "_gc._tcp",
    // Common services
    "_http._tcp",
    "_https._tcp",
    "_sip._tcp",
    "_sip._udp",
    "_sips._tcp",
    "_xmpp-client._tcp",
    "_xmpp-server._tcp",
    "_jabber._tcp",
    "_imap._tcp",
    "_imaps._tcp",
    "_submission._tcp",
    "_caldav._tcp",
    "_caldavs._tcp",
    "_carddav._tcp",
    "_carddavs._tcp",
    // VoIP
    "_h323cs._tcp",
    "_h323ls._udp",
    // Other
    "_minecraft._tcp",
    "_minecraft._udp",
    "_ts3._udp",
    "_mumble._tcp",
];

/// Enumerate DNS service
pub async fn enumerate_dns(
    target: &ScanTarget,
    depth: EnumDepth,
    wordlist_path: &Option<PathBuf>,
    _timeout: Duration,
    progress_tx: Option<Sender<ScanProgressMessage>>,
) -> Result<EnumerationResult> {
    let start = Instant::now();
    info!(
        "Starting DNS enumeration for {} with depth: {:?}",
        target.ip, depth
    );

    let mut findings = Vec::new();
    let mut metadata = HashMap::new();
    let mut discovered_ips: HashSet<IpAddr> = HashSet::new();

    // Use the target IP as the nameserver if it's a DNS server
    let resolver = create_resolver_with_nameserver(target.ip)?;

    // Also create a public resolver for comparison and fallback
    let public_resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());

    // Determine the domain to query
    // If target has hostname, use that. Otherwise skip DNS enumeration
    let domain = match &target.hostname {
        Some(hostname) => hostname.clone(),
        None => {
            info!("No hostname provided for DNS enumeration, skipping");
            return Ok(EnumerationResult {
                service_type: ServiceType::Dns,
                enumeration_depth: depth,
                findings,
                duration: start.elapsed(),
                metadata,
            });
        }
    };

    metadata.insert("domain".to_string(), domain.clone());

    // Passive enumeration: Just basic lookups
    if matches!(depth, EnumDepth::Passive) {
        debug!("Passive DNS enumeration for {}", domain);
        let basic_findings = query_basic_records(&resolver, &domain).await;
        // Collect discovered IPs
        for finding in &basic_findings {
            if let Some(ip_str) = finding.metadata.get("ip") {
                if let Ok(ip) = ip_str.parse::<IpAddr>() {
                    discovered_ips.insert(ip);
                }
            }
        }
        findings.extend(basic_findings);

        return Ok(EnumerationResult {
            service_type: ServiceType::Dns,
            enumeration_depth: depth,
            findings,
            duration: start.elapsed(),
            metadata,
        });
    }

    // Active enumeration starts here

    // Step 1: Query all common record types
    info!("Querying DNS records for {}", domain);
    let basic_findings = query_basic_records(&resolver, &domain).await;
    for finding in &basic_findings {
        if let Some(ip_str) = finding.metadata.get("ip") {
            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                discovered_ips.insert(ip);
            }
        }
    }
    findings.extend(basic_findings);
    findings.extend(query_extended_records(&resolver, &domain).await);

    // Step 2: Query SRV records for service discovery
    info!("Querying SRV records for {}", domain);
    findings.extend(query_srv_records(&resolver, &domain).await);

    // Step 3: Query CAA records (Certificate Authority Authorization)
    info!("Querying CAA records for {}", domain);
    findings.extend(query_caa_records(&resolver, &domain).await);

    // Step 4: Check DNSSEC validation
    info!("Checking DNSSEC for {}", domain);
    findings.extend(check_dnssec(&resolver, &public_resolver, &domain).await);

    // Step 5: Wildcard detection
    info!("Checking for DNS wildcard for {}", domain);
    let (is_wildcard, wildcard_findings) = detect_wildcard(&resolver, &domain).await;
    findings.extend(wildcard_findings);
    metadata.insert("has_wildcard".to_string(), is_wildcard.to_string());

    // Step 6: Subdomain enumeration (light or aggressive)
    if !matches!(depth, EnumDepth::Passive) {
        let wordlist = if let Some(path) = wordlist_path {
            WordlistManager::load_custom_wordlist(path)?
        } else {
            let manager = WordlistManager::new();
            manager.get_subdomain_wordlist(depth).to_vec()
        };

        debug!(
            "Starting subdomain enumeration with {} entries",
            wordlist.len()
        );

        let subdomain_findings = enumerate_subdomains(
            &resolver,
            &domain,
            &wordlist,
            progress_tx.clone(),
            target,
        )
        .await;

        // Collect IPs from subdomains
        for finding in &subdomain_findings {
            if let Some(ip_str) = finding.metadata.get("ips") {
                for ip_part in ip_str.split(", ") {
                    if let Ok(ip) = ip_part.parse::<IpAddr>() {
                        discovered_ips.insert(ip);
                    }
                }
            }
        }
        findings.extend(subdomain_findings);
    }

    // Step 7: Zone transfer attempt (aggressive only)
    if matches!(depth, EnumDepth::Aggressive) {
        info!("Attempting zone transfer for {}", domain);
        let zone_findings = attempt_zone_transfer_full(target.ip, &domain).await;
        findings.extend(zone_findings);
    }

    // Step 8: Reverse DNS lookups for discovered IPs (light and aggressive)
    if !matches!(depth, EnumDepth::Passive) && !discovered_ips.is_empty() {
        info!("Performing reverse DNS lookups for {} discovered IPs", discovered_ips.len());
        let reverse_findings = query_reverse_dns(&public_resolver, &discovered_ips).await;
        findings.extend(reverse_findings);
    }

    metadata.insert("records_found".to_string(), findings.len().to_string());
    metadata.insert("discovered_ips".to_string(), discovered_ips.len().to_string());

    Ok(EnumerationResult {
        service_type: ServiceType::Dns,
        enumeration_depth: depth,
        findings,
        duration: start.elapsed(),
        metadata,
    })
}

/// Create a resolver that uses a specific nameserver
fn create_resolver_with_nameserver(nameserver_ip: IpAddr) -> Result<TokioAsyncResolver> {
    let nameserver = NameServerConfig {
        socket_addr: std::net::SocketAddr::new(nameserver_ip, 53),
        protocol: Protocol::Udp,
        tls_dns_name: None,
        trust_negative_responses: false,
        bind_addr: None,
    };

    let mut config = ResolverConfig::new();
    config.add_name_server(nameserver);

    let resolver = TokioAsyncResolver::tokio(config, ResolverOpts::default());
    Ok(resolver)
}

/// Query basic DNS records (A, AAAA)
async fn query_basic_records(resolver: &TokioAsyncResolver, domain: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    // A records
    if let Ok(response) = resolver.lookup_ip(domain).await {
        for ip in response.iter() {
            let dns_record_type = if ip.is_ipv4() { DnsRecordType::A } else { DnsRecordType::AAAA };
            findings.push(
                Finding::new(
                    FindingType::DnsRecord(dns_record_type.clone()),
                    format!("{} -> {}", domain, ip),
                )
                .with_metadata("record_type".to_string(), format!("{:?}", dns_record_type))
                .with_metadata("ip".to_string(), ip.to_string()),
            );
        }
    }

    findings
}

/// Query extended DNS records (MX, TXT, NS, etc.)
async fn query_extended_records(resolver: &TokioAsyncResolver, domain: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    // MX records
    if let Ok(response) = resolver.mx_lookup(domain).await {
        for mx in response.iter() {
            findings.push(
                Finding::new(
                    FindingType::DnsRecord(DnsRecordType::MX),
                    format!("MX: {} (priority: {})", mx.exchange(), mx.preference()),
                )
                .with_metadata("record_type".to_string(), "MX".to_string())
                .with_metadata("exchange".to_string(), mx.exchange().to_string())
                .with_metadata("priority".to_string(), mx.preference().to_string()),
            );
        }
    }

    // TXT records
    if let Ok(response) = resolver.txt_lookup(domain).await {
        for txt in response.iter() {
            let txt_data = txt
                .iter()
                .map(|d| String::from_utf8_lossy(d).to_string())
                .collect::<Vec<_>>()
                .join("");

            findings.push(
                Finding::new(FindingType::DnsRecord(DnsRecordType::TXT), format!("TXT: {}", txt_data))
                    .with_metadata("record_type".to_string(), "TXT".to_string())
                    .with_metadata("data".to_string(), txt_data),
            );
        }
    }

    // NS records
    if let Ok(response) = resolver.ns_lookup(domain).await {
        for ns in response.iter() {
            findings.push(
                Finding::new(FindingType::DnsRecord(DnsRecordType::NS), format!("NS: {}", ns))
                    .with_metadata("record_type".to_string(), "NS".to_string())
                    .with_metadata("nameserver".to_string(), ns.to_string()),
            );
        }
    }

    findings
}

/// Enumerate subdomains using a wordlist
async fn enumerate_subdomains(
    resolver: &TokioAsyncResolver,
    domain: &str,
    wordlist: &[String],
    progress_tx: Option<Sender<ScanProgressMessage>>,
    target: &ScanTarget,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_QUERIES));
    let mut tasks = Vec::new();

    for subdomain in wordlist {
        let full_domain = format!("{}.{}", subdomain, domain);
        let resolver = resolver.clone();
        let semaphore = semaphore.clone();
        let progress_tx = progress_tx.clone();
        let target_ip = target.ip.to_string();

        let task = tokio::spawn(async move {
            let _permit = semaphore.acquire().await.ok()?;

            if let Ok(response) = resolver.lookup_ip(&full_domain).await {
                let ips: Vec<String> = response.iter().map(|ip| ip.to_string()).collect();

                if !ips.is_empty() {
                    let mut finding = Finding::with_confidence(
                        FindingType::Subdomain,
                        full_domain.clone(),
                        95,
                    );

                    finding
                        .metadata
                        .insert("ips".to_string(), ips.join(", "));

                    // Send progress update
                    if let Some(tx) = progress_tx {
                        let _ = tx.send(ScanProgressMessage::EnumerationFinding {
                            ip: target_ip,
                            port: 53,
                            finding_type: "Subdomain".to_string(),
                            value: full_domain,
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

/// Query SRV records for service discovery
async fn query_srv_records(resolver: &TokioAsyncResolver, domain: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    for service_prefix in SRV_SERVICE_PREFIXES {
        let srv_name = format!("{}.{}", service_prefix, domain);

        if let Ok(response) = resolver.srv_lookup(&srv_name).await {
            for srv in response.iter() {
                let finding = Finding::new(
                    FindingType::DnsRecord(DnsRecordType::SRV),
                    format!(
                        "SRV: {} -> {}:{} (priority: {}, weight: {})",
                        srv_name,
                        srv.target(),
                        srv.port(),
                        srv.priority(),
                        srv.weight()
                    ),
                )
                .with_metadata("record_type".to_string(), "SRV".to_string())
                .with_metadata("service".to_string(), service_prefix.to_string())
                .with_metadata("target".to_string(), srv.target().to_string())
                .with_metadata("port".to_string(), srv.port().to_string())
                .with_metadata("priority".to_string(), srv.priority().to_string())
                .with_metadata("weight".to_string(), srv.weight().to_string());

                findings.push(finding);

                debug!("Found SRV record: {} -> {}:{}", srv_name, srv.target(), srv.port());
            }
        }
    }

    findings
}

/// Query CAA records (Certificate Authority Authorization)
async fn query_caa_records(resolver: &TokioAsyncResolver, domain: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Use generic lookup for CAA records
    if let Ok(response) = resolver.lookup(domain, RecordType::CAA).await {
        for record in response.iter() {
            let record_str = record.to_string();

            // Parse CAA record format: flag tag "value"
            let finding = Finding::new(
                FindingType::DnsRecord(DnsRecordType::CAA),
                format!("CAA: {}", record_str),
            )
            .with_metadata("record_type".to_string(), "CAA".to_string())
            .with_metadata("data".to_string(), record_str.clone());

            // Check for specific CAA tags
            let record_lower = record_str.to_lowercase();
            if record_lower.contains("issue ") || record_lower.contains("issuewild ") {
                findings.push(finding.with_metadata(
                    "ca_authorized".to_string(),
                    "true".to_string(),
                ));
            } else if record_lower.contains("iodef ") {
                findings.push(finding.with_metadata(
                    "reporting".to_string(),
                    "true".to_string(),
                ));
            } else {
                findings.push(finding);
            }
        }
    }

    // If no CAA records found, note this as a potential misconfiguration
    if findings.is_empty() {
        findings.push(
            Finding::with_confidence(
                FindingType::SecurityConfig,
                format!("No CAA records found for {}", domain),
                70,
            )
            .with_metadata("record_type".to_string(), "CAA".to_string())
            .with_metadata("status".to_string(), "missing".to_string())
            .with_metadata(
                "recommendation".to_string(),
                "Consider adding CAA records to restrict which CAs can issue certificates".to_string(),
            ),
        );
    }

    findings
}

/// Check DNSSEC status for a domain
async fn check_dnssec(
    target_resolver: &TokioAsyncResolver,
    public_resolver: &TokioAsyncResolver,
    domain: &str,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Check for DNSKEY records (indicates DNSSEC is configured)
    let has_dnskey = if let Ok(response) = public_resolver.lookup(domain, RecordType::DNSKEY).await {
        !response.iter().next().is_none()
    } else {
        false
    };

    // Check for DS records at parent zone
    let has_ds = if let Ok(response) = public_resolver.lookup(domain, RecordType::DS).await {
        !response.iter().next().is_none()
    } else {
        false
    };

    // Check for RRSIG records (signatures)
    let has_rrsig = if let Ok(response) = target_resolver.lookup(domain, RecordType::RRSIG).await {
        !response.iter().next().is_none()
    } else {
        false
    };

    if has_dnskey || has_ds || has_rrsig {
        let status = if has_dnskey && has_ds && has_rrsig {
            "fully_configured"
        } else if has_dnskey && has_rrsig {
            "configured_no_ds"
        } else if has_dnskey {
            "dnskey_only"
        } else {
            "partial"
        };

        findings.push(
            Finding::new(
                FindingType::SecurityConfig,
                format!("DNSSEC is enabled for {} (status: {})", domain, status),
            )
            .with_metadata("dnssec_status".to_string(), status.to_string())
            .with_metadata("has_dnskey".to_string(), has_dnskey.to_string())
            .with_metadata("has_ds".to_string(), has_ds.to_string())
            .with_metadata("has_rrsig".to_string(), has_rrsig.to_string()),
        );

        // Record individual DNSSEC records found
        if has_dnskey {
            findings.push(
                Finding::new(
                    FindingType::DnsRecord(DnsRecordType::DNSKEY),
                    format!("DNSKEY record found for {}", domain),
                )
                .with_metadata("record_type".to_string(), "DNSKEY".to_string()),
            );
        }
    } else {
        findings.push(
            Finding::with_confidence(
                FindingType::SecurityConfig,
                format!("DNSSEC is not enabled for {}", domain),
                80,
            )
            .with_metadata("dnssec_status".to_string(), "disabled".to_string())
            .with_metadata(
                "recommendation".to_string(),
                "Consider enabling DNSSEC to protect against DNS spoofing attacks".to_string(),
            ),
        );
    }

    findings
}

/// Detect if domain has wildcard DNS configured
async fn detect_wildcard(resolver: &TokioAsyncResolver, domain: &str) -> (bool, Vec<Finding>) {
    let mut findings = Vec::new();

    // Generate random subdomain names that shouldn't exist
    let random_subdomain1 = format!("heroforge-wildcard-test-{}.{}", uuid::Uuid::new_v4().simple(), domain);
    let random_subdomain2 = format!("hf-random-test-{}.{}", uuid::Uuid::new_v4().simple(), domain);

    let mut wildcard_ips: Vec<IpAddr> = Vec::new();
    let mut is_wildcard = false;

    // Test first random subdomain
    if let Ok(response) = resolver.lookup_ip(&random_subdomain1).await {
        let ips: Vec<IpAddr> = response.iter().collect();
        if !ips.is_empty() {
            wildcard_ips = ips;
            is_wildcard = true;
        }
    }

    // Confirm with second test
    if is_wildcard {
        if let Ok(response) = resolver.lookup_ip(&random_subdomain2).await {
            let ips: Vec<IpAddr> = response.iter().collect();
            // If both random subdomains resolve to the same IPs, it's definitely wildcard
            if !ips.is_empty() && ips.iter().any(|ip| wildcard_ips.contains(ip)) {
                findings.push(
                    Finding::new(
                        FindingType::SecurityConfig,
                        format!(
                            "Wildcard DNS detected for *.{} (resolves to {})",
                            domain,
                            wildcard_ips.iter().map(|ip| ip.to_string()).collect::<Vec<_>>().join(", ")
                        ),
                    )
                    .with_metadata("wildcard".to_string(), "true".to_string())
                    .with_metadata(
                        "wildcard_ips".to_string(),
                        wildcard_ips.iter().map(|ip| ip.to_string()).collect::<Vec<_>>().join(", "),
                    )
                    .with_metadata(
                        "note".to_string(),
                        "Wildcard DNS can interfere with subdomain enumeration accuracy".to_string(),
                    ),
                );
            }
        }
    }

    (is_wildcard, findings)
}

/// Perform reverse DNS lookups for discovered IPs
async fn query_reverse_dns(resolver: &TokioAsyncResolver, ips: &HashSet<IpAddr>) -> Vec<Finding> {
    let mut findings = Vec::new();
    let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_QUERIES));
    let mut tasks = Vec::new();

    for ip in ips {
        let resolver = resolver.clone();
        let ip = *ip;
        let semaphore = semaphore.clone();

        let task = tokio::spawn(async move {
            let _permit = semaphore.acquire().await.ok()?;

            if let Ok(response) = resolver.reverse_lookup(ip).await {
                let hostnames: Vec<String> = response.iter().map(|name| name.to_string()).collect();
                if !hostnames.is_empty() {
                    return Some(
                        Finding::new(
                            FindingType::DnsRecord(DnsRecordType::PTR),
                            format!("PTR: {} -> {}", ip, hostnames.join(", ")),
                        )
                        .with_metadata("record_type".to_string(), "PTR".to_string())
                        .with_metadata("ip".to_string(), ip.to_string())
                        .with_metadata("hostnames".to_string(), hostnames.join(", ")),
                    );
                }
            }
            None
        });

        tasks.push(task);
    }

    for task in tasks {
        if let Ok(Some(finding)) = task.await {
            findings.push(finding);
        }
    }

    findings
}

/// Attempt DNS zone transfer (AXFR) with proper implementation
async fn attempt_zone_transfer_full(nameserver_ip: IpAddr, domain: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    // First, get the NS records for the domain to find authoritative nameservers
    let resolver = match create_resolver_with_nameserver(nameserver_ip) {
        Ok(r) => r,
        Err(e) => {
            warn!("Failed to create resolver for zone transfer: {}", e);
            return findings;
        }
    };

    let nameservers: Vec<String> = if let Ok(response) = resolver.ns_lookup(domain).await {
        response.iter().map(|ns| ns.to_string()).collect()
    } else {
        vec![nameserver_ip.to_string()]
    };

    // Try zone transfer against each nameserver using dig/host command
    // Note: trust-dns-resolver doesn't support AXFR, so we use command-line tools
    for ns in nameservers.iter().take(5) {  // Limit to first 5 nameservers
        info!("Attempting zone transfer for {} against {}", domain, ns);

        // Try using dig for zone transfer
        let output = tokio::process::Command::new("dig")
            .args([
                &format!("@{}", ns.trim_end_matches('.')),
                domain,
                "AXFR",
                "+noall",
                "+answer",
                "+tries=1",
                "+time=10",
            ])
            .output()
            .await;

        match output {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let stderr = String::from_utf8_lossy(&output.stderr);

                // Check if zone transfer was successful (returns DNS records)
                if !stdout.trim().is_empty() && !stdout.contains("Transfer failed") && !stdout.contains("connection refused") {
                    // Parse the zone transfer results
                    let record_count = stdout.lines().filter(|l| !l.trim().is_empty() && !l.starts_with(';')).count();

                    if record_count > 0 {
                        findings.push(
                            Finding::with_confidence(
                                FindingType::ZoneTransfer,
                                format!(
                                    "Zone transfer SUCCESSFUL for {} via {} ({} records)",
                                    domain, ns, record_count
                                ),
                                100,
                            )
                            .with_metadata("nameserver".to_string(), ns.to_string())
                            .with_metadata("status".to_string(), "successful".to_string())
                            .with_metadata("record_count".to_string(), record_count.to_string())
                            .with_metadata(
                                "severity".to_string(),
                                "high".to_string(),
                            )
                            .with_metadata(
                                "recommendation".to_string(),
                                "Restrict zone transfers to authorized secondary nameservers only".to_string(),
                            ),
                        );

                        // Extract some key records from the zone transfer
                        for line in stdout.lines().take(50) {  // Limit to first 50 records
                            if !line.trim().is_empty() && !line.starts_with(';') {
                                findings.push(
                                    Finding::with_confidence(
                                        FindingType::DnsRecord(DnsRecordType::A),
                                        format!("AXFR: {}", line.trim()),
                                        90,
                                    )
                                    .with_metadata("source".to_string(), "zone_transfer".to_string()),
                                );
                            }
                        }

                        debug!("Zone transfer successful for {} via {}", domain, ns);
                    }
                } else if stderr.contains("refused") || stderr.contains("denied") || stdout.contains("Transfer failed") {
                    findings.push(
                        Finding::with_confidence(
                            FindingType::ZoneTransfer,
                            format!("Zone transfer denied for {} via {}", domain, ns),
                            90,
                        )
                        .with_metadata("nameserver".to_string(), ns.to_string())
                        .with_metadata("status".to_string(), "denied".to_string()),
                    );
                    debug!("Zone transfer denied for {} via {}", domain, ns);
                }
            }
            Err(e) => {
                // dig command not available, try host command as fallback
                debug!("dig command failed ({}), trying host command", e);

                let host_output = tokio::process::Command::new("host")
                    .args(["-l", domain, ns.trim_end_matches('.')])
                    .output()
                    .await;

                if let Ok(output) = host_output {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    if !stdout.contains("failed") && !stdout.contains("refused") && stdout.lines().count() > 2 {
                        findings.push(
                            Finding::with_confidence(
                                FindingType::ZoneTransfer,
                                format!("Zone transfer SUCCESSFUL for {} via {}", domain, ns),
                                100,
                            )
                            .with_metadata("nameserver".to_string(), ns.to_string())
                            .with_metadata("status".to_string(), "successful".to_string())
                            .with_metadata("severity".to_string(), "high".to_string()),
                        );
                    }
                } else {
                    warn!(
                        "Zone transfer tools not available for {} against {}",
                        domain, ns
                    );
                    findings.push(
                        Finding::with_confidence(
                            FindingType::ZoneTransfer,
                            format!("Zone transfer could not be attempted for {} (tools unavailable)", domain),
                            30,
                        )
                        .with_metadata("nameserver".to_string(), ns.to_string())
                        .with_metadata("status".to_string(), "tools_unavailable".to_string()),
                    );
                }
            }
        }
    }

    if findings.is_empty() {
        findings.push(
            Finding::with_confidence(
                FindingType::ZoneTransfer,
                format!("Zone transfer not tested for {} (no nameservers found)", domain),
                30,
            )
            .with_metadata("status".to_string(), "not_tested".to_string()),
        );
    }

    findings
}

/// Legacy zone transfer function (kept for compatibility)
#[allow(dead_code)]
async fn attempt_zone_transfer(nameserver_ip: IpAddr, domain: &str) -> Option<Finding> {
    let findings = attempt_zone_transfer_full(nameserver_ip, domain).await;
    findings.into_iter().next()
}
