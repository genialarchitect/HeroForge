use super::types::{DnsRecordType, EnumDepth, EnumerationResult, Finding, FindingType, ServiceType};
use super::wordlists::WordlistManager;
use crate::types::{ScanProgressMessage, ScanTarget};
use anyhow::Result;
use log::{debug, info, warn};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{broadcast::Sender, Semaphore};
use trust_dns_resolver::config::*;
use trust_dns_resolver::TokioAsyncResolver;

const MAX_CONCURRENT_QUERIES: usize = 100;

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

    // Use the target IP as the nameserver if it's a DNS server
    let resolver = create_resolver_with_nameserver(target.ip)?;

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
        findings.extend(query_basic_records(&resolver, &domain).await);

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
    findings.extend(query_basic_records(&resolver, &domain).await);
    findings.extend(query_extended_records(&resolver, &domain).await);

    // Step 2: Subdomain enumeration (light or aggressive)
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

        findings.extend(subdomain_findings);
    }

    // Step 3: Zone transfer attempt (aggressive only)
    if matches!(depth, EnumDepth::Aggressive) {
        info!("Attempting zone transfer for {}", domain);
        if let Some(finding) = attempt_zone_transfer(target.ip, &domain).await {
            findings.push(finding);
        }
    }

    metadata.insert("records_found".to_string(), findings.len().to_string());

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

/// Attempt DNS zone transfer (AXFR)
async fn attempt_zone_transfer(nameserver_ip: IpAddr, domain: &str) -> Option<Finding> {
    // Note: Zone transfer requires TCP connection and special AXFR query
    // trust-dns-resolver doesn't directly support AXFR, would need trust-dns-client
    // For now, we'll just log the attempt
    warn!(
        "Zone transfer attempt for {} against {} (not yet fully implemented)",
        domain, nameserver_ip
    );

    // Return a finding indicating the attempt
    Some(
        Finding::with_confidence(
            FindingType::ZoneTransfer,
            format!("Zone transfer attempted for {}", domain),
            50,
        )
        .with_metadata("nameserver".to_string(), nameserver_ip.to_string())
        .with_metadata("status".to_string(), "not_implemented".to_string()),
    )
}
