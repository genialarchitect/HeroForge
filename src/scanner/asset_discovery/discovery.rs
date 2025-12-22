use anyhow::Result;
use log::{debug, info, warn};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::RwLock;

use super::ct_logs::search_ct_logs;
use super::shodan::search_shodan;
use super::types::*;
use super::whois::lookup_whois;
use crate::scanner::dns_recon::{perform_dns_recon, DnsReconResult};

/// Run asset discovery for a domain
pub async fn run_asset_discovery(
    config: AssetDiscoveryConfig,
) -> Result<AssetDiscoveryResult> {
    let start_time = chrono::Utc::now();
    info!("Starting asset discovery for domain: {}", config.domain);

    let mut result = AssetDiscoveryResult {
        id: uuid::Uuid::new_v4().to_string(),
        domain: config.domain.clone(),
        config: config.clone(),
        status: AssetDiscoveryStatus::Running,
        assets: Vec::new(),
        whois: None,
        statistics: DiscoveryStatistics::default(),
        errors: Vec::new(),
        started_at: start_time,
        completed_at: None,
    };

    // Collect assets from various sources
    let assets: Arc<RwLock<HashMap<String, DiscoveredAsset>>> = Arc::new(RwLock::new(HashMap::new()));

    // Run discovery tasks concurrently
    let mut handles = Vec::new();

    // 1. Certificate Transparency logs
    if config.include_ct_logs {
        let domain = config.domain.clone();
        let timeout = config.timeout_secs;
        let assets_ref = assets.clone();

        handles.push(tokio::spawn(async move {
            match search_ct_logs(&domain, timeout).await {
                Ok(subdomains) => {
                    let count = subdomains.len();
                    let mut assets_guard = assets_ref.write().await;
                    for hostname in subdomains {
                        let asset = DiscoveredAsset::new(
                            hostname.clone(),
                            DiscoverySource::CertificateTransparency,
                        );
                        assets_guard.entry(hostname).or_insert(asset);
                    }
                    Ok(("ct_logs".to_string(), count))
                }
                Err(e) => Err(format!("CT logs search failed: {}", e)),
            }
        }));
    }

    // 2. DNS enumeration
    if config.include_dns {
        let domain = config.domain.clone();
        let timeout = config.timeout_secs;
        let wordlist = config.wordlist.clone();
        let active_enum = config.active_enum;
        let assets_ref = assets.clone();

        handles.push(tokio::spawn(async move {
            match perform_dns_recon(&domain, active_enum, wordlist, timeout).await {
                Ok(dns_result) => {
                    let count = process_dns_results(&domain, dns_result, assets_ref).await;
                    Ok(("dns".to_string(), count))
                }
                Err(e) => Err(format!("DNS enumeration failed: {}", e)),
            }
        }));
    }

    // 3. Shodan lookup
    if config.include_shodan {
        if let Some(api_key) = config.shodan_api_key.clone() {
            let domain = config.domain.clone();
            let timeout = config.timeout_secs;
            let assets_ref = assets.clone();

            handles.push(tokio::spawn(async move {
                match search_shodan(&domain, &api_key, timeout).await {
                    Ok(shodan_assets) => {
                        let count = shodan_assets.len();
                        let mut assets_guard = assets_ref.write().await;
                        for asset in shodan_assets {
                            let hostname = asset.hostname.clone();
                            assets_guard
                                .entry(hostname)
                                .and_modify(|existing| existing.merge(&asset))
                                .or_insert(asset);
                        }
                        Ok(("shodan".to_string(), count))
                    }
                    Err(e) => Err(format!("Shodan search failed: {}", e)),
                }
            }));
        } else {
            result.errors.push("Shodan enabled but no API key provided".to_string());
        }
    }

    // 4. WHOIS lookup
    if config.include_whois {
        let domain = config.domain.clone();
        let timeout = config.timeout_secs;

        let whois_handle = tokio::spawn(async move {
            lookup_whois(&domain, timeout).await
        });

        match whois_handle.await {
            Ok(Ok(whois_info)) => {
                result.whois = Some(whois_info);
            }
            Ok(Err(e)) => {
                result.errors.push(format!("WHOIS lookup failed: {}", e));
            }
            Err(e) => {
                result.errors.push(format!("WHOIS task failed: {}", e));
            }
        }
    }

    // Wait for all discovery tasks to complete
    for handle in handles {
        match handle.await {
            Ok(Ok((source, count))) => {
                debug!("Discovery source {} found {} items", source, count);
                match source.as_str() {
                    "ct_logs" => result.statistics.subdomains_from_ct = count,
                    "dns" => result.statistics.subdomains_from_dns = count,
                    "shodan" => result.statistics.subdomains_from_shodan = count,
                    "censys" => result.statistics.subdomains_from_censys = count,
                    _ => {}
                }
            }
            Ok(Err(err_msg)) => {
                warn!("{}", err_msg);
                result.errors.push(err_msg);
            }
            Err(e) => {
                result.errors.push(format!("Discovery task panicked: {}", e));
            }
        }
    }

    // Collect final assets
    let assets_guard = assets.read().await;
    result.assets = assets_guard.values().cloned().collect();

    // Resolve IPs for assets without them
    resolve_asset_ips(&mut result.assets).await;

    // Calculate statistics
    result.statistics.total_assets = result.assets.len();
    result.statistics.unique_hostnames = result.assets.len();
    result.statistics.unique_ips = result
        .assets
        .iter()
        .flat_map(|a| &a.ip_addresses)
        .collect::<std::collections::HashSet<_>>()
        .len();
    result.statistics.open_ports_found = result
        .assets
        .iter()
        .map(|a| a.ports.len())
        .sum();
    result.statistics.technologies_identified = result
        .assets
        .iter()
        .map(|a| a.technologies.len())
        .sum();
    result.statistics.certificates_found = result
        .assets
        .iter()
        .map(|a| a.certificates.len())
        .sum();

    result.status = AssetDiscoveryStatus::Completed;
    result.completed_at = Some(chrono::Utc::now());

    info!(
        "Asset discovery completed: {} assets, {} unique IPs, {} errors",
        result.statistics.total_assets,
        result.statistics.unique_ips,
        result.errors.len()
    );

    Ok(result)
}

/// Process DNS reconnaissance results into assets
async fn process_dns_results(
    domain: &str,
    dns_result: DnsReconResult,
    assets: Arc<RwLock<HashMap<String, DiscoveredAsset>>>,
) -> usize {
    let mut count = 0;
    let mut assets_guard = assets.write().await;

    // Add the main domain
    let mut main_asset = DiscoveredAsset::new(domain.to_string(), DiscoverySource::DnsEnumeration);

    // Process A/AAAA records for IP addresses
    if let Some(a_records) = dns_result.records.get("A") {
        for record in a_records {
            if let Ok(ip) = record.value.parse::<IpAddr>() {
                if !main_asset.ip_addresses.contains(&ip) {
                    main_asset.ip_addresses.push(ip);
                }
            }
        }
    }

    if let Some(aaaa_records) = dns_result.records.get("AAAA") {
        for record in aaaa_records {
            if let Ok(ip) = record.value.parse::<IpAddr>() {
                if !main_asset.ip_addresses.contains(&ip) {
                    main_asset.ip_addresses.push(ip);
                }
            }
        }
    }

    // Add DNS records to asset
    for (rtype, records) in &dns_result.records {
        main_asset.dns_records.insert(
            rtype.clone(),
            records.iter().map(|r| r.value.clone()).collect(),
        );
    }

    assets_guard.insert(domain.to_string(), main_asset);
    count += 1;

    // Add discovered subdomains
    for subdomain in &dns_result.subdomains_found {
        let asset = DiscoveredAsset::new(subdomain.clone(), DiscoverySource::DnsEnumeration);
        assets_guard.entry(subdomain.clone()).or_insert(asset);
        count += 1;
    }

    count
}

/// Resolve IP addresses for assets that don't have them
async fn resolve_asset_ips(assets: &mut Vec<DiscoveredAsset>) {
    use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
    use trust_dns_resolver::TokioAsyncResolver;

    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());

    for asset in assets.iter_mut() {
        if asset.ip_addresses.is_empty() {
            // Try to resolve A record
            match resolver.lookup_ip(&asset.hostname).await {
                Ok(response) => {
                    for ip in response.iter() {
                        if !asset.ip_addresses.contains(&ip) {
                            asset.ip_addresses.push(ip);
                        }
                    }
                }
                Err(_) => {
                    // Host may not resolve, that's okay
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_asset_discovery_config_default() {
        let config = AssetDiscoveryConfig::default();
        assert!(config.include_ct_logs);
        assert!(config.include_dns);
        assert!(!config.include_shodan);
        assert!(config.include_whois);
    }
}
