use anyhow::{anyhow, Result};
use log::{debug, info, warn};
use reqwest::Client;
use serde::Deserialize;
use std::net::IpAddr;
use std::time::Duration;

use super::types::{DiscoveredAsset, DiscoveredPort, DiscoverySource, TechnologyFingerprint};

const SHODAN_API_BASE: &str = "https://api.shodan.io";

/// Shodan API response for domain search
#[derive(Debug, Deserialize)]
struct ShodanDomainResponse {
    #[serde(default)]
    domain: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    subdomains: Vec<String>,
    #[serde(default)]
    data: Vec<ShodanDnsRecord>,
}

#[derive(Debug, Deserialize)]
struct ShodanDnsRecord {
    #[serde(default)]
    subdomain: Option<String>,
    #[serde(rename = "type", default)]
    record_type: Option<String>,
    #[serde(default)]
    value: Option<String>,
    #[serde(default)]
    ports: Vec<u16>,
}

/// Shodan API response for host lookup
#[derive(Debug, Deserialize)]
struct ShodanHostResponse {
    #[serde(default)]
    ip_str: Option<String>,
    #[serde(default)]
    hostnames: Vec<String>,
    #[serde(default)]
    ports: Vec<u16>,
    #[serde(default)]
    org: Option<String>,
    #[serde(default)]
    asn: Option<String>,
    #[serde(default)]
    isp: Option<String>,
    #[serde(default)]
    country_code: Option<String>,
    #[serde(default)]
    country_name: Option<String>,
    #[serde(default)]
    city: Option<String>,
    #[serde(default)]
    data: Vec<ShodanServiceData>,
}

#[derive(Debug, Deserialize)]
struct ShodanServiceData {
    #[serde(default)]
    port: u16,
    #[serde(default)]
    transport: Option<String>,
    #[serde(default)]
    product: Option<String>,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    cpe: Vec<String>,
    #[serde(default)]
    banner: Option<String>,
    #[serde(default)]
    ssl: Option<ShodanSslInfo>,
    #[serde(default)]
    http: Option<ShodanHttpInfo>,
}

#[derive(Debug, Deserialize)]
struct ShodanSslInfo {
    #[serde(default)]
    cert: Option<ShodanCertInfo>,
}

#[derive(Debug, Deserialize)]
struct ShodanCertInfo {
    #[serde(default)]
    subject: Option<ShodanSubject>,
    #[serde(default)]
    issuer: Option<ShodanSubject>,
    #[serde(default)]
    fingerprint: Option<ShodanFingerprint>,
    #[serde(default)]
    expires: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ShodanSubject {
    #[serde(rename = "CN", default)]
    cn: Option<String>,
    #[serde(rename = "O", default)]
    o: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ShodanFingerprint {
    #[serde(default)]
    sha256: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ShodanHttpInfo {
    #[serde(default)]
    server: Option<String>,
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    components: Option<serde_json::Value>,
}

/// Search Shodan for subdomains and assets
pub async fn search_shodan(
    domain: &str,
    api_key: &str,
    timeout_secs: u64,
) -> Result<Vec<DiscoveredAsset>> {
    info!("Searching Shodan for domain: {}", domain);

    let client = Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .build()?;

    let mut assets: Vec<DiscoveredAsset> = Vec::new();

    // Search for domain DNS records
    let url = format!(
        "{}/dns/domain/{}?key={}",
        SHODAN_API_BASE, domain, api_key
    );

    debug!("Querying Shodan domain API");

    match client.get(&url).send().await {
        Ok(response) => {
            if response.status().is_success() {
                let domain_data: ShodanDomainResponse = response.json().await?;

                // Process subdomains
                for subdomain in &domain_data.subdomains {
                    let hostname = if subdomain.is_empty() {
                        domain.to_string()
                    } else {
                        format!("{}.{}", subdomain, domain)
                    };

                    let mut asset = DiscoveredAsset::new(
                        hostname.clone(),
                        DiscoverySource::Shodan,
                    );

                    // Add any open ports from DNS records
                    for record in &domain_data.data {
                        if record.subdomain.as_deref() == Some(subdomain.as_str()) {
                            for &port in &record.ports {
                                asset.ports.push(DiscoveredPort {
                                    port,
                                    protocol: "tcp".to_string(),
                                    service: None,
                                    version: None,
                                    banner: None,
                                });
                            }
                        }
                    }

                    assets.push(asset);
                }

                info!(
                    "Shodan found {} subdomains for {}",
                    domain_data.subdomains.len(),
                    domain
                );
            } else {
                let status = response.status();
                if status.as_u16() == 401 {
                    warn!("Shodan API: Invalid API key");
                    return Err(anyhow!("Invalid Shodan API key"));
                } else if status.as_u16() == 429 {
                    warn!("Shodan API: Rate limit exceeded");
                    return Err(anyhow!("Shodan API rate limit exceeded"));
                } else {
                    warn!("Shodan API error: {}", status);
                }
            }
        }
        Err(e) => {
            warn!("Failed to query Shodan domain API: {}", e);
        }
    }

    Ok(assets)
}

/// Look up detailed information for an IP address
pub async fn lookup_shodan_host(
    ip: &str,
    api_key: &str,
    timeout_secs: u64,
) -> Result<DiscoveredAsset> {
    info!("Looking up Shodan host info for: {}", ip);

    let client = Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .build()?;

    let url = format!("{}/shodan/host/{}?key={}", SHODAN_API_BASE, ip, api_key);

    let response = client.get(&url).send().await?;

    if !response.status().is_success() {
        return Err(anyhow!("Shodan host lookup failed: {}", response.status()));
    }

    let host_data: ShodanHostResponse = response.json().await?;

    let hostname = host_data
        .hostnames
        .first()
        .cloned()
        .unwrap_or_else(|| ip.to_string());

    let mut asset = DiscoveredAsset::new(hostname, DiscoverySource::Shodan);

    // Parse IP
    if let Ok(ip_addr) = ip.parse::<IpAddr>() {
        asset.ip_addresses.push(ip_addr);
    }

    // Add ASN info
    asset.asn = host_data.asn;
    asset.asn_org = host_data.org.or(host_data.isp);
    asset.country = host_data.country_name.or(host_data.country_code);
    asset.city = host_data.city;

    // Process services
    for service in host_data.data {
        asset.ports.push(DiscoveredPort {
            port: service.port,
            protocol: service.transport.unwrap_or_else(|| "tcp".to_string()),
            service: service.product.clone(),
            version: service.version.clone(),
            banner: service.banner.map(|b| b.chars().take(500).collect()),
        });

        // Extract technologies from CPE and HTTP info
        for cpe in service.cpe {
            if let Some(tech) = parse_cpe(&cpe) {
                if !asset.technologies.iter().any(|t| t.name == tech.name) {
                    asset.technologies.push(tech);
                }
            }
        }

        // Extract HTTP server info
        if let Some(http) = service.http {
            if let Some(server) = http.server {
                asset.technologies.push(TechnologyFingerprint {
                    name: server,
                    version: None,
                    category: "Web Server".to_string(),
                    confidence: 0.9,
                });
            }
        }
    }

    Ok(asset)
}

/// Parse CPE string into technology fingerprint
fn parse_cpe(cpe: &str) -> Option<TechnologyFingerprint> {
    // CPE format: cpe:/a:vendor:product:version or cpe:2.3:a:vendor:product:version:...
    let parts: Vec<&str> = if cpe.starts_with("cpe:2.3:") {
        cpe.trim_start_matches("cpe:2.3:").split(':').collect()
    } else {
        cpe.trim_start_matches("cpe:/").split(':').collect()
    };

    if parts.len() >= 3 {
        let category = match parts.first().copied() {
            Some("a") => "Application",
            Some("o") => "Operating System",
            Some("h") => "Hardware",
            _ => "Unknown",
        };

        let product = parts.get(2).copied().unwrap_or("Unknown");
        let version = parts.get(3).and_then(|v| {
            if *v != "*" && !v.is_empty() {
                Some(v.to_string())
            } else {
                None
            }
        });

        Some(TechnologyFingerprint {
            name: product.to_string(),
            version,
            category: category.to_string(),
            confidence: 0.85,
        })
    } else {
        None
    }
}

/// Check if Shodan API key is valid
pub async fn validate_api_key(api_key: &str) -> Result<bool> {
    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;

    let url = format!("{}/api-info?key={}", SHODAN_API_BASE, api_key);

    let response = client.get(&url).send().await?;
    Ok(response.status().is_success())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cpe() {
        let tech = parse_cpe("cpe:/a:apache:http_server:2.4.41").unwrap();
        assert_eq!(tech.name, "http_server");
        assert_eq!(tech.version, Some("2.4.41".to_string()));
        assert_eq!(tech.category, "Application");

        let tech2 = parse_cpe("cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*").unwrap();
        assert_eq!(tech2.name, "nginx");
        assert_eq!(tech2.version, Some("1.18.0".to_string()));
    }
}
