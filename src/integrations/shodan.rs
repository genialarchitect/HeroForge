//! Shodan API integration for HeroForge
//!
//! This module provides a comprehensive Shodan API client for network reconnaissance,
//! including host lookups, searches, and DNS operations.

#![allow(dead_code)]

use anyhow::{anyhow, Result};
use log::{debug, info, warn};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

const SHODAN_API_BASE: &str = "https://api.shodan.io";
const REQUEST_TIMEOUT_SECS: u64 = 30;

/// Shodan API client for network reconnaissance
pub struct ShodanClient {
    client: Client,
    api_key: String,
}

/// Shodan host information from /shodan/host/{ip}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShodanHost {
    /// IP address
    pub ip: String,
    /// Hostnames associated with the IP
    pub hostnames: Vec<String>,
    /// Open ports
    pub ports: Vec<u16>,
    /// CVE vulnerabilities associated with the host
    pub vulns: Vec<String>,
    /// Organization that owns the IP
    pub org: Option<String>,
    /// Internet Service Provider
    pub isp: Option<String>,
    /// Autonomous System Number
    pub asn: Option<String>,
    /// Country name
    pub country: Option<String>,
    /// City name
    pub city: Option<String>,
    /// Latitude
    pub latitude: Option<f64>,
    /// Longitude
    pub longitude: Option<f64>,
    /// Operating system (if detected)
    pub os: Option<String>,
    /// Tags assigned by Shodan (e.g., "cloud", "honeypot")
    pub tags: Vec<String>,
    /// Service data per port
    pub data: Vec<ShodanService>,
    /// Last update timestamp
    pub last_update: Option<String>,
}

/// Shodan service information for a specific port
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShodanService {
    /// Port number
    pub port: u16,
    /// Transport protocol (tcp/udp)
    pub transport: String,
    /// Detected product name
    pub product: Option<String>,
    /// Detected version
    pub version: Option<String>,
    /// Service banner data
    pub banner: Option<String>,
    /// Common Platform Enumeration identifiers
    pub cpe: Vec<String>,
    /// Vulnerabilities specific to this service
    pub vulns: Vec<String>,
    /// HTTP-specific data (if applicable)
    pub http: Option<ShodanHttpData>,
    /// SSL/TLS certificate data (if applicable)
    pub ssl: Option<ShodanSslData>,
}

/// HTTP-specific data from Shodan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShodanHttpData {
    /// HTTP server header
    pub server: Option<String>,
    /// Page title
    pub title: Option<String>,
    /// HTTP status code
    pub status: Option<i32>,
    /// HTML content (truncated)
    pub html: Option<String>,
    /// Robots.txt content
    pub robots: Option<String>,
    /// Favicon hash
    pub favicon_hash: Option<String>,
}

/// SSL/TLS certificate data from Shodan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShodanSslData {
    /// Certificate chain
    pub chain: Vec<String>,
    /// Certificate common name
    pub cn: Option<String>,
    /// Subject Alternative Names
    pub san: Vec<String>,
    /// Certificate issuer
    pub issuer: Option<String>,
    /// Certificate expiration date
    pub expires: Option<String>,
    /// TLS version
    pub version: Option<String>,
}

/// Shodan search result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShodanSearchResult {
    /// Search matches
    pub matches: Vec<ShodanSearchMatch>,
    /// Total number of results
    pub total: i64,
    /// Facet aggregations (if requested)
    pub facets: Option<HashMap<String, Vec<ShodanFacet>>>,
}

/// Individual search match from Shodan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShodanSearchMatch {
    /// IP address
    pub ip_str: String,
    /// Port number
    pub port: u16,
    /// Organization
    pub org: Option<String>,
    /// ISP
    pub isp: Option<String>,
    /// ASN
    pub asn: Option<String>,
    /// Country code
    pub country_code: Option<String>,
    /// Product name
    pub product: Option<String>,
    /// Version
    pub version: Option<String>,
    /// Banner data
    pub data: Option<String>,
    /// Detected OS
    pub os: Option<String>,
    /// Transport protocol
    pub transport: Option<String>,
    /// Hostnames
    pub hostnames: Vec<String>,
    /// Domains
    pub domains: Vec<String>,
}

/// Facet aggregation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShodanFacet {
    /// Value of the facet
    pub value: serde_json::Value,
    /// Count of matches
    pub count: i64,
}

/// Shodan API info response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShodanApiInfo {
    /// Query credits remaining
    pub query_credits: i32,
    /// Scan credits remaining
    pub scan_credits: i32,
    /// Account plan type
    pub plan: String,
    /// Whether HTTPS is available
    pub https: Option<bool>,
    /// Unlocked features
    pub unlocked: Option<bool>,
    /// Telnet access available
    pub telnet: Option<bool>,
}

// Internal API response types for deserialization

#[derive(Debug, Deserialize)]
struct ShodanHostResponse {
    ip_str: String,
    hostnames: Option<Vec<String>>,
    country_name: Option<String>,
    city: Option<String>,
    org: Option<String>,
    isp: Option<String>,
    asn: Option<String>,
    ports: Option<Vec<u16>>,
    vulns: Option<Vec<String>>,
    tags: Option<Vec<String>>,
    os: Option<String>,
    latitude: Option<f64>,
    longitude: Option<f64>,
    data: Option<Vec<ShodanServiceData>>,
    last_update: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ShodanServiceData {
    port: u16,
    transport: Option<String>,
    product: Option<String>,
    version: Option<String>,
    #[serde(rename = "data")]
    banner: Option<String>,
    cpe: Option<Vec<String>>,
    vulns: Option<HashMap<String, serde_json::Value>>,
    http: Option<ShodanHttpResponse>,
    ssl: Option<ShodanSslResponse>,
}

#[derive(Debug, Deserialize)]
struct ShodanHttpResponse {
    server: Option<String>,
    title: Option<String>,
    status: Option<i32>,
    html: Option<String>,
    robots: Option<String>,
    #[serde(rename = "favicon")]
    favicon_data: Option<ShodanFaviconData>,
}

#[derive(Debug, Deserialize)]
struct ShodanFaviconData {
    hash: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct ShodanSslResponse {
    chain: Option<Vec<String>>,
    cert: Option<ShodanCertData>,
    versions: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct ShodanCertData {
    subject: Option<ShodanSubject>,
    issuer: Option<ShodanSubject>,
    expires: Option<String>,
    #[serde(rename = "extensions")]
    extensions: Option<Vec<ShodanCertExtension>>,
}

#[derive(Debug, Deserialize)]
struct ShodanSubject {
    #[serde(rename = "CN")]
    cn: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ShodanCertExtension {
    #[serde(rename = "subjectAltName")]
    subject_alt_name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ShodanSearchResponse {
    matches: Vec<ShodanSearchMatchResponse>,
    total: i64,
    facets: Option<HashMap<String, Vec<ShodanFacetResponse>>>,
}

#[derive(Debug, Deserialize)]
struct ShodanSearchMatchResponse {
    ip_str: String,
    port: u16,
    org: Option<String>,
    isp: Option<String>,
    asn: Option<String>,
    #[serde(rename = "location")]
    location: Option<ShodanLocation>,
    product: Option<String>,
    version: Option<String>,
    data: Option<String>,
    os: Option<String>,
    transport: Option<String>,
    hostnames: Option<Vec<String>>,
    domains: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct ShodanLocation {
    country_code: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ShodanFacetResponse {
    value: serde_json::Value,
    count: i64,
}

#[derive(Debug, Deserialize)]
struct DnsResolveResponse {
    #[serde(flatten)]
    results: HashMap<String, Option<String>>,
}

#[derive(Debug, Deserialize)]
struct DnsReverseResponse {
    #[serde(flatten)]
    results: HashMap<String, Option<Vec<String>>>,
}

impl ShodanClient {
    /// Create a new Shodan client with the provided API key
    pub fn new(api_key: String) -> Result<Self> {
        if api_key.is_empty() {
            return Err(anyhow!("Shodan API key is required"));
        }

        let client = Client::builder()
            .timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS))
            .user_agent("HeroForge/0.2.0 (Security Scanner)")
            .build()?;

        Ok(Self { client, api_key })
    }

    /// Create a Shodan client from the SHODAN_API_KEY environment variable
    pub fn from_env() -> Result<Self> {
        let api_key = std::env::var("SHODAN_API_KEY")
            .map_err(|_| anyhow!("SHODAN_API_KEY environment variable not set"))?;
        Self::new(api_key)
    }

    /// Get API info (quota, plan, etc.)
    pub async fn get_api_info(&self) -> Result<ShodanApiInfo> {
        let url = format!("{}/api-info?key={}", SHODAN_API_BASE, self.api_key);

        debug!("Fetching Shodan API info");

        let response = self.client.get(&url).send().await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow!("Shodan API error: {} - {}", status, body));
        }

        let info: ShodanApiInfo = response.json().await?;
        Ok(info)
    }

    /// Look up host information by IP address
    ///
    /// Endpoint: /shodan/host/{ip}
    pub async fn host_lookup(&self, ip: &str) -> Result<ShodanHost> {
        // Validate IP format
        if ip.parse::<std::net::IpAddr>().is_err() {
            return Err(anyhow!("Invalid IP address format: {}", ip));
        }

        let url = format!(
            "{}/shodan/host/{}?key={}",
            SHODAN_API_BASE, ip, self.api_key
        );

        info!("Looking up host {} on Shodan", ip);
        debug!("Shodan URL: {}", url.replace(&self.api_key, "***"));

        let response = self.client.get(&url).send().await?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(anyhow!("Host {} not found in Shodan database", ip));
        }

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            warn!("Shodan API error for {}: {} - {}", ip, status, body);
            return Err(anyhow!("Shodan API error: {} - {}", status, body));
        }

        let host_data: ShodanHostResponse = response.json().await?;
        Ok(convert_host_response(host_data))
    }

    /// Search Shodan for hosts matching a query
    ///
    /// Endpoint: /shodan/host/search
    ///
    /// Example queries:
    /// - `apache`: Find all Apache servers
    /// - `port:22`: Find SSH servers
    /// - `product:nginx version:1.19`: Find specific nginx versions
    /// - `country:US city:"San Francisco"`: Geolocation filter
    /// - `org:"Google"`: Filter by organization
    /// - `vuln:CVE-2021-44228`: Search for vulnerable hosts
    pub async fn search(&self, query: &str, page: u32) -> Result<ShodanSearchResult> {
        let url = format!(
            "{}/shodan/host/search?key={}&query={}&page={}",
            SHODAN_API_BASE,
            self.api_key,
            urlencoding::encode(query),
            page
        );

        info!("Searching Shodan: {} (page {})", query, page);

        let response = self.client.get(&url).send().await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow!("Shodan search error: {} - {}", status, body));
        }

        let search_response: ShodanSearchResponse = response.json().await?;

        info!(
            "Shodan search returned {} total results",
            search_response.total
        );

        Ok(convert_search_response(search_response))
    }

    /// Resolve hostnames to IP addresses
    ///
    /// Endpoint: /dns/resolve
    pub async fn dns_resolve(&self, hostnames: &[&str]) -> Result<HashMap<String, Vec<String>>> {
        if hostnames.is_empty() {
            return Ok(HashMap::new());
        }

        let hostnames_str = hostnames.join(",");
        let url = format!(
            "{}/dns/resolve?hostnames={}&key={}",
            SHODAN_API_BASE,
            urlencoding::encode(&hostnames_str),
            self.api_key
        );

        info!("Resolving {} hostnames via Shodan DNS", hostnames.len());

        let response = self.client.get(&url).send().await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow!("Shodan DNS resolve error: {} - {}", status, body));
        }

        // Shodan returns: { "hostname": "ip" or null }
        let raw_result: HashMap<String, Option<String>> = response.json().await?;

        let result: HashMap<String, Vec<String>> = raw_result
            .into_iter()
            .filter_map(|(hostname, maybe_ip)| {
                maybe_ip.map(|ip| (hostname, vec![ip]))
            })
            .collect();

        Ok(result)
    }

    /// Reverse DNS lookup - resolve IP addresses to hostnames
    ///
    /// Endpoint: /dns/reverse
    pub async fn dns_reverse(&self, ips: &[&str]) -> Result<HashMap<String, Vec<String>>> {
        if ips.is_empty() {
            return Ok(HashMap::new());
        }

        // Validate IPs
        for ip in ips {
            if ip.parse::<std::net::IpAddr>().is_err() {
                return Err(anyhow!("Invalid IP address: {}", ip));
            }
        }

        let ips_str = ips.join(",");
        let url = format!(
            "{}/dns/reverse?ips={}&key={}",
            SHODAN_API_BASE,
            urlencoding::encode(&ips_str),
            self.api_key
        );

        info!("Reverse DNS lookup for {} IPs via Shodan", ips.len());

        let response = self.client.get(&url).send().await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow!("Shodan DNS reverse error: {} - {}", status, body));
        }

        // Shodan returns: { "ip": ["hostname1", "hostname2"] or null }
        let raw_result: HashMap<String, Option<Vec<String>>> = response.json().await?;

        let result: HashMap<String, Vec<String>> = raw_result
            .into_iter()
            .filter_map(|(ip, maybe_hostnames)| {
                maybe_hostnames.map(|hostnames| (ip, hostnames))
            })
            .collect();

        Ok(result)
    }

    /// Search for hosts with a specific CVE vulnerability
    pub async fn search_by_cve(&self, cve_id: &str, page: u32) -> Result<ShodanSearchResult> {
        let query = format!("vuln:{}", cve_id);
        self.search(&query, page).await
    }

    /// Search for hosts with a specific product/service
    pub async fn search_by_product(
        &self,
        product: &str,
        version: Option<&str>,
        page: u32,
    ) -> Result<ShodanSearchResult> {
        let query = if let Some(ver) = version {
            format!("product:{} version:{}", product, ver)
        } else {
            format!("product:{}", product)
        };
        self.search(&query, page).await
    }

    /// Search for hosts in a specific country
    pub async fn search_by_country(&self, country_code: &str, page: u32) -> Result<ShodanSearchResult> {
        let query = format!("country:{}", country_code);
        self.search(&query, page).await
    }

    /// Search for hosts by port
    pub async fn search_by_port(&self, port: u16, page: u32) -> Result<ShodanSearchResult> {
        let query = format!("port:{}", port);
        self.search(&query, page).await
    }

    /// Search for hosts by organization
    pub async fn search_by_org(&self, org: &str, page: u32) -> Result<ShodanSearchResult> {
        let query = format!("org:\"{}\"", org);
        self.search(&query, page).await
    }

    /// Get the number of results for a search query without consuming query credits
    pub async fn search_count(&self, query: &str) -> Result<i64> {
        let url = format!(
            "{}/shodan/host/count?key={}&query={}",
            SHODAN_API_BASE,
            self.api_key,
            urlencoding::encode(query)
        );

        let response = self.client.get(&url).send().await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow!("Shodan count error: {} - {}", status, body));
        }

        #[derive(Deserialize)]
        struct CountResponse {
            total: i64,
        }

        let count: CountResponse = response.json().await?;
        Ok(count.total)
    }
}

/// Convert Shodan API host response to our ShodanHost type
fn convert_host_response(resp: ShodanHostResponse) -> ShodanHost {
    let services: Vec<ShodanService> = resp
        .data
        .unwrap_or_default()
        .into_iter()
        .map(|svc| {
            let vulns: Vec<String> = svc
                .vulns
                .map(|v| v.keys().cloned().collect())
                .unwrap_or_default();

            let http = svc.http.map(|h| ShodanHttpData {
                server: h.server,
                title: h.title,
                status: h.status,
                html: h.html.map(|html| truncate_string(&html, 1000)),
                robots: h.robots,
                favicon_hash: h.favicon_data.and_then(|f| f.hash.map(|h| h.to_string())),
            });

            let ssl = svc.ssl.map(|s| {
                let cn = s.cert.as_ref().and_then(|c| {
                    c.subject.as_ref().and_then(|subj| subj.cn.clone())
                });
                let issuer = s.cert.as_ref().and_then(|c| {
                    c.issuer.as_ref().and_then(|iss| iss.cn.clone())
                });
                let expires = s.cert.as_ref().and_then(|c| c.expires.clone());
                let san = s
                    .cert
                    .as_ref()
                    .and_then(|c| c.extensions.as_ref())
                    .map(|exts| {
                        exts.iter()
                            .filter_map(|e| e.subject_alt_name.clone())
                            .flat_map(|san| {
                                san.split(',')
                                    .map(|s| s.trim().replace("DNS:", ""))
                                    .collect::<Vec<_>>()
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                let version = s.versions.and_then(|v| v.into_iter().last());

                ShodanSslData {
                    chain: s.chain.unwrap_or_default(),
                    cn,
                    san,
                    issuer,
                    expires,
                    version,
                }
            });

            ShodanService {
                port: svc.port,
                transport: svc.transport.unwrap_or_else(|| "tcp".to_string()),
                product: svc.product,
                version: svc.version,
                banner: svc.banner.map(|b| truncate_string(&b, 500)),
                cpe: svc.cpe.unwrap_or_default(),
                vulns,
                http,
                ssl,
            }
        })
        .collect();

    ShodanHost {
        ip: resp.ip_str,
        hostnames: resp.hostnames.unwrap_or_default(),
        country: resp.country_name,
        city: resp.city,
        org: resp.org,
        isp: resp.isp,
        asn: resp.asn,
        ports: resp.ports.unwrap_or_default(),
        vulns: resp.vulns.unwrap_or_default(),
        tags: resp.tags.unwrap_or_default(),
        os: resp.os,
        latitude: resp.latitude,
        longitude: resp.longitude,
        data: services,
        last_update: resp.last_update,
    }
}

/// Convert Shodan API search response to our ShodanSearchResult type
fn convert_search_response(resp: ShodanSearchResponse) -> ShodanSearchResult {
    let matches: Vec<ShodanSearchMatch> = resp
        .matches
        .into_iter()
        .map(|m| ShodanSearchMatch {
            ip_str: m.ip_str,
            port: m.port,
            org: m.org,
            isp: m.isp,
            asn: m.asn,
            country_code: m.location.and_then(|l| l.country_code),
            product: m.product,
            version: m.version,
            data: m.data.map(|d| truncate_string(&d, 500)),
            os: m.os,
            transport: m.transport,
            hostnames: m.hostnames.unwrap_or_default(),
            domains: m.domains.unwrap_or_default(),
        })
        .collect();

    let facets = resp.facets.map(|f| {
        f.into_iter()
            .map(|(k, v)| {
                let facets: Vec<ShodanFacet> = v
                    .into_iter()
                    .map(|f| ShodanFacet {
                        value: f.value,
                        count: f.count,
                    })
                    .collect();
                (k, facets)
            })
            .collect()
    });

    ShodanSearchResult {
        matches,
        total: resp.total,
        facets,
    }
}

/// Truncate a string to a maximum length
fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shodan_client_requires_key() {
        let result = ShodanClient::new(String::new());
        assert!(result.is_err());
    }

    #[test]
    fn test_shodan_client_with_key() {
        let result = ShodanClient::new("test-key".to_string());
        assert!(result.is_ok());
    }

    #[test]
    fn test_truncate_string() {
        assert_eq!(truncate_string("short", 100), "short");
        assert_eq!(
            truncate_string(&"a".repeat(100), 10),
            "aaaaaaaaaa..."
        );
    }

    #[tokio::test]
    async fn test_shodan_host_lookup_invalid_ip() {
        let client = ShodanClient::new("test-key".to_string()).unwrap();
        let result = client.host_lookup("not-an-ip").await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid IP"));
    }

    #[tokio::test]
    async fn test_shodan_dns_reverse_invalid_ip() {
        let client = ShodanClient::new("test-key".to_string()).unwrap();
        let result = client.dns_reverse(&["not-an-ip"]).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid IP"));
    }

    #[tokio::test]
    async fn test_shodan_dns_resolve_empty() {
        let client = ShodanClient::new("test-key".to_string()).unwrap();
        let result = client.dns_resolve(&[]).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_shodan_dns_reverse_empty() {
        let client = ShodanClient::new("test-key".to_string()).unwrap();
        let result = client.dns_reverse(&[]).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }
}
