#![allow(dead_code)]

pub mod cache;
pub mod nvd_client;
pub mod offline_db;

use crate::types::{ServiceInfo, Severity, Vulnerability};
use anyhow::Result;
use log::{debug, info, warn};
use sqlx::SqlitePool;

/// Configuration for CVE scanning
#[derive(Debug, Clone)]
pub struct CveConfig {
    pub use_nvd_api: bool,
    pub offline_fallback: bool,
    pub nvd_api_key: Option<String>,
    pub cache_ttl_days: i64,
}

impl Default for CveConfig {
    fn default() -> Self {
        Self {
            use_nvd_api: true,
            offline_fallback: true,
            nvd_api_key: None,
            cache_ttl_days: 30,
        }
    }
}

/// CVE Scanner that combines offline database, cache, and NVD API
pub struct CveScanner {
    pool: Option<SqlitePool>,
    config: CveConfig,
}

impl CveScanner {
    /// Create a new CVE scanner with database pool for caching
    pub fn new(pool: SqlitePool, config: CveConfig) -> Self {
        Self {
            pool: Some(pool),
            config,
        }
    }

    /// Create a CVE scanner without database (offline-only mode)
    pub fn offline_only() -> Self {
        Self {
            pool: None,
            config: CveConfig {
                use_nvd_api: false,
                offline_fallback: true,
                nvd_api_key: None,
                cache_ttl_days: 0,
            },
        }
    }

    /// Look up CVEs for a detected service
    pub async fn lookup_service_cves(
        &self,
        service: &ServiceInfo,
        port: u16,
    ) -> Result<Vec<Vulnerability>> {
        let product = normalize_product_name(&service.name);
        let version = service.version.as_deref();

        debug!(
            "Looking up CVEs for product='{}', version={:?}",
            product, version
        );

        // Step 1: Check offline database first (fastest)
        let mut vulns = offline_db::query_offline_cves(&product, version, port);
        if !vulns.is_empty() {
            info!(
                "Found {} CVEs in offline database for {}",
                vulns.len(),
                product
            );
            return Ok(vulns);
        }

        // Step 2: Check cache if we have a database connection
        if let Some(ref pool) = self.pool {
            match cache::get_cached_cves(pool, &product, version).await {
                Ok(cached) if !cached.is_empty() => {
                    info!("Found {} CVEs in cache for {}", cached.len(), product);
                    return Ok(cached);
                }
                Ok(_) => {
                    debug!("No cached CVEs for {}", product);
                }
                Err(e) => {
                    warn!("Cache lookup failed: {}", e);
                }
            }
        }

        // Step 3: Query NVD API if enabled and we have a cache miss
        if self.config.use_nvd_api {
            match nvd_client::query_nvd_api(
                &product,
                version,
                self.config.nvd_api_key.as_deref(),
            )
            .await
            {
                Ok(nvd_vulns) if !nvd_vulns.is_empty() => {
                    info!("Found {} CVEs from NVD API for {}", nvd_vulns.len(), product);

                    // Cache the results if we have a pool
                    if let Some(ref pool) = self.pool {
                        for vuln in &nvd_vulns {
                            if let Err(e) = cache::cache_cve(
                                pool,
                                &product,
                                version,
                                vuln,
                                self.config.cache_ttl_days,
                            )
                            .await
                            {
                                warn!("Failed to cache CVE: {}", e);
                            }
                        }
                    }

                    vulns = nvd_vulns;
                }
                Ok(_) => {
                    debug!("No CVEs found from NVD API for {}", product);
                }
                Err(e) => {
                    warn!("NVD API query failed: {}", e);
                    // Fall through to return empty or offline results
                }
            }
        }

        // Add service exposure warnings for commonly misconfigured services
        vulns.extend(check_service_exposure(&service.name, port));

        Ok(vulns)
    }

    /// Batch lookup for multiple services
    pub async fn lookup_host_cves(
        &self,
        ports: &[crate::types::PortInfo],
    ) -> Result<Vec<Vulnerability>> {
        let mut all_vulns = Vec::new();

        for port_info in ports {
            if let Some(ref service) = port_info.service {
                let vulns = self.lookup_service_cves(service, port_info.port).await?;
                all_vulns.extend(vulns);
            }
        }

        Ok(all_vulns)
    }
}

/// Normalize product names for consistent lookup
fn normalize_product_name(name: &str) -> String {
    let lower = name.to_lowercase();
    match lower.as_str() {
        "http" | "https" | "nginx" => {
            if lower.contains("nginx") {
                "nginx".to_string()
            } else if lower.contains("apache") {
                "apache".to_string()
            } else if lower.contains("iis") {
                "iis".to_string()
            } else {
                lower
            }
        }
        "ssh" | "openssh" => "openssh".to_string(),
        "mysql" | "mariadb" => "mysql".to_string(),
        "postgres" | "postgresql" => "postgresql".to_string(),
        "mssql" | "microsoft-sql" | "ms-sql" => "mssql".to_string(),
        "ftp" | "vsftpd" | "proftpd" => {
            if lower.contains("vsftpd") {
                "vsftpd".to_string()
            } else if lower.contains("proftpd") {
                "proftpd".to_string()
            } else {
                "ftp".to_string()
            }
        }
        _ => lower,
    }
}

/// Check for service exposure vulnerabilities (services that shouldn't be public)
fn check_service_exposure(service_name: &str, port: u16) -> Vec<Vulnerability> {
    let mut vulns = Vec::new();
    let lower = service_name.to_lowercase();

    match lower.as_str() {
        "redis" => {
            vulns.push(Vulnerability {
                cve_id: None,
                title: "Redis Exposed to Network".to_string(),
                severity: Severity::High,
                description: "Redis should not be directly exposed to untrusted networks. Verify authentication is enabled and bind address is restricted.".to_string(),
                affected_service: Some(format!("redis:{}", port)),
            });
        }
        "mongodb" => {
            vulns.push(Vulnerability {
                cve_id: None,
                title: "MongoDB Exposed to Network".to_string(),
                severity: Severity::High,
                description: "MongoDB should not be directly exposed. Verify authentication is enabled.".to_string(),
                affected_service: Some(format!("mongodb:{}", port)),
            });
        }
        "elasticsearch" => {
            vulns.push(Vulnerability {
                cve_id: None,
                title: "Elasticsearch Exposed to Network".to_string(),
                severity: Severity::High,
                description: "Elasticsearch should not be publicly accessible without authentication.".to_string(),
                affected_service: Some(format!("elasticsearch:{}", port)),
            });
        }
        "memcached" => {
            vulns.push(Vulnerability {
                cve_id: None,
                title: "Memcached Exposed to Network".to_string(),
                severity: Severity::High,
                description: "Memcached should not be publicly accessible. Can be used for DDoS amplification attacks.".to_string(),
                affected_service: Some(format!("memcached:{}", port)),
            });
        }
        "telnet" => {
            vulns.push(Vulnerability {
                cve_id: None,
                title: "Telnet Service Detected".to_string(),
                severity: Severity::High,
                description: "Telnet transmits all data including passwords in cleartext. Use SSH instead.".to_string(),
                affected_service: Some(format!("telnet:{}", port)),
            });
        }
        "ftp" => {
            vulns.push(Vulnerability {
                cve_id: None,
                title: "FTP Service Detected".to_string(),
                severity: Severity::Low,
                description: "FTP transmits credentials in cleartext. Consider using SFTP or FTPS instead.".to_string(),
                affected_service: Some(format!("ftp:{}", port)),
            });
        }
        "http" if port != 443 && port != 8443 => {
            vulns.push(Vulnerability {
                cve_id: None,
                title: "Unencrypted HTTP Service".to_string(),
                severity: Severity::Medium,
                description: "HTTP service without TLS encryption detected. Consider using HTTPS.".to_string(),
                affected_service: Some(format!("http:{}", port)),
            });
        }
        _ => {}
    }

    vulns
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_product_name() {
        assert_eq!(normalize_product_name("SSH"), "openssh");
        assert_eq!(normalize_product_name("OpenSSH"), "openssh");
        assert_eq!(normalize_product_name("MySQL"), "mysql");
        assert_eq!(normalize_product_name("PostgreSQL"), "postgresql");
    }

    #[tokio::test]
    async fn test_offline_scanner() {
        let scanner = CveScanner::offline_only();
        let service = ServiceInfo {
            name: "apache".to_string(),
            version: Some("2.4.49".to_string()),
            banner: None,
            cpe: None,
            enumeration: None,
            ssl_info: None,
        };

        let vulns = scanner.lookup_service_cves(&service, 80).await.unwrap();
        assert!(!vulns.is_empty());
        assert!(vulns.iter().any(|v| v.cve_id == Some("CVE-2021-41773".to_string())));
    }
}
