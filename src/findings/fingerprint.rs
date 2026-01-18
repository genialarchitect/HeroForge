// ============================================================================
// Finding Fingerprinting Module
// ============================================================================
//
// Generates unique fingerprints for vulnerability findings to enable
// deduplication across multiple scans. Fingerprints are hash-based identifiers
// that remain consistent for the same underlying vulnerability.

use sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};

/// Components used to generate a finding fingerprint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FingerprintComponents {
    /// Vulnerability identifier (CVE, plugin ID, or custom ID)
    pub vulnerability_id: String,
    /// Target host IP or hostname
    pub host: String,
    /// Port number (if applicable)
    pub port: Option<u16>,
    /// Protocol (tcp, udp, etc.)
    pub protocol: Option<String>,
    /// Service name (if detected)
    pub service: Option<String>,
    /// Additional context for uniqueness (e.g., URI path for web vulns)
    pub context: Option<String>,
}

impl FingerprintComponents {
    /// Create new fingerprint components
    pub fn new(vulnerability_id: &str, host: &str) -> Self {
        Self {
            vulnerability_id: vulnerability_id.to_lowercase(),
            host: normalize_host(host),
            port: None,
            protocol: None,
            service: None,
            context: None,
        }
    }

    /// Set the port
    pub fn with_port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }

    /// Set the protocol
    pub fn with_protocol(mut self, protocol: &str) -> Self {
        self.protocol = Some(protocol.to_lowercase());
        self
    }

    /// Set the service
    pub fn with_service(mut self, service: &str) -> Self {
        self.service = Some(service.to_lowercase());
        self
    }

    /// Set additional context
    pub fn with_context(mut self, context: &str) -> Self {
        self.context = Some(context.to_string());
        self
    }

    /// Generate the canonical string for hashing
    fn to_canonical_string(&self) -> String {
        let mut parts = vec![
            self.vulnerability_id.clone(),
            self.host.clone(),
        ];

        if let Some(port) = self.port {
            parts.push(port.to_string());
        }

        if let Some(ref protocol) = self.protocol {
            parts.push(protocol.clone());
        }

        if let Some(ref service) = self.service {
            parts.push(service.clone());
        }

        if let Some(ref context) = self.context {
            parts.push(context.clone());
        }

        parts.join("|")
    }
}

/// A unique fingerprint for a finding
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FindingFingerprint {
    /// The hash value
    pub hash: String,
    /// Algorithm used (for future-proofing)
    pub algorithm: String,
    /// Version of the fingerprinting logic
    pub version: u32,
}

impl FindingFingerprint {
    /// Current fingerprinting algorithm version
    pub const CURRENT_VERSION: u32 = 1;

    /// Generate a fingerprint from components
    pub fn from_components(components: &FingerprintComponents) -> Self {
        let canonical = components.to_canonical_string();
        let hash = Self::compute_hash(&canonical);

        Self {
            hash,
            algorithm: "sha256".to_string(),
            version: Self::CURRENT_VERSION,
        }
    }

    /// Compute SHA-256 hash of the input
    fn compute_hash(input: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(input.as_bytes());
        let result = hasher.finalize();
        hex::encode(result)
    }

    /// Get a short version of the hash (first 16 characters)
    pub fn short_hash(&self) -> &str {
        &self.hash[..16.min(self.hash.len())]
    }
}

/// Normalize host string for consistent fingerprinting
fn normalize_host(host: &str) -> String {
    let host = host.trim().to_lowercase();

    // Remove trailing dots from hostnames
    let host = host.trim_end_matches('.');

    // Handle IPv6 addresses - remove brackets if present
    if host.starts_with('[') && host.ends_with(']') {
        return host[1..host.len()-1].to_string();
    }

    host.to_string()
}

/// Fingerprint configuration options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FingerprintConfig {
    /// Include port in fingerprint (default: true)
    pub include_port: bool,
    /// Include protocol in fingerprint (default: true)
    pub include_protocol: bool,
    /// Include service in fingerprint (default: false - services can change)
    pub include_service: bool,
    /// Include context in fingerprint (default: true)
    pub include_context: bool,
}

impl Default for FingerprintConfig {
    fn default() -> Self {
        Self {
            include_port: true,
            include_protocol: true,
            include_service: false,
            include_context: true,
        }
    }
}

/// Fingerprint generator with configurable options
pub struct FingerprintGenerator {
    config: FingerprintConfig,
}

impl FingerprintGenerator {
    /// Create a new generator with default config
    pub fn new() -> Self {
        Self {
            config: FingerprintConfig::default(),
        }
    }

    /// Create a generator with custom config
    pub fn with_config(config: FingerprintConfig) -> Self {
        Self { config }
    }

    /// Generate fingerprint for a vulnerability finding
    pub fn generate(
        &self,
        vulnerability_id: &str,
        host: &str,
        port: Option<u16>,
        protocol: Option<&str>,
        service: Option<&str>,
        context: Option<&str>,
    ) -> FindingFingerprint {
        let mut components = FingerprintComponents::new(vulnerability_id, host);

        if self.config.include_port {
            if let Some(p) = port {
                components = components.with_port(p);
            }
        }

        if self.config.include_protocol {
            if let Some(proto) = protocol {
                components = components.with_protocol(proto);
            }
        }

        if self.config.include_service {
            if let Some(svc) = service {
                components = components.with_service(svc);
            }
        }

        if self.config.include_context {
            if let Some(ctx) = context {
                components = components.with_context(ctx);
            }
        }

        FindingFingerprint::from_components(&components)
    }

    /// Generate fingerprint for a host-level finding (no port)
    pub fn generate_host_level(
        &self,
        vulnerability_id: &str,
        host: &str,
    ) -> FindingFingerprint {
        self.generate(vulnerability_id, host, None, None, None, None)
    }

    /// Generate fingerprint for a service-level finding
    pub fn generate_service_level(
        &self,
        vulnerability_id: &str,
        host: &str,
        port: u16,
        protocol: &str,
    ) -> FindingFingerprint {
        self.generate(vulnerability_id, host, Some(port), Some(protocol), None, None)
    }
}

impl Default for FingerprintGenerator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fingerprint_consistency() {
        let gen = FingerprintGenerator::new();

        let fp1 = gen.generate("CVE-2021-44228", "192.168.1.1", Some(8080), Some("tcp"), None, None);
        let fp2 = gen.generate("CVE-2021-44228", "192.168.1.1", Some(8080), Some("tcp"), None, None);

        assert_eq!(fp1.hash, fp2.hash);
    }

    #[test]
    fn test_fingerprint_case_insensitive() {
        let gen = FingerprintGenerator::new();

        let fp1 = gen.generate("CVE-2021-44228", "192.168.1.1", Some(8080), Some("TCP"), None, None);
        let fp2 = gen.generate("cve-2021-44228", "192.168.1.1", Some(8080), Some("tcp"), None, None);

        assert_eq!(fp1.hash, fp2.hash);
    }

    #[test]
    fn test_different_ports_different_fingerprints() {
        let gen = FingerprintGenerator::new();

        let fp1 = gen.generate("CVE-2021-44228", "192.168.1.1", Some(8080), Some("tcp"), None, None);
        let fp2 = gen.generate("CVE-2021-44228", "192.168.1.1", Some(443), Some("tcp"), None, None);

        assert_ne!(fp1.hash, fp2.hash);
    }

    #[test]
    fn test_host_normalization() {
        assert_eq!(normalize_host("Example.COM"), "example.com");
        assert_eq!(normalize_host("example.com."), "example.com");
        assert_eq!(normalize_host("[::1]"), "::1");
    }

    #[test]
    fn test_short_hash() {
        let gen = FingerprintGenerator::new();
        let fp = gen.generate("CVE-2021-44228", "192.168.1.1", Some(8080), Some("tcp"), None, None);

        assert_eq!(fp.short_hash().len(), 16);
    }
}
