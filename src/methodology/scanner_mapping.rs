//! Scanner Mapping for Methodology Items
//!
//! Maps methodology checklist item codes (WSTG-*, PTES-*) to appropriate scanner functions.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use utoipa::ToSchema;

/// Defines the type of scanner to execute for a methodology item
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ScannerType {
    /// Cross-site scripting vulnerability scanner
    XssScan,
    /// SQL injection vulnerability scanner
    SqlInjectionScan,
    /// Security headers analysis
    SecurityHeadersScan,
    /// SSL/TLS configuration analysis
    SslTlsScan,
    /// Directory and file enumeration
    DirectoryEnumeration,
    /// Web technology fingerprinting
    TechnologyFingerprint,
    /// Network port scanning
    PortScan,
    /// Service version enumeration
    ServiceEnumeration,
    /// DNS record enumeration
    DnsEnumeration,
    /// Asset discovery (OSINT, search engines)
    AssetDiscovery,
    /// WHOIS lookup and analysis
    WhoisLookup,
    /// Default/common credential testing
    DefaultCredentialCheck,
    /// HTTP method testing (OPTIONS, TRACE, etc.)
    HttpMethodTest,
    /// Session management testing
    SessionManagementTest,
    /// Authentication bypass testing
    AuthBypassTest,
    /// File upload vulnerability testing
    FileUploadTest,
    /// CORS misconfiguration testing
    CorsMisconfigTest,
    /// Requires manual verification only
    ManualOnly,
}

impl std::fmt::Display for ScannerType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScannerType::XssScan => write!(f, "XSS Scanner"),
            ScannerType::SqlInjectionScan => write!(f, "SQL Injection Scanner"),
            ScannerType::SecurityHeadersScan => write!(f, "Security Headers Scanner"),
            ScannerType::SslTlsScan => write!(f, "SSL/TLS Scanner"),
            ScannerType::DirectoryEnumeration => write!(f, "Directory Enumeration"),
            ScannerType::TechnologyFingerprint => write!(f, "Technology Fingerprinting"),
            ScannerType::PortScan => write!(f, "Port Scanner"),
            ScannerType::ServiceEnumeration => write!(f, "Service Enumeration"),
            ScannerType::DnsEnumeration => write!(f, "DNS Enumeration"),
            ScannerType::AssetDiscovery => write!(f, "Asset Discovery"),
            ScannerType::WhoisLookup => write!(f, "WHOIS Lookup"),
            ScannerType::DefaultCredentialCheck => write!(f, "Default Credential Check"),
            ScannerType::HttpMethodTest => write!(f, "HTTP Method Test"),
            ScannerType::SessionManagementTest => write!(f, "Session Management Test"),
            ScannerType::AuthBypassTest => write!(f, "Authentication Bypass Test"),
            ScannerType::FileUploadTest => write!(f, "File Upload Test"),
            ScannerType::CorsMisconfigTest => write!(f, "CORS Misconfiguration Test"),
            ScannerType::ManualOnly => write!(f, "Manual Verification Required"),
        }
    }
}

/// Mapping between a methodology item code and its scanner
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ScannerMapping {
    /// The methodology item code (e.g., "WSTG-INFO-01")
    pub item_code: String,
    /// The type of scanner to execute
    pub scanner_type: ScannerType,
    /// Human-readable description of what the test does
    pub description: String,
    /// Whether a target URL is required
    pub requires_url: bool,
    /// Whether a target IP address is required
    pub requires_ip: bool,
    /// Whether the test is considered safe (read-only/non-destructive)
    pub is_safe: bool,
}

/// Get all scanner mappings for methodology items
pub fn get_all_mappings() -> HashMap<String, ScannerMapping> {
    let mut map = HashMap::new();

    // =========================================================================
    // OWASP WSTG - Information Gathering (WSTG-INFO)
    // =========================================================================

    map.insert(
        "WSTG-INFO-01".into(),
        ScannerMapping {
            item_code: "WSTG-INFO-01".into(),
            scanner_type: ScannerType::AssetDiscovery,
            description: "Conduct search engine discovery reconnaissance".into(),
            requires_url: false,
            requires_ip: false,
            is_safe: true,
        },
    );

    map.insert(
        "WSTG-INFO-02".into(),
        ScannerMapping {
            item_code: "WSTG-INFO-02".into(),
            scanner_type: ScannerType::TechnologyFingerprint,
            description: "Fingerprint web server technology and version".into(),
            requires_url: true,
            requires_ip: false,
            is_safe: true,
        },
    );

    map.insert(
        "WSTG-INFO-03".into(),
        ScannerMapping {
            item_code: "WSTG-INFO-03".into(),
            scanner_type: ScannerType::DirectoryEnumeration,
            description: "Review webserver metafiles (robots.txt, sitemap.xml)".into(),
            requires_url: true,
            requires_ip: false,
            is_safe: true,
        },
    );

    map.insert(
        "WSTG-INFO-04".into(),
        ScannerMapping {
            item_code: "WSTG-INFO-04".into(),
            scanner_type: ScannerType::DirectoryEnumeration,
            description: "Enumerate applications on the web server".into(),
            requires_url: true,
            requires_ip: false,
            is_safe: true,
        },
    );

    map.insert(
        "WSTG-INFO-05".into(),
        ScannerMapping {
            item_code: "WSTG-INFO-05".into(),
            scanner_type: ScannerType::DirectoryEnumeration,
            description: "Review webpage content for information leakage".into(),
            requires_url: true,
            requires_ip: false,
            is_safe: true,
        },
    );

    map.insert(
        "WSTG-INFO-06".into(),
        ScannerMapping {
            item_code: "WSTG-INFO-06".into(),
            scanner_type: ScannerType::TechnologyFingerprint,
            description: "Identify application entry points".into(),
            requires_url: true,
            requires_ip: false,
            is_safe: true,
        },
    );

    map.insert(
        "WSTG-INFO-07".into(),
        ScannerMapping {
            item_code: "WSTG-INFO-07".into(),
            scanner_type: ScannerType::TechnologyFingerprint,
            description: "Map execution paths through the application".into(),
            requires_url: true,
            requires_ip: false,
            is_safe: true,
        },
    );

    map.insert(
        "WSTG-INFO-08".into(),
        ScannerMapping {
            item_code: "WSTG-INFO-08".into(),
            scanner_type: ScannerType::TechnologyFingerprint,
            description: "Fingerprint web application framework".into(),
            requires_url: true,
            requires_ip: false,
            is_safe: true,
        },
    );

    map.insert(
        "WSTG-INFO-09".into(),
        ScannerMapping {
            item_code: "WSTG-INFO-09".into(),
            scanner_type: ScannerType::TechnologyFingerprint,
            description: "Fingerprint web application".into(),
            requires_url: true,
            requires_ip: false,
            is_safe: true,
        },
    );

    map.insert(
        "WSTG-INFO-10".into(),
        ScannerMapping {
            item_code: "WSTG-INFO-10".into(),
            scanner_type: ScannerType::TechnologyFingerprint,
            description: "Map application architecture".into(),
            requires_url: true,
            requires_ip: false,
            is_safe: true,
        },
    );

    // =========================================================================
    // OWASP WSTG - Configuration and Deployment Management (WSTG-CONF)
    // =========================================================================

    map.insert(
        "WSTG-CONF-01".into(),
        ScannerMapping {
            item_code: "WSTG-CONF-01".into(),
            scanner_type: ScannerType::PortScan,
            description: "Test network infrastructure configuration".into(),
            requires_url: false,
            requires_ip: true,
            is_safe: true,
        },
    );

    map.insert(
        "WSTG-CONF-02".into(),
        ScannerMapping {
            item_code: "WSTG-CONF-02".into(),
            scanner_type: ScannerType::TechnologyFingerprint,
            description: "Test application platform configuration".into(),
            requires_url: true,
            requires_ip: false,
            is_safe: true,
        },
    );

    map.insert(
        "WSTG-CONF-03".into(),
        ScannerMapping {
            item_code: "WSTG-CONF-03".into(),
            scanner_type: ScannerType::DirectoryEnumeration,
            description: "Test for file extensions handling".into(),
            requires_url: true,
            requires_ip: false,
            is_safe: true,
        },
    );

    map.insert(
        "WSTG-CONF-04".into(),
        ScannerMapping {
            item_code: "WSTG-CONF-04".into(),
            scanner_type: ScannerType::DirectoryEnumeration,
            description: "Review backup and unreferenced files for sensitive information".into(),
            requires_url: true,
            requires_ip: false,
            is_safe: true,
        },
    );

    map.insert(
        "WSTG-CONF-05".into(),
        ScannerMapping {
            item_code: "WSTG-CONF-05".into(),
            scanner_type: ScannerType::TechnologyFingerprint,
            description: "Enumerate infrastructure and application admin interfaces".into(),
            requires_url: true,
            requires_ip: false,
            is_safe: true,
        },
    );

    map.insert(
        "WSTG-CONF-06".into(),
        ScannerMapping {
            item_code: "WSTG-CONF-06".into(),
            scanner_type: ScannerType::HttpMethodTest,
            description: "Test HTTP methods".into(),
            requires_url: true,
            requires_ip: false,
            is_safe: true,
        },
    );

    map.insert(
        "WSTG-CONF-07".into(),
        ScannerMapping {
            item_code: "WSTG-CONF-07".into(),
            scanner_type: ScannerType::SslTlsScan,
            description: "Test HTTP Strict Transport Security".into(),
            requires_url: true,
            requires_ip: false,
            is_safe: true,
        },
    );

    map.insert(
        "WSTG-CONF-08".into(),
        ScannerMapping {
            item_code: "WSTG-CONF-08".into(),
            scanner_type: ScannerType::ManualOnly,
            description: "Test RIA cross domain policy".into(),
            requires_url: true,
            requires_ip: false,
            is_safe: true,
        },
    );

    map.insert(
        "WSTG-CONF-09".into(),
        ScannerMapping {
            item_code: "WSTG-CONF-09".into(),
            scanner_type: ScannerType::SecurityHeadersScan,
            description: "Test file permission".into(),
            requires_url: true,
            requires_ip: false,
            is_safe: true,
        },
    );

    map.insert(
        "WSTG-CONF-10".into(),
        ScannerMapping {
            item_code: "WSTG-CONF-10".into(),
            scanner_type: ScannerType::DnsEnumeration,
            description: "Test for subdomain takeover".into(),
            requires_url: false,
            requires_ip: false,
            is_safe: true,
        },
    );

    map.insert(
        "WSTG-CONF-11".into(),
        ScannerMapping {
            item_code: "WSTG-CONF-11".into(),
            scanner_type: ScannerType::ManualOnly,
            description: "Test cloud storage".into(),
            requires_url: true,
            requires_ip: false,
            is_safe: true,
        },
    );

    // =========================================================================
    // OWASP WSTG - Identity Management (WSTG-IDNT)
    // =========================================================================

    map.insert(
        "WSTG-IDNT-01".into(),
        ScannerMapping {
            item_code: "WSTG-IDNT-01".into(),
            scanner_type: ScannerType::ManualOnly,
            description: "Test role definitions".into(),
            requires_url: true,
            requires_ip: false,
            is_safe: true,
        },
    );

    map.insert(
        "WSTG-IDNT-02".into(),
        ScannerMapping {
            item_code: "WSTG-IDNT-02".into(),
            scanner_type: ScannerType::ManualOnly,
            description: "Test user registration process".into(),
            requires_url: true,
            requires_ip: false,
            is_safe: false,
        },
    );

    map.insert(
        "WSTG-IDNT-03".into(),
        ScannerMapping {
            item_code: "WSTG-IDNT-03".into(),
            scanner_type: ScannerType::ManualOnly,
            description: "Test account provisioning process".into(),
            requires_url: true,
            requires_ip: false,
            is_safe: true,
        },
    );

    map.insert(
        "WSTG-IDNT-04".into(),
        ScannerMapping {
            item_code: "WSTG-IDNT-04".into(),
            scanner_type: ScannerType::ManualOnly,
            description: "Test for account enumeration and guessable user accounts".into(),
            requires_url: true,
            requires_ip: false,
            is_safe: true,
        },
    );

    map.insert(
        "WSTG-IDNT-05".into(),
        ScannerMapping {
            item_code: "WSTG-IDNT-05".into(),
            scanner_type: ScannerType::ManualOnly,
            description: "Test for weak or unenforced username policy".into(),
            requires_url: true,
            requires_ip: false,
            is_safe: true,
        },
    );

    // =========================================================================
    // OWASP WSTG - Authentication (WSTG-ATHN)
    // =========================================================================

    map.insert(
        "WSTG-ATHN-01".into(),
        ScannerMapping {
            item_code: "WSTG-ATHN-01".into(),
            scanner_type: ScannerType::SslTlsScan,
            description: "Test credentials transported over encrypted channel".into(),
            requires_url: true,
            requires_ip: false,
            is_safe: true,
        },
    );

    map.insert(
        "WSTG-ATHN-02".into(),
        ScannerMapping {
            item_code: "WSTG-ATHN-02".into(),
            scanner_type: ScannerType::DefaultCredentialCheck,
            description: "Test for default credentials".into(),
            requires_url: true,
            requires_ip: false,
            is_safe: false,
        },
    );

    map.insert(
        "WSTG-ATHN-03".into(),
        ScannerMapping {
            item_code: "WSTG-ATHN-03".into(),
            scanner_type: ScannerType::ManualOnly,
            description: "Test for weak lock out mechanism".into(),
            requires_url: true,
            requires_ip: false,
            is_safe: false,
        },
    );

    map.insert(
        "WSTG-ATHN-04".into(),
        ScannerMapping {
            item_code: "WSTG-ATHN-04".into(),
            scanner_type: ScannerType::AuthBypassTest,
            description: "Test for authentication bypass".into(),
            requires_url: true,
            requires_ip: false,
            is_safe: false,
        },
    );

    map.insert(
        "WSTG-ATHN-05".into(),
        ScannerMapping {
            item_code: "WSTG-ATHN-05".into(),
            scanner_type: ScannerType::ManualOnly,
            description: "Test for vulnerable remember password".into(),
            requires_url: true,
            requires_ip: false,
            is_safe: true,
        },
    );

    map.insert(
        "WSTG-ATHN-06".into(),
        ScannerMapping {
            item_code: "WSTG-ATHN-06".into(),
            scanner_type: ScannerType::ManualOnly,
            description: "Test for browser cache weaknesses".into(),
            requires_url: true,
            requires_ip: false,
            is_safe: true,
        },
    );

    map.insert(
        "WSTG-ATHN-07".into(),
        ScannerMapping {
            item_code: "WSTG-ATHN-07".into(),
            scanner_type: ScannerType::ManualOnly,
            description: "Test for weak password policy".into(),
            requires_url: true,
            requires_ip: false,
            is_safe: true,
        },
    );

    map.insert(
        "WSTG-ATHN-08".into(),
        ScannerMapping {
            item_code: "WSTG-ATHN-08".into(),
            scanner_type: ScannerType::ManualOnly,
            description: "Test for weak security question answer".into(),
            requires_url: true,
            requires_ip: false,
            is_safe: true,
        },
    );

    map.insert(
        "WSTG-ATHN-09".into(),
        ScannerMapping {
            item_code: "WSTG-ATHN-09".into(),
            scanner_type: ScannerType::ManualOnly,
            description: "Test for weak password change or reset functionalities".into(),
            requires_url: true,
            requires_ip: false,
            is_safe: false,
        },
    );

    map.insert(
        "WSTG-ATHN-10".into(),
        ScannerMapping {
            item_code: "WSTG-ATHN-10".into(),
            scanner_type: ScannerType::ManualOnly,
            description: "Test for weaker authentication in alternative channel".into(),
            requires_url: true,
            requires_ip: false,
            is_safe: true,
        },
    );

    // =========================================================================
    // OWASP WSTG - Authorization (WSTG-ATHZ)
    // =========================================================================

    map.insert(
        "WSTG-ATHZ-01".into(),
        ScannerMapping {
            item_code: "WSTG-ATHZ-01".into(),
            scanner_type: ScannerType::DirectoryEnumeration,
            description: "Test directory traversal and file include".into(),
            requires_url: true,
            requires_ip: false,
            is_safe: false,
        },
    );

    map.insert(
        "WSTG-ATHZ-02".into(),
        ScannerMapping {
            item_code: "WSTG-ATHZ-02".into(),
            scanner_type: ScannerType::AuthBypassTest,
            description: "Test for bypassing authorization schema".into(),
            requires_url: true,
            requires_ip: false,
            is_safe: false,
        },
    );

    map.insert(
        "WSTG-ATHZ-03".into(),
        ScannerMapping {
            item_code: "WSTG-ATHZ-03".into(),
            scanner_type: ScannerType::ManualOnly,
            description: "Test for privilege escalation".into(),
            requires_url: true,
            requires_ip: false,
            is_safe: false,
        },
    );

    map.insert(
        "WSTG-ATHZ-04".into(),
        ScannerMapping {
            item_code: "WSTG-ATHZ-04".into(),
            scanner_type: ScannerType::ManualOnly,
            description: "Test for insecure direct object references".into(),
            requires_url: true,
            requires_ip: false,
            is_safe: false,
        },
    );

    // =========================================================================
    // OWASP WSTG - Session Management (WSTG-SESS)
    // =========================================================================

    map.insert(
        "WSTG-SESS-01".into(),
        ScannerMapping {
            item_code: "WSTG-SESS-01".into(),
            scanner_type: ScannerType::SessionManagementTest,
            description: "Test for session management schema".into(),
            requires_url: true,
            requires_ip: false,
            is_safe: true,
        },
    );

    map.insert(
        "WSTG-SESS-02".into(),
        ScannerMapping {
            item_code: "WSTG-SESS-02".into(),
            scanner_type: ScannerType::SecurityHeadersScan,
            description: "Test for cookie attributes".into(),
            requires_url: true,
            requires_ip: false,
            is_safe: true,
        },
    );

    map.insert(
        "WSTG-SESS-03".into(),
        ScannerMapping {
            item_code: "WSTG-SESS-03".into(),
            scanner_type: ScannerType::SessionManagementTest,
            description: "Test for session fixation".into(),
            requires_url: true,
            requires_ip: false,
            is_safe: false,
        },
    );

    map.insert(
        "WSTG-SESS-04".into(),
        ScannerMapping {
            item_code: "WSTG-SESS-04".into(),
            scanner_type: ScannerType::ManualOnly,
            description: "Test for exposed session variables".into(),
            requires_url: true,
            requires_ip: false,
            is_safe: true,
        },
    );

    map.insert(
        "WSTG-SESS-05".into(),
        ScannerMapping {
            item_code: "WSTG-SESS-05".into(),
            scanner_type: ScannerType::ManualOnly,
            description: "Test for cross site request forgery".into(),
            requires_url: true,
            requires_ip: false,
            is_safe: true,
        },
    );

    map.insert(
        "WSTG-SESS-06".into(),
        ScannerMapping {
            item_code: "WSTG-SESS-06".into(),
            scanner_type: ScannerType::ManualOnly,
            description: "Test for logout functionality".into(),
            requires_url: true,
            requires_ip: false,
            is_safe: true,
        },
    );

    map.insert(
        "WSTG-SESS-07".into(),
        ScannerMapping {
            item_code: "WSTG-SESS-07".into(),
            scanner_type: ScannerType::ManualOnly,
            description: "Test session timeout".into(),
            requires_url: true,
            requires_ip: false,
            is_safe: true,
        },
    );

    map.insert(
        "WSTG-SESS-08".into(),
        ScannerMapping {
            item_code: "WSTG-SESS-08".into(),
            scanner_type: ScannerType::ManualOnly,
            description: "Test for session puzzling".into(),
            requires_url: true,
            requires_ip: false,
            is_safe: true,
        },
    );

    map.insert(
        "WSTG-SESS-09".into(),
        ScannerMapping {
            item_code: "WSTG-SESS-09".into(),
            scanner_type: ScannerType::ManualOnly,
            description: "Test for session hijacking".into(),
            requires_url: true,
            requires_ip: false,
            is_safe: false,
        },
    );

    // =========================================================================
    // OWASP WSTG - Input Validation (WSTG-INPV) - KEY VULNERABILITY TESTS
    // =========================================================================

    map.insert(
        "WSTG-INPV-01".into(),
        ScannerMapping {
            item_code: "WSTG-INPV-01".into(),
            scanner_type: ScannerType::XssScan,
            description: "Test for reflected cross-site scripting".into(),
            requires_url: true,
            requires_ip: false,
            is_safe: false,
        },
    );

    map.insert(
        "WSTG-INPV-02".into(),
        ScannerMapping {
            item_code: "WSTG-INPV-02".into(),
            scanner_type: ScannerType::XssScan,
            description: "Test for stored cross-site scripting".into(),
            requires_url: true,
            requires_ip: false,
            is_safe: false,
        },
    );

    map.insert(
        "WSTG-INPV-03".into(),
        ScannerMapping {
            item_code: "WSTG-INPV-03".into(),
            scanner_type: ScannerType::ManualOnly,
            description: "Test for HTTP verb tampering".into(),
            requires_url: true,
            requires_ip: false,
            is_safe: false,
        },
    );

    map.insert(
        "WSTG-INPV-04".into(),
        ScannerMapping {
            item_code: "WSTG-INPV-04".into(),
            scanner_type: ScannerType::ManualOnly,
            description: "Test for HTTP parameter pollution".into(),
            requires_url: true,
            requires_ip: false,
            is_safe: false,
        },
    );

    map.insert(
        "WSTG-INPV-05".into(),
        ScannerMapping {
            item_code: "WSTG-INPV-05".into(),
            scanner_type: ScannerType::SqlInjectionScan,
            description: "Test for SQL injection".into(),
            requires_url: true,
            requires_ip: false,
            is_safe: false,
        },
    );

    map.insert(
        "WSTG-INPV-06".into(),
        ScannerMapping {
            item_code: "WSTG-INPV-06".into(),
            scanner_type: ScannerType::ManualOnly,
            description: "Test for LDAP injection".into(),
            requires_url: true,
            requires_ip: false,
            is_safe: false,
        },
    );

    map.insert(
        "WSTG-INPV-07".into(),
        ScannerMapping {
            item_code: "WSTG-INPV-07".into(),
            scanner_type: ScannerType::ManualOnly,
            description: "Test for XML injection".into(),
            requires_url: true,
            requires_ip: false,
            is_safe: false,
        },
    );

    map.insert(
        "WSTG-INPV-08".into(),
        ScannerMapping {
            item_code: "WSTG-INPV-08".into(),
            scanner_type: ScannerType::ManualOnly,
            description: "Test for SSI injection".into(),
            requires_url: true,
            requires_ip: false,
            is_safe: false,
        },
    );

    map.insert(
        "WSTG-INPV-09".into(),
        ScannerMapping {
            item_code: "WSTG-INPV-09".into(),
            scanner_type: ScannerType::ManualOnly,
            description: "Test for XPath injection".into(),
            requires_url: true,
            requires_ip: false,
            is_safe: false,
        },
    );

    map.insert(
        "WSTG-INPV-10".into(),
        ScannerMapping {
            item_code: "WSTG-INPV-10".into(),
            scanner_type: ScannerType::ManualOnly,
            description: "Test for IMAP/SMTP injection".into(),
            requires_url: true,
            requires_ip: false,
            is_safe: false,
        },
    );

    map.insert(
        "WSTG-INPV-11".into(),
        ScannerMapping {
            item_code: "WSTG-INPV-11".into(),
            scanner_type: ScannerType::ManualOnly,
            description: "Test for code injection".into(),
            requires_url: true,
            requires_ip: false,
            is_safe: false,
        },
    );

    map.insert(
        "WSTG-INPV-12".into(),
        ScannerMapping {
            item_code: "WSTG-INPV-12".into(),
            scanner_type: ScannerType::ManualOnly,
            description: "Test for command injection".into(),
            requires_url: true,
            requires_ip: false,
            is_safe: false,
        },
    );

    map.insert(
        "WSTG-INPV-13".into(),
        ScannerMapping {
            item_code: "WSTG-INPV-13".into(),
            scanner_type: ScannerType::ManualOnly,
            description: "Test for format string injection".into(),
            requires_url: true,
            requires_ip: false,
            is_safe: false,
        },
    );

    map.insert(
        "WSTG-INPV-14".into(),
        ScannerMapping {
            item_code: "WSTG-INPV-14".into(),
            scanner_type: ScannerType::ManualOnly,
            description: "Test for incubated vulnerabilities".into(),
            requires_url: true,
            requires_ip: false,
            is_safe: true,
        },
    );

    map.insert(
        "WSTG-INPV-15".into(),
        ScannerMapping {
            item_code: "WSTG-INPV-15".into(),
            scanner_type: ScannerType::ManualOnly,
            description: "Test for HTTP splitting/smuggling".into(),
            requires_url: true,
            requires_ip: false,
            is_safe: false,
        },
    );

    map.insert(
        "WSTG-INPV-16".into(),
        ScannerMapping {
            item_code: "WSTG-INPV-16".into(),
            scanner_type: ScannerType::ManualOnly,
            description: "Test for HTTP incoming requests".into(),
            requires_url: true,
            requires_ip: false,
            is_safe: true,
        },
    );

    map.insert(
        "WSTG-INPV-17".into(),
        ScannerMapping {
            item_code: "WSTG-INPV-17".into(),
            scanner_type: ScannerType::SecurityHeadersScan,
            description: "Test for host header injection".into(),
            requires_url: true,
            requires_ip: false,
            is_safe: false,
        },
    );

    map.insert(
        "WSTG-INPV-18".into(),
        ScannerMapping {
            item_code: "WSTG-INPV-18".into(),
            scanner_type: ScannerType::ManualOnly,
            description: "Test for server-side template injection".into(),
            requires_url: true,
            requires_ip: false,
            is_safe: false,
        },
    );

    map.insert(
        "WSTG-INPV-19".into(),
        ScannerMapping {
            item_code: "WSTG-INPV-19".into(),
            scanner_type: ScannerType::ManualOnly,
            description: "Test for server-side request forgery".into(),
            requires_url: true,
            requires_ip: false,
            is_safe: false,
        },
    );

    // =========================================================================
    // OWASP WSTG - Error Handling (WSTG-ERRH)
    // =========================================================================

    map.insert(
        "WSTG-ERRH-01".into(),
        ScannerMapping {
            item_code: "WSTG-ERRH-01".into(),
            scanner_type: ScannerType::TechnologyFingerprint,
            description: "Test for improper error handling".into(),
            requires_url: true,
            requires_ip: false,
            is_safe: true,
        },
    );

    map.insert(
        "WSTG-ERRH-02".into(),
        ScannerMapping {
            item_code: "WSTG-ERRH-02".into(),
            scanner_type: ScannerType::TechnologyFingerprint,
            description: "Test for stack traces".into(),
            requires_url: true,
            requires_ip: false,
            is_safe: true,
        },
    );

    // =========================================================================
    // OWASP WSTG - Cryptography (WSTG-CRYP)
    // =========================================================================

    map.insert(
        "WSTG-CRYP-01".into(),
        ScannerMapping {
            item_code: "WSTG-CRYP-01".into(),
            scanner_type: ScannerType::SslTlsScan,
            description: "Test for weak transport layer security".into(),
            requires_url: false,
            requires_ip: true,
            is_safe: true,
        },
    );

    map.insert(
        "WSTG-CRYP-02".into(),
        ScannerMapping {
            item_code: "WSTG-CRYP-02".into(),
            scanner_type: ScannerType::ManualOnly,
            description: "Test for padding oracle".into(),
            requires_url: true,
            requires_ip: false,
            is_safe: false,
        },
    );

    map.insert(
        "WSTG-CRYP-03".into(),
        ScannerMapping {
            item_code: "WSTG-CRYP-03".into(),
            scanner_type: ScannerType::ManualOnly,
            description: "Test for sensitive information sent via unencrypted channels".into(),
            requires_url: true,
            requires_ip: false,
            is_safe: true,
        },
    );

    map.insert(
        "WSTG-CRYP-04".into(),
        ScannerMapping {
            item_code: "WSTG-CRYP-04".into(),
            scanner_type: ScannerType::ManualOnly,
            description: "Test for weak encryption".into(),
            requires_url: true,
            requires_ip: false,
            is_safe: true,
        },
    );

    // =========================================================================
    // OWASP WSTG - Business Logic (WSTG-BUSL)
    // =========================================================================

    map.insert(
        "WSTG-BUSL-01".into(),
        ScannerMapping {
            item_code: "WSTG-BUSL-01".into(),
            scanner_type: ScannerType::ManualOnly,
            description: "Test business logic data validation".into(),
            requires_url: true,
            requires_ip: false,
            is_safe: true,
        },
    );

    map.insert(
        "WSTG-BUSL-02".into(),
        ScannerMapping {
            item_code: "WSTG-BUSL-02".into(),
            scanner_type: ScannerType::ManualOnly,
            description: "Test ability to forge requests".into(),
            requires_url: true,
            requires_ip: false,
            is_safe: false,
        },
    );

    map.insert(
        "WSTG-BUSL-03".into(),
        ScannerMapping {
            item_code: "WSTG-BUSL-03".into(),
            scanner_type: ScannerType::ManualOnly,
            description: "Test integrity checks".into(),
            requires_url: true,
            requires_ip: false,
            is_safe: true,
        },
    );

    map.insert(
        "WSTG-BUSL-04".into(),
        ScannerMapping {
            item_code: "WSTG-BUSL-04".into(),
            scanner_type: ScannerType::ManualOnly,
            description: "Test for process timing".into(),
            requires_url: true,
            requires_ip: false,
            is_safe: true,
        },
    );

    map.insert(
        "WSTG-BUSL-05".into(),
        ScannerMapping {
            item_code: "WSTG-BUSL-05".into(),
            scanner_type: ScannerType::ManualOnly,
            description: "Test number of times a function can be used limits".into(),
            requires_url: true,
            requires_ip: false,
            is_safe: false,
        },
    );

    map.insert(
        "WSTG-BUSL-06".into(),
        ScannerMapping {
            item_code: "WSTG-BUSL-06".into(),
            scanner_type: ScannerType::ManualOnly,
            description: "Test for the circumvention of work flows".into(),
            requires_url: true,
            requires_ip: false,
            is_safe: false,
        },
    );

    map.insert(
        "WSTG-BUSL-07".into(),
        ScannerMapping {
            item_code: "WSTG-BUSL-07".into(),
            scanner_type: ScannerType::ManualOnly,
            description: "Test defenses against application misuse".into(),
            requires_url: true,
            requires_ip: false,
            is_safe: false,
        },
    );

    map.insert(
        "WSTG-BUSL-08".into(),
        ScannerMapping {
            item_code: "WSTG-BUSL-08".into(),
            scanner_type: ScannerType::FileUploadTest,
            description: "Test upload of unexpected file types".into(),
            requires_url: true,
            requires_ip: false,
            is_safe: false,
        },
    );

    map.insert(
        "WSTG-BUSL-09".into(),
        ScannerMapping {
            item_code: "WSTG-BUSL-09".into(),
            scanner_type: ScannerType::FileUploadTest,
            description: "Test upload of malicious files".into(),
            requires_url: true,
            requires_ip: false,
            is_safe: false,
        },
    );

    // =========================================================================
    // OWASP WSTG - Client-side (WSTG-CLNT)
    // =========================================================================

    map.insert(
        "WSTG-CLNT-01".into(),
        ScannerMapping {
            item_code: "WSTG-CLNT-01".into(),
            scanner_type: ScannerType::XssScan,
            description: "Test for DOM-based cross-site scripting".into(),
            requires_url: true,
            requires_ip: false,
            is_safe: false,
        },
    );

    map.insert(
        "WSTG-CLNT-02".into(),
        ScannerMapping {
            item_code: "WSTG-CLNT-02".into(),
            scanner_type: ScannerType::ManualOnly,
            description: "Test for JavaScript execution".into(),
            requires_url: true,
            requires_ip: false,
            is_safe: true,
        },
    );

    map.insert(
        "WSTG-CLNT-03".into(),
        ScannerMapping {
            item_code: "WSTG-CLNT-03".into(),
            scanner_type: ScannerType::ManualOnly,
            description: "Test for HTML injection".into(),
            requires_url: true,
            requires_ip: false,
            is_safe: false,
        },
    );

    map.insert(
        "WSTG-CLNT-04".into(),
        ScannerMapping {
            item_code: "WSTG-CLNT-04".into(),
            scanner_type: ScannerType::ManualOnly,
            description: "Test for client-side URL redirect".into(),
            requires_url: true,
            requires_ip: false,
            is_safe: true,
        },
    );

    map.insert(
        "WSTG-CLNT-05".into(),
        ScannerMapping {
            item_code: "WSTG-CLNT-05".into(),
            scanner_type: ScannerType::ManualOnly,
            description: "Test for CSS injection".into(),
            requires_url: true,
            requires_ip: false,
            is_safe: false,
        },
    );

    map.insert(
        "WSTG-CLNT-06".into(),
        ScannerMapping {
            item_code: "WSTG-CLNT-06".into(),
            scanner_type: ScannerType::ManualOnly,
            description: "Test for client-side resource manipulation".into(),
            requires_url: true,
            requires_ip: false,
            is_safe: true,
        },
    );

    map.insert(
        "WSTG-CLNT-07".into(),
        ScannerMapping {
            item_code: "WSTG-CLNT-07".into(),
            scanner_type: ScannerType::CorsMisconfigTest,
            description: "Test cross origin resource sharing".into(),
            requires_url: true,
            requires_ip: false,
            is_safe: true,
        },
    );

    map.insert(
        "WSTG-CLNT-08".into(),
        ScannerMapping {
            item_code: "WSTG-CLNT-08".into(),
            scanner_type: ScannerType::ManualOnly,
            description: "Test for cross site flashing".into(),
            requires_url: true,
            requires_ip: false,
            is_safe: true,
        },
    );

    map.insert(
        "WSTG-CLNT-09".into(),
        ScannerMapping {
            item_code: "WSTG-CLNT-09".into(),
            scanner_type: ScannerType::SecurityHeadersScan,
            description: "Test for clickjacking".into(),
            requires_url: true,
            requires_ip: false,
            is_safe: true,
        },
    );

    map.insert(
        "WSTG-CLNT-10".into(),
        ScannerMapping {
            item_code: "WSTG-CLNT-10".into(),
            scanner_type: ScannerType::ManualOnly,
            description: "Test WebSockets".into(),
            requires_url: true,
            requires_ip: false,
            is_safe: true,
        },
    );

    map.insert(
        "WSTG-CLNT-11".into(),
        ScannerMapping {
            item_code: "WSTG-CLNT-11".into(),
            scanner_type: ScannerType::ManualOnly,
            description: "Test web messaging".into(),
            requires_url: true,
            requires_ip: false,
            is_safe: true,
        },
    );

    map.insert(
        "WSTG-CLNT-12".into(),
        ScannerMapping {
            item_code: "WSTG-CLNT-12".into(),
            scanner_type: ScannerType::ManualOnly,
            description: "Test browser storage".into(),
            requires_url: true,
            requires_ip: false,
            is_safe: true,
        },
    );

    map.insert(
        "WSTG-CLNT-13".into(),
        ScannerMapping {
            item_code: "WSTG-CLNT-13".into(),
            scanner_type: ScannerType::ManualOnly,
            description: "Test for cross site script inclusion".into(),
            requires_url: true,
            requires_ip: false,
            is_safe: true,
        },
    );

    // =========================================================================
    // OWASP WSTG - API Testing (WSTG-APIT)
    // =========================================================================

    map.insert(
        "WSTG-APIT-01".into(),
        ScannerMapping {
            item_code: "WSTG-APIT-01".into(),
            scanner_type: ScannerType::TechnologyFingerprint,
            description: "Test GraphQL".into(),
            requires_url: true,
            requires_ip: false,
            is_safe: true,
        },
    );

    // =========================================================================
    // PTES - Intelligence Gathering (PTES-IG)
    // =========================================================================

    map.insert(
        "PTES-IG-01".into(),
        ScannerMapping {
            item_code: "PTES-IG-01".into(),
            scanner_type: ScannerType::AssetDiscovery,
            description: "Passive reconnaissance (OSINT, DNS, WHOIS)".into(),
            requires_url: false,
            requires_ip: false,
            is_safe: true,
        },
    );

    map.insert(
        "PTES-IG-02".into(),
        ScannerMapping {
            item_code: "PTES-IG-02".into(),
            scanner_type: ScannerType::PortScan,
            description: "Active reconnaissance (port scanning, enumeration)".into(),
            requires_url: false,
            requires_ip: true,
            is_safe: true,
        },
    );

    map.insert(
        "PTES-IG-03".into(),
        ScannerMapping {
            item_code: "PTES-IG-03".into(),
            scanner_type: ScannerType::ServiceEnumeration,
            description: "Target identification and documentation".into(),
            requires_url: false,
            requires_ip: true,
            is_safe: true,
        },
    );

    // =========================================================================
    // PTES - Threat Modeling (PTES-TM)
    // =========================================================================

    map.insert(
        "PTES-TM-01".into(),
        ScannerMapping {
            item_code: "PTES-TM-01".into(),
            scanner_type: ScannerType::ManualOnly,
            description: "Business asset analysis".into(),
            requires_url: false,
            requires_ip: false,
            is_safe: true,
        },
    );

    map.insert(
        "PTES-TM-02".into(),
        ScannerMapping {
            item_code: "PTES-TM-02".into(),
            scanner_type: ScannerType::ManualOnly,
            description: "Business process analysis".into(),
            requires_url: false,
            requires_ip: false,
            is_safe: true,
        },
    );

    map.insert(
        "PTES-TM-03".into(),
        ScannerMapping {
            item_code: "PTES-TM-03".into(),
            scanner_type: ScannerType::ManualOnly,
            description: "Threat agent/community analysis".into(),
            requires_url: false,
            requires_ip: false,
            is_safe: true,
        },
    );

    map.insert(
        "PTES-TM-04".into(),
        ScannerMapping {
            item_code: "PTES-TM-04".into(),
            scanner_type: ScannerType::ManualOnly,
            description: "Threat capability analysis".into(),
            requires_url: false,
            requires_ip: false,
            is_safe: true,
        },
    );

    map.insert(
        "PTES-TM-05".into(),
        ScannerMapping {
            item_code: "PTES-TM-05".into(),
            scanner_type: ScannerType::ManualOnly,
            description: "Motivation modeling".into(),
            requires_url: false,
            requires_ip: false,
            is_safe: true,
        },
    );

    // =========================================================================
    // PTES - Vulnerability Analysis (PTES-VA)
    // =========================================================================

    map.insert(
        "PTES-VA-01".into(),
        ScannerMapping {
            item_code: "PTES-VA-01".into(),
            scanner_type: ScannerType::PortScan,
            description: "Automated vulnerability scanning".into(),
            requires_url: false,
            requires_ip: true,
            is_safe: true,
        },
    );

    map.insert(
        "PTES-VA-02".into(),
        ScannerMapping {
            item_code: "PTES-VA-02".into(),
            scanner_type: ScannerType::ManualOnly,
            description: "Manual vulnerability testing".into(),
            requires_url: false,
            requires_ip: true,
            is_safe: false,
        },
    );

    map.insert(
        "PTES-VA-03".into(),
        ScannerMapping {
            item_code: "PTES-VA-03".into(),
            scanner_type: ScannerType::ManualOnly,
            description: "Vulnerability research and verification".into(),
            requires_url: false,
            requires_ip: false,
            is_safe: true,
        },
    );

    map.insert(
        "PTES-VA-04".into(),
        ScannerMapping {
            item_code: "PTES-VA-04".into(),
            scanner_type: ScannerType::ManualOnly,
            description: "Attack avenue identification".into(),
            requires_url: false,
            requires_ip: false,
            is_safe: true,
        },
    );

    // =========================================================================
    // PTES - Exploitation (PTES-EX)
    // =========================================================================

    map.insert(
        "PTES-EX-01".into(),
        ScannerMapping {
            item_code: "PTES-EX-01".into(),
            scanner_type: ScannerType::ManualOnly,
            description: "Exploitation planning".into(),
            requires_url: false,
            requires_ip: false,
            is_safe: true,
        },
    );

    map.insert(
        "PTES-EX-02".into(),
        ScannerMapping {
            item_code: "PTES-EX-02".into(),
            scanner_type: ScannerType::ManualOnly,
            description: "Controlled exploitation".into(),
            requires_url: false,
            requires_ip: true,
            is_safe: false,
        },
    );

    map.insert(
        "PTES-EX-03".into(),
        ScannerMapping {
            item_code: "PTES-EX-03".into(),
            scanner_type: ScannerType::ManualOnly,
            description: "Exploitation impact analysis".into(),
            requires_url: false,
            requires_ip: false,
            is_safe: true,
        },
    );

    // =========================================================================
    // PTES - Post-Exploitation (PTES-PE)
    // =========================================================================

    map.insert(
        "PTES-PE-01".into(),
        ScannerMapping {
            item_code: "PTES-PE-01".into(),
            scanner_type: ScannerType::ManualOnly,
            description: "Infrastructure analysis".into(),
            requires_url: false,
            requires_ip: true,
            is_safe: false,
        },
    );

    map.insert(
        "PTES-PE-02".into(),
        ScannerMapping {
            item_code: "PTES-PE-02".into(),
            scanner_type: ScannerType::ManualOnly,
            description: "Pillaging".into(),
            requires_url: false,
            requires_ip: true,
            is_safe: false,
        },
    );

    map.insert(
        "PTES-PE-03".into(),
        ScannerMapping {
            item_code: "PTES-PE-03".into(),
            scanner_type: ScannerType::ManualOnly,
            description: "Persistence".into(),
            requires_url: false,
            requires_ip: true,
            is_safe: false,
        },
    );

    map.insert(
        "PTES-PE-04".into(),
        ScannerMapping {
            item_code: "PTES-PE-04".into(),
            scanner_type: ScannerType::ManualOnly,
            description: "Further penetration".into(),
            requires_url: false,
            requires_ip: true,
            is_safe: false,
        },
    );

    map.insert(
        "PTES-PE-05".into(),
        ScannerMapping {
            item_code: "PTES-PE-05".into(),
            scanner_type: ScannerType::ManualOnly,
            description: "Cleanup".into(),
            requires_url: false,
            requires_ip: true,
            is_safe: false,
        },
    );

    // =========================================================================
    // PTES - Reporting (PTES-RP)
    // =========================================================================

    map.insert(
        "PTES-RP-01".into(),
        ScannerMapping {
            item_code: "PTES-RP-01".into(),
            scanner_type: ScannerType::ManualOnly,
            description: "Executive summary".into(),
            requires_url: false,
            requires_ip: false,
            is_safe: true,
        },
    );

    map.insert(
        "PTES-RP-02".into(),
        ScannerMapping {
            item_code: "PTES-RP-02".into(),
            scanner_type: ScannerType::ManualOnly,
            description: "Technical findings".into(),
            requires_url: false,
            requires_ip: false,
            is_safe: true,
        },
    );

    map.insert(
        "PTES-RP-03".into(),
        ScannerMapping {
            item_code: "PTES-RP-03".into(),
            scanner_type: ScannerType::ManualOnly,
            description: "Recommendations".into(),
            requires_url: false,
            requires_ip: false,
            is_safe: true,
        },
    );

    map
}

/// Get the scanner mapping for a specific methodology item code
pub fn get_mapping(item_code: &str) -> Option<ScannerMapping> {
    get_all_mappings().get(item_code).cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_all_mappings_not_empty() {
        let mappings = get_all_mappings();
        assert!(!mappings.is_empty());
        // Should have at least 70+ mappings for WSTG and PTES
        assert!(mappings.len() >= 70);
    }

    #[test]
    fn test_get_mapping_wstg_xss() {
        let mapping = get_mapping("WSTG-INPV-01").unwrap();
        assert_eq!(mapping.scanner_type, ScannerType::XssScan);
        assert!(mapping.requires_url);
        assert!(!mapping.is_safe);
    }

    #[test]
    fn test_get_mapping_wstg_sqli() {
        let mapping = get_mapping("WSTG-INPV-05").unwrap();
        assert_eq!(mapping.scanner_type, ScannerType::SqlInjectionScan);
        assert!(mapping.requires_url);
        assert!(!mapping.is_safe);
    }

    #[test]
    fn test_get_mapping_wstg_ssl() {
        let mapping = get_mapping("WSTG-CRYP-01").unwrap();
        assert_eq!(mapping.scanner_type, ScannerType::SslTlsScan);
        assert!(mapping.requires_ip);
        assert!(mapping.is_safe);
    }

    #[test]
    fn test_get_mapping_ptes_port_scan() {
        let mapping = get_mapping("PTES-IG-02").unwrap();
        assert_eq!(mapping.scanner_type, ScannerType::PortScan);
        assert!(mapping.requires_ip);
        assert!(mapping.is_safe);
    }

    #[test]
    fn test_get_mapping_not_found() {
        let mapping = get_mapping("INVALID-CODE-99");
        assert!(mapping.is_none());
    }

    #[test]
    fn test_scanner_type_display() {
        assert_eq!(format!("{}", ScannerType::XssScan), "XSS Scanner");
        assert_eq!(format!("{}", ScannerType::SqlInjectionScan), "SQL Injection Scanner");
        assert_eq!(format!("{}", ScannerType::ManualOnly), "Manual Verification Required");
    }
}
