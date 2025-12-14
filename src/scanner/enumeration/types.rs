use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

/// Main enumeration result container
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnumerationResult {
    pub service_type: ServiceType,
    pub enumeration_depth: EnumDepth,
    pub findings: Vec<Finding>,
    pub duration: Duration,
    pub metadata: HashMap<String, String>,
}

/// Type of service being enumerated
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ServiceType {
    Http,
    Https,
    Smb,
    Dns,
    Ftp,
    Ssh,
    Smtp,
    Ldap,
    Snmp,
    Rdp,
    Vnc,
    Telnet,
    Database(DbType),
}

/// Database type for database enumeration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DbType {
    MySQL,
    PostgreSQL,
    MongoDB,
    Redis,
    Elasticsearch,
}

/// Enumeration depth/aggressiveness level
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Copy)]
pub enum EnumDepth {
    /// Passive: Banner analysis only, no additional probes
    Passive,
    /// Light: Common checks, small wordlists, moderate noise
    Light,
    /// Aggressive: Full wordlists, comprehensive checks, high noise
    Aggressive,
}

impl Default for EnumDepth {
    fn default() -> Self {
        EnumDepth::Light
    }
}

/// Individual finding from enumeration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub finding_type: FindingType,
    pub value: String,
    pub confidence: u8, // 0-100
    pub metadata: HashMap<String, String>,
}

impl Finding {
    /// Create a new finding with high confidence
    pub fn new(finding_type: FindingType, value: String) -> Self {
        Self {
            finding_type,
            value,
            confidence: 90,
            metadata: HashMap::new(),
        }
    }

    /// Create a new finding with specific confidence
    pub fn with_confidence(finding_type: FindingType, value: String, confidence: u8) -> Self {
        Self {
            finding_type,
            value,
            confidence,
            metadata: HashMap::new(),
        }
    }

    /// Add metadata to this finding
    pub fn with_metadata(mut self, key: String, value: String) -> Self {
        self.metadata.insert(key, value);
        self
    }
}

/// Type of finding discovered during enumeration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum FindingType {
    // HTTP/HTTPS findings
    Directory,
    File,
    AdminPanel,
    Technology,
    Header,
    RobotsTxt,
    SitemapXml,
    BackupFile,
    ConfigFile,

    // SMB findings
    Share,
    User,
    Group,
    Domain,
    Policy,
    NullSession,

    // DNS findings
    Subdomain,
    DnsRecord(DnsRecordType),
    ZoneTransfer,
    Nameserver,

    // Database findings
    DatabaseList,
    TableList,
    DefaultCredentials,
    UserList,
    Version,
    Privilege,

    // FTP findings
    AnonymousLogin,
    WritableDirectory,
    FtpBounce,

    // SSH findings
    WeakAlgorithm,
    SshKey,

    // SMTP findings
    OpenRelay,
    UserEnumeration,

    // LDAP findings
    AnonymousBind,
    LdapObject,
    BaseDn,

    // SSL/TLS findings
    TlsVersion,
    CipherSuite,
    Certificate,
    WeakCrypto,

    // SNMP findings
    SnmpCommunityString,
    SnmpSystemInfo,
    SnmpInterface,
    SnmpIpAddress,
    SnmpRoute,
    SnmpArpEntry,
    SnmpTcpConnection,
    SnmpUdpListener,
    SnmpV3Required,

    // RDP findings
    RdpVersion,
    RdpSecurityProtocol,
    RdpNlaRequired,
    RdpEncryptionLevel,
    RdpBlueKeep,

    // VNC findings
    VncVersion,
    VncSecurityType,
    VncNoAuth,

    // Telnet findings
    TelnetBanner,
    TelnetOption,

    // General findings
    Misconfiguration,
    InformationDisclosure,
    Vulnerability,
    SecurityConfig,
}

/// DNS record types for DNS enumeration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DnsRecordType {
    A,
    AAAA,
    MX,
    TXT,
    CNAME,
    NS,
    SOA,
    PTR,
    SRV,
}

impl std::fmt::Display for ServiceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServiceType::Http => write!(f, "HTTP"),
            ServiceType::Https => write!(f, "HTTPS"),
            ServiceType::Smb => write!(f, "SMB"),
            ServiceType::Dns => write!(f, "DNS"),
            ServiceType::Ftp => write!(f, "FTP"),
            ServiceType::Ssh => write!(f, "SSH"),
            ServiceType::Smtp => write!(f, "SMTP"),
            ServiceType::Ldap => write!(f, "LDAP"),
            ServiceType::Snmp => write!(f, "SNMP"),
            ServiceType::Rdp => write!(f, "RDP"),
            ServiceType::Vnc => write!(f, "VNC"),
            ServiceType::Telnet => write!(f, "Telnet"),
            ServiceType::Database(db) => write!(f, "{:?}", db),
        }
    }
}

impl std::fmt::Display for EnumDepth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EnumDepth::Passive => write!(f, "passive"),
            EnumDepth::Light => write!(f, "light"),
            EnumDepth::Aggressive => write!(f, "aggressive"),
        }
    }
}

impl std::str::FromStr for EnumDepth {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "passive" => Ok(EnumDepth::Passive),
            "light" => Ok(EnumDepth::Light),
            "aggressive" => Ok(EnumDepth::Aggressive),
            _ => Err(format!("Invalid enumeration depth: {}", s)),
        }
    }
}

impl std::fmt::Display for FindingType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FindingType::Directory => write!(f, "Directory"),
            FindingType::File => write!(f, "File"),
            FindingType::AdminPanel => write!(f, "Admin Panel"),
            FindingType::Technology => write!(f, "Technology"),
            FindingType::Header => write!(f, "HTTP Header"),
            FindingType::RobotsTxt => write!(f, "robots.txt"),
            FindingType::SitemapXml => write!(f, "sitemap.xml"),
            FindingType::BackupFile => write!(f, "Backup File"),
            FindingType::ConfigFile => write!(f, "Config File"),
            FindingType::Share => write!(f, "SMB Share"),
            FindingType::User => write!(f, "User"),
            FindingType::Group => write!(f, "Group"),
            FindingType::Domain => write!(f, "Domain"),
            FindingType::Policy => write!(f, "Policy"),
            FindingType::NullSession => write!(f, "Null Session"),
            FindingType::Subdomain => write!(f, "Subdomain"),
            FindingType::DnsRecord(t) => write!(f, "DNS {:?} Record", t),
            FindingType::ZoneTransfer => write!(f, "Zone Transfer"),
            FindingType::Nameserver => write!(f, "Nameserver"),
            FindingType::DatabaseList => write!(f, "Database"),
            FindingType::TableList => write!(f, "Table"),
            FindingType::DefaultCredentials => write!(f, "Default Credentials"),
            FindingType::UserList => write!(f, "Database User"),
            FindingType::Version => write!(f, "Version"),
            FindingType::Privilege => write!(f, "Privilege"),
            FindingType::AnonymousLogin => write!(f, "Anonymous Login"),
            FindingType::WritableDirectory => write!(f, "Writable Directory"),
            FindingType::FtpBounce => write!(f, "FTP Bounce"),
            FindingType::WeakAlgorithm => write!(f, "Weak Algorithm"),
            FindingType::SshKey => write!(f, "SSH Key"),
            FindingType::OpenRelay => write!(f, "Open Relay"),
            FindingType::UserEnumeration => write!(f, "User Enumeration"),
            FindingType::AnonymousBind => write!(f, "Anonymous Bind"),
            FindingType::LdapObject => write!(f, "LDAP Object"),
            FindingType::BaseDn => write!(f, "Base DN"),
            FindingType::TlsVersion => write!(f, "TLS Version"),
            FindingType::CipherSuite => write!(f, "Cipher Suite"),
            FindingType::Certificate => write!(f, "Certificate"),
            FindingType::WeakCrypto => write!(f, "Weak Cryptography"),
            FindingType::SnmpCommunityString => write!(f, "SNMP Community String"),
            FindingType::SnmpSystemInfo => write!(f, "SNMP System Info"),
            FindingType::SnmpInterface => write!(f, "SNMP Interface"),
            FindingType::SnmpIpAddress => write!(f, "SNMP IP Address"),
            FindingType::SnmpRoute => write!(f, "SNMP Route"),
            FindingType::SnmpArpEntry => write!(f, "SNMP ARP Entry"),
            FindingType::SnmpTcpConnection => write!(f, "SNMP TCP Connection"),
            FindingType::SnmpUdpListener => write!(f, "SNMP UDP Listener"),
            FindingType::SnmpV3Required => write!(f, "SNMPv3 Required"),
            FindingType::RdpVersion => write!(f, "RDP Version"),
            FindingType::RdpSecurityProtocol => write!(f, "RDP Security Protocol"),
            FindingType::RdpNlaRequired => write!(f, "NLA Requirement"),
            FindingType::RdpEncryptionLevel => write!(f, "RDP Encryption Level"),
            FindingType::RdpBlueKeep => write!(f, "BlueKeep Vulnerability"),
            FindingType::VncVersion => write!(f, "VNC Version"),
            FindingType::VncSecurityType => write!(f, "VNC Security Type"),
            FindingType::VncNoAuth => write!(f, "VNC No Authentication"),
            FindingType::TelnetBanner => write!(f, "Telnet Banner"),
            FindingType::TelnetOption => write!(f, "Telnet Option"),
            FindingType::Misconfiguration => write!(f, "Misconfiguration"),
            FindingType::InformationDisclosure => write!(f, "Information Disclosure"),
            FindingType::Vulnerability => write!(f, "Vulnerability"),
            FindingType::SecurityConfig => write!(f, "Security Configuration"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enum_depth_from_str() {
        assert_eq!("passive".parse::<EnumDepth>().unwrap(), EnumDepth::Passive);
        assert_eq!("light".parse::<EnumDepth>().unwrap(), EnumDepth::Light);
        assert_eq!("aggressive".parse::<EnumDepth>().unwrap(), EnumDepth::Aggressive);
        assert_eq!("PASSIVE".parse::<EnumDepth>().unwrap(), EnumDepth::Passive);
    }

    #[test]
    fn test_finding_creation() {
        let finding = Finding::new(FindingType::Directory, "/admin".to_string());
        assert_eq!(finding.value, "/admin");
        assert_eq!(finding.confidence, 90);

        let finding_with_meta = Finding::new(FindingType::Technology, "PHP".to_string())
            .with_metadata("version".to_string(), "7.4".to_string());
        assert_eq!(finding_with_meta.metadata.get("version"), Some(&"7.4".to_string()));
    }
}
