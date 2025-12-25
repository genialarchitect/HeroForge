#![allow(dead_code)]
//! IDS (Intrusion Detection System) Rule Support Module
//!
//! This module provides Suricata/Snort IDS rule parsing, validation, and matching
//! capabilities for blue team threat detection. It supports the standard
//! Suricata rule format and includes a built-in database of common detection rules.
//!
//! ## Features
//!
//! - **Rule Parsing**: Parse Suricata/Snort rule format including all common options
//! - **Rule Validation**: Validate rule syntax and semantic correctness
//! - **Packet Matching**: Match rules against network packets
//! - **Built-in Rules**: Pre-defined rules for malware, exploits, and suspicious traffic
//!
//! ## Example
//!
//! ```ignore
//! use heroforge::scanner::ids::{IdsRule, parse_rule, match_packet};
//!
//! let rule_text = r#"alert tcp any any -> any 80 (msg:"HTTP GET Request"; content:"GET"; sid:1000001;)"#;
//! let rule = parse_rule(rule_text)?;
//!
//! if match_packet(&packet, &rule) {
//!     println!("Rule {} matched: {}", rule.sid, rule.msg);
//! }
//! ```

pub mod parser;
pub mod rules_db;

use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;

// Re-export main types and functions
pub use parser::parse_rule;
#[allow(unused_imports)]
pub use parser::{parse_ruleset, RuleParser};
pub use rules_db::RulesDatabase;
#[allow(unused_imports)]
pub use rules_db::{get_default_rules, get_rules_by_category};

// =============================================================================
// Core Types
// =============================================================================

/// IDS rule action - what to do when a rule matches
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IdsRuleAction {
    /// Generate an alert
    Alert,
    /// Drop the packet (IPS mode)
    Drop,
    /// Pass the packet without further inspection
    Pass,
    /// Reject the connection (send RST/ICMP unreachable)
    Reject,
    /// Log only, no alert
    Log,
    /// Rewrite packet content
    Rewrite,
}

impl Default for IdsRuleAction {
    fn default() -> Self {
        Self::Alert
    }
}

impl std::fmt::Display for IdsRuleAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Alert => write!(f, "alert"),
            Self::Drop => write!(f, "drop"),
            Self::Pass => write!(f, "pass"),
            Self::Reject => write!(f, "reject"),
            Self::Log => write!(f, "log"),
            Self::Rewrite => write!(f, "rewrite"),
        }
    }
}

impl std::str::FromStr for IdsRuleAction {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "alert" => Ok(Self::Alert),
            "drop" => Ok(Self::Drop),
            "pass" => Ok(Self::Pass),
            "reject" => Ok(Self::Reject),
            "log" => Ok(Self::Log),
            "rewrite" => Ok(Self::Rewrite),
            _ => Err(anyhow!("Unknown rule action: {}", s)),
        }
    }
}

/// Protocol for IDS rule matching
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IdsProtocol {
    /// Any protocol
    Any,
    /// TCP protocol
    Tcp,
    /// UDP protocol
    Udp,
    /// ICMP protocol
    Icmp,
    /// IP protocol (any IP traffic)
    Ip,
    /// HTTP application layer
    Http,
    /// DNS application layer
    Dns,
    /// TLS/SSL application layer
    Tls,
    /// SMB/CIFS application layer
    Smb,
    /// FTP application layer
    Ftp,
    /// SSH application layer
    Ssh,
    /// SMTP application layer
    Smtp,
    /// IMAP application layer
    Imap,
    /// POP3 application layer
    Pop3,
    /// DHCP application layer
    Dhcp,
    /// NTP application layer
    Ntp,
    /// SNMP application layer
    Snmp,
    /// SIP application layer
    Sip,
    /// RDP application layer
    Rdp,
    /// MQTT application layer
    Mqtt,
    /// Modbus industrial protocol
    Modbus,
    /// DNP3 industrial protocol
    Dnp3,
}

impl Default for IdsProtocol {
    fn default() -> Self {
        Self::Any
    }
}

impl std::fmt::Display for IdsProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Any => write!(f, "any"),
            Self::Tcp => write!(f, "tcp"),
            Self::Udp => write!(f, "udp"),
            Self::Icmp => write!(f, "icmp"),
            Self::Ip => write!(f, "ip"),
            Self::Http => write!(f, "http"),
            Self::Dns => write!(f, "dns"),
            Self::Tls => write!(f, "tls"),
            Self::Smb => write!(f, "smb"),
            Self::Ftp => write!(f, "ftp"),
            Self::Ssh => write!(f, "ssh"),
            Self::Smtp => write!(f, "smtp"),
            Self::Imap => write!(f, "imap"),
            Self::Pop3 => write!(f, "pop3"),
            Self::Dhcp => write!(f, "dhcp"),
            Self::Ntp => write!(f, "ntp"),
            Self::Snmp => write!(f, "snmp"),
            Self::Sip => write!(f, "sip"),
            Self::Rdp => write!(f, "rdp"),
            Self::Mqtt => write!(f, "mqtt"),
            Self::Modbus => write!(f, "modbus"),
            Self::Dnp3 => write!(f, "dnp3"),
        }
    }
}

impl std::str::FromStr for IdsProtocol {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "any" => Ok(Self::Any),
            "tcp" => Ok(Self::Tcp),
            "udp" => Ok(Self::Udp),
            "icmp" => Ok(Self::Icmp),
            "ip" => Ok(Self::Ip),
            "http" => Ok(Self::Http),
            "dns" => Ok(Self::Dns),
            "tls" | "ssl" => Ok(Self::Tls),
            "smb" | "cifs" => Ok(Self::Smb),
            "ftp" => Ok(Self::Ftp),
            "ssh" => Ok(Self::Ssh),
            "smtp" => Ok(Self::Smtp),
            "imap" => Ok(Self::Imap),
            "pop3" => Ok(Self::Pop3),
            "dhcp" => Ok(Self::Dhcp),
            "ntp" => Ok(Self::Ntp),
            "snmp" => Ok(Self::Snmp),
            "sip" => Ok(Self::Sip),
            "rdp" => Ok(Self::Rdp),
            "mqtt" => Ok(Self::Mqtt),
            "modbus" => Ok(Self::Modbus),
            "dnp3" => Ok(Self::Dnp3),
            _ => Err(anyhow!("Unknown protocol: {}", s)),
        }
    }
}

/// Rule direction
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IdsDirection {
    /// Unidirectional (source -> destination)
    Unidirectional,
    /// Bidirectional (source <-> destination)
    Bidirectional,
}

impl Default for IdsDirection {
    fn default() -> Self {
        Self::Unidirectional
    }
}

/// Network address specification for rules
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value")]
pub enum IdsAddress {
    /// Any address
    Any,
    /// Single IP address
    Ip(IpAddr),
    /// CIDR network (e.g., 192.168.1.0/24)
    Cidr(String),
    /// Address variable (e.g., $HOME_NET)
    Variable(String),
    /// Negated address
    Negated(Box<IdsAddress>),
    /// Group of addresses
    Group(Vec<IdsAddress>),
}

impl Default for IdsAddress {
    fn default() -> Self {
        Self::Any
    }
}

impl std::fmt::Display for IdsAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Any => write!(f, "any"),
            Self::Ip(ip) => write!(f, "{}", ip),
            Self::Cidr(cidr) => write!(f, "{}", cidr),
            Self::Variable(var) => write!(f, "{}", var),
            Self::Negated(addr) => write!(f, "!{}", addr),
            Self::Group(addrs) => {
                write!(f, "[")?;
                for (i, addr) in addrs.iter().enumerate() {
                    if i > 0 {
                        write!(f, ",")?;
                    }
                    write!(f, "{}", addr)?;
                }
                write!(f, "]")
            }
        }
    }
}

/// Port specification for rules
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value")]
pub enum IdsPort {
    /// Any port
    Any,
    /// Single port
    Single(u16),
    /// Port range (start, end)
    Range(u16, u16),
    /// Port variable (e.g., $HTTP_PORTS)
    Variable(String),
    /// Negated port
    Negated(Box<IdsPort>),
    /// Group of ports
    Group(Vec<IdsPort>),
}

impl Default for IdsPort {
    fn default() -> Self {
        Self::Any
    }
}

impl std::fmt::Display for IdsPort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Any => write!(f, "any"),
            Self::Single(port) => write!(f, "{}", port),
            Self::Range(start, end) => write!(f, "{}:{}", start, end),
            Self::Variable(var) => write!(f, "{}", var),
            Self::Negated(port) => write!(f, "!{}", port),
            Self::Group(ports) => {
                write!(f, "[")?;
                for (i, port) in ports.iter().enumerate() {
                    if i > 0 {
                        write!(f, ",")?;
                    }
                    write!(f, "{}", port)?;
                }
                write!(f, "]")
            }
        }
    }
}

/// Content match pattern with modifiers
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContentMatch {
    /// The content to match (raw bytes or string)
    pub pattern: Vec<u8>,
    /// Case-insensitive matching
    pub nocase: bool,
    /// Match at specific depth (bytes from start)
    pub depth: Option<u32>,
    /// Start matching at offset
    pub offset: Option<u32>,
    /// Distance from previous match
    pub distance: Option<i32>,
    /// Match within N bytes of previous match
    pub within: Option<u32>,
    /// Raw bytes (hex-encoded in rule)
    pub is_raw: bool,
    /// Negated match (must NOT contain)
    pub negated: bool,
    /// Fast pattern match
    pub fast_pattern: bool,
}

impl Default for ContentMatch {
    fn default() -> Self {
        Self {
            pattern: Vec::new(),
            nocase: false,
            depth: None,
            offset: None,
            distance: None,
            within: None,
            is_raw: false,
            negated: false,
            fast_pattern: false,
        }
    }
}

/// PCRE (Perl Compatible Regular Expression) match
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PcreMatch {
    /// The regex pattern
    pub pattern: String,
    /// Regex flags (i, s, m, etc.)
    pub flags: String,
    /// Negated match
    pub negated: bool,
    /// Relative to previous match
    pub relative: bool,
}

/// Byte test operation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ByteTest {
    /// Number of bytes to test
    pub bytes: u32,
    /// Comparison operator
    pub operator: ByteTestOperator,
    /// Value to compare against
    pub value: u64,
    /// Offset in payload
    pub offset: i32,
    /// Relative to previous match
    pub relative: bool,
    /// Byte order
    pub endian: ByteOrder,
    /// Base for value (hex, dec, oct)
    pub base: NumberBase,
    /// Bitmask to apply
    pub bitmask: Option<u32>,
}

/// Byte test comparison operators
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ByteTestOperator {
    Equal,
    NotEqual,
    Less,
    LessOrEqual,
    Greater,
    GreaterOrEqual,
    And,
    Or,
}

/// Byte order
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ByteOrder {
    Big,
    Little,
}

impl Default for ByteOrder {
    fn default() -> Self {
        Self::Big
    }
}

/// Number base
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NumberBase {
    Decimal,
    Hexadecimal,
    Octal,
}

impl Default for NumberBase {
    fn default() -> Self {
        Self::Decimal
    }
}

/// Byte jump operation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ByteJump {
    /// Number of bytes to read
    pub bytes: u32,
    /// Offset to start reading
    pub offset: i32,
    /// Relative to previous match
    pub relative: bool,
    /// Multiplier for jump value
    pub multiplier: u32,
    /// Byte order
    pub endian: ByteOrder,
    /// Base for value
    pub base: NumberBase,
    /// Jump from beginning instead of current position
    pub from_beginning: bool,
    /// Align to 4-byte boundary
    pub align: bool,
    /// Bitmask
    pub bitmask: Option<u32>,
}

/// Flowbits operation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Flowbits {
    /// Operation type
    pub operation: FlowbitsOp,
    /// Flowbit name(s)
    pub names: Vec<String>,
    /// Group name (for group operations)
    pub group: Option<String>,
}

/// Flowbits operation types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FlowbitsOp {
    Set,
    Unset,
    Toggle,
    IsSet,
    IsNotSet,
    NoAlert,
}

/// Reference for a rule (CVE, URL, etc.)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleReference {
    /// Reference type (cve, url, bugtraq, etc.)
    pub ref_type: String,
    /// Reference value
    pub value: String,
}

/// Rule metadata key-value pair
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleMetadata {
    pub key: String,
    pub value: String,
}

/// Rule classification type
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleClasstype {
    /// Classification name
    pub name: String,
    /// Classification priority (1-4, 1 being highest)
    pub priority: u8,
}

/// Complete IDS rule representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdsRule {
    /// Rule action (alert, drop, pass, etc.)
    pub action: IdsRuleAction,
    /// Protocol to match
    pub protocol: IdsProtocol,
    /// Source address
    pub src_addr: IdsAddress,
    /// Source port
    pub src_port: IdsPort,
    /// Destination address
    pub dst_addr: IdsAddress,
    /// Destination port
    pub dst_port: IdsPort,
    /// Rule direction
    pub direction: IdsDirection,

    // Rule options
    /// Signature ID (unique identifier)
    pub sid: u64,
    /// Revision number
    pub rev: u32,
    /// Alert message
    pub msg: String,
    /// Classification type
    pub classtype: Option<RuleClasstype>,
    /// Priority (1-255, 1 being highest)
    pub priority: Option<u8>,
    /// Rule references (CVE, URL, etc.)
    pub references: Vec<RuleReference>,
    /// Content matches
    pub content_matches: Vec<ContentMatch>,
    /// PCRE matches
    pub pcre_matches: Vec<PcreMatch>,
    /// Byte tests
    pub byte_tests: Vec<ByteTest>,
    /// Byte jumps
    pub byte_jumps: Vec<ByteJump>,
    /// Flowbits operations
    pub flowbits: Vec<Flowbits>,
    /// Metadata key-value pairs
    pub metadata: Vec<RuleMetadata>,
    /// MITRE ATT&CK tactic IDs
    pub mitre_tactics: Vec<String>,
    /// MITRE ATT&CK technique IDs
    pub mitre_techniques: Vec<String>,
    /// Flow options (e.g., established, to_server)
    pub flow: Option<String>,
    /// Threshold/detection_filter settings
    pub threshold: Option<ThresholdConfig>,
    /// Target (src_ip or dest_ip for logging)
    pub target: Option<String>,
    /// Tags to apply to alerts
    pub tags: Vec<String>,
    /// Rule category
    pub category: Option<String>,
    /// Whether rule is enabled
    pub enabled: bool,
    /// Original rule text
    pub raw_rule: String,
    /// Rule creation time
    pub created_at: Option<DateTime<Utc>>,
    /// Last modification time
    pub updated_at: Option<DateTime<Utc>>,
}

impl Default for IdsRule {
    fn default() -> Self {
        Self {
            action: IdsRuleAction::Alert,
            protocol: IdsProtocol::Any,
            src_addr: IdsAddress::Any,
            src_port: IdsPort::Any,
            dst_addr: IdsAddress::Any,
            dst_port: IdsPort::Any,
            direction: IdsDirection::Unidirectional,
            sid: 0,
            rev: 1,
            msg: String::new(),
            classtype: None,
            priority: None,
            references: Vec::new(),
            content_matches: Vec::new(),
            pcre_matches: Vec::new(),
            byte_tests: Vec::new(),
            byte_jumps: Vec::new(),
            flowbits: Vec::new(),
            metadata: Vec::new(),
            mitre_tactics: Vec::new(),
            mitre_techniques: Vec::new(),
            flow: None,
            threshold: None,
            target: None,
            tags: Vec::new(),
            category: None,
            enabled: true,
            raw_rule: String::new(),
            created_at: None,
            updated_at: None,
        }
    }
}

/// Threshold/rate limiting configuration
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThresholdConfig {
    /// Threshold type
    pub threshold_type: ThresholdType,
    /// Track by (by_src, by_dst, by_both)
    pub track: String,
    /// Number of matches before triggering
    pub count: u32,
    /// Time window in seconds
    pub seconds: u32,
}

/// Threshold types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThresholdType {
    /// Alert once per time period
    Limit,
    /// Alert after N matches
    Threshold,
    /// Alert once per N matches
    Both,
}

// =============================================================================
// Packet Types for Matching
// =============================================================================

/// Simplified packet representation for rule matching
#[derive(Debug, Clone)]
pub struct Packet {
    /// Timestamp
    pub timestamp: DateTime<Utc>,
    /// Source IP address
    pub src_ip: Option<IpAddr>,
    /// Destination IP address
    pub dst_ip: Option<IpAddr>,
    /// Source port
    pub src_port: Option<u16>,
    /// Destination port
    pub dst_port: Option<u16>,
    /// Protocol
    pub protocol: IdsProtocol,
    /// Packet payload
    pub payload: Vec<u8>,
    /// Packet flags (TCP flags, ICMP type/code, etc.)
    pub flags: PacketFlags,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

impl Default for Packet {
    fn default() -> Self {
        Self {
            timestamp: Utc::now(),
            src_ip: None,
            dst_ip: None,
            src_port: None,
            dst_port: None,
            protocol: IdsProtocol::Any,
            payload: Vec::new(),
            flags: PacketFlags::default(),
            metadata: HashMap::new(),
        }
    }
}

/// Packet flags
#[derive(Debug, Clone, Default)]
pub struct PacketFlags {
    /// TCP SYN flag
    pub syn: bool,
    /// TCP ACK flag
    pub ack: bool,
    /// TCP FIN flag
    pub fin: bool,
    /// TCP RST flag
    pub rst: bool,
    /// TCP PSH flag
    pub psh: bool,
    /// TCP URG flag
    pub urg: bool,
    /// Established connection
    pub established: bool,
    /// Direction (to_server, to_client)
    pub to_server: bool,
}

// =============================================================================
// Rule Validation
// =============================================================================

/// Rule validation error
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleValidationError {
    pub field: String,
    pub message: String,
    pub severity: ValidationSeverity,
}

/// Validation error severity
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValidationSeverity {
    Error,
    Warning,
    Info,
}

/// Validate an IDS rule for correctness
pub fn validate_rule(rule: &IdsRule) -> Result<Vec<RuleValidationError>> {
    let mut errors = Vec::new();

    // Check required fields
    if rule.sid == 0 {
        errors.push(RuleValidationError {
            field: "sid".to_string(),
            message: "SID must be non-zero".to_string(),
            severity: ValidationSeverity::Error,
        });
    }

    if rule.msg.is_empty() {
        errors.push(RuleValidationError {
            field: "msg".to_string(),
            message: "Message (msg) is required".to_string(),
            severity: ValidationSeverity::Warning,
        });
    }

    // Validate priority range
    if let Some(priority) = rule.priority {
        if priority == 0 {
            errors.push(RuleValidationError {
                field: "priority".to_string(),
                message: "Priority must be between 1 and 255".to_string(),
                severity: ValidationSeverity::Error,
            });
        }
    }

    // Validate content patterns
    for (i, content) in rule.content_matches.iter().enumerate() {
        if content.pattern.is_empty() {
            errors.push(RuleValidationError {
                field: format!("content[{}]", i),
                message: "Content pattern cannot be empty".to_string(),
                severity: ValidationSeverity::Error,
            });
        }

        // Check for conflicting modifiers
        if content.distance.is_some() && content.offset.is_some() {
            errors.push(RuleValidationError {
                field: format!("content[{}]", i),
                message: "Cannot use both distance and offset on same content".to_string(),
                severity: ValidationSeverity::Warning,
            });
        }
    }

    // Validate PCRE patterns
    for (i, pcre) in rule.pcre_matches.iter().enumerate() {
        // Try to compile the regex to validate it
        if let Err(e) = regex::Regex::new(&pcre.pattern) {
            errors.push(RuleValidationError {
                field: format!("pcre[{}]", i),
                message: format!("Invalid regex pattern: {}", e),
                severity: ValidationSeverity::Error,
            });
        }
    }

    // Validate references
    for (i, reference) in rule.references.iter().enumerate() {
        if reference.ref_type.is_empty() || reference.value.is_empty() {
            errors.push(RuleValidationError {
                field: format!("reference[{}]", i),
                message: "Reference type and value must not be empty".to_string(),
                severity: ValidationSeverity::Warning,
            });
        }
    }

    // Check for at least one detection mechanism
    if rule.content_matches.is_empty()
        && rule.pcre_matches.is_empty()
        && rule.byte_tests.is_empty() {
        errors.push(RuleValidationError {
            field: "detection".to_string(),
            message: "Rule should have at least one detection mechanism (content, pcre, or byte_test)".to_string(),
            severity: ValidationSeverity::Warning,
        });
    }

    Ok(errors)
}

// =============================================================================
// Packet Matching
// =============================================================================

/// Check if a packet matches a rule
pub fn match_packet(packet: &Packet, rule: &IdsRule) -> bool {
    // Check if rule is enabled
    if !rule.enabled {
        return false;
    }

    // Check protocol
    if rule.protocol != IdsProtocol::Any && rule.protocol != packet.protocol {
        return false;
    }

    // Check source address
    if !match_address(&rule.src_addr, &packet.src_ip) {
        return false;
    }

    // Check destination address
    if !match_address(&rule.dst_addr, &packet.dst_ip) {
        return false;
    }

    // Check source port
    if !match_port(&rule.src_port, &packet.src_port) {
        return false;
    }

    // Check destination port
    if !match_port(&rule.dst_port, &packet.dst_port) {
        return false;
    }

    // Check content matches
    for content in &rule.content_matches {
        if !match_content(content, &packet.payload) {
            return false;
        }
    }

    // Check PCRE matches
    for pcre in &rule.pcre_matches {
        if !match_pcre(pcre, &packet.payload) {
            return false;
        }
    }

    // Check flow if specified
    if let Some(ref flow) = rule.flow {
        if !match_flow(flow, &packet.flags) {
            return false;
        }
    }

    true
}

/// Match address against packet IP
fn match_address(addr: &IdsAddress, ip: &Option<IpAddr>) -> bool {
    match addr {
        IdsAddress::Any => true,
        IdsAddress::Ip(rule_ip) => {
            ip.as_ref().map_or(false, |pkt_ip| pkt_ip == rule_ip)
        }
        IdsAddress::Cidr(cidr) => {
            if let Some(pkt_ip) = ip {
                if let Ok(network) = cidr.parse::<ipnetwork::IpNetwork>() {
                    network.contains(*pkt_ip)
                } else {
                    false
                }
            } else {
                false
            }
        }
        IdsAddress::Variable(_) => {
            // Variables need to be resolved at runtime
            // For now, match any
            true
        }
        IdsAddress::Negated(inner) => !match_address(inner, ip),
        IdsAddress::Group(addrs) => {
            addrs.iter().any(|a| match_address(a, ip))
        }
    }
}

/// Match port against packet port
fn match_port(port: &IdsPort, pkt_port: &Option<u16>) -> bool {
    match port {
        IdsPort::Any => true,
        IdsPort::Single(p) => pkt_port.as_ref().map_or(false, |pp| pp == p),
        IdsPort::Range(start, end) => {
            pkt_port.as_ref().map_or(false, |pp| pp >= start && pp <= end)
        }
        IdsPort::Variable(_) => {
            // Variables need to be resolved at runtime
            true
        }
        IdsPort::Negated(inner) => !match_port(inner, pkt_port),
        IdsPort::Group(ports) => {
            ports.iter().any(|p| match_port(p, pkt_port))
        }
    }
}

/// Match content pattern against payload
fn match_content(content: &ContentMatch, payload: &[u8]) -> bool {
    if content.pattern.is_empty() {
        return true;
    }

    let pattern = if content.nocase {
        content.pattern.to_ascii_lowercase()
    } else {
        content.pattern.clone()
    };

    let search_payload = if content.nocase {
        payload.to_ascii_lowercase()
    } else {
        payload.to_vec()
    };

    // Apply offset and depth
    let start = content.offset.unwrap_or(0) as usize;
    let end = content.depth.map(|d| (start + d as usize).min(search_payload.len()))
        .unwrap_or(search_payload.len());

    if start >= search_payload.len() {
        return content.negated;
    }

    let search_region = &search_payload[start..end];

    // Search for pattern
    let found = search_region.windows(pattern.len())
        .any(|window| window == pattern.as_slice());

    if content.negated {
        !found
    } else {
        found
    }
}

/// Match PCRE pattern against payload
fn match_pcre(pcre: &PcreMatch, payload: &[u8]) -> bool {
    // Convert payload to string for regex matching
    let payload_str = String::from_utf8_lossy(payload);

    // Build regex with flags
    let mut pattern = String::new();
    if pcre.flags.contains('i') {
        pattern.push_str("(?i)");
    }
    if pcre.flags.contains('s') {
        pattern.push_str("(?s)");
    }
    if pcre.flags.contains('m') {
        pattern.push_str("(?m)");
    }
    pattern.push_str(&pcre.pattern);

    match regex::Regex::new(&pattern) {
        Ok(re) => {
            let found = re.is_match(&payload_str);
            if pcre.negated { !found } else { found }
        }
        Err(_) => false,
    }
}

/// Match flow options against packet flags
fn match_flow(flow: &str, flags: &PacketFlags) -> bool {
    let parts: Vec<&str> = flow.split(',').map(|s| s.trim()).collect();

    for part in parts {
        match part {
            "established" => {
                if !flags.established {
                    return false;
                }
            }
            "to_server" | "from_client" => {
                if !flags.to_server {
                    return false;
                }
            }
            "to_client" | "from_server" => {
                if flags.to_server {
                    return false;
                }
            }
            "stateless" => {
                // Stateless matching, always pass
            }
            _ => {
                // Unknown flow option, ignore
            }
        }
    }

    true
}

// =============================================================================
// Rule Match Result
// =============================================================================

/// Result of a rule match
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleMatchResult {
    /// The matched rule SID
    pub rule_sid: u64,
    /// Rule message
    pub msg: String,
    /// Rule priority
    pub priority: u8,
    /// Classification
    pub classtype: Option<String>,
    /// Source IP from packet
    pub src_ip: Option<String>,
    /// Source port from packet
    pub src_port: Option<u16>,
    /// Destination IP from packet
    pub dst_ip: Option<String>,
    /// Destination port from packet
    pub dst_port: Option<u16>,
    /// Protocol
    pub protocol: String,
    /// Payload excerpt (first 256 bytes)
    pub payload_excerpt: Option<String>,
    /// Match timestamp
    pub timestamp: DateTime<Utc>,
    /// References from rule
    pub references: Vec<RuleReference>,
    /// Tags from rule
    pub tags: Vec<String>,
    /// MITRE ATT&CK techniques
    pub mitre_techniques: Vec<String>,
}

impl RuleMatchResult {
    /// Create a match result from a rule and packet
    pub fn from_match(rule: &IdsRule, packet: &Packet) -> Self {
        let payload_excerpt = if !packet.payload.is_empty() {
            let excerpt_len = packet.payload.len().min(256);
            Some(hex::encode(&packet.payload[..excerpt_len]))
        } else {
            None
        };

        Self {
            rule_sid: rule.sid,
            msg: rule.msg.clone(),
            priority: rule.priority.unwrap_or(
                rule.classtype.as_ref().map(|c| c.priority).unwrap_or(3)
            ),
            classtype: rule.classtype.as_ref().map(|c| c.name.clone()),
            src_ip: packet.src_ip.map(|ip| ip.to_string()),
            src_port: packet.src_port,
            dst_ip: packet.dst_ip.map(|ip| ip.to_string()),
            dst_port: packet.dst_port,
            protocol: packet.protocol.to_string(),
            payload_excerpt,
            timestamp: packet.timestamp,
            references: rule.references.clone(),
            tags: rule.tags.clone(),
            mitre_techniques: rule.mitre_techniques.clone(),
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_ids_rule_action_from_str() {
        assert_eq!("alert".parse::<IdsRuleAction>().unwrap(), IdsRuleAction::Alert);
        assert_eq!("DROP".parse::<IdsRuleAction>().unwrap(), IdsRuleAction::Drop);
        assert_eq!("Pass".parse::<IdsRuleAction>().unwrap(), IdsRuleAction::Pass);
        assert!("invalid".parse::<IdsRuleAction>().is_err());
    }

    #[test]
    fn test_ids_protocol_from_str() {
        assert_eq!("tcp".parse::<IdsProtocol>().unwrap(), IdsProtocol::Tcp);
        assert_eq!("UDP".parse::<IdsProtocol>().unwrap(), IdsProtocol::Udp);
        assert_eq!("http".parse::<IdsProtocol>().unwrap(), IdsProtocol::Http);
        assert_eq!("ssl".parse::<IdsProtocol>().unwrap(), IdsProtocol::Tls);
        assert!("invalid".parse::<IdsProtocol>().is_err());
    }

    #[test]
    fn test_validate_rule() {
        let mut rule = IdsRule::default();

        // Invalid: SID is 0
        let errors = validate_rule(&rule).unwrap();
        assert!(errors.iter().any(|e| e.field == "sid"));

        // Valid rule
        rule.sid = 1000001;
        rule.msg = "Test rule".to_string();
        rule.content_matches.push(ContentMatch {
            pattern: b"test".to_vec(),
            ..Default::default()
        });

        let errors = validate_rule(&rule).unwrap();
        assert!(errors.iter().all(|e| e.severity != ValidationSeverity::Error));
    }

    #[test]
    fn test_match_address() {
        use std::net::Ipv4Addr;

        let any_addr = IdsAddress::Any;
        let ip = Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)));
        assert!(match_address(&any_addr, &ip));

        let specific = IdsAddress::Ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)));
        assert!(match_address(&specific, &ip));

        let wrong = IdsAddress::Ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(!match_address(&wrong, &ip));

        let cidr = IdsAddress::Cidr("192.168.1.0/24".to_string());
        assert!(match_address(&cidr, &ip));

        let negated = IdsAddress::Negated(Box::new(wrong.clone()));
        assert!(match_address(&negated, &ip));
    }

    #[test]
    fn test_match_port() {
        let any_port = IdsPort::Any;
        let port = Some(80u16);
        assert!(match_port(&any_port, &port));

        let specific = IdsPort::Single(80);
        assert!(match_port(&specific, &port));

        let range = IdsPort::Range(80, 443);
        assert!(match_port(&range, &port));
        assert!(match_port(&range, &Some(443)));
        assert!(!match_port(&range, &Some(8080)));
    }

    #[test]
    fn test_match_content() {
        let payload = b"GET /index.html HTTP/1.1\r\nHost: example.com";

        let content = ContentMatch {
            pattern: b"GET".to_vec(),
            ..Default::default()
        };
        assert!(match_content(&content, payload));

        let content_nocase = ContentMatch {
            pattern: b"get".to_vec(),
            nocase: true,
            ..Default::default()
        };
        assert!(match_content(&content_nocase, payload));

        let content_negated = ContentMatch {
            pattern: b"POST".to_vec(),
            negated: true,
            ..Default::default()
        };
        assert!(match_content(&content_negated, payload));
    }

    #[test]
    fn test_match_packet() {
        use std::net::Ipv4Addr;

        let rule = IdsRule {
            action: IdsRuleAction::Alert,
            protocol: IdsProtocol::Tcp,
            src_addr: IdsAddress::Any,
            src_port: IdsPort::Any,
            dst_addr: IdsAddress::Any,
            dst_port: IdsPort::Single(80),
            direction: IdsDirection::Unidirectional,
            sid: 1000001,
            msg: "HTTP GET Request".to_string(),
            content_matches: vec![ContentMatch {
                pattern: b"GET".to_vec(),
                ..Default::default()
            }],
            enabled: true,
            ..Default::default()
        };

        let packet = Packet {
            src_ip: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))),
            dst_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            src_port: Some(54321),
            dst_port: Some(80),
            protocol: IdsProtocol::Tcp,
            payload: b"GET /index.html HTTP/1.1".to_vec(),
            ..Default::default()
        };

        assert!(match_packet(&packet, &rule));

        // Test with wrong port
        let mut wrong_port_packet = packet.clone();
        wrong_port_packet.dst_port = Some(8080);
        assert!(!match_packet(&wrong_port_packet, &rule));

        // Test with wrong content
        let mut wrong_content_packet = packet.clone();
        wrong_content_packet.payload = b"POST /index.html HTTP/1.1".to_vec();
        assert!(!match_packet(&wrong_content_packet, &rule));
    }
}
