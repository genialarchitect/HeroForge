//! Log parsing module for various log formats.
//!
//! Supports parsing of:
//! - Syslog RFC 3164 (BSD format)
//! - Syslog RFC 5424 (structured format)
//! - CEF (Common Event Format)
//! - LEEF (Log Event Extended Format)
//! - JSON logs
//! - Raw/unstructured logs

#![allow(dead_code)]

use anyhow::{anyhow, Result};
use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use regex::Regex;
use serde_json::Value;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::LazyLock;

use super::types::{LogEntry, LogFormat, SiemSeverity, SyslogFacility};

/// Regex patterns for parsing various log formats
static RFC3164_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    // <PRI>TIMESTAMP HOSTNAME TAG: MESSAGE
    // Example: <34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick
    Regex::new(
        r"^<(\d{1,3})>(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s*(.*)$"
    ).unwrap()
});

static RFC5424_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    // <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
    // Example: <165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut="3"] BOMAn application event log entry...
    Regex::new(
        r"^<(\d{1,3})>(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\[.*?\]|-)\s*(.*)$"
    ).unwrap()
});

static CEF_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    // CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
    // Example: CEF:0|Security|threatmanager|1.0|100|worm successfully stopped|10|src=10.0.0.1 dst=2.1.2.2 spt=1232
    Regex::new(
        r"^CEF:(\d+)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(.*)$"
    ).unwrap()
});

static LEEF_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    // LEEF:Version|Vendor|Product|Version|EventID|Extension
    // Example: LEEF:1.0|Microsoft|MSExchange|4.0 SP1|15345|src=192.0.2.0 dst=172.50.123.1
    Regex::new(
        r"^LEEF:(\d+(?:\.\d+)?)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(.*)$"
    ).unwrap()
});

static SD_ELEMENT_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    // Parse structured data elements: [sdid@iana param="value" param2="value2"]
    Regex::new(r#"\[(\S+?)(?:\s+([^\]]+))?\]"#).unwrap()
});

static SD_PARAM_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    // Parse parameters within structured data: param="value"
    Regex::new(r#"(\S+?)="([^"\\]*(?:\\.[^"\\]*)*)""#).unwrap()
});

/// A log parser that can handle multiple formats
pub struct LogParser {
    /// Default source ID to use if not specified
    default_source_id: String,
    /// Whether to attempt auto-detection of format
    auto_detect: bool,
    /// Default format if auto-detection fails
    default_format: LogFormat,
}

impl Default for LogParser {
    fn default() -> Self {
        Self {
            default_source_id: "unknown".to_string(),
            auto_detect: true,
            default_format: LogFormat::Raw,
        }
    }
}

impl LogParser {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_source_id(mut self, source_id: String) -> Self {
        self.default_source_id = source_id;
        self
    }

    pub fn with_default_format(mut self, format: LogFormat) -> Self {
        self.default_format = format;
        self
    }

    pub fn with_auto_detect(mut self, auto_detect: bool) -> Self {
        self.auto_detect = auto_detect;
        self
    }

    /// Parse a raw log message, auto-detecting the format if enabled
    pub fn parse(&self, raw: &str) -> Result<LogEntry> {
        self.parse_with_source(raw, &self.default_source_id)
    }

    /// Parse a raw log message with a specific source ID
    pub fn parse_with_source(&self, raw: &str, source_id: &str) -> Result<LogEntry> {
        let format = if self.auto_detect {
            detect_format(raw)
        } else {
            self.default_format
        };

        self.parse_with_format(raw, source_id, format)
    }

    /// Parse a raw log message with a specific format
    pub fn parse_with_format(&self, raw: &str, source_id: &str, format: LogFormat) -> Result<LogEntry> {
        match format {
            LogFormat::SyslogRfc3164 => parse_rfc3164(raw, source_id),
            LogFormat::SyslogRfc5424 => parse_rfc5424(raw, source_id),
            LogFormat::Cef => parse_cef(raw, source_id),
            LogFormat::Leef => parse_leef(raw, source_id),
            LogFormat::Json => parse_json(raw, source_id),
            LogFormat::Raw | LogFormat::HeroForge | LogFormat::WindowsEvent => {
                parse_raw(raw, source_id)
            }
        }
    }
}

/// Auto-detect the format of a log message
pub fn detect_format(raw: &str) -> LogFormat {
    let trimmed = raw.trim();

    // Check for CEF format
    if trimmed.starts_with("CEF:") {
        return LogFormat::Cef;
    }

    // Check for LEEF format
    if trimmed.starts_with("LEEF:") {
        return LogFormat::Leef;
    }

    // Check for JSON format
    if (trimmed.starts_with('{') && trimmed.ends_with('}'))
        || (trimmed.starts_with('[') && trimmed.ends_with(']'))
    {
        if serde_json::from_str::<Value>(trimmed).is_ok() {
            return LogFormat::Json;
        }
    }

    // Check for syslog format (starts with priority in angle brackets)
    if trimmed.starts_with('<') {
        // Check for RFC 5424 (has version number after priority)
        if RFC5424_PATTERN.is_match(trimmed) {
            return LogFormat::SyslogRfc5424;
        }
        // Check for RFC 3164
        if RFC3164_PATTERN.is_match(trimmed) {
            return LogFormat::SyslogRfc3164;
        }
    }

    // Default to raw
    LogFormat::Raw
}

/// Parse RFC 3164 (BSD) syslog format
fn parse_rfc3164(raw: &str, source_id: &str) -> Result<LogEntry> {
    let caps = RFC3164_PATTERN
        .captures(raw)
        .ok_or_else(|| anyhow!("Failed to parse RFC 3164 syslog message"))?;

    let priority: u8 = caps.get(1).unwrap().as_str().parse()?;
    let (facility, severity) = decode_priority(priority);

    let timestamp_str = caps.get(2).unwrap().as_str();
    let timestamp = parse_bsd_timestamp(timestamp_str)?;

    let hostname = caps.get(3).map(|m| m.as_str().to_string());
    let tag = caps.get(4).map(|m| m.as_str().to_string());
    let pid = caps.get(5).and_then(|m| m.as_str().parse().ok());
    let message = caps.get(6).map(|m| m.as_str().to_string()).unwrap_or_default();

    let mut entry = LogEntry::new(source_id.to_string(), message.clone(), raw.to_string());
    entry.timestamp = timestamp;
    entry.severity = severity;
    entry.facility = Some(facility);
    entry.format = LogFormat::SyslogRfc3164;
    entry.hostname = hostname;
    entry.application = tag;
    entry.pid = pid;
    entry.update_partition_date();

    Ok(entry)
}

/// Parse RFC 5424 structured syslog format
fn parse_rfc5424(raw: &str, source_id: &str) -> Result<LogEntry> {
    let caps = RFC5424_PATTERN
        .captures(raw)
        .ok_or_else(|| anyhow!("Failed to parse RFC 5424 syslog message"))?;

    let priority: u8 = caps.get(1).unwrap().as_str().parse()?;
    let (facility, severity) = decode_priority(priority);

    let _version = caps.get(2).unwrap().as_str();
    let timestamp_str = caps.get(3).unwrap().as_str();
    let timestamp = parse_rfc3339_timestamp(timestamp_str)?;

    let hostname = parse_nilvalue(caps.get(4).map(|m| m.as_str()));
    let app_name = parse_nilvalue(caps.get(5).map(|m| m.as_str()));
    let procid = parse_nilvalue(caps.get(6).map(|m| m.as_str()));
    let msgid = parse_nilvalue(caps.get(7).map(|m| m.as_str()));
    let structured_data_str = caps.get(8).map(|m| m.as_str()).unwrap_or("-");
    let message = caps.get(9).map(|m| m.as_str().to_string()).unwrap_or_default();

    // Parse structured data
    let structured_data = parse_structured_data(structured_data_str);

    let mut entry = LogEntry::new(source_id.to_string(), message.clone(), raw.to_string());
    entry.timestamp = timestamp;
    entry.severity = severity;
    entry.facility = Some(facility);
    entry.format = LogFormat::SyslogRfc5424;
    entry.hostname = hostname;
    entry.application = app_name;
    entry.pid = procid.and_then(|p| p.parse().ok());
    entry.message_id = msgid;
    entry.structured_data = structured_data;
    entry.update_partition_date();

    Ok(entry)
}

/// Parse CEF (Common Event Format)
fn parse_cef(raw: &str, source_id: &str) -> Result<LogEntry> {
    let caps = CEF_PATTERN
        .captures(raw)
        .ok_or_else(|| anyhow!("Failed to parse CEF message"))?;

    let _version = caps.get(1).unwrap().as_str();
    let device_vendor = caps.get(2).unwrap().as_str();
    let device_product = caps.get(3).unwrap().as_str();
    let device_version = caps.get(4).unwrap().as_str();
    let signature_id = caps.get(5).unwrap().as_str();
    let name = caps.get(6).unwrap().as_str();
    let severity_str = caps.get(7).unwrap().as_str();
    let extension = caps.get(8).unwrap().as_str();

    // Parse CEF severity (0-10 scale)
    let severity = parse_cef_severity(severity_str);

    // Parse extension key=value pairs
    let mut structured_data = HashMap::new();
    structured_data.insert(
        "cef.device_vendor".to_string(),
        Value::String(device_vendor.to_string()),
    );
    structured_data.insert(
        "cef.device_product".to_string(),
        Value::String(device_product.to_string()),
    );
    structured_data.insert(
        "cef.device_version".to_string(),
        Value::String(device_version.to_string()),
    );
    structured_data.insert(
        "cef.signature_id".to_string(),
        Value::String(signature_id.to_string()),
    );

    let ext_fields = parse_cef_extension(extension);
    for (k, v) in &ext_fields {
        structured_data.insert(format!("cef.{}", k), Value::String(v.clone()));
    }

    let mut entry = LogEntry::new(source_id.to_string(), name.to_string(), raw.to_string());
    entry.severity = severity;
    entry.format = LogFormat::Cef;
    entry.application = Some(device_product.to_string());
    entry.structured_data = structured_data;

    // Extract common fields from extension
    if let Some(src) = ext_fields.iter().find(|(k, _)| k == "src").map(|(_, v)| v) {
        entry.source_ip = src.parse().ok();
    }
    if let Some(dst) = ext_fields.iter().find(|(k, _)| k == "dst").map(|(_, v)| v) {
        entry.destination_ip = dst.parse().ok();
    }
    if let Some(spt) = ext_fields.iter().find(|(k, _)| k == "spt").map(|(_, v)| v) {
        entry.source_port = spt.parse().ok();
    }
    if let Some(dpt) = ext_fields.iter().find(|(k, _)| k == "dpt").map(|(_, v)| v) {
        entry.destination_port = dpt.parse().ok();
    }
    if let Some(suser) = ext_fields.iter().find(|(k, _)| k == "suser").map(|(_, v)| v) {
        entry.user = Some(suser.clone());
    }
    if let Some(dhost) = ext_fields.iter().find(|(k, _)| k == "dhost").map(|(_, v)| v) {
        entry.hostname = Some(dhost.clone());
    }

    entry.update_partition_date();
    Ok(entry)
}

/// Parse LEEF (Log Event Extended Format)
fn parse_leef(raw: &str, source_id: &str) -> Result<LogEntry> {
    let caps = LEEF_PATTERN
        .captures(raw)
        .ok_or_else(|| anyhow!("Failed to parse LEEF message"))?;

    let _version = caps.get(1).unwrap().as_str();
    let vendor = caps.get(2).unwrap().as_str();
    let product = caps.get(3).unwrap().as_str();
    let product_version = caps.get(4).unwrap().as_str();
    let event_id = caps.get(5).unwrap().as_str();
    let extension = caps.get(6).unwrap().as_str();

    // Parse extension key=value pairs
    let mut structured_data = HashMap::new();
    structured_data.insert(
        "leef.vendor".to_string(),
        Value::String(vendor.to_string()),
    );
    structured_data.insert(
        "leef.product".to_string(),
        Value::String(product.to_string()),
    );
    structured_data.insert(
        "leef.product_version".to_string(),
        Value::String(product_version.to_string()),
    );
    structured_data.insert(
        "leef.event_id".to_string(),
        Value::String(event_id.to_string()),
    );

    let ext_fields = parse_leef_extension(extension);
    for (k, v) in &ext_fields {
        structured_data.insert(format!("leef.{}", k), Value::String(v.clone()));
    }

    // Determine severity from sev field
    let severity = ext_fields
        .iter()
        .find(|(k, _)| k == "sev")
        .map(|(_, v)| parse_leef_severity(v))
        .unwrap_or(SiemSeverity::Info);

    let message = format!("{} - {}", product, event_id);
    let mut entry = LogEntry::new(source_id.to_string(), message, raw.to_string());
    entry.severity = severity;
    entry.format = LogFormat::Leef;
    entry.application = Some(product.to_string());
    entry.structured_data = structured_data;

    // Extract common fields
    if let Some(src) = ext_fields.iter().find(|(k, _)| k == "src").map(|(_, v)| v) {
        entry.source_ip = src.parse().ok();
    }
    if let Some(dst) = ext_fields.iter().find(|(k, _)| k == "dst").map(|(_, v)| v) {
        entry.destination_ip = dst.parse().ok();
    }
    if let Some(src_port) = ext_fields.iter().find(|(k, _)| k == "srcPort").map(|(_, v)| v) {
        entry.source_port = src_port.parse().ok();
    }
    if let Some(dst_port) = ext_fields.iter().find(|(k, _)| k == "dstPort").map(|(_, v)| v) {
        entry.destination_port = dst_port.parse().ok();
    }
    if let Some(usr_name) = ext_fields.iter().find(|(k, _)| k == "usrName").map(|(_, v)| v) {
        entry.user = Some(usr_name.clone());
    }

    entry.update_partition_date();
    Ok(entry)
}

/// Parse JSON log format
fn parse_json(raw: &str, source_id: &str) -> Result<LogEntry> {
    let value: Value = serde_json::from_str(raw)?;

    let obj = value.as_object().ok_or_else(|| anyhow!("Expected JSON object"))?;

    // Extract common fields with various naming conventions
    let message = extract_string_field(obj, &["message", "msg", "log", "text", "body"])
        .unwrap_or_else(|| raw.to_string());

    let timestamp = extract_timestamp_field(obj).unwrap_or_else(Utc::now);

    let severity = extract_severity_field(obj).unwrap_or(SiemSeverity::Info);

    let hostname = extract_string_field(obj, &["hostname", "host", "source_host", "computer"]);
    let application = extract_string_field(obj, &["application", "app", "program", "service", "process"]);
    let user = extract_string_field(obj, &["user", "username", "user_name", "account"]);
    let source_ip = extract_ip_field(obj, &["source_ip", "src_ip", "srcip", "client_ip", "remote_ip"]);
    let destination_ip = extract_ip_field(obj, &["destination_ip", "dst_ip", "dstip", "server_ip"]);
    let source_port = extract_u16_field(obj, &["source_port", "src_port", "srcport", "client_port"]);
    let destination_port = extract_u16_field(obj, &["destination_port", "dst_port", "dstport", "server_port"]);
    let category = extract_string_field(obj, &["category", "event_category", "type", "event_type"]);
    let action = extract_string_field(obj, &["action", "event_action", "operation"]);
    let outcome = extract_string_field(obj, &["outcome", "result", "status"]);

    // Store all fields as structured data
    let mut structured_data = HashMap::new();
    for (k, v) in obj {
        structured_data.insert(k.clone(), v.clone());
    }

    let mut entry = LogEntry::new(source_id.to_string(), message, raw.to_string());
    entry.timestamp = timestamp;
    entry.severity = severity;
    entry.format = LogFormat::Json;
    entry.hostname = hostname;
    entry.application = application;
    entry.user = user;
    entry.source_ip = source_ip;
    entry.destination_ip = destination_ip;
    entry.source_port = source_port;
    entry.destination_port = destination_port;
    entry.category = category;
    entry.action = action;
    entry.outcome = outcome;
    entry.structured_data = structured_data;
    entry.update_partition_date();

    Ok(entry)
}

/// Parse raw/unstructured log format
fn parse_raw(raw: &str, source_id: &str) -> Result<LogEntry> {
    let mut entry = LogEntry::new(source_id.to_string(), raw.to_string(), raw.to_string());
    entry.format = LogFormat::Raw;
    Ok(entry)
}

// Helper functions

/// Decode syslog priority into facility and severity
fn decode_priority(priority: u8) -> (SyslogFacility, SiemSeverity) {
    let facility_code = priority / 8;
    let severity_code = priority % 8;

    let facility = SyslogFacility::from_code(facility_code).unwrap_or(SyslogFacility::User);
    let severity = SiemSeverity::from_syslog_priority(severity_code);

    (facility, severity)
}

/// Parse BSD timestamp (e.g., "Oct 11 22:14:15")
fn parse_bsd_timestamp(s: &str) -> Result<DateTime<Utc>> {
    let current_year = Utc::now().year();
    let with_year = format!("{} {}", s, current_year);

    let naive = NaiveDateTime::parse_from_str(&with_year, "%b %d %H:%M:%S %Y")
        .or_else(|_| NaiveDateTime::parse_from_str(&with_year, "%b  %d %H:%M:%S %Y"))?;

    Ok(Utc.from_utc_datetime(&naive))
}

use chrono::Datelike;

/// Parse RFC 3339 timestamp (e.g., "2003-10-11T22:14:15.003Z")
fn parse_rfc3339_timestamp(s: &str) -> Result<DateTime<Utc>> {
    // Handle NILVALUE
    if s == "-" {
        return Ok(Utc::now());
    }

    DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| anyhow!("Failed to parse RFC 3339 timestamp: {}", e))
}

/// Parse NILVALUE ("-") in RFC 5424
fn parse_nilvalue(s: Option<&str>) -> Option<String> {
    s.filter(|v| *v != "-").map(|v| v.to_string())
}

/// Parse RFC 5424 structured data
fn parse_structured_data(s: &str) -> HashMap<String, Value> {
    let mut result = HashMap::new();

    if s == "-" {
        return result;
    }

    for caps in SD_ELEMENT_PATTERN.captures_iter(s) {
        let sd_id = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        let params_str = caps.get(2).map(|m| m.as_str()).unwrap_or("");

        for param_caps in SD_PARAM_PATTERN.captures_iter(params_str) {
            let param_name = param_caps.get(1).map(|m| m.as_str()).unwrap_or("");
            let param_value = param_caps
                .get(2)
                .map(|m| m.as_str())
                .unwrap_or("")
                .replace("\\\"", "\"")
                .replace("\\\\", "\\")
                .replace("\\]", "]");

            let key = format!("{}.{}", sd_id, param_name);
            result.insert(key, Value::String(param_value));
        }
    }

    result
}

/// Parse CEF severity (0-10 scale) to SiemSeverity
fn parse_cef_severity(s: &str) -> SiemSeverity {
    // CEF severity: 0-3 = Low, 4-6 = Medium, 7-8 = High, 9-10 = Critical
    match s.parse::<u8>().unwrap_or(0) {
        0..=1 => SiemSeverity::Info,
        2..=3 => SiemSeverity::Notice,
        4..=5 => SiemSeverity::Warning,
        6 => SiemSeverity::Error,
        7..=8 => SiemSeverity::Critical,
        9..=10 => SiemSeverity::Emergency,
        _ => SiemSeverity::Info,
    }
}

/// Parse CEF extension field
fn parse_cef_extension(s: &str) -> Vec<(String, String)> {
    let mut result = Vec::new();
    let mut current_key = String::new();
    let mut current_value = String::new();
    let mut in_value = false;

    for part in s.split_whitespace() {
        if let Some(idx) = part.find('=') {
            if in_value {
                // Save previous key-value
                result.push((current_key.clone(), current_value.trim().to_string()));
            }
            current_key = part[..idx].to_string();
            current_value = part[idx + 1..].to_string();
            in_value = true;
        } else if in_value {
            current_value.push(' ');
            current_value.push_str(part);
        }
    }

    if in_value && !current_key.is_empty() {
        result.push((current_key, current_value.trim().to_string()));
    }

    result
}

/// Parse LEEF extension field (tab-separated or key=value)
fn parse_leef_extension(s: &str) -> Vec<(String, String)> {
    let mut result = Vec::new();

    // LEEF uses tab as default delimiter, but can use others
    let parts: Vec<&str> = if s.contains('\t') {
        s.split('\t').collect()
    } else {
        s.split_whitespace().collect()
    };

    for part in parts {
        if let Some(idx) = part.find('=') {
            let key = part[..idx].to_string();
            let value = part[idx + 1..].to_string();
            result.push((key, value));
        }
    }

    result
}

/// Parse LEEF severity to SiemSeverity
fn parse_leef_severity(s: &str) -> SiemSeverity {
    match s.parse::<u8>().unwrap_or(5) {
        0..=1 => SiemSeverity::Info,
        2..=3 => SiemSeverity::Warning,
        4..=6 => SiemSeverity::Error,
        7..=8 => SiemSeverity::Critical,
        9..=10 => SiemSeverity::Emergency,
        _ => SiemSeverity::Info,
    }
}

/// Extract string field from JSON object with multiple possible names
fn extract_string_field(obj: &serde_json::Map<String, Value>, names: &[&str]) -> Option<String> {
    for name in names {
        if let Some(Value::String(s)) = obj.get(*name) {
            return Some(s.clone());
        }
    }
    None
}

/// Extract IP address field from JSON object
fn extract_ip_field(obj: &serde_json::Map<String, Value>, names: &[&str]) -> Option<IpAddr> {
    for name in names {
        if let Some(Value::String(s)) = obj.get(*name) {
            if let Ok(ip) = s.parse() {
                return Some(ip);
            }
        }
    }
    None
}

/// Extract u16 field from JSON object
fn extract_u16_field(obj: &serde_json::Map<String, Value>, names: &[&str]) -> Option<u16> {
    for name in names {
        match obj.get(*name) {
            Some(Value::Number(n)) => {
                if let Some(v) = n.as_u64() {
                    if v <= u16::MAX as u64 {
                        return Some(v as u16);
                    }
                }
            }
            Some(Value::String(s)) => {
                if let Ok(v) = s.parse() {
                    return Some(v);
                }
            }
            _ => {}
        }
    }
    None
}

/// Extract timestamp field from JSON object
fn extract_timestamp_field(obj: &serde_json::Map<String, Value>) -> Option<DateTime<Utc>> {
    let timestamp_fields = [
        "timestamp",
        "@timestamp",
        "time",
        "datetime",
        "date",
        "created_at",
        "event_time",
        "log_time",
    ];

    for name in timestamp_fields {
        if let Some(value) = obj.get(name) {
            match value {
                Value::String(s) => {
                    // Try RFC 3339
                    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
                        return Some(dt.with_timezone(&Utc));
                    }
                    // Try RFC 2822
                    if let Ok(dt) = DateTime::parse_from_rfc2822(s) {
                        return Some(dt.with_timezone(&Utc));
                    }
                    // Try common formats
                    if let Ok(dt) = NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S") {
                        return Some(Utc.from_utc_datetime(&dt));
                    }
                    if let Ok(dt) = NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S") {
                        return Some(Utc.from_utc_datetime(&dt));
                    }
                }
                Value::Number(n) => {
                    // Unix timestamp (seconds or milliseconds)
                    if let Some(ts) = n.as_i64() {
                        // If > year 2100 in seconds, assume milliseconds
                        if ts > 4102444800 {
                            return Utc.timestamp_millis_opt(ts).single();
                        } else {
                            return Utc.timestamp_opt(ts, 0).single();
                        }
                    }
                }
                _ => {}
            }
        }
    }
    None
}

/// Extract severity field from JSON object
fn extract_severity_field(obj: &serde_json::Map<String, Value>) -> Option<SiemSeverity> {
    let severity_fields = ["severity", "level", "log_level", "priority", "sev"];

    for name in severity_fields {
        if let Some(value) = obj.get(name) {
            match value {
                Value::String(s) => {
                    let lower = s.to_lowercase();
                    return Some(match lower.as_str() {
                        "emergency" | "emerg" => SiemSeverity::Emergency,
                        "alert" => SiemSeverity::Alert,
                        "critical" | "crit" | "fatal" => SiemSeverity::Critical,
                        "error" | "err" => SiemSeverity::Error,
                        "warning" | "warn" => SiemSeverity::Warning,
                        "notice" => SiemSeverity::Notice,
                        "info" | "information" => SiemSeverity::Info,
                        "debug" | "trace" => SiemSeverity::Debug,
                        _ => SiemSeverity::Info,
                    });
                }
                Value::Number(n) => {
                    if let Some(level) = n.as_u64() {
                        return Some(SiemSeverity::from_syslog_priority(level as u8));
                    }
                }
                _ => {}
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_cef() {
        let log = "CEF:0|Security|threatmanager|1.0|100|worm successfully stopped|10|src=10.0.0.1 dst=2.1.2.2";
        assert_eq!(detect_format(log), LogFormat::Cef);
    }

    #[test]
    fn test_detect_leef() {
        let log = "LEEF:1.0|Microsoft|MSExchange|4.0|15345|src=192.0.2.0";
        assert_eq!(detect_format(log), LogFormat::Leef);
    }

    #[test]
    fn test_detect_json() {
        let log = r#"{"message": "test", "level": "info"}"#;
        assert_eq!(detect_format(log), LogFormat::Json);
    }

    #[test]
    fn test_detect_rfc5424() {
        let log = "<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut=\"3\"] BOMAn application event";
        assert_eq!(detect_format(log), LogFormat::SyslogRfc5424);
    }

    #[test]
    fn test_detect_rfc3164() {
        let log = "<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick";
        assert_eq!(detect_format(log), LogFormat::SyslogRfc3164);
    }

    #[test]
    fn test_parse_rfc3164() {
        let log = "<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick";
        let parser = LogParser::new().with_source_id("test".to_string());
        let entry = parser.parse(log).unwrap();

        assert_eq!(entry.format, LogFormat::SyslogRfc3164);
        assert_eq!(entry.hostname, Some("mymachine".to_string()));
        assert_eq!(entry.application, Some("su".to_string()));
        assert!(entry.message.contains("su root"));
    }

    #[test]
    fn test_parse_rfc5424() {
        let log = "<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut=\"3\"] BOMAn application event";
        let parser = LogParser::new().with_source_id("test".to_string());
        let entry = parser.parse(log).unwrap();

        assert_eq!(entry.format, LogFormat::SyslogRfc5424);
        assert_eq!(entry.hostname, Some("mymachine.example.com".to_string()));
        assert_eq!(entry.application, Some("evntslog".to_string()));
        assert_eq!(entry.message_id, Some("ID47".to_string()));
        assert!(entry.structured_data.contains_key("exampleSDID@32473.iut"));
    }

    #[test]
    fn test_parse_cef() {
        let log = "CEF:0|Security|threatmanager|1.0|100|worm successfully stopped|10|src=10.0.0.1 dst=2.1.2.2 spt=1232";
        let parser = LogParser::new().with_source_id("test".to_string());
        let entry = parser.parse(log).unwrap();

        assert_eq!(entry.format, LogFormat::Cef);
        assert_eq!(entry.message, "worm successfully stopped");
        assert_eq!(entry.severity, SiemSeverity::Emergency);
        assert_eq!(entry.source_ip, Some("10.0.0.1".parse().unwrap()));
        assert_eq!(entry.destination_ip, Some("2.1.2.2".parse().unwrap()));
        assert_eq!(entry.source_port, Some(1232));
    }

    #[test]
    fn test_parse_leef() {
        let log = "LEEF:1.0|Microsoft|MSExchange|4.0|15345|src=192.0.2.0\tdst=172.50.123.1\tsev=5";
        let parser = LogParser::new().with_source_id("test".to_string());
        let entry = parser.parse(log).unwrap();

        assert_eq!(entry.format, LogFormat::Leef);
        assert_eq!(entry.source_ip, Some("192.0.2.0".parse().unwrap()));
        assert_eq!(entry.destination_ip, Some("172.50.123.1".parse().unwrap()));
    }

    #[test]
    fn test_parse_json() {
        let log = r#"{"message": "User login successful", "level": "info", "user": "admin", "source_ip": "192.168.1.100"}"#;
        let parser = LogParser::new().with_source_id("test".to_string());
        let entry = parser.parse(log).unwrap();

        assert_eq!(entry.format, LogFormat::Json);
        assert_eq!(entry.message, "User login successful");
        assert_eq!(entry.severity, SiemSeverity::Info);
        assert_eq!(entry.user, Some("admin".to_string()));
        assert_eq!(entry.source_ip, Some("192.168.1.100".parse().unwrap()));
    }

    #[test]
    fn test_decode_priority() {
        // Priority 34 = Facility 4 (auth) * 8 + Severity 2 (critical)
        let (facility, severity) = decode_priority(34);
        assert_eq!(facility, SyslogFacility::Auth);
        assert_eq!(severity, SiemSeverity::Critical);

        // Priority 165 = Facility 20 (local4) * 8 + Severity 5 (notice)
        let (facility, severity) = decode_priority(165);
        assert_eq!(facility, SyslogFacility::Local4);
        assert_eq!(severity, SiemSeverity::Notice);
    }

    #[test]
    fn test_cef_severity_mapping() {
        assert_eq!(parse_cef_severity("0"), SiemSeverity::Info);
        assert_eq!(parse_cef_severity("3"), SiemSeverity::Notice);
        assert_eq!(parse_cef_severity("5"), SiemSeverity::Warning);
        assert_eq!(parse_cef_severity("7"), SiemSeverity::Critical);
        assert_eq!(parse_cef_severity("10"), SiemSeverity::Emergency);
    }
}
