//! Qualys Scanner Import Parser
//!
//! Parses Qualys XML export files (Asset/Vulnerability Report format).

use anyhow::Result;
use chrono::{DateTime, TimeZone, Utc};
use quick_xml::events::Event;
use quick_xml::Reader;
use std::collections::HashMap;

use super::types::{ImportSource, ImportedFinding, ImportedHost, ImportedScan};
use crate::types::Severity;

/// Qualys file parser
pub struct QualysParser;

impl QualysParser {
    /// Parse a Qualys XML report
    pub fn parse_xml(content: &str) -> Result<ImportedScan> {
        let mut reader = Reader::from_str(content);
        reader.config_mut().trim_text(true);

        let mut scan = ImportedScan {
            source: ImportSource::Qualys,
            scanner_name: "Qualys".to_string(),
            ..Default::default()
        };

        let mut hosts: HashMap<String, ImportedHost> = HashMap::new();
        let mut current_host: Option<String> = None;
        let mut current_finding: Option<ImportedFinding> = None;
        let mut current_element = String::new();
        let mut in_host = false;
        let mut in_vuln = false;
        let mut in_glossary = false;

        // Qualys uses a glossary to define vulnerability details
        let mut vuln_glossary: HashMap<String, VulnDetails> = HashMap::new();
        let mut current_glossary_qid: Option<String> = None;
        let mut current_glossary_vuln: Option<VulnDetails> = None;

        let mut buf = Vec::new();

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(ref e)) => {
                    let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                    current_element = name.clone();

                    match name.as_str() {
                        "SCAN" => {
                            for attr in e.attributes().filter_map(|a| a.ok()) {
                                let key = String::from_utf8_lossy(attr.key.as_ref()).to_string();
                                let value = String::from_utf8_lossy(&attr.value).to_string();
                                match key.as_str() {
                                    "value" => scan.scan_name = Some(value),
                                    _ => {}
                                }
                            }
                        }
                        "GLOSSARY" => {
                            in_glossary = true;
                        }
                        "VULN_DETAILS" if in_glossary => {
                            current_glossary_vuln = Some(VulnDetails::default());
                            for attr in e.attributes().filter_map(|a| a.ok()) {
                                if attr.key.as_ref() == b"id" {
                                    current_glossary_qid = Some(String::from_utf8_lossy(&attr.value).to_string());
                                }
                            }
                        }
                        "HOST" | "IP" => {
                            in_host = true;
                            let mut host = ImportedHost::default();
                            for attr in e.attributes().filter_map(|a| a.ok()) {
                                let key = String::from_utf8_lossy(attr.key.as_ref()).to_string();
                                let value = String::from_utf8_lossy(&attr.value).to_string();
                                match key.as_str() {
                                    "value" | "ip" => {
                                        host.ip = value.clone();
                                        current_host = Some(value.clone());
                                        hosts.insert(value, host.clone());
                                    }
                                    "name" => host.hostname = Some(value),
                                    _ => {}
                                }
                            }
                        }
                        "VULN" | "DETECTION" => {
                            in_vuln = true;
                            let mut finding = ImportedFinding::default();
                            if let Some(ref host_ip) = current_host {
                                finding.host = host_ip.clone();
                            }

                            for attr in e.attributes().filter_map(|a| a.ok()) {
                                let key = String::from_utf8_lossy(attr.key.as_ref()).to_string();
                                let value = String::from_utf8_lossy(&attr.value).to_string();
                                match key.as_str() {
                                    "number" | "qid" => {
                                        finding.plugin_id = Some(value.clone());
                                        // Look up details from glossary
                                        if let Some(details) = vuln_glossary.get(&value) {
                                            finding.title = details.title.clone();
                                            finding.description = details.description.clone();
                                            finding.solution = details.solution.clone();
                                            finding.cvss_score = details.cvss_score;
                                            finding.cvss_vector = details.cvss_vector.clone();
                                            finding.cve_ids = details.cve_ids.clone();
                                            finding.severity = details.severity.clone();
                                        }
                                    }
                                    "severity" => {
                                        finding.severity = map_qualys_severity(value.parse().unwrap_or(0));
                                    }
                                    _ => {}
                                }
                            }
                            current_finding = Some(finding);
                        }
                        _ => {}
                    }
                }
                Ok(Event::End(ref e)) => {
                    let name = String::from_utf8_lossy(e.name().as_ref()).to_string();

                    match name.as_str() {
                        "GLOSSARY" => {
                            in_glossary = false;
                        }
                        "VULN_DETAILS" => {
                            if let (Some(qid), Some(vuln)) = (current_glossary_qid.take(), current_glossary_vuln.take()) {
                                vuln_glossary.insert(qid, vuln);
                            }
                        }
                        "HOST" | "IP" => {
                            in_host = false;
                            current_host = None;
                        }
                        "VULN" | "DETECTION" => {
                            in_vuln = false;
                            if let (Some(finding), Some(ref host_ip)) = (current_finding.take(), &current_host) {
                                if let Some(host) = hosts.get_mut(host_ip) {
                                    match finding.severity {
                                        Severity::Critical => host.critical_count += 1,
                                        Severity::High => host.high_count += 1,
                                        Severity::Medium => host.medium_count += 1,
                                        Severity::Low => host.low_count += 1,
                                    }
                                    host.findings.push(finding);
                                }
                            }
                        }
                        _ => {}
                    }
                    current_element.clear();
                }
                Ok(Event::Text(ref e)) => {
                    let text = String::from_utf8_lossy(e.as_ref()).to_string();
                    if text.trim().is_empty() {
                        continue;
                    }

                    if in_glossary {
                        if let Some(ref mut vuln) = current_glossary_vuln {
                            match current_element.as_str() {
                                "TITLE" => vuln.title = text,
                                "DESCRIPTION" | "CONSEQUENCE" => {
                                    if vuln.description.is_empty() {
                                        vuln.description = text;
                                    } else {
                                        vuln.description.push_str("\n\n");
                                        vuln.description.push_str(&text);
                                    }
                                }
                                "SOLUTION" => vuln.solution = Some(text),
                                "CVSS_BASE" | "CVSS3_BASE" => {
                                    vuln.cvss_score = text.parse().ok();
                                }
                                "CVSS_VECTOR" | "CVSS3_VECTOR" => {
                                    vuln.cvss_vector = Some(text);
                                }
                                "CVE_LIST" | "CVE_ID" => {
                                    for cve in text.split(',') {
                                        let cve = cve.trim();
                                        if !cve.is_empty() {
                                            vuln.cve_ids.push(cve.to_string());
                                        }
                                    }
                                }
                                "SEVERITY" => {
                                    vuln.severity = map_qualys_severity(text.parse().unwrap_or(0));
                                }
                                _ => {}
                            }
                        }
                    } else if in_vuln {
                        if let Some(ref mut finding) = current_finding {
                            match current_element.as_str() {
                                "TITLE" => {
                                    if finding.title.is_empty() {
                                        finding.title = text;
                                    }
                                }
                                "QID" => {
                                    finding.plugin_id = Some(text.clone());
                                    // Look up details from glossary
                                    if let Some(details) = vuln_glossary.get(&text) {
                                        if finding.title.is_empty() {
                                            finding.title = details.title.clone();
                                        }
                                        if finding.description.is_empty() {
                                            finding.description = details.description.clone();
                                        }
                                        if finding.solution.is_none() {
                                            finding.solution = details.solution.clone();
                                        }
                                        if finding.cvss_score.is_none() {
                                            finding.cvss_score = details.cvss_score;
                                        }
                                        if finding.cve_ids.is_empty() {
                                            finding.cve_ids = details.cve_ids.clone();
                                        }
                                    }
                                }
                                "SEVERITY" => {
                                    finding.severity = map_qualys_severity(text.parse().unwrap_or(0));
                                }
                                "PORT" => {
                                    finding.port = text.parse().ok();
                                }
                                "PROTOCOL" => {
                                    finding.protocol = Some(text);
                                }
                                "SERVICE" => {
                                    finding.service = Some(text);
                                }
                                "RESULTS" | "OUTPUT" => {
                                    finding.plugin_output = Some(text);
                                }
                                "FIRST_FOUND_DATETIME" | "FIRST_DETECTED" => {
                                    finding.first_discovered = parse_qualys_datetime(&text);
                                }
                                "LAST_FOUND_DATETIME" | "LAST_DETECTED" => {
                                    finding.last_observed = parse_qualys_datetime(&text);
                                }
                                _ => {}
                            }
                        }
                    } else if in_host {
                        if let Some(ref host_ip) = current_host {
                            if let Some(host) = hosts.get_mut(host_ip) {
                                match current_element.as_str() {
                                    "IP" => {
                                        if host.ip.is_empty() {
                                            host.ip = text;
                                        }
                                    }
                                    "DNS" | "HOSTNAME" => {
                                        host.hostname = Some(text);
                                    }
                                    "NETBIOS" => {
                                        host.netbios_name = Some(text);
                                    }
                                    "OS" | "OPERATING_SYSTEM" => {
                                        host.os = Some(text);
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                }
                Ok(Event::Eof) => break,
                Err(e) => return Err(anyhow::anyhow!("XML parse error: {}", e)),
                _ => {}
            }
            buf.clear();
        }

        // Aggregate counts
        for host in hosts.values() {
            scan.critical_count += host.critical_count;
            scan.high_count += host.high_count;
            scan.medium_count += host.medium_count;
            scan.low_count += host.low_count;
            scan.total_findings += host.findings.len();
        }

        scan.hosts = hosts.into_values().collect();
        Ok(scan)
    }
}

/// Temporary struct for glossary entries
#[derive(Clone)]
struct VulnDetails {
    title: String,
    description: String,
    solution: Option<String>,
    cvss_score: Option<f32>,
    cvss_vector: Option<String>,
    cve_ids: Vec<String>,
    severity: Severity,
}

impl Default for VulnDetails {
    fn default() -> Self {
        Self {
            title: String::new(),
            description: String::new(),
            solution: None,
            cvss_score: None,
            cvss_vector: None,
            cve_ids: Vec::new(),
            severity: Severity::Low, // Default to Low for unknown severity
        }
    }
}

/// Map Qualys severity (1-5) to our Severity enum
/// Qualys: 1 = Minimal, 2 = Medium, 3 = Serious, 4 = Critical, 5 = Urgent
pub fn map_qualys_severity(qualys_severity: u8) -> Severity {
    match qualys_severity {
        5 => Severity::Critical,
        4 => Severity::Critical,
        3 => Severity::High,
        2 => Severity::Medium,
        1 => Severity::Low,
        _ => Severity::Low,
    }
}

/// Map Qualys QID to CVE if known (partial mapping for common vulns)
pub fn map_qualys_qid(qid: u32) -> Option<String> {
    // This is a sample mapping - a full implementation would need a comprehensive QID database
    match qid {
        38173 => Some("CVE-2014-0160".to_string()),  // Heartbleed
        38556 => Some("CVE-2014-6271".to_string()),  // Shellshock
        91475 => Some("CVE-2017-0143".to_string()),  // EternalBlue
        _ => None,
    }
}

/// Parse Qualys datetime format
fn parse_qualys_datetime(datetime_str: &str) -> Option<DateTime<Utc>> {
    // Qualys uses ISO 8601 format: 2024-01-15T10:30:00Z
    DateTime::parse_from_rfc3339(datetime_str)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
        .or_else(|| {
            // Try alternate formats
            // YYYY-MM-DD HH:MM:SS
            let parts: Vec<&str> = datetime_str.split(&['T', ' '][..]).collect();
            if parts.len() >= 2 {
                let date_parts: Vec<&str> = parts[0].split('-').collect();
                let time_parts: Vec<&str> = parts[1].split(':').collect();

                if date_parts.len() == 3 && time_parts.len() >= 2 {
                    let year: i32 = date_parts[0].parse().ok()?;
                    let month: u32 = date_parts[1].parse().ok()?;
                    let day: u32 = date_parts[2].parse().ok()?;
                    let hour: u32 = time_parts[0].parse().ok()?;
                    let min: u32 = time_parts[1].parse().ok()?;
                    let sec: u32 = time_parts.get(2)
                        .and_then(|s| s.trim_end_matches('Z').parse().ok())
                        .unwrap_or(0);

                    return Utc.with_ymd_and_hms(year, month, day, hour, min, sec).single();
                }
            }
            None
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Datelike;

    #[test]
    fn test_map_qualys_severity() {
        assert_eq!(map_qualys_severity(5), Severity::Critical);
        assert_eq!(map_qualys_severity(4), Severity::Critical);
        assert_eq!(map_qualys_severity(3), Severity::High);
        assert_eq!(map_qualys_severity(2), Severity::Medium);
        assert_eq!(map_qualys_severity(1), Severity::Low);
    }

    #[test]
    fn test_parse_qualys_datetime() {
        let dt = parse_qualys_datetime("2024-01-15T10:30:00Z");
        assert!(dt.is_some());
        let datetime = dt.unwrap();
        assert_eq!(datetime.year(), 2024);
        assert_eq!(datetime.month(), 1);
        assert_eq!(datetime.day(), 15);
    }
}
