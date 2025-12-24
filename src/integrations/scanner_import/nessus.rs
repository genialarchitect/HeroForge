//! Nessus Scanner Import Parser
//!
//! Parses Nessus .nessus (XML) and CSV export files.

use anyhow::{Context, Result};
use chrono::{DateTime, TimeZone, Utc};
use quick_xml::events::Event;
use quick_xml::Reader;
use std::collections::HashMap;
use std::io::BufRead;

use super::types::{ImportSource, ImportedFinding, ImportedHost, ImportedScan};
use crate::types::Severity;

/// Nessus file parser
pub struct NessusParser;

impl NessusParser {
    /// Parse a Nessus XML (.nessus) file
    pub fn parse_xml(content: &str) -> Result<ImportedScan> {
        let mut reader = Reader::from_str(content);
        reader.config_mut().trim_text(true);

        let mut scan = ImportedScan {
            source: ImportSource::Nessus,
            scanner_name: "Nessus".to_string(),
            ..Default::default()
        };

        let mut hosts: HashMap<String, ImportedHost> = HashMap::new();
        let mut current_host: Option<String> = None;
        let mut current_finding: Option<ImportedFinding> = None;
        let mut current_element = String::new();
        let mut in_report_host = false;
        let mut buf = Vec::new();

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(ref e)) => {
                    let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                    current_element = name.clone();

                    match name.as_str() {
                        "Policy" => {}
                        "Report" => {
                            for attr in e.attributes().filter_map(|a| a.ok()) {
                                if attr.key.as_ref() == b"name" {
                                    scan.scan_name = Some(String::from_utf8_lossy(&attr.value).to_string());
                                }
                            }
                        }
                        "ReportHost" => {
                            in_report_host = true;
                            let mut host = ImportedHost::default();
                            for attr in e.attributes().filter_map(|a| a.ok()) {
                                if attr.key.as_ref() == b"name" {
                                    let host_name = String::from_utf8_lossy(&attr.value).to_string();
                                    host.ip = host_name.clone();
                                    current_host = Some(host_name.clone());
                                    hosts.insert(host_name, host);
                                    break;
                                }
                            }
                        }
                        "ReportItem" if in_report_host => {
                            let mut finding = ImportedFinding::default();
                            if let Some(ref host_ip) = current_host {
                                finding.host = host_ip.clone();
                            }

                            for attr in e.attributes().filter_map(|a| a.ok()) {
                                let key = String::from_utf8_lossy(attr.key.as_ref()).to_string();
                                let value = String::from_utf8_lossy(&attr.value).to_string();

                                match key.as_str() {
                                    "port" => finding.port = value.parse().ok(),
                                    "protocol" => finding.protocol = Some(value),
                                    "svc_name" => finding.service = Some(value),
                                    "pluginID" => finding.plugin_id = Some(value),
                                    "pluginName" => finding.title = value,
                                    "severity" => {
                                        finding.severity = match value.as_str() {
                                            "4" => Severity::Critical,
                                            "3" => Severity::High,
                                            "2" => Severity::Medium,
                                            "1" => Severity::Low,
                                            _ => Severity::Low,
                                        };
                                    }
                                    "pluginFamily" => {}
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
                        "ReportHost" => {
                            in_report_host = false;
                            current_host = None;
                        }
                        "ReportItem" => {
                            if let (Some(finding), Some(ref host_ip)) = (current_finding.take(), &current_host) {
                                if let Some(host) = hosts.get_mut(host_ip) {
                                    // Update host counts
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

                    if let Some(ref mut finding) = current_finding {
                        match current_element.as_str() {
                            "description" => finding.description = text,
                            "solution" => finding.solution = Some(text),
                            "plugin_output" => finding.plugin_output = Some(text),
                            "cvss_base_score" | "cvss3_base_score" => {
                                if finding.cvss_score.is_none() {
                                    finding.cvss_score = text.parse().ok();
                                }
                            }
                            "cvss_vector" | "cvss3_vector" => {
                                if finding.cvss_vector.is_none() {
                                    finding.cvss_vector = Some(text);
                                }
                            }
                            "cve" => {
                                finding.cve_ids.push(text);
                            }
                            "cwe" => {
                                finding.cwe_ids.push(text);
                            }
                            "see_also" => {
                                for url in text.lines() {
                                    let url = url.trim();
                                    if !url.is_empty() {
                                        finding.see_also.push(url.to_string());
                                    }
                                }
                            }
                            "exploit_available" => {
                                finding.exploit_available = text.to_lowercase() == "true";
                            }
                            "exploitability_ease" => {
                                finding.exploitability_ease = Some(text);
                            }
                            "patch_publication_date" => {
                                finding.patch_published = parse_nessus_date(&text);
                            }
                            "plugin_publication_date" => {
                                if finding.first_discovered.is_none() {
                                    finding.first_discovered = parse_nessus_date(&text);
                                }
                            }
                            _ => {}
                        }
                    } else if in_report_host {
                        // Host-level tags
                        if let Some(ref host_ip) = current_host {
                            if let Some(host) = hosts.get_mut(host_ip) {
                                match current_element.as_str() {
                                    "tag" => {
                                        // Parse host properties
                                    }
                                    "HostProperties" => {}
                                    _ => {}
                                }
                            }
                        }
                    }
                }
                Ok(Event::Empty(ref e)) => {
                    let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                    if name == "tag" && in_report_host {
                        if let Some(ref host_ip) = current_host {
                            if let Some(host) = hosts.get_mut(host_ip) {
                                let mut tag_name = String::new();
                                let mut tag_value = String::new();

                                for attr in e.attributes().filter_map(|a| a.ok()) {
                                    let key = String::from_utf8_lossy(attr.key.as_ref()).to_string();
                                    let value = String::from_utf8_lossy(&attr.value).to_string();
                                    if key == "name" {
                                        tag_name = value;
                                    }
                                }

                                match tag_name.as_str() {
                                    "host-ip" => host.ip = tag_value,
                                    "host-fqdn" => host.fqdn = Some(tag_value),
                                    "hostname" => host.hostname = Some(tag_value),
                                    "mac-address" => host.mac_address = Some(tag_value),
                                    "operating-system" => host.os = Some(tag_value),
                                    "netbios-name" => host.netbios_name = Some(tag_value),
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

    /// Parse a Nessus CSV export file
    pub fn parse_csv<R: BufRead>(reader: R) -> Result<ImportedScan> {
        let mut rdr = csv::ReaderBuilder::new()
            .has_headers(true)
            .flexible(true)
            .from_reader(reader);

        let headers = rdr.headers()
            .context("Failed to read CSV headers")?
            .clone();

        let mut scan = ImportedScan {
            source: ImportSource::Nessus,
            scanner_name: "Nessus".to_string(),
            ..Default::default()
        };

        let mut hosts: HashMap<String, ImportedHost> = HashMap::new();

        for result in rdr.records() {
            let record = result.context("Failed to read CSV record")?;

            let get_field = |name: &str| -> Option<String> {
                headers.iter()
                    .position(|h| h.eq_ignore_ascii_case(name))
                    .and_then(|idx| record.get(idx))
                    .map(|s| s.to_string())
                    .filter(|s| !s.is_empty())
            };

            let host_ip = get_field("Host").or_else(|| get_field("IP"))
                .unwrap_or_default();

            if host_ip.is_empty() {
                continue;
            }

            let severity_str = get_field("Risk").or_else(|| get_field("Severity"))
                .unwrap_or_default();

            let severity = match severity_str.to_lowercase().as_str() {
                "critical" => Severity::Critical,
                "high" => Severity::High,
                "medium" => Severity::Medium,
                "low" | "none" | "info" => Severity::Low,
                _ => Severity::Low,
            };

            let finding = ImportedFinding {
                plugin_id: get_field("Plugin ID"),
                title: get_field("Name").or_else(|| get_field("Plugin Name")).unwrap_or_default(),
                description: get_field("Description").or_else(|| get_field("Synopsis")).unwrap_or_default(),
                severity,
                cvss_score: get_field("CVSS v3.0 Base Score")
                    .or_else(|| get_field("CVSS v2.0 Base Score"))
                    .and_then(|s| s.parse().ok()),
                cvss_vector: get_field("CVSS v3.0 Vector")
                    .or_else(|| get_field("CVSS v2.0 Vector")),
                cve_ids: get_field("CVE")
                    .map(|s| s.split(',').map(|c| c.trim().to_string()).collect())
                    .unwrap_or_default(),
                cwe_ids: Vec::new(),
                host: host_ip.clone(),
                port: get_field("Port").and_then(|s| s.parse().ok()),
                protocol: get_field("Protocol"),
                service: get_field("Service"),
                solution: get_field("Solution"),
                see_also: get_field("See Also")
                    .map(|s| s.lines().map(|l| l.trim().to_string()).collect())
                    .unwrap_or_default(),
                plugin_output: get_field("Plugin Output"),
                first_discovered: None,
                last_observed: None,
                exploit_available: get_field("Exploit?")
                    .map(|s| s.to_lowercase() == "yes" || s.to_lowercase() == "true")
                    .unwrap_or(false),
                exploitability_ease: get_field("Exploit Ease"),
                patch_published: None,
            };

            let host = hosts.entry(host_ip.clone()).or_insert_with(|| {
                ImportedHost {
                    ip: host_ip,
                    hostname: get_field("NetBIOS Name").or_else(|| get_field("DNS Name")),
                    fqdn: get_field("DNS Name"),
                    os: get_field("OS"),
                    ..Default::default()
                }
            });

            match finding.severity {
                Severity::Critical => host.critical_count += 1,
                Severity::High => host.high_count += 1,
                Severity::Medium => host.medium_count += 1,
                Severity::Low => host.low_count += 1,
            }

            host.findings.push(finding);
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

/// Parse Nessus date format (YYYY/MM/DD)
fn parse_nessus_date(date_str: &str) -> Option<DateTime<Utc>> {
    let parts: Vec<&str> = date_str.split('/').collect();
    if parts.len() == 3 {
        let year: i32 = parts[0].parse().ok()?;
        let month: u32 = parts[1].parse().ok()?;
        let day: u32 = parts[2].parse().ok()?;
        Utc.with_ymd_and_hms(year, month, day, 0, 0, 0).single()
    } else {
        None
    }
}

/// Map Nessus severity (0-4) to our Severity enum
pub fn map_nessus_severity(nessus_severity: u8) -> Severity {
    match nessus_severity {
        4 => Severity::Critical,
        3 => Severity::High,
        2 => Severity::Medium,
        1 => Severity::Low,
        _ => Severity::Low,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Datelike;

    #[test]
    fn test_parse_nessus_date() {
        let date = parse_nessus_date("2024/01/15");
        assert!(date.is_some());
        let dt = date.unwrap();
        assert_eq!(dt.year(), 2024);
        assert_eq!(dt.month(), 1);
        assert_eq!(dt.day(), 15);
    }

    #[test]
    fn test_map_severity() {
        assert_eq!(map_nessus_severity(4), Severity::Critical);
        assert_eq!(map_nessus_severity(3), Severity::High);
        assert_eq!(map_nessus_severity(2), Severity::Medium);
        assert_eq!(map_nessus_severity(1), Severity::Low);
        assert_eq!(map_nessus_severity(0), Severity::Low);
    }
}
