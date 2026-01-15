//! Topology Import Module
//!
//! Provides parsers for importing network topology data from external scanning tools
//! into the cATO Network Topology Map.
//!
//! Supported tools:
//! - Nmap (XML and grepable formats)
//! - Masscan (JSON format)
//! - Netcat (log format)
//! - Rustscan (multiple formats)

pub mod masscan;
pub mod netcat;
pub mod nmap_grepable;
pub mod nmap_xml;
pub mod rustscan;
pub mod types;

pub use types::*;

use anyhow::{anyhow, Result};

/// Auto-detect the format of the input content
pub fn detect_format(content: &str, filename: &str) -> Option<TopologyImportSource> {
    let filename_lower = filename.to_lowercase();
    let content_trimmed = content.trim();

    // Check file extension first
    if filename_lower.ends_with(".gnmap") || filename_lower.ends_with(".greppable") {
        return Some(TopologyImportSource::NmapGrepable);
    }

    // Check content signatures
    if content_trimmed.starts_with("<?xml") || content_trimmed.starts_with("<nmaprun") {
        return Some(TopologyImportSource::NmapXml);
    }

    // Check for masscan JSON format
    if (content_trimmed.starts_with('[') || content_trimmed.starts_with('{'))
        && content.contains("\"ip\"")
        && (content.contains("\"ports\"") || content.contains("\"port\""))
    {
        // Could be masscan or rustscan JSON
        if content.contains("\"proto\"") || content.contains("\"timestamp\"") {
            return Some(TopologyImportSource::MasscanJson);
        }
        return Some(TopologyImportSource::Rustscan);
    }

    // Check for nmap grepable format
    if content.contains("Host:") && content.contains("Ports:") {
        return Some(TopologyImportSource::NmapGrepable);
    }

    // Check for rustscan greppable format
    if content.contains(" -> [") {
        return Some(TopologyImportSource::Rustscan);
    }

    // Check for rustscan Open format
    if content.lines().any(|l| l.trim().starts_with("Open ")) {
        return Some(TopologyImportSource::Rustscan);
    }

    // Check for netcat output patterns
    if content.contains("Connection to") && content.contains("succeeded") {
        return Some(TopologyImportSource::NetcatLog);
    }

    if content.contains("nc: connect to") {
        return Some(TopologyImportSource::NetcatLog);
    }

    // Fallback: check for common patterns
    if content.lines().any(|l| {
        let l = l.trim();
        l.contains(":") && l.contains("open")
    }) {
        return Some(TopologyImportSource::NetcatLog);
    }

    // Default based on extension
    if filename_lower.ends_with(".xml") {
        return Some(TopologyImportSource::NmapXml);
    }
    if filename_lower.ends_with(".json") {
        return Some(TopologyImportSource::MasscanJson);
    }
    if filename_lower.ends_with(".txt") || filename_lower.ends_with(".log") {
        // Could be netcat or rustscan - try netcat first
        return Some(TopologyImportSource::NetcatLog);
    }

    None
}

/// Parse content using the specified format
pub fn parse(content: &str, source: TopologyImportSource) -> Result<TopologyImportResult> {
    match source {
        TopologyImportSource::NmapXml => nmap_xml::NmapXmlParser::parse(content),
        TopologyImportSource::NmapGrepable => nmap_grepable::NmapGrepableParser::parse(content),
        TopologyImportSource::MasscanJson => masscan::MasscanParser::parse(content),
        TopologyImportSource::NetcatLog => netcat::NetcatParser::parse(content),
        TopologyImportSource::Rustscan => rustscan::RustscanParser::parse(content),
    }
}

/// Auto-detect format and parse content
pub fn auto_parse(content: &str, filename: &str) -> Result<TopologyImportResult> {
    let source = detect_format(content, filename)
        .ok_or_else(|| anyhow!("Could not detect file format"))?;

    parse(content, source)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_nmap_xml() {
        let content = r#"<?xml version="1.0"?><nmaprun></nmaprun>"#;
        assert_eq!(detect_format(content, "scan.xml"), Some(TopologyImportSource::NmapXml));
    }

    #[test]
    fn test_detect_nmap_grepable() {
        let content = r#"Host: 192.168.1.1 ()    Ports: 22/open/tcp//ssh///"#;
        assert_eq!(detect_format(content, "scan.gnmap"), Some(TopologyImportSource::NmapGrepable));
    }

    #[test]
    fn test_detect_masscan_json() {
        let content = r#"[{"ip": "192.168.1.1", "timestamp": "123", "ports": [{"port": 22, "proto": "tcp"}]}]"#;
        assert_eq!(detect_format(content, "scan.json"), Some(TopologyImportSource::MasscanJson));
    }

    #[test]
    fn test_detect_netcat() {
        let content = r#"Connection to 192.168.1.1 22 port [tcp/ssh] succeeded!"#;
        assert_eq!(detect_format(content, "scan.txt"), Some(TopologyImportSource::NetcatLog));
    }

    #[test]
    fn test_detect_rustscan_greppable() {
        let content = r#"192.168.1.1 -> [22,80,443]"#;
        assert_eq!(detect_format(content, "scan.txt"), Some(TopologyImportSource::Rustscan));
    }

    #[test]
    fn test_detect_rustscan_open() {
        let content = r#"Open 192.168.1.1:22"#;
        assert_eq!(detect_format(content, "scan.txt"), Some(TopologyImportSource::Rustscan));
    }
}
