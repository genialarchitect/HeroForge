// Nuclei Output Parser
// Parse JSON output from Nuclei scans

#![allow(dead_code)]

use super::types::*;
use chrono::Utc;
use log::debug;
use serde::Deserialize;
use uuid::Uuid;

/// Raw Nuclei JSON output format
#[derive(Debug, Deserialize)]
struct NucleiJsonOutput {
    #[serde(rename = "template-id")]
    template_id: Option<String>,
    #[serde(rename = "templateID")]
    template_id_alt: Option<String>,

    #[serde(rename = "template-name")]
    template_name: Option<String>,
    #[serde(rename = "name")]
    name_alt: Option<String>,

    #[serde(rename = "type")]
    check_type: Option<String>,

    host: Option<String>,

    #[serde(rename = "matched-at")]
    matched_at: Option<String>,
    #[serde(rename = "matched")]
    matched_alt: Option<String>,

    #[serde(rename = "extracted-results")]
    extracted_results: Option<Vec<String>>,

    info: Option<NucleiInfoBlock>,

    request: Option<String>,
    response: Option<String>,

    #[serde(rename = "curl-command")]
    curl_command: Option<String>,

    ip: Option<String>,

    #[serde(rename = "matcher-name")]
    matcher_name: Option<String>,

    timestamp: Option<String>,
}

/// Nuclei info block in JSON output
#[derive(Debug, Deserialize)]
struct NucleiInfoBlock {
    name: Option<String>,
    author: Option<StringOrVec>,
    tags: Option<StringOrVec>,
    description: Option<String>,
    reference: Option<StringOrVec>,
    severity: Option<String>,
    classification: Option<NucleiClassificationBlock>,
}

/// Classification block in Nuclei output
#[derive(Debug, Deserialize)]
struct NucleiClassificationBlock {
    #[serde(rename = "cve-id")]
    cve_id: Option<StringOrVec>,
    #[serde(rename = "cwe-id")]
    cwe_id: Option<StringOrVec>,
    #[serde(rename = "cvss-score")]
    cvss_score: Option<f32>,
}

/// Helper type for fields that can be string or array
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum StringOrVec {
    String(String),
    Vec(Vec<String>),
}

impl StringOrVec {
    fn to_vec(&self) -> Vec<String> {
        match self {
            StringOrVec::String(s) => vec![s.clone()],
            StringOrVec::Vec(v) => v.clone(),
        }
    }

    fn first(&self) -> Option<String> {
        match self {
            StringOrVec::String(s) => Some(s.clone()),
            StringOrVec::Vec(v) => v.first().cloned(),
        }
    }
}

/// Parse a single line of Nuclei JSON output
pub fn parse_nuclei_output(line: &str) -> Option<NucleiResult> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }

    // Try to parse as JSON
    let output: NucleiJsonOutput = match serde_json::from_str(line) {
        Ok(o) => o,
        Err(e) => {
            // Not all lines are JSON (progress output, etc.)
            debug!("Failed to parse nuclei JSON line: {} (line: {})", e, line);
            return None;
        }
    };

    // Extract template ID
    let template_id = output
        .template_id
        .or(output.template_id_alt)
        .unwrap_or_else(|| "unknown".to_string());

    // Extract template name (from info block or top-level)
    let template_name = output
        .info
        .as_ref()
        .and_then(|i| i.name.clone())
        .or(output.template_name)
        .or(output.name_alt)
        .unwrap_or_else(|| template_id.clone());

    // Extract severity
    let severity = output
        .info
        .as_ref()
        .and_then(|i| i.severity.as_ref())
        .map(|s| NucleiSeverity::from(s.as_str()))
        .unwrap_or(NucleiSeverity::Unknown);

    // Extract host
    let host = output.host.unwrap_or_else(|| "unknown".to_string());

    // Extract matched URL
    let matched_at = output
        .matched_at
        .or(output.matched_alt)
        .unwrap_or_else(|| host.clone());

    // Extract check type
    let check_type = output.check_type.unwrap_or_else(|| "http".to_string());

    // Extract CVE ID if available
    let cve_id = output
        .info
        .as_ref()
        .and_then(|i| i.classification.as_ref())
        .and_then(|c| c.cve_id.as_ref())
        .and_then(|c| c.first());

    // Extract results
    let extracted_results = output.extracted_results.unwrap_or_default();

    Some(NucleiResult {
        id: Uuid::new_v4().to_string(),
        template_id,
        template_name,
        severity,
        host,
        matched_at,
        check_type,
        extracted_results,
        request: output.request,
        response: truncate_response(output.response),
        curl_command: output.curl_command,
        ip: output.ip,
        matcher_name: output.matcher_name,
        cve_id,
        timestamp: Utc::now(),
    })
}

/// Truncate response to avoid storing huge responses
fn truncate_response(response: Option<String>) -> Option<String> {
    const MAX_RESPONSE_SIZE: usize = 10_000;

    response.map(|r| {
        if r.len() > MAX_RESPONSE_SIZE {
            format!("{}... [truncated {} bytes]", &r[..MAX_RESPONSE_SIZE], r.len() - MAX_RESPONSE_SIZE)
        } else {
            r
        }
    })
}

/// Parse multiple lines of Nuclei output
pub fn parse_nuclei_results(output: &str) -> Vec<NucleiResult> {
    output
        .lines()
        .filter_map(parse_nuclei_output)
        .collect()
}

/// Convert a NucleiResult to a HeroForge Vulnerability
pub fn result_to_vulnerability(result: &NucleiResult) -> crate::types::Vulnerability {
    use crate::types::{Severity, Vulnerability};

    let severity = match result.severity {
        NucleiSeverity::Critical => Severity::Critical,
        NucleiSeverity::High => Severity::High,
        NucleiSeverity::Medium => Severity::Medium,
        NucleiSeverity::Low => Severity::Low,
        NucleiSeverity::Info => Severity::Low, // Map Info to Low
        NucleiSeverity::Unknown => Severity::Low,
    };

    let mut description = format!(
        "Nuclei template '{}' matched at {}",
        result.template_id, result.matched_at
    );

    if !result.extracted_results.is_empty() {
        description.push_str("\n\nExtracted data:\n");
        for extracted in &result.extracted_results {
            description.push_str(&format!("- {}\n", extracted));
        }
    }

    if let Some(ref curl) = result.curl_command {
        description.push_str(&format!("\n\nReproduction command:\n{}", curl));
    }

    Vulnerability {
        cve_id: result.cve_id.clone(),
        title: result.template_name.clone(),
        description,
        severity,
        affected_service: Some(format!("{}:{}", result.check_type, result.host)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_nuclei_json() {
        let json = r#"{"template-id":"cve-2021-44228","template-name":"Log4j RCE","type":"http","host":"http://example.com","matched-at":"http://example.com/vulnerable","info":{"name":"Log4j RCE (CVE-2021-44228)","severity":"critical","classification":{"cve-id":"CVE-2021-44228"}}}"#;

        let result = parse_nuclei_output(json).unwrap();

        assert_eq!(result.template_id, "cve-2021-44228");
        assert_eq!(result.severity, NucleiSeverity::Critical);
        assert_eq!(result.cve_id, Some("CVE-2021-44228".to_string()));
    }

    #[test]
    fn test_parse_invalid_json() {
        let result = parse_nuclei_output("not json at all");
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_empty_line() {
        let result = parse_nuclei_output("");
        assert!(result.is_none());
    }

    #[test]
    fn test_truncate_response() {
        let short = truncate_response(Some("short".to_string()));
        assert_eq!(short, Some("short".to_string()));

        let long = "x".repeat(20_000);
        let truncated = truncate_response(Some(long));
        assert!(truncated.unwrap().contains("[truncated"));
    }

    #[test]
    fn test_severity_parsing() {
        let json = r#"{"template-id":"test","host":"test.com","info":{"severity":"high"}}"#;
        let result = parse_nuclei_output(json).unwrap();
        assert_eq!(result.severity, NucleiSeverity::High);
    }
}
