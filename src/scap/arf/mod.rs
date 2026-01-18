//! ARF - Asset Reporting Format
//!
//! Implements ARF 1.1 for standardized SCAP result reporting.

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::net::IpAddr;

use crate::scap::{generate_scap_id, sanitize_xml};
use crate::scap::oval::types::{OvalResultType, DefinitionResult};

/// ARF Report document
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArfReport {
    pub id: String,
    pub assets: Vec<ArfAsset>,
    pub report_requests: Vec<ReportRequest>,
    pub reports: Vec<ArfReportContent>,
    pub relationships: Vec<ArfRelationship>,
    pub created_at: DateTime<Utc>,
}

impl Default for ArfReport {
    fn default() -> Self {
        Self {
            id: generate_scap_id(),
            assets: Vec::new(),
            report_requests: Vec::new(),
            reports: Vec::new(),
            relationships: Vec::new(),
            created_at: Utc::now(),
        }
    }
}

impl ArfReport {
    /// Create a new ARF report with the given ID
    pub fn new(id: String) -> Self {
        Self {
            id,
            ..Default::default()
        }
    }

    /// Add an asset to the report
    pub fn add_asset(&mut self, asset: ArfAsset) {
        self.assets.push(asset);
    }

    /// Add XCCDF test results
    pub fn add_xccdf_result(&mut self, rule_results: &[XccdfRuleResult], benchmark_id: &str) {
        let report_id = format!("xccdf-result-{}", generate_scap_id());

        let xccdf_xml = self.generate_xccdf_test_result_xml(rule_results, benchmark_id);

        self.reports.push(ArfReportContent {
            id: report_id.clone(),
            content_type: ArfContentType::XccdfTestResult,
            content: xccdf_xml,
        });

        // Add relationship for each asset
        for asset in &self.assets {
            self.relationships.push(ArfRelationship {
                subject: report_id.clone(),
                rel_type: RelationshipType::IsAbout,
                object: asset.id.clone(),
            });
        }
    }

    /// Add OVAL results
    pub fn add_oval_results(&mut self, definition_results: &[DefinitionResult], definitions_id: &str) {
        let report_id = format!("oval-result-{}", generate_scap_id());

        let oval_xml = self.generate_oval_results_xml(definition_results, definitions_id);

        self.reports.push(ArfReportContent {
            id: report_id.clone(),
            content_type: ArfContentType::OvalResults,
            content: oval_xml,
        });

        // Add relationship for each asset
        for asset in &self.assets {
            self.relationships.push(ArfRelationship {
                subject: report_id.clone(),
                rel_type: RelationshipType::IsAbout,
                object: asset.id.clone(),
            });
        }
    }

    fn generate_xccdf_test_result_xml(&self, rule_results: &[XccdfRuleResult], benchmark_id: &str) -> String {
        let mut xml = String::new();
        xml.push_str(&format!(
            "      <xccdf:TestResult id=\"{}\" test-system=\"HeroForge\" version=\"1.0\" ",
            generate_scap_id()
        ));
        xml.push_str(&format!("start-time=\"{}\" end-time=\"{}\">\n",
            self.created_at.format("%Y-%m-%dT%H:%M:%S"),
            self.created_at.format("%Y-%m-%dT%H:%M:%S")
        ));
        xml.push_str(&format!("        <xccdf:benchmark href=\"{}\" id=\"{}\"/>\n",
            sanitize_xml(benchmark_id), sanitize_xml(benchmark_id)));

        for target in self.assets.iter() {
            if let Some(device) = &target.computing_device {
                if let Some(hostname) = &device.hostname {
                    xml.push_str(&format!("        <xccdf:target>{}</xccdf:target>\n",
                        sanitize_xml(hostname)));
                }
                for conn in &device.connections {
                    if let Some(ip) = &conn.ip_address {
                        xml.push_str(&format!("        <xccdf:target-address>{}</xccdf:target-address>\n", ip));
                    }
                }
            }
        }

        // Write rule results
        for result in rule_results {
            let result_str = match result.result {
                XccdfResult::Pass => "pass",
                XccdfResult::Fail => "fail",
                XccdfResult::Error => "error",
                XccdfResult::Unknown => "unknown",
                XccdfResult::NotApplicable => "notapplicable",
                XccdfResult::NotChecked => "notchecked",
                XccdfResult::NotSelected => "notselected",
                XccdfResult::Informational => "informational",
                XccdfResult::Fixed => "fixed",
            };
            xml.push_str(&format!(
                "        <xccdf:rule-result idref=\"{}\">\n          <xccdf:result>{}</xccdf:result>\n        </xccdf:rule-result>\n",
                sanitize_xml(&result.rule_id), result_str
            ));
        }

        xml.push_str("      </xccdf:TestResult>\n");
        xml
    }

    fn generate_oval_results_xml(&self, definition_results: &[DefinitionResult], definitions_id: &str) -> String {
        let mut xml = String::new();
        xml.push_str("      <oval-res:oval_results xmlns:oval-res=\"http://oval.mitre.org/XMLSchema/oval-results-5\">\n");
        xml.push_str(&format!("        <oval-res:generator>\n          <oval:product_name>HeroForge</oval:product_name>\n          <oval:timestamp>{}</oval:timestamp>\n        </oval-res:generator>\n",
            self.created_at.format("%Y-%m-%dT%H:%M:%S")));

        xml.push_str(&format!("        <oval-res:directives definitions_ref=\"{}\">\n", sanitize_xml(definitions_id)));
        xml.push_str("          <oval-res:definition_true reported=\"true\" content=\"full\"/>\n");
        xml.push_str("          <oval-res:definition_false reported=\"true\" content=\"full\"/>\n");
        xml.push_str("          <oval-res:definition_error reported=\"true\" content=\"full\"/>\n");
        xml.push_str("          <oval-res:definition_unknown reported=\"true\" content=\"full\"/>\n");
        xml.push_str("        </oval-res:directives>\n");

        xml.push_str("        <oval-res:results>\n");
        xml.push_str("          <oval-res:system>\n");

        // Add definitions section
        xml.push_str("            <oval-res:definitions>\n");
        for def_result in definition_results {
            let result_str = match def_result.result {
                OvalResultType::True => "true",
                OvalResultType::False => "false",
                OvalResultType::Error => "error",
                OvalResultType::Unknown => "unknown",
                OvalResultType::NotApplicable => "not applicable",
                OvalResultType::NotEvaluated => "not evaluated",
            };
            xml.push_str(&format!(
                "              <oval-res:definition definition_id=\"{}\" result=\"{}\" version=\"1\"/>\n",
                sanitize_xml(&def_result.definition_id), result_str
            ));
        }
        xml.push_str("            </oval-res:definitions>\n");

        xml.push_str("          </oval-res:system>\n");
        xml.push_str("        </oval-res:results>\n");
        xml.push_str("      </oval-res:oval_results>\n");
        xml
    }
}

/// Asset in ARF report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArfAsset {
    pub id: String,
    pub computing_device: Option<ComputingDevice>,
    pub network: Option<Network>,
    pub software: Option<Software>,
    pub locations: Vec<Location>,
}

impl ArfAsset {
    /// Create a new computing device asset
    pub fn new_computing_device(hostname: &str, fqdn: Option<&str>, ip: Option<IpAddr>) -> Self {
        let connections = if let Some(ip_addr) = ip {
            vec![Connection {
                ip_address: Some(ip_addr),
                mac_address: None,
                subnet_mask: None,
            }]
        } else {
            vec![]
        };

        Self {
            id: format!("asset-{}", generate_scap_id()),
            computing_device: Some(ComputingDevice {
                fqdn: fqdn.map(|s| s.to_string()),
                hostname: Some(hostname.to_string()),
                distinguished_name: None,
                cpe: None,
                connections,
            }),
            network: None,
            software: None,
            locations: vec![],
        }
    }

    /// Create a new software asset
    pub fn new_software(name: &str, version: Option<&str>, cpe: Option<&str>) -> Self {
        Self {
            id: format!("asset-{}", generate_scap_id()),
            computing_device: None,
            network: None,
            software: Some(Software {
                name: Some(name.to_string()),
                vendor: None,
                version: version.map(|s| s.to_string()),
                cpe: cpe.map(|s| s.to_string()),
            }),
            locations: vec![],
        }
    }
}

/// Computing device asset
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComputingDevice {
    pub fqdn: Option<String>,
    pub hostname: Option<String>,
    pub distinguished_name: Option<String>,
    pub cpe: Option<String>,
    pub connections: Vec<Connection>,
}

/// Network connection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Connection {
    pub ip_address: Option<IpAddr>,
    pub mac_address: Option<String>,
    pub subnet_mask: Option<String>,
}

/// Network asset
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Network {
    pub network_name: Option<String>,
    pub ip_range: Option<String>,
}

/// Software asset
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Software {
    pub name: Option<String>,
    pub vendor: Option<String>,
    pub version: Option<String>,
    pub cpe: Option<String>,
}

/// Location
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Location {
    pub name: Option<String>,
    pub address: Option<String>,
}

/// Report request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportRequest {
    pub id: String,
    pub content_type: String,
}

/// ARF report content (embedded XCCDF/OVAL results)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArfReportContent {
    pub id: String,
    pub content_type: ArfContentType,
    pub content: String,
}

/// Content type for ARF reports
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArfContentType {
    XccdfTestResult,
    OvalResults,
    OvalSystemCharacteristics,
    Ocil,
    Custom(String),
}

/// Relationship between assets and reports
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArfRelationship {
    pub subject: String,
    pub rel_type: RelationshipType,
    pub object: String,
}

/// Relationship type
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RelationshipType {
    IsAbout,
    RetrievedFrom,
    CreatedBy,
    HasSource,
}

/// XCCDF Rule result for ARF
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XccdfRuleResult {
    pub rule_id: String,
    pub result: XccdfResult,
    pub message: Option<String>,
    pub check_ref: Option<String>,
}

/// XCCDF result type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum XccdfResult {
    Pass,
    Fail,
    Error,
    Unknown,
    NotApplicable,
    NotChecked,
    NotSelected,
    Informational,
    Fixed,
}

impl From<OvalResultType> for XccdfResult {
    fn from(oval: OvalResultType) -> Self {
        match oval {
            OvalResultType::True => XccdfResult::Pass,
            OvalResultType::False => XccdfResult::Fail,
            OvalResultType::Error => XccdfResult::Error,
            OvalResultType::Unknown => XccdfResult::Unknown,
            OvalResultType::NotApplicable => XccdfResult::NotApplicable,
            OvalResultType::NotEvaluated => XccdfResult::NotChecked,
        }
    }
}

/// ARF Report Generator
pub struct ArfGenerator<'a> {
    pool: &'a SqlitePool,
}

impl<'a> ArfGenerator<'a> {
    pub fn new(pool: &'a SqlitePool) -> Self {
        Self { pool }
    }

    /// Generate ARF XML from execution ID
    pub async fn generate(&self, execution_id: &str) -> Result<String> {
        // Load execution metadata from database
        let execution = self.load_execution(execution_id).await?;

        // Build ARF report
        let mut report = ArfReport::new(format!("arf-{}", execution_id));

        // Add target assets
        for target in &execution.targets {
            let asset = ArfAsset::new_computing_device(
                &target.hostname,
                target.fqdn.as_deref(),
                target.ip_address,
            );
            report.add_asset(asset);
        }

        // Add OVAL results if present
        if !execution.oval_results.is_empty() {
            report.add_oval_results(&execution.oval_results, &execution.content_id);
        }

        // Add XCCDF results if present
        if !execution.xccdf_results.is_empty() {
            report.add_xccdf_result(&execution.xccdf_results, &execution.benchmark_id);
        }

        self.to_xml(&report)
    }

    /// Load execution data from database
    async fn load_execution(&self, execution_id: &str) -> Result<ScapExecution> {
        // Query execution record
        let row = sqlx::query_as::<_, (String, String, String, String, String)>(
            r#"SELECT id, content_id, benchmark_id, status, COALESCE(targets, '[]')
               FROM scap_executions WHERE id = ?"#
        )
        .bind(execution_id)
        .fetch_optional(self.pool)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Execution not found: {}", execution_id))?;

        let targets: Vec<ScapTarget> = serde_json::from_str(&row.4).unwrap_or_default();

        // Query OVAL results
        let oval_rows = sqlx::query_as::<_, (String, String, Option<String>)>(
            r#"SELECT definition_id, result, message FROM scap_oval_results
               WHERE execution_id = ?"#
        )
        .bind(execution_id)
        .fetch_all(self.pool)
        .await
        .unwrap_or_default();

        let oval_results: Vec<DefinitionResult> = oval_rows.iter().map(|r| {
            DefinitionResult {
                definition_id: r.0.clone(),
                result: match r.1.as_str() {
                    "true" => OvalResultType::True,
                    "false" => OvalResultType::False,
                    "error" => OvalResultType::Error,
                    "unknown" => OvalResultType::Unknown,
                    "not applicable" => OvalResultType::NotApplicable,
                    _ => OvalResultType::NotEvaluated,
                },
                criteria_results: None,
                message: r.2.clone(),
                evaluated_at: Utc::now(),
            }
        }).collect();

        // Query XCCDF results
        let xccdf_rows = sqlx::query_as::<_, (String, String, Option<String>)>(
            r#"SELECT rule_id, result, message FROM scap_xccdf_results
               WHERE execution_id = ?"#
        )
        .bind(execution_id)
        .fetch_all(self.pool)
        .await
        .unwrap_or_default();

        let xccdf_results: Vec<XccdfRuleResult> = xccdf_rows.iter().map(|r| {
            XccdfRuleResult {
                rule_id: r.0.clone(),
                result: match r.1.as_str() {
                    "pass" => XccdfResult::Pass,
                    "fail" => XccdfResult::Fail,
                    "error" => XccdfResult::Error,
                    "unknown" => XccdfResult::Unknown,
                    "notapplicable" => XccdfResult::NotApplicable,
                    "notchecked" => XccdfResult::NotChecked,
                    _ => XccdfResult::Unknown,
                },
                message: r.2.clone(),
                check_ref: None,
            }
        }).collect();

        Ok(ScapExecution {
            id: row.0,
            content_id: row.1,
            benchmark_id: row.2,
            status: row.3,
            targets,
            oval_results,
            xccdf_results,
        })
    }

    /// Generate ARF report from OVAL definition results directly
    pub fn generate_from_results(
        &self,
        hostname: &str,
        ip: Option<IpAddr>,
        definition_results: &[DefinitionResult],
        definitions_id: &str,
    ) -> Result<String> {
        let mut report = ArfReport::default();

        // Add target asset
        let asset = ArfAsset::new_computing_device(hostname, None, ip);
        report.add_asset(asset);

        // Add OVAL results
        report.add_oval_results(definition_results, definitions_id);

        self.to_xml(&report)
    }

    /// Convert ARF report to XML
    fn to_xml(&self, report: &ArfReport) -> Result<String> {
        let mut xml = String::new();
        xml.push_str(r#"<?xml version="1.0" encoding="UTF-8"?>"#);
        xml.push('\n');
        xml.push_str(r#"<arf:asset-report-collection "#);
        xml.push_str(r#"xmlns:arf="http://scap.nist.gov/schema/asset-reporting-format/1.1" "#);
        xml.push_str(r#"xmlns:ai="http://scap.nist.gov/schema/asset-identification/1.1" "#);
        xml.push_str(r#"xmlns:oval="http://oval.mitre.org/XMLSchema/oval-common-5" "#);
        xml.push_str(r#"xmlns:oval-res="http://oval.mitre.org/XMLSchema/oval-results-5" "#);
        xml.push_str(r#"xmlns:xccdf="http://checklists.nist.gov/xccdf/1.2">"#);
        xml.push('\n');

        // Report requests
        xml.push_str("  <arf:report-requests>\n");
        for request in &report.report_requests {
            xml.push_str(&format!(
                "    <arf:report-request id=\"{}\">\n      <arf:content type=\"{}\"/>\n    </arf:report-request>\n",
                sanitize_xml(&request.id),
                sanitize_xml(&request.content_type)
            ));
        }
        xml.push_str("  </arf:report-requests>\n");

        // Assets
        xml.push_str("  <arf:assets>\n");
        for asset in &report.assets {
            xml.push_str(&format!("    <arf:asset id=\"{}\">\n", sanitize_xml(&asset.id)));
            if let Some(device) = &asset.computing_device {
                xml.push_str("      <ai:computing-device>\n");
                if let Some(fqdn) = &device.fqdn {
                    xml.push_str(&format!("        <ai:fqdn>{}</ai:fqdn>\n", sanitize_xml(fqdn)));
                }
                if let Some(hostname) = &device.hostname {
                    xml.push_str(&format!("        <ai:hostname>{}</ai:hostname>\n", sanitize_xml(hostname)));
                }
                if let Some(dn) = &device.distinguished_name {
                    xml.push_str(&format!("        <ai:distinguished-name>{}</ai:distinguished-name>\n", sanitize_xml(dn)));
                }
                if let Some(cpe) = &device.cpe {
                    xml.push_str(&format!("        <ai:cpe>{}</ai:cpe>\n", sanitize_xml(cpe)));
                }
                if !device.connections.is_empty() {
                    xml.push_str("        <ai:connections>\n");
                    for conn in &device.connections {
                        xml.push_str("          <ai:connection>\n");
                        if let Some(ip) = &conn.ip_address {
                            match ip {
                                IpAddr::V4(_) => {
                                    xml.push_str(&format!("            <ai:ip-address><ai:ip-v4>{}</ai:ip-v4></ai:ip-address>\n", ip));
                                }
                                IpAddr::V6(_) => {
                                    xml.push_str(&format!("            <ai:ip-address><ai:ip-v6>{}</ai:ip-v6></ai:ip-address>\n", ip));
                                }
                            }
                        }
                        if let Some(mac) = &conn.mac_address {
                            xml.push_str(&format!("            <ai:mac-address>{}</ai:mac-address>\n", sanitize_xml(mac)));
                        }
                        if let Some(mask) = &conn.subnet_mask {
                            xml.push_str(&format!("            <ai:subnet-mask>{}</ai:subnet-mask>\n", sanitize_xml(mask)));
                        }
                        xml.push_str("          </ai:connection>\n");
                    }
                    xml.push_str("        </ai:connections>\n");
                }
                xml.push_str("      </ai:computing-device>\n");
            }
            if let Some(software) = &asset.software {
                xml.push_str("      <ai:software>\n");
                if let Some(name) = &software.name {
                    xml.push_str(&format!("        <ai:name>{}</ai:name>\n", sanitize_xml(name)));
                }
                if let Some(vendor) = &software.vendor {
                    xml.push_str(&format!("        <ai:vendor>{}</ai:vendor>\n", sanitize_xml(vendor)));
                }
                if let Some(version) = &software.version {
                    xml.push_str(&format!("        <ai:version>{}</ai:version>\n", sanitize_xml(version)));
                }
                if let Some(cpe) = &software.cpe {
                    xml.push_str(&format!("        <ai:cpe>{}</ai:cpe>\n", sanitize_xml(cpe)));
                }
                xml.push_str("      </ai:software>\n");
            }
            for location in &asset.locations {
                xml.push_str("      <ai:location>\n");
                if let Some(name) = &location.name {
                    xml.push_str(&format!("        <ai:name>{}</ai:name>\n", sanitize_xml(name)));
                }
                if let Some(address) = &location.address {
                    xml.push_str(&format!("        <ai:address>{}</ai:address>\n", sanitize_xml(address)));
                }
                xml.push_str("      </ai:location>\n");
            }
            xml.push_str("    </arf:asset>\n");
        }
        xml.push_str("  </arf:assets>\n");

        // Reports
        xml.push_str("  <arf:reports>\n");
        for report_content in &report.reports {
            xml.push_str(&format!("    <arf:report id=\"{}\">\n", sanitize_xml(&report_content.id)));
            xml.push_str(&report_content.content);
            xml.push_str("    </arf:report>\n");
        }
        xml.push_str("  </arf:reports>\n");

        // Relationships
        if !report.relationships.is_empty() {
            xml.push_str("  <arf:relationships>\n");
            for rel in &report.relationships {
                let rel_type = match rel.rel_type {
                    RelationshipType::IsAbout => "isAbout",
                    RelationshipType::RetrievedFrom => "retrievedFrom",
                    RelationshipType::CreatedBy => "createdBy",
                    RelationshipType::HasSource => "hasSource",
                };
                xml.push_str(&format!(
                    "    <arf:relationship subject=\"#{}\" type=\"http://scap.nist.gov/specifications/arf/vocabulary/relationships/1.0#{}\">\n      <arf:ref>#{}</arf:ref>\n    </arf:relationship>\n",
                    sanitize_xml(&rel.subject),
                    rel_type,
                    sanitize_xml(&rel.object)
                ));
            }
            xml.push_str("  </arf:relationships>\n");
        }

        xml.push_str("</arf:asset-report-collection>\n");

        Ok(xml)
    }
}

/// Internal structure for loaded SCAP execution
struct ScapExecution {
    id: String,
    content_id: String,
    benchmark_id: String,
    #[allow(dead_code)]
    status: String,
    targets: Vec<ScapTarget>,
    oval_results: Vec<DefinitionResult>,
    xccdf_results: Vec<XccdfRuleResult>,
}

/// Target info from execution
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ScapTarget {
    hostname: String,
    fqdn: Option<String>,
    ip_address: Option<IpAddr>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xccdf_result_from_oval() {
        assert_eq!(XccdfResult::from(OvalResultType::True), XccdfResult::Pass);
        assert_eq!(XccdfResult::from(OvalResultType::False), XccdfResult::Fail);
        assert_eq!(XccdfResult::from(OvalResultType::Error), XccdfResult::Error);
    }

    #[test]
    fn test_arf_asset_creation() {
        let asset = ArfAsset::new_computing_device(
            "server01",
            Some("server01.example.com"),
            Some("192.168.1.100".parse().unwrap()),
        );
        assert!(asset.computing_device.is_some());
        let device = asset.computing_device.unwrap();
        assert_eq!(device.hostname, Some("server01".to_string()));
        assert_eq!(device.fqdn, Some("server01.example.com".to_string()));
        assert_eq!(device.connections.len(), 1);
    }

    #[tokio::test]
    async fn test_arf_report_xml_generation() {
        let mut report = ArfReport::default();
        report.add_asset(ArfAsset::new_computing_device(
            "test-host",
            None,
            Some("10.0.0.1".parse().unwrap()),
        ));

        // Just ensure it doesn't panic - full XML validation would need schema
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        let generator = ArfGenerator::new(&pool);
        let xml = generator.to_xml(&report).unwrap();
        assert!(xml.contains("test-host"));
        assert!(xml.contains("10.0.0.1"));
    }
}
