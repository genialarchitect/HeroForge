//! ARF (Asset Reporting Format) Generator
//!
//! Generates SCAP 1.3 ARF XML reports for compliance documentation
//! and federal audit requirements.

use anyhow::Result;
use chrono::{DateTime, Utc};
use quick_xml::{Writer, events::{Event, BytesDecl, BytesEnd, BytesStart, BytesText}};
use std::io::Cursor;
use uuid::Uuid;

use crate::scap::xccdf::{XccdfResultType, RuleResult as XccdfRuleResult};

/// XCCDF test result container for ARF generation
#[derive(Debug, Clone)]
pub struct XccdfResult {
    pub benchmark_id: String,
    pub profile_id: String,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub rule_results: Vec<RuleResult>,
    pub score: f64,
}

/// Simplified rule result for ARF
#[derive(Debug, Clone)]
pub struct RuleResult {
    pub rule_id: String,
    pub result: ResultValue,
    pub message: Option<String>,
    pub time: DateTime<Utc>,
}

/// Result value enum for ARF (simplified from XccdfResultType)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResultValue {
    Pass,
    Fail,
    Error,
    Unknown,
    NotApplicable,
    NotChecked,
    NotSelected,
    InformationalValue,
    Fixed,
}

impl From<XccdfResultType> for ResultValue {
    fn from(xccdf: XccdfResultType) -> Self {
        match xccdf {
            XccdfResultType::Pass => ResultValue::Pass,
            XccdfResultType::Fail => ResultValue::Fail,
            XccdfResultType::Error => ResultValue::Error,
            XccdfResultType::Unknown => ResultValue::Unknown,
            XccdfResultType::NotApplicable => ResultValue::NotApplicable,
            XccdfResultType::NotChecked => ResultValue::NotChecked,
            XccdfResultType::NotSelected => ResultValue::NotSelected,
            XccdfResultType::Informational => ResultValue::InformationalValue,
            XccdfResultType::Fixed => ResultValue::Fixed,
        }
    }
}

/// ARF document structure
#[derive(Debug, Clone)]
pub struct ArfDocument {
    pub report_id: String,
    pub assets: Vec<ArfAsset>,
    pub reports: Vec<ArfReport>,
    pub generated_at: DateTime<Utc>,
}

/// ARF asset information
#[derive(Debug, Clone)]
pub struct ArfAsset {
    pub asset_id: String,
    pub fqdn: Option<String>,
    pub ip_addresses: Vec<String>,
    pub mac_addresses: Vec<String>,
    pub hostname: String,
    pub os_name: Option<String>,
    pub os_version: Option<String>,
}

/// ARF report content
#[derive(Debug, Clone)]
pub struct ArfReport {
    pub report_id: String,
    pub asset_ref: String,
    pub content: ArfReportContent,
}

/// Report content type
#[derive(Debug, Clone)]
pub enum ArfReportContent {
    XccdfTestResult(XccdfTestResultContent),
    OvalResults(OvalResultsContent),
}

/// XCCDF test result content
#[derive(Debug, Clone)]
pub struct XccdfTestResultContent {
    pub benchmark_id: String,
    pub profile_id: String,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub rule_results: Vec<ArfRuleResult>,
    pub score: f64,
    pub score_maximum: f64,
}

/// Individual rule result
#[derive(Debug, Clone)]
pub struct ArfRuleResult {
    pub rule_id: String,
    pub result: String,
    pub message: Option<String>,
    pub check_content_ref: Option<String>,
}

/// OVAL results content
#[derive(Debug, Clone)]
pub struct OvalResultsContent {
    pub definition_results: Vec<OvalDefinitionResult>,
}

/// OVAL definition result
#[derive(Debug, Clone)]
pub struct OvalDefinitionResult {
    pub definition_id: String,
    pub result: String,
}

/// ARF XML namespaces
const ARF_NS: &str = "http://scap.nist.gov/schema/asset-reporting-format/1.1";
const AI_NS: &str = "http://scap.nist.gov/schema/asset-identification/1.1";
const XCCDF_NS: &str = "http://checklists.nist.gov/xccdf/1.2";
const OVAL_RESULTS_NS: &str = "http://oval.mitre.org/XMLSchema/oval-results-5";
const CORE_NS: &str = "http://scap.nist.gov/schema/reporting-core/1.1";

/// ARF Generator
pub struct ArfGenerator;

impl ArfGenerator {
    /// Generate ARF XML from document
    pub fn generate(doc: &ArfDocument) -> Result<String> {
        let mut buffer = Cursor::new(Vec::new());
        let mut writer = Writer::new_with_indent(&mut buffer, b' ', 2);

        // XML declaration
        writer.write_event(Event::Decl(BytesDecl::new("1.0", Some("UTF-8"), None)))?;

        // Root element with namespaces
        let mut root = BytesStart::new("arf:asset-report-collection");
        root.push_attribute(("xmlns:arf", ARF_NS));
        root.push_attribute(("xmlns:ai", AI_NS));
        root.push_attribute(("xmlns:xccdf", XCCDF_NS));
        root.push_attribute(("xmlns:oval-results", OVAL_RESULTS_NS));
        root.push_attribute(("xmlns:core", CORE_NS));
        writer.write_event(Event::Start(root))?;

        // Write report-requests (optional, empty for now)
        writer.write_event(Event::Start(BytesStart::new("arf:report-requests")))?;
        writer.write_event(Event::End(BytesEnd::new("arf:report-requests")))?;

        // Write assets
        Self::write_assets(&mut writer, &doc.assets)?;

        // Write reports
        Self::write_reports(&mut writer, &doc.reports)?;

        // Write extended-infos (optional, empty for now)
        writer.write_event(Event::Start(BytesStart::new("arf:extended-infos")))?;
        writer.write_event(Event::End(BytesEnd::new("arf:extended-infos")))?;

        writer.write_event(Event::End(BytesEnd::new("arf:asset-report-collection")))?;

        let xml_bytes = buffer.into_inner();
        Ok(String::from_utf8(xml_bytes)?)
    }

    fn write_assets<W: std::io::Write>(writer: &mut Writer<W>, assets: &[ArfAsset]) -> Result<()> {
        writer.write_event(Event::Start(BytesStart::new("arf:assets")))?;

        for asset in assets {
            Self::write_asset(writer, asset)?;
        }

        writer.write_event(Event::End(BytesEnd::new("arf:assets")))?;

        Ok(())
    }

    fn write_asset<W: std::io::Write>(writer: &mut Writer<W>, asset: &ArfAsset) -> Result<()> {
        let mut elem = BytesStart::new("arf:asset");
        elem.push_attribute(("id", asset.asset_id.as_str()));
        writer.write_event(Event::Start(elem))?;

        // Write computing-device
        writer.write_event(Event::Start(BytesStart::new("ai:computing-device")))?;

        // FQDN
        if let Some(ref fqdn) = asset.fqdn {
            writer.write_event(Event::Start(BytesStart::new("ai:fqdn")))?;
            writer.write_event(Event::Text(BytesText::new(fqdn)))?;
            writer.write_event(Event::End(BytesEnd::new("ai:fqdn")))?;
        }

        // Hostname
        writer.write_event(Event::Start(BytesStart::new("ai:hostname")))?;
        writer.write_event(Event::Text(BytesText::new(&asset.hostname)))?;
        writer.write_event(Event::End(BytesEnd::new("ai:hostname")))?;

        // Connections (IP/MAC)
        if !asset.ip_addresses.is_empty() || !asset.mac_addresses.is_empty() {
            writer.write_event(Event::Start(BytesStart::new("ai:connections")))?;

            for ip in &asset.ip_addresses {
                writer.write_event(Event::Start(BytesStart::new("ai:connection")))?;
                writer.write_event(Event::Start(BytesStart::new("ai:ip-address")))?;

                let ip_elem = BytesStart::new("ai:ip-v4");
                writer.write_event(Event::Start(ip_elem))?;
                writer.write_event(Event::Text(BytesText::new(ip)))?;
                writer.write_event(Event::End(BytesEnd::new("ai:ip-v4")))?;

                writer.write_event(Event::End(BytesEnd::new("ai:ip-address")))?;
                writer.write_event(Event::End(BytesEnd::new("ai:connection")))?;
            }

            writer.write_event(Event::End(BytesEnd::new("ai:connections")))?;
        }

        writer.write_event(Event::End(BytesEnd::new("ai:computing-device")))?;

        writer.write_event(Event::End(BytesEnd::new("arf:asset")))?;

        Ok(())
    }

    fn write_reports<W: std::io::Write>(writer: &mut Writer<W>, reports: &[ArfReport]) -> Result<()> {
        writer.write_event(Event::Start(BytesStart::new("arf:reports")))?;

        for report in reports {
            Self::write_report(writer, report)?;
        }

        writer.write_event(Event::End(BytesEnd::new("arf:reports")))?;

        Ok(())
    }

    fn write_report<W: std::io::Write>(writer: &mut Writer<W>, report: &ArfReport) -> Result<()> {
        let mut elem = BytesStart::new("arf:report");
        elem.push_attribute(("id", report.report_id.as_str()));
        writer.write_event(Event::Start(elem))?;

        // Write content based on type
        writer.write_event(Event::Start(BytesStart::new("arf:content")))?;

        match &report.content {
            ArfReportContent::XccdfTestResult(xccdf) => {
                Self::write_xccdf_test_result(writer, xccdf)?;
            }
            ArfReportContent::OvalResults(oval) => {
                Self::write_oval_results(writer, oval)?;
            }
        }

        writer.write_event(Event::End(BytesEnd::new("arf:content")))?;

        writer.write_event(Event::End(BytesEnd::new("arf:report")))?;

        Ok(())
    }

    fn write_xccdf_test_result<W: std::io::Write>(
        writer: &mut Writer<W>,
        xccdf: &XccdfTestResultContent,
    ) -> Result<()> {
        let mut elem = BytesStart::new("xccdf:TestResult");
        elem.push_attribute(("id", format!("xccdf_heroforge_testresult_{}", Uuid::new_v4()).as_str()));
        elem.push_attribute(("start-time", xccdf.start_time.to_rfc3339().as_str()));
        elem.push_attribute(("end-time", xccdf.end_time.to_rfc3339().as_str()));
        writer.write_event(Event::Start(elem))?;

        // Benchmark reference
        let mut bench_elem = BytesStart::new("xccdf:benchmark");
        bench_elem.push_attribute(("href", xccdf.benchmark_id.as_str()));
        writer.write_event(Event::Empty(bench_elem))?;

        // Profile
        let mut profile_elem = BytesStart::new("xccdf:profile");
        profile_elem.push_attribute(("idref", xccdf.profile_id.as_str()));
        writer.write_event(Event::Empty(profile_elem))?;

        // Target
        writer.write_event(Event::Start(BytesStart::new("xccdf:target")))?;
        writer.write_event(Event::Text(BytesText::new("scanned-system")))?;
        writer.write_event(Event::End(BytesEnd::new("xccdf:target")))?;

        // Rule results
        for rule_result in &xccdf.rule_results {
            Self::write_rule_result(writer, rule_result)?;
        }

        // Score
        let mut score_elem = BytesStart::new("xccdf:score");
        score_elem.push_attribute(("system", "urn:xccdf:scoring:default"));
        score_elem.push_attribute(("maximum", xccdf.score_maximum.to_string().as_str()));
        writer.write_event(Event::Start(score_elem))?;
        writer.write_event(Event::Text(BytesText::new(&xccdf.score.to_string())))?;
        writer.write_event(Event::End(BytesEnd::new("xccdf:score")))?;

        writer.write_event(Event::End(BytesEnd::new("xccdf:TestResult")))?;

        Ok(())
    }

    fn write_rule_result<W: std::io::Write>(
        writer: &mut Writer<W>,
        rule_result: &ArfRuleResult,
    ) -> Result<()> {
        let mut elem = BytesStart::new("xccdf:rule-result");
        elem.push_attribute(("idref", rule_result.rule_id.as_str()));
        writer.write_event(Event::Start(elem))?;

        // Result
        writer.write_event(Event::Start(BytesStart::new("xccdf:result")))?;
        writer.write_event(Event::Text(BytesText::new(&rule_result.result)))?;
        writer.write_event(Event::End(BytesEnd::new("xccdf:result")))?;

        // Message (if present)
        if let Some(ref msg) = rule_result.message {
            writer.write_event(Event::Start(BytesStart::new("xccdf:message")))?;
            writer.write_event(Event::Text(BytesText::new(msg)))?;
            writer.write_event(Event::End(BytesEnd::new("xccdf:message")))?;
        }

        // Check content reference (if present)
        if let Some(ref check_ref) = rule_result.check_content_ref {
            let mut check_elem = BytesStart::new("xccdf:check");
            check_elem.push_attribute(("system", "http://oval.mitre.org/XMLSchema/oval-definitions-5"));
            writer.write_event(Event::Start(check_elem))?;

            let mut ref_elem = BytesStart::new("xccdf:check-content-ref");
            ref_elem.push_attribute(("name", check_ref.as_str()));
            writer.write_event(Event::Empty(ref_elem))?;

            writer.write_event(Event::End(BytesEnd::new("xccdf:check")))?;
        }

        writer.write_event(Event::End(BytesEnd::new("xccdf:rule-result")))?;

        Ok(())
    }

    fn write_oval_results<W: std::io::Write>(
        writer: &mut Writer<W>,
        oval: &OvalResultsContent,
    ) -> Result<()> {
        writer.write_event(Event::Start(BytesStart::new("oval-results:oval_results")))?;

        writer.write_event(Event::Start(BytesStart::new("oval-results:results")))?;

        for def_result in &oval.definition_results {
            writer.write_event(Event::Start(BytesStart::new("oval-results:system")))?;

            let mut def_elem = BytesStart::new("oval-results:definition");
            def_elem.push_attribute(("definition_id", def_result.definition_id.as_str()));
            def_elem.push_attribute(("result", def_result.result.as_str()));
            writer.write_event(Event::Empty(def_elem))?;

            writer.write_event(Event::End(BytesEnd::new("oval-results:system")))?;
        }

        writer.write_event(Event::End(BytesEnd::new("oval-results:results")))?;

        writer.write_event(Event::End(BytesEnd::new("oval-results:oval_results")))?;

        Ok(())
    }
}

/// Convert XCCDF results to ARF document
pub fn xccdf_results_to_arf(
    xccdf_result: &XccdfResult,
    hostname: &str,
    ip_address: &str,
    benchmark_id: &str,
) -> ArfDocument {
    let asset_id = format!("asset-{}", Uuid::new_v4());
    let report_id = format!("report-{}", Uuid::new_v4());

    let asset = ArfAsset {
        asset_id: asset_id.clone(),
        fqdn: None,
        ip_addresses: vec![ip_address.to_string()],
        mac_addresses: Vec::new(),
        hostname: hostname.to_string(),
        os_name: None,
        os_version: None,
    };

    let rule_results: Vec<ArfRuleResult> = xccdf_result
        .rule_results
        .iter()
        .map(|r| ArfRuleResult {
            rule_id: r.rule_id.clone(),
            result: result_value_to_string(&r.result),
            message: r.message.clone(),
            check_content_ref: None,
        })
        .collect();

    // Calculate score
    let total = rule_results.len() as f64;
    let passed = rule_results.iter().filter(|r| r.result == "pass").count() as f64;
    let score = if total > 0.0 { (passed / total) * 100.0 } else { 0.0 };

    let xccdf_content = XccdfTestResultContent {
        benchmark_id: benchmark_id.to_string(),
        profile_id: xccdf_result.profile_id.clone(),
        start_time: xccdf_result.start_time,
        end_time: xccdf_result.end_time,
        rule_results,
        score,
        score_maximum: 100.0,
    };

    let report = ArfReport {
        report_id,
        asset_ref: asset_id,
        content: ArfReportContent::XccdfTestResult(xccdf_content),
    };

    ArfDocument {
        report_id: format!("arf-collection-{}", Uuid::new_v4()),
        assets: vec![asset],
        reports: vec![report],
        generated_at: Utc::now(),
    }
}

fn result_value_to_string(result: &ResultValue) -> String {
    match result {
        ResultValue::Pass => "pass",
        ResultValue::Fail => "fail",
        ResultValue::Error => "error",
        ResultValue::Unknown => "unknown",
        ResultValue::NotApplicable => "notapplicable",
        ResultValue::NotChecked => "notchecked",
        ResultValue::NotSelected => "notselected",
        ResultValue::InformationalValue => "informational",
        ResultValue::Fixed => "fixed",
    }
    .to_string()
}

/// Generate ARF XML from XCCDF results
pub fn generate_arf(
    xccdf_result: &XccdfResult,
    hostname: &str,
    ip_address: &str,
    benchmark_id: &str,
) -> Result<String> {
    let doc = xccdf_results_to_arf(xccdf_result, hostname, ip_address, benchmark_id);
    ArfGenerator::generate(&doc)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_arf() {
        let xccdf_result = XccdfResult {
            benchmark_id: "test-benchmark".to_string(),
            profile_id: "test-profile".to_string(),
            start_time: Utc::now(),
            end_time: Utc::now(),
            rule_results: vec![
                RuleResult {
                    rule_id: "rule-1".to_string(),
                    result: ResultValue::Pass,
                    message: None,
                    time: Utc::now(),
                },
            ],
            score: 100.0,
        };

        let arf = generate_arf(&xccdf_result, "test-host", "192.168.1.100", "benchmark-1").unwrap();

        assert!(arf.contains("asset-report-collection"));
        assert!(arf.contains("ai:hostname"));
        assert!(arf.contains("xccdf:TestResult"));
        assert!(arf.contains("<xccdf:result>pass</xccdf:result>"));
    }
}
