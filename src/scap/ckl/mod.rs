//! CKL - STIG Viewer Checklist Format
//!
//! Implements CKL export for compatibility with DISA STIG Viewer application.
//! CKL is an XML format used for documenting STIG compliance status.

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::net::IpAddr;

use crate::scap::{generate_scap_id, sanitize_xml, ScapSeverity};
use crate::scap::xccdf::XccdfResultType;

/// CKL Checklist document
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CklChecklist {
    /// Asset information
    pub asset: CklAsset,
    /// STIG sections
    pub stigs: Vec<CklStig>,
    /// Generation timestamp
    pub generated_at: DateTime<Utc>,
}

impl Default for CklChecklist {
    fn default() -> Self {
        Self {
            asset: CklAsset::default(),
            stigs: Vec::new(),
            generated_at: Utc::now(),
        }
    }
}

impl CklChecklist {
    /// Create a new empty checklist
    pub fn new() -> Self {
        Self::default()
    }

    /// Set asset information
    pub fn with_asset(mut self, asset: CklAsset) -> Self {
        self.asset = asset;
        self
    }

    /// Add a STIG section
    pub fn add_stig(&mut self, stig: CklStig) {
        self.stigs.push(stig);
    }
}

/// Asset information in CKL
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CklAsset {
    pub role: Option<String>,
    pub asset_type: CklAssetType,
    pub host_name: Option<String>,
    pub host_ip: Option<String>,
    pub host_mac: Option<String>,
    pub host_fqdn: Option<String>,
    pub tech_area: Option<String>,
    pub target_key: Option<String>,
    pub target_comment: Option<String>,
    pub web_site: Option<String>,
    pub web_db_site: Option<String>,
    pub web_db_instance: Option<String>,
}

impl CklAsset {
    /// Create asset for a computing device
    pub fn new_computing(hostname: &str, ip: Option<&str>, fqdn: Option<&str>) -> Self {
        Self {
            role: Some("None".to_string()),
            asset_type: CklAssetType::Computing,
            host_name: Some(hostname.to_string()),
            host_ip: ip.map(|s| s.to_string()),
            host_mac: None,
            host_fqdn: fqdn.map(|s| s.to_string()),
            tech_area: None,
            target_key: None,
            target_comment: None,
            web_site: None,
            web_db_site: None,
            web_db_instance: None,
        }
    }

    /// Create asset for a network device
    pub fn new_network(hostname: &str, ip: Option<&str>) -> Self {
        Self {
            role: Some("None".to_string()),
            asset_type: CklAssetType::NonComputing,
            host_name: Some(hostname.to_string()),
            host_ip: ip.map(|s| s.to_string()),
            host_mac: None,
            host_fqdn: None,
            tech_area: Some("NETWORK".to_string()),
            target_key: None,
            target_comment: None,
            web_site: None,
            web_db_site: None,
            web_db_instance: None,
        }
    }
}

/// Asset type enum
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum CklAssetType {
    #[default]
    Computing,
    NonComputing,
}

impl CklAssetType {
    pub fn as_str(&self) -> &'static str {
        match self {
            CklAssetType::Computing => "Computing",
            CklAssetType::NonComputing => "Non-Computing",
        }
    }
}

/// STIG section in CKL
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CklStig {
    /// STIG metadata
    pub stig_info: CklStigInfo,
    /// Vulnerability entries
    pub vulns: Vec<CklVuln>,
}

impl CklStig {
    /// Create a new STIG section
    pub fn new(stig_id: &str, title: &str, version: &str, release: &str) -> Self {
        Self {
            stig_info: CklStigInfo {
                stig_id: stig_id.to_string(),
                stig_name: title.to_string(),
                version: version.to_string(),
                release_info: release.to_string(),
                classification: "UNCLASSIFIED".to_string(),
                custom_name: None,
                uuid: generate_scap_id(),
                notice: None,
                source: Some("DISA".to_string()),
            },
            vulns: Vec::new(),
        }
    }

    /// Add a vulnerability entry
    pub fn add_vuln(&mut self, vuln: CklVuln) {
        self.vulns.push(vuln);
    }
}

/// STIG info metadata
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CklStigInfo {
    pub stig_id: String,
    pub stig_name: String,
    pub version: String,
    pub release_info: String,
    pub classification: String,
    pub custom_name: Option<String>,
    pub uuid: String,
    pub notice: Option<String>,
    pub source: Option<String>,
}

/// Vulnerability entry in CKL
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CklVuln {
    /// Vulnerability number (V-xxxxx)
    pub vuln_num: String,
    /// Severity (high, medium, low)
    pub severity: CklSeverity,
    /// Group title
    pub group_title: String,
    /// Rule ID (SV-xxxxx)
    pub rule_id: String,
    /// Rule version
    pub rule_ver: String,
    /// Rule title
    pub rule_title: String,
    /// Vulnerability discussion
    pub vuln_discuss: Option<String>,
    /// IA controls
    pub ia_controls: Option<String>,
    /// Check content
    pub check_content: Option<String>,
    /// Fix text
    pub fix_text: Option<String>,
    /// False positives
    pub false_positives: Option<String>,
    /// False negatives
    pub false_negatives: Option<String>,
    /// Documentable
    pub documentable: bool,
    /// Mitigations
    pub mitigations: Option<String>,
    /// Potential impact
    pub potential_impact: Option<String>,
    /// Third party tools
    pub third_party_tools: Option<String>,
    /// Mitigation control
    pub mitigation_control: Option<String>,
    /// Responsibility
    pub responsibility: Option<String>,
    /// Security override guidance
    pub security_override_guidance: Option<String>,
    /// Check content reference (OVAL ID etc.)
    pub check_content_ref: Option<String>,
    /// Weight
    pub weight: Option<String>,
    /// Class (Unclass)
    pub class: String,
    /// STIGRef
    pub stig_ref: Option<String>,
    /// Target key
    pub target_key: Option<String>,
    /// STIG UUID
    pub stig_uuid: Option<String>,
    /// Legacy IDs (e.g., CCI numbers)
    pub legacy_ids: Vec<String>,
    /// CCI references
    pub cci_refs: Vec<String>,

    // Result fields
    /// Finding status
    pub status: CklStatus,
    /// Finding details (evidence)
    pub finding_details: Option<String>,
    /// Comments
    pub comments: Option<String>,
    /// Severity override
    pub severity_override: Option<CklSeverity>,
    /// Severity justification
    pub severity_justification: Option<String>,
}

impl CklVuln {
    /// Create a basic vulnerability entry
    pub fn new(vuln_num: &str, rule_id: &str, severity: CklSeverity) -> Self {
        Self {
            vuln_num: vuln_num.to_string(),
            severity,
            rule_id: rule_id.to_string(),
            class: "Unclass".to_string(),
            documentable: false,
            status: CklStatus::NotReviewed,
            ..Default::default()
        }
    }

    /// Set the result status
    pub fn with_status(mut self, status: CklStatus) -> Self {
        self.status = status;
        self
    }

    /// Set finding details
    pub fn with_finding_details(mut self, details: &str) -> Self {
        self.finding_details = Some(details.to_string());
        self
    }

    /// Set comments
    pub fn with_comments(mut self, comments: &str) -> Self {
        self.comments = Some(comments.to_string());
        self
    }

    /// Set rule title
    pub fn with_title(mut self, title: &str) -> Self {
        self.rule_title = title.to_string();
        self
    }

    /// Set check content
    pub fn with_check_content(mut self, content: &str) -> Self {
        self.check_content = Some(content.to_string());
        self
    }

    /// Set fix text
    pub fn with_fix_text(mut self, fix: &str) -> Self {
        self.fix_text = Some(fix.to_string());
        self
    }

    /// Add CCI reference
    pub fn add_cci(&mut self, cci: &str) {
        self.cci_refs.push(cci.to_string());
    }
}

/// CKL severity levels
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum CklSeverity {
    High,
    #[default]
    Medium,
    Low,
}

impl CklSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            CklSeverity::High => "high",
            CklSeverity::Medium => "medium",
            CklSeverity::Low => "low",
        }
    }

    /// Convert from CAT level (I, II, III)
    pub fn from_cat(cat: &str) -> Self {
        match cat.to_uppercase().as_str() {
            "CAT I" | "CATI" | "I" | "1" => CklSeverity::High,
            "CAT II" | "CATII" | "II" | "2" => CklSeverity::Medium,
            "CAT III" | "CATIII" | "III" | "3" => CklSeverity::Low,
            _ => CklSeverity::Medium,
        }
    }
}

impl From<ScapSeverity> for CklSeverity {
    fn from(sev: ScapSeverity) -> Self {
        match sev {
            ScapSeverity::High | ScapSeverity::Critical => CklSeverity::High,
            ScapSeverity::Medium | ScapSeverity::Unknown => CklSeverity::Medium,
            ScapSeverity::Low | ScapSeverity::Info => CklSeverity::Low,
        }
    }
}

/// CKL finding status
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum CklStatus {
    /// Open finding (vulnerability exists)
    Open,
    /// Not a Finding (passed check)
    NotAFinding,
    /// Not Applicable (check doesn't apply to this system)
    NotApplicable,
    /// Not Reviewed (not yet assessed)
    #[default]
    NotReviewed,
}

impl CklStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            CklStatus::Open => "Open",
            CklStatus::NotAFinding => "NotAFinding",
            CklStatus::NotApplicable => "Not_Applicable",
            CklStatus::NotReviewed => "Not_Reviewed",
        }
    }
}

impl From<XccdfResultType> for CklStatus {
    fn from(result: XccdfResultType) -> Self {
        match result {
            XccdfResultType::Pass | XccdfResultType::Fixed => CklStatus::NotAFinding,
            XccdfResultType::Fail => CklStatus::Open,
            XccdfResultType::NotApplicable => CklStatus::NotApplicable,
            XccdfResultType::NotChecked | XccdfResultType::NotSelected |
            XccdfResultType::Error | XccdfResultType::Unknown |
            XccdfResultType::Informational => CklStatus::NotReviewed,
        }
    }
}

/// CKL Generator
pub struct CklGenerator<'a> {
    pool: &'a SqlitePool,
}

impl<'a> CklGenerator<'a> {
    pub fn new(pool: &'a SqlitePool) -> Self {
        Self { pool }
    }

    /// Generate CKL from an execution ID
    pub async fn generate(&self, execution_id: &str) -> Result<String> {
        // Load execution from database
        let execution = self.load_execution(execution_id).await?;

        // Build checklist
        let mut checklist = CklChecklist::new();

        // Set asset info
        if let Some(target) = execution.targets.first() {
            checklist.asset = CklAsset::new_computing(
                &target.hostname,
                target.ip_address.as_deref(),
                target.fqdn.as_deref(),
            );
        }

        // Build STIG section from results
        let mut stig = CklStig::new(
            &execution.benchmark_id,
            &execution.benchmark_title,
            &execution.benchmark_version,
            &execution.benchmark_release,
        );

        // Add vulnerability entries from rule results
        for result in &execution.rule_results {
            let mut vuln = CklVuln::new(
                &result.vuln_num,
                &result.rule_id,
                result.severity,
            );
            vuln.status = result.status;
            vuln.rule_title = result.rule_title.clone();
            vuln.finding_details = result.finding_details.clone();
            vuln.comments = result.comments.clone();
            vuln.check_content = result.check_content.clone();
            vuln.fix_text = result.fix_text.clone();
            vuln.cci_refs = result.cci_refs.clone();
            vuln.vuln_discuss = result.discussion.clone();

            stig.add_vuln(vuln);
        }

        checklist.add_stig(stig);

        self.to_xml(&checklist)
    }

    /// Generate CKL directly from results (without database)
    pub fn generate_from_results(
        &self,
        asset: CklAsset,
        stig: CklStig,
    ) -> Result<String> {
        let mut checklist = CklChecklist::new();
        checklist.asset = asset;
        checklist.add_stig(stig);

        self.to_xml(&checklist)
    }

    /// Load execution data from database
    async fn load_execution(&self, execution_id: &str) -> Result<CklExecution> {
        // Query execution record
        let row = sqlx::query_as::<_, (String, String, String, String, String)>(
            r#"SELECT id, benchmark_id, COALESCE(benchmark_title, ''),
               COALESCE(benchmark_version, '1'), COALESCE(targets, '[]')
               FROM scap_executions WHERE id = ?"#
        )
        .bind(execution_id)
        .fetch_optional(self.pool)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Execution not found: {}", execution_id))?;

        let targets: Vec<CklTargetInfo> = serde_json::from_str(&row.4).unwrap_or_default();

        // Query rule results
        let result_rows = sqlx::query_as::<_, (String, String, String, String, Option<String>, Option<String>)>(
            r#"SELECT rule_id, result, COALESCE(severity, 'medium'),
               COALESCE(rule_title, ''), finding_details, comments
               FROM scap_xccdf_results WHERE execution_id = ?"#
        )
        .bind(execution_id)
        .fetch_all(self.pool)
        .await
        .unwrap_or_default();

        let rule_results: Vec<CklRuleResult> = result_rows.iter().map(|r| {
            let status = match r.1.as_str() {
                "pass" | "fixed" => CklStatus::NotAFinding,
                "fail" => CklStatus::Open,
                "notapplicable" => CklStatus::NotApplicable,
                _ => CklStatus::NotReviewed,
            };
            let severity = CklSeverity::from_cat(&r.2);

            // Extract V-number from rule_id if present
            let vuln_num = if r.0.starts_with("V-") {
                r.0.clone()
            } else {
                // Try to extract from rule ID pattern like "SV-xxxxx_rule" or generate one
                format!("V-{}", &r.0[..r.0.len().min(6)])
            };

            CklRuleResult {
                rule_id: r.0.clone(),
                vuln_num,
                rule_title: r.3.clone(),
                status,
                severity,
                finding_details: r.4.clone(),
                comments: r.5.clone(),
                check_content: None,
                fix_text: None,
                cci_refs: Vec::new(),
                discussion: None,
            }
        }).collect();

        Ok(CklExecution {
            id: row.0,
            benchmark_id: row.1,
            benchmark_title: row.2,
            benchmark_version: row.3,
            benchmark_release: "1".to_string(),
            targets,
            rule_results,
        })
    }

    /// Convert CKL checklist to XML
    fn to_xml(&self, checklist: &CklChecklist) -> Result<String> {
        let mut xml = String::new();
        xml.push_str(r#"<?xml version="1.0" encoding="UTF-8"?>"#);
        xml.push('\n');
        xml.push_str("<!--DISA STIG Viewer :: Generated by HeroForge-->\n");
        xml.push_str("<CHECKLIST>\n");

        // Asset section
        xml.push_str("  <ASSET>\n");
        self.write_asset_element(&mut xml, &checklist.asset);
        xml.push_str("  </ASSET>\n");

        // STIGs section
        xml.push_str("  <STIGS>\n");
        for stig in &checklist.stigs {
            self.write_stig_element(&mut xml, stig);
        }
        xml.push_str("  </STIGS>\n");

        xml.push_str("</CHECKLIST>\n");

        Ok(xml)
    }

    fn write_asset_element(&self, xml: &mut String, asset: &CklAsset) {
        self.write_optional_element(xml, "ROLE", asset.role.as_deref(), 4);
        xml.push_str(&format!("    <ASSET_TYPE>{}</ASSET_TYPE>\n", asset.asset_type.as_str()));
        self.write_optional_element(xml, "HOST_NAME", asset.host_name.as_deref(), 4);
        self.write_optional_element(xml, "HOST_IP", asset.host_ip.as_deref(), 4);
        self.write_optional_element(xml, "HOST_MAC", asset.host_mac.as_deref(), 4);
        self.write_optional_element(xml, "HOST_FQDN", asset.host_fqdn.as_deref(), 4);
        self.write_optional_element(xml, "TECH_AREA", asset.tech_area.as_deref(), 4);
        self.write_optional_element(xml, "TARGET_KEY", asset.target_key.as_deref(), 4);
        self.write_optional_element(xml, "TARGET_COMMENT", asset.target_comment.as_deref(), 4);
        self.write_optional_element(xml, "WEB_OR_DATABASE", Some("false"), 4);
        self.write_optional_element(xml, "WEB_DB_SITE", asset.web_db_site.as_deref(), 4);
        self.write_optional_element(xml, "WEB_DB_INSTANCE", asset.web_db_instance.as_deref(), 4);
    }

    fn write_stig_element(&self, xml: &mut String, stig: &CklStig) {
        xml.push_str("    <iSTIG>\n");

        // STIG_INFO section
        xml.push_str("      <STIG_INFO>\n");
        self.write_si_data(xml, "version", &stig.stig_info.version);
        self.write_si_data(xml, "classification", &stig.stig_info.classification);
        self.write_si_data(xml, "customname", stig.stig_info.custom_name.as_deref().unwrap_or(""));
        self.write_si_data(xml, "stigid", &stig.stig_info.stig_id);
        self.write_si_data(xml, "description", &stig.stig_info.stig_name);
        self.write_si_data(xml, "filename", &format!("{}.xml", &stig.stig_info.stig_id));
        self.write_si_data(xml, "releaseinfo", &stig.stig_info.release_info);
        self.write_si_data(xml, "title", &stig.stig_info.stig_name);
        self.write_si_data(xml, "uuid", &stig.stig_info.uuid);
        self.write_si_data(xml, "notice", stig.stig_info.notice.as_deref().unwrap_or("terms-of-use"));
        self.write_si_data(xml, "source", stig.stig_info.source.as_deref().unwrap_or("DISA"));
        xml.push_str("      </STIG_INFO>\n");

        // VULN entries
        for vuln in &stig.vulns {
            self.write_vuln_element(xml, vuln);
        }

        xml.push_str("    </iSTIG>\n");
    }

    fn write_si_data(&self, xml: &mut String, name: &str, data: &str) {
        xml.push_str("        <SI_DATA>\n");
        xml.push_str(&format!("          <SID_NAME>{}</SID_NAME>\n", sanitize_xml(name)));
        xml.push_str(&format!("          <SID_DATA>{}</SID_DATA>\n", sanitize_xml(data)));
        xml.push_str("        </SI_DATA>\n");
    }

    fn write_vuln_element(&self, xml: &mut String, vuln: &CklVuln) {
        xml.push_str("      <VULN>\n");

        // STIG_DATA entries
        self.write_stig_data(xml, "Vuln_Num", &vuln.vuln_num);
        self.write_stig_data(xml, "Severity", vuln.severity.as_str());
        self.write_stig_data(xml, "Group_Title", &vuln.group_title);
        self.write_stig_data(xml, "Rule_ID", &vuln.rule_id);
        self.write_stig_data(xml, "Rule_Ver", &vuln.rule_ver);
        self.write_stig_data(xml, "Rule_Title", &vuln.rule_title);
        self.write_stig_data(xml, "Vuln_Discuss", vuln.vuln_discuss.as_deref().unwrap_or(""));
        self.write_stig_data(xml, "IA_Controls", vuln.ia_controls.as_deref().unwrap_or(""));
        self.write_stig_data(xml, "Check_Content", vuln.check_content.as_deref().unwrap_or(""));
        self.write_stig_data(xml, "Fix_Text", vuln.fix_text.as_deref().unwrap_or(""));
        self.write_stig_data(xml, "False_Positives", vuln.false_positives.as_deref().unwrap_or(""));
        self.write_stig_data(xml, "False_Negatives", vuln.false_negatives.as_deref().unwrap_or(""));
        self.write_stig_data(xml, "Documentable", if vuln.documentable { "true" } else { "false" });
        self.write_stig_data(xml, "Mitigations", vuln.mitigations.as_deref().unwrap_or(""));
        self.write_stig_data(xml, "Potential_Impact", vuln.potential_impact.as_deref().unwrap_or(""));
        self.write_stig_data(xml, "Third_Party_Tools", vuln.third_party_tools.as_deref().unwrap_or(""));
        self.write_stig_data(xml, "Mitigation_Control", vuln.mitigation_control.as_deref().unwrap_or(""));
        self.write_stig_data(xml, "Responsibility", vuln.responsibility.as_deref().unwrap_or(""));
        self.write_stig_data(xml, "Security_Override_Guidance", vuln.security_override_guidance.as_deref().unwrap_or(""));
        self.write_stig_data(xml, "Check_Content_Ref", vuln.check_content_ref.as_deref().unwrap_or(""));
        self.write_stig_data(xml, "Weight", vuln.weight.as_deref().unwrap_or("10.0"));
        self.write_stig_data(xml, "Class", &vuln.class);
        self.write_stig_data(xml, "STIGRef", vuln.stig_ref.as_deref().unwrap_or(""));
        self.write_stig_data(xml, "TargetKey", vuln.target_key.as_deref().unwrap_or(""));
        self.write_stig_data(xml, "STIG_UUID", vuln.stig_uuid.as_deref().unwrap_or(""));

        // Legacy IDs
        for legacy_id in &vuln.legacy_ids {
            self.write_stig_data(xml, "LEGACY_ID", legacy_id);
        }

        // CCI references
        for cci in &vuln.cci_refs {
            self.write_stig_data(xml, "CCI_REF", cci);
        }

        // Result fields
        xml.push_str(&format!("        <STATUS>{}</STATUS>\n", vuln.status.as_str()));
        xml.push_str(&format!("        <FINDING_DETAILS>{}</FINDING_DETAILS>\n",
            sanitize_xml(vuln.finding_details.as_deref().unwrap_or(""))));
        xml.push_str(&format!("        <COMMENTS>{}</COMMENTS>\n",
            sanitize_xml(vuln.comments.as_deref().unwrap_or(""))));
        xml.push_str(&format!("        <SEVERITY_OVERRIDE>{}</SEVERITY_OVERRIDE>\n",
            vuln.severity_override.map(|s| s.as_str()).unwrap_or("")));
        xml.push_str(&format!("        <SEVERITY_JUSTIFICATION>{}</SEVERITY_JUSTIFICATION>\n",
            sanitize_xml(vuln.severity_justification.as_deref().unwrap_or(""))));

        xml.push_str("      </VULN>\n");
    }

    fn write_stig_data(&self, xml: &mut String, attr: &str, data: &str) {
        xml.push_str("        <STIG_DATA>\n");
        xml.push_str(&format!("          <VULN_ATTRIBUTE>{}</VULN_ATTRIBUTE>\n", sanitize_xml(attr)));
        xml.push_str(&format!("          <ATTRIBUTE_DATA>{}</ATTRIBUTE_DATA>\n", sanitize_xml(data)));
        xml.push_str("        </STIG_DATA>\n");
    }

    fn write_optional_element(&self, xml: &mut String, tag: &str, value: Option<&str>, indent: usize) {
        let spaces: String = " ".repeat(indent);
        xml.push_str(&format!("{}<{}>{}</{}>\n",
            spaces,
            tag,
            sanitize_xml(value.unwrap_or("")),
            tag
        ));
    }
}

/// Internal structure for loaded CKL execution
struct CklExecution {
    #[allow(dead_code)]
    id: String,
    benchmark_id: String,
    benchmark_title: String,
    benchmark_version: String,
    benchmark_release: String,
    targets: Vec<CklTargetInfo>,
    rule_results: Vec<CklRuleResult>,
}

/// Target info from execution
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CklTargetInfo {
    hostname: String,
    fqdn: Option<String>,
    ip_address: Option<String>,
}

/// Rule result for CKL
#[derive(Debug, Clone)]
struct CklRuleResult {
    rule_id: String,
    vuln_num: String,
    rule_title: String,
    status: CklStatus,
    severity: CklSeverity,
    finding_details: Option<String>,
    comments: Option<String>,
    check_content: Option<String>,
    fix_text: Option<String>,
    cci_refs: Vec<String>,
    discussion: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ckl_severity_from_cat() {
        assert_eq!(CklSeverity::from_cat("CAT I"), CklSeverity::High);
        assert_eq!(CklSeverity::from_cat("CAT II"), CklSeverity::Medium);
        assert_eq!(CklSeverity::from_cat("CAT III"), CklSeverity::Low);
        assert_eq!(CklSeverity::from_cat("I"), CklSeverity::High);
        assert_eq!(CklSeverity::from_cat("unknown"), CklSeverity::Medium);
    }

    #[test]
    fn test_ckl_status_from_xccdf() {
        assert_eq!(CklStatus::from(XccdfResultType::Pass), CklStatus::NotAFinding);
        assert_eq!(CklStatus::from(XccdfResultType::Fail), CklStatus::Open);
        assert_eq!(CklStatus::from(XccdfResultType::NotApplicable), CklStatus::NotApplicable);
        assert_eq!(CklStatus::from(XccdfResultType::NotChecked), CklStatus::NotReviewed);
    }

    #[test]
    fn test_ckl_asset_creation() {
        let asset = CklAsset::new_computing("server01", Some("192.168.1.100"), Some("server01.example.com"));
        assert_eq!(asset.host_name, Some("server01".to_string()));
        assert_eq!(asset.host_ip, Some("192.168.1.100".to_string()));
        assert_eq!(asset.host_fqdn, Some("server01.example.com".to_string()));
        assert_eq!(asset.asset_type, CklAssetType::Computing);
    }

    #[test]
    fn test_ckl_vuln_builder() {
        let vuln = CklVuln::new("V-12345", "SV-12345r1_rule", CklSeverity::High)
            .with_status(CklStatus::Open)
            .with_title("Test Rule")
            .with_finding_details("Evidence found")
            .with_comments("Needs remediation");

        assert_eq!(vuln.vuln_num, "V-12345");
        assert_eq!(vuln.rule_id, "SV-12345r1_rule");
        assert_eq!(vuln.severity, CklSeverity::High);
        assert_eq!(vuln.status, CklStatus::Open);
        assert_eq!(vuln.rule_title, "Test Rule");
        assert!(vuln.finding_details.is_some());
    }

    #[tokio::test]
    async fn test_ckl_xml_generation() {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        let generator = CklGenerator::new(&pool);

        let asset = CklAsset::new_computing("test-host", Some("10.0.0.1"), None);
        let mut stig = CklStig::new("test-stig", "Test STIG", "1", "Release 1");
        stig.add_vuln(
            CklVuln::new("V-00001", "SV-00001r1_rule", CklSeverity::Medium)
                .with_status(CklStatus::NotAFinding)
                .with_title("Test Check")
        );

        let xml = generator.generate_from_results(asset, stig).unwrap();

        assert!(xml.contains("<?xml version"));
        assert!(xml.contains("<CHECKLIST>"));
        assert!(xml.contains("<ASSET>"));
        assert!(xml.contains("test-host"));
        assert!(xml.contains("<iSTIG>"));
        assert!(xml.contains("V-00001"));
        assert!(xml.contains("NotAFinding"));
    }
}
