//! CKL (DISA STIG Viewer Checklist) Format Generator
//!
//! Generates CKL XML files compatible with DISA STIG Viewer for
//! compliance documentation and audit evidence.

use anyhow::Result;
use chrono::{DateTime, Utc};
use quick_xml::{Writer, events::{Event, BytesDecl, BytesEnd, BytesStart, BytesText}};
use std::io::Cursor;

use crate::scanner::windows_audit::types::{StigCheckResult, StigCheckStatus, StigCategory};

/// CKL document structure
#[derive(Debug, Clone)]
pub struct CklDocument {
    pub asset: CklAsset,
    pub stigs: Vec<CklStig>,
}

/// Asset information for CKL
#[derive(Debug, Clone)]
pub struct CklAsset {
    pub host_name: String,
    pub host_ip: String,
    pub host_mac: Option<String>,
    pub host_fqdn: Option<String>,
    pub target_comment: Option<String>,
    pub role: AssetRole,
    pub asset_type: AssetType,
}

/// Asset role
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssetRole {
    None,
    Workstation,
    MemberServer,
    DomainController,
}

impl AssetRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            AssetRole::None => "None",
            AssetRole::Workstation => "Workstation",
            AssetRole::MemberServer => "Member Server",
            AssetRole::DomainController => "Domain Controller",
        }
    }
}

/// Asset type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssetType {
    Computing,
    NonComputing,
}

impl AssetType {
    pub fn as_str(&self) -> &'static str {
        match self {
            AssetType::Computing => "Computing",
            AssetType::NonComputing => "Non-Computing",
        }
    }
}

/// STIG information for CKL
#[derive(Debug, Clone)]
pub struct CklStig {
    pub stig_info: StigInfo,
    pub vulnerabilities: Vec<CklVulnerability>,
}

/// STIG metadata
#[derive(Debug, Clone)]
pub struct StigInfo {
    pub stig_id: String,
    pub sid_name: String,
    pub version: String,
    pub release_info: String,
    pub filename: String,
}

/// Individual vulnerability/check in CKL
#[derive(Debug, Clone)]
pub struct CklVulnerability {
    pub stig_data: Vec<StigDataItem>,
    pub status: CklStatus,
    pub finding_details: Option<String>,
    pub comments: Option<String>,
    pub severity_override: Option<String>,
    pub severity_justification: Option<String>,
}

/// STIG data item
#[derive(Debug, Clone)]
pub struct StigDataItem {
    pub vuln_attribute: String,
    pub attribute_data: String,
}

/// CKL finding status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CklStatus {
    NotReviewed,
    Open,
    NotAFinding,
    NotApplicable,
}

impl CklStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            CklStatus::NotReviewed => "Not_Reviewed",
            CklStatus::Open => "Open",
            CklStatus::NotAFinding => "NotAFinding",
            CklStatus::NotApplicable => "Not_Applicable",
        }
    }

    pub fn from_stig_status(status: &StigCheckStatus) -> Self {
        match status {
            StigCheckStatus::NotAFinding => CklStatus::NotAFinding,
            StigCheckStatus::Open => CklStatus::Open,
            StigCheckStatus::NotApplicable => CklStatus::NotApplicable,
            StigCheckStatus::NotReviewed => CklStatus::NotReviewed,
        }
    }
}

/// CKL Generator
pub struct CklGenerator;

impl CklGenerator {
    /// Generate CKL XML from a CklDocument
    pub fn generate(doc: &CklDocument) -> Result<String> {
        let mut buffer = Cursor::new(Vec::new());
        let mut writer = Writer::new_with_indent(&mut buffer, b' ', 2);

        // XML declaration
        writer.write_event(Event::Decl(BytesDecl::new("1.0", Some("UTF-8"), None)))?;

        // Root element
        let checklist = BytesStart::new("CHECKLIST");
        writer.write_event(Event::Start(checklist))?;

        // Write ASSET section
        Self::write_asset(&mut writer, &doc.asset)?;

        // Write STIGS section
        Self::write_stigs(&mut writer, &doc.stigs)?;

        writer.write_event(Event::End(BytesEnd::new("CHECKLIST")))?;

        let xml_bytes = buffer.into_inner();
        Ok(String::from_utf8(xml_bytes)?)
    }

    fn write_asset<W: std::io::Write>(writer: &mut Writer<W>, asset: &CklAsset) -> Result<()> {
        writer.write_event(Event::Start(BytesStart::new("ASSET")))?;

        Self::write_element(writer, "ROLE", asset.role.as_str())?;
        Self::write_element(writer, "ASSET_TYPE", asset.asset_type.as_str())?;
        Self::write_element(writer, "HOST_NAME", &asset.host_name)?;
        Self::write_element(writer, "HOST_IP", &asset.host_ip)?;

        if let Some(ref mac) = asset.host_mac {
            Self::write_element(writer, "HOST_MAC", mac)?;
        } else {
            Self::write_element(writer, "HOST_MAC", "")?;
        }

        if let Some(ref fqdn) = asset.host_fqdn {
            Self::write_element(writer, "HOST_FQDN", fqdn)?;
        } else {
            Self::write_element(writer, "HOST_FQDN", "")?;
        }

        if let Some(ref comment) = asset.target_comment {
            Self::write_element(writer, "TARGET_COMMENT", comment)?;
        } else {
            Self::write_element(writer, "TARGET_COMMENT", "")?;
        }

        Self::write_element(writer, "WEB_OR_DATABASE", "false")?;
        Self::write_element(writer, "WEB_DB_SITE", "")?;
        Self::write_element(writer, "WEB_DB_INSTANCE", "")?;

        writer.write_event(Event::End(BytesEnd::new("ASSET")))?;

        Ok(())
    }

    fn write_stigs<W: std::io::Write>(writer: &mut Writer<W>, stigs: &[CklStig]) -> Result<()> {
        writer.write_event(Event::Start(BytesStart::new("STIGS")))?;

        for stig in stigs {
            Self::write_istig(writer, stig)?;
        }

        writer.write_event(Event::End(BytesEnd::new("STIGS")))?;

        Ok(())
    }

    fn write_istig<W: std::io::Write>(writer: &mut Writer<W>, stig: &CklStig) -> Result<()> {
        writer.write_event(Event::Start(BytesStart::new("iSTIG")))?;

        // Write STIG_INFO
        Self::write_stig_info(writer, &stig.stig_info)?;

        // Write vulnerabilities
        for vuln in &stig.vulnerabilities {
            Self::write_vuln(writer, vuln)?;
        }

        writer.write_event(Event::End(BytesEnd::new("iSTIG")))?;

        Ok(())
    }

    fn write_stig_info<W: std::io::Write>(writer: &mut Writer<W>, info: &StigInfo) -> Result<()> {
        writer.write_event(Event::Start(BytesStart::new("STIG_INFO")))?;

        Self::write_si_data(writer, "version", &info.version)?;
        Self::write_si_data(writer, "releaseinfo", &info.release_info)?;
        Self::write_si_data(writer, "title", &info.sid_name)?;
        Self::write_si_data(writer, "stigid", &info.stig_id)?;
        Self::write_si_data(writer, "filename", &info.filename)?;

        writer.write_event(Event::End(BytesEnd::new("STIG_INFO")))?;

        Ok(())
    }

    fn write_si_data<W: std::io::Write>(writer: &mut Writer<W>, name: &str, data: &str) -> Result<()> {
        writer.write_event(Event::Start(BytesStart::new("SI_DATA")))?;

        Self::write_element(writer, "SID_NAME", name)?;
        Self::write_element(writer, "SID_DATA", data)?;

        writer.write_event(Event::End(BytesEnd::new("SI_DATA")))?;

        Ok(())
    }

    fn write_vuln<W: std::io::Write>(writer: &mut Writer<W>, vuln: &CklVulnerability) -> Result<()> {
        writer.write_event(Event::Start(BytesStart::new("VULN")))?;

        // Write STIG_DATA elements
        for item in &vuln.stig_data {
            writer.write_event(Event::Start(BytesStart::new("STIG_DATA")))?;
            Self::write_element(writer, "VULN_ATTRIBUTE", &item.vuln_attribute)?;
            Self::write_element(writer, "ATTRIBUTE_DATA", &item.attribute_data)?;
            writer.write_event(Event::End(BytesEnd::new("STIG_DATA")))?;
        }

        Self::write_element(writer, "STATUS", vuln.status.as_str())?;
        Self::write_element(writer, "FINDING_DETAILS", vuln.finding_details.as_deref().unwrap_or(""))?;
        Self::write_element(writer, "COMMENTS", vuln.comments.as_deref().unwrap_or(""))?;
        Self::write_element(writer, "SEVERITY_OVERRIDE", vuln.severity_override.as_deref().unwrap_or(""))?;
        Self::write_element(writer, "SEVERITY_JUSTIFICATION", vuln.severity_justification.as_deref().unwrap_or(""))?;

        writer.write_event(Event::End(BytesEnd::new("VULN")))?;

        Ok(())
    }

    fn write_element<W: std::io::Write>(writer: &mut Writer<W>, name: &str, value: &str) -> Result<()> {
        writer.write_event(Event::Start(BytesStart::new(name)))?;
        writer.write_event(Event::Text(BytesText::new(value)))?;
        writer.write_event(Event::End(BytesEnd::new(name)))?;
        Ok(())
    }
}

/// Convert STIG check results to CKL document
pub fn stig_results_to_ckl(
    results: &[StigCheckResult],
    hostname: &str,
    ip_address: &str,
    stig_name: &str,
    stig_version: &str,
) -> CklDocument {
    let asset = CklAsset {
        host_name: hostname.to_string(),
        host_ip: ip_address.to_string(),
        host_mac: None,
        host_fqdn: None,
        target_comment: Some(format!("Generated by HeroForge at {}", Utc::now().format("%Y-%m-%d %H:%M:%S UTC"))),
        role: AssetRole::None,
        asset_type: AssetType::Computing,
    };

    let vulnerabilities: Vec<CklVulnerability> = results
        .iter()
        .map(|r| CklVulnerability {
            stig_data: vec![
                StigDataItem {
                    vuln_attribute: "Vuln_Num".to_string(),
                    attribute_data: r.stig_id.clone(),
                },
                StigDataItem {
                    vuln_attribute: "Rule_ID".to_string(),
                    attribute_data: r.rule_id.clone(),
                },
                StigDataItem {
                    vuln_attribute: "Rule_Title".to_string(),
                    attribute_data: r.title.clone(),
                },
                StigDataItem {
                    vuln_attribute: "Severity".to_string(),
                    attribute_data: match r.category {
                        StigCategory::CatI => "high",
                        StigCategory::CatII => "medium",
                        StigCategory::CatIII => "low",
                    }.to_string(),
                },
            ],
            status: CklStatus::from_stig_status(&r.status),
            finding_details: r.finding_details.clone(),
            comments: Some(format!(
                "Automated check by HeroForge\nExpected: {}\nActual: {}",
                r.expected, r.actual
            )),
            severity_override: None,
            severity_justification: None,
        })
        .collect();

    let stig = CklStig {
        stig_info: StigInfo {
            stig_id: format!("{}_STIG", stig_name.replace(' ', "_")),
            sid_name: stig_name.to_string(),
            version: stig_version.to_string(),
            release_info: format!("Release: 1 Benchmark Date: {}", Utc::now().format("%d %b %Y")),
            filename: format!("{}.xml", stig_name.replace(' ', "_")),
        },
        vulnerabilities,
    };

    CklDocument {
        asset,
        stigs: vec![stig],
    }
}

/// Generate CKL from STIG check results
pub fn generate_ckl(
    results: &[StigCheckResult],
    hostname: &str,
    ip_address: &str,
    stig_name: &str,
    stig_version: &str,
) -> Result<String> {
    let doc = stig_results_to_ckl(results, hostname, ip_address, stig_name, stig_version);
    CklGenerator::generate(&doc)
}

/// Parse existing CKL file
pub fn parse_ckl(xml: &str) -> Result<CklDocument> {
    use quick_xml::Reader;
    use quick_xml::events::Event;

    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut asset = CklAsset {
        host_name: String::new(),
        host_ip: String::new(),
        host_mac: None,
        host_fqdn: None,
        target_comment: None,
        role: AssetRole::None,
        asset_type: AssetType::Computing,
    };

    let mut stigs: Vec<CklStig> = Vec::new();
    let mut current_stig: Option<CklStig> = None;
    let mut current_vuln: Option<CklVulnerability> = None;
    let mut current_stig_data: Option<StigDataItem> = None;
    let mut current_element: Option<String> = None;
    let mut in_asset = false;
    let mut in_stig_info = false;
    let mut in_vuln = false;
    let mut in_stig_data = false;
    let stig_info = StigInfo {
        stig_id: String::new(),
        sid_name: String::new(),
        version: String::new(),
        release_info: String::new(),
        filename: String::new(),
    };

    loop {
        match reader.read_event() {
            Ok(Event::Start(ref e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                current_element = Some(name.clone());

                match name.as_str() {
                    "ASSET" => in_asset = true,
                    "iSTIG" => {
                        current_stig = Some(CklStig {
                            stig_info: StigInfo {
                                stig_id: String::new(),
                                sid_name: String::new(),
                                version: String::new(),
                                release_info: String::new(),
                                filename: String::new(),
                            },
                            vulnerabilities: Vec::new(),
                        });
                    }
                    "STIG_INFO" => in_stig_info = true,
                    "VULN" => {
                        in_vuln = true;
                        current_vuln = Some(CklVulnerability {
                            stig_data: Vec::new(),
                            status: CklStatus::NotReviewed,
                            finding_details: None,
                            comments: None,
                            severity_override: None,
                            severity_justification: None,
                        });
                    }
                    "STIG_DATA" => {
                        in_stig_data = true;
                        current_stig_data = Some(StigDataItem {
                            vuln_attribute: String::new(),
                            attribute_data: String::new(),
                        });
                    }
                    _ => {}
                }
            }
            Ok(Event::End(ref e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).to_string();

                match name.as_str() {
                    "ASSET" => in_asset = false,
                    "iSTIG" => {
                        if let Some(mut stig) = current_stig.take() {
                            stig.stig_info = stig_info.clone();
                            stigs.push(stig);
                        }
                    }
                    "STIG_INFO" => in_stig_info = false,
                    "VULN" => {
                        in_vuln = false;
                        if let (Some(stig), Some(vuln)) = (current_stig.as_mut(), current_vuln.take()) {
                            stig.vulnerabilities.push(vuln);
                        }
                    }
                    "STIG_DATA" => {
                        in_stig_data = false;
                        if let (Some(vuln), Some(data)) = (current_vuln.as_mut(), current_stig_data.take()) {
                            vuln.stig_data.push(data);
                        }
                    }
                    _ => {}
                }

                current_element = None;
            }
            Ok(Event::Text(ref e)) => {
                let text = String::from_utf8_lossy(e.as_ref()).to_string();

                if let Some(ref elem) = current_element {
                    if in_asset {
                        match elem.as_str() {
                            "HOST_NAME" => asset.host_name = text,
                            "HOST_IP" => asset.host_ip = text,
                            "HOST_MAC" => asset.host_mac = Some(text),
                            "HOST_FQDN" => asset.host_fqdn = Some(text),
                            "TARGET_COMMENT" => asset.target_comment = Some(text),
                            "ROLE" => {
                                asset.role = match text.as_str() {
                                    "Workstation" => AssetRole::Workstation,
                                    "Member Server" => AssetRole::MemberServer,
                                    "Domain Controller" => AssetRole::DomainController,
                                    _ => AssetRole::None,
                                };
                            }
                            _ => {}
                        }
                    } else if in_stig_info {
                        match elem.as_str() {
                            "SID_NAME" | "SID_DATA" => {
                                // Handle SI_DATA parsing
                            }
                            _ => {}
                        }
                    } else if in_vuln {
                        if in_stig_data {
                            if let Some(ref mut data) = current_stig_data {
                                match elem.as_str() {
                                    "VULN_ATTRIBUTE" => data.vuln_attribute = text,
                                    "ATTRIBUTE_DATA" => data.attribute_data = text,
                                    _ => {}
                                }
                            }
                        } else if let Some(ref mut vuln) = current_vuln {
                            match elem.as_str() {
                                "STATUS" => {
                                    vuln.status = match text.as_str() {
                                        "Open" => CklStatus::Open,
                                        "NotAFinding" => CklStatus::NotAFinding,
                                        "Not_Applicable" => CklStatus::NotApplicable,
                                        _ => CklStatus::NotReviewed,
                                    };
                                }
                                "FINDING_DETAILS" => vuln.finding_details = Some(text),
                                "COMMENTS" => vuln.comments = Some(text),
                                "SEVERITY_OVERRIDE" => vuln.severity_override = Some(text),
                                "SEVERITY_JUSTIFICATION" => vuln.severity_justification = Some(text),
                                _ => {}
                            }
                        }
                    }
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(anyhow::anyhow!("Error parsing CKL: {}", e)),
            _ => {}
        }
    }

    Ok(CklDocument { asset, stigs })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_ckl() {
        let results = vec![
            StigCheckResult {
                stig_id: "V-220697".to_string(),
                rule_id: "SV-220697r857091_rule".to_string(),
                title: "Windows 10 must have Credential Guard enabled".to_string(),
                category: StigCategory::CatI,
                status: StigCheckStatus::NotAFinding,
                finding_details: Some("Credential Guard is enabled".to_string()),
                expected: "Enabled".to_string(),
                actual: "Enabled".to_string(),
                remediation: None,
            },
        ];

        let ckl = generate_ckl(&results, "test-host", "192.168.1.100", "Windows 10", "V1R2").unwrap();

        assert!(ckl.contains("<CHECKLIST>"));
        assert!(ckl.contains("<HOST_NAME>test-host</HOST_NAME>"));
        assert!(ckl.contains("V-220697"));
        assert!(ckl.contains("<STATUS>NotAFinding</STATUS>"));
    }
}
