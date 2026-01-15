//! DOCX Report Export
//!
//! Generates Microsoft Word documents from scan reports.
//! Uses Open XML format (DOCX) for cross-platform compatibility.

use anyhow::Result;
use std::path::Path;
use tokio::fs;

use crate::reports::types::{FindingDetail, ReportData, ReportScreenshot, ReportSummary};
use crate::types::Severity;
use std::io::{Cursor, Write};
use zip::write::SimpleFileOptions;
use zip::ZipWriter;

/// Generate a DOCX report and save to file
pub async fn generate(data: &ReportData, reports_dir: &str) -> Result<(String, i64)> {
    // Ensure reports directory exists
    fs::create_dir_all(reports_dir).await?;

    // Generate filename
    let filename = format!("{}.docx", data.id);
    let file_path = Path::new(reports_dir).join(&filename);

    // Generate DOCX bytes
    let docx_bytes = generate_docx(data)?;
    let file_size = docx_bytes.len() as i64;

    // Write to file
    fs::write(&file_path, &docx_bytes).await?;

    let path_str = file_path.to_string_lossy().to_string();
    Ok((path_str, file_size))
}

/// Generate a DOCX report from scan data (returns raw bytes)
pub fn generate_docx(data: &ReportData) -> anyhow::Result<Vec<u8>> {
    let mut buffer = Cursor::new(Vec::new());
    let mut zip = ZipWriter::new(&mut buffer);
    let options = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);

    // Add required DOCX structure files
    add_content_types(&mut zip, options)?;
    add_rels(&mut zip, options)?;
    add_document_xml(&mut zip, options, data)?;
    add_styles_xml(&mut zip, options)?;
    add_settings_xml(&mut zip, options)?;
    add_numbering_xml(&mut zip, options)?;

    zip.finish()?;
    Ok(buffer.into_inner())
}

fn add_content_types<W: Write + std::io::Seek>(
    zip: &mut ZipWriter<W>,
    options: SimpleFileOptions,
) -> anyhow::Result<()> {
    zip.start_file("[Content_Types].xml", options)?;
    zip.write_all(
        br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
  <Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>
  <Override PartName="/word/settings.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.settings+xml"/>
  <Override PartName="/word/numbering.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.numbering+xml"/>
</Types>"#,
    )?;
    Ok(())
}

fn add_rels<W: Write + std::io::Seek>(
    zip: &mut ZipWriter<W>,
    options: SimpleFileOptions,
) -> anyhow::Result<()> {
    zip.start_file("_rels/.rels", options)?;
    zip.write_all(
        br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>"#,
    )?;

    zip.start_file("word/_rels/document.xml.rels", options)?;
    zip.write_all(
        br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/settings" Target="settings.xml"/>
  <Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/numbering" Target="numbering.xml"/>
</Relationships>"#,
    )?;

    Ok(())
}

fn add_document_xml<W: Write + std::io::Seek>(
    zip: &mut ZipWriter<W>,
    options: SimpleFileOptions,
    data: &ReportData,
) -> anyhow::Result<()> {
    zip.start_file("word/document.xml", options)?;

    let mut content = String::from(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"
            xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <w:body>"#,
    );

    // Title
    content.push_str(&format!(
        r#"
    <w:p>
      <w:pPr><w:pStyle w:val="Title"/></w:pPr>
      <w:r><w:t>{}</w:t></w:r>
    </w:p>"#,
        escape_xml(&data.name)
    ));

    // Subtitle with date
    content.push_str(&format!(
        r#"
    <w:p>
      <w:pPr><w:pStyle w:val="Subtitle"/></w:pPr>
      <w:r><w:t>Security Assessment Report - {}</w:t></w:r>
    </w:p>"#,
        data.created_at.format("%Y-%m-%d")
    ));

    // Company name if provided
    if let Some(ref company) = data.options.company_name {
        content.push_str(&format!(
            r#"
    <w:p>
      <w:pPr><w:jc w:val="center"/></w:pPr>
      <w:r><w:t>Prepared for: {}</w:t></w:r>
    </w:p>"#,
            escape_xml(company)
        ));
    }

    // Classification if provided
    if let Some(ref classification) = data.options.classification {
        content.push_str(&format!(
            r#"
    <w:p>
      <w:pPr><w:jc w:val="center"/></w:pPr>
      <w:r><w:rPr><w:b/><w:color w:val="FF0000"/></w:rPr><w:t>{}</w:t></w:r>
    </w:p>"#,
            escape_xml(classification)
        ));
    }

    // Page break
    content.push_str(r#"<w:p><w:r><w:br w:type="page"/></w:r></w:p>"#);

    // Executive Summary
    add_heading(&mut content, "Executive Summary", 1);
    add_executive_summary(&mut content, &data.summary);

    // Risk Overview
    add_heading(&mut content, "Risk Overview", 1);
    add_risk_overview(&mut content, &data.summary);

    // Vulnerability Findings
    if !data.findings.is_empty() {
        add_heading(&mut content, "Vulnerability Findings", 1);
        add_findings(&mut content, &data.findings);
    }

    // Host Inventory
    if !data.hosts.is_empty() {
        add_heading(&mut content, "Host Inventory", 1);
        add_host_inventory(&mut content, data);
    }

    // Remediation Recommendations
    if !data.remediation.is_empty() {
        add_heading(&mut content, "Remediation Recommendations", 1);
        add_remediation(&mut content, data);
    }

    // Screenshots/Evidence
    if !data.screenshots.is_empty() && data.options.include_screenshots {
        add_heading(&mut content, "Visual Evidence", 1);
        add_screenshots_section(&mut content, &data.screenshots);
    }

    // Close document
    content.push_str(
        r#"
    <w:sectPr>
      <w:pgSz w:w="12240" w:h="15840"/>
      <w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1440"/>
    </w:sectPr>
  </w:body>
</w:document>"#,
    );

    zip.write_all(content.as_bytes())?;
    Ok(())
}

fn add_heading(content: &mut String, text: &str, level: u8) {
    let style = format!("Heading{}", level);
    content.push_str(&format!(
        r#"
    <w:p>
      <w:pPr><w:pStyle w:val="{}"/></w:pPr>
      <w:r><w:t>{}</w:t></w:r>
    </w:p>"#,
        style,
        escape_xml(text)
    ));
}

fn add_paragraph(content: &mut String, text: &str) {
    content.push_str(&format!(
        r#"
    <w:p>
      <w:r><w:t>{}</w:t></w:r>
    </w:p>"#,
        escape_xml(text)
    ));
}

fn add_executive_summary(content: &mut String, summary: &ReportSummary) {
    add_paragraph(
        content,
        &format!(
            "This security assessment identified {} vulnerabilities across {} live hosts. \
            The overall risk level is {} with a risk score of {}/100.",
            summary.total_vulnerabilities,
            summary.live_hosts,
            summary.overall_risk_level,
            summary.overall_risk_score
        ),
    );

    add_paragraph(
        content,
        &format!(
            "Breakdown by severity: {} Critical, {} High, {} Medium, {} Low.",
            summary.critical_count, summary.high_count, summary.medium_count, summary.low_count
        ),
    );
}

fn add_risk_overview(content: &mut String, summary: &ReportSummary) {
    // Summary table
    content.push_str(
        r#"
    <w:tbl>
      <w:tblPr>
        <w:tblStyle w:val="TableGrid"/>
        <w:tblW w:w="5000" w:type="pct"/>
      </w:tblPr>"#,
    );

    // Header row
    add_table_row(content, &["Metric", "Value"], true);

    // Data rows
    add_table_row(
        content,
        &["Total Hosts", &summary.total_hosts.to_string()],
        false,
    );
    add_table_row(
        content,
        &["Live Hosts", &summary.live_hosts.to_string()],
        false,
    );
    add_table_row(
        content,
        &["Open Ports", &summary.open_ports.to_string()],
        false,
    );
    add_table_row(
        content,
        &["Total Vulnerabilities", &summary.total_vulnerabilities.to_string()],
        false,
    );
    add_table_row(
        content,
        &["Critical", &summary.critical_count.to_string()],
        false,
    );
    add_table_row(
        content,
        &["High", &summary.high_count.to_string()],
        false,
    );
    add_table_row(
        content,
        &["Medium", &summary.medium_count.to_string()],
        false,
    );
    add_table_row(
        content,
        &["Low", &summary.low_count.to_string()],
        false,
    );
    add_table_row(
        content,
        &["Risk Score", &format!("{}/100", summary.overall_risk_score)],
        false,
    );
    add_table_row(
        content,
        &["Risk Level", &summary.overall_risk_level],
        false,
    );

    content.push_str("</w:tbl>");
}

fn add_findings(content: &mut String, findings: &[FindingDetail]) {
    for (i, finding) in findings.iter().enumerate() {
        add_heading(content, &format!("{}. {}", i + 1, finding.title), 2);

        // Severity badge
        let severity_color = match finding.severity {
            Severity::Critical => "8B0000",
            Severity::High => "FF4500",
            Severity::Medium => "FFA500",
            Severity::Low => "228B22",
        };

        content.push_str(&format!(
            r#"
    <w:p>
      <w:r><w:rPr><w:b/><w:color w:val="{}"/></w:rPr><w:t>Severity: {:?}</w:t></w:r>
    </w:p>"#,
            severity_color, finding.severity
        ));

        if let Some(ref cve) = finding.cve_id {
            add_paragraph(content, &format!("CVE: {}", cve));
        }

        add_heading(content, "Description", 3);
        add_paragraph(content, &finding.description);

        add_heading(content, "Impact", 3);
        add_paragraph(content, &finding.impact);

        add_heading(content, "Affected Hosts", 3);
        add_paragraph(content, &finding.affected_hosts.join(", "));

        add_heading(content, "Remediation", 3);
        add_paragraph(content, &finding.remediation);

        // Page break between findings
        if i < findings.len() - 1 {
            content.push_str(r#"<w:p><w:r><w:br w:type="page"/></w:r></w:p>"#);
        }
    }
}

fn add_host_inventory(content: &mut String, data: &ReportData) {
    content.push_str(
        r#"
    <w:tbl>
      <w:tblPr>
        <w:tblStyle w:val="TableGrid"/>
        <w:tblW w:w="5000" w:type="pct"/>
      </w:tblPr>"#,
    );

    add_table_row(content, &["IP Address", "Hostname", "OS", "Open Ports", "Vulnerabilities"], true);

    for host in &data.hosts {
        let ip = host.target.ip.to_string();
        let hostname = host.target.hostname.clone().unwrap_or_else(|| "-".to_string());
        let os = host
            .os_guess
            .as_ref()
            .map(|o| format!("{} {}", o.os_family, o.os_version.as_deref().unwrap_or("")))
            .unwrap_or_else(|| "Unknown".to_string());
        let open_ports = host.ports.iter().filter(|p| p.state == crate::types::PortState::Open).count();
        let vuln_count = host.vulnerabilities.len();

        add_table_row(
            content,
            &[
                &ip,
                &hostname,
                &os,
                &open_ports.to_string(),
                &vuln_count.to_string(),
            ],
            false,
        );
    }

    content.push_str("</w:tbl>");
}

fn add_remediation(content: &mut String, data: &ReportData) {
    for rec in &data.remediation {
        add_heading(content, &format!("Priority {}: {}", rec.priority, rec.title), 2);
        add_paragraph(content, &rec.description);
        add_paragraph(content, &format!("Effort Estimate: {}", rec.effort_estimate));
        add_paragraph(content, &format!("Timeline: {}", rec.timeline_suggestion));
    }
}

fn add_screenshots_section(content: &mut String, screenshots: &[ReportScreenshot]) {
    for screenshot in screenshots {
        add_heading(content, &screenshot.title, 2);
        if let Some(ref desc) = screenshot.description {
            add_paragraph(content, desc);
        }
        add_paragraph(content, &format!("File: {}", screenshot.file_path));
        add_paragraph(content, &format!("Captured: {}", screenshot.captured_at.format("%Y-%m-%d %H:%M:%S")));
    }
}

fn add_table_row(content: &mut String, cells: &[&str], is_header: bool) {
    content.push_str("<w:tr>");
    for cell in cells {
        content.push_str("<w:tc><w:p>");
        if is_header {
            content.push_str(&format!(
                r#"<w:r><w:rPr><w:b/></w:rPr><w:t>{}</w:t></w:r>"#,
                escape_xml(cell)
            ));
        } else {
            content.push_str(&format!(r#"<w:r><w:t>{}</w:t></w:r>"#, escape_xml(cell)));
        }
        content.push_str("</w:p></w:tc>");
    }
    content.push_str("</w:tr>");
}

fn add_styles_xml<W: Write + std::io::Seek>(
    zip: &mut ZipWriter<W>,
    options: SimpleFileOptions,
) -> anyhow::Result<()> {
    zip.start_file("word/styles.xml", options)?;
    zip.write_all(
        br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:style w:type="paragraph" w:styleId="Title">
    <w:name w:val="Title"/>
    <w:pPr><w:jc w:val="center"/></w:pPr>
    <w:rPr><w:b/><w:sz w:val="56"/></w:rPr>
  </w:style>
  <w:style w:type="paragraph" w:styleId="Subtitle">
    <w:name w:val="Subtitle"/>
    <w:pPr><w:jc w:val="center"/></w:pPr>
    <w:rPr><w:sz w:val="32"/><w:color w:val="666666"/></w:rPr>
  </w:style>
  <w:style w:type="paragraph" w:styleId="Heading1">
    <w:name w:val="Heading 1"/>
    <w:pPr><w:spacing w:before="240" w:after="120"/></w:pPr>
    <w:rPr><w:b/><w:sz w:val="36"/><w:color w:val="1F4E79"/></w:rPr>
  </w:style>
  <w:style w:type="paragraph" w:styleId="Heading2">
    <w:name w:val="Heading 2"/>
    <w:pPr><w:spacing w:before="200" w:after="80"/></w:pPr>
    <w:rPr><w:b/><w:sz w:val="28"/><w:color w:val="2E75B6"/></w:rPr>
  </w:style>
  <w:style w:type="paragraph" w:styleId="Heading3">
    <w:name w:val="Heading 3"/>
    <w:pPr><w:spacing w:before="160" w:after="60"/></w:pPr>
    <w:rPr><w:b/><w:sz w:val="24"/><w:color w:val="5B9BD5"/></w:rPr>
  </w:style>
  <w:style w:type="table" w:styleId="TableGrid">
    <w:name w:val="Table Grid"/>
    <w:tblPr>
      <w:tblBorders>
        <w:top w:val="single" w:sz="4" w:color="auto"/>
        <w:left w:val="single" w:sz="4" w:color="auto"/>
        <w:bottom w:val="single" w:sz="4" w:color="auto"/>
        <w:right w:val="single" w:sz="4" w:color="auto"/>
        <w:insideH w:val="single" w:sz="4" w:color="auto"/>
        <w:insideV w:val="single" w:sz="4" w:color="auto"/>
      </w:tblBorders>
    </w:tblPr>
  </w:style>
</w:styles>"#,
    )?;
    Ok(())
}

fn add_settings_xml<W: Write + std::io::Seek>(
    zip: &mut ZipWriter<W>,
    options: SimpleFileOptions,
) -> anyhow::Result<()> {
    zip.start_file("word/settings.xml", options)?;
    zip.write_all(
        br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:settings xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:zoom w:percent="100"/>
  <w:defaultTabStop w:val="720"/>
</w:settings>"#,
    )?;
    Ok(())
}

fn add_numbering_xml<W: Write + std::io::Seek>(
    zip: &mut ZipWriter<W>,
    options: SimpleFileOptions,
) -> anyhow::Result<()> {
    zip.start_file("word/numbering.xml", options)?;
    zip.write_all(
        br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:numbering xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
</w:numbering>"#,
    )?;
    Ok(())
}

fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reports::types::{ReportOptions, ReportTemplate};
    use chrono::Utc;

    #[test]
    fn test_generate_docx() {
        let data = ReportData {
            id: "test-report".to_string(),
            name: "Test Security Report".to_string(),
            description: Some("Test report".to_string()),
            scan_id: "scan-123".to_string(),
            scan_name: "Test Scan".to_string(),
            created_at: Utc::now(),
            scan_date: Utc::now(),
            template: ReportTemplate::technical(),
            sections: vec![],
            options: ReportOptions::default(),
            hosts: vec![],
            summary: crate::reports::types::ReportSummary {
                total_hosts: 10,
                live_hosts: 8,
                total_ports: 100,
                open_ports: 45,
                total_vulnerabilities: 25,
                critical_count: 2,
                high_count: 5,
                medium_count: 10,
                low_count: 8,
                overall_risk_score: 65,
                overall_risk_level: "High".to_string(),
                top_findings: vec![],
                affected_services: vec![],
            },
            findings: vec![],
            secrets: vec![],
            remediation: vec![],
            screenshots: vec![],
            operator_notes: None,
            finding_notes: std::collections::HashMap::new(),
        };

        let result = generate_docx(&data);
        assert!(result.is_ok());
        let bytes = result.unwrap();
        // DOCX files start with ZIP signature
        assert!(bytes.len() > 100);
        assert_eq!(&bytes[0..4], &[0x50, 0x4B, 0x03, 0x04]);
    }
}
