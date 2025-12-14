use anyhow::Result;
use std::path::Path;
use tokio::fs;

use crate::reports::types::{ReportData, ReportSection};
use crate::types::Severity;

/// Generate an HTML report
pub async fn generate(data: &ReportData, reports_dir: &str) -> Result<(String, i64)> {
    // Ensure reports directory exists
    fs::create_dir_all(reports_dir).await?;

    // Generate filename
    let filename = format!("{}.html", data.id);
    let file_path = Path::new(reports_dir).join(&filename);

    // Generate HTML content
    let html_content = generate_html(data);

    // Write to file
    fs::write(&file_path, &html_content).await?;

    let file_size = html_content.len() as i64;
    let path_str = file_path.to_string_lossy().to_string();

    Ok((path_str, file_size))
}

/// Generate the complete HTML document (public for PDF generation)
pub fn generate_html(data: &ReportData) -> String {
    let mut html = String::new();

    // Document head
    html.push_str(&format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{} - Security Assessment Report</title>
    <style>{}</style>
</head>
<body>
"#,
        html_escape(&data.name),
        get_css_styles()
    ));

    // Cover page
    html.push_str(&generate_cover_page(data));

    // Generate sections based on configuration
    for section in &data.sections {
        match section {
            ReportSection::TableOfContents => html.push_str(&generate_toc(data)),
            ReportSection::ExecutiveSummary => html.push_str(&generate_executive_summary(data)),
            ReportSection::RiskOverview => html.push_str(&generate_risk_overview(data)),
            ReportSection::HostInventory => html.push_str(&generate_host_inventory(data)),
            ReportSection::PortAnalysis => html.push_str(&generate_port_analysis(data)),
            ReportSection::VulnerabilityFindings => html.push_str(&generate_vulnerability_findings(data)),
            ReportSection::ServiceEnumeration => html.push_str(&generate_service_enumeration(data)),
            ReportSection::RemediationRecommendations => html.push_str(&generate_remediation(data)),
            ReportSection::Appendix => html.push_str(&generate_appendix(data)),
        }
    }

    // Footer
    html.push_str(&generate_footer(data));

    html.push_str("</body>\n</html>");

    html
}

fn generate_cover_page(data: &ReportData) -> String {
    let classification = data.options.classification.as_deref().unwrap_or("CONFIDENTIAL");
    let company = data.options.company_name.as_deref().unwrap_or("Client");
    let assessor = data.options.assessor_name.as_deref().unwrap_or("Security Team");

    format!(
        r#"
<div class="cover-page">
    <div class="classification">{}</div>
    <h1 class="report-title">{}</h1>
    <p class="subtitle">Security Assessment Report</p>
    <div class="cover-meta">
        <p><strong>Prepared for:</strong> {}</p>
        <p><strong>Prepared by:</strong> {}</p>
        <p><strong>Assessment Date:</strong> {}</p>
        <p><strong>Report Generated:</strong> {}</p>
    </div>
    <div class="cover-summary">
        <div class="summary-stat">
            <span class="stat-value">{}</span>
            <span class="stat-label">Hosts Scanned</span>
        </div>
        <div class="summary-stat">
            <span class="stat-value">{}</span>
            <span class="stat-label">Vulnerabilities</span>
        </div>
        <div class="summary-stat risk-{}">
            <span class="stat-value">{}</span>
            <span class="stat-label">Risk Score</span>
        </div>
    </div>
</div>
"#,
        html_escape(classification),
        html_escape(&data.name),
        html_escape(company),
        html_escape(assessor),
        data.scan_date.format("%Y-%m-%d"),
        data.created_at.format("%Y-%m-%d %H:%M UTC"),
        data.summary.total_hosts,
        data.summary.total_vulnerabilities,
        data.summary.overall_risk_level.to_lowercase(),
        data.summary.overall_risk_score
    )
}

fn generate_toc(data: &ReportData) -> String {
    let mut toc = String::from("<div class=\"section toc\"><h2>Table of Contents</h2><ul class=\"toc-list\">");

    for (i, section) in data.sections.iter().enumerate() {
        if *section != ReportSection::TableOfContents {
            toc.push_str(&format!(
                "<li><span class=\"toc-number\">{}</span> <a href=\"#{}\">{}</a></li>",
                i,
                section_id(section),
                section.title()
            ));
        }
    }

    toc.push_str("</ul></div>");
    toc
}

fn generate_executive_summary(data: &ReportData) -> String {
    let risk_class = data.summary.overall_risk_level.to_lowercase().replace(' ', "-");

    format!(
        r#"
<div class="section" id="executive-summary">
    <h2>Executive Summary</h2>

    <p>This report presents the findings of a security assessment conducted on <strong>{}</strong>.
    The assessment identified <strong>{} live hosts</strong> with <strong>{} open ports</strong>
    and discovered <strong>{} security vulnerabilities</strong>.</p>

    <div class="risk-summary">
        <div class="risk-badge risk-{}">
            <span class="risk-score">{}</span>
            <span class="risk-label">{} Risk</span>
        </div>
        <div class="vuln-breakdown">
            <div class="vuln-count critical"><span>{}</span> Critical</div>
            <div class="vuln-count high"><span>{}</span> High</div>
            <div class="vuln-count medium"><span>{}</span> Medium</div>
            <div class="vuln-count low"><span>{}</span> Low</div>
        </div>
    </div>

    {}

    <h3>Key Recommendations</h3>
    <ol class="recommendations">
        {}
    </ol>
</div>
"#,
        data.scan_date.format("%B %d, %Y"),
        data.summary.live_hosts,
        data.summary.open_ports,
        data.summary.total_vulnerabilities,
        risk_class,
        data.summary.overall_risk_score,
        data.summary.overall_risk_level,
        data.summary.critical_count,
        data.summary.high_count,
        data.summary.medium_count,
        data.summary.low_count,
        if !data.summary.top_findings.is_empty() {
            format!(
                r#"<h3>Critical Findings</h3><ul class="findings-list">{}</ul>"#,
                data.summary.top_findings.iter()
                    .map(|f| format!("<li>{}</li>", html_escape(f)))
                    .collect::<Vec<_>>()
                    .join("\n")
            )
        } else {
            String::new()
        },
        data.remediation.iter().take(5)
            .map(|r| format!("<li><strong>{}</strong> - {}</li>", html_escape(&r.title), html_escape(&r.description)))
            .collect::<Vec<_>>()
            .join("\n")
    )
}

fn generate_risk_overview(data: &ReportData) -> String {
    format!(
        r#"
<div class="section" id="risk-overview">
    <h2>Risk Overview</h2>

    <div class="stats-grid">
        <div class="stat-card">
            <div class="stat-value">{}</div>
            <div class="stat-label">Total Hosts</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">{}</div>
            <div class="stat-label">Live Hosts</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">{}</div>
            <div class="stat-label">Open Ports</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">{}</div>
            <div class="stat-label">Total Vulnerabilities</div>
        </div>
    </div>

    <h3>Vulnerability Distribution</h3>
    <div class="vuln-chart">
        {}
    </div>

    <h3>Affected Services</h3>
    <div class="services-list">
        {}
    </div>
</div>
"#,
        data.summary.total_hosts,
        data.summary.live_hosts,
        data.summary.open_ports,
        data.summary.total_vulnerabilities,
        generate_severity_bars(data),
        data.summary.affected_services.iter()
            .map(|s| format!(r#"<span class="service-tag">{}</span>"#, html_escape(s)))
            .collect::<Vec<_>>()
            .join(" ")
    )
}

fn generate_severity_bars(data: &ReportData) -> String {
    let total = data.summary.total_vulnerabilities.max(1) as f64;

    format!(
        r#"
<div class="severity-bar critical" style="width: {}%"><span>Critical: {}</span></div>
<div class="severity-bar high" style="width: {}%"><span>High: {}</span></div>
<div class="severity-bar medium" style="width: {}%"><span>Medium: {}</span></div>
<div class="severity-bar low" style="width: {}%"><span>Low: {}</span></div>
"#,
        (data.summary.critical_count as f64 / total * 100.0).min(100.0),
        data.summary.critical_count,
        (data.summary.high_count as f64 / total * 100.0).min(100.0),
        data.summary.high_count,
        (data.summary.medium_count as f64 / total * 100.0).min(100.0),
        data.summary.medium_count,
        (data.summary.low_count as f64 / total * 100.0).min(100.0),
        data.summary.low_count
    )
}

fn generate_host_inventory(data: &ReportData) -> String {
    let mut html = String::from(
        r#"<div class="section" id="host-inventory"><h2>Host Inventory</h2><table class="data-table"><thead><tr><th>IP Address</th><th>Hostname</th><th>Status</th><th>OS</th><th>Open Ports</th><th>Vulnerabilities</th></tr></thead><tbody>"#
    );

    for host in &data.hosts {
        let open_ports = host.ports.iter()
            .filter(|p| p.state == crate::types::PortState::Open)
            .count();

        html.push_str(&format!(
            r#"<tr><td>{}</td><td>{}</td><td class="{}">{}</td><td>{}</td><td>{}</td><td>{}</td></tr>"#,
            host.target.ip,
            host.target.hostname.as_deref().unwrap_or("-"),
            if host.is_alive { "status-up" } else { "status-down" },
            if host.is_alive { "Up" } else { "Down" },
            host.os_guess.as_ref().map(|os| os.os_family.as_str()).unwrap_or("-"),
            open_ports,
            host.vulnerabilities.len()
        ));
    }

    html.push_str("</tbody></table></div>");
    html
}

fn generate_port_analysis(data: &ReportData) -> String {
    let mut html = String::from(
        r#"<div class="section" id="port-analysis"><h2>Port Analysis</h2>"#
    );

    for host in &data.hosts {
        if host.ports.is_empty() {
            continue;
        }

        html.push_str(&format!(
            r#"<h3>{}{}</h3><table class="data-table"><thead><tr><th>Port</th><th>Protocol</th><th>State</th><th>Service</th><th>Version</th></tr></thead><tbody>"#,
            host.target.ip,
            host.target.hostname.as_ref().map(|h| format!(" ({})", h)).unwrap_or_default()
        ));

        for port in &host.ports {
            let service_name = port.service.as_ref().map(|s| s.name.as_str()).unwrap_or("-");
            let version = port.service.as_ref()
                .and_then(|s| s.version.as_deref())
                .unwrap_or("-");

            html.push_str(&format!(
                r#"<tr><td>{}</td><td>{:?}</td><td class="state-{}">{:?}</td><td>{}</td><td>{}</td></tr>"#,
                port.port,
                port.protocol,
                format!("{:?}", port.state).to_lowercase(),
                port.state,
                html_escape(service_name),
                html_escape(version)
            ));
        }

        html.push_str("</tbody></table>");
    }

    html.push_str("</div>");
    html
}

fn generate_vulnerability_findings(data: &ReportData) -> String {
    let mut html = String::from(
        r#"<div class="section" id="vulnerability-findings"><h2>Vulnerability Findings</h2>"#
    );

    if data.findings.is_empty() {
        html.push_str("<p>No vulnerabilities were identified during this assessment.</p>");
    } else {
        for finding in &data.findings {
            let severity_class = format!("{:?}", finding.severity).to_lowercase();

            html.push_str(&format!(
                r#"
<div class="finding-card">
    <div class="finding-header">
        <span class="severity-badge {}">{:?}</span>
        <h3>{}</h3>
        {}
    </div>
    <div class="finding-body">
        <p><strong>Description:</strong> {}</p>
        <p><strong>Impact:</strong> {}</p>
        <p><strong>Affected Hosts:</strong> {}</p>
        {}
        <p><strong>Remediation:</strong> {}</p>
        {}
    </div>
</div>
"#,
                severity_class,
                finding.severity,
                html_escape(&finding.title),
                finding.cve_id.as_ref().map(|cve| format!(r#"<span class="cve-tag">{}</span>"#, cve)).unwrap_or_default(),
                html_escape(&finding.description),
                html_escape(&finding.impact),
                finding.affected_hosts.join(", "),
                finding.affected_service.as_ref().map(|s| format!("<p><strong>Affected Service:</strong> {}</p>", html_escape(s))).unwrap_or_default(),
                html_escape(&finding.remediation),
                if !finding.references.is_empty() {
                    format!(
                        r#"<p><strong>References:</strong></p><ul>{}</ul>"#,
                        finding.references.iter()
                            .map(|r| format!(r#"<li><a href="{}" target="_blank">{}</a></li>"#, r, r))
                            .collect::<Vec<_>>()
                            .join("")
                    )
                } else {
                    String::new()
                }
            ));
        }
    }

    html.push_str("</div>");
    html
}

fn generate_service_enumeration(data: &ReportData) -> String {
    let mut html = String::from(
        r#"<div class="section" id="service-enumeration"><h2>Service Enumeration</h2>"#
    );

    let mut has_enumeration = false;

    for host in &data.hosts {
        for port in &host.ports {
            if let Some(ref service) = port.service {
                if let Some(ref enum_result) = service.enumeration {
                    if !enum_result.findings.is_empty() {
                        has_enumeration = true;

                        html.push_str(&format!(
                            r#"<h3>{}:{} ({})</h3><table class="data-table"><thead><tr><th>Finding Type</th><th>Value</th><th>Confidence</th></tr></thead><tbody>"#,
                            host.target.ip,
                            port.port,
                            html_escape(&service.name)
                        ));

                        for finding in &enum_result.findings {
                            html.push_str(&format!(
                                r#"<tr><td>{:?}</td><td class="finding-value">{}</td><td>{}%</td></tr>"#,
                                finding.finding_type,
                                html_escape(&finding.value),
                                finding.confidence
                            ));
                        }

                        html.push_str("</tbody></table>");
                    }
                }
            }
        }
    }

    if !has_enumeration {
        html.push_str("<p>No service enumeration data available.</p>");
    }

    html.push_str("</div>");
    html
}

fn generate_remediation(data: &ReportData) -> String {
    let mut html = String::from(
        r#"<div class="section" id="remediation-recommendations"><h2>Remediation Recommendations</h2>"#
    );

    if data.remediation.is_empty() {
        html.push_str("<p>No specific remediation recommendations at this time.</p>");
    } else {
        html.push_str("<div class=\"remediation-list\">");

        for rec in &data.remediation {
            html.push_str(&format!(
                r#"
<div class="remediation-item">
    <div class="priority-badge priority-{}">P{}</div>
    <div class="remediation-content">
        <h3>{}</h3>
        <p>{}</p>
        <div class="remediation-meta">
            <span><strong>Effort:</strong> {}</span>
            <span><strong>Timeline:</strong> {}</span>
        </div>
    </div>
</div>
"#,
                rec.priority,
                rec.priority,
                html_escape(&rec.title),
                html_escape(&rec.description),
                html_escape(&rec.effort_estimate),
                html_escape(&rec.timeline_suggestion)
            ));
        }

        html.push_str("</div>");
    }

    html.push_str("</div>");
    html
}

fn generate_appendix(data: &ReportData) -> String {
    format!(
        r#"
<div class="section" id="appendix">
    <h2>Appendix</h2>

    <h3>A. Assessment Methodology</h3>
    <p>This security assessment was conducted using HeroForge, an automated network reconnaissance
    and vulnerability assessment tool. The assessment followed standard penetration testing
    methodologies including:</p>
    <ul>
        <li>Network discovery and host enumeration</li>
        <li>Port scanning and service detection</li>
        <li>Service enumeration and banner grabbing</li>
        <li>Vulnerability identification and CVE mapping</li>
        <li>Risk scoring and prioritization</li>
    </ul>

    <h3>B. Scan Parameters</h3>
    <table class="data-table">
        <tr><th>Parameter</th><th>Value</th></tr>
        <tr><td>Scan ID</td><td>{}</td></tr>
        <tr><td>Scan Name</td><td>{}</td></tr>
        <tr><td>Assessment Date</td><td>{}</td></tr>
        <tr><td>Total Hosts</td><td>{}</td></tr>
        <tr><td>Report Template</td><td>{}</td></tr>
    </table>

    <h3>C. Disclaimer</h3>
    <p class="disclaimer">This report is intended for authorized security testing purposes only.
    The findings represent the state of the target systems at the time of assessment and may
    not reflect current conditions. Always obtain proper authorization before conducting
    security assessments.</p>
</div>
"#,
        data.scan_id,
        html_escape(&data.scan_name),
        data.scan_date.format("%Y-%m-%d %H:%M UTC"),
        data.summary.total_hosts,
        html_escape(&data.template.name)
    )
}

fn generate_footer(data: &ReportData) -> String {
    format!(
        r#"
<footer class="report-footer">
    <p>Generated by HeroForge Security Assessment Tool</p>
    <p>Report ID: {} | Generated: {}</p>
    <p class="disclaimer">For authorized security testing only.</p>
</footer>
"#,
        data.id,
        data.created_at.format("%Y-%m-%d %H:%M UTC")
    )
}

fn section_id(section: &ReportSection) -> &'static str {
    match section {
        ReportSection::TableOfContents => "toc",
        ReportSection::ExecutiveSummary => "executive-summary",
        ReportSection::RiskOverview => "risk-overview",
        ReportSection::HostInventory => "host-inventory",
        ReportSection::PortAnalysis => "port-analysis",
        ReportSection::VulnerabilityFindings => "vulnerability-findings",
        ReportSection::ServiceEnumeration => "service-enumeration",
        ReportSection::RemediationRecommendations => "remediation-recommendations",
        ReportSection::Appendix => "appendix",
    }
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

fn get_css_styles() -> &'static str {
    r#"
/* Reset and base */
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    line-height: 1.6;
    color: #1a1a2e;
    background: #fff;
    max-width: 1200px;
    margin: 0 auto;
    padding: 20px;
}

/* Cover page */
.cover-page {
    min-height: 90vh;
    display: flex;
    flex-direction: column;
    justify-content: center;
    align-items: center;
    text-align: center;
    page-break-after: always;
    border-bottom: 2px solid #e2e8f0;
    margin-bottom: 40px;
    padding-bottom: 40px;
}
.classification {
    background: #ef4444;
    color: white;
    padding: 8px 24px;
    font-weight: bold;
    text-transform: uppercase;
    letter-spacing: 2px;
    margin-bottom: 40px;
}
.report-title {
    font-size: 2.5rem;
    color: #1e3a5f;
    margin-bottom: 10px;
}
.subtitle {
    font-size: 1.2rem;
    color: #64748b;
    margin-bottom: 40px;
}
.cover-meta {
    margin-bottom: 40px;
}
.cover-meta p {
    margin: 8px 0;
    color: #475569;
}
.cover-summary {
    display: flex;
    gap: 40px;
}
.summary-stat {
    text-align: center;
}
.stat-value {
    display: block;
    font-size: 3rem;
    font-weight: bold;
    color: #1e3a5f;
}
.stat-label {
    color: #64748b;
    text-transform: uppercase;
    font-size: 0.85rem;
    letter-spacing: 1px;
}
.risk-critical .stat-value { color: #ef4444; }
.risk-very-high .stat-value { color: #f97316; }
.risk-high .stat-value { color: #f97316; }
.risk-medium .stat-value { color: #eab308; }
.risk-low .stat-value { color: #22c55e; }

/* Sections */
.section {
    margin-bottom: 40px;
    page-break-inside: avoid;
}
.section h2 {
    font-size: 1.75rem;
    color: #1e3a5f;
    border-bottom: 2px solid #3b82f6;
    padding-bottom: 10px;
    margin-bottom: 20px;
}
.section h3 {
    font-size: 1.25rem;
    color: #334155;
    margin: 20px 0 10px;
}

/* Table of Contents */
.toc-list {
    list-style: none;
}
.toc-list li {
    padding: 8px 0;
    border-bottom: 1px dotted #e2e8f0;
}
.toc-number {
    color: #3b82f6;
    font-weight: bold;
    margin-right: 10px;
}

/* Risk summary */
.risk-summary {
    display: flex;
    align-items: center;
    gap: 40px;
    background: #f8fafc;
    padding: 20px;
    border-radius: 8px;
    margin: 20px 0;
}
.risk-badge {
    text-align: center;
    padding: 20px;
    border-radius: 8px;
    min-width: 120px;
}
.risk-badge.risk-critical { background: #fef2f2; border: 2px solid #ef4444; }
.risk-badge.risk-very-high { background: #fff7ed; border: 2px solid #f97316; }
.risk-badge.risk-high { background: #fff7ed; border: 2px solid #f97316; }
.risk-badge.risk-medium { background: #fefce8; border: 2px solid #eab308; }
.risk-badge.risk-low { background: #f0fdf4; border: 2px solid #22c55e; }
.risk-score {
    display: block;
    font-size: 2.5rem;
    font-weight: bold;
}
.risk-label {
    font-size: 0.9rem;
    text-transform: uppercase;
}

/* Vulnerability counts */
.vuln-breakdown {
    display: flex;
    gap: 20px;
}
.vuln-count {
    padding: 10px 20px;
    border-radius: 4px;
    font-weight: bold;
}
.vuln-count span {
    font-size: 1.5rem;
    margin-right: 5px;
}
.vuln-count.critical { background: #fef2f2; color: #dc2626; }
.vuln-count.high { background: #fff7ed; color: #ea580c; }
.vuln-count.medium { background: #fefce8; color: #ca8a04; }
.vuln-count.low { background: #eff6ff; color: #2563eb; }

/* Stats grid */
.stats-grid {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 20px;
    margin: 20px 0;
}
.stat-card {
    background: #f8fafc;
    padding: 20px;
    border-radius: 8px;
    text-align: center;
    border: 1px solid #e2e8f0;
}
.stat-card .stat-value {
    font-size: 2rem;
}
.stat-card .stat-label {
    font-size: 0.85rem;
}

/* Severity bars */
.vuln-chart {
    margin: 20px 0;
}
.severity-bar {
    height: 30px;
    margin: 5px 0;
    border-radius: 4px;
    display: flex;
    align-items: center;
    padding: 0 10px;
    color: white;
    font-weight: bold;
    min-width: 80px;
}
.severity-bar.critical { background: #ef4444; }
.severity-bar.high { background: #f97316; }
.severity-bar.medium { background: #eab308; }
.severity-bar.low { background: #3b82f6; }

/* Services list */
.services-list {
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
    margin: 10px 0;
}
.service-tag {
    background: #e2e8f0;
    padding: 5px 15px;
    border-radius: 20px;
    font-size: 0.9rem;
}

/* Data tables */
.data-table {
    width: 100%;
    border-collapse: collapse;
    margin: 15px 0;
}
.data-table th, .data-table td {
    padding: 12px;
    text-align: left;
    border-bottom: 1px solid #e2e8f0;
}
.data-table th {
    background: #f1f5f9;
    font-weight: 600;
    color: #334155;
}
.data-table tr:hover {
    background: #f8fafc;
}
.status-up { color: #22c55e; font-weight: bold; }
.status-down { color: #ef4444; }
.state-open { color: #22c55e; }
.state-closed { color: #ef4444; }
.state-filtered { color: #eab308; }

/* Finding cards */
.finding-card {
    border: 1px solid #e2e8f0;
    border-radius: 8px;
    margin: 20px 0;
    overflow: hidden;
}
.finding-header {
    background: #f8fafc;
    padding: 15px 20px;
    display: flex;
    align-items: center;
    gap: 15px;
}
.finding-header h3 {
    margin: 0;
    flex-grow: 1;
}
.severity-badge {
    padding: 5px 15px;
    border-radius: 4px;
    font-weight: bold;
    text-transform: uppercase;
    font-size: 0.8rem;
    color: white;
}
.severity-badge.critical { background: #ef4444; }
.severity-badge.high { background: #f97316; }
.severity-badge.medium { background: #eab308; }
.severity-badge.low { background: #3b82f6; }
.cve-tag {
    background: #1e3a5f;
    color: white;
    padding: 3px 10px;
    border-radius: 4px;
    font-size: 0.85rem;
    font-family: monospace;
}
.finding-body {
    padding: 20px;
}
.finding-body p {
    margin: 10px 0;
}
.finding-value {
    font-family: monospace;
    max-width: 400px;
    overflow: hidden;
    text-overflow: ellipsis;
}

/* Remediation items */
.remediation-list {
    margin: 20px 0;
}
.remediation-item {
    display: flex;
    gap: 20px;
    padding: 20px;
    border: 1px solid #e2e8f0;
    border-radius: 8px;
    margin: 15px 0;
}
.priority-badge {
    width: 50px;
    height: 50px;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    font-weight: bold;
    font-size: 1.2rem;
    color: white;
    flex-shrink: 0;
}
.priority-1 { background: #ef4444; }
.priority-2 { background: #f97316; }
.priority-3 { background: #eab308; }
.priority-4, .priority-5 { background: #3b82f6; }
.remediation-content h3 {
    margin: 0 0 10px 0;
}
.remediation-meta {
    display: flex;
    gap: 30px;
    margin-top: 15px;
    color: #64748b;
    font-size: 0.9rem;
}

/* Appendix */
.disclaimer {
    background: #fef3c7;
    border: 1px solid #f59e0b;
    padding: 15px;
    border-radius: 4px;
    margin: 20px 0;
}

/* Footer */
.report-footer {
    margin-top: 60px;
    padding-top: 20px;
    border-top: 2px solid #e2e8f0;
    text-align: center;
    color: #64748b;
    font-size: 0.9rem;
}

/* Print styles */
@media print {
    body { padding: 0; }
    .cover-page { min-height: auto; page-break-after: always; }
    .section { page-break-inside: avoid; }
    .finding-card { break-inside: avoid; }
    .data-table { font-size: 0.85rem; }
}
"#
}
