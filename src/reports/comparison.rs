//! Report Comparison Module
//!
//! Compares two security scan reports to identify changes in:
//! - New vulnerabilities discovered
//! - Resolved/remediated vulnerabilities
//! - Severity changes
//! - Host changes (new/removed)
//! - Risk score trends

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

use crate::reports::types::{FindingDetail, ReportData, ReportSummary};
use crate::types::Severity;

/// Result of comparing two reports
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportComparison {
    /// ID of the comparison
    pub id: String,
    /// First (older) report ID
    pub report_a_id: String,
    /// First report name
    pub report_a_name: String,
    /// First report date
    pub report_a_date: DateTime<Utc>,
    /// Second (newer) report ID
    pub report_b_id: String,
    /// Second report name
    pub report_b_name: String,
    /// Second report date
    pub report_b_date: DateTime<Utc>,
    /// Comparison timestamp
    pub compared_at: DateTime<Utc>,
    /// Summary of changes
    pub summary: ComparisonSummary,
    /// New findings in report B
    pub new_findings: Vec<FindingChange>,
    /// Findings resolved (in A but not B)
    pub resolved_findings: Vec<FindingChange>,
    /// Findings with changed severity
    pub severity_changes: Vec<SeverityChange>,
    /// Host changes
    pub host_changes: HostChanges,
    /// Risk score comparison
    pub risk_comparison: RiskComparison,
}

/// Summary of changes between reports
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComparisonSummary {
    /// Number of new vulnerabilities
    pub new_vulnerabilities: usize,
    /// Number of resolved vulnerabilities
    pub resolved_vulnerabilities: usize,
    /// Number of severity upgrades (e.g., medium -> high)
    pub severity_upgrades: usize,
    /// Number of severity downgrades (e.g., high -> medium)
    pub severity_downgrades: usize,
    /// Number of new hosts discovered
    pub new_hosts: usize,
    /// Number of hosts no longer present
    pub removed_hosts: usize,
    /// Risk score change (positive = worsened, negative = improved)
    pub risk_score_change: i32,
    /// Overall assessment
    pub overall_assessment: String,
    /// Trend indicator
    pub trend: SecurityTrend,
}

/// Security trend indicator
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SecurityTrend {
    Improving,
    Stable,
    Worsening,
}

/// A finding change entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingChange {
    /// Finding title
    pub title: String,
    /// CVE ID if available
    pub cve_id: Option<String>,
    /// Severity level
    pub severity: Severity,
    /// Description
    pub description: String,
    /// Affected hosts
    pub affected_hosts: Vec<String>,
    /// Impact description
    pub impact: String,
}

/// Severity change entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeverityChange {
    /// Finding title
    pub title: String,
    /// CVE ID if available
    pub cve_id: Option<String>,
    /// Previous severity
    pub previous_severity: Severity,
    /// New severity
    pub new_severity: Severity,
    /// Affected hosts
    pub affected_hosts: Vec<String>,
    /// Change reason (if known)
    pub reason: Option<String>,
}

/// Host changes between reports
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostChanges {
    /// New hosts in report B
    pub new_hosts: Vec<HostChange>,
    /// Hosts removed (in A but not B)
    pub removed_hosts: Vec<HostChange>,
    /// Hosts with changed vulnerability counts
    pub vulnerability_changes: Vec<HostVulnerabilityChange>,
}

/// Host change entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostChange {
    /// IP address
    pub ip: String,
    /// Hostname
    pub hostname: Option<String>,
    /// Operating system
    pub os: Option<String>,
    /// Open port count
    pub open_ports: usize,
    /// Vulnerability count
    pub vulnerability_count: usize,
}

/// Host vulnerability change
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostVulnerabilityChange {
    /// IP address
    pub ip: String,
    /// Hostname
    pub hostname: Option<String>,
    /// Previous vulnerability count
    pub previous_count: usize,
    /// New vulnerability count
    pub new_count: usize,
    /// Change (positive = more vulns)
    pub change: i32,
}

/// Risk score comparison
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskComparison {
    /// Previous risk score (0-100)
    pub previous_score: u8,
    /// New risk score (0-100)
    pub new_score: u8,
    /// Previous risk level
    pub previous_level: String,
    /// New risk level
    pub new_level: String,
    /// Score change
    pub change: i32,
    /// Change percentage
    pub change_percent: f32,
}

/// Compare two reports
pub fn compare_reports(report_a: &ReportData, report_b: &ReportData) -> Result<ReportComparison> {
    let comparison_id = uuid::Uuid::new_v4().to_string();

    // Build finding maps for comparison
    let findings_a = build_finding_map(&report_a.findings);
    let findings_b = build_finding_map(&report_b.findings);

    // Find new findings (in B but not A)
    let new_findings = find_new_findings(&findings_a, &findings_b);

    // Find resolved findings (in A but not B)
    let resolved_findings = find_resolved_findings(&findings_a, &findings_b);

    // Find severity changes
    let severity_changes = find_severity_changes(&findings_a, &findings_b);

    // Analyze host changes
    let host_changes = analyze_host_changes(report_a, report_b);

    // Compare risk scores
    let risk_comparison = compare_risk_scores(&report_a.summary, &report_b.summary);

    // Build summary
    let summary = build_comparison_summary(
        &new_findings,
        &resolved_findings,
        &severity_changes,
        &host_changes,
        &risk_comparison,
    );

    Ok(ReportComparison {
        id: comparison_id,
        report_a_id: report_a.id.clone(),
        report_a_name: report_a.name.clone(),
        report_a_date: report_a.scan_date,
        report_b_id: report_b.id.clone(),
        report_b_name: report_b.name.clone(),
        report_b_date: report_b.scan_date,
        compared_at: Utc::now(),
        summary,
        new_findings,
        resolved_findings,
        severity_changes,
        host_changes,
        risk_comparison,
    })
}

/// Build a map of findings by unique key
fn build_finding_map(findings: &[FindingDetail]) -> HashMap<String, &FindingDetail> {
    findings
        .iter()
        .map(|f| (finding_key(f), f))
        .collect()
}

/// Generate a unique key for a finding
fn finding_key(finding: &FindingDetail) -> String {
    // Use CVE ID if available, otherwise use title + first affected host
    if let Some(ref cve) = finding.cve_id {
        cve.clone()
    } else {
        let host = finding.affected_hosts.first()
            .map(|h| h.as_str())
            .unwrap_or("unknown");
        format!("{}:{}", finding.title, host)
    }
}

/// Find new findings (in B but not A)
fn find_new_findings(
    findings_a: &HashMap<String, &FindingDetail>,
    findings_b: &HashMap<String, &FindingDetail>,
) -> Vec<FindingChange> {
    findings_b
        .iter()
        .filter(|(key, _)| !findings_a.contains_key(*key))
        .map(|(_, finding)| FindingChange {
            title: finding.title.clone(),
            cve_id: finding.cve_id.clone(),
            severity: finding.severity.clone(),
            description: finding.description.clone(),
            affected_hosts: finding.affected_hosts.clone(),
            impact: finding.impact.clone(),
        })
        .collect()
}

/// Find resolved findings (in A but not B)
fn find_resolved_findings(
    findings_a: &HashMap<String, &FindingDetail>,
    findings_b: &HashMap<String, &FindingDetail>,
) -> Vec<FindingChange> {
    findings_a
        .iter()
        .filter(|(key, _)| !findings_b.contains_key(*key))
        .map(|(_, finding)| FindingChange {
            title: finding.title.clone(),
            cve_id: finding.cve_id.clone(),
            severity: finding.severity.clone(),
            description: finding.description.clone(),
            affected_hosts: finding.affected_hosts.clone(),
            impact: finding.impact.clone(),
        })
        .collect()
}

/// Find findings with severity changes
fn find_severity_changes(
    findings_a: &HashMap<String, &FindingDetail>,
    findings_b: &HashMap<String, &FindingDetail>,
) -> Vec<SeverityChange> {
    findings_a
        .iter()
        .filter_map(|(key, finding_a)| {
            findings_b.get(key).and_then(|finding_b| {
                if finding_a.severity != finding_b.severity {
                    Some(SeverityChange {
                        title: finding_b.title.clone(),
                        cve_id: finding_b.cve_id.clone(),
                        previous_severity: finding_a.severity.clone(),
                        new_severity: finding_b.severity.clone(),
                        affected_hosts: finding_b.affected_hosts.clone(),
                        reason: None,
                    })
                } else {
                    None
                }
            })
        })
        .collect()
}

/// Analyze host changes between reports
fn analyze_host_changes(report_a: &ReportData, report_b: &ReportData) -> HostChanges {
    let hosts_a: HashMap<String, _> = report_a.hosts
        .iter()
        .map(|h| (h.target.ip.to_string(), h))
        .collect();

    let hosts_b: HashMap<String, _> = report_b.hosts
        .iter()
        .map(|h| (h.target.ip.to_string(), h))
        .collect();

    // New hosts
    let new_hosts: Vec<HostChange> = hosts_b
        .iter()
        .filter(|(ip, _)| !hosts_a.contains_key(*ip))
        .map(|(_, host)| {
            let open_ports = host.ports.iter()
                .filter(|p| p.state == crate::types::PortState::Open)
                .count();
            HostChange {
                ip: host.target.ip.to_string(),
                hostname: host.target.hostname.clone(),
                os: host.os_guess.as_ref().map(|o| o.os_family.clone()),
                open_ports,
                vulnerability_count: host.vulnerabilities.len(),
            }
        })
        .collect();

    // Removed hosts
    let removed_hosts: Vec<HostChange> = hosts_a
        .iter()
        .filter(|(ip, _)| !hosts_b.contains_key(*ip))
        .map(|(_, host)| {
            let open_ports = host.ports.iter()
                .filter(|p| p.state == crate::types::PortState::Open)
                .count();
            HostChange {
                ip: host.target.ip.to_string(),
                hostname: host.target.hostname.clone(),
                os: host.os_guess.as_ref().map(|o| o.os_family.clone()),
                open_ports,
                vulnerability_count: host.vulnerabilities.len(),
            }
        })
        .collect();

    // Vulnerability count changes
    let vulnerability_changes: Vec<HostVulnerabilityChange> = hosts_a
        .iter()
        .filter_map(|(ip, host_a)| {
            hosts_b.get(ip).and_then(|host_b| {
                let prev_count = host_a.vulnerabilities.len();
                let new_count = host_b.vulnerabilities.len();
                if prev_count != new_count {
                    Some(HostVulnerabilityChange {
                        ip: ip.clone(),
                        hostname: host_b.target.hostname.clone(),
                        previous_count: prev_count,
                        new_count,
                        change: new_count as i32 - prev_count as i32,
                    })
                } else {
                    None
                }
            })
        })
        .collect();

    HostChanges {
        new_hosts,
        removed_hosts,
        vulnerability_changes,
    }
}

/// Compare risk scores between reports
fn compare_risk_scores(summary_a: &ReportSummary, summary_b: &ReportSummary) -> RiskComparison {
    let change = summary_b.overall_risk_score as i32 - summary_a.overall_risk_score as i32;
    let change_percent = if summary_a.overall_risk_score > 0 {
        (change as f32 / summary_a.overall_risk_score as f32) * 100.0
    } else {
        if summary_b.overall_risk_score > 0 { 100.0 } else { 0.0 }
    };

    RiskComparison {
        previous_score: summary_a.overall_risk_score,
        new_score: summary_b.overall_risk_score,
        previous_level: summary_a.overall_risk_level.clone(),
        new_level: summary_b.overall_risk_level.clone(),
        change,
        change_percent,
    }
}

/// Build comparison summary
fn build_comparison_summary(
    new_findings: &[FindingChange],
    resolved_findings: &[FindingChange],
    severity_changes: &[SeverityChange],
    host_changes: &HostChanges,
    risk_comparison: &RiskComparison,
) -> ComparisonSummary {
    let severity_upgrades = severity_changes
        .iter()
        .filter(|c| severity_rank(&c.new_severity) > severity_rank(&c.previous_severity))
        .count();

    let severity_downgrades = severity_changes
        .iter()
        .filter(|c| severity_rank(&c.new_severity) < severity_rank(&c.previous_severity))
        .count();

    // Determine trend
    let trend = determine_trend(
        new_findings.len(),
        resolved_findings.len(),
        severity_upgrades,
        severity_downgrades,
        risk_comparison.change,
    );

    let overall_assessment = generate_assessment(
        new_findings.len(),
        resolved_findings.len(),
        severity_upgrades,
        severity_downgrades,
        risk_comparison.change,
        &trend,
    );

    ComparisonSummary {
        new_vulnerabilities: new_findings.len(),
        resolved_vulnerabilities: resolved_findings.len(),
        severity_upgrades,
        severity_downgrades,
        new_hosts: host_changes.new_hosts.len(),
        removed_hosts: host_changes.removed_hosts.len(),
        risk_score_change: risk_comparison.change,
        overall_assessment,
        trend,
    }
}

/// Convert severity to numeric rank for comparison
fn severity_rank(severity: &Severity) -> u8 {
    match severity {
        Severity::Low => 1,
        Severity::Medium => 2,
        Severity::High => 3,
        Severity::Critical => 4,
    }
}

/// Determine the overall security trend
fn determine_trend(
    new_vulns: usize,
    resolved_vulns: usize,
    upgrades: usize,
    downgrades: usize,
    risk_change: i32,
) -> SecurityTrend {
    // Calculate a simple trend score
    let score = (resolved_vulns as i32 - new_vulns as i32)
        + (downgrades as i32 - upgrades as i32)
        - risk_change / 10;

    if score > 2 {
        SecurityTrend::Improving
    } else if score < -2 {
        SecurityTrend::Worsening
    } else {
        SecurityTrend::Stable
    }
}

/// Generate human-readable assessment
fn generate_assessment(
    new_vulns: usize,
    resolved_vulns: usize,
    upgrades: usize,
    downgrades: usize,
    risk_change: i32,
    trend: &SecurityTrend,
) -> String {
    let mut parts = Vec::new();

    match trend {
        SecurityTrend::Improving => {
            parts.push("Security posture is IMPROVING.".to_string());
        }
        SecurityTrend::Worsening => {
            parts.push("Security posture is WORSENING - immediate attention required.".to_string());
        }
        SecurityTrend::Stable => {
            parts.push("Security posture is STABLE.".to_string());
        }
    }

    if resolved_vulns > 0 {
        parts.push(format!("{} vulnerabilities were remediated.", resolved_vulns));
    }

    if new_vulns > 0 {
        parts.push(format!("{} new vulnerabilities were discovered.", new_vulns));
    }

    if upgrades > 0 {
        parts.push(format!("{} findings had severity increased.", upgrades));
    }

    if downgrades > 0 {
        parts.push(format!("{} findings had severity decreased.", downgrades));
    }

    if risk_change != 0 {
        let direction = if risk_change > 0 { "increased" } else { "decreased" };
        parts.push(format!("Risk score {} by {} points.", direction, risk_change.abs()));
    }

    parts.join(" ")
}

/// Generate HTML comparison report
pub fn generate_html_comparison(comparison: &ReportComparison) -> String {
    let mut html = String::from(r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Report Comparison</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 20px; }
        .header { text-align: center; margin-bottom: 40px; }
        .summary-card { background: #f5f5f5; padding: 20px; border-radius: 8px; margin: 20px 0; }
        .improving { color: #22c55e; }
        .worsening { color: #ef4444; }
        .stable { color: #6b7280; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
        th { background: #374151; color: white; }
        .severity-critical { color: #dc2626; font-weight: bold; }
        .severity-high { color: #ea580c; font-weight: bold; }
        .severity-medium { color: #ca8a04; }
        .severity-low { color: #16a34a; }
        .new-finding { background: #fef3c7; }
        .resolved-finding { background: #d1fae5; }
        .section { margin: 30px 0; }
        h2 { border-bottom: 2px solid #374151; padding-bottom: 10px; }
        .stat-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; }
        .stat-card { background: white; border: 1px solid #ddd; padding: 20px; text-align: center; border-radius: 8px; }
        .stat-value { font-size: 2em; font-weight: bold; }
        .stat-label { color: #6b7280; }
    </style>
</head>
<body>
"#);

    // Header
    html.push_str(&format!(r#"
    <div class="header">
        <h1>Security Report Comparison</h1>
        <p>Comparing <strong>{}</strong> ({}) vs <strong>{}</strong> ({})</p>
        <p>Generated: {}</p>
    </div>
"#,
        comparison.report_a_name,
        comparison.report_a_date.format("%Y-%m-%d"),
        comparison.report_b_name,
        comparison.report_b_date.format("%Y-%m-%d"),
        comparison.compared_at.format("%Y-%m-%d %H:%M:%S UTC"),
    ));

    // Summary card
    let trend_class = match comparison.summary.trend {
        SecurityTrend::Improving => "improving",
        SecurityTrend::Worsening => "worsening",
        SecurityTrend::Stable => "stable",
    };

    html.push_str(&format!(r#"
    <div class="summary-card">
        <h2 class="{}">Overall Assessment</h2>
        <p>{}</p>
    </div>
"#, trend_class, comparison.summary.overall_assessment));

    // Stats grid
    html.push_str(r#"
    <div class="stat-grid">
"#);

    let stats = [
        (&comparison.summary.new_vulnerabilities, "New Vulnerabilities", "#ef4444"),
        (&comparison.summary.resolved_vulnerabilities, "Resolved", "#22c55e"),
        (&comparison.summary.severity_upgrades, "Severity Upgrades", "#f97316"),
        (&comparison.summary.severity_downgrades, "Severity Downgrades", "#3b82f6"),
    ];

    for (value, label, color) in stats {
        html.push_str(&format!(r#"
        <div class="stat-card">
            <div class="stat-value" style="color: {}">{}</div>
            <div class="stat-label">{}</div>
        </div>
"#, color, value, label));
    }

    html.push_str("    </div>\n");

    // Risk comparison
    html.push_str(&format!(r#"
    <div class="section">
        <h2>Risk Score Comparison</h2>
        <table>
            <tr>
                <th>Metric</th>
                <th>Previous</th>
                <th>Current</th>
                <th>Change</th>
            </tr>
            <tr>
                <td>Risk Score</td>
                <td>{}/100</td>
                <td>{}/100</td>
                <td style="color: {}">{:+}</td>
            </tr>
            <tr>
                <td>Risk Level</td>
                <td>{}</td>
                <td>{}</td>
                <td>-</td>
            </tr>
        </table>
    </div>
"#,
        comparison.risk_comparison.previous_score,
        comparison.risk_comparison.new_score,
        if comparison.risk_comparison.change > 0 { "#ef4444" } else if comparison.risk_comparison.change < 0 { "#22c55e" } else { "#6b7280" },
        comparison.risk_comparison.change,
        comparison.risk_comparison.previous_level,
        comparison.risk_comparison.new_level,
    ));

    // New findings
    if !comparison.new_findings.is_empty() {
        html.push_str(r#"
    <div class="section">
        <h2>New Vulnerabilities</h2>
        <table>
            <tr>
                <th>Title</th>
                <th>CVE</th>
                <th>Severity</th>
                <th>Affected Hosts</th>
            </tr>
"#);
        for finding in &comparison.new_findings {
            let severity_class = severity_class(&finding.severity);
            html.push_str(&format!(r#"
            <tr class="new-finding">
                <td>{}</td>
                <td>{}</td>
                <td class="{}">{:?}</td>
                <td>{}</td>
            </tr>
"#,
                finding.title,
                finding.cve_id.as_deref().unwrap_or("-"),
                severity_class,
                finding.severity,
                finding.affected_hosts.join(", "),
            ));
        }
        html.push_str("        </table>\n    </div>\n");
    }

    // Resolved findings
    if !comparison.resolved_findings.is_empty() {
        html.push_str(r#"
    <div class="section">
        <h2>Resolved Vulnerabilities</h2>
        <table>
            <tr>
                <th>Title</th>
                <th>CVE</th>
                <th>Severity</th>
                <th>Previously Affected Hosts</th>
            </tr>
"#);
        for finding in &comparison.resolved_findings {
            let severity_class = severity_class(&finding.severity);
            html.push_str(&format!(r#"
            <tr class="resolved-finding">
                <td>{}</td>
                <td>{}</td>
                <td class="{}">{:?}</td>
                <td>{}</td>
            </tr>
"#,
                finding.title,
                finding.cve_id.as_deref().unwrap_or("-"),
                severity_class,
                finding.severity,
                finding.affected_hosts.join(", "),
            ));
        }
        html.push_str("        </table>\n    </div>\n");
    }

    // Severity changes
    if !comparison.severity_changes.is_empty() {
        html.push_str(r#"
    <div class="section">
        <h2>Severity Changes</h2>
        <table>
            <tr>
                <th>Title</th>
                <th>CVE</th>
                <th>Previous</th>
                <th>Current</th>
                <th>Affected Hosts</th>
            </tr>
"#);
        for change in &comparison.severity_changes {
            let prev_class = severity_class(&change.previous_severity);
            let new_class = severity_class(&change.new_severity);
            html.push_str(&format!(r#"
            <tr>
                <td>{}</td>
                <td>{}</td>
                <td class="{}">{:?}</td>
                <td class="{}">{:?}</td>
                <td>{}</td>
            </tr>
"#,
                change.title,
                change.cve_id.as_deref().unwrap_or("-"),
                prev_class,
                change.previous_severity,
                new_class,
                change.new_severity,
                change.affected_hosts.join(", "),
            ));
        }
        html.push_str("        </table>\n    </div>\n");
    }

    // Host changes
    if !comparison.host_changes.new_hosts.is_empty() || !comparison.host_changes.removed_hosts.is_empty() {
        html.push_str(r#"
    <div class="section">
        <h2>Host Changes</h2>
"#);

        if !comparison.host_changes.new_hosts.is_empty() {
            html.push_str(r#"
        <h3>New Hosts</h3>
        <table>
            <tr>
                <th>IP Address</th>
                <th>Hostname</th>
                <th>OS</th>
                <th>Open Ports</th>
                <th>Vulnerabilities</th>
            </tr>
"#);
            for host in &comparison.host_changes.new_hosts {
                html.push_str(&format!(r#"
            <tr class="new-finding">
                <td>{}</td>
                <td>{}</td>
                <td>{}</td>
                <td>{}</td>
                <td>{}</td>
            </tr>
"#,
                    host.ip,
                    host.hostname.as_deref().unwrap_or("-"),
                    host.os.as_deref().unwrap_or("-"),
                    host.open_ports,
                    host.vulnerability_count,
                ));
            }
            html.push_str("        </table>\n");
        }

        if !comparison.host_changes.removed_hosts.is_empty() {
            html.push_str(r#"
        <h3>Removed Hosts</h3>
        <table>
            <tr>
                <th>IP Address</th>
                <th>Hostname</th>
                <th>OS</th>
                <th>Open Ports</th>
                <th>Vulnerabilities</th>
            </tr>
"#);
            for host in &comparison.host_changes.removed_hosts {
                html.push_str(&format!(r#"
            <tr class="resolved-finding">
                <td>{}</td>
                <td>{}</td>
                <td>{}</td>
                <td>{}</td>
                <td>{}</td>
            </tr>
"#,
                    host.ip,
                    host.hostname.as_deref().unwrap_or("-"),
                    host.os.as_deref().unwrap_or("-"),
                    host.open_ports,
                    host.vulnerability_count,
                ));
            }
            html.push_str("        </table>\n");
        }

        html.push_str("    </div>\n");
    }

    // Footer
    html.push_str(r#"
    <footer style="margin-top: 40px; text-align: center; color: #6b7280;">
        <p>Generated by HeroForge - Security Assessment Platform</p>
    </footer>
</body>
</html>
"#);

    html
}

/// Get CSS class for severity
fn severity_class(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical => "severity-critical",
        Severity::High => "severity-high",
        Severity::Medium => "severity-medium",
        Severity::Low => "severity-low",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reports::types::{ReportOptions, ReportTemplate};
    use chrono::Utc;

    fn create_test_report(id: &str, findings: Vec<FindingDetail>) -> ReportData {
        ReportData {
            id: id.to_string(),
            name: format!("Test Report {}", id),
            description: None,
            scan_id: "scan-123".to_string(),
            scan_name: "Test Scan".to_string(),
            created_at: Utc::now(),
            scan_date: Utc::now(),
            template: ReportTemplate::technical(),
            sections: vec![],
            options: ReportOptions::default(),
            hosts: vec![],
            summary: ReportSummary {
                total_hosts: 5,
                live_hosts: 4,
                total_ports: 50,
                open_ports: 20,
                total_vulnerabilities: findings.len(),
                critical_count: findings.iter().filter(|f| f.severity == Severity::Critical).count(),
                high_count: findings.iter().filter(|f| f.severity == Severity::High).count(),
                medium_count: findings.iter().filter(|f| f.severity == Severity::Medium).count(),
                low_count: findings.iter().filter(|f| f.severity == Severity::Low).count(),
                overall_risk_score: 65,
                overall_risk_level: "High".to_string(),
                top_findings: vec![],
                affected_services: vec![],
            },
            findings,
            secrets: vec![],
            remediation: vec![],
            screenshots: vec![],
            operator_notes: None,
            finding_notes: std::collections::HashMap::new(),
            ai_narrative: None,
        }
    }

    #[test]
    fn test_compare_reports_new_findings() {
        let finding_a = FindingDetail {
            id: "finding-001".to_string(),
            title: "Existing Vuln".to_string(),
            cve_id: Some("CVE-2023-0001".to_string()),
            cvss_score: Some(7.5),
            severity: Severity::High,
            description: "Test description".to_string(),
            impact: "Test impact".to_string(),
            affected_hosts: vec!["192.168.1.1".to_string()],
            affected_service: Some("http".to_string()),
            remediation: "Fix it".to_string(),
            references: vec![],
            evidence: None,
        };

        let finding_b = FindingDetail {
            id: "finding-002".to_string(),
            title: "New Vuln".to_string(),
            cve_id: Some("CVE-2023-0002".to_string()),
            cvss_score: Some(9.8),
            severity: Severity::Critical,
            description: "New vulnerability".to_string(),
            impact: "Severe impact".to_string(),
            affected_hosts: vec!["192.168.1.2".to_string()],
            affected_service: Some("ssh".to_string()),
            remediation: "Patch immediately".to_string(),
            references: vec![],
            evidence: None,
        };

        let report_a = create_test_report("a", vec![finding_a.clone()]);
        let report_b = create_test_report("b", vec![finding_a, finding_b]);

        let comparison = compare_reports(&report_a, &report_b).unwrap();

        assert_eq!(comparison.new_findings.len(), 1);
        assert_eq!(comparison.new_findings[0].title, "New Vuln");
        assert_eq!(comparison.resolved_findings.len(), 0);
    }

    #[test]
    fn test_compare_reports_resolved_findings() {
        let finding_a = FindingDetail {
            id: "finding-001".to_string(),
            title: "Old Vuln".to_string(),
            cve_id: Some("CVE-2023-0001".to_string()),
            cvss_score: Some(7.5),
            severity: Severity::High,
            description: "Test description".to_string(),
            impact: "Test impact".to_string(),
            affected_hosts: vec!["192.168.1.1".to_string()],
            affected_service: Some("http".to_string()),
            remediation: "Fix it".to_string(),
            references: vec![],
            evidence: None,
        };

        let report_a = create_test_report("a", vec![finding_a]);
        let report_b = create_test_report("b", vec![]);

        let comparison = compare_reports(&report_a, &report_b).unwrap();

        assert_eq!(comparison.new_findings.len(), 0);
        assert_eq!(comparison.resolved_findings.len(), 1);
        assert_eq!(comparison.resolved_findings[0].title, "Old Vuln");
    }

    #[test]
    fn test_security_trend() {
        // Improving: many resolved, few new
        let trend = determine_trend(1, 10, 0, 2, -5);
        assert_eq!(trend, SecurityTrend::Improving);

        // Worsening: many new, few resolved
        let trend = determine_trend(10, 1, 3, 0, 15);
        assert_eq!(trend, SecurityTrend::Worsening);

        // Stable: balanced
        let trend = determine_trend(3, 3, 1, 1, 0);
        assert_eq!(trend, SecurityTrend::Stable);
    }
}
