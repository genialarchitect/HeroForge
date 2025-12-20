use std::fmt::Write;

use crate::db::models::ScanResult;
use crate::types::{HostInfo, PortState, Severity};

/// Generate a Markdown report from scan results
///
/// Creates a well-formatted GitHub-flavored Markdown document with:
/// - Scan metadata header
/// - Executive summary with stats table
/// - Host details table
/// - Per-host port/service details
/// - Vulnerability findings grouped by severity
/// - Compliance summary if available
pub fn generate_markdown_report(scan: &ScanResult, hosts: &[HostInfo]) -> String {
    let mut md = String::new();

    // Header with scan metadata
    writeln!(md, "# Scan Report: {}", scan.name).unwrap();
    writeln!(md).unwrap();
    writeln!(md, "**Date:** {}", format_datetime(&scan.created_at)).unwrap();
    if let Some(ref completed) = scan.completed_at {
        writeln!(md, "**Completed:** {}", format_datetime(completed)).unwrap();
    }
    writeln!(md, "**Status:** {}", scan.status).unwrap();
    writeln!(md, "**Targets:** {}", scan.targets).unwrap();
    writeln!(md).unwrap();
    writeln!(md, "---").unwrap();
    writeln!(md).unwrap();

    // Executive Summary
    writeln!(md, "## Executive Summary").unwrap();
    writeln!(md).unwrap();

    let summary = calculate_summary(hosts);
    writeln!(md, "| Metric | Count |").unwrap();
    writeln!(md, "|--------|-------|").unwrap();
    writeln!(md, "| Hosts Discovered | {} |", summary.total_hosts).unwrap();
    writeln!(md, "| Alive Hosts | {} |", summary.alive_hosts).unwrap();
    writeln!(md, "| Open Ports | {} |", summary.open_ports).unwrap();
    writeln!(md, "| Total Vulnerabilities | {} |", summary.total_vulns).unwrap();
    writeln!(md, "| Critical Vulnerabilities | {} |", summary.critical_vulns).unwrap();
    writeln!(md, "| High Vulnerabilities | {} |", summary.high_vulns).unwrap();
    writeln!(md, "| Medium Vulnerabilities | {} |", summary.medium_vulns).unwrap();
    writeln!(md, "| Low Vulnerabilities | {} |", summary.low_vulns).unwrap();
    writeln!(md).unwrap();

    // Risk assessment
    let risk_level = calculate_risk_level(&summary);
    writeln!(md, "**Overall Risk Level:** {}", risk_level).unwrap();
    writeln!(md).unwrap();

    // Hosts Overview Table
    writeln!(md, "## Hosts").unwrap();
    writeln!(md).unwrap();

    if hosts.is_empty() {
        writeln!(md, "_No hosts discovered._").unwrap();
    } else {
        writeln!(md, "| IP | Hostname | OS | Open Ports | Vulnerabilities |").unwrap();
        writeln!(md, "|----|----------|-----|------------|-----------------|").unwrap();

        for host in hosts {
            let ip = host.target.ip.to_string();
            let hostname = host.target.hostname.as_deref().unwrap_or("-");
            let os = host.os_guess.as_ref()
                .map(|o| format!("{} {}", o.os_family, o.os_version.as_deref().unwrap_or("")))
                .unwrap_or_else(|| "-".to_string());
            let open_ports = host.ports.iter()
                .filter(|p| p.state == PortState::Open)
                .count();
            let vuln_count = host.vulnerabilities.len();

            writeln!(md, "| {} | {} | {} | {} | {} |",
                     ip, hostname, os.trim(), open_ports, vuln_count).unwrap();
        }
    }
    writeln!(md).unwrap();

    // Detailed Host Information
    writeln!(md, "## Host Details").unwrap();
    writeln!(md).unwrap();

    for host in hosts {
        writeln!(md, "### {}{}",
                 host.target.ip,
                 host.target.hostname.as_ref()
                     .map(|h| format!(" ({})", h))
                     .unwrap_or_default()).unwrap();
        writeln!(md).unwrap();

        // Status and OS
        writeln!(md, "- **Status:** {}", if host.is_alive { "Alive" } else { "Down" }).unwrap();
        if let Some(ref os) = host.os_guess {
            writeln!(md, "- **OS:** {} {} ({}% confidence)",
                     os.os_family,
                     os.os_version.as_deref().unwrap_or(""),
                     os.confidence).unwrap();
        }
        writeln!(md).unwrap();

        // Open Ports Table
        let open_ports: Vec<_> = host.ports.iter()
            .filter(|p| p.state == PortState::Open)
            .collect();

        if !open_ports.is_empty() {
            writeln!(md, "#### Open Ports").unwrap();
            writeln!(md).unwrap();
            writeln!(md, "| Port | Protocol | Service | Version | Banner |").unwrap();
            writeln!(md, "|------|----------|---------|---------|--------|").unwrap();

            for port in open_ports {
                let protocol = match port.protocol {
                    crate::types::Protocol::TCP => "TCP",
                    crate::types::Protocol::UDP => "UDP",
                };
                let service_name = port.service.as_ref()
                    .map(|s| s.name.as_str())
                    .unwrap_or("-");
                let version = port.service.as_ref()
                    .and_then(|s| s.version.as_deref())
                    .unwrap_or("-");
                let banner = port.service.as_ref()
                    .and_then(|s| s.banner.as_deref())
                    .map(|b| truncate_and_escape(b, 50))
                    .unwrap_or_else(|| "-".to_string());

                writeln!(md, "| {} | {} | {} | {} | {} |",
                         port.port, protocol, service_name, version, banner).unwrap();
            }
            writeln!(md).unwrap();
        }

        // SSL/TLS Info
        for port in &host.ports {
            if let Some(ref service) = port.service {
                if let Some(ref ssl) = service.ssl_info {
                    writeln!(md, "#### SSL/TLS (Port {})", port.port).unwrap();
                    writeln!(md).unwrap();
                    writeln!(md, "- **Certificate Valid:** {}", if ssl.cert_valid { "Yes" } else { "No" }).unwrap();
                    writeln!(md, "- **Issuer:** {}", escape_markdown(&ssl.issuer)).unwrap();
                    writeln!(md, "- **Subject:** {}", escape_markdown(&ssl.subject)).unwrap();
                    writeln!(md, "- **Valid Until:** {}", ssl.valid_until).unwrap();
                    if let Some(days) = ssl.days_until_expiry {
                        writeln!(md, "- **Days Until Expiry:** {}", days).unwrap();
                    }
                    if ssl.self_signed {
                        writeln!(md, "- **Warning:** Self-signed certificate").unwrap();
                    }
                    if ssl.hostname_mismatch {
                        writeln!(md, "- **Warning:** Hostname mismatch").unwrap();
                    }
                    if !ssl.weak_protocols.is_empty() {
                        writeln!(md, "- **Weak Protocols:** {}", ssl.weak_protocols.join(", ")).unwrap();
                    }
                    if !ssl.weak_ciphers.is_empty() {
                        writeln!(md, "- **Weak Ciphers:** {}", ssl.weak_ciphers.join(", ")).unwrap();
                    }
                    writeln!(md).unwrap();
                }
            }
        }

        // Host Vulnerabilities
        if !host.vulnerabilities.is_empty() {
            writeln!(md, "#### Vulnerabilities").unwrap();
            writeln!(md).unwrap();

            for vuln in &host.vulnerabilities {
                let severity_emoji = severity_to_emoji(&vuln.severity);
                writeln!(md, "##### {} {} {}",
                         severity_emoji,
                         severity_to_string(&vuln.severity),
                         escape_markdown(&vuln.title)).unwrap();
                writeln!(md).unwrap();

                if let Some(ref cve) = vuln.cve_id {
                    writeln!(md, "- **CVE:** [{}](https://nvd.nist.gov/vuln/detail/{})", cve, cve).unwrap();
                }
                if let Some(ref service) = vuln.affected_service {
                    writeln!(md, "- **Affected Service:** {}", service).unwrap();
                }
                writeln!(md, "- **Description:** {}", escape_markdown(&vuln.description)).unwrap();
                writeln!(md).unwrap();
            }
        }

        writeln!(md, "---").unwrap();
        writeln!(md).unwrap();
    }

    // Vulnerabilities Summary Section
    let all_vulns: Vec<_> = hosts.iter()
        .flat_map(|h| h.vulnerabilities.iter().map(move |v| (h, v)))
        .collect();

    if !all_vulns.is_empty() {
        writeln!(md, "## Vulnerability Summary").unwrap();
        writeln!(md).unwrap();

        // Group by severity
        let mut critical: Vec<_> = all_vulns.iter()
            .filter(|(_, v)| v.severity == Severity::Critical)
            .collect();
        let mut high: Vec<_> = all_vulns.iter()
            .filter(|(_, v)| v.severity == Severity::High)
            .collect();
        let mut medium: Vec<_> = all_vulns.iter()
            .filter(|(_, v)| v.severity == Severity::Medium)
            .collect();
        let mut low: Vec<_> = all_vulns.iter()
            .filter(|(_, v)| v.severity == Severity::Low)
            .collect();

        // Sort each group by title
        critical.sort_by(|(_, a), (_, b)| a.title.cmp(&b.title));
        high.sort_by(|(_, a), (_, b)| a.title.cmp(&b.title));
        medium.sort_by(|(_, a), (_, b)| a.title.cmp(&b.title));
        low.sort_by(|(_, a), (_, b)| a.title.cmp(&b.title));

        if !critical.is_empty() {
            writeln!(md, "### {} Critical", severity_to_emoji(&Severity::Critical)).unwrap();
            writeln!(md).unwrap();
            write_vuln_table(&mut md, &critical);
        }

        if !high.is_empty() {
            writeln!(md, "### {} High", severity_to_emoji(&Severity::High)).unwrap();
            writeln!(md).unwrap();
            write_vuln_table(&mut md, &high);
        }

        if !medium.is_empty() {
            writeln!(md, "### {} Medium", severity_to_emoji(&Severity::Medium)).unwrap();
            writeln!(md).unwrap();
            write_vuln_table(&mut md, &medium);
        }

        if !low.is_empty() {
            writeln!(md, "### {} Low", severity_to_emoji(&Severity::Low)).unwrap();
            writeln!(md).unwrap();
            write_vuln_table(&mut md, &low);
        }
    }

    // Footer
    writeln!(md, "---").unwrap();
    writeln!(md).unwrap();
    writeln!(md, "_Report generated by HeroForge - Network Reconnaissance Tool_").unwrap();
    writeln!(md).unwrap();
    writeln!(md, "_For authorized security testing only._").unwrap();

    md
}

/// Write a vulnerability table section
fn write_vuln_table(md: &mut String, vulns: &[&(&HostInfo, &crate::types::Vulnerability)]) {
    writeln!(md, "| Host | Title | CVE | Service |").unwrap();
    writeln!(md, "|------|-------|-----|---------|").unwrap();

    for (host, vuln) in vulns {
        let host_str = host.target.ip.to_string();
        let title = truncate_and_escape(&vuln.title, 40);
        let cve = vuln.cve_id.as_deref().unwrap_or("-");
        let service = vuln.affected_service.as_deref().unwrap_or("-");

        writeln!(md, "| {} | {} | {} | {} |", host_str, title, cve, service).unwrap();
    }
    writeln!(md).unwrap();
}

/// Summary statistics
struct ScanSummary {
    total_hosts: usize,
    alive_hosts: usize,
    open_ports: usize,
    total_vulns: usize,
    critical_vulns: usize,
    high_vulns: usize,
    medium_vulns: usize,
    low_vulns: usize,
}

fn calculate_summary(hosts: &[HostInfo]) -> ScanSummary {
    let mut summary = ScanSummary {
        total_hosts: hosts.len(),
        alive_hosts: 0,
        open_ports: 0,
        total_vulns: 0,
        critical_vulns: 0,
        high_vulns: 0,
        medium_vulns: 0,
        low_vulns: 0,
    };

    for host in hosts {
        if host.is_alive {
            summary.alive_hosts += 1;
        }

        summary.open_ports += host.ports.iter()
            .filter(|p| p.state == PortState::Open)
            .count();

        for vuln in &host.vulnerabilities {
            summary.total_vulns += 1;
            match vuln.severity {
                Severity::Critical => summary.critical_vulns += 1,
                Severity::High => summary.high_vulns += 1,
                Severity::Medium => summary.medium_vulns += 1,
                Severity::Low => summary.low_vulns += 1,
            }
        }
    }

    summary
}

fn calculate_risk_level(summary: &ScanSummary) -> &'static str {
    if summary.critical_vulns > 0 {
        "Critical - Immediate action required"
    } else if summary.high_vulns > 5 {
        "High - Action required within 24-48 hours"
    } else if summary.high_vulns > 0 {
        "Medium-High - Action required within 1 week"
    } else if summary.medium_vulns > 5 {
        "Medium - Schedule remediation"
    } else if summary.medium_vulns > 0 || summary.low_vulns > 0 {
        "Low - Address during regular maintenance"
    } else {
        "Minimal - No significant vulnerabilities found"
    }
}

fn severity_to_emoji(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical => "🔴",
        Severity::High => "🟠",
        Severity::Medium => "🟡",
        Severity::Low => "🔵",
    }
}

fn severity_to_string(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical => "Critical",
        Severity::High => "High",
        Severity::Medium => "Medium",
        Severity::Low => "Low",
    }
}

fn format_datetime(dt: &chrono::DateTime<chrono::Utc>) -> String {
    dt.format("%Y-%m-%d %H:%M:%S UTC").to_string()
}

/// Escape special markdown characters in text
fn escape_markdown(text: &str) -> String {
    text.replace('|', "\\|")
        .replace('*', "\\*")
        .replace('_', "\\_")
        .replace('[', "\\[")
        .replace(']', "\\]")
        .replace('`', "\\`")
        .replace('\n', " ")
        .replace('\r', "")
}

/// Truncate text and escape markdown characters
fn truncate_and_escape(text: &str, max_len: usize) -> String {
    let escaped = escape_markdown(text);
    if escaped.len() > max_len {
        format!("{}...", &escaped[..max_len.saturating_sub(3)])
    } else {
        escaped
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ScanTarget, PortInfo, Protocol, PortState, ServiceInfo, Vulnerability, OsInfo};
    use std::net::IpAddr;
    use std::time::Duration;
    use chrono::Utc;

    fn create_test_scan() -> ScanResult {
        ScanResult {
            id: "test-scan-id".to_string(),
            user_id: "test-user".to_string(),
            name: "Production Network Audit".to_string(),
            targets: "192.168.1.0/24".to_string(),
            status: "completed".to_string(),
            results: None,
            error_message: None,
            created_at: Utc::now(),
            started_at: Some(Utc::now()),
            completed_at: Some(Utc::now()),
            customer_id: None,
            engagement_id: None,
        }
    }

    fn create_test_host() -> HostInfo {
        HostInfo {
            target: ScanTarget {
                ip: "192.168.1.10".parse::<IpAddr>().unwrap(),
                hostname: Some("webserver.local".to_string()),
            },
            is_alive: true,
            os_guess: Some(OsInfo {
                os_family: "Linux".to_string(),
                os_version: Some("Ubuntu 22.04".to_string()),
                confidence: 85,
            }),
            ports: vec![
                PortInfo {
                    port: 22,
                    protocol: Protocol::TCP,
                    state: PortState::Open,
                    service: Some(ServiceInfo {
                        name: "ssh".to_string(),
                        version: Some("OpenSSH 8.9".to_string()),
                        banner: Some("SSH-2.0-OpenSSH_8.9".to_string()),
                        cpe: None,
                        enumeration: None,
                        ssl_info: None,
                    }),
                },
                PortInfo {
                    port: 443,
                    protocol: Protocol::TCP,
                    state: PortState::Open,
                    service: Some(ServiceInfo {
                        name: "https".to_string(),
                        version: Some("nginx 1.22".to_string()),
                        banner: None,
                        cpe: None,
                        enumeration: None,
                        ssl_info: None,
                    }),
                },
            ],
            vulnerabilities: vec![
                Vulnerability {
                    cve_id: Some("CVE-2024-1234".to_string()),
                    title: "Remote Code Execution in OpenSSH".to_string(),
                    severity: Severity::Critical,
                    description: "A vulnerability in OpenSSH allows remote attackers to execute arbitrary code.".to_string(),
                    affected_service: Some("ssh".to_string()),
                },
                Vulnerability {
                    cve_id: Some("CVE-2024-5678".to_string()),
                    title: "Information Disclosure".to_string(),
                    severity: Severity::Medium,
                    description: "Server reveals version information.".to_string(),
                    affected_service: Some("https".to_string()),
                },
            ],
            scan_duration: Duration::from_secs(10),
        }
    }

    #[test]
    fn test_generate_markdown_report() {
        let scan = create_test_scan();
        let hosts = vec![create_test_host()];

        let md = generate_markdown_report(&scan, &hosts);

        // Check header
        assert!(md.contains("# Scan Report: Production Network Audit"));
        assert!(md.contains("**Targets:** 192.168.1.0/24"));

        // Check summary table
        assert!(md.contains("| Hosts Discovered | 1 |"));
        assert!(md.contains("| Critical Vulnerabilities | 1 |"));

        // Check hosts table
        assert!(md.contains("| 192.168.1.10 | webserver.local |"));

        // Check host details
        assert!(md.contains("### 192.168.1.10 (webserver.local)"));
        assert!(md.contains("**OS:** Linux Ubuntu 22.04"));

        // Check ports table
        assert!(md.contains("| 22 | TCP | ssh | OpenSSH 8.9 |"));
        assert!(md.contains("| 443 | TCP | https | nginx 1.22 |"));

        // Check vulnerabilities
        assert!(md.contains("CVE-2024-1234"));
        assert!(md.contains("Remote Code Execution"));

        // Check footer
        assert!(md.contains("HeroForge"));
    }

    #[test]
    fn test_escape_markdown() {
        let input = "Test|with*special_chars[and]`backticks`";
        let escaped = escape_markdown(input);

        assert!(escaped.contains("\\|"));
        assert!(escaped.contains("\\*"));
        assert!(escaped.contains("\\_"));
        assert!(escaped.contains("\\["));
        assert!(escaped.contains("\\]"));
        assert!(escaped.contains("\\`"));
    }

    #[test]
    fn test_truncate_and_escape() {
        let long_text = "This is a very long text that should be truncated at some point";
        let truncated = truncate_and_escape(long_text, 20);

        assert!(truncated.len() <= 20);
        assert!(truncated.ends_with("..."));
    }

    #[test]
    fn test_empty_hosts() {
        let scan = create_test_scan();
        let hosts: Vec<HostInfo> = vec![];

        let md = generate_markdown_report(&scan, &hosts);

        assert!(md.contains("_No hosts discovered._"));
        assert!(md.contains("| Hosts Discovered | 0 |"));
    }

    #[test]
    fn test_calculate_risk_level() {
        // Critical vulns
        let critical_summary = ScanSummary {
            total_hosts: 1,
            alive_hosts: 1,
            open_ports: 1,
            total_vulns: 1,
            critical_vulns: 1,
            high_vulns: 0,
            medium_vulns: 0,
            low_vulns: 0,
        };
        assert!(calculate_risk_level(&critical_summary).contains("Critical"));

        // No vulns
        let clean_summary = ScanSummary {
            total_hosts: 1,
            alive_hosts: 1,
            open_ports: 1,
            total_vulns: 0,
            critical_vulns: 0,
            high_vulns: 0,
            medium_vulns: 0,
            low_vulns: 0,
        };
        assert!(calculate_risk_level(&clean_summary).contains("Minimal"));
    }
}
