use anyhow::Result;
use crate::types::{HostInfo, PortInfo, Severity};
use colored::*;
use prettytable::{row, Table};
use std::collections::HashMap;
use std::net::IpAddr;

pub fn output_terminal(results: &[HostInfo]) -> Result<()> {
    println!("\n{}", "═".repeat(80).bright_cyan());
    println!(
        "{}",
        " SCAN RESULTS ".bright_white().bold().on_bright_cyan()
    );
    println!("{}\n", "═".repeat(80).bright_cyan());

    if results.is_empty() {
        println!("{}", "No hosts found.".yellow());
        return Ok(());
    }

    for (idx, host) in results.iter().enumerate() {
        if idx > 0 {
            println!("\n{}", "─".repeat(80).bright_black());
        }

        println!(
            "\n{} {}",
            "Host:".bright_white().bold(),
            host.target.ip.to_string().bright_cyan()
        );

        if let Some(ref hostname) = host.target.hostname {
            println!("{} {}", "Hostname:".bright_white(), hostname.cyan());
        }

        if let Some(ref os) = host.os_guess {
            println!(
                "{} {} ({}% confidence)",
                "OS:".bright_white(),
                format!("{} {}", os.os_family, os.os_version.as_ref().unwrap_or(&"".to_string()))
                    .yellow(),
                os.confidence
            );
        }

        println!(
            "{} {:.2}s",
            "Scan Duration:".bright_white(),
            host.scan_duration.as_secs_f64()
        );

        // Open Ports Table
        if !host.ports.is_empty() {
            println!("\n{}", "Open Ports:".bright_white().bold());
            let mut table = Table::new();
            table.add_row(row![
                "Port".bold(),
                "Proto".bold(),
                "State".bold(),
                "Service".bold(),
                "Version".bold()
            ]);

            for port in &host.ports {
                let protocol_str = match port.protocol {
                    crate::types::Protocol::TCP => "TCP".cyan(),
                    crate::types::Protocol::UDP => "UDP".yellow(),
                };

                let state_str = match port.state {
                    crate::types::PortState::Open => "Open".green(),
                    crate::types::PortState::Closed => "Closed".red(),
                    crate::types::PortState::Filtered => "Filtered".yellow(),
                    crate::types::PortState::OpenFiltered => "Open|Filtered".yellow(),
                };

                let service_name = port
                    .service
                    .as_ref()
                    .map(|s| s.name.as_str())
                    .unwrap_or("unknown");

                let version = port
                    .service
                    .as_ref()
                    .and_then(|s| s.version.as_ref())
                    .map(|v| v.as_str())
                    .unwrap_or("-");

                table.add_row(row![port.port, protocol_str, state_str, service_name, version]);
            }

            table.printstd();
        }

        // Enumeration Results
        display_enumeration_results(&host.ports);

        // Vulnerabilities
        if !host.vulnerabilities.is_empty() {
            println!("\n{}", "Vulnerabilities:".bright_red().bold());

            for vuln in &host.vulnerabilities {
                let severity_color = match vuln.severity {
                    Severity::Critical => "CRITICAL".bright_red().bold(),
                    Severity::High => "HIGH".red().bold(),
                    Severity::Medium => "MEDIUM".yellow().bold(),
                    Severity::Low => "LOW".blue(),
                };

                print!("  {} ", severity_color);

                if let Some(ref cve) = vuln.cve_id {
                    print!("{} ", cve.bright_white().bold());
                }

                println!("{}", vuln.title.white());

                if let Some(ref service) = vuln.affected_service {
                    println!("    Service: {}", service.cyan());
                }

                println!("    {}", vuln.description.bright_black());
            }
        }
    }

    println!("\n{}", "═".repeat(80).bright_cyan());
    println!(
        "{} {}",
        "Total hosts scanned:".bright_white().bold(),
        results.len().to_string().bright_cyan()
    );
    println!("{}\n", "═".repeat(80).bright_cyan());

    Ok(())
}

pub fn output_port_scan_terminal(
    results: &HashMap<IpAddr, Vec<PortInfo>>,
) -> Result<()> {
    println!("\n{}", "PORT SCAN RESULTS".bright_white().bold());
    println!("{}", "=".repeat(60).bright_cyan());

    for (ip, ports) in results {
        println!("\n{} {}", "Host:".bright_white().bold(), ip.to_string().bright_cyan());

        if ports.is_empty() {
            println!("  {}", "No open ports found".yellow());
            continue;
        }

        let mut table = Table::new();
        table.add_row(row![
            "Port".bold(),
            "Proto".bold(),
            "State".bold(),
            "Service".bold()
        ]);

        for port in ports {
            let protocol_str = match port.protocol {
                crate::types::Protocol::TCP => "TCP".cyan(),
                crate::types::Protocol::UDP => "UDP".yellow(),
            };

            let state_str = match port.state {
                crate::types::PortState::Open => "Open".green(),
                crate::types::PortState::Closed => "Closed".red(),
                crate::types::PortState::Filtered => "Filtered".yellow(),
                crate::types::PortState::OpenFiltered => "Open|Filtered".yellow(),
            };

            let service_name = port
                .service
                .as_ref()
                .map(|s| s.name.as_str())
                .unwrap_or("unknown");

            table.add_row(row![port.port, protocol_str, state_str, service_name]);
        }

        table.printstd();
    }

    println!();
    Ok(())
}

fn display_enumeration_results(ports: &[PortInfo]) {
    use std::collections::HashMap;

    // Check if any ports have enumeration data
    let has_enumeration = ports.iter().any(|p| {
        p.service.as_ref().and_then(|s| s.enumeration.as_ref()).is_some()
    });

    if !has_enumeration {
        return;
    }

    for port in ports {
        if let Some(ref service) = port.service {
            if let Some(ref enum_result) = service.enumeration {
                println!(
                    "\n{} {} {}",
                    "Enumeration Results:".bright_white().bold(),
                    format!("Port {}", port.port).bright_cyan(),
                    format!("({})", enum_result.service_type).bright_black()
                );
                println!(
                    "{} {} | {} {}",
                    "Depth:".bright_white(),
                    format!("{:?}", enum_result.enumeration_depth).yellow(),
                    "Duration:".bright_white(),
                    format!("{:.2}s", enum_result.duration.as_secs_f64()).bright_black()
                );

                if enum_result.findings.is_empty() {
                    println!("  {}", "No findings".bright_black());
                    continue;
                }

                // Group findings by type
                let mut grouped: HashMap<String, Vec<&crate::scanner::enumeration::types::Finding>> = HashMap::new();
                for finding in &enum_result.findings {
                    let type_str = finding.finding_type.to_string();
                    grouped.entry(type_str).or_insert_with(Vec::new).push(finding);
                }

                // Display findings grouped by type
                for (finding_type, findings) in grouped.iter() {
                    println!("\n  {} {}", get_finding_icon(finding_type), finding_type.bright_white().bold());

                    for finding in findings {
                        let confidence_color = if finding.confidence >= 90 {
                            finding.value.bright_green()
                        } else if finding.confidence >= 70 {
                            finding.value.green()
                        } else if finding.confidence >= 50 {
                            finding.value.yellow()
                        } else {
                            finding.value.bright_black()
                        };

                        print!("    {} ", confidence_color);

                        // Display metadata if available
                        if let Some(status) = finding.metadata.get("status_code") {
                            let status_colored = match status.as_str() {
                                "200" => status.green(),
                                "301" | "302" => status.yellow(),
                                "401" | "403" => status.red(),
                                _ => status.normal(),
                            };
                            print!("[{}] ", status_colored);
                        }

                        if let Some(length) = finding.metadata.get("content_length") {
                            print!("({} bytes) ", length.bright_black());
                        }

                        if let Some(tech) = finding.metadata.get("technology") {
                            print!("{} ", tech.cyan());
                        }

                        println!();
                    }
                }

                // Display summary metadata
                if !enum_result.metadata.is_empty() {
                    println!("\n  {}", "Summary:".bright_white());
                    for (key, value) in &enum_result.metadata {
                        println!("    {}: {}", key.bright_black(), value.bright_black());
                    }
                }
            }
        }
    }
}

fn get_finding_icon(finding_type: &str) -> &'static str {
    match finding_type {
        // HTTP/HTTPS findings
        "Directory" => "📁",
        "File" => "📄",
        "AdminPanel" => "🔐",
        "Technology" => "⚙️",
        "Header" => "📋",
        "Misconfiguration" => "⚠️",
        "BackupFile" => "💾",
        "ConfigFile" => "⚙️",
        "RobotsTxt" => "🤖",
        "SitemapXml" => "🗺️",
        "InformationDisclosure" => "ℹ️",
        // DNS findings
        "Subdomain" => "🌐",
        "Zone Transfer" => "🔄",
        "Nameserver" => "📡",
        // Database findings
        "Database List" => "🗄️",
        "Table List" => "📊",
        "Default Credentials" => "🔑",
        "User List" => "👥",
        "Version" => "📌",
        "Privilege" => "⚡",
        // SMB findings
        "Share" => "📂",
        "User" => "👤",
        "Group" => "👥",
        "Domain" => "🌍",
        "Policy" => "📜",
        "Null Session" => "🔓",
        // Catch DNS Record types
        _ if finding_type.starts_with("DNS ") && finding_type.ends_with(" Record") => "📝",
        // Default
        _ => "•",
    }
}
