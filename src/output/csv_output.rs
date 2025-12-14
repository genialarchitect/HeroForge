use anyhow::Result;
use crate::types::{HostInfo, PortInfo};
use csv::Writer;
use std::collections::HashMap;
use std::net::IpAddr;

pub fn output_csv(
    results: &[HostInfo],
    output_file: Option<&str>,
) -> Result<()> {
    let file_path = output_file.unwrap_or("scan_results.csv");
    let mut wtr = Writer::from_path(file_path)?;

    // Write header
    wtr.write_record(&[
        "IP",
        "Hostname",
        "Port",
        "State",
        "Service",
        "Version",
        "OS Family",
        "OS Version",
        "Vulnerability",
        "Severity",
        "Enum Finding Type",
        "Enum Value",
        "Enum Confidence",
    ])?;

    for host in results {
        let ip = host.target.ip.to_string();
        let hostname = host
            .target
            .hostname
            .as_ref()
            .map(|h| h.as_str())
            .unwrap_or("");
        let os_family = host
            .os_guess
            .as_ref()
            .map(|o| o.os_family.as_str())
            .unwrap_or("");
        let os_version = host
            .os_guess
            .as_ref()
            .and_then(|o| o.os_version.as_ref())
            .map(|v| v.as_str())
            .unwrap_or("");

        // Write port information
        for port in &host.ports {
            let port_num = port.port.to_string();
            let state = format!("{:?}", port.state);
            let service = port
                .service
                .as_ref()
                .map(|s| s.name.as_str())
                .unwrap_or("");
            let version = port
                .service
                .as_ref()
                .and_then(|s| s.version.as_ref())
                .map(|v| v.as_str())
                .unwrap_or("");

            wtr.write_record(&[
                &ip,
                hostname,
                &port_num,
                &state,
                service,
                version,
                os_family,
                os_version,
                "",
                "",
                "",
                "",
                "",
            ])?;
        }

        // Write vulnerability information
        for vuln in &host.vulnerabilities {
            let vuln_title = &vuln.title;
            let severity = format!("{:?}", vuln.severity);

            wtr.write_record(&[
                &ip,
                hostname,
                "",
                "",
                "",
                "",
                os_family,
                os_version,
                vuln_title,
                &severity,
                "",
                "",
                "",
            ])?;
        }

        // Write enumeration findings
        for port in &host.ports {
            if let Some(ref service) = port.service {
                if let Some(ref enumeration) = service.enumeration {
                    let port_num = port.port.to_string();
                    let service_name = &service.name;

                    for finding in &enumeration.findings {
                        let finding_type = finding.finding_type.to_string();
                        let confidence = finding.confidence.to_string();

                        wtr.write_record(&[
                            &ip,
                            hostname,
                            &port_num,
                            "",
                            service_name,
                            "",
                            os_family,
                            os_version,
                            "",
                            "",
                            &finding_type,
                            &finding.value,
                            &confidence,
                        ])?;
                    }
                }
            }
        }

        // If no ports or vulns, write at least one row for the host
        if host.ports.is_empty() && host.vulnerabilities.is_empty() {
            wtr.write_record(&[&ip, hostname, "", "", "", "", os_family, os_version, "", "", "", "", ""])?;
        }
    }

    wtr.flush()?;
    println!("CSV results saved to: {}", file_path);
    Ok(())
}

pub fn output_port_scan_csv(
    results: &HashMap<IpAddr, Vec<PortInfo>>,
) -> Result<()> {
    let mut wtr = Writer::from_writer(std::io::stdout());

    wtr.write_record(&["IP", "Port", "State", "Service"])?;

    for (ip, ports) in results {
        for port in ports {
            wtr.write_record(&[
                &ip.to_string(),
                &port.port.to_string(),
                &format!("{:?}", port.state),
                port.service
                    .as_ref()
                    .map(|s| s.name.as_str())
                    .unwrap_or("unknown"),
            ])?;
        }
    }

    wtr.flush()?;
    Ok(())
}
