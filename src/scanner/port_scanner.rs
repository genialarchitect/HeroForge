use anyhow::Result;
use crate::types::{PortInfo, PortState, Protocol, ScanConfig, ScanTarget, ScanType};
use crate::scanner::udp_scanner;
use log::{debug, info};
use std::collections::HashMap;
use std::net::IpAddr;
use tokio::sync::Semaphore;
use std::sync::Arc;

pub async fn scan_ports(
    config: &ScanConfig,
) -> Result<HashMap<IpAddr, Vec<PortInfo>>, anyhow::Error> {
    let mut results = HashMap::new();

    for target_spec in &config.targets {
        let ip: IpAddr = target_spec.parse()?;
        let target = ScanTarget { ip, hostname: None };
        let ports = scan_target_ports(&target, config).await?;
        results.insert(ip, ports);
    }

    Ok(results)
}

/// Scan ports on a target, dispatching to the appropriate scanner based on scan type
pub async fn scan_target_ports(
    target: &ScanTarget,
    config: &ScanConfig,
) -> Result<Vec<PortInfo>, anyhow::Error> {
    match config.scan_type {
        ScanType::TCPConnect => {
            debug!(
                "TCP Connect scan: ports {}-{} on {}",
                config.port_range.0, config.port_range.1, target.ip
            );
            scan_tcp_connect(target, config).await
        }
        ScanType::UDPScan => {
            info!("UDP scan on {}", target.ip);
            udp_scanner::scan_target_udp_ports(target, config).await
        }
        ScanType::TCPSyn => {
            // TCP SYN scan not yet implemented, fall back to TCP Connect
            debug!(
                "TCP SYN scan not implemented, using TCP Connect for {}",
                target.ip
            );
            scan_tcp_connect(target, config).await
        }
        ScanType::Comprehensive => {
            // Run both TCP and UDP scans
            info!("Comprehensive scan (TCP + UDP) on {}", target.ip);

            // TCP scan
            let tcp_ports = scan_tcp_connect(target, config).await?;

            // UDP scan
            let udp_ports = match udp_scanner::scan_target_udp_ports(target, config).await {
                Ok(ports) => ports,
                Err(e) => {
                    // UDP might fail due to permissions - log but continue
                    log::warn!("UDP scan failed (may require root): {}", e);
                    Vec::new()
                }
            };

            // Merge results
            let mut all_ports = tcp_ports;
            all_ports.extend(udp_ports);
            all_ports.sort_by_key(|p| (p.port, matches!(p.protocol, Protocol::UDP)));

            Ok(all_ports)
        }
    }
}

/// TCP Connect scan (original implementation)
async fn scan_tcp_connect(
    target: &ScanTarget,
    config: &ScanConfig,
) -> Result<Vec<PortInfo>, anyhow::Error> {
    let ports: Vec<u16> = (config.port_range.0..=config.port_range.1).collect();
    let semaphore = Arc::new(Semaphore::new(config.threads));
    let mut tasks = Vec::new();

    for port in ports {
        let sem = semaphore.clone();
        let ip = target.ip;
        let timeout = config.timeout;

        let task = tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            scan_port(ip, port, timeout).await
        });

        tasks.push(task);
    }

    let mut open_ports = Vec::new();
    for task in tasks {
        if let Ok(Some(port_info)) = task.await {
            if matches!(port_info.state, PortState::Open) {
                open_ports.push(port_info);
            }
        }
    }

    open_ports.sort_by_key(|p| p.port);
    Ok(open_ports)
}

async fn scan_port(ip: IpAddr, port: u16, timeout: std::time::Duration) -> Option<PortInfo> {
    let addr = format!("{}:{}", ip, port);

    match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(&addr)).await {
        Ok(Ok(_)) => Some(PortInfo {
            port,
            protocol: Protocol::TCP,
            state: PortState::Open,
            service: None,
        }),
        Ok(Err(_)) => Some(PortInfo {
            port,
            protocol: Protocol::TCP,
            state: PortState::Closed,
            service: None,
        }),
        Err(_) => Some(PortInfo {
            port,
            protocol: Protocol::TCP,
            state: PortState::Filtered,
            service: None,
        }),
    }
}

// Common port to service name mapping
pub fn get_common_service(port: u16) -> Option<&'static str> {
    match port {
        20 => Some("ftp-data"),
        21 => Some("ftp"),
        22 => Some("ssh"),
        23 => Some("telnet"),
        25 => Some("smtp"),
        53 => Some("dns"),
        80 => Some("http"),
        110 => Some("pop3"),
        119 => Some("nntp"),
        143 => Some("imap"),
        161 => Some("snmp"),
        194 => Some("irc"),
        443 => Some("https"),
        445 => Some("microsoft-ds"),
        465 => Some("smtps"),
        514 => Some("syslog"),
        587 => Some("submission"),
        631 => Some("ipp"),
        636 => Some("ldaps"),
        993 => Some("imaps"),
        995 => Some("pop3s"),
        1433 => Some("ms-sql-s"),
        1521 => Some("oracle"),
        3306 => Some("mysql"),
        3389 => Some("ms-wbt-server"),
        5432 => Some("postgresql"),
        5900 => Some("vnc"),
        6379 => Some("redis"),
        8080 => Some("http-proxy"),
        8443 => Some("https-alt"),
        9200 => Some("elasticsearch"),
        27017 => Some("mongodb"),
        _ => None,
    }
}
