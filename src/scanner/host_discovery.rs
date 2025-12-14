use anyhow::Result;
use crate::types::{ScanConfig, ScanTarget};
use ipnetwork::IpNetwork;
use log::{debug, info, warn};
use std::net::{IpAddr, ToSocketAddrs};
use std::str::FromStr;
use std::time::Duration;
use tokio::task;

pub async fn discover_hosts(
    config: &ScanConfig,
) -> Result<Vec<ScanTarget>, anyhow::Error> {
    let mut all_targets = Vec::new();

    // Parse all target specifications (with hostname resolution)
    for target_spec in &config.targets {
        match parse_target_spec(target_spec) {
            Ok(targets) => all_targets.extend(targets),
            Err(e) => warn!("Failed to parse target '{}': {}", target_spec, e),
        }
    }

    debug!("Checking {} potential targets", all_targets.len());

    // Use tokio to check hosts concurrently
    let mut tasks = Vec::new();
    let timeout = config.timeout;

    for target in all_targets {
        let ip = target.ip;
        let hostname = target.hostname;
        let task = task::spawn(async move {
            (check_host_alive(ip, timeout).await, hostname)
        });
        tasks.push((ip, task));
    }

    let mut live_hosts = Vec::new();
    for (ip, task) in tasks {
        match task.await {
            Ok((true, hostname)) => {
                // Use resolved hostname if available, otherwise try reverse lookup
                let final_hostname = hostname.or_else(|| {
                    // We can try reverse lookup here, but it's often not reliable
                    None
                });
                live_hosts.push(ScanTarget { ip, hostname: final_hostname });
            }
            Ok((false, _)) => {
                debug!("{} appears to be down", ip);
            }
            Err(e) => {
                warn!("Error checking {}: {}", ip, e);
            }
        }
    }

    Ok(live_hosts)
}

/// Parsed target with optional hostname
pub struct ParsedTarget {
    pub ip: IpAddr,
    pub hostname: Option<String>,
}

fn parse_target_spec(spec: &str) -> Result<Vec<ParsedTarget>, anyhow::Error> {
    // Try to parse as CIDR notation first
    if spec.contains('/') {
        let network = IpNetwork::from_str(spec)?;
        Ok(network.iter().map(|ip| ParsedTarget { ip, hostname: None }).collect())
    } else if spec.contains('-') {
        // IP range like 192.168.1.1-192.168.1.10
        let ips = parse_ip_range(spec)?;
        Ok(ips.into_iter().map(|ip| ParsedTarget { ip, hostname: None }).collect())
    } else {
        // Try to parse as IP address first
        if let Ok(ip) = spec.parse::<IpAddr>() {
            return Ok(vec![ParsedTarget { ip, hostname: None }]);
        }

        // Try to resolve as hostname
        debug!("Resolving hostname: {}", spec);
        match format!("{}:0", spec).to_socket_addrs() {
            Ok(addrs) => {
                let resolved: Vec<_> = addrs.collect();
                if resolved.is_empty() {
                    Err(anyhow::anyhow!("Hostname resolved to no addresses: {}", spec))
                } else {
                    let ip = resolved[0].ip();
                    info!("Resolved {} -> {}", spec, ip);
                    Ok(vec![ParsedTarget { ip, hostname: Some(spec.to_string()) }])
                }
            }
            Err(e) => Err(anyhow::anyhow!("Failed to resolve hostname '{}': {}", spec, e)),
        }
    }
}

fn parse_ip_range(range: &str) -> Result<Vec<IpAddr>, anyhow::Error> {
    let parts: Vec<&str> = range.split('-').collect();
    if parts.len() != 2 {
        return Err(anyhow::anyhow!("Invalid IP range format"));
    }

    let start_ip: IpAddr = parts[0].trim().parse()?;
    let end_ip: IpAddr = parts[1].trim().parse()?;

    // For simplicity, only support IPv4 ranges
    match (start_ip, end_ip) {
        (IpAddr::V4(start), IpAddr::V4(end)) => {
            let start_u32 = u32::from(start);
            let end_u32 = u32::from(end);

            let mut ips = Vec::new();
            for i in start_u32..=end_u32 {
                let ip = std::net::Ipv4Addr::from(i);
                ips.push(IpAddr::V4(ip));
            }
            Ok(ips)
        }
        _ => Err(anyhow::anyhow!("Only IPv4 ranges are supported")),
    }
}

async fn check_host_alive(ip: IpAddr, timeout: Duration) -> bool {
    // Multi-method host detection:
    // 1. Try ICMP ping (if we have permissions)
    // 2. Try TCP connect to common ports (80, 443, 22)

    // Since ICMP requires raw sockets (root/admin), we'll use TCP connect probe
    // to common ports as a more portable solution
    let common_ports = vec![80, 443, 22, 21, 25, 445, 3389];

    for port in common_ports {
        if tcp_connect_probe(ip, port, timeout).await {
            return true;
        }
    }

    false
}

async fn tcp_connect_probe(ip: IpAddr, port: u16, timeout: Duration) -> bool {
    let addr = format!("{}:{}", ip, port);

    match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(&addr)).await {
        Ok(Ok(_)) => true,
        Ok(Err(_)) => false,
        Err(_) => false, // Timeout
    }
}

