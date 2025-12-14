use anyhow::Result;
use crate::types::{ScanConfig, ScanTarget};
use ipnetwork::IpNetwork;
use log::{debug, warn};
use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;
use tokio::task;

pub async fn discover_hosts(
    config: &ScanConfig,
) -> Result<Vec<ScanTarget>, anyhow::Error> {
    let mut all_targets = Vec::new();

    // Parse all target specifications
    for target_spec in &config.targets {
        let targets = parse_target_spec(target_spec)?;
        all_targets.extend(targets);
    }

    debug!("Checking {} potential targets", all_targets.len());

    // Use tokio to check hosts concurrently
    let mut tasks = Vec::new();
    let timeout = config.timeout;

    for ip in all_targets {
        let task = task::spawn(async move { check_host_alive(ip, timeout).await });
        tasks.push((ip, task));
    }

    let mut live_hosts = Vec::new();
    for (ip, task) in tasks {
        match task.await {
            Ok(true) => {
                // Try to get hostname
                let hostname = get_hostname(&ip).await;
                live_hosts.push(ScanTarget { ip, hostname });
            }
            Ok(false) => {
                debug!("{} appears to be down", ip);
            }
            Err(e) => {
                warn!("Error checking {}: {}", ip, e);
            }
        }
    }

    Ok(live_hosts)
}

fn parse_target_spec(spec: &str) -> Result<Vec<IpAddr>, anyhow::Error> {
    // Try to parse as CIDR notation first
    if spec.contains('/') {
        let network = IpNetwork::from_str(spec)?;
        Ok(network.iter().collect())
    } else if spec.contains('-') {
        // IP range like 192.168.1.1-192.168.1.10
        parse_ip_range(spec)
    } else {
        // Single IP address
        let ip = spec.parse::<IpAddr>()?;
        Ok(vec![ip])
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

async fn get_hostname(ip: &IpAddr) -> Option<String> {
    // Try reverse DNS lookup
    match tokio::net::lookup_host(format!("{}:0", ip)).await {
        Ok(mut addrs) => {
            if let Some(addr) = addrs.next() {
                // This doesn't actually give us the hostname, need a proper reverse lookup
                // For now, return None - we can improve this later with trust-dns-resolver
                None
            } else {
                None
            }
        }
        Err(_) => None,
    }
}
