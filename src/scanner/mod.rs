use anyhow::Result;
pub mod ad_assessment;
pub mod api_security;
pub mod asset_discovery;
pub mod attack_paths;
pub mod bas;
pub mod bloodhound;
pub mod cloud;
pub mod comparison;
pub mod container;
pub mod credential_audit;
pub mod dns_recon;
pub mod enumeration;
pub mod exploitation;
pub mod host_discovery;
pub mod iac;
pub mod nuclei;
pub mod os_fingerprint;
pub mod port_scanner;
pub mod privesc;
pub mod secret_detection;
pub mod service_detection;
pub mod ssl_scanner;
pub mod syn_scanner;
pub mod udp_probes;
pub mod udp_scanner;
pub mod udp_service_detection;
pub mod webapp;
pub mod wireless;

use crate::types::{HostInfo, ScanConfig, ScanProgressMessage, ScanTarget};
use log::{debug, info, warn};
use std::net::{IpAddr, ToSocketAddrs};
use std::time::Instant;
use tokio::sync::broadcast::Sender;

/// Resolve a target string to a ScanTarget
/// Handles IP addresses, hostnames, and CIDR notation
fn resolve_target(target_str: &str) -> Vec<ScanTarget> {
    let mut targets = Vec::new();

    // Handle CIDR notation
    if target_str.contains('/') {
        if let Ok(network) = target_str.parse::<ipnetwork::IpNetwork>() {
            for ip in network.iter() {
                targets.push(ScanTarget {
                    ip,
                    hostname: None,
                });
            }
        } else {
            warn!("Failed to parse CIDR notation: {}", target_str);
        }
        return targets;
    }

    // Try to parse as IP address first
    if let Ok(ip) = target_str.parse::<IpAddr>() {
        targets.push(ScanTarget {
            ip,
            hostname: None,
        });
        return targets;
    }

    // Try to resolve as hostname
    debug!("Resolving hostname: {}", target_str);
    match format!("{}:0", target_str).to_socket_addrs() {
        Ok(addrs) => {
            let resolved: Vec<_> = addrs.collect();
            if resolved.is_empty() {
                warn!("Hostname resolved to no addresses: {}", target_str);
            } else {
                // Use the first resolved address
                let ip = resolved[0].ip();
                info!("Resolved {} -> {}", target_str, ip);
                targets.push(ScanTarget {
                    ip,
                    hostname: Some(target_str.to_string()),
                });
            }
        }
        Err(e) => {
            warn!("Failed to resolve hostname '{}': {}", target_str, e);
        }
    }

    targets
}

pub async fn run_scan(
    config: &ScanConfig,
    progress_tx: Option<Sender<ScanProgressMessage>>,
) -> Result<Vec<HostInfo>, anyhow::Error> {
    let start = Instant::now();
    info!("Starting comprehensive network scan...");

    // Log exclusion rules if any
    if !config.exclusions.is_empty() {
        info!(
            "Applying {} exclusion rule(s) to scan",
            config.exclusions.len()
        );
        for rule in &config.exclusions {
            debug!(
                "Exclusion: {:?} = {}",
                rule.exclusion_type, rule.value
            );
        }
    }

    // Helper function to send progress messages
    let send_progress = |tx: &Option<Sender<ScanProgressMessage>>, msg: ScanProgressMessage| {
        if let Some(sender) = tx {
            let _ = sender.send(msg);
        }
    };

    // Step 1: Discover live hosts (or skip if --skip-discovery is set)
    let discovered_hosts = if config.skip_host_discovery {
        info!("Phase 1: Skipping Host Discovery (--skip-discovery)");
        send_progress(
            &progress_tx,
            ScanProgressMessage::PhaseStarted {
                phase: "discovery".to_string(),
                progress: 0.0,
            },
        );

        // Convert targets directly to ScanTargets (with hostname resolution)
        let mut targets = Vec::new();
        for target_str in &config.targets {
            targets.extend(resolve_target(target_str));
        }
        info!("Treating {} targets as live (discovery skipped)", targets.len());
        targets
    } else {
        info!("Phase 1: Host Discovery");
        send_progress(
            &progress_tx,
            ScanProgressMessage::PhaseStarted {
                phase: "discovery".to_string(),
                progress: 0.0,
            },
        );

        let hosts = host_discovery::discover_hosts(config).await?;
        info!("Found {} live hosts", hosts.len());
        hosts
    };

    // Apply host exclusions
    let discovered_count = discovered_hosts.len();
    let live_hosts: Vec<ScanTarget> = discovered_hosts
        .into_iter()
        .filter(|host| {
            let ip_str = host.ip.to_string();
            let should_exclude = crate::db::exclusions::should_exclude_target(&ip_str, &config.exclusions);

            // Also check hostname if present
            let hostname_excluded = host.hostname.as_ref().map_or(false, |h| {
                crate::db::exclusions::should_exclude_target(h, &config.exclusions)
            });

            if should_exclude || hostname_excluded {
                info!(
                    "Excluding host {} (hostname: {:?}) due to exclusion rule",
                    ip_str,
                    host.hostname
                );
                false
            } else {
                true
            }
        })
        .collect();

    if discovered_count != live_hosts.len() {
        info!(
            "Excluded {} host(s) based on exclusion rules ({} remaining)",
            discovered_count - live_hosts.len(),
            live_hosts.len()
        );
    }

    if live_hosts.is_empty() {
        return Ok(Vec::new());
    }

    // Notify about discovered hosts (only non-excluded ones)
    for host in &live_hosts {
        send_progress(
            &progress_tx,
            ScanProgressMessage::HostDiscovered {
                ip: host.ip.to_string(),
                hostname: host.hostname.clone(),
            },
        );
    }

    // Step 2: Scan ports on live hosts
    info!("Phase 2: Port Scanning");
    send_progress(
        &progress_tx,
        ScanProgressMessage::PhaseStarted {
            phase: "port_scan".to_string(),
            progress: 20.0,
        },
    );

    let mut results = Vec::new();
    let total_hosts = live_hosts.len();

    for (idx, target) in live_hosts.into_iter().enumerate() {
        let scan_start = Instant::now();
        // Cache IP string for reuse in progress messages
        let target_ip_str = target.ip.to_string();

        // Scan ports
        let ports = port_scanner::scan_target_ports(&target, config).await?;

        // Notify about found ports
        for port in &ports {
            send_progress(
                &progress_tx,
                ScanProgressMessage::PortFound {
                    ip: target_ip_str.clone(),
                    port: port.port,
                    protocol: format!("{:?}", port.protocol),
                    state: format!("{:?}", port.state),
                },
            );
        }

        let mut host_info = HostInfo {
            target, // Move target instead of cloning (ownership transferred from iterator)
            is_alive: true,
            os_guess: None,
            ports, // Move ports instead of cloning (no longer needed separately)
            vulnerabilities: Vec::new(),
            scan_duration: scan_start.elapsed(),
        };

        // Step 3: Service detection
        if config.enable_service_detection && !host_info.ports.is_empty() {
            info!("Phase 3: Service Detection for {}", target_ip_str);
            send_progress(
                &progress_tx,
                ScanProgressMessage::PhaseStarted {
                    phase: "service_detection".to_string(),
                    progress: 40.0 + (idx as f32 / total_hosts as f32) * 30.0,
                },
            );

            service_detection::detect_services(&mut host_info, config).await?;

            // Notify about detected services
            for port in &host_info.ports {
                if let Some(service) = &port.service {
                    send_progress(
                        &progress_tx,
                        ScanProgressMessage::ServiceDetected {
                            ip: target_ip_str.clone(),
                            port: port.port,
                            service_name: service.name.clone(),
                            version: service.version.clone(),
                        },
                    );
                }
            }
        }

        // Step 3.5: Enumeration
        if config.enable_enumeration && config.enable_service_detection && !host_info.ports.is_empty() {
            info!("Phase 3.5: Service Enumeration for {}", target_ip_str);
            send_progress(
                &progress_tx,
                ScanProgressMessage::PhaseStarted {
                    phase: "enumeration".to_string(),
                    progress: 50.0 + (idx as f32 / total_hosts as f32) * 15.0,
                },
            );

            enumeration::enumerate_services(&mut host_info, config, progress_tx.clone()).await?;
        }

        // Step 4: OS fingerprinting
        if config.enable_os_detection && !host_info.ports.is_empty() {
            info!("Phase 4: OS Fingerprinting for {}", target_ip_str);
            send_progress(
                &progress_tx,
                ScanProgressMessage::PhaseStarted {
                    phase: "os_fingerprint".to_string(),
                    progress: 70.0 + (idx as f32 / total_hosts as f32) * 15.0,
                },
            );

            host_info.os_guess = os_fingerprint::fingerprint_os(&host_info.target, &host_info.ports, config).await?;
        }

        // Step 5: Vulnerability scanning
        if config.enable_vuln_scan && !host_info.ports.is_empty() {
            info!("Phase 5: Vulnerability Scanning for {}", target_ip_str);
            send_progress(
                &progress_tx,
                ScanProgressMessage::PhaseStarted {
                    phase: "vuln_scan".to_string(),
                    progress: 85.0 + (idx as f32 / total_hosts as f32) * 14.0,
                },
            );

            host_info.vulnerabilities =
                crate::vuln::scanner::scan_vulnerabilities(&host_info, config).await?;

            // Notify about found vulnerabilities
            for vuln in &host_info.vulnerabilities {
                send_progress(
                    &progress_tx,
                    ScanProgressMessage::VulnerabilityFound {
                        ip: target_ip_str.clone(),
                        cve_id: vuln.cve_id.clone(),
                        severity: format!("{:?}", vuln.severity),
                        title: vuln.title.clone(),
                    },
                );
            }
        }

        results.push(host_info);
    }

    let duration = start.elapsed();
    info!("Scan completed in {:.2}s", duration.as_secs_f64());

    Ok(results)
}
