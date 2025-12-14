use anyhow::Result;
pub mod enumeration;
pub mod host_discovery;
pub mod os_fingerprint;
pub mod port_scanner;
pub mod service_detection;

use crate::types::{HostInfo, ScanConfig, ScanProgressMessage};
use log::info;
use std::time::Instant;
use tokio::sync::broadcast::Sender;

pub async fn run_scan(
    config: &ScanConfig,
    progress_tx: Option<Sender<ScanProgressMessage>>,
) -> Result<Vec<HostInfo>, anyhow::Error> {
    let start = Instant::now();
    info!("Starting comprehensive network scan...");

    // Helper function to send progress messages
    let send_progress = |tx: &Option<Sender<ScanProgressMessage>>, msg: ScanProgressMessage| {
        if let Some(sender) = tx {
            let _ = sender.send(msg);
        }
    };

    // Step 1: Discover live hosts
    info!("Phase 1: Host Discovery");
    send_progress(
        &progress_tx,
        ScanProgressMessage::PhaseStarted {
            phase: "discovery".to_string(),
            progress: 0.0,
        },
    );

    let live_hosts = host_discovery::discover_hosts(config).await?;
    info!("Found {} live hosts", live_hosts.len());

    if live_hosts.is_empty() {
        return Ok(Vec::new());
    }

    // Notify about discovered hosts
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

        // Scan ports
        let ports = port_scanner::scan_target_ports(&target, config).await?;

        // Notify about found ports
        for port in &ports {
            send_progress(
                &progress_tx,
                ScanProgressMessage::PortFound {
                    ip: target.ip.to_string(),
                    port: port.port,
                    protocol: format!("{:?}", port.protocol),
                    state: format!("{:?}", port.state),
                },
            );
        }

        let mut host_info = HostInfo {
            target: target.clone(),
            is_alive: true,
            os_guess: None,
            ports: ports.clone(),
            vulnerabilities: Vec::new(),
            scan_duration: scan_start.elapsed(),
        };

        // Step 3: Service detection
        if config.enable_service_detection && !ports.is_empty() {
            info!("Phase 3: Service Detection for {}", target.ip);
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
                            ip: target.ip.to_string(),
                            port: port.port,
                            service_name: service.name.clone(),
                            version: service.version.clone(),
                        },
                    );
                }
            }
        }

        // Step 3.5: Enumeration (NEW)
        if config.enable_enumeration && config.enable_service_detection && !ports.is_empty() {
            info!("Phase 3.5: Service Enumeration for {}", target.ip);
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
        if config.enable_os_detection && !ports.is_empty() {
            info!("Phase 4: OS Fingerprinting for {}", target.ip);
            send_progress(
                &progress_tx,
                ScanProgressMessage::PhaseStarted {
                    phase: "os_fingerprint".to_string(),
                    progress: 70.0 + (idx as f32 / total_hosts as f32) * 15.0,
                },
            );

            host_info.os_guess = os_fingerprint::fingerprint_os(&target, &ports, config).await?;
        }

        // Step 5: Vulnerability scanning
        if config.enable_vuln_scan && !ports.is_empty() {
            info!("Phase 5: Vulnerability Scanning for {}", target.ip);
            send_progress(
                &progress_tx,
                ScanProgressMessage::PhaseStarted {
                    phase: "vuln_scan".to_string(),
                    progress: 85.0 + (idx as f32 / total_hosts as f32) * 14.0,
                },
            );

            // Notify about detected services
            for port in &host_info.ports {
                if let Some(service) = &port.service {
                    send_progress(
                        &progress_tx,
                        ScanProgressMessage::ServiceDetected {
                            ip: target.ip.to_string(),
                            port: port.port,
                            service_name: service.name.clone(),
                            version: service.version.clone(),
                        },
                    );
                }
            }
        }

        // Step 4: OS fingerprinting
        if config.enable_os_detection && !ports.is_empty() {
            info!("Phase 4: OS Fingerprinting for {}", target.ip);
            send_progress(
                &progress_tx,
                ScanProgressMessage::PhaseStarted {
                    phase: "os_fingerprint".to_string(),
                    progress: 70.0 + (idx as f32 / total_hosts as f32) * 15.0,
                },
            );

            host_info.os_guess = os_fingerprint::fingerprint_os(&target, &ports, config).await?;
        }

        // Step 5: Vulnerability scanning
        if config.enable_vuln_scan && !ports.is_empty() {
            info!("Phase 5: Vulnerability Scanning for {}", target.ip);
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
                        ip: target.ip.to_string(),
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
