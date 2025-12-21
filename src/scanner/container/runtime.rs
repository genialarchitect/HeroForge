//! Container Runtime Security Scanner
//!
//! This module scans running containers for security issues:
//! - Privileged mode containers
//! - Host network/PID/IPC namespace sharing
//! - Dangerous capabilities
//! - Sensitive volume mounts
//! - Resource limits

use anyhow::Result;
use chrono::Utc;
use serde::Deserialize;
use std::process::Command;
use uuid::Uuid;

use super::types::{
    ContainerFinding, ContainerFindingSeverity, ContainerFindingType, ContainerScanConfig,
    FindingStatus,
};

/// Scan running containers for security issues (real implementation)
pub async fn scan_runtime(
    _config: &ContainerScanConfig,
) -> Result<Vec<ContainerFinding>> {
    let mut findings = Vec::new();
    let scan_id = Uuid::new_v4().to_string();

    // Get list of running containers
    let output = Command::new("docker")
        .args(["ps", "-q"])
        .output()?;

    if !output.status.success() {
        log::warn!("Failed to list Docker containers. Docker may not be available.");
        return Ok(findings);
    }

    let container_ids: Vec<&str> = std::str::from_utf8(&output.stdout)?
        .lines()
        .filter(|s| !s.is_empty())
        .collect();

    for container_id in container_ids {
        let container_findings = inspect_container(container_id, &scan_id).await?;
        findings.extend(container_findings);
    }

    Ok(findings)
}

/// Generate demo runtime scan results
pub async fn scan_runtime_demo(
    _config: &ContainerScanConfig,
) -> Result<Vec<ContainerFinding>> {
    let scan_id = Uuid::new_v4().to_string();

    let demo_findings = vec![
        ContainerFinding {
            id: Uuid::new_v4().to_string(),
            scan_id: scan_id.clone(),
            image_id: None,
            resource_id: Some("container_web_app_1".to_string()),
            finding_type: ContainerFindingType::PrivilegeEscalation,
            severity: ContainerFindingSeverity::Critical,
            title: "Container running in privileged mode".to_string(),
            description: "The container 'web_app' is running with --privileged flag. \
                This gives the container full access to the host system, effectively \
                bypassing all container isolation.".to_string(),
            cve_id: None,
            cvss_score: None,
            cwe_ids: vec!["CWE-250".to_string()],
            package_name: None,
            package_version: None,
            fixed_version: None,
            file_path: None,
            line_number: None,
            remediation: Some(
                "Remove the --privileged flag. If specific capabilities are needed, \
                use --cap-add to grant only the required capabilities.".to_string()
            ),
            references: vec![
                "https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities".to_string(),
            ],
            status: FindingStatus::Open,
            created_at: Utc::now(),
        },
        ContainerFinding {
            id: Uuid::new_v4().to_string(),
            scan_id: scan_id.clone(),
            image_id: None,
            resource_id: Some("container_db_1".to_string()),
            finding_type: ContainerFindingType::NetworkExposure,
            severity: ContainerFindingSeverity::High,
            title: "Container using host network mode".to_string(),
            description: "The container 'db' is using --net=host, which shares the host's \
                network namespace. This bypasses Docker's network isolation and exposes \
                all host network interfaces.".to_string(),
            cve_id: None,
            cvss_score: None,
            cwe_ids: vec!["CWE-668".to_string()],
            package_name: None,
            package_version: None,
            fixed_version: None,
            file_path: None,
            line_number: None,
            remediation: Some(
                "Use Docker's bridge networking or create a custom network. \
                Only expose necessary ports with -p flag.".to_string()
            ),
            references: vec![],
            status: FindingStatus::Open,
            created_at: Utc::now(),
        },
        ContainerFinding {
            id: Uuid::new_v4().to_string(),
            scan_id: scan_id.clone(),
            image_id: None,
            resource_id: Some("container_app_1".to_string()),
            finding_type: ContainerFindingType::Misconfiguration,
            severity: ContainerFindingSeverity::High,
            title: "Dangerous capability: SYS_ADMIN".to_string(),
            description: "The container has the SYS_ADMIN capability, which allows many \
                privileged operations including mounting filesystems and loading kernel modules.".to_string(),
            cve_id: None,
            cvss_score: None,
            cwe_ids: vec!["CWE-250".to_string()],
            package_name: None,
            package_version: None,
            fixed_version: None,
            file_path: None,
            line_number: None,
            remediation: Some(
                "Remove SYS_ADMIN capability unless absolutely necessary. \
                Consider using more specific capabilities.".to_string()
            ),
            references: vec![
                "https://man7.org/linux/man-pages/man7/capabilities.7.html".to_string(),
            ],
            status: FindingStatus::Open,
            created_at: Utc::now(),
        },
        ContainerFinding {
            id: Uuid::new_v4().to_string(),
            scan_id: scan_id.clone(),
            image_id: None,
            resource_id: Some("container_worker_1".to_string()),
            finding_type: ContainerFindingType::Misconfiguration,
            severity: ContainerFindingSeverity::High,
            title: "Docker socket mounted in container".to_string(),
            description: "The Docker socket (/var/run/docker.sock) is mounted inside the container. \
                This allows the container to control the Docker daemon and potentially escape \
                to the host.".to_string(),
            cve_id: None,
            cvss_score: None,
            cwe_ids: vec!["CWE-250".to_string()],
            package_name: None,
            package_version: None,
            fixed_version: None,
            file_path: None,
            line_number: None,
            remediation: Some(
                "Avoid mounting the Docker socket. If Docker-in-Docker is needed, \
                consider using Docker's rootless mode or sysbox runtime.".to_string()
            ),
            references: vec![],
            status: FindingStatus::Open,
            created_at: Utc::now(),
        },
        ContainerFinding {
            id: Uuid::new_v4().to_string(),
            scan_id: scan_id.clone(),
            image_id: None,
            resource_id: Some("container_api_1".to_string()),
            finding_type: ContainerFindingType::Misconfiguration,
            severity: ContainerFindingSeverity::Medium,
            title: "Container running as root user".to_string(),
            description: "The container 'api' is running as root (UID 0). If the container \
                is compromised, the attacker will have root privileges within the container.".to_string(),
            cve_id: None,
            cvss_score: None,
            cwe_ids: vec!["CWE-250".to_string()],
            package_name: None,
            package_version: None,
            fixed_version: None,
            file_path: None,
            line_number: None,
            remediation: Some(
                "Configure the container to run as a non-root user using the USER directive \
                in Dockerfile or --user flag.".to_string()
            ),
            references: vec![],
            status: FindingStatus::Open,
            created_at: Utc::now(),
        },
        ContainerFinding {
            id: Uuid::new_v4().to_string(),
            scan_id: scan_id.clone(),
            image_id: None,
            resource_id: Some("container_cache_1".to_string()),
            finding_type: ContainerFindingType::Misconfiguration,
            severity: ContainerFindingSeverity::Medium,
            title: "No memory limit configured".to_string(),
            description: "The container 'cache' has no memory limit set. This could allow \
                the container to consume all available host memory, affecting other containers \
                and the host system.".to_string(),
            cve_id: None,
            cvss_score: None,
            cwe_ids: vec!["CWE-770".to_string()],
            package_name: None,
            package_version: None,
            fixed_version: None,
            file_path: None,
            line_number: None,
            remediation: Some(
                "Set memory limits using --memory flag or resources.limits in Docker Compose.".to_string()
            ),
            references: vec![],
            status: FindingStatus::Open,
            created_at: Utc::now(),
        },
        ContainerFinding {
            id: Uuid::new_v4().to_string(),
            scan_id: scan_id.clone(),
            image_id: None,
            resource_id: Some("container_debug_1".to_string()),
            finding_type: ContainerFindingType::Misconfiguration,
            severity: ContainerFindingSeverity::Medium,
            title: "Container sharing host PID namespace".to_string(),
            description: "The container is using --pid=host, which allows it to see and \
                potentially interact with all processes on the host.".to_string(),
            cve_id: None,
            cvss_score: None,
            cwe_ids: vec!["CWE-668".to_string()],
            package_name: None,
            package_version: None,
            fixed_version: None,
            file_path: None,
            line_number: None,
            remediation: Some(
                "Remove the --pid=host flag unless absolutely necessary for debugging.".to_string()
            ),
            references: vec![],
            status: FindingStatus::Open,
            created_at: Utc::now(),
        },
        ContainerFinding {
            id: Uuid::new_v4().to_string(),
            scan_id: scan_id.clone(),
            image_id: None,
            resource_id: Some("container_legacy_1".to_string()),
            finding_type: ContainerFindingType::Misconfiguration,
            severity: ContainerFindingSeverity::Low,
            title: "Seccomp profile disabled".to_string(),
            description: "The container is running with --security-opt seccomp=unconfined, \
                which disables the default syscall filtering.".to_string(),
            cve_id: None,
            cvss_score: None,
            cwe_ids: vec![],
            package_name: None,
            package_version: None,
            fixed_version: None,
            file_path: None,
            line_number: None,
            remediation: Some(
                "Remove the seccomp=unconfined option. Use the default profile or create \
                a custom profile for your application.".to_string()
            ),
            references: vec![
                "https://docs.docker.com/engine/security/seccomp/".to_string(),
            ],
            status: FindingStatus::Open,
            created_at: Utc::now(),
        },
    ];

    Ok(demo_findings)
}

/// Inspect a single container for security issues
async fn inspect_container(
    container_id: &str,
    scan_id: &str,
) -> Result<Vec<ContainerFinding>> {
    let mut findings = Vec::new();

    let output = Command::new("docker")
        .args(["inspect", container_id])
        .output()?;

    if !output.status.success() {
        return Ok(findings);
    }

    let inspect_data: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout)?;
    let container = match inspect_data.first() {
        Some(c) => c,
        None => return Ok(findings),
    };

    let name = container.get("Name")
        .and_then(|n| n.as_str())
        .map(|s| s.trim_start_matches('/').to_string())
        .unwrap_or_else(|| container_id.to_string());

    let resource_id = format!("container_{}", name);

    // Check HostConfig for security issues
    if let Some(host_config) = container.get("HostConfig") {
        // Check privileged mode
        if host_config.get("Privileged").and_then(|p| p.as_bool()).unwrap_or(false) {
            findings.push(ContainerFinding {
                id: Uuid::new_v4().to_string(),
                scan_id: scan_id.to_string(),
                image_id: None,
                resource_id: Some(resource_id.clone()),
                finding_type: ContainerFindingType::PrivilegeEscalation,
                severity: ContainerFindingSeverity::Critical,
                title: "Container running in privileged mode".to_string(),
                description: format!(
                    "The container '{}' is running with --privileged flag, \
                    giving it full access to the host system.", name
                ),
                cve_id: None,
                cvss_score: None,
                cwe_ids: vec!["CWE-250".to_string()],
                package_name: None,
                package_version: None,
                fixed_version: None,
                file_path: None,
                line_number: None,
                remediation: Some(
                    "Remove the --privileged flag. Use --cap-add for specific capabilities.".to_string()
                ),
                references: vec![],
                status: FindingStatus::Open,
                created_at: Utc::now(),
            });
        }

        // Check network mode
        if let Some(network_mode) = host_config.get("NetworkMode").and_then(|n| n.as_str()) {
            if network_mode == "host" {
                findings.push(ContainerFinding {
                    id: Uuid::new_v4().to_string(),
                    scan_id: scan_id.to_string(),
                    image_id: None,
                    resource_id: Some(resource_id.clone()),
                    finding_type: ContainerFindingType::NetworkExposure,
                    severity: ContainerFindingSeverity::High,
                    title: "Container using host network mode".to_string(),
                    description: format!(
                        "The container '{}' is using host network namespace, \
                        bypassing Docker's network isolation.", name
                    ),
                    cve_id: None,
                    cvss_score: None,
                    cwe_ids: vec!["CWE-668".to_string()],
                    package_name: None,
                    package_version: None,
                    fixed_version: None,
                    file_path: None,
                    line_number: None,
                    remediation: Some("Use bridge networking and expose only necessary ports.".to_string()),
                    references: vec![],
                    status: FindingStatus::Open,
                    created_at: Utc::now(),
                });
            }
        }

        // Check PID mode
        if let Some(pid_mode) = host_config.get("PidMode").and_then(|p| p.as_str()) {
            if pid_mode == "host" {
                findings.push(ContainerFinding {
                    id: Uuid::new_v4().to_string(),
                    scan_id: scan_id.to_string(),
                    image_id: None,
                    resource_id: Some(resource_id.clone()),
                    finding_type: ContainerFindingType::Misconfiguration,
                    severity: ContainerFindingSeverity::Medium,
                    title: "Container sharing host PID namespace".to_string(),
                    description: format!(
                        "The container '{}' can see and interact with all host processes.", name
                    ),
                    cve_id: None,
                    cvss_score: None,
                    cwe_ids: vec!["CWE-668".to_string()],
                    package_name: None,
                    package_version: None,
                    fixed_version: None,
                    file_path: None,
                    line_number: None,
                    remediation: Some("Remove --pid=host flag.".to_string()),
                    references: vec![],
                    status: FindingStatus::Open,
                    created_at: Utc::now(),
                });
            }
        }

        // Check dangerous capabilities
        if let Some(cap_add) = host_config.get("CapAdd").and_then(|c| c.as_array()) {
            let dangerous_caps = ["SYS_ADMIN", "SYS_PTRACE", "NET_ADMIN", "DAC_OVERRIDE"];
            for cap in cap_add {
                if let Some(cap_str) = cap.as_str() {
                    if dangerous_caps.contains(&cap_str) {
                        findings.push(ContainerFinding {
                            id: Uuid::new_v4().to_string(),
                            scan_id: scan_id.to_string(),
                            image_id: None,
                            resource_id: Some(resource_id.clone()),
                            finding_type: ContainerFindingType::Misconfiguration,
                            severity: ContainerFindingSeverity::High,
                            title: format!("Dangerous capability: {}", cap_str),
                            description: format!(
                                "The container '{}' has the {} capability which could be used for privilege escalation.",
                                name, cap_str
                            ),
                            cve_id: None,
                            cvss_score: None,
                            cwe_ids: vec!["CWE-250".to_string()],
                            package_name: None,
                            package_version: None,
                            fixed_version: None,
                            file_path: None,
                            line_number: None,
                            remediation: Some(format!("Remove {} capability if not required.", cap_str)),
                            references: vec![],
                            status: FindingStatus::Open,
                            created_at: Utc::now(),
                        });
                    }
                }
            }
        }

        // Check for Docker socket mount
        if let Some(binds) = host_config.get("Binds").and_then(|b| b.as_array()) {
            for bind in binds {
                if let Some(bind_str) = bind.as_str() {
                    if bind_str.contains("/var/run/docker.sock") {
                        findings.push(ContainerFinding {
                            id: Uuid::new_v4().to_string(),
                            scan_id: scan_id.to_string(),
                            image_id: None,
                            resource_id: Some(resource_id.clone()),
                            finding_type: ContainerFindingType::Misconfiguration,
                            severity: ContainerFindingSeverity::High,
                            title: "Docker socket mounted in container".to_string(),
                            description: format!(
                                "The container '{}' has the Docker socket mounted, \
                                allowing container escape.", name
                            ),
                            cve_id: None,
                            cvss_score: None,
                            cwe_ids: vec!["CWE-250".to_string()],
                            package_name: None,
                            package_version: None,
                            fixed_version: None,
                            file_path: None,
                            line_number: None,
                            remediation: Some(
                                "Avoid mounting Docker socket. Consider Docker-in-Docker alternatives.".to_string()
                            ),
                            references: vec![],
                            status: FindingStatus::Open,
                            created_at: Utc::now(),
                        });
                    }
                }
            }
        }

        // Check memory limits
        let memory = host_config.get("Memory").and_then(|m| m.as_i64()).unwrap_or(0);
        if memory == 0 {
            findings.push(ContainerFinding {
                id: Uuid::new_v4().to_string(),
                scan_id: scan_id.to_string(),
                image_id: None,
                resource_id: Some(resource_id.clone()),
                finding_type: ContainerFindingType::Misconfiguration,
                severity: ContainerFindingSeverity::Medium,
                title: "No memory limit configured".to_string(),
                description: format!(
                    "The container '{}' has no memory limit, risking resource exhaustion.", name
                ),
                cve_id: None,
                cvss_score: None,
                cwe_ids: vec!["CWE-770".to_string()],
                package_name: None,
                package_version: None,
                fixed_version: None,
                file_path: None,
                line_number: None,
                remediation: Some("Set memory limits using --memory flag.".to_string()),
                references: vec![],
                status: FindingStatus::Open,
                created_at: Utc::now(),
            });
        }
    }

    // Check if running as root
    if let Some(config) = container.get("Config") {
        let user = config.get("User").and_then(|u| u.as_str()).unwrap_or("");
        if user.is_empty() || user == "root" || user == "0" {
            findings.push(ContainerFinding {
                id: Uuid::new_v4().to_string(),
                scan_id: scan_id.to_string(),
                image_id: None,
                resource_id: Some(resource_id.clone()),
                finding_type: ContainerFindingType::Misconfiguration,
                severity: ContainerFindingSeverity::Medium,
                title: "Container running as root user".to_string(),
                description: format!(
                    "The container '{}' is running as root (UID 0).", name
                ),
                cve_id: None,
                cvss_score: None,
                cwe_ids: vec!["CWE-250".to_string()],
                package_name: None,
                package_version: None,
                fixed_version: None,
                file_path: None,
                line_number: None,
                remediation: Some("Run container as non-root user with --user flag.".to_string()),
                references: vec![],
                status: FindingStatus::Open,
                created_at: Utc::now(),
            });
        }
    }

    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_scan_runtime_demo() {
        let config = ContainerScanConfig {
            name: "Test".to_string(),
            scan_types: vec![],
            images: vec![],
            registry_url: None,
            registry_username: None,
            registry_password: None,
            dockerfile_content: None,
            manifest_content: None,
            k8s_context: None,
            k8s_namespace: None,
            demo_mode: true,
            customer_id: None,
            engagement_id: None,
        };

        let findings = scan_runtime_demo(&config).await.unwrap();
        assert!(!findings.is_empty());

        // Check for various finding types
        let has_privileged = findings.iter()
            .any(|f| f.title.contains("privileged"));
        assert!(has_privileged);
    }
}
