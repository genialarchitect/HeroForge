//! Kubernetes workload security

use super::*;
use anyhow::Result;
use std::process::Command;

pub struct WorkloadScanner {
    /// Path to kubeconfig file
    kubeconfig_path: Option<String>,
    /// Kubernetes context to use
    context: Option<String>,
    /// Namespace to scan (None for all namespaces)
    namespace: Option<String>,
}

impl WorkloadScanner {
    pub fn new() -> Self {
        Self {
            kubeconfig_path: None,
            context: None,
            namespace: None,
        }
    }

    pub fn with_config(kubeconfig_path: Option<String>, context: Option<String>, namespace: Option<String>) -> Self {
        Self {
            kubeconfig_path,
            context,
            namespace,
        }
    }

    /// Build kubectl command with optional kubeconfig and context
    fn kubectl_cmd(&self) -> Command {
        let mut cmd = Command::new("kubectl");
        if let Some(path) = &self.kubeconfig_path {
            cmd.arg("--kubeconfig").arg(path);
        }
        if let Some(ctx) = &self.context {
            cmd.arg("--context").arg(ctx);
        }
        cmd
    }

    /// Scan all workload security aspects
    pub async fn scan_all(&self) -> Result<Vec<K8sFinding>> {
        let mut findings = Vec::new();
        findings.extend(self.scan_pod_security().await?);
        findings.extend(self.scan_images().await?);
        findings.extend(self.scan_runtime().await?);
        Ok(findings)
    }

    /// Scan Pod Security Standards compliance
    pub async fn scan_pod_security(&self) -> Result<Vec<K8sFinding>> {
        let mut findings = Vec::new();

        // Get pods based on namespace scope
        let mut cmd = self.kubectl_cmd();
        cmd.args(["get", "pods"]);
        if let Some(ns) = &self.namespace {
            cmd.args(["-n", ns]);
        } else {
            cmd.arg("--all-namespaces");
        }
        cmd.args(["-o", "json"]);

        let pods_output = cmd.output()?;

        if pods_output.status.success() {
            if let Ok(pod_list) = serde_json::from_slice::<serde_json::Value>(&pods_output.stdout) {
                if let Some(items) = pod_list.get("items").and_then(|i| i.as_array()) {
                    for pod in items {
                        let pod_name = pod.get("metadata")
                            .and_then(|m| m.get("name"))
                            .and_then(|n| n.as_str())
                            .unwrap_or("unknown");
                        let namespace = pod.get("metadata")
                            .and_then(|m| m.get("namespace"))
                            .and_then(|n| n.as_str())
                            .unwrap_or("default");

                        // Skip kube-system pods for some checks
                        let is_system_pod = namespace == "kube-system" || namespace == "kube-public" || namespace == "kube-node-lease";

                        if let Some(spec) = pod.get("spec") {
                            // Check hostNetwork
                            if spec.get("hostNetwork").and_then(|h| h.as_bool()).unwrap_or(false) {
                                if !is_system_pod {
                                    findings.push(K8sFinding {
                                        resource_type: "Pod".to_string(),
                                        resource_name: pod_name.to_string(),
                                        namespace: namespace.to_string(),
                                        finding_type: "Host Network Enabled".to_string(),
                                        severity: "high".to_string(),
                                        description: format!(
                                            "Pod '{}' uses hostNetwork: true. This allows the pod to access host network interfaces and bypass network policies.",
                                            pod_name
                                        ),
                                        remediation: "Remove hostNetwork: true unless absolutely required. Use Network Policies to control pod communication.".to_string(),
                                    });
                                }
                            }

                            // Check hostPID
                            if spec.get("hostPID").and_then(|h| h.as_bool()).unwrap_or(false) {
                                if !is_system_pod {
                                    findings.push(K8sFinding {
                                        resource_type: "Pod".to_string(),
                                        resource_name: pod_name.to_string(),
                                        namespace: namespace.to_string(),
                                        finding_type: "Host PID Namespace".to_string(),
                                        severity: "high".to_string(),
                                        description: format!(
                                            "Pod '{}' uses hostPID: true. This allows viewing all processes on the host and potential PID namespace escape.",
                                            pod_name
                                        ),
                                        remediation: "Remove hostPID: true. Containers should not need access to host PID namespace.".to_string(),
                                    });
                                }
                            }

                            // Check hostIPC
                            if spec.get("hostIPC").and_then(|h| h.as_bool()).unwrap_or(false) {
                                if !is_system_pod {
                                    findings.push(K8sFinding {
                                        resource_type: "Pod".to_string(),
                                        resource_name: pod_name.to_string(),
                                        namespace: namespace.to_string(),
                                        finding_type: "Host IPC Namespace".to_string(),
                                        severity: "high".to_string(),
                                        description: format!(
                                            "Pod '{}' uses hostIPC: true. This allows access to host IPC resources and potential information disclosure.",
                                            pod_name
                                        ),
                                        remediation: "Remove hostIPC: true unless inter-process communication with host is required.".to_string(),
                                    });
                                }
                            }

                            // Check for hostPath volumes
                            if let Some(volumes) = spec.get("volumes").and_then(|v| v.as_array()) {
                                for volume in volumes {
                                    if let Some(host_path) = volume.get("hostPath") {
                                        let vol_name = volume.get("name").and_then(|n| n.as_str()).unwrap_or("unknown");
                                        let path = host_path.get("path").and_then(|p| p.as_str()).unwrap_or("unknown");

                                        // Sensitive host paths
                                        let sensitive_paths = ["/", "/etc", "/var", "/root", "/home", "/proc", "/sys",
                                            "/var/run/docker.sock", "/var/run/crio/crio.sock", "/run/containerd/containerd.sock"];

                                        if sensitive_paths.iter().any(|p| path.starts_with(p) || path == *p) {
                                            findings.push(K8sFinding {
                                                resource_type: "Pod".to_string(),
                                                resource_name: pod_name.to_string(),
                                                namespace: namespace.to_string(),
                                                finding_type: "Sensitive hostPath Mount".to_string(),
                                                severity: "critical".to_string(),
                                                description: format!(
                                                    "Pod '{}' mounts sensitive host path '{}' via volume '{}'. This could allow container escape or host compromise.",
                                                    pod_name, path, vol_name
                                                ),
                                                remediation: "Avoid mounting sensitive host paths. Use PersistentVolumes or emptyDir instead.".to_string(),
                                            });
                                        }
                                    }
                                }
                            }

                            // Check containers
                            if let Some(containers) = spec.get("containers").and_then(|c| c.as_array()) {
                                for container in containers {
                                    let container_name = container.get("name").and_then(|n| n.as_str()).unwrap_or("unknown");

                                    // Check security context
                                    if let Some(sec_ctx) = container.get("securityContext") {
                                        // Check privileged
                                        if sec_ctx.get("privileged").and_then(|p| p.as_bool()).unwrap_or(false) {
                                            findings.push(K8sFinding {
                                                resource_type: "Pod".to_string(),
                                                resource_name: format!("{}/{}", pod_name, container_name),
                                                namespace: namespace.to_string(),
                                                finding_type: "Privileged Container".to_string(),
                                                severity: "critical".to_string(),
                                                description: format!(
                                                    "Container '{}' in pod '{}' runs as privileged. This grants full host access.",
                                                    container_name, pod_name
                                                ),
                                                remediation: "Remove privileged: true. Use specific capabilities instead of full privileges.".to_string(),
                                            });
                                        }

                                        // Check allowPrivilegeEscalation
                                        let allow_priv_esc = sec_ctx.get("allowPrivilegeEscalation")
                                            .and_then(|a| a.as_bool())
                                            .unwrap_or(true); // Default is true

                                        if allow_priv_esc {
                                            findings.push(K8sFinding {
                                                resource_type: "Pod".to_string(),
                                                resource_name: format!("{}/{}", pod_name, container_name),
                                                namespace: namespace.to_string(),
                                                finding_type: "Privilege Escalation Allowed".to_string(),
                                                severity: "medium".to_string(),
                                                description: format!(
                                                    "Container '{}' allows privilege escalation (default behavior). Processes may gain more privileges than parent.",
                                                    container_name
                                                ),
                                                remediation: "Set allowPrivilegeEscalation: false in the container securityContext.".to_string(),
                                            });
                                        }

                                        // Check runAsRoot
                                        let run_as_user = sec_ctx.get("runAsUser").and_then(|r| r.as_i64());
                                        let run_as_non_root = sec_ctx.get("runAsNonRoot").and_then(|r| r.as_bool());

                                        if run_as_user == Some(0) || (run_as_user.is_none() && run_as_non_root != Some(true)) {
                                            findings.push(K8sFinding {
                                                resource_type: "Pod".to_string(),
                                                resource_name: format!("{}/{}", pod_name, container_name),
                                                namespace: namespace.to_string(),
                                                finding_type: "Running as Root".to_string(),
                                                severity: "medium".to_string(),
                                                description: format!(
                                                    "Container '{}' may run as root (UID 0). Root containers have elevated privileges.",
                                                    container_name
                                                ),
                                                remediation: "Set runAsNonRoot: true and specify a non-zero runAsUser in securityContext.".to_string(),
                                            });
                                        }

                                        // Check dangerous capabilities
                                        if let Some(capabilities) = sec_ctx.get("capabilities") {
                                            if let Some(add) = capabilities.get("add").and_then(|a| a.as_array()) {
                                                let dangerous_caps = ["SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE", "NET_ADMIN",
                                                    "SYS_RAWIO", "DAC_OVERRIDE", "SETUID", "SETGID"];

                                                for cap in add {
                                                    if let Some(cap_str) = cap.as_str() {
                                                        if dangerous_caps.contains(&cap_str) {
                                                            findings.push(K8sFinding {
                                                                resource_type: "Pod".to_string(),
                                                                resource_name: format!("{}/{}", pod_name, container_name),
                                                                namespace: namespace.to_string(),
                                                                finding_type: "Dangerous Capability".to_string(),
                                                                severity: "high".to_string(),
                                                                description: format!(
                                                                    "Container '{}' has dangerous capability '{}' added. This can be used for privilege escalation.",
                                                                    container_name, cap_str
                                                                ),
                                                                remediation: format!("Remove capability {}. Use minimum required capabilities.", cap_str),
                                                            });
                                                        }
                                                    }
                                                }
                                            }
                                        }

                                        // Check readOnlyRootFilesystem
                                        if sec_ctx.get("readOnlyRootFilesystem").and_then(|r| r.as_bool()).unwrap_or(false) == false {
                                            findings.push(K8sFinding {
                                                resource_type: "Pod".to_string(),
                                                resource_name: format!("{}/{}", pod_name, container_name),
                                                namespace: namespace.to_string(),
                                                finding_type: "Writable Root Filesystem".to_string(),
                                                severity: "low".to_string(),
                                                description: format!(
                                                    "Container '{}' has writable root filesystem. This can allow malware persistence.",
                                                    container_name
                                                ),
                                                remediation: "Set readOnlyRootFilesystem: true and use emptyDir volumes for write needs.".to_string(),
                                            });
                                        }
                                    } else {
                                        // No security context defined
                                        findings.push(K8sFinding {
                                            resource_type: "Pod".to_string(),
                                            resource_name: format!("{}/{}", pod_name, container_name),
                                            namespace: namespace.to_string(),
                                            finding_type: "Missing Security Context".to_string(),
                                            severity: "medium".to_string(),
                                            description: format!(
                                                "Container '{}' has no securityContext defined. Default security settings may be insecure.",
                                                container_name
                                            ),
                                            remediation: "Define a securityContext with runAsNonRoot: true, allowPrivilegeEscalation: false, and readOnlyRootFilesystem: true.".to_string(),
                                        });
                                    }

                                    // Check resource limits
                                    if container.get("resources").and_then(|r| r.get("limits")).is_none() {
                                        findings.push(K8sFinding {
                                            resource_type: "Pod".to_string(),
                                            resource_name: format!("{}/{}", pod_name, container_name),
                                            namespace: namespace.to_string(),
                                            finding_type: "No Resource Limits".to_string(),
                                            severity: "low".to_string(),
                                            description: format!(
                                                "Container '{}' has no resource limits. This can lead to resource exhaustion attacks.",
                                                container_name
                                            ),
                                            remediation: "Set CPU and memory limits in resources.limits.".to_string(),
                                        });
                                    }
                                }
                            }

                            // Check for automountServiceAccountToken
                            let automount = spec.get("automountServiceAccountToken")
                                .and_then(|a| a.as_bool())
                                .unwrap_or(true);

                            if automount && !is_system_pod {
                                findings.push(K8sFinding {
                                    resource_type: "Pod".to_string(),
                                    resource_name: pod_name.to_string(),
                                    namespace: namespace.to_string(),
                                    finding_type: "Auto-Mounted Service Account Token".to_string(),
                                    severity: "low".to_string(),
                                    description: format!(
                                        "Pod '{}' automatically mounts service account token. This exposes API credentials to containers.",
                                        pod_name
                                    ),
                                    remediation: "Set automountServiceAccountToken: false unless API access is needed.".to_string(),
                                });
                            }
                        }
                    }
                }
            }
        }

        Ok(findings)
    }

    /// Scan container images for vulnerabilities
    pub async fn scan_images(&self) -> Result<Vec<K8sFinding>> {
        let mut findings = Vec::new();

        // Get pods to extract image information
        let mut cmd = self.kubectl_cmd();
        cmd.args(["get", "pods"]);
        if let Some(ns) = &self.namespace {
            cmd.args(["-n", ns]);
        } else {
            cmd.arg("--all-namespaces");
        }
        cmd.args(["-o", "json"]);

        let pods_output = cmd.output()?;

        if pods_output.status.success() {
            if let Ok(pod_list) = serde_json::from_slice::<serde_json::Value>(&pods_output.stdout) {
                if let Some(items) = pod_list.get("items").and_then(|i| i.as_array()) {
                    let mut seen_images: std::collections::HashSet<String> = std::collections::HashSet::new();

                    for pod in items {
                        let pod_name = pod.get("metadata")
                            .and_then(|m| m.get("name"))
                            .and_then(|n| n.as_str())
                            .unwrap_or("unknown");
                        let namespace = pod.get("metadata")
                            .and_then(|m| m.get("namespace"))
                            .and_then(|n| n.as_str())
                            .unwrap_or("default");

                        if let Some(spec) = pod.get("spec") {
                            if let Some(containers) = spec.get("containers").and_then(|c| c.as_array()) {
                                for container in containers {
                                    let container_name = container.get("name").and_then(|n| n.as_str()).unwrap_or("unknown");
                                    let image = container.get("image").and_then(|i| i.as_str()).unwrap_or("unknown");

                                    // Check image tag
                                    if image.contains(":latest") || !image.contains(':') {
                                        findings.push(K8sFinding {
                                            resource_type: "Pod".to_string(),
                                            resource_name: format!("{}/{}", pod_name, container_name),
                                            namespace: namespace.to_string(),
                                            finding_type: "Latest or No Image Tag".to_string(),
                                            severity: "medium".to_string(),
                                            description: format!(
                                                "Container '{}' uses image '{}' with ':latest' tag or no tag. This is unpredictable and not reproducible.",
                                                container_name, image
                                            ),
                                            remediation: "Use specific image tags (e.g., :v1.2.3) or SHA256 digests for reproducibility.".to_string(),
                                        });
                                    }

                                    // Check for insecure registries (non-HTTPS)
                                    if image.starts_with("http://") {
                                        findings.push(K8sFinding {
                                            resource_type: "Pod".to_string(),
                                            resource_name: format!("{}/{}", pod_name, container_name),
                                            namespace: namespace.to_string(),
                                            finding_type: "Insecure Registry".to_string(),
                                            severity: "high".to_string(),
                                            description: format!(
                                                "Container '{}' pulls image from insecure HTTP registry: '{}'",
                                                container_name, image
                                            ),
                                            remediation: "Use HTTPS registries only. Configure container runtime to reject insecure registries.".to_string(),
                                        });
                                    }

                                    // Check imagePullPolicy
                                    let pull_policy = container.get("imagePullPolicy")
                                        .and_then(|p| p.as_str())
                                        .unwrap_or("");

                                    if pull_policy == "Never" || (pull_policy.is_empty() && image.contains(":latest")) {
                                        findings.push(K8sFinding {
                                            resource_type: "Pod".to_string(),
                                            resource_name: format!("{}/{}", pod_name, container_name),
                                            namespace: namespace.to_string(),
                                            finding_type: "Weak Image Pull Policy".to_string(),
                                            severity: "low".to_string(),
                                            description: format!(
                                                "Container '{}' may not pull latest image. Consider using 'Always' for security updates.",
                                                container_name
                                            ),
                                            remediation: "Set imagePullPolicy: Always for mutable tags, or use immutable tags/digests.".to_string(),
                                        });
                                    }

                                    // Check for known vulnerable base images (simplified check)
                                    let vulnerable_patterns = [
                                        ("alpine:3.12", "Alpine 3.12 is EOL and has known CVEs"),
                                        ("alpine:3.13", "Alpine 3.13 is EOL and has known CVEs"),
                                        ("ubuntu:18.04", "Ubuntu 18.04 LTS reached end of standard support"),
                                        ("debian:stretch", "Debian Stretch (9) is EOL"),
                                        ("debian:jessie", "Debian Jessie (8) is EOL"),
                                        ("centos:7", "CentOS 7 reached end of maintenance updates"),
                                        ("centos:8", "CentOS 8 is EOL"),
                                        ("node:12", "Node.js 12 is EOL and has known vulnerabilities"),
                                        ("node:14", "Node.js 14 is EOL and has known vulnerabilities"),
                                        ("python:3.6", "Python 3.6 is EOL and has known vulnerabilities"),
                                        ("python:3.7", "Python 3.7 is EOL and has known vulnerabilities"),
                                    ];

                                    for (pattern, message) in vulnerable_patterns {
                                        if image.contains(pattern) && !seen_images.contains(image) {
                                            seen_images.insert(image.to_string());
                                            findings.push(K8sFinding {
                                                resource_type: "Pod".to_string(),
                                                resource_name: format!("{}/{}", pod_name, container_name),
                                                namespace: namespace.to_string(),
                                                finding_type: "Outdated Base Image".to_string(),
                                                severity: "high".to_string(),
                                                description: format!(
                                                    "Image '{}' uses an outdated/vulnerable base: {}",
                                                    image, message
                                                ),
                                                remediation: "Update to a supported and patched base image version.".to_string(),
                                            });
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(findings)
    }

    /// Scan runtime security (container status and behavior)
    pub async fn scan_runtime(&self) -> Result<Vec<K8sFinding>> {
        let mut findings = Vec::new();

        // Get pods with their status
        let mut cmd = self.kubectl_cmd();
        cmd.args(["get", "pods"]);
        if let Some(ns) = &self.namespace {
            cmd.args(["-n", ns]);
        } else {
            cmd.arg("--all-namespaces");
        }
        cmd.args(["-o", "json"]);

        let pods_output = cmd.output()?;

        if pods_output.status.success() {
            if let Ok(pod_list) = serde_json::from_slice::<serde_json::Value>(&pods_output.stdout) {
                if let Some(items) = pod_list.get("items").and_then(|i| i.as_array()) {
                    for pod in items {
                        let pod_name = pod.get("metadata")
                            .and_then(|m| m.get("name"))
                            .and_then(|n| n.as_str())
                            .unwrap_or("unknown");
                        let namespace = pod.get("metadata")
                            .and_then(|m| m.get("namespace"))
                            .and_then(|n| n.as_str())
                            .unwrap_or("default");

                        if let Some(status) = pod.get("status") {
                            // Check for crashed or restarting containers
                            if let Some(container_statuses) = status.get("containerStatuses").and_then(|c| c.as_array()) {
                                for cs in container_statuses {
                                    let container_name = cs.get("name").and_then(|n| n.as_str()).unwrap_or("unknown");
                                    let restart_count = cs.get("restartCount").and_then(|r| r.as_i64()).unwrap_or(0);

                                    // High restart count may indicate instability or attack attempts
                                    if restart_count > 10 {
                                        findings.push(K8sFinding {
                                            resource_type: "Pod".to_string(),
                                            resource_name: format!("{}/{}", pod_name, container_name),
                                            namespace: namespace.to_string(),
                                            finding_type: "High Restart Count".to_string(),
                                            severity: "medium".to_string(),
                                            description: format!(
                                                "Container '{}' has restarted {} times. This may indicate instability, crashes, or attack attempts.",
                                                container_name, restart_count
                                            ),
                                            remediation: "Investigate container logs for crash reasons. Check for resource exhaustion or misconfigurations.".to_string(),
                                        });
                                    }

                                    // Check for CrashLoopBackOff
                                    if let Some(waiting) = cs.get("state").and_then(|s| s.get("waiting")) {
                                        let reason = waiting.get("reason").and_then(|r| r.as_str()).unwrap_or("");
                                        if reason == "CrashLoopBackOff" {
                                            findings.push(K8sFinding {
                                                resource_type: "Pod".to_string(),
                                                resource_name: format!("{}/{}", pod_name, container_name),
                                                namespace: namespace.to_string(),
                                                finding_type: "CrashLoopBackOff".to_string(),
                                                severity: "high".to_string(),
                                                description: format!(
                                                    "Container '{}' is in CrashLoopBackOff. The container is crashing repeatedly.",
                                                    container_name
                                                ),
                                                remediation: "Check container logs, verify configuration, and ensure resource availability.".to_string(),
                                            });
                                        } else if reason == "ImagePullBackOff" || reason == "ErrImagePull" {
                                            findings.push(K8sFinding {
                                                resource_type: "Pod".to_string(),
                                                resource_name: format!("{}/{}", pod_name, container_name),
                                                namespace: namespace.to_string(),
                                                finding_type: "Image Pull Failure".to_string(),
                                                severity: "medium".to_string(),
                                                description: format!(
                                                    "Container '{}' cannot pull image. This may indicate registry issues or invalid credentials.",
                                                    container_name
                                                ),
                                                remediation: "Verify image exists, check registry credentials, and ensure network access to registry.".to_string(),
                                            });
                                        }
                                    }

                                    // Check for terminated with error
                                    if let Some(terminated) = cs.get("lastState").and_then(|s| s.get("terminated")) {
                                        let exit_code = terminated.get("exitCode").and_then(|e| e.as_i64()).unwrap_or(0);
                                        let reason = terminated.get("reason").and_then(|r| r.as_str()).unwrap_or("");

                                        if reason == "OOMKilled" {
                                            findings.push(K8sFinding {
                                                resource_type: "Pod".to_string(),
                                                resource_name: format!("{}/{}", pod_name, container_name),
                                                namespace: namespace.to_string(),
                                                finding_type: "OOM Killed".to_string(),
                                                severity: "medium".to_string(),
                                                description: format!(
                                                    "Container '{}' was OOM killed. Memory limit may be too low or there's a memory leak.",
                                                    container_name
                                                ),
                                                remediation: "Increase memory limits or investigate application memory usage.".to_string(),
                                            });
                                        } else if exit_code == 137 {
                                            findings.push(K8sFinding {
                                                resource_type: "Pod".to_string(),
                                                resource_name: format!("{}/{}", pod_name, container_name),
                                                namespace: namespace.to_string(),
                                                finding_type: "Container Killed (SIGKILL)".to_string(),
                                                severity: "low".to_string(),
                                                description: format!(
                                                    "Container '{}' was terminated with SIGKILL (exit code 137). May indicate OOM or forced termination.",
                                                    container_name
                                                ),
                                                remediation: "Check if container was OOM killed or manually terminated.".to_string(),
                                            });
                                        }
                                    }
                                }
                            }

                            // Check pod phase
                            let phase = status.get("phase").and_then(|p| p.as_str()).unwrap_or("");
                            if phase == "Failed" {
                                findings.push(K8sFinding {
                                    resource_type: "Pod".to_string(),
                                    resource_name: pod_name.to_string(),
                                    namespace: namespace.to_string(),
                                    finding_type: "Pod Failed".to_string(),
                                    severity: "medium".to_string(),
                                    description: format!(
                                        "Pod '{}' is in Failed state.",
                                        pod_name
                                    ),
                                    remediation: "Investigate pod events and container logs to determine failure reason.".to_string(),
                                });
                            }
                        }
                    }
                }
            }
        }

        // Check for pods with excessive CPU/memory usage (if metrics available)
        let metrics_output = self.kubectl_cmd()
            .args(["top", "pods"])
            .args(if self.namespace.is_some() { vec!["-n", self.namespace.as_ref().unwrap()] } else { vec!["--all-namespaces"] })
            .output();

        if let Ok(output) = metrics_output {
            if !output.status.success() {
                findings.push(K8sFinding {
                    resource_type: "Cluster".to_string(),
                    resource_name: "metrics-server".to_string(),
                    namespace: "kube-system".to_string(),
                    finding_type: "Metrics Not Available".to_string(),
                    severity: "info".to_string(),
                    description: "Kubernetes metrics-server is not available. Cannot monitor resource usage.".to_string(),
                    remediation: "Install metrics-server to enable resource monitoring and HPA.".to_string(),
                });
            }
        }

        Ok(findings)
    }
}

impl Default for WorkloadScanner {
    fn default() -> Self {
        Self::new()
    }
}
