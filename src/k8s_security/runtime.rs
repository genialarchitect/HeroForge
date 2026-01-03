//! Kubernetes runtime security monitoring

use super::*;
use anyhow::Result;
use std::process::Command;

pub struct RuntimeMonitor {
    /// Path to kubeconfig file
    kubeconfig_path: Option<String>,
    /// Kubernetes context to use
    context: Option<String>,
    /// Namespace to monitor (None for all namespaces)
    namespace: Option<String>,
}

impl RuntimeMonitor {
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

    /// Monitor all runtime security aspects
    pub async fn monitor_all(&self) -> Result<Vec<K8sFinding>> {
        let mut findings = Vec::new();
        findings.extend(self.monitor_containers().await?);
        findings.extend(self.monitor_filesystem().await?);
        Ok(findings)
    }

    /// Monitor container behavior - detect anomalous processes and network connections
    pub async fn monitor_containers(&self) -> Result<Vec<K8sFinding>> {
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

                        // Skip system namespaces for process monitoring
                        if namespace == "kube-system" || namespace == "kube-public" || namespace == "kube-node-lease" {
                            continue;
                        }

                        if let Some(spec) = pod.get("spec") {
                            if let Some(containers) = spec.get("containers").and_then(|c| c.as_array()) {
                                for container in containers {
                                    let container_name = container.get("name")
                                        .and_then(|n| n.as_str())
                                        .unwrap_or("unknown");

                                    // Check running processes in container (if exec is allowed)
                                    let proc_output = self.kubectl_cmd()
                                        .args(["exec", "-n", namespace, pod_name, "-c", container_name, "--", "ps", "aux"])
                                        .output();

                                    if let Ok(output) = proc_output {
                                        if output.status.success() {
                                            let proc_list = String::from_utf8_lossy(&output.stdout);

                                            // Check for suspicious processes
                                            let suspicious_processes = [
                                                ("nc ", "Netcat - potential reverse shell or port scanner"),
                                                ("ncat ", "Ncat - potential reverse shell or port scanner"),
                                                ("netcat ", "Netcat - potential reverse shell or port scanner"),
                                                ("/bin/bash -i", "Interactive bash shell - potential shell access"),
                                                ("python -c", "Python one-liner - potential script execution"),
                                                ("perl -e", "Perl one-liner - potential script execution"),
                                                ("curl ", "Curl - potential data exfiltration or download"),
                                                ("wget ", "Wget - potential download of malicious content"),
                                                ("chmod ", "Chmod - potential permission changes"),
                                                ("chown ", "Chown - potential ownership changes"),
                                                ("cryptominer", "Cryptocurrency miner detected"),
                                                ("xmrig", "XMRig cryptocurrency miner"),
                                                ("minerd", "Mining daemon detected"),
                                                ("kdevtmpfsi", "Known cryptominer process"),
                                                ("kinsing", "Known malware process"),
                                                ("/tmp/", "Process running from /tmp - potential malware"),
                                            ];

                                            for (pattern, description) in suspicious_processes {
                                                if proc_list.to_lowercase().contains(&pattern.to_lowercase()) {
                                                    findings.push(K8sFinding {
                                                        resource_type: "Pod".to_string(),
                                                        resource_name: format!("{}/{}", pod_name, container_name),
                                                        namespace: namespace.to_string(),
                                                        finding_type: "Suspicious Process".to_string(),
                                                        severity: "high".to_string(),
                                                        description: format!(
                                                            "Container '{}' has suspicious process: {}",
                                                            container_name, description
                                                        ),
                                                        remediation: "Investigate the process immediately. Check if it's expected behavior or a security incident.".to_string(),
                                                    });
                                                }
                                            }
                                        }
                                    }

                                    // Check network connections (if netstat/ss available)
                                    let net_output = self.kubectl_cmd()
                                        .args(["exec", "-n", namespace, pod_name, "-c", container_name, "--", "sh", "-c", "netstat -tulpn 2>/dev/null || ss -tulpn 2>/dev/null"])
                                        .output();

                                    if let Ok(output) = net_output {
                                        if output.status.success() {
                                            let net_list = String::from_utf8_lossy(&output.stdout);

                                            // Check for suspicious network activity
                                            let suspicious_ports = [
                                                ("4444", "Metasploit default port"),
                                                ("5555", "Common backdoor port"),
                                                ("6666", "Common backdoor port"),
                                                ("6667", "IRC (potential C2)"),
                                                ("31337", "Elite/Backdoor port"),
                                                ("1337", "Elite port"),
                                                ("3389", "RDP (unusual in container)"),
                                                ("22", "SSH (may indicate unauthorized access)"),
                                            ];

                                            for (port, description) in suspicious_ports {
                                                if net_list.contains(&format!(":{}", port)) {
                                                    findings.push(K8sFinding {
                                                        resource_type: "Pod".to_string(),
                                                        resource_name: format!("{}/{}", pod_name, container_name),
                                                        namespace: namespace.to_string(),
                                                        finding_type: "Suspicious Network Connection".to_string(),
                                                        severity: "high".to_string(),
                                                        description: format!(
                                                            "Container '{}' has connection on suspicious port {}: {}",
                                                            container_name, port, description
                                                        ),
                                                        remediation: "Investigate the network connection. Verify if it's expected application behavior.".to_string(),
                                                    });
                                                }
                                            }

                                            // Check for many ESTABLISHED connections (potential DoS or botnet)
                                            let established_count = net_list.matches("ESTABLISHED").count()
                                                + net_list.matches("ESTAB").count();
                                            if established_count > 100 {
                                                findings.push(K8sFinding {
                                                    resource_type: "Pod".to_string(),
                                                    resource_name: format!("{}/{}", pod_name, container_name),
                                                    namespace: namespace.to_string(),
                                                    finding_type: "High Connection Count".to_string(),
                                                    severity: "medium".to_string(),
                                                    description: format!(
                                                        "Container '{}' has {} established connections. May indicate DoS attack or botnet activity.",
                                                        container_name, established_count
                                                    ),
                                                    remediation: "Review application connection patterns. Implement connection limits if needed.".to_string(),
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
        }

        // Check for Falco or similar runtime security tools
        let falco_check = self.kubectl_cmd()
            .args(["get", "pods", "-n", "falco", "-l", "app=falco", "-o", "json"])
            .output();

        if let Ok(output) = falco_check {
            if !output.status.success() || String::from_utf8_lossy(&output.stdout).contains("\"items\": []") {
                // Also check for Falco in other common namespaces
                let falco_ns_check = self.kubectl_cmd()
                    .args(["get", "pods", "--all-namespaces", "-l", "app.kubernetes.io/name=falco", "-o", "json"])
                    .output();

                let has_falco = falco_ns_check.map(|o| {
                    o.status.success() && !String::from_utf8_lossy(&o.stdout).contains("\"items\": []")
                }).unwrap_or(false);

                if !has_falco {
                    findings.push(K8sFinding {
                        resource_type: "Cluster".to_string(),
                        resource_name: "runtime-security".to_string(),
                        namespace: "N/A".to_string(),
                        finding_type: "No Runtime Security Tool".to_string(),
                        severity: "medium".to_string(),
                        description: "No runtime security tool (Falco) detected in the cluster. Container behavior is not being monitored.".to_string(),
                        remediation: "Install Falco or similar runtime security tool to detect anomalous container behavior.".to_string(),
                    });
                }
            }
        }

        Ok(findings)
    }

    /// Monitor file system changes - detect unauthorized modifications
    pub async fn monitor_filesystem(&self) -> Result<Vec<K8sFinding>> {
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

                        // Skip system namespaces
                        if namespace == "kube-system" || namespace == "kube-public" || namespace == "kube-node-lease" {
                            continue;
                        }

                        if let Some(spec) = pod.get("spec") {
                            if let Some(containers) = spec.get("containers").and_then(|c| c.as_array()) {
                                for container in containers {
                                    let container_name = container.get("name")
                                        .and_then(|n| n.as_str())
                                        .unwrap_or("unknown");

                                    // Check for files in suspicious locations
                                    let suspicious_dirs = [
                                        "/tmp",
                                        "/var/tmp",
                                        "/dev/shm",
                                    ];

                                    for dir in suspicious_dirs {
                                        let ls_output = self.kubectl_cmd()
                                            .args(["exec", "-n", namespace, pod_name, "-c", container_name, "--", "ls", "-la", dir])
                                            .output();

                                        if let Ok(output) = ls_output {
                                            if output.status.success() {
                                                let file_list = String::from_utf8_lossy(&output.stdout);
                                                let lines: Vec<&str> = file_list.lines().collect();

                                                // Check for executable files in temp directories
                                                let executable_count = lines.iter()
                                                    .filter(|line| line.starts_with("-rwx") || line.contains("x "))
                                                    .count();

                                                if executable_count > 5 {
                                                    findings.push(K8sFinding {
                                                        resource_type: "Pod".to_string(),
                                                        resource_name: format!("{}/{}", pod_name, container_name),
                                                        namespace: namespace.to_string(),
                                                        finding_type: "Executables in Temp Directory".to_string(),
                                                        severity: "medium".to_string(),
                                                        description: format!(
                                                            "Container '{}' has {} executable files in {}. This may indicate malware.",
                                                            container_name, executable_count, dir
                                                        ),
                                                        remediation: "Investigate executable files in temp directories. Consider using readOnlyRootFilesystem.".to_string(),
                                                    });
                                                }

                                                // Check for shell scripts
                                                let script_patterns = [".sh", ".py", ".pl", ".rb"];
                                                for pattern in script_patterns {
                                                    if lines.iter().any(|l| l.contains(pattern)) {
                                                        findings.push(K8sFinding {
                                                            resource_type: "Pod".to_string(),
                                                            resource_name: format!("{}/{}", pod_name, container_name),
                                                            namespace: namespace.to_string(),
                                                            finding_type: "Scripts in Temp Directory".to_string(),
                                                            severity: "low".to_string(),
                                                            description: format!(
                                                                "Container '{}' has script files ({}) in {}.",
                                                                container_name, pattern, dir
                                                            ),
                                                            remediation: "Review scripts in temp directories. They may be legitimate or malicious.".to_string(),
                                                        });
                                                        break;
                                                    }
                                                }
                                            }
                                        }
                                    }

                                    // Check for modifications to /etc/passwd, /etc/shadow, etc.
                                    let etc_check = self.kubectl_cmd()
                                        .args(["exec", "-n", namespace, pod_name, "-c", container_name, "--", "stat", "-c", "%Y", "/etc/passwd"])
                                        .output();

                                    // Note: This is a simplified check - in production you'd compare against baseline
                                    if let Ok(output) = etc_check {
                                        if output.status.success() {
                                            // Check if container has writable /etc (which it shouldn't)
                                            let touch_check = self.kubectl_cmd()
                                                .args(["exec", "-n", namespace, pod_name, "-c", container_name, "--", "sh", "-c", "touch /etc/.writetest 2>/dev/null && rm /etc/.writetest && echo 'writable'"])
                                                .output();

                                            if let Ok(touch_output) = touch_check {
                                                if String::from_utf8_lossy(&touch_output.stdout).contains("writable") {
                                                    findings.push(K8sFinding {
                                                        resource_type: "Pod".to_string(),
                                                        resource_name: format!("{}/{}", pod_name, container_name),
                                                        namespace: namespace.to_string(),
                                                        finding_type: "Writable /etc Directory".to_string(),
                                                        severity: "medium".to_string(),
                                                        description: format!(
                                                            "Container '{}' has writable /etc directory. System configuration can be modified.",
                                                            container_name
                                                        ),
                                                        remediation: "Use readOnlyRootFilesystem: true in securityContext to prevent filesystem modifications.".to_string(),
                                                    });
                                                }
                                            }
                                        }
                                    }

                                    // Check for SUID/SGID binaries
                                    let suid_check = self.kubectl_cmd()
                                        .args(["exec", "-n", namespace, pod_name, "-c", container_name, "--", "find", "/", "-perm", "-4000", "-type", "f"])
                                        .output();

                                    if let Ok(output) = suid_check {
                                        if output.status.success() {
                                            let suid_files = String::from_utf8_lossy(&output.stdout);
                                            let suid_list: Vec<&str> = suid_files.lines().filter(|l| !l.is_empty()).collect();

                                            // Flag unexpected SUID binaries
                                            let expected_suid = [
                                                "/bin/su", "/usr/bin/su",
                                                "/bin/ping", "/usr/bin/ping",
                                                "/bin/mount", "/usr/bin/mount",
                                                "/bin/umount", "/usr/bin/umount",
                                            ];

                                            let unexpected_suid: Vec<&&str> = suid_list.iter()
                                                .filter(|f| !expected_suid.contains(*f))
                                                .collect();

                                            if !unexpected_suid.is_empty() {
                                                findings.push(K8sFinding {
                                                    resource_type: "Pod".to_string(),
                                                    resource_name: format!("{}/{}", pod_name, container_name),
                                                    namespace: namespace.to_string(),
                                                    finding_type: "Unexpected SUID Binaries".to_string(),
                                                    severity: "high".to_string(),
                                                    description: format!(
                                                        "Container '{}' has {} unexpected SUID binaries: {:?}. These could be used for privilege escalation.",
                                                        container_name, unexpected_suid.len(), unexpected_suid.iter().take(5).collect::<Vec<_>>()
                                                    ),
                                                    remediation: "Remove SUID bit from unnecessary binaries or use distroless/minimal images.".to_string(),
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
        }

        Ok(findings)
    }
}

impl Default for RuntimeMonitor {
    fn default() -> Self {
        Self::new()
    }
}
