//! Kubernetes compliance scanning (CIS, NSA/CISA)

use super::*;
use anyhow::Result;
use std::process::Command;

pub struct K8sComplianceScanner {
    /// Path to kubeconfig file
    kubeconfig_path: Option<String>,
    /// Kubernetes context to use
    context: Option<String>,
}

impl K8sComplianceScanner {
    pub fn new() -> Self {
        Self {
            kubeconfig_path: None,
            context: None,
        }
    }

    pub fn with_config(kubeconfig_path: Option<String>, context: Option<String>) -> Self {
        Self {
            kubeconfig_path,
            context,
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

    /// Scan all compliance aspects
    pub async fn scan_all(&self) -> Result<Vec<K8sFinding>> {
        let mut findings = Vec::new();
        findings.extend(self.scan_cis_benchmark().await?);
        findings.extend(self.scan_nsa_cisa_hardening().await?);
        Ok(findings)
    }

    /// Run CIS Kubernetes Benchmark checks
    /// Based on CIS Kubernetes Benchmark v1.8.0
    pub async fn scan_cis_benchmark(&self) -> Result<Vec<K8sFinding>> {
        let mut findings = Vec::new();

        // CIS 1.1 - Control Plane Configuration
        // Check API server configuration
        let api_server_output = self.kubectl_cmd()
            .args(["get", "pod", "-n", "kube-system", "-l", "component=kube-apiserver", "-o", "json"])
            .output()?;

        if api_server_output.status.success() {
            if let Ok(pod_list) = serde_json::from_slice::<serde_json::Value>(&api_server_output.stdout) {
                if let Some(items) = pod_list.get("items").and_then(|i| i.as_array()) {
                    for pod in items {
                        if let Some(containers) = pod.get("spec")
                            .and_then(|s| s.get("containers"))
                            .and_then(|c| c.as_array())
                        {
                            for container in containers {
                                if let Some(command) = container.get("command").and_then(|c| c.as_array()) {
                                    let cmd_str: String = command.iter()
                                        .filter_map(|c| c.as_str())
                                        .collect::<Vec<_>>()
                                        .join(" ");

                                    // CIS 1.2.1 - Ensure anonymous authentication is disabled
                                    if !cmd_str.contains("--anonymous-auth=false") {
                                        findings.push(K8sFinding {
                                            resource_type: "CIS-Benchmark".to_string(),
                                            resource_name: "1.2.1".to_string(),
                                            namespace: "kube-system".to_string(),
                                            finding_type: "CIS Control Failure".to_string(),
                                            severity: "high".to_string(),
                                            description: "CIS 1.2.1: Anonymous authentication should be disabled on the API server. Set --anonymous-auth=false.".to_string(),
                                            remediation: "Set --anonymous-auth=false on the API server.".to_string(),
                                        });
                                    }

                                    // CIS 1.2.2 - Ensure --token-auth-file is not set
                                    if cmd_str.contains("--token-auth-file") {
                                        findings.push(K8sFinding {
                                            resource_type: "CIS-Benchmark".to_string(),
                                            resource_name: "1.2.2".to_string(),
                                            namespace: "kube-system".to_string(),
                                            finding_type: "CIS Control Failure".to_string(),
                                            severity: "high".to_string(),
                                            description: "CIS 1.2.2: Token authentication file should not be used. It cannot be revoked.".to_string(),
                                            remediation: "Remove --token-auth-file from API server arguments. Use certificates or OIDC instead.".to_string(),
                                        });
                                    }

                                    // CIS 1.2.6 - Ensure --kubelet-certificate-authority is set
                                    if !cmd_str.contains("--kubelet-certificate-authority") {
                                        findings.push(K8sFinding {
                                            resource_type: "CIS-Benchmark".to_string(),
                                            resource_name: "1.2.6".to_string(),
                                            namespace: "kube-system".to_string(),
                                            finding_type: "CIS Control Warning".to_string(),
                                            severity: "medium".to_string(),
                                            description: "CIS 1.2.6: Kubelet certificate authority should be configured for API server to kubelet communication.".to_string(),
                                            remediation: "Set --kubelet-certificate-authority on the API server.".to_string(),
                                        });
                                    }

                                    // CIS 1.2.16 - Ensure admission control plugin PodSecurityPolicy is set (deprecated, check for Pod Security Admission)
                                    if !cmd_str.contains("PodSecurity") && !cmd_str.contains("PodSecurityPolicy") {
                                        findings.push(K8sFinding {
                                            resource_type: "CIS-Benchmark".to_string(),
                                            resource_name: "1.2.16".to_string(),
                                            namespace: "kube-system".to_string(),
                                            finding_type: "CIS Control Failure".to_string(),
                                            severity: "high".to_string(),
                                            description: "CIS 1.2.16: Pod Security admission controller should be enabled.".to_string(),
                                            remediation: "Enable Pod Security Admission (PSA) or legacy PodSecurityPolicy.".to_string(),
                                        });
                                    }

                                    // CIS 1.2.22 - Ensure --audit-log-path is set
                                    if !cmd_str.contains("--audit-log-path") {
                                        findings.push(K8sFinding {
                                            resource_type: "CIS-Benchmark".to_string(),
                                            resource_name: "1.2.22".to_string(),
                                            namespace: "kube-system".to_string(),
                                            finding_type: "CIS Control Failure".to_string(),
                                            severity: "medium".to_string(),
                                            description: "CIS 1.2.22: Audit logging should be enabled on the API server.".to_string(),
                                            remediation: "Set --audit-log-path to enable audit logging.".to_string(),
                                        });
                                    }

                                    // CIS 1.2.29 - Ensure encryption provider is configured
                                    if !cmd_str.contains("--encryption-provider-config") {
                                        findings.push(K8sFinding {
                                            resource_type: "CIS-Benchmark".to_string(),
                                            resource_name: "1.2.29".to_string(),
                                            namespace: "kube-system".to_string(),
                                            finding_type: "CIS Control Failure".to_string(),
                                            severity: "high".to_string(),
                                            description: "CIS 1.2.29: Encryption at rest should be configured for etcd data.".to_string(),
                                            remediation: "Configure --encryption-provider-config with an EncryptionConfiguration.".to_string(),
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // CIS 5.1 - RBAC and Service Accounts
        // CIS 5.1.1 - Ensure cluster-admin role is only used where required
        let crb_output = self.kubectl_cmd()
            .args(["get", "clusterrolebindings", "-o", "json"])
            .output()?;

        if crb_output.status.success() {
            if let Ok(crb_list) = serde_json::from_slice::<serde_json::Value>(&crb_output.stdout) {
                if let Some(items) = crb_list.get("items").and_then(|i| i.as_array()) {
                    let admin_bindings: Vec<&str> = items.iter()
                        .filter(|item| {
                            item.get("roleRef")
                                .and_then(|r| r.get("name"))
                                .and_then(|n| n.as_str())
                                .map(|n| n == "cluster-admin")
                                .unwrap_or(false)
                        })
                        .filter_map(|item| {
                            item.get("metadata")
                                .and_then(|m| m.get("name"))
                                .and_then(|n| n.as_str())
                        })
                        .collect();

                    if admin_bindings.len() > 3 {
                        findings.push(K8sFinding {
                            resource_type: "CIS-Benchmark".to_string(),
                            resource_name: "5.1.1".to_string(),
                            namespace: "cluster-wide".to_string(),
                            finding_type: "CIS Control Warning".to_string(),
                            severity: "medium".to_string(),
                            description: format!(
                                "CIS 5.1.1: Found {} cluster-admin bindings ({}). Minimize use of cluster-admin.",
                                admin_bindings.len(),
                                admin_bindings.join(", ")
                            ),
                            remediation: "Review and remove unnecessary cluster-admin bindings.".to_string(),
                        });
                    }
                }
            }
        }

        // CIS 5.1.6 - Ensure default service account is not used
        let pods_output = self.kubectl_cmd()
            .args(["get", "pods", "--all-namespaces", "-o", "json"])
            .output()?;

        if pods_output.status.success() {
            if let Ok(pod_list) = serde_json::from_slice::<serde_json::Value>(&pods_output.stdout) {
                if let Some(items) = pod_list.get("items").and_then(|i| i.as_array()) {
                    let mut default_sa_pods: Vec<String> = Vec::new();

                    for pod in items {
                        let namespace = pod.get("metadata")
                            .and_then(|m| m.get("namespace"))
                            .and_then(|n| n.as_str())
                            .unwrap_or("default");

                        // Skip system namespaces
                        if namespace == "kube-system" || namespace == "kube-public" || namespace == "kube-node-lease" {
                            continue;
                        }

                        let pod_name = pod.get("metadata")
                            .and_then(|m| m.get("name"))
                            .and_then(|n| n.as_str())
                            .unwrap_or("unknown");

                        let service_account = pod.get("spec")
                            .and_then(|s| s.get("serviceAccountName"))
                            .and_then(|sa| sa.as_str())
                            .unwrap_or("default");

                        if service_account == "default" {
                            default_sa_pods.push(format!("{}/{}", namespace, pod_name));
                        }
                    }

                    if !default_sa_pods.is_empty() && default_sa_pods.len() <= 20 {
                        findings.push(K8sFinding {
                            resource_type: "CIS-Benchmark".to_string(),
                            resource_name: "5.1.6".to_string(),
                            namespace: "multiple".to_string(),
                            finding_type: "CIS Control Failure".to_string(),
                            severity: "medium".to_string(),
                            description: format!(
                                "CIS 5.1.6: {} pods use the default service account: {}",
                                default_sa_pods.len(),
                                default_sa_pods.iter().take(5).cloned().collect::<Vec<_>>().join(", ")
                            ),
                            remediation: "Create dedicated service accounts for workloads and set serviceAccountName in pod specs.".to_string(),
                        });
                    }
                }
            }
        }

        // CIS 5.2 - Pod Security Standards
        // Check for pods violating restricted profile
        if pods_output.status.success() {
            if let Ok(pod_list) = serde_json::from_slice::<serde_json::Value>(&pods_output.stdout) {
                if let Some(items) = pod_list.get("items").and_then(|i| i.as_array()) {
                    let mut privileged_pods: Vec<String> = Vec::new();
                    let mut host_namespace_pods: Vec<String> = Vec::new();

                    for pod in items {
                        let namespace = pod.get("metadata")
                            .and_then(|m| m.get("namespace"))
                            .and_then(|n| n.as_str())
                            .unwrap_or("default");

                        if namespace == "kube-system" {
                            continue;
                        }

                        let pod_name = pod.get("metadata")
                            .and_then(|m| m.get("name"))
                            .and_then(|n| n.as_str())
                            .unwrap_or("unknown");

                        if let Some(spec) = pod.get("spec") {
                            // Check hostNetwork, hostPID, hostIPC
                            if spec.get("hostNetwork").and_then(|h| h.as_bool()).unwrap_or(false)
                                || spec.get("hostPID").and_then(|h| h.as_bool()).unwrap_or(false)
                                || spec.get("hostIPC").and_then(|h| h.as_bool()).unwrap_or(false)
                            {
                                host_namespace_pods.push(format!("{}/{}", namespace, pod_name));
                            }

                            // Check privileged containers
                            if let Some(containers) = spec.get("containers").and_then(|c| c.as_array()) {
                                for container in containers {
                                    if let Some(sec_ctx) = container.get("securityContext") {
                                        if sec_ctx.get("privileged").and_then(|p| p.as_bool()).unwrap_or(false) {
                                            privileged_pods.push(format!("{}/{}", namespace, pod_name));
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }

                    if !privileged_pods.is_empty() {
                        findings.push(K8sFinding {
                            resource_type: "CIS-Benchmark".to_string(),
                            resource_name: "5.2.1".to_string(),
                            namespace: "multiple".to_string(),
                            finding_type: "CIS Control Failure".to_string(),
                            severity: "critical".to_string(),
                            description: format!(
                                "CIS 5.2.1: {} pods have privileged containers: {}",
                                privileged_pods.len(),
                                privileged_pods.iter().take(5).cloned().collect::<Vec<_>>().join(", ")
                            ),
                            remediation: "Remove privileged: true from container security contexts.".to_string(),
                        });
                    }

                    if !host_namespace_pods.is_empty() {
                        findings.push(K8sFinding {
                            resource_type: "CIS-Benchmark".to_string(),
                            resource_name: "5.2.2-5.2.4".to_string(),
                            namespace: "multiple".to_string(),
                            finding_type: "CIS Control Failure".to_string(),
                            severity: "high".to_string(),
                            description: format!(
                                "CIS 5.2.2-4: {} pods use host namespaces: {}",
                                host_namespace_pods.len(),
                                host_namespace_pods.iter().take(5).cloned().collect::<Vec<_>>().join(", ")
                            ),
                            remediation: "Remove hostNetwork, hostPID, and hostIPC from pod specs.".to_string(),
                        });
                    }
                }
            }
        }

        // CIS 5.3 - Network Policies
        let np_output = self.kubectl_cmd()
            .args(["get", "networkpolicies", "--all-namespaces", "-o", "json"])
            .output()?;

        if np_output.status.success() {
            if let Ok(np_list) = serde_json::from_slice::<serde_json::Value>(&np_output.stdout) {
                let items = np_list.get("items").and_then(|i| i.as_array());
                if items.map(|i| i.is_empty()).unwrap_or(true) {
                    findings.push(K8sFinding {
                        resource_type: "CIS-Benchmark".to_string(),
                        resource_name: "5.3.2".to_string(),
                        namespace: "cluster-wide".to_string(),
                        finding_type: "CIS Control Failure".to_string(),
                        severity: "high".to_string(),
                        description: "CIS 5.3.2: No NetworkPolicies found. Network segmentation is not enforced.".to_string(),
                        remediation: "Create NetworkPolicies to segment pod network access.".to_string(),
                    });
                }
            }
        }

        Ok(findings)
    }

    /// Run NSA/CISA Kubernetes Hardening Guide checks
    /// Based on NSA/CISA Kubernetes Hardening Guide v1.2
    pub async fn scan_nsa_cisa_hardening(&self) -> Result<Vec<K8sFinding>> {
        let mut findings = Vec::new();

        // NSA/CISA - Pod Security
        // Check for non-root containers
        let pods_output = self.kubectl_cmd()
            .args(["get", "pods", "--all-namespaces", "-o", "json"])
            .output()?;

        if pods_output.status.success() {
            if let Ok(pod_list) = serde_json::from_slice::<serde_json::Value>(&pods_output.stdout) {
                if let Some(items) = pod_list.get("items").and_then(|i| i.as_array()) {
                    let mut root_containers: Vec<String> = Vec::new();
                    let mut no_resource_limits: Vec<String> = Vec::new();
                    let mut writable_fs: Vec<String> = Vec::new();

                    for pod in items {
                        let namespace = pod.get("metadata")
                            .and_then(|m| m.get("namespace"))
                            .and_then(|n| n.as_str())
                            .unwrap_or("default");

                        if namespace == "kube-system" || namespace == "kube-public" || namespace == "kube-node-lease" {
                            continue;
                        }

                        let pod_name = pod.get("metadata")
                            .and_then(|m| m.get("name"))
                            .and_then(|n| n.as_str())
                            .unwrap_or("unknown");

                        if let Some(spec) = pod.get("spec") {
                            if let Some(containers) = spec.get("containers").and_then(|c| c.as_array()) {
                                for container in containers {
                                    let container_name = container.get("name").and_then(|n| n.as_str()).unwrap_or("unknown");
                                    let full_name = format!("{}/{}/{}", namespace, pod_name, container_name);

                                    // Check runAsNonRoot
                                    let run_as_non_root = container.get("securityContext")
                                        .and_then(|sc| sc.get("runAsNonRoot"))
                                        .and_then(|r| r.as_bool())
                                        .unwrap_or(false);

                                    let run_as_user = container.get("securityContext")
                                        .and_then(|sc| sc.get("runAsUser"))
                                        .and_then(|u| u.as_i64());

                                    if !run_as_non_root && run_as_user.unwrap_or(0) == 0 {
                                        root_containers.push(full_name.clone());
                                    }

                                    // Check resource limits
                                    let has_limits = container.get("resources")
                                        .and_then(|r| r.get("limits"))
                                        .is_some();

                                    if !has_limits {
                                        no_resource_limits.push(full_name.clone());
                                    }

                                    // Check readOnlyRootFilesystem
                                    let read_only_fs = container.get("securityContext")
                                        .and_then(|sc| sc.get("readOnlyRootFilesystem"))
                                        .and_then(|r| r.as_bool())
                                        .unwrap_or(false);

                                    if !read_only_fs {
                                        writable_fs.push(full_name.clone());
                                    }
                                }
                            }
                        }
                    }

                    if !root_containers.is_empty() && root_containers.len() <= 20 {
                        findings.push(K8sFinding {
                            resource_type: "NSA-CISA".to_string(),
                            resource_name: "Pod-Security".to_string(),
                            namespace: "multiple".to_string(),
                            finding_type: "NSA/CISA Hardening".to_string(),
                            severity: "medium".to_string(),
                            description: format!(
                                "NSA/CISA: {} containers may run as root: {}",
                                root_containers.len(),
                                root_containers.iter().take(5).cloned().collect::<Vec<_>>().join(", ")
                            ),
                            remediation: "Set securityContext.runAsNonRoot: true and specify a non-zero runAsUser.".to_string(),
                        });
                    }

                    if !no_resource_limits.is_empty() && no_resource_limits.len() <= 20 {
                        findings.push(K8sFinding {
                            resource_type: "NSA-CISA".to_string(),
                            resource_name: "Resource-Limits".to_string(),
                            namespace: "multiple".to_string(),
                            finding_type: "NSA/CISA Hardening".to_string(),
                            severity: "low".to_string(),
                            description: format!(
                                "NSA/CISA: {} containers have no resource limits: {}",
                                no_resource_limits.len(),
                                no_resource_limits.iter().take(5).cloned().collect::<Vec<_>>().join(", ")
                            ),
                            remediation: "Set resources.limits for CPU and memory on all containers.".to_string(),
                        });
                    }

                    if !writable_fs.is_empty() && writable_fs.len() <= 20 {
                        findings.push(K8sFinding {
                            resource_type: "NSA-CISA".to_string(),
                            resource_name: "Filesystem-Security".to_string(),
                            namespace: "multiple".to_string(),
                            finding_type: "NSA/CISA Hardening".to_string(),
                            severity: "low".to_string(),
                            description: format!(
                                "NSA/CISA: {} containers have writable root filesystem: {}",
                                writable_fs.len(),
                                writable_fs.iter().take(5).cloned().collect::<Vec<_>>().join(", ")
                            ),
                            remediation: "Set securityContext.readOnlyRootFilesystem: true.".to_string(),
                        });
                    }
                }
            }
        }

        // NSA/CISA - Network Hardening
        // Check for network policies and mTLS
        let np_output = self.kubectl_cmd()
            .args(["get", "networkpolicies", "--all-namespaces", "-o", "json"])
            .output()?;

        if np_output.status.success() {
            if let Ok(np_list) = serde_json::from_slice::<serde_json::Value>(&np_output.stdout) {
                let items = np_list.get("items").and_then(|i| i.as_array());
                if items.map(|i| i.is_empty()).unwrap_or(true) {
                    findings.push(K8sFinding {
                        resource_type: "NSA-CISA".to_string(),
                        resource_name: "Network-Policies".to_string(),
                        namespace: "cluster-wide".to_string(),
                        finding_type: "NSA/CISA Hardening".to_string(),
                        severity: "high".to_string(),
                        description: "NSA/CISA: No NetworkPolicies defined. Implement network segmentation.".to_string(),
                        remediation: "Create default-deny NetworkPolicies and explicitly allow required traffic.".to_string(),
                    });
                }
            }
        }

        // NSA/CISA - Authentication and Authorization
        // Check for RBAC configuration
        let crb_output = self.kubectl_cmd()
            .args(["get", "clusterrolebindings", "-o", "json"])
            .output()?;

        if crb_output.status.success() {
            if let Ok(crb_list) = serde_json::from_slice::<serde_json::Value>(&crb_output.stdout) {
                if let Some(items) = crb_list.get("items").and_then(|i| i.as_array()) {
                    // Check for anonymous or unauthenticated bindings
                    for crb in items {
                        if let Some(subjects) = crb.get("subjects").and_then(|s| s.as_array()) {
                            for subject in subjects {
                                let name = subject.get("name").and_then(|n| n.as_str()).unwrap_or("");
                                if name == "system:anonymous" || name == "system:unauthenticated" {
                                    let crb_name = crb.get("metadata")
                                        .and_then(|m| m.get("name"))
                                        .and_then(|n| n.as_str())
                                        .unwrap_or("unknown");

                                    findings.push(K8sFinding {
                                        resource_type: "NSA-CISA".to_string(),
                                        resource_name: crb_name.to_string(),
                                        namespace: "cluster-wide".to_string(),
                                        finding_type: "NSA/CISA Hardening".to_string(),
                                        severity: "critical".to_string(),
                                        description: format!(
                                            "NSA/CISA: ClusterRoleBinding '{}' grants access to {}. Anonymous access should be disabled.",
                                            crb_name, name
                                        ),
                                        remediation: "Remove bindings to system:anonymous and system:unauthenticated.".to_string(),
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }

        // NSA/CISA - Audit Logging
        // Check if audit logging is enabled (via API server)
        let api_server_output = self.kubectl_cmd()
            .args(["get", "pod", "-n", "kube-system", "-l", "component=kube-apiserver", "-o", "json"])
            .output()?;

        if api_server_output.status.success() {
            if let Ok(pod_list) = serde_json::from_slice::<serde_json::Value>(&api_server_output.stdout) {
                if let Some(items) = pod_list.get("items").and_then(|i| i.as_array()) {
                    let mut audit_enabled = false;

                    for pod in items {
                        if let Some(containers) = pod.get("spec")
                            .and_then(|s| s.get("containers"))
                            .and_then(|c| c.as_array())
                        {
                            for container in containers {
                                if let Some(command) = container.get("command").and_then(|c| c.as_array()) {
                                    let cmd_str: String = command.iter()
                                        .filter_map(|c| c.as_str())
                                        .collect::<Vec<_>>()
                                        .join(" ");

                                    if cmd_str.contains("--audit-log-path") || cmd_str.contains("--audit-policy-file") {
                                        audit_enabled = true;
                                    }
                                }
                            }
                        }
                    }

                    if !audit_enabled {
                        findings.push(K8sFinding {
                            resource_type: "NSA-CISA".to_string(),
                            resource_name: "Audit-Logging".to_string(),
                            namespace: "kube-system".to_string(),
                            finding_type: "NSA/CISA Hardening".to_string(),
                            severity: "medium".to_string(),
                            description: "NSA/CISA: Audit logging is not configured on the API server.".to_string(),
                            remediation: "Enable audit logging with --audit-log-path and --audit-policy-file.".to_string(),
                        });
                    }
                }
            }
        }

        // NSA/CISA - Secrets Management
        // Check for secrets encryption
        let secrets_output = self.kubectl_cmd()
            .args(["get", "secrets", "--all-namespaces", "-o", "json"])
            .output()?;

        if secrets_output.status.success() {
            if let Ok(secret_list) = serde_json::from_slice::<serde_json::Value>(&secrets_output.stdout) {
                if let Some(items) = secret_list.get("items").and_then(|i| i.as_array()) {
                    let mut exposed_secrets: Vec<String> = Vec::new();

                    for secret in items {
                        let namespace = secret.get("metadata")
                            .and_then(|m| m.get("namespace"))
                            .and_then(|n| n.as_str())
                            .unwrap_or("default");

                        if namespace == "kube-system" {
                            continue;
                        }

                        let secret_name = secret.get("metadata")
                            .and_then(|m| m.get("name"))
                            .and_then(|n| n.as_str())
                            .unwrap_or("unknown");

                        let secret_type = secret.get("type")
                            .and_then(|t| t.as_str())
                            .unwrap_or("Opaque");

                        // Flag Opaque secrets with sensitive names
                        let name_lower = secret_name.to_lowercase();
                        if secret_type == "Opaque" && (name_lower.contains("password") || name_lower.contains("apikey") || name_lower.contains("token")) {
                            exposed_secrets.push(format!("{}/{}", namespace, secret_name));
                        }
                    }

                    if !exposed_secrets.is_empty() && exposed_secrets.len() <= 10 {
                        findings.push(K8sFinding {
                            resource_type: "NSA-CISA".to_string(),
                            resource_name: "Secrets-Management".to_string(),
                            namespace: "multiple".to_string(),
                            finding_type: "NSA/CISA Hardening".to_string(),
                            severity: "low".to_string(),
                            description: format!(
                                "NSA/CISA: {} sensitive secrets found without external secret management: {}",
                                exposed_secrets.len(),
                                exposed_secrets.join(", ")
                            ),
                            remediation: "Consider using external secret management (Vault, Sealed Secrets, External Secrets).".to_string(),
                        });
                    }
                }
            }
        }

        // NSA/CISA - Container Images
        // Check for latest tags
        if pods_output.status.success() {
            if let Ok(pod_list) = serde_json::from_slice::<serde_json::Value>(&pods_output.stdout) {
                if let Some(items) = pod_list.get("items").and_then(|i| i.as_array()) {
                    let mut latest_tag_images: Vec<String> = Vec::new();

                    for pod in items {
                        let namespace = pod.get("metadata")
                            .and_then(|m| m.get("namespace"))
                            .and_then(|n| n.as_str())
                            .unwrap_or("default");

                        if namespace == "kube-system" {
                            continue;
                        }

                        if let Some(spec) = pod.get("spec") {
                            if let Some(containers) = spec.get("containers").and_then(|c| c.as_array()) {
                                for container in containers {
                                    let image = container.get("image")
                                        .and_then(|i| i.as_str())
                                        .unwrap_or("unknown");

                                    if image.contains(":latest") || !image.contains(':') {
                                        latest_tag_images.push(image.to_string());
                                    }
                                }
                            }
                        }
                    }

                    // Deduplicate
                    latest_tag_images.sort();
                    latest_tag_images.dedup();

                    if !latest_tag_images.is_empty() && latest_tag_images.len() <= 10 {
                        findings.push(K8sFinding {
                            resource_type: "NSA-CISA".to_string(),
                            resource_name: "Image-Tags".to_string(),
                            namespace: "multiple".to_string(),
                            finding_type: "NSA/CISA Hardening".to_string(),
                            severity: "medium".to_string(),
                            description: format!(
                                "NSA/CISA: {} images use :latest or no tag: {}",
                                latest_tag_images.len(),
                                latest_tag_images.iter().take(5).cloned().collect::<Vec<_>>().join(", ")
                            ),
                            remediation: "Use specific version tags or SHA256 digests for container images.".to_string(),
                        });
                    }
                }
            }
        }

        Ok(findings)
    }
}

impl Default for K8sComplianceScanner {
    fn default() -> Self {
        Self::new()
    }
}
