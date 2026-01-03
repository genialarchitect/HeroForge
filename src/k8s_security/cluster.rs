//! Kubernetes cluster security scanning

use super::*;
use anyhow::Result;
use std::process::Command;

pub struct ClusterScanner {
    /// Path to kubeconfig file
    kubeconfig_path: Option<String>,
    /// Kubernetes context to use
    context: Option<String>,
}

impl ClusterScanner {
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

    /// Scan all cluster-level security aspects
    pub async fn scan_all(&self) -> Result<Vec<K8sFinding>> {
        let mut findings = Vec::new();
        findings.extend(self.scan_rbac().await?);
        findings.extend(self.scan_api_server().await?);
        findings.extend(self.scan_nodes().await?);
        findings.extend(self.scan_secrets().await?);
        Ok(findings)
    }

    /// Scan RBAC configuration
    pub async fn scan_rbac(&self) -> Result<Vec<K8sFinding>> {
        let mut findings = Vec::new();

        // Check for overly permissive ClusterRoleBindings (cluster-admin usage)
        let crb_output = self.kubectl_cmd()
            .args(["get", "clusterrolebindings", "-o", "json"])
            .output()?;

        if crb_output.status.success() {
            if let Ok(crb_list) = serde_json::from_slice::<serde_json::Value>(&crb_output.stdout) {
                if let Some(items) = crb_list.get("items").and_then(|i| i.as_array()) {
                    // Find cluster-admin bindings
                    let admin_bindings: Vec<&serde_json::Value> = items.iter()
                        .filter(|item| {
                            item.get("roleRef")
                                .and_then(|r| r.get("name"))
                                .and_then(|n| n.as_str())
                                .map(|n| n == "cluster-admin")
                                .unwrap_or(false)
                        })
                        .collect();

                    if admin_bindings.len() > 2 {
                        let binding_names: Vec<String> = admin_bindings.iter()
                            .filter_map(|b| b.get("metadata").and_then(|m| m.get("name")).and_then(|n| n.as_str()))
                            .map(|s| s.to_string())
                            .collect();

                        findings.push(K8sFinding {
                            resource_type: "ClusterRoleBinding".to_string(),
                            resource_name: "cluster-admin".to_string(),
                            namespace: "cluster-wide".to_string(),
                            finding_type: "Overly Permissive RBAC".to_string(),
                            severity: "high".to_string(),
                            description: format!(
                                "Found {} ClusterRoleBindings granting cluster-admin privileges: {}. \
                                The cluster-admin role provides unrestricted access to the entire cluster.",
                                admin_bindings.len(),
                                binding_names.join(", ")
                            ),
                            remediation: "Review and remove unnecessary cluster-admin bindings. \
                                Create more restrictive custom ClusterRoles with only required permissions. \
                                Follow principle of least privilege.".to_string(),
                        });
                    }

                    // Check for bindings to 'system:anonymous' or 'system:unauthenticated'
                    for item in items {
                        if let Some(subjects) = item.get("subjects").and_then(|s| s.as_array()) {
                            for subject in subjects {
                                let name = subject.get("name").and_then(|n| n.as_str()).unwrap_or("");
                                if name == "system:anonymous" || name == "system:unauthenticated" {
                                    let binding_name = item.get("metadata")
                                        .and_then(|m| m.get("name"))
                                        .and_then(|n| n.as_str())
                                        .unwrap_or("unknown");

                                    findings.push(K8sFinding {
                                        resource_type: "ClusterRoleBinding".to_string(),
                                        resource_name: binding_name.to_string(),
                                        namespace: "cluster-wide".to_string(),
                                        finding_type: "Anonymous/Unauthenticated Access".to_string(),
                                        severity: "critical".to_string(),
                                        description: format!(
                                            "ClusterRoleBinding '{}' grants permissions to '{}'. \
                                            This allows unauthenticated access to cluster resources.",
                                            binding_name, name
                                        ),
                                        remediation: "Remove bindings to system:anonymous and system:unauthenticated \
                                            unless absolutely required. Require authentication for all API access.".to_string(),
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }

        // Check for Roles/ClusterRoles with wildcard permissions
        let cr_output = self.kubectl_cmd()
            .args(["get", "clusterroles", "-o", "json"])
            .output()?;

        if cr_output.status.success() {
            if let Ok(cr_list) = serde_json::from_slice::<serde_json::Value>(&cr_output.stdout) {
                if let Some(items) = cr_list.get("items").and_then(|i| i.as_array()) {
                    for item in items {
                        let role_name = item.get("metadata")
                            .and_then(|m| m.get("name"))
                            .and_then(|n| n.as_str())
                            .unwrap_or("unknown");

                        // Skip system roles
                        if role_name.starts_with("system:") {
                            continue;
                        }

                        if let Some(rules) = item.get("rules").and_then(|r| r.as_array()) {
                            for rule in rules {
                                let verbs = rule.get("verbs").and_then(|v| v.as_array());
                                let resources = rule.get("resources").and_then(|r| r.as_array());
                                let api_groups = rule.get("apiGroups").and_then(|a| a.as_array());

                                let has_wildcard_verb = verbs.map(|v| v.iter().any(|x| x.as_str() == Some("*"))).unwrap_or(false);
                                let has_wildcard_resource = resources.map(|r| r.iter().any(|x| x.as_str() == Some("*"))).unwrap_or(false);
                                let has_wildcard_apigroup = api_groups.map(|a| a.iter().any(|x| x.as_str() == Some("*"))).unwrap_or(false);

                                if has_wildcard_verb && has_wildcard_resource {
                                    findings.push(K8sFinding {
                                        resource_type: "ClusterRole".to_string(),
                                        resource_name: role_name.to_string(),
                                        namespace: "cluster-wide".to_string(),
                                        finding_type: "Wildcard Permissions".to_string(),
                                        severity: "high".to_string(),
                                        description: format!(
                                            "ClusterRole '{}' has wildcard verbs and resources (verbs: ['*'], resources: ['*']). \
                                            This grants extremely broad permissions.",
                                            role_name
                                        ),
                                        remediation: "Replace wildcard permissions with explicit verb and resource lists. \
                                            Define minimum required permissions for each role.".to_string(),
                                    });
                                } else if has_wildcard_apigroup && has_wildcard_resource {
                                    findings.push(K8sFinding {
                                        resource_type: "ClusterRole".to_string(),
                                        resource_name: role_name.to_string(),
                                        namespace: "cluster-wide".to_string(),
                                        finding_type: "Wildcard Permissions".to_string(),
                                        severity: "medium".to_string(),
                                        description: format!(
                                            "ClusterRole '{}' has wildcard apiGroups and resources. \
                                            Consider narrowing the scope.",
                                            role_name
                                        ),
                                        remediation: "Specify explicit apiGroups and resources instead of wildcards.".to_string(),
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(findings)
    }

    /// Scan API server configuration
    pub async fn scan_api_server(&self) -> Result<Vec<K8sFinding>> {
        let mut findings = Vec::new();

        // Check API server pod configuration in kube-system
        let api_pod_output = self.kubectl_cmd()
            .args(["get", "pod", "-n", "kube-system", "-l", "component=kube-apiserver", "-o", "json"])
            .output()?;

        if api_pod_output.status.success() {
            if let Ok(pod_list) = serde_json::from_slice::<serde_json::Value>(&api_pod_output.stdout) {
                if let Some(items) = pod_list.get("items").and_then(|i| i.as_array()) {
                    for pod in items {
                        let pod_name = pod.get("metadata")
                            .and_then(|m| m.get("name"))
                            .and_then(|n| n.as_str())
                            .unwrap_or("kube-apiserver");

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

                                    // Check for anonymous auth enabled
                                    if cmd_str.contains("--anonymous-auth=true") {
                                        findings.push(K8sFinding {
                                            resource_type: "Pod".to_string(),
                                            resource_name: pod_name.to_string(),
                                            namespace: "kube-system".to_string(),
                                            finding_type: "Anonymous Authentication Enabled".to_string(),
                                            severity: "critical".to_string(),
                                            description: "The API server allows anonymous authentication. \
                                                Unauthenticated requests can access the API.".to_string(),
                                            remediation: "Set --anonymous-auth=false on the API server \
                                                unless specifically required for health checks.".to_string(),
                                        });
                                    }

                                    // Check for missing audit log configuration
                                    if !cmd_str.contains("--audit-log-path") && !cmd_str.contains("--audit-policy-file") {
                                        findings.push(K8sFinding {
                                            resource_type: "Pod".to_string(),
                                            resource_name: pod_name.to_string(),
                                            namespace: "kube-system".to_string(),
                                            finding_type: "Audit Logging Not Configured".to_string(),
                                            severity: "medium".to_string(),
                                            description: "The API server does not have audit logging configured. \
                                                Security events are not being recorded.".to_string(),
                                            remediation: "Configure audit logging with --audit-log-path and \
                                                --audit-policy-file. Define an appropriate audit policy.".to_string(),
                                        });
                                    }

                                    // Check for insecure port enabled
                                    if cmd_str.contains("--insecure-port") && !cmd_str.contains("--insecure-port=0") {
                                        findings.push(K8sFinding {
                                            resource_type: "Pod".to_string(),
                                            resource_name: pod_name.to_string(),
                                            namespace: "kube-system".to_string(),
                                            finding_type: "Insecure Port Enabled".to_string(),
                                            severity: "critical".to_string(),
                                            description: "The API server has an insecure (non-TLS) port enabled. \
                                                This allows unencrypted access to the API.".to_string(),
                                            remediation: "Set --insecure-port=0 to disable the insecure port. \
                                                All API access should use TLS.".to_string(),
                                        });
                                    }

                                    // Check for missing admission controllers
                                    let recommended_admission = [
                                        "PodSecurityPolicy", "NodeRestriction", "AlwaysPullImages",
                                        "ServiceAccount", "NamespaceLifecycle"
                                    ];
                                    if cmd_str.contains("--enable-admission-plugins") {
                                        for plugin in recommended_admission {
                                            if !cmd_str.contains(plugin) {
                                                findings.push(K8sFinding {
                                                    resource_type: "Pod".to_string(),
                                                    resource_name: pod_name.to_string(),
                                                    namespace: "kube-system".to_string(),
                                                    finding_type: "Missing Admission Controller".to_string(),
                                                    severity: "low".to_string(),
                                                    description: format!(
                                                        "Recommended admission controller '{}' is not enabled.",
                                                        plugin
                                                    ),
                                                    remediation: format!(
                                                        "Consider enabling the {} admission controller for enhanced security.",
                                                        plugin
                                                    ),
                                                });
                                            }
                                        }
                                    }

                                    // Check for profiling enabled
                                    if !cmd_str.contains("--profiling=false") {
                                        findings.push(K8sFinding {
                                            resource_type: "Pod".to_string(),
                                            resource_name: pod_name.to_string(),
                                            namespace: "kube-system".to_string(),
                                            finding_type: "Profiling Enabled".to_string(),
                                            severity: "low".to_string(),
                                            description: "API server profiling may be enabled, which can expose sensitive performance data.".to_string(),
                                            remediation: "Set --profiling=false unless profiling data is actively needed.".to_string(),
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Check for ValidatingWebhookConfigurations (admission controllers)
        let vwc_output = self.kubectl_cmd()
            .args(["get", "validatingwebhookconfigurations", "-o", "json"])
            .output()?;

        if vwc_output.status.success() {
            if let Ok(vwc_list) = serde_json::from_slice::<serde_json::Value>(&vwc_output.stdout) {
                let items = vwc_list.get("items").and_then(|i| i.as_array());
                if items.map(|i| i.is_empty()).unwrap_or(true) {
                    findings.push(K8sFinding {
                        resource_type: "ValidatingWebhookConfiguration".to_string(),
                        resource_name: "N/A".to_string(),
                        namespace: "cluster-wide".to_string(),
                        finding_type: "No Validating Webhooks".to_string(),
                        severity: "low".to_string(),
                        description: "No ValidatingWebhookConfigurations found. Custom admission validation is not configured.".to_string(),
                        remediation: "Consider implementing validating admission webhooks for additional security controls.".to_string(),
                    });
                }
            }
        }

        Ok(findings)
    }

    /// Scan node security
    pub async fn scan_nodes(&self) -> Result<Vec<K8sFinding>> {
        let mut findings = Vec::new();

        // Get node information
        let nodes_output = self.kubectl_cmd()
            .args(["get", "nodes", "-o", "json"])
            .output()?;

        if nodes_output.status.success() {
            if let Ok(node_list) = serde_json::from_slice::<serde_json::Value>(&nodes_output.stdout) {
                if let Some(items) = node_list.get("items").and_then(|i| i.as_array()) {
                    for node in items {
                        let node_name = node.get("metadata")
                            .and_then(|m| m.get("name"))
                            .and_then(|n| n.as_str())
                            .unwrap_or("unknown");

                        // Check node conditions
                        if let Some(conditions) = node.get("status")
                            .and_then(|s| s.get("conditions"))
                            .and_then(|c| c.as_array())
                        {
                            for condition in conditions {
                                let cond_type = condition.get("type").and_then(|t| t.as_str()).unwrap_or("");
                                let status = condition.get("status").and_then(|s| s.as_str()).unwrap_or("");

                                if cond_type == "Ready" && status != "True" {
                                    findings.push(K8sFinding {
                                        resource_type: "Node".to_string(),
                                        resource_name: node_name.to_string(),
                                        namespace: "N/A".to_string(),
                                        finding_type: "Node Not Ready".to_string(),
                                        severity: "high".to_string(),
                                        description: format!("Node '{}' is not in Ready state. This may indicate issues with kubelet or node health.", node_name),
                                        remediation: "Investigate node health, check kubelet logs, and ensure the node has sufficient resources.".to_string(),
                                    });
                                }

                                if cond_type == "DiskPressure" && status == "True" {
                                    findings.push(K8sFinding {
                                        resource_type: "Node".to_string(),
                                        resource_name: node_name.to_string(),
                                        namespace: "N/A".to_string(),
                                        finding_type: "Node Disk Pressure".to_string(),
                                        severity: "medium".to_string(),
                                        description: format!("Node '{}' has disk pressure. Low disk space can cause pod evictions.", node_name),
                                        remediation: "Free up disk space or expand storage on the node.".to_string(),
                                    });
                                }

                                if cond_type == "MemoryPressure" && status == "True" {
                                    findings.push(K8sFinding {
                                        resource_type: "Node".to_string(),
                                        resource_name: node_name.to_string(),
                                        namespace: "N/A".to_string(),
                                        finding_type: "Node Memory Pressure".to_string(),
                                        severity: "medium".to_string(),
                                        description: format!("Node '{}' has memory pressure. This can cause OOM kills and pod evictions.", node_name),
                                        remediation: "Reduce workload on the node or add more memory.".to_string(),
                                    });
                                }
                            }
                        }

                        // Check kubelet version
                        if let Some(node_info) = node.get("status").and_then(|s| s.get("nodeInfo")) {
                            let kubelet_version = node_info.get("kubeletVersion")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown");

                            // Check for outdated Kubernetes versions
                            if kubelet_version.starts_with("v1.24") || kubelet_version.starts_with("v1.25") || kubelet_version.starts_with("v1.26") {
                                findings.push(K8sFinding {
                                    resource_type: "Node".to_string(),
                                    resource_name: node_name.to_string(),
                                    namespace: "N/A".to_string(),
                                    finding_type: "Outdated Kubelet Version".to_string(),
                                    severity: "medium".to_string(),
                                    description: format!(
                                        "Node '{}' is running kubelet {}. This version may be out of support.",
                                        node_name, kubelet_version
                                    ),
                                    remediation: "Upgrade to a supported Kubernetes version (1.28+).".to_string(),
                                });
                            }

                            // Check container runtime
                            let container_runtime = node_info.get("containerRuntimeVersion")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown");

                            if container_runtime.contains("docker://") {
                                let version_parts: Vec<&str> = container_runtime.split("://").collect();
                                if version_parts.len() > 1 {
                                    let version = version_parts[1];
                                    // Docker versions before 20.10 have known security issues
                                    if version.starts_with("19.") || version.starts_with("18.") {
                                        findings.push(K8sFinding {
                                            resource_type: "Node".to_string(),
                                            resource_name: node_name.to_string(),
                                            namespace: "N/A".to_string(),
                                            finding_type: "Outdated Container Runtime".to_string(),
                                            severity: "high".to_string(),
                                            description: format!(
                                                "Node '{}' is running Docker {}. Older Docker versions have known security vulnerabilities.",
                                                node_name, container_runtime
                                            ),
                                            remediation: "Upgrade Docker to version 20.10 or later, or migrate to containerd.".to_string(),
                                        });
                                    }
                                }
                            }
                        }

                        // Check node labels for potential security issues
                        if let Some(labels) = node.get("metadata").and_then(|m| m.get("labels")).and_then(|l| l.as_object()) {
                            // Check if node is a master/control-plane running workloads
                            let is_control_plane = labels.contains_key("node-role.kubernetes.io/master")
                                || labels.contains_key("node-role.kubernetes.io/control-plane");

                            if is_control_plane {
                                // Check taints to see if workloads can be scheduled
                                let has_noschedule_taint = node.get("spec")
                                    .and_then(|s| s.get("taints"))
                                    .and_then(|t| t.as_array())
                                    .map(|taints| {
                                        taints.iter().any(|t| {
                                            t.get("effect").and_then(|e| e.as_str()) == Some("NoSchedule")
                                        })
                                    })
                                    .unwrap_or(false);

                                if !has_noschedule_taint {
                                    findings.push(K8sFinding {
                                        resource_type: "Node".to_string(),
                                        resource_name: node_name.to_string(),
                                        namespace: "N/A".to_string(),
                                        finding_type: "Control Plane Accepts Workloads".to_string(),
                                        severity: "medium".to_string(),
                                        description: format!(
                                            "Control plane node '{}' does not have a NoSchedule taint. User workloads can be scheduled on control plane.",
                                            node_name
                                        ),
                                        remediation: "Add a NoSchedule taint to control plane nodes to prevent user workloads from running on them.".to_string(),
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }

        // Check kubelet configuration via configmaps
        let kubelet_cm_output = self.kubectl_cmd()
            .args(["get", "configmap", "-n", "kube-system", "kubelet-config", "-o", "json"])
            .output()?;

        if kubelet_cm_output.status.success() {
            if let Ok(cm) = serde_json::from_slice::<serde_json::Value>(&kubelet_cm_output.stdout) {
                if let Some(data) = cm.get("data").and_then(|d| d.get("kubelet")).and_then(|k| k.as_str()) {
                    // Check for read-only port
                    if data.contains("readOnlyPort: 10255") || (!data.contains("readOnlyPort: 0") && !data.contains("readOnlyPort: \"0\"")) {
                        findings.push(K8sFinding {
                            resource_type: "ConfigMap".to_string(),
                            resource_name: "kubelet-config".to_string(),
                            namespace: "kube-system".to_string(),
                            finding_type: "Kubelet Read-Only Port Enabled".to_string(),
                            severity: "medium".to_string(),
                            description: "The kubelet read-only port (10255) may be enabled. This exposes pod and node information without authentication.".to_string(),
                            remediation: "Set readOnlyPort: 0 in the kubelet configuration to disable the read-only port.".to_string(),
                        });
                    }

                    // Check for anonymous auth
                    if data.contains("anonymous:") && data.contains("enabled: true") {
                        findings.push(K8sFinding {
                            resource_type: "ConfigMap".to_string(),
                            resource_name: "kubelet-config".to_string(),
                            namespace: "kube-system".to_string(),
                            finding_type: "Kubelet Anonymous Auth Enabled".to_string(),
                            severity: "high".to_string(),
                            description: "Kubelet anonymous authentication is enabled. Unauthenticated requests can access kubelet API.".to_string(),
                            remediation: "Set authentication.anonymous.enabled: false in the kubelet configuration.".to_string(),
                        });
                    }
                }
            }
        }

        Ok(findings)
    }

    /// Scan secrets management
    pub async fn scan_secrets(&self) -> Result<Vec<K8sFinding>> {
        let mut findings = Vec::new();

        // Check for encryption at rest configuration
        // This is typically checked via the API server configuration
        // We can also check for secrets that might be misconfigured

        // Get all secrets (checking for potential security issues)
        let secrets_output = self.kubectl_cmd()
            .args(["get", "secrets", "--all-namespaces", "-o", "json"])
            .output()?;

        if secrets_output.status.success() {
            if let Ok(secret_list) = serde_json::from_slice::<serde_json::Value>(&secrets_output.stdout) {
                if let Some(items) = secret_list.get("items").and_then(|i| i.as_array()) {
                    let mut secrets_by_namespace: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();

                    for secret in items {
                        let namespace = secret.get("metadata")
                            .and_then(|m| m.get("namespace"))
                            .and_then(|n| n.as_str())
                            .unwrap_or("default");
                        let secret_name = secret.get("metadata")
                            .and_then(|m| m.get("name"))
                            .and_then(|n| n.as_str())
                            .unwrap_or("unknown");
                        let secret_type = secret.get("type")
                            .and_then(|t| t.as_str())
                            .unwrap_or("Opaque");

                        secrets_by_namespace.entry(namespace.to_string())
                            .or_default()
                            .push(secret_name.to_string());

                        // Check for secrets with sensitive names that might be misconfigured
                        let sensitive_patterns = ["password", "key", "token", "credential", "secret", "apikey"];
                        let name_lower = secret_name.to_lowercase();

                        // Check for Opaque secrets that don't use kubernetes.io/basic-auth or similar types
                        if secret_type == "Opaque" && sensitive_patterns.iter().any(|p| name_lower.contains(p)) {
                            // Check if the secret has labels indicating it's managed
                            let has_management_labels = secret.get("metadata")
                                .and_then(|m| m.get("labels"))
                                .and_then(|l| l.as_object())
                                .map(|labels| {
                                    labels.keys().any(|k| {
                                        k.contains("helm") || k.contains("argocd") || k.contains("sealed-secrets")
                                    })
                                })
                                .unwrap_or(false);

                            if !has_management_labels && !secret_name.starts_with("default-token") {
                                findings.push(K8sFinding {
                                    resource_type: "Secret".to_string(),
                                    resource_name: secret_name.to_string(),
                                    namespace: namespace.to_string(),
                                    finding_type: "Unmanaged Sensitive Secret".to_string(),
                                    severity: "low".to_string(),
                                    description: format!(
                                        "Secret '{}' in namespace '{}' appears to contain sensitive data but is not managed by a secrets management tool.",
                                        secret_name, namespace
                                    ),
                                    remediation: "Consider using a secrets management solution like Sealed Secrets, HashiCorp Vault, or External Secrets Operator.".to_string(),
                                });
                            }
                        }

                        // Check for service account tokens that shouldn't exist (Kubernetes 1.24+ doesn't auto-create them)
                        if secret_type == "kubernetes.io/service-account-token" {
                            let annotations = secret.get("metadata")
                                .and_then(|m| m.get("annotations"))
                                .and_then(|a| a.as_object());

                            // Check for manually created long-lived tokens
                            if annotations.map(|a| !a.contains_key("kubernetes.io/service-account.uid")).unwrap_or(true) {
                                findings.push(K8sFinding {
                                    resource_type: "Secret".to_string(),
                                    resource_name: secret_name.to_string(),
                                    namespace: namespace.to_string(),
                                    finding_type: "Long-Lived Service Account Token".to_string(),
                                    severity: "medium".to_string(),
                                    description: format!(
                                        "Service account token secret '{}' may be a manually created long-lived token. These don't auto-expire.",
                                        secret_name
                                    ),
                                    remediation: "Use short-lived projected service account tokens (TokenRequest API) instead of long-lived secrets.".to_string(),
                                });
                            }
                        }
                    }

                    // Check for namespaces with excessive secrets
                    for (namespace, secrets) in &secrets_by_namespace {
                        if secrets.len() > 50 {
                            findings.push(K8sFinding {
                                resource_type: "Namespace".to_string(),
                                resource_name: namespace.to_string(),
                                namespace: namespace.to_string(),
                                finding_type: "Excessive Secrets".to_string(),
                                severity: "info".to_string(),
                                description: format!(
                                    "Namespace '{}' has {} secrets. Consider reviewing if all are necessary.",
                                    namespace, secrets.len()
                                ),
                                remediation: "Audit secrets regularly and remove unused ones. Consider consolidating related secrets.".to_string(),
                            });
                        }
                    }
                }
            }
        }

        // Check encryption configuration (if accessible)
        let encrypt_output = self.kubectl_cmd()
            .args(["get", "configmap", "-n", "kube-system", "-o", "json"])
            .output()?;

        if encrypt_output.status.success() {
            // Look for encryption-related configmaps
            if let Ok(cm_list) = serde_json::from_slice::<serde_json::Value>(&encrypt_output.stdout) {
                let has_encryption_config = cm_list.get("items")
                    .and_then(|i| i.as_array())
                    .map(|items| {
                        items.iter().any(|item| {
                            item.get("metadata")
                                .and_then(|m| m.get("name"))
                                .and_then(|n| n.as_str())
                                .map(|name| name.contains("encrypt"))
                                .unwrap_or(false)
                        })
                    })
                    .unwrap_or(false);

                if !has_encryption_config {
                    findings.push(K8sFinding {
                        resource_type: "Cluster".to_string(),
                        resource_name: "encryption-config".to_string(),
                        namespace: "kube-system".to_string(),
                        finding_type: "Encryption at Rest Not Verified".to_string(),
                        severity: "medium".to_string(),
                        description: "Could not verify that encryption at rest is configured for etcd. Secrets may be stored unencrypted.".to_string(),
                        remediation: "Configure etcd encryption using EncryptionConfiguration with AES-GCM or secretbox encryption providers.".to_string(),
                    });
                }
            }
        }

        Ok(findings)
    }
}

impl Default for ClusterScanner {
    fn default() -> Self {
        Self::new()
    }
}
