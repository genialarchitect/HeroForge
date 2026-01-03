//! Kubernetes network security

use super::*;
use anyhow::Result;
use std::collections::HashSet;
use std::process::Command;

pub struct NetworkScanner {
    /// Path to kubeconfig file
    kubeconfig_path: Option<String>,
    /// Kubernetes context to use
    context: Option<String>,
    /// Namespace to scan (None for all namespaces)
    namespace: Option<String>,
}

impl NetworkScanner {
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

    /// Scan all network security aspects
    pub async fn scan_all(&self) -> Result<Vec<K8sFinding>> {
        let mut findings = Vec::new();
        findings.extend(self.scan_network_policies().await?);
        findings.extend(self.scan_service_mesh().await?);
        Ok(findings)
    }

    /// Scan network policies - check for default deny policies and ingress/egress rules
    pub async fn scan_network_policies(&self) -> Result<Vec<K8sFinding>> {
        let mut findings = Vec::new();

        // Get all namespaces
        let ns_output = self.kubectl_cmd()
            .args(["get", "namespaces", "-o", "json"])
            .output()?;

        let mut namespaces_without_policies: Vec<String> = Vec::new();
        let mut namespaces_to_check: Vec<String> = Vec::new();

        if ns_output.status.success() {
            if let Ok(ns_list) = serde_json::from_slice::<serde_json::Value>(&ns_output.stdout) {
                if let Some(items) = ns_list.get("items").and_then(|i| i.as_array()) {
                    for ns in items {
                        let ns_name = ns.get("metadata")
                            .and_then(|m| m.get("name"))
                            .and_then(|n| n.as_str())
                            .unwrap_or("default");

                        // Skip system namespaces
                        if ns_name == "kube-system" || ns_name == "kube-public" || ns_name == "kube-node-lease" {
                            continue;
                        }

                        // Apply namespace filter if specified
                        if let Some(target_ns) = &self.namespace {
                            if ns_name != target_ns {
                                continue;
                            }
                        }

                        namespaces_to_check.push(ns_name.to_string());
                    }
                }
            }
        }

        // Get network policies
        let mut cmd = self.kubectl_cmd();
        cmd.args(["get", "networkpolicies"]);
        if let Some(ns) = &self.namespace {
            cmd.args(["-n", ns]);
        } else {
            cmd.arg("--all-namespaces");
        }
        cmd.args(["-o", "json"]);

        let np_output = cmd.output()?;

        let mut namespaces_with_policies: HashSet<String> = HashSet::new();
        let mut has_default_deny_ingress: HashSet<String> = HashSet::new();
        let mut has_default_deny_egress: HashSet<String> = HashSet::new();

        if np_output.status.success() {
            if let Ok(np_list) = serde_json::from_slice::<serde_json::Value>(&np_output.stdout) {
                if let Some(items) = np_list.get("items").and_then(|i| i.as_array()) {
                    for policy in items {
                        let policy_name = policy.get("metadata")
                            .and_then(|m| m.get("name"))
                            .and_then(|n| n.as_str())
                            .unwrap_or("unknown");
                        let namespace = policy.get("metadata")
                            .and_then(|m| m.get("namespace"))
                            .and_then(|n| n.as_str())
                            .unwrap_or("default");

                        namespaces_with_policies.insert(namespace.to_string());

                        if let Some(spec) = policy.get("spec") {
                            // Check for pod selector (empty selector = applies to all pods)
                            let pod_selector = spec.get("podSelector")
                                .and_then(|p| p.get("matchLabels"))
                                .and_then(|m| m.as_object());

                            let is_default_policy = pod_selector.map(|m| m.is_empty()).unwrap_or(true);

                            // Check policy types
                            let policy_types = spec.get("policyTypes")
                                .and_then(|p| p.as_array())
                                .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>())
                                .unwrap_or_default();

                            // Check ingress rules
                            let ingress_rules = spec.get("ingress").and_then(|i| i.as_array());
                            let egress_rules = spec.get("egress").and_then(|e| e.as_array());

                            // Default deny ingress: policyTypes includes Ingress but no ingress rules
                            if policy_types.contains(&"Ingress") && ingress_rules.map(|r| r.is_empty()).unwrap_or(true) && is_default_policy {
                                has_default_deny_ingress.insert(namespace.to_string());
                            }

                            // Default deny egress: policyTypes includes Egress but no egress rules
                            if policy_types.contains(&"Egress") && egress_rules.map(|r| r.is_empty()).unwrap_or(true) && is_default_policy {
                                has_default_deny_egress.insert(namespace.to_string());
                            }

                            // Check for overly permissive ingress rules
                            if let Some(rules) = ingress_rules {
                                for rule in rules {
                                    // Check for allow-all-from rules (empty from)
                                    let from = rule.get("from").and_then(|f| f.as_array());
                                    if from.map(|f| f.is_empty()).unwrap_or(true) {
                                        // Empty or missing 'from' means allow from anywhere
                                        findings.push(K8sFinding {
                                            resource_type: "NetworkPolicy".to_string(),
                                            resource_name: policy_name.to_string(),
                                            namespace: namespace.to_string(),
                                            finding_type: "Permissive Ingress Rule".to_string(),
                                            severity: "medium".to_string(),
                                            description: format!(
                                                "NetworkPolicy '{}' has an ingress rule that allows traffic from any source.",
                                                policy_name
                                            ),
                                            remediation: "Specify explicit source selectors (podSelector, namespaceSelector, or ipBlock) in ingress rules.".to_string(),
                                        });
                                    }

                                    // Check for wide CIDR blocks
                                    if let Some(from_rules) = from {
                                        for from_rule in from_rules {
                                            if let Some(ip_block) = from_rule.get("ipBlock") {
                                                let cidr = ip_block.get("cidr").and_then(|c| c.as_str()).unwrap_or("");
                                                if cidr == "0.0.0.0/0" || cidr == "::/0" {
                                                    findings.push(K8sFinding {
                                                        resource_type: "NetworkPolicy".to_string(),
                                                        resource_name: policy_name.to_string(),
                                                        namespace: namespace.to_string(),
                                                        finding_type: "Wide CIDR in Ingress".to_string(),
                                                        severity: "high".to_string(),
                                                        description: format!(
                                                            "NetworkPolicy '{}' allows ingress from all IPs ({}).",
                                                            policy_name, cidr
                                                        ),
                                                        remediation: "Restrict the CIDR block to only necessary IP ranges.".to_string(),
                                                    });
                                                }
                                            }
                                        }
                                    }
                                }
                            }

                            // Check for overly permissive egress rules
                            if let Some(rules) = egress_rules {
                                for rule in rules {
                                    let to = rule.get("to").and_then(|t| t.as_array());
                                    if to.map(|t| t.is_empty()).unwrap_or(true) {
                                        findings.push(K8sFinding {
                                            resource_type: "NetworkPolicy".to_string(),
                                            resource_name: policy_name.to_string(),
                                            namespace: namespace.to_string(),
                                            finding_type: "Permissive Egress Rule".to_string(),
                                            severity: "medium".to_string(),
                                            description: format!(
                                                "NetworkPolicy '{}' has an egress rule that allows traffic to any destination.",
                                                policy_name
                                            ),
                                            remediation: "Specify explicit destination selectors in egress rules.".to_string(),
                                        });
                                    }

                                    if let Some(to_rules) = to {
                                        for to_rule in to_rules {
                                            if let Some(ip_block) = to_rule.get("ipBlock") {
                                                let cidr = ip_block.get("cidr").and_then(|c| c.as_str()).unwrap_or("");
                                                if cidr == "0.0.0.0/0" || cidr == "::/0" {
                                                    findings.push(K8sFinding {
                                                        resource_type: "NetworkPolicy".to_string(),
                                                        resource_name: policy_name.to_string(),
                                                        namespace: namespace.to_string(),
                                                        finding_type: "Wide CIDR in Egress".to_string(),
                                                        severity: "medium".to_string(),
                                                        description: format!(
                                                            "NetworkPolicy '{}' allows egress to all IPs ({}). Consider restricting for data exfiltration prevention.",
                                                            policy_name, cidr
                                                        ),
                                                        remediation: "Restrict egress to known required destinations.".to_string(),
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
        }

        // Find namespaces without any network policies
        for ns in &namespaces_to_check {
            if !namespaces_with_policies.contains(ns) {
                namespaces_without_policies.push(ns.clone());
            }
        }

        if !namespaces_without_policies.is_empty() {
            findings.push(K8sFinding {
                resource_type: "Namespace".to_string(),
                resource_name: namespaces_without_policies.join(", "),
                namespace: "N/A".to_string(),
                finding_type: "No NetworkPolicy".to_string(),
                severity: "high".to_string(),
                description: format!(
                    "{} namespace(s) have no NetworkPolicies: {}. Pods have unrestricted network access.",
                    namespaces_without_policies.len(),
                    namespaces_without_policies.join(", ")
                ),
                remediation: "Create default-deny NetworkPolicies for each namespace and explicitly allow required traffic.".to_string(),
            });
        }

        // Check for namespaces missing default deny
        for ns in &namespaces_to_check {
            if namespaces_with_policies.contains(ns) {
                if !has_default_deny_ingress.contains(ns) {
                    findings.push(K8sFinding {
                        resource_type: "Namespace".to_string(),
                        resource_name: ns.clone(),
                        namespace: ns.clone(),
                        finding_type: "No Default Deny Ingress".to_string(),
                        severity: "medium".to_string(),
                        description: format!(
                            "Namespace '{}' has NetworkPolicies but no default deny ingress policy. Pods may receive unexpected traffic.",
                            ns
                        ),
                        remediation: "Create a default deny ingress NetworkPolicy that selects all pods in the namespace.".to_string(),
                    });
                }

                if !has_default_deny_egress.contains(ns) {
                    findings.push(K8sFinding {
                        resource_type: "Namespace".to_string(),
                        resource_name: ns.clone(),
                        namespace: ns.clone(),
                        finding_type: "No Default Deny Egress".to_string(),
                        severity: "low".to_string(),
                        description: format!(
                            "Namespace '{}' has no default deny egress policy. Pods can make outbound connections to any destination.",
                            ns
                        ),
                        remediation: "Consider adding default deny egress to prevent data exfiltration. Allow specific egress targets.".to_string(),
                    });
                }
            }
        }

        Ok(findings)
    }

    /// Scan service mesh security (Istio, Linkerd) - check mTLS and authorization policies
    pub async fn scan_service_mesh(&self) -> Result<Vec<K8sFinding>> {
        let mut findings = Vec::new();
        let mut has_service_mesh = false;

        // Check for Istio
        let istio_check = self.kubectl_cmd()
            .args(["get", "namespace", "istio-system", "-o", "json"])
            .output();

        if let Ok(output) = istio_check {
            if output.status.success() {
                has_service_mesh = true;

                // Check Istio mTLS configuration (PeerAuthentication)
                let peer_auth_output = self.kubectl_cmd()
                    .args(["get", "peerauthentication", "--all-namespaces", "-o", "json"])
                    .output()?;

                let mut has_strict_mtls = false;

                if peer_auth_output.status.success() {
                    if let Ok(pa_list) = serde_json::from_slice::<serde_json::Value>(&peer_auth_output.stdout) {
                        if let Some(items) = pa_list.get("items").and_then(|i| i.as_array()) {
                            for pa in items {
                                let pa_name = pa.get("metadata")
                                    .and_then(|m| m.get("name"))
                                    .and_then(|n| n.as_str())
                                    .unwrap_or("unknown");
                                let namespace = pa.get("metadata")
                                    .and_then(|m| m.get("namespace"))
                                    .and_then(|n| n.as_str())
                                    .unwrap_or("default");

                                if let Some(spec) = pa.get("spec") {
                                    let mtls_mode = spec.get("mtls")
                                        .and_then(|m| m.get("mode"))
                                        .and_then(|m| m.as_str())
                                        .unwrap_or("PERMISSIVE");

                                    // Check for mesh-wide (istio-system) strict mTLS
                                    if namespace == "istio-system" && mtls_mode == "STRICT" {
                                        has_strict_mtls = true;
                                    }

                                    if mtls_mode == "DISABLE" {
                                        findings.push(K8sFinding {
                                            resource_type: "PeerAuthentication".to_string(),
                                            resource_name: pa_name.to_string(),
                                            namespace: namespace.to_string(),
                                            finding_type: "mTLS Disabled".to_string(),
                                            severity: "high".to_string(),
                                            description: format!(
                                                "PeerAuthentication '{}' in namespace '{}' has mTLS disabled. Traffic is unencrypted.",
                                                pa_name, namespace
                                            ),
                                            remediation: "Enable mTLS by setting mtls.mode to STRICT or PERMISSIVE.".to_string(),
                                        });
                                    } else if mtls_mode == "PERMISSIVE" {
                                        findings.push(K8sFinding {
                                            resource_type: "PeerAuthentication".to_string(),
                                            resource_name: pa_name.to_string(),
                                            namespace: namespace.to_string(),
                                            finding_type: "mTLS Permissive".to_string(),
                                            severity: "medium".to_string(),
                                            description: format!(
                                                "PeerAuthentication '{}' uses PERMISSIVE mode. Both encrypted and plaintext traffic allowed.",
                                                pa_name
                                            ),
                                            remediation: "Consider setting mtls.mode to STRICT after confirming all services support mTLS.".to_string(),
                                        });
                                    }
                                }
                            }
                        }
                    }
                }

                if !has_strict_mtls {
                    findings.push(K8sFinding {
                        resource_type: "Istio".to_string(),
                        resource_name: "mesh-mtls".to_string(),
                        namespace: "istio-system".to_string(),
                        finding_type: "No Mesh-Wide Strict mTLS".to_string(),
                        severity: "medium".to_string(),
                        description: "Istio mesh does not have mesh-wide strict mTLS enabled. Some traffic may be unencrypted.".to_string(),
                        remediation: "Create a PeerAuthentication in istio-system with mtls.mode: STRICT for mesh-wide encryption.".to_string(),
                    });
                }

                // Check Istio AuthorizationPolicy
                let auth_policy_output = self.kubectl_cmd()
                    .args(["get", "authorizationpolicy", "--all-namespaces", "-o", "json"])
                    .output()?;

                let mut has_auth_policies = false;

                if auth_policy_output.status.success() {
                    if let Ok(ap_list) = serde_json::from_slice::<serde_json::Value>(&auth_policy_output.stdout) {
                        if let Some(items) = ap_list.get("items").and_then(|i| i.as_array()) {
                            has_auth_policies = !items.is_empty();

                            for ap in items {
                                let ap_name = ap.get("metadata")
                                    .and_then(|m| m.get("name"))
                                    .and_then(|n| n.as_str())
                                    .unwrap_or("unknown");
                                let namespace = ap.get("metadata")
                                    .and_then(|m| m.get("namespace"))
                                    .and_then(|n| n.as_str())
                                    .unwrap_or("default");

                                if let Some(spec) = ap.get("spec") {
                                    // Check for ALLOW policy with no rules (allows all)
                                    let action = spec.get("action")
                                        .and_then(|a| a.as_str())
                                        .unwrap_or("ALLOW");
                                    let rules = spec.get("rules").and_then(|r| r.as_array());

                                    if action == "ALLOW" && rules.map(|r| r.is_empty()).unwrap_or(true) {
                                        let selector = spec.get("selector");
                                        if selector.is_none() {
                                            findings.push(K8sFinding {
                                                resource_type: "AuthorizationPolicy".to_string(),
                                                resource_name: ap_name.to_string(),
                                                namespace: namespace.to_string(),
                                                finding_type: "Permissive Authorization".to_string(),
                                                severity: "medium".to_string(),
                                                description: format!(
                                                    "AuthorizationPolicy '{}' allows all traffic without rules or selector.",
                                                    ap_name
                                                ),
                                                remediation: "Define specific rules or use selector to limit policy scope.".to_string(),
                                            });
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                if !has_auth_policies {
                    findings.push(K8sFinding {
                        resource_type: "Istio".to_string(),
                        resource_name: "authorization".to_string(),
                        namespace: "N/A".to_string(),
                        finding_type: "No Authorization Policies".to_string(),
                        severity: "medium".to_string(),
                        description: "No Istio AuthorizationPolicies defined. All service-to-service communication is allowed.".to_string(),
                        remediation: "Create AuthorizationPolicies to implement least-privilege access between services.".to_string(),
                    });
                }

                // Check for Istio Gateway security
                let gateway_output = self.kubectl_cmd()
                    .args(["get", "gateway", "--all-namespaces", "-o", "json"])
                    .output()?;

                if gateway_output.status.success() {
                    if let Ok(gw_list) = serde_json::from_slice::<serde_json::Value>(&gateway_output.stdout) {
                        if let Some(items) = gw_list.get("items").and_then(|i| i.as_array()) {
                            for gw in items {
                                let gw_name = gw.get("metadata")
                                    .and_then(|m| m.get("name"))
                                    .and_then(|n| n.as_str())
                                    .unwrap_or("unknown");
                                let namespace = gw.get("metadata")
                                    .and_then(|m| m.get("namespace"))
                                    .and_then(|n| n.as_str())
                                    .unwrap_or("default");

                                if let Some(spec) = gw.get("spec") {
                                    if let Some(servers) = spec.get("servers").and_then(|s| s.as_array()) {
                                        for server in servers {
                                            let port = server.get("port")
                                                .and_then(|p| p.get("protocol"))
                                                .and_then(|p| p.as_str())
                                                .unwrap_or("");

                                            let tls = server.get("tls");

                                            if port == "HTTP" || (port == "HTTPS" && tls.is_none()) {
                                                let hosts = server.get("hosts")
                                                    .and_then(|h| h.as_array())
                                                    .map(|h| h.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>().join(", "))
                                                    .unwrap_or_else(|| "*".to_string());

                                                findings.push(K8sFinding {
                                                    resource_type: "Gateway".to_string(),
                                                    resource_name: gw_name.to_string(),
                                                    namespace: namespace.to_string(),
                                                    finding_type: "Insecure Gateway".to_string(),
                                                    severity: "high".to_string(),
                                                    description: format!(
                                                        "Gateway '{}' exposes hosts ({}) over unencrypted HTTP.",
                                                        gw_name, hosts
                                                    ),
                                                    remediation: "Configure TLS on the Gateway server or redirect HTTP to HTTPS.".to_string(),
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

        // Check for Linkerd
        let linkerd_check = self.kubectl_cmd()
            .args(["get", "namespace", "linkerd", "-o", "json"])
            .output();

        if let Ok(output) = linkerd_check {
            if output.status.success() {
                has_service_mesh = true;

                // Check Linkerd proxy injection
                let ns_output = self.kubectl_cmd()
                    .args(["get", "namespaces", "-o", "json"])
                    .output()?;

                if ns_output.status.success() {
                    if let Ok(ns_list) = serde_json::from_slice::<serde_json::Value>(&ns_output.stdout) {
                        if let Some(items) = ns_list.get("items").and_then(|i| i.as_array()) {
                            let mut uninject_namespaces: Vec<String> = Vec::new();

                            for ns in items {
                                let ns_name = ns.get("metadata")
                                    .and_then(|m| m.get("name"))
                                    .and_then(|n| n.as_str())
                                    .unwrap_or("default");

                                // Skip system namespaces
                                if ns_name.starts_with("kube-") || ns_name == "linkerd" || ns_name == "linkerd-viz" {
                                    continue;
                                }

                                let annotations = ns.get("metadata")
                                    .and_then(|m| m.get("annotations"))
                                    .and_then(|a| a.as_object());

                                let has_injection = annotations.map(|a| {
                                    a.get("linkerd.io/inject").and_then(|v| v.as_str()) == Some("enabled")
                                }).unwrap_or(false);

                                if !has_injection {
                                    uninject_namespaces.push(ns_name.to_string());
                                }
                            }

                            if !uninject_namespaces.is_empty() && uninject_namespaces.len() < 10 {
                                findings.push(K8sFinding {
                                    resource_type: "Namespace".to_string(),
                                    resource_name: uninject_namespaces.join(", "),
                                    namespace: "N/A".to_string(),
                                    finding_type: "Linkerd Not Injected".to_string(),
                                    severity: "low".to_string(),
                                    description: format!(
                                        "Namespaces without Linkerd proxy injection: {}. Traffic is not encrypted by service mesh.",
                                        uninject_namespaces.join(", ")
                                    ),
                                    remediation: "Add annotation 'linkerd.io/inject: enabled' to namespaces that should use mTLS.".to_string(),
                                });
                            }
                        }
                    }
                }

                // Check Linkerd Server resources for authorization
                let server_output = self.kubectl_cmd()
                    .args(["get", "servers.policy.linkerd.io", "--all-namespaces", "-o", "json"])
                    .output();

                if let Ok(output) = server_output {
                    if output.status.success() {
                        if let Ok(srv_list) = serde_json::from_slice::<serde_json::Value>(&output.stdout) {
                            let items = srv_list.get("items").and_then(|i| i.as_array());
                            if items.map(|i| i.is_empty()).unwrap_or(true) {
                                findings.push(K8sFinding {
                                    resource_type: "Linkerd".to_string(),
                                    resource_name: "authorization".to_string(),
                                    namespace: "N/A".to_string(),
                                    finding_type: "No Linkerd Authorization".to_string(),
                                    severity: "medium".to_string(),
                                    description: "No Linkerd Server resources defined. Consider using Linkerd's authorization policies.".to_string(),
                                    remediation: "Define Server and ServerAuthorization resources for fine-grained access control.".to_string(),
                                });
                            }
                        }
                    }
                }
            }
        }

        // If no service mesh detected
        if !has_service_mesh {
            findings.push(K8sFinding {
                resource_type: "Cluster".to_string(),
                resource_name: "service-mesh".to_string(),
                namespace: "N/A".to_string(),
                finding_type: "No Service Mesh".to_string(),
                severity: "low".to_string(),
                description: "No service mesh (Istio or Linkerd) detected. Service-to-service traffic may be unencrypted.".to_string(),
                remediation: "Consider deploying a service mesh for automatic mTLS between services.".to_string(),
            });
        }

        Ok(findings)
    }
}

impl Default for NetworkScanner {
    fn default() -> Self {
        Self::new()
    }
}
