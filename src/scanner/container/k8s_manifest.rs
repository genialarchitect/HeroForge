//! Kubernetes Manifest Security Analyzer
//!
//! This module analyzes Kubernetes YAML manifests for security issues:
//! - Pod security context violations
//! - Privileged containers
//! - Host network/PID/IPC sharing
//! - Missing resource limits
//! - RBAC misconfigurations
//! - Network policy gaps
//! - Secret management issues

use anyhow::Result;
use chrono::Utc;
use std::collections::HashMap;
use uuid::Uuid;

use super::types::{
    ContainerFinding, ContainerFindingSeverity, ContainerFindingType, FindingStatus,
    K8sManifestAnalysis, K8sResource, K8sResourceType,
};

/// Analyze Kubernetes manifests for security issues
pub async fn analyze_manifest(
    content: &str,
    demo_mode: bool,
) -> Result<K8sManifestAnalysis> {
    if content.is_empty() && demo_mode {
        return generate_demo_manifest_analysis().await;
    }

    let scan_id = Uuid::new_v4().to_string();
    let mut resources = Vec::new();
    let mut findings = Vec::new();
    let mut resource_counts: HashMap<String, i32> = HashMap::new();
    let mut namespaces = Vec::new();

    // Parse YAML documents (handle multi-document YAML)
    for document in content.split("---") {
        let trimmed = document.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        match serde_yaml::from_str::<serde_json::Value>(trimmed) {
            Ok(manifest) => {
                if let Some((resource, resource_findings)) = analyze_resource(&manifest, &scan_id) {
                    let resource_type_str = resource.resource_type.to_string();
                    *resource_counts.entry(resource_type_str).or_insert(0) += 1;

                    if let Some(ns) = &resource.namespace {
                        if !namespaces.contains(ns) {
                            namespaces.push(ns.clone());
                        }
                    }

                    resources.push(resource);
                    findings.extend(resource_findings);
                }
            }
            Err(e) => {
                log::warn!("Failed to parse YAML document: {}", e);
            }
        }
    }

    Ok(K8sManifestAnalysis {
        resources,
        findings,
        resource_counts,
        namespaces,
    })
}

/// Analyze a single Kubernetes resource
fn analyze_resource(
    manifest: &serde_json::Value,
    scan_id: &str,
) -> Option<(K8sResource, Vec<ContainerFinding>)> {
    let kind = manifest.get("kind")?.as_str()?;
    let api_version = manifest.get("apiVersion")?.as_str().unwrap_or("v1");

    let metadata = manifest.get("metadata")?;
    let name = metadata.get("name")?.as_str()?.to_string();
    let namespace = metadata.get("namespace").and_then(|n| n.as_str()).map(String::from);

    let labels: HashMap<String, String> = metadata.get("labels")
        .and_then(|l| serde_json::from_value(l.clone()).ok())
        .unwrap_or_default();

    let annotations: HashMap<String, String> = metadata.get("annotations")
        .and_then(|a| serde_json::from_value(a.clone()).ok())
        .unwrap_or_default();

    let resource_type = parse_resource_type(kind);
    let resource_id = Uuid::new_v4().to_string();

    let mut findings = Vec::new();

    // Analyze based on resource type
    match &resource_type {
        K8sResourceType::Pod
        | K8sResourceType::Deployment
        | K8sResourceType::StatefulSet
        | K8sResourceType::DaemonSet
        | K8sResourceType::Job
        | K8sResourceType::CronJob => {
            // Get pod spec
            let pod_spec = if kind == "Pod" {
                manifest.get("spec")
            } else {
                manifest.get("spec")
                    .and_then(|s| s.get("template"))
                    .and_then(|t| t.get("spec"))
            };

            if let Some(spec) = pod_spec {
                findings.extend(analyze_pod_spec(spec, &resource_id, scan_id, &name));
            }
        }
        K8sResourceType::Service => {
            findings.extend(analyze_service(manifest, &resource_id, scan_id, &name));
        }
        K8sResourceType::Ingress => {
            findings.extend(analyze_ingress(manifest, &resource_id, scan_id, &name));
        }
        K8sResourceType::Role | K8sResourceType::ClusterRole => {
            findings.extend(analyze_role(manifest, &resource_id, scan_id, &name));
        }
        K8sResourceType::RoleBinding | K8sResourceType::ClusterRoleBinding => {
            findings.extend(analyze_role_binding(manifest, &resource_id, scan_id, &name));
        }
        K8sResourceType::NetworkPolicy => {
            findings.extend(analyze_network_policy(manifest, &resource_id, scan_id, &name));
        }
        K8sResourceType::Secret => {
            findings.extend(analyze_secret(manifest, &resource_id, scan_id, &name));
        }
        K8sResourceType::ConfigMap => {
            findings.extend(analyze_configmap(manifest, &resource_id, scan_id, &name));
        }
        _ => {}
    }

    let resource = K8sResource {
        id: resource_id.clone(),
        scan_id: scan_id.to_string(),
        resource_type,
        api_version: api_version.to_string(),
        name,
        namespace,
        labels,
        annotations,
        manifest: manifest.clone(),
        finding_count: findings.len() as i32,
        discovered_at: Utc::now(),
    };

    Some((resource, findings))
}

/// Parse Kubernetes resource type
fn parse_resource_type(kind: &str) -> K8sResourceType {
    match kind.to_lowercase().as_str() {
        "pod" => K8sResourceType::Pod,
        "deployment" => K8sResourceType::Deployment,
        "statefulset" => K8sResourceType::StatefulSet,
        "daemonset" => K8sResourceType::DaemonSet,
        "replicaset" => K8sResourceType::ReplicaSet,
        "job" => K8sResourceType::Job,
        "cronjob" => K8sResourceType::CronJob,
        "service" => K8sResourceType::Service,
        "ingress" => K8sResourceType::Ingress,
        "configmap" => K8sResourceType::ConfigMap,
        "secret" => K8sResourceType::Secret,
        "serviceaccount" => K8sResourceType::ServiceAccount,
        "role" => K8sResourceType::Role,
        "clusterrole" => K8sResourceType::ClusterRole,
        "rolebinding" => K8sResourceType::RoleBinding,
        "clusterrolebinding" => K8sResourceType::ClusterRoleBinding,
        "networkpolicy" => K8sResourceType::NetworkPolicy,
        "podsecuritypolicy" => K8sResourceType::PodSecurityPolicy,
        "namespace" => K8sResourceType::Namespace,
        "node" => K8sResourceType::Node,
        "persistentvolume" => K8sResourceType::PersistentVolume,
        "persistentvolumeclaim" => K8sResourceType::PersistentVolumeClaim,
        other => K8sResourceType::Other(other.to_string()),
    }
}

/// Analyze pod spec for security issues
fn analyze_pod_spec(
    spec: &serde_json::Value,
    resource_id: &str,
    scan_id: &str,
    resource_name: &str,
) -> Vec<ContainerFinding> {
    let mut findings = Vec::new();

    // Check host network
    if spec.get("hostNetwork").and_then(|h| h.as_bool()).unwrap_or(false) {
        findings.push(ContainerFinding {
            id: Uuid::new_v4().to_string(),
            scan_id: scan_id.to_string(),
            image_id: None,
            resource_id: Some(resource_id.to_string()),
            finding_type: ContainerFindingType::NetworkExposure,
            severity: ContainerFindingSeverity::High,
            title: "Pod uses host network".to_string(),
            description: format!(
                "The pod '{}' has hostNetwork: true, sharing the host's network namespace. \
                This bypasses Kubernetes network policies.", resource_name
            ),
            cve_id: None,
            cvss_score: None,
            cwe_ids: vec!["CWE-668".to_string()],
            package_name: None,
            package_version: None,
            fixed_version: None,
            file_path: None,
            line_number: None,
            remediation: Some("Set hostNetwork: false unless absolutely required.".to_string()),
            references: vec![],
            status: FindingStatus::Open,
            created_at: Utc::now(),
        });
    }

    // Check host PID
    if spec.get("hostPID").and_then(|h| h.as_bool()).unwrap_or(false) {
        findings.push(ContainerFinding {
            id: Uuid::new_v4().to_string(),
            scan_id: scan_id.to_string(),
            image_id: None,
            resource_id: Some(resource_id.to_string()),
            finding_type: ContainerFindingType::PrivilegeEscalation,
            severity: ContainerFindingSeverity::High,
            title: "Pod shares host PID namespace".to_string(),
            description: format!(
                "The pod '{}' has hostPID: true, allowing it to see all host processes.", resource_name
            ),
            cve_id: None,
            cvss_score: None,
            cwe_ids: vec!["CWE-668".to_string()],
            package_name: None,
            package_version: None,
            fixed_version: None,
            file_path: None,
            line_number: None,
            remediation: Some("Set hostPID: false.".to_string()),
            references: vec![],
            status: FindingStatus::Open,
            created_at: Utc::now(),
        });
    }

    // Check host IPC
    if spec.get("hostIPC").and_then(|h| h.as_bool()).unwrap_or(false) {
        findings.push(ContainerFinding {
            id: Uuid::new_v4().to_string(),
            scan_id: scan_id.to_string(),
            image_id: None,
            resource_id: Some(resource_id.to_string()),
            finding_type: ContainerFindingType::PrivilegeEscalation,
            severity: ContainerFindingSeverity::Medium,
            title: "Pod shares host IPC namespace".to_string(),
            description: format!(
                "The pod '{}' has hostIPC: true, sharing inter-process communication.", resource_name
            ),
            cve_id: None,
            cvss_score: None,
            cwe_ids: vec!["CWE-668".to_string()],
            package_name: None,
            package_version: None,
            fixed_version: None,
            file_path: None,
            line_number: None,
            remediation: Some("Set hostIPC: false.".to_string()),
            references: vec![],
            status: FindingStatus::Open,
            created_at: Utc::now(),
        });
    }

    // Analyze containers
    if let Some(containers) = spec.get("containers").and_then(|c| c.as_array()) {
        for container in containers {
            findings.extend(analyze_container(container, resource_id, scan_id, resource_name));
        }
    }

    // Analyze init containers
    if let Some(init_containers) = spec.get("initContainers").and_then(|c| c.as_array()) {
        for container in init_containers {
            findings.extend(analyze_container(container, resource_id, scan_id, resource_name));
        }
    }

    // Check for automountServiceAccountToken
    let automount = spec.get("automountServiceAccountToken")
        .and_then(|a| a.as_bool())
        .unwrap_or(true);

    if automount {
        findings.push(ContainerFinding {
            id: Uuid::new_v4().to_string(),
            scan_id: scan_id.to_string(),
            image_id: None,
            resource_id: Some(resource_id.to_string()),
            finding_type: ContainerFindingType::Misconfiguration,
            severity: ContainerFindingSeverity::Low,
            title: "Service account token auto-mounted".to_string(),
            description: format!(
                "The pod '{}' automatically mounts the service account token. \
                If the pod doesn't need API access, this is unnecessary exposure.", resource_name
            ),
            cve_id: None,
            cvss_score: None,
            cwe_ids: vec![],
            package_name: None,
            package_version: None,
            fixed_version: None,
            file_path: None,
            line_number: None,
            remediation: Some(
                "Set automountServiceAccountToken: false if the pod doesn't need Kubernetes API access.".to_string()
            ),
            references: vec![],
            status: FindingStatus::Open,
            created_at: Utc::now(),
        });
    }

    findings
}

/// Analyze a container spec
fn analyze_container(
    container: &serde_json::Value,
    resource_id: &str,
    scan_id: &str,
    resource_name: &str,
) -> Vec<ContainerFinding> {
    let mut findings = Vec::new();
    let container_name = container.get("name")
        .and_then(|n| n.as_str())
        .unwrap_or("unknown");

    // Check security context
    if let Some(security_context) = container.get("securityContext") {
        // Check privileged
        if security_context.get("privileged").and_then(|p| p.as_bool()).unwrap_or(false) {
            findings.push(ContainerFinding {
                id: Uuid::new_v4().to_string(),
                scan_id: scan_id.to_string(),
                image_id: None,
                resource_id: Some(resource_id.to_string()),
                finding_type: ContainerFindingType::PrivilegeEscalation,
                severity: ContainerFindingSeverity::Critical,
                title: format!("Container '{}' runs in privileged mode", container_name),
                description: format!(
                    "Container '{}' in pod '{}' has privileged: true, \
                    giving it full access to the host.", container_name, resource_name
                ),
                cve_id: None,
                cvss_score: None,
                cwe_ids: vec!["CWE-250".to_string()],
                package_name: None,
                package_version: None,
                fixed_version: None,
                file_path: None,
                line_number: None,
                remediation: Some("Set privileged: false.".to_string()),
                references: vec![],
                status: FindingStatus::Open,
                created_at: Utc::now(),
            });
        }

        // Check allowPrivilegeEscalation
        let allow_priv_esc = security_context.get("allowPrivilegeEscalation")
            .and_then(|a| a.as_bool())
            .unwrap_or(true);

        if allow_priv_esc {
            findings.push(ContainerFinding {
                id: Uuid::new_v4().to_string(),
                scan_id: scan_id.to_string(),
                image_id: None,
                resource_id: Some(resource_id.to_string()),
                finding_type: ContainerFindingType::PrivilegeEscalation,
                severity: ContainerFindingSeverity::Medium,
                title: format!("Container '{}' allows privilege escalation", container_name),
                description: format!(
                    "Container '{}' can gain more privileges than its parent process.", container_name
                ),
                cve_id: None,
                cvss_score: None,
                cwe_ids: vec!["CWE-250".to_string()],
                package_name: None,
                package_version: None,
                fixed_version: None,
                file_path: None,
                line_number: None,
                remediation: Some("Set allowPrivilegeEscalation: false.".to_string()),
                references: vec![],
                status: FindingStatus::Open,
                created_at: Utc::now(),
            });
        }

        // Check runAsNonRoot
        let run_as_non_root = security_context.get("runAsNonRoot")
            .and_then(|r| r.as_bool())
            .unwrap_or(false);

        if !run_as_non_root {
            findings.push(ContainerFinding {
                id: Uuid::new_v4().to_string(),
                scan_id: scan_id.to_string(),
                image_id: None,
                resource_id: Some(resource_id.to_string()),
                finding_type: ContainerFindingType::Misconfiguration,
                severity: ContainerFindingSeverity::Medium,
                title: format!("Container '{}' may run as root", container_name),
                description: format!(
                    "Container '{}' doesn't enforce running as non-root.", container_name
                ),
                cve_id: None,
                cvss_score: None,
                cwe_ids: vec!["CWE-250".to_string()],
                package_name: None,
                package_version: None,
                fixed_version: None,
                file_path: None,
                line_number: None,
                remediation: Some("Set runAsNonRoot: true and runAsUser to a non-zero UID.".to_string()),
                references: vec![],
                status: FindingStatus::Open,
                created_at: Utc::now(),
            });
        }

        // Check readOnlyRootFilesystem
        let read_only = security_context.get("readOnlyRootFilesystem")
            .and_then(|r| r.as_bool())
            .unwrap_or(false);

        if !read_only {
            findings.push(ContainerFinding {
                id: Uuid::new_v4().to_string(),
                scan_id: scan_id.to_string(),
                image_id: None,
                resource_id: Some(resource_id.to_string()),
                finding_type: ContainerFindingType::BestPractice,
                severity: ContainerFindingSeverity::Low,
                title: format!("Container '{}' has writable root filesystem", container_name),
                description: format!(
                    "Container '{}' can write to its root filesystem, \
                    increasing attack surface.", container_name
                ),
                cve_id: None,
                cvss_score: None,
                cwe_ids: vec![],
                package_name: None,
                package_version: None,
                fixed_version: None,
                file_path: None,
                line_number: None,
                remediation: Some("Set readOnlyRootFilesystem: true.".to_string()),
                references: vec![],
                status: FindingStatus::Open,
                created_at: Utc::now(),
            });
        }

        // Check dangerous capabilities
        if let Some(capabilities) = security_context.get("capabilities") {
            if let Some(add) = capabilities.get("add").and_then(|a| a.as_array()) {
                let dangerous = ["SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "DAC_OVERRIDE", "ALL"];
                for cap in add {
                    if let Some(cap_str) = cap.as_str() {
                        if dangerous.contains(&cap_str.to_uppercase().as_str()) {
                            findings.push(ContainerFinding {
                                id: Uuid::new_v4().to_string(),
                                scan_id: scan_id.to_string(),
                                image_id: None,
                                resource_id: Some(resource_id.to_string()),
                                finding_type: ContainerFindingType::PrivilegeEscalation,
                                severity: ContainerFindingSeverity::High,
                                title: format!("Container '{}' has dangerous capability: {}", container_name, cap_str),
                                description: format!(
                                    "The {} capability can be used for privilege escalation.", cap_str
                                ),
                                cve_id: None,
                                cvss_score: None,
                                cwe_ids: vec!["CWE-250".to_string()],
                                package_name: None,
                                package_version: None,
                                fixed_version: None,
                                file_path: None,
                                line_number: None,
                                remediation: Some(format!("Remove {} from capabilities.add.", cap_str)),
                                references: vec![],
                                status: FindingStatus::Open,
                                created_at: Utc::now(),
                            });
                        }
                    }
                }
            }
        }
    } else {
        // No security context defined
        findings.push(ContainerFinding {
            id: Uuid::new_v4().to_string(),
            scan_id: scan_id.to_string(),
            image_id: None,
            resource_id: Some(resource_id.to_string()),
            finding_type: ContainerFindingType::Misconfiguration,
            severity: ContainerFindingSeverity::Medium,
            title: format!("Container '{}' has no security context", container_name),
            description: format!(
                "Container '{}' doesn't define a securityContext, \
                relying on defaults which may be insecure.", container_name
            ),
            cve_id: None,
            cvss_score: None,
            cwe_ids: vec![],
            package_name: None,
            package_version: None,
            fixed_version: None,
            file_path: None,
            line_number: None,
            remediation: Some(
                "Add a securityContext with runAsNonRoot: true, \
                allowPrivilegeEscalation: false, and drop all capabilities.".to_string()
            ),
            references: vec![],
            status: FindingStatus::Open,
            created_at: Utc::now(),
        });
    }

    // Check resource limits
    if container.get("resources").is_none() {
        findings.push(ContainerFinding {
            id: Uuid::new_v4().to_string(),
            scan_id: scan_id.to_string(),
            image_id: None,
            resource_id: Some(resource_id.to_string()),
            finding_type: ContainerFindingType::Misconfiguration,
            severity: ContainerFindingSeverity::Medium,
            title: format!("Container '{}' has no resource limits", container_name),
            description: format!(
                "Container '{}' doesn't define resource limits, \
                risking resource exhaustion.", container_name
            ),
            cve_id: None,
            cvss_score: None,
            cwe_ids: vec!["CWE-770".to_string()],
            package_name: None,
            package_version: None,
            fixed_version: None,
            file_path: None,
            line_number: None,
            remediation: Some("Define resources.limits and resources.requests.".to_string()),
            references: vec![],
            status: FindingStatus::Open,
            created_at: Utc::now(),
        });
    }

    // Check image tag
    if let Some(image) = container.get("image").and_then(|i| i.as_str()) {
        if !image.contains(':') || image.ends_with(":latest") {
            findings.push(ContainerFinding {
                id: Uuid::new_v4().to_string(),
                scan_id: scan_id.to_string(),
                image_id: None,
                resource_id: Some(resource_id.to_string()),
                finding_type: ContainerFindingType::BestPractice,
                severity: ContainerFindingSeverity::Medium,
                title: format!("Container '{}' uses 'latest' or untagged image", container_name),
                description: format!(
                    "Container '{}' uses image '{}' without a specific version tag.", container_name, image
                ),
                cve_id: None,
                cvss_score: None,
                cwe_ids: vec!["CWE-1104".to_string()],
                package_name: None,
                package_version: None,
                fixed_version: None,
                file_path: None,
                line_number: None,
                remediation: Some("Use a specific version tag or digest.".to_string()),
                references: vec![],
                status: FindingStatus::Open,
                created_at: Utc::now(),
            });
        }
    }

    findings
}

/// Analyze Service resource
fn analyze_service(
    manifest: &serde_json::Value,
    resource_id: &str,
    scan_id: &str,
    resource_name: &str,
) -> Vec<ContainerFinding> {
    let mut findings = Vec::new();

    if let Some(spec) = manifest.get("spec") {
        // Check for LoadBalancer without restrictions
        if let Some(svc_type) = spec.get("type").and_then(|t| t.as_str()) {
            if svc_type == "LoadBalancer" {
                findings.push(ContainerFinding {
                    id: Uuid::new_v4().to_string(),
                    scan_id: scan_id.to_string(),
                    image_id: None,
                    resource_id: Some(resource_id.to_string()),
                    finding_type: ContainerFindingType::NetworkExposure,
                    severity: ContainerFindingSeverity::Medium,
                    title: format!("Service '{}' exposed as LoadBalancer", resource_name),
                    description: format!(
                        "Service '{}' is exposed externally. Ensure proper network policies.", resource_name
                    ),
                    cve_id: None,
                    cvss_score: None,
                    cwe_ids: vec![],
                    package_name: None,
                    package_version: None,
                    fixed_version: None,
                    file_path: None,
                    line_number: None,
                    remediation: Some("Consider using Ingress with authentication instead.".to_string()),
                    references: vec![],
                    status: FindingStatus::Open,
                    created_at: Utc::now(),
                });
            }
        }
    }

    findings
}

/// Analyze Ingress resource
fn analyze_ingress(
    manifest: &serde_json::Value,
    resource_id: &str,
    scan_id: &str,
    resource_name: &str,
) -> Vec<ContainerFinding> {
    let mut findings = Vec::new();

    if let Some(spec) = manifest.get("spec") {
        // Check for missing TLS
        if spec.get("tls").is_none() {
            findings.push(ContainerFinding {
                id: Uuid::new_v4().to_string(),
                scan_id: scan_id.to_string(),
                image_id: None,
                resource_id: Some(resource_id.to_string()),
                finding_type: ContainerFindingType::Misconfiguration,
                severity: ContainerFindingSeverity::High,
                title: format!("Ingress '{}' has no TLS configured", resource_name),
                description: format!(
                    "Ingress '{}' doesn't configure TLS, exposing traffic unencrypted.", resource_name
                ),
                cve_id: None,
                cvss_score: None,
                cwe_ids: vec!["CWE-319".to_string()],
                package_name: None,
                package_version: None,
                fixed_version: None,
                file_path: None,
                line_number: None,
                remediation: Some("Add TLS configuration with valid certificates.".to_string()),
                references: vec![],
                status: FindingStatus::Open,
                created_at: Utc::now(),
            });
        }
    }

    findings
}

/// Analyze Role/ClusterRole
fn analyze_role(
    manifest: &serde_json::Value,
    resource_id: &str,
    scan_id: &str,
    resource_name: &str,
) -> Vec<ContainerFinding> {
    let mut findings = Vec::new();

    if let Some(rules) = manifest.get("rules").and_then(|r| r.as_array()) {
        for rule in rules {
            let verbs: Vec<&str> = rule.get("verbs")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
                .unwrap_or_default();

            let resources: Vec<&str> = rule.get("resources")
                .and_then(|r| r.as_array())
                .map(|arr| arr.iter().filter_map(|r| r.as_str()).collect())
                .unwrap_or_default();

            // Check for wildcard permissions
            if verbs.contains(&"*") || resources.contains(&"*") {
                findings.push(ContainerFinding {
                    id: Uuid::new_v4().to_string(),
                    scan_id: scan_id.to_string(),
                    image_id: None,
                    resource_id: Some(resource_id.to_string()),
                    finding_type: ContainerFindingType::PolicyViolation,
                    severity: ContainerFindingSeverity::Critical,
                    title: format!("Role '{}' has wildcard permissions", resource_name),
                    description: format!(
                        "Role '{}' grants overly broad permissions with wildcards.", resource_name
                    ),
                    cve_id: None,
                    cvss_score: None,
                    cwe_ids: vec!["CWE-250".to_string()],
                    package_name: None,
                    package_version: None,
                    fixed_version: None,
                    file_path: None,
                    line_number: None,
                    remediation: Some("Specify exact verbs and resources needed.".to_string()),
                    references: vec![],
                    status: FindingStatus::Open,
                    created_at: Utc::now(),
                });
            }

            // Check for secrets access
            if resources.contains(&"secrets") {
                findings.push(ContainerFinding {
                    id: Uuid::new_v4().to_string(),
                    scan_id: scan_id.to_string(),
                    image_id: None,
                    resource_id: Some(resource_id.to_string()),
                    finding_type: ContainerFindingType::PolicyViolation,
                    severity: ContainerFindingSeverity::High,
                    title: format!("Role '{}' can access secrets", resource_name),
                    description: format!(
                        "Role '{}' grants access to secrets. Verify this is necessary.", resource_name
                    ),
                    cve_id: None,
                    cvss_score: None,
                    cwe_ids: vec![],
                    package_name: None,
                    package_version: None,
                    fixed_version: None,
                    file_path: None,
                    line_number: None,
                    remediation: Some("Limit secret access to only required secrets using resourceNames.".to_string()),
                    references: vec![],
                    status: FindingStatus::Open,
                    created_at: Utc::now(),
                });
            }
        }
    }

    findings
}

/// Analyze RoleBinding/ClusterRoleBinding
fn analyze_role_binding(
    manifest: &serde_json::Value,
    resource_id: &str,
    scan_id: &str,
    resource_name: &str,
) -> Vec<ContainerFinding> {
    let mut findings = Vec::new();

    // Check if binding to cluster-admin
    if let Some(role_ref) = manifest.get("roleRef") {
        if let Some(role_name) = role_ref.get("name").and_then(|n| n.as_str()) {
            if role_name == "cluster-admin" {
                findings.push(ContainerFinding {
                    id: Uuid::new_v4().to_string(),
                    scan_id: scan_id.to_string(),
                    image_id: None,
                    resource_id: Some(resource_id.to_string()),
                    finding_type: ContainerFindingType::PolicyViolation,
                    severity: ContainerFindingSeverity::Critical,
                    title: format!("Binding '{}' grants cluster-admin", resource_name),
                    description: format!(
                        "The binding '{}' grants cluster-admin privileges, \
                        which provides full cluster access.", resource_name
                    ),
                    cve_id: None,
                    cvss_score: None,
                    cwe_ids: vec!["CWE-250".to_string()],
                    package_name: None,
                    package_version: None,
                    fixed_version: None,
                    file_path: None,
                    line_number: None,
                    remediation: Some("Use a more restrictive role with minimum required permissions.".to_string()),
                    references: vec![],
                    status: FindingStatus::Open,
                    created_at: Utc::now(),
                });
            }
        }
    }

    findings
}

/// Analyze NetworkPolicy
fn analyze_network_policy(
    manifest: &serde_json::Value,
    resource_id: &str,
    scan_id: &str,
    resource_name: &str,
) -> Vec<ContainerFinding> {
    let mut findings = Vec::new();

    // Check for allow-all policies
    if let Some(spec) = manifest.get("spec") {
        let ingress = spec.get("ingress").and_then(|i| i.as_array());
        let _egress = spec.get("egress").and_then(|e| e.as_array());

        if ingress.map(|i| i.is_empty()).unwrap_or(false) {
            findings.push(ContainerFinding {
                id: Uuid::new_v4().to_string(),
                scan_id: scan_id.to_string(),
                image_id: None,
                resource_id: Some(resource_id.to_string()),
                finding_type: ContainerFindingType::NetworkExposure,
                severity: ContainerFindingSeverity::High,
                title: format!("NetworkPolicy '{}' allows all ingress", resource_name),
                description: format!(
                    "The NetworkPolicy '{}' has an empty ingress array, allowing all ingress traffic.", resource_name
                ),
                cve_id: None,
                cvss_score: None,
                cwe_ids: vec![],
                package_name: None,
                package_version: None,
                fixed_version: None,
                file_path: None,
                line_number: None,
                remediation: Some("Define specific ingress rules to restrict traffic.".to_string()),
                references: vec![],
                status: FindingStatus::Open,
                created_at: Utc::now(),
            });
        }
    }

    findings
}

/// Analyze Secret
fn analyze_secret(
    manifest: &serde_json::Value,
    resource_id: &str,
    scan_id: &str,
    resource_name: &str,
) -> Vec<ContainerFinding> {
    let mut findings = Vec::new();

    // Check if secret type is Opaque (could contain sensitive data)
    if let Some(secret_type) = manifest.get("type").and_then(|t| t.as_str()) {
        if secret_type == "Opaque" {
            findings.push(ContainerFinding {
                id: Uuid::new_v4().to_string(),
                scan_id: scan_id.to_string(),
                image_id: None,
                resource_id: Some(resource_id.to_string()),
                finding_type: ContainerFindingType::SecretExposure,
                severity: ContainerFindingSeverity::Info,
                title: format!("Opaque Secret '{}' found in manifest", resource_name),
                description: format!(
                    "Secret '{}' is defined in the manifest. Secrets should be managed \
                    through a secrets management solution.", resource_name
                ),
                cve_id: None,
                cvss_score: None,
                cwe_ids: vec![],
                package_name: None,
                package_version: None,
                fixed_version: None,
                file_path: None,
                line_number: None,
                remediation: Some(
                    "Use external secrets management (Vault, AWS Secrets Manager, etc.) \
                    instead of storing secrets in manifests.".to_string()
                ),
                references: vec![],
                status: FindingStatus::Open,
                created_at: Utc::now(),
            });
        }
    }

    findings
}

/// Analyze ConfigMap
fn analyze_configmap(
    manifest: &serde_json::Value,
    resource_id: &str,
    scan_id: &str,
    resource_name: &str,
) -> Vec<ContainerFinding> {
    let mut findings = Vec::new();

    // Check for potential secrets in ConfigMap
    if let Some(data) = manifest.get("data").and_then(|d| d.as_object()) {
        let secret_patterns = ["password", "secret", "key", "token", "credential", "api_key"];
        for (key, _) in data {
            let key_lower = key.to_lowercase();
            if secret_patterns.iter().any(|p| key_lower.contains(p)) {
                findings.push(ContainerFinding {
                    id: Uuid::new_v4().to_string(),
                    scan_id: scan_id.to_string(),
                    image_id: None,
                    resource_id: Some(resource_id.to_string()),
                    finding_type: ContainerFindingType::SecretExposure,
                    severity: ContainerFindingSeverity::High,
                    title: format!("Potential secret in ConfigMap '{}'", resource_name),
                    description: format!(
                        "ConfigMap '{}' contains key '{}' which may be a secret. \
                        ConfigMaps are not encrypted at rest.", resource_name, key
                    ),
                    cve_id: None,
                    cvss_score: None,
                    cwe_ids: vec!["CWE-312".to_string()],
                    package_name: None,
                    package_version: None,
                    fixed_version: None,
                    file_path: None,
                    line_number: None,
                    remediation: Some("Move sensitive data to a Secret resource.".to_string()),
                    references: vec![],
                    status: FindingStatus::Open,
                    created_at: Utc::now(),
                });
                break;
            }
        }
    }

    findings
}

/// Generate demo manifest analysis results
async fn generate_demo_manifest_analysis() -> Result<K8sManifestAnalysis> {
    let scan_id = Uuid::new_v4().to_string();

    // Create demo resources
    let resources = vec![
        K8sResource {
            id: Uuid::new_v4().to_string(),
            scan_id: scan_id.clone(),
            resource_type: K8sResourceType::Deployment,
            api_version: "apps/v1".to_string(),
            name: "web-app".to_string(),
            namespace: Some("default".to_string()),
            labels: HashMap::from([("app".to_string(), "web".to_string())]),
            annotations: HashMap::new(),
            manifest: serde_json::json!({}),
            finding_count: 5,
            discovered_at: Utc::now(),
        },
        K8sResource {
            id: Uuid::new_v4().to_string(),
            scan_id: scan_id.clone(),
            resource_type: K8sResourceType::Service,
            api_version: "v1".to_string(),
            name: "web-service".to_string(),
            namespace: Some("default".to_string()),
            labels: HashMap::new(),
            annotations: HashMap::new(),
            manifest: serde_json::json!({}),
            finding_count: 1,
            discovered_at: Utc::now(),
        },
        K8sResource {
            id: Uuid::new_v4().to_string(),
            scan_id: scan_id.clone(),
            resource_type: K8sResourceType::ClusterRole,
            api_version: "rbac.authorization.k8s.io/v1".to_string(),
            name: "admin-role".to_string(),
            namespace: None,
            labels: HashMap::new(),
            annotations: HashMap::new(),
            manifest: serde_json::json!({}),
            finding_count: 2,
            discovered_at: Utc::now(),
        },
    ];

    // Create demo findings
    let findings = vec![
        ContainerFinding {
            id: Uuid::new_v4().to_string(),
            scan_id: scan_id.clone(),
            image_id: None,
            resource_id: Some(resources[0].id.clone()),
            finding_type: ContainerFindingType::PrivilegeEscalation,
            severity: ContainerFindingSeverity::Critical,
            title: "Container runs in privileged mode".to_string(),
            description: "Container 'app' in Deployment 'web-app' has privileged: true.".to_string(),
            cve_id: None,
            cvss_score: None,
            cwe_ids: vec!["CWE-250".to_string()],
            package_name: None,
            package_version: None,
            fixed_version: None,
            file_path: None,
            line_number: None,
            remediation: Some("Set privileged: false in the container's securityContext.".to_string()),
            references: vec![],
            status: FindingStatus::Open,
            created_at: Utc::now(),
        },
        ContainerFinding {
            id: Uuid::new_v4().to_string(),
            scan_id: scan_id.clone(),
            image_id: None,
            resource_id: Some(resources[0].id.clone()),
            finding_type: ContainerFindingType::Misconfiguration,
            severity: ContainerFindingSeverity::Medium,
            title: "Container may run as root".to_string(),
            description: "Container doesn't enforce runAsNonRoot: true.".to_string(),
            cve_id: None,
            cvss_score: None,
            cwe_ids: vec![],
            package_name: None,
            package_version: None,
            fixed_version: None,
            file_path: None,
            line_number: None,
            remediation: Some("Add runAsNonRoot: true to securityContext.".to_string()),
            references: vec![],
            status: FindingStatus::Open,
            created_at: Utc::now(),
        },
        ContainerFinding {
            id: Uuid::new_v4().to_string(),
            scan_id: scan_id.clone(),
            image_id: None,
            resource_id: Some(resources[2].id.clone()),
            finding_type: ContainerFindingType::PolicyViolation,
            severity: ContainerFindingSeverity::Critical,
            title: "Role has wildcard permissions".to_string(),
            description: "ClusterRole 'admin-role' grants '*' verbs on all resources.".to_string(),
            cve_id: None,
            cvss_score: None,
            cwe_ids: vec!["CWE-250".to_string()],
            package_name: None,
            package_version: None,
            fixed_version: None,
            file_path: None,
            line_number: None,
            remediation: Some("Specify exact verbs and resources needed.".to_string()),
            references: vec![],
            status: FindingStatus::Open,
            created_at: Utc::now(),
        },
    ];

    Ok(K8sManifestAnalysis {
        resources,
        findings,
        resource_counts: HashMap::from([
            ("deployment".to_string(), 1),
            ("service".to_string(), 1),
            ("clusterrole".to_string(), 1),
        ]),
        namespaces: vec!["default".to_string()],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_analyze_manifest_basic() {
        let manifest = r#"
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-app
  namespace: default
spec:
  template:
    spec:
      containers:
      - name: app
        image: nginx:latest
        securityContext:
          privileged: true
"#;

        let analysis = analyze_manifest(manifest, false).await.unwrap();

        assert_eq!(analysis.resources.len(), 1);
        assert!(!analysis.findings.is_empty());

        // Should have findings for privileged mode and latest tag
        let finding_titles: Vec<_> = analysis.findings.iter().map(|f| &f.title).collect();
        assert!(finding_titles.iter().any(|t| t.contains("privileged")));
    }

    #[tokio::test]
    async fn test_demo_analysis() {
        let analysis = analyze_manifest("", true).await.unwrap();

        assert!(!analysis.resources.is_empty());
        assert!(!analysis.findings.is_empty());
    }
}
