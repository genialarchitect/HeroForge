//! Kubernetes Cluster Security Scanner
//!
//! This module scans a live Kubernetes cluster for security issues:
//! - Node security (kubelet, API server configuration)
//! - Namespace policies
//! - RBAC configuration
//! - Network policies
//! - Pod security policies/standards
//! - Secrets management
//! - Resource quotas

use anyhow::Result;
use chrono::Utc;
use std::collections::HashMap;
use std::process::Command;
use uuid::Uuid;

use super::types::{
    ContainerFinding, ContainerFindingSeverity, ContainerFindingType, ContainerScanConfig,
    FindingStatus, K8sResource, K8sResourceType,
};

/// Scan a Kubernetes cluster for security issues (real implementation)
pub async fn scan_cluster(
    config: &ContainerScanConfig,
) -> Result<(Vec<K8sResource>, Vec<ContainerFinding>)> {
    let mut resources = Vec::new();
    let mut findings = Vec::new();
    let scan_id = Uuid::new_v4().to_string();

    // Set kubectl context if specified
    if let Some(context) = &config.k8s_context {
        let _ = Command::new("kubectl")
            .args(["config", "use-context", context])
            .output();
    }

    // Check if kubectl is available and cluster is accessible
    let cluster_check = Command::new("kubectl")
        .args(["cluster-info"])
        .output()?;

    if !cluster_check.status.success() {
        log::warn!("Unable to connect to Kubernetes cluster");
        return Ok((resources, findings));
    }

    // Determine namespace scope
    let namespaces = if let Some(ns) = &config.k8s_namespace {
        vec![ns.clone()]
    } else {
        get_all_namespaces()?
    };

    // Scan cluster-level security
    let (cluster_resources, cluster_findings) = scan_cluster_level(&scan_id).await?;
    resources.extend(cluster_resources);
    findings.extend(cluster_findings);

    // Scan each namespace
    for namespace in &namespaces {
        let (ns_resources, ns_findings) = scan_namespace(namespace, &scan_id).await?;
        resources.extend(ns_resources);
        findings.extend(ns_findings);
    }

    Ok((resources, findings))
}

/// Generate demo cluster scan results
pub async fn scan_cluster_demo(
    _config: &ContainerScanConfig,
) -> Result<(Vec<K8sResource>, Vec<ContainerFinding>)> {
    let scan_id = Uuid::new_v4().to_string();

    let resources = vec![
        K8sResource {
            id: Uuid::new_v4().to_string(),
            scan_id: scan_id.clone(),
            resource_type: K8sResourceType::Namespace,
            api_version: "v1".to_string(),
            name: "default".to_string(),
            namespace: None,
            labels: HashMap::new(),
            annotations: HashMap::new(),
            manifest: serde_json::json!({}),
            finding_count: 2,
            discovered_at: Utc::now(),
        },
        K8sResource {
            id: Uuid::new_v4().to_string(),
            scan_id: scan_id.clone(),
            resource_type: K8sResourceType::Namespace,
            api_version: "v1".to_string(),
            name: "kube-system".to_string(),
            namespace: None,
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
            name: "cluster-admin".to_string(),
            namespace: None,
            labels: HashMap::new(),
            annotations: HashMap::new(),
            manifest: serde_json::json!({}),
            finding_count: 1,
            discovered_at: Utc::now(),
        },
        K8sResource {
            id: Uuid::new_v4().to_string(),
            scan_id: scan_id.clone(),
            resource_type: K8sResourceType::Pod,
            api_version: "v1".to_string(),
            name: "etcd-master".to_string(),
            namespace: Some("kube-system".to_string()),
            labels: HashMap::from([("component".to_string(), "etcd".to_string())]),
            annotations: HashMap::new(),
            manifest: serde_json::json!({}),
            finding_count: 1,
            discovered_at: Utc::now(),
        },
        K8sResource {
            id: Uuid::new_v4().to_string(),
            scan_id: scan_id.clone(),
            resource_type: K8sResourceType::ServiceAccount,
            api_version: "v1".to_string(),
            name: "default".to_string(),
            namespace: Some("default".to_string()),
            labels: HashMap::new(),
            annotations: HashMap::new(),
            manifest: serde_json::json!({}),
            finding_count: 1,
            discovered_at: Utc::now(),
        },
    ];

    let findings = vec![
        ContainerFinding {
            id: Uuid::new_v4().to_string(),
            scan_id: scan_id.clone(),
            image_id: None,
            resource_id: Some(resources[0].id.clone()),
            finding_type: ContainerFindingType::Misconfiguration,
            severity: ContainerFindingSeverity::High,
            title: "Default namespace has no NetworkPolicy".to_string(),
            description: "The 'default' namespace has no NetworkPolicy defined, allowing \
                unrestricted pod-to-pod communication.".to_string(),
            cve_id: None,
            cvss_score: None,
            cwe_ids: vec![],
            package_name: None,
            package_version: None,
            fixed_version: None,
            file_path: None,
            line_number: None,
            remediation: Some(
                "Create a default-deny NetworkPolicy and explicitly allow required traffic.".to_string()
            ),
            references: vec![
                "https://kubernetes.io/docs/concepts/services-networking/network-policies/".to_string(),
            ],
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
            title: "Default namespace has no ResourceQuota".to_string(),
            description: "The 'default' namespace has no ResourceQuota, allowing pods to \
                consume unlimited cluster resources.".to_string(),
            cve_id: None,
            cvss_score: None,
            cwe_ids: vec!["CWE-770".to_string()],
            package_name: None,
            package_version: None,
            fixed_version: None,
            file_path: None,
            line_number: None,
            remediation: Some(
                "Create ResourceQuota to limit CPU, memory, and object counts.".to_string()
            ),
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
            severity: ContainerFindingSeverity::High,
            title: "Multiple ClusterRoleBindings to cluster-admin".to_string(),
            description: "Found 5 ClusterRoleBindings granting cluster-admin privileges. \
                This role provides full cluster access.".to_string(),
            cve_id: None,
            cvss_score: None,
            cwe_ids: vec!["CWE-250".to_string()],
            package_name: None,
            package_version: None,
            fixed_version: None,
            file_path: None,
            line_number: None,
            remediation: Some(
                "Review and remove unnecessary cluster-admin bindings. Use more restrictive roles.".to_string()
            ),
            references: vec![
                "https://kubernetes.io/docs/reference/access-authn-authz/rbac/".to_string(),
            ],
            status: FindingStatus::Open,
            created_at: Utc::now(),
        },
        ContainerFinding {
            id: Uuid::new_v4().to_string(),
            scan_id: scan_id.clone(),
            image_id: None,
            resource_id: Some(resources[3].id.clone()),
            finding_type: ContainerFindingType::Misconfiguration,
            severity: ContainerFindingSeverity::High,
            title: "etcd encryption at rest not enabled".to_string(),
            description: "The etcd database storing Kubernetes secrets is not configured \
                with encryption at rest. Secrets are stored in plain text.".to_string(),
            cve_id: None,
            cvss_score: None,
            cwe_ids: vec!["CWE-311".to_string()],
            package_name: None,
            package_version: None,
            fixed_version: None,
            file_path: None,
            line_number: None,
            remediation: Some(
                "Configure etcd encryption using EncryptionConfiguration. \
                Use AES-GCM or secretbox for encryption.".to_string()
            ),
            references: vec![
                "https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/".to_string(),
            ],
            status: FindingStatus::Open,
            created_at: Utc::now(),
        },
        ContainerFinding {
            id: Uuid::new_v4().to_string(),
            scan_id: scan_id.clone(),
            image_id: None,
            resource_id: Some(resources[4].id.clone()),
            finding_type: ContainerFindingType::Misconfiguration,
            severity: ContainerFindingSeverity::Medium,
            title: "Default ServiceAccount has auto-mounted token".to_string(),
            description: "The default ServiceAccount in 'default' namespace automatically \
                mounts API credentials to all pods.".to_string(),
            cve_id: None,
            cvss_score: None,
            cwe_ids: vec![],
            package_name: None,
            package_version: None,
            fixed_version: None,
            file_path: None,
            line_number: None,
            remediation: Some(
                "Set automountServiceAccountToken: false on the default ServiceAccount.".to_string()
            ),
            references: vec![],
            status: FindingStatus::Open,
            created_at: Utc::now(),
        },
        ContainerFinding {
            id: Uuid::new_v4().to_string(),
            scan_id: scan_id.clone(),
            image_id: None,
            resource_id: None,
            finding_type: ContainerFindingType::Misconfiguration,
            severity: ContainerFindingSeverity::Critical,
            title: "Kubernetes API server allows anonymous access".to_string(),
            description: "The API server is configured to allow anonymous requests, which \
                could be exploited by attackers with network access.".to_string(),
            cve_id: None,
            cvss_score: None,
            cwe_ids: vec!["CWE-287".to_string()],
            package_name: None,
            package_version: None,
            fixed_version: None,
            file_path: None,
            line_number: None,
            remediation: Some(
                "Disable anonymous access by setting --anonymous-auth=false on the API server.".to_string()
            ),
            references: vec![
                "https://kubernetes.io/docs/reference/access-authn-authz/authentication/".to_string(),
            ],
            status: FindingStatus::Open,
            created_at: Utc::now(),
        },
        ContainerFinding {
            id: Uuid::new_v4().to_string(),
            scan_id: scan_id.clone(),
            image_id: None,
            resource_id: None,
            finding_type: ContainerFindingType::Misconfiguration,
            severity: ContainerFindingSeverity::High,
            title: "No Pod Security Standard enforcement".to_string(),
            description: "The cluster does not enforce Pod Security Standards. Pods can \
                run with privileged containers, host networking, etc.".to_string(),
            cve_id: None,
            cvss_score: None,
            cwe_ids: vec![],
            package_name: None,
            package_version: None,
            fixed_version: None,
            file_path: None,
            line_number: None,
            remediation: Some(
                "Enable Pod Security Admission with 'restricted' or 'baseline' profile at namespace level.".to_string()
            ),
            references: vec![
                "https://kubernetes.io/docs/concepts/security/pod-security-standards/".to_string(),
            ],
            status: FindingStatus::Open,
            created_at: Utc::now(),
        },
        ContainerFinding {
            id: Uuid::new_v4().to_string(),
            scan_id: scan_id.clone(),
            image_id: None,
            resource_id: None,
            finding_type: ContainerFindingType::Misconfiguration,
            severity: ContainerFindingSeverity::Medium,
            title: "Kubelet read-only port enabled".to_string(),
            description: "The kubelet read-only port (10255) is enabled on cluster nodes, \
                exposing pod and node information without authentication.".to_string(),
            cve_id: None,
            cvss_score: None,
            cwe_ids: vec!["CWE-200".to_string()],
            package_name: None,
            package_version: None,
            fixed_version: None,
            file_path: None,
            line_number: None,
            remediation: Some(
                "Disable the read-only port by setting --read-only-port=0 on kubelet.".to_string()
            ),
            references: vec![],
            status: FindingStatus::Open,
            created_at: Utc::now(),
        },
        ContainerFinding {
            id: Uuid::new_v4().to_string(),
            scan_id: scan_id.clone(),
            image_id: None,
            resource_id: None,
            finding_type: ContainerFindingType::Outdated,
            severity: ContainerFindingSeverity::Medium,
            title: "Kubernetes version is outdated".to_string(),
            description: "The cluster is running Kubernetes v1.24.5 which is no longer \
                receiving security updates. Current stable version is v1.28.x.".to_string(),
            cve_id: None,
            cvss_score: None,
            cwe_ids: vec!["CWE-1104".to_string()],
            package_name: Some("kubernetes".to_string()),
            package_version: Some("1.24.5".to_string()),
            fixed_version: Some("1.28.0".to_string()),
            file_path: None,
            line_number: None,
            remediation: Some(
                "Upgrade to a supported Kubernetes version (1.26+).".to_string()
            ),
            references: vec![
                "https://kubernetes.io/releases/".to_string(),
            ],
            status: FindingStatus::Open,
            created_at: Utc::now(),
        },
        ContainerFinding {
            id: Uuid::new_v4().to_string(),
            scan_id: scan_id.clone(),
            image_id: None,
            resource_id: None,
            finding_type: ContainerFindingType::Misconfiguration,
            severity: ContainerFindingSeverity::Low,
            title: "Audit logging not configured".to_string(),
            description: "Kubernetes API server audit logging is not enabled. \
                Security events are not being recorded.".to_string(),
            cve_id: None,
            cvss_score: None,
            cwe_ids: vec!["CWE-778".to_string()],
            package_name: None,
            package_version: None,
            fixed_version: None,
            file_path: None,
            line_number: None,
            remediation: Some(
                "Configure audit logging with an audit policy file.".to_string()
            ),
            references: vec![
                "https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/".to_string(),
            ],
            status: FindingStatus::Open,
            created_at: Utc::now(),
        },
    ];

    Ok((resources, findings))
}

/// Get all namespaces in the cluster
fn get_all_namespaces() -> Result<Vec<String>> {
    let output = Command::new("kubectl")
        .args(["get", "namespaces", "-o", "jsonpath={.items[*].metadata.name}"])
        .output()?;

    if !output.status.success() {
        return Ok(vec!["default".to_string()]);
    }

    let namespaces: Vec<String> = std::str::from_utf8(&output.stdout)?
        .split_whitespace()
        .map(String::from)
        .collect();

    Ok(namespaces)
}

/// Scan cluster-level resources
async fn scan_cluster_level(
    scan_id: &str,
) -> Result<(Vec<K8sResource>, Vec<ContainerFinding>)> {
    let resources = Vec::new();
    let mut findings = Vec::new();

    // Check cluster version
    let version_output = Command::new("kubectl")
        .args(["version", "--output=json"])
        .output()?;

    if version_output.status.success() {
        if let Ok(version_info) = serde_json::from_slice::<serde_json::Value>(&version_output.stdout) {
            if let Some(server_version) = version_info.get("serverVersion") {
                let git_version = server_version.get("gitVersion")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");

                // Check if version is outdated (simple check)
                if git_version.starts_with("v1.24") || git_version.starts_with("v1.25") {
                    findings.push(ContainerFinding {
                        id: Uuid::new_v4().to_string(),
                        scan_id: scan_id.to_string(),
                        image_id: None,
                        resource_id: None,
                        finding_type: ContainerFindingType::Outdated,
                        severity: ContainerFindingSeverity::Medium,
                        title: "Kubernetes version may be outdated".to_string(),
                        description: format!(
                            "Cluster is running {}. Consider upgrading to a newer version.", git_version
                        ),
                        cve_id: None,
                        cvss_score: None,
                        cwe_ids: vec!["CWE-1104".to_string()],
                        package_name: Some("kubernetes".to_string()),
                        package_version: Some(git_version.to_string()),
                        fixed_version: None,
                        file_path: None,
                        line_number: None,
                        remediation: Some("Upgrade to a supported Kubernetes version.".to_string()),
                        references: vec![],
                        status: FindingStatus::Open,
                        created_at: Utc::now(),
                    });
                }
            }
        }
    }

    // Check for cluster-admin bindings
    let crb_output = Command::new("kubectl")
        .args(["get", "clusterrolebindings", "-o", "json"])
        .output()?;

    if crb_output.status.success() {
        if let Ok(crb_list) = serde_json::from_slice::<serde_json::Value>(&crb_output.stdout) {
            if let Some(items) = crb_list.get("items").and_then(|i| i.as_array()) {
                let admin_bindings: Vec<_> = items.iter()
                    .filter(|item| {
                        item.get("roleRef")
                            .and_then(|r| r.get("name"))
                            .and_then(|n| n.as_str())
                            .map(|n| n == "cluster-admin")
                            .unwrap_or(false)
                    })
                    .collect();

                if admin_bindings.len() > 2 {
                    findings.push(ContainerFinding {
                        id: Uuid::new_v4().to_string(),
                        scan_id: scan_id.to_string(),
                        image_id: None,
                        resource_id: None,
                        finding_type: ContainerFindingType::PolicyViolation,
                        severity: ContainerFindingSeverity::High,
                        title: "Multiple cluster-admin bindings found".to_string(),
                        description: format!(
                            "Found {} ClusterRoleBindings granting cluster-admin. \
                            This should be limited.", admin_bindings.len()
                        ),
                        cve_id: None,
                        cvss_score: None,
                        cwe_ids: vec!["CWE-250".to_string()],
                        package_name: None,
                        package_version: None,
                        fixed_version: None,
                        file_path: None,
                        line_number: None,
                        remediation: Some("Review and remove unnecessary cluster-admin bindings.".to_string()),
                        references: vec![],
                        status: FindingStatus::Open,
                        created_at: Utc::now(),
                    });
                }
            }
        }
    }

    Ok((resources, findings))
}

/// Scan a namespace for security issues
async fn scan_namespace(
    namespace: &str,
    scan_id: &str,
) -> Result<(Vec<K8sResource>, Vec<ContainerFinding>)> {
    let mut resources = Vec::new();
    let mut findings = Vec::new();

    let resource_id = Uuid::new_v4().to_string();

    // Create namespace resource
    resources.push(K8sResource {
        id: resource_id.clone(),
        scan_id: scan_id.to_string(),
        resource_type: K8sResourceType::Namespace,
        api_version: "v1".to_string(),
        name: namespace.to_string(),
        namespace: None,
        labels: HashMap::new(),
        annotations: HashMap::new(),
        manifest: serde_json::json!({}),
        finding_count: 0,
        discovered_at: Utc::now(),
    });

    // Check for NetworkPolicies
    let np_output = Command::new("kubectl")
        .args(["get", "networkpolicies", "-n", namespace, "-o", "json"])
        .output()?;

    if np_output.status.success() {
        if let Ok(np_list) = serde_json::from_slice::<serde_json::Value>(&np_output.stdout) {
            let items = np_list.get("items").and_then(|i| i.as_array());
            if items.map(|i| i.is_empty()).unwrap_or(true) {
                findings.push(ContainerFinding {
                    id: Uuid::new_v4().to_string(),
                    scan_id: scan_id.to_string(),
                    image_id: None,
                    resource_id: Some(resource_id.clone()),
                    finding_type: ContainerFindingType::Misconfiguration,
                    severity: ContainerFindingSeverity::High,
                    title: format!("Namespace '{}' has no NetworkPolicy", namespace),
                    description: format!(
                        "The namespace '{}' has no NetworkPolicies, allowing unrestricted network access.", namespace
                    ),
                    cve_id: None,
                    cvss_score: None,
                    cwe_ids: vec![],
                    package_name: None,
                    package_version: None,
                    fixed_version: None,
                    file_path: None,
                    line_number: None,
                    remediation: Some("Create a default-deny NetworkPolicy.".to_string()),
                    references: vec![],
                    status: FindingStatus::Open,
                    created_at: Utc::now(),
                });
            }
        }
    }

    // Check for ResourceQuotas
    let rq_output = Command::new("kubectl")
        .args(["get", "resourcequotas", "-n", namespace, "-o", "json"])
        .output()?;

    if rq_output.status.success() {
        if let Ok(rq_list) = serde_json::from_slice::<serde_json::Value>(&rq_output.stdout) {
            let items = rq_list.get("items").and_then(|i| i.as_array());
            if items.map(|i| i.is_empty()).unwrap_or(true) {
                findings.push(ContainerFinding {
                    id: Uuid::new_v4().to_string(),
                    scan_id: scan_id.to_string(),
                    image_id: None,
                    resource_id: Some(resource_id.clone()),
                    finding_type: ContainerFindingType::Misconfiguration,
                    severity: ContainerFindingSeverity::Medium,
                    title: format!("Namespace '{}' has no ResourceQuota", namespace),
                    description: format!(
                        "The namespace '{}' has no ResourceQuota to limit resource consumption.", namespace
                    ),
                    cve_id: None,
                    cvss_score: None,
                    cwe_ids: vec!["CWE-770".to_string()],
                    package_name: None,
                    package_version: None,
                    fixed_version: None,
                    file_path: None,
                    line_number: None,
                    remediation: Some("Create ResourceQuota to limit resources.".to_string()),
                    references: vec![],
                    status: FindingStatus::Open,
                    created_at: Utc::now(),
                });
            }
        }
    }

    // Check default ServiceAccount
    let sa_output = Command::new("kubectl")
        .args(["get", "serviceaccount", "default", "-n", namespace, "-o", "json"])
        .output()?;

    if sa_output.status.success() {
        if let Ok(sa) = serde_json::from_slice::<serde_json::Value>(&sa_output.stdout) {
            let automount = sa.get("automountServiceAccountToken")
                .and_then(|a| a.as_bool())
                .unwrap_or(true);

            if automount {
                findings.push(ContainerFinding {
                    id: Uuid::new_v4().to_string(),
                    scan_id: scan_id.to_string(),
                    image_id: None,
                    resource_id: Some(resource_id.clone()),
                    finding_type: ContainerFindingType::Misconfiguration,
                    severity: ContainerFindingSeverity::Low,
                    title: format!("Default SA in '{}' auto-mounts token", namespace),
                    description: "The default ServiceAccount automatically mounts API credentials.".to_string(),
                    cve_id: None,
                    cvss_score: None,
                    cwe_ids: vec![],
                    package_name: None,
                    package_version: None,
                    fixed_version: None,
                    file_path: None,
                    line_number: None,
                    remediation: Some("Set automountServiceAccountToken: false on default SA.".to_string()),
                    references: vec![],
                    status: FindingStatus::Open,
                    created_at: Utc::now(),
                });
            }
        }
    }

    // Update finding count on namespace resource
    if let Some(ns_resource) = resources.first_mut() {
        ns_resource.finding_count = findings.len() as i32;
    }

    Ok((resources, findings))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_scan_cluster_demo() {
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

        let (resources, findings) = scan_cluster_demo(&config).await.unwrap();

        assert!(!resources.is_empty());
        assert!(!findings.is_empty());

        // Check for various types of findings
        let has_network_policy_finding = findings.iter()
            .any(|f| f.title.contains("NetworkPolicy"));
        assert!(has_network_policy_finding);
    }
}
