//! CIS Kubernetes Benchmark Scanner
//!
//! Implements checks based on the CIS Kubernetes Benchmark v1.8 covering:
//! - Control Plane Components (1.x)
//! - etcd (2.x)
//! - Control Plane Configuration (3.x)
//! - Worker Nodes (4.x)
//! - Policies (5.x)

use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// CIS Benchmark control status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CisControlStatus {
    Pass,
    Fail,
    Warn,
    Info,
    Manual,
    NotApplicable,
}

impl std::fmt::Display for CisControlStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pass => write!(f, "PASS"),
            Self::Fail => write!(f, "FAIL"),
            Self::Warn => write!(f, "WARN"),
            Self::Info => write!(f, "INFO"),
            Self::Manual => write!(f, "MANUAL"),
            Self::NotApplicable => write!(f, "N/A"),
        }
    }
}

/// CIS Benchmark severity level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CisSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

/// CIS Benchmark section
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CisSection {
    ControlPlaneNode,
    Etcd,
    ControlPlaneConfiguration,
    WorkerNodes,
    Policies,
}

impl std::fmt::Display for CisSection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ControlPlaneNode => write!(f, "1 - Control Plane Components"),
            Self::Etcd => write!(f, "2 - etcd"),
            Self::ControlPlaneConfiguration => write!(f, "3 - Control Plane Configuration"),
            Self::WorkerNodes => write!(f, "4 - Worker Nodes"),
            Self::Policies => write!(f, "5 - Policies"),
        }
    }
}

/// CIS Benchmark control definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CisControl {
    pub id: String,
    pub title: String,
    pub description: String,
    pub section: CisSection,
    pub severity: CisSeverity,
    pub scored: bool,
    pub remediation: String,
    pub references: Vec<String>,
}

/// CIS Benchmark finding (result of a control check)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CisFinding {
    pub id: String,
    pub scan_id: String,
    pub control_id: String,
    pub control_title: String,
    pub section: String,
    pub status: CisControlStatus,
    pub severity: CisSeverity,
    pub actual_value: String,
    pub expected_value: String,
    pub remediation: String,
    pub references: Vec<String>,
    pub resource_name: Option<String>,
    pub namespace: Option<String>,
    pub created_at: chrono::DateTime<Utc>,
}

/// CIS Benchmark scan results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CisBenchmarkResults {
    pub scan_id: String,
    pub findings: Vec<CisFinding>,
    pub summary: CisSummary,
    pub scanned_at: chrono::DateTime<Utc>,
}

/// Summary of CIS benchmark results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CisSummary {
    pub total_controls: i32,
    pub passed: i32,
    pub failed: i32,
    pub warnings: i32,
    pub manual: i32,
    pub not_applicable: i32,
    pub score_percentage: f64,
    pub by_section: HashMap<String, SectionSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionSummary {
    pub total: i32,
    pub passed: i32,
    pub failed: i32,
}

/// CIS Kubernetes Benchmark Scanner
pub struct CisBenchmarkScanner {
    controls: Vec<CisControl>,
}

impl CisBenchmarkScanner {
    pub fn new() -> Self {
        Self {
            controls: Self::load_controls(),
        }
    }

    /// Load all CIS benchmark controls
    fn load_controls() -> Vec<CisControl> {
        let mut controls = Vec::new();

        // Section 1: Control Plane Components
        controls.extend(Self::control_plane_controls());

        // Section 2: etcd
        controls.extend(Self::etcd_controls());

        // Section 3: Control Plane Configuration
        controls.extend(Self::control_plane_config_controls());

        // Section 4: Worker Nodes
        controls.extend(Self::worker_node_controls());

        // Section 5: Policies
        controls.extend(Self::policy_controls());

        controls
    }

    /// Section 1: Control Plane Components
    fn control_plane_controls() -> Vec<CisControl> {
        vec![
            CisControl {
                id: "1.1.1".to_string(),
                title: "Ensure that the API server pod specification file permissions are set to 600 or more restrictive".to_string(),
                description: "Ensure that the API server pod specification file has permissions of 600 or more restrictive.".to_string(),
                section: CisSection::ControlPlaneNode,
                severity: CisSeverity::High,
                scored: true,
                remediation: "Run: chmod 600 /etc/kubernetes/manifests/kube-apiserver.yaml".to_string(),
                references: vec!["https://kubernetes.io/docs/setup/best-practices/cluster-large/".to_string()],
            },
            CisControl {
                id: "1.1.2".to_string(),
                title: "Ensure that the API server pod specification file ownership is set to root:root".to_string(),
                description: "Ensure that the API server pod specification file ownership is set to root:root.".to_string(),
                section: CisSection::ControlPlaneNode,
                severity: CisSeverity::High,
                scored: true,
                remediation: "Run: chown root:root /etc/kubernetes/manifests/kube-apiserver.yaml".to_string(),
                references: vec![],
            },
            CisControl {
                id: "1.2.1".to_string(),
                title: "Ensure that the --anonymous-auth argument is set to false".to_string(),
                description: "Disable anonymous requests to the API server.".to_string(),
                section: CisSection::ControlPlaneNode,
                severity: CisSeverity::Critical,
                scored: true,
                remediation: "Edit /etc/kubernetes/manifests/kube-apiserver.yaml and set --anonymous-auth=false".to_string(),
                references: vec!["https://kubernetes.io/docs/reference/access-authn-authz/authentication/".to_string()],
            },
            CisControl {
                id: "1.2.2".to_string(),
                title: "Ensure that the --token-auth-file parameter is not set".to_string(),
                description: "Do not use token based authentication.".to_string(),
                section: CisSection::ControlPlaneNode,
                severity: CisSeverity::High,
                scored: true,
                remediation: "Remove --token-auth-file argument from kube-apiserver.".to_string(),
                references: vec![],
            },
            CisControl {
                id: "1.2.3".to_string(),
                title: "Ensure that the --DenyServiceExternalIPs is set".to_string(),
                description: "Deny external IPs on Services.".to_string(),
                section: CisSection::ControlPlaneNode,
                severity: CisSeverity::Medium,
                scored: false,
                remediation: "Enable DenyServiceExternalIPs admission controller.".to_string(),
                references: vec![],
            },
            CisControl {
                id: "1.2.4".to_string(),
                title: "Ensure that the --kubelet-client-certificate and --kubelet-client-key arguments are set".to_string(),
                description: "Enable certificate based kubelet authentication.".to_string(),
                section: CisSection::ControlPlaneNode,
                severity: CisSeverity::High,
                scored: true,
                remediation: "Set --kubelet-client-certificate and --kubelet-client-key in kube-apiserver.".to_string(),
                references: vec![],
            },
            CisControl {
                id: "1.2.5".to_string(),
                title: "Ensure that the --kubelet-certificate-authority argument is set".to_string(),
                description: "Verify kubelet's certificate before establishing connection.".to_string(),
                section: CisSection::ControlPlaneNode,
                severity: CisSeverity::High,
                scored: true,
                remediation: "Set --kubelet-certificate-authority in kube-apiserver.".to_string(),
                references: vec![],
            },
            CisControl {
                id: "1.2.6".to_string(),
                title: "Ensure that the --authorization-mode argument is not set to AlwaysAllow".to_string(),
                description: "Do not allow all requests.".to_string(),
                section: CisSection::ControlPlaneNode,
                severity: CisSeverity::Critical,
                scored: true,
                remediation: "Set --authorization-mode to RBAC,Node.".to_string(),
                references: vec!["https://kubernetes.io/docs/reference/access-authn-authz/authorization/".to_string()],
            },
            CisControl {
                id: "1.2.7".to_string(),
                title: "Ensure that the --authorization-mode argument includes Node".to_string(),
                description: "Restrict kubelet nodes to only be able to read objects that are bound to them.".to_string(),
                section: CisSection::ControlPlaneNode,
                severity: CisSeverity::High,
                scored: true,
                remediation: "Set --authorization-mode to include Node.".to_string(),
                references: vec![],
            },
            CisControl {
                id: "1.2.8".to_string(),
                title: "Ensure that the --authorization-mode argument includes RBAC".to_string(),
                description: "Turn on Role Based Access Control.".to_string(),
                section: CisSection::ControlPlaneNode,
                severity: CisSeverity::Critical,
                scored: true,
                remediation: "Set --authorization-mode to include RBAC.".to_string(),
                references: vec![],
            },
            CisControl {
                id: "1.2.9".to_string(),
                title: "Ensure that the admission control plugin EventRateLimit is set".to_string(),
                description: "Limit the rate at which the API server accepts requests.".to_string(),
                section: CisSection::ControlPlaneNode,
                severity: CisSeverity::Medium,
                scored: false,
                remediation: "Enable EventRateLimit admission controller.".to_string(),
                references: vec![],
            },
            CisControl {
                id: "1.2.10".to_string(),
                title: "Ensure that the admission control plugin AlwaysAdmit is not set".to_string(),
                description: "Do not allow all requests.".to_string(),
                section: CisSection::ControlPlaneNode,
                severity: CisSeverity::Critical,
                scored: true,
                remediation: "Remove AlwaysAdmit from --enable-admission-plugins.".to_string(),
                references: vec![],
            },
            CisControl {
                id: "1.2.11".to_string(),
                title: "Ensure that the admission control plugin AlwaysPullImages is set".to_string(),
                description: "Always pull images.".to_string(),
                section: CisSection::ControlPlaneNode,
                severity: CisSeverity::Medium,
                scored: false,
                remediation: "Enable AlwaysPullImages admission controller.".to_string(),
                references: vec![],
            },
            CisControl {
                id: "1.2.12".to_string(),
                title: "Ensure that the admission control plugin SecurityContextDeny is set if PodSecurityPolicy is not used".to_string(),
                description: "Reject pods that have security context set.".to_string(),
                section: CisSection::ControlPlaneNode,
                severity: CisSeverity::Medium,
                scored: false,
                remediation: "Enable SecurityContextDeny or use PodSecurityPolicy/Pod Security Admission.".to_string(),
                references: vec![],
            },
            CisControl {
                id: "1.2.13".to_string(),
                title: "Ensure that the admission control plugin ServiceAccount is set".to_string(),
                description: "Automate service account provisioning.".to_string(),
                section: CisSection::ControlPlaneNode,
                severity: CisSeverity::High,
                scored: true,
                remediation: "Enable ServiceAccount admission controller.".to_string(),
                references: vec![],
            },
            CisControl {
                id: "1.2.14".to_string(),
                title: "Ensure that the admission control plugin NamespaceLifecycle is set".to_string(),
                description: "Reject pods in terminating namespaces.".to_string(),
                section: CisSection::ControlPlaneNode,
                severity: CisSeverity::High,
                scored: true,
                remediation: "Enable NamespaceLifecycle admission controller.".to_string(),
                references: vec![],
            },
            CisControl {
                id: "1.2.15".to_string(),
                title: "Ensure that the admission control plugin NodeRestriction is set".to_string(),
                description: "Limit node and pod modifications.".to_string(),
                section: CisSection::ControlPlaneNode,
                severity: CisSeverity::High,
                scored: true,
                remediation: "Enable NodeRestriction admission controller.".to_string(),
                references: vec![],
            },
            CisControl {
                id: "1.2.16".to_string(),
                title: "Ensure that the --secure-port argument is not set to 0".to_string(),
                description: "Do not disable the secure port.".to_string(),
                section: CisSection::ControlPlaneNode,
                severity: CisSeverity::Critical,
                scored: true,
                remediation: "Set --secure-port to a non-zero value (default 6443).".to_string(),
                references: vec![],
            },
            CisControl {
                id: "1.2.17".to_string(),
                title: "Ensure that the --profiling argument is set to false".to_string(),
                description: "Disable profiling.".to_string(),
                section: CisSection::ControlPlaneNode,
                severity: CisSeverity::Medium,
                scored: true,
                remediation: "Set --profiling=false in kube-apiserver.".to_string(),
                references: vec![],
            },
            CisControl {
                id: "1.2.18".to_string(),
                title: "Ensure that the --audit-log-path argument is set".to_string(),
                description: "Enable auditing.".to_string(),
                section: CisSection::ControlPlaneNode,
                severity: CisSeverity::High,
                scored: true,
                remediation: "Set --audit-log-path to a suitable path.".to_string(),
                references: vec!["https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/".to_string()],
            },
            CisControl {
                id: "1.2.19".to_string(),
                title: "Ensure that the --audit-log-maxage argument is set to 30 or as appropriate".to_string(),
                description: "Retain audit logs for specified number of days.".to_string(),
                section: CisSection::ControlPlaneNode,
                severity: CisSeverity::Medium,
                scored: true,
                remediation: "Set --audit-log-maxage=30 or higher.".to_string(),
                references: vec![],
            },
            CisControl {
                id: "1.2.20".to_string(),
                title: "Ensure that the --audit-log-maxbackup argument is set to 10 or as appropriate".to_string(),
                description: "Retain 10 or more old audit log files.".to_string(),
                section: CisSection::ControlPlaneNode,
                severity: CisSeverity::Medium,
                scored: true,
                remediation: "Set --audit-log-maxbackup=10 or higher.".to_string(),
                references: vec![],
            },
            CisControl {
                id: "1.2.21".to_string(),
                title: "Ensure that the --audit-log-maxsize argument is set to 100 or as appropriate".to_string(),
                description: "Rotate log files at appropriate size.".to_string(),
                section: CisSection::ControlPlaneNode,
                severity: CisSeverity::Medium,
                scored: true,
                remediation: "Set --audit-log-maxsize=100 or higher.".to_string(),
                references: vec![],
            },
        ]
    }

    /// Section 2: etcd controls
    fn etcd_controls() -> Vec<CisControl> {
        vec![
            CisControl {
                id: "2.1".to_string(),
                title: "Ensure that the --cert-file and --key-file arguments are set as appropriate".to_string(),
                description: "Configure TLS encryption for the etcd service.".to_string(),
                section: CisSection::Etcd,
                severity: CisSeverity::Critical,
                scored: true,
                remediation: "Set --cert-file and --key-file to the certificate and key file for etcd.".to_string(),
                references: vec!["https://etcd.io/docs/latest/op-guide/security/".to_string()],
            },
            CisControl {
                id: "2.2".to_string(),
                title: "Ensure that the --client-cert-auth argument is set to true".to_string(),
                description: "Enable client certificate authentication.".to_string(),
                section: CisSection::Etcd,
                severity: CisSeverity::Critical,
                scored: true,
                remediation: "Set --client-cert-auth=true in etcd configuration.".to_string(),
                references: vec![],
            },
            CisControl {
                id: "2.3".to_string(),
                title: "Ensure that the --auto-tls argument is not set to true".to_string(),
                description: "Do not use self-signed certificates for TLS.".to_string(),
                section: CisSection::Etcd,
                severity: CisSeverity::High,
                scored: true,
                remediation: "Set --auto-tls=false or remove the argument.".to_string(),
                references: vec![],
            },
            CisControl {
                id: "2.4".to_string(),
                title: "Ensure that the --peer-cert-file and --peer-key-file arguments are set as appropriate".to_string(),
                description: "Configure peer TLS encryption for etcd.".to_string(),
                section: CisSection::Etcd,
                severity: CisSeverity::High,
                scored: true,
                remediation: "Set --peer-cert-file and --peer-key-file appropriately.".to_string(),
                references: vec![],
            },
            CisControl {
                id: "2.5".to_string(),
                title: "Ensure that the --peer-client-cert-auth argument is set to true".to_string(),
                description: "Enable peer client certificate authentication.".to_string(),
                section: CisSection::Etcd,
                severity: CisSeverity::High,
                scored: true,
                remediation: "Set --peer-client-cert-auth=true.".to_string(),
                references: vec![],
            },
            CisControl {
                id: "2.6".to_string(),
                title: "Ensure that the --peer-auto-tls argument is not set to true".to_string(),
                description: "Do not use self-signed certificates for peer TLS.".to_string(),
                section: CisSection::Etcd,
                severity: CisSeverity::High,
                scored: true,
                remediation: "Set --peer-auto-tls=false.".to_string(),
                references: vec![],
            },
            CisControl {
                id: "2.7".to_string(),
                title: "Ensure that a unique Certificate Authority is used for etcd".to_string(),
                description: "Use unique CA for etcd to prevent unauthorized access.".to_string(),
                section: CisSection::Etcd,
                severity: CisSeverity::Medium,
                scored: false,
                remediation: "Create a separate CA for etcd.".to_string(),
                references: vec![],
            },
        ]
    }

    /// Section 3: Control Plane Configuration
    fn control_plane_config_controls() -> Vec<CisControl> {
        vec![
            CisControl {
                id: "3.1.1".to_string(),
                title: "Client certificate authentication should not be used for users".to_string(),
                description: "Prefer external authentication systems over client certificates.".to_string(),
                section: CisSection::ControlPlaneConfiguration,
                severity: CisSeverity::Medium,
                scored: false,
                remediation: "Configure OIDC or webhook token authentication.".to_string(),
                references: vec!["https://kubernetes.io/docs/reference/access-authn-authz/authentication/".to_string()],
            },
            CisControl {
                id: "3.2.1".to_string(),
                title: "Ensure that a minimal audit policy is created".to_string(),
                description: "Enable Kubernetes auditing with appropriate policy.".to_string(),
                section: CisSection::ControlPlaneConfiguration,
                severity: CisSeverity::High,
                scored: true,
                remediation: "Create an audit-policy.yaml and set --audit-policy-file.".to_string(),
                references: vec!["https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/".to_string()],
            },
            CisControl {
                id: "3.2.2".to_string(),
                title: "Ensure that the audit policy covers key security concerns".to_string(),
                description: "Audit policy should cover authentication, authorization, secrets access.".to_string(),
                section: CisSection::ControlPlaneConfiguration,
                severity: CisSeverity::Medium,
                scored: false,
                remediation: "Review and enhance audit policy to cover security events.".to_string(),
                references: vec![],
            },
        ]
    }

    /// Section 4: Worker Node controls
    fn worker_node_controls() -> Vec<CisControl> {
        vec![
            CisControl {
                id: "4.1.1".to_string(),
                title: "Ensure that the kubelet service file permissions are set to 600 or more restrictive".to_string(),
                description: "Restrict kubelet service file permissions.".to_string(),
                section: CisSection::WorkerNodes,
                severity: CisSeverity::High,
                scored: true,
                remediation: "Run: chmod 600 /etc/systemd/system/kubelet.service.d/10-kubeadm.conf".to_string(),
                references: vec![],
            },
            CisControl {
                id: "4.1.2".to_string(),
                title: "Ensure that the kubelet service file ownership is set to root:root".to_string(),
                description: "Set correct ownership for kubelet service file.".to_string(),
                section: CisSection::WorkerNodes,
                severity: CisSeverity::High,
                scored: true,
                remediation: "Run: chown root:root /etc/systemd/system/kubelet.service.d/10-kubeadm.conf".to_string(),
                references: vec![],
            },
            CisControl {
                id: "4.2.1".to_string(),
                title: "Ensure that the --anonymous-auth argument is set to false".to_string(),
                description: "Disable anonymous authentication to the kubelet.".to_string(),
                section: CisSection::WorkerNodes,
                severity: CisSeverity::Critical,
                scored: true,
                remediation: "Set --anonymous-auth=false in kubelet configuration.".to_string(),
                references: vec![],
            },
            CisControl {
                id: "4.2.2".to_string(),
                title: "Ensure that the --authorization-mode argument is not set to AlwaysAllow".to_string(),
                description: "Use Webhook authorization for kubelet.".to_string(),
                section: CisSection::WorkerNodes,
                severity: CisSeverity::Critical,
                scored: true,
                remediation: "Set --authorization-mode=Webhook.".to_string(),
                references: vec![],
            },
            CisControl {
                id: "4.2.3".to_string(),
                title: "Ensure that the --client-ca-file argument is set as appropriate".to_string(),
                description: "Enable kubelet certificate authentication.".to_string(),
                section: CisSection::WorkerNodes,
                severity: CisSeverity::High,
                scored: true,
                remediation: "Set --client-ca-file to the CA certificate file.".to_string(),
                references: vec![],
            },
            CisControl {
                id: "4.2.4".to_string(),
                title: "Verify that the --read-only-port argument is set to 0".to_string(),
                description: "Disable the read-only port.".to_string(),
                section: CisSection::WorkerNodes,
                severity: CisSeverity::High,
                scored: true,
                remediation: "Set --read-only-port=0.".to_string(),
                references: vec![],
            },
            CisControl {
                id: "4.2.5".to_string(),
                title: "Ensure that the --streaming-connection-idle-timeout argument is not set to 0".to_string(),
                description: "Set appropriate idle timeout for streaming connections.".to_string(),
                section: CisSection::WorkerNodes,
                severity: CisSeverity::Medium,
                scored: true,
                remediation: "Set --streaming-connection-idle-timeout to a non-zero value.".to_string(),
                references: vec![],
            },
            CisControl {
                id: "4.2.6".to_string(),
                title: "Ensure that the --make-iptables-util-chains argument is set to true".to_string(),
                description: "Allow kubelet to manage iptables.".to_string(),
                section: CisSection::WorkerNodes,
                severity: CisSeverity::Medium,
                scored: true,
                remediation: "Set --make-iptables-util-chains=true.".to_string(),
                references: vec![],
            },
            CisControl {
                id: "4.2.7".to_string(),
                title: "Ensure that the --hostname-override argument is not set".to_string(),
                description: "Do not override the hostname.".to_string(),
                section: CisSection::WorkerNodes,
                severity: CisSeverity::Low,
                scored: false,
                remediation: "Remove --hostname-override argument.".to_string(),
                references: vec![],
            },
            CisControl {
                id: "4.2.8".to_string(),
                title: "Ensure that the eventRecordQPS argument is set to a level which ensures appropriate event capture".to_string(),
                description: "Configure appropriate event capture rate.".to_string(),
                section: CisSection::WorkerNodes,
                severity: CisSeverity::Low,
                scored: false,
                remediation: "Set eventRecordQPS appropriately (default 50).".to_string(),
                references: vec![],
            },
            CisControl {
                id: "4.2.9".to_string(),
                title: "Ensure that the --tls-cert-file and --tls-private-key-file arguments are set as appropriate".to_string(),
                description: "Configure TLS for kubelet.".to_string(),
                section: CisSection::WorkerNodes,
                severity: CisSeverity::High,
                scored: true,
                remediation: "Set --tls-cert-file and --tls-private-key-file.".to_string(),
                references: vec![],
            },
            CisControl {
                id: "4.2.10".to_string(),
                title: "Ensure that the --rotate-certificates argument is not set to false".to_string(),
                description: "Enable certificate rotation.".to_string(),
                section: CisSection::WorkerNodes,
                severity: CisSeverity::High,
                scored: true,
                remediation: "Set --rotate-certificates=true or remove the argument.".to_string(),
                references: vec![],
            },
            CisControl {
                id: "4.2.11".to_string(),
                title: "Verify that the RotateKubeletServerCertificate argument is set to true".to_string(),
                description: "Enable server certificate rotation.".to_string(),
                section: CisSection::WorkerNodes,
                severity: CisSeverity::High,
                scored: true,
                remediation: "Set RotateKubeletServerCertificate=true in kubelet config.".to_string(),
                references: vec![],
            },
            CisControl {
                id: "4.2.12".to_string(),
                title: "Ensure that the Kubelet only makes use of Strong Cryptographic Ciphers".to_string(),
                description: "Use only strong TLS ciphers.".to_string(),
                section: CisSection::WorkerNodes,
                severity: CisSeverity::Medium,
                scored: false,
                remediation: "Configure --tls-cipher-suites with strong ciphers.".to_string(),
                references: vec![],
            },
        ]
    }

    /// Section 5: Policies
    fn policy_controls() -> Vec<CisControl> {
        vec![
            CisControl {
                id: "5.1.1".to_string(),
                title: "Ensure that the cluster-admin role is only used where required".to_string(),
                description: "Limit use of cluster-admin role.".to_string(),
                section: CisSection::Policies,
                severity: CisSeverity::High,
                scored: false,
                remediation: "Review cluster-admin bindings and remove unnecessary ones.".to_string(),
                references: vec!["https://kubernetes.io/docs/reference/access-authn-authz/rbac/".to_string()],
            },
            CisControl {
                id: "5.1.2".to_string(),
                title: "Minimize access to secrets".to_string(),
                description: "Limit access to Kubernetes secrets.".to_string(),
                section: CisSection::Policies,
                severity: CisSeverity::High,
                scored: false,
                remediation: "Review RBAC policies granting access to secrets.".to_string(),
                references: vec![],
            },
            CisControl {
                id: "5.1.3".to_string(),
                title: "Minimize wildcard use in Roles and ClusterRoles".to_string(),
                description: "Avoid using wildcards in RBAC.".to_string(),
                section: CisSection::Policies,
                severity: CisSeverity::High,
                scored: false,
                remediation: "Replace wildcards with specific resources and verbs.".to_string(),
                references: vec![],
            },
            CisControl {
                id: "5.1.4".to_string(),
                title: "Minimize access to create pods".to_string(),
                description: "Limit pod creation privileges.".to_string(),
                section: CisSection::Policies,
                severity: CisSeverity::High,
                scored: false,
                remediation: "Review and limit pod creation permissions.".to_string(),
                references: vec![],
            },
            CisControl {
                id: "5.1.5".to_string(),
                title: "Ensure that default service accounts are not actively used".to_string(),
                description: "Do not use default service accounts.".to_string(),
                section: CisSection::Policies,
                severity: CisSeverity::Medium,
                scored: false,
                remediation: "Create and use specific service accounts for each workload.".to_string(),
                references: vec![],
            },
            CisControl {
                id: "5.1.6".to_string(),
                title: "Ensure that Service Account Tokens are only mounted where necessary".to_string(),
                description: "Disable automatic service account token mounting.".to_string(),
                section: CisSection::Policies,
                severity: CisSeverity::Medium,
                scored: false,
                remediation: "Set automountServiceAccountToken: false where not needed.".to_string(),
                references: vec![],
            },
            CisControl {
                id: "5.1.7".to_string(),
                title: "Avoid use of system:masters group".to_string(),
                description: "Do not bind to the system:masters group.".to_string(),
                section: CisSection::Policies,
                severity: CisSeverity::Critical,
                scored: false,
                remediation: "Remove bindings to system:masters group.".to_string(),
                references: vec![],
            },
            CisControl {
                id: "5.1.8".to_string(),
                title: "Limit use of the Bind, Impersonate and Escalate permissions in the cluster".to_string(),
                description: "Restrict dangerous RBAC permissions.".to_string(),
                section: CisSection::Policies,
                severity: CisSeverity::Critical,
                scored: false,
                remediation: "Review and limit bind, impersonate, and escalate permissions.".to_string(),
                references: vec![],
            },
            CisControl {
                id: "5.2.1".to_string(),
                title: "Ensure that the cluster has at least one active policy control mechanism in place".to_string(),
                description: "Use Pod Security Admission or third-party policy engine.".to_string(),
                section: CisSection::Policies,
                severity: CisSeverity::High,
                scored: false,
                remediation: "Enable Pod Security Admission or install OPA Gatekeeper/Kyverno.".to_string(),
                references: vec!["https://kubernetes.io/docs/concepts/security/pod-security-admission/".to_string()],
            },
            CisControl {
                id: "5.2.2".to_string(),
                title: "Minimize the admission of privileged containers".to_string(),
                description: "Prevent privileged container execution.".to_string(),
                section: CisSection::Policies,
                severity: CisSeverity::Critical,
                scored: false,
                remediation: "Apply 'restricted' Pod Security Standard.".to_string(),
                references: vec![],
            },
            CisControl {
                id: "5.2.3".to_string(),
                title: "Minimize the admission of containers wishing to share the host process ID namespace".to_string(),
                description: "Prevent hostPID usage.".to_string(),
                section: CisSection::Policies,
                severity: CisSeverity::High,
                scored: false,
                remediation: "Apply policies to deny hostPID.".to_string(),
                references: vec![],
            },
            CisControl {
                id: "5.2.4".to_string(),
                title: "Minimize the admission of containers wishing to share the host IPC namespace".to_string(),
                description: "Prevent hostIPC usage.".to_string(),
                section: CisSection::Policies,
                severity: CisSeverity::High,
                scored: false,
                remediation: "Apply policies to deny hostIPC.".to_string(),
                references: vec![],
            },
            CisControl {
                id: "5.2.5".to_string(),
                title: "Minimize the admission of containers wishing to share the host network namespace".to_string(),
                description: "Prevent hostNetwork usage.".to_string(),
                section: CisSection::Policies,
                severity: CisSeverity::High,
                scored: false,
                remediation: "Apply policies to deny hostNetwork.".to_string(),
                references: vec![],
            },
            CisControl {
                id: "5.2.6".to_string(),
                title: "Minimize the admission of containers with allowPrivilegeEscalation".to_string(),
                description: "Prevent privilege escalation.".to_string(),
                section: CisSection::Policies,
                severity: CisSeverity::High,
                scored: false,
                remediation: "Enforce allowPrivilegeEscalation: false.".to_string(),
                references: vec![],
            },
            CisControl {
                id: "5.2.7".to_string(),
                title: "Minimize the admission of root containers".to_string(),
                description: "Prevent containers running as root.".to_string(),
                section: CisSection::Policies,
                severity: CisSeverity::High,
                scored: false,
                remediation: "Enforce runAsNonRoot: true.".to_string(),
                references: vec![],
            },
            CisControl {
                id: "5.2.8".to_string(),
                title: "Minimize the admission of containers with the NET_RAW capability".to_string(),
                description: "Prevent NET_RAW capability.".to_string(),
                section: CisSection::Policies,
                severity: CisSeverity::Medium,
                scored: false,
                remediation: "Drop NET_RAW capability.".to_string(),
                references: vec![],
            },
            CisControl {
                id: "5.2.9".to_string(),
                title: "Minimize the admission of containers with added capabilities".to_string(),
                description: "Drop all capabilities by default.".to_string(),
                section: CisSection::Policies,
                severity: CisSeverity::Medium,
                scored: false,
                remediation: "Drop ALL capabilities and add only required ones.".to_string(),
                references: vec![],
            },
            CisControl {
                id: "5.2.10".to_string(),
                title: "Minimize the admission of containers with capabilities assigned".to_string(),
                description: "Prefer dropping all capabilities.".to_string(),
                section: CisSection::Policies,
                severity: CisSeverity::Low,
                scored: false,
                remediation: "Use capabilities.drop: [ALL].".to_string(),
                references: vec![],
            },
            CisControl {
                id: "5.2.11".to_string(),
                title: "Minimize the admission of Windows HostProcess containers".to_string(),
                description: "Prevent Windows HostProcess containers.".to_string(),
                section: CisSection::Policies,
                severity: CisSeverity::High,
                scored: false,
                remediation: "Deny windowsOptions.hostProcess.".to_string(),
                references: vec![],
            },
            CisControl {
                id: "5.2.12".to_string(),
                title: "Minimize the admission of HostPath volumes".to_string(),
                description: "Restrict hostPath volume usage.".to_string(),
                section: CisSection::Policies,
                severity: CisSeverity::Medium,
                scored: false,
                remediation: "Deny or limit hostPath volumes.".to_string(),
                references: vec![],
            },
            CisControl {
                id: "5.2.13".to_string(),
                title: "Minimize the admission of containers which use HostPorts".to_string(),
                description: "Restrict hostPort usage.".to_string(),
                section: CisSection::Policies,
                severity: CisSeverity::Medium,
                scored: false,
                remediation: "Deny or limit hostPort usage.".to_string(),
                references: vec![],
            },
            CisControl {
                id: "5.3.1".to_string(),
                title: "Ensure that the CNI in use supports NetworkPolicies".to_string(),
                description: "Use a CNI that supports NetworkPolicy.".to_string(),
                section: CisSection::Policies,
                severity: CisSeverity::High,
                scored: false,
                remediation: "Install a NetworkPolicy-capable CNI (Calico, Cilium, etc.).".to_string(),
                references: vec!["https://kubernetes.io/docs/concepts/services-networking/network-policies/".to_string()],
            },
            CisControl {
                id: "5.3.2".to_string(),
                title: "Ensure that all Namespaces have NetworkPolicies defined".to_string(),
                description: "Define NetworkPolicies for all namespaces.".to_string(),
                section: CisSection::Policies,
                severity: CisSeverity::High,
                scored: false,
                remediation: "Create default-deny NetworkPolicies in all namespaces.".to_string(),
                references: vec![],
            },
            CisControl {
                id: "5.4.1".to_string(),
                title: "Prefer using Secrets as files over Secrets as environment variables".to_string(),
                description: "Mount secrets as files, not env vars.".to_string(),
                section: CisSection::Policies,
                severity: CisSeverity::Medium,
                scored: false,
                remediation: "Use volumeMounts for secrets instead of envFrom.".to_string(),
                references: vec![],
            },
            CisControl {
                id: "5.4.2".to_string(),
                title: "Consider external secret storage".to_string(),
                description: "Use external secrets management.".to_string(),
                section: CisSection::Policies,
                severity: CisSeverity::Medium,
                scored: false,
                remediation: "Integrate with Vault, AWS Secrets Manager, etc.".to_string(),
                references: vec![],
            },
            CisControl {
                id: "5.5.1".to_string(),
                title: "Configure Image Provenance using ImagePolicyWebhook admission controller".to_string(),
                description: "Verify image signatures and sources.".to_string(),
                section: CisSection::Policies,
                severity: CisSeverity::Medium,
                scored: false,
                remediation: "Enable ImagePolicyWebhook or use Sigstore/cosign.".to_string(),
                references: vec![],
            },
            CisControl {
                id: "5.7.1".to_string(),
                title: "Create administrative boundaries between resources using namespaces".to_string(),
                description: "Use namespaces for resource isolation.".to_string(),
                section: CisSection::Policies,
                severity: CisSeverity::Medium,
                scored: false,
                remediation: "Create namespaces per team/application/environment.".to_string(),
                references: vec![],
            },
            CisControl {
                id: "5.7.2".to_string(),
                title: "Ensure that the seccomp profile is set to docker/default in your Pod definitions".to_string(),
                description: "Enable seccomp profiles.".to_string(),
                section: CisSection::Policies,
                severity: CisSeverity::Medium,
                scored: false,
                remediation: "Set seccompProfile.type: RuntimeDefault.".to_string(),
                references: vec![],
            },
            CisControl {
                id: "5.7.3".to_string(),
                title: "Apply SecurityContext to your Pods and Containers".to_string(),
                description: "Define security contexts for all pods.".to_string(),
                section: CisSection::Policies,
                severity: CisSeverity::High,
                scored: false,
                remediation: "Add securityContext to all pod and container specs.".to_string(),
                references: vec![],
            },
            CisControl {
                id: "5.7.4".to_string(),
                title: "The default namespace should not be used".to_string(),
                description: "Avoid using the default namespace.".to_string(),
                section: CisSection::Policies,
                severity: CisSeverity::Medium,
                scored: false,
                remediation: "Deploy workloads to dedicated namespaces.".to_string(),
                references: vec![],
            },
        ]
    }

    /// Get all controls
    pub fn get_controls(&self) -> &[CisControl] {
        &self.controls
    }

    /// Get controls by section
    pub fn get_controls_by_section(&self, section: &CisSection) -> Vec<&CisControl> {
        self.controls.iter().filter(|c| &c.section == section).collect()
    }

    /// Analyze Kubernetes manifests against CIS benchmark
    pub fn analyze_manifests(
        &self,
        manifests: &[serde_json::Value],
        scan_id: &str,
    ) -> CisBenchmarkResults {
        let mut findings = Vec::new();

        for manifest in manifests {
            findings.extend(self.check_manifest_controls(manifest, scan_id));
        }

        let summary = self.calculate_summary(&findings);

        CisBenchmarkResults {
            scan_id: scan_id.to_string(),
            findings,
            summary,
            scanned_at: Utc::now(),
        }
    }

    /// Check manifest against applicable controls
    fn check_manifest_controls(
        &self,
        manifest: &serde_json::Value,
        scan_id: &str,
    ) -> Vec<CisFinding> {
        let mut findings = Vec::new();
        let kind = manifest.get("kind").and_then(|k| k.as_str()).unwrap_or("");
        let name = manifest.get("metadata")
            .and_then(|m| m.get("name"))
            .and_then(|n| n.as_str())
            .unwrap_or("unknown");
        let namespace = manifest.get("metadata")
            .and_then(|m| m.get("namespace"))
            .and_then(|n| n.as_str())
            .map(String::from);

        // Check Pod-related controls
        if ["Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"].contains(&kind) {
            let pod_spec = if kind == "Pod" {
                manifest.get("spec")
            } else {
                manifest.get("spec")
                    .and_then(|s| s.get("template"))
                    .and_then(|t| t.get("spec"))
            };

            if let Some(spec) = pod_spec {
                findings.extend(self.check_pod_security_controls(spec, scan_id, name, &namespace));
            }
        }

        // Check RBAC controls
        if kind == "Role" || kind == "ClusterRole" {
            findings.extend(self.check_rbac_controls(manifest, scan_id, name, &namespace));
        }

        if kind == "RoleBinding" || kind == "ClusterRoleBinding" {
            findings.extend(self.check_rbac_binding_controls(manifest, scan_id, name, &namespace));
        }

        // Check NetworkPolicy controls
        if kind == "NetworkPolicy" {
            findings.extend(self.check_network_policy_controls(manifest, scan_id, name, &namespace));
        }

        findings
    }

    /// Check pod security controls (Section 5.2)
    fn check_pod_security_controls(
        &self,
        spec: &serde_json::Value,
        scan_id: &str,
        resource_name: &str,
        namespace: &Option<String>,
    ) -> Vec<CisFinding> {
        let mut findings = Vec::new();

        // 5.2.2 - Check privileged containers
        if let Some(containers) = spec.get("containers").and_then(|c| c.as_array()) {
            for container in containers {
                let container_name = container.get("name").and_then(|n| n.as_str()).unwrap_or("unknown");

                if let Some(sc) = container.get("securityContext") {
                    // Check privileged
                    if sc.get("privileged").and_then(|p| p.as_bool()).unwrap_or(false) {
                        findings.push(CisFinding {
                            id: Uuid::new_v4().to_string(),
                            scan_id: scan_id.to_string(),
                            control_id: "5.2.2".to_string(),
                            control_title: "Minimize the admission of privileged containers".to_string(),
                            section: "5 - Policies".to_string(),
                            status: CisControlStatus::Fail,
                            severity: CisSeverity::Critical,
                            actual_value: format!("Container '{}' has privileged: true", container_name),
                            expected_value: "privileged: false or not set".to_string(),
                            remediation: "Set privileged: false in securityContext".to_string(),
                            references: vec![],
                            resource_name: Some(resource_name.to_string()),
                            namespace: namespace.clone(),
                            created_at: Utc::now(),
                        });
                    }

                    // 5.2.6 - Check allowPrivilegeEscalation
                    if sc.get("allowPrivilegeEscalation").and_then(|a| a.as_bool()).unwrap_or(true) {
                        findings.push(CisFinding {
                            id: Uuid::new_v4().to_string(),
                            scan_id: scan_id.to_string(),
                            control_id: "5.2.6".to_string(),
                            control_title: "Minimize the admission of containers with allowPrivilegeEscalation".to_string(),
                            section: "5 - Policies".to_string(),
                            status: CisControlStatus::Fail,
                            severity: CisSeverity::High,
                            actual_value: format!("Container '{}' allows privilege escalation", container_name),
                            expected_value: "allowPrivilegeEscalation: false".to_string(),
                            remediation: "Set allowPrivilegeEscalation: false".to_string(),
                            references: vec![],
                            resource_name: Some(resource_name.to_string()),
                            namespace: namespace.clone(),
                            created_at: Utc::now(),
                        });
                    }

                    // 5.2.7 - Check runAsNonRoot
                    let run_as_non_root = sc.get("runAsNonRoot").and_then(|r| r.as_bool()).unwrap_or(false);
                    let run_as_user = sc.get("runAsUser").and_then(|u| u.as_i64()).unwrap_or(0);

                    if !run_as_non_root && run_as_user == 0 {
                        findings.push(CisFinding {
                            id: Uuid::new_v4().to_string(),
                            scan_id: scan_id.to_string(),
                            control_id: "5.2.7".to_string(),
                            control_title: "Minimize the admission of root containers".to_string(),
                            section: "5 - Policies".to_string(),
                            status: CisControlStatus::Fail,
                            severity: CisSeverity::High,
                            actual_value: format!("Container '{}' may run as root", container_name),
                            expected_value: "runAsNonRoot: true or runAsUser != 0".to_string(),
                            remediation: "Set runAsNonRoot: true and runAsUser to non-zero".to_string(),
                            references: vec![],
                            resource_name: Some(resource_name.to_string()),
                            namespace: namespace.clone(),
                            created_at: Utc::now(),
                        });
                    }

                    // 5.2.9 - Check capabilities
                    if let Some(caps) = sc.get("capabilities") {
                        if caps.get("drop").is_none() {
                            findings.push(CisFinding {
                                id: Uuid::new_v4().to_string(),
                                scan_id: scan_id.to_string(),
                                control_id: "5.2.9".to_string(),
                                control_title: "Minimize the admission of containers with added capabilities".to_string(),
                                section: "5 - Policies".to_string(),
                                status: CisControlStatus::Warn,
                                severity: CisSeverity::Medium,
                                actual_value: format!("Container '{}' doesn't drop capabilities", container_name),
                                expected_value: "capabilities.drop: [ALL]".to_string(),
                                remediation: "Add capabilities.drop: [ALL] and only add required capabilities".to_string(),
                                references: vec![],
                                resource_name: Some(resource_name.to_string()),
                                namespace: namespace.clone(),
                                created_at: Utc::now(),
                            });
                        }
                    }
                } else {
                    // No security context
                    findings.push(CisFinding {
                        id: Uuid::new_v4().to_string(),
                        scan_id: scan_id.to_string(),
                        control_id: "5.7.3".to_string(),
                        control_title: "Apply SecurityContext to your Pods and Containers".to_string(),
                        section: "5 - Policies".to_string(),
                        status: CisControlStatus::Fail,
                        severity: CisSeverity::High,
                        actual_value: format!("Container '{}' has no securityContext", container_name),
                        expected_value: "securityContext defined".to_string(),
                        remediation: "Add securityContext with appropriate settings".to_string(),
                        references: vec![],
                        resource_name: Some(resource_name.to_string()),
                        namespace: namespace.clone(),
                        created_at: Utc::now(),
                    });
                }
            }
        }

        // 5.2.3 - Check hostPID
        if spec.get("hostPID").and_then(|h| h.as_bool()).unwrap_or(false) {
            findings.push(CisFinding {
                id: Uuid::new_v4().to_string(),
                scan_id: scan_id.to_string(),
                control_id: "5.2.3".to_string(),
                control_title: "Minimize the admission of containers wishing to share the host process ID namespace".to_string(),
                section: "5 - Policies".to_string(),
                status: CisControlStatus::Fail,
                severity: CisSeverity::High,
                actual_value: "hostPID: true".to_string(),
                expected_value: "hostPID: false or not set".to_string(),
                remediation: "Set hostPID: false".to_string(),
                references: vec![],
                resource_name: Some(resource_name.to_string()),
                namespace: namespace.clone(),
                created_at: Utc::now(),
            });
        }

        // 5.2.4 - Check hostIPC
        if spec.get("hostIPC").and_then(|h| h.as_bool()).unwrap_or(false) {
            findings.push(CisFinding {
                id: Uuid::new_v4().to_string(),
                scan_id: scan_id.to_string(),
                control_id: "5.2.4".to_string(),
                control_title: "Minimize the admission of containers wishing to share the host IPC namespace".to_string(),
                section: "5 - Policies".to_string(),
                status: CisControlStatus::Fail,
                severity: CisSeverity::High,
                actual_value: "hostIPC: true".to_string(),
                expected_value: "hostIPC: false or not set".to_string(),
                remediation: "Set hostIPC: false".to_string(),
                references: vec![],
                resource_name: Some(resource_name.to_string()),
                namespace: namespace.clone(),
                created_at: Utc::now(),
            });
        }

        // 5.2.5 - Check hostNetwork
        if spec.get("hostNetwork").and_then(|h| h.as_bool()).unwrap_or(false) {
            findings.push(CisFinding {
                id: Uuid::new_v4().to_string(),
                scan_id: scan_id.to_string(),
                control_id: "5.2.5".to_string(),
                control_title: "Minimize the admission of containers wishing to share the host network namespace".to_string(),
                section: "5 - Policies".to_string(),
                status: CisControlStatus::Fail,
                severity: CisSeverity::High,
                actual_value: "hostNetwork: true".to_string(),
                expected_value: "hostNetwork: false or not set".to_string(),
                remediation: "Set hostNetwork: false".to_string(),
                references: vec![],
                resource_name: Some(resource_name.to_string()),
                namespace: namespace.clone(),
                created_at: Utc::now(),
            });
        }

        // 5.1.6 - Check automountServiceAccountToken
        if spec.get("automountServiceAccountToken").and_then(|a| a.as_bool()).unwrap_or(true) {
            findings.push(CisFinding {
                id: Uuid::new_v4().to_string(),
                scan_id: scan_id.to_string(),
                control_id: "5.1.6".to_string(),
                control_title: "Ensure that Service Account Tokens are only mounted where necessary".to_string(),
                section: "5 - Policies".to_string(),
                status: CisControlStatus::Warn,
                severity: CisSeverity::Medium,
                actual_value: "automountServiceAccountToken: true or not set".to_string(),
                expected_value: "automountServiceAccountToken: false (if API access not needed)".to_string(),
                remediation: "Set automountServiceAccountToken: false if API access is not required".to_string(),
                references: vec![],
                resource_name: Some(resource_name.to_string()),
                namespace: namespace.clone(),
                created_at: Utc::now(),
            });
        }

        // 5.7.2 - Check seccomp profile
        let has_seccomp = spec.get("securityContext")
            .and_then(|sc| sc.get("seccompProfile"))
            .is_some();

        if !has_seccomp {
            findings.push(CisFinding {
                id: Uuid::new_v4().to_string(),
                scan_id: scan_id.to_string(),
                control_id: "5.7.2".to_string(),
                control_title: "Ensure that the seccomp profile is set".to_string(),
                section: "5 - Policies".to_string(),
                status: CisControlStatus::Warn,
                severity: CisSeverity::Medium,
                actual_value: "No seccomp profile defined".to_string(),
                expected_value: "seccompProfile.type: RuntimeDefault".to_string(),
                remediation: "Add securityContext.seccompProfile.type: RuntimeDefault".to_string(),
                references: vec![],
                resource_name: Some(resource_name.to_string()),
                namespace: namespace.clone(),
                created_at: Utc::now(),
            });
        }

        findings
    }

    /// Check RBAC controls (Section 5.1)
    fn check_rbac_controls(
        &self,
        manifest: &serde_json::Value,
        scan_id: &str,
        resource_name: &str,
        namespace: &Option<String>,
    ) -> Vec<CisFinding> {
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

                let api_groups: Vec<&str> = rule.get("apiGroups")
                    .and_then(|a| a.as_array())
                    .map(|arr| arr.iter().filter_map(|a| a.as_str()).collect())
                    .unwrap_or_default();

                // 5.1.3 - Check wildcards
                if verbs.contains(&"*") || resources.contains(&"*") || api_groups.contains(&"*") {
                    findings.push(CisFinding {
                        id: Uuid::new_v4().to_string(),
                        scan_id: scan_id.to_string(),
                        control_id: "5.1.3".to_string(),
                        control_title: "Minimize wildcard use in Roles and ClusterRoles".to_string(),
                        section: "5 - Policies".to_string(),
                        status: CisControlStatus::Fail,
                        severity: CisSeverity::High,
                        actual_value: "Wildcards used in role definition".to_string(),
                        expected_value: "No wildcards in verbs, resources, or apiGroups".to_string(),
                        remediation: "Replace wildcards with specific resources and verbs".to_string(),
                        references: vec![],
                        resource_name: Some(resource_name.to_string()),
                        namespace: namespace.clone(),
                        created_at: Utc::now(),
                    });
                }

                // 5.1.2 - Check secrets access
                if resources.contains(&"secrets") {
                    findings.push(CisFinding {
                        id: Uuid::new_v4().to_string(),
                        scan_id: scan_id.to_string(),
                        control_id: "5.1.2".to_string(),
                        control_title: "Minimize access to secrets".to_string(),
                        section: "5 - Policies".to_string(),
                        status: CisControlStatus::Warn,
                        severity: CisSeverity::High,
                        actual_value: "Role grants access to secrets".to_string(),
                        expected_value: "Secrets access should be minimized".to_string(),
                        remediation: "Review and limit access to secrets".to_string(),
                        references: vec![],
                        resource_name: Some(resource_name.to_string()),
                        namespace: namespace.clone(),
                        created_at: Utc::now(),
                    });
                }

                // 5.1.4 - Check pod creation
                if resources.contains(&"pods") && (verbs.contains(&"create") || verbs.contains(&"*")) {
                    findings.push(CisFinding {
                        id: Uuid::new_v4().to_string(),
                        scan_id: scan_id.to_string(),
                        control_id: "5.1.4".to_string(),
                        control_title: "Minimize access to create pods".to_string(),
                        section: "5 - Policies".to_string(),
                        status: CisControlStatus::Warn,
                        severity: CisSeverity::High,
                        actual_value: "Role can create pods".to_string(),
                        expected_value: "Pod creation should be limited".to_string(),
                        remediation: "Review pod creation permissions".to_string(),
                        references: vec![],
                        resource_name: Some(resource_name.to_string()),
                        namespace: namespace.clone(),
                        created_at: Utc::now(),
                    });
                }

                // 5.1.8 - Check escalation permissions
                let escalation_verbs = ["bind", "escalate", "impersonate"];
                for verb in &escalation_verbs {
                    if verbs.contains(verb) {
                        findings.push(CisFinding {
                            id: Uuid::new_v4().to_string(),
                            scan_id: scan_id.to_string(),
                            control_id: "5.1.8".to_string(),
                            control_title: "Limit use of the Bind, Impersonate and Escalate permissions".to_string(),
                            section: "5 - Policies".to_string(),
                            status: CisControlStatus::Fail,
                            severity: CisSeverity::Critical,
                            actual_value: format!("Role has '{}' permission", verb),
                            expected_value: "No bind, impersonate, or escalate permissions".to_string(),
                            remediation: format!("Remove '{}' permission", verb),
                            references: vec![],
                            resource_name: Some(resource_name.to_string()),
                            namespace: namespace.clone(),
                            created_at: Utc::now(),
                        });
                    }
                }
            }
        }

        findings
    }

    /// Check RBAC binding controls
    fn check_rbac_binding_controls(
        &self,
        manifest: &serde_json::Value,
        scan_id: &str,
        resource_name: &str,
        namespace: &Option<String>,
    ) -> Vec<CisFinding> {
        let mut findings = Vec::new();

        if let Some(role_ref) = manifest.get("roleRef") {
            let role_name = role_ref.get("name").and_then(|n| n.as_str()).unwrap_or("");

            // 5.1.1 - Check cluster-admin usage
            if role_name == "cluster-admin" {
                findings.push(CisFinding {
                    id: Uuid::new_v4().to_string(),
                    scan_id: scan_id.to_string(),
                    control_id: "5.1.1".to_string(),
                    control_title: "Ensure that the cluster-admin role is only used where required".to_string(),
                    section: "5 - Policies".to_string(),
                    status: CisControlStatus::Warn,
                    severity: CisSeverity::High,
                    actual_value: "Binding grants cluster-admin".to_string(),
                    expected_value: "cluster-admin should be limited".to_string(),
                    remediation: "Review if cluster-admin is necessary".to_string(),
                    references: vec![],
                    resource_name: Some(resource_name.to_string()),
                    namespace: namespace.clone(),
                    created_at: Utc::now(),
                });
            }
        }

        // 5.1.7 - Check system:masters group
        if let Some(subjects) = manifest.get("subjects").and_then(|s| s.as_array()) {
            for subject in subjects {
                if subject.get("kind").and_then(|k| k.as_str()) == Some("Group") {
                    if subject.get("name").and_then(|n| n.as_str()) == Some("system:masters") {
                        findings.push(CisFinding {
                            id: Uuid::new_v4().to_string(),
                            scan_id: scan_id.to_string(),
                            control_id: "5.1.7".to_string(),
                            control_title: "Avoid use of system:masters group".to_string(),
                            section: "5 - Policies".to_string(),
                            status: CisControlStatus::Fail,
                            severity: CisSeverity::Critical,
                            actual_value: "Binding to system:masters group".to_string(),
                            expected_value: "No bindings to system:masters".to_string(),
                            remediation: "Remove binding to system:masters group".to_string(),
                            references: vec![],
                            resource_name: Some(resource_name.to_string()),
                            namespace: namespace.clone(),
                            created_at: Utc::now(),
                        });
                    }
                }
            }
        }

        findings
    }

    /// Check NetworkPolicy controls
    fn check_network_policy_controls(
        &self,
        _manifest: &serde_json::Value,
        _scan_id: &str,
        _resource_name: &str,
        _namespace: &Option<String>,
    ) -> Vec<CisFinding> {
        // NetworkPolicy existence is checked at namespace level
        Vec::new()
    }

    /// Calculate summary from findings
    fn calculate_summary(&self, findings: &[CisFinding]) -> CisSummary {
        let total_controls = self.controls.len() as i32;

        let mut passed = 0;
        let mut failed = 0;
        let mut warnings = 0;
        let mut manual = 0;
        let mut not_applicable = 0;
        let mut by_section: HashMap<String, SectionSummary> = HashMap::new();

        // Count unique control statuses
        let mut control_statuses: HashMap<String, CisControlStatus> = HashMap::new();

        for finding in findings {
            let entry = control_statuses.entry(finding.control_id.clone()).or_insert(CisControlStatus::Pass);
            // Worst status wins
            if finding.status == CisControlStatus::Fail {
                *entry = CisControlStatus::Fail;
            } else if *entry != CisControlStatus::Fail && finding.status == CisControlStatus::Warn {
                *entry = CisControlStatus::Warn;
            }
        }

        for status in control_statuses.values() {
            match status {
                CisControlStatus::Pass => passed += 1,
                CisControlStatus::Fail => failed += 1,
                CisControlStatus::Warn => warnings += 1,
                CisControlStatus::Manual => manual += 1,
                CisControlStatus::NotApplicable => not_applicable += 1,
                CisControlStatus::Info => {}
            }
        }

        // Calculate pass rate
        let scored_total = total_controls - manual - not_applicable;
        let score_percentage = if scored_total > 0 {
            (passed as f64 / scored_total as f64) * 100.0
        } else {
            0.0
        };

        CisSummary {
            total_controls,
            passed,
            failed,
            warnings,
            manual,
            not_applicable,
            score_percentage,
            by_section,
        }
    }
}

impl Default for CisBenchmarkScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scanner_initialization() {
        let scanner = CisBenchmarkScanner::new();
        assert!(!scanner.controls.is_empty());
        assert!(scanner.controls.len() > 50);
    }

    #[test]
    fn test_analyze_privileged_pod() {
        let scanner = CisBenchmarkScanner::new();
        let manifest = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "test-pod",
                "namespace": "default"
            },
            "spec": {
                "containers": [{
                    "name": "app",
                    "image": "nginx",
                    "securityContext": {
                        "privileged": true
                    }
                }]
            }
        });

        let results = scanner.analyze_manifests(&[manifest], "test-scan");

        let privileged_finding = results.findings.iter()
            .find(|f| f.control_id == "5.2.2");

        assert!(privileged_finding.is_some());
        assert_eq!(privileged_finding.unwrap().status, CisControlStatus::Fail);
    }
}
