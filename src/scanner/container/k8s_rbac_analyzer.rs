//! Kubernetes RBAC Security Analyzer
//!
//! Provides deep analysis of Kubernetes Role-Based Access Control configurations
//! to identify security issues such as over-privileged accounts, escalation paths,
//! and dangerous permission combinations.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Types of RBAC security findings
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum RbacFindingType {
    /// Non-system users/groups bound to cluster-admin
    ClusterAdminBinding,
    /// Roles with wildcard (*) in verbs, resources, or apiGroups
    WildcardPermissions,
    /// Principals with access to secrets
    SecretAccess,
    /// Permissions that allow privilege escalation (bind, escalate, impersonate)
    EscalationPaths,
    /// Service accounts with excessive permissions
    OverPrivilegedServiceAccount,
    /// Pods using the default service account
    DefaultServiceAccountUsage,
    /// RoleBindings that grant cross-namespace access
    CrossNamespaceAccess,
    /// Permissions to create privileged pods
    PrivilegedPodCreation,
    /// Permissions to exec into pods
    PodExecAccess,
    /// Permissions to access node/proxy endpoints
    NodeProxyAccess,
    /// Permissions to read/modify ConfigMaps (potential secrets)
    ConfigMapAccess,
    /// Permissions to create/modify webhooks
    WebhookModification,
    /// Service account token auto-mounting enabled
    TokenAutoMount,
    /// Permissions to modify RBAC resources
    RbacModification,
    /// Dangerous verb combinations
    DangerousVerbCombination,
}

impl RbacFindingType {
    pub fn description(&self) -> &'static str {
        match self {
            Self::ClusterAdminBinding => "Non-system principal bound to cluster-admin role",
            Self::WildcardPermissions => "Role contains wildcard (*) permissions",
            Self::SecretAccess => "Principal has access to Kubernetes secrets",
            Self::EscalationPaths => "Principal has privilege escalation permissions",
            Self::OverPrivilegedServiceAccount => "Service account has excessive permissions",
            Self::DefaultServiceAccountUsage => "Workload uses the default service account",
            Self::CrossNamespaceAccess => "RoleBinding grants cross-namespace access",
            Self::PrivilegedPodCreation => "Principal can create privileged pods",
            Self::PodExecAccess => "Principal can exec into pods",
            Self::NodeProxyAccess => "Principal can access node/proxy endpoints",
            Self::ConfigMapAccess => "Principal has broad ConfigMap access",
            Self::WebhookModification => "Principal can modify admission webhooks",
            Self::TokenAutoMount => "Service account token auto-mounting is enabled",
            Self::RbacModification => "Principal can modify RBAC resources",
            Self::DangerousVerbCombination => "Role has dangerous verb combinations",
        }
    }

    pub fn remediation(&self) -> &'static str {
        match self {
            Self::ClusterAdminBinding => "Remove cluster-admin binding or use more restrictive roles",
            Self::WildcardPermissions => "Replace wildcards with explicit resource and verb lists",
            Self::SecretAccess => "Limit secret access to specific secrets needed by the workload",
            Self::EscalationPaths => "Remove bind, escalate, and impersonate permissions",
            Self::OverPrivilegedServiceAccount => "Create dedicated service accounts with minimal permissions",
            Self::DefaultServiceAccountUsage => "Create and use a dedicated service account",
            Self::CrossNamespaceAccess => "Use namespace-scoped roles instead of cluster roles",
            Self::PrivilegedPodCreation => "Restrict pod security context permissions",
            Self::PodExecAccess => "Remove pods/exec permission or limit to specific pods",
            Self::NodeProxyAccess => "Remove nodes/proxy permission",
            Self::ConfigMapAccess => "Limit ConfigMap access to specific ConfigMaps",
            Self::WebhookModification => "Restrict webhook modification to cluster administrators",
            Self::TokenAutoMount => "Set automountServiceAccountToken: false in pod spec",
            Self::RbacModification => "Restrict RBAC modification to cluster administrators",
            Self::DangerousVerbCombination => "Review and restrict verb combinations",
        }
    }
}

/// Severity levels for RBAC findings
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum RbacSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl RbacFindingType {
    pub fn default_severity(&self) -> RbacSeverity {
        match self {
            Self::ClusterAdminBinding => RbacSeverity::Critical,
            Self::WildcardPermissions => RbacSeverity::High,
            Self::SecretAccess => RbacSeverity::High,
            Self::EscalationPaths => RbacSeverity::Critical,
            Self::OverPrivilegedServiceAccount => RbacSeverity::High,
            Self::DefaultServiceAccountUsage => RbacSeverity::Medium,
            Self::CrossNamespaceAccess => RbacSeverity::Medium,
            Self::PrivilegedPodCreation => RbacSeverity::Critical,
            Self::PodExecAccess => RbacSeverity::High,
            Self::NodeProxyAccess => RbacSeverity::Critical,
            Self::ConfigMapAccess => RbacSeverity::Low,
            Self::WebhookModification => RbacSeverity::Critical,
            Self::TokenAutoMount => RbacSeverity::Low,
            Self::RbacModification => RbacSeverity::High,
            Self::DangerousVerbCombination => RbacSeverity::Medium,
        }
    }
}

/// Subject types in RBAC
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SubjectKind {
    User,
    Group,
    ServiceAccount,
}

/// An RBAC subject (user, group, or service account)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RbacSubject {
    pub kind: SubjectKind,
    pub name: String,
    pub namespace: Option<String>,
}

/// A permission rule from a Role/ClusterRole
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionRule {
    pub api_groups: Vec<String>,
    pub resources: Vec<String>,
    pub verbs: Vec<String>,
    pub resource_names: Vec<String>,
}

/// A Role or ClusterRole
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RbacRole {
    pub name: String,
    pub namespace: Option<String>,
    pub is_cluster_role: bool,
    pub rules: Vec<PermissionRule>,
}

/// A RoleBinding or ClusterRoleBinding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RbacBinding {
    pub name: String,
    pub namespace: Option<String>,
    pub is_cluster_binding: bool,
    pub role_ref: String,
    pub role_is_cluster_role: bool,
    pub subjects: Vec<RbacSubject>,
}

/// An RBAC security finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RbacFinding {
    pub finding_type: RbacFindingType,
    pub severity: RbacSeverity,
    pub subject: Option<RbacSubject>,
    pub role_name: Option<String>,
    pub binding_name: Option<String>,
    pub namespace: Option<String>,
    pub permissions: Vec<PermissionRule>,
    pub description: String,
    pub remediation: String,
}

/// Results from RBAC analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RbacAnalysisResults {
    pub findings: Vec<RbacFinding>,
    pub roles_analyzed: usize,
    pub bindings_analyzed: usize,
    pub subjects_analyzed: usize,
    pub summary: RbacSummary,
}

/// Summary statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RbacSummary {
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub cluster_admin_bindings: usize,
    pub wildcard_roles: usize,
    pub secret_access_count: usize,
    pub escalation_paths: usize,
}

/// Known system namespaces that should have elevated permissions
const SYSTEM_NAMESPACES: &[&str] = &[
    "kube-system",
    "kube-public",
    "kube-node-lease",
    "default",
];

/// Known system users/groups that legitimately need cluster-admin
const SYSTEM_SUBJECTS: &[&str] = &[
    "system:admin",
    "system:masters",
    "system:kube-controller-manager",
    "system:kube-scheduler",
    "system:node",
    "system:nodes",
    "kubernetes-admin",
];

/// Dangerous verbs that indicate potential security issues
const DANGEROUS_VERBS: &[&str] = &[
    "create",
    "update",
    "patch",
    "delete",
    "deletecollection",
    "escalate",
    "bind",
    "impersonate",
];

/// Sensitive resources
const SENSITIVE_RESOURCES: &[&str] = &[
    "secrets",
    "configmaps",
    "pods/exec",
    "pods/attach",
    "pods/portforward",
    "nodes/proxy",
    "serviceaccounts/token",
    "certificatesigningrequests/approval",
    "validatingwebhookconfigurations",
    "mutatingwebhookconfigurations",
];

/// RBAC resources
const RBAC_RESOURCES: &[&str] = &[
    "roles",
    "rolebindings",
    "clusterroles",
    "clusterrolebindings",
];

/// Kubernetes RBAC Analyzer
pub struct RbacAnalyzer {
    roles: Vec<RbacRole>,
    bindings: Vec<RbacBinding>,
    /// Map from role name to role
    role_map: HashMap<String, RbacRole>,
}

impl RbacAnalyzer {
    /// Create a new RBAC analyzer
    pub fn new() -> Self {
        Self {
            roles: Vec::new(),
            bindings: Vec::new(),
            role_map: HashMap::new(),
        }
    }

    /// Add a Role or ClusterRole from parsed YAML
    pub fn add_role(&mut self, manifest: &serde_yaml::Value) {
        if let Some(role) = Self::parse_role(manifest) {
            let key = if role.is_cluster_role {
                role.name.clone()
            } else {
                format!("{}/{}", role.namespace.as_deref().unwrap_or("default"), role.name)
            };
            self.role_map.insert(key, role.clone());
            self.roles.push(role);
        }
    }

    /// Add a RoleBinding or ClusterRoleBinding from parsed YAML
    pub fn add_binding(&mut self, manifest: &serde_yaml::Value) {
        if let Some(binding) = Self::parse_binding(manifest) {
            self.bindings.push(binding);
        }
    }

    /// Parse a Role/ClusterRole from YAML
    fn parse_role(manifest: &serde_yaml::Value) -> Option<RbacRole> {
        let kind = manifest.get("kind")?.as_str()?;
        if kind != "Role" && kind != "ClusterRole" {
            return None;
        }

        let metadata = manifest.get("metadata")?;
        let name = metadata.get("name")?.as_str()?.to_string();
        let namespace = metadata
            .get("namespace")
            .and_then(|n| n.as_str())
            .map(String::from);

        let rules = manifest
            .get("rules")
            .and_then(|r| r.as_sequence())
            .map(|rules| {
                rules
                    .iter()
                    .filter_map(|rule| Self::parse_permission_rule(rule))
                    .collect()
            })
            .unwrap_or_default();

        Some(RbacRole {
            name,
            namespace,
            is_cluster_role: kind == "ClusterRole",
            rules,
        })
    }

    /// Parse a RoleBinding/ClusterRoleBinding from YAML
    fn parse_binding(manifest: &serde_yaml::Value) -> Option<RbacBinding> {
        let kind = manifest.get("kind")?.as_str()?;
        if kind != "RoleBinding" && kind != "ClusterRoleBinding" {
            return None;
        }

        let metadata = manifest.get("metadata")?;
        let name = metadata.get("name")?.as_str()?.to_string();
        let namespace = metadata
            .get("namespace")
            .and_then(|n| n.as_str())
            .map(String::from);

        let role_ref = manifest.get("roleRef")?;
        let role_name = role_ref.get("name")?.as_str()?.to_string();
        let role_kind = role_ref.get("kind").and_then(|k| k.as_str()).unwrap_or("Role");

        let subjects = manifest
            .get("subjects")
            .and_then(|s| s.as_sequence())
            .map(|subjects| {
                subjects
                    .iter()
                    .filter_map(|subj| Self::parse_subject(subj))
                    .collect()
            })
            .unwrap_or_default();

        Some(RbacBinding {
            name,
            namespace,
            is_cluster_binding: kind == "ClusterRoleBinding",
            role_ref: role_name,
            role_is_cluster_role: role_kind == "ClusterRole",
            subjects,
        })
    }

    /// Parse a permission rule
    fn parse_permission_rule(rule: &serde_yaml::Value) -> Option<PermissionRule> {
        let api_groups = Self::parse_string_list(rule.get("apiGroups"));
        let resources = Self::parse_string_list(rule.get("resources"));
        let verbs = Self::parse_string_list(rule.get("verbs"));
        let resource_names = Self::parse_string_list(rule.get("resourceNames"));

        Some(PermissionRule {
            api_groups,
            resources,
            verbs,
            resource_names,
        })
    }

    /// Parse an RBAC subject
    fn parse_subject(subject: &serde_yaml::Value) -> Option<RbacSubject> {
        let kind_str = subject.get("kind")?.as_str()?;
        let kind = match kind_str {
            "User" => SubjectKind::User,
            "Group" => SubjectKind::Group,
            "ServiceAccount" => SubjectKind::ServiceAccount,
            _ => return None,
        };

        let name = subject.get("name")?.as_str()?.to_string();
        let namespace = subject
            .get("namespace")
            .and_then(|n| n.as_str())
            .map(String::from);

        Some(RbacSubject {
            kind,
            name,
            namespace,
        })
    }

    /// Parse a string list from YAML
    fn parse_string_list(value: Option<&serde_yaml::Value>) -> Vec<String> {
        value
            .and_then(|v| v.as_sequence())
            .map(|seq| {
                seq.iter()
                    .filter_map(|s| s.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Run the RBAC analysis
    pub fn analyze(&self) -> RbacAnalysisResults {
        let mut findings = Vec::new();

        // Analyze roles for dangerous permissions
        for role in &self.roles {
            findings.extend(self.analyze_role(role));
        }

        // Analyze bindings
        for binding in &self.bindings {
            findings.extend(self.analyze_binding(binding));
        }

        // Calculate summary
        let summary = self.calculate_summary(&findings);

        // Collect unique subjects
        let subjects: HashSet<_> = self
            .bindings
            .iter()
            .flat_map(|b| b.subjects.iter().map(|s| &s.name))
            .collect();

        RbacAnalysisResults {
            findings,
            roles_analyzed: self.roles.len(),
            bindings_analyzed: self.bindings.len(),
            subjects_analyzed: subjects.len(),
            summary,
        }
    }

    /// Analyze a single role
    fn analyze_role(&self, role: &RbacRole) -> Vec<RbacFinding> {
        let mut findings = Vec::new();

        for rule in &role.rules {
            // Check for wildcard permissions
            if self.has_wildcards(rule) {
                findings.push(RbacFinding {
                    finding_type: RbacFindingType::WildcardPermissions,
                    severity: RbacSeverity::High,
                    subject: None,
                    role_name: Some(role.name.clone()),
                    binding_name: None,
                    namespace: role.namespace.clone(),
                    permissions: vec![rule.clone()],
                    description: format!(
                        "Role '{}' contains wildcard permissions: apiGroups={:?}, resources={:?}, verbs={:?}",
                        role.name, rule.api_groups, rule.resources, rule.verbs
                    ),
                    remediation: RbacFindingType::WildcardPermissions.remediation().to_string(),
                });
            }

            // Check for secret access
            if self.has_secret_access(rule) {
                findings.push(RbacFinding {
                    finding_type: RbacFindingType::SecretAccess,
                    severity: RbacSeverity::High,
                    subject: None,
                    role_name: Some(role.name.clone()),
                    binding_name: None,
                    namespace: role.namespace.clone(),
                    permissions: vec![rule.clone()],
                    description: format!(
                        "Role '{}' grants access to secrets with verbs: {:?}",
                        role.name, rule.verbs
                    ),
                    remediation: RbacFindingType::SecretAccess.remediation().to_string(),
                });
            }

            // Check for escalation permissions
            if self.has_escalation_permissions(rule) {
                findings.push(RbacFinding {
                    finding_type: RbacFindingType::EscalationPaths,
                    severity: RbacSeverity::Critical,
                    subject: None,
                    role_name: Some(role.name.clone()),
                    binding_name: None,
                    namespace: role.namespace.clone(),
                    permissions: vec![rule.clone()],
                    description: format!(
                        "Role '{}' contains privilege escalation permissions: {:?}",
                        role.name, rule.verbs
                    ),
                    remediation: RbacFindingType::EscalationPaths.remediation().to_string(),
                });
            }

            // Check for pod exec access
            if self.has_pod_exec_access(rule) {
                findings.push(RbacFinding {
                    finding_type: RbacFindingType::PodExecAccess,
                    severity: RbacSeverity::High,
                    subject: None,
                    role_name: Some(role.name.clone()),
                    binding_name: None,
                    namespace: role.namespace.clone(),
                    permissions: vec![rule.clone()],
                    description: format!(
                        "Role '{}' grants pods/exec access",
                        role.name
                    ),
                    remediation: RbacFindingType::PodExecAccess.remediation().to_string(),
                });
            }

            // Check for node/proxy access
            if self.has_node_proxy_access(rule) {
                findings.push(RbacFinding {
                    finding_type: RbacFindingType::NodeProxyAccess,
                    severity: RbacSeverity::Critical,
                    subject: None,
                    role_name: Some(role.name.clone()),
                    binding_name: None,
                    namespace: role.namespace.clone(),
                    permissions: vec![rule.clone()],
                    description: format!(
                        "Role '{}' grants nodes/proxy access",
                        role.name
                    ),
                    remediation: RbacFindingType::NodeProxyAccess.remediation().to_string(),
                });
            }

            // Check for webhook modification
            if self.has_webhook_access(rule) {
                findings.push(RbacFinding {
                    finding_type: RbacFindingType::WebhookModification,
                    severity: RbacSeverity::Critical,
                    subject: None,
                    role_name: Some(role.name.clone()),
                    binding_name: None,
                    namespace: role.namespace.clone(),
                    permissions: vec![rule.clone()],
                    description: format!(
                        "Role '{}' can modify admission webhooks",
                        role.name
                    ),
                    remediation: RbacFindingType::WebhookModification.remediation().to_string(),
                });
            }

            // Check for RBAC modification
            if self.has_rbac_modification(rule) {
                findings.push(RbacFinding {
                    finding_type: RbacFindingType::RbacModification,
                    severity: RbacSeverity::High,
                    subject: None,
                    role_name: Some(role.name.clone()),
                    binding_name: None,
                    namespace: role.namespace.clone(),
                    permissions: vec![rule.clone()],
                    description: format!(
                        "Role '{}' can modify RBAC resources",
                        role.name
                    ),
                    remediation: RbacFindingType::RbacModification.remediation().to_string(),
                });
            }

            // Check for privileged pod creation
            if self.can_create_privileged_pods(rule) {
                findings.push(RbacFinding {
                    finding_type: RbacFindingType::PrivilegedPodCreation,
                    severity: RbacSeverity::Critical,
                    subject: None,
                    role_name: Some(role.name.clone()),
                    binding_name: None,
                    namespace: role.namespace.clone(),
                    permissions: vec![rule.clone()],
                    description: format!(
                        "Role '{}' can create/update pods (potential for privileged containers)",
                        role.name
                    ),
                    remediation: RbacFindingType::PrivilegedPodCreation.remediation().to_string(),
                });
            }
        }

        findings
    }

    /// Analyze a single binding
    fn analyze_binding(&self, binding: &RbacBinding) -> Vec<RbacFinding> {
        let mut findings = Vec::new();

        // Check for cluster-admin bindings to non-system subjects
        if binding.role_ref == "cluster-admin" || binding.role_ref == "admin" {
            for subject in &binding.subjects {
                if !self.is_system_subject(subject) {
                    findings.push(RbacFinding {
                        finding_type: RbacFindingType::ClusterAdminBinding,
                        severity: RbacSeverity::Critical,
                        subject: Some(subject.clone()),
                        role_name: Some(binding.role_ref.clone()),
                        binding_name: Some(binding.name.clone()),
                        namespace: binding.namespace.clone(),
                        permissions: Vec::new(),
                        description: format!(
                            "Non-system {:?} '{}' is bound to '{}' via binding '{}'",
                            subject.kind, subject.name, binding.role_ref, binding.name
                        ),
                        remediation: RbacFindingType::ClusterAdminBinding.remediation().to_string(),
                    });
                }
            }
        }

        // Check for cross-namespace access
        if !binding.is_cluster_binding && binding.role_is_cluster_role {
            for subject in &binding.subjects {
                if let SubjectKind::ServiceAccount = subject.kind {
                    if subject.namespace.as_ref() != binding.namespace.as_ref() {
                        findings.push(RbacFinding {
                            finding_type: RbacFindingType::CrossNamespaceAccess,
                            severity: RbacSeverity::Medium,
                            subject: Some(subject.clone()),
                            role_name: Some(binding.role_ref.clone()),
                            binding_name: Some(binding.name.clone()),
                            namespace: binding.namespace.clone(),
                            permissions: Vec::new(),
                            description: format!(
                                "ServiceAccount '{}' from namespace '{}' is bound to ClusterRole '{}' in namespace '{}'",
                                subject.name,
                                subject.namespace.as_deref().unwrap_or("unknown"),
                                binding.role_ref,
                                binding.namespace.as_deref().unwrap_or("unknown")
                            ),
                            remediation: RbacFindingType::CrossNamespaceAccess.remediation().to_string(),
                        });
                    }
                }
            }
        }

        // Check for over-privileged service accounts in non-system namespaces
        for subject in &binding.subjects {
            if let SubjectKind::ServiceAccount = subject.kind {
                let sa_namespace = subject.namespace.as_deref().unwrap_or("default");
                if !SYSTEM_NAMESPACES.contains(&sa_namespace) {
                    // Look up the role to check permissions
                    if let Some(role) = self.get_role(&binding.role_ref, binding.role_is_cluster_role, &binding.namespace) {
                        let dangerous_rules: Vec<_> = role
                            .rules
                            .iter()
                            .filter(|r| self.is_dangerous_rule(r))
                            .cloned()
                            .collect();

                        if !dangerous_rules.is_empty() {
                            findings.push(RbacFinding {
                                finding_type: RbacFindingType::OverPrivilegedServiceAccount,
                                severity: RbacSeverity::High,
                                subject: Some(subject.clone()),
                                role_name: Some(binding.role_ref.clone()),
                                binding_name: Some(binding.name.clone()),
                                namespace: Some(sa_namespace.to_string()),
                                permissions: dangerous_rules,
                                description: format!(
                                    "ServiceAccount '{}' in namespace '{}' has dangerous permissions via role '{}'",
                                    subject.name, sa_namespace, binding.role_ref
                                ),
                                remediation: RbacFindingType::OverPrivilegedServiceAccount.remediation().to_string(),
                            });
                        }
                    }
                }
            }
        }

        findings
    }

    /// Get a role by name
    fn get_role(&self, name: &str, is_cluster_role: bool, binding_namespace: &Option<String>) -> Option<&RbacRole> {
        if is_cluster_role {
            self.role_map.get(name)
        } else {
            let key = format!("{}/{}", binding_namespace.as_deref().unwrap_or("default"), name);
            self.role_map.get(&key)
        }
    }

    /// Check if a rule has wildcard permissions
    fn has_wildcards(&self, rule: &PermissionRule) -> bool {
        rule.api_groups.contains(&"*".to_string())
            || rule.resources.contains(&"*".to_string())
            || rule.verbs.contains(&"*".to_string())
    }

    /// Check if a rule grants secret access
    fn has_secret_access(&self, rule: &PermissionRule) -> bool {
        (rule.resources.contains(&"secrets".to_string()) || rule.resources.contains(&"*".to_string()))
            && (rule.verbs.iter().any(|v| v == "get" || v == "list" || v == "watch" || v == "*"))
    }

    /// Check if a rule has escalation permissions
    fn has_escalation_permissions(&self, rule: &PermissionRule) -> bool {
        rule.verbs.iter().any(|v| v == "escalate" || v == "bind" || v == "impersonate")
    }

    /// Check if a rule grants pod exec access
    fn has_pod_exec_access(&self, rule: &PermissionRule) -> bool {
        rule.resources.iter().any(|r| r == "pods/exec" || r == "pods/attach")
            || (rule.resources.contains(&"*".to_string()) && rule.verbs.iter().any(|v| v == "create" || v == "*"))
    }

    /// Check if a rule grants node proxy access
    fn has_node_proxy_access(&self, rule: &PermissionRule) -> bool {
        rule.resources.iter().any(|r| r == "nodes/proxy")
            || (rule.resources.contains(&"*".to_string()) && rule.verbs.iter().any(|v| v == "get" || v == "*"))
    }

    /// Check if a rule grants webhook modification
    fn has_webhook_access(&self, rule: &PermissionRule) -> bool {
        rule.resources.iter().any(|r| {
            r == "validatingwebhookconfigurations"
                || r == "mutatingwebhookconfigurations"
        }) && rule.verbs.iter().any(|v| DANGEROUS_VERBS.contains(&v.as_str()) || v == "*")
    }

    /// Check if a rule grants RBAC modification
    fn has_rbac_modification(&self, rule: &PermissionRule) -> bool {
        rule.resources.iter().any(|r| RBAC_RESOURCES.contains(&r.as_str()))
            && rule.verbs.iter().any(|v| v == "create" || v == "update" || v == "patch" || v == "delete" || v == "*")
    }

    /// Check if a rule can create pods (potential for privileged)
    fn can_create_privileged_pods(&self, rule: &PermissionRule) -> bool {
        (rule.resources.contains(&"pods".to_string()) || rule.resources.contains(&"*".to_string()))
            && rule.verbs.iter().any(|v| v == "create" || v == "update" || v == "patch" || v == "*")
    }

    /// Check if a rule is dangerous
    fn is_dangerous_rule(&self, rule: &PermissionRule) -> bool {
        self.has_wildcards(rule)
            || self.has_secret_access(rule)
            || self.has_escalation_permissions(rule)
            || self.has_pod_exec_access(rule)
            || self.has_node_proxy_access(rule)
            || self.has_webhook_access(rule)
            || self.has_rbac_modification(rule)
    }

    /// Check if a subject is a system subject
    fn is_system_subject(&self, subject: &RbacSubject) -> bool {
        // System users/groups
        if SYSTEM_SUBJECTS.contains(&subject.name.as_str()) {
            return true;
        }

        // System prefixes
        if subject.name.starts_with("system:") {
            return true;
        }

        // Service accounts in system namespaces
        if let SubjectKind::ServiceAccount = subject.kind {
            if let Some(ns) = &subject.namespace {
                if SYSTEM_NAMESPACES.contains(&ns.as_str()) {
                    return true;
                }
            }
        }

        false
    }

    /// Calculate summary statistics
    fn calculate_summary(&self, findings: &[RbacFinding]) -> RbacSummary {
        let mut summary = RbacSummary {
            critical_count: 0,
            high_count: 0,
            medium_count: 0,
            low_count: 0,
            cluster_admin_bindings: 0,
            wildcard_roles: 0,
            secret_access_count: 0,
            escalation_paths: 0,
        };

        for finding in findings {
            match finding.severity {
                RbacSeverity::Critical => summary.critical_count += 1,
                RbacSeverity::High => summary.high_count += 1,
                RbacSeverity::Medium => summary.medium_count += 1,
                RbacSeverity::Low => summary.low_count += 1,
            }

            match finding.finding_type {
                RbacFindingType::ClusterAdminBinding => summary.cluster_admin_bindings += 1,
                RbacFindingType::WildcardPermissions => summary.wildcard_roles += 1,
                RbacFindingType::SecretAccess => summary.secret_access_count += 1,
                RbacFindingType::EscalationPaths => summary.escalation_paths += 1,
                _ => {}
            }
        }

        summary
    }

    /// Analyze Pod manifests for default service account usage
    pub fn analyze_pod_service_accounts(&self, manifests: &[serde_yaml::Value]) -> Vec<RbacFinding> {
        let mut findings = Vec::new();

        for manifest in manifests {
            let kind = manifest.get("kind").and_then(|k| k.as_str()).unwrap_or("");

            // Handle Pods and workloads with pod templates
            let pod_spec = match kind {
                "Pod" => manifest.get("spec"),
                "Deployment" | "DaemonSet" | "StatefulSet" | "ReplicaSet" | "Job" => {
                    manifest
                        .get("spec")
                        .and_then(|s| s.get("template"))
                        .and_then(|t| t.get("spec"))
                }
                "CronJob" => {
                    manifest
                        .get("spec")
                        .and_then(|s| s.get("jobTemplate"))
                        .and_then(|j| j.get("spec"))
                        .and_then(|s| s.get("template"))
                        .and_then(|t| t.get("spec"))
                }
                _ => continue,
            };

            if let Some(spec) = pod_spec {
                let name = manifest
                    .get("metadata")
                    .and_then(|m| m.get("name"))
                    .and_then(|n| n.as_str())
                    .unwrap_or("unknown");

                let namespace = manifest
                    .get("metadata")
                    .and_then(|m| m.get("namespace"))
                    .and_then(|n| n.as_str())
                    .map(String::from);

                // Check for default service account
                let service_account = spec
                    .get("serviceAccountName")
                    .or_else(|| spec.get("serviceAccount"))
                    .and_then(|s| s.as_str())
                    .unwrap_or("default");

                if service_account == "default" {
                    findings.push(RbacFinding {
                        finding_type: RbacFindingType::DefaultServiceAccountUsage,
                        severity: RbacSeverity::Medium,
                        subject: Some(RbacSubject {
                            kind: SubjectKind::ServiceAccount,
                            name: "default".to_string(),
                            namespace: namespace.clone(),
                        }),
                        role_name: None,
                        binding_name: None,
                        namespace: namespace.clone(),
                        permissions: Vec::new(),
                        description: format!(
                            "{} '{}' uses the default service account",
                            kind, name
                        ),
                        remediation: RbacFindingType::DefaultServiceAccountUsage.remediation().to_string(),
                    });
                }

                // Check for token auto-mount
                let auto_mount = spec
                    .get("automountServiceAccountToken")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true);

                if auto_mount {
                    findings.push(RbacFinding {
                        finding_type: RbacFindingType::TokenAutoMount,
                        severity: RbacSeverity::Low,
                        subject: Some(RbacSubject {
                            kind: SubjectKind::ServiceAccount,
                            name: service_account.to_string(),
                            namespace: namespace.clone(),
                        }),
                        role_name: None,
                        binding_name: None,
                        namespace,
                        permissions: Vec::new(),
                        description: format!(
                            "{} '{}' has service account token auto-mounting enabled",
                            kind, name
                        ),
                        remediation: RbacFindingType::TokenAutoMount.remediation().to_string(),
                    });
                }
            }
        }

        findings
    }
}

impl Default for RbacAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_cluster_admin_binding() -> serde_yaml::Value {
        serde_yaml::from_str(r#"
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: test-admin-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
- kind: User
  name: test-user
  apiGroup: rbac.authorization.k8s.io
"#).expect("test YAML fixture should be valid")
    }

    fn create_wildcard_role() -> serde_yaml::Value {
        serde_yaml::from_str(r#"
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: wildcard-role
rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["*"]
"#).expect("test YAML fixture should be valid")
    }

    fn create_secret_access_role() -> serde_yaml::Value {
        serde_yaml::from_str(r#"
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: secret-reader
  namespace: default
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get", "list", "watch"]
"#).expect("test YAML fixture should be valid")
    }

    fn create_pod_with_default_sa() -> serde_yaml::Value {
        serde_yaml::from_str(r#"
apiVersion: v1
kind: Pod
metadata:
  name: test-pod
  namespace: default
spec:
  containers:
  - name: nginx
    image: nginx
"#).expect("test YAML fixture should be valid")
    }

    #[test]
    fn test_detect_cluster_admin_binding() {
        let mut analyzer = RbacAnalyzer::new();
        analyzer.add_binding(&create_cluster_admin_binding());

        let results = analyzer.analyze();
        assert!(results.findings.iter().any(|f| f.finding_type == RbacFindingType::ClusterAdminBinding));
    }

    #[test]
    fn test_detect_wildcard_permissions() {
        let mut analyzer = RbacAnalyzer::new();
        analyzer.add_role(&create_wildcard_role());

        let results = analyzer.analyze();
        assert!(results.findings.iter().any(|f| f.finding_type == RbacFindingType::WildcardPermissions));
    }

    #[test]
    fn test_detect_secret_access() {
        let mut analyzer = RbacAnalyzer::new();
        analyzer.add_role(&create_secret_access_role());

        let results = analyzer.analyze();
        assert!(results.findings.iter().any(|f| f.finding_type == RbacFindingType::SecretAccess));
    }

    #[test]
    fn test_detect_default_service_account() {
        let analyzer = RbacAnalyzer::new();
        let manifests = vec![create_pod_with_default_sa()];

        let findings = analyzer.analyze_pod_service_accounts(&manifests);
        assert!(findings.iter().any(|f| f.finding_type == RbacFindingType::DefaultServiceAccountUsage));
    }

    #[test]
    fn test_system_subject_detection() {
        let analyzer = RbacAnalyzer::new();

        let system_subject = RbacSubject {
            kind: SubjectKind::User,
            name: "system:kube-controller-manager".to_string(),
            namespace: None,
        };
        assert!(analyzer.is_system_subject(&system_subject));

        let non_system_subject = RbacSubject {
            kind: SubjectKind::User,
            name: "test-user".to_string(),
            namespace: None,
        };
        assert!(!analyzer.is_system_subject(&non_system_subject));
    }

    #[test]
    fn test_summary_calculation() {
        let mut analyzer = RbacAnalyzer::new();
        analyzer.add_binding(&create_cluster_admin_binding());
        analyzer.add_role(&create_wildcard_role());
        analyzer.add_role(&create_secret_access_role());

        let results = analyzer.analyze();
        assert!(results.summary.critical_count > 0);
        assert!(results.summary.cluster_admin_bindings > 0);
        assert!(results.summary.wildcard_roles > 0);
    }
}
