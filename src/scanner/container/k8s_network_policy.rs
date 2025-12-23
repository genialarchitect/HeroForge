//! Kubernetes Network Policy Security Audit
//!
//! Analyzes Kubernetes NetworkPolicy configurations to identify security issues
//! such as missing default deny policies, overly permissive rules, and
//! exposed sensitive ports.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Types of Network Policy findings
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum NetworkPolicyFindingType {
    /// Namespace lacks a default deny ingress policy
    NoDefaultDenyIngress,
    /// Namespace lacks a default deny egress policy
    NoDefaultDenyEgress,
    /// Policy allows all ingress traffic
    AllowAllIngress,
    /// Policy allows all egress traffic
    AllowAllEgress,
    /// Sensitive ports are exposed (22, 3389, database ports)
    ExposedSensitivePorts,
    /// Policy allows egress to internet (0.0.0.0/0)
    InternetEgress,
    /// Policy allows cross-namespace traffic
    CrossNamespaceAllowed,
    /// Pods/workloads without any network policy coverage
    MissingPolicies,
    /// Overly permissive CIDR block
    OverlyPermissiveCidr,
    /// Policy with empty pod selector (applies to all pods)
    EmptyPodSelector,
    /// Policy with empty namespace selector (all namespaces)
    EmptyNamespaceSelector,
    /// Deprecated API version
    DeprecatedApiVersion,
    /// DNS egress blocked (pods can't resolve DNS)
    DnsEgressBlocked,
    /// Metadata service access allowed (cloud provider IMDS)
    MetadataServiceAccess,
}

impl NetworkPolicyFindingType {
    pub fn description(&self) -> &'static str {
        match self {
            Self::NoDefaultDenyIngress => "Namespace lacks default deny ingress NetworkPolicy",
            Self::NoDefaultDenyEgress => "Namespace lacks default deny egress NetworkPolicy",
            Self::AllowAllIngress => "NetworkPolicy allows all ingress traffic",
            Self::AllowAllEgress => "NetworkPolicy allows all egress traffic",
            Self::ExposedSensitivePorts => "Sensitive ports are exposed to ingress",
            Self::InternetEgress => "NetworkPolicy allows egress to internet (0.0.0.0/0)",
            Self::CrossNamespaceAllowed => "NetworkPolicy allows cross-namespace traffic",
            Self::MissingPolicies => "Workloads have no NetworkPolicy coverage",
            Self::OverlyPermissiveCidr => "NetworkPolicy uses overly permissive CIDR block",
            Self::EmptyPodSelector => "NetworkPolicy applies to all pods in namespace",
            Self::EmptyNamespaceSelector => "NetworkPolicy allows traffic from any namespace",
            Self::DeprecatedApiVersion => "NetworkPolicy uses deprecated API version",
            Self::DnsEgressBlocked => "Default deny egress may block DNS resolution",
            Self::MetadataServiceAccess => "Policy allows access to cloud metadata service",
        }
    }

    pub fn remediation(&self) -> &'static str {
        match self {
            Self::NoDefaultDenyIngress => "Create a default deny ingress NetworkPolicy for the namespace",
            Self::NoDefaultDenyEgress => "Create a default deny egress NetworkPolicy for the namespace",
            Self::AllowAllIngress => "Restrict ingress to specific sources and ports",
            Self::AllowAllEgress => "Restrict egress to specific destinations and ports",
            Self::ExposedSensitivePorts => "Remove or restrict access to sensitive ports",
            Self::InternetEgress => "Restrict egress to specific IP ranges or use egress gateways",
            Self::CrossNamespaceAllowed => "Limit cross-namespace traffic to specific namespaces",
            Self::MissingPolicies => "Create NetworkPolicies for all workloads",
            Self::OverlyPermissiveCidr => "Use more specific CIDR blocks",
            Self::EmptyPodSelector => "Use specific pod selectors to limit policy scope",
            Self::EmptyNamespaceSelector => "Specify namespace selectors to limit cross-namespace access",
            Self::DeprecatedApiVersion => "Update to networking.k8s.io/v1 API version",
            Self::DnsEgressBlocked => "Allow egress to kube-dns service on port 53",
            Self::MetadataServiceAccess => "Block egress to 169.254.169.254 (metadata service)",
        }
    }
}

/// Severity levels
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum NetworkPolicySeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl NetworkPolicyFindingType {
    pub fn default_severity(&self) -> NetworkPolicySeverity {
        match self {
            Self::NoDefaultDenyIngress => NetworkPolicySeverity::High,
            Self::NoDefaultDenyEgress => NetworkPolicySeverity::Medium,
            Self::AllowAllIngress => NetworkPolicySeverity::Critical,
            Self::AllowAllEgress => NetworkPolicySeverity::High,
            Self::ExposedSensitivePorts => NetworkPolicySeverity::High,
            Self::InternetEgress => NetworkPolicySeverity::Medium,
            Self::CrossNamespaceAllowed => NetworkPolicySeverity::Medium,
            Self::MissingPolicies => NetworkPolicySeverity::High,
            Self::OverlyPermissiveCidr => NetworkPolicySeverity::Medium,
            Self::EmptyPodSelector => NetworkPolicySeverity::Low,
            Self::EmptyNamespaceSelector => NetworkPolicySeverity::Medium,
            Self::DeprecatedApiVersion => NetworkPolicySeverity::Low,
            Self::DnsEgressBlocked => NetworkPolicySeverity::Info,
            Self::MetadataServiceAccess => NetworkPolicySeverity::High,
        }
    }
}

/// Sensitive ports that should be restricted
const SENSITIVE_PORTS: &[(u16, &str)] = &[
    (22, "SSH"),
    (23, "Telnet"),
    (3389, "RDP"),
    (5432, "PostgreSQL"),
    (3306, "MySQL"),
    (27017, "MongoDB"),
    (6379, "Redis"),
    (9200, "Elasticsearch"),
    (11211, "Memcached"),
    (2379, "etcd client"),
    (2380, "etcd peer"),
    (10250, "Kubelet"),
    (10255, "Kubelet read-only"),
    (6443, "Kubernetes API"),
];

/// Cloud metadata service IPs
const METADATA_SERVICE_IPS: &[&str] = &[
    "169.254.169.254",      // AWS, GCP, Azure
    "169.254.170.2",        // AWS ECS
    "100.100.100.200",      // Alibaba Cloud
];

/// A parsed NetworkPolicy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedNetworkPolicy {
    pub name: String,
    pub namespace: String,
    pub pod_selector: HashMap<String, String>,
    pub policy_types: Vec<String>,
    pub ingress_rules: Vec<IngressRule>,
    pub egress_rules: Vec<EgressRule>,
    pub api_version: String,
}

/// An ingress rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngressRule {
    pub from: Vec<NetworkPolicyPeer>,
    pub ports: Vec<NetworkPolicyPort>,
}

/// An egress rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EgressRule {
    pub to: Vec<NetworkPolicyPeer>,
    pub ports: Vec<NetworkPolicyPort>,
}

/// A network policy peer (source/destination)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkPolicyPeer {
    pub pod_selector: Option<HashMap<String, String>>,
    pub namespace_selector: Option<HashMap<String, String>>,
    pub ip_block: Option<IpBlock>,
}

/// An IP block specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpBlock {
    pub cidr: String,
    pub except: Vec<String>,
}

/// A port specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkPolicyPort {
    pub protocol: Option<String>,
    pub port: Option<PortValue>,
    pub end_port: Option<u16>,
}

/// Port value (can be number or named port)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PortValue {
    Number(u16),
    Named(String),
}

/// A network policy finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkPolicyFinding {
    pub finding_type: NetworkPolicyFindingType,
    pub severity: NetworkPolicySeverity,
    pub namespace: String,
    pub policy_name: Option<String>,
    pub affected_pods: Vec<String>,
    pub description: String,
    pub remediation: String,
    pub details: HashMap<String, String>,
}

/// Results from network policy analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkPolicyAnalysisResults {
    pub findings: Vec<NetworkPolicyFinding>,
    pub namespaces_analyzed: usize,
    pub policies_analyzed: usize,
    pub workloads_analyzed: usize,
    pub summary: NetworkPolicySummary,
    pub coverage_by_namespace: HashMap<String, NamespaceCoverage>,
}

/// Coverage statistics for a namespace
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NamespaceCoverage {
    pub namespace: String,
    pub total_pods: usize,
    pub covered_pods: usize,
    pub has_default_deny_ingress: bool,
    pub has_default_deny_egress: bool,
    pub policy_count: usize,
}

/// Summary statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkPolicySummary {
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub info_count: usize,
    pub namespaces_without_default_deny: usize,
    pub exposed_sensitive_ports: usize,
    pub uncovered_workloads: usize,
}

/// Kubernetes Network Policy Analyzer
pub struct NetworkPolicyAnalyzer {
    policies: Vec<ParsedNetworkPolicy>,
    workloads: Vec<WorkloadInfo>,
    namespaces: HashSet<String>,
}

/// Information about a workload
#[derive(Debug, Clone)]
struct WorkloadInfo {
    name: String,
    namespace: String,
    kind: String,
    labels: HashMap<String, String>,
}

impl NetworkPolicyAnalyzer {
    /// Create a new analyzer
    pub fn new() -> Self {
        Self {
            policies: Vec::new(),
            workloads: Vec::new(),
            namespaces: HashSet::new(),
        }
    }

    /// Add a NetworkPolicy from parsed YAML
    pub fn add_policy(&mut self, manifest: &serde_yaml::Value) {
        if let Some(policy) = self.parse_network_policy(manifest) {
            self.namespaces.insert(policy.namespace.clone());
            self.policies.push(policy);
        }
    }

    /// Add a workload (Pod, Deployment, etc.) from parsed YAML
    pub fn add_workload(&mut self, manifest: &serde_yaml::Value) {
        if let Some(workload) = self.parse_workload(manifest) {
            self.namespaces.insert(workload.namespace.clone());
            self.workloads.push(workload);
        }
    }

    /// Parse a NetworkPolicy from YAML
    fn parse_network_policy(&self, manifest: &serde_yaml::Value) -> Option<ParsedNetworkPolicy> {
        let kind = manifest.get("kind")?.as_str()?;
        if kind != "NetworkPolicy" {
            return None;
        }

        let api_version = manifest
            .get("apiVersion")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();

        let metadata = manifest.get("metadata")?;
        let name = metadata.get("name")?.as_str()?.to_string();
        let namespace = metadata
            .get("namespace")
            .and_then(|n| n.as_str())
            .unwrap_or("default")
            .to_string();

        let spec = manifest.get("spec")?;

        let pod_selector = self.parse_label_selector(spec.get("podSelector"));

        let policy_types = spec
            .get("policyTypes")
            .and_then(|p| p.as_sequence())
            .map(|types| {
                types
                    .iter()
                    .filter_map(|t| t.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        let ingress_rules = spec
            .get("ingress")
            .and_then(|i| i.as_sequence())
            .map(|rules| rules.iter().filter_map(|r| self.parse_ingress_rule(r)).collect())
            .unwrap_or_default();

        let egress_rules = spec
            .get("egress")
            .and_then(|e| e.as_sequence())
            .map(|rules| rules.iter().filter_map(|r| self.parse_egress_rule(r)).collect())
            .unwrap_or_default();

        Some(ParsedNetworkPolicy {
            name,
            namespace,
            pod_selector,
            policy_types,
            ingress_rules,
            egress_rules,
            api_version,
        })
    }

    /// Parse a workload from YAML
    fn parse_workload(&self, manifest: &serde_yaml::Value) -> Option<WorkloadInfo> {
        let kind = manifest.get("kind")?.as_str()?;

        // Get pod labels based on workload type
        let (labels, namespace) = match kind {
            "Pod" => {
                let metadata = manifest.get("metadata")?;
                let labels = self.parse_labels(metadata.get("labels"));
                let namespace = metadata
                    .get("namespace")
                    .and_then(|n| n.as_str())
                    .unwrap_or("default")
                    .to_string();
                (labels, namespace)
            }
            "Deployment" | "DaemonSet" | "StatefulSet" | "ReplicaSet" => {
                let metadata = manifest.get("metadata")?;
                let namespace = metadata
                    .get("namespace")
                    .and_then(|n| n.as_str())
                    .unwrap_or("default")
                    .to_string();
                let labels = manifest
                    .get("spec")
                    .and_then(|s| s.get("template"))
                    .and_then(|t| t.get("metadata"))
                    .and_then(|m| m.get("labels"))
                    .map(|l| self.parse_labels(Some(l)))
                    .unwrap_or_default();
                (labels, namespace)
            }
            _ => return None,
        };

        let name = manifest
            .get("metadata")?
            .get("name")?
            .as_str()?
            .to_string();

        Some(WorkloadInfo {
            name,
            namespace,
            kind: kind.to_string(),
            labels,
        })
    }

    /// Parse labels from YAML
    fn parse_labels(&self, labels: Option<&serde_yaml::Value>) -> HashMap<String, String> {
        labels
            .and_then(|l| l.as_mapping())
            .map(|mapping| {
                mapping
                    .iter()
                    .filter_map(|(k, v)| {
                        Some((k.as_str()?.to_string(), v.as_str()?.to_string()))
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Parse a label selector
    fn parse_label_selector(&self, selector: Option<&serde_yaml::Value>) -> HashMap<String, String> {
        selector
            .and_then(|s| s.get("matchLabels"))
            .map(|labels| self.parse_labels(Some(labels)))
            .unwrap_or_default()
    }

    /// Parse an ingress rule
    fn parse_ingress_rule(&self, rule: &serde_yaml::Value) -> Option<IngressRule> {
        let from = rule
            .get("from")
            .and_then(|f| f.as_sequence())
            .map(|peers| peers.iter().filter_map(|p| self.parse_peer(p)).collect())
            .unwrap_or_default();

        let ports = rule
            .get("ports")
            .and_then(|p| p.as_sequence())
            .map(|ports| ports.iter().filter_map(|p| self.parse_port(p)).collect())
            .unwrap_or_default();

        Some(IngressRule { from, ports })
    }

    /// Parse an egress rule
    fn parse_egress_rule(&self, rule: &serde_yaml::Value) -> Option<EgressRule> {
        let to = rule
            .get("to")
            .and_then(|t| t.as_sequence())
            .map(|peers| peers.iter().filter_map(|p| self.parse_peer(p)).collect())
            .unwrap_or_default();

        let ports = rule
            .get("ports")
            .and_then(|p| p.as_sequence())
            .map(|ports| ports.iter().filter_map(|p| self.parse_port(p)).collect())
            .unwrap_or_default();

        Some(EgressRule { to, ports })
    }

    /// Parse a network policy peer
    fn parse_peer(&self, peer: &serde_yaml::Value) -> Option<NetworkPolicyPeer> {
        let pod_selector = peer
            .get("podSelector")
            .and_then(|s| s.get("matchLabels"))
            .map(|labels| self.parse_labels(Some(labels)));

        let namespace_selector = peer
            .get("namespaceSelector")
            .and_then(|s| s.get("matchLabels"))
            .map(|labels| self.parse_labels(Some(labels)));

        let ip_block = peer.get("ipBlock").and_then(|block| {
            let cidr = block.get("cidr")?.as_str()?.to_string();
            let except = block
                .get("except")
                .and_then(|e| e.as_sequence())
                .map(|seq| {
                    seq.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            Some(IpBlock { cidr, except })
        });

        Some(NetworkPolicyPeer {
            pod_selector,
            namespace_selector,
            ip_block,
        })
    }

    /// Parse a port specification
    fn parse_port(&self, port: &serde_yaml::Value) -> Option<NetworkPolicyPort> {
        let protocol = port.get("protocol").and_then(|p| p.as_str()).map(String::from);

        let port_value = port.get("port").and_then(|p| {
            if let Some(num) = p.as_u64() {
                Some(PortValue::Number(num as u16))
            } else if let Some(name) = p.as_str() {
                Some(PortValue::Named(name.to_string()))
            } else {
                None
            }
        });

        let end_port = port.get("endPort").and_then(|p| p.as_u64()).map(|p| p as u16);

        Some(NetworkPolicyPort {
            protocol,
            port: port_value,
            end_port,
        })
    }

    /// Run the network policy analysis
    pub fn analyze(&self) -> NetworkPolicyAnalysisResults {
        let mut findings = Vec::new();
        let mut coverage_by_namespace = HashMap::new();

        // Analyze each namespace
        for namespace in &self.namespaces {
            let namespace_policies: Vec<_> = self
                .policies
                .iter()
                .filter(|p| &p.namespace == namespace)
                .collect();

            let namespace_workloads: Vec<_> = self
                .workloads
                .iter()
                .filter(|w| &w.namespace == namespace)
                .collect();

            // Check for default deny policies
            let has_default_deny_ingress = namespace_policies.iter().any(|p| self.is_default_deny_ingress(p));
            let has_default_deny_egress = namespace_policies.iter().any(|p| self.is_default_deny_egress(p));

            if !has_default_deny_ingress && !namespace_workloads.is_empty() {
                findings.push(NetworkPolicyFinding {
                    finding_type: NetworkPolicyFindingType::NoDefaultDenyIngress,
                    severity: NetworkPolicySeverity::High,
                    namespace: namespace.clone(),
                    policy_name: None,
                    affected_pods: namespace_workloads.iter().map(|w| w.name.clone()).collect(),
                    description: format!(
                        "Namespace '{}' lacks a default deny ingress NetworkPolicy",
                        namespace
                    ),
                    remediation: NetworkPolicyFindingType::NoDefaultDenyIngress.remediation().to_string(),
                    details: HashMap::new(),
                });
            }

            if !has_default_deny_egress && !namespace_workloads.is_empty() {
                findings.push(NetworkPolicyFinding {
                    finding_type: NetworkPolicyFindingType::NoDefaultDenyEgress,
                    severity: NetworkPolicySeverity::Medium,
                    namespace: namespace.clone(),
                    policy_name: None,
                    affected_pods: namespace_workloads.iter().map(|w| w.name.clone()).collect(),
                    description: format!(
                        "Namespace '{}' lacks a default deny egress NetworkPolicy",
                        namespace
                    ),
                    remediation: NetworkPolicyFindingType::NoDefaultDenyEgress.remediation().to_string(),
                    details: HashMap::new(),
                });
            }

            // Check if default deny exists, warn about DNS
            if has_default_deny_egress {
                let has_dns_allow = namespace_policies.iter().any(|p| self.allows_dns(p));
                if !has_dns_allow {
                    findings.push(NetworkPolicyFinding {
                        finding_type: NetworkPolicyFindingType::DnsEgressBlocked,
                        severity: NetworkPolicySeverity::Info,
                        namespace: namespace.clone(),
                        policy_name: None,
                        affected_pods: namespace_workloads.iter().map(|w| w.name.clone()).collect(),
                        description: format!(
                            "Namespace '{}' has default deny egress but no explicit DNS allow rule",
                            namespace
                        ),
                        remediation: NetworkPolicyFindingType::DnsEgressBlocked.remediation().to_string(),
                        details: HashMap::new(),
                    });
                }
            }

            // Check workload coverage
            let covered_pods = self.count_covered_workloads(&namespace_workloads, &namespace_policies);

            coverage_by_namespace.insert(
                namespace.clone(),
                NamespaceCoverage {
                    namespace: namespace.clone(),
                    total_pods: namespace_workloads.len(),
                    covered_pods,
                    has_default_deny_ingress,
                    has_default_deny_egress,
                    policy_count: namespace_policies.len(),
                },
            );

            // Find uncovered workloads
            if covered_pods < namespace_workloads.len() && !has_default_deny_ingress {
                let uncovered: Vec<_> = namespace_workloads
                    .iter()
                    .filter(|w| !self.is_workload_covered(w, &namespace_policies))
                    .map(|w| w.name.clone())
                    .collect();

                if !uncovered.is_empty() {
                    findings.push(NetworkPolicyFinding {
                        finding_type: NetworkPolicyFindingType::MissingPolicies,
                        severity: NetworkPolicySeverity::High,
                        namespace: namespace.clone(),
                        policy_name: None,
                        affected_pods: uncovered,
                        description: format!(
                            "Workloads in namespace '{}' have no NetworkPolicy coverage",
                            namespace
                        ),
                        remediation: NetworkPolicyFindingType::MissingPolicies.remediation().to_string(),
                        details: HashMap::new(),
                    });
                }
            }

            // Analyze individual policies
            for policy in &namespace_policies {
                findings.extend(self.analyze_policy(policy));
            }
        }

        let summary = self.calculate_summary(&findings, &coverage_by_namespace);

        NetworkPolicyAnalysisResults {
            findings,
            namespaces_analyzed: self.namespaces.len(),
            policies_analyzed: self.policies.len(),
            workloads_analyzed: self.workloads.len(),
            summary,
            coverage_by_namespace,
        }
    }

    /// Analyze a single policy
    fn analyze_policy(&self, policy: &ParsedNetworkPolicy) -> Vec<NetworkPolicyFinding> {
        let mut findings = Vec::new();

        // Check for deprecated API version
        if !policy.api_version.contains("networking.k8s.io") {
            findings.push(NetworkPolicyFinding {
                finding_type: NetworkPolicyFindingType::DeprecatedApiVersion,
                severity: NetworkPolicySeverity::Low,
                namespace: policy.namespace.clone(),
                policy_name: Some(policy.name.clone()),
                affected_pods: Vec::new(),
                description: format!(
                    "NetworkPolicy '{}' uses deprecated API version '{}'",
                    policy.name, policy.api_version
                ),
                remediation: NetworkPolicyFindingType::DeprecatedApiVersion.remediation().to_string(),
                details: HashMap::from([
                    ("api_version".to_string(), policy.api_version.clone()),
                ]),
            });
        }

        // Check ingress rules
        for rule in &policy.ingress_rules {
            // Check for allow-all ingress (empty from)
            if rule.from.is_empty() && !policy.ingress_rules.is_empty() {
                // Empty from with rules means allow all
                if policy.ingress_rules.len() == 1 {
                    findings.push(NetworkPolicyFinding {
                        finding_type: NetworkPolicyFindingType::AllowAllIngress,
                        severity: NetworkPolicySeverity::Critical,
                        namespace: policy.namespace.clone(),
                        policy_name: Some(policy.name.clone()),
                        affected_pods: Vec::new(),
                        description: format!(
                            "NetworkPolicy '{}' allows all ingress traffic",
                            policy.name
                        ),
                        remediation: NetworkPolicyFindingType::AllowAllIngress.remediation().to_string(),
                        details: HashMap::new(),
                    });
                }
            }

            // Check for sensitive port exposure
            for port in &rule.ports {
                if let Some(PortValue::Number(port_num)) = &port.port {
                    if let Some((_, service)) = SENSITIVE_PORTS.iter().find(|(p, _)| p == port_num) {
                        findings.push(NetworkPolicyFinding {
                            finding_type: NetworkPolicyFindingType::ExposedSensitivePorts,
                            severity: NetworkPolicySeverity::High,
                            namespace: policy.namespace.clone(),
                            policy_name: Some(policy.name.clone()),
                            affected_pods: Vec::new(),
                            description: format!(
                                "NetworkPolicy '{}' exposes sensitive port {} ({})",
                                policy.name, port_num, service
                            ),
                            remediation: NetworkPolicyFindingType::ExposedSensitivePorts.remediation().to_string(),
                            details: HashMap::from([
                                ("port".to_string(), port_num.to_string()),
                                ("service".to_string(), service.to_string()),
                            ]),
                        });
                    }
                }
            }

            // Check for cross-namespace access and empty selectors
            for peer in &rule.from {
                if peer.namespace_selector.is_some() && peer.namespace_selector.as_ref().map(|s| s.is_empty()).unwrap_or(false) {
                    findings.push(NetworkPolicyFinding {
                        finding_type: NetworkPolicyFindingType::EmptyNamespaceSelector,
                        severity: NetworkPolicySeverity::Medium,
                        namespace: policy.namespace.clone(),
                        policy_name: Some(policy.name.clone()),
                        affected_pods: Vec::new(),
                        description: format!(
                            "NetworkPolicy '{}' has empty namespace selector (allows from any namespace)",
                            policy.name
                        ),
                        remediation: NetworkPolicyFindingType::EmptyNamespaceSelector.remediation().to_string(),
                        details: HashMap::new(),
                    });
                }

                if peer.namespace_selector.is_some() && !peer.namespace_selector.as_ref().map(|s| s.is_empty()).unwrap_or(true) {
                    findings.push(NetworkPolicyFinding {
                        finding_type: NetworkPolicyFindingType::CrossNamespaceAllowed,
                        severity: NetworkPolicySeverity::Medium,
                        namespace: policy.namespace.clone(),
                        policy_name: Some(policy.name.clone()),
                        affected_pods: Vec::new(),
                        description: format!(
                            "NetworkPolicy '{}' allows cross-namespace ingress traffic",
                            policy.name
                        ),
                        remediation: NetworkPolicyFindingType::CrossNamespaceAllowed.remediation().to_string(),
                        details: HashMap::new(),
                    });
                }

                // Check for overly permissive CIDR
                if let Some(ip_block) = &peer.ip_block {
                    if ip_block.cidr == "0.0.0.0/0" {
                        findings.push(NetworkPolicyFinding {
                            finding_type: NetworkPolicyFindingType::OverlyPermissiveCidr,
                            severity: NetworkPolicySeverity::Medium,
                            namespace: policy.namespace.clone(),
                            policy_name: Some(policy.name.clone()),
                            affected_pods: Vec::new(),
                            description: format!(
                                "NetworkPolicy '{}' allows ingress from 0.0.0.0/0",
                                policy.name
                            ),
                            remediation: NetworkPolicyFindingType::OverlyPermissiveCidr.remediation().to_string(),
                            details: HashMap::from([("cidr".to_string(), ip_block.cidr.clone())]),
                        });
                    }
                }
            }
        }

        // Check egress rules
        for rule in &policy.egress_rules {
            // Check for allow-all egress
            if rule.to.is_empty() && !policy.egress_rules.is_empty() {
                if policy.egress_rules.len() == 1 && rule.ports.is_empty() {
                    findings.push(NetworkPolicyFinding {
                        finding_type: NetworkPolicyFindingType::AllowAllEgress,
                        severity: NetworkPolicySeverity::High,
                        namespace: policy.namespace.clone(),
                        policy_name: Some(policy.name.clone()),
                        affected_pods: Vec::new(),
                        description: format!(
                            "NetworkPolicy '{}' allows all egress traffic",
                            policy.name
                        ),
                        remediation: NetworkPolicyFindingType::AllowAllEgress.remediation().to_string(),
                        details: HashMap::new(),
                    });
                }
            }

            for peer in &rule.to {
                // Check for internet egress
                if let Some(ip_block) = &peer.ip_block {
                    if ip_block.cidr == "0.0.0.0/0" {
                        findings.push(NetworkPolicyFinding {
                            finding_type: NetworkPolicyFindingType::InternetEgress,
                            severity: NetworkPolicySeverity::Medium,
                            namespace: policy.namespace.clone(),
                            policy_name: Some(policy.name.clone()),
                            affected_pods: Vec::new(),
                            description: format!(
                                "NetworkPolicy '{}' allows egress to 0.0.0.0/0 (internet)",
                                policy.name
                            ),
                            remediation: NetworkPolicyFindingType::InternetEgress.remediation().to_string(),
                            details: HashMap::new(),
                        });
                    }

                    // Check for metadata service access
                    for metadata_ip in METADATA_SERVICE_IPS {
                        if self.cidr_contains_ip(&ip_block.cidr, metadata_ip)
                            && !ip_block.except.iter().any(|e| self.cidr_contains_ip(e, metadata_ip))
                        {
                            findings.push(NetworkPolicyFinding {
                                finding_type: NetworkPolicyFindingType::MetadataServiceAccess,
                                severity: NetworkPolicySeverity::High,
                                namespace: policy.namespace.clone(),
                                policy_name: Some(policy.name.clone()),
                                affected_pods: Vec::new(),
                                description: format!(
                                    "NetworkPolicy '{}' allows access to cloud metadata service ({})",
                                    policy.name, metadata_ip
                                ),
                                remediation: NetworkPolicyFindingType::MetadataServiceAccess.remediation().to_string(),
                                details: HashMap::from([
                                    ("metadata_ip".to_string(), metadata_ip.to_string()),
                                ]),
                            });
                        }
                    }
                }
            }
        }

        // Check for empty pod selector (applies to all pods)
        if policy.pod_selector.is_empty() {
            findings.push(NetworkPolicyFinding {
                finding_type: NetworkPolicyFindingType::EmptyPodSelector,
                severity: NetworkPolicySeverity::Low,
                namespace: policy.namespace.clone(),
                policy_name: Some(policy.name.clone()),
                affected_pods: Vec::new(),
                description: format!(
                    "NetworkPolicy '{}' has empty pod selector (applies to all pods in namespace)",
                    policy.name
                ),
                remediation: NetworkPolicyFindingType::EmptyPodSelector.remediation().to_string(),
                details: HashMap::new(),
            });
        }

        findings
    }

    /// Check if a policy is a default deny ingress
    fn is_default_deny_ingress(&self, policy: &ParsedNetworkPolicy) -> bool {
        policy.pod_selector.is_empty()
            && (policy.policy_types.contains(&"Ingress".to_string()) || policy.policy_types.is_empty())
            && policy.ingress_rules.is_empty()
    }

    /// Check if a policy is a default deny egress
    fn is_default_deny_egress(&self, policy: &ParsedNetworkPolicy) -> bool {
        policy.pod_selector.is_empty()
            && policy.policy_types.contains(&"Egress".to_string())
            && policy.egress_rules.is_empty()
    }

    /// Check if a policy allows DNS egress
    fn allows_dns(&self, policy: &ParsedNetworkPolicy) -> bool {
        for rule in &policy.egress_rules {
            for port in &rule.ports {
                if let Some(PortValue::Number(53)) = port.port {
                    return true;
                }
            }
        }
        false
    }

    /// Count covered workloads in a namespace
    fn count_covered_workloads(
        &self,
        workloads: &[&WorkloadInfo],
        policies: &[&ParsedNetworkPolicy],
    ) -> usize {
        workloads
            .iter()
            .filter(|w| self.is_workload_covered(w, policies))
            .count()
    }

    /// Check if a workload is covered by any policy
    fn is_workload_covered(&self, workload: &WorkloadInfo, policies: &[&ParsedNetworkPolicy]) -> bool {
        policies.iter().any(|p| self.policy_matches_workload(p, workload))
    }

    /// Check if a policy matches a workload
    fn policy_matches_workload(&self, policy: &ParsedNetworkPolicy, workload: &WorkloadInfo) -> bool {
        if policy.pod_selector.is_empty() {
            return true;
        }

        policy
            .pod_selector
            .iter()
            .all(|(key, value)| workload.labels.get(key) == Some(value))
    }

    /// Check if a CIDR contains an IP (simplified)
    fn cidr_contains_ip(&self, cidr: &str, ip: &str) -> bool {
        if cidr == "0.0.0.0/0" {
            return true;
        }
        // Simple prefix matching for common cases
        if let Some(prefix) = cidr.split('/').next() {
            if prefix == ip {
                return true;
            }
            // Check if IP starts with CIDR prefix (simplified)
            let cidr_parts: Vec<&str> = prefix.split('.').collect();
            let ip_parts: Vec<&str> = ip.split('.').collect();
            if cidr_parts.len() >= 3 && ip_parts.len() == 4 {
                return cidr_parts[0..3] == ip_parts[0..3];
            }
        }
        false
    }

    /// Calculate summary statistics
    fn calculate_summary(
        &self,
        findings: &[NetworkPolicyFinding],
        coverage: &HashMap<String, NamespaceCoverage>,
    ) -> NetworkPolicySummary {
        let mut summary = NetworkPolicySummary {
            critical_count: 0,
            high_count: 0,
            medium_count: 0,
            low_count: 0,
            info_count: 0,
            namespaces_without_default_deny: 0,
            exposed_sensitive_ports: 0,
            uncovered_workloads: 0,
        };

        for finding in findings {
            match finding.severity {
                NetworkPolicySeverity::Critical => summary.critical_count += 1,
                NetworkPolicySeverity::High => summary.high_count += 1,
                NetworkPolicySeverity::Medium => summary.medium_count += 1,
                NetworkPolicySeverity::Low => summary.low_count += 1,
                NetworkPolicySeverity::Info => summary.info_count += 1,
            }

            if finding.finding_type == NetworkPolicyFindingType::ExposedSensitivePorts {
                summary.exposed_sensitive_ports += 1;
            }
        }

        for cov in coverage.values() {
            if !cov.has_default_deny_ingress {
                summary.namespaces_without_default_deny += 1;
            }
            summary.uncovered_workloads += cov.total_pods.saturating_sub(cov.covered_pods);
        }

        summary
    }
}

impl Default for NetworkPolicyAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_deny_ingress_policy() -> serde_yaml::Value {
        serde_yaml::from_str(r#"
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
  namespace: default
spec:
  podSelector: {}
  policyTypes:
  - Ingress
"#).unwrap()
    }

    fn allow_all_ingress_policy() -> serde_yaml::Value {
        serde_yaml::from_str(r#"
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-all
  namespace: default
spec:
  podSelector: {}
  ingress:
  - {}
  policyTypes:
  - Ingress
"#).unwrap()
    }

    fn internet_egress_policy() -> serde_yaml::Value {
        serde_yaml::from_str(r#"
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-internet
  namespace: default
spec:
  podSelector:
    matchLabels:
      app: web
  egress:
  - to:
    - ipBlock:
        cidr: 0.0.0.0/0
  policyTypes:
  - Egress
"#).unwrap()
    }

    fn sensitive_port_policy() -> serde_yaml::Value {
        serde_yaml::from_str(r#"
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-ssh
  namespace: default
spec:
  podSelector:
    matchLabels:
      app: bastion
  ingress:
  - ports:
    - protocol: TCP
      port: 22
  policyTypes:
  - Ingress
"#).unwrap()
    }

    fn test_deployment() -> serde_yaml::Value {
        serde_yaml::from_str(r#"
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx
  namespace: default
spec:
  template:
    metadata:
      labels:
        app: nginx
    spec:
      containers:
      - name: nginx
        image: nginx
"#).unwrap()
    }

    #[test]
    fn test_detect_no_default_deny() {
        let mut analyzer = NetworkPolicyAnalyzer::new();
        analyzer.add_workload(&test_deployment());

        let results = analyzer.analyze();
        assert!(results.findings.iter().any(|f| f.finding_type == NetworkPolicyFindingType::NoDefaultDenyIngress));
    }

    #[test]
    fn test_default_deny_present() {
        let mut analyzer = NetworkPolicyAnalyzer::new();
        analyzer.add_policy(&default_deny_ingress_policy());
        analyzer.add_workload(&test_deployment());

        let results = analyzer.analyze();
        assert!(!results.findings.iter().any(|f| f.finding_type == NetworkPolicyFindingType::NoDefaultDenyIngress));
    }

    #[test]
    fn test_detect_allow_all_ingress() {
        let mut analyzer = NetworkPolicyAnalyzer::new();
        analyzer.add_policy(&allow_all_ingress_policy());

        let results = analyzer.analyze();
        assert!(results.findings.iter().any(|f| f.finding_type == NetworkPolicyFindingType::AllowAllIngress));
    }

    #[test]
    fn test_detect_internet_egress() {
        let mut analyzer = NetworkPolicyAnalyzer::new();
        analyzer.add_policy(&internet_egress_policy());

        let results = analyzer.analyze();
        assert!(results.findings.iter().any(|f| f.finding_type == NetworkPolicyFindingType::InternetEgress));
    }

    #[test]
    fn test_detect_sensitive_port() {
        let mut analyzer = NetworkPolicyAnalyzer::new();
        analyzer.add_policy(&sensitive_port_policy());

        let results = analyzer.analyze();
        assert!(results.findings.iter().any(|f| f.finding_type == NetworkPolicyFindingType::ExposedSensitivePorts));
    }

    #[test]
    fn test_coverage_calculation() {
        let mut analyzer = NetworkPolicyAnalyzer::new();
        analyzer.add_policy(&default_deny_ingress_policy());
        analyzer.add_workload(&test_deployment());

        let results = analyzer.analyze();
        let coverage = results.coverage_by_namespace.get("default").unwrap();
        assert!(coverage.has_default_deny_ingress);
        assert_eq!(coverage.total_pods, 1);
    }
}
