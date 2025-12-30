//! Kubernetes security types

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct K8sCluster {
    pub name: String,
    pub version: String,
    pub api_server: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PodSecurityStandard {
    Privileged,
    Baseline,
    Restricted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkloadSecurity {
    pub name: String,
    pub namespace: String,
    pub image_vulnerabilities: Vec<String>,
    pub security_context_issues: Vec<String>,
}
