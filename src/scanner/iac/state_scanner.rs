//! Terraform State File Security Scanner
//!
//! Scans Terraform state files for security issues:
//! - Exposed secrets in state (passwords, API keys, tokens)
//! - Sensitive outputs not marked as sensitive
//! - Remote state backend security (encryption, locking)
//! - Drift detection indicators
//! - Orphaned resources
//! - Security-critical resource configurations

#![allow(dead_code)]

use anyhow::{anyhow, Result};
use lazy_static::lazy_static;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

lazy_static! {
    // Secret patterns to detect in state values
    static ref SECRET_PATTERNS: Vec<(&'static str, Regex)> = vec![
        ("AWS Access Key", Regex::new(r#"AKIA[A-Z0-9]{16}"#).unwrap()),
        ("AWS Secret Key", Regex::new(r#"[A-Za-z0-9/+=]{40}"#).unwrap()),
        ("Generic API Key", Regex::new(r#"(?i)api[_-]?key["']?\s*[:=]\s*["']?[A-Za-z0-9_\-]{20,}"#).unwrap()),
        ("Password", Regex::new(r#"(?i)(password|passwd|pwd)\s*[:=]\s*["']?[^\s"']{8,}"#).unwrap()),
        ("Private Key", Regex::new(r#"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----"#).unwrap()),
        ("GitHub Token", Regex::new(r#"ghp_[A-Za-z0-9]{36}"#).unwrap()),
        ("Slack Token", Regex::new(r#"xox[baprs]-[A-Za-z0-9-]+"#).unwrap()),
        ("Azure Client Secret", Regex::new(r#"[A-Za-z0-9_\-~.]{34,}"#).unwrap()),
        ("Google API Key", Regex::new(r#"AIza[A-Za-z0-9_\-]{35}"#).unwrap()),
        ("JWT Token", Regex::new(r#"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"#).unwrap()),
        ("Connection String", Regex::new(r#"(?i)(postgres|mysql|mongodb|redis)://[^:\s]+:[^@\s]+@"#).unwrap()),
        ("Bearer Token", Regex::new(r#"(?i)bearer\s+[A-Za-z0-9_\-.]+"#).unwrap()),
        ("SSH Key", Regex::new(r#"ssh-(?:rsa|ed25519|ecdsa)\s+[A-Za-z0-9+/]+"#).unwrap()),
    ];

    // Sensitive attribute names to check
    static ref SENSITIVE_ATTRIBUTES: Vec<&'static str> = vec![
        "password", "secret", "key", "token", "credential", "auth",
        "private_key", "api_key", "access_key", "secret_key",
        "connection_string", "certificate", "passphrase",
    ];

    // Attribute name patterns that indicate sensitive data
    static ref SENSITIVE_ATTR_PATTERN: Regex = Regex::new(r#"(?i)(password|secret|key|token|credential|auth|certificate)"#).unwrap();
}

/// State scan finding severity
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, PartialOrd)]
#[serde(rename_all = "snake_case")]
pub enum StateFindingSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for StateFindingSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Info => write!(f, "info"),
            Self::Low => write!(f, "low"),
            Self::Medium => write!(f, "medium"),
            Self::High => write!(f, "high"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

/// State scan finding category
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum StateFindingCategory {
    /// Secret exposed in state
    ExposedSecret,
    /// Sensitive output not marked
    SensitiveOutput,
    /// Remote state misconfiguration
    RemoteStateConfig,
    /// Resource drift
    DriftDetected,
    /// Orphaned resource
    OrphanedResource,
    /// Security misconfiguration in resource
    SecurityMisconfiguration,
    /// State file integrity
    StateIntegrity,
}

impl std::fmt::Display for StateFindingCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ExposedSecret => write!(f, "exposed_secret"),
            Self::SensitiveOutput => write!(f, "sensitive_output"),
            Self::RemoteStateConfig => write!(f, "remote_state_config"),
            Self::DriftDetected => write!(f, "drift_detected"),
            Self::OrphanedResource => write!(f, "orphaned_resource"),
            Self::SecurityMisconfiguration => write!(f, "security_misconfiguration"),
            Self::StateIntegrity => write!(f, "state_integrity"),
        }
    }
}

/// State security finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateFinding {
    pub id: String,
    pub category: StateFindingCategory,
    pub severity: StateFindingSeverity,
    pub title: String,
    pub description: String,
    pub remediation: String,
    pub resource_address: Option<String>,
    pub resource_type: Option<String>,
    pub attribute_path: Option<String>,
    pub masked_value: Option<String>,
}

/// Resource information from state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateResource {
    pub address: String,
    pub resource_type: String,
    pub name: String,
    pub provider: String,
    pub module: Option<String>,
    pub mode: String,
    pub tainted: bool,
    pub dependencies: Vec<String>,
    pub sensitive_attributes: Vec<String>,
}

/// Output information from state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateOutput {
    pub name: String,
    pub is_sensitive: bool,
    pub should_be_sensitive: bool,
    pub value_type: String,
}

/// State analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateAnalysisResult {
    pub version: i64,
    pub terraform_version: Option<String>,
    pub serial: i64,
    pub resources: Vec<StateResource>,
    pub outputs: Vec<StateOutput>,
    pub findings: Vec<StateFinding>,
    pub security_score: u8,
    pub summary: StateAnalysisSummary,
}

/// Summary of state analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateAnalysisSummary {
    pub total_resources: usize,
    pub total_outputs: usize,
    pub tainted_resources: usize,
    pub sensitive_outputs: usize,
    pub exposed_secrets_count: usize,
    pub findings_by_severity: HashMap<String, usize>,
    pub findings_by_category: HashMap<String, usize>,
    pub resources_by_type: HashMap<String, usize>,
}

/// Backend configuration analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendAnalysis {
    pub backend_type: String,
    pub is_remote: bool,
    pub has_encryption: bool,
    pub has_locking: bool,
    pub has_versioning: bool,
    pub findings: Vec<StateFinding>,
}

/// Terraform State Scanner
pub struct StateScanner {
    state: Value,
    check_secrets: bool,
    check_outputs: bool,
    check_resources: bool,
}

impl StateScanner {
    /// Create a new state scanner from JSON content
    pub fn from_json(content: &str) -> Result<Self> {
        let state: Value = serde_json::from_str(content)
            .map_err(|e| anyhow!("Failed to parse state file: {}", e))?;

        Ok(Self {
            state,
            check_secrets: true,
            check_outputs: true,
            check_resources: true,
        })
    }

    /// Analyze the state file
    pub fn analyze(&self) -> Result<StateAnalysisResult> {
        let version = self.state.get("version").and_then(|v| v.as_i64()).unwrap_or(0);
        let terraform_version = self.state.get("terraform_version").and_then(|v| v.as_str()).map(String::from);
        let serial = self.state.get("serial").and_then(|v| v.as_i64()).unwrap_or(0);

        let resources = self.extract_resources()?;
        let outputs = self.extract_outputs()?;
        let mut findings = Vec::new();

        // Check for exposed secrets in resources
        if self.check_secrets {
            findings.extend(self.scan_for_secrets(&resources)?);
        }

        // Check output sensitivity
        if self.check_outputs {
            findings.extend(self.check_output_sensitivity(&outputs));
        }

        // Check resource security configurations
        if self.check_resources {
            findings.extend(self.check_resource_security(&resources)?);
        }

        // Check for tainted resources
        findings.extend(self.check_tainted_resources(&resources));

        // Calculate security score
        let security_score = self.calculate_security_score(&findings, &resources);

        // Build summary
        let summary = self.build_summary(&resources, &outputs, &findings);

        Ok(StateAnalysisResult {
            version,
            terraform_version,
            serial,
            resources,
            outputs,
            findings,
            security_score,
            summary,
        })
    }

    /// Extract resources from state
    fn extract_resources(&self) -> Result<Vec<StateResource>> {
        let mut resources = Vec::new();

        if let Some(state_resources) = self.state.get("resources").and_then(|r| r.as_array()) {
            for resource in state_resources {
                let mode = resource.get("mode").and_then(|m| m.as_str()).unwrap_or("managed");
                let resource_type = resource.get("type").and_then(|t| t.as_str()).unwrap_or("unknown");
                let name = resource.get("name").and_then(|n| n.as_str()).unwrap_or("unknown");
                let provider = resource.get("provider").and_then(|p| p.as_str()).unwrap_or("unknown");
                let module = resource.get("module").and_then(|m| m.as_str()).map(String::from);

                // Get instances
                if let Some(instances) = resource.get("instances").and_then(|i| i.as_array()) {
                    for (idx, instance) in instances.iter().enumerate() {
                        let index_suffix = if instances.len() > 1 {
                            format!("[{}]", idx)
                        } else {
                            String::new()
                        };

                        let address = if let Some(ref mod_name) = module {
                            format!("{}.{}.{}{}", mod_name, resource_type, name, index_suffix)
                        } else {
                            format!("{}.{}{}", resource_type, name, index_suffix)
                        };

                        let tainted = instance.get("status").and_then(|s| s.as_str()) == Some("tainted");

                        let dependencies = instance.get("dependencies")
                            .and_then(|d| d.as_array())
                            .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                            .unwrap_or_default();

                        // Find sensitive attributes
                        let sensitive_attrs = self.find_sensitive_attributes(instance);

                        resources.push(StateResource {
                            address,
                            resource_type: resource_type.to_string(),
                            name: name.to_string(),
                            provider: provider.to_string(),
                            module: module.clone(),
                            mode: mode.to_string(),
                            tainted,
                            dependencies,
                            sensitive_attributes: sensitive_attrs,
                        });
                    }
                }
            }
        }

        Ok(resources)
    }

    /// Find sensitive attributes in a resource instance
    fn find_sensitive_attributes(&self, instance: &Value) -> Vec<String> {
        let mut sensitive = Vec::new();

        if let Some(attrs) = instance.get("attributes") {
            self.find_sensitive_in_value(attrs, "", &mut sensitive);
        }

        // Check sensitive_attributes array (Terraform 0.15+)
        if let Some(sens_attrs) = instance.get("sensitive_attributes").and_then(|s| s.as_array()) {
            for attr in sens_attrs {
                if let Some(attr_str) = attr.as_str() {
                    if !sensitive.contains(&attr_str.to_string()) {
                        sensitive.push(attr_str.to_string());
                    }
                }
            }
        }

        sensitive
    }

    /// Recursively find sensitive values
    fn find_sensitive_in_value(&self, value: &Value, path: &str, sensitive: &mut Vec<String>) {
        match value {
            Value::Object(map) => {
                for (key, val) in map {
                    let new_path = if path.is_empty() {
                        key.clone()
                    } else {
                        format!("{}.{}", path, key)
                    };

                    // Check if key is sensitive
                    if SENSITIVE_ATTR_PATTERN.is_match(key) {
                        sensitive.push(new_path.clone());
                    }

                    self.find_sensitive_in_value(val, &new_path, sensitive);
                }
            }
            Value::Array(arr) => {
                for (idx, val) in arr.iter().enumerate() {
                    let new_path = format!("{}[{}]", path, idx);
                    self.find_sensitive_in_value(val, &new_path, sensitive);
                }
            }
            Value::String(s) => {
                // Check if value matches secret patterns
                for (_, pattern) in SECRET_PATTERNS.iter() {
                    if pattern.is_match(s) {
                        if !sensitive.contains(&path.to_string()) {
                            sensitive.push(path.to_string());
                        }
                        break;
                    }
                }
            }
            _ => {}
        }
    }

    /// Extract outputs from state
    fn extract_outputs(&self) -> Result<Vec<StateOutput>> {
        let mut outputs = Vec::new();

        if let Some(state_outputs) = self.state.get("outputs").and_then(|o| o.as_object()) {
            for (name, output) in state_outputs {
                let is_sensitive = output.get("sensitive").and_then(|s| s.as_bool()).unwrap_or(false);

                // Determine if it should be sensitive based on name
                let should_be_sensitive = SENSITIVE_ATTR_PATTERN.is_match(name);

                let value_type = match output.get("value") {
                    Some(Value::String(_)) => "string",
                    Some(Value::Number(_)) => "number",
                    Some(Value::Bool(_)) => "bool",
                    Some(Value::Array(_)) => "list",
                    Some(Value::Object(_)) => "map",
                    _ => "unknown",
                };

                outputs.push(StateOutput {
                    name: name.clone(),
                    is_sensitive,
                    should_be_sensitive,
                    value_type: value_type.to_string(),
                });
            }
        }

        Ok(outputs)
    }

    /// Scan for exposed secrets in resources
    fn scan_for_secrets(&self, resources: &[StateResource]) -> Result<Vec<StateFinding>> {
        let mut findings = Vec::new();

        if let Some(state_resources) = self.state.get("resources").and_then(|r| r.as_array()) {
            for resource in state_resources {
                let resource_type = resource.get("type").and_then(|t| t.as_str()).unwrap_or("unknown");
                let name = resource.get("name").and_then(|n| n.as_str()).unwrap_or("unknown");
                let module = resource.get("module").and_then(|m| m.as_str());

                let address = if let Some(mod_name) = module {
                    format!("{}.{}.{}", mod_name, resource_type, name)
                } else {
                    format!("{}.{}", resource_type, name)
                };

                if let Some(instances) = resource.get("instances").and_then(|i| i.as_array()) {
                    for instance in instances {
                        if let Some(attrs) = instance.get("attributes") {
                            let secrets = self.find_secrets_in_value(attrs, "");
                            for (secret_type, attr_path, masked) in secrets {
                                findings.push(StateFinding {
                                    id: uuid::Uuid::new_v4().to_string(),
                                    category: StateFindingCategory::ExposedSecret,
                                    severity: StateFindingSeverity::Critical,
                                    title: format!("{} exposed in state", secret_type),
                                    description: format!(
                                        "A {} was found in the state file at resource '{}' attribute '{}'",
                                        secret_type.to_lowercase(), address, attr_path
                                    ),
                                    remediation: "Use sensitive variables, AWS Secrets Manager, HashiCorp Vault, or other secret management solutions. Mark the variable as sensitive in Terraform.".to_string(),
                                    resource_address: Some(address.clone()),
                                    resource_type: Some(resource_type.to_string()),
                                    attribute_path: Some(attr_path),
                                    masked_value: Some(masked),
                                });
                            }
                        }
                    }
                }
            }
        }

        Ok(findings)
    }

    /// Find secrets in a JSON value
    fn find_secrets_in_value(&self, value: &Value, path: &str) -> Vec<(String, String, String)> {
        let mut secrets = Vec::new();

        match value {
            Value::Object(map) => {
                for (key, val) in map {
                    let new_path = if path.is_empty() {
                        key.clone()
                    } else {
                        format!("{}.{}", path, key)
                    };
                    secrets.extend(self.find_secrets_in_value(val, &new_path));
                }
            }
            Value::Array(arr) => {
                for (idx, val) in arr.iter().enumerate() {
                    let new_path = format!("{}[{}]", path, idx);
                    secrets.extend(self.find_secrets_in_value(val, &new_path));
                }
            }
            Value::String(s) => {
                for (secret_type, pattern) in SECRET_PATTERNS.iter() {
                    if pattern.is_match(s) {
                        // Mask the secret value
                        let masked = if s.len() > 8 {
                            format!("{}...{}", &s[..4], &s[s.len()-4..])
                        } else {
                            "****".to_string()
                        };
                        secrets.push((secret_type.to_string(), path.to_string(), masked));
                        break;
                    }
                }
            }
            _ => {}
        }

        secrets
    }

    /// Check output sensitivity
    fn check_output_sensitivity(&self, outputs: &[StateOutput]) -> Vec<StateFinding> {
        let mut findings = Vec::new();

        for output in outputs {
            if output.should_be_sensitive && !output.is_sensitive {
                findings.push(StateFinding {
                    id: uuid::Uuid::new_v4().to_string(),
                    category: StateFindingCategory::SensitiveOutput,
                    severity: StateFindingSeverity::High,
                    title: format!("Output '{}' should be marked sensitive", output.name),
                    description: format!(
                        "Output '{}' appears to contain sensitive data based on its name but is not marked as sensitive",
                        output.name
                    ),
                    remediation: "Add 'sensitive = true' to the output block in your Terraform configuration".to_string(),
                    resource_address: None,
                    resource_type: None,
                    attribute_path: Some(format!("output.{}", output.name)),
                    masked_value: None,
                });
            }
        }

        findings
    }

    /// Check resource security configurations
    fn check_resource_security(&self, resources: &[StateResource]) -> Result<Vec<StateFinding>> {
        let mut findings = Vec::new();

        if let Some(state_resources) = self.state.get("resources").and_then(|r| r.as_array()) {
            for resource in state_resources {
                let resource_type = resource.get("type").and_then(|t| t.as_str()).unwrap_or("unknown");
                let name = resource.get("name").and_then(|n| n.as_str()).unwrap_or("unknown");
                let module = resource.get("module").and_then(|m| m.as_str());

                let address = if let Some(mod_name) = module {
                    format!("{}.{}.{}", mod_name, resource_type, name)
                } else {
                    format!("{}.{}", resource_type, name)
                };

                if let Some(instances) = resource.get("instances").and_then(|i| i.as_array()) {
                    for instance in instances {
                        if let Some(attrs) = instance.get("attributes") {
                            findings.extend(self.check_resource_type_security(
                                resource_type,
                                &address,
                                attrs,
                            ));
                        }
                    }
                }
            }
        }

        Ok(findings)
    }

    /// Check security for specific resource types
    fn check_resource_type_security(
        &self,
        resource_type: &str,
        address: &str,
        attrs: &Value,
    ) -> Vec<StateFinding> {
        let mut findings = Vec::new();

        match resource_type {
            // AWS S3 Bucket
            "aws_s3_bucket" | "aws_s3_bucket_acl" => {
                // Check for public ACL
                if let Some(acl) = attrs.get("acl").and_then(|a| a.as_str()) {
                    if acl == "public-read" || acl == "public-read-write" || acl == "authenticated-read" {
                        findings.push(StateFinding {
                            id: uuid::Uuid::new_v4().to_string(),
                            category: StateFindingCategory::SecurityMisconfiguration,
                            severity: StateFindingSeverity::Critical,
                            title: "S3 bucket has public ACL".to_string(),
                            description: format!("S3 bucket '{}' has ACL set to '{}' allowing public access", address, acl),
                            remediation: "Set ACL to 'private' and use bucket policies for access control".to_string(),
                            resource_address: Some(address.to_string()),
                            resource_type: Some(resource_type.to_string()),
                            attribute_path: Some("acl".to_string()),
                            masked_value: None,
                        });
                    }
                }
            }

            // AWS Security Group
            "aws_security_group" | "aws_security_group_rule" => {
                // Check for 0.0.0.0/0 ingress
                if let Some(ingress) = attrs.get("ingress").and_then(|i| i.as_array()) {
                    for rule in ingress {
                        if let Some(cidr_blocks) = rule.get("cidr_blocks").and_then(|c| c.as_array()) {
                            for cidr in cidr_blocks {
                                if cidr.as_str() == Some("0.0.0.0/0") {
                                    let from_port = rule.get("from_port").and_then(|p| p.as_i64()).unwrap_or(0);
                                    let to_port = rule.get("to_port").and_then(|p| p.as_i64()).unwrap_or(0);

                                    findings.push(StateFinding {
                                        id: uuid::Uuid::new_v4().to_string(),
                                        category: StateFindingCategory::SecurityMisconfiguration,
                                        severity: StateFindingSeverity::High,
                                        title: "Security group allows traffic from anywhere".to_string(),
                                        description: format!(
                                            "Security group '{}' allows ingress on ports {}-{} from 0.0.0.0/0",
                                            address, from_port, to_port
                                        ),
                                        remediation: "Restrict CIDR blocks to specific IP ranges".to_string(),
                                        resource_address: Some(address.to_string()),
                                        resource_type: Some(resource_type.to_string()),
                                        attribute_path: Some("ingress.cidr_blocks".to_string()),
                                        masked_value: None,
                                    });
                                }
                            }
                        }
                    }
                }
            }

            // AWS RDS Instance
            "aws_db_instance" | "aws_rds_cluster" => {
                // Check for publicly accessible
                if attrs.get("publicly_accessible").and_then(|p| p.as_bool()) == Some(true) {
                    findings.push(StateFinding {
                        id: uuid::Uuid::new_v4().to_string(),
                        category: StateFindingCategory::SecurityMisconfiguration,
                        severity: StateFindingSeverity::Critical,
                        title: "RDS instance is publicly accessible".to_string(),
                        description: format!("RDS instance '{}' is configured with publicly_accessible = true", address),
                        remediation: "Set publicly_accessible to false and use VPC for access".to_string(),
                        resource_address: Some(address.to_string()),
                        resource_type: Some(resource_type.to_string()),
                        attribute_path: Some("publicly_accessible".to_string()),
                        masked_value: None,
                    });
                }

                // Check for encryption
                if attrs.get("storage_encrypted").and_then(|e| e.as_bool()) == Some(false) {
                    findings.push(StateFinding {
                        id: uuid::Uuid::new_v4().to_string(),
                        category: StateFindingCategory::SecurityMisconfiguration,
                        severity: StateFindingSeverity::High,
                        title: "RDS instance storage not encrypted".to_string(),
                        description: format!("RDS instance '{}' does not have storage encryption enabled", address),
                        remediation: "Enable storage encryption with storage_encrypted = true".to_string(),
                        resource_address: Some(address.to_string()),
                        resource_type: Some(resource_type.to_string()),
                        attribute_path: Some("storage_encrypted".to_string()),
                        masked_value: None,
                    });
                }
            }

            // AWS IAM Policy
            "aws_iam_policy" | "aws_iam_role_policy" => {
                // Check for wildcard permissions
                if let Some(policy) = attrs.get("policy").and_then(|p| p.as_str()) {
                    if policy.contains("\"Action\": \"*\"") || policy.contains("\"Resource\": \"*\"") {
                        findings.push(StateFinding {
                            id: uuid::Uuid::new_v4().to_string(),
                            category: StateFindingCategory::SecurityMisconfiguration,
                            severity: StateFindingSeverity::High,
                            title: "IAM policy uses wildcard permissions".to_string(),
                            description: format!("IAM policy '{}' contains wildcard (*) in Action or Resource", address),
                            remediation: "Follow principle of least privilege - specify exact actions and resources".to_string(),
                            resource_address: Some(address.to_string()),
                            resource_type: Some(resource_type.to_string()),
                            attribute_path: Some("policy".to_string()),
                            masked_value: None,
                        });
                    }
                }
            }

            // AWS EBS Volume
            "aws_ebs_volume" => {
                if attrs.get("encrypted").and_then(|e| e.as_bool()) == Some(false) {
                    findings.push(StateFinding {
                        id: uuid::Uuid::new_v4().to_string(),
                        category: StateFindingCategory::SecurityMisconfiguration,
                        severity: StateFindingSeverity::High,
                        title: "EBS volume not encrypted".to_string(),
                        description: format!("EBS volume '{}' is not encrypted", address),
                        remediation: "Enable EBS encryption with encrypted = true".to_string(),
                        resource_address: Some(address.to_string()),
                        resource_type: Some(resource_type.to_string()),
                        attribute_path: Some("encrypted".to_string()),
                        masked_value: None,
                    });
                }
            }

            // AWS CloudTrail
            "aws_cloudtrail" => {
                if attrs.get("enable_logging").and_then(|e| e.as_bool()) == Some(false) {
                    findings.push(StateFinding {
                        id: uuid::Uuid::new_v4().to_string(),
                        category: StateFindingCategory::SecurityMisconfiguration,
                        severity: StateFindingSeverity::High,
                        title: "CloudTrail logging disabled".to_string(),
                        description: format!("CloudTrail '{}' has logging disabled", address),
                        remediation: "Enable CloudTrail logging with enable_logging = true".to_string(),
                        resource_address: Some(address.to_string()),
                        resource_type: Some(resource_type.to_string()),
                        attribute_path: Some("enable_logging".to_string()),
                        masked_value: None,
                    });
                }
            }

            _ => {}
        }

        findings
    }

    /// Check for tainted resources
    fn check_tainted_resources(&self, resources: &[StateResource]) -> Vec<StateFinding> {
        let mut findings = Vec::new();

        for resource in resources {
            if resource.tainted {
                findings.push(StateFinding {
                    id: uuid::Uuid::new_v4().to_string(),
                    category: StateFindingCategory::DriftDetected,
                    severity: StateFindingSeverity::Medium,
                    title: format!("Resource '{}' is tainted", resource.address),
                    description: "Resource is marked as tainted and will be destroyed and recreated on next apply".to_string(),
                    remediation: "Review the resource state and run terraform apply to recreate, or terraform untaint if the marking was incorrect".to_string(),
                    resource_address: Some(resource.address.clone()),
                    resource_type: Some(resource.resource_type.clone()),
                    attribute_path: None,
                    masked_value: None,
                });
            }
        }

        findings
    }

    /// Calculate security score (0-100)
    fn calculate_security_score(&self, findings: &[StateFinding], resources: &[StateResource]) -> u8 {
        if resources.is_empty() {
            return 100;
        }

        let mut score = 100i32;

        // Deduct points for findings
        for finding in findings {
            match finding.severity {
                StateFindingSeverity::Critical => score -= 25,
                StateFindingSeverity::High => score -= 15,
                StateFindingSeverity::Medium => score -= 10,
                StateFindingSeverity::Low => score -= 5,
                StateFindingSeverity::Info => score -= 2,
            }
        }

        score.max(0).min(100) as u8
    }

    /// Build analysis summary
    fn build_summary(
        &self,
        resources: &[StateResource],
        outputs: &[StateOutput],
        findings: &[StateFinding],
    ) -> StateAnalysisSummary {
        let mut findings_by_severity = HashMap::new();
        let mut findings_by_category = HashMap::new();
        let mut resources_by_type = HashMap::new();

        for finding in findings {
            *findings_by_severity.entry(finding.severity.to_string()).or_insert(0) += 1;
            *findings_by_category.entry(finding.category.to_string()).or_insert(0) += 1;
        }

        for resource in resources {
            *resources_by_type.entry(resource.resource_type.clone()).or_insert(0) += 1;
        }

        let exposed_secrets_count = findings
            .iter()
            .filter(|f| f.category == StateFindingCategory::ExposedSecret)
            .count();

        StateAnalysisSummary {
            total_resources: resources.len(),
            total_outputs: outputs.len(),
            tainted_resources: resources.iter().filter(|r| r.tainted).count(),
            sensitive_outputs: outputs.iter().filter(|o| o.is_sensitive).count(),
            exposed_secrets_count,
            findings_by_severity,
            findings_by_category,
            resources_by_type,
        }
    }
}

/// Analyze Terraform state content
pub fn analyze_state(content: &str) -> Result<StateAnalysisResult> {
    let scanner = StateScanner::from_json(content)?;
    scanner.analyze()
}

/// Analyze backend configuration from Terraform content
pub fn analyze_backend(content: &str) -> Result<BackendAnalysis> {
    let mut findings = Vec::new();
    let mut backend_type = "local".to_string();
    let mut has_encryption = false;
    let mut has_locking = false;
    let mut has_versioning = false;

    // Parse backend configuration
    let backend_pattern = Regex::new(r#"backend\s+"([^"]+)"\s*\{"#).unwrap();
    let encrypt_pattern = Regex::new(r#"(?i)encrypt\s*=\s*true"#).unwrap();
    let lock_pattern = Regex::new(r#"(?i)dynamodb_table\s*="#).unwrap();
    let versioning_pattern = Regex::new(r#"(?i)versioning\s*=\s*true"#).unwrap();

    if let Some(caps) = backend_pattern.captures(content) {
        backend_type = caps.get(1).map(|m| m.as_str()).unwrap_or("local").to_string();
    }

    has_encryption = encrypt_pattern.is_match(content);
    has_locking = lock_pattern.is_match(content);
    has_versioning = versioning_pattern.is_match(content);

    let is_remote = backend_type != "local";

    // Check for issues
    if is_remote && !has_encryption && backend_type == "s3" {
        findings.push(StateFinding {
            id: uuid::Uuid::new_v4().to_string(),
            category: StateFindingCategory::RemoteStateConfig,
            severity: StateFindingSeverity::High,
            title: "S3 backend encryption not enabled".to_string(),
            description: "Remote state stored in S3 is not encrypted at rest".to_string(),
            remediation: "Add 'encrypt = true' to the S3 backend configuration".to_string(),
            resource_address: None,
            resource_type: None,
            attribute_path: Some("backend.s3.encrypt".to_string()),
            masked_value: None,
        });
    }

    if is_remote && !has_locking && backend_type == "s3" {
        findings.push(StateFinding {
            id: uuid::Uuid::new_v4().to_string(),
            category: StateFindingCategory::RemoteStateConfig,
            severity: StateFindingSeverity::Medium,
            title: "S3 backend state locking not configured".to_string(),
            description: "Remote state in S3 does not have DynamoDB locking configured".to_string(),
            remediation: "Add 'dynamodb_table' to the S3 backend configuration for state locking".to_string(),
            resource_address: None,
            resource_type: None,
            attribute_path: Some("backend.s3.dynamodb_table".to_string()),
            masked_value: None,
        });
    }

    Ok(BackendAnalysis {
        backend_type,
        is_remote,
        has_encryption,
        has_locking,
        has_versioning,
        findings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analyze_empty_state() {
        let state = r#"{"version": 4, "resources": [], "outputs": {}}"#;
        let result = analyze_state(state).unwrap();
        assert_eq!(result.resources.len(), 0);
        assert_eq!(result.security_score, 100);
    }

    #[test]
    fn test_detect_exposed_secret() {
        let state = r#"{
            "version": 4,
            "resources": [{
                "type": "aws_db_instance",
                "name": "main",
                "instances": [{
                    "attributes": {
                        "password": "AKIAIOSFODNN7EXAMPLE"
                    }
                }]
            }],
            "outputs": {}
        }"#;

        let result = analyze_state(state).unwrap();
        assert!(result.findings.iter().any(|f| f.category == StateFindingCategory::ExposedSecret));
    }

    #[test]
    fn test_detect_public_rds() {
        let state = r#"{
            "version": 4,
            "resources": [{
                "type": "aws_db_instance",
                "name": "main",
                "instances": [{
                    "attributes": {
                        "publicly_accessible": true
                    }
                }]
            }],
            "outputs": {}
        }"#;

        let result = analyze_state(state).unwrap();
        assert!(result.findings.iter().any(|f|
            f.category == StateFindingCategory::SecurityMisconfiguration &&
            f.title.contains("publicly accessible")
        ));
    }

    #[test]
    fn test_backend_analysis() {
        let config = r#"
terraform {
  backend "s3" {
    bucket         = "my-terraform-state"
    key            = "terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "terraform-locks"
  }
}
"#;

        let result = analyze_backend(config).unwrap();
        assert_eq!(result.backend_type, "s3");
        assert!(result.is_remote);
        assert!(result.has_encryption);
        assert!(result.has_locking);
        assert!(result.findings.is_empty());
    }
}
