//! Terraform Module Security Analyzer
//!
//! Analyzes Terraform modules for security issues including:
//! - Module source validation (registry, GitHub, local)
//! - Version pinning checks
//! - Known vulnerability detection
//! - Input security analysis
//! - Provider version constraints

#![allow(dead_code)]

use anyhow::Result;
use lazy_static::lazy_static;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

lazy_static! {
    // Module source patterns
    static ref REGISTRY_MODULE: Regex = Regex::new(r#"^\s*source\s*=\s*["']([a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+)["']"#).unwrap();
    static ref GITHUB_MODULE: Regex = Regex::new(r#"^\s*source\s*=\s*["'](git(?:hub\.com|@github\.com:|::https://github\.com)[^"']+)["']"#).unwrap();
    static ref GITLAB_MODULE: Regex = Regex::new(r#"^\s*source\s*=\s*["'](git(?:lab\.com|@gitlab\.com:|::https://gitlab\.com)[^"']+)["']"#).unwrap();
    static ref BITBUCKET_MODULE: Regex = Regex::new(r#"^\s*source\s*=\s*["'](bitbucket\.org[^"']+)["']"#).unwrap();
    static ref LOCAL_MODULE: Regex = Regex::new(r#"^\s*source\s*=\s*["'](\./[^"']+|\.\.\/[^"']+)["']"#).unwrap();
    static ref HTTP_MODULE: Regex = Regex::new(r#"^\s*source\s*=\s*["'](https?://[^"']+)["']"#).unwrap();
    static ref S3_MODULE: Regex = Regex::new(r#"^\s*source\s*=\s*["'](s3::[^"']+)["']"#).unwrap();
    static ref GCS_MODULE: Regex = Regex::new(r#"^\s*source\s*=\s*["'](gcs::[^"']+)["']"#).unwrap();

    // Version patterns
    static ref VERSION_PINNED: Regex = Regex::new(r#"^\s*version\s*=\s*["'](\d+\.\d+\.\d+)["']"#).unwrap();
    static ref VERSION_CONSTRAINT: Regex = Regex::new(r#"^\s*version\s*=\s*["']([~>=<!\d\.,\s]+)["']"#).unwrap();
    static ref GIT_REF: Regex = Regex::new(r#"\?ref=([a-fA-F0-9]{40}|v?\d+\.\d+\.\d+)"#).unwrap();
    static ref GIT_TAG: Regex = Regex::new(r#"\?ref=(v?\d+\.\d+\.\d+)"#).unwrap();
    static ref GIT_COMMIT: Regex = Regex::new(r#"\?ref=([a-fA-F0-9]{40})"#).unwrap();

    // Module block pattern
    static ref MODULE_BLOCK: Regex = Regex::new(r#"module\s+"([^"]+)"\s*\{"#).unwrap();

    // Sensitive input patterns (simple patterns without look-around)
    static ref SENSITIVE_DEFAULT: Regex = Regex::new(r#"(?i)default\s*=\s*["'][^"']+["'].*(?:password|secret|key|token|credential)"#).unwrap();
    static ref SENSITIVE_VAR_NAME: Regex = Regex::new(r#"(?i)variable\s+["']([^"']*(?:password|secret|key|token|credential|api_key)[^"']*)["']"#).unwrap();
    static ref SENSITIVE_MARKED: Regex = Regex::new(r#"(?i)sensitive\s*=\s*true"#).unwrap();

    // Provider version pattern
    static ref PROVIDER_VERSION: Regex = Regex::new(r#"^\s*(?:required_)?version\s*=\s*["']([^"']+)["']"#).unwrap();
    static ref PROVIDER_UPPER_BOUND: Regex = Regex::new(r#"<\s*\d+\.\d+"#).unwrap();
    static ref PROVIDER_LOWER_BOUND: Regex = Regex::new(r#">=\s*\d+\.\d+(?:\.\d+)?"#).unwrap();
}

/// Module source type classification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ModuleSourceType {
    /// Terraform Registry (registry.terraform.io)
    Registry,
    /// GitHub repository
    GitHub,
    /// GitLab repository
    GitLab,
    /// Bitbucket repository
    Bitbucket,
    /// Local filesystem path
    Local,
    /// HTTP/HTTPS URL
    Http,
    /// AWS S3 bucket
    S3,
    /// Google Cloud Storage bucket
    Gcs,
    /// Unknown source type
    Unknown,
}

impl std::fmt::Display for ModuleSourceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Registry => write!(f, "registry"),
            Self::GitHub => write!(f, "github"),
            Self::GitLab => write!(f, "gitlab"),
            Self::Bitbucket => write!(f, "bitbucket"),
            Self::Local => write!(f, "local"),
            Self::Http => write!(f, "http"),
            Self::S3 => write!(f, "s3"),
            Self::Gcs => write!(f, "gcs"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

/// Module version pinning status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum VersionPinningStatus {
    /// Exact version pinned (1.2.3)
    Pinned,
    /// Commit SHA pinned
    CommitPinned,
    /// Tag/release pinned
    TagPinned,
    /// Constrained but not exact (~> 1.0, >= 1.0)
    Constrained,
    /// No version specified
    Unpinned,
}

impl std::fmt::Display for VersionPinningStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pinned => write!(f, "pinned"),
            Self::CommitPinned => write!(f, "commit_pinned"),
            Self::TagPinned => write!(f, "tag_pinned"),
            Self::Constrained => write!(f, "constrained"),
            Self::Unpinned => write!(f, "unpinned"),
        }
    }
}

/// Module finding severity
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, PartialOrd)]
#[serde(rename_all = "snake_case")]
pub enum ModuleFindingSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for ModuleFindingSeverity {
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

/// Module finding category
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ModuleFindingCategory {
    /// Version not pinned
    UnpinnedVersion,
    /// Using deprecated module
    DeprecatedModule,
    /// Known vulnerability in module
    KnownVulnerability,
    /// Untrusted source
    UntrustedSource,
    /// Sensitive defaults
    SensitiveDefaults,
    /// Missing sensitive flag
    MissingSensitiveFlag,
    /// Provider version issue
    ProviderVersion,
    /// Module integrity
    Integrity,
}

impl std::fmt::Display for ModuleFindingCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnpinnedVersion => write!(f, "unpinned_version"),
            Self::DeprecatedModule => write!(f, "deprecated_module"),
            Self::KnownVulnerability => write!(f, "known_vulnerability"),
            Self::UntrustedSource => write!(f, "untrusted_source"),
            Self::SensitiveDefaults => write!(f, "sensitive_defaults"),
            Self::MissingSensitiveFlag => write!(f, "missing_sensitive_flag"),
            Self::ProviderVersion => write!(f, "provider_version"),
            Self::Integrity => write!(f, "integrity"),
        }
    }
}

/// Information about a Terraform module reference
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleReference {
    pub name: String,
    pub source: String,
    pub source_type: ModuleSourceType,
    pub version: Option<String>,
    pub version_status: VersionPinningStatus,
    pub line_number: i32,
    pub registry_namespace: Option<String>,
    pub registry_name: Option<String>,
    pub registry_provider: Option<String>,
}

/// Security finding for a module
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleFinding {
    pub id: String,
    pub module_name: String,
    pub category: ModuleFindingCategory,
    pub severity: ModuleFindingSeverity,
    pub title: String,
    pub description: String,
    pub remediation: String,
    pub line_number: i32,
    pub code_snippet: Option<String>,
}

/// Input variable security analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputSecurityInfo {
    pub name: String,
    pub has_default: bool,
    pub is_sensitive: bool,
    pub should_be_sensitive: bool,
    pub has_hardcoded_secret: bool,
    pub line_number: i32,
}

/// Module security analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleAnalysisResult {
    pub modules: Vec<ModuleReference>,
    pub findings: Vec<ModuleFinding>,
    pub inputs: Vec<InputSecurityInfo>,
    pub security_score: u8,
    pub summary: ModuleAnalysisSummary,
}

/// Summary of module analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleAnalysisSummary {
    pub total_modules: usize,
    pub registry_modules: usize,
    pub git_modules: usize,
    pub local_modules: usize,
    pub http_modules: usize,
    pub pinned_count: usize,
    pub unpinned_count: usize,
    pub findings_by_severity: HashMap<String, usize>,
    pub findings_by_category: HashMap<String, usize>,
}

/// Known vulnerable module entry
#[derive(Debug, Clone)]
pub struct KnownVulnerableModule {
    pub source_pattern: &'static str,
    pub affected_versions: &'static str,
    pub description: &'static str,
    pub severity: ModuleFindingSeverity,
    pub cve: Option<&'static str>,
}

/// Known vulnerable/deprecated modules database
const KNOWN_VULNERABLE_MODULES: &[KnownVulnerableModule] = &[
    KnownVulnerableModule {
        source_pattern: "cloudposse/terraform-aws-s3-bucket",
        affected_versions: "< 0.38.0",
        description: "S3 bucket module with public access misconfiguration",
        severity: ModuleFindingSeverity::High,
        cve: None,
    },
    KnownVulnerableModule {
        source_pattern: "terraform-aws-modules/vpc/aws",
        affected_versions: "< 2.0.0",
        description: "VPC module with NAT gateway security issues",
        severity: ModuleFindingSeverity::Medium,
        cve: None,
    },
    // Add more known vulnerable modules as needed
];

/// Deprecated module patterns
const DEPRECATED_MODULES: &[(&str, &str)] = &[
    ("terraform-aws-modules/autoscaling/aws", "Use aws_autoscaling_group resource directly"),
    ("hashicorp/consul/aws", "Use hashicorp/consul-ecs/aws for ECS deployments"),
];

/// Module Security Analyzer
pub struct ModuleAnalyzer {
    content: String,
    filename: String,
    check_known_vulns: bool,
}

impl ModuleAnalyzer {
    /// Create a new module analyzer
    pub fn new(content: &str, filename: &str) -> Self {
        Self {
            content: content.to_string(),
            filename: filename.to_string(),
            check_known_vulns: true,
        }
    }

    /// Analyze modules in the Terraform content
    pub fn analyze(&self) -> Result<ModuleAnalysisResult> {
        let modules = self.extract_modules()?;
        let inputs = self.extract_inputs()?;
        let mut findings = Vec::new();

        // Check each module for security issues
        for module in &modules {
            findings.extend(self.check_module_security(module));
        }

        // Check inputs for sensitive value issues
        for input in &inputs {
            findings.extend(self.check_input_security(input));
        }

        // Check provider versions
        findings.extend(self.check_provider_versions()?);

        // Calculate security score
        let security_score = self.calculate_security_score(&modules, &findings);

        // Build summary
        let summary = self.build_summary(&modules, &findings);

        Ok(ModuleAnalysisResult {
            modules,
            findings,
            inputs,
            security_score,
            summary,
        })
    }

    /// Extract module references from content
    fn extract_modules(&self) -> Result<Vec<ModuleReference>> {
        let mut modules = Vec::new();
        let lines: Vec<&str> = self.content.lines().collect();

        let mut current_module: Option<(String, i32)> = None;
        let mut source: Option<String> = None;
        let mut version: Option<String> = None;
        let mut brace_count = 0;

        for (line_idx, line) in lines.iter().enumerate() {
            let line_num = (line_idx + 1) as i32;

            // Check for module block start
            if let Some(caps) = MODULE_BLOCK.captures(line) {
                let module_name = caps.get(1).map(|m| m.as_str()).unwrap_or("unknown");
                current_module = Some((module_name.to_string(), line_num));
                brace_count = line.chars().filter(|c| *c == '{').count();
                brace_count -= line.chars().filter(|c| *c == '}').count();
                source = None;
                version = None;
            } else if current_module.is_some() {
                brace_count += line.chars().filter(|c| *c == '{').count();
                brace_count -= line.chars().filter(|c| *c == '}').count();

                // Check for source
                if source.is_none() {
                    source = self.extract_source(line);
                }

                // Check for version
                if version.is_none() {
                    version = self.extract_version(line);
                }

                // End of module block
                if brace_count == 0 {
                    if let (Some((name, start_line)), Some(src)) = (&current_module, &source) {
                        let (source_type, registry_parts) = self.classify_source(src);
                        let version_status = self.determine_version_status(src, &version);

                        modules.push(ModuleReference {
                            name: name.clone(),
                            source: src.clone(),
                            source_type,
                            version: version.clone(),
                            version_status,
                            line_number: *start_line,
                            registry_namespace: registry_parts.0,
                            registry_name: registry_parts.1,
                            registry_provider: registry_parts.2,
                        });
                    }
                    current_module = None;
                    source = None;
                    version = None;
                }
            }
        }

        Ok(modules)
    }

    /// Extract source from a line
    fn extract_source(&self, line: &str) -> Option<String> {
        let trimmed = line.trim();
        if trimmed.starts_with("source") {
            // Extract value between quotes
            let start = trimmed.find('"').or_else(|| trimmed.find('\''))?;
            let end_char = if trimmed.chars().nth(start) == Some('"') { '"' } else { '\'' };
            let rest = &trimmed[start + 1..];
            let end = rest.find(end_char)?;
            Some(rest[..end].to_string())
        } else {
            None
        }
    }

    /// Extract version from a line
    fn extract_version(&self, line: &str) -> Option<String> {
        if let Some(caps) = VERSION_PINNED.captures(line) {
            return caps.get(1).map(|m| m.as_str().to_string());
        }
        if let Some(caps) = VERSION_CONSTRAINT.captures(line) {
            return caps.get(1).map(|m| m.as_str().to_string());
        }
        None
    }

    /// Classify module source type
    fn classify_source(&self, source: &str) -> (ModuleSourceType, (Option<String>, Option<String>, Option<String>)) {
        // Check for registry module (namespace/name/provider)
        if let Some(caps) = REGISTRY_MODULE.captures(&format!("source = \"{}\"", source)) {
            let parts: Vec<&str> = caps.get(1).map(|m| m.as_str()).unwrap_or("").split('/').collect();
            if parts.len() == 3 {
                return (
                    ModuleSourceType::Registry,
                    (Some(parts[0].to_string()), Some(parts[1].to_string()), Some(parts[2].to_string())),
                );
            }
        }

        let source_type = if source.contains("github.com") || source.starts_with("git@github.com") {
            ModuleSourceType::GitHub
        } else if source.contains("gitlab.com") || source.starts_with("git@gitlab.com") {
            ModuleSourceType::GitLab
        } else if source.contains("bitbucket.org") {
            ModuleSourceType::Bitbucket
        } else if source.starts_with("./") || source.starts_with("../") {
            ModuleSourceType::Local
        } else if source.starts_with("http://") || source.starts_with("https://") {
            ModuleSourceType::Http
        } else if source.starts_with("s3::") {
            ModuleSourceType::S3
        } else if source.starts_with("gcs::") {
            ModuleSourceType::Gcs
        } else if source.split('/').count() == 3 && !source.contains("://") && !source.starts_with("git") {
            return (
                ModuleSourceType::Registry,
                {
                    let parts: Vec<&str> = source.split('/').collect();
                    (Some(parts[0].to_string()), Some(parts[1].to_string()), Some(parts[2].to_string()))
                },
            );
        } else {
            ModuleSourceType::Unknown
        };

        (source_type, (None, None, None))
    }

    /// Determine version pinning status
    fn determine_version_status(&self, source: &str, version: &Option<String>) -> VersionPinningStatus {
        // Check for git commit reference
        if GIT_COMMIT.is_match(source) {
            return VersionPinningStatus::CommitPinned;
        }

        // Check for git tag reference
        if GIT_TAG.is_match(source) {
            return VersionPinningStatus::TagPinned;
        }

        // Check version field
        if let Some(ver) = version {
            // Exact version (x.y.z)
            if Regex::new(r"^\d+\.\d+\.\d+$").unwrap().is_match(ver) {
                return VersionPinningStatus::Pinned;
            }
            // Has constraints
            if ver.contains('~') || ver.contains('>') || ver.contains('<') || ver.contains('!') {
                return VersionPinningStatus::Constrained;
            }
        }

        VersionPinningStatus::Unpinned
    }

    /// Extract input variables from content
    fn extract_inputs(&self) -> Result<Vec<InputSecurityInfo>> {
        let mut inputs = Vec::new();
        let lines: Vec<&str> = self.content.lines().collect();

        let mut in_variable = false;
        let mut var_name = String::new();
        let mut var_start_line = 0;
        let mut has_default = false;
        let mut is_sensitive = false;
        let mut should_be_sensitive = false;
        let mut has_hardcoded_secret = false;
        let mut brace_count = 0;

        for (line_idx, line) in lines.iter().enumerate() {
            let line_num = (line_idx + 1) as i32;

            // Check for variable block start
            if let Some(caps) = SENSITIVE_VAR_NAME.captures(line) {
                var_name = caps.get(1).map(|m| m.as_str()).unwrap_or("").to_string();
                in_variable = true;
                var_start_line = line_num;
                has_default = false;
                is_sensitive = false;
                should_be_sensitive = var_name.to_lowercase().contains("password")
                    || var_name.to_lowercase().contains("secret")
                    || var_name.to_lowercase().contains("token")
                    || var_name.to_lowercase().contains("key")
                    || var_name.to_lowercase().contains("credential");
                has_hardcoded_secret = false;
                brace_count = line.chars().filter(|c| *c == '{').count();
                brace_count -= line.chars().filter(|c| *c == '}').count();
            } else if line.trim().starts_with("variable") && line.contains("{") {
                // Non-sensitive variable
                let trimmed = line.trim();
                let start = trimmed.find('"').unwrap_or(0) + 1;
                let rest = &trimmed[start..];
                let end = rest.find('"').unwrap_or(rest.len());
                var_name = rest[..end].to_string();
                in_variable = true;
                var_start_line = line_num;
                has_default = false;
                is_sensitive = false;
                should_be_sensitive = var_name.to_lowercase().contains("password")
                    || var_name.to_lowercase().contains("secret")
                    || var_name.to_lowercase().contains("token")
                    || var_name.to_lowercase().contains("api_key")
                    || var_name.to_lowercase().contains("credential");
                has_hardcoded_secret = false;
                brace_count = line.chars().filter(|c| *c == '{').count();
                brace_count -= line.chars().filter(|c| *c == '}').count();
            } else if in_variable {
                brace_count += line.chars().filter(|c| *c == '{').count();
                brace_count -= line.chars().filter(|c| *c == '}').count();

                // Check for default
                if line.contains("default") && line.contains("=") {
                    has_default = true;
                    // Check for hardcoded secret in default
                    if should_be_sensitive && (line.contains('"') || line.contains('\'')) {
                        let trimmed = line.trim();
                        // Not empty string or null
                        if !trimmed.contains(r#"""""#) && !trimmed.contains("''") && !trimmed.contains("null") {
                            has_hardcoded_secret = true;
                        }
                    }
                }

                // Check for sensitive flag
                if line.contains("sensitive") && line.contains("true") {
                    is_sensitive = true;
                }

                // End of variable block
                if brace_count == 0 {
                    inputs.push(InputSecurityInfo {
                        name: var_name.clone(),
                        has_default,
                        is_sensitive,
                        should_be_sensitive,
                        has_hardcoded_secret,
                        line_number: var_start_line,
                    });
                    in_variable = false;
                }
            }
        }

        Ok(inputs)
    }

    /// Check a module for security issues
    fn check_module_security(&self, module: &ModuleReference) -> Vec<ModuleFinding> {
        let mut findings = Vec::new();

        // Check version pinning
        if module.version_status == VersionPinningStatus::Unpinned {
            findings.push(ModuleFinding {
                id: uuid::Uuid::new_v4().to_string(),
                module_name: module.name.clone(),
                category: ModuleFindingCategory::UnpinnedVersion,
                severity: ModuleFindingSeverity::Medium,
                title: format!("Module '{}' has unpinned version", module.name),
                description: format!(
                    "Module '{}' from source '{}' does not have a pinned version, which can lead to unexpected changes",
                    module.name, module.source
                ),
                remediation: match module.source_type {
                    ModuleSourceType::Registry => "Add a version constraint like: version = \"~> 1.0\"".to_string(),
                    ModuleSourceType::GitHub | ModuleSourceType::GitLab | ModuleSourceType::Bitbucket => {
                        "Add a git ref like: ?ref=v1.0.0 or ?ref=<commit_sha>".to_string()
                    }
                    _ => "Pin the module version to ensure reproducible deployments".to_string(),
                },
                line_number: module.line_number,
                code_snippet: Some(format!("source = \"{}\"", module.source)),
            });
        }

        // Check for HTTP source (insecure)
        if module.source_type == ModuleSourceType::Http && module.source.starts_with("http://") {
            findings.push(ModuleFinding {
                id: uuid::Uuid::new_v4().to_string(),
                module_name: module.name.clone(),
                category: ModuleFindingCategory::UntrustedSource,
                severity: ModuleFindingSeverity::High,
                title: format!("Module '{}' uses insecure HTTP source", module.name),
                description: "Module is loaded over unencrypted HTTP which is vulnerable to MITM attacks".to_string(),
                remediation: "Use HTTPS instead of HTTP for module sources".to_string(),
                line_number: module.line_number,
                code_snippet: Some(format!("source = \"{}\"", module.source)),
            });
        }

        // Check for unknown source
        if module.source_type == ModuleSourceType::Unknown {
            findings.push(ModuleFinding {
                id: uuid::Uuid::new_v4().to_string(),
                module_name: module.name.clone(),
                category: ModuleFindingCategory::UntrustedSource,
                severity: ModuleFindingSeverity::Low,
                title: format!("Module '{}' has unrecognized source", module.name),
                description: format!("Module source '{}' is not from a recognized provider", module.source),
                remediation: "Verify the module source is from a trusted location".to_string(),
                line_number: module.line_number,
                code_snippet: Some(format!("source = \"{}\"", module.source)),
            });
        }

        // Check for known vulnerable modules
        if self.check_known_vulns {
            for vuln in KNOWN_VULNERABLE_MODULES {
                if module.source.contains(vuln.source_pattern) {
                    findings.push(ModuleFinding {
                        id: uuid::Uuid::new_v4().to_string(),
                        module_name: module.name.clone(),
                        category: ModuleFindingCategory::KnownVulnerability,
                        severity: vuln.severity.clone(),
                        title: format!("Module '{}' has known vulnerability", module.name),
                        description: format!(
                            "{}. Affected versions: {}",
                            vuln.description, vuln.affected_versions
                        ),
                        remediation: format!("Update to a version newer than {}", vuln.affected_versions),
                        line_number: module.line_number,
                        code_snippet: Some(format!("source = \"{}\"", module.source)),
                    });
                }
            }
        }

        // Check for deprecated modules
        for (pattern, message) in DEPRECATED_MODULES {
            if module.source.contains(pattern) {
                findings.push(ModuleFinding {
                    id: uuid::Uuid::new_v4().to_string(),
                    module_name: module.name.clone(),
                    category: ModuleFindingCategory::DeprecatedModule,
                    severity: ModuleFindingSeverity::Low,
                    title: format!("Module '{}' is deprecated", module.name),
                    description: format!("Module '{}' is deprecated", module.source),
                    remediation: message.to_string(),
                    line_number: module.line_number,
                    code_snippet: Some(format!("source = \"{}\"", module.source)),
                });
            }
        }

        findings
    }

    /// Check input security
    fn check_input_security(&self, input: &InputSecurityInfo) -> Vec<ModuleFinding> {
        let mut findings = Vec::new();

        // Check for hardcoded secrets in defaults
        if input.has_hardcoded_secret {
            findings.push(ModuleFinding {
                id: uuid::Uuid::new_v4().to_string(),
                module_name: input.name.clone(),
                category: ModuleFindingCategory::SensitiveDefaults,
                severity: ModuleFindingSeverity::Critical,
                title: format!("Variable '{}' has hardcoded sensitive default", input.name),
                description: "Sensitive variable has a hardcoded default value which may be exposed".to_string(),
                remediation: "Remove the default value and require the variable to be provided at runtime".to_string(),
                line_number: input.line_number,
                code_snippet: Some(format!("variable \"{}\"", input.name)),
            });
        }

        // Check for missing sensitive flag
        if input.should_be_sensitive && !input.is_sensitive {
            findings.push(ModuleFinding {
                id: uuid::Uuid::new_v4().to_string(),
                module_name: input.name.clone(),
                category: ModuleFindingCategory::MissingSensitiveFlag,
                severity: ModuleFindingSeverity::Medium,
                title: format!("Variable '{}' should be marked sensitive", input.name),
                description: "Variable appears to contain sensitive data but is not marked as sensitive".to_string(),
                remediation: "Add 'sensitive = true' to the variable block".to_string(),
                line_number: input.line_number,
                code_snippet: Some(format!("variable \"{}\"", input.name)),
            });
        }

        findings
    }

    /// Check provider version constraints
    fn check_provider_versions(&self) -> Result<Vec<ModuleFinding>> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = self.content.lines().collect();

        for (line_idx, line) in lines.iter().enumerate() {
            let line_num = (line_idx + 1) as i32;

            // Check for loose provider version constraints (has >= but no < upper bound)
            if PROVIDER_LOWER_BOUND.is_match(line) && !PROVIDER_UPPER_BOUND.is_match(line) && line.contains("version") {
                findings.push(ModuleFinding {
                    id: uuid::Uuid::new_v4().to_string(),
                    module_name: "provider".to_string(),
                    category: ModuleFindingCategory::ProviderVersion,
                    severity: ModuleFindingSeverity::Low,
                    title: "Provider version constraint is too loose".to_string(),
                    description: "Provider version constraint allows major version upgrades which may introduce breaking changes".to_string(),
                    remediation: "Use a constraint like '~> 4.0' to allow only minor version upgrades".to_string(),
                    line_number: line_num,
                    code_snippet: Some(line.trim().to_string()),
                });
            }
        }

        Ok(findings)
    }

    /// Calculate security score (0-100)
    fn calculate_security_score(&self, modules: &[ModuleReference], findings: &[ModuleFinding]) -> u8 {
        if modules.is_empty() {
            return 100;
        }

        let mut score = 100i32;

        // Deduct points for findings
        for finding in findings {
            match finding.severity {
                ModuleFindingSeverity::Critical => score -= 25,
                ModuleFindingSeverity::High => score -= 15,
                ModuleFindingSeverity::Medium => score -= 10,
                ModuleFindingSeverity::Low => score -= 5,
                ModuleFindingSeverity::Info => score -= 2,
            }
        }

        // Bonus for using registry modules
        let registry_ratio = modules.iter().filter(|m| m.source_type == ModuleSourceType::Registry).count() as f32 / modules.len() as f32;
        score += (registry_ratio * 10.0) as i32;

        score.max(0).min(100) as u8
    }

    /// Build analysis summary
    fn build_summary(&self, modules: &[ModuleReference], findings: &[ModuleFinding]) -> ModuleAnalysisSummary {
        let mut findings_by_severity = HashMap::new();
        let mut findings_by_category = HashMap::new();

        for finding in findings {
            *findings_by_severity.entry(finding.severity.to_string()).or_insert(0) += 1;
            *findings_by_category.entry(finding.category.to_string()).or_insert(0) += 1;
        }

        let pinned_count = modules.iter().filter(|m| {
            matches!(m.version_status, VersionPinningStatus::Pinned | VersionPinningStatus::CommitPinned | VersionPinningStatus::TagPinned)
        }).count();

        ModuleAnalysisSummary {
            total_modules: modules.len(),
            registry_modules: modules.iter().filter(|m| m.source_type == ModuleSourceType::Registry).count(),
            git_modules: modules.iter().filter(|m| matches!(m.source_type, ModuleSourceType::GitHub | ModuleSourceType::GitLab | ModuleSourceType::Bitbucket)).count(),
            local_modules: modules.iter().filter(|m| m.source_type == ModuleSourceType::Local).count(),
            http_modules: modules.iter().filter(|m| m.source_type == ModuleSourceType::Http).count(),
            pinned_count,
            unpinned_count: modules.len() - pinned_count,
            findings_by_severity,
            findings_by_category,
        }
    }
}

/// Analyze modules in Terraform content
pub fn analyze_modules(content: &str, filename: &str) -> Result<ModuleAnalysisResult> {
    let analyzer = ModuleAnalyzer::new(content, filename);
    analyzer.analyze()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_registry_module() {
        let content = r#"
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "3.14.0"

  name = "my-vpc"
}
"#;
        let result = analyze_modules(content, "main.tf").unwrap();
        assert_eq!(result.modules.len(), 1);
        assert_eq!(result.modules[0].source_type, ModuleSourceType::Registry);
        assert_eq!(result.modules[0].version_status, VersionPinningStatus::Pinned);
    }

    #[test]
    fn test_detect_unpinned_module() {
        let content = r#"
module "s3" {
  source = "terraform-aws-modules/s3-bucket/aws"

  bucket = "my-bucket"
}
"#;
        let result = analyze_modules(content, "main.tf").unwrap();
        assert_eq!(result.modules[0].version_status, VersionPinningStatus::Unpinned);
        assert!(!result.findings.is_empty());
    }

    #[test]
    fn test_github_module_with_ref() {
        let content = r#"
module "example" {
  source = "github.com/example/module?ref=v1.0.0"
}
"#;
        let result = analyze_modules(content, "main.tf").unwrap();
        assert_eq!(result.modules[0].source_type, ModuleSourceType::GitHub);
        assert_eq!(result.modules[0].version_status, VersionPinningStatus::TagPinned);
    }

    #[test]
    fn test_sensitive_variable_detection() {
        let content = r#"
variable "db_password" {
  type = string
  default = "mysecretpassword"
}
"#;
        let result = analyze_modules(content, "main.tf").unwrap();
        assert!(!result.inputs.is_empty());
        // Should find hardcoded secret and missing sensitive flag
        assert!(result.findings.iter().any(|f| f.category == ModuleFindingCategory::SensitiveDefaults));
    }
}
