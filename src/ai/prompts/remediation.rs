//! Platform-Specific Remediation Prompt Templates
//!
//! This module provides structured prompts for generating remediation
//! suggestions tailored to different platforms and environments.

use serde::{Deserialize, Serialize};

/// Supported remediation platforms
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum RemediationPlatform {
    Linux,
    Windows,
    Aws,
    Azure,
    Gcp,
    Kubernetes,
    Docker,
    Generic,
}

impl Default for RemediationPlatform {
    fn default() -> Self {
        Self::Generic
    }
}

impl std::str::FromStr for RemediationPlatform {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "linux" | "ubuntu" | "debian" | "rhel" | "centos" | "fedora" => Ok(Self::Linux),
            "windows" | "win" | "win32" | "win64" => Ok(Self::Windows),
            "aws" | "amazon" => Ok(Self::Aws),
            "azure" | "microsoft" => Ok(Self::Azure),
            "gcp" | "google" | "gcloud" => Ok(Self::Gcp),
            "kubernetes" | "k8s" => Ok(Self::Kubernetes),
            "docker" | "container" => Ok(Self::Docker),
            _ => Ok(Self::Generic),
        }
    }
}

/// Remediation request context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationContext {
    pub vulnerability_id: String,
    pub cve_id: Option<String>,
    pub title: String,
    pub description: String,
    pub severity: String,
    pub affected_component: Option<String>,
    pub affected_version: Option<String>,
    pub platform: RemediationPlatform,
    pub host_os: Option<String>,
    pub include_rollback: bool,
    pub verbose: bool,
}

/// Generated remediation suggestion
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationSuggestion {
    pub vulnerability_id: String,
    pub platform: String,
    pub steps: Vec<RemediationStep>,
    pub code_snippets: Vec<CodeSnippet>,
    pub estimated_effort: String,
    pub risk_notes: Vec<String>,
    pub prerequisites: Vec<String>,
    pub verification_steps: Vec<String>,
    pub rollback_steps: Option<Vec<String>>,
    pub generated_at: chrono::DateTime<chrono::Utc>,
}

/// A single remediation step
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationStep {
    pub step_number: u32,
    pub title: String,
    pub description: String,
    pub code_snippet: Option<String>,
    pub code_language: Option<String>,
    pub estimated_time: Option<String>,
    pub risk_level: Option<String>,
    pub requires_reboot: Option<bool>,
    pub requires_downtime: Option<bool>,
}

/// A code snippet for remediation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeSnippet {
    pub title: String,
    pub language: String,
    pub code: String,
    pub description: Option<String>,
    pub filename: Option<String>,
}

/// Build the system prompt for remediation generation
pub fn build_system_prompt(platform: &RemediationPlatform) -> String {
    let platform_context = match platform {
        RemediationPlatform::Linux => LINUX_CONTEXT,
        RemediationPlatform::Windows => WINDOWS_CONTEXT,
        RemediationPlatform::Aws => AWS_CONTEXT,
        RemediationPlatform::Azure => AZURE_CONTEXT,
        RemediationPlatform::Gcp => GCP_CONTEXT,
        RemediationPlatform::Kubernetes => KUBERNETES_CONTEXT,
        RemediationPlatform::Docker => DOCKER_CONTEXT,
        RemediationPlatform::Generic => GENERIC_CONTEXT,
    };

    format!(
        r#"You are a security remediation expert. Generate detailed, actionable remediation steps for vulnerabilities.

{platform_context}

OUTPUT FORMAT:
Return a JSON object with this structure:
{{
  "steps": [
    {{
      "step_number": 1,
      "title": "Step title",
      "description": "Detailed description",
      "code_snippet": "actual code if applicable",
      "code_language": "bash|powershell|terraform|yaml|etc",
      "estimated_time": "5 minutes",
      "risk_level": "low|medium|high",
      "requires_reboot": false,
      "requires_downtime": false
    }}
  ],
  "code_snippets": [
    {{
      "title": "Snippet title",
      "language": "language",
      "code": "full code block",
      "description": "What this code does",
      "filename": "optional filename"
    }}
  ],
  "estimated_effort": "30 minutes to 2 hours",
  "risk_notes": ["Note about potential risks"],
  "prerequisites": ["Required prerequisites"],
  "verification_steps": ["How to verify the fix worked"],
  "rollback_steps": ["How to rollback if needed"]
}}

GUIDELINES:
1. Provide specific, copy-pasteable commands
2. Include error handling in scripts
3. Note any service restarts required
4. Highlight potential breaking changes
5. Include verification commands
6. Estimate realistic time requirements
"#
    )
}

/// Build the user prompt for remediation generation
pub fn build_user_prompt(context: &RemediationContext) -> String {
    let mut prompt = format!(
        r#"Generate remediation steps for the following vulnerability:

**Vulnerability ID:** {}
**Title:** {}
**Severity:** {}
**Description:** {}
"#,
        context.vulnerability_id, context.title, context.severity, context.description
    );

    if let Some(ref cve) = context.cve_id {
        prompt.push_str(&format!("**CVE:** {}\n", cve));
    }

    if let Some(ref component) = context.affected_component {
        prompt.push_str(&format!("**Affected Component:** {}\n", component));
    }

    if let Some(ref version) = context.affected_version {
        prompt.push_str(&format!("**Affected Version:** {}\n", version));
    }

    if let Some(ref os) = context.host_os {
        prompt.push_str(&format!("**Host OS:** {}\n", os));
    }

    prompt.push_str(&format!(
        "\n**Target Platform:** {:?}\n",
        context.platform
    ));

    if context.include_rollback {
        prompt.push_str("\nPlease include detailed rollback steps.\n");
    }

    if context.verbose {
        prompt.push_str("\nProvide verbose explanations for each step.\n");
    }

    prompt
}

// Platform-specific context strings

const LINUX_CONTEXT: &str = r#"PLATFORM: Linux (Ubuntu, Debian, RHEL, CentOS)

Use these conventions:
- Package management: apt/yum/dnf commands
- Service management: systemctl commands
- Configuration files: /etc/ paths
- Permissions: chmod/chown commands
- Bash scripting with proper error handling

Example commands:
- sudo apt update && sudo apt upgrade -y package-name
- sudo systemctl restart service-name
- sudo chmod 600 /path/to/config
"#;

const WINDOWS_CONTEXT: &str = r#"PLATFORM: Windows Server / Windows Desktop

Use these conventions:
- PowerShell commands (preferred)
- Registry modifications via PowerShell
- Group Policy references where applicable
- Windows Defender/Security settings
- Service management: Get-Service, Restart-Service

Example commands:
- Install-WindowsFeature -Name feature-name
- Set-ItemProperty -Path "HKLM:\..." -Name "key" -Value value
- Restart-Service -Name "ServiceName" -Force
- winrm quickconfig
"#;

const AWS_CONTEXT: &str = r#"PLATFORM: Amazon Web Services (AWS)

Use these conventions:
- AWS CLI commands (aws ...)
- Terraform HCL for infrastructure changes
- CloudFormation YAML where applicable
- IAM policy JSON
- Security group rules

Example commands:
- aws ec2 modify-instance-attribute --instance-id i-xxx --no-source-dest-check
- aws s3api put-bucket-encryption --bucket name --server-side-encryption-configuration ...
- Terraform resource definitions
"#;

const AZURE_CONTEXT: &str = r#"PLATFORM: Microsoft Azure

Use these conventions:
- Azure CLI commands (az ...)
- ARM templates (JSON)
- Terraform AzureRM provider
- Azure Policy definitions
- Network Security Group rules

Example commands:
- az vm update --resource-group rg --name vm --set ...
- az network nsg rule create --resource-group rg --nsg-name nsg --name rule ...
- Terraform azurerm_* resources
"#;

const GCP_CONTEXT: &str = r#"PLATFORM: Google Cloud Platform (GCP)

Use these conventions:
- gcloud CLI commands
- Terraform Google provider
- Organization policies
- VPC firewall rules
- IAM bindings

Example commands:
- gcloud compute instances update INSTANCE --update-labels=...
- gcloud compute firewall-rules create ...
- Terraform google_* resources
"#;

const KUBERNETES_CONTEXT: &str = r#"PLATFORM: Kubernetes

Use these conventions:
- kubectl commands
- YAML manifests
- Helm chart values
- Network policies
- RBAC configurations
- Pod Security Standards

Example commands:
- kubectl patch deployment name -p '{"spec":...}'
- kubectl apply -f manifest.yaml
- Helm values.yaml configurations
"#;

const DOCKER_CONTEXT: &str = r#"PLATFORM: Docker / Containers

Use these conventions:
- Dockerfile best practices
- docker-compose.yml configurations
- Docker security options
- Image scanning references
- Network configurations

Example commands:
- docker update --restart=unless-stopped container
- docker-compose configuration snippets
- Dockerfile security improvements
"#;

const GENERIC_CONTEXT: &str = r#"PLATFORM: Generic / Cross-Platform

Provide remediation that can be adapted to multiple environments:
- Conceptual steps first
- Platform-specific variations where needed
- Reference documentation
- General security best practices
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_platform_parsing() {
        assert_eq!("linux".parse::<RemediationPlatform>().unwrap(), RemediationPlatform::Linux);
        assert_eq!("ubuntu".parse::<RemediationPlatform>().unwrap(), RemediationPlatform::Linux);
        assert_eq!("windows".parse::<RemediationPlatform>().unwrap(), RemediationPlatform::Windows);
        assert_eq!("aws".parse::<RemediationPlatform>().unwrap(), RemediationPlatform::Aws);
        assert_eq!("k8s".parse::<RemediationPlatform>().unwrap(), RemediationPlatform::Kubernetes);
        assert_eq!("unknown".parse::<RemediationPlatform>().unwrap(), RemediationPlatform::Generic);
    }

    #[test]
    fn test_build_system_prompt() {
        let prompt = build_system_prompt(&RemediationPlatform::Linux);
        assert!(prompt.contains("Linux"));
        assert!(prompt.contains("apt"));
        assert!(prompt.contains("systemctl"));
    }

    #[test]
    fn test_build_user_prompt() {
        let context = RemediationContext {
            vulnerability_id: "VULN-001".to_string(),
            cve_id: Some("CVE-2024-1234".to_string()),
            title: "OpenSSL Buffer Overflow".to_string(),
            description: "A buffer overflow in OpenSSL allows RCE".to_string(),
            severity: "Critical".to_string(),
            affected_component: Some("openssl".to_string()),
            affected_version: Some("3.0.0".to_string()),
            platform: RemediationPlatform::Linux,
            host_os: Some("Ubuntu 22.04".to_string()),
            include_rollback: true,
            verbose: false,
        };

        let prompt = build_user_prompt(&context);
        assert!(prompt.contains("VULN-001"));
        assert!(prompt.contains("CVE-2024-1234"));
        assert!(prompt.contains("OpenSSL Buffer Overflow"));
        assert!(prompt.contains("rollback"));
    }
}
