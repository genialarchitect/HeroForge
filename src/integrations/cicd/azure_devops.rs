//! Azure DevOps Integration
//!
//! Provides integration with Azure DevOps Pipelines including:
//! - Security scanning tasks for Azure Pipelines YAML
//! - Code scanning results upload to Azure DevOps Advanced Security
//! - PR/MR comment integration
//! - Quality gate policies

#![allow(dead_code)]
#![allow(unused_variables)]

use super::types::*;
use crate::types::{HostInfo, Severity, Vulnerability};
use anyhow::Result;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ============================================================================
// Azure DevOps Types
// ============================================================================

/// Azure DevOps SARIF upload format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AzureDevOpsSarifUpload {
    #[serde(rename = "$schema")]
    pub schema: String,
    pub version: String,
    pub runs: Vec<SarifRun>,
}

/// Azure DevOps Pipeline YAML configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AzurePipelineConfig {
    pub trigger: Vec<String>,
    pub pool: PipelinePool,
    pub stages: Vec<PipelineStage>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelinePool {
    #[serde(rename = "vmImage")]
    pub vm_image: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineStage {
    pub stage: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
    pub jobs: Vec<PipelineJob>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineJob {
    pub job: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
    pub steps: Vec<PipelineStep>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PipelineStep {
    Task {
        task: String,
        #[serde(rename = "displayName")]
        display_name: String,
        inputs: HashMap<String, String>,
    },
    Script {
        script: String,
        #[serde(rename = "displayName")]
        display_name: String,
    },
    Bash {
        bash: String,
        #[serde(rename = "displayName")]
        display_name: String,
    },
}

// ============================================================================
// SARIF Generation for Azure DevOps
// ============================================================================

/// Generate SARIF report for Azure DevOps Advanced Security
pub fn generate_sarif_report(
    scan_id: &str,
    hosts: &[HostInfo],
    scan_name: &str,
) -> Result<SarifReport> {
    let mut rules: Vec<SarifRule> = Vec::new();
    let mut results: Vec<SarifResult> = Vec::new();
    let mut rule_ids: HashMap<String, usize> = HashMap::new();

    for host in hosts {
        for vuln in &host.vulnerabilities {
            let rule_id = generate_rule_id(vuln);

            // Add rule if not already present
            if !rule_ids.contains_key(&rule_id) {
                let rule = create_sarif_rule(&rule_id, vuln);
                rule_ids.insert(rule_id.clone(), rules.len());
                rules.push(rule);
            }

            // Add result for this vulnerability instance
            let result = create_sarif_result(&rule_id, vuln, host);
            results.push(result);
        }
    }

    let sarif_run = SarifRun {
        tool: SarifTool {
            driver: SarifDriver {
                name: "HeroForge".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                information_uri: "https://heroforge.genialarchitect.io".to_string(),
                rules,
            },
        },
        results,
        invocations: Some(vec![SarifInvocation {
            execution_successful: true,
            end_time_utc: Some(Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()),
        }]),
    };

    Ok(SarifReport {
        runs: vec![sarif_run],
        ..Default::default()
    })
}

/// Generate a unique rule ID for a vulnerability
fn generate_rule_id(vuln: &Vulnerability) -> String {
    if let Some(cve_id) = &vuln.cve_id {
        cve_id.clone()
    } else {
        format!(
            "HEROFORGE-{}",
            vuln.title
                .chars()
                .filter(|c| c.is_alphanumeric() || *c == ' ')
                .collect::<String>()
                .split_whitespace()
                .take(3)
                .collect::<Vec<_>>()
                .join("-")
                .to_uppercase()
        )
    }
}

/// Create a SARIF rule from a vulnerability
fn create_sarif_rule(rule_id: &str, vuln: &Vulnerability) -> SarifRule {
    let level = severity_to_sarif_level(&vuln.severity);
    let security_severity = severity_to_security_severity(&vuln.severity);

    SarifRule {
        id: rule_id.to_string(),
        name: vuln.title.clone(),
        short_description: SarifMessage {
            text: vuln.title.clone(),
        },
        full_description: Some(SarifMessage {
            text: vuln.description.clone(),
        }),
        default_configuration: SarifConfiguration {
            level: level.to_string(),
        },
        help: Some(SarifMessage {
            text: vuln.description.clone(),
        }),
        properties: Some(SarifRuleProperties {
            tags: Some(vec!["security".to_string(), "vulnerability".to_string()]),
            security_severity: Some(security_severity.to_string()),
        }),
    }
}

/// Create a SARIF result from a vulnerability
fn create_sarif_result(rule_id: &str, vuln: &Vulnerability, host: &HostInfo) -> SarifResult {
    let level = severity_to_sarif_level(&vuln.severity);
    let ip_str = match &host.target.ip {
        std::net::IpAddr::V4(ip) => ip.to_string(),
        std::net::IpAddr::V6(ip) => ip.to_string(),
    };

    SarifResult {
        rule_id: rule_id.to_string(),
        message: SarifMessage {
            text: format!("{} on {}", vuln.title, ip_str),
        },
        level: level.to_string(),
        locations: vec![SarifLocation {
            physical_location: SarifPhysicalLocation {
                artifact_location: SarifArtifactLocation {
                    uri: format!("network://{}", ip_str),
                    uri_base_id: None,
                },
                region: Some(SarifRegion {
                    start_line: 1,
                    start_column: None,
                }),
            },
        }],
        fingerprints: None,
    }
}

/// Convert HeroForge severity to SARIF level
fn severity_to_sarif_level(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical => "error",
        Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low => "note",
    }
}

/// Convert severity to numeric security severity score (0.0-10.0)
fn severity_to_security_severity(severity: &Severity) -> f64 {
    match severity {
        Severity::Critical => 10.0,
        Severity::High => 8.0,
        Severity::Medium => 5.0,
        Severity::Low => 3.0,
    }
}

// ============================================================================
// Azure Pipeline YAML Generation
// ============================================================================

/// Generate Azure Pipelines example configuration
pub fn generate_pipeline_example(api_url: &str) -> String {
    use uuid::Uuid;

    generate_pipeline_yaml(
        "yourorg/yourrepo",
        "main",
        &vec!["192.168.1.0/24".to_string()],
        &QualityGate {
            id: Uuid::new_v4().to_string(),
            user_id: "example".to_string(),
            name: "Default Gate".to_string(),
            fail_on_severity: "high".to_string(),
            max_vulnerabilities: Some(10),
            max_critical: Some(0),
            max_high: Some(5),
            max_medium: Some(20),
            max_low: None,
            fail_on_new_vulns: true,
            baseline_scan_id: None,
            is_default: true,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        },
    )
}

/// Generate Azure Pipelines YAML configuration for HeroForge security scanning
pub fn generate_pipeline_yaml(
    repository: &str,
    branch: &str,
    scan_targets: &[String],
    quality_gate: &QualityGate,
) -> String {
    let targets_str = scan_targets.join(",");

    format!(
        r###"# Azure Pipeline for Genial Architect Scanning
# Generated by HeroForge

trigger:
  branches:
    include:
      - {branch}

pool:
  vmImage: 'ubuntu-latest'

stages:
  - stage: SecurityScan
    displayName: 'Security Scanning'
    jobs:
      - job: HeroForgeScan
        displayName: 'Run Genial Architect Scan'
        steps:
          - checkout: self
            fetchDepth: 1

          - task: Bash@3
            displayName: 'Install HeroForge'
            inputs:
              targetType: 'inline'
              script: |
                echo "Installing HeroForge..."
                # Download and install HeroForge CLI
                curl -sSL https://heroforge.genialarchitect.io/install.sh | bash
                echo "HeroForge installed successfully"

          - task: Bash@3
            displayName: 'Run Security Scan'
            inputs:
              targetType: 'inline'
              script: |
                echo "Running HeroForge security scan..."
                heroforge scan {targets_str} --output sarif --output-file heroforge-results.sarif
                echo "Scan complete"

          - task: PublishBuildArtifacts@1
            displayName: 'Publish SARIF Results'
            inputs:
              pathToPublish: 'heroforge-results.sarif'
              artifactName: 'CodeAnalysisLogs'
              publishLocation: 'Container'

          - task: Bash@3
            displayName: 'Evaluate Quality Gate'
            inputs:
              targetType: 'inline'
              script: |
                echo "Evaluating quality gate..."
                heroforge gate-check heroforge-results.sarif \\
                  --fail-on-severity {fail_severity} \\
                  --max-critical {max_critical} \\
                  --max-high {max_high} \\
                  --max-medium {max_medium}

                if [ $? -ne 0 ]; then
                  echo "##vso[task.logissue type=error]Quality gate failed: Vulnerabilities exceed threshold"
                  echo "##vso[task.complete result=Failed;]Quality gate check failed"
                  exit 1
                fi

                echo "##vso[task.complete result=Succeeded;]Quality gate passed"

          - task: PublishCodeCoverageResults@2
            displayName: 'Publish Security Scan Results'
            condition: always()
            inputs:
              codeCoverageTool: 'Cobertura'
              summaryFileLocation: 'heroforge-results.sarif'
              pathToSources: '$(Build.SourcesDirectory)'

  - stage: SecurityReport
    displayName: 'Security Report'
    dependsOn: SecurityScan
    condition: always()
    jobs:
      - job: GenerateReport
        displayName: 'Generate Security Report'
        steps:
          - task: Bash@3
            displayName: 'Generate HTML Report'
            inputs:
              targetType: 'inline'
              script: |
                echo "Generating security report..."
                heroforge report heroforge-results.sarif --format html --output security-report.html

          - task: PublishBuildArtifacts@1
            displayName: 'Publish Security Report'
            inputs:
              pathToPublish: 'security-report.html'
              artifactName: 'SecurityReport'
              publishLocation: 'Container'
"###,
        branch = branch,
        targets_str = targets_str,
        fail_severity = quality_gate.fail_on_severity,
        max_critical = quality_gate.max_critical.unwrap_or(0),
        max_high = quality_gate.max_high.unwrap_or(0),
        max_medium = quality_gate.max_medium.unwrap_or(0),
    )
}

/// Generate Azure Pipeline extension manifest (vss-extension.json)
pub fn generate_extension_manifest() -> String {
    r#"{
  "manifestVersion": 1,
  "id": "heroforge-security-scanner",
  "version": "1.0.0",
  "name": "Genial Architect Scanner",
  "description": "Comprehensive security scanning and vulnerability assessment for Azure DevOps pipelines",
  "publisher": "heroforge",
  "categories": ["Azure Pipelines"],
  "targets": [
    {
      "id": "Microsoft.VisualStudio.Services"
    }
  ],
  "icons": {
    "default": "images/logo.png"
  },
  "files": [
    {
      "path": "buildAndReleaseTask"
    }
  ],
  "contributions": [
    {
      "id": "heroforge-scan-task",
      "type": "ms.vss-distributed-task.task",
      "targets": ["ms.vss-distributed-task.tasks"],
      "properties": {
        "name": "buildAndReleaseTask"
      }
    }
  ]
}"#.to_string()
}

/// Generate task.json for Azure DevOps task definition
pub fn generate_task_definition() -> String {
    r#"{
  "$schema": "https://raw.githubusercontent.com/Microsoft/azure-pipelines-task-lib/master/tasks.schema.json",
  "id": "a1b2c3d4-e5f6-4789-a0b1-c2d3e4f56789",
  "name": "HeroForgeScan",
  "friendlyName": "Genial Architect Scan",
  "description": "Run comprehensive security scanning with HeroForge",
  "helpMarkDown": "[More Information](https://heroforge.genialarchitect.io/docs/azure-devops)",
  "category": "Utility",
  "visibility": ["Build", "Release"],
  "author": "HeroForge",
  "version": {
    "Major": 1,
    "Minor": 0,
    "Patch": 0
  },
  "instanceNameFormat": "Genial Architect Scan: $(scanTargets)",
  "inputs": [
    {
      "name": "scanTargets",
      "type": "string",
      "label": "Scan Targets",
      "defaultValue": "",
      "required": true,
      "helpMarkDown": "Comma-separated list of IP addresses or CIDR ranges to scan"
    },
    {
      "name": "scanType",
      "type": "picklist List",
      "label": "Scan Type",
      "defaultValue": "tcp-connect",
      "required": true,
      "options": {
        "tcp-connect": "TCP Connect",
        "tcp-syn": "TCP SYN",
        "udp": "UDP",
        "comprehensive": "Comprehensive"
      },
      "helpMarkDown": "Type of port scan to perform"
    },
    {
      "name": "qualityGateEnabled",
      "type": "boolean",
      "label": "Enable Quality Gate",
      "defaultValue": "true",
      "required": false,
      "helpMarkDown": "Fail the build if quality gate thresholds are exceeded"
    },
    {
      "name": "failOnSeverity",
      "type": "pickList",
      "label": "Fail on Severity",
      "defaultValue": "high",
      "required": false,
      "visibleRule": "qualityGateEnabled = true",
      "options": {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low"
      },
      "helpMarkDown": "Minimum severity level to fail the build"
    },
    {
      "name": "maxCritical",
      "type": "int",
      "label": "Max Critical Vulnerabilities",
      "defaultValue": "0",
      "required": false,
      "visibleRule": "qualityGateEnabled = true",
      "helpMarkDown": "Maximum number of critical vulnerabilities allowed (0 = fail on any)"
    },
    {
      "name": "maxHigh",
      "type": "int",
      "label": "Max High Vulnerabilities",
      "defaultValue": "0",
      "required": false,
      "visibleRule": "qualityGateEnabled = true",
      "helpMarkDown": "Maximum number of high vulnerabilities allowed"
    },
    {
      "name": "generateReport",
      "type": "boolean",
      "label": "Generate HTML Report",
      "defaultValue": "true",
      "required": false,
      "helpMarkDown": "Generate an HTML security report"
    },
    {
      "name": "publishSarif",
      "type": "boolean",
      "label": "Publish SARIF to Advanced Security",
      "defaultValue": "true",
      "required": false,
      "helpMarkDown": "Upload SARIF results to Azure DevOps Advanced Security"
    }
  ],
  "execution": {
    "Node16": {
      "target": "index.js"
    }
  }
}"#.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{HostInfo, PortInfo, Vulnerability};

    #[test]
    fn test_generate_sarif_report() {
        let mut host = HostInfo {
            ip: "192.168.1.1".to_string(),
            hostname: Some("test-host".to_string()),
            os: None,
            ports: vec![],
            vulnerabilities: vec![Vulnerability {
                title: "Test Vulnerability".to_string(),
                description: "Test description".to_string(),
                severity: Severity::High,
                port: 80,
                service: Some("http".to_string()),
                cve_id: Some("CVE-2024-1234".to_string()),
                cvss_score: Some(7.5),
                remediation: Some("Update to latest version".to_string()),
                references: vec![],
                exploitable: false,
                exploits_available: false,
            }],
        };

        let result = generate_sarif_report("scan-1", &[host], "Test Scan");
        assert!(result.is_ok());

        let sarif = result.unwrap();
        assert_eq!(sarif.runs.len(), 1);
        assert_eq!(sarif.runs[0].tool.driver.name, "HeroForge");
        assert_eq!(sarif.runs[0].results.len(), 1);
        assert_eq!(sarif.runs[0].results[0].rule_id, "CVE-2024-1234");
    }

    #[test]
    fn test_generate_pipeline_yaml() {
        let quality_gate = QualityGate {
            fail_on_severity: "high".to_string(),
            max_vulnerabilities: Some(10),
            max_critical: Some(0),
            max_high: Some(5),
            max_medium: Some(10),
            max_low: None,
            fail_on_new_vulns: false,
        };

        let yaml = generate_pipeline_yaml(
            "myrepo",
            "main",
            &["192.168.1.0/24".to_string()],
            &quality_gate,
        );

        assert!(yaml.contains("trigger:"));
        assert!(yaml.contains("branches:"));
        assert!(yaml.contains("HeroForge"));
        assert!(yaml.contains("SecurityScan"));
    }

    #[test]
    fn test_generate_extension_manifest() {
        let manifest = generate_extension_manifest();
        assert!(manifest.contains("heroforge-security-scanner"));
        assert!(manifest.contains("Azure Pipelines"));
    }

    #[test]
    fn test_generate_task_definition() {
        let task_def = generate_task_definition();
        assert!(task_def.contains("HeroForgeScan"));
        assert!(task_def.contains("scanTargets"));
        assert!(task_def.contains("qualityGateEnabled"));
    }
}
