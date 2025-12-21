// GitHub Actions Integration
#![allow(dead_code)]
#![allow(unused_variables)]

use super::types::*;
use crate::types::{HostInfo, Severity, Vulnerability};
use anyhow::Result;
use chrono::Utc;
use sha2::{Sha256, Digest};
use std::collections::HashMap;

/// Generate SARIF report from scan results for GitHub Security tab
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
                information_uri: "https://github.com/heroforge/heroforge".to_string(),
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
        // Generate a slug from the title
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
            text: format!(
                "Severity: {:?}\n\n{}",
                vuln.severity, vuln.description
            ),
        }),
        properties: Some(SarifRuleProperties {
            tags: Some(vec![
                "security".to_string(),
                format!("severity/{:?}", vuln.severity).to_lowercase(),
            ]),
            security_severity: Some(security_severity),
        }),
    }
}

/// Create a SARIF result from a vulnerability instance
fn create_sarif_result(rule_id: &str, vuln: &Vulnerability, host: &HostInfo) -> SarifResult {
    let level = severity_to_sarif_level(&vuln.severity);

    // Generate a fingerprint for deduplication
    let mut fingerprints = HashMap::new();
    let fingerprint = format!(
        "{}:{}:{}",
        host.target.ip,
        rule_id,
        vuln.affected_service.as_deref().unwrap_or("unknown")
    );
    let mut hasher = Sha256::new();
    hasher.update(fingerprint.as_bytes());
    fingerprints.insert(
        "primaryLocationLineHash".to_string(),
        format!("{:x}", hasher.finalize())[..32].to_string(),
    );

    SarifResult {
        rule_id: rule_id.to_string(),
        level: level.to_string(),
        message: SarifMessage {
            text: format!(
                "{} found on {} ({})",
                vuln.title,
                host.target.ip,
                vuln.affected_service.as_deref().unwrap_or("unknown service")
            ),
        },
        locations: vec![SarifLocation {
            physical_location: SarifPhysicalLocation {
                artifact_location: SarifArtifactLocation {
                    // Use host:port as the "file" location for network vulnerabilities
                    uri: format!(
                        "network://{}",
                        host.target.ip
                    ),
                    uri_base_id: None,
                },
                region: None,
            },
        }],
        fingerprints: Some(fingerprints),
    }
}

/// Convert severity to SARIF level
fn severity_to_sarif_level(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low => "note",
    }
}

/// Convert severity to CVSS-like security severity score
fn severity_to_security_severity(severity: &Severity) -> String {
    match severity {
        Severity::Critical => "9.0".to_string(),
        Severity::High => "7.0".to_string(),
        Severity::Medium => "5.0".to_string(),
        Severity::Low => "3.0".to_string(),
    }
}

/// Generate GitHub Actions workflow example YAML
pub fn generate_workflow_example(api_url: &str) -> String {
    format!(
        r#"# HeroForge Security Scan - GitHub Actions Workflow
name: Security Scan

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]
  schedule:
    # Run weekly on Monday at 2 AM UTC
    - cron: '0 2 * * 1'

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Run HeroForge Security Scan
        id: scan
        env:
          HEROFORGE_API_URL: {api_url}
          HEROFORGE_TOKEN: ${{{{ secrets.HEROFORGE_CI_TOKEN }}}}
        run: |
          # Trigger scan
          SCAN_RESPONSE=$(curl -s -X POST "$HEROFORGE_API_URL/api/cicd/scan" \
            -H "Authorization: Bearer $HEROFORGE_TOKEN" \
            -H "Content-Type: application/json" \
            -d '{{
              "name": "CI Security Scan - ${{{{ github.repository }}}}",
              "targets": ["YOUR_TARGET_IP_OR_CIDR"],
              "port_range": [1, 1000],
              "enable_vuln_scan": true,
              "ci_ref": "${{{{ github.sha }}}}",
              "ci_branch": "${{{{ github.ref_name }}}}",
              "ci_url": "${{{{ github.server_url }}}}/${{{{ github.repository }}}}/actions/runs/${{{{ github.run_id }}}}",
              "repository": "${{{{ github.repository }}}}"
            }}')

          RUN_ID=$(echo $SCAN_RESPONSE | jq -r '.run_id')
          SCAN_ID=$(echo $SCAN_RESPONSE | jq -r '.scan_id')
          echo "run_id=$RUN_ID" >> $GITHUB_OUTPUT
          echo "scan_id=$SCAN_ID" >> $GITHUB_OUTPUT

          # Poll for completion
          while true; do
            STATUS_RESPONSE=$(curl -s "$HEROFORGE_API_URL/api/cicd/scan/$RUN_ID/status" \
              -H "Authorization: Bearer $HEROFORGE_TOKEN")
            STATUS=$(echo $STATUS_RESPONSE | jq -r '.status')

            if [ "$STATUS" = "completed" ] || [ "$STATUS" = "failed" ]; then
              echo "exit_code=$(echo $STATUS_RESPONSE | jq -r '.exit_code')" >> $GITHUB_OUTPUT
              break
            fi

            echo "Scan status: $STATUS ($(echo $STATUS_RESPONSE | jq -r '.progress')%)"
            sleep 30
          done

      - name: Download SARIF Results
        if: always()
        env:
          HEROFORGE_API_URL: {api_url}
          HEROFORGE_TOKEN: ${{{{ secrets.HEROFORGE_CI_TOKEN }}}}
        run: |
          curl -s "$HEROFORGE_API_URL/api/cicd/scan/${{{{ steps.scan.outputs.run_id }}}}/sarif" \
            -H "Authorization: Bearer $HEROFORGE_TOKEN" \
            -o heroforge-results.sarif

      - name: Upload SARIF to GitHub Security
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: heroforge-results.sarif
          category: heroforge-security-scan

      - name: Check Quality Gate
        if: steps.scan.outputs.exit_code != '0'
        run: |
          echo "Security scan failed quality gate check"
          exit 1
"#,
        api_url = api_url
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ScanTarget, Severity};
    use std::net::IpAddr;
    use std::time::Duration;

    #[test]
    fn test_generate_sarif_report() {
        let hosts = vec![HostInfo {
            target: ScanTarget {
                ip: "192.168.1.1".parse::<IpAddr>().unwrap(),
                hostname: Some("test-host".to_string()),
            },
            is_alive: true,
            os_guess: None,
            ports: vec![],
            vulnerabilities: vec![
                Vulnerability {
                    cve_id: Some("CVE-2024-1234".to_string()),
                    title: "Test Vulnerability".to_string(),
                    severity: Severity::High,
                    description: "A test vulnerability".to_string(),
                    affected_service: Some("http".to_string()),
                },
            ],
            scan_duration: Duration::from_secs(10),
        }];

        let report = generate_sarif_report("scan-123", &hosts, "Test Scan").unwrap();

        assert_eq!(report.version, "2.1.0");
        assert_eq!(report.runs.len(), 1);

        let run = &report.runs[0];
        assert_eq!(run.tool.driver.name, "HeroForge");
        assert_eq!(run.tool.driver.rules.len(), 1);
        assert_eq!(run.results.len(), 1);

        let rule = &run.tool.driver.rules[0];
        assert_eq!(rule.id, "CVE-2024-1234");

        let result = &run.results[0];
        assert_eq!(result.rule_id, "CVE-2024-1234");
        assert_eq!(result.level, "error"); // High severity = error
    }

    #[test]
    fn test_severity_mapping() {
        assert_eq!(severity_to_sarif_level(&Severity::Critical), "error");
        assert_eq!(severity_to_sarif_level(&Severity::High), "error");
        assert_eq!(severity_to_sarif_level(&Severity::Medium), "warning");
        assert_eq!(severity_to_sarif_level(&Severity::Low), "note");
    }

    #[test]
    fn test_generate_rule_id() {
        let vuln_with_cve = Vulnerability {
            cve_id: Some("CVE-2024-1234".to_string()),
            title: "Test".to_string(),
            severity: Severity::High,
            description: "Test".to_string(),
            affected_service: None,
        };
        assert_eq!(generate_rule_id(&vuln_with_cve), "CVE-2024-1234");

        let vuln_without_cve = Vulnerability {
            cve_id: None,
            title: "SQL Injection Attack".to_string(),
            severity: Severity::High,
            description: "Test".to_string(),
            affected_service: None,
        };
        assert_eq!(generate_rule_id(&vuln_without_cve), "HEROFORGE-SQL-INJECTION-ATTACK");
    }
}
