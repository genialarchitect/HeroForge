// GitLab CI Integration
#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(unused_imports)]

use super::types::*;
use crate::types::{HostInfo, Severity, Vulnerability};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};

/// GitLab Code Quality report format
/// See: https://docs.gitlab.com/ee/ci/testing/code_quality.html#implementing-a-custom-tool
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabCodeQualityReport {
    pub issues: Vec<GitLabCodeQualityIssue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabCodeQualityIssue {
    pub description: String,
    pub check_name: String,
    pub fingerprint: String,
    pub severity: String, // info, minor, major, critical, blocker
    pub location: GitLabLocation,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub categories: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabLocation {
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lines: Option<GitLabLines>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabLines {
    pub begin: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end: Option<i32>,
}

/// GitLab Security Report format (SAST/DAST)
/// See: https://docs.gitlab.com/ee/development/integrations/secure.html
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabSecurityReport {
    pub version: String,
    pub vulnerabilities: Vec<GitLabVulnerability>,
    pub scan: GitLabScan,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabVulnerability {
    pub id: String,
    pub category: String,
    pub name: String,
    pub message: String,
    pub description: String,
    pub severity: String, // Critical, High, Medium, Low, Unknown, Info
    pub confidence: String, // High, Medium, Low, Unknown, Experimental, Ignore
    #[serde(skip_serializing_if = "Option::is_none")]
    pub solution: Option<String>,
    pub scanner: GitLabScanner,
    pub identifiers: Vec<GitLabIdentifier>,
    pub location: GitLabSecurityLocation,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub links: Option<Vec<GitLabLink>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabScanner {
    pub id: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    pub vendor: GitLabVendor,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabVendor {
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabIdentifier {
    #[serde(rename = "type")]
    pub identifier_type: String, // cve, cwe, etc.
    pub name: String,
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabSecurityLocation {
    pub hostname: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabLink {
    pub name: String,
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabScan {
    pub scanner: GitLabScanner,
    #[serde(rename = "type")]
    pub scan_type: String, // dast
    pub start_time: String,
    pub end_time: String,
    pub status: String, // success, failure
    #[serde(skip_serializing_if = "Option::is_none")]
    pub messages: Option<Vec<GitLabScanMessage>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabScanMessage {
    pub level: String, // info, warn, error
    pub value: String,
}

/// Generate GitLab Security Report (DAST format)
pub fn generate_security_report(
    scan_id: &str,
    hosts: &[HostInfo],
    scan_name: &str,
    start_time: &str,
    end_time: &str,
) -> Result<GitLabSecurityReport> {
    let scanner = GitLabScanner {
        id: "heroforge".to_string(),
        name: "HeroForge".to_string(),
        url: Some("https://github.com/heroforge/heroforge".to_string()),
        vendor: GitLabVendor {
            name: "HeroForge".to_string(),
        },
        version: Some(env!("CARGO_PKG_VERSION").to_string()),
    };

    let mut vulnerabilities: Vec<GitLabVulnerability> = Vec::new();

    for host in hosts {
        for vuln in &host.vulnerabilities {
            let gitlab_vuln = create_gitlab_vulnerability(host, vuln, &scanner);
            vulnerabilities.push(gitlab_vuln);
        }
    }

    Ok(GitLabSecurityReport {
        version: "15.0.0".to_string(),
        vulnerabilities,
        scan: GitLabScan {
            scanner: scanner.clone(),
            scan_type: "dast".to_string(),
            start_time: start_time.to_string(),
            end_time: end_time.to_string(),
            status: "success".to_string(),
            messages: None,
        },
    })
}

/// Create a GitLab vulnerability from a HeroForge vulnerability
fn create_gitlab_vulnerability(
    host: &HostInfo,
    vuln: &Vulnerability,
    scanner: &GitLabScanner,
) -> GitLabVulnerability {
    let severity = severity_to_gitlab(&vuln.severity);

    // Find the port for this vulnerability if it has an affected service
    let port = if let Some(service) = &vuln.affected_service {
        host.ports
            .iter()
            .find(|p| {
                p.service
                    .as_ref()
                    .map(|s| s.name.to_lowercase() == service.to_lowercase())
                    .unwrap_or(false)
            })
            .map(|p| p.port as i32)
    } else {
        None
    };

    let mut identifiers = Vec::new();

    // Add CVE identifier if present
    if let Some(cve_id) = &vuln.cve_id {
        identifiers.push(GitLabIdentifier {
            identifier_type: "cve".to_string(),
            name: cve_id.clone(),
            value: cve_id.clone(),
            url: Some(format!("https://nvd.nist.gov/vuln/detail/{}", cve_id)),
        });
    }

    // Generate a unique ID
    let vuln_id = format!(
        "{}-{}-{}",
        host.target.ip,
        vuln.cve_id.as_deref().unwrap_or("unknown"),
        vuln.affected_service.as_deref().unwrap_or("general")
    );
    let mut hasher = Sha256::new();
    hasher.update(vuln_id.as_bytes());
    let fingerprint = format!("{:x}", hasher.finalize())[..32].to_string();

    GitLabVulnerability {
        id: fingerprint.clone(),
        category: "dast".to_string(),
        name: vuln.title.clone(),
        message: vuln.title.clone(),
        description: vuln.description.clone(),
        severity,
        confidence: "High".to_string(),
        solution: Some("Review and remediate according to security best practices.".to_string()),
        scanner: scanner.clone(),
        identifiers,
        location: GitLabSecurityLocation {
            hostname: host.target.ip.to_string(),
            port,
            service: vuln.affected_service.clone(),
        },
        links: vuln.cve_id.as_ref().map(|cve| {
            vec![GitLabLink {
                name: "NVD".to_string(),
                url: format!("https://nvd.nist.gov/vuln/detail/{}", cve),
            }]
        }),
    }
}

/// Generate GitLab Code Quality report
pub fn generate_code_quality_report(
    scan_id: &str,
    hosts: &[HostInfo],
) -> Result<Vec<GitLabCodeQualityIssue>> {
    let mut issues: Vec<GitLabCodeQualityIssue> = Vec::new();

    for host in hosts {
        for vuln in &host.vulnerabilities {
            let fp_input = format!(
                "{}:{}:{}",
                host.target.ip,
                vuln.cve_id.as_deref().unwrap_or(&vuln.title),
                vuln.affected_service.as_deref().unwrap_or("unknown")
            );
            let mut hasher = Sha256::new();
            hasher.update(fp_input.as_bytes());
            let fingerprint = format!("{:x}", hasher.finalize())[..32].to_string();

            let severity = match vuln.severity {
                Severity::Critical => "blocker",
                Severity::High => "critical",
                Severity::Medium => "major",
                Severity::Low => "minor",
            };

            issues.push(GitLabCodeQualityIssue {
                description: format!(
                    "{} on {} ({})",
                    vuln.title,
                    host.target.ip,
                    vuln.affected_service.as_deref().unwrap_or("unknown service")
                ),
                check_name: vuln.cve_id.clone().unwrap_or_else(|| {
                    format!(
                        "heroforge/{}",
                        vuln.title.to_lowercase().replace(' ', "-")
                    )
                }),
                fingerprint,
                severity: severity.to_string(),
                location: GitLabLocation {
                    path: format!("network://{}", host.target.ip),
                    lines: Some(GitLabLines {
                        begin: 1,
                        end: None,
                    }),
                },
                categories: Some(vec!["Security".to_string()]),
            });
        }
    }

    Ok(issues)
}

/// Convert HeroForge severity to GitLab severity
fn severity_to_gitlab(severity: &Severity) -> String {
    match severity {
        Severity::Critical => "Critical".to_string(),
        Severity::High => "High".to_string(),
        Severity::Medium => "Medium".to_string(),
        Severity::Low => "Low".to_string(),
    }
}

/// Generate GitLab CI pipeline example (.gitlab-ci.yml)
pub fn generate_pipeline_example(api_url: &str) -> String {
    format!(
        r#"# HeroForge Security Scan - GitLab CI Configuration
stages:
  - security

variables:
  HEROFORGE_API_URL: "{api_url}"

security-scan:
  stage: security
  image: curlimages/curl:latest
  variables:
    GIT_STRATEGY: none
  before_script:
    - apk add --no-cache jq
  script:
    # Trigger the scan
    - |
      SCAN_RESPONSE=$(curl -s -X POST "$HEROFORGE_API_URL/api/cicd/scan" \
        -H "Authorization: Bearer $HEROFORGE_CI_TOKEN" \
        -H "Content-Type: application/json" \
        -d "{{
          \"name\": \"CI Security Scan - $CI_PROJECT_PATH\",
          \"targets\": [\"YOUR_TARGET_IP_OR_CIDR\"],
          \"port_range\": [1, 1000],
          \"enable_vuln_scan\": true,
          \"ci_ref\": \"$CI_COMMIT_SHA\",
          \"ci_branch\": \"$CI_COMMIT_REF_NAME\",
          \"ci_url\": \"$CI_PIPELINE_URL\",
          \"repository\": \"$CI_PROJECT_URL\"
        }}")

      RUN_ID=$(echo $SCAN_RESPONSE | jq -r '.run_id')
      SCAN_ID=$(echo $SCAN_RESPONSE | jq -r '.scan_id')
      echo "RUN_ID=$RUN_ID" >> variables.env
      echo "SCAN_ID=$SCAN_ID" >> variables.env
      echo "Scan started: $RUN_ID"

    # Poll for completion
    - |
      while true; do
        STATUS_RESPONSE=$(curl -s "$HEROFORGE_API_URL/api/cicd/scan/$RUN_ID/status" \
          -H "Authorization: Bearer $HEROFORGE_CI_TOKEN")
        STATUS=$(echo $STATUS_RESPONSE | jq -r '.status')
        PROGRESS=$(echo $STATUS_RESPONSE | jq -r '.progress')

        echo "Scan status: $STATUS ($PROGRESS%)"

        if [ "$STATUS" = "completed" ] || [ "$STATUS" = "failed" ]; then
          EXIT_CODE=$(echo $STATUS_RESPONSE | jq -r '.exit_code')
          echo "EXIT_CODE=$EXIT_CODE" >> variables.env
          break
        fi

        sleep 30
      done

    # Download GitLab Security Report
    - |
      source variables.env
      curl -s "$HEROFORGE_API_URL/api/cicd/scan/$RUN_ID/gitlab-security" \
        -H "Authorization: Bearer $HEROFORGE_CI_TOKEN" \
        -o gl-dast-report.json

    # Download Code Quality Report
    - |
      source variables.env
      curl -s "$HEROFORGE_API_URL/api/cicd/scan/$RUN_ID/gitlab-quality" \
        -H "Authorization: Bearer $HEROFORGE_CI_TOKEN" \
        -o gl-code-quality-report.json

  artifacts:
    reports:
      dast: gl-dast-report.json
      codequality: gl-code-quality-report.json
    paths:
      - gl-dast-report.json
      - gl-code-quality-report.json
    expire_in: 1 week
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_PIPELINE_SOURCE == "schedule"

quality-gate:
  stage: security
  needs:
    - security-scan
  script:
    - |
      source variables.env
      if [ "$EXIT_CODE" != "0" ]; then
        echo "Security scan failed quality gate check"
        exit 1
      fi
      echo "Quality gate passed"
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
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
    fn test_generate_security_report() {
        let hosts = vec![HostInfo {
            target: ScanTarget {
                ip: "192.168.1.1".parse::<IpAddr>().unwrap(),
                hostname: Some("test-host".to_string()),
            },
            is_alive: true,
            os_guess: None,
            ports: vec![],
            vulnerabilities: vec![Vulnerability {
                cve_id: Some("CVE-2024-1234".to_string()),
                title: "Test Vulnerability".to_string(),
                severity: Severity::High,
                description: "A test vulnerability".to_string(),
                affected_service: Some("http".to_string()),
            }],
            scan_duration: Duration::from_secs(10),
        }];

        let report = generate_security_report(
            "scan-123",
            &hosts,
            "Test Scan",
            "2024-01-01T00:00:00Z",
            "2024-01-01T00:10:00Z",
        )
        .unwrap();

        assert_eq!(report.version, "15.0.0");
        assert_eq!(report.vulnerabilities.len(), 1);

        let vuln = &report.vulnerabilities[0];
        assert_eq!(vuln.name, "Test Vulnerability");
        assert_eq!(vuln.severity, "High");
        assert_eq!(vuln.location.hostname, "192.168.1.1");
    }

    #[test]
    fn test_generate_code_quality_report() {
        let hosts = vec![HostInfo {
            target: ScanTarget {
                ip: "192.168.1.1".parse::<IpAddr>().unwrap(),
                hostname: None,
            },
            is_alive: true,
            os_guess: None,
            ports: vec![],
            vulnerabilities: vec![
                Vulnerability {
                    cve_id: Some("CVE-2024-1234".to_string()),
                    title: "Critical Issue".to_string(),
                    severity: Severity::Critical,
                    description: "Critical".to_string(),
                    affected_service: None,
                },
                Vulnerability {
                    cve_id: None,
                    title: "Low Issue".to_string(),
                    severity: Severity::Low,
                    description: "Low".to_string(),
                    affected_service: None,
                },
            ],
            scan_duration: Duration::from_secs(5),
        }];

        let issues = generate_code_quality_report("scan-123", &hosts).unwrap();

        assert_eq!(issues.len(), 2);
        assert_eq!(issues[0].severity, "blocker"); // Critical
        assert_eq!(issues[1].severity, "minor"); // Low
    }

    #[test]
    fn test_severity_mapping() {
        assert_eq!(severity_to_gitlab(&Severity::Critical), "Critical");
        assert_eq!(severity_to_gitlab(&Severity::High), "High");
        assert_eq!(severity_to_gitlab(&Severity::Medium), "Medium");
        assert_eq!(severity_to_gitlab(&Severity::Low), "Low");
    }
}
