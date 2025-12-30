// Jenkins Integration
#![allow(dead_code)]
#![allow(unused_variables)]

use super::types::*;
use crate::types::{HostInfo, Severity};
use anyhow::Result;
use chrono::Utc;

/// Generate JUnit XML report from scan results for Jenkins
pub fn generate_junit_report(
    scan_id: &str,
    hosts: &[HostInfo],
    scan_name: &str,
    quality_gate_result: Option<&QualityGateResult>,
) -> Result<String> {
    let mut testcases: Vec<JUnitTestCase> = Vec::new();
    let mut failures = 0;
    let start_time = Utc::now();

    // Create test cases for each host
    for host in hosts {
        let host_ip = host.target.ip.to_string();

        if host.vulnerabilities.is_empty() {
            // No vulnerabilities = passing test
            testcases.push(JUnitTestCase {
                name: format!("Host {} - No vulnerabilities", host_ip),
                classname: format!("heroforge.security.{}", host_ip.replace('.', "_")),
                time: host.scan_duration.as_secs_f64(),
                failure: None,
                error: None,
                skipped: None,
            });
        } else {
            // Each vulnerability is a test case
            for vuln in &host.vulnerabilities {
                let is_failure = matches!(vuln.severity, Severity::High | Severity::Critical);

                let testcase = JUnitTestCase {
                    name: format!("{} - {}", host_ip, vuln.title),
                    classname: format!(
                        "heroforge.security.{}.{}",
                        host_ip.replace('.', "_"),
                        vuln.affected_service.as_deref().unwrap_or("general")
                    ),
                    time: 0.0,
                    failure: if is_failure {
                        failures += 1;
                        Some(JUnitFailure {
                            message: vuln.title.clone(),
                            failure_type: format!("Severity::{:?}", vuln.severity),
                            content: format!(
                                "CVE: {}\nSeverity: {:?}\nDescription: {}\nAffected Service: {}",
                                vuln.cve_id.as_deref().unwrap_or("N/A"),
                                vuln.severity,
                                vuln.description,
                                vuln.affected_service.as_deref().unwrap_or("unknown")
                            ),
                        })
                    } else {
                        None
                    },
                    error: None,
                    skipped: None,
                };
                testcases.push(testcase);
            }
        }
    }

    // Add quality gate test case
    if let Some(qg_result) = quality_gate_result {
        let qg_testcase = JUnitTestCase {
            name: format!("Quality Gate: {}", qg_result.gate_name),
            classname: "heroforge.quality_gate".to_string(),
            time: 0.0,
            failure: if !qg_result.passed {
                failures += 1;
                Some(JUnitFailure {
                    message: qg_result.fail_reason.clone().unwrap_or_else(|| "Quality gate failed".to_string()),
                    failure_type: "QualityGateFailure".to_string(),
                    content: format!(
                        "Vulnerability Counts:\n  Critical: {}\n  High: {}\n  Medium: {}\n  Low: {}\n  Total: {}\n\nViolations:\n{}",
                        qg_result.vulnerability_counts.critical,
                        qg_result.vulnerability_counts.high,
                        qg_result.vulnerability_counts.medium,
                        qg_result.vulnerability_counts.low,
                        qg_result.vulnerability_counts.total,
                        qg_result.threshold_violations.iter()
                            .map(|v| format!("  - {}", v.message))
                            .collect::<Vec<_>>()
                            .join("\n")
                    ),
                })
            } else {
                None
            },
            error: None,
            skipped: None,
        };
        testcases.push(qg_testcase);
    }

    let total_tests = testcases.len() as i32;
    let scan_duration = Utc::now().signed_duration_since(start_time);

    let testsuite = JUnitTestSuite {
        name: scan_name.to_string(),
        tests: total_tests,
        failures,
        errors: 0,
        skipped: 0,
        time: scan_duration.num_milliseconds() as f64 / 1000.0,
        timestamp: Utc::now().format("%Y-%m-%dT%H:%M:%S").to_string(),
        testcases,
    };

    // Generate XML
    generate_junit_xml(&testsuite)
}

/// Generate JUnit XML string from test suite
fn generate_junit_xml(suite: &JUnitTestSuite) -> Result<String> {
    let mut xml = String::new();
    xml.push_str(r#"<?xml version="1.0" encoding="UTF-8"?>"#);
    xml.push('\n');

    xml.push_str(&format!(
        r#"<testsuites name="Genial Architect Scan" tests="{}" failures="{}" errors="{}" skipped="{}" time="{}">"#,
        suite.tests, suite.failures, suite.errors, suite.skipped, suite.time
    ));
    xml.push('\n');

    xml.push_str(&format!(
        r#"  <testsuite name="{}" tests="{}" failures="{}" errors="{}" skipped="{}" time="{}" timestamp="{}">"#,
        escape_xml(&suite.name),
        suite.tests,
        suite.failures,
        suite.errors,
        suite.skipped,
        suite.time,
        suite.timestamp
    ));
    xml.push('\n');

    for testcase in &suite.testcases {
        xml.push_str(&format!(
            r#"    <testcase name="{}" classname="{}" time="{}">"#,
            escape_xml(&testcase.name),
            escape_xml(&testcase.classname),
            testcase.time
        ));

        if let Some(failure) = &testcase.failure {
            xml.push('\n');
            xml.push_str(&format!(
                r#"      <failure message="{}" type="{}">{}</failure>"#,
                escape_xml(&failure.message),
                escape_xml(&failure.failure_type),
                escape_xml(&failure.content)
            ));
            xml.push('\n');
            xml.push_str("    ");
        }

        if let Some(error) = &testcase.error {
            xml.push('\n');
            xml.push_str(&format!(
                r#"      <error message="{}" type="{}">{}</error>"#,
                escape_xml(&error.message),
                escape_xml(&error.error_type),
                escape_xml(&error.content)
            ));
            xml.push('\n');
            xml.push_str("    ");
        }

        if testcase.skipped.is_some() {
            xml.push('\n');
            xml.push_str("      <skipped/>");
            xml.push('\n');
            xml.push_str("    ");
        }

        xml.push_str("</testcase>\n");
    }

    xml.push_str("  </testsuite>\n");
    xml.push_str("</testsuites>");

    Ok(xml)
}

/// Escape XML special characters
fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// Generate Jenkins pipeline example (Jenkinsfile)
pub fn generate_pipeline_example(api_url: &str) -> String {
    format!(
        r#"// Genial Architect Scan - Jenkins Pipeline
pipeline {{
    agent any

    environment {{
        HEROFORGE_API_URL = '{api_url}'
        HEROFORGE_TOKEN = credentials('heroforge-ci-token')
    }}

    stages {{
        stage('Security Scan') {{
            steps {{
                script {{
                    // Trigger the scan
                    def scanResponse = httpRequest(
                        url: "${{HEROFORGE_API_URL}}/api/cicd/scan",
                        httpMode: 'POST',
                        contentType: 'APPLICATION_JSON',
                        customHeaders: [[name: 'Authorization', value: "Bearer ${{HEROFORGE_TOKEN}}"]],
                        requestBody: """{{
                            "name": "CI Security Scan - ${{env.JOB_NAME}} #${{env.BUILD_NUMBER}}",
                            "targets": ["YOUR_TARGET_IP_OR_CIDR"],
                            "port_range": [1, 1000],
                            "enable_vuln_scan": true,
                            "ci_ref": "${{env.GIT_COMMIT}}",
                            "ci_branch": "${{env.GIT_BRANCH}}",
                            "ci_url": "${{env.BUILD_URL}}",
                            "repository": "${{env.GIT_URL}}"
                        }}"""
                    )

                    def scanData = readJSON text: scanResponse.content
                    env.RUN_ID = scanData.run_id
                    env.SCAN_ID = scanData.scan_id

                    echo "Scan started: ${{env.RUN_ID}}"

                    // Poll for completion
                    def completed = false
                    while (!completed) {{
                        sleep(time: 30, unit: 'SECONDS')

                        def statusResponse = httpRequest(
                            url: "${{HEROFORGE_API_URL}}/api/cicd/scan/${{env.RUN_ID}}/status",
                            httpMode: 'GET',
                            customHeaders: [[name: 'Authorization', value: "Bearer ${{HEROFORGE_TOKEN}}"]]
                        )

                        def statusData = readJSON text: statusResponse.content
                        echo "Scan status: ${{statusData.status}} (${{statusData.progress}}%)"

                        if (statusData.status == 'completed' || statusData.status == 'failed') {{
                            completed = true
                            env.EXIT_CODE = statusData.exit_code
                        }}
                    }}
                }}
            }}
        }}

        stage('Download Results') {{
            steps {{
                script {{
                    // Download JUnit XML results
                    def junitResponse = httpRequest(
                        url: "${{HEROFORGE_API_URL}}/api/cicd/scan/${{env.RUN_ID}}/junit",
                        httpMode: 'GET',
                        customHeaders: [[name: 'Authorization', value: "Bearer ${{HEROFORGE_TOKEN}}"]]
                    )
                    writeFile file: 'heroforge-results.xml', text: junitResponse.content
                }}
            }}
        }}

        stage('Publish Results') {{
            steps {{
                // Publish JUnit test results
                junit 'heroforge-results.xml'
            }}
        }}

        stage('Quality Gate') {{
            steps {{
                script {{
                    if (env.EXIT_CODE != '0') {{
                        error 'Security scan failed quality gate check'
                    }}
                }}
            }}
        }}
    }}

    post {{
        always {{
            // Archive the results
            archiveArtifacts artifacts: 'heroforge-results.xml', allowEmptyArchive: true
        }}
        failure {{
            // Send notification on failure
            echo 'Security scan detected vulnerabilities that failed the quality gate'
        }}
    }}
}}
"#,
        api_url = api_url
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ScanTarget, Severity, Vulnerability};
    use std::net::IpAddr;
    use std::time::Duration;

    #[test]
    fn test_generate_junit_report() {
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
                    title: "Critical Vulnerability".to_string(),
                    severity: Severity::Critical,
                    description: "A critical vulnerability".to_string(),
                    affected_service: Some("http".to_string()),
                },
                Vulnerability {
                    cve_id: None,
                    title: "Low Severity Issue".to_string(),
                    severity: Severity::Low,
                    description: "A low severity issue".to_string(),
                    affected_service: Some("ssh".to_string()),
                },
            ],
            scan_duration: Duration::from_secs(10),
        }];

        let result = generate_junit_report("scan-123", &hosts, "Test Scan", None).unwrap();

        assert!(result.contains(r#"<?xml version="1.0" encoding="UTF-8"?>"#));
        assert!(result.contains("testsuites"));
        assert!(result.contains("testsuite"));
        assert!(result.contains("testcase"));
        assert!(result.contains("failure")); // Critical vuln should have failure
        assert!(result.contains("CVE-2024-1234"));
    }

    #[test]
    fn test_generate_junit_with_quality_gate() {
        let hosts = vec![];
        let qg_result = QualityGateResult {
            passed: false,
            gate_name: "Default Quality Gate".to_string(),
            fail_reason: Some("Critical vulnerabilities found".to_string()),
            vulnerability_counts: VulnerabilityCounts {
                critical: 1,
                high: 0,
                medium: 0,
                low: 0,
                total: 1,
            },
            threshold_violations: vec![ThresholdViolation {
                threshold_type: "max_critical".to_string(),
                threshold_value: 0,
                actual_value: 1,
                message: "Critical vulnerabilities: 1 (max: 0)".to_string(),
            }],
            new_vulnerabilities: None,
        };

        let result = generate_junit_report("scan-123", &hosts, "Test Scan", Some(&qg_result)).unwrap();

        assert!(result.contains("Quality Gate"));
        assert!(result.contains("QualityGateFailure"));
        assert!(result.contains("Critical vulnerabilities found"));
    }

    #[test]
    fn test_escape_xml() {
        assert_eq!(escape_xml("a < b > c"), "a &lt; b &gt; c");
        assert_eq!(escape_xml("a & b"), "a &amp; b");
        assert_eq!(escape_xml(r#"a "quote" b"#), "a &quot;quote&quot; b");
    }

    #[test]
    fn test_no_vulnerabilities_passes() {
        let hosts = vec![HostInfo {
            target: ScanTarget {
                ip: "192.168.1.1".parse::<IpAddr>().unwrap(),
                hostname: None,
            },
            is_alive: true,
            os_guess: None,
            ports: vec![],
            vulnerabilities: vec![],
            scan_duration: Duration::from_secs(5),
        }];

        let result = generate_junit_report("scan-123", &hosts, "Clean Scan", None).unwrap();

        assert!(result.contains("No vulnerabilities"));
        assert!(!result.contains("<failure"));
    }
}
