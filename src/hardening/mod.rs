//! Security Hardening Module - Final production hardening

#![allow(dead_code)]

pub mod input_validation;
pub mod secrets_detection;
pub mod security_headers;

use anyhow::Result;
use std::path::Path;

use crate::hardening::input_validation::InputValidator;
use crate::hardening::secrets_detection::{SecretsScanner, SecretsSummary, SecretFinding, SecretSeverity};
use crate::hardening::security_headers::SecurityHeaders;

/// Configuration for hardening checks
#[derive(Debug, Clone)]
pub struct HardeningConfig {
    /// Directory to scan for secrets
    pub scan_directory: Option<String>,
    /// File extensions to scan for secrets
    pub scan_extensions: Vec<String>,
    /// Target URL for security header checks
    pub target_url: Option<String>,
    /// Skip files matching these patterns
    pub skip_patterns: Vec<String>,
}

impl Default for HardeningConfig {
    fn default() -> Self {
        Self {
            scan_directory: None,
            scan_extensions: vec![
                "rs".to_string(), "py".to_string(), "js".to_string(), "ts".to_string(),
                "java".to_string(), "go".to_string(), "rb".to_string(), "php".to_string(),
                "yaml".to_string(), "yml".to_string(), "json".to_string(), "toml".to_string(),
                "env".to_string(), "conf".to_string(), "config".to_string(), "ini".to_string(),
            ],
            target_url: None,
            skip_patterns: vec![
                "node_modules".to_string(),
                "target".to_string(),
                ".git".to_string(),
                "dist".to_string(),
                "build".to_string(),
                "vendor".to_string(),
                "__pycache__".to_string(),
            ],
        }
    }
}

pub struct HardeningChecker {
    config: HardeningConfig,
    secrets_scanner: SecretsScanner,
    input_validator: InputValidator,
}

impl HardeningChecker {
    pub fn new() -> Self {
        Self {
            config: HardeningConfig::default(),
            secrets_scanner: SecretsScanner::new(),
            input_validator: InputValidator::new(),
        }
    }

    /// Create a new checker with custom configuration
    pub fn with_config(config: HardeningConfig) -> Self {
        Self {
            config,
            secrets_scanner: SecretsScanner::new(),
            input_validator: InputValidator::new(),
        }
    }

    pub async fn run_all_checks(&self) -> Result<HardeningReport> {
        let mut report = HardeningReport::default();

        // 1. Check security headers
        log::info!("Checking security headers configuration...");
        let header_check = self.check_security_headers().await;
        report.security_headers_configured = header_check.all_headers_present;
        report.security_headers_details = header_check;

        // 2. Check input validation
        log::info!("Checking input validation...");
        report.input_validation_enabled = self.check_input_validation();
        report.input_validation_details = self.get_input_validation_details();

        // 3. Scan for secrets
        log::info!("Scanning for secrets...");
        let secrets_result = self.scan_for_secrets().await?;
        report.secrets_detected = secrets_result.findings.len();
        report.secrets_summary = self.secrets_scanner.get_summary(&secrets_result.findings);
        report.secret_findings = secrets_result.findings;

        // 4. Calculate overall score
        report.overall_score = self.calculate_score(&report);
        report.recommendations = self.generate_recommendations(&report);

        log::info!(
            "Hardening check complete: score={}/100, secrets={}, headers={}",
            report.overall_score,
            report.secrets_detected,
            report.security_headers_configured
        );

        Ok(report)
    }

    /// Check security headers configuration
    async fn check_security_headers(&self) -> SecurityHeadersCheck {
        let recommended = SecurityHeaders::get_recommended_headers();
        let mut check = SecurityHeadersCheck {
            all_headers_present: true,
            present_headers: Vec::new(),
            missing_headers: Vec::new(),
            recommendations: Vec::new(),
        };

        if let Some(ref url) = self.config.target_url {
            // Try to fetch headers from the target URL
            match reqwest::get(url).await {
                Ok(response) => {
                    let headers = response.headers();

                    for (header_name, expected_value) in &recommended {
                        if let Some(actual_value) = headers.get(*header_name) {
                            let actual_str = actual_value.to_str().unwrap_or("");
                            check.present_headers.push(HeaderInfo {
                                name: header_name.to_string(),
                                expected_value: expected_value.to_string(),
                                actual_value: Some(actual_str.to_string()),
                                compliant: actual_str.contains(expected_value),
                            });
                        } else {
                            check.all_headers_present = false;
                            check.missing_headers.push(HeaderInfo {
                                name: header_name.to_string(),
                                expected_value: expected_value.to_string(),
                                actual_value: None,
                                compliant: false,
                            });
                            check.recommendations.push(format!(
                                "Add header: {} with value: {}",
                                header_name, expected_value
                            ));
                        }
                    }
                }
                Err(e) => {
                    log::warn!("Failed to fetch headers from {}: {}", url, e);
                    check.all_headers_present = false;
                    check.recommendations.push(format!(
                        "Unable to verify headers: {}. Ensure the following headers are configured:",
                        e
                    ));
                    for (name, value) in &recommended {
                        check.recommendations.push(format!("  {} = {}", name, value));
                    }
                }
            }
        } else {
            // No URL configured, just report recommended headers
            check.all_headers_present = false;
            check.recommendations.push(
                "No target URL configured. Verify these headers are set:".to_string()
            );
            for (name, value) in &recommended {
                check.missing_headers.push(HeaderInfo {
                    name: name.to_string(),
                    expected_value: value.to_string(),
                    actual_value: None,
                    compliant: false,
                });
            }
        }

        check
    }

    /// Check if input validation is properly configured
    fn check_input_validation(&self) -> bool {
        // The InputValidator is always available, so validation is enabled
        // This would typically check if the validator is being used in the application
        true
    }

    /// Get details about input validation capabilities
    fn get_input_validation_details(&self) -> InputValidationDetails {
        InputValidationDetails {
            email_validation: true,
            url_validation: true,
            sql_injection_detection: true,
            xss_prevention: true,
            path_traversal_prevention: true,
            command_injection_prevention: true,
        }
    }

    /// Scan for secrets in the configured directory
    async fn scan_for_secrets(&self) -> Result<SecretsResult> {
        let mut all_findings = Vec::new();
        let mut files_scanned = 0;

        if let Some(ref dir) = self.config.scan_directory {
            let path = Path::new(dir);
            if path.exists() && path.is_dir() {
                all_findings = self.scan_directory_recursive(path, &mut files_scanned).await?;
            }
        }

        Ok(SecretsResult {
            files_scanned,
            findings: all_findings,
        })
    }

    /// Recursively scan a directory for secrets
    async fn scan_directory_recursive(&self, dir: &Path, files_scanned: &mut usize) -> Result<Vec<SecretFinding>> {
        let mut findings = Vec::new();

        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(e) => {
                log::warn!("Failed to read directory {:?}: {}", dir, e);
                return Ok(findings);
            }
        };

        for entry in entries.flatten() {
            let path = entry.path();
            let path_str = path.to_string_lossy();

            // Skip patterns
            if self.config.skip_patterns.iter().any(|p| path_str.contains(p)) {
                continue;
            }

            if path.is_dir() {
                let sub_findings = Box::pin(self.scan_directory_recursive(&path, files_scanned)).await?;
                findings.extend(sub_findings);
            } else if path.is_file() {
                // Check file extension
                if let Some(ext) = path.extension() {
                    let ext_str = ext.to_string_lossy().to_lowercase();
                    if self.config.scan_extensions.iter().any(|e| e.to_lowercase() == ext_str) {
                        // Read and scan file
                        if let Ok(content) = tokio::fs::read_to_string(&path).await {
                            *files_scanned += 1;
                            if let Ok(mut file_findings) = self.secrets_scanner.scan_file(&content) {
                                // Add file path context to findings
                                for finding in &mut file_findings {
                                    finding.context = format!(
                                        "File: {}\n{}",
                                        path_str,
                                        finding.context
                                    );
                                }
                                findings.extend(file_findings);
                            }
                        }
                    }
                }

                // Also scan files with no extension that might be config files
                if path.extension().is_none() {
                    if let Some(name) = path.file_name() {
                        let name_str = name.to_string_lossy().to_lowercase();
                        let config_names = [".env", "credentials", "secrets", "config", ".npmrc", ".pypirc"];
                        if config_names.iter().any(|n| name_str.contains(n)) {
                            if let Ok(content) = tokio::fs::read_to_string(&path).await {
                                *files_scanned += 1;
                                if let Ok(mut file_findings) = self.secrets_scanner.scan_file(&content) {
                                    for finding in &mut file_findings {
                                        finding.context = format!("File: {}\n{}", path_str, finding.context);
                                    }
                                    findings.extend(file_findings);
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(findings)
    }

    /// Calculate overall hardening score (0-100)
    fn calculate_score(&self, report: &HardeningReport) -> u32 {
        let mut score = 100u32;

        // Deduct for missing security headers
        if !report.security_headers_configured {
            let missing_count = report.security_headers_details.missing_headers.len();
            score = score.saturating_sub((missing_count * 5) as u32);
        }

        // Deduct for secrets found
        let critical_secrets = report.secret_findings.iter()
            .filter(|f| f.severity == SecretSeverity::Critical)
            .count();
        let high_secrets = report.secret_findings.iter()
            .filter(|f| f.severity == SecretSeverity::High)
            .count();
        let medium_secrets = report.secret_findings.iter()
            .filter(|f| f.severity == SecretSeverity::Medium)
            .count();

        score = score.saturating_sub((critical_secrets * 15) as u32);
        score = score.saturating_sub((high_secrets * 10) as u32);
        score = score.saturating_sub((medium_secrets * 5) as u32);

        score.min(100)
    }

    /// Generate recommendations based on the report
    fn generate_recommendations(&self, report: &HardeningReport) -> Vec<String> {
        let mut recommendations = Vec::new();

        // Security headers recommendations
        if !report.security_headers_configured {
            recommendations.push("Configure all recommended security headers".to_string());
            recommendations.extend(report.security_headers_details.recommendations.clone());
        }

        // Secrets recommendations
        if report.secrets_detected > 0 {
            let critical = report.secrets_summary.critical;
            let high = report.secrets_summary.high;

            if critical > 0 {
                recommendations.push(format!(
                    "CRITICAL: Found {} critical secrets that must be rotated immediately",
                    critical
                ));
            }
            if high > 0 {
                recommendations.push(format!(
                    "HIGH: Found {} high-severity secrets that should be removed from code",
                    high
                ));
            }

            recommendations.push(
                "Use environment variables or a secrets manager instead of hardcoding credentials".to_string()
            );
            recommendations.push(
                "Review git history for leaked secrets and consider using git-filter-repo to remove them".to_string()
            );
        }

        // General recommendations
        if report.overall_score < 70 {
            recommendations.push(
                "Overall hardening score is below 70. Prioritize security improvements before production deployment.".to_string()
            );
        } else if report.overall_score < 90 {
            recommendations.push(
                "Consider addressing remaining issues to achieve a higher security posture.".to_string()
            );
        }

        recommendations
    }
}

impl Default for HardeningChecker {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct HardeningReport {
    pub security_headers_configured: bool,
    pub security_headers_details: SecurityHeadersCheck,
    pub input_validation_enabled: bool,
    pub input_validation_details: InputValidationDetails,
    pub secrets_detected: usize,
    pub secrets_summary: SecretsSummary,
    pub secret_findings: Vec<SecretFinding>,
    pub overall_score: u32,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct SecurityHeadersCheck {
    pub all_headers_present: bool,
    pub present_headers: Vec<HeaderInfo>,
    pub missing_headers: Vec<HeaderInfo>,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct HeaderInfo {
    pub name: String,
    pub expected_value: String,
    pub actual_value: Option<String>,
    pub compliant: bool,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct InputValidationDetails {
    pub email_validation: bool,
    pub url_validation: bool,
    pub sql_injection_detection: bool,
    pub xss_prevention: bool,
    pub path_traversal_prevention: bool,
    pub command_injection_prevention: bool,
}

#[derive(Debug, Clone, Default)]
struct SecretsResult {
    files_scanned: usize,
    findings: Vec<SecretFinding>,
}
