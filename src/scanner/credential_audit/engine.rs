//! Credential Audit Engine
//!
//! This module provides the orchestration engine for credential auditing.
//! It coordinates testing credentials across multiple targets with rate limiting
//! and progress reporting.
//!
//! **WARNING: This tool is for AUTHORIZED SECURITY TESTING ONLY.**
//! Unauthorized access to computer systems is illegal. Only use this tool
//! on systems you have explicit permission to test.

use super::testers::test_credential;
use super::types::*;
use super::wordlists::get_credentials_for_service;
use anyhow::Result;
use chrono::Utc;
use log::{debug, error, info, warn};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{broadcast, Semaphore};
use tokio::time::{sleep, Duration};
use uuid::Uuid;

/// Credential Audit Engine
///
/// Orchestrates credential testing across multiple targets with rate limiting,
/// progress reporting, and result aggregation.
pub struct CredentialAuditEngine {
    config: CredentialAuditConfig,
    progress_tx: Option<broadcast::Sender<CredentialAuditProgress>>,
}

impl CredentialAuditEngine {
    /// Create a new credential audit engine with the given configuration
    pub fn new(config: CredentialAuditConfig) -> Self {
        Self {
            config,
            progress_tx: None,
        }
    }

    /// Set the progress channel for real-time updates
    pub fn with_progress_channel(
        mut self,
        tx: broadcast::Sender<CredentialAuditProgress>,
    ) -> Self {
        self.progress_tx = Some(tx);
        self
    }

    /// Run the credential audit
    pub async fn run(&self) -> Result<CredentialAuditResult> {
        let id = Uuid::new_v4().to_string();
        let started_at = Utc::now().to_rfc3339();
        let start_time = Instant::now();

        info!(
            "Starting credential audit {} with {} targets",
            id,
            self.config.targets.len()
        );

        // Send started progress
        self.send_progress(CredentialAuditProgress::Started {
            id: id.clone(),
            total_targets: self.config.targets.len(),
        });

        // Prepare semaphore for rate limiting
        let semaphore = Arc::new(Semaphore::new(self.config.max_concurrent));

        // Process each target
        let mut results = Vec::new();
        let mut total_attempts = 0;
        let mut total_successful = 0;
        let mut total_errors = 0;
        let mut services_tested = Vec::new();

        for target in &self.config.targets {
            let target_result = self
                .audit_target(target, semaphore.clone())
                .await;

            match target_result {
                Ok(result) => {
                    total_attempts += result.failed_attempts + result.successful_credentials.len();
                    total_successful += result.successful_credentials.len();
                    total_errors += result.connection_errors;

                    if !services_tested.contains(&target.service_type) {
                        services_tested.push(target.service_type);
                    }

                    // Send target completed progress
                    self.send_progress(CredentialAuditProgress::TargetCompleted {
                        host: target.host.clone(),
                        port: target.port,
                        successful_logins: result.successful_credentials.len(),
                    });

                    results.push(result);
                }
                Err(e) => {
                    error!(
                        "Error auditing target {}:{}: {}",
                        target.host, target.port, e
                    );
                    total_errors += 1;

                    results.push(TargetAuditResult {
                        target: target.clone(),
                        successful_credentials: Vec::new(),
                        failed_attempts: 0,
                        connection_errors: 1,
                        error_message: Some(e.to_string()),
                    });
                }
            }
        }

        let duration_secs = start_time.elapsed().as_secs_f64();
        let completed_at = Utc::now().to_rfc3339();

        let summary = CredentialAuditSummary {
            total_targets: self.config.targets.len(),
            total_attempts,
            successful_logins: total_successful,
            failed_attempts: total_attempts - total_successful,
            connection_errors: total_errors,
            services_tested,
        };

        // Send completed progress
        self.send_progress(CredentialAuditProgress::Completed {
            id: id.clone(),
            summary: summary.clone(),
        });

        info!(
            "Credential audit {} completed: {} successful logins found out of {} attempts",
            id, total_successful, total_attempts
        );

        Ok(CredentialAuditResult {
            id,
            status: CredentialAuditStatus::Completed,
            config: self.config.clone(),
            results,
            summary,
            started_at,
            completed_at: Some(completed_at),
            duration_secs: Some(duration_secs),
        })
    }

    /// Audit a single target
    async fn audit_target(
        &self,
        target: &CredentialAuditTarget,
        semaphore: Arc<Semaphore>,
    ) -> Result<TargetAuditResult> {
        info!(
            "Auditing target {}:{} ({})",
            target.host,
            target.port,
            target.service_type.display_name()
        );

        // Send target started progress
        self.send_progress(CredentialAuditProgress::TargetStarted {
            host: target.host.clone(),
            port: target.port,
            service_type: target.service_type,
        });

        // Get credentials to test
        let custom_creds: Option<Vec<(String, String)>> = if self.config.custom_credentials.is_empty()
        {
            None
        } else {
            Some(self.config.custom_credentials.clone())
        };

        let credentials = get_credentials_for_service(
            target.service_type,
            custom_creds.as_deref(),
            self.config.default_creds_only,
        );

        debug!(
            "Testing {} credentials against {}:{}",
            credentials.len(),
            target.host,
            target.port
        );

        let mut successful_credentials = Vec::new();
        let mut failed_attempts = 0;
        let mut connection_errors = 0;
        let mut attempt_count = 0;

        for credential in &credentials {
            // Check max attempts limit
            if self.config.max_attempts_per_account > 0
                && attempt_count >= self.config.max_attempts_per_account
            {
                debug!(
                    "Reached max attempts per account ({}), stopping",
                    self.config.max_attempts_per_account
                );
                break;
            }

            // Acquire semaphore permit for rate limiting
            let _permit = semaphore.acquire().await?;

            // Add delay between attempts
            if attempt_count > 0 && self.config.delay_between_attempts_ms > 0 {
                sleep(Duration::from_millis(self.config.delay_between_attempts_ms)).await;
            }

            attempt_count += 1;

            // Test the credential
            let result = test_credential(
                &target.host,
                target.port,
                target.service_type,
                credential,
                self.config.timeout,
                target.use_ssl,
                target.path.as_deref(),
            )
            .await;

            // Send attempt progress
            self.send_progress(CredentialAuditProgress::AttemptMade {
                host: target.host.clone(),
                port: target.port,
                username: credential.username.clone(),
                success: result.success,
            });

            if result.success {
                info!(
                    "SUCCESS: Valid credentials found for {}:{} - user: {}",
                    target.host, target.port, credential.username
                );
                successful_credentials.push(result);

                if self.config.stop_on_success {
                    debug!("Stopping on first success as configured");
                    break;
                }
            } else if result.error.is_some() {
                connection_errors += 1;
                debug!(
                    "Connection error for {}:{}: {:?}",
                    target.host, target.port, result.error
                );
            } else {
                failed_attempts += 1;
            }
        }

        Ok(TargetAuditResult {
            target: target.clone(),
            successful_credentials,
            failed_attempts,
            connection_errors,
            error_message: None,
        })
    }

    /// Send a progress update if a channel is configured
    fn send_progress(&self, progress: CredentialAuditProgress) {
        if let Some(tx) = &self.progress_tx {
            let _ = tx.send(progress);
        }
    }
}

/// Create targets from scan results (detected services)
pub fn create_targets_from_services(
    hosts: &[crate::types::HostInfo],
) -> Vec<CredentialAuditTarget> {
    let mut targets = Vec::new();

    for host in hosts {
        for port in &host.ports {
            if port.state != crate::types::PortState::Open {
                continue;
            }

            // Try to determine service type from detected service
            let service_type = if let Some(service) = &port.service {
                match service.name.to_lowercase().as_str() {
                    "ssh" | "openssh" => Some(CredentialServiceType::Ssh),
                    "ftp" | "vsftpd" | "proftpd" => Some(CredentialServiceType::Ftp),
                    "telnet" => Some(CredentialServiceType::Telnet),
                    "mysql" | "mariadb" => Some(CredentialServiceType::Mysql),
                    "postgresql" | "postgres" => Some(CredentialServiceType::Postgresql),
                    "mssql" | "ms-sql" | "sqlserver" => Some(CredentialServiceType::Mssql),
                    "mongodb" | "mongo" => Some(CredentialServiceType::Mongodb),
                    "redis" => Some(CredentialServiceType::Redis),
                    "snmp" => Some(CredentialServiceType::Snmp),
                    "rdp" | "ms-wbt-server" => Some(CredentialServiceType::Rdp),
                    "vnc" => Some(CredentialServiceType::Vnc),
                    _ => None,
                }
            } else {
                // Fall back to port-based detection
                match port.port {
                    21 => Some(CredentialServiceType::Ftp),
                    22 => Some(CredentialServiceType::Ssh),
                    23 => Some(CredentialServiceType::Telnet),
                    161 => Some(CredentialServiceType::Snmp),
                    1433 => Some(CredentialServiceType::Mssql),
                    3306 => Some(CredentialServiceType::Mysql),
                    3389 => Some(CredentialServiceType::Rdp),
                    5432 => Some(CredentialServiceType::Postgresql),
                    5900..=5910 => Some(CredentialServiceType::Vnc),
                    6379 => Some(CredentialServiceType::Redis),
                    27017 => Some(CredentialServiceType::Mongodb),
                    _ => None,
                }
            };

            if let Some(svc_type) = service_type {
                targets.push(CredentialAuditTarget::new(
                    host.target.ip.to_string(),
                    port.port,
                    svc_type,
                ));
            }
        }
    }

    targets
}

/// Run a quick credential audit on scan results
pub async fn run_quick_audit(
    hosts: &[crate::types::HostInfo],
    progress_tx: Option<broadcast::Sender<CredentialAuditProgress>>,
) -> Result<CredentialAuditResult> {
    let targets = create_targets_from_services(hosts);

    if targets.is_empty() {
        return Ok(CredentialAuditResult {
            id: Uuid::new_v4().to_string(),
            status: CredentialAuditStatus::Completed,
            config: CredentialAuditConfig::default(),
            results: Vec::new(),
            summary: CredentialAuditSummary {
                total_targets: 0,
                total_attempts: 0,
                successful_logins: 0,
                failed_attempts: 0,
                connection_errors: 0,
                services_tested: Vec::new(),
            },
            started_at: Utc::now().to_rfc3339(),
            completed_at: Some(Utc::now().to_rfc3339()),
            duration_secs: Some(0.0),
        });
    }

    let config = CredentialAuditConfig {
        targets,
        default_creds_only: true, // Quick mode uses only default creds
        stop_on_success: true,
        max_concurrent: 3,
        delay_between_attempts_ms: 500,
        ..Default::default()
    };

    let mut engine = CredentialAuditEngine::new(config);

    if let Some(tx) = progress_tx {
        engine = engine.with_progress_channel(tx);
    }

    engine.run().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_credential_audit_engine_creation() {
        let config = CredentialAuditConfig::default();
        let engine = CredentialAuditEngine::new(config);
        assert!(engine.progress_tx.is_none());
    }

    #[test]
    fn test_create_targets_from_empty_hosts() {
        let hosts: Vec<crate::types::HostInfo> = Vec::new();
        let targets = create_targets_from_services(&hosts);
        assert!(targets.is_empty());
    }

    #[tokio::test]
    async fn test_quick_audit_no_targets() {
        let hosts: Vec<crate::types::HostInfo> = Vec::new();
        let result = run_quick_audit(&hosts, None).await.unwrap();
        assert_eq!(result.status, CredentialAuditStatus::Completed);
        assert_eq!(result.summary.total_targets, 0);
    }
}
