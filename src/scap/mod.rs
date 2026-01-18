//! SCAP 1.3 Security Content Automation Protocol Engine
//!
//! This module provides a complete implementation of SCAP 1.3 for HeroForge,
//! enabling standardized vulnerability assessment and compliance checking.
//!
//! # Components
//!
//! - **CPE**: Common Platform Enumeration - Platform identification and matching
//! - **CCE**: Common Configuration Enumeration - Configuration identifiers
//! - **XCCDF**: Extensible Configuration Checklist Description Format - Benchmarks and profiles
//! - **OVAL**: Open Vulnerability and Assessment Language - Technical checks
//! - **ARF**: Asset Reporting Format - Standardized results output
//!
//! # Usage
//!
//! ```rust,ignore
//! use heroforge::scap::{ScapEngine, ScapScanConfig};
//!
//! // Load SCAP content
//! let engine = ScapEngine::new(pool).await?;
//! engine.import_content("path/to/stig.zip").await?;
//!
//! // List available benchmarks
//! let benchmarks = engine.list_benchmarks().await?;
//!
//! // Execute a SCAP scan
//! let config = ScapScanConfig {
//!     target: "192.168.1.100".to_string(),
//!     benchmark_id: "windows_server_2022".to_string(),
//!     profile_id: "CAT_I_Only".to_string(),
//!     ..Default::default()
//! };
//! let results = engine.execute_scan(config).await?;
//!
//! // Generate ARF report
//! let arf = engine.generate_arf(&results).await?;
//! ```

pub mod types;
pub mod content;
pub mod cpe;
pub mod cce;
pub mod xccdf;
pub mod oval;
pub mod arf;
pub mod ckl;
pub mod integration;
pub mod stig_sync;

// Re-export commonly used types
pub use types::{
    // Common types
    ScapVersion,
    LocalizedText,
    Reference,

    // Content bundle types
    ScapContentBundle,
    ScapContentSource,
    ContentStatus,
    BundleId,

    // Severity and status
    ScapSeverity,
    StigCategory,
    ExecutionStatus,

    // Identifiers
    CceId,
    CciId,
    CveId,
    Ident,

    // Platform types
    TargetPlatform,

    // Scan types
    ScapScanConfig,
    ScapCredentials,
    ScapAuthType,
    ScapScanExecution,
    ExecutionId,
    ExecutionStatistics,

    // Remediation
    RemediationInfo,
    RemediationComplexity,
    DisruptionLevel,

    // Errors
    ScapError,

    // Utilities
    generate_scap_id,
    parse_scap_date,
    sanitize_xml,
};

use anyhow::{Result, Context};
use sqlx::SqlitePool;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Main SCAP engine for content management and scan execution
pub struct ScapEngine {
    pool: SqlitePool,
    /// Cached content repository
    content_cache: Arc<RwLock<content::ContentRepository>>,
    /// CPE dictionary for platform matching
    cpe_dictionary: Arc<RwLock<cpe::CpeDictionary>>,
}

impl ScapEngine {
    /// Create a new SCAP engine
    pub async fn new(pool: SqlitePool) -> Result<Self> {
        let content_cache = Arc::new(RwLock::new(content::ContentRepository::new()));
        let cpe_dictionary = Arc::new(RwLock::new(cpe::CpeDictionary::new()));

        Ok(Self {
            pool,
            content_cache,
            cpe_dictionary,
        })
    }

    /// Import SCAP content from a file (ZIP or DataStream)
    pub async fn import_content(
        &self,
        path: &str,
        source: ScapContentSource,
    ) -> Result<ScapContentBundle> {
        let loader = content::ContentLoader::new();

        // First load the bundle metadata
        let bundle = loader.load_from_file(path, source).await?;

        // Read the file and parse full content for validation
        let data = tokio::fs::read(path).await
            .with_context(|| format!("Failed to read file: {}", path))?;
        let parsed_content = loader.parse_full(&data).await?;

        // Validate content
        let validator = content::ContentValidator::new();
        let validation_result = validator.validate(&parsed_content)?;

        if !validation_result.is_valid() {
            // Log errors but allow import to continue with warnings
            for error in &validation_result.errors {
                log::warn!("SCAP validation error [{}]: {}", error.code, error.message);
            }
        }

        for warning in &validation_result.warnings {
            log::debug!("SCAP validation warning [{}]: {}", warning.code, warning.message);
        }

        // Store in database
        let mut cache = self.content_cache.write().await;
        cache.add_bundle(bundle.clone(), &self.pool).await?;

        Ok(bundle)
    }

    /// List all available benchmarks
    pub async fn list_benchmarks(&self) -> Result<Vec<xccdf::XccdfBenchmarkSummary>> {
        let cache = self.content_cache.read().await;
        cache.list_benchmarks(&self.pool).await
    }

    /// Get a specific benchmark with full details
    pub async fn get_benchmark(&self, benchmark_id: &str) -> Result<xccdf::XccdfBenchmark> {
        let cache = self.content_cache.read().await;
        cache.get_benchmark(benchmark_id, &self.pool).await
    }

    /// List profiles for a benchmark
    pub async fn list_profiles(&self, benchmark_id: &str) -> Result<Vec<xccdf::XccdfProfile>> {
        let benchmark = self.get_benchmark(benchmark_id).await?;
        Ok(benchmark.profiles)
    }

    /// Execute a SCAP scan
    pub async fn execute_scan(
        &self,
        config: ScapScanConfig,
        progress_tx: Option<tokio::sync::broadcast::Sender<ScapProgressMessage>>,
    ) -> Result<ScapScanExecution> {
        // Create execution record
        let execution_id = generate_scap_id();
        let mut execution = ScapScanExecution {
            id: execution_id.clone(),
            scan_id: generate_scap_id(),
            benchmark_id: config.benchmark_id.clone(),
            profile_id: config.profile_id.clone(),
            target_host: config.target.clone(),
            target_cpes: Vec::new(),
            status: ExecutionStatus::Pending,
            started_at: None,
            completed_at: None,
            error_message: None,
            statistics: ExecutionStatistics::default(),
            created_at: chrono::Utc::now(),
        };

        // Load benchmark and profile
        let benchmark = self.get_benchmark(&config.benchmark_id).await?;
        let profile = benchmark
            .profiles
            .iter()
            .find(|p| p.id == config.profile_id)
            .ok_or_else(|| anyhow::anyhow!("Profile not found: {}", config.profile_id))?
            .clone();

        // Get selected rules
        let selected_rules = xccdf::resolve_profile_selections(&benchmark, &profile);

        execution.status = ExecutionStatus::Running;
        execution.started_at = Some(chrono::Utc::now());
        execution.statistics.rules_total = selected_rules.len();

        // Send progress update
        if let Some(ref tx) = progress_tx {
            let _ = tx.send(ScapProgressMessage::ScanStarted {
                execution_id: execution_id.clone(),
                total_rules: selected_rules.len(),
            });
        }

        // Build remote execution context if needed
        let remote_ctx = if let Some(creds) = &config.credentials {
            Some(oval::remote::RemoteExecutionContext::new(
                &config.target,
                creds,
            )?)
        } else {
            None
        };

        // Create OVAL engine
        let cache = self.content_cache.read().await;
        let oval_defs = cache.get_oval_definitions(&benchmark.id, &self.pool).await?;
        let mut oval_engine = oval::OvalEngine::new(oval_defs);

        if let Some(ctx) = remote_ctx {
            oval_engine.set_remote_context(ctx);
        }

        // Evaluate each selected rule
        let mut rule_results = Vec::new();
        for (idx, rule) in selected_rules.iter().enumerate() {
            // Send progress
            if let Some(ref tx) = progress_tx {
                let _ = tx.send(ScapProgressMessage::RuleStarted {
                    rule_id: rule.id.clone(),
                    rule_index: idx,
                    total_rules: selected_rules.len(),
                });
            }

            // Evaluate rule's OVAL checks
            let result = self.evaluate_rule(rule, &mut oval_engine).await;

            // Update statistics
            match result.result {
                xccdf::XccdfResultType::Pass => execution.statistics.rules_pass += 1,
                xccdf::XccdfResultType::Fail => execution.statistics.rules_fail += 1,
                xccdf::XccdfResultType::Error => execution.statistics.rules_error += 1,
                xccdf::XccdfResultType::Unknown => execution.statistics.rules_unknown += 1,
                xccdf::XccdfResultType::NotApplicable => execution.statistics.rules_not_applicable += 1,
                xccdf::XccdfResultType::NotChecked => execution.statistics.rules_not_checked += 1,
                xccdf::XccdfResultType::NotSelected => execution.statistics.rules_not_selected += 1,
                xccdf::XccdfResultType::Informational => execution.statistics.rules_informational += 1,
                xccdf::XccdfResultType::Fixed => execution.statistics.rules_pass += 1,
            }

            rule_results.push(result);

            // Send completion
            if let Some(ref tx) = progress_tx {
                let _ = tx.send(ScapProgressMessage::RuleCompleted {
                    rule_id: rule.id.clone(),
                    result: rule_results.last().unwrap().result,
                });
            }
        }

        // Calculate score
        execution.statistics.score = Some(xccdf::calculate_score(&rule_results, &benchmark.scoring));
        execution.statistics.score_max = Some(xccdf::calculate_max_score(&selected_rules, &benchmark.scoring));
        execution.statistics.oval_definitions_evaluated = oval_engine.definitions_evaluated();
        execution.statistics.oval_objects_collected = oval_engine.objects_collected();

        // Complete execution
        execution.status = ExecutionStatus::Completed;
        execution.completed_at = Some(chrono::Utc::now());

        // Store results in database
        self.store_execution(&execution, &rule_results).await?;

        // Send completion
        if let Some(ref tx) = progress_tx {
            let _ = tx.send(ScapProgressMessage::ScanCompleted {
                execution_id: execution_id.clone(),
                statistics: execution.statistics.clone(),
            });
        }

        Ok(execution)
    }

    /// Evaluate a single XCCDF rule
    async fn evaluate_rule(
        &self,
        rule: &xccdf::XccdfRule,
        oval_engine: &mut oval::OvalEngine,
    ) -> xccdf::RuleResult {
        let start_time = chrono::Utc::now();

        // Get OVAL definition references from rule checks
        let oval_refs: Vec<&str> = rule
            .checks
            .iter()
            .filter(|c| c.system == xccdf::CheckSystem::Oval)
            .filter_map(|c| c.check_content_ref.as_deref())
            .collect();

        if oval_refs.is_empty() {
            return xccdf::RuleResult {
                rule_id: rule.id.clone(),
                result: xccdf::XccdfResultType::NotChecked,
                severity: rule.severity,
                time: start_time,
                version: rule.version.clone(),
                weight: rule.weight,
                check_results: Vec::new(),
                idents: rule.idents.clone(),
                fix: rule.fix.first().cloned(),
                message: Some("No OVAL checks defined".to_string()),
                instance: None,
            };
        }

        // Evaluate each OVAL definition
        let mut check_results = Vec::new();
        let mut overall_result = xccdf::XccdfResultType::Pass;

        for oval_ref in oval_refs {
            match oval_engine.evaluate_definition(oval_ref).await {
                Ok(def_result) => {
                    let check_result = xccdf::CheckResult {
                        system: xccdf::CheckSystem::Oval,
                        definition_id: oval_ref.to_string(),
                        result: match def_result.result {
                            oval::OvalResultType::True => xccdf::XccdfResultType::Pass,
                            oval::OvalResultType::False => xccdf::XccdfResultType::Fail,
                            oval::OvalResultType::Error => xccdf::XccdfResultType::Error,
                            oval::OvalResultType::Unknown => xccdf::XccdfResultType::Unknown,
                            oval::OvalResultType::NotApplicable => xccdf::XccdfResultType::NotApplicable,
                            oval::OvalResultType::NotEvaluated => xccdf::XccdfResultType::NotChecked,
                        },
                        message: def_result.message.clone(),
                    };

                    // Combine results (fail takes precedence)
                    if check_result.result == xccdf::XccdfResultType::Fail {
                        overall_result = xccdf::XccdfResultType::Fail;
                    } else if check_result.result == xccdf::XccdfResultType::Error
                        && overall_result != xccdf::XccdfResultType::Fail
                    {
                        overall_result = xccdf::XccdfResultType::Error;
                    }

                    check_results.push(check_result);
                }
                Err(e) => {
                    check_results.push(xccdf::CheckResult {
                        system: xccdf::CheckSystem::Oval,
                        definition_id: oval_ref.to_string(),
                        result: xccdf::XccdfResultType::Error,
                        message: Some(e.to_string()),
                    });
                    if overall_result == xccdf::XccdfResultType::Pass {
                        overall_result = xccdf::XccdfResultType::Error;
                    }
                }
            }
        }

        xccdf::RuleResult {
            rule_id: rule.id.clone(),
            result: overall_result,
            severity: rule.severity,
            time: start_time,
            version: rule.version.clone(),
            weight: rule.weight,
            check_results,
            idents: rule.idents.clone(),
            fix: rule.fix.first().cloned(),
            message: None,
            instance: None,
        }
    }

    /// Store execution and results in database
    async fn store_execution(
        &self,
        execution: &ScapScanExecution,
        rule_results: &[xccdf::RuleResult],
    ) -> Result<()> {
        // Store execution record
        sqlx::query(
            r#"
            INSERT INTO scap_scan_executions
            (id, scan_id, benchmark_id, profile_id, target_host, target_cpes,
             status, started_at, completed_at, error_message, statistics, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&execution.id)
        .bind(&execution.scan_id)
        .bind(&execution.benchmark_id)
        .bind(&execution.profile_id)
        .bind(&execution.target_host)
        .bind(serde_json::to_string(&execution.target_cpes)?)
        .bind(execution.status.to_string())
        .bind(execution.started_at.map(|t| t.to_rfc3339()))
        .bind(execution.completed_at.map(|t| t.to_rfc3339()))
        .bind(&execution.error_message)
        .bind(serde_json::to_string(&execution.statistics)?)
        .bind(execution.created_at.to_rfc3339())
        .execute(&self.pool)
        .await?;

        // Store individual rule results
        for rule_result in rule_results {
            let db_result = crate::db::scap::ScapRuleResult {
                id: String::new(), // Will be generated by create_rule_result
                execution_id: execution.id.clone(),
                rule_id: rule_result.rule_id.clone(),
                result: rule_result.result.to_string().to_lowercase(),
                severity_override: None,
                message: rule_result.message.clone(),
                finding_details: rule_result.check_results.first().and_then(|cr| {
                    // Include check result details as JSON
                    serde_json::to_string(&cr).ok()
                }),
                collected_items: None, // Will be populated during OVAL collection
                evaluated_at: rule_result.time.to_rfc3339(),
            };

            if let Err(e) = crate::db::scap::create_rule_result(&self.pool, &db_result).await {
                log::warn!("Failed to store rule result for {}: {}", rule_result.rule_id, e);
                // Continue with other results even if one fails
            }
        }

        log::info!("Stored {} rule results for execution {}", rule_results.len(), execution.id);

        Ok(())
    }

    /// Generate ARF report from execution
    pub async fn generate_arf(&self, execution_id: &str) -> Result<String> {
        let generator = arf::ArfGenerator::new(&self.pool);
        generator.generate(execution_id).await
    }

    /// Get CPE dictionary for platform matching
    pub async fn get_cpe_dictionary(&self) -> Arc<RwLock<cpe::CpeDictionary>> {
        self.cpe_dictionary.clone()
    }
}

/// Progress messages for SCAP scan execution
#[derive(Debug, Clone)]
pub enum ScapProgressMessage {
    ScanStarted {
        execution_id: String,
        total_rules: usize,
    },
    RuleStarted {
        rule_id: String,
        rule_index: usize,
        total_rules: usize,
    },
    RuleCompleted {
        rule_id: String,
        result: xccdf::XccdfResultType,
    },
    OvalDefinitionEvaluated {
        definition_id: String,
        result: oval::OvalResultType,
    },
    ScanCompleted {
        execution_id: String,
        statistics: ExecutionStatistics,
    },
    ScanFailed {
        execution_id: String,
        error: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scap_version_display() {
        assert_eq!(ScapVersion::V1_3.to_string(), "1.3");
        assert_eq!(ScapVersion::V1_2.to_string(), "1.2");
    }

    #[test]
    fn test_severity_ordering() {
        assert!(ScapSeverity::Critical.weight() > ScapSeverity::High.weight());
        assert!(ScapSeverity::High.weight() > ScapSeverity::Medium.weight());
        assert!(ScapSeverity::Medium.weight() > ScapSeverity::Low.weight());
    }
}
