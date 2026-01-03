use anyhow::Result;
use sqlx::SqlitePool;
use uuid::Uuid;
use chrono::{Utc, DateTime, Duration};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use std::str::FromStr;

use super::types::{HuntExecution, ExecutionStatus, TimeRange};
use super::query_dsl::{QueryParser, QueryExecutor, QueryContext};
use super::hypothesis::get_hypothesis;

/// Hunt schedule configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HuntSchedule {
    pub id: String,
    pub hypothesis_id: String,
    pub cron_expression: String,
    pub enabled: bool,
    pub last_run: Option<DateTime<Utc>>,
    pub next_run: Option<DateTime<Utc>>,
    pub timeout_seconds: i64,
    pub alert_threshold: i64,
}

/// Hunt scheduler manager using simple interval-based scheduling
pub struct HuntScheduler {
    pool: SqlitePool,
    schedules: Arc<RwLock<Vec<HuntSchedule>>>,
    running: Arc<RwLock<bool>>,
}

impl HuntScheduler {
    /// Create a new hunt scheduler
    pub fn new(pool: SqlitePool) -> Self {
        Self {
            pool,
            schedules: Arc::new(RwLock::new(Vec::new())),
            running: Arc::new(RwLock::new(false)),
        }
    }

    /// Start the scheduler background task
    pub async fn start(&self) -> Result<()> {
        let mut running = self.running.write().await;
        if *running {
            return Ok(());
        }
        *running = true;
        drop(running);

        let pool = self.pool.clone();
        let schedules = self.schedules.clone();
        let running_flag = self.running.clone();

        tokio::spawn(async move {
            loop {
                // Check if we should stop
                {
                    let running = running_flag.read().await;
                    if !*running {
                        break;
                    }
                }

                // Check each schedule
                let now = Utc::now();
                let schedules_list = {
                    let schedules = schedules.read().await;
                    schedules.clone()
                };

                for schedule in &schedules_list {
                    if !schedule.enabled {
                        continue;
                    }

                    // Check if it's time to run this schedule
                    if let Some(next_run) = schedule.next_run {
                        if now >= next_run {
                            log::info!("Executing scheduled hunt: {}", schedule.id);

                            match execute_hunt(&pool, &schedule.hypothesis_id, None).await {
                                Ok(execution) => {
                                    if execution.findings_count >= schedule.alert_threshold {
                                        log::warn!(
                                            "Hunt {} found {} findings (threshold: {})",
                                            execution.id,
                                            execution.findings_count,
                                            schedule.alert_threshold
                                        );
                                    }

                                    // Update schedule with next run time
                                    if let Ok(next) = calculate_next_run(&schedule.cron_expression) {
                                        let mut schedules = schedules.write().await;
                                        if let Some(s) = schedules.iter_mut().find(|s| s.id == schedule.id) {
                                            s.last_run = Some(now);
                                            s.next_run = Some(next);
                                        }
                                    }
                                }
                                Err(e) => {
                                    log::error!("Scheduled hunt {} failed: {}", schedule.id, e);
                                }
                            }
                        }
                    }
                }

                // Sleep for 60 seconds before checking again
                tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
            }
        });

        log::info!("Hunt scheduler started");
        Ok(())
    }

    /// Stop the scheduler
    pub async fn shutdown(&self) -> Result<()> {
        let mut running = self.running.write().await;
        *running = false;
        log::info!("Hunt scheduler stopped");
        Ok(())
    }

    /// Add a scheduled hunt
    pub async fn add_schedule(&self, mut schedule: HuntSchedule) -> Result<()> {
        // Calculate initial next run time
        if schedule.next_run.is_none() {
            schedule.next_run = calculate_next_run(&schedule.cron_expression).ok();
        }

        let mut schedules = self.schedules.write().await;
        schedules.push(schedule);
        Ok(())
    }

    /// Remove a scheduled hunt
    pub async fn remove_schedule(&self, schedule_id: &str) -> Result<bool> {
        let mut schedules = self.schedules.write().await;
        if let Some(pos) = schedules.iter().position(|s| s.id == schedule_id) {
            schedules.remove(pos);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// List all schedules
    pub async fn list_schedules(&self) -> Vec<HuntSchedule> {
        let schedules = self.schedules.read().await;
        schedules.clone()
    }

    /// Enable or disable a schedule
    pub async fn set_schedule_enabled(&self, schedule_id: &str, enabled: bool) -> Result<bool> {
        let mut schedules = self.schedules.write().await;
        if let Some(schedule) = schedules.iter_mut().find(|s| s.id == schedule_id) {
            schedule.enabled = enabled;
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

/// Calculate next run time based on cron expression
fn calculate_next_run(cron_expression: &str) -> Result<DateTime<Utc>> {
    let schedule = cron::Schedule::from_str(cron_expression)
        .map_err(|e| anyhow::anyhow!("Invalid cron expression: {}", e))?;

    schedule
        .upcoming(Utc)
        .next()
        .ok_or_else(|| anyhow::anyhow!("No upcoming schedule"))
}

/// Execute a hunt hypothesis by parsing and running its query
pub async fn execute_hunt(
    pool: &SqlitePool,
    hypothesis_id: &str,
    campaign_id: Option<String>,
) -> Result<HuntExecution> {
    let id = Uuid::new_v4().to_string();
    let start_time = std::time::Instant::now();
    let now = Utc::now();

    // Get the hypothesis
    let hypothesis = get_hypothesis(pool, hypothesis_id).await?
        .ok_or_else(|| anyhow::anyhow!("Hypothesis not found: {}", hypothesis_id))?;

    // Parse the query
    let mut parser = QueryParser::new(hypothesis.query.clone());
    let ast = match parser.parse() {
        Ok(ast) => ast,
        Err(e) => {
            log::error!("Failed to parse hunt query: {}", e);
            return save_failed_execution(
                pool, &id, hypothesis_id, campaign_id, now,
                format!("Query parse error: {}", e)
            ).await;
        }
    };

    // Create query context (default to last 7 days)
    let context = QueryContext {
        start_time: now - Duration::days(7),
        end_time: now,
        source_filter: None,
        max_results: 10000,
        offset: 0,
    };

    // Execute the query
    let mut executor = QueryExecutor::new(pool.clone());
    let results = match executor.execute_with_context(&ast, &context).await {
        Ok(results) => results,
        Err(e) => {
            log::error!("Hunt execution failed: {}", e);
            return save_failed_execution(
                pool, &id, hypothesis_id, campaign_id, now,
                format!("Execution error: {}", e)
            ).await;
        }
    };

    let execution_time = start_time.elapsed();
    let findings_count = results.len() as i64;

    // Analyze results for false positives (heuristic: mark as FP if score < 0.5)
    let (true_positives, false_positives) = analyze_findings(&results);

    let results_json = serde_json::json!({
        "status": "completed",
        "execution_time_ms": execution_time.as_millis(),
        "records_examined": findings_count,
        "true_positives": true_positives,
        "false_positives": false_positives,
        "sample_results": results.iter().take(10).cloned().collect::<Vec<_>>(),
    });

    let status = ExecutionStatus::Completed;

    // Save execution record
    sqlx::query(
        "INSERT INTO hunt_executions (id, hypothesis_id, campaign_id, executed_at, results, findings_count, false_positives, status)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
    )
    .bind(&id)
    .bind(hypothesis_id)
    .bind(&campaign_id)
    .bind(now.to_rfc3339())
    .bind(results_json.to_string())
    .bind(findings_count)
    .bind(false_positives as i64)
    .bind(status.to_string())
    .execute(pool)
    .await?;

    log::info!(
        "Hunt {} completed: {} findings ({} FP) in {}ms",
        id,
        findings_count,
        false_positives,
        execution_time.as_millis()
    );

    Ok(HuntExecution {
        id,
        hypothesis_id: Some(hypothesis_id.to_string()),
        campaign_id,
        executed_at: now,
        results: results_json,
        findings_count,
        false_positives: false_positives as i64,
        status,
    })
}

/// Execute a hunt with a custom time range
pub async fn execute_hunt_with_timerange(
    pool: &SqlitePool,
    hypothesis_id: &str,
    campaign_id: Option<String>,
    time_range: TimeRange,
) -> Result<HuntExecution> {
    let id = Uuid::new_v4().to_string();
    let start_time = std::time::Instant::now();
    let now = Utc::now();

    let hypothesis = get_hypothesis(pool, hypothesis_id).await?
        .ok_or_else(|| anyhow::anyhow!("Hypothesis not found: {}", hypothesis_id))?;

    let mut parser = QueryParser::new(hypothesis.query.clone());
    let ast = match parser.parse() {
        Ok(ast) => ast,
        Err(e) => {
            return save_failed_execution(
                pool, &id, hypothesis_id, campaign_id, now,
                format!("Query parse error: {}", e)
            ).await;
        }
    };

    let context = QueryContext {
        start_time: time_range.start,
        end_time: time_range.end,
        source_filter: None,
        max_results: 10000,
        offset: 0,
    };

    let mut executor = QueryExecutor::new(pool.clone());
    let results = match executor.execute_with_context(&ast, &context).await {
        Ok(results) => results,
        Err(e) => {
            return save_failed_execution(
                pool, &id, hypothesis_id, campaign_id, now,
                format!("Execution error: {}", e)
            ).await;
        }
    };

    let execution_time = start_time.elapsed();
    let findings_count = results.len() as i64;
    let (true_positives, false_positives) = analyze_findings(&results);

    let results_json = serde_json::json!({
        "status": "completed",
        "execution_time_ms": execution_time.as_millis(),
        "time_range": {
            "start": time_range.start.to_rfc3339(),
            "end": time_range.end.to_rfc3339(),
        },
        "records_examined": findings_count,
        "true_positives": true_positives,
        "false_positives": false_positives,
        "sample_results": results.iter().take(10).cloned().collect::<Vec<_>>(),
    });

    sqlx::query(
        "INSERT INTO hunt_executions (id, hypothesis_id, campaign_id, executed_at, results, findings_count, false_positives, status)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
    )
    .bind(&id)
    .bind(hypothesis_id)
    .bind(&campaign_id)
    .bind(now.to_rfc3339())
    .bind(results_json.to_string())
    .bind(findings_count)
    .bind(false_positives as i64)
    .bind(ExecutionStatus::Completed.to_string())
    .execute(pool)
    .await?;

    Ok(HuntExecution {
        id,
        hypothesis_id: Some(hypothesis_id.to_string()),
        campaign_id,
        executed_at: now,
        results: results_json,
        findings_count,
        false_positives: false_positives as i64,
        status: ExecutionStatus::Completed,
    })
}

/// Analyze findings to identify potential false positives
fn analyze_findings(results: &[serde_json::Value]) -> (usize, usize) {
    let mut true_positives = 0;
    let mut false_positives = 0;

    for result in results {
        let score = calculate_finding_score(result);

        if score >= 0.5 {
            true_positives += 1;
        } else {
            false_positives += 1;
        }
    }

    (true_positives, false_positives)
}

/// Calculate a confidence score for a finding
fn calculate_finding_score(result: &serde_json::Value) -> f64 {
    let mut score: f64 = 0.5;

    if let Some(data) = result.get("data") {
        // High severity events boost score
        if let Some(severity) = data.get("severity") {
            if let Some(sev_str) = severity.as_str() {
                match sev_str.to_lowercase().as_str() {
                    "critical" | "high" => score += 0.3,
                    "medium" => score += 0.1,
                    _ => {}
                }
            }
        }

        // Known malicious indicators
        if let Some(is_malicious) = data.get("is_malicious") {
            if is_malicious.as_bool().unwrap_or(false) {
                score += 0.3;
            }
        }

        // Threat intel matches
        if data.get("threat_intel_match").is_some() {
            score += 0.2;
        }

        // Known benign indicators decrease score
        if let Some(is_benign) = data.get("is_benign") {
            if is_benign.as_bool().unwrap_or(false) {
                score -= 0.3;
            }
        }

        // Internal sources are often less suspicious
        if let Some(source) = data.get("source_type") {
            if let Some(src_str) = source.as_str() {
                if src_str == "internal" || src_str == "trusted" {
                    score -= 0.1;
                }
            }
        }
    }

    score.max(0.0).min(1.0)
}

async fn save_failed_execution(
    pool: &SqlitePool,
    id: &str,
    hypothesis_id: &str,
    campaign_id: Option<String>,
    executed_at: DateTime<Utc>,
    error: String,
) -> Result<HuntExecution> {
    let results = serde_json::json!({
        "status": "failed",
        "error": error,
    });

    sqlx::query(
        "INSERT INTO hunt_executions (id, hypothesis_id, campaign_id, executed_at, results, findings_count, false_positives, status)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
    )
    .bind(id)
    .bind(hypothesis_id)
    .bind(&campaign_id)
    .bind(executed_at.to_rfc3339())
    .bind(results.to_string())
    .bind(0i64)
    .bind(0i64)
    .bind(ExecutionStatus::Failed.to_string())
    .execute(pool)
    .await?;

    Ok(HuntExecution {
        id: id.to_string(),
        hypothesis_id: Some(hypothesis_id.to_string()),
        campaign_id,
        executed_at,
        results,
        findings_count: 0,
        false_positives: 0,
        status: ExecutionStatus::Failed,
    })
}

/// Schedule a hunt to run periodically
pub async fn schedule_hunt(
    hypothesis_id: &str,
    cron_expression: &str,
) -> Result<HuntSchedule> {
    // Validate cron expression
    let _ = cron::Schedule::from_str(cron_expression)
        .map_err(|e| anyhow::anyhow!("Invalid cron expression: {}", e))?;

    // Calculate next run time
    let next_run = calculate_next_run(cron_expression).ok();

    Ok(HuntSchedule {
        id: Uuid::new_v4().to_string(),
        hypothesis_id: hypothesis_id.to_string(),
        cron_expression: cron_expression.to_string(),
        enabled: true,
        last_run: None,
        next_run,
        timeout_seconds: 3600,
        alert_threshold: 1,
    })
}

/// Trigger hunt on IOC match
pub async fn trigger_hunt_on_ioc(
    pool: &SqlitePool,
    ioc_type: &str,
    ioc_value: &str,
    related_hypothesis_ids: Vec<String>,
) -> Result<Vec<HuntExecution>> {
    let mut executions = Vec::new();

    for hypothesis_id in related_hypothesis_ids {
        let execution = execute_hunt(pool, &hypothesis_id, None).await?;
        executions.push(execution);
    }

    log::info!(
        "Triggered {} hunts based on IOC: {} = {}",
        executions.len(),
        ioc_type,
        ioc_value
    );

    Ok(executions)
}

/// Alert on hunt results exceeding threshold
pub async fn alert_on_hunt_results(
    execution: &HuntExecution,
    threshold: i64,
) -> Result<Option<HuntAlert>> {
    if execution.findings_count >= threshold {
        log::warn!(
            "Hunt {} found {} findings (threshold: {})",
            execution.id,
            execution.findings_count,
            threshold
        );

        let alert = HuntAlert {
            id: Uuid::new_v4().to_string(),
            execution_id: execution.id.clone(),
            hypothesis_id: execution.hypothesis_id.clone(),
            findings_count: execution.findings_count,
            threshold,
            created_at: Utc::now(),
            acknowledged: false,
            acknowledged_by: None,
            acknowledged_at: None,
        };

        return Ok(Some(alert));
    }

    Ok(None)
}

/// Hunt alert structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HuntAlert {
    pub id: String,
    pub execution_id: String,
    pub hypothesis_id: Option<String>,
    pub findings_count: i64,
    pub threshold: i64,
    pub created_at: DateTime<Utc>,
    pub acknowledged: bool,
    pub acknowledged_by: Option<String>,
    pub acknowledged_at: Option<DateTime<Utc>>,
}

/// Hunt playbook integration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HuntPlaybook {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub steps: Vec<HuntPlaybookStep>,
    pub created_by: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HuntPlaybookStep {
    pub step_number: i32,
    pub hypothesis_id: String,
    pub wait_for_completion: bool,
    pub continue_on_failure: bool,
    pub delay_seconds: Option<i64>,
}

/// Execute a hunt playbook
pub async fn execute_hunt_playbook(
    pool: &SqlitePool,
    playbook: &HuntPlaybook,
    campaign_id: Option<String>,
) -> Result<Vec<HuntExecution>> {
    let mut executions = Vec::new();

    log::info!("Starting playbook execution: {}", playbook.name);

    for step in &playbook.steps {
        // Optional delay before step
        if let Some(delay) = step.delay_seconds {
            tokio::time::sleep(tokio::time::Duration::from_secs(delay as u64)).await;
        }

        log::info!("Executing playbook step {}: {}", step.step_number, step.hypothesis_id);

        let execution = execute_hunt(pool, &step.hypothesis_id, campaign_id.clone()).await;

        match execution {
            Ok(exec) => {
                let findings = exec.findings_count;
                executions.push(exec);

                if step.wait_for_completion {
                    log::info!(
                        "Step {} completed with {} findings",
                        step.step_number,
                        findings
                    );
                }
            }
            Err(e) => {
                if !step.continue_on_failure {
                    log::error!("Playbook step {} failed, aborting: {}", step.step_number, e);
                    return Err(e);
                }
                log::warn!("Step {} failed, continuing: {}", step.step_number, e);
            }
        }
    }

    log::info!(
        "Playbook {} completed: {} steps executed",
        playbook.name,
        executions.len()
    );

    Ok(executions)
}

/// Get hunt execution history
pub async fn get_execution_history(
    pool: &SqlitePool,
    hypothesis_id: Option<&str>,
    limit: i64,
) -> Result<Vec<HuntExecution>> {
    let rows = if let Some(hyp_id) = hypothesis_id {
        sqlx::query_as::<_, (String, Option<String>, Option<String>, String, String, i64, i64, String)>(
            "SELECT id, hypothesis_id, campaign_id, executed_at, results, findings_count, false_positives, status
             FROM hunt_executions
             WHERE hypothesis_id = ?
             ORDER BY executed_at DESC
             LIMIT ?"
        )
        .bind(hyp_id)
        .bind(limit)
        .fetch_all(pool)
        .await?
    } else {
        sqlx::query_as::<_, (String, Option<String>, Option<String>, String, String, i64, i64, String)>(
            "SELECT id, hypothesis_id, campaign_id, executed_at, results, findings_count, false_positives, status
             FROM hunt_executions
             ORDER BY executed_at DESC
             LIMIT ?"
        )
        .bind(limit)
        .fetch_all(pool)
        .await?
    };

    let mut executions = Vec::new();
    for (id, hypothesis_id, campaign_id, executed_at, results, findings_count, false_positives, status) in rows {
        executions.push(HuntExecution {
            id,
            hypothesis_id,
            campaign_id,
            executed_at: executed_at.parse()?,
            results: serde_json::from_str(&results)?,
            findings_count,
            false_positives,
            status: status.parse()?,
        });
    }

    Ok(executions)
}

/// Continuous hunting mode - runs hunts in a loop
pub async fn run_continuous_hunting(
    pool: SqlitePool,
    hypothesis_ids: Vec<String>,
    interval_seconds: u64,
    stop_signal: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    let mut stop_rx = stop_signal;

    loop {
        for hypothesis_id in &hypothesis_ids {
            match execute_hunt(&pool, hypothesis_id, None).await {
                Ok(execution) => {
                    if execution.findings_count > 0 {
                        log::info!(
                            "Continuous hunt {} found {} findings",
                            hypothesis_id,
                            execution.findings_count
                        );
                    }
                }
                Err(e) => {
                    log::error!("Continuous hunt {} failed: {}", hypothesis_id, e);
                }
            }

            // Check stop signal between hunts
            if *stop_rx.borrow() {
                log::info!("Continuous hunting stopped by signal");
                return Ok(());
            }
        }

        // Wait for interval or stop signal
        tokio::select! {
            _ = tokio::time::sleep(tokio::time::Duration::from_secs(interval_seconds)) => {}
            _ = stop_rx.changed() => {
                if *stop_rx.borrow() {
                    log::info!("Continuous hunting stopped by signal");
                    return Ok(());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_schedule_creation() {
        let schedule = HuntSchedule {
            id: "test".to_string(),
            hypothesis_id: "hyp1".to_string(),
            cron_expression: "0 0 * * *".to_string(),
            enabled: true,
            last_run: None,
            next_run: None,
            timeout_seconds: 3600,
            alert_threshold: 1,
        };

        assert_eq!(schedule.cron_expression, "0 0 * * *");
        assert!(schedule.enabled);
    }

    #[test]
    fn test_playbook_step() {
        let step = HuntPlaybookStep {
            step_number: 1,
            hypothesis_id: "hyp1".to_string(),
            wait_for_completion: true,
            continue_on_failure: false,
            delay_seconds: Some(5),
        };

        assert_eq!(step.step_number, 1);
        assert!(step.wait_for_completion);
        assert!(!step.continue_on_failure);
    }

    #[test]
    fn test_finding_score_calculation() {
        let high_severity = serde_json::json!({
            "data": {
                "severity": "critical",
                "is_malicious": true
            }
        });
        assert!(calculate_finding_score(&high_severity) > 0.8);

        let low_severity = serde_json::json!({
            "data": {
                "severity": "low",
                "is_benign": true,
                "source_type": "internal"
            }
        });
        assert!(calculate_finding_score(&low_severity) < 0.3);
    }

    #[test]
    fn test_cron_validation() {
        // Valid expressions
        assert!(cron::Schedule::from_str("0 0 * * * *").is_ok());
        assert!(cron::Schedule::from_str("0 0 */6 * * *").is_ok());

        // Invalid expressions
        assert!(cron::Schedule::from_str("invalid").is_err());
    }

    #[test]
    fn test_next_run_calculation() {
        // Valid cron should calculate next run
        assert!(calculate_next_run("0 0 * * * *").is_ok());
    }
}
