//! Intelligence Operations Center (IOC)
//!
//! Provides SOC-style intelligence operations including:
//! - 24/7 intelligence monitoring
//! - Analyst workflow management
//! - Intelligence report generation
//! - Performance metrics tracking
//! - Analyst collaboration tools

use super::types::*;
use anyhow::{Result, anyhow};
use std::collections::HashMap;
use log::info;

/// Setup Intelligence Operations Center
pub async fn setup_ioc(config: &IOCConfig) -> Result<OperationsCenter> {
    info!("Setting up Intelligence Operations Center");

    let mut workflows = Vec::new();
    let mut reports = Vec::new();

    // Create default workflows if enabled
    if config.analyst_workflows {
        workflows = create_default_workflows();
    }

    // Initialize with any existing reports
    if config.reporting_enabled {
        reports = load_recent_reports().await?;
    }

    let metrics = if config.metrics_tracking {
        calculate_initial_metrics(&workflows, &reports)
    } else {
        IOCMetrics::default()
    };

    info!(
        "IOC initialized: {} workflows, {} reports, metrics tracking: {}",
        workflows.len(),
        reports.len(),
        config.metrics_tracking
    );

    Ok(OperationsCenter {
        active_analysts: 0,
        workflows,
        reports,
        metrics,
    })
}

/// Create default analyst workflows
fn create_default_workflows() -> Vec<AnalystWorkflow> {
    vec![
        AnalystWorkflow {
            workflow_id: "incident-triage".to_string(),
            name: "Incident Triage".to_string(),
            steps: vec![
                WorkflowStep {
                    step_id: "1".to_string(),
                    name: "Initial Assessment".to_string(),
                    completed: false,
                    tools: vec!["SIEM".to_string(), "Threat Intel".to_string()],
                },
                WorkflowStep {
                    step_id: "2".to_string(),
                    name: "Indicator Extraction".to_string(),
                    completed: false,
                    tools: vec!["IOC Extractor".to_string(), "YARA".to_string()],
                },
                WorkflowStep {
                    step_id: "3".to_string(),
                    name: "Enrichment".to_string(),
                    completed: false,
                    tools: vec!["VirusTotal".to_string(), "Shodan".to_string()],
                },
                WorkflowStep {
                    step_id: "4".to_string(),
                    name: "Report Generation".to_string(),
                    completed: false,
                    tools: vec!["Report Builder".to_string()],
                },
            ],
            assigned_to: None,
            status: WorkflowStatus::Pending,
        },
        AnalystWorkflow {
            workflow_id: "threat-hunting".to_string(),
            name: "Threat Hunting".to_string(),
            steps: vec![
                WorkflowStep {
                    step_id: "1".to_string(),
                    name: "Hypothesis Development".to_string(),
                    completed: false,
                    tools: vec!["MITRE ATT&CK".to_string()],
                },
                WorkflowStep {
                    step_id: "2".to_string(),
                    name: "Data Collection".to_string(),
                    completed: false,
                    tools: vec!["SIEM".to_string(), "EDR".to_string()],
                },
                WorkflowStep {
                    step_id: "3".to_string(),
                    name: "Analysis".to_string(),
                    completed: false,
                    tools: vec!["Jupyter".to_string(), "YARA".to_string()],
                },
                WorkflowStep {
                    step_id: "4".to_string(),
                    name: "Documentation".to_string(),
                    completed: false,
                    tools: vec!["Wiki".to_string(), "Report Builder".to_string()],
                },
            ],
            assigned_to: None,
            status: WorkflowStatus::Pending,
        },
        AnalystWorkflow {
            workflow_id: "malware-analysis".to_string(),
            name: "Malware Analysis".to_string(),
            steps: vec![
                WorkflowStep {
                    step_id: "1".to_string(),
                    name: "Static Analysis".to_string(),
                    completed: false,
                    tools: vec!["PE Tools".to_string(), "Strings".to_string()],
                },
                WorkflowStep {
                    step_id: "2".to_string(),
                    name: "Dynamic Analysis".to_string(),
                    completed: false,
                    tools: vec!["Sandbox".to_string(), "Process Monitor".to_string()],
                },
                WorkflowStep {
                    step_id: "3".to_string(),
                    name: "IOC Extraction".to_string(),
                    completed: false,
                    tools: vec!["IOC Extractor".to_string()],
                },
                WorkflowStep {
                    step_id: "4".to_string(),
                    name: "YARA Rule Creation".to_string(),
                    completed: false,
                    tools: vec!["YARA".to_string()],
                },
            ],
            assigned_to: None,
            status: WorkflowStatus::Pending,
        },
    ]
}

/// Load recent reports
async fn load_recent_reports() -> Result<Vec<IntelligenceReport>> {
    // In real implementation, would load from database
    Ok(vec![])
}

/// Calculate initial metrics
fn calculate_initial_metrics(
    workflows: &[AnalystWorkflow],
    reports: &[IntelligenceReport],
) -> IOCMetrics {
    let completed_workflows = workflows.iter()
        .filter(|w| matches!(w.status, WorkflowStatus::Completed))
        .count();

    IOCMetrics {
        indicators_processed_24h: 0,
        reports_generated_week: reports.len(),
        mean_time_to_analysis: 0.0,
        analyst_productivity: HashMap::new(),
    }
}

/// Assign a workflow to an analyst
pub async fn assign_workflow(
    ops_center: &mut OperationsCenter,
    workflow_id: &str,
    analyst_id: &str,
) -> Result<()> {
    let workflow = ops_center.workflows.iter_mut()
        .find(|w| w.workflow_id == workflow_id)
        .ok_or_else(|| anyhow!("Workflow not found: {}", workflow_id))?;

    workflow.assigned_to = Some(analyst_id.to_string());
    workflow.status = WorkflowStatus::InProgress;

    info!("Assigned workflow {} to analyst {}", workflow_id, analyst_id);
    Ok(())
}

/// Complete a workflow step
pub async fn complete_step(
    ops_center: &mut OperationsCenter,
    workflow_id: &str,
    step_id: &str,
) -> Result<()> {
    let workflow = ops_center.workflows.iter_mut()
        .find(|w| w.workflow_id == workflow_id)
        .ok_or_else(|| anyhow!("Workflow not found: {}", workflow_id))?;

    let step = workflow.steps.iter_mut()
        .find(|s| s.step_id == step_id)
        .ok_or_else(|| anyhow!("Step not found: {}", step_id))?;

    step.completed = true;

    // Check if all steps are complete
    if workflow.steps.iter().all(|s| s.completed) {
        workflow.status = WorkflowStatus::Completed;
    }

    Ok(())
}

/// Create a new intelligence report
pub async fn create_report(
    ops_center: &mut OperationsCenter,
    title: &str,
    report_type: ReportType,
    author: &str,
    distribution: SharingLevel,
) -> Result<IntelligenceReport> {
    let report = IntelligenceReport {
        report_id: uuid::Uuid::new_v4().to_string(),
        title: title.to_string(),
        report_type,
        created_at: chrono::Utc::now(),
        author: author.to_string(),
        distribution,
    };

    ops_center.reports.push(report.clone());
    ops_center.metrics.reports_generated_week += 1;

    info!("Created intelligence report: {}", title);
    Ok(report)
}

/// Register analyst activity
pub fn register_analyst_login(ops_center: &mut OperationsCenter, analyst_id: &str) {
    ops_center.active_analysts += 1;
    ops_center.metrics.analyst_productivity
        .entry(analyst_id.to_string())
        .or_insert(0.0);
}

/// Unregister analyst
pub fn register_analyst_logout(ops_center: &mut OperationsCenter) {
    ops_center.active_analysts = ops_center.active_analysts.saturating_sub(1);
}

/// Update analyst productivity metrics
pub fn update_analyst_productivity(
    ops_center: &mut OperationsCenter,
    analyst_id: &str,
    tasks_completed: usize,
) {
    if let Some(productivity) = ops_center.metrics.analyst_productivity.get_mut(analyst_id) {
        *productivity += tasks_completed as f64;
    }
}

/// Get workflow by ID
pub fn get_workflow<'a>(
    ops_center: &'a OperationsCenter,
    workflow_id: &str,
) -> Option<&'a AnalystWorkflow> {
    ops_center.workflows.iter().find(|w| w.workflow_id == workflow_id)
}

/// Get workflows by status
pub fn get_workflows_by_status<'a>(
    ops_center: &'a OperationsCenter,
    status: &WorkflowStatus,
) -> Vec<&'a AnalystWorkflow> {
    ops_center.workflows.iter()
        .filter(|w| std::mem::discriminant(&w.status) == std::mem::discriminant(status))
        .collect()
}

/// Get reports by type
pub fn get_reports_by_type<'a>(
    ops_center: &'a OperationsCenter,
    report_type: &ReportType,
) -> Vec<&'a IntelligenceReport> {
    ops_center.reports.iter()
        .filter(|r| std::mem::discriminant(&r.report_type) == std::mem::discriminant(report_type))
        .collect()
}

/// Calculate IOC performance metrics
pub fn calculate_performance_metrics(ops_center: &OperationsCenter) -> PerformanceMetrics {
    let total_workflows = ops_center.workflows.len();
    let completed = ops_center.workflows.iter()
        .filter(|w| matches!(w.status, WorkflowStatus::Completed))
        .count();
    let in_progress = ops_center.workflows.iter()
        .filter(|w| matches!(w.status, WorkflowStatus::InProgress))
        .count();

    let completion_rate = if total_workflows > 0 {
        (completed as f64 / total_workflows as f64) * 100.0
    } else {
        0.0
    };

    PerformanceMetrics {
        total_workflows,
        completed_workflows: completed,
        in_progress_workflows: in_progress,
        pending_workflows: total_workflows - completed - in_progress,
        completion_rate,
        active_analysts: ops_center.active_analysts,
        reports_count: ops_center.reports.len(),
    }
}

// Additional types

#[derive(Debug, Clone)]
pub struct PerformanceMetrics {
    pub total_workflows: usize,
    pub completed_workflows: usize,
    pub in_progress_workflows: usize,
    pub pending_workflows: usize,
    pub completion_rate: f64,
    pub active_analysts: usize,
    pub reports_count: usize,
}
