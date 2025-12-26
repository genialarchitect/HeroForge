//! DevSecOps Metrics and Dashboard System
//!
//! This module provides:
//! - MTTR (Mean Time to Remediate) tracking by severity
//! - Vulnerability density metrics (vulns per KLOC)
//! - Fix rate analysis (% of vulns fixed over time)
//! - SLA compliance monitoring
//! - Security debt estimation
//! - Pipeline gate configuration and evaluation
//! - Trend analysis with historical comparison

use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ============================================================================
// Core Metrics Types
// ============================================================================

/// DevSecOps metrics snapshot for a specific date
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DevSecOpsMetrics {
    pub id: Uuid,
    pub org_id: Option<Uuid>,
    pub project_id: Option<Uuid>,
    pub metric_date: NaiveDate,
    /// Mean time to remediate critical vulnerabilities (hours)
    pub mttr_critical_hours: Option<f64>,
    /// Mean time to remediate high vulnerabilities (hours)
    pub mttr_high_hours: Option<f64>,
    /// Mean time to remediate medium vulnerabilities (hours)
    pub mttr_medium_hours: Option<f64>,
    /// Mean time to remediate low vulnerabilities (hours)
    pub mttr_low_hours: Option<f64>,
    /// Vulnerability density per 1000 lines of code
    pub vulnerability_density: f64,
    /// Percentage of vulnerabilities fixed
    pub fix_rate: f64,
    /// Percentage of vulnerabilities fixed within SLA
    pub sla_compliance_rate: f64,
    /// Count of open critical vulnerabilities
    pub open_critical: u32,
    /// Count of open high vulnerabilities
    pub open_high: u32,
    /// Count of open medium vulnerabilities
    pub open_medium: u32,
    /// Count of open low vulnerabilities
    pub open_low: u32,
    /// Estimated hours to fix all open vulnerabilities
    pub security_debt_hours: f64,
    /// CI/CD pipeline gate pass rate (percentage)
    pub pipeline_pass_rate: f64,
    /// Scan coverage percentage (repos/projects scanned)
    pub scan_coverage: f64,
    pub created_at: DateTime<Utc>,
}

impl DevSecOpsMetrics {
    /// Calculate overall MTTR across all severities
    pub fn overall_mttr_hours(&self) -> f64 {
        let mut total = 0.0;
        let mut count = 0;

        if let Some(mttr) = self.mttr_critical_hours {
            total += mttr;
            count += 1;
        }
        if let Some(mttr) = self.mttr_high_hours {
            total += mttr;
            count += 1;
        }
        if let Some(mttr) = self.mttr_medium_hours {
            total += mttr;
            count += 1;
        }
        if let Some(mttr) = self.mttr_low_hours {
            total += mttr;
            count += 1;
        }

        if count > 0 {
            total / count as f64
        } else {
            0.0
        }
    }

    /// Calculate total open vulnerabilities
    pub fn total_open_vulns(&self) -> u32 {
        self.open_critical + self.open_high + self.open_medium + self.open_low
    }

    /// Calculate security health score (0-100)
    pub fn health_score(&self) -> f64 {
        let mut score = 100.0;

        // Deduct for open critical/high vulns
        score -= (self.open_critical as f64 * 10.0).min(40.0);
        score -= (self.open_high as f64 * 5.0).min(20.0);

        // Deduct for poor SLA compliance
        if self.sla_compliance_rate < 80.0 {
            score -= (80.0 - self.sla_compliance_rate) * 0.3;
        }

        // Deduct for poor fix rate
        if self.fix_rate < 70.0 {
            score -= (70.0 - self.fix_rate) * 0.2;
        }

        // Deduct for high vulnerability density
        if self.vulnerability_density > 5.0 {
            score -= ((self.vulnerability_density - 5.0) * 2.0).min(15.0);
        }

        score.max(0.0).min(100.0)
    }
}

/// Database row representation for DevSecOps metrics
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct DevSecOpsMetricsRow {
    pub id: String,
    pub org_id: Option<String>,
    pub project_id: Option<String>,
    pub metric_date: String,
    pub mttr_critical_hours: Option<f64>,
    pub mttr_high_hours: Option<f64>,
    pub mttr_medium_hours: Option<f64>,
    pub mttr_low_hours: Option<f64>,
    pub vulnerability_density: f64,
    pub fix_rate: f64,
    pub sla_compliance_rate: f64,
    pub open_critical: i32,
    pub open_high: i32,
    pub open_medium: i32,
    pub open_low: i32,
    pub security_debt_hours: f64,
    pub pipeline_pass_rate: f64,
    pub scan_coverage: f64,
    pub created_at: String,
}

// ============================================================================
// Dashboard Types
// ============================================================================

/// Complete DevSecOps dashboard response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DevSecOpsDashboard {
    /// Current metrics snapshot
    pub current_metrics: DevSecOpsMetrics,
    /// Trend analysis
    pub trends: MetricsTrends,
    /// Top vulnerabilities by risk
    pub top_vulnerabilities: Vec<VulnSummary>,
    /// Project health overview
    pub project_health: Vec<ProjectHealth>,
    /// Recent fixes
    pub recent_fixes: Vec<RecentFix>,
    /// SLA breaches
    pub sla_breaches: Vec<SlaBreach>,
}

/// Metrics trends over time
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsTrends {
    /// MTTR trend direction
    pub mttr_trend: TrendDirection,
    /// MTTR change percentage
    pub mttr_change_pct: f64,
    /// Vulnerability density trend
    pub vuln_density_trend: TrendDirection,
    /// Vulnerability density change percentage
    pub vuln_density_change_pct: f64,
    /// Fix rate trend
    pub fix_rate_trend: TrendDirection,
    /// Fix rate change percentage
    pub fix_rate_change_pct: f64,
    /// Security debt trend
    pub debt_trend: TrendDirection,
    /// Security debt change percentage
    pub debt_change_pct: f64,
    /// Historical data points for charting
    pub history: Vec<MetricsHistoryPoint>,
}

impl Default for MetricsTrends {
    fn default() -> Self {
        Self {
            mttr_trend: TrendDirection::Stable,
            mttr_change_pct: 0.0,
            vuln_density_trend: TrendDirection::Stable,
            vuln_density_change_pct: 0.0,
            fix_rate_trend: TrendDirection::Stable,
            fix_rate_change_pct: 0.0,
            debt_trend: TrendDirection::Stable,
            debt_change_pct: 0.0,
            history: Vec::new(),
        }
    }
}

/// Historical data point for trend charts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsHistoryPoint {
    pub date: NaiveDate,
    pub mttr_hours: f64,
    pub vulnerability_density: f64,
    pub fix_rate: f64,
    pub security_debt_hours: f64,
    pub open_vulns: u32,
}

/// Trend direction indicator
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrendDirection {
    /// Metric is improving (e.g., MTTR going down, fix rate going up)
    Improving,
    /// Metric is stable (change less than 5%)
    Stable,
    /// Metric is declining (e.g., MTTR going up, fix rate going down)
    Declining,
}

impl TrendDirection {
    /// Determine trend direction based on metric change
    /// For metrics where lower is better (MTTR, debt), negative change = improving
    pub fn from_change_lower_is_better(change_pct: f64) -> Self {
        if change_pct < -5.0 {
            Self::Improving
        } else if change_pct > 5.0 {
            Self::Declining
        } else {
            Self::Stable
        }
    }

    /// For metrics where higher is better (fix rate, coverage), positive change = improving
    pub fn from_change_higher_is_better(change_pct: f64) -> Self {
        if change_pct > 5.0 {
            Self::Improving
        } else if change_pct < -5.0 {
            Self::Declining
        } else {
            Self::Stable
        }
    }
}

/// Summary of a vulnerability for dashboard display
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnSummary {
    pub id: Uuid,
    pub title: String,
    pub severity: Severity,
    pub project_name: Option<String>,
    pub age_days: u32,
    pub sla_status: SlaStatus,
}

/// Database row for vulnerability summary
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct VulnSummaryRow {
    pub id: String,
    pub title: String,
    pub severity: String,
    pub project_name: Option<String>,
    pub age_days: i32,
    pub sla_status: String,
}

/// Project health status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectHealth {
    pub project_id: Uuid,
    pub project_name: String,
    /// Health score 0-100
    pub health_score: f64,
    pub open_vulns: u32,
    pub last_scan: Option<DateTime<Utc>>,
    pub gate_status: GateStatus,
}

/// Database row for project health
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ProjectHealthRow {
    pub project_id: String,
    pub project_name: String,
    pub health_score: f64,
    pub open_vulns: i32,
    pub last_scan: Option<String>,
    pub gate_status: String,
}

/// Recently fixed vulnerability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecentFix {
    pub vuln_id: Uuid,
    pub title: String,
    pub severity: Severity,
    pub fixed_by: Option<String>,
    pub fixed_at: DateTime<Utc>,
    pub resolution_time_hours: f64,
}

/// Database row for recent fix
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct RecentFixRow {
    pub vuln_id: String,
    pub title: String,
    pub severity: String,
    pub fixed_by: Option<String>,
    pub fixed_at: String,
    pub resolution_time_hours: f64,
}

/// SLA breach record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlaBreach {
    pub vuln_id: Uuid,
    pub title: String,
    pub severity: Severity,
    pub days_overdue: u32,
    pub project_name: Option<String>,
    pub assignee: Option<String>,
}

/// Database row for SLA breach
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SlaBreachRow {
    pub vuln_id: String,
    pub title: String,
    pub severity: String,
    pub days_overdue: i32,
    pub project_name: Option<String>,
    pub assignee: Option<String>,
}

// ============================================================================
// Pipeline Gate Types
// ============================================================================

/// Pipeline gate configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineGate {
    pub id: Uuid,
    /// None means organization-wide default
    pub project_id: Option<Uuid>,
    pub name: String,
    pub description: Option<String>,
    pub rules: Vec<GateRule>,
    /// If true, gate will block pipeline on failure
    pub is_blocking: bool,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Database row for pipeline gate
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct PipelineGateRow {
    pub id: String,
    pub project_id: Option<String>,
    pub name: String,
    pub description: Option<String>,
    pub rules_json: String,
    pub is_blocking: bool,
    pub is_active: bool,
    pub created_at: String,
    pub updated_at: String,
}

/// Individual gate rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateRule {
    pub rule_type: GateRuleType,
    pub threshold: u32,
    pub action: GateAction,
}

/// Types of gate rules
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateRuleType {
    /// Maximum allowed critical severity vulnerabilities
    MaxCritical,
    /// Maximum allowed high severity vulnerabilities
    MaxHigh,
    /// Maximum allowed medium severity vulnerabilities
    MaxMedium,
    /// Maximum total vulnerabilities
    MaxTotal,
    /// Minimum required fix rate percentage
    MinFixRate,
    /// Maximum security debt hours
    MaxSecurityDebt,
    /// Required scan types (SAST, SCA, DAST, etc.)
    RequiredScanTypes,
}

impl std::fmt::Display for GateRuleType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MaxCritical => write!(f, "max_critical"),
            Self::MaxHigh => write!(f, "max_high"),
            Self::MaxMedium => write!(f, "max_medium"),
            Self::MaxTotal => write!(f, "max_total"),
            Self::MinFixRate => write!(f, "min_fix_rate"),
            Self::MaxSecurityDebt => write!(f, "max_security_debt"),
            Self::RequiredScanTypes => write!(f, "required_scan_types"),
        }
    }
}

/// Gate action on rule failure
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateAction {
    /// Block the pipeline
    Block,
    /// Warn but allow to proceed
    Warn,
}

impl std::fmt::Display for GateAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Block => write!(f, "block"),
            Self::Warn => write!(f, "warn"),
        }
    }
}

/// Gate evaluation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateEvaluation {
    pub id: Uuid,
    pub gate_id: Uuid,
    pub scan_id: Uuid,
    pub project_id: Option<Uuid>,
    pub passed: bool,
    pub rule_results: Vec<RuleEvaluationResult>,
    pub evaluated_at: DateTime<Utc>,
}

/// Database row for gate evaluation
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct GateEvaluationRow {
    pub id: String,
    pub gate_id: String,
    pub scan_id: String,
    pub project_id: Option<String>,
    pub passed: bool,
    pub rule_results_json: String,
    pub evaluated_at: String,
}

/// Individual rule evaluation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleEvaluationResult {
    pub rule_type: GateRuleType,
    pub threshold: u32,
    pub actual_value: u32,
    pub passed: bool,
    pub action: GateAction,
    pub message: String,
}

// ============================================================================
// Supporting Types
// ============================================================================

/// Vulnerability severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Critical => write!(f, "critical"),
            Self::High => write!(f, "high"),
            Self::Medium => write!(f, "medium"),
            Self::Low => write!(f, "low"),
            Self::Info => write!(f, "info"),
        }
    }
}

impl std::str::FromStr for Severity {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "critical" => Ok(Self::Critical),
            "high" => Ok(Self::High),
            "medium" => Ok(Self::Medium),
            "low" => Ok(Self::Low),
            "info" | "informational" => Ok(Self::Info),
            _ => Err(format!("Unknown severity: {}", s)),
        }
    }
}

/// SLA status for a vulnerability
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlaStatus {
    /// Within SLA timeframe
    OnTrack,
    /// Approaching SLA deadline (within warning threshold)
    AtRisk,
    /// SLA breached
    Breached,
    /// No SLA applicable
    NoSla,
}

impl std::fmt::Display for SlaStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OnTrack => write!(f, "on_track"),
            Self::AtRisk => write!(f, "at_risk"),
            Self::Breached => write!(f, "breached"),
            Self::NoSla => write!(f, "no_sla"),
        }
    }
}

impl std::str::FromStr for SlaStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "on_track" => Ok(Self::OnTrack),
            "at_risk" => Ok(Self::AtRisk),
            "breached" => Ok(Self::Breached),
            "no_sla" => Ok(Self::NoSla),
            _ => Err(format!("Unknown SLA status: {}", s)),
        }
    }
}

/// Pipeline gate status for a project
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateStatus {
    /// Gate is passing
    Passing,
    /// Gate is failing
    Failing,
    /// No gate configured
    NoGate,
}

impl std::fmt::Display for GateStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Passing => write!(f, "passing"),
            Self::Failing => write!(f, "failing"),
            Self::NoGate => write!(f, "no_gate"),
        }
    }
}

impl std::str::FromStr for GateStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "passing" => Ok(Self::Passing),
            "failing" => Ok(Self::Failing),
            "no_gate" => Ok(Self::NoGate),
            _ => Err(format!("Unknown gate status: {}", s)),
        }
    }
}

// ============================================================================
// Request/Response Types
// ============================================================================

/// Request to create/update a pipeline gate
#[derive(Debug, Clone, Deserialize)]
pub struct CreatePipelineGateRequest {
    pub project_id: Option<Uuid>,
    pub name: String,
    pub description: Option<String>,
    pub rules: Vec<GateRule>,
    pub is_blocking: bool,
}

/// Request to update a pipeline gate
#[derive(Debug, Clone, Deserialize)]
pub struct UpdatePipelineGateRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub rules: Option<Vec<GateRule>>,
    pub is_blocking: Option<bool>,
    pub is_active: Option<bool>,
}

/// Request to evaluate a gate
#[derive(Debug, Clone, Deserialize)]
pub struct EvaluateGateRequest {
    pub scan_id: Uuid,
}

/// Query parameters for metrics endpoints
#[derive(Debug, Clone, Deserialize)]
pub struct MetricsQuery {
    pub project_id: Option<Uuid>,
    pub start_date: Option<NaiveDate>,
    pub end_date: Option<NaiveDate>,
    pub limit: Option<i32>,
}

/// Query parameters for project health
#[derive(Debug, Clone, Deserialize)]
pub struct ProjectHealthQuery {
    pub limit: Option<i32>,
    pub sort_by: Option<String>,
}

// ============================================================================
// SLA Configuration
// ============================================================================

/// Default SLA targets by severity (in hours)
pub const SLA_CRITICAL_HOURS: u32 = 24;      // 1 day
pub const SLA_HIGH_HOURS: u32 = 72;          // 3 days
pub const SLA_MEDIUM_HOURS: u32 = 168;       // 7 days
pub const SLA_LOW_HOURS: u32 = 720;          // 30 days

/// Get SLA target hours for a severity level
pub fn get_sla_hours(severity: Severity) -> u32 {
    match severity {
        Severity::Critical => SLA_CRITICAL_HOURS,
        Severity::High => SLA_HIGH_HOURS,
        Severity::Medium => SLA_MEDIUM_HOURS,
        Severity::Low => SLA_LOW_HOURS,
        Severity::Info => 0, // No SLA for informational
    }
}

/// Estimated remediation hours by severity (for security debt calculation)
pub const REMEDIATION_HOURS_CRITICAL: f64 = 8.0;
pub const REMEDIATION_HOURS_HIGH: f64 = 4.0;
pub const REMEDIATION_HOURS_MEDIUM: f64 = 2.0;
pub const REMEDIATION_HOURS_LOW: f64 = 1.0;

/// Calculate estimated security debt hours
pub fn calculate_security_debt(critical: u32, high: u32, medium: u32, low: u32) -> f64 {
    (critical as f64 * REMEDIATION_HOURS_CRITICAL)
        + (high as f64 * REMEDIATION_HOURS_HIGH)
        + (medium as f64 * REMEDIATION_HOURS_MEDIUM)
        + (low as f64 * REMEDIATION_HOURS_LOW)
}

// ============================================================================
// Metrics Calculation Utilities
// ============================================================================

/// Calculate vulnerability density (vulns per 1000 LOC)
pub fn calculate_vulnerability_density(total_vulns: u32, lines_of_code: u32) -> f64 {
    if lines_of_code == 0 {
        return 0.0;
    }
    (total_vulns as f64 / lines_of_code as f64) * 1000.0
}

/// Calculate fix rate percentage
pub fn calculate_fix_rate(fixed_vulns: u32, total_vulns: u32) -> f64 {
    if total_vulns == 0 {
        return 100.0; // No vulns = 100% fixed
    }
    (fixed_vulns as f64 / total_vulns as f64) * 100.0
}

/// Calculate SLA compliance rate
pub fn calculate_sla_compliance(within_sla: u32, total_resolved: u32) -> f64 {
    if total_resolved == 0 {
        return 100.0;
    }
    (within_sla as f64 / total_resolved as f64) * 100.0
}

/// Calculate percentage change between two values
pub fn calculate_change_pct(old_value: f64, new_value: f64) -> f64 {
    if old_value == 0.0 {
        if new_value == 0.0 {
            return 0.0;
        }
        return 100.0; // Went from 0 to something
    }
    ((new_value - old_value) / old_value) * 100.0
}

// ============================================================================
// Security Coverage Types
// ============================================================================

/// Security coverage status across various DevSecOps tools
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityCoverage {
    /// SAST (Static Application Security Testing) enabled
    pub sast_enabled: bool,
    /// SBOM (Software Bill of Materials) generated
    pub sbom_generated: bool,
    /// API Security scanning performed
    pub api_security_scanned: bool,
    /// Threat model exists for the project
    pub threat_model_exists: bool,
    /// DAST (Dynamic Application Security Testing) enabled
    pub dast_enabled: bool,
    /// Container scanning enabled
    pub container_scanning_enabled: bool,
    /// IaC (Infrastructure as Code) scanning enabled
    pub iac_scanning_enabled: bool,
    /// Secret scanning enabled
    pub secret_scanning_enabled: bool,
    /// Date of last SAST scan
    pub last_sast_scan: Option<String>,
    /// Date of last SBOM scan
    pub last_sbom_scan: Option<String>,
    /// Date of last API security scan
    pub last_api_scan: Option<String>,
    /// Date of last DAST scan
    pub last_dast_scan: Option<String>,
    /// Date of last container scan
    pub last_container_scan: Option<String>,
    /// Date of last IaC scan
    pub last_iac_scan: Option<String>,
    /// Date of last secret scan
    pub last_secret_scan: Option<String>,
}

impl Default for SecurityCoverage {
    fn default() -> Self {
        Self {
            sast_enabled: false,
            sbom_generated: false,
            api_security_scanned: false,
            threat_model_exists: false,
            dast_enabled: false,
            container_scanning_enabled: false,
            iac_scanning_enabled: false,
            secret_scanning_enabled: false,
            last_sast_scan: None,
            last_sbom_scan: None,
            last_api_scan: None,
            last_dast_scan: None,
            last_container_scan: None,
            last_iac_scan: None,
            last_secret_scan: None,
        }
    }
}

impl SecurityCoverage {
    /// Calculate overall coverage percentage (0-100)
    pub fn coverage_percentage(&self) -> f64 {
        let checks = [
            self.sast_enabled,
            self.sbom_generated,
            self.api_security_scanned,
            self.threat_model_exists,
            self.dast_enabled,
            self.container_scanning_enabled,
            self.iac_scanning_enabled,
            self.secret_scanning_enabled,
        ];
        let enabled_count = checks.iter().filter(|&&x| x).count();
        (enabled_count as f64 / checks.len() as f64) * 100.0
    }
}

/// Database row representation for security coverage
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SecurityCoverageRow {
    pub id: String,
    pub user_id: String,
    pub project_name: Option<String>,
    pub sast_enabled: bool,
    pub sbom_generated: bool,
    pub api_security_scanned: bool,
    pub threat_model_exists: bool,
    pub dast_enabled: bool,
    pub container_scanning_enabled: bool,
    pub iac_scanning_enabled: bool,
    pub secret_scanning_enabled: bool,
    pub last_sast_scan: Option<String>,
    pub last_sbom_scan: Option<String>,
    pub last_api_scan: Option<String>,
    pub last_dast_scan: Option<String>,
    pub last_container_scan: Option<String>,
    pub last_iac_scan: Option<String>,
    pub last_secret_scan: Option<String>,
    pub updated_at: String,
}

// ============================================================================
// Finding Resolution Types (for MTTR calculation)
// ============================================================================

/// Finding resolution record for MTTR tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingResolution {
    pub id: Uuid,
    pub finding_id: String,
    pub finding_type: String,
    pub severity: Severity,
    pub user_id: Option<Uuid>,
    pub org_id: Option<Uuid>,
    pub project_name: Option<String>,
    pub created_at: DateTime<Utc>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub resolution_hours: Option<f64>,
    pub source: Option<String>,
}

/// Database row representation for finding resolution
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct FindingResolutionRow {
    pub id: String,
    pub finding_id: String,
    pub finding_type: String,
    pub severity: String,
    pub user_id: Option<String>,
    pub org_id: Option<String>,
    pub project_name: Option<String>,
    pub created_at: String,
    pub resolved_at: Option<String>,
    pub resolution_hours: Option<f64>,
    pub source: Option<String>,
}

/// Request to create a finding resolution record
#[derive(Debug, Clone, Deserialize)]
pub struct CreateFindingResolutionRequest {
    pub finding_id: String,
    pub finding_type: String,
    pub severity: String,
    pub project_name: Option<String>,
    pub source: Option<String>,
}

/// Request to mark a finding as resolved
#[derive(Debug, Clone, Deserialize)]
pub struct ResolveFindingRequest {
    pub finding_id: String,
}

// ============================================================================
// Security Debt Types
// ============================================================================

/// Security debt item representing an open finding with age
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityDebtItem {
    pub finding_id: String,
    pub finding_type: String,
    pub severity: Severity,
    pub title: Option<String>,
    pub age_days: u32,
    pub estimated_hours: f64,
    pub source: String,
    pub project_name: Option<String>,
    pub sla_status: SlaStatus,
}

/// Database row for security debt query
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SecurityDebtRow {
    pub finding_id: String,
    pub finding_type: String,
    pub severity: String,
    pub title: Option<String>,
    pub age_days: i32,
    pub source: String,
    pub project_name: Option<String>,
    pub sla_status: String,
}

// ============================================================================
// Trend Types
// ============================================================================

/// Daily trend point for findings over time
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrendPoint {
    pub date: String,
    pub critical: u32,
    pub high: u32,
    pub medium: u32,
    pub low: u32,
    pub total: u32,
}

/// Database row for trend data
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct TrendPointRow {
    pub date: String,
    pub critical: i32,
    pub high: i32,
    pub medium: i32,
    pub low: i32,
}

/// Findings trend response with historical data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingsTrend {
    pub trend_points: Vec<TrendPoint>,
    pub period_days: u32,
    pub change_critical: i32,
    pub change_high: i32,
    pub change_medium: i32,
    pub change_low: i32,
    pub overall_trend: TrendDirection,
}

impl FindingsTrend {
    /// Create a new findings trend from trend points
    pub fn from_points(points: Vec<TrendPoint>, period_days: u32) -> Self {
        let (change_critical, change_high, change_medium, change_low) = if points.len() >= 2 {
            let first = &points[0];
            let last = points.last().unwrap();
            (
                last.critical as i32 - first.critical as i32,
                last.high as i32 - first.high as i32,
                last.medium as i32 - first.medium as i32,
                last.low as i32 - first.low as i32,
            )
        } else {
            (0, 0, 0, 0)
        };

        let total_change = change_critical + change_high + change_medium + change_low;
        let overall_trend = if total_change < -5 {
            TrendDirection::Improving
        } else if total_change > 5 {
            TrendDirection::Declining
        } else {
            TrendDirection::Stable
        };

        Self {
            trend_points: points,
            period_days,
            change_critical,
            change_high,
            change_medium,
            change_low,
            overall_trend,
        }
    }
}

// ============================================================================
// MTTR (Mean Time to Remediate) Types
// ============================================================================

/// MTTR breakdown by severity with trend data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MttrBreakdown {
    pub mttr_critical: Option<f64>,
    pub mttr_high: Option<f64>,
    pub mttr_medium: Option<f64>,
    pub mttr_low: Option<f64>,
    pub overall_mttr: Option<f64>,
    pub period_days: u32,
    pub sample_size_critical: u32,
    pub sample_size_high: u32,
    pub sample_size_medium: u32,
    pub sample_size_low: u32,
    pub trend: TrendDirection,
    pub previous_mttr: Option<f64>,
}

impl MttrBreakdown {
    /// Calculate overall MTTR as weighted average
    pub fn calculate_overall(&self) -> Option<f64> {
        let mut total_weighted = 0.0;
        let mut total_count = 0u32;

        if let Some(mttr) = self.mttr_critical {
            total_weighted += mttr * self.sample_size_critical as f64;
            total_count += self.sample_size_critical;
        }
        if let Some(mttr) = self.mttr_high {
            total_weighted += mttr * self.sample_size_high as f64;
            total_count += self.sample_size_high;
        }
        if let Some(mttr) = self.mttr_medium {
            total_weighted += mttr * self.sample_size_medium as f64;
            total_count += self.sample_size_medium;
        }
        if let Some(mttr) = self.mttr_low {
            total_weighted += mttr * self.sample_size_low as f64;
            total_count += self.sample_size_low;
        }

        if total_count > 0 {
            Some(total_weighted / total_count as f64)
        } else {
            None
        }
    }
}

// ============================================================================
// Security Debt Summary
// ============================================================================

/// Summary of security debt across all open findings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityDebtSummary {
    pub total_debt_hours: f64,
    pub total_debt_days: f64,
    pub by_severity: SeverityDebtBreakdown,
    pub by_source: Vec<SourceDebtBreakdown>,
    pub top_items: Vec<SecurityDebtItem>,
    pub trend: TrendDirection,
}

/// Debt breakdown by severity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeverityDebtBreakdown {
    pub critical: DebtCategory,
    pub high: DebtCategory,
    pub medium: DebtCategory,
    pub low: DebtCategory,
}

/// Debt category with count and hours
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebtCategory {
    pub count: u32,
    pub hours: f64,
    pub percentage: f64,
}

/// Debt breakdown by source (SAST, API Security, etc.)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceDebtBreakdown {
    pub source: String,
    pub count: u32,
    pub hours: f64,
    pub percentage: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_vulnerability_density() {
        assert_eq!(calculate_vulnerability_density(10, 10000), 1.0);
        assert_eq!(calculate_vulnerability_density(50, 10000), 5.0);
        assert_eq!(calculate_vulnerability_density(0, 10000), 0.0);
        assert_eq!(calculate_vulnerability_density(10, 0), 0.0);
    }

    #[test]
    fn test_calculate_fix_rate() {
        assert_eq!(calculate_fix_rate(80, 100), 80.0);
        assert_eq!(calculate_fix_rate(100, 100), 100.0);
        assert_eq!(calculate_fix_rate(0, 100), 0.0);
        assert_eq!(calculate_fix_rate(0, 0), 100.0);
    }

    #[test]
    fn test_calculate_security_debt() {
        let debt = calculate_security_debt(1, 2, 3, 4);
        // 1*8 + 2*4 + 3*2 + 4*1 = 8 + 8 + 6 + 4 = 26
        assert_eq!(debt, 26.0);
    }

    #[test]
    fn test_trend_direction() {
        // For metrics where lower is better (MTTR)
        assert_eq!(TrendDirection::from_change_lower_is_better(-10.0), TrendDirection::Improving);
        assert_eq!(TrendDirection::from_change_lower_is_better(10.0), TrendDirection::Declining);
        assert_eq!(TrendDirection::from_change_lower_is_better(2.0), TrendDirection::Stable);

        // For metrics where higher is better (fix rate)
        assert_eq!(TrendDirection::from_change_higher_is_better(10.0), TrendDirection::Improving);
        assert_eq!(TrendDirection::from_change_higher_is_better(-10.0), TrendDirection::Declining);
        assert_eq!(TrendDirection::from_change_higher_is_better(-2.0), TrendDirection::Stable);
    }

    #[test]
    fn test_severity_parsing() {
        assert_eq!("critical".parse::<Severity>().unwrap(), Severity::Critical);
        assert_eq!("HIGH".parse::<Severity>().unwrap(), Severity::High);
        assert_eq!("Medium".parse::<Severity>().unwrap(), Severity::Medium);
    }

    #[test]
    fn test_sla_hours() {
        assert_eq!(get_sla_hours(Severity::Critical), 24);
        assert_eq!(get_sla_hours(Severity::High), 72);
        assert_eq!(get_sla_hours(Severity::Medium), 168);
        assert_eq!(get_sla_hours(Severity::Low), 720);
        assert_eq!(get_sla_hours(Severity::Info), 0);
    }
}
