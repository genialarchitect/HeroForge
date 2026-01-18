// ============================================================================
// Intelligent Remediation Roadmapping
// ============================================================================
//
// This module provides AI-powered remediation planning with:
// - Dependency analysis between findings
// - Week-by-week remediation phases
// - Critical path identification
// - Resource allocation suggestions
// - Risk reduction projections
//
// The planner creates optimal remediation sequences considering:
// - Vulnerability severity and risk scores
// - Dependencies (e.g., patch X before Y)
// - Resource constraints
// - Parallel work identification
// - Business impact minimization

use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use log::{debug, info, warn};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::ai::{AIVulnerabilityScore, RiskCategory};

// ============================================================================
// Types
// ============================================================================

/// A complete remediation roadmap
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationRoadmap {
    /// Unique identifier for this roadmap
    pub id: String,
    /// Scan ID this roadmap is based on
    pub scan_id: String,
    /// When the roadmap was generated
    pub generated_at: DateTime<Utc>,
    /// Weekly phases of the roadmap
    pub phases: Vec<RemediationPhase>,
    /// Summary statistics
    pub summary: RoadmapSummary,
    /// Critical path items (must be done in sequence)
    pub critical_path: Vec<CriticalPathItem>,
    /// Risk reduction projection over time
    pub risk_projection: RiskProjection,
    /// Resource allocation suggestions
    pub resource_suggestions: Vec<ResourceSuggestion>,
}

/// A phase (typically one week) of remediation work
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationPhase {
    /// Phase number (1-based)
    pub phase_number: u32,
    /// Phase name/title
    pub name: String,
    /// Start date of the phase
    pub start_date: DateTime<Utc>,
    /// End date of the phase
    pub end_date: DateTime<Utc>,
    /// Tasks in this phase
    pub tasks: Vec<RemediationTask>,
    /// Total estimated effort in hours
    pub total_effort_hours: u32,
    /// Expected risk reduction percentage
    pub expected_risk_reduction: f64,
    /// Parallel work groups (tasks that can be done simultaneously)
    pub parallel_groups: Vec<ParallelGroup>,
}

/// A single remediation task
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationTask {
    /// Task ID
    pub id: String,
    /// Vulnerability ID being remediated
    pub vulnerability_id: String,
    /// Task title
    pub title: String,
    /// Detailed description
    pub description: String,
    /// Severity level
    pub severity: String,
    /// Host affected
    pub host: String,
    /// Port affected (if applicable)
    pub port: Option<u16>,
    /// Estimated effort in hours
    pub effort_hours: u32,
    /// Priority score (higher = more urgent)
    pub priority_score: f64,
    /// Dependencies (task IDs that must be completed first)
    pub dependencies: Vec<String>,
    /// Suggested assignee type
    pub suggested_assignee: AssigneeType,
    /// Required skills/expertise
    pub required_skills: Vec<String>,
    /// Whether this task requires system downtime
    pub requires_downtime: bool,
    /// Whether testing is required after remediation
    pub requires_testing: bool,
    /// Remediation steps
    pub remediation_steps: Vec<String>,
    /// Risk score before remediation
    pub risk_before: f64,
    /// Expected risk score after remediation
    pub risk_after: f64,
}

/// Type of assignee best suited for a task
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum AssigneeType {
    SecurityEngineer,
    SystemAdministrator,
    DeveloperBackend,
    DeveloperFrontend,
    NetworkEngineer,
    DatabaseAdmin,
    DevOps,
    CloudEngineer,
    GeneralIt,
}

impl AssigneeType {
    fn from_vulnerability(vuln_id: &str, service: Option<&str>) -> Self {
        let vuln_lower = vuln_id.to_lowercase();
        let service_lower = service.map(|s| s.to_lowercase());

        // Database-related vulnerabilities
        if vuln_lower.contains("sql")
            || vuln_lower.contains("mysql")
            || vuln_lower.contains("postgres")
            || vuln_lower.contains("oracle")
            || vuln_lower.contains("mongodb")
            || service_lower.as_ref().map(|s| s.contains("sql") || s.contains("mongo") || s.contains("redis")).unwrap_or(false)
        {
            return AssigneeType::DatabaseAdmin;
        }

        // Network-related vulnerabilities
        if vuln_lower.contains("network")
            || vuln_lower.contains("firewall")
            || vuln_lower.contains("routing")
            || vuln_lower.contains("dns")
            || vuln_lower.contains("dhcp")
        {
            return AssigneeType::NetworkEngineer;
        }

        // Cloud-related vulnerabilities
        if vuln_lower.contains("aws")
            || vuln_lower.contains("azure")
            || vuln_lower.contains("gcp")
            || vuln_lower.contains("cloud")
            || vuln_lower.contains("s3")
            || vuln_lower.contains("iam")
        {
            return AssigneeType::CloudEngineer;
        }

        // Container/DevOps vulnerabilities
        if vuln_lower.contains("docker")
            || vuln_lower.contains("kubernetes")
            || vuln_lower.contains("container")
            || vuln_lower.contains("helm")
            || vuln_lower.contains("ci/cd")
            || vuln_lower.contains("pipeline")
        {
            return AssigneeType::DevOps;
        }

        // Web application vulnerabilities
        if vuln_lower.contains("xss")
            || vuln_lower.contains("csrf")
            || vuln_lower.contains("injection")
            || vuln_lower.contains("frontend")
            || service_lower.as_ref().map(|s| s.contains("http") || s.contains("web")).unwrap_or(false)
        {
            return AssigneeType::DeveloperBackend;
        }

        // System administration tasks
        if vuln_lower.contains("ssh")
            || vuln_lower.contains("patch")
            || vuln_lower.contains("update")
            || vuln_lower.contains("configuration")
            || vuln_lower.contains("permission")
        {
            return AssigneeType::SystemAdministrator;
        }

        // Default to security engineer for other security-related issues
        AssigneeType::SecurityEngineer
    }
}

/// Group of tasks that can be done in parallel
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParallelGroup {
    /// Group name
    pub name: String,
    /// Task IDs in this group
    pub task_ids: Vec<String>,
    /// Total effort if done in parallel
    pub parallel_effort_hours: u32,
}

/// Critical path item (must be done in sequence)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CriticalPathItem {
    /// Task ID
    pub task_id: String,
    /// Position in critical path
    pub sequence: u32,
    /// Why this is on the critical path
    pub reason: String,
    /// Risk of delaying this item
    pub delay_risk: String,
}

/// Risk projection over time
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskProjection {
    /// Starting risk score
    pub initial_risk: f64,
    /// Weekly risk scores
    pub weekly_risk: Vec<WeeklyRisk>,
    /// Final projected risk score
    pub final_risk: f64,
    /// Total risk reduction percentage
    pub total_reduction_percent: f64,
}

/// Risk score for a specific week
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WeeklyRisk {
    /// Week number (0 = current)
    pub week: u32,
    /// Date of the week start
    pub date: DateTime<Utc>,
    /// Risk score at end of week
    pub risk_score: f64,
    /// Risk reduction this week
    pub reduction: f64,
    /// Key items completed this week
    pub completed_items: Vec<String>,
}

/// Resource allocation suggestion
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceSuggestion {
    /// Resource type
    pub resource_type: AssigneeType,
    /// Recommended FTE allocation
    pub recommended_fte: f64,
    /// Total hours needed
    pub total_hours: u32,
    /// Peak week demand
    pub peak_week: u32,
    /// Peak hours in that week
    pub peak_hours: u32,
    /// Skills needed
    pub skills_needed: Vec<String>,
}

/// Summary statistics for the roadmap
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoadmapSummary {
    /// Total number of tasks
    pub total_tasks: u32,
    /// Total estimated hours
    pub total_effort_hours: u32,
    /// Number of phases (weeks)
    pub total_phases: u32,
    /// Critical vulnerabilities count
    pub critical_count: u32,
    /// High vulnerabilities count
    pub high_count: u32,
    /// Medium vulnerabilities count
    pub medium_count: u32,
    /// Low vulnerabilities count
    pub low_count: u32,
    /// Projected completion date
    pub projected_completion: DateTime<Utc>,
    /// Initial aggregate risk score
    pub initial_risk_score: f64,
    /// Final projected risk score
    pub final_risk_score: f64,
    /// Risk reduction percentage
    pub risk_reduction_percent: f64,
}

/// Request to generate a remediation roadmap
#[derive(Debug, Clone, Deserialize)]
pub struct GenerateRoadmapRequest {
    /// Scan ID to generate roadmap for
    pub scan_id: String,
    /// Start date (defaults to now)
    pub start_date: Option<DateTime<Utc>>,
    /// Available hours per week (defaults to 40)
    pub hours_per_week: Option<u32>,
    /// Number of resources available (defaults to 1)
    pub available_resources: Option<u32>,
    /// Whether to include low-severity items
    pub include_low_severity: Option<bool>,
    /// Maximum weeks to plan (defaults to 12)
    pub max_weeks: Option<u32>,
}

// ============================================================================
// Remediation Planner
// ============================================================================

/// AI-powered remediation planner
pub struct RemediationPlanner {
    pool: Arc<SqlitePool>,
}

impl RemediationPlanner {
    /// Create a new remediation planner
    pub fn new(pool: Arc<SqlitePool>) -> Self {
        Self { pool }
    }

    /// Generate a remediation roadmap for a scan
    pub async fn generate_roadmap(&self, request: GenerateRoadmapRequest) -> Result<RemediationRoadmap> {
        info!("Generating remediation roadmap for scan: {}", request.scan_id);

        let start_date = request.start_date.unwrap_or_else(Utc::now);
        let hours_per_week = request.hours_per_week.unwrap_or(40);
        let available_resources = request.available_resources.unwrap_or(1);
        let include_low = request.include_low_severity.unwrap_or(true);
        let max_weeks = request.max_weeks.unwrap_or(12);

        // Get AI prioritization scores for the scan
        let scores = self.get_prioritization_scores(&request.scan_id).await?;

        // Filter scores based on severity if needed
        let filtered_scores: Vec<_> = if include_low {
            scores
        } else {
            scores.into_iter()
                .filter(|s| s.risk_category != RiskCategory::Low)
                .collect()
        };

        if filtered_scores.is_empty() {
            return Ok(self.create_empty_roadmap(&request.scan_id, start_date));
        }

        // Build dependency graph
        let dependencies = self.analyze_dependencies(&filtered_scores).await?;

        // Create remediation tasks
        let mut tasks = self.create_tasks(&filtered_scores, &dependencies).await?;

        // Calculate topological order respecting dependencies
        let ordered_tasks = self.topological_sort(&tasks, &dependencies)?;
        tasks = ordered_tasks;

        // Schedule tasks into weekly phases
        let phases = self.schedule_phases(
            &tasks,
            start_date,
            hours_per_week * available_resources,
            max_weeks,
        )?;

        // Identify critical path
        let critical_path = self.identify_critical_path(&tasks, &dependencies);

        // Calculate risk projection
        let risk_projection = self.calculate_risk_projection(&phases, &tasks);

        // Generate resource suggestions
        let resource_suggestions = self.suggest_resources(&phases);

        // Create summary
        let summary = self.create_summary(&phases, &tasks, start_date, &risk_projection);

        let roadmap = RemediationRoadmap {
            id: uuid::Uuid::new_v4().to_string(),
            scan_id: request.scan_id.clone(),
            generated_at: Utc::now(),
            phases,
            summary,
            critical_path,
            risk_projection,
            resource_suggestions,
        };

        // Store roadmap in database
        self.store_roadmap(&roadmap).await?;

        info!("Generated roadmap with {} phases for scan {}",
            roadmap.phases.len(), request.scan_id);

        Ok(roadmap)
    }

    /// Get prioritization scores for a scan
    async fn get_prioritization_scores(&self, scan_id: &str) -> Result<Vec<AIVulnerabilityScore>> {
        // Try to get existing scores
        let result = crate::db::ai::get_prioritization_result(&self.pool, scan_id).await;

        match result {
            Ok(result) => Ok(result.scores),
            Err(_) => {
                // Generate new scores if none exist
                info!("No existing AI scores for scan {}, generating...", scan_id);
                let manager = crate::ai::AIPrioritizationManager::new(self.pool.clone());
                let result = manager.prioritize_scan(scan_id).await?;
                Ok(result.scores)
            }
        }
    }

    /// Analyze dependencies between vulnerabilities
    async fn analyze_dependencies(
        &self,
        scores: &[AIVulnerabilityScore],
    ) -> Result<HashMap<String, Vec<String>>> {
        let mut dependencies: HashMap<String, Vec<String>> = HashMap::new();

        // Get vulnerability details for dependency analysis
        let vuln_ids: Vec<_> = scores.iter().map(|s| s.vulnerability_id.clone()).collect();

        for score in scores {
            let mut deps = Vec::new();

            // Rule 1: Configuration vulnerabilities should be fixed before application vulns
            // (e.g., fix SSL config before XSS)
            if self.is_application_vuln(&score.vulnerability_id) {
                for other in scores {
                    if self.is_config_vuln(&other.vulnerability_id)
                        && self.same_host(&score.vulnerability_id, &other.vulnerability_id).await
                    {
                        deps.push(other.vulnerability_id.clone());
                    }
                }
            }

            // Rule 2: Network-level fixes before application-level
            if self.is_service_vuln(&score.vulnerability_id) {
                for other in scores {
                    if self.is_network_vuln(&other.vulnerability_id)
                        && self.same_host(&score.vulnerability_id, &other.vulnerability_id).await
                    {
                        deps.push(other.vulnerability_id.clone());
                    }
                }
            }

            // Rule 3: Authentication issues before authorization issues
            if self.is_authz_vuln(&score.vulnerability_id) {
                for other in scores {
                    if self.is_authn_vuln(&other.vulnerability_id)
                        && self.same_host(&score.vulnerability_id, &other.vulnerability_id).await
                    {
                        deps.push(other.vulnerability_id.clone());
                    }
                }
            }

            dependencies.insert(score.vulnerability_id.clone(), deps);
        }

        // Remove circular dependencies
        self.remove_circular_deps(&mut dependencies);

        debug!("Analyzed dependencies for {} vulnerabilities", vuln_ids.len());
        Ok(dependencies)
    }

    /// Check if two vulnerabilities are on the same host
    async fn same_host(&self, vuln1: &str, vuln2: &str) -> bool {
        let host1: Option<String> = sqlx::query_scalar(
            "SELECT host_ip FROM vulnerability_tracking WHERE vulnerability_id = ?"
        )
        .bind(vuln1)
        .fetch_optional(&*self.pool)
        .await
        .ok()
        .flatten();

        let host2: Option<String> = sqlx::query_scalar(
            "SELECT host_ip FROM vulnerability_tracking WHERE vulnerability_id = ?"
        )
        .bind(vuln2)
        .fetch_optional(&*self.pool)
        .await
        .ok()
        .flatten();

        host1.is_some() && host1 == host2
    }

    fn is_application_vuln(&self, vuln_id: &str) -> bool {
        let lower = vuln_id.to_lowercase();
        lower.contains("xss")
            || lower.contains("sqli")
            || lower.contains("csrf")
            || lower.contains("injection")
            || lower.contains("rce")
            || lower.contains("lfi")
            || lower.contains("rfi")
    }

    fn is_config_vuln(&self, vuln_id: &str) -> bool {
        let lower = vuln_id.to_lowercase();
        lower.contains("config")
            || lower.contains("ssl")
            || lower.contains("tls")
            || lower.contains("header")
            || lower.contains("cors")
            || lower.contains("permission")
    }

    fn is_service_vuln(&self, vuln_id: &str) -> bool {
        let lower = vuln_id.to_lowercase();
        lower.contains("service")
            || lower.contains("port")
            || lower.contains("daemon")
            || lower.contains("server")
    }

    fn is_network_vuln(&self, vuln_id: &str) -> bool {
        let lower = vuln_id.to_lowercase();
        lower.contains("network")
            || lower.contains("firewall")
            || lower.contains("routing")
            || lower.contains("dns")
    }

    fn is_authn_vuln(&self, vuln_id: &str) -> bool {
        let lower = vuln_id.to_lowercase();
        lower.contains("auth")
            || lower.contains("login")
            || lower.contains("password")
            || lower.contains("credential")
            || lower.contains("session")
    }

    fn is_authz_vuln(&self, vuln_id: &str) -> bool {
        let lower = vuln_id.to_lowercase();
        lower.contains("authorization")
            || lower.contains("privilege")
            || lower.contains("escalation")
            || lower.contains("access control")
            || lower.contains("idor")
            || lower.contains("bola")
    }

    /// Remove circular dependencies
    fn remove_circular_deps(&self, deps: &mut HashMap<String, Vec<String>>) {
        // Build a set of circular dependency pairs
        let mut to_remove: Vec<(String, String)> = Vec::new();

        for (key, dep_list) in deps.iter() {
            for dep in dep_list {
                // Check if dep depends on key (would create cycle)
                if let Some(dep_deps) = deps.get(dep) {
                    if dep_deps.contains(key) {
                        to_remove.push((key.clone(), dep.clone()));
                    }
                }
            }
        }

        // Remove the circular dependencies
        for (key, dep_to_remove) in to_remove {
            if let Some(dep_list) = deps.get_mut(&key) {
                dep_list.retain(|d| d != &dep_to_remove);
            }
        }
    }

    /// Create remediation tasks from vulnerability scores
    async fn create_tasks(
        &self,
        scores: &[AIVulnerabilityScore],
        dependencies: &HashMap<String, Vec<String>>,
    ) -> Result<Vec<RemediationTask>> {
        let mut tasks = Vec::new();

        for score in scores {
            // Get vulnerability details
            let vuln_detail = crate::db::vulnerabilities::get_vulnerability_detail(&self.pool, &score.vulnerability_id)
                .await
                .ok();

            let (host, port, service, title, description, severity) = if let Some(detail) = vuln_detail {
                (detail.vulnerability.host_ip, detail.vulnerability.port, None::<String>,
                 detail.vulnerability.vulnerability_id.clone(), String::new(), detail.vulnerability.severity)
            } else {
                // Use minimal info from score
                (String::from("unknown"), None, None,
                 score.vulnerability_id.clone(), String::new(),
                 format!("{:?}", score.risk_category))
            };

            let effort_hours = score.estimated_effort.estimated_hours;
            let deps = dependencies.get(&score.vulnerability_id)
                .cloned()
                .unwrap_or_default();

            let assignee = AssigneeType::from_vulnerability(&score.vulnerability_id, service.as_deref());
            let required_skills = self.get_required_skills(&score.vulnerability_id, &assignee);
            let remediation_steps = self.get_remediation_steps(&score.vulnerability_id).await;

            let task = RemediationTask {
                id: uuid::Uuid::new_v4().to_string(),
                vulnerability_id: score.vulnerability_id.clone(),
                title: format!("Remediate: {}", title),
                description: self.generate_task_description(&score, &description),
                severity: severity.clone(),
                host,
                port: port.map(|p| p as u16),
                effort_hours,
                priority_score: score.effective_risk_score,
                dependencies: deps,
                suggested_assignee: assignee,
                required_skills,
                requires_downtime: score.estimated_effort.requires_downtime,
                requires_testing: score.estimated_effort.requires_testing,
                remediation_steps,
                risk_before: score.effective_risk_score,
                risk_after: score.effective_risk_score * 0.1, // Assume 90% reduction after fix
            };

            tasks.push(task);
        }

        Ok(tasks)
    }

    fn generate_task_description(&self, score: &AIVulnerabilityScore, base_desc: &str) -> String {
        let mut desc = if base_desc.is_empty() {
            format!("Remediate vulnerability {} with risk score {:.1}",
                score.vulnerability_id, score.effective_risk_score)
        } else {
            base_desc.to_string()
        };

        desc.push_str(&format!("\n\nRisk Category: {:?}", score.risk_category));
        desc.push_str(&format!("\nEffective Risk Score: {:.1}/100", score.effective_risk_score));
        desc.push_str(&format!("\nEstimated Effort: {} hours", score.estimated_effort.estimated_hours));

        if score.estimated_effort.requires_downtime {
            desc.push_str("\n\n**WARNING: This fix may require system downtime.**");
        }

        desc
    }

    fn get_required_skills(&self, vuln_id: &str, assignee: &AssigneeType) -> Vec<String> {
        let mut skills = Vec::new();
        let lower = vuln_id.to_lowercase();

        // Add assignee-specific skills
        match assignee {
            AssigneeType::DatabaseAdmin => {
                skills.push("Database Administration".to_string());
                skills.push("SQL Security".to_string());
            }
            AssigneeType::NetworkEngineer => {
                skills.push("Network Security".to_string());
                skills.push("Firewall Configuration".to_string());
            }
            AssigneeType::CloudEngineer => {
                skills.push("Cloud Security".to_string());
                skills.push("IAM Management".to_string());
            }
            AssigneeType::DevOps => {
                skills.push("Container Security".to_string());
                skills.push("CI/CD Security".to_string());
            }
            AssigneeType::DeveloperBackend => {
                skills.push("Secure Coding".to_string());
                skills.push("Web Security".to_string());
            }
            AssigneeType::DeveloperFrontend => {
                skills.push("Frontend Security".to_string());
                skills.push("XSS Prevention".to_string());
            }
            AssigneeType::SecurityEngineer => {
                skills.push("Security Engineering".to_string());
                skills.push("Vulnerability Assessment".to_string());
            }
            AssigneeType::SystemAdministrator => {
                skills.push("System Administration".to_string());
                skills.push("Patch Management".to_string());
            }
            AssigneeType::GeneralIt => {
                skills.push("IT Operations".to_string());
            }
        }

        // Add vulnerability-specific skills
        if lower.contains("xss") {
            skills.push("XSS Remediation".to_string());
        }
        if lower.contains("sql") {
            skills.push("SQL Injection Prevention".to_string());
        }
        if lower.contains("ssl") || lower.contains("tls") {
            skills.push("TLS Configuration".to_string());
        }

        skills
    }

    async fn get_remediation_steps(&self, vuln_id: &str) -> Vec<String> {
        // Try to get remediation from finding templates
        let template: Option<String> = sqlx::query_scalar(
            "SELECT remediation_steps FROM finding_templates WHERE id = ? OR title LIKE ?"
        )
        .bind(vuln_id)
        .bind(format!("%{}%", vuln_id))
        .fetch_optional(&*self.pool)
        .await
        .ok()
        .flatten();

        if let Some(steps_json) = template {
            if let Ok(steps) = serde_json::from_str::<Vec<String>>(&steps_json) {
                return steps;
            }
        }

        // Return generic steps based on vulnerability type
        let lower = vuln_id.to_lowercase();
        if lower.contains("xss") {
            return vec![
                "Identify all user input points".to_string(),
                "Implement output encoding/escaping".to_string(),
                "Use Content Security Policy (CSP)".to_string(),
                "Validate and sanitize all inputs".to_string(),
                "Test with XSS payloads".to_string(),
            ];
        }
        if lower.contains("sql") {
            return vec![
                "Identify affected SQL queries".to_string(),
                "Convert to parameterized queries/prepared statements".to_string(),
                "Implement input validation".to_string(),
                "Apply principle of least privilege to database accounts".to_string(),
                "Test with SQL injection payloads".to_string(),
            ];
        }

        vec![
            "Review vulnerability details".to_string(),
            "Identify affected systems/code".to_string(),
            "Apply appropriate fix/patch".to_string(),
            "Test the remediation".to_string(),
            "Verify fix with security scan".to_string(),
        ]
    }

    /// Perform topological sort respecting dependencies
    fn topological_sort(
        &self,
        tasks: &[RemediationTask],
        dependencies: &HashMap<String, Vec<String>>,
    ) -> Result<Vec<RemediationTask>> {
        let mut result = Vec::new();
        let mut visited = HashSet::new();
        let mut temp_mark = HashSet::new();

        let task_map: HashMap<_, _> = tasks.iter()
            .map(|t| (t.vulnerability_id.clone(), t.clone()))
            .collect();

        fn visit(
            vuln_id: &str,
            task_map: &HashMap<String, RemediationTask>,
            dependencies: &HashMap<String, Vec<String>>,
            visited: &mut HashSet<String>,
            temp_mark: &mut HashSet<String>,
            result: &mut Vec<RemediationTask>,
        ) -> Result<()> {
            if temp_mark.contains(vuln_id) {
                // Cycle detected - just skip this dependency
                return Ok(());
            }
            if visited.contains(vuln_id) {
                return Ok(());
            }

            temp_mark.insert(vuln_id.to_string());

            if let Some(deps) = dependencies.get(vuln_id) {
                for dep in deps {
                    visit(dep, task_map, dependencies, visited, temp_mark, result)?;
                }
            }

            temp_mark.remove(vuln_id);
            visited.insert(vuln_id.to_string());

            if let Some(task) = task_map.get(vuln_id) {
                result.push(task.clone());
            }

            Ok(())
        }

        for task in tasks {
            visit(
                &task.vulnerability_id,
                &task_map,
                dependencies,
                &mut visited,
                &mut temp_mark,
                &mut result,
            )?;
        }

        // Sort by priority within dependency constraints
        result.sort_by(|a, b| b.priority_score.partial_cmp(&a.priority_score).unwrap());

        Ok(result)
    }

    /// Schedule tasks into weekly phases
    fn schedule_phases(
        &self,
        tasks: &[RemediationTask],
        start_date: DateTime<Utc>,
        hours_per_week: u32,
        max_weeks: u32,
    ) -> Result<Vec<RemediationPhase>> {
        let mut phases = Vec::new();
        let mut remaining_tasks: Vec<_> = tasks.to_vec();
        let mut completed_task_ids = HashSet::new();

        for week in 0..max_weeks {
            if remaining_tasks.is_empty() {
                break;
            }

            let phase_start = start_date + Duration::weeks(week as i64);
            let phase_end = phase_start + Duration::weeks(1);

            let mut phase_tasks = Vec::new();
            let mut phase_hours = 0u32;

            // Find tasks that can be scheduled this week
            let mut scheduled_indices = Vec::new();
            for (i, task) in remaining_tasks.iter().enumerate() {
                // Check if all dependencies are completed
                let deps_met = task.dependencies.iter()
                    .all(|d| completed_task_ids.contains(d) ||
                         !remaining_tasks.iter().any(|t| &t.vulnerability_id == d));

                if deps_met && phase_hours + task.effort_hours <= hours_per_week {
                    phase_tasks.push(task.clone());
                    phase_hours += task.effort_hours;
                    scheduled_indices.push(i);
                }
            }

            // Remove scheduled tasks from remaining
            for i in scheduled_indices.into_iter().rev() {
                let task = remaining_tasks.remove(i);
                completed_task_ids.insert(task.vulnerability_id.clone());
            }

            if !phase_tasks.is_empty() {
                // Identify parallel groups
                let parallel_groups = self.identify_parallel_groups(&phase_tasks);

                // Calculate expected risk reduction
                let expected_risk_reduction = phase_tasks.iter()
                    .map(|t| t.risk_before - t.risk_after)
                    .sum::<f64>();

                let phase = RemediationPhase {
                    phase_number: (week + 1) as u32,
                    name: format!("Week {} - {} tasks", week + 1, phase_tasks.len()),
                    start_date: phase_start,
                    end_date: phase_end,
                    tasks: phase_tasks,
                    total_effort_hours: phase_hours,
                    expected_risk_reduction,
                    parallel_groups,
                };

                phases.push(phase);
            }
        }

        Ok(phases)
    }

    /// Identify tasks that can be done in parallel
    fn identify_parallel_groups(&self, tasks: &[RemediationTask]) -> Vec<ParallelGroup> {
        let mut groups: HashMap<String, Vec<String>> = HashMap::new();

        for task in tasks {
            // Group by host
            let key = format!("{}", task.host);
            groups.entry(key).or_default().push(task.id.clone());
        }

        // Convert to parallel groups
        let mut result = Vec::new();
        let mut group_num = 1;

        for (host, task_ids) in groups {
            if task_ids.len() > 1 {
                let max_effort = tasks.iter()
                    .filter(|t| task_ids.contains(&t.id))
                    .map(|t| t.effort_hours)
                    .max()
                    .unwrap_or(0);

                result.push(ParallelGroup {
                    name: format!("Group {} ({})", group_num, host),
                    task_ids,
                    parallel_effort_hours: max_effort,
                });
                group_num += 1;
            }
        }

        result
    }

    /// Identify critical path items
    fn identify_critical_path(
        &self,
        tasks: &[RemediationTask],
        dependencies: &HashMap<String, Vec<String>>,
    ) -> Vec<CriticalPathItem> {
        let mut critical_path = Vec::new();

        // Critical path items are high-priority tasks with dependencies
        let mut high_priority: Vec<_> = tasks.iter()
            .filter(|t| t.priority_score >= 70.0)
            .collect();

        high_priority.sort_by(|a, b| b.priority_score.partial_cmp(&a.priority_score).unwrap());

        for (i, task) in high_priority.iter().take(10).enumerate() {
            let reason = if task.dependencies.is_empty() {
                "High priority with no blockers - should be addressed first".to_string()
            } else {
                format!("Depends on {} other fixes - schedule dependencies first", task.dependencies.len())
            };

            let delay_risk = if task.priority_score >= 90.0 {
                "CRITICAL: Delays could result in exploitation".to_string()
            } else if task.priority_score >= 75.0 {
                "HIGH: Extended delay increases attack surface".to_string()
            } else {
                "MEDIUM: Should be addressed within the planned timeframe".to_string()
            };

            critical_path.push(CriticalPathItem {
                task_id: task.id.clone(),
                sequence: (i + 1) as u32,
                reason,
                delay_risk,
            });
        }

        critical_path
    }

    /// Calculate risk reduction projection over time
    fn calculate_risk_projection(
        &self,
        phases: &[RemediationPhase],
        tasks: &[RemediationTask],
    ) -> RiskProjection {
        let initial_risk: f64 = tasks.iter().map(|t| t.risk_before).sum();
        let mut current_risk = initial_risk;
        let mut weekly_risk = Vec::new();

        for phase in phases {
            let reduction: f64 = phase.tasks.iter()
                .map(|t| t.risk_before - t.risk_after)
                .sum();

            current_risk -= reduction;
            let completed: Vec<_> = phase.tasks.iter()
                .map(|t| t.vulnerability_id.clone())
                .collect();

            weekly_risk.push(WeeklyRisk {
                week: phase.phase_number,
                date: phase.start_date,
                risk_score: current_risk,
                reduction,
                completed_items: completed,
            });
        }

        let final_risk = current_risk.max(0.0);
        let total_reduction = if initial_risk > 0.0 {
            ((initial_risk - final_risk) / initial_risk) * 100.0
        } else {
            100.0
        };

        RiskProjection {
            initial_risk,
            weekly_risk,
            final_risk,
            total_reduction_percent: total_reduction,
        }
    }

    /// Generate resource allocation suggestions
    fn suggest_resources(&self, phases: &[RemediationPhase]) -> Vec<ResourceSuggestion> {
        let mut resource_hours: HashMap<AssigneeType, Vec<(u32, u32)>> = HashMap::new();

        // Collect hours by resource type per week
        for phase in phases {
            for task in &phase.tasks {
                let entry = resource_hours.entry(task.suggested_assignee.clone()).or_default();
                entry.push((phase.phase_number, task.effort_hours));
            }
        }

        // Create suggestions
        let mut suggestions = Vec::new();
        for (resource_type, week_hours) in resource_hours {
            let total_hours: u32 = week_hours.iter().map(|(_, h)| h).sum();

            // Find peak week
            let mut week_totals: HashMap<u32, u32> = HashMap::new();
            for (week, hours) in &week_hours {
                *week_totals.entry(*week).or_default() += hours;
            }

            let (peak_week, peak_hours) = week_totals.iter()
                .max_by_key(|(_, h)| *h)
                .map(|(w, h)| (*w, *h))
                .unwrap_or((0, 0));

            // Calculate recommended FTE (assuming 40 hours/week)
            let recommended_fte = (peak_hours as f64 / 40.0).ceil().max(0.5);

            // Get skills for this resource type
            let skills = match resource_type {
                AssigneeType::SecurityEngineer => vec!["Security Engineering".to_string()],
                AssigneeType::SystemAdministrator => vec!["System Administration".to_string()],
                AssigneeType::DatabaseAdmin => vec!["Database Administration".to_string()],
                AssigneeType::NetworkEngineer => vec!["Network Engineering".to_string()],
                AssigneeType::CloudEngineer => vec!["Cloud Security".to_string()],
                AssigneeType::DevOps => vec!["DevOps".to_string()],
                AssigneeType::DeveloperBackend => vec!["Backend Development".to_string()],
                AssigneeType::DeveloperFrontend => vec!["Frontend Development".to_string()],
                AssigneeType::GeneralIt => vec!["IT Operations".to_string()],
            };

            suggestions.push(ResourceSuggestion {
                resource_type,
                recommended_fte,
                total_hours,
                peak_week,
                peak_hours,
                skills_needed: skills,
            });
        }

        // Sort by total hours descending
        suggestions.sort_by(|a, b| b.total_hours.cmp(&a.total_hours));

        suggestions
    }

    /// Create roadmap summary
    fn create_summary(
        &self,
        phases: &[RemediationPhase],
        tasks: &[RemediationTask],
        start_date: DateTime<Utc>,
        risk_projection: &RiskProjection,
    ) -> RoadmapSummary {
        let total_tasks = tasks.len() as u32;
        let total_effort_hours: u32 = tasks.iter().map(|t| t.effort_hours).sum();
        let total_phases = phases.len() as u32;

        let critical_count = tasks.iter().filter(|t| t.severity.to_lowercase() == "critical").count() as u32;
        let high_count = tasks.iter().filter(|t| t.severity.to_lowercase() == "high").count() as u32;
        let medium_count = tasks.iter().filter(|t| t.severity.to_lowercase() == "medium").count() as u32;
        let low_count = tasks.iter().filter(|t| t.severity.to_lowercase() == "low").count() as u32;

        let projected_completion = if !phases.is_empty() {
            phases.last().unwrap().end_date
        } else {
            start_date
        };

        RoadmapSummary {
            total_tasks,
            total_effort_hours,
            total_phases,
            critical_count,
            high_count,
            medium_count,
            low_count,
            projected_completion,
            initial_risk_score: risk_projection.initial_risk,
            final_risk_score: risk_projection.final_risk,
            risk_reduction_percent: risk_projection.total_reduction_percent,
        }
    }

    /// Create an empty roadmap (no vulnerabilities)
    fn create_empty_roadmap(&self, scan_id: &str, start_date: DateTime<Utc>) -> RemediationRoadmap {
        RemediationRoadmap {
            id: uuid::Uuid::new_v4().to_string(),
            scan_id: scan_id.to_string(),
            generated_at: Utc::now(),
            phases: Vec::new(),
            summary: RoadmapSummary {
                total_tasks: 0,
                total_effort_hours: 0,
                total_phases: 0,
                critical_count: 0,
                high_count: 0,
                medium_count: 0,
                low_count: 0,
                projected_completion: start_date,
                initial_risk_score: 0.0,
                final_risk_score: 0.0,
                risk_reduction_percent: 100.0,
            },
            critical_path: Vec::new(),
            risk_projection: RiskProjection {
                initial_risk: 0.0,
                weekly_risk: Vec::new(),
                final_risk: 0.0,
                total_reduction_percent: 100.0,
            },
            resource_suggestions: Vec::new(),
        }
    }

    /// Store roadmap in database
    async fn store_roadmap(&self, roadmap: &RemediationRoadmap) -> Result<()> {
        let roadmap_json = serde_json::to_string(roadmap)?;

        sqlx::query(
            r#"
            INSERT INTO remediation_roadmaps (id, scan_id, generated_at, roadmap_data)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                roadmap_data = excluded.roadmap_data,
                generated_at = excluded.generated_at
            "#
        )
        .bind(&roadmap.id)
        .bind(&roadmap.scan_id)
        .bind(roadmap.generated_at.to_rfc3339())
        .bind(&roadmap_json)
        .execute(&*self.pool)
        .await?;

        Ok(())
    }

    /// Get a roadmap by ID
    pub async fn get_roadmap(&self, roadmap_id: &str) -> Result<Option<RemediationRoadmap>> {
        let row: Option<(String,)> = sqlx::query_as(
            "SELECT roadmap_data FROM remediation_roadmaps WHERE id = ?"
        )
        .bind(roadmap_id)
        .fetch_optional(&*self.pool)
        .await?;

        if let Some((data,)) = row {
            let roadmap: RemediationRoadmap = serde_json::from_str(&data)?;
            Ok(Some(roadmap))
        } else {
            Ok(None)
        }
    }

    /// Get roadmaps for a scan
    pub async fn get_roadmaps_for_scan(&self, scan_id: &str) -> Result<Vec<RemediationRoadmap>> {
        let rows: Vec<(String,)> = sqlx::query_as(
            "SELECT roadmap_data FROM remediation_roadmaps WHERE scan_id = ? ORDER BY generated_at DESC"
        )
        .bind(scan_id)
        .fetch_all(&*self.pool)
        .await?;

        let mut roadmaps = Vec::new();
        for (data,) in rows {
            if let Ok(roadmap) = serde_json::from_str::<RemediationRoadmap>(&data) {
                roadmaps.push(roadmap);
            }
        }

        Ok(roadmaps)
    }

    /// Delete a roadmap
    pub async fn delete_roadmap(&self, roadmap_id: &str) -> Result<bool> {
        let result = sqlx::query("DELETE FROM remediation_roadmaps WHERE id = ?")
            .bind(roadmap_id)
            .execute(&*self.pool)
            .await?;

        Ok(result.rows_affected() > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_assignee_type_from_vulnerability() {
        assert_eq!(
            AssigneeType::from_vulnerability("SQL_INJECTION", None),
            AssigneeType::DatabaseAdmin
        );
        assert_eq!(
            AssigneeType::from_vulnerability("NETWORK_SEGMENTATION", None),
            AssigneeType::NetworkEngineer
        );
        assert_eq!(
            AssigneeType::from_vulnerability("AWS_S3_PUBLIC", None),
            AssigneeType::CloudEngineer
        );
        assert_eq!(
            AssigneeType::from_vulnerability("DOCKER_PRIVILEGED", None),
            AssigneeType::DevOps
        );
        assert_eq!(
            AssigneeType::from_vulnerability("XSS_REFLECTED", None),
            AssigneeType::DeveloperBackend
        );
    }
}
