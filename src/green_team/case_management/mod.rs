//! Case management for security incidents and investigations
//!
//! Provides comprehensive case management including:
//! - Case lifecycle management
//! - Task assignment and tracking
//! - Evidence collection and chain of custody
//! - Timeline reconstruction

use crate::green_team::types::*;
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use uuid::Uuid;

/// Case management engine
pub struct CaseManager {
    cases: HashMap<Uuid, SoarCase>,
    tasks: HashMap<Uuid, Vec<CaseTask>>,
    evidence: HashMap<Uuid, Vec<CaseEvidence>>,
    comments: HashMap<Uuid, Vec<CaseComment>>,
    timeline: HashMap<Uuid, Vec<CaseTimelineEvent>>,
    case_counter: u32,
}

impl CaseManager {
    /// Create a new case manager
    pub fn new() -> Self {
        Self {
            cases: HashMap::new(),
            tasks: HashMap::new(),
            evidence: HashMap::new(),
            comments: HashMap::new(),
            timeline: HashMap::new(),
            case_counter: 0,
        }
    }

    /// Create a new case
    pub fn create_case(&mut self, request: CreateCaseRequest) -> SoarCase {
        self.case_counter += 1;
        let case_number = format!("CASE-{:05}", self.case_counter);
        let now = Utc::now();
        let id = Uuid::new_v4();

        let case = SoarCase {
            id,
            case_number: case_number.clone(),
            title: request.title,
            description: request.description,
            severity: request.severity,
            status: CaseStatus::Open,
            priority: request.priority,
            case_type: request.case_type,
            assignee_id: request.assignee_id,
            source: request.source,
            source_ref: request.source_ref,
            tlp: request.tlp.unwrap_or(Tlp::Amber),
            tags: request.tags.unwrap_or_default(),
            resolution: None,
            resolution_time_hours: None,
            created_by: request.created_by,
            created_at: now,
            updated_at: now,
            resolved_at: None,
            closed_at: None,
        };

        self.cases.insert(id, case.clone());
        self.tasks.insert(id, Vec::new());
        self.evidence.insert(id, Vec::new());
        self.comments.insert(id, Vec::new());
        self.timeline.insert(id, Vec::new());

        // Add creation event to timeline
        self.add_timeline_event(id, TimelineEventType::Created, serde_json::json!({
            "case_number": case_number,
            "severity": case.severity.to_string(),
            "case_type": case.case_type.to_string()
        }), Some(request.created_by));

        case
    }

    /// Get a case by ID
    pub fn get_case(&self, id: &Uuid) -> Option<&SoarCase> {
        self.cases.get(id)
    }

    /// Get a case by case number
    pub fn get_case_by_number(&self, case_number: &str) -> Option<&SoarCase> {
        self.cases.values().find(|c| c.case_number == case_number)
    }

    /// List all cases
    pub fn list_cases(&self, filter: Option<CaseFilter>) -> Vec<&SoarCase> {
        let mut cases: Vec<_> = self.cases.values().collect();

        if let Some(f) = filter {
            cases = cases
                .into_iter()
                .filter(|c| {
                    if let Some(ref status) = f.status {
                        if &c.status != status {
                            return false;
                        }
                    }
                    if let Some(ref severity) = f.severity {
                        if &c.severity != severity {
                            return false;
                        }
                    }
                    if let Some(ref assignee_id) = f.assignee_id {
                        if c.assignee_id.as_ref() != Some(assignee_id) {
                            return false;
                        }
                    }
                    if let Some(ref case_type) = f.case_type {
                        if &c.case_type != case_type {
                            return false;
                        }
                    }
                    true
                })
                .collect();
        }

        cases.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        cases
    }

    /// Update case status
    pub fn update_status(&mut self, case_id: &Uuid, status: CaseStatus, user_id: Uuid) -> Result<(), String> {
        let case = self.cases.get_mut(case_id).ok_or("Case not found")?;
        let old_status = case.status.clone();
        case.status = status.clone();
        case.updated_at = Utc::now();

        if status == CaseStatus::Resolved {
            case.resolved_at = Some(Utc::now());
            let duration = case.resolved_at.unwrap() - case.created_at;
            case.resolution_time_hours = Some(duration.num_minutes() as f64 / 60.0);
        } else if status == CaseStatus::Closed {
            case.closed_at = Some(Utc::now());
        }

        self.add_timeline_event(*case_id, TimelineEventType::StatusChange, serde_json::json!({
            "old_status": old_status.to_string(),
            "new_status": status.to_string()
        }), Some(user_id));

        Ok(())
    }

    /// Assign case to user
    pub fn assign_case(&mut self, case_id: &Uuid, assignee_id: Uuid, assigned_by: Uuid) -> Result<(), String> {
        let case = self.cases.get_mut(case_id).ok_or("Case not found")?;
        let old_assignee = case.assignee_id;
        case.assignee_id = Some(assignee_id);
        case.updated_at = Utc::now();

        self.add_timeline_event(*case_id, TimelineEventType::Assignment, serde_json::json!({
            "old_assignee": old_assignee,
            "new_assignee": assignee_id.to_string()
        }), Some(assigned_by));

        Ok(())
    }

    /// Resolve a case
    pub fn resolve_case(&mut self, case_id: &Uuid, resolution: String, user_id: Uuid) -> Result<(), String> {
        let case = self.cases.get_mut(case_id).ok_or("Case not found")?;
        case.resolution = Some(resolution.clone());
        case.status = CaseStatus::Resolved;
        case.resolved_at = Some(Utc::now());
        case.updated_at = Utc::now();

        let duration = case.resolved_at.unwrap() - case.created_at;
        case.resolution_time_hours = Some(duration.num_minutes() as f64 / 60.0);

        self.add_timeline_event(*case_id, TimelineEventType::Resolution, serde_json::json!({
            "resolution": resolution
        }), Some(user_id));

        Ok(())
    }

    // Task Management

    /// Add a task to a case
    pub fn add_task(&mut self, case_id: &Uuid, request: CreateTaskRequest) -> Result<CaseTask, String> {
        if !self.cases.contains_key(case_id) {
            return Err("Case not found".to_string());
        }

        let task = CaseTask {
            id: Uuid::new_v4(),
            case_id: *case_id,
            title: request.title,
            description: request.description,
            status: TaskStatus::Pending,
            priority: request.priority,
            assignee_id: request.assignee_id,
            due_at: request.due_at,
            completed_at: None,
            created_at: Utc::now(),
        };

        self.tasks
            .get_mut(case_id)
            .map(|tasks| tasks.push(task.clone()));

        self.add_timeline_event(*case_id, TimelineEventType::Task, serde_json::json!({
            "task_id": task.id.to_string(),
            "action": "created",
            "title": task.title.clone()
        }), request.assignee_id);

        Ok(task)
    }

    /// Get tasks for a case
    pub fn get_tasks(&self, case_id: &Uuid) -> Vec<&CaseTask> {
        self.tasks
            .get(case_id)
            .map(|tasks| tasks.iter().collect())
            .unwrap_or_default()
    }

    /// Update task status
    pub fn update_task_status(&mut self, case_id: &Uuid, task_id: &Uuid, status: TaskStatus) -> Result<(), String> {
        let tasks = self.tasks.get_mut(case_id).ok_or("Case not found")?;
        let task = tasks.iter_mut().find(|t| &t.id == task_id).ok_or("Task not found")?;

        task.status = status.clone();
        if status == TaskStatus::Completed {
            task.completed_at = Some(Utc::now());
        }

        Ok(())
    }

    // Evidence Management

    /// Add evidence to a case
    pub fn add_evidence(&mut self, case_id: &Uuid, request: AddEvidenceRequest) -> Result<CaseEvidence, String> {
        if !self.cases.contains_key(case_id) {
            return Err("Case not found".to_string());
        }

        let evidence = CaseEvidence {
            id: Uuid::new_v4(),
            case_id: *case_id,
            evidence_type: request.evidence_type,
            name: request.name.clone(),
            description: request.description,
            file_path: request.file_path,
            hash_sha256: request.hash_sha256,
            metadata: request.metadata,
            collected_by: request.collected_by,
            collected_at: Utc::now(),
        };

        self.evidence
            .get_mut(case_id)
            .map(|ev| ev.push(evidence.clone()));

        self.add_timeline_event(*case_id, TimelineEventType::Evidence, serde_json::json!({
            "evidence_id": evidence.id.to_string(),
            "name": request.name,
            "evidence_type": evidence.evidence_type.to_string()
        }), Some(request.collected_by));

        Ok(evidence)
    }

    /// Get evidence for a case
    pub fn get_evidence(&self, case_id: &Uuid) -> Vec<&CaseEvidence> {
        self.evidence
            .get(case_id)
            .map(|ev| ev.iter().collect())
            .unwrap_or_default()
    }

    // Comments

    /// Add a comment to a case
    pub fn add_comment(&mut self, case_id: &Uuid, user_id: Uuid, content: String, is_internal: bool) -> Result<CaseComment, String> {
        if !self.cases.contains_key(case_id) {
            return Err("Case not found".to_string());
        }

        let comment = CaseComment {
            id: Uuid::new_v4(),
            case_id: *case_id,
            user_id,
            content: content.clone(),
            is_internal,
            created_at: Utc::now(),
        };

        self.comments
            .get_mut(case_id)
            .map(|c| c.push(comment.clone()));

        self.add_timeline_event(*case_id, TimelineEventType::Comment, serde_json::json!({
            "comment_id": comment.id.to_string(),
            "is_internal": is_internal
        }), Some(user_id));

        Ok(comment)
    }

    /// Get comments for a case
    pub fn get_comments(&self, case_id: &Uuid) -> Vec<&CaseComment> {
        self.comments
            .get(case_id)
            .map(|c| c.iter().collect())
            .unwrap_or_default()
    }

    // Timeline

    /// Add an event to the case timeline
    fn add_timeline_event(
        &mut self,
        case_id: Uuid,
        event_type: TimelineEventType,
        event_data: serde_json::Value,
        user_id: Option<Uuid>,
    ) {
        let event = CaseTimelineEvent {
            id: Uuid::new_v4(),
            case_id,
            event_type,
            event_data,
            user_id,
            created_at: Utc::now(),
        };

        self.timeline
            .get_mut(&case_id)
            .map(|t| t.push(event));
    }

    /// Get timeline for a case
    pub fn get_timeline(&self, case_id: &Uuid) -> Vec<&CaseTimelineEvent> {
        self.timeline
            .get(case_id)
            .map(|t| t.iter().collect())
            .unwrap_or_default()
    }

    // Statistics

    /// Get case statistics
    pub fn get_statistics(&self) -> CaseStatistics {
        let cases: Vec<_> = self.cases.values().collect();

        let total = cases.len();
        let open = cases.iter().filter(|c| c.status == CaseStatus::Open).count();
        let in_progress = cases.iter().filter(|c| c.status == CaseStatus::InProgress).count();
        let resolved = cases.iter().filter(|c| c.status == CaseStatus::Resolved).count();
        let closed = cases.iter().filter(|c| c.status == CaseStatus::Closed).count();

        let resolved_cases: Vec<_> = cases.iter().filter(|c| c.resolved_at.is_some()).collect();
        let avg_resolution_time = if !resolved_cases.is_empty() {
            resolved_cases
                .iter()
                .filter_map(|c| c.resolution_time_hours)
                .sum::<f64>() / resolved_cases.len() as f64
        } else {
            0.0
        };

        let by_severity = [
            (Severity::Critical, cases.iter().filter(|c| c.severity == Severity::Critical && c.status != CaseStatus::Closed).count()),
            (Severity::High, cases.iter().filter(|c| c.severity == Severity::High && c.status != CaseStatus::Closed).count()),
            (Severity::Medium, cases.iter().filter(|c| c.severity == Severity::Medium && c.status != CaseStatus::Closed).count()),
            (Severity::Low, cases.iter().filter(|c| c.severity == Severity::Low && c.status != CaseStatus::Closed).count()),
        ].into_iter().collect();

        CaseStatistics {
            total,
            open,
            in_progress,
            resolved,
            closed,
            avg_resolution_time_hours: avg_resolution_time,
            by_severity,
        }
    }
}

impl Default for CaseManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Request to create a new case
#[derive(Debug, Clone)]
pub struct CreateCaseRequest {
    pub title: String,
    pub description: Option<String>,
    pub severity: Severity,
    pub priority: Priority,
    pub case_type: CaseType,
    pub assignee_id: Option<Uuid>,
    pub source: Option<String>,
    pub source_ref: Option<String>,
    pub tlp: Option<Tlp>,
    pub tags: Option<Vec<String>>,
    pub created_by: Uuid,
}

/// Request to create a task
#[derive(Debug, Clone)]
pub struct CreateTaskRequest {
    pub title: String,
    pub description: Option<String>,
    pub priority: Priority,
    pub assignee_id: Option<Uuid>,
    pub due_at: Option<DateTime<Utc>>,
}

/// Request to add evidence
#[derive(Debug, Clone)]
pub struct AddEvidenceRequest {
    pub evidence_type: EvidenceType,
    pub name: String,
    pub description: Option<String>,
    pub file_path: Option<String>,
    pub hash_sha256: Option<String>,
    pub metadata: Option<serde_json::Value>,
    pub collected_by: Uuid,
}

/// Filter for listing cases
#[derive(Debug, Clone, Default)]
pub struct CaseFilter {
    pub status: Option<CaseStatus>,
    pub severity: Option<Severity>,
    pub assignee_id: Option<Uuid>,
    pub case_type: Option<CaseType>,
}

/// Case statistics
#[derive(Debug, Clone)]
pub struct CaseStatistics {
    pub total: usize,
    pub open: usize,
    pub in_progress: usize,
    pub resolved: usize,
    pub closed: usize,
    pub avg_resolution_time_hours: f64,
    pub by_severity: HashMap<Severity, usize>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_case() {
        let mut manager = CaseManager::new();
        let user_id = Uuid::new_v4();

        let case = manager.create_case(CreateCaseRequest {
            title: "Test Case".to_string(),
            description: Some("Test description".to_string()),
            severity: Severity::High,
            priority: Priority::High,
            case_type: CaseType::Incident,
            assignee_id: None,
            source: Some("manual".to_string()),
            source_ref: None,
            tlp: None,
            tags: None,
            created_by: user_id,
        });

        assert_eq!(case.title, "Test Case");
        assert_eq!(case.status, CaseStatus::Open);
        assert!(case.case_number.starts_with("CASE-"));
    }

    #[test]
    fn test_case_lifecycle() {
        let mut manager = CaseManager::new();
        let user_id = Uuid::new_v4();

        let case = manager.create_case(CreateCaseRequest {
            title: "Test Case".to_string(),
            description: None,
            severity: Severity::Medium,
            priority: Priority::Medium,
            case_type: CaseType::Investigation,
            assignee_id: None,
            source: None,
            source_ref: None,
            tlp: None,
            tags: None,
            created_by: user_id,
        });

        let case_id = case.id;

        // Update status
        manager.update_status(&case_id, CaseStatus::InProgress, user_id).unwrap();
        assert_eq!(manager.get_case(&case_id).unwrap().status, CaseStatus::InProgress);

        // Resolve case
        manager.resolve_case(&case_id, "Issue resolved".to_string(), user_id).unwrap();
        assert_eq!(manager.get_case(&case_id).unwrap().status, CaseStatus::Resolved);
        assert!(manager.get_case(&case_id).unwrap().resolved_at.is_some());
    }
}
