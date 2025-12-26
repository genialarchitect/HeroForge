//! Compliance Training module - Mandatory training tracking and reminders

use crate::orange_team::types::*;
use chrono::{Duration, NaiveDate, Utc};
use std::collections::HashMap;
use uuid::Uuid;

/// Compliance training manager
pub struct ComplianceTrainingManager {
    requirements: Vec<ComplianceTrainingRequirement>,
    user_status: HashMap<(Uuid, Uuid), ComplianceTrainingUserStatus>,
}

impl ComplianceTrainingManager {
    /// Create a new compliance training manager
    pub fn new() -> Self {
        Self {
            requirements: create_default_requirements(),
            user_status: HashMap::new(),
        }
    }

    /// Create a new compliance requirement
    pub fn create_requirement(
        &mut self,
        name: &str,
        framework: ComplianceFramework,
        required_courses: Vec<Uuid>,
        recurrence_months: u32,
    ) -> ComplianceTrainingRequirement {
        let requirement = ComplianceTrainingRequirement {
            id: Uuid::new_v4(),
            name: name.to_string(),
            framework,
            required_courses,
            recurrence_months,
            grace_period_days: 30,
            is_active: true,
            created_at: Utc::now(),
        };

        self.requirements.push(requirement.clone());
        requirement
    }

    /// Assign a requirement to a user
    pub fn assign_to_user(
        &mut self,
        user_id: Uuid,
        requirement_id: Uuid,
        due_date: NaiveDate,
    ) -> Option<ComplianceTrainingUserStatus> {
        // Check if requirement exists
        if !self.requirements.iter().any(|r| r.id == requirement_id) {
            return None;
        }

        let status = ComplianceTrainingUserStatus {
            id: Uuid::new_v4(),
            user_id,
            requirement_id,
            status: ComplianceTrainingStatus::Pending,
            due_date,
            completed_at: None,
            next_due_date: None,
            created_at: Utc::now(),
        };

        self.user_status.insert((user_id, requirement_id), status.clone());
        Some(status)
    }

    /// Update user's compliance status
    pub fn update_status(
        &mut self,
        user_id: Uuid,
        requirement_id: Uuid,
        new_status: ComplianceTrainingStatus,
    ) -> Option<&ComplianceTrainingUserStatus> {
        if let Some(status) = self.user_status.get_mut(&(user_id, requirement_id)) {
            status.status = new_status;

            if new_status == ComplianceTrainingStatus::Compliant {
                status.completed_at = Some(Utc::now());

                // Calculate next due date
                if let Some(req) = self.requirements.iter().find(|r| r.id == requirement_id) {
                    let next_due = Utc::now().date_naive()
                        + Duration::days(req.recurrence_months as i64 * 30);
                    status.next_due_date = Some(next_due);
                }
            }

            return Some(status);
        }
        None
    }

    /// Get user's compliance status for all requirements
    pub fn get_user_status(&self, user_id: Uuid) -> Vec<&ComplianceTrainingUserStatus> {
        self.user_status
            .iter()
            .filter(|((uid, _), _)| *uid == user_id)
            .map(|(_, status)| status)
            .collect()
    }

    /// Get overdue users
    pub fn get_overdue_users(&self) -> Vec<&ComplianceTrainingUserStatus> {
        let today = Utc::now().date_naive();

        self.user_status
            .values()
            .filter(|s| s.due_date < today && s.status != ComplianceTrainingStatus::Compliant)
            .collect()
    }

    /// Check and update overdue statuses
    pub fn check_overdue(&mut self) -> Vec<Uuid> {
        let today = Utc::now().date_naive();
        let mut overdue_users = Vec::new();

        for status in self.user_status.values_mut() {
            if status.due_date < today
                && !matches!(
                    status.status,
                    ComplianceTrainingStatus::Compliant | ComplianceTrainingStatus::Overdue
                )
            {
                status.status = ComplianceTrainingStatus::Overdue;
                overdue_users.push(status.user_id);
            }
        }

        overdue_users
    }

    /// Get organization compliance overview
    pub fn get_overview(&self) -> ComplianceOverview {
        let total_assignments = self.user_status.len() as u32;
        let compliant = self
            .user_status
            .values()
            .filter(|s| s.status == ComplianceTrainingStatus::Compliant)
            .count() as u32;
        let overdue = self
            .user_status
            .values()
            .filter(|s| s.status == ComplianceTrainingStatus::Overdue)
            .count() as u32;
        let in_progress = self
            .user_status
            .values()
            .filter(|s| s.status == ComplianceTrainingStatus::InProgress)
            .count() as u32;
        let pending = self
            .user_status
            .values()
            .filter(|s| s.status == ComplianceTrainingStatus::Pending)
            .count() as u32;

        let compliance_rate = if total_assignments > 0 {
            compliant as f64 / total_assignments as f64 * 100.0
        } else {
            100.0
        };

        ComplianceOverview {
            total_assignments,
            compliant,
            overdue,
            in_progress,
            pending,
            compliance_rate,
            requirements: self.requirements.iter().map(|r| r.name.clone()).collect(),
        }
    }

    /// Get all requirements
    pub fn get_requirements(&self) -> &[ComplianceTrainingRequirement] {
        &self.requirements
    }

    /// Get users due for reminders
    pub fn get_users_for_reminder(&self, days_until_due: u32) -> Vec<&ComplianceTrainingUserStatus> {
        let threshold = Utc::now().date_naive() + Duration::days(days_until_due as i64);

        self.user_status
            .values()
            .filter(|s| {
                s.due_date <= threshold
                    && s.due_date > Utc::now().date_naive()
                    && s.status == ComplianceTrainingStatus::Pending
            })
            .collect()
    }
}

impl Default for ComplianceTrainingManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Compliance overview summary
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ComplianceOverview {
    pub total_assignments: u32,
    pub compliant: u32,
    pub overdue: u32,
    pub in_progress: u32,
    pub pending: u32,
    pub compliance_rate: f64,
    pub requirements: Vec<String>,
}

/// Create default compliance requirements
fn create_default_requirements() -> Vec<ComplianceTrainingRequirement> {
    vec![
        ComplianceTrainingRequirement {
            id: Uuid::new_v4(),
            name: "Annual Security Awareness Training".to_string(),
            framework: ComplianceFramework::Nist,
            required_courses: Vec::new(),
            recurrence_months: 12,
            grace_period_days: 30,
            is_active: true,
            created_at: Utc::now(),
        },
        ComplianceTrainingRequirement {
            id: Uuid::new_v4(),
            name: "HIPAA Privacy Training".to_string(),
            framework: ComplianceFramework::Hipaa,
            required_courses: Vec::new(),
            recurrence_months: 12,
            grace_period_days: 30,
            is_active: true,
            created_at: Utc::now(),
        },
        ComplianceTrainingRequirement {
            id: Uuid::new_v4(),
            name: "PCI-DSS Security Training".to_string(),
            framework: ComplianceFramework::PciDss,
            required_courses: Vec::new(),
            recurrence_months: 12,
            grace_period_days: 30,
            is_active: true,
            created_at: Utc::now(),
        },
        ComplianceTrainingRequirement {
            id: Uuid::new_v4(),
            name: "GDPR Data Protection Training".to_string(),
            framework: ComplianceFramework::Gdpr,
            required_courses: Vec::new(),
            recurrence_months: 12,
            grace_period_days: 30,
            is_active: true,
            created_at: Utc::now(),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_assign_requirement() {
        let mut manager = ComplianceTrainingManager::new();
        let user_id = Uuid::new_v4();
        let req_id = manager.requirements[0].id;

        let due_date = Utc::now().date_naive() + Duration::days(30);
        let status = manager.assign_to_user(user_id, req_id, due_date);

        assert!(status.is_some());
        assert_eq!(status.unwrap().status, ComplianceTrainingStatus::Pending);
    }

    #[test]
    fn test_compliance_overview() {
        let manager = ComplianceTrainingManager::new();
        let overview = manager.get_overview();

        assert_eq!(overview.total_assignments, 0);
        assert_eq!(overview.compliance_rate, 100.0);
    }
}
