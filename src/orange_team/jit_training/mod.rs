//! Just-in-Time (JIT) Training module - Event-triggered training assignments

use crate::orange_team::types::*;
use chrono::{Duration, Utc};
use std::collections::HashMap;
use uuid::Uuid;

/// JIT Training engine
pub struct JitTrainingEngine {
    triggers: Vec<JitTrainingTrigger>,
    assignments: Vec<JitTrainingAssignment>,
    modules: HashMap<Uuid, TrainingModule>,
}

impl JitTrainingEngine {
    /// Create a new JIT training engine
    pub fn new() -> Self {
        Self {
            triggers: create_default_triggers(),
            assignments: Vec::new(),
            modules: HashMap::new(),
        }
    }

    /// Add a training module
    pub fn add_module(&mut self, module: TrainingModule) {
        self.modules.insert(module.id, module);
    }

    /// Create a new trigger
    pub fn create_trigger(
        &mut self,
        name: &str,
        trigger_type: JitTriggerType,
        training_module_id: Uuid,
        delay_minutes: u32,
    ) -> JitTrainingTrigger {
        let trigger = JitTrainingTrigger {
            id: Uuid::new_v4(),
            name: name.to_string(),
            trigger_type,
            training_module_id,
            delay_minutes,
            is_active: true,
            created_at: Utc::now(),
        };

        self.triggers.push(trigger.clone());
        trigger
    }

    /// Fire an event and create assignments if triggers match
    pub fn fire_event(
        &mut self,
        user_id: Uuid,
        event_type: JitTriggerType,
        event_id: Option<Uuid>,
    ) -> Vec<JitTrainingAssignment> {
        let matching_triggers: Vec<_> = self
            .triggers
            .iter()
            .filter(|t| t.is_active && t.trigger_type == event_type)
            .cloned()
            .collect();

        let mut assignments = Vec::new();

        for trigger in matching_triggers {
            // Check if user already has a pending assignment for this trigger
            let has_pending = self.assignments.iter().any(|a| {
                a.user_id == user_id
                    && a.trigger_id == trigger.id
                    && matches!(
                        a.status,
                        JitAssignmentStatus::Assigned | JitAssignmentStatus::InProgress
                    )
            });

            if has_pending {
                continue;
            }

            let due_at = if trigger.delay_minutes > 0 {
                Some(Utc::now() + Duration::minutes(trigger.delay_minutes as i64))
            } else {
                Some(Utc::now() + Duration::hours(24))
            };

            let assignment = JitTrainingAssignment {
                id: Uuid::new_v4(),
                user_id,
                trigger_id: trigger.id,
                training_module_id: trigger.training_module_id,
                trigger_event_id: event_id,
                status: JitAssignmentStatus::Assigned,
                assigned_at: Utc::now(),
                due_at,
                completed_at: None,
            };

            self.assignments.push(assignment.clone());
            assignments.push(assignment);
        }

        assignments
    }

    /// Get pending assignments for a user
    pub fn get_pending_assignments(&self, user_id: Uuid) -> Vec<&JitTrainingAssignment> {
        self.assignments
            .iter()
            .filter(|a| {
                a.user_id == user_id
                    && matches!(
                        a.status,
                        JitAssignmentStatus::Assigned | JitAssignmentStatus::InProgress
                    )
            })
            .collect()
    }

    /// Start an assignment
    pub fn start_assignment(&mut self, assignment_id: Uuid) -> Option<&JitTrainingAssignment> {
        if let Some(assignment) = self.assignments.iter_mut().find(|a| a.id == assignment_id) {
            if assignment.status == JitAssignmentStatus::Assigned {
                assignment.status = JitAssignmentStatus::InProgress;
            }
            return Some(assignment);
        }
        None
    }

    /// Complete an assignment
    pub fn complete_assignment(&mut self, assignment_id: Uuid) -> Option<&JitTrainingAssignment> {
        if let Some(assignment) = self.assignments.iter_mut().find(|a| a.id == assignment_id) {
            assignment.status = JitAssignmentStatus::Completed;
            assignment.completed_at = Some(Utc::now());
            return Some(assignment);
        }
        None
    }

    /// Dismiss an assignment
    pub fn dismiss_assignment(&mut self, assignment_id: Uuid) -> Option<&JitTrainingAssignment> {
        if let Some(assignment) = self.assignments.iter_mut().find(|a| a.id == assignment_id) {
            assignment.status = JitAssignmentStatus::Dismissed;
            return Some(assignment);
        }
        None
    }

    /// Check for overdue assignments
    pub fn check_overdue(&mut self) -> Vec<&JitTrainingAssignment> {
        let now = Utc::now();

        for assignment in &mut self.assignments {
            if let Some(due) = assignment.due_at {
                if due < now && assignment.status == JitAssignmentStatus::Assigned {
                    assignment.status = JitAssignmentStatus::Overdue;
                }
            }
        }

        self.assignments
            .iter()
            .filter(|a| a.status == JitAssignmentStatus::Overdue)
            .collect()
    }

    /// Get all triggers
    pub fn get_triggers(&self) -> &[JitTrainingTrigger] {
        &self.triggers
    }

    /// Update trigger status
    pub fn set_trigger_active(&mut self, trigger_id: Uuid, is_active: bool) -> bool {
        if let Some(trigger) = self.triggers.iter_mut().find(|t| t.id == trigger_id) {
            trigger.is_active = is_active;
            return true;
        }
        false
    }
}

impl Default for JitTrainingEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Generate a deterministic UUID from a seed string (for default module references)
fn generate_module_uuid(seed: &str) -> Uuid {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    seed.hash(&mut hasher);
    let hash = hasher.finish();

    // Create UUID v4-like format from hash
    Uuid::from_u128((hash as u128) << 64 | (hash as u128))
}

/// Create default JIT training triggers
fn create_default_triggers() -> Vec<JitTrainingTrigger> {
    // Use deterministic UUIDs for default training module references
    // These can be replaced when actual modules are configured
    let phishing_module_id = generate_module_uuid("default-phishing-awareness-module");
    let quiz_module_id = generate_module_uuid("default-quiz-remediation-module");
    let incident_module_id = generate_module_uuid("default-incident-response-module");
    let login_module_id = generate_module_uuid("default-account-security-module");

    vec![
        JitTrainingTrigger {
            id: generate_module_uuid("trigger-phishing-click"),
            name: "Phishing Click Response".to_string(),
            trigger_type: JitTriggerType::PhishingClick,
            training_module_id: phishing_module_id,
            delay_minutes: 0,
            is_active: true,
            created_at: Utc::now(),
        },
        JitTrainingTrigger {
            id: generate_module_uuid("trigger-failed-quiz"),
            name: "Failed Quiz Remediation".to_string(),
            trigger_type: JitTriggerType::FailedQuiz,
            training_module_id: quiz_module_id,
            delay_minutes: 60,
            is_active: true,
            created_at: Utc::now(),
        },
        JitTrainingTrigger {
            id: generate_module_uuid("trigger-security-incident"),
            name: "Security Incident Response".to_string(),
            trigger_type: JitTriggerType::SecurityIncident,
            training_module_id: incident_module_id,
            delay_minutes: 30,
            is_active: true,
            created_at: Utc::now(),
        },
        JitTrainingTrigger {
            id: generate_module_uuid("trigger-suspicious-login"),
            name: "Suspicious Login Training".to_string(),
            trigger_type: JitTriggerType::SuspiciousLogin,
            training_module_id: login_module_id,
            delay_minutes: 0,
            is_active: true,
            created_at: Utc::now(),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fire_event() {
        let mut engine = JitTrainingEngine::new();
        let user_id = Uuid::new_v4();

        let assignments = engine.fire_event(user_id, JitTriggerType::PhishingClick, None);

        assert!(!assignments.is_empty());
        assert_eq!(assignments[0].user_id, user_id);
        assert_eq!(assignments[0].status, JitAssignmentStatus::Assigned);
    }

    #[test]
    fn test_complete_assignment() {
        let mut engine = JitTrainingEngine::new();
        let user_id = Uuid::new_v4();

        let assignments = engine.fire_event(user_id, JitTriggerType::PhishingClick, None);
        let assignment_id = assignments[0].id;

        engine.start_assignment(assignment_id);
        engine.complete_assignment(assignment_id);

        let pending = engine.get_pending_assignments(user_id);
        assert!(pending.is_empty());
    }
}
