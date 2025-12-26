// Policy Management Module
//
// Provides comprehensive policy lifecycle management:
// - Document creation and editing
// - Version control with change tracking
// - Approval workflows
// - User acknowledgments
// - Policy exceptions

use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::types::{
    ApprovalStatus, ExceptionStatus, Policy, PolicyAcknowledgment, PolicyApproval,
    PolicyCategory, PolicyException, PolicyStatus, PolicyVersion,
};

/// Policy management engine
pub struct PolicyManager {
    policies: HashMap<String, Policy>,
    versions: HashMap<String, Vec<PolicyVersion>>,
    approvals: HashMap<String, Vec<PolicyApproval>>,
    acknowledgments: HashMap<String, Vec<PolicyAcknowledgment>>,
    exceptions: HashMap<String, Vec<PolicyException>>,
}

impl PolicyManager {
    pub fn new() -> Self {
        Self {
            policies: HashMap::new(),
            versions: HashMap::new(),
            approvals: HashMap::new(),
            acknowledgments: HashMap::new(),
            exceptions: HashMap::new(),
        }
    }

    /// Create a new policy draft
    pub fn create_policy(
        &mut self,
        title: String,
        category: PolicyCategory,
        content: String,
        owner_id: String,
    ) -> Policy {
        let id = uuid::Uuid::new_v4().to_string();
        let policy_number = format!("POL-{}", &id[..8].to_uppercase());
        let now = Utc::now();

        let policy = Policy {
            id: id.clone(),
            policy_number,
            title,
            category,
            status: PolicyStatus::Draft,
            version: "1.0".to_string(),
            content: content.clone(),
            summary: None,
            owner_id: owner_id.clone(),
            effective_date: None,
            review_date: None,
            expiry_date: None,
            parent_policy_id: None,
            requires_acknowledgment: true,
            created_at: now,
            updated_at: now,
        };

        // Create initial version
        let version = PolicyVersion {
            id: uuid::Uuid::new_v4().to_string(),
            policy_id: id.clone(),
            version: "1.0".to_string(),
            content,
            change_summary: Some("Initial version".to_string()),
            created_by: owner_id,
            created_at: now,
        };

        self.policies.insert(id.clone(), policy.clone());
        self.versions.insert(id, vec![version]);

        policy
    }

    /// Update policy content (creates new version)
    pub fn update_policy(
        &mut self,
        policy_id: &str,
        content: String,
        change_summary: Option<String>,
        updated_by: String,
    ) -> Result<PolicyVersion, PolicyError> {
        let policy = self.policies.get_mut(policy_id)
            .ok_or(PolicyError::NotFound)?;

        if policy.status != PolicyStatus::Draft {
            return Err(PolicyError::InvalidStatus("Can only update draft policies".to_string()));
        }

        // Increment version
        let version_parts: Vec<&str> = policy.version.split('.').collect();
        let major: u32 = version_parts.get(0).and_then(|v| v.parse().ok()).unwrap_or(1);
        let minor: u32 = version_parts.get(1).and_then(|v| v.parse().ok()).unwrap_or(0);
        let new_version = format!("{}.{}", major, minor + 1);

        let now = Utc::now();
        let version = PolicyVersion {
            id: uuid::Uuid::new_v4().to_string(),
            policy_id: policy_id.to_string(),
            version: new_version.clone(),
            content: content.clone(),
            change_summary,
            created_by: updated_by,
            created_at: now,
        };

        policy.content = content;
        policy.version = new_version;
        policy.updated_at = now;

        self.versions
            .entry(policy_id.to_string())
            .or_default()
            .push(version.clone());

        Ok(version)
    }

    /// Submit policy for review
    pub fn submit_for_review(&mut self, policy_id: &str) -> Result<(), PolicyError> {
        let policy = self.policies.get_mut(policy_id)
            .ok_or(PolicyError::NotFound)?;

        if policy.status != PolicyStatus::Draft {
            return Err(PolicyError::InvalidStatus("Can only submit draft policies".to_string()));
        }

        policy.status = PolicyStatus::PendingReview;
        policy.updated_at = Utc::now();

        Ok(())
    }

    /// Submit policy for approval
    pub fn submit_for_approval(
        &mut self,
        policy_id: &str,
        approver_ids: Vec<String>,
    ) -> Result<Vec<PolicyApproval>, PolicyError> {
        let policy = self.policies.get_mut(policy_id)
            .ok_or(PolicyError::NotFound)?;

        if policy.status != PolicyStatus::PendingReview {
            return Err(PolicyError::InvalidStatus("Policy must be pending review".to_string()));
        }

        policy.status = PolicyStatus::PendingApproval;
        policy.updated_at = Utc::now();

        let now = Utc::now();
        let mut approvals = Vec::new();

        for approver_id in approver_ids {
            let approval = PolicyApproval {
                id: uuid::Uuid::new_v4().to_string(),
                policy_id: policy_id.to_string(),
                version: policy.version.clone(),
                approver_id,
                status: ApprovalStatus::Pending,
                comments: None,
                decided_at: None,
                created_at: now,
            };
            approvals.push(approval.clone());
        }

        self.approvals
            .entry(policy_id.to_string())
            .or_default()
            .extend(approvals.clone());

        Ok(approvals)
    }

    /// Approve or reject a policy
    pub fn decide_approval(
        &mut self,
        approval_id: &str,
        approved: bool,
        comments: Option<String>,
    ) -> Result<PolicyApproval, PolicyError> {
        // First find and update the approval, storing needed data
        let (result, policy_id) = {
            let mut found = None;
            for approvals in self.approvals.values_mut() {
                if let Some(approval) = approvals.iter_mut().find(|a| a.id == approval_id) {
                    approval.status = if approved {
                        ApprovalStatus::Approved
                    } else {
                        ApprovalStatus::Rejected
                    };
                    approval.comments = comments;
                    approval.decided_at = Some(Utc::now());
                    found = Some((approval.clone(), approval.policy_id.clone()));
                    break;
                }
            }
            found.ok_or(PolicyError::NotFound)?
        };

        // Now check if all approvals for this policy are decided
        if let Some(policy_approvals) = self.approvals.get(&policy_id) {
            let all_decided = policy_approvals.iter().all(|a| a.decided_at.is_some());
            let all_approved = policy_approvals.iter().all(|a| a.status == ApprovalStatus::Approved);

            if all_decided {
                if let Some(policy) = self.policies.get_mut(&policy_id) {
                    if all_approved {
                        policy.status = PolicyStatus::Approved;
                        policy.effective_date = Some(Utc::now().date_naive());
                    } else {
                        policy.status = PolicyStatus::Draft; // Back to draft if rejected
                    }
                    policy.updated_at = Utc::now();
                }
            }
        }

        Ok(result)
    }

    /// Record user acknowledgment
    pub fn acknowledge_policy(
        &mut self,
        policy_id: &str,
        user_id: String,
        ip_address: Option<String>,
    ) -> Result<PolicyAcknowledgment, PolicyError> {
        let policy = self.policies.get(policy_id)
            .ok_or(PolicyError::NotFound)?;

        if policy.status != PolicyStatus::Approved {
            return Err(PolicyError::InvalidStatus("Can only acknowledge approved policies".to_string()));
        }

        // Check if already acknowledged this version
        if let Some(acks) = self.acknowledgments.get(policy_id) {
            if acks.iter().any(|a| a.user_id == user_id && a.version == policy.version) {
                return Err(PolicyError::AlreadyAcknowledged);
            }
        }

        let ack = PolicyAcknowledgment {
            id: uuid::Uuid::new_v4().to_string(),
            policy_id: policy_id.to_string(),
            user_id,
            version: policy.version.clone(),
            acknowledged_at: Utc::now(),
            ip_address,
        };

        self.acknowledgments
            .entry(policy_id.to_string())
            .or_default()
            .push(ack.clone());

        Ok(ack)
    }

    /// Create a policy exception
    pub fn create_exception(
        &mut self,
        policy_id: &str,
        title: String,
        description: String,
        justification: String,
        requestor_id: String,
        start_date: NaiveDate,
        end_date: NaiveDate,
    ) -> Result<PolicyException, PolicyError> {
        if !self.policies.contains_key(policy_id) {
            return Err(PolicyError::NotFound);
        }

        let exception = PolicyException {
            id: uuid::Uuid::new_v4().to_string(),
            policy_id: policy_id.to_string(),
            title,
            description,
            justification,
            risk_accepted: None,
            compensating_controls: None,
            requestor_id,
            approver_id: None,
            status: ExceptionStatus::Pending,
            start_date,
            end_date,
            created_at: Utc::now(),
        };

        self.exceptions
            .entry(policy_id.to_string())
            .or_default()
            .push(exception.clone());

        Ok(exception)
    }

    /// Approve or reject exception
    pub fn decide_exception(
        &mut self,
        exception_id: &str,
        approver_id: String,
        approved: bool,
        risk_accepted: Option<String>,
        compensating_controls: Option<String>,
    ) -> Result<PolicyException, PolicyError> {
        for exceptions in self.exceptions.values_mut() {
            if let Some(exception) = exceptions.iter_mut().find(|e| e.id == exception_id) {
                exception.approver_id = Some(approver_id);
                exception.status = if approved {
                    ExceptionStatus::Approved
                } else {
                    ExceptionStatus::Rejected
                };
                exception.risk_accepted = risk_accepted;
                exception.compensating_controls = compensating_controls;

                return Ok(exception.clone());
            }
        }

        Err(PolicyError::NotFound)
    }

    /// Get policy by ID
    pub fn get_policy(&self, policy_id: &str) -> Option<&Policy> {
        self.policies.get(policy_id)
    }

    /// List all policies
    pub fn list_policies(&self, category: Option<PolicyCategory>, status: Option<PolicyStatus>) -> Vec<&Policy> {
        self.policies
            .values()
            .filter(|p| {
                category.as_ref().map_or(true, |c| &p.category == c)
                    && status.as_ref().map_or(true, |s| &p.status == s)
            })
            .collect()
    }

    /// Get policy versions
    pub fn get_versions(&self, policy_id: &str) -> Vec<&PolicyVersion> {
        self.versions
            .get(policy_id)
            .map(|v| v.iter().collect())
            .unwrap_or_default()
    }

    /// Get acknowledgments for a policy
    pub fn get_acknowledgments(&self, policy_id: &str) -> Vec<&PolicyAcknowledgment> {
        self.acknowledgments
            .get(policy_id)
            .map(|a| a.iter().collect())
            .unwrap_or_default()
    }

    /// Get exceptions for a policy
    pub fn get_exceptions(&self, policy_id: &str) -> Vec<&PolicyException> {
        self.exceptions
            .get(policy_id)
            .map(|e| e.iter().collect())
            .unwrap_or_default()
    }

    /// Calculate acknowledgment compliance rate
    pub fn calculate_acknowledgment_compliance(&self, policy_id: &str, total_users: u32) -> f64 {
        if total_users == 0 {
            return 0.0;
        }

        let acknowledged_count = self.acknowledgments
            .get(policy_id)
            .map(|a| a.len())
            .unwrap_or(0) as f64;

        acknowledged_count / total_users as f64 * 100.0
    }

    /// Retire a policy
    pub fn retire_policy(&mut self, policy_id: &str) -> Result<(), PolicyError> {
        let policy = self.policies.get_mut(policy_id)
            .ok_or(PolicyError::NotFound)?;

        policy.status = PolicyStatus::Retired;
        policy.updated_at = Utc::now();

        Ok(())
    }
}

impl Default for PolicyManager {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PolicyError {
    NotFound,
    InvalidStatus(String),
    AlreadyAcknowledged,
    ValidationError(String),
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => write!(f, "Policy not found"),
            Self::InvalidStatus(msg) => write!(f, "Invalid status: {}", msg),
            Self::AlreadyAcknowledged => write!(f, "Policy already acknowledged"),
            Self::ValidationError(msg) => write!(f, "Validation error: {}", msg),
        }
    }
}

impl std::error::Error for PolicyError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_lifecycle() {
        let mut manager = PolicyManager::new();

        // Create policy
        let policy = manager.create_policy(
            "Information Security Policy".to_string(),
            PolicyCategory::InformationSecurity,
            "# Information Security Policy\n\nThis policy...".to_string(),
            "user-1".to_string(),
        );

        assert_eq!(policy.status, PolicyStatus::Draft);
        assert_eq!(policy.version, "1.0");

        // Submit for review
        manager.submit_for_review(&policy.id).unwrap();
        let updated = manager.get_policy(&policy.id).unwrap();
        assert_eq!(updated.status, PolicyStatus::PendingReview);

        // Submit for approval
        let approvals = manager.submit_for_approval(&policy.id, vec!["approver-1".to_string()]).unwrap();
        assert_eq!(approvals.len(), 1);
        assert_eq!(approvals[0].status, ApprovalStatus::Pending);

        // Approve
        manager.decide_approval(&approvals[0].id, true, Some("Approved".to_string())).unwrap();
        let final_policy = manager.get_policy(&policy.id).unwrap();
        assert_eq!(final_policy.status, PolicyStatus::Approved);
    }

    #[test]
    fn test_policy_acknowledgment() {
        let mut manager = PolicyManager::new();

        let policy = manager.create_policy(
            "Test Policy".to_string(),
            PolicyCategory::AcceptableUse,
            "Content".to_string(),
            "user-1".to_string(),
        );

        // Can't acknowledge draft
        let result = manager.acknowledge_policy(&policy.id, "user-2".to_string(), None);
        assert!(result.is_err());
    }
}
