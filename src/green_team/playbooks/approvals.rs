//! Approval workflow system for playbook actions
//!
//! Provides approval mechanisms for high-risk playbook actions:
//! - Approval requests
//! - Multi-level approvals
//! - Approval notifications
//! - Auto-approval for low-risk actions

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Risk level for playbook actions
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl RiskLevel {
    /// Check if this risk level requires approval
    pub fn requires_approval(&self) -> bool {
        matches!(self, RiskLevel::High | RiskLevel::Critical)
    }

    /// Get minimum number of approvals required
    pub fn min_approvals(&self) -> u32 {
        match self {
            RiskLevel::Low | RiskLevel::Medium => 0,
            RiskLevel::High => 1,
            RiskLevel::Critical => 2,
        }
    }
}

/// Approval request status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ApprovalStatus {
    Pending,
    Approved,
    Rejected,
    Expired,
}

/// Approval request for a playbook action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequest {
    pub id: Uuid,
    pub run_id: Uuid,
    pub step_id: String,
    pub action_name: String,
    pub action_description: String,
    pub risk_level: RiskLevel,
    pub approvers: Vec<String>,
    pub required_approvals: u32,
    pub status: ApprovalStatus,
    pub approvals: Vec<Approval>,
    pub rejections: Vec<Rejection>,
    pub requested_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub timeout_hours: u32,
    pub auto_approve_enabled: bool,
}

impl ApprovalRequest {
    /// Create a new approval request
    pub fn new(
        run_id: Uuid,
        step_id: String,
        action_name: String,
        action_description: String,
        risk_level: RiskLevel,
        approvers: Vec<String>,
        timeout_hours: u32,
    ) -> Self {
        let required_approvals = risk_level.min_approvals();
        let now = Utc::now();
        let expires_at = if timeout_hours > 0 {
            Some(now + chrono::Duration::hours(timeout_hours as i64))
        } else {
            None
        };

        Self {
            id: Uuid::new_v4(),
            run_id,
            step_id,
            action_name,
            action_description,
            risk_level,
            approvers,
            required_approvals,
            status: ApprovalStatus::Pending,
            approvals: Vec::new(),
            rejections: Vec::new(),
            requested_at: now,
            expires_at,
            completed_at: None,
            timeout_hours,
            auto_approve_enabled: false,
        }
    }

    /// Check if request has expired
    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            Utc::now() > expires_at
        } else {
            false
        }
    }

    /// Check if request is approved
    pub fn is_approved(&self) -> bool {
        self.approvals.len() as u32 >= self.required_approvals
    }

    /// Check if request is rejected
    pub fn is_rejected(&self) -> bool {
        !self.rejections.is_empty()
    }

    /// Add an approval
    pub fn add_approval(&mut self, approver: String, comment: Option<String>) -> Result<(), String> {
        if self.status != ApprovalStatus::Pending {
            return Err("Approval request is not pending".to_string());
        }

        if self.is_expired() {
            self.status = ApprovalStatus::Expired;
            return Err("Approval request has expired".to_string());
        }

        if !self.approvers.contains(&approver) {
            return Err("User is not an authorized approver".to_string());
        }

        // Check if already approved by this user
        if self.approvals.iter().any(|a| a.approver == approver) {
            return Err("User has already approved this request".to_string());
        }

        self.approvals.push(Approval {
            approver,
            approved_at: Utc::now(),
            comment,
        });

        if self.is_approved() {
            self.status = ApprovalStatus::Approved;
            self.completed_at = Some(Utc::now());
        }

        Ok(())
    }

    /// Add a rejection
    pub fn add_rejection(&mut self, rejector: String, reason: String) -> Result<(), String> {
        if self.status != ApprovalStatus::Pending {
            return Err("Approval request is not pending".to_string());
        }

        if !self.approvers.contains(&rejector) {
            return Err("User is not an authorized approver".to_string());
        }

        self.rejections.push(Rejection {
            rejector,
            rejected_at: Utc::now(),
            reason,
        });

        self.status = ApprovalStatus::Rejected;
        self.completed_at = Some(Utc::now());

        Ok(())
    }
}

/// Individual approval
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Approval {
    pub approver: String,
    pub approved_at: DateTime<Utc>,
    pub comment: Option<String>,
}

/// Individual rejection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rejection {
    pub rejector: String,
    pub rejected_at: DateTime<Utc>,
    pub reason: String,
}

/// Approval manager for handling approval workflows
pub struct ApprovalManager {
    requests: HashMap<Uuid, ApprovalRequest>,
}

impl ApprovalManager {
    /// Create a new approval manager
    pub fn new() -> Self {
        Self {
            requests: HashMap::new(),
        }
    }

    /// Create an approval request
    pub fn create_request(
        &mut self,
        run_id: Uuid,
        step_id: String,
        action_name: String,
        action_description: String,
        risk_level: RiskLevel,
        approvers: Vec<String>,
        timeout_hours: u32,
    ) -> Uuid {
        let request = ApprovalRequest::new(
            run_id,
            step_id,
            action_name,
            action_description,
            risk_level,
            approvers,
            timeout_hours,
        );

        let id = request.id;
        self.requests.insert(id, request);
        id
    }

    /// Get an approval request
    pub fn get_request(&self, id: &Uuid) -> Option<&ApprovalRequest> {
        self.requests.get(id)
    }

    /// Get mutable approval request
    pub fn get_request_mut(&mut self, id: &Uuid) -> Option<&mut ApprovalRequest> {
        self.requests.get_mut(id)
    }

    /// Approve a request
    pub fn approve(
        &mut self,
        request_id: &Uuid,
        approver: String,
        comment: Option<String>,
    ) -> Result<(), String> {
        let request = self
            .requests
            .get_mut(request_id)
            .ok_or_else(|| "Approval request not found".to_string())?;

        request.add_approval(approver, comment)
    }

    /// Reject a request
    pub fn reject(
        &mut self,
        request_id: &Uuid,
        rejector: String,
        reason: String,
    ) -> Result<(), String> {
        let request = self
            .requests
            .get_mut(request_id)
            .ok_or_else(|| "Approval request not found".to_string())?;

        request.add_rejection(rejector, reason)
    }

    /// Get pending requests for a user
    pub fn get_pending_for_user(&self, username: &str) -> Vec<&ApprovalRequest> {
        self.requests
            .values()
            .filter(|r| {
                r.status == ApprovalStatus::Pending
                    && r.approvers.contains(&username.to_string())
                    && !r.is_expired()
            })
            .collect()
    }

    /// Get all pending requests
    pub fn get_all_pending(&self) -> Vec<&ApprovalRequest> {
        self.requests
            .values()
            .filter(|r| r.status == ApprovalStatus::Pending && !r.is_expired())
            .collect()
    }

    /// Clean up expired requests
    pub fn cleanup_expired(&mut self) {
        for request in self.requests.values_mut() {
            if request.status == ApprovalStatus::Pending && request.is_expired() {
                request.status = ApprovalStatus::Expired;
                request.completed_at = Some(Utc::now());
            }
        }
    }

    /// Get request by run ID and step ID
    pub fn get_by_run_and_step(&self, run_id: &Uuid, step_id: &str) -> Option<&ApprovalRequest> {
        self.requests.values().find(|r| {
            r.run_id == *run_id && r.step_id == step_id && r.status == ApprovalStatus::Pending
        })
    }
}

impl Default for ApprovalManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_risk_level_requires_approval() {
        assert!(!RiskLevel::Low.requires_approval());
        assert!(!RiskLevel::Medium.requires_approval());
        assert!(RiskLevel::High.requires_approval());
        assert!(RiskLevel::Critical.requires_approval());
    }

    #[test]
    fn test_approval_request_single_approval() {
        let mut request = ApprovalRequest::new(
            Uuid::new_v4(),
            "step1".to_string(),
            "Block IP".to_string(),
            "Block malicious IP address".to_string(),
            RiskLevel::High,
            vec!["admin".to_string(), "security_lead".to_string()],
            24,
        );

        assert_eq!(request.status, ApprovalStatus::Pending);
        assert!(!request.is_approved());

        request
            .add_approval("admin".to_string(), Some("Approved".to_string()))
            .unwrap();

        assert_eq!(request.status, ApprovalStatus::Approved);
        assert!(request.is_approved());
    }

    #[test]
    fn test_approval_request_multi_approval() {
        let mut request = ApprovalRequest::new(
            Uuid::new_v4(),
            "step1".to_string(),
            "Shutdown Production Server".to_string(),
            "Emergency shutdown of compromised production server".to_string(),
            RiskLevel::Critical,
            vec!["admin".to_string(), "ciso".to_string(), "cto".to_string()],
            2,
        );

        assert_eq!(request.required_approvals, 2);

        request.add_approval("admin".to_string(), None).unwrap();
        assert_eq!(request.status, ApprovalStatus::Pending);

        request.add_approval("ciso".to_string(), None).unwrap();
        assert_eq!(request.status, ApprovalStatus::Approved);
    }

    #[test]
    fn test_approval_request_rejection() {
        let mut request = ApprovalRequest::new(
            Uuid::new_v4(),
            "step1".to_string(),
            "Delete Database".to_string(),
            "Delete customer database".to_string(),
            RiskLevel::Critical,
            vec!["admin".to_string()],
            1,
        );

        request
            .add_rejection("admin".to_string(), "Too risky".to_string())
            .unwrap();

        assert_eq!(request.status, ApprovalStatus::Rejected);
        assert!(!request.is_approved());
        assert!(request.is_rejected());
    }

    #[test]
    fn test_approval_manager() {
        let mut manager = ApprovalManager::new();

        let request_id = manager.create_request(
            Uuid::new_v4(),
            "step1".to_string(),
            "Reboot Server".to_string(),
            "Reboot web server".to_string(),
            RiskLevel::High,
            vec!["admin".to_string()],
            24,
        );

        assert_eq!(manager.get_pending_for_user("admin").len(), 1);

        manager
            .approve(&request_id, "admin".to_string(), None)
            .unwrap();

        assert_eq!(manager.get_pending_for_user("admin").len(), 0);

        let request = manager.get_request(&request_id).unwrap();
        assert_eq!(request.status, ApprovalStatus::Approved);
    }
}
