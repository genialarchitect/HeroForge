// Policy Management Module
//
// Provides comprehensive policy lifecycle management with SQLite persistence:
// - Document creation and editing
// - Version control with change tracking
// - Approval workflows
// - User acknowledgments
// - Policy exceptions

use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use super::types::{
    ApprovalStatus, ExceptionStatus, Policy, PolicyAcknowledgment, PolicyApproval,
    PolicyCategory, PolicyException, PolicyStatus, PolicyVersion,
};

/// Policy management engine backed by SQLite
pub struct PolicyManager {
    pool: SqlitePool,
}

impl PolicyManager {
    pub async fn new(pool: SqlitePool) -> Result<Self, PolicyError> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS policies (
                id TEXT PRIMARY KEY,
                policy_number TEXT NOT NULL UNIQUE,
                title TEXT NOT NULL,
                category TEXT NOT NULL,
                status TEXT NOT NULL,
                version TEXT NOT NULL,
                content TEXT NOT NULL,
                summary TEXT,
                owner_id TEXT NOT NULL,
                effective_date TEXT,
                review_date TEXT,
                expiry_date TEXT,
                parent_policy_id TEXT,
                requires_acknowledgment INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )"
        )
        .execute(&pool)
        .await
        .map_err(|e| PolicyError::DatabaseError(e.to_string()))?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS policy_versions (
                id TEXT PRIMARY KEY,
                policy_id TEXT NOT NULL,
                version TEXT NOT NULL,
                content TEXT NOT NULL,
                change_summary TEXT,
                created_by TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (policy_id) REFERENCES policies(id)
            )"
        )
        .execute(&pool)
        .await
        .map_err(|e| PolicyError::DatabaseError(e.to_string()))?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS policy_approvals (
                id TEXT PRIMARY KEY,
                policy_id TEXT NOT NULL,
                version TEXT NOT NULL,
                approver_id TEXT NOT NULL,
                status TEXT NOT NULL,
                comments TEXT,
                decided_at TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (policy_id) REFERENCES policies(id)
            )"
        )
        .execute(&pool)
        .await
        .map_err(|e| PolicyError::DatabaseError(e.to_string()))?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS policy_acknowledgments (
                id TEXT PRIMARY KEY,
                policy_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                version TEXT NOT NULL,
                acknowledged_at TEXT NOT NULL,
                ip_address TEXT,
                FOREIGN KEY (policy_id) REFERENCES policies(id)
            )"
        )
        .execute(&pool)
        .await
        .map_err(|e| PolicyError::DatabaseError(e.to_string()))?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS policy_exceptions (
                id TEXT PRIMARY KEY,
                policy_id TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                justification TEXT NOT NULL,
                risk_accepted TEXT,
                compensating_controls TEXT,
                requestor_id TEXT NOT NULL,
                approver_id TEXT,
                status TEXT NOT NULL,
                start_date TEXT NOT NULL,
                end_date TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (policy_id) REFERENCES policies(id)
            )"
        )
        .execute(&pool)
        .await
        .map_err(|e| PolicyError::DatabaseError(e.to_string()))?;

        Ok(Self { pool })
    }

    /// Create a new policy draft
    pub async fn create_policy(
        &self,
        title: String,
        category: PolicyCategory,
        content: String,
        owner_id: String,
    ) -> Result<Policy, PolicyError> {
        let id = uuid::Uuid::new_v4().to_string();
        let policy_number = format!("POL-{}", &id[..8].to_uppercase());
        let now = Utc::now();
        let now_str = now.to_rfc3339();

        let policy = Policy {
            id: id.clone(),
            policy_number: policy_number.clone(),
            title: title.clone(),
            category: category.clone(),
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

        sqlx::query(
            "INSERT INTO policies (id, policy_number, title, category, status, version, content, summary, owner_id, effective_date, review_date, expiry_date, parent_policy_id, requires_acknowledgment, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)"
        )
        .bind(&id)
        .bind(&policy_number)
        .bind(&title)
        .bind(category.to_string())
        .bind("draft")
        .bind("1.0")
        .bind(&content)
        .bind(None::<String>)
        .bind(&owner_id)
        .bind(None::<String>)
        .bind(None::<String>)
        .bind(None::<String>)
        .bind(None::<String>)
        .bind(true)
        .bind(&now_str)
        .bind(&now_str)
        .execute(&self.pool)
        .await
        .map_err(|e| PolicyError::DatabaseError(e.to_string()))?;

        // Create initial version
        let version_id = uuid::Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO policy_versions (id, policy_id, version, content, change_summary, created_by, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"
        )
        .bind(&version_id)
        .bind(&id)
        .bind("1.0")
        .bind(&content)
        .bind(Some("Initial version"))
        .bind(&owner_id)
        .bind(&now_str)
        .execute(&self.pool)
        .await
        .map_err(|e| PolicyError::DatabaseError(e.to_string()))?;

        Ok(policy)
    }

    /// Update policy content (creates new version)
    pub async fn update_policy(
        &self,
        policy_id: &str,
        content: String,
        change_summary: Option<String>,
        updated_by: String,
    ) -> Result<PolicyVersion, PolicyError> {
        let policy = self.get_policy(policy_id).await?
            .ok_or(PolicyError::NotFound)?;

        if policy.status != PolicyStatus::Draft {
            return Err(PolicyError::InvalidStatus("Can only update draft policies".to_string()));
        }

        // Increment version
        let version_parts: Vec<&str> = policy.version.split('.').collect();
        let major: u32 = version_parts.first().and_then(|v| v.parse().ok()).unwrap_or(1);
        let minor: u32 = version_parts.get(1).and_then(|v| v.parse().ok()).unwrap_or(0);
        let new_version = format!("{}.{}", major, minor + 1);

        let now = Utc::now();
        let now_str = now.to_rfc3339();

        // Update policy
        sqlx::query(
            "UPDATE policies SET content = ?1, version = ?2, updated_at = ?3 WHERE id = ?4"
        )
        .bind(&content)
        .bind(&new_version)
        .bind(&now_str)
        .bind(policy_id)
        .execute(&self.pool)
        .await
        .map_err(|e| PolicyError::DatabaseError(e.to_string()))?;

        // Create version record
        let version_id = uuid::Uuid::new_v4().to_string();
        let version = PolicyVersion {
            id: version_id.clone(),
            policy_id: policy_id.to_string(),
            version: new_version,
            content: content.clone(),
            change_summary: change_summary.clone(),
            created_by: updated_by.clone(),
            created_at: now,
        };

        sqlx::query(
            "INSERT INTO policy_versions (id, policy_id, version, content, change_summary, created_by, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"
        )
        .bind(&version.id)
        .bind(policy_id)
        .bind(&version.version)
        .bind(&content)
        .bind(&change_summary)
        .bind(&updated_by)
        .bind(&now_str)
        .execute(&self.pool)
        .await
        .map_err(|e| PolicyError::DatabaseError(e.to_string()))?;

        Ok(version)
    }

    /// Submit policy for review
    pub async fn submit_for_review(&self, policy_id: &str) -> Result<(), PolicyError> {
        let policy = self.get_policy(policy_id).await?
            .ok_or(PolicyError::NotFound)?;

        if policy.status != PolicyStatus::Draft {
            return Err(PolicyError::InvalidStatus("Can only submit draft policies".to_string()));
        }

        let now_str = Utc::now().to_rfc3339();
        sqlx::query("UPDATE policies SET status = 'pending_review', updated_at = ?1 WHERE id = ?2")
            .bind(&now_str)
            .bind(policy_id)
            .execute(&self.pool)
            .await
            .map_err(|e| PolicyError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    /// Submit policy for approval
    pub async fn submit_for_approval(
        &self,
        policy_id: &str,
        approver_ids: Vec<String>,
    ) -> Result<Vec<PolicyApproval>, PolicyError> {
        let policy = self.get_policy(policy_id).await?
            .ok_or(PolicyError::NotFound)?;

        if policy.status != PolicyStatus::PendingReview {
            return Err(PolicyError::InvalidStatus("Policy must be pending review".to_string()));
        }

        let now = Utc::now();
        let now_str = now.to_rfc3339();

        // Update policy status
        sqlx::query("UPDATE policies SET status = 'pending_approval', updated_at = ?1 WHERE id = ?2")
            .bind(&now_str)
            .bind(policy_id)
            .execute(&self.pool)
            .await
            .map_err(|e| PolicyError::DatabaseError(e.to_string()))?;

        let mut approvals = Vec::new();
        for approver_id in approver_ids {
            let approval_id = uuid::Uuid::new_v4().to_string();
            let approval = PolicyApproval {
                id: approval_id.clone(),
                policy_id: policy_id.to_string(),
                version: policy.version.clone(),
                approver_id: approver_id.clone(),
                status: ApprovalStatus::Pending,
                comments: None,
                decided_at: None,
                created_at: now,
            };

            sqlx::query(
                "INSERT INTO policy_approvals (id, policy_id, version, approver_id, status, comments, decided_at, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)"
            )
            .bind(&approval_id)
            .bind(policy_id)
            .bind(&policy.version)
            .bind(&approver_id)
            .bind("pending")
            .bind(None::<String>)
            .bind(None::<String>)
            .bind(&now_str)
            .execute(&self.pool)
            .await
            .map_err(|e| PolicyError::DatabaseError(e.to_string()))?;

            approvals.push(approval);
        }

        Ok(approvals)
    }

    /// Approve or reject a policy
    pub async fn decide_approval(
        &self,
        approval_id: &str,
        approved: bool,
        comments: Option<String>,
    ) -> Result<PolicyApproval, PolicyError> {
        // Find the approval
        let row = sqlx::query_as::<_, ApprovalRow>(
            "SELECT id, policy_id, version, approver_id, status, comments, decided_at, created_at
             FROM policy_approvals WHERE id = ?1"
        )
        .bind(approval_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| PolicyError::DatabaseError(e.to_string()))?
        .ok_or(PolicyError::NotFound)?;

        let new_status = if approved { "approved" } else { "rejected" };
        let decided_at = Utc::now();
        let decided_str = decided_at.to_rfc3339();

        // Update the approval
        sqlx::query(
            "UPDATE policy_approvals SET status = ?1, comments = ?2, decided_at = ?3 WHERE id = ?4"
        )
        .bind(new_status)
        .bind(&comments)
        .bind(&decided_str)
        .bind(approval_id)
        .execute(&self.pool)
        .await
        .map_err(|e| PolicyError::DatabaseError(e.to_string()))?;

        let policy_id = &row.policy_id;

        // Check if all approvals for this policy are decided
        let pending_count: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM policy_approvals WHERE policy_id = ?1 AND decided_at IS NULL"
        )
        .bind(policy_id)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| PolicyError::DatabaseError(e.to_string()))?;

        if pending_count.0 == 0 {
            // All decided - check if all approved
            let rejected_count: (i64,) = sqlx::query_as(
                "SELECT COUNT(*) FROM policy_approvals WHERE policy_id = ?1 AND status = 'rejected'"
            )
            .bind(policy_id)
            .fetch_one(&self.pool)
            .await
            .map_err(|e| PolicyError::DatabaseError(e.to_string()))?;

            let now_str = Utc::now().to_rfc3339();
            if rejected_count.0 == 0 {
                // All approved
                let effective_date = Utc::now().date_naive().to_string();
                sqlx::query(
                    "UPDATE policies SET status = 'approved', effective_date = ?1, updated_at = ?2 WHERE id = ?3"
                )
                .bind(&effective_date)
                .bind(&now_str)
                .bind(policy_id)
                .execute(&self.pool)
                .await
                .map_err(|e| PolicyError::DatabaseError(e.to_string()))?;
            } else {
                // Rejected - back to draft
                sqlx::query("UPDATE policies SET status = 'draft', updated_at = ?1 WHERE id = ?2")
                    .bind(&now_str)
                    .bind(policy_id)
                    .execute(&self.pool)
                    .await
                    .map_err(|e| PolicyError::DatabaseError(e.to_string()))?;
            }
        }

        Ok(PolicyApproval {
            id: row.id,
            policy_id: row.policy_id,
            version: row.version,
            approver_id: row.approver_id,
            status: if approved { ApprovalStatus::Approved } else { ApprovalStatus::Rejected },
            comments,
            decided_at: Some(decided_at),
            created_at: parse_datetime(&row.created_at),
        })
    }

    /// Record user acknowledgment
    pub async fn acknowledge_policy(
        &self,
        policy_id: &str,
        user_id: String,
        ip_address: Option<String>,
    ) -> Result<PolicyAcknowledgment, PolicyError> {
        let policy = self.get_policy(policy_id).await?
            .ok_or(PolicyError::NotFound)?;

        if policy.status != PolicyStatus::Approved {
            return Err(PolicyError::InvalidStatus("Can only acknowledge approved policies".to_string()));
        }

        // Check if already acknowledged this version
        let existing: Option<(String,)> = sqlx::query_as(
            "SELECT id FROM policy_acknowledgments WHERE policy_id = ?1 AND user_id = ?2 AND version = ?3"
        )
        .bind(policy_id)
        .bind(&user_id)
        .bind(&policy.version)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| PolicyError::DatabaseError(e.to_string()))?;

        if existing.is_some() {
            return Err(PolicyError::AlreadyAcknowledged);
        }

        let ack_id = uuid::Uuid::new_v4().to_string();
        let now = Utc::now();
        let now_str = now.to_rfc3339();

        sqlx::query(
            "INSERT INTO policy_acknowledgments (id, policy_id, user_id, version, acknowledged_at, ip_address)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)"
        )
        .bind(&ack_id)
        .bind(policy_id)
        .bind(&user_id)
        .bind(&policy.version)
        .bind(&now_str)
        .bind(&ip_address)
        .execute(&self.pool)
        .await
        .map_err(|e| PolicyError::DatabaseError(e.to_string()))?;

        Ok(PolicyAcknowledgment {
            id: ack_id,
            policy_id: policy_id.to_string(),
            user_id,
            version: policy.version,
            acknowledged_at: now,
            ip_address,
        })
    }

    /// Create a policy exception
    pub async fn create_exception(
        &self,
        policy_id: &str,
        title: String,
        description: String,
        justification: String,
        requestor_id: String,
        start_date: NaiveDate,
        end_date: NaiveDate,
    ) -> Result<PolicyException, PolicyError> {
        // Verify policy exists
        let _ = self.get_policy(policy_id).await?
            .ok_or(PolicyError::NotFound)?;

        let exception_id = uuid::Uuid::new_v4().to_string();
        let now = Utc::now();
        let now_str = now.to_rfc3339();

        let exception = PolicyException {
            id: exception_id.clone(),
            policy_id: policy_id.to_string(),
            title: title.clone(),
            description: description.clone(),
            justification: justification.clone(),
            risk_accepted: None,
            compensating_controls: None,
            requestor_id: requestor_id.clone(),
            approver_id: None,
            status: ExceptionStatus::Pending,
            start_date,
            end_date,
            created_at: now,
        };

        sqlx::query(
            "INSERT INTO policy_exceptions (id, policy_id, title, description, justification, risk_accepted, compensating_controls, requestor_id, approver_id, status, start_date, end_date, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)"
        )
        .bind(&exception_id)
        .bind(policy_id)
        .bind(&title)
        .bind(&description)
        .bind(&justification)
        .bind(None::<String>)
        .bind(None::<String>)
        .bind(&requestor_id)
        .bind(None::<String>)
        .bind("pending")
        .bind(start_date.to_string())
        .bind(end_date.to_string())
        .bind(&now_str)
        .execute(&self.pool)
        .await
        .map_err(|e| PolicyError::DatabaseError(e.to_string()))?;

        Ok(exception)
    }

    /// Approve or reject exception
    pub async fn decide_exception(
        &self,
        exception_id: &str,
        approver_id: String,
        approved: bool,
        risk_accepted: Option<String>,
        compensating_controls: Option<String>,
    ) -> Result<PolicyException, PolicyError> {
        let row = sqlx::query_as::<_, ExceptionRow>(
            "SELECT id, policy_id, title, description, justification, risk_accepted, compensating_controls, requestor_id, approver_id, status, start_date, end_date, created_at
             FROM policy_exceptions WHERE id = ?1"
        )
        .bind(exception_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| PolicyError::DatabaseError(e.to_string()))?
        .ok_or(PolicyError::NotFound)?;

        let new_status = if approved { "approved" } else { "rejected" };

        sqlx::query(
            "UPDATE policy_exceptions SET approver_id = ?1, status = ?2, risk_accepted = ?3, compensating_controls = ?4 WHERE id = ?5"
        )
        .bind(&approver_id)
        .bind(new_status)
        .bind(&risk_accepted)
        .bind(&compensating_controls)
        .bind(exception_id)
        .execute(&self.pool)
        .await
        .map_err(|e| PolicyError::DatabaseError(e.to_string()))?;

        Ok(PolicyException {
            id: row.id,
            policy_id: row.policy_id,
            title: row.title,
            description: row.description,
            justification: row.justification,
            risk_accepted,
            compensating_controls,
            requestor_id: row.requestor_id,
            approver_id: Some(approver_id),
            status: if approved { ExceptionStatus::Approved } else { ExceptionStatus::Rejected },
            start_date: parse_naive_date(&row.start_date),
            end_date: parse_naive_date(&row.end_date),
            created_at: parse_datetime(&row.created_at),
        })
    }

    /// Get policy by ID
    pub async fn get_policy(&self, policy_id: &str) -> Result<Option<Policy>, PolicyError> {
        let row = sqlx::query_as::<_, PolicyRow>(
            "SELECT id, policy_number, title, category, status, version, content, summary, owner_id, effective_date, review_date, expiry_date, parent_policy_id, requires_acknowledgment, created_at, updated_at
             FROM policies WHERE id = ?1"
        )
        .bind(policy_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| PolicyError::DatabaseError(e.to_string()))?;

        Ok(row.map(|r| r.into_policy()))
    }

    /// List all policies with optional filters
    pub async fn list_policies(
        &self,
        category: Option<PolicyCategory>,
        status: Option<PolicyStatus>,
    ) -> Result<Vec<Policy>, PolicyError> {
        let mut query = String::from(
            "SELECT id, policy_number, title, category, status, version, content, summary, owner_id, effective_date, review_date, expiry_date, parent_policy_id, requires_acknowledgment, created_at, updated_at FROM policies WHERE 1=1"
        );
        let mut binds: Vec<String> = Vec::new();

        if let Some(ref cat) = category {
            binds.push(cat.to_string());
            query.push_str(&format!(" AND category = ?{}", binds.len()));
        }
        if let Some(ref st) = status {
            binds.push(st.to_string());
            query.push_str(&format!(" AND status = ?{}", binds.len()));
        }

        query.push_str(" ORDER BY updated_at DESC");

        let mut q = sqlx::query_as::<_, PolicyRow>(&query);
        for b in &binds {
            q = q.bind(b);
        }

        let rows = q.fetch_all(&self.pool)
            .await
            .map_err(|e| PolicyError::DatabaseError(e.to_string()))?;

        Ok(rows.into_iter().map(|r| r.into_policy()).collect())
    }

    /// Get policy versions
    pub async fn get_versions(&self, policy_id: &str) -> Result<Vec<PolicyVersion>, PolicyError> {
        let rows = sqlx::query_as::<_, VersionRow>(
            "SELECT id, policy_id, version, content, change_summary, created_by, created_at
             FROM policy_versions WHERE policy_id = ?1 ORDER BY created_at ASC"
        )
        .bind(policy_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| PolicyError::DatabaseError(e.to_string()))?;

        Ok(rows.into_iter().map(|r| r.into_version()).collect())
    }

    /// Get acknowledgments for a policy
    pub async fn get_acknowledgments(&self, policy_id: &str) -> Result<Vec<PolicyAcknowledgment>, PolicyError> {
        let rows = sqlx::query_as::<_, AcknowledgmentRow>(
            "SELECT id, policy_id, user_id, version, acknowledged_at, ip_address
             FROM policy_acknowledgments WHERE policy_id = ?1 ORDER BY acknowledged_at ASC"
        )
        .bind(policy_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| PolicyError::DatabaseError(e.to_string()))?;

        Ok(rows.into_iter().map(|r| r.into_acknowledgment()).collect())
    }

    /// Get exceptions for a policy
    pub async fn get_exceptions(&self, policy_id: &str) -> Result<Vec<PolicyException>, PolicyError> {
        let rows = sqlx::query_as::<_, ExceptionRow>(
            "SELECT id, policy_id, title, description, justification, risk_accepted, compensating_controls, requestor_id, approver_id, status, start_date, end_date, created_at
             FROM policy_exceptions WHERE policy_id = ?1 ORDER BY created_at DESC"
        )
        .bind(policy_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| PolicyError::DatabaseError(e.to_string()))?;

        Ok(rows.into_iter().map(|r| r.into_exception()).collect())
    }

    /// Calculate acknowledgment compliance rate
    pub async fn calculate_acknowledgment_compliance(
        &self,
        policy_id: &str,
        total_users: u32,
    ) -> Result<f64, PolicyError> {
        if total_users == 0 {
            return Ok(0.0);
        }

        let count: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM policy_acknowledgments WHERE policy_id = ?1"
        )
        .bind(policy_id)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| PolicyError::DatabaseError(e.to_string()))?;

        Ok(count.0 as f64 / total_users as f64 * 100.0)
    }

    /// Retire a policy
    pub async fn retire_policy(&self, policy_id: &str) -> Result<(), PolicyError> {
        let policy = self.get_policy(policy_id).await?
            .ok_or(PolicyError::NotFound)?;

        let now_str = Utc::now().to_rfc3339();
        sqlx::query("UPDATE policies SET status = 'retired', updated_at = ?1 WHERE id = ?2")
            .bind(&now_str)
            .bind(policy_id)
            .execute(&self.pool)
            .await
            .map_err(|e| PolicyError::DatabaseError(e.to_string()))?;

        Ok(())
    }
}

// ============================================================================
// Database Row Types
// ============================================================================

#[derive(Debug, sqlx::FromRow)]
struct PolicyRow {
    id: String,
    policy_number: String,
    title: String,
    category: String,
    status: String,
    version: String,
    content: String,
    summary: Option<String>,
    owner_id: String,
    effective_date: Option<String>,
    review_date: Option<String>,
    expiry_date: Option<String>,
    parent_policy_id: Option<String>,
    requires_acknowledgment: bool,
    created_at: String,
    updated_at: String,
}

impl PolicyRow {
    fn into_policy(self) -> Policy {
        Policy {
            id: self.id,
            policy_number: self.policy_number,
            title: self.title,
            category: parse_policy_category(&self.category),
            status: parse_policy_status(&self.status),
            version: self.version,
            content: self.content,
            summary: self.summary,
            owner_id: self.owner_id,
            effective_date: self.effective_date.as_deref().and_then(|s| parse_naive_date_opt(s)),
            review_date: self.review_date.as_deref().and_then(|s| parse_naive_date_opt(s)),
            expiry_date: self.expiry_date.as_deref().and_then(|s| parse_naive_date_opt(s)),
            parent_policy_id: self.parent_policy_id,
            requires_acknowledgment: self.requires_acknowledgment,
            created_at: parse_datetime(&self.created_at),
            updated_at: parse_datetime(&self.updated_at),
        }
    }
}

#[derive(Debug, sqlx::FromRow)]
struct VersionRow {
    id: String,
    policy_id: String,
    version: String,
    content: String,
    change_summary: Option<String>,
    created_by: String,
    created_at: String,
}

impl VersionRow {
    fn into_version(self) -> PolicyVersion {
        PolicyVersion {
            id: self.id,
            policy_id: self.policy_id,
            version: self.version,
            content: self.content,
            change_summary: self.change_summary,
            created_by: self.created_by,
            created_at: parse_datetime(&self.created_at),
        }
    }
}

#[derive(Debug, sqlx::FromRow)]
struct ApprovalRow {
    id: String,
    policy_id: String,
    version: String,
    approver_id: String,
    status: String,
    comments: Option<String>,
    decided_at: Option<String>,
    created_at: String,
}

#[derive(Debug, sqlx::FromRow)]
struct AcknowledgmentRow {
    id: String,
    policy_id: String,
    user_id: String,
    version: String,
    acknowledged_at: String,
    ip_address: Option<String>,
}

impl AcknowledgmentRow {
    fn into_acknowledgment(self) -> PolicyAcknowledgment {
        PolicyAcknowledgment {
            id: self.id,
            policy_id: self.policy_id,
            user_id: self.user_id,
            version: self.version,
            acknowledged_at: parse_datetime(&self.acknowledged_at),
            ip_address: self.ip_address,
        }
    }
}

#[derive(Debug, sqlx::FromRow)]
struct ExceptionRow {
    id: String,
    policy_id: String,
    title: String,
    description: String,
    justification: String,
    risk_accepted: Option<String>,
    compensating_controls: Option<String>,
    requestor_id: String,
    approver_id: Option<String>,
    status: String,
    start_date: String,
    end_date: String,
    created_at: String,
}

impl ExceptionRow {
    fn into_exception(self) -> PolicyException {
        PolicyException {
            id: self.id,
            policy_id: self.policy_id,
            title: self.title,
            description: self.description,
            justification: self.justification,
            risk_accepted: self.risk_accepted,
            compensating_controls: self.compensating_controls,
            requestor_id: self.requestor_id,
            approver_id: self.approver_id,
            status: parse_exception_status(&self.status),
            start_date: parse_naive_date(&self.start_date),
            end_date: parse_naive_date(&self.end_date),
            created_at: parse_datetime(&self.created_at),
        }
    }
}

// ============================================================================
// Parser Helpers
// ============================================================================

fn parse_datetime(s: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now())
}

fn parse_naive_date(s: &str) -> NaiveDate {
    NaiveDate::parse_from_str(s, "%Y-%m-%d")
        .unwrap_or_else(|_| Utc::now().date_naive())
}

fn parse_naive_date_opt(s: &str) -> Option<NaiveDate> {
    NaiveDate::parse_from_str(s, "%Y-%m-%d").ok()
}

fn parse_policy_status(s: &str) -> PolicyStatus {
    match s {
        "draft" => PolicyStatus::Draft,
        "pending_review" => PolicyStatus::PendingReview,
        "pending_approval" => PolicyStatus::PendingApproval,
        "approved" => PolicyStatus::Approved,
        "retired" => PolicyStatus::Retired,
        _ => PolicyStatus::Draft,
    }
}

fn parse_policy_category(s: &str) -> PolicyCategory {
    match s {
        "information_security" => PolicyCategory::InformationSecurity,
        "acceptable_use" => PolicyCategory::AcceptableUse,
        "data_protection" => PolicyCategory::DataProtection,
        "incident_response" => PolicyCategory::IncidentResponse,
        "access_control" => PolicyCategory::AccessControl,
        "business_continuity" => PolicyCategory::BusinessContinuity,
        "change_management" => PolicyCategory::ChangeManagement,
        "vendor_management" => PolicyCategory::VendorManagement,
        "compliance" => PolicyCategory::Compliance,
        "privacy" => PolicyCategory::Privacy,
        "physical_security" => PolicyCategory::PhysicalSecurity,
        "human_resources" => PolicyCategory::HumanResources,
        _ => PolicyCategory::InformationSecurity,
    }
}

fn parse_exception_status(s: &str) -> ExceptionStatus {
    match s {
        "pending" => ExceptionStatus::Pending,
        "approved" => ExceptionStatus::Approved,
        "rejected" => ExceptionStatus::Rejected,
        "expired" => ExceptionStatus::Expired,
        _ => ExceptionStatus::Pending,
    }
}

// ============================================================================
// Error Type
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PolicyError {
    NotFound,
    InvalidStatus(String),
    AlreadyAcknowledged,
    ValidationError(String),
    DatabaseError(String),
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => write!(f, "Policy not found"),
            Self::InvalidStatus(msg) => write!(f, "Invalid status: {}", msg),
            Self::AlreadyAcknowledged => write!(f, "Policy already acknowledged"),
            Self::ValidationError(msg) => write!(f, "Validation error: {}", msg),
            Self::DatabaseError(msg) => write!(f, "Database error: {}", msg),
        }
    }
}

impl std::error::Error for PolicyError {}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::sqlite::SqlitePoolOptions;

    async fn test_pool() -> SqlitePool {
        SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn test_create_policy() {
        let pool = test_pool().await;
        let manager = PolicyManager::new(pool).await.unwrap();

        let policy = manager.create_policy(
            "Information Security Policy".to_string(),
            PolicyCategory::InformationSecurity,
            "# InfoSec Policy\n\nContent here.".to_string(),
            "owner-1".to_string(),
        ).await.unwrap();

        assert_eq!(policy.status, PolicyStatus::Draft);
        assert_eq!(policy.version, "1.0");
        assert!(policy.policy_number.starts_with("POL-"));

        // Verify persistence
        let fetched = manager.get_policy(&policy.id).await.unwrap().unwrap();
        assert_eq!(fetched.title, "Information Security Policy");
    }

    #[tokio::test]
    async fn test_update_policy_version() {
        let pool = test_pool().await;
        let manager = PolicyManager::new(pool).await.unwrap();

        let policy = manager.create_policy(
            "Test Policy".to_string(),
            PolicyCategory::AcceptableUse,
            "Version 1 content".to_string(),
            "owner-1".to_string(),
        ).await.unwrap();

        let new_version = manager.update_policy(
            &policy.id,
            "Version 2 content".to_string(),
            Some("Updated wording".to_string()),
            "editor-1".to_string(),
        ).await.unwrap();

        assert_eq!(new_version.version, "1.1");

        let versions = manager.get_versions(&policy.id).await.unwrap();
        assert_eq!(versions.len(), 2);
        assert_eq!(versions[0].version, "1.0");
        assert_eq!(versions[1].version, "1.1");
    }

    #[tokio::test]
    async fn test_policy_lifecycle() {
        let pool = test_pool().await;
        let manager = PolicyManager::new(pool).await.unwrap();

        let policy = manager.create_policy(
            "Security Policy".to_string(),
            PolicyCategory::InformationSecurity,
            "Content".to_string(),
            "user-1".to_string(),
        ).await.unwrap();

        // Submit for review
        manager.submit_for_review(&policy.id).await.unwrap();
        let p = manager.get_policy(&policy.id).await.unwrap().unwrap();
        assert_eq!(p.status, PolicyStatus::PendingReview);

        // Submit for approval
        let approvals = manager.submit_for_approval(
            &policy.id,
            vec!["approver-1".to_string()],
        ).await.unwrap();
        assert_eq!(approvals.len(), 1);
        assert_eq!(approvals[0].status, ApprovalStatus::Pending);

        let p = manager.get_policy(&policy.id).await.unwrap().unwrap();
        assert_eq!(p.status, PolicyStatus::PendingApproval);

        // Approve
        let result = manager.decide_approval(&approvals[0].id, true, Some("LGTM".to_string())).await.unwrap();
        assert_eq!(result.status, ApprovalStatus::Approved);

        let p = manager.get_policy(&policy.id).await.unwrap().unwrap();
        assert_eq!(p.status, PolicyStatus::Approved);
        assert!(p.effective_date.is_some());
    }

    #[tokio::test]
    async fn test_approval_rejection() {
        let pool = test_pool().await;
        let manager = PolicyManager::new(pool).await.unwrap();

        let policy = manager.create_policy(
            "Bad Policy".to_string(),
            PolicyCategory::DataProtection,
            "Content".to_string(),
            "user-1".to_string(),
        ).await.unwrap();

        manager.submit_for_review(&policy.id).await.unwrap();
        let approvals = manager.submit_for_approval(
            &policy.id,
            vec!["approver-1".to_string()],
        ).await.unwrap();

        // Reject
        manager.decide_approval(&approvals[0].id, false, Some("Needs rework".to_string())).await.unwrap();

        let p = manager.get_policy(&policy.id).await.unwrap().unwrap();
        assert_eq!(p.status, PolicyStatus::Draft); // Back to draft
    }

    #[tokio::test]
    async fn test_acknowledgment() {
        let pool = test_pool().await;
        let manager = PolicyManager::new(pool).await.unwrap();

        let policy = manager.create_policy(
            "Ack Policy".to_string(),
            PolicyCategory::AcceptableUse,
            "Content".to_string(),
            "user-1".to_string(),
        ).await.unwrap();

        // Can't acknowledge a draft
        let result = manager.acknowledge_policy(&policy.id, "user-2".to_string(), None).await;
        assert!(result.is_err());

        // Approve it first
        manager.submit_for_review(&policy.id).await.unwrap();
        let approvals = manager.submit_for_approval(&policy.id, vec!["approver-1".to_string()]).await.unwrap();
        manager.decide_approval(&approvals[0].id, true, None).await.unwrap();

        // Now acknowledge
        let ack = manager.acknowledge_policy(
            &policy.id,
            "user-2".to_string(),
            Some("192.168.1.1".to_string()),
        ).await.unwrap();
        assert_eq!(ack.user_id, "user-2");
        assert_eq!(ack.ip_address, Some("192.168.1.1".to_string()));

        // Can't acknowledge twice
        let result = manager.acknowledge_policy(&policy.id, "user-2".to_string(), None).await;
        assert!(result.is_err());

        // Compliance rate
        let rate = manager.calculate_acknowledgment_compliance(&policy.id, 10).await.unwrap();
        assert!((rate - 10.0).abs() < 0.01); // 1/10 = 10%
    }

    #[tokio::test]
    async fn test_exception_lifecycle() {
        let pool = test_pool().await;
        let manager = PolicyManager::new(pool).await.unwrap();

        let policy = manager.create_policy(
            "Strict Policy".to_string(),
            PolicyCategory::AccessControl,
            "Content".to_string(),
            "user-1".to_string(),
        ).await.unwrap();

        let exception = manager.create_exception(
            &policy.id,
            "Temporary exception".to_string(),
            "Need legacy system access".to_string(),
            "Migration in progress".to_string(),
            "requestor-1".to_string(),
            NaiveDate::from_ymd_opt(2025, 1, 1).unwrap(),
            NaiveDate::from_ymd_opt(2025, 6, 30).unwrap(),
        ).await.unwrap();

        assert_eq!(exception.status, ExceptionStatus::Pending);

        // Approve exception
        let decided = manager.decide_exception(
            &exception.id,
            "approver-1".to_string(),
            true,
            Some("Risk accepted for migration period".to_string()),
            Some("VPN-only access, audit logging".to_string()),
        ).await.unwrap();

        assert_eq!(decided.status, ExceptionStatus::Approved);
        assert_eq!(decided.approver_id, Some("approver-1".to_string()));
        assert!(decided.risk_accepted.is_some());
        assert!(decided.compensating_controls.is_some());

        // Verify in list
        let exceptions = manager.get_exceptions(&policy.id).await.unwrap();
        assert_eq!(exceptions.len(), 1);
    }

    #[tokio::test]
    async fn test_list_policies_with_filters() {
        let pool = test_pool().await;
        let manager = PolicyManager::new(pool).await.unwrap();

        manager.create_policy(
            "Policy A".to_string(),
            PolicyCategory::InformationSecurity,
            "Content A".to_string(),
            "user-1".to_string(),
        ).await.unwrap();

        manager.create_policy(
            "Policy B".to_string(),
            PolicyCategory::DataProtection,
            "Content B".to_string(),
            "user-1".to_string(),
        ).await.unwrap();

        let all = manager.list_policies(None, None).await.unwrap();
        assert_eq!(all.len(), 2);

        let infosec = manager.list_policies(Some(PolicyCategory::InformationSecurity), None).await.unwrap();
        assert_eq!(infosec.len(), 1);
        assert_eq!(infosec[0].title, "Policy A");

        let drafts = manager.list_policies(None, Some(PolicyStatus::Draft)).await.unwrap();
        assert_eq!(drafts.len(), 2);
    }

    #[tokio::test]
    async fn test_retire_policy() {
        let pool = test_pool().await;
        let manager = PolicyManager::new(pool).await.unwrap();

        let policy = manager.create_policy(
            "Old Policy".to_string(),
            PolicyCategory::Privacy,
            "Content".to_string(),
            "user-1".to_string(),
        ).await.unwrap();

        manager.retire_policy(&policy.id).await.unwrap();
        let p = manager.get_policy(&policy.id).await.unwrap().unwrap();
        assert_eq!(p.status, PolicyStatus::Retired);
    }

    #[tokio::test]
    async fn test_cannot_update_non_draft() {
        let pool = test_pool().await;
        let manager = PolicyManager::new(pool).await.unwrap();

        let policy = manager.create_policy(
            "Policy".to_string(),
            PolicyCategory::Compliance,
            "Content".to_string(),
            "user-1".to_string(),
        ).await.unwrap();

        // Move to pending review
        manager.submit_for_review(&policy.id).await.unwrap();

        // Try to update - should fail
        let result = manager.update_policy(
            &policy.id,
            "New content".to_string(),
            None,
            "user-1".to_string(),
        ).await;

        assert!(result.is_err());
    }
}
