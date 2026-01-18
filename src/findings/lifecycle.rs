//! Finding Lifecycle Management
//!
//! Manages the lifecycle states of security findings from discovery to closure.
//!
//! States:
//! - Discovered: Initial state when finding is first detected
//! - Triaged: Finding has been reviewed and prioritized
//! - Acknowledged: Client/owner has acknowledged the finding
//! - InRemediation: Remediation work is in progress
//! - VerificationPending: Fix applied, awaiting verification
//! - Verified: Fix has been verified
//! - Closed: Finding is resolved and closed
//! - FalsePositive: Marked as false positive
//! - Accepted: Risk accepted, no remediation planned

use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use anyhow::Result;
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Finding lifecycle states
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingState {
    /// Initial state when finding is first detected
    Discovered,
    /// Finding has been reviewed and prioritized
    Triaged,
    /// Client/owner has acknowledged the finding
    Acknowledged,
    /// Remediation work is in progress
    InRemediation,
    /// Fix applied, awaiting verification
    VerificationPending,
    /// Fix has been verified
    Verified,
    /// Finding is resolved and closed
    Closed,
    /// Marked as false positive
    FalsePositive,
    /// Risk accepted, no remediation planned
    RiskAccepted,
}

impl FindingState {
    /// Get display name for the state
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Discovered => "Discovered",
            Self::Triaged => "Triaged",
            Self::Acknowledged => "Acknowledged",
            Self::InRemediation => "In Remediation",
            Self::VerificationPending => "Verification Pending",
            Self::Verified => "Verified",
            Self::Closed => "Closed",
            Self::FalsePositive => "False Positive",
            Self::RiskAccepted => "Risk Accepted",
        }
    }

    /// Get description of the state
    pub fn description(&self) -> &'static str {
        match self {
            Self::Discovered => "Finding has been detected by the scanner",
            Self::Triaged => "Finding has been reviewed and assigned priority",
            Self::Acknowledged => "The finding has been acknowledged by the responsible party",
            Self::InRemediation => "Work is actively being done to remediate the finding",
            Self::VerificationPending => "A fix has been applied and is awaiting verification",
            Self::Verified => "The fix has been verified as effective",
            Self::Closed => "The finding has been fully resolved",
            Self::FalsePositive => "The finding has been determined to be a false positive",
            Self::RiskAccepted => "The risk has been accepted without remediation",
        }
    }

    /// Get valid transitions from this state
    pub fn valid_transitions(&self) -> Vec<FindingState> {
        match self {
            Self::Discovered => vec![
                Self::Triaged,
                Self::FalsePositive,
            ],
            Self::Triaged => vec![
                Self::Acknowledged,
                Self::InRemediation,
                Self::FalsePositive,
                Self::RiskAccepted,
            ],
            Self::Acknowledged => vec![
                Self::InRemediation,
                Self::RiskAccepted,
            ],
            Self::InRemediation => vec![
                Self::VerificationPending,
                Self::Acknowledged, // Can go back if remediation blocked
            ],
            Self::VerificationPending => vec![
                Self::Verified,
                Self::InRemediation, // Verification failed, back to remediation
            ],
            Self::Verified => vec![
                Self::Closed,
                Self::InRemediation, // Reopened
            ],
            Self::Closed => vec![
                Self::Discovered, // Reopened if issue reappears
            ],
            Self::FalsePositive => vec![
                Self::Discovered, // Revisit the finding
            ],
            Self::RiskAccepted => vec![
                Self::InRemediation, // Decided to remediate after all
                Self::Closed,
            ],
        }
    }

    /// Check if transition to target state is valid
    pub fn can_transition_to(&self, target: FindingState) -> bool {
        self.valid_transitions().contains(&target)
    }

    /// Check if this is a terminal state
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Closed | Self::FalsePositive)
    }

    /// Check if this state counts as "open"
    pub fn is_open(&self) -> bool {
        !matches!(self, Self::Closed | Self::FalsePositive | Self::RiskAccepted | Self::Verified)
    }

    /// Parse from string
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().replace('_', "").replace('-', "").as_str() {
            "discovered" | "new" | "open" => Some(Self::Discovered),
            "triaged" | "reviewed" => Some(Self::Triaged),
            "acknowledged" | "ack" => Some(Self::Acknowledged),
            "inremediation" | "remediation" | "fixing" => Some(Self::InRemediation),
            "verificationpending" | "verification" | "pending" => Some(Self::VerificationPending),
            "verified" | "fixed" => Some(Self::Verified),
            "closed" | "resolved" => Some(Self::Closed),
            "falsepositive" | "fp" => Some(Self::FalsePositive),
            "riskaccepted" | "accepted" => Some(Self::RiskAccepted),
            _ => None,
        }
    }
}

impl std::fmt::Display for FindingState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

/// State transition record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateTransition {
    pub id: String,
    pub finding_id: String,
    pub from_state: FindingState,
    pub to_state: FindingState,
    pub transitioned_by: String,
    pub transitioned_at: DateTime<Utc>,
    pub reason: Option<String>,
    pub notes: Option<String>,
}

/// Finding lifecycle record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingLifecycle {
    pub finding_id: String,
    pub current_state: FindingState,
    pub first_discovered_at: DateTime<Utc>,
    pub last_state_change: DateTime<Utc>,
    pub state_history: Vec<StateTransition>,
    pub assignee: Option<String>,
    pub due_date: Option<DateTime<Utc>>,
    pub sla_breach: bool,
    pub retest_count: i32,
}

impl FindingLifecycle {
    /// Create a new lifecycle for a discovered finding
    pub fn new(finding_id: &str) -> Self {
        let now = Utc::now();
        Self {
            finding_id: finding_id.to_string(),
            current_state: FindingState::Discovered,
            first_discovered_at: now,
            last_state_change: now,
            state_history: Vec::new(),
            assignee: None,
            due_date: None,
            sla_breach: false,
            retest_count: 0,
        }
    }

    /// Transition to a new state
    pub fn transition(&mut self, to_state: FindingState, by: &str, reason: Option<String>, notes: Option<String>) -> Result<()> {
        if !self.current_state.can_transition_to(to_state) {
            return Err(anyhow::anyhow!(
                "Invalid transition from {} to {}",
                self.current_state.display_name(),
                to_state.display_name()
            ));
        }

        let now = Utc::now();
        let transition = StateTransition {
            id: Uuid::new_v4().to_string(),
            finding_id: self.finding_id.clone(),
            from_state: self.current_state,
            to_state,
            transitioned_by: by.to_string(),
            transitioned_at: now,
            reason,
            notes,
        };

        // Track retests
        if self.current_state == FindingState::VerificationPending && to_state == FindingState::InRemediation {
            self.retest_count += 1;
        }

        self.state_history.push(transition);
        self.current_state = to_state;
        self.last_state_change = now;

        Ok(())
    }

    /// Get time in current state
    pub fn time_in_current_state(&self) -> chrono::Duration {
        Utc::now().signed_duration_since(self.last_state_change)
    }

    /// Get total time since discovery
    pub fn total_age(&self) -> chrono::Duration {
        Utc::now().signed_duration_since(self.first_discovered_at)
    }

    /// Check if SLA is breached
    pub fn check_sla(&self, max_days: i64) -> bool {
        if let Some(due) = self.due_date {
            Utc::now() > due
        } else {
            self.total_age().num_days() > max_days
        }
    }
}

/// SLA configuration by severity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlAConfig {
    /// Days to remediate critical findings
    pub critical_days: i64,
    /// Days to remediate high findings
    pub high_days: i64,
    /// Days to remediate medium findings
    pub medium_days: i64,
    /// Days to remediate low findings
    pub low_days: i64,
    /// Days to remediate informational findings
    pub info_days: i64,
}

impl Default for SlAConfig {
    fn default() -> Self {
        Self {
            critical_days: 7,
            high_days: 30,
            medium_days: 90,
            low_days: 180,
            info_days: 365,
        }
    }
}

impl SlAConfig {
    /// Get SLA days for a severity level
    pub fn days_for_severity(&self, severity: &str) -> i64 {
        match severity.to_lowercase().as_str() {
            "critical" => self.critical_days,
            "high" => self.high_days,
            "medium" => self.medium_days,
            "low" => self.low_days,
            _ => self.info_days,
        }
    }
}

/// Lifecycle manager for batch operations
pub struct LifecycleManager {
    pool: SqlitePool,
    sla_config: SlAConfig,
}

impl LifecycleManager {
    pub fn new(pool: SqlitePool) -> Self {
        Self {
            pool,
            sla_config: SlAConfig::default(),
        }
    }

    pub fn with_sla_config(pool: SqlitePool, sla_config: SlAConfig) -> Self {
        Self { pool, sla_config }
    }

    /// Initialize lifecycle for a new finding
    pub async fn init_finding(&self, finding_id: &str, severity: &str) -> Result<FindingLifecycle> {
        let mut lifecycle = FindingLifecycle::new(finding_id);

        // Set due date based on SLA
        let sla_days = self.sla_config.days_for_severity(severity);
        lifecycle.due_date = Some(Utc::now() + chrono::Duration::days(sla_days));

        self.save_lifecycle(&lifecycle).await?;
        Ok(lifecycle)
    }

    /// Transition a finding to a new state
    pub async fn transition_finding(
        &self,
        finding_id: &str,
        to_state: FindingState,
        by: &str,
        reason: Option<String>,
        notes: Option<String>,
    ) -> Result<FindingLifecycle> {
        let mut lifecycle = self.get_lifecycle(finding_id).await?
            .ok_or_else(|| anyhow::anyhow!("Finding lifecycle not found"))?;

        lifecycle.transition(to_state, by, reason, notes)?;
        self.save_lifecycle(&lifecycle).await?;
        self.save_transition(lifecycle.state_history.last().unwrap()).await?;

        Ok(lifecycle)
    }

    /// Bulk transition findings
    pub async fn bulk_transition(
        &self,
        finding_ids: &[String],
        to_state: FindingState,
        by: &str,
        reason: Option<String>,
    ) -> Result<Vec<(String, Result<FindingLifecycle>)>> {
        let mut results = Vec::new();

        for finding_id in finding_ids {
            let result = self.transition_finding(finding_id, to_state, by, reason.clone(), None).await;
            results.push((finding_id.clone(), result));
        }

        Ok(results)
    }

    /// Get findings by state
    pub async fn get_findings_by_state(&self, state: FindingState) -> Result<Vec<FindingLifecycle>> {
        let state_str = format!("{:?}", state).to_lowercase();
        let rows = sqlx::query_as::<_, (String, String, String, String, Option<String>, Option<String>, bool, i32)>(
            r#"SELECT finding_id, current_state, first_discovered_at, last_state_change,
                      assignee, due_date, sla_breach, retest_count
               FROM finding_lifecycles WHERE current_state = ?"#
        )
        .bind(&state_str)
        .fetch_all(&self.pool)
        .await?;

        let mut lifecycles = Vec::new();
        for (finding_id, _current_state, first_discovered, last_change, assignee, due_date, sla_breach, retest_count) in rows {
            let history = self.get_transition_history(&finding_id).await?;
            lifecycles.push(FindingLifecycle {
                finding_id,
                current_state: state,
                first_discovered_at: DateTime::parse_from_rfc3339(&first_discovered)?.with_timezone(&Utc),
                last_state_change: DateTime::parse_from_rfc3339(&last_change)?.with_timezone(&Utc),
                state_history: history,
                assignee,
                due_date: due_date.map(|d| DateTime::parse_from_rfc3339(&d).ok().map(|dt| dt.with_timezone(&Utc))).flatten(),
                sla_breach,
                retest_count,
            });
        }

        Ok(lifecycles)
    }

    /// Get SLA breached findings
    pub async fn get_sla_breached(&self) -> Result<Vec<FindingLifecycle>> {
        let rows = sqlx::query_as::<_, (String, String, String, String, Option<String>, Option<String>, bool, i32)>(
            r#"SELECT finding_id, current_state, first_discovered_at, last_state_change,
                      assignee, due_date, sla_breach, retest_count
               FROM finding_lifecycles WHERE sla_breach = 1 AND current_state NOT IN ('closed', 'false_positive', 'risk_accepted')"#
        )
        .fetch_all(&self.pool)
        .await?;

        let mut lifecycles = Vec::new();
        for (finding_id, current_state, first_discovered, last_change, assignee, due_date, sla_breach, retest_count) in rows {
            let state = FindingState::from_str(&current_state).unwrap_or(FindingState::Discovered);
            let history = self.get_transition_history(&finding_id).await?;
            lifecycles.push(FindingLifecycle {
                finding_id,
                current_state: state,
                first_discovered_at: DateTime::parse_from_rfc3339(&first_discovered)?.with_timezone(&Utc),
                last_state_change: DateTime::parse_from_rfc3339(&last_change)?.with_timezone(&Utc),
                state_history: history,
                assignee,
                due_date: due_date.map(|d| DateTime::parse_from_rfc3339(&d).ok().map(|dt| dt.with_timezone(&Utc))).flatten(),
                sla_breach,
                retest_count,
            });
        }

        Ok(lifecycles)
    }

    /// Update SLA breach status for all findings
    pub async fn update_sla_status(&self) -> Result<i32> {
        let now = Utc::now().to_rfc3339();
        let result = sqlx::query(
            r#"UPDATE finding_lifecycles
               SET sla_breach = 1
               WHERE due_date IS NOT NULL AND due_date < ?
               AND current_state NOT IN ('closed', 'false_positive', 'risk_accepted', 'verified')
               AND sla_breach = 0"#
        )
        .bind(&now)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() as i32)
    }

    /// Get lifecycle metrics
    pub async fn get_metrics(&self) -> Result<LifecycleMetrics> {
        let total = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM finding_lifecycles")
            .fetch_one(&self.pool)
            .await?;

        let open = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM finding_lifecycles WHERE current_state NOT IN ('closed', 'false_positive', 'risk_accepted', 'verified')"
        )
        .fetch_one(&self.pool)
        .await?;

        let closed = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM finding_lifecycles WHERE current_state = 'closed'"
        )
        .fetch_one(&self.pool)
        .await?;

        let sla_breached = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM finding_lifecycles WHERE sla_breach = 1 AND current_state NOT IN ('closed', 'false_positive', 'risk_accepted', 'verified')"
        )
        .fetch_one(&self.pool)
        .await?;

        let false_positives = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM finding_lifecycles WHERE current_state = 'false_positive'"
        )
        .fetch_one(&self.pool)
        .await?;

        let by_state = sqlx::query_as::<_, (String, i64)>(
            "SELECT current_state, COUNT(*) FROM finding_lifecycles GROUP BY current_state"
        )
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .collect();

        Ok(LifecycleMetrics {
            total,
            open,
            closed,
            sla_breached,
            false_positives,
            by_state,
        })
    }

    // Database helpers

    async fn save_lifecycle(&self, lifecycle: &FindingLifecycle) -> Result<()> {
        let state_str = format!("{:?}", lifecycle.current_state).to_lowercase();
        sqlx::query(
            r#"INSERT INTO finding_lifecycles
               (finding_id, current_state, first_discovered_at, last_state_change, assignee, due_date, sla_breach, retest_count)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(finding_id) DO UPDATE SET
               current_state = excluded.current_state,
               last_state_change = excluded.last_state_change,
               assignee = excluded.assignee,
               due_date = excluded.due_date,
               sla_breach = excluded.sla_breach,
               retest_count = excluded.retest_count"#
        )
        .bind(&lifecycle.finding_id)
        .bind(&state_str)
        .bind(lifecycle.first_discovered_at.to_rfc3339())
        .bind(lifecycle.last_state_change.to_rfc3339())
        .bind(&lifecycle.assignee)
        .bind(lifecycle.due_date.map(|d| d.to_rfc3339()))
        .bind(lifecycle.sla_breach)
        .bind(lifecycle.retest_count)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn save_transition(&self, transition: &StateTransition) -> Result<()> {
        let from_str = format!("{:?}", transition.from_state).to_lowercase();
        let to_str = format!("{:?}", transition.to_state).to_lowercase();

        sqlx::query(
            r#"INSERT INTO finding_state_transitions
               (id, finding_id, from_state, to_state, transitioned_by, transitioned_at, reason, notes)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)"#
        )
        .bind(&transition.id)
        .bind(&transition.finding_id)
        .bind(&from_str)
        .bind(&to_str)
        .bind(&transition.transitioned_by)
        .bind(transition.transitioned_at.to_rfc3339())
        .bind(&transition.reason)
        .bind(&transition.notes)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn get_lifecycle(&self, finding_id: &str) -> Result<Option<FindingLifecycle>> {
        let row = sqlx::query_as::<_, (String, String, String, String, Option<String>, Option<String>, bool, i32)>(
            r#"SELECT finding_id, current_state, first_discovered_at, last_state_change,
                      assignee, due_date, sla_breach, retest_count
               FROM finding_lifecycles WHERE finding_id = ?"#
        )
        .bind(finding_id)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some((finding_id, current_state, first_discovered, last_change, assignee, due_date, sla_breach, retest_count)) => {
                let state = FindingState::from_str(&current_state).unwrap_or(FindingState::Discovered);
                let history = self.get_transition_history(&finding_id).await?;
                Ok(Some(FindingLifecycle {
                    finding_id,
                    current_state: state,
                    first_discovered_at: DateTime::parse_from_rfc3339(&first_discovered)?.with_timezone(&Utc),
                    last_state_change: DateTime::parse_from_rfc3339(&last_change)?.with_timezone(&Utc),
                    state_history: history,
                    assignee,
                    due_date: due_date.map(|d| DateTime::parse_from_rfc3339(&d).ok().map(|dt| dt.with_timezone(&Utc))).flatten(),
                    sla_breach,
                    retest_count,
                }))
            }
            None => Ok(None),
        }
    }

    async fn get_transition_history(&self, finding_id: &str) -> Result<Vec<StateTransition>> {
        let rows = sqlx::query_as::<_, (String, String, String, String, String, String, Option<String>, Option<String>)>(
            r#"SELECT id, finding_id, from_state, to_state, transitioned_by, transitioned_at, reason, notes
               FROM finding_state_transitions WHERE finding_id = ? ORDER BY transitioned_at ASC"#
        )
        .bind(finding_id)
        .fetch_all(&self.pool)
        .await?;

        let mut history = Vec::new();
        for (id, finding_id, from_state, to_state, transitioned_by, transitioned_at, reason, notes) in rows {
            history.push(StateTransition {
                id,
                finding_id,
                from_state: FindingState::from_str(&from_state).unwrap_or(FindingState::Discovered),
                to_state: FindingState::from_str(&to_state).unwrap_or(FindingState::Discovered),
                transitioned_by,
                transitioned_at: DateTime::parse_from_rfc3339(&transitioned_at)?.with_timezone(&Utc),
                reason,
                notes,
            });
        }

        Ok(history)
    }
}

/// Lifecycle metrics
#[derive(Debug, Clone, Serialize)]
pub struct LifecycleMetrics {
    pub total: i64,
    pub open: i64,
    pub closed: i64,
    pub sla_breached: i64,
    pub false_positives: i64,
    pub by_state: std::collections::HashMap<String, i64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_transitions() {
        assert!(FindingState::Discovered.can_transition_to(FindingState::Triaged));
        assert!(FindingState::Triaged.can_transition_to(FindingState::InRemediation));
        assert!(!FindingState::Discovered.can_transition_to(FindingState::Closed));
        assert!(!FindingState::Closed.can_transition_to(FindingState::Triaged));
    }

    #[test]
    fn test_lifecycle_transition() {
        let mut lifecycle = FindingLifecycle::new("test-123");
        assert_eq!(lifecycle.current_state, FindingState::Discovered);

        lifecycle.transition(FindingState::Triaged, "user1", Some("Initial triage".to_string()), None).unwrap();
        assert_eq!(lifecycle.current_state, FindingState::Triaged);
        assert_eq!(lifecycle.state_history.len(), 1);

        lifecycle.transition(FindingState::InRemediation, "user2", None, None).unwrap();
        assert_eq!(lifecycle.current_state, FindingState::InRemediation);
        assert_eq!(lifecycle.state_history.len(), 2);
    }

    #[test]
    fn test_invalid_transition() {
        let mut lifecycle = FindingLifecycle::new("test-123");
        let result = lifecycle.transition(FindingState::Closed, "user1", None, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_sla_config() {
        let config = SlAConfig::default();
        assert_eq!(config.days_for_severity("critical"), 7);
        assert_eq!(config.days_for_severity("high"), 30);
        assert_eq!(config.days_for_severity("low"), 180);
    }

    #[test]
    fn test_state_is_open() {
        assert!(FindingState::Discovered.is_open());
        assert!(FindingState::InRemediation.is_open());
        assert!(!FindingState::Closed.is_open());
        assert!(!FindingState::FalsePositive.is_open());
    }
}
