//! Voice Phishing (Vishing) Module
//!
//! Provides vishing campaign management for voice-based social engineering
//! awareness training and authorized penetration testing.
//!
//! # Features
//!
//! - Vishing script management with call flows
//! - Campaign tracking and metrics
//! - Call outcome logging
//! - Integration with pretext templates
//! - Optional VoIP integration (Twilio Voice)
//!
//! # Security Notice
//!
//! This module is intended for:
//! - Security awareness training programs
//! - Authorized penetration testing engagements
//! - Red team assessments with proper authorization
//!
//! Unauthorized vishing is illegal. Always obtain proper authorization.

use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::collections::HashMap;
use uuid::Uuid;

use super::pretexts::{PretextCategory, PretextDifficulty, PretextScript};

/// Vishing campaign status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum VishingCampaignStatus {
    /// Campaign is being prepared
    Draft,
    /// Campaign is scheduled to start
    Scheduled,
    /// Campaign is actively being executed
    Active,
    /// Campaign is temporarily paused
    Paused,
    /// Campaign has been completed
    Completed,
    /// Campaign was cancelled
    Cancelled,
}

impl std::fmt::Display for VishingCampaignStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VishingCampaignStatus::Draft => write!(f, "draft"),
            VishingCampaignStatus::Scheduled => write!(f, "scheduled"),
            VishingCampaignStatus::Active => write!(f, "active"),
            VishingCampaignStatus::Paused => write!(f, "paused"),
            VishingCampaignStatus::Completed => write!(f, "completed"),
            VishingCampaignStatus::Cancelled => write!(f, "cancelled"),
        }
    }
}

impl std::str::FromStr for VishingCampaignStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "draft" => Ok(VishingCampaignStatus::Draft),
            "scheduled" => Ok(VishingCampaignStatus::Scheduled),
            "active" => Ok(VishingCampaignStatus::Active),
            "paused" => Ok(VishingCampaignStatus::Paused),
            "completed" => Ok(VishingCampaignStatus::Completed),
            "cancelled" => Ok(VishingCampaignStatus::Cancelled),
            _ => Err(format!("Unknown campaign status: {}", s)),
        }
    }
}

/// Call outcome types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum CallOutcome {
    /// Call was not answered
    NoAnswer,
    /// Target answered but immediately hung up
    HungUp,
    /// Target was suspicious and refused
    Suspicious,
    /// Target engaged but did not comply
    EngagedNoCompliance,
    /// Target partially complied (gave some info)
    PartialSuccess,
    /// Target fully complied with request
    FullSuccess,
    /// Target reported the call as suspicious
    Reported,
    /// Call went to voicemail
    Voicemail,
    /// Target asked to call back
    CallbackRequested,
    /// Wrong number or target unavailable
    WrongNumber,
    /// Technical issue with call
    TechnicalIssue,
}

impl std::fmt::Display for CallOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CallOutcome::NoAnswer => write!(f, "no_answer"),
            CallOutcome::HungUp => write!(f, "hung_up"),
            CallOutcome::Suspicious => write!(f, "suspicious"),
            CallOutcome::EngagedNoCompliance => write!(f, "engaged_no_compliance"),
            CallOutcome::PartialSuccess => write!(f, "partial_success"),
            CallOutcome::FullSuccess => write!(f, "full_success"),
            CallOutcome::Reported => write!(f, "reported"),
            CallOutcome::Voicemail => write!(f, "voicemail"),
            CallOutcome::CallbackRequested => write!(f, "callback_requested"),
            CallOutcome::WrongNumber => write!(f, "wrong_number"),
            CallOutcome::TechnicalIssue => write!(f, "technical_issue"),
        }
    }
}

impl std::str::FromStr for CallOutcome {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "no_answer" => Ok(CallOutcome::NoAnswer),
            "hung_up" => Ok(CallOutcome::HungUp),
            "suspicious" => Ok(CallOutcome::Suspicious),
            "engaged_no_compliance" => Ok(CallOutcome::EngagedNoCompliance),
            "partial_success" => Ok(CallOutcome::PartialSuccess),
            "full_success" => Ok(CallOutcome::FullSuccess),
            "reported" => Ok(CallOutcome::Reported),
            "voicemail" => Ok(CallOutcome::Voicemail),
            "callback_requested" => Ok(CallOutcome::CallbackRequested),
            "wrong_number" => Ok(CallOutcome::WrongNumber),
            "technical_issue" => Ok(CallOutcome::TechnicalIssue),
            _ => Err(format!("Unknown call outcome: {}", s)),
        }
    }
}

/// Vishing script with call flow and responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VishingScript {
    /// Unique identifier
    pub id: String,
    /// User ID who created the script (None for built-in)
    pub user_id: Option<String>,
    /// Script name
    pub name: String,
    /// Description of the script
    pub description: String,
    /// Category of the pretext
    pub category: PretextCategory,
    /// Difficulty level
    pub difficulty: PretextDifficulty,
    /// The scenario/persona being used
    pub persona: String,
    /// Caller ID to display (if using VoIP)
    pub caller_id: Option<String>,
    /// The actual script content
    pub script: PretextScript,
    /// Call flow stages
    pub call_flow: Vec<CallFlowStage>,
    /// Common objections and responses
    pub objection_handling: HashMap<String, String>,
    /// Red flags to watch for
    pub red_flags: Vec<String>,
    /// Success indicators
    pub success_indicators: Vec<String>,
    /// Tips for callers
    pub caller_tips: Vec<String>,
    /// Associated pretext template ID (if any)
    pub pretext_template_id: Option<String>,
    /// Whether this is a built-in script
    pub is_builtin: bool,
    /// Created timestamp
    pub created_at: DateTime<Utc>,
    /// Updated timestamp
    pub updated_at: DateTime<Utc>,
}

/// A stage in the call flow
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallFlowStage {
    /// Stage number (1-based)
    pub stage: u32,
    /// Stage name
    pub name: String,
    /// What to say at this stage
    pub script_text: String,
    /// Expected responses and how to handle them
    pub response_handlers: HashMap<String, String>,
    /// Information to gather at this stage
    pub information_to_gather: Vec<String>,
    /// Conditions to move to next stage
    pub success_criteria: Vec<String>,
    /// When to abort the call
    pub abort_conditions: Vec<String>,
}

/// Vishing campaign for tracking voice phishing attempts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VishingCampaign {
    /// Unique identifier
    pub id: String,
    /// User ID who created the campaign
    pub user_id: String,
    /// Campaign name
    pub name: String,
    /// Campaign description
    pub description: Option<String>,
    /// Current status
    pub status: VishingCampaignStatus,
    /// Script to use for calls
    pub script_id: String,
    /// Pretext template to use (optional, can use script directly)
    pub pretext_template_id: Option<String>,
    /// Caller ID to display
    pub caller_id: Option<String>,
    /// Start date
    pub start_date: Option<DateTime<Utc>>,
    /// End date
    pub end_date: Option<DateTime<Utc>>,
    /// Target organization
    pub target_organization: Option<String>,
    /// Notes and observations
    pub notes: Option<String>,
    /// Created timestamp
    pub created_at: DateTime<Utc>,
    /// Updated timestamp
    pub updated_at: DateTime<Utc>,
}

/// Summary of campaign with statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VishingCampaignSummary {
    pub id: String,
    pub name: String,
    pub status: VishingCampaignStatus,
    pub total_targets: u32,
    pub calls_attempted: u32,
    pub calls_connected: u32,
    pub successful_calls: u32,
    pub failed_calls: u32,
    pub reported_calls: u32,
    pub start_date: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// Target for a vishing campaign
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VishingTarget {
    /// Unique identifier
    pub id: String,
    /// Campaign ID
    pub campaign_id: String,
    /// Target's name
    pub name: String,
    /// Target's phone number
    pub phone_number: String,
    /// Target's email (for follow-up)
    pub email: Option<String>,
    /// Target's job title
    pub job_title: Option<String>,
    /// Target's department
    pub department: Option<String>,
    /// Notes about the target
    pub notes: Option<String>,
    /// Whether target has been called
    pub called: bool,
    /// Last call outcome
    pub last_outcome: Option<CallOutcome>,
    /// Number of call attempts
    pub attempt_count: u32,
    /// Created timestamp
    pub created_at: DateTime<Utc>,
    /// Updated timestamp
    pub updated_at: DateTime<Utc>,
}

/// Call log entry for tracking call attempts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VishingCallLog {
    /// Unique identifier
    pub id: String,
    /// Campaign ID
    pub campaign_id: String,
    /// Target ID
    pub target_id: String,
    /// Caller (operator) ID
    pub caller_id: Option<String>,
    /// Script used for the call
    pub script_id: String,
    /// Call start time
    pub started_at: DateTime<Utc>,
    /// Call end time
    pub ended_at: Option<DateTime<Utc>>,
    /// Duration in seconds
    pub duration_seconds: Option<u32>,
    /// Call outcome
    pub outcome: CallOutcome,
    /// Information gathered during call
    pub information_gathered: HashMap<String, String>,
    /// Notes from the caller
    pub notes: Option<String>,
    /// Whether target became suspicious
    pub target_suspicious: bool,
    /// Whether target asked to verify
    pub verification_requested: bool,
    /// Call flow stage reached
    pub stages_completed: u32,
    /// Created timestamp
    pub created_at: DateTime<Utc>,
}

/// Statistics for a vishing campaign
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VishingCampaignStats {
    pub total_targets: u32,
    pub calls_attempted: u32,
    pub calls_connected: u32,
    pub no_answer: u32,
    pub voicemail: u32,
    pub hung_up: u32,
    pub suspicious: u32,
    pub engaged_no_compliance: u32,
    pub partial_success: u32,
    pub full_success: u32,
    pub reported: u32,
    pub callback_requested: u32,
    pub average_call_duration: f32,
    pub success_rate: f32,
    pub connection_rate: f32,
    pub suspicion_rate: f32,
    pub reporting_rate: f32,
    pub outcomes_by_department: HashMap<String, HashMap<String, u32>>,
    pub calls_by_date: HashMap<String, u32>,
}

/// Request to create a vishing campaign
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateVishingCampaignRequest {
    pub name: String,
    pub description: Option<String>,
    pub script_id: Option<String>,
    pub pretext_template_id: Option<String>,
    pub caller_id: Option<String>,
    pub start_date: Option<DateTime<Utc>>,
    pub end_date: Option<DateTime<Utc>>,
    pub target_organization: Option<String>,
    pub targets: Vec<CreateVishingTargetRequest>,
}

/// Request to create a vishing target
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateVishingTargetRequest {
    pub name: String,
    pub phone_number: String,
    pub email: Option<String>,
    pub job_title: Option<String>,
    pub department: Option<String>,
    pub notes: Option<String>,
}

/// Request to create a vishing script
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateVishingScriptRequest {
    pub name: String,
    pub description: String,
    pub category: PretextCategory,
    pub difficulty: Option<PretextDifficulty>,
    pub persona: String,
    pub caller_id: Option<String>,
    pub script: PretextScript,
    pub call_flow: Vec<CallFlowStage>,
    pub objection_handling: Option<HashMap<String, String>>,
    pub red_flags: Option<Vec<String>>,
    pub success_indicators: Option<Vec<String>>,
    pub caller_tips: Option<Vec<String>>,
    pub pretext_template_id: Option<String>,
}

/// Request to log a call outcome
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogCallRequest {
    pub target_id: String,
    pub script_id: String,
    pub started_at: DateTime<Utc>,
    pub ended_at: Option<DateTime<Utc>>,
    pub duration_seconds: Option<u32>,
    pub outcome: CallOutcome,
    pub information_gathered: Option<HashMap<String, String>>,
    pub notes: Option<String>,
    pub target_suspicious: Option<bool>,
    pub verification_requested: Option<bool>,
    pub stages_completed: Option<u32>,
}

/// Vishing campaign manager
pub struct VishingManager {
    pool: SqlitePool,
}

impl VishingManager {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Create a new vishing campaign
    pub async fn create_campaign(
        &self,
        user_id: &str,
        request: CreateVishingCampaignRequest,
    ) -> Result<VishingCampaign> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();

        // Validate script exists if provided
        if let Some(ref script_id) = request.script_id {
            let script_exists = sqlx::query_as::<_, (i64,)>(
                "SELECT COUNT(*) FROM vishing_scripts WHERE id = ?",
            )
            .bind(script_id)
            .fetch_one(&self.pool)
            .await?
            .0;

            if script_exists == 0 {
                return Err(anyhow!("Script not found: {}", script_id));
            }
        }

        // Create default script ID if not provided
        let script_id = request.script_id.unwrap_or_else(|| "default".to_string());

        sqlx::query(
            r#"
            INSERT INTO vishing_campaigns (
                id, user_id, name, description, status, script_id,
                pretext_template_id, caller_id, start_date, end_date,
                target_organization, notes, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&id)
        .bind(user_id)
        .bind(&request.name)
        .bind(&request.description)
        .bind(VishingCampaignStatus::Draft.to_string())
        .bind(&script_id)
        .bind(&request.pretext_template_id)
        .bind(&request.caller_id)
        .bind(request.start_date.map(|d| d.to_rfc3339()))
        .bind(request.end_date.map(|d| d.to_rfc3339()))
        .bind(&request.target_organization)
        .bind::<Option<String>>(None)
        .bind(now.to_rfc3339())
        .bind(now.to_rfc3339())
        .execute(&self.pool)
        .await?;

        // Add targets
        for target in &request.targets {
            self.add_target(&id, target).await?;
        }

        Ok(VishingCampaign {
            id,
            user_id: user_id.to_string(),
            name: request.name,
            description: request.description,
            status: VishingCampaignStatus::Draft,
            script_id,
            pretext_template_id: request.pretext_template_id,
            caller_id: request.caller_id,
            start_date: request.start_date,
            end_date: request.end_date,
            target_organization: request.target_organization,
            notes: None,
            created_at: now,
            updated_at: now,
        })
    }

    /// Add a target to a campaign
    pub async fn add_target(
        &self,
        campaign_id: &str,
        target: &CreateVishingTargetRequest,
    ) -> Result<VishingTarget> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();

        sqlx::query(
            r#"
            INSERT INTO vishing_targets (
                id, campaign_id, name, phone_number, email, job_title,
                department, notes, called, last_outcome, attempt_count,
                created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&id)
        .bind(campaign_id)
        .bind(&target.name)
        .bind(&target.phone_number)
        .bind(&target.email)
        .bind(&target.job_title)
        .bind(&target.department)
        .bind(&target.notes)
        .bind(false)
        .bind::<Option<String>>(None)
        .bind(0i64)
        .bind(now.to_rfc3339())
        .bind(now.to_rfc3339())
        .execute(&self.pool)
        .await?;

        Ok(VishingTarget {
            id,
            campaign_id: campaign_id.to_string(),
            name: target.name.clone(),
            phone_number: target.phone_number.clone(),
            email: target.email.clone(),
            job_title: target.job_title.clone(),
            department: target.department.clone(),
            notes: target.notes.clone(),
            called: false,
            last_outcome: None,
            attempt_count: 0,
            created_at: now,
            updated_at: now,
        })
    }

    /// Get campaign by ID
    pub async fn get_campaign(&self, campaign_id: &str) -> Result<Option<VishingCampaign>> {
        let row = sqlx::query_as::<_, (
            String,
            String,
            String,
            Option<String>,
            String,
            String,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
            String,
            String,
        )>(
            r#"
            SELECT id, user_id, name, description, status, script_id,
                   pretext_template_id, caller_id, start_date, end_date,
                   target_organization, notes, created_at, updated_at
            FROM vishing_campaigns WHERE id = ?
            "#,
        )
        .bind(campaign_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| VishingCampaign {
            id: r.0,
            user_id: r.1,
            name: r.2,
            description: r.3,
            status: r.4.parse().unwrap_or(VishingCampaignStatus::Draft),
            script_id: r.5,
            pretext_template_id: r.6,
            caller_id: r.7,
            start_date: r.8.and_then(|d| {
                chrono::DateTime::parse_from_rfc3339(&d)
                    .ok()
                    .map(|dt| dt.with_timezone(&Utc))
            }),
            end_date: r.9.and_then(|d| {
                chrono::DateTime::parse_from_rfc3339(&d)
                    .ok()
                    .map(|dt| dt.with_timezone(&Utc))
            }),
            target_organization: r.10,
            notes: r.11,
            created_at: chrono::DateTime::parse_from_rfc3339(&r.12)
                .unwrap()
                .with_timezone(&Utc),
            updated_at: chrono::DateTime::parse_from_rfc3339(&r.13)
                .unwrap()
                .with_timezone(&Utc),
        }))
    }

    /// List campaigns for a user
    pub async fn list_campaigns(
        &self,
        user_id: &str,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<VishingCampaignSummary>> {
        let rows = sqlx::query_as::<_, (
            String,
            String,
            String,
            i64,
            i64,
            i64,
            i64,
            i64,
            i64,
            Option<String>,
            String,
        )>(
            r#"
            SELECT
                c.id, c.name, c.status,
                (SELECT COUNT(*) FROM vishing_targets WHERE campaign_id = c.id) as total_targets,
                (SELECT COUNT(*) FROM vishing_call_logs WHERE campaign_id = c.id) as calls_attempted,
                (SELECT COUNT(*) FROM vishing_call_logs WHERE campaign_id = c.id AND outcome NOT IN ('no_answer', 'voicemail', 'wrong_number', 'technical_issue')) as calls_connected,
                (SELECT COUNT(*) FROM vishing_call_logs WHERE campaign_id = c.id AND outcome IN ('partial_success', 'full_success')) as successful_calls,
                (SELECT COUNT(*) FROM vishing_call_logs WHERE campaign_id = c.id AND outcome IN ('hung_up', 'suspicious', 'engaged_no_compliance')) as failed_calls,
                (SELECT COUNT(*) FROM vishing_call_logs WHERE campaign_id = c.id AND outcome = 'reported') as reported_calls,
                c.start_date, c.created_at
            FROM vishing_campaigns c
            WHERE c.user_id = ?
            ORDER BY c.created_at DESC
            LIMIT ? OFFSET ?
            "#,
        )
        .bind(user_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| VishingCampaignSummary {
                id: r.0,
                name: r.1,
                status: r.2.parse().unwrap_or(VishingCampaignStatus::Draft),
                total_targets: r.3 as u32,
                calls_attempted: r.4 as u32,
                calls_connected: r.5 as u32,
                successful_calls: r.6 as u32,
                failed_calls: r.7 as u32,
                reported_calls: r.8 as u32,
                start_date: r.9.and_then(|d| {
                    chrono::DateTime::parse_from_rfc3339(&d)
                        .ok()
                        .map(|dt| dt.with_timezone(&Utc))
                }),
                created_at: chrono::DateTime::parse_from_rfc3339(&r.10)
                    .unwrap()
                    .with_timezone(&Utc),
            })
            .collect())
    }

    /// Log a call attempt
    pub async fn log_call(
        &self,
        campaign_id: &str,
        caller_id: Option<&str>,
        request: LogCallRequest,
    ) -> Result<VishingCallLog> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();

        // Extract values before moving
        let info_gathered = request.information_gathered.clone().unwrap_or_default();
        let target_suspicious = request.target_suspicious.unwrap_or(false);
        let verification_requested = request.verification_requested.unwrap_or(false);
        let stages_completed = request.stages_completed.unwrap_or(0);
        let outcome_str = request.outcome.to_string();

        let info_json = serde_json::to_string(&info_gathered)
            .map_err(|e| anyhow!("Failed to serialize info: {}", e))?;

        sqlx::query(
            r#"
            INSERT INTO vishing_call_logs (
                id, campaign_id, target_id, caller_id, script_id,
                started_at, ended_at, duration_seconds, outcome,
                information_gathered, notes, target_suspicious,
                verification_requested, stages_completed, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&id)
        .bind(campaign_id)
        .bind(&request.target_id)
        .bind(caller_id)
        .bind(&request.script_id)
        .bind(request.started_at.to_rfc3339())
        .bind(request.ended_at.map(|d| d.to_rfc3339()))
        .bind(request.duration_seconds.map(|d| d as i64))
        .bind(&outcome_str)
        .bind(&info_json)
        .bind(&request.notes)
        .bind(target_suspicious)
        .bind(verification_requested)
        .bind(stages_completed as i64)
        .bind(now.to_rfc3339())
        .execute(&self.pool)
        .await?;

        // Update target status
        sqlx::query(
            r#"
            UPDATE vishing_targets SET
                called = 1,
                last_outcome = ?,
                attempt_count = attempt_count + 1,
                updated_at = ?
            WHERE id = ?
            "#,
        )
        .bind(&outcome_str)
        .bind(now.to_rfc3339())
        .bind(&request.target_id)
        .execute(&self.pool)
        .await?;

        Ok(VishingCallLog {
            id,
            campaign_id: campaign_id.to_string(),
            target_id: request.target_id,
            caller_id: caller_id.map(String::from),
            script_id: request.script_id,
            started_at: request.started_at,
            ended_at: request.ended_at,
            duration_seconds: request.duration_seconds,
            outcome: request.outcome,
            information_gathered: info_gathered,
            notes: request.notes,
            target_suspicious,
            verification_requested,
            stages_completed,
            created_at: now,
        })
    }

    /// Get campaign statistics
    pub async fn get_campaign_stats(&self, campaign_id: &str) -> Result<VishingCampaignStats> {
        // Get total targets
        let total_targets = sqlx::query_as::<_, (i64,)>(
            "SELECT COUNT(*) FROM vishing_targets WHERE campaign_id = ?",
        )
        .bind(campaign_id)
        .fetch_one(&self.pool)
        .await?
        .0 as u32;

        // Get outcome counts
        let outcomes = sqlx::query_as::<_, (String, i64)>(
            r#"
            SELECT outcome, COUNT(*) FROM vishing_call_logs
            WHERE campaign_id = ?
            GROUP BY outcome
            "#,
        )
        .bind(campaign_id)
        .fetch_all(&self.pool)
        .await?;

        let mut outcome_counts: HashMap<String, u32> = HashMap::new();
        for (outcome, count) in outcomes {
            outcome_counts.insert(outcome, count as u32);
        }

        let calls_attempted: u32 = outcome_counts.values().sum();
        let no_answer = *outcome_counts.get("no_answer").unwrap_or(&0);
        let voicemail = *outcome_counts.get("voicemail").unwrap_or(&0);
        let hung_up = *outcome_counts.get("hung_up").unwrap_or(&0);
        let suspicious = *outcome_counts.get("suspicious").unwrap_or(&0);
        let engaged_no_compliance = *outcome_counts.get("engaged_no_compliance").unwrap_or(&0);
        let partial_success = *outcome_counts.get("partial_success").unwrap_or(&0);
        let full_success = *outcome_counts.get("full_success").unwrap_or(&0);
        let reported = *outcome_counts.get("reported").unwrap_or(&0);
        let callback_requested = *outcome_counts.get("callback_requested").unwrap_or(&0);

        let calls_connected = calls_attempted
            - no_answer
            - voicemail
            - *outcome_counts.get("wrong_number").unwrap_or(&0)
            - *outcome_counts.get("technical_issue").unwrap_or(&0);

        // Calculate average duration
        let avg_duration = sqlx::query_as::<_, (f64,)>(
            r#"
            SELECT COALESCE(AVG(duration_seconds), 0.0) FROM vishing_call_logs
            WHERE campaign_id = ? AND duration_seconds IS NOT NULL
            "#,
        )
        .bind(campaign_id)
        .fetch_one(&self.pool)
        .await?
        .0 as f32;

        // Calculate rates
        let success_rate = if calls_connected > 0 {
            (partial_success + full_success) as f32 / calls_connected as f32 * 100.0
        } else {
            0.0
        };

        let connection_rate = if calls_attempted > 0 {
            calls_connected as f32 / calls_attempted as f32 * 100.0
        } else {
            0.0
        };

        let suspicion_rate = if calls_connected > 0 {
            suspicious as f32 / calls_connected as f32 * 100.0
        } else {
            0.0
        };

        let reporting_rate = if calls_connected > 0 {
            reported as f32 / calls_connected as f32 * 100.0
        } else {
            0.0
        };

        Ok(VishingCampaignStats {
            total_targets,
            calls_attempted,
            calls_connected,
            no_answer,
            voicemail,
            hung_up,
            suspicious,
            engaged_no_compliance,
            partial_success,
            full_success,
            reported,
            callback_requested,
            average_call_duration: avg_duration,
            success_rate,
            connection_rate,
            suspicion_rate,
            reporting_rate,
            outcomes_by_department: HashMap::new(), // Would need additional query
            calls_by_date: HashMap::new(),          // Would need additional query
        })
    }

    /// Update campaign status
    pub async fn update_campaign_status(
        &self,
        campaign_id: &str,
        status: VishingCampaignStatus,
    ) -> Result<()> {
        sqlx::query("UPDATE vishing_campaigns SET status = ?, updated_at = ? WHERE id = ?")
            .bind(status.to_string())
            .bind(Utc::now().to_rfc3339())
            .bind(campaign_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Create a vishing script
    pub async fn create_script(
        &self,
        user_id: &str,
        request: CreateVishingScriptRequest,
    ) -> Result<VishingScript> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();

        let script_json = serde_json::to_string(&request.script)
            .map_err(|e| anyhow!("Failed to serialize script: {}", e))?;
        let call_flow_json = serde_json::to_string(&request.call_flow)
            .map_err(|e| anyhow!("Failed to serialize call flow: {}", e))?;
        let objection_json =
            serde_json::to_string(&request.objection_handling.clone().unwrap_or_default())
                .map_err(|e| anyhow!("Failed to serialize objections: {}", e))?;
        let red_flags_json = serde_json::to_string(&request.red_flags.clone().unwrap_or_default())
            .map_err(|e| anyhow!("Failed to serialize red flags: {}", e))?;
        let success_json =
            serde_json::to_string(&request.success_indicators.clone().unwrap_or_default())
                .map_err(|e| anyhow!("Failed to serialize success indicators: {}", e))?;
        let tips_json = serde_json::to_string(&request.caller_tips.clone().unwrap_or_default())
            .map_err(|e| anyhow!("Failed to serialize tips: {}", e))?;

        sqlx::query(
            r#"
            INSERT INTO vishing_scripts (
                id, user_id, name, description, category, difficulty,
                persona, caller_id, script, call_flow, objection_handling,
                red_flags, success_indicators, caller_tips,
                pretext_template_id, is_builtin, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&id)
        .bind(user_id)
        .bind(&request.name)
        .bind(&request.description)
        .bind(request.category.to_string())
        .bind(
            request
                .difficulty
                .clone()
                .unwrap_or(PretextDifficulty::Medium)
                .to_string(),
        )
        .bind(&request.persona)
        .bind(&request.caller_id)
        .bind(&script_json)
        .bind(&call_flow_json)
        .bind(&objection_json)
        .bind(&red_flags_json)
        .bind(&success_json)
        .bind(&tips_json)
        .bind(&request.pretext_template_id)
        .bind(false)
        .bind(now.to_rfc3339())
        .bind(now.to_rfc3339())
        .execute(&self.pool)
        .await?;

        Ok(VishingScript {
            id,
            user_id: Some(user_id.to_string()),
            name: request.name,
            description: request.description,
            category: request.category,
            difficulty: request.difficulty.unwrap_or(PretextDifficulty::Medium),
            persona: request.persona,
            caller_id: request.caller_id,
            script: request.script,
            call_flow: request.call_flow,
            objection_handling: request.objection_handling.unwrap_or_default(),
            red_flags: request.red_flags.unwrap_or_default(),
            success_indicators: request.success_indicators.unwrap_or_default(),
            caller_tips: request.caller_tips.unwrap_or_default(),
            pretext_template_id: request.pretext_template_id,
            is_builtin: false,
            created_at: now,
            updated_at: now,
        })
    }

    /// Get a vishing script by ID
    pub async fn get_script(&self, script_id: &str) -> Result<Option<VishingScript>> {
        let row = sqlx::query(
            r#"
            SELECT id, user_id, name, description, category, difficulty,
                   persona, caller_id, script, call_flow, objection_handling,
                   red_flags, success_indicators, caller_tips,
                   pretext_template_id, is_builtin, created_at, updated_at
            FROM vishing_scripts WHERE id = ?
            "#,
        )
        .bind(script_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| {
            use sqlx::Row;
            VishingScript {
                id: r.get("id"),
                user_id: r.get("user_id"),
                name: r.get("name"),
                description: r.get("description"),
                category: r.get::<String, _>("category").parse().unwrap_or(PretextCategory::Custom),
                difficulty: r.get::<String, _>("difficulty").parse().unwrap_or(PretextDifficulty::Medium),
                persona: r.get("persona"),
                caller_id: r.get("caller_id"),
                script: serde_json::from_str(&r.get::<String, _>("script")).unwrap_or_else(|_| PretextScript {
                    opening: String::new(),
                    talking_points: Vec::new(),
                    objection_handling: HashMap::new(),
                    information_to_gather: Vec::new(),
                    closing: String::new(),
                    follow_up: None,
                }),
                call_flow: serde_json::from_str(&r.get::<String, _>("call_flow")).unwrap_or_default(),
                objection_handling: serde_json::from_str(&r.get::<String, _>("objection_handling")).unwrap_or_default(),
                red_flags: serde_json::from_str(&r.get::<String, _>("red_flags")).unwrap_or_default(),
                success_indicators: serde_json::from_str(&r.get::<String, _>("success_indicators")).unwrap_or_default(),
                caller_tips: serde_json::from_str(&r.get::<String, _>("caller_tips")).unwrap_or_default(),
                pretext_template_id: r.get("pretext_template_id"),
                is_builtin: r.get("is_builtin"),
                created_at: chrono::DateTime::parse_from_rfc3339(&r.get::<String, _>("created_at"))
                    .unwrap()
                    .with_timezone(&Utc),
                updated_at: chrono::DateTime::parse_from_rfc3339(&r.get::<String, _>("updated_at"))
                    .unwrap()
                    .with_timezone(&Utc),
            }
        }))
    }

    /// List vishing scripts
    pub async fn list_scripts(&self, user_id: &str) -> Result<Vec<VishingScript>> {
        let rows = sqlx::query(
            r#"
            SELECT id, user_id, name, description, category, difficulty,
                   persona, caller_id, script, call_flow, objection_handling,
                   red_flags, success_indicators, caller_tips,
                   pretext_template_id, is_builtin, created_at, updated_at
            FROM vishing_scripts
            WHERE user_id = ? OR is_builtin = 1
            ORDER BY is_builtin DESC, created_at DESC
            "#,
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;

        use sqlx::Row;
        Ok(rows
            .into_iter()
            .map(|r| VishingScript {
                id: r.get("id"),
                user_id: r.get("user_id"),
                name: r.get("name"),
                description: r.get("description"),
                category: r.get::<String, _>("category").parse().unwrap_or(PretextCategory::Custom),
                difficulty: r.get::<String, _>("difficulty").parse().unwrap_or(PretextDifficulty::Medium),
                persona: r.get("persona"),
                caller_id: r.get("caller_id"),
                script: serde_json::from_str(&r.get::<String, _>("script")).unwrap_or_else(|_| PretextScript {
                    opening: String::new(),
                    talking_points: Vec::new(),
                    objection_handling: HashMap::new(),
                    information_to_gather: Vec::new(),
                    closing: String::new(),
                    follow_up: None,
                }),
                call_flow: serde_json::from_str(&r.get::<String, _>("call_flow")).unwrap_or_default(),
                objection_handling: serde_json::from_str(&r.get::<String, _>("objection_handling")).unwrap_or_default(),
                red_flags: serde_json::from_str(&r.get::<String, _>("red_flags")).unwrap_or_default(),
                success_indicators: serde_json::from_str(&r.get::<String, _>("success_indicators")).unwrap_or_default(),
                caller_tips: serde_json::from_str(&r.get::<String, _>("caller_tips")).unwrap_or_default(),
                pretext_template_id: r.get("pretext_template_id"),
                is_builtin: r.get("is_builtin"),
                created_at: chrono::DateTime::parse_from_rfc3339(&r.get::<String, _>("created_at"))
                    .unwrap()
                    .with_timezone(&Utc),
                updated_at: chrono::DateTime::parse_from_rfc3339(&r.get::<String, _>("updated_at"))
                    .unwrap()
                    .with_timezone(&Utc),
            })
            .collect())
    }

    /// Get targets for a campaign
    pub async fn get_targets(&self, campaign_id: &str) -> Result<Vec<VishingTarget>> {
        let rows = sqlx::query_as::<_, (
            String,
            String,
            String,
            String,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
            bool,
            Option<String>,
            i64,
            String,
            String,
        )>(
            r#"
            SELECT id, campaign_id, name, phone_number, email, job_title,
                   department, notes, called, last_outcome, attempt_count,
                   created_at, updated_at
            FROM vishing_targets WHERE campaign_id = ?
            ORDER BY called ASC, created_at ASC
            "#,
        )
        .bind(campaign_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| VishingTarget {
                id: r.0,
                campaign_id: r.1,
                name: r.2,
                phone_number: r.3,
                email: r.4,
                job_title: r.5,
                department: r.6,
                notes: r.7,
                called: r.8,
                last_outcome: r.9.and_then(|o| o.parse().ok()),
                attempt_count: r.10 as u32,
                created_at: chrono::DateTime::parse_from_rfc3339(&r.11)
                    .unwrap()
                    .with_timezone(&Utc),
                updated_at: chrono::DateTime::parse_from_rfc3339(&r.12)
                    .unwrap()
                    .with_timezone(&Utc),
            })
            .collect())
    }

    /// Get call logs for a campaign
    pub async fn get_call_logs(&self, campaign_id: &str) -> Result<Vec<VishingCallLog>> {
        let rows = sqlx::query_as::<_, (
            String,
            String,
            String,
            Option<String>,
            String,
            String,
            Option<String>,
            Option<i64>,
            String,
            String,
            Option<String>,
            bool,
            bool,
            i64,
            String,
        )>(
            r#"
            SELECT id, campaign_id, target_id, caller_id, script_id,
                   started_at, ended_at, duration_seconds, outcome,
                   information_gathered, notes, target_suspicious,
                   verification_requested, stages_completed, created_at
            FROM vishing_call_logs WHERE campaign_id = ?
            ORDER BY created_at DESC
            "#,
        )
        .bind(campaign_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| VishingCallLog {
                id: r.0,
                campaign_id: r.1,
                target_id: r.2,
                caller_id: r.3,
                script_id: r.4,
                started_at: chrono::DateTime::parse_from_rfc3339(&r.5)
                    .unwrap()
                    .with_timezone(&Utc),
                ended_at: r.6.and_then(|d| {
                    chrono::DateTime::parse_from_rfc3339(&d)
                        .ok()
                        .map(|dt| dt.with_timezone(&Utc))
                }),
                duration_seconds: r.7.map(|d| d as u32),
                outcome: r.8.parse().unwrap_or(CallOutcome::TechnicalIssue),
                information_gathered: serde_json::from_str(&r.9).unwrap_or_default(),
                notes: r.10,
                target_suspicious: r.11,
                verification_requested: r.12,
                stages_completed: r.13 as u32,
                created_at: chrono::DateTime::parse_from_rfc3339(&r.14)
                    .unwrap()
                    .with_timezone(&Utc),
            })
            .collect())
    }

    /// Delete a vishing campaign
    pub async fn delete_campaign(&self, campaign_id: &str) -> Result<()> {
        sqlx::query("DELETE FROM vishing_campaigns WHERE id = ?")
            .bind(campaign_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Delete a vishing script
    pub async fn delete_script(&self, script_id: &str) -> Result<()> {
        // Don't allow deleting built-in scripts
        let is_builtin = sqlx::query_as::<_, (bool,)>(
            "SELECT is_builtin FROM vishing_scripts WHERE id = ?",
        )
        .bind(script_id)
        .fetch_optional(&self.pool)
        .await?
        .map(|r| r.0)
        .unwrap_or(false);

        if is_builtin {
            return Err(anyhow!("Cannot delete built-in scripts"));
        }

        sqlx::query("DELETE FROM vishing_scripts WHERE id = ?")
            .bind(script_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}
