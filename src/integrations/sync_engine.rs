//! Bi-Directional Integration Sync Engine
//!
//! Provides synchronization between HeroForge and external systems like JIRA and ServiceNow.
//! Features:
//! - Pull ticket status changes from external systems
//! - Two-way comment synchronization
//! - Auto-close tickets when vulnerabilities are verified
//! - Conflict resolution for simultaneous edits

use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use super::jira::JiraClient;
use super::servicenow::ServiceNowClient;

/// Types of external integration systems
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IntegrationType {
    Jira,
    ServiceNow,
    GitHub,
    GitLab,
}

impl std::fmt::Display for IntegrationType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IntegrationType::Jira => write!(f, "jira"),
            IntegrationType::ServiceNow => write!(f, "servicenow"),
            IntegrationType::GitHub => write!(f, "github"),
            IntegrationType::GitLab => write!(f, "gitlab"),
        }
    }
}

/// Status of a linked ticket
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TicketStatus {
    Open,
    InProgress,
    Resolved,
    Closed,
    Reopened,
    Unknown(String),
}

impl From<&str> for TicketStatus {
    fn from(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "open" | "to do" | "new" => TicketStatus::Open,
            "in progress" | "in-progress" | "active" | "work in progress" => {
                TicketStatus::InProgress
            }
            "resolved" | "fixed" | "done" => TicketStatus::Resolved,
            "closed" | "complete" | "completed" => TicketStatus::Closed,
            "reopened" | "reopen" => TicketStatus::Reopened,
            other => TicketStatus::Unknown(other.to_string()),
        }
    }
}

/// A linked ticket in an external system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkedTicket {
    pub id: String,
    pub vulnerability_id: String,
    pub integration_type: IntegrationType,
    pub external_id: String,
    pub external_key: String,
    pub external_url: String,
    pub status: TicketStatus,
    pub last_synced_at: DateTime<Utc>,
    pub local_updated_at: DateTime<Utc>,
    pub remote_updated_at: Option<DateTime<Utc>>,
    pub sync_enabled: bool,
    pub created_at: DateTime<Utc>,
}

/// A synchronized comment between systems
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncedComment {
    pub id: String,
    pub linked_ticket_id: String,
    pub local_comment_id: Option<String>,
    pub remote_comment_id: Option<String>,
    pub author: String,
    pub content: String,
    pub source: CommentSource,
    pub synced_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

/// Source of a comment
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CommentSource {
    Local,
    Remote,
}

/// Sync action result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncAction {
    pub action_type: SyncActionType,
    pub linked_ticket_id: String,
    pub details: String,
    pub success: bool,
    pub error: Option<String>,
    pub timestamp: DateTime<Utc>,
}

/// Types of sync actions
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyncActionType {
    StatusPulled,
    StatusPushed,
    CommentPulled,
    CommentPushed,
    TicketClosed,
    ConflictResolved,
}

/// Conflict resolution strategy
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConflictStrategy {
    LocalWins,
    RemoteWins,
    MostRecent,
    Manual,
}

/// Sync configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncConfig {
    pub enabled: bool,
    pub auto_close_on_verify: bool,
    pub sync_comments: bool,
    pub conflict_strategy: ConflictStrategy,
    pub poll_interval_secs: u64,
    pub status_mapping: HashMap<String, String>,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            auto_close_on_verify: true,
            sync_comments: true,
            conflict_strategy: ConflictStrategy::MostRecent,
            poll_interval_secs: 300, // 5 minutes
            status_mapping: Self::default_status_mapping(),
        }
    }
}

impl SyncConfig {
    fn default_status_mapping() -> HashMap<String, String> {
        let mut m = HashMap::new();
        // HeroForge status -> External status
        m.insert("open".to_string(), "Open".to_string());
        m.insert("in_progress".to_string(), "In Progress".to_string());
        m.insert("resolved".to_string(), "Resolved".to_string());
        m.insert("verified".to_string(), "Closed".to_string());
        m.insert("false_positive".to_string(), "Closed".to_string());
        m.insert("accepted_risk".to_string(), "Closed".to_string());
        m
    }
}

/// Sync statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SyncStats {
    pub total_synced: u64,
    pub status_updates: u64,
    pub comments_synced: u64,
    pub tickets_closed: u64,
    pub conflicts_resolved: u64,
    pub errors: u64,
    pub last_sync_at: Option<DateTime<Utc>>,
}

/// Bi-directional sync engine
pub struct SyncEngine {
    pool: Arc<SqlitePool>,
    config: Arc<RwLock<SyncConfig>>,
    jira_clients: Arc<RwLock<HashMap<String, JiraClient>>>,
    servicenow_clients: Arc<RwLock<HashMap<String, ServiceNowClient>>>,
    stats: Arc<RwLock<SyncStats>>,
}

impl SyncEngine {
    /// Create a new sync engine
    pub fn new(pool: Arc<SqlitePool>) -> Self {
        Self {
            pool,
            config: Arc::new(RwLock::new(SyncConfig::default())),
            jira_clients: Arc::new(RwLock::new(HashMap::new())),
            servicenow_clients: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(SyncStats::default())),
        }
    }

    /// Update sync configuration
    pub async fn set_config(&self, config: SyncConfig) {
        let mut cfg = self.config.write().await;
        *cfg = config;
    }

    /// Get current sync configuration
    pub async fn get_config(&self) -> SyncConfig {
        self.config.read().await.clone()
    }

    /// Get sync statistics
    pub async fn get_stats(&self) -> SyncStats {
        self.stats.read().await.clone()
    }

    /// Register a JIRA client for a specific user/org
    pub async fn register_jira_client(&self, user_id: &str, client: JiraClient) {
        let mut clients = self.jira_clients.write().await;
        clients.insert(user_id.to_string(), client);
    }

    /// Register a ServiceNow client for a specific user/org
    pub async fn register_servicenow_client(&self, user_id: &str, client: ServiceNowClient) {
        let mut clients = self.servicenow_clients.write().await;
        clients.insert(user_id.to_string(), client);
    }

    /// Link a vulnerability to an external ticket
    pub async fn link_ticket(
        &self,
        vulnerability_id: &str,
        integration_type: IntegrationType,
        external_id: &str,
        external_key: &str,
        external_url: &str,
        user_id: &str,
    ) -> Result<LinkedTicket> {
        let id = uuid::Uuid::new_v4().to_string();
        let now = Utc::now();

        let ticket = LinkedTicket {
            id: id.clone(),
            vulnerability_id: vulnerability_id.to_string(),
            integration_type,
            external_id: external_id.to_string(),
            external_key: external_key.to_string(),
            external_url: external_url.to_string(),
            status: TicketStatus::Open,
            last_synced_at: now,
            local_updated_at: now,
            remote_updated_at: None,
            sync_enabled: true,
            created_at: now,
        };

        // Store in database
        sqlx::query(
            r#"
            INSERT INTO linked_tickets (
                id, vulnerability_id, integration_type, external_id, external_key,
                external_url, status, last_synced_at, local_updated_at, remote_updated_at,
                sync_enabled, user_id, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&ticket.id)
        .bind(&ticket.vulnerability_id)
        .bind(ticket.integration_type.to_string())
        .bind(&ticket.external_id)
        .bind(&ticket.external_key)
        .bind(&ticket.external_url)
        .bind(serde_json::to_string(&ticket.status)?)
        .bind(ticket.last_synced_at.to_rfc3339())
        .bind(ticket.local_updated_at.to_rfc3339())
        .bind(ticket.remote_updated_at.map(|t| t.to_rfc3339()))
        .bind(ticket.sync_enabled)
        .bind(user_id)
        .bind(ticket.created_at.to_rfc3339())
        .execute(&*self.pool)
        .await?;

        info!(
            "Linked vulnerability {} to {} ticket {}",
            vulnerability_id, ticket.integration_type, external_key
        );

        Ok(ticket)
    }

    /// Get all linked tickets for a vulnerability
    pub async fn get_linked_tickets(&self, vulnerability_id: &str) -> Result<Vec<LinkedTicket>> {
        let rows: Vec<(
            String,
            String,
            String,
            String,
            String,
            String,
            String,
            String,
            String,
            Option<String>,
            bool,
            String,
        )> = sqlx::query_as(
            r#"
            SELECT id, vulnerability_id, integration_type, external_id, external_key,
                   external_url, status, last_synced_at, local_updated_at, remote_updated_at,
                   sync_enabled, created_at
            FROM linked_tickets
            WHERE vulnerability_id = ?
            "#,
        )
        .bind(vulnerability_id)
        .fetch_all(&*self.pool)
        .await?;

        let tickets = rows
            .into_iter()
            .filter_map(|row| {
                let integration_type = match row.2.as_str() {
                    "jira" => IntegrationType::Jira,
                    "servicenow" => IntegrationType::ServiceNow,
                    "github" => IntegrationType::GitHub,
                    "gitlab" => IntegrationType::GitLab,
                    _ => return None,
                };
                let status: TicketStatus =
                    serde_json::from_str(&row.6).unwrap_or(TicketStatus::Unknown(row.6.clone()));

                Some(LinkedTicket {
                    id: row.0,
                    vulnerability_id: row.1,
                    integration_type,
                    external_id: row.3,
                    external_key: row.4,
                    external_url: row.5,
                    status,
                    last_synced_at: DateTime::parse_from_rfc3339(&row.7)
                        .map(|t| t.with_timezone(&Utc))
                        .unwrap_or_else(|_| Utc::now()),
                    local_updated_at: DateTime::parse_from_rfc3339(&row.8)
                        .map(|t| t.with_timezone(&Utc))
                        .unwrap_or_else(|_| Utc::now()),
                    remote_updated_at: row.9.and_then(|s| {
                        DateTime::parse_from_rfc3339(&s)
                            .map(|t| t.with_timezone(&Utc))
                            .ok()
                    }),
                    sync_enabled: row.10,
                    created_at: DateTime::parse_from_rfc3339(&row.11)
                        .map(|t| t.with_timezone(&Utc))
                        .unwrap_or_else(|_| Utc::now()),
                })
            })
            .collect();

        Ok(tickets)
    }

    /// Sync all linked tickets for a user
    pub async fn sync_all(&self, user_id: &str) -> Result<Vec<SyncAction>> {
        let config = self.config.read().await;
        if !config.enabled {
            return Ok(Vec::new());
        }
        drop(config);

        info!("Starting sync for user {}", user_id);
        let mut actions = Vec::new();

        // Get all linked tickets for this user
        let rows: Vec<(String,)> = sqlx::query_as(
            r#"
            SELECT id FROM linked_tickets WHERE user_id = ? AND sync_enabled = true
            "#,
        )
        .bind(user_id)
        .fetch_all(&*self.pool)
        .await?;

        for (ticket_id,) in rows {
            match self.sync_ticket(&ticket_id, user_id).await {
                Ok(ticket_actions) => actions.extend(ticket_actions),
                Err(e) => {
                    error!("Failed to sync ticket {}: {}", ticket_id, e);
                    actions.push(SyncAction {
                        action_type: SyncActionType::StatusPulled,
                        linked_ticket_id: ticket_id,
                        details: "Sync failed".to_string(),
                        success: false,
                        error: Some(e.to_string()),
                        timestamp: Utc::now(),
                    });
                }
            }
        }

        // Update stats
        let mut stats = self.stats.write().await;
        stats.last_sync_at = Some(Utc::now());
        stats.total_synced += actions.iter().filter(|a| a.success).count() as u64;
        stats.errors += actions.iter().filter(|a| !a.success).count() as u64;

        info!(
            "Sync complete for user {}: {} actions, {} successful",
            user_id,
            actions.len(),
            actions.iter().filter(|a| a.success).count()
        );

        Ok(actions)
    }

    /// Sync a specific linked ticket
    pub async fn sync_ticket(&self, ticket_id: &str, user_id: &str) -> Result<Vec<SyncAction>> {
        let mut actions = Vec::new();

        // Get ticket details
        let row: Option<(String, String, String, String, String, String)> = sqlx::query_as(
            r#"
            SELECT id, vulnerability_id, integration_type, external_id, external_key, status
            FROM linked_tickets
            WHERE id = ?
            "#,
        )
        .bind(ticket_id)
        .fetch_optional(&*self.pool)
        .await?;

        let (_, vulnerability_id, integration_type_str, external_id, external_key, local_status) =
            row.ok_or_else(|| anyhow!("Linked ticket not found: {}", ticket_id))?;

        let integration_type = match integration_type_str.as_str() {
            "jira" => IntegrationType::Jira,
            "servicenow" => IntegrationType::ServiceNow,
            _ => return Err(anyhow!("Unsupported integration type: {}", integration_type_str)),
        };

        // Pull remote status
        let remote_status = self
            .pull_remote_status(&integration_type, &external_id, &external_key, user_id)
            .await?;

        let local_status: TicketStatus = serde_json::from_str(&local_status)
            .unwrap_or(TicketStatus::Unknown(local_status.clone()));

        // Handle status changes
        if remote_status != local_status {
            let config = self.config.read().await;

            match config.conflict_strategy {
                ConflictStrategy::RemoteWins | ConflictStrategy::MostRecent => {
                    // Update local status based on remote
                    self.update_local_status(ticket_id, &remote_status).await?;
                    actions.push(SyncAction {
                        action_type: SyncActionType::StatusPulled,
                        linked_ticket_id: ticket_id.to_string(),
                        details: format!(
                            "Status updated from {} to {}",
                            format!("{:?}", local_status),
                            format!("{:?}", remote_status)
                        ),
                        success: true,
                        error: None,
                        timestamp: Utc::now(),
                    });

                    // Update vulnerability status if needed
                    self.sync_vulnerability_status(&vulnerability_id, &remote_status)
                        .await?;
                }
                ConflictStrategy::LocalWins => {
                    // Push local status to remote
                    self.push_status_to_remote(
                        &integration_type,
                        &external_key,
                        &local_status,
                        user_id,
                    )
                    .await?;
                    actions.push(SyncAction {
                        action_type: SyncActionType::StatusPushed,
                        linked_ticket_id: ticket_id.to_string(),
                        details: format!("Pushed local status {:?} to remote", local_status),
                        success: true,
                        error: None,
                        timestamp: Utc::now(),
                    });
                }
                ConflictStrategy::Manual => {
                    // Flag for manual review
                    warn!(
                        "Status conflict detected for ticket {}: local={:?}, remote={:?}",
                        ticket_id, local_status, remote_status
                    );
                    actions.push(SyncAction {
                        action_type: SyncActionType::ConflictResolved,
                        linked_ticket_id: ticket_id.to_string(),
                        details: "Status conflict - requires manual resolution".to_string(),
                        success: false,
                        error: Some("Manual resolution required".to_string()),
                        timestamp: Utc::now(),
                    });
                }
            }
        }

        // Sync comments if enabled
        let config = self.config.read().await;
        if config.sync_comments {
            drop(config);
            let comment_actions = self
                .sync_comments(ticket_id, &integration_type, &external_key, user_id)
                .await?;
            actions.extend(comment_actions);
        }

        // Update last synced timestamp
        sqlx::query("UPDATE linked_tickets SET last_synced_at = ? WHERE id = ?")
            .bind(Utc::now().to_rfc3339())
            .bind(ticket_id)
            .execute(&*self.pool)
            .await?;

        Ok(actions)
    }

    /// Pull remote ticket status
    async fn pull_remote_status(
        &self,
        integration_type: &IntegrationType,
        external_id: &str,
        external_key: &str,
        user_id: &str,
    ) -> Result<TicketStatus> {
        match integration_type {
            IntegrationType::Jira => {
                let clients = self.jira_clients.read().await;
                let client = clients
                    .get(user_id)
                    .ok_or_else(|| anyhow!("JIRA client not configured for user"))?;

                // Get issue status from JIRA
                let issue = client.get_issue(external_key).await?;
                Ok(TicketStatus::from(issue.fields.status.name.as_str()))
            }
            IntegrationType::ServiceNow => {
                let clients = self.servicenow_clients.read().await;
                let client = clients
                    .get(user_id)
                    .ok_or_else(|| anyhow!("ServiceNow client not configured for user"))?;

                // Get incident status from ServiceNow
                let incident = client.get_incident(external_id).await?;
                Ok(TicketStatus::from(incident.state.as_str()))
            }
            _ => Err(anyhow!("Unsupported integration type for status pull")),
        }
    }

    /// Push local status to remote system
    async fn push_status_to_remote(
        &self,
        integration_type: &IntegrationType,
        external_key: &str,
        status: &TicketStatus,
        user_id: &str,
    ) -> Result<()> {
        let config = self.config.read().await;
        let status_str = match status {
            TicketStatus::Open => "open",
            TicketStatus::InProgress => "in_progress",
            TicketStatus::Resolved => "resolved",
            TicketStatus::Closed => "verified",
            TicketStatus::Reopened => "open",
            TicketStatus::Unknown(_) => return Ok(()), // Don't push unknown statuses
        };

        let mapped_status = config
            .status_mapping
            .get(status_str)
            .cloned()
            .unwrap_or_else(|| status_str.to_string());
        drop(config);

        match integration_type {
            IntegrationType::Jira => {
                let clients = self.jira_clients.read().await;
                let client = clients
                    .get(user_id)
                    .ok_or_else(|| anyhow!("JIRA client not configured"))?;

                // Get available transitions and find matching one
                let transitions = client.get_transitions(external_key).await?;
                if let Some(transition) = transitions
                    .iter()
                    .find(|t| t.name.to_lowercase() == mapped_status.to_lowercase())
                {
                    client
                        .transition_issue(external_key, &transition.id)
                        .await?;
                } else {
                    warn!("No matching transition found for status: {}", mapped_status);
                }
            }
            IntegrationType::ServiceNow => {
                let clients = self.servicenow_clients.read().await;
                let client = clients
                    .get(user_id)
                    .ok_or_else(|| anyhow!("ServiceNow client not configured"))?;

                client
                    .update_incident_state(external_key, &mapped_status)
                    .await?;
            }
            _ => return Err(anyhow!("Unsupported integration type for status push")),
        }

        Ok(())
    }

    /// Update local ticket status
    async fn update_local_status(&self, ticket_id: &str, status: &TicketStatus) -> Result<()> {
        sqlx::query("UPDATE linked_tickets SET status = ?, local_updated_at = ? WHERE id = ?")
            .bind(serde_json::to_string(status)?)
            .bind(Utc::now().to_rfc3339())
            .bind(ticket_id)
            .execute(&*self.pool)
            .await?;
        Ok(())
    }

    /// Sync vulnerability status based on ticket status
    async fn sync_vulnerability_status(
        &self,
        vulnerability_id: &str,
        ticket_status: &TicketStatus,
    ) -> Result<()> {
        let vuln_status = match ticket_status {
            TicketStatus::Open => "open",
            TicketStatus::InProgress => "in_progress",
            TicketStatus::Resolved => "resolved",
            TicketStatus::Closed => "verified",
            TicketStatus::Reopened => "open",
            TicketStatus::Unknown(_) => return Ok(()),
        };

        sqlx::query("UPDATE vulnerability_tracking SET status = ?, updated_at = ? WHERE id = ?")
            .bind(vuln_status)
            .bind(Utc::now().to_rfc3339())
            .bind(vulnerability_id)
            .execute(&*self.pool)
            .await?;

        debug!(
            "Updated vulnerability {} status to {}",
            vulnerability_id, vuln_status
        );

        Ok(())
    }

    /// Sync comments between local and remote
    async fn sync_comments(
        &self,
        ticket_id: &str,
        integration_type: &IntegrationType,
        external_key: &str,
        user_id: &str,
    ) -> Result<Vec<SyncAction>> {
        let mut actions = Vec::new();

        // Get remote comments
        let remote_comments = self
            .pull_remote_comments(integration_type, external_key, user_id)
            .await?;

        // Get already synced comment IDs
        let synced_ids: Vec<(String,)> = sqlx::query_as(
            "SELECT remote_comment_id FROM synced_comments WHERE linked_ticket_id = ?",
        )
        .bind(ticket_id)
        .fetch_all(&*self.pool)
        .await?;

        let synced_set: std::collections::HashSet<_> =
            synced_ids.into_iter().map(|(id,)| id).collect();

        // Import new remote comments
        for comment in remote_comments {
            if !synced_set.contains(&comment.id) {
                let synced_comment = SyncedComment {
                    id: uuid::Uuid::new_v4().to_string(),
                    linked_ticket_id: ticket_id.to_string(),
                    local_comment_id: None,
                    remote_comment_id: Some(comment.id.clone()),
                    author: comment.author,
                    content: comment.body,
                    source: CommentSource::Remote,
                    synced_at: Utc::now(),
                    created_at: comment.created_at,
                };

                self.save_synced_comment(&synced_comment).await?;
                actions.push(SyncAction {
                    action_type: SyncActionType::CommentPulled,
                    linked_ticket_id: ticket_id.to_string(),
                    details: format!("Imported comment from {}", synced_comment.author),
                    success: true,
                    error: None,
                    timestamp: Utc::now(),
                });
            }
        }

        // Push unsynced local comments to remote
        let unsynced_local: Vec<(String, String, String)> = sqlx::query_as(
            r#"
            SELECT vc.id, vc.comment, u.username
            FROM vulnerability_comments vc
            JOIN users u ON vc.user_id = u.id
            WHERE vc.vulnerability_id = (
                SELECT vulnerability_id FROM linked_tickets WHERE id = ?
            )
            AND vc.id NOT IN (
                SELECT local_comment_id FROM synced_comments
                WHERE linked_ticket_id = ? AND local_comment_id IS NOT NULL
            )
            "#,
        )
        .bind(ticket_id)
        .bind(ticket_id)
        .fetch_all(&*self.pool)
        .await?;

        for (comment_id, content, author) in unsynced_local {
            match self
                .push_comment_to_remote(integration_type, external_key, &content, &author, user_id)
                .await
            {
                Ok(remote_id) => {
                    let synced_comment = SyncedComment {
                        id: uuid::Uuid::new_v4().to_string(),
                        linked_ticket_id: ticket_id.to_string(),
                        local_comment_id: Some(comment_id.clone()),
                        remote_comment_id: remote_id,
                        author: author.clone(),
                        content,
                        source: CommentSource::Local,
                        synced_at: Utc::now(),
                        created_at: Utc::now(),
                    };
                    self.save_synced_comment(&synced_comment).await?;
                    actions.push(SyncAction {
                        action_type: SyncActionType::CommentPushed,
                        linked_ticket_id: ticket_id.to_string(),
                        details: format!("Pushed comment from {}", author),
                        success: true,
                        error: None,
                        timestamp: Utc::now(),
                    });
                }
                Err(e) => {
                    actions.push(SyncAction {
                        action_type: SyncActionType::CommentPushed,
                        linked_ticket_id: ticket_id.to_string(),
                        details: "Failed to push comment".to_string(),
                        success: false,
                        error: Some(e.to_string()),
                        timestamp: Utc::now(),
                    });
                }
            }
        }

        Ok(actions)
    }

    /// Pull comments from remote system
    async fn pull_remote_comments(
        &self,
        integration_type: &IntegrationType,
        external_key: &str,
        user_id: &str,
    ) -> Result<Vec<RemoteComment>> {
        match integration_type {
            IntegrationType::Jira => {
                let clients = self.jira_clients.read().await;
                let client = clients
                    .get(user_id)
                    .ok_or_else(|| anyhow!("JIRA client not configured"))?;
                client.get_comments(external_key).await
            }
            IntegrationType::ServiceNow => {
                let clients = self.servicenow_clients.read().await;
                let client = clients
                    .get(user_id)
                    .ok_or_else(|| anyhow!("ServiceNow client not configured"))?;
                client.get_work_notes(external_key).await
            }
            _ => Ok(Vec::new()),
        }
    }

    /// Push a comment to remote system
    async fn push_comment_to_remote(
        &self,
        integration_type: &IntegrationType,
        external_key: &str,
        content: &str,
        author: &str,
        user_id: &str,
    ) -> Result<Option<String>> {
        let formatted_content = format!("[HeroForge - {}] {}", author, content);

        match integration_type {
            IntegrationType::Jira => {
                let clients = self.jira_clients.read().await;
                let client = clients
                    .get(user_id)
                    .ok_or_else(|| anyhow!("JIRA client not configured"))?;
                client.add_comment(external_key, &formatted_content).await?;
                Ok(None) // JIRA doesn't return comment ID on create
            }
            IntegrationType::ServiceNow => {
                let clients = self.servicenow_clients.read().await;
                let client = clients
                    .get(user_id)
                    .ok_or_else(|| anyhow!("ServiceNow client not configured"))?;
                client
                    .add_work_note(external_key, &formatted_content)
                    .await?;
                Ok(None)
            }
            _ => Err(anyhow!("Unsupported integration type for comment push")),
        }
    }

    /// Save a synced comment record
    async fn save_synced_comment(&self, comment: &SyncedComment) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO synced_comments (
                id, linked_ticket_id, local_comment_id, remote_comment_id,
                author, content, source, synced_at, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&comment.id)
        .bind(&comment.linked_ticket_id)
        .bind(&comment.local_comment_id)
        .bind(&comment.remote_comment_id)
        .bind(&comment.author)
        .bind(&comment.content)
        .bind(if comment.source == CommentSource::Local {
            "local"
        } else {
            "remote"
        })
        .bind(comment.synced_at.to_rfc3339())
        .bind(comment.created_at.to_rfc3339())
        .execute(&*self.pool)
        .await?;
        Ok(())
    }

    /// Auto-close linked tickets when vulnerability is verified
    pub async fn on_vulnerability_verified(
        &self,
        vulnerability_id: &str,
        user_id: &str,
    ) -> Result<Vec<SyncAction>> {
        let config = self.config.read().await;
        if !config.auto_close_on_verify {
            return Ok(Vec::new());
        }
        drop(config);

        let mut actions = Vec::new();

        let tickets = self.get_linked_tickets(vulnerability_id).await?;
        for ticket in tickets {
            if !ticket.sync_enabled {
                continue;
            }

            match self
                .push_status_to_remote(
                    &ticket.integration_type,
                    &ticket.external_key,
                    &TicketStatus::Closed,
                    user_id,
                )
                .await
            {
                Ok(()) => {
                    self.update_local_status(&ticket.id, &TicketStatus::Closed)
                        .await?;
                    actions.push(SyncAction {
                        action_type: SyncActionType::TicketClosed,
                        linked_ticket_id: ticket.id,
                        details: format!(
                            "Closed {} ticket {} on verification",
                            ticket.integration_type, ticket.external_key
                        ),
                        success: true,
                        error: None,
                        timestamp: Utc::now(),
                    });
                }
                Err(e) => {
                    actions.push(SyncAction {
                        action_type: SyncActionType::TicketClosed,
                        linked_ticket_id: ticket.id,
                        details: "Failed to close ticket on verification".to_string(),
                        success: false,
                        error: Some(e.to_string()),
                        timestamp: Utc::now(),
                    });
                }
            }
        }

        Ok(actions)
    }
}

/// Remote comment from external system
#[derive(Debug, Clone)]
pub struct RemoteComment {
    pub id: String,
    pub author: String,
    pub body: String,
    pub created_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ticket_status_from_string() {
        assert_eq!(TicketStatus::from("open"), TicketStatus::Open);
        assert_eq!(TicketStatus::from("In Progress"), TicketStatus::InProgress);
        assert_eq!(TicketStatus::from("resolved"), TicketStatus::Resolved);
        assert_eq!(TicketStatus::from("closed"), TicketStatus::Closed);
        assert_eq!(TicketStatus::from("reopened"), TicketStatus::Reopened);
        assert!(matches!(
            TicketStatus::from("custom status"),
            TicketStatus::Unknown(_)
        ));
    }

    #[test]
    fn test_default_sync_config() {
        let config = SyncConfig::default();
        assert!(config.enabled);
        assert!(config.auto_close_on_verify);
        assert!(config.sync_comments);
        assert_eq!(config.conflict_strategy, ConflictStrategy::MostRecent);
        assert_eq!(config.poll_interval_secs, 300);
    }
}
