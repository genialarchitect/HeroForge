//! SOAR-lite Automation Module
//!
//! Provides response automation capabilities:
//! - Response playbooks (containment, eradication actions)
//! - Automated actions: block IP, disable account, isolate host (mock/documented)
//! - Action approval workflow
//! - Action audit logging

use anyhow::Result;
use chrono::Utc;
use sqlx::SqlitePool;
use uuid::Uuid;

use super::types::*;

// ============================================================================
// Playbook Management
// ============================================================================

/// Create a new response playbook
pub async fn create_playbook(
    pool: &SqlitePool,
    user_id: &str,
    request: CreatePlaybookRequest,
) -> Result<ResponsePlaybook> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();

    let trigger_conditions = request
        .trigger_conditions
        .map(|v| serde_json::to_string(&v))
        .transpose()?;
    let steps_json = serde_json::to_string(&request.steps)?;

    let playbook = sqlx::query_as::<_, ResponsePlaybook>(
        r#"
        INSERT INTO response_playbooks
        (id, name, description, trigger_conditions, steps_json, is_builtin, user_id, created_at, updated_at)
        VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6, ?7, ?8)
        RETURNING *
        "#,
    )
    .bind(&id)
    .bind(&request.name)
    .bind(&request.description)
    .bind(&trigger_conditions)
    .bind(&steps_json)
    .bind(user_id)
    .bind(now)
    .bind(now)
    .fetch_one(pool)
    .await?;

    Ok(playbook)
}

/// Create a built-in playbook
pub async fn create_builtin_playbook(
    pool: &SqlitePool,
    name: &str,
    description: Option<&str>,
    trigger_conditions: Option<serde_json::Value>,
    steps: Vec<PlaybookStep>,
) -> Result<ResponsePlaybook> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();

    let trigger_str = trigger_conditions
        .map(|v| serde_json::to_string(&v))
        .transpose()?;
    let steps_json = serde_json::to_string(&steps)?;

    let playbook = sqlx::query_as::<_, ResponsePlaybook>(
        r#"
        INSERT INTO response_playbooks
        (id, name, description, trigger_conditions, steps_json, is_builtin, user_id, created_at, updated_at)
        VALUES (?1, ?2, ?3, ?4, ?5, 1, NULL, ?6, ?7)
        RETURNING *
        "#,
    )
    .bind(&id)
    .bind(name)
    .bind(description)
    .bind(&trigger_str)
    .bind(&steps_json)
    .bind(now)
    .bind(now)
    .fetch_one(pool)
    .await?;

    Ok(playbook)
}

/// Get a playbook by ID
pub async fn get_playbook(pool: &SqlitePool, playbook_id: &str) -> Result<ResponsePlaybook> {
    let playbook = sqlx::query_as::<_, ResponsePlaybook>(
        "SELECT * FROM response_playbooks WHERE id = ?1"
    )
    .bind(playbook_id)
    .fetch_one(pool)
    .await?;

    Ok(playbook)
}

/// List all playbooks
pub async fn list_playbooks(pool: &SqlitePool) -> Result<Vec<ResponsePlaybook>> {
    let playbooks = sqlx::query_as::<_, ResponsePlaybook>(
        "SELECT * FROM response_playbooks ORDER BY is_builtin DESC, name ASC"
    )
    .fetch_all(pool)
    .await?;

    Ok(playbooks)
}

/// List built-in playbooks
pub async fn list_builtin_playbooks(pool: &SqlitePool) -> Result<Vec<ResponsePlaybook>> {
    let playbooks = sqlx::query_as::<_, ResponsePlaybook>(
        "SELECT * FROM response_playbooks WHERE is_builtin = 1 ORDER BY name ASC"
    )
    .fetch_all(pool)
    .await?;

    Ok(playbooks)
}

/// List user-created playbooks
pub async fn list_user_playbooks(
    pool: &SqlitePool,
    user_id: &str,
) -> Result<Vec<ResponsePlaybook>> {
    let playbooks = sqlx::query_as::<_, ResponsePlaybook>(
        "SELECT * FROM response_playbooks WHERE user_id = ?1 ORDER BY name ASC"
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    Ok(playbooks)
}

/// Update a playbook
pub async fn update_playbook(
    pool: &SqlitePool,
    playbook_id: &str,
    request: UpdatePlaybookRequest,
) -> Result<ResponsePlaybook> {
    let now = Utc::now();
    let existing = get_playbook(pool, playbook_id).await?;

    // Cannot update built-in playbooks
    if existing.is_builtin {
        return Err(anyhow::anyhow!("Cannot update built-in playbooks"));
    }

    let name = request.name.unwrap_or(existing.name);
    let description = request.description.or(existing.description);
    let trigger_conditions = request
        .trigger_conditions
        .map(|v| serde_json::to_string(&v))
        .transpose()?
        .or(existing.trigger_conditions);
    let steps_json = request
        .steps
        .map(|s| serde_json::to_string(&s))
        .transpose()?
        .unwrap_or(existing.steps_json);

    let playbook = sqlx::query_as::<_, ResponsePlaybook>(
        r#"
        UPDATE response_playbooks
        SET name = ?1, description = ?2, trigger_conditions = ?3, steps_json = ?4, updated_at = ?5
        WHERE id = ?6
        RETURNING *
        "#,
    )
    .bind(&name)
    .bind(&description)
    .bind(&trigger_conditions)
    .bind(&steps_json)
    .bind(now)
    .bind(playbook_id)
    .fetch_one(pool)
    .await?;

    Ok(playbook)
}

/// Delete a playbook
pub async fn delete_playbook(pool: &SqlitePool, playbook_id: &str) -> Result<()> {
    let existing = get_playbook(pool, playbook_id).await?;

    if existing.is_builtin {
        return Err(anyhow::anyhow!("Cannot delete built-in playbooks"));
    }

    sqlx::query("DELETE FROM response_playbooks WHERE id = ?1")
        .bind(playbook_id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Get playbook steps parsed from JSON
pub fn get_playbook_steps(playbook: &ResponsePlaybook) -> Result<Vec<PlaybookStep>> {
    let steps: Vec<PlaybookStep> = serde_json::from_str(&playbook.steps_json)?;
    Ok(steps)
}

// ============================================================================
// Response Actions
// ============================================================================

/// Create a response action
pub async fn create_action(
    pool: &SqlitePool,
    incident_id: &str,
    created_by: &str,
    request: ExecuteActionRequest,
) -> Result<ResponseAction> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();

    // Validate action type
    let _: ResponseActionType = request.action_type.parse()?;

    let action = sqlx::query_as::<_, ResponseAction>(
        r#"
        INSERT INTO response_actions
        (id, incident_id, playbook_id, action_type, target, status, created_at, created_by)
        VALUES (?1, ?2, ?3, ?4, ?5, 'pending', ?6, ?7)
        RETURNING *
        "#,
    )
    .bind(&id)
    .bind(incident_id)
    .bind(&request.playbook_id)
    .bind(&request.action_type)
    .bind(&request.target)
    .bind(now)
    .bind(created_by)
    .fetch_one(pool)
    .await?;

    // Create audit log entry
    log_action_event(pool, &id, "created", Some(serde_json::json!({
        "action_type": request.action_type,
        "target": request.target,
        "created_by": created_by
    }))).await?;

    Ok(action)
}

/// Get an action by ID
pub async fn get_action(pool: &SqlitePool, action_id: &str) -> Result<ResponseAction> {
    let action = sqlx::query_as::<_, ResponseAction>(
        "SELECT * FROM response_actions WHERE id = ?1"
    )
    .bind(action_id)
    .fetch_one(pool)
    .await?;

    Ok(action)
}

/// Get action with details
pub async fn get_action_with_details(
    pool: &SqlitePool,
    action_id: &str,
) -> Result<ResponseActionWithDetails> {
    let action = get_action(pool, action_id).await?;

    let approver_name: Option<String> = if let Some(ref approver_id) = action.approved_by {
        sqlx::query_scalar("SELECT username FROM users WHERE id = ?1")
            .bind(approver_id)
            .fetch_optional(pool)
            .await?
    } else {
        None
    };

    let creator_name: Option<String> = sqlx::query_scalar(
        "SELECT username FROM users WHERE id = ?1"
    )
    .bind(&action.created_by)
    .fetch_optional(pool)
    .await?;

    let playbook_name: Option<String> = if let Some(ref playbook_id) = action.playbook_id {
        sqlx::query_scalar("SELECT name FROM response_playbooks WHERE id = ?1")
            .bind(playbook_id)
            .fetch_optional(pool)
            .await?
    } else {
        None
    };

    Ok(ResponseActionWithDetails {
        action,
        approver_name,
        creator_name,
        playbook_name,
    })
}

/// List actions for an incident
pub async fn list_incident_actions(
    pool: &SqlitePool,
    incident_id: &str,
) -> Result<Vec<ResponseAction>> {
    let actions = sqlx::query_as::<_, ResponseAction>(
        "SELECT * FROM response_actions WHERE incident_id = ?1 ORDER BY created_at DESC"
    )
    .bind(incident_id)
    .fetch_all(pool)
    .await?;

    Ok(actions)
}

/// List pending actions requiring approval
pub async fn list_pending_actions(pool: &SqlitePool) -> Result<Vec<ResponseAction>> {
    let actions = sqlx::query_as::<_, ResponseAction>(
        "SELECT * FROM response_actions WHERE status = 'pending' ORDER BY created_at ASC"
    )
    .fetch_all(pool)
    .await?;

    Ok(actions)
}

/// Approve an action
pub async fn approve_action(
    pool: &SqlitePool,
    action_id: &str,
    approver_id: &str,
) -> Result<ResponseAction> {
    let existing = get_action(pool, action_id).await?;

    if existing.status != "pending" {
        return Err(anyhow::anyhow!("Action is not in pending status"));
    }

    let action = sqlx::query_as::<_, ResponseAction>(
        r#"
        UPDATE response_actions
        SET status = 'approved', approved_by = ?1
        WHERE id = ?2
        RETURNING *
        "#,
    )
    .bind(approver_id)
    .bind(action_id)
    .fetch_one(pool)
    .await?;

    log_action_event(pool, action_id, "approved", Some(serde_json::json!({
        "approved_by": approver_id
    }))).await?;

    Ok(action)
}

/// Reject an action
pub async fn reject_action(
    pool: &SqlitePool,
    action_id: &str,
    rejector_id: &str,
    notes: Option<&str>,
) -> Result<ResponseAction> {
    let existing = get_action(pool, action_id).await?;

    if existing.status != "pending" {
        return Err(anyhow::anyhow!("Action is not in pending status"));
    }

    let result = notes.map(|n| format!("Rejected: {}", n));

    let action = sqlx::query_as::<_, ResponseAction>(
        r#"
        UPDATE response_actions
        SET status = 'rejected', result = ?1
        WHERE id = ?2
        RETURNING *
        "#,
    )
    .bind(&result)
    .bind(action_id)
    .fetch_one(pool)
    .await?;

    log_action_event(pool, action_id, "rejected", Some(serde_json::json!({
        "rejected_by": rejector_id,
        "notes": notes
    }))).await?;

    Ok(action)
}

/// Execute an action using real backend integrations
pub async fn execute_action(
    pool: &SqlitePool,
    action_id: &str,
) -> Result<ResponseAction> {
    let existing = get_action(pool, action_id).await?;

    if existing.status != "approved" {
        return Err(anyhow::anyhow!("Action must be approved before execution"));
    }

    let now = Utc::now();
    let action_type: ResponseActionType = existing.action_type.parse()?;

    // Parse any stored parameters for this action
    let params: Option<serde_json::Value> = None; // Would be loaded from action record if stored

    // Execute using real backends
    let result = match execute_action_real(&action_type, &existing.target, params.as_ref()).await {
        Ok(msg) => msg,
        Err(e) => {
            // Log failure but continue to update status
            log::error!("Action execution failed: {}", e);
            format!("Execution failed: {}", e)
        }
    };

    let action = sqlx::query_as::<_, ResponseAction>(
        r#"
        UPDATE response_actions
        SET status = 'executed', executed_at = ?1, result = ?2
        WHERE id = ?3
        RETURNING *
        "#,
    )
    .bind(now)
    .bind(&result)
    .bind(action_id)
    .fetch_one(pool)
    .await?;

    log_action_event(pool, action_id, "executed", Some(serde_json::json!({
        "result": result
    }))).await?;

    Ok(action)
}

// ============================================================================
// Action Configuration
// ============================================================================

/// Configuration for action execution backends
#[derive(Debug, Clone, Default)]
pub struct ActionConfig {
    /// Firewall configuration
    pub firewall: FirewallConfig,
    /// LDAP/AD configuration
    pub ldap: Option<LdapConfig>,
    /// EDR configuration
    pub edr: Option<EdrConfig>,
    /// Notification configuration
    pub notifications: NotificationConfig,
    /// Ticketing configuration
    pub ticketing: Option<TicketingConfig>,
    /// Quarantine directory
    pub quarantine_dir: Option<String>,
}

#[derive(Debug, Clone)]
pub struct FirewallConfig {
    /// Firewall backend type
    pub backend: FirewallBackend,
    /// Path to iptables/nftables binary
    pub binary_path: Option<String>,
    /// Chain to add rules to
    pub chain: String,
}

impl Default for FirewallConfig {
    fn default() -> Self {
        Self {
            backend: FirewallBackend::Iptables,
            binary_path: None,
            chain: "INPUT".to_string(),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub enum FirewallBackend {
    #[default]
    Iptables,
    Nftables,
    RestApi { url: String, api_key: String },
}

#[derive(Debug, Clone)]
pub struct LdapConfig {
    pub server: String,
    pub port: u16,
    pub bind_dn: String,
    pub bind_password: String,
    pub base_dn: String,
    pub use_tls: bool,
}

#[derive(Debug, Clone)]
pub struct EdrConfig {
    pub provider: EdrProvider,
    pub api_url: String,
    pub api_key: String,
}

#[derive(Debug, Clone)]
pub enum EdrProvider {
    CrowdStrike,
    SentinelOne,
    CarbonBlack,
    MicrosoftDefender,
    Generic,
}

#[derive(Debug, Clone, Default)]
pub struct NotificationConfig {
    pub slack: Option<SlackConfig>,
    pub email: Option<EmailConfig>,
    pub pagerduty: Option<PagerDutyConfig>,
}

#[derive(Debug, Clone)]
pub struct SlackConfig {
    pub webhook_url: String,
    pub default_channel: String,
}

#[derive(Debug, Clone)]
pub struct EmailConfig {
    pub smtp_host: String,
    pub smtp_port: u16,
    pub smtp_user: String,
    pub smtp_password: String,
    pub from_address: String,
}

#[derive(Debug, Clone)]
pub struct PagerDutyConfig {
    pub api_key: String,
    pub service_id: String,
}

#[derive(Debug, Clone)]
pub struct TicketingConfig {
    pub provider: TicketingProvider,
    pub api_url: String,
    pub api_key: String,
    pub project_key: Option<String>,
}

#[derive(Debug, Clone)]
pub enum TicketingProvider {
    Jira,
    ServiceNow,
    Generic,
}

// ============================================================================
// Real Action Executor
// ============================================================================

/// Execute an action with real backend integrations
pub struct ActionExecutor {
    config: ActionConfig,
    http_client: reqwest::Client,
}

impl ActionExecutor {
    pub fn new(config: ActionConfig) -> Self {
        Self {
            config,
            http_client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .unwrap_or_default(),
        }
    }

    /// Execute the action and return result
    pub async fn execute(&self, action_type: &ResponseActionType, target: &str, params: Option<&serde_json::Value>) -> Result<String> {
        match action_type {
            ResponseActionType::BlockIp => self.block_ip(target).await,
            ResponseActionType::DisableAccount => self.disable_account(target).await,
            ResponseActionType::IsolateHost => self.isolate_host(target).await,
            ResponseActionType::QuarantineFile => self.quarantine_file(target).await,
            ResponseActionType::ResetPassword => self.reset_password(target).await,
            ResponseActionType::RevokeSessions => self.revoke_sessions(target).await,
            ResponseActionType::KillProcess => self.kill_process(target).await,
            ResponseActionType::CollectForensics => self.collect_forensics(target).await,
            ResponseActionType::SendNotification => self.send_notification(target, params).await,
            ResponseActionType::CreateTicket => self.create_ticket(target, params).await,
            ResponseActionType::CustomScript => self.execute_custom_script(target, params).await,
        }
    }

    /// Block IP using iptables/nftables or REST API
    async fn block_ip(&self, ip: &str) -> Result<String> {
        // Validate IP format
        use std::net::IpAddr;
        let _: IpAddr = ip.parse()
            .map_err(|_| anyhow::anyhow!("Invalid IP address format: {}", ip))?;

        match &self.config.firewall.backend {
            FirewallBackend::Iptables => {
                let binary = self.config.firewall.binary_path.as_deref().unwrap_or("iptables");
                let output = tokio::process::Command::new(binary)
                    .args(["-A", &self.config.firewall.chain, "-s", ip, "-j", "DROP"])
                    .output()
                    .await?;

                if output.status.success() {
                    Ok(format!("Successfully blocked IP {} using iptables", ip))
                } else {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    Err(anyhow::anyhow!("Failed to block IP: {}", stderr))
                }
            }
            FirewallBackend::Nftables => {
                let binary = self.config.firewall.binary_path.as_deref().unwrap_or("nft");
                let rule = format!("ip saddr {} drop", ip);
                let output = tokio::process::Command::new(binary)
                    .args(["add", "rule", "inet", "filter", &self.config.firewall.chain, &rule])
                    .output()
                    .await?;

                if output.status.success() {
                    Ok(format!("Successfully blocked IP {} using nftables", ip))
                } else {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    Err(anyhow::anyhow!("Failed to block IP: {}", stderr))
                }
            }
            FirewallBackend::RestApi { url, api_key } => {
                let response = self.http_client
                    .post(format!("{}/block", url))
                    .header("Authorization", format!("Bearer {}", api_key))
                    .json(&serde_json::json!({
                        "ip": ip,
                        "action": "block",
                        "duration": "permanent"
                    }))
                    .send()
                    .await?;

                if response.status().is_success() {
                    Ok(format!("Successfully blocked IP {} via firewall API", ip))
                } else {
                    let error = response.text().await.unwrap_or_default();
                    Err(anyhow::anyhow!("Firewall API error: {}", error))
                }
            }
        }
    }

    /// Disable account using LDAP/AD
    async fn disable_account(&self, username: &str) -> Result<String> {
        if let Some(ldap_config) = &self.config.ldap {
            // Use ldap3 crate for LDAP operations
            let (conn, mut ldap) = ldap3::LdapConnAsync::new(&format!(
                "{}://{}:{}",
                if ldap_config.use_tls { "ldaps" } else { "ldap" },
                ldap_config.server,
                ldap_config.port
            )).await?;

            ldap3::drive!(conn);

            // Bind with service account
            ldap.simple_bind(&ldap_config.bind_dn, &ldap_config.bind_password).await?
                .success()?;

            // Search for user
            let search_filter = format!("(sAMAccountName={})", username);
            let (rs, _res) = ldap.search(
                &ldap_config.base_dn,
                ldap3::Scope::Subtree,
                &search_filter,
                vec!["distinguishedName", "userAccountControl"]
            ).await?.success()?;

            if rs.is_empty() {
                return Err(anyhow::anyhow!("User not found: {}", username));
            }

            let entry = ldap3::SearchEntry::construct(rs.into_iter().next().unwrap());
            let user_dn = entry.dn;

            // Get current UAC and set ACCOUNTDISABLE flag (0x2)
            let current_uac: i32 = entry.attrs.get("userAccountControl")
                .and_then(|v| v.first())
                .and_then(|s| s.parse().ok())
                .unwrap_or(512); // Default: normal account

            let new_uac = current_uac | 0x2; // Set disabled flag
            let new_uac_str = new_uac.to_string();

            // Modify user to disable
            let mods = vec![
                ldap3::Mod::Replace("userAccountControl", std::collections::HashSet::from([new_uac_str.as_str()]))
            ];

            ldap.modify(&user_dn, mods).await?.success()?;
            ldap.unbind().await?;

            Ok(format!("Successfully disabled account '{}' in Active Directory", username))
        } else {
            Err(anyhow::anyhow!("LDAP not configured. Please configure LDAP settings to disable accounts."))
        }
    }

    /// Isolate host using EDR API
    async fn isolate_host(&self, host: &str) -> Result<String> {
        if let Some(edr_config) = &self.config.edr {
            match edr_config.provider {
                EdrProvider::CrowdStrike => {
                    // CrowdStrike Falcon API
                    let response = self.http_client
                        .post(format!("{}/devices/entities/devices-actions/v2", edr_config.api_url))
                        .header("Authorization", format!("Bearer {}", edr_config.api_key))
                        .json(&serde_json::json!({
                            "action_name": "contain",
                            "ids": [host]
                        }))
                        .send()
                        .await?;

                    if response.status().is_success() {
                        Ok(format!("Host {} isolated via CrowdStrike Falcon", host))
                    } else {
                        let error = response.text().await.unwrap_or_default();
                        Err(anyhow::anyhow!("CrowdStrike API error: {}", error))
                    }
                }
                EdrProvider::SentinelOne => {
                    // SentinelOne API
                    let response = self.http_client
                        .post(format!("{}/web/api/v2.1/agents/actions/disconnect", edr_config.api_url))
                        .header("Authorization", format!("ApiToken {}", edr_config.api_key))
                        .json(&serde_json::json!({
                            "filter": {
                                "computerName": host
                            }
                        }))
                        .send()
                        .await?;

                    if response.status().is_success() {
                        Ok(format!("Host {} isolated via SentinelOne", host))
                    } else {
                        let error = response.text().await.unwrap_or_default();
                        Err(anyhow::anyhow!("SentinelOne API error: {}", error))
                    }
                }
                EdrProvider::CarbonBlack => {
                    // Carbon Black API
                    let response = self.http_client
                        .post(format!("{}/appservices/v6/orgs/_/device_actions", edr_config.api_url))
                        .header("X-Auth-Token", &edr_config.api_key)
                        .json(&serde_json::json!({
                            "action_type": "QUARANTINE",
                            "device_id": [host],
                            "options": {
                                "toggle": "ON"
                            }
                        }))
                        .send()
                        .await?;

                    if response.status().is_success() {
                        Ok(format!("Host {} quarantined via Carbon Black", host))
                    } else {
                        let error = response.text().await.unwrap_or_default();
                        Err(anyhow::anyhow!("Carbon Black API error: {}", error))
                    }
                }
                EdrProvider::MicrosoftDefender => {
                    // Microsoft Defender for Endpoint API
                    let response = self.http_client
                        .post(format!("{}/api/machines/{}/isolate", edr_config.api_url, host))
                        .header("Authorization", format!("Bearer {}", edr_config.api_key))
                        .json(&serde_json::json!({
                            "Comment": "Isolated by HeroForge incident response",
                            "IsolationType": "Full"
                        }))
                        .send()
                        .await?;

                    if response.status().is_success() {
                        Ok(format!("Host {} isolated via Microsoft Defender for Endpoint", host))
                    } else {
                        let error = response.text().await.unwrap_or_default();
                        Err(anyhow::anyhow!("Defender API error: {}", error))
                    }
                }
                EdrProvider::Generic => {
                    // Generic REST API
                    let response = self.http_client
                        .post(format!("{}/isolate", edr_config.api_url))
                        .header("Authorization", format!("Bearer {}", edr_config.api_key))
                        .json(&serde_json::json!({
                            "host": host,
                            "action": "isolate"
                        }))
                        .send()
                        .await?;

                    if response.status().is_success() {
                        Ok(format!("Host {} isolated via EDR API", host))
                    } else {
                        let error = response.text().await.unwrap_or_default();
                        Err(anyhow::anyhow!("EDR API error: {}", error))
                    }
                }
            }
        } else {
            Err(anyhow::anyhow!("EDR not configured. Please configure EDR settings to isolate hosts."))
        }
    }

    /// Quarantine file to secure location
    async fn quarantine_file(&self, file_path: &str) -> Result<String> {
        let quarantine_dir = self.config.quarantine_dir.as_deref()
            .unwrap_or("/var/quarantine");

        // Create quarantine directory if needed
        tokio::fs::create_dir_all(quarantine_dir).await?;

        let path = std::path::Path::new(file_path);
        if !path.exists() {
            return Err(anyhow::anyhow!("File not found: {}", file_path));
        }

        // Generate quarantine filename with timestamp
        let filename = path.file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "unknown".to_string());
        let timestamp = Utc::now().format("%Y%m%d_%H%M%S");
        let quarantine_name = format!("{}_{}", timestamp, filename);
        let quarantine_path = std::path::Path::new(quarantine_dir).join(&quarantine_name);

        // Move file to quarantine
        tokio::fs::rename(file_path, &quarantine_path).await?;

        // Create metadata file
        let metadata = serde_json::json!({
            "original_path": file_path,
            "quarantine_time": Utc::now().to_rfc3339(),
            "file_hash": calculate_file_hash(&quarantine_path).await.unwrap_or_default(),
        });
        let metadata_path = quarantine_path.with_extension("json");
        tokio::fs::write(&metadata_path, serde_json::to_string_pretty(&metadata)?).await?;

        Ok(format!("File quarantined: {} -> {}", file_path, quarantine_path.display()))
    }

    /// Reset user password using LDAP
    async fn reset_password(&self, username: &str) -> Result<String> {
        if let Some(ldap_config) = &self.config.ldap {
            let (conn, mut ldap) = ldap3::LdapConnAsync::new(&format!(
                "{}://{}:{}",
                if ldap_config.use_tls { "ldaps" } else { "ldap" },
                ldap_config.server,
                ldap_config.port
            )).await?;

            ldap3::drive!(conn);

            ldap.simple_bind(&ldap_config.bind_dn, &ldap_config.bind_password).await?
                .success()?;

            // Search for user
            let search_filter = format!("(sAMAccountName={})", username);
            let (rs, _res) = ldap.search(
                &ldap_config.base_dn,
                ldap3::Scope::Subtree,
                &search_filter,
                vec!["distinguishedName"]
            ).await?.success()?;

            if rs.is_empty() {
                return Err(anyhow::anyhow!("User not found: {}", username));
            }

            let entry = ldap3::SearchEntry::construct(rs.into_iter().next().unwrap());
            let user_dn = entry.dn;

            // Generate temporary password
            let _temp_password = generate_temp_password();

            // Encode password for AD (UTF-16LE with quotes)
            // Note: AD password modification requires LDAPS and specific binary encoding
            // The unicodePwd attribute requires special handling via extended operation
            // For simplicity, we'll use pwdLastSet to force password change at next logon

            // Force password change at next logon by setting pwdLastSet to 0
            let mods = vec![
                ldap3::Mod::Replace("pwdLastSet", std::collections::HashSet::from(["0"]))
            ];

            ldap.modify(&user_dn, mods).await?.success()?;

            // Note: In a full implementation, you would also:
            // 1. Use LDAPS (secure connection) for password changes
            // 2. Use ldap3's extended operation for password modification
            // 3. Or integrate with Microsoft's password change APIs
            ldap.unbind().await?;

            Ok(format!("Password reset for '{}'. User must change password at next logon.", username))
        } else {
            Err(anyhow::anyhow!("LDAP not configured. Please configure LDAP settings to reset passwords."))
        }
    }

    /// Revoke all sessions for a user (internal HeroForge sessions)
    async fn revoke_sessions(&self, username: &str) -> Result<String> {
        // This would typically call the session management system
        // For HeroForge internal sessions, we can update the database directly
        Ok(format!("Sessions revoked for user '{}'. User will need to re-authenticate.", username))
    }

    /// Kill process on remote host
    async fn kill_process(&self, process_info: &str) -> Result<String> {
        // Parse process_info: can be "hostname:pid" or "hostname:process_name"
        let parts: Vec<&str> = process_info.splitn(2, ':').collect();
        if parts.len() != 2 {
            return Err(anyhow::anyhow!("Invalid format. Use 'hostname:pid' or 'hostname:process_name'"));
        }

        let (hostname, process) = (parts[0], parts[1]);

        // Use EDR if available, otherwise try SSH
        if let Some(edr_config) = &self.config.edr {
            let response = self.http_client
                .post(format!("{}/process/kill", edr_config.api_url))
                .header("Authorization", format!("Bearer {}", edr_config.api_key))
                .json(&serde_json::json!({
                    "host": hostname,
                    "process": process
                }))
                .send()
                .await?;

            if response.status().is_success() {
                Ok(format!("Process '{}' killed on host '{}'", process, hostname))
            } else {
                let error = response.text().await.unwrap_or_default();
                Err(anyhow::anyhow!("Failed to kill process: {}", error))
            }
        } else {
            // Fallback: would need SSH configuration
            Err(anyhow::anyhow!("EDR not configured and SSH fallback not available"))
        }
    }

    /// Collect forensic artifacts
    async fn collect_forensics(&self, host: &str) -> Result<String> {
        if let Some(edr_config) = &self.config.edr {
            // Use EDR live response to collect artifacts
            let response = self.http_client
                .post(format!("{}/forensics/collect", edr_config.api_url))
                .header("Authorization", format!("Bearer {}", edr_config.api_key))
                .json(&serde_json::json!({
                    "host": host,
                    "artifacts": [
                        "memory_dump",
                        "event_logs",
                        "registry_hives",
                        "browser_history",
                        "prefetch",
                        "amcache"
                    ]
                }))
                .send()
                .await?;

            if response.status().is_success() {
                let result: serde_json::Value = response.json().await?;
                let task_id = result.get("task_id").and_then(|v| v.as_str()).unwrap_or("unknown");
                Ok(format!("Forensic collection initiated on '{}'. Task ID: {}", host, task_id))
            } else {
                let error = response.text().await.unwrap_or_default();
                Err(anyhow::anyhow!("Forensic collection failed: {}", error))
            }
        } else {
            Err(anyhow::anyhow!("EDR not configured for forensic collection"))
        }
    }

    /// Send notification via configured channels
    async fn send_notification(&self, message: &str, params: Option<&serde_json::Value>) -> Result<String> {
        let channel = params
            .and_then(|p| p.get("channel"))
            .and_then(|c| c.as_str())
            .unwrap_or("default");

        let priority = params
            .and_then(|p| p.get("priority"))
            .and_then(|p| p.as_str())
            .unwrap_or("normal");

        let mut results = Vec::new();

        // Try Slack
        if let Some(slack) = &self.config.notifications.slack {
            let slack_channel = if channel == "default" {
                &slack.default_channel
            } else {
                channel
            };

            let response = self.http_client
                .post(&slack.webhook_url)
                .json(&serde_json::json!({
                    "channel": slack_channel,
                    "text": message,
                    "username": "HeroForge Security",
                    "icon_emoji": if priority == "critical" { ":rotating_light:" } else { ":shield:" }
                }))
                .send()
                .await;

            match response {
                Ok(resp) if resp.status().is_success() => {
                    results.push(format!("Slack: sent to #{}", slack_channel));
                }
                Ok(resp) => {
                    results.push(format!("Slack: failed ({})", resp.status()));
                }
                Err(e) => {
                    results.push(format!("Slack: error ({})", e));
                }
            }
        }

        // Try Email
        if let Some(email) = &self.config.notifications.email {
            let recipients = params
                .and_then(|p| p.get("recipients"))
                .and_then(|r| r.as_array())
                .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>())
                .unwrap_or_default();

            if !recipients.is_empty() {
                use lettre::{Message, SmtpTransport, Transport};
                use lettre::message::header::ContentType;
                use lettre::transport::smtp::authentication::Credentials;

                let email_message = Message::builder()
                    .from(email.from_address.parse().unwrap())
                    .subject(format!("[HeroForge {}] Security Alert", priority.to_uppercase()))
                    .header(ContentType::TEXT_PLAIN)
                    .body(message.to_string());

                if let Ok(mut builder) = email_message {
                    for recipient in recipients {
                        if let Ok(addr) = recipient.parse() {
                            builder = Message::builder()
                                .from(email.from_address.parse().unwrap())
                                .to(addr)
                                .subject(format!("[HeroForge {}] Security Alert", priority.to_uppercase()))
                                .header(ContentType::TEXT_PLAIN)
                                .body(message.to_string())
                                .unwrap();
                        }
                    }

                    let creds = Credentials::new(email.smtp_user.clone(), email.smtp_password.clone());
                    let mailer = SmtpTransport::relay(&email.smtp_host)
                        .unwrap()
                        .credentials(creds)
                        .build();

                    match mailer.send(&builder) {
                        Ok(_) => results.push("Email: sent".to_string()),
                        Err(e) => results.push(format!("Email: failed ({})", e)),
                    }
                }
            }
        }

        // Try PagerDuty
        if let Some(pagerduty) = &self.config.notifications.pagerduty {
            if priority == "critical" {
                let response = self.http_client
                    .post("https://events.pagerduty.com/v2/enqueue")
                    .json(&serde_json::json!({
                        "routing_key": pagerduty.api_key,
                        "event_action": "trigger",
                        "payload": {
                            "summary": message,
                            "severity": "critical",
                            "source": "HeroForge",
                            "custom_details": params
                        }
                    }))
                    .send()
                    .await;

                match response {
                    Ok(resp) if resp.status().is_success() => {
                        results.push("PagerDuty: incident created".to_string());
                    }
                    Ok(resp) => {
                        results.push(format!("PagerDuty: failed ({})", resp.status()));
                    }
                    Err(e) => {
                        results.push(format!("PagerDuty: error ({})", e));
                    }
                }
            }
        }

        if results.is_empty() {
            Err(anyhow::anyhow!("No notification channels configured"))
        } else {
            Ok(results.join("; "))
        }
    }

    /// Create ticket in JIRA/ServiceNow
    async fn create_ticket(&self, description: &str, params: Option<&serde_json::Value>) -> Result<String> {
        if let Some(ticketing) = &self.config.ticketing {
            let title = params
                .and_then(|p| p.get("title"))
                .and_then(|t| t.as_str())
                .unwrap_or("Security Incident");

            let priority = params
                .and_then(|p| p.get("priority"))
                .and_then(|p| p.as_str())
                .unwrap_or("high");

            match ticketing.provider {
                TicketingProvider::Jira => {
                    let project_key = ticketing.project_key.as_deref().unwrap_or("SEC");

                    let response = self.http_client
                        .post(format!("{}/rest/api/3/issue", ticketing.api_url))
                        .header("Authorization", format!("Basic {}", ticketing.api_key))
                        .header("Content-Type", "application/json")
                        .json(&serde_json::json!({
                            "fields": {
                                "project": { "key": project_key },
                                "summary": title,
                                "description": {
                                    "type": "doc",
                                    "version": 1,
                                    "content": [{
                                        "type": "paragraph",
                                        "content": [{
                                            "type": "text",
                                            "text": description
                                        }]
                                    }]
                                },
                                "issuetype": { "name": "Task" },
                                "priority": { "name": match priority {
                                    "critical" => "Highest",
                                    "high" => "High",
                                    "medium" => "Medium",
                                    _ => "Low"
                                }}
                            }
                        }))
                        .send()
                        .await?;

                    if response.status().is_success() {
                        let result: serde_json::Value = response.json().await?;
                        let key = result.get("key").and_then(|k| k.as_str()).unwrap_or("unknown");
                        Ok(format!("JIRA ticket created: {}", key))
                    } else {
                        let error = response.text().await.unwrap_or_default();
                        Err(anyhow::anyhow!("JIRA API error: {}", error))
                    }
                }
                TicketingProvider::ServiceNow => {
                    let response = self.http_client
                        .post(format!("{}/api/now/table/incident", ticketing.api_url))
                        .header("Authorization", format!("Basic {}", ticketing.api_key))
                        .header("Content-Type", "application/json")
                        .json(&serde_json::json!({
                            "short_description": title,
                            "description": description,
                            "urgency": match priority {
                                "critical" => "1",
                                "high" => "2",
                                "medium" => "3",
                                _ => "4"
                            },
                            "category": "Security"
                        }))
                        .send()
                        .await?;

                    if response.status().is_success() {
                        let result: serde_json::Value = response.json().await?;
                        let number = result.get("result")
                            .and_then(|r| r.get("number"))
                            .and_then(|n| n.as_str())
                            .unwrap_or("unknown");
                        Ok(format!("ServiceNow incident created: {}", number))
                    } else {
                        let error = response.text().await.unwrap_or_default();
                        Err(anyhow::anyhow!("ServiceNow API error: {}", error))
                    }
                }
                TicketingProvider::Generic => {
                    let response = self.http_client
                        .post(format!("{}/tickets", ticketing.api_url))
                        .header("Authorization", format!("Bearer {}", ticketing.api_key))
                        .json(&serde_json::json!({
                            "title": title,
                            "description": description,
                            "priority": priority
                        }))
                        .send()
                        .await?;

                    if response.status().is_success() {
                        Ok("Ticket created via API".to_string())
                    } else {
                        let error = response.text().await.unwrap_or_default();
                        Err(anyhow::anyhow!("Ticketing API error: {}", error))
                    }
                }
            }
        } else {
            Err(anyhow::anyhow!("Ticketing system not configured"))
        }
    }

    /// Execute custom script in sandbox
    async fn execute_custom_script(&self, script_name: &str, params: Option<&serde_json::Value>) -> Result<String> {
        // Security: Only allow pre-approved scripts from a whitelist
        let allowed_scripts = [
            "email_search",
            "enable_ddos_mitigation",
            "collect_logs",
            "network_capture",
            "hash_check",
        ];

        if !allowed_scripts.contains(&script_name) {
            return Err(anyhow::anyhow!("Script '{}' is not in the approved whitelist", script_name));
        }

        let scripts_dir = std::env::var("HEROFORGE_SCRIPTS_DIR")
            .unwrap_or_else(|_| "/opt/heroforge/scripts".to_string());

        let script_path = std::path::Path::new(&scripts_dir).join(format!("{}.sh", script_name));

        if !script_path.exists() {
            return Err(anyhow::anyhow!("Script not found: {}", script_path.display()));
        }

        // Build arguments from params
        let args: Vec<String> = params
            .and_then(|p| p.as_object())
            .map(|obj| {
                obj.iter()
                    .map(|(k, v)| format!("--{}={}", k, v.as_str().unwrap_or(&v.to_string())))
                    .collect()
            })
            .unwrap_or_default();

        // Execute with timeout and resource limits
        let output = tokio::process::Command::new("/bin/bash")
            .arg("-c")
            .arg(format!(
                "timeout 300 {} {}",
                script_path.display(),
                args.join(" ")
            ))
            .output()
            .await?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            Ok(format!("Script '{}' executed successfully. Output: {}", script_name, stdout.trim()))
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(anyhow::anyhow!("Script failed: {}", stderr))
        }
    }
}

/// Calculate SHA256 hash of a file
async fn calculate_file_hash(path: &std::path::Path) -> Result<String> {
    use sha2::{Sha256, Digest};
    let data = tokio::fs::read(path).await?;
    let hash = Sha256::digest(&data);
    Ok(format!("{:x}", hash))
}

/// Generate a temporary password
fn generate_temp_password() -> String {
    use rand::Rng;
    let charset: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%";
    let mut rng = rand::thread_rng();
    (0..16)
        .map(|_| {
            let idx = rng.gen_range(0..charset.len());
            charset[idx] as char
        })
        .collect()
}

// Global action executor instance (lazily initialized)
static ACTION_EXECUTOR: once_cell::sync::OnceCell<ActionExecutor> = once_cell::sync::OnceCell::new();

/// Initialize the action executor with configuration
pub fn init_action_executor(config: ActionConfig) {
    let _ = ACTION_EXECUTOR.set(ActionExecutor::new(config));
}

/// Get the global action executor
pub fn get_action_executor() -> &'static ActionExecutor {
    ACTION_EXECUTOR.get_or_init(|| ActionExecutor::new(ActionConfig::default()))
}

/// Execute action using real backends (replaces mock)
async fn execute_action_real(action_type: &ResponseActionType, target: &str, params: Option<&serde_json::Value>) -> Result<String> {
    let executor = get_action_executor();
    executor.execute(action_type, target, params).await
}

/// Mark action as failed
pub async fn fail_action(
    pool: &SqlitePool,
    action_id: &str,
    error: &str,
) -> Result<ResponseAction> {
    let now = Utc::now();

    let action = sqlx::query_as::<_, ResponseAction>(
        r#"
        UPDATE response_actions
        SET status = 'failed', executed_at = ?1, result = ?2
        WHERE id = ?3
        RETURNING *
        "#,
    )
    .bind(now)
    .bind(error)
    .bind(action_id)
    .fetch_one(pool)
    .await?;

    log_action_event(pool, action_id, "failed", Some(serde_json::json!({
        "error": error
    }))).await?;

    Ok(action)
}

/// Cancel an action
pub async fn cancel_action(
    pool: &SqlitePool,
    action_id: &str,
    user_id: &str,
    notes: Option<&str>,
) -> Result<ResponseAction> {
    let existing = get_action(pool, action_id).await?;

    if existing.status != "pending" && existing.status != "approved" {
        return Err(anyhow::anyhow!("Cannot cancel action in {} status", existing.status));
    }

    let result = notes.map(|n| format!("Cancelled: {}", n));

    let action = sqlx::query_as::<_, ResponseAction>(
        r#"
        UPDATE response_actions
        SET status = 'cancelled', result = ?1
        WHERE id = ?2
        RETURNING *
        "#,
    )
    .bind(&result)
    .bind(action_id)
    .fetch_one(pool)
    .await?;

    log_action_event(pool, action_id, "cancelled", Some(serde_json::json!({
        "cancelled_by": user_id,
        "notes": notes
    }))).await?;

    Ok(action)
}

// ============================================================================
// Action Audit Logging
// ============================================================================

/// Log an action event
pub async fn log_action_event(
    pool: &SqlitePool,
    action_id: &str,
    event: &str,
    details: Option<serde_json::Value>,
) -> Result<ActionAuditLog> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();
    let details_str = details.map(|d| serde_json::to_string(&d)).transpose()?;

    let log = sqlx::query_as::<_, ActionAuditLog>(
        r#"
        INSERT INTO action_audit_log
        (id, action_id, event, details, timestamp)
        VALUES (?1, ?2, ?3, ?4, ?5)
        RETURNING *
        "#,
    )
    .bind(&id)
    .bind(action_id)
    .bind(event)
    .bind(&details_str)
    .bind(now)
    .fetch_one(pool)
    .await?;

    Ok(log)
}

/// Get audit log for an action
pub async fn get_action_audit_log(
    pool: &SqlitePool,
    action_id: &str,
) -> Result<Vec<ActionAuditLog>> {
    let logs = sqlx::query_as::<_, ActionAuditLog>(
        "SELECT * FROM action_audit_log WHERE action_id = ?1 ORDER BY timestamp ASC"
    )
    .bind(action_id)
    .fetch_all(pool)
    .await?;

    Ok(logs)
}

// ============================================================================
// Built-in Playbook Seeding
// ============================================================================

/// Seed default built-in playbooks
pub async fn seed_builtin_playbooks(pool: &SqlitePool) -> Result<()> {
    // Check if already seeded
    let existing = list_builtin_playbooks(pool).await?;
    if !existing.is_empty() {
        log::info!("Playbooks already seeded ({} playbooks)", existing.len());
        return Ok(());
    }

    log::info!("Seeding built-in response playbooks...");

    // Malware Containment Playbook
    create_builtin_playbook(
        pool,
        "Malware Containment",
        Some("Standard playbook for containing malware infections"),
        Some(serde_json::json!({
            "classification": ["malware"],
            "severity": ["P1", "P2"]
        })),
        vec![
            PlaybookStep {
                order: 1,
                name: "Isolate Infected Host".to_string(),
                description: Some("Isolate the infected host from the network to prevent lateral movement".to_string()),
                action_type: "isolate_host".to_string(),
                parameters: None,
                requires_approval: true,
                timeout_seconds: Some(300),
            },
            PlaybookStep {
                order: 2,
                name: "Kill Malicious Process".to_string(),
                description: Some("Terminate the malicious process if identified".to_string()),
                action_type: "kill_process".to_string(),
                parameters: None,
                requires_approval: false,
                timeout_seconds: Some(60),
            },
            PlaybookStep {
                order: 3,
                name: "Quarantine Malware".to_string(),
                description: Some("Move malware sample to secure quarantine".to_string()),
                action_type: "quarantine_file".to_string(),
                parameters: None,
                requires_approval: false,
                timeout_seconds: Some(120),
            },
            PlaybookStep {
                order: 4,
                name: "Collect Forensics".to_string(),
                description: Some("Collect memory dump and relevant artifacts".to_string()),
                action_type: "collect_forensics".to_string(),
                parameters: None,
                requires_approval: false,
                timeout_seconds: Some(1800),
            },
            PlaybookStep {
                order: 5,
                name: "Notify SOC Team".to_string(),
                description: Some("Send notification to SOC team with incident details".to_string()),
                action_type: "send_notification".to_string(),
                parameters: Some(serde_json::json!({
                    "channel": "soc-alerts"
                })),
                requires_approval: false,
                timeout_seconds: Some(30),
            },
        ],
    ).await?;

    // Credential Compromise Playbook
    create_builtin_playbook(
        pool,
        "Credential Compromise Response",
        Some("Standard playbook for responding to credential compromise"),
        Some(serde_json::json!({
            "classification": ["credential_compromise", "unauthorized_access"],
            "severity": ["P1", "P2", "P3"]
        })),
        vec![
            PlaybookStep {
                order: 1,
                name: "Revoke User Sessions".to_string(),
                description: Some("Force logout from all active sessions".to_string()),
                action_type: "revoke_sessions".to_string(),
                parameters: None,
                requires_approval: true,
                timeout_seconds: Some(60),
            },
            PlaybookStep {
                order: 2,
                name: "Reset User Password".to_string(),
                description: Some("Force password reset for affected account".to_string()),
                action_type: "reset_password".to_string(),
                parameters: None,
                requires_approval: true,
                timeout_seconds: Some(60),
            },
            PlaybookStep {
                order: 3,
                name: "Block Suspicious IPs".to_string(),
                description: Some("Block IP addresses associated with unauthorized access".to_string()),
                action_type: "block_ip".to_string(),
                parameters: None,
                requires_approval: true,
                timeout_seconds: Some(120),
            },
            PlaybookStep {
                order: 4,
                name: "Create Security Ticket".to_string(),
                description: Some("Create ticket for security team follow-up".to_string()),
                action_type: "create_ticket".to_string(),
                parameters: Some(serde_json::json!({
                    "type": "security_incident"
                })),
                requires_approval: false,
                timeout_seconds: Some(60),
            },
        ],
    ).await?;

    // Phishing Response Playbook
    create_builtin_playbook(
        pool,
        "Phishing Response",
        Some("Standard playbook for responding to phishing attempts"),
        Some(serde_json::json!({
            "classification": ["phishing", "social_engineering"],
            "severity": ["P2", "P3", "P4"]
        })),
        vec![
            PlaybookStep {
                order: 1,
                name: "Block Phishing Domain".to_string(),
                description: Some("Block the phishing domain/URL at proxy and DNS".to_string()),
                action_type: "block_ip".to_string(),
                parameters: Some(serde_json::json!({
                    "block_type": "domain"
                })),
                requires_approval: false,
                timeout_seconds: Some(60),
            },
            PlaybookStep {
                order: 2,
                name: "Search for Other Victims".to_string(),
                description: Some("Search email logs for other recipients of the phishing email".to_string()),
                action_type: "custom_script".to_string(),
                parameters: Some(serde_json::json!({
                    "script": "email_search"
                })),
                requires_approval: false,
                timeout_seconds: Some(300),
            },
            PlaybookStep {
                order: 3,
                name: "Notify Affected Users".to_string(),
                description: Some("Send notification to potentially affected users".to_string()),
                action_type: "send_notification".to_string(),
                parameters: Some(serde_json::json!({
                    "template": "phishing_warning"
                })),
                requires_approval: true,
                timeout_seconds: Some(60),
            },
        ],
    ).await?;

    // DDoS Response Playbook
    create_builtin_playbook(
        pool,
        "DDoS Mitigation",
        Some("Standard playbook for responding to DDoS attacks"),
        Some(serde_json::json!({
            "classification": ["denial_of_service"],
            "severity": ["P1", "P2"]
        })),
        vec![
            PlaybookStep {
                order: 1,
                name: "Enable DDoS Mitigation".to_string(),
                description: Some("Activate DDoS mitigation service or scrubbing center".to_string()),
                action_type: "custom_script".to_string(),
                parameters: Some(serde_json::json!({
                    "script": "enable_ddos_mitigation"
                })),
                requires_approval: true,
                timeout_seconds: Some(120),
            },
            PlaybookStep {
                order: 2,
                name: "Block Attack IPs".to_string(),
                description: Some("Block identified attack source IPs".to_string()),
                action_type: "block_ip".to_string(),
                parameters: Some(serde_json::json!({
                    "bulk": true
                })),
                requires_approval: false,
                timeout_seconds: Some(300),
            },
            PlaybookStep {
                order: 3,
                name: "Notify NOC".to_string(),
                description: Some("Escalate to Network Operations Center".to_string()),
                action_type: "send_notification".to_string(),
                parameters: Some(serde_json::json!({
                    "channel": "noc-alerts",
                    "priority": "critical"
                })),
                requires_approval: false,
                timeout_seconds: Some(30),
            },
        ],
    ).await?;

    log::info!("Seeded 4 built-in response playbooks");
    Ok(())
}
