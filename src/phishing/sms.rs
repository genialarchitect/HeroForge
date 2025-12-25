//! SMS Phishing (Smishing) Module
//!
//! Full-featured SMS phishing campaign management for security awareness training
//! and authorized penetration testing.
//!
//! # Features
//!
//! - SMS template builder with variable substitution
//! - Twilio API integration for SMS delivery
//! - Link tracking in SMS messages
//! - Delivery status tracking
//! - Rate limiting to avoid carrier blocks
//! - Campaign scheduling
//!
//! # Security Notice
//!
//! This module is intended for:
//! - Security awareness training programs
//! - Authorized penetration testing engagements
//! - Red team assessments with proper authorization
//!
//! Unauthorized SMS phishing (smishing) is illegal. Always obtain proper authorization.

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::collections::HashMap;
use std::time::Duration;
use uuid::Uuid;

use super::types::{generate_tracking_id, CampaignStatus, TargetStatus};

// ============================================================================
// SMS Provider Trait and Implementations
// ============================================================================

/// Trait for SMS provider abstraction
#[async_trait]
pub trait SmsClient: Send + Sync {
    /// Send an SMS message
    async fn send_sms(&self, to: &str, from: &str, body: &str) -> Result<SmsDeliveryResult>;

    /// Check delivery status of a message
    async fn get_delivery_status(&self, message_sid: &str) -> Result<SmsDeliveryStatus>;

    /// Test connection to the SMS provider
    async fn test_connection(&self) -> Result<bool>;
}

/// Result of an SMS delivery attempt
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmsDeliveryResult {
    pub message_sid: String,
    pub status: SmsDeliveryStatus,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
}

/// SMS delivery status
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SmsDeliveryStatus {
    Queued,
    Sending,
    Sent,
    Delivered,
    Undelivered,
    Failed,
    Unknown,
}

impl std::fmt::Display for SmsDeliveryStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SmsDeliveryStatus::Queued => write!(f, "queued"),
            SmsDeliveryStatus::Sending => write!(f, "sending"),
            SmsDeliveryStatus::Sent => write!(f, "sent"),
            SmsDeliveryStatus::Delivered => write!(f, "delivered"),
            SmsDeliveryStatus::Undelivered => write!(f, "undelivered"),
            SmsDeliveryStatus::Failed => write!(f, "failed"),
            SmsDeliveryStatus::Unknown => write!(f, "unknown"),
        }
    }
}

impl std::str::FromStr for SmsDeliveryStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "queued" => Ok(SmsDeliveryStatus::Queued),
            "sending" => Ok(SmsDeliveryStatus::Sending),
            "sent" => Ok(SmsDeliveryStatus::Sent),
            "delivered" => Ok(SmsDeliveryStatus::Delivered),
            "undelivered" => Ok(SmsDeliveryStatus::Undelivered),
            "failed" => Ok(SmsDeliveryStatus::Failed),
            _ => Ok(SmsDeliveryStatus::Unknown),
        }
    }
}

// ============================================================================
// Twilio Client Implementation
// ============================================================================

/// Twilio SMS provider configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TwilioConfig {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub account_sid: String,
    #[serde(skip_serializing)]
    pub auth_token: String,
    pub from_number: String,
    pub messaging_service_sid: Option<String>,
    pub rate_limit_per_second: u32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Twilio SMS client implementation
#[derive(Clone)]
pub struct TwilioClient {
    account_sid: String,
    auth_token: String,
    from_number: String,
    messaging_service_sid: Option<String>,
    http_client: reqwest::Client,
    rate_limit_per_second: u32,
}

impl TwilioClient {
    pub fn new(config: &TwilioConfig) -> Self {
        Self {
            account_sid: config.account_sid.clone(),
            auth_token: config.auth_token.clone(),
            from_number: config.from_number.clone(),
            messaging_service_sid: config.messaging_service_sid.clone(),
            http_client: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .unwrap_or_default(),
            rate_limit_per_second: config.rate_limit_per_second,
        }
    }

    /// Build the Twilio API URL for sending messages
    fn messages_url(&self) -> String {
        format!(
            "https://api.twilio.com/2010-04-01/Accounts/{}/Messages.json",
            self.account_sid
        )
    }

    /// Build the Twilio API URL for fetching a message
    fn message_url(&self, message_sid: &str) -> String {
        format!(
            "https://api.twilio.com/2010-04-01/Accounts/{}/Messages/{}.json",
            self.account_sid, message_sid
        )
    }
}

#[async_trait]
impl SmsClient for TwilioClient {
    async fn send_sms(&self, to: &str, from: &str, body: &str) -> Result<SmsDeliveryResult> {
        let mut params = vec![
            ("To", to.to_string()),
            ("Body", body.to_string()),
        ];

        // Use messaging service SID if configured, otherwise use from number
        if let Some(ref service_sid) = self.messaging_service_sid {
            params.push(("MessagingServiceSid", service_sid.clone()));
        } else {
            params.push(("From", from.to_string()));
        }

        let response = self
            .http_client
            .post(&self.messages_url())
            .basic_auth(&self.account_sid, Some(&self.auth_token))
            .form(&params)
            .send()
            .await
            .map_err(|e| anyhow!("Failed to send SMS: {}", e))?;

        let status_code = response.status();
        let response_text = response.text().await.unwrap_or_default();

        if status_code.is_success() {
            let response_json: serde_json::Value = serde_json::from_str(&response_text)
                .map_err(|e| anyhow!("Failed to parse Twilio response: {}", e))?;

            let message_sid = response_json["sid"]
                .as_str()
                .unwrap_or("unknown")
                .to_string();

            let status_str = response_json["status"].as_str().unwrap_or("queued");
            let status = status_str.parse().unwrap_or(SmsDeliveryStatus::Queued);

            Ok(SmsDeliveryResult {
                message_sid,
                status,
                error_code: None,
                error_message: None,
            })
        } else {
            let error_json: serde_json::Value = serde_json::from_str(&response_text)
                .unwrap_or_else(|_| serde_json::json!({}));

            let error_code = error_json["code"].as_i64().map(|c| c.to_string());
            let error_message = error_json["message"].as_str().map(String::from);

            Ok(SmsDeliveryResult {
                message_sid: String::new(),
                status: SmsDeliveryStatus::Failed,
                error_code,
                error_message,
            })
        }
    }

    async fn get_delivery_status(&self, message_sid: &str) -> Result<SmsDeliveryStatus> {
        let response = self
            .http_client
            .get(&self.message_url(message_sid))
            .basic_auth(&self.account_sid, Some(&self.auth_token))
            .send()
            .await
            .map_err(|e| anyhow!("Failed to fetch message status: {}", e))?;

        if response.status().is_success() {
            let response_json: serde_json::Value = response
                .json()
                .await
                .map_err(|e| anyhow!("Failed to parse status response: {}", e))?;

            let status_str = response_json["status"].as_str().unwrap_or("unknown");
            Ok(status_str.parse().unwrap_or(SmsDeliveryStatus::Unknown))
        } else {
            Err(anyhow!("Failed to fetch message status: HTTP {}", response.status()))
        }
    }

    async fn test_connection(&self) -> Result<bool> {
        // Try to fetch account info to verify credentials
        let url = format!(
            "https://api.twilio.com/2010-04-01/Accounts/{}.json",
            self.account_sid
        );

        let response = self
            .http_client
            .get(&url)
            .basic_auth(&self.account_sid, Some(&self.auth_token))
            .send()
            .await
            .map_err(|e| anyhow!("Failed to connect to Twilio: {}", e))?;

        Ok(response.status().is_success())
    }
}

// ============================================================================
// SMS Campaign Types
// ============================================================================

/// SMS campaign
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmsCampaign {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub description: Option<String>,
    pub status: CampaignStatus,
    pub template_id: String,
    pub twilio_config_id: String,
    pub tracking_domain: String,
    pub awareness_training: bool,
    pub training_url: Option<String>,
    pub launch_date: Option<DateTime<Utc>>,
    pub end_date: Option<DateTime<Utc>>,
    pub rate_limit_per_minute: u32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// SMS campaign summary with statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmsCampaignSummary {
    pub id: String,
    pub name: String,
    pub status: CampaignStatus,
    pub total_targets: u32,
    pub messages_sent: u32,
    pub messages_delivered: u32,
    pub messages_failed: u32,
    pub links_clicked: u32,
    pub launch_date: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// Detailed SMS campaign statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmsCampaignStatistics {
    pub total_targets: u32,
    pub messages_sent: u32,
    pub messages_delivered: u32,
    pub messages_failed: u32,
    pub links_clicked: u32,
    pub unique_clicks: u32,
    pub delivery_rate: f32,
    pub click_rate: f32,
    pub clicks_by_hour: HashMap<String, u32>,
}

/// SMS message template
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmsTemplate {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub content: String,
    pub variables: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// SMS phishing target
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmsTarget {
    pub id: String,
    pub campaign_id: String,
    pub phone_number: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub company: Option<String>,
    pub department: Option<String>,
    pub tracking_id: String,
    pub status: TargetStatus,
    pub message_sid: Option<String>,
    pub delivery_status: Option<SmsDeliveryStatus>,
    pub sent_at: Option<DateTime<Utc>>,
    pub delivered_at: Option<DateTime<Utc>>,
    pub clicked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// SMS click event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmsClickEvent {
    pub id: String,
    pub target_id: String,
    pub campaign_id: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub referrer: Option<String>,
    pub created_at: DateTime<Utc>,
}

// ============================================================================
// Template Variables
// ============================================================================

/// SMS template variables for message personalization
#[derive(Debug, Clone)]
pub struct SmsTemplateVariables {
    pub first_name: String,
    pub last_name: String,
    pub phone_number: String,
    pub company: String,
    pub department: String,
    pub tracking_url: String,
    pub short_url: String,
}

impl SmsTemplateVariables {
    /// Replace variables in template content
    pub fn apply(&self, content: &str) -> String {
        content
            .replace("{{.FirstName}}", &self.first_name)
            .replace("{{.LastName}}", &self.last_name)
            .replace("{{.PhoneNumber}}", &self.phone_number)
            .replace("{{.Company}}", &self.company)
            .replace("{{.Department}}", &self.department)
            .replace("{{.TrackingURL}}", &self.tracking_url)
            .replace("{{.ShortURL}}", &self.short_url)
            // Alternative syntax
            .replace("${FirstName}", &self.first_name)
            .replace("${LastName}", &self.last_name)
            .replace("${PhoneNumber}", &self.phone_number)
            .replace("${Company}", &self.company)
            .replace("${Department}", &self.department)
            .replace("${TrackingURL}", &self.tracking_url)
            .replace("${ShortURL}", &self.short_url)
    }

    /// Extract variable names from template
    pub fn extract_variables(content: &str) -> Vec<String> {
        let mut variables = Vec::new();
        let re1 = regex::Regex::new(r"\{\{\.(\w+)\}\}").unwrap();
        let re2 = regex::Regex::new(r"\$\{(\w+)\}").unwrap();

        for cap in re1.captures_iter(content) {
            if let Some(var) = cap.get(1) {
                let var_name = var.as_str().to_string();
                if !variables.contains(&var_name) {
                    variables.push(var_name);
                }
            }
        }

        for cap in re2.captures_iter(content) {
            if let Some(var) = cap.get(1) {
                let var_name = var.as_str().to_string();
                if !variables.contains(&var_name) {
                    variables.push(var_name);
                }
            }
        }

        variables
    }
}

// ============================================================================
// Request Types
// ============================================================================

/// SMS campaign creation request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateSmsCampaignRequest {
    pub name: String,
    pub description: Option<String>,
    pub template_id: String,
    pub twilio_config_id: String,
    pub tracking_domain: Option<String>,
    pub awareness_training: Option<bool>,
    pub training_url: Option<String>,
    pub launch_date: Option<DateTime<Utc>>,
    pub end_date: Option<DateTime<Utc>>,
    pub rate_limit_per_minute: Option<u32>,
    pub targets: Vec<CreateSmsTargetRequest>,
}

/// SMS target creation request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateSmsTargetRequest {
    pub phone_number: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub company: Option<String>,
    pub department: Option<String>,
}

/// SMS template creation request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateSmsTemplateRequest {
    pub name: String,
    pub content: String,
}

/// Twilio config creation request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateTwilioConfigRequest {
    pub name: String,
    pub account_sid: String,
    pub auth_token: String,
    pub from_number: String,
    pub messaging_service_sid: Option<String>,
    pub rate_limit_per_second: Option<u32>,
}

/// Single SMS send request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendSingleSmsRequest {
    pub twilio_config_id: String,
    pub to_number: String,
    pub message: String,
}

// ============================================================================
// SMS Campaign Manager
// ============================================================================

/// SMS campaign manager handles campaign lifecycle and SMS delivery
pub struct SmsCampaignManager {
    pool: SqlitePool,
}

impl SmsCampaignManager {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Create a new SMS campaign
    pub async fn create_campaign(
        &self,
        user_id: &str,
        request: CreateSmsCampaignRequest,
    ) -> Result<SmsCampaign> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();
        let tracking_domain = request.tracking_domain.unwrap_or_else(|| "sms.track.example.com".to_string());
        let rate_limit = request.rate_limit_per_minute.unwrap_or(30);

        sqlx::query(
            r#"
            INSERT INTO sms_campaigns (
                id, user_id, name, description, status, template_id,
                twilio_config_id, tracking_domain, awareness_training,
                training_url, launch_date, end_date, rate_limit_per_minute,
                created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&id)
        .bind(user_id)
        .bind(&request.name)
        .bind(&request.description)
        .bind(CampaignStatus::Draft.to_string())
        .bind(&request.template_id)
        .bind(&request.twilio_config_id)
        .bind(&tracking_domain)
        .bind(request.awareness_training.unwrap_or(false))
        .bind(&request.training_url)
        .bind(request.launch_date.map(|d| d.to_rfc3339()))
        .bind(request.end_date.map(|d| d.to_rfc3339()))
        .bind(rate_limit as i64)
        .bind(now.to_rfc3339())
        .bind(now.to_rfc3339())
        .execute(&self.pool)
        .await?;

        // Add targets
        for target in &request.targets {
            self.add_target(&id, target).await?;
        }

        let campaign = SmsCampaign {
            id,
            user_id: user_id.to_string(),
            name: request.name,
            description: request.description,
            status: CampaignStatus::Draft,
            template_id: request.template_id,
            twilio_config_id: request.twilio_config_id,
            tracking_domain,
            awareness_training: request.awareness_training.unwrap_or(false),
            training_url: request.training_url,
            launch_date: request.launch_date,
            end_date: request.end_date,
            rate_limit_per_minute: rate_limit,
            created_at: now,
            updated_at: now,
        };

        Ok(campaign)
    }

    /// Add a target to a campaign
    pub async fn add_target(
        &self,
        campaign_id: &str,
        target: &CreateSmsTargetRequest,
    ) -> Result<SmsTarget> {
        let id = Uuid::new_v4().to_string();
        let tracking_id = generate_tracking_id();
        let now = Utc::now();

        // Normalize phone number (remove non-digits except leading +)
        let normalized_phone = normalize_phone_number(&target.phone_number);

        sqlx::query(
            r#"
            INSERT INTO sms_targets (
                id, campaign_id, phone_number, first_name, last_name,
                company, department, tracking_id, status, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&id)
        .bind(campaign_id)
        .bind(&normalized_phone)
        .bind(&target.first_name)
        .bind(&target.last_name)
        .bind(&target.company)
        .bind(&target.department)
        .bind(&tracking_id)
        .bind(TargetStatus::Pending.to_string())
        .bind(now.to_rfc3339())
        .execute(&self.pool)
        .await?;

        Ok(SmsTarget {
            id,
            campaign_id: campaign_id.to_string(),
            phone_number: normalized_phone,
            first_name: target.first_name.clone(),
            last_name: target.last_name.clone(),
            company: target.company.clone(),
            department: target.department.clone(),
            tracking_id,
            status: TargetStatus::Pending,
            message_sid: None,
            delivery_status: None,
            sent_at: None,
            delivered_at: None,
            clicked_at: None,
            created_at: now,
        })
    }

    /// Launch an SMS campaign
    pub async fn launch_campaign(&self, campaign_id: &str) -> Result<()> {
        let campaign = self.get_campaign(campaign_id).await?
            .ok_or_else(|| anyhow!("Campaign not found"))?;

        if campaign.status != CampaignStatus::Draft && campaign.status != CampaignStatus::Scheduled {
            return Err(anyhow!("Campaign cannot be launched from current status"));
        }

        // Update status to running
        sqlx::query("UPDATE sms_campaigns SET status = ?, updated_at = ? WHERE id = ?")
            .bind(CampaignStatus::Running.to_string())
            .bind(Utc::now().to_rfc3339())
            .bind(campaign_id)
            .execute(&self.pool)
            .await?;

        // Get template
        let template = self.get_template(&campaign.template_id).await?
            .ok_or_else(|| anyhow!("SMS template not found"))?;

        // Get Twilio config
        let twilio_config = self.get_twilio_config(&campaign.twilio_config_id).await?
            .ok_or_else(|| anyhow!("Twilio configuration not found"))?;

        let client = TwilioClient::new(&twilio_config);

        // Get pending targets
        let targets = self.get_pending_targets(campaign_id).await?;

        // Calculate delay between messages based on rate limit
        let delay_ms = if campaign.rate_limit_per_minute > 0 {
            60_000 / campaign.rate_limit_per_minute as u64
        } else {
            2000 // Default 30 per minute
        };

        // Send SMS to all targets with rate limiting
        for target in targets {
            match self.send_sms_to_target(&campaign, &template, &client, &twilio_config, &target).await {
                Ok(result) => {
                    self.update_target_sent(&target.id, &result).await?;
                }
                Err(e) => {
                    log::error!("Failed to send SMS to {}: {}", target.phone_number, e);
                    self.update_target_failed(&target.id, &e.to_string()).await?;
                }
            }

            // Rate limiting delay
            tokio::time::sleep(Duration::from_millis(delay_ms)).await;
        }

        Ok(())
    }

    /// Send SMS to a specific target
    async fn send_sms_to_target(
        &self,
        campaign: &SmsCampaign,
        template: &SmsTemplate,
        client: &TwilioClient,
        config: &TwilioConfig,
        target: &SmsTarget,
    ) -> Result<SmsDeliveryResult> {
        // Build tracking URL
        let tracking_url = format!(
            "https://{}/s/{}",
            campaign.tracking_domain, target.tracking_id
        );

        // Generate short URL for SMS (could integrate with URL shortener)
        let short_url = format!(
            "https://{}/s/{}",
            campaign.tracking_domain,
            &target.tracking_id[..8] // Use first 8 chars for shorter URL
        );

        // Build template variables
        let variables = SmsTemplateVariables {
            first_name: target.first_name.clone().unwrap_or_default(),
            last_name: target.last_name.clone().unwrap_or_default(),
            phone_number: target.phone_number.clone(),
            company: target.company.clone().unwrap_or_default(),
            department: target.department.clone().unwrap_or_default(),
            tracking_url,
            short_url,
        };

        // Apply variables to template
        let message_body = variables.apply(&template.content);

        // Send the SMS
        client.send_sms(&target.phone_number, &config.from_number, &message_body).await
    }

    /// Update target after successful send
    async fn update_target_sent(&self, target_id: &str, result: &SmsDeliveryResult) -> Result<()> {
        let now = Utc::now();
        sqlx::query(
            r#"
            UPDATE sms_targets SET
                status = ?, message_sid = ?, delivery_status = ?, sent_at = ?
            WHERE id = ?
            "#,
        )
        .bind(TargetStatus::Sent.to_string())
        .bind(&result.message_sid)
        .bind(result.status.to_string())
        .bind(now.to_rfc3339())
        .bind(target_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Update target after failed send
    async fn update_target_failed(&self, target_id: &str, error: &str) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE sms_targets SET
                status = ?, delivery_status = ?
            WHERE id = ?
            "#,
        )
        .bind(TargetStatus::Failed.to_string())
        .bind(SmsDeliveryStatus::Failed.to_string())
        .bind(target_id)
        .execute(&self.pool)
        .await?;

        // Log the error
        log::error!("SMS send failed for target {}: {}", target_id, error);
        Ok(())
    }

    /// Pause a running campaign
    pub async fn pause_campaign(&self, campaign_id: &str) -> Result<()> {
        sqlx::query("UPDATE sms_campaigns SET status = ?, updated_at = ? WHERE id = ? AND status = ?")
            .bind(CampaignStatus::Paused.to_string())
            .bind(Utc::now().to_rfc3339())
            .bind(campaign_id)
            .bind(CampaignStatus::Running.to_string())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Resume a paused campaign
    pub async fn resume_campaign(&self, campaign_id: &str) -> Result<()> {
        sqlx::query("UPDATE sms_campaigns SET status = ?, updated_at = ? WHERE id = ? AND status = ?")
            .bind(CampaignStatus::Running.to_string())
            .bind(Utc::now().to_rfc3339())
            .bind(campaign_id)
            .bind(CampaignStatus::Paused.to_string())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Complete a campaign
    pub async fn complete_campaign(&self, campaign_id: &str) -> Result<()> {
        sqlx::query("UPDATE sms_campaigns SET status = ?, updated_at = ? WHERE id = ?")
            .bind(CampaignStatus::Completed.to_string())
            .bind(Utc::now().to_rfc3339())
            .bind(campaign_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Cancel a campaign
    pub async fn cancel_campaign(&self, campaign_id: &str) -> Result<()> {
        sqlx::query("UPDATE sms_campaigns SET status = ?, updated_at = ? WHERE id = ?")
            .bind(CampaignStatus::Cancelled.to_string())
            .bind(Utc::now().to_rfc3339())
            .bind(campaign_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Get campaign by ID
    pub async fn get_campaign(&self, campaign_id: &str) -> Result<Option<SmsCampaign>> {
        let row = sqlx::query_as::<_, (
            String, String, String, Option<String>, String, String,
            String, String, bool, Option<String>,
            Option<String>, Option<String>, i64, String, String,
        )>(
            r#"
            SELECT id, user_id, name, description, status, template_id,
                   twilio_config_id, tracking_domain, awareness_training, training_url,
                   launch_date, end_date, rate_limit_per_minute, created_at, updated_at
            FROM sms_campaigns WHERE id = ?
            "#,
        )
        .bind(campaign_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| SmsCampaign {
            id: r.0,
            user_id: r.1,
            name: r.2,
            description: r.3,
            status: r.4.parse().unwrap_or(CampaignStatus::Draft),
            template_id: r.5,
            twilio_config_id: r.6,
            tracking_domain: r.7,
            awareness_training: r.8,
            training_url: r.9,
            launch_date: r.10.and_then(|d| chrono::DateTime::parse_from_rfc3339(&d).ok().map(|dt| dt.with_timezone(&Utc))),
            end_date: r.11.and_then(|d| chrono::DateTime::parse_from_rfc3339(&d).ok().map(|dt| dt.with_timezone(&Utc))),
            rate_limit_per_minute: r.12 as u32,
            created_at: chrono::DateTime::parse_from_rfc3339(&r.13).unwrap().with_timezone(&Utc),
            updated_at: chrono::DateTime::parse_from_rfc3339(&r.14).unwrap().with_timezone(&Utc),
        }))
    }

    /// Get SMS template by ID
    pub async fn get_template(&self, template_id: &str) -> Result<Option<SmsTemplate>> {
        let row = sqlx::query_as::<_, (String, String, String, String, String, String)>(
            r#"
            SELECT id, user_id, name, content, created_at, updated_at
            FROM sms_templates WHERE id = ?
            "#,
        )
        .bind(template_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| {
            let variables = SmsTemplateVariables::extract_variables(&r.3);
            SmsTemplate {
                id: r.0,
                user_id: r.1,
                name: r.2,
                content: r.3,
                variables,
                created_at: chrono::DateTime::parse_from_rfc3339(&r.4).unwrap().with_timezone(&Utc),
                updated_at: chrono::DateTime::parse_from_rfc3339(&r.5).unwrap().with_timezone(&Utc),
            }
        }))
    }

    /// Get Twilio config by ID
    pub async fn get_twilio_config(&self, config_id: &str) -> Result<Option<TwilioConfig>> {
        let row = sqlx::query_as::<_, (
            String, String, String, String, String, String,
            Option<String>, i64, String, String,
        )>(
            r#"
            SELECT id, user_id, name, account_sid, auth_token, from_number,
                   messaging_service_sid, rate_limit_per_second, created_at, updated_at
            FROM sms_twilio_configs WHERE id = ?
            "#,
        )
        .bind(config_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| TwilioConfig {
            id: r.0,
            user_id: r.1,
            name: r.2,
            account_sid: r.3,
            auth_token: r.4,
            from_number: r.5,
            messaging_service_sid: r.6,
            rate_limit_per_second: r.7 as u32,
            created_at: chrono::DateTime::parse_from_rfc3339(&r.8).unwrap().with_timezone(&Utc),
            updated_at: chrono::DateTime::parse_from_rfc3339(&r.9).unwrap().with_timezone(&Utc),
        }))
    }

    /// Get pending targets for a campaign
    async fn get_pending_targets(&self, campaign_id: &str) -> Result<Vec<SmsTarget>> {
        let rows = sqlx::query_as::<_, (
            String, String, String, Option<String>, Option<String>,
            Option<String>, Option<String>, String, String,
            Option<String>, Option<String>, Option<String>,
            Option<String>, Option<String>, String,
        )>(
            r#"
            SELECT id, campaign_id, phone_number, first_name, last_name,
                   company, department, tracking_id, status,
                   message_sid, delivery_status, sent_at,
                   delivered_at, clicked_at, created_at
            FROM sms_targets WHERE campaign_id = ? AND status = ?
            "#,
        )
        .bind(campaign_id)
        .bind(TargetStatus::Pending.to_string())
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(|r| SmsTarget {
            id: r.0,
            campaign_id: r.1,
            phone_number: r.2,
            first_name: r.3,
            last_name: r.4,
            company: r.5,
            department: r.6,
            tracking_id: r.7,
            status: r.8.parse().unwrap_or(TargetStatus::Pending),
            message_sid: r.9,
            delivery_status: r.10.and_then(|s| s.parse().ok()),
            sent_at: r.11.and_then(|d| chrono::DateTime::parse_from_rfc3339(&d).ok().map(|dt| dt.with_timezone(&Utc))),
            delivered_at: r.12.and_then(|d| chrono::DateTime::parse_from_rfc3339(&d).ok().map(|dt| dt.with_timezone(&Utc))),
            clicked_at: r.13.and_then(|d| chrono::DateTime::parse_from_rfc3339(&d).ok().map(|dt| dt.with_timezone(&Utc))),
            created_at: chrono::DateTime::parse_from_rfc3339(&r.14).unwrap().with_timezone(&Utc),
        }).collect())
    }

    /// Get campaign statistics
    pub async fn get_statistics(&self, campaign_id: &str) -> Result<SmsCampaignStatistics> {
        let counts = sqlx::query_as::<_, (i64, i64, i64, i64, i64)>(
            r#"
            SELECT
                COUNT(*) as total,
                SUM(CASE WHEN status != 'pending' THEN 1 ELSE 0 END) as sent,
                SUM(CASE WHEN delivery_status = 'delivered' THEN 1 ELSE 0 END) as delivered,
                SUM(CASE WHEN status = 'failed' OR delivery_status = 'failed' THEN 1 ELSE 0 END) as failed,
                SUM(CASE WHEN clicked_at IS NOT NULL THEN 1 ELSE 0 END) as clicked
            FROM sms_targets WHERE campaign_id = ?
            "#,
        )
        .bind(campaign_id)
        .fetch_one(&self.pool)
        .await?;

        let total = counts.0 as u32;
        let sent = counts.1 as u32;
        let delivered = counts.2 as u32;
        let failed = counts.3 as u32;
        let clicked = counts.4 as u32;

        let delivery_rate = if sent > 0 { delivered as f32 / sent as f32 * 100.0 } else { 0.0 };
        let click_rate = if delivered > 0 { clicked as f32 / delivered as f32 * 100.0 } else { 0.0 };

        Ok(SmsCampaignStatistics {
            total_targets: total,
            messages_sent: sent,
            messages_delivered: delivered,
            messages_failed: failed,
            links_clicked: clicked,
            unique_clicks: clicked, // Simplified for now
            delivery_rate,
            click_rate,
            clicks_by_hour: HashMap::new(),
        })
    }

    /// Record a click event for SMS tracking
    pub async fn record_click(
        &self,
        tracking_id: &str,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
        referrer: Option<&str>,
    ) -> Result<Option<(SmsTarget, Option<String>)>> {
        // Find target by tracking ID
        let target = self.get_target_by_tracking_id(tracking_id).await?;

        if let Some(target) = target {
            let now = Utc::now();

            // Update target click timestamp if first click
            if target.clicked_at.is_none() {
                sqlx::query("UPDATE sms_targets SET clicked_at = ?, status = ? WHERE id = ?")
                    .bind(now.to_rfc3339())
                    .bind(TargetStatus::Clicked.to_string())
                    .bind(&target.id)
                    .execute(&self.pool)
                    .await?;
            }

            // Record click event
            let event_id = Uuid::new_v4().to_string();
            sqlx::query(
                r#"
                INSERT INTO sms_click_events (
                    id, target_id, campaign_id, ip_address, user_agent, referrer, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                "#,
            )
            .bind(&event_id)
            .bind(&target.id)
            .bind(&target.campaign_id)
            .bind(ip_address)
            .bind(user_agent)
            .bind(referrer)
            .bind(now.to_rfc3339())
            .execute(&self.pool)
            .await?;

            // Check if this is awareness training mode
            let training_url = self.get_training_url(&target.campaign_id).await?;

            let updated_target = self.get_target_by_tracking_id(tracking_id).await?;
            if let Some(t) = updated_target {
                return Ok(Some((t, training_url)));
            }
        }

        Ok(None)
    }

    /// Get target by tracking ID
    async fn get_target_by_tracking_id(&self, tracking_id: &str) -> Result<Option<SmsTarget>> {
        // Also check for short tracking ID (first 8 chars)
        let short_id = if tracking_id.len() >= 8 {
            &tracking_id[..8]
        } else {
            tracking_id
        };

        let row = sqlx::query_as::<_, (
            String, String, String, Option<String>, Option<String>,
            Option<String>, Option<String>, String, String,
            Option<String>, Option<String>, Option<String>,
            Option<String>, Option<String>, String,
        )>(
            r#"
            SELECT id, campaign_id, phone_number, first_name, last_name,
                   company, department, tracking_id, status,
                   message_sid, delivery_status, sent_at,
                   delivered_at, clicked_at, created_at
            FROM sms_targets WHERE tracking_id = ? OR tracking_id LIKE ?
            "#,
        )
        .bind(tracking_id)
        .bind(format!("{}%", short_id))
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| SmsTarget {
            id: r.0,
            campaign_id: r.1,
            phone_number: r.2,
            first_name: r.3,
            last_name: r.4,
            company: r.5,
            department: r.6,
            tracking_id: r.7,
            status: r.8.parse().unwrap_or(TargetStatus::Pending),
            message_sid: r.9,
            delivery_status: r.10.and_then(|s| s.parse().ok()),
            sent_at: r.11.and_then(|d| chrono::DateTime::parse_from_rfc3339(&d).ok().map(|dt| dt.with_timezone(&Utc))),
            delivered_at: r.12.and_then(|d| chrono::DateTime::parse_from_rfc3339(&d).ok().map(|dt| dt.with_timezone(&Utc))),
            clicked_at: r.13.and_then(|d| chrono::DateTime::parse_from_rfc3339(&d).ok().map(|dt| dt.with_timezone(&Utc))),
            created_at: chrono::DateTime::parse_from_rfc3339(&r.14).unwrap().with_timezone(&Utc),
        }))
    }

    /// Get training URL for a campaign if awareness training is enabled
    async fn get_training_url(&self, campaign_id: &str) -> Result<Option<String>> {
        let row = sqlx::query_as::<_, (bool, Option<String>)>(
            "SELECT awareness_training, training_url FROM sms_campaigns WHERE id = ?"
        )
        .bind(campaign_id)
        .fetch_optional(&self.pool)
        .await?;

        if let Some((awareness_training, training_url)) = row {
            if awareness_training {
                return Ok(training_url);
            }
        }

        Ok(None)
    }

    /// Create an SMS template
    pub async fn create_template(
        &self,
        user_id: &str,
        request: CreateSmsTemplateRequest,
    ) -> Result<SmsTemplate> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();
        let variables = SmsTemplateVariables::extract_variables(&request.content);

        sqlx::query(
            r#"
            INSERT INTO sms_templates (id, user_id, name, content, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&id)
        .bind(user_id)
        .bind(&request.name)
        .bind(&request.content)
        .bind(now.to_rfc3339())
        .bind(now.to_rfc3339())
        .execute(&self.pool)
        .await?;

        Ok(SmsTemplate {
            id,
            user_id: user_id.to_string(),
            name: request.name,
            content: request.content,
            variables,
            created_at: now,
            updated_at: now,
        })
    }

    /// Create a Twilio configuration
    pub async fn create_twilio_config(
        &self,
        user_id: &str,
        request: CreateTwilioConfigRequest,
    ) -> Result<TwilioConfig> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();
        let rate_limit = request.rate_limit_per_second.unwrap_or(1);

        sqlx::query(
            r#"
            INSERT INTO sms_twilio_configs (
                id, user_id, name, account_sid, auth_token, from_number,
                messaging_service_sid, rate_limit_per_second, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&id)
        .bind(user_id)
        .bind(&request.name)
        .bind(&request.account_sid)
        .bind(&request.auth_token)
        .bind(&request.from_number)
        .bind(&request.messaging_service_sid)
        .bind(rate_limit as i64)
        .bind(now.to_rfc3339())
        .bind(now.to_rfc3339())
        .execute(&self.pool)
        .await?;

        Ok(TwilioConfig {
            id,
            user_id: user_id.to_string(),
            name: request.name,
            account_sid: request.account_sid,
            auth_token: request.auth_token,
            from_number: request.from_number,
            messaging_service_sid: request.messaging_service_sid,
            rate_limit_per_second: rate_limit,
            created_at: now,
            updated_at: now,
        })
    }

    /// Send a single SMS (not part of a campaign)
    pub async fn send_single_sms(
        &self,
        user_id: &str,
        request: SendSingleSmsRequest,
    ) -> Result<SmsDeliveryResult> {
        let config = self.get_twilio_config(&request.twilio_config_id).await?
            .ok_or_else(|| anyhow!("Twilio configuration not found"))?;

        if config.user_id != user_id {
            return Err(anyhow!("Access denied to Twilio configuration"));
        }

        let client = TwilioClient::new(&config);
        client.send_sms(&request.to_number, &config.from_number, &request.message).await
    }

    /// Test Twilio configuration
    pub async fn test_twilio_config(&self, config_id: &str) -> Result<bool> {
        let config = self.get_twilio_config(config_id).await?
            .ok_or_else(|| anyhow!("Twilio configuration not found"))?;

        let client = TwilioClient::new(&config);
        client.test_connection().await
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Normalize phone number to E.164 format
fn normalize_phone_number(phone: &str) -> String {
    let mut result = String::new();
    let mut chars = phone.chars().peekable();

    // Keep leading + if present
    if chars.peek() == Some(&'+') {
        result.push('+');
        chars.next();
    }

    // Keep only digits
    for ch in chars {
        if ch.is_ascii_digit() {
            result.push(ch);
        }
    }

    // Add + if not present and number starts with country code
    if !result.starts_with('+') && result.len() >= 10 {
        result.insert(0, '+');
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_phone_number() {
        assert_eq!(normalize_phone_number("+1 (555) 123-4567"), "+15551234567");
        assert_eq!(normalize_phone_number("1-555-123-4567"), "+15551234567");
        assert_eq!(normalize_phone_number("+44 7911 123456"), "+447911123456");
        // Short local numbers (< 10 digits) don't get + prefix as they're not valid E.164
        assert_eq!(normalize_phone_number("555-1234"), "5551234");
    }

    #[test]
    fn test_sms_template_variables() {
        let vars = SmsTemplateVariables {
            first_name: "John".to_string(),
            last_name: "Doe".to_string(),
            phone_number: "+15551234567".to_string(),
            company: "Acme Corp".to_string(),
            department: "IT".to_string(),
            tracking_url: "https://track.example.com/s/abc123".to_string(),
            short_url: "https://t.co/xyz".to_string(),
        };

        let template = "Hi {{.FirstName}}, click here: {{.ShortURL}}";
        let result = vars.apply(template);
        assert_eq!(result, "Hi John, click here: https://t.co/xyz");
    }

    #[test]
    fn test_extract_variables() {
        let content = "Hi {{.FirstName}} {{.LastName}}, from ${Company}";
        let vars = SmsTemplateVariables::extract_variables(content);
        assert!(vars.contains(&"FirstName".to_string()));
        assert!(vars.contains(&"LastName".to_string()));
        assert!(vars.contains(&"Company".to_string()));
    }

    #[test]
    fn test_delivery_status_parsing() {
        assert_eq!("delivered".parse::<SmsDeliveryStatus>().unwrap(), SmsDeliveryStatus::Delivered);
        assert_eq!("failed".parse::<SmsDeliveryStatus>().unwrap(), SmsDeliveryStatus::Failed);
        assert_eq!("unknown".parse::<SmsDeliveryStatus>().unwrap(), SmsDeliveryStatus::Unknown);
    }
}
