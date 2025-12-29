//! Phishing Campaign Types
//!
//! Data structures for phishing campaign management, email templates,
//! landing pages, and tracking.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Campaign status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum CampaignStatus {
    Draft,
    Scheduled,
    Running,
    Paused,
    Completed,
    Cancelled,
}

impl std::fmt::Display for CampaignStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CampaignStatus::Draft => write!(f, "draft"),
            CampaignStatus::Scheduled => write!(f, "scheduled"),
            CampaignStatus::Running => write!(f, "running"),
            CampaignStatus::Paused => write!(f, "paused"),
            CampaignStatus::Completed => write!(f, "completed"),
            CampaignStatus::Cancelled => write!(f, "cancelled"),
        }
    }
}

impl std::str::FromStr for CampaignStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "draft" => Ok(CampaignStatus::Draft),
            "scheduled" => Ok(CampaignStatus::Scheduled),
            "running" => Ok(CampaignStatus::Running),
            "paused" => Ok(CampaignStatus::Paused),
            "completed" => Ok(CampaignStatus::Completed),
            "cancelled" => Ok(CampaignStatus::Cancelled),
            _ => Err(format!("Unknown campaign status: {}", s)),
        }
    }
}

/// Target event type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TargetEventType {
    EmailSent,
    EmailOpened,
    LinkClicked,
    CredentialsSubmitted,
    AttachmentOpened,
    ReportedPhish,
}

impl std::fmt::Display for TargetEventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TargetEventType::EmailSent => write!(f, "email_sent"),
            TargetEventType::EmailOpened => write!(f, "email_opened"),
            TargetEventType::LinkClicked => write!(f, "link_clicked"),
            TargetEventType::CredentialsSubmitted => write!(f, "credentials_submitted"),
            TargetEventType::AttachmentOpened => write!(f, "attachment_opened"),
            TargetEventType::ReportedPhish => write!(f, "reported_phish"),
        }
    }
}

impl std::str::FromStr for TargetEventType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "email_sent" => Ok(TargetEventType::EmailSent),
            "email_opened" => Ok(TargetEventType::EmailOpened),
            "link_clicked" => Ok(TargetEventType::LinkClicked),
            "credentials_submitted" => Ok(TargetEventType::CredentialsSubmitted),
            "attachment_opened" => Ok(TargetEventType::AttachmentOpened),
            "reported_phish" => Ok(TargetEventType::ReportedPhish),
            _ => Err(format!("Unknown event type: {}", s)),
        }
    }
}

/// Phishing campaign
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhishingCampaign {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub description: Option<String>,
    pub status: CampaignStatus,
    pub email_template_id: String,
    pub landing_page_id: Option<String>,
    pub smtp_profile_id: String,
    pub tracking_domain: String,
    pub awareness_training: bool,
    pub training_url: Option<String>,
    pub launch_date: Option<DateTime<Utc>>,
    pub end_date: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Campaign summary with statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignSummary {
    pub id: String,
    pub name: String,
    pub status: CampaignStatus,
    pub total_targets: u32,
    pub emails_sent: u32,
    pub emails_opened: u32,
    pub links_clicked: u32,
    pub credentials_captured: u32,
    pub reported_phish: u32,
    pub launch_date: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// Detailed campaign statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignStatistics {
    pub total_targets: u32,
    pub emails_sent: u32,
    pub emails_failed: u32,
    pub emails_opened: u32,
    pub unique_opens: u32,
    pub links_clicked: u32,
    pub unique_clicks: u32,
    pub credentials_captured: u32,
    pub reported_phish: u32,
    pub open_rate: f32,
    pub click_rate: f32,
    pub submit_rate: f32,
    pub report_rate: f32,
    pub events_by_hour: HashMap<String, u32>,
    pub events_by_department: HashMap<String, DepartmentStats>,
}

/// Department-level statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepartmentStats {
    pub total: u32,
    pub sent: u32,
    pub opened: u32,
    pub clicked: u32,
    pub submitted: u32,
    pub reported: u32,
}

/// Phishing target
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhishingTarget {
    pub id: String,
    pub campaign_id: String,
    pub email: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub position: Option<String>,
    pub department: Option<String>,
    pub tracking_id: String,
    pub status: TargetStatus,
    pub email_sent_at: Option<DateTime<Utc>>,
    pub email_opened_at: Option<DateTime<Utc>>,
    pub link_clicked_at: Option<DateTime<Utc>>,
    pub credentials_submitted_at: Option<DateTime<Utc>>,
    pub reported_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// Target status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TargetStatus {
    Pending,
    Sent,
    Opened,
    Clicked,
    Submitted,
    Reported,
    Failed,
}

impl std::fmt::Display for TargetStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TargetStatus::Pending => write!(f, "pending"),
            TargetStatus::Sent => write!(f, "sent"),
            TargetStatus::Opened => write!(f, "opened"),
            TargetStatus::Clicked => write!(f, "clicked"),
            TargetStatus::Submitted => write!(f, "submitted"),
            TargetStatus::Reported => write!(f, "reported"),
            TargetStatus::Failed => write!(f, "failed"),
        }
    }
}

impl std::str::FromStr for TargetStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "pending" => Ok(TargetStatus::Pending),
            "sent" => Ok(TargetStatus::Sent),
            "opened" => Ok(TargetStatus::Opened),
            "clicked" => Ok(TargetStatus::Clicked),
            "submitted" => Ok(TargetStatus::Submitted),
            "reported" => Ok(TargetStatus::Reported),
            "failed" => Ok(TargetStatus::Failed),
            _ => Err(format!("Unknown target status: {}", s)),
        }
    }
}

/// Target event for timeline
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetEvent {
    pub id: String,
    pub target_id: String,
    pub event_type: TargetEventType,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub details: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
}

/// Email template
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailTemplate {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub subject: String,
    pub html_body: String,
    pub text_body: Option<String>,
    pub from_name: String,
    pub from_email: String,
    pub envelope_sender: Option<String>,
    pub attachments: Vec<TemplateAttachment>,
    pub variables: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Template attachment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateAttachment {
    pub name: String,
    pub content_type: String,
    pub content_base64: String,
}

/// Landing page for credential capture
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LandingPage {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub html_content: String,
    pub capture_credentials: bool,
    pub capture_fields: Vec<String>,
    pub redirect_url: Option<String>,
    pub redirect_delay: u32,
    pub cloned_from: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// SMTP profile for sending emails
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmtpProfile {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
    pub use_tls: bool,
    pub use_starttls: bool,
    pub from_address: String,
    pub ignore_cert_errors: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Captured credentials
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapturedCredential {
    pub id: String,
    pub campaign_id: String,
    pub target_id: String,
    pub landing_page_id: String,
    pub fields: HashMap<String, String>,
    pub ip_address: String,
    pub user_agent: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Website clone request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloneRequest {
    pub url: String,
    pub name: String,
    pub capture_credentials: bool,
    pub capture_fields: Vec<String>,
    pub redirect_url: Option<String>,
}

/// Campaign creation request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateCampaignRequest {
    pub name: String,
    pub description: Option<String>,
    pub email_template_id: String,
    pub landing_page_id: Option<String>,
    pub smtp_profile_id: String,
    pub tracking_domain: Option<String>,
    pub awareness_training: Option<bool>,
    pub training_url: Option<String>,
    pub launch_date: Option<DateTime<Utc>>,
    pub end_date: Option<DateTime<Utc>>,
    pub targets: Vec<CreateTargetRequest>,
    pub customer_id: Option<String>,
    pub engagement_id: Option<String>,
}

/// Target creation request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateTargetRequest {
    pub email: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub position: Option<String>,
    pub department: Option<String>,
}

/// Email template creation request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateEmailTemplateRequest {
    pub name: String,
    pub subject: String,
    pub html_body: String,
    pub text_body: Option<String>,
    pub from_name: String,
    pub from_email: String,
    pub envelope_sender: Option<String>,
    pub attachments: Option<Vec<TemplateAttachment>>,
}

/// Landing page creation request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateLandingPageRequest {
    pub name: String,
    pub html_content: String,
    pub capture_credentials: bool,
    pub capture_fields: Vec<String>,
    pub redirect_url: Option<String>,
    pub redirect_delay: Option<u32>,
}

/// SMTP profile creation request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateSmtpProfileRequest {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
    pub use_tls: Option<bool>,
    pub use_starttls: Option<bool>,
    pub from_address: String,
    pub ignore_cert_errors: Option<bool>,
}

/// Target import from CSV
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetImport {
    pub email: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub position: Option<String>,
    pub department: Option<String>,
}

/// Template variables for email personalization
pub struct TemplateVariables {
    pub first_name: String,
    pub last_name: String,
    pub email: String,
    pub position: String,
    pub department: String,
    pub tracking_url: String,
    pub tracking_pixel: String,
    pub phish_url: String,
}

impl TemplateVariables {
    /// Replace variables in template content
    pub fn apply(&self, content: &str) -> String {
        content
            .replace("{{.FirstName}}", &self.first_name)
            .replace("{{.LastName}}", &self.last_name)
            .replace("{{.Email}}", &self.email)
            .replace("{{.Position}}", &self.position)
            .replace("{{.Department}}", &self.department)
            .replace("{{.TrackingURL}}", &self.tracking_url)
            .replace("{{.TrackingPixel}}", &self.tracking_pixel)
            .replace("{{.PhishURL}}", &self.phish_url)
            // Alternative syntax
            .replace("${FirstName}", &self.first_name)
            .replace("${LastName}", &self.last_name)
            .replace("${Email}", &self.email)
            .replace("${Position}", &self.position)
            .replace("${Department}", &self.department)
            .replace("${TrackingURL}", &self.tracking_url)
            .replace("${TrackingPixel}", &self.tracking_pixel)
            .replace("${PhishURL}", &self.phish_url)
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

/// Tracking ID generator
pub fn generate_tracking_id() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let chars: Vec<char> = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        .chars()
        .collect();
    (0..32)
        .map(|_| chars[rng.gen_range(0..chars.len())])
        .collect()
}
