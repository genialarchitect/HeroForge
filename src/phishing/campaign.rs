//! Campaign Management
//!
//! Handles campaign lifecycle, scheduling, and execution.

#![allow(dead_code)]

use anyhow::{anyhow, Result};
use chrono::Utc;
use sqlx::SqlitePool;
use uuid::Uuid;

use super::types::*;
use super::sender::EmailSender;

/// Campaign manager
pub struct CampaignManager {
    pool: SqlitePool,
    sender: EmailSender,
}

impl CampaignManager {
    pub fn new(pool: SqlitePool, sender: EmailSender) -> Self {
        Self { pool, sender }
    }

    /// Create a new campaign
    pub async fn create_campaign(
        &self,
        user_id: &str,
        request: CreateCampaignRequest,
    ) -> Result<PhishingCampaign> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();
        let tracking_domain = request.tracking_domain.unwrap_or_else(|| "track.example.com".to_string());

        // Create the campaign
        sqlx::query(
            r#"
            INSERT INTO phishing_campaigns (
                id, user_id, name, description, status, email_template_id,
                landing_page_id, smtp_profile_id, tracking_domain,
                awareness_training, training_url, launch_date, end_date,
                created_at, updated_at, customer_id, engagement_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&id)
        .bind(user_id)
        .bind(&request.name)
        .bind(&request.description)
        .bind(CampaignStatus::Draft.to_string())
        .bind(&request.email_template_id)
        .bind(&request.landing_page_id)
        .bind(&request.smtp_profile_id)
        .bind(&tracking_domain)
        .bind(request.awareness_training.unwrap_or(false))
        .bind(&request.training_url)
        .bind(request.launch_date.map(|d| d.to_rfc3339()))
        .bind(request.end_date.map(|d| d.to_rfc3339()))
        .bind(now.to_rfc3339())
        .bind(now.to_rfc3339())
        .bind(&request.customer_id)
        .bind(&request.engagement_id)
        .execute(&self.pool)
        .await?;

        // Add targets
        for target in &request.targets {
            self.add_target(&id, target).await?;
        }

        let campaign = PhishingCampaign {
            id,
            user_id: user_id.to_string(),
            name: request.name,
            description: request.description,
            status: CampaignStatus::Draft,
            email_template_id: request.email_template_id,
            landing_page_id: request.landing_page_id,
            smtp_profile_id: request.smtp_profile_id,
            tracking_domain,
            awareness_training: request.awareness_training.unwrap_or(false),
            training_url: request.training_url,
            launch_date: request.launch_date,
            end_date: request.end_date,
            created_at: now,
            updated_at: now,
        };

        Ok(campaign)
    }

    /// Add a target to a campaign
    pub async fn add_target(
        &self,
        campaign_id: &str,
        target: &CreateTargetRequest,
    ) -> Result<PhishingTarget> {
        let id = Uuid::new_v4().to_string();
        let tracking_id = generate_tracking_id();
        let now = Utc::now();

        sqlx::query(
            r#"
            INSERT INTO phishing_targets (
                id, campaign_id, email, first_name, last_name,
                position, department, tracking_id, status, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&id)
        .bind(campaign_id)
        .bind(&target.email)
        .bind(&target.first_name)
        .bind(&target.last_name)
        .bind(&target.position)
        .bind(&target.department)
        .bind(&tracking_id)
        .bind(TargetStatus::Pending.to_string())
        .bind(now.to_rfc3339())
        .execute(&self.pool)
        .await?;

        Ok(PhishingTarget {
            id,
            campaign_id: campaign_id.to_string(),
            email: target.email.clone(),
            first_name: target.first_name.clone(),
            last_name: target.last_name.clone(),
            position: target.position.clone(),
            department: target.department.clone(),
            tracking_id,
            status: TargetStatus::Pending,
            email_sent_at: None,
            email_opened_at: None,
            link_clicked_at: None,
            credentials_submitted_at: None,
            reported_at: None,
            created_at: now,
        })
    }

    /// Launch a campaign
    pub async fn launch_campaign(&self, campaign_id: &str) -> Result<()> {
        // Get campaign
        let campaign = self.get_campaign(campaign_id).await?
            .ok_or_else(|| anyhow!("Campaign not found"))?;

        if campaign.status != CampaignStatus::Draft && campaign.status != CampaignStatus::Scheduled {
            return Err(anyhow!("Campaign cannot be launched from current status"));
        }

        // Update status to running
        sqlx::query("UPDATE phishing_campaigns SET status = ?, updated_at = ? WHERE id = ?")
            .bind(CampaignStatus::Running.to_string())
            .bind(Utc::now().to_rfc3339())
            .bind(campaign_id)
            .execute(&self.pool)
            .await?;

        // Get email template
        let template = self.get_email_template(&campaign.email_template_id).await?
            .ok_or_else(|| anyhow!("Email template not found"))?;

        // Get SMTP profile
        let smtp_profile = self.get_smtp_profile(&campaign.smtp_profile_id).await?
            .ok_or_else(|| anyhow!("SMTP profile not found"))?;

        // Get pending targets
        let targets = self.get_pending_targets(campaign_id).await?;

        // Send emails to all targets
        for target in targets {
            match self.send_phishing_email(&campaign, &template, &smtp_profile, &target).await {
                Ok(_) => {
                    self.update_target_status(&target.id, TargetStatus::Sent).await?;
                    self.record_event(&target.id, TargetEventType::EmailSent, None, None, None).await?;
                }
                Err(e) => {
                    log::error!("Failed to send email to {}: {}", target.email, e);
                    self.update_target_status(&target.id, TargetStatus::Failed).await?;
                }
            }
        }

        Ok(())
    }

    /// Send phishing email to a target
    async fn send_phishing_email(
        &self,
        campaign: &PhishingCampaign,
        template: &EmailTemplate,
        smtp_profile: &SmtpProfile,
        target: &PhishingTarget,
    ) -> Result<()> {
        // Build tracking URLs
        let tracking_url = format!(
            "https://{}/t/{}",
            campaign.tracking_domain, target.tracking_id
        );
        let tracking_pixel = format!(
            "<img src=\"https://{}/p/{}.png\" width=\"1\" height=\"1\" />",
            campaign.tracking_domain, target.tracking_id
        );
        let phish_url = format!(
            "https://{}/c/{}",
            campaign.tracking_domain, target.tracking_id
        );

        // Build template variables
        let variables = TemplateVariables {
            first_name: target.first_name.clone().unwrap_or_default(),
            last_name: target.last_name.clone().unwrap_or_default(),
            email: target.email.clone(),
            position: target.position.clone().unwrap_or_default(),
            department: target.department.clone().unwrap_or_default(),
            tracking_url,
            tracking_pixel: tracking_pixel.clone(),
            phish_url,
        };

        // Apply variables to template
        let subject = variables.apply(&template.subject);
        let mut html_body = variables.apply(&template.html_body);

        // Append tracking pixel to HTML body if not already present
        if !html_body.contains(&tracking_pixel) {
            html_body.push_str(&tracking_pixel);
        }

        let text_body = template.text_body.as_ref().map(|t| variables.apply(t));

        // Send the email
        self.sender.send_email(
            smtp_profile,
            &target.email,
            &template.from_name,
            &template.from_email,
            &subject,
            &html_body,
            text_body.as_deref(),
            &template.attachments,
        ).await?;

        // Update sent timestamp
        sqlx::query("UPDATE phishing_targets SET email_sent_at = ? WHERE id = ?")
            .bind(Utc::now().to_rfc3339())
            .bind(&target.id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    /// Pause a running campaign
    pub async fn pause_campaign(&self, campaign_id: &str) -> Result<()> {
        sqlx::query("UPDATE phishing_campaigns SET status = ?, updated_at = ? WHERE id = ? AND status = ?")
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
        sqlx::query("UPDATE phishing_campaigns SET status = ?, updated_at = ? WHERE id = ? AND status = ?")
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
        sqlx::query("UPDATE phishing_campaigns SET status = ?, updated_at = ? WHERE id = ?")
            .bind(CampaignStatus::Completed.to_string())
            .bind(Utc::now().to_rfc3339())
            .bind(campaign_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Cancel a campaign
    pub async fn cancel_campaign(&self, campaign_id: &str) -> Result<()> {
        sqlx::query("UPDATE phishing_campaigns SET status = ?, updated_at = ? WHERE id = ?")
            .bind(CampaignStatus::Cancelled.to_string())
            .bind(Utc::now().to_rfc3339())
            .bind(campaign_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Get campaign by ID
    pub async fn get_campaign(&self, campaign_id: &str) -> Result<Option<PhishingCampaign>> {
        let row = sqlx::query_as::<_, (
            String, String, String, Option<String>, String, String,
            Option<String>, String, String, bool, Option<String>,
            Option<String>, Option<String>, String, String,
        )>(
            r#"
            SELECT id, user_id, name, description, status, email_template_id,
                   landing_page_id, smtp_profile_id, tracking_domain,
                   awareness_training, training_url, launch_date, end_date,
                   created_at, updated_at
            FROM phishing_campaigns WHERE id = ?
            "#,
        )
        .bind(campaign_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| PhishingCampaign {
            id: r.0,
            user_id: r.1,
            name: r.2,
            description: r.3,
            status: r.4.parse().unwrap_or(CampaignStatus::Draft),
            email_template_id: r.5,
            landing_page_id: r.6,
            smtp_profile_id: r.7,
            tracking_domain: r.8,
            awareness_training: r.9,
            training_url: r.10,
            launch_date: r.11.and_then(|d| chrono::DateTime::parse_from_rfc3339(&d).ok().map(|dt| dt.with_timezone(&Utc))),
            end_date: r.12.and_then(|d| chrono::DateTime::parse_from_rfc3339(&d).ok().map(|dt| dt.with_timezone(&Utc))),
            created_at: chrono::DateTime::parse_from_rfc3339(&r.13).unwrap().with_timezone(&Utc),
            updated_at: chrono::DateTime::parse_from_rfc3339(&r.14).unwrap().with_timezone(&Utc),
        }))
    }

    /// Get email template by ID
    pub async fn get_email_template(&self, template_id: &str) -> Result<Option<EmailTemplate>> {
        let row = sqlx::query_as::<_, (
            String, String, String, String, String, Option<String>,
            String, String, Option<String>, Option<String>, String, String,
        )>(
            r#"
            SELECT id, user_id, name, subject, html_body, text_body,
                   from_name, from_email, envelope_sender, attachments,
                   created_at, updated_at
            FROM phishing_email_templates WHERE id = ?
            "#,
        )
        .bind(template_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| {
            let attachments: Vec<TemplateAttachment> = r.9
                .as_ref()
                .and_then(|a| serde_json::from_str(a).ok())
                .unwrap_or_default();
            let variables = TemplateVariables::extract_variables(&r.4);

            EmailTemplate {
                id: r.0,
                user_id: r.1,
                name: r.2,
                subject: r.3,
                html_body: r.4,
                text_body: r.5,
                from_name: r.6,
                from_email: r.7,
                envelope_sender: r.8,
                attachments,
                variables,
                created_at: chrono::DateTime::parse_from_rfc3339(&r.10).unwrap().with_timezone(&Utc),
                updated_at: chrono::DateTime::parse_from_rfc3339(&r.11).unwrap().with_timezone(&Utc),
            }
        }))
    }

    /// Get SMTP profile by ID
    pub async fn get_smtp_profile(&self, profile_id: &str) -> Result<Option<SmtpProfile>> {
        let row = sqlx::query_as::<_, (
            String, String, String, String, i64, Option<String>,
            Option<String>, bool, bool, String, bool, String, String,
        )>(
            r#"
            SELECT id, user_id, name, host, port, username, password,
                   use_tls, use_starttls, from_address, ignore_cert_errors,
                   created_at, updated_at
            FROM phishing_smtp_profiles WHERE id = ?
            "#,
        )
        .bind(profile_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| SmtpProfile {
            id: r.0,
            user_id: r.1,
            name: r.2,
            host: r.3,
            port: r.4 as u16,
            username: r.5,
            password: r.6,
            use_tls: r.7,
            use_starttls: r.8,
            from_address: r.9,
            ignore_cert_errors: r.10,
            created_at: chrono::DateTime::parse_from_rfc3339(&r.11).unwrap().with_timezone(&Utc),
            updated_at: chrono::DateTime::parse_from_rfc3339(&r.12).unwrap().with_timezone(&Utc),
        }))
    }

    /// Get pending targets for a campaign
    async fn get_pending_targets(&self, campaign_id: &str) -> Result<Vec<PhishingTarget>> {
        let rows = sqlx::query_as::<_, (
            String, String, String, Option<String>, Option<String>,
            Option<String>, Option<String>, String, String,
            Option<String>, Option<String>, Option<String>,
            Option<String>, Option<String>, String,
        )>(
            r#"
            SELECT id, campaign_id, email, first_name, last_name,
                   position, department, tracking_id, status,
                   email_sent_at, email_opened_at, link_clicked_at,
                   credentials_submitted_at, reported_at, created_at
            FROM phishing_targets WHERE campaign_id = ? AND status = ?
            "#,
        )
        .bind(campaign_id)
        .bind(TargetStatus::Pending.to_string())
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(|r| PhishingTarget {
            id: r.0,
            campaign_id: r.1,
            email: r.2,
            first_name: r.3,
            last_name: r.4,
            position: r.5,
            department: r.6,
            tracking_id: r.7,
            status: r.8.parse().unwrap_or(TargetStatus::Pending),
            email_sent_at: r.9.and_then(|d| chrono::DateTime::parse_from_rfc3339(&d).ok().map(|dt| dt.with_timezone(&Utc))),
            email_opened_at: r.10.and_then(|d| chrono::DateTime::parse_from_rfc3339(&d).ok().map(|dt| dt.with_timezone(&Utc))),
            link_clicked_at: r.11.and_then(|d| chrono::DateTime::parse_from_rfc3339(&d).ok().map(|dt| dt.with_timezone(&Utc))),
            credentials_submitted_at: r.12.and_then(|d| chrono::DateTime::parse_from_rfc3339(&d).ok().map(|dt| dt.with_timezone(&Utc))),
            reported_at: r.13.and_then(|d| chrono::DateTime::parse_from_rfc3339(&d).ok().map(|dt| dt.with_timezone(&Utc))),
            created_at: chrono::DateTime::parse_from_rfc3339(&r.14).unwrap().with_timezone(&Utc),
        }).collect())
    }

    /// Update target status
    pub async fn update_target_status(&self, target_id: &str, status: TargetStatus) -> Result<()> {
        sqlx::query("UPDATE phishing_targets SET status = ? WHERE id = ?")
            .bind(status.to_string())
            .bind(target_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Record a target event
    pub async fn record_event(
        &self,
        target_id: &str,
        event_type: TargetEventType,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
        details: Option<serde_json::Value>,
    ) -> Result<TargetEvent> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();

        sqlx::query(
            r#"
            INSERT INTO phishing_target_events (
                id, target_id, event_type, ip_address, user_agent, details, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&id)
        .bind(target_id)
        .bind(event_type.to_string())
        .bind(ip_address)
        .bind(user_agent)
        .bind(details.as_ref().map(|d| d.to_string()))
        .bind(now.to_rfc3339())
        .execute(&self.pool)
        .await?;

        Ok(TargetEvent {
            id,
            target_id: target_id.to_string(),
            event_type,
            ip_address: ip_address.map(String::from),
            user_agent: user_agent.map(String::from),
            details,
            created_at: now,
        })
    }

    /// Get campaign statistics
    pub async fn get_statistics(&self, campaign_id: &str) -> Result<CampaignStatistics> {
        // Get target counts
        let counts = sqlx::query_as::<_, (i64, i64, i64, i64, i64, i64)>(
            r#"
            SELECT
                COUNT(*) as total,
                SUM(CASE WHEN status != 'pending' THEN 1 ELSE 0 END) as sent,
                SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) as failed,
                SUM(CASE WHEN email_opened_at IS NOT NULL THEN 1 ELSE 0 END) as opened,
                SUM(CASE WHEN link_clicked_at IS NOT NULL THEN 1 ELSE 0 END) as clicked,
                SUM(CASE WHEN credentials_submitted_at IS NOT NULL THEN 1 ELSE 0 END) as submitted
            FROM phishing_targets WHERE campaign_id = ?
            "#,
        )
        .bind(campaign_id)
        .fetch_one(&self.pool)
        .await?;

        let reported = sqlx::query_as::<_, (i64,)>(
            "SELECT COUNT(*) FROM phishing_targets WHERE campaign_id = ? AND reported_at IS NOT NULL"
        )
        .bind(campaign_id)
        .fetch_one(&self.pool)
        .await?
        .0;

        let total = counts.0 as u32;
        let sent = counts.1 as u32;
        let failed = counts.2 as u32;
        let opened = counts.3 as u32;
        let clicked = counts.4 as u32;
        let submitted = counts.5 as u32;
        let reported = reported as u32;

        let open_rate = if sent > 0 { opened as f32 / sent as f32 * 100.0 } else { 0.0 };
        let click_rate = if sent > 0 { clicked as f32 / sent as f32 * 100.0 } else { 0.0 };
        let submit_rate = if sent > 0 { submitted as f32 / sent as f32 * 100.0 } else { 0.0 };
        let report_rate = if sent > 0 { reported as f32 / sent as f32 * 100.0 } else { 0.0 };

        Ok(CampaignStatistics {
            total_targets: total,
            emails_sent: sent,
            emails_failed: failed,
            emails_opened: opened,
            unique_opens: opened, // Simplified for now
            links_clicked: clicked,
            unique_clicks: clicked, // Simplified for now
            credentials_captured: submitted,
            reported_phish: reported,
            open_rate,
            click_rate,
            submit_rate,
            report_rate,
            events_by_hour: std::collections::HashMap::new(),
            events_by_department: std::collections::HashMap::new(),
        })
    }
}
