//! Tracking System
//!
//! Handles tracking of email opens, link clicks, and credential submissions.

use anyhow::{anyhow, Result};
use chrono::Utc;
use sqlx::SqlitePool;

use super::types::*;

/// 1x1 transparent PNG pixel (base64 decoded)
pub const TRACKING_PIXEL: &[u8] = &[
    0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D,
    0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
    0x08, 0x06, 0x00, 0x00, 0x00, 0x1F, 0x15, 0xC4, 0x89, 0x00, 0x00, 0x00,
    0x0A, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9C, 0x63, 0x00, 0x01, 0x00, 0x00,
    0x05, 0x00, 0x01, 0x0D, 0x0A, 0x2D, 0xB4, 0x00, 0x00, 0x00, 0x00, 0x49,
    0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82,
];

/// Tracker for phishing events
pub struct Tracker {
    pool: SqlitePool,
}

impl Tracker {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Record email open event
    pub async fn record_open(
        &self,
        tracking_id: &str,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<Option<PhishingTarget>> {
        // Find target by tracking ID
        let target = self.get_target_by_tracking_id(tracking_id).await?;

        if let Some(target) = target {
            let now = Utc::now();

            // Update target if first open
            if target.email_opened_at.is_none() {
                sqlx::query(
                    "UPDATE phishing_targets SET email_opened_at = ?, status = ? WHERE id = ?"
                )
                .bind(now.to_rfc3339())
                .bind(TargetStatus::Opened.to_string())
                .bind(&target.id)
                .execute(&self.pool)
                .await?;
            }

            // Record the event
            self.record_event(
                &target.id,
                TargetEventType::EmailOpened,
                ip_address,
                user_agent,
                None,
            ).await?;

            // Return updated target
            return self.get_target_by_tracking_id(tracking_id).await;
        }

        Ok(None)
    }

    /// Record link click event
    pub async fn record_click(
        &self,
        tracking_id: &str,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<Option<(PhishingTarget, Option<LandingPage>)>> {
        // Find target by tracking ID
        let target = self.get_target_by_tracking_id(tracking_id).await?;

        if let Some(target) = target {
            let now = Utc::now();

            // Update target if first click
            if target.link_clicked_at.is_none() {
                sqlx::query(
                    "UPDATE phishing_targets SET link_clicked_at = ?, status = ? WHERE id = ?"
                )
                .bind(now.to_rfc3339())
                .bind(TargetStatus::Clicked.to_string())
                .bind(&target.id)
                .execute(&self.pool)
                .await?;
            }

            // Record the event
            self.record_event(
                &target.id,
                TargetEventType::LinkClicked,
                ip_address,
                user_agent,
                None,
            ).await?;

            // Get the campaign's landing page
            let landing_page = self.get_campaign_landing_page(&target.campaign_id).await?;

            // Return updated target and landing page
            let updated_target = self.get_target_by_tracking_id(tracking_id).await?;
            if let Some(t) = updated_target {
                return Ok(Some((t, landing_page)));
            }
        }

        Ok(None)
    }

    /// Record credential submission
    pub async fn record_credential_submission(
        &self,
        tracking_id: &str,
        credentials: std::collections::HashMap<String, String>,
        ip_address: &str,
        user_agent: Option<&str>,
    ) -> Result<Option<CapturedCredential>> {
        // Find target by tracking ID
        let target = self.get_target_by_tracking_id(tracking_id).await?;

        if let Some(target) = target {
            let now = Utc::now();

            // Update target
            sqlx::query(
                "UPDATE phishing_targets SET credentials_submitted_at = ?, status = ? WHERE id = ?"
            )
            .bind(now.to_rfc3339())
            .bind(TargetStatus::Submitted.to_string())
            .bind(&target.id)
            .execute(&self.pool)
            .await?;

            // Get landing page ID from campaign
            let landing_page_id = sqlx::query_as::<_, (Option<String>,)>(
                "SELECT landing_page_id FROM phishing_campaigns WHERE id = ?"
            )
            .bind(&target.campaign_id)
            .fetch_optional(&self.pool)
            .await?
            .and_then(|r| r.0)
            .unwrap_or_default();

            // Store captured credentials
            let cred_id = uuid::Uuid::new_v4().to_string();
            let fields_json = serde_json::to_string(&credentials)?;

            sqlx::query(
                r#"
                INSERT INTO phishing_captured_credentials (
                    id, campaign_id, target_id, landing_page_id, fields,
                    ip_address, user_agent, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                "#
            )
            .bind(&cred_id)
            .bind(&target.campaign_id)
            .bind(&target.id)
            .bind(&landing_page_id)
            .bind(&fields_json)
            .bind(ip_address)
            .bind(user_agent)
            .bind(now.to_rfc3339())
            .execute(&self.pool)
            .await?;

            // Record the event
            self.record_event(
                &target.id,
                TargetEventType::CredentialsSubmitted,
                Some(ip_address),
                user_agent,
                Some(serde_json::json!({
                    "fields_captured": credentials.keys().collect::<Vec<_>>()
                })),
            ).await?;

            return Ok(Some(CapturedCredential {
                id: cred_id,
                campaign_id: target.campaign_id,
                target_id: target.id,
                landing_page_id,
                fields: credentials,
                ip_address: ip_address.to_string(),
                user_agent: user_agent.map(String::from),
                created_at: now,
            }));
        }

        Ok(None)
    }

    /// Record phish report event
    pub async fn record_phish_report(
        &self,
        tracking_id: &str,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<Option<PhishingTarget>> {
        // Find target by tracking ID
        let target = self.get_target_by_tracking_id(tracking_id).await?;

        if let Some(target) = target {
            let now = Utc::now();

            // Update target
            sqlx::query(
                "UPDATE phishing_targets SET reported_at = ?, status = ? WHERE id = ?"
            )
            .bind(now.to_rfc3339())
            .bind(TargetStatus::Reported.to_string())
            .bind(&target.id)
            .execute(&self.pool)
            .await?;

            // Record the event
            self.record_event(
                &target.id,
                TargetEventType::ReportedPhish,
                ip_address,
                user_agent,
                None,
            ).await?;

            // Return updated target
            return self.get_target_by_tracking_id(tracking_id).await;
        }

        Ok(None)
    }

    /// Get target by tracking ID
    async fn get_target_by_tracking_id(&self, tracking_id: &str) -> Result<Option<PhishingTarget>> {
        let row = sqlx::query_as::<_, (
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
            FROM phishing_targets WHERE tracking_id = ?
            "#,
        )
        .bind(tracking_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| PhishingTarget {
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
        }))
    }

    /// Get campaign's landing page
    async fn get_campaign_landing_page(&self, campaign_id: &str) -> Result<Option<LandingPage>> {
        let row = sqlx::query_as::<_, (
            String, String, String, String, bool, String,
            Option<String>, i64, Option<String>, String, String,
        )>(
            r#"
            SELECT lp.id, lp.user_id, lp.name, lp.html_content, lp.capture_credentials,
                   lp.capture_fields, lp.redirect_url, lp.redirect_delay, lp.cloned_from,
                   lp.created_at, lp.updated_at
            FROM phishing_landing_pages lp
            JOIN phishing_campaigns c ON c.landing_page_id = lp.id
            WHERE c.id = ?
            "#,
        )
        .bind(campaign_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| {
            let capture_fields: Vec<String> = serde_json::from_str(&r.5).unwrap_or_default();
            LandingPage {
                id: r.0,
                user_id: r.1,
                name: r.2,
                html_content: r.3,
                capture_credentials: r.4,
                capture_fields,
                redirect_url: r.6,
                redirect_delay: r.7 as u32,
                cloned_from: r.8,
                created_at: chrono::DateTime::parse_from_rfc3339(&r.9).unwrap().with_timezone(&Utc),
                updated_at: chrono::DateTime::parse_from_rfc3339(&r.10).unwrap().with_timezone(&Utc),
            }
        }))
    }

    /// Record a target event
    async fn record_event(
        &self,
        target_id: &str,
        event_type: TargetEventType,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
        details: Option<serde_json::Value>,
    ) -> Result<()> {
        let id = uuid::Uuid::new_v4().to_string();
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

        Ok(())
    }

    /// Get events for a target
    pub async fn get_target_events(&self, target_id: &str) -> Result<Vec<TargetEvent>> {
        let rows = sqlx::query_as::<_, (
            String, String, String, Option<String>, Option<String>,
            Option<String>, String,
        )>(
            r#"
            SELECT id, target_id, event_type, ip_address, user_agent, details, created_at
            FROM phishing_target_events WHERE target_id = ? ORDER BY created_at DESC
            "#,
        )
        .bind(target_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(|r| TargetEvent {
            id: r.0,
            target_id: r.1,
            event_type: r.2.parse().unwrap_or(TargetEventType::EmailSent),
            ip_address: r.3,
            user_agent: r.4,
            details: r.5.and_then(|d| serde_json::from_str(&d).ok()),
            created_at: chrono::DateTime::parse_from_rfc3339(&r.6).unwrap().with_timezone(&Utc),
        }).collect())
    }

    /// Check if training mode should redirect to training
    pub async fn should_redirect_to_training(&self, tracking_id: &str) -> Result<Option<String>> {
        let row = sqlx::query_as::<_, (bool, Option<String>)>(
            r#"
            SELECT c.awareness_training, c.training_url
            FROM phishing_campaigns c
            JOIN phishing_targets t ON t.campaign_id = c.id
            WHERE t.tracking_id = ?
            "#,
        )
        .bind(tracking_id)
        .fetch_optional(&self.pool)
        .await?;

        if let Some((awareness_training, training_url)) = row {
            if awareness_training {
                return Ok(training_url);
            }
        }

        Ok(None)
    }
}
