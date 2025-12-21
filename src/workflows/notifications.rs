//! Workflow Notifications
//!
//! This module handles sending notifications for workflow events:
//! - Stage entered (approval requests)
//! - SLA breaches
//! - Workflow completed
//! - Workflow rejected

use anyhow::Result;
use chrono::{DateTime, Utc};
use sqlx::SqlitePool;

use super::types::{WorkflowInstance, WorkflowStage};
use crate::notifications::{SlackNotifier, TeamsNotifier, EmailNotifier};
use crate::db;

/// Workflow notification handler
pub struct WorkflowNotifier {
    pool: SqlitePool,
}

impl WorkflowNotifier {
    /// Create a new workflow notifier
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Send notification when entering a new workflow stage
    pub async fn notify_stage_entered(
        &self,
        instance: &WorkflowInstance,
        stage: &WorkflowStage,
        vulnerability_id: &str,
    ) -> Result<()> {
        // Get vulnerability details
        let vuln = crate::db::get_vulnerability_detail(&self.pool, vulnerability_id).await;
        let vuln_title = vuln.as_ref()
            .map(|v| v.vulnerability.vulnerability_id.clone())
            .unwrap_or_else(|_| vulnerability_id.to_string());
        let severity = vuln.as_ref()
            .map(|v| v.vulnerability.severity.clone())
            .unwrap_or_else(|_| "Unknown".to_string());

        // Get notification settings
        if let Ok(settings) = db::get_system_notification_settings(&self.pool).await {
            // Send Slack notification if configured
            if let Some(webhook_url) = settings.slack_webhook_url {
                if settings.notify_on_workflow_action.unwrap_or(true) {
                    let notifier = SlackNotifier::new(webhook_url);
                    if let Err(e) = self.send_slack_stage_notification(
                        &notifier,
                        instance,
                        stage,
                        &vuln_title,
                        &severity,
                    ).await {
                        log::warn!("Failed to send Slack notification: {}", e);
                    }
                }
            }

            // Send Teams notification if configured
            if let Some(webhook_url) = settings.teams_webhook_url {
                if settings.notify_on_workflow_action.unwrap_or(true) {
                    let notifier = TeamsNotifier::new(webhook_url);
                    if let Err(e) = self.send_teams_stage_notification(
                        &notifier,
                        instance,
                        stage,
                        &vuln_title,
                        &severity,
                    ).await {
                        log::warn!("Failed to send Teams notification: {}", e);
                    }
                }
            }

            // Send email notification if SMTP is configured
            if let Ok(email_config) = crate::notifications::EmailConfig::from_env() {
                if settings.notify_on_workflow_action.unwrap_or(true) {
                    if let Some(email) = settings.notification_email {
                        let notifier = EmailNotifier::new(email_config, email);
                        if let Err(e) = self.send_email_stage_notification(
                            &notifier,
                            instance,
                            stage,
                            &vuln_title,
                            &severity,
                        ).await {
                            log::warn!("Failed to send email notification: {}", e);
                        }
                    }
                }
            }
        }

        log::info!(
            "Sent stage entered notifications for workflow {} stage {}",
            instance.id,
            stage.name
        );

        Ok(())
    }

    /// Send notification when SLA is breached
    pub async fn notify_sla_breach(
        &self,
        instance: &WorkflowInstance,
        stage: &WorkflowStage,
        deadline: Option<&DateTime<Utc>>,
    ) -> Result<()> {
        // Get vulnerability details
        let vuln = crate::db::get_vulnerability_detail(&self.pool, &instance.vulnerability_id).await;
        let vuln_title = vuln.as_ref()
            .map(|v| v.vulnerability.vulnerability_id.clone())
            .unwrap_or_else(|_| instance.vulnerability_id.clone());
        let severity = vuln.as_ref()
            .map(|v| v.vulnerability.severity.clone())
            .unwrap_or_else(|_| "Unknown".to_string());

        // Get notification settings
        if let Ok(settings) = db::get_system_notification_settings(&self.pool).await {
            // Send Slack notification if configured
            if let Some(webhook_url) = settings.slack_webhook_url {
                if settings.notify_on_sla_breach.unwrap_or(true) {
                    let notifier = SlackNotifier::new(webhook_url);
                    if let Err(e) = self.send_slack_sla_breach(
                        &notifier,
                        instance,
                        stage,
                        &vuln_title,
                        &severity,
                        deadline,
                    ).await {
                        log::warn!("Failed to send Slack SLA breach notification: {}", e);
                    }
                }
            }

            // Send Teams notification if configured
            if let Some(webhook_url) = settings.teams_webhook_url {
                if settings.notify_on_sla_breach.unwrap_or(true) {
                    let notifier = TeamsNotifier::new(webhook_url);
                    if let Err(e) = self.send_teams_sla_breach(
                        &notifier,
                        instance,
                        stage,
                        &vuln_title,
                        &severity,
                        deadline,
                    ).await {
                        log::warn!("Failed to send Teams SLA breach notification: {}", e);
                    }
                }
            }
        }

        log::warn!(
            "SLA breached for workflow {} stage {} (deadline: {:?})",
            instance.id,
            stage.name,
            deadline
        );

        Ok(())
    }

    /// Send notification when workflow is completed
    pub async fn notify_workflow_completed(&self, instance: &WorkflowInstance) -> Result<()> {
        // Get notification settings
        if let Ok(settings) = db::get_system_notification_settings(&self.pool).await {
            if let Some(webhook_url) = settings.slack_webhook_url {
                if settings.notify_on_workflow_action.unwrap_or(true) {
                    let notifier = SlackNotifier::new(webhook_url);
                    if let Err(e) = self.send_slack_workflow_completed(&notifier, instance).await {
                        log::warn!("Failed to send Slack completion notification: {}", e);
                    }
                }
            }

            if let Some(webhook_url) = settings.teams_webhook_url {
                if settings.notify_on_workflow_action.unwrap_or(true) {
                    let notifier = TeamsNotifier::new(webhook_url);
                    if let Err(e) = self.send_teams_workflow_completed(&notifier, instance).await {
                        log::warn!("Failed to send Teams completion notification: {}", e);
                    }
                }
            }
        }

        log::info!("Workflow {} completed", instance.id);
        Ok(())
    }

    /// Send notification when workflow is rejected
    pub async fn notify_workflow_rejected(
        &self,
        instance: &WorkflowInstance,
        stage: &WorkflowStage,
        reason: &str,
    ) -> Result<()> {
        // Get notification settings
        if let Ok(settings) = db::get_system_notification_settings(&self.pool).await {
            if let Some(webhook_url) = settings.slack_webhook_url {
                if settings.notify_on_workflow_action.unwrap_or(true) {
                    let notifier = SlackNotifier::new(webhook_url);
                    if let Err(e) = self.send_slack_workflow_rejected(
                        &notifier,
                        instance,
                        stage,
                        reason,
                    ).await {
                        log::warn!("Failed to send Slack rejection notification: {}", e);
                    }
                }
            }

            if let Some(webhook_url) = settings.teams_webhook_url {
                if settings.notify_on_workflow_action.unwrap_or(true) {
                    let notifier = TeamsNotifier::new(webhook_url);
                    if let Err(e) = self.send_teams_workflow_rejected(
                        &notifier,
                        instance,
                        stage,
                        reason,
                    ).await {
                        log::warn!("Failed to send Teams rejection notification: {}", e);
                    }
                }
            }
        }

        log::info!("Workflow {} rejected at stage {}: {}", instance.id, stage.name, reason);
        Ok(())
    }

    // ============================================================================
    // Private Slack notification methods
    // ============================================================================

    async fn send_slack_stage_notification(
        &self,
        notifier: &SlackNotifier,
        instance: &WorkflowInstance,
        stage: &WorkflowStage,
        vuln_title: &str,
        severity: &str,
    ) -> Result<()> {
        let color = match severity.to_lowercase().as_str() {
            "critical" => "#DC2626",
            "high" => "#EA580C",
            "medium" => "#CA8A04",
            "low" => "#65A30D",
            _ => "#6B7280",
        };

        let payload = serde_json::json!({
            "attachments": [{
                "color": color,
                "title": format!("Workflow Stage: {} - Action Required", stage.name),
                "text": format!(
                    "A vulnerability remediation workflow requires your attention.\n\n\
                    *Vulnerability:* {}\n\
                    *Severity:* {}\n\
                    *Stage:* {}\n\
                    *Required Approvals:* {}",
                    vuln_title,
                    severity,
                    stage.name,
                    stage.required_approvals
                ),
                "fields": [
                    {
                        "title": "Workflow ID",
                        "value": &instance.id,
                        "short": true
                    },
                    {
                        "title": "Stage Type",
                        "value": &stage.stage_type,
                        "short": true
                    }
                ],
                "footer": "HeroForge Remediation Workflow",
                "ts": chrono::Utc::now().timestamp()
            }]
        });

        notifier.send_raw_message(&payload).await
    }

    async fn send_slack_sla_breach(
        &self,
        notifier: &SlackNotifier,
        instance: &WorkflowInstance,
        stage: &WorkflowStage,
        vuln_title: &str,
        severity: &str,
        deadline: Option<&DateTime<Utc>>,
    ) -> Result<()> {
        let deadline_str = deadline
            .map(|d| d.format("%Y-%m-%d %H:%M UTC").to_string())
            .unwrap_or_else(|| "Not set".to_string());

        let payload = serde_json::json!({
            "attachments": [{
                "color": "#DC2626",
                "title": ":warning: SLA Breach Alert",
                "text": format!(
                    "A workflow stage has exceeded its SLA deadline!\n\n\
                    *Vulnerability:* {}\n\
                    *Severity:* {}\n\
                    *Stage:* {}\n\
                    *SLA Deadline:* {}",
                    vuln_title,
                    severity,
                    stage.name,
                    deadline_str
                ),
                "fields": [
                    {
                        "title": "Workflow ID",
                        "value": &instance.id,
                        "short": true
                    },
                    {
                        "title": "SLA Hours",
                        "value": stage.sla_hours.map(|h| format!("{} hours", h)).unwrap_or_else(|| "N/A".to_string()),
                        "short": true
                    }
                ],
                "footer": "HeroForge SLA Monitor",
                "ts": chrono::Utc::now().timestamp()
            }]
        });

        notifier.send_raw_message(&payload).await
    }

    async fn send_slack_workflow_completed(
        &self,
        notifier: &SlackNotifier,
        instance: &WorkflowInstance,
    ) -> Result<()> {
        let duration = instance.completed_at
            .map(|c| {
                let duration = c - instance.started_at;
                format!("{} hours", duration.num_hours())
            })
            .unwrap_or_else(|| "N/A".to_string());

        let payload = serde_json::json!({
            "attachments": [{
                "color": "#16A34A",
                "title": ":white_check_mark: Workflow Completed",
                "text": format!(
                    "A remediation workflow has been completed successfully.\n\n\
                    *Vulnerability ID:* {}\n\
                    *Duration:* {}",
                    instance.vulnerability_id,
                    duration
                ),
                "fields": [
                    {
                        "title": "Workflow ID",
                        "value": &instance.id,
                        "short": true
                    }
                ],
                "footer": "HeroForge Remediation Workflow",
                "ts": chrono::Utc::now().timestamp()
            }]
        });

        notifier.send_raw_message(&payload).await
    }

    async fn send_slack_workflow_rejected(
        &self,
        notifier: &SlackNotifier,
        instance: &WorkflowInstance,
        stage: &WorkflowStage,
        reason: &str,
    ) -> Result<()> {
        let payload = serde_json::json!({
            "attachments": [{
                "color": "#DC2626",
                "title": ":x: Workflow Rejected",
                "text": format!(
                    "A remediation workflow has been rejected.\n\n\
                    *Vulnerability ID:* {}\n\
                    *Stage:* {}\n\
                    *Reason:* {}",
                    instance.vulnerability_id,
                    stage.name,
                    reason
                ),
                "fields": [
                    {
                        "title": "Workflow ID",
                        "value": &instance.id,
                        "short": true
                    }
                ],
                "footer": "HeroForge Remediation Workflow",
                "ts": chrono::Utc::now().timestamp()
            }]
        });

        notifier.send_raw_message(&payload).await
    }

    // ============================================================================
    // Private Teams notification methods
    // ============================================================================

    async fn send_teams_stage_notification(
        &self,
        notifier: &TeamsNotifier,
        instance: &WorkflowInstance,
        stage: &WorkflowStage,
        vuln_title: &str,
        severity: &str,
    ) -> Result<()> {
        let color = match severity.to_lowercase().as_str() {
            "critical" => "attention",
            "high" => "warning",
            "medium" => "warning",
            "low" => "good",
            _ => "default",
        };

        let payload = serde_json::json!({
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": color,
            "summary": format!("Workflow Stage: {} - Action Required", stage.name),
            "sections": [{
                "activityTitle": format!("Workflow Stage: {} - Action Required", stage.name),
                "facts": [
                    {"name": "Vulnerability", "value": vuln_title},
                    {"name": "Severity", "value": severity},
                    {"name": "Stage", "value": &stage.name},
                    {"name": "Required Approvals", "value": stage.required_approvals.to_string()},
                    {"name": "Workflow ID", "value": &instance.id}
                ],
                "markdown": true
            }]
        });

        notifier.send_raw_message(&payload).await
    }

    async fn send_teams_sla_breach(
        &self,
        notifier: &TeamsNotifier,
        instance: &WorkflowInstance,
        stage: &WorkflowStage,
        vuln_title: &str,
        severity: &str,
        deadline: Option<&DateTime<Utc>>,
    ) -> Result<()> {
        let deadline_str = deadline
            .map(|d| d.format("%Y-%m-%d %H:%M UTC").to_string())
            .unwrap_or_else(|| "Not set".to_string());

        let payload = serde_json::json!({
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": "attention",
            "summary": "SLA Breach Alert",
            "sections": [{
                "activityTitle": "SLA Breach Alert",
                "facts": [
                    {"name": "Vulnerability", "value": vuln_title},
                    {"name": "Severity", "value": severity},
                    {"name": "Stage", "value": &stage.name},
                    {"name": "SLA Deadline", "value": deadline_str},
                    {"name": "Workflow ID", "value": &instance.id}
                ],
                "markdown": true
            }]
        });

        notifier.send_raw_message(&payload).await
    }

    async fn send_teams_workflow_completed(
        &self,
        notifier: &TeamsNotifier,
        instance: &WorkflowInstance,
    ) -> Result<()> {
        let duration = instance.completed_at
            .map(|c| {
                let duration = c - instance.started_at;
                format!("{} hours", duration.num_hours())
            })
            .unwrap_or_else(|| "N/A".to_string());

        let payload = serde_json::json!({
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": "good",
            "summary": "Workflow Completed",
            "sections": [{
                "activityTitle": "Workflow Completed Successfully",
                "facts": [
                    {"name": "Vulnerability ID", "value": &instance.vulnerability_id},
                    {"name": "Duration", "value": duration},
                    {"name": "Workflow ID", "value": &instance.id}
                ],
                "markdown": true
            }]
        });

        notifier.send_raw_message(&payload).await
    }

    async fn send_teams_workflow_rejected(
        &self,
        notifier: &TeamsNotifier,
        instance: &WorkflowInstance,
        stage: &WorkflowStage,
        reason: &str,
    ) -> Result<()> {
        let payload = serde_json::json!({
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": "attention",
            "summary": "Workflow Rejected",
            "sections": [{
                "activityTitle": "Workflow Rejected",
                "facts": [
                    {"name": "Vulnerability ID", "value": &instance.vulnerability_id},
                    {"name": "Stage", "value": &stage.name},
                    {"name": "Reason", "value": reason},
                    {"name": "Workflow ID", "value": &instance.id}
                ],
                "markdown": true
            }]
        });

        notifier.send_raw_message(&payload).await
    }

    // ============================================================================
    // Private Email notification methods
    // ============================================================================

    async fn send_email_stage_notification(
        &self,
        notifier: &EmailNotifier,
        instance: &WorkflowInstance,
        stage: &WorkflowStage,
        vuln_title: &str,
        severity: &str,
    ) -> Result<()> {
        let subject = format!("[HeroForge] Workflow Action Required: {} - {}", stage.name, vuln_title);

        let text_body = format!(
            "A vulnerability remediation workflow requires your attention.\n\n\
            Vulnerability: {}\n\
            Severity: {}\n\
            Stage: {}\n\
            Required Approvals: {}\n\
            Workflow ID: {}\n\n\
            Please log in to HeroForge to review and take action.",
            vuln_title,
            severity,
            stage.name,
            stage.required_approvals,
            instance.id
        );

        let severity_color = match severity.to_lowercase().as_str() {
            "critical" => "#DC2626",
            "high" => "#EA580C",
            "medium" => "#CA8A04",
            "low" => "#65A30D",
            _ => "#6B7280",
        };

        let html_body = format!(r#"
            <html>
            <body style="font-family: Arial, sans-serif; line-height: 1.6;">
                <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                    <h2 style="color: #1e293b;">Workflow Action Required</h2>
                    <p>A vulnerability remediation workflow requires your attention.</p>

                    <table style="width: 100%; border-collapse: collapse; margin: 20px 0;">
                        <tr>
                            <td style="padding: 10px; border-bottom: 1px solid #e2e8f0;"><strong>Vulnerability</strong></td>
                            <td style="padding: 10px; border-bottom: 1px solid #e2e8f0;">{}</td>
                        </tr>
                        <tr>
                            <td style="padding: 10px; border-bottom: 1px solid #e2e8f0;"><strong>Severity</strong></td>
                            <td style="padding: 10px; border-bottom: 1px solid #e2e8f0;">
                                <span style="background-color: {}; color: white; padding: 2px 8px; border-radius: 4px;">{}</span>
                            </td>
                        </tr>
                        <tr>
                            <td style="padding: 10px; border-bottom: 1px solid #e2e8f0;"><strong>Stage</strong></td>
                            <td style="padding: 10px; border-bottom: 1px solid #e2e8f0;">{}</td>
                        </tr>
                        <tr>
                            <td style="padding: 10px; border-bottom: 1px solid #e2e8f0;"><strong>Required Approvals</strong></td>
                            <td style="padding: 10px; border-bottom: 1px solid #e2e8f0;">{}</td>
                        </tr>
                    </table>

                    <p style="color: #64748b; font-size: 12px;">
                        Workflow ID: {}
                    </p>
                </div>
            </body>
            </html>
        "#, vuln_title, severity_color, severity, stage.name, stage.required_approvals, instance.id);

        notifier.send_email(&subject, &text_body, &html_body).await
    }
}
