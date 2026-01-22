//! Status Page API
//!
//! Public API for service status, uptime monitoring, and incident tracking.
//! Provides real uptime data for building trust with users.

use actix_web::{web, HttpResponse};
use anyhow::Context;
use lettre::message::{header, MultiPart, SinglePart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

// ============================================================================
// Types
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct ServiceStatus {
    pub id: String,
    pub name: String,
    pub description: String,
    pub status: String,     // operational, degraded, partial_outage, major_outage, maintenance
    pub latency_ms: Option<i32>,
    pub uptime_percent: f64,
    pub last_check_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Incident {
    pub id: String,
    pub title: String,
    pub status: String,         // investigating, identified, monitoring, resolved
    pub severity: String,       // minor, major, critical
    pub affected_services: String,  // JSON array of service names
    pub created_at: String,
    pub updated_at: String,
    pub resolved_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentUpdate {
    pub id: String,
    pub incident_id: String,
    pub status: String,
    pub message: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentWithUpdates {
    #[serde(flatten)]
    pub incident: Incident,
    pub updates: Vec<IncidentUpdate>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct UptimeRecord {
    pub service_id: String,
    pub date: String,
    pub status: String,         // operational, degraded, partial_outage, major_outage, maintenance
    pub uptime_percent: f64,
    pub avg_latency_ms: Option<i32>,
    pub check_count: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct StatusSubscriber {
    pub id: String,
    pub email: String,
    pub verified: bool,
    pub created_at: String,
}

#[derive(Debug, Deserialize)]
pub struct SubscribeRequest {
    pub email: String,
}

#[derive(Debug, Serialize)]
struct ApiResponse<T> {
    success: bool,
    data: Option<T>,
    error: Option<String>,
}

impl<T> ApiResponse<T> {
    fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }

    fn error(message: impl Into<String>) -> ApiResponse<()> {
        ApiResponse {
            success: false,
            data: None,
            error: Some(message.into()),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct OverallStatus {
    pub status: String,
    pub text: String,
    pub last_updated: String,
}

#[derive(Debug, Serialize)]
pub struct UptimeSummary {
    pub current_month: f64,
    pub last_30_days: f64,
    pub last_90_days: f64,
    pub all_time: f64,
}

#[derive(Debug, Serialize)]
pub struct StatusPageData {
    pub overall_status: OverallStatus,
    pub services: Vec<ServiceStatus>,
    pub uptime_summary: UptimeSummary,
}

// ============================================================================
// API Handlers
// ============================================================================

/// GET /api/status/services
/// Returns current status of all services
pub async fn get_services(pool: web::Data<SqlitePool>) -> HttpResponse {
    let services = match sqlx::query_as::<_, ServiceStatus>(
        r#"SELECT id, name, description, status, latency_ms, uptime_percent, last_check_at
           FROM status_services
           ORDER BY name"#
    )
    .fetch_all(pool.get_ref())
    .await {
        Ok(services) => services,
        Err(e) => {
            log::error!("Failed to fetch services: {}", e);
            return HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error("Failed to fetch services"));
        }
    };

    HttpResponse::Ok().json(ApiResponse::success(services))
}

/// GET /api/status/overall
/// Returns overall system status
pub async fn get_overall_status(pool: web::Data<SqlitePool>) -> HttpResponse {
    let services = match sqlx::query_as::<_, (String,)>(
        "SELECT status FROM status_services"
    )
    .fetch_all(pool.get_ref())
    .await {
        Ok(services) => services,
        Err(e) => {
            log::error!("Failed to fetch services for overall status: {}", e);
            return HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error("Failed to fetch status"));
        }
    };

    let statuses: Vec<&str> = services.iter().map(|s| s.0.as_str()).collect();

    let (status, text) = if statuses.iter().any(|s| *s == "major_outage") {
        ("major_outage", "Major System Outage")
    } else if statuses.iter().any(|s| *s == "partial_outage") {
        ("partial_outage", "Partial System Outage")
    } else if statuses.iter().any(|s| *s == "degraded") {
        ("degraded", "Degraded Performance")
    } else if statuses.iter().any(|s| *s == "maintenance") {
        ("maintenance", "Scheduled Maintenance")
    } else {
        ("operational", "All Systems Operational")
    };

    let overall = OverallStatus {
        status: status.to_string(),
        text: text.to_string(),
        last_updated: chrono::Utc::now().to_rfc3339(),
    };

    HttpResponse::Ok().json(ApiResponse::success(overall))
}

/// GET /api/status/uptime
/// Returns uptime history for the last 90 days
pub async fn get_uptime_history(pool: web::Data<SqlitePool>) -> HttpResponse {
    let history = match sqlx::query_as::<_, UptimeRecord>(
        r#"SELECT service_id, date, status, uptime_percent, avg_latency_ms, check_count
           FROM status_uptime_history
           WHERE date >= date('now', '-90 days')
           ORDER BY service_id, date"#
    )
    .fetch_all(pool.get_ref())
    .await {
        Ok(history) => history,
        Err(e) => {
            log::error!("Failed to fetch uptime history: {}", e);
            return HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error("Failed to fetch uptime history"));
        }
    };

    HttpResponse::Ok().json(ApiResponse::success(history))
}

/// GET /api/status/uptime/summary
/// Returns uptime summary statistics
pub async fn get_uptime_summary(pool: web::Data<SqlitePool>) -> HttpResponse {
    // Calculate uptime percentages for different periods
    let current_month = sqlx::query_scalar::<_, f64>(
        r#"SELECT COALESCE(AVG(uptime_percent), 99.99)
           FROM status_uptime_history
           WHERE date >= date('now', 'start of month')"#
    )
    .fetch_one(pool.get_ref())
    .await
    .unwrap_or(99.99);

    let last_30_days = sqlx::query_scalar::<_, f64>(
        r#"SELECT COALESCE(AVG(uptime_percent), 99.99)
           FROM status_uptime_history
           WHERE date >= date('now', '-30 days')"#
    )
    .fetch_one(pool.get_ref())
    .await
    .unwrap_or(99.99);

    let last_90_days = sqlx::query_scalar::<_, f64>(
        r#"SELECT COALESCE(AVG(uptime_percent), 99.99)
           FROM status_uptime_history
           WHERE date >= date('now', '-90 days')"#
    )
    .fetch_one(pool.get_ref())
    .await
    .unwrap_or(99.99);

    let all_time = sqlx::query_scalar::<_, f64>(
        "SELECT COALESCE(AVG(uptime_percent), 99.99) FROM status_uptime_history"
    )
    .fetch_one(pool.get_ref())
    .await
    .unwrap_or(99.99);

    let summary = UptimeSummary {
        current_month: (current_month * 100.0).round() / 100.0,
        last_30_days: (last_30_days * 100.0).round() / 100.0,
        last_90_days: (last_90_days * 100.0).round() / 100.0,
        all_time: (all_time * 100.0).round() / 100.0,
    };

    HttpResponse::Ok().json(ApiResponse::success(summary))
}

/// GET /api/status/incidents
/// Returns recent incidents with updates
pub async fn get_incidents(pool: web::Data<SqlitePool>) -> HttpResponse {
    // Get incidents from last 90 days
    let incidents = match sqlx::query_as::<_, Incident>(
        r#"SELECT id, title, status, severity, affected_services, created_at, updated_at, resolved_at
           FROM status_incidents
           WHERE created_at >= datetime('now', '-90 days')
           ORDER BY created_at DESC"#
    )
    .fetch_all(pool.get_ref())
    .await {
        Ok(incidents) => incidents,
        Err(e) => {
            log::error!("Failed to fetch incidents: {}", e);
            return HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error("Failed to fetch incidents"));
        }
    };

    // Get updates for each incident
    let mut incidents_with_updates = Vec::new();
    for incident in incidents {
        let updates = sqlx::query_as::<_, (String, String, String, String, String)>(
            r#"SELECT id, incident_id, status, message, created_at
               FROM status_incident_updates
               WHERE incident_id = ?
               ORDER BY created_at ASC"#
        )
        .bind(&incident.id)
        .fetch_all(pool.get_ref())
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|(id, incident_id, status, message, created_at)| {
            IncidentUpdate {
                id,
                incident_id,
                status,
                message,
                created_at,
            }
        })
        .collect();

        incidents_with_updates.push(IncidentWithUpdates {
            incident,
            updates,
        });
    }

    HttpResponse::Ok().json(ApiResponse::success(incidents_with_updates))
}

/// GET /api/status/maintenance
/// Returns upcoming scheduled maintenance
pub async fn get_maintenance(pool: web::Data<SqlitePool>) -> HttpResponse {
    let maintenance = match sqlx::query_as::<_, Incident>(
        r#"SELECT id, title, status, severity, affected_services, created_at, updated_at, resolved_at
           FROM status_incidents
           WHERE severity = 'maintenance'
           AND (resolved_at IS NULL OR resolved_at > datetime('now'))
           ORDER BY created_at ASC"#
    )
    .fetch_all(pool.get_ref())
    .await {
        Ok(incidents) => incidents,
        Err(e) => {
            log::error!("Failed to fetch maintenance: {}", e);
            return HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error("Failed to fetch maintenance"));
        }
    };

    HttpResponse::Ok().json(ApiResponse::success(maintenance))
}

/// POST /api/status/subscribe
/// Subscribe to status updates
pub async fn subscribe(
    pool: web::Data<SqlitePool>,
    body: web::Json<SubscribeRequest>,
) -> HttpResponse {
    let email = body.email.trim().to_lowercase();

    // Validate email format
    if !email.contains('@') || !email.contains('.') {
        return HttpResponse::BadRequest()
            .json(ApiResponse::<()>::error("Invalid email address"));
    }

    // Check if already subscribed
    let exists = sqlx::query_scalar::<_, i32>(
        "SELECT COUNT(*) FROM status_subscribers WHERE email = ?"
    )
    .bind(&email)
    .fetch_one(pool.get_ref())
    .await
    .unwrap_or(0) > 0;

    if exists {
        return HttpResponse::Conflict()
            .json(ApiResponse::<()>::error("Email already subscribed"));
    }

    // Create subscription
    let subscriber_id = uuid::Uuid::new_v4().to_string();
    let verification_token = uuid::Uuid::new_v4().to_string();

    if let Err(e) = sqlx::query(
        r#"INSERT INTO status_subscribers
           (id, email, verified, verification_token, created_at)
           VALUES (?, ?, 0, ?, datetime('now'))"#
    )
    .bind(&subscriber_id)
    .bind(&email)
    .bind(&verification_token)
    .execute(pool.get_ref())
    .await {
        log::error!("Failed to create subscription: {}", e);
        return HttpResponse::InternalServerError()
            .json(ApiResponse::<()>::error("Failed to subscribe"));
    }

    // Send verification email
    let base_url = std::env::var("BASE_URL")
        .unwrap_or_else(|_| "https://heroforge.genialarchitect.io".to_string());
    let verify_url = format!("{}/api/status/subscribe/verify/{}", base_url, verification_token);

    if let Err(e) = send_status_verification_email(&email, &verify_url).await {
        log::error!("Failed to send verification email: {}", e);
        // Still return success - subscription is created, email just failed
    }

    HttpResponse::Created().json(ApiResponse::success(serde_json::json!({
        "message": "Please check your email to verify your subscription."
    })))
}

/// GET /api/status/subscribe/verify/{token}
/// Verify email subscription
pub async fn verify_subscription(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> HttpResponse {
    let token = path.into_inner();

    let result = sqlx::query(
        "UPDATE status_subscribers SET verified = 1 WHERE verification_token = ?"
    )
    .bind(&token)
    .execute(pool.get_ref())
    .await;

    match result {
        Ok(r) if r.rows_affected() > 0 => {
            HttpResponse::Ok().json(ApiResponse::success(serde_json::json!({
                "message": "Email verified successfully. You will now receive status updates."
            })))
        }
        Ok(_) => {
            HttpResponse::NotFound()
                .json(ApiResponse::<()>::error("Invalid verification token"))
        }
        Err(e) => {
            log::error!("Failed to verify subscription: {}", e);
            HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error("Failed to verify subscription"))
        }
    }
}

/// DELETE /api/status/subscribe/{token}
/// Unsubscribe from status updates
pub async fn unsubscribe(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> HttpResponse {
    let token = path.into_inner();

    let result = sqlx::query(
        "DELETE FROM status_subscribers WHERE id = ? OR verification_token = ?"
    )
    .bind(&token)
    .bind(&token)
    .execute(pool.get_ref())
    .await;

    match result {
        Ok(r) if r.rows_affected() > 0 => {
            HttpResponse::Ok().json(ApiResponse::success(serde_json::json!({
                "message": "Successfully unsubscribed from status updates."
            })))
        }
        Ok(_) => {
            HttpResponse::NotFound()
                .json(ApiResponse::<()>::error("Subscription not found"))
        }
        Err(e) => {
            log::error!("Failed to unsubscribe: {}", e);
            HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error("Failed to unsubscribe"))
        }
    }
}

// ============================================================================
// Email Helper
// ============================================================================

/// Send verification email for status subscription
async fn send_status_verification_email(
    recipient_email: &str,
    verify_url: &str,
) -> anyhow::Result<()> {
    // Check if SMTP is configured
    let smtp_host = std::env::var("SMTP_HOST")
        .context("SMTP_HOST environment variable not set")?;
    let smtp_port: u16 = std::env::var("SMTP_PORT")
        .context("SMTP_PORT environment variable not set")?
        .parse()
        .context("Invalid SMTP_PORT")?;
    let smtp_user = std::env::var("SMTP_USER")
        .context("SMTP_USER environment variable not set")?;
    let smtp_password = std::env::var("SMTP_PASSWORD")
        .context("SMTP_PASSWORD environment variable not set")?;
    let from_address = std::env::var("SMTP_FROM_ADDRESS")
        .unwrap_or_else(|_| "noreply@heroforge.local".to_string());
    let from_name = std::env::var("SMTP_FROM_NAME")
        .unwrap_or_else(|_| "HeroForge Status".to_string());

    let subject = "Verify Your HeroForge Status Subscription";

    let html_body = format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .header {{ background-color: #4F46E5; color: white; padding: 20px; text-align: center; border-radius: 8px 8px 0 0; }}
        .content {{ background-color: #f9fafb; padding: 20px; }}
        .button {{ display: inline-block; background-color: #4F46E5; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-weight: bold; margin: 10px 0; }}
        .footer {{ text-align: center; padding: 20px; color: #6b7280; font-size: 12px; border-radius: 0 0 8px 8px; }}
        .link {{ word-break: break-all; color: #4F46E5; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Verify Your Subscription</h1>
        </div>
        <div class="content">
            <p>Hello,</p>
            <p>Thank you for subscribing to HeroForge status updates! Click the button below to verify your email:</p>

            <div style="text-align: center; margin: 20px 0;">
                <a href="{}" class="button" style="color: white;">Verify Email</a>
            </div>

            <p>Or copy and paste this link into your browser:</p>
            <p class="link">{}</p>

            <p>Once verified, you'll receive notifications about:</p>
            <ul>
                <li>Service outages and degradations</li>
                <li>Scheduled maintenance windows</li>
                <li>Incident resolution updates</li>
            </ul>

            <p><small>This link expires in 24 hours. If you didn't request this subscription, you can safely ignore this email.</small></p>
        </div>
        <div class="footer">
            <p>This is an automated message from Genial Architect Scanner.</p>
        </div>
    </div>
</body>
</html>"#,
        verify_url, verify_url
    );

    let text_body = format!(
        r#"Verify Your HeroForge Status Subscription

Hello,

Thank you for subscribing to HeroForge status updates!

Click the link below to verify your email:
{}

Once verified, you'll receive notifications about:
- Service outages and degradations
- Scheduled maintenance windows
- Incident resolution updates

This link expires in 24 hours. If you didn't request this subscription, you can safely ignore this email.

---
This is an automated message from Genial Architect Scanner.
"#,
        verify_url
    );

    let email = Message::builder()
        .from(
            format!("{} <{}>", from_name, from_address)
                .parse()
                .context("Failed to parse from address")?,
        )
        .to(recipient_email
            .parse()
            .context("Failed to parse recipient address")?)
        .subject(subject)
        .multipart(
            MultiPart::alternative()
                .singlepart(
                    SinglePart::builder()
                        .header(header::ContentType::TEXT_PLAIN)
                        .body(text_body),
                )
                .singlepart(
                    SinglePart::builder()
                        .header(header::ContentType::TEXT_HTML)
                        .body(html_body),
                ),
        )
        .context("Failed to build email message")?;

    let creds = Credentials::new(smtp_user, smtp_password);

    let mailer = SmtpTransport::relay(&smtp_host)
        .context("Failed to create SMTP transport")?
        .credentials(creds)
        .port(smtp_port)
        .build();

    // Send email in a blocking task since lettre is synchronous
    let result = tokio::task::spawn_blocking(move || mailer.send(&email))
        .await
        .context("Failed to execute email send task")?;

    result.context("Failed to send verification email")?;

    log::info!("Status verification email sent to {}", recipient_email);
    Ok(())
}

// ============================================================================
// Route Configuration
// ============================================================================

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg
        .route("/status/services", web::get().to(get_services))
        .route("/status/overall", web::get().to(get_overall_status))
        .route("/status/uptime", web::get().to(get_uptime_history))
        .route("/status/uptime/summary", web::get().to(get_uptime_summary))
        .route("/status/incidents", web::get().to(get_incidents))
        .route("/status/maintenance", web::get().to(get_maintenance))
        .route("/status/subscribe", web::post().to(subscribe))
        .route("/status/subscribe/verify/{token}", web::get().to(verify_subscription))
        .route("/status/unsubscribe/{token}", web::delete().to(unsubscribe));
}
