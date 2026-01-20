//! Security Score Badge API
//!
//! Provides embeddable security badges for websites showing real-time security posture.
//! This is a viral growth feature - badges drive awareness and signups.

use actix_web::{web, HttpRequest, HttpResponse};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

// ============================================================================
// Types
// ============================================================================

#[derive(Debug, Serialize, Deserialize)]
pub struct SecurityScore {
    pub domain: String,
    pub score: i32,           // 0-100
    pub grade: String,        // A+, A, B, C, D, F
    pub grade_color: String,  // hex color for the grade
    pub last_scan: Option<String>,
    pub issues: SecurityIssues,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct SecurityIssues {
    pub critical: i32,
    pub high: i32,
    pub medium: i32,
    pub low: i32,
    pub info: i32,
}

#[derive(Debug, Deserialize)]
pub struct BadgeQuery {
    pub style: Option<String>,  // shield, flat, gradient
    pub label: Option<String>,  // custom label text
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

// ============================================================================
// Score Calculation
// ============================================================================

fn calculate_grade(score: i32) -> (String, String) {
    match score {
        95..=100 => ("A+".to_string(), "#22c55e".to_string()), // green-500
        90..=94 => ("A".to_string(), "#22c55e".to_string()),
        85..=89 => ("A-".to_string(), "#84cc16".to_string()),  // lime-500
        80..=84 => ("B+".to_string(), "#84cc16".to_string()),
        75..=79 => ("B".to_string(), "#eab308".to_string()),   // yellow-500
        70..=74 => ("B-".to_string(), "#eab308".to_string()),
        65..=69 => ("C+".to_string(), "#f97316".to_string()),  // orange-500
        60..=64 => ("C".to_string(), "#f97316".to_string()),
        55..=59 => ("C-".to_string(), "#ef4444".to_string()),  // red-500
        50..=54 => ("D+".to_string(), "#ef4444".to_string()),
        40..=49 => ("D".to_string(), "#dc2626".to_string()),   // red-600
        _ => ("F".to_string(), "#991b1b".to_string()),         // red-800
    }
}

fn calculate_score_from_issues(issues: &SecurityIssues) -> i32 {
    // Start at 100, deduct based on severity
    let mut score = 100;
    score -= issues.critical * 20;  // Critical issues are severe
    score -= issues.high * 10;
    score -= issues.medium * 5;
    score -= issues.low * 2;
    score -= issues.info * 1;

    // Clamp to 0-100
    score.max(0).min(100)
}

// ============================================================================
// SVG Badge Generation
// ============================================================================

fn generate_shield_badge(grade: &str, grade_color: &str, label: &str) -> String {
    let label_width = (label.len() * 7 + 10) as i32;
    let grade_width = 45;
    let total_width = label_width + grade_width;

    format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" width="{total_width}" height="20" role="img" aria-label="{label}: {grade}">
  <title>{label}: {grade}</title>
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r">
    <rect width="{total_width}" height="20" rx="3" fill="#fff"/>
  </clipPath>
  <g clip-path="url(#r)">
    <rect width="{label_width}" height="20" fill="#555"/>
    <rect x="{label_width}" width="{grade_width}" height="20" fill="{grade_color}"/>
    <rect width="{total_width}" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="11">
    <text aria-hidden="true" x="{label_x}" y="15" fill="#010101" fill-opacity=".3">{label}</text>
    <text x="{label_x}" y="14">{label}</text>
    <text aria-hidden="true" x="{grade_x}" y="15" fill="#010101" fill-opacity=".3">{grade}</text>
    <text x="{grade_x}" y="14">{grade}</text>
  </g>
</svg>"##,
        total_width = total_width,
        label_width = label_width,
        grade_width = grade_width,
        grade_color = grade_color,
        label = label,
        grade = grade,
        label_x = label_width / 2,
        grade_x = label_width + grade_width / 2,
    )
}

fn generate_flat_badge(grade: &str, grade_color: &str, label: &str) -> String {
    let label_width = (label.len() * 7 + 10) as i32;
    let grade_width = 45;
    let total_width = label_width + grade_width;

    format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" width="{total_width}" height="20" role="img" aria-label="{label}: {grade}">
  <title>{label}: {grade}</title>
  <rect width="{label_width}" height="20" fill="#555"/>
  <rect x="{label_width}" width="{grade_width}" height="20" fill="{grade_color}"/>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="11">
    <text x="{label_x}" y="14">{label}</text>
    <text x="{grade_x}" y="14">{grade}</text>
  </g>
</svg>"##,
        total_width = total_width,
        label_width = label_width,
        grade_width = grade_width,
        grade_color = grade_color,
        label = label,
        grade = grade,
        label_x = label_width / 2,
        grade_x = label_width + grade_width / 2,
    )
}

fn generate_gradient_badge(score: i32, grade: &str, grade_color: &str, label: &str) -> String {
    let width = 140;
    let height = 28;
    let bar_width = ((score as f32 / 100.0) * 100.0) as i32;

    format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" role="img" aria-label="{label}: {grade}">
  <title>{label}: {grade} ({score}/100)</title>
  <defs>
    <linearGradient id="bg" x1="0%" y1="0%" x2="100%" y2="0%">
      <stop offset="0%" style="stop-color:#1f2937"/>
      <stop offset="100%" style="stop-color:#374151"/>
    </linearGradient>
    <linearGradient id="bar" x1="0%" y1="0%" x2="100%" y2="0%">
      <stop offset="0%" style="stop-color:{grade_color}"/>
      <stop offset="100%" style="stop-color:{grade_color};stop-opacity:0.7"/>
    </linearGradient>
  </defs>
  <rect width="{width}" height="{height}" rx="4" fill="url(#bg)"/>
  <rect x="4" y="20" width="{bar_width}" height="4" rx="2" fill="url(#bar)"/>
  <rect x="4" y="20" width="100" height="4" rx="2" fill="#374151" opacity="0.5"/>
  <rect x="4" y="20" width="{bar_width}" height="4" rx="2" fill="url(#bar)"/>
  <g fill="#fff" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision">
    <text x="8" y="14" font-size="10" fill="#9ca3af">{label}</text>
    <text x="132" y="14" font-size="12" font-weight="bold" text-anchor="end" fill="{grade_color}">{grade}</text>
  </g>
</svg>"##,
        width = width,
        height = height,
        bar_width = bar_width,
        grade_color = grade_color,
        label = label,
        grade = grade,
        score = score,
    )
}

// ============================================================================
// API Handlers
// ============================================================================

/// GET /api/badges/{domain}
/// Returns an SVG badge for the domain's security score
pub async fn get_badge(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    query: web::Query<BadgeQuery>,
) -> HttpResponse {
    let domain = path.into_inner();
    let style = query.style.clone().unwrap_or_else(|| "shield".to_string());
    let label = query.label.clone().unwrap_or_else(|| "security".to_string());

    // Try to get cached score from database
    let score_result = get_domain_score(&pool, &domain).await;

    let security_score = match score_result {
        Ok(Some(score)) => score,
        Ok(None) => {
            // No score yet - return "unknown" badge
            let svg = generate_shield_badge("?", "#6b7280", &label);
            return HttpResponse::Ok()
                .content_type("image/svg+xml")
                .insert_header(("Cache-Control", "public, max-age=3600"))
                .body(svg);
        }
        Err(e) => {
            log::error!("Failed to get domain score: {}", e);
            let svg = generate_shield_badge("?", "#6b7280", &label);
            return HttpResponse::Ok()
                .content_type("image/svg+xml")
                .insert_header(("Cache-Control", "public, max-age=60"))
                .body(svg);
        }
    };

    let svg = match style.as_str() {
        "flat" => generate_flat_badge(&security_score.grade, &security_score.grade_color, &label),
        "gradient" => generate_gradient_badge(
            security_score.score,
            &security_score.grade,
            &security_score.grade_color,
            &label,
        ),
        _ => generate_shield_badge(&security_score.grade, &security_score.grade_color, &label),
    };

    HttpResponse::Ok()
        .content_type("image/svg+xml")
        .insert_header(("Cache-Control", "public, max-age=3600")) // Cache for 1 hour
        .body(svg)
}

/// GET /api/badges/{domain}/score
/// Returns the full security score details as JSON
pub async fn get_score(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> HttpResponse {
    let domain = path.into_inner();

    match get_domain_score(&pool, &domain).await {
        Ok(Some(score)) => HttpResponse::Ok().json(ApiResponse::success(score)),
        Ok(None) => HttpResponse::NotFound().json(ApiResponse::<()>::error(
            "No security score found for this domain. Request a scan first."
        )),
        Err(e) => {
            log::error!("Failed to get domain score: {}", e);
            HttpResponse::InternalServerError().json(ApiResponse::<()>::error("Failed to retrieve score"))
        }
    }
}

/// POST /api/badges/{domain}/scan
/// Request a security scan for a domain (rate limited)
pub async fn request_scan(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    req: HttpRequest,
) -> HttpResponse {
    let domain = path.into_inner();

    // Validate domain format
    if !is_valid_domain(&domain) {
        return HttpResponse::BadRequest().json(ApiResponse::<()>::error("Invalid domain format"));
    }

    // Check if we've scanned recently (rate limit: 1 scan per domain per hour)
    match get_last_scan_time(&pool, &domain).await {
        Ok(Some(last_scan)) => {
            let now = chrono::Utc::now();
            if let Ok(last) = chrono::DateTime::parse_from_rfc3339(&last_scan) {
                let elapsed = now.signed_duration_since(last);
                if elapsed.num_hours() < 1 {
                    return HttpResponse::TooManyRequests().json(ApiResponse::<()>::error(
                        format!("Domain was scanned recently. Next scan available in {} minutes.",
                            60 - elapsed.num_minutes())
                    ));
                }
            }
        }
        Ok(None) => {}
        Err(e) => {
            log::error!("Failed to check last scan time: {}", e);
        }
    }

    // Queue the scan (in production, this would trigger an async job)
    // For now, we'll do a quick lightweight scan
    match perform_quick_scan(&pool, &domain).await {
        Ok(score) => HttpResponse::Ok().json(ApiResponse::success(score)),
        Err(e) => {
            log::error!("Failed to perform scan: {}", e);
            HttpResponse::InternalServerError().json(ApiResponse::<()>::error("Failed to perform scan"))
        }
    }
}

/// GET /api/badges/{domain}/embed
/// Returns embed code snippets for the badge
pub async fn get_embed_code(
    path: web::Path<String>,
    req: HttpRequest,
) -> HttpResponse {
    let domain = path.into_inner();

    // Get the base URL from the request
    let base_url = req
        .connection_info()
        .scheme()
        .to_string()
        + "://"
        + req.connection_info().host();

    let embed_codes = serde_json::json!({
        "markdown": format!("[![Security Score]({})]({})",
            format!("{}/api/badges/{}", base_url, domain),
            format!("{}/security/{}", base_url, domain)
        ),
        "html": format!(
            r#"<a href="{}/security/{}"><img src="{}/api/badges/{}" alt="Security Score" /></a>"#,
            base_url, domain, base_url, domain
        ),
        "html_flat": format!(
            r#"<a href="{}/security/{}"><img src="{}/api/badges/{}?style=flat" alt="Security Score" /></a>"#,
            base_url, domain, base_url, domain
        ),
        "html_gradient": format!(
            r#"<a href="{}/security/{}"><img src="{}/api/badges/{}?style=gradient" alt="Security Score" /></a>"#,
            base_url, domain, base_url, domain
        ),
        "image_url": format!("{}/api/badges/{}", base_url, domain),
        "profile_url": format!("{}/security/{}", base_url, domain),
    });

    HttpResponse::Ok().json(ApiResponse::success(embed_codes))
}

// ============================================================================
// Database Functions
// ============================================================================

async fn get_domain_score(pool: &SqlitePool, domain: &str) -> anyhow::Result<Option<SecurityScore>> {
    let row = sqlx::query_as::<_, (String, i32, i32, i32, i32, i32, Option<String>)>(
        r#"SELECT domain, critical_count, high_count, medium_count, low_count, info_count, last_scan_at
           FROM security_badges
           WHERE domain = ?
           ORDER BY last_scan_at DESC
           LIMIT 1"#
    )
    .bind(domain)
    .fetch_optional(pool)
    .await?;

    match row {
        Some((domain, critical, high, medium, low, info, last_scan)) => {
            let issues = SecurityIssues {
                critical,
                high,
                medium,
                low,
                info,
            };
            let score = calculate_score_from_issues(&issues);
            let (grade, grade_color) = calculate_grade(score);

            Ok(Some(SecurityScore {
                domain,
                score,
                grade,
                grade_color,
                last_scan,
                issues,
            }))
        }
        None => Ok(None),
    }
}

async fn get_last_scan_time(pool: &SqlitePool, domain: &str) -> anyhow::Result<Option<String>> {
    let row = sqlx::query_scalar::<_, String>(
        "SELECT last_scan_at FROM security_badges WHERE domain = ? ORDER BY last_scan_at DESC LIMIT 1"
    )
    .bind(domain)
    .fetch_optional(pool)
    .await?;

    Ok(row)
}

async fn save_domain_score(pool: &SqlitePool, score: &SecurityScore) -> anyhow::Result<()> {
    sqlx::query(
        r#"INSERT OR REPLACE INTO security_badges
           (domain, critical_count, high_count, medium_count, low_count, info_count, last_scan_at)
           VALUES (?, ?, ?, ?, ?, ?, datetime('now'))"#
    )
    .bind(&score.domain)
    .bind(score.issues.critical)
    .bind(score.issues.high)
    .bind(score.issues.medium)
    .bind(score.issues.low)
    .bind(score.issues.info)
    .execute(pool)
    .await?;

    Ok(())
}

// ============================================================================
// Scanning Functions
// ============================================================================

fn is_valid_domain(domain: &str) -> bool {
    // Basic domain validation
    if domain.is_empty() || domain.len() > 253 {
        return false;
    }

    // Must contain at least one dot
    if !domain.contains('.') {
        return false;
    }

    // Check for valid characters
    domain.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '.')
}

async fn perform_quick_scan(pool: &SqlitePool, domain: &str) -> anyhow::Result<SecurityScore> {
    // This is a lightweight scan that checks:
    // 1. SSL/TLS configuration
    // 2. Security headers
    // 3. DNS security (SPF, DKIM, DMARC)

    let mut issues = SecurityIssues::default();

    // Check HTTPS availability
    let https_url = format!("https://{}", domain);
    match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?
        .get(&https_url)
        .send()
        .await
    {
        Ok(response) => {
            // Check security headers
            let headers = response.headers();

            // Strict-Transport-Security
            if headers.get("strict-transport-security").is_none() {
                issues.medium += 1;
            }

            // X-Content-Type-Options
            if headers.get("x-content-type-options").is_none() {
                issues.low += 1;
            }

            // X-Frame-Options or CSP frame-ancestors
            if headers.get("x-frame-options").is_none()
               && headers.get("content-security-policy").is_none() {
                issues.medium += 1;
            }

            // Content-Security-Policy
            if headers.get("content-security-policy").is_none() {
                issues.medium += 1;
            }

            // X-XSS-Protection (deprecated but still useful)
            if headers.get("x-xss-protection").is_none() {
                issues.info += 1;
            }

            // Referrer-Policy
            if headers.get("referrer-policy").is_none() {
                issues.low += 1;
            }

            // Permissions-Policy
            if headers.get("permissions-policy").is_none() {
                issues.info += 1;
            }
        }
        Err(_) => {
            // HTTPS not available - critical issue
            issues.critical += 1;
        }
    }

    // Check DNS security records
    // In production, this would use a DNS library
    // For now, we'll add placeholder checks

    let score = calculate_score_from_issues(&issues);
    let (grade, grade_color) = calculate_grade(score);

    let security_score = SecurityScore {
        domain: domain.to_string(),
        score,
        grade,
        grade_color,
        last_scan: Some(chrono::Utc::now().to_rfc3339()),
        issues,
    };

    // Save to database
    save_domain_score(pool, &security_score).await?;

    Ok(security_score)
}

// ============================================================================
// Route Configuration
// ============================================================================

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg
        .route("/badges/{domain}", web::get().to(get_badge))
        .route("/badges/{domain}/score", web::get().to(get_score))
        .route("/badges/{domain}/scan", web::post().to(request_scan))
        .route("/badges/{domain}/embed", web::get().to(get_embed_code));
}
