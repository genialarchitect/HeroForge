//! Custom Report Templates Database Module
//!
//! Provides CRUD operations for custom report templates, marketplace functionality,
//! ratings, versioning, and scheduled report delivery.

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

// ============================================================================
// Types
// ============================================================================

/// Base template types that custom templates extend
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum BaseTemplate {
    Executive,
    Technical,
    Compliance,
}

impl BaseTemplate {
    pub fn as_str(&self) -> &'static str {
        match self {
            BaseTemplate::Executive => "executive",
            BaseTemplate::Technical => "technical",
            BaseTemplate::Compliance => "compliance",
        }
    }
}

impl std::str::FromStr for BaseTemplate {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "executive" => Ok(BaseTemplate::Executive),
            "technical" => Ok(BaseTemplate::Technical),
            "compliance" => Ok(BaseTemplate::Compliance),
            _ => Err(format!("Invalid base template: {}", s)),
        }
    }
}

/// Custom report template record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomReportTemplate {
    pub id: String,
    pub user_id: String,
    pub organization_id: Option<String>,
    pub name: String,
    pub description: Option<String>,
    pub base_template: String,
    pub sections: serde_json::Value,
    pub branding: Option<serde_json::Value>,
    pub header_html: Option<String>,
    pub footer_html: Option<String>,
    pub css_overrides: Option<String>,
    pub cover_page_html: Option<String>,
    pub is_public: bool,
    pub is_active: bool,
    pub downloads: i32,
    pub rating: Option<f64>,
    pub rating_count: i32,
    pub version: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub published_at: Option<DateTime<Utc>>,
}

/// Template branding configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TemplateBranding {
    pub logo_url: Option<String>,
    pub logo_asset_id: Option<String>,
    pub company_name: Option<String>,
    pub primary_color: Option<String>,
    pub secondary_color: Option<String>,
    pub accent_color: Option<String>,
    pub font_family: Option<String>,
    pub header_background_color: Option<String>,
    pub footer_background_color: Option<String>,
}

/// Section configuration for templates
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionConfig {
    pub section_type: String,
    pub enabled: bool,
    pub order: i32,
    pub custom_title: Option<String>,
    pub custom_content: Option<String>,
    pub settings: Option<serde_json::Value>,
}

/// Template rating record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateRating {
    pub id: String,
    pub template_id: String,
    pub user_id: String,
    pub rating: i32,
    pub review: Option<String>,
    pub helpful_count: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Template rating with user info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateRatingWithUser {
    pub id: String,
    pub template_id: String,
    pub user_id: String,
    pub username: String,
    pub rating: i32,
    pub review: Option<String>,
    pub helpful_count: i32,
    pub created_at: DateTime<Utc>,
}

/// Template version record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateVersion {
    pub id: String,
    pub template_id: String,
    pub version: i32,
    pub sections: serde_json::Value,
    pub branding: Option<serde_json::Value>,
    pub header_html: Option<String>,
    pub footer_html: Option<String>,
    pub css_overrides: Option<String>,
    pub cover_page_html: Option<String>,
    pub change_notes: Option<String>,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
}

/// Reusable template section
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateSection {
    pub id: String,
    pub user_id: String,
    pub organization_id: Option<String>,
    pub name: String,
    pub section_type: String,
    pub content_html: String,
    pub content_css: Option<String>,
    pub is_public: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Template asset (logo, image)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateAsset {
    pub id: String,
    pub user_id: String,
    pub organization_id: Option<String>,
    pub name: String,
    pub asset_type: String,
    pub mime_type: String,
    pub file_path: String,
    pub file_size: i64,
    pub width: Option<i32>,
    pub height: Option<i32>,
    pub created_at: DateTime<Utc>,
}

/// Template usage statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateUsageStats {
    pub template_id: String,
    pub total_uses: i32,
    pub unique_users: i32,
    pub last_used_at: Option<DateTime<Utc>>,
}

/// Scheduled report delivery channel
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduledReportDelivery {
    pub id: String,
    pub scheduled_report_id: String,
    pub channel: String,
    pub channel_config: serde_json::Value,
    pub is_enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Scheduled report run history
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduledReportRun {
    pub id: String,
    pub scheduled_report_id: String,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub status: String,
    pub file_path: Option<String>,
    pub file_size: Option<i64>,
    pub recipients_notified: i32,
    pub error_message: Option<String>,
    pub delivery_results: Option<serde_json::Value>,
}

/// Marketplace template listing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarketplaceTemplate {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub base_template: String,
    pub author_username: String,
    pub author_id: String,
    pub downloads: i32,
    pub rating: Option<f64>,
    pub rating_count: i32,
    pub preview_image_url: Option<String>,
    pub created_at: DateTime<Utc>,
    pub published_at: Option<DateTime<Utc>>,
}

/// Template statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateStats {
    pub total_templates: i32,
    pub public_templates: i32,
    pub total_downloads: i32,
    pub avg_rating: Option<f64>,
    pub templates_by_base: Vec<BaseTemplateCount>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaseTemplateCount {
    pub base_template: String,
    pub count: i32,
}

// ============================================================================
// Request Types
// ============================================================================

#[derive(Debug, Clone, Deserialize)]
pub struct CreateTemplateRequest {
    pub name: String,
    pub description: Option<String>,
    pub base_template: String,
    pub sections: serde_json::Value,
    pub branding: Option<serde_json::Value>,
    pub header_html: Option<String>,
    pub footer_html: Option<String>,
    pub css_overrides: Option<String>,
    pub cover_page_html: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UpdateTemplateRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub sections: Option<serde_json::Value>,
    pub branding: Option<serde_json::Value>,
    pub header_html: Option<String>,
    pub footer_html: Option<String>,
    pub css_overrides: Option<String>,
    pub cover_page_html: Option<String>,
    pub change_notes: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateRatingRequest {
    pub rating: i32,
    pub review: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateSectionRequest {
    pub name: String,
    pub section_type: String,
    pub content_html: String,
    pub content_css: Option<String>,
    pub is_public: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateDeliveryChannelRequest {
    pub channel: String,
    pub channel_config: serde_json::Value,
    pub is_enabled: Option<bool>,
}

// ============================================================================
// Template CRUD Operations
// ============================================================================

/// Create a new custom report template
pub async fn create_template(
    pool: &SqlitePool,
    user_id: &str,
    organization_id: Option<&str>,
    request: CreateTemplateRequest,
) -> Result<CustomReportTemplate> {
    let id = uuid::Uuid::new_v4().to_string();
    let now = Utc::now();
    let sections_json = serde_json::to_string(&request.sections)?;
    let branding_json = request.branding.as_ref().map(|b| serde_json::to_string(b)).transpose()?;

    sqlx::query(
        r#"
        INSERT INTO custom_report_templates (
            id, user_id, organization_id, name, description, base_template,
            sections, branding, header_html, footer_html, css_overrides,
            cover_page_html, is_public, is_active, downloads, rating_count,
            version, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 1, 0, 0, 1, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(user_id)
    .bind(organization_id)
    .bind(&request.name)
    .bind(&request.description)
    .bind(&request.base_template)
    .bind(&sections_json)
    .bind(&branding_json)
    .bind(&request.header_html)
    .bind(&request.footer_html)
    .bind(&request.css_overrides)
    .bind(&request.cover_page_html)
    .bind(now.to_rfc3339())
    .bind(now.to_rfc3339())
    .execute(pool)
    .await?;

    get_template_by_id(pool, &id).await?.ok_or_else(|| anyhow::anyhow!("Failed to create template"))
}

/// Get template by ID
pub async fn get_template_by_id(pool: &SqlitePool, id: &str) -> Result<Option<CustomReportTemplate>> {
    use sqlx::Row;

    let row = sqlx::query(
        r#"
        SELECT id, user_id, organization_id, name, description, base_template,
               sections, branding, header_html, footer_html, css_overrides,
               cover_page_html, is_public, is_active, downloads, rating, rating_count,
               version, created_at, updated_at, published_at
        FROM custom_report_templates
        WHERE id = ?
        "#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|r| {
        let sections_str: String = r.get("sections");
        let branding_str: Option<String> = r.get("branding");
        let created_at_str: String = r.get("created_at");
        let updated_at_str: String = r.get("updated_at");
        let published_at_str: Option<String> = r.get("published_at");

        CustomReportTemplate {
            id: r.get("id"),
            user_id: r.get("user_id"),
            organization_id: r.get("organization_id"),
            name: r.get("name"),
            description: r.get("description"),
            base_template: r.get("base_template"),
            sections: serde_json::from_str(&sections_str).unwrap_or(serde_json::json!([])),
            branding: branding_str.and_then(|s| serde_json::from_str(&s).ok()),
            header_html: r.get("header_html"),
            footer_html: r.get("footer_html"),
            css_overrides: r.get("css_overrides"),
            cover_page_html: r.get("cover_page_html"),
            is_public: r.get("is_public"),
            is_active: r.get("is_active"),
            downloads: r.get("downloads"),
            rating: r.get("rating"),
            rating_count: r.get("rating_count"),
            version: r.get("version"),
            created_at: DateTime::parse_from_rfc3339(&created_at_str).unwrap().with_timezone(&Utc),
            updated_at: DateTime::parse_from_rfc3339(&updated_at_str).unwrap().with_timezone(&Utc),
            published_at: published_at_str.and_then(|s| DateTime::parse_from_rfc3339(&s).ok().map(|dt| dt.with_timezone(&Utc))),
        }
    }))
}

/// List user's templates
pub async fn list_user_templates(
    pool: &SqlitePool,
    user_id: &str,
    organization_id: Option<&str>,
) -> Result<Vec<CustomReportTemplate>> {
    use sqlx::Row;

    let rows = if let Some(org_id) = organization_id {
        sqlx::query(
            r#"
            SELECT id, user_id, organization_id, name, description, base_template,
                   sections, branding, header_html, footer_html, css_overrides,
                   cover_page_html, is_public, is_active, downloads, rating, rating_count,
                   version, created_at, updated_at, published_at
            FROM custom_report_templates
            WHERE (user_id = ? OR organization_id = ?) AND is_active = 1
            ORDER BY updated_at DESC
            "#,
        )
        .bind(user_id)
        .bind(org_id)
        .fetch_all(pool)
        .await?
    } else {
        sqlx::query(
            r#"
            SELECT id, user_id, organization_id, name, description, base_template,
                   sections, branding, header_html, footer_html, css_overrides,
                   cover_page_html, is_public, is_active, downloads, rating, rating_count,
                   version, created_at, updated_at, published_at
            FROM custom_report_templates
            WHERE user_id = ? AND is_active = 1
            ORDER BY updated_at DESC
            "#,
        )
        .bind(user_id)
        .fetch_all(pool)
        .await?
    };

    Ok(rows.into_iter().map(|r| {
        let sections_str: String = r.get("sections");
        let branding_str: Option<String> = r.get("branding");
        let created_at_str: String = r.get("created_at");
        let updated_at_str: String = r.get("updated_at");
        let published_at_str: Option<String> = r.get("published_at");

        CustomReportTemplate {
            id: r.get("id"),
            user_id: r.get("user_id"),
            organization_id: r.get("organization_id"),
            name: r.get("name"),
            description: r.get("description"),
            base_template: r.get("base_template"),
            sections: serde_json::from_str(&sections_str).unwrap_or(serde_json::json!([])),
            branding: branding_str.and_then(|s| serde_json::from_str(&s).ok()),
            header_html: r.get("header_html"),
            footer_html: r.get("footer_html"),
            css_overrides: r.get("css_overrides"),
            cover_page_html: r.get("cover_page_html"),
            is_public: r.get("is_public"),
            is_active: r.get("is_active"),
            downloads: r.get("downloads"),
            rating: r.get("rating"),
            rating_count: r.get("rating_count"),
            version: r.get("version"),
            created_at: DateTime::parse_from_rfc3339(&created_at_str).unwrap().with_timezone(&Utc),
            updated_at: DateTime::parse_from_rfc3339(&updated_at_str).unwrap().with_timezone(&Utc),
            published_at: published_at_str.and_then(|s| DateTime::parse_from_rfc3339(&s).ok().map(|dt| dt.with_timezone(&Utc))),
        }
    }).collect())
}

/// Update a template
pub async fn update_template(
    pool: &SqlitePool,
    template_id: &str,
    user_id: &str,
    request: UpdateTemplateRequest,
) -> Result<Option<CustomReportTemplate>> {
    // First verify ownership
    let template = get_template_by_id(pool, template_id).await?;
    if template.as_ref().map(|t| &t.user_id) != Some(&user_id.to_string()) {
        return Ok(None);
    }
    let template = template.unwrap();

    // Save current version before updating
    let version_id = uuid::Uuid::new_v4().to_string();
    let now = Utc::now();
    let sections_json = serde_json::to_string(&template.sections)?;
    let branding_json = template.branding.as_ref().map(|b| serde_json::to_string(b)).transpose()?;

    sqlx::query(
        r#"
        INSERT INTO template_versions (
            id, template_id, version, sections, branding, header_html,
            footer_html, css_overrides, cover_page_html, change_notes,
            created_by, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&version_id)
    .bind(template_id)
    .bind(template.version)
    .bind(&sections_json)
    .bind(&branding_json)
    .bind(&template.header_html)
    .bind(&template.footer_html)
    .bind(&template.css_overrides)
    .bind(&template.cover_page_html)
    .bind(&request.change_notes)
    .bind(user_id)
    .bind(now.to_rfc3339())
    .execute(pool)
    .await?;

    // Update the template
    let new_sections = request.sections.as_ref()
        .map(|s| serde_json::to_string(s).unwrap())
        .unwrap_or(sections_json);
    let new_branding = request.branding.as_ref()
        .map(|b| serde_json::to_string(b).ok())
        .unwrap_or(branding_json);

    sqlx::query(
        r#"
        UPDATE custom_report_templates SET
            name = COALESCE(?, name),
            description = COALESCE(?, description),
            sections = ?,
            branding = ?,
            header_html = COALESCE(?, header_html),
            footer_html = COALESCE(?, footer_html),
            css_overrides = COALESCE(?, css_overrides),
            cover_page_html = COALESCE(?, cover_page_html),
            version = version + 1,
            updated_at = ?
        WHERE id = ?
        "#,
    )
    .bind(&request.name)
    .bind(&request.description)
    .bind(&new_sections)
    .bind(&new_branding)
    .bind(&request.header_html)
    .bind(&request.footer_html)
    .bind(&request.css_overrides)
    .bind(&request.cover_page_html)
    .bind(now.to_rfc3339())
    .bind(template_id)
    .execute(pool)
    .await?;

    get_template_by_id(pool, template_id).await
}

/// Delete a template (soft delete by setting is_active = false)
pub async fn delete_template(pool: &SqlitePool, template_id: &str, user_id: &str) -> Result<bool> {
    let result = sqlx::query(
        "UPDATE custom_report_templates SET is_active = 0, updated_at = ? WHERE id = ? AND user_id = ?",
    )
    .bind(Utc::now().to_rfc3339())
    .bind(template_id)
    .bind(user_id)
    .execute(pool)
    .await?;

    Ok(result.rows_affected() > 0)
}

/// Clone a template
pub async fn clone_template(
    pool: &SqlitePool,
    template_id: &str,
    user_id: &str,
    new_name: &str,
) -> Result<Option<CustomReportTemplate>> {
    let template = get_template_by_id(pool, template_id).await?;
    if template.is_none() {
        return Ok(None);
    }
    let template = template.unwrap();

    // Increment download count if cloning public template
    if template.is_public && template.user_id != user_id {
        sqlx::query("UPDATE custom_report_templates SET downloads = downloads + 1 WHERE id = ?")
            .bind(template_id)
            .execute(pool)
            .await?;
    }

    let request = CreateTemplateRequest {
        name: new_name.to_string(),
        description: template.description.map(|d| format!("Cloned from: {}", d)),
        base_template: template.base_template,
        sections: template.sections,
        branding: template.branding,
        header_html: template.header_html,
        footer_html: template.footer_html,
        css_overrides: template.css_overrides,
        cover_page_html: template.cover_page_html,
    };

    let cloned = create_template(pool, user_id, None, request).await?;
    Ok(Some(cloned))
}

/// Publish template to marketplace
pub async fn publish_template(pool: &SqlitePool, template_id: &str, user_id: &str) -> Result<bool> {
    let now = Utc::now();
    let result = sqlx::query(
        r#"
        UPDATE custom_report_templates SET
            is_public = 1,
            published_at = ?,
            updated_at = ?
        WHERE id = ? AND user_id = ?
        "#,
    )
    .bind(now.to_rfc3339())
    .bind(now.to_rfc3339())
    .bind(template_id)
    .bind(user_id)
    .execute(pool)
    .await?;

    Ok(result.rows_affected() > 0)
}

/// Unpublish template from marketplace
pub async fn unpublish_template(pool: &SqlitePool, template_id: &str, user_id: &str) -> Result<bool> {
    let result = sqlx::query(
        r#"
        UPDATE custom_report_templates SET
            is_public = 0,
            updated_at = ?
        WHERE id = ? AND user_id = ?
        "#,
    )
    .bind(Utc::now().to_rfc3339())
    .bind(template_id)
    .bind(user_id)
    .execute(pool)
    .await?;

    Ok(result.rows_affected() > 0)
}

// ============================================================================
// Marketplace Operations
// ============================================================================

/// List marketplace templates
pub async fn list_marketplace_templates(
    pool: &SqlitePool,
    base_template: Option<&str>,
    sort_by: Option<&str>,
    limit: i32,
    offset: i32,
) -> Result<Vec<MarketplaceTemplate>> {
    let order_by = match sort_by {
        Some("downloads") => "t.downloads DESC",
        Some("rating") => "t.rating DESC NULLS LAST",
        Some("newest") => "t.published_at DESC",
        _ => "t.downloads DESC",
    };

    let query = if let Some(_base) = base_template {
        format!(
            r#"
            SELECT t.id, t.name, t.description, t.base_template, u.username,
                   t.user_id, t.downloads, t.rating, t.rating_count,
                   t.created_at, t.published_at
            FROM custom_report_templates t
            JOIN users u ON t.user_id = u.id
            WHERE t.is_public = 1 AND t.is_active = 1 AND t.base_template = ?
            ORDER BY {}
            LIMIT ? OFFSET ?
            "#,
            order_by
        )
    } else {
        format!(
            r#"
            SELECT t.id, t.name, t.description, t.base_template, u.username,
                   t.user_id, t.downloads, t.rating, t.rating_count,
                   t.created_at, t.published_at
            FROM custom_report_templates t
            JOIN users u ON t.user_id = u.id
            WHERE t.is_public = 1 AND t.is_active = 1
            ORDER BY {}
            LIMIT ? OFFSET ?
            "#,
            order_by
        )
    };

    let rows = if base_template.is_some() {
        sqlx::query_as::<_, (
            String, String, Option<String>, String, String, String,
            i32, Option<f64>, i32, String, Option<String>,
        )>(&query)
        .bind(base_template)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await?
    } else {
        sqlx::query_as::<_, (
            String, String, Option<String>, String, String, String,
            i32, Option<f64>, i32, String, Option<String>,
        )>(&query)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await?
    };

    Ok(rows.into_iter().map(|r| MarketplaceTemplate {
        id: r.0,
        name: r.1,
        description: r.2,
        base_template: r.3,
        author_username: r.4,
        author_id: r.5,
        downloads: r.6,
        rating: r.7,
        rating_count: r.8,
        preview_image_url: None,
        created_at: DateTime::parse_from_rfc3339(&r.9).unwrap().with_timezone(&Utc),
        published_at: r.10.and_then(|s| DateTime::parse_from_rfc3339(&s).ok().map(|dt| dt.with_timezone(&Utc))),
    }).collect())
}

/// Search marketplace templates
pub async fn search_marketplace(
    pool: &SqlitePool,
    query: &str,
    limit: i32,
) -> Result<Vec<MarketplaceTemplate>> {
    let search_pattern = format!("%{}%", query);

    let rows = sqlx::query_as::<_, (
        String, String, Option<String>, String, String, String,
        i32, Option<f64>, i32, String, Option<String>,
    )>(
        r#"
        SELECT t.id, t.name, t.description, t.base_template, u.username,
               t.user_id, t.downloads, t.rating, t.rating_count,
               t.created_at, t.published_at
        FROM custom_report_templates t
        JOIN users u ON t.user_id = u.id
        WHERE t.is_public = 1 AND t.is_active = 1
          AND (t.name LIKE ? OR t.description LIKE ?)
        ORDER BY t.downloads DESC
        LIMIT ?
        "#,
    )
    .bind(&search_pattern)
    .bind(&search_pattern)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(|r| MarketplaceTemplate {
        id: r.0,
        name: r.1,
        description: r.2,
        base_template: r.3,
        author_username: r.4,
        author_id: r.5,
        downloads: r.6,
        rating: r.7,
        rating_count: r.8,
        preview_image_url: None,
        created_at: DateTime::parse_from_rfc3339(&r.9).unwrap().with_timezone(&Utc),
        published_at: r.10.and_then(|s| DateTime::parse_from_rfc3339(&s).ok().map(|dt| dt.with_timezone(&Utc))),
    }).collect())
}

// ============================================================================
// Rating Operations
// ============================================================================

/// Add or update a rating for a template
pub async fn rate_template(
    pool: &SqlitePool,
    template_id: &str,
    user_id: &str,
    request: CreateRatingRequest,
) -> Result<TemplateRating> {
    let id = uuid::Uuid::new_v4().to_string();
    let now = Utc::now();

    // Upsert the rating
    sqlx::query(
        r#"
        INSERT INTO template_ratings (id, template_id, user_id, rating, review, helpful_count, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, 0, ?, ?)
        ON CONFLICT(template_id, user_id) DO UPDATE SET
            rating = excluded.rating,
            review = excluded.review,
            updated_at = excluded.updated_at
        "#,
    )
    .bind(&id)
    .bind(template_id)
    .bind(user_id)
    .bind(request.rating)
    .bind(&request.review)
    .bind(now.to_rfc3339())
    .bind(now.to_rfc3339())
    .execute(pool)
    .await?;

    // Update the aggregate rating on the template
    sqlx::query(
        r#"
        UPDATE custom_report_templates SET
            rating = (SELECT AVG(rating) FROM template_ratings WHERE template_id = ?),
            rating_count = (SELECT COUNT(*) FROM template_ratings WHERE template_id = ?),
            updated_at = ?
        WHERE id = ?
        "#,
    )
    .bind(template_id)
    .bind(template_id)
    .bind(now.to_rfc3339())
    .bind(template_id)
    .execute(pool)
    .await?;

    // Fetch and return the rating
    let row = sqlx::query_as::<_, (String, String, String, i32, Option<String>, i32, String, String)>(
        "SELECT id, template_id, user_id, rating, review, helpful_count, created_at, updated_at FROM template_ratings WHERE template_id = ? AND user_id = ?",
    )
    .bind(template_id)
    .bind(user_id)
    .fetch_one(pool)
    .await?;

    Ok(TemplateRating {
        id: row.0,
        template_id: row.1,
        user_id: row.2,
        rating: row.3,
        review: row.4,
        helpful_count: row.5,
        created_at: DateTime::parse_from_rfc3339(&row.6).unwrap().with_timezone(&Utc),
        updated_at: DateTime::parse_from_rfc3339(&row.7).unwrap().with_timezone(&Utc),
    })
}

/// Get ratings for a template
pub async fn get_template_ratings(
    pool: &SqlitePool,
    template_id: &str,
    limit: i32,
    offset: i32,
) -> Result<Vec<TemplateRatingWithUser>> {
    let rows = sqlx::query_as::<_, (String, String, String, String, i32, Option<String>, i32, String)>(
        r#"
        SELECT r.id, r.template_id, r.user_id, u.username, r.rating, r.review, r.helpful_count, r.created_at
        FROM template_ratings r
        JOIN users u ON r.user_id = u.id
        WHERE r.template_id = ?
        ORDER BY r.helpful_count DESC, r.created_at DESC
        LIMIT ? OFFSET ?
        "#,
    )
    .bind(template_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(|r| TemplateRatingWithUser {
        id: r.0,
        template_id: r.1,
        user_id: r.2,
        username: r.3,
        rating: r.4,
        review: r.5,
        helpful_count: r.6,
        created_at: DateTime::parse_from_rfc3339(&r.7).unwrap().with_timezone(&Utc),
    }).collect())
}

/// Mark a rating as helpful
pub async fn mark_rating_helpful(pool: &SqlitePool, rating_id: &str) -> Result<bool> {
    let result = sqlx::query(
        "UPDATE template_ratings SET helpful_count = helpful_count + 1 WHERE id = ?",
    )
    .bind(rating_id)
    .execute(pool)
    .await?;

    Ok(result.rows_affected() > 0)
}

// ============================================================================
// Version History
// ============================================================================

/// Get version history for a template
pub async fn get_template_versions(
    pool: &SqlitePool,
    template_id: &str,
) -> Result<Vec<TemplateVersion>> {
    let rows = sqlx::query_as::<_, (
        String, String, i32, String, Option<String>, Option<String>,
        Option<String>, Option<String>, Option<String>, Option<String>,
        String, String,
    )>(
        r#"
        SELECT id, template_id, version, sections, branding, header_html,
               footer_html, css_overrides, cover_page_html, change_notes,
               created_by, created_at
        FROM template_versions
        WHERE template_id = ?
        ORDER BY version DESC
        "#,
    )
    .bind(template_id)
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(|r| TemplateVersion {
        id: r.0,
        template_id: r.1,
        version: r.2,
        sections: serde_json::from_str(&r.3).unwrap_or(serde_json::json!([])),
        branding: r.4.and_then(|s| serde_json::from_str(&s).ok()),
        header_html: r.5,
        footer_html: r.6,
        css_overrides: r.7,
        cover_page_html: r.8,
        change_notes: r.9,
        created_by: r.10,
        created_at: DateTime::parse_from_rfc3339(&r.11).unwrap().with_timezone(&Utc),
    }).collect())
}

/// Restore a template from a previous version
pub async fn restore_version(
    pool: &SqlitePool,
    template_id: &str,
    version_id: &str,
    user_id: &str,
) -> Result<Option<CustomReportTemplate>> {
    // Get the version
    let version = sqlx::query_as::<_, (String, Option<String>, Option<String>, Option<String>, Option<String>, Option<String>)>(
        "SELECT sections, branding, header_html, footer_html, css_overrides, cover_page_html FROM template_versions WHERE id = ? AND template_id = ?",
    )
    .bind(version_id)
    .bind(template_id)
    .fetch_optional(pool)
    .await?;

    if version.is_none() {
        return Ok(None);
    }
    let version = version.unwrap();

    // Update the template
    let now = Utc::now();
    sqlx::query(
        r#"
        UPDATE custom_report_templates SET
            sections = ?,
            branding = ?,
            header_html = ?,
            footer_html = ?,
            css_overrides = ?,
            cover_page_html = ?,
            version = version + 1,
            updated_at = ?
        WHERE id = ? AND user_id = ?
        "#,
    )
    .bind(&version.0)
    .bind(&version.1)
    .bind(&version.2)
    .bind(&version.3)
    .bind(&version.4)
    .bind(&version.5)
    .bind(now.to_rfc3339())
    .bind(template_id)
    .bind(user_id)
    .execute(pool)
    .await?;

    get_template_by_id(pool, template_id).await
}

// ============================================================================
// Template Sections
// ============================================================================

/// Create a reusable section
pub async fn create_section(
    pool: &SqlitePool,
    user_id: &str,
    organization_id: Option<&str>,
    request: CreateSectionRequest,
) -> Result<TemplateSection> {
    let id = uuid::Uuid::new_v4().to_string();
    let now = Utc::now();

    sqlx::query(
        r#"
        INSERT INTO template_sections (
            id, user_id, organization_id, name, section_type,
            content_html, content_css, is_public, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(user_id)
    .bind(organization_id)
    .bind(&request.name)
    .bind(&request.section_type)
    .bind(&request.content_html)
    .bind(&request.content_css)
    .bind(request.is_public.unwrap_or(false))
    .bind(now.to_rfc3339())
    .bind(now.to_rfc3339())
    .execute(pool)
    .await?;

    Ok(TemplateSection {
        id,
        user_id: user_id.to_string(),
        organization_id: organization_id.map(|s| s.to_string()),
        name: request.name,
        section_type: request.section_type,
        content_html: request.content_html,
        content_css: request.content_css,
        is_public: request.is_public.unwrap_or(false),
        created_at: now,
        updated_at: now,
    })
}

/// List user's sections
pub async fn list_user_sections(
    pool: &SqlitePool,
    user_id: &str,
    organization_id: Option<&str>,
) -> Result<Vec<TemplateSection>> {
    let rows = if let Some(org_id) = organization_id {
        sqlx::query_as::<_, (String, String, Option<String>, String, String, String, Option<String>, bool, String, String)>(
            r#"
            SELECT id, user_id, organization_id, name, section_type, content_html, content_css, is_public, created_at, updated_at
            FROM template_sections
            WHERE user_id = ? OR organization_id = ? OR is_public = 1
            ORDER BY name ASC
            "#,
        )
        .bind(user_id)
        .bind(org_id)
        .fetch_all(pool)
        .await?
    } else {
        sqlx::query_as::<_, (String, String, Option<String>, String, String, String, Option<String>, bool, String, String)>(
            r#"
            SELECT id, user_id, organization_id, name, section_type, content_html, content_css, is_public, created_at, updated_at
            FROM template_sections
            WHERE user_id = ? OR is_public = 1
            ORDER BY name ASC
            "#,
        )
        .bind(user_id)
        .fetch_all(pool)
        .await?
    };

    Ok(rows.into_iter().map(|r| TemplateSection {
        id: r.0,
        user_id: r.1,
        organization_id: r.2,
        name: r.3,
        section_type: r.4,
        content_html: r.5,
        content_css: r.6,
        is_public: r.7,
        created_at: DateTime::parse_from_rfc3339(&r.8).unwrap().with_timezone(&Utc),
        updated_at: DateTime::parse_from_rfc3339(&r.9).unwrap().with_timezone(&Utc),
    }).collect())
}

/// Delete a section
pub async fn delete_section(pool: &SqlitePool, section_id: &str, user_id: &str) -> Result<bool> {
    let result = sqlx::query("DELETE FROM template_sections WHERE id = ? AND user_id = ?")
        .bind(section_id)
        .bind(user_id)
        .execute(pool)
        .await?;

    Ok(result.rows_affected() > 0)
}

// ============================================================================
// Template Assets
// ============================================================================

/// Create a template asset
pub async fn create_asset(
    pool: &SqlitePool,
    user_id: &str,
    organization_id: Option<&str>,
    name: &str,
    asset_type: &str,
    mime_type: &str,
    file_path: &str,
    file_size: i64,
    width: Option<i32>,
    height: Option<i32>,
) -> Result<TemplateAsset> {
    let id = uuid::Uuid::new_v4().to_string();
    let now = Utc::now();

    sqlx::query(
        r#"
        INSERT INTO template_assets (
            id, user_id, organization_id, name, asset_type,
            mime_type, file_path, file_size, width, height, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(user_id)
    .bind(organization_id)
    .bind(name)
    .bind(asset_type)
    .bind(mime_type)
    .bind(file_path)
    .bind(file_size)
    .bind(width)
    .bind(height)
    .bind(now.to_rfc3339())
    .execute(pool)
    .await?;

    Ok(TemplateAsset {
        id,
        user_id: user_id.to_string(),
        organization_id: organization_id.map(|s| s.to_string()),
        name: name.to_string(),
        asset_type: asset_type.to_string(),
        mime_type: mime_type.to_string(),
        file_path: file_path.to_string(),
        file_size,
        width,
        height,
        created_at: now,
    })
}

/// List user's assets
pub async fn list_user_assets(
    pool: &SqlitePool,
    user_id: &str,
    organization_id: Option<&str>,
) -> Result<Vec<TemplateAsset>> {
    let rows = if let Some(org_id) = organization_id {
        sqlx::query_as::<_, (String, String, Option<String>, String, String, String, String, i64, Option<i32>, Option<i32>, String)>(
            r#"
            SELECT id, user_id, organization_id, name, asset_type, mime_type, file_path, file_size, width, height, created_at
            FROM template_assets
            WHERE user_id = ? OR organization_id = ?
            ORDER BY created_at DESC
            "#,
        )
        .bind(user_id)
        .bind(org_id)
        .fetch_all(pool)
        .await?
    } else {
        sqlx::query_as::<_, (String, String, Option<String>, String, String, String, String, i64, Option<i32>, Option<i32>, String)>(
            r#"
            SELECT id, user_id, organization_id, name, asset_type, mime_type, file_path, file_size, width, height, created_at
            FROM template_assets
            WHERE user_id = ?
            ORDER BY created_at DESC
            "#,
        )
        .bind(user_id)
        .fetch_all(pool)
        .await?
    };

    Ok(rows.into_iter().map(|r| TemplateAsset {
        id: r.0,
        user_id: r.1,
        organization_id: r.2,
        name: r.3,
        asset_type: r.4,
        mime_type: r.5,
        file_path: r.6,
        file_size: r.7,
        width: r.8,
        height: r.9,
        created_at: DateTime::parse_from_rfc3339(&r.10).unwrap().with_timezone(&Utc),
    }).collect())
}

/// Get asset by ID
pub async fn get_asset_by_id(pool: &SqlitePool, asset_id: &str) -> Result<Option<TemplateAsset>> {
    let row = sqlx::query_as::<_, (String, String, Option<String>, String, String, String, String, i64, Option<i32>, Option<i32>, String)>(
        "SELECT id, user_id, organization_id, name, asset_type, mime_type, file_path, file_size, width, height, created_at FROM template_assets WHERE id = ?",
    )
    .bind(asset_id)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|r| TemplateAsset {
        id: r.0,
        user_id: r.1,
        organization_id: r.2,
        name: r.3,
        asset_type: r.4,
        mime_type: r.5,
        file_path: r.6,
        file_size: r.7,
        width: r.8,
        height: r.9,
        created_at: DateTime::parse_from_rfc3339(&r.10).unwrap().with_timezone(&Utc),
    }))
}

/// Delete an asset
pub async fn delete_asset(pool: &SqlitePool, asset_id: &str, user_id: &str) -> Result<bool> {
    let result = sqlx::query("DELETE FROM template_assets WHERE id = ? AND user_id = ?")
        .bind(asset_id)
        .bind(user_id)
        .execute(pool)
        .await?;

    Ok(result.rows_affected() > 0)
}

// ============================================================================
// Usage Statistics
// ============================================================================

/// Record template usage
pub async fn record_template_usage(
    pool: &SqlitePool,
    template_id: &str,
    user_id: &str,
    report_id: Option<&str>,
) -> Result<()> {
    let id = uuid::Uuid::new_v4().to_string();
    let now = Utc::now();

    sqlx::query(
        "INSERT INTO template_usage_stats (id, template_id, user_id, report_id, used_at) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(template_id)
    .bind(user_id)
    .bind(report_id)
    .bind(now.to_rfc3339())
    .execute(pool)
    .await?;

    Ok(())
}

/// Get usage statistics for a template
pub async fn get_template_usage_stats(pool: &SqlitePool, template_id: &str) -> Result<TemplateUsageStats> {
    let row = sqlx::query_as::<_, (i32, i32, Option<String>)>(
        r#"
        SELECT COUNT(*) as total_uses,
               COUNT(DISTINCT user_id) as unique_users,
               MAX(used_at) as last_used_at
        FROM template_usage_stats
        WHERE template_id = ?
        "#,
    )
    .bind(template_id)
    .fetch_one(pool)
    .await?;

    Ok(TemplateUsageStats {
        template_id: template_id.to_string(),
        total_uses: row.0,
        unique_users: row.1,
        last_used_at: row.2.and_then(|s| DateTime::parse_from_rfc3339(&s).ok().map(|dt| dt.with_timezone(&Utc))),
    })
}

// ============================================================================
// Scheduled Report Delivery
// ============================================================================

/// Add delivery channel to scheduled report
pub async fn add_delivery_channel(
    pool: &SqlitePool,
    scheduled_report_id: &str,
    request: CreateDeliveryChannelRequest,
) -> Result<ScheduledReportDelivery> {
    let id = uuid::Uuid::new_v4().to_string();
    let now = Utc::now();
    let config_json = serde_json::to_string(&request.channel_config)?;

    sqlx::query(
        r#"
        INSERT INTO scheduled_report_delivery (
            id, scheduled_report_id, channel, channel_config, is_enabled, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(scheduled_report_id)
    .bind(&request.channel)
    .bind(&config_json)
    .bind(request.is_enabled.unwrap_or(true))
    .bind(now.to_rfc3339())
    .bind(now.to_rfc3339())
    .execute(pool)
    .await?;

    Ok(ScheduledReportDelivery {
        id,
        scheduled_report_id: scheduled_report_id.to_string(),
        channel: request.channel,
        channel_config: request.channel_config,
        is_enabled: request.is_enabled.unwrap_or(true),
        created_at: now,
        updated_at: now,
    })
}

/// List delivery channels for a scheduled report
pub async fn list_delivery_channels(
    pool: &SqlitePool,
    scheduled_report_id: &str,
) -> Result<Vec<ScheduledReportDelivery>> {
    let rows = sqlx::query_as::<_, (String, String, String, String, bool, String, String)>(
        r#"
        SELECT id, scheduled_report_id, channel, channel_config, is_enabled, created_at, updated_at
        FROM scheduled_report_delivery
        WHERE scheduled_report_id = ?
        "#,
    )
    .bind(scheduled_report_id)
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(|r| ScheduledReportDelivery {
        id: r.0,
        scheduled_report_id: r.1,
        channel: r.2,
        channel_config: serde_json::from_str(&r.3).unwrap_or(serde_json::json!({})),
        is_enabled: r.4,
        created_at: DateTime::parse_from_rfc3339(&r.5).unwrap().with_timezone(&Utc),
        updated_at: DateTime::parse_from_rfc3339(&r.6).unwrap().with_timezone(&Utc),
    }).collect())
}

/// Delete delivery channel
pub async fn delete_delivery_channel(pool: &SqlitePool, channel_id: &str) -> Result<bool> {
    let result = sqlx::query("DELETE FROM scheduled_report_delivery WHERE id = ?")
        .bind(channel_id)
        .execute(pool)
        .await?;

    Ok(result.rows_affected() > 0)
}

/// Create a scheduled report run record
pub async fn create_report_run(
    pool: &SqlitePool,
    scheduled_report_id: &str,
) -> Result<ScheduledReportRun> {
    let id = uuid::Uuid::new_v4().to_string();
    let now = Utc::now();

    sqlx::query(
        r#"
        INSERT INTO scheduled_report_runs (
            id, scheduled_report_id, started_at, status, recipients_notified
        ) VALUES (?, ?, ?, 'pending', 0)
        "#,
    )
    .bind(&id)
    .bind(scheduled_report_id)
    .bind(now.to_rfc3339())
    .execute(pool)
    .await?;

    Ok(ScheduledReportRun {
        id,
        scheduled_report_id: scheduled_report_id.to_string(),
        started_at: now,
        completed_at: None,
        status: "pending".to_string(),
        file_path: None,
        file_size: None,
        recipients_notified: 0,
        error_message: None,
        delivery_results: None,
    })
}

/// Update a scheduled report run
pub async fn update_report_run(
    pool: &SqlitePool,
    run_id: &str,
    status: &str,
    file_path: Option<&str>,
    file_size: Option<i64>,
    recipients_notified: Option<i32>,
    error_message: Option<&str>,
    delivery_results: Option<serde_json::Value>,
) -> Result<bool> {
    let now = Utc::now();
    let delivery_json = delivery_results.map(|d| serde_json::to_string(&d).ok()).flatten();

    let result = sqlx::query(
        r#"
        UPDATE scheduled_report_runs SET
            status = ?,
            completed_at = ?,
            file_path = COALESCE(?, file_path),
            file_size = COALESCE(?, file_size),
            recipients_notified = COALESCE(?, recipients_notified),
            error_message = ?,
            delivery_results = COALESCE(?, delivery_results)
        WHERE id = ?
        "#,
    )
    .bind(status)
    .bind(now.to_rfc3339())
    .bind(file_path)
    .bind(file_size)
    .bind(recipients_notified)
    .bind(error_message)
    .bind(&delivery_json)
    .bind(run_id)
    .execute(pool)
    .await?;

    Ok(result.rows_affected() > 0)
}

/// Get run history for a scheduled report
pub async fn get_report_run_history(
    pool: &SqlitePool,
    scheduled_report_id: &str,
    limit: i32,
) -> Result<Vec<ScheduledReportRun>> {
    let rows = sqlx::query_as::<_, (
        String, String, String, Option<String>, String,
        Option<String>, Option<i64>, i32, Option<String>, Option<String>,
    )>(
        r#"
        SELECT id, scheduled_report_id, started_at, completed_at, status,
               file_path, file_size, recipients_notified, error_message, delivery_results
        FROM scheduled_report_runs
        WHERE scheduled_report_id = ?
        ORDER BY started_at DESC
        LIMIT ?
        "#,
    )
    .bind(scheduled_report_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(|r| ScheduledReportRun {
        id: r.0,
        scheduled_report_id: r.1,
        started_at: DateTime::parse_from_rfc3339(&r.2).unwrap().with_timezone(&Utc),
        completed_at: r.3.and_then(|s| DateTime::parse_from_rfc3339(&s).ok().map(|dt| dt.with_timezone(&Utc))),
        status: r.4,
        file_path: r.5,
        file_size: r.6,
        recipients_notified: r.7,
        error_message: r.8,
        delivery_results: r.9.and_then(|s| serde_json::from_str(&s).ok()),
    }).collect())
}

// ============================================================================
// Statistics
// ============================================================================

/// Get template statistics
pub async fn get_template_stats(pool: &SqlitePool, user_id: Option<&str>) -> Result<TemplateStats> {
    let (total, public, downloads, avg_rating) = if let Some(uid) = user_id {
        let row = sqlx::query_as::<_, (i32, i32, i32, Option<f64>)>(
            r#"
            SELECT COUNT(*) as total,
                   SUM(CASE WHEN is_public = 1 THEN 1 ELSE 0 END) as public,
                   SUM(downloads) as total_downloads,
                   AVG(rating) as avg_rating
            FROM custom_report_templates
            WHERE user_id = ? AND is_active = 1
            "#,
        )
        .bind(uid)
        .fetch_one(pool)
        .await?;
        (row.0, row.1, row.2, row.3)
    } else {
        let row = sqlx::query_as::<_, (i32, i32, i32, Option<f64>)>(
            r#"
            SELECT COUNT(*) as total,
                   SUM(CASE WHEN is_public = 1 THEN 1 ELSE 0 END) as public,
                   SUM(downloads) as total_downloads,
                   AVG(rating) as avg_rating
            FROM custom_report_templates
            WHERE is_active = 1
            "#,
        )
        .fetch_one(pool)
        .await?;
        (row.0, row.1, row.2, row.3)
    };

    let base_counts = if let Some(uid) = user_id {
        sqlx::query_as::<_, (String, i32)>(
            r#"
            SELECT base_template, COUNT(*) as count
            FROM custom_report_templates
            WHERE user_id = ? AND is_active = 1
            GROUP BY base_template
            "#,
        )
        .bind(uid)
        .fetch_all(pool)
        .await?
    } else {
        sqlx::query_as::<_, (String, i32)>(
            r#"
            SELECT base_template, COUNT(*) as count
            FROM custom_report_templates
            WHERE is_active = 1
            GROUP BY base_template
            "#,
        )
        .fetch_all(pool)
        .await?
    };

    Ok(TemplateStats {
        total_templates: total,
        public_templates: public,
        total_downloads: downloads,
        avg_rating,
        templates_by_base: base_counts.into_iter().map(|(base, count)| BaseTemplateCount {
            base_template: base,
            count,
        }).collect(),
    })
}
