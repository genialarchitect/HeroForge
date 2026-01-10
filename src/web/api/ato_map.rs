//! ATO (Authority to Operate) Map API
//!
//! Provides endpoints for generating and managing ATO assessment maps
//! based on compliance data from scans and manual assessments.
//!
//! Includes Zeus AI integration for intelligent ATO map manipulation.

use actix_web::{web, HttpResponse, Result};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::collections::HashMap;

use crate::compliance::frameworks::nist_800_53;
use crate::ai::llm_orchestrator;

// ============================================================================
// Types
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AtoControl {
    pub id: String,
    pub control_id: String,
    pub title: String,
    pub status: String,
    pub evidence_count: i32,
    pub poam_id: Option<String>,
    pub last_assessed: Option<String>,
    pub assessor: Option<String>,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AtoControlFamily {
    pub id: String,
    pub name: String,
    pub abbreviation: String,
    pub controls: Vec<AtoControl>,
    pub compliant_count: i32,
    pub non_compliant_count: i32,
    pub partial_count: i32,
    pub not_assessed_count: i32,
    pub not_applicable_count: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AtoMapData {
    pub system_name: String,
    pub system_id: Option<String>,
    pub organization: Option<String>,
    pub authorizing_official: Option<String>,
    pub assessment_date: Option<String>,
    pub target_ato_date: Option<String>,
    pub baseline: String,
    pub framework: String,
    pub control_families: Vec<AtoControlFamily>,
    pub overall_score: i32,
    pub poam_count: i32,
}

#[derive(Debug, Deserialize)]
pub struct GetAtoMapQuery {
    pub scan_id: Option<String>,
    pub engagement_id: Option<String>,
    pub framework: Option<String>,
}

// ============================================================================
// Zeus AI Types
// ============================================================================

/// Request to Zeus AI for ATO manipulation
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ZeusRequest {
    pub prompt: String,
    pub context: ZeusContext,
}

/// Context provided to Zeus for ATO decisions
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ZeusContext {
    pub system_name: String,
    pub overall_score: i32,
    pub families: Vec<ZeusFamilyContext>,
}

/// Family context for Zeus
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ZeusFamilyContext {
    pub id: String,
    pub name: String,
    pub stats: ZeusFamilyStats,
}

/// Control statistics for a family
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ZeusFamilyStats {
    pub compliant: i32,
    pub non_compliant: i32,
    pub partial: i32,
    pub not_assessed: i32,
    pub not_applicable: i32,
    pub total: i32,
}

/// Zeus AI response
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ZeusResponse {
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<ZeusAction>,
}

/// Action that Zeus can trigger
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ZeusAction {
    #[serde(rename = "type")]
    pub action_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub control_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub family_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

/// Request to update a single control status
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateControlRequest {
    pub control_id: String,
    pub status: String,
    pub notes: Option<String>,
}

/// Request to bulk update controls
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BulkUpdateRequest {
    pub family_id: Option<String>,
    pub target_status: String,
    pub new_status: String,
    pub notes: Option<String>,
}

// ============================================================================
// NIST 800-53 Control Family Definitions
// ============================================================================

const NIST_CONTROL_FAMILIES: &[(&str, &str)] = &[
    ("AC", "Access Control"),
    ("AT", "Awareness and Training"),
    ("AU", "Audit and Accountability"),
    ("CA", "Assessment, Authorization, and Monitoring"),
    ("CM", "Configuration Management"),
    ("CP", "Contingency Planning"),
    ("IA", "Identification and Authentication"),
    ("IR", "Incident Response"),
    ("MA", "Maintenance"),
    ("MP", "Media Protection"),
    ("PE", "Physical and Environmental Protection"),
    ("PL", "Planning"),
    ("PM", "Program Management"),
    ("PS", "Personnel Security"),
    ("PT", "PII Processing and Transparency"),
    ("RA", "Risk Assessment"),
    ("SA", "System and Services Acquisition"),
    ("SC", "System and Communications Protection"),
    ("SI", "System and Information Integrity"),
    ("SR", "Supply Chain Risk Management"),
];

// ============================================================================
// Handlers
// ============================================================================

/// Get ATO map data from compliance assessments
pub async fn get_ato_map(
    pool: web::Data<SqlitePool>,
    query: web::Query<GetAtoMapQuery>,
) -> Result<HttpResponse> {
    let framework_id = query.framework.as_deref().unwrap_or("nist_800_53");

    // Build ATO map from database data
    let ato_data = build_ato_map_from_db(
        pool.get_ref(),
        query.scan_id.as_deref(),
        query.engagement_id.as_deref(),
        framework_id,
    )
    .await
    .map_err(|e| {
        log::error!("Failed to build ATO map: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to generate ATO map")
    })?;

    Ok(HttpResponse::Ok().json(ato_data))
}

/// Get ATO map for a specific engagement
pub async fn get_engagement_ato_map(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let engagement_id = path.into_inner();

    // Get engagement details
    let engagement: Option<(String, String, Option<String>)> = sqlx::query_as(
        "SELECT id, name, customer_id FROM engagements WHERE id = ?"
    )
    .bind(&engagement_id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to fetch engagement: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to fetch engagement")
    })?;

    let (eng_id, eng_name, customer_id) = match engagement {
        Some(e) => e,
        None => {
            return Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": "Engagement not found"
            })));
        }
    };

    // Get customer/organization name
    let org_name: Option<String> = if let Some(cust_id) = &customer_id {
        sqlx::query_scalar("SELECT company_name FROM portal_customers WHERE id = ?")
            .bind(cust_id)
            .fetch_optional(pool.get_ref())
            .await
            .ok()
            .flatten()
    } else {
        None
    };

    let ato_data = build_ato_map_from_db(
        pool.get_ref(),
        None,
        Some(&eng_id),
        "nist_800_53",
    )
    .await
    .map_err(|e| {
        log::error!("Failed to build ATO map for engagement: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to generate ATO map")
    })?;

    // Override with engagement-specific info
    let mut ato_data = ato_data;
    ato_data.system_name = eng_name;
    ato_data.system_id = Some(eng_id);
    ato_data.organization = org_name;

    Ok(HttpResponse::Ok().json(ato_data))
}

/// Generate sample/demo ATO map data
pub async fn get_sample_ato_map() -> Result<HttpResponse> {
    let sample_data = generate_sample_ato_map();
    Ok(HttpResponse::Ok().json(sample_data))
}

/// Zeus AI endpoint for intelligent ATO manipulation
pub async fn zeus_ato(
    body: web::Json<ZeusRequest>,
) -> Result<HttpResponse> {
    let request = body.into_inner();

    // Build context summary for LLM (used for debugging/logging)
    let _context_summary = build_zeus_context_summary(&request.context);

    // Analyze the prompt to determine intent and generate response
    let (message, action) = analyze_zeus_prompt(&request.prompt, &request.context).await;

    log::info!("Zeus ATO request: '{}' -> action: {:?}", request.prompt, action.as_ref().map(|a| &a.action_type));

    Ok(HttpResponse::Ok().json(ZeusResponse {
        message,
        action,
    }))
}

/// Update a single control status
pub async fn update_control(
    pool: web::Data<SqlitePool>,
    body: web::Json<UpdateControlRequest>,
) -> Result<HttpResponse> {
    let request = body.into_inner();

    // Update in database if there's a matching assessment
    let result = sqlx::query(
        r#"
        UPDATE manual_assessments
        SET overall_rating = ?, findings = COALESCE(?, findings), updated_at = datetime('now')
        WHERE control_id = ?
        "#
    )
    .bind(&request.status)
    .bind(&request.notes)
    .bind(&request.control_id)
    .execute(pool.get_ref())
    .await;

    match result {
        Ok(r) => {
            log::info!("Updated control {} to status {} ({} rows)",
                request.control_id, request.status, r.rows_affected());
            Ok(HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "controlId": request.control_id,
                "newStatus": request.status
            })))
        }
        Err(e) => {
            log::error!("Failed to update control {}: {}", request.control_id, e);
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to update control"
            })))
        }
    }
}

/// Bulk update controls by family or status
pub async fn bulk_update_controls(
    pool: web::Data<SqlitePool>,
    body: web::Json<BulkUpdateRequest>,
) -> Result<HttpResponse> {
    let request = body.into_inner();

    // Build query based on filters
    let query = if let Some(family_id) = &request.family_id {
        let family_prefix = format!("{}-%", family_id);
        sqlx::query(
            r#"
            UPDATE manual_assessments
            SET overall_rating = ?, findings = COALESCE(?, findings), updated_at = datetime('now')
            WHERE control_id LIKE ? AND overall_rating = ?
            "#
        )
        .bind(&request.new_status)
        .bind(&request.notes)
        .bind(&family_prefix)
        .bind(&request.target_status)
        .execute(pool.get_ref())
        .await
    } else {
        sqlx::query(
            r#"
            UPDATE manual_assessments
            SET overall_rating = ?, findings = COALESCE(?, findings), updated_at = datetime('now')
            WHERE overall_rating = ?
            "#
        )
        .bind(&request.new_status)
        .bind(&request.notes)
        .bind(&request.target_status)
        .execute(pool.get_ref())
        .await
    };

    match query {
        Ok(r) => {
            log::info!("Bulk updated {} controls from {} to {}",
                r.rows_affected(), request.target_status, request.new_status);
            Ok(HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "updatedCount": r.rows_affected()
            })))
        }
        Err(e) => {
            log::error!("Failed to bulk update controls: {}", e);
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to bulk update controls"
            })))
        }
    }
}

// ============================================================================
// Zeus AI Helper Functions
// ============================================================================

fn build_zeus_context_summary(context: &ZeusContext) -> String {
    let mut summary = format!(
        "System: {} (Score: {}%)\n\nControl Families:\n",
        context.system_name, context.overall_score
    );

    for family in &context.families {
        summary.push_str(&format!(
            "- {} ({}): {} compliant, {} non-compliant, {} partial, {} not assessed\n",
            family.name, family.id,
            family.stats.compliant, family.stats.non_compliant,
            family.stats.partial, family.stats.not_assessed
        ));
    }

    summary
}

async fn analyze_zeus_prompt(prompt: &str, context: &ZeusContext) -> (String, Option<ZeusAction>) {
    let prompt_lower = prompt.to_lowercase();

    // Pattern matching for common ATO commands

    // Status update commands
    if prompt_lower.contains("mark") && prompt_lower.contains("compliant") {
        if let Some(control_id) = extract_control_id(&prompt_lower) {
            return (
                format!("I'll mark control {} as compliant.", control_id.to_uppercase()),
                Some(ZeusAction {
                    action_type: "update_status".to_string(),
                    control_id: Some(control_id.to_uppercase()),
                    family_id: None,
                    new_status: Some("Compliant".to_string()),
                    target_status: None,
                    notes: Some("Marked compliant by Zeus AI".to_string()),
                }),
            );
        }
    }

    if prompt_lower.contains("mark") && prompt_lower.contains("non-compliant") {
        if let Some(control_id) = extract_control_id(&prompt_lower) {
            return (
                format!("I'll mark control {} as non-compliant.", control_id.to_uppercase()),
                Some(ZeusAction {
                    action_type: "update_status".to_string(),
                    control_id: Some(control_id.to_uppercase()),
                    family_id: None,
                    new_status: Some("NonCompliant".to_string()),
                    target_status: None,
                    notes: Some("Marked non-compliant by Zeus AI".to_string()),
                }),
            );
        }
    }

    // Bulk update all non-assessed to not applicable
    if prompt_lower.contains("not assessed") && prompt_lower.contains("not applicable") {
        if let Some(family_id) = extract_family_id(&prompt_lower) {
            let family_name = context.families.iter()
                .find(|f| f.id.to_lowercase() == family_id.to_lowercase())
                .map(|f| f.name.as_str())
                .unwrap_or(&family_id);

            return (
                format!("I'll mark all not-assessed controls in {} as not applicable.", family_name),
                Some(ZeusAction {
                    action_type: "bulk_update".to_string(),
                    control_id: None,
                    family_id: Some(family_id.to_uppercase()),
                    new_status: Some("NotApplicable".to_string()),
                    target_status: Some("NotAssessed".to_string()),
                    notes: Some("Bulk marked N/A by Zeus AI".to_string()),
                }),
            );
        } else {
            return (
                "I'll mark all not-assessed controls as not applicable.".to_string(),
                Some(ZeusAction {
                    action_type: "bulk_update".to_string(),
                    control_id: None,
                    family_id: None,
                    new_status: Some("NotApplicable".to_string()),
                    target_status: Some("NotAssessed".to_string()),
                    notes: Some("Bulk marked N/A by Zeus AI".to_string()),
                }),
            );
        }
    }

    // Focus on a family
    if prompt_lower.contains("focus") || prompt_lower.contains("show") || prompt_lower.contains("expand") {
        if let Some(family_id) = extract_family_id(&prompt_lower) {
            let family_name = context.families.iter()
                .find(|f| f.id.to_lowercase() == family_id.to_lowercase())
                .map(|f| f.name.as_str())
                .unwrap_or(&family_id);

            return (
                format!("Focusing on the {} control family.", family_name),
                Some(ZeusAction {
                    action_type: "focus_family".to_string(),
                    control_id: None,
                    family_id: Some(family_id.to_uppercase()),
                    new_status: None,
                    target_status: None,
                    notes: None,
                }),
            );
        }
    }

    // Highlight non-compliant
    if prompt_lower.contains("highlight") && prompt_lower.contains("non-compliant") {
        return (
            "Highlighting all non-compliant controls.".to_string(),
            Some(ZeusAction {
                action_type: "highlight_status".to_string(),
                control_id: None,
                family_id: None,
                new_status: None,
                target_status: Some("NonCompliant".to_string()),
                notes: None,
            }),
        );
    }

    // Analysis and recommendations
    if prompt_lower.contains("analyze") || prompt_lower.contains("recommend") || prompt_lower.contains("priority") {
        let non_compliant_families: Vec<&ZeusFamilyContext> = context.families.iter()
            .filter(|f| f.stats.non_compliant > 0)
            .collect();

        if non_compliant_families.is_empty() {
            return (
                "Great news! All assessed controls are either compliant, partially compliant, or marked as not applicable. Consider reviewing the not-assessed controls next.".to_string(),
                None,
            );
        }

        let worst_family = non_compliant_families.iter()
            .max_by_key(|f| f.stats.non_compliant)
            .unwrap();

        return (
            format!(
                "Analysis: The {} family has the most non-compliant controls ({} out of {}). I recommend focusing on this family first. Would you like me to highlight these controls?",
                worst_family.name, worst_family.stats.non_compliant, worst_family.stats.total
            ),
            Some(ZeusAction {
                action_type: "focus_family".to_string(),
                control_id: None,
                family_id: Some(worst_family.id.clone()),
                new_status: None,
                target_status: None,
                notes: None,
            }),
        );
    }

    // Export actions
    if prompt_lower.contains("export") || prompt_lower.contains("generate report") {
        return (
            "I can help you export the ATO map. Would you like to export as Excel or JSON format?".to_string(),
            Some(ZeusAction {
                action_type: "export".to_string(),
                control_id: None,
                family_id: None,
                new_status: None,
                target_status: None,
                notes: None,
            }),
        );
    }

    // Status summary
    if prompt_lower.contains("status") || prompt_lower.contains("summary") || prompt_lower.contains("overview") {
        let total_controls: i32 = context.families.iter().map(|f| f.stats.total).sum();
        let total_compliant: i32 = context.families.iter().map(|f| f.stats.compliant).sum();
        let total_non_compliant: i32 = context.families.iter().map(|f| f.stats.non_compliant).sum();
        let total_partial: i32 = context.families.iter().map(|f| f.stats.partial).sum();
        let total_not_assessed: i32 = context.families.iter().map(|f| f.stats.not_assessed).sum();

        return (
            format!(
                "ATO Status Summary for {}:\n\n\
                 Overall Score: {}%\n\
                 Total Controls: {}\n\
                 - Compliant: {} ({:.1}%)\n\
                 - Non-Compliant: {} ({:.1}%)\n\
                 - Partially Compliant: {} ({:.1}%)\n\
                 - Not Assessed: {} ({:.1}%)\n\n\
                 {} control families are being tracked.",
                context.system_name,
                context.overall_score,
                total_controls,
                total_compliant, (total_compliant as f64 / total_controls as f64 * 100.0),
                total_non_compliant, (total_non_compliant as f64 / total_controls as f64 * 100.0),
                total_partial, (total_partial as f64 / total_controls as f64 * 100.0),
                total_not_assessed, (total_not_assessed as f64 / total_controls as f64 * 100.0),
                context.families.len()
            ),
            None,
        );
    }

    // Default response - try to use LLM if available
    let llm_response = try_llm_response(prompt, context).await;
    if let Some(response) = llm_response {
        return (response, None);
    }

    // Fallback helpful response
    (
        "I can help you with the ATO map. Here are some things I can do:\n\n\
         - 'Mark [control-id] as compliant' - Update a control's status\n\
         - 'Mark all not-assessed in [family] as N/A' - Bulk update controls\n\
         - 'Focus on [family]' - Expand a control family\n\
         - 'Highlight non-compliant' - Show all failing controls\n\
         - 'Analyze priorities' - Get recommendations\n\
         - 'Show status summary' - Get an overview\n\
         - 'Export' - Generate a report".to_string(),
        None,
    )
}

fn extract_control_id(text: &str) -> Option<String> {
    // Match patterns like AC-1, AC-1(1), SI-4(5), etc.
    let patterns = [
        r"([a-z]{2})-(\d+)(?:\((\d+)\))?",  // AC-1, AC-1(1)
    ];

    for pattern in patterns {
        if let Ok(re) = regex::Regex::new(pattern) {
            if let Some(captures) = re.captures(text) {
                let family = captures.get(1).map(|m| m.as_str()).unwrap_or("");
                let number = captures.get(2).map(|m| m.as_str()).unwrap_or("");
                let enhancement = captures.get(3).map(|m| m.as_str());

                return Some(if let Some(enh) = enhancement {
                    format!("{}-{}({})", family.to_uppercase(), number, enh)
                } else {
                    format!("{}-{}", family.to_uppercase(), number)
                });
            }
        }
    }
    None
}

fn extract_family_id(text: &str) -> Option<String> {
    let families = [
        "ac", "at", "au", "ca", "cm", "cp", "ia", "ir", "ma", "mp",
        "pe", "pl", "pm", "ps", "pt", "ra", "sa", "sc", "si", "sr",
    ];

    for family in families {
        if text.contains(family) {
            // Make sure it's not part of a control ID
            let idx = text.find(family)?;
            let after = text.get(idx + family.len()..);
            if let Some(after_str) = after {
                if after_str.starts_with('-') && after_str.chars().nth(1).map(|c| c.is_ascii_digit()).unwrap_or(false) {
                    continue; // This is a control ID like "ac-1", not a family reference
                }
            }
            return Some(family.to_uppercase());
        }
    }

    // Also check for full family names
    let family_names = [
        ("access control", "AC"),
        ("awareness", "AT"),
        ("audit", "AU"),
        ("assessment", "CA"),
        ("configuration", "CM"),
        ("contingency", "CP"),
        ("identification", "IA"),
        ("incident response", "IR"),
        ("maintenance", "MA"),
        ("media protection", "MP"),
        ("physical", "PE"),
        ("planning", "PL"),
        ("program management", "PM"),
        ("personnel", "PS"),
        ("pii", "PT"),
        ("risk assessment", "RA"),
        ("acquisition", "SA"),
        ("communications", "SC"),
        ("integrity", "SI"),
        ("supply chain", "SR"),
    ];

    for (name, id) in family_names {
        if text.contains(name) {
            return Some(id.to_string());
        }
    }

    None
}

async fn try_llm_response(prompt: &str, context: &ZeusContext) -> Option<String> {
    // Try to use the LLM orchestrator for complex queries
    let system_prompt = format!(
        "You are Zeus, an AI assistant helping with ATO (Authority to Operate) compliance assessments. \
         The current system is '{}' with an overall score of {}%. \
         Be concise and helpful. Focus on actionable advice for improving compliance.",
        context.system_name, context.overall_score
    );

    match llm_orchestrator::quick_chat(&system_prompt, prompt).await {
        Ok(response) => Some(response),
        Err(e) => {
            log::debug!("LLM not available for Zeus: {}", e);
            None
        }
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

async fn build_ato_map_from_db(
    pool: &SqlitePool,
    scan_id: Option<&str>,
    engagement_id: Option<&str>,
    _framework_id: &str,
) -> anyhow::Result<AtoMapData> {
    // Get manual assessments
    let assessments: Vec<(String, String, String, String, Option<String>, String)> = if let Some(eng_id) = engagement_id {
        sqlx::query_as(
            r#"
            SELECT
                ma.id,
                ma.control_id,
                ma.overall_rating,
                ma.rating_score,
                ma.findings,
                ma.created_at
            FROM manual_assessments ma
            JOIN assessment_campaigns ac ON ma.campaign_id = ac.id
            WHERE ac.engagement_id = ?
            ORDER BY ma.control_id
            "#
        )
        .bind(eng_id)
        .fetch_all(pool)
        .await
        .unwrap_or_default()
    } else if let Some(sid) = scan_id {
        // Try to get from scan's compliance results
        sqlx::query_as(
            r#"
            SELECT
                id,
                control_id,
                status as overall_rating,
                CAST(score as TEXT) as rating_score,
                findings,
                created_at
            FROM compliance_results
            WHERE scan_id = ?
            ORDER BY control_id
            "#
        )
        .bind(sid)
        .fetch_all(pool)
        .await
        .unwrap_or_default()
    } else {
        Vec::new()
    };

    // Get evidence counts per control
    let evidence_counts: HashMap<String, i32> = sqlx::query_as::<_, (String, i32)>(
        r#"
        SELECT control_id, COUNT(*) as count
        FROM assessment_evidence
        GROUP BY control_id
        "#
    )
    .fetch_all(pool)
    .await
    .unwrap_or_default()
    .into_iter()
    .collect();

    // Build control family map
    let mut family_controls: HashMap<String, Vec<AtoControl>> = HashMap::new();

    // Initialize all families
    for (abbrev, _) in NIST_CONTROL_FAMILIES {
        family_controls.insert(abbrev.to_string(), Vec::new());
    }

    // Check if we have assessments before consuming the vector
    let has_assessments = !assessments.is_empty();

    // Process assessments
    for (id, control_id, rating, _score, findings, created_at) in assessments {
        let family_abbrev = control_id.split('-').next().unwrap_or("").to_uppercase();

        if let Some(controls) = family_controls.get_mut(&family_abbrev) {
            let status = match rating.as_str() {
                "Compliant" | "compliant" => "Compliant",
                "NonCompliant" | "non_compliant" => "NonCompliant",
                "PartiallyCompliant" | "partially_compliant" | "partial" => "PartiallyCompliant",
                "NotApplicable" | "not_applicable" | "n/a" => "NotApplicable",
                _ => "NotAssessed",
            };

            controls.push(AtoControl {
                id: id.clone(),
                control_id: control_id.clone(),
                title: format!("Control {}", control_id),
                status: status.to_string(),
                evidence_count: *evidence_counts.get(&control_id).unwrap_or(&0),
                poam_id: if status == "NonCompliant" {
                    Some(format!("POA&M-{}", controls.len() + 1))
                } else {
                    None
                },
                last_assessed: Some(created_at.split('T').next().unwrap_or(&created_at).to_string()),
                assessor: None,
                notes: findings,
            });
        }
    }

    // If no data, use framework defaults
    if !has_assessments {
        for control in nist_800_53::get_controls() {
            let family_abbrev = control.control_id.split('-').next().unwrap_or("").to_uppercase();

            if let Some(controls) = family_controls.get_mut(&family_abbrev) {
                controls.push(AtoControl {
                    id: control.control_id.clone(),
                    control_id: control.control_id.clone(),
                    title: control.title.clone(),
                    status: "NotAssessed".to_string(),
                    evidence_count: 0,
                    poam_id: None,
                    last_assessed: None,
                    assessor: None,
                    notes: None,
                });
            }
        }
    }

    // Build control families
    let mut control_families: Vec<AtoControlFamily> = Vec::new();
    let mut total_poam = 0;

    for (abbrev, name) in NIST_CONTROL_FAMILIES {
        let controls = family_controls.remove(*abbrev).unwrap_or_default();

        if controls.is_empty() {
            continue;
        }

        let compliant_count = controls.iter().filter(|c| c.status == "Compliant").count() as i32;
        let non_compliant_count = controls.iter().filter(|c| c.status == "NonCompliant").count() as i32;
        let partial_count = controls.iter().filter(|c| c.status == "PartiallyCompliant").count() as i32;
        let not_assessed_count = controls.iter().filter(|c| c.status == "NotAssessed").count() as i32;
        let not_applicable_count = controls.iter().filter(|c| c.status == "NotApplicable").count() as i32;

        total_poam += controls.iter().filter(|c| c.poam_id.is_some()).count() as i32;

        control_families.push(AtoControlFamily {
            id: abbrev.to_string(),
            name: name.to_string(),
            abbreviation: abbrev.to_string(),
            controls,
            compliant_count,
            non_compliant_count,
            partial_count,
            not_assessed_count,
            not_applicable_count,
        });
    }

    // Calculate overall score
    let total_controls: i32 = control_families.iter().map(|f| f.controls.len() as i32).sum();
    let total_compliant: i32 = control_families.iter().map(|f| f.compliant_count).sum();
    let total_partial: i32 = control_families.iter().map(|f| f.partial_count).sum();
    let total_na: i32 = control_families.iter().map(|f| f.not_applicable_count).sum();
    let total_not_assessed: i32 = control_families.iter().map(|f| f.not_assessed_count).sum();

    let assessable = total_controls - total_na - total_not_assessed;
    let overall_score = if assessable > 0 {
        ((total_compliant as f64 + total_partial as f64 * 0.5) / assessable as f64 * 100.0) as i32
    } else {
        0
    };

    Ok(AtoMapData {
        system_name: "System Assessment".to_string(),
        system_id: None,
        organization: None,
        authorizing_official: None,
        assessment_date: Some(chrono::Utc::now().format("%Y-%m-%d").to_string()),
        target_ato_date: None,
        baseline: "Moderate".to_string(),
        framework: "NIST 800-53 Rev 5".to_string(),
        control_families,
        overall_score,
        poam_count: total_poam,
    })
}

fn generate_sample_ato_map() -> AtoMapData {
    use rand::Rng;
    let mut rng = rand::thread_rng();

    let mut control_families: Vec<AtoControlFamily> = Vec::new();
    let mut total_poam = 0;

    for (abbrev, name) in NIST_CONTROL_FAMILIES {
        let control_count = rng.gen_range(5..=20);
        let mut controls: Vec<AtoControl> = Vec::new();

        for i in 1..=control_count {
            let rand_val: f64 = rng.gen();
            let status = if rand_val < 0.5 {
                "Compliant"
            } else if rand_val < 0.65 {
                "PartiallyCompliant"
            } else if rand_val < 0.75 {
                "NonCompliant"
            } else if rand_val < 0.85 {
                "NotAssessed"
            } else {
                "NotApplicable"
            };

            let has_poam = status == "NonCompliant";
            if has_poam {
                total_poam += 1;
            }

            controls.push(AtoControl {
                id: format!("{}-{}", abbrev, i),
                control_id: format!("{}-{}", abbrev, i),
                title: format!("{} Control {}", name, i),
                status: status.to_string(),
                evidence_count: if status == "Compliant" { rng.gen_range(1..=5) } else { 0 },
                poam_id: if has_poam { Some(format!("POA&M-{}", total_poam)) } else { None },
                last_assessed: Some(format!(
                    "{}-{:02}-{:02}",
                    2024,
                    rng.gen_range(1..=12),
                    rng.gen_range(1..=28)
                )),
                assessor: None,
                notes: None,
            });
        }

        let compliant_count = controls.iter().filter(|c| c.status == "Compliant").count() as i32;
        let non_compliant_count = controls.iter().filter(|c| c.status == "NonCompliant").count() as i32;
        let partial_count = controls.iter().filter(|c| c.status == "PartiallyCompliant").count() as i32;
        let not_assessed_count = controls.iter().filter(|c| c.status == "NotAssessed").count() as i32;
        let not_applicable_count = controls.iter().filter(|c| c.status == "NotApplicable").count() as i32;

        control_families.push(AtoControlFamily {
            id: abbrev.to_string(),
            name: name.to_string(),
            abbreviation: abbrev.to_string(),
            controls,
            compliant_count,
            non_compliant_count,
            partial_count,
            not_assessed_count,
            not_applicable_count,
        });
    }

    // Calculate overall score
    let total_controls: i32 = control_families.iter().map(|f| f.controls.len() as i32).sum();
    let total_compliant: i32 = control_families.iter().map(|f| f.compliant_count).sum();
    let total_partial: i32 = control_families.iter().map(|f| f.partial_count).sum();
    let total_na: i32 = control_families.iter().map(|f| f.not_applicable_count).sum();
    let total_not_assessed: i32 = control_families.iter().map(|f| f.not_assessed_count).sum();

    let assessable = total_controls - total_na - total_not_assessed;
    let overall_score = if assessable > 0 {
        ((total_compliant as f64 + total_partial as f64 * 0.5) / assessable as f64 * 100.0) as i32
    } else {
        0
    };

    AtoMapData {
        system_name: "Sample Information System".to_string(),
        system_id: Some("SYS-2024-001".to_string()),
        organization: Some("Sample Organization".to_string()),
        authorizing_official: Some("Jane Smith, CISO".to_string()),
        assessment_date: Some(chrono::Utc::now().format("%Y-%m-%d").to_string()),
        target_ato_date: Some(
            (chrono::Utc::now() + chrono::Duration::days(90))
                .format("%Y-%m-%d")
                .to_string(),
        ),
        baseline: "Moderate".to_string(),
        framework: "NIST 800-53 Rev 5".to_string(),
        control_families,
        overall_score,
        poam_count: total_poam,
    }
}

// ============================================================================
// Route Configuration
// ============================================================================

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/ato-map")
            .route("", web::get().to(get_ato_map))
            .route("/sample", web::get().to(get_sample_ato_map))
            .route("/engagement/{id}", web::get().to(get_engagement_ato_map))
            // Zeus AI endpoints
            .route("/zeus", web::post().to(zeus_ato))
            .route("/control", web::put().to(update_control))
            .route("/bulk-update", web::post().to(bulk_update_controls)),
    );
}
