//! Threat Hunting API Endpoints
//!
//! Provides REST API access to threat hunting capabilities including:
//! - IOC management (CRUD, import/export, matching)
//! - MITRE ATT&CK matrix and coverage
//! - Hunting playbooks
//! - Hunting sessions
//! - Retrospective search

use actix_web::{web, HttpResponse, Result};
use log::{error, info};
use serde::Deserialize;
use sqlx::SqlitePool;

use crate::db;
use crate::threat_hunting::{
    ioc::{
        IocType, IocStatus, IocSeverity, IocFilter, CreateIocRequest, UpdateIocRequest,
        IocValidator, CsvIocParser, StixIocParser, BulkImportResult,
        export_to_csv, export_to_stix, export_to_openioc,
    },
    mitre::{MitreDatabase, CreateDetectionMappingRequest},
    playbooks::{
        PlaybookCategory, SessionStatus,
        CreatePlaybookRequest, StartSessionRequest, AddFindingRequest,
    },
    retrospective::{
        CreateSearchRequest, SearchStatus, SearchResult, SearchSourceType, MatchContext,
        RetrospectiveSearchEngine,
    },
};
use log::warn;
use crate::web::auth::Claims;

// ============================================================================
// IOC Endpoints
// ============================================================================

/// Query parameters for IOC list
#[derive(Debug, Deserialize)]
pub struct IocQuery {
    pub ioc_type: Option<String>,
    pub status: Option<String>,
    pub severity: Option<String>,
    pub source: Option<String>,
    pub tag: Option<String>,
    pub threat_actor: Option<String>,
    pub mitre_technique: Option<String>,
    pub search: Option<String>,
    pub limit: Option<i32>,
    pub offset: Option<i32>,
}

/// POST /api/hunting/iocs - Create IOC
pub async fn create_ioc(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    body: web::Json<CreateIocRequest>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;

    info!("Creating IOC: {} (type: {})", body.value, body.ioc_type);

    // Validate IOC value
    if let Err(e) = IocValidator::validate(body.ioc_type, &body.value) {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": format!("Invalid IOC value: {}", e)
        })));
    }

    let ioc = db::threat_hunting::create_ioc(pool.get_ref(), user_id, &body).await
        .map_err(|e| {
            error!("Failed to create IOC: {}", e);
            if e.to_string().contains("UNIQUE constraint failed") {
                actix_web::error::ErrorConflict("IOC already exists")
            } else {
                actix_web::error::ErrorInternalServerError("Failed to create IOC")
            }
        })?;

    Ok(HttpResponse::Created().json(ioc))
}

/// GET /api/hunting/iocs - List IOCs
pub async fn list_iocs(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    query: web::Query<IocQuery>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;

    let filter = IocFilter {
        ioc_type: query.ioc_type.as_ref().and_then(|t| IocType::from_str(t)),
        status: query.status.as_ref().and_then(|s| IocStatus::from_str(s)),
        severity: query.severity.as_ref().and_then(|s| IocSeverity::from_str(s)),
        source: query.source.as_ref().and_then(|s| crate::threat_hunting::ioc::IocSource::from_str(s)),
        tag: query.tag.clone(),
        threat_actor: query.threat_actor.clone(),
        mitre_technique: query.mitre_technique.clone(),
        search: query.search.clone(),
        limit: query.limit.or(Some(100)),
        offset: query.offset,
    };

    let iocs = db::threat_hunting::get_iocs(pool.get_ref(), user_id, &filter).await
        .map_err(|e| {
            error!("Failed to list IOCs: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to list IOCs")
        })?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "iocs": iocs,
        "count": iocs.len()
    })))
}

/// GET /api/hunting/iocs/{id} - Get IOC by ID
pub async fn get_ioc(
    _claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let id = path.into_inner();

    let ioc = db::threat_hunting::get_ioc_by_id(pool.get_ref(), &id).await
        .map_err(|e| {
            error!("Failed to get IOC: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to get IOC")
        })?;

    match ioc {
        Some(ioc) => Ok(HttpResponse::Ok().json(ioc)),
        None => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "IOC not found"
        }))),
    }
}

/// PUT /api/hunting/iocs/{id} - Update IOC
pub async fn update_ioc(
    _claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    body: web::Json<UpdateIocRequest>,
) -> Result<HttpResponse> {
    let id = path.into_inner();

    let updated = db::threat_hunting::update_ioc(pool.get_ref(), &id, &body).await
        .map_err(|e| {
            error!("Failed to update IOC: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to update IOC")
        })?;

    if updated {
        let ioc = db::threat_hunting::get_ioc_by_id(pool.get_ref(), &id).await
            .map_err(|e| actix_web::error::ErrorInternalServerError(format!("{}", e)))?;
        Ok(HttpResponse::Ok().json(ioc))
    } else {
        Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "IOC not found"
        })))
    }
}

/// DELETE /api/hunting/iocs/{id} - Delete IOC
pub async fn delete_ioc(
    _claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let id = path.into_inner();

    let deleted = db::threat_hunting::delete_ioc(pool.get_ref(), &id).await
        .map_err(|e| {
            error!("Failed to delete IOC: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to delete IOC")
        })?;

    if deleted {
        Ok(HttpResponse::Ok().json(serde_json::json!({
            "success": true,
            "message": "IOC deleted"
        })))
    } else {
        Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "IOC not found"
        })))
    }
}

/// Import request
#[derive(Debug, Deserialize)]
pub struct ImportRequest {
    pub format: String,
    pub content: String,
}

/// POST /api/hunting/iocs/import - Bulk import IOCs
pub async fn import_iocs(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    body: web::Json<ImportRequest>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;

    info!("Importing IOCs (format: {})", body.format);

    let iocs = match body.format.to_lowercase().as_str() {
        "csv" => CsvIocParser::parse(&body.content)
            .map_err(|e| actix_web::error::ErrorBadRequest(format!("Invalid CSV: {}", e)))?,
        "stix" => StixIocParser::parse(&body.content)
            .map_err(|e| actix_web::error::ErrorBadRequest(format!("Invalid STIX: {}", e)))?,
        _ => return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Unsupported format. Use 'csv' or 'stix'"
        }))),
    };

    let (imported, skipped, errors) = db::threat_hunting::bulk_import_iocs(pool.get_ref(), user_id, &iocs).await
        .map_err(|e| {
            error!("Failed to import IOCs: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to import IOCs")
        })?;

    let result = BulkImportResult {
        total: iocs.len(),
        imported,
        skipped,
        errors,
    };

    Ok(HttpResponse::Ok().json(result))
}

/// Export query
#[derive(Debug, Deserialize)]
pub struct ExportQuery {
    pub format: Option<String>,
    pub status: Option<String>,
}

/// GET /api/hunting/iocs/export - Export IOCs
pub async fn export_iocs(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    query: web::Query<ExportQuery>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;

    let filter = IocFilter {
        status: query.status.as_ref().and_then(|s| IocStatus::from_str(s)),
        limit: Some(10000),
        ..Default::default()
    };

    let iocs = db::threat_hunting::get_iocs(pool.get_ref(), user_id, &filter).await
        .map_err(|e| {
            error!("Failed to get IOCs for export: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to export IOCs")
        })?;

    let format = query.format.as_deref().unwrap_or("csv");

    match format.to_lowercase().as_str() {
        "csv" => {
            let csv = export_to_csv(&iocs);
            Ok(HttpResponse::Ok()
                .content_type("text/csv")
                .insert_header(("Content-Disposition", "attachment; filename=\"iocs.csv\""))
                .body(csv))
        }
        "stix" => {
            let stix = export_to_stix(&iocs);
            Ok(HttpResponse::Ok()
                .content_type("application/json")
                .insert_header(("Content-Disposition", "attachment; filename=\"iocs.stix.json\""))
                .json(stix))
        }
        "openioc" => {
            let xml = export_to_openioc(&iocs);
            Ok(HttpResponse::Ok()
                .content_type("application/xml")
                .insert_header(("Content-Disposition", "attachment; filename=\"iocs.xml\""))
                .body(xml))
        }
        "json" => {
            Ok(HttpResponse::Ok()
                .content_type("application/json")
                .insert_header(("Content-Disposition", "attachment; filename=\"iocs.json\""))
                .json(&iocs))
        }
        _ => Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Unsupported format. Use 'csv', 'stix', 'openioc', or 'json'"
        }))),
    }
}

/// Match request
#[derive(Debug, Deserialize)]
pub struct MatchRequest {
    pub data: serde_json::Value,
    pub source_type: Option<String>,
    pub source_id: Option<String>,
}

/// POST /api/hunting/iocs/match - Match IOCs against data
pub async fn match_iocs(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    body: web::Json<MatchRequest>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;

    // Get active IOCs
    let filter = IocFilter {
        status: Some(IocStatus::Active),
        limit: Some(10000),
        ..Default::default()
    };

    let iocs = db::threat_hunting::get_iocs(pool.get_ref(), user_id, &filter).await
        .map_err(|e| {
            error!("Failed to get IOCs: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to get IOCs")
        })?;

    // Create matcher
    let matcher = crate::threat_hunting::ioc::IocMatcher::new(&iocs);

    // Match against data
    let matches = matcher.match_data(&body.data);

    // Record matches if source provided
    let source_type = body.source_type.as_deref().unwrap_or("api_match");
    let source_id = body.source_id.as_deref().unwrap_or("unknown");

    let mut recorded_matches = Vec::new();
    for (ioc_id, ioc_type, value, path) in &matches {
        let context = serde_json::json!({
            "matched_path": path,
            "matched_value": value
        });

        if let Ok(m) = db::threat_hunting::create_ioc_match(
            pool.get_ref(),
            ioc_id,
            source_type,
            source_id,
            Some(context),
        ).await {
            recorded_matches.push(serde_json::json!({
                "match_id": m.id,
                "ioc_id": ioc_id,
                "ioc_type": ioc_type.to_string(),
                "ioc_value": value,
                "matched_path": path
            }));
        }
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "matches": recorded_matches,
        "total_matches": matches.len()
    })))
}

// ============================================================================
// MITRE ATT&CK Endpoints
// ============================================================================

/// GET /api/hunting/mitre/matrix - Get ATT&CK matrix
pub async fn get_mitre_matrix(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;

    // Get detection mappings for coverage
    let mappings = db::threat_hunting::get_detection_mappings(pool.get_ref(), user_id).await
        .map_err(|e| {
            error!("Failed to get mappings: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to get mappings")
        })?;

    // Calculate coverage
    let heatmap = MitreDatabase::calculate_coverage(&mappings);

    // Build matrix with coverage
    let matrix = MitreDatabase::build_matrix(Some(&heatmap.technique_coverage));

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "matrix": matrix,
        "coverage": heatmap
    })))
}

/// GET /api/hunting/mitre/techniques - Get all techniques
pub async fn get_mitre_techniques(
    _claims: web::ReqData<Claims>,
) -> Result<HttpResponse> {
    let techniques = MitreDatabase::get_all_techniques();

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "techniques": techniques,
        "count": techniques.len()
    })))
}

/// GET /api/hunting/mitre/techniques/{id} - Get technique details
pub async fn get_mitre_technique(
    _claims: web::ReqData<Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let technique_id = path.into_inner();

    let technique = MitreDatabase::get_technique(&technique_id);

    match technique {
        Some(t) => Ok(HttpResponse::Ok().json(t)),
        None => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Technique not found"
        }))),
    }
}

/// GET /api/hunting/mitre/coverage - Get detection coverage
pub async fn get_mitre_coverage(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;

    let mappings = db::threat_hunting::get_detection_mappings(pool.get_ref(), user_id).await
        .map_err(|e| {
            error!("Failed to get mappings: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to get mappings")
        })?;

    let heatmap = MitreDatabase::calculate_coverage(&mappings);

    Ok(HttpResponse::Ok().json(heatmap))
}

/// POST /api/hunting/mitre/mappings - Create detection mapping
pub async fn create_detection_mapping(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    body: web::Json<CreateDetectionMappingRequest>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;

    info!("Creating detection mapping: {}", body.detection_name);

    let mapping = db::threat_hunting::create_detection_mapping(pool.get_ref(), user_id, &body).await
        .map_err(|e| {
            error!("Failed to create mapping: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to create mapping")
        })?;

    Ok(HttpResponse::Created().json(mapping))
}

/// GET /api/hunting/mitre/mappings - List detection mappings
pub async fn list_detection_mappings(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;

    let mappings = db::threat_hunting::get_detection_mappings(pool.get_ref(), user_id).await
        .map_err(|e| {
            error!("Failed to list mappings: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to list mappings")
        })?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "mappings": mappings,
        "count": mappings.len()
    })))
}

/// DELETE /api/hunting/mitre/mappings/{id} - Delete detection mapping
pub async fn delete_detection_mapping(
    _claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let id = path.into_inner();

    let deleted = db::threat_hunting::delete_detection_mapping(pool.get_ref(), &id).await
        .map_err(|e| {
            error!("Failed to delete mapping: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to delete mapping")
        })?;

    if deleted {
        Ok(HttpResponse::Ok().json(serde_json::json!({
            "success": true,
            "message": "Mapping deleted"
        })))
    } else {
        Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Mapping not found"
        })))
    }
}

// ============================================================================
// Playbook Endpoints
// ============================================================================

/// Playbook query
#[derive(Debug, Deserialize)]
pub struct PlaybookQuery {
    pub category: Option<String>,
}

/// POST /api/hunting/playbooks - Create playbook
pub async fn create_playbook(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    body: web::Json<CreatePlaybookRequest>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;

    info!("Creating playbook: {}", body.name);

    let playbook = db::threat_hunting::create_playbook(pool.get_ref(), user_id, &body).await
        .map_err(|e| {
            error!("Failed to create playbook: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to create playbook")
        })?;

    Ok(HttpResponse::Created().json(playbook))
}

/// GET /api/hunting/playbooks - List playbooks
pub async fn list_playbooks(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    query: web::Query<PlaybookQuery>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;

    let playbooks = if let Some(ref category) = query.category {
        if let Some(cat) = PlaybookCategory::from_str(category) {
            db::threat_hunting::get_playbooks_by_category(pool.get_ref(), cat).await
        } else {
            db::threat_hunting::get_playbooks(pool.get_ref(), user_id).await
        }
    } else {
        db::threat_hunting::get_playbooks(pool.get_ref(), user_id).await
    }.map_err(|e| {
        error!("Failed to list playbooks: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to list playbooks")
    })?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "playbooks": playbooks,
        "count": playbooks.len()
    })))
}

/// GET /api/hunting/playbooks/categories - Get playbook categories
pub async fn get_playbook_categories(
    _claims: web::ReqData<Claims>,
) -> Result<HttpResponse> {
    let categories: Vec<_> = PlaybookCategory::all()
        .into_iter()
        .map(|c| serde_json::json!({
            "id": c.to_string(),
            "name": c.display_name()
        }))
        .collect();

    Ok(HttpResponse::Ok().json(categories))
}

/// GET /api/hunting/playbooks/{id} - Get playbook by ID
pub async fn get_playbook(
    _claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let id = path.into_inner();

    let playbook = db::threat_hunting::get_playbook_by_id(pool.get_ref(), &id).await
        .map_err(|e| {
            error!("Failed to get playbook: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to get playbook")
        })?;

    match playbook {
        Some(p) => Ok(HttpResponse::Ok().json(p)),
        None => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Playbook not found"
        }))),
    }
}

/// DELETE /api/hunting/playbooks/{id} - Delete playbook
pub async fn delete_playbook(
    _claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let id = path.into_inner();

    let deleted = db::threat_hunting::delete_playbook(pool.get_ref(), &id).await
        .map_err(|e| {
            error!("Failed to delete playbook: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to delete playbook")
        })?;

    if deleted {
        Ok(HttpResponse::Ok().json(serde_json::json!({
            "success": true,
            "message": "Playbook deleted"
        })))
    } else {
        Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Cannot delete built-in playbooks"
        })))
    }
}

// ============================================================================
// Session Endpoints
// ============================================================================

/// POST /api/hunting/sessions - Start hunting session
pub async fn start_session(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    body: web::Json<StartSessionRequest>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;

    info!("Starting hunting session for playbook: {}", body.playbook_id);

    // Verify playbook exists
    let playbook = db::threat_hunting::get_playbook_by_id(pool.get_ref(), &body.playbook_id).await
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("{}", e)))?;

    if playbook.is_none() {
        return Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Playbook not found"
        })));
    }

    let session = db::threat_hunting::start_hunting_session(pool.get_ref(), user_id, &body).await
        .map_err(|e| {
            error!("Failed to start session: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to start session")
        })?;

    Ok(HttpResponse::Created().json(session))
}

/// GET /api/hunting/sessions - List sessions
pub async fn list_sessions(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;

    let sessions = db::threat_hunting::get_user_sessions(pool.get_ref(), user_id).await
        .map_err(|e| {
            error!("Failed to list sessions: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to list sessions")
        })?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "sessions": sessions,
        "count": sessions.len()
    })))
}

/// GET /api/hunting/sessions/{id} - Get session by ID
pub async fn get_session(
    _claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let id = path.into_inner();

    let session = db::threat_hunting::get_session_by_id(pool.get_ref(), &id).await
        .map_err(|e| {
            error!("Failed to get session: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to get session")
        })?;

    match session {
        Some(s) => Ok(HttpResponse::Ok().json(s)),
        None => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Session not found"
        }))),
    }
}

/// Update session request
#[derive(Debug, Deserialize)]
pub struct UpdateSessionRequest {
    pub status: Option<String>,
    pub current_step: Option<u32>,
    pub time_spent_minutes: Option<u32>,
}

/// PUT /api/hunting/sessions/{id} - Update session
pub async fn update_session(
    _claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    body: web::Json<UpdateSessionRequest>,
) -> Result<HttpResponse> {
    let id = path.into_inner();

    if let Some(ref status_str) = body.status {
        if let Some(status) = SessionStatus::from_str(status_str) {
            db::threat_hunting::update_session_status(pool.get_ref(), &id, status).await
                .map_err(|e| {
                    error!("Failed to update session status: {}", e);
                    actix_web::error::ErrorInternalServerError("Failed to update session")
                })?;
        }
    }

    // Get updated session
    let session = db::threat_hunting::get_session_by_id(pool.get_ref(), &id).await
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("{}", e)))?;

    match session {
        Some(s) => Ok(HttpResponse::Ok().json(s)),
        None => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Session not found"
        })))
    }
}

/// POST /api/hunting/sessions/{id}/findings - Add finding to session
pub async fn add_finding(
    _claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    body: web::Json<AddFindingRequest>,
) -> Result<HttpResponse> {
    let session_id = path.into_inner();

    let finding = db::threat_hunting::add_session_finding(pool.get_ref(), &session_id, &body).await
        .map_err(|e| {
            error!("Failed to add finding: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to add finding")
        })?;

    Ok(HttpResponse::Created().json(finding))
}

/// Add note request
#[derive(Debug, Deserialize)]
pub struct AddNoteRequest {
    pub step_number: Option<u32>,
    pub content: String,
}

/// POST /api/hunting/sessions/{id}/notes - Add note to session
pub async fn add_note(
    _claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    body: web::Json<AddNoteRequest>,
) -> Result<HttpResponse> {
    let session_id = path.into_inner();

    let note = db::threat_hunting::add_session_note(pool.get_ref(), &session_id, body.step_number, &body.content).await
        .map_err(|e| {
            error!("Failed to add note: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to add note")
        })?;

    Ok(HttpResponse::Created().json(note))
}

// ============================================================================
// Retrospective Search Endpoints
// ============================================================================

/// POST /api/hunting/retrospective - Create retrospective search
pub async fn create_retrospective_search(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    body: web::Json<CreateSearchRequest>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;

    info!("Creating retrospective search: {}", body.name);

    let search = db::threat_hunting::create_retrospective_search(pool.get_ref(), user_id, &body).await
        .map_err(|e| {
            error!("Failed to create search: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to create search")
        })?;

    // Spawn background task to perform the retrospective search
    let search_id = search.id.clone();
    let pool_clone = pool.get_ref().clone();
    let search_request = body.into_inner();

    tokio::spawn(async move {
        info!("Starting retrospective search task: {}", search_id);

        // Update search status to running
        if let Err(e) = db::threat_hunting::update_search_status(&pool_clone, &search_id, SearchStatus::Running, None, None).await {
            error!("Failed to update search status to running: {}", e);
            return;
        }

        let mut total_matches = 0u32;
        let mut progress: u8 = 0;

        // Collect IOC values to search for
        let ioc_values: Vec<String> = search_request.ioc_values
            .unwrap_or_default()
            .into_iter()
            .map(|ioc| ioc.value)
            .collect();

        // Also get IOCs by ID if provided
        let mut all_iocs = ioc_values;
        if let Some(ioc_ids) = &search_request.ioc_ids {
            for ioc_id in ioc_ids {
                if let Ok(Some(ioc)) = db::threat_hunting::get_ioc_by_id(&pool_clone, ioc_id).await {
                    all_iocs.push(ioc.value);
                }
            }
        }

        // Search through various data sources
        let sources = search_request.sources.unwrap_or_else(|| vec![
            "siem_logs".to_string(),
            "scan_results".to_string(),
            "network_flows".to_string(),
        ]);

        let sources_count = sources.len();
        for (idx, source) in sources.iter().enumerate() {
            info!("Searching source '{}' for {} IOCs", source, all_iocs.len());

            // Search each data source for IOC matches
            // This searches local database tables for matches
            match source.as_str() {
                "siem_logs" => {
                    // Search siem_events table for IOC values
                    for ioc in &all_iocs {
                        let query_result: Result<Vec<(String,)>, _> = sqlx::query_as(
                            r#"SELECT id FROM siem_events
                               WHERE raw_log LIKE ? OR source_ip LIKE ? OR dest_ip LIKE ?
                               LIMIT 100"#
                        )
                        .bind(format!("%{}%", ioc))
                        .bind(format!("%{}%", ioc))
                        .bind(format!("%{}%", ioc))
                        .fetch_all(&pool_clone)
                        .await;

                        if let Ok(matches) = query_result {
                            for (event_id,) in matches {
                                let result = SearchResult {
                                    id: uuid::Uuid::new_v4().to_string(),
                                    search_id: search_id.clone(),
                                    matched_ioc: ioc.clone(),
                                    ioc_type: IocType::Ip, // Default type
                                    source_type: SearchSourceType::SiemLogs,
                                    source_id: event_id.clone(),
                                    match_timestamp: chrono::Utc::now(),
                                    context: MatchContext {
                                        source_ip: None,
                                        dest_ip: None,
                                        hostname: None,
                                        user: None,
                                        process: None,
                                        raw_data: Some(format!("Found in SIEM event {}", event_id)),
                                        scan_id: None,
                                        vulnerability_id: None,
                                        additional_fields: None,
                                    },
                                    severity: "medium".to_string(),
                                    metadata: None,
                                };
                                let _ = db::threat_hunting::store_search_result(&pool_clone, &result).await;
                                total_matches += 1;
                            }
                        }
                    }
                }
                "scan_results" => {
                    // Search scan_results for IOC values (IPs, hostnames)
                    for ioc in &all_iocs {
                        let query_result: Result<Vec<(String, String)>, _> = sqlx::query_as(
                            r#"SELECT id, target FROM scan_results
                               WHERE target LIKE ?
                               LIMIT 100"#
                        )
                        .bind(format!("%{}%", ioc))
                        .fetch_all(&pool_clone)
                        .await;

                        if let Ok(matches) = query_result {
                            for (found_scan_id, target) in matches {
                                let result = SearchResult {
                                    id: uuid::Uuid::new_v4().to_string(),
                                    search_id: search_id.clone(),
                                    matched_ioc: ioc.clone(),
                                    ioc_type: IocType::Ip,
                                    source_type: SearchSourceType::ScanResults,
                                    source_id: found_scan_id.clone(),
                                    match_timestamp: chrono::Utc::now(),
                                    context: MatchContext {
                                        source_ip: Some(target.clone()),
                                        dest_ip: None,
                                        hostname: None,
                                        user: None,
                                        process: None,
                                        raw_data: Some(format!("Found in scan {} targeting {}", found_scan_id, target)),
                                        scan_id: Some(found_scan_id),
                                        vulnerability_id: None,
                                        additional_fields: None,
                                    },
                                    severity: "medium".to_string(),
                                    metadata: None,
                                };
                                let _ = db::threat_hunting::store_search_result(&pool_clone, &result).await;
                                total_matches += 1;
                            }
                        }
                    }
                }
                "network_flows" => {
                    // Search netflow_flows for IOC values
                    for ioc in &all_iocs {
                        let query_result: Result<Vec<(String,)>, _> = sqlx::query_as(
                            r#"SELECT id FROM netflow_flows
                               WHERE src_ip LIKE ? OR dst_ip LIKE ?
                               LIMIT 100"#
                        )
                        .bind(format!("%{}%", ioc))
                        .bind(format!("%{}%", ioc))
                        .fetch_all(&pool_clone)
                        .await;

                        if let Ok(matches) = query_result {
                            for (flow_id,) in matches {
                                let result = SearchResult {
                                    id: uuid::Uuid::new_v4().to_string(),
                                    search_id: search_id.clone(),
                                    matched_ioc: ioc.clone(),
                                    ioc_type: IocType::Ip,
                                    source_type: SearchSourceType::NetworkFlows,
                                    source_id: flow_id.clone(),
                                    match_timestamp: chrono::Utc::now(),
                                    context: MatchContext {
                                        source_ip: None,
                                        dest_ip: None,
                                        hostname: None,
                                        user: None,
                                        process: None,
                                        raw_data: Some(format!("Found in network flow {}", flow_id)),
                                        scan_id: None,
                                        vulnerability_id: None,
                                        additional_fields: None,
                                    },
                                    severity: "medium".to_string(),
                                    metadata: None,
                                };
                                let _ = db::threat_hunting::store_search_result(&pool_clone, &result).await;
                                total_matches += 1;
                            }
                        }
                    }
                }
                _ => {
                    warn!("Unknown search source: {}", source);
                }
            }

            // Update progress
            progress = ((idx + 1) * 100 / sources_count) as u8;
            let _ = db::threat_hunting::update_search_progress(&pool_clone, &search_id, progress).await;
        }

        // Mark search as completed
        if let Err(e) = db::threat_hunting::update_search_status(&pool_clone, &search_id, SearchStatus::Completed, Some(total_matches), None).await {
            error!("Failed to complete search: {}", e);
            let _ = db::threat_hunting::update_search_status(&pool_clone, &search_id, SearchStatus::Failed, None, Some(e.to_string())).await;
        } else {
            info!("Retrospective search {} completed: {} matches found", search_id, total_matches);
        }
    });

    Ok(HttpResponse::Created().json(search))
}

/// Search query
#[derive(Debug, Deserialize)]
pub struct SearchQuery {
    pub limit: Option<i32>,
}

/// GET /api/hunting/retrospective - List retrospective searches
pub async fn list_retrospective_searches(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    query: web::Query<SearchQuery>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let limit = query.limit.unwrap_or(50);

    let searches = db::threat_hunting::get_user_searches(pool.get_ref(), user_id, limit).await
        .map_err(|e| {
            error!("Failed to list searches: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to list searches")
        })?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "searches": searches,
        "count": searches.len()
    })))
}

/// GET /api/hunting/retrospective/{id} - Get search by ID
pub async fn get_retrospective_search(
    _claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let id = path.into_inner();

    let search = db::threat_hunting::get_search_by_id(pool.get_ref(), &id).await
        .map_err(|e| {
            error!("Failed to get search: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to get search")
        })?;

    match search {
        Some(s) => Ok(HttpResponse::Ok().json(s)),
        None => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Search not found"
        }))),
    }
}

/// Results query
#[derive(Debug, Deserialize)]
pub struct ResultsQuery {
    pub limit: Option<i32>,
    pub offset: Option<i32>,
}

/// GET /api/hunting/retrospective/{id}/results - Get search results
pub async fn get_retrospective_results(
    _claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    query: web::Query<ResultsQuery>,
) -> Result<HttpResponse> {
    let id = path.into_inner();
    let limit = query.limit.unwrap_or(100);
    let offset = query.offset.unwrap_or(0);

    let results = db::threat_hunting::get_search_results(pool.get_ref(), &id, limit, offset).await
        .map_err(|e| {
            error!("Failed to get results: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to get results")
        })?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "results": results,
        "count": results.len()
    })))
}

/// GET /api/hunting/retrospective/{id}/summary - Get search summary
pub async fn get_retrospective_summary(
    _claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let id = path.into_inner();

    let search = db::threat_hunting::get_search_by_id(pool.get_ref(), &id).await
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("{}", e)))?;

    let search = match search {
        Some(s) => s,
        None => return Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Search not found"
        }))),
    };

    let results = db::threat_hunting::get_search_results(pool.get_ref(), &id, 10000, 0).await
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("{}", e)))?;

    let summary = RetrospectiveSearchEngine::generate_summary(&search, &results);

    Ok(HttpResponse::Ok().json(summary))
}

// ============================================================================
// Route Configuration
// ============================================================================

/// Configure threat hunting routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/hunting")
            // IOC endpoints
            .route("/iocs", web::post().to(create_ioc))
            .route("/iocs", web::get().to(list_iocs))
            .route("/iocs/import", web::post().to(import_iocs))
            .route("/iocs/export", web::get().to(export_iocs))
            .route("/iocs/match", web::post().to(match_iocs))
            .route("/iocs/{id}", web::get().to(get_ioc))
            .route("/iocs/{id}", web::put().to(update_ioc))
            .route("/iocs/{id}", web::delete().to(delete_ioc))
            // MITRE ATT&CK endpoints
            .route("/mitre/matrix", web::get().to(get_mitre_matrix))
            .route("/mitre/techniques", web::get().to(get_mitre_techniques))
            .route("/mitre/techniques/{id}", web::get().to(get_mitre_technique))
            .route("/mitre/coverage", web::get().to(get_mitre_coverage))
            .route("/mitre/mappings", web::post().to(create_detection_mapping))
            .route("/mitre/mappings", web::get().to(list_detection_mappings))
            .route("/mitre/mappings/{id}", web::delete().to(delete_detection_mapping))
            // Playbook endpoints
            .route("/playbooks", web::post().to(create_playbook))
            .route("/playbooks", web::get().to(list_playbooks))
            .route("/playbooks/categories", web::get().to(get_playbook_categories))
            .route("/playbooks/{id}", web::get().to(get_playbook))
            .route("/playbooks/{id}", web::delete().to(delete_playbook))
            // Session endpoints
            .route("/sessions", web::post().to(start_session))
            .route("/sessions", web::get().to(list_sessions))
            .route("/sessions/{id}", web::get().to(get_session))
            .route("/sessions/{id}", web::put().to(update_session))
            .route("/sessions/{id}/findings", web::post().to(add_finding))
            .route("/sessions/{id}/notes", web::post().to(add_note))
            // Retrospective search endpoints
            .route("/retrospective", web::post().to(create_retrospective_search))
            .route("/retrospective", web::get().to(list_retrospective_searches))
            .route("/retrospective/{id}", web::get().to(get_retrospective_search))
            .route("/retrospective/{id}/results", web::get().to(get_retrospective_results))
            .route("/retrospective/{id}/summary", web::get().to(get_retrospective_summary)),
    );
}
