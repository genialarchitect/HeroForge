//! Digital Forensics REST API endpoints
//!
//! Provides REST API endpoints for digital forensics capabilities:
//! - Case management (CRUD)
//! - Memory dump analysis
//! - Disk image analysis
//! - PCAP file analysis
//! - Artifact collection and management
//! - Timeline and findings

use actix_web::{web, HttpResponse, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use uuid::Uuid;
use utoipa::ToSchema;

use crate::forensics::{
    memory::{
        ConnectionAnalysisResult, MemoryAnalyzer, MemoryConnection, MemoryProcess,
        MemoryString, ModuleAnalysisResult, ProcessAnalysisResult, StringAnalysisResult,
        StringCategory, LoadedModule,
    },
    disk::{
        BrowserArtifactsResult, BrowserCookie, BrowserDownload, BrowserHistoryEntry,
        DeletedFile, DeletedFilesResult, DiskAnalyzer, DiskImageType, FileEntry,
        PrefetchEntry, PrefetchResult, RecentFileEntry, RecentFilesResult, TimelineResult,
    },
    network::{
        ConnectionSummary, DnsAnalysisResult, DnsQuery, HttpAnalysisResult,
        HttpConversation, NetworkAnalyzer, ProtocolStats, SuspiciousTrafficResult,
    },
    artifacts::{ArtifactCategory, ArtifactCollector, OperatingSystem},
    types::{
        AnalysisStatus, CaseStatus, CaseType, FindingSeverity, FindingType,
        ForensicCase, ForensicFinding, TimelineEvent, TimelineEventType,
    },
};
use crate::web::auth;

// =============================================================================
// Request/Response Types
// =============================================================================

/// Request to create a new forensic case
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateCaseRequest {
    pub name: String,
    pub description: Option<String>,
    pub case_type: String,
    pub lead_analyst: Option<String>,
}

/// Request to update a forensic case
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateCaseRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub case_type: Option<String>,
    pub status: Option<String>,
    pub lead_analyst: Option<String>,
}

/// Query parameters for listing cases
#[derive(Debug, Deserialize)]
pub struct ListCasesQuery {
    pub status: Option<String>,
    pub case_type: Option<String>,
    pub limit: Option<i32>,
    pub offset: Option<i32>,
}

/// Case list response
#[derive(Debug, Serialize, ToSchema)]
pub struct CaseListResponse {
    pub cases: Vec<CaseResponse>,
    pub total: i64,
}

/// Single case response
#[derive(Debug, Serialize, ToSchema)]
pub struct CaseResponse {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub case_type: String,
    pub status: String,
    pub lead_analyst: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub memory_dump_count: i64,
    pub disk_image_count: i64,
    pub pcap_count: i64,
    pub artifact_count: i64,
    pub finding_count: i64,
}

/// Request to register a memory dump
#[derive(Debug, Deserialize, ToSchema)]
pub struct RegisterMemoryDumpRequest {
    pub filename: String,
    pub file_hash: String,
    pub file_size: i64,
    pub os_profile: Option<String>,
    pub collected_at: Option<String>,
}

/// Memory dump response
#[derive(Debug, Serialize, ToSchema)]
pub struct MemoryDumpResponse {
    pub id: String,
    pub case_id: String,
    pub filename: String,
    pub file_hash: String,
    pub file_size: i64,
    pub os_profile: Option<String>,
    pub collected_at: String,
    pub analysis_status: String,
    pub findings_json: Option<serde_json::Value>,
}

/// Request to register a disk image
#[derive(Debug, Deserialize, ToSchema)]
pub struct RegisterDiskImageRequest {
    pub filename: String,
    pub file_hash: String,
    pub file_size: i64,
    pub image_type: Option<String>,
    pub collected_at: Option<String>,
}

/// Disk image response
#[derive(Debug, Serialize, ToSchema)]
pub struct DiskImageResponse {
    pub id: String,
    pub case_id: String,
    pub filename: String,
    pub file_hash: String,
    pub file_size: i64,
    pub image_type: String,
    pub collected_at: String,
    pub analysis_status: String,
    pub findings_json: Option<serde_json::Value>,
}

/// Request to register a PCAP file
#[derive(Debug, Deserialize, ToSchema)]
pub struct RegisterPcapRequest {
    pub filename: String,
    pub file_hash: String,
    pub file_size: i64,
    pub capture_start: Option<String>,
    pub capture_end: Option<String>,
    pub packet_count: Option<i64>,
}

/// PCAP file response
#[derive(Debug, Serialize, ToSchema)]
pub struct PcapFileResponse {
    pub id: String,
    pub case_id: String,
    pub filename: String,
    pub file_hash: String,
    pub file_size: i64,
    pub capture_start: Option<String>,
    pub capture_end: Option<String>,
    pub packet_count: i64,
    pub analysis_status: String,
    pub findings_json: Option<serde_json::Value>,
}

/// Request to add process data for analysis
#[derive(Debug, Deserialize, ToSchema)]
pub struct AnalyzeProcessesRequest {
    pub processes: Vec<ProcessInput>,
}

/// Process input for analysis
#[derive(Debug, Deserialize, ToSchema)]
pub struct ProcessInput {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub path: Option<String>,
    pub cmdline: Option<String>,
    pub create_time: Option<String>,
    pub threads: Option<u32>,
    pub handles: Option<u32>,
    pub wow64: Option<bool>,
    pub is_hidden: Option<bool>,
}

/// Request to add connection data for analysis
#[derive(Debug, Deserialize, ToSchema)]
pub struct AnalyzeConnectionsRequest {
    pub connections: Vec<ConnectionInput>,
}

/// Connection input for analysis
#[derive(Debug, Deserialize, ToSchema)]
pub struct ConnectionInput {
    pub protocol: String,
    pub local_address: String,
    pub local_port: u16,
    pub remote_address: Option<String>,
    pub remote_port: Option<u16>,
    pub state: String,
    pub pid: u32,
    pub process_name: Option<String>,
}

/// Request to analyze strings
#[derive(Debug, Deserialize, ToSchema)]
pub struct AnalyzeStringsRequest {
    pub strings: Vec<StringInput>,
    pub filter_category: Option<String>,
    pub min_length: Option<usize>,
}

/// String input for analysis
#[derive(Debug, Deserialize, ToSchema)]
pub struct StringInput {
    pub offset: u64,
    pub value: String,
    pub encoding: Option<String>,
    pub pid: Option<u32>,
}

/// Request to build timeline
#[derive(Debug, Deserialize, ToSchema)]
pub struct BuildTimelineRequest {
    pub files: Vec<FileEntryInput>,
    pub start_time: Option<String>,
    pub end_time: Option<String>,
}

/// File entry input for timeline
#[derive(Debug, Deserialize, ToSchema)]
pub struct FileEntryInput {
    pub path: String,
    pub name: String,
    pub size: i64,
    pub created: Option<String>,
    pub modified: Option<String>,
    pub accessed: Option<String>,
    pub is_directory: Option<bool>,
    pub is_deleted: Option<bool>,
    pub mft_entry_number: Option<u64>,
}

/// Request to analyze disk artifacts
#[derive(Debug, Deserialize, ToSchema)]
pub struct AnalyzeDiskArtifactsRequest {
    pub artifact_type: String,
    #[serde(default)]
    pub browser_history: Vec<BrowserHistoryInput>,
    #[serde(default)]
    pub browser_downloads: Vec<BrowserDownloadInput>,
    #[serde(default)]
    pub browser_cookies: Vec<BrowserCookieInput>,
    #[serde(default)]
    pub prefetch_entries: Vec<PrefetchInput>,
    #[serde(default)]
    pub recent_files: Vec<RecentFileInput>,
    #[serde(default)]
    pub deleted_files: Vec<DeletedFileInput>,
}

/// Browser history input
#[derive(Debug, Deserialize, ToSchema)]
pub struct BrowserHistoryInput {
    pub browser: String,
    pub url: String,
    pub title: Option<String>,
    pub visit_time: String,
    pub visit_count: Option<u32>,
}

/// Browser download input
#[derive(Debug, Deserialize, ToSchema)]
pub struct BrowserDownloadInput {
    pub browser: String,
    pub url: String,
    pub target_path: String,
    pub filename: String,
    pub start_time: String,
    pub received_bytes: i64,
    pub total_bytes: i64,
}

/// Browser cookie input
#[derive(Debug, Deserialize, ToSchema)]
pub struct BrowserCookieInput {
    pub browser: String,
    pub host: String,
    pub name: String,
    pub path: String,
    pub creation_time: String,
    pub last_access_time: String,
    pub is_secure: Option<bool>,
    pub is_http_only: Option<bool>,
}

/// Prefetch input
#[derive(Debug, Deserialize, ToSchema)]
pub struct PrefetchInput {
    pub filename: String,
    pub executable_name: String,
    pub hash: String,
    pub run_count: u32,
    pub last_run_time: String,
    pub file_references: Vec<String>,
}

/// Recent file input
#[derive(Debug, Deserialize, ToSchema)]
pub struct RecentFileInput {
    pub link_path: String,
    pub target_path: String,
    pub target_name: String,
    pub target_size: i64,
    pub link_created: String,
}

/// Deleted file input
#[derive(Debug, Deserialize, ToSchema)]
pub struct DeletedFileInput {
    pub path: String,
    pub name: String,
    pub size: i64,
    pub deleted_time: Option<String>,
    pub original_location: Option<String>,
    pub recovery_status: Option<String>,
}

/// Request to analyze PCAP connections
#[derive(Debug, Deserialize, ToSchema)]
pub struct AnalyzePcapConnectionsRequest {
    pub connections: Vec<PcapConnectionInput>,
}

/// PCAP connection input
#[derive(Debug, Deserialize, ToSchema)]
pub struct PcapConnectionInput {
    pub src_ip: String,
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
    pub protocol: String,
    pub packet_count: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub first_seen: String,
    pub last_seen: String,
}

/// Request to analyze DNS queries
#[derive(Debug, Deserialize, ToSchema)]
pub struct AnalyzeDnsRequest {
    pub queries: Vec<DnsQueryInput>,
}

/// DNS query input
#[derive(Debug, Deserialize, ToSchema)]
pub struct DnsQueryInput {
    pub timestamp: String,
    pub src_ip: String,
    pub dst_ip: String,
    pub query_name: String,
    pub query_type: String,
    pub is_response: Option<bool>,
    pub response_code: Option<String>,
}

/// Request to add an artifact
#[derive(Debug, Deserialize, ToSchema)]
pub struct AddArtifactRequest {
    pub artifact_type: String,
    pub source_path: String,
    pub content_hash: String,
    pub collected_at: Option<String>,
    pub analysis_notes: Option<String>,
    pub tags: Option<Vec<String>>,
    pub metadata: Option<serde_json::Value>,
}

/// Artifact response
#[derive(Debug, Serialize, ToSchema)]
pub struct ArtifactResponse {
    pub id: String,
    pub case_id: String,
    pub artifact_type: String,
    pub source_path: String,
    pub content_hash: String,
    pub collected_at: String,
    pub analysis_notes: Option<String>,
    pub tags: Vec<String>,
    pub metadata: Option<serde_json::Value>,
}

/// Query parameters for listing artifacts
#[derive(Debug, Deserialize)]
pub struct ListArtifactsQuery {
    pub artifact_type: Option<String>,
    pub limit: Option<i32>,
    pub offset: Option<i32>,
}

/// Request to add a timeline event
#[derive(Debug, Deserialize, ToSchema)]
pub struct AddTimelineEventRequest {
    pub timestamp: String,
    pub event_type: String,
    pub source: String,
    pub description: String,
    pub artifact_id: Option<String>,
}

/// Timeline event response
#[derive(Debug, Serialize, ToSchema)]
pub struct TimelineEventResponse {
    pub id: String,
    pub case_id: String,
    pub timestamp: String,
    pub event_type: String,
    pub source: String,
    pub description: String,
    pub artifact_id: Option<String>,
}

/// Query parameters for timeline
#[derive(Debug, Deserialize)]
pub struct TimelineQuery {
    pub start_time: Option<String>,
    pub end_time: Option<String>,
    pub event_type: Option<String>,
    pub limit: Option<i32>,
    pub offset: Option<i32>,
}

/// Request to add a finding
#[derive(Debug, Deserialize, ToSchema)]
pub struct AddFindingRequest {
    pub finding_type: String,
    pub severity: String,
    pub title: String,
    pub description: String,
    pub evidence_refs: Option<Vec<String>>,
}

/// Finding response
#[derive(Debug, Serialize, ToSchema)]
pub struct FindingResponse {
    pub id: String,
    pub case_id: String,
    pub finding_type: String,
    pub severity: String,
    pub title: String,
    pub description: String,
    pub evidence_refs: Vec<String>,
    pub created_at: String,
}

/// Query parameters for findings
#[derive(Debug, Deserialize)]
pub struct FindingsQuery {
    pub finding_type: Option<String>,
    pub severity: Option<String>,
    pub limit: Option<i32>,
    pub offset: Option<i32>,
}

/// Artifact template response
#[derive(Debug, Serialize, ToSchema)]
pub struct ArtifactTemplateResponse {
    pub operating_system: String,
    pub name: String,
    pub description: String,
    pub artifacts: Vec<ArtifactPathResponse>,
}

/// Artifact path response
#[derive(Debug, Serialize, ToSchema)]
pub struct ArtifactPathResponse {
    pub category: String,
    pub path: String,
    pub description: String,
    pub is_directory: bool,
    pub recursive: bool,
    pub file_pattern: Option<String>,
    pub forensic_value: String,
}

// =============================================================================
// Case Management Endpoints
// =============================================================================

/// POST /api/forensics/cases - Create a new forensic case
#[utoipa::path(
    post,
    path = "/api/forensics/cases",
    tag = "Digital Forensics",
    security(("bearer_auth" = [])),
    request_body = CreateCaseRequest,
    responses(
        (status = 201, description = "Case created", body = CaseResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized")
    )
)]
pub async fn create_case(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    body: web::Json<CreateCaseRequest>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let case_id = Uuid::new_v4().to_string();
    let now = Utc::now();

    let case_type = CaseType::from_str(&body.case_type);

    sqlx::query(
        r#"
        INSERT INTO forensic_cases (id, name, description, case_type, status, lead_analyst, created_at, updated_at, user_id)
        VALUES (?, ?, ?, ?, 'open', ?, ?, ?, ?)
        "#,
    )
    .bind(&case_id)
    .bind(&body.name)
    .bind(&body.description)
    .bind(case_type.as_str())
    .bind(&body.lead_analyst)
    .bind(now.to_rfc3339())
    .bind(now.to_rfc3339())
    .bind(user_id)
    .execute(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to create forensic case: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to create case")
    })?;

    let response = CaseResponse {
        id: case_id,
        name: body.name.clone(),
        description: body.description.clone(),
        case_type: case_type.as_str().to_string(),
        status: "open".to_string(),
        lead_analyst: body.lead_analyst.clone(),
        created_at: now.to_rfc3339(),
        updated_at: now.to_rfc3339(),
        memory_dump_count: 0,
        disk_image_count: 0,
        pcap_count: 0,
        artifact_count: 0,
        finding_count: 0,
    };

    Ok(HttpResponse::Created().json(response))
}

/// GET /api/forensics/cases - List forensic cases
#[utoipa::path(
    get,
    path = "/api/forensics/cases",
    tag = "Digital Forensics",
    security(("bearer_auth" = [])),
    params(
        ("status" = Option<String>, Query, description = "Filter by status"),
        ("case_type" = Option<String>, Query, description = "Filter by case type"),
        ("limit" = Option<i32>, Query, description = "Limit results"),
        ("offset" = Option<i32>, Query, description = "Offset for pagination")
    ),
    responses(
        (status = 200, description = "List of cases", body = CaseListResponse),
        (status = 401, description = "Unauthorized")
    )
)]
pub async fn list_cases(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    query: web::Query<ListCasesQuery>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let limit = query.limit.unwrap_or(50);
    let offset = query.offset.unwrap_or(0);

    let mut sql = String::from(
        r#"
        SELECT c.*,
            (SELECT COUNT(*) FROM memory_dumps WHERE case_id = c.id) as memory_dump_count,
            (SELECT COUNT(*) FROM disk_images WHERE case_id = c.id) as disk_image_count,
            (SELECT COUNT(*) FROM pcap_files WHERE case_id = c.id) as pcap_count,
            (SELECT COUNT(*) FROM forensic_artifacts WHERE case_id = c.id) as artifact_count,
            (SELECT COUNT(*) FROM forensic_findings WHERE case_id = c.id) as finding_count
        FROM forensic_cases c
        WHERE c.user_id = ?
        "#,
    );

    if let Some(ref status) = query.status {
        sql.push_str(&format!(" AND c.status = '{}'", status));
    }

    if let Some(ref case_type) = query.case_type {
        sql.push_str(&format!(" AND c.case_type = '{}'", case_type));
    }

    sql.push_str(" ORDER BY c.created_at DESC LIMIT ? OFFSET ?");

    let cases: Vec<(String, String, Option<String>, String, String, Option<String>, String, String, String, i64, i64, i64, i64, i64)> = sqlx::query_as(&sql)
        .bind(user_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool.get_ref())
        .await
        .map_err(|e| {
            log::error!("Failed to list forensic cases: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to list cases")
        })?;

    let total: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM forensic_cases WHERE user_id = ?"
    )
    .bind(user_id)
    .fetch_one(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to count cases: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to count cases")
    })?;

    let case_responses: Vec<CaseResponse> = cases
        .into_iter()
        .map(|(id, name, description, case_type, status, lead_analyst, created_at, updated_at, _user_id, memory_dump_count, disk_image_count, pcap_count, artifact_count, finding_count)| {
            CaseResponse {
                id,
                name,
                description,
                case_type,
                status,
                lead_analyst,
                created_at,
                updated_at,
                memory_dump_count,
                disk_image_count,
                pcap_count,
                artifact_count,
                finding_count,
            }
        })
        .collect();

    Ok(HttpResponse::Ok().json(CaseListResponse {
        cases: case_responses,
        total: total.0,
    }))
}

/// GET /api/forensics/cases/{id} - Get case details
#[utoipa::path(
    get,
    path = "/api/forensics/cases/{id}",
    tag = "Digital Forensics",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "Case ID")
    ),
    responses(
        (status = 200, description = "Case details", body = CaseResponse),
        (status = 404, description = "Case not found"),
        (status = 401, description = "Unauthorized")
    )
)]
pub async fn get_case(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let case_id = path.into_inner();
    let user_id = &claims.sub;

    let case: Option<(String, String, Option<String>, String, String, Option<String>, String, String, String)> = sqlx::query_as(
        "SELECT id, name, description, case_type, status, lead_analyst, created_at, updated_at, user_id FROM forensic_cases WHERE id = ? AND user_id = ?"
    )
    .bind(&case_id)
    .bind(user_id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to get case: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to get case")
    })?;

    let case = case.ok_or_else(|| actix_web::error::ErrorNotFound("Case not found"))?;

    // Get counts
    let memory_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM memory_dumps WHERE case_id = ?")
        .bind(&case_id)
        .fetch_one(pool.get_ref())
        .await
        .unwrap_or((0,));

    let disk_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM disk_images WHERE case_id = ?")
        .bind(&case_id)
        .fetch_one(pool.get_ref())
        .await
        .unwrap_or((0,));

    let pcap_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM pcap_files WHERE case_id = ?")
        .bind(&case_id)
        .fetch_one(pool.get_ref())
        .await
        .unwrap_or((0,));

    let artifact_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM forensic_artifacts WHERE case_id = ?")
        .bind(&case_id)
        .fetch_one(pool.get_ref())
        .await
        .unwrap_or((0,));

    let finding_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM forensic_findings WHERE case_id = ?")
        .bind(&case_id)
        .fetch_one(pool.get_ref())
        .await
        .unwrap_or((0,));

    Ok(HttpResponse::Ok().json(CaseResponse {
        id: case.0,
        name: case.1,
        description: case.2,
        case_type: case.3,
        status: case.4,
        lead_analyst: case.5,
        created_at: case.6,
        updated_at: case.7,
        memory_dump_count: memory_count.0,
        disk_image_count: disk_count.0,
        pcap_count: pcap_count.0,
        artifact_count: artifact_count.0,
        finding_count: finding_count.0,
    }))
}

/// PUT /api/forensics/cases/{id} - Update a case
#[utoipa::path(
    put,
    path = "/api/forensics/cases/{id}",
    tag = "Digital Forensics",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "Case ID")
    ),
    request_body = UpdateCaseRequest,
    responses(
        (status = 200, description = "Case updated"),
        (status = 404, description = "Case not found"),
        (status = 401, description = "Unauthorized")
    )
)]
pub async fn update_case(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
    body: web::Json<UpdateCaseRequest>,
) -> Result<HttpResponse> {
    let case_id = path.into_inner();
    let user_id = &claims.sub;
    let now = Utc::now();

    // Verify case exists and belongs to user
    let exists: Option<(i64,)> = sqlx::query_as(
        "SELECT 1 FROM forensic_cases WHERE id = ? AND user_id = ?"
    )
    .bind(&case_id)
    .bind(user_id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to check case: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to check case")
    })?;

    if exists.is_none() {
        return Err(actix_web::error::ErrorNotFound("Case not found"));
    }

    let mut updates = vec!["updated_at = ?".to_string()];
    let mut values: Vec<String> = vec![now.to_rfc3339()];

    if let Some(ref name) = body.name {
        updates.push("name = ?".to_string());
        values.push(name.clone());
    }

    if let Some(ref description) = body.description {
        updates.push("description = ?".to_string());
        values.push(description.clone());
    }

    if let Some(ref case_type) = body.case_type {
        updates.push("case_type = ?".to_string());
        values.push(case_type.clone());
    }

    if let Some(ref status) = body.status {
        updates.push("status = ?".to_string());
        values.push(status.clone());
    }

    if let Some(ref lead_analyst) = body.lead_analyst {
        updates.push("lead_analyst = ?".to_string());
        values.push(lead_analyst.clone());
    }

    let sql = format!(
        "UPDATE forensic_cases SET {} WHERE id = ?",
        updates.join(", ")
    );

    let mut query = sqlx::query(&sql);
    for value in &values {
        query = query.bind(value);
    }
    query = query.bind(&case_id);

    query.execute(pool.get_ref()).await.map_err(|e| {
        log::error!("Failed to update case: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to update case")
    })?;

    Ok(HttpResponse::Ok().json(serde_json::json!({"message": "Case updated"})))
}

// =============================================================================
// Memory Analysis Endpoints
// =============================================================================

/// POST /api/forensics/cases/{id}/memory - Register a memory dump
#[utoipa::path(
    post,
    path = "/api/forensics/cases/{id}/memory",
    tag = "Digital Forensics",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "Case ID")
    ),
    request_body = RegisterMemoryDumpRequest,
    responses(
        (status = 201, description = "Memory dump registered", body = MemoryDumpResponse),
        (status = 404, description = "Case not found"),
        (status = 401, description = "Unauthorized")
    )
)]
pub async fn register_memory_dump(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
    body: web::Json<RegisterMemoryDumpRequest>,
) -> Result<HttpResponse> {
    let case_id = path.into_inner();
    let user_id = &claims.sub;

    // Verify case exists and belongs to user
    verify_case_access(pool.get_ref(), &case_id, user_id).await?;

    let dump_id = Uuid::new_v4().to_string();
    let now = Utc::now();
    let collected_at = body.collected_at.clone().unwrap_or_else(|| now.to_rfc3339());

    sqlx::query(
        r#"
        INSERT INTO memory_dumps (id, case_id, filename, file_hash, file_size, os_profile, collected_at, analysis_status, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?)
        "#,
    )
    .bind(&dump_id)
    .bind(&case_id)
    .bind(&body.filename)
    .bind(&body.file_hash)
    .bind(body.file_size)
    .bind(&body.os_profile)
    .bind(&collected_at)
    .bind(now.to_rfc3339())
    .execute(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to register memory dump: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to register memory dump")
    })?;

    Ok(HttpResponse::Created().json(MemoryDumpResponse {
        id: dump_id,
        case_id,
        filename: body.filename.clone(),
        file_hash: body.file_hash.clone(),
        file_size: body.file_size,
        os_profile: body.os_profile.clone(),
        collected_at,
        analysis_status: "pending".to_string(),
        findings_json: None,
    }))
}

/// GET /api/forensics/memory/{id}/processes - Analyze processes from memory dump
#[utoipa::path(
    post,
    path = "/api/forensics/memory/{id}/processes",
    tag = "Digital Forensics",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "Memory dump ID")
    ),
    request_body = AnalyzeProcessesRequest,
    responses(
        (status = 200, description = "Process analysis result"),
        (status = 404, description = "Memory dump not found"),
        (status = 401, description = "Unauthorized")
    )
)]
pub async fn analyze_memory_processes(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
    body: web::Json<AnalyzeProcessesRequest>,
) -> Result<HttpResponse> {
    let dump_id = path.into_inner();
    let user_id = &claims.sub;

    // Verify memory dump access
    verify_memory_dump_access(pool.get_ref(), &dump_id, user_id).await?;

    // Convert input to MemoryProcess
    let processes: Vec<MemoryProcess> = body.processes.iter().map(|p| {
        MemoryProcess {
            pid: p.pid,
            ppid: p.ppid,
            name: p.name.clone(),
            path: p.path.clone(),
            cmdline: p.cmdline.clone(),
            create_time: p.create_time.as_ref().and_then(|t| DateTime::parse_from_rfc3339(t).ok()).map(|t| t.with_timezone(&Utc)),
            exit_time: None,
            threads: p.threads.unwrap_or(0),
            handles: p.handles.unwrap_or(0),
            wow64: p.wow64.unwrap_or(false),
            is_hidden: p.is_hidden.unwrap_or(false),
            is_suspicious: false,
            suspicion_reasons: vec![],
        }
    }).collect();

    let analyzer = MemoryAnalyzer::new();
    let result = analyzer.analyze_processes(processes);

    Ok(HttpResponse::Ok().json(result))
}

/// POST /api/forensics/memory/{id}/connections - Analyze connections from memory dump
#[utoipa::path(
    post,
    path = "/api/forensics/memory/{id}/connections",
    tag = "Digital Forensics",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "Memory dump ID")
    ),
    request_body = AnalyzeConnectionsRequest,
    responses(
        (status = 200, description = "Connection analysis result"),
        (status = 404, description = "Memory dump not found"),
        (status = 401, description = "Unauthorized")
    )
)]
pub async fn analyze_memory_connections(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
    body: web::Json<AnalyzeConnectionsRequest>,
) -> Result<HttpResponse> {
    let dump_id = path.into_inner();
    let user_id = &claims.sub;

    verify_memory_dump_access(pool.get_ref(), &dump_id, user_id).await?;

    let connections: Vec<MemoryConnection> = body.connections.iter().map(|c| {
        use crate::forensics::memory::ConnectionState;
        MemoryConnection {
            protocol: c.protocol.clone(),
            local_address: c.local_address.clone(),
            local_port: c.local_port,
            remote_address: c.remote_address.clone(),
            remote_port: c.remote_port,
            state: ConnectionState::from_str(&c.state),
            pid: c.pid,
            process_name: c.process_name.clone(),
            is_suspicious: false,
            suspicion_reasons: vec![],
        }
    }).collect();

    let analyzer = MemoryAnalyzer::new();
    let result = analyzer.analyze_connections(connections);

    Ok(HttpResponse::Ok().json(result))
}

/// POST /api/forensics/memory/{id}/strings - Analyze strings from memory dump
#[utoipa::path(
    post,
    path = "/api/forensics/memory/{id}/strings",
    tag = "Digital Forensics",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "Memory dump ID")
    ),
    request_body = AnalyzeStringsRequest,
    responses(
        (status = 200, description = "String analysis result"),
        (status = 404, description = "Memory dump not found"),
        (status = 401, description = "Unauthorized")
    )
)]
pub async fn analyze_memory_strings(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
    body: web::Json<AnalyzeStringsRequest>,
) -> Result<HttpResponse> {
    let dump_id = path.into_inner();
    let user_id = &claims.sub;

    verify_memory_dump_access(pool.get_ref(), &dump_id, user_id).await?;

    let strings: Vec<MemoryString> = body.strings.iter().map(|s| {
        MemoryString {
            offset: s.offset,
            value: s.value.clone(),
            category: StringCategory::All,
            encoding: s.encoding.clone().unwrap_or_else(|| "utf-8".to_string()),
            pid: s.pid,
            is_suspicious: false,
        }
    }).collect();

    let filter = body.filter_category.as_ref().map(|c| StringCategory::from_str(c));
    let analyzer = MemoryAnalyzer::new();
    let result = analyzer.analyze_strings(strings, filter, body.min_length);

    Ok(HttpResponse::Ok().json(result))
}

// =============================================================================
// Disk Analysis Endpoints
// =============================================================================

/// POST /api/forensics/cases/{id}/disk - Register a disk image
#[utoipa::path(
    post,
    path = "/api/forensics/cases/{id}/disk",
    tag = "Digital Forensics",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "Case ID")
    ),
    request_body = RegisterDiskImageRequest,
    responses(
        (status = 201, description = "Disk image registered", body = DiskImageResponse),
        (status = 404, description = "Case not found"),
        (status = 401, description = "Unauthorized")
    )
)]
pub async fn register_disk_image(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
    body: web::Json<RegisterDiskImageRequest>,
) -> Result<HttpResponse> {
    let case_id = path.into_inner();
    let user_id = &claims.sub;

    verify_case_access(pool.get_ref(), &case_id, user_id).await?;

    let image_id = Uuid::new_v4().to_string();
    let now = Utc::now();
    let collected_at = body.collected_at.clone().unwrap_or_else(|| now.to_rfc3339());
    let image_type = body.image_type.as_ref()
        .map(|t| DiskImageType::from_str(t))
        .unwrap_or(DiskImageType::Raw);

    sqlx::query(
        r#"
        INSERT INTO disk_images (id, case_id, filename, file_hash, file_size, image_type, collected_at, analysis_status, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?)
        "#,
    )
    .bind(&image_id)
    .bind(&case_id)
    .bind(&body.filename)
    .bind(&body.file_hash)
    .bind(body.file_size)
    .bind(image_type.as_str())
    .bind(&collected_at)
    .bind(now.to_rfc3339())
    .execute(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to register disk image: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to register disk image")
    })?;

    Ok(HttpResponse::Created().json(DiskImageResponse {
        id: image_id,
        case_id,
        filename: body.filename.clone(),
        file_hash: body.file_hash.clone(),
        file_size: body.file_size,
        image_type: image_type.as_str().to_string(),
        collected_at,
        analysis_status: "pending".to_string(),
        findings_json: None,
    }))
}

/// POST /api/forensics/disk/{id}/timeline - Build file system timeline
#[utoipa::path(
    post,
    path = "/api/forensics/disk/{id}/timeline",
    tag = "Digital Forensics",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "Disk image ID")
    ),
    request_body = BuildTimelineRequest,
    responses(
        (status = 200, description = "Timeline result"),
        (status = 404, description = "Disk image not found"),
        (status = 401, description = "Unauthorized")
    )
)]
pub async fn build_disk_timeline(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
    body: web::Json<BuildTimelineRequest>,
) -> Result<HttpResponse> {
    let image_id = path.into_inner();
    let user_id = &claims.sub;

    verify_disk_image_access(pool.get_ref(), &image_id, user_id).await?;

    let files: Vec<FileEntry> = body.files.iter().map(|f| {
        FileEntry {
            path: f.path.clone(),
            name: f.name.clone(),
            size: f.size,
            created: f.created.as_ref().and_then(|t| DateTime::parse_from_rfc3339(t).ok()).map(|t| t.with_timezone(&Utc)),
            modified: f.modified.as_ref().and_then(|t| DateTime::parse_from_rfc3339(t).ok()).map(|t| t.with_timezone(&Utc)),
            accessed: f.accessed.as_ref().and_then(|t| DateTime::parse_from_rfc3339(t).ok()).map(|t| t.with_timezone(&Utc)),
            changed: None,
            is_directory: f.is_directory.unwrap_or(false),
            is_deleted: f.is_deleted.unwrap_or(false),
            is_hidden: false,
            is_system: false,
            extension: f.name.split('.').last().map(|s| s.to_string()),
            mft_entry_number: f.mft_entry_number,
            parent_mft_entry: None,
            attributes: vec![],
        }
    }).collect();

    let start_time = body.start_time.as_ref().and_then(|t| DateTime::parse_from_rfc3339(t).ok()).map(|t| t.with_timezone(&Utc));
    let end_time = body.end_time.as_ref().and_then(|t| DateTime::parse_from_rfc3339(t).ok()).map(|t| t.with_timezone(&Utc));

    let analyzer = DiskAnalyzer::new();
    let result = analyzer.build_timeline(files, start_time, end_time);

    Ok(HttpResponse::Ok().json(result))
}

/// POST /api/forensics/disk/{id}/artifacts - Analyze disk artifacts
#[utoipa::path(
    post,
    path = "/api/forensics/disk/{id}/artifacts",
    tag = "Digital Forensics",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "Disk image ID")
    ),
    request_body = AnalyzeDiskArtifactsRequest,
    responses(
        (status = 200, description = "Artifact analysis result"),
        (status = 404, description = "Disk image not found"),
        (status = 401, description = "Unauthorized")
    )
)]
pub async fn analyze_disk_artifacts(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
    body: web::Json<AnalyzeDiskArtifactsRequest>,
) -> Result<HttpResponse> {
    let image_id = path.into_inner();
    let user_id = &claims.sub;

    verify_disk_image_access(pool.get_ref(), &image_id, user_id).await?;

    let analyzer = DiskAnalyzer::new();

    match body.artifact_type.as_str() {
        "browser" => {
            use crate::forensics::disk::BrowserType;

            let history: Vec<BrowserHistoryEntry> = body.browser_history.iter().map(|h| {
                BrowserHistoryEntry {
                    browser: BrowserType::Chrome, // Default, could parse from h.browser
                    url: h.url.clone(),
                    title: h.title.clone(),
                    visit_time: DateTime::parse_from_rfc3339(&h.visit_time)
                        .map(|t| t.with_timezone(&Utc))
                        .unwrap_or_else(|_| Utc::now()),
                    visit_count: h.visit_count.unwrap_or(1),
                    from_visit: None,
                    transition_type: None,
                }
            }).collect();

            let downloads: Vec<BrowserDownload> = body.browser_downloads.iter().map(|d| {
                BrowserDownload {
                    browser: BrowserType::Chrome,
                    url: d.url.clone(),
                    target_path: d.target_path.clone(),
                    filename: d.filename.clone(),
                    start_time: DateTime::parse_from_rfc3339(&d.start_time)
                        .map(|t| t.with_timezone(&Utc))
                        .unwrap_or_else(|_| Utc::now()),
                    end_time: None,
                    received_bytes: d.received_bytes,
                    total_bytes: d.total_bytes,
                    danger_type: None,
                    mime_type: None,
                }
            }).collect();

            let cookies: Vec<BrowserCookie> = body.browser_cookies.iter().map(|c| {
                BrowserCookie {
                    browser: BrowserType::Chrome,
                    host: c.host.clone(),
                    name: c.name.clone(),
                    path: c.path.clone(),
                    value: None,
                    creation_time: DateTime::parse_from_rfc3339(&c.creation_time)
                        .map(|t| t.with_timezone(&Utc))
                        .unwrap_or_else(|_| Utc::now()),
                    last_access_time: DateTime::parse_from_rfc3339(&c.last_access_time)
                        .map(|t| t.with_timezone(&Utc))
                        .unwrap_or_else(|_| Utc::now()),
                    expiry_time: None,
                    is_secure: c.is_secure.unwrap_or(false),
                    is_http_only: c.is_http_only.unwrap_or(false),
                }
            }).collect();

            let result = analyzer.analyze_browser_artifacts(history, downloads, cookies);
            Ok(HttpResponse::Ok().json(result))
        }
        "prefetch" => {
            use crate::forensics::disk::PrefetchEntry;

            let entries: Vec<PrefetchEntry> = body.prefetch_entries.iter().map(|p| {
                PrefetchEntry {
                    filename: p.filename.clone(),
                    executable_name: p.executable_name.clone(),
                    hash: p.hash.clone(),
                    run_count: p.run_count,
                    last_run_time: DateTime::parse_from_rfc3339(&p.last_run_time)
                        .map(|t| t.with_timezone(&Utc))
                        .unwrap_or_else(|_| Utc::now()),
                    previous_run_times: vec![],
                    created: Utc::now(),
                    modified: Utc::now(),
                    file_references: p.file_references.clone(),
                    volume_info: vec![],
                }
            }).collect();

            let result = analyzer.analyze_prefetch(entries);
            Ok(HttpResponse::Ok().json(result))
        }
        "deleted" => {
            use crate::forensics::disk::{DeletedFile, RecoveryStatus};

            let files: Vec<DeletedFile> = body.deleted_files.iter().map(|f| {
                DeletedFile {
                    path: f.path.clone(),
                    name: f.name.clone(),
                    size: f.size,
                    deleted_time: f.deleted_time.as_ref().and_then(|t| DateTime::parse_from_rfc3339(t).ok()).map(|t| t.with_timezone(&Utc)),
                    original_location: f.original_location.clone(),
                    recovery_status: f.recovery_status.as_ref()
                        .map(|s| match s.as_str() {
                            "fully_recoverable" => RecoveryStatus::FullyRecoverable,
                            "partially_recoverable" => RecoveryStatus::PartiallyRecoverable,
                            "overwritten" => RecoveryStatus::Overwritten,
                            _ => RecoveryStatus::Unknown,
                        })
                        .unwrap_or(RecoveryStatus::Unknown),
                    cluster_range: None,
                    mft_entry: None,
                    file_signature: None,
                }
            }).collect();

            let result = analyzer.analyze_deleted_files(files);
            Ok(HttpResponse::Ok().json(result))
        }
        _ => {
            Err(actix_web::error::ErrorBadRequest("Invalid artifact type"))
        }
    }
}

// =============================================================================
// PCAP Analysis Endpoints
// =============================================================================

/// POST /api/forensics/cases/{id}/pcap - Register a PCAP file
#[utoipa::path(
    post,
    path = "/api/forensics/cases/{id}/pcap",
    tag = "Digital Forensics",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "Case ID")
    ),
    request_body = RegisterPcapRequest,
    responses(
        (status = 201, description = "PCAP file registered", body = PcapFileResponse),
        (status = 404, description = "Case not found"),
        (status = 401, description = "Unauthorized")
    )
)]
pub async fn register_pcap(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
    body: web::Json<RegisterPcapRequest>,
) -> Result<HttpResponse> {
    let case_id = path.into_inner();
    let user_id = &claims.sub;

    verify_case_access(pool.get_ref(), &case_id, user_id).await?;

    let pcap_id = Uuid::new_v4().to_string();
    let now = Utc::now();

    sqlx::query(
        r#"
        INSERT INTO pcap_files (id, case_id, filename, file_hash, file_size, capture_start, capture_end, packet_count, analysis_status, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?)
        "#,
    )
    .bind(&pcap_id)
    .bind(&case_id)
    .bind(&body.filename)
    .bind(&body.file_hash)
    .bind(body.file_size)
    .bind(&body.capture_start)
    .bind(&body.capture_end)
    .bind(body.packet_count.unwrap_or(0))
    .bind(now.to_rfc3339())
    .execute(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to register PCAP: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to register PCAP")
    })?;

    Ok(HttpResponse::Created().json(PcapFileResponse {
        id: pcap_id,
        case_id,
        filename: body.filename.clone(),
        file_hash: body.file_hash.clone(),
        file_size: body.file_size,
        capture_start: body.capture_start.clone(),
        capture_end: body.capture_end.clone(),
        packet_count: body.packet_count.unwrap_or(0),
        analysis_status: "pending".to_string(),
        findings_json: None,
    }))
}

/// POST /api/forensics/pcap/{id}/stats - Get protocol statistics
#[utoipa::path(
    post,
    path = "/api/forensics/pcap/{id}/stats",
    tag = "Digital Forensics",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "PCAP file ID")
    ),
    responses(
        (status = 200, description = "Protocol statistics"),
        (status = 404, description = "PCAP not found"),
        (status = 401, description = "Unauthorized")
    )
)]
pub async fn get_pcap_stats(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let pcap_id = path.into_inner();
    let user_id = &claims.sub;

    verify_pcap_access(pool.get_ref(), &pcap_id, user_id).await?;

    // Return default stats - in real implementation would parse from findings_json
    let stats = ProtocolStats::default();
    Ok(HttpResponse::Ok().json(stats))
}

/// POST /api/forensics/pcap/{id}/connections - Analyze PCAP connections
#[utoipa::path(
    post,
    path = "/api/forensics/pcap/{id}/connections",
    tag = "Digital Forensics",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "PCAP file ID")
    ),
    request_body = AnalyzePcapConnectionsRequest,
    responses(
        (status = 200, description = "Connection analysis result"),
        (status = 404, description = "PCAP not found"),
        (status = 401, description = "Unauthorized")
    )
)]
pub async fn analyze_pcap_connections(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
    body: web::Json<AnalyzePcapConnectionsRequest>,
) -> Result<HttpResponse> {
    let pcap_id = path.into_inner();
    let user_id = &claims.sub;

    verify_pcap_access(pool.get_ref(), &pcap_id, user_id).await?;

    let connections: Vec<ConnectionSummary> = body.connections.iter().map(|c| {
        ConnectionSummary {
            src_ip: c.src_ip.clone(),
            src_port: c.src_port,
            dst_ip: c.dst_ip.clone(),
            dst_port: c.dst_port,
            protocol: c.protocol.clone(),
            packet_count: c.packet_count,
            bytes_sent: c.bytes_sent,
            bytes_received: c.bytes_received,
            first_seen: DateTime::parse_from_rfc3339(&c.first_seen)
                .map(|t| t.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            last_seen: DateTime::parse_from_rfc3339(&c.last_seen)
                .map(|t| t.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            duration_seconds: 0.0,
            tcp_flags: None,
            is_suspicious: false,
            suspicion_reasons: vec![],
        }
    }).collect();

    let analyzer = NetworkAnalyzer::new();
    let result = analyzer.analyze_connections(connections);

    Ok(HttpResponse::Ok().json(result))
}

/// POST /api/forensics/pcap/{id}/dns - Analyze DNS queries
#[utoipa::path(
    post,
    path = "/api/forensics/pcap/{id}/dns",
    tag = "Digital Forensics",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "PCAP file ID")
    ),
    request_body = AnalyzeDnsRequest,
    responses(
        (status = 200, description = "DNS analysis result"),
        (status = 404, description = "PCAP not found"),
        (status = 401, description = "Unauthorized")
    )
)]
pub async fn analyze_pcap_dns(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
    body: web::Json<AnalyzeDnsRequest>,
) -> Result<HttpResponse> {
    let pcap_id = path.into_inner();
    let user_id = &claims.sub;

    verify_pcap_access(pool.get_ref(), &pcap_id, user_id).await?;

    use crate::forensics::network::DnsQueryType;

    let queries: Vec<DnsQuery> = body.queries.iter().map(|q| {
        DnsQuery {
            timestamp: DateTime::parse_from_rfc3339(&q.timestamp)
                .map(|t| t.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            src_ip: q.src_ip.clone(),
            dst_ip: q.dst_ip.clone(),
            query_name: q.query_name.clone(),
            query_type: DnsQueryType::from_str(&q.query_type),
            transaction_id: 0,
            is_response: q.is_response.unwrap_or(false),
            response_code: q.response_code.clone(),
            answers: vec![],
            is_suspicious: false,
            suspicion_reasons: vec![],
        }
    }).collect();

    let analyzer = NetworkAnalyzer::new();
    let result = analyzer.analyze_dns(queries);

    Ok(HttpResponse::Ok().json(result))
}

// =============================================================================
// Artifact Management Endpoints
// =============================================================================

/// POST /api/forensics/cases/{id}/artifacts - Add an artifact
#[utoipa::path(
    post,
    path = "/api/forensics/cases/{id}/artifacts",
    tag = "Digital Forensics",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "Case ID")
    ),
    request_body = AddArtifactRequest,
    responses(
        (status = 201, description = "Artifact added", body = ArtifactResponse),
        (status = 404, description = "Case not found"),
        (status = 401, description = "Unauthorized")
    )
)]
pub async fn add_artifact(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
    body: web::Json<AddArtifactRequest>,
) -> Result<HttpResponse> {
    let case_id = path.into_inner();
    let user_id = &claims.sub;

    verify_case_access(pool.get_ref(), &case_id, user_id).await?;

    let artifact_id = Uuid::new_v4().to_string();
    let now = Utc::now();
    let collected_at = body.collected_at.clone().unwrap_or_else(|| now.to_rfc3339());
    let tags_json = serde_json::to_string(&body.tags.clone().unwrap_or_default()).unwrap_or_else(|_| "[]".to_string());
    let metadata_json = body.metadata.as_ref().map(|m| serde_json::to_string(m).unwrap_or_else(|_| "{}".to_string()));

    sqlx::query(
        r#"
        INSERT INTO forensic_artifacts (id, case_id, artifact_type, source_path, content_hash, collected_at, analysis_notes, tags, metadata, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&artifact_id)
    .bind(&case_id)
    .bind(&body.artifact_type)
    .bind(&body.source_path)
    .bind(&body.content_hash)
    .bind(&collected_at)
    .bind(&body.analysis_notes)
    .bind(&tags_json)
    .bind(&metadata_json)
    .bind(now.to_rfc3339())
    .execute(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to add artifact: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to add artifact")
    })?;

    Ok(HttpResponse::Created().json(ArtifactResponse {
        id: artifact_id,
        case_id,
        artifact_type: body.artifact_type.clone(),
        source_path: body.source_path.clone(),
        content_hash: body.content_hash.clone(),
        collected_at,
        analysis_notes: body.analysis_notes.clone(),
        tags: body.tags.clone().unwrap_or_default(),
        metadata: body.metadata.clone(),
    }))
}

/// GET /api/forensics/cases/{id}/artifacts - List artifacts
#[utoipa::path(
    get,
    path = "/api/forensics/cases/{id}/artifacts",
    tag = "Digital Forensics",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "Case ID"),
        ("artifact_type" = Option<String>, Query, description = "Filter by type"),
        ("limit" = Option<i32>, Query, description = "Limit"),
        ("offset" = Option<i32>, Query, description = "Offset")
    ),
    responses(
        (status = 200, description = "List of artifacts"),
        (status = 404, description = "Case not found"),
        (status = 401, description = "Unauthorized")
    )
)]
pub async fn list_artifacts(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
    query: web::Query<ListArtifactsQuery>,
) -> Result<HttpResponse> {
    let case_id = path.into_inner();
    let user_id = &claims.sub;

    verify_case_access(pool.get_ref(), &case_id, user_id).await?;

    let limit = query.limit.unwrap_or(50);
    let offset = query.offset.unwrap_or(0);

    let mut sql = "SELECT id, case_id, artifact_type, source_path, content_hash, collected_at, analysis_notes, tags, metadata FROM forensic_artifacts WHERE case_id = ?".to_string();

    if let Some(ref artifact_type) = query.artifact_type {
        sql.push_str(&format!(" AND artifact_type = '{}'", artifact_type));
    }

    sql.push_str(" ORDER BY collected_at DESC LIMIT ? OFFSET ?");

    let artifacts: Vec<(String, String, String, String, String, String, Option<String>, String, Option<String>)> = sqlx::query_as(&sql)
        .bind(&case_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool.get_ref())
        .await
        .map_err(|e| {
            log::error!("Failed to list artifacts: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to list artifacts")
        })?;

    let responses: Vec<ArtifactResponse> = artifacts.into_iter().map(|(id, case_id, artifact_type, source_path, content_hash, collected_at, analysis_notes, tags, metadata)| {
        ArtifactResponse {
            id,
            case_id,
            artifact_type,
            source_path,
            content_hash,
            collected_at,
            analysis_notes,
            tags: serde_json::from_str(&tags).unwrap_or_default(),
            metadata: metadata.and_then(|m| serde_json::from_str(&m).ok()),
        }
    }).collect();

    Ok(HttpResponse::Ok().json(responses))
}

// =============================================================================
// Timeline Endpoints
// =============================================================================

/// GET /api/forensics/cases/{id}/timeline - Get combined timeline
#[utoipa::path(
    get,
    path = "/api/forensics/cases/{id}/timeline",
    tag = "Digital Forensics",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "Case ID"),
        ("start_time" = Option<String>, Query, description = "Start time filter"),
        ("end_time" = Option<String>, Query, description = "End time filter"),
        ("event_type" = Option<String>, Query, description = "Event type filter"),
        ("limit" = Option<i32>, Query, description = "Limit"),
        ("offset" = Option<i32>, Query, description = "Offset")
    ),
    responses(
        (status = 200, description = "Timeline events"),
        (status = 404, description = "Case not found"),
        (status = 401, description = "Unauthorized")
    )
)]
pub async fn get_timeline(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
    query: web::Query<TimelineQuery>,
) -> Result<HttpResponse> {
    let case_id = path.into_inner();
    let user_id = &claims.sub;

    verify_case_access(pool.get_ref(), &case_id, user_id).await?;

    let limit = query.limit.unwrap_or(100);
    let offset = query.offset.unwrap_or(0);

    let mut sql = "SELECT id, case_id, timestamp, event_type, source, description, artifact_id FROM forensic_timeline WHERE case_id = ?".to_string();

    if let Some(ref start_time) = query.start_time {
        sql.push_str(&format!(" AND timestamp >= '{}'", start_time));
    }

    if let Some(ref end_time) = query.end_time {
        sql.push_str(&format!(" AND timestamp <= '{}'", end_time));
    }

    if let Some(ref event_type) = query.event_type {
        sql.push_str(&format!(" AND event_type = '{}'", event_type));
    }

    sql.push_str(" ORDER BY timestamp ASC LIMIT ? OFFSET ?");

    let events: Vec<(String, String, String, String, String, String, Option<String>)> = sqlx::query_as(&sql)
        .bind(&case_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool.get_ref())
        .await
        .map_err(|e| {
            log::error!("Failed to get timeline: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to get timeline")
        })?;

    let responses: Vec<TimelineEventResponse> = events.into_iter().map(|(id, case_id, timestamp, event_type, source, description, artifact_id)| {
        TimelineEventResponse {
            id,
            case_id,
            timestamp,
            event_type,
            source,
            description,
            artifact_id,
        }
    }).collect();

    Ok(HttpResponse::Ok().json(responses))
}

// =============================================================================
// Findings Endpoints
// =============================================================================

/// POST /api/forensics/cases/{id}/findings - Add a finding
#[utoipa::path(
    post,
    path = "/api/forensics/cases/{id}/findings",
    tag = "Digital Forensics",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "Case ID")
    ),
    request_body = AddFindingRequest,
    responses(
        (status = 201, description = "Finding added", body = FindingResponse),
        (status = 404, description = "Case not found"),
        (status = 401, description = "Unauthorized")
    )
)]
pub async fn add_finding(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
    body: web::Json<AddFindingRequest>,
) -> Result<HttpResponse> {
    let case_id = path.into_inner();
    let user_id = &claims.sub;

    verify_case_access(pool.get_ref(), &case_id, user_id).await?;

    let finding_id = Uuid::new_v4().to_string();
    let now = Utc::now();
    let evidence_refs_json = serde_json::to_string(&body.evidence_refs.clone().unwrap_or_default()).unwrap_or_else(|_| "[]".to_string());

    sqlx::query(
        r#"
        INSERT INTO forensic_findings (id, case_id, finding_type, severity, title, description, evidence_refs, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&finding_id)
    .bind(&case_id)
    .bind(&body.finding_type)
    .bind(&body.severity)
    .bind(&body.title)
    .bind(&body.description)
    .bind(&evidence_refs_json)
    .bind(now.to_rfc3339())
    .execute(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to add finding: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to add finding")
    })?;

    Ok(HttpResponse::Created().json(FindingResponse {
        id: finding_id,
        case_id,
        finding_type: body.finding_type.clone(),
        severity: body.severity.clone(),
        title: body.title.clone(),
        description: body.description.clone(),
        evidence_refs: body.evidence_refs.clone().unwrap_or_default(),
        created_at: now.to_rfc3339(),
    }))
}

/// GET /api/forensics/cases/{id}/findings - List findings
#[utoipa::path(
    get,
    path = "/api/forensics/cases/{id}/findings",
    tag = "Digital Forensics",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "Case ID"),
        ("finding_type" = Option<String>, Query, description = "Filter by type"),
        ("severity" = Option<String>, Query, description = "Filter by severity"),
        ("limit" = Option<i32>, Query, description = "Limit"),
        ("offset" = Option<i32>, Query, description = "Offset")
    ),
    responses(
        (status = 200, description = "List of findings"),
        (status = 404, description = "Case not found"),
        (status = 401, description = "Unauthorized")
    )
)]
pub async fn list_findings(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
    query: web::Query<FindingsQuery>,
) -> Result<HttpResponse> {
    let case_id = path.into_inner();
    let user_id = &claims.sub;

    verify_case_access(pool.get_ref(), &case_id, user_id).await?;

    let limit = query.limit.unwrap_or(50);
    let offset = query.offset.unwrap_or(0);

    let mut sql = "SELECT id, case_id, finding_type, severity, title, description, evidence_refs, created_at FROM forensic_findings WHERE case_id = ?".to_string();

    if let Some(ref finding_type) = query.finding_type {
        sql.push_str(&format!(" AND finding_type = '{}'", finding_type));
    }

    if let Some(ref severity) = query.severity {
        sql.push_str(&format!(" AND severity = '{}'", severity));
    }

    sql.push_str(" ORDER BY created_at DESC LIMIT ? OFFSET ?");

    let findings: Vec<(String, String, String, String, String, String, String, String)> = sqlx::query_as(&sql)
        .bind(&case_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool.get_ref())
        .await
        .map_err(|e| {
            log::error!("Failed to list findings: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to list findings")
        })?;

    let responses: Vec<FindingResponse> = findings.into_iter().map(|(id, case_id, finding_type, severity, title, description, evidence_refs, created_at)| {
        FindingResponse {
            id,
            case_id,
            finding_type,
            severity,
            title,
            description,
            evidence_refs: serde_json::from_str(&evidence_refs).unwrap_or_default(),
            created_at,
        }
    }).collect();

    Ok(HttpResponse::Ok().json(responses))
}

// =============================================================================
// Artifact Templates Endpoint
// =============================================================================

/// GET /api/forensics/templates/{os} - Get artifact collection template for OS
#[utoipa::path(
    get,
    path = "/api/forensics/templates/{os}",
    tag = "Digital Forensics",
    security(("bearer_auth" = [])),
    params(
        ("os" = String, Path, description = "Operating system (windows, linux, browser)")
    ),
    responses(
        (status = 200, description = "Collection template", body = ArtifactTemplateResponse),
        (status = 400, description = "Invalid OS"),
        (status = 401, description = "Unauthorized")
    )
)]
pub async fn get_artifact_template(
    _claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let os = path.into_inner();
    let collector = ArtifactCollector::new();

    let template = match os.to_lowercase().as_str() {
        "windows" => crate::forensics::artifacts::get_windows_collection_template(),
        "linux" => crate::forensics::artifacts::get_linux_collection_template(),
        "browser" => crate::forensics::artifacts::get_browser_collection_template(),
        _ => return Err(actix_web::error::ErrorBadRequest("Invalid operating system")),
    };

    let response = ArtifactTemplateResponse {
        operating_system: template.operating_system.as_str().to_string(),
        name: template.name,
        description: template.description,
        artifacts: template.artifacts.into_iter().map(|a| {
            ArtifactPathResponse {
                category: a.category.as_str().to_string(),
                path: a.path,
                description: a.description,
                is_directory: a.is_directory,
                recursive: a.recursive,
                file_pattern: a.file_pattern,
                forensic_value: a.forensic_value,
            }
        }).collect(),
    };

    Ok(HttpResponse::Ok().json(response))
}

// =============================================================================
// Helper Functions
// =============================================================================

async fn verify_case_access(pool: &SqlitePool, case_id: &str, user_id: &str) -> Result<()> {
    let exists: Option<(i64,)> = sqlx::query_as(
        "SELECT 1 FROM forensic_cases WHERE id = ? AND user_id = ?"
    )
    .bind(case_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| {
        log::error!("Failed to verify case access: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to verify case access")
    })?;

    if exists.is_none() {
        return Err(actix_web::error::ErrorNotFound("Case not found"));
    }

    Ok(())
}

async fn verify_memory_dump_access(pool: &SqlitePool, dump_id: &str, user_id: &str) -> Result<()> {
    let exists: Option<(i64,)> = sqlx::query_as(
        r#"
        SELECT 1 FROM memory_dumps md
        JOIN forensic_cases fc ON md.case_id = fc.id
        WHERE md.id = ? AND fc.user_id = ?
        "#
    )
    .bind(dump_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| {
        log::error!("Failed to verify memory dump access: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to verify access")
    })?;

    if exists.is_none() {
        return Err(actix_web::error::ErrorNotFound("Memory dump not found"));
    }

    Ok(())
}

async fn verify_disk_image_access(pool: &SqlitePool, image_id: &str, user_id: &str) -> Result<()> {
    let exists: Option<(i64,)> = sqlx::query_as(
        r#"
        SELECT 1 FROM disk_images di
        JOIN forensic_cases fc ON di.case_id = fc.id
        WHERE di.id = ? AND fc.user_id = ?
        "#
    )
    .bind(image_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| {
        log::error!("Failed to verify disk image access: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to verify access")
    })?;

    if exists.is_none() {
        return Err(actix_web::error::ErrorNotFound("Disk image not found"));
    }

    Ok(())
}

async fn verify_pcap_access(pool: &SqlitePool, pcap_id: &str, user_id: &str) -> Result<()> {
    let exists: Option<(i64,)> = sqlx::query_as(
        r#"
        SELECT 1 FROM pcap_files pf
        JOIN forensic_cases fc ON pf.case_id = fc.id
        WHERE pf.id = ? AND fc.user_id = ?
        "#
    )
    .bind(pcap_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| {
        log::error!("Failed to verify PCAP access: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to verify access")
    })?;

    if exists.is_none() {
        return Err(actix_web::error::ErrorNotFound("PCAP file not found"));
    }

    Ok(())
}

// =============================================================================
// Route Configuration
// =============================================================================

/// Configure forensics routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/forensics")
            // Case management
            .route("/cases", web::post().to(create_case))
            .route("/cases", web::get().to(list_cases))
            .route("/cases/{id}", web::get().to(get_case))
            .route("/cases/{id}", web::put().to(update_case))
            // Memory analysis
            .route("/cases/{id}/memory", web::post().to(register_memory_dump))
            .route("/memory/{id}/processes", web::post().to(analyze_memory_processes))
            .route("/memory/{id}/connections", web::post().to(analyze_memory_connections))
            .route("/memory/{id}/strings", web::post().to(analyze_memory_strings))
            // Disk analysis
            .route("/cases/{id}/disk", web::post().to(register_disk_image))
            .route("/disk/{id}/timeline", web::post().to(build_disk_timeline))
            .route("/disk/{id}/artifacts", web::post().to(analyze_disk_artifacts))
            // PCAP analysis
            .route("/cases/{id}/pcap", web::post().to(register_pcap))
            .route("/pcap/{id}/stats", web::post().to(get_pcap_stats))
            .route("/pcap/{id}/connections", web::post().to(analyze_pcap_connections))
            .route("/pcap/{id}/dns", web::post().to(analyze_pcap_dns))
            // Artifacts
            .route("/cases/{id}/artifacts", web::post().to(add_artifact))
            .route("/cases/{id}/artifacts", web::get().to(list_artifacts))
            // Timeline
            .route("/cases/{id}/timeline", web::get().to(get_timeline))
            // Findings
            .route("/cases/{id}/findings", web::post().to(add_finding))
            .route("/cases/{id}/findings", web::get().to(list_findings))
            // Templates
            .route("/templates/{os}", web::get().to(get_artifact_template))
    );
}
