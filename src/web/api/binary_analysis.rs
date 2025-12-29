//! Binary Analysis API
//!
//! Provides endpoints for analyzing PE/ELF binaries, including:
//! - Binary upload and analysis
//! - Hash lookup and comparison
//! - String extraction
//! - Hex dump viewing
//! - Packer detection

use actix_multipart::Multipart;
use actix_web::{web, HttpResponse};
use anyhow::Result;
use chrono::Utc;
use futures::{StreamExt, TryStreamExt};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use uuid::Uuid;

use crate::binary_analysis::{
    BinaryAnalyzer, BinarySample, BinarySampleSummary, AnalysisConfig,
    BinaryType, Architecture, AnalysisStatus, ExtractedString, StringType,
    HexViewResponse, HexViewRequest,
};
use crate::web::auth;
use crate::web::error::ApiError;

/// Binary analysis statistics
#[derive(Debug, Serialize)]
pub struct BinaryAnalysisStats {
    pub total_samples: i64,
    pub pe_samples: i64,
    pub elf_samples: i64,
    pub packed_samples: i64,
    pub pending_analysis: i64,
    pub total_strings_extracted: i64,
    pub unique_packers: i64,
}

/// Sample upload response
#[derive(Debug, Serialize)]
pub struct UploadResponse {
    pub id: String,
    pub filename: String,
    pub sha256: String,
    pub file_type: String,
    pub status: String,
    pub message: String,
}

/// Query parameters for binary upload
#[derive(Debug, Deserialize)]
pub struct UploadQuery {
    pub customer_id: Option<String>,
    pub engagement_id: Option<String>,
}

/// Sample list query params
#[derive(Debug, Deserialize)]
pub struct SampleListQuery {
    pub page: Option<u32>,
    pub limit: Option<u32>,
    pub file_type: Option<String>,
    pub is_packed: Option<bool>,
    pub search: Option<String>,
}

/// String filter query
#[derive(Debug, Deserialize)]
pub struct StringFilterQuery {
    pub string_type: Option<String>,
    pub interesting_only: Option<bool>,
    pub limit: Option<u32>,
    pub search: Option<String>,
}

/// Hash lookup request
#[derive(Debug, Deserialize)]
pub struct HashLookupRequest {
    pub hash: String,
    pub hash_type: Option<String>, // md5, sha1, sha256
}

/// Hash lookup response
#[derive(Debug, Serialize)]
pub struct HashLookupResponse {
    pub found: bool,
    pub sample: Option<SampleSummary>,
}

/// Sample summary for API responses
#[derive(Debug, Clone, Serialize)]
pub struct SampleSummary {
    pub id: String,
    pub filename: String,
    pub file_size: i64,
    pub file_type: String,
    pub architecture: Option<String>,
    pub sha256: String,
    pub entropy: f64,
    pub is_packed: bool,
    pub packer_name: Option<String>,
    pub analysis_status: String,
    pub strings_count: i32,
    pub imports_count: i32,
    pub created_at: String,
}

/// Full sample detail response
#[derive(Debug, Serialize)]
pub struct SampleDetail {
    pub id: String,
    pub filename: String,
    pub file_size: i64,
    pub file_type: String,
    pub architecture: Option<String>,
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
    pub imphash: Option<String>,
    pub ssdeep: Option<String>,
    pub entropy: f64,
    pub is_packed: bool,
    pub packer_name: Option<String>,
    pub packer_version: Option<String>,
    pub packer_confidence: Option<f64>,
    pub analysis_status: String,
    pub strings_count: i32,
    pub imports_count: i32,
    pub exports_count: i32,
    pub sections: Vec<SectionInfo>,
    pub pe_info: Option<PeInfo>,
    pub elf_info: Option<ElfInfo>,
    pub created_at: String,
    pub analyzed_at: Option<String>,
}

/// PE-specific information
#[derive(Debug, Serialize)]
pub struct PeInfo {
    pub machine_type: Option<String>,
    pub subsystem: Option<String>,
    pub is_dll: bool,
    pub is_64bit: bool,
    pub has_debug_info: bool,
    pub has_tls: bool,
    pub has_rich_header: bool,
    pub checksum_valid: bool,
    pub timestamp: Option<String>,
    pub entry_point: Option<i64>,
    pub image_base: Option<i64>,
}

/// ELF-specific information
#[derive(Debug, Serialize)]
pub struct ElfInfo {
    pub machine_type: Option<String>,
    pub elf_type: Option<String>,
    pub os_abi: Option<String>,
    pub is_pie: bool,
    pub has_relro: bool,
    pub has_nx: bool,
    pub has_stack_canary: bool,
    pub interpreter: Option<String>,
    pub entry_point: Option<i64>,
}

/// Section information
#[derive(Debug, Serialize)]
pub struct SectionInfo {
    pub name: String,
    pub virtual_address: i64,
    pub virtual_size: i64,
    pub raw_size: i64,
    pub entropy: f64,
    pub is_executable: bool,
    pub is_writable: bool,
}

/// Import entry
#[derive(Debug, Serialize)]
pub struct ImportEntry {
    pub dll_name: String,
    pub function_name: String,
    pub is_suspicious: bool,
}

/// Configure binary analysis routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/binary-analysis")
            .route("/upload", web::post().to(upload_binary))
            .route("/samples", web::get().to(list_samples))
            .route("/samples/{id}", web::get().to(get_sample))
            .route("/samples/{id}", web::delete().to(delete_sample))
            .route("/samples/{id}/strings", web::get().to(get_strings))
            .route("/samples/{id}/imports", web::get().to(get_imports))
            .route("/samples/{id}/exports", web::get().to(get_exports))
            .route("/samples/{id}/sections", web::get().to(get_sections))
            .route("/samples/{id}/hex", web::get().to(get_hex_view))
            .route("/samples/{id}/reanalyze", web::post().to(reanalyze_sample))
            .route("/lookup", web::post().to(lookup_hash))
            .route("/stats", web::get().to(get_stats))
            .route("/compare", web::post().to(compare_samples)),
    );
}

/// Upload a binary file for analysis
async fn upload_binary(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    query: web::Query<UploadQuery>,
    mut payload: Multipart,
) -> Result<HttpResponse, ApiError> {
    // Extract file from multipart
    let (filename, data) = extract_binary_from_multipart(&mut payload).await?;

    // Check file size (max 100MB)
    if data.len() > 100 * 1024 * 1024 {
        return Err(ApiError::bad_request("File too large. Maximum size is 100MB"));
    }

    // Analyze binary
    let analyzer = BinaryAnalyzer::new();
    let sample = analyzer.analyze_bytes(&data, filename.clone(), &claims.sub)
        .map_err(|e| ApiError::internal(format!("Analysis failed: {}", e)))?;

    // Save to database
    save_sample_to_db(
        pool.get_ref(),
        &sample,
        Some(&data),
        query.customer_id.as_deref(),
        query.engagement_id.as_deref(),
    ).await?;

    Ok(HttpResponse::Ok().json(UploadResponse {
        id: sample.id,
        filename: sample.filename,
        sha256: sample.hashes.sha256,
        file_type: sample.file_type.to_string(),
        status: "completed".to_string(),
        message: "Binary analyzed successfully".to_string(),
    }))
}

/// Extract binary file from multipart upload
async fn extract_binary_from_multipart(payload: &mut Multipart) -> Result<(String, Vec<u8>), ApiError> {
    let mut filename = String::from("unknown");
    let mut content = Vec::new();

    while let Ok(Some(mut field)) = payload.try_next().await {
        if let Some(cd) = field.content_disposition() {
            if let Some(name) = cd.get_filename() {
                filename = name.to_string();
            }
        }

        while let Some(chunk) = field.next().await {
            let data = chunk.map_err(|e| ApiError::bad_request(format!("Failed to read upload: {}", e)))?;
            content.extend_from_slice(&data);
        }
    }

    if content.is_empty() {
        return Err(ApiError::bad_request("No file uploaded"));
    }

    Ok((filename, content))
}

/// Save analyzed sample to database
async fn save_sample_to_db(
    pool: &SqlitePool,
    sample: &BinarySample,
    data: Option<&[u8]>,
    customer_id: Option<&str>,
    engagement_id: Option<&str>,
) -> Result<(), ApiError> {
    // Insert main sample record
    sqlx::query(
        r#"
        INSERT INTO binary_samples (
            id, user_id, filename, file_size, file_type, architecture,
            md5, sha1, sha256, ssdeep, imphash, tlsh, entropy,
            is_packed, packer_name, packer_version, packer_confidence,
            analysis_status, strings_count, imports_count, exports_count,
            pe_machine_type, pe_subsystem, pe_is_dll, pe_is_64bit,
            pe_has_debug_info, pe_has_tls, pe_has_rich_header, pe_checksum_valid,
            pe_timestamp, pe_entry_point, pe_image_base,
            elf_machine_type, elf_type, elf_os_abi, elf_is_pie,
            elf_has_relro, elf_has_nx, elf_has_stack_canary,
            elf_interpreter, elf_entry_point, created_at, analyzed_at,
            customer_id, engagement_id
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#
    )
    .bind(&sample.id)
    .bind(&sample.user_id)
    .bind(&sample.filename)
    .bind(sample.file_size as i64)
    .bind(sample.file_type.to_string())
    .bind(sample.architecture.to_string())
    .bind(&sample.hashes.md5)
    .bind(&sample.hashes.sha1)
    .bind(&sample.hashes.sha256)
    .bind(&sample.hashes.ssdeep)
    .bind(&sample.hashes.imphash)
    .bind(&sample.hashes.tlsh)
    .bind(sample.entropy)
    .bind(sample.is_packed)
    .bind(sample.packer_info.as_ref().map(|p| &p.name))
    .bind(sample.packer_info.as_ref().and_then(|p| p.version.as_ref()))
    .bind(sample.packer_info.as_ref().map(|p| p.confidence))
    .bind("completed")
    .bind(sample.strings_count as i32)
    .bind(sample.imports_count as i32)
    .bind(sample.exports_count as i32)
    // PE fields
    .bind(sample.pe_analysis.as_ref().map(|p| &p.machine_type))
    .bind(sample.pe_analysis.as_ref().map(|p| &p.subsystem))
    .bind(sample.pe_analysis.as_ref().map(|p| p.is_dll))
    .bind(sample.pe_analysis.as_ref().map(|p| p.is_64bit))
    .bind(sample.pe_analysis.as_ref().map(|p| p.has_debug_info))
    .bind(sample.pe_analysis.as_ref().map(|p| p.has_tls))
    .bind(sample.pe_analysis.as_ref().map(|p| p.has_rich_header))
    .bind(sample.pe_analysis.as_ref().map(|p| p.checksum_valid))
    .bind(sample.pe_analysis.as_ref().and_then(|p| p.timestamp.map(|t| t.to_rfc3339())))
    .bind(sample.pe_analysis.as_ref().map(|p| p.entry_point as i64))
    .bind(sample.pe_analysis.as_ref().map(|p| p.image_base as i64))
    // ELF fields
    .bind(sample.elf_analysis.as_ref().map(|e| &e.machine_type))
    .bind(sample.elf_analysis.as_ref().map(|e| &e.elf_type))
    .bind(sample.elf_analysis.as_ref().map(|e| &e.os_abi))
    .bind(sample.elf_analysis.as_ref().map(|e| e.is_pie))
    .bind(sample.elf_analysis.as_ref().map(|e| e.has_relro))
    .bind(sample.elf_analysis.as_ref().map(|e| e.has_nx))
    .bind(sample.elf_analysis.as_ref().map(|e| e.has_stack_canary))
    .bind(sample.elf_analysis.as_ref().and_then(|e| e.interpreter.as_ref()))
    .bind(sample.elf_analysis.as_ref().map(|e| e.entry_point as i64))
    .bind(sample.created_at.to_rfc3339())
    .bind(sample.analyzed_at.map(|t| t.to_rfc3339()))
    .bind(customer_id)
    .bind(engagement_id)
    .execute(pool)
    .await
    .map_err(|e| ApiError::internal(format!("Failed to save sample: {}", e)))?;

    // Save sections
    if let Some(pe) = &sample.pe_analysis {
        for section in &pe.sections {
            let section_id = Uuid::new_v4().to_string();
            sqlx::query(
                r#"
                INSERT INTO binary_sections (id, sample_id, name, virtual_address, virtual_size, raw_size, raw_offset, characteristics, entropy, is_executable, is_writable)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                "#
            )
            .bind(&section_id)
            .bind(&sample.id)
            .bind(&section.name)
            .bind(section.virtual_address as i64)
            .bind(section.virtual_size as i64)
            .bind(section.raw_size as i64)
            .bind(section.raw_offset as i64)
            .bind(section.characteristics as i64)
            .bind(section.entropy)
            .bind(section.is_executable)
            .bind(section.is_writable)
            .execute(pool)
            .await
            .ok(); // Ignore errors for individual sections
        }

        // Save imports
        for import in &pe.imports {
            for func in &import.functions {
                let import_id = Uuid::new_v4().to_string();
                let is_suspicious = is_suspicious_import(&import.dll_name, func);
                sqlx::query(
                    r#"
                    INSERT INTO binary_imports (id, sample_id, dll_name, function_name, is_suspicious)
                    VALUES (?, ?, ?, ?, ?)
                    "#
                )
                .bind(&import_id)
                .bind(&sample.id)
                .bind(&import.dll_name)
                .bind(func)
                .bind(is_suspicious)
                .execute(pool)
                .await
                .ok();
            }
        }

        // Save exports
        for export in &pe.exports {
            let export_id = Uuid::new_v4().to_string();
            sqlx::query(
                r#"
                INSERT INTO binary_exports (id, sample_id, name, ordinal, address)
                VALUES (?, ?, ?, ?, ?)
                "#
            )
            .bind(&export_id)
            .bind(&sample.id)
            .bind(&export.name)
            .bind(export.ordinal as i32)
            .bind(export.address as i64)
            .execute(pool)
            .await
            .ok();
        }
    }

    // Save ELF sections and symbols
    if let Some(elf) = &sample.elf_analysis {
        for section in &elf.sections {
            let section_id = Uuid::new_v4().to_string();
            sqlx::query(
                r#"
                INSERT INTO binary_sections (id, sample_id, name, virtual_address, virtual_size, raw_size, raw_offset, entropy, is_executable, is_writable)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                "#
            )
            .bind(&section_id)
            .bind(&sample.id)
            .bind(&section.name)
            .bind(section.address as i64)
            .bind(section.size as i64)
            .bind(section.size as i64)
            .bind(section.offset as i64)
            .bind(section.entropy)
            .bind(section.is_executable)
            .bind(section.is_writable)
            .execute(pool)
            .await
            .ok();
        }

        for lib in &elf.dynamic_libs {
            let lib_id = Uuid::new_v4().to_string();
            sqlx::query(
                r#"
                INSERT INTO binary_dynamic_libs (id, sample_id, name, path)
                VALUES (?, ?, ?, ?)
                "#
            )
            .bind(&lib_id)
            .bind(&sample.id)
            .bind(&lib.name)
            .bind(&lib.path)
            .execute(pool)
            .await
            .ok();
        }
    }

    // Optionally store the binary data
    if let Some(binary_data) = data {
        let storage_id = Uuid::new_v4().to_string();
        sqlx::query(
            r#"
            INSERT INTO binary_file_storage (id, sample_id, file_data, storage_method)
            VALUES (?, ?, ?, 'raw')
            "#
        )
        .bind(&storage_id)
        .bind(&sample.id)
        .bind(binary_data)
        .execute(pool)
        .await
        .ok(); // Non-critical, ignore errors
    }

    Ok(())
}

/// Check if an import is suspicious (commonly used in malware)
fn is_suspicious_import(dll: &str, func: &str) -> bool {
    let dll_lower = dll.to_lowercase();
    let func_lower = func.to_lowercase();

    let suspicious_functions = [
        "virtualalloc", "virtualprotect", "virtualallocex",
        "createremotethread", "writeprocessmemory", "readprocessmemory",
        "ntallocatevirtualmemory", "ntwritevirtualmemory",
        "createprocess", "shellexecute", "winexec",
        "loadlibrary", "getprocaddress", "freelibrary",
        "regsetvalue", "regcreatekey", "regopenkeyex",
        "internetopen", "internetconnect", "httpsendrequesta",
        "wsastartup", "socket", "connect", "send", "recv",
        "cryptencrypt", "cryptdecrypt", "cryptacquirecontext",
        "adjusttokenprivileges", "lookupprivilegevalue",
        "setwindowshookex", "getasynckeystate", "getforegroundwindow",
        "isdebuggerpresent", "checkremotedebuggerpresent",
        "ntqueryinformationprocess", "ntsetinformationthread",
    ];

    suspicious_functions.iter().any(|s| func_lower.contains(s))
}

/// List binary samples
async fn list_samples(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    query: web::Query<SampleListQuery>,
) -> Result<HttpResponse, ApiError> {
    let page = query.page.unwrap_or(1).max(1);
    let limit = query.limit.unwrap_or(20).min(100);
    let offset = (page - 1) * limit;

    let samples: Vec<SampleSummary> = sqlx::query_as::<_, (String, String, i64, String, Option<String>, String, f64, bool, Option<String>, String, i32, i32, String)>(
        r#"
        SELECT id, filename, file_size, file_type, architecture, sha256, entropy,
               is_packed, packer_name, analysis_status, strings_count, imports_count, created_at
        FROM binary_samples
        WHERE user_id = ?
        ORDER BY created_at DESC
        LIMIT ? OFFSET ?
        "#
    )
    .bind(&claims.sub)
    .bind(limit as i32)
    .bind(offset as i32)
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?
    .into_iter()
    .map(|row| SampleSummary {
        id: row.0,
        filename: row.1,
        file_size: row.2,
        file_type: row.3,
        architecture: row.4,
        sha256: row.5,
        entropy: row.6,
        is_packed: row.7,
        packer_name: row.8,
        analysis_status: row.9,
        strings_count: row.10,
        imports_count: row.11,
        created_at: row.12,
    })
    .collect();

    Ok(HttpResponse::Ok().json(samples))
}

/// Get sample details
async fn get_sample(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    use sqlx::Row;

    let sample_id = path.into_inner();

    let row = sqlx::query(
        r#"
        SELECT id, filename, file_size, file_type, architecture, md5, sha1, sha256,
               ssdeep, imphash, entropy, is_packed, packer_name, packer_version, packer_confidence,
               analysis_status, strings_count, imports_count, exports_count,
               pe_machine_type, pe_subsystem, pe_is_dll, pe_is_64bit, pe_has_debug_info,
               pe_has_tls, pe_has_rich_header, pe_checksum_valid, pe_timestamp, pe_entry_point, pe_image_base,
               elf_machine_type, elf_type, elf_os_abi, elf_is_pie, elf_has_relro,
               elf_has_nx, elf_has_stack_canary, elf_interpreter, elf_entry_point,
               created_at, analyzed_at
        FROM binary_samples
        WHERE id = ? AND user_id = ?
        "#
    )
    .bind(&sample_id)
    .bind(&claims.sub)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?
    .ok_or_else(|| ApiError::not_found("Sample not found"))?;

    // Get sections
    let sections: Vec<SectionInfo> = sqlx::query_as::<_, (String, i64, i64, i64, f64, bool, bool)>(
        r#"
        SELECT name, virtual_address, virtual_size, raw_size, entropy, is_executable, is_writable
        FROM binary_sections
        WHERE sample_id = ?
        ORDER BY virtual_address
        "#
    )
    .bind(&sample_id)
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?
    .into_iter()
    .map(|s| SectionInfo {
        name: s.0,
        virtual_address: s.1,
        virtual_size: s.2,
        raw_size: s.3,
        entropy: s.4,
        is_executable: s.5,
        is_writable: s.6,
    })
    .collect();

    let pe_machine_type: Option<String> = row.get("pe_machine_type");
    let pe_info = if pe_machine_type.is_some() {
        Some(PeInfo {
            machine_type: pe_machine_type,
            subsystem: row.get("pe_subsystem"),
            is_dll: row.get::<Option<bool>, _>("pe_is_dll").unwrap_or(false),
            is_64bit: row.get::<Option<bool>, _>("pe_is_64bit").unwrap_or(false),
            has_debug_info: row.get::<Option<bool>, _>("pe_has_debug_info").unwrap_or(false),
            has_tls: row.get::<Option<bool>, _>("pe_has_tls").unwrap_or(false),
            has_rich_header: row.get::<Option<bool>, _>("pe_has_rich_header").unwrap_or(false),
            checksum_valid: row.get::<Option<bool>, _>("pe_checksum_valid").unwrap_or(false),
            timestamp: row.get("pe_timestamp"),
            entry_point: row.get("pe_entry_point"),
            image_base: row.get("pe_image_base"),
        })
    } else {
        None
    };

    let elf_machine_type: Option<String> = row.get("elf_machine_type");
    let elf_info = if elf_machine_type.is_some() {
        Some(ElfInfo {
            machine_type: elf_machine_type,
            elf_type: row.get("elf_type"),
            os_abi: row.get("elf_os_abi"),
            is_pie: row.get::<Option<bool>, _>("elf_is_pie").unwrap_or(false),
            has_relro: row.get::<Option<bool>, _>("elf_has_relro").unwrap_or(false),
            has_nx: row.get::<Option<bool>, _>("elf_has_nx").unwrap_or(false),
            has_stack_canary: row.get::<Option<bool>, _>("elf_has_stack_canary").unwrap_or(false),
            interpreter: row.get("elf_interpreter"),
            entry_point: row.get("elf_entry_point"),
        })
    } else {
        None
    };

    let detail = SampleDetail {
        id: row.get("id"),
        filename: row.get("filename"),
        file_size: row.get("file_size"),
        file_type: row.get("file_type"),
        architecture: row.get("architecture"),
        md5: row.get("md5"),
        sha1: row.get("sha1"),
        sha256: row.get("sha256"),
        ssdeep: row.get("ssdeep"),
        imphash: row.get("imphash"),
        entropy: row.get("entropy"),
        is_packed: row.get("is_packed"),
        packer_name: row.get("packer_name"),
        packer_version: row.get("packer_version"),
        packer_confidence: row.get("packer_confidence"),
        analysis_status: row.get("analysis_status"),
        strings_count: row.get("strings_count"),
        imports_count: row.get("imports_count"),
        exports_count: row.get("exports_count"),
        sections,
        pe_info,
        elf_info,
        created_at: row.get("created_at"),
        analyzed_at: row.get("analyzed_at"),
    };

    Ok(HttpResponse::Ok().json(detail))
}

/// Delete a sample
async fn delete_sample(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let sample_id = path.into_inner();

    let result = sqlx::query("DELETE FROM binary_samples WHERE id = ? AND user_id = ?")
        .bind(&sample_id)
        .bind(&claims.sub)
        .execute(pool.get_ref())
        .await
        .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?;

    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("Sample not found"));
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Sample deleted successfully"
    })))
}

/// Get extracted strings for a sample
async fn get_strings(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
    query: web::Query<StringFilterQuery>,
) -> Result<HttpResponse, ApiError> {
    let sample_id = path.into_inner();
    let limit = query.limit.unwrap_or(1000).min(5000);

    // Verify ownership
    let exists: Option<(i32,)> = sqlx::query_as(
        "SELECT 1 FROM binary_samples WHERE id = ? AND user_id = ?"
    )
    .bind(&sample_id)
    .bind(&claims.sub)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?;

    if exists.is_none() {
        return Err(ApiError::not_found("Sample not found"));
    }

    let mut sql = String::from(
        "SELECT value, encoding, offset, section_name, string_type, is_interesting
         FROM binary_strings WHERE sample_id = ?"
    );

    if query.interesting_only.unwrap_or(false) {
        sql.push_str(" AND is_interesting = 1");
    }

    if let Some(ref st) = query.string_type {
        sql.push_str(&format!(" AND string_type = '{}'", st));
    }

    sql.push_str(&format!(" LIMIT {}", limit));

    let strings: Vec<(String, String, i64, Option<String>, String, bool)> = sqlx::query_as(&sql)
        .bind(&sample_id)
        .fetch_all(pool.get_ref())
        .await
        .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?;

    let result: Vec<serde_json::Value> = strings.into_iter().map(|s| {
        serde_json::json!({
            "value": s.0,
            "encoding": s.1,
            "offset": s.2,
            "section": s.3,
            "type": s.4,
            "is_interesting": s.5,
        })
    }).collect();

    Ok(HttpResponse::Ok().json(result))
}

/// Get imports for a sample
async fn get_imports(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let sample_id = path.into_inner();

    // Verify ownership
    let exists: Option<(i32,)> = sqlx::query_as(
        "SELECT 1 FROM binary_samples WHERE id = ? AND user_id = ?"
    )
    .bind(&sample_id)
    .bind(&claims.sub)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?;

    if exists.is_none() {
        return Err(ApiError::not_found("Sample not found"));
    }

    let imports: Vec<(String, String, bool)> = sqlx::query_as(
        "SELECT dll_name, function_name, is_suspicious FROM binary_imports WHERE sample_id = ? ORDER BY dll_name, function_name"
    )
    .bind(&sample_id)
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?;

    let result: Vec<ImportEntry> = imports.into_iter().map(|i| ImportEntry {
        dll_name: i.0,
        function_name: i.1,
        is_suspicious: i.2,
    }).collect();

    Ok(HttpResponse::Ok().json(result))
}

/// Get exports for a sample
async fn get_exports(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let sample_id = path.into_inner();

    // Verify ownership
    let exists: Option<(i32,)> = sqlx::query_as(
        "SELECT 1 FROM binary_samples WHERE id = ? AND user_id = ?"
    )
    .bind(&sample_id)
    .bind(&claims.sub)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?;

    if exists.is_none() {
        return Err(ApiError::not_found("Sample not found"));
    }

    let exports: Vec<(String, i32, i64)> = sqlx::query_as(
        "SELECT name, ordinal, address FROM binary_exports WHERE sample_id = ? ORDER BY ordinal"
    )
    .bind(&sample_id)
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?;

    let result: Vec<serde_json::Value> = exports.into_iter().map(|e| {
        serde_json::json!({
            "name": e.0,
            "ordinal": e.1,
            "address": format!("0x{:x}", e.2),
        })
    }).collect();

    Ok(HttpResponse::Ok().json(result))
}

/// Get sections for a sample
async fn get_sections(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let sample_id = path.into_inner();

    // Verify ownership
    let exists: Option<(i32,)> = sqlx::query_as(
        "SELECT 1 FROM binary_samples WHERE id = ? AND user_id = ?"
    )
    .bind(&sample_id)
    .bind(&claims.sub)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?;

    if exists.is_none() {
        return Err(ApiError::not_found("Sample not found"));
    }

    let sections: Vec<SectionInfo> = sqlx::query_as::<_, (String, i64, i64, i64, f64, bool, bool)>(
        r#"
        SELECT name, virtual_address, virtual_size, raw_size, entropy, is_executable, is_writable
        FROM binary_sections
        WHERE sample_id = ?
        ORDER BY virtual_address
        "#
    )
    .bind(&sample_id)
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?
    .into_iter()
    .map(|s| SectionInfo {
        name: s.0,
        virtual_address: s.1,
        virtual_size: s.2,
        raw_size: s.3,
        entropy: s.4,
        is_executable: s.5,
        is_writable: s.6,
    })
    .collect();

    Ok(HttpResponse::Ok().json(sections))
}

/// Get hex view of binary data
async fn get_hex_view(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
    query: web::Query<HexViewRequest>,
) -> Result<HttpResponse, ApiError> {
    let sample_id = path.into_inner();

    // Get stored binary data
    let data: Option<(Vec<u8>,)> = sqlx::query_as(
        r#"
        SELECT s.file_data
        FROM binary_file_storage s
        JOIN binary_samples b ON s.sample_id = b.id
        WHERE s.sample_id = ? AND b.user_id = ?
        "#
    )
    .bind(&sample_id)
    .bind(&claims.sub)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?;

    let data = data.ok_or_else(|| ApiError::not_found("Binary data not found"))?;

    let analyzer = BinaryAnalyzer::new();
    let hex_view = analyzer.get_hex_view(&data.0, query.offset, query.length);

    Ok(HttpResponse::Ok().json(hex_view))
}

/// Re-analyze a sample
async fn reanalyze_sample(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let sample_id = path.into_inner();

    // Get stored binary data
    let data: Option<(Vec<u8>, String)> = sqlx::query_as(
        r#"
        SELECT s.file_data, b.filename
        FROM binary_file_storage s
        JOIN binary_samples b ON s.sample_id = b.id
        WHERE s.sample_id = ? AND b.user_id = ?
        "#
    )
    .bind(&sample_id)
    .bind(&claims.sub)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?;

    let (file_data, filename) = data.ok_or_else(|| ApiError::not_found("Binary data not found"))?;

    // Delete existing records (cascade will handle related tables)
    sqlx::query("DELETE FROM binary_samples WHERE id = ?")
        .bind(&sample_id)
        .execute(pool.get_ref())
        .await
        .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?;

    // Re-analyze
    let analyzer = BinaryAnalyzer::new();
    let mut sample = analyzer.analyze_bytes(&file_data, filename.clone(), &claims.sub)
        .map_err(|e| ApiError::internal(format!("Analysis failed: {}", e)))?;

    // Preserve original ID
    sample.id = sample_id;

    // Save to database (no CRM fields for re-analysis)
    save_sample_to_db(&pool, &sample, Some(&file_data), None, None).await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Sample re-analyzed successfully",
        "id": sample.id,
    })))
}

/// Look up a sample by hash
async fn lookup_hash(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    body: web::Json<HashLookupRequest>,
) -> Result<HttpResponse, ApiError> {
    let hash = body.hash.to_lowercase();
    let hash_type = body.hash_type.as_deref().unwrap_or_else(|| {
        // Auto-detect hash type from length
        match hash.len() {
            32 => "md5",
            40 => "sha1",
            64 => "sha256",
            _ => "sha256",
        }
    });

    let column = match hash_type {
        "md5" => "md5",
        "sha1" => "sha1",
        "sha256" => "sha256",
        _ => return Err(ApiError::bad_request("Invalid hash type")),
    };

    let sql = format!(
        "SELECT id, filename, file_size, file_type, architecture, sha256, entropy,
                is_packed, packer_name, analysis_status, strings_count, imports_count, created_at
         FROM binary_samples WHERE {} = ? AND user_id = ?",
        column
    );

    let row: Option<(String, String, i64, String, Option<String>, String, f64, bool, Option<String>, String, i32, i32, String)> =
        sqlx::query_as(&sql)
        .bind(&hash)
        .bind(&claims.sub)
        .fetch_optional(pool.get_ref())
        .await
        .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?;

    let response = match row {
        Some(r) => HashLookupResponse {
            found: true,
            sample: Some(SampleSummary {
                id: r.0,
                filename: r.1,
                file_size: r.2,
                file_type: r.3,
                architecture: r.4,
                sha256: r.5,
                entropy: r.6,
                is_packed: r.7,
                packer_name: r.8,
                analysis_status: r.9,
                strings_count: r.10,
                imports_count: r.11,
                created_at: r.12,
            }),
        },
        None => HashLookupResponse {
            found: false,
            sample: None,
        },
    };

    Ok(HttpResponse::Ok().json(response))
}

/// Get binary analysis statistics
async fn get_stats(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse, ApiError> {
    let total: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM binary_samples WHERE user_id = ?"
    )
    .bind(&claims.sub)
    .fetch_one(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?;

    let pe_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM binary_samples WHERE user_id = ? AND file_type = 'PE'"
    )
    .bind(&claims.sub)
    .fetch_one(pool.get_ref())
    .await
    .unwrap_or((0,));

    let elf_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM binary_samples WHERE user_id = ? AND file_type = 'ELF'"
    )
    .bind(&claims.sub)
    .fetch_one(pool.get_ref())
    .await
    .unwrap_or((0,));

    let packed_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM binary_samples WHERE user_id = ? AND is_packed = 1"
    )
    .bind(&claims.sub)
    .fetch_one(pool.get_ref())
    .await
    .unwrap_or((0,));

    let pending: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM binary_samples WHERE user_id = ? AND analysis_status = 'pending'"
    )
    .bind(&claims.sub)
    .fetch_one(pool.get_ref())
    .await
    .unwrap_or((0,));

    let strings_total: (i64,) = sqlx::query_as(
        r#"
        SELECT COALESCE(SUM(strings_count), 0)
        FROM binary_samples WHERE user_id = ?
        "#
    )
    .bind(&claims.sub)
    .fetch_one(pool.get_ref())
    .await
    .unwrap_or((0,));

    let unique_packers: (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(DISTINCT packer_name)
        FROM binary_samples
        WHERE user_id = ? AND packer_name IS NOT NULL
        "#
    )
    .bind(&claims.sub)
    .fetch_one(pool.get_ref())
    .await
    .unwrap_or((0,));

    Ok(HttpResponse::Ok().json(BinaryAnalysisStats {
        total_samples: total.0,
        pe_samples: pe_count.0,
        elf_samples: elf_count.0,
        packed_samples: packed_count.0,
        pending_analysis: pending.0,
        total_strings_extracted: strings_total.0,
        unique_packers: unique_packers.0,
    }))
}

/// Compare request
#[derive(Debug, Deserialize)]
pub struct CompareRequest {
    pub sample_id_1: String,
    pub sample_id_2: String,
}

/// Compare two samples
async fn compare_samples(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    body: web::Json<CompareRequest>,
) -> Result<HttpResponse, ApiError> {
    // Get both samples
    let sample1: Option<(String, String, i64, String, f64, bool, Option<String>, i32, i32)> = sqlx::query_as(
        r#"
        SELECT id, sha256, file_size, file_type, entropy, is_packed, imphash, imports_count, strings_count
        FROM binary_samples WHERE id = ? AND user_id = ?
        "#
    )
    .bind(&body.sample_id_1)
    .bind(&claims.sub)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?;

    let sample2: Option<(String, String, i64, String, f64, bool, Option<String>, i32, i32)> = sqlx::query_as(
        r#"
        SELECT id, sha256, file_size, file_type, entropy, is_packed, imphash, imports_count, strings_count
        FROM binary_samples WHERE id = ? AND user_id = ?
        "#
    )
    .bind(&body.sample_id_2)
    .bind(&claims.sub)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?;

    let s1 = sample1.ok_or_else(|| ApiError::not_found("Sample 1 not found"))?;
    let s2 = sample2.ok_or_else(|| ApiError::not_found("Sample 2 not found"))?;

    // Calculate similarity metrics
    let sha256_match = s1.1 == s2.1;
    let imphash_match = s1.6.is_some() && s2.6.is_some() && s1.6 == s2.6;
    let file_type_match = s1.3 == s2.3;
    let entropy_diff = (s1.4 - s2.4).abs();
    let size_ratio = (s1.2.min(s2.2) as f64) / (s1.2.max(s2.2) as f64);

    // Get common imports
    let common_imports: (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*) FROM binary_imports a
        JOIN binary_imports b ON a.dll_name = b.dll_name AND a.function_name = b.function_name
        WHERE a.sample_id = ? AND b.sample_id = ?
        "#
    )
    .bind(&body.sample_id_1)
    .bind(&body.sample_id_2)
    .fetch_one(pool.get_ref())
    .await
    .unwrap_or((0,));

    let total_imports = (s1.7 + s2.7) as i64;
    let import_similarity = if total_imports > 0 {
        (2 * common_imports.0) as f64 / total_imports as f64
    } else {
        0.0
    };

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "sample1": {
            "id": s1.0,
            "sha256": s1.1,
            "file_size": s1.2,
            "file_type": s1.3,
            "entropy": s1.4,
            "is_packed": s1.5,
            "imphash": s1.6,
        },
        "sample2": {
            "id": s2.0,
            "sha256": s2.1,
            "file_size": s2.2,
            "file_type": s2.3,
            "entropy": s2.4,
            "is_packed": s2.5,
            "imphash": s2.6,
        },
        "comparison": {
            "sha256_match": sha256_match,
            "imphash_match": imphash_match,
            "file_type_match": file_type_match,
            "entropy_difference": entropy_diff,
            "size_ratio": size_ratio,
            "common_imports": common_imports.0,
            "import_similarity": import_similarity,
        }
    })))
}
