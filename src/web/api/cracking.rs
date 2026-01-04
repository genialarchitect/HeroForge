//! Password cracking API endpoints

#![allow(dead_code)]

use actix_multipart::Multipart;
use actix_web::{web, HttpResponse};
use sqlx::sqlite::SqlitePool;
use serde::Deserialize;
use std::sync::Arc;
use std::io::BufRead;
use tokio::sync::RwLock;
use tokio::io::AsyncWriteExt;
use futures_util::StreamExt;

use crate::cracking::{
    CrackingEngine, CreateCrackingJobRequest, CrackerType, HashType,
    DetectHashRequest, DetectHashResponse, HashTypeInfo,
};
use crate::db;
use crate::web::auth::jwt::Claims;
use crate::web::error::ApiError;

// ============================================================================
// Cracking Jobs
// ============================================================================

/// Create a new cracking job
pub async fn create_job(
    _pool: web::Data<SqlitePool>,
    engine: web::Data<Arc<RwLock<CrackingEngine>>>,
    claims: Claims,
    body: web::Json<CreateCrackingJobRequest>,
) -> Result<HttpResponse, ApiError> {
    let engine = engine.read().await;
    let job = engine.create_job(&claims.sub, body.into_inner()).await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    Ok(HttpResponse::Created().json(job))
}

/// List cracking jobs for the current user
pub async fn list_jobs(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    query: web::Query<ListJobsQuery>,
) -> Result<HttpResponse, ApiError> {
    let jobs = db::cracking::get_user_cracking_jobs(
        pool.get_ref(),
        &claims.sub,
        query.limit.map(|l| l as i64),
        query.offset.map(|o| o as i64),
    ).await.map_err(|e| ApiError::internal(e.to_string()))?;

    Ok(HttpResponse::Ok().json(jobs))
}

/// Get a specific cracking job
pub async fn get_job(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let job_id = path.into_inner();
    let job = db::cracking::get_cracking_job(pool.get_ref(), &job_id).await
        .map_err(|_| ApiError::not_found("Job not found".to_string()))?;

    // Check ownership
    if job.user_id != claims.sub {
        return Err(ApiError::forbidden("Not authorized to view this job".to_string()));
    }

    Ok(HttpResponse::Ok().json(job))
}

/// Start a cracking job
pub async fn start_job(
    pool: web::Data<SqlitePool>,
    engine: web::Data<Arc<RwLock<CrackingEngine>>>,
    claims: Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let job_id = path.into_inner();

    // Verify ownership
    let job = db::cracking::get_cracking_job(pool.get_ref(), &job_id).await
        .map_err(|_| ApiError::not_found("Job not found".to_string()))?;

    if job.user_id != claims.sub {
        return Err(ApiError::forbidden("Not authorized to start this job".to_string()));
    }

    let engine = engine.read().await;
    engine.start_job(&job_id).await
        .map_err(|e| ApiError::bad_request(e.to_string()))?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "message": "Job started"
    })))
}

/// Stop a running cracking job
pub async fn stop_job(
    pool: web::Data<SqlitePool>,
    engine: web::Data<Arc<RwLock<CrackingEngine>>>,
    claims: Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let job_id = path.into_inner();

    // Verify ownership
    let job = db::cracking::get_cracking_job(pool.get_ref(), &job_id).await
        .map_err(|_| ApiError::not_found("Job not found".to_string()))?;

    if job.user_id != claims.sub {
        return Err(ApiError::forbidden("Not authorized to stop this job".to_string()));
    }

    let engine = engine.read().await;
    engine.stop_job(&job_id).await
        .map_err(|e| ApiError::bad_request(e.to_string()))?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "message": "Job stopped"
    })))
}

/// Delete a cracking job
pub async fn delete_job(
    pool: web::Data<SqlitePool>,
    engine: web::Data<Arc<RwLock<CrackingEngine>>>,
    claims: Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let job_id = path.into_inner();

    // Verify ownership
    let job = db::cracking::get_cracking_job(pool.get_ref(), &job_id).await
        .map_err(|_| ApiError::not_found("Job not found".to_string()))?;

    if job.user_id != claims.sub {
        return Err(ApiError::forbidden("Not authorized to delete this job".to_string()));
    }

    let engine = engine.read().await;
    engine.delete_job(&job_id).await
        .map_err(|e| ApiError::bad_request(e.to_string()))?;

    Ok(HttpResponse::NoContent().finish())
}

/// Get cracked credentials for a job
pub async fn get_job_results(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let job_id = path.into_inner();

    // Verify ownership
    let job = db::cracking::get_cracking_job(pool.get_ref(), &job_id).await
        .map_err(|_| ApiError::not_found("Job not found".to_string()))?;

    if job.user_id != claims.sub {
        return Err(ApiError::forbidden("Not authorized to view this job".to_string()));
    }

    let credentials = db::cracking::get_job_credentials(pool.get_ref(), &job_id).await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    Ok(HttpResponse::Ok().json(credentials))
}

// ============================================================================
// Wordlists
// ============================================================================

/// List available wordlists
pub async fn list_wordlists(
    pool: web::Data<SqlitePool>,
    claims: Claims,
) -> Result<HttpResponse, ApiError> {
    let wordlists = db::cracking::get_available_wordlists(pool.get_ref(), &claims.sub).await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    Ok(HttpResponse::Ok().json(wordlists))
}

/// Upload a new wordlist (multipart file upload)
pub async fn upload_wordlist(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    mut payload: Multipart,
) -> Result<HttpResponse, ApiError> {
    let mut name: Option<String> = None;
    let mut description: Option<String> = None;
    let mut category: Option<String> = None;
    let mut file_data: Option<Vec<u8>> = None;
    let mut original_filename: Option<String> = None;

    // Parse multipart form fields
    while let Some(item) = payload.next().await {
        let mut field = item.map_err(|e| ApiError::bad_request(format!("Multipart error: {}", e)))?;

        // Get content disposition, skip if not present
        let content_disposition = match field.content_disposition() {
            Some(cd) => cd,
            None => continue,
        };

        let field_name = content_disposition.get_name();

        match field_name {
            Some("name") => {
                let mut data = Vec::new();
                while let Some(chunk) = field.next().await {
                    let chunk = chunk.map_err(|e| ApiError::bad_request(e.to_string()))?;
                    data.extend_from_slice(&chunk);
                }
                name = Some(String::from_utf8_lossy(&data).to_string());
            }
            Some("description") => {
                let mut data = Vec::new();
                while let Some(chunk) = field.next().await {
                    let chunk = chunk.map_err(|e| ApiError::bad_request(e.to_string()))?;
                    data.extend_from_slice(&chunk);
                }
                description = Some(String::from_utf8_lossy(&data).to_string());
            }
            Some("category") => {
                let mut data = Vec::new();
                while let Some(chunk) = field.next().await {
                    let chunk = chunk.map_err(|e| ApiError::bad_request(e.to_string()))?;
                    data.extend_from_slice(&chunk);
                }
                category = Some(String::from_utf8_lossy(&data).to_string());
            }
            Some("file") => {
                original_filename = content_disposition.get_filename().map(String::from);
                let mut data = Vec::new();
                while let Some(chunk) = field.next().await {
                    let chunk = chunk.map_err(|e| ApiError::bad_request(e.to_string()))?;
                    data.extend_from_slice(&chunk);
                }
                file_data = Some(data);
            }
            _ => {}
        }
    }

    // Validate required fields
    let name = name.ok_or_else(|| ApiError::bad_request("name field is required".to_string()))?;
    let file_data = file_data.ok_or_else(|| ApiError::bad_request("file field is required".to_string()))?;

    // Create wordlists directory if it doesn't exist
    let wordlist_dir = std::path::PathBuf::from("./wordlists");
    tokio::fs::create_dir_all(&wordlist_dir).await
        .map_err(|e| ApiError::internal(format!("Failed to create wordlists directory: {}", e)))?;

    // Generate unique filename
    let wordlist_id = uuid::Uuid::new_v4().to_string();
    let extension = original_filename
        .as_ref()
        .and_then(|f| std::path::Path::new(f).extension())
        .and_then(|e| e.to_str())
        .unwrap_or("txt");
    let filename = format!("{}_{}.{}", claims.sub, wordlist_id, extension);
    let file_path = wordlist_dir.join(&filename);

    // Write file to disk
    let mut file = tokio::fs::File::create(&file_path).await
        .map_err(|e| ApiError::internal(format!("Failed to create file: {}", e)))?;
    file.write_all(&file_data).await
        .map_err(|e| ApiError::internal(format!("Failed to write file: {}", e)))?;
    file.flush().await
        .map_err(|e| ApiError::internal(format!("Failed to flush file: {}", e)))?;

    // Count lines in the file
    let line_count = std::io::BufReader::new(
        std::fs::File::open(&file_path)
            .map_err(|e| ApiError::internal(format!("Failed to read file: {}", e)))?
    ).lines().count() as i64;

    let size_bytes = file_data.len() as i64;
    let file_path_str = file_path.to_string_lossy().to_string();
    let category_str = category.unwrap_or_else(|| "custom".to_string());

    // Create wordlist entry in database
    let wordlist = db::cracking::create_wordlist(
        pool.get_ref(),
        &wordlist_id,
        Some(&claims.sub),
        &name,
        description.as_deref(),
        &file_path_str,
        size_bytes,
        line_count,
        false, // not builtin
        &category_str,
    ).await.map_err(|e| ApiError::internal(format!("Failed to save wordlist: {}", e)))?;

    Ok(HttpResponse::Created().json(wordlist))
}

/// Delete a wordlist
pub async fn delete_wordlist(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let wordlist_id = path.into_inner();

    // Verify ownership
    let wordlist = db::cracking::get_wordlist(pool.get_ref(), &wordlist_id).await
        .map_err(|_| ApiError::not_found("Wordlist not found".to_string()))?;

    if wordlist.is_builtin {
        return Err(ApiError::forbidden("Cannot delete built-in wordlists".to_string()));
    }

    if wordlist.user_id.as_deref() != Some(&claims.sub) {
        return Err(ApiError::forbidden("Not authorized to delete this wordlist".to_string()));
    }

    db::cracking::delete_wordlist(pool.get_ref(), &wordlist_id).await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    Ok(HttpResponse::NoContent().finish())
}

// ============================================================================
// Rule Files
// ============================================================================

/// List available rule files
pub async fn list_rules(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    query: web::Query<ListRulesQuery>,
) -> Result<HttpResponse, ApiError> {
    let cracker_type = query.cracker_type.as_ref().map(|ct| {
        if ct == "john" { CrackerType::John } else { CrackerType::Hashcat }
    });

    let rules = db::cracking::get_available_rules(pool.get_ref(), &claims.sub, cracker_type).await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    Ok(HttpResponse::Ok().json(rules))
}

/// Delete a rule file
pub async fn delete_rule(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let rule_id = path.into_inner();

    // Verify ownership
    let rule = db::cracking::get_rule_file(pool.get_ref(), &rule_id).await
        .map_err(|_| ApiError::not_found("Rule file not found".to_string()))?;

    if rule.is_builtin {
        return Err(ApiError::forbidden("Cannot delete built-in rule files".to_string()));
    }

    if rule.user_id.as_deref() != Some(&claims.sub) {
        return Err(ApiError::forbidden("Not authorized to delete this rule file".to_string()));
    }

    db::cracking::delete_rule_file(pool.get_ref(), &rule_id).await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    Ok(HttpResponse::NoContent().finish())
}

// ============================================================================
// Utilities
// ============================================================================

/// Detect hash type from samples
pub async fn detect_hash_type(
    body: web::Json<DetectHashRequest>,
) -> Result<HttpResponse, ApiError> {
    if body.hashes.is_empty() {
        return Err(ApiError::bad_request("No hashes provided".to_string()));
    }

    let first_hash = &body.hashes[0];
    let detected = HashType::detect(first_hash);

    let response = if let Some(hash_type) = detected {
        DetectHashResponse {
            hash_type: Some(hash_type.mode()),
            hash_type_name: Some(hash_type.name().to_string()),
            confidence: "high".to_string(),
            alternatives: vec![],
        }
    } else {
        // Try to provide some alternatives
        let alternatives = vec![
            HashTypeInfo { mode: 1000, name: "NTLM".to_string(), example: Some("32 hex characters".to_string()) },
            HashTypeInfo { mode: 0, name: "MD5".to_string(), example: Some("32 hex characters".to_string()) },
            HashTypeInfo { mode: 1400, name: "SHA-256".to_string(), example: Some("64 hex characters".to_string()) },
        ];
        DetectHashResponse {
            hash_type: None,
            hash_type_name: None,
            confidence: "none".to_string(),
            alternatives,
        }
    };

    Ok(HttpResponse::Ok().json(response))
}

/// Get cracking statistics
pub async fn get_stats(
    pool: web::Data<SqlitePool>,
    claims: Claims,
) -> Result<HttpResponse, ApiError> {
    let stats = db::cracking::get_cracking_stats(pool.get_ref(), &claims.sub).await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    Ok(HttpResponse::Ok().json(stats))
}

/// Get list of supported hash types
pub async fn list_hash_types() -> Result<HttpResponse, ApiError> {
    let hash_types = vec![
        HashTypeInfo { mode: 0, name: "MD5".to_string(), example: Some("8743b52063cd84097a65d1633f5c74f5".to_string()) },
        HashTypeInfo { mode: 100, name: "SHA-1".to_string(), example: Some("b89eaac7e61417341b710b727768294d0e6a277b".to_string()) },
        HashTypeInfo { mode: 1000, name: "NTLM".to_string(), example: Some("b4b9b02e6f09a9bd760f388b67351e2b".to_string()) },
        HashTypeInfo { mode: 1400, name: "SHA-256".to_string(), example: Some("127e6fbfe24a750e72930c220a8e138275656b8e5d8f48a98c3c92df2caba935".to_string()) },
        HashTypeInfo { mode: 1700, name: "SHA-512".to_string(), example: None },
        HashTypeInfo { mode: 3000, name: "LM".to_string(), example: Some("299BD128C1101FD6".to_string()) },
        HashTypeInfo { mode: 3200, name: "bcrypt".to_string(), example: Some("$2a$05$LhayLxezLhK1LhWvKxCyLOj0j1u.Kj0jZ0pEmm134uzrQlFvQJLF6".to_string()) },
        HashTypeInfo { mode: 5600, name: "NetNTLMv2".to_string(), example: None },
        HashTypeInfo { mode: 13100, name: "Kerberos 5 TGS (Kerberoasting)".to_string(), example: Some("$krb5tgs$23$*user$realm$spn*$...".to_string()) },
        HashTypeInfo { mode: 18200, name: "Kerberos 5 AS-REP".to_string(), example: Some("$krb5asrep$23$...".to_string()) },
        HashTypeInfo { mode: 1800, name: "SHA-512 crypt".to_string(), example: Some("$6$rounds=5000$...".to_string()) },
        HashTypeInfo { mode: 22000, name: "WPA-PMKID-PBKDF2".to_string(), example: None },
    ];

    Ok(HttpResponse::Ok().json(hash_types))
}

// ============================================================================
// Query Types
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct ListJobsQuery {
    pub limit: Option<i32>,
    pub offset: Option<i32>,
}

#[derive(Debug, Deserialize)]
pub struct ListRulesQuery {
    pub cracker_type: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreateWordlistRequest {
    pub name: String,
    pub description: Option<String>,
    pub file_path: String,
}

// ============================================================================
// Route Configuration
// ============================================================================

/// Configure cracking routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/cracking")
            // Jobs
            .route("/jobs", web::post().to(create_job))
            .route("/jobs", web::get().to(list_jobs))
            .route("/jobs/{id}", web::get().to(get_job))
            .route("/jobs/{id}", web::delete().to(delete_job))
            .route("/jobs/{id}/start", web::post().to(start_job))
            .route("/jobs/{id}/stop", web::post().to(stop_job))
            .route("/jobs/{id}/results", web::get().to(get_job_results))
            // Wordlists
            .route("/wordlists", web::get().to(list_wordlists))
            .route("/wordlists", web::post().to(upload_wordlist))
            .route("/wordlists/{id}", web::delete().to(delete_wordlist))
            // Rules
            .route("/rules", web::get().to(list_rules))
            .route("/rules/{id}", web::delete().to(delete_rule))
            // Utilities
            .route("/detect-hash", web::post().to(detect_hash_type))
            .route("/hash-types", web::get().to(list_hash_types))
            .route("/stats", web::get().to(get_stats))
    );
}
