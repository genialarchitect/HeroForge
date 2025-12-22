//! BloodHound API endpoints
//!
//! Provides REST API for importing SharpHound data and querying attack paths.

use actix_multipart::Multipart;
use actix_web::{web, HttpResponse};
use futures_util::StreamExt;
use log::{error, info};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::io::Read;

use crate::db::bloodhound;
use crate::scanner::bloodhound::{
    analyze_import, parse_sharphound_json, parse_sharphound_zip, ADObjectType,
    AsrepRoastableUser, AttackPath, HighValueTarget, ImportStatistics, ImportStatus,
    KerberoastableUser, PathNode, PathStep, UnconstrainedDelegation,
};
use crate::web::auth::jwt::Claims;
use crate::web::error::ApiError;

/// Response for import list
#[derive(Serialize)]
pub struct ImportListResponse {
    pub imports: Vec<ImportSummary>,
    pub total: i64,
}

#[derive(Serialize)]
pub struct ImportSummary {
    pub id: String,
    pub domain: String,
    pub status: String,
    pub statistics: ImportStatistics,
    pub created_at: String,
    pub completed_at: Option<String>,
}

/// Full import detail response
#[derive(Serialize)]
pub struct ImportDetailResponse {
    pub id: String,
    pub domain: String,
    pub status: String,
    pub statistics: ImportStatistics,
    pub attack_paths: Vec<AttackPath>,
    pub high_value_targets: Vec<HighValueTarget>,
    pub kerberoastable_users: Vec<KerberoastableUser>,
    pub asrep_roastable_users: Vec<AsrepRoastableUser>,
    pub unconstrained_delegation: Vec<UnconstrainedDelegation>,
    pub created_at: String,
    pub completed_at: Option<String>,
}

/// Upload response
#[derive(Serialize)]
pub struct UploadResponse {
    pub id: String,
    pub status: String,
    pub message: String,
}

/// Pagination query parameters
#[derive(Deserialize)]
pub struct PaginationQuery {
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

/// Upload SharpHound data (ZIP or JSON)
pub async fn upload_data(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    mut payload: Multipart,
) -> Result<HttpResponse, ApiError> {
    info!("User {} uploading SharpHound data", claims.sub);

    let mut file_data: Vec<u8> = Vec::new();
    let mut file_name = String::new();
    let mut file_type = String::new();

    // Process multipart form
    while let Some(field) = payload.next().await {
        let mut field = field.map_err(|e| ApiError::bad_request(format!("Upload error: {}", e)))?;

        // Get field name and content disposition
        let content_disposition = field.content_disposition();
        let field_name = content_disposition
            .and_then(|cd| cd.get_name().map(|s| s.to_string()))
            .unwrap_or_default();

        if field_name == "file" {
            file_name = content_disposition
                .and_then(|cd| cd.get_filename().map(|s| s.to_string()))
                .unwrap_or_else(|| "unknown".to_string());

            // Determine file type from extension
            if file_name.ends_with(".zip") {
                file_type = "zip".to_string();
            } else if file_name.ends_with(".json") {
                file_type = "json".to_string();
            } else {
                return Err(ApiError::bad_request(
                    "Unsupported file type. Please upload a .zip or .json file",
                ));
            }

            // Read file data
            while let Some(chunk) = field.next().await {
                let data = chunk.map_err(|e| ApiError::bad_request(format!("Read error: {}", e)))?;
                file_data.extend_from_slice(&data);
            }
        } else if field_name == "type" {
            // Optional file type override
            let mut type_data = Vec::new();
            while let Some(chunk) = field.next().await {
                let data = chunk.map_err(|e| ApiError::bad_request(format!("Read error: {}", e)))?;
                type_data.extend_from_slice(&data);
            }
            if !type_data.is_empty() {
                file_type = String::from_utf8_lossy(&type_data).to_string();
            }
        }
    }

    if file_data.is_empty() {
        return Err(ApiError::bad_request("No file uploaded"));
    }

    // Create import record
    let import_id =
        bloodhound::create_import(pool.get_ref(), &claims.sub, "Processing...").await?;

    // Parse and analyze data
    let pool_clone = pool.get_ref().clone();
    let import_id_clone = import_id.clone();

    tokio::spawn(async move {
        let result = match file_type.as_str() {
            "zip" => match parse_sharphound_zip(&file_data) {
                Ok(data) => analyze_import(&data),
                Err(e) => Err(e),
            },
            "json" => {
                // Try to determine JSON type from content
                let json_str = String::from_utf8_lossy(&file_data);
                let json_type = detect_json_type(&json_str);

                match parse_sharphound_json(&json_str, &json_type) {
                    Ok(data) => analyze_import(&data),
                    Err(e) => Err(e),
                }
            }
            _ => Err(anyhow::anyhow!("Unsupported file type")),
        };

        match result {
            Ok(import_result) => {
                if let Err(e) =
                    bloodhound::save_import_results(&pool_clone, &import_id_clone, &import_result)
                        .await
                {
                    error!("Failed to save import results: {}", e);
                    let _ = bloodhound::update_import_status(
                        &pool_clone,
                        &import_id_clone,
                        ImportStatus::Failed,
                    )
                    .await;
                }
            }
            Err(e) => {
                error!("Failed to process SharpHound data: {}", e);
                let _ = bloodhound::update_import_status(
                    &pool_clone,
                    &import_id_clone,
                    ImportStatus::Failed,
                )
                .await;
            }
        }
    });

    Ok(HttpResponse::Ok().json(UploadResponse {
        id: import_id,
        status: "processing".to_string(),
        message: "SharpHound data upload started. Processing in background.".to_string(),
    }))
}

/// Detect the type of SharpHound JSON from its content
fn detect_json_type(json: &str) -> String {
    // Look for type hints in the meta section or data content
    let lower = json.to_lowercase();

    if lower.contains("\"type\":\"computers\"") || lower.contains("operatingsystem") {
        "computers".to_string()
    } else if lower.contains("\"type\":\"users\"") || lower.contains("serviceprincipalnames") {
        "users".to_string()
    } else if lower.contains("\"type\":\"groups\"") || lower.contains("\"members\":") {
        "groups".to_string()
    } else if lower.contains("\"type\":\"domains\"") || lower.contains("\"trusts\":") {
        "domains".to_string()
    } else if lower.contains("\"type\":\"gpos\"") || lower.contains("gpcpath") {
        "gpos".to_string()
    } else if lower.contains("\"type\":\"ous\"") || lower.contains("blockinheritance") {
        "ous".to_string()
    } else if lower.contains("\"type\":\"containers\"") {
        "containers".to_string()
    } else {
        // Default to users if unknown
        "users".to_string()
    }
}

/// List all imports for the current user
pub async fn list_imports(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    query: web::Query<PaginationQuery>,
) -> Result<HttpResponse, ApiError> {
    let limit = query.limit.unwrap_or(50).min(100);
    let offset = query.offset.unwrap_or(0);

    let imports =
        bloodhound::get_user_imports(pool.get_ref(), &claims.sub, limit as i64, offset as i64)
            .await?;

    let summaries: Vec<ImportSummary> = imports
        .into_iter()
        .filter_map(|row| {
            let statistics: ImportStatistics = serde_json::from_str(&row.statistics).ok()?;
            let status: ImportStatus = serde_json::from_str(&row.status).ok()?;

            Some(ImportSummary {
                id: row.id,
                domain: row.domain,
                status: format!("{:?}", status).to_lowercase(),
                statistics,
                created_at: row.created_at,
                completed_at: row.completed_at,
            })
        })
        .collect();

    Ok(HttpResponse::Ok().json(ImportListResponse {
        total: summaries.len() as i64,
        imports: summaries,
    }))
}

/// Get a specific import with full details
pub async fn get_import(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let import_id = path.into_inner();

    let import = bloodhound::get_import_by_id(pool.get_ref(), &import_id)
        .await?
        .ok_or_else(|| ApiError::not_found("Import not found"))?;

    // Verify ownership
    if import.user_id != claims.sub {
        return Err(ApiError::forbidden("Access denied"));
    }

    // Get all associated data
    let attack_paths = bloodhound::get_attack_paths(pool.get_ref(), &import_id).await?;
    let high_value = bloodhound::get_high_value_targets(pool.get_ref(), &import_id).await?;
    let kerberoastable = bloodhound::get_kerberoastable_users(pool.get_ref(), &import_id).await?;
    let asrep = bloodhound::get_asrep_roastable_users(pool.get_ref(), &import_id).await?;
    let unconstrained = bloodhound::get_unconstrained_delegation(pool.get_ref(), &import_id).await?;

    let statistics: ImportStatistics =
        serde_json::from_str(&import.statistics).unwrap_or_default();
    let status: ImportStatus = serde_json::from_str(&import.status).unwrap_or_default();

    // Convert rows to response types
    let attack_paths: Vec<AttackPath> = attack_paths
        .into_iter()
        .filter_map(|row| {
            let path: Vec<PathStep> = serde_json::from_str(&row.path_json).ok()?;
            let techniques: Vec<String> = serde_json::from_str(&row.techniques).ok()?;
            let start_node: PathNode = serde_json::from_str(&row.start_node).ok()?;
            let end_node: PathNode = serde_json::from_str(&row.end_node).ok()?;

            Some(AttackPath {
                id: row.id,
                start_node,
                end_node,
                path,
                length: row.path_length as usize,
                risk_score: row.risk_score as u8,
                techniques,
                description: row.description,
            })
        })
        .collect();

    let high_value_targets: Vec<HighValueTarget> = high_value
        .into_iter()
        .filter_map(|row| {
            let object_type: ADObjectType = serde_json::from_str(&row.object_type).ok()?;

            Some(HighValueTarget {
                object_id: row.object_id,
                name: row.name,
                object_type,
                domain: row.domain,
                reason: row.reason,
                paths_to_target: row.paths_to_target as usize,
            })
        })
        .collect();

    let kerberoastable_users: Vec<KerberoastableUser> = kerberoastable
        .into_iter()
        .filter_map(|row| {
            let spns: Vec<String> = serde_json::from_str(&row.spns).ok()?;

            Some(KerberoastableUser {
                object_id: row.object_id,
                name: row.name,
                domain: row.domain,
                service_principal_names: spns,
                is_admin: row.is_admin,
                password_last_set: row.password_last_set,
                description: row.description,
            })
        })
        .collect();

    let asrep_roastable_users: Vec<AsrepRoastableUser> = asrep
        .into_iter()
        .map(|row| AsrepRoastableUser {
            object_id: row.object_id,
            name: row.name,
            domain: row.domain,
            is_enabled: row.is_enabled,
            is_admin: row.is_admin,
            description: row.description,
        })
        .collect();

    let unconstrained_delegation: Vec<UnconstrainedDelegation> = unconstrained
        .into_iter()
        .filter_map(|row| {
            let object_type: ADObjectType = serde_json::from_str(&row.object_type).ok()?;

            Some(UnconstrainedDelegation {
                object_id: row.object_id,
                name: row.name,
                object_type,
                domain: row.domain,
                is_dc: row.is_dc,
                description: row.description,
            })
        })
        .collect();

    Ok(HttpResponse::Ok().json(ImportDetailResponse {
        id: import.id,
        domain: import.domain,
        status: format!("{:?}", status).to_lowercase(),
        statistics,
        attack_paths,
        high_value_targets,
        kerberoastable_users,
        asrep_roastable_users,
        unconstrained_delegation,
        created_at: import.created_at,
        completed_at: import.completed_at,
    }))
}

/// Get attack paths for an import
pub async fn get_attack_paths(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let import_id = path.into_inner();

    // Verify ownership
    let import = bloodhound::get_import_by_id(pool.get_ref(), &import_id)
        .await?
        .ok_or_else(|| ApiError::not_found("Import not found"))?;

    if import.user_id != claims.sub {
        return Err(ApiError::forbidden("Access denied"));
    }

    let paths = bloodhound::get_attack_paths(pool.get_ref(), &import_id).await?;

    let attack_paths: Vec<AttackPath> = paths
        .into_iter()
        .filter_map(|row| {
            let path_steps: Vec<PathStep> = serde_json::from_str(&row.path_json).ok()?;
            let techniques: Vec<String> = serde_json::from_str(&row.techniques).ok()?;
            let start_node: PathNode = serde_json::from_str(&row.start_node).ok()?;
            let end_node: PathNode = serde_json::from_str(&row.end_node).ok()?;

            Some(AttackPath {
                id: row.id,
                start_node,
                end_node,
                path: path_steps,
                length: row.path_length as usize,
                risk_score: row.risk_score as u8,
                techniques,
                description: row.description,
            })
        })
        .collect();

    Ok(HttpResponse::Ok().json(attack_paths))
}

/// Get Kerberoastable users for an import
pub async fn get_kerberoastable(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let import_id = path.into_inner();

    // Verify ownership
    let import = bloodhound::get_import_by_id(pool.get_ref(), &import_id)
        .await?
        .ok_or_else(|| ApiError::not_found("Import not found"))?;

    if import.user_id != claims.sub {
        return Err(ApiError::forbidden("Access denied"));
    }

    let users = bloodhound::get_kerberoastable_users(pool.get_ref(), &import_id).await?;

    let kerberoastable: Vec<KerberoastableUser> = users
        .into_iter()
        .filter_map(|row| {
            let spns: Vec<String> = serde_json::from_str(&row.spns).ok()?;

            Some(KerberoastableUser {
                object_id: row.object_id,
                name: row.name,
                domain: row.domain,
                service_principal_names: spns,
                is_admin: row.is_admin,
                password_last_set: row.password_last_set,
                description: row.description,
            })
        })
        .collect();

    Ok(HttpResponse::Ok().json(kerberoastable))
}

/// Get AS-REP roastable users for an import
pub async fn get_asrep_roastable(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let import_id = path.into_inner();

    // Verify ownership
    let import = bloodhound::get_import_by_id(pool.get_ref(), &import_id)
        .await?
        .ok_or_else(|| ApiError::not_found("Import not found"))?;

    if import.user_id != claims.sub {
        return Err(ApiError::forbidden("Access denied"));
    }

    let users = bloodhound::get_asrep_roastable_users(pool.get_ref(), &import_id).await?;

    let asrep: Vec<AsrepRoastableUser> = users
        .into_iter()
        .map(|row| AsrepRoastableUser {
            object_id: row.object_id,
            name: row.name,
            domain: row.domain,
            is_enabled: row.is_enabled,
            is_admin: row.is_admin,
            description: row.description,
        })
        .collect();

    Ok(HttpResponse::Ok().json(asrep))
}

/// Delete an import
pub async fn delete_import(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let import_id = path.into_inner();

    // Verify ownership
    let import = bloodhound::get_import_by_id(pool.get_ref(), &import_id)
        .await?
        .ok_or_else(|| ApiError::not_found("Import not found"))?;

    if import.user_id != claims.sub {
        return Err(ApiError::forbidden("Access denied"));
    }

    bloodhound::delete_import(pool.get_ref(), &import_id).await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Import deleted",
        "id": import_id
    })))
}

/// Configure routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/bloodhound")
            .route("/upload", web::post().to(upload_data))
            .route("/imports", web::get().to(list_imports))
            .route("/imports/{id}", web::get().to(get_import))
            .route("/imports/{id}", web::delete().to(delete_import))
            .route("/imports/{id}/paths", web::get().to(get_attack_paths))
            .route(
                "/imports/{id}/kerberoastable",
                web::get().to(get_kerberoastable),
            )
            .route(
                "/imports/{id}/asrep-roastable",
                web::get().to(get_asrep_roastable),
            ),
    );
}
