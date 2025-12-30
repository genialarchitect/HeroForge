use actix_web::{web, HttpResponse};
use sqlx::SqlitePool;
use serde_json::json;
use uuid::Uuid;
use chrono::Utc;

use crate::data_lake::types::*;

/// GET /api/data-lake/sources - List data sources
pub async fn list_sources(pool: web::Data<SqlitePool>) -> HttpResponse {
    match sqlx::query_as::<_, (String, String, String, String, bool, Option<String>, i64)>(
        "SELECT id, name, type, config, enabled, last_sync, records_ingested
         FROM data_lake_sources
         ORDER BY name"
    )
    .fetch_all(pool.get_ref())
    .await
    {
        Ok(rows) => {
            let sources: Vec<DataSource> = rows
                .into_iter()
                .filter_map(|(id, name, source_type, config, enabled, last_sync, records_ingested)| {
                    let source_type = source_type.parse().ok()?;
                    let config = serde_json::from_str(&config).ok()?;
                    let last_sync = last_sync.and_then(|s| s.parse().ok());

                    Some(DataSource {
                        id,
                        name,
                        source_type,
                        config,
                        enabled,
                        last_sync,
                        records_ingested,
                    })
                })
                .collect();

            HttpResponse::Ok().json(sources)
        }
        Err(e) => {
            log::error!("Failed to list data sources: {}", e);
            HttpResponse::InternalServerError().json(json!({
                "error": "Failed to list data sources",
                "details": e.to_string()
            }))
        }
    }
}

/// POST /api/data-lake/sources - Add data source
pub async fn create_source(
    pool: web::Data<SqlitePool>,
    body: web::Json<CreateDataSourceRequest>,
) -> HttpResponse {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();

    let config_json = match serde_json::to_string(&body.config) {
        Ok(json) => json,
        Err(e) => {
            return HttpResponse::BadRequest().json(json!({
                "error": "Invalid configuration",
                "details": e.to_string()
            }))
        }
    };

    match sqlx::query(
        "INSERT INTO data_lake_sources (id, name, type, config, enabled, records_ingested, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
    )
    .bind(&id)
    .bind(&body.name)
    .bind(body.source_type.to_string())
    .bind(&config_json)
    .bind(true)
    .bind(0)
    .bind(now.to_rfc3339())
    .bind(now.to_rfc3339())
    .execute(pool.get_ref())
    .await
    {
        Ok(_) => {
            let source = DataSource {
                id,
                name: body.name.clone(),
                source_type: body.source_type.clone(),
                config: body.config.clone(),
                enabled: true,
                last_sync: None,
                records_ingested: 0,
            };

            HttpResponse::Ok().json(source)
        }
        Err(e) => {
            log::error!("Failed to create data source: {}", e);
            HttpResponse::InternalServerError().json(json!({
                "error": "Failed to create data source",
                "details": e.to_string()
            }))
        }
    }
}

/// GET /api/data-lake/sources/{id} - Get data source
pub async fn get_source(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> HttpResponse {
    let id = path.into_inner();

    match sqlx::query_as::<_, (String, String, String, String, bool, Option<String>, i64)>(
        "SELECT id, name, type, config, enabled, last_sync, records_ingested
         FROM data_lake_sources
         WHERE id = ?"
    )
    .bind(&id)
    .fetch_optional(pool.get_ref())
    .await
    {
        Ok(Some((id, name, source_type, config, enabled, last_sync, records_ingested))) => {
            match (source_type.parse(), serde_json::from_str(&config)) {
                (Ok(source_type), Ok(config)) => {
                    let last_sync = last_sync.and_then(|s| s.parse().ok());

                    HttpResponse::Ok().json(DataSource {
                        id,
                        name,
                        source_type,
                        config,
                        enabled,
                        last_sync,
                        records_ingested,
                    })
                }
                _ => HttpResponse::InternalServerError().json(json!({
                    "error": "Failed to parse data source"
                }))
            }
        }
        Ok(None) => HttpResponse::NotFound().json(json!({
            "error": "Data source not found"
        })),
        Err(e) => {
            log::error!("Failed to get data source: {}", e);
            HttpResponse::InternalServerError().json(json!({
                "error": "Failed to get data source",
                "details": e.to_string()
            }))
        }
    }
}

/// POST /api/data-lake/query - Query data lake
pub async fn query_data_lake(
    _pool: web::Data<SqlitePool>,
    body: web::Json<DataLakeQueryRequest>,
) -> HttpResponse {
    // TODO: Implement actual data lake querying
    log::info!("Querying data lake: {:?}", body);

    HttpResponse::Ok().json(DataLakeQueryResponse {
        records: vec![],
        total_count: 0,
        execution_time_ms: 0,
    })
}

/// GET /api/data-lake/stats - Data lake statistics
pub async fn get_stats(pool: web::Data<SqlitePool>) -> HttpResponse {
    // Total sources
    let total_sources: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM data_lake_sources"
    )
    .fetch_one(pool.get_ref())
    .await
    .unwrap_or(0);

    // Enabled sources
    let enabled_sources: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM data_lake_sources WHERE enabled = 1"
    )
    .fetch_one(pool.get_ref())
    .await
    .unwrap_or(0);

    // Total records
    let total_records: i64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(records_ingested), 0) FROM data_lake_sources"
    )
    .fetch_one(pool.get_ref())
    .await
    .unwrap_or(0);

    // Records by tier (would come from actual storage backend)
    let hot_tier_records = 0;
    let warm_tier_records = 0;
    let cold_tier_records = 0;
    let archive_tier_records = 0;

    let stats = DataLakeStats {
        total_sources,
        enabled_sources,
        total_records,
        hot_tier_records,
        warm_tier_records,
        cold_tier_records,
        archive_tier_records,
        storage_size_bytes: 0,
        ingestion_rate_per_second: 0.0,
    };

    HttpResponse::Ok().json(stats)
}

/// PUT /api/data-lake/sources/{id}/enable - Enable/disable source
pub async fn toggle_source(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    body: web::Json<serde_json::Value>,
) -> HttpResponse {
    let id = path.into_inner();
    let enabled = body.get("enabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    let now = Utc::now();

    match sqlx::query(
        "UPDATE data_lake_sources SET enabled = ?, updated_at = ? WHERE id = ?"
    )
    .bind(enabled)
    .bind(now.to_rfc3339())
    .bind(&id)
    .execute(pool.get_ref())
    .await
    {
        Ok(result) if result.rows_affected() > 0 => {
            HttpResponse::Ok().json(json!({
                "success": true,
                "enabled": enabled
            }))
        }
        Ok(_) => HttpResponse::NotFound().json(json!({
            "error": "Data source not found"
        })),
        Err(e) => {
            log::error!("Failed to toggle data source: {}", e);
            HttpResponse::InternalServerError().json(json!({
                "error": "Failed to toggle data source",
                "details": e.to_string()
            }))
        }
    }
}

/// Configure data lake API routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/data-lake")
            .route("/sources", web::get().to(list_sources))
            .route("/sources", web::post().to(create_source))
            .route("/sources/{id}", web::get().to(get_source))
            .route("/sources/{id}/enable", web::put().to(toggle_source))
            .route("/query", web::post().to(query_data_lake))
            .route("/stats", web::get().to(get_stats))
    );
}
