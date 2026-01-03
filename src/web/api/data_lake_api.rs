use actix_web::{web, HttpResponse};
use sqlx::SqlitePool;
use serde_json::json;
use uuid::Uuid;
use chrono::Utc;

use crate::data_lake::types::*;
use crate::data_lake::types::FilterOperator;

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
    pool: web::Data<SqlitePool>,
    body: web::Json<DataLakeQueryRequest>,
) -> HttpResponse {
    log::info!("Querying data lake: {:?}", body);
    let start = std::time::Instant::now();

    // Build the data lake storage manager
    let base_path = std::env::var("DATA_LAKE_PATH").unwrap_or_else(|_| "./data_lake".to_string());
    let local_config = crate::data_lake::storage::LocalConfig {
        base_path,
        max_size_bytes: None,
        retention_days: None,
    };
    let backend = crate::data_lake::storage::StorageBackend::Local(local_config);
    let storage_manager = crate::data_lake::storage::StorageManager::new(backend);

    // Query records from storage based on time range and source filters
    let mut all_records = Vec::new();

    // Determine which sources to query
    let source_ids = match &body.source_ids {
        Some(ids) if !ids.is_empty() => ids.clone(),
        _ => {
            // If no sources specified, get all enabled sources from database
            match sqlx::query_as::<_, (String,)>("SELECT id FROM data_lake_sources WHERE enabled = 1")
                .fetch_all(pool.get_ref())
                .await
            {
                Ok(rows) => rows.into_iter().map(|r| r.0).collect(),
                Err(e) => {
                    log::error!("Failed to fetch sources: {}", e);
                    return HttpResponse::InternalServerError().json(json!({
                        "error": "Failed to fetch data sources",
                        "details": e.to_string()
                    }));
                }
            }
        }
    };

    // Query records from each source
    for source_id in &source_ids {
        match storage_manager
            .retrieve_records(source_id, body.time_range.start, body.time_range.end)
            .await
        {
            Ok(records) => {
                all_records.extend(records);
            }
            Err(e) => {
                log::warn!("Failed to retrieve records for source {}: {}", source_id, e);
            }
        }
    }

    // Apply filters to records
    let filtered_records: Vec<_> = all_records
        .into_iter()
        .filter(|record| {
            // Apply each filter condition
            for filter in &body.filters {
                let field_value = record.data.get(&filter.field);
                let matches = match (&filter.operator, field_value) {
                    (FilterOperator::Equals, Some(v)) => v == &filter.value,
                    (FilterOperator::NotEquals, Some(v)) => v != &filter.value,
                    (FilterOperator::Contains, Some(v)) => {
                        if let (Some(haystack), Some(needle)) = (v.as_str(), filter.value.as_str()) {
                            haystack.contains(needle)
                        } else {
                            false
                        }
                    }
                    (FilterOperator::StartsWith, Some(v)) => {
                        if let (Some(haystack), Some(needle)) = (v.as_str(), filter.value.as_str()) {
                            haystack.starts_with(needle)
                        } else {
                            false
                        }
                    }
                    (FilterOperator::EndsWith, Some(v)) => {
                        if let (Some(haystack), Some(needle)) = (v.as_str(), filter.value.as_str()) {
                            haystack.ends_with(needle)
                        } else {
                            false
                        }
                    }
                    (FilterOperator::GreaterThan, Some(v)) => {
                        if let (Some(a), Some(b)) = (v.as_f64(), filter.value.as_f64()) {
                            a > b
                        } else {
                            false
                        }
                    }
                    (FilterOperator::LessThan, Some(v)) => {
                        if let (Some(a), Some(b)) = (v.as_f64(), filter.value.as_f64()) {
                            a < b
                        } else {
                            false
                        }
                    }
                    (FilterOperator::GreaterThanOrEqual, Some(v)) => {
                        if let (Some(a), Some(b)) = (v.as_f64(), filter.value.as_f64()) {
                            a >= b
                        } else {
                            false
                        }
                    }
                    (FilterOperator::LessThanOrEqual, Some(v)) => {
                        if let (Some(a), Some(b)) = (v.as_f64(), filter.value.as_f64()) {
                            a <= b
                        } else {
                            false
                        }
                    }
                    (FilterOperator::In, Some(v)) => {
                        if let Some(arr) = filter.value.as_array() {
                            arr.contains(v)
                        } else {
                            false
                        }
                    }
                    (FilterOperator::NotIn, Some(v)) => {
                        if let Some(arr) = filter.value.as_array() {
                            !arr.contains(v)
                        } else {
                            true
                        }
                    }
                    _ => true, // Field not present, skip filter
                };
                if !matches {
                    return false;
                }
            }
            true
        })
        .collect();

    let total_count = filtered_records.len() as i64;

    // Apply offset and limit
    let offset = body.offset.unwrap_or(0) as usize;
    let limit = body.limit.unwrap_or(100) as usize;

    let paginated_records: Vec<_> = filtered_records
        .into_iter()
        .skip(offset)
        .take(limit)
        .collect();

    let execution_time_ms = start.elapsed().as_millis() as i64;

    log::info!(
        "Data lake query completed: {} records in {}ms",
        total_count,
        execution_time_ms
    );

    HttpResponse::Ok().json(DataLakeQueryResponse {
        records: paginated_records,
        total_count,
        execution_time_ms,
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
