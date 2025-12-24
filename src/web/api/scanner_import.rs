//! Scanner Import API
//!
//! Provides endpoints for importing scan results from external scanners (Nessus, Qualys).

use actix_multipart::Multipart;
use actix_web::{web, HttpResponse};
use anyhow::Result;
use chrono::Utc;
use futures::{StreamExt, TryStreamExt};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use uuid::Uuid;

use crate::integrations::scanner_import::{
    ImportedScan, NessusParser, QualysParser,
};
use crate::types::Severity;
use crate::web::auth;
use crate::web::error::ApiError;

/// Import statistics response
#[derive(Debug, Serialize)]
pub struct ImportStats {
    pub total_imports: i64,
    pub pending_imports: i64,
    pub completed_imports: i64,
    pub failed_imports: i64,
    pub total_findings_imported: i64,
    pub total_hosts_imported: i64,
    pub by_source: Vec<SourceStats>,
}

#[derive(Debug, Serialize)]
pub struct SourceStats {
    pub source: String,
    pub count: i64,
    pub findings: i64,
}

/// Import record from database
#[derive(Debug, Serialize)]
pub struct ImportRecord {
    pub id: String,
    pub source: String,
    pub original_filename: String,
    pub scanner_name: Option<String>,
    pub scan_name: Option<String>,
    pub scan_date: Option<String>,
    pub host_count: i32,
    pub finding_count: i32,
    pub critical_count: i32,
    pub high_count: i32,
    pub medium_count: i32,
    pub low_count: i32,
    pub status: String,
    pub error_message: Option<String>,
    pub imported_at: String,
}

/// Import upload response
#[derive(Debug, Serialize)]
pub struct ImportResponse {
    pub id: String,
    pub status: String,
    pub message: String,
    pub host_count: usize,
    pub finding_count: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
}

/// Configure scanner import routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/import")
            .route("/nessus", web::post().to(import_nessus))
            .route("/qualys", web::post().to(import_qualys))
            .route("", web::get().to(list_imports))
            .route("/stats", web::get().to(get_import_stats))
            .route("/{id}", web::get().to(get_import))
            .route("/{id}", web::delete().to(delete_import))
            .route("/{id}/hosts", web::get().to(get_import_hosts))
            .route("/{id}/findings", web::get().to(get_import_findings)),
    );
}

/// Import Nessus scan file (.nessus XML or CSV)
async fn import_nessus(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    mut payload: Multipart,
) -> Result<HttpResponse, ApiError> {
    let (filename, content) = extract_file_from_multipart(&mut payload).await?;

    let scan = if filename.ends_with(".csv") {
        NessusParser::parse_csv(std::io::Cursor::new(content.as_bytes()))
            .map_err(|e| ApiError::bad_request(format!("Failed to parse Nessus CSV: {}", e)))?
    } else {
        NessusParser::parse_xml(&content)
            .map_err(|e| ApiError::bad_request(format!("Failed to parse Nessus XML: {}", e)))?
    };

    let response = save_imported_scan(&pool, &claims.sub, &filename, scan).await?;

    Ok(HttpResponse::Ok().json(response))
}

/// Import Qualys scan file (XML)
async fn import_qualys(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    mut payload: Multipart,
) -> Result<HttpResponse, ApiError> {
    let (filename, content) = extract_file_from_multipart(&mut payload).await?;

    let scan = QualysParser::parse_xml(&content)
        .map_err(|e| ApiError::bad_request(format!("Failed to parse Qualys XML: {}", e)))?;

    let response = save_imported_scan(&pool, &claims.sub, &filename, scan).await?;

    Ok(HttpResponse::Ok().json(response))
}

/// Extract file from multipart upload
async fn extract_file_from_multipart(payload: &mut Multipart) -> Result<(String, String), ApiError> {
    let mut filename = String::new();
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

    let content_str = String::from_utf8(content)
        .map_err(|_| ApiError::bad_request("File content is not valid UTF-8"))?;

    Ok((filename, content_str))
}

/// Save imported scan to database
async fn save_imported_scan(
    pool: &SqlitePool,
    user_id: &str,
    filename: &str,
    scan: ImportedScan,
) -> Result<ImportResponse, ApiError> {
    let import_id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    // Insert main import record
    sqlx::query(
        r#"
        INSERT INTO imported_scans (
            id, user_id, source, original_filename, scanner_name, scanner_version,
            policy_name, scan_name, scan_date, host_count, finding_count,
            critical_count, high_count, medium_count, low_count, info_count,
            status, imported_at, processing_completed_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'completed', ?, ?)
        "#,
    )
    .bind(&import_id)
    .bind(user_id)
    .bind(scan.source.to_string())
    .bind(filename)
    .bind(&scan.scanner_name)
    .bind(&scan.scanner_version)
    .bind(&scan.policy_name)
    .bind(&scan.scan_name)
    .bind(scan.scan_start.map(|d| d.to_rfc3339()))
    .bind(scan.hosts.len() as i32)
    .bind(scan.total_findings as i32)
    .bind(scan.critical_count as i32)
    .bind(scan.high_count as i32)
    .bind(scan.medium_count as i32)
    .bind(scan.low_count as i32)
    .bind(scan.info_count as i32)
    .bind(&now)
    .bind(&now)
    .execute(pool)
    .await
    .map_err(|e| ApiError::internal(format!("Failed to save import: {}", e)))?;

    // Insert hosts and findings
    for host in &scan.hosts {
        let host_id = Uuid::new_v4().to_string();

        sqlx::query(
            r#"
            INSERT INTO imported_hosts (
                id, import_id, ip, hostname, fqdn, mac_address, os, os_confidence,
                netbios_name, critical_count, high_count, medium_count, low_count,
                info_count, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&host_id)
        .bind(&import_id)
        .bind(&host.ip)
        .bind(&host.hostname)
        .bind(&host.fqdn)
        .bind(&host.mac_address)
        .bind(&host.os)
        .bind(host.os_confidence.map(|c| c as i32))
        .bind(&host.netbios_name)
        .bind(host.critical_count as i32)
        .bind(host.high_count as i32)
        .bind(host.medium_count as i32)
        .bind(host.low_count as i32)
        .bind(host.info_count as i32)
        .bind(&now)
        .execute(pool)
        .await
        .map_err(|e| ApiError::internal(format!("Failed to save host: {}", e)))?;

        // Insert findings for this host
        for finding in &host.findings {
            let finding_id = Uuid::new_v4().to_string();

            sqlx::query(
                r#"
                INSERT INTO imported_findings (
                    id, import_id, imported_host_id, plugin_id, title, description,
                    severity, cvss_score, cvss_vector, cve_ids, cwe_ids, port,
                    protocol, service, solution, see_also, plugin_output,
                    first_discovered, last_observed, exploit_available,
                    exploitability_ease, patch_published, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                "#,
            )
            .bind(&finding_id)
            .bind(&import_id)
            .bind(&host_id)
            .bind(&finding.plugin_id)
            .bind(&finding.title)
            .bind(&finding.description)
            .bind(severity_to_string(&finding.severity))
            .bind(finding.cvss_score)
            .bind(&finding.cvss_vector)
            .bind(serde_json::to_string(&finding.cve_ids).unwrap_or_default())
            .bind(serde_json::to_string(&finding.cwe_ids).unwrap_or_default())
            .bind(finding.port.map(|p| p as i32))
            .bind(&finding.protocol)
            .bind(&finding.service)
            .bind(&finding.solution)
            .bind(serde_json::to_string(&finding.see_also).unwrap_or_default())
            .bind(&finding.plugin_output)
            .bind(finding.first_discovered.map(|d| d.to_rfc3339()))
            .bind(finding.last_observed.map(|d| d.to_rfc3339()))
            .bind(finding.exploit_available)
            .bind(&finding.exploitability_ease)
            .bind(finding.patch_published.map(|d| d.to_rfc3339()))
            .bind(&now)
            .execute(pool)
            .await
            .map_err(|e| ApiError::internal(format!("Failed to save finding: {}", e)))?;
        }
    }

    Ok(ImportResponse {
        id: import_id,
        status: "completed".to_string(),
        message: format!(
            "Successfully imported {} hosts with {} findings",
            scan.hosts.len(),
            scan.total_findings
        ),
        host_count: scan.hosts.len(),
        finding_count: scan.total_findings,
        critical_count: scan.critical_count,
        high_count: scan.high_count,
        medium_count: scan.medium_count,
        low_count: scan.low_count,
    })
}

fn severity_to_string(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
    }
}

/// List all imports for user
async fn list_imports(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse, ApiError> {
    use sqlx::Row;

    let rows = sqlx::query(
        r#"
        SELECT id, source, original_filename, scanner_name, scan_name, scan_date,
               host_count, finding_count, critical_count, high_count, medium_count,
               low_count, status, error_message, imported_at
        FROM imported_scans
        WHERE user_id = ?
        ORDER BY imported_at DESC
        "#,
    )
    .bind(&claims.sub)
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Failed to list imports: {}", e)))?;

    let imports: Vec<ImportRecord> = rows
        .iter()
        .map(|row| ImportRecord {
            id: row.get("id"),
            source: row.get("source"),
            original_filename: row.get("original_filename"),
            scanner_name: row.get("scanner_name"),
            scan_name: row.get("scan_name"),
            scan_date: row.get("scan_date"),
            host_count: row.get("host_count"),
            finding_count: row.get("finding_count"),
            critical_count: row.get("critical_count"),
            high_count: row.get("high_count"),
            medium_count: row.get("medium_count"),
            low_count: row.get("low_count"),
            status: row.get("status"),
            error_message: row.get("error_message"),
            imported_at: row.get("imported_at"),
        })
        .collect();

    Ok(HttpResponse::Ok().json(imports))
}

/// Get import statistics
async fn get_import_stats(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse, ApiError> {
    use sqlx::Row;

    // Overall stats
    let overall = sqlx::query(
        r#"
        SELECT
            COUNT(*) as total,
            SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) as pending,
            SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as completed,
            SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) as failed,
            SUM(finding_count) as total_findings,
            SUM(host_count) as total_hosts
        FROM imported_scans
        WHERE user_id = ?
        "#,
    )
    .bind(&claims.sub)
    .fetch_one(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Failed to get stats: {}", e)))?;

    // By source
    let by_source_rows = sqlx::query(
        r#"
        SELECT source, COUNT(*) as count, SUM(finding_count) as findings
        FROM imported_scans
        WHERE user_id = ?
        GROUP BY source
        "#,
    )
    .bind(&claims.sub)
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Failed to get source stats: {}", e)))?;

    let by_source: Vec<SourceStats> = by_source_rows
        .iter()
        .map(|row| SourceStats {
            source: row.get("source"),
            count: row.get("count"),
            findings: row.get::<Option<i64>, _>("findings").unwrap_or(0),
        })
        .collect();

    let stats = ImportStats {
        total_imports: overall.get("total"),
        pending_imports: overall.get::<Option<i64>, _>("pending").unwrap_or(0),
        completed_imports: overall.get::<Option<i64>, _>("completed").unwrap_or(0),
        failed_imports: overall.get::<Option<i64>, _>("failed").unwrap_or(0),
        total_findings_imported: overall.get::<Option<i64>, _>("total_findings").unwrap_or(0),
        total_hosts_imported: overall.get::<Option<i64>, _>("total_hosts").unwrap_or(0),
        by_source,
    };

    Ok(HttpResponse::Ok().json(stats))
}

/// Get single import details
async fn get_import(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    use sqlx::Row;

    let id = path.into_inner();

    let row = sqlx::query(
        r#"
        SELECT id, source, original_filename, scanner_name, scan_name, scan_date,
               host_count, finding_count, critical_count, high_count, medium_count,
               low_count, status, error_message, imported_at
        FROM imported_scans
        WHERE id = ? AND user_id = ?
        "#,
    )
    .bind(&id)
    .bind(&claims.sub)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Failed to get import: {}", e)))?;

    match row {
        Some(row) => {
            let import = ImportRecord {
                id: row.get("id"),
                source: row.get("source"),
                original_filename: row.get("original_filename"),
                scanner_name: row.get("scanner_name"),
                scan_name: row.get("scan_name"),
                scan_date: row.get("scan_date"),
                host_count: row.get("host_count"),
                finding_count: row.get("finding_count"),
                critical_count: row.get("critical_count"),
                high_count: row.get("high_count"),
                medium_count: row.get("medium_count"),
                low_count: row.get("low_count"),
                status: row.get("status"),
                error_message: row.get("error_message"),
                imported_at: row.get("imported_at"),
            };
            Ok(HttpResponse::Ok().json(import))
        }
        None => Err(ApiError::not_found("Import not found")),
    }
}

/// Delete import
async fn delete_import(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let id = path.into_inner();

    let result = sqlx::query(
        "DELETE FROM imported_scans WHERE id = ? AND user_id = ?",
    )
    .bind(&id)
    .bind(&claims.sub)
    .execute(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Failed to delete import: {}", e)))?;

    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("Import not found"));
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "message": "Import deleted"
    })))
}

/// Get hosts from an import
async fn get_import_hosts(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    use sqlx::Row;

    let id = path.into_inner();

    // Verify ownership
    let exists = sqlx::query_scalar::<_, i32>(
        "SELECT 1 FROM imported_scans WHERE id = ? AND user_id = ?",
    )
    .bind(&id)
    .bind(&claims.sub)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Failed to verify import: {}", e)))?;

    if exists.is_none() {
        return Err(ApiError::not_found("Import not found"));
    }

    let rows = sqlx::query(
        r#"
        SELECT id, ip, hostname, fqdn, mac_address, os, netbios_name,
               critical_count, high_count, medium_count, low_count, info_count
        FROM imported_hosts
        WHERE import_id = ?
        ORDER BY ip
        "#,
    )
    .bind(&id)
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Failed to get hosts: {}", e)))?;

    #[derive(Serialize)]
    struct HostResponse {
        id: String,
        ip: String,
        hostname: Option<String>,
        fqdn: Option<String>,
        mac_address: Option<String>,
        os: Option<String>,
        netbios_name: Option<String>,
        critical_count: i32,
        high_count: i32,
        medium_count: i32,
        low_count: i32,
        info_count: i32,
    }

    let hosts: Vec<HostResponse> = rows
        .iter()
        .map(|row| HostResponse {
            id: row.get("id"),
            ip: row.get("ip"),
            hostname: row.get("hostname"),
            fqdn: row.get("fqdn"),
            mac_address: row.get("mac_address"),
            os: row.get("os"),
            netbios_name: row.get("netbios_name"),
            critical_count: row.get("critical_count"),
            high_count: row.get("high_count"),
            medium_count: row.get("medium_count"),
            low_count: row.get("low_count"),
            info_count: row.get("info_count"),
        })
        .collect();

    Ok(HttpResponse::Ok().json(hosts))
}

/// Findings query params
#[derive(Debug, Deserialize)]
pub struct FindingsQuery {
    pub severity: Option<String>,
    pub host_id: Option<String>,
    pub limit: Option<i32>,
    pub offset: Option<i32>,
}

/// Get findings from an import
async fn get_import_findings(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
    query: web::Query<FindingsQuery>,
) -> Result<HttpResponse, ApiError> {
    use sqlx::Row;

    let id = path.into_inner();

    // Verify ownership
    let exists = sqlx::query_scalar::<_, i32>(
        "SELECT 1 FROM imported_scans WHERE id = ? AND user_id = ?",
    )
    .bind(&id)
    .bind(&claims.sub)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Failed to verify import: {}", e)))?;

    if exists.is_none() {
        return Err(ApiError::not_found("Import not found"));
    }

    let limit = query.limit.unwrap_or(100).min(500);
    let offset = query.offset.unwrap_or(0);

    let mut sql = String::from(
        r#"
        SELECT f.id, f.plugin_id, f.title, f.description, f.severity, f.cvss_score,
               f.cvss_vector, f.cve_ids, f.port, f.protocol, f.service, f.solution,
               f.exploit_available, h.ip as host_ip
        FROM imported_findings f
        JOIN imported_hosts h ON f.imported_host_id = h.id
        WHERE f.import_id = ?
        "#,
    );

    if let Some(ref severity) = query.severity {
        sql.push_str(" AND f.severity = '");
        sql.push_str(severity);
        sql.push('\'');
    }

    if let Some(ref host_id) = query.host_id {
        sql.push_str(" AND f.imported_host_id = '");
        sql.push_str(host_id);
        sql.push('\'');
    }

    sql.push_str(" ORDER BY CASE f.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END, f.title");
    sql.push_str(&format!(" LIMIT {} OFFSET {}", limit, offset));

    let rows = sqlx::query(&sql)
        .bind(&id)
        .fetch_all(pool.get_ref())
        .await
        .map_err(|e| ApiError::internal(format!("Failed to get findings: {}", e)))?;

    #[derive(Serialize)]
    struct FindingResponse {
        id: String,
        plugin_id: Option<String>,
        title: String,
        description: Option<String>,
        severity: String,
        cvss_score: Option<f64>,
        cvss_vector: Option<String>,
        cve_ids: Vec<String>,
        port: Option<i32>,
        protocol: Option<String>,
        service: Option<String>,
        solution: Option<String>,
        exploit_available: bool,
        host_ip: String,
    }

    let findings: Vec<FindingResponse> = rows
        .iter()
        .map(|row| {
            let cve_ids_str: String = row.get::<Option<String>, _>("cve_ids").unwrap_or_default();
            let cve_ids: Vec<String> = serde_json::from_str(&cve_ids_str).unwrap_or_default();

            FindingResponse {
                id: row.get("id"),
                plugin_id: row.get("plugin_id"),
                title: row.get("title"),
                description: row.get("description"),
                severity: row.get("severity"),
                cvss_score: row.get("cvss_score"),
                cvss_vector: row.get("cvss_vector"),
                cve_ids,
                port: row.get("port"),
                protocol: row.get("protocol"),
                service: row.get("service"),
                solution: row.get("solution"),
                exploit_available: row.get::<i32, _>("exploit_available") == 1,
                host_ip: row.get("host_ip"),
            }
        })
        .collect();

    Ok(HttpResponse::Ok().json(findings))
}
