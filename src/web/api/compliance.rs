//! Compliance API endpoints
//!
//! Provides REST API endpoints for compliance framework management,
//! running compliance analysis on scans, and retrieving compliance findings.

use actix_web::{web, HttpResponse, Result};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::compliance::{
    analyzer::ComplianceAnalyzer,
    frameworks,
    types::{ComplianceFramework, ComplianceFinding, ComplianceSummary, ControlStatus},
};
use crate::db;
use crate::reports::compliance_report::{ComplianceReportData, ComplianceReportRequest, generate};
use crate::reports::types::ReportFormat;
use crate::web::auth;

/// Response for listing available compliance frameworks
#[derive(Debug, Serialize)]
pub struct FrameworkListResponse {
    pub frameworks: Vec<FrameworkInfo>,
}

/// Information about a compliance framework
#[derive(Debug, Serialize)]
pub struct FrameworkInfo {
    pub id: String,
    pub name: String,
    pub version: String,
    pub description: String,
    pub control_count: usize,
    pub automated_percentage: f32,
}

/// Response for framework controls
#[derive(Debug, Serialize)]
pub struct ControlListResponse {
    pub framework_id: String,
    pub framework_name: String,
    pub controls: Vec<ControlInfo>,
    pub categories: Vec<String>,
}

/// Information about a compliance control
#[derive(Debug, Serialize)]
pub struct ControlInfo {
    pub id: String,
    pub control_id: String,
    pub title: String,
    pub description: String,
    pub category: String,
    pub priority: String,
    pub automated: bool,
    pub remediation_guidance: Option<String>,
}

/// Request to run compliance analysis
#[derive(Debug, Deserialize)]
pub struct AnalyzeRequest {
    pub frameworks: Vec<String>,
}

/// Response for compliance analysis
#[derive(Debug, Serialize)]
pub struct AnalyzeResponse {
    pub summary: ComplianceSummary,
    pub findings: Vec<ComplianceFinding>,
}

/// Request to override a compliance finding
#[derive(Debug, Deserialize)]
pub struct OverrideFindingRequest {
    pub status: String,
    pub reason: String,
}

/// GET /api/compliance/frameworks
/// List all available compliance frameworks
pub async fn list_frameworks(
    _claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let all_frameworks = vec![
        ComplianceFramework::PciDss4,
        ComplianceFramework::Nist80053,
        ComplianceFramework::NistCsf,
        ComplianceFramework::CisBenchmarks,
        ComplianceFramework::Hipaa,
        ComplianceFramework::Soc2,
        ComplianceFramework::Ferpa,
        ComplianceFramework::OwaspTop10,
    ];

    let frameworks: Vec<FrameworkInfo> = all_frameworks
        .iter()
        .map(|f| {
            let controls = frameworks::get_controls(*f);
            let automated_count = controls.iter().filter(|c| c.automated_check).count();
            let automated_percentage = if controls.is_empty() {
                0.0
            } else {
                (automated_count as f32 / controls.len() as f32) * 100.0
            };

            FrameworkInfo {
                id: f.id().to_string(),
                name: f.name().to_string(),
                version: f.version().to_string(),
                description: f.description().to_string(),
                control_count: controls.len(),
                automated_percentage,
            }
        })
        .collect();

    Ok(HttpResponse::Ok().json(FrameworkListResponse { frameworks }))
}

/// GET /api/compliance/frameworks/{id}
/// Get details about a specific framework
pub async fn get_framework(
    _claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let framework_id = path.into_inner();

    let framework = match ComplianceFramework::from_id(&framework_id) {
        Some(f) => f,
        None => {
            return Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": "Framework not found",
                "framework_id": framework_id
            })));
        }
    };

    let controls = frameworks::get_controls(framework);
    let automated_count = controls.iter().filter(|c| c.automated_check).count();
    let automated_percentage = if controls.is_empty() {
        0.0
    } else {
        (automated_count as f32 / controls.len() as f32) * 100.0
    };

    Ok(HttpResponse::Ok().json(FrameworkInfo {
        id: framework.id().to_string(),
        name: framework.name().to_string(),
        version: framework.version().to_string(),
        description: framework.description().to_string(),
        control_count: controls.len(),
        automated_percentage,
    }))
}

/// GET /api/compliance/frameworks/{id}/controls
/// Get all controls for a specific framework
pub async fn get_framework_controls(
    _claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let framework_id = path.into_inner();

    let framework = match ComplianceFramework::from_id(&framework_id) {
        Some(f) => f,
        None => {
            return Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": "Framework not found",
                "framework_id": framework_id
            })));
        }
    };

    let controls = frameworks::get_controls(framework);
    let categories = frameworks::get_categories(framework);

    let control_list: Vec<ControlInfo> = controls
        .iter()
        .map(|c| ControlInfo {
            id: c.id.clone(),
            control_id: c.control_id.clone(),
            title: c.title.clone(),
            description: c.description.clone(),
            category: c.category.clone(),
            priority: format!("{:?}", c.priority),
            automated: c.automated_check,
            remediation_guidance: c.remediation_guidance.clone(),
        })
        .collect();

    Ok(HttpResponse::Ok().json(ControlListResponse {
        framework_id: framework.id().to_string(),
        framework_name: framework.name().to_string(),
        controls: control_list,
        categories,
    }))
}

/// POST /api/scans/{id}/compliance
/// Run compliance analysis on a scan
pub async fn analyze_scan_compliance(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
    body: web::Json<AnalyzeRequest>,
) -> Result<HttpResponse> {
    let scan_id = path.into_inner();

    // Get the scan
    let scan = match db::get_scan_by_id(pool.get_ref(), &scan_id).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            return Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": "Scan not found"
            })));
        }
        Err(e) => {
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Database error: {}", e)
            })));
        }
    };

    // Check ownership
    if scan.user_id != claims.sub {
        return Ok(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Not authorized to access this scan"
        })));
    }

    // Check scan status
    if scan.status != "completed" {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Scan must be completed before compliance analysis",
            "current_status": scan.status
        })));
    }

    // Parse frameworks
    let frameworks: Vec<ComplianceFramework> = body
        .frameworks
        .iter()
        .filter_map(|id| ComplianceFramework::from_id(id))
        .collect();

    if frameworks.is_empty() {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "No valid frameworks specified",
            "valid_frameworks": ["pci_dss", "nist_800_53", "nist_csf", "cis", "hipaa", "soc2", "ferpa", "owasp", "owasp_top10"]
        })));
    }

    // Parse scan results
    let hosts: Vec<crate::types::HostInfo> = match &scan.results {
        Some(results_json) => {
            serde_json::from_str(results_json).unwrap_or_default()
        }
        None => Vec::new(),
    };

    // Run compliance analysis
    let analyzer = ComplianceAnalyzer::new(frameworks);
    let summary = match analyzer.analyze(&hosts, &scan_id).await {
        Ok(s) => s,
        Err(e) => {
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Compliance analysis failed: {}", e)
            })));
        }
    };

    // Note: In a full implementation, we would store findings in the database here
    // For now, we return the analysis results directly

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "scan_id": scan_id,
        "summary": summary,
        "message": "Compliance analysis completed successfully"
    })))
}

/// GET /api/scans/{id}/compliance
/// Get compliance results for a scan (if previously analyzed)
pub async fn get_scan_compliance(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let scan_id = path.into_inner();

    // Get the scan
    let scan = match db::get_scan_by_id(pool.get_ref(), &scan_id).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            return Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": "Scan not found"
            })));
        }
        Err(e) => {
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Database error: {}", e)
            })));
        }
    };

    // Check ownership
    if scan.user_id != claims.sub {
        return Ok(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Not authorized to access this scan"
        })));
    }

    // For now, run a quick analysis with common frameworks
    // In a full implementation, this would retrieve stored compliance results from DB
    let frameworks = vec![
        ComplianceFramework::PciDss4,
        ComplianceFramework::Nist80053,
        ComplianceFramework::CisBenchmarks,
        ComplianceFramework::OwaspTop10,
    ];

    let hosts: Vec<crate::types::HostInfo> = match &scan.results {
        Some(results_json) => {
            serde_json::from_str(results_json).unwrap_or_default()
        }
        None => Vec::new(),
    };

    let analyzer = ComplianceAnalyzer::new(frameworks);
    let summary = match analyzer.analyze(&hosts, &scan_id).await {
        Ok(s) => s,
        Err(e) => {
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Compliance analysis failed: {}", e)
            })));
        }
    };

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "scan_id": scan_id,
        "summary": summary
    })))
}

/// POST /api/scans/{id}/compliance/report
/// Generate a compliance report for a scan
pub async fn generate_compliance_report(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
    body: web::Json<ComplianceReportRequest>,
) -> Result<HttpResponse> {
    let scan_id = path.into_inner();

    // Get the scan
    let scan = match db::get_scan_by_id(pool.get_ref(), &scan_id).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            return Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": "Scan not found"
            })));
        }
        Err(e) => {
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Database error: {}", e)
            })));
        }
    };

    // Check ownership
    if scan.user_id != claims.sub {
        return Ok(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Not authorized to access this scan"
        })));
    }

    // Check scan status
    if scan.status != "completed" {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Scan must be completed before generating compliance report",
            "current_status": scan.status
        })));
    }

    // Parse frameworks
    let frameworks: Vec<ComplianceFramework> = if body.frameworks.is_empty() {
        // Default frameworks if none specified
        vec![
            ComplianceFramework::PciDss4,
            ComplianceFramework::Nist80053,
            ComplianceFramework::CisBenchmarks,
            ComplianceFramework::OwaspTop10,
        ]
    } else {
        body.frameworks
            .iter()
            .filter_map(|id| ComplianceFramework::from_id(id))
            .collect()
    };

    if frameworks.is_empty() {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "No valid frameworks specified",
            "valid_frameworks": ["pci_dss", "nist_800_53", "nist_csf", "cis", "hipaa", "soc2", "ferpa", "owasp", "owasp_top10"]
        })));
    }

    // Parse scan results
    let hosts: Vec<crate::types::HostInfo> = match &scan.results {
        Some(results_json) => {
            serde_json::from_str(results_json).unwrap_or_default()
        }
        None => Vec::new(),
    };

    // Run compliance analysis
    let analyzer = ComplianceAnalyzer::new(frameworks);
    let summary = match analyzer.analyze(&hosts, &scan_id).await {
        Ok(s) => s,
        Err(e) => {
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Compliance analysis failed: {}", e)
            })));
        }
    };

    // Generate report
    let report_id = uuid::Uuid::new_v4().to_string();
    let report_name = format!("Compliance Report - {}", scan.name);

    let report_data = ComplianceReportData {
        id: report_id.clone(),
        name: report_name,
        scan_id: scan_id.clone(),
        scan_name: scan.name.clone(),
        created_at: chrono::Utc::now(),
        scan_date: scan.completed_at.unwrap_or(scan.created_at),
        summary,
        company_name: None,
        assessor_name: None,
        classification: Some("CONFIDENTIAL".to_string()),
        include_evidence: body.include_evidence,
    };

    let reports_dir = std::env::var("REPORTS_DIR").unwrap_or_else(|_| "./reports".to_string());

    let (file_path, file_size) = match generate(&report_data, body.format, &reports_dir).await {
        Ok(result) => result,
        Err(e) => {
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Report generation failed: {}", e)
            })));
        }
    };

    // Return download URL
    let download_url = format!("/api/compliance/reports/{}/download", report_id);

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "report_id": report_id,
        "file_path": file_path,
        "file_size": file_size,
        "format": body.format,
        "download_url": download_url,
        "message": "Compliance report generated successfully"
    })))
}

/// GET /api/compliance/reports/{id}/download
/// Download a compliance report
pub async fn download_compliance_report(
    _claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let report_id = path.into_inner();
    let reports_dir = std::env::var("REPORTS_DIR").unwrap_or_else(|_| "./reports".to_string());

    // Try to find the report file (check all formats)
    for format in &["pdf", "html", "json"] {
        let file_path = format!("{}/{}.{}", reports_dir, report_id, format);

        if let Ok(content) = tokio::fs::read(&file_path).await {
            let content_type = match *format {
                "pdf" => "application/pdf",
                "html" => "text/html",
                "json" => "application/json",
                _ => "application/octet-stream",
            };

            let filename = format!("compliance_report_{}.{}", report_id, format);

            return Ok(HttpResponse::Ok()
                .content_type(content_type)
                .insert_header(("Content-Disposition", format!("attachment; filename=\"{}\"", filename)))
                .body(content));
        }
    }

    Ok(HttpResponse::NotFound().json(serde_json::json!({
        "error": "Report file not found"
    })))
}

/// Configure compliance routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/compliance")
            .route("/frameworks", web::get().to(list_frameworks))
            .route("/frameworks/{id}", web::get().to(get_framework))
            .route("/frameworks/{id}/controls", web::get().to(get_framework_controls))
            .route("/reports/{id}/download", web::get().to(download_compliance_report))
    );
}
