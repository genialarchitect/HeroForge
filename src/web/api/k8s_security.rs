//! Kubernetes Security API Endpoints
//!
//! Provides API endpoints for:
//! - CIS Kubernetes Benchmark scanning
//! - RBAC analysis
//! - Network Policy auditing
//! - Pod Security Standards validation

use actix_web::{web, HttpResponse};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use uuid::Uuid;
use utoipa::ToSchema;

use crate::scanner::container::{
    k8s_cis_benchmark::{CisBenchmarkScanner, CisSeverity, CisControlStatus},
    k8s_rbac_analyzer::{RbacAnalyzer, RbacSeverity},
    k8s_network_policy::{NetworkPolicyAnalyzer, NetworkPolicySeverity},
    k8s_pss::{PssValidator, PssProfile, PssSeverity},
};
use crate::web::auth::jwt::Claims;
use crate::web::error::ApiError;

/// K8s security scan types
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum K8sScanType {
    CisBenchmark,
    Rbac,
    NetworkPolicy,
    Pss,
    All,
}

/// Request to start a K8s security scan
#[derive(Debug, Deserialize, ToSchema)]
pub struct StartK8sScanRequest {
    /// Scan types to perform
    pub scan_types: Vec<K8sScanType>,
    /// Kubernetes manifest content (YAML, can be multi-document)
    pub manifests: String,
    /// Cluster name (optional, for labeling)
    pub cluster_name: Option<String>,
    /// Namespaces to analyze (empty = all)
    pub namespaces: Option<Vec<String>>,
    /// Target PSS profile for validation
    pub pss_profile: Option<String>,
}

/// Request to analyze manifests immediately
#[derive(Debug, Deserialize, ToSchema)]
pub struct AnalyzeK8sManifestRequest {
    /// Kubernetes manifest content (YAML)
    pub content: String,
    /// Analysis type
    pub analysis_type: String,
    /// Target PSS profile (for pss analysis)
    pub pss_profile: Option<String>,
}

/// K8s scan status
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum K8sScanStatus {
    Pending,
    Running,
    Completed,
    Failed,
}

/// K8s security scan summary
#[derive(Debug, Serialize, ToSchema)]
pub struct K8sScanSummary {
    pub id: String,
    pub status: K8sScanStatus,
    pub scan_types: Vec<String>,
    pub cluster_name: Option<String>,
    pub total_findings: i64,
    pub critical_count: i64,
    pub high_count: i64,
    pub medium_count: i64,
    pub low_count: i64,
    pub cis_score: Option<f64>,
    pub pss_compliant_baseline: bool,
    pub pss_compliant_restricted: bool,
    pub created_at: String,
    pub completed_at: Option<String>,
}

/// CIS finding response
#[derive(Debug, Serialize, ToSchema)]
pub struct CisFindingResponse {
    pub id: String,
    pub control_id: String,
    pub control_title: String,
    pub section: String,
    pub status: String,
    pub severity: String,
    pub description: Option<String>,
    pub remediation: Option<String>,
    pub resource_name: Option<String>,
    pub namespace: Option<String>,
}

/// RBAC finding response
#[derive(Debug, Serialize, ToSchema)]
pub struct RbacFindingResponse {
    pub id: String,
    pub finding_type: String,
    pub severity: String,
    pub subject_kind: Option<String>,
    pub subject_name: Option<String>,
    pub role_name: Option<String>,
    pub namespace: Option<String>,
    pub description: String,
    pub remediation: String,
}

/// Network policy finding response
#[derive(Debug, Serialize, ToSchema)]
pub struct NetworkPolicyFindingResponse {
    pub id: String,
    pub finding_type: String,
    pub severity: String,
    pub namespace: String,
    pub policy_name: Option<String>,
    pub affected_pods: Vec<String>,
    pub description: String,
    pub remediation: String,
}

/// PSS violation response
#[derive(Debug, Serialize, ToSchema)]
pub struct PssFindingResponse {
    pub id: String,
    pub violation_type: String,
    pub severity: String,
    pub profile: String,
    pub workload_name: String,
    pub workload_kind: String,
    pub namespace: String,
    pub container_name: Option<String>,
    pub field_path: String,
    pub current_value: String,
    pub description: String,
    pub remediation: String,
}

/// Immediate analysis response
#[derive(Debug, Serialize, ToSchema)]
pub struct K8sAnalysisResponse {
    pub analysis_type: String,
    pub findings_count: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub findings: serde_json::Value,
}

/// K8s security stats
#[derive(Debug, Serialize, ToSchema)]
pub struct K8sSecurityStats {
    pub total_scans: i64,
    pub scans_this_month: i64,
    pub total_cis_findings: i64,
    pub total_rbac_findings: i64,
    pub total_network_findings: i64,
    pub total_pss_findings: i64,
    pub avg_cis_score: Option<f64>,
    pub clusters_scanned: i64,
}

/// Start a K8s security scan
#[utoipa::path(
    post,
    path = "/api/k8s-security/scan",
    request_body = StartK8sScanRequest,
    responses(
        (status = 202, description = "Scan started", body = K8sScanSummary),
        (status = 400, description = "Bad request"),
        (status = 401, description = "Unauthorized"),
    ),
    security(("bearer_auth" = [])),
    tag = "K8s Security"
)]
pub async fn start_scan(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<Claims>,
    req: web::Json<StartK8sScanRequest>,
) -> Result<HttpResponse, ApiError> {
    let user_id = &claims.sub;
    let scan_id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    // Determine scan types
    let scan_types: Vec<String> = if req.scan_types.contains(&K8sScanType::All) {
        vec!["cis_benchmark".to_string(), "rbac".to_string(), "network_policy".to_string(), "pss".to_string()]
    } else {
        req.scan_types.iter().map(|t| match t {
            K8sScanType::CisBenchmark => "cis_benchmark".to_string(),
            K8sScanType::Rbac => "rbac".to_string(),
            K8sScanType::NetworkPolicy => "network_policy".to_string(),
            K8sScanType::Pss => "pss".to_string(),
            K8sScanType::All => "all".to_string(),
        }).collect()
    };

    let namespaces_json = req.namespaces.as_ref()
        .map(|ns| serde_json::to_string(ns).unwrap_or_default())
        .unwrap_or_default();

    // Create scan record
    sqlx::query(
        r#"
        INSERT INTO k8s_security_scans (
            id, user_id, cluster_name, namespaces, scan_types, status, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, 'pending', ?, ?)
        "#,
    )
    .bind(&scan_id)
    .bind(user_id)
    .bind(&req.cluster_name)
    .bind(&namespaces_json)
    .bind(serde_json::to_string(&scan_types).unwrap_or_default())
    .bind(&now)
    .bind(&now)
    .execute(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Failed to create scan: {}", e)))?;

    // Parse manifests
    let manifests: Vec<serde_yaml::Value> = parse_yaml_documents(&req.manifests)?;

    // Run analysis
    let mut total_findings = 0i64;
    let mut critical_count = 0i64;
    let mut high_count = 0i64;
    let mut medium_count = 0i64;
    let mut low_count = 0i64;
    let mut cis_score: Option<f64> = None;
    let mut pss_compliant_baseline = false;
    let mut pss_compliant_restricted = false;

    // Update status to running
    sqlx::query("UPDATE k8s_security_scans SET status = 'running', started_at = ? WHERE id = ?")
        .bind(&now)
        .bind(&scan_id)
        .execute(pool.get_ref())
        .await?;

    // CIS Benchmark Analysis
    if scan_types.contains(&"cis_benchmark".to_string()) {
        let scanner = CisBenchmarkScanner::new();
        // Convert YAML manifests to JSON for CIS scanner
        let json_manifests: Vec<serde_json::Value> = manifests
            .iter()
            .filter_map(|y| serde_json::to_value(y).ok())
            .collect();
        let results = scanner.analyze_manifests(&json_manifests, &scan_id);

        for finding in &results.findings {
            let finding_id = Uuid::new_v4().to_string();
            let severity_str = match finding.severity {
                CisSeverity::Critical => { critical_count += 1; "critical" }
                CisSeverity::High => { high_count += 1; "high" }
                CisSeverity::Medium => { medium_count += 1; "medium" }
                CisSeverity::Low | CisSeverity::Info => { low_count += 1; "low" }
            };
            let status_str = match finding.status {
                CisControlStatus::Pass => "pass",
                CisControlStatus::Fail => "fail",
                CisControlStatus::Warn => "warn",
                CisControlStatus::Info => "info",
                CisControlStatus::Manual => "manual",
                CisControlStatus::NotApplicable => "not_applicable",
            };

            sqlx::query(
                r#"
                INSERT INTO k8s_cis_findings (
                    id, scan_id, control_id, control_title, section, status, severity,
                    description, remediation, resource_name, namespace, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                "#,
            )
            .bind(&finding_id)
            .bind(&scan_id)
            .bind(&finding.control_id)
            .bind(&finding.control_title)
            .bind(&finding.section)
            .bind(status_str)
            .bind(severity_str)
            .bind(&finding.remediation)
            .bind(&finding.remediation)
            .bind(&finding.resource_name)
            .bind(&finding.namespace)
            .bind(&now)
            .execute(pool.get_ref())
            .await?;

            total_findings += 1;
        }

        // Calculate CIS score (percentage of passed controls)
        let total_controls = results.findings.len() as f64;
        let passed = results.findings.iter().filter(|f| f.status == CisControlStatus::Pass).count() as f64;
        if total_controls > 0.0 {
            cis_score = Some((passed / total_controls) * 100.0);
        }
    }

    // RBAC Analysis
    if scan_types.contains(&"rbac".to_string()) {
        let mut analyzer = RbacAnalyzer::new();

        for manifest in &manifests {
            analyzer.add_role(manifest);
            analyzer.add_binding(manifest);
        }

        let results = analyzer.analyze();

        // Also check pod service accounts
        let pod_findings = analyzer.analyze_pod_service_accounts(&manifests);

        for finding in results.findings.iter().chain(pod_findings.iter()) {
            let finding_id = Uuid::new_v4().to_string();
            let severity_str = match finding.severity {
                RbacSeverity::Critical => { critical_count += 1; "critical" }
                RbacSeverity::High => { high_count += 1; "high" }
                RbacSeverity::Medium => { medium_count += 1; "medium" }
                RbacSeverity::Low => { low_count += 1; "low" }
            };

            let subject_kind = finding.subject.as_ref().map(|s| format!("{:?}", s.kind));
            let subject_name = finding.subject.as_ref().map(|s| s.name.clone());
            let subject_namespace = finding.subject.as_ref().and_then(|s| s.namespace.clone());
            let permissions_json = serde_json::to_string(&finding.permissions).ok();

            sqlx::query(
                r#"
                INSERT INTO k8s_rbac_findings (
                    id, scan_id, finding_type, severity, subject_kind, subject_name,
                    subject_namespace, role_name, binding_name, namespace, permissions,
                    description, remediation, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                "#,
            )
            .bind(&finding_id)
            .bind(&scan_id)
            .bind(format!("{:?}", finding.finding_type))
            .bind(severity_str)
            .bind(&subject_kind)
            .bind(&subject_name)
            .bind(&subject_namespace)
            .bind(&finding.role_name)
            .bind(&finding.binding_name)
            .bind(&finding.namespace)
            .bind(&permissions_json)
            .bind(&finding.description)
            .bind(&finding.remediation)
            .bind(&now)
            .execute(pool.get_ref())
            .await?;

            total_findings += 1;
        }
    }

    // Network Policy Analysis
    if scan_types.contains(&"network_policy".to_string()) {
        let mut analyzer = NetworkPolicyAnalyzer::new();

        for manifest in &manifests {
            analyzer.add_policy(manifest);
            analyzer.add_workload(manifest);
        }

        let results = analyzer.analyze();

        for finding in &results.findings {
            let finding_id = Uuid::new_v4().to_string();
            let severity_str = match finding.severity {
                NetworkPolicySeverity::Critical => { critical_count += 1; "critical" }
                NetworkPolicySeverity::High => { high_count += 1; "high" }
                NetworkPolicySeverity::Medium => { medium_count += 1; "medium" }
                NetworkPolicySeverity::Low => { low_count += 1; "low" }
                NetworkPolicySeverity::Info => "info"
            };

            sqlx::query(
                r#"
                INSERT INTO k8s_network_policy_findings (
                    id, scan_id, finding_type, severity, namespace, policy_name,
                    affected_pods, description, remediation, details, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                "#,
            )
            .bind(&finding_id)
            .bind(&scan_id)
            .bind(format!("{:?}", finding.finding_type))
            .bind(severity_str)
            .bind(&finding.namespace)
            .bind(&finding.policy_name)
            .bind(serde_json::to_string(&finding.affected_pods).ok())
            .bind(&finding.description)
            .bind(&finding.remediation)
            .bind(serde_json::to_string(&finding.details).ok())
            .bind(&now)
            .execute(pool.get_ref())
            .await?;

            total_findings += 1;
        }

        // Store namespace coverage
        for (ns, coverage) in &results.coverage_by_namespace {
            let coverage_id = Uuid::new_v4().to_string();
            sqlx::query(
                r#"
                INSERT INTO k8s_namespace_coverage (
                    id, scan_id, namespace, total_pods, covered_pods,
                    has_default_deny_ingress, has_default_deny_egress, policy_count, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                "#,
            )
            .bind(&coverage_id)
            .bind(&scan_id)
            .bind(ns)
            .bind(coverage.total_pods as i64)
            .bind(coverage.covered_pods as i64)
            .bind(coverage.has_default_deny_ingress)
            .bind(coverage.has_default_deny_egress)
            .bind(coverage.policy_count as i64)
            .bind(&now)
            .execute(pool.get_ref())
            .await?;
        }
    }

    // Pod Security Standards Analysis
    if scan_types.contains(&"pss".to_string()) {
        let profile = match req.pss_profile.as_deref() {
            Some("privileged") => PssProfile::Privileged,
            Some("baseline") => PssProfile::Baseline,
            Some("restricted") | None => PssProfile::Restricted,
            _ => PssProfile::Restricted,
        };

        let validator = PssValidator::new(profile);
        let results = validator.validate(&manifests);

        pss_compliant_baseline = results.compliant_with_baseline;
        pss_compliant_restricted = results.compliant_with_restricted;

        for violation in &results.violations {
            let finding_id = Uuid::new_v4().to_string();
            let severity_str = match violation.severity {
                PssSeverity::Critical => { critical_count += 1; "critical" }
                PssSeverity::High => { high_count += 1; "high" }
                PssSeverity::Medium => { medium_count += 1; "medium" }
                PssSeverity::Low => { low_count += 1; "low" }
            };
            let profile_str = match violation.profile {
                PssProfile::Privileged => "privileged",
                PssProfile::Baseline => "baseline",
                PssProfile::Restricted => "restricted",
            };

            sqlx::query(
                r#"
                INSERT INTO k8s_pss_findings (
                    id, scan_id, violation_type, severity, profile, workload_name,
                    workload_kind, namespace, container_name, field_path, current_value,
                    description, remediation, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                "#,
            )
            .bind(&finding_id)
            .bind(&scan_id)
            .bind(format!("{:?}", violation.violation_type))
            .bind(severity_str)
            .bind(profile_str)
            .bind(&violation.workload_name)
            .bind(&violation.workload_kind)
            .bind(&violation.namespace)
            .bind(&violation.container_name)
            .bind(&violation.field_path)
            .bind(&violation.current_value)
            .bind(&violation.description)
            .bind(&violation.remediation)
            .bind(&now)
            .execute(pool.get_ref())
            .await?;

            total_findings += 1;
        }
    }

    // Update scan with results
    let completed_at = Utc::now().to_rfc3339();
    sqlx::query(
        r#"
        UPDATE k8s_security_scans SET
            status = 'completed',
            total_findings = ?,
            critical_count = ?,
            high_count = ?,
            medium_count = ?,
            low_count = ?,
            cis_score = ?,
            pss_compliant_baseline = ?,
            pss_compliant_restricted = ?,
            completed_at = ?,
            updated_at = ?
        WHERE id = ?
        "#,
    )
    .bind(total_findings)
    .bind(critical_count)
    .bind(high_count)
    .bind(medium_count)
    .bind(low_count)
    .bind(cis_score)
    .bind(pss_compliant_baseline)
    .bind(pss_compliant_restricted)
    .bind(&completed_at)
    .bind(&completed_at)
    .bind(&scan_id)
    .execute(pool.get_ref())
    .await?;

    Ok(HttpResponse::Accepted().json(K8sScanSummary {
        id: scan_id,
        status: K8sScanStatus::Completed,
        scan_types,
        cluster_name: req.cluster_name.clone(),
        total_findings,
        critical_count,
        high_count,
        medium_count,
        low_count,
        cis_score,
        pss_compliant_baseline,
        pss_compliant_restricted,
        created_at: now,
        completed_at: Some(completed_at),
    }))
}

/// Analyze K8s manifests immediately without storing results
#[utoipa::path(
    post,
    path = "/api/k8s-security/analyze",
    request_body = AnalyzeK8sManifestRequest,
    responses(
        (status = 200, description = "Analysis results", body = K8sAnalysisResponse),
        (status = 400, description = "Bad request"),
        (status = 401, description = "Unauthorized"),
    ),
    security(("bearer_auth" = [])),
    tag = "K8s Security"
)]
pub async fn analyze_manifest(
    _claims: web::ReqData<Claims>,
    req: web::Json<AnalyzeK8sManifestRequest>,
) -> Result<HttpResponse, ApiError> {
    let manifests = parse_yaml_documents(&req.content)?;

    let (findings_json, findings_count, critical_count, high_count, medium_count, low_count) =
        match req.analysis_type.as_str() {
            "cis" | "cis_benchmark" => {
                let scanner = CisBenchmarkScanner::new();
                // Convert YAML manifests to JSON for CIS scanner
                let json_manifests: Vec<serde_json::Value> = manifests
                    .iter()
                    .filter_map(|y| serde_json::to_value(y).ok())
                    .collect();
                let results = scanner.analyze_manifests(&json_manifests, "analyze");

                let mut critical = 0;
                let mut high = 0;
                let mut medium = 0;
                let mut low = 0;

                for f in &results.findings {
                    match f.severity {
                        CisSeverity::Critical => critical += 1,
                        CisSeverity::High => high += 1,
                        CisSeverity::Medium => medium += 1,
                        CisSeverity::Low | CisSeverity::Info => low += 1,
                    }
                }

                let json_val = serde_json::to_value(&results)
                    .map_err(|e| ApiError::internal(format!("JSON serialization error: {}", e)))?;
                (json_val, results.findings.len(), critical, high, medium, low)
            }
            "rbac" => {
                let mut analyzer = RbacAnalyzer::new();
                for manifest in &manifests {
                    analyzer.add_role(manifest);
                    analyzer.add_binding(manifest);
                }
                let results = analyzer.analyze();
                let pod_findings = analyzer.analyze_pod_service_accounts(&manifests);

                let all_findings: Vec<_> = results.findings.iter()
                    .chain(pod_findings.iter())
                    .collect();

                let mut critical = 0;
                let mut high = 0;
                let mut medium = 0;
                let mut low = 0;

                for f in &all_findings {
                    match f.severity {
                        RbacSeverity::Critical => critical += 1,
                        RbacSeverity::High => high += 1,
                        RbacSeverity::Medium => medium += 1,
                        RbacSeverity::Low => low += 1,
                    }
                }

                let count = all_findings.len();
                let json_val = serde_json::to_value(&results)
                    .map_err(|e| ApiError::internal(format!("JSON serialization error: {}", e)))?;
                (json_val, count, critical, high, medium, low)
            }
            "network" | "network_policy" => {
                let mut analyzer = NetworkPolicyAnalyzer::new();
                for manifest in &manifests {
                    analyzer.add_policy(manifest);
                    analyzer.add_workload(manifest);
                }
                let results = analyzer.analyze();

                let mut critical = 0;
                let mut high = 0;
                let mut medium = 0;
                let mut low = 0;

                for f in &results.findings {
                    match f.severity {
                        NetworkPolicySeverity::Critical => critical += 1,
                        NetworkPolicySeverity::High => high += 1,
                        NetworkPolicySeverity::Medium => medium += 1,
                        NetworkPolicySeverity::Low | NetworkPolicySeverity::Info => low += 1,
                    }
                }

                let json_val = serde_json::to_value(&results)
                    .map_err(|e| ApiError::internal(format!("JSON serialization error: {}", e)))?;
                (json_val, results.findings.len(), critical, high, medium, low)
            }
            "pss" | "pod_security" => {
                let profile = match req.pss_profile.as_deref() {
                    Some("privileged") => PssProfile::Privileged,
                    Some("baseline") => PssProfile::Baseline,
                    Some("restricted") | None => PssProfile::Restricted,
                    _ => PssProfile::Restricted,
                };

                let validator = PssValidator::new(profile);
                let results = validator.validate(&manifests);

                let mut critical = 0;
                let mut high = 0;
                let mut medium = 0;
                let mut low = 0;

                for v in &results.violations {
                    match v.severity {
                        PssSeverity::Critical => critical += 1,
                        PssSeverity::High => high += 1,
                        PssSeverity::Medium => medium += 1,
                        PssSeverity::Low => low += 1,
                    }
                }

                let json_val = serde_json::to_value(&results)
                    .map_err(|e| ApiError::internal(format!("JSON serialization error: {}", e)))?;
                (json_val, results.violations.len(), critical, high, medium, low)
            }
            _ => {
                return Err(ApiError::bad_request(format!(
                    "Invalid analysis_type '{}'. Valid types: cis, rbac, network, pss",
                    req.analysis_type
                )));
            }
        };

    Ok(HttpResponse::Ok().json(K8sAnalysisResponse {
        analysis_type: req.analysis_type.clone(),
        findings_count,
        critical_count,
        high_count,
        medium_count,
        low_count,
        findings: findings_json,
    }))
}

/// List K8s security scans
#[utoipa::path(
    get,
    path = "/api/k8s-security/scans",
    responses(
        (status = 200, description = "List of scans", body = Vec<K8sScanSummary>),
        (status = 401, description = "Unauthorized"),
    ),
    security(("bearer_auth" = [])),
    tag = "K8s Security"
)]
pub async fn list_scans(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<Claims>,
) -> Result<HttpResponse, ApiError> {
    let user_id = &claims.sub;

    let scans = sqlx::query_as::<_, (String, String, Option<String>, String, i64, i64, i64, i64, i64, Option<f64>, bool, bool, String, Option<String>)>(
        r#"
        SELECT id, status, cluster_name, scan_types, total_findings, critical_count,
               high_count, medium_count, low_count, cis_score, pss_compliant_baseline,
               pss_compliant_restricted, created_at, completed_at
        FROM k8s_security_scans
        WHERE user_id = ?
        ORDER BY created_at DESC
        LIMIT 100
        "#,
    )
    .bind(user_id)
    .fetch_all(pool.get_ref())
    .await?;

    let summaries: Vec<K8sScanSummary> = scans
        .into_iter()
        .map(|(id, status, cluster_name, scan_types, total_findings, critical, high, medium, low, cis_score, baseline, restricted, created_at, completed_at)| {
            K8sScanSummary {
                id,
                status: match status.as_str() {
                    "pending" => K8sScanStatus::Pending,
                    "running" => K8sScanStatus::Running,
                    "completed" => K8sScanStatus::Completed,
                    _ => K8sScanStatus::Failed,
                },
                scan_types: serde_json::from_str(&scan_types).unwrap_or_default(),
                cluster_name,
                total_findings,
                critical_count: critical,
                high_count: high,
                medium_count: medium,
                low_count: low,
                cis_score,
                pss_compliant_baseline: baseline,
                pss_compliant_restricted: restricted,
                created_at,
                completed_at,
            }
        })
        .collect();

    Ok(HttpResponse::Ok().json(summaries))
}

/// Get K8s security scan details
#[utoipa::path(
    get,
    path = "/api/k8s-security/scans/{id}",
    responses(
        (status = 200, description = "Scan details", body = K8sScanSummary),
        (status = 404, description = "Scan not found"),
        (status = 401, description = "Unauthorized"),
    ),
    security(("bearer_auth" = [])),
    tag = "K8s Security"
)]
pub async fn get_scan(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let scan_id = path.into_inner();
    let user_id = &claims.sub;

    let scan = sqlx::query_as::<_, (String, String, Option<String>, String, i64, i64, i64, i64, i64, Option<f64>, bool, bool, String, Option<String>)>(
        r#"
        SELECT id, status, cluster_name, scan_types, total_findings, critical_count,
               high_count, medium_count, low_count, cis_score, pss_compliant_baseline,
               pss_compliant_restricted, created_at, completed_at
        FROM k8s_security_scans
        WHERE id = ? AND user_id = ?
        "#,
    )
    .bind(&scan_id)
    .bind(user_id)
    .fetch_optional(pool.get_ref())
    .await?
    .ok_or_else(|| ApiError::not_found("Scan not found"))?;

    Ok(HttpResponse::Ok().json(K8sScanSummary {
        id: scan.0,
        status: match scan.1.as_str() {
            "pending" => K8sScanStatus::Pending,
            "running" => K8sScanStatus::Running,
            "completed" => K8sScanStatus::Completed,
            _ => K8sScanStatus::Failed,
        },
        scan_types: serde_json::from_str(&scan.3).unwrap_or_default(),
        cluster_name: scan.2,
        total_findings: scan.4,
        critical_count: scan.5,
        high_count: scan.6,
        medium_count: scan.7,
        low_count: scan.8,
        cis_score: scan.9,
        pss_compliant_baseline: scan.10,
        pss_compliant_restricted: scan.11,
        created_at: scan.12,
        completed_at: scan.13,
    }))
}

/// Get CIS findings for a scan
#[utoipa::path(
    get,
    path = "/api/k8s-security/scans/{id}/cis",
    responses(
        (status = 200, description = "CIS findings", body = Vec<CisFindingResponse>),
        (status = 404, description = "Scan not found"),
        (status = 401, description = "Unauthorized"),
    ),
    security(("bearer_auth" = [])),
    tag = "K8s Security"
)]
pub async fn get_cis_findings(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let scan_id = path.into_inner();
    let _user_id = &claims.sub;

    let findings = sqlx::query_as::<_, (String, String, String, String, String, String, Option<String>, Option<String>, Option<String>, Option<String>)>(
        r#"
        SELECT id, control_id, control_title, section, status, severity,
               description, remediation, resource_name, namespace
        FROM k8s_cis_findings
        WHERE scan_id = ?
        ORDER BY severity DESC, control_id ASC
        "#,
    )
    .bind(&scan_id)
    .fetch_all(pool.get_ref())
    .await?;

    let responses: Vec<CisFindingResponse> = findings
        .into_iter()
        .map(|(id, control_id, control_title, section, status, severity, description, remediation, resource_name, namespace)| {
            CisFindingResponse {
                id,
                control_id,
                control_title,
                section,
                status,
                severity,
                description,
                remediation,
                resource_name,
                namespace,
            }
        })
        .collect();

    Ok(HttpResponse::Ok().json(responses))
}

/// Get RBAC findings for a scan
#[utoipa::path(
    get,
    path = "/api/k8s-security/scans/{id}/rbac",
    responses(
        (status = 200, description = "RBAC findings", body = Vec<RbacFindingResponse>),
        (status = 404, description = "Scan not found"),
        (status = 401, description = "Unauthorized"),
    ),
    security(("bearer_auth" = [])),
    tag = "K8s Security"
)]
pub async fn get_rbac_findings(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let scan_id = path.into_inner();
    let _user_id = &claims.sub;

    let findings = sqlx::query_as::<_, (String, String, String, Option<String>, Option<String>, Option<String>, Option<String>, String, String)>(
        r#"
        SELECT id, finding_type, severity, subject_kind, subject_name, role_name,
               namespace, description, remediation
        FROM k8s_rbac_findings
        WHERE scan_id = ?
        ORDER BY severity DESC
        "#,
    )
    .bind(&scan_id)
    .fetch_all(pool.get_ref())
    .await?;

    let responses: Vec<RbacFindingResponse> = findings
        .into_iter()
        .map(|(id, finding_type, severity, subject_kind, subject_name, role_name, namespace, description, remediation)| {
            RbacFindingResponse {
                id,
                finding_type,
                severity,
                subject_kind,
                subject_name,
                role_name,
                namespace,
                description,
                remediation,
            }
        })
        .collect();

    Ok(HttpResponse::Ok().json(responses))
}

/// Get Network Policy findings for a scan
#[utoipa::path(
    get,
    path = "/api/k8s-security/scans/{id}/network-policies",
    responses(
        (status = 200, description = "Network Policy findings", body = Vec<NetworkPolicyFindingResponse>),
        (status = 404, description = "Scan not found"),
        (status = 401, description = "Unauthorized"),
    ),
    security(("bearer_auth" = [])),
    tag = "K8s Security"
)]
pub async fn get_network_policy_findings(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let scan_id = path.into_inner();
    let _user_id = &claims.sub;

    let findings = sqlx::query_as::<_, (String, String, String, String, Option<String>, Option<String>, String, String)>(
        r#"
        SELECT id, finding_type, severity, namespace, policy_name, affected_pods,
               description, remediation
        FROM k8s_network_policy_findings
        WHERE scan_id = ?
        ORDER BY severity DESC
        "#,
    )
    .bind(&scan_id)
    .fetch_all(pool.get_ref())
    .await?;

    let responses: Vec<NetworkPolicyFindingResponse> = findings
        .into_iter()
        .map(|(id, finding_type, severity, namespace, policy_name, affected_pods, description, remediation)| {
            NetworkPolicyFindingResponse {
                id,
                finding_type,
                severity,
                namespace,
                policy_name,
                affected_pods: affected_pods
                    .and_then(|s| serde_json::from_str(&s).ok())
                    .unwrap_or_default(),
                description,
                remediation,
            }
        })
        .collect();

    Ok(HttpResponse::Ok().json(responses))
}

/// Get PSS findings for a scan
#[utoipa::path(
    get,
    path = "/api/k8s-security/scans/{id}/pss",
    responses(
        (status = 200, description = "PSS findings", body = Vec<PssFindingResponse>),
        (status = 404, description = "Scan not found"),
        (status = 401, description = "Unauthorized"),
    ),
    security(("bearer_auth" = [])),
    tag = "K8s Security"
)]
pub async fn get_pss_findings(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let scan_id = path.into_inner();
    let _user_id = &claims.sub;

    let findings = sqlx::query_as::<_, (String, String, String, String, String, String, String, Option<String>, String, String, String, String)>(
        r#"
        SELECT id, violation_type, severity, profile, workload_name, workload_kind,
               namespace, container_name, field_path, current_value, description, remediation
        FROM k8s_pss_findings
        WHERE scan_id = ?
        ORDER BY severity DESC
        "#,
    )
    .bind(&scan_id)
    .fetch_all(pool.get_ref())
    .await?;

    let responses: Vec<PssFindingResponse> = findings
        .into_iter()
        .map(|(id, violation_type, severity, profile, workload_name, workload_kind, namespace, container_name, field_path, current_value, description, remediation)| {
            PssFindingResponse {
                id,
                violation_type,
                severity,
                profile,
                workload_name,
                workload_kind,
                namespace,
                container_name,
                field_path,
                current_value,
                description,
                remediation,
            }
        })
        .collect();

    Ok(HttpResponse::Ok().json(responses))
}

/// Get K8s security statistics
#[utoipa::path(
    get,
    path = "/api/k8s-security/stats",
    responses(
        (status = 200, description = "K8s security statistics", body = K8sSecurityStats),
        (status = 401, description = "Unauthorized"),
    ),
    security(("bearer_auth" = [])),
    tag = "K8s Security"
)]
pub async fn get_stats(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<Claims>,
) -> Result<HttpResponse, ApiError> {
    let user_id = &claims.sub;

    let total_scans: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM k8s_security_scans WHERE user_id = ?",
    )
    .bind(user_id)
    .fetch_one(pool.get_ref())
    .await?;

    let scans_this_month: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM k8s_security_scans WHERE user_id = ? AND created_at >= datetime('now', '-30 days')",
    )
    .bind(user_id)
    .fetch_one(pool.get_ref())
    .await?;

    let total_cis_findings: (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*) FROM k8s_cis_findings cf
        JOIN k8s_security_scans s ON cf.scan_id = s.id
        WHERE s.user_id = ?
        "#,
    )
    .bind(user_id)
    .fetch_one(pool.get_ref())
    .await?;

    let total_rbac_findings: (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*) FROM k8s_rbac_findings rf
        JOIN k8s_security_scans s ON rf.scan_id = s.id
        WHERE s.user_id = ?
        "#,
    )
    .bind(user_id)
    .fetch_one(pool.get_ref())
    .await?;

    let total_network_findings: (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*) FROM k8s_network_policy_findings nf
        JOIN k8s_security_scans s ON nf.scan_id = s.id
        WHERE s.user_id = ?
        "#,
    )
    .bind(user_id)
    .fetch_one(pool.get_ref())
    .await?;

    let total_pss_findings: (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*) FROM k8s_pss_findings pf
        JOIN k8s_security_scans s ON pf.scan_id = s.id
        WHERE s.user_id = ?
        "#,
    )
    .bind(user_id)
    .fetch_one(pool.get_ref())
    .await?;

    let avg_cis_score: (Option<f64>,) = sqlx::query_as(
        "SELECT AVG(cis_score) FROM k8s_security_scans WHERE user_id = ? AND cis_score IS NOT NULL",
    )
    .bind(user_id)
    .fetch_one(pool.get_ref())
    .await?;

    let clusters_scanned: (i64,) = sqlx::query_as(
        "SELECT COUNT(DISTINCT cluster_name) FROM k8s_security_scans WHERE user_id = ? AND cluster_name IS NOT NULL",
    )
    .bind(user_id)
    .fetch_one(pool.get_ref())
    .await?;

    Ok(HttpResponse::Ok().json(K8sSecurityStats {
        total_scans: total_scans.0,
        scans_this_month: scans_this_month.0,
        total_cis_findings: total_cis_findings.0,
        total_rbac_findings: total_rbac_findings.0,
        total_network_findings: total_network_findings.0,
        total_pss_findings: total_pss_findings.0,
        avg_cis_score: avg_cis_score.0,
        clusters_scanned: clusters_scanned.0,
    }))
}

/// Parse YAML documents from content
fn parse_yaml_documents(content: &str) -> Result<Vec<serde_yaml::Value>, ApiError> {
    let mut manifests = Vec::new();

    for doc in serde_yaml::Deserializer::from_str(content) {
        match serde_yaml::Value::deserialize(doc) {
            Ok(value) => {
                if !value.is_null() {
                    manifests.push(value);
                }
            }
            Err(e) => {
                return Err(ApiError::bad_request(format!("Invalid YAML: {}", e)));
            }
        }
    }

    if manifests.is_empty() {
        return Err(ApiError::bad_request("No valid YAML documents found"));
    }

    Ok(manifests)
}

/// Configure K8s security routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/k8s-security")
            .route("/scan", web::post().to(start_scan))
            .route("/analyze", web::post().to(analyze_manifest))
            .route("/scans", web::get().to(list_scans))
            .route("/scans/{id}", web::get().to(get_scan))
            .route("/scans/{id}/cis", web::get().to(get_cis_findings))
            .route("/scans/{id}/rbac", web::get().to(get_rbac_findings))
            .route("/scans/{id}/network-policies", web::get().to(get_network_policy_findings))
            .route("/scans/{id}/pss", web::get().to(get_pss_findings))
            .route("/stats", web::get().to(get_stats)),
    );
}
