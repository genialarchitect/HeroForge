// AV/EDR Evasion Analysis API Endpoints
// REST API for payload analysis, evasion technique documentation, and sandbox detection
// For educational and authorized penetration testing purposes only

use actix_web::{web, HttpResponse, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use uuid::Uuid;

use crate::scanner::exploitation::evasion::{
    self, analysis, behavior, signature,
    DetectionRisk, EvasionCategory, EvasionProfile, EvasionResult,
    EvasionTechnique, EvasionTechniqueInfo, PayloadAnalysisResult,
};
use crate::web::auth::Claims;
use crate::web::error::ApiError;

// ============================================================================
// Request/Response Types
// ============================================================================

/// Request to analyze a payload for detection risk
#[derive(Debug, Deserialize)]
pub struct AnalyzePayloadRequest {
    /// Base64-encoded payload data
    pub payload_base64: String,
    /// Optional: Run heuristic analysis (simulated AV engines)
    #[serde(default)]
    pub include_heuristics: bool,
}

/// Response for payload analysis
#[derive(Debug, Serialize)]
pub struct AnalyzePayloadResponse {
    pub job_id: String,
    pub analysis: PayloadAnalysisResult,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub heuristic_results: Option<Vec<analysis::HeuristicResult>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub heuristic_summary: Option<std::collections::HashMap<String, serde_json::Value>>,
}

/// Request to apply evasion analysis to a payload
#[derive(Debug, Deserialize)]
pub struct ApplyEvasionRequest {
    /// Base64-encoded payload data
    pub payload_base64: String,
    /// Techniques to analyze/document
    pub techniques: Vec<EvasionTechnique>,
    /// Optional: Use a predefined profile instead of individual techniques
    pub profile_name: Option<String>,
}

/// Response for evasion application
#[derive(Debug, Serialize)]
pub struct ApplyEvasionResponse {
    pub job_id: String,
    pub result: EvasionResult,
}

/// Request for sandbox check documentation
#[derive(Debug, Deserialize)]
pub struct SandboxCheckRequest {
    /// Whether to include code examples
    #[serde(default)]
    pub include_code_examples: bool,
    /// Filter by indicator category
    pub category_filter: Option<String>,
}

/// Response for available techniques
#[derive(Debug, Serialize)]
pub struct TechniquesResponse {
    pub techniques: Vec<EvasionTechniqueInfo>,
    pub categories: Vec<CategoryInfo>,
    pub profiles: Vec<ProfileInfo>,
}

#[derive(Debug, Serialize)]
pub struct CategoryInfo {
    pub category: EvasionCategory,
    pub technique_count: usize,
    pub description: String,
}

#[derive(Debug, Serialize)]
pub struct ProfileInfo {
    pub name: String,
    pub description: String,
    pub technique_count: usize,
    pub target_platform: String,
    pub estimated_risk: DetectionRisk,
}

/// Response for sandbox indicators
#[derive(Debug, Serialize)]
pub struct SandboxIndicatorsResponse {
    pub indicators: Vec<behavior::SandboxIndicatorInfo>,
    pub categories: Vec<String>,
    pub total_count: usize,
}

/// Response for sleep obfuscation techniques
#[derive(Debug, Serialize)]
pub struct SleepTechniquesResponse {
    pub techniques: Vec<behavior::SleepObfuscationInfo>,
}

/// Response for unhooking techniques
#[derive(Debug, Serialize)]
pub struct UnhookingTechniquesResponse {
    pub techniques: Vec<behavior::UnhookingTechniqueInfo>,
}

/// Response for process injection documentation
#[derive(Debug, Serialize)]
pub struct ProcessInjectionResponse {
    pub techniques: Vec<behavior::ProcessInjectionInfo>,
}

/// Response for API obfuscation analysis
#[derive(Debug, Serialize)]
pub struct ApiObfuscationResponse {
    pub analysis: signature::ApiObfuscationAnalysis,
}

/// Response for encryption options
#[derive(Debug, Serialize)]
pub struct EncryptionOptionsResponse {
    pub analysis: signature::EncryptionAnalysis,
}

/// Request for string obfuscation analysis
#[derive(Debug, Deserialize)]
pub struct StringObfuscationRequest {
    pub input_string: String,
    #[serde(default)]
    pub xor_key: Option<u8>,
}

/// Response for string obfuscation analysis
#[derive(Debug, Serialize)]
pub struct StringObfuscationResponse {
    pub xor_analysis: Option<signature::XorAnalysis>,
    pub concat_analysis: signature::StringConcatAnalysis,
}

// ============================================================================
// API Handlers
// ============================================================================

/// POST /api/evasion/analyze - Analyze payload for detection risk
pub async fn analyze_payload(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    request: web::Json<AnalyzePayloadRequest>,
) -> Result<HttpResponse, ApiError> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use sha2::{Sha256, Digest};

    // Decode payload
    let payload = STANDARD.decode(&request.payload_base64)
        .map_err(|e| ApiError::bad_request(format!("Invalid base64 payload: {}", e)))?;

    // Create job record
    let job_id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    let mut hasher = Sha256::new();
    hasher.update(&payload);
    let payload_hash = format!("{:x}", hasher.finalize());

    sqlx::query(
        r#"
        INSERT INTO evasion_jobs (id, user_id, job_type, status, input_hash, input_size, created_at, started_at)
        VALUES (?, ?, 'analyze', 'running', ?, ?, ?, ?)
        "#,
    )
    .bind(&job_id)
    .bind(&claims.sub)
    .bind(&payload_hash)
    .bind(payload.len() as i64)
    .bind(&now)
    .bind(&now)
    .execute(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Failed to create job: {}", e)))?;

    // Perform analysis
    let analysis = analysis::analyze_payload(&payload);

    // Optionally run heuristic analysis
    let (heuristic_results, heuristic_summary) = if request.include_heuristics {
        let results = analysis::run_heuristic_analysis(&payload);
        let summary = analysis::get_heuristic_summary(&results);
        (Some(results), Some(summary))
    } else {
        (None, None)
    };

    // Store analysis result
    let completed_at = Utc::now().to_rfc3339();
    sqlx::query(
        r#"
        UPDATE evasion_jobs
        SET status = 'completed',
            result = ?,
            completed_at = ?
        WHERE id = ?
        "#,
    )
    .bind(serde_json::to_string(&analysis).unwrap_or_default())
    .bind(&completed_at)
    .bind(&job_id)
    .execute(pool.get_ref())
    .await
    .ok();

    // Store in payload_analysis table
    sqlx::query(
        r#"
        INSERT INTO payload_analysis (
            id, user_id, job_id, payload_hash, payload_size, detection_risk, risk_score,
            entropy_overall, entropy_assessment, suspicious_strings_count, suspicious_patterns_count,
            api_analysis, heuristic_results, recommendations, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(Uuid::new_v4().to_string())
    .bind(&claims.sub)
    .bind(&job_id)
    .bind(&payload_hash)
    .bind(payload.len() as i64)
    .bind(format!("{:?}", analysis.detection_risk))
    .bind(analysis.risk_score as i64)
    .bind(analysis.entropy.overall_entropy)
    .bind(&analysis.entropy.assessment)
    .bind(analysis.suspicious_strings.len() as i64)
    .bind(analysis.suspicious_patterns.len() as i64)
    .bind(serde_json::to_string(&analysis.api_analysis).ok())
    .bind(serde_json::to_string(&heuristic_results).ok())
    .bind(serde_json::to_string(&analysis.recommendations).ok())
    .bind(&completed_at)
    .execute(pool.get_ref())
    .await
    .ok();

    // Audit log
    log_evasion_action(
        pool.get_ref(),
        &claims.sub,
        Some(&job_id),
        "analyze_payload",
        None,
        Some(&payload_hash),
        Some(&format!("Analyzed {} byte payload, risk score: {}", payload.len(), analysis.risk_score)),
    ).await;

    Ok(HttpResponse::Ok().json(AnalyzePayloadResponse {
        job_id,
        analysis,
        heuristic_results,
        heuristic_summary,
    }))
}

/// POST /api/evasion/apply - Apply evasion technique analysis
pub async fn apply_evasion(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    request: web::Json<ApplyEvasionRequest>,
) -> Result<HttpResponse, ApiError> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use sha2::{Sha256, Digest};

    // Decode payload
    let payload = STANDARD.decode(&request.payload_base64)
        .map_err(|e| ApiError::bad_request(format!("Invalid base64 payload: {}", e)))?;

    // Determine techniques to use
    let techniques = if let Some(profile_name) = &request.profile_name {
        // Use predefined profile
        EvasionProfile::predefined_profiles()
            .into_iter()
            .find(|p| p.name.eq_ignore_ascii_case(profile_name))
            .map(|p| p.techniques)
            .ok_or_else(|| ApiError::bad_request(format!("Unknown profile: {}", profile_name)))?
    } else {
        request.techniques.clone()
    };

    if techniques.is_empty() {
        return Err(ApiError::bad_request("No techniques specified"));
    }

    // Create job record
    let job_id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    let mut hasher = Sha256::new();
    hasher.update(&payload);
    let payload_hash = format!("{:x}", hasher.finalize());

    sqlx::query(
        r#"
        INSERT INTO evasion_jobs (id, user_id, job_type, status, input_hash, input_size, techniques, profile_name, created_at, started_at)
        VALUES (?, ?, 'apply_evasion', 'running', ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&job_id)
    .bind(&claims.sub)
    .bind(&payload_hash)
    .bind(payload.len() as i64)
    .bind(serde_json::to_string(&techniques).ok())
    .bind(&request.profile_name)
    .bind(&now)
    .bind(&now)
    .execute(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Failed to create job: {}", e)))?;

    // Apply evasion analysis based on technique categories
    let has_signature_techniques = techniques.iter().any(|t| matches!(t.category(), EvasionCategory::Signature));
    let has_behavioral_techniques = techniques.iter().any(|t| matches!(t.category(), EvasionCategory::Behavioral | EvasionCategory::Memory));

    let result = if has_behavioral_techniques {
        behavior::apply_behavioral_evasion_analysis(&techniques)
    } else if has_signature_techniques {
        signature::apply_signature_evasion_analysis(&payload, &techniques)
    } else {
        // Default to signature analysis
        signature::apply_signature_evasion_analysis(&payload, &techniques)
    };

    // Update job with result
    let completed_at = Utc::now().to_rfc3339();
    sqlx::query(
        r#"
        UPDATE evasion_jobs
        SET status = 'completed',
            result = ?,
            completed_at = ?
        WHERE id = ?
        "#,
    )
    .bind(serde_json::to_string(&result).unwrap_or_default())
    .bind(&completed_at)
    .bind(&job_id)
    .execute(pool.get_ref())
    .await
    .ok();

    // Audit log
    log_evasion_action(
        pool.get_ref(),
        &claims.sub,
        Some(&job_id),
        "apply_evasion",
        Some(&serde_json::to_string(&techniques).unwrap_or_default()),
        Some(&payload_hash),
        Some(&format!("Applied {} techniques", techniques.len())),
    ).await;

    Ok(HttpResponse::Ok().json(ApplyEvasionResponse {
        job_id,
        result,
    }))
}

/// GET /api/evasion/techniques - List available evasion techniques
pub async fn list_techniques() -> Result<HttpResponse, ApiError> {
    let techniques = evasion::get_all_techniques();

    // Build category info
    let mut category_counts: std::collections::HashMap<EvasionCategory, usize> = std::collections::HashMap::new();
    for t in &techniques {
        *category_counts.entry(t.category.clone()).or_insert(0) += 1;
    }

    let categories: Vec<CategoryInfo> = vec![
        CategoryInfo {
            category: EvasionCategory::Signature,
            technique_count: *category_counts.get(&EvasionCategory::Signature).unwrap_or(&0),
            description: "Techniques to evade static signature detection".to_string(),
        },
        CategoryInfo {
            category: EvasionCategory::Behavioral,
            technique_count: *category_counts.get(&EvasionCategory::Behavioral).unwrap_or(&0),
            description: "Techniques to evade behavioral analysis and sandbox detection".to_string(),
        },
        CategoryInfo {
            category: EvasionCategory::Memory,
            technique_count: *category_counts.get(&EvasionCategory::Memory).unwrap_or(&0),
            description: "Memory manipulation techniques (documentation only)".to_string(),
        },
        CategoryInfo {
            category: EvasionCategory::Network,
            technique_count: *category_counts.get(&EvasionCategory::Network).unwrap_or(&0),
            description: "Network-based evasion techniques".to_string(),
        },
        CategoryInfo {
            category: EvasionCategory::FileBased,
            technique_count: *category_counts.get(&EvasionCategory::FileBased).unwrap_or(&0),
            description: "File-based evasion techniques".to_string(),
        },
    ];

    // Build profile info
    let profiles: Vec<ProfileInfo> = EvasionProfile::predefined_profiles()
        .into_iter()
        .map(|p| ProfileInfo {
            name: p.name,
            description: p.description,
            technique_count: p.techniques.len(),
            target_platform: p.target_platform,
            estimated_risk: p.estimated_risk,
        })
        .collect();

    Ok(HttpResponse::Ok().json(TechniquesResponse {
        techniques,
        categories,
        profiles,
    }))
}

/// POST /api/evasion/sandbox-check - Get sandbox detection indicators documentation
pub async fn sandbox_check(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    request: web::Json<SandboxCheckRequest>,
) -> Result<HttpResponse, ApiError> {
    let mut indicators = behavior::get_sandbox_indicators();

    // Filter by category if specified
    if let Some(category) = &request.category_filter {
        indicators.retain(|i| i.category.to_string().eq_ignore_ascii_case(category));
    }

    // Create job record
    let job_id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        INSERT INTO evasion_jobs (id, user_id, job_type, status, created_at, completed_at)
        VALUES (?, ?, 'sandbox_check', 'completed', ?, ?)
        "#,
    )
    .bind(&job_id)
    .bind(&claims.sub)
    .bind(&now)
    .bind(&now)
    .execute(pool.get_ref())
    .await
    .ok();

    // Get unique categories
    let categories: Vec<String> = indicators
        .iter()
        .map(|i| i.category.to_string())
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();

    // Store sandbox check result
    let result = behavior::analyze_sandbox_indicators();
    sqlx::query(
        r#"
        INSERT INTO sandbox_check_results (id, user_id, job_id, is_sandbox, confidence, indicators, environment, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(Uuid::new_v4().to_string())
    .bind(&claims.sub)
    .bind(&job_id)
    .bind(result.is_sandbox)
    .bind(result.confidence as i64)
    .bind(serde_json::to_string(&result.indicators).ok())
    .bind(serde_json::to_string(&result.environment).ok())
    .bind(&now)
    .execute(pool.get_ref())
    .await
    .ok();

    // Audit log
    log_evasion_action(
        pool.get_ref(),
        &claims.sub,
        Some(&job_id),
        "sandbox_check",
        None,
        None,
        Some(&format!("Retrieved {} sandbox indicators", indicators.len())),
    ).await;

    Ok(HttpResponse::Ok().json(SandboxIndicatorsResponse {
        total_count: indicators.len(),
        indicators,
        categories,
    }))
}

/// GET /api/evasion/sleep-techniques - Get sleep obfuscation techniques
pub async fn sleep_techniques() -> Result<HttpResponse, ApiError> {
    let techniques = behavior::get_sleep_obfuscation_techniques();
    Ok(HttpResponse::Ok().json(SleepTechniquesResponse { techniques }))
}

/// GET /api/evasion/unhooking - Get unhooking technique documentation
pub async fn unhooking_techniques() -> Result<HttpResponse, ApiError> {
    let techniques = behavior::get_unhooking_techniques();
    Ok(HttpResponse::Ok().json(UnhookingTechniquesResponse { techniques }))
}

/// GET /api/evasion/injection - Get process injection technique documentation
pub async fn injection_techniques() -> Result<HttpResponse, ApiError> {
    let techniques = behavior::get_process_injection_techniques();
    Ok(HttpResponse::Ok().json(ProcessInjectionResponse { techniques }))
}

/// GET /api/evasion/api-obfuscation/{api_name} - Get API obfuscation analysis
pub async fn api_obfuscation(
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let api_name = path.into_inner();
    let analysis = signature::analyze_api_obfuscation(&api_name);
    Ok(HttpResponse::Ok().json(ApiObfuscationResponse { analysis }))
}

/// GET /api/evasion/encryption-options - Get encryption algorithm options
pub async fn encryption_options() -> Result<HttpResponse, ApiError> {
    let analysis = signature::analyze_encryption_options();
    Ok(HttpResponse::Ok().json(EncryptionOptionsResponse { analysis }))
}

/// POST /api/evasion/string-obfuscation - Analyze string obfuscation options
pub async fn string_obfuscation(
    request: web::Json<StringObfuscationRequest>,
) -> Result<HttpResponse, ApiError> {
    let xor_analysis = request.xor_key.map(|key| {
        signature::analyze_xor_encoding(request.input_string.as_bytes(), key)
    });

    let concat_analysis = signature::analyze_string_concatenation(&request.input_string);

    Ok(HttpResponse::Ok().json(StringObfuscationResponse {
        xor_analysis,
        concat_analysis,
    }))
}

/// GET /api/evasion/iat - Get IAT manipulation documentation
pub async fn iat_manipulation() -> Result<HttpResponse, ApiError> {
    let result = signature::analyze_iat_manipulation();
    Ok(HttpResponse::Ok().json(result))
}

/// GET /api/evasion/dead-code/{hash} - Get dead code insertion analysis
pub async fn dead_code_analysis(
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let payload_hash = path.into_inner();
    let analysis = signature::analyze_dead_code_insertion(&payload_hash);
    Ok(HttpResponse::Ok().json(analysis))
}

/// GET /api/evasion/jobs - List evasion jobs for current user
pub async fn list_jobs(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    query: web::Query<JobsQuery>,
) -> Result<HttpResponse, ApiError> {
    let limit = query.limit.unwrap_or(50).min(100);
    let offset = query.offset.unwrap_or(0);

    let jobs: Vec<JobSummary> = sqlx::query_as(
        r#"
        SELECT id, job_type, status, input_hash, input_size, profile_name, created_at, completed_at
        FROM evasion_jobs
        WHERE user_id = ?
        ORDER BY created_at DESC
        LIMIT ? OFFSET ?
        "#,
    )
    .bind(&claims.sub)
    .bind(limit as i64)
    .bind(offset as i64)
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Failed to fetch jobs: {}", e)))?;

    Ok(HttpResponse::Ok().json(jobs))
}

/// GET /api/evasion/jobs/{id} - Get evasion job details
pub async fn get_job(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let job_id = path.into_inner();

    let job: Option<JobDetail> = sqlx::query_as(
        r#"
        SELECT id, job_type, status, input_hash, input_size, techniques, profile_name,
               result, error_message, created_at, started_at, completed_at
        FROM evasion_jobs
        WHERE id = ? AND user_id = ?
        "#,
    )
    .bind(&job_id)
    .bind(&claims.sub)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Failed to fetch job: {}", e)))?;

    match job {
        Some(j) => Ok(HttpResponse::Ok().json(j)),
        None => Err(ApiError::not_found("Job not found")),
    }
}

// ============================================================================
// Helper Types
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct JobsQuery {
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct JobSummary {
    pub id: String,
    pub job_type: String,
    pub status: String,
    pub input_hash: Option<String>,
    pub input_size: Option<i64>,
    pub profile_name: Option<String>,
    pub created_at: String,
    pub completed_at: Option<String>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct JobDetail {
    pub id: String,
    pub job_type: String,
    pub status: String,
    pub input_hash: Option<String>,
    pub input_size: Option<i64>,
    pub techniques: Option<String>,
    pub profile_name: Option<String>,
    pub result: Option<String>,
    pub error_message: Option<String>,
    pub created_at: String,
    pub started_at: Option<String>,
    pub completed_at: Option<String>,
}

/// Log evasion action for audit trail
async fn log_evasion_action(
    pool: &SqlitePool,
    user_id: &str,
    job_id: Option<&str>,
    action: &str,
    techniques: Option<&str>,
    payload_hash: Option<&str>,
    details: Option<&str>,
) {
    let now = Utc::now().to_rfc3339();
    let _ = sqlx::query(
        r#"
        INSERT INTO evasion_audit_log (id, user_id, job_id, action, techniques, payload_hash, details, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(Uuid::new_v4().to_string())
    .bind(user_id)
    .bind(job_id)
    .bind(action)
    .bind(techniques)
    .bind(payload_hash)
    .bind(details)
    .bind(&now)
    .execute(pool)
    .await;
}

/// Configure evasion routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/evasion")
            // Analysis endpoints
            .route("/analyze", web::post().to(analyze_payload))
            .route("/apply", web::post().to(apply_evasion))

            // Technique documentation
            .route("/techniques", web::get().to(list_techniques))
            .route("/sandbox-check", web::post().to(sandbox_check))
            .route("/sleep-techniques", web::get().to(sleep_techniques))
            .route("/unhooking", web::get().to(unhooking_techniques))
            .route("/injection", web::get().to(injection_techniques))

            // Signature evasion
            .route("/api-obfuscation/{api_name}", web::get().to(api_obfuscation))
            .route("/encryption-options", web::get().to(encryption_options))
            .route("/string-obfuscation", web::post().to(string_obfuscation))
            .route("/iat", web::get().to(iat_manipulation))
            .route("/dead-code/{hash}", web::get().to(dead_code_analysis))

            // Job management
            .route("/jobs", web::get().to(list_jobs))
            .route("/jobs/{id}", web::get().to(get_job))
    );
}
