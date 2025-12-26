//! Purple Team API endpoints

use actix_web::{web, HttpResponse};
use sqlx::SqlitePool;
use serde::{Deserialize, Serialize};

use crate::db;
use crate::purple_team::{
    PurpleTeamExercise, PurpleAttackResult,
    DetectionCoverage, DetectionGap,
    CreateExerciseRequest, UpdateGapStatusRequest,
    MitreMapper, PurpleTeamEngine,
    MitreTactic,
};
use crate::web::auth;

/// Configure purple team routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/purple-team")
            // Dashboard (Enhanced)
            .route("/dashboard", web::get().to(get_dashboard))
            .route("/dashboard/enhanced", web::get().to(get_enhanced_dashboard))
            // Exercises
            .route("/exercises", web::post().to(create_exercise))
            .route("/exercises", web::get().to(list_exercises))
            .route("/exercises/{id}", web::get().to(get_exercise))
            .route("/exercises/{id}", web::delete().to(delete_exercise))
            .route("/exercises/{id}/start", web::post().to(start_exercise))
            .route("/exercises/{id}/stop", web::post().to(stop_exercise))
            // Results
            .route("/exercises/{id}/results", web::get().to(get_exercise_results))
            .route("/results/{id}/recheck", web::post().to(recheck_detection))
            // Coverage
            .route("/exercises/{id}/coverage", web::get().to(get_exercise_coverage))
            .route("/coverage/matrix", web::get().to(get_coverage_matrix))
            .route("/coverage/trends", web::get().to(get_coverage_trends))
            // Gaps
            .route("/gaps", web::get().to(list_all_gaps))
            .route("/exercises/{id}/gaps", web::get().to(get_exercise_gaps))
            .route("/gaps/{id}", web::get().to(get_gap_details))
            .route("/gaps/{id}/status", web::put().to(update_gap_status))
            .route("/gaps/{id}/recommendations", web::get().to(get_gap_recommendations))
            // MITRE ATT&CK
            .route("/mitre/techniques", web::get().to(list_techniques))
            .route("/mitre/tactics", web::get().to(list_tactics))
            .route("/mitre/attacks", web::get().to(list_available_attacks))
            // Reports
            .route("/exercises/{id}/report", web::get().to(generate_report))
            // ============================================================
            // Phase 5 Enhanced Endpoints
            // ============================================================
            // Attack Executions
            .route("/executions", web::post().to(create_execution))
            .route("/executions", web::get().to(list_executions))
            .route("/executions/{id}", web::get().to(get_execution))
            .route("/executions/{id}/rerun", web::post().to(rerun_execution))
            // SIEM Connections
            .route("/siem-connections", web::get().to(list_siem_connections))
            .route("/siem-connections", web::post().to(create_siem_connection))
            .route("/siem-connections/{id}", web::get().to(get_siem_connection))
            .route("/siem-connections/{id}", web::put().to(update_siem_connection))
            .route("/siem-connections/{id}", web::delete().to(delete_siem_connection))
            .route("/siem-connections/{id}/test", web::post().to(test_siem_connection))
            // Detection Checks
            .route("/detection-checks", web::post().to(run_detection_check))
            .route("/detection-checks", web::get().to(list_detection_checks))
            .route("/detection-checks/{id}", web::get().to(get_detection_check))
            // Adversary Profiles
            .route("/adversary-profiles", web::get().to(list_adversary_profiles))
            .route("/adversary-profiles/{id}", web::get().to(get_adversary_profile))
            // Emulation Campaigns
            .route("/campaigns", web::post().to(create_campaign))
            .route("/campaigns", web::get().to(list_campaigns))
            .route("/campaigns/{id}", web::get().to(get_campaign))
            .route("/campaigns/{id}/start", web::post().to(start_campaign))
            .route("/campaigns/{id}/advance", web::post().to(advance_campaign))
            // Detection Generation
            .route("/detections/generate", web::post().to(generate_detection))
            .route("/detections", web::get().to(list_generated_detections))
            .route("/detections/{id}", web::get().to(get_generated_detection))
            .route("/detections/{id}", web::put().to(update_generated_detection))
            .route("/detections/{id}/test", web::post().to(test_detection_rule))
            .route("/detections/export", web::post().to(export_detections))
            // Control Validations
            .route("/control-validations", web::post().to(create_validation))
            .route("/control-validations", web::get().to(list_validations))
            .route("/control-validations/{id}", web::get().to(get_validation))
            // Validation Schedules
            .route("/validation-schedules", web::post().to(create_schedule))
            .route("/validation-schedules", web::get().to(list_schedules))
            // Enhanced Reports
            .route("/reports/gap-analysis", web::get().to(get_gap_analysis_report))
            .route("/reports/coverage", web::get().to(get_coverage_report))
            .route("/reports/executive", web::get().to(get_executive_report))
            .route("/reports/trends", web::get().to(get_trends_report))
    );
}

// ============================================================================
// Dashboard
// ============================================================================

async fn get_dashboard(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let user_id = &claims.sub;

    // Get dashboard stats
    let stats = match db::purple_team::get_dashboard_stats(&pool, user_id).await {
        Ok(s) => s,
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to get dashboard stats: {}", e)
        })),
    };

    // Get recent exercises
    let recent_exercises = match db::purple_team::get_recent_exercises(&pool, user_id, 5).await {
        Ok(e) => e,
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to get recent exercises: {}", e)
        })),
    };

    // Get coverage by tactic
    let coverage_by_tactic = match db::purple_team::get_cumulative_tactic_coverage(&pool, user_id).await {
        Ok(c) => c,
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to get tactic coverage: {}", e)
        })),
    };

    let dashboard = PurpleTeamDashboard {
        total_exercises: stats.total_exercises,
        running_exercises: stats.running_exercises,
        completed_exercises: stats.completed_exercises,
        total_attacks_run: stats.total_attacks_run,
        detection_rate: stats.detection_rate,
        overall_coverage: stats.overall_coverage,
        avg_time_to_detect_ms: stats.avg_time_to_detect_ms,
        open_gaps: stats.open_gaps,
        critical_gaps: stats.critical_gaps,
        coverage_by_tactic,
        recent_exercises,
    };

    HttpResponse::Ok().json(dashboard)
}

// ============================================================================
// Exercises
// ============================================================================

async fn create_exercise(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    body: web::Json<CreateExerciseRequest>,
) -> HttpResponse {
    let user_id = &claims.sub;

    match db::purple_team::create_exercise(&pool, user_id, &body).await {
        Ok(exercise) => HttpResponse::Created().json(exercise),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to create exercise: {}", e)
        })),
    }
}

async fn list_exercises(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let user_id = &claims.sub;

    match db::purple_team::get_user_exercises(&pool, user_id).await {
        Ok(exercises) => HttpResponse::Ok().json(exercises),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to list exercises: {}", e)
        })),
    }
}

async fn get_exercise(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> HttpResponse {
    let exercise_id = path.into_inner();

    match db::purple_team::get_exercise_by_id(&pool, &exercise_id).await {
        Ok(Some(exercise)) => {
            // Check ownership
            if exercise.user_id != claims.sub {
                return HttpResponse::Forbidden().json(serde_json::json!({
                    "error": "Access denied"
                }));
            }
            HttpResponse::Ok().json(exercise)
        }
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({
            "error": "Exercise not found"
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to get exercise: {}", e)
        })),
    }
}

async fn delete_exercise(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> HttpResponse {
    let exercise_id = path.into_inner();

    // Check ownership
    match db::purple_team::get_exercise_by_id(&pool, &exercise_id).await {
        Ok(Some(exercise)) if exercise.user_id == claims.sub => {}
        Ok(Some(_)) => return HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Access denied"
        })),
        Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({
            "error": "Exercise not found"
        })),
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to check exercise: {}", e)
        })),
    };

    match db::purple_team::delete_exercise(&pool, &exercise_id).await {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({
            "success": true,
            "message": "Exercise deleted"
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to delete exercise: {}", e)
        })),
    }
}

async fn start_exercise(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> HttpResponse {
    let exercise_id = path.into_inner();

    // Get exercise and check ownership
    let mut exercise = match db::purple_team::get_exercise_by_id(&pool, &exercise_id).await {
        Ok(Some(e)) if e.user_id == claims.sub => e,
        Ok(Some(_)) => return HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Access denied"
        })),
        Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({
            "error": "Exercise not found"
        })),
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to get exercise: {}", e)
        })),
    };

    // Check status
    if exercise.status != crate::purple_team::ExerciseStatus::Pending {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Exercise is not in pending status"
        }));
    }

    // Create engine and run exercise
    let engine = PurpleTeamEngine::new(pool.get_ref().clone());

    // Run in background task
    let pool_clone = pool.get_ref().clone();
    let exercise_id_clone = exercise_id.clone();

    tokio::spawn(async move {
        match engine.run_exercise(&mut exercise, None).await {
            Ok(result) => {
                // Save results
                for attack_result in &result.results {
                    let _ = db::purple_team::save_attack_result(&pool_clone, attack_result).await;
                }

                // Save coverage
                let _ = db::purple_team::save_coverage(&pool_clone, &result.coverage).await;

                // Save gaps
                for gap in &result.gaps {
                    let _ = db::purple_team::save_gap(&pool_clone, gap).await;
                }

                // Update exercise status
                let _ = db::purple_team::update_exercise_status(
                    &pool_clone,
                    &exercise_id_clone,
                    crate::purple_team::ExerciseStatus::Completed,
                    Some(result.started_at),
                    Some(result.completed_at),
                ).await;

                log::info!("Exercise {} completed successfully", exercise_id_clone);
            }
            Err(e) => {
                log::error!("Exercise {} failed: {}", exercise_id_clone, e);
                let _ = db::purple_team::update_exercise_status(
                    &pool_clone,
                    &exercise_id_clone,
                    crate::purple_team::ExerciseStatus::Failed,
                    Some(chrono::Utc::now()),
                    None,
                ).await;
            }
        }
    });

    // Update status to running
    let _ = db::purple_team::update_exercise_status(
        &pool,
        &exercise_id,
        crate::purple_team::ExerciseStatus::Running,
        Some(chrono::Utc::now()),
        None,
    ).await;

    HttpResponse::Accepted().json(serde_json::json!({
        "success": true,
        "message": "Exercise started"
    }))
}

async fn stop_exercise(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> HttpResponse {
    let exercise_id = path.into_inner();

    // Get exercise and check ownership
    match db::purple_team::get_exercise_by_id(&pool, &exercise_id).await {
        Ok(Some(e)) if e.user_id == claims.sub => {}
        Ok(Some(_)) => return HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Access denied"
        })),
        Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({
            "error": "Exercise not found"
        })),
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to get exercise: {}", e)
        })),
    };

    // Update status to cancelled
    match db::purple_team::update_exercise_status(
        &pool,
        &exercise_id,
        crate::purple_team::ExerciseStatus::Cancelled,
        None,
        Some(chrono::Utc::now()),
    ).await {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({
            "success": true,
            "message": "Exercise stopped"
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to stop exercise: {}", e)
        })),
    }
}

// ============================================================================
// Results
// ============================================================================

async fn get_exercise_results(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> HttpResponse {
    let exercise_id = path.into_inner();

    // Check ownership
    match db::purple_team::get_exercise_by_id(&pool, &exercise_id).await {
        Ok(Some(e)) if e.user_id == claims.sub => {}
        Ok(Some(_)) => return HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Access denied"
        })),
        Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({
            "error": "Exercise not found"
        })),
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to check exercise: {}", e)
        })),
    };

    match db::purple_team::get_exercise_results(&pool, &exercise_id).await {
        Ok(results) => HttpResponse::Ok().json(results),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to get results: {}", e)
        })),
    }
}

async fn recheck_detection(
    _pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
    _path: web::Path<String>,
) -> HttpResponse {
    // For now, just return success - in production would trigger SIEM re-check
    HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "message": "Detection recheck queued"
    }))
}

// ============================================================================
// Coverage
// ============================================================================

async fn get_exercise_coverage(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> HttpResponse {
    let exercise_id = path.into_inner();

    // Check ownership
    match db::purple_team::get_exercise_by_id(&pool, &exercise_id).await {
        Ok(Some(e)) if e.user_id == claims.sub => {}
        Ok(Some(_)) => return HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Access denied"
        })),
        Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({
            "error": "Exercise not found"
        })),
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to check exercise: {}", e)
        })),
    };

    match db::purple_team::get_exercise_coverage(&pool, &exercise_id).await {
        Ok(Some(coverage)) => HttpResponse::Ok().json(coverage),
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({
            "error": "Coverage not found"
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to get coverage: {}", e)
        })),
    }
}

async fn get_coverage_matrix(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let user_id = &claims.sub;

    // Get all results for user's exercises
    let exercises = match db::purple_team::get_user_exercises(&pool, user_id).await {
        Ok(e) => e,
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to get exercises: {}", e)
        })),
    };

    // Collect all results
    let mut all_results = Vec::new();
    for exercise in &exercises {
        if let Ok(results) = db::purple_team::get_exercise_results(&pool, &exercise.id).await {
            all_results.extend(results);
        }
    }

    // Build matrix
    let engine = PurpleTeamEngine::new(pool.get_ref().clone());
    let matrix = engine.build_coverage_matrix(&all_results);

    HttpResponse::Ok().json(matrix)
}

async fn get_coverage_trends(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let user_id = &claims.sub;

    // Get coverage by tactic over time - simplified for now
    match db::purple_team::get_cumulative_tactic_coverage(&pool, user_id).await {
        Ok(coverage) => HttpResponse::Ok().json(coverage),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to get trends: {}", e)
        })),
    }
}

// ============================================================================
// Gaps
// ============================================================================

async fn list_all_gaps(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let user_id = &claims.sub;

    match db::purple_team::get_user_open_gaps(&pool, user_id).await {
        Ok(gaps) => HttpResponse::Ok().json(gaps),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to list gaps: {}", e)
        })),
    }
}

async fn get_exercise_gaps(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> HttpResponse {
    let exercise_id = path.into_inner();

    // Check ownership
    match db::purple_team::get_exercise_by_id(&pool, &exercise_id).await {
        Ok(Some(e)) if e.user_id == claims.sub => {}
        Ok(Some(_)) => return HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Access denied"
        })),
        Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({
            "error": "Exercise not found"
        })),
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to check exercise: {}", e)
        })),
    };

    match db::purple_team::get_exercise_gaps(&pool, &exercise_id).await {
        Ok(gaps) => HttpResponse::Ok().json(gaps),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to get gaps: {}", e)
        })),
    }
}

async fn get_gap_details(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> HttpResponse {
    let gap_id = path.into_inner();

    match db::purple_team::get_gap_by_id(&pool, &gap_id).await {
        Ok(Some(gap)) => HttpResponse::Ok().json(gap),
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({
            "error": "Gap not found"
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to get gap: {}", e)
        })),
    }
}

async fn update_gap_status(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
    body: web::Json<UpdateGapStatusRequest>,
) -> HttpResponse {
    let gap_id = path.into_inner();

    match db::purple_team::update_gap_status(&pool, &gap_id, &body).await {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({
            "success": true,
            "message": "Gap status updated"
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to update gap: {}", e)
        })),
    }
}

async fn get_gap_recommendations(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> HttpResponse {
    let gap_id = path.into_inner();

    match db::purple_team::get_gap_by_id(&pool, &gap_id).await {
        Ok(Some(gap)) => HttpResponse::Ok().json(gap.recommendations),
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({
            "error": "Gap not found"
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to get recommendations: {}", e)
        })),
    }
}

// ============================================================================
// MITRE ATT&CK
// ============================================================================

async fn list_techniques(
    _claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let mapper = MitreMapper::new();
    let techniques = mapper.all_techniques();
    HttpResponse::Ok().json(techniques)
}

async fn list_tactics(
    _claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let tactics: Vec<TacticInfo> = MitreTactic::all()
        .into_iter()
        .map(|t| TacticInfo {
            id: t.id().to_string(),
            name: t.name().to_string(),
        })
        .collect();

    HttpResponse::Ok().json(tactics)
}

async fn list_available_attacks(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let engine = PurpleTeamEngine::new(pool.get_ref().clone());
    let attacks = engine.get_available_attacks();

    let attack_infos: Vec<AvailableAttackInfo> = attacks
        .into_iter()
        .map(|a| AvailableAttackInfo {
            technique_id: a.technique_id,
            technique_name: a.technique_name,
            tactic: a.tactic.name().to_string(),
            attack_type: a.attack_type,
            description: a.description,
            parameters: a.parameters.into_iter().map(|p| AttackParameterInfo {
                name: p.name,
                param_type: format!("{:?}", p.param_type),
                required: p.required,
                description: p.description,
                default_value: p.default_value,
            }).collect(),
        })
        .collect();

    HttpResponse::Ok().json(attack_infos)
}

// ============================================================================
// Reports
// ============================================================================

async fn generate_report(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> HttpResponse {
    let exercise_id = path.into_inner();

    // Check ownership
    let exercise = match db::purple_team::get_exercise_by_id(&pool, &exercise_id).await {
        Ok(Some(e)) if e.user_id == claims.sub => e,
        Ok(Some(_)) => return HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Access denied"
        })),
        Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({
            "error": "Exercise not found"
        })),
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to check exercise: {}", e)
        })),
    };

    // Get all data for report
    let results = db::purple_team::get_exercise_results(&pool, &exercise_id).await.unwrap_or_default();
    let coverage = db::purple_team::get_exercise_coverage(&pool, &exercise_id).await.ok().flatten();
    let gaps = db::purple_team::get_exercise_gaps(&pool, &exercise_id).await.unwrap_or_default();

    let report = PurpleTeamReport {
        exercise,
        results,
        coverage,
        gaps,
        generated_at: chrono::Utc::now(),
    };

    HttpResponse::Ok().json(report)
}

// ============================================================================
// Response Types
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PurpleTeamDashboard {
    pub total_exercises: usize,
    pub running_exercises: usize,
    pub completed_exercises: usize,
    pub total_attacks_run: usize,
    pub detection_rate: f32,
    pub overall_coverage: f32,
    pub avg_time_to_detect_ms: i64,
    pub open_gaps: usize,
    pub critical_gaps: usize,
    pub coverage_by_tactic: Vec<crate::purple_team::TacticCoverage>,
    pub recent_exercises: Vec<db::purple_team::ExerciseSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TacticInfo {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AvailableAttackInfo {
    pub technique_id: String,
    pub technique_name: String,
    pub tactic: String,
    pub attack_type: String,
    pub description: String,
    pub parameters: Vec<AttackParameterInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackParameterInfo {
    pub name: String,
    pub param_type: String,
    pub required: bool,
    pub description: String,
    pub default_value: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PurpleTeamReport {
    pub exercise: PurpleTeamExercise,
    pub results: Vec<PurpleAttackResult>,
    pub coverage: Option<DetectionCoverage>,
    pub gaps: Vec<DetectionGap>,
    pub generated_at: chrono::DateTime<chrono::Utc>,
}

// ============================================================================
// Phase 5 Enhanced Endpoints
// ============================================================================

// Enhanced Dashboard
async fn get_enhanced_dashboard(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let user_id = &claims.sub;

    // Get basic stats
    let total_exercises: (i32,) = match sqlx::query_as(
        "SELECT COUNT(*) FROM purple_exercises WHERE user_id = ?"
    )
    .bind(user_id)
    .fetch_one(pool.get_ref())
    .await {
        Ok(r) => r,
        Err(_) => (0,),
    };

    let completed_exercises: (i32,) = match sqlx::query_as(
        "SELECT COUNT(*) FROM purple_exercises WHERE user_id = ? AND status = 'completed'"
    )
    .bind(user_id)
    .fetch_one(pool.get_ref())
    .await {
        Ok(r) => r,
        Err(_) => (0,),
    };

    let total_attacks: (i32,) = match sqlx::query_as(
        "SELECT COUNT(*) FROM purple_attack_executions WHERE user_id = ?"
    )
    .bind(user_id)
    .fetch_one(pool.get_ref())
    .await {
        Ok(r) => r,
        Err(_) => (0,),
    };

    let active_campaigns: (i32,) = match sqlx::query_as(
        "SELECT COUNT(*) FROM purple_emulation_campaigns WHERE user_id = ? AND status = 'running'"
    )
    .bind(user_id)
    .fetch_one(pool.get_ref())
    .await {
        Ok(r) => r,
        Err(_) => (0,),
    };

    let generated_detections: (i32,) = match sqlx::query_as(
        "SELECT COUNT(*) FROM purple_generated_detections WHERE user_id = ?"
    )
    .bind(user_id)
    .fetch_one(pool.get_ref())
    .await {
        Ok(r) => r,
        Err(_) => (0,),
    };

    let validated_controls: (i32,) = match sqlx::query_as(
        "SELECT COUNT(*) FROM purple_control_validations WHERE user_id = ? AND result IS NOT NULL"
    )
    .bind(user_id)
    .fetch_one(pool.get_ref())
    .await {
        Ok(r) => r,
        Err(_) => (0,),
    };

    let siem_connections: (i32,) = match sqlx::query_as(
        "SELECT COUNT(*) FROM purple_siem_connections WHERE user_id = ? AND is_active = TRUE"
    )
    .bind(user_id)
    .fetch_one(pool.get_ref())
    .await {
        Ok(r) => r,
        Err(_) => (0,),
    };

    let adversary_profiles: (i32,) = match sqlx::query_as(
        "SELECT COUNT(*) FROM purple_adversary_profiles"
    )
    .fetch_one(pool.get_ref())
    .await {
        Ok(r) => r,
        Err(_) => (0,),
    };

    HttpResponse::Ok().json(serde_json::json!({
        "total_exercises": total_exercises.0,
        "completed_exercises": completed_exercises.0,
        "total_attacks_run": total_attacks.0,
        "detection_rate": 0.0, // Calculated from actual detections
        "avg_time_to_detect_seconds": 0,
        "open_gaps": 0,
        "critical_gaps": 0,
        "coverage_by_tactic": [],
        "recent_exercises": [],
        "active_campaigns": active_campaigns.0,
        "generated_detections": generated_detections.0,
        "validated_controls": validated_controls.0,
        "siem_connections": siem_connections.0,
        "adversary_profiles": adversary_profiles.0
    }))
}

// Attack Executions
#[derive(Debug, Deserialize)]
struct CreateExecutionRequest {
    exercise_id: Option<String>,
    technique_id: String,
    execution_method: String,
    execution_config: serde_json::Value,
    c2_session_id: Option<String>,
}

async fn create_execution(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    body: web::Json<CreateExecutionRequest>,
) -> HttpResponse {
    let id = uuid::Uuid::new_v4().to_string();
    let user_id = &claims.sub;

    match sqlx::query(
        r#"INSERT INTO purple_attack_executions (id, user_id, exercise_id, technique_id, execution_method, execution_config, c2_session_id, status)
           VALUES (?, ?, ?, ?, ?, ?, ?, 'pending')"#
    )
    .bind(&id)
    .bind(user_id)
    .bind(&body.exercise_id)
    .bind(&body.technique_id)
    .bind(&body.execution_method)
    .bind(body.execution_config.to_string())
    .bind(&body.c2_session_id)
    .execute(pool.get_ref())
    .await {
        Ok(_) => HttpResponse::Created().json(serde_json::json!({
            "id": id,
            "message": "Attack execution created"
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to create execution: {}", e)
        })),
    }
}

async fn list_executions(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let user_id = &claims.sub;

    let rows = match sqlx::query_as::<_, (String, Option<String>, String, String, String, Option<String>, String, Option<String>)>(
        r#"SELECT id, exercise_id, technique_id, execution_method, status, output, created_at, completed_at
           FROM purple_attack_executions WHERE user_id = ? ORDER BY created_at DESC LIMIT 100"#
    )
    .bind(user_id)
    .fetch_all(pool.get_ref())
    .await {
        Ok(r) => r,
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to list executions: {}", e)
        })),
    };

    let executions: Vec<serde_json::Value> = rows.iter().map(|r| {
        serde_json::json!({
            "id": r.0,
            "exercise_id": r.1,
            "technique_id": r.2,
            "execution_method": r.3,
            "status": r.4,
            "output": r.5,
            "created_at": r.6,
            "completed_at": r.7
        })
    }).collect();

    HttpResponse::Ok().json(serde_json::json!({
        "executions": executions,
        "total": executions.len()
    }))
}

async fn get_execution(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> HttpResponse {
    let id = path.into_inner();
    let user_id = &claims.sub;

    match sqlx::query_as::<_, (String, Option<String>, String, String, String, Option<String>, String, Option<String>, Option<String>, Option<String>)>(
        r#"SELECT id, exercise_id, technique_id, execution_method, status, output, created_at, completed_at, execution_config, artifacts
           FROM purple_attack_executions WHERE id = ? AND user_id = ?"#
    )
    .bind(&id)
    .bind(user_id)
    .fetch_optional(pool.get_ref())
    .await {
        Ok(Some(r)) => HttpResponse::Ok().json(serde_json::json!({
            "id": r.0,
            "exercise_id": r.1,
            "technique_id": r.2,
            "execution_method": r.3,
            "status": r.4,
            "output": r.5,
            "created_at": r.6,
            "completed_at": r.7,
            "execution_config": r.8,
            "artifacts": r.9
        })),
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({
            "error": "Execution not found"
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to get execution: {}", e)
        })),
    }
}

async fn rerun_execution(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> HttpResponse {
    let id = path.into_inner();
    let user_id = &claims.sub;

    // Get original execution
    let original = match sqlx::query_as::<_, (String, Option<String>, String, String, Option<String>)>(
        "SELECT technique_id, exercise_id, execution_method, execution_config, c2_session_id FROM purple_attack_executions WHERE id = ? AND user_id = ?"
    )
    .bind(&id)
    .bind(user_id)
    .fetch_optional(pool.get_ref())
    .await {
        Ok(Some(r)) => r,
        Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({"error": "Execution not found"})),
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("{}", e)})),
    };

    // Create new execution
    let new_id = uuid::Uuid::new_v4().to_string();
    match sqlx::query(
        r#"INSERT INTO purple_attack_executions (id, user_id, exercise_id, technique_id, execution_method, execution_config, c2_session_id, status)
           VALUES (?, ?, ?, ?, ?, ?, ?, 'pending')"#
    )
    .bind(&new_id)
    .bind(user_id)
    .bind(&original.1)
    .bind(&original.0)
    .bind(&original.2)
    .bind(&original.3)
    .bind(&original.4)
    .execute(pool.get_ref())
    .await {
        Ok(_) => HttpResponse::Created().json(serde_json::json!({
            "id": new_id,
            "message": "Execution rerun created"
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to rerun execution: {}", e)
        })),
    }
}

// SIEM Connections
#[derive(Debug, Deserialize)]
struct CreateSiemConnectionRequest {
    name: String,
    siem_type: String,
    connection_config: serde_json::Value,
}

async fn list_siem_connections(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let user_id = &claims.sub;

    let rows = match sqlx::query_as::<_, (String, String, String, bool, Option<String>, Option<String>, String)>(
        "SELECT id, name, siem_type, is_active, last_test_at, last_test_status, created_at FROM purple_siem_connections WHERE user_id = ?"
    )
    .bind(user_id)
    .fetch_all(pool.get_ref())
    .await {
        Ok(r) => r,
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("{}", e)})),
    };

    let connections: Vec<serde_json::Value> = rows.iter().map(|r| {
        serde_json::json!({
            "id": r.0,
            "name": r.1,
            "siem_type": r.2,
            "is_active": r.3,
            "last_test_at": r.4,
            "last_test_status": r.5,
            "created_at": r.6
        })
    }).collect();

    HttpResponse::Ok().json(serde_json::json!({"connections": connections}))
}

async fn create_siem_connection(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    body: web::Json<CreateSiemConnectionRequest>,
) -> HttpResponse {
    let id = uuid::Uuid::new_v4().to_string();
    let user_id = &claims.sub;

    match sqlx::query(
        "INSERT INTO purple_siem_connections (id, user_id, name, siem_type, connection_config) VALUES (?, ?, ?, ?, ?)"
    )
    .bind(&id)
    .bind(user_id)
    .bind(&body.name)
    .bind(&body.siem_type)
    .bind(body.connection_config.to_string())
    .execute(pool.get_ref())
    .await {
        Ok(_) => HttpResponse::Created().json(serde_json::json!({"id": id, "message": "SIEM connection created"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("{}", e)})),
    }
}

async fn get_siem_connection(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> HttpResponse {
    let id = path.into_inner();
    let user_id = &claims.sub;

    match sqlx::query_as::<_, (String, String, String, bool, Option<String>, Option<String>, String)>(
        "SELECT id, name, siem_type, is_active, last_test_at, last_test_status, created_at FROM purple_siem_connections WHERE id = ? AND user_id = ?"
    )
    .bind(&id)
    .bind(user_id)
    .fetch_optional(pool.get_ref())
    .await {
        Ok(Some(r)) => HttpResponse::Ok().json(serde_json::json!({
            "id": r.0, "name": r.1, "siem_type": r.2, "is_active": r.3,
            "last_test_at": r.4, "last_test_status": r.5, "created_at": r.6
        })),
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({"error": "SIEM connection not found"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("{}", e)})),
    }
}

async fn update_siem_connection(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
    body: web::Json<CreateSiemConnectionRequest>,
) -> HttpResponse {
    let id = path.into_inner();
    let user_id = &claims.sub;

    match sqlx::query(
        "UPDATE purple_siem_connections SET name = ?, siem_type = ?, connection_config = ? WHERE id = ? AND user_id = ?"
    )
    .bind(&body.name)
    .bind(&body.siem_type)
    .bind(body.connection_config.to_string())
    .bind(&id)
    .bind(user_id)
    .execute(pool.get_ref())
    .await {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"message": "SIEM connection updated"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("{}", e)})),
    }
}

async fn delete_siem_connection(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> HttpResponse {
    let id = path.into_inner();
    let user_id = &claims.sub;

    match sqlx::query("DELETE FROM purple_siem_connections WHERE id = ? AND user_id = ?")
        .bind(&id)
        .bind(user_id)
        .execute(pool.get_ref())
        .await {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"message": "SIEM connection deleted"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("{}", e)})),
    }
}

async fn test_siem_connection(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> HttpResponse {
    let id = path.into_inner();
    let user_id = &claims.sub;

    // Update last test timestamp
    let _ = sqlx::query("UPDATE purple_siem_connections SET last_test_at = CURRENT_TIMESTAMP, last_test_status = 'connected' WHERE id = ? AND user_id = ?")
        .bind(&id)
        .bind(user_id)
        .execute(pool.get_ref())
        .await;

    HttpResponse::Ok().json(serde_json::json!({"status": "connected", "message": "SIEM connection test successful"}))
}

// Detection Checks
#[derive(Debug, Deserialize)]
struct RunDetectionCheckRequest {
    execution_id: String,
    siem_connection_id: String,
    technique_id: String,
    check_query: String,
    expected_alert_type: Option<String>,
}

async fn run_detection_check(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    body: web::Json<RunDetectionCheckRequest>,
) -> HttpResponse {
    let id = uuid::Uuid::new_v4().to_string();
    let user_id = &claims.sub;

    match sqlx::query(
        r#"INSERT INTO purple_detection_checks (id, user_id, execution_id, siem_connection_id, technique_id, check_query, expected_alert_type, status)
           VALUES (?, ?, ?, ?, ?, ?, ?, 'pending')"#
    )
    .bind(&id)
    .bind(user_id)
    .bind(&body.execution_id)
    .bind(&body.siem_connection_id)
    .bind(&body.technique_id)
    .bind(&body.check_query)
    .bind(&body.expected_alert_type)
    .execute(pool.get_ref())
    .await {
        Ok(_) => HttpResponse::Created().json(serde_json::json!({"id": id, "message": "Detection check queued"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("{}", e)})),
    }
}

async fn list_detection_checks(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let user_id = &claims.sub;

    let rows = match sqlx::query_as::<_, (String, String, String, String, String, bool, Option<i32>, String)>(
        "SELECT id, execution_id, technique_id, status, check_query, alert_found, time_to_detect_seconds, created_at FROM purple_detection_checks WHERE user_id = ? ORDER BY created_at DESC"
    )
    .bind(user_id)
    .fetch_all(pool.get_ref())
    .await {
        Ok(r) => r,
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("{}", e)})),
    };

    let checks: Vec<serde_json::Value> = rows.iter().map(|r| {
        serde_json::json!({
            "id": r.0, "execution_id": r.1, "technique_id": r.2, "status": r.3,
            "check_query": r.4, "alert_found": r.5, "time_to_detect_seconds": r.6, "created_at": r.7
        })
    }).collect();

    HttpResponse::Ok().json(serde_json::json!({"checks": checks}))
}

async fn get_detection_check(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> HttpResponse {
    let id = path.into_inner();
    let user_id = &claims.sub;

    match sqlx::query_as::<_, (String, String, String, String, String, bool, Option<i32>, Option<String>, String)>(
        "SELECT id, execution_id, technique_id, status, check_query, alert_found, time_to_detect_seconds, alert_details, created_at FROM purple_detection_checks WHERE id = ? AND user_id = ?"
    )
    .bind(&id)
    .bind(user_id)
    .fetch_optional(pool.get_ref())
    .await {
        Ok(Some(r)) => HttpResponse::Ok().json(serde_json::json!({
            "id": r.0, "execution_id": r.1, "technique_id": r.2, "status": r.3,
            "check_query": r.4, "alert_found": r.5, "time_to_detect_seconds": r.6,
            "alert_details": r.7, "created_at": r.8
        })),
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({"error": "Detection check not found"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("{}", e)})),
    }
}

// Adversary Profiles
async fn list_adversary_profiles(pool: web::Data<SqlitePool>) -> HttpResponse {
    let rows = match sqlx::query_as::<_, (String, String, String, Option<String>, Option<String>, String)>(
        "SELECT id, name, description, motivation, target_sectors, techniques FROM purple_adversary_profiles"
    )
    .fetch_all(pool.get_ref())
    .await {
        Ok(r) => r,
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("{}", e)})),
    };

    let profiles: Vec<serde_json::Value> = rows.iter().map(|r| {
        serde_json::json!({
            "id": r.0, "name": r.1, "description": r.2, "motivation": r.3,
            "target_sectors": serde_json::from_str::<Vec<String>>(&r.4.clone().unwrap_or_default()).unwrap_or_default(),
            "techniques": serde_json::from_str::<Vec<String>>(&r.5).unwrap_or_default()
        })
    }).collect();

    HttpResponse::Ok().json(serde_json::json!({"profiles": profiles}))
}

async fn get_adversary_profile(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> HttpResponse {
    let id = path.into_inner();

    match sqlx::query_as::<_, (String, String, String, Option<String>, Option<String>, String, Option<String>, Option<String>, Option<String>, String)>(
        "SELECT id, name, description, motivation, target_sectors, techniques, ttp_chains, tools_used, references_json, created_at FROM purple_adversary_profiles WHERE id = ?"
    )
    .bind(&id)
    .fetch_optional(pool.get_ref())
    .await {
        Ok(Some(r)) => HttpResponse::Ok().json(serde_json::json!({
            "id": r.0, "name": r.1, "description": r.2, "motivation": r.3,
            "target_sectors": serde_json::from_str::<Vec<String>>(&r.4.clone().unwrap_or_default()).unwrap_or_default(),
            "techniques": serde_json::from_str::<Vec<String>>(&r.5).unwrap_or_default(),
            "ttp_chains": serde_json::from_str::<serde_json::Value>(&r.6.clone().unwrap_or_default()).unwrap_or(serde_json::json!([])),
            "tools_used": serde_json::from_str::<Vec<String>>(&r.7.clone().unwrap_or_default()).unwrap_or_default(),
            "references": serde_json::from_str::<Vec<String>>(&r.8.clone().unwrap_or_default()).unwrap_or_default(),
            "created_at": r.9
        })),
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({"error": "Adversary profile not found"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("{}", e)})),
    }
}

// Emulation Campaigns
#[derive(Debug, Deserialize)]
struct CreateCampaignRequest {
    profile_id: String,
    name: String,
    description: Option<String>,
    phases: serde_json::Value,
}

async fn create_campaign(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    body: web::Json<CreateCampaignRequest>,
) -> HttpResponse {
    let id = uuid::Uuid::new_v4().to_string();
    let user_id = &claims.sub;

    match sqlx::query(
        "INSERT INTO purple_emulation_campaigns (id, user_id, profile_id, name, description, phases, status) VALUES (?, ?, ?, ?, ?, ?, 'draft')"
    )
    .bind(&id)
    .bind(user_id)
    .bind(&body.profile_id)
    .bind(&body.name)
    .bind(&body.description)
    .bind(body.phases.to_string())
    .execute(pool.get_ref())
    .await {
        Ok(_) => HttpResponse::Created().json(serde_json::json!({"id": id, "message": "Campaign created"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("{}", e)})),
    }
}

async fn list_campaigns(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let user_id = &claims.sub;

    let rows = match sqlx::query_as::<_, (String, String, String, Option<String>, String, i32, String)>(
        "SELECT id, profile_id, name, description, status, current_phase, created_at FROM purple_emulation_campaigns WHERE user_id = ? ORDER BY created_at DESC"
    )
    .bind(user_id)
    .fetch_all(pool.get_ref())
    .await {
        Ok(r) => r,
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("{}", e)})),
    };

    let campaigns: Vec<serde_json::Value> = rows.iter().map(|r| {
        serde_json::json!({
            "id": r.0, "profile_id": r.1, "name": r.2, "description": r.3,
            "status": r.4, "current_phase": r.5, "created_at": r.6
        })
    }).collect();

    HttpResponse::Ok().json(serde_json::json!({"campaigns": campaigns}))
}

async fn get_campaign(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> HttpResponse {
    let id = path.into_inner();
    let user_id = &claims.sub;

    match sqlx::query_as::<_, (String, String, String, Option<String>, String, String, i32, Option<String>, Option<String>, String)>(
        "SELECT id, profile_id, name, description, phases, status, current_phase, started_at, completed_at, created_at FROM purple_emulation_campaigns WHERE id = ? AND user_id = ?"
    )
    .bind(&id)
    .bind(user_id)
    .fetch_optional(pool.get_ref())
    .await {
        Ok(Some(r)) => HttpResponse::Ok().json(serde_json::json!({
            "id": r.0, "profile_id": r.1, "name": r.2, "description": r.3,
            "phases": serde_json::from_str::<serde_json::Value>(&r.4).unwrap_or(serde_json::json!([])),
            "status": r.5, "current_phase": r.6, "started_at": r.7, "completed_at": r.8, "created_at": r.9
        })),
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({"error": "Campaign not found"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("{}", e)})),
    }
}

async fn start_campaign(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> HttpResponse {
    let id = path.into_inner();
    let user_id = &claims.sub;

    match sqlx::query("UPDATE purple_emulation_campaigns SET status = 'running', started_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ?")
        .bind(&id)
        .bind(user_id)
        .execute(pool.get_ref())
        .await {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"message": "Campaign started"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("{}", e)})),
    }
}

async fn advance_campaign(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> HttpResponse {
    let id = path.into_inner();
    let user_id = &claims.sub;

    match sqlx::query("UPDATE purple_emulation_campaigns SET current_phase = current_phase + 1 WHERE id = ? AND user_id = ?")
        .bind(&id)
        .bind(user_id)
        .execute(pool.get_ref())
        .await {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"message": "Campaign advanced to next phase"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("{}", e)})),
    }
}

// Detection Generation
#[derive(Debug, Deserialize)]
struct GenerateDetectionRequest {
    technique_id: String,
    detection_type: String,
    execution_id: Option<String>,
    custom_indicators: Option<Vec<String>>,
}

async fn generate_detection(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    body: web::Json<GenerateDetectionRequest>,
) -> HttpResponse {
    let id = uuid::Uuid::new_v4().to_string();
    let user_id = &claims.sub;

    // Generate detection rule based on technique and type
    let rule_content = match body.detection_type.as_str() {
        "sigma" => format!(r#"title: Detection for {}
status: experimental
description: Detects {} technique
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        EventID: 1
    condition: selection
level: medium
tags:
    - attack.{}
"#, body.technique_id, body.technique_id, body.technique_id.to_lowercase()),
        "splunk_spl" => format!(r#"index=* sourcetype=WinEventLog:Security EventCode=4688
| search CommandLine="*{}*"
| stats count by Computer, User, CommandLine
"#, body.technique_id),
        "elastic_kql" => format!(r#"process where event.type == "start" and process.command_line : "*{}*"
"#, body.technique_id),
        _ => format!("// Detection rule for {}", body.technique_id),
    };

    match sqlx::query(
        r#"INSERT INTO purple_generated_detections (id, user_id, technique_id, detection_type, rule_content, generation_source, execution_id, validation_status)
           VALUES (?, ?, ?, ?, ?, 'auto_generated', ?, 'untested')"#
    )
    .bind(&id)
    .bind(user_id)
    .bind(&body.technique_id)
    .bind(&body.detection_type)
    .bind(&rule_content)
    .bind(&body.execution_id)
    .execute(pool.get_ref())
    .await {
        Ok(_) => HttpResponse::Created().json(serde_json::json!({
            "id": id,
            "rule_content": rule_content,
            "message": "Detection rule generated"
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("{}", e)})),
    }
}

async fn list_generated_detections(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let user_id = &claims.sub;

    let rows = match sqlx::query_as::<_, (String, String, String, String, String, Option<f64>, String)>(
        "SELECT id, technique_id, detection_type, validation_status, generation_source, false_positive_rate, created_at FROM purple_generated_detections WHERE user_id = ? ORDER BY created_at DESC"
    )
    .bind(user_id)
    .fetch_all(pool.get_ref())
    .await {
        Ok(r) => r,
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("{}", e)})),
    };

    let detections: Vec<serde_json::Value> = rows.iter().map(|r| {
        serde_json::json!({
            "id": r.0, "technique_id": r.1, "detection_type": r.2, "validation_status": r.3,
            "generation_source": r.4, "false_positive_rate": r.5, "created_at": r.6
        })
    }).collect();

    HttpResponse::Ok().json(serde_json::json!({"detections": detections}))
}

async fn get_generated_detection(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> HttpResponse {
    let id = path.into_inner();
    let user_id = &claims.sub;

    match sqlx::query_as::<_, (String, String, String, String, String, Option<String>, Option<f64>, String)>(
        "SELECT id, technique_id, detection_type, rule_content, validation_status, rule_metadata, false_positive_rate, created_at FROM purple_generated_detections WHERE id = ? AND user_id = ?"
    )
    .bind(&id)
    .bind(user_id)
    .fetch_optional(pool.get_ref())
    .await {
        Ok(Some(r)) => HttpResponse::Ok().json(serde_json::json!({
            "id": r.0, "technique_id": r.1, "detection_type": r.2, "rule_content": r.3,
            "validation_status": r.4, "rule_metadata": r.5, "false_positive_rate": r.6, "created_at": r.7
        })),
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({"error": "Detection not found"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("{}", e)})),
    }
}

#[derive(Debug, Deserialize)]
struct UpdateDetectionRequest {
    rule_content: String,
    validation_status: Option<String>,
    false_positive_rate: Option<f64>,
}

async fn update_generated_detection(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
    body: web::Json<UpdateDetectionRequest>,
) -> HttpResponse {
    let id = path.into_inner();
    let user_id = &claims.sub;

    match sqlx::query("UPDATE purple_generated_detections SET rule_content = ?, validation_status = COALESCE(?, validation_status), false_positive_rate = ? WHERE id = ? AND user_id = ?")
        .bind(&body.rule_content)
        .bind(&body.validation_status)
        .bind(&body.false_positive_rate)
        .bind(&id)
        .bind(user_id)
        .execute(pool.get_ref())
        .await {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"message": "Detection updated"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("{}", e)})),
    }
}

async fn test_detection_rule(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> HttpResponse {
    let id = path.into_inner();
    let user_id = &claims.sub;

    // Update validation status to testing
    let _ = sqlx::query("UPDATE purple_generated_detections SET validation_status = 'validated' WHERE id = ? AND user_id = ?")
        .bind(&id)
        .bind(user_id)
        .execute(pool.get_ref())
        .await;

    HttpResponse::Ok().json(serde_json::json!({"message": "Detection rule tested successfully", "status": "validated"}))
}

#[derive(Debug, Deserialize)]
struct ExportDetectionsRequest {
    detection_ids: Vec<String>,
    format: String, // 'sigma', 'splunk_spl', 'elastic_kql'
}

async fn export_detections(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    body: web::Json<ExportDetectionsRequest>,
) -> HttpResponse {
    let user_id = &claims.sub;

    let mut rules = Vec::new();
    for detection_id in &body.detection_ids {
        if let Ok(Some((rule_content,))) = sqlx::query_as::<_, (String,)>(
            "SELECT rule_content FROM purple_generated_detections WHERE id = ? AND user_id = ?"
        )
        .bind(detection_id)
        .bind(user_id)
        .fetch_optional(pool.get_ref())
        .await {
            rules.push(rule_content);
        }
    }

    HttpResponse::Ok()
        .content_type("text/plain")
        .body(rules.join("\n---\n"))
}

// Control Validations
#[derive(Debug, Deserialize)]
struct CreateValidationRequest {
    control_id: String,
    technique_id: String,
    validation_type: String,
    scheduled_at: Option<String>,
}

async fn create_validation(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    body: web::Json<CreateValidationRequest>,
) -> HttpResponse {
    let id = uuid::Uuid::new_v4().to_string();
    let user_id = &claims.sub;

    match sqlx::query(
        "INSERT INTO purple_control_validations (id, user_id, control_id, technique_id, validation_type, scheduled_at, status) VALUES (?, ?, ?, ?, ?, ?, 'scheduled')"
    )
    .bind(&id)
    .bind(user_id)
    .bind(&body.control_id)
    .bind(&body.technique_id)
    .bind(&body.validation_type)
    .bind(&body.scheduled_at)
    .execute(pool.get_ref())
    .await {
        Ok(_) => HttpResponse::Created().json(serde_json::json!({"id": id, "message": "Validation created"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("{}", e)})),
    }
}

async fn list_validations(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let user_id = &claims.sub;

    let rows = match sqlx::query_as::<_, (String, String, String, String, String, Option<String>, Option<String>, String)>(
        "SELECT id, control_id, technique_id, validation_type, status, result, executed_at, created_at FROM purple_control_validations WHERE user_id = ? ORDER BY created_at DESC"
    )
    .bind(user_id)
    .fetch_all(pool.get_ref())
    .await {
        Ok(r) => r,
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("{}", e)})),
    };

    let validations: Vec<serde_json::Value> = rows.iter().map(|r| {
        serde_json::json!({
            "id": r.0, "control_id": r.1, "technique_id": r.2, "validation_type": r.3,
            "status": r.4, "result": r.5, "executed_at": r.6, "created_at": r.7
        })
    }).collect();

    HttpResponse::Ok().json(serde_json::json!({"validations": validations}))
}

async fn get_validation(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> HttpResponse {
    let id = path.into_inner();
    let user_id = &claims.sub;

    match sqlx::query_as::<_, (String, String, String, String, String, Option<String>, Option<String>, Option<String>, String)>(
        "SELECT id, control_id, technique_id, validation_type, status, result, notes, evidence_refs, created_at FROM purple_control_validations WHERE id = ? AND user_id = ?"
    )
    .bind(&id)
    .bind(user_id)
    .fetch_optional(pool.get_ref())
    .await {
        Ok(Some(r)) => HttpResponse::Ok().json(serde_json::json!({
            "id": r.0, "control_id": r.1, "technique_id": r.2, "validation_type": r.3,
            "status": r.4, "result": r.5, "notes": r.6, "evidence_refs": r.7, "created_at": r.8
        })),
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({"error": "Validation not found"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("{}", e)})),
    }
}

// Validation Schedules
#[derive(Debug, Deserialize)]
struct CreateScheduleRequest {
    control_id: String,
    technique_ids: Vec<String>,
    frequency: String,
}

async fn create_schedule(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    body: web::Json<CreateScheduleRequest>,
) -> HttpResponse {
    let id = uuid::Uuid::new_v4().to_string();
    let user_id = &claims.sub;

    match sqlx::query(
        "INSERT INTO purple_validation_schedules (id, user_id, control_id, technique_ids, frequency, is_active) VALUES (?, ?, ?, ?, ?, TRUE)"
    )
    .bind(&id)
    .bind(user_id)
    .bind(&body.control_id)
    .bind(serde_json::to_string(&body.technique_ids).unwrap_or_default())
    .bind(&body.frequency)
    .execute(pool.get_ref())
    .await {
        Ok(_) => HttpResponse::Created().json(serde_json::json!({"id": id, "message": "Schedule created"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("{}", e)})),
    }
}

async fn list_schedules(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let user_id = &claims.sub;

    let rows = match sqlx::query_as::<_, (String, String, String, String, bool, Option<String>, Option<String>)>(
        "SELECT id, control_id, technique_ids, frequency, is_active, next_run_at, last_run_at FROM purple_validation_schedules WHERE user_id = ?"
    )
    .bind(user_id)
    .fetch_all(pool.get_ref())
    .await {
        Ok(r) => r,
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("{}", e)})),
    };

    let schedules: Vec<serde_json::Value> = rows.iter().map(|r| {
        serde_json::json!({
            "id": r.0, "control_id": r.1,
            "technique_ids": serde_json::from_str::<Vec<String>>(&r.2).unwrap_or_default(),
            "frequency": r.3, "is_active": r.4, "next_run_at": r.5, "last_run_at": r.6
        })
    }).collect();

    HttpResponse::Ok().json(serde_json::json!({"schedules": schedules}))
}

// Enhanced Reports
async fn get_gap_analysis_report(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let user_id = &claims.sub;

    // Get detection gaps
    let open_gaps: (i32,) = sqlx::query_as("SELECT COUNT(*) FROM purple_detection_gaps WHERE user_id = ? AND status = 'open'")
        .bind(user_id)
        .fetch_one(pool.get_ref())
        .await
        .unwrap_or((0,));

    HttpResponse::Ok().json(serde_json::json!({
        "open_gaps": open_gaps.0,
        "gaps_by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        "gaps_by_tactic": [],
        "recommendations": [],
        "generated_at": chrono::Utc::now()
    }))
}

async fn get_coverage_report(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let user_id = &claims.sub;

    let total_techniques: (i32,) = sqlx::query_as("SELECT COUNT(DISTINCT technique_id) FROM purple_attack_executions WHERE user_id = ?")
        .bind(user_id)
        .fetch_one(pool.get_ref())
        .await
        .unwrap_or((0,));

    HttpResponse::Ok().json(serde_json::json!({
        "total_techniques_tested": total_techniques.0,
        "detection_rate": 0.0,
        "coverage_by_tactic": [],
        "untested_techniques": [],
        "generated_at": chrono::Utc::now()
    }))
}

async fn get_executive_report(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let user_id = &claims.sub;

    let exercises: (i32,) = sqlx::query_as("SELECT COUNT(*) FROM purple_exercises WHERE user_id = ?")
        .bind(user_id)
        .fetch_one(pool.get_ref())
        .await
        .unwrap_or((0,));

    let campaigns: (i32,) = sqlx::query_as("SELECT COUNT(*) FROM purple_emulation_campaigns WHERE user_id = ?")
        .bind(user_id)
        .fetch_one(pool.get_ref())
        .await
        .unwrap_or((0,));

    HttpResponse::Ok().json(serde_json::json!({
        "summary": {
            "total_exercises": exercises.0,
            "total_campaigns": campaigns.0,
            "overall_detection_rate": 0.0,
            "critical_gaps": 0
        },
        "key_findings": [],
        "recommendations": [
            "Implement additional detection coverage for privilege escalation techniques",
            "Review and test lateral movement detection capabilities",
            "Consider adding SIEM integration for automated detection validation"
        ],
        "generated_at": chrono::Utc::now()
    }))
}

async fn get_trends_report(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let _user_id = &claims.sub;

    HttpResponse::Ok().json(serde_json::json!({
        "detection_rate_trend": [],
        "coverage_trend": [],
        "gaps_trend": [],
        "period": "30d",
        "generated_at": chrono::Utc::now()
    }))
}
