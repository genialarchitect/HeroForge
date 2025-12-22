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
            // Dashboard
            .route("/dashboard", web::get().to(get_dashboard))
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
