//! Manual Compliance Assessment API endpoints
//!
//! Provides REST API endpoints for manual compliance assessments, including:
//! - Rubric management (create, read, update, delete)
//! - Assessment management with workflow (draft, submit, approve, reject)
//! - Evidence file upload and management
//! - Assessment campaigns for coordinating multiple assessments
//! - Combined results merging automated and manual assessments

pub mod assessments;
pub mod campaigns;
pub mod evidence;
pub mod reports;
pub mod rubrics;
pub mod types;

use actix_web::web;

/// Configure manual compliance routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg
        // Rubric endpoints
        .route("/compliance/rubrics", web::get().to(rubrics::list_rubrics))
        .route("/compliance/rubrics", web::post().to(rubrics::create_rubric))
        .route(
            "/compliance/rubrics/{id}",
            web::get().to(rubrics::get_rubric),
        )
        .route(
            "/compliance/rubrics/{id}",
            web::put().to(rubrics::update_rubric),
        )
        .route(
            "/compliance/rubrics/{id}",
            web::delete().to(rubrics::delete_rubric),
        )
        .route(
            "/compliance/frameworks/{framework_id}/rubrics",
            web::get().to(rubrics::get_framework_rubrics),
        )
        // Assessment endpoints
        .route(
            "/compliance/assessments",
            web::get().to(assessments::list_assessments),
        )
        .route(
            "/compliance/assessments",
            web::post().to(assessments::create_assessment),
        )
        .route(
            "/compliance/assessments/{id}",
            web::get().to(assessments::get_assessment),
        )
        .route(
            "/compliance/assessments/{id}",
            web::put().to(assessments::update_assessment),
        )
        .route(
            "/compliance/assessments/{id}",
            web::delete().to(assessments::delete_assessment),
        )
        .route(
            "/compliance/assessments/{id}/submit",
            web::post().to(assessments::submit_assessment),
        )
        .route(
            "/compliance/assessments/{id}/approve",
            web::post().to(assessments::approve_assessment),
        )
        .route(
            "/compliance/assessments/{id}/reject",
            web::post().to(assessments::reject_assessment),
        )
        // Evidence endpoints
        .route(
            "/compliance/assessments/{id}/evidence",
            web::post().to(evidence::add_evidence),
        )
        .route(
            "/compliance/assessments/{id}/evidence/upload",
            web::post().to(evidence::upload_evidence_file),
        )
        .route(
            "/compliance/assessments/{id}/evidence",
            web::get().to(evidence::list_evidence),
        )
        .route(
            "/compliance/evidence/{id}",
            web::delete().to(evidence::delete_evidence),
        )
        .route(
            "/compliance/evidence/{id}/download",
            web::get().to(evidence::download_evidence),
        )
        // Campaign endpoints
        .route(
            "/compliance/campaigns",
            web::get().to(campaigns::list_campaigns),
        )
        .route(
            "/compliance/campaigns",
            web::post().to(campaigns::create_campaign),
        )
        .route(
            "/compliance/campaigns/{id}",
            web::get().to(campaigns::get_campaign),
        )
        .route(
            "/compliance/campaigns/{id}",
            web::put().to(campaigns::update_campaign),
        )
        .route(
            "/compliance/campaigns/{id}",
            web::delete().to(campaigns::delete_campaign),
        )
        .route(
            "/compliance/campaigns/{id}/progress",
            web::get().to(campaigns::get_campaign_progress),
        )
        // Combined results endpoint
        .route(
            "/scans/{id}/compliance/combined",
            web::get().to(reports::get_combined_compliance),
        );
}
