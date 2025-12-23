pub mod api;
pub mod audit;
pub mod auth;
pub mod broadcast;
pub mod error;
pub mod exploitation_broadcast;
pub mod openapi;
pub mod rate_limit;
pub mod rate_limit_stats;
pub mod scheduler;
pub mod websocket;

use actix_cors::Cors;
use actix_files as fs;
use actix_web::{middleware::{DefaultHeaders, Logger}, web, App, HttpServer, HttpRequest, HttpResponse};
use std::sync::Arc;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;
use crate::scanner::exploitation::ExploitationEngine;
use crate::cracking::CrackingEngine;

/// Fallback handler for SPA - serves index.html for any unmatched non-API routes
async fn spa_fallback(req: HttpRequest) -> HttpResponse {
    let path = req.path();

    // Don't serve SPA for API routes - return 404 instead
    if path.starts_with("/api/") {
        return HttpResponse::NotFound().json(serde_json::json!({
            "error": "Not found"
        }));
    }

    // Serve index.html for all other routes (SPA client-side routing)
    match std::fs::read_to_string("./frontend/dist/index.html") {
        Ok(content) => HttpResponse::Ok()
            .content_type("text/html; charset=utf-8")
            .body(content),
        Err(_) => HttpResponse::NotFound().body("Frontend not found"),
    }
}

pub async fn run_web_server(database_url: &str, bind_address: &str) -> std::io::Result<()> {
    log::info!("Initializing database...");
    let pool = crate::db::init_database(database_url)
        .await
        .expect("Failed to initialize database");

    // Initialize the shared exploitation engine
    let exploitation_engine = Arc::new(ExploitationEngine::with_default_safety());
    log::info!("Exploitation engine initialized");

    // Initialize the shared cracking engine
    let cracking_engine = Arc::new(tokio::sync::RwLock::new(CrackingEngine::new(pool.clone())));
    log::info!("Cracking engine initialized");

    // Start the background scheduler daemon
    scheduler::start_scheduler(Arc::new(pool.clone()));

    log::info!("Starting web server at http://{}", bind_address);

    // Log rate limiting configuration
    log::info!("Rate limiting enabled:");
    log::info!("  - Auth endpoints: 5 requests/minute per IP");
    log::info!("  - API endpoints: 100 requests/minute per IP");

    let engine_clone = exploitation_engine.clone();
    let cracking_engine_clone = cracking_engine.clone();
    let nuclei_state = Arc::new(api::nuclei::NucleiState::new());
    let nuclei_state_clone = nuclei_state.clone();
    let discovery_state = Arc::new(api::asset_discovery::DiscoveryState::default());
    let discovery_state_clone = discovery_state.clone();
    let privesc_state = Arc::new(api::privesc::PrivescState::default());
    let privesc_state_clone = privesc_state.clone();

    HttpServer::new(move || {
        // Configure CORS origins from environment variable or use defaults
        let mut cors = Cors::default();

        // Default development and production origins
        let default_origins = vec![
            "http://localhost:3000",
            "http://localhost:5173",
            "https://heroforge.genialarchitect.io",
        ];

        // Check for custom CORS origins from environment
        if let Ok(custom_origins) = std::env::var("CORS_ALLOWED_ORIGINS") {
            log::info!("Using custom CORS origins from environment variable");
            for origin in custom_origins.split(',') {
                let origin = origin.trim();
                if !origin.is_empty() {
                    log::info!("Adding CORS origin: {}", origin);
                    cors = cors.allowed_origin(origin);
                }
            }
        } else {
            // Use default origins
            log::info!("Using default CORS origins");
            for origin in default_origins {
                log::info!("Adding CORS origin: {}", origin);
                cors = cors.allowed_origin(origin);
            }
        }

        cors = cors
            .allowed_methods(vec!["GET", "POST", "PUT", "DELETE"])
            .allowed_headers(vec![
                actix_web::http::header::AUTHORIZATION,
                actix_web::http::header::ACCEPT,
                actix_web::http::header::CONTENT_TYPE,
            ])
            .supports_credentials()
            .max_age(3600);

        App::new()
            .app_data(web::Data::new(pool.clone()))
            .app_data(web::Data::from(engine_clone.clone()))
            .app_data(web::Data::from(cracking_engine_clone.clone()))
            .app_data(web::Data::from(nuclei_state_clone.clone()))
            .app_data(web::Data::from(discovery_state_clone.clone()))
            .app_data(web::Data::from(privesc_state_clone.clone()))
            .wrap(cors)
            .wrap(Logger::default())
            // Security headers per OWASP guidelines
            .wrap(
                DefaultHeaders::new()
                    .add(("X-Content-Type-Options", "nosniff"))
                    .add(("X-Frame-Options", "DENY"))
                    .add(("X-XSS-Protection", "1; mode=block"))
                    .add(("Referrer-Policy", "strict-origin-when-cross-origin"))
                    // CSP hardened: Removed 'unsafe-inline' for scripts, using 'self' only
                    // Note: Vite-built SPAs bundle all scripts, so 'self' is sufficient
                    // For styles, we keep 'unsafe-inline' as Vite uses inline styles for hot reload
                    // In production builds, consider using a build-time hash for styles
                    // Added connect-src for WebSocket connections (ws: wss:)
                    // Added object-src 'none', base-uri 'self', form-action 'self' for additional security
                    .add(("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self' ws: wss:; object-src 'none'; base-uri 'self'; form-action 'self';"))
                    .add(("Permissions-Policy", "geolocation=(), microphone=(), camera=()"))
                    .add(("Strict-Transport-Security", "max-age=31536000; includeSubDomains"))
            )
            // Public authentication routes with strict rate limiting (5 req/min per IP)
            .service(
                web::scope("/api/auth")
                    .wrap(rate_limit::RateLimitStatsMiddleware::auth())
                    .wrap(rate_limit::auth_rate_limiter())
                    .route("/register", web::post().to(api::auth::register))
                    .route("/login", web::post().to(api::auth::login))
                    .route("/refresh", web::post().to(api::auth::refresh))
                    .route("/logout", web::post().to(api::auth::logout))
                    // MFA verification endpoint (public, but requires MFA token from login)
                    .route("/mfa/verify", web::post().to(api::mfa::verify_mfa))
            )
            // Public privacy policy endpoint (no authentication required)
            .route("/api/privacy-policy", web::get().to(api::privacy::get_privacy_policy))
            // SSO public endpoints (callbacks, provider list for login)
            .service(
                web::scope("/api/sso")
                    .wrap(rate_limit::RateLimitStatsMiddleware::auth())
                    .wrap(rate_limit::auth_rate_limiter())
                    .route("/providers", web::get().to(api::sso::get_sso_providers_for_login))
                    .route("/login/{provider_id}", web::get().to(api::sso::initiate_login))
                    .route("/callback/saml", web::post().to(api::sso::saml_callback))
                    .route("/callback/oidc", web::get().to(api::sso::oidc_callback))
            )
            // Phishing tracking routes (public, no auth required)
            .configure(api::phishing::configure_tracking)
            // Customer Portal routes (separate auth from main app) - at /api/portal/*
            .service(
                web::scope("/api/portal")
                    .wrap(rate_limit::RateLimitStatsMiddleware::api())
                    .wrap(rate_limit::api_rate_limiter())
                    // Public portal auth endpoints
                    .route("/auth/login", web::post().to(api::portal::auth::login))
                    .route("/auth/forgot-password", web::post().to(api::portal::auth::forgot_password))
                    .route("/auth/reset-password", web::post().to(api::portal::auth::reset_password))
                    // Protected portal endpoints (require portal JWT)
                    .service(
                        web::scope("")
                            .wrap(api::portal::auth::PortalAuthMiddleware)
                            .route("/auth/me", web::get().to(api::portal::auth::get_current_user))
                            .route("/auth/change-password", web::post().to(api::portal::auth::change_password))
                            .route("/profile", web::get().to(api::portal::auth::get_profile))
                            .route("/profile", web::put().to(api::portal::auth::update_profile))
                            .route("/dashboard", web::get().to(api::portal::dashboard::get_dashboard))
                            .route("/engagements", web::get().to(api::portal::engagements::list_engagements))
                            .route("/engagements/{id}", web::get().to(api::portal::engagements::get_engagement))
                            .route("/engagements/{id}/milestones", web::get().to(api::portal::engagements::get_milestones))
                            .route("/engagements/{engagement_id}/milestones/{milestone_id}", web::put().to(api::portal::engagements::update_milestone))
                            .route("/vulnerabilities", web::get().to(api::portal::vulnerabilities::list_vulnerabilities))
                            .route("/vulnerabilities/{id}", web::get().to(api::portal::vulnerabilities::get_vulnerability))
                            .route("/vulnerabilities/{id}/status", web::put().to(api::portal::vulnerabilities::update_status))
                            .route("/vulnerabilities/{id}/comments", web::get().to(api::portal::vulnerabilities::get_comments))
                            .route("/vulnerabilities/{id}/comments", web::post().to(api::portal::vulnerabilities::add_comment))
                            .route("/reports", web::get().to(api::portal::reports::list_reports))
                            .route("/reports/{id}", web::get().to(api::portal::reports::get_report))
                            .route("/reports/{id}/download", web::get().to(api::portal::reports::download_report))
                    )
            )
            // Protected routes with moderate rate limiting (100 req/min per IP)
            .service(
                web::scope("/api")
                    .wrap(rate_limit::RateLimitStatsMiddleware::api())
                    .wrap(rate_limit::api_rate_limiter())
                    .wrap(auth::JwtMiddleware)
                    // User account endpoints (protected, require authentication)
                    .route("/user/me", web::get().to(api::auth::me))
                    .route("/user/profile", web::put().to(api::auth::update_profile))
                    .route("/user/password", web::put().to(api::auth::change_password))
                    // MFA management endpoints (protected, require authentication)
                    .route("/user/mfa/setup", web::post().to(api::mfa::setup_mfa))
                    .route("/user/mfa/verify-setup", web::post().to(api::mfa::verify_setup))
                    .route("/user/mfa", web::delete().to(api::mfa::disable_mfa))
                    .route("/user/mfa/recovery-codes", web::post().to(api::mfa::regenerate_recovery_codes))
                    // GDPR compliance endpoints
                    .route("/user/terms-status", web::get().to(api::auth::get_terms_status))
                    .route("/user/accept-terms", web::post().to(api::auth::accept_terms))
                    .route("/user/export", web::get().to(api::auth::export_user_data))
                    .route("/user/account", web::delete().to(api::auth::delete_account))
                    // Users endpoint (for assignment picker - any authenticated user)
                    .route("/users", web::get().to(api::vulnerabilities::list_users_for_picker))
                    // Scan endpoints
                    .route("/scans", web::post().to(api::scans::create_scan))
                    .route("/scans", web::get().to(api::scans::get_scans))
                    .route("/scans/stats", web::get().to(api::scans::get_aggregated_stats))
                    .route("/scans/{id}", web::get().to(api::scans::get_scan))
                    .route("/scans/{id}", web::delete().to(api::scans::delete_scan))
                    // Scan presets endpoint
                    .route("/scan-presets", web::get().to(api::scan_presets::get_presets))
                    .route(
                        "/scans/{id}/results",
                        web::get().to(api::scans::get_scan_results),
                    )
                    .route("/scans/{id}/export", web::get().to(api::scans::export_scan_csv))
                    .route("/scans/{id}/export/markdown", web::get().to(api::scans::export_scan_markdown))
                    .route("/scans/{id}/ssl-report", web::get().to(api::scans::get_ssl_report))
                    .route("/scans/{id}/secrets", web::get().to(api::secret_findings::get_scan_secrets))
                    .route("/scans/{id}/topology", web::get().to(api::topology::get_scan_topology))
                    .route("/scans/bulk-export", web::post().to(api::scans::bulk_export_scans))
                    .route("/scans/bulk-delete", web::post().to(api::scans::bulk_delete_scans))
                    .route("/scans/compare", web::post().to(api::compare::compare_scans))
                    // Scan tags endpoints
                    .route("/scans/tags", web::get().to(api::scans::get_scan_tags))
                    .route("/scans/tags", web::post().to(api::scans::create_scan_tag))
                    .route("/scans/tags/suggestions", web::get().to(api::scans::get_tag_suggestions))
                    .route("/scans/tags/{id}", web::delete().to(api::scans::delete_scan_tag))
                    .route("/scans/with-tags", web::get().to(api::scans::get_scans_with_tags))
                    .route("/scans/{id}/tags", web::get().to(api::scans::get_tags_for_scan))
                    .route("/scans/{id}/tags", web::post().to(api::scans::add_tags_to_scan))
                    .route("/scans/{id}/tags/{tag_id}", web::delete().to(api::scans::remove_tag_from_scan))
                    // Duplicate scan endpoint
                    .route("/scans/{id}/duplicate", web::post().to(api::scans::duplicate_scan))
                    .route("/ws/scans/{id}", web::get().to(websocket::ws_handler))
                    .route("/ws/exploitation/{id}", web::get().to(websocket::exploitation::ws_handler))
                    // Report endpoints
                    .route("/reports", web::post().to(api::reports::create_report))
                    .route("/reports", web::get().to(api::reports::get_reports))
                    .route("/reports/templates", web::get().to(api::reports::get_templates))
                    .route("/reports/{id}", web::get().to(api::reports::get_report))
                    .route("/reports/{id}/download", web::get().to(api::reports::download_report))
                    .route("/reports/{id}", web::delete().to(api::reports::delete_report))
                    // Template endpoints
                    .route("/templates", web::post().to(api::templates::create_template))
                    .route("/templates", web::get().to(api::templates::get_templates))
                    .route("/templates/system", web::get().to(api::templates::get_system_templates))
                    .route("/templates/categories", web::get().to(api::templates::get_template_categories))
                    .route("/templates/default", web::get().to(api::templates::get_default_template))
                    .route("/templates/default", web::delete().to(api::templates::clear_default_template))
                    .route("/templates/import", web::post().to(api::templates::import_template))
                    .route("/templates/{id}", web::get().to(api::templates::get_template))
                    .route("/templates/{id}", web::put().to(api::templates::update_template))
                    .route("/templates/{id}", web::delete().to(api::templates::delete_template))
                    .route("/templates/{id}/export", web::get().to(api::templates::export_template))
                    .route("/templates/{id}/scan", web::post().to(api::templates::create_scan_from_template))
                    .route("/templates/{id}/clone", web::post().to(api::templates::clone_template))
                    .route("/templates/{id}/set-default", web::post().to(api::templates::set_default_template))
                    // Target group endpoints
                    .route("/target-groups", web::post().to(api::target_groups::create_target_group))
                    .route("/target-groups", web::get().to(api::target_groups::get_target_groups))
                    .route("/target-groups/{id}", web::get().to(api::target_groups::get_target_group))
                    .route("/target-groups/{id}", web::put().to(api::target_groups::update_target_group))
                    .route("/target-groups/{id}", web::delete().to(api::target_groups::delete_target_group))
                    // Scheduled scan endpoints
                    .route("/scheduled-scans", web::post().to(api::scheduled_scans::create_scheduled_scan))
                    .route("/scheduled-scans", web::get().to(api::scheduled_scans::get_scheduled_scans))
                    .route("/scheduled-scans/{id}", web::get().to(api::scheduled_scans::get_scheduled_scan))
                    .route("/scheduled-scans/{id}", web::put().to(api::scheduled_scans::update_scheduled_scan))
                    .route("/scheduled-scans/{id}", web::delete().to(api::scheduled_scans::delete_scheduled_scan))
                    .route("/scheduled-scans/{id}/history", web::get().to(api::scheduled_scans::get_scheduled_scan_history))
                    // Scheduled report endpoints
                    .route("/scheduled-reports", web::post().to(api::scheduled_reports::create_scheduled_report))
                    .route("/scheduled-reports", web::get().to(api::scheduled_reports::get_scheduled_reports))
                    .route("/scheduled-reports/presets", web::get().to(api::scheduled_reports::get_schedule_presets))
                    .route("/scheduled-reports/{id}", web::get().to(api::scheduled_reports::get_scheduled_report))
                    .route("/scheduled-reports/{id}", web::put().to(api::scheduled_reports::update_scheduled_report))
                    .route("/scheduled-reports/{id}", web::delete().to(api::scheduled_reports::delete_scheduled_report))
                    .route("/scheduled-reports/{id}/run-now", web::post().to(api::scheduled_reports::run_scheduled_report_now))
                    // Notification settings endpoints
                    .route("/notifications/settings", web::get().to(api::notifications::get_notification_settings))
                    .route("/notifications/settings", web::put().to(api::notifications::update_notification_settings))
                    .route("/notifications/test-slack", web::post().to(api::notifications::test_slack_webhook))
                    .route("/notifications/test-teams", web::post().to(api::notifications::test_teams_webhook))
                    .route("/notifications/test-email", web::post().to(api::notifications::test_email))
                    .route("/notifications/smtp-status", web::get().to(api::notifications::check_smtp_status))
                    // API Keys endpoints
                    .route("/api-keys", web::get().to(api::api_keys::get_api_keys))
                    .route("/api-keys", web::post().to(api::api_keys::create_api_key))
                    .route("/api-keys/{id}", web::patch().to(api::api_keys::update_api_key))
                    .route("/api-keys/{id}", web::delete().to(api::api_keys::delete_api_key))
                    // Analytics endpoints
                    .route("/analytics/summary", web::get().to(api::analytics::get_summary))
                    .route("/analytics/hosts", web::get().to(api::analytics::get_hosts_over_time))
                    .route("/analytics/vulnerabilities", web::get().to(api::analytics::get_vulnerabilities_over_time))
                    .route("/analytics/services", web::get().to(api::analytics::get_top_services))
                    .route("/analytics/frequency", web::get().to(api::analytics::get_scan_frequency))
                    // Executive Analytics endpoints
                    .route("/analytics/customer/{id}/trends", web::get().to(api::analytics::get_customer_trends))
                    .route("/analytics/customer/{id}/summary", web::get().to(api::analytics::get_customer_summary))
                    .route("/analytics/remediation-velocity", web::get().to(api::analytics::get_remediation_velocity))
                    .route("/analytics/risk-trends", web::get().to(api::analytics::get_risk_trends))
                    .route("/analytics/methodology-coverage", web::get().to(api::analytics::get_methodology_coverage))
                    .route("/analytics/executive-dashboard", web::get().to(api::analytics::get_executive_dashboard))
                    // Vulnerability Trends Analytics endpoints
                    .route("/analytics/vulnerability-trends", web::get().to(api::analytics::get_vulnerability_trends_endpoint))
                    .route("/analytics/severity-trends", web::get().to(api::analytics::get_severity_trends_endpoint))
                    .route("/analytics/remediation-rate", web::get().to(api::analytics::get_remediation_rate_endpoint))
                    .route("/analytics/top-vulnerabilities", web::get().to(api::analytics::get_top_vulnerabilities_endpoint))
                    .route("/analytics/vulnerability-trends-dashboard", web::get().to(api::analytics::get_vulnerability_trends_dashboard))
                    // Asset Inventory endpoints
                    .route("/assets", web::get().to(api::assets::get_assets))
                    .route("/assets/by-tags", web::get().to(api::assets::get_assets_by_tags))
                    .route("/assets/with-tags", web::get().to(api::assets::get_assets_with_tags))
                    .route("/assets/tags", web::get().to(api::assets::get_asset_tags))
                    .route("/assets/tags", web::post().to(api::assets::create_asset_tag))
                    .route("/assets/tags/{id}", web::get().to(api::assets::get_asset_tag))
                    .route("/assets/tags/{id}", web::put().to(api::assets::update_asset_tag))
                    .route("/assets/tags/{id}", web::delete().to(api::assets::delete_asset_tag))
                    .route("/assets/{id}", web::get().to(api::assets::get_asset_with_tags))
                    .route("/assets/{id}", web::patch().to(api::assets::update_asset))
                    .route("/assets/{id}", web::delete().to(api::assets::delete_asset))
                    .route("/assets/{id}/history", web::get().to(api::assets::get_asset_history))
                    .route("/assets/{id}/tags", web::post().to(api::assets::add_tags_to_asset))
                    .route("/assets/{id}/tags/{tag_id}", web::delete().to(api::assets::remove_tag_from_asset))
                    .route("/assets/{id}/full", web::get().to(api::assets::get_asset_full))
                    // Asset Groups endpoints
                    .route("/asset-groups", web::get().to(api::assets::get_asset_groups))
                    .route("/asset-groups", web::post().to(api::assets::create_asset_group))
                    .route("/asset-groups/assets", web::get().to(api::assets::get_assets_by_group))
                    .route("/asset-groups/{id}", web::get().to(api::assets::get_asset_group))
                    .route("/asset-groups/{id}", web::put().to(api::assets::update_asset_group))
                    .route("/asset-groups/{id}", web::delete().to(api::assets::delete_asset_group))
                    .route("/asset-groups/{id}/members", web::post().to(api::assets::add_assets_to_group))
                    .route("/asset-groups/{id}/members/{asset_id}", web::delete().to(api::assets::remove_asset_from_group))
                    .route("/asset-groups/{id}/bulk-add", web::post().to(api::assets::bulk_add_assets_to_group))
                    // Vulnerability management endpoints
                    .route("/vulnerabilities", web::get().to(api::vulnerabilities::list_vulnerabilities))
                    .route("/vulnerabilities/stats", web::get().to(api::vulnerabilities::get_vulnerability_stats))
                    .route("/vulnerabilities/assigned", web::get().to(api::vulnerabilities::get_my_assignments))
                    .route("/vulnerabilities/assignment-stats", web::get().to(api::vulnerabilities::get_assignment_stats))
                    .route("/vulnerabilities/with-assignments", web::get().to(api::vulnerabilities::list_vulnerabilities_with_assignments))
                    .route("/vulnerabilities/bulk-update", web::post().to(api::vulnerabilities::bulk_update_vulnerabilities))
                    .route("/vulnerabilities/bulk-export", web::post().to(api::vulnerabilities::bulk_export_vulnerabilities))
                    .route("/vulnerabilities/bulk-assign", web::post().to(api::vulnerabilities::bulk_assign))
                    // New bulk operation endpoints
                    .route("/vulnerabilities/bulk/status", web::post().to(api::vulnerabilities::bulk_update_status))
                    .route("/vulnerabilities/bulk/severity", web::post().to(api::vulnerabilities::bulk_update_severity))
                    .route("/vulnerabilities/bulk/delete", web::post().to(api::vulnerabilities::bulk_delete))
                    .route("/vulnerabilities/bulk/tags", web::post().to(api::vulnerabilities::bulk_add_tags))
                    .route("/vulnerabilities/{id}", web::get().to(api::vulnerabilities::get_vulnerability))
                    .route("/vulnerabilities/{id}", web::put().to(api::vulnerabilities::update_vulnerability))
                    .route("/vulnerabilities/{id}/assign", web::post().to(api::vulnerabilities::assign_vulnerability))
                    .route("/vulnerabilities/{id}/assign", web::delete().to(api::vulnerabilities::unassign_vulnerability))
                    .route("/vulnerabilities/{id}/assignment", web::put().to(api::vulnerabilities::update_assignment))
                    .route("/vulnerabilities/{id}/comments", web::get().to(api::vulnerabilities::get_comments))
                    .route("/vulnerabilities/{id}/comments", web::post().to(api::vulnerabilities::add_comment))
                    .route("/vulnerabilities/{id}/comments/{comment_id}", web::put().to(api::vulnerabilities::update_comment))
                    .route("/vulnerabilities/{id}/comments/{comment_id}", web::delete().to(api::vulnerabilities::delete_comment))
                    .route("/vulnerabilities/{id}/timeline", web::get().to(api::vulnerabilities::get_vulnerability_timeline))
                    .route("/vulnerabilities/{id}/verify", web::post().to(api::vulnerabilities::mark_for_verification))
                    // Retest workflow endpoints
                    .route("/vulnerabilities/pending-retest", web::get().to(api::vulnerabilities::get_pending_retests))
                    .route("/vulnerabilities/bulk-retest", web::post().to(api::vulnerabilities::bulk_request_retest))
                    .route("/vulnerabilities/{id}/request-retest", web::post().to(api::vulnerabilities::request_retest))
                    .route("/vulnerabilities/{id}/complete-retest", web::post().to(api::vulnerabilities::complete_retest))
                    .route("/vulnerabilities/{id}/retest-history", web::get().to(api::vulnerabilities::get_retest_history))
                    // Compliance endpoints
                    .route("/compliance/frameworks", web::get().to(api::compliance::list_frameworks))
                    .route("/compliance/frameworks/{id}", web::get().to(api::compliance::get_framework))
                    .route("/compliance/frameworks/{id}/controls", web::get().to(api::compliance::get_framework_controls))
                    .route("/scans/{id}/compliance", web::post().to(api::compliance::analyze_scan_compliance))
                    .route("/scans/{id}/compliance", web::get().to(api::compliance::get_scan_compliance))
                    .route("/scans/{id}/compliance/report", web::post().to(api::compliance::generate_compliance_report))
                    .route("/compliance/reports/{id}/download", web::get().to(api::compliance::download_compliance_report))
                    // Manual compliance assessment endpoints
                    .configure(api::manual_compliance::configure)
                    // CRM endpoints
                    .configure(api::crm::configure)
                    // DNS reconnaissance endpoints
                    .route("/dns/recon", web::post().to(api::dns::perform_dns_recon))
                    .route("/dns/recon", web::get().to(api::dns::list_dns_recon_results))
                    .route("/dns/recon/{id}", web::get().to(api::dns::get_dns_recon_result))
                    .route("/dns/recon/{id}", web::delete().to(api::dns::delete_dns_recon_result))
                    .route("/dns/wordlist", web::get().to(api::dns::get_wordlist))
                    // Web Application scanning endpoints
                    .configure(api::webapp::configure)
                    // JIRA integration endpoints
                    .route("/integrations/jira/settings", web::get().to(api::jira::get_jira_settings))
                    .route("/integrations/jira/settings", web::post().to(api::jira::upsert_jira_settings))
                    .route("/integrations/jira/test", web::post().to(api::jira::test_jira_connection))
                    .route("/integrations/jira/projects", web::get().to(api::jira::list_jira_projects))
                    .route("/integrations/jira/issue-types", web::get().to(api::jira::list_jira_issue_types))
                    .route("/vulnerabilities/{id}/create-ticket", web::post().to(api::jira::create_jira_ticket))
                    // SIEM integration endpoints (Full SIEM)
                    .route("/siem/sources", web::get().to(api::siem::list_log_sources))
                    .route("/siem/sources", web::post().to(api::siem::create_log_source))
                    .route("/siem/sources/{id}", web::get().to(api::siem::get_log_source))
                    .route("/siem/sources/{id}", web::put().to(api::siem::update_log_source))
                    .route("/siem/sources/{id}", web::delete().to(api::siem::delete_log_source))
                    .route("/siem/logs", web::get().to(api::siem::query_logs))
                    .route("/siem/logs/{id}", web::get().to(api::siem::get_log_entry))
                    .route("/siem/rules", web::get().to(api::siem::list_rules))
                    .route("/siem/rules", web::post().to(api::siem::create_rule))
                    .route("/siem/stats", web::get().to(api::siem::get_siem_stats))
                    // ServiceNow integration endpoints
                    .route("/integrations/servicenow/settings", web::get().to(api::servicenow::get_servicenow_settings))
                    .route("/integrations/servicenow/settings", web::post().to(api::servicenow::upsert_servicenow_settings))
                    .route("/integrations/servicenow/test", web::post().to(api::servicenow::test_servicenow_connection))
                    .route("/integrations/servicenow/assignment-groups", web::get().to(api::servicenow::get_assignment_groups))
                    .route("/integrations/servicenow/categories", web::get().to(api::servicenow::get_categories))
                    .route("/integrations/servicenow/tickets/{ticket_number}/status", web::get().to(api::servicenow::get_ticket_status))
                    .route("/vulnerabilities/{id}/servicenow/tickets", web::get().to(api::servicenow::get_tickets_for_vulnerability))
                    .route("/vulnerabilities/{id}/servicenow/incident", web::post().to(api::servicenow::create_incident))
                    .route("/vulnerabilities/{id}/servicenow/change", web::post().to(api::servicenow::create_change))
                    // Webhooks (outbound) endpoints
                    .route("/webhooks", web::get().to(api::webhooks::list_webhooks))
                    .route("/webhooks", web::post().to(api::webhooks::create_webhook))
                    .route("/webhooks/event-types", web::get().to(api::webhooks::get_event_types))
                    .route("/webhooks/generate-secret", web::post().to(api::webhooks::generate_secret))
                    .route("/webhooks/{id}", web::get().to(api::webhooks::get_webhook))
                    .route("/webhooks/{id}", web::put().to(api::webhooks::update_webhook))
                    .route("/webhooks/{id}", web::delete().to(api::webhooks::delete_webhook))
                    .route("/webhooks/{id}/test", web::post().to(api::webhooks::test_webhook))
                    .route("/webhooks/{id}/deliveries", web::get().to(api::webhooks::get_deliveries))
                    .route("/webhooks/{id}/stats", web::get().to(api::webhooks::get_stats))
                    // Finding templates endpoints
                    .route("/finding-templates", web::get().to(api::finding_templates::list_templates))
                    .route("/finding-templates", web::post().to(api::finding_templates::create_template))
                    .route("/finding-templates/categories", web::get().to(api::finding_templates::get_categories))
                    .route("/finding-templates/categories/all", web::get().to(api::finding_templates::list_all_categories))
                    .route("/finding-templates/popular", web::get().to(api::finding_templates::get_popular_templates))
                    .route("/finding-templates/search", web::get().to(api::finding_templates::search_templates))
                    .route("/finding-templates/import", web::post().to(api::finding_templates::import_templates))
                    .route("/finding-templates/export", web::get().to(api::finding_templates::export_templates))
                    .route("/finding-templates/owasp/{category}", web::get().to(api::finding_templates::get_templates_by_owasp))
                    .route("/finding-templates/mitre/{technique_id}", web::get().to(api::finding_templates::get_templates_by_mitre))
                    .route("/finding-templates/{id}", web::get().to(api::finding_templates::get_template))
                    .route("/finding-templates/{id}", web::put().to(api::finding_templates::update_template))
                    .route("/finding-templates/{id}", web::delete().to(api::finding_templates::delete_template))
                    .route("/finding-templates/{id}/clone", web::post().to(api::finding_templates::clone_template))
                    .route("/finding-templates/{id}/apply", web::post().to(api::finding_templates::apply_template))
                    // Methodology checklists endpoints
                    .route("/methodology/templates", web::get().to(api::methodology::list_templates))
                    .route("/methodology/templates/{id}", web::get().to(api::methodology::get_template))
                    .route("/methodology/checklists", web::get().to(api::methodology::list_checklists))
                    .route("/methodology/checklists", web::post().to(api::methodology::create_checklist))
                    .route("/methodology/checklists/{id}", web::get().to(api::methodology::get_checklist))
                    .route("/methodology/checklists/{id}", web::put().to(api::methodology::update_checklist))
                    .route("/methodology/checklists/{id}", web::delete().to(api::methodology::delete_checklist))
                    .route("/methodology/checklists/{id}/progress", web::get().to(api::methodology::get_progress))
                    .route("/methodology/checklists/{checklist_id}/items/{item_id}", web::get().to(api::methodology::get_item))
                    .route("/methodology/checklists/{checklist_id}/items/{item_id}", web::put().to(api::methodology::update_item))
                    // VPN integration endpoints
                    .route("/vpn/configs", web::post().to(api::vpn::upload_vpn_config))
                    .route("/vpn/configs", web::get().to(api::vpn::list_vpn_configs))
                    .route("/vpn/configs/{id}", web::get().to(api::vpn::get_vpn_config))
                    .route("/vpn/configs/{id}", web::put().to(api::vpn::update_vpn_config))
                    .route("/vpn/configs/{id}", web::delete().to(api::vpn::delete_vpn_config))
                    .route("/vpn/configs/{id}/test", web::post().to(api::vpn::test_vpn_connection))
                    .route("/vpn/connect", web::post().to(api::vpn::connect_vpn))
                    .route("/vpn/disconnect", web::post().to(api::vpn::disconnect_vpn))
                    .route("/vpn/status", web::get().to(api::vpn::get_vpn_status))
                    .route("/vpn/connections", web::get().to(api::vpn::get_vpn_connections))
                    // Agent-based scanning endpoints
                    .configure(api::agents::configure)
                    .configure(api::admin::configure)
                    .configure(api::dashboard::configure)
                    .configure(api::threat_intel::configure)
                    // Cloud infrastructure scanning endpoints
                    .configure(api::cloud::configure)
                    // Container/K8s scanning endpoints
                    .configure(api::container::configure)
                    // Attack path analysis endpoints
                    .configure(api::attack_paths::configure)
                    // API Security scanning endpoints
                    .configure(api::api_security::configure)
                    // AD Assessment endpoints
                    .configure(api::ad_assessment::configure)
                    // Credential Audit endpoints
                    .configure(api::credential_audit::configure)
                    // Password Cracking endpoints
                    .configure(api::cracking::configure)
                    // Scan Exclusions endpoints
                    .configure(api::exclusions::configure)
                    // Secret Findings endpoints
                    .configure(api::secret_findings::configure)
                    // AI Prioritization endpoints
                    .configure(api::ai::configure)
                    // AI Chat endpoints
                    .configure(api::chat::configure)
                    // CI/CD integration endpoints
                    .configure(api::cicd::configure)
                    // CI/CD Pipeline Security scanning endpoints
                    .configure(api::cicd_pipeline::configure)
                    // Kubernetes Security scanning endpoints
                    .configure(api::k8s_security::configure)
                    // IaC Security scanning endpoints
                    .configure(api::iac::configure)
                    // Breach & Attack Simulation endpoints
                    .configure(api::bas::configure)
                    // Remediation Workflows endpoints
                    .configure(api::workflows::configure)
                    // Mobile app endpoints
                    .configure(api::mobile::configure)
                    // Push notification endpoints
                    .configure(api::push::configure)
                    // Plugin marketplace endpoints
                    .configure(api::plugins::configure)
                    // Compliance Evidence Collection endpoints
                    .configure(api::evidence::configure)
                    // SIEM (Full capabilities) endpoints
                    .configure(api::siem::configure)
                    // Exploitation Framework endpoints
                    .configure(api::exploitation::configure)
                    // Nuclei scanner endpoints
                    .configure(api::nuclei::configure)
                    // Asset discovery endpoints
                    .configure(api::asset_discovery::configure)
                    // Privilege escalation scanner endpoints
                    .configure(api::privesc::configure)
                    // BloodHound integration endpoints
                    .configure(api::bloodhound::configure)
                    // Phishing campaign endpoints
                    .configure(api::phishing::configure)
                    // C2 framework integration endpoints
                    .configure(api::c2::configure)
                    // Wireless security endpoints
                    .configure(api::wireless::configure)
                    // Attack Surface Management endpoints
                    .configure(api::asm::configure)
                    // Purple Team Mode endpoints
                    .configure(api::purple_team::configure)
                    // Organization and team management endpoints
                    .configure(api::organizations::configure)
                    // Role and permission management endpoints
                    .configure(api::permissions::configure)
                    // Enhanced remediation workflow endpoints
                    .configure(api::remediation::configure)
                    // Executive dashboard endpoints
                    .configure(api::executive_dashboard::configure)
                    // Custom report templates endpoints
                    .configure(api::report_templates::configure)
                    // Start workflow from vulnerability
                    .route("/vulnerabilities/{id}/workflow", web::post().to(api::workflows::start_workflow))
                    // SSO Admin endpoints
                    .route("/sso/admin/providers", web::get().to(api::sso::list_sso_providers))
                    .route("/sso/admin/providers", web::post().to(api::sso::create_provider))
                    .route("/sso/admin/presets", web::get().to(api::sso::get_presets))
                    .route("/sso/admin/parse-metadata", web::post().to(api::sso::parse_idp_metadata))
                    .route("/sso/admin/providers/{id}", web::get().to(api::sso::get_provider))
                    .route("/sso/admin/providers/{id}", web::put().to(api::sso::update_provider))
                    .route("/sso/admin/providers/{id}", web::delete().to(api::sso::delete_provider))
                    .route("/sso/admin/providers/{id}/metadata", web::get().to(api::sso::get_provider_metadata))
                    .route("/sso/admin/providers/{id}/metadata.xml", web::get().to(api::sso::download_metadata_xml))
                    .route("/sso/admin/providers/{id}/mappings", web::put().to(api::sso::update_mappings))
                    .route("/sso/admin/providers/{id}/test", web::post().to(api::sso::test_provider))
                    .route("/sso/logout", web::post().to(api::sso::sso_logout)),
            )
            // Swagger UI for API documentation
            .service(
                SwaggerUi::new("/api/docs/{_:.*}")
                    .url("/api/openapi.json", openapi::ApiDoc::openapi())
            )
            // SPA routes that might conflict with static assets - serve index.html
            .route("/assets", web::get().to(spa_fallback))
            // Serve frontend static assets (Vite build output - files like /assets/index-xyz.js)
            .service(fs::Files::new("/assets", "./frontend/dist/assets"))
            // Serve vite.svg
            .route("/vite.svg", web::get().to(|| async {
                match std::fs::read("./frontend/dist/vite.svg") {
                    Ok(content) => HttpResponse::Ok()
                        .content_type("image/svg+xml")
                        .body(content),
                    Err(_) => HttpResponse::NotFound().finish(),
                }
            }))
            // Root path serves index.html
            .route("/", web::get().to(spa_fallback))
            // SPA fallback - serve index.html for all unmatched non-API routes
            .default_service(web::route().to(spa_fallback))
    })
    .bind(bind_address)?
    .run()
    .await
}