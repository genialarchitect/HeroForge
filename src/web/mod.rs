pub mod api;
pub mod auth;
pub mod broadcast;
pub mod rate_limit;
pub mod scheduler;
pub mod websocket;

use actix_cors::Cors;
use actix_files as fs;
use actix_web::{middleware::{DefaultHeaders, Logger}, web, App, HttpServer};
use std::sync::Arc;

pub async fn run_web_server(database_url: &str, bind_address: &str) -> std::io::Result<()> {
    log::info!("Initializing database...");
    let pool = crate::db::init_database(database_url)
        .await
        .expect("Failed to initialize database");

    // Start the background scheduler daemon
    scheduler::start_scheduler(Arc::new(pool.clone()));

    log::info!("Starting web server at http://{}", bind_address);

    // Log rate limiting configuration
    log::info!("Rate limiting enabled:");
    log::info!("  - Auth endpoints: 5 requests/minute per IP");
    log::info!("  - API endpoints: 100 requests/minute per IP");
    log::info!("  - Scan creation: 10 requests/hour per IP");

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
            // Protected routes with moderate rate limiting (100 req/min per IP)
            .service(
                web::scope("/api")
                    .wrap(rate_limit::api_rate_limiter())
                    .wrap(auth::JwtMiddleware)
                    .route("/auth/me", web::get().to(api::auth::me))
                    .route("/auth/profile", web::put().to(api::auth::update_profile))
                    .route("/auth/password", web::put().to(api::auth::change_password))
                    // MFA management endpoints (protected, require authentication)
                    .route("/auth/mfa/setup", web::post().to(api::mfa::setup_mfa))
                    .route("/auth/mfa/verify-setup", web::post().to(api::mfa::verify_setup))
                    .route("/auth/mfa", web::delete().to(api::mfa::disable_mfa))
                    .route("/auth/mfa/recovery-codes", web::post().to(api::mfa::regenerate_recovery_codes))
                    // GDPR compliance endpoints
                    .route("/auth/terms-status", web::get().to(api::auth::get_terms_status))
                    .route("/auth/accept-terms", web::post().to(api::auth::accept_terms))
                    .route("/auth/export", web::get().to(api::auth::export_user_data))
                    .route("/auth/account", web::delete().to(api::auth::delete_account))
                    // Scan endpoints - scan creation has additional rate limiting at handler level
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
                    .route("/scans/{id}/topology", web::get().to(api::topology::get_scan_topology))
                    .route("/scans/bulk-export", web::post().to(api::scans::bulk_export_scans))
                    .route("/scans/bulk-delete", web::post().to(api::scans::bulk_delete_scans))
                    .route("/scans/compare", web::post().to(api::compare::compare_scans))
                    .route("/ws/scans/{id}", web::get().to(websocket::ws_handler))
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
                    .route("/templates/{id}", web::get().to(api::templates::get_template))
                    .route("/templates/{id}", web::put().to(api::templates::update_template))
                    .route("/templates/{id}", web::delete().to(api::templates::delete_template))
                    .route("/templates/{id}/export", web::get().to(api::templates::export_template))
                    .route("/templates/import", web::post().to(api::templates::import_template))
                    .route("/templates/{id}/scan", web::post().to(api::templates::create_scan_from_template))
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
                    // Notification settings endpoints
                    .route("/notifications/settings", web::get().to(api::notifications::get_notification_settings))
                    .route("/notifications/settings", web::put().to(api::notifications::update_notification_settings))
                    .route("/notifications/test-slack", web::post().to(api::notifications::test_slack_webhook))
                    .route("/notifications/test-teams", web::post().to(api::notifications::test_teams_webhook))
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
                    // Asset Inventory endpoints
                    .route("/assets", web::get().to(api::assets::get_assets))
                    .route("/assets/{id}", web::get().to(api::assets::get_asset))
                    .route("/assets/{id}", web::patch().to(api::assets::update_asset))
                    .route("/assets/{id}", web::delete().to(api::assets::delete_asset))
                    .route("/assets/{id}/history", web::get().to(api::assets::get_asset_history))
                    // Vulnerability management endpoints
                    .route("/vulnerabilities", web::get().to(api::vulnerabilities::list_vulnerabilities))
                    .route("/vulnerabilities/stats", web::get().to(api::vulnerabilities::get_vulnerability_stats))
                    .route("/vulnerabilities/bulk-update", web::post().to(api::vulnerabilities::bulk_update_vulnerabilities))
                    .route("/vulnerabilities/bulk-export", web::post().to(api::vulnerabilities::bulk_export_vulnerabilities))
                    .route("/vulnerabilities/{id}", web::get().to(api::vulnerabilities::get_vulnerability))
                    .route("/vulnerabilities/{id}", web::put().to(api::vulnerabilities::update_vulnerability))
                    .route("/vulnerabilities/{id}/comments", web::post().to(api::vulnerabilities::add_comment))
                    // Compliance endpoints
                    .route("/compliance/frameworks", web::get().to(api::compliance::list_frameworks))
                    .route("/compliance/frameworks/{id}", web::get().to(api::compliance::get_framework))
                    .route("/compliance/frameworks/{id}/controls", web::get().to(api::compliance::get_framework_controls))
                    .route("/scans/{id}/compliance", web::post().to(api::compliance::analyze_scan_compliance))
                    .route("/scans/{id}/compliance", web::get().to(api::compliance::get_scan_compliance))
                    .route("/scans/{id}/compliance/report", web::post().to(api::compliance::generate_compliance_report))
                    .route("/compliance/reports/{id}/download", web::get().to(api::compliance::download_compliance_report))
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
                    // SIEM integration endpoints
                    .route("/integrations/siem/settings", web::get().to(api::siem::get_siem_settings))
                    .route("/integrations/siem/settings", web::post().to(api::siem::create_siem_settings))
                    .route("/integrations/siem/settings/{id}", web::put().to(api::siem::update_siem_settings))
                    .route("/integrations/siem/settings/{id}", web::delete().to(api::siem::delete_siem_settings))
                    .route("/integrations/siem/settings/{id}/test", web::post().to(api::siem::test_siem_connection))
                    .route("/integrations/siem/export/{scan_id}", web::post().to(api::siem::export_scan_to_siem))
                    .configure(api::admin::configure)
                    .configure(api::dashboard::configure),
            )
            // Serve frontend static files
            .service(fs::Files::new("/", "./frontend/dist").index_file("index.html"))
    })
    .bind(bind_address)?
    .run()
    .await
}
