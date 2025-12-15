pub mod api;
pub mod auth;
pub mod broadcast;
pub mod scheduler;
pub mod websocket;

use actix_cors::Cors;
use actix_files as fs;
use actix_web::{middleware::Logger, web, App, HttpServer};
use std::sync::Arc;

pub async fn run_web_server(database_url: &str, bind_address: &str) -> std::io::Result<()> {
    log::info!("Initializing database...");
    let pool = crate::db::init_database(database_url)
        .await
        .expect("Failed to initialize database");

    // Start the background scheduler daemon
    scheduler::start_scheduler(Arc::new(pool.clone()));

    log::info!("Starting web server at http://{}", bind_address);

    HttpServer::new(move || {
        let cors = Cors::default()
            .allowed_origin("http://localhost:3000")
            .allowed_origin("http://localhost:5173")
            .allowed_methods(vec!["GET", "POST", "PUT", "DELETE"])
            .allowed_headers(vec![
                actix_web::http::header::AUTHORIZATION,
                actix_web::http::header::ACCEPT,
                actix_web::http::header::CONTENT_TYPE,
            ])
            .max_age(3600);

        App::new()
            .app_data(web::Data::new(pool.clone()))
            .wrap(cors)
            .wrap(Logger::default())
            // Public routes
            .route("/api/auth/register", web::post().to(api::auth::register))
            .route("/api/auth/login", web::post().to(api::auth::login))
            // Protected routes
            .service(
                web::scope("/api")
                    .wrap(auth::JwtMiddleware)
                    .route("/auth/me", web::get().to(api::auth::me))
                    .route("/auth/profile", web::put().to(api::auth::update_profile))
                    .route("/auth/password", web::put().to(api::auth::change_password))
                    .route("/scans", web::post().to(api::scans::create_scan))
                    .route("/scans", web::get().to(api::scans::get_scans))
                    .route("/scans/{id}", web::get().to(api::scans::get_scan))
                    .route(
                        "/scans/{id}/results",
                        web::get().to(api::scans::get_scan_results),
                    )
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
                    // Notification settings endpoints
                    .route("/notifications/settings", web::get().to(api::notifications::get_notification_settings))
                    .route("/notifications/settings", web::put().to(api::notifications::update_notification_settings))
                    .configure(api::admin::configure),
            )
            // Serve frontend static files
            .service(fs::Files::new("/", "./frontend/dist").index_file("index.html"))
    })
    .bind(bind_address)?
    .run()
    .await
}
