pub mod api;
pub mod auth;
pub mod broadcast;
pub mod websocket;

use actix_cors::Cors;
use actix_files as fs;
use actix_web::{middleware::Logger, web, App, HttpServer};
use sqlx::SqlitePool;

pub async fn run_web_server(database_url: &str, bind_address: &str) -> std::io::Result<()> {
    log::info!("Initializing database...");
    let pool = crate::db::init_database(database_url)
        .await
        .expect("Failed to initialize database");

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
                    .route("/scans", web::post().to(api::scans::create_scan))
                    .route("/scans", web::get().to(api::scans::get_scans))
                    .route("/scans/{id}", web::get().to(api::scans::get_scan))
                    .route(
                        "/scans/{id}/results",
                        web::get().to(api::scans::get_scan_results),
                    )
                    .route("/ws/scans/{id}", web::get().to(websocket::ws_handler))
                    .configure(api::admin::configure),
            )
            // Serve frontend static files
            .service(fs::Files::new("/", "./frontend/dist").index_file("index.html"))
    })
    .bind(bind_address)?
    .run()
    .await
}
