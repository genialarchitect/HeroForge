//! Integration tests for HeroForge Web API
//!
//! This module contains integration tests for the authentication, scan, and
//! vulnerability management endpoints.

#[cfg(test)]
mod tests {
    use actix_web::{test, web, App, http::StatusCode};
    use sqlx::sqlite::{SqlitePool, SqlitePoolOptions, SqliteConnectOptions};
    use std::str::FromStr;
    use serde_json::json;

    use crate::db::models::{
        CreateUser, LoginRequest, LoginResponse,
    };
    use crate::web::api;
    use crate::web::auth::{self, JwtMiddleware, Claims};

    /// Helper to create an in-memory SQLite database for testing
    async fn setup_test_db() -> SqlitePool {
        let connect_options = SqliteConnectOptions::from_str("sqlite::memory:")
            .expect("Failed to parse SQLite connection string")
            .create_if_missing(true);

        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(connect_options)
            .await
            .expect("Failed to create test database pool");

        // Run migrations manually for test database
        setup_test_tables(&pool).await;

        pool
    }

    /// Set up required tables for testing
    async fn setup_test_tables(pool: &SqlitePool) {
        // Create users table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL,
                is_active BOOLEAN NOT NULL DEFAULT 1,
                accepted_terms_at TEXT,
                terms_version TEXT
            )
            "#,
        )
        .execute(pool)
        .await
        .expect("Failed to create users table");

        // Create scan_results table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS scan_results (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                name TEXT NOT NULL,
                targets TEXT NOT NULL,
                status TEXT NOT NULL,
                results TEXT,
                created_at TEXT NOT NULL,
                started_at TEXT,
                completed_at TEXT,
                error_message TEXT,
                customer_id TEXT,
                engagement_id TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
            "#,
        )
        .execute(pool)
        .await
        .expect("Failed to create scan_results table");

        // Create roles table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS roles (
                id TEXT PRIMARY KEY,
                name TEXT UNIQUE NOT NULL,
                description TEXT,
                can_manage_users BOOLEAN NOT NULL DEFAULT 0,
                can_manage_scans BOOLEAN NOT NULL DEFAULT 0,
                can_view_all_scans BOOLEAN NOT NULL DEFAULT 0,
                can_delete_any_scan BOOLEAN NOT NULL DEFAULT 0,
                can_view_audit_logs BOOLEAN NOT NULL DEFAULT 0,
                can_manage_settings BOOLEAN NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            )
            "#,
        )
        .execute(pool)
        .await
        .expect("Failed to create roles table");

        // Create user_roles table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS user_roles (
                user_id TEXT NOT NULL,
                role_id TEXT NOT NULL,
                assigned_at TEXT NOT NULL,
                assigned_by TEXT,
                PRIMARY KEY (user_id, role_id),
                FOREIGN KEY (user_id) REFERENCES users(id),
                FOREIGN KEY (role_id) REFERENCES roles(id)
            )
            "#,
        )
        .execute(pool)
        .await
        .expect("Failed to create user_roles table");

        // Create refresh_tokens table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS refresh_tokens (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                token_hash TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL,
                revoked_at TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
            "#,
        )
        .execute(pool)
        .await
        .expect("Failed to create refresh_tokens table");

        // Create login_attempts table for account lockout
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS login_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                attempt_time TEXT NOT NULL,
                success BOOLEAN NOT NULL,
                ip_address TEXT,
                user_agent TEXT
            )
            "#,
        )
        .execute(pool)
        .await
        .expect("Failed to create login_attempts table");

        // Create account_lockouts table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS account_lockouts (
                username TEXT PRIMARY KEY,
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                locked_until TEXT,
                last_attempt TEXT
            )
            "#,
        )
        .execute(pool)
        .await
        .expect("Failed to create account_lockouts table");

        // Create MFA secrets table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS mfa_secrets (
                user_id TEXT PRIMARY KEY,
                encrypted_secret TEXT NOT NULL,
                is_verified BOOLEAN NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                verified_at TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
            "#,
        )
        .execute(pool)
        .await
        .expect("Failed to create mfa_secrets table");

        // Create password history table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS password_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
            "#,
        )
        .execute(pool)
        .await
        .expect("Failed to create password_history table");

        // Create vulnerability_tracking table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS vulnerability_tracking (
                id TEXT PRIMARY KEY,
                scan_id TEXT NOT NULL,
                host_ip TEXT NOT NULL,
                port INTEGER,
                vulnerability_id TEXT NOT NULL,
                severity TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'open',
                assignee_id TEXT,
                notes TEXT,
                due_date TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                resolved_at TEXT,
                resolved_by TEXT,
                FOREIGN KEY (scan_id) REFERENCES scan_results(id),
                FOREIGN KEY (assignee_id) REFERENCES users(id)
            )
            "#,
        )
        .execute(pool)
        .await
        .expect("Failed to create vulnerability_tracking table");

        // Create vulnerability_comments table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS vulnerability_comments (
                id TEXT PRIMARY KEY,
                vulnerability_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                comment TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (vulnerability_id) REFERENCES vulnerability_tracking(id),
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
            "#,
        )
        .execute(pool)
        .await
        .expect("Failed to create vulnerability_comments table");

        // Create vulnerability_history table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS vulnerability_history (
                id TEXT PRIMARY KEY,
                vulnerability_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                field_name TEXT NOT NULL,
                old_value TEXT,
                new_value TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (vulnerability_id) REFERENCES vulnerability_tracking(id),
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
            "#,
        )
        .execute(pool)
        .await
        .expect("Failed to create vulnerability_history table");

        // Insert default roles
        let now = chrono::Utc::now().to_rfc3339();
        sqlx::query(
            r#"
            INSERT OR IGNORE INTO roles (id, name, description, can_manage_users, can_manage_scans, can_view_all_scans, can_delete_any_scan, can_view_audit_logs, can_manage_settings, created_at)
            VALUES
                ('admin', 'Administrator', 'Full system access', 1, 1, 1, 1, 1, 1, ?1),
                ('user', 'User', 'Standard user access', 0, 0, 0, 0, 0, 0, ?1)
            "#,
        )
        .bind(&now)
        .execute(pool)
        .await
        .expect("Failed to insert default roles");
    }

    /// Create a test user and return JWT token for authenticated requests
    async fn create_test_user_and_get_token(pool: &SqlitePool) -> (String, String, String) {
        let user_id = uuid::Uuid::new_v4().to_string();
        let username = format!("testuser_{}", &user_id[..8]);
        let password = "TestPassword123!";
        let password_hash = bcrypt::hash(password, 4).expect("Failed to hash password");
        let now = chrono::Utc::now();

        sqlx::query(
            r#"
            INSERT INTO users (id, username, email, password_hash, created_at, is_active, accepted_terms_at, terms_version)
            VALUES (?1, ?2, ?3, ?4, ?5, 1, ?5, '1.0')
            "#,
        )
        .bind(&user_id)
        .bind(&username)
        .bind(format!("{}@test.com", username))
        .bind(&password_hash)
        .bind(now)
        .execute(pool)
        .await
        .expect("Failed to create test user");

        // Assign user role
        sqlx::query(
            "INSERT INTO user_roles (user_id, role_id, assigned_at) VALUES (?1, 'user', ?2)"
        )
        .bind(&user_id)
        .bind(now)
        .execute(pool)
        .await
        .expect("Failed to assign role");

        let token = auth::create_jwt(&user_id, &username, vec!["user".to_string()])
            .expect("Failed to create JWT");

        (user_id, username, token)
    }

    // =========================================================================
    // Authentication Tests
    // =========================================================================

    #[tokio::test]
    async fn test_register_user_success() {
        // Set JWT_SECRET for test
        std::env::set_var("JWT_SECRET", "test_secret_key_for_testing_purposes_only_32");

        let pool = setup_test_db().await;

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(pool.clone()))
                .route("/api/auth/register", web::post().to(api::auth::register))
        ).await;

        let user_data = CreateUser {
            username: "newuser".to_string(),
            email: "newuser@example.com".to_string(),
            password: "SecurePassword123!".to_string(),
            first_name: None,
            last_name: None,
            accept_terms: true,
        };

        let req = test::TestRequest::post()
            .uri("/api/auth/register")
            .set_json(&user_data)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let body: LoginResponse = test::read_body_json(resp).await;
        assert!(!body.token.is_empty());
        assert!(!body.refresh_token.is_empty());
        assert_eq!(body.user.username, "newuser");
        assert_eq!(body.user.email, "newuser@example.com");
    }

    #[tokio::test]
    async fn test_register_user_duplicate_username() {
        std::env::set_var("JWT_SECRET", "test_secret_key_for_testing_purposes_only_32");

        let pool = setup_test_db().await;

        // Create existing user
        let (_user_id, username, _token) = create_test_user_and_get_token(&pool).await;

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(pool.clone()))
                .route("/api/auth/register", web::post().to(api::auth::register))
        ).await;

        let user_data = CreateUser {
            username,
            email: "different@example.com".to_string(),
            password: "SecurePassword123!".to_string(),
            first_name: None,
            last_name: None,
            accept_terms: true,
        };

        let req = test::TestRequest::post()
            .uri("/api/auth/register")
            .set_json(&user_data)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let body: serde_json::Value = test::read_body_json(resp).await;
        assert!(body["error"].as_str().unwrap().contains("already exists"));
    }

    #[tokio::test]
    async fn test_register_user_weak_password() {
        std::env::set_var("JWT_SECRET", "test_secret_key_for_testing_purposes_only_32");

        let pool = setup_test_db().await;

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(pool.clone()))
                .route("/api/auth/register", web::post().to(api::auth::register))
        ).await;

        let user_data = CreateUser {
            username: "weakpassuser".to_string(),
            email: "weak@example.com".to_string(),
            password: "weak".to_string(), // Too short, no uppercase, no number
            first_name: None,
            last_name: None,
            accept_terms: true,
        };

        let req = test::TestRequest::post()
            .uri("/api/auth/register")
            .set_json(&user_data)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn test_register_user_must_accept_terms() {
        std::env::set_var("JWT_SECRET", "test_secret_key_for_testing_purposes_only_32");

        let pool = setup_test_db().await;

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(pool.clone()))
                .route("/api/auth/register", web::post().to(api::auth::register))
        ).await;

        let user_data = CreateUser {
            username: "notermsuser".to_string(),
            email: "noterms@example.com".to_string(),
            password: "SecurePassword123!".to_string(),
            first_name: None,
            last_name: None,
            accept_terms: false, // Must accept terms
        };

        let req = test::TestRequest::post()
            .uri("/api/auth/register")
            .set_json(&user_data)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn test_login_success() {
        std::env::set_var("JWT_SECRET", "test_secret_key_for_testing_purposes_only_32");

        let pool = setup_test_db().await;

        // Create user with known password
        let user_id = uuid::Uuid::new_v4().to_string();
        let username = "loginuser";
        let password = "TestPassword123!";
        let password_hash = bcrypt::hash(password, 4).expect("Failed to hash password");
        let now = chrono::Utc::now();

        sqlx::query(
            r#"
            INSERT INTO users (id, username, email, password_hash, created_at, is_active, accepted_terms_at, terms_version)
            VALUES (?1, ?2, ?3, ?4, ?5, 1, ?5, '1.0')
            "#,
        )
        .bind(&user_id)
        .bind(username)
        .bind("loginuser@test.com")
        .bind(&password_hash)
        .bind(now)
        .execute(&pool)
        .await
        .expect("Failed to create test user");

        // Assign role
        sqlx::query(
            "INSERT INTO user_roles (user_id, role_id, assigned_at) VALUES (?1, 'user', ?2)"
        )
        .bind(&user_id)
        .bind(now)
        .execute(&pool)
        .await
        .expect("Failed to assign role");

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(pool.clone()))
                .route("/api/auth/login", web::post().to(api::auth::login))
        ).await;

        let login_data = LoginRequest {
            username: username.to_string(),
            password: password.to_string(),
        };

        let req = test::TestRequest::post()
            .uri("/api/auth/login")
            .set_json(&login_data)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let body: LoginResponse = test::read_body_json(resp).await;
        assert!(!body.token.is_empty());
        assert!(!body.refresh_token.is_empty());
        assert_eq!(body.user.username, username);
    }

    #[tokio::test]
    async fn test_login_invalid_credentials() {
        std::env::set_var("JWT_SECRET", "test_secret_key_for_testing_purposes_only_32");

        let pool = setup_test_db().await;
        let (_user_id, username, _token) = create_test_user_and_get_token(&pool).await;

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(pool.clone()))
                .route("/api/auth/login", web::post().to(api::auth::login))
        ).await;

        let login_data = LoginRequest {
            username,
            password: "wrongpassword".to_string(),
        };

        let req = test::TestRequest::post()
            .uri("/api/auth/login")
            .set_json(&login_data)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let body: serde_json::Value = test::read_body_json(resp).await;
        assert!(body["error"].as_str().unwrap().contains("Invalid credentials"));
    }

    #[tokio::test]
    async fn test_login_nonexistent_user() {
        std::env::set_var("JWT_SECRET", "test_secret_key_for_testing_purposes_only_32");

        let pool = setup_test_db().await;

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(pool.clone()))
                .route("/api/auth/login", web::post().to(api::auth::login))
        ).await;

        let login_data = LoginRequest {
            username: "nonexistent".to_string(),
            password: "anypassword".to_string(),
        };

        let req = test::TestRequest::post()
            .uri("/api/auth/login")
            .set_json(&login_data)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let body: serde_json::Value = test::read_body_json(resp).await;
        // Should return generic message to prevent username enumeration
        assert!(body["error"].as_str().unwrap().contains("Invalid credentials"));
    }

    #[tokio::test]
    async fn test_jwt_validation_valid_token() {
        std::env::set_var("JWT_SECRET", "test_secret_key_for_testing_purposes_only_32");

        let pool = setup_test_db().await;
        let (user_id, _username, token) = create_test_user_and_get_token(&pool).await;

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(pool.clone()))
                .service(
                    web::scope("/api")
                        .wrap(JwtMiddleware)
                        .route("/auth/me", web::get().to(api::auth::me))
                )
        ).await;

        let req = test::TestRequest::get()
            .uri("/api/auth/me")
            .insert_header(("Authorization", format!("Bearer {}", token)))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["id"].as_str().unwrap(), user_id);
    }

    #[tokio::test]
    async fn test_jwt_validation_invalid_token() {
        std::env::set_var("JWT_SECRET", "test_secret_key_for_testing_purposes_only_32");

        let pool = setup_test_db().await;

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(pool.clone()))
                .service(
                    web::scope("/api")
                        .wrap(JwtMiddleware)
                        .route("/auth/me", web::get().to(api::auth::me))
                )
        ).await;

        let req = test::TestRequest::get()
            .uri("/api/auth/me")
            .insert_header(("Authorization", "Bearer invalid_token"))
            .to_request();

        // Use try_call_service since middleware returns error (not response)
        let result = test::try_call_service(&app, req).await;
        assert!(result.is_err(), "Expected authentication error for invalid token");
    }

    #[tokio::test]
    async fn test_jwt_validation_missing_token() {
        std::env::set_var("JWT_SECRET", "test_secret_key_for_testing_purposes_only_32");

        let pool = setup_test_db().await;

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(pool.clone()))
                .service(
                    web::scope("/api")
                        .wrap(JwtMiddleware)
                        .route("/auth/me", web::get().to(api::auth::me))
                )
        ).await;

        let req = test::TestRequest::get()
            .uri("/api/auth/me")
            .to_request();

        // Use try_call_service since middleware returns error (not response)
        let result = test::try_call_service(&app, req).await;
        assert!(result.is_err(), "Expected authentication error for missing token");
    }

    // =========================================================================
    // Scan CRUD Tests
    // =========================================================================

    #[tokio::test]
    async fn test_get_scans_empty() {
        std::env::set_var("JWT_SECRET", "test_secret_key_for_testing_purposes_only_32");

        let pool = setup_test_db().await;
        let (_user_id, _username, token) = create_test_user_and_get_token(&pool).await;

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(pool.clone()))
                .service(
                    web::scope("/api")
                        .wrap(JwtMiddleware)
                        .route("/scans", web::get().to(api::scans::get_scans))
                )
        ).await;

        let req = test::TestRequest::get()
            .uri("/api/scans")
            .insert_header(("Authorization", format!("Bearer {}", token)))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let body: Vec<serde_json::Value> = test::read_body_json(resp).await;
        assert!(body.is_empty());
    }

    #[tokio::test]
    async fn test_get_scan_not_found() {
        std::env::set_var("JWT_SECRET", "test_secret_key_for_testing_purposes_only_32");

        let pool = setup_test_db().await;
        let (_user_id, _username, token) = create_test_user_and_get_token(&pool).await;

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(pool.clone()))
                .service(
                    web::scope("/api")
                        .wrap(JwtMiddleware)
                        .route("/scans/{id}", web::get().to(api::scans::get_scan))
                )
        ).await;

        let req = test::TestRequest::get()
            .uri("/api/scans/nonexistent-id")
            .insert_header(("Authorization", format!("Bearer {}", token)))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        let body: serde_json::Value = test::read_body_json(resp).await;
        assert!(body["error"].as_str().unwrap().contains("not found"));
    }

    #[tokio::test]
    async fn test_get_scan_by_id() {
        std::env::set_var("JWT_SECRET", "test_secret_key_for_testing_purposes_only_32");

        let pool = setup_test_db().await;
        let (user_id, _username, token) = create_test_user_and_get_token(&pool).await;

        // Create a scan directly in database
        let scan_id = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now();
        sqlx::query(
            r#"
            INSERT INTO scan_results (id, user_id, name, targets, status, created_at)
            VALUES (?1, ?2, ?3, ?4, 'completed', ?5)
            "#,
        )
        .bind(&scan_id)
        .bind(&user_id)
        .bind("Test Scan")
        .bind(r#"["8.8.8.8"]"#)
        .bind(now)
        .execute(&pool)
        .await
        .expect("Failed to create test scan");

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(pool.clone()))
                .service(
                    web::scope("/api")
                        .wrap(JwtMiddleware)
                        .route("/scans/{id}", web::get().to(api::scans::get_scan))
                )
        ).await;

        let req = test::TestRequest::get()
            .uri(&format!("/api/scans/{}", scan_id))
            .insert_header(("Authorization", format!("Bearer {}", token)))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["id"].as_str().unwrap(), scan_id);
        assert_eq!(body["name"].as_str().unwrap(), "Test Scan");
        assert_eq!(body["status"].as_str().unwrap(), "completed");
    }

    #[tokio::test]
    async fn test_get_scan_access_denied_other_user() {
        std::env::set_var("JWT_SECRET", "test_secret_key_for_testing_purposes_only_32");

        let pool = setup_test_db().await;

        // Create first user's scan
        let (user1_id, _username1, _token1) = create_test_user_and_get_token(&pool).await;
        let scan_id = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now();
        sqlx::query(
            r#"
            INSERT INTO scan_results (id, user_id, name, targets, status, created_at)
            VALUES (?1, ?2, ?3, ?4, 'completed', ?5)
            "#,
        )
        .bind(&scan_id)
        .bind(&user1_id)
        .bind("User1 Scan")
        .bind(r#"["8.8.8.8"]"#)
        .bind(now)
        .execute(&pool)
        .await
        .expect("Failed to create test scan");

        // Create second user and try to access first user's scan
        let (_user2_id, _username2, token2) = create_test_user_and_get_token(&pool).await;

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(pool.clone()))
                .service(
                    web::scope("/api")
                        .wrap(JwtMiddleware)
                        .route("/scans/{id}", web::get().to(api::scans::get_scan))
                )
        ).await;

        let req = test::TestRequest::get()
            .uri(&format!("/api/scans/{}", scan_id))
            .insert_header(("Authorization", format!("Bearer {}", token2)))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        let body: serde_json::Value = test::read_body_json(resp).await;
        assert!(body["error"].as_str().unwrap().contains("denied"));
    }

    #[tokio::test]
    async fn test_delete_scan_success() {
        std::env::set_var("JWT_SECRET", "test_secret_key_for_testing_purposes_only_32");

        let pool = setup_test_db().await;
        let (user_id, _username, token) = create_test_user_and_get_token(&pool).await;

        // Create a scan
        let scan_id = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now();
        sqlx::query(
            r#"
            INSERT INTO scan_results (id, user_id, name, targets, status, created_at)
            VALUES (?1, ?2, ?3, ?4, 'completed', ?5)
            "#,
        )
        .bind(&scan_id)
        .bind(&user_id)
        .bind("Scan to Delete")
        .bind(r#"["8.8.8.8"]"#)
        .bind(now)
        .execute(&pool)
        .await
        .expect("Failed to create test scan");

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(pool.clone()))
                .service(
                    web::scope("/api")
                        .wrap(JwtMiddleware)
                        .route("/scans/{id}", web::delete().to(api::scans::delete_scan))
                )
        ).await;

        let req = test::TestRequest::delete()
            .uri(&format!("/api/scans/{}", scan_id))
            .insert_header(("Authorization", format!("Bearer {}", token)))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let body: serde_json::Value = test::read_body_json(resp).await;
        assert!(body["message"].as_str().unwrap().contains("deleted"));

        // Verify scan is actually deleted
        let scan = sqlx::query_as::<_, crate::db::models::ScanResult>(
            "SELECT * FROM scan_results WHERE id = ?1"
        )
        .bind(&scan_id)
        .fetch_optional(&pool)
        .await
        .expect("Failed to query scan");

        assert!(scan.is_none());
    }

    #[tokio::test]
    async fn test_delete_scan_not_found() {
        std::env::set_var("JWT_SECRET", "test_secret_key_for_testing_purposes_only_32");

        let pool = setup_test_db().await;
        let (_user_id, _username, token) = create_test_user_and_get_token(&pool).await;

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(pool.clone()))
                .service(
                    web::scope("/api")
                        .wrap(JwtMiddleware)
                        .route("/scans/{id}", web::delete().to(api::scans::delete_scan))
                )
        ).await;

        let req = test::TestRequest::delete()
            .uri("/api/scans/nonexistent-scan-id")
            .insert_header(("Authorization", format!("Bearer {}", token)))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_delete_scan_other_user_denied() {
        std::env::set_var("JWT_SECRET", "test_secret_key_for_testing_purposes_only_32");

        let pool = setup_test_db().await;

        // Create first user's scan
        let (user1_id, _username1, _token1) = create_test_user_and_get_token(&pool).await;
        let scan_id = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now();
        sqlx::query(
            r#"
            INSERT INTO scan_results (id, user_id, name, targets, status, created_at)
            VALUES (?1, ?2, ?3, ?4, 'completed', ?5)
            "#,
        )
        .bind(&scan_id)
        .bind(&user1_id)
        .bind("User1 Scan")
        .bind(r#"["8.8.8.8"]"#)
        .bind(now)
        .execute(&pool)
        .await
        .expect("Failed to create test scan");

        // Create second user and try to delete first user's scan
        let (_user2_id, _username2, token2) = create_test_user_and_get_token(&pool).await;

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(pool.clone()))
                .service(
                    web::scope("/api")
                        .wrap(JwtMiddleware)
                        .route("/scans/{id}", web::delete().to(api::scans::delete_scan))
                )
        ).await;

        let req = test::TestRequest::delete()
            .uri(&format!("/api/scans/{}", scan_id))
            .insert_header(("Authorization", format!("Bearer {}", token2)))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND); // Returns 404 to not leak info

        // Verify scan still exists
        let scan = sqlx::query_as::<_, crate::db::models::ScanResult>(
            "SELECT * FROM scan_results WHERE id = ?1"
        )
        .bind(&scan_id)
        .fetch_optional(&pool)
        .await
        .expect("Failed to query scan");

        assert!(scan.is_some());
    }

    #[tokio::test]
    async fn test_get_user_scans_list() {
        std::env::set_var("JWT_SECRET", "test_secret_key_for_testing_purposes_only_32");

        let pool = setup_test_db().await;
        let (user_id, _username, token) = create_test_user_and_get_token(&pool).await;

        // Create multiple scans
        let now = chrono::Utc::now();
        for i in 1..=3 {
            let scan_id = uuid::Uuid::new_v4().to_string();
            sqlx::query(
                r#"
                INSERT INTO scan_results (id, user_id, name, targets, status, created_at)
                VALUES (?1, ?2, ?3, ?4, 'completed', ?5)
                "#,
            )
            .bind(&scan_id)
            .bind(&user_id)
            .bind(format!("Test Scan {}", i))
            .bind(r#"["8.8.8.8"]"#)
            .bind(now)
            .execute(&pool)
            .await
            .expect("Failed to create test scan");
        }

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(pool.clone()))
                .service(
                    web::scope("/api")
                        .wrap(JwtMiddleware)
                        .route("/scans", web::get().to(api::scans::get_scans))
                )
        ).await;

        let req = test::TestRequest::get()
            .uri("/api/scans")
            .insert_header(("Authorization", format!("Bearer {}", token)))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let body: Vec<serde_json::Value> = test::read_body_json(resp).await;
        assert_eq!(body.len(), 3);
    }

    // =========================================================================
    // Vulnerability Management Tests
    // =========================================================================

    #[tokio::test]
    async fn test_list_vulnerabilities_requires_scan_id() {
        std::env::set_var("JWT_SECRET", "test_secret_key_for_testing_purposes_only_32");

        let pool = setup_test_db().await;
        let (_user_id, _username, token) = create_test_user_and_get_token(&pool).await;

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(pool.clone()))
                .service(
                    web::scope("/api")
                        .wrap(JwtMiddleware)
                        .route("/vulnerabilities", web::get().to(api::vulnerabilities::list_vulnerabilities))
                )
        ).await;

        let req = test::TestRequest::get()
            .uri("/api/vulnerabilities")
            .insert_header(("Authorization", format!("Bearer {}", token)))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let body: serde_json::Value = test::read_body_json(resp).await;
        assert!(body["error"].as_str().unwrap().contains("scan_id"));
    }

    #[tokio::test]
    async fn test_get_vulnerability_not_found() {
        std::env::set_var("JWT_SECRET", "test_secret_key_for_testing_purposes_only_32");

        let pool = setup_test_db().await;
        let (_user_id, _username, token) = create_test_user_and_get_token(&pool).await;

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(pool.clone()))
                .service(
                    web::scope("/api")
                        .wrap(JwtMiddleware)
                        .route("/vulnerabilities/{id}", web::get().to(api::vulnerabilities::get_vulnerability))
                )
        ).await;

        let req = test::TestRequest::get()
            .uri("/api/vulnerabilities/nonexistent-vuln-id")
            .insert_header(("Authorization", format!("Bearer {}", token)))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_bulk_export_vulnerabilities_validation() {
        std::env::set_var("JWT_SECRET", "test_secret_key_for_testing_purposes_only_32");

        let pool = setup_test_db().await;
        let (_user_id, _username, token) = create_test_user_and_get_token(&pool).await;

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(pool.clone()))
                .service(
                    web::scope("/api")
                        .wrap(JwtMiddleware)
                        .route("/vulnerabilities/bulk-export", web::post().to(api::vulnerabilities::bulk_export_vulnerabilities))
                )
        ).await;

        // Test with empty vulnerability_ids
        let req = test::TestRequest::post()
            .uri("/api/vulnerabilities/bulk-export")
            .insert_header(("Authorization", format!("Bearer {}", token)))
            .set_json(&json!({
                "vulnerability_ids": [],
                "format": "json"
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let body: serde_json::Value = test::read_body_json(resp).await;
        assert!(body["error"].as_str().unwrap().contains("At least one"));
    }

    #[tokio::test]
    async fn test_bulk_export_vulnerabilities_invalid_format() {
        std::env::set_var("JWT_SECRET", "test_secret_key_for_testing_purposes_only_32");

        let pool = setup_test_db().await;
        let (_user_id, _username, token) = create_test_user_and_get_token(&pool).await;

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(pool.clone()))
                .service(
                    web::scope("/api")
                        .wrap(JwtMiddleware)
                        .route("/vulnerabilities/bulk-export", web::post().to(api::vulnerabilities::bulk_export_vulnerabilities))
                )
        ).await;

        let req = test::TestRequest::post()
            .uri("/api/vulnerabilities/bulk-export")
            .insert_header(("Authorization", format!("Bearer {}", token)))
            .set_json(&json!({
                "vulnerability_ids": ["vuln-1"],
                "format": "invalid_format"
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let body: serde_json::Value = test::read_body_json(resp).await;
        assert!(body["error"].as_str().unwrap().contains("Invalid format"));
    }

    // =========================================================================
    // Scan Input Validation Tests
    // =========================================================================
    // Note: Detailed input validation tests are in src/web/api/scans.rs#tests

    // =========================================================================
    // Edge Case and Security Tests
    // =========================================================================

    #[tokio::test]
    async fn test_auth_without_bearer_prefix() {
        std::env::set_var("JWT_SECRET", "test_secret_key_for_testing_purposes_only_32");

        let pool = setup_test_db().await;
        let (_user_id, _username, token) = create_test_user_and_get_token(&pool).await;

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(pool.clone()))
                .service(
                    web::scope("/api")
                        .wrap(JwtMiddleware)
                        .route("/auth/me", web::get().to(api::auth::me))
                )
        ).await;

        // Missing "Bearer " prefix
        let req = test::TestRequest::get()
            .uri("/api/auth/me")
            .insert_header(("Authorization", token))
            .to_request();

        // Use try_call_service since middleware returns error (not response)
        let result = test::try_call_service(&app, req).await;
        assert!(result.is_err(), "Expected authentication error for token without Bearer prefix");
    }

    #[tokio::test]
    async fn test_expired_jwt_token() {
        std::env::set_var("JWT_SECRET", "test_secret_key_for_testing_purposes_only_32");

        let pool = setup_test_db().await;

        // Create an expired token manually
        let claims = Claims {
            sub: "test-user-id".to_string(),
            username: "testuser".to_string(),
            roles: vec!["user".to_string()],
            exp: 0, // Expired
            iat: 0,
            org_id: None,
            org_role: None,
            teams: vec![],
            permissions: vec![],
        };

        let expired_token = jsonwebtoken::encode(
            &jsonwebtoken::Header::default(),
            &claims,
            &jsonwebtoken::EncodingKey::from_secret(b"test_secret_key_for_testing_purposes_only_32"),
        ).expect("Failed to create expired token");

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(pool.clone()))
                .service(
                    web::scope("/api")
                        .wrap(JwtMiddleware)
                        .route("/auth/me", web::get().to(api::auth::me))
                )
        ).await;

        let req = test::TestRequest::get()
            .uri("/api/auth/me")
            .insert_header(("Authorization", format!("Bearer {}", expired_token)))
            .to_request();

        // Use try_call_service since middleware returns error (not response)
        let result = test::try_call_service(&app, req).await;
        assert!(result.is_err(), "Expected authentication error for expired token");
    }

    #[tokio::test]
    async fn test_malformed_json_request() {
        std::env::set_var("JWT_SECRET", "test_secret_key_for_testing_purposes_only_32");

        let pool = setup_test_db().await;

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(pool.clone()))
                .route("/api/auth/login", web::post().to(api::auth::login))
        ).await;

        let req = test::TestRequest::post()
            .uri("/api/auth/login")
            .insert_header(("Content-Type", "application/json"))
            .set_payload("{ invalid json }")
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_content_type_validation() {
        std::env::set_var("JWT_SECRET", "test_secret_key_for_testing_purposes_only_32");

        let pool = setup_test_db().await;

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(pool.clone()))
                .route("/api/auth/login", web::post().to(api::auth::login))
        ).await;

        // Send form data instead of JSON
        let req = test::TestRequest::post()
            .uri("/api/auth/login")
            .insert_header(("Content-Type", "application/x-www-form-urlencoded"))
            .set_payload("username=test&password=test")
            .to_request();

        let resp = test::call_service(&app, req).await;
        // Should fail because endpoint expects JSON
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }
}
