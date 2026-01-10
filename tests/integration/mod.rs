//! HeroForge Comprehensive Integration Tests
//!
//! This file contains production-ready integration tests for all critical API endpoints.
//! Copy these tests to /tests/integration/ in the HeroForge repository.
//!
//! Run with: cargo test --test integration_tests -- --test-threads=1

use actix_web::{test, web, App};
use serde_json::{json, Value};
use std::sync::Once;

static INIT: Once = Once::new();

/// Initialize test environment
fn init_test_env() {
    INIT.call_once(|| {
        std::env::set_var("DATABASE_URL", "sqlite:./test_heroforge.db");
        std::env::set_var("JWT_SECRET", "test_jwt_secret_key_for_integration_tests");
        std::env::set_var("RUST_LOG", "debug");
    });
}

// ============================================================================
// Test Utilities
// ============================================================================

mod test_utils {
    use super::*;
    use heroforge::db;
    use heroforge::web::create_app;
    use sqlx::SqlitePool;

    /// Create a fresh test database
    pub async fn setup_test_db() -> SqlitePool {
        let pool = db::init_database().await.expect("Failed to init test database");

        // Clean up any existing test data
        sqlx::query("DELETE FROM users WHERE username LIKE 'test_%'")
            .execute(&pool)
            .await
            .ok();

        pool
    }

    /// Create test application with all routes configured
    pub fn create_test_app(pool: SqlitePool) -> impl actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
    > {
        test::init_service(create_app(pool))
    }

    /// Register a test user and return JWT token
    pub async fn register_and_login(app: &impl actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
    >, username: &str) -> String {
        // Register
        let register_req = test::TestRequest::post()
            .uri("/api/auth/register")
            .set_json(json!({
                "username": username,
                "email": format!("{}@test.heroforge.io", username),
                "password": "TestPassword123!@#",
                "password_confirm": "TestPassword123!@#"
            }))
            .to_request();

        let resp = test::call_service(app, register_req).await;
        assert!(resp.status().is_success(), "Registration failed");

        // Login
        let login_req = test::TestRequest::post()
            .uri("/api/auth/login")
            .set_json(json!({
                "username": username,
                "password": "TestPassword123!@#"
            }))
            .to_request();

        let resp = test::call_service(app, login_req).await;
        assert!(resp.status().is_success(), "Login failed");

        let body: Value = test::read_body_json(resp).await;
        body["token"].as_str().unwrap().to_string()
    }
}

// ============================================================================
// Authentication Tests
// ============================================================================

mod auth_tests {
    use super::*;
    use super::test_utils::*;

    #[actix_web::test]
    async fn test_user_registration_success() {
        init_test_env();
        let pool = setup_test_db().await;
        let app = test::init_service(heroforge::web::create_app(pool)).await;

        let req = test::TestRequest::post()
            .uri("/api/auth/register")
            .set_json(json!({
                "username": "test_user_reg_1",
                "email": "test_reg_1@heroforge.io",
                "password": "SecurePass123!@#",
                "password_confirm": "SecurePass123!@#"
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 201, "Expected 201 Created");

        let body: Value = test::read_body_json(resp).await;
        assert!(body["user"]["id"].is_string());
        assert_eq!(body["user"]["username"], "test_user_reg_1");
        assert!(body["token"].is_string());
    }

    #[actix_web::test]
    async fn test_user_registration_duplicate_username() {
        init_test_env();
        let pool = setup_test_db().await;
        let app = test::init_service(heroforge::web::create_app(pool)).await;

        // First registration
        let req1 = test::TestRequest::post()
            .uri("/api/auth/register")
            .set_json(json!({
                "username": "test_user_dup",
                "email": "test_dup_1@heroforge.io",
                "password": "SecurePass123!@#",
                "password_confirm": "SecurePass123!@#"
            }))
            .to_request();
        test::call_service(&app, req1).await;

        // Duplicate registration
        let req2 = test::TestRequest::post()
            .uri("/api/auth/register")
            .set_json(json!({
                "username": "test_user_dup",
                "email": "test_dup_2@heroforge.io",
                "password": "SecurePass123!@#",
                "password_confirm": "SecurePass123!@#"
            }))
            .to_request();

        let resp = test::call_service(&app, req2).await;
        assert_eq!(resp.status(), 409, "Expected 409 Conflict for duplicate username");
    }

    #[actix_web::test]
    async fn test_user_registration_weak_password() {
        init_test_env();
        let pool = setup_test_db().await;
        let app = test::init_service(heroforge::web::create_app(pool)).await;

        let req = test::TestRequest::post()
            .uri("/api/auth/register")
            .set_json(json!({
                "username": "test_user_weak",
                "email": "test_weak@heroforge.io",
                "password": "weak",
                "password_confirm": "weak"
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400, "Expected 400 Bad Request for weak password");
    }

    #[actix_web::test]
    async fn test_user_login_success() {
        init_test_env();
        let pool = setup_test_db().await;
        let app = test::init_service(heroforge::web::create_app(pool)).await;

        // Register first
        let reg_req = test::TestRequest::post()
            .uri("/api/auth/register")
            .set_json(json!({
                "username": "test_login_user",
                "email": "test_login@heroforge.io",
                "password": "SecurePass123!@#",
                "password_confirm": "SecurePass123!@#"
            }))
            .to_request();
        test::call_service(&app, reg_req).await;

        // Login
        let login_req = test::TestRequest::post()
            .uri("/api/auth/login")
            .set_json(json!({
                "username": "test_login_user",
                "password": "SecurePass123!@#"
            }))
            .to_request();

        let resp = test::call_service(&app, login_req).await;
        assert_eq!(resp.status(), 200, "Expected 200 OK for successful login");

        let body: Value = test::read_body_json(resp).await;
        assert!(body["token"].is_string());
        assert!(body["refresh_token"].is_string());
        assert!(body["expires_in"].is_number());
    }

    #[actix_web::test]
    async fn test_user_login_invalid_credentials() {
        init_test_env();
        let pool = setup_test_db().await;
        let app = test::init_service(heroforge::web::create_app(pool)).await;

        let req = test::TestRequest::post()
            .uri("/api/auth/login")
            .set_json(json!({
                "username": "nonexistent_user",
                "password": "WrongPassword123!"
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 401, "Expected 401 Unauthorized");
    }

    #[actix_web::test]
    async fn test_account_lockout_after_failed_attempts() {
        init_test_env();
        let pool = setup_test_db().await;
        let app = test::init_service(heroforge::web::create_app(pool)).await;

        // Register user
        let reg_req = test::TestRequest::post()
            .uri("/api/auth/register")
            .set_json(json!({
                "username": "test_lockout_user",
                "email": "test_lockout@heroforge.io",
                "password": "SecurePass123!@#",
                "password_confirm": "SecurePass123!@#"
            }))
            .to_request();
        test::call_service(&app, reg_req).await;

        // Attempt 5 failed logins
        for i in 0..5 {
            let fail_req = test::TestRequest::post()
                .uri("/api/auth/login")
                .set_json(json!({
                    "username": "test_lockout_user",
                    "password": "WrongPassword!"
                }))
                .to_request();
            let resp = test::call_service(&app, fail_req).await;
            assert_eq!(resp.status(), 401, "Attempt {} should fail", i + 1);
        }

        // 6th attempt should result in lockout
        let lockout_req = test::TestRequest::post()
            .uri("/api/auth/login")
            .set_json(json!({
                "username": "test_lockout_user",
                "password": "SecurePass123!@#"  // Even correct password
            }))
            .to_request();

        let resp = test::call_service(&app, lockout_req).await;
        assert_eq!(resp.status(), 429, "Expected 429 Too Many Requests (account locked)");
    }

    #[actix_web::test]
    async fn test_jwt_token_refresh() {
        init_test_env();
        let pool = setup_test_db().await;
        let app = test::init_service(heroforge::web::create_app(pool)).await;

        // Register and login
        let reg_req = test::TestRequest::post()
            .uri("/api/auth/register")
            .set_json(json!({
                "username": "test_refresh_user",
                "email": "test_refresh@heroforge.io",
                "password": "SecurePass123!@#",
                "password_confirm": "SecurePass123!@#"
            }))
            .to_request();
        test::call_service(&app, reg_req).await;

        let login_req = test::TestRequest::post()
            .uri("/api/auth/login")
            .set_json(json!({
                "username": "test_refresh_user",
                "password": "SecurePass123!@#"
            }))
            .to_request();
        let login_resp = test::call_service(&app, login_req).await;
        let login_body: Value = test::read_body_json(login_resp).await;
        let refresh_token = login_body["refresh_token"].as_str().unwrap();

        // Refresh token
        let refresh_req = test::TestRequest::post()
            .uri("/api/auth/refresh")
            .set_json(json!({
                "refresh_token": refresh_token
            }))
            .to_request();

        let resp = test::call_service(&app, refresh_req).await;
        assert_eq!(resp.status(), 200, "Expected 200 OK for token refresh");

        let body: Value = test::read_body_json(resp).await;
        assert!(body["token"].is_string());
        assert_ne!(body["token"], login_body["token"], "New token should be different");
    }

    #[actix_web::test]
    async fn test_protected_endpoint_without_token() {
        init_test_env();
        let pool = setup_test_db().await;
        let app = test::init_service(heroforge::web::create_app(pool)).await;

        let req = test::TestRequest::get()
            .uri("/api/user/me")
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 401, "Expected 401 Unauthorized without token");
    }

    #[actix_web::test]
    async fn test_protected_endpoint_with_valid_token() {
        init_test_env();
        let pool = setup_test_db().await;
        let app = test::init_service(heroforge::web::create_app(pool)).await;

        let token = register_and_login(&app, "test_protected_user").await;

        let req = test::TestRequest::get()
            .uri("/api/user/me")
            .insert_header(("Authorization", format!("Bearer {}", token)))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200, "Expected 200 OK with valid token");
    }
}

// ============================================================================
// Scan API Tests
// ============================================================================

mod scan_tests {
    use super::*;
    use super::test_utils::*;

    #[actix_web::test]
    async fn test_create_scan_success() {
        init_test_env();
        let pool = setup_test_db().await;
        let app = test::init_service(heroforge::web::create_app(pool)).await;
        let token = register_and_login(&app, "test_scan_user").await;

        let req = test::TestRequest::post()
            .uri("/api/scans")
            .insert_header(("Authorization", format!("Bearer {}", token)))
            .set_json(json!({
                "name": "Test Scan",
                "targets": ["127.0.0.1"],
                "scan_type": "tcp-connect",
                "ports": "22,80,443"
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 201, "Expected 201 Created for new scan");

        let body: Value = test::read_body_json(resp).await;
        assert!(body["id"].is_string());
        assert_eq!(body["name"], "Test Scan");
        assert_eq!(body["status"], "pending");
    }

    #[actix_web::test]
    async fn test_create_scan_invalid_target() {
        init_test_env();
        let pool = setup_test_db().await;
        let app = test::init_service(heroforge::web::create_app(pool)).await;
        let token = register_and_login(&app, "test_scan_invalid_user").await;

        let req = test::TestRequest::post()
            .uri("/api/scans")
            .insert_header(("Authorization", format!("Bearer {}", token)))
            .set_json(json!({
                "name": "Invalid Scan",
                "targets": ["not-a-valid-ip-or-hostname!!!"],
                "scan_type": "tcp-connect"
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400, "Expected 400 Bad Request for invalid target");
    }

    #[actix_web::test]
    async fn test_list_scans() {
        init_test_env();
        let pool = setup_test_db().await;
        let app = test::init_service(heroforge::web::create_app(pool)).await;
        let token = register_and_login(&app, "test_list_scans_user").await;

        // Create a scan first
        let create_req = test::TestRequest::post()
            .uri("/api/scans")
            .insert_header(("Authorization", format!("Bearer {}", token)))
            .set_json(json!({
                "name": "List Test Scan",
                "targets": ["127.0.0.1"],
                "scan_type": "tcp-connect"
            }))
            .to_request();
        test::call_service(&app, create_req).await;

        // List scans
        let list_req = test::TestRequest::get()
            .uri("/api/scans")
            .insert_header(("Authorization", format!("Bearer {}", token)))
            .to_request();

        let resp = test::call_service(&app, list_req).await;
        assert_eq!(resp.status(), 200);

        let body: Value = test::read_body_json(resp).await;
        assert!(body["scans"].is_array());
        assert!(body["scans"].as_array().unwrap().len() >= 1);
    }

    #[actix_web::test]
    async fn test_get_scan_by_id() {
        init_test_env();
        let pool = setup_test_db().await;
        let app = test::init_service(heroforge::web::create_app(pool)).await;
        let token = register_and_login(&app, "test_get_scan_user").await;

        // Create scan
        let create_req = test::TestRequest::post()
            .uri("/api/scans")
            .insert_header(("Authorization", format!("Bearer {}", token)))
            .set_json(json!({
                "name": "Get Test Scan",
                "targets": ["127.0.0.1"],
                "scan_type": "tcp-connect"
            }))
            .to_request();
        let create_resp = test::call_service(&app, create_req).await;
        let create_body: Value = test::read_body_json(create_resp).await;
        let scan_id = create_body["id"].as_str().unwrap();

        // Get scan by ID
        let get_req = test::TestRequest::get()
            .uri(&format!("/api/scans/{}", scan_id))
            .insert_header(("Authorization", format!("Bearer {}", token)))
            .to_request();

        let resp = test::call_service(&app, get_req).await;
        assert_eq!(resp.status(), 200);

        let body: Value = test::read_body_json(resp).await;
        assert_eq!(body["id"], scan_id);
        assert_eq!(body["name"], "Get Test Scan");
    }

    #[actix_web::test]
    async fn test_get_scan_not_found() {
        init_test_env();
        let pool = setup_test_db().await;
        let app = test::init_service(heroforge::web::create_app(pool)).await;
        let token = register_and_login(&app, "test_notfound_user").await;

        let req = test::TestRequest::get()
            .uri("/api/scans/nonexistent-scan-id-12345")
            .insert_header(("Authorization", format!("Bearer {}", token)))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 404, "Expected 404 Not Found");
    }

    #[actix_web::test]
    async fn test_delete_scan() {
        init_test_env();
        let pool = setup_test_db().await;
        let app = test::init_service(heroforge::web::create_app(pool)).await;
        let token = register_and_login(&app, "test_delete_scan_user").await;

        // Create scan
        let create_req = test::TestRequest::post()
            .uri("/api/scans")
            .insert_header(("Authorization", format!("Bearer {}", token)))
            .set_json(json!({
                "name": "Delete Test Scan",
                "targets": ["127.0.0.1"],
                "scan_type": "tcp-connect"
            }))
            .to_request();
        let create_resp = test::call_service(&app, create_req).await;
        let create_body: Value = test::read_body_json(create_resp).await;
        let scan_id = create_body["id"].as_str().unwrap();

        // Delete scan
        let delete_req = test::TestRequest::delete()
            .uri(&format!("/api/scans/{}", scan_id))
            .insert_header(("Authorization", format!("Bearer {}", token)))
            .to_request();

        let resp = test::call_service(&app, delete_req).await;
        assert_eq!(resp.status(), 200, "Expected 200 OK for successful delete");

        // Verify deleted
        let get_req = test::TestRequest::get()
            .uri(&format!("/api/scans/{}", scan_id))
            .insert_header(("Authorization", format!("Bearer {}", token)))
            .to_request();
        let get_resp = test::call_service(&app, get_req).await;
        assert_eq!(get_resp.status(), 404, "Deleted scan should not be found");
    }

    #[actix_web::test]
    async fn test_scan_authorization() {
        init_test_env();
        let pool = setup_test_db().await;
        let app = test::init_service(heroforge::web::create_app(pool)).await;

        // Create two users
        let token1 = register_and_login(&app, "test_auth_user1").await;
        let token2 = register_and_login(&app, "test_auth_user2").await;

        // User 1 creates a scan
        let create_req = test::TestRequest::post()
            .uri("/api/scans")
            .insert_header(("Authorization", format!("Bearer {}", token1)))
            .set_json(json!({
                "name": "User1 Private Scan",
                "targets": ["127.0.0.1"],
                "scan_type": "tcp-connect"
            }))
            .to_request();
        let create_resp = test::call_service(&app, create_req).await;
        let create_body: Value = test::read_body_json(create_resp).await;
        let scan_id = create_body["id"].as_str().unwrap();

        // User 2 tries to access User 1's scan
        let get_req = test::TestRequest::get()
            .uri(&format!("/api/scans/{}", scan_id))
            .insert_header(("Authorization", format!("Bearer {}", token2)))
            .to_request();

        let resp = test::call_service(&app, get_req).await;
        assert_eq!(resp.status(), 403, "User 2 should not access User 1's scan");
    }
}

// ============================================================================
// Vulnerability API Tests
// ============================================================================

mod vulnerability_tests {
    use super::*;
    use super::test_utils::*;

    #[actix_web::test]
    async fn test_list_vulnerabilities() {
        init_test_env();
        let pool = setup_test_db().await;
        let app = test::init_service(heroforge::web::create_app(pool)).await;
        let token = register_and_login(&app, "test_vuln_user").await;

        let req = test::TestRequest::get()
            .uri("/api/vulnerabilities")
            .insert_header(("Authorization", format!("Bearer {}", token)))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);

        let body: Value = test::read_body_json(resp).await;
        assert!(body["vulnerabilities"].is_array());
        assert!(body["total"].is_number());
    }

    #[actix_web::test]
    async fn test_vulnerability_filters() {
        init_test_env();
        let pool = setup_test_db().await;
        let app = test::init_service(heroforge::web::create_app(pool)).await;
        let token = register_and_login(&app, "test_vuln_filter_user").await;

        // Filter by severity
        let req = test::TestRequest::get()
            .uri("/api/vulnerabilities?severity=critical&status=open")
            .insert_header(("Authorization", format!("Bearer {}", token)))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
    }

    #[actix_web::test]
    async fn test_vulnerability_statistics() {
        init_test_env();
        let pool = setup_test_db().await;
        let app = test::init_service(heroforge::web::create_app(pool)).await;
        let token = register_and_login(&app, "test_vuln_stats_user").await;

        let req = test::TestRequest::get()
            .uri("/api/vulnerabilities/statistics")
            .insert_header(("Authorization", format!("Bearer {}", token)))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);

        let body: Value = test::read_body_json(resp).await;
        assert!(body["by_severity"].is_object());
        assert!(body["by_status"].is_object());
    }
}

// ============================================================================
// Compliance API Tests
// ============================================================================

mod compliance_tests {
    use super::*;
    use super::test_utils::*;

    #[actix_web::test]
    async fn test_list_compliance_frameworks() {
        init_test_env();
        let pool = setup_test_db().await;
        let app = test::init_service(heroforge::web::create_app(pool)).await;
        let token = register_and_login(&app, "test_compliance_user").await;

        let req = test::TestRequest::get()
            .uri("/api/compliance/frameworks")
            .insert_header(("Authorization", format!("Bearer {}", token)))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);

        let body: Value = test::read_body_json(resp).await;
        assert!(body["frameworks"].is_array());

        // Verify expected frameworks exist
        let frameworks: Vec<&str> = body["frameworks"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|f| f["id"].as_str())
            .collect();

        assert!(frameworks.contains(&"pci-dss-4.0") || frameworks.contains(&"pci_dss"));
        assert!(frameworks.contains(&"hipaa") || frameworks.contains(&"HIPAA"));
    }

    #[actix_web::test]
    async fn test_compliance_assessment() {
        init_test_env();
        let pool = setup_test_db().await;
        let app = test::init_service(heroforge::web::create_app(pool)).await;
        let token = register_and_login(&app, "test_assess_user").await;

        let req = test::TestRequest::post()
            .uri("/api/compliance/assess")
            .insert_header(("Authorization", format!("Bearer {}", token)))
            .set_json(json!({
                "framework": "pci-dss-4.0",
                "scope": "full"
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        // Accept either 200 (success) or 202 (accepted/processing)
        assert!(
            resp.status() == 200 || resp.status() == 202,
            "Expected 200 or 202 for compliance assessment"
        );
    }
}

// ============================================================================
// Asset API Tests
// ============================================================================

mod asset_tests {
    use super::*;
    use super::test_utils::*;

    #[actix_web::test]
    async fn test_create_asset() {
        init_test_env();
        let pool = setup_test_db().await;
        let app = test::init_service(heroforge::web::create_app(pool)).await;
        let token = register_and_login(&app, "test_asset_user").await;

        let req = test::TestRequest::post()
            .uri("/api/assets")
            .insert_header(("Authorization", format!("Bearer {}", token)))
            .set_json(json!({
                "name": "Test Server",
                "asset_type": "server",
                "ip_address": "192.168.1.100",
                "hostname": "test-server.local",
                "criticality": "high",
                "tags": ["production", "web"]
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 201);

        let body: Value = test::read_body_json(resp).await;
        assert!(body["id"].is_string());
        assert_eq!(body["name"], "Test Server");
    }

    #[actix_web::test]
    async fn test_list_assets() {
        init_test_env();
        let pool = setup_test_db().await;
        let app = test::init_service(heroforge::web::create_app(pool)).await;
        let token = register_and_login(&app, "test_list_assets_user").await;

        let req = test::TestRequest::get()
            .uri("/api/assets")
            .insert_header(("Authorization", format!("Bearer {}", token)))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);

        let body: Value = test::read_body_json(resp).await;
        assert!(body["assets"].is_array());
    }
}

// ============================================================================
// Report API Tests
// ============================================================================

mod report_tests {
    use super::*;
    use super::test_utils::*;

    #[actix_web::test]
    async fn test_generate_report() {
        init_test_env();
        let pool = setup_test_db().await;
        let app = test::init_service(heroforge::web::create_app(pool)).await;
        let token = register_and_login(&app, "test_report_user").await;

        // First create a scan
        let scan_req = test::TestRequest::post()
            .uri("/api/scans")
            .insert_header(("Authorization", format!("Bearer {}", token)))
            .set_json(json!({
                "name": "Report Test Scan",
                "targets": ["127.0.0.1"],
                "scan_type": "tcp-connect"
            }))
            .to_request();
        let scan_resp = test::call_service(&app, scan_req).await;
        let scan_body: Value = test::read_body_json(scan_resp).await;
        let scan_id = scan_body["id"].as_str().unwrap();

        // Generate report
        let report_req = test::TestRequest::post()
            .uri("/api/reports/generate")
            .insert_header(("Authorization", format!("Bearer {}", token)))
            .set_json(json!({
                "scan_id": scan_id,
                "format": "json",
                "include_executive_summary": true,
                "include_technical_details": true
            }))
            .to_request();

        let resp = test::call_service(&app, report_req).await;
        // Accept 200 (immediate) or 202 (queued)
        assert!(resp.status() == 200 || resp.status() == 202);
    }

    #[actix_web::test]
    async fn test_list_reports() {
        init_test_env();
        let pool = setup_test_db().await;
        let app = test::init_service(heroforge::web::create_app(pool)).await;
        let token = register_and_login(&app, "test_list_reports_user").await;

        let req = test::TestRequest::get()
            .uri("/api/reports")
            .insert_header(("Authorization", format!("Bearer {}", token)))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);

        let body: Value = test::read_body_json(resp).await;
        assert!(body["reports"].is_array());
    }
}

// ============================================================================
// Health Check Tests
// ============================================================================

mod health_tests {
    use super::*;

    #[actix_web::test]
    async fn test_health_live() {
        init_test_env();
        let pool = test_utils::setup_test_db().await;
        let app = test::init_service(heroforge::web::create_app(pool)).await;

        let req = test::TestRequest::get()
            .uri("/health/live")
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);

        let body: Value = test::read_body_json(resp).await;
        assert_eq!(body["status"], "ok");
    }

    #[actix_web::test]
    async fn test_health_ready() {
        init_test_env();
        let pool = test_utils::setup_test_db().await;
        let app = test::init_service(heroforge::web::create_app(pool)).await;

        let req = test::TestRequest::get()
            .uri("/health/ready")
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);

        let body: Value = test::read_body_json(resp).await;
        assert_eq!(body["status"], "ok");
        assert!(body["database"].is_object());
    }
}

// ============================================================================
// Rate Limiting Tests
// ============================================================================

mod rate_limit_tests {
    use super::*;
    use super::test_utils::*;

    #[actix_web::test]
    async fn test_auth_rate_limiting() {
        init_test_env();
        let pool = setup_test_db().await;
        let app = test::init_service(heroforge::web::create_app(pool)).await;

        // Make many rapid login attempts
        let mut rate_limited = false;
        for i in 0..20 {
            let req = test::TestRequest::post()
                .uri("/api/auth/login")
                .set_json(json!({
                    "username": format!("ratelimit_user_{}", i),
                    "password": "SomePassword123!"
                }))
                .to_request();

            let resp = test::call_service(&app, req).await;
            if resp.status() == 429 {
                rate_limited = true;
                break;
            }
        }

        assert!(rate_limited, "Expected rate limiting to kick in after many requests");
    }
}

// ============================================================================
// WebSocket Tests
// ============================================================================

mod websocket_tests {
    use super::*;

    #[actix_web::test]
    async fn test_websocket_requires_auth() {
        init_test_env();
        let pool = test_utils::setup_test_db().await;
        let app = test::init_service(heroforge::web::create_app(pool)).await;

        // Attempt WebSocket connection without token
        let req = test::TestRequest::get()
            .uri("/api/ws/scans/test-scan-id")
            .to_request();

        let resp = test::call_service(&app, req).await;
        // Should fail without proper WebSocket upgrade and token
        assert!(resp.status() == 400 || resp.status() == 401);
    }
}

// ============================================================================
// Admin API Tests
// ============================================================================

mod admin_tests {
    use super::*;
    use super::test_utils::*;

    #[actix_web::test]
    async fn test_admin_endpoint_requires_admin_role() {
        init_test_env();
        let pool = setup_test_db().await;
        let app = test::init_service(heroforge::web::create_app(pool)).await;

        // Regular user (not admin)
        let token = register_and_login(&app, "test_nonadmin_user").await;

        let req = test::TestRequest::get()
            .uri("/api/admin/users")
            .insert_header(("Authorization", format!("Bearer {}", token)))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 403, "Non-admin should get 403 Forbidden");
    }

    #[actix_web::test]
    async fn test_admin_audit_logs() {
        init_test_env();
        let pool = setup_test_db().await;
        let app = test::init_service(heroforge::web::create_app(pool)).await;

        // Note: This test assumes an admin user exists or is auto-created
        // In real tests, you'd need to set ADMIN_USERNAME env var
        let token = register_and_login(&app, "test_audit_user").await;

        let req = test::TestRequest::get()
            .uri("/api/admin/audit-logs")
            .insert_header(("Authorization", format!("Bearer {}", token)))
            .to_request();

        let resp = test::call_service(&app, req).await;
        // Either 403 (not admin) or 200 (is admin) - both are valid responses
        assert!(resp.status() == 200 || resp.status() == 403);
    }
}
