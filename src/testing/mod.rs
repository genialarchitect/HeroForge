//! Testing utilities and helpers for HeroForge
//!
//! This module provides common testing utilities for:
//! - Test database setup and teardown
//! - Mock data generation
//! - Test fixtures
//! - HTTP client helpers
//! - Assertion helpers

use anyhow::Result;
use sqlx::{SqlitePool, sqlite::SqliteConnectOptions};
use std::str::FromStr;

pub mod fixtures;
pub mod mocks;
pub mod helpers;

/// Create a temporary test database
pub async fn create_test_database() -> Result<SqlitePool> {
    let db_url = format!("sqlite::memory:");

    let connect_options = SqliteConnectOptions::from_str(&db_url)?
        .create_if_missing(true)
        .shared_cache(false); // Each test gets its own database

    let pool = SqlitePool::connect_with(connect_options).await?;

    // Run migrations
    crate::db::init_database("sqlite::memory:").await?;

    Ok(pool)
}

/// Test user credentials
pub struct TestUser {
    pub username: String,
    pub email: String,
    pub password: String,
    pub id: Option<String>,
}

impl TestUser {
    /// Create a new test user with random credentials
    pub fn random() -> Self {
        let id = uuid::Uuid::new_v4().to_string();
        Self {
            username: format!("testuser_{}", &id[..8]),
            email: format!("test_{}@example.com", &id[..8]),
            password: "TestPassword123!".to_string(),
            id: None,
        }
    }

    /// Create a test user with specific credentials
    pub fn with_credentials(username: &str, email: &str, password: &str) -> Self {
        Self {
            username: username.to_string(),
            email: email.to_string(),
            password: password.to_string(),
            id: None,
        }
    }
}

/// Test scan configuration
pub struct TestScan {
    pub name: String,
    pub targets: Vec<String>,
    pub user_id: String,
}

impl TestScan {
    pub fn new(name: &str, targets: Vec<String>, user_id: &str) -> Self {
        Self {
            name: name.to_string(),
            targets,
            user_id: user_id.to_string(),
        }
    }

    pub fn default_for_user(user_id: &str) -> Self {
        Self {
            name: "Test Scan".to_string(),
            targets: vec!["192.168.1.1".to_string()],
            user_id: user_id.to_string(),
        }
    }
}

/// HTTP test client helper
#[cfg(any(test, feature = "test-client"))]
#[allow(unexpected_cfgs)]
pub mod http_client {
    use reqwest::Client;
    use serde::Serialize;

    pub struct TestClient {
        client: Client,
        base_url: String,
        auth_token: Option<String>,
    }

    impl TestClient {
        pub fn new(base_url: &str) -> Self {
            Self {
                client: Client::new(),
                base_url: base_url.to_string(),
                auth_token: None,
            }
        }

        pub fn with_token(mut self, token: String) -> Self {
            self.auth_token = Some(token);
            self
        }

        pub async fn get(&self, path: &str) -> reqwest::Result<reqwest::Response> {
            let url = format!("{}{}", self.base_url, path);
            let mut req = self.client.get(&url);

            if let Some(token) = &self.auth_token {
                req = req.bearer_auth(token);
            }

            req.send().await
        }

        pub async fn post<T: Serialize>(&self, path: &str, body: &T) -> reqwest::Result<reqwest::Response> {
            let url = format!("{}{}", self.base_url, path);
            let mut req = self.client.post(&url).json(body);

            if let Some(token) = &self.auth_token {
                req = req.bearer_auth(token);
            }

            req.send().await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_test_database() {
        let pool = create_test_database().await;
        assert!(pool.is_ok());
    }

    #[test]
    fn test_random_test_user() {
        let user1 = TestUser::random();
        let user2 = TestUser::random();

        // Should generate different usernames
        assert_ne!(user1.username, user2.username);
        assert_ne!(user1.email, user2.email);
    }
}
