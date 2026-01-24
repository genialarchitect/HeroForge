//! Honeytoken system for detecting unauthorized access
//!
//! Generates and monitors fake credentials, API keys, and canary files
//! that trigger alerts when accessed. Supports:
//! - Fake AWS credentials (access key + secret key pairs)
//! - Fake API keys (various formats)
//! - Fake database connection strings
//! - Canary file tokens (detectable document/config files)
//! - Custom credential tokens

use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};
use anyhow::Result;
use rand::Rng;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use log::{info, warn};

/// Global honeytoken state
static HONEYTOKEN_STATE: once_cell::sync::Lazy<Arc<RwLock<HoneytokenState>>> =
    once_cell::sync::Lazy::new(|| Arc::new(RwLock::new(HoneytokenState::default())));

#[derive(Default)]
struct HoneytokenState {
    tokens: HashMap<String, Honeytoken>,
    accesses: Vec<HoneytokenAccess>,
    alert_callbacks: Vec<AlertCallback>,
}

impl std::fmt::Debug for HoneytokenState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HoneytokenState")
            .field("tokens", &self.tokens)
            .field("accesses", &self.accesses)
            .field("alert_callbacks", &format!("[{} callbacks]", self.alert_callbacks.len()))
            .finish()
    }
}

type AlertCallback = Arc<dyn Fn(&HoneytokenAccess) + Send + Sync>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Honeytoken {
    pub id: String,
    pub token_type: HoneytokenType,
    pub value: String,
    pub description: String,
    pub metadata: HashMap<String, String>,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub accessed_count: u32,
    pub last_accessed: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum HoneytokenType {
    AwsCredential,
    ApiKey,
    DatabaseCredential,
    CanaryFile,
    GitHubToken,
    SlackToken,
    JwtSecret,
    CustomCredential,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HoneytokenAccess {
    pub id: String,
    pub honeytoken_id: String,
    pub honeytoken_type: HoneytokenType,
    pub accessor_ip: String,
    pub accessor_user: Option<String>,
    pub timestamp: DateTime<Utc>,
    pub access_method: String,
    pub context: HashMap<String, String>,
    pub severity: AccessSeverity,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AccessSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Generate a new honeytoken of the specified type
pub async fn create_honeytoken(token_type: HoneytokenType, description: &str) -> Result<Honeytoken> {
    let (value, metadata) = generate_token_value(&token_type);

    let token = Honeytoken {
        id: uuid::Uuid::new_v4().to_string(),
        token_type,
        value,
        description: description.to_string(),
        metadata,
        is_active: true,
        created_at: Utc::now(),
        accessed_count: 0,
        last_accessed: None,
    };

    let mut state = HONEYTOKEN_STATE.write().await;
    state.tokens.insert(token.id.clone(), token.clone());

    info!("Created honeytoken: {} ({})", token.id, description);
    Ok(token)
}

/// Generate a honeytoken with a specific value (for embedding in known locations)
pub async fn create_honeytoken_with_value(
    token_type: HoneytokenType,
    value: &str,
    description: &str,
) -> Result<Honeytoken> {
    let metadata = match &token_type {
        HoneytokenType::AwsCredential => {
            let mut m = HashMap::new();
            m.insert("format".to_string(), "aws_keypair".to_string());
            m
        }
        _ => HashMap::new(),
    };

    let token = Honeytoken {
        id: uuid::Uuid::new_v4().to_string(),
        token_type,
        value: value.to_string(),
        description: description.to_string(),
        metadata,
        is_active: true,
        created_at: Utc::now(),
        accessed_count: 0,
        last_accessed: None,
    };

    let mut state = HONEYTOKEN_STATE.write().await;
    state.tokens.insert(token.id.clone(), token.clone());

    Ok(token)
}

/// Check if a given credential/token value matches any registered honeytoken
pub async fn check_token_access(
    value: &str,
    accessor_ip: &str,
    access_method: &str,
    context: HashMap<String, String>,
) -> Option<HoneytokenAccess> {
    let mut state = HONEYTOKEN_STATE.write().await;

    // Search for matching token
    let matching_token = state.tokens.values_mut()
        .find(|t| t.is_active && t.value == value)?;

    // Record access
    matching_token.accessed_count += 1;
    matching_token.last_accessed = Some(Utc::now());

    let severity = determine_severity(access_method, matching_token.accessed_count);

    let access = HoneytokenAccess {
        id: uuid::Uuid::new_v4().to_string(),
        honeytoken_id: matching_token.id.clone(),
        honeytoken_type: matching_token.token_type.clone(),
        accessor_ip: accessor_ip.to_string(),
        accessor_user: context.get("user").cloned(),
        timestamp: Utc::now(),
        access_method: access_method.to_string(),
        context,
        severity,
    };

    warn!(
        "HONEYTOKEN TRIGGERED: id={} type={:?} by {} via {} (count: {})",
        access.honeytoken_id, access.honeytoken_type,
        accessor_ip, access_method, matching_token.accessed_count
    );

    state.accesses.push(access.clone());

    // Fire alert callbacks
    for callback in &state.alert_callbacks {
        callback(&access);
    }

    Some(access)
}

/// Log an access to a specific honeytoken by ID
pub async fn log_access(
    honeytoken_id: &str,
    accessor_ip: &str,
    method: &str,
) -> Result<HoneytokenAccess> {
    let mut state = HONEYTOKEN_STATE.write().await;

    let token = state.tokens.get_mut(honeytoken_id)
        .ok_or_else(|| anyhow::anyhow!("Honeytoken not found: {}", honeytoken_id))?;

    token.accessed_count += 1;
    token.last_accessed = Some(Utc::now());

    let severity = determine_severity(method, token.accessed_count);

    let access = HoneytokenAccess {
        id: uuid::Uuid::new_v4().to_string(),
        honeytoken_id: honeytoken_id.to_string(),
        honeytoken_type: token.token_type.clone(),
        accessor_ip: accessor_ip.to_string(),
        accessor_user: None,
        timestamp: Utc::now(),
        access_method: method.to_string(),
        context: HashMap::new(),
        severity,
    };

    warn!(
        "HONEYTOKEN ACCESS: id={} type={:?} by {} via {}",
        honeytoken_id, token.token_type, accessor_ip, method
    );

    state.accesses.push(access.clone());

    for callback in &state.alert_callbacks {
        callback(&access);
    }

    Ok(access)
}

/// Register an alert callback for honeytoken access events
pub async fn register_alert_callback<F>(callback: F)
where
    F: Fn(&HoneytokenAccess) + Send + Sync + 'static,
{
    let mut state = HONEYTOKEN_STATE.write().await;
    state.alert_callbacks.push(Arc::new(callback));
}

/// Get all access events for a honeytoken
pub async fn get_accesses(honeytoken_id: &str) -> Vec<HoneytokenAccess> {
    let state = HONEYTOKEN_STATE.read().await;
    state.accesses.iter()
        .filter(|a| a.honeytoken_id == honeytoken_id)
        .cloned()
        .collect()
}

/// Get all recent access events
pub async fn get_recent_accesses(limit: usize) -> Vec<HoneytokenAccess> {
    let state = HONEYTOKEN_STATE.read().await;
    let mut accesses: Vec<_> = state.accesses.iter().cloned().collect();
    accesses.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
    accesses.truncate(limit);
    accesses
}

/// List all honeytokens
pub async fn list_honeytokens() -> Vec<Honeytoken> {
    let state = HONEYTOKEN_STATE.read().await;
    state.tokens.values().cloned().collect()
}

/// Get a specific honeytoken
pub async fn get_honeytoken(id: &str) -> Option<Honeytoken> {
    let state = HONEYTOKEN_STATE.read().await;
    state.tokens.get(id).cloned()
}

/// Deactivate a honeytoken
pub async fn deactivate_honeytoken(id: &str) -> Result<()> {
    let mut state = HONEYTOKEN_STATE.write().await;
    let token = state.tokens.get_mut(id)
        .ok_or_else(|| anyhow::anyhow!("Honeytoken not found: {}", id))?;
    token.is_active = false;
    info!("Deactivated honeytoken: {}", id);
    Ok(())
}

/// Generate a canary file that can be placed in the filesystem.
/// Returns the file content that should be written to disk.
pub fn generate_canary_file(token_id: &str, file_type: &str) -> String {
    match file_type {
        "env" => format!(
            r#"# Production Environment Configuration
# DO NOT COMMIT - Contains sensitive credentials
DB_HOST=prod-db-01.internal.corp
DB_USER=admin
DB_PASSWORD={}
AWS_ACCESS_KEY_ID={}
AWS_SECRET_ACCESS_KEY={}
API_KEY={}
"#,
            generate_fake_password(),
            generate_fake_aws_key_id(),
            generate_fake_aws_secret(),
            token_id, // Use token_id as the API key for detection
        ),
        "credentials" | "json" => format!(
            r#"{{
  "database": {{
    "host": "prod-rds.us-east-1.rds.amazonaws.com",
    "username": "db_admin",
    "password": "{}"
  }},
  "aws": {{
    "access_key_id": "{}",
    "secret_access_key": "{}"
  }},
  "api_token": "{}"
}}"#,
            generate_fake_password(),
            generate_fake_aws_key_id(),
            generate_fake_aws_secret(),
            token_id,
        ),
        "ssh_key" => format!(
            "-----BEGIN OPENSSH PRIVATE KEY-----\n{}\n{}\n{}\n-----END OPENSSH PRIVATE KEY-----\n# Canary: {}\n",
            generate_random_base64(70),
            generate_random_base64(70),
            generate_random_base64(40),
            token_id,
        ),
        _ => format!("# Canary token: {}\nSECRET={}\n", token_id, generate_fake_password()),
    }
}

// =============================================================================
// TOKEN GENERATION
// =============================================================================

fn generate_token_value(token_type: &HoneytokenType) -> (String, HashMap<String, String>) {
    let mut metadata = HashMap::new();

    let value = match token_type {
        HoneytokenType::AwsCredential => {
            let key_id = generate_fake_aws_key_id();
            let secret = generate_fake_aws_secret();
            metadata.insert("access_key_id".to_string(), key_id.clone());
            metadata.insert("secret_access_key".to_string(), secret.clone());
            format!("{}:{}", key_id, secret)
        }
        HoneytokenType::ApiKey => {
            let key = generate_fake_api_key();
            metadata.insert("format".to_string(), "bearer".to_string());
            key
        }
        HoneytokenType::DatabaseCredential => {
            let user = "db_admin";
            let pass = generate_fake_password();
            let host = "prod-db-01.internal.corp";
            metadata.insert("username".to_string(), user.to_string());
            metadata.insert("host".to_string(), host.to_string());
            format!("postgresql://{}:{}@{}/production", user, pass, host)
        }
        HoneytokenType::CanaryFile => {
            let filename = format!("credentials_{}.json", &uuid::Uuid::new_v4().to_string()[..8]);
            metadata.insert("filename".to_string(), filename.clone());
            filename
        }
        HoneytokenType::GitHubToken => {
            let token = generate_fake_github_token();
            metadata.insert("scope".to_string(), "repo,admin:org".to_string());
            token
        }
        HoneytokenType::SlackToken => {
            let token = generate_fake_slack_token();
            metadata.insert("workspace".to_string(), "internal-corp".to_string());
            token
        }
        HoneytokenType::JwtSecret => {
            let secret = generate_random_hex(64);
            metadata.insert("algorithm".to_string(), "HS256".to_string());
            secret
        }
        HoneytokenType::CustomCredential => {
            let cred = generate_fake_password();
            metadata.insert("format".to_string(), "custom".to_string());
            cred
        }
    };

    (value, metadata)
}

fn generate_fake_aws_key_id() -> String {
    let mut rng = rand::thread_rng();
    let suffix: String = (0..16)
        .map(|_| {
            let idx = rng.gen_range(0..36);
            if idx < 10 { (b'0' + idx) as char } else { (b'A' + idx - 10) as char }
        })
        .collect();
    format!("AKIA{}", suffix)
}

fn generate_fake_aws_secret() -> String {
    generate_random_base64(40)
}

fn generate_fake_api_key() -> String {
    let mut rng = rand::thread_rng();
    let prefix = ["sk-", "pk_live_", "api_", "key_"][rng.gen_range(0..4)];
    format!("{}{}", prefix, generate_random_hex(32))
}

fn generate_fake_github_token() -> String {
    format!("ghp_{}", generate_random_alnum(36))
}

fn generate_fake_slack_token() -> String {
    format!("xoxb-{}-{}-{}",
        generate_random_digits(12),
        generate_random_digits(12),
        generate_random_alnum(24),
    )
}

fn generate_fake_password() -> String {
    let mut rng = rand::thread_rng();
    let length = rng.gen_range(16..24);
    let charset = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*";
    (0..length)
        .map(|_| charset[rng.gen_range(0..charset.len())] as char)
        .collect()
}

fn generate_random_hex(len: usize) -> String {
    let mut rng = rand::thread_rng();
    (0..len)
        .map(|_| format!("{:x}", rng.gen_range(0u8..16)))
        .collect()
}

fn generate_random_base64(len: usize) -> String {
    let mut rng = rand::thread_rng();
    let charset = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    (0..len)
        .map(|_| charset[rng.gen_range(0..charset.len())] as char)
        .collect()
}

fn generate_random_alnum(len: usize) -> String {
    let mut rng = rand::thread_rng();
    let charset = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    (0..len)
        .map(|_| charset[rng.gen_range(0..charset.len())] as char)
        .collect()
}

fn generate_random_digits(len: usize) -> String {
    let mut rng = rand::thread_rng();
    (0..len)
        .map(|_| (b'0' + rng.gen_range(0u8..10)) as char)
        .collect()
}

fn determine_severity(access_method: &str, access_count: u32) -> AccessSeverity {
    let method_lower = access_method.to_lowercase();

    // Repeated access is always escalated
    if access_count > 5 {
        return AccessSeverity::Critical;
    }

    // Severity based on access method
    if method_lower.contains("api_call") || method_lower.contains("authenticate") {
        AccessSeverity::Critical
    } else if method_lower.contains("network") || method_lower.contains("external") {
        AccessSeverity::High
    } else if method_lower.contains("file_read") || method_lower.contains("env_access") {
        AccessSeverity::Medium
    } else if access_count > 2 {
        AccessSeverity::High
    } else {
        AccessSeverity::Medium
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_aws_honeytoken() {
        let token = create_honeytoken(HoneytokenType::AwsCredential, "Test AWS key").await.unwrap();
        assert_eq!(token.token_type, HoneytokenType::AwsCredential);
        assert!(token.value.contains("AKIA"));
        assert!(token.metadata.contains_key("access_key_id"));
        assert!(token.metadata.contains_key("secret_access_key"));
    }

    #[tokio::test]
    async fn test_create_api_key_honeytoken() {
        let token = create_honeytoken(HoneytokenType::ApiKey, "Test API key").await.unwrap();
        assert_eq!(token.token_type, HoneytokenType::ApiKey);
        assert!(!token.value.is_empty());
    }

    #[tokio::test]
    async fn test_create_github_token() {
        let token = create_honeytoken(HoneytokenType::GitHubToken, "GitHub PAT").await.unwrap();
        assert!(token.value.starts_with("ghp_"));
    }

    #[tokio::test]
    async fn test_access_detection() {
        let token = create_honeytoken(HoneytokenType::ApiKey, "Detect test").await.unwrap();
        let token_value = token.value.clone();

        let access = check_token_access(
            &token_value,
            "192.168.1.100",
            "api_call",
            HashMap::new(),
        ).await;

        assert!(access.is_some());
        let access = access.unwrap();
        assert_eq!(access.severity, AccessSeverity::Critical);
        assert_eq!(access.accessor_ip, "192.168.1.100");
    }

    #[tokio::test]
    async fn test_no_false_positive() {
        let result = check_token_access(
            "not-a-real-token-value",
            "10.0.0.1",
            "test",
            HashMap::new(),
        ).await;

        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_canary_file_generation() {
        let content = generate_canary_file("test-token-id", "env");
        assert!(content.contains("AWS_ACCESS_KEY_ID"));
        assert!(content.contains("test-token-id"));
    }

    #[tokio::test]
    async fn test_log_access() {
        let token = create_honeytoken(HoneytokenType::DatabaseCredential, "DB creds").await.unwrap();

        let access = log_access(&token.id, "10.0.0.50", "network_probe").await.unwrap();
        assert_eq!(access.honeytoken_id, token.id);

        let updated = get_honeytoken(&token.id).await.unwrap();
        assert_eq!(updated.accessed_count, 1);
    }

    #[tokio::test]
    async fn test_severity_escalation() {
        assert_eq!(determine_severity("file_read", 1), AccessSeverity::Medium);
        assert_eq!(determine_severity("api_call", 1), AccessSeverity::Critical);
        assert_eq!(determine_severity("file_read", 6), AccessSeverity::Critical);
    }
}
