//! Honeytoken system (Sprint 7)

use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};
use anyhow::Result;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Honeytoken {
    pub id: String,
    pub token_type: HoneytokenType,
    pub value: String,
    pub description: String,
    pub created_at: DateTime<Utc>,
    pub accessed_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HoneytokenType {
    FakeCredential,
    FakeApiKey,
    FakeDocument,
    FakeDatabase,
    CanaryFile,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HoneytokenAccess {
    pub id: String,
    pub honeytoken_id: String,
    pub accessor_ip: String,
    pub accessor_user: Option<String>,
    pub timestamp: DateTime<Utc>,
    pub access_method: String,
}

pub async fn create_honeytoken(token_type: HoneytokenType, value: &str, description: &str) -> Result<Honeytoken> {
    Ok(Honeytoken {
        id: uuid::Uuid::new_v4().to_string(),
        token_type,
        value: value.to_string(),
        description: description.to_string(),
        created_at: Utc::now(),
        accessed_count: 0,
    })
}

pub async fn log_access(honeytoken_id: &str, accessor_ip: &str, method: &str) -> Result<HoneytokenAccess> {
    Ok(HoneytokenAccess {
        id: uuid::Uuid::new_v4().to_string(),
        honeytoken_id: honeytoken_id.to_string(),
        accessor_ip: accessor_ip.to_string(),
        accessor_user: None,
        timestamp: Utc::now(),
        access_method: method.to_string(),
    })
}
