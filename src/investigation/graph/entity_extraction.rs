use crate::investigation::types::GraphEntity;
use anyhow::Result;
use chrono::Utc;
use regex::Regex;
use uuid::Uuid;

/// Automatically extract entities from text
pub fn extract_entities_from_text(
    investigation_id: &str,
    text: &str,
) -> Result<Vec<GraphEntity>> {
    let mut entities = Vec::new();

    // Extract IPs
    entities.extend(extract_ips(investigation_id, text)?);

    // Extract domains
    entities.extend(extract_domains(investigation_id, text)?);

    // Extract file hashes
    entities.extend(extract_hashes(investigation_id, text)?);

    // Extract email addresses
    entities.extend(extract_emails(investigation_id, text)?);

    Ok(entities)
}

fn extract_ips(investigation_id: &str, text: &str) -> Result<Vec<GraphEntity>> {
    let ip_regex = Regex::new(
        r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
    )?;

    let entities: Vec<GraphEntity> = ip_regex.find_iter(text)
        .map(|m| GraphEntity {
            id: Uuid::new_v4().to_string(),
            investigation_id: investigation_id.to_string(),
            entity_type: "IP".to_string(),
            entity_value: m.as_str().to_string(),
            properties: None,
            risk_score: None,
            first_seen: Utc::now(),
            last_seen: Utc::now(),
            created_at: Utc::now(),
        })
        .collect();

    Ok(entities)
}

fn extract_domains(investigation_id: &str, text: &str) -> Result<Vec<GraphEntity>> {
    let domain_regex = Regex::new(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
    )?;

    let entities: Vec<GraphEntity> = domain_regex.find_iter(text)
        .map(|m| GraphEntity {
            id: Uuid::new_v4().to_string(),
            investigation_id: investigation_id.to_string(),
            entity_type: "Domain".to_string(),
            entity_value: m.as_str().to_string(),
            properties: None,
            risk_score: None,
            first_seen: Utc::now(),
            last_seen: Utc::now(),
            created_at: Utc::now(),
        })
        .collect();

    Ok(entities)
}

fn extract_hashes(investigation_id: &str, text: &str) -> Result<Vec<GraphEntity>> {
    let mut entities = Vec::new();

    // MD5
    let md5_regex = Regex::new(r"\b[a-fA-F0-9]{32}\b")?;
    for m in md5_regex.find_iter(text) {
        entities.push(GraphEntity {
            id: Uuid::new_v4().to_string(),
            investigation_id: investigation_id.to_string(),
            entity_type: "FileHash".to_string(),
            entity_value: m.as_str().to_string(),
            properties: Some(serde_json::json!({"hash_type": "MD5"}).to_string()),
            risk_score: None,
            first_seen: Utc::now(),
            last_seen: Utc::now(),
            created_at: Utc::now(),
        });
    }

    // SHA256
    let sha256_regex = Regex::new(r"\b[a-fA-F0-9]{64}\b")?;
    for m in sha256_regex.find_iter(text) {
        entities.push(GraphEntity {
            id: Uuid::new_v4().to_string(),
            investigation_id: investigation_id.to_string(),
            entity_type: "FileHash".to_string(),
            entity_value: m.as_str().to_string(),
            properties: Some(serde_json::json!({"hash_type": "SHA256"}).to_string()),
            risk_score: None,
            first_seen: Utc::now(),
            last_seen: Utc::now(),
            created_at: Utc::now(),
        });
    }

    Ok(entities)
}

fn extract_emails(investigation_id: &str, text: &str) -> Result<Vec<GraphEntity>> {
    let email_regex = Regex::new(
        r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"
    )?;

    let entities: Vec<GraphEntity> = email_regex.find_iter(text)
        .map(|m| GraphEntity {
            id: Uuid::new_v4().to_string(),
            investigation_id: investigation_id.to_string(),
            entity_type: "Email".to_string(),
            entity_value: m.as_str().to_string(),
            properties: None,
            risk_score: None,
            first_seen: Utc::now(),
            last_seen: Utc::now(),
            created_at: Utc::now(),
        })
        .collect();

    Ok(entities)
}

/// Calculate centrality scores for entities
pub fn calculate_centrality(entities: &[GraphEntity]) -> Result<Vec<(String, f64)>> {
    // Simple degree centrality based on entity frequency
    let mut centrality = Vec::new();

    for entity in entities {
        // In a real implementation, this would calculate based on graph connections
        centrality.push((entity.id.clone(), 1.0));
    }

    Ok(centrality)
}
