use anyhow::Result;
use sqlx::SqlitePool;
use uuid::Uuid;
use chrono::Utc;

use super::types::{Hypothesis, CreateHypothesisRequest, UpdateHypothesisRequest, HypothesisStatus};

/// Hypothesis template
#[derive(Debug, Clone)]
pub struct HypothesisTemplate {
    pub name: String,
    pub description: String,
    pub query_template: String,
    pub expected_outcome: String,
    pub category: String,
}

/// Get built-in hypothesis templates
pub fn get_hypothesis_templates() -> Vec<HypothesisTemplate> {
    vec![
        HypothesisTemplate {
            name: "Unusual Login Times".to_string(),
            description: "Detect logins occurring outside normal business hours".to_string(),
            query_template: "source:auth AND event:login AND time:(NOT [08:00 TO 18:00])".to_string(),
            expected_outcome: "Identify potential compromised accounts or insider threats".to_string(),
            category: "Authentication".to_string(),
        },
        HypothesisTemplate {
            name: "Privilege Escalation".to_string(),
            description: "Detect users gaining elevated privileges".to_string(),
            query_template: "source:security AND event:privilege_change AND new_role:(admin OR root)".to_string(),
            expected_outcome: "Identify unauthorized privilege escalation attempts".to_string(),
            category: "Authorization".to_string(),
        },
        HypothesisTemplate {
            name: "Data Exfiltration".to_string(),
            description: "Detect large data transfers to external destinations".to_string(),
            query_template: "source:network AND bytes_out:>10000000 AND destination:external".to_string(),
            expected_outcome: "Identify potential data theft".to_string(),
            category: "Data Loss".to_string(),
        },
        HypothesisTemplate {
            name: "Lateral Movement".to_string(),
            description: "Detect unusual network connections between internal hosts".to_string(),
            query_template: "source:network AND src:internal AND dst:internal AND port:(445 OR 3389 OR 22)".to_string(),
            expected_outcome: "Identify attackers moving through the network".to_string(),
            category: "Network".to_string(),
        },
        HypothesisTemplate {
            name: "Command and Control".to_string(),
            description: "Detect beaconing behavior to external IPs".to_string(),
            query_template: "source:network AND destination:external AND connection_count:>100 AND interval:regular".to_string(),
            expected_outcome: "Identify C2 communication channels".to_string(),
            category: "Malware".to_string(),
        },
    ]
}

/// Create a new hypothesis
pub async fn create_hypothesis(
    pool: &SqlitePool,
    request: CreateHypothesisRequest,
    user_id: Option<String>,
) -> Result<Hypothesis> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();

    sqlx::query(
        "INSERT INTO hunt_hypotheses (id, name, description, query, expected_outcome, status, created_by, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
    )
    .bind(&id)
    .bind(&request.name)
    .bind(&request.description)
    .bind(&request.query)
    .bind(&request.expected_outcome)
    .bind(HypothesisStatus::Draft.to_string())
    .bind(&user_id)
    .bind(now.to_rfc3339())
    .bind(now.to_rfc3339())
    .execute(pool)
    .await?;

    Ok(Hypothesis {
        id,
        name: request.name,
        description: request.description,
        query: request.query,
        expected_outcome: request.expected_outcome,
        status: HypothesisStatus::Draft,
        created_by: user_id,
        created_at: now,
        updated_at: now,
    })
}

/// Get hypothesis by ID
#[allow(dead_code)]
pub async fn get_hypothesis(pool: &SqlitePool, id: &str) -> Result<Option<Hypothesis>> {
    let row = sqlx::query_as::<_, (String, String, Option<String>, String, Option<String>, String, Option<String>, String, String)>(
        "SELECT id, name, description, query, expected_outcome, status, created_by, created_at, updated_at
         FROM hunt_hypotheses
         WHERE id = ?"
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    if let Some((id, name, description, query, expected_outcome, status, created_by, created_at, updated_at)) = row {
        Ok(Some(Hypothesis {
            id,
            name,
            description,
            query,
            expected_outcome,
            status: status.parse()?,
            created_by,
            created_at: created_at.parse()?,
            updated_at: updated_at.parse()?,
        }))
    } else {
        Ok(None)
    }
}

/// List all hypotheses
#[allow(dead_code)]
pub async fn list_hypotheses(pool: &SqlitePool) -> Result<Vec<Hypothesis>> {
    let rows = sqlx::query_as::<_, (String, String, Option<String>, String, Option<String>, String, Option<String>, String, String)>(
        "SELECT id, name, description, query, expected_outcome, status, created_by, created_at, updated_at
         FROM hunt_hypotheses
         ORDER BY created_at DESC"
    )
    .fetch_all(pool)
    .await?;

    let mut hypotheses = Vec::new();
    for (id, name, description, query, expected_outcome, status, created_by, created_at, updated_at) in rows {
        hypotheses.push(Hypothesis {
            id,
            name,
            description,
            query,
            expected_outcome,
            status: status.parse()?,
            created_by,
            created_at: created_at.parse()?,
            updated_at: updated_at.parse()?,
        });
    }

    Ok(hypotheses)
}

/// Update hypothesis
#[allow(dead_code)]
pub async fn update_hypothesis(
    pool: &SqlitePool,
    id: &str,
    request: UpdateHypothesisRequest,
) -> Result<Option<Hypothesis>> {
    let now = Utc::now();

    // Build dynamic update query
    let mut updates = Vec::new();
    let mut params: Vec<String> = Vec::new();

    if let Some(name) = &request.name {
        updates.push("name = ?");
        params.push(name.clone());
    }
    if let Some(description) = &request.description {
        updates.push("description = ?");
        params.push(description.clone());
    }
    if let Some(query) = &request.query {
        updates.push("query = ?");
        params.push(query.clone());
    }
    if let Some(expected_outcome) = &request.expected_outcome {
        updates.push("expected_outcome = ?");
        params.push(expected_outcome.clone());
    }
    if let Some(status) = &request.status {
        updates.push("status = ?");
        params.push(status.to_string());
    }

    if updates.is_empty() {
        return get_hypothesis(pool, id).await;
    }

    updates.push("updated_at = ?");
    params.push(now.to_rfc3339());

    let query_str = format!(
        "UPDATE hunt_hypotheses SET {} WHERE id = ?",
        updates.join(", ")
    );

    let mut query = sqlx::query(&query_str);
    for param in params {
        query = query.bind(param);
    }
    query = query.bind(id);

    let result = query.execute(pool).await?;

    if result.rows_affected() == 0 {
        Ok(None)
    } else {
        get_hypothesis(pool, id).await
    }
}

/// Delete hypothesis
#[allow(dead_code)]
pub async fn delete_hypothesis(pool: &SqlitePool, id: &str) -> Result<bool> {
    let result = sqlx::query("DELETE FROM hunt_hypotheses WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;

    Ok(result.rows_affected() > 0)
}

/// Validate hypothesis based on execution results
#[allow(dead_code)]
pub async fn validate_hypothesis(
    pool: &SqlitePool,
    hypothesis_id: &str,
    findings_count: i64,
    false_positives: i64,
) -> Result<f64> {
    // Calculate validation score
    let total_results = findings_count + false_positives;
    let score = if total_results > 0 {
        findings_count as f64 / total_results as f64
    } else {
        0.0
    };

    // Update status based on score
    let status = if score >= 0.7 {
        HypothesisStatus::Validated
    } else if score < 0.3 {
        HypothesisStatus::Invalidated
    } else {
        HypothesisStatus::Active
    };

    sqlx::query("UPDATE hunt_hypotheses SET status = ?, updated_at = ? WHERE id = ?")
        .bind(status.to_string())
        .bind(Utc::now().to_rfc3339())
        .bind(hypothesis_id)
        .execute(pool)
        .await?;

    Ok(score)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hypothesis_templates() {
        let templates = get_hypothesis_templates();
        assert!(!templates.is_empty());
        assert!(templates.iter().any(|t| t.category == "Authentication"));
    }
}
