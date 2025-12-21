// CI/CD Database Operations
#![allow(dead_code)]

use anyhow::Result;
use chrono::{DateTime, Utc};
use sqlx::SqlitePool;

use crate::integrations::cicd::types::*;
use crate::integrations::cicd;

// ============================================================================
// CI/CD Token Operations
// ============================================================================

/// Create a new CI/CD token
pub async fn create_cicd_token(
    pool: &SqlitePool,
    user_id: &str,
    request: &CreateCiCdTokenRequest,
) -> Result<CreateCiCdTokenResponse> {
    let id = uuid::Uuid::new_v4().to_string();
    let token = cicd::generate_token();
    let token_hash = cicd::hash_token(&token);
    let token_prefix = cicd::get_token_prefix(&token);
    let permissions_json = serde_json::to_string(&request.permissions)?;
    let now = Utc::now();
    let expires_at = request.expires_in_days.map(|days| {
        now + chrono::Duration::days(days as i64)
    });

    sqlx::query(
        r#"
        INSERT INTO cicd_tokens (id, user_id, name, token_hash, token_prefix, platform, permissions, expires_at, created_at, is_active)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
        "#,
    )
    .bind(&id)
    .bind(user_id)
    .bind(&request.name)
    .bind(&token_hash)
    .bind(&token_prefix)
    .bind(request.platform.as_str())
    .bind(&permissions_json)
    .bind(expires_at.map(|t| t.to_rfc3339()))
    .bind(now.to_rfc3339())
    .execute(pool)
    .await?;

    Ok(CreateCiCdTokenResponse {
        id,
        token, // Only returned once
        token_prefix,
        name: request.name.clone(),
        platform: request.platform.as_str().to_string(),
        permissions: request.permissions.clone(),
        expires_at,
        created_at: now,
    })
}

/// Get all CI/CD tokens for a user
pub async fn get_user_cicd_tokens(pool: &SqlitePool, user_id: &str) -> Result<Vec<CiCdTokenInfo>> {
    let tokens: Vec<CiCdToken> = sqlx::query_as(
        r#"
        SELECT id, user_id, name, token_hash, token_prefix, platform, permissions,
               last_used_at, expires_at, created_at, is_active
        FROM cicd_tokens
        WHERE user_id = ? AND is_active = 1
        ORDER BY created_at DESC
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    tokens.into_iter().map(|t| {
        let permissions: CiCdTokenPermissions = serde_json::from_str(&t.permissions)
            .unwrap_or_default();
        Ok(CiCdTokenInfo {
            id: t.id,
            name: t.name,
            token_prefix: t.token_prefix,
            platform: t.platform,
            permissions,
            last_used_at: t.last_used_at,
            expires_at: t.expires_at,
            created_at: t.created_at,
            is_active: t.is_active,
        })
    }).collect()
}

/// Get a CI/CD token by ID
pub async fn get_cicd_token_by_id(
    pool: &SqlitePool,
    token_id: &str,
    user_id: &str,
) -> Result<Option<CiCdTokenInfo>> {
    let token: Option<CiCdToken> = sqlx::query_as(
        r#"
        SELECT id, user_id, name, token_hash, token_prefix, platform, permissions,
               last_used_at, expires_at, created_at, is_active
        FROM cicd_tokens
        WHERE id = ? AND user_id = ?
        "#,
    )
    .bind(token_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await?;

    match token {
        Some(t) => {
            let permissions: CiCdTokenPermissions = serde_json::from_str(&t.permissions)
                .unwrap_or_default();
            Ok(Some(CiCdTokenInfo {
                id: t.id,
                name: t.name,
                token_prefix: t.token_prefix,
                platform: t.platform,
                permissions,
                last_used_at: t.last_used_at,
                expires_at: t.expires_at,
                created_at: t.created_at,
                is_active: t.is_active,
            }))
        }
        None => Ok(None),
    }
}

/// Validate a CI/CD token and return token info if valid
pub async fn validate_cicd_token(
    pool: &SqlitePool,
    token: &str,
) -> Result<Option<(CiCdToken, String)>> {
    let token_hash = cicd::hash_token(token);

    let result: Option<CiCdToken> = sqlx::query_as(
        r#"
        SELECT id, user_id, name, token_hash, token_prefix, platform, permissions,
               last_used_at, expires_at, created_at, is_active
        FROM cicd_tokens
        WHERE token_hash = ? AND is_active = 1
        "#,
    )
    .bind(&token_hash)
    .fetch_optional(pool)
    .await?;

    match result {
        Some(t) => {
            // Check if token is expired
            if let Some(expires_at) = &t.expires_at {
                if *expires_at < Utc::now() {
                    return Ok(None);
                }
            }

            // Update last_used_at
            sqlx::query("UPDATE cicd_tokens SET last_used_at = ? WHERE id = ?")
                .bind(Utc::now().to_rfc3339())
                .bind(&t.id)
                .execute(pool)
                .await?;

            let user_id = t.user_id.clone();
            Ok(Some((t, user_id)))
        }
        None => Ok(None),
    }
}

/// Revoke (delete) a CI/CD token
pub async fn delete_cicd_token(
    pool: &SqlitePool,
    token_id: &str,
    user_id: &str,
) -> Result<bool> {
    let result = sqlx::query(
        "UPDATE cicd_tokens SET is_active = 0 WHERE id = ? AND user_id = ?",
    )
    .bind(token_id)
    .bind(user_id)
    .execute(pool)
    .await?;

    Ok(result.rows_affected() > 0)
}

// ============================================================================
// CI/CD Run Operations
// ============================================================================

/// Create a new CI/CD run
pub async fn create_cicd_run(
    pool: &SqlitePool,
    token_id: &str,
    scan_id: &str,
    platform: &str,
    ci_ref: Option<&str>,
    ci_branch: Option<&str>,
    ci_url: Option<&str>,
    repository: Option<&str>,
) -> Result<CiCdRun> {
    let id = uuid::Uuid::new_v4().to_string();
    let now = Utc::now();

    sqlx::query(
        r#"
        INSERT INTO cicd_runs (id, token_id, scan_id, platform, ci_ref, ci_branch, ci_url, repository, status, started_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?)
        "#,
    )
    .bind(&id)
    .bind(token_id)
    .bind(scan_id)
    .bind(platform)
    .bind(ci_ref)
    .bind(ci_branch)
    .bind(ci_url)
    .bind(repository)
    .bind(now.to_rfc3339())
    .execute(pool)
    .await?;

    Ok(CiCdRun {
        id,
        token_id: token_id.to_string(),
        scan_id: scan_id.to_string(),
        platform: platform.to_string(),
        ci_ref: ci_ref.map(|s| s.to_string()),
        ci_branch: ci_branch.map(|s| s.to_string()),
        ci_url: ci_url.map(|s| s.to_string()),
        repository: repository.map(|s| s.to_string()),
        status: "pending".to_string(),
        quality_gate_passed: None,
        quality_gate_details: None,
        started_at: now,
        completed_at: None,
    })
}

/// Get a CI/CD run by ID
pub async fn get_cicd_run(pool: &SqlitePool, run_id: &str) -> Result<Option<CiCdRun>> {
    let run: Option<CiCdRun> = sqlx::query_as(
        r#"
        SELECT id, token_id, scan_id, platform, ci_ref, ci_branch, ci_url, repository,
               status, quality_gate_passed, quality_gate_details, started_at, completed_at
        FROM cicd_runs
        WHERE id = ?
        "#,
    )
    .bind(run_id)
    .fetch_optional(pool)
    .await?;

    Ok(run)
}

/// Get a CI/CD run by scan ID
pub async fn get_cicd_run_by_scan(pool: &SqlitePool, scan_id: &str) -> Result<Option<CiCdRun>> {
    let run: Option<CiCdRun> = sqlx::query_as(
        r#"
        SELECT id, token_id, scan_id, platform, ci_ref, ci_branch, ci_url, repository,
               status, quality_gate_passed, quality_gate_details, started_at, completed_at
        FROM cicd_runs
        WHERE scan_id = ?
        "#,
    )
    .bind(scan_id)
    .fetch_optional(pool)
    .await?;

    Ok(run)
}

/// Update CI/CD run status
pub async fn update_cicd_run_status(
    pool: &SqlitePool,
    run_id: &str,
    status: &str,
) -> Result<()> {
    sqlx::query("UPDATE cicd_runs SET status = ? WHERE id = ?")
        .bind(status)
        .bind(run_id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Complete a CI/CD run with quality gate result
pub async fn complete_cicd_run(
    pool: &SqlitePool,
    run_id: &str,
    quality_gate_passed: bool,
    quality_gate_details: Option<&str>,
) -> Result<()> {
    let now = Utc::now();

    sqlx::query(
        r#"
        UPDATE cicd_runs
        SET status = 'completed',
            quality_gate_passed = ?,
            quality_gate_details = ?,
            completed_at = ?
        WHERE id = ?
        "#,
    )
    .bind(quality_gate_passed)
    .bind(quality_gate_details)
    .bind(now.to_rfc3339())
    .bind(run_id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Fail a CI/CD run
pub async fn fail_cicd_run(
    pool: &SqlitePool,
    run_id: &str,
    error_details: Option<&str>,
) -> Result<()> {
    let now = Utc::now();

    sqlx::query(
        r#"
        UPDATE cicd_runs
        SET status = 'failed',
            quality_gate_passed = 0,
            quality_gate_details = ?,
            completed_at = ?
        WHERE id = ?
        "#,
    )
    .bind(error_details)
    .bind(now.to_rfc3339())
    .bind(run_id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Get recent CI/CD runs for a user
pub async fn get_user_cicd_runs(
    pool: &SqlitePool,
    user_id: &str,
    limit: i64,
) -> Result<Vec<CiCdRun>> {
    let runs: Vec<CiCdRun> = sqlx::query_as(
        r#"
        SELECT r.id, r.token_id, r.scan_id, r.platform, r.ci_ref, r.ci_branch, r.ci_url,
               r.repository, r.status, r.quality_gate_passed, r.quality_gate_details,
               r.started_at, r.completed_at
        FROM cicd_runs r
        INNER JOIN cicd_tokens t ON r.token_id = t.id
        WHERE t.user_id = ?
        ORDER BY r.started_at DESC
        LIMIT ?
        "#,
    )
    .bind(user_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    Ok(runs)
}

// ============================================================================
// Quality Gate Operations
// ============================================================================

/// Create a new quality gate
pub async fn create_quality_gate(
    pool: &SqlitePool,
    user_id: &str,
    request: &QualityGateRequest,
) -> Result<QualityGate> {
    let id = uuid::Uuid::new_v4().to_string();
    let now = Utc::now();

    // If this is set as default, unset any existing default for this user
    if request.is_default {
        sqlx::query("UPDATE quality_gates SET is_default = 0 WHERE user_id = ?")
            .bind(user_id)
            .execute(pool)
            .await?;
    }

    sqlx::query(
        r#"
        INSERT INTO quality_gates (id, user_id, name, fail_on_severity, max_vulnerabilities,
                                   max_critical, max_high, max_medium, max_low,
                                   fail_on_new_vulns, baseline_scan_id, is_default,
                                   created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(user_id)
    .bind(&request.name)
    .bind(request.fail_on_severity.as_str())
    .bind(request.max_vulnerabilities)
    .bind(request.max_critical)
    .bind(request.max_high)
    .bind(request.max_medium)
    .bind(request.max_low)
    .bind(request.fail_on_new_vulns)
    .bind(&request.baseline_scan_id)
    .bind(request.is_default)
    .bind(now.to_rfc3339())
    .bind(now.to_rfc3339())
    .execute(pool)
    .await?;

    Ok(QualityGate {
        id,
        user_id: user_id.to_string(),
        name: request.name.clone(),
        fail_on_severity: request.fail_on_severity.as_str().to_string(),
        max_vulnerabilities: request.max_vulnerabilities,
        max_critical: request.max_critical,
        max_high: request.max_high,
        max_medium: request.max_medium,
        max_low: request.max_low,
        fail_on_new_vulns: request.fail_on_new_vulns,
        baseline_scan_id: request.baseline_scan_id.clone(),
        is_default: request.is_default,
        created_at: now,
        updated_at: now,
    })
}

/// Get all quality gates for a user (including system defaults)
pub async fn get_user_quality_gates(pool: &SqlitePool, user_id: &str) -> Result<Vec<QualityGate>> {
    let gates: Vec<QualityGate> = sqlx::query_as(
        r#"
        SELECT id, user_id, name, fail_on_severity, max_vulnerabilities,
               max_critical, max_high, max_medium, max_low,
               fail_on_new_vulns, baseline_scan_id, is_default,
               created_at, updated_at
        FROM quality_gates
        WHERE user_id = ? OR user_id = 'system'
        ORDER BY is_default DESC, name ASC
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    Ok(gates)
}

/// Get a quality gate by ID
pub async fn get_quality_gate(pool: &SqlitePool, gate_id: &str) -> Result<Option<QualityGate>> {
    let gate: Option<QualityGate> = sqlx::query_as(
        r#"
        SELECT id, user_id, name, fail_on_severity, max_vulnerabilities,
               max_critical, max_high, max_medium, max_low,
               fail_on_new_vulns, baseline_scan_id, is_default,
               created_at, updated_at
        FROM quality_gates
        WHERE id = ?
        "#,
    )
    .bind(gate_id)
    .fetch_optional(pool)
    .await?;

    Ok(gate)
}

/// Get the default quality gate for a user
pub async fn get_default_quality_gate(pool: &SqlitePool, user_id: &str) -> Result<Option<QualityGate>> {
    // First try to find user's default, then fall back to system default
    let gate: Option<QualityGate> = sqlx::query_as(
        r#"
        SELECT id, user_id, name, fail_on_severity, max_vulnerabilities,
               max_critical, max_high, max_medium, max_low,
               fail_on_new_vulns, baseline_scan_id, is_default,
               created_at, updated_at
        FROM quality_gates
        WHERE (user_id = ? OR user_id = 'system') AND is_default = 1
        ORDER BY CASE WHEN user_id = ? THEN 0 ELSE 1 END
        LIMIT 1
        "#,
    )
    .bind(user_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await?;

    Ok(gate)
}

/// Update a quality gate
pub async fn update_quality_gate(
    pool: &SqlitePool,
    gate_id: &str,
    user_id: &str,
    request: &QualityGateRequest,
) -> Result<Option<QualityGate>> {
    let now = Utc::now();

    // If this is set as default, unset any existing default for this user
    if request.is_default {
        sqlx::query("UPDATE quality_gates SET is_default = 0 WHERE user_id = ? AND id != ?")
            .bind(user_id)
            .bind(gate_id)
            .execute(pool)
            .await?;
    }

    let result = sqlx::query(
        r#"
        UPDATE quality_gates
        SET name = ?,
            fail_on_severity = ?,
            max_vulnerabilities = ?,
            max_critical = ?,
            max_high = ?,
            max_medium = ?,
            max_low = ?,
            fail_on_new_vulns = ?,
            baseline_scan_id = ?,
            is_default = ?,
            updated_at = ?
        WHERE id = ? AND user_id = ?
        "#,
    )
    .bind(&request.name)
    .bind(request.fail_on_severity.as_str())
    .bind(request.max_vulnerabilities)
    .bind(request.max_critical)
    .bind(request.max_high)
    .bind(request.max_medium)
    .bind(request.max_low)
    .bind(request.fail_on_new_vulns)
    .bind(&request.baseline_scan_id)
    .bind(request.is_default)
    .bind(now.to_rfc3339())
    .bind(gate_id)
    .bind(user_id)
    .execute(pool)
    .await?;

    if result.rows_affected() == 0 {
        return Ok(None);
    }

    get_quality_gate(pool, gate_id).await
}

/// Delete a quality gate
pub async fn delete_quality_gate(
    pool: &SqlitePool,
    gate_id: &str,
    user_id: &str,
) -> Result<bool> {
    // Don't allow deleting system quality gates
    let result = sqlx::query(
        "DELETE FROM quality_gates WHERE id = ? AND user_id = ? AND user_id != 'system'",
    )
    .bind(gate_id)
    .bind(user_id)
    .execute(pool)
    .await?;

    Ok(result.rows_affected() > 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_token_lifecycle() {
        // This would require a test database setup
        // For now, we just ensure the code compiles
    }
}
