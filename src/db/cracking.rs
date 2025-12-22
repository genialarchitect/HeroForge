//! Database operations for password cracking module

use anyhow::Result;
use chrono::{DateTime, Utc};
use sqlx::sqlite::SqlitePool;

use crate::cracking::types::{
    CrackingJob, CrackingJobStatus, CrackerType, CrackingStats,
    Wordlist, RuleFile,
};

// ============================================================================
// Cracking Jobs
// ============================================================================

/// Create a new cracking job
pub async fn create_cracking_job(
    pool: &SqlitePool,
    id: &str,
    user_id: &str,
    name: Option<&str>,
    hash_type: i32,
    cracker_type: CrackerType,
    hashes_json: &str,
    config_json: &str,
    source_campaign_id: Option<&str>,
    customer_id: Option<&str>,
    engagement_id: Option<&str>,
) -> Result<CrackingJob> {
    let now = Utc::now();
    let cracker_str = match cracker_type {
        CrackerType::Hashcat => "hashcat",
        CrackerType::John => "john",
    };

    sqlx::query(
        r#"
        INSERT INTO cracking_jobs (
            id, user_id, name, status, hash_type, cracker_type,
            hashes_json, config_json, source_campaign_id, customer_id,
            engagement_id, created_at
        )
        VALUES (?1, ?2, ?3, 'pending', ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
        "#
    )
    .bind(id)
    .bind(user_id)
    .bind(name)
    .bind(hash_type)
    .bind(cracker_str)
    .bind(hashes_json)
    .bind(config_json)
    .bind(source_campaign_id)
    .bind(customer_id)
    .bind(engagement_id)
    .bind(now.to_rfc3339())
    .execute(pool)
    .await?;

    get_cracking_job(pool, id).await
}

/// Get a cracking job by ID
pub async fn get_cracking_job(pool: &SqlitePool, id: &str) -> Result<CrackingJob> {
    let row = sqlx::query_as::<_, CrackingJobRow>(
        r#"
        SELECT id, user_id, name, status, hash_type, cracker_type,
               hashes_json, config_json, progress_json, results_json,
               error_message, source_campaign_id, customer_id, engagement_id,
               created_at, started_at, completed_at
        FROM cracking_jobs
        WHERE id = ?1
        "#
    )
    .bind(id)
    .fetch_one(pool)
    .await?;

    Ok(row.into())
}

/// Get all cracking jobs for a user
pub async fn get_user_cracking_jobs(
    pool: &SqlitePool,
    user_id: &str,
    limit: Option<i64>,
    offset: Option<i64>,
) -> Result<Vec<CrackingJob>> {
    let limit = limit.unwrap_or(100);
    let offset = offset.unwrap_or(0);

    let rows = sqlx::query_as::<_, CrackingJobRow>(
        r#"
        SELECT id, user_id, name, status, hash_type, cracker_type,
               hashes_json, config_json, progress_json, results_json,
               error_message, source_campaign_id, customer_id, engagement_id,
               created_at, started_at, completed_at
        FROM cracking_jobs
        WHERE user_id = ?1
        ORDER BY created_at DESC
        LIMIT ?2 OFFSET ?3
        "#
    )
    .bind(user_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(|r| r.into()).collect())
}

/// Get running cracking jobs
pub async fn get_running_jobs(pool: &SqlitePool) -> Result<Vec<CrackingJob>> {
    let rows = sqlx::query_as::<_, CrackingJobRow>(
        r#"
        SELECT id, user_id, name, status, hash_type, cracker_type,
               hashes_json, config_json, progress_json, results_json,
               error_message, source_campaign_id, customer_id, engagement_id,
               created_at, started_at, completed_at
        FROM cracking_jobs
        WHERE status = 'running'
        ORDER BY started_at ASC
        "#
    )
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(|r| r.into()).collect())
}

/// Update job status
pub async fn update_job_status(
    pool: &SqlitePool,
    id: &str,
    status: CrackingJobStatus,
    error_message: Option<&str>,
) -> Result<()> {
    let status_str = match status {
        CrackingJobStatus::Pending => "pending",
        CrackingJobStatus::Running => "running",
        CrackingJobStatus::Completed => "completed",
        CrackingJobStatus::Failed => "failed",
        CrackingJobStatus::Cancelled => "cancelled",
        CrackingJobStatus::Paused => "paused",
    };

    let now = Utc::now();

    match status {
        CrackingJobStatus::Running => {
            sqlx::query(
                "UPDATE cracking_jobs SET status = ?1, started_at = ?2 WHERE id = ?3"
            )
            .bind(status_str)
            .bind(now.to_rfc3339())
            .bind(id)
            .execute(pool)
            .await?;
        }
        CrackingJobStatus::Completed | CrackingJobStatus::Failed | CrackingJobStatus::Cancelled => {
            sqlx::query(
                "UPDATE cracking_jobs SET status = ?1, completed_at = ?2, error_message = ?3 WHERE id = ?4"
            )
            .bind(status_str)
            .bind(now.to_rfc3339())
            .bind(error_message)
            .bind(id)
            .execute(pool)
            .await?;
        }
        _ => {
            sqlx::query(
                "UPDATE cracking_jobs SET status = ?1 WHERE id = ?2"
            )
            .bind(status_str)
            .bind(id)
            .execute(pool)
            .await?;
        }
    }

    Ok(())
}

/// Update job progress
pub async fn update_job_progress(
    pool: &SqlitePool,
    id: &str,
    progress_json: &str,
) -> Result<()> {
    sqlx::query(
        "UPDATE cracking_jobs SET progress_json = ?1 WHERE id = ?2"
    )
    .bind(progress_json)
    .bind(id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Update job results
pub async fn update_job_results(
    pool: &SqlitePool,
    id: &str,
    results_json: &str,
) -> Result<()> {
    sqlx::query(
        "UPDATE cracking_jobs SET results_json = ?1 WHERE id = ?2"
    )
    .bind(results_json)
    .bind(id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Delete a cracking job
pub async fn delete_cracking_job(pool: &SqlitePool, id: &str) -> Result<()> {
    sqlx::query("DELETE FROM cracking_jobs WHERE id = ?1")
        .bind(id)
        .execute(pool)
        .await?;

    Ok(())
}

// ============================================================================
// Cracked Credentials
// ============================================================================

/// Store a cracked credential
pub async fn store_cracked_credential(
    pool: &SqlitePool,
    id: &str,
    job_id: &str,
    hash: &str,
    plaintext: &str,
    hash_type: i32,
    username: Option<&str>,
    domain: Option<&str>,
    asset_id: Option<&str>,
) -> Result<()> {
    let now = Utc::now();

    sqlx::query(
        r#"
        INSERT INTO cracked_credentials (
            id, job_id, hash, plaintext, hash_type,
            username, domain, asset_id, cracked_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
        ON CONFLICT(hash, job_id) DO UPDATE SET
            plaintext = excluded.plaintext,
            cracked_at = excluded.cracked_at
        "#
    )
    .bind(id)
    .bind(job_id)
    .bind(hash)
    .bind(plaintext)
    .bind(hash_type)
    .bind(username)
    .bind(domain)
    .bind(asset_id)
    .bind(now.to_rfc3339())
    .execute(pool)
    .await?;

    Ok(())
}

/// Get cracked credentials for a job
pub async fn get_job_credentials(
    pool: &SqlitePool,
    job_id: &str,
) -> Result<Vec<CrackedCredentialRow>> {
    let rows = sqlx::query_as::<_, CrackedCredentialRow>(
        r#"
        SELECT id, job_id, hash, plaintext, hash_type,
               username, domain, asset_id, cracked_at
        FROM cracked_credentials
        WHERE job_id = ?1
        ORDER BY cracked_at DESC
        "#
    )
    .bind(job_id)
    .fetch_all(pool)
    .await?;

    Ok(rows)
}

/// Get all cracked credentials for a user (across all jobs)
pub async fn get_user_credentials(
    pool: &SqlitePool,
    user_id: &str,
    limit: Option<i64>,
) -> Result<Vec<CrackedCredentialRow>> {
    let limit = limit.unwrap_or(1000);

    let rows = sqlx::query_as::<_, CrackedCredentialRow>(
        r#"
        SELECT c.id, c.job_id, c.hash, c.plaintext, c.hash_type,
               c.username, c.domain, c.asset_id, c.cracked_at
        FROM cracked_credentials c
        JOIN cracking_jobs j ON c.job_id = j.id
        WHERE j.user_id = ?1
        ORDER BY c.cracked_at DESC
        LIMIT ?2
        "#
    )
    .bind(user_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    Ok(rows)
}

// ============================================================================
// Wordlists
// ============================================================================

/// Create a wordlist entry
pub async fn create_wordlist(
    pool: &SqlitePool,
    id: &str,
    user_id: Option<&str>,
    name: &str,
    description: Option<&str>,
    file_path: &str,
    size_bytes: i64,
    line_count: i64,
    is_builtin: bool,
    category: &str,
) -> Result<Wordlist> {
    let now = Utc::now();

    sqlx::query(
        r#"
        INSERT INTO cracking_wordlists (
            id, user_id, name, description, file_path,
            size_bytes, line_count, is_builtin, category, created_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
        "#
    )
    .bind(id)
    .bind(user_id)
    .bind(name)
    .bind(description)
    .bind(file_path)
    .bind(size_bytes)
    .bind(line_count)
    .bind(is_builtin)
    .bind(category)
    .bind(now.to_rfc3339())
    .execute(pool)
    .await?;

    get_wordlist(pool, id).await
}

/// Get a wordlist by ID
pub async fn get_wordlist(pool: &SqlitePool, id: &str) -> Result<Wordlist> {
    let row = sqlx::query_as::<_, WordlistRow>(
        r#"
        SELECT id, user_id, name, description, file_path,
               size_bytes, line_count, is_builtin, category, created_at
        FROM cracking_wordlists
        WHERE id = ?1
        "#
    )
    .bind(id)
    .fetch_one(pool)
    .await?;

    Ok(row.into())
}

/// Get all available wordlists (built-in + user's custom)
pub async fn get_available_wordlists(
    pool: &SqlitePool,
    user_id: &str,
) -> Result<Vec<Wordlist>> {
    let rows = sqlx::query_as::<_, WordlistRow>(
        r#"
        SELECT id, user_id, name, description, file_path,
               size_bytes, line_count, is_builtin, category, created_at
        FROM cracking_wordlists
        WHERE is_builtin = 1 OR user_id = ?1
        ORDER BY is_builtin DESC, name ASC
        "#
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(|r| r.into()).collect())
}

/// Delete a wordlist
pub async fn delete_wordlist(pool: &SqlitePool, id: &str) -> Result<()> {
    sqlx::query("DELETE FROM cracking_wordlists WHERE id = ?1 AND is_builtin = 0")
        .bind(id)
        .execute(pool)
        .await?;

    Ok(())
}

// ============================================================================
// Rule Files
// ============================================================================

/// Create a rule file entry
pub async fn create_rule_file(
    pool: &SqlitePool,
    id: &str,
    user_id: Option<&str>,
    name: &str,
    description: Option<&str>,
    file_path: &str,
    rule_count: i32,
    cracker_type: CrackerType,
    is_builtin: bool,
) -> Result<RuleFile> {
    let now = Utc::now();
    let cracker_str = match cracker_type {
        CrackerType::Hashcat => "hashcat",
        CrackerType::John => "john",
    };

    sqlx::query(
        r#"
        INSERT INTO cracking_rules (
            id, user_id, name, description, file_path,
            rule_count, cracker_type, is_builtin, created_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
        "#
    )
    .bind(id)
    .bind(user_id)
    .bind(name)
    .bind(description)
    .bind(file_path)
    .bind(rule_count)
    .bind(cracker_str)
    .bind(is_builtin)
    .bind(now.to_rfc3339())
    .execute(pool)
    .await?;

    get_rule_file(pool, id).await
}

/// Get a rule file by ID
pub async fn get_rule_file(pool: &SqlitePool, id: &str) -> Result<RuleFile> {
    let row = sqlx::query_as::<_, RuleFileRow>(
        r#"
        SELECT id, user_id, name, description, file_path,
               rule_count, cracker_type, is_builtin, created_at
        FROM cracking_rules
        WHERE id = ?1
        "#
    )
    .bind(id)
    .fetch_one(pool)
    .await?;

    Ok(row.into())
}

/// Get all available rule files
pub async fn get_available_rules(
    pool: &SqlitePool,
    user_id: &str,
    cracker_type: Option<CrackerType>,
) -> Result<Vec<RuleFile>> {
    let cracker_filter = cracker_type.map(|ct| match ct {
        CrackerType::Hashcat => "hashcat",
        CrackerType::John => "john",
    });

    let rows = if let Some(cracker) = cracker_filter {
        sqlx::query_as::<_, RuleFileRow>(
            r#"
            SELECT id, user_id, name, description, file_path,
                   rule_count, cracker_type, is_builtin, created_at
            FROM cracking_rules
            WHERE (is_builtin = 1 OR user_id = ?1) AND cracker_type = ?2
            ORDER BY is_builtin DESC, name ASC
            "#
        )
        .bind(user_id)
        .bind(cracker)
        .fetch_all(pool)
        .await?
    } else {
        sqlx::query_as::<_, RuleFileRow>(
            r#"
            SELECT id, user_id, name, description, file_path,
                   rule_count, cracker_type, is_builtin, created_at
            FROM cracking_rules
            WHERE is_builtin = 1 OR user_id = ?1
            ORDER BY is_builtin DESC, name ASC
            "#
        )
        .bind(user_id)
        .fetch_all(pool)
        .await?
    };

    Ok(rows.into_iter().map(|r| r.into()).collect())
}

/// Delete a rule file
pub async fn delete_rule_file(pool: &SqlitePool, id: &str) -> Result<()> {
    sqlx::query("DELETE FROM cracking_rules WHERE id = ?1 AND is_builtin = 0")
        .bind(id)
        .execute(pool)
        .await?;

    Ok(())
}

// ============================================================================
// Statistics
// ============================================================================

/// Get cracking statistics
pub async fn get_cracking_stats(pool: &SqlitePool, user_id: &str) -> Result<CrackingStats> {
    // Total jobs
    let total_jobs: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM cracking_jobs WHERE user_id = ?1"
    )
    .bind(user_id)
    .fetch_one(pool)
    .await?;

    // Running jobs
    let running_jobs: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM cracking_jobs WHERE user_id = ?1 AND status = 'running'"
    )
    .bind(user_id)
    .fetch_one(pool)
    .await?;

    // Total hashes and cracked (from completed jobs)
    let hash_stats: (i64, i64) = sqlx::query_as(
        r#"
        SELECT
            COALESCE(SUM(json_array_length(hashes_json)), 0),
            (SELECT COUNT(*) FROM cracked_credentials c
             JOIN cracking_jobs j ON c.job_id = j.id
             WHERE j.user_id = ?1)
        FROM cracking_jobs
        WHERE user_id = ?1
        "#
    )
    .bind(user_id)
    .fetch_one(pool)
    .await
    .unwrap_or((0, 0));

    let total_hashes = hash_stats.0;
    let total_cracked = hash_stats.1;
    let success_rate = if total_hashes > 0 {
        (total_cracked as f64 / total_hashes as f64) * 100.0
    } else {
        0.0
    };

    // Get top hash types from cracked credentials
    let top_hash_types_raw: Vec<(i32, i64)> = sqlx::query_as(
        r#"
        SELECT c.hash_type, COUNT(*) as count
        FROM cracked_credentials c
        JOIN cracking_jobs j ON c.job_id = j.id
        WHERE j.user_id = ?1
        GROUP BY c.hash_type
        ORDER BY count DESC
        LIMIT 5
        "#
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    // Convert hash type codes to names
    let top_hash_types: Vec<(String, i64)> = top_hash_types_raw
        .into_iter()
        .map(|(hash_type, count)| {
            let hash_name = match hash_type {
                0 => "MD5",
                100 => "SHA-1",
                1400 => "SHA-256",
                1700 => "SHA-512",
                1000 => "NTLM",
                3000 => "LM",
                5500 => "NetNTLMv1",
                5600 => "NetNTLMv2",
                13100 => "Kerberos TGS",
                18200 => "Kerberos AS-REP",
                3200 => "bcrypt",
                500 => "md5crypt",
                1800 => "sha512crypt",
                7400 => "sha256crypt",
                _ => "Other",
            };
            (hash_name.to_string(), count)
        })
        .collect();

    // Get top passwords from cracked credentials
    let top_passwords: Vec<(String, i64)> = sqlx::query_as(
        r#"
        SELECT c.plaintext, COUNT(*) as count
        FROM cracked_credentials c
        JOIN cracking_jobs j ON c.job_id = j.id
        WHERE j.user_id = ?1 AND c.plaintext IS NOT NULL AND c.plaintext != ''
        GROUP BY c.plaintext
        ORDER BY count DESC
        LIMIT 10
        "#
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    Ok(CrackingStats {
        total_jobs: total_jobs.0,
        running_jobs: running_jobs.0,
        total_hashes,
        total_cracked,
        success_rate,
        top_hash_types,
        top_passwords,
    })
}

// ============================================================================
// Row Types
// ============================================================================

#[derive(Debug, sqlx::FromRow)]
struct CrackingJobRow {
    id: String,
    user_id: String,
    name: Option<String>,
    status: String,
    hash_type: i32,
    cracker_type: String,
    hashes_json: String,
    config_json: String,
    progress_json: Option<String>,
    results_json: Option<String>,
    error_message: Option<String>,
    source_campaign_id: Option<String>,
    customer_id: Option<String>,
    engagement_id: Option<String>,
    created_at: String,
    started_at: Option<String>,
    completed_at: Option<String>,
}

impl From<CrackingJobRow> for CrackingJob {
    fn from(row: CrackingJobRow) -> Self {
        CrackingJob {
            id: row.id,
            user_id: row.user_id,
            name: row.name,
            status: match row.status.as_str() {
                "running" => CrackingJobStatus::Running,
                "completed" => CrackingJobStatus::Completed,
                "failed" => CrackingJobStatus::Failed,
                "cancelled" => CrackingJobStatus::Cancelled,
                "paused" => CrackingJobStatus::Paused,
                _ => CrackingJobStatus::Pending,
            },
            hash_type: row.hash_type,
            cracker_type: match row.cracker_type.as_str() {
                "john" => CrackerType::John,
                _ => CrackerType::Hashcat,
            },
            hashes_json: row.hashes_json,
            config_json: row.config_json,
            progress_json: row.progress_json,
            results_json: row.results_json,
            error_message: row.error_message,
            source_campaign_id: row.source_campaign_id,
            customer_id: row.customer_id,
            engagement_id: row.engagement_id,
            created_at: DateTime::parse_from_rfc3339(&row.created_at)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            started_at: row.started_at.and_then(|s|
                DateTime::parse_from_rfc3339(&s).ok().map(|dt| dt.with_timezone(&Utc))
            ),
            completed_at: row.completed_at.and_then(|s|
                DateTime::parse_from_rfc3339(&s).ok().map(|dt| dt.with_timezone(&Utc))
            ),
        }
    }
}

#[derive(Debug, sqlx::FromRow, serde::Serialize)]
pub struct CrackedCredentialRow {
    pub id: String,
    pub job_id: String,
    pub hash: String,
    pub plaintext: String,
    pub hash_type: i32,
    pub username: Option<String>,
    pub domain: Option<String>,
    pub asset_id: Option<String>,
    pub cracked_at: String,
}

#[derive(Debug, sqlx::FromRow)]
struct WordlistRow {
    id: String,
    user_id: Option<String>,
    name: String,
    description: Option<String>,
    file_path: String,
    size_bytes: i64,
    line_count: i64,
    is_builtin: bool,
    category: String,
    created_at: String,
}

impl From<WordlistRow> for Wordlist {
    fn from(row: WordlistRow) -> Self {
        Wordlist {
            id: row.id,
            user_id: row.user_id,
            name: row.name,
            description: row.description,
            file_path: row.file_path,
            size_bytes: row.size_bytes,
            line_count: row.line_count,
            is_builtin: row.is_builtin,
            category: row.category,
            created_at: DateTime::parse_from_rfc3339(&row.created_at)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
        }
    }
}

#[derive(Debug, sqlx::FromRow)]
struct RuleFileRow {
    id: String,
    user_id: Option<String>,
    name: String,
    description: Option<String>,
    file_path: String,
    rule_count: i32,
    cracker_type: String,
    is_builtin: bool,
    created_at: String,
}

impl From<RuleFileRow> for RuleFile {
    fn from(row: RuleFileRow) -> Self {
        RuleFile {
            id: row.id,
            user_id: row.user_id,
            name: row.name,
            description: row.description,
            file_path: row.file_path,
            rule_count: row.rule_count,
            cracker_type: match row.cracker_type.as_str() {
                "john" => CrackerType::John,
                _ => CrackerType::Hashcat,
            },
            is_builtin: row.is_builtin,
            created_at: DateTime::parse_from_rfc3339(&row.created_at)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
        }
    }
}
