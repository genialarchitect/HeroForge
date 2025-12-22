//! Database operations for BloodHound imports and analysis

use anyhow::Result;
use sqlx::SqlitePool;
use uuid::Uuid;

use crate::scanner::bloodhound::{
    AsrepRoastableUser, AttackPath, BloodHoundImportResult, HighValueTarget, ImportStatistics,
    ImportStatus, KerberoastableUser, UnconstrainedDelegation,
};

/// Create a new BloodHound import record
pub async fn create_import(
    pool: &SqlitePool,
    user_id: &str,
    domain: &str,
) -> Result<String> {
    let id = Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();
    let status = serde_json::to_string(&ImportStatus::Processing)?;
    let stats = serde_json::to_string(&ImportStatistics::default())?;

    sqlx::query(
        r#"
        INSERT INTO bloodhound_imports (id, user_id, domain, status, statistics, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(user_id)
    .bind(domain)
    .bind(&status)
    .bind(&stats)
    .bind(&now)
    .execute(pool)
    .await?;

    Ok(id)
}

/// Update import status
pub async fn update_import_status(
    pool: &SqlitePool,
    import_id: &str,
    status: ImportStatus,
) -> Result<()> {
    let status_json = serde_json::to_string(&status)?;

    sqlx::query(
        r#"
        UPDATE bloodhound_imports
        SET status = ?
        WHERE id = ?
        "#,
    )
    .bind(&status_json)
    .bind(import_id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Save import results
pub async fn save_import_results(
    pool: &SqlitePool,
    import_id: &str,
    result: &BloodHoundImportResult,
) -> Result<()> {
    let now = chrono::Utc::now().to_rfc3339();
    let status = serde_json::to_string(&ImportStatus::Completed)?;
    let stats = serde_json::to_string(&result.statistics)?;

    // Update import record
    sqlx::query(
        r#"
        UPDATE bloodhound_imports
        SET status = ?, statistics = ?, completed_at = ?, domain = ?
        WHERE id = ?
        "#,
    )
    .bind(&status)
    .bind(&stats)
    .bind(&now)
    .bind(&result.domain)
    .bind(import_id)
    .execute(pool)
    .await?;

    // Save attack paths
    for path in &result.attack_paths {
        save_attack_path(pool, import_id, path).await?;
    }

    // Save high-value targets
    for target in &result.high_value_targets {
        save_high_value_target(pool, import_id, target).await?;
    }

    // Save Kerberoastable users
    for user in &result.kerberoastable_users {
        save_kerberoastable_user(pool, import_id, user).await?;
    }

    // Save AS-REP roastable users
    for user in &result.asrep_roastable_users {
        save_asrep_roastable_user(pool, import_id, user).await?;
    }

    // Save unconstrained delegation
    for obj in &result.unconstrained_delegation {
        save_unconstrained_delegation(pool, import_id, obj).await?;
    }

    Ok(())
}

async fn save_attack_path(pool: &SqlitePool, import_id: &str, path: &AttackPath) -> Result<()> {
    let id = Uuid::new_v4().to_string();
    let path_json = serde_json::to_string(&path.path)?;
    let techniques_json = serde_json::to_string(&path.techniques)?;
    let start_node_json = serde_json::to_string(&path.start_node)?;
    let end_node_json = serde_json::to_string(&path.end_node)?;

    sqlx::query(
        r#"
        INSERT INTO bloodhound_attack_paths
        (id, import_id, start_node, end_node, path_json, path_length, risk_score, techniques, description)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(import_id)
    .bind(&start_node_json)
    .bind(&end_node_json)
    .bind(&path_json)
    .bind(path.length as i64)
    .bind(path.risk_score as i64)
    .bind(&techniques_json)
    .bind(&path.description)
    .execute(pool)
    .await?;

    Ok(())
}

async fn save_high_value_target(
    pool: &SqlitePool,
    import_id: &str,
    target: &HighValueTarget,
) -> Result<()> {
    let id = Uuid::new_v4().to_string();
    let object_type = serde_json::to_string(&target.object_type)?;

    sqlx::query(
        r#"
        INSERT INTO bloodhound_high_value_targets
        (id, import_id, object_id, name, object_type, domain, reason, paths_to_target)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(import_id)
    .bind(&target.object_id)
    .bind(&target.name)
    .bind(&object_type)
    .bind(&target.domain)
    .bind(&target.reason)
    .bind(target.paths_to_target as i64)
    .execute(pool)
    .await?;

    Ok(())
}

async fn save_kerberoastable_user(
    pool: &SqlitePool,
    import_id: &str,
    user: &KerberoastableUser,
) -> Result<()> {
    let id = Uuid::new_v4().to_string();
    let spns_json = serde_json::to_string(&user.service_principal_names)?;

    sqlx::query(
        r#"
        INSERT INTO bloodhound_kerberoastable
        (id, import_id, object_id, name, domain, spns, is_admin, password_last_set, description)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(import_id)
    .bind(&user.object_id)
    .bind(&user.name)
    .bind(&user.domain)
    .bind(&spns_json)
    .bind(user.is_admin)
    .bind(&user.password_last_set)
    .bind(&user.description)
    .execute(pool)
    .await?;

    Ok(())
}

async fn save_asrep_roastable_user(
    pool: &SqlitePool,
    import_id: &str,
    user: &AsrepRoastableUser,
) -> Result<()> {
    let id = Uuid::new_v4().to_string();

    sqlx::query(
        r#"
        INSERT INTO bloodhound_asrep_roastable
        (id, import_id, object_id, name, domain, is_enabled, is_admin, description)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(import_id)
    .bind(&user.object_id)
    .bind(&user.name)
    .bind(&user.domain)
    .bind(user.is_enabled)
    .bind(user.is_admin)
    .bind(&user.description)
    .execute(pool)
    .await?;

    Ok(())
}

async fn save_unconstrained_delegation(
    pool: &SqlitePool,
    import_id: &str,
    obj: &UnconstrainedDelegation,
) -> Result<()> {
    let id = Uuid::new_v4().to_string();
    let object_type = serde_json::to_string(&obj.object_type)?;

    sqlx::query(
        r#"
        INSERT INTO bloodhound_unconstrained_delegation
        (id, import_id, object_id, name, object_type, domain, is_dc, description)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(import_id)
    .bind(&obj.object_id)
    .bind(&obj.name)
    .bind(&object_type)
    .bind(&obj.domain)
    .bind(obj.is_dc)
    .bind(&obj.description)
    .execute(pool)
    .await?;

    Ok(())
}

/// Import row structure
#[derive(sqlx::FromRow)]
pub struct BloodHoundImportRow {
    pub id: String,
    pub user_id: String,
    pub domain: String,
    pub status: String,
    pub statistics: String,
    pub created_at: String,
    pub completed_at: Option<String>,
}

/// Get all imports for a user
pub async fn get_user_imports(
    pool: &SqlitePool,
    user_id: &str,
    limit: i64,
    offset: i64,
) -> Result<Vec<BloodHoundImportRow>> {
    let imports = sqlx::query_as::<_, BloodHoundImportRow>(
        r#"
        SELECT id, user_id, domain, status, statistics, created_at, completed_at
        FROM bloodhound_imports
        WHERE user_id = ?
        ORDER BY created_at DESC
        LIMIT ? OFFSET ?
        "#,
    )
    .bind(user_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await?;

    Ok(imports)
}

/// Get a specific import by ID
pub async fn get_import_by_id(
    pool: &SqlitePool,
    import_id: &str,
) -> Result<Option<BloodHoundImportRow>> {
    let import = sqlx::query_as::<_, BloodHoundImportRow>(
        r#"
        SELECT id, user_id, domain, status, statistics, created_at, completed_at
        FROM bloodhound_imports
        WHERE id = ?
        "#,
    )
    .bind(import_id)
    .fetch_optional(pool)
    .await?;

    Ok(import)
}

/// Attack path row
#[derive(sqlx::FromRow)]
pub struct AttackPathRow {
    pub id: String,
    pub import_id: String,
    pub start_node: String,
    pub end_node: String,
    pub path_json: String,
    pub path_length: i64,
    pub risk_score: i64,
    pub techniques: String,
    pub description: String,
}

/// Get attack paths for an import
pub async fn get_attack_paths(
    pool: &SqlitePool,
    import_id: &str,
) -> Result<Vec<AttackPathRow>> {
    let paths = sqlx::query_as::<_, AttackPathRow>(
        r#"
        SELECT id, import_id, start_node, end_node, path_json, path_length, risk_score, techniques, description
        FROM bloodhound_attack_paths
        WHERE import_id = ?
        ORDER BY risk_score DESC
        "#,
    )
    .bind(import_id)
    .fetch_all(pool)
    .await?;

    Ok(paths)
}

/// Kerberoastable row
#[derive(sqlx::FromRow)]
pub struct KerberoastableRow {
    pub id: String,
    pub import_id: String,
    pub object_id: String,
    pub name: String,
    pub domain: String,
    pub spns: String,
    pub is_admin: bool,
    pub password_last_set: Option<String>,
    pub description: Option<String>,
}

/// Get Kerberoastable users for an import
pub async fn get_kerberoastable_users(
    pool: &SqlitePool,
    import_id: &str,
) -> Result<Vec<KerberoastableRow>> {
    let users = sqlx::query_as::<_, KerberoastableRow>(
        r#"
        SELECT id, import_id, object_id, name, domain, spns, is_admin, password_last_set, description
        FROM bloodhound_kerberoastable
        WHERE import_id = ?
        ORDER BY is_admin DESC, name ASC
        "#,
    )
    .bind(import_id)
    .fetch_all(pool)
    .await?;

    Ok(users)
}

/// AS-REP roastable row
#[derive(sqlx::FromRow)]
pub struct AsrepRoastableRow {
    pub id: String,
    pub import_id: String,
    pub object_id: String,
    pub name: String,
    pub domain: String,
    pub is_enabled: bool,
    pub is_admin: bool,
    pub description: Option<String>,
}

/// Get AS-REP roastable users for an import
pub async fn get_asrep_roastable_users(
    pool: &SqlitePool,
    import_id: &str,
) -> Result<Vec<AsrepRoastableRow>> {
    let users = sqlx::query_as::<_, AsrepRoastableRow>(
        r#"
        SELECT id, import_id, object_id, name, domain, is_enabled, is_admin, description
        FROM bloodhound_asrep_roastable
        WHERE import_id = ?
        ORDER BY is_admin DESC, name ASC
        "#,
    )
    .bind(import_id)
    .fetch_all(pool)
    .await?;

    Ok(users)
}

/// High-value target row
#[derive(sqlx::FromRow)]
pub struct HighValueTargetRow {
    pub id: String,
    pub import_id: String,
    pub object_id: String,
    pub name: String,
    pub object_type: String,
    pub domain: String,
    pub reason: String,
    pub paths_to_target: i64,
}

/// Get high-value targets for an import
pub async fn get_high_value_targets(
    pool: &SqlitePool,
    import_id: &str,
) -> Result<Vec<HighValueTargetRow>> {
    let targets = sqlx::query_as::<_, HighValueTargetRow>(
        r#"
        SELECT id, import_id, object_id, name, object_type, domain, reason, paths_to_target
        FROM bloodhound_high_value_targets
        WHERE import_id = ?
        ORDER BY paths_to_target DESC
        "#,
    )
    .bind(import_id)
    .fetch_all(pool)
    .await?;

    Ok(targets)
}

/// Unconstrained delegation row
#[derive(sqlx::FromRow)]
pub struct UnconstrainedDelegationRow {
    pub id: String,
    pub import_id: String,
    pub object_id: String,
    pub name: String,
    pub object_type: String,
    pub domain: String,
    pub is_dc: bool,
    pub description: Option<String>,
}

/// Get unconstrained delegation objects for an import
pub async fn get_unconstrained_delegation(
    pool: &SqlitePool,
    import_id: &str,
) -> Result<Vec<UnconstrainedDelegationRow>> {
    let objects = sqlx::query_as::<_, UnconstrainedDelegationRow>(
        r#"
        SELECT id, import_id, object_id, name, object_type, domain, is_dc, description
        FROM bloodhound_unconstrained_delegation
        WHERE import_id = ?
        ORDER BY is_dc DESC, name ASC
        "#,
    )
    .bind(import_id)
    .fetch_all(pool)
    .await?;

    Ok(objects)
}

/// Delete an import and all associated data
pub async fn delete_import(pool: &SqlitePool, import_id: &str) -> Result<()> {
    // Delete associated data first
    sqlx::query("DELETE FROM bloodhound_attack_paths WHERE import_id = ?")
        .bind(import_id)
        .execute(pool)
        .await?;

    sqlx::query("DELETE FROM bloodhound_high_value_targets WHERE import_id = ?")
        .bind(import_id)
        .execute(pool)
        .await?;

    sqlx::query("DELETE FROM bloodhound_kerberoastable WHERE import_id = ?")
        .bind(import_id)
        .execute(pool)
        .await?;

    sqlx::query("DELETE FROM bloodhound_asrep_roastable WHERE import_id = ?")
        .bind(import_id)
        .execute(pool)
        .await?;

    sqlx::query("DELETE FROM bloodhound_unconstrained_delegation WHERE import_id = ?")
        .bind(import_id)
        .execute(pool)
        .await?;

    // Delete the import
    sqlx::query("DELETE FROM bloodhound_imports WHERE id = ?")
        .bind(import_id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Convert import row to result
pub fn row_to_import_summary(row: BloodHoundImportRow) -> Result<BloodHoundImportResult> {
    let status: ImportStatus = serde_json::from_str(&row.status)?;
    let statistics: ImportStatistics = serde_json::from_str(&row.statistics)?;

    Ok(BloodHoundImportResult {
        id: row.id,
        status,
        domain: row.domain,
        statistics,
        attack_paths: Vec::new(), // Not loaded in summary
        high_value_targets: Vec::new(),
        kerberoastable_users: Vec::new(),
        asrep_roastable_users: Vec::new(),
        unconstrained_delegation: Vec::new(),
        created_at: row.created_at,
        completed_at: row.completed_at,
        error: None,
    })
}
