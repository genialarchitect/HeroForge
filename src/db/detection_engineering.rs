//! Database operations for Detection Engineering
//!
//! This module provides database access for:
//! - Detections and versions
//! - Coverage mappings
//! - False positives and tuning
//! - Detection tests and test runs

use anyhow::Result;
use chrono::{DateTime, Utc};
use sqlx::SqlitePool;
use uuid::Uuid;

// =============================================================================
// Detection CRUD Operations
// =============================================================================

/// Create a new detection
pub async fn create_detection(
    pool: &SqlitePool,
    id: &str,
    name: &str,
    description: &str,
    logic_yaml: &str,
    data_sources_json: &str,
    severity: &str,
    status: &str,
    author_id: &str,
    mitre_techniques_json: &str,
    mitre_tactics_json: &str,
    tags_json: &str,
) -> Result<()> {
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        INSERT INTO detections (
            id, name, description, logic_yaml, data_sources, severity, status,
            author_id, version, mitre_techniques, mitre_tactics, tags,
            enabled, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, 1, ?, ?)
        "#,
    )
    .bind(id)
    .bind(name)
    .bind(description)
    .bind(logic_yaml)
    .bind(data_sources_json)
    .bind(severity)
    .bind(status)
    .bind(author_id)
    .bind(mitre_techniques_json)
    .bind(mitre_tactics_json)
    .bind(tags_json)
    .bind(&now)
    .bind(&now)
    .execute(pool)
    .await?;

    // Create initial version
    create_detection_version(
        pool,
        &Uuid::new_v4().to_string(),
        id,
        1,
        logic_yaml,
        "Initial version",
        author_id,
    )
    .await?;

    Ok(())
}

/// Get detection by ID
pub async fn get_detection_by_id(
    pool: &SqlitePool,
    id: &str,
) -> Result<Option<DetectionRow>> {
    let row = sqlx::query_as::<_, DetectionRow>(
        r#"
        SELECT d.*, u.username as author_name
        FROM detections d
        LEFT JOIN users u ON d.author_id = u.id
        WHERE d.id = ?
        "#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    Ok(row)
}

/// List all detections with pagination
pub async fn list_detections(
    pool: &SqlitePool,
    status: Option<&str>,
    severity: Option<&str>,
    search: Option<&str>,
    offset: u32,
    limit: u32,
) -> Result<(Vec<DetectionRow>, i64)> {
    let mut sql = String::from(
        r#"
        SELECT d.*, u.username as author_name
        FROM detections d
        LEFT JOIN users u ON d.author_id = u.id
        WHERE 1=1
        "#,
    );
    let mut count_sql = String::from("SELECT COUNT(*) FROM detections WHERE 1=1");

    if let Some(s) = status {
        sql.push_str(&format!(" AND d.status = '{}'", s.replace('\'', "''")));
        count_sql.push_str(&format!(" AND status = '{}'", s.replace('\'', "''")));
    }
    if let Some(sev) = severity {
        sql.push_str(&format!(" AND d.severity = '{}'", sev.replace('\'', "''")));
        count_sql.push_str(&format!(" AND severity = '{}'", sev.replace('\'', "''")));
    }
    if let Some(q) = search {
        let escaped = q.replace('\'', "''");
        sql.push_str(&format!(
            " AND (d.name LIKE '%{}%' OR d.description LIKE '%{}%')",
            escaped, escaped
        ));
        count_sql.push_str(&format!(
            " AND (name LIKE '%{}%' OR description LIKE '%{}%')",
            escaped, escaped
        ));
    }

    sql.push_str(" ORDER BY d.updated_at DESC");
    sql.push_str(&format!(" LIMIT {} OFFSET {}", limit, offset));

    let rows = sqlx::query_as::<_, DetectionRow>(&sql)
        .fetch_all(pool)
        .await?;

    let total: (i64,) = sqlx::query_as(&count_sql).fetch_one(pool).await?;

    Ok((rows, total.0))
}

/// Update a detection
pub async fn update_detection(
    pool: &SqlitePool,
    id: &str,
    name: Option<&str>,
    description: Option<&str>,
    logic_yaml: Option<&str>,
    data_sources_json: Option<&str>,
    severity: Option<&str>,
    status: Option<&str>,
    mitre_techniques_json: Option<&str>,
    mitre_tactics_json: Option<&str>,
    tags_json: Option<&str>,
    enabled: Option<bool>,
    user_id: &str,
    change_notes: &str,
) -> Result<u32> {
    // Get current version
    let current: (i32,) = sqlx::query_as("SELECT version FROM detections WHERE id = ?")
        .bind(id)
        .fetch_one(pool)
        .await?;

    let new_version = current.0 as u32 + 1;
    let now = Utc::now().to_rfc3339();

    // Build update query dynamically
    let mut updates = vec!["version = ?", "updated_at = ?"];
    let mut values: Vec<String> = vec![new_version.to_string(), now.clone()];

    if let Some(n) = name {
        updates.push("name = ?");
        values.push(n.to_string());
    }
    if let Some(d) = description {
        updates.push("description = ?");
        values.push(d.to_string());
    }
    if let Some(l) = logic_yaml {
        updates.push("logic_yaml = ?");
        values.push(l.to_string());
    }
    if let Some(ds) = data_sources_json {
        updates.push("data_sources = ?");
        values.push(ds.to_string());
    }
    if let Some(sev) = severity {
        updates.push("severity = ?");
        values.push(sev.to_string());
    }
    if let Some(st) = status {
        updates.push("status = ?");
        values.push(st.to_string());
    }
    if let Some(mt) = mitre_techniques_json {
        updates.push("mitre_techniques = ?");
        values.push(mt.to_string());
    }
    if let Some(mt) = mitre_tactics_json {
        updates.push("mitre_tactics = ?");
        values.push(mt.to_string());
    }
    if let Some(t) = tags_json {
        updates.push("tags = ?");
        values.push(t.to_string());
    }
    if let Some(e) = enabled {
        updates.push("enabled = ?");
        values.push(if e { "1" } else { "0" }.to_string());
    }

    let sql = format!(
        "UPDATE detections SET {} WHERE id = ?",
        updates.join(", ")
    );

    // Execute using raw query with numbered bindings
    let mut query = sqlx::query(&sql);
    for val in &values {
        query = query.bind(val);
    }
    query = query.bind(id);
    query.execute(pool).await?;

    // Create version record
    let logic = logic_yaml.unwrap_or("");
    create_detection_version(
        pool,
        &Uuid::new_v4().to_string(),
        id,
        new_version,
        logic,
        change_notes,
        user_id,
    )
    .await?;

    Ok(new_version)
}

/// Delete a detection
pub async fn delete_detection(pool: &SqlitePool, id: &str) -> Result<bool> {
    let result = sqlx::query("DELETE FROM detections WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;

    Ok(result.rows_affected() > 0)
}

// =============================================================================
// Detection Version Operations
// =============================================================================

/// Create a detection version record
pub async fn create_detection_version(
    pool: &SqlitePool,
    id: &str,
    detection_id: &str,
    version: u32,
    logic_yaml: &str,
    change_notes: &str,
    created_by: &str,
) -> Result<()> {
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        INSERT INTO detection_versions (
            id, detection_id, version, logic_yaml, change_notes, created_by, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(id)
    .bind(detection_id)
    .bind(version as i32)
    .bind(logic_yaml)
    .bind(change_notes)
    .bind(created_by)
    .bind(&now)
    .execute(pool)
    .await?;

    Ok(())
}

/// Get version history for a detection
pub async fn get_detection_versions(
    pool: &SqlitePool,
    detection_id: &str,
) -> Result<Vec<DetectionVersionRow>> {
    let rows = sqlx::query_as::<_, DetectionVersionRow>(
        r#"
        SELECT v.*, u.username as created_by_name
        FROM detection_versions v
        LEFT JOIN users u ON v.created_by = u.id
        WHERE v.detection_id = ?
        ORDER BY v.version DESC
        "#,
    )
    .bind(detection_id)
    .fetch_all(pool)
    .await?;

    Ok(rows)
}

/// Get a specific version
pub async fn get_detection_version(
    pool: &SqlitePool,
    detection_id: &str,
    version: u32,
) -> Result<Option<DetectionVersionRow>> {
    let row = sqlx::query_as::<_, DetectionVersionRow>(
        r#"
        SELECT v.*, u.username as created_by_name
        FROM detection_versions v
        LEFT JOIN users u ON v.created_by = u.id
        WHERE v.detection_id = ? AND v.version = ?
        "#,
    )
    .bind(detection_id)
    .bind(version as i32)
    .fetch_optional(pool)
    .await?;

    Ok(row)
}

// =============================================================================
// Coverage Mapping Operations
// =============================================================================

/// Add coverage mapping
pub async fn add_coverage_mapping(
    pool: &SqlitePool,
    detection_id: &str,
    technique_id: &str,
    coverage_type: &str,
    notes: Option<&str>,
    created_by: &str,
) -> Result<()> {
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        INSERT INTO detection_coverage (
            detection_id, technique_id, coverage_type, notes, created_by, created_at
        ) VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(detection_id, technique_id) DO UPDATE SET
            coverage_type = excluded.coverage_type,
            notes = excluded.notes,
            created_at = excluded.created_at
        "#,
    )
    .bind(detection_id)
    .bind(technique_id)
    .bind(coverage_type)
    .bind(notes)
    .bind(created_by)
    .bind(&now)
    .execute(pool)
    .await?;

    Ok(())
}

/// Get coverage mappings for a detection
pub async fn get_detection_coverage(
    pool: &SqlitePool,
    detection_id: &str,
) -> Result<Vec<CoverageMappingRow>> {
    let rows = sqlx::query_as::<_, CoverageMappingRow>(
        "SELECT * FROM detection_coverage WHERE detection_id = ?",
    )
    .bind(detection_id)
    .fetch_all(pool)
    .await?;

    Ok(rows)
}

/// Get all coverage mappings
pub async fn get_all_coverage_mappings(pool: &SqlitePool) -> Result<Vec<CoverageMappingRow>> {
    let rows = sqlx::query_as::<_, CoverageMappingRow>(
        "SELECT * FROM detection_coverage ORDER BY technique_id",
    )
    .fetch_all(pool)
    .await?;

    Ok(rows)
}

/// Delete coverage mapping
pub async fn delete_coverage_mapping(
    pool: &SqlitePool,
    detection_id: &str,
    technique_id: &str,
) -> Result<bool> {
    let result = sqlx::query(
        "DELETE FROM detection_coverage WHERE detection_id = ? AND technique_id = ?",
    )
    .bind(detection_id)
    .bind(technique_id)
    .execute(pool)
    .await?;

    Ok(result.rows_affected() > 0)
}

// =============================================================================
// Data Source Operations
// =============================================================================

/// Add data source requirement
pub async fn add_data_source_requirement(
    pool: &SqlitePool,
    detection_id: &str,
    data_source: &str,
    required: bool,
) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO detection_data_sources (detection_id, data_source, required)
        VALUES (?, ?, ?)
        ON CONFLICT(detection_id, data_source) DO UPDATE SET required = excluded.required
        "#,
    )
    .bind(detection_id)
    .bind(data_source)
    .bind(required)
    .execute(pool)
    .await?;

    Ok(())
}

/// Get data sources for a detection
pub async fn get_detection_data_sources(
    pool: &SqlitePool,
    detection_id: &str,
) -> Result<Vec<DataSourceRow>> {
    let rows = sqlx::query_as::<_, DataSourceRow>(
        "SELECT * FROM detection_data_sources WHERE detection_id = ?",
    )
    .bind(detection_id)
    .fetch_all(pool)
    .await?;

    Ok(rows)
}

// =============================================================================
// False Positive Operations
// =============================================================================

/// Report a false positive
pub async fn report_false_positive(
    pool: &SqlitePool,
    id: &str,
    detection_id: &str,
    alert_id: &str,
    reason: &str,
    explanation: Option<&str>,
    evidence: Option<&str>,
    pattern_json: Option<&str>,
    exception_rule: Option<&str>,
    priority: &str,
    reported_by: &str,
    alert_data: Option<&str>,
    tags_json: &str,
) -> Result<()> {
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        INSERT INTO false_positives (
            id, detection_id, alert_id, reason, explanation, evidence,
            pattern, exception_rule, status, priority, reported_by,
            alert_data, tags, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(id)
    .bind(detection_id)
    .bind(alert_id)
    .bind(reason)
    .bind(explanation)
    .bind(evidence)
    .bind(pattern_json)
    .bind(exception_rule)
    .bind(priority)
    .bind(reported_by)
    .bind(alert_data)
    .bind(tags_json)
    .bind(&now)
    .bind(&now)
    .execute(pool)
    .await?;

    Ok(())
}

/// Get false positive by ID
pub async fn get_false_positive_by_id(
    pool: &SqlitePool,
    id: &str,
) -> Result<Option<FalsePositiveRow>> {
    let row = sqlx::query_as::<_, FalsePositiveRow>(
        r#"
        SELECT fp.*, u.username as reported_by_name
        FROM false_positives fp
        LEFT JOIN users u ON fp.reported_by = u.id
        WHERE fp.id = ?
        "#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    Ok(row)
}

/// List false positives for a detection
pub async fn list_detection_false_positives(
    pool: &SqlitePool,
    detection_id: &str,
    status: Option<&str>,
    offset: u32,
    limit: u32,
) -> Result<(Vec<FalsePositiveRow>, i64)> {
    let mut sql = String::from(
        r#"
        SELECT fp.*, u.username as reported_by_name
        FROM false_positives fp
        LEFT JOIN users u ON fp.reported_by = u.id
        WHERE fp.detection_id = ?
        "#,
    );
    let mut count_sql = String::from(
        "SELECT COUNT(*) FROM false_positives WHERE detection_id = ?",
    );

    if let Some(s) = status {
        sql.push_str(&format!(" AND fp.status = '{}'", s.replace('\'', "''")));
        count_sql.push_str(&format!(" AND status = '{}'", s.replace('\'', "''")));
    }

    sql.push_str(" ORDER BY fp.created_at DESC");
    sql.push_str(&format!(" LIMIT {} OFFSET {}", limit, offset));

    let rows = sqlx::query_as::<_, FalsePositiveRow>(&sql)
        .bind(detection_id)
        .fetch_all(pool)
        .await?;

    let total: (i64,) = sqlx::query_as(&count_sql)
        .bind(detection_id)
        .fetch_one(pool)
        .await?;

    Ok((rows, total.0))
}

/// Update false positive status
pub async fn update_false_positive_status(
    pool: &SqlitePool,
    id: &str,
    status: &str,
    resolution_notes: Option<&str>,
    resolved_by: Option<&str>,
) -> Result<bool> {
    let now = Utc::now().to_rfc3339();
    let resolved_at = if status == "resolved" || status == "rejected" || status == "closed" {
        Some(now.clone())
    } else {
        None
    };

    let result = sqlx::query(
        r#"
        UPDATE false_positives SET
            status = ?, resolution_notes = ?, resolved_by = ?,
            resolved_at = ?, updated_at = ?
        WHERE id = ?
        "#,
    )
    .bind(status)
    .bind(resolution_notes)
    .bind(resolved_by)
    .bind(resolved_at)
    .bind(&now)
    .bind(id)
    .execute(pool)
    .await?;

    Ok(result.rows_affected() > 0)
}

/// Assign false positive to analyst
pub async fn assign_false_positive(
    pool: &SqlitePool,
    id: &str,
    assigned_to: &str,
) -> Result<bool> {
    let now = Utc::now().to_rfc3339();

    let result = sqlx::query(
        "UPDATE false_positives SET assigned_to = ?, status = 'investigating', updated_at = ? WHERE id = ?",
    )
    .bind(assigned_to)
    .bind(&now)
    .bind(id)
    .execute(pool)
    .await?;

    Ok(result.rows_affected() > 0)
}

// =============================================================================
// Detection Tuning Operations
// =============================================================================

/// Apply tuning to a detection
pub async fn apply_detection_tuning(
    pool: &SqlitePool,
    id: &str,
    detection_id: &str,
    tuning_type: &str,
    original_value: &str,
    new_value: &str,
    reason: &str,
    related_fp_ids_json: &str,
    applied_by: &str,
) -> Result<()> {
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        INSERT INTO detection_tuning (
            id, detection_id, tuning_type, original_value, new_value,
            reason, related_fp_ids, applied_at, applied_by, active
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
        "#,
    )
    .bind(id)
    .bind(detection_id)
    .bind(tuning_type)
    .bind(original_value)
    .bind(new_value)
    .bind(reason)
    .bind(related_fp_ids_json)
    .bind(&now)
    .bind(applied_by)
    .execute(pool)
    .await?;

    Ok(())
}

/// Get tuning history for a detection
pub async fn get_detection_tuning_history(
    pool: &SqlitePool,
    detection_id: &str,
) -> Result<Vec<DetectionTuningRow>> {
    let rows = sqlx::query_as::<_, DetectionTuningRow>(
        r#"
        SELECT t.*, u.username as applied_by_name
        FROM detection_tuning t
        LEFT JOIN users u ON t.applied_by = u.id
        WHERE t.detection_id = ?
        ORDER BY t.applied_at DESC
        "#,
    )
    .bind(detection_id)
    .fetch_all(pool)
    .await?;

    Ok(rows)
}

/// Rollback tuning
pub async fn rollback_tuning(pool: &SqlitePool, id: &str) -> Result<bool> {
    let now = Utc::now().to_rfc3339();

    let result = sqlx::query(
        "UPDATE detection_tuning SET active = 0, rolled_back_at = ? WHERE id = ?",
    )
    .bind(&now)
    .bind(id)
    .execute(pool)
    .await?;

    Ok(result.rows_affected() > 0)
}

// =============================================================================
// Detection Test Operations
// =============================================================================

/// Create a test case
pub async fn create_detection_test(
    pool: &SqlitePool,
    id: &str,
    detection_id: &str,
    name: &str,
    description: Option<&str>,
    test_type: &str,
    input_logs_json: &str,
    expected_result_json: &str,
    priority: &str,
    tags_json: &str,
    created_by: &str,
) -> Result<()> {
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        INSERT INTO detection_tests (
            id, detection_id, name, description, test_type, input_logs_json,
            expected_result, priority, tags, enabled, created_by, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
        "#,
    )
    .bind(id)
    .bind(detection_id)
    .bind(name)
    .bind(description)
    .bind(test_type)
    .bind(input_logs_json)
    .bind(expected_result_json)
    .bind(priority)
    .bind(tags_json)
    .bind(created_by)
    .bind(&now)
    .bind(&now)
    .execute(pool)
    .await?;

    Ok(())
}

/// Get test by ID
pub async fn get_detection_test_by_id(
    pool: &SqlitePool,
    id: &str,
) -> Result<Option<DetectionTestRow>> {
    let row = sqlx::query_as::<_, DetectionTestRow>(
        "SELECT * FROM detection_tests WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    Ok(row)
}

/// List tests for a detection
pub async fn list_detection_tests(
    pool: &SqlitePool,
    detection_id: &str,
) -> Result<Vec<DetectionTestRow>> {
    let rows = sqlx::query_as::<_, DetectionTestRow>(
        "SELECT * FROM detection_tests WHERE detection_id = ? ORDER BY priority, name",
    )
    .bind(detection_id)
    .fetch_all(pool)
    .await?;

    Ok(rows)
}

/// Update test
pub async fn update_detection_test(
    pool: &SqlitePool,
    id: &str,
    name: Option<&str>,
    description: Option<&str>,
    test_type: Option<&str>,
    input_logs_json: Option<&str>,
    expected_result_json: Option<&str>,
    priority: Option<&str>,
    tags_json: Option<&str>,
    enabled: Option<bool>,
) -> Result<bool> {
    let now = Utc::now().to_rfc3339();

    let mut updates = vec!["updated_at = ?"];
    if name.is_some() { updates.push("name = ?"); }
    if description.is_some() { updates.push("description = ?"); }
    if test_type.is_some() { updates.push("test_type = ?"); }
    if input_logs_json.is_some() { updates.push("input_logs_json = ?"); }
    if expected_result_json.is_some() { updates.push("expected_result = ?"); }
    if priority.is_some() { updates.push("priority = ?"); }
    if tags_json.is_some() { updates.push("tags = ?"); }
    if enabled.is_some() { updates.push("enabled = ?"); }

    let sql = format!("UPDATE detection_tests SET {} WHERE id = ?", updates.join(", "));

    let mut query = sqlx::query(&sql).bind(&now);
    if let Some(v) = name { query = query.bind(v); }
    if let Some(v) = description { query = query.bind(v); }
    if let Some(v) = test_type { query = query.bind(v); }
    if let Some(v) = input_logs_json { query = query.bind(v); }
    if let Some(v) = expected_result_json { query = query.bind(v); }
    if let Some(v) = priority { query = query.bind(v); }
    if let Some(v) = tags_json { query = query.bind(v); }
    if let Some(v) = enabled { query = query.bind(v); }
    query = query.bind(id);

    let result = query.execute(pool).await?;
    Ok(result.rows_affected() > 0)
}

/// Delete test
pub async fn delete_detection_test(pool: &SqlitePool, id: &str) -> Result<bool> {
    let result = sqlx::query("DELETE FROM detection_tests WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;

    Ok(result.rows_affected() > 0)
}

// =============================================================================
// Test Run Operations
// =============================================================================

/// Record a test run
pub async fn record_test_run(
    pool: &SqlitePool,
    id: &str,
    test_id: &str,
    detection_id: &str,
    result_json: &str,
    actual_output_json: &str,
    passed: bool,
    detection_version: u32,
    environment: &str,
    triggered_by: Option<&str>,
) -> Result<()> {
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        INSERT INTO detection_test_runs (
            id, test_id, detection_id, result, actual_output, passed,
            detection_version, environment, triggered_by, run_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(id)
    .bind(test_id)
    .bind(detection_id)
    .bind(result_json)
    .bind(actual_output_json)
    .bind(passed)
    .bind(detection_version as i32)
    .bind(environment)
    .bind(triggered_by)
    .bind(&now)
    .execute(pool)
    .await?;

    Ok(())
}

/// Get test runs for a test
pub async fn get_test_runs(
    pool: &SqlitePool,
    test_id: &str,
    limit: u32,
) -> Result<Vec<TestRunRow>> {
    let rows = sqlx::query_as::<_, TestRunRow>(
        "SELECT * FROM detection_test_runs WHERE test_id = ? ORDER BY run_at DESC LIMIT ?",
    )
    .bind(test_id)
    .bind(limit as i32)
    .fetch_all(pool)
    .await?;

    Ok(rows)
}

/// Get latest test run for each test of a detection
pub async fn get_latest_test_runs_for_detection(
    pool: &SqlitePool,
    detection_id: &str,
) -> Result<Vec<TestRunRow>> {
    let rows = sqlx::query_as::<_, TestRunRow>(
        r#"
        SELECT tr.*
        FROM detection_test_runs tr
        INNER JOIN (
            SELECT test_id, MAX(run_at) as max_run_at
            FROM detection_test_runs
            WHERE detection_id = ?
            GROUP BY test_id
        ) latest ON tr.test_id = latest.test_id AND tr.run_at = latest.max_run_at
        "#,
    )
    .bind(detection_id)
    .fetch_all(pool)
    .await?;

    Ok(rows)
}

// =============================================================================
// Dashboard/Statistics
// =============================================================================

/// Get detection engineering dashboard statistics
pub async fn get_detection_dashboard_stats(pool: &SqlitePool) -> Result<DashboardStatsRow> {
    let total_detections: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM detections",
    )
    .fetch_one(pool)
    .await?;

    let production_detections: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM detections WHERE status = 'production' AND enabled = 1",
    )
    .fetch_one(pool)
    .await?;

    let testing_detections: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM detections WHERE status = 'testing'",
    )
    .fetch_one(pool)
    .await?;

    let draft_detections: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM detections WHERE status = 'draft'",
    )
    .fetch_one(pool)
    .await?;

    let pending_fps: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM false_positives WHERE status = 'pending' OR status = 'investigating'",
    )
    .fetch_one(pool)
    .await?;

    let total_tests: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM detection_tests WHERE enabled = 1",
    )
    .fetch_one(pool)
    .await?;

    let passing_tests: (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(DISTINCT tr.test_id)
        FROM detection_test_runs tr
        INNER JOIN (
            SELECT test_id, MAX(run_at) as max_run_at
            FROM detection_test_runs
            GROUP BY test_id
        ) latest ON tr.test_id = latest.test_id AND tr.run_at = latest.max_run_at
        WHERE tr.passed = 1
        "#,
    )
    .fetch_one(pool)
    .await?;

    let unique_techniques: (i64,) = sqlx::query_as(
        "SELECT COUNT(DISTINCT technique_id) FROM detection_coverage",
    )
    .fetch_one(pool)
    .await?;

    Ok(DashboardStatsRow {
        total_detections: total_detections.0,
        production_detections: production_detections.0,
        testing_detections: testing_detections.0,
        draft_detections: draft_detections.0,
        pending_false_positives: pending_fps.0,
        total_tests: total_tests.0,
        passing_tests: passing_tests.0,
        unique_techniques_covered: unique_techniques.0,
    })
}

// =============================================================================
// Row Types
// =============================================================================

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct DetectionRow {
    pub id: String,
    pub name: String,
    pub description: String,
    pub logic_yaml: String,
    pub data_sources: String,
    pub severity: String,
    pub status: String,
    pub author_id: String,
    pub version: i32,
    pub mitre_techniques: Option<String>,
    pub mitre_tactics: Option<String>,
    pub tags: Option<String>,
    pub fp_rate: Option<f64>,
    pub confidence: Option<f64>,
    pub enabled: bool,
    pub created_at: String,
    pub updated_at: String,
    pub author_name: Option<String>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct DetectionVersionRow {
    pub id: String,
    pub detection_id: String,
    pub version: i32,
    pub logic_yaml: String,
    pub change_notes: String,
    pub created_by: String,
    pub created_at: String,
    pub created_by_name: Option<String>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct CoverageMappingRow {
    pub detection_id: String,
    pub technique_id: String,
    pub coverage_type: String,
    pub notes: Option<String>,
    pub created_by: String,
    pub created_at: String,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct DataSourceRow {
    pub detection_id: String,
    pub data_source: String,
    pub required: bool,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct FalsePositiveRow {
    pub id: String,
    pub detection_id: String,
    pub alert_id: String,
    pub reason: String,
    pub explanation: Option<String>,
    pub evidence: Option<String>,
    pub pattern: Option<String>,
    pub exception_rule: Option<String>,
    pub status: String,
    pub priority: String,
    pub reported_by: String,
    pub assigned_to: Option<String>,
    pub resolution_notes: Option<String>,
    pub resolved_by: Option<String>,
    pub resolved_at: Option<String>,
    pub alert_data: Option<String>,
    pub tags: String,
    pub created_at: String,
    pub updated_at: String,
    pub reported_by_name: Option<String>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct DetectionTuningRow {
    pub id: String,
    pub detection_id: String,
    pub tuning_type: String,
    pub original_value: String,
    pub new_value: String,
    pub reason: String,
    pub related_fp_ids: String,
    pub applied_at: String,
    pub applied_by: String,
    pub active: bool,
    pub rolled_back_at: Option<String>,
    pub applied_by_name: Option<String>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct DetectionTestRow {
    pub id: String,
    pub detection_id: String,
    pub name: String,
    pub description: Option<String>,
    pub test_type: String,
    pub input_logs_json: String,
    pub expected_result: String,
    pub priority: String,
    pub tags: String,
    pub enabled: bool,
    pub created_by: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct TestRunRow {
    pub id: String,
    pub test_id: String,
    pub detection_id: String,
    pub result: String,
    pub actual_output: String,
    pub passed: bool,
    pub detection_version: i32,
    pub environment: String,
    pub triggered_by: Option<String>,
    pub run_at: String,
}

#[derive(Debug, Clone)]
pub struct DashboardStatsRow {
    pub total_detections: i64,
    pub production_detections: i64,
    pub testing_detections: i64,
    pub draft_detections: i64,
    pub pending_false_positives: i64,
    pub total_tests: i64,
    pub passing_tests: i64,
    pub unique_techniques_covered: i64,
}
