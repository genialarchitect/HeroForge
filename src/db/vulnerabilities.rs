//! Vulnerability tracking and remediation database operations

use sqlx::sqlite::SqlitePool;
use sqlx::Row;
use anyhow::Result;
use chrono::Utc;
use uuid::Uuid;

use super::models;

// ============================================================================
// Vulnerability Tracking Functions
// ============================================================================

/// Create vulnerability tracking record
pub async fn create_vulnerability_tracking(
    pool: &SqlitePool,
    scan_id: &str,
    host_ip: &str,
    port: Option<i32>,
    vulnerability_id: &str,
    severity: &str,
) -> Result<models::VulnerabilityTracking> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();

    let vuln = sqlx::query_as::<_, models::VulnerabilityTracking>(
        r#"
        INSERT INTO vulnerability_tracking
        (id, scan_id, host_ip, port, vulnerability_id, severity, status, created_at, updated_at)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
        RETURNING *
        "#,
    )
    .bind(&id)
    .bind(scan_id)
    .bind(host_ip)
    .bind(port)
    .bind(vulnerability_id)
    .bind(severity)
    .bind("open")
    .bind(now)
    .bind(now)
    .fetch_one(pool)
    .await?;

    Ok(vuln)
}

/// Get vulnerability tracking records by scan ID with optional filters
pub async fn get_vulnerability_tracking_by_scan(
    pool: &SqlitePool,
    scan_id: &str,
    status: Option<&str>,
    severity: Option<&str>,
) -> Result<Vec<models::VulnerabilityTracking>> {
    let mut query = String::from("SELECT * FROM vulnerability_tracking WHERE scan_id = ?1");
    let mut params = vec![scan_id.to_string()];

    if let Some(s) = status {
        query.push_str(" AND status = ?");
        params.push(s.to_string());
    }

    if let Some(sev) = severity {
        query.push_str(" AND severity = ?");
        params.push(sev.to_string());
    }

    query.push_str(" ORDER BY created_at DESC");

    let mut q = sqlx::query_as::<_, models::VulnerabilityTracking>(&query);
    for param in &params {
        q = q.bind(param);
    }

    let vulnerabilities = q.fetch_all(pool).await?;
    Ok(vulnerabilities)
}

/// Get single vulnerability with details
pub async fn get_vulnerability_detail(
    pool: &SqlitePool,
    vuln_id: &str,
) -> Result<models::VulnerabilityDetail> {
    let vulnerability = sqlx::query_as::<_, models::VulnerabilityTracking>(
        "SELECT * FROM vulnerability_tracking WHERE id = ?1",
    )
    .bind(vuln_id)
    .fetch_one(pool)
    .await?;

    // Get comments with user information
    let comments = sqlx::query_as::<_, models::VulnerabilityCommentWithUser>(
        r#"
        SELECT
            vc.id,
            vc.vulnerability_tracking_id,
            vc.user_id,
            u.username,
            vc.comment,
            vc.created_at
        FROM vulnerability_comments vc
        JOIN users u ON vc.user_id = u.id
        WHERE vc.vulnerability_tracking_id = ?1
        ORDER BY vc.created_at ASC
        "#,
    )
    .bind(vuln_id)
    .fetch_all(pool)
    .await?;

    // Get assignee info if exists
    let assignee = if let Some(assignee_id) = &vulnerability.assignee_id {
        sqlx::query_as::<_, models::User>("SELECT * FROM users WHERE id = ?1")
            .bind(assignee_id)
            .fetch_optional(pool)
            .await?
            .map(|u| u.into())
    } else {
        None
    };

    // Get resolved_by info if exists
    let resolved_by_user = if let Some(resolved_by) = &vulnerability.resolved_by {
        sqlx::query_as::<_, models::User>("SELECT * FROM users WHERE id = ?1")
            .bind(resolved_by)
            .fetch_optional(pool)
            .await?
            .map(|u| u.into())
    } else {
        None
    };

    // Get verified_by info if exists
    let verified_by_user = if let Some(verified_by) = &vulnerability.verified_by {
        sqlx::query_as::<_, models::User>("SELECT * FROM users WHERE id = ?1")
            .bind(verified_by)
            .fetch_optional(pool)
            .await?
            .map(|u| u.into())
    } else {
        None
    };

    // Get timeline events with user information
    let timeline = get_remediation_timeline(pool, vuln_id).await?;

    Ok(models::VulnerabilityDetail {
        vulnerability,
        comments,
        timeline,
        assignee,
        resolved_by_user,
        verified_by_user,
    })
}

/// Get remediation timeline for a vulnerability with user information
pub async fn get_remediation_timeline(
    pool: &SqlitePool,
    vuln_id: &str,
) -> Result<Vec<models::RemediationTimelineEventWithUser>> {
    let timeline = sqlx::query_as::<_, models::RemediationTimelineEventWithUser>(
        r#"
        SELECT
            rt.id,
            rt.vulnerability_tracking_id,
            rt.user_id,
            u.username,
            rt.event_type,
            rt.old_value,
            rt.new_value,
            rt.comment,
            rt.created_at
        FROM remediation_timeline rt
        JOIN users u ON rt.user_id = u.id
        WHERE rt.vulnerability_tracking_id = ?1
        ORDER BY rt.created_at DESC
        "#,
    )
    .bind(vuln_id)
    .fetch_all(pool)
    .await?;

    Ok(timeline)
}

/// Create timeline events for vulnerability update
async fn create_timeline_events_for_update(
    pool: &SqlitePool,
    vuln_id: &str,
    request: &models::UpdateVulnerabilityRequest,
    user_id: &str,
) -> Result<()> {
    let now = Utc::now();

    // Get current vulnerability state to track changes
    let current = sqlx::query_as::<_, models::VulnerabilityTracking>(
        "SELECT * FROM vulnerability_tracking WHERE id = ?1",
    )
    .bind(vuln_id)
    .fetch_one(pool)
    .await?;

    // Track status change
    if let Some(new_status) = &request.status {
        if &current.status != new_status {
            let id = Uuid::new_v4().to_string();
            sqlx::query(
                r#"
                INSERT INTO remediation_timeline (id, vulnerability_tracking_id, user_id, event_type, old_value, new_value, created_at)
                VALUES (?1, ?2, ?3, 'status_change', ?4, ?5, ?6)
                "#,
            )
            .bind(&id)
            .bind(vuln_id)
            .bind(user_id)
            .bind(&current.status)
            .bind(new_status)
            .bind(now)
            .execute(pool)
            .await?;
        }
    }

    // Track assignment change
    if let Some(new_assignee) = &request.assignee_id {
        if current.assignee_id.as_ref() != Some(new_assignee) {
            let id = Uuid::new_v4().to_string();
            sqlx::query(
                r#"
                INSERT INTO remediation_timeline (id, vulnerability_tracking_id, user_id, event_type, old_value, new_value, created_at)
                VALUES (?1, ?2, ?3, 'assignment', ?4, ?5, ?6)
                "#,
            )
            .bind(&id)
            .bind(vuln_id)
            .bind(user_id)
            .bind(current.assignee_id)
            .bind(new_assignee)
            .bind(now)
            .execute(pool)
            .await?;
        }
    }

    // Track priority change
    if let Some(new_priority) = &request.priority {
        if current.priority.as_ref() != Some(new_priority) {
            let id = Uuid::new_v4().to_string();
            sqlx::query(
                r#"
                INSERT INTO remediation_timeline (id, vulnerability_tracking_id, user_id, event_type, old_value, new_value, comment, created_at)
                VALUES (?1, ?2, ?3, 'priority_change', ?4, ?5, 'Priority updated', ?6)
                "#,
            )
            .bind(&id)
            .bind(vuln_id)
            .bind(user_id)
            .bind(current.priority)
            .bind(new_priority)
            .bind(now)
            .execute(pool)
            .await?;
        }
    }

    // Track notes update
    if let Some(new_notes) = &request.notes {
        if current.notes.as_ref() != Some(new_notes) {
            let id = Uuid::new_v4().to_string();
            sqlx::query(
                r#"
                INSERT INTO remediation_timeline (id, vulnerability_tracking_id, user_id, event_type, comment, created_at)
                VALUES (?1, ?2, ?3, 'note_added', ?4, ?5)
                "#,
            )
            .bind(&id)
            .bind(vuln_id)
            .bind(user_id)
            .bind(new_notes)
            .bind(now)
            .execute(pool)
            .await?;
        }
    }

    Ok(())
}

/// Update vulnerability status and metadata
pub async fn update_vulnerability_status(
    pool: &SqlitePool,
    vuln_id: &str,
    request: &models::UpdateVulnerabilityRequest,
    user_id: &str,
) -> Result<models::VulnerabilityTracking> {
    let now = Utc::now();

    // Build update query dynamically based on provided fields
    let mut update_parts = Vec::new();
    let mut param_count = 2;

    update_parts.push("updated_at = ?1".to_string());

    if request.status.is_some() {
        update_parts.push(format!("status = ?{}", param_count));
        param_count += 1;
    }
    if request.assignee_id.is_some() {
        update_parts.push(format!("assignee_id = ?{}", param_count));
        param_count += 1;
    }
    if request.notes.is_some() {
        update_parts.push(format!("notes = ?{}", param_count));
        param_count += 1;
    }
    if request.due_date.is_some() {
        update_parts.push(format!("due_date = ?{}", param_count));
        param_count += 1;
    }
    if request.priority.is_some() {
        update_parts.push(format!("priority = ?{}", param_count));
        param_count += 1;
    }
    if request.remediation_steps.is_some() {
        update_parts.push(format!("remediation_steps = ?{}", param_count));
        param_count += 1;
    }
    if request.estimated_effort.is_some() {
        update_parts.push(format!("estimated_effort = ?{}", param_count));
        param_count += 1;
    }
    if request.actual_effort.is_some() {
        update_parts.push(format!("actual_effort = ?{}", param_count));
        param_count += 1;
    }

    // Check if status is being set to 'resolved'
    if let Some(status) = &request.status {
        if status == "resolved" {
            update_parts.push(format!("resolved_at = ?{}", param_count));
            param_count += 1;
            update_parts.push(format!("resolved_by = ?{}", param_count));
        }
    }

    let query = format!(
        "UPDATE vulnerability_tracking SET {} WHERE id = ?{}",
        update_parts.join(", "),
        param_count
    );

    let mut q = sqlx::query(&query).bind(now);

    if let Some(status) = &request.status {
        q = q.bind(status);
        if status == "resolved" {
            q = q.bind(now).bind(user_id);
        }
    }
    if let Some(assignee_id) = &request.assignee_id {
        q = q.bind(assignee_id);
    }
    if let Some(notes) = &request.notes {
        q = q.bind(notes);
    }
    if let Some(due_date) = &request.due_date {
        q = q.bind(due_date);
    }
    if let Some(priority) = &request.priority {
        q = q.bind(priority);
    }
    if let Some(remediation_steps) = &request.remediation_steps {
        q = q.bind(remediation_steps);
    }
    if let Some(estimated_effort) = &request.estimated_effort {
        q = q.bind(estimated_effort);
    }
    if let Some(actual_effort) = &request.actual_effort {
        q = q.bind(actual_effort);
    }

    q = q.bind(vuln_id);
    q.execute(pool).await?;

    // Create timeline events for the changes
    create_timeline_events_for_update(pool, vuln_id, request, user_id).await?;

    // Return updated vulnerability
    let updated = sqlx::query_as::<_, models::VulnerabilityTracking>(
        "SELECT * FROM vulnerability_tracking WHERE id = ?1",
    )
    .bind(vuln_id)
    .fetch_one(pool)
    .await?;

    Ok(updated)
}

/// Add comment to vulnerability
pub async fn add_vulnerability_comment(
    pool: &SqlitePool,
    vuln_id: &str,
    user_id: &str,
    comment: &str,
) -> Result<models::VulnerabilityComment> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();

    let comment_record = sqlx::query_as::<_, models::VulnerabilityComment>(
        r#"
        INSERT INTO vulnerability_comments (id, vulnerability_tracking_id, user_id, comment, created_at)
        VALUES (?1, ?2, ?3, ?4, ?5)
        RETURNING *
        "#,
    )
    .bind(&id)
    .bind(vuln_id)
    .bind(user_id)
    .bind(comment)
    .bind(now)
    .fetch_one(pool)
    .await?;

    Ok(comment_record)
}

/// Get comments for a vulnerability
pub async fn get_vulnerability_comments(
    pool: &SqlitePool,
    vuln_id: &str,
) -> Result<Vec<models::VulnerabilityComment>> {
    let comments = sqlx::query_as::<_, models::VulnerabilityComment>(
        "SELECT * FROM vulnerability_comments WHERE vulnerability_tracking_id = ?1 ORDER BY created_at ASC",
    )
    .bind(vuln_id)
    .fetch_all(pool)
    .await?;

    Ok(comments)
}

/// Bulk update vulnerability statuses
pub async fn bulk_update_vulnerability_status(
    pool: &SqlitePool,
    vulnerability_ids: &[String],
    status: Option<&str>,
    assignee_id: Option<&str>,
    due_date: Option<chrono::DateTime<Utc>>,
    priority: Option<&str>,
    user_id: &str,
) -> Result<usize> {
    if vulnerability_ids.is_empty() {
        return Ok(0);
    }

    let now = Utc::now();

    // Use a transaction for bulk updates
    let mut tx = pool.begin().await?;
    let mut updated_count = 0;

    for vuln_id in vulnerability_ids {
        // Build dynamic update query
        let mut set_parts = vec!["updated_at = ?1".to_string()];
        let mut param_count = 2;

        if status.is_some() {
            set_parts.push(format!("status = ?{}", param_count));
            param_count += 1;
        }
        if assignee_id.is_some() {
            set_parts.push(format!("assignee_id = ?{}", param_count));
            param_count += 1;
        }
        if due_date.is_some() {
            set_parts.push(format!("due_date = ?{}", param_count));
            param_count += 1;
        }
        if priority.is_some() {
            set_parts.push(format!("priority = ?{}", param_count));
            param_count += 1;
        }

        // Handle resolved status special case
        let is_resolving = status.map(|s| s == "resolved").unwrap_or(false);
        if is_resolving {
            set_parts.push(format!("resolved_at = ?{}", param_count));
            param_count += 1;
            set_parts.push(format!("resolved_by = ?{}", param_count));
            param_count += 1;
        }

        let query_str = format!(
            "UPDATE vulnerability_tracking SET {} WHERE id = ?{}",
            set_parts.join(", "),
            param_count
        );

        let mut q = sqlx::query(&query_str).bind(now);

        if let Some(s) = status {
            q = q.bind(s);
        }
        if let Some(assignee) = assignee_id {
            q = q.bind(assignee);
        }
        if let Some(dd) = &due_date {
            q = q.bind(dd);
        }
        if let Some(p) = priority {
            q = q.bind(p);
        }
        if is_resolving {
            q = q.bind(now).bind(user_id);
        }
        q = q.bind(vuln_id);

        let result = q.execute(&mut *tx).await?;
        if result.rows_affected() > 0 {
            updated_count += 1;

            // Create timeline events for each update
            if let Some(s) = status {
                let event_id = Uuid::new_v4().to_string();
                sqlx::query(
                    r#"
                    INSERT INTO remediation_timeline (id, vulnerability_tracking_id, user_id, event_type, new_value, comment, created_at)
                    VALUES (?1, ?2, ?3, 'status_change', ?4, 'Bulk status update', ?5)
                    "#,
                )
                .bind(&event_id)
                .bind(vuln_id)
                .bind(user_id)
                .bind(s)
                .bind(now)
                .execute(&mut *tx)
                .await?;
            }
            if let Some(assignee) = assignee_id {
                let event_id = Uuid::new_v4().to_string();
                sqlx::query(
                    r#"
                    INSERT INTO remediation_timeline (id, vulnerability_tracking_id, user_id, event_type, new_value, comment, created_at)
                    VALUES (?1, ?2, ?3, 'assignment', ?4, 'Bulk assignment', ?5)
                    "#,
                )
                .bind(&event_id)
                .bind(vuln_id)
                .bind(user_id)
                .bind(assignee)
                .bind(now)
                .execute(&mut *tx)
                .await?;
            }
        }
    }

    tx.commit().await?;
    Ok(updated_count)
}

/// Mark vulnerability for verification
pub async fn mark_vulnerability_for_verification(
    pool: &SqlitePool,
    vuln_id: &str,
    scan_id: Option<&str>,
    user_id: &str,
) -> Result<models::VulnerabilityTracking> {
    let now = Utc::now();

    // Update status to pending_verification
    if let Some(sid) = scan_id {
        sqlx::query(
            "UPDATE vulnerability_tracking SET status = 'pending_verification', updated_at = ?1, verification_scan_id = ?2 WHERE id = ?3",
        )
        .bind(now)
        .bind(sid)
        .bind(vuln_id)
        .execute(pool)
        .await?;
    } else {
        sqlx::query(
            "UPDATE vulnerability_tracking SET status = 'pending_verification', updated_at = ?1 WHERE id = ?2",
        )
        .bind(now)
        .bind(vuln_id)
        .execute(pool)
        .await?;
    }

    // Create timeline event
    let event_id = Uuid::new_v4().to_string();
    sqlx::query(
        r#"
        INSERT INTO remediation_timeline (id, vulnerability_tracking_id, user_id, event_type, old_value, new_value, comment, created_at)
        VALUES (?1, ?2, ?3, 'verification_requested', NULL, ?4, 'Marked for verification', ?5)
        "#,
    )
    .bind(&event_id)
    .bind(vuln_id)
    .bind(user_id)
    .bind(scan_id)
    .bind(now)
    .execute(pool)
    .await?;

    // Return updated vulnerability
    let updated = sqlx::query_as::<_, models::VulnerabilityTracking>(
        "SELECT * FROM vulnerability_tracking WHERE id = ?1",
    )
    .bind(vuln_id)
    .fetch_one(pool)
    .await?;

    Ok(updated)
}

/// Bulk assign vulnerabilities to a user
pub async fn bulk_assign_vulnerabilities(
    pool: &SqlitePool,
    vulnerability_ids: &[String],
    assignee_id: &str,
    user_id: &str,
) -> Result<usize> {
    if vulnerability_ids.is_empty() {
        return Ok(0);
    }

    let now = Utc::now();
    let mut tx = pool.begin().await?;
    let mut updated_count = 0;

    for vuln_id in vulnerability_ids {
        // Update assignee
        let result = sqlx::query(
            "UPDATE vulnerability_tracking SET updated_at = ?1, assignee_id = ?2 WHERE id = ?3",
        )
        .bind(now)
        .bind(assignee_id)
        .bind(vuln_id)
        .execute(&mut *tx)
        .await?;

        if result.rows_affected() > 0 {
            // Create timeline event
            let event_id = Uuid::new_v4().to_string();
            sqlx::query(
                r#"
                INSERT INTO remediation_timeline (id, vulnerability_tracking_id, user_id, event_type, old_value, new_value, comment, created_at)
                VALUES (?1, ?2, ?3, 'assignment', NULL, ?4, 'Bulk assigned', ?5)
                "#,
            )
            .bind(&event_id)
            .bind(vuln_id)
            .bind(user_id)
            .bind(assignee_id)
            .bind(now)
            .execute(&mut *tx)
            .await?;

            updated_count += 1;
        }
    }

    tx.commit().await?;
    Ok(updated_count)
}

/// Validate workflow state transitions
pub fn validate_status_transition(current_status: &str, new_status: &str) -> Result<()> {
    // State machine: open -> in_progress -> pending_verification -> resolved
    // Can also go to false_positive or accepted_risk from any state
    let valid_transitions = match current_status {
        "open" => vec!["in_progress", "false_positive", "accepted_risk", "resolved"],
        "in_progress" => vec!["open", "pending_verification", "resolved", "false_positive", "accepted_risk"],
        "pending_verification" => vec!["in_progress", "resolved", "false_positive"],
        "resolved" => vec!["in_progress", "open"], // Allow reopening
        "false_positive" => vec!["open", "in_progress"],
        "accepted_risk" => vec!["open", "in_progress"],
        _ => vec![],
    };

    if !valid_transitions.contains(&new_status) {
        return Err(anyhow::anyhow!(
            "Invalid status transition from '{}' to '{}'",
            current_status,
            new_status
        ));
    }

    Ok(())
}

/// Get vulnerability statistics for a scan
pub async fn get_vulnerability_statistics(
    pool: &SqlitePool,
    scan_id: Option<&str>,
) -> Result<models::VulnerabilityStats> {
    let query = if let Some(sid) = scan_id {
        format!(
            r#"
            SELECT
                COUNT(*) as total,
                SUM(CASE WHEN status = 'open' THEN 1 ELSE 0 END) as open,
                SUM(CASE WHEN status = 'in_progress' THEN 1 ELSE 0 END) as in_progress,
                SUM(CASE WHEN status = 'resolved' THEN 1 ELSE 0 END) as resolved,
                SUM(CASE WHEN status = 'false_positive' THEN 1 ELSE 0 END) as false_positive,
                SUM(CASE WHEN status = 'accepted_risk' THEN 1 ELSE 0 END) as accepted_risk,
                SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical,
                SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as high,
                SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END) as medium,
                SUM(CASE WHEN severity = 'low' THEN 1 ELSE 0 END) as low
            FROM vulnerability_tracking
            WHERE scan_id = '{}'
            "#,
            sid
        )
    } else {
        r#"
        SELECT
            COUNT(*) as total,
            SUM(CASE WHEN status = 'open' THEN 1 ELSE 0 END) as open,
            SUM(CASE WHEN status = 'in_progress' THEN 1 ELSE 0 END) as in_progress,
            SUM(CASE WHEN status = 'resolved' THEN 1 ELSE 0 END) as resolved,
            SUM(CASE WHEN status = 'false_positive' THEN 1 ELSE 0 END) as false_positive,
            SUM(CASE WHEN status = 'accepted_risk' THEN 1 ELSE 0 END) as accepted_risk,
            SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical,
            SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as high,
            SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END) as medium,
            SUM(CASE WHEN severity = 'low' THEN 1 ELSE 0 END) as low
        FROM vulnerability_tracking
        "#
        .to_string()
    };

    let row = sqlx::query(&query).fetch_one(pool).await?;

    let stats = models::VulnerabilityStats {
        total: row.try_get("total").unwrap_or(0),
        open: row.try_get("open").unwrap_or(0),
        in_progress: row.try_get("in_progress").unwrap_or(0),
        resolved: row.try_get("resolved").unwrap_or(0),
        false_positive: row.try_get("false_positive").unwrap_or(0),
        accepted_risk: row.try_get("accepted_risk").unwrap_or(0),
        critical: row.try_get("critical").unwrap_or(0),
        high: row.try_get("high").unwrap_or(0),
        medium: row.try_get("medium").unwrap_or(0),
        low: row.try_get("low").unwrap_or(0),
    };

    Ok(stats)
}

// ============================================================================
// Retest Workflow Functions
// ============================================================================

/// Request a retest for a vulnerability
pub async fn request_vulnerability_retest(
    pool: &SqlitePool,
    vuln_id: &str,
    user_id: &str,
    notes: Option<&str>,
) -> Result<models::VulnerabilityTracking> {
    let now = Utc::now();

    // Update the vulnerability with retest request info
    sqlx::query(
        r#"
        UPDATE vulnerability_tracking
        SET updated_at = ?1,
            retest_requested_at = ?2,
            retest_requested_by = ?3,
            retest_completed_at = NULL,
            retest_result = NULL,
            retest_scan_id = NULL
        WHERE id = ?4
        "#,
    )
    .bind(now)
    .bind(now)
    .bind(user_id)
    .bind(vuln_id)
    .execute(pool)
    .await?;

    // Create timeline event
    let event_id = Uuid::new_v4().to_string();
    sqlx::query(
        r#"
        INSERT INTO remediation_timeline (id, vulnerability_tracking_id, user_id, event_type, new_value, comment, created_at)
        VALUES (?1, ?2, ?3, 'retest_requested', 'pending', ?4, ?5)
        "#,
    )
    .bind(&event_id)
    .bind(vuln_id)
    .bind(user_id)
    .bind(notes.unwrap_or("Retest requested"))
    .bind(now)
    .execute(pool)
    .await?;

    // Return updated vulnerability
    let updated = sqlx::query_as::<_, models::VulnerabilityTracking>(
        "SELECT * FROM vulnerability_tracking WHERE id = ?1",
    )
    .bind(vuln_id)
    .fetch_one(pool)
    .await?;

    Ok(updated)
}

/// Bulk request retests for multiple vulnerabilities
pub async fn bulk_request_retests(
    pool: &SqlitePool,
    vulnerability_ids: &[String],
    user_id: &str,
    notes: Option<&str>,
) -> Result<usize> {
    if vulnerability_ids.is_empty() {
        return Ok(0);
    }

    let now = Utc::now();
    let mut tx = pool.begin().await?;
    let mut updated_count = 0;

    for vuln_id in vulnerability_ids {
        // Update the vulnerability with retest request info
        let result = sqlx::query(
            r#"
            UPDATE vulnerability_tracking
            SET updated_at = ?1,
                retest_requested_at = ?2,
                retest_requested_by = ?3,
                retest_completed_at = NULL,
                retest_result = NULL,
                retest_scan_id = NULL
            WHERE id = ?4
            "#,
        )
        .bind(now)
        .bind(now)
        .bind(user_id)
        .bind(vuln_id)
        .execute(&mut *tx)
        .await?;

        if result.rows_affected() > 0 {
            // Create timeline event
            let event_id = Uuid::new_v4().to_string();
            sqlx::query(
                r#"
                INSERT INTO remediation_timeline (id, vulnerability_tracking_id, user_id, event_type, new_value, comment, created_at)
                VALUES (?1, ?2, ?3, 'retest_requested', 'pending', ?4, ?5)
                "#,
            )
            .bind(&event_id)
            .bind(vuln_id)
            .bind(user_id)
            .bind(notes.unwrap_or("Bulk retest requested"))
            .bind(now)
            .execute(&mut *tx)
            .await?;

            updated_count += 1;
        }
    }

    tx.commit().await?;
    Ok(updated_count)
}

/// Complete a retest with a result
pub async fn complete_vulnerability_retest(
    pool: &SqlitePool,
    vuln_id: &str,
    result: &str,
    scan_id: Option<&str>,
    user_id: &str,
    notes: Option<&str>,
) -> Result<models::VulnerabilityTracking> {
    // Validate result
    let valid_results = ["still_vulnerable", "remediated", "partially_remediated"];
    if !valid_results.contains(&result) {
        return Err(anyhow::anyhow!(
            "Invalid retest result '{}'. Must be one of: {}",
            result,
            valid_results.join(", ")
        ));
    }

    let now = Utc::now();

    // Update the vulnerability with retest completion
    sqlx::query(
        r#"
        UPDATE vulnerability_tracking
        SET updated_at = ?1,
            retest_completed_at = ?2,
            retest_result = ?3,
            retest_scan_id = ?4
        WHERE id = ?5
        "#,
    )
    .bind(now)
    .bind(now)
    .bind(result)
    .bind(scan_id)
    .bind(vuln_id)
    .execute(pool)
    .await?;

    // If remediated, also update the status
    if result == "remediated" {
        sqlx::query(
            "UPDATE vulnerability_tracking SET status = 'resolved', resolved_at = ?1, resolved_by = ?2 WHERE id = ?3",
        )
        .bind(now)
        .bind(user_id)
        .bind(vuln_id)
        .execute(pool)
        .await?;
    }

    // Create timeline event
    let event_id = Uuid::new_v4().to_string();
    sqlx::query(
        r#"
        INSERT INTO remediation_timeline (id, vulnerability_tracking_id, user_id, event_type, old_value, new_value, comment, created_at)
        VALUES (?1, ?2, ?3, 'retest_completed', 'pending', ?4, ?5, ?6)
        "#,
    )
    .bind(&event_id)
    .bind(vuln_id)
    .bind(user_id)
    .bind(result)
    .bind(notes.unwrap_or(&format!("Retest completed: {}", result)))
    .bind(now)
    .execute(pool)
    .await?;

    // Return updated vulnerability
    let updated = sqlx::query_as::<_, models::VulnerabilityTracking>(
        "SELECT * FROM vulnerability_tracking WHERE id = ?1",
    )
    .bind(vuln_id)
    .fetch_one(pool)
    .await?;

    Ok(updated)
}

/// Get vulnerabilities pending retest (requested but not completed)
pub async fn get_vulnerabilities_pending_retest(
    pool: &SqlitePool,
    scan_id: Option<&str>,
) -> Result<Vec<models::VulnerabilityTracking>> {
    let vulnerabilities = if let Some(sid) = scan_id {
        sqlx::query_as::<_, models::VulnerabilityTracking>(
            r#"
            SELECT * FROM vulnerability_tracking
            WHERE scan_id = ?1
              AND retest_requested_at IS NOT NULL
              AND retest_completed_at IS NULL
            ORDER BY retest_requested_at DESC
            "#,
        )
        .bind(sid)
        .fetch_all(pool)
        .await?
    } else {
        sqlx::query_as::<_, models::VulnerabilityTracking>(
            r#"
            SELECT * FROM vulnerability_tracking
            WHERE retest_requested_at IS NOT NULL
              AND retest_completed_at IS NULL
            ORDER BY retest_requested_at DESC
            "#,
        )
        .fetch_all(pool)
        .await?
    };

    Ok(vulnerabilities)
}

/// Get retest history for a vulnerability from timeline
pub async fn get_retest_history(
    pool: &SqlitePool,
    vuln_id: &str,
) -> Result<Vec<models::RemediationTimelineEventWithUser>> {
    let history = sqlx::query_as::<_, models::RemediationTimelineEventWithUser>(
        r#"
        SELECT
            rt.id,
            rt.vulnerability_tracking_id,
            rt.user_id,
            u.username,
            rt.event_type,
            rt.old_value,
            rt.new_value,
            rt.comment,
            rt.created_at
        FROM remediation_timeline rt
        JOIN users u ON rt.user_id = u.id
        WHERE rt.vulnerability_tracking_id = ?1
          AND rt.event_type IN ('retest_requested', 'retest_completed')
        ORDER BY rt.created_at DESC
        "#,
    )
    .bind(vuln_id)
    .fetch_all(pool)
    .await?;

    Ok(history)
}
