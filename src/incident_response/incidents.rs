//! Incident Management Module
//!
//! Provides incident lifecycle management:
//! - Create, update, and close incidents
//! - Status transitions (detected -> triaged -> contained -> eradicated -> recovered -> closed)
//! - Assignment and escalation
//! - SLA tracking based on severity

use anyhow::Result;
use chrono::{Duration, Utc};
use sqlx::SqlitePool;
use uuid::Uuid;

use super::types::*;

/// Get SLA hours based on incident severity
pub fn get_sla_hours(severity: &IncidentSeverity) -> i64 {
    match severity {
        IncidentSeverity::P1 => 1,   // 1 hour for critical
        IncidentSeverity::P2 => 4,   // 4 hours for high
        IncidentSeverity::P3 => 24,  // 24 hours for medium
        IncidentSeverity::P4 => 72,  // 72 hours for low
    }
}

/// Create a new incident
pub async fn create_incident(
    pool: &SqlitePool,
    user_id: &str,
    request: CreateIncidentRequest,
    organization_id: Option<&str>,
) -> Result<Incident> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();

    // Calculate SLA breach time based on severity
    let severity: IncidentSeverity = request.severity.parse().unwrap_or_default();
    let sla_hours = get_sla_hours(&severity);
    let sla_breach_at = now + Duration::hours(sla_hours);

    let incident = sqlx::query_as::<_, Incident>(
        r#"
        INSERT INTO incidents
        (id, title, description, severity, classification, status, assignee_id,
         sla_breach_at, created_at, updated_at, user_id, organization_id)
        VALUES (?1, ?2, ?3, ?4, ?5, 'detected', ?6, ?7, ?8, ?9, ?10, ?11)
        RETURNING *
        "#,
    )
    .bind(&id)
    .bind(&request.title)
    .bind(&request.description)
    .bind(&request.severity)
    .bind(&request.classification)
    .bind(&request.assignee_id)
    .bind(sla_breach_at)
    .bind(now)
    .bind(now)
    .bind(user_id)
    .bind(organization_id)
    .fetch_one(pool)
    .await?;

    Ok(incident)
}

/// Get an incident by ID
pub async fn get_incident(pool: &SqlitePool, incident_id: &str) -> Result<Incident> {
    let incident = sqlx::query_as::<_, Incident>(
        "SELECT * FROM incidents WHERE id = ?1"
    )
    .bind(incident_id)
    .fetch_one(pool)
    .await?;

    Ok(incident)
}

/// Get an incident with all related details
pub async fn get_incident_with_details(pool: &SqlitePool, incident_id: &str) -> Result<IncidentWithDetails> {
    let incident = get_incident(pool, incident_id).await?;

    // Get assignee name
    let assignee_name: Option<String> = if let Some(ref assignee_id) = incident.assignee_id {
        sqlx::query_scalar("SELECT username FROM users WHERE id = ?1")
            .bind(assignee_id)
            .fetch_optional(pool)
            .await?
    } else {
        None
    };

    // Get creator name
    let creator_name: Option<String> = sqlx::query_scalar(
        "SELECT username FROM users WHERE id = ?1"
    )
    .bind(&incident.user_id)
    .fetch_optional(pool)
    .await?;

    // Get counts
    let alert_count: i32 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM incident_alerts WHERE incident_id = ?1"
    )
    .bind(incident_id)
    .fetch_one(pool)
    .await
    .unwrap_or(0);

    let ioc_count: i32 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM incident_iocs WHERE incident_id = ?1"
    )
    .bind(incident_id)
    .fetch_one(pool)
    .await
    .unwrap_or(0);

    let evidence_count: i32 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM incident_evidence WHERE incident_id = ?1"
    )
    .bind(incident_id)
    .fetch_one(pool)
    .await
    .unwrap_or(0);

    let timeline_event_count: i32 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM incident_timeline WHERE incident_id = ?1"
    )
    .bind(incident_id)
    .fetch_one(pool)
    .await
    .unwrap_or(0);

    Ok(IncidentWithDetails {
        incident,
        assignee_name,
        creator_name,
        alert_count,
        ioc_count,
        evidence_count,
        timeline_event_count,
    })
}

/// List all incidents with optional filters
pub async fn list_incidents(
    pool: &SqlitePool,
    status: Option<&str>,
    severity: Option<&str>,
    classification: Option<&str>,
    assignee_id: Option<&str>,
    organization_id: Option<&str>,
    limit: Option<i64>,
    offset: Option<i64>,
) -> Result<Vec<Incident>> {
    let mut query = String::from("SELECT * FROM incidents WHERE 1=1");
    let mut params: Vec<String> = Vec::new();

    if let Some(s) = status {
        params.push(s.to_string());
        query.push_str(&format!(" AND status = ?{}", params.len()));
    }
    if let Some(s) = severity {
        params.push(s.to_string());
        query.push_str(&format!(" AND severity = ?{}", params.len()));
    }
    if let Some(c) = classification {
        params.push(c.to_string());
        query.push_str(&format!(" AND classification = ?{}", params.len()));
    }
    if let Some(a) = assignee_id {
        params.push(a.to_string());
        query.push_str(&format!(" AND assignee_id = ?{}", params.len()));
    }
    if let Some(o) = organization_id {
        params.push(o.to_string());
        query.push_str(&format!(" AND organization_id = ?{}", params.len()));
    }

    query.push_str(" ORDER BY created_at DESC");

    if let Some(l) = limit {
        query.push_str(&format!(" LIMIT {}", l));
    }
    if let Some(o) = offset {
        query.push_str(&format!(" OFFSET {}", o));
    }

    let mut q = sqlx::query_as::<_, Incident>(&query);
    for param in &params {
        q = q.bind(param);
    }

    let incidents = q.fetch_all(pool).await?;
    Ok(incidents)
}

/// Update an incident
pub async fn update_incident(
    pool: &SqlitePool,
    incident_id: &str,
    request: UpdateIncidentRequest,
) -> Result<Incident> {
    let now = Utc::now();
    let existing = get_incident(pool, incident_id).await?;

    let title = request.title.unwrap_or(existing.title);
    let description = request.description.or(existing.description);
    let severity_changed = request.severity.is_some();
    let severity = request.severity.unwrap_or(existing.severity);
    let classification = request.classification.unwrap_or(existing.classification);

    // Recalculate SLA if severity changed
    let sla_breach_at = if severity_changed {
        let new_severity: IncidentSeverity = severity.parse().unwrap_or_default();
        let sla_hours = get_sla_hours(&new_severity);
        Some(existing.created_at + Duration::hours(sla_hours))
    } else {
        existing.sla_breach_at
    };

    let incident = sqlx::query_as::<_, Incident>(
        r#"
        UPDATE incidents
        SET title = ?1, description = ?2, severity = ?3, classification = ?4,
            sla_breach_at = ?5, updated_at = ?6
        WHERE id = ?7
        RETURNING *
        "#,
    )
    .bind(&title)
    .bind(&description)
    .bind(&severity)
    .bind(&classification)
    .bind(sla_breach_at)
    .bind(now)
    .bind(incident_id)
    .fetch_one(pool)
    .await?;

    Ok(incident)
}

/// Update incident status with lifecycle validation
pub async fn update_incident_status(
    pool: &SqlitePool,
    incident_id: &str,
    new_status: &str,
) -> Result<Incident> {
    let now = Utc::now();
    let _existing = get_incident(pool, incident_id).await?;

    // Validate status transition (could add more strict validation)
    let new_status_enum: IncidentStatus = new_status.parse()?;

    let closed_at = if new_status_enum == IncidentStatus::Closed {
        Some(now)
    } else {
        None
    };

    let incident = sqlx::query_as::<_, Incident>(
        r#"
        UPDATE incidents
        SET status = ?1, updated_at = ?2, closed_at = ?3
        WHERE id = ?4
        RETURNING *
        "#,
    )
    .bind(new_status)
    .bind(now)
    .bind(closed_at)
    .bind(incident_id)
    .fetch_one(pool)
    .await?;

    Ok(incident)
}

/// Assign an incident to a user
pub async fn assign_incident(
    pool: &SqlitePool,
    incident_id: &str,
    assignee_id: Option<&str>,
) -> Result<Incident> {
    let now = Utc::now();

    let incident = sqlx::query_as::<_, Incident>(
        r#"
        UPDATE incidents
        SET assignee_id = ?1, updated_at = ?2
        WHERE id = ?3
        RETURNING *
        "#,
    )
    .bind(assignee_id)
    .bind(now)
    .bind(incident_id)
    .fetch_one(pool)
    .await?;

    Ok(incident)
}

/// Link an alert to an incident
pub async fn link_alert(
    pool: &SqlitePool,
    incident_id: &str,
    alert_id: &str,
) -> Result<()> {
    sqlx::query(
        "INSERT OR IGNORE INTO incident_alerts (incident_id, alert_id) VALUES (?1, ?2)"
    )
    .bind(incident_id)
    .bind(alert_id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Unlink an alert from an incident
pub async fn unlink_alert(
    pool: &SqlitePool,
    incident_id: &str,
    alert_id: &str,
) -> Result<()> {
    sqlx::query(
        "DELETE FROM incident_alerts WHERE incident_id = ?1 AND alert_id = ?2"
    )
    .bind(incident_id)
    .bind(alert_id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Get alerts linked to an incident
pub async fn get_incident_alerts(
    pool: &SqlitePool,
    incident_id: &str,
) -> Result<Vec<String>> {
    let alerts: Vec<String> = sqlx::query_scalar(
        "SELECT alert_id FROM incident_alerts WHERE incident_id = ?1"
    )
    .bind(incident_id)
    .fetch_all(pool)
    .await?;

    Ok(alerts)
}

/// Link an IOC to an incident
pub async fn link_ioc(
    pool: &SqlitePool,
    incident_id: &str,
    ioc_id: &str,
) -> Result<()> {
    sqlx::query(
        "INSERT OR IGNORE INTO incident_iocs (incident_id, ioc_id) VALUES (?1, ?2)"
    )
    .bind(incident_id)
    .bind(ioc_id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Unlink an IOC from an incident
pub async fn unlink_ioc(
    pool: &SqlitePool,
    incident_id: &str,
    ioc_id: &str,
) -> Result<()> {
    sqlx::query(
        "DELETE FROM incident_iocs WHERE incident_id = ?1 AND ioc_id = ?2"
    )
    .bind(incident_id)
    .bind(ioc_id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Get IOCs linked to an incident
pub async fn get_incident_iocs(
    pool: &SqlitePool,
    incident_id: &str,
) -> Result<Vec<String>> {
    let iocs: Vec<String> = sqlx::query_scalar(
        "SELECT ioc_id FROM incident_iocs WHERE incident_id = ?1"
    )
    .bind(incident_id)
    .fetch_all(pool)
    .await?;

    Ok(iocs)
}

/// Delete an incident
pub async fn delete_incident(pool: &SqlitePool, incident_id: &str) -> Result<()> {
    sqlx::query("DELETE FROM incidents WHERE id = ?1")
        .bind(incident_id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Get incident dashboard statistics
pub async fn get_dashboard_stats(
    pool: &SqlitePool,
    organization_id: Option<&str>,
) -> Result<IncidentDashboardStats> {
    let org_filter = if organization_id.is_some() {
        " AND organization_id = ?1"
    } else {
        ""
    };

    // Total incidents
    let total_query = format!("SELECT COUNT(*) FROM incidents WHERE 1=1{}", org_filter);
    let mut q = sqlx::query_scalar::<_, i64>(&total_query);
    if let Some(org) = organization_id {
        q = q.bind(org);
    }
    let total_incidents = q.fetch_one(pool).await.unwrap_or(0);

    // Open incidents (not closed)
    let open_query = format!("SELECT COUNT(*) FROM incidents WHERE status != 'closed'{}", org_filter);
    let mut q = sqlx::query_scalar::<_, i64>(&open_query);
    if let Some(org) = organization_id {
        q = q.bind(org);
    }
    let open_incidents = q.fetch_one(pool).await.unwrap_or(0);

    // Incidents by severity
    let severity_query = format!(
        "SELECT severity, COUNT(*) as count FROM incidents WHERE 1=1{} GROUP BY severity",
        org_filter
    );
    let mut q = sqlx::query_as::<_, (String, i64)>(&severity_query);
    if let Some(org) = organization_id {
        q = q.bind(org);
    }
    let severity_rows = q.fetch_all(pool).await.unwrap_or_default();
    let incidents_by_severity: Vec<SeverityCount> = severity_rows
        .into_iter()
        .map(|(severity, count)| SeverityCount { severity, count })
        .collect();

    // Incidents by status
    let status_query = format!(
        "SELECT status, COUNT(*) as count FROM incidents WHERE 1=1{} GROUP BY status",
        org_filter
    );
    let mut q = sqlx::query_as::<_, (String, i64)>(&status_query);
    if let Some(org) = organization_id {
        q = q.bind(org);
    }
    let status_rows = q.fetch_all(pool).await.unwrap_or_default();
    let incidents_by_status: Vec<StatusCount> = status_rows
        .into_iter()
        .map(|(status, count)| StatusCount { status, count })
        .collect();

    // Incidents by classification
    let class_query = format!(
        "SELECT classification, COUNT(*) as count FROM incidents WHERE 1=1{} GROUP BY classification",
        org_filter
    );
    let mut q = sqlx::query_as::<_, (String, i64)>(&class_query);
    if let Some(org) = organization_id {
        q = q.bind(org);
    }
    let class_rows = q.fetch_all(pool).await.unwrap_or_default();
    let incidents_by_classification: Vec<ClassificationCount> = class_rows
        .into_iter()
        .map(|(classification, count)| ClassificationCount { classification, count })
        .collect();

    // SLA breaches
    let now = Utc::now();
    let sla_query = format!(
        "SELECT COUNT(*) FROM incidents WHERE sla_breach_at < ?1 AND status != 'closed'{}",
        org_filter
    );
    let mut q = sqlx::query_scalar::<_, i64>(&sla_query).bind(now);
    if let Some(org) = organization_id {
        q = q.bind(org);
    }
    let sla_breaches = q.fetch_one(pool).await.unwrap_or(0);

    // Mean time to contain (for incidents that have reached 'contained' status)
    let mttc_query = format!(
        r#"
        SELECT AVG(
            (julianday(updated_at) - julianday(created_at)) * 24
        ) as hours
        FROM incidents
        WHERE status IN ('contained', 'eradicated', 'recovered', 'closed'){}
        "#,
        org_filter
    );
    let mut q = sqlx::query_scalar::<_, Option<f64>>(&mttc_query);
    if let Some(org) = organization_id {
        q = q.bind(org);
    }
    let mean_time_to_contain_hours = q.fetch_one(pool).await.ok().flatten();

    // Mean time to close
    let mttc_query = format!(
        r#"
        SELECT AVG(
            (julianday(closed_at) - julianday(created_at)) * 24
        ) as hours
        FROM incidents
        WHERE status = 'closed' AND closed_at IS NOT NULL{}
        "#,
        org_filter
    );
    let mut q = sqlx::query_scalar::<_, Option<f64>>(&mttc_query);
    if let Some(org) = organization_id {
        q = q.bind(org);
    }
    let mean_time_to_close_hours = q.fetch_one(pool).await.ok().flatten();

    // Recent incidents
    let recent_query = format!(
        "SELECT * FROM incidents WHERE 1=1{} ORDER BY created_at DESC LIMIT 10",
        org_filter
    );
    let mut q = sqlx::query_as::<_, Incident>(&recent_query);
    if let Some(org) = organization_id {
        q = q.bind(org);
    }
    let recent_incidents = q.fetch_all(pool).await.unwrap_or_default();

    // Pending actions
    let pending_query = format!(
        r#"
        SELECT COUNT(*) FROM response_actions ra
        JOIN incidents i ON ra.incident_id = i.id
        WHERE ra.status = 'pending'{}
        "#,
        if organization_id.is_some() { " AND i.organization_id = ?1" } else { "" }
    );
    let mut q = sqlx::query_scalar::<_, i64>(&pending_query);
    if let Some(org) = organization_id {
        q = q.bind(org);
    }
    let pending_actions = q.fetch_one(pool).await.unwrap_or(0);

    Ok(IncidentDashboardStats {
        total_incidents,
        open_incidents,
        incidents_by_severity,
        incidents_by_status,
        incidents_by_classification,
        sla_breaches,
        mean_time_to_contain_hours,
        mean_time_to_close_hours,
        recent_incidents,
        pending_actions,
    })
}
