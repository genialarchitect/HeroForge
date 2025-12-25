//! Timeline Builder Module
//!
//! Provides event timeline functionality for incident response:
//! - Timeline events from multiple sources (alerts, logs, manual entries)
//! - Event categorization (attacker action, defender action, system event)
//! - Timeline visualization data (sorted events with timestamps)
//! - Timeline export (JSON, CSV, PDF-ready format)

use anyhow::Result;
use chrono::{DateTime, Utc};
use sqlx::SqlitePool;
use uuid::Uuid;

use super::types::*;

/// Create a new timeline event
pub async fn create_timeline_event(
    pool: &SqlitePool,
    incident_id: &str,
    created_by: &str,
    request: CreateTimelineEventRequest,
) -> Result<TimelineEvent> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();

    // Validate event type
    let _: TimelineEventType = request.event_type.parse()?;

    let event = sqlx::query_as::<_, TimelineEvent>(
        r#"
        INSERT INTO incident_timeline
        (id, incident_id, event_type, timestamp, description, source, actor, created_by, created_at)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
        RETURNING *
        "#,
    )
    .bind(&id)
    .bind(incident_id)
    .bind(&request.event_type)
    .bind(&request.timestamp)
    .bind(&request.description)
    .bind(&request.source)
    .bind(&request.actor)
    .bind(created_by)
    .bind(now)
    .fetch_one(pool)
    .await?;

    Ok(event)
}

/// Get a single timeline event by ID
pub async fn get_timeline_event(pool: &SqlitePool, event_id: &str) -> Result<TimelineEvent> {
    let event = sqlx::query_as::<_, TimelineEvent>(
        "SELECT * FROM incident_timeline WHERE id = ?1"
    )
    .bind(event_id)
    .fetch_one(pool)
    .await?;

    Ok(event)
}

/// Get all timeline events for an incident (sorted by timestamp)
pub async fn get_incident_timeline(
    pool: &SqlitePool,
    incident_id: &str,
) -> Result<Vec<TimelineEvent>> {
    let events = sqlx::query_as::<_, TimelineEvent>(
        "SELECT * FROM incident_timeline WHERE incident_id = ?1 ORDER BY timestamp ASC"
    )
    .bind(incident_id)
    .fetch_all(pool)
    .await?;

    Ok(events)
}

/// Get timeline events with creator information
pub async fn get_incident_timeline_with_creators(
    pool: &SqlitePool,
    incident_id: &str,
) -> Result<Vec<TimelineEventWithCreator>> {
    let events = get_incident_timeline(pool, incident_id).await?;

    let mut results = Vec::with_capacity(events.len());
    for event in events {
        let creator_name: Option<String> = sqlx::query_scalar(
            "SELECT username FROM users WHERE id = ?1"
        )
        .bind(&event.created_by)
        .fetch_optional(pool)
        .await?;

        results.push(TimelineEventWithCreator {
            event,
            creator_name,
        });
    }

    Ok(results)
}

/// Get timeline events filtered by event type
pub async fn get_timeline_by_type(
    pool: &SqlitePool,
    incident_id: &str,
    event_type: &str,
) -> Result<Vec<TimelineEvent>> {
    let events = sqlx::query_as::<_, TimelineEvent>(
        "SELECT * FROM incident_timeline WHERE incident_id = ?1 AND event_type = ?2 ORDER BY timestamp ASC"
    )
    .bind(incident_id)
    .bind(event_type)
    .fetch_all(pool)
    .await?;

    Ok(events)
}

/// Get timeline events within a time range
pub async fn get_timeline_in_range(
    pool: &SqlitePool,
    incident_id: &str,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
) -> Result<Vec<TimelineEvent>> {
    let events = sqlx::query_as::<_, TimelineEvent>(
        r#"
        SELECT * FROM incident_timeline
        WHERE incident_id = ?1 AND timestamp >= ?2 AND timestamp <= ?3
        ORDER BY timestamp ASC
        "#
    )
    .bind(incident_id)
    .bind(start)
    .bind(end)
    .fetch_all(pool)
    .await?;

    Ok(events)
}

/// Update a timeline event
pub async fn update_timeline_event(
    pool: &SqlitePool,
    event_id: &str,
    description: Option<&str>,
    timestamp: Option<DateTime<Utc>>,
    actor: Option<&str>,
) -> Result<TimelineEvent> {
    let existing = get_timeline_event(pool, event_id).await?;

    let new_description = description.unwrap_or(&existing.description);
    let new_timestamp = timestamp.unwrap_or(existing.timestamp);
    let new_actor = actor.map(|s| s.to_string()).or(existing.actor);

    let event = sqlx::query_as::<_, TimelineEvent>(
        r#"
        UPDATE incident_timeline
        SET description = ?1, timestamp = ?2, actor = ?3
        WHERE id = ?4
        RETURNING *
        "#,
    )
    .bind(new_description)
    .bind(new_timestamp)
    .bind(&new_actor)
    .bind(event_id)
    .fetch_one(pool)
    .await?;

    Ok(event)
}

/// Delete a timeline event
pub async fn delete_timeline_event(pool: &SqlitePool, event_id: &str) -> Result<()> {
    sqlx::query("DELETE FROM incident_timeline WHERE id = ?1")
        .bind(event_id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Export timeline to JSON format
pub fn export_timeline_json(events: &[TimelineEvent]) -> Result<String> {
    let json = serde_json::to_string_pretty(events)?;
    Ok(json)
}

/// Export timeline to CSV format
pub fn export_timeline_csv(events: &[TimelineEvent]) -> Result<String> {
    let mut csv = String::new();

    // Header
    csv.push_str("timestamp,event_type,description,source,actor,created_by,created_at\n");

    // Rows
    for event in events {
        let actor = event.actor.as_deref().unwrap_or("");
        csv.push_str(&format!(
            "\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\"\n",
            event.timestamp.to_rfc3339(),
            event.event_type,
            event.description.replace('"', "\"\""),
            event.source,
            actor.replace('"', "\"\""),
            event.created_by,
            event.created_at.to_rfc3339()
        ));
    }

    Ok(csv)
}

/// Timeline data for PDF export (structured for rendering)
#[derive(Debug, Clone, serde::Serialize)]
pub struct TimelinePdfData {
    pub incident_id: String,
    pub export_date: String,
    pub events: Vec<TimelinePdfEvent>,
    pub summary: TimelineSummary,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct TimelinePdfEvent {
    pub timestamp: String,
    pub event_type: String,
    pub event_type_display: String,
    pub description: String,
    pub source: String,
    pub actor: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct TimelineSummary {
    pub total_events: usize,
    pub first_event: Option<String>,
    pub last_event: Option<String>,
    pub duration: Option<String>,
    pub events_by_type: Vec<(String, usize)>,
}

/// Generate PDF-ready timeline data
pub fn export_timeline_pdf_data(
    incident_id: &str,
    events: &[TimelineEvent],
) -> TimelinePdfData {
    let pdf_events: Vec<TimelinePdfEvent> = events
        .iter()
        .map(|e| TimelinePdfEvent {
            timestamp: e.timestamp.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
            event_type: e.event_type.clone(),
            event_type_display: format_event_type(&e.event_type),
            description: e.description.clone(),
            source: e.source.clone(),
            actor: e.actor.clone(),
        })
        .collect();

    // Calculate summary
    let first_event = events.first().map(|e| e.timestamp.format("%Y-%m-%d %H:%M:%S UTC").to_string());
    let last_event = events.last().map(|e| e.timestamp.format("%Y-%m-%d %H:%M:%S UTC").to_string());

    let duration = if events.len() >= 2 {
        let first = events.first().unwrap().timestamp;
        let last = events.last().unwrap().timestamp;
        let diff = last - first;
        Some(format_duration(diff))
    } else {
        None
    };

    // Count events by type
    let mut type_counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for event in events {
        *type_counts.entry(event.event_type.clone()).or_insert(0) += 1;
    }
    let mut events_by_type: Vec<(String, usize)> = type_counts.into_iter().collect();
    events_by_type.sort_by(|a, b| b.1.cmp(&a.1));

    TimelinePdfData {
        incident_id: incident_id.to_string(),
        export_date: Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        events: pdf_events,
        summary: TimelineSummary {
            total_events: events.len(),
            first_event,
            last_event,
            duration,
            events_by_type,
        },
    }
}

/// Format event type for display
fn format_event_type(event_type: &str) -> String {
    match event_type {
        "attacker_action" => "Attacker Action".to_string(),
        "defender_action" => "Defender Action".to_string(),
        "system_event" => "System Event".to_string(),
        "alert" => "Alert".to_string(),
        "log_entry" => "Log Entry".to_string(),
        "observation" => "Observation".to_string(),
        "communication" => "Communication".to_string(),
        "evidence_collected" => "Evidence Collected".to_string(),
        "ioc_identified" => "IOC Identified".to_string(),
        other => other.replace('_', " "),
    }
}

/// Format duration in human-readable format
fn format_duration(duration: chrono::Duration) -> String {
    let total_seconds = duration.num_seconds();
    let days = total_seconds / 86400;
    let hours = (total_seconds % 86400) / 3600;
    let minutes = (total_seconds % 3600) / 60;

    if days > 0 {
        format!("{} days, {} hours, {} minutes", days, hours, minutes)
    } else if hours > 0 {
        format!("{} hours, {} minutes", hours, minutes)
    } else {
        format!("{} minutes", minutes)
    }
}

/// Auto-generate timeline event when incident status changes
pub async fn create_status_change_event(
    pool: &SqlitePool,
    incident_id: &str,
    old_status: &str,
    new_status: &str,
    user_id: &str,
) -> Result<TimelineEvent> {
    let request = CreateTimelineEventRequest {
        event_type: "defender_action".to_string(),
        timestamp: Utc::now(),
        description: format!("Incident status changed from '{}' to '{}'", old_status, new_status),
        source: "heroforge".to_string(),
        actor: Some(user_id.to_string()),
    };

    create_timeline_event(pool, incident_id, user_id, request).await
}

/// Auto-generate timeline event when incident is assigned
pub async fn create_assignment_event(
    pool: &SqlitePool,
    incident_id: &str,
    assignee_id: Option<&str>,
    user_id: &str,
) -> Result<TimelineEvent> {
    let description = match assignee_id {
        Some(id) => format!("Incident assigned to user {}", id),
        None => "Incident unassigned".to_string(),
    };

    let request = CreateTimelineEventRequest {
        event_type: "defender_action".to_string(),
        timestamp: Utc::now(),
        description,
        source: "heroforge".to_string(),
        actor: Some(user_id.to_string()),
    };

    create_timeline_event(pool, incident_id, user_id, request).await
}
