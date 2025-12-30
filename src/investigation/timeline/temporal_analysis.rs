use crate::investigation::types::{TimelineEvent, TemporalPattern};
use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use std::collections::HashMap;

/// Detect anomalous timing patterns in events
pub fn detect_anomalous_timing(events: &[TimelineEvent]) -> Result<Vec<TemporalPattern>> {
    let mut patterns = Vec::new();

    // Detect unusual time clustering
    if let Some(cluster) = detect_time_clustering(events)? {
        patterns.push(cluster);
    }

    // Detect suspicious gaps
    if let Some(gap) = detect_suspicious_gaps(events)? {
        patterns.push(gap);
    }

    Ok(patterns)
}

/// Detect time clustering (many events in short period)
fn detect_time_clustering(events: &[TimelineEvent]) -> Result<Option<TemporalPattern>> {
    if events.len() < 10 {
        return Ok(None);
    }

    let mut sorted_events = events.to_vec();
    sorted_events.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

    // Look for clusters of 10+ events within 1 minute
    for window in sorted_events.windows(10) {
        let start = &window[0];
        let end = &window[9];
        let duration = end.timestamp.signed_duration_since(start.timestamp);

        if duration < Duration::minutes(1) {
            return Ok(Some(TemporalPattern {
                pattern_type: "TimeCluster".to_string(),
                description: format!("10 events within {} seconds", duration.num_seconds()),
                events: window.iter().map(|e| e.id.clone()).collect(),
                start_time: start.timestamp,
                end_time: end.timestamp,
                confidence: 0.85,
            }));
        }
    }

    Ok(None)
}

/// Detect suspicious gaps in event sequence
fn detect_suspicious_gaps(events: &[TimelineEvent]) -> Result<Option<TemporalPattern>> {
    if events.len() < 2 {
        return Ok(None);
    }

    let mut sorted_events = events.to_vec();
    sorted_events.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

    for window in sorted_events.windows(2) {
        let duration = window[1].timestamp.signed_duration_since(window[0].timestamp);

        // Gaps longer than 1 hour might indicate log deletion
        if duration > Duration::hours(1) {
            return Ok(Some(TemporalPattern {
                pattern_type: "SuspiciousGap".to_string(),
                description: format!("{}  hour gap in events (possible log deletion)", duration.num_hours()),
                events: vec![window[0].id.clone(), window[1].id.clone()],
                start_time: window[0].timestamp,
                end_time: window[1].timestamp,
                confidence: 0.70,
            }));
        }
    }

    Ok(None)
}

/// Perform frequency analysis on events
pub fn frequency_analysis(events: &[TimelineEvent]) -> Result<HashMap<String, i64>> {
    let mut frequency = HashMap::new();

    for event in events {
        *frequency.entry(event.event_type.clone()).or_insert(0) += 1;
    }

    Ok(frequency)
}

/// Time-series forecasting for event occurrence
pub fn forecast_event_occurrence(
    events: &[TimelineEvent],
    event_type: &str,
    horizon_hours: i64,
) -> Result<f64> {
    // Simple moving average forecast
    let relevant_events: Vec<_> = events.iter()
        .filter(|e| e.event_type == event_type)
        .collect();

    if relevant_events.is_empty() {
        return Ok(0.0);
    }

    // Calculate average occurrence rate
    let total_duration = if let (Some(first), Some(last)) = (relevant_events.first(), relevant_events.last()) {
        last.timestamp.signed_duration_since(first.timestamp).num_hours() as f64
    } else {
        return Ok(0.0);
    };

    if total_duration <= 0.0 {
        return Ok(0.0);
    }

    let rate = relevant_events.len() as f64 / total_duration;
    let forecast = rate * horizon_hours as f64;

    Ok(forecast)
}

/// Temporal correlation between event types
pub fn temporal_correlation(
    events: &[TimelineEvent],
    event_type_a: &str,
    event_type_b: &str,
    time_window_seconds: i64,
) -> Result<f64> {
    let events_a: Vec<_> = events.iter()
        .filter(|e| e.event_type == event_type_a)
        .collect();

    let events_b: Vec<_> = events.iter()
        .filter(|e| e.event_type == event_type_b)
        .collect();

    if events_a.is_empty() || events_b.is_empty() {
        return Ok(0.0);
    }

    let mut correlation_count = 0;

    for event_a in &events_a {
        for event_b in &events_b {
            let diff = (event_b.timestamp.timestamp() - event_a.timestamp.timestamp()).abs();
            if diff <= time_window_seconds {
                correlation_count += 1;
                break;
            }
        }
    }

    let correlation = correlation_count as f64 / events_a.len() as f64;

    Ok(correlation)
}
