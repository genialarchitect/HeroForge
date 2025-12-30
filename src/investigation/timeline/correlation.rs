use crate::investigation::types::TimelineEvent;
use anyhow::Result;
use std::collections::HashMap;

/// Correlate events by entity involvement
pub fn correlate_by_entity(events: &[TimelineEvent]) -> Result<HashMap<String, Vec<String>>> {
    let mut entity_events: HashMap<String, Vec<String>> = HashMap::new();

    for event in events {
        if let Some(entities_json) = &event.entities {
            if let Ok(entities) = serde_json::from_str::<Vec<String>>(entities_json) {
                for entity in entities {
                    entity_events.entry(entity)
                        .or_insert_with(Vec::new)
                        .push(event.id.clone());
                }
            }
        }
    }

    Ok(entity_events)
}

/// Group events by similarity
pub fn group_similar_events(events: &[TimelineEvent]) -> Result<Vec<Vec<TimelineEvent>>> {
    let mut groups: HashMap<String, Vec<TimelineEvent>> = HashMap::new();

    for event in events {
        // Group by event type and source
        let key = format!("{}:{}", event.event_type, event.source);
        groups.entry(key)
            .or_insert_with(Vec::new)
            .push(event.clone());
    }

    Ok(groups.into_values().collect())
}

/// Identify causal relationships between events
pub fn identify_causal_relationships(
    events: &[TimelineEvent],
) -> Result<Vec<(String, String, String)>> {
    // Returns tuples of (cause_event_id, effect_event_id, relationship_type)
    let mut relationships = Vec::new();

    let mut sorted_events = events.to_vec();
    sorted_events.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

    // Simple heuristic: events of type A followed by type B within time window
    let causal_patterns = vec![
        ("Login", "FileAccess", "UserAction"),
        ("FileDownload", "ProcessExecution", "MalwareExecution"),
        ("NetworkConnection", "DataTransfer", "Exfiltration"),
    ];

    for window in sorted_events.windows(2) {
        let (event_a, event_b) = (&window[0], &window[1]);

        for (type_a, type_b, relationship) in &causal_patterns {
            if event_a.event_type == *type_a && event_b.event_type == *type_b {
                // Check if within 5 minutes
                let diff = event_b.timestamp.signed_duration_since(event_a.timestamp);
                if diff.num_minutes() <= 5 {
                    relationships.push((
                        event_a.id.clone(),
                        event_b.id.clone(),
                        relationship.to_string(),
                    ));
                }
            }
        }
    }

    Ok(relationships)
}
