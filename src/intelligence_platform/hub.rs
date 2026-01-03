//! Unified intelligence hub
//!
//! Provides a single pane of glass for all intelligence sources with:
//! - Source aggregation and normalization
//! - Deduplication across sources
//! - Unified security event timeline
//! - Customizable dashboards with widgets
//! - Real-time update streaming

use super::types::*;
use anyhow::Result;
use std::collections::{HashMap, HashSet};
use log::info;

/// Initialize unified intelligence hub
pub async fn initialize_hub(config: &HubConfig) -> Result<IntelligenceHub> {
    info!("Initializing unified intelligence hub with {} sources", config.sources.len());

    // Initialize sources and calculate total indicators
    let mut total_indicators = 0;
    let sources: Vec<IntelligenceSource> = config.sources.iter()
        .map(|s| {
            total_indicators += s.indicator_count;
            s.clone()
        })
        .collect();

    // Build unified timeline from all sources
    let timeline = build_initial_timeline(&sources).await;

    // Create default dashboard
    let dashboard = create_default_dashboard();

    let unified_view = UnifiedView {
        timeline,
        dashboard,
        deduplicated: config.deduplication,
    };

    info!("Intelligence hub initialized with {} total indicators", total_indicators);

    Ok(IntelligenceHub {
        total_indicators,
        sources,
        unified_view,
    })
}

/// Build initial timeline from sources
async fn build_initial_timeline(sources: &[IntelligenceSource]) -> Vec<TimelineEvent> {
    let mut events = Vec::new();

    for source in sources {
        if source.enabled {
            events.push(TimelineEvent {
                event_id: uuid::Uuid::new_v4().to_string(),
                timestamp: source.last_updated,
                event_type: "source_sync".to_string(),
                source: source.source_id.clone(),
                indicators: vec![],
                severity: Severity::Info,
            });
        }
    }

    // Sort by timestamp descending (most recent first)
    events.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
    events
}

/// Create default dashboard configuration
fn create_default_dashboard() -> Dashboard {
    Dashboard {
        widgets: vec![
            DashboardWidget {
                widget_id: "overview-metrics".to_string(),
                widget_type: WidgetType::MetricCard,
                data_source: "indicators".to_string(),
                refresh_interval_seconds: 60,
            },
            DashboardWidget {
                widget_id: "threat-timeline".to_string(),
                widget_type: WidgetType::Timeline,
                data_source: "events".to_string(),
                refresh_interval_seconds: 30,
            },
            DashboardWidget {
                widget_id: "severity-chart".to_string(),
                widget_type: WidgetType::Chart,
                data_source: "severity_distribution".to_string(),
                refresh_interval_seconds: 120,
            },
            DashboardWidget {
                widget_id: "threat-map".to_string(),
                widget_type: WidgetType::Map,
                data_source: "geo_indicators".to_string(),
                refresh_interval_seconds: 300,
            },
            DashboardWidget {
                widget_id: "recent-indicators".to_string(),
                widget_type: WidgetType::Table,
                data_source: "indicators".to_string(),
                refresh_interval_seconds: 60,
            },
        ],
        layout: "grid-2x3".to_string(),
    }
}

/// Add a new intelligence source to the hub
pub async fn add_source(hub: &mut IntelligenceHub, source: IntelligenceSource) -> Result<()> {
    // Check for duplicates
    if hub.sources.iter().any(|s| s.source_id == source.source_id) {
        return Err(anyhow::anyhow!("Source already exists: {}", source.source_id));
    }

    hub.total_indicators += source.indicator_count;
    hub.sources.push(source.clone());

    // Add sync event to timeline
    hub.unified_view.timeline.insert(0, TimelineEvent {
        event_id: uuid::Uuid::new_v4().to_string(),
        timestamp: chrono::Utc::now(),
        event_type: "source_added".to_string(),
        source: source.source_id,
        indicators: vec![],
        severity: Severity::Info,
    });

    Ok(())
}

/// Remove an intelligence source from the hub
pub async fn remove_source(hub: &mut IntelligenceHub, source_id: &str) -> Result<()> {
    if let Some(pos) = hub.sources.iter().position(|s| s.source_id == source_id) {
        let source = hub.sources.remove(pos);
        hub.total_indicators = hub.total_indicators.saturating_sub(source.indicator_count);

        // Add removal event to timeline
        hub.unified_view.timeline.insert(0, TimelineEvent {
            event_id: uuid::Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now(),
            event_type: "source_removed".to_string(),
            source: source_id.to_string(),
            indicators: vec![],
            severity: Severity::Info,
        });

        Ok(())
    } else {
        Err(anyhow::anyhow!("Source not found: {}", source_id))
    }
}

/// Sync all sources and update the hub
pub async fn sync_sources(hub: &mut IntelligenceHub) -> Result<SyncResult> {
    let mut synced = 0;
    let mut failed = 0;
    let mut new_indicators = 0;

    for source in hub.sources.iter_mut() {
        if source.enabled {
            match sync_single_source(source).await {
                Ok(count) => {
                    synced += 1;
                    new_indicators += count;
                }
                Err(_) => {
                    failed += 1;
                }
            }
        }
    }

    hub.total_indicators += new_indicators;

    Ok(SyncResult {
        sources_synced: synced,
        sources_failed: failed,
        new_indicators,
        timestamp: chrono::Utc::now(),
    })
}

/// Sync a single source
async fn sync_single_source(source: &mut IntelligenceSource) -> Result<usize> {
    // Simulate fetching new indicators from source
    source.last_updated = chrono::Utc::now();

    // In real implementation, would fetch from actual source
    let new_count = 0; // Placeholder
    source.indicator_count += new_count;

    Ok(new_count)
}

/// Add an event to the timeline
pub fn add_timeline_event(hub: &mut IntelligenceHub, event: TimelineEvent) {
    if hub.unified_view.deduplicated {
        // Check for duplicates based on content
        let exists = hub.unified_view.timeline.iter().any(|e| {
            e.event_type == event.event_type
                && e.source == event.source
                && e.indicators == event.indicators
                && (e.timestamp - event.timestamp).num_seconds().abs() < 60
        });

        if exists {
            return;
        }
    }

    hub.unified_view.timeline.insert(0, event);

    // Limit timeline size
    if hub.unified_view.timeline.len() > 10000 {
        hub.unified_view.timeline.truncate(10000);
    }
}

/// Query the unified timeline
pub fn query_timeline<'a>(
    hub: &'a IntelligenceHub,
    filter: &TimelineFilter,
) -> Vec<&'a TimelineEvent> {
    hub.unified_view.timeline.iter()
        .filter(|event| {
            // Filter by severity
            if let Some(ref min_severity) = filter.min_severity {
                if &event.severity < min_severity {
                    return false;
                }
            }

            // Filter by source
            if let Some(ref sources) = filter.sources {
                if !sources.contains(&event.source) {
                    return false;
                }
            }

            // Filter by event type
            if let Some(ref event_types) = filter.event_types {
                if !event_types.contains(&event.event_type) {
                    return false;
                }
            }

            // Filter by time range
            if let Some(ref start) = filter.start_time {
                if &event.timestamp < start {
                    return false;
                }
            }

            if let Some(ref end) = filter.end_time {
                if &event.timestamp > end {
                    return false;
                }
            }

            true
        })
        .take(filter.limit.unwrap_or(100))
        .collect()
}

/// Deduplicate indicators across all sources
pub fn deduplicate_indicators(hub: &mut IntelligenceHub) -> DeduplicationResult {
    let mut seen: HashSet<String> = HashSet::new();
    let mut duplicates_removed = 0;
    let mut sources_affected = HashSet::new();

    for event in hub.unified_view.timeline.iter() {
        for indicator in &event.indicators {
            if !seen.insert(indicator.clone()) {
                duplicates_removed += 1;
                sources_affected.insert(event.source.clone());
            }
        }
    }

    DeduplicationResult {
        duplicates_removed,
        sources_affected: sources_affected.len(),
        unique_indicators: seen.len(),
    }
}

/// Get hub statistics
pub fn get_hub_stats(hub: &IntelligenceHub) -> HubStats {
    let sources_by_type: HashMap<String, usize> = hub.sources.iter()
        .fold(HashMap::new(), |mut acc, s| {
            let type_name = format!("{:?}", s.source_type);
            *acc.entry(type_name).or_insert(0) += 1;
            acc
        });

    let active_sources = hub.sources.iter().filter(|s| s.enabled).count();

    let severity_counts: HashMap<Severity, usize> = hub.unified_view.timeline.iter()
        .fold(HashMap::new(), |mut acc, e| {
            *acc.entry(e.severity).or_insert(0) += 1;
            acc
        });

    HubStats {
        total_sources: hub.sources.len(),
        active_sources,
        total_indicators: hub.total_indicators,
        timeline_events: hub.unified_view.timeline.len(),
        sources_by_type,
        severity_distribution: severity_counts.into_iter()
            .map(|(k, v)| (format!("{:?}", k), v))
            .collect(),
    }
}

// Additional types for hub operations

#[derive(Debug, Clone)]
pub struct SyncResult {
    pub sources_synced: usize,
    pub sources_failed: usize,
    pub new_indicators: usize,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Default)]
pub struct TimelineFilter {
    pub min_severity: Option<Severity>,
    pub sources: Option<Vec<String>>,
    pub event_types: Option<Vec<String>>,
    pub start_time: Option<chrono::DateTime<chrono::Utc>>,
    pub end_time: Option<chrono::DateTime<chrono::Utc>>,
    pub limit: Option<usize>,
}

#[derive(Debug, Clone)]
pub struct DeduplicationResult {
    pub duplicates_removed: usize,
    pub sources_affected: usize,
    pub unique_indicators: usize,
}

#[derive(Debug, Clone)]
pub struct HubStats {
    pub total_sources: usize,
    pub active_sources: usize,
    pub total_indicators: usize,
    pub timeline_events: usize,
    pub sources_by_type: HashMap<String, usize>,
    pub severity_distribution: HashMap<String, usize>,
}
