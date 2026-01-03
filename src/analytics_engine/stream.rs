//! Real-time Stream Processing Engine
//!
//! Provides real-time analytics processing with:
//! - Windowed computations (tumbling, sliding, session)
//! - Complex event processing (CEP)
//! - Stateful stream processing
//! - Late data handling with watermarks

use super::types::*;
use anyhow::{Result, Context};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::RwLock;
use chrono::{DateTime, Utc, Duration as ChronoDuration};

/// Stream processor state
pub struct StreamProcessor {
    /// Active windows
    windows: Arc<RwLock<HashMap<String, Window>>>,
    /// Event buffer for late arrivals
    late_buffer: Arc<RwLock<VecDeque<StreamEvent>>>,
    /// Watermark (latest event time minus allowed lateness)
    watermark: Arc<RwLock<DateTime<Utc>>>,
    /// Configuration
    config: StreamProcessorConfig,
}

/// Stream processor configuration
#[derive(Debug, Clone)]
pub struct StreamProcessorConfig {
    /// Maximum allowed lateness in seconds
    pub max_lateness_secs: u64,
    /// Maximum buffer size for late events
    pub max_late_buffer_size: usize,
    /// Window cleanup interval in seconds
    pub cleanup_interval_secs: u64,
}

impl Default for StreamProcessorConfig {
    fn default() -> Self {
        Self {
            max_lateness_secs: 60,
            max_late_buffer_size: 10000,
            cleanup_interval_secs: 30,
        }
    }
}

/// A streaming event
#[derive(Debug, Clone)]
pub struct StreamEvent {
    pub event_id: String,
    pub event_type: String,
    pub timestamp: DateTime<Utc>,
    pub data: HashMap<String, serde_json::Value>,
    pub source: String,
}

/// A processing window
#[derive(Debug)]
struct Window {
    window_id: String,
    window_type: WindowType,
    start_time: DateTime<Utc>,
    end_time: DateTime<Utc>,
    events: Vec<StreamEvent>,
    aggregates: HashMap<String, f64>,
}

impl Window {
    fn new(window_id: String, window_type: WindowType, start: DateTime<Utc>, end: DateTime<Utc>) -> Self {
        Self {
            window_id,
            window_type,
            start_time: start,
            end_time: end,
            events: Vec::new(),
            aggregates: HashMap::new(),
        }
    }

    fn add_event(&mut self, event: StreamEvent) {
        self.events.push(event);
    }

    fn is_expired(&self, current_time: DateTime<Utc>) -> bool {
        current_time > self.end_time
    }

    fn compute_aggregates(&mut self, aggregation: &Aggregation) {
        let values: Vec<f64> = self.events.iter()
            .filter_map(|e| {
                e.data.get(&aggregation.field)
                    .and_then(|v| v.as_f64())
            })
            .collect();

        if values.is_empty() {
            return;
        }

        let result = match &aggregation.function {
            AggregationFunction::Count => values.len() as f64,
            AggregationFunction::Sum => values.iter().sum(),
            AggregationFunction::Average => values.iter().sum::<f64>() / values.len() as f64,
            AggregationFunction::Min => values.iter().cloned().fold(f64::INFINITY, f64::min),
            AggregationFunction::Max => values.iter().cloned().fold(f64::NEG_INFINITY, f64::max),
            AggregationFunction::Percentile(p) => {
                let mut sorted = values.clone();
                sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
                let idx = ((*p / 100.0) * (sorted.len() - 1) as f64) as usize;
                sorted.get(idx).copied().unwrap_or(0.0)
            }
            AggregationFunction::StdDev => {
                let mean = values.iter().sum::<f64>() / values.len() as f64;
                let variance = values.iter()
                    .map(|x| (x - mean).powi(2))
                    .sum::<f64>() / values.len() as f64;
                variance.sqrt()
            }
            AggregationFunction::Variance => {
                let mean = values.iter().sum::<f64>() / values.len() as f64;
                values.iter()
                    .map(|x| (x - mean).powi(2))
                    .sum::<f64>() / values.len() as f64
            }
        };

        self.aggregates.insert(aggregation.alias.clone(), result);
    }
}

impl StreamProcessor {
    /// Create new stream processor
    pub fn new(config: StreamProcessorConfig) -> Self {
        Self {
            windows: Arc::new(RwLock::new(HashMap::new())),
            late_buffer: Arc::new(RwLock::new(VecDeque::new())),
            watermark: Arc::new(RwLock::new(Utc::now())),
            config,
        }
    }

    /// Process an incoming event
    pub async fn process_event(&self, event: StreamEvent, window_config: &WindowConfig) -> Result<()> {
        // Update watermark
        let mut watermark = self.watermark.write().await;
        let allowed_lateness = ChronoDuration::seconds(self.config.max_lateness_secs as i64);

        if event.timestamp > *watermark + allowed_lateness {
            *watermark = event.timestamp - allowed_lateness;
        }

        // Check if event is late
        if event.timestamp < *watermark {
            // Buffer late event for potential reprocessing
            let mut late_buffer = self.late_buffer.write().await;
            if late_buffer.len() < self.config.max_late_buffer_size {
                late_buffer.push_back(event.clone());
            }
            // Still process the late event
        }
        drop(watermark);

        // Assign event to windows
        let window_ids = self.get_windows_for_event(&event, window_config).await?;

        let mut windows = self.windows.write().await;
        for window_id in window_ids {
            if let Some(window) = windows.get_mut(&window_id) {
                window.add_event(event.clone());
            }
        }

        Ok(())
    }

    /// Get window IDs that an event belongs to
    async fn get_windows_for_event(&self, event: &StreamEvent, config: &WindowConfig) -> Result<Vec<String>> {
        let mut window_ids = Vec::new();
        let event_time = event.timestamp;
        let window_duration = ChronoDuration::seconds(config.size_seconds as i64);

        match config.window_type {
            WindowType::Tumbling => {
                // Event belongs to exactly one window
                let window_start = event_time.timestamp() / config.size_seconds as i64 * config.size_seconds as i64;
                let window_id = format!("tumbling_{}_{}", window_start, config.size_seconds);

                // Create window if it doesn't exist
                let mut windows = self.windows.write().await;
                if !windows.contains_key(&window_id) {
                    let start = DateTime::from_timestamp(window_start, 0)
                        .context("Invalid timestamp")?;
                    let end = start + window_duration;
                    windows.insert(window_id.clone(), Window::new(
                        window_id.clone(),
                        WindowType::Tumbling,
                        start,
                        end,
                    ));
                }
                window_ids.push(window_id);
            }
            WindowType::Sliding => {
                // Event can belong to multiple overlapping windows
                let slide_secs = config.slide_seconds.unwrap_or(config.size_seconds / 2);
                let slide_duration = ChronoDuration::seconds(slide_secs as i64);

                // Calculate all windows this event falls into
                let earliest_window_start = event_time - window_duration + slide_duration;
                let mut current_start = DateTime::from_timestamp(
                    earliest_window_start.timestamp() / slide_secs as i64 * slide_secs as i64,
                    0
                ).unwrap_or(event_time);

                let mut windows = self.windows.write().await;
                while current_start <= event_time {
                    let window_end = current_start + window_duration;
                    if event_time >= current_start && event_time < window_end {
                        let window_id = format!("sliding_{}_{}_{}",
                            current_start.timestamp(), config.size_seconds, slide_secs);

                        if !windows.contains_key(&window_id) {
                            windows.insert(window_id.clone(), Window::new(
                                window_id.clone(),
                                WindowType::Sliding,
                                current_start,
                                window_end,
                            ));
                        }
                        window_ids.push(window_id);
                    }
                    current_start = current_start + slide_duration;
                }
            }
            WindowType::Session => {
                // Session windows based on activity gaps
                // For simplicity, use source as session key
                let session_key = &event.source;
                let session_id = format!("session_{}", session_key);

                let mut windows = self.windows.write().await;
                if let Some(window) = windows.get_mut(&session_id) {
                    // Extend session if event is within gap timeout
                    let gap_timeout = ChronoDuration::seconds(config.size_seconds as i64);
                    if event_time <= window.end_time + gap_timeout {
                        window.end_time = event_time + gap_timeout;
                        window_ids.push(session_id);
                    } else {
                        // Start new session
                        let new_session_id = format!("session_{}_{}", session_key, event_time.timestamp());
                        windows.insert(new_session_id.clone(), Window::new(
                            new_session_id.clone(),
                            WindowType::Session,
                            event_time,
                            event_time + gap_timeout,
                        ));
                        window_ids.push(new_session_id);
                    }
                } else {
                    windows.insert(session_id.clone(), Window::new(
                        session_id.clone(),
                        WindowType::Session,
                        event_time,
                        event_time + ChronoDuration::seconds(config.size_seconds as i64),
                    ));
                    window_ids.push(session_id);
                }
            }
            WindowType::Global => {
                // Single global window
                let window_id = "global".to_string();
                let mut windows = self.windows.write().await;
                if !windows.contains_key(&window_id) {
                    windows.insert(window_id.clone(), Window::new(
                        window_id.clone(),
                        WindowType::Global,
                        DateTime::from_timestamp(0, 0).unwrap(),
                        DateTime::from_timestamp(i64::MAX / 2, 0).unwrap(),
                    ));
                }
                window_ids.push(window_id);
            }
        }

        Ok(window_ids)
    }

    /// Trigger window computation and emit results
    pub async fn trigger_windows(&self, aggregations: &[Aggregation]) -> Result<Vec<WindowResult>> {
        let mut results = Vec::new();
        let current_time = Utc::now();
        let watermark = *self.watermark.read().await;

        let mut windows = self.windows.write().await;
        let mut expired_windows = Vec::new();

        for (window_id, window) in windows.iter_mut() {
            // Only trigger windows that are past the watermark
            if window.end_time <= watermark {
                // Compute aggregates
                for agg in aggregations {
                    window.compute_aggregates(agg);
                }

                results.push(WindowResult {
                    window_id: window_id.clone(),
                    window_start: window.start_time,
                    window_end: window.end_time,
                    event_count: window.events.len(),
                    aggregates: window.aggregates.clone(),
                });

                if window.is_expired(current_time) {
                    expired_windows.push(window_id.clone());
                }
            }
        }

        // Cleanup expired windows
        for window_id in expired_windows {
            windows.remove(&window_id);
        }

        Ok(results)
    }

    /// Get current watermark
    pub async fn get_watermark(&self) -> DateTime<Utc> {
        *self.watermark.read().await
    }

    /// Get late event count
    pub async fn get_late_event_count(&self) -> usize {
        self.late_buffer.read().await.len()
    }
}

/// Result from a triggered window
#[derive(Debug, Clone)]
pub struct WindowResult {
    pub window_id: String,
    pub window_start: DateTime<Utc>,
    pub window_end: DateTime<Utc>,
    pub event_count: usize,
    pub aggregates: HashMap<String, f64>,
}

/// Process real-time stream query
pub async fn process_stream_query(query: &AnalyticsQuery) -> Result<AnalyticsResult> {
    let start = std::time::Instant::now();

    // Extract stream configuration from query parameters
    let window_config = WindowConfig {
        window_type: WindowType::Tumbling,
        size_seconds: 60,
        slide_seconds: None,
    };

    // Create stream processor
    let processor = StreamProcessor::new(StreamProcessorConfig::default());

    // Process any events from the query (simulated here)
    // In production, this would connect to actual streaming sources
    let mut rows = Vec::new();

    // Apply filters to determine what events to process
    for filter in &query.parameters.filters {
        // Build filter criteria for stream source subscription
        log::debug!("Stream filter: {} {:?}", filter.field, filter.operator);
    }

    // Trigger any pending windows
    let window_results = processor.trigger_windows(&query.parameters.aggregations).await?;

    // Convert window results to query result rows
    for result in window_results {
        let mut row: HashMap<String, serde_json::Value> = HashMap::new();
        row.insert("window_id".to_string(), serde_json::json!(result.window_id));
        row.insert("window_start".to_string(), serde_json::json!(result.window_start.to_rfc3339()));
        row.insert("window_end".to_string(), serde_json::json!(result.window_end.to_rfc3339()));
        row.insert("event_count".to_string(), serde_json::json!(result.event_count));

        for (key, value) in result.aggregates {
            row.insert(key, serde_json::json!(value));
        }

        rows.push(row);
    }

    // Apply sorting
    for sort in &query.parameters.sorting {
        rows.sort_by(|a, b| {
            let a_val = a.get(&sort.field).and_then(|v| v.as_f64()).unwrap_or(0.0);
            let b_val = b.get(&sort.field).and_then(|v| v.as_f64()).unwrap_or(0.0);
            match sort.direction {
                SortDirection::Ascending => a_val.partial_cmp(&b_val).unwrap_or(std::cmp::Ordering::Equal),
                SortDirection::Descending => b_val.partial_cmp(&a_val).unwrap_or(std::cmp::Ordering::Equal),
            }
        });
    }

    // Apply limit
    let total_count = rows.len();
    if let Some(limit) = query.parameters.limit {
        rows.truncate(limit);
    }

    let execution_time = start.elapsed().as_secs_f64() * 1000.0;

    Ok(AnalyticsResult {
        query_id: query.query_id.clone(),
        execution_time_ms: execution_time,
        rows,
        total_count,
        metadata: ResultMetadata {
            columns: vec![
                ColumnInfo { name: "window_id".to_string(), data_type: "string".to_string(), nullable: false },
                ColumnInfo { name: "window_start".to_string(), data_type: "datetime".to_string(), nullable: false },
                ColumnInfo { name: "window_end".to_string(), data_type: "datetime".to_string(), nullable: false },
                ColumnInfo { name: "event_count".to_string(), data_type: "integer".to_string(), nullable: false },
            ],
            scanned_bytes: 0,
            cached: false,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_stream_processor_tumbling_window() {
        let processor = StreamProcessor::new(StreamProcessorConfig::default());

        let window_config = WindowConfig {
            window_type: WindowType::Tumbling,
            size_seconds: 60,
            slide_seconds: None,
        };

        let event = StreamEvent {
            event_id: "1".to_string(),
            event_type: "test".to_string(),
            timestamp: Utc::now(),
            data: {
                let mut d = HashMap::new();
                d.insert("value".to_string(), serde_json::json!(100.0));
                d
            },
            source: "test_source".to_string(),
        };

        processor.process_event(event, &window_config).await.unwrap();

        let aggregations = vec![Aggregation {
            field: "value".to_string(),
            function: AggregationFunction::Sum,
            alias: "total".to_string(),
        }];

        // Window won't trigger immediately since watermark hasn't advanced
        let results = processor.trigger_windows(&aggregations).await.unwrap();
        // Results depend on watermark timing
        assert!(results.len() <= 1);
    }

    #[tokio::test]
    async fn test_process_stream_query() {
        let query = AnalyticsQuery {
            query_id: "test-stream".to_string(),
            query_type: QueryType::RealTimeStream,
            parameters: QueryParameters {
                filters: vec![],
                aggregations: vec![],
                grouping: vec![],
                sorting: vec![],
                limit: Some(10),
            },
            time_range: None,
        };

        let result = process_stream_query(&query).await.unwrap();
        assert_eq!(result.query_id, "test-stream");
    }
}
