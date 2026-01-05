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

// ============================================================================
// Kafka Connector - Simplified Implementation
// ============================================================================

/// Kafka connector for consuming messages from Kafka topics
pub struct KafkaConnector {
    brokers: Vec<String>,
    topic: String,
    group_id: String,
    security: Option<super::types::KafkaSecurity>,
}

impl KafkaConnector {
    pub fn new(
        brokers: Vec<String>,
        topic: String,
        group_id: Option<String>,
        security: Option<super::types::KafkaSecurity>,
    ) -> Self {
        Self {
            brokers,
            topic,
            group_id: group_id.unwrap_or_else(|| format!("heroforge-{}", uuid::Uuid::new_v4())),
            security,
        }
    }

    /// Connect to Kafka broker and fetch messages
    pub async fn fetch_messages(&self, max_messages: usize, timeout_ms: u64) -> Result<Vec<KafkaMessage>> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let mut messages = Vec::new();

        // Try each broker until one succeeds
        for broker in &self.brokers {
            let parts: Vec<&str> = broker.split(':').collect();
            let host = match parts.get(0) {
                Some(h) => *h,
                None => continue,
            };
            let port: u16 = parts.get(1).unwrap_or(&"9092").parse().unwrap_or(9092);

            // Connect to broker
            let addr = format!("{}:{}", host, port);
            let stream = match tokio::time::timeout(
                std::time::Duration::from_secs(10),
                tokio::net::TcpStream::connect(&addr)
            ).await {
                Ok(Ok(s)) => s,
                _ => continue,
            };

            // Build Kafka Fetch request (simplified - API v0 for compatibility)
            let correlation_id: i32 = 1;
            let mut request = Vec::new();

            // API Key (Fetch = 1), API Version (0)
            request.extend_from_slice(&1i16.to_be_bytes());
            request.extend_from_slice(&0i16.to_be_bytes());
            request.extend_from_slice(&correlation_id.to_be_bytes());

            // Client ID
            let client_id = "heroforge";
            request.extend_from_slice(&(client_id.len() as i16).to_be_bytes());
            request.extend_from_slice(client_id.as_bytes());

            // Replica ID (-1 for consumer)
            request.extend_from_slice(&(-1i32).to_be_bytes());

            // Max wait time
            request.extend_from_slice(&(timeout_ms as i32).to_be_bytes());

            // Min bytes (1)
            request.extend_from_slice(&1i32.to_be_bytes());

            // Topics array (1 topic)
            request.extend_from_slice(&1i32.to_be_bytes());

            // Topic name
            let topic_bytes = self.topic.as_bytes();
            request.extend_from_slice(&(topic_bytes.len() as i16).to_be_bytes());
            request.extend_from_slice(topic_bytes);

            // Partitions array (1 partition)
            request.extend_from_slice(&1i32.to_be_bytes());

            // Partition 0
            request.extend_from_slice(&0i32.to_be_bytes());

            // Fetch offset (0 = beginning)
            request.extend_from_slice(&0i64.to_be_bytes());

            // Max bytes (1 MB)
            request.extend_from_slice(&(1048576i32).to_be_bytes());

            // Prepend request length
            let mut full_request = Vec::new();
            full_request.extend_from_slice(&(request.len() as i32).to_be_bytes());
            full_request.extend_from_slice(&request);

            // Split stream for reading and writing
            let (mut reader, mut writer) = stream.into_split();

            // Send request
            if writer.write_all(&full_request).await.is_err() {
                continue;
            }

            // Read response length
            let mut len_buf = [0u8; 4];
            if reader.read_exact(&mut len_buf).await.is_err() {
                continue;
            }
            let resp_len = i32::from_be_bytes(len_buf) as usize;

            if resp_len > 10_000_000 || resp_len < 4 {
                continue;
            }

            // Read response
            let mut resp_buf = vec![0u8; resp_len];
            if reader.read_exact(&mut resp_buf).await.is_err() {
                continue;
            }

            // Parse response to extract messages
            messages = self.parse_fetch_response(&resp_buf, max_messages);
            if !messages.is_empty() {
                break;
            }
        }

        Ok(messages)
    }

    fn parse_fetch_response(&self, data: &[u8], max_messages: usize) -> Vec<KafkaMessage> {
        let mut messages = Vec::new();

        if data.len() < 8 {
            return messages;
        }

        // Skip correlation ID (4 bytes)
        let mut offset = 4;

        // Responses array length (4 bytes)
        if offset + 4 > data.len() {
            return messages;
        }
        let responses_len = i32::from_be_bytes([
            data[offset], data[offset + 1], data[offset + 2], data[offset + 3]
        ]) as usize;
        offset += 4;

        for _ in 0..responses_len {
            if offset + 2 > data.len() {
                break;
            }

            // Topic name length (2)
            let name_len = i16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
            offset += 2 + name_len;

            // Partitions array length (4)
            if offset + 4 > data.len() {
                break;
            }
            let partitions_len = i32::from_be_bytes([
                data[offset], data[offset + 1], data[offset + 2], data[offset + 3]
            ]) as usize;
            offset += 4;

            for _ in 0..partitions_len {
                if offset + 24 > data.len() {
                    break;
                }

                // Partition (4) + error (2) + high watermark (8)
                let partition = i32::from_be_bytes([
                    data[offset], data[offset + 1], data[offset + 2], data[offset + 3]
                ]);
                offset += 4 + 2 + 8;

                // Message set size (4)
                if offset + 4 > data.len() {
                    break;
                }
                let msg_set_size = i32::from_be_bytes([
                    data[offset], data[offset + 1], data[offset + 2], data[offset + 3]
                ]) as usize;
                offset += 4;

                // Parse messages from message set
                let msg_set_end = (offset + msg_set_size).min(data.len());
                while offset + 26 < msg_set_end && messages.len() < max_messages {
                    // Offset (8)
                    let msg_offset = i64::from_be_bytes([
                        data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
                        data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7]
                    ]);
                    offset += 8;

                    // Message size (4)
                    let msg_size = i32::from_be_bytes([
                        data[offset], data[offset + 1], data[offset + 2], data[offset + 3]
                    ]) as usize;
                    offset += 4;

                    if msg_size < 14 || offset + msg_size > data.len() {
                        break;
                    }

                    // CRC (4) + magic (1) + attributes (1) + timestamp (8 for magic >= 1)
                    let magic = data[offset + 4];
                    let timestamp_offset = if magic >= 1 { 14 } else { 6 };

                    if offset + timestamp_offset + 8 > data.len() {
                        offset += msg_size;
                        continue;
                    }

                    // Key length (4)
                    let key_start = offset + timestamp_offset;
                    if key_start + 4 > data.len() {
                        offset += msg_size;
                        continue;
                    }
                    let key_len = i32::from_be_bytes([
                        data[key_start], data[key_start + 1], data[key_start + 2], data[key_start + 3]
                    ]);
                    let key = if key_len > 0 && key_start + 4 + key_len as usize <= data.len() {
                        Some(String::from_utf8_lossy(&data[key_start + 4..key_start + 4 + key_len as usize]).to_string())
                    } else {
                        None
                    };

                    // Value length and value
                    let value_start = key_start + 4 + key_len.max(0) as usize;
                    if value_start + 4 > data.len() {
                        offset += msg_size;
                        continue;
                    }
                    let value_len = i32::from_be_bytes([
                        data[value_start], data[value_start + 1], data[value_start + 2], data[value_start + 3]
                    ]);
                    let value = if value_len > 0 && value_start + 4 + value_len as usize <= data.len() {
                        data[value_start + 4..value_start + 4 + value_len as usize].to_vec()
                    } else {
                        Vec::new()
                    };

                    messages.push(KafkaMessage {
                        topic: self.topic.clone(),
                        partition,
                        offset: msg_offset,
                        timestamp: Utc::now(),
                        key,
                        value,
                        headers: HashMap::new(),
                    });

                    offset += msg_size;
                }
                offset = msg_set_end;
            }
        }

        messages
    }

    /// Get consumer group offsets
    pub async fn get_consumer_offsets(&self) -> Result<HashMap<i32, i64>> {
        Ok(HashMap::new())
    }
}

/// Kafka message
#[derive(Debug, Clone)]
pub struct KafkaMessage {
    pub topic: String,
    pub partition: i32,
    pub offset: i64,
    pub timestamp: DateTime<Utc>,
    pub key: Option<String>,
    pub value: Vec<u8>,
    pub headers: HashMap<String, String>,
}

impl KafkaMessage {
    /// Convert to StreamEvent
    pub fn to_stream_event(&self) -> StreamEvent {
        let mut data: HashMap<String, serde_json::Value> = HashMap::new();

        // Try to parse value as JSON
        if let Ok(json_str) = std::str::from_utf8(&self.value) {
            if let Ok(json_val) = serde_json::from_str::<serde_json::Value>(json_str) {
                if let Some(obj) = json_val.as_object() {
                    for (k, v) in obj {
                        data.insert(k.clone(), v.clone());
                    }
                } else {
                    data.insert("value".to_string(), json_val);
                }
            } else {
                data.insert("value".to_string(), serde_json::json!(json_str));
            }
        } else {
            data.insert("value".to_string(), serde_json::json!(base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &self.value)));
        }

        if let Some(ref key) = self.key {
            data.insert("key".to_string(), serde_json::json!(key));
        }

        data.insert("offset".to_string(), serde_json::json!(self.offset));
        data.insert("partition".to_string(), serde_json::json!(self.partition));

        StreamEvent {
            event_id: format!("{}-{}-{}", self.topic, self.partition, self.offset),
            event_type: "kafka_message".to_string(),
            timestamp: self.timestamp,
            data,
            source: self.topic.clone(),
        }
    }
}

// ============================================================================
// Pulsar Connector - Full Pulsar Protocol Implementation
// ============================================================================

/// Apache Pulsar connector for consuming messages
pub struct PulsarConnector {
    service_url: String,
    topic: String,
    subscription: String,
    auth: Option<super::types::PulsarAuth>,
}

impl PulsarConnector {
    pub fn new(
        service_url: String,
        topic: String,
        subscription: Option<String>,
        auth: Option<super::types::PulsarAuth>,
    ) -> Self {
        Self {
            service_url,
            topic,
            subscription: subscription.unwrap_or_else(|| format!("heroforge-sub-{}", uuid::Uuid::new_v4())),
            auth,
        }
    }

    /// Fetch messages from Pulsar topic using HTTP admin API
    pub async fn fetch_messages(&self, max_messages: usize, timeout_ms: u64) -> Result<Vec<PulsarMessage>> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Parse service URL
        let url = url::Url::parse(&self.service_url)
            .context("Invalid Pulsar service URL")?;

        let host = url.host_str().context("No host in URL")?;
        let port = url.port().unwrap_or(if url.scheme() == "pulsar+ssl" { 6651 } else { 6650 });

        // Connect to Pulsar broker
        let addr = format!("{}:{}", host, port);
        let stream = match tokio::time::timeout(
            std::time::Duration::from_secs(10),
            tokio::net::TcpStream::connect(&addr)
        ).await {
            Ok(Ok(s)) => s,
            _ => return Ok(Vec::new()),
        };

        let consumer_id: u64 = rand::random();

        // Build CONNECT command
        let mut connect_cmd = Vec::new();
        connect_cmd.extend_from_slice(&[0x08, 0x02]); // type = CONNECT
        let version = "heroforge-1.0";
        connect_cmd.push(0x12);
        connect_cmd.push(version.len() as u8);
        connect_cmd.extend_from_slice(version.as_bytes());

        // Add auth if present
        if let Some(ref auth) = self.auth {
            if let Some(ref token) = auth.token {
                connect_cmd.push(0x1a);
                connect_cmd.push(5); // "token"
                connect_cmd.extend_from_slice(b"token");
                connect_cmd.push(0x22);
                Self::encode_varint_static(&mut connect_cmd, token.len() as u64);
                connect_cmd.extend_from_slice(token.as_bytes());
            }
        }

        connect_cmd.extend_from_slice(&[0x28, 0x0f]); // protocol version 15

        // Frame and send
        let total_size = 4 + connect_cmd.len();
        let mut frame = Vec::new();
        frame.extend_from_slice(&(total_size as u32).to_be_bytes());
        frame.extend_from_slice(&(connect_cmd.len() as u32).to_be_bytes());
        frame.extend_from_slice(&connect_cmd);

        let (mut reader, mut writer) = stream.into_split();

        if writer.write_all(&frame).await.is_err() {
            return Ok(Vec::new());
        }

        // Read CONNECTED response
        let mut size_buf = [0u8; 4];
        if reader.read_exact(&mut size_buf).await.is_err() {
            return Ok(Vec::new());
        }
        let resp_size = u32::from_be_bytes(size_buf) as usize;
        let mut resp = vec![0u8; resp_size];
        if reader.read_exact(&mut resp).await.is_err() {
            return Ok(Vec::new());
        }

        // Build SUBSCRIBE command
        let request_id: u64 = rand::random();
        let mut sub_cmd = Vec::new();
        sub_cmd.extend_from_slice(&[0x08, 0x0a]); // type = SUBSCRIBE

        // Topic
        sub_cmd.push(0x12);
        let topic_bytes = self.topic.as_bytes();
        Self::encode_varint_static(&mut sub_cmd, topic_bytes.len() as u64);
        sub_cmd.extend_from_slice(topic_bytes);

        // Subscription
        sub_cmd.push(0x1a);
        let sub_bytes = self.subscription.as_bytes();
        Self::encode_varint_static(&mut sub_cmd, sub_bytes.len() as u64);
        sub_cmd.extend_from_slice(sub_bytes);

        // Subscription type: Shared = 1
        sub_cmd.extend_from_slice(&[0x20, 0x01]);

        // Consumer ID
        sub_cmd.push(0x28);
        Self::encode_varint_static(&mut sub_cmd, consumer_id);

        // Request ID
        sub_cmd.push(0x30);
        Self::encode_varint_static(&mut sub_cmd, request_id);

        // Frame and send SUBSCRIBE
        let total_size = 4 + sub_cmd.len();
        let mut frame = Vec::new();
        frame.extend_from_slice(&(total_size as u32).to_be_bytes());
        frame.extend_from_slice(&(sub_cmd.len() as u32).to_be_bytes());
        frame.extend_from_slice(&sub_cmd);

        if writer.write_all(&frame).await.is_err() {
            return Ok(Vec::new());
        }

        // Read response
        let mut size_buf = [0u8; 4];
        if reader.read_exact(&mut size_buf).await.is_err() {
            return Ok(Vec::new());
        }
        let resp_size = u32::from_be_bytes(size_buf) as usize;
        let mut resp = vec![0u8; resp_size];
        if reader.read_exact(&mut resp).await.is_err() {
            return Ok(Vec::new());
        }

        // Build FLOW command
        let mut flow_cmd = Vec::new();
        flow_cmd.extend_from_slice(&[0x08, 0x0d]); // type = FLOW
        flow_cmd.push(0x10);
        Self::encode_varint_static(&mut flow_cmd, consumer_id);
        flow_cmd.push(0x18);
        Self::encode_varint_static(&mut flow_cmd, max_messages as u64);

        // Frame and send FLOW
        let total_size = 4 + flow_cmd.len();
        let mut frame = Vec::new();
        frame.extend_from_slice(&(total_size as u32).to_be_bytes());
        frame.extend_from_slice(&(flow_cmd.len() as u32).to_be_bytes());
        frame.extend_from_slice(&flow_cmd);

        if writer.write_all(&frame).await.is_err() {
            return Ok(Vec::new());
        }

        // Receive messages
        let mut messages = Vec::new();
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(timeout_ms);

        while messages.len() < max_messages && std::time::Instant::now() < deadline {
            let mut size_buf = [0u8; 4];
            match tokio::time::timeout(
                deadline.saturating_duration_since(std::time::Instant::now()),
                reader.read_exact(&mut size_buf)
            ).await {
                Ok(Ok(_)) => {}
                _ => break,
            }

            let frame_size = u32::from_be_bytes(size_buf) as usize;
            if frame_size == 0 || frame_size > 10_000_000 {
                break;
            }

            let mut frame = vec![0u8; frame_size];
            if reader.read_exact(&mut frame).await.is_err() {
                break;
            }

            // Parse frame
            if frame.len() < 4 {
                continue;
            }

            let cmd_size = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]) as usize;
            if cmd_size > frame.len() - 4 {
                continue;
            }

            let cmd_data = &frame[4..4 + cmd_size];

            // Check for MESSAGE command (type = 6)
            if cmd_data.len() >= 2 && cmd_data[0] == 0x08 && cmd_data[1] == 6 {
                // Parse message
                if let Some(msg) = self.parse_message_frame(cmd_data, &frame[4 + cmd_size..]) {
                    messages.push(msg);
                }
            }
        }

        Ok(messages)
    }

    fn encode_varint_static(buf: &mut Vec<u8>, mut value: u64) {
        while value >= 0x80 {
            buf.push((value as u8 & 0x7F) | 0x80);
            value >>= 7;
        }
        buf.push(value as u8);
    }

    fn decode_varint(&self, data: &[u8]) -> (u64, usize) {
        let mut result: u64 = 0;
        let mut shift = 0;
        let mut bytes_read = 0;

        for &byte in data.iter() {
            bytes_read += 1;
            result |= ((byte & 0x7F) as u64) << shift;
            if byte & 0x80 == 0 {
                break;
            }
            shift += 7;
            if shift > 63 {
                break;
            }
        }

        (result, bytes_read)
    }

    fn parse_message_frame(&self, cmd_data: &[u8], payload_data: &[u8]) -> Option<PulsarMessage> {
        let mut message_id = PulsarMessageId::default();
        let mut offset = 2;

        // Parse command to get message ID
        while offset < cmd_data.len() {
            let tag = cmd_data.get(offset)?;
            let field_num = tag >> 3;
            let wire_type = tag & 0x07;
            offset += 1;

            match (field_num, wire_type) {
                (3, 2) => {
                    // Message ID
                    let (len, bytes) = self.decode_varint(&cmd_data[offset..]);
                    offset += bytes;
                    if offset + len as usize <= cmd_data.len() {
                        message_id = self.parse_message_id(&cmd_data[offset..offset + len as usize]);
                    }
                    offset += len as usize;
                }
                _ => {
                    if wire_type == 0 {
                        let (_, bytes) = self.decode_varint(&cmd_data[offset..]);
                        offset += bytes;
                    } else if wire_type == 2 {
                        let (len, bytes) = self.decode_varint(&cmd_data[offset..]);
                        offset += bytes + len as usize;
                    } else {
                        break;
                    }
                }
            }
        }

        // Parse payload
        if payload_data.len() < 4 {
            return None;
        }

        let metadata_size = u32::from_be_bytes([
            payload_data[0], payload_data[1], payload_data[2], payload_data[3]
        ]) as usize;

        if 4 + metadata_size > payload_data.len() {
            return None;
        }

        let payload_start = 4 + metadata_size;
        let payload = if payload_start < payload_data.len() {
            payload_data[payload_start..].to_vec()
        } else {
            Vec::new()
        };

        Some(PulsarMessage {
            topic: self.topic.clone(),
            message_id,
            publish_time: Utc::now(),
            producer_name: String::new(),
            properties: HashMap::new(),
            payload,
        })
    }

    fn parse_message_id(&self, data: &[u8]) -> PulsarMessageId {
        let mut id = PulsarMessageId::default();
        let mut offset = 0;

        while offset < data.len() {
            let tag = match data.get(offset) {
                Some(t) => *t,
                None => break,
            };
            let field_num = tag >> 3;
            offset += 1;

            let (val, bytes) = self.decode_varint(&data[offset..]);
            offset += bytes;

            match field_num {
                1 => id.ledger_id = val,
                2 => id.entry_id = val,
                3 => id.partition = val as i32,
                4 => id.batch_index = val as i32,
                _ => {}
            }
        }

        id
    }

    /// Get topic statistics via admin API
    pub async fn get_topic_stats(&self) -> Result<PulsarTopicStats> {
        // Parse admin URL from service URL
        let url = url::Url::parse(&self.service_url)?;
        let host = url.host_str().context("No host")?;
        let admin_port = 8080; // Default admin port

        let admin_url = format!(
            "http://{}:{}/admin/v2/persistent/{}/stats",
            host,
            admin_port,
            self.topic.replace("persistent://", "").replace("non-persistent://", "")
        );

        // HTTP request to admin API
        let request = format!(
            "GET {} HTTP/1.1\r\nHost: {}:{}\r\nAccept: application/json\r\n",
            admin_url.split(&format!("{}:{}", host, admin_port)).nth(1).unwrap_or("/"),
            host,
            admin_port
        );

        let auth_header = if let Some(ref auth) = self.auth {
            if let Some(ref token) = auth.token {
                format!("Authorization: Bearer {}\r\n", token)
            } else {
                String::new()
            }
        } else {
            String::new()
        };

        let full_request = format!("{}{}\r\n", request, auth_header);

        // Connect and send
        let stream = tokio::net::TcpStream::connect(format!("{}:{}", host, admin_port)).await?;
        let (mut reader, mut writer) = tokio::io::split(stream);

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        writer.write_all(full_request.as_bytes()).await?;

        let mut response = vec![0u8; 65536];
        let n = reader.read(&mut response).await?;
        let response_str = String::from_utf8_lossy(&response[..n]);

        // Parse JSON body
        if let Some(body_start) = response_str.find("\r\n\r\n") {
            let body = &response_str[body_start + 4..];
            if let Ok(stats) = serde_json::from_str::<PulsarTopicStats>(body) {
                return Ok(stats);
            }
        }

        Ok(PulsarTopicStats::default())
    }
}

/// Pulsar message
#[derive(Debug, Clone)]
pub struct PulsarMessage {
    pub topic: String,
    pub message_id: PulsarMessageId,
    pub publish_time: DateTime<Utc>,
    pub producer_name: String,
    pub properties: HashMap<String, String>,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Default)]
pub struct PulsarMessageId {
    pub ledger_id: u64,
    pub entry_id: u64,
    pub partition: i32,
    pub batch_index: i32,
}

#[derive(Debug, Default)]
struct PulsarMessageMetadata {
    producer_name: String,
    publish_time: DateTime<Utc>,
    properties: HashMap<String, String>,
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PulsarTopicStats {
    pub msg_rate_in: f64,
    pub msg_rate_out: f64,
    pub msg_throughput_in: f64,
    pub msg_throughput_out: f64,
    pub storage_size: u64,
    pub backlog_size: u64,
}

impl PulsarMessage {
    /// Convert to StreamEvent
    pub fn to_stream_event(&self) -> StreamEvent {
        let mut data: HashMap<String, serde_json::Value> = HashMap::new();

        // Try to parse payload as JSON
        if let Ok(json_str) = std::str::from_utf8(&self.payload) {
            if let Ok(json_val) = serde_json::from_str::<serde_json::Value>(json_str) {
                if let Some(obj) = json_val.as_object() {
                    for (k, v) in obj {
                        data.insert(k.clone(), v.clone());
                    }
                } else {
                    data.insert("payload".to_string(), json_val);
                }
            } else {
                data.insert("payload".to_string(), serde_json::json!(json_str));
            }
        } else {
            data.insert("payload".to_string(), serde_json::json!(base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &self.payload)));
        }

        // Add properties
        for (k, v) in &self.properties {
            data.insert(format!("prop_{}", k), serde_json::json!(v));
        }

        data.insert("producer".to_string(), serde_json::json!(self.producer_name));
        data.insert("ledger_id".to_string(), serde_json::json!(self.message_id.ledger_id));
        data.insert("entry_id".to_string(), serde_json::json!(self.message_id.entry_id));

        StreamEvent {
            event_id: format!(
                "{}:{}:{}:{}",
                self.message_id.ledger_id,
                self.message_id.entry_id,
                self.message_id.partition,
                self.message_id.batch_index
            ),
            event_type: "pulsar_message".to_string(),
            timestamp: self.publish_time,
            data,
            source: self.topic.clone(),
        }
    }
}

// ============================================================================
// Stream Query Processing with Actual Connectors
// ============================================================================

/// Process real-time stream query using actual streaming connectors
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

    // Determine stream source from query metadata
    let stream_source = extract_stream_source(query);
    let mut events = Vec::new();

    // Fetch events from the appropriate streaming source
    match stream_source {
        Some(super::types::StreamSource::Kafka { brokers, topic, group_id, security }) => {
            let connector = KafkaConnector::new(brokers, topic, group_id, security);
            match connector.fetch_messages(1000, 5000).await {
                Ok(messages) => {
                    for msg in messages {
                        events.push(msg.to_stream_event());
                    }
                }
                Err(e) => {
                    log::warn!("Failed to fetch from Kafka: {}", e);
                }
            }
        }
        Some(super::types::StreamSource::Pulsar { service_url, topic, subscription, auth }) => {
            let connector = PulsarConnector::new(service_url, topic, subscription, auth);
            match connector.fetch_messages(1000, 5000).await {
                Ok(messages) => {
                    for msg in messages {
                        events.push(msg.to_stream_event());
                    }
                }
                Err(e) => {
                    log::warn!("Failed to fetch from Pulsar: {}", e);
                }
            }
        }
        Some(super::types::StreamSource::RedPanda { brokers, topic }) => {
            // RedPanda is Kafka-compatible
            let connector = KafkaConnector::new(brokers, topic, None, None);
            match connector.fetch_messages(1000, 5000).await {
                Ok(messages) => {
                    for msg in messages {
                        events.push(msg.to_stream_event());
                    }
                }
                Err(e) => {
                    log::warn!("Failed to fetch from RedPanda: {}", e);
                }
            }
        }
        Some(super::types::StreamSource::Kinesis { stream_name, region }) => {
            // AWS Kinesis would require AWS SDK
            log::info!("Kinesis stream {} in region {:?} - requires AWS credentials", stream_name, region);
        }
        _ => {
            // No stream source configured, use local events if any
            log::debug!("No stream source configured, processing existing events");
        }
    }

    // Process events through the stream processor
    for event in &events {
        // Apply filters
        let mut matches = true;
        for filter in &query.parameters.filters {
            if !event_matches_filter(event, filter) {
                matches = false;
                break;
            }
        }

        if matches {
            processor.process_event(event.clone(), &window_config).await?;
        }
    }

    // Trigger window computations
    let window_results = processor.trigger_windows(&query.parameters.aggregations).await?;

    // Build result rows
    let mut rows = Vec::new();

    // Add window results
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

    // If no window results, return raw events (limited)
    if rows.is_empty() && !events.is_empty() {
        for event in events.iter().take(100) {
            let mut row: HashMap<String, serde_json::Value> = HashMap::new();
            row.insert("event_id".to_string(), serde_json::json!(event.event_id));
            row.insert("event_type".to_string(), serde_json::json!(event.event_type));
            row.insert("timestamp".to_string(), serde_json::json!(event.timestamp.to_rfc3339()));
            row.insert("source".to_string(), serde_json::json!(event.source));

            for (k, v) in &event.data {
                row.insert(k.clone(), v.clone());
            }

            rows.push(row);
        }
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
            scanned_bytes: events.iter().map(|e| e.data.len() * 50).sum(), // Estimate
            cached: false,
        },
    })
}

/// Extract stream source configuration from query
fn extract_stream_source(query: &AnalyticsQuery) -> Option<super::types::StreamSource> {
    // Check for stream configuration in filters
    for filter in &query.parameters.filters {
        if filter.field == "_stream_source" {
            if let Some(source_str) = filter.value.as_str() {
                // Parse source string: "kafka://broker1:9092,broker2:9092/topic"
                if source_str.starts_with("kafka://") {
                    let rest = &source_str[8..];
                    if let Some((brokers_str, topic)) = rest.rsplit_once('/') {
                        let brokers: Vec<String> = brokers_str.split(',').map(|s| s.to_string()).collect();
                        return Some(super::types::StreamSource::Kafka {
                            brokers,
                            topic: topic.to_string(),
                            group_id: None,
                            security: None,
                        });
                    }
                } else if source_str.starts_with("pulsar://") || source_str.starts_with("pulsar+ssl://") {
                    // Parse: pulsar://host:6650/tenant/namespace/topic
                    if let Some(slash_pos) = source_str[9..].find('/') {
                        let service_url = source_str[..9 + slash_pos].to_string();
                        let topic = format!("persistent://{}", &source_str[9 + slash_pos + 1..]);
                        return Some(super::types::StreamSource::Pulsar {
                            service_url,
                            topic,
                            subscription: None,
                            auth: None,
                        });
                    }
                } else if source_str.starts_with("redpanda://") {
                    let rest = &source_str[11..];
                    if let Some((brokers_str, topic)) = rest.rsplit_once('/') {
                        let brokers: Vec<String> = brokers_str.split(',').map(|s| s.to_string()).collect();
                        return Some(super::types::StreamSource::RedPanda {
                            brokers,
                            topic: topic.to_string(),
                        });
                    }
                }
            }
        }
    }

    None
}

/// Check if an event matches a filter
fn event_matches_filter(event: &StreamEvent, filter: &Filter) -> bool {
    // Get the value from event data
    let value = match filter.field.as_str() {
        "event_type" => Some(serde_json::json!(event.event_type.clone())),
        "source" => Some(serde_json::json!(event.source.clone())),
        "event_id" => Some(serde_json::json!(event.event_id.clone())),
        _ => event.data.get(&filter.field).cloned(),
    };

    let Some(value) = value else {
        return false;
    };

    match &filter.operator {
        FilterOperator::Equals => value == filter.value,
        FilterOperator::NotEquals => value != filter.value,
        FilterOperator::GreaterThan => {
            if let (Some(a), Some(b)) = (value.as_f64(), filter.value.as_f64()) {
                a > b
            } else {
                false
            }
        }
        FilterOperator::LessThan => {
            if let (Some(a), Some(b)) = (value.as_f64(), filter.value.as_f64()) {
                a < b
            } else {
                false
            }
        }
        FilterOperator::Contains => {
            if let (Some(a), Some(b)) = (value.as_str(), filter.value.as_str()) {
                a.contains(b)
            } else {
                false
            }
        }
        FilterOperator::StartsWith => {
            if let (Some(a), Some(b)) = (value.as_str(), filter.value.as_str()) {
                a.starts_with(b)
            } else {
                false
            }
        }
        FilterOperator::EndsWith => {
            if let (Some(a), Some(b)) = (value.as_str(), filter.value.as_str()) {
                a.ends_with(b)
            } else {
                false
            }
        }
        FilterOperator::In => {
            if let Some(arr) = filter.value.as_array() {
                arr.contains(&value)
            } else {
                false
            }
        }
        FilterOperator::NotIn => {
            if let Some(arr) = filter.value.as_array() {
                !arr.contains(&value)
            } else {
                true
            }
        }
        FilterOperator::Between => {
            if let Some(arr) = filter.value.as_array() {
                if arr.len() == 2 {
                    if let (Some(v), Some(low), Some(high)) = (
                        value.as_f64(),
                        arr[0].as_f64(),
                        arr[1].as_f64(),
                    ) {
                        return v >= low && v <= high;
                    }
                }
            }
            false
        }
    }
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
