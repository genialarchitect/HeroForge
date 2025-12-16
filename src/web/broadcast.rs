#![allow(dead_code)]

use crate::types::ScanProgressMessage;
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{broadcast, RwLock, Mutex};
use tokio::time;

pub type ProgressSender = broadcast::Sender<ScanProgressMessage>;
pub type ProgressReceiver = broadcast::Receiver<ScanProgressMessage>;

// Configuration constants for message throttling and batching
const MAX_MESSAGES_PER_SECOND: u32 = 10;
const BATCH_INTERVAL_MS: u64 = 100;
const MAX_BATCH_SIZE: usize = 50;
const CHANNEL_CLEANUP_DELAY_SECS: u64 = 300; // 5 minutes

/// Metadata for a scan channel
#[derive(Clone)]
struct ScanChannelInfo {
    sender: ProgressSender,
    created_at: Instant,
    last_message_at: Instant,
    message_count: u32,
    is_completed: bool,
}

/// Throttle state for rate limiting
struct ThrottleState {
    last_reset: Instant,
    message_count: u32,
}

/// Message batch for aggregating progress updates
struct MessageBatch {
    messages: Vec<ScanProgressMessage>,
    last_flush: Instant,
}

// Global map of scan_id -> channel info
static SCAN_CHANNELS: Lazy<Arc<RwLock<HashMap<String, ScanChannelInfo>>>> =
    Lazy::new(|| Arc::new(RwLock::new(HashMap::new())));

// Global map of scan_id -> throttle state
static THROTTLE_STATES: Lazy<Arc<RwLock<HashMap<String, Arc<Mutex<ThrottleState>>>>>> =
    Lazy::new(|| Arc::new(RwLock::new(HashMap::new())));

// Global map of scan_id -> message batch
static MESSAGE_BATCHES: Lazy<Arc<RwLock<HashMap<String, Arc<Mutex<MessageBatch>>>>>> =
    Lazy::new(|| Arc::new(RwLock::new(HashMap::new())));

/// Create a new broadcast channel for a scan
pub async fn create_scan_channel(scan_id: String) -> ProgressSender {
    let (tx, _) = broadcast::channel(100);
    let now = Instant::now();

    let info = ScanChannelInfo {
        sender: tx.clone(),
        created_at: now,
        last_message_at: now,
        message_count: 0,
        is_completed: false,
    };

    let mut channels = SCAN_CHANNELS.write().await;
    channels.insert(scan_id.clone(), info);

    // Initialize throttle state
    let mut throttle_states = THROTTLE_STATES.write().await;
    throttle_states.insert(
        scan_id.clone(),
        Arc::new(Mutex::new(ThrottleState {
            last_reset: now,
            message_count: 0,
        })),
    );

    // Initialize message batch
    let mut batches = MESSAGE_BATCHES.write().await;
    batches.insert(
        scan_id.clone(),
        Arc::new(Mutex::new(MessageBatch {
            messages: Vec::new(),
            last_flush: now,
        })),
    );

    // Spawn batch flusher task
    spawn_batch_flusher(scan_id);

    tx
}

/// Subscribe to progress updates for a scan
pub async fn subscribe_to_scan(scan_id: &str) -> Option<ProgressReceiver> {
    let channels = SCAN_CHANNELS.read().await;
    channels.get(scan_id).map(|info| info.sender.subscribe())
}

/// Send a progress message to all subscribers of a scan with throttling and batching
pub async fn send_progress(scan_id: &str, message: ScanProgressMessage) {
    // Check if message should bypass throttling (critical messages)
    let is_critical = is_critical_message(&message);

    if is_critical {
        // Send critical messages immediately without batching
        send_immediate(scan_id, message).await;
    } else {
        // Check throttle limit
        if should_throttle(scan_id).await {
            // Drop this message (intermediate progress update)
            log::debug!("Throttling message for scan: {}", scan_id);
            return;
        }

        // Add to batch
        add_to_batch(scan_id, message).await;
    }
}

/// Check if a message is critical and should not be dropped
fn is_critical_message(message: &ScanProgressMessage) -> bool {
    matches!(
        message,
        ScanProgressMessage::ScanStarted { .. }
            | ScanProgressMessage::PhaseStarted { .. }
            | ScanProgressMessage::ScanCompleted { .. }
            | ScanProgressMessage::Error { .. }
    )
}

/// Check if we should throttle messages for this scan
async fn should_throttle(scan_id: &str) -> bool {
    let throttle_states = THROTTLE_STATES.read().await;

    if let Some(state_arc) = throttle_states.get(scan_id) {
        let mut state = state_arc.lock().await;
        let now = Instant::now();

        // Reset counter every second
        if now.duration_since(state.last_reset) >= Duration::from_secs(1) {
            state.last_reset = now;
            state.message_count = 0;
        }

        // Check if we've exceeded the rate limit
        if state.message_count >= MAX_MESSAGES_PER_SECOND {
            return true;
        }

        state.message_count += 1;
        false
    } else {
        false
    }
}

/// Add a message to the batch
async fn add_to_batch(scan_id: &str, message: ScanProgressMessage) {
    let batches = MESSAGE_BATCHES.read().await;

    if let Some(batch_arc) = batches.get(scan_id) {
        let mut batch = batch_arc.lock().await;
        batch.messages.push(message);

        // Flush if batch is full
        if batch.messages.len() >= MAX_BATCH_SIZE {
            flush_batch_internal(scan_id, &mut batch).await;
        }
    }
}

/// Send a message immediately without batching
async fn send_immediate(scan_id: &str, message: ScanProgressMessage) {
    let channels = SCAN_CHANNELS.read().await;

    if let Some(info) = channels.get(scan_id) {
        let _ = info.sender.send(message.clone());

        // Update channel info
        drop(channels);
        let mut channels_mut = SCAN_CHANNELS.write().await;
        if let Some(info_mut) = channels_mut.get_mut(scan_id) {
            info_mut.last_message_at = Instant::now();
            info_mut.message_count += 1;

            // Mark as completed if this is a completion message
            if matches!(
                message,
                ScanProgressMessage::ScanCompleted { .. } | ScanProgressMessage::Error { .. }
            ) {
                info_mut.is_completed = true;

                // Schedule cleanup
                let scan_id_clone = scan_id.to_string();
                tokio::spawn(async move {
                    time::sleep(Duration::from_secs(CHANNEL_CLEANUP_DELAY_SECS)).await;
                    cleanup_scan_channel(&scan_id_clone).await;
                });
            }
        }
    }
}

/// Flush the message batch for a scan
async fn flush_batch(scan_id: &str) {
    let batches = MESSAGE_BATCHES.read().await;

    if let Some(batch_arc) = batches.get(scan_id) {
        let mut batch = batch_arc.lock().await;
        flush_batch_internal(scan_id, &mut batch).await;
    }
}

/// Internal batch flushing logic
async fn flush_batch_internal(scan_id: &str, batch: &mut MessageBatch) {
    if batch.messages.is_empty() {
        return;
    }

    let channels = SCAN_CHANNELS.read().await;

    if let Some(info) = channels.get(scan_id) {
        // Create a batched progress message
        let batched_message = create_batched_message(&batch.messages);
        let _ = info.sender.send(batched_message);

        // Update channel info
        drop(channels);
        let mut channels_mut = SCAN_CHANNELS.write().await;
        if let Some(info_mut) = channels_mut.get_mut(scan_id) {
            info_mut.last_message_at = Instant::now();
            info_mut.message_count += 1;
        }
    }

    batch.messages.clear();
    batch.last_flush = Instant::now();
}

/// Create a batched progress message from multiple messages
fn create_batched_message(messages: &[ScanProgressMessage]) -> ScanProgressMessage {
    if messages.is_empty() {
        return ScanProgressMessage::ScanProgress {
            phase: "unknown".to_string(),
            progress: 0.0,
            message: "Empty batch".to_string(),
        };
    }

    // For now, just send the last message in the batch
    // In a more sophisticated implementation, we could aggregate stats
    messages.last().unwrap().clone()
}

/// Spawn a background task to periodically flush batches
fn spawn_batch_flusher(scan_id: String) {
    tokio::spawn(async move {
        let mut interval = time::interval(Duration::from_millis(BATCH_INTERVAL_MS));

        loop {
            interval.tick().await;

            // Check if scan still exists
            let exists = {
                let channels = SCAN_CHANNELS.read().await;
                channels.contains_key(&scan_id)
            };

            if !exists {
                break;
            }

            flush_batch(&scan_id).await;
        }
    });
}

/// Remove a scan channel (cleanup after scan completes)
pub async fn remove_scan_channel(scan_id: &str) {
    cleanup_scan_channel(scan_id).await;
}

/// Clean up all resources for a scan channel
async fn cleanup_scan_channel(scan_id: &str) {
    log::info!("Cleaning up scan channel: {}", scan_id);

    // Flush any remaining batched messages
    flush_batch(scan_id).await;

    // Remove from all maps
    let mut channels = SCAN_CHANNELS.write().await;
    channels.remove(scan_id);

    let mut throttle_states = THROTTLE_STATES.write().await;
    throttle_states.remove(scan_id);

    let mut batches = MESSAGE_BATCHES.write().await;
    batches.remove(scan_id);
}

/// Get statistics for all active scans
pub async fn get_all_scans_stats() -> Vec<ScanStats> {
    let channels = SCAN_CHANNELS.read().await;

    channels
        .iter()
        .map(|(scan_id, info)| ScanStats {
            scan_id: scan_id.clone(),
            message_count: info.message_count,
            elapsed_time: info.created_at.elapsed().as_secs_f64(),
            is_completed: info.is_completed,
        })
        .collect()
}

/// Statistics for a single scan
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ScanStats {
    pub scan_id: String,
    pub message_count: u32,
    pub elapsed_time: f64,
    pub is_completed: bool,
}
