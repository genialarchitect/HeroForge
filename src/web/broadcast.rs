use crate::types::ScanProgressMessage;
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};

pub type ProgressSender = broadcast::Sender<ScanProgressMessage>;
pub type ProgressReceiver = broadcast::Receiver<ScanProgressMessage>;

// Global map of scan_id -> broadcast sender
static SCAN_CHANNELS: Lazy<Arc<RwLock<HashMap<String, ProgressSender>>>> =
    Lazy::new(|| Arc::new(RwLock::new(HashMap::new())));

/// Create a new broadcast channel for a scan
pub async fn create_scan_channel(scan_id: String) -> ProgressSender {
    let (tx, _) = broadcast::channel(100);
    let mut channels = SCAN_CHANNELS.write().await;
    channels.insert(scan_id, tx.clone());
    tx
}

/// Subscribe to progress updates for a scan
pub async fn subscribe_to_scan(scan_id: &str) -> Option<ProgressReceiver> {
    let channels = SCAN_CHANNELS.read().await;
    channels.get(scan_id).map(|tx| tx.subscribe())
}

/// Send a progress message to all subscribers of a scan
pub async fn send_progress(scan_id: &str, message: ScanProgressMessage) {
    let channels = SCAN_CHANNELS.read().await;
    if let Some(tx) = channels.get(scan_id) {
        let _ = tx.send(message);
    }
}

/// Remove a scan channel (cleanup after scan completes)
pub async fn remove_scan_channel(scan_id: &str) {
    let mut channels = SCAN_CHANNELS.write().await;
    channels.remove(scan_id);
}
