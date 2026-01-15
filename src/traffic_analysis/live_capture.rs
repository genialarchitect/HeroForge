//! Live Packet Capture Module
//!
//! Provides real-time packet capture from network interfaces using libpcap.

use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use pcap::{Capture, Device, Linktype};
use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

/// Live capture manager - handles multiple concurrent captures
pub struct LiveCaptureManager {
    /// Active captures by ID
    captures: Arc<RwLock<HashMap<String, Arc<LiveCapture>>>>,
    /// Output directory for PCAP files
    output_dir: PathBuf,
}

impl LiveCaptureManager {
    /// Create a new capture manager
    pub fn new(output_dir: PathBuf) -> Self {
        // Ensure output directory exists
        std::fs::create_dir_all(&output_dir).ok();

        Self {
            captures: Arc::new(RwLock::new(HashMap::new())),
            output_dir,
        }
    }

    /// List available network interfaces
    pub fn list_interfaces() -> Result<Vec<NetworkInterface>> {
        let devices = Device::list()
            .map_err(|e| anyhow!("Failed to list devices: {}", e))?;

        Ok(devices
            .into_iter()
            .map(|d| NetworkInterface {
                name: d.name.clone(),
                description: d.desc.clone(),
                addresses: d.addresses.iter().map(|a| format!("{:?}", a.addr)).collect(),
                is_up: true, // pcap doesn't expose this directly
                is_loopback: d.name.contains("lo") || d.name.contains("loopback"),
            })
            .collect())
    }

    /// Start a new capture
    pub async fn start_capture(&self, config: CaptureConfig) -> Result<CaptureInfo> {
        let capture_id = Uuid::new_v4().to_string();

        // Generate output file path
        let timestamp = Utc::now().format("%Y%m%d_%H%M%S");
        let filename = format!("capture_{}_{}.pcap", config.interface, timestamp);
        let file_path = self.output_dir.join(&filename);

        // Create the capture
        let live_capture = LiveCapture::new(
            capture_id.clone(),
            config.clone(),
            file_path.clone(),
        )?;

        let capture_arc = Arc::new(live_capture);

        // Store in manager
        {
            let mut captures = self.captures.write().await;
            captures.insert(capture_id.clone(), capture_arc.clone());
        }

        // Start capture in background thread
        let capture_clone = capture_arc.clone();
        std::thread::spawn(move || {
            if let Err(e) = capture_clone.run() {
                log::error!("Capture error: {}", e);
            }
        });

        Ok(CaptureInfo {
            id: capture_id,
            interface: config.interface,
            filter: config.filter,
            file_path: file_path.to_string_lossy().to_string(),
            started_at: Utc::now(),
            status: CaptureStatus::Running,
            packet_count: 0,
            bytes_captured: 0,
        })
    }

    /// Stop a capture
    pub async fn stop_capture(&self, capture_id: &str) -> Result<CaptureInfo> {
        let capture = {
            let captures = self.captures.read().await;
            captures.get(capture_id).cloned()
        };

        let capture = capture.ok_or_else(|| anyhow!("Capture not found: {}", capture_id))?;
        capture.stop();

        // Wait a moment for capture to finish
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

        let info = capture.get_info();

        // Remove from active captures
        {
            let mut captures = self.captures.write().await;
            captures.remove(capture_id);
        }

        Ok(info)
    }

    /// Get capture status
    pub async fn get_capture_status(&self, capture_id: &str) -> Result<CaptureInfo> {
        let captures = self.captures.read().await;
        let capture = captures.get(capture_id)
            .ok_or_else(|| anyhow!("Capture not found: {}", capture_id))?;

        Ok(capture.get_info())
    }

    /// List all active captures
    pub async fn list_active_captures(&self) -> Vec<CaptureInfo> {
        let captures = self.captures.read().await;
        captures.values().map(|c| c.get_info()).collect()
    }
}

/// Individual live capture session
pub struct LiveCapture {
    id: String,
    config: CaptureConfig,
    file_path: PathBuf,
    started_at: DateTime<Utc>,
    running: AtomicBool,
    packet_count: AtomicU64,
    bytes_captured: AtomicU64,
}

impl LiveCapture {
    /// Create a new live capture
    pub fn new(id: String, config: CaptureConfig, file_path: PathBuf) -> Result<Self> {
        Ok(Self {
            id,
            config,
            file_path,
            started_at: Utc::now(),
            running: AtomicBool::new(true),
            packet_count: AtomicU64::new(0),
            bytes_captured: AtomicU64::new(0),
        })
    }

    /// Run the capture (blocking - should be called from a thread)
    pub fn run(&self) -> Result<()> {
        log::info!("Starting live capture on interface: {}", self.config.interface);

        // Open capture device
        let mut cap = Capture::from_device(self.config.interface.as_str())
            .map_err(|e| anyhow!("Failed to open device: {}", e))?
            .promisc(self.config.promiscuous)
            .snaplen(self.config.snaplen as i32)
            .timeout(1000) // 1 second timeout for checking stop flag
            .open()
            .map_err(|e| anyhow!("Failed to activate capture: {}", e))?;

        // Apply BPF filter if specified
        if let Some(ref filter) = self.config.filter {
            cap.filter(filter, true)
                .map_err(|e| anyhow!("Failed to set filter '{}': {}", filter, e))?;
            log::info!("Applied BPF filter: {}", filter);
        }

        // Create PCAP file with savefile
        let mut savefile = cap.savefile(&self.file_path)
            .map_err(|e| anyhow!("Failed to create PCAP file: {}", e))?;

        log::info!("Writing packets to: {:?}", self.file_path);

        // Capture loop
        while self.running.load(Ordering::Relaxed) {
            // Check max packets limit
            if let Some(max) = self.config.max_packets {
                if self.packet_count.load(Ordering::Relaxed) >= max {
                    log::info!("Reached max packet limit: {}", max);
                    break;
                }
            }

            // Check duration limit
            if let Some(max_secs) = self.config.max_duration_secs {
                let elapsed = (Utc::now() - self.started_at).num_seconds() as u64;
                if elapsed >= max_secs {
                    log::info!("Reached max duration: {} seconds", max_secs);
                    break;
                }
            }

            // Try to get next packet
            match cap.next_packet() {
                Ok(packet) => {
                    // Write packet to file
                    savefile.write(&packet);

                    // Update counters
                    self.packet_count.fetch_add(1, Ordering::Relaxed);
                    self.bytes_captured.fetch_add(packet.len() as u64, Ordering::Relaxed);
                }
                Err(pcap::Error::TimeoutExpired) => {
                    // Normal timeout, continue loop to check stop flag
                    continue;
                }
                Err(e) => {
                    log::warn!("Packet capture error: {}", e);
                    // Continue capturing despite errors
                    continue;
                }
            }
        }

        // Flush and close
        drop(savefile);

        log::info!(
            "Capture stopped. Packets: {}, Bytes: {}",
            self.packet_count.load(Ordering::Relaxed),
            self.bytes_captured.load(Ordering::Relaxed)
        );

        Ok(())
    }

    /// Stop the capture
    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }

    /// Get capture info
    pub fn get_info(&self) -> CaptureInfo {
        let status = if self.running.load(Ordering::Relaxed) {
            CaptureStatus::Running
        } else {
            CaptureStatus::Stopped
        };

        CaptureInfo {
            id: self.id.clone(),
            interface: self.config.interface.clone(),
            filter: self.config.filter.clone(),
            file_path: self.file_path.to_string_lossy().to_string(),
            started_at: self.started_at,
            status,
            packet_count: self.packet_count.load(Ordering::Relaxed),
            bytes_captured: self.bytes_captured.load(Ordering::Relaxed),
        }
    }
}

/// Capture configuration
#[derive(Debug, Clone)]
pub struct CaptureConfig {
    /// Network interface to capture from
    pub interface: String,
    /// BPF filter expression (optional)
    pub filter: Option<String>,
    /// Capture in promiscuous mode
    pub promiscuous: bool,
    /// Snapshot length (max bytes per packet)
    pub snaplen: u32,
    /// Maximum number of packets to capture (optional)
    pub max_packets: Option<u64>,
    /// Maximum capture duration in seconds (optional)
    pub max_duration_secs: Option<u64>,
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            interface: "eth0".to_string(),
            filter: None,
            promiscuous: true,
            snaplen: 65535,
            max_packets: None,
            max_duration_secs: None,
        }
    }
}

/// Network interface information
#[derive(Debug, Clone, serde::Serialize)]
pub struct NetworkInterface {
    pub name: String,
    pub description: Option<String>,
    pub addresses: Vec<String>,
    pub is_up: bool,
    pub is_loopback: bool,
}

/// Capture status
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CaptureStatus {
    Running,
    Stopped,
    Error,
}

/// Capture information
#[derive(Debug, Clone, serde::Serialize)]
pub struct CaptureInfo {
    pub id: String,
    pub interface: String,
    pub filter: Option<String>,
    pub file_path: String,
    pub started_at: DateTime<Utc>,
    pub status: CaptureStatus,
    pub packet_count: u64,
    pub bytes_captured: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_list_interfaces() {
        // This test requires root/CAP_NET_RAW on Linux
        match LiveCaptureManager::list_interfaces() {
            Ok(interfaces) => {
                println!("Found {} interfaces", interfaces.len());
                for iface in &interfaces {
                    println!("  {} - {:?}", iface.name, iface.description);
                }
            }
            Err(e) => {
                println!("Could not list interfaces (may need root): {}", e);
            }
        }
    }
}
