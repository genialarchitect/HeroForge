//! Beacon Detection Module
//!
//! C2 beacon detection through:
//! - Regular interval analysis
//! - Jitter detection
//! - Payload size analysis
//! - Statistical methods

use crate::traffic_analysis::types::*;
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::net::IpAddr;

/// Beacon detector for C2 traffic
pub struct BeaconDetector {
    /// Connection tracking
    connections: HashMap<ConnectionKey, Vec<ConnectionEvent>>,
    /// Detected beacons
    detected_beacons: Vec<BeaconDetection>,
    /// Configuration
    config: BeaconConfig,
}

/// Connection tracking key
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct ConnectionKey {
    src_ip: IpAddr,
    dst_ip: IpAddr,
    dst_port: u16,
}

/// Individual connection event
#[derive(Debug, Clone)]
struct ConnectionEvent {
    timestamp: DateTime<Utc>,
    bytes_sent: u64,
    bytes_received: u64,
}

/// Beacon detection configuration
#[derive(Debug, Clone)]
pub struct BeaconConfig {
    /// Minimum connections to analyze
    pub min_connections: usize,
    /// Maximum jitter percentage for beacon
    pub max_jitter_percent: f64,
    /// Minimum beacon score to report
    pub min_beacon_score: f64,
    /// Analysis window in seconds
    pub analysis_window_secs: u64,
    /// Ignore connections with high byte variance
    pub max_byte_variance_ratio: f64,
}

impl Default for BeaconConfig {
    fn default() -> Self {
        Self {
            min_connections: 10,
            max_jitter_percent: 25.0,
            min_beacon_score: 0.7,
            analysis_window_secs: 3600, // 1 hour
            max_byte_variance_ratio: 0.5,
        }
    }
}

impl BeaconDetector {
    /// Create a new beacon detector
    pub fn new() -> Self {
        Self::with_config(BeaconConfig::default())
    }

    /// Create with custom configuration
    pub fn with_config(config: BeaconConfig) -> Self {
        Self {
            connections: HashMap::new(),
            detected_beacons: Vec::new(),
            config,
        }
    }

    /// Record a connection
    pub fn record_connection(
        &mut self,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        dst_port: u16,
        bytes_sent: u64,
        bytes_received: u64,
        timestamp: DateTime<Utc>,
    ) {
        let key = ConnectionKey { src_ip, dst_ip, dst_port };

        let events = self.connections.entry(key).or_insert_with(Vec::new);
        events.push(ConnectionEvent {
            timestamp,
            bytes_sent,
            bytes_received,
        });

        // Limit memory usage
        if events.len() > 1000 {
            events.remove(0);
        }
    }

    /// Analyze all connections for beacons
    pub fn analyze(&mut self, pcap_id: &str) -> Vec<BeaconDetection> {
        let mut new_beacons = Vec::new();

        for (key, events) in &self.connections {
            if events.len() < self.config.min_connections {
                continue;
            }

            if let Some(detection) = self.analyze_connection(pcap_id, key, events) {
                if detection.beacon_score >= self.config.min_beacon_score {
                    new_beacons.push(detection);
                }
            }
        }

        self.detected_beacons.extend(new_beacons.clone());
        new_beacons
    }

    /// Analyze a single connection for beacon behavior
    fn analyze_connection(
        &self,
        pcap_id: &str,
        key: &ConnectionKey,
        events: &[ConnectionEvent],
    ) -> Option<BeaconDetection> {
        if events.len() < 2 {
            return None;
        }

        // Sort by timestamp
        let mut sorted_events: Vec<_> = events.iter().collect();
        sorted_events.sort_by_key(|e| e.timestamp);

        // Calculate intervals
        let mut intervals: Vec<f64> = Vec::new();
        for i in 1..sorted_events.len() {
            let interval = (sorted_events[i].timestamp - sorted_events[i - 1].timestamp)
                .num_seconds() as f64;
            if interval > 0.0 {
                intervals.push(interval);
            }
        }

        if intervals.is_empty() {
            return None;
        }

        // Calculate statistics
        let avg_interval = intervals.iter().sum::<f64>() / intervals.len() as f64;
        let variance = intervals.iter()
            .map(|i| (i - avg_interval).powi(2))
            .sum::<f64>() / intervals.len() as f64;
        let std_dev = variance.sqrt();

        // Calculate jitter percentage
        let jitter_percent = if avg_interval > 0.0 {
            (std_dev / avg_interval) * 100.0
        } else {
            100.0
        };

        // Calculate byte statistics
        let bytes_per_conn: Vec<f64> = events.iter()
            .map(|e| (e.bytes_sent + e.bytes_received) as f64)
            .collect();
        let avg_bytes = bytes_per_conn.iter().sum::<f64>() / bytes_per_conn.len() as f64;

        // Calculate beacon score
        // - Low jitter = higher score
        // - Regular interval = higher score
        // - Consistent payload size = higher score

        let jitter_score = if jitter_percent <= self.config.max_jitter_percent {
            1.0 - (jitter_percent / self.config.max_jitter_percent)
        } else {
            0.0
        };

        // Check for regularity using coefficient of variation
        let cv = if avg_interval > 0.0 { std_dev / avg_interval } else { 1.0 };
        let regularity_score = 1.0 - cv.min(1.0);

        // Payload consistency
        let byte_variance = bytes_per_conn.iter()
            .map(|b| (b - avg_bytes).powi(2))
            .sum::<f64>() / bytes_per_conn.len() as f64;
        let byte_std = byte_variance.sqrt();
        let byte_cv = if avg_bytes > 0.0 { byte_std / avg_bytes } else { 1.0 };
        let payload_score = 1.0 - byte_cv.min(1.0);

        // Combined score
        let beacon_score = jitter_score * 0.4 + regularity_score * 0.4 + payload_score * 0.2;

        // Determine if likely beacon
        let is_likely_beacon = beacon_score >= self.config.min_beacon_score &&
                              jitter_percent <= self.config.max_jitter_percent;

        Some(BeaconDetection {
            id: uuid::Uuid::new_v4().to_string(),
            pcap_id: pcap_id.to_string(),
            src_ip: key.src_ip,
            dst_ip: key.dst_ip,
            dst_port: key.dst_port,
            connection_count: events.len() as u64,
            avg_interval_seconds: avg_interval,
            interval_variance: variance,
            avg_bytes_per_connection: avg_bytes,
            jitter_percentage: jitter_percent,
            beacon_score,
            is_likely_beacon,
            first_seen: sorted_events.first().map(|e| e.timestamp).unwrap_or_else(Utc::now),
            last_seen: sorted_events.last().map(|e| e.timestamp).unwrap_or_else(Utc::now),
        })
    }

    /// Get detected beacons
    pub fn get_beacons(&self) -> &[BeaconDetection] {
        &self.detected_beacons
    }

    /// Get likely beacons only
    pub fn get_likely_beacons(&self) -> Vec<&BeaconDetection> {
        self.detected_beacons.iter()
            .filter(|b| b.is_likely_beacon)
            .collect()
    }

    /// Get statistics
    pub fn get_statistics(&self) -> BeaconStats {
        let total = self.connections.len();
        let analyzed = self.detected_beacons.len();
        let likely = self.detected_beacons.iter()
            .filter(|b| b.is_likely_beacon)
            .count();

        BeaconStats {
            total_connections_tracked: total,
            connections_analyzed: analyzed,
            likely_beacons: likely,
            average_beacon_score: if analyzed > 0 {
                self.detected_beacons.iter()
                    .map(|b| b.beacon_score)
                    .sum::<f64>() / analyzed as f64
            } else {
                0.0
            },
        }
    }

    /// Clear connection tracking
    pub fn clear(&mut self) {
        self.connections.clear();
        self.detected_beacons.clear();
    }
}

/// Beacon statistics
#[derive(Debug, Clone)]
pub struct BeaconStats {
    pub total_connections_tracked: usize,
    pub connections_analyzed: usize,
    pub likely_beacons: usize,
    pub average_beacon_score: f64,
}

impl Default for BeaconDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn test_beacon_detection() {
        let mut detector = BeaconDetector::new();

        let src_ip: IpAddr = "192.168.1.100".parse().unwrap();
        let dst_ip: IpAddr = "10.0.0.1".parse().unwrap();
        let base_time = Utc::now();

        // Simulate regular beacon at 60 second intervals
        for i in 0..20 {
            detector.record_connection(
                src_ip,
                dst_ip,
                443,
                100 + (i % 5) as u64, // Small variation
                200 + (i % 3) as u64,
                base_time + Duration::seconds(i * 60),
            );
        }

        let beacons = detector.analyze("test-pcap");

        assert!(!beacons.is_empty());
        let beacon = &beacons[0];
        assert!(beacon.avg_interval_seconds > 55.0 && beacon.avg_interval_seconds < 65.0);
        assert!(beacon.jitter_percentage < 10.0);
        assert!(beacon.is_likely_beacon);
    }
}
