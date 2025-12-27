//! Coverage Tracking
//!
//! Track code coverage during fuzzing for guided mutation.

use std::collections::{HashMap, HashSet};
use chrono::{DateTime, Utc};

use crate::fuzzing::types::CoverageInfo;

/// Edge in the control flow graph
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub struct Edge {
    pub from: u64,
    pub to: u64,
}

/// Coverage tracker
pub struct CoverageTracker {
    /// All seen edges
    edges: HashSet<Edge>,
    /// Edge hit counts
    edge_hits: HashMap<Edge, u64>,
    /// New edges discovered in current session
    new_edges: HashSet<Edge>,
    /// Session start time
    session_start: DateTime<Utc>,
    /// Total edges (if known from static analysis)
    total_edges: Option<u64>,
    /// Basic blocks covered
    blocks: HashSet<u64>,
    /// Total blocks (if known)
    total_blocks: Option<u64>,
}

impl CoverageTracker {
    /// Create a new coverage tracker
    pub fn new() -> Self {
        Self {
            edges: HashSet::new(),
            edge_hits: HashMap::new(),
            new_edges: HashSet::new(),
            session_start: Utc::now(),
            total_edges: None,
            blocks: HashSet::new(),
            total_blocks: None,
        }
    }

    /// Set total edges for coverage percentage calculation
    pub fn set_total_edges(&mut self, total: u64) {
        self.total_edges = Some(total);
    }

    /// Set total blocks for coverage percentage calculation
    pub fn set_total_blocks(&mut self, total: u64) {
        self.total_blocks = Some(total);
    }

    /// Record an edge hit
    pub fn record_edge(&mut self, from: u64, to: u64) -> bool {
        let edge = Edge { from, to };
        let is_new = self.edges.insert(edge);

        *self.edge_hits.entry(edge).or_insert(0) += 1;

        if is_new {
            self.new_edges.insert(edge);
        }

        is_new
    }

    /// Record a block hit
    pub fn record_block(&mut self, addr: u64) -> bool {
        self.blocks.insert(addr)
    }

    /// Record coverage from AFL-style bitmap
    pub fn record_bitmap(&mut self, bitmap: &[u8]) -> usize {
        let mut new_edges = 0;

        for (i, &hit_count) in bitmap.iter().enumerate() {
            if hit_count > 0 {
                // AFL uses single byte for edge ID
                let edge = Edge {
                    from: i as u64,
                    to: 0, // AFL doesn't distinguish from/to
                };

                if self.edges.insert(edge) {
                    new_edges += 1;
                    self.new_edges.insert(edge);
                }

                *self.edge_hits.entry(edge).or_insert(0) += hit_count as u64;
            }
        }

        new_edges
    }

    /// Record coverage from SanCov-style trace
    pub fn record_trace(&mut self, pcs: &[u64]) -> usize {
        let mut new_edges = 0;

        // Record blocks
        for &pc in pcs {
            if self.blocks.insert(pc) {
                new_edges += 1;
            }
        }

        // Record edges between consecutive PCs
        for window in pcs.windows(2) {
            let edge = Edge {
                from: window[0],
                to: window[1],
            };

            if self.edges.insert(edge) {
                self.new_edges.insert(edge);
            }

            *self.edge_hits.entry(edge).or_insert(0) += 1;
        }

        new_edges
    }

    /// Get coverage percentage
    pub fn get_coverage_percent(&self) -> f64 {
        if let Some(total) = self.total_edges {
            if total > 0 {
                return (self.edges.len() as f64 / total as f64) * 100.0;
            }
        }

        // If total is unknown, return edges discovered
        self.edges.len() as f64
    }

    /// Get block coverage percentage
    pub fn get_block_coverage_percent(&self) -> f64 {
        if let Some(total) = self.total_blocks {
            if total > 0 {
                return (self.blocks.len() as f64 / total as f64) * 100.0;
            }
        }

        self.blocks.len() as f64
    }

    /// Get number of covered edges
    pub fn get_covered_edges(&self) -> u64 {
        self.edges.len() as u64
    }

    /// Get number of new edges this session
    pub fn get_new_edges(&self) -> u64 {
        self.new_edges.len() as u64
    }

    /// Get number of covered blocks
    pub fn get_covered_blocks(&self) -> u64 {
        self.blocks.len() as u64
    }

    /// Get edge hit map (for analysis)
    pub fn get_edge_hits(&self) -> HashMap<u64, u64> {
        // Convert Edge keys to u64 for simpler serialization
        self.edge_hits
            .iter()
            .map(|(edge, count)| (edge.from ^ edge.to, *count))
            .collect()
    }

    /// Get hot edges (most frequently hit)
    pub fn get_hot_edges(&self, top_n: usize) -> Vec<(Edge, u64)> {
        let mut edges: Vec<_> = self.edge_hits.iter().map(|(&e, &c)| (e, c)).collect();
        edges.sort_by(|a, b| b.1.cmp(&a.1));
        edges.truncate(top_n);
        edges
    }

    /// Get cold edges (least frequently hit but covered)
    pub fn get_cold_edges(&self, top_n: usize) -> Vec<(Edge, u64)> {
        let mut edges: Vec<_> = self.edge_hits.iter().map(|(&e, &c)| (e, c)).collect();
        edges.sort_by(|a, b| a.1.cmp(&b.1));
        edges.truncate(top_n);
        edges
    }

    /// Reset new edges counter (called at start of new session)
    pub fn reset_session(&mut self) {
        self.new_edges.clear();
        self.session_start = Utc::now();
    }

    /// Get coverage info for reporting
    pub fn get_info(&self, campaign_id: &str) -> CoverageInfo {
        CoverageInfo {
            campaign_id: campaign_id.to_string(),
            timestamp: Utc::now(),
            total_edges: self.total_edges.unwrap_or(0),
            covered_edges: self.edges.len() as u64,
            coverage_percent: self.get_coverage_percent(),
            new_edges_this_session: self.new_edges.len() as u64,
            total_blocks: self.total_blocks,
            covered_blocks: Some(self.blocks.len() as u64),
            edge_hits: Some(self.get_edge_hits()),
        }
    }

    /// Merge coverage from another tracker
    pub fn merge(&mut self, other: &CoverageTracker) {
        for edge in &other.edges {
            self.edges.insert(*edge);
        }

        for (&edge, &count) in &other.edge_hits {
            *self.edge_hits.entry(edge).or_insert(0) += count;
        }

        for &block in &other.blocks {
            self.blocks.insert(block);
        }
    }

    /// Export coverage to LCOV format
    pub fn export_lcov(&self, source_files: &HashMap<String, Vec<(u64, u32)>>) -> String {
        let mut output = String::new();

        for (file, lines) in source_files {
            output.push_str(&format!("SF:{}\n", file));

            for (addr, line) in lines {
                let hit_count = self.blocks.contains(addr) as u32;
                output.push_str(&format!("DA:{},{}\n", line, hit_count));
            }

            output.push_str("end_of_record\n");
        }

        output
    }

    /// Calculate path stability (how consistent are coverage results)
    pub fn calculate_stability(&self, runs: &[HashSet<Edge>]) -> f64 {
        if runs.is_empty() {
            return 100.0;
        }

        // Find edges that appear in all runs
        let mut stable_edges = runs[0].clone();
        for run in &runs[1..] {
            stable_edges = stable_edges.intersection(run).cloned().collect();
        }

        // Find edges that appear in any run
        let mut all_edges = HashSet::new();
        for run in runs {
            for edge in run {
                all_edges.insert(*edge);
            }
        }

        if all_edges.is_empty() {
            return 100.0;
        }

        (stable_edges.len() as f64 / all_edges.len() as f64) * 100.0
    }
}

impl Default for CoverageTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse SanCov PC files
pub fn parse_sancov_pcs(data: &[u8]) -> Vec<u64> {
    if data.len() < 8 {
        return Vec::new();
    }

    // Check magic number
    let magic = u64::from_le_bytes(data[0..8].try_into().unwrap());
    if magic != 0xC0BFFFFFFFFFFF64 && magic != 0xC0BFFFFFFFFFFF32 {
        return Vec::new();
    }

    let is_64bit = magic == 0xC0BFFFFFFFFFFF64;
    let entry_size = if is_64bit { 8 } else { 4 };

    let mut pcs = Vec::new();
    let mut offset = 8;

    while offset + entry_size <= data.len() {
        let pc = if is_64bit {
            u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap())
        } else {
            u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap()) as u64
        };
        pcs.push(pc);
        offset += entry_size;
    }

    pcs
}

/// Parse AFL bitmap
pub fn parse_afl_bitmap(data: &[u8]) -> Vec<(usize, u8)> {
    data.iter()
        .enumerate()
        .filter(|(_, &count)| count > 0)
        .map(|(idx, &count)| (idx, count))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_edge_recording() {
        let mut tracker = CoverageTracker::new();

        // First edge should be new
        assert!(tracker.record_edge(0x1000, 0x1010));
        assert_eq!(tracker.get_covered_edges(), 1);
        assert_eq!(tracker.get_new_edges(), 1);

        // Same edge should not be new
        assert!(!tracker.record_edge(0x1000, 0x1010));
        assert_eq!(tracker.get_covered_edges(), 1);
        assert_eq!(tracker.get_new_edges(), 1);

        // Different edge should be new
        assert!(tracker.record_edge(0x1010, 0x1020));
        assert_eq!(tracker.get_covered_edges(), 2);
        assert_eq!(tracker.get_new_edges(), 2);
    }

    #[test]
    fn test_coverage_percent() {
        let mut tracker = CoverageTracker::new();
        tracker.set_total_edges(100);

        tracker.record_edge(0x1000, 0x1010);
        tracker.record_edge(0x1010, 0x1020);

        assert_eq!(tracker.get_coverage_percent(), 2.0);
    }

    #[test]
    fn test_bitmap_recording() {
        let mut tracker = CoverageTracker::new();

        let mut bitmap = vec![0u8; 65536];
        bitmap[100] = 1;
        bitmap[200] = 5;
        bitmap[300] = 10;

        let new_edges = tracker.record_bitmap(&bitmap);
        assert_eq!(new_edges, 3);
        assert_eq!(tracker.get_covered_edges(), 3);
    }

    #[test]
    fn test_hot_edges() {
        let mut tracker = CoverageTracker::new();

        for _ in 0..100 {
            tracker.record_edge(0x1000, 0x1010);
        }
        for _ in 0..50 {
            tracker.record_edge(0x1010, 0x1020);
        }
        for _ in 0..10 {
            tracker.record_edge(0x1020, 0x1030);
        }

        let hot = tracker.get_hot_edges(2);
        assert_eq!(hot.len(), 2);
        assert_eq!(hot[0].1, 100); // Hottest edge
        assert_eq!(hot[1].1, 50);
    }
}
