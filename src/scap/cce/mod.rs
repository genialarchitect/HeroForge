//! CCE - Common Configuration Enumeration
//!
//! Provides mapping between CCE identifiers and compliance controls.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::scap::CceId;

/// CCE to control mapping
pub struct CceMapper {
    mappings: HashMap<String, Vec<ControlMapping>>,
}

/// Mapping from CCE to a compliance control
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlMapping {
    pub cce_id: CceId,
    pub framework: String,
    pub control_id: String,
    pub confidence: f64,
}

impl CceMapper {
    pub fn new() -> Self {
        Self {
            mappings: HashMap::new(),
        }
    }

    /// Add a mapping
    pub fn add(&mut self, cce_id: &str, mapping: ControlMapping) {
        self.mappings
            .entry(cce_id.to_string())
            .or_default()
            .push(mapping);
    }

    /// Get mappings for a CCE ID
    pub fn get(&self, cce_id: &str) -> Option<&Vec<ControlMapping>> {
        self.mappings.get(cce_id)
    }

    /// Get all control IDs for a CCE in a specific framework
    pub fn get_controls(&self, cce_id: &str, framework: &str) -> Vec<&str> {
        self.mappings
            .get(cce_id)
            .map(|mappings| {
                mappings
                    .iter()
                    .filter(|m| m.framework == framework)
                    .map(|m| m.control_id.as_str())
                    .collect()
            })
            .unwrap_or_default()
    }
}

impl Default for CceMapper {
    fn default() -> Self {
        Self::new()
    }
}
