//! CPE Dictionary

use super::types::*;
use super::matcher::CpeMatcher;
use std::collections::HashMap;

/// CPE Dictionary for platform identification
pub struct CpeDictionary {
    entries: HashMap<String, CpeDictionaryItem>,
}

impl CpeDictionary {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Add an entry to the dictionary
    pub fn add(&mut self, item: CpeDictionaryItem) {
        let uri = item.cpe.to_uri();
        self.entries.insert(uri, item);
    }

    /// Look up a CPE by URI
    pub fn get(&self, uri: &str) -> Option<&CpeDictionaryItem> {
        self.entries.get(uri)
    }

    /// Search for CPEs matching a pattern
    pub fn search(&self, pattern: &Cpe) -> Vec<&CpeDictionaryItem> {
        self.entries
            .values()
            .filter(|item| CpeMatcher::matches(pattern, &item.cpe))
            .collect()
    }

    /// Get all entries
    pub fn all(&self) -> impl Iterator<Item = &CpeDictionaryItem> {
        self.entries.values()
    }

    /// Get entry count
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Default for CpeDictionary {
    fn default() -> Self {
        Self::new()
    }
}
