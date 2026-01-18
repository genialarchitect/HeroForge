//! Linux OVAL Object Collectors
//!
//! Implements collectors for Linux-specific OVAL object types:
//! - dpkginfo objects (Debian/Ubuntu packages)
//! - rpminfo objects (RHEL/CentOS/Fedora packages)
//! - partition objects
//! - systemd unit objects

pub mod dpkg;
pub mod rpm;

use std::collections::HashMap;
use anyhow::Result;
use async_trait::async_trait;

use crate::scap::oval::types::{OvalItem, OvalObject, OvalValue, ItemStatus, ObjectType};
use super::unix::{UnixCollector, UnixCollectionContext, CloneUnixCollector};

/// Trait for Linux OVAL collectors (extends Unix)
#[async_trait]
pub trait LinuxCollector: UnixCollector {
    /// Check if this collector is supported on the target system
    async fn is_supported(&self, context: &UnixCollectionContext) -> bool;
}

/// Linux collector registry
pub struct LinuxCollectorRegistry {
    collectors: HashMap<ObjectType, Box<dyn CloneLinuxCollector>>,
}

impl Default for LinuxCollectorRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl LinuxCollectorRegistry {
    /// Create a new registry with all standard collectors
    pub fn new() -> Self {
        let mut registry = Self {
            collectors: HashMap::new(),
        };

        // Register all built-in collectors
        registry.register(dpkg::DpkgInfoCollector::new());
        registry.register(rpm::RpmInfoCollector::new());

        registry
    }

    /// Register a collector
    pub fn register<T: CloneLinuxCollector + Clone + 'static>(&mut self, collector: T) {
        for obj_type in collector.supported_types() {
            self.collectors.insert(obj_type, collector.clone_collector());
        }
    }

    /// Get collector for a specific object type
    pub fn get(&self, object_type: ObjectType) -> Option<&dyn LinuxCollector> {
        self.collectors.get(&object_type).map(|c| c.as_linux_collector())
    }

    /// Collect items for an OVAL object
    pub async fn collect(&self, object: &OvalObject, context: &UnixCollectionContext) -> Result<Vec<OvalItem>> {
        if let Some(collector) = self.get(object.object_type) {
            collector.collect(object, context).await
        } else {
            Ok(vec![])
        }
    }
}

/// Helper trait for cloning boxed Linux collectors
pub trait CloneLinuxCollector: LinuxCollector {
    fn clone_collector(&self) -> Box<dyn CloneLinuxCollector>;
    fn as_linux_collector(&self) -> &dyn LinuxCollector;
}

impl Clone for Box<dyn CloneLinuxCollector> {
    fn clone(&self) -> Self {
        self.clone_collector()
    }
}

/// Utility to generate unique item IDs
pub fn generate_item_id() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(10000);
    COUNTER.fetch_add(1, Ordering::SeqCst)
}

/// Version comparison for packages
pub fn compare_evr(epoch1: i32, ver1: &str, rel1: &str, epoch2: i32, ver2: &str, rel2: &str) -> std::cmp::Ordering {
    // Compare epoch first
    if epoch1 != epoch2 {
        return epoch1.cmp(&epoch2);
    }

    // Compare version using RPM-style version comparison
    let ver_cmp = compare_version_string(ver1, ver2);
    if ver_cmp != std::cmp::Ordering::Equal {
        return ver_cmp;
    }

    // Compare release
    compare_version_string(rel1, rel2)
}

/// RPM-style version string comparison
fn compare_version_string(v1: &str, v2: &str) -> std::cmp::Ordering {
    let mut p1 = v1.chars().peekable();
    let mut p2 = v2.chars().peekable();

    while p1.peek().is_some() || p2.peek().is_some() {
        // Skip non-alphanumeric characters
        while p1.peek().map(|c| !c.is_alphanumeric()).unwrap_or(false) {
            p1.next();
        }
        while p2.peek().map(|c| !c.is_alphanumeric()).unwrap_or(false) {
            p2.next();
        }

        // Collect numeric or alphabetic segment
        let seg1: String = if p1.peek().map(|c| c.is_ascii_digit()).unwrap_or(false) {
            p1.by_ref().take_while(|c| c.is_ascii_digit()).collect()
        } else {
            p1.by_ref().take_while(|c| c.is_alphabetic()).collect()
        };

        let seg2: String = if p2.peek().map(|c| c.is_ascii_digit()).unwrap_or(false) {
            p2.by_ref().take_while(|c| c.is_ascii_digit()).collect()
        } else {
            p2.by_ref().take_while(|c| c.is_alphabetic()).collect()
        };

        // Handle empty segments
        if seg1.is_empty() && seg2.is_empty() {
            continue;
        }
        if seg1.is_empty() {
            return std::cmp::Ordering::Less;
        }
        if seg2.is_empty() {
            return std::cmp::Ordering::Greater;
        }

        // Compare segments
        let is_num1 = seg1.chars().all(|c| c.is_ascii_digit());
        let is_num2 = seg2.chars().all(|c| c.is_ascii_digit());

        let cmp = if is_num1 && is_num2 {
            // Numeric comparison
            let n1: u64 = seg1.parse().unwrap_or(0);
            let n2: u64 = seg2.parse().unwrap_or(0);
            n1.cmp(&n2)
        } else if is_num1 {
            // Numeric > alphabetic
            std::cmp::Ordering::Greater
        } else if is_num2 {
            std::cmp::Ordering::Less
        } else {
            // Alphabetic comparison
            seg1.cmp(&seg2)
        };

        if cmp != std::cmp::Ordering::Equal {
            return cmp;
        }
    }

    std::cmp::Ordering::Equal
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compare_version_string() {
        assert_eq!(compare_version_string("1.0", "1.0"), std::cmp::Ordering::Equal);
        assert_eq!(compare_version_string("1.1", "1.0"), std::cmp::Ordering::Greater);
        assert_eq!(compare_version_string("1.0", "1.1"), std::cmp::Ordering::Less);
        assert_eq!(compare_version_string("1.0.1", "1.0"), std::cmp::Ordering::Greater);
        assert_eq!(compare_version_string("2.0", "1.99"), std::cmp::Ordering::Greater);
    }

    #[test]
    fn test_compare_evr() {
        // Same version
        assert_eq!(compare_evr(0, "1.0", "1", 0, "1.0", "1"), std::cmp::Ordering::Equal);
        // Epoch wins
        assert_eq!(compare_evr(1, "1.0", "1", 0, "2.0", "1"), std::cmp::Ordering::Greater);
        // Version comparison
        assert_eq!(compare_evr(0, "1.1", "1", 0, "1.0", "1"), std::cmp::Ordering::Greater);
        // Release comparison
        assert_eq!(compare_evr(0, "1.0", "2", 0, "1.0", "1"), std::cmp::Ordering::Greater);
    }
}
