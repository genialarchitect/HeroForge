//! Windows OVAL Object Collectors
//!
//! Implements collectors for Windows-specific OVAL object types:
//! - Registry objects
//! - File objects
//! - WMI objects
//! - Service objects
//! - User/Group objects
//! - Audit policy objects
//! - Password policy objects
//! - Lockout policy objects

pub mod registry;
pub mod file;
pub mod wmi;
pub mod service;
pub mod user;
pub mod audit_policy;
pub mod password_policy;
pub mod lockout_policy;

use std::collections::HashMap;
use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::scap::oval::types::{
    OvalItem, OvalObject, OvalValue, ItemStatus, ObjectType,
};
use crate::scanner::windows_audit::client::WinRmClient;
use crate::scanner::windows_audit::types::WindowsCredentials;

/// Trait for Windows OVAL collectors
#[async_trait]
pub trait WindowsCollector: Send + Sync {
    /// Collect items matching the OVAL object specification
    async fn collect(&self, object: &OvalObject, context: &CollectionContext) -> Result<Vec<OvalItem>>;

    /// Get the object types this collector handles
    fn supported_types(&self) -> Vec<ObjectType>;
}

/// Context for collection operations
#[derive(Debug, Clone)]
pub struct CollectionContext {
    /// Target hostname or IP
    pub target: String,
    /// WinRM endpoint URL
    pub winrm_endpoint: Option<String>,
    /// Username for authentication
    pub username: Option<String>,
    /// Password for authentication (should be handled securely)
    pub password: Option<String>,
    /// Domain for authentication
    pub domain: Option<String>,
    /// Whether to use SSL
    pub use_ssl: bool,
    /// Connection timeout in seconds
    pub timeout_seconds: u64,
    /// Whether to skip certificate verification
    pub skip_cert_verify: bool,
}

impl Default for CollectionContext {
    fn default() -> Self {
        Self {
            target: String::new(),
            winrm_endpoint: None,
            username: None,
            password: None,
            domain: None,
            use_ssl: true,
            timeout_seconds: 30,
            skip_cert_verify: false,
        }
    }
}

impl CollectionContext {
    /// Create a new context with required connection parameters
    pub fn new(target: &str, username: &str, password: &str) -> Self {
        Self {
            target: target.to_string(),
            username: Some(username.to_string()),
            password: Some(password.to_string()),
            ..Default::default()
        }
    }

    /// Set the domain for authentication
    pub fn with_domain(mut self, domain: &str) -> Self {
        self.domain = Some(domain.to_string());
        self
    }

    /// Set SSL usage
    pub fn with_ssl(mut self, use_ssl: bool) -> Self {
        self.use_ssl = use_ssl;
        self
    }

    /// Execute a PowerShell script on the target system via WinRM
    pub async fn execute_script(&self, script: &str) -> Result<String> {
        let username = self.username.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Username not configured for WinRM"))?;
        let password = self.password.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Password not configured for WinRM"))?;

        // Create Windows credentials
        let credentials = WindowsCredentials {
            username: username.clone(),
            password: password.clone(),
            domain: self.domain.clone(),
            auth_type: crate::scanner::windows_audit::types::WindowsAuthType::Ntlm,
        };

        // Create WinRM client
        let mut client = WinRmClient::new(&self.target, credentials);

        // Configure SSL
        if !self.use_ssl {
            client = client.without_ssl();
        }

        // Execute the script
        client.execute_powershell(script).await
    }

    /// Check if the context has valid credentials configured
    pub fn has_credentials(&self) -> bool {
        self.username.is_some() && self.password.is_some() && !self.target.is_empty()
    }
}

/// Windows collector registry
pub struct WindowsCollectorRegistry {
    collectors: HashMap<ObjectType, Box<dyn CloneCollector>>,
}

impl Default for WindowsCollectorRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl WindowsCollectorRegistry {
    /// Create a new registry with all standard collectors
    pub fn new() -> Self {
        let mut registry = Self {
            collectors: HashMap::new(),
        };

        // Register all built-in collectors
        registry.register(registry::RegistryCollector::new());
        registry.register(file::FileCollector::new());
        registry.register(wmi::WmiCollector::new());
        registry.register(service::ServiceCollector::new());
        registry.register(user::UserCollector::new());
        registry.register(audit_policy::AuditPolicyCollector::new());
        registry.register(password_policy::PasswordPolicyCollector::new());
        registry.register(lockout_policy::LockoutPolicyCollector::new());

        registry
    }

    /// Register a collector
    pub fn register<T: CloneCollector + Clone + 'static>(&mut self, collector: T) {
        for obj_type in collector.supported_types() {
            self.collectors.insert(obj_type, collector.clone_collector());
        }
    }

    /// Get collector for a specific object type
    pub fn get(&self, object_type: ObjectType) -> Option<&dyn WindowsCollector> {
        self.collectors.get(&object_type).map(|c| c.as_ref() as &dyn WindowsCollector)
    }

    /// Collect items for an OVAL object
    pub async fn collect(&self, object: &OvalObject, context: &CollectionContext) -> Result<Vec<OvalItem>> {
        if let Some(collector) = self.get(object.object_type) {
            collector.collect(object, context).await
        } else {
            Ok(vec![])
        }
    }
}

/// Helper trait for cloning boxed collectors
pub trait CloneCollector: WindowsCollector {
    fn clone_collector(&self) -> Box<dyn CloneCollector>;
}

impl Clone for Box<dyn CloneCollector> {
    fn clone(&self) -> Self {
        self.clone_collector()
    }
}

/// Utility to generate unique item IDs
pub fn generate_item_id() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(1);
    COUNTER.fetch_add(1, Ordering::SeqCst)
}

/// Parse OVAL entity value patterns
pub fn matches_pattern(value: &str, pattern: &str, operation: &str) -> bool {
    match operation {
        "equals" => value == pattern,
        "not equal" => value != pattern,
        "case insensitive equals" => value.to_lowercase() == pattern.to_lowercase(),
        "case insensitive not equal" => value.to_lowercase() != pattern.to_lowercase(),
        "pattern match" => {
            if let Ok(re) = regex::Regex::new(pattern) {
                re.is_match(value)
            } else {
                false
            }
        }
        "greater than" => value > pattern,
        "less than" => value < pattern,
        "greater than or equal" => value >= pattern,
        "less than or equal" => value <= pattern,
        _ => value == pattern, // Default to equals
    }
}

/// Convert a string to OvalValue based on expected data type
pub fn parse_oval_value(value: &str, datatype: &str) -> OvalValue {
    match datatype {
        "int" | "integer" => {
            if let Ok(i) = value.parse::<i64>() {
                OvalValue::Int(i)
            } else {
                OvalValue::String(value.to_string())
            }
        }
        "float" | "double" => {
            if let Ok(f) = value.parse::<f64>() {
                OvalValue::Float(f)
            } else {
                OvalValue::String(value.to_string())
            }
        }
        "boolean" | "bool" => {
            let lower = value.to_lowercase();
            OvalValue::Boolean(lower == "true" || lower == "1" || lower == "yes")
        }
        "binary" => {
            if let Ok(bytes) = hex::decode(value.replace(' ', "")) {
                OvalValue::Binary(bytes)
            } else {
                OvalValue::String(value.to_string())
            }
        }
        _ => OvalValue::String(value.to_string()),
    }
}

/// Windows registry hive constants
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegistryHive {
    HkeyClassesRoot,
    HkeyCurrentUser,
    HkeyLocalMachine,
    HkeyUsers,
    HkeyCurrentConfig,
}

impl RegistryHive {
    pub fn from_str(s: &str) -> Option<Self> {
        let upper = s.to_uppercase();
        match upper.as_str() {
            "HKEY_CLASSES_ROOT" | "HKCR" => Some(Self::HkeyClassesRoot),
            "HKEY_CURRENT_USER" | "HKCU" => Some(Self::HkeyCurrentUser),
            "HKEY_LOCAL_MACHINE" | "HKLM" => Some(Self::HkeyLocalMachine),
            "HKEY_USERS" | "HKU" => Some(Self::HkeyUsers),
            "HKEY_CURRENT_CONFIG" | "HKCC" => Some(Self::HkeyCurrentConfig),
            _ => None,
        }
    }

    pub fn powershell_path(&self) -> &'static str {
        match self {
            Self::HkeyClassesRoot => "HKCR:",
            Self::HkeyCurrentUser => "HKCU:",
            Self::HkeyLocalMachine => "HKLM:",
            Self::HkeyUsers => "HKU:",
            Self::HkeyCurrentConfig => "HKCC:",
        }
    }

    pub fn full_name(&self) -> &'static str {
        match self {
            Self::HkeyClassesRoot => "HKEY_CLASSES_ROOT",
            Self::HkeyCurrentUser => "HKEY_CURRENT_USER",
            Self::HkeyLocalMachine => "HKEY_LOCAL_MACHINE",
            Self::HkeyUsers => "HKEY_USERS",
            Self::HkeyCurrentConfig => "HKEY_CURRENT_CONFIG",
        }
    }
}

/// Windows file system behaviors
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum FileBehaviors {
    #[default]
    MaxDepthOne,
    RecurseUp,
    RecurseDown,
    RecurseNoSymlinks,
}

/// Windows registry behaviors
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RegistryBehaviors {
    #[default]
    MaxDepthOne,
    RecurseUp,
    RecurseDown,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_hive_parsing() {
        assert_eq!(RegistryHive::from_str("HKLM"), Some(RegistryHive::HkeyLocalMachine));
        assert_eq!(RegistryHive::from_str("HKEY_LOCAL_MACHINE"), Some(RegistryHive::HkeyLocalMachine));
        assert_eq!(RegistryHive::from_str("HKCU"), Some(RegistryHive::HkeyCurrentUser));
        assert_eq!(RegistryHive::from_str("invalid"), None);
    }

    #[test]
    fn test_matches_pattern() {
        assert!(matches_pattern("test", "test", "equals"));
        assert!(!matches_pattern("test", "TEST", "equals"));
        assert!(matches_pattern("test", "TEST", "case insensitive equals"));
        assert!(matches_pattern("test123", "test\\d+", "pattern match"));
    }

    #[test]
    fn test_parse_oval_value() {
        match parse_oval_value("123", "int") {
            OvalValue::Int(i) => assert_eq!(i, 123),
            _ => panic!("Expected Int"),
        }
        match parse_oval_value("2.5", "float") {
            OvalValue::Float(f) => assert!((f - 2.5_f64).abs() < 0.001),
            _ => panic!("Expected Float"),
        }
        match parse_oval_value("true", "boolean") {
            OvalValue::Boolean(b) => assert!(b),
            _ => panic!("Expected Boolean"),
        }
    }
}
