//! Unix OVAL Object Collectors
//!
//! Implements collectors for Unix-specific OVAL object types:
//! - File objects
//! - Process objects
//! - Uname objects
//! - Password/Shadow objects
//! - Sysctl objects

pub mod file;
pub mod process;
pub mod uname;

use std::collections::HashMap;
use anyhow::Result;
use async_trait::async_trait;

use crate::scap::oval::types::{OvalItem, OvalObject, OvalValue, ItemStatus, ObjectType};

/// Trait for Unix OVAL collectors
#[async_trait]
pub trait UnixCollector: Send + Sync {
    /// Collect items matching the OVAL object specification
    async fn collect(&self, object: &OvalObject, context: &UnixCollectionContext) -> Result<Vec<OvalItem>>;

    /// Get the object types this collector handles
    fn supported_types(&self) -> Vec<ObjectType>;
}

/// Context for Unix collection operations
#[derive(Debug, Clone)]
pub struct UnixCollectionContext {
    /// Target hostname or IP
    pub target: String,
    /// SSH port
    pub ssh_port: u16,
    /// Username for SSH authentication
    pub username: Option<String>,
    /// Password for SSH authentication (prefer key-based auth)
    pub password: Option<String>,
    /// Path to SSH private key
    pub private_key_path: Option<String>,
    /// Passphrase for private key
    pub key_passphrase: Option<String>,
    /// Connection timeout in seconds
    pub timeout_seconds: u64,
    /// Use sudo for privileged operations
    pub use_sudo: bool,
    /// Sudo password (if different from user password)
    pub sudo_password: Option<String>,
}

impl Default for UnixCollectionContext {
    fn default() -> Self {
        Self {
            target: String::new(),
            ssh_port: 22,
            username: None,
            password: None,
            private_key_path: None,
            key_passphrase: None,
            timeout_seconds: 30,
            use_sudo: false,
            sudo_password: None,
        }
    }
}

impl UnixCollectionContext {
    /// Create a new context with password authentication
    pub fn with_password(target: &str, username: &str, password: &str) -> Self {
        Self {
            target: target.to_string(),
            username: Some(username.to_string()),
            password: Some(password.to_string()),
            ..Default::default()
        }
    }

    /// Create a new context with key-based authentication
    pub fn with_key(target: &str, username: &str, key_path: &str) -> Self {
        Self {
            target: target.to_string(),
            username: Some(username.to_string()),
            private_key_path: Some(key_path.to_string()),
            ..Default::default()
        }
    }

    /// Enable sudo for privileged operations
    pub fn with_sudo(mut self, sudo_password: Option<&str>) -> Self {
        self.use_sudo = true;
        self.sudo_password = sudo_password.map(|s| s.to_string());
        self
    }

    /// Execute a shell command on the target system via SSH
    pub async fn execute_command(&self, command: &str) -> Result<String> {
        use ssh2::Session;
        use std::io::Read;
        use std::net::TcpStream;

        let username = self.username.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Username not configured for SSH"))?;

        // Connect to SSH
        let addr = format!("{}:{}", self.target, self.ssh_port);
        let tcp = TcpStream::connect(&addr)?;
        tcp.set_read_timeout(Some(std::time::Duration::from_secs(self.timeout_seconds)))?;

        let mut sess = Session::new()?;
        sess.set_tcp_stream(tcp);
        sess.handshake()?;

        // Authenticate
        if let Some(key_path) = &self.private_key_path {
            let passphrase = self.key_passphrase.as_deref();
            sess.userauth_pubkey_file(username, None, std::path::Path::new(key_path), passphrase)?;
        } else if let Some(password) = &self.password {
            sess.userauth_password(username, password)?;
        } else {
            return Err(anyhow::anyhow!("No authentication method configured"));
        }

        if !sess.authenticated() {
            return Err(anyhow::anyhow!("SSH authentication failed"));
        }

        // Build command with optional sudo
        let full_command = if self.use_sudo {
            if let Some(sudo_pass) = &self.sudo_password {
                format!("echo '{}' | sudo -S {}", sudo_pass, command)
            } else if let Some(pass) = &self.password {
                format!("echo '{}' | sudo -S {}", pass, command)
            } else {
                format!("sudo {}", command)
            }
        } else {
            command.to_string()
        };

        // Execute command
        let mut channel = sess.channel_session()?;
        channel.exec(&full_command)?;

        let mut output = String::new();
        channel.read_to_string(&mut output)?;
        channel.wait_close()?;

        Ok(output)
    }

    /// Check if the context has valid credentials configured
    pub fn has_credentials(&self) -> bool {
        !self.target.is_empty() &&
        self.username.is_some() &&
        (self.password.is_some() || self.private_key_path.is_some())
    }
}

/// Unix collector registry
pub struct UnixCollectorRegistry {
    collectors: HashMap<ObjectType, Box<dyn CloneUnixCollector>>,
}

impl Default for UnixCollectorRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl UnixCollectorRegistry {
    /// Create a new registry with all standard collectors
    pub fn new() -> Self {
        let mut registry = Self {
            collectors: HashMap::new(),
        };

        // Register all built-in collectors
        registry.register(file::FileCollector::new());
        registry.register(process::ProcessCollector::new());
        registry.register(uname::UnameCollector::new());

        registry
    }

    /// Register a collector
    pub fn register<T: CloneUnixCollector + Clone + 'static>(&mut self, collector: T) {
        for obj_type in collector.supported_types() {
            self.collectors.insert(obj_type, collector.clone_collector());
        }
    }

    /// Get collector for a specific object type
    pub fn get(&self, object_type: ObjectType) -> Option<&dyn UnixCollector> {
        self.collectors.get(&object_type).map(|c| c.as_ref() as &dyn UnixCollector)
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

/// Helper trait for cloning boxed collectors
pub trait CloneUnixCollector: UnixCollector {
    fn clone_collector(&self) -> Box<dyn CloneUnixCollector>;
}

impl Clone for Box<dyn CloneUnixCollector> {
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
        _ => value == pattern,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_context_creation() {
        let ctx = UnixCollectionContext::with_password("192.168.1.1", "user", "pass");
        assert_eq!(ctx.target, "192.168.1.1");
        assert_eq!(ctx.username, Some("user".to_string()));
        assert!(ctx.has_credentials());
    }

    #[test]
    fn test_matches_pattern() {
        assert!(matches_pattern("test", "test", "equals"));
        assert!(!matches_pattern("test", "TEST", "equals"));
        assert!(matches_pattern("test", "TEST", "case insensitive equals"));
        assert!(matches_pattern("test123", "test\\d+", "pattern match"));
    }
}
