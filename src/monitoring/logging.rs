//! Structured logging system for HeroForge

use chrono::Utc;
use serde::{Serialize, Deserialize};
use log::{Level, Record};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;

/// Structured log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub timestamp: String,
    pub level: String,
    pub message: String,
    pub module: Option<String>,
    pub file: Option<String>,
    pub line: Option<u32>,
    pub user_id: Option<String>,
    pub request_id: Option<String>,
    pub metadata: serde_json::Value,
}

impl LogEntry {
    pub fn new(level: Level, message: String) -> Self {
        Self {
            timestamp: Utc::now().to_rfc3339(),
            level: level.to_string(),
            message,
            module: None,
            file: None,
            line: None,
            user_id: None,
            request_id: None,
            metadata: serde_json::Value::Null,
        }
    }

    pub fn from_record(record: &Record) -> Self {
        Self {
            timestamp: Utc::now().to_rfc3339(),
            level: record.level().to_string(),
            message: format!("{}", record.args()),
            module: record.module_path().map(String::from),
            file: record.file().map(String::from),
            line: record.line(),
            user_id: None,
            request_id: None,
            metadata: serde_json::Value::Null,
        }
    }

    pub fn with_user(mut self, user_id: &str) -> Self {
        self.user_id = Some(user_id.to_string());
        self
    }

    pub fn with_request(mut self, request_id: &str) -> Self {
        self.request_id = Some(request_id.to_string());
        self
    }

    pub fn with_metadata(mut self, metadata: serde_json::Value) -> Self {
        self.metadata = metadata;
        self
    }
}

/// JSON file logger
pub struct JsonLogger {
    log_file_path: PathBuf,
    min_level: Level,
}

impl JsonLogger {
    pub fn new(log_file_path: PathBuf, min_level: Level) -> Self {
        Self {
            log_file_path,
            min_level,
        }
    }

    pub fn log(&self, entry: &LogEntry) -> std::io::Result<()> {
        if self.should_log(&entry.level) {
            let json = serde_json::to_string(entry)?;
            let mut file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.log_file_path)?;

            writeln!(file, "{}", json)?;
        }
        Ok(())
    }

    fn should_log(&self, level_str: &str) -> bool {
        let level = match level_str {
            "ERROR" => Level::Error,
            "WARN" => Level::Warn,
            "INFO" => Level::Info,
            "DEBUG" => Level::Debug,
            "TRACE" => Level::Trace,
            _ => Level::Info,
        };
        level <= self.min_level
    }
}

/// Security event logger for audit trails
pub struct SecurityLogger {
    logger: JsonLogger,
}

impl SecurityLogger {
    pub fn new(log_file_path: PathBuf) -> Self {
        Self {
            logger: JsonLogger::new(log_file_path, Level::Info),
        }
    }

    pub fn log_auth_attempt(&self, username: &str, success: bool, ip: &str) -> std::io::Result<()> {
        let entry = LogEntry::new(
            Level::Info,
            format!("Authentication attempt: user={}, success={}, ip={}", username, success, ip),
        ).with_metadata(serde_json::json!({
            "event_type": "auth_attempt",
            "username": username,
            "success": success,
            "ip_address": ip,
        }));

        self.logger.log(&entry)
    }

    pub fn log_permission_denied(&self, user_id: &str, resource: &str, action: &str) -> std::io::Result<()> {
        let entry = LogEntry::new(
            Level::Warn,
            format!("Permission denied: user={}, resource={}, action={}", user_id, resource, action),
        ).with_user(user_id)
            .with_metadata(serde_json::json!({
            "event_type": "permission_denied",
            "resource": resource,
            "action": action,
        }));

        self.logger.log(&entry)
    }

    pub fn log_data_access(&self, user_id: &str, resource_type: &str, resource_id: &str) -> std::io::Result<()> {
        let entry = LogEntry::new(
            Level::Info,
            format!("Data access: user={}, type={}, id={}", user_id, resource_type, resource_id),
        ).with_user(user_id)
            .with_metadata(serde_json::json!({
            "event_type": "data_access",
            "resource_type": resource_type,
            "resource_id": resource_id,
        }));

        self.logger.log(&entry)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_log_entry_creation() {
        let entry = LogEntry::new(Level::Info, "Test message".to_string())
            .with_user("user123")
            .with_request("req456");

        assert_eq!(entry.level, "INFO");
        assert_eq!(entry.message, "Test message");
        assert_eq!(entry.user_id, Some("user123".to_string()));
        assert_eq!(entry.request_id, Some("req456".to_string()));
    }

    #[test]
    fn test_json_logger() -> std::io::Result<()> {
        let temp_file = NamedTempFile::new()?;
        let logger = JsonLogger::new(temp_file.path().to_path_buf(), Level::Info);

        let entry = LogEntry::new(Level::Info, "Test log".to_string());
        logger.log(&entry)?;

        let content = std::fs::read_to_string(temp_file.path())?;
        assert!(content.contains("Test log"));

        Ok(())
    }
}
