//! Configuration file scanner for secret detection
//!
//! Deep parsing of configuration files to find secrets in:
//! - YAML files
//! - JSON files
//! - TOML files
//! - .env files
//! - XML files
//! - Properties files

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;

use super::entropy::{analyze_entropy, EntropyConfig};
use super::types::{SecretFinding, SecretSeverity, SecretSource, SecretType};
use super::{detect_secrets, SecretDetectionConfig};

/// Configuration file type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConfigFileType {
    Yaml,
    Json,
    Toml,
    Env,
    Xml,
    Properties,
    Ini,
    Unknown,
}

impl ConfigFileType {
    /// Detect file type from extension
    pub fn from_extension(ext: &str) -> Self {
        match ext.to_lowercase().as_str() {
            "yaml" | "yml" => ConfigFileType::Yaml,
            "json" => ConfigFileType::Json,
            "toml" => ConfigFileType::Toml,
            "env" => ConfigFileType::Env,
            "xml" => ConfigFileType::Xml,
            "properties" => ConfigFileType::Properties,
            "ini" | "cfg" | "conf" => ConfigFileType::Ini,
            _ => ConfigFileType::Unknown,
        }
    }

    /// Detect file type from filename
    pub fn from_filename(name: &str) -> Self {
        let lower = name.to_lowercase();

        // Check for dotenv files
        if lower == ".env"
            || lower.starts_with(".env.")
            || lower.ends_with(".env")
            || lower == "env"
        {
            return ConfigFileType::Env;
        }

        // Check extension
        if let Some(ext) = Path::new(name).extension() {
            return Self::from_extension(&ext.to_string_lossy());
        }

        ConfigFileType::Unknown
    }
}

/// Keys that typically contain secrets
const SECRET_KEY_PATTERNS: &[&str] = &[
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "api-key",
    "auth",
    "credential",
    "private_key",
    "privatekey",
    "private-key",
    "access_key",
    "accesskey",
    "access-key",
    "secret_key",
    "secretkey",
    "secret-key",
    "encryption_key",
    "encryptionkey",
    "encryption-key",
    "signing_key",
    "signingkey",
    "signing-key",
    "bearer",
    "authorization",
    "connection_string",
    "connectionstring",
    "connection-string",
    "database_url",
    "databaseurl",
    "database-url",
    "db_password",
    "dbpassword",
    "db-password",
    "smtp_password",
    "smtppassword",
    "smtp-password",
    "aws_secret",
    "aws_access",
    "github_token",
    "gitlab_token",
    "slack_token",
    "sendgrid",
    "stripe",
    "twilio",
    "oauth",
    "jwt",
    "session_secret",
    "sessionsecret",
    "session-secret",
    "cookie_secret",
    "cookiesecret",
    "cookie-secret",
];

/// Configuration file scanner
#[derive(Debug, Clone)]
pub struct ConfigScanner {
    /// Secret detection config
    pub secret_config: SecretDetectionConfig,
    /// Entropy detection config
    pub entropy_config: EntropyConfig,
    /// Minimum value length to consider
    pub min_value_length: usize,
    /// Maximum value length to consider
    pub max_value_length: usize,
}

impl Default for ConfigScanner {
    fn default() -> Self {
        Self {
            secret_config: SecretDetectionConfig::default(),
            entropy_config: EntropyConfig::default(),
            min_value_length: 8,
            max_value_length: 1024,
        }
    }
}

/// A key-value pair found in a config file
#[derive(Debug, Clone)]
pub struct ConfigKeyValue {
    pub key: String,
    pub value: String,
    pub path: Vec<String>,
    pub line: Option<usize>,
}

/// Secret finding from a config file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigSecretFinding {
    /// The underlying secret finding
    pub finding: SecretFinding,
    /// Configuration key path (e.g., "database.credentials.password")
    pub key_path: String,
    /// File type
    pub file_type: ConfigFileType,
}

impl ConfigScanner {
    /// Create a new config scanner
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if a key name suggests it contains a secret
    fn is_secret_key(&self, key: &str) -> bool {
        let lower = key.to_lowercase();
        SECRET_KEY_PATTERNS.iter().any(|pattern| lower.contains(pattern))
    }

    /// Determine secret type based on key name
    fn infer_secret_type(&self, key: &str) -> SecretType {
        let lower = key.to_lowercase();

        if lower.contains("aws") {
            if lower.contains("secret") {
                return SecretType::AwsSecretKey;
            }
            if lower.contains("access") {
                return SecretType::AwsAccessKey;
            }
        }

        if lower.contains("github") {
            return SecretType::GitHubToken;
        }

        if lower.contains("gitlab") {
            return SecretType::GitLabToken;
        }

        if lower.contains("slack") {
            return SecretType::SlackToken;
        }

        if lower.contains("stripe") {
            return SecretType::StripeKey;
        }

        if lower.contains("sendgrid") {
            return SecretType::SendGridKey;
        }

        if lower.contains("twilio") {
            return SecretType::TwilioApiKey;
        }

        if lower.contains("database") || lower.contains("db_") || lower.contains("connection") {
            if lower.contains("mongo") {
                return SecretType::MongoDbUri;
            }
            if lower.contains("postgres") || lower.contains("pg_") {
                return SecretType::PostgresUri;
            }
            if lower.contains("mysql") {
                return SecretType::MySqlUri;
            }
            if lower.contains("redis") {
                return SecretType::RedisUri;
            }
        }

        if lower.contains("password") || lower.contains("passwd") || lower.contains("pwd") {
            return SecretType::PasswordInConfig;
        }

        if lower.contains("private_key") || lower.contains("privatekey") {
            return SecretType::GenericSecretKey;
        }

        if lower.contains("jwt") || lower.contains("bearer") {
            return SecretType::JwtToken;
        }

        if lower.contains("api") {
            if lower.contains("key") {
                return SecretType::GenericApiKey;
            }
            if lower.contains("token") {
                return SecretType::GenericApiToken;
            }
        }

        if lower.contains("token") {
            return SecretType::GenericApiToken;
        }

        if lower.contains("secret") || lower.contains("key") {
            return SecretType::GenericSecretKey;
        }

        SecretType::GenericSecretKey
    }

    /// Determine severity based on key name and value
    fn determine_severity(&self, key: &str, value: &str) -> SecretSeverity {
        let lower_key = key.to_lowercase();

        // Critical: Cloud provider credentials, database passwords
        if lower_key.contains("aws_secret")
            || lower_key.contains("gcp_")
            || lower_key.contains("azure_")
            || (lower_key.contains("database") && lower_key.contains("password"))
            || lower_key.contains("private_key")
        {
            return SecretSeverity::Critical;
        }

        // High: API tokens, general passwords
        if lower_key.contains("api_key")
            || lower_key.contains("token")
            || lower_key.contains("password")
            || lower_key.contains("secret")
        {
            return SecretSeverity::High;
        }

        // Medium: Other credentials
        if lower_key.contains("auth") || lower_key.contains("credential") {
            return SecretSeverity::Medium;
        }

        // Check value length - longer values are more likely to be real secrets
        if value.len() >= 32 {
            return SecretSeverity::High;
        }

        SecretSeverity::Medium
    }

    /// Parse .env file content
    fn parse_env(&self, content: &str) -> Vec<ConfigKeyValue> {
        let mut results = Vec::new();

        for (line_num, line) in content.lines().enumerate() {
            let line = line.trim();

            // Skip comments and empty lines
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Parse KEY=VALUE or KEY="VALUE"
            if let Some(eq_pos) = line.find('=') {
                let key = line[..eq_pos].trim().to_string();
                let mut value = line[eq_pos + 1..].trim().to_string();

                // Remove quotes
                if (value.starts_with('"') && value.ends_with('"'))
                    || (value.starts_with('\'') && value.ends_with('\''))
                {
                    value = value[1..value.len() - 1].to_string();
                }

                if !key.is_empty() && !value.is_empty() {
                    results.push(ConfigKeyValue {
                        key: key.clone(),
                        value,
                        path: vec![key],
                        line: Some(line_num + 1),
                    });
                }
            }
        }

        results
    }

    /// Parse JSON content recursively
    fn parse_json(&self, content: &str) -> Result<Vec<ConfigKeyValue>> {
        let value: serde_json::Value = serde_json::from_str(content)?;
        let mut results = Vec::new();
        self.extract_json_values(&value, Vec::new(), &mut results);
        Ok(results)
    }

    fn extract_json_values(
        &self,
        value: &serde_json::Value,
        path: Vec<String>,
        results: &mut Vec<ConfigKeyValue>,
    ) {
        match value {
            serde_json::Value::Object(map) => {
                for (key, val) in map {
                    let mut new_path = path.clone();
                    new_path.push(key.clone());
                    self.extract_json_values(val, new_path, results);
                }
            }
            serde_json::Value::Array(arr) => {
                for (i, val) in arr.iter().enumerate() {
                    let mut new_path = path.clone();
                    new_path.push(format!("[{}]", i));
                    self.extract_json_values(val, new_path, results);
                }
            }
            serde_json::Value::String(s) => {
                if !path.is_empty() {
                    results.push(ConfigKeyValue {
                        key: path.last().unwrap().clone(),
                        value: s.clone(),
                        path,
                        line: None,
                    });
                }
            }
            _ => {}
        }
    }

    /// Parse YAML content recursively
    fn parse_yaml(&self, content: &str) -> Result<Vec<ConfigKeyValue>> {
        let value: serde_yaml::Value = serde_yaml::from_str(content)?;
        let mut results = Vec::new();
        self.extract_yaml_values(&value, Vec::new(), &mut results);
        Ok(results)
    }

    fn extract_yaml_values(
        &self,
        value: &serde_yaml::Value,
        path: Vec<String>,
        results: &mut Vec<ConfigKeyValue>,
    ) {
        match value {
            serde_yaml::Value::Mapping(map) => {
                for (key, val) in map {
                    if let serde_yaml::Value::String(key_str) = key {
                        let mut new_path = path.clone();
                        new_path.push(key_str.clone());
                        self.extract_yaml_values(val, new_path, results);
                    }
                }
            }
            serde_yaml::Value::Sequence(arr) => {
                for (i, val) in arr.iter().enumerate() {
                    let mut new_path = path.clone();
                    new_path.push(format!("[{}]", i));
                    self.extract_yaml_values(val, new_path, results);
                }
            }
            serde_yaml::Value::String(s) => {
                if !path.is_empty() {
                    results.push(ConfigKeyValue {
                        key: path.last().unwrap().clone(),
                        value: s.clone(),
                        path,
                        line: None,
                    });
                }
            }
            _ => {}
        }
    }

    /// Parse TOML content recursively
    fn parse_toml(&self, content: &str) -> Result<Vec<ConfigKeyValue>> {
        let value: toml::Value = toml::from_str(content)?;
        let mut results = Vec::new();
        self.extract_toml_values(&value, Vec::new(), &mut results);
        Ok(results)
    }

    fn extract_toml_values(
        &self,
        value: &toml::Value,
        path: Vec<String>,
        results: &mut Vec<ConfigKeyValue>,
    ) {
        match value {
            toml::Value::Table(map) => {
                for (key, val) in map {
                    let mut new_path = path.clone();
                    new_path.push(key.clone());
                    self.extract_toml_values(val, new_path, results);
                }
            }
            toml::Value::Array(arr) => {
                for (i, val) in arr.iter().enumerate() {
                    let mut new_path = path.clone();
                    new_path.push(format!("[{}]", i));
                    self.extract_toml_values(val, new_path, results);
                }
            }
            toml::Value::String(s) => {
                if !path.is_empty() {
                    results.push(ConfigKeyValue {
                        key: path.last().unwrap().clone(),
                        value: s.clone(),
                        path,
                        line: None,
                    });
                }
            }
            _ => {}
        }
    }

    /// Scan a configuration file for secrets
    pub fn scan_config_file(
        &self,
        content: &str,
        filename: &str,
        file_type: Option<ConfigFileType>,
    ) -> Result<Vec<ConfigSecretFinding>> {
        let file_type = file_type.unwrap_or_else(|| ConfigFileType::from_filename(filename));

        // Parse the file based on type
        let key_values = match file_type {
            ConfigFileType::Env => self.parse_env(content),
            ConfigFileType::Json => self.parse_json(content)?,
            ConfigFileType::Yaml => self.parse_yaml(content)?,
            ConfigFileType::Toml => self.parse_toml(content)?,
            ConfigFileType::Properties | ConfigFileType::Ini => {
                // Simple key=value parsing similar to .env
                self.parse_env(content)
            }
            ConfigFileType::Xml | ConfigFileType::Unknown => {
                // Fall back to pattern-based detection
                let source = SecretSource::ConfigFile {
                    path: filename.to_string(),
                };
                let pattern_findings = detect_secrets(content, source, &self.secret_config);
                return Ok(pattern_findings
                    .into_iter()
                    .map(|f| ConfigSecretFinding {
                        finding: f,
                        key_path: "".to_string(),
                        file_type,
                    })
                    .collect());
            }
        };

        let mut findings = Vec::new();

        for kv in key_values {
            // Skip values that are too short or too long
            if kv.value.len() < self.min_value_length || kv.value.len() > self.max_value_length {
                continue;
            }

            let key_path = kv.path.join(".");
            let is_secret_key = self.is_secret_key(&kv.key);

            // Check for secrets if the key suggests it might be a secret
            if is_secret_key {
                // Pattern-based detection on the value
                let source = SecretSource::ConfigFile {
                    path: filename.to_string(),
                };
                let pattern_findings = detect_secrets(&kv.value, source.clone(), &self.secret_config);

                if !pattern_findings.is_empty() {
                    for finding in pattern_findings {
                        findings.push(ConfigSecretFinding {
                            finding,
                            key_path: key_path.clone(),
                            file_type,
                        });
                    }
                } else {
                    // No pattern match, but key suggests it's a secret
                    // Use entropy analysis
                    let entropy_result = analyze_entropy(&kv.value, &key_path, &self.entropy_config);

                    // If high entropy OR the key strongly suggests a secret
                    if entropy_result.is_high_entropy || is_secret_key {
                        let secret_type = self.infer_secret_type(&kv.key);
                        let severity = self.determine_severity(&kv.key, &kv.value);

                        let finding = SecretFinding {
                            secret_type,
                            severity,
                            redacted_value: redact_secret(&kv.value),
                            source,
                            line: kv.line,
                            column: None,
                            context: Some(format!("Found in config key: {}", key_path)),
                            remediation: Some(
                                "Move this secret to a secure secrets manager or environment variable.".to_string(),
                            ),
                            verified: false,
                            entropy_score: Some(entropy_result.entropy),
                            detection_method: Some(if entropy_result.is_high_entropy {
                                "key_name+entropy".to_string()
                            } else {
                                "key_name".to_string()
                            }),
                        };

                        findings.push(ConfigSecretFinding {
                            finding,
                            key_path,
                            file_type,
                        });
                    }
                }
            }
        }

        Ok(findings)
    }
}

/// Redact a secret value for safe storage/display
fn redact_secret(value: &str) -> String {
    let len = value.len();
    if len <= 8 {
        "*".repeat(len)
    } else {
        format!("{}...{}", &value[..4], &value[len - 4..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_type_detection() {
        assert_eq!(ConfigFileType::from_filename(".env"), ConfigFileType::Env);
        assert_eq!(ConfigFileType::from_filename(".env.local"), ConfigFileType::Env);
        assert_eq!(ConfigFileType::from_filename("config.yaml"), ConfigFileType::Yaml);
        assert_eq!(ConfigFileType::from_filename("config.yml"), ConfigFileType::Yaml);
        assert_eq!(ConfigFileType::from_filename("package.json"), ConfigFileType::Json);
        assert_eq!(ConfigFileType::from_filename("Cargo.toml"), ConfigFileType::Toml);
    }

    #[test]
    fn test_env_parsing() {
        let scanner = ConfigScanner::default();
        let content = r#"
# Comment
API_KEY=secret123
DATABASE_URL="postgres://user:pass@host/db"
EMPTY=
"#;
        let results = scanner.parse_env(content);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].key, "API_KEY");
        assert_eq!(results[0].value, "secret123");
        assert_eq!(results[1].key, "DATABASE_URL");
        assert_eq!(results[1].value, "postgres://user:pass@host/db");
    }

    #[test]
    fn test_secret_key_detection() {
        let scanner = ConfigScanner::default();
        assert!(scanner.is_secret_key("api_key"));
        assert!(scanner.is_secret_key("API_KEY"));
        assert!(scanner.is_secret_key("database_password"));
        assert!(scanner.is_secret_key("secret_token"));
        assert!(!scanner.is_secret_key("username"));
        assert!(!scanner.is_secret_key("email"));
    }
}
