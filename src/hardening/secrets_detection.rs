//! Secret scanning in configs and code

use anyhow::Result;
use regex::Regex;

pub struct SecretsScanner {}

impl SecretsScanner {
    pub fn new() -> Self {
        Self {}
    }

    pub fn scan_file(&self, content: &str) -> Result<Vec<SecretFinding>> {
        let mut findings = vec![];

        // AWS Access Key pattern
        if let Ok(re) = Regex::new(r"AKIA[0-9A-Z]{16}") {
            for m in re.find_iter(content) {
                findings.push(SecretFinding {
                    secret_type: "AWS Access Key".to_string(),
                    value: m.as_str().to_string(),
                    line: 0,
                });
            }
        }

        // TODO: Add more patterns (API keys, tokens, passwords)

        Ok(findings)
    }
}

impl Default for SecretsScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SecretFinding {
    pub secret_type: String,
    pub value: String,
    pub line: usize,
}
