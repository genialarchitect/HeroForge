//! Secret scanning in configs and code

use anyhow::Result;
use regex::Regex;

/// Secret pattern definition
struct SecretPattern {
    name: &'static str,
    pattern: &'static str,
    severity: SecretSeverity,
}

/// Severity level for secret findings
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SecretSeverity {
    Critical,
    High,
    Medium,
    Low,
}

/// Comprehensive list of secret patterns to detect
const SECRET_PATTERNS: &[SecretPattern] = &[
    // AWS
    SecretPattern { name: "AWS Access Key ID", pattern: r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}", severity: SecretSeverity::Critical },
    SecretPattern { name: "AWS Secret Access Key", pattern: r#"(?i)aws[_\-\.]?secret[_\-\.]?(?:access[_\-\.]?)?key['"]?\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})"#, severity: SecretSeverity::Critical },
    SecretPattern { name: "AWS Session Token", pattern: r#"(?i)aws[_\-\.]?session[_\-\.]?token['"]?\s*[:=]\s*['"]?([A-Za-z0-9/+=]{100,})"#, severity: SecretSeverity::Critical },
    SecretPattern { name: "AWS MWS Key", pattern: r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", severity: SecretSeverity::High },

    // Google Cloud
    SecretPattern { name: "Google API Key", pattern: r"AIza[0-9A-Za-z_-]{35}", severity: SecretSeverity::High },
    SecretPattern { name: "Google OAuth Token", pattern: r"ya29\.[0-9A-Za-z_-]+", severity: SecretSeverity::High },
    SecretPattern { name: "Google Cloud Service Account", pattern: r#""type":\s*"service_account""#, severity: SecretSeverity::High },
    SecretPattern { name: "Google OAuth Client ID", pattern: r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com", severity: SecretSeverity::Medium },

    // Azure
    SecretPattern { name: "Azure Storage Account Key", pattern: r"(?i)(?:DefaultEndpointsProtocol|AccountKey)\s*=\s*[A-Za-z0-9+/=]{88}", severity: SecretSeverity::Critical },
    SecretPattern { name: "Azure AD Client Secret", pattern: r#"(?i)(?:client[_-]?secret|azure[_-]?secret)['"]?\s*[:=]\s*['"]?([A-Za-z0-9~._-]{34,})"#, severity: SecretSeverity::Critical },
    SecretPattern { name: "Azure SAS Token", pattern: r"(?:sv|sig|se|sp)=[^&\s]{10,}", severity: SecretSeverity::High },

    // GitHub
    SecretPattern { name: "GitHub Personal Access Token", pattern: r"ghp_[A-Za-z0-9]{36}", severity: SecretSeverity::Critical },
    SecretPattern { name: "GitHub OAuth Access Token", pattern: r"gho_[A-Za-z0-9]{36}", severity: SecretSeverity::Critical },
    SecretPattern { name: "GitHub App Token", pattern: r"(?:ghu|ghs)_[A-Za-z0-9]{36}", severity: SecretSeverity::Critical },
    SecretPattern { name: "GitHub Refresh Token", pattern: r"ghr_[A-Za-z0-9]{36}", severity: SecretSeverity::Critical },
    SecretPattern { name: "GitHub Fine-grained Token", pattern: r"github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}", severity: SecretSeverity::Critical },

    // GitLab
    SecretPattern { name: "GitLab Personal Access Token", pattern: r"glpat-[A-Za-z0-9_-]{20,}", severity: SecretSeverity::Critical },
    SecretPattern { name: "GitLab Pipeline Token", pattern: r"glptt-[A-Za-z0-9]{40}", severity: SecretSeverity::High },
    SecretPattern { name: "GitLab Runner Token", pattern: r"GR1348941[A-Za-z0-9_-]{20,}", severity: SecretSeverity::High },

    // Slack
    SecretPattern { name: "Slack Bot Token", pattern: r"xoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24}", severity: SecretSeverity::High },
    SecretPattern { name: "Slack User Token", pattern: r"xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-z0-9]{32}", severity: SecretSeverity::High },
    SecretPattern { name: "Slack Webhook URL", pattern: r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+", severity: SecretSeverity::High },
    SecretPattern { name: "Slack App Token", pattern: r"xapp-[0-9]-[A-Z0-9]+-[0-9]+-[A-Za-z0-9]+", severity: SecretSeverity::High },

    // Stripe
    SecretPattern { name: "Stripe API Key", pattern: r"(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,}", severity: SecretSeverity::Critical },
    SecretPattern { name: "Stripe Restricted Key", pattern: r"rk_(?:live|test)_[0-9a-zA-Z]{24,}", severity: SecretSeverity::Critical },

    // PayPal
    SecretPattern { name: "PayPal Braintree Token", pattern: r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}", severity: SecretSeverity::Critical },

    // Square
    SecretPattern { name: "Square Access Token", pattern: r"sq0atp-[0-9A-Za-z_-]{22}", severity: SecretSeverity::Critical },
    SecretPattern { name: "Square OAuth Secret", pattern: r"sq0csp-[0-9A-Za-z_-]{43}", severity: SecretSeverity::Critical },

    // Twilio
    SecretPattern { name: "Twilio API Key", pattern: r"SK[0-9a-fA-F]{32}", severity: SecretSeverity::High },
    SecretPattern { name: "Twilio Account SID", pattern: r"AC[a-zA-Z0-9]{32}", severity: SecretSeverity::Medium },

    // SendGrid
    SecretPattern { name: "SendGrid API Key", pattern: r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}", severity: SecretSeverity::High },

    // Mailchimp
    SecretPattern { name: "Mailchimp API Key", pattern: r"[0-9a-f]{32}-us[0-9]{1,2}", severity: SecretSeverity::High },

    // Mailgun
    SecretPattern { name: "Mailgun API Key", pattern: r"key-[0-9a-zA-Z]{32}", severity: SecretSeverity::High },

    // NPM
    SecretPattern { name: "NPM Access Token", pattern: r"npm_[A-Za-z0-9]{36}", severity: SecretSeverity::Critical },

    // PyPI
    SecretPattern { name: "PyPI API Token", pattern: r"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}", severity: SecretSeverity::Critical },

    // NuGet
    SecretPattern { name: "NuGet API Key", pattern: r"oy2[a-z0-9]{43}", severity: SecretSeverity::High },

    // Docker Hub
    SecretPattern { name: "Docker Hub Token", pattern: r"dckr_pat_[A-Za-z0-9_-]{27,}", severity: SecretSeverity::High },

    // Heroku
    SecretPattern { name: "Heroku API Key", pattern: r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", severity: SecretSeverity::Medium },

    // Firebase
    SecretPattern { name: "Firebase Cloud Messaging", pattern: r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}", severity: SecretSeverity::High },

    // Shopify
    SecretPattern { name: "Shopify Access Token", pattern: r"shpat_[a-fA-F0-9]{32}", severity: SecretSeverity::Critical },
    SecretPattern { name: "Shopify Private App Token", pattern: r"shppa_[a-fA-F0-9]{32}", severity: SecretSeverity::Critical },
    SecretPattern { name: "Shopify Shared Secret", pattern: r"shpss_[a-fA-F0-9]{32}", severity: SecretSeverity::Critical },

    // Databricks
    SecretPattern { name: "Databricks API Token", pattern: r"dapi[a-h0-9]{32}", severity: SecretSeverity::High },

    // Discord
    SecretPattern { name: "Discord Bot Token", pattern: r"[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}", severity: SecretSeverity::High },
    SecretPattern { name: "Discord Webhook URL", pattern: r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9\-_]+", severity: SecretSeverity::Medium },

    // Telegram
    SecretPattern { name: "Telegram Bot Token", pattern: r"[0-9]+:AA[0-9A-Za-z\-_]{33}", severity: SecretSeverity::High },

    // JWT
    SecretPattern { name: "JSON Web Token", pattern: r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+", severity: SecretSeverity::High },

    // Generic Secrets
    SecretPattern { name: "Generic API Key", pattern: r#"(?i)(?:api[_.-]?key|apikey)['"]?\s*[:=]\s*['"]?([A-Za-z0-9_-]{20,})"#, severity: SecretSeverity::Medium },
    SecretPattern { name: "Generic Secret Key", pattern: r#"(?i)(?:secret[_.-]?key|secretkey)['"]?\s*[:=]\s*['"]?([A-Za-z0-9_-]{20,})"#, severity: SecretSeverity::Medium },
    SecretPattern { name: "Generic Access Token", pattern: r#"(?i)(?:access[_.-]?token|accesstoken)['"]?\s*[:=]\s*['"]?([A-Za-z0-9_-]{20,})"#, severity: SecretSeverity::Medium },
    SecretPattern { name: "Generic Private Key", pattern: r#"(?i)(?:private[_.-]?key|privatekey)['"]?\s*[:=]\s*['"]?([A-Za-z0-9_/+=-]{20,})"#, severity: SecretSeverity::High },
    SecretPattern { name: "Generic Auth Token", pattern: r#"(?i)(?:auth[_.-]?token|authtoken|bearer)['"]?\s*[:=]\s*['"]?([A-Za-z0-9_-]{20,})"#, severity: SecretSeverity::Medium },

    // Password Patterns
    SecretPattern { name: "Password in URL", pattern: r"(?i)(?:https?://[^:]+):([^@]+)@", severity: SecretSeverity::Critical },
    SecretPattern { name: "Password Assignment", pattern: r#"(?i)(?:password|passwd|pwd)['"]?\s*[:=]\s*['"]([^'"]{8,})['"]"#, severity: SecretSeverity::High },
    SecretPattern { name: "Database Connection String", pattern: r"(?i)(?:mongodb|postgres|mysql|mssql|redis)(?:\+srv)?://[^:]+:[^@]+@", severity: SecretSeverity::Critical },

    // SSH/RSA Keys
    SecretPattern { name: "RSA Private Key", pattern: r"-----BEGIN RSA PRIVATE KEY-----", severity: SecretSeverity::Critical },
    SecretPattern { name: "DSA Private Key", pattern: r"-----BEGIN DSA PRIVATE KEY-----", severity: SecretSeverity::Critical },
    SecretPattern { name: "EC Private Key", pattern: r"-----BEGIN EC PRIVATE KEY-----", severity: SecretSeverity::Critical },
    SecretPattern { name: "OpenSSH Private Key", pattern: r"-----BEGIN OPENSSH PRIVATE KEY-----", severity: SecretSeverity::Critical },
    SecretPattern { name: "PGP Private Key", pattern: r"-----BEGIN PGP PRIVATE KEY BLOCK-----", severity: SecretSeverity::Critical },

    // OAuth
    SecretPattern { name: "OAuth Client Secret", pattern: r#"(?i)client[_.-]?secret['"]?\s*[:=]\s*['"]?([A-Za-z0-9_-]{20,})"#, severity: SecretSeverity::High },

    // Encryption Keys
    SecretPattern { name: "Encryption Key (Hex)", pattern: r#"(?i)(?:encryption[_.-]?key|aes[_.-]?key)['"]?\s*[:=]\s*['"]?([0-9a-fA-F]{32,})"#, severity: SecretSeverity::Critical },

    // HashiCorp Vault
    SecretPattern { name: "Vault Token", pattern: r"hvs\.[A-Za-z0-9]{24,}", severity: SecretSeverity::Critical },

    // Datadog
    SecretPattern { name: "Datadog API Key", pattern: r#"(?i)(?:dd[_.-]?api[_.-]?key|datadog[_.-]?api[_.-]?key)['"]?\s*[:=]\s*['"]?([a-z0-9]{32})"#, severity: SecretSeverity::High },

    // New Relic
    SecretPattern { name: "New Relic API Key", pattern: r"NRAK-[A-Z0-9]{27}", severity: SecretSeverity::High },
    SecretPattern { name: "New Relic License Key", pattern: r"[A-Fa-f0-9]{40}NRAL", severity: SecretSeverity::High },

    // Okta
    SecretPattern { name: "Okta API Token", pattern: r"00[A-Za-z0-9\-_]{40}", severity: SecretSeverity::High },

    // Linear
    SecretPattern { name: "Linear API Key", pattern: r"lin_api_[A-Za-z0-9]{40}", severity: SecretSeverity::Medium },

    // Anthropic
    SecretPattern { name: "Anthropic API Key", pattern: r"sk-ant-api[0-9]{2}-[A-Za-z0-9\-_]{93}", severity: SecretSeverity::Critical },

    // OpenAI
    SecretPattern { name: "OpenAI API Key", pattern: r"sk-[A-Za-z0-9]{48}", severity: SecretSeverity::Critical },

    // Hugging Face
    SecretPattern { name: "Hugging Face API Token", pattern: r"hf_[A-Za-z0-9]{34}", severity: SecretSeverity::High },

    // CircleCI
    SecretPattern { name: "CircleCI API Token", pattern: r"circle-token-[a-f0-9]{40}", severity: SecretSeverity::High },

    // Travis CI
    SecretPattern { name: "Travis CI Token", pattern: r#"(?i)travis[_.-]?(?:api[_.-]?)?token['"]?\s*[:=]\s*['"]?([A-Za-z0-9]{22})"#, severity: SecretSeverity::High },

    // Sentry
    SecretPattern { name: "Sentry DSN", pattern: r"https://[a-f0-9]{32}@(?:o[0-9]+\.)?sentry\.io/[0-9]+", severity: SecretSeverity::Medium },

    // Algolia
    SecretPattern { name: "Algolia API Key", pattern: r#"(?i)algolia[_.-]?(?:api[_.-]?)?key['"]?\s*[:=]\s*['"]?([a-f0-9]{32})"#, severity: SecretSeverity::Medium },
];

pub struct SecretsScanner {
    compiled_patterns: Vec<(String, Regex, SecretSeverity)>,
}

impl SecretsScanner {
    pub fn new() -> Self {
        let compiled_patterns = SECRET_PATTERNS
            .iter()
            .filter_map(|p| {
                Regex::new(p.pattern)
                    .ok()
                    .map(|re| (p.name.to_string(), re, p.severity))
            })
            .collect();

        Self { compiled_patterns }
    }

    pub fn scan_file(&self, content: &str) -> Result<Vec<SecretFinding>> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = content.lines().collect();

        for (name, regex, severity) in &self.compiled_patterns {
            for (line_num, line) in lines.iter().enumerate() {
                for m in regex.find_iter(line) {
                    // Check if it's likely a false positive
                    if self.is_false_positive(m.as_str(), line) {
                        continue;
                    }

                    // Mask the secret value for security
                    let masked_value = self.mask_secret(m.as_str());

                    findings.push(SecretFinding {
                        secret_type: name.clone(),
                        value: masked_value,
                        line: line_num + 1,
                        severity: *severity,
                        context: self.get_context(&lines, line_num),
                        recommendation: self.get_recommendation(name),
                    });
                }
            }
        }

        // Remove duplicates (same type on same line)
        findings.sort_by(|a, b| {
            a.line.cmp(&b.line).then(a.secret_type.cmp(&b.secret_type))
        });
        findings.dedup_by(|a, b| a.line == b.line && a.secret_type == b.secret_type);

        Ok(findings)
    }

    /// Scan multiple files and aggregate results
    pub fn scan_files(&self, files: &[(String, String)]) -> Result<Vec<FileSecretFindings>> {
        let mut results = Vec::new();

        for (path, content) in files {
            let findings = self.scan_file(content)?;
            if !findings.is_empty() {
                results.push(FileSecretFindings {
                    file_path: path.clone(),
                    findings,
                });
            }
        }

        Ok(results)
    }

    /// Check if a match is likely a false positive
    fn is_false_positive(&self, matched: &str, line: &str) -> bool {
        let line_lower = line.to_lowercase();

        // Skip if in a comment
        if line.trim().starts_with("//")
            || line.trim().starts_with('#')
            || line.trim().starts_with("/*")
            || line.trim().starts_with('*')
        {
            // Unless it looks like a real secret leaked in a comment
            if !line_lower.contains("password") && !line_lower.contains("secret") {
                return true;
            }
        }

        // Skip example/placeholder values
        let placeholders = [
            "example", "sample", "test", "dummy", "fake", "placeholder",
            "your_", "xxx", "abc", "123", "000", "changeme", "replace",
            "insert", "enter", "<", ">", "${", "{{", "ENV[", "process.env",
        ];

        for placeholder in placeholders {
            if matched.to_lowercase().contains(placeholder) {
                return true;
            }
        }

        // Skip if it's in a URL that looks like documentation
        if line_lower.contains("example.com")
            || line_lower.contains("docs.")
            || line_lower.contains("documentation")
        {
            return true;
        }

        // Skip if the match is too short (likely a false positive)
        if matched.len() < 10 && !matched.starts_with("-----BEGIN") {
            return true;
        }

        false
    }

    /// Mask the secret value to avoid leaking it in reports
    fn mask_secret(&self, secret: &str) -> String {
        if secret.len() <= 8 {
            return "*".repeat(secret.len());
        }

        let visible_chars = 4;
        let prefix = &secret[..visible_chars];
        let suffix = &secret[secret.len() - visible_chars..];
        let masked_len = secret.len() - (visible_chars * 2);

        format!("{}{}...{}", prefix, "*".repeat(masked_len.min(20)), suffix)
    }

    /// Get context around the finding (surrounding lines)
    fn get_context(&self, lines: &[&str], line_num: usize) -> String {
        let start = line_num.saturating_sub(1);
        let end = (line_num + 2).min(lines.len());

        lines[start..end]
            .iter()
            .enumerate()
            .map(|(i, line)| {
                let actual_line = start + i + 1;
                let marker = if actual_line == line_num + 1 { ">" } else { " " };
                format!("{} {:4}: {}", marker, actual_line, line)
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Get remediation recommendation based on secret type
    fn get_recommendation(&self, secret_type: &str) -> String {
        match secret_type {
            s if s.contains("AWS") => {
                "Rotate AWS credentials immediately via IAM console. Use AWS Secrets Manager or environment variables instead of hardcoding.".to_string()
            }
            s if s.contains("GitHub") => {
                "Revoke the token in GitHub Settings > Developer settings > Personal access tokens. Use GitHub Actions secrets for CI/CD.".to_string()
            }
            s if s.contains("Private Key") => {
                "Regenerate the key pair immediately. Never commit private keys to version control. Use a secrets manager.".to_string()
            }
            s if s.contains("Password") || s.contains("Database Connection") => {
                "Change the password immediately. Use environment variables or a secrets manager for credentials.".to_string()
            }
            s if s.contains("JWT") => {
                "If this is a signing key, rotate it and invalidate existing tokens. Review your JWT implementation.".to_string()
            }
            s if s.contains("Slack") => {
                "Regenerate the token in Slack App settings. Review app permissions and use environment variables.".to_string()
            }
            s if s.contains("Stripe") => {
                "Roll your API keys in the Stripe Dashboard. Use restricted keys with minimal permissions.".to_string()
            }
            s if s.contains("Google") || s.contains("Firebase") => {
                "Regenerate the key in Google Cloud Console. Restrict key permissions and use Application Default Credentials.".to_string()
            }
            s if s.contains("Azure") => {
                "Rotate the secret in Azure Portal. Use Azure Key Vault or Managed Identity for authentication.".to_string()
            }
            s if s.contains("API Key") || s.contains("Token") => {
                "Rotate the credential immediately. Store secrets in environment variables or a secrets manager.".to_string()
            }
            _ => {
                "Remove the secret from code. Use environment variables or a secrets manager for sensitive data.".to_string()
            }
        }
    }

    /// Get summary statistics of findings
    pub fn get_summary(&self, findings: &[SecretFinding]) -> SecretsSummary {
        let critical = findings.iter().filter(|f| f.severity == SecretSeverity::Critical).count();
        let high = findings.iter().filter(|f| f.severity == SecretSeverity::High).count();
        let medium = findings.iter().filter(|f| f.severity == SecretSeverity::Medium).count();
        let low = findings.iter().filter(|f| f.severity == SecretSeverity::Low).count();

        let mut by_type: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        for finding in findings {
            *by_type.entry(finding.secret_type.clone()).or_insert(0) += 1;
        }

        SecretsSummary {
            total: findings.len(),
            critical,
            high,
            medium,
            low,
            by_type,
        }
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
    pub severity: SecretSeverity,
    pub context: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FileSecretFindings {
    pub file_path: String,
    pub findings: Vec<SecretFinding>,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct SecretsSummary {
    pub total: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub by_type: std::collections::HashMap<String, usize>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aws_access_key_detection() {
        let scanner = SecretsScanner::new();
        // Use a realistic-looking AWS key that won't be filtered as a placeholder
        let content = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7REALKEY";
        let findings = scanner.scan_file(content).unwrap();
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.secret_type.contains("AWS")));
    }

    #[test]
    fn test_github_token_detection() {
        let scanner = SecretsScanner::new();
        // Use a realistic-looking GitHub token that won't be filtered as a placeholder
        // Avoid placeholders: example, sample, test, dummy, fake, xxx, abc, 123, 000, etc.
        // GitHub PAT pattern requires exactly 36 alphanumeric chars after ghp_
        let content = "token = 'ghp_qRstuVwxYzMnopQrstuvWxYz045678qRstuV'";
        let findings = scanner.scan_file(content).unwrap();
        assert!(findings.iter().any(|f| f.secret_type.contains("GitHub")));
    }

    #[test]
    fn test_private_key_detection() {
        let scanner = SecretsScanner::new();
        let content = "-----BEGIN RSA PRIVATE KEY-----\nMIIE...";
        let findings = scanner.scan_file(content).unwrap();
        assert!(findings.iter().any(|f| f.secret_type.contains("Private Key")));
    }

    #[test]
    fn test_false_positive_filtering() {
        let scanner = SecretsScanner::new();
        let content = "// Example: API_KEY=your_api_key_here";
        let findings = scanner.scan_file(content).unwrap();
        // Should be filtered out as a comment with placeholder
        assert!(findings.is_empty() || findings.iter().all(|f| f.secret_type != "Generic API Key"));
    }

    #[test]
    fn test_password_in_url_detection() {
        let scanner = SecretsScanner::new();
        let content = "DATABASE_URL=postgres://user:secretpassword@localhost:5432/db";
        let findings = scanner.scan_file(content).unwrap();
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_jwt_detection() {
        let scanner = SecretsScanner::new();
        // JWT token that avoids placeholder strings (no 123, abc, test, example, etc in the token)
        let content = "Authorization: Bearer eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJzdWIiOiAiOTg3NjU0IiwgIm5hbWUiOiAiQWxpY2UiLCAiaWF0IjogMTYwOTQ1OTIwMH0.KxWRJMmvLFYhD9bKTJ8qN3gVf5YZfRWGhE7sT2nPwXm";
        let findings = scanner.scan_file(content).unwrap();
        // Pattern name is "JSON Web Token", not "JWT"
        assert!(findings.iter().any(|f| f.secret_type.contains("Web Token")));
    }
}
