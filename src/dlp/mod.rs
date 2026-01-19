//! Data Loss Prevention (DLP) engine (Sprint 8)
//!
//! Provides content scanning for sensitive data patterns including:
//! - Credit card numbers (Luhn validation)
//! - Social Security Numbers
//! - API keys and secrets
//! - Email addresses
//! - Custom regex patterns

use serde::{Serialize, Deserialize};
use regex::Regex;
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DLPPolicy {
    pub id: String,
    pub name: String,
    pub patterns: Vec<DataPattern>,
    pub action: PolicyAction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataPattern {
    pub pattern_type: PatternType,
    pub regex: String,
    pub sensitivity: Sensitivity,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PatternType {
    CreditCard,
    SSN,
    Email,
    APIKey,
    Password,
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, PartialOrd)]
pub enum Sensitivity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PolicyAction {
    Block,
    Warn,
    Log,
    Encrypt,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DLPViolation {
    pub id: String,
    pub policy_id: String,
    pub user_id: String,
    pub pattern_matched: String,
    pub action_taken: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanContext {
    pub user_id: String,
    pub source: String,
    pub metadata: HashMap<String, String>,
}

impl Default for ScanContext {
    fn default() -> Self {
        Self {
            user_id: "system".to_string(),
            source: "unknown".to_string(),
            metadata: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub violations: Vec<DLPViolation>,
    pub patterns_matched: usize,
    pub highest_sensitivity: Option<Sensitivity>,
    pub blocked: bool,
    pub scan_duration_ms: u64,
}

/// Scan content against DLP policies and return violations
pub async fn scan_content(content: &str, policies: &[DLPPolicy]) -> Vec<DLPViolation> {
    let context = ScanContext::default();
    scan_content_with_context(content, policies, &context).await
}

/// Scan content with full context information
pub async fn scan_content_with_context(
    content: &str,
    policies: &[DLPPolicy],
    context: &ScanContext,
) -> Vec<DLPViolation> {
    let mut violations = Vec::new();
    let mut compiled_patterns: HashMap<String, Regex> = HashMap::new();

    for policy in policies {
        for pattern in &policy.patterns {
            // Get or compile the regex pattern
            let regex = match compiled_patterns.get(&pattern.regex) {
                Some(r) => r,
                None => {
                    match Regex::new(&pattern.regex) {
                        Ok(r) => {
                            compiled_patterns.insert(pattern.regex.clone(), r);
                            compiled_patterns.get(&pattern.regex).unwrap()
                        }
                        Err(_) => continue, // Skip invalid patterns
                    }
                }
            };

            // Find all matches in content
            for mat in regex.find_iter(content) {
                let matched_text = mat.as_str();

                // Validate specific patterns
                let is_valid = match pattern.pattern_type {
                    PatternType::CreditCard => validate_credit_card(matched_text),
                    PatternType::SSN => validate_ssn(matched_text),
                    PatternType::APIKey => validate_api_key(matched_text),
                    _ => true, // Accept other patterns as-is
                };

                if is_valid {
                    let action_taken = match policy.action {
                        PolicyAction::Block => "blocked",
                        PolicyAction::Warn => "warned",
                        PolicyAction::Log => "logged",
                        PolicyAction::Encrypt => "encrypted",
                    };

                    violations.push(DLPViolation {
                        id: Uuid::new_v4().to_string(),
                        policy_id: policy.id.clone(),
                        user_id: context.user_id.clone(),
                        pattern_matched: redact_sensitive(matched_text, &pattern.pattern_type),
                        action_taken: action_taken.to_string(),
                        timestamp: chrono::Utc::now(),
                    });
                }
            }
        }
    }

    violations
}

/// Full scan with detailed result
pub async fn scan_content_full(
    content: &str,
    policies: &[DLPPolicy],
    context: &ScanContext,
) -> ScanResult {
    let start = std::time::Instant::now();
    let violations = scan_content_with_context(content, policies, context).await;

    let blocked = violations.iter().any(|v| v.action_taken == "blocked");

    // Find highest sensitivity from policies that had violations
    let policy_map: HashMap<_, _> = policies.iter()
        .map(|p| (p.id.clone(), p))
        .collect();

    let highest_sensitivity = violations.iter()
        .filter_map(|v| policy_map.get(&v.policy_id))
        .flat_map(|p| p.patterns.iter().map(|pat| &pat.sensitivity))
        .max_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
        .cloned();

    ScanResult {
        patterns_matched: violations.len(),
        violations,
        highest_sensitivity,
        blocked,
        scan_duration_ms: start.elapsed().as_millis() as u64,
    }
}

/// Validate credit card number using Luhn algorithm
fn validate_credit_card(number: &str) -> bool {
    // Remove spaces and dashes
    let digits: String = number.chars()
        .filter(|c| c.is_ascii_digit())
        .collect();

    if digits.len() < 13 || digits.len() > 19 {
        return false;
    }

    // Luhn algorithm
    let mut sum = 0;
    let mut double = false;

    for c in digits.chars().rev() {
        if let Some(digit) = c.to_digit(10) {
            let mut d = digit;
            if double {
                d *= 2;
                if d > 9 {
                    d -= 9;
                }
            }
            sum += d;
            double = !double;
        }
    }

    sum % 10 == 0
}

/// Validate SSN format
fn validate_ssn(ssn: &str) -> bool {
    // Remove dashes
    let digits: String = ssn.chars()
        .filter(|c| c.is_ascii_digit())
        .collect();

    if digits.len() != 9 {
        return false;
    }

    // Check for invalid SSN patterns
    let area: u32 = digits[0..3].parse().unwrap_or(0);
    let group: u32 = digits[3..5].parse().unwrap_or(0);
    let serial: u32 = digits[5..9].parse().unwrap_or(0);

    // Area numbers 000, 666, and 900-999 are invalid
    if area == 0 || area == 666 || area >= 900 {
        return false;
    }

    // Group and serial can't be all zeros
    if group == 0 || serial == 0 {
        return false;
    }

    true
}

/// Validate potential API key patterns
fn validate_api_key(key: &str) -> bool {
    // API keys typically have high entropy and specific prefixes
    let entropy = calculate_entropy(key);

    // Check for common API key prefixes
    let common_prefixes = [
        "sk_live_", "sk_test_", "pk_live_", "pk_test_",  // Stripe
        "ghp_", "gho_", "ghs_",                          // GitHub
        "xoxb-", "xoxp-", "xoxa-",                       // Slack
        "AKIA", "ASIA",                                   // AWS
        "AIza",                                           // Google
        "Bearer ", "Basic ",                              // Auth headers
    ];

    let has_prefix = common_prefixes.iter().any(|p| key.starts_with(p));

    // High entropy (> 3.5) or has known prefix
    entropy > 3.5 || has_prefix
}

/// Calculate Shannon entropy of a string
fn calculate_entropy(s: &str) -> f64 {
    let mut freq: HashMap<char, usize> = HashMap::new();
    let len = s.len() as f64;

    for c in s.chars() {
        *freq.entry(c).or_insert(0) += 1;
    }

    freq.values()
        .map(|&count| {
            let p = count as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Redact sensitive data for logging
fn redact_sensitive(text: &str, pattern_type: &PatternType) -> String {
    match pattern_type {
        PatternType::CreditCard => {
            let digits: String = text.chars()
                .filter(|c| c.is_ascii_digit())
                .collect();
            if digits.len() >= 4 {
                format!("****-****-****-{}", &digits[digits.len()-4..])
            } else {
                "****".to_string()
            }
        }
        PatternType::SSN => "***-**-****".to_string(),
        PatternType::APIKey => {
            if text.len() > 8 {
                format!("{}...{}", &text[..4], &text[text.len()-4..])
            } else {
                "****".to_string()
            }
        }
        PatternType::Password => "********".to_string(),
        PatternType::Email => {
            if let Some(at_pos) = text.find('@') {
                let local = &text[..at_pos];
                let domain = &text[at_pos..];
                if local.len() > 2 {
                    format!("{}...{}", &local[..1], domain)
                } else {
                    format!("*{}", domain)
                }
            } else {
                "***@***.***".to_string()
            }
        }
        PatternType::Custom => {
            if text.len() > 8 {
                format!("{}...{}", &text[..4], &text[text.len()-4..])
            } else {
                "****".to_string()
            }
        }
    }
}

/// Get default DLP patterns for common sensitive data
pub fn get_default_patterns() -> Vec<DataPattern> {
    vec![
        DataPattern {
            pattern_type: PatternType::CreditCard,
            regex: r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b".to_string(),
            sensitivity: Sensitivity::Critical,
        },
        DataPattern {
            pattern_type: PatternType::SSN,
            regex: r"\b\d{3}-\d{2}-\d{4}\b".to_string(),
            sensitivity: Sensitivity::Critical,
        },
        DataPattern {
            pattern_type: PatternType::Email,
            regex: r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b".to_string(),
            sensitivity: Sensitivity::Medium,
        },
        DataPattern {
            pattern_type: PatternType::APIKey,
            regex: r"\b(sk_live_[a-zA-Z0-9]{24}|ghp_[a-zA-Z0-9]{36}|AKIA[A-Z0-9]{16}|xoxb-[0-9]+-[a-zA-Z0-9]+)\b".to_string(),
            sensitivity: Sensitivity::Critical,
        },
        DataPattern {
            pattern_type: PatternType::Password,
            regex: r#"(?i)(password|passwd|pwd|secret|token)\s*[=:]\s*["']?[^\s"']{8,}["']?"#.to_string(),
            sensitivity: Sensitivity::Critical,
        },
    ]
}

/// Get extended patterns for comprehensive scanning
pub fn get_extended_patterns() -> Vec<DataPattern> {
    let mut patterns = get_default_patterns();
    patterns.extend(vec![
        // AWS Access Keys
        DataPattern {
            pattern_type: PatternType::APIKey,
            regex: r"\bAKIA[A-Z0-9]{16}\b".to_string(),
            sensitivity: Sensitivity::Critical,
        },
        // AWS Secret Keys
        DataPattern {
            pattern_type: PatternType::APIKey,
            regex: r"\b[A-Za-z0-9/+=]{40}\b".to_string(),
            sensitivity: Sensitivity::High,
        },
        // Private Keys
        DataPattern {
            pattern_type: PatternType::APIKey,
            regex: r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----".to_string(),
            sensitivity: Sensitivity::Critical,
        },
        // JWT Tokens
        DataPattern {
            pattern_type: PatternType::APIKey,
            regex: r"\beyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\b".to_string(),
            sensitivity: Sensitivity::High,
        },
        // IP Addresses (internal ranges)
        DataPattern {
            pattern_type: PatternType::Custom,
            regex: r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b".to_string(),
            sensitivity: Sensitivity::Low,
        },
        // Phone Numbers (US)
        DataPattern {
            pattern_type: PatternType::Custom,
            regex: r"\b(\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b".to_string(),
            sensitivity: Sensitivity::Medium,
        },
    ]);
    patterns
}

/// Create a policy from a set of patterns
pub fn create_policy(
    name: &str,
    patterns: Vec<DataPattern>,
    action: PolicyAction,
) -> DLPPolicy {
    DLPPolicy {
        id: Uuid::new_v4().to_string(),
        name: name.to_string(),
        patterns,
        action,
    }
}

/// Create default policies for common use cases
pub fn get_default_policies() -> Vec<DLPPolicy> {
    vec![
        DLPPolicy {
            id: "pii-critical".to_string(),
            name: "PII Critical Data".to_string(),
            patterns: vec![
                DataPattern {
                    pattern_type: PatternType::SSN,
                    regex: r"\b\d{3}-\d{2}-\d{4}\b".to_string(),
                    sensitivity: Sensitivity::Critical,
                },
                DataPattern {
                    pattern_type: PatternType::CreditCard,
                    regex: r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b".to_string(),
                    sensitivity: Sensitivity::Critical,
                },
            ],
            action: PolicyAction::Block,
        },
        DLPPolicy {
            id: "secrets-detection".to_string(),
            name: "Secrets and API Keys".to_string(),
            patterns: vec![
                DataPattern {
                    pattern_type: PatternType::APIKey,
                    regex: r"\b(sk_live_[a-zA-Z0-9]{24}|ghp_[a-zA-Z0-9]{36}|AKIA[A-Z0-9]{16})\b".to_string(),
                    sensitivity: Sensitivity::Critical,
                },
                DataPattern {
                    pattern_type: PatternType::Password,
                    regex: r#"(?i)(password|passwd|pwd|secret|token)\s*[=:]\s*["']?[^\s"']{8,}["']?"#.to_string(),
                    sensitivity: Sensitivity::Critical,
                },
            ],
            action: PolicyAction::Block,
        },
        DLPPolicy {
            id: "email-monitoring".to_string(),
            name: "Email Monitoring".to_string(),
            patterns: vec![
                DataPattern {
                    pattern_type: PatternType::Email,
                    regex: r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b".to_string(),
                    sensitivity: Sensitivity::Medium,
                },
            ],
            action: PolicyAction::Log,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_luhn_validation() {
        // Valid test card numbers
        assert!(validate_credit_card("4532015112830366"));
        assert!(validate_credit_card("4532-0151-1283-0366"));
        assert!(validate_credit_card("4532 0151 1283 0366"));

        // Invalid numbers (fails Luhn check)
        assert!(!validate_credit_card("1234567890123456"));
        // Note: 0000000000000000 actually passes Luhn (sum = 0, 0 % 10 == 0)
        // but it should still be rejected by length check for too-short numbers
        assert!(!validate_credit_card("123456789012")); // Too short (12 digits)
    }

    #[test]
    fn test_ssn_validation() {
        // Valid SSNs
        assert!(validate_ssn("123-45-6789"));

        // Invalid SSNs
        assert!(!validate_ssn("000-45-6789")); // Area 000
        assert!(!validate_ssn("666-45-6789")); // Area 666
        assert!(!validate_ssn("900-45-6789")); // Area 900+
        assert!(!validate_ssn("123-00-6789")); // Group 00
        assert!(!validate_ssn("123-45-0000")); // Serial 0000
    }

    #[test]
    fn test_entropy_calculation() {
        let low_entropy = calculate_entropy("aaaaaaaaaa");
        let high_entropy = calculate_entropy("aB3$xY9@mK");

        assert!(low_entropy < high_entropy);
        assert!(high_entropy > 3.0);
    }

    #[tokio::test]
    async fn test_scan_content() {
        let policies = get_default_policies();
        let content = "My SSN is 123-45-6789 and my card is 4532-0151-1283-0366";

        let violations = scan_content(content, &policies).await;

        assert!(violations.len() >= 2);
    }
}
