//! Entropy-based secret detection
//!
//! Uses Shannon entropy and character class analysis to detect high-entropy
//! strings that may be secrets, API keys, or cryptographic material.

use std::collections::HashSet;

/// Configuration for entropy-based detection
#[derive(Debug, Clone)]
pub struct EntropyConfig {
    /// Minimum entropy threshold for flagging (default: 4.5)
    pub min_entropy: f64,
    /// Minimum string length to analyze (default: 16)
    pub min_length: usize,
    /// Maximum string length to analyze (default: 256)
    pub max_length: usize,
    /// Require multiple character classes (default: true)
    pub require_mixed_classes: bool,
    /// Minimum number of character classes required (default: 3)
    pub min_char_classes: usize,
    /// Boost score for context keywords (default: 0.5)
    pub context_boost: f64,
    /// Enable false positive filtering (default: true)
    pub filter_false_positives: bool,
}

impl Default for EntropyConfig {
    fn default() -> Self {
        Self {
            min_entropy: 4.5,
            min_length: 16,
            max_length: 256,
            require_mixed_classes: true,
            min_char_classes: 3,
            context_boost: 0.5,
            filter_false_positives: true,
        }
    }
}

/// Result of entropy analysis
#[derive(Debug, Clone)]
pub struct EntropyResult {
    /// The analyzed string
    pub value: String,
    /// Shannon entropy score
    pub entropy: f64,
    /// Number of character classes present
    pub char_classes: usize,
    /// Whether this appears to be a secret
    pub is_high_entropy: bool,
    /// Context keywords found nearby
    pub context_keywords: Vec<String>,
    /// Adjusted score after context boosting
    pub adjusted_score: f64,
    /// Detection confidence (0.0 - 1.0)
    pub confidence: f64,
}

/// Context keywords that boost confidence when found near high-entropy strings
const CONTEXT_KEYWORDS: &[&str] = &[
    "secret", "key", "token", "password", "passwd", "pwd", "credential",
    "api_key", "apikey", "api-key", "auth", "bearer", "access_token",
    "private_key", "privatekey", "private-key", "encryption", "decrypt",
    "signing", "signature", "certificate", "cert", "pem", "rsa", "ssh",
    "aws", "azure", "gcp", "github", "gitlab", "slack", "stripe", "twilio",
    "sendgrid", "mailgun", "database", "connection", "jdbc", "mongodb",
    "postgres", "mysql", "redis", "oauth", "jwt", "session", "cookie",
];

/// Patterns that indicate false positives
const FALSE_POSITIVE_PATTERNS: &[&str] = &[
    // UUIDs
    "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    // Common hash lengths that aren't secrets
    "0000000000000000",
    "ffffffffffffffff",
    // Lorem ipsum and test data
    "lorem", "ipsum", "dolor", "amet",
    "test", "example", "sample", "demo", "placeholder",
    // File paths and URLs components
    ".js", ".css", ".html", ".json", ".xml", ".yaml", ".yml",
    "http://", "https://", "file://", "mailto:",
    // Common non-secret hex patterns
    "deadbeef", "cafebabe", "badc0de",
];

/// Calculate Shannon entropy of a string
pub fn calculate_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }

    let mut freq: std::collections::HashMap<char, usize> = std::collections::HashMap::new();
    for c in s.chars() {
        *freq.entry(c).or_insert(0) += 1;
    }

    let len = s.len() as f64;
    let mut entropy = 0.0;

    for count in freq.values() {
        let p = *count as f64 / len;
        if p > 0.0 {
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// Count the number of character classes in a string
pub fn count_char_classes(s: &str) -> usize {
    let mut classes = HashSet::new();

    for c in s.chars() {
        if c.is_ascii_lowercase() {
            classes.insert("lowercase");
        } else if c.is_ascii_uppercase() {
            classes.insert("uppercase");
        } else if c.is_ascii_digit() {
            classes.insert("digit");
        } else if c.is_ascii_punctuation() || c == '_' || c == '-' {
            classes.insert("special");
        } else if c.is_whitespace() {
            classes.insert("whitespace");
        } else {
            classes.insert("other");
        }
    }

    classes.len()
}

/// Check if a string looks like a UUID
fn is_uuid(s: &str) -> bool {
    let s = s.to_lowercase();
    // Standard UUID format: 8-4-4-4-12
    if s.len() == 36 {
        let parts: Vec<&str> = s.split('-').collect();
        if parts.len() == 5 {
            return parts[0].len() == 8
                && parts[1].len() == 4
                && parts[2].len() == 4
                && parts[3].len() == 4
                && parts[4].len() == 12
                && s.chars().all(|c| c.is_ascii_hexdigit() || c == '-');
        }
    }
    // UUID without dashes
    if s.len() == 32 && s.chars().all(|c| c.is_ascii_hexdigit()) {
        return true;
    }
    false
}

/// Check if a string looks like a hash (MD5, SHA1, SHA256, etc.)
fn is_common_hash(s: &str) -> bool {
    let len = s.len();
    // Common hash lengths: MD5=32, SHA1=40, SHA256=64, SHA512=128
    let is_hash_length = len == 32 || len == 40 || len == 64 || len == 128;
    if is_hash_length && s.chars().all(|c| c.is_ascii_hexdigit()) {
        // Check for patterns that suggest it's a placeholder or test hash
        let lower = s.to_lowercase();
        if lower.chars().all(|c| c == '0' || c == 'f' || c == 'a') {
            return true; // Likely a placeholder like 000...000 or fff...fff
        }
        // Real hashes are usually not secrets - they're checksums
        return true;
    }
    false
}

/// Check if string contains false positive indicators
fn has_false_positive_indicator(s: &str, context: &str) -> bool {
    let lower_s = s.to_lowercase();
    let lower_context = context.to_lowercase();

    for pattern in FALSE_POSITIVE_PATTERNS {
        if lower_s.contains(pattern) || lower_context.contains(pattern) {
            return true;
        }
    }

    // Check for repeated characters (suggests placeholder)
    if s.len() >= 8 {
        let chars: Vec<char> = s.chars().collect();
        let mut repeat_count = 1;
        for i in 1..chars.len() {
            if chars[i] == chars[i - 1] {
                repeat_count += 1;
                if repeat_count >= 4 {
                    return true; // 4+ repeated chars suggests placeholder
                }
            } else {
                repeat_count = 1;
            }
        }
    }

    false
}

/// Find context keywords near a position in the content
pub fn find_context_keywords(content: &str, position: usize, window_size: usize) -> Vec<String> {
    let start = position.saturating_sub(window_size);
    let end = (position + window_size).min(content.len());
    let context = &content[start..end].to_lowercase();

    CONTEXT_KEYWORDS
        .iter()
        .filter(|kw| context.contains(*kw))
        .map(|s| s.to_string())
        .collect()
}

/// Analyze a string for high entropy (potential secret)
pub fn analyze_entropy(value: &str, context: &str, config: &EntropyConfig) -> EntropyResult {
    let entropy = calculate_entropy(value);
    let char_classes = count_char_classes(value);
    let context_keywords = find_context_keywords(context, 0, context.len());

    // Calculate adjusted score with context boost
    let context_boost = if !context_keywords.is_empty() {
        config.context_boost * (context_keywords.len() as f64).min(2.0)
    } else {
        0.0
    };
    let adjusted_score = entropy + context_boost;

    // Determine if this is high entropy
    let mut is_high_entropy = entropy >= config.min_entropy
        && value.len() >= config.min_length
        && value.len() <= config.max_length;

    // Check character class requirements
    if config.require_mixed_classes && char_classes < config.min_char_classes {
        is_high_entropy = false;
    }

    // Filter false positives
    if config.filter_false_positives && is_high_entropy {
        if is_uuid(value) || is_common_hash(value) || has_false_positive_indicator(value, context) {
            is_high_entropy = false;
        }
    }

    // Calculate confidence based on various factors
    let mut confidence = 0.0;
    if is_high_entropy {
        // Base confidence from entropy
        confidence = ((entropy - config.min_entropy) / 2.0).min(0.5);

        // Boost for character classes
        if char_classes >= 4 {
            confidence += 0.2;
        } else if char_classes >= 3 {
            confidence += 0.1;
        }

        // Boost for context keywords
        confidence += (context_keywords.len() as f64 * 0.1).min(0.3);

        confidence = confidence.min(1.0);
    }

    EntropyResult {
        value: value.to_string(),
        entropy,
        char_classes,
        is_high_entropy,
        context_keywords,
        adjusted_score,
        confidence,
    }
}

/// Extract and analyze potential secrets from content based on entropy
pub fn find_high_entropy_strings(
    content: &str,
    config: &EntropyConfig,
) -> Vec<EntropyResult> {
    let mut results = Vec::new();

    // Split on whitespace and common delimiters
    let tokens: Vec<&str> = content
        .split(|c: char| c.is_whitespace() || c == '"' || c == '\'' || c == '=' || c == ':' || c == ',' || c == ';')
        .filter(|s| !s.is_empty())
        .collect();

    for token in tokens {
        // Clean up the token
        let cleaned = token.trim_matches(|c: char| !c.is_alphanumeric() && c != '_' && c != '-' && c != '+' && c != '/');

        if cleaned.len() < config.min_length || cleaned.len() > config.max_length {
            continue;
        }

        let result = analyze_entropy(cleaned, content, config);
        if result.is_high_entropy {
            results.push(result);
        }
    }

    // Deduplicate results
    let mut seen = HashSet::new();
    results.retain(|r| seen.insert(r.value.clone()));

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_calculation() {
        // Low entropy - repeated chars
        assert!(calculate_entropy("aaaaaaaaaa") < 1.0);

        // Medium entropy - some variation
        assert!(calculate_entropy("abcdefghij") > 3.0);

        // High entropy - random-looking
        assert!(calculate_entropy("aB3$xY9@mK2!pQ7&") > 4.0);
    }

    #[test]
    fn test_char_classes() {
        assert_eq!(count_char_classes("abc"), 1);
        assert_eq!(count_char_classes("abcABC"), 2);
        assert_eq!(count_char_classes("abcABC123"), 3);
        assert_eq!(count_char_classes("abcABC123!@#"), 4);
    }

    #[test]
    fn test_uuid_detection() {
        assert!(is_uuid("550e8400-e29b-41d4-a716-446655440000"));
        assert!(is_uuid("550e8400e29b41d4a716446655440000"));
        assert!(!is_uuid("not-a-uuid"));
    }

    #[test]
    fn test_high_entropy_detection() {
        let config = EntropyConfig::default();

        // This should be detected as high entropy (looks like an API key)
        let result = analyze_entropy(
            "sk_live_aBcDeFgHiJkLmNoPqRsTuVwX",
            "api_key = sk_live_aBcDeFgHiJkLmNoPqRsTuVwX",
            &config,
        );
        assert!(result.is_high_entropy);
        assert!(result.confidence > 0.5);

        // This should NOT be detected (UUID)
        let result = analyze_entropy(
            "550e8400-e29b-41d4-a716-446655440000",
            "user_id = 550e8400-e29b-41d4-a716-446655440000",
            &config,
        );
        assert!(!result.is_high_entropy);
    }
}
