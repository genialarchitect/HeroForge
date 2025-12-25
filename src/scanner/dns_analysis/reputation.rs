//! Domain Reputation Checking
//!
//! This module provides domain reputation analysis including:
//! - Known malicious domain lists
//! - Newly registered domain detection
//! - Typosquatting detection
//! - Homograph attack detection (IDN/punycode abuse)

#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

// =============================================================================
// Types
// =============================================================================

/// Domain reputation categories
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ReputationCategory {
    /// Known malware distribution domain
    Malware,
    /// Known phishing domain
    Phishing,
    /// Known command and control domain
    C2,
    /// Known spam domain
    Spam,
    /// Generally suspicious domain
    Suspicious,
}

/// Result of reputation check
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationResult {
    /// Whether the domain is clean (no negative reputation)
    pub is_clean: bool,
    /// Reputation categories that matched
    pub categories: Vec<ReputationCategory>,
    /// Confidence score (0.0 - 1.0)
    pub confidence: f64,
    /// Source of the reputation data
    pub source: String,
    /// Additional details
    pub details: Vec<String>,
    /// Domain age if available (None if unknown)
    pub domain_age_days: Option<u32>,
    /// Whether domain appears to be typosquatting a popular domain
    pub is_typosquat: bool,
    /// Target of typosquatting (if applicable)
    pub typosquat_target: Option<String>,
    /// Whether domain uses IDN/punycode that resembles another domain
    pub is_homograph: bool,
    /// Visual target of homograph attack (if applicable)
    pub homograph_target: Option<String>,
}

/// Typosquatting detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TyposquatResult {
    /// Whether typosquatting was detected
    pub is_typosquat: bool,
    /// The likely target domain
    pub target: Option<String>,
    /// Type of typosquatting
    pub squat_type: Option<TyposquatType>,
    /// Similarity score (0.0 - 1.0)
    pub similarity: f64,
}

/// Types of typosquatting
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TyposquatType {
    /// Missing character (gogle.com -> google.com)
    Omission,
    /// Repeated character (googgle.com -> google.com)
    Repetition,
    /// Transposed characters (googel.com -> google.com)
    Transposition,
    /// Replaced character (goog1e.com -> google.com)
    Replacement,
    /// Added character (gooogle.com -> google.com)
    Insertion,
    /// Wrong TLD (google.co -> google.com)
    WrongTld,
    /// Subdomain impersonation (google.com.malicious.com)
    SubdomainImpersonation,
    /// Hyphenation (g-oogle.com -> google.com)
    Hyphenation,
    /// Homoglyph replacement (g00gle.com using zeros)
    Homoglyph,
}

/// Homograph attack detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HomographResult {
    /// Whether a homograph attack was detected
    pub is_homograph: bool,
    /// The visual target domain
    pub target: Option<String>,
    /// Punycode representation
    pub punycode: Option<String>,
    /// Unicode characters used for visual deception
    pub deceptive_chars: Vec<(char, char)>,
    /// Confidence score
    pub confidence: f64,
}

// =============================================================================
// Domain Reputation Checker
// =============================================================================

/// Domain reputation checker
pub struct DomainReputation {
    /// Known malicious domains
    malicious_domains: HashSet<String>,
    /// Known phishing domains
    phishing_domains: HashSet<String>,
    /// Known C2 domains
    c2_domains: HashSet<String>,
    /// Popular domains for typosquatting detection
    popular_domains: Vec<String>,
    /// Homoglyph character mappings
    homoglyphs: Vec<(char, char)>,
    /// Newly registered domain threshold (days)
    new_domain_threshold_days: u32,
}

impl DomainReputation {
    /// Create a new domain reputation checker
    pub fn new() -> Self {
        Self {
            malicious_domains: build_malicious_domain_list(),
            phishing_domains: build_phishing_domain_list(),
            c2_domains: build_c2_domain_list(),
            popular_domains: build_popular_domain_list(),
            homoglyphs: build_homoglyph_mappings(),
            new_domain_threshold_days: 30,
        }
    }

    /// Check domain reputation
    pub fn check(&self, domain: &str) -> ReputationResult {
        let domain = domain.to_lowercase();
        let mut categories = Vec::new();
        let mut details = Vec::new();
        let mut confidence: f64 = 0.0;

        // Check against known malicious lists
        if self.malicious_domains.contains(&domain) {
            categories.push(ReputationCategory::Malware);
            details.push("Domain in known malware list".to_string());
            confidence = 0.95;
        }

        if self.phishing_domains.contains(&domain) {
            categories.push(ReputationCategory::Phishing);
            details.push("Domain in known phishing list".to_string());
            confidence = confidence.max(0.95);
        }

        if self.c2_domains.contains(&domain) {
            categories.push(ReputationCategory::C2);
            details.push("Domain in known C2 list".to_string());
            confidence = confidence.max(0.95);
        }

        // Check for typosquatting
        let typosquat_result = self.check_typosquatting(&domain);
        let is_typosquat = typosquat_result.is_typosquat;
        let typosquat_target = typosquat_result.target.clone();

        if is_typosquat {
            if categories.is_empty() {
                categories.push(ReputationCategory::Suspicious);
            }
            details.push(format!(
                "Possible typosquatting of '{}'",
                typosquat_result.target.as_ref().unwrap_or(&"unknown".to_string())
            ));
            confidence = confidence.max(typosquat_result.similarity * 0.8);
        }

        // Check for homograph attacks
        let homograph_result = self.check_homograph(&domain);
        let is_homograph = homograph_result.is_homograph;
        let homograph_target = homograph_result.target.clone();

        if is_homograph {
            if categories.is_empty() {
                categories.push(ReputationCategory::Phishing);
            }
            details.push(format!(
                "IDN homograph attack targeting '{}'",
                homograph_result.target.as_ref().unwrap_or(&"unknown".to_string())
            ));
            confidence = confidence.max(homograph_result.confidence);
        }

        // Check for suspicious TLD patterns
        if is_suspicious_tld(&domain) {
            if categories.is_empty() {
                categories.push(ReputationCategory::Suspicious);
            }
            details.push("Domain uses suspicious TLD".to_string());
            confidence = confidence.max(0.3);
        }

        let is_clean = categories.is_empty();

        ReputationResult {
            is_clean,
            categories,
            confidence,
            source: "HeroForge Built-in".to_string(),
            details,
            domain_age_days: None, // Would need external API for this
            is_typosquat,
            typosquat_target,
            is_homograph,
            homograph_target,
        }
    }

    /// Check for typosquatting
    pub fn check_typosquatting(&self, domain: &str) -> TyposquatResult {
        let domain_lower = domain.to_lowercase();

        // Extract the main domain name (without TLD)
        let domain_parts: Vec<&str> = domain_lower.split('.').collect();
        if domain_parts.is_empty() {
            return TyposquatResult {
                is_typosquat: false,
                target: None,
                squat_type: None,
                similarity: 0.0,
            };
        }

        let domain_name = domain_parts[0];

        for popular in &self.popular_domains {
            let popular_parts: Vec<&str> = popular.split('.').collect();
            if popular_parts.is_empty() {
                continue;
            }
            let popular_name = popular_parts[0];

            // Skip if domains are identical
            if domain_name == popular_name {
                continue;
            }

            // Check for various typosquatting patterns
            if let Some((squat_type, similarity)) =
                detect_typosquat_type(domain_name, popular_name)
            {
                if similarity > 0.7 {
                    return TyposquatResult {
                        is_typosquat: true,
                        target: Some(popular.clone()),
                        squat_type: Some(squat_type),
                        similarity,
                    };
                }
            }

            // Check for subdomain impersonation (google.com.malicious.com)
            if domain_lower.contains(&format!("{}.com.", popular_name))
                || domain_lower.contains(&format!("{}.", popular_name))
            {
                return TyposquatResult {
                    is_typosquat: true,
                    target: Some(popular.clone()),
                    squat_type: Some(TyposquatType::SubdomainImpersonation),
                    similarity: 0.9,
                };
            }
        }

        TyposquatResult {
            is_typosquat: false,
            target: None,
            squat_type: None,
            similarity: 0.0,
        }
    }

    /// Check for IDN homograph attacks
    pub fn check_homograph(&self, domain: &str) -> HomographResult {
        // Check if domain contains punycode
        if !domain.starts_with("xn--") && !domain.contains(".xn--") {
            // Check for Latin lookalike characters in the domain
            let mut deceptive_chars = Vec::new();

            for c in domain.chars() {
                for &(visual, actual) in &self.homoglyphs {
                    if c == visual && c != actual {
                        deceptive_chars.push((visual, actual));
                    }
                }
            }

            if !deceptive_chars.is_empty() {
                // Try to reconstruct the target domain
                let target = reconstruct_ascii_domain(domain, &deceptive_chars);

                // Check if target matches a popular domain
                for popular in &self.popular_domains {
                    if similar_to_domain(&target, popular) > 0.8 {
                        return HomographResult {
                            is_homograph: true,
                            target: Some(popular.clone()),
                            punycode: None,
                            deceptive_chars,
                            confidence: 0.85,
                        };
                    }
                }
            }

            return HomographResult {
                is_homograph: false,
                target: None,
                punycode: None,
                deceptive_chars: Vec::new(),
                confidence: 0.0,
            };
        }

        // Domain contains punycode, decode and analyze
        let decoded = decode_punycode_domain(domain);

        if let Some(decoded_domain) = decoded {
            let mut deceptive_chars = Vec::new();

            for c in decoded_domain.chars() {
                for &(visual, actual) in &self.homoglyphs {
                    if c == visual {
                        deceptive_chars.push((visual, actual));
                    }
                }
            }

            if !deceptive_chars.is_empty() {
                let target = reconstruct_ascii_domain(&decoded_domain, &deceptive_chars);

                for popular in &self.popular_domains {
                    if similar_to_domain(&target, popular) > 0.8 {
                        return HomographResult {
                            is_homograph: true,
                            target: Some(popular.clone()),
                            punycode: Some(domain.to_string()),
                            deceptive_chars,
                            confidence: 0.9,
                        };
                    }
                }
            }
        }

        HomographResult {
            is_homograph: false,
            target: None,
            punycode: None,
            deceptive_chars: Vec::new(),
            confidence: 0.0,
        }
    }

    /// Add a domain to the malicious list
    pub fn add_malicious_domain(&mut self, domain: &str) {
        self.malicious_domains.insert(domain.to_lowercase());
    }

    /// Add a domain to the phishing list
    pub fn add_phishing_domain(&mut self, domain: &str) {
        self.phishing_domains.insert(domain.to_lowercase());
    }

    /// Add a domain to the C2 list
    pub fn add_c2_domain(&mut self, domain: &str) {
        self.c2_domains.insert(domain.to_lowercase());
    }

    /// Check if a domain is in any blocklist
    pub fn is_blocklisted(&self, domain: &str) -> bool {
        let domain = domain.to_lowercase();
        self.malicious_domains.contains(&domain)
            || self.phishing_domains.contains(&domain)
            || self.c2_domains.contains(&domain)
    }
}

impl Default for DomainReputation {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Detect type of typosquatting
fn detect_typosquat_type(domain: &str, target: &str) -> Option<(TyposquatType, f64)> {
    let domain_chars: Vec<char> = domain.chars().collect();
    let target_chars: Vec<char> = target.chars().collect();

    // Check length differences
    let len_diff = (domain_chars.len() as i32 - target_chars.len() as i32).abs();

    // Omission: one character missing
    if len_diff == 1 && domain_chars.len() < target_chars.len() {
        let similarity = calculate_similarity(domain, target);
        if similarity > 0.8 {
            return Some((TyposquatType::Omission, similarity));
        }
    }

    // Insertion: one character added
    if len_diff == 1 && domain_chars.len() > target_chars.len() {
        let similarity = calculate_similarity(domain, target);
        if similarity > 0.8 {
            return Some((TyposquatType::Insertion, similarity));
        }
    }

    // Repetition: one character repeated
    if len_diff == 1 && domain_chars.len() > target_chars.len() {
        // Check for repeated adjacent characters
        for i in 0..domain_chars.len().saturating_sub(1) {
            if domain_chars[i] == domain_chars.get(i + 1).copied().unwrap_or(' ') {
                let without_repeat: String = domain_chars
                    .iter()
                    .enumerate()
                    .filter(|(j, _)| *j != i + 1)
                    .map(|(_, c)| c)
                    .collect();
                if without_repeat == target {
                    return Some((TyposquatType::Repetition, 0.9));
                }
            }
        }
    }

    // Same length - check transposition or replacement
    if len_diff == 0 {
        let mut differences = 0;
        let mut diff_positions = Vec::new();

        for i in 0..domain_chars.len().min(target_chars.len()) {
            if domain_chars[i] != target_chars[i] {
                differences += 1;
                diff_positions.push(i);
            }
        }

        // Single character replacement
        if differences == 1 {
            return Some((TyposquatType::Replacement, 0.85));
        }

        // Transposition (adjacent characters swapped)
        if differences == 2 && diff_positions.len() == 2 {
            let (a, b) = (diff_positions[0], diff_positions[1]);
            if b == a + 1 {
                if domain_chars[a] == target_chars[b] && domain_chars[b] == target_chars[a] {
                    return Some((TyposquatType::Transposition, 0.9));
                }
            }
        }
    }

    // Check for hyphenation
    if domain.contains('-') && !target.contains('-') {
        let without_hyphens: String = domain.chars().filter(|c| *c != '-').collect();
        if without_hyphens == target {
            return Some((TyposquatType::Hyphenation, 0.8));
        }
    }

    // Check for homoglyphs (0 for o, 1 for l, etc.)
    let homoglyph_pairs = [
        ('0', 'o'),
        ('1', 'l'),
        ('1', 'i'),
        ('3', 'e'),
        ('4', 'a'),
        ('5', 's'),
        ('8', 'b'),
    ];

    let mut replaced = domain.to_string();
    for (fake, real) in homoglyph_pairs {
        replaced = replaced.replace(fake, &real.to_string());
    }

    if replaced == target {
        return Some((TyposquatType::Homoglyph, 0.85));
    }

    // Calculate general similarity
    let similarity = calculate_similarity(domain, target);
    if similarity > 0.75 {
        return Some((TyposquatType::Replacement, similarity));
    }

    None
}

/// Calculate string similarity (Levenshtein-based)
fn calculate_similarity(a: &str, b: &str) -> f64 {
    let distance = levenshtein_distance(a, b);
    let max_len = a.len().max(b.len());
    if max_len == 0 {
        return 1.0;
    }
    1.0 - (distance as f64 / max_len as f64)
}

/// Calculate Levenshtein distance
fn levenshtein_distance(a: &str, b: &str) -> usize {
    let a_chars: Vec<char> = a.chars().collect();
    let b_chars: Vec<char> = b.chars().collect();

    let mut matrix = vec![vec![0; b_chars.len() + 1]; a_chars.len() + 1];

    for i in 0..=a_chars.len() {
        matrix[i][0] = i;
    }
    for j in 0..=b_chars.len() {
        matrix[0][j] = j;
    }

    for i in 1..=a_chars.len() {
        for j in 1..=b_chars.len() {
            let cost = if a_chars[i - 1] == b_chars[j - 1] {
                0
            } else {
                1
            };

            matrix[i][j] = (matrix[i - 1][j] + 1)
                .min(matrix[i][j - 1] + 1)
                .min(matrix[i - 1][j - 1] + cost);
        }
    }

    matrix[a_chars.len()][b_chars.len()]
}

/// Check if domain uses a suspicious TLD
fn is_suspicious_tld(domain: &str) -> bool {
    let suspicious_tlds = [
        ".tk", ".ml", ".ga", ".cf", ".gq", // Free TLDs often abused
        ".xyz", ".top", ".icu", ".buzz", // Cheap TLDs often abused
        ".ru", // Sometimes suspicious (depends on context)
        ".cn", // Sometimes suspicious (depends on context)
    ];

    let domain_lower = domain.to_lowercase();
    suspicious_tlds.iter().any(|tld| domain_lower.ends_with(tld))
}

/// Similar to domain (basic check)
fn similar_to_domain(domain: &str, target: &str) -> f64 {
    calculate_similarity(domain, target)
}

/// Decode punycode domain (simplified)
fn decode_punycode_domain(domain: &str) -> Option<String> {
    // This is a simplified implementation
    // In production, use the `idna` crate for proper decoding
    if !domain.contains("xn--") {
        return Some(domain.to_string());
    }

    // For now, just return the domain as-is
    // A full implementation would decode punycode segments
    Some(domain.to_string())
}

/// Reconstruct ASCII domain from homograph
fn reconstruct_ascii_domain(domain: &str, deceptive_chars: &[(char, char)]) -> String {
    let mut result = domain.to_string();
    for &(visual, actual) in deceptive_chars {
        result = result.replace(visual, &actual.to_string());
    }
    result
}

/// Build known malicious domain list
fn build_malicious_domain_list() -> HashSet<String> {
    // This is a small sample - in production, this would be loaded from threat intel feeds
    let domains = [
        "malware-distribution.com",
        "evil-downloads.net",
        "trojan-host.org",
        "ransomware-c2.com",
        "botnet-master.net",
    ];
    domains.iter().map(|s| s.to_string()).collect()
}

/// Build known phishing domain list
fn build_phishing_domain_list() -> HashSet<String> {
    let domains = [
        "login-secure-bank.com",
        "paypal-verify.net",
        "apple-id-reset.com",
        "microsoft-365-login.net",
        "amazon-account-verify.com",
    ];
    domains.iter().map(|s| s.to_string()).collect()
}

/// Build known C2 domain list
fn build_c2_domain_list() -> HashSet<String> {
    let domains = [
        "c2-server.onion",
        "command-control.xyz",
        "beacon-host.net",
        "callback-server.com",
    ];
    domains.iter().map(|s| s.to_string()).collect()
}

/// Build popular domains for typosquatting detection
fn build_popular_domain_list() -> Vec<String> {
    vec![
        "google.com".to_string(),
        "facebook.com".to_string(),
        "amazon.com".to_string(),
        "apple.com".to_string(),
        "microsoft.com".to_string(),
        "paypal.com".to_string(),
        "netflix.com".to_string(),
        "instagram.com".to_string(),
        "linkedin.com".to_string(),
        "twitter.com".to_string(),
        "youtube.com".to_string(),
        "github.com".to_string(),
        "dropbox.com".to_string(),
        "spotify.com".to_string(),
        "uber.com".to_string(),
        "ebay.com".to_string(),
        "walmart.com".to_string(),
        "target.com".to_string(),
        "chase.com".to_string(),
        "wellsfargo.com".to_string(),
        "bankofamerica.com".to_string(),
        "yahoo.com".to_string(),
        "outlook.com".to_string(),
        "icloud.com".to_string(),
        "zoom.us".to_string(),
        "slack.com".to_string(),
        "office.com".to_string(),
    ]
}

/// Build homoglyph character mappings
fn build_homoglyph_mappings() -> Vec<(char, char)> {
    vec![
        // Cyrillic lookalikes
        ('\u{0430}', 'a'), // Cyrillic а -> Latin a
        ('\u{0435}', 'e'), // Cyrillic е -> Latin e
        ('\u{043e}', 'o'), // Cyrillic о -> Latin o
        ('\u{0440}', 'p'), // Cyrillic р -> Latin p
        ('\u{0441}', 'c'), // Cyrillic с -> Latin c
        ('\u{0443}', 'y'), // Cyrillic у -> Latin y
        ('\u{0445}', 'x'), // Cyrillic х -> Latin x
        // Greek lookalikes
        ('\u{03B1}', 'a'), // Greek α -> Latin a
        ('\u{03BF}', 'o'), // Greek ο -> Latin o
        // Number/letter confusion
        ('0', 'o'),
        ('1', 'l'),
        ('1', 'i'),
        // Special characters
        ('\u{00ED}', 'i'), // í -> i
        ('\u{00F3}', 'o'), // ó -> o
        ('\u{00E1}', 'a'), // á -> a
        ('\u{00E9}', 'e'), // é -> e
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reputation_clean_domain() {
        let checker = DomainReputation::new();
        let result = checker.check("example.com");
        assert!(result.is_clean);
    }

    #[test]
    fn test_reputation_malicious_domain() {
        let checker = DomainReputation::new();
        let result = checker.check("malware-distribution.com");
        assert!(!result.is_clean);
        assert!(result.categories.contains(&ReputationCategory::Malware));
    }

    #[test]
    fn test_typosquatting_detection() {
        let checker = DomainReputation::new();

        // Test omission
        let result = checker.check_typosquatting("gogle.com");
        assert!(result.is_typosquat);
        assert!(result.target.as_ref().unwrap().contains("google"));

        // Test replacement
        let result = checker.check_typosquatting("g00gle.com");
        assert!(result.is_typosquat);
    }

    #[test]
    fn test_levenshtein_distance() {
        assert_eq!(levenshtein_distance("hello", "hello"), 0);
        assert_eq!(levenshtein_distance("hello", "helo"), 1);
        assert_eq!(levenshtein_distance("hello", "world"), 4);
    }

    #[test]
    fn test_calculate_similarity() {
        assert!(calculate_similarity("google", "google") > 0.99);
        assert!(calculate_similarity("google", "gogle") > 0.8);
        assert!(calculate_similarity("google", "xyz") < 0.3);
    }

    #[test]
    fn test_suspicious_tld() {
        assert!(is_suspicious_tld("evil.tk"));
        assert!(is_suspicious_tld("phish.xyz"));
        assert!(!is_suspicious_tld("legitimate.com"));
    }

    #[test]
    fn test_homograph_detection() {
        let checker = DomainReputation::new();
        // Note: This would require actual Unicode characters for full testing
        let result = checker.check_homograph("google.com");
        assert!(!result.is_homograph);
    }
}
