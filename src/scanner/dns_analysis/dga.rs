//! Domain Generation Algorithm (DGA) Detection
//!
//! This module provides detection capabilities for DGA-generated domains using:
//! - Entropy-based detection (high entropy = likely DGA)
//! - N-gram analysis (unusual character sequences)
//! - Dictionary word ratio (DGA domains lack real words)
//! - Length analysis (DGA domains often have consistent lengths)
//! - Known DGA patterns (specific malware family patterns)
//! - Markov chain probability scoring

#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

// =============================================================================
// Types
// =============================================================================

/// Result of DGA detection analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DgaResult {
    /// Whether the domain is likely a DGA domain
    pub is_dga: bool,
    /// Overall confidence score (0.0 - 1.0)
    pub confidence: f64,
    /// Individual scores from different detection methods
    pub scores: DgaScore,
    /// Entropy of the domain
    pub entropy: f64,
    /// N-gram score
    pub ngram_score: f64,
    /// Dictionary word ratio (0.0 = no dictionary words, 1.0 = all dictionary words)
    pub dictionary_ratio: f64,
    /// Reason for classification
    pub reason: String,
    /// Potential malware family if pattern matches
    pub malware_family: Option<String>,
}

/// Individual scores from DGA detection methods
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DgaScore {
    /// Entropy score (higher = more random)
    pub entropy_score: f64,
    /// N-gram score (lower = more unusual)
    pub ngram_score: f64,
    /// Dictionary score (higher = more dictionary words)
    pub dictionary_score: f64,
    /// Length score (based on typical DGA lengths)
    pub length_score: f64,
    /// Consonant ratio score (DGA often has unusual ratios)
    pub consonant_score: f64,
    /// Vowel ratio score
    pub vowel_score: f64,
    /// Digit ratio score (DGA often contains digits)
    pub digit_score: f64,
    /// Markov chain probability score
    pub markov_score: f64,
    /// Pattern match score (known DGA patterns)
    pub pattern_score: f64,
}

// =============================================================================
// DGA Detector
// =============================================================================

/// DGA detection engine
pub struct DgaDetector {
    /// N-gram frequency data for English domains
    ngram_frequencies: HashMap<String, f64>,
    /// Common dictionary words
    dictionary: HashSet<String>,
    /// Known DGA patterns
    dga_patterns: Vec<DgaPattern>,
    /// Markov chain transition probabilities
    markov_probs: HashMap<(char, char), f64>,
    /// Configuration
    config: DgaDetectorConfig,
}

/// Configuration for DGA detector
#[derive(Debug, Clone)]
pub struct DgaDetectorConfig {
    /// Minimum entropy to consider suspicious (default: 3.5)
    pub entropy_threshold: f64,
    /// Maximum dictionary ratio for DGA (default: 0.3)
    pub dictionary_threshold: f64,
    /// Minimum domain length to analyze (default: 5)
    pub min_length: usize,
    /// Weights for combining scores
    pub weights: DgaWeights,
}

/// Weights for combining DGA detection scores
#[derive(Debug, Clone)]
pub struct DgaWeights {
    pub entropy: f64,
    pub ngram: f64,
    pub dictionary: f64,
    pub length: f64,
    pub consonant: f64,
    pub markov: f64,
    pub pattern: f64,
}

impl Default for DgaWeights {
    fn default() -> Self {
        Self {
            entropy: 0.25,
            ngram: 0.20,
            dictionary: 0.20,
            length: 0.05,
            consonant: 0.10,
            markov: 0.15,
            pattern: 0.05,
        }
    }
}

impl Default for DgaDetectorConfig {
    fn default() -> Self {
        Self {
            entropy_threshold: 3.5,
            dictionary_threshold: 0.3,
            min_length: 5,
            weights: DgaWeights::default(),
        }
    }
}

/// Known DGA pattern
#[derive(Debug, Clone)]
struct DgaPattern {
    /// Name of the malware family
    name: String,
    /// Regex pattern to match
    pattern: regex::Regex,
    /// Typical length range
    length_range: (usize, usize),
    /// Uses only hex characters
    hex_only: bool,
    /// Contains specific character sequences
    sequences: Vec<String>,
}

impl DgaDetector {
    /// Create a new DGA detector with default configuration
    pub fn new() -> Self {
        Self::with_config(DgaDetectorConfig::default())
    }

    /// Create a new DGA detector with custom configuration
    pub fn with_config(config: DgaDetectorConfig) -> Self {
        Self {
            ngram_frequencies: build_ngram_frequencies(),
            dictionary: build_dictionary(),
            dga_patterns: build_dga_patterns(),
            markov_probs: build_markov_probabilities(),
            config,
        }
    }

    /// Analyze a domain for DGA characteristics
    pub fn detect(&self, domain: &str) -> DgaResult {
        let domain = extract_sld(domain).to_lowercase();

        // Skip very short domains
        if domain.len() < self.config.min_length {
            return DgaResult {
                is_dga: false,
                confidence: 0.0,
                scores: DgaScore::default(),
                entropy: 0.0,
                ngram_score: 0.0,
                dictionary_ratio: 1.0,
                reason: "Domain too short for analysis".to_string(),
                malware_family: None,
            };
        }

        let mut scores = DgaScore::default();

        // 1. Entropy analysis
        let entropy = calculate_entropy(&domain);
        scores.entropy_score = normalize_entropy_score(entropy);

        // 2. N-gram analysis
        let ngram_score = self.calculate_ngram_score(&domain);
        scores.ngram_score = ngram_score;

        // 3. Dictionary word ratio
        let dictionary_ratio = self.calculate_dictionary_ratio(&domain);
        scores.dictionary_score = 1.0 - dictionary_ratio; // Invert so lower ratio = higher score

        // 4. Length analysis
        scores.length_score = calculate_length_score(domain.len());

        // 5. Character ratio analysis
        let (consonant_ratio, vowel_ratio, digit_ratio) = calculate_char_ratios(&domain);
        scores.consonant_score = normalize_consonant_score(consonant_ratio);
        scores.vowel_score = normalize_vowel_score(vowel_ratio);
        scores.digit_score = if digit_ratio > 0.0 { 0.3 + digit_ratio * 0.7 } else { 0.0 };

        // 6. Markov chain analysis
        scores.markov_score = self.calculate_markov_score(&domain);

        // 7. Pattern matching
        let (pattern_score, malware_family) = self.check_dga_patterns(&domain);
        scores.pattern_score = pattern_score;

        // Calculate weighted final score
        let weights = &self.config.weights;
        let final_score = scores.entropy_score * weights.entropy
            + (1.0 - scores.ngram_score) * weights.ngram
            + scores.dictionary_score * weights.dictionary
            + scores.length_score * weights.length
            + scores.consonant_score * weights.consonant
            + scores.markov_score * weights.markov
            + scores.pattern_score * weights.pattern;

        // Determine if DGA
        let is_dga = final_score > 0.55
            && (entropy > self.config.entropy_threshold
                || dictionary_ratio < self.config.dictionary_threshold
                || pattern_score > 0.5);

        // Generate reason
        let reason = generate_reason(&scores, entropy, dictionary_ratio, &malware_family);

        DgaResult {
            is_dga,
            confidence: final_score.min(1.0),
            scores,
            entropy,
            ngram_score,
            dictionary_ratio,
            reason,
            malware_family,
        }
    }

    /// Calculate n-gram score for a domain
    fn calculate_ngram_score(&self, domain: &str) -> f64 {
        if domain.len() < 2 {
            return 0.5;
        }

        let mut total_score = 0.0;
        let mut count = 0;

        // Check bigrams
        for i in 0..domain.len() - 1 {
            let bigram: String = domain.chars().skip(i).take(2).collect();
            if let Some(&freq) = self.ngram_frequencies.get(&bigram) {
                total_score += freq;
                count += 1;
            }
        }

        // Check trigrams
        for i in 0..domain.len().saturating_sub(2) {
            let trigram: String = domain.chars().skip(i).take(3).collect();
            if let Some(&freq) = self.ngram_frequencies.get(&trigram) {
                total_score += freq;
                count += 1;
            }
        }

        if count > 0 {
            (total_score / count as f64).min(1.0)
        } else {
            0.0 // No matching n-grams = suspicious
        }
    }

    /// Calculate dictionary word ratio
    fn calculate_dictionary_ratio(&self, domain: &str) -> f64 {
        if domain.len() < 3 {
            return 0.0;
        }

        let mut matched_chars = 0;

        // Try to find dictionary words in the domain
        for word in &self.dictionary {
            if word.len() >= 3 && domain.contains(word.as_str()) {
                matched_chars += word.len();
            }
        }

        // Also check for the entire domain as a word
        if self.dictionary.contains(domain) {
            return 1.0;
        }

        let ratio = matched_chars as f64 / domain.len() as f64;
        ratio.min(1.0)
    }

    /// Calculate Markov chain probability score
    fn calculate_markov_score(&self, domain: &str) -> f64 {
        if domain.len() < 2 {
            return 0.5;
        }

        let chars: Vec<char> = domain.chars().collect();
        let mut log_prob = 0.0;
        let mut transitions = 0;

        for i in 0..chars.len() - 1 {
            let key = (chars[i], chars[i + 1]);
            if let Some(&prob) = self.markov_probs.get(&key) {
                log_prob += prob.ln();
                transitions += 1;
            } else {
                // Unknown transition = very unlikely
                log_prob += (-10.0_f64).ln();
                transitions += 1;
            }
        }

        if transitions == 0 {
            return 0.5;
        }

        // Normalize: higher (less negative) = more normal
        let avg_log_prob = log_prob / transitions as f64;
        // Convert to 0-1 scale where lower probability = higher DGA score
        let normalized = (1.0 - (avg_log_prob / -10.0).max(0.0)).max(0.0).min(1.0);
        normalized
    }

    /// Check against known DGA patterns
    fn check_dga_patterns(&self, domain: &str) -> (f64, Option<String>) {
        for pattern in &self.dga_patterns {
            if pattern.pattern.is_match(domain) {
                // Check length constraint
                if domain.len() >= pattern.length_range.0
                    && domain.len() <= pattern.length_range.1
                {
                    return (0.9, Some(pattern.name.clone()));
                } else {
                    return (0.5, Some(pattern.name.clone()));
                }
            }

            // Check hex-only for certain patterns
            if pattern.hex_only && is_hex_string(domain) {
                return (0.7, Some(format!("{} (hex)", pattern.name)));
            }
        }

        (0.0, None)
    }
}

impl Default for DgaDetector {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Calculate Shannon entropy of a string
pub fn calculate_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }

    let mut char_counts: HashMap<char, usize> = HashMap::new();
    for c in s.chars() {
        *char_counts.entry(c).or_insert(0) += 1;
    }

    let len = s.len() as f64;
    let mut entropy = 0.0;

    for &count in char_counts.values() {
        let p = count as f64 / len;
        if p > 0.0 {
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// Extract second-level domain from FQDN
fn extract_sld(domain: &str) -> &str {
    let domain = domain.trim_end_matches('.');
    let parts: Vec<&str> = domain.split('.').collect();

    if parts.is_empty() {
        return domain;
    }

    if parts.len() == 1 {
        return parts[0];
    }

    // Handle common multi-part TLDs (e.g., .co.uk, .com.au)
    let common_second_level = ["co", "com", "org", "net", "gov", "edu", "ac"];
    if parts.len() >= 3
        && common_second_level.contains(&parts[parts.len() - 2])
        && parts[parts.len() - 1].len() == 2
    {
        return parts[parts.len() - 3];
    }

    // Return the part before the TLD
    parts[parts.len() - 2]
}

/// Normalize entropy score to 0-1 range
fn normalize_entropy_score(entropy: f64) -> f64 {
    // Normal domains typically have entropy 2.5-3.5
    // DGA domains typically have entropy 3.5-4.5+
    if entropy < 2.5 {
        0.0
    } else if entropy > 4.5 {
        1.0
    } else {
        (entropy - 2.5) / 2.0
    }
}

/// Calculate length-based score
fn calculate_length_score(len: usize) -> f64 {
    // Many DGA domains are 12-16 characters
    match len {
        12..=16 => 0.6,
        17..=25 => 0.8,
        26..=40 => 0.9,
        41.. => 1.0,
        8..=11 => 0.3,
        _ => 0.1,
    }
}

/// Calculate character ratios
fn calculate_char_ratios(s: &str) -> (f64, f64, f64) {
    let vowels = "aeiou";
    let consonants = "bcdfghjklmnpqrstvwxyz";

    let mut vowel_count = 0;
    let mut consonant_count = 0;
    let mut digit_count = 0;
    let total = s.len() as f64;

    for c in s.chars() {
        if vowels.contains(c) {
            vowel_count += 1;
        } else if consonants.contains(c) {
            consonant_count += 1;
        } else if c.is_ascii_digit() {
            digit_count += 1;
        }
    }

    (
        consonant_count as f64 / total,
        vowel_count as f64 / total,
        digit_count as f64 / total,
    )
}

/// Normalize consonant ratio score
fn normalize_consonant_score(ratio: f64) -> f64 {
    // Normal English has about 60% consonants
    // DGA often has 70%+ or unusual distributions
    if ratio > 0.8 {
        1.0
    } else if ratio > 0.7 {
        0.7
    } else if ratio < 0.4 {
        0.5
    } else {
        0.2
    }
}

/// Normalize vowel ratio score
fn normalize_vowel_score(ratio: f64) -> f64 {
    // Normal English has about 40% vowels
    if ratio < 0.1 {
        1.0
    } else if ratio < 0.2 {
        0.7
    } else if ratio > 0.5 {
        0.5
    } else {
        0.2
    }
}

/// Check if string is only hex characters
fn is_hex_string(s: &str) -> bool {
    s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Generate human-readable reason for classification
fn generate_reason(
    scores: &DgaScore,
    entropy: f64,
    dictionary_ratio: f64,
    malware_family: &Option<String>,
) -> String {
    let mut reasons = Vec::new();

    if let Some(family) = malware_family {
        reasons.push(format!("Matches {} DGA pattern", family));
    }

    if entropy > 4.0 {
        reasons.push(format!("Very high entropy ({:.2})", entropy));
    } else if entropy > 3.5 {
        reasons.push(format!("High entropy ({:.2})", entropy));
    }

    if dictionary_ratio < 0.1 {
        reasons.push("No dictionary words found".to_string());
    } else if dictionary_ratio < 0.3 {
        reasons.push("Few dictionary words".to_string());
    }

    if scores.ngram_score < 0.2 {
        reasons.push("Unusual character sequences".to_string());
    }

    if scores.consonant_score > 0.7 {
        reasons.push("Abnormal consonant ratio".to_string());
    }

    if scores.digit_score > 0.5 {
        reasons.push("Contains many digits".to_string());
    }

    if reasons.is_empty() {
        "Low confidence detection".to_string()
    } else {
        reasons.join("; ")
    }
}

/// Build n-gram frequency table for common domains
fn build_ngram_frequencies() -> HashMap<String, f64> {
    let mut freqs = HashMap::new();

    // Common bigrams in English domains
    let bigrams = [
        ("th", 0.9), ("he", 0.85), ("in", 0.8), ("er", 0.8), ("an", 0.75),
        ("re", 0.75), ("on", 0.7), ("en", 0.7), ("at", 0.7), ("es", 0.7),
        ("or", 0.65), ("te", 0.65), ("ti", 0.65), ("al", 0.6), ("ar", 0.6),
        ("le", 0.6), ("se", 0.55), ("to", 0.55), ("me", 0.55), ("ne", 0.55),
        ("de", 0.5), ("co", 0.5), ("ma", 0.5), ("st", 0.5), ("io", 0.5),
        ("ng", 0.45), ("is", 0.45), ("it", 0.45), ("ou", 0.45), ("nt", 0.45),
        ("ro", 0.4), ("ed", 0.4), ("ha", 0.4), ("ve", 0.4), ("as", 0.4),
    ];

    for (gram, freq) in bigrams {
        freqs.insert(gram.to_string(), freq);
    }

    // Common trigrams
    let trigrams = [
        ("the", 0.9), ("and", 0.85), ("ing", 0.8), ("ion", 0.75), ("ent", 0.7),
        ("for", 0.7), ("tio", 0.65), ("ere", 0.65), ("her", 0.6), ("ate", 0.6),
        ("ter", 0.55), ("com", 0.55), ("hat", 0.5), ("tha", 0.5), ("ith", 0.5),
        ("all", 0.45), ("eth", 0.45), ("ver", 0.45), ("his", 0.4), ("oft", 0.4),
    ];

    for (gram, freq) in trigrams {
        freqs.insert(gram.to_string(), freq);
    }

    freqs
}

/// Build common dictionary word set
fn build_dictionary() -> HashSet<String> {
    let words = [
        // Common domain words
        "web", "mail", "shop", "store", "news", "blog", "tech", "cloud",
        "data", "info", "site", "page", "home", "online", "digital",
        "media", "network", "server", "host", "link", "connect", "secure",
        "global", "world", "group", "team", "corp", "company", "business",
        // Common prefixes/suffixes
        "pro", "max", "plus", "hub", "lab", "dev", "app", "net", "sys",
        "soft", "ware", "tech", "smart", "fast", "quick", "easy", "simple",
        // Common words
        "the", "and", "for", "with", "that", "this", "from", "have", "are",
        "not", "but", "can", "all", "was", "one", "our", "your", "their",
        "will", "more", "when", "what", "how", "get", "new", "best", "free",
        // Tech terms
        "api", "cdn", "ssl", "vpn", "dns", "sql", "http", "https", "ftp",
        // Common TLDs as words
        "com", "org", "net", "edu", "gov", "biz", "info",
    ];

    words.iter().map(|s| s.to_string()).collect()
}

/// Build known DGA patterns
fn build_dga_patterns() -> Vec<DgaPattern> {
    vec![
        DgaPattern {
            name: "Conficker".to_string(),
            pattern: regex::Regex::new(r"^[a-z]{5,12}$").unwrap(),
            length_range: (5, 12),
            hex_only: false,
            sequences: vec![],
        },
        DgaPattern {
            name: "Cryptolocker".to_string(),
            pattern: regex::Regex::new(r"^[a-z]{15,20}$").unwrap(),
            length_range: (15, 20),
            hex_only: false,
            sequences: vec![],
        },
        DgaPattern {
            name: "Necurs".to_string(),
            pattern: regex::Regex::new(r"^[a-z0-9]{16,24}$").unwrap(),
            length_range: (16, 24),
            hex_only: false,
            sequences: vec![],
        },
        DgaPattern {
            name: "Qakbot".to_string(),
            pattern: regex::Regex::new(r"^[a-z]{6,10}[0-9]{1,4}$").unwrap(),
            length_range: (7, 14),
            hex_only: false,
            sequences: vec![],
        },
        DgaPattern {
            name: "Bamital".to_string(),
            pattern: regex::Regex::new(r"^[a-f0-9]{32}$").unwrap(),
            length_range: (32, 32),
            hex_only: true,
            sequences: vec![],
        },
        DgaPattern {
            name: "Suppobox".to_string(),
            pattern: regex::Regex::new(r"^[a-z]{8,16}[0-9]{2,4}$").unwrap(),
            length_range: (10, 20),
            hex_only: false,
            sequences: vec![],
        },
    ]
}

/// Build Markov chain transition probabilities
fn build_markov_probabilities() -> HashMap<(char, char), f64> {
    let mut probs = HashMap::new();

    // Common character transitions in English
    let transitions = [
        (('t', 'h'), 0.15), (('h', 'e'), 0.12), (('e', 'r'), 0.08),
        (('a', 'n'), 0.07), (('i', 'n'), 0.07), (('n', 'g'), 0.06),
        (('o', 'n'), 0.05), (('e', 'n'), 0.05), (('e', 's'), 0.05),
        (('a', 't'), 0.05), (('o', 'r'), 0.04), (('t', 'i'), 0.04),
        (('a', 'l'), 0.04), (('i', 'o'), 0.04), (('s', 't'), 0.04),
        (('l', 'e'), 0.03), (('s', 'e'), 0.03), (('r', 'e'), 0.03),
        (('m', 'e'), 0.03), (('n', 'e'), 0.03), (('a', 'r'), 0.03),
        (('c', 'o'), 0.03), (('m', 'a'), 0.03), (('i', 't'), 0.03),
        (('d', 'e'), 0.02), (('r', 'o'), 0.02), (('t', 'e'), 0.02),
        (('e', 'd'), 0.02), (('h', 'a'), 0.02), (('v', 'e'), 0.02),
        (('i', 's'), 0.02), (('o', 'u'), 0.02), (('n', 't'), 0.02),
        (('c', 'h'), 0.02), (('w', 'i'), 0.02), (('w', 'e'), 0.02),
    ];

    for ((a, b), prob) in transitions {
        probs.insert((a, b), prob);
    }

    // Add default low probabilities for common letters
    let letters: Vec<char> = "abcdefghijklmnopqrstuvwxyz0123456789".chars().collect();
    for &a in &letters {
        for &b in &letters {
            probs.entry((a, b)).or_insert(0.001);
        }
    }

    probs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_calculation() {
        // Equal distribution = max entropy for that alphabet size
        let entropy = calculate_entropy("abcd");
        assert!(entropy > 1.9 && entropy < 2.1);

        // Single character = 0 entropy
        let entropy = calculate_entropy("aaaa");
        assert!(entropy < 0.01);

        // Random-looking string = high entropy
        let entropy = calculate_entropy("x8k2m9p4q7");
        assert!(entropy > 3.0);
    }

    #[test]
    fn test_extract_sld() {
        assert_eq!(extract_sld("www.example.com"), "example");
        assert_eq!(extract_sld("example.com"), "example");
        assert_eq!(extract_sld("sub.domain.example.co.uk"), "example");
    }

    #[test]
    fn test_detect_normal_domain() {
        let detector = DgaDetector::new();
        let result = detector.detect("google.com");
        assert!(!result.is_dga || result.confidence < 0.5);
    }

    #[test]
    fn test_detect_suspicious_domain() {
        let detector = DgaDetector::new();
        // Typical DGA-looking domain
        let result = detector.detect("qxzwvjkpmn123.com");
        // Should have high entropy at least
        assert!(result.entropy > 3.0);
    }

    #[test]
    fn test_detect_hex_domain() {
        let detector = DgaDetector::new();
        let result = detector.detect("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6.com");
        assert!(result.entropy > 3.5);
    }

    #[test]
    fn test_char_ratios() {
        let (consonant, vowel, digit) = calculate_char_ratios("hello");
        assert!(consonant > 0.5);
        assert!(vowel > 0.3);
        assert!(digit < 0.01);

        let (_, _, digit) = calculate_char_ratios("abc123");
        assert!(digit > 0.4);
    }

    #[test]
    fn test_is_hex_string() {
        assert!(is_hex_string("abcdef123456"));
        assert!(!is_hex_string("abcdefg"));
        assert!(!is_hex_string("xyz123"));
    }
}
