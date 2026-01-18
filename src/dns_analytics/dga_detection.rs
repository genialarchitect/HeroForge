//! DGA (Domain Generation Algorithm) Detection
//!
//! Detects algorithmically generated domains using multiple heuristics:
//! - Shannon entropy analysis
//! - Character distribution analysis
//! - N-gram frequency analysis
//! - Dictionary word matching
//! - Length analysis

use std::collections::{HashMap, HashSet};
use super::types::{DgaAnalysis, DgaConfidence};

/// Configuration for DGA detection
#[derive(Debug, Clone)]
pub struct DgaConfig {
    /// Entropy threshold for flagging domains (default: 3.5)
    pub entropy_threshold: f64,
    /// Minimum domain length to analyze (default: 6)
    pub min_length: usize,
    /// Maximum consonant ratio before flagging (default: 0.7)
    pub max_consonant_ratio: f64,
}

impl Default for DgaConfig {
    fn default() -> Self {
        Self {
            entropy_threshold: 3.5,
            min_length: 6,
            max_consonant_ratio: 0.7,
        }
    }
}

/// Known DGA families and their characteristics
#[derive(Debug, Clone)]
pub struct DgaFamily {
    pub name: String,
    pub min_length: usize,
    pub max_length: usize,
    pub charset: String,
    pub tlds: Vec<String>,
    pub entropy_range: (f64, f64),
}

/// DGA detector with configurable thresholds
pub struct DgaDetector {
    /// Entropy threshold for flagging domains
    pub entropy_threshold: f64,
    /// Minimum domain length to analyze
    pub min_length: usize,
    /// Maximum consonant ratio before flagging
    pub max_consonant_ratio: f64,
    /// Common English bigrams for scoring
    common_bigrams: HashSet<String>,
    /// Common English trigrams for scoring
    common_trigrams: HashSet<String>,
    /// Common dictionary words
    dictionary_words: HashSet<String>,
    /// Known legitimate high-entropy domains (CDNs, etc.)
    whitelist: HashSet<String>,
    /// Known DGA families
    dga_families: Vec<DgaFamily>,
}

impl Default for DgaDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl DgaDetector {
    pub fn new() -> Self {
        Self::with_config(DgaConfig::default())
    }

    /// Create a new DgaDetector with custom configuration
    pub fn with_config(config: DgaConfig) -> Self {
        Self {
            entropy_threshold: config.entropy_threshold,
            min_length: config.min_length,
            max_consonant_ratio: config.max_consonant_ratio,
            common_bigrams: Self::load_common_bigrams(),
            common_trigrams: Self::load_common_trigrams(),
            dictionary_words: Self::load_dictionary_words(),
            whitelist: Self::load_whitelist(),
            dga_families: Self::load_dga_families(),
        }
    }

    /// Analyze a domain for DGA characteristics
    pub fn analyze(&self, domain: &str) -> DgaAnalysis {
        let domain_lower = domain.to_lowercase();
        let (sld, tld) = self.extract_sld_tld(&domain_lower);

        // Skip whitelisted domains
        if self.is_whitelisted(&domain_lower) {
            return DgaAnalysis {
                domain: domain.to_string(),
                is_dga: false,
                probability: 0.0,
                entropy: self.calculate_entropy(&sld),
                consonant_ratio: self.calculate_consonant_ratio(&sld),
                digit_ratio: self.calculate_digit_ratio(&sld),
                length_score: 0.0,
                ngram_score: 1.0,
                dictionary_score: 1.0,
                tld: tld.to_string(),
                detected_family: None,
                confidence: DgaConfidence::Low,
            };
        }

        // Calculate various metrics
        let entropy = self.calculate_entropy(&sld);
        let consonant_ratio = self.calculate_consonant_ratio(&sld);
        let digit_ratio = self.calculate_digit_ratio(&sld);
        let length_score = self.calculate_length_score(&sld);
        let ngram_score = self.calculate_ngram_score(&sld);
        let dictionary_score = self.calculate_dictionary_score(&sld);

        // Calculate overall DGA probability
        let (probability, confidence) = self.calculate_dga_probability(
            entropy,
            consonant_ratio,
            digit_ratio,
            length_score,
            ngram_score,
            dictionary_score,
            sld.len(),
        );

        // Try to identify DGA family
        let detected_family = self.identify_dga_family(&sld, &tld, entropy);

        let is_dga = probability >= 0.6;

        DgaAnalysis {
            domain: domain.to_string(),
            is_dga,
            probability,
            entropy,
            consonant_ratio,
            digit_ratio,
            length_score,
            ngram_score,
            dictionary_score,
            tld: tld.to_string(),
            detected_family,
            confidence,
        }
    }

    /// Batch analyze multiple domains
    pub fn analyze_batch(&self, domains: &[String]) -> Vec<DgaAnalysis> {
        domains.iter().map(|d| self.analyze(d)).collect()
    }

    /// Extract second-level domain and TLD
    fn extract_sld_tld<'a>(&self, domain: &'a str) -> (&'a str, &'a str) {
        let parts: Vec<&str> = domain.split('.').collect();
        if parts.len() >= 2 {
            let tld = parts[parts.len() - 1];
            let sld = parts[parts.len() - 2];
            (sld, tld)
        } else {
            (domain, "")
        }
    }

    /// Calculate Shannon entropy of a string
    pub fn calculate_entropy(&self, s: &str) -> f64 {
        if s.is_empty() {
            return 0.0;
        }

        let mut freq: HashMap<char, usize> = HashMap::new();
        for c in s.chars() {
            *freq.entry(c).or_insert(0) += 1;
        }

        let len = s.len() as f64;
        freq.values()
            .map(|&count| {
                let p = count as f64 / len;
                -p * p.log2()
            })
            .sum()
    }

    /// Calculate ratio of consonants to total letters
    fn calculate_consonant_ratio(&self, s: &str) -> f64 {
        let consonants = "bcdfghjklmnpqrstvwxyz";
        let vowels = "aeiou";

        let letter_count: usize = s.chars()
            .filter(|c| c.is_ascii_alphabetic())
            .count();

        if letter_count == 0 {
            return 0.0;
        }

        let consonant_count: usize = s.chars()
            .filter(|c| consonants.contains(*c))
            .count();

        consonant_count as f64 / letter_count as f64
    }

    /// Calculate ratio of digits to total characters
    fn calculate_digit_ratio(&self, s: &str) -> f64 {
        if s.is_empty() {
            return 0.0;
        }

        let digit_count: usize = s.chars().filter(|c| c.is_ascii_digit()).count();
        digit_count as f64 / s.len() as f64
    }

    /// Calculate length-based score (very short or very long domains are suspicious)
    fn calculate_length_score(&self, s: &str) -> f64 {
        let len = s.len();

        // Optimal length range is 5-15 characters
        if len < 5 {
            0.3 // Very short
        } else if len <= 15 {
            1.0 // Normal
        } else if len <= 25 {
            0.7 // Somewhat long
        } else if len <= 40 {
            0.4 // Long
        } else {
            0.2 // Very long (likely tunneling or DGA)
        }
    }

    /// Calculate n-gram frequency score
    fn calculate_ngram_score(&self, s: &str) -> f64 {
        if s.len() < 2 {
            return 0.5;
        }

        let chars: Vec<char> = s.chars().collect();
        let mut bigram_hits = 0;
        let mut trigram_hits = 0;
        let mut bigram_total = 0;
        let mut trigram_total = 0;

        // Check bigrams
        for i in 0..chars.len() - 1 {
            let bigram: String = chars[i..=i+1].iter().collect();
            if bigram.chars().all(|c| c.is_ascii_alphabetic()) {
                bigram_total += 1;
                if self.common_bigrams.contains(&bigram.to_lowercase()) {
                    bigram_hits += 1;
                }
            }
        }

        // Check trigrams
        for i in 0..chars.len().saturating_sub(2) {
            let trigram: String = chars[i..=i+2].iter().collect();
            if trigram.chars().all(|c| c.is_ascii_alphabetic()) {
                trigram_total += 1;
                if self.common_trigrams.contains(&trigram.to_lowercase()) {
                    trigram_hits += 1;
                }
            }
        }

        let bigram_score = if bigram_total > 0 {
            bigram_hits as f64 / bigram_total as f64
        } else {
            0.5
        };

        let trigram_score = if trigram_total > 0 {
            trigram_hits as f64 / trigram_total as f64
        } else {
            0.5
        };

        // Weight trigrams more heavily
        bigram_score * 0.4 + trigram_score * 0.6
    }

    /// Calculate dictionary word match score
    fn calculate_dictionary_score(&self, s: &str) -> f64 {
        let s_lower = s.to_lowercase();

        // Check if entire domain is a dictionary word
        if self.dictionary_words.contains(&s_lower) {
            return 1.0;
        }

        // Check for dictionary word substrings (min 4 chars)
        let mut matched_chars = 0;
        for word in &self.dictionary_words {
            if word.len() >= 4 && s_lower.contains(word.as_str()) {
                matched_chars = matched_chars.max(word.len());
            }
        }

        if s.is_empty() {
            return 0.5;
        }

        let coverage = matched_chars as f64 / s.len() as f64;
        coverage.min(1.0)
    }

    /// Calculate overall DGA probability
    fn calculate_dga_probability(
        &self,
        entropy: f64,
        consonant_ratio: f64,
        digit_ratio: f64,
        length_score: f64,
        ngram_score: f64,
        dictionary_score: f64,
        domain_len: usize,
    ) -> (f64, DgaConfidence) {
        let mut score = 0.0;
        let mut _factors = 0; // Used for future weighted scoring

        // High entropy is suspicious (weight: 25%)
        if entropy > self.entropy_threshold {
            let entropy_factor = ((entropy - self.entropy_threshold) / 2.0).min(1.0);
            score += entropy_factor * 0.25;
        }
        _factors += 1;

        // High consonant ratio is suspicious (weight: 15%)
        if consonant_ratio > self.max_consonant_ratio {
            let consonant_factor = ((consonant_ratio - self.max_consonant_ratio) / 0.3).min(1.0);
            score += consonant_factor * 0.15;
        }
        _factors += 1;

        // High digit ratio is suspicious (weight: 10%)
        if digit_ratio > 0.3 {
            score += ((digit_ratio - 0.3) / 0.7).min(1.0) * 0.10;
        }
        _factors += 1;

        // Low n-gram score is suspicious (weight: 25%)
        if ngram_score < 0.3 {
            score += (1.0 - ngram_score / 0.3) * 0.25;
        }
        _factors += 1;

        // Low dictionary score is suspicious (weight: 15%)
        if dictionary_score < 0.2 {
            score += (1.0 - dictionary_score / 0.2) * 0.15;
        }
        _factors += 1;

        // Abnormal length is suspicious (weight: 10%)
        if length_score < 0.5 {
            score += (1.0 - length_score / 0.5) * 0.10;
        }
        _factors += 1;

        // Normalize score
        let probability = score.min(1.0);

        // Determine confidence
        let confidence = if probability >= 0.85 && entropy > 4.0 && ngram_score < 0.2 {
            DgaConfidence::High
        } else if probability >= 0.6 {
            DgaConfidence::Medium
        } else {
            DgaConfidence::Low
        };

        (probability, confidence)
    }

    /// Try to identify known DGA family
    fn identify_dga_family(&self, sld: &str, tld: &str, entropy: f64) -> Option<String> {
        for family in &self.dga_families {
            let len = sld.len();

            // Check length constraints
            if len < family.min_length || len > family.max_length {
                continue;
            }

            // Check TLD
            if !family.tlds.is_empty() && !family.tlds.contains(&tld.to_string()) {
                continue;
            }

            // Check charset
            if !family.charset.is_empty() {
                let all_chars_match = sld.chars().all(|c| family.charset.contains(c));
                if !all_chars_match {
                    continue;
                }
            }

            // Check entropy range
            if entropy >= family.entropy_range.0 && entropy <= family.entropy_range.1 {
                return Some(family.name.clone());
            }
        }

        None
    }

    /// Check if domain is whitelisted
    fn is_whitelisted(&self, domain: &str) -> bool {
        // Check exact match
        if self.whitelist.contains(domain) {
            return true;
        }

        // Check if domain ends with whitelisted suffix
        for wl in &self.whitelist {
            if domain.ends_with(&format!(".{}", wl)) {
                return true;
            }
        }

        false
    }

    /// Load common English bigrams
    fn load_common_bigrams() -> HashSet<String> {
        vec![
            "th", "he", "in", "er", "an", "re", "on", "at", "en", "nd",
            "ti", "es", "or", "te", "of", "ed", "is", "it", "al", "ar",
            "st", "to", "nt", "ng", "se", "ha", "as", "ou", "io", "le",
            "ve", "co", "me", "de", "hi", "ri", "ro", "ic", "ne", "ea",
            "ra", "ce", "li", "ch", "ll", "be", "ma", "si", "om", "ur",
        ].into_iter().map(String::from).collect()
    }

    /// Load common English trigrams
    fn load_common_trigrams() -> HashSet<String> {
        vec![
            "the", "and", "ing", "ion", "tio", "ent", "ati", "for", "her", "ter",
            "hat", "tha", "ere", "ate", "his", "con", "res", "ver", "all", "ons",
            "nce", "men", "ith", "ted", "ers", "pro", "thi", "wit", "are", "ess",
            "not", "ive", "was", "ect", "rea", "com", "eve", "per", "int", "est",
            "sta", "cti", "ica", "ist", "ear", "ain", "one", "our", "iti", "rat",
        ].into_iter().map(String::from).collect()
    }

    /// Load common dictionary words
    fn load_dictionary_words() -> HashSet<String> {
        vec![
            // Common words in domain names
            "shop", "store", "online", "web", "site", "page", "home", "mail", "cloud",
            "service", "tech", "digital", "media", "group", "network", "system", "data",
            "info", "news", "blog", "forum", "social", "mobile", "app", "game", "music",
            "video", "photo", "image", "file", "download", "upload", "share", "link",
            "search", "find", "help", "support", "contact", "about", "login", "signup",
            "account", "user", "member", "admin", "secure", "safe", "fast", "free",
            "best", "top", "new", "hot", "cool", "great", "super", "mega", "ultra",
            "global", "world", "inter", "national", "local", "city", "town", "country",
            "bank", "finance", "money", "pay", "buy", "sell", "trade", "market", "stock",
            "health", "medical", "doctor", "care", "life", "food", "travel", "hotel",
            "auto", "car", "sport", "fitness", "fashion", "beauty", "art", "design",
            "learn", "edu", "school", "university", "book", "read", "write", "code",
            "soft", "hard", "ware", "tool", "build", "make", "create", "dev", "test",
        ].into_iter().map(String::from).collect()
    }

    /// Load whitelist of legitimate high-entropy domains
    fn load_whitelist() -> HashSet<String> {
        vec![
            // CDNs and cloud providers
            "cloudfront.net", "akamaihd.net", "akamaized.net", "cloudflare.com",
            "fastly.net", "azureedge.net", "amazonaws.com", "googleusercontent.com",
            "gstatic.com", "googlevideo.com", "ytimg.com", "fbcdn.net",
            // URL shorteners
            "bit.ly", "goo.gl", "t.co", "tinyurl.com", "ow.ly",
            // Common high-entropy legitimate domains
            "1e100.net", "2mdn.net", "doubleclick.net",
        ].into_iter().map(String::from).collect()
    }

    /// Load known DGA family patterns
    fn load_dga_families() -> Vec<DgaFamily> {
        vec![
            DgaFamily {
                name: "Conficker".to_string(),
                min_length: 4,
                max_length: 10,
                charset: "abcdefghijklmnopqrstuvwxyz".to_string(),
                tlds: vec!["com", "net", "org", "info", "biz"].iter().map(|s| s.to_string()).collect(),
                entropy_range: (3.0, 4.5),
            },
            DgaFamily {
                name: "CryptoLocker".to_string(),
                min_length: 12,
                max_length: 24,
                charset: "abcdefghijklmnopqrstuvwxyz0123456789".to_string(),
                tlds: vec!["com", "net", "org", "biz", "ru"].iter().map(|s| s.to_string()).collect(),
                entropy_range: (3.5, 5.0),
            },
            DgaFamily {
                name: "Necurs".to_string(),
                min_length: 6,
                max_length: 16,
                charset: "abcdefghijklmnopqrstuvwxyz".to_string(),
                tlds: vec!["com", "net", "org", "pw", "bit"].iter().map(|s| s.to_string()).collect(),
                entropy_range: (3.2, 4.2),
            },
            DgaFamily {
                name: "Qakbot".to_string(),
                min_length: 8,
                max_length: 25,
                charset: "abcdefghijklmnopqrstuvwxyz".to_string(),
                tlds: vec!["com", "net", "org"].iter().map(|s| s.to_string()).collect(),
                entropy_range: (3.5, 4.8),
            },
            DgaFamily {
                name: "Ramnit".to_string(),
                min_length: 8,
                max_length: 19,
                charset: "abcdefghijklmnopqrstuvwxyz".to_string(),
                tlds: vec!["com", "eu", "bid"].iter().map(|s| s.to_string()).collect(),
                entropy_range: (3.3, 4.5),
            },
            DgaFamily {
                name: "Suppobox".to_string(),
                min_length: 6,
                max_length: 16,
                charset: "abcdefghijklmnopqrstuvwxyz0123456789".to_string(),
                tlds: vec!["com", "net"].iter().map(|s| s.to_string()).collect(),
                entropy_range: (3.0, 4.0),
            },
            DgaFamily {
                name: "Tinba".to_string(),
                min_length: 12,
                max_length: 12,
                charset: "abcdefghijklmnopqrstuvwxyz".to_string(),
                tlds: vec!["com"].iter().map(|s| s.to_string()).collect(),
                entropy_range: (3.5, 4.5),
            },
            DgaFamily {
                name: "Pykspa".to_string(),
                min_length: 6,
                max_length: 11,
                charset: "abcdefghijklmnopqrstuvwxyz".to_string(),
                tlds: vec!["com", "net", "biz", "org"].iter().map(|s| s.to_string()).collect(),
                entropy_range: (3.0, 4.2),
            },
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_legitimate_domain() {
        let detector = DgaDetector::new();
        let result = detector.analyze("google.com");
        assert!(!result.is_dga);
        assert!(result.probability < 0.5);
    }

    #[test]
    fn test_dga_domain() {
        let detector = DgaDetector::new();
        // Random-looking domain
        let result = detector.analyze("xjklqwerty.com");
        assert!(result.entropy > 3.0);
    }

    #[test]
    fn test_high_entropy_domain() {
        let detector = DgaDetector::new();
        let result = detector.analyze("a1b2c3d4e5f6g7h8.com");
        assert!(result.entropy > 3.5);
        assert!(result.digit_ratio > 0.3);
    }

    #[test]
    fn test_entropy_calculation() {
        let detector = DgaDetector::new();

        // Low entropy (repeated chars)
        let low_entropy = detector.calculate_entropy("aaaa");
        assert!(low_entropy < 1.0);

        // Higher entropy (varied chars)
        let high_entropy = detector.calculate_entropy("abcd");
        assert!(high_entropy > 1.5);
    }

    #[test]
    fn test_whitelisted_domain() {
        let detector = DgaDetector::new();
        let result = detector.analyze("d1234.cloudfront.net");
        assert!(!result.is_dga);
    }
}
