//! Brute-force attack implementation
//!
//! Generate all possible password combinations within a character space.

use super::Attack;
use crate::cracking::native::types::{Charset, BuiltinCharsets};

/// Brute-force attack configuration
#[derive(Debug, Clone)]
pub struct BruteForceAttack {
    /// Character set to use
    pub charset: Charset,
    /// Minimum password length
    pub min_length: usize,
    /// Maximum password length
    pub max_length: usize,
}

impl BruteForceAttack {
    /// Create a new brute-force attack with default charset (lowercase + digits)
    pub fn new(min_length: usize, max_length: usize) -> Self {
        Self {
            charset: BuiltinCharsets::alphanumeric(),
            min_length,
            max_length,
        }
    }

    /// Create with a specific charset
    pub fn with_charset(charset: Charset, min_length: usize, max_length: usize) -> Self {
        Self {
            charset,
            min_length,
            max_length,
        }
    }

    /// Create lowercase-only brute force
    pub fn lowercase(min_length: usize, max_length: usize) -> Self {
        Self {
            charset: BuiltinCharsets::lowercase(),
            min_length,
            max_length,
        }
    }

    /// Create digits-only brute force (numeric PINs)
    pub fn digits(min_length: usize, max_length: usize) -> Self {
        Self {
            charset: BuiltinCharsets::digits(),
            min_length,
            max_length,
        }
    }

    /// Create alphanumeric brute force
    pub fn alphanumeric(min_length: usize, max_length: usize) -> Self {
        Self {
            charset: BuiltinCharsets::alphanumeric(),
            min_length,
            max_length,
        }
    }

    /// Create full printable ASCII brute force
    pub fn full_ascii(min_length: usize, max_length: usize) -> Self {
        Self {
            charset: BuiltinCharsets::all(),
            min_length,
            max_length,
        }
    }
}

impl Attack for BruteForceAttack {
    fn name(&self) -> &'static str {
        "Brute-Force"
    }

    fn estimate_candidates(&self) -> Option<u64> {
        let charset_len = self.charset.len() as u64;
        if charset_len == 0 {
            return Some(0);
        }

        let mut total: u64 = 0;
        for len in self.min_length..=self.max_length {
            // charset_len ^ len
            if let Some(count) = charset_len.checked_pow(len as u32) {
                total = total.saturating_add(count);
            } else {
                // Overflow - return None to indicate unknown
                return None;
            }
        }
        Some(total)
    }

    fn candidates(&self) -> Box<dyn Iterator<Item = String> + Send> {
        Box::new(BruteForceIterator {
            charset: self.charset.chars.clone(),
            min_length: self.min_length,
            max_length: self.max_length,
            current_length: self.min_length,
            indices: vec![0; self.min_length],
            first: true,
        })
    }
}

/// Iterator for brute-force password generation
struct BruteForceIterator {
    charset: Vec<char>,
    min_length: usize,
    max_length: usize,
    current_length: usize,
    indices: Vec<usize>,
    first: bool,
}

impl Iterator for BruteForceIterator {
    type Item = String;

    fn next(&mut self) -> Option<Self::Item> {
        if self.charset.is_empty() || self.current_length > self.max_length {
            return None;
        }

        // Handle first iteration
        if self.first {
            self.first = false;
            if self.current_length == 0 {
                self.current_length = 1;
                self.indices = vec![0; 1];
                if self.current_length > self.max_length {
                    return None;
                }
            }
            return Some(self.build_string());
        }

        // Increment indices (like a counter in base charset_len)
        let mut i = self.indices.len();
        while i > 0 {
            i -= 1;
            self.indices[i] += 1;
            if self.indices[i] < self.charset.len() {
                return Some(self.build_string());
            }
            self.indices[i] = 0;
        }

        // All combinations for current length exhausted, move to next length
        self.current_length += 1;
        if self.current_length > self.max_length {
            return None;
        }

        self.indices = vec![0; self.current_length];
        Some(self.build_string())
    }
}

impl BruteForceIterator {
    fn build_string(&self) -> String {
        self.indices.iter().map(|&i| self.charset[i]).collect()
    }
}

unsafe impl Send for BruteForceIterator {}

/// Incremental mode attack (progressively longer passwords)
/// Similar to John the Ripper's incremental mode
#[derive(Debug, Clone)]
pub struct IncrementalAttack {
    /// Character frequencies (more common chars first)
    pub charset: Vec<char>,
    /// Maximum password length
    pub max_length: usize,
}

impl IncrementalAttack {
    /// Create with common English letter frequencies
    pub fn english(max_length: usize) -> Self {
        // Ordered by frequency in English + common password chars
        let charset: Vec<char> = "etaoinshrdlcumwfgypbvkjxqz0123456789!@#$%^&*".chars().collect();
        Self { charset, max_length }
    }

    /// Create with numeric preference (for PIN-like passwords)
    pub fn numeric_first(max_length: usize) -> Self {
        let charset: Vec<char> = "0123456789etaoinshrdlcumwfgypbvkjxqz!@#$%^&*".chars().collect();
        Self { charset, max_length }
    }
}

impl Attack for IncrementalAttack {
    fn name(&self) -> &'static str {
        "Incremental"
    }

    fn estimate_candidates(&self) -> Option<u64> {
        let charset_len = self.charset.len() as u64;
        let mut total: u64 = 0;
        for len in 1..=self.max_length {
            if let Some(count) = charset_len.checked_pow(len as u32) {
                total = total.saturating_add(count);
            } else {
                return None;
            }
        }
        Some(total)
    }

    fn candidates(&self) -> Box<dyn Iterator<Item = String> + Send> {
        // Uses same iterator as brute force but with ordered charset
        Box::new(BruteForceIterator {
            charset: self.charset.clone(),
            min_length: 1,
            max_length: self.max_length,
            current_length: 1,
            indices: vec![0],
            first: true,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bruteforce_digits() {
        let attack = BruteForceAttack::digits(1, 2);
        let candidates: Vec<String> = attack.candidates().collect();

        // 10 single digits + 100 two-digit combinations = 110
        assert_eq!(candidates.len(), 110);
        assert!(candidates.contains(&"0".to_string()));
        assert!(candidates.contains(&"9".to_string()));
        assert!(candidates.contains(&"00".to_string()));
        assert!(candidates.contains(&"99".to_string()));
    }

    #[test]
    fn test_bruteforce_estimate() {
        let attack = BruteForceAttack::digits(1, 3);
        // 10 + 100 + 1000 = 1110
        assert_eq!(attack.estimate_candidates(), Some(1110));
    }

    #[test]
    fn test_bruteforce_lowercase_short() {
        let attack = BruteForceAttack::lowercase(1, 1);
        let candidates: Vec<String> = attack.candidates().collect();

        assert_eq!(candidates.len(), 26);
        assert_eq!(candidates[0], "a");
        assert_eq!(candidates[25], "z");
    }

    #[test]
    fn test_bruteforce_order() {
        let charset = Charset::new("test", "ab");
        let attack = BruteForceAttack::with_charset(charset, 1, 2);
        let candidates: Vec<String> = attack.candidates().collect();

        // a, b, aa, ab, ba, bb
        assert_eq!(candidates, vec!["a", "b", "aa", "ab", "ba", "bb"]);
    }

    #[test]
    fn test_incremental_attack() {
        let attack = IncrementalAttack::english(2);
        let candidates: Vec<String> = attack.candidates().take(10).collect();

        // Should start with 'e' (most common letter)
        assert_eq!(candidates[0], "e");
        assert_eq!(candidates[1], "t");
    }
}
