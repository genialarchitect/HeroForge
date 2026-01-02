//! Native password cracking types
//!
//! Core types for the native password cracking engine.

use std::time::Duration;
use serde::{Deserialize, Serialize};

/// Result of a cracking operation
#[derive(Debug, Clone)]
pub struct CrackResult {
    /// The original hash
    pub hash: String,
    /// The cracked plaintext (if found)
    pub plaintext: Option<String>,
    /// Time taken to crack
    pub duration: Duration,
    /// Number of candidates tried
    pub candidates_tried: u64,
}

/// Configuration for the native cracking engine
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeCrackConfig {
    /// Maximum number of worker threads
    pub threads: usize,
    /// Enable SIMD optimizations
    pub use_simd: bool,
    /// Batch size for parallel processing
    pub batch_size: usize,
    /// Progress callback interval (in candidates)
    pub progress_interval: u64,
    /// Maximum candidates to try (0 = unlimited)
    pub max_candidates: u64,
    /// Timeout per hash (0 = unlimited)
    pub timeout_secs: u64,
}

impl Default for NativeCrackConfig {
    fn default() -> Self {
        Self {
            threads: num_cpus::get(),
            use_simd: true,
            batch_size: 10000,
            progress_interval: 100000,
            max_candidates: 0,
            timeout_secs: 0,
        }
    }
}

/// Progress information during cracking
#[derive(Debug, Clone, Default)]
pub struct CrackProgress {
    /// Total hashes being processed
    pub total_hashes: usize,
    /// Hashes cracked so far
    pub cracked: usize,
    /// Current cracking speed (hashes per second)
    pub speed: f64,
    /// Candidates tested so far
    pub candidates_tested: u64,
    /// Total candidates to test (if known)
    pub total_candidates: Option<u64>,
    /// Estimated time remaining in seconds
    pub eta_seconds: Option<u64>,
}

/// A mask character set
#[derive(Debug, Clone)]
pub struct Charset {
    /// Name of the charset
    pub name: String,
    /// Characters in the set
    pub chars: Vec<char>,
}

impl Charset {
    pub fn new(name: &str, chars: &str) -> Self {
        Self {
            name: name.to_string(),
            chars: chars.chars().collect(),
        }
    }

    pub fn len(&self) -> usize {
        self.chars.len()
    }

    pub fn is_empty(&self) -> bool {
        self.chars.is_empty()
    }
}

/// Built-in charsets for mask attacks
pub struct BuiltinCharsets;

impl BuiltinCharsets {
    /// Lowercase letters (a-z)
    pub fn lowercase() -> Charset {
        Charset::new("lowercase", "abcdefghijklmnopqrstuvwxyz")
    }

    /// Uppercase letters (A-Z)
    pub fn uppercase() -> Charset {
        Charset::new("uppercase", "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    }

    /// Digits (0-9)
    pub fn digits() -> Charset {
        Charset::new("digits", "0123456789")
    }

    /// Special characters
    pub fn special() -> Charset {
        Charset::new("special", "!@#$%^&*()-_=+[]{}|;:',.<>?/`~\"\\")
    }

    /// All alphanumeric (a-zA-Z0-9)
    pub fn alphanumeric() -> Charset {
        Charset::new(
            "alphanumeric",
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
        )
    }

    /// All printable ASCII
    pub fn all() -> Charset {
        let mut chars = String::new();
        for c in 32u8..=126u8 {
            chars.push(c as char);
        }
        Charset::new("all", &chars)
    }
}

/// Hashcat-style mask placeholders
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaskPlaceholder {
    /// ?l - lowercase letters
    Lowercase,
    /// ?u - uppercase letters
    Uppercase,
    /// ?d - digits
    Digits,
    /// ?s - special characters
    Special,
    /// ?a - all printable ASCII
    All,
    /// ?b - all bytes (0x00-0xff)
    Binary,
    /// ?1, ?2, ?3, ?4 - custom charsets
    Custom(u8),
}

impl MaskPlaceholder {
    /// Parse a mask placeholder from a string
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "?l" => Some(Self::Lowercase),
            "?u" => Some(Self::Uppercase),
            "?d" => Some(Self::Digits),
            "?s" => Some(Self::Special),
            "?a" => Some(Self::All),
            "?b" => Some(Self::Binary),
            "?1" => Some(Self::Custom(1)),
            "?2" => Some(Self::Custom(2)),
            "?3" => Some(Self::Custom(3)),
            "?4" => Some(Self::Custom(4)),
            _ => None,
        }
    }

    /// Get the charset for this placeholder
    pub fn charset(&self) -> Charset {
        match self {
            Self::Lowercase => BuiltinCharsets::lowercase(),
            Self::Uppercase => BuiltinCharsets::uppercase(),
            Self::Digits => BuiltinCharsets::digits(),
            Self::Special => BuiltinCharsets::special(),
            Self::All => BuiltinCharsets::all(),
            Self::Binary => {
                let mut chars = Vec::with_capacity(256);
                for b in 0u8..=255u8 {
                    // For binary, we use byte values directly
                    chars.push(b as char);
                }
                Charset {
                    name: "binary".to_string(),
                    chars,
                }
            }
            Self::Custom(_) => {
                // Custom charsets need to be provided by the user
                Charset::new("custom", "")
            }
        }
    }
}

/// A rule for password mutations
#[derive(Debug, Clone)]
pub enum MutationRule {
    /// No change (passthrough)
    Noop,
    /// Convert to lowercase
    Lowercase,
    /// Convert to uppercase
    Uppercase,
    /// Capitalize first letter
    Capitalize,
    /// Reverse the string
    Reverse,
    /// Duplicate the string
    Duplicate,
    /// Reflect (append reversed)
    Reflect,
    /// Rotate left by N characters
    RotateLeft(usize),
    /// Rotate right by N characters
    RotateRight(usize),
    /// Append a character
    AppendChar(char),
    /// Prepend a character
    PrependChar(char),
    /// Append a string
    AppendString(String),
    /// Prepend a string
    PrependString(String),
    /// Delete character at position
    DeleteAt(usize),
    /// Delete first character
    DeleteFirst,
    /// Delete last character
    DeleteLast,
    /// Replace character at position
    ReplaceAt(usize, char),
    /// Replace all occurrences of a character
    ReplaceAll(char, char),
    /// Truncate to N characters
    Truncate(usize),
    /// Insert character at position
    InsertAt(usize, char),
    /// Toggle case of character at position
    ToggleAt(usize),
    /// Leet speak substitutions
    Leet,
    /// Extract substring
    Extract(usize, usize),
    /// Overwrite at position
    Overwrite(usize, String),
}

impl MutationRule {
    /// Apply this rule to a password candidate
    pub fn apply(&self, password: &str) -> String {
        match self {
            Self::Noop => password.to_string(),
            Self::Lowercase => password.to_lowercase(),
            Self::Uppercase => password.to_uppercase(),
            Self::Capitalize => {
                let mut chars: Vec<char> = password.chars().collect();
                if let Some(first) = chars.first_mut() {
                    *first = first.to_uppercase().next().unwrap_or(*first);
                }
                chars.into_iter().collect()
            }
            Self::Reverse => password.chars().rev().collect(),
            Self::Duplicate => format!("{}{}", password, password),
            Self::Reflect => {
                let reversed: String = password.chars().rev().collect();
                format!("{}{}", password, reversed)
            }
            Self::RotateLeft(n) => {
                let chars: Vec<char> = password.chars().collect();
                if chars.is_empty() {
                    return password.to_string();
                }
                let n = n % chars.len();
                chars[n..].iter().chain(chars[..n].iter()).collect()
            }
            Self::RotateRight(n) => {
                let chars: Vec<char> = password.chars().collect();
                if chars.is_empty() {
                    return password.to_string();
                }
                let n = n % chars.len();
                let split = chars.len() - n;
                chars[split..].iter().chain(chars[..split].iter()).collect()
            }
            Self::AppendChar(c) => format!("{}{}", password, c),
            Self::PrependChar(c) => format!("{}{}", c, password),
            Self::AppendString(s) => format!("{}{}", password, s),
            Self::PrependString(s) => format!("{}{}", s, password),
            Self::DeleteAt(pos) => {
                let mut chars: Vec<char> = password.chars().collect();
                if *pos < chars.len() {
                    chars.remove(*pos);
                }
                chars.into_iter().collect()
            }
            Self::DeleteFirst => {
                let mut chars: Vec<char> = password.chars().collect();
                if !chars.is_empty() {
                    chars.remove(0);
                }
                chars.into_iter().collect()
            }
            Self::DeleteLast => {
                let mut chars: Vec<char> = password.chars().collect();
                if !chars.is_empty() {
                    chars.pop();
                }
                chars.into_iter().collect()
            }
            Self::ReplaceAt(pos, c) => {
                let mut chars: Vec<char> = password.chars().collect();
                if *pos < chars.len() {
                    chars[*pos] = *c;
                }
                chars.into_iter().collect()
            }
            Self::ReplaceAll(from, to) => password.replace(*from, &to.to_string()),
            Self::Truncate(n) => password.chars().take(*n).collect(),
            Self::InsertAt(pos, c) => {
                let mut chars: Vec<char> = password.chars().collect();
                if *pos <= chars.len() {
                    chars.insert(*pos, *c);
                }
                chars.into_iter().collect()
            }
            Self::ToggleAt(pos) => {
                let mut chars: Vec<char> = password.chars().collect();
                if let Some(c) = chars.get_mut(*pos) {
                    if c.is_lowercase() {
                        *c = c.to_uppercase().next().unwrap_or(*c);
                    } else if c.is_uppercase() {
                        *c = c.to_lowercase().next().unwrap_or(*c);
                    }
                }
                chars.into_iter().collect()
            }
            Self::Leet => {
                password
                    .replace('a', "4")
                    .replace('A', "4")
                    .replace('e', "3")
                    .replace('E', "3")
                    .replace('i', "1")
                    .replace('I', "1")
                    .replace('o', "0")
                    .replace('O', "0")
                    .replace('s', "5")
                    .replace('S', "5")
                    .replace('t', "7")
                    .replace('T', "7")
            }
            Self::Extract(start, len) => {
                password.chars().skip(*start).take(*len).collect()
            }
            Self::Overwrite(pos, s) => {
                let mut chars: Vec<char> = password.chars().collect();
                for (i, c) in s.chars().enumerate() {
                    let idx = pos + i;
                    if idx < chars.len() {
                        chars[idx] = c;
                    }
                }
                chars.into_iter().collect()
            }
        }
    }
}

/// Hash algorithm trait for implementing custom hash types
pub trait HashAlgorithm: Send + Sync {
    /// Name of the hash algorithm
    fn name(&self) -> &'static str;

    /// Compute hash of input and return hex string
    fn hash(&self, input: &[u8]) -> String;

    /// Verify if plaintext produces the target hash
    fn verify(&self, plaintext: &[u8], target_hash: &str) -> bool {
        self.hash(plaintext).eq_ignore_ascii_case(target_hash)
    }

    /// Check if this algorithm supports SIMD optimization
    fn supports_simd(&self) -> bool {
        false
    }

    /// Compute multiple hashes in parallel (SIMD)
    fn hash_batch(&self, inputs: &[&[u8]]) -> Vec<String> {
        inputs.iter().map(|input| self.hash(input)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mutation_rules() {
        assert_eq!(MutationRule::Lowercase.apply("HELLO"), "hello");
        assert_eq!(MutationRule::Uppercase.apply("hello"), "HELLO");
        assert_eq!(MutationRule::Capitalize.apply("hello"), "Hello");
        assert_eq!(MutationRule::Reverse.apply("hello"), "olleh");
        assert_eq!(MutationRule::Duplicate.apply("hi"), "hihi");
        assert_eq!(MutationRule::Reflect.apply("abc"), "abccba");
        assert_eq!(MutationRule::AppendChar('!').apply("test"), "test!");
        assert_eq!(MutationRule::PrependChar('$').apply("test"), "$test");
        assert_eq!(MutationRule::DeleteFirst.apply("test"), "est");
        assert_eq!(MutationRule::DeleteLast.apply("test"), "tes");
        assert_eq!(MutationRule::Leet.apply("password"), "p455w0rd");
        assert_eq!(MutationRule::RotateLeft(1).apply("abcd"), "bcda");
        assert_eq!(MutationRule::RotateRight(1).apply("abcd"), "dabc");
    }

    #[test]
    fn test_charsets() {
        assert_eq!(BuiltinCharsets::lowercase().len(), 26);
        assert_eq!(BuiltinCharsets::uppercase().len(), 26);
        assert_eq!(BuiltinCharsets::digits().len(), 10);
        assert_eq!(BuiltinCharsets::alphanumeric().len(), 62);
    }

    #[test]
    fn test_mask_placeholder_parse() {
        assert_eq!(MaskPlaceholder::parse("?l"), Some(MaskPlaceholder::Lowercase));
        assert_eq!(MaskPlaceholder::parse("?u"), Some(MaskPlaceholder::Uppercase));
        assert_eq!(MaskPlaceholder::parse("?d"), Some(MaskPlaceholder::Digits));
        assert_eq!(MaskPlaceholder::parse("?1"), Some(MaskPlaceholder::Custom(1)));
        assert_eq!(MaskPlaceholder::parse("?x"), None);
    }
}
