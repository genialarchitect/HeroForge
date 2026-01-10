//! Mask attack implementation
//!
//! Hashcat-style mask-based password generation.

use super::Attack;
use crate::cracking::native::types::{Charset, MaskPlaceholder};

/// Mask attack configuration
///
/// Supports hashcat-style masks:
/// - ?l = lowercase letters (a-z)
/// - ?u = uppercase letters (A-Z)
/// - ?d = digits (0-9)
/// - ?s = special characters
/// - ?a = all printable ASCII
/// - ?1, ?2, ?3, ?4 = custom charsets
#[derive(Debug, Clone)]
pub struct MaskAttack {
    /// The mask pattern
    pub mask: String,
    /// Custom charsets (?1, ?2, ?3, ?4)
    pub custom_charsets: [Charset; 4],
    /// Parsed mask positions
    positions: Vec<MaskPosition>,
}

#[derive(Debug, Clone)]
enum MaskPosition {
    /// A placeholder that expands to a charset
    Placeholder(Charset),
    /// A literal character
    Literal(char),
}

impl MaskAttack {
    /// Create a new mask attack
    pub fn new(mask: &str) -> Self {
        let custom_charsets = [
            Charset::new("custom1", ""),
            Charset::new("custom2", ""),
            Charset::new("custom3", ""),
            Charset::new("custom4", ""),
        ];

        let mut attack = Self {
            mask: mask.to_string(),
            custom_charsets,
            positions: Vec::new(),
        };

        attack.parse_mask();
        attack
    }

    /// Create with custom charsets
    pub fn with_custom_charsets(mask: &str, custom1: &str, custom2: &str, custom3: &str, custom4: &str) -> Self {
        let custom_charsets = [
            Charset::new("custom1", custom1),
            Charset::new("custom2", custom2),
            Charset::new("custom3", custom3),
            Charset::new("custom4", custom4),
        ];

        let mut attack = Self {
            mask: mask.to_string(),
            custom_charsets,
            positions: Vec::new(),
        };

        attack.parse_mask();
        attack
    }

    /// Set a custom charset
    pub fn set_custom_charset(&mut self, index: usize, chars: &str) {
        if index < 4 {
            self.custom_charsets[index] = Charset::new(&format!("custom{}", index + 1), chars);
            self.parse_mask(); // Re-parse to update positions
        }
    }

    /// Parse the mask string into positions
    fn parse_mask(&mut self) {
        self.positions.clear();

        let mut chars = self.mask.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '?' {
                if let Some(&next) = chars.peek() {
                    let placeholder = match next {
                        'l' => Some(MaskPlaceholder::Lowercase),
                        'u' => Some(MaskPlaceholder::Uppercase),
                        'd' => Some(MaskPlaceholder::Digits),
                        's' => Some(MaskPlaceholder::Special),
                        'a' => Some(MaskPlaceholder::All),
                        'b' => Some(MaskPlaceholder::Binary),
                        '1' => Some(MaskPlaceholder::Custom(1)),
                        '2' => Some(MaskPlaceholder::Custom(2)),
                        '3' => Some(MaskPlaceholder::Custom(3)),
                        '4' => Some(MaskPlaceholder::Custom(4)),
                        '?' => {
                            // Escaped ?
                            chars.next();
                            self.positions.push(MaskPosition::Literal('?'));
                            continue;
                        }
                        _ => None,
                    };

                    if let Some(ph) = placeholder {
                        chars.next(); // Consume the placeholder char
                        let charset = match ph {
                            MaskPlaceholder::Custom(n) => {
                                self.custom_charsets[(n - 1) as usize].clone()
                            }
                            _ => ph.charset(),
                        };
                        self.positions.push(MaskPosition::Placeholder(charset));
                    } else {
                        // Unknown placeholder, treat as literal
                        self.positions.push(MaskPosition::Literal(c));
                    }
                } else {
                    // ? at end, treat as literal
                    self.positions.push(MaskPosition::Literal(c));
                }
            } else {
                self.positions.push(MaskPosition::Literal(c));
            }
        }
    }

    /// Get the effective length of the mask
    pub fn len(&self) -> usize {
        self.positions.len()
    }

    /// Check if mask is empty
    pub fn is_empty(&self) -> bool {
        self.positions.is_empty()
    }
}

impl Attack for MaskAttack {
    fn name(&self) -> &'static str {
        "Mask"
    }

    fn estimate_candidates(&self) -> Option<u64> {
        let mut total: u64 = 1;
        for pos in &self.positions {
            match pos {
                MaskPosition::Placeholder(charset) => {
                    let len = charset.len() as u64;
                    if len == 0 {
                        return Some(0);
                    }
                    total = total.checked_mul(len)?;
                }
                MaskPosition::Literal(_) => {
                    // Literal doesn't multiply
                }
            }
        }
        Some(total)
    }

    fn candidates(&self) -> Box<dyn Iterator<Item = String> + Send> {
        Box::new(MaskIterator::new(&self.positions))
    }
}

/// Iterator for mask-based password generation
struct MaskIterator {
    /// Character options at each position
    position_chars: Vec<Vec<char>>,
    /// Current indices into position_chars
    indices: Vec<usize>,
    /// Whether this is the first iteration
    first: bool,
    /// Whether iteration is complete
    done: bool,
}

impl MaskIterator {
    fn new(positions: &[MaskPosition]) -> Self {
        let position_chars: Vec<Vec<char>> = positions
            .iter()
            .map(|pos| match pos {
                MaskPosition::Placeholder(charset) => charset.chars.clone(),
                MaskPosition::Literal(c) => vec![*c],
            })
            .collect();

        // Check for empty charsets
        let done = position_chars.iter().any(|v| v.is_empty());

        let indices = vec![0; position_chars.len()];

        Self {
            position_chars,
            indices,
            first: true,
            done,
        }
    }

    fn build_string(&self) -> String {
        self.indices
            .iter()
            .enumerate()
            .map(|(i, &idx)| self.position_chars[i][idx])
            .collect()
    }
}

impl Iterator for MaskIterator {
    type Item = String;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done || self.position_chars.is_empty() {
            return None;
        }

        if self.first {
            self.first = false;
            return Some(self.build_string());
        }

        // Increment indices from right to left
        let mut i = self.indices.len();
        while i > 0 {
            i -= 1;
            self.indices[i] += 1;
            if self.indices[i] < self.position_chars[i].len() {
                return Some(self.build_string());
            }
            self.indices[i] = 0;
        }

        // All combinations exhausted
        self.done = true;
        None
    }
}

unsafe impl Send for MaskIterator {}

/// Mask increment attack (multiple mask lengths)
#[derive(Debug, Clone)]
pub struct MaskIncrementAttack {
    /// Base mask pattern (e.g., "?a")
    pub base_mask: String,
    /// Minimum repetitions
    pub min_length: usize,
    /// Maximum repetitions
    pub max_length: usize,
    /// Custom charsets
    pub custom_charsets: [Charset; 4],
}

impl MaskIncrementAttack {
    /// Create a mask increment attack
    pub fn new(base_mask: &str, min_length: usize, max_length: usize) -> Self {
        Self {
            base_mask: base_mask.to_string(),
            min_length,
            max_length,
            custom_charsets: [
                Charset::new("custom1", ""),
                Charset::new("custom2", ""),
                Charset::new("custom3", ""),
                Charset::new("custom4", ""),
            ],
        }
    }
}

impl Attack for MaskIncrementAttack {
    fn name(&self) -> &'static str {
        "Mask Increment"
    }

    fn estimate_candidates(&self) -> Option<u64> {
        let mut total: u64 = 0;
        for len in self.min_length..=self.max_length {
            let mask = self.base_mask.repeat(len);
            let attack = MaskAttack::new(&mask);
            if let Some(count) = attack.estimate_candidates() {
                total = total.saturating_add(count);
            } else {
                return None;
            }
        }
        Some(total)
    }

    fn candidates(&self) -> Box<dyn Iterator<Item = String> + Send> {
        let base_mask = self.base_mask.clone();
        let min = self.min_length;
        let max = self.max_length;

        Box::new(MaskIncrementIterator {
            base_mask,
            current_length: min,
            max_length: max,
            current_attack: None,
            current_iter: None,
        })
    }
}

struct MaskIncrementIterator {
    base_mask: String,
    current_length: usize,
    max_length: usize,
    current_attack: Option<MaskAttack>,
    current_iter: Option<Box<dyn Iterator<Item = String> + Send>>,
}

impl Iterator for MaskIncrementIterator {
    type Item = String;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            // Try current iterator
            if let Some(ref mut iter) = self.current_iter {
                if let Some(candidate) = iter.next() {
                    return Some(candidate);
                }
            }

            // Move to next length
            if self.current_length > self.max_length {
                return None;
            }

            let mask = self.base_mask.repeat(self.current_length);
            let attack = MaskAttack::new(&mask);
            self.current_iter = Some(attack.candidates());
            self.current_attack = Some(attack);
            self.current_length += 1;
        }
    }
}

unsafe impl Send for MaskIncrementIterator {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mask_digits() {
        let attack = MaskAttack::new("?d?d");
        let candidates: Vec<String> = attack.candidates().collect();

        assert_eq!(candidates.len(), 100);
        assert!(candidates.contains(&"00".to_string()));
        assert!(candidates.contains(&"99".to_string()));
        assert!(candidates.contains(&"42".to_string()));
    }

    #[test]
    fn test_mask_mixed() {
        let attack = MaskAttack::new("a?d");
        let candidates: Vec<String> = attack.candidates().collect();

        assert_eq!(candidates.len(), 10);
        assert!(candidates.contains(&"a0".to_string()));
        assert!(candidates.contains(&"a9".to_string()));
    }

    #[test]
    fn test_mask_estimate() {
        let attack = MaskAttack::new("?l?l?d");
        // 26 * 26 * 10 = 6760
        assert_eq!(attack.estimate_candidates(), Some(6760));
    }

    #[test]
    fn test_mask_custom_charset() {
        let attack = MaskAttack::with_custom_charsets("?1?1", "ab", "", "", "");
        let candidates: Vec<String> = attack.candidates().collect();

        // 2 * 2 = 4
        assert_eq!(candidates.len(), 4);
        assert!(candidates.contains(&"aa".to_string()));
        assert!(candidates.contains(&"ab".to_string()));
        assert!(candidates.contains(&"ba".to_string()));
        assert!(candidates.contains(&"bb".to_string()));
    }

    #[test]
    fn test_mask_literal() {
        let attack = MaskAttack::new("pass?d");
        let candidates: Vec<String> = attack.candidates().collect();

        assert_eq!(candidates.len(), 10);
        assert!(candidates.contains(&"pass0".to_string()));
        assert!(candidates.contains(&"pass9".to_string()));
    }

    #[test]
    fn test_mask_increment() {
        let attack = MaskIncrementAttack::new("?d", 1, 2);
        let candidates: Vec<String> = attack.candidates().collect();

        // 10 + 100 = 110
        assert_eq!(candidates.len(), 110);
    }

    #[test]
    fn test_escaped_question_mark() {
        let attack = MaskAttack::new("??test");
        let candidates: Vec<String> = attack.candidates().collect();

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0], "?test");
    }
}
