//! Rule-based attack implementation
//!
//! Apply transformation rules to wordlist entries.

use super::{Attack, dictionary::DictionaryAttack};
use crate::cracking::native::types::MutationRule;

/// Rule-based attack that applies mutations to dictionary words
#[derive(Debug, Clone)]
pub struct RuleBasedAttack {
    /// Base dictionary
    pub dictionary: DictionaryAttack,
    /// Rules to apply
    pub rules: Vec<MutationRule>,
}

impl RuleBasedAttack {
    /// Create a new rule-based attack
    pub fn new(dictionary: DictionaryAttack, rules: Vec<MutationRule>) -> Self {
        Self { dictionary, rules }
    }

    /// Create with common password mutation rules
    pub fn common_rules(dictionary: DictionaryAttack) -> Self {
        let rules = vec![
            MutationRule::Noop,                    // Original
            MutationRule::Capitalize,             // First letter uppercase
            MutationRule::Uppercase,              // All uppercase
            MutationRule::Lowercase,              // All lowercase
            MutationRule::AppendChar('1'),        // Append 1
            MutationRule::AppendChar('!'),        // Append !
            MutationRule::AppendString("123".to_string()),  // Append 123
            MutationRule::AppendString("!".to_string()),    // Append !
            MutationRule::PrependChar('1'),       // Prepend 1
            MutationRule::Leet,                   // Leet speak
            MutationRule::Reverse,                // Reversed
            MutationRule::Duplicate,              // Duplicated
        ];
        Self { dictionary, rules }
    }

    /// Create with aggressive password mutation rules
    pub fn aggressive_rules(dictionary: DictionaryAttack) -> Self {
        let mut rules = vec![
            MutationRule::Noop,
            MutationRule::Capitalize,
            MutationRule::Uppercase,
            MutationRule::Lowercase,
            MutationRule::Leet,
            MutationRule::Reverse,
            MutationRule::Duplicate,
            MutationRule::Reflect,
        ];

        // Add common number suffixes
        for n in 0..=99 {
            rules.push(MutationRule::AppendString(n.to_string()));
        }
        for n in &[123, 1234, 12345, 2020, 2021, 2022, 2023, 2024, 2025] {
            rules.push(MutationRule::AppendString(n.to_string()));
        }

        // Add common special char suffixes
        for c in ['!', '@', '#', '$', '%', '^', '&', '*', '.', '?'] {
            rules.push(MutationRule::AppendChar(c));
        }

        // Add common prefixes
        for c in ['1', '!', '@', '#'] {
            rules.push(MutationRule::PrependChar(c));
        }

        Self { dictionary, rules }
    }

    /// Parse rules from hashcat rule file format
    pub fn from_hashcat_rules(dictionary: DictionaryAttack, rule_content: &str) -> Self {
        let rules: Vec<MutationRule> = rule_content
            .lines()
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .filter_map(|line| parse_hashcat_rule(line))
            .collect();

        Self { dictionary, rules }
    }
}

/// Parse a single hashcat rule
fn parse_hashcat_rule(rule: &str) -> Option<MutationRule> {
    let rule = rule.trim();
    if rule.is_empty() {
        return Some(MutationRule::Noop);
    }

    let mut chars = rule.chars().peekable();
    let cmd = chars.next()?;

    match cmd {
        ':' => Some(MutationRule::Noop),          // Do nothing
        'l' => Some(MutationRule::Lowercase),     // Lowercase all
        'u' => Some(MutationRule::Uppercase),     // Uppercase all
        'c' => Some(MutationRule::Capitalize),    // Capitalize
        'r' => Some(MutationRule::Reverse),       // Reverse
        'd' => Some(MutationRule::Duplicate),     // Duplicate word
        'f' => Some(MutationRule::Reflect),       // Reflect (word + reversed)
        '[' => Some(MutationRule::DeleteFirst),   // Delete first char
        ']' => Some(MutationRule::DeleteLast),    // Delete last char
        '$' => {
            // Append char
            let c = chars.next()?;
            Some(MutationRule::AppendChar(c))
        }
        '^' => {
            // Prepend char
            let c = chars.next()?;
            Some(MutationRule::PrependChar(c))
        }
        'D' => {
            // Delete at position
            let pos: usize = chars.next()?.to_digit(10)? as usize;
            Some(MutationRule::DeleteAt(pos))
        }
        'T' => {
            // Toggle case at position
            let pos: usize = chars.next()?.to_digit(10)? as usize;
            Some(MutationRule::ToggleAt(pos))
        }
        '\'' => {
            // Truncate at position
            let pos: usize = chars.next()?.to_digit(10)? as usize;
            Some(MutationRule::Truncate(pos))
        }
        's' => {
            // Replace char
            let from = chars.next()?;
            let to = chars.next()?;
            Some(MutationRule::ReplaceAll(from, to))
        }
        '{' => {
            // Rotate left
            Some(MutationRule::RotateLeft(1))
        }
        '}' => {
            // Rotate right
            Some(MutationRule::RotateRight(1))
        }
        // Many more rules exist in hashcat - this is a subset
        _ => None,
    }
}

impl Attack for RuleBasedAttack {
    fn name(&self) -> &'static str {
        "Rule-Based"
    }

    fn estimate_candidates(&self) -> Option<u64> {
        let dict_count = self.dictionary.estimate_candidates()?;
        let rule_count = self.rules.len() as u64;
        Some(dict_count * rule_count)
    }

    fn candidates(&self) -> Box<dyn Iterator<Item = String> + Send> {
        let words: Vec<String> = self.dictionary.candidates().collect();
        let rules = self.rules.clone();

        Box::new(RuleIterator {
            words,
            rules,
            word_idx: 0,
            rule_idx: 0,
        })
    }
}

struct RuleIterator {
    words: Vec<String>,
    rules: Vec<MutationRule>,
    word_idx: usize,
    rule_idx: usize,
}

impl Iterator for RuleIterator {
    type Item = String;

    fn next(&mut self) -> Option<Self::Item> {
        if self.word_idx >= self.words.len() {
            return None;
        }

        let word = &self.words[self.word_idx];
        let rule = &self.rules[self.rule_idx];
        let result = rule.apply(word);

        self.rule_idx += 1;
        if self.rule_idx >= self.rules.len() {
            self.rule_idx = 0;
            self.word_idx += 1;
        }

        Some(result)
    }
}

unsafe impl Send for RuleIterator {}

/// Hybrid attack: wordlist + mask
pub struct HybridWordlistMaskAttack {
    /// Base dictionary
    pub dictionary: DictionaryAttack,
    /// Mask to append/prepend
    pub mask: String,
    /// Whether to prepend (true) or append (false)
    pub prepend: bool,
}

impl HybridWordlistMaskAttack {
    /// Create wordlist + mask (append mask to words)
    pub fn wordlist_mask(dictionary: DictionaryAttack, mask: &str) -> Self {
        Self {
            dictionary,
            mask: mask.to_string(),
            prepend: false,
        }
    }

    /// Create mask + wordlist (prepend mask to words)
    pub fn mask_wordlist(dictionary: DictionaryAttack, mask: &str) -> Self {
        Self {
            dictionary,
            mask: mask.to_string(),
            prepend: true,
        }
    }
}

impl Attack for HybridWordlistMaskAttack {
    fn name(&self) -> &'static str {
        if self.prepend {
            "Hybrid Mask+Wordlist"
        } else {
            "Hybrid Wordlist+Mask"
        }
    }

    fn estimate_candidates(&self) -> Option<u64> {
        // Would need to expand mask to know count
        None
    }

    fn candidates(&self) -> Box<dyn Iterator<Item = String> + Send> {
        use crate::cracking::native::attacks::mask::MaskAttack;

        let words: Vec<String> = self.dictionary.candidates().collect();
        let mask_attack = MaskAttack::new(&self.mask);
        let mask_candidates: Vec<String> = mask_attack.candidates().collect();
        let prepend = self.prepend;

        Box::new(HybridIterator {
            words,
            mask_candidates,
            word_idx: 0,
            mask_idx: 0,
            prepend,
        })
    }
}

struct HybridIterator {
    words: Vec<String>,
    mask_candidates: Vec<String>,
    word_idx: usize,
    mask_idx: usize,
    prepend: bool,
}

impl Iterator for HybridIterator {
    type Item = String;

    fn next(&mut self) -> Option<Self::Item> {
        if self.word_idx >= self.words.len() {
            return None;
        }

        let word = &self.words[self.word_idx];
        let mask_part = &self.mask_candidates[self.mask_idx];

        let result = if self.prepend {
            format!("{}{}", mask_part, word)
        } else {
            format!("{}{}", word, mask_part)
        };

        self.mask_idx += 1;
        if self.mask_idx >= self.mask_candidates.len() {
            self.mask_idx = 0;
            self.word_idx += 1;
        }

        Some(result)
    }
}

unsafe impl Send for HybridIterator {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_based_attack() {
        let dict = DictionaryAttack::from_list(vec!["password".to_string()]);
        let rules = vec![
            MutationRule::Noop,
            MutationRule::Uppercase,
            MutationRule::AppendChar('1'),
        ];
        let attack = RuleBasedAttack::new(dict, rules);

        let candidates: Vec<String> = attack.candidates().collect();

        assert_eq!(candidates.len(), 3);
        assert!(candidates.contains(&"password".to_string()));
        assert!(candidates.contains(&"PASSWORD".to_string()));
        assert!(candidates.contains(&"password1".to_string()));
    }

    #[test]
    fn test_parse_hashcat_rule() {
        assert!(matches!(parse_hashcat_rule(":"), Some(MutationRule::Noop)));
        assert!(matches!(parse_hashcat_rule("l"), Some(MutationRule::Lowercase)));
        assert!(matches!(parse_hashcat_rule("u"), Some(MutationRule::Uppercase)));
        assert!(matches!(parse_hashcat_rule("c"), Some(MutationRule::Capitalize)));
        assert!(matches!(parse_hashcat_rule("$1"), Some(MutationRule::AppendChar('1'))));
        assert!(matches!(parse_hashcat_rule("^!"), Some(MutationRule::PrependChar('!'))));
    }

    #[test]
    fn test_common_rules() {
        let dict = DictionaryAttack::from_list(vec!["test".to_string()]);
        let attack = RuleBasedAttack::common_rules(dict);

        let candidates: Vec<String> = attack.candidates().collect();

        assert!(candidates.contains(&"test".to_string()));    // Noop
        assert!(candidates.contains(&"Test".to_string()));    // Capitalize
        assert!(candidates.contains(&"TEST".to_string()));    // Uppercase
        assert!(candidates.contains(&"test1".to_string()));   // Append 1
        assert!(candidates.contains(&"test!".to_string()));   // Append !
        assert!(candidates.contains(&"t3st".to_string()));    // Leet
    }
}
