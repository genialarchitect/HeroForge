//! Dictionary attack implementation
//!
//! Simple wordlist-based password cracking.

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use super::Attack;

/// Dictionary attack using wordlists
#[derive(Debug, Clone)]
pub struct DictionaryAttack {
    /// Words loaded into memory
    words: Vec<String>,
    /// Wordlist file paths (for lazy loading)
    wordlist_paths: Vec<String>,
}

impl DictionaryAttack {
    /// Create from a list of words
    pub fn from_list(words: Vec<String>) -> Self {
        Self {
            words,
            wordlist_paths: Vec::new(),
        }
    }

    /// Create from wordlist file paths
    pub fn from_files(paths: Vec<String>) -> Self {
        Self {
            words: Vec::new(),
            wordlist_paths: paths,
        }
    }

    /// Load words from a file
    pub fn load_file<P: AsRef<Path>>(path: P) -> std::io::Result<Self> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let words: Vec<String> = reader
            .lines()
            .filter_map(|line| line.ok())
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .collect();

        Ok(Self {
            words,
            wordlist_paths: Vec::new(),
        })
    }

    /// Add more words to the dictionary
    pub fn add_words(&mut self, words: impl IntoIterator<Item = String>) {
        self.words.extend(words);
    }

    /// Add a wordlist file
    pub fn add_wordlist_file(&mut self, path: String) {
        self.wordlist_paths.push(path);
    }

    /// Get total word count
    pub fn word_count(&self) -> usize {
        self.words.len()
    }
}

impl Attack for DictionaryAttack {
    fn name(&self) -> &'static str {
        "Dictionary"
    }

    fn estimate_candidates(&self) -> Option<u64> {
        if self.wordlist_paths.is_empty() {
            Some(self.words.len() as u64)
        } else {
            // Can't easily estimate without reading files
            None
        }
    }

    fn candidates(&self) -> Box<dyn Iterator<Item = String> + Send> {
        // First yield in-memory words
        let mem_words = self.words.clone();
        let file_paths = self.wordlist_paths.clone();

        Box::new(DictionaryIterator {
            mem_words: mem_words.into_iter(),
            file_paths: file_paths.into_iter(),
            current_reader: None,
        })
    }
}

/// Iterator that yields words from memory and files
struct DictionaryIterator {
    mem_words: std::vec::IntoIter<String>,
    file_paths: std::vec::IntoIter<String>,
    current_reader: Option<std::io::Lines<BufReader<File>>>,
}

impl Iterator for DictionaryIterator {
    type Item = String;

    fn next(&mut self) -> Option<Self::Item> {
        // First try in-memory words
        if let Some(word) = self.mem_words.next() {
            return Some(word);
        }

        // Then try current file reader
        loop {
            if let Some(ref mut reader) = self.current_reader {
                while let Some(Ok(line)) = reader.next() {
                    if !line.is_empty() && !line.starts_with('#') {
                        return Some(line);
                    }
                }
            }

            // Try next file
            if let Some(path) = self.file_paths.next() {
                if let Ok(file) = File::open(&path) {
                    self.current_reader = Some(BufReader::new(file).lines());
                    continue;
                }
            }

            break;
        }

        None
    }
}

// Make iterator Send by not holding file handles across yield points
// This is a simplified version - for production, use a channel-based approach
unsafe impl Send for DictionaryIterator {}

/// Combined dictionary attack with multiple wordlists
pub struct CombinatorAttack {
    /// First wordlist
    pub first: DictionaryAttack,
    /// Second wordlist
    pub second: DictionaryAttack,
}

impl CombinatorAttack {
    /// Create a combinator attack from two wordlists
    pub fn new(first: DictionaryAttack, second: DictionaryAttack) -> Self {
        Self { first, second }
    }
}

impl Attack for CombinatorAttack {
    fn name(&self) -> &'static str {
        "Combinator"
    }

    fn estimate_candidates(&self) -> Option<u64> {
        let first_count = self.first.estimate_candidates()?;
        let second_count = self.second.estimate_candidates()?;
        Some(first_count * second_count)
    }

    fn candidates(&self) -> Box<dyn Iterator<Item = String> + Send> {
        let first_words: Vec<String> = self.first.candidates().collect();
        let second_words: Vec<String> = self.second.candidates().collect();

        Box::new(CombinatorIterator {
            first_words,
            second_words,
            first_idx: 0,
            second_idx: 0,
        })
    }
}

struct CombinatorIterator {
    first_words: Vec<String>,
    second_words: Vec<String>,
    first_idx: usize,
    second_idx: usize,
}

impl Iterator for CombinatorIterator {
    type Item = String;

    fn next(&mut self) -> Option<Self::Item> {
        if self.first_idx >= self.first_words.len() {
            return None;
        }

        let result = format!(
            "{}{}",
            self.first_words[self.first_idx],
            self.second_words[self.second_idx]
        );

        self.second_idx += 1;
        if self.second_idx >= self.second_words.len() {
            self.second_idx = 0;
            self.first_idx += 1;
        }

        Some(result)
    }
}

unsafe impl Send for CombinatorIterator {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dictionary_attack() {
        let attack = DictionaryAttack::from_list(vec![
            "password".to_string(),
            "123456".to_string(),
            "admin".to_string(),
        ]);

        let candidates: Vec<String> = attack.candidates().collect();
        assert_eq!(candidates.len(), 3);
        assert!(candidates.contains(&"password".to_string()));
    }

    #[test]
    fn test_combinator_attack() {
        let first = DictionaryAttack::from_list(vec!["admin".to_string(), "root".to_string()]);
        let second = DictionaryAttack::from_list(vec!["123".to_string(), "456".to_string()]);

        let attack = CombinatorAttack::new(first, second);
        let candidates: Vec<String> = attack.candidates().collect();

        assert_eq!(candidates.len(), 4);
        assert!(candidates.contains(&"admin123".to_string()));
        assert!(candidates.contains(&"admin456".to_string()));
        assert!(candidates.contains(&"root123".to_string()));
        assert!(candidates.contains(&"root456".to_string()));
    }

    #[test]
    fn test_estimate_candidates() {
        let attack = DictionaryAttack::from_list(vec![
            "a".to_string(),
            "b".to_string(),
            "c".to_string(),
        ]);

        assert_eq!(attack.estimate_candidates(), Some(3));
    }
}
