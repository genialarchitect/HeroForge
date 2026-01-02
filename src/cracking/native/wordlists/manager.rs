//! Wordlist manager
//!
//! Manages wordlist files and provides utilities for wordlist operations.

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};

/// Wordlist metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WordlistInfo {
    /// Wordlist ID
    pub id: String,
    /// Name
    pub name: String,
    /// Description
    pub description: Option<String>,
    /// File path
    pub path: PathBuf,
    /// File size in bytes
    pub size_bytes: u64,
    /// Line count (word count)
    pub line_count: u64,
    /// Category
    pub category: String,
    /// Is built-in
    pub is_builtin: bool,
}

/// Wordlist manager
pub struct WordlistManager {
    /// Base directory for wordlists
    base_dir: PathBuf,
    /// Cached wordlist metadata
    cache: HashMap<String, WordlistInfo>,
}

impl WordlistManager {
    /// Create a new wordlist manager
    pub fn new(base_dir: impl Into<PathBuf>) -> Self {
        let base_dir = base_dir.into();
        Self {
            base_dir,
            cache: HashMap::new(),
        }
    }

    /// Initialize the manager (create directories, scan existing files)
    pub fn init(&mut self) -> std::io::Result<()> {
        // Create base directory if needed
        fs::create_dir_all(&self.base_dir)?;

        // Create subdirectories
        fs::create_dir_all(self.base_dir.join("common"))?;
        fs::create_dir_all(self.base_dir.join("leaked"))?;
        fs::create_dir_all(self.base_dir.join("custom"))?;
        fs::create_dir_all(self.base_dir.join("rules"))?;

        // Scan existing wordlists
        self.scan_directory()?;

        Ok(())
    }

    /// Scan directory for wordlists
    fn scan_directory(&mut self) -> std::io::Result<()> {
        self.cache.clear();

        for category in ["common", "leaked", "custom"] {
            let dir = self.base_dir.join(category);
            if dir.exists() {
                for entry in fs::read_dir(dir)? {
                    let entry = entry?;
                    let path = entry.path();
                    if path.is_file() {
                        if let Ok(info) = self.analyze_wordlist(&path, category) {
                            self.cache.insert(info.id.clone(), info);
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Analyze a wordlist file
    fn analyze_wordlist(&self, path: &Path, category: &str) -> std::io::Result<WordlistInfo> {
        let metadata = fs::metadata(path)?;
        let size_bytes = metadata.len();

        // Count lines
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let line_count = reader.lines().count() as u64;

        let name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string();

        let id = format!("{}_{}", category, name);

        Ok(WordlistInfo {
            id,
            name,
            description: None,
            path: path.to_path_buf(),
            size_bytes,
            line_count,
            category: category.to_string(),
            is_builtin: category == "common",
        })
    }

    /// Get wordlist by ID
    pub fn get(&self, id: &str) -> Option<&WordlistInfo> {
        self.cache.get(id)
    }

    /// List all wordlists
    pub fn list(&self) -> Vec<&WordlistInfo> {
        self.cache.values().collect()
    }

    /// List wordlists by category
    pub fn list_by_category(&self, category: &str) -> Vec<&WordlistInfo> {
        self.cache
            .values()
            .filter(|w| w.category == category)
            .collect()
    }

    /// Add a new wordlist from content
    pub fn add_wordlist(
        &mut self,
        name: &str,
        category: &str,
        words: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> std::io::Result<WordlistInfo> {
        let filename = format!("{}.txt", name.replace(' ', "_").to_lowercase());
        let path = self.base_dir.join(category).join(&filename);

        // Write words to file
        let mut file = File::create(&path)?;
        let mut count = 0u64;
        for word in words {
            writeln!(file, "{}", word.as_ref())?;
            count += 1;
        }

        let size_bytes = fs::metadata(&path)?.len();
        let id = format!("{}_{}", category, name.replace(' ', "_").to_lowercase());

        let info = WordlistInfo {
            id: id.clone(),
            name: name.to_string(),
            description: None,
            path,
            size_bytes,
            line_count: count,
            category: category.to_string(),
            is_builtin: false,
        };

        self.cache.insert(id, info.clone());
        Ok(info)
    }

    /// Add wordlist from file
    pub fn add_wordlist_file(
        &mut self,
        source_path: &Path,
        name: Option<&str>,
        category: &str,
    ) -> std::io::Result<WordlistInfo> {
        let source_name = source_path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("wordlist");

        let name = name.unwrap_or(source_name);
        let filename = format!("{}.txt", name.replace(' ', "_").to_lowercase());
        let dest_path = self.base_dir.join(category).join(&filename);

        // Copy file
        fs::copy(source_path, &dest_path)?;

        // Analyze the wordlist
        let info = self.analyze_wordlist(&dest_path, category)?;
        self.cache.insert(info.id.clone(), info.clone());

        Ok(info)
    }

    /// Delete a wordlist
    pub fn delete(&mut self, id: &str) -> std::io::Result<bool> {
        if let Some(info) = self.cache.remove(id) {
            if !info.is_builtin {
                fs::remove_file(&info.path)?;
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Create embedded wordlists as files
    pub fn create_embedded_wordlists(&mut self) -> std::io::Result<()> {
        use super::embedded::EmbeddedWordlists;

        // Create top100 wordlist
        self.add_wordlist(
            "top100",
            "common",
            EmbeddedWordlists::top_100(),
        )?;

        // Create top1000 wordlist
        self.add_wordlist(
            "top1000",
            "common",
            EmbeddedWordlists::top_1000(),
        )?;

        // Create number sequences
        self.add_wordlist(
            "numbers",
            "common",
            EmbeddedWordlists::number_sequences(),
        )?;

        // Create wifi passwords
        self.add_wordlist(
            "wifi",
            "common",
            EmbeddedWordlists::wifi_passwords(),
        )?;

        // Create tech passwords
        self.add_wordlist(
            "tech",
            "common",
            EmbeddedWordlists::tech_passwords(),
        )?;

        Ok(())
    }

    /// Combine multiple wordlists into one
    pub fn combine(
        &mut self,
        ids: &[&str],
        output_name: &str,
        deduplicate: bool,
    ) -> std::io::Result<WordlistInfo> {
        let mut words: Vec<String> = Vec::new();

        for id in ids {
            if let Some(info) = self.cache.get(*id) {
                let file = File::open(&info.path)?;
                let reader = BufReader::new(file);
                for line in reader.lines() {
                    if let Ok(word) = line {
                        if !word.is_empty() {
                            words.push(word);
                        }
                    }
                }
            }
        }

        if deduplicate {
            words.sort();
            words.dedup();
        }

        self.add_wordlist(output_name, "custom", words)
    }

    /// Filter wordlist by length
    pub fn filter_by_length(
        &mut self,
        id: &str,
        min_length: usize,
        max_length: usize,
        output_name: &str,
    ) -> std::io::Result<WordlistInfo> {
        let info = self.cache.get(id).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::NotFound, "Wordlist not found")
        })?;

        let file = File::open(&info.path)?;
        let reader = BufReader::new(file);

        let filtered: Vec<String> = reader
            .lines()
            .filter_map(|line| line.ok())
            .filter(|word| word.len() >= min_length && word.len() <= max_length)
            .collect();

        self.add_wordlist(output_name, "custom", filtered)
    }

    /// Generate password variants based on a policy
    pub fn generate_policy_wordlist(
        &mut self,
        base_id: &str,
        output_name: &str,
        min_length: usize,
        require_uppercase: bool,
        require_digit: bool,
        require_special: bool,
    ) -> std::io::Result<WordlistInfo> {
        let info = self.cache.get(base_id).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::NotFound, "Wordlist not found")
        })?;

        let file = File::open(&info.path)?;
        let reader = BufReader::new(file);

        let mut variants: Vec<String> = Vec::new();

        for line in reader.lines() {
            let word = line?;
            if word.is_empty() {
                continue;
            }

            // Generate variants that meet the policy
            let mut candidates = vec![word.clone()];

            if require_uppercase {
                let capitalized = capitalize_first(&word);
                let all_upper = word.to_uppercase();
                candidates.push(capitalized);
                candidates.push(all_upper);
            }

            // Add digit variants
            if require_digit {
                let with_digits: Vec<String> = candidates
                    .iter()
                    .flat_map(|w| {
                        vec![
                            format!("{}1", w),
                            format!("{}123", w),
                            format!("1{}", w),
                        ]
                    })
                    .collect();
                candidates.extend(with_digits);
            }

            // Add special char variants
            if require_special {
                let with_special: Vec<String> = candidates
                    .iter()
                    .flat_map(|w| {
                        vec![
                            format!("{}!", w),
                            format!("{}@", w),
                            format!("{}#", w),
                        ]
                    })
                    .collect();
                candidates.extend(with_special);
            }

            // Filter by length and policy compliance
            for candidate in candidates {
                if candidate.len() >= min_length
                    && (!require_uppercase || candidate.chars().any(|c| c.is_uppercase()))
                    && (!require_digit || candidate.chars().any(|c| c.is_ascii_digit()))
                    && (!require_special || candidate.chars().any(|c| !c.is_alphanumeric()))
                {
                    variants.push(candidate);
                }
            }
        }

        variants.sort();
        variants.dedup();

        self.add_wordlist(output_name, "custom", variants)
    }

    /// Get base directory
    pub fn base_dir(&self) -> &Path {
        &self.base_dir
    }
}

fn capitalize_first(s: &str) -> String {
    let mut chars: Vec<char> = s.chars().collect();
    if let Some(first) = chars.first_mut() {
        *first = first.to_uppercase().next().unwrap_or(*first);
    }
    chars.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_wordlist_manager_init() {
        let temp_dir = TempDir::new().unwrap();
        let mut manager = WordlistManager::new(temp_dir.path());
        manager.init().unwrap();

        assert!(temp_dir.path().join("common").exists());
        assert!(temp_dir.path().join("leaked").exists());
        assert!(temp_dir.path().join("custom").exists());
    }

    #[test]
    fn test_add_wordlist() {
        let temp_dir = TempDir::new().unwrap();
        let mut manager = WordlistManager::new(temp_dir.path());
        manager.init().unwrap();

        let words = vec!["password", "123456", "admin"];
        let info = manager.add_wordlist("test", "custom", words).unwrap();

        assert_eq!(info.line_count, 3);
        assert_eq!(info.category, "custom");
        assert!(info.path.exists());
    }

    #[test]
    fn test_list_wordlists() {
        let temp_dir = TempDir::new().unwrap();
        let mut manager = WordlistManager::new(temp_dir.path());
        manager.init().unwrap();

        manager.add_wordlist("test1", "common", vec!["a", "b"]).unwrap();
        manager.add_wordlist("test2", "custom", vec!["c", "d"]).unwrap();

        assert_eq!(manager.list().len(), 2);
        assert_eq!(manager.list_by_category("common").len(), 1);
        assert_eq!(manager.list_by_category("custom").len(), 1);
    }

    #[test]
    fn test_combine_wordlists() {
        let temp_dir = TempDir::new().unwrap();
        let mut manager = WordlistManager::new(temp_dir.path());
        manager.init().unwrap();

        manager.add_wordlist("list1", "common", vec!["a", "b"]).unwrap();
        manager.add_wordlist("list2", "common", vec!["b", "c"]).unwrap();

        let combined = manager.combine(
            &["common_list1", "common_list2"],
            "combined",
            true,
        ).unwrap();

        assert_eq!(combined.line_count, 3); // deduplicated
    }
}
