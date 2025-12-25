//! Local Breach Database
//!
//! Provides an interface for checking credentials against locally stored breach data.
//! This can include imported breach compilations or manually curated breach lists.
//!
//! The local database is primarily used for:
//! - Offline breach checking when external APIs are unavailable
//! - Organization-specific breach data
//! - Custom breach compilations

#![allow(dead_code)]

use anyhow::Result;
use chrono::Utc;
use log::debug;
use std::collections::HashMap;

use super::types::{BreachInfo, BreachSeverity, BreachSource, ExposedCredential};

/// Local breach database
///
/// In-memory database of known breaches. Can be extended to support
/// SQLite-backed storage for larger datasets.
pub struct LocalBreachDb {
    /// Map of email domain to known breach data
    domain_breaches: HashMap<String, Vec<LocalBreachEntry>>,
    /// Map of email to known breach data
    email_breaches: HashMap<String, Vec<LocalBreachEntry>>,
    /// Known breach metadata
    breaches: HashMap<String, BreachInfo>,
}

/// A single entry from the local breach database
#[derive(Debug, Clone)]
pub struct LocalBreachEntry {
    /// The email address
    pub email: String,
    /// The breach name
    pub breach_name: String,
    /// Whether a password hash was included
    pub has_password_hash: bool,
    /// Type of hash if known
    pub hash_type: Option<String>,
}

impl LocalBreachDb {
    /// Create a new local breach database
    pub fn new() -> Result<Self> {
        let mut db = Self {
            domain_breaches: HashMap::new(),
            email_breaches: HashMap::new(),
            breaches: HashMap::new(),
        };

        // Initialize with some common known breaches
        // These are public knowledge breaches for reference
        db.add_known_breach(BreachInfo {
            name: "LinkedIn2021".to_string(),
            title: "LinkedIn 2021 Data Leak".to_string(),
            domain: "linkedin.com".to_string(),
            breach_date: Some(chrono::DateTime::parse_from_rfc3339("2021-04-01T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc)),
            added_date: None,
            modified_date: None,
            pwn_count: Some(700_000_000),
            description: Some("LinkedIn data scraped from public profiles".to_string()),
            data_classes: vec![
                "Email addresses".to_string(),
                "Names".to_string(),
                "Phone numbers".to_string(),
                "Job titles".to_string(),
            ],
            is_verified: true,
            is_fabricated: false,
            is_sensitive: false,
            is_spam_list: false,
            logo_path: None,
            source: BreachSource::LocalDatabase,
            severity: BreachSeverity::Medium,
        });

        db.add_known_breach(BreachInfo {
            name: "RockYou2021".to_string(),
            title: "RockYou2021 Password Compilation".to_string(),
            domain: "compilation".to_string(),
            breach_date: Some(chrono::DateTime::parse_from_rfc3339("2021-06-01T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc)),
            added_date: None,
            modified_date: None,
            pwn_count: Some(8_400_000_000),
            description: Some("Compilation of passwords from many breaches".to_string()),
            data_classes: vec!["Passwords".to_string()],
            is_verified: true,
            is_fabricated: false,
            is_sensitive: false,
            is_spam_list: false,
            logo_path: None,
            source: BreachSource::LocalDatabase,
            severity: BreachSeverity::Critical,
        });

        db.add_known_breach(BreachInfo {
            name: "Collection1".to_string(),
            title: "Collection #1".to_string(),
            domain: "compilation".to_string(),
            breach_date: Some(chrono::DateTime::parse_from_rfc3339("2019-01-16T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc)),
            added_date: None,
            modified_date: None,
            pwn_count: Some(773_000_000),
            description: Some("Large aggregated credential dump from multiple breaches".to_string()),
            data_classes: vec!["Email addresses".to_string(), "Passwords".to_string()],
            is_verified: true,
            is_fabricated: false,
            is_sensitive: false,
            is_spam_list: false,
            logo_path: None,
            source: BreachSource::LocalDatabase,
            severity: BreachSeverity::Critical,
        });

        Ok(db)
    }

    /// Add a known breach to the database
    pub fn add_known_breach(&mut self, breach: BreachInfo) {
        self.breaches.insert(breach.name.clone(), breach);
    }

    /// Add a breach entry for an email
    pub fn add_email_entry(&mut self, entry: LocalBreachEntry) {
        let email_lower = entry.email.to_lowercase();
        let domain = email_lower.split('@').nth(1).unwrap_or("").to_string();

        self.email_breaches
            .entry(email_lower)
            .or_insert_with(Vec::new)
            .push(entry.clone());

        if !domain.is_empty() {
            self.domain_breaches
                .entry(domain)
                .or_insert_with(Vec::new)
                .push(entry);
        }
    }

    /// Import entries from a CSV file (email,breach_name,has_password)
    pub fn import_from_csv(&mut self, csv_data: &str) -> Result<usize> {
        let mut count = 0;

        for line in csv_data.lines().skip(1) {
            // Skip header
            let parts: Vec<&str> = line.split(',').collect();
            if parts.len() >= 2 {
                let email = parts[0].trim().to_lowercase();
                let breach_name = parts[1].trim().to_string();
                let has_password = parts.get(2).map(|s| s.trim() == "true").unwrap_or(false);

                if !email.is_empty() && email.contains('@') {
                    self.add_email_entry(LocalBreachEntry {
                        email,
                        breach_name,
                        has_password_hash: has_password,
                        hash_type: None,
                    });
                    count += 1;
                }
            }
        }

        Ok(count)
    }

    /// Check an email for breaches in the local database
    pub fn check_email(&self, email: &str) -> Option<Vec<ExposedCredential>> {
        let email_lower = email.to_lowercase();
        debug!("Checking local DB for email: {}", email_lower);

        let entries = self.email_breaches.get(&email_lower)?;

        let exposures: Vec<ExposedCredential> = entries
            .iter()
            .filter_map(|entry| {
                let breach = self.breaches.get(&entry.breach_name)?.clone();
                let domain = email_lower.split('@').nth(1).unwrap_or("").to_string();

                Some(ExposedCredential {
                    email: entry.email.clone(),
                    domain,
                    breach,
                    password_hash_exposed: entry.has_password_hash,
                    hash_type: entry.hash_type.clone(),
                    discovered_at: Utc::now(),
                    source: BreachSource::LocalDatabase,
                })
            })
            .collect();

        if exposures.is_empty() {
            None
        } else {
            Some(exposures)
        }
    }

    /// Check a domain for breaches in the local database
    pub fn check_domain(&self, domain: &str) -> Option<Vec<ExposedCredential>> {
        let domain_lower = domain.to_lowercase();
        debug!("Checking local DB for domain: {}", domain_lower);

        let entries = self.domain_breaches.get(&domain_lower)?;

        let exposures: Vec<ExposedCredential> = entries
            .iter()
            .filter_map(|entry| {
                let breach = self.breaches.get(&entry.breach_name)?.clone();
                let email_domain = entry.email.split('@').nth(1).unwrap_or("").to_string();

                Some(ExposedCredential {
                    email: entry.email.clone(),
                    domain: email_domain,
                    breach,
                    password_hash_exposed: entry.has_password_hash,
                    hash_type: entry.hash_type.clone(),
                    discovered_at: Utc::now(),
                    source: BreachSource::LocalDatabase,
                })
            })
            .collect();

        if exposures.is_empty() {
            None
        } else {
            Some(exposures)
        }
    }

    /// Get all known breaches in the local database
    pub fn list_breaches(&self) -> Vec<&BreachInfo> {
        self.breaches.values().collect()
    }

    /// Get statistics about the local database
    pub fn get_stats(&self) -> LocalDbStats {
        LocalDbStats {
            total_emails: self.email_breaches.len(),
            total_domains: self.domain_breaches.len(),
            total_breaches: self.breaches.len(),
            total_entries: self.email_breaches.values().map(|v| v.len()).sum(),
        }
    }
}

/// Statistics about the local breach database
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LocalDbStats {
    /// Number of unique emails in the database
    pub total_emails: usize,
    /// Number of unique domains in the database
    pub total_domains: usize,
    /// Number of unique breaches tracked
    pub total_breaches: usize,
    /// Total number of entries
    pub total_entries: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_local_db_creation() {
        let db = LocalBreachDb::new().unwrap();
        assert!(db.breaches.len() >= 3);
    }

    #[test]
    fn test_add_and_check_email() {
        let mut db = LocalBreachDb::new().unwrap();

        db.add_email_entry(LocalBreachEntry {
            email: "test@example.com".to_string(),
            breach_name: "LinkedIn2021".to_string(),
            has_password_hash: false,
            hash_type: None,
        });

        let result = db.check_email("test@example.com");
        assert!(result.is_some());
        let exposures = result.unwrap();
        assert_eq!(exposures.len(), 1);
        assert_eq!(exposures[0].breach.name, "LinkedIn2021");
    }

    #[test]
    fn test_check_domain() {
        let mut db = LocalBreachDb::new().unwrap();

        db.add_email_entry(LocalBreachEntry {
            email: "user1@company.com".to_string(),
            breach_name: "LinkedIn2021".to_string(),
            has_password_hash: false,
            hash_type: None,
        });

        db.add_email_entry(LocalBreachEntry {
            email: "user2@company.com".to_string(),
            breach_name: "Collection1".to_string(),
            has_password_hash: true,
            hash_type: Some("md5".to_string()),
        });

        let result = db.check_domain("company.com");
        assert!(result.is_some());
        let exposures = result.unwrap();
        assert_eq!(exposures.len(), 2);
    }

    #[test]
    fn test_import_csv() {
        let mut db = LocalBreachDb::new().unwrap();

        let csv = "email,breach_name,has_password\n\
                   test1@test.com,LinkedIn2021,false\n\
                   test2@test.com,Collection1,true\n";

        let count = db.import_from_csv(csv).unwrap();
        assert_eq!(count, 2);

        let stats = db.get_stats();
        assert_eq!(stats.total_emails, 2);
    }
}
