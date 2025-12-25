#![allow(dead_code)]

use anyhow::{anyhow, Result};
use log::{debug, info, warn};
use reqwest::Client;
use serde::Deserialize;
use std::collections::HashSet;
use std::time::Duration;

/// Certificate Transparency log entry from crt.sh
#[derive(Debug, Deserialize)]
struct CrtShEntry {
    #[serde(default)]
    issuer_ca_id: Option<i64>,
    #[serde(default)]
    issuer_name: Option<String>,
    #[serde(default)]
    common_name: Option<String>,
    #[serde(default)]
    name_value: Option<String>,
    #[serde(default)]
    id: Option<i64>,
    #[serde(default)]
    entry_timestamp: Option<String>,
    #[serde(default)]
    not_before: Option<String>,
    #[serde(default)]
    not_after: Option<String>,
    #[serde(default)]
    serial_number: Option<String>,
}

/// Search Certificate Transparency logs for subdomains
pub async fn search_ct_logs(domain: &str, timeout_secs: u64) -> Result<Vec<String>> {
    info!("Searching Certificate Transparency logs for: {}", domain);

    let client = Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .user_agent("HeroForge Security Scanner")
        .build()?;

    // Query crt.sh API
    let url = format!(
        "https://crt.sh/?q=%.{}&output=json",
        urlencoding::encode(domain)
    );

    debug!("Fetching CT logs from: {}", url);

    let response = match client.get(&url).send().await {
        Ok(resp) => resp,
        Err(e) => {
            warn!("Failed to fetch CT logs from crt.sh: {}", e);
            return Err(anyhow!("Failed to fetch CT logs: {}", e));
        }
    };

    if !response.status().is_success() {
        let status = response.status();
        warn!("crt.sh returned error status: {}", status);
        return Err(anyhow!("crt.sh returned error: {}", status));
    }

    let text = response.text().await?;

    // Handle empty response
    if text.trim().is_empty() || text.trim() == "[]" {
        info!("No CT log entries found for {}", domain);
        return Ok(Vec::new());
    }

    // Parse JSON response
    let entries: Vec<CrtShEntry> = match serde_json::from_str(&text) {
        Ok(e) => e,
        Err(e) => {
            warn!("Failed to parse crt.sh response: {}", e);
            // Try to extract subdomains from raw text as fallback
            return extract_subdomains_from_text(&text, domain);
        }
    };

    // Extract unique subdomains from name_value and common_name fields
    let mut subdomains: HashSet<String> = HashSet::new();
    let domain_lower = domain.to_lowercase();

    for entry in entries {
        // Process name_value (can contain multiple names separated by newlines)
        if let Some(name_value) = entry.name_value {
            for name in name_value.split('\n') {
                let name = name.trim().to_lowercase();
                if is_valid_subdomain(&name, &domain_lower) {
                    subdomains.insert(name);
                }
            }
        }

        // Process common_name
        if let Some(common_name) = entry.common_name {
            let name = common_name.trim().to_lowercase();
            if is_valid_subdomain(&name, &domain_lower) {
                subdomains.insert(name);
            }
        }
    }

    // Remove wildcard prefix and deduplicate
    let cleaned: Vec<String> = subdomains
        .into_iter()
        .map(|s| s.trim_start_matches("*.").to_string())
        .filter(|s| !s.is_empty() && s.ends_with(&domain_lower))
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();

    info!(
        "Found {} unique subdomains from CT logs for {}",
        cleaned.len(),
        domain
    );

    Ok(cleaned)
}

/// Validate if a name is a valid subdomain of the target domain
fn is_valid_subdomain(name: &str, domain: &str) -> bool {
    // Skip empty names
    if name.is_empty() {
        return false;
    }

    // Skip wildcard-only entries
    if name == "*" || name == "*." {
        return false;
    }

    // Must end with the target domain
    let name_clean = name.trim_start_matches("*.");
    if !name_clean.ends_with(domain) {
        return false;
    }

    // Skip very long names (likely noise)
    if name_clean.len() > 255 {
        return false;
    }

    // Check for valid hostname characters
    let valid_chars = name_clean
        .chars()
        .all(|c| c.is_alphanumeric() || c == '.' || c == '-' || c == '_');

    valid_chars
}

/// Fallback: extract subdomains from raw text response
fn extract_subdomains_from_text(text: &str, domain: &str) -> Result<Vec<String>> {
    let mut subdomains: HashSet<String> = HashSet::new();
    let domain_lower = domain.to_lowercase();

    // Simple regex-like pattern matching for domain names
    for word in text.split(|c: char| !c.is_alphanumeric() && c != '.' && c != '-' && c != '_') {
        let word = word.trim().to_lowercase();
        if is_valid_subdomain(&word, &domain_lower) {
            let cleaned = word.trim_start_matches("*.").to_string();
            subdomains.insert(cleaned);
        }
    }

    Ok(subdomains.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_valid_subdomain() {
        assert!(is_valid_subdomain("www.example.com", "example.com"));
        assert!(is_valid_subdomain("*.example.com", "example.com"));
        assert!(is_valid_subdomain("api.test.example.com", "example.com"));
        assert!(!is_valid_subdomain("example.com", "test.com"));
        assert!(!is_valid_subdomain("", "example.com"));
        assert!(!is_valid_subdomain("*", "example.com"));
    }
}
