//! Placeholder Engine for Legal Documents
//!
//! This module handles placeholder substitution in legal document templates.
//! Placeholders use the format {{PLACEHOLDER_NAME}} and are replaced with
//! actual values from engagement, customer, and system data.

use anyhow::Result;
use chrono::Utc;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::db::crm::{Customer, Contact, Engagement};
use super::types::PlaceholderInfo;

/// Placeholder engine for substituting template variables
pub struct PlaceholderEngine {
    pattern: Regex,
}

impl Default for PlaceholderEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl PlaceholderEngine {
    /// Create a new placeholder engine
    pub fn new() -> Self {
        // Match {{PLACEHOLDER_NAME}} patterns
        let pattern = Regex::new(r"\{\{([A-Z_]+)\}\}").expect("Invalid regex pattern");
        Self { pattern }
    }

    /// Get list of available placeholders with descriptions
    pub fn get_available_placeholders() -> Vec<PlaceholderInfo> {
        vec![
            PlaceholderInfo {
                key: "CLIENT_NAME".to_string(),
                description: "Client company name".to_string(),
                source: "customers.name".to_string(),
                example: "Acme Corporation".to_string(),
            },
            PlaceholderInfo {
                key: "CLIENT_ADDRESS".to_string(),
                description: "Client company address".to_string(),
                source: "customers.address".to_string(),
                example: "123 Main St, Suite 100, New York, NY 10001".to_string(),
            },
            PlaceholderInfo {
                key: "CLIENT_CONTACT_NAME".to_string(),
                description: "Primary contact full name".to_string(),
                source: "contacts (primary)".to_string(),
                example: "John Smith".to_string(),
            },
            PlaceholderInfo {
                key: "CLIENT_CONTACT_EMAIL".to_string(),
                description: "Primary contact email address".to_string(),
                source: "contacts.email".to_string(),
                example: "john.smith@acme.com".to_string(),
            },
            PlaceholderInfo {
                key: "CLIENT_CONTACT_TITLE".to_string(),
                description: "Primary contact job title".to_string(),
                source: "contacts.title".to_string(),
                example: "Chief Information Security Officer".to_string(),
            },
            PlaceholderInfo {
                key: "ENGAGEMENT_NAME".to_string(),
                description: "Name of the engagement".to_string(),
                source: "engagements.name".to_string(),
                example: "Q1 2026 Penetration Test".to_string(),
            },
            PlaceholderInfo {
                key: "ENGAGEMENT_TYPE".to_string(),
                description: "Type of engagement".to_string(),
                source: "engagements.engagement_type".to_string(),
                example: "Penetration Test".to_string(),
            },
            PlaceholderInfo {
                key: "ENGAGEMENT_SCOPE".to_string(),
                description: "Scope of the engagement".to_string(),
                source: "engagements.scope".to_string(),
                example: "External network penetration test including web applications".to_string(),
            },
            PlaceholderInfo {
                key: "START_DATE".to_string(),
                description: "Engagement start date".to_string(),
                source: "engagements.start_date".to_string(),
                example: "January 15, 2026".to_string(),
            },
            PlaceholderInfo {
                key: "END_DATE".to_string(),
                description: "Engagement end date".to_string(),
                source: "engagements.end_date".to_string(),
                example: "January 31, 2026".to_string(),
            },
            PlaceholderInfo {
                key: "ENGAGEMENT_BUDGET".to_string(),
                description: "Engagement budget/value".to_string(),
                source: "engagements.budget".to_string(),
                example: "$50,000.00".to_string(),
            },
            PlaceholderInfo {
                key: "COMPANY_NAME".to_string(),
                description: "Your company name (provider)".to_string(),
                source: "system settings".to_string(),
                example: "Genial Architect Security".to_string(),
            },
            PlaceholderInfo {
                key: "COMPANY_ADDRESS".to_string(),
                description: "Your company address".to_string(),
                source: "system settings".to_string(),
                example: "456 Security Blvd, Austin, TX 78701".to_string(),
            },
            PlaceholderInfo {
                key: "CURRENT_DATE".to_string(),
                description: "Current date (document generation date)".to_string(),
                source: "dynamic".to_string(),
                example: "January 17, 2026".to_string(),
            },
            PlaceholderInfo {
                key: "CURRENT_YEAR".to_string(),
                description: "Current year".to_string(),
                source: "dynamic".to_string(),
                example: "2026".to_string(),
            },
        ]
    }

    /// Build a values map from engagement, customer, and contact data
    pub fn build_values_map(
        customer: &Customer,
        engagement: &Engagement,
        primary_contact: Option<&Contact>,
        company_name: &str,
        company_address: &str,
    ) -> HashMap<String, String> {
        let mut values = HashMap::new();

        // Customer data
        values.insert("CLIENT_NAME".to_string(), customer.name.clone());
        values.insert(
            "CLIENT_ADDRESS".to_string(),
            customer.address.clone().unwrap_or_else(|| "[Address not provided]".to_string()),
        );

        // Contact data
        if let Some(contact) = primary_contact {
            values.insert(
                "CLIENT_CONTACT_NAME".to_string(),
                format!("{} {}", contact.first_name, contact.last_name),
            );
            values.insert(
                "CLIENT_CONTACT_EMAIL".to_string(),
                contact.email.clone().unwrap_or_else(|| "[Email not provided]".to_string()),
            );
            values.insert(
                "CLIENT_CONTACT_TITLE".to_string(),
                contact.title.clone().unwrap_or_else(|| "[Title not provided]".to_string()),
            );
        } else {
            values.insert("CLIENT_CONTACT_NAME".to_string(), "[Contact not assigned]".to_string());
            values.insert("CLIENT_CONTACT_EMAIL".to_string(), "[Email not provided]".to_string());
            values.insert("CLIENT_CONTACT_TITLE".to_string(), "[Title not provided]".to_string());
        }

        // Engagement data
        values.insert("ENGAGEMENT_NAME".to_string(), engagement.name.clone());
        values.insert("ENGAGEMENT_TYPE".to_string(), Self::format_engagement_type(&engagement.engagement_type));
        values.insert(
            "ENGAGEMENT_SCOPE".to_string(),
            engagement.scope.clone().unwrap_or_else(|| "[Scope to be determined]".to_string()),
        );
        values.insert(
            "START_DATE".to_string(),
            engagement.start_date.as_ref()
                .map(|d| Self::format_date(d))
                .unwrap_or_else(|| "[Start date TBD]".to_string()),
        );
        values.insert(
            "END_DATE".to_string(),
            engagement.end_date.as_ref()
                .map(|d| Self::format_date(d))
                .unwrap_or_else(|| "[End date TBD]".to_string()),
        );
        values.insert(
            "ENGAGEMENT_BUDGET".to_string(),
            engagement.budget
                .map(|b| format!("${:.2}", b))
                .unwrap_or_else(|| "[Budget TBD]".to_string()),
        );

        // Provider/Company data
        values.insert("COMPANY_NAME".to_string(), company_name.to_string());
        values.insert("COMPANY_ADDRESS".to_string(), company_address.to_string());

        // Dynamic values
        let now = Utc::now();
        values.insert("CURRENT_DATE".to_string(), now.format("%B %d, %Y").to_string());
        values.insert("CURRENT_YEAR".to_string(), now.format("%Y").to_string());

        values
    }

    /// Replace all placeholders in the content with actual values
    pub fn replace_placeholders(&self, content: &str, values: &HashMap<String, String>) -> String {
        self.pattern.replace_all(content, |caps: &regex::Captures| {
            let key = &caps[1];
            values.get(key)
                .cloned()
                .unwrap_or_else(|| format!("{{{{{}}}}} ", key))  // Keep placeholder if not found
        }).to_string()
    }

    /// Extract all placeholders from a template
    pub fn extract_placeholders(&self, content: &str) -> Vec<String> {
        self.pattern
            .captures_iter(content)
            .map(|cap| cap[1].to_string())
            .collect()
    }

    /// Validate that all placeholders in content have values
    pub fn validate_placeholders(&self, content: &str, values: &HashMap<String, String>) -> Vec<String> {
        let placeholders = self.extract_placeholders(content);
        placeholders
            .into_iter()
            .filter(|p| !values.contains_key(p))
            .collect()
    }

    /// Format date string (ISO 8601 or YYYY-MM-DD) to human readable
    fn format_date(date_str: &str) -> String {
        // Try parsing as ISO 8601 first
        if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(date_str) {
            return dt.format("%B %d, %Y").to_string();
        }
        // Try parsing as YYYY-MM-DD
        if let Ok(dt) = chrono::NaiveDate::parse_from_str(date_str, "%Y-%m-%d") {
            return dt.format("%B %d, %Y").to_string();
        }
        // Return as-is if parsing fails
        date_str.to_string()
    }

    /// Format engagement type to human readable
    fn format_engagement_type(engagement_type: &str) -> String {
        match engagement_type.to_lowercase().as_str() {
            "pentest" | "penetration_test" => "Penetration Test".to_string(),
            "vuln_assessment" | "vulnerability_assessment" => "Vulnerability Assessment".to_string(),
            "red_team" => "Red Team Engagement".to_string(),
            "purple_team" => "Purple Team Exercise".to_string(),
            "security_audit" => "Security Audit".to_string(),
            "compliance_assessment" => "Compliance Assessment".to_string(),
            "incident_response" => "Incident Response".to_string(),
            "consulting" => "Security Consulting".to_string(),
            _ => engagement_type.replace('_', " ").to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_placeholder_extraction() {
        let engine = PlaceholderEngine::new();
        let content = "Dear {{CLIENT_NAME}}, this agreement is for {{ENGAGEMENT_NAME}}.";
        let placeholders = engine.extract_placeholders(content);
        assert_eq!(placeholders.len(), 2);
        assert!(placeholders.contains(&"CLIENT_NAME".to_string()));
        assert!(placeholders.contains(&"ENGAGEMENT_NAME".to_string()));
    }

    #[test]
    fn test_placeholder_replacement() {
        let engine = PlaceholderEngine::new();
        let content = "Dear {{CLIENT_NAME}}, welcome to {{COMPANY_NAME}}.";
        let mut values = HashMap::new();
        values.insert("CLIENT_NAME".to_string(), "Acme Corp".to_string());
        values.insert("COMPANY_NAME".to_string(), "Security Inc".to_string());

        let result = engine.replace_placeholders(content, &values);
        assert_eq!(result, "Dear Acme Corp, welcome to Security Inc.");
    }

    #[test]
    fn test_missing_placeholder_preserved() {
        let engine = PlaceholderEngine::new();
        let content = "Dear {{CLIENT_NAME}}, your {{UNKNOWN_FIELD}} is ready.";
        let mut values = HashMap::new();
        values.insert("CLIENT_NAME".to_string(), "Acme Corp".to_string());

        let result = engine.replace_placeholders(content, &values);
        assert!(result.contains("{{UNKNOWN_FIELD}}"));
    }

    #[test]
    fn test_date_formatting() {
        assert_eq!(
            PlaceholderEngine::format_date("2026-01-15"),
            "January 15, 2026"
        );
    }
}
