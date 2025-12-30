//! Playbook marketplace for sharing and discovering playbooks

use crate::green_team::types::*;
use chrono::Utc;
use std::collections::HashMap;
use uuid::Uuid;

/// Marketplace for playbook templates
pub struct PlaybookMarketplace {
    playbooks: HashMap<Uuid, MarketplacePlaybook>,
    ratings: HashMap<Uuid, Vec<PlaybookRating>>,
}

impl PlaybookMarketplace {
    /// Create a new marketplace
    pub fn new() -> Self {
        let mut marketplace = Self {
            playbooks: HashMap::new(),
            ratings: HashMap::new(),
        };
        marketplace.seed_default_playbooks();
        marketplace
    }

    /// Seed default playbooks
    fn seed_default_playbooks(&mut self) {
        let playbooks = vec![
            MarketplacePlaybook {
                id: Uuid::new_v4(),
                name: "Phishing Response".to_string(),
                description: "Automated response to phishing alerts including email analysis, IOC extraction, and user notification.".to_string(),
                author: "Genial Architect".to_string(),
                category: PlaybookCategory::IncidentResponse,
                tags: vec!["phishing".to_string(), "email".to_string(), "ioc".to_string()],
                version: "1.0.0".to_string(),
                downloads: 1250,
                rating: 4.5,
                ratings_count: 45,
                playbook_json: serde_json::json!({
                    "steps": [
                        {"id": "1", "name": "Extract IOCs", "action": {"type": "enrich_ioc", "ioc_type": "email", "sources": ["virustotal", "urlscan"]}},
                        {"id": "2", "name": "Block sender", "action": {"type": "block_ip", "ip_template": "{{ input.sender_ip }}", "firewall": "palo_alto"}},
                        {"id": "3", "name": "Notify user", "action": {"type": "send_notification", "channel": "email", "template": "phishing_alert"}}
                    ]
                }),
                is_verified: true,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            },
            MarketplacePlaybook {
                id: Uuid::new_v4(),
                name: "Malware Containment".to_string(),
                description: "Immediate containment of malware-infected hosts with isolation, evidence collection, and incident creation.".to_string(),
                author: "Genial Architect".to_string(),
                category: PlaybookCategory::IncidentResponse,
                tags: vec!["malware".to_string(), "containment".to_string(), "edr".to_string()],
                version: "1.2.0".to_string(),
                downloads: 890,
                rating: 4.8,
                ratings_count: 32,
                playbook_json: serde_json::json!({
                    "steps": [
                        {"id": "1", "name": "Isolate host", "action": {"type": "isolate_host", "hostname_template": "{{ input.hostname }}", "agent_type": "crowdstrike"}},
                        {"id": "2", "name": "Create case", "action": {"type": "create_case", "title": "Malware detected on {{ input.hostname }}", "severity": "high", "case_type": "incident"}},
                        {"id": "3", "name": "Collect memory", "action": {"type": "run_script", "script": "collect_memory.ps1", "interpreter": "powershell"}}
                    ]
                }),
                is_verified: true,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            },
            MarketplacePlaybook {
                id: Uuid::new_v4(),
                name: "IOC Enrichment".to_string(),
                description: "Automated enrichment of IOCs from multiple threat intelligence sources.".to_string(),
                author: "Genial Architect".to_string(),
                category: PlaybookCategory::Enrichment,
                tags: vec!["ioc".to_string(), "threat_intel".to_string(), "enrichment".to_string()],
                version: "1.1.0".to_string(),
                downloads: 2100,
                rating: 4.6,
                ratings_count: 78,
                playbook_json: serde_json::json!({
                    "steps": [
                        {"id": "1", "name": "VirusTotal lookup", "action": {"type": "enrich_ioc", "sources": ["virustotal"]}},
                        {"id": "2", "name": "Shodan lookup", "action": {"type": "enrich_ioc", "sources": ["shodan"]}},
                        {"id": "3", "name": "AbuseIPDB lookup", "action": {"type": "enrich_ioc", "sources": ["abuseipdb"]}},
                        {"id": "4", "name": "Store results", "action": {"type": "set_variable", "name": "enrichment_complete", "value": "true"}}
                    ]
                }),
                is_verified: true,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            },
            MarketplacePlaybook {
                id: Uuid::new_v4(),
                name: "Suspicious Login Response".to_string(),
                description: "Respond to suspicious login attempts with user verification and conditional account lockout.".to_string(),
                author: "Community".to_string(),
                category: PlaybookCategory::IncidentResponse,
                tags: vec!["authentication".to_string(), "login".to_string(), "brute_force".to_string()],
                version: "1.0.0".to_string(),
                downloads: 650,
                rating: 4.2,
                ratings_count: 18,
                playbook_json: serde_json::json!({
                    "steps": [
                        {"id": "1", "name": "Check login history", "action": {"type": "http_request", "method": "GET", "url": "{{ config.siem_url }}/api/user_logins/{{ input.username }}"}},
                        {"id": "2", "name": "Notify user", "action": {"type": "send_notification", "channel": "email", "template": "suspicious_login"}},
                        {"id": "3", "name": "Wait for response", "action": {"type": "wait_for_approval", "approvers": ["{{ input.username }}"], "timeout_hours": 1, "message": "Was this you?"}}
                    ]
                }),
                is_verified: false,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            },
            MarketplacePlaybook {
                id: Uuid::new_v4(),
                name: "Vulnerability Notification".to_string(),
                description: "Notify asset owners about critical vulnerabilities with remediation guidance.".to_string(),
                author: "Community".to_string(),
                category: PlaybookCategory::Notification,
                tags: vec!["vulnerability".to_string(), "notification".to_string(), "remediation".to_string()],
                version: "1.0.0".to_string(),
                downloads: 420,
                rating: 4.0,
                ratings_count: 12,
                playbook_json: serde_json::json!({
                    "steps": [
                        {"id": "1", "name": "Get asset owner", "action": {"type": "http_request", "method": "GET", "url": "{{ config.cmdb_url }}/api/assets/{{ input.asset_id }}/owner"}},
                        {"id": "2", "name": "Create ticket", "action": {"type": "create_ticket", "system": "jira", "title": "Critical vulnerability on {{ input.asset_name }}", "priority": "high"}},
                        {"id": "3", "name": "Notify owner", "action": {"type": "send_notification", "channel": "slack", "template": "vuln_alert"}}
                    ]
                }),
                is_verified: false,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            },
        ];

        for playbook in playbooks {
            self.playbooks.insert(playbook.id, playbook);
        }
    }

    /// Search playbooks in the marketplace
    pub fn search(&self, query: &str, category: Option<&PlaybookCategory>) -> Vec<&MarketplacePlaybook> {
        let query_lower = query.to_lowercase();

        self.playbooks
            .values()
            .filter(|p| {
                // Filter by category if specified
                if let Some(cat) = category {
                    if &p.category != cat {
                        return false;
                    }
                }

                // Search in name, description, and tags
                if query.is_empty() {
                    return true;
                }

                p.name.to_lowercase().contains(&query_lower)
                    || p.description.to_lowercase().contains(&query_lower)
                    || p.tags.iter().any(|t| t.to_lowercase().contains(&query_lower))
            })
            .collect()
    }

    /// Get a playbook by ID
    pub fn get(&self, id: &Uuid) -> Option<&MarketplacePlaybook> {
        self.playbooks.get(id)
    }

    /// List top playbooks by downloads
    pub fn top_by_downloads(&self, limit: usize) -> Vec<&MarketplacePlaybook> {
        let mut playbooks: Vec<_> = self.playbooks.values().collect();
        playbooks.sort_by(|a, b| b.downloads.cmp(&a.downloads));
        playbooks.into_iter().take(limit).collect()
    }

    /// List top playbooks by rating
    pub fn top_by_rating(&self, limit: usize) -> Vec<&MarketplacePlaybook> {
        let mut playbooks: Vec<_> = self.playbooks.values().collect();
        playbooks.sort_by(|a, b| b.rating.partial_cmp(&a.rating).unwrap_or(std::cmp::Ordering::Equal));
        playbooks.into_iter().take(limit).collect()
    }

    /// List newest playbooks
    pub fn newest(&self, limit: usize) -> Vec<&MarketplacePlaybook> {
        let mut playbooks: Vec<_> = self.playbooks.values().collect();
        playbooks.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        playbooks.into_iter().take(limit).collect()
    }

    /// Install a playbook (increment download count)
    pub fn install(&mut self, id: &Uuid) -> Option<MarketplacePlaybook> {
        if let Some(playbook) = self.playbooks.get_mut(id) {
            playbook.downloads += 1;
            Some(playbook.clone())
        } else {
            None
        }
    }

    /// Add a rating to a playbook
    pub fn rate(&mut self, playbook_id: Uuid, user_id: Uuid, rating: u8, review: Option<String>) -> Result<(), String> {
        if rating < 1 || rating > 5 {
            return Err("Rating must be between 1 and 5".to_string());
        }

        let playbook = self.playbooks.get_mut(&playbook_id)
            .ok_or_else(|| "Playbook not found".to_string())?;

        let playbook_rating = PlaybookRating {
            id: Uuid::new_v4(),
            playbook_id,
            user_id,
            rating,
            review,
            helpful_votes: 0,
            created_at: Utc::now(),
        };

        let ratings = self.ratings.entry(playbook_id).or_insert_with(Vec::new);

        // Check if user already rated
        if ratings.iter().any(|r| r.user_id == user_id) {
            return Err("User has already rated this playbook".to_string());
        }

        ratings.push(playbook_rating);

        // Update average rating
        let total_rating: u32 = ratings.iter().map(|r| r.rating as u32).sum();
        playbook.rating = total_rating as f64 / ratings.len() as f64;
        playbook.ratings_count = ratings.len() as u32;

        Ok(())
    }

    /// Get ratings for a playbook
    pub fn get_ratings(&self, playbook_id: &Uuid) -> Vec<&PlaybookRating> {
        self.ratings
            .get(playbook_id)
            .map(|r| r.iter().collect())
            .unwrap_or_default()
    }

    /// Publish a new playbook to the marketplace
    pub fn publish(
        &mut self,
        name: String,
        description: String,
        author: String,
        category: PlaybookCategory,
        tags: Vec<String>,
        playbook_json: serde_json::Value,
    ) -> Uuid {
        let id = Uuid::new_v4();
        let now = Utc::now();

        let playbook = MarketplacePlaybook {
            id,
            name,
            description,
            author,
            category,
            tags,
            version: "1.0.0".to_string(),
            downloads: 0,
            rating: 0.0,
            ratings_count: 0,
            playbook_json,
            is_verified: false,
            created_at: now,
            updated_at: now,
        };

        self.playbooks.insert(id, playbook);
        id
    }

    /// List playbooks by category
    pub fn by_category(&self, category: &PlaybookCategory) -> Vec<&MarketplacePlaybook> {
        self.playbooks
            .values()
            .filter(|p| &p.category == category)
            .collect()
    }

    /// Get verified playbooks only
    pub fn verified_only(&self) -> Vec<&MarketplacePlaybook> {
        self.playbooks
            .values()
            .filter(|p| p.is_verified)
            .collect()
    }
}

impl Default for PlaybookMarketplace {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_marketplace_search() {
        let marketplace = PlaybookMarketplace::new();
        let results = marketplace.search("phishing", None);
        assert!(!results.is_empty());
        assert!(results[0].name.to_lowercase().contains("phishing"));
    }

    #[test]
    fn test_marketplace_install() {
        let mut marketplace = PlaybookMarketplace::new();
        let playbook = marketplace.top_by_downloads(1)[0];
        let original_downloads = playbook.downloads;
        let id = playbook.id;

        marketplace.install(&id);

        let updated = marketplace.get(&id).unwrap();
        assert_eq!(updated.downloads, original_downloads + 1);
    }

    #[test]
    fn test_marketplace_rating() {
        let mut marketplace = PlaybookMarketplace::new();
        let playbook_id = marketplace.top_by_downloads(1)[0].id;
        let user_id = Uuid::new_v4();

        let result = marketplace.rate(playbook_id, user_id, 5, Some("Great playbook!".to_string()));
        assert!(result.is_ok());

        let ratings = marketplace.get_ratings(&playbook_id);
        assert_eq!(ratings.len(), 1);
    }
}
