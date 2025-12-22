//! BloodHound Integration Module
//!
//! This module provides integration with BloodHound/SharpHound for Active Directory
//! attack path analysis. It can ingest SharpHound collection data and analyze it
//! for privilege escalation paths and security weaknesses.
//!
//! # Features
//!
//! - **SharpHound Ingestion**: Parse ZIP archives and JSON files from SharpHound
//! - **Graph Analysis**: Build and query attack paths between AD objects
//! - **Pre-built Queries**: Find Kerberoastable users, DCSync principals, etc.
//! - **Attack Paths**: Shortest path to Domain Admin and other high-value targets
//!
//! # Example
//!
//! ```rust,ignore
//! use heroforge::scanner::bloodhound::{parse_sharphound_zip, analyze_import};
//!
//! // Parse SharpHound ZIP file
//! let data = std::fs::read("sharphound_data.zip")?;
//! let sharphound_data = parse_sharphound_zip(&data)?;
//!
//! // Analyze the data
//! let result = analyze_import(&sharphound_data)?;
//!
//! // Find Kerberoastable users
//! for user in &result.kerberoastable_users {
//!     println!("Kerberoastable: {} ({})", user.name, user.service_principal_names.join(", "));
//! }
//! ```

mod analyzer;
mod ingestor;
mod types;

// Re-export main types
pub use types::*;

// Re-export ingestor functions
pub use ingestor::{
    convert_to_ad_objects, extract_relationships, parse_sharphound_json, parse_sharphound_zip,
};

// Re-export analyzer
pub use analyzer::{analyze_attack_surface, find_dcsync_principals, ADGraph};

use anyhow::Result;
use uuid::Uuid;

/// Analyze imported SharpHound data and return comprehensive results
pub fn analyze_import(data: &SharpHoundData) -> Result<BloodHoundImportResult> {
    // Convert to internal AD objects
    let (users, computers, groups, domains, gpos, ous) = convert_to_ad_objects(data);

    // Extract relationships
    let relationships = extract_relationships(data);

    // Analyze attack surface
    let (kerberoastable, asrep_roastable, unconstrained, high_value) =
        analyze_attack_surface(&users, &computers, &groups, &domains, &relationships);

    // Build graph and find attack paths
    let graph = ADGraph::from_sharphound_data(
        &users,
        &computers,
        &groups,
        &domains,
        &gpos,
        &ous,
        &relationships,
    );

    // Find users with path to DA
    let users_with_path = graph.find_users_with_path_to_da();

    // Find DCSync principals
    let dcsync_principals = find_dcsync_principals(&relationships, &domains);

    // Build attack paths for users with shortest paths
    let mut attack_paths = Vec::new();
    for (user_id, _) in users_with_path.iter().take(20) {
        // Limit to top 20
        for path in graph.find_paths_to_domain_admins(user_id) {
            attack_paths.push(path);
        }
    }

    // Calculate statistics
    let statistics = ImportStatistics {
        total_computers: computers.len(),
        total_users: users.len(),
        total_groups: groups.len(),
        total_domains: domains.len(),
        total_gpos: gpos.len(),
        total_ous: ous.len(),
        total_containers: data.containers.len(),
        total_sessions: data
            .computers
            .iter()
            .map(|c| c.sessions.results.len())
            .sum(),
        total_relationships: relationships.len(),
        domain_admins: graph.domain_admin_sids.len(),
        enterprise_admins: graph.enterprise_admin_sids.len(),
        attack_paths_found: attack_paths.len(),
    };

    // Get domain name
    let domain = domains
        .first()
        .map(|d| d.name.clone())
        .unwrap_or_else(|| "Unknown".to_string());

    Ok(BloodHoundImportResult {
        id: Uuid::new_v4().to_string(),
        status: ImportStatus::Completed,
        domain,
        statistics,
        attack_paths,
        high_value_targets: high_value,
        kerberoastable_users: kerberoastable,
        asrep_roastable_users: asrep_roastable,
        unconstrained_delegation: unconstrained,
        created_at: chrono::Utc::now().to_rfc3339(),
        completed_at: Some(chrono::Utc::now().to_rfc3339()),
        error: None,
    })
}
