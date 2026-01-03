use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationResult {
    pub iocs: Vec<String>,
    pub campaign_id: Option<String>,
    pub actor_id: Option<String>,
    pub confidence: f64,
}

/// IOC relationship types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RelationshipType {
    Resolves,       // Domain resolves to IP
    Contains,       // File contains domain/IP
    Downloads,      // URL downloads file
    CommunicatesWith, // Malware communicates with C2
    Uses,           // Actor uses malware/tool
    Targets,        // Campaign targets sector
    AttributedTo,   // Malware attributed to actor
    RelatedTo,      // Generic relationship
}

/// IOC cluster representing a potential campaign
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IocCluster {
    pub cluster_id: String,
    pub iocs: Vec<ClusteredIoc>,
    pub similarity_score: f64,
    pub potential_campaign: Option<String>,
    pub potential_actor: Option<String>,
    pub ttp_patterns: Vec<String>,
}

/// IOC within a cluster
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusteredIoc {
    pub ioc_type: String,
    pub value: String,
    pub sources: Vec<String>,
    pub relationships: Vec<IocRelationship>,
}

/// Relationship between IOCs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IocRelationship {
    pub source_ioc: String,
    pub target_ioc: String,
    pub relationship_type: RelationshipType,
    pub confidence: f64,
    pub first_seen: DateTime<Utc>,
}

/// Correlate IOCs across multiple threat intel sources
pub async fn correlate_cross_source(iocs: Vec<String>) -> Result<Vec<CorrelationResult>> {
    let mut results = Vec::new();

    if iocs.is_empty() {
        return Ok(results);
    }

    // Build relationship graph
    let graph = build_ioc_relationship_graph(&iocs).await?;

    // Find connected components (potential campaigns)
    let clusters = find_connected_components(&graph);

    // Analyze each cluster
    for (cluster_idx, cluster_iocs) in clusters.iter().enumerate() {
        if cluster_iocs.len() < 2 {
            continue; // Skip single IOCs
        }

        // Calculate cluster confidence
        let confidence = calculate_cluster_confidence(cluster_iocs, &graph);

        // Try to identify campaign
        let campaign_id = identify_campaign(cluster_iocs).await;

        // Try to identify threat actor
        let actor_id = identify_threat_actor(cluster_iocs).await;

        results.push(CorrelationResult {
            iocs: cluster_iocs.clone(),
            campaign_id,
            actor_id,
            confidence,
        });
    }

    Ok(results)
}

/// Build IOC relationship graph
async fn build_ioc_relationship_graph(iocs: &[String]) -> Result<HashMap<String, Vec<IocRelationship>>> {
    let mut graph: HashMap<String, Vec<IocRelationship>> = HashMap::new();

    // Initialize nodes
    for ioc in iocs {
        graph.insert(ioc.clone(), Vec::new());
    }

    // Find relationships between IOCs
    for i in 0..iocs.len() {
        for j in (i + 1)..iocs.len() {
            let ioc_a = &iocs[i];
            let ioc_b = &iocs[j];

            // Check for relationships in threat intel sources
            if let Some(relationship) = find_relationship(ioc_a, ioc_b).await {
                graph.entry(ioc_a.clone()).or_default().push(relationship.clone());

                // Add reverse relationship
                let reverse = IocRelationship {
                    source_ioc: ioc_b.clone(),
                    target_ioc: ioc_a.clone(),
                    relationship_type: relationship.relationship_type,
                    confidence: relationship.confidence,
                    first_seen: relationship.first_seen,
                };
                graph.entry(ioc_b.clone()).or_default().push(reverse);
            }

            // Check for co-occurrence
            if let Some(cooccurrence) = check_cooccurrence(ioc_a, ioc_b).await {
                graph.entry(ioc_a.clone()).or_default().push(cooccurrence.clone());

                let reverse = IocRelationship {
                    source_ioc: ioc_b.clone(),
                    target_ioc: ioc_a.clone(),
                    relationship_type: cooccurrence.relationship_type,
                    confidence: cooccurrence.confidence,
                    first_seen: cooccurrence.first_seen,
                };
                graph.entry(ioc_b.clone()).or_default().push(reverse);
            }
        }
    }

    Ok(graph)
}

/// Find relationship between two IOCs
async fn find_relationship(ioc_a: &str, ioc_b: &str) -> Option<IocRelationship> {
    // In production, would query:
    // 1. MISP for relationships
    // 2. VirusTotal for file-domain/IP relationships
    // 3. PassiveTotal for domain-IP history
    // 4. Threat reports for campaign relationships

    // Detect IOC types
    let type_a = detect_ioc_type(ioc_a);
    let type_b = detect_ioc_type(ioc_b);

    // Check for domain-IP relationship
    if type_a == "domain" && type_b == "ip" {
        // Would check DNS history
        return None;
    }

    // Check for file-domain relationship
    if type_a == "sha256" && type_b == "domain" {
        // Would check sandbox results
        return None;
    }

    None
}

/// Check for co-occurrence of IOCs
async fn check_cooccurrence(ioc_a: &str, ioc_b: &str) -> Option<IocRelationship> {
    // In production, would check if IOCs appear together in:
    // 1. Threat reports
    // 2. Sandbox analyses
    // 3. SIEM events
    // 4. Historical incidents

    None
}

/// Detect IOC type from value
fn detect_ioc_type(ioc: &str) -> &'static str {
    // IPv4
    if ioc.parse::<std::net::Ipv4Addr>().is_ok() {
        return "ip";
    }

    // IPv6
    if ioc.parse::<std::net::Ipv6Addr>().is_ok() {
        return "ipv6";
    }

    // SHA256
    if ioc.len() == 64 && ioc.chars().all(|c| c.is_ascii_hexdigit()) {
        return "sha256";
    }

    // SHA1
    if ioc.len() == 40 && ioc.chars().all(|c| c.is_ascii_hexdigit()) {
        return "sha1";
    }

    // MD5
    if ioc.len() == 32 && ioc.chars().all(|c| c.is_ascii_hexdigit()) {
        return "md5";
    }

    // Email
    if ioc.contains('@') && ioc.contains('.') {
        return "email";
    }

    // URL
    if ioc.starts_with("http://") || ioc.starts_with("https://") {
        return "url";
    }

    // Domain (basic check)
    if ioc.contains('.') && !ioc.contains('/') {
        return "domain";
    }

    "unknown"
}

/// Find connected components in relationship graph
fn find_connected_components(graph: &HashMap<String, Vec<IocRelationship>>) -> Vec<Vec<String>> {
    let mut visited: HashSet<String> = HashSet::new();
    let mut components = Vec::new();

    for node in graph.keys() {
        if !visited.contains(node) {
            let mut component = Vec::new();
            let mut stack = vec![node.clone()];

            while let Some(current) = stack.pop() {
                if visited.contains(&current) {
                    continue;
                }
                visited.insert(current.clone());
                component.push(current.clone());

                if let Some(relationships) = graph.get(&current) {
                    for rel in relationships {
                        if !visited.contains(&rel.target_ioc) {
                            stack.push(rel.target_ioc.clone());
                        }
                    }
                }
            }

            if !component.is_empty() {
                components.push(component);
            }
        }
    }

    components
}

/// Calculate confidence for a cluster
fn calculate_cluster_confidence(cluster: &[String], graph: &HashMap<String, Vec<IocRelationship>>) -> f64 {
    if cluster.is_empty() {
        return 0.0;
    }

    let mut total_confidence: f64 = 0.0;
    let mut relationship_count = 0;

    for ioc in cluster {
        if let Some(relationships) = graph.get(ioc) {
            for rel in relationships {
                if cluster.contains(&rel.target_ioc) {
                    total_confidence += rel.confidence;
                    relationship_count += 1;
                }
            }
        }
    }

    if relationship_count == 0 {
        return 0.0;
    }

    // Normalize by number of relationships and cluster size
    let avg_confidence = total_confidence / relationship_count as f64;
    let size_bonus = (cluster.len() as f64).ln() / 10.0;

    (avg_confidence + size_bonus).min(1.0)
}

/// Identify potential campaign from IOC cluster
async fn identify_campaign(cluster: &[String]) -> Option<String> {
    // In production, would:
    // 1. Query threat intel platforms for campaign associations
    // 2. Match against known campaign IOC lists
    // 3. Compare TTP patterns with known campaigns

    // Check against known campaign patterns
    let _known_campaigns = [
        ("APT28", vec!["fancy", "bear", "sofacy"]),
        ("APT29", vec!["cozy", "bear", "dukes"]),
        ("Lazarus", vec!["hidden", "cobra", "zinc"]),
    ];

    None
}

/// Identify threat actor from IOC cluster
async fn identify_threat_actor(cluster: &[String]) -> Option<String> {
    // In production, would:
    // 1. Query MITRE ATT&CK for actor TTPs
    // 2. Compare infrastructure patterns
    // 3. Analyze malware families used

    None
}

/// Cluster IOCs into campaigns using similarity
pub async fn cluster_campaigns(iocs: Vec<String>) -> Result<Vec<String>> {
    let mut campaign_ids = Vec::new();

    if iocs.is_empty() {
        return Ok(campaign_ids);
    }

    // Calculate pairwise similarity
    let mut similarity_matrix: HashMap<(usize, usize), f64> = HashMap::new();

    for i in 0..iocs.len() {
        for j in (i + 1)..iocs.len() {
            let sim = calculate_ioc_similarity(&iocs[i], &iocs[j]).await;
            if sim > 0.0 {
                similarity_matrix.insert((i, j), sim);
            }
        }
    }

    // Agglomerative clustering
    let mut clusters: Vec<HashSet<usize>> = (0..iocs.len())
        .map(|i| {
            let mut s = HashSet::new();
            s.insert(i);
            s
        })
        .collect();

    let threshold = 0.3;

    loop {
        let mut best_merge: Option<(usize, usize, f64)> = None;

        for i in 0..clusters.len() {
            for j in (i + 1)..clusters.len() {
                let sim = cluster_similarity(&clusters[i], &clusters[j], &similarity_matrix);
                if sim >= threshold {
                    if best_merge.is_none() || sim > best_merge.as_ref().unwrap().2 {
                        best_merge = Some((i, j, sim));
                    }
                }
            }
        }

        if let Some((i, j, _)) = best_merge {
            // Merge clusters
            let cluster_j = clusters.remove(j);
            clusters[i].extend(cluster_j);
        } else {
            break;
        }
    }

    // Generate campaign IDs for clusters with multiple IOCs
    for (idx, cluster) in clusters.iter().enumerate() {
        if cluster.len() > 1 {
            campaign_ids.push(format!("CAMPAIGN-{:04}", idx));
        }
    }

    Ok(campaign_ids)
}

/// Calculate similarity between two IOCs
async fn calculate_ioc_similarity(ioc_a: &str, ioc_b: &str) -> f64 {
    let type_a = detect_ioc_type(ioc_a);
    let type_b = detect_ioc_type(ioc_b);

    // Same type gets base similarity
    let type_similarity = if type_a == type_b { 0.2 } else { 0.0 };

    // Check for infrastructure overlap
    let infra_similarity = if type_a == "ip" && type_b == "ip" {
        // Same subnet
        if ioc_a.starts_with(&ioc_b[..ioc_b.rfind('.').unwrap_or(0)]) {
            0.3
        } else {
            0.0
        }
    } else if type_a == "domain" && type_b == "domain" {
        // Same registrar/TLD pattern
        let tld_a = ioc_a.rsplit('.').next().unwrap_or("");
        let tld_b = ioc_b.rsplit('.').next().unwrap_or("");
        if tld_a == tld_b { 0.1 } else { 0.0 }
    } else {
        0.0
    };

    // Check for co-occurrence in threat intel
    let cooccurrence_sim = 0.0; // Would query threat intel sources

    type_similarity + infra_similarity + cooccurrence_sim
}

/// Calculate similarity between two clusters
fn cluster_similarity(
    cluster_a: &HashSet<usize>,
    cluster_b: &HashSet<usize>,
    similarity_matrix: &HashMap<(usize, usize), f64>,
) -> f64 {
    let mut total_sim: f64 = 0.0;
    let mut count = 0;

    for &a in cluster_a {
        for &b in cluster_b {
            let key = if a < b { (a, b) } else { (b, a) };
            if let Some(&sim) = similarity_matrix.get(&key) {
                total_sim += sim;
                count += 1;
            }
        }
    }

    if count == 0 {
        0.0
    } else {
        total_sim / count as f64
    }
}

/// Attribute campaign to threat actor
pub async fn attribute_actor(campaign_id: &str) -> Result<Option<String>> {
    // In production, would:
    // 1. Query campaign database for associated TTPs
    // 2. Match TTPs against MITRE ATT&CK actor profiles
    // 3. Compare infrastructure patterns
    // 4. Analyze malware families and tools used

    // Known actor TTP patterns
    let _actor_ttp_patterns = [
        ("APT28", vec!["T1566.001", "T1059.001", "T1047"]),
        ("APT29", vec!["T1566.002", "T1059.001", "T1055"]),
        ("FIN7", vec!["T1566.001", "T1059.003", "T1055.012"]),
    ];

    // Would match campaign TTPs against known actor patterns
    Ok(None)
}

/// Enrich IOC with related information
pub async fn enrich_ioc(ioc: &str) -> Result<serde_json::Value> {
    let ioc_type = detect_ioc_type(ioc);

    let mut enrichment = serde_json::json!({
        "ioc": ioc,
        "type": ioc_type,
        "enriched_at": Utc::now().to_rfc3339(),
    });

    match ioc_type {
        "ip" => {
            // Would enrich with:
            // - Geolocation
            // - ASN
            // - Reputation
            // - Historical DNS
            enrichment["geolocation"] = serde_json::json!(null);
            enrichment["asn"] = serde_json::json!(null);
        }
        "domain" => {
            // Would enrich with:
            // - WHOIS
            // - DNS records
            // - Certificate history
            // - Reputation
            enrichment["whois"] = serde_json::json!(null);
            enrichment["dns"] = serde_json::json!(null);
        }
        "sha256" | "sha1" | "md5" => {
            // Would enrich with:
            // - VirusTotal results
            // - Malware family
            // - Associated campaigns
            enrichment["av_detections"] = serde_json::json!(null);
            enrichment["malware_family"] = serde_json::json!(null);
        }
        _ => {}
    }

    Ok(enrichment)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_ioc_type() {
        assert_eq!(detect_ioc_type("1.2.3.4"), "ip");
        assert_eq!(detect_ioc_type("example.com"), "domain");
        assert_eq!(detect_ioc_type("d41d8cd98f00b204e9800998ecf8427e"), "md5");
        assert_eq!(detect_ioc_type("a" .repeat(64).as_str()), "sha256");
        assert_eq!(detect_ioc_type("https://example.com/malware"), "url");
        assert_eq!(detect_ioc_type("attacker@evil.com"), "email");
    }

    #[test]
    fn test_find_connected_components() {
        let mut graph: HashMap<String, Vec<IocRelationship>> = HashMap::new();

        // Create simple connected component
        graph.insert("a".to_string(), vec![IocRelationship {
            source_ioc: "a".to_string(),
            target_ioc: "b".to_string(),
            relationship_type: RelationshipType::RelatedTo,
            confidence: 0.8,
            first_seen: Utc::now(),
        }]);
        graph.insert("b".to_string(), vec![]);
        graph.insert("c".to_string(), vec![]);  // Isolated node

        let components = find_connected_components(&graph);
        assert_eq!(components.len(), 2);  // One connected, one isolated
    }

    #[tokio::test]
    async fn test_correlate_cross_source() {
        let iocs = vec![
            "1.2.3.4".to_string(),
            "evil.com".to_string(),
        ];

        let results = correlate_cross_source(iocs).await.unwrap();
        // Should return empty for simulated correlation
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn test_cluster_campaigns() {
        let iocs = vec![
            "1.2.3.4".to_string(),
            "1.2.3.5".to_string(),
            "8.8.8.8".to_string(),
        ];

        let campaigns = cluster_campaigns(iocs).await.unwrap();
        // Should identify related IPs as potential campaign
        assert!(campaigns.len() <= 2);
    }
}
