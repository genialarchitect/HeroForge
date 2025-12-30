use crate::investigation::types::{GraphEntity, GraphRelationship};
use anyhow::Result;
use chrono::Utc;
use uuid::Uuid;

/// Discover relationships between entities
pub fn discover_relationships(
    investigation_id: &str,
    entities: &[GraphEntity],
) -> Result<Vec<GraphRelationship>> {
    let mut relationships = Vec::new();

    // Discover IP-Domain relationships
    for i in 0..entities.len() {
        for j in (i + 1)..entities.len() {
            if let Some(rel) = infer_relationship(investigation_id, &entities[i], &entities[j])? {
                relationships.push(rel);
            }
        }
    }

    Ok(relationships)
}

fn infer_relationship(
    investigation_id: &str,
    entity_a: &GraphEntity,
    entity_b: &GraphEntity,
) -> Result<Option<GraphRelationship>> {
    // Infer relationship based on entity types
    let relationship_type = match (entity_a.entity_type.as_str(), entity_b.entity_type.as_str()) {
        ("IP", "Domain") | ("Domain", "IP") => Some("Resolves"),
        ("IP", "IP") => Some("Communicates"),
        ("User", "Process") => Some("Executes"),
        ("Process", "File") => Some("Accesses"),
        _ => None,
    };

    if let Some(rel_type) = relationship_type {
        Ok(Some(GraphRelationship {
            id: Uuid::new_v4().to_string(),
            investigation_id: investigation_id.to_string(),
            source_entity_id: entity_a.id.clone(),
            target_entity_id: entity_b.id.clone(),
            relationship_type: rel_type.to_string(),
            properties: None,
            first_seen: Utc::now(),
            last_seen: Utc::now(),
            count: 1,
            created_at: Utc::now(),
        }))
    } else {
        Ok(None)
    }
}

/// Calculate community detection in graph
pub fn detect_communities(
    entities: &[GraphEntity],
    relationships: &[GraphRelationship],
) -> Result<Vec<Vec<String>>> {
    // Simple connected components algorithm
    let mut communities: Vec<Vec<String>> = Vec::new();
    let mut visited = std::collections::HashSet::new();

    for entity in entities {
        if visited.contains(&entity.id) {
            continue;
        }

        let mut community = Vec::new();
        let mut stack = vec![entity.id.clone()];

        while let Some(current_id) = stack.pop() {
            if visited.contains(&current_id) {
                continue;
            }

            visited.insert(current_id.clone());
            community.push(current_id.clone());

            // Find connected entities
            for rel in relationships {
                if rel.source_entity_id == current_id && !visited.contains(&rel.target_entity_id) {
                    stack.push(rel.target_entity_id.clone());
                }
                if rel.target_entity_id == current_id && !visited.contains(&rel.source_entity_id) {
                    stack.push(rel.source_entity_id.clone());
                }
            }
        }

        if !community.is_empty() {
            communities.push(community);
        }
    }

    Ok(communities)
}
