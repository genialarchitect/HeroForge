use crate::investigation::types::{GraphEntity, GraphRelationship};
use anyhow::Result;

/// Generate force-directed graph visualization data
pub fn generate_force_directed_graph(
    entities: &[GraphEntity],
    relationships: &[GraphRelationship],
) -> Result<serde_json::Value> {
    let nodes: Vec<serde_json::Value> = entities
        .iter()
        .map(|e| {
            serde_json::json!({
                "id": e.id,
                "label": e.entity_value,
                "type": e.entity_type,
                "risk_score": e.risk_score.unwrap_or(0.0)
            })
        })
        .collect();

    let edges: Vec<serde_json::Value> = relationships
        .iter()
        .map(|r| {
            serde_json::json!({
                "id": r.id,
                "source": r.source_entity_id,
                "target": r.target_entity_id,
                "type": r.relationship_type,
                "count": r.count
            })
        })
        .collect();

    Ok(serde_json::json!({
        "nodes": nodes,
        "edges": edges
    }))
}

/// Generate hierarchical graph visualization
pub fn generate_hierarchical_graph(
    entities: &[GraphEntity],
    relationships: &[GraphRelationship],
    root_id: &str,
) -> Result<serde_json::Value> {
    // Build tree structure from root
    fn build_tree(
        current_id: &str,
        entities: &[GraphEntity],
        relationships: &[GraphRelationship],
        visited: &mut std::collections::HashSet<String>,
    ) -> serde_json::Value {
        if visited.contains(current_id) {
            return serde_json::json!(null);
        }

        visited.insert(current_id.to_string());

        let entity = entities.iter().find(|e| e.id == current_id);

        let children: Vec<serde_json::Value> = relationships
            .iter()
            .filter(|r| r.source_entity_id == current_id)
            .map(|r| build_tree(&r.target_entity_id, entities, relationships, visited))
            .filter(|v| !v.is_null())
            .collect();

        if let Some(e) = entity {
            serde_json::json!({
                "id": e.id,
                "label": e.entity_value,
                "type": e.entity_type,
                "children": children
            })
        } else {
            serde_json::json!(null)
        }
    }

    let mut visited = std::collections::HashSet::new();
    let tree = build_tree(root_id, entities, relationships, &mut visited);

    Ok(tree)
}
