use crate::investigation::types::{AttackGraph, AttackPath, GraphEntity, GraphRelationship};
use anyhow::Result;
use std::collections::{HashMap, HashSet};

/// Generate attack graph showing paths from entry point to target
pub fn generate_attack_graph(
    investigation_id: &str,
    entities: &[GraphEntity],
    relationships: &[GraphRelationship],
    entry_point_id: &str,
    target_id: &str,
) -> Result<AttackGraph> {
    let paths = find_all_paths(entities, relationships, entry_point_id, target_id)?;
    let pivot_points = identify_pivot_points(relationships, &paths)?;
    let blast_radius = calculate_blast_radius(relationships, target_id)?;

    Ok(AttackGraph {
        investigation_id: investigation_id.to_string(),
        entry_point: entry_point_id.to_string(),
        target: target_id.to_string(),
        paths,
        pivot_points,
        blast_radius,
    })
}

fn find_all_paths(
    entities: &[GraphEntity],
    relationships: &[GraphRelationship],
    start_id: &str,
    end_id: &str,
) -> Result<Vec<AttackPath>> {
    let mut paths = Vec::new();
    let mut current_path = Vec::new();
    let mut visited = HashSet::new();

    dfs_find_paths(
        start_id,
        end_id,
        relationships,
        &mut current_path,
        &mut visited,
        &mut paths,
    )?;

    Ok(paths)
}

fn dfs_find_paths(
    current: &str,
    target: &str,
    relationships: &[GraphRelationship],
    path: &mut Vec<String>,
    visited: &mut HashSet<String>,
    all_paths: &mut Vec<AttackPath>,
) -> Result<()> {
    if visited.contains(current) {
        return Ok(());
    }

    path.push(current.to_string());
    visited.insert(current.to_string());

    if current == target {
        all_paths.push(AttackPath {
            entities: path.clone(),
            relationships: Vec::new(), // Would be populated with relationship IDs
            risk_score: 0.8, // Would be calculated based on path
            techniques: Vec::new(), // Would map to MITRE ATT&CK
        });
    } else {
        for rel in relationships {
            if rel.source_entity_id == current {
                dfs_find_paths(
                    &rel.target_entity_id,
                    target,
                    relationships,
                    path,
                    visited,
                    all_paths,
                )?;
            }
        }
    }

    path.pop();
    visited.remove(current);

    Ok(())
}

fn identify_pivot_points(
    relationships: &[GraphRelationship],
    paths: &[AttackPath],
) -> Result<Vec<String>> {
    let mut entity_frequency: HashMap<String, usize> = HashMap::new();

    for path in paths {
        for entity_id in &path.entities {
            *entity_frequency.entry(entity_id.clone()).or_insert(0) += 1;
        }
    }

    // Pivot points appear in multiple paths
    let pivot_points: Vec<String> = entity_frequency
        .into_iter()
        .filter(|(_, count)| *count > 1)
        .map(|(id, _)| id)
        .collect();

    Ok(pivot_points)
}

fn calculate_blast_radius(
    relationships: &[GraphRelationship],
    target_id: &str,
) -> Result<Vec<String>> {
    let mut blast_radius = HashSet::new();
    let mut stack = vec![target_id.to_string()];

    while let Some(current) = stack.pop() {
        if blast_radius.contains(&current) {
            continue;
        }

        blast_radius.insert(current.clone());

        // Find all entities connected to current
        for rel in relationships {
            if rel.source_entity_id == current {
                stack.push(rel.target_entity_id.clone());
            }
            if rel.target_entity_id == current {
                stack.push(rel.source_entity_id.clone());
            }
        }
    }

    Ok(blast_radius.into_iter().collect())
}
