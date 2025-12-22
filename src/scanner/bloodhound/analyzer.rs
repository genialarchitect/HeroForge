//! BloodHound attack path analysis
//!
//! Provides graph-based analysis to find attack paths in Active Directory.

use std::collections::{HashMap, HashSet, VecDeque};
use uuid::Uuid;

use super::types::*;

/// Graph structure for AD objects and relationships
#[derive(Debug, Default)]
pub struct ADGraph {
    /// All objects indexed by object_id
    pub objects: HashMap<String, ADObject>,
    /// Adjacency list: source_id -> [(target_id, relationship)]
    pub edges: HashMap<String, Vec<(String, RelationshipType)>>,
    /// Reverse adjacency list: target_id -> [(source_id, relationship)]
    pub reverse_edges: HashMap<String, Vec<(String, RelationshipType)>>,
    /// High-value target object IDs
    pub high_value_targets: HashSet<String>,
    /// Domain Admin group SIDs
    pub domain_admin_sids: HashSet<String>,
    /// Enterprise Admin group SIDs
    pub enterprise_admin_sids: HashSet<String>,
}

impl ADGraph {
    pub fn new() -> Self {
        Self::default()
    }

    /// Build graph from parsed SharpHound data
    pub fn from_sharphound_data(
        users: &[ADUser],
        computers: &[ADComputer],
        groups: &[ADGroup],
        domains: &[ADDomain],
        gpos: &[ADGpo],
        ous: &[ADOu],
        relationships: &[ADRelationship],
    ) -> Self {
        let mut graph = Self::new();

        // Add users
        for user in users {
            graph.objects.insert(
                user.object_id.clone(),
                ADObject {
                    object_id: user.object_id.clone(),
                    object_type: ADObjectType::User,
                    name: user.name.clone(),
                    domain: user.domain.clone(),
                    distinguished_name: user.distinguished_name.clone(),
                    properties: user.properties.clone(),
                },
            );
        }

        // Add computers
        for computer in computers {
            let obj = ADObject {
                object_id: computer.object_id.clone(),
                object_type: ADObjectType::Computer,
                name: computer.name.clone(),
                domain: computer.domain.clone(),
                distinguished_name: computer.distinguished_name.clone(),
                properties: computer.properties.clone(),
            };
            graph.objects.insert(computer.object_id.clone(), obj);

            // Mark DCs as high-value
            if computer.is_dc {
                graph.high_value_targets.insert(computer.object_id.clone());
            }
        }

        // Add groups
        for group in groups {
            let obj = ADObject {
                object_id: group.object_id.clone(),
                object_type: ADObjectType::Group,
                name: group.name.clone(),
                domain: group.domain.clone(),
                distinguished_name: group.distinguished_name.clone(),
                properties: group.properties.clone(),
            };
            graph.objects.insert(group.object_id.clone(), obj);

            // Identify Domain Admins and Enterprise Admins
            let name_lower = group.name.to_lowercase();
            if name_lower.contains("domain admins") {
                graph.domain_admin_sids.insert(group.object_id.clone());
                graph.high_value_targets.insert(group.object_id.clone());
            }
            if name_lower.contains("enterprise admins") {
                graph.enterprise_admin_sids.insert(group.object_id.clone());
                graph.high_value_targets.insert(group.object_id.clone());
            }
            if name_lower.contains("administrators") || group.is_high_value {
                graph.high_value_targets.insert(group.object_id.clone());
            }
        }

        // Add domains
        for domain in domains {
            graph.objects.insert(
                domain.object_id.clone(),
                ADObject {
                    object_id: domain.object_id.clone(),
                    object_type: ADObjectType::Domain,
                    name: domain.name.clone(),
                    domain: domain.name.clone(),
                    distinguished_name: None,
                    properties: domain.properties.clone(),
                },
            );
            graph.high_value_targets.insert(domain.object_id.clone());
        }

        // Add GPOs
        for gpo in gpos {
            graph.objects.insert(
                gpo.object_id.clone(),
                ADObject {
                    object_id: gpo.object_id.clone(),
                    object_type: ADObjectType::GPO,
                    name: gpo.name.clone(),
                    domain: gpo.domain.clone(),
                    distinguished_name: None,
                    properties: gpo.properties.clone(),
                },
            );
        }

        // Add OUs
        for ou in ous {
            graph.objects.insert(
                ou.object_id.clone(),
                ADObject {
                    object_id: ou.object_id.clone(),
                    object_type: ADObjectType::OU,
                    name: ou.name.clone(),
                    domain: ou.domain.clone(),
                    distinguished_name: ou.distinguished_name.clone(),
                    properties: ou.properties.clone(),
                },
            );
        }

        // Add relationships (edges)
        for rel in relationships {
            graph
                .edges
                .entry(rel.source_id.clone())
                .or_default()
                .push((rel.target_id.clone(), rel.relationship_type.clone()));

            graph
                .reverse_edges
                .entry(rel.target_id.clone())
                .or_default()
                .push((rel.source_id.clone(), rel.relationship_type.clone()));
        }

        graph
    }

    /// Find shortest path from source to target using BFS
    pub fn find_shortest_path(&self, source_id: &str, target_id: &str) -> Option<AttackPath> {
        if source_id == target_id {
            return None;
        }

        let mut visited: HashSet<String> = HashSet::new();
        let mut queue: VecDeque<(String, Vec<PathStep>)> = VecDeque::new();

        queue.push_back((source_id.to_string(), Vec::new()));
        visited.insert(source_id.to_string());

        while let Some((current_id, path)) = queue.pop_front() {
            if let Some(edges) = self.edges.get(&current_id) {
                for (next_id, rel_type) in edges {
                    if visited.contains(next_id) {
                        continue;
                    }

                    let from_node = self.object_to_path_node(&current_id);
                    let to_node = self.object_to_path_node(next_id);

                    let step = PathStep {
                        from_node,
                        to_node: to_node.clone(),
                        relationship: rel_type.clone(),
                        abuse_info: get_abuse_info(rel_type),
                        opsec_considerations: get_opsec_considerations(rel_type),
                    };

                    let mut new_path = path.clone();
                    new_path.push(step);

                    if next_id == target_id {
                        let start_node = self.object_to_path_node(source_id);
                        return Some(AttackPath {
                            id: Uuid::new_v4().to_string(),
                            start_node,
                            end_node: to_node,
                            length: new_path.len(),
                            risk_score: calculate_risk_score(&new_path),
                            techniques: extract_mitre_techniques(&new_path),
                            description: format!(
                                "Path from {} to {} via {} steps",
                                source_id,
                                target_id,
                                new_path.len()
                            ),
                            path: new_path,
                        });
                    }

                    visited.insert(next_id.clone());
                    queue.push_back((next_id.clone(), new_path));
                }
            }
        }

        None
    }

    /// Find all shortest paths to Domain Admins
    pub fn find_paths_to_domain_admins(&self, from_id: &str) -> Vec<AttackPath> {
        let mut paths = Vec::new();

        for da_sid in &self.domain_admin_sids {
            if let Some(path) = self.find_shortest_path(from_id, da_sid) {
                paths.push(path);
            }
        }

        paths
    }

    /// Find all users with a path to Domain Admin
    pub fn find_users_with_path_to_da(&self) -> Vec<(String, usize)> {
        let mut results = Vec::new();

        for (obj_id, obj) in &self.objects {
            if obj.object_type != ADObjectType::User {
                continue;
            }

            // Check if user is already a DA
            if self.is_member_of_domain_admins(obj_id) {
                continue;
            }

            // Find shortest path to any DA group
            for da_sid in &self.domain_admin_sids {
                if let Some(path) = self.find_shortest_path(obj_id, da_sid) {
                    results.push((obj_id.clone(), path.length));
                    break; // Only count once per user
                }
            }
        }

        // Sort by path length (shortest first)
        results.sort_by_key(|(_, len)| *len);
        results
    }

    /// Check if an object is a member of Domain Admins (direct or nested)
    pub fn is_member_of_domain_admins(&self, object_id: &str) -> bool {
        let mut visited: HashSet<String> = HashSet::new();
        let mut queue: VecDeque<String> = VecDeque::new();

        queue.push_back(object_id.to_string());

        while let Some(current_id) = queue.pop_front() {
            if visited.contains(&current_id) {
                continue;
            }
            visited.insert(current_id.clone());

            if self.domain_admin_sids.contains(&current_id) {
                return true;
            }

            // Check MemberOf edges
            if let Some(edges) = self.edges.get(&current_id) {
                for (target_id, rel_type) in edges {
                    if *rel_type == RelationshipType::MemberOf {
                        queue.push_back(target_id.clone());
                    }
                }
            }
        }

        false
    }

    /// Convert object ID to PathNode
    fn object_to_path_node(&self, object_id: &str) -> PathNode {
        if let Some(obj) = self.objects.get(object_id) {
            PathNode {
                object_id: obj.object_id.clone(),
                name: obj.name.clone(),
                object_type: obj.object_type.clone(),
                domain: obj.domain.clone(),
                is_high_value: self.high_value_targets.contains(object_id),
            }
        } else {
            PathNode {
                object_id: object_id.to_string(),
                name: "Unknown".to_string(),
                object_type: ADObjectType::Unknown,
                domain: String::new(),
                is_high_value: false,
            }
        }
    }
}

/// Analyze SharpHound data for common attack patterns
pub fn analyze_attack_surface(
    users: &[ADUser],
    computers: &[ADComputer],
    groups: &[ADGroup],
    _domains: &[ADDomain],
    relationships: &[ADRelationship],
) -> (
    Vec<KerberoastableUser>,
    Vec<AsrepRoastableUser>,
    Vec<UnconstrainedDelegation>,
    Vec<HighValueTarget>,
) {
    let mut kerberoastable = Vec::new();
    let mut asrep_roastable = Vec::new();
    let mut unconstrained = Vec::new();
    let mut high_value = Vec::new();

    // Find Kerberoastable users
    for user in users {
        if user.has_spn && user.enabled && !user.service_principal_names.is_empty() {
            kerberoastable.push(KerberoastableUser {
                object_id: user.object_id.clone(),
                name: user.name.clone(),
                domain: user.domain.clone(),
                service_principal_names: user.service_principal_names.clone(),
                is_admin: user.admin_count || user.is_domain_admin,
                password_last_set: user.last_password_change.clone(),
                description: user.description.clone(),
            });
        }
    }

    // Find AS-REP roastable users
    for user in users {
        if user.dont_require_preauth {
            asrep_roastable.push(AsrepRoastableUser {
                object_id: user.object_id.clone(),
                name: user.name.clone(),
                domain: user.domain.clone(),
                is_enabled: user.enabled,
                is_admin: user.admin_count || user.is_domain_admin,
                description: user.description.clone(),
            });
        }
    }

    // Find unconstrained delegation
    for computer in computers {
        if computer.unconstrained_delegation {
            unconstrained.push(UnconstrainedDelegation {
                object_id: computer.object_id.clone(),
                name: computer.name.clone(),
                object_type: ADObjectType::Computer,
                domain: computer.domain.clone(),
                is_dc: computer.is_dc,
                description: None,
            });
        }
    }

    // Find high-value targets
    for group in groups {
        let name_lower = group.name.to_lowercase();
        if name_lower.contains("domain admins")
            || name_lower.contains("enterprise admins")
            || name_lower.contains("administrators")
            || group.is_high_value
        {
            // Count paths to this group
            let paths_count = relationships
                .iter()
                .filter(|r| r.target_id == group.object_id)
                .count();

            high_value.push(HighValueTarget {
                object_id: group.object_id.clone(),
                name: group.name.clone(),
                object_type: ADObjectType::Group,
                domain: group.domain.clone(),
                reason: if name_lower.contains("domain admins") {
                    "Domain Admins group".to_string()
                } else if name_lower.contains("enterprise admins") {
                    "Enterprise Admins group".to_string()
                } else {
                    "High-value group".to_string()
                },
                paths_to_target: paths_count,
            });
        }
    }

    // Add DCs as high-value
    for computer in computers {
        if computer.is_dc {
            high_value.push(HighValueTarget {
                object_id: computer.object_id.clone(),
                name: computer.name.clone(),
                object_type: ADObjectType::Computer,
                domain: computer.domain.clone(),
                reason: "Domain Controller".to_string(),
                paths_to_target: 0,
            });
        }
    }

    // Sort by importance
    kerberoastable.sort_by(|a, b| b.is_admin.cmp(&a.is_admin));
    high_value.sort_by(|a, b| b.paths_to_target.cmp(&a.paths_to_target));

    (kerberoastable, asrep_roastable, unconstrained, high_value)
}

/// Find users/computers that can DCSync
pub fn find_dcsync_principals(relationships: &[ADRelationship], domains: &[ADDomain]) -> Vec<String> {
    let domain_ids: HashSet<String> = domains.iter().map(|d| d.object_id.clone()).collect();

    let mut dcsync_principals = HashSet::new();

    // Look for GetChanges + GetChangesAll or DCSync on domain objects
    let mut get_changes: HashSet<String> = HashSet::new();
    let mut get_changes_all: HashSet<String> = HashSet::new();

    for rel in relationships {
        if !domain_ids.contains(&rel.target_id) {
            continue;
        }

        match rel.relationship_type {
            RelationshipType::GetChanges => {
                get_changes.insert(rel.source_id.clone());
            }
            RelationshipType::GetChangesAll => {
                get_changes_all.insert(rel.source_id.clone());
            }
            RelationshipType::DCSync => {
                dcsync_principals.insert(rel.source_id.clone());
            }
            RelationshipType::AllExtendedRights | RelationshipType::GenericAll => {
                // These also grant DCSync
                dcsync_principals.insert(rel.source_id.clone());
            }
            _ => {}
        }
    }

    // Principals with both GetChanges and GetChangesAll can DCSync
    for principal in &get_changes {
        if get_changes_all.contains(principal) {
            dcsync_principals.insert(principal.clone());
        }
    }

    dcsync_principals.into_iter().collect()
}

/// Get abuse information for a relationship type
fn get_abuse_info(rel_type: &RelationshipType) -> String {
    match rel_type {
        RelationshipType::MemberOf => "Group membership grants all privileges of the group".to_string(),
        RelationshipType::HasSession => "Active session allows credential theft via Mimikatz".to_string(),
        RelationshipType::AdminTo => "Local admin access allows code execution and credential theft".to_string(),
        RelationshipType::CanRDP => "RDP access allows interactive logon".to_string(),
        RelationshipType::CanPSRemote => "PowerShell remoting allows remote code execution".to_string(),
        RelationshipType::ExecuteDCOM => "DCOM access allows remote code execution".to_string(),
        RelationshipType::GenericAll => "Full control - can modify any attribute, reset password, add to groups".to_string(),
        RelationshipType::GenericWrite => "Can modify most attributes including scriptPath for code execution".to_string(),
        RelationshipType::WriteOwner => "Can change owner to gain full control".to_string(),
        RelationshipType::WriteDacl => "Can modify permissions to grant full control".to_string(),
        RelationshipType::AddMember => "Can add members to the group".to_string(),
        RelationshipType::ForceChangePassword => "Can reset user password without knowing current password".to_string(),
        RelationshipType::AllExtendedRights => "Grants all extended rights including DCSync".to_string(),
        RelationshipType::AllowedToDelegate => "Constrained delegation - can impersonate users to target service".to_string(),
        RelationshipType::AllowedToAct => "Resource-based constrained delegation attack possible".to_string(),
        RelationshipType::GetChanges | RelationshipType::GetChangesAll => "Part of DCSync attack - need both rights".to_string(),
        RelationshipType::DCSync => "Can perform DCSync to dump all password hashes".to_string(),
        RelationshipType::ReadLAPSPassword => "Can read LAPS local admin password".to_string(),
        RelationshipType::ReadGMSAPassword => "Can read GMSA password".to_string(),
        RelationshipType::AddKeyCredentialLink => "Shadow Credentials attack - can add key for authentication".to_string(),
        RelationshipType::Owns => "Object owner can modify DACL".to_string(),
        RelationshipType::GPLink => "GPO affects linked objects - can push malicious settings".to_string(),
        RelationshipType::TrustedBy => "Trust relationship allows cross-domain attacks".to_string(),
        _ => "Relationship allows privilege escalation".to_string(),
    }
}

/// Get OPSEC considerations for a relationship type
fn get_opsec_considerations(rel_type: &RelationshipType) -> Option<String> {
    match rel_type {
        RelationshipType::HasSession => Some("Credential theft may be detected by EDR".to_string()),
        RelationshipType::AdminTo => Some("Local admin actions are logged".to_string()),
        RelationshipType::ForceChangePassword => Some("Password reset generates security event 4724".to_string()),
        RelationshipType::DCSync => Some("DCSync generates event 4662 - highly monitored".to_string()),
        RelationshipType::GenericAll | RelationshipType::WriteDacl => {
            Some("DACL modifications are logged".to_string())
        }
        _ => None,
    }
}

/// Calculate risk score for an attack path
fn calculate_risk_score(path: &[PathStep]) -> u8 {
    let mut score: u8 = 0;

    for step in path {
        let step_score = match step.relationship {
            RelationshipType::GenericAll => 10,
            RelationshipType::DCSync => 10,
            RelationshipType::ForceChangePassword => 9,
            RelationshipType::WriteDacl => 9,
            RelationshipType::WriteOwner => 8,
            RelationshipType::AdminTo => 8,
            RelationshipType::AllowedToDelegate => 7,
            RelationshipType::AddMember => 7,
            RelationshipType::GenericWrite => 6,
            RelationshipType::HasSession => 5,
            RelationshipType::MemberOf => 3,
            _ => 4,
        };
        score = score.saturating_add(step_score);
    }

    // Cap at 100
    score.min(100)
}

/// Extract MITRE ATT&CK techniques from path
fn extract_mitre_techniques(path: &[PathStep]) -> Vec<String> {
    let mut techniques = HashSet::new();

    for step in path {
        match step.relationship {
            RelationshipType::HasSession => {
                techniques.insert("T1550.002".to_string()); // Pass the Hash
                techniques.insert("T1003.001".to_string()); // LSASS Memory
            }
            RelationshipType::AdminTo => {
                techniques.insert("T1021.006".to_string()); // Windows Remote Management
            }
            RelationshipType::DCSync => {
                techniques.insert("T1003.006".to_string()); // DCSync
            }
            RelationshipType::ForceChangePassword => {
                techniques.insert("T1098".to_string()); // Account Manipulation
            }
            RelationshipType::AddMember => {
                techniques.insert("T1098.001".to_string()); // Additional Cloud Credentials
            }
            RelationshipType::AllowedToDelegate => {
                techniques.insert("T1550.003".to_string()); // Pass the Ticket
            }
            RelationshipType::GPLink => {
                techniques.insert("T1484.001".to_string()); // Group Policy Modification
            }
            _ => {}
        }
    }

    techniques.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_risk_score_calculation() {
        let path = vec![
            PathStep {
                from_node: PathNode::default(),
                to_node: PathNode::default(),
                relationship: RelationshipType::MemberOf,
                abuse_info: String::new(),
                opsec_considerations: None,
            },
            PathStep {
                from_node: PathNode::default(),
                to_node: PathNode::default(),
                relationship: RelationshipType::GenericAll,
                abuse_info: String::new(),
                opsec_considerations: None,
            },
        ];

        let score = calculate_risk_score(&path);
        assert_eq!(score, 13); // 3 + 10
    }
}
