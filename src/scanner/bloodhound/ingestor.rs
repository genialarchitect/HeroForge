//! SharpHound data ingestion
//!
//! Parses SharpHound JSON files and ZIP archives into structured AD data.

use anyhow::{anyhow, Result};
use log::{debug, info, warn};
use std::collections::HashMap;
use std::io::Read;
use zip::ZipArchive;

use super::types::*;

/// Parse a SharpHound ZIP archive containing JSON files
pub fn parse_sharphound_zip(data: &[u8]) -> Result<SharpHoundData> {
    let cursor = std::io::Cursor::new(data);
    let mut archive = ZipArchive::new(cursor)?;

    let mut result = SharpHoundData::default();

    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        let name = file.name().to_lowercase();

        if !name.ends_with(".json") {
            continue;
        }

        let mut contents = String::new();
        file.read_to_string(&mut contents)?;

        // Determine file type from name
        if name.contains("computers") {
            match parse_computers_json(&contents) {
                Ok((meta, computers)) => {
                    result.meta = meta;
                    result.computers = computers;
                    info!("Parsed {} computers", result.computers.len());
                }
                Err(e) => warn!("Failed to parse computers: {}", e),
            }
        } else if name.contains("users") {
            match parse_users_json(&contents) {
                Ok((meta, users)) => {
                    result.meta = meta;
                    result.users = users;
                    info!("Parsed {} users", result.users.len());
                }
                Err(e) => warn!("Failed to parse users: {}", e),
            }
        } else if name.contains("groups") {
            match parse_groups_json(&contents) {
                Ok((meta, groups)) => {
                    result.meta = meta;
                    result.groups = groups;
                    info!("Parsed {} groups", result.groups.len());
                }
                Err(e) => warn!("Failed to parse groups: {}", e),
            }
        } else if name.contains("domains") {
            match parse_domains_json(&contents) {
                Ok((meta, domains)) => {
                    result.meta = meta;
                    result.domains = domains;
                    info!("Parsed {} domains", result.domains.len());
                }
                Err(e) => warn!("Failed to parse domains: {}", e),
            }
        } else if name.contains("gpos") {
            match parse_gpos_json(&contents) {
                Ok((meta, gpos)) => {
                    result.meta = meta;
                    result.gpos = gpos;
                    info!("Parsed {} GPOs", result.gpos.len());
                }
                Err(e) => warn!("Failed to parse GPOs: {}", e),
            }
        } else if name.contains("ous") {
            match parse_ous_json(&contents) {
                Ok((meta, ous)) => {
                    result.meta = meta;
                    result.ous = ous;
                    info!("Parsed {} OUs", result.ous.len());
                }
                Err(e) => warn!("Failed to parse OUs: {}", e),
            }
        } else if name.contains("containers") {
            match parse_containers_json(&contents) {
                Ok((meta, containers)) => {
                    result.meta = meta;
                    result.containers = containers;
                    info!("Parsed {} containers", result.containers.len());
                }
                Err(e) => warn!("Failed to parse containers: {}", e),
            }
        }
    }

    Ok(result)
}

/// Parse a single SharpHound JSON file
pub fn parse_sharphound_json(json: &str, file_type: &str) -> Result<SharpHoundData> {
    let mut result = SharpHoundData::default();

    match file_type.to_lowercase().as_str() {
        "computers" => {
            let (meta, computers) = parse_computers_json(json)?;
            result.meta = meta;
            result.computers = computers;
        }
        "users" => {
            let (meta, users) = parse_users_json(json)?;
            result.meta = meta;
            result.users = users;
        }
        "groups" => {
            let (meta, groups) = parse_groups_json(json)?;
            result.meta = meta;
            result.groups = groups;
        }
        "domains" => {
            let (meta, domains) = parse_domains_json(json)?;
            result.meta = meta;
            result.domains = domains;
        }
        "gpos" => {
            let (meta, gpos) = parse_gpos_json(json)?;
            result.meta = meta;
            result.gpos = gpos;
        }
        "ous" => {
            let (meta, ous) = parse_ous_json(json)?;
            result.meta = meta;
            result.ous = ous;
        }
        "containers" => {
            let (meta, containers) = parse_containers_json(json)?;
            result.meta = meta;
            result.containers = containers;
        }
        _ => return Err(anyhow!("Unknown file type: {}", file_type)),
    }

    Ok(result)
}

/// SharpHound JSON wrapper structure
#[derive(Debug, serde::Deserialize)]
struct SharpHoundJsonWrapper<T> {
    meta: SharpHoundMeta,
    data: Vec<T>,
}

fn parse_computers_json(json: &str) -> Result<(SharpHoundMeta, Vec<SharpHoundComputer>)> {
    let wrapper: SharpHoundJsonWrapper<SharpHoundComputer> = serde_json::from_str(json)?;
    Ok((wrapper.meta, wrapper.data))
}

fn parse_users_json(json: &str) -> Result<(SharpHoundMeta, Vec<SharpHoundUser>)> {
    let wrapper: SharpHoundJsonWrapper<SharpHoundUser> = serde_json::from_str(json)?;
    Ok((wrapper.meta, wrapper.data))
}

fn parse_groups_json(json: &str) -> Result<(SharpHoundMeta, Vec<SharpHoundGroup>)> {
    let wrapper: SharpHoundJsonWrapper<SharpHoundGroup> = serde_json::from_str(json)?;
    Ok((wrapper.meta, wrapper.data))
}

fn parse_domains_json(json: &str) -> Result<(SharpHoundMeta, Vec<SharpHoundDomain>)> {
    let wrapper: SharpHoundJsonWrapper<SharpHoundDomain> = serde_json::from_str(json)?;
    Ok((wrapper.meta, wrapper.data))
}

fn parse_gpos_json(json: &str) -> Result<(SharpHoundMeta, Vec<SharpHoundGpo>)> {
    let wrapper: SharpHoundJsonWrapper<SharpHoundGpo> = serde_json::from_str(json)?;
    Ok((wrapper.meta, wrapper.data))
}

fn parse_ous_json(json: &str) -> Result<(SharpHoundMeta, Vec<SharpHoundOu>)> {
    let wrapper: SharpHoundJsonWrapper<SharpHoundOu> = serde_json::from_str(json)?;
    Ok((wrapper.meta, wrapper.data))
}

fn parse_containers_json(json: &str) -> Result<(SharpHoundMeta, Vec<SharpHoundContainer>)> {
    let wrapper: SharpHoundJsonWrapper<SharpHoundContainer> = serde_json::from_str(json)?;
    Ok((wrapper.meta, wrapper.data))
}

/// Convert SharpHound data to internal AD objects
pub fn convert_to_ad_objects(data: &SharpHoundData) -> (Vec<ADUser>, Vec<ADComputer>, Vec<ADGroup>, Vec<ADDomain>, Vec<ADGpo>, Vec<ADOu>) {
    let users = convert_users(&data.users);
    let computers = convert_computers(&data.computers);
    let groups = convert_groups(&data.groups);
    let domains = convert_domains(&data.domains);
    let gpos = convert_gpos(&data.gpos);
    let ous = convert_ous(&data.ous);

    (users, computers, groups, domains, gpos, ous)
}

fn convert_users(sharphound_users: &[SharpHoundUser]) -> Vec<ADUser> {
    sharphound_users
        .iter()
        .map(|u| {
            let props = &u.properties;
            ADUser {
                object_id: u.object_identifier.clone(),
                name: props.name.clone().unwrap_or_default(),
                domain: props.domain.clone().unwrap_or_default(),
                distinguished_name: props.distinguishedname.clone(),
                sam_account_name: props.samaccountname.clone(),
                display_name: props.displayname.clone(),
                email: props.email.clone(),
                description: props.description.clone(),
                enabled: props.enabled.unwrap_or(false),
                admin_count: props.admincount.unwrap_or(false),
                is_domain_admin: false, // Will be computed during analysis
                is_enterprise_admin: false,
                password_never_expires: props.pwdneverexpires.unwrap_or(false),
                password_not_required: props.passwordnotreqd.unwrap_or(false),
                dont_require_preauth: props.dontreqpreauth.unwrap_or(false),
                has_spn: props.hasspn.unwrap_or(false),
                service_principal_names: props.serviceprincipalnames.clone(),
                last_logon: props.lastlogon.map(|t| format_timestamp(t)),
                last_password_change: props.pwdlastset.map(|t| format_timestamp(t)),
                member_of: Vec::new(),
                has_session_on: Vec::new(),
                properties: HashMap::new(),
            }
        })
        .collect()
}

fn convert_computers(sharphound_computers: &[SharpHoundComputer]) -> Vec<ADComputer> {
    sharphound_computers
        .iter()
        .map(|c| {
            let props = &c.properties;
            ADComputer {
                object_id: c.object_identifier.clone(),
                name: props.name.clone().unwrap_or_default(),
                domain: props.domain.clone().unwrap_or_default(),
                distinguished_name: props.distinguishedname.clone(),
                sam_account_name: props.samaccountname.clone(),
                operating_system: props.operatingsystem.clone(),
                os_version: None,
                enabled: props.enabled.unwrap_or(false),
                is_dc: props.isdc.unwrap_or(false),
                unconstrained_delegation: props.unconstraineddelegation.unwrap_or(false),
                constrained_delegation: !c.allowed_to_delegate.is_empty(),
                allowed_to_delegate: c
                    .allowed_to_delegate
                    .iter()
                    .map(|a| a.principal_sid.clone())
                    .collect(),
                local_admins: c
                    .local_admins
                    .results
                    .iter()
                    .map(|a| a.principal_sid.clone())
                    .collect(),
                sessions: c
                    .sessions
                    .results
                    .iter()
                    .map(|a| a.principal_sid.clone())
                    .collect(),
                properties: HashMap::new(),
            }
        })
        .collect()
}

fn convert_groups(sharphound_groups: &[SharpHoundGroup]) -> Vec<ADGroup> {
    sharphound_groups
        .iter()
        .map(|g| {
            let props = &g.properties;
            ADGroup {
                object_id: g.object_identifier.clone(),
                name: props.name.clone().unwrap_or_default(),
                domain: props.domain.clone().unwrap_or_default(),
                distinguished_name: props.distinguishedname.clone(),
                sam_account_name: props.samaccountname.clone(),
                description: props.description.clone(),
                admin_count: props.admincount.unwrap_or(false),
                is_high_value: props.highvalue.unwrap_or(false),
                members: g.members.iter().map(|m| m.object_identifier.clone()).collect(),
                member_of: Vec::new(),
                properties: HashMap::new(),
            }
        })
        .collect()
}

fn convert_domains(sharphound_domains: &[SharpHoundDomain]) -> Vec<ADDomain> {
    sharphound_domains
        .iter()
        .map(|d| {
            let props = &d.properties;
            ADDomain {
                object_id: d.object_identifier.clone(),
                name: props.name.clone().unwrap_or_default(),
                domain_sid: props.domainsid.clone(),
                forest_name: None,
                functional_level: props.functionallevel.clone(),
                trusts: d
                    .trusts
                    .iter()
                    .map(|t| DomainTrust {
                        target_domain: t.target_domain_name.clone(),
                        trust_direction: match t.trust_direction {
                            0 => "Disabled".to_string(),
                            1 => "Inbound".to_string(),
                            2 => "Outbound".to_string(),
                            3 => "Bidirectional".to_string(),
                            _ => "Unknown".to_string(),
                        },
                        trust_type: match t.trust_type {
                            1 => "Downlevel".to_string(),
                            2 => "Uplevel".to_string(),
                            3 => "MIT".to_string(),
                            4 => "DCE".to_string(),
                            _ => "Unknown".to_string(),
                        },
                        is_transitive: t.is_transitive,
                        sid_filtering_enabled: t.sid_filtering_enabled,
                    })
                    .collect(),
                child_domains: d
                    .child_objects
                    .iter()
                    .filter(|c| c.object_type == "Domain")
                    .map(|c| c.object_identifier.clone())
                    .collect(),
                linked_gpos: d.links.iter().map(|l| l.guid.clone()).collect(),
                properties: HashMap::new(),
            }
        })
        .collect()
}

fn convert_gpos(sharphound_gpos: &[SharpHoundGpo]) -> Vec<ADGpo> {
    sharphound_gpos
        .iter()
        .map(|g| {
            let props = &g.properties;
            ADGpo {
                object_id: g.object_identifier.clone(),
                name: props.name.clone().unwrap_or_default(),
                domain: props.domain.clone().unwrap_or_default(),
                guid: g.object_identifier.clone(),
                gpc_path: props.gpcpath.clone(),
                affects_computers: Vec::new(),
                affects_users: Vec::new(),
                properties: HashMap::new(),
            }
        })
        .collect()
}

fn convert_ous(sharphound_ous: &[SharpHoundOu]) -> Vec<ADOu> {
    sharphound_ous
        .iter()
        .map(|o| {
            let props = &o.properties;
            ADOu {
                object_id: o.object_identifier.clone(),
                name: props.name.clone().unwrap_or_default(),
                domain: props.domain.clone().unwrap_or_default(),
                distinguished_name: props.distinguishedname.clone(),
                guid: Some(o.object_identifier.clone()),
                block_inheritance: props.blockinheritance.unwrap_or(false),
                linked_gpos: o.links.iter().map(|l| l.guid.clone()).collect(),
                child_objects: o.child_objects.iter().map(|c| c.object_identifier.clone()).collect(),
                properties: HashMap::new(),
            }
        })
        .collect()
}

/// Extract all relationships from SharpHound data
pub fn extract_relationships(data: &SharpHoundData) -> Vec<ADRelationship> {
    let mut relationships = Vec::new();

    // Extract user relationships
    for user in &data.users {
        // ACEs
        for ace in &user.aces {
            if let Some(rel_type) = ace_to_relationship_type(&ace.right_name) {
                relationships.push(ADRelationship {
                    source_id: ace.principal_sid.clone(),
                    target_id: user.object_identifier.clone(),
                    relationship_type: rel_type,
                    is_acl: true,
                    is_inherited: ace.is_inherited,
                    properties: HashMap::new(),
                });
            }
        }

        // Delegation
        for delegate in &user.allowed_to_delegate {
            relationships.push(ADRelationship {
                source_id: user.object_identifier.clone(),
                target_id: delegate.principal_sid.clone(),
                relationship_type: RelationshipType::AllowedToDelegate,
                is_acl: false,
                is_inherited: false,
                properties: HashMap::new(),
            });
        }
    }

    // Extract computer relationships
    for computer in &data.computers {
        // Local admins
        for admin in &computer.local_admins.results {
            relationships.push(ADRelationship {
                source_id: admin.principal_sid.clone(),
                target_id: computer.object_identifier.clone(),
                relationship_type: RelationshipType::AdminTo,
                is_acl: false,
                is_inherited: false,
                properties: HashMap::new(),
            });
        }

        // Sessions
        for session in &computer.sessions.results {
            relationships.push(ADRelationship {
                source_id: session.principal_sid.clone(),
                target_id: computer.object_identifier.clone(),
                relationship_type: RelationshipType::HasSession,
                is_acl: false,
                is_inherited: false,
                properties: HashMap::new(),
            });
        }

        // RDP users
        for rdp in &computer.remote_desktop_users.results {
            relationships.push(ADRelationship {
                source_id: rdp.principal_sid.clone(),
                target_id: computer.object_identifier.clone(),
                relationship_type: RelationshipType::CanRDP,
                is_acl: false,
                is_inherited: false,
                properties: HashMap::new(),
            });
        }

        // PS Remote users
        for ps in &computer.ps_remote_users.results {
            relationships.push(ADRelationship {
                source_id: ps.principal_sid.clone(),
                target_id: computer.object_identifier.clone(),
                relationship_type: RelationshipType::CanPSRemote,
                is_acl: false,
                is_inherited: false,
                properties: HashMap::new(),
            });
        }

        // DCOM users
        for dcom in &computer.dcom_users.results {
            relationships.push(ADRelationship {
                source_id: dcom.principal_sid.clone(),
                target_id: computer.object_identifier.clone(),
                relationship_type: RelationshipType::ExecuteDCOM,
                is_acl: false,
                is_inherited: false,
                properties: HashMap::new(),
            });
        }

        // ACEs
        for ace in &computer.aces {
            if let Some(rel_type) = ace_to_relationship_type(&ace.right_name) {
                relationships.push(ADRelationship {
                    source_id: ace.principal_sid.clone(),
                    target_id: computer.object_identifier.clone(),
                    relationship_type: rel_type,
                    is_acl: true,
                    is_inherited: ace.is_inherited,
                    properties: HashMap::new(),
                });
            }
        }
    }

    // Extract group relationships
    for group in &data.groups {
        // Members
        for member in &group.members {
            relationships.push(ADRelationship {
                source_id: member.object_identifier.clone(),
                target_id: group.object_identifier.clone(),
                relationship_type: RelationshipType::MemberOf,
                is_acl: false,
                is_inherited: false,
                properties: HashMap::new(),
            });
        }

        // ACEs
        for ace in &group.aces {
            if let Some(rel_type) = ace_to_relationship_type(&ace.right_name) {
                relationships.push(ADRelationship {
                    source_id: ace.principal_sid.clone(),
                    target_id: group.object_identifier.clone(),
                    relationship_type: rel_type,
                    is_acl: true,
                    is_inherited: ace.is_inherited,
                    properties: HashMap::new(),
                });
            }
        }
    }

    // Extract domain relationships
    for domain in &data.domains {
        // Trusts
        for trust in &domain.trusts {
            relationships.push(ADRelationship {
                source_id: domain.object_identifier.clone(),
                target_id: trust.target_domain_sid.clone(),
                relationship_type: RelationshipType::TrustedBy,
                is_acl: false,
                is_inherited: false,
                properties: HashMap::new(),
            });
        }

        // GP Links
        for link in &domain.links {
            relationships.push(ADRelationship {
                source_id: link.guid.clone(),
                target_id: domain.object_identifier.clone(),
                relationship_type: RelationshipType::GPLink,
                is_acl: false,
                is_inherited: false,
                properties: HashMap::new(),
            });
        }

        // ACEs
        for ace in &domain.aces {
            if let Some(rel_type) = ace_to_relationship_type(&ace.right_name) {
                relationships.push(ADRelationship {
                    source_id: ace.principal_sid.clone(),
                    target_id: domain.object_identifier.clone(),
                    relationship_type: rel_type,
                    is_acl: true,
                    is_inherited: ace.is_inherited,
                    properties: HashMap::new(),
                });
            }
        }
    }

    // Extract OU relationships
    for ou in &data.ous {
        // Child objects
        for child in &ou.child_objects {
            relationships.push(ADRelationship {
                source_id: ou.object_identifier.clone(),
                target_id: child.object_identifier.clone(),
                relationship_type: RelationshipType::Contains,
                is_acl: false,
                is_inherited: false,
                properties: HashMap::new(),
            });
        }

        // GP Links
        for link in &ou.links {
            relationships.push(ADRelationship {
                source_id: link.guid.clone(),
                target_id: ou.object_identifier.clone(),
                relationship_type: RelationshipType::GPLink,
                is_acl: false,
                is_inherited: false,
                properties: HashMap::new(),
            });
        }
    }

    debug!("Extracted {} relationships", relationships.len());
    relationships
}

/// Map ACE right name to relationship type
fn ace_to_relationship_type(right_name: &str) -> Option<RelationshipType> {
    match right_name {
        "GenericAll" => Some(RelationshipType::GenericAll),
        "GenericWrite" => Some(RelationshipType::GenericWrite),
        "WriteOwner" => Some(RelationshipType::WriteOwner),
        "WriteDacl" => Some(RelationshipType::WriteDacl),
        "AddMember" => Some(RelationshipType::AddMember),
        "ForceChangePassword" => Some(RelationshipType::ForceChangePassword),
        "AllExtendedRights" => Some(RelationshipType::AllExtendedRights),
        "Owns" => Some(RelationshipType::Owns),
        "GetChanges" => Some(RelationshipType::GetChanges),
        "GetChangesAll" => Some(RelationshipType::GetChangesAll),
        "ReadLAPSPassword" => Some(RelationshipType::ReadLAPSPassword),
        "ReadGMSAPassword" => Some(RelationshipType::ReadGMSAPassword),
        "AddKeyCredentialLink" => Some(RelationshipType::AddKeyCredentialLink),
        "DCSync" => Some(RelationshipType::DCSync),
        _ => None,
    }
}

/// Format Windows FILETIME to ISO string
fn format_timestamp(timestamp: i64) -> String {
    if timestamp <= 0 {
        return "Never".to_string();
    }

    // Windows FILETIME is 100-nanosecond intervals since Jan 1, 1601
    // Convert to Unix timestamp (seconds since Jan 1, 1970)
    let unix_seconds = (timestamp / 10_000_000) - 11_644_473_600;

    if unix_seconds < 0 {
        return "Never".to_string();
    }

    chrono::DateTime::from_timestamp(unix_seconds, 0)
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
        .unwrap_or_else(|| "Invalid".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_timestamp() {
        // Test with 0
        assert_eq!(format_timestamp(0), "Never");

        // Test with a known timestamp (Jan 1, 2020 00:00:00 UTC)
        // Windows FILETIME: 132224352000000000
        let ts = 132224352000000000i64;
        let result = format_timestamp(ts);
        assert!(result.contains("2020"));
    }

    #[test]
    fn test_ace_to_relationship() {
        assert_eq!(
            ace_to_relationship_type("GenericAll"),
            Some(RelationshipType::GenericAll)
        );
        assert_eq!(
            ace_to_relationship_type("DCSync"),
            Some(RelationshipType::DCSync)
        );
        assert_eq!(ace_to_relationship_type("Unknown"), None);
    }
}
