//! ACL (Access Control List) Parser for Active Directory
//!
//! Parses Windows Security Descriptors from the nTSecurityDescriptor attribute
//! to detect dangerous permissions like GenericAll, WriteDacl, WriteOwner, DCSync.

use anyhow::{anyhow, Result};

use super::types::{AdDangerousAcl, AdPermissionType, FindingSeverity};

// ============================================================================
// Security Descriptor Structures
// ============================================================================

/// Parsed Windows Security Descriptor
#[derive(Debug, Clone)]
pub struct SecurityDescriptor {
    pub revision: u8,
    pub control: u16,
    pub owner_sid: Option<String>,
    pub group_sid: Option<String>,
    pub dacl: Option<Acl>,
    pub sacl: Option<Acl>,
}

/// Access Control List
#[derive(Debug, Clone)]
pub struct Acl {
    pub revision: u8,
    pub aces: Vec<Ace>,
}

/// Access Control Entry
#[derive(Debug, Clone)]
pub struct Ace {
    pub ace_type: AceType,
    pub flags: u8,
    pub access_mask: u32,
    pub principal_sid: String,
    pub object_guid: Option<String>,
    pub inherited_object_guid: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AceType {
    AccessAllowed,
    AccessDenied,
    AccessAllowedObject,
    AccessDeniedObject,
    SystemAudit,
    SystemAuditObject,
    Unknown(u8),
}

// ============================================================================
// Well-Known GUIDs and Access Rights
// ============================================================================

/// Extended Right GUIDs for DCSync and password operations
pub mod extended_rights {
    /// DS-Replication-Get-Changes
    pub const DS_REPLICATION_GET_CHANGES: &str = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2";
    /// DS-Replication-Get-Changes-All
    pub const DS_REPLICATION_GET_CHANGES_ALL: &str = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2";
    /// User-Force-Change-Password (Reset Password)
    pub const USER_FORCE_CHANGE_PASSWORD: &str = "00299570-246d-11d0-a768-00aa006e0529";
    /// DS-Replication-Get-Changes-In-Filtered-Set
    pub const DS_REPLICATION_GET_CHANGES_FILTERED: &str = "89e95b76-444d-4c62-991a-0facbeda640c";
}

/// Schema class and attribute GUIDs
pub mod schema_guids {
    /// User object class
    pub const USER: &str = "bf967aba-0de6-11d0-a285-00aa003049e2";
    /// Group object class
    pub const GROUP: &str = "bf967a9c-0de6-11d0-a285-00aa003049e2";
    /// Computer object class
    pub const COMPUTER: &str = "bf967a86-0de6-11d0-a285-00aa003049e2";
    /// Member attribute
    pub const MEMBER: &str = "bf9679c0-0de6-11d0-a285-00aa003049e2";
}

/// Access mask bit flags
pub mod access_rights {
    pub const GENERIC_READ: u32 = 0x80000000;
    pub const GENERIC_WRITE: u32 = 0x40000000;
    pub const GENERIC_EXECUTE: u32 = 0x20000000;
    pub const GENERIC_ALL: u32 = 0x10000000;
    pub const DELETE: u32 = 0x00010000;
    pub const READ_CONTROL: u32 = 0x00020000;
    pub const WRITE_DACL: u32 = 0x00040000;
    pub const WRITE_OWNER: u32 = 0x00080000;
    pub const SYNCHRONIZE: u32 = 0x00100000;

    // AD-specific rights
    pub const ADS_RIGHT_DS_CREATE_CHILD: u32 = 0x00000001;
    pub const ADS_RIGHT_DS_DELETE_CHILD: u32 = 0x00000002;
    pub const ADS_RIGHT_ACTRL_DS_LIST: u32 = 0x00000004;
    pub const ADS_RIGHT_DS_SELF: u32 = 0x00000008;
    pub const ADS_RIGHT_DS_READ_PROP: u32 = 0x00000010;
    pub const ADS_RIGHT_DS_WRITE_PROP: u32 = 0x00000020;
    pub const ADS_RIGHT_DS_DELETE_TREE: u32 = 0x00000040;
    pub const ADS_RIGHT_DS_LIST_OBJECT: u32 = 0x00000080;
    pub const ADS_RIGHT_DS_CONTROL_ACCESS: u32 = 0x00000100;
}

// ============================================================================
// Parsing Functions
// ============================================================================

/// Parse a binary security descriptor
pub fn parse_security_descriptor(bytes: &[u8]) -> Result<SecurityDescriptor> {
    if bytes.len() < 20 {
        return Err(anyhow!("Security descriptor too short: {} bytes", bytes.len()));
    }

    let revision = bytes[0];
    let _sbz1 = bytes[1];
    let control = u16::from_le_bytes([bytes[2], bytes[3]]);

    let owner_offset = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as usize;
    let group_offset = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]) as usize;
    let sacl_offset = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]) as usize;
    let dacl_offset = u32::from_le_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]) as usize;

    let owner_sid = if owner_offset > 0 && owner_offset < bytes.len() {
        parse_sid(&bytes[owner_offset..]).ok()
    } else {
        None
    };

    let group_sid = if group_offset > 0 && group_offset < bytes.len() {
        parse_sid(&bytes[group_offset..]).ok()
    } else {
        None
    };

    let dacl = if dacl_offset > 0 && dacl_offset < bytes.len() {
        parse_acl(&bytes[dacl_offset..]).ok()
    } else {
        None
    };

    let sacl = if sacl_offset > 0 && sacl_offset < bytes.len() {
        parse_acl(&bytes[sacl_offset..]).ok()
    } else {
        None
    };

    Ok(SecurityDescriptor {
        revision,
        control,
        owner_sid,
        group_sid,
        dacl,
        sacl,
    })
}

/// Parse a SID from bytes to string format (S-1-5-21-...)
pub fn parse_sid(bytes: &[u8]) -> Result<String> {
    if bytes.len() < 8 {
        return Err(anyhow!("SID too short: {} bytes", bytes.len()));
    }

    let revision = bytes[0];
    let sub_auth_count = bytes[1] as usize;

    // Identifier authority (6 bytes, big-endian)
    let auth: u64 = (bytes[2] as u64) << 40
        | (bytes[3] as u64) << 32
        | (bytes[4] as u64) << 24
        | (bytes[5] as u64) << 16
        | (bytes[6] as u64) << 8
        | (bytes[7] as u64);

    let mut result = format!("S-{}-{}", revision, auth);

    // Sub-authorities (4 bytes each, little-endian)
    let min_len = 8 + sub_auth_count * 4;
    if bytes.len() < min_len {
        return Err(anyhow!("SID truncated: expected {} bytes, got {}", min_len, bytes.len()));
    }

    for i in 0..sub_auth_count {
        let offset = 8 + i * 4;
        let sub_auth = u32::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]);
        result.push_str(&format!("-{}", sub_auth));
    }

    Ok(result)
}

/// Parse an ACL from bytes
fn parse_acl(bytes: &[u8]) -> Result<Acl> {
    if bytes.len() < 8 {
        return Err(anyhow!("ACL too short: {} bytes", bytes.len()));
    }

    let revision = bytes[0];
    let _sbz1 = bytes[1];
    let acl_size = u16::from_le_bytes([bytes[2], bytes[3]]) as usize;
    let ace_count = u16::from_le_bytes([bytes[4], bytes[5]]) as usize;
    let _sbz2 = u16::from_le_bytes([bytes[6], bytes[7]]);

    let mut aces = Vec::with_capacity(ace_count);
    let mut offset = 8;

    for _ in 0..ace_count {
        if offset + 4 > bytes.len() || offset + 4 > acl_size {
            break;
        }

        let ace_type = bytes[offset];
        let ace_flags = bytes[offset + 1];
        let ace_size = u16::from_le_bytes([bytes[offset + 2], bytes[offset + 3]]) as usize;

        if ace_size < 4 || offset + ace_size > bytes.len() {
            break;
        }

        if let Ok(ace) = parse_ace(&bytes[offset..offset + ace_size], ace_type, ace_flags) {
            aces.push(ace);
        }

        offset += ace_size;
    }

    Ok(Acl { revision, aces })
}

/// Parse an ACE from bytes
fn parse_ace(bytes: &[u8], ace_type: u8, ace_flags: u8) -> Result<Ace> {
    if bytes.len() < 8 {
        return Err(anyhow!("ACE too short: {} bytes", bytes.len()));
    }

    let access_mask = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);

    let (principal_offset, object_guid, inherited_guid) = match ace_type {
        0x05 | 0x06 | 0x07 | 0x08 => {
            // ACCESS_ALLOWED_OBJECT_ACE (0x05), ACCESS_DENIED_OBJECT_ACE (0x06)
            // SYSTEM_AUDIT_OBJECT_ACE (0x07), etc.
            if bytes.len() < 12 {
                return Err(anyhow!("Object ACE too short"));
            }
            let flags = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
            let mut off = 12;

            let obj_guid = if flags & 0x01 != 0 && off + 16 <= bytes.len() {
                let guid = parse_guid(&bytes[off..off + 16]);
                off += 16;
                Some(guid)
            } else {
                None
            };

            let inh_guid = if flags & 0x02 != 0 && off + 16 <= bytes.len() {
                let guid = parse_guid(&bytes[off..off + 16]);
                off += 16;
                Some(guid)
            } else {
                None
            };

            (off, obj_guid, inh_guid)
        }
        _ => (8, None, None),
    };

    let principal_sid = if principal_offset < bytes.len() {
        parse_sid(&bytes[principal_offset..]).unwrap_or_default()
    } else {
        String::new()
    };

    let ace_type_enum = match ace_type {
        0x00 => AceType::AccessAllowed,
        0x01 => AceType::AccessDenied,
        0x05 => AceType::AccessAllowedObject,
        0x06 => AceType::AccessDeniedObject,
        0x02 => AceType::SystemAudit,
        0x07 => AceType::SystemAuditObject,
        _ => AceType::Unknown(ace_type),
    };

    Ok(Ace {
        ace_type: ace_type_enum,
        flags: ace_flags,
        access_mask,
        principal_sid,
        object_guid,
        inherited_object_guid: inherited_guid,
    })
}

/// Parse a GUID from bytes to string format
fn parse_guid(bytes: &[u8]) -> String {
    if bytes.len() < 16 {
        return String::new();
    }

    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        u16::from_le_bytes([bytes[4], bytes[5]]),
        u16::from_le_bytes([bytes[6], bytes[7]]),
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    )
}

// ============================================================================
// Dangerous Permission Detection
// ============================================================================

/// Well-known safe SIDs that should be excluded from dangerous ACL reporting
fn is_safe_sid(sid: &str) -> bool {
    let safe_sids = [
        "S-1-5-18",      // NT AUTHORITY\SYSTEM
        "S-1-5-9",       // Enterprise Domain Controllers
        "S-1-5-10",      // NT AUTHORITY\SELF
        "S-1-3-0",       // Creator Owner
    ];

    // Check for exact matches
    if safe_sids.iter().any(|s| sid == *s) {
        return true;
    }

    // Domain Controllers groups end in -516
    if sid.ends_with("-516") {
        return true;
    }

    false
}

/// Check if a SID represents a privileged built-in group
fn is_builtin_privileged_sid(sid: &str) -> bool {
    // Well-known privileged group RIDs
    let privileged_rids = [
        "-512",  // Domain Admins
        "-519",  // Enterprise Admins
        "-518",  // Schema Admins
        "-544",  // Administrators
    ];

    privileged_rids.iter().any(|rid| sid.ends_with(rid))
}

/// Analyze a security descriptor for dangerous permissions
pub fn find_dangerous_permissions(
    sd: &SecurityDescriptor,
    object_dn: &str,
    object_type: &str,
    excluded_sids: &[String],
) -> Vec<AdDangerousAcl> {
    let mut dangerous = Vec::new();

    let dacl = match &sd.dacl {
        Some(d) => d,
        None => return dangerous,
    };

    for ace in &dacl.aces {
        // Only check allow ACEs
        if !matches!(ace.ace_type, AceType::AccessAllowed | AceType::AccessAllowedObject) {
            continue;
        }

        // Skip well-known safe SIDs
        if is_safe_sid(&ace.principal_sid) {
            continue;
        }

        // Skip explicitly excluded SIDs
        if excluded_sids.contains(&ace.principal_sid) {
            continue;
        }

        // Skip built-in privileged groups unless the object is high-value
        if is_builtin_privileged_sid(&ace.principal_sid) && !is_high_value_object(object_dn) {
            continue;
        }

        let is_inherited = (ace.flags & 0x10) != 0; // INHERITED_ACE flag

        // Check for GenericAll
        if (ace.access_mask & access_rights::GENERIC_ALL) != 0 {
            dangerous.push(AdDangerousAcl {
                object_dn: object_dn.to_string(),
                object_type: object_type.to_string(),
                principal: ace.principal_sid.clone(),
                principal_sid: Some(ace.principal_sid.clone()),
                permission: AdPermissionType::GenericAll,
                is_inherited,
                risk_level: FindingSeverity::Critical,
                attack_path: "Full control allows password reset, adding to groups, DCSync".to_string(),
            });
            continue; // GenericAll implies everything else
        }

        // Check for WriteDACL
        if (ace.access_mask & access_rights::WRITE_DACL) != 0 {
            dangerous.push(AdDangerousAcl {
                object_dn: object_dn.to_string(),
                object_type: object_type.to_string(),
                principal: ace.principal_sid.clone(),
                principal_sid: Some(ace.principal_sid.clone()),
                permission: AdPermissionType::WriteDacl,
                is_inherited,
                risk_level: FindingSeverity::Critical,
                attack_path: "Can modify permissions to grant self GenericAll".to_string(),
            });
        }

        // Check for WriteOwner
        if (ace.access_mask & access_rights::WRITE_OWNER) != 0 {
            dangerous.push(AdDangerousAcl {
                object_dn: object_dn.to_string(),
                object_type: object_type.to_string(),
                principal: ace.principal_sid.clone(),
                principal_sid: Some(ace.principal_sid.clone()),
                permission: AdPermissionType::WriteOwner,
                is_inherited,
                risk_level: FindingSeverity::High,
                attack_path: "Can take ownership to gain WriteDACL".to_string(),
            });
        }

        // Check for GenericWrite
        if (ace.access_mask & access_rights::GENERIC_WRITE) != 0 {
            dangerous.push(AdDangerousAcl {
                object_dn: object_dn.to_string(),
                object_type: object_type.to_string(),
                principal: ace.principal_sid.clone(),
                principal_sid: Some(ace.principal_sid.clone()),
                permission: AdPermissionType::GenericWrite,
                is_inherited,
                risk_level: FindingSeverity::High,
                attack_path: "Can modify object properties for privilege escalation".to_string(),
            });
        }

        // Check for extended rights / control access on domain objects (DCSync)
        if object_type.to_lowercase().contains("domain")
            && (ace.access_mask & access_rights::ADS_RIGHT_DS_CONTROL_ACCESS) != 0
        {
            if let Some(ref guid) = ace.object_guid {
                let guid_lower = guid.to_lowercase();
                if guid_lower == extended_rights::DS_REPLICATION_GET_CHANGES
                    || guid_lower == extended_rights::DS_REPLICATION_GET_CHANGES_ALL
                {
                    dangerous.push(AdDangerousAcl {
                        object_dn: object_dn.to_string(),
                        object_type: object_type.to_string(),
                        principal: ace.principal_sid.clone(),
                        principal_sid: Some(ace.principal_sid.clone()),
                        permission: AdPermissionType::DsSyncReplication,
                        is_inherited,
                        risk_level: FindingSeverity::Critical,
                        attack_path: "DCSync: Can extract all password hashes from domain".to_string(),
                    });
                }
            }
        }

        // Check for WriteProperty on member attribute (can add to groups)
        if (ace.access_mask & access_rights::ADS_RIGHT_DS_WRITE_PROP) != 0 {
            if let Some(ref guid) = ace.object_guid {
                if guid.to_lowercase() == schema_guids::MEMBER {
                    dangerous.push(AdDangerousAcl {
                        object_dn: object_dn.to_string(),
                        object_type: object_type.to_string(),
                        principal: ace.principal_sid.clone(),
                        principal_sid: Some(ace.principal_sid.clone()),
                        permission: AdPermissionType::AddMember,
                        is_inherited,
                        risk_level: FindingSeverity::High,
                        attack_path: "Can add members to group".to_string(),
                    });
                }
            }
        }

        // Check for Force Change Password
        if (ace.access_mask & access_rights::ADS_RIGHT_DS_CONTROL_ACCESS) != 0 {
            if let Some(ref guid) = ace.object_guid {
                if guid.to_lowercase() == extended_rights::USER_FORCE_CHANGE_PASSWORD {
                    dangerous.push(AdDangerousAcl {
                        object_dn: object_dn.to_string(),
                        object_type: object_type.to_string(),
                        principal: ace.principal_sid.clone(),
                        principal_sid: Some(ace.principal_sid.clone()),
                        permission: AdPermissionType::ForceChangePassword,
                        is_inherited,
                        risk_level: FindingSeverity::High,
                        attack_path: "Can reset user password without knowing current password".to_string(),
                    });
                }
            }
        }
    }

    dangerous
}

/// Check if an object DN indicates a high-value target
fn is_high_value_object(dn: &str) -> bool {
    let dn_lower = dn.to_lowercase();

    // Domain Admins, Enterprise Admins, Schema Admins, Administrators
    let high_value_groups = [
        "cn=domain admins",
        "cn=enterprise admins",
        "cn=schema admins",
        "cn=administrators",
        "cn=account operators",
        "cn=backup operators",
        "cn=domain controllers",
        "cn=adminsdholder",
    ];

    high_value_groups.iter().any(|hv| dn_lower.contains(hv))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_sid_basic() {
        // S-1-5-21-xxx SID example (simplified)
        let sid_bytes: Vec<u8> = vec![
            0x01, // Revision
            0x04, // Sub-authority count
            0x00, 0x00, 0x00, 0x00, 0x00, 0x05, // Authority (5 = NT Authority)
            0x15, 0x00, 0x00, 0x00, // Sub-auth 1: 21
            0x01, 0x00, 0x00, 0x00, // Sub-auth 2: 1
            0x02, 0x00, 0x00, 0x00, // Sub-auth 3: 2
            0x03, 0x00, 0x00, 0x00, // Sub-auth 4: 3
        ];
        let result = parse_sid(&sid_bytes).unwrap();
        assert_eq!(result, "S-1-5-21-1-2-3");
    }

    #[test]
    fn test_is_safe_sid() {
        assert!(is_safe_sid("S-1-5-18")); // SYSTEM
        assert!(is_safe_sid("S-1-5-9"));  // Enterprise DCs
        assert!(!is_safe_sid("S-1-5-21-1234-5678-9012-1001"));
    }

    #[test]
    fn test_is_builtin_privileged() {
        assert!(is_builtin_privileged_sid("S-1-5-21-xxx-512")); // Domain Admins
        assert!(is_builtin_privileged_sid("S-1-5-21-xxx-519")); // Enterprise Admins
        assert!(!is_builtin_privileged_sid("S-1-5-21-xxx-513")); // Domain Users
    }
}
