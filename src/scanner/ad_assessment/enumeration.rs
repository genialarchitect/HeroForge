//! Active Directory Enumeration
//!
//! This module handles enumeration of AD objects: users, groups, computers, OUs, GPOs.

use anyhow::Result;
use ldap3::Scope;
use log::{info, warn};

use super::ldap_client::{ldap_utils, AdLdapClient};
use super::types::*;

/// Enumerate domain information
pub async fn enumerate_domain_info(client: &mut AdLdapClient) -> Result<AdDomainInfo> {
    info!("Enumerating domain information");

    let rootdse = client.get_rootdse().await?;
    let base_dn = client.base_dn().to_string();

    // Extract domain info from RootDSE
    let domain_name = dn_to_domain_name(&base_dn);
    let dns_host_name = ldap_utils::get_attr(&rootdse, "dnsHostName");
    let ldap_service_name = ldap_utils::get_attr(&rootdse, "ldapServiceName");

    let domain_level = ldap_utils::get_attr(&rootdse, "domainFunctionality")
        .and_then(|v| v.parse::<u32>().ok())
        .map(functional_level_to_string);

    let forest_level = ldap_utils::get_attr(&rootdse, "forestFunctionality")
        .and_then(|v| v.parse::<u32>().ok())
        .map(functional_level_to_string);

    // Try to get NetBIOS name from configuration
    let netbios_name = get_netbios_name(client, &base_dn).await.ok();

    // Extract forest name from ldapServiceName if available
    let forest_name = ldap_service_name
        .as_ref()
        .and_then(|s| s.split(':').next())
        .map(String::from);

    // Try to get domain SID
    let domain_sid = get_domain_sid(client, &base_dn).await.ok();

    Ok(AdDomainInfo {
        domain_name,
        netbios_name,
        forest_name,
        domain_level,
        forest_level,
        dc_name: dns_host_name,
        domain_sid,
        base_dn,
    })
}

/// Enumerate AD users
pub async fn enumerate_users(
    client: &mut AdLdapClient,
    max_results: u32,
) -> Result<Vec<AdUser>> {
    info!("Enumerating AD users (max: {})", max_results);

    let filter = "(&(objectClass=user)(objectCategory=person))";
    let attrs = vec![
        "distinguishedName",
        "sAMAccountName",
        "userPrincipalName",
        "displayName",
        "mail",
        "description",
        "userAccountControl",
        "memberOf",
        "servicePrincipalName",
        "lastLogon",
        "lastLogonTimestamp",
        "pwdLastSet",
        "whenCreated",
        "adminCount",
        "msDS-AllowedToDelegateTo",
    ];

    let entries = client
        .search_paged("", Scope::Subtree, filter, attrs, 1000, max_results)
        .await?;

    let mut users = Vec::new();

    for entry in entries {
        let dn = entry.dn.clone();
        let sam = match ldap_utils::get_attr(&entry, "sAMAccountName") {
            Some(s) => s,
            None => continue,
        };

        let uac = ldap_utils::get_u32_attr(&entry, "userAccountControl").unwrap_or(0);
        let flags = ldap_utils::parse_uac_flags(uac);

        let spns = ldap_utils::get_attrs(&entry, "servicePrincipalName");
        let member_of = ldap_utils::get_attrs(&entry, "memberOf");

        let last_logon = ldap_utils::get_attr(&entry, "lastLogonTimestamp")
            .or_else(|| ldap_utils::get_attr(&entry, "lastLogon"))
            .and_then(|v| ldap_utils::parse_filetime(&v));

        let pwd_last_set = ldap_utils::get_attr(&entry, "pwdLastSet")
            .and_then(|v| ldap_utils::parse_filetime(&v));

        let created = ldap_utils::get_attr(&entry, "whenCreated")
            .and_then(|v| ldap_utils::parse_generalized_time(&v));

        let admin_count = ldap_utils::get_attr(&entry, "adminCount")
            .map(|v| v == "1")
            .unwrap_or(false);

        // Build risk indicators
        let mut risk_indicators = Vec::new();
        if flags.dont_require_preauth {
            risk_indicators.push("AS-REP Roastable".to_string());
        }
        if !spns.is_empty() {
            risk_indicators.push("Kerberoastable (has SPNs)".to_string());
        }
        if flags.trusted_for_delegation {
            risk_indicators.push("Unconstrained Delegation".to_string());
        }
        if flags.trusted_to_auth_for_delegation {
            risk_indicators.push("Constrained Delegation".to_string());
        }
        if flags.password_not_required {
            risk_indicators.push("Password Not Required".to_string());
        }
        if flags.dont_expire_password {
            risk_indicators.push("Password Never Expires".to_string());
        }
        if admin_count {
            risk_indicators.push("AdminCount=1 (Protected)".to_string());
        }

        users.push(AdUser {
            dn,
            sam_account_name: sam,
            upn: ldap_utils::get_attr(&entry, "userPrincipalName"),
            display_name: ldap_utils::get_attr(&entry, "displayName"),
            email: ldap_utils::get_attr(&entry, "mail"),
            description: ldap_utils::get_attr(&entry, "description"),
            enabled: !flags.disabled,
            password_never_expires: flags.dont_expire_password,
            password_not_required: flags.password_not_required,
            locked_out: flags.lockout,
            dont_require_preauth: flags.dont_require_preauth,
            not_delegated: flags.not_delegated,
            trusted_for_delegation: flags.trusted_for_delegation,
            trusted_for_constrained_delegation: flags.trusted_to_auth_for_delegation,
            spns,
            member_of,
            last_logon,
            password_last_set: pwd_last_set,
            created,
            user_account_control: uac,
            admin_count,
            risk_indicators,
        });
    }

    info!("Enumerated {} users", users.len());
    Ok(users)
}

/// Enumerate AD groups
pub async fn enumerate_groups(
    client: &mut AdLdapClient,
    max_results: u32,
) -> Result<Vec<AdGroup>> {
    info!("Enumerating AD groups (max: {})", max_results);

    let filter = "(objectClass=group)";
    let attrs = vec![
        "distinguishedName",
        "sAMAccountName",
        "displayName",
        "description",
        "groupType",
        "member",
        "memberOf",
        "adminCount",
    ];

    let entries = client
        .search_paged("", Scope::Subtree, filter, attrs, 1000, max_results)
        .await?;

    let mut groups = Vec::new();

    for entry in entries {
        let dn = entry.dn.clone();
        let sam = match ldap_utils::get_attr(&entry, "sAMAccountName") {
            Some(s) => s,
            None => continue,
        };

        let group_type_raw = ldap_utils::get_int_attr(&entry, "groupType").unwrap_or(0) as i32;
        let (is_security, scope) = ldap_utils::parse_group_type(group_type_raw);

        let members = ldap_utils::get_attrs(&entry, "member");
        let member_of = ldap_utils::get_attrs(&entry, "memberOf");

        let admin_count = ldap_utils::get_attr(&entry, "adminCount")
            .map(|v| v == "1")
            .unwrap_or(false);

        // Check if this is a privileged group
        let is_privileged = is_privileged_group(&sam, &dn);

        groups.push(AdGroup {
            dn,
            sam_account_name: sam,
            display_name: ldap_utils::get_attr(&entry, "displayName"),
            description: ldap_utils::get_attr(&entry, "description"),
            group_type: if is_security {
                AdGroupType::Security
            } else {
                AdGroupType::Distribution
            },
            group_scope: scope,
            members,
            member_of,
            is_privileged,
            admin_count,
        });
    }

    info!("Enumerated {} groups", groups.len());
    Ok(groups)
}

/// Enumerate AD computers
pub async fn enumerate_computers(
    client: &mut AdLdapClient,
    max_results: u32,
) -> Result<Vec<AdComputer>> {
    info!("Enumerating AD computers (max: {})", max_results);

    let filter = "(objectClass=computer)";
    let attrs = vec![
        "distinguishedName",
        "sAMAccountName",
        "dNSHostName",
        "operatingSystem",
        "operatingSystemVersion",
        "operatingSystemServicePack",
        "userAccountControl",
        "servicePrincipalName",
        "lastLogonTimestamp",
        "whenCreated",
        "msDS-AllowedToDelegateTo",
    ];

    let entries = client
        .search_paged("", Scope::Subtree, filter, attrs, 1000, max_results)
        .await?;

    let mut computers = Vec::new();

    for entry in entries {
        let dn = entry.dn.clone();
        let sam = match ldap_utils::get_attr(&entry, "sAMAccountName") {
            Some(s) => s,
            None => continue,
        };

        let uac = ldap_utils::get_u32_attr(&entry, "userAccountControl").unwrap_or(0);
        let flags = ldap_utils::parse_uac_flags(uac);

        let spns = ldap_utils::get_attrs(&entry, "servicePrincipalName");

        let last_logon = ldap_utils::get_attr(&entry, "lastLogonTimestamp")
            .and_then(|v| ldap_utils::parse_filetime(&v));

        let created = ldap_utils::get_attr(&entry, "whenCreated")
            .and_then(|v| ldap_utils::parse_generalized_time(&v));

        // Check if it's a domain controller
        let is_dc = flags.server_trust_account
            || dn.to_lowercase().contains("domain controllers");

        computers.push(AdComputer {
            dn,
            sam_account_name: sam,
            dns_hostname: ldap_utils::get_attr(&entry, "dNSHostName"),
            operating_system: ldap_utils::get_attr(&entry, "operatingSystem"),
            operating_system_version: ldap_utils::get_attr(&entry, "operatingSystemVersion"),
            operating_system_sp: ldap_utils::get_attr(&entry, "operatingSystemServicePack"),
            enabled: !flags.disabled,
            is_domain_controller: is_dc,
            trusted_for_delegation: flags.trusted_for_delegation,
            trusted_for_constrained_delegation: flags.trusted_to_auth_for_delegation,
            spns,
            last_logon,
            created,
        });
    }

    info!("Enumerated {} computers", computers.len());
    Ok(computers)
}

/// Enumerate organizational units
pub async fn enumerate_ous(
    client: &mut AdLdapClient,
    max_results: u32,
) -> Result<Vec<AdOrganizationalUnit>> {
    info!("Enumerating OUs (max: {})", max_results);

    let filter = "(objectClass=organizationalUnit)";
    let attrs = vec![
        "distinguishedName",
        "name",
        "description",
        "gpLink",
    ];

    let entries = client
        .search_paged("", Scope::Subtree, filter, attrs, 1000, max_results)
        .await?;

    let mut ous = Vec::new();

    for entry in entries {
        let dn = entry.dn.clone();
        let name = ldap_utils::get_attr(&entry, "name").unwrap_or_else(|| {
            // Extract name from DN
            dn.split(',')
                .next()
                .and_then(|s| s.strip_prefix("OU="))
                .map(String::from)
                .unwrap_or_default()
        });

        // Parse gpLink to extract linked GPOs
        let linked_gpos = ldap_utils::get_attr(&entry, "gpLink")
            .map(|link| parse_gp_link(&link))
            .unwrap_or_default();

        ous.push(AdOrganizationalUnit {
            dn,
            name,
            description: ldap_utils::get_attr(&entry, "description"),
            linked_gpos,
        });
    }

    info!("Enumerated {} OUs", ous.len());
    Ok(ous)
}

/// Enumerate Group Policy Objects
pub async fn enumerate_gpos(
    client: &mut AdLdapClient,
    max_results: u32,
) -> Result<Vec<AdGroupPolicy>> {
    info!("Enumerating GPOs (max: {})", max_results);

    // GPOs are stored in the System/Policies container of the configuration NC
    // and in CN=Policies,CN=System,<domain_dn>
    let base_dn = client.base_dn();
    let policies_dn = format!("CN=Policies,CN=System,{}", base_dn);

    let filter = "(objectClass=groupPolicyContainer)";
    let attrs = vec![
        "distinguishedName",
        "displayName",
        "name",
        "versionNumber",
        "whenCreated",
        "whenChanged",
        "gPCFileSysPath",
        "flags",
    ];

    let entries = match client
        .search_paged(&policies_dn, Scope::Subtree, filter, attrs, 1000, max_results)
        .await
    {
        Ok(e) => e,
        Err(e) => {
            warn!("Could not enumerate GPOs: {}", e);
            return Ok(Vec::new());
        }
    };

    let mut gpos = Vec::new();

    for entry in entries {
        let dn = entry.dn.clone();

        // Extract GUID from name attribute
        let gpo_guid = ldap_utils::get_attr(&entry, "name").unwrap_or_default();

        let version = ldap_utils::get_u32_attr(&entry, "versionNumber").unwrap_or(0);
        let flags = ldap_utils::get_u32_attr(&entry, "flags").unwrap_or(0);

        let created = ldap_utils::get_attr(&entry, "whenCreated")
            .and_then(|v| ldap_utils::parse_generalized_time(&v));

        let modified = ldap_utils::get_attr(&entry, "whenChanged")
            .and_then(|v| ldap_utils::parse_generalized_time(&v));

        // Flags: bit 0 = user disabled, bit 1 = computer disabled
        let user_enabled = (flags & 0x01) == 0;
        let computer_enabled = (flags & 0x02) == 0;

        gpos.push(AdGroupPolicy {
            dn,
            display_name: ldap_utils::get_attr(&entry, "displayName").unwrap_or_default(),
            gpo_guid,
            version,
            created,
            modified,
            gpc_file_sys_path: ldap_utils::get_attr(&entry, "gPCFileSysPath"),
            user_version_enabled: user_enabled,
            computer_version_enabled: computer_enabled,
        });
    }

    info!("Enumerated {} GPOs", gpos.len());
    Ok(gpos)
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Convert a DN to a domain name (e.g., "DC=contoso,DC=local" -> "contoso.local")
fn dn_to_domain_name(dn: &str) -> String {
    dn.split(',')
        .filter_map(|part| {
            let part = part.trim();
            if part.to_uppercase().starts_with("DC=") {
                Some(part[3..].to_string())
            } else {
                None
            }
        })
        .collect::<Vec<_>>()
        .join(".")
}

/// Get NetBIOS name from configuration partition
async fn get_netbios_name(client: &mut AdLdapClient, base_dn: &str) -> Result<String> {
    let config_dn = format!("CN=Partitions,CN=Configuration,{}", base_dn);
    let filter = format!("(&(objectClass=crossRef)(nCName={}))", base_dn);

    let entries = client
        .search(&config_dn, Scope::OneLevel, &filter, vec!["nETBIOSName"])
        .await?;

    entries
        .first()
        .and_then(|e| ldap_utils::get_attr(e, "nETBIOSName"))
        .ok_or_else(|| anyhow::anyhow!("NetBIOS name not found"))
}

/// Get domain SID
async fn get_domain_sid(client: &mut AdLdapClient, base_dn: &str) -> Result<String> {
    let entries = client
        .search(base_dn, Scope::Base, "(objectClass=*)", vec!["objectSid"])
        .await?;

    entries
        .first()
        .and_then(|e| {
            e.bin_attrs.get("objectSid")
                .and_then(|v| v.first())
                .map(|sid_bytes| sid_to_string(sid_bytes))
        })
        .ok_or_else(|| anyhow::anyhow!("Domain SID not found"))
}

/// Convert SID bytes to string format
fn sid_to_string(sid_bytes: &[u8]) -> String {
    if sid_bytes.len() < 8 {
        return String::new();
    }

    let revision = sid_bytes[0];
    let sub_auth_count = sid_bytes[1] as usize;

    // Read identifier authority (big endian, 6 bytes)
    let auth: u64 = (sid_bytes[2] as u64) << 40
        | (sid_bytes[3] as u64) << 32
        | (sid_bytes[4] as u64) << 24
        | (sid_bytes[5] as u64) << 16
        | (sid_bytes[6] as u64) << 8
        | (sid_bytes[7] as u64);

    let mut result = format!("S-{}-{}", revision, auth);

    // Read sub-authorities (little endian, 4 bytes each)
    for i in 0..sub_auth_count {
        let offset = 8 + i * 4;
        if offset + 4 <= sid_bytes.len() {
            let sub_auth = u32::from_le_bytes([
                sid_bytes[offset],
                sid_bytes[offset + 1],
                sid_bytes[offset + 2],
                sid_bytes[offset + 3],
            ]);
            result.push_str(&format!("-{}", sub_auth));
        }
    }

    result
}

/// Convert functional level number to string
fn functional_level_to_string(level: u32) -> String {
    match level {
        0 => "Windows 2000".to_string(),
        1 => "Windows Server 2003 Mixed".to_string(),
        2 => "Windows Server 2003".to_string(),
        3 => "Windows Server 2008".to_string(),
        4 => "Windows Server 2008 R2".to_string(),
        5 => "Windows Server 2012".to_string(),
        6 => "Windows Server 2012 R2".to_string(),
        7 => "Windows Server 2016".to_string(),
        _ => format!("Unknown ({})", level),
    }
}

/// Check if a group is a well-known privileged group
fn is_privileged_group(sam_name: &str, dn: &str) -> bool {
    let privileged_groups = [
        "Domain Admins",
        "Enterprise Admins",
        "Schema Admins",
        "Administrators",
        "Account Operators",
        "Backup Operators",
        "Server Operators",
        "Print Operators",
        "DnsAdmins",
        "Domain Controllers",
        "Group Policy Creator Owners",
        "Cert Publishers",
    ];

    privileged_groups.iter().any(|g| {
        sam_name.eq_ignore_ascii_case(g)
            || dn.to_lowercase().contains(&format!("cn={}", g.to_lowercase()))
    })
}

/// Parse gpLink attribute to extract linked GPO DNs
fn parse_gp_link(gp_link: &str) -> Vec<String> {
    // Format: [LDAP://CN={GUID},CN=Policies,CN=System,DC=...;0][...]
    let mut gpos = Vec::new();

    for link in gp_link.split("][") {
        let link = link.trim_start_matches('[').trim_end_matches(']');
        if let Some(dn_start) = link.find("CN=") {
            if let Some(semicolon) = link.find(';') {
                let dn = &link[dn_start..semicolon];
                gpos.push(dn.to_string());
            }
        }
    }

    gpos
}
