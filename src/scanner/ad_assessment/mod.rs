//! Active Directory Assessment Module
//!
//! This module provides comprehensive security assessment capabilities for
//! Active Directory environments. It performs enumeration of AD objects and
//! identifies security misconfigurations, attack paths, and vulnerabilities.
//!
//! **WARNING: This tool is for AUTHORIZED SECURITY TESTING ONLY.**
//! Unauthorized access to computer systems is illegal. Only use this tool
//! on systems you have explicit permission to test.
//!
//! # Features
//!
//! - Domain enumeration (domain info, functional levels, DCs)
//! - User enumeration with risk analysis (Kerberoasting, AS-REP roasting)
//! - Group enumeration (privileged groups, nested memberships)
//! - Computer enumeration (DCs, delegation settings)
//! - Password policy analysis
//! - Trust relationship mapping
//! - SPN enumeration for Kerberos attacks
//! - Dangerous ACL detection
//! - AD Certificate Services (ADCS) vulnerability scanning
//!
//! # Usage
//!
//! ```rust,ignore
//! use heroforge::scanner::ad_assessment::{run_ad_assessment, AdAssessmentConfig, AdAuthMode};
//!
//! let config = AdAssessmentConfig {
//!     domain_controller: "dc.contoso.local".to_string(),
//!     port: 389,
//!     use_ldaps: false,
//!     base_dn: None,
//!     auth_mode: AdAuthMode::Simple {
//!         username: "user".to_string(),
//!         password: "pass".to_string(),
//!         domain: Some("CONTOSO".to_string()),
//!     },
//!     scan_options: Default::default(),
//! };
//!
//! let results = run_ad_assessment(&config).await?;
//! ```

pub mod acl_parser;
pub mod enumeration;
pub mod ldap_client;
pub mod types;

pub use ldap_client::AdLdapClient;
pub use types::*;

use anyhow::Result;
use chrono::Utc;
use log::{error, info, warn};
use std::collections::HashMap;
use uuid::Uuid;

/// Run a complete AD assessment
pub async fn run_ad_assessment(config: &AdAssessmentConfig) -> Result<AdAssessmentResults> {
    let id = Uuid::new_v4().to_string();
    let scan_time = Utc::now();

    info!(
        "Starting AD assessment against {} (ID: {})",
        config.domain_controller, id
    );

    // Connect to domain controller
    let mut client = match AdLdapClient::connect(config).await {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to connect to domain controller: {}", e);
            return Ok(AdAssessmentResults {
                id,
                scan_time,
                domain_info: None,
                users: Vec::new(),
                groups: Vec::new(),
                computers: Vec::new(),
                organizational_units: Vec::new(),
                group_policies: Vec::new(),
                password_policy: None,
                trusts: Vec::new(),
                spns: Vec::new(),
                dangerous_acls: Vec::new(),
                certificate_templates: Vec::new(),
                certificate_authorities: Vec::new(),
                findings: vec![AdSecurityFinding {
                    id: Uuid::new_v4().to_string(),
                    title: "Connection Failed".to_string(),
                    description: format!("Failed to connect to domain controller: {}", e),
                    severity: FindingSeverity::Critical,
                    category: FindingCategory::Misconfiguration,
                    mitre_attack_ids: Vec::new(),
                    affected_objects: vec![config.domain_controller.clone()],
                    affected_count: 1,
                    remediation: "Verify network connectivity and credentials".to_string(),
                    risk_score: 0,
                    evidence: HashMap::new(),
                    references: Vec::new(),
                }],
                summary: AdAssessmentSummary::default(),
            });
        }
    };

    let opts = &config.scan_options;
    let max_objects = if opts.max_objects == 0 {
        u32::MAX
    } else {
        opts.max_objects
    };

    // Enumerate domain information
    let domain_info = match enumeration::enumerate_domain_info(&mut client).await {
        Ok(info) => {
            info!("Domain: {} ({})", info.domain_name, info.base_dn);
            Some(info)
        }
        Err(e) => {
            warn!("Failed to enumerate domain info: {}", e);
            None
        }
    };

    // Enumerate users
    let users = if opts.enumerate_users {
        match enumeration::enumerate_users(&mut client, max_objects).await {
            Ok(u) => {
                info!("Enumerated {} users", u.len());
                u
            }
            Err(e) => {
                warn!("Failed to enumerate users: {}", e);
                Vec::new()
            }
        }
    } else {
        Vec::new()
    };

    // Enumerate groups
    let groups = if opts.enumerate_groups {
        match enumeration::enumerate_groups(&mut client, max_objects).await {
            Ok(g) => {
                info!("Enumerated {} groups", g.len());
                g
            }
            Err(e) => {
                warn!("Failed to enumerate groups: {}", e);
                Vec::new()
            }
        }
    } else {
        Vec::new()
    };

    // Enumerate computers
    let computers = if opts.enumerate_computers {
        match enumeration::enumerate_computers(&mut client, max_objects).await {
            Ok(c) => {
                info!("Enumerated {} computers", c.len());
                c
            }
            Err(e) => {
                warn!("Failed to enumerate computers: {}", e);
                Vec::new()
            }
        }
    } else {
        Vec::new()
    };

    // Enumerate OUs
    let organizational_units = if opts.enumerate_ous {
        match enumeration::enumerate_ous(&mut client, max_objects).await {
            Ok(o) => {
                info!("Enumerated {} OUs", o.len());
                o
            }
            Err(e) => {
                warn!("Failed to enumerate OUs: {}", e);
                Vec::new()
            }
        }
    } else {
        Vec::new()
    };

    // Enumerate GPOs
    let group_policies = if opts.enumerate_gpos {
        match enumeration::enumerate_gpos(&mut client, max_objects).await {
            Ok(g) => {
                info!("Enumerated {} GPOs", g.len());
                g
            }
            Err(e) => {
                warn!("Failed to enumerate GPOs: {}", e);
                Vec::new()
            }
        }
    } else {
        Vec::new()
    };

    // Enumerate password policy
    let password_policy = if opts.check_password_policy {
        match enumeration::enumerate_password_policy(&mut client).await {
            Ok(policy) => {
                info!("Enumerated password policy");
                Some(policy)
            }
            Err(e) => {
                warn!("Failed to enumerate password policy: {}", e);
                None
            }
        }
    } else {
        None
    };

    // Enumerate trusts
    let trusts = if opts.check_trusts {
        match enumeration::enumerate_trusts(&mut client).await {
            Ok(t) => {
                info!("Enumerated {} trusts", t.len());
                t
            }
            Err(e) => {
                warn!("Failed to enumerate trusts: {}", e);
                Vec::new()
            }
        }
    } else {
        Vec::new()
    };

    // Enumerate ADCS (Certificate Services)
    let (certificate_templates, certificate_authorities) = if opts.check_adcs {
        match enumeration::enumerate_certificate_services(&mut client).await {
            Ok((templates, cas)) => {
                info!("Enumerated {} certificate templates, {} CAs", templates.len(), cas.len());
                (templates, cas)
            }
            Err(e) => {
                warn!("Failed to enumerate ADCS: {}", e);
                (Vec::new(), Vec::new())
            }
        }
    } else {
        (Vec::new(), Vec::new())
    };

    // Enumerate dangerous ACLs (on high-value objects)
    let dangerous_acls = if opts.check_acls {
        enumerate_dangerous_acls(&mut client, &users, &groups, domain_info.as_ref()).await
    } else {
        Vec::new()
    };

    // Close the LDAP connection
    if let Err(e) = client.close().await {
        warn!("Error closing LDAP connection: {}", e);
    }

    // Extract SPNs from users and computers
    let spns = extract_spns(&users, &computers);

    // Generate security findings
    let mut findings = generate_findings(&users, &groups, &computers, &spns, domain_info.as_ref());

    // Add password policy findings
    if let Some(ref policy) = password_policy {
        findings.extend(generate_password_policy_findings(policy));
    }

    // Add trust findings
    if !trusts.is_empty() {
        findings.extend(generate_trust_findings(&trusts));
    }

    // Add dangerous ACL findings
    if !dangerous_acls.is_empty() {
        findings.extend(generate_acl_findings(&dangerous_acls));
    }

    // Add ADCS findings
    if !certificate_templates.is_empty() {
        findings.extend(generate_adcs_findings(&certificate_templates));
    }

    // Calculate summary
    let summary = calculate_summary(&users, &computers, &findings);

    info!(
        "AD assessment complete: {} findings ({} critical, {} high)",
        findings.len(),
        summary.critical_findings,
        summary.high_findings
    );

    Ok(AdAssessmentResults {
        id,
        scan_time,
        domain_info,
        users,
        groups,
        computers,
        organizational_units,
        group_policies,
        password_policy,
        trusts,
        spns,
        dangerous_acls,
        certificate_templates,
        certificate_authorities,
        findings,
        summary,
    })
}

/// Extract SPNs from users and computers
fn extract_spns(users: &[AdUser], computers: &[AdComputer]) -> Vec<AdSpn> {
    let mut spns = Vec::new();

    for user in users {
        for spn_str in &user.spns {
            if let Some((service_class, hostname, port, service_name)) =
                ldap_client::ldap_utils::parse_spn(spn_str)
            {
                spns.push(AdSpn {
                    spn: spn_str.clone(),
                    service_class,
                    hostname,
                    port,
                    service_name,
                    account_dn: user.dn.clone(),
                    is_user_account: true,
                });
            }
        }
    }

    for computer in computers {
        for spn_str in &computer.spns {
            if let Some((service_class, hostname, port, service_name)) =
                ldap_client::ldap_utils::parse_spn(spn_str)
            {
                spns.push(AdSpn {
                    spn: spn_str.clone(),
                    service_class,
                    hostname,
                    port,
                    service_name,
                    account_dn: computer.dn.clone(),
                    is_user_account: false,
                });
            }
        }
    }

    spns
}

/// Generate security findings from enumeration results
fn generate_findings(
    users: &[AdUser],
    groups: &[AdGroup],
    computers: &[AdComputer],
    _spns: &[AdSpn],
    domain_info: Option<&AdDomainInfo>,
) -> Vec<AdSecurityFinding> {
    let mut findings = Vec::new();

    // Check for Kerberoastable accounts (users with SPNs)
    let kerberoastable: Vec<_> = users
        .iter()
        .filter(|u| !u.spns.is_empty() && u.enabled)
        .collect();

    if !kerberoastable.is_empty() {
        findings.push(AdSecurityFinding {
            id: Uuid::new_v4().to_string(),
            title: "Kerberoastable User Accounts".to_string(),
            description: format!(
                "Found {} user accounts with Service Principal Names (SPNs) that are vulnerable to Kerberoasting attacks. \
                 Attackers can request TGS tickets for these accounts and crack them offline to obtain passwords.",
                kerberoastable.len()
            ),
            severity: FindingSeverity::High,
            category: FindingCategory::Kerberos,
            mitre_attack_ids: vec!["T1558.003".to_string()],
            affected_objects: kerberoastable.iter().map(|u| u.dn.clone()).collect(),
            affected_count: kerberoastable.len() as u32,
            remediation: "Use Group Managed Service Accounts (gMSAs) or ensure service account passwords are long (25+ characters) and randomly generated. Consider removing unnecessary SPNs.".to_string(),
            risk_score: 75,
            evidence: {
                let mut ev = HashMap::new();
                ev.insert(
                    "accounts".to_string(),
                    serde_json::json!(kerberoastable
                        .iter()
                        .map(|u| {
                            serde_json::json!({
                                "sam_account_name": u.sam_account_name,
                                "spns": u.spns,
                            })
                        })
                        .collect::<Vec<_>>()),
                );
                ev
            },
            references: vec![
                "https://attack.mitre.org/techniques/T1558/003/".to_string(),
                "https://www.harmj0y.net/blog/powershell/kerberoasting-without-mimikatz/".to_string(),
            ],
        });
    }

    // Check for AS-REP roastable accounts
    let asrep_roastable: Vec<_> = users
        .iter()
        .filter(|u| u.dont_require_preauth && u.enabled)
        .collect();

    if !asrep_roastable.is_empty() {
        findings.push(AdSecurityFinding {
            id: Uuid::new_v4().to_string(),
            title: "AS-REP Roastable User Accounts".to_string(),
            description: format!(
                "Found {} user accounts with 'Do not require Kerberos preauthentication' enabled. \
                 Attackers can request AS-REP tickets for these accounts without authentication and crack them offline.",
                asrep_roastable.len()
            ),
            severity: FindingSeverity::High,
            category: FindingCategory::Kerberos,
            mitre_attack_ids: vec!["T1558.004".to_string()],
            affected_objects: asrep_roastable.iter().map(|u| u.dn.clone()).collect(),
            affected_count: asrep_roastable.len() as u32,
            remediation: "Enable Kerberos preauthentication for all user accounts. Only disable it if absolutely required for legacy applications.".to_string(),
            risk_score: 80,
            evidence: {
                let mut ev = HashMap::new();
                ev.insert(
                    "accounts".to_string(),
                    serde_json::json!(asrep_roastable
                        .iter()
                        .map(|u| u.sam_account_name.clone())
                        .collect::<Vec<_>>()),
                );
                ev
            },
            references: vec![
                "https://attack.mitre.org/techniques/T1558/004/".to_string(),
            ],
        });
    }

    // Check for unconstrained delegation
    let unconstrained_users: Vec<_> = users
        .iter()
        .filter(|u| u.trusted_for_delegation && u.enabled)
        .collect();

    let unconstrained_computers: Vec<_> = computers
        .iter()
        .filter(|c| c.trusted_for_delegation && c.enabled && !c.is_domain_controller)
        .collect();

    if !unconstrained_users.is_empty() || !unconstrained_computers.is_empty() {
        let mut affected = Vec::new();
        affected.extend(unconstrained_users.iter().map(|u| u.dn.clone()));
        affected.extend(unconstrained_computers.iter().map(|c| c.dn.clone()));

        findings.push(AdSecurityFinding {
            id: Uuid::new_v4().to_string(),
            title: "Unconstrained Delegation Enabled".to_string(),
            description: format!(
                "Found {} non-DC accounts with unconstrained delegation enabled. \
                 An attacker who compromises these systems can impersonate any user that authenticates to them, \
                 including privileged accounts.",
                affected.len()
            ),
            severity: FindingSeverity::Critical,
            category: FindingCategory::Delegation,
            mitre_attack_ids: vec!["T1558.001".to_string()],
            affected_objects: affected.clone(),
            affected_count: affected.len() as u32,
            remediation: "Replace unconstrained delegation with constrained delegation or resource-based constrained delegation. Monitor for TGT requests to these systems.".to_string(),
            risk_score: 90,
            evidence: {
                let mut ev = HashMap::new();
                ev.insert(
                    "users".to_string(),
                    serde_json::json!(unconstrained_users
                        .iter()
                        .map(|u| u.sam_account_name.clone())
                        .collect::<Vec<_>>()),
                );
                ev.insert(
                    "computers".to_string(),
                    serde_json::json!(unconstrained_computers
                        .iter()
                        .map(|c| c.sam_account_name.clone())
                        .collect::<Vec<_>>()),
                );
                ev
            },
            references: vec![
                "https://attack.mitre.org/techniques/T1558/001/".to_string(),
                "https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/".to_string(),
            ],
        });
    }

    // Check for password not required
    let no_password: Vec<_> = users
        .iter()
        .filter(|u| u.password_not_required && u.enabled)
        .collect();

    if !no_password.is_empty() {
        findings.push(AdSecurityFinding {
            id: Uuid::new_v4().to_string(),
            title: "Accounts with Password Not Required".to_string(),
            description: format!(
                "Found {} enabled user accounts with 'Password not required' flag set. \
                 These accounts may have blank passwords or be vulnerable to password spraying attacks.",
                no_password.len()
            ),
            severity: FindingSeverity::High,
            category: FindingCategory::AccountSecurity,
            mitre_attack_ids: vec!["T1078.002".to_string()],
            affected_objects: no_password.iter().map(|u| u.dn.clone()).collect(),
            affected_count: no_password.len() as u32,
            remediation: "Remove the 'Password not required' flag and set strong passwords for all accounts.".to_string(),
            risk_score: 70,
            evidence: {
                let mut ev = HashMap::new();
                ev.insert(
                    "accounts".to_string(),
                    serde_json::json!(no_password
                        .iter()
                        .map(|u| u.sam_account_name.clone())
                        .collect::<Vec<_>>()),
                );
                ev
            },
            references: vec![
                "https://attack.mitre.org/techniques/T1078/002/".to_string(),
            ],
        });
    }

    // Check for password never expires
    let never_expires: Vec<_> = users
        .iter()
        .filter(|u| u.password_never_expires && u.enabled && u.admin_count)
        .collect();

    if !never_expires.is_empty() {
        findings.push(AdSecurityFinding {
            id: Uuid::new_v4().to_string(),
            title: "Privileged Accounts with Password Never Expires".to_string(),
            description: format!(
                "Found {} privileged accounts with 'Password never expires' set. \
                 Long-lived passwords increase the risk of credential compromise.",
                never_expires.len()
            ),
            severity: FindingSeverity::Medium,
            category: FindingCategory::PasswordPolicy,
            mitre_attack_ids: vec!["T1078.002".to_string()],
            affected_objects: never_expires.iter().map(|u| u.dn.clone()).collect(),
            affected_count: never_expires.len() as u32,
            remediation: "Implement password rotation for privileged accounts. Consider using PAM solutions for just-in-time privilege access.".to_string(),
            risk_score: 50,
            evidence: {
                let mut ev = HashMap::new();
                ev.insert(
                    "accounts".to_string(),
                    serde_json::json!(never_expires
                        .iter()
                        .map(|u| u.sam_account_name.clone())
                        .collect::<Vec<_>>()),
                );
                ev
            },
            references: vec![
                "https://docs.microsoft.com/en-us/azure/active-directory/roles/security-planning".to_string(),
            ],
        });
    }

    // Check for privileged group membership
    let privileged_groups: Vec<_> = groups.iter().filter(|g| g.is_privileged).collect();
    let mut total_privileged_users = 0;
    for group in &privileged_groups {
        total_privileged_users += group.members.len();
    }

    if total_privileged_users > 10 {
        findings.push(AdSecurityFinding {
            id: Uuid::new_v4().to_string(),
            title: "Excessive Privileged Group Membership".to_string(),
            description: format!(
                "Found {} members across privileged groups. \
                 Large numbers of privileged accounts increase the attack surface.",
                total_privileged_users
            ),
            severity: FindingSeverity::Medium,
            category: FindingCategory::PrivilegedAccess,
            mitre_attack_ids: vec!["T1078.002".to_string()],
            affected_objects: privileged_groups.iter().map(|g| g.dn.clone()).collect(),
            affected_count: privileged_groups.len() as u32,
            remediation: "Review privileged group memberships and remove unnecessary access. Implement least-privilege access and use just-in-time privilege solutions.".to_string(),
            risk_score: 55,
            evidence: {
                let mut ev = HashMap::new();
                ev.insert(
                    "groups".to_string(),
                    serde_json::json!(privileged_groups
                        .iter()
                        .map(|g| {
                            serde_json::json!({
                                "name": g.sam_account_name,
                                "member_count": g.members.len(),
                            })
                        })
                        .collect::<Vec<_>>()),
                );
                ev
            },
            references: vec![
                "https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory".to_string(),
            ],
        });
    }

    // Check for outdated domain functional level
    if let Some(info) = domain_info {
        if let Some(ref level) = info.domain_level {
            if level.contains("2008") || level.contains("2003") || level.contains("2000") {
                findings.push(AdSecurityFinding {
                    id: Uuid::new_v4().to_string(),
                    title: "Outdated Domain Functional Level".to_string(),
                    description: format!(
                        "Domain functional level is set to '{}'. \
                         Older functional levels lack security features available in newer versions.",
                        level
                    ),
                    severity: FindingSeverity::Medium,
                    category: FindingCategory::Misconfiguration,
                    mitre_attack_ids: Vec::new(),
                    affected_objects: vec![info.domain_name.clone()],
                    affected_count: 1,
                    remediation: "Upgrade domain controllers and raise the domain functional level to Windows Server 2016 or higher.".to_string(),
                    risk_score: 40,
                    evidence: {
                        let mut ev = HashMap::new();
                        ev.insert("domain_level".to_string(), serde_json::json!(level));
                        ev.insert(
                            "forest_level".to_string(),
                            serde_json::json!(info.forest_level),
                        );
                        ev
                    },
                    references: vec![
                        "https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/active-directory-functional-levels".to_string(),
                    ],
                });
            }
        }
    }

    findings
}

/// Calculate summary statistics
fn calculate_summary(
    users: &[AdUser],
    computers: &[AdComputer],
    findings: &[AdSecurityFinding],
) -> AdAssessmentSummary {
    let mut findings_by_severity = HashMap::new();
    let mut critical = 0u32;
    let mut high = 0u32;
    let mut medium = 0u32;
    let mut low = 0u32;

    for finding in findings {
        let severity_str = finding.severity.to_string();
        *findings_by_severity.entry(severity_str).or_insert(0) += 1;

        match finding.severity {
            FindingSeverity::Critical => critical += 1,
            FindingSeverity::High => high += 1,
            FindingSeverity::Medium => medium += 1,
            FindingSeverity::Low => low += 1,
            FindingSeverity::Info => {}
        }
    }

    let kerberoastable = users.iter().filter(|u| !u.spns.is_empty() && u.enabled).count() as u32;
    let asrep_roastable = users
        .iter()
        .filter(|u| u.dont_require_preauth && u.enabled)
        .count() as u32;
    let unconstrained = users
        .iter()
        .filter(|u| u.trusted_for_delegation && u.enabled)
        .count() as u32
        + computers
            .iter()
            .filter(|c| c.trusted_for_delegation && c.enabled && !c.is_domain_controller)
            .count() as u32;
    let constrained = users
        .iter()
        .filter(|u| u.trusted_for_constrained_delegation && u.enabled)
        .count() as u32
        + computers
            .iter()
            .filter(|c| c.trusted_for_constrained_delegation && c.enabled)
            .count() as u32;
    let privileged = users.iter().filter(|u| u.admin_count && u.enabled).count() as u32;

    // Calculate overall risk score (0-100)
    let overall_risk_score = calculate_risk_score(critical, high, medium, low);

    AdAssessmentSummary {
        total_users: users.len() as u32,
        total_groups: 0, // Will be set by caller
        total_computers: computers.len() as u32,
        kerberoastable_accounts: kerberoastable,
        asrep_roastable_accounts: asrep_roastable,
        unconstrained_delegation_accounts: unconstrained,
        constrained_delegation_accounts: constrained,
        privileged_users: privileged,
        findings_by_severity,
        critical_findings: critical,
        high_findings: high,
        medium_findings: medium,
        low_findings: low,
        overall_risk_score,
    }
}

/// Calculate overall risk score based on findings
fn calculate_risk_score(critical: u32, high: u32, medium: u32, low: u32) -> u8 {
    // Weighted scoring: critical=40, high=20, medium=10, low=5
    let raw_score = (critical * 40 + high * 20 + medium * 10 + low * 5) as f32;
    // Normalize to 0-100 with diminishing returns
    let score = 100.0 * (1.0 - (-raw_score / 100.0).exp());
    score.min(100.0) as u8
}

// ============================================================================
// Dangerous ACL Enumeration
// ============================================================================

/// Enumerate dangerous ACLs on high-value AD objects
async fn enumerate_dangerous_acls(
    client: &mut AdLdapClient,
    users: &[AdUser],
    groups: &[AdGroup],
    domain_info: Option<&AdDomainInfo>,
) -> Vec<AdDangerousAcl> {
    use ldap3::Scope;

    let mut all_dangerous = Vec::new();
    let base_dn = client.base_dn().to_string();

    // Collect domain SID for exclusions
    let excluded_sids: Vec<String> = domain_info
        .and_then(|d| d.domain_sid.clone())
        .map(|sid| vec![format!("{}-512", sid), format!("{}-519", sid), format!("{}-516", sid)])
        .unwrap_or_default();

    // Query domain object for DCSync rights
    let domain_attrs = vec!["nTSecurityDescriptor"];
    if let Ok(entries) = client.search(&base_dn, Scope::Base, "(objectClass=domain)", domain_attrs).await {
        for entry in entries {
            if let Some(sd_bytes) = ldap_client::ldap_utils::get_binary_attr(&entry, "nTSecurityDescriptor") {
                if let Ok(sd) = acl_parser::parse_security_descriptor(&sd_bytes) {
                    let dangerous = acl_parser::find_dangerous_permissions(&sd, &base_dn, "domain", &excluded_sids);
                    all_dangerous.extend(dangerous);
                }
            }
        }
    }

    // Query AdminSDHolder for modifications
    let adminsdholder_dn = format!("CN=AdminSDHolder,CN=System,{}", base_dn);
    if let Ok(entries) = client.search(&adminsdholder_dn, Scope::Base, "(objectClass=*)", vec!["nTSecurityDescriptor"]).await {
        for entry in entries {
            if let Some(sd_bytes) = ldap_client::ldap_utils::get_binary_attr(&entry, "nTSecurityDescriptor") {
                if let Ok(sd) = acl_parser::parse_security_descriptor(&sd_bytes) {
                    let dangerous = acl_parser::find_dangerous_permissions(&sd, &adminsdholder_dn, "adminSDHolder", &excluded_sids);
                    all_dangerous.extend(dangerous);
                }
            }
        }
    }

    // Query privileged groups for write permissions
    let privileged_groups: Vec<_> = groups.iter().filter(|g| g.is_privileged).collect();
    for group in privileged_groups.iter().take(10) {
        if let Ok(entries) = client.search(&group.dn, Scope::Base, "(objectClass=*)", vec!["nTSecurityDescriptor"]).await {
            for entry in entries {
                if let Some(sd_bytes) = ldap_client::ldap_utils::get_binary_attr(&entry, "nTSecurityDescriptor") {
                    if let Ok(sd) = acl_parser::parse_security_descriptor(&sd_bytes) {
                        let dangerous = acl_parser::find_dangerous_permissions(&sd, &group.dn, "group", &excluded_sids);
                        all_dangerous.extend(dangerous);
                    }
                }
            }
        }
    }

    // Sample admin users for ForceChangePassword and other dangerous perms
    let admin_users: Vec<_> = users.iter().filter(|u| u.admin_count).take(20).collect();
    for user in admin_users {
        if let Ok(entries) = client.search(&user.dn, Scope::Base, "(objectClass=*)", vec!["nTSecurityDescriptor"]).await {
            for entry in entries {
                if let Some(sd_bytes) = ldap_client::ldap_utils::get_binary_attr(&entry, "nTSecurityDescriptor") {
                    if let Ok(sd) = acl_parser::parse_security_descriptor(&sd_bytes) {
                        let dangerous = acl_parser::find_dangerous_permissions(&sd, &user.dn, "user", &excluded_sids);
                        all_dangerous.extend(dangerous);
                    }
                }
            }
        }
    }

    info!("Found {} dangerous ACL entries", all_dangerous.len());
    all_dangerous
}

// ============================================================================
// Finding Generation Functions
// ============================================================================

/// Generate findings from password policy analysis
fn generate_password_policy_findings(policy: &AdPasswordPolicy) -> Vec<AdSecurityFinding> {
    let mut findings = Vec::new();

    // Check for weak password length
    if policy.min_password_length < 12 {
        findings.push(AdSecurityFinding {
            id: Uuid::new_v4().to_string(),
            title: "Weak Minimum Password Length".to_string(),
            description: format!(
                "Domain password policy requires only {} characters minimum. \
                 NIST recommends at least 12-14 characters for user passwords.",
                policy.min_password_length
            ),
            severity: if policy.min_password_length < 8 {
                FindingSeverity::High
            } else {
                FindingSeverity::Medium
            },
            category: FindingCategory::PasswordPolicy,
            mitre_attack_ids: vec!["T1110".to_string()],
            affected_objects: vec!["Domain Password Policy".to_string()],
            affected_count: 1,
            remediation: "Increase minimum password length to at least 14 characters.".to_string(),
            risk_score: if policy.min_password_length < 8 { 70 } else { 50 },
            evidence: {
                let mut ev = HashMap::new();
                ev.insert("min_length".to_string(), serde_json::json!(policy.min_password_length));
                ev
            },
            references: vec![
                "https://pages.nist.gov/800-63-3/sp800-63b.html".to_string(),
            ],
        });
    }

    // Check for no complexity
    if !policy.complexity_enabled {
        findings.push(AdSecurityFinding {
            id: Uuid::new_v4().to_string(),
            title: "Password Complexity Not Enabled".to_string(),
            description: "Domain password policy does not require password complexity. \
                 Passwords may be composed of dictionary words or simple patterns.".to_string(),
            severity: FindingSeverity::Medium,
            category: FindingCategory::PasswordPolicy,
            mitre_attack_ids: vec!["T1110".to_string()],
            affected_objects: vec!["Domain Password Policy".to_string()],
            affected_count: 1,
            remediation: "Enable password complexity requirements or implement a stronger passphrase policy.".to_string(),
            risk_score: 45,
            evidence: HashMap::new(),
            references: vec![
                "https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/password-must-meet-complexity-requirements".to_string(),
            ],
        });
    }

    // Check for no lockout threshold
    if policy.lockout_threshold == 0 {
        findings.push(AdSecurityFinding {
            id: Uuid::new_v4().to_string(),
            title: "No Account Lockout Policy".to_string(),
            description: "Domain has no account lockout threshold configured. \
                 Attackers can perform unlimited password guessing attacks.".to_string(),
            severity: FindingSeverity::High,
            category: FindingCategory::PasswordPolicy,
            mitre_attack_ids: vec!["T1110.001".to_string()],
            affected_objects: vec!["Domain Password Policy".to_string()],
            affected_count: 1,
            remediation: "Configure account lockout threshold (5-10 attempts) with reasonable lockout duration.".to_string(),
            risk_score: 65,
            evidence: HashMap::new(),
            references: vec![
                "https://attack.mitre.org/techniques/T1110/001/".to_string(),
            ],
        });
    }

    // Check for reversible encryption
    if policy.reversible_encryption_enabled {
        findings.push(AdSecurityFinding {
            id: Uuid::new_v4().to_string(),
            title: "Reversible Password Encryption Enabled".to_string(),
            description: "Domain is configured to store passwords using reversible encryption. \
                 This effectively stores passwords in plaintext in the AD database.".to_string(),
            severity: FindingSeverity::Critical,
            category: FindingCategory::PasswordPolicy,
            mitre_attack_ids: vec!["T1003.006".to_string()],
            affected_objects: vec!["Domain Password Policy".to_string()],
            affected_count: 1,
            remediation: "Disable 'Store password using reversible encryption' unless absolutely required for legacy applications.".to_string(),
            risk_score: 90,
            evidence: HashMap::new(),
            references: vec![
                "https://attack.mitre.org/techniques/T1003/006/".to_string(),
            ],
        });
    }

    findings
}

/// Generate findings from trust analysis
fn generate_trust_findings(trusts: &[AdTrust]) -> Vec<AdSecurityFinding> {
    let mut findings = Vec::new();

    // Check for external trusts without SID filtering
    let risky_trusts: Vec<_> = trusts
        .iter()
        .filter(|t| matches!(t.trust_type, TrustType::External | TrustType::Forest) && !t.sid_filtering_enabled)
        .collect();

    if !risky_trusts.is_empty() {
        findings.push(AdSecurityFinding {
            id: Uuid::new_v4().to_string(),
            title: "External Trust Without SID Filtering".to_string(),
            description: format!(
                "Found {} external/forest trust(s) without SID filtering enabled. \
                 Attackers in the trusted domain could forge SIDs to gain access.",
                risky_trusts.len()
            ),
            severity: FindingSeverity::High,
            category: FindingCategory::TrustRelationship,
            mitre_attack_ids: vec!["T1134.005".to_string()],
            affected_objects: risky_trusts.iter().map(|t| t.trusted_domain.clone()).collect(),
            affected_count: risky_trusts.len() as u32,
            remediation: "Enable SID filtering (quarantine) on all external and forest trusts.".to_string(),
            risk_score: 75,
            evidence: {
                let mut ev = HashMap::new();
                ev.insert(
                    "trusts".to_string(),
                    serde_json::json!(risky_trusts.iter().map(|t| &t.trusted_domain).collect::<Vec<_>>()),
                );
                ev
            },
            references: vec![
                "https://attack.mitre.org/techniques/T1134/005/".to_string(),
                "https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc773178(v=ws.10)".to_string(),
            ],
        });
    }

    // Check for bidirectional external trusts
    let bidir_external: Vec<_> = trusts
        .iter()
        .filter(|t| matches!(t.trust_type, TrustType::External) && matches!(t.direction, TrustDirection::Bidirectional))
        .collect();

    if !bidir_external.is_empty() {
        findings.push(AdSecurityFinding {
            id: Uuid::new_v4().to_string(),
            title: "Bidirectional External Trust".to_string(),
            description: format!(
                "Found {} bidirectional external trust(s). \
                 This allows users from external domains full authentication to this domain.",
                bidir_external.len()
            ),
            severity: FindingSeverity::Medium,
            category: FindingCategory::TrustRelationship,
            mitre_attack_ids: vec!["T1199".to_string()],
            affected_objects: bidir_external.iter().map(|t| t.trusted_domain.clone()).collect(),
            affected_count: bidir_external.len() as u32,
            remediation: "Review trust necessity. Consider one-way trusts or selective authentication.".to_string(),
            risk_score: 55,
            evidence: HashMap::new(),
            references: vec![
                "https://attack.mitre.org/techniques/T1199/".to_string(),
            ],
        });
    }

    findings
}

/// Generate findings from dangerous ACL analysis
fn generate_acl_findings(dangerous_acls: &[AdDangerousAcl]) -> Vec<AdSecurityFinding> {
    let mut findings = Vec::new();

    // DCSync permissions
    let dcsync: Vec<_> = dangerous_acls
        .iter()
        .filter(|a| matches!(a.permission, AdPermissionType::DsSyncReplication))
        .collect();

    if !dcsync.is_empty() {
        findings.push(AdSecurityFinding {
            id: Uuid::new_v4().to_string(),
            title: "DCSync Rights Detected".to_string(),
            description: format!(
                "Found {} non-standard principal(s) with DCSync rights. \
                 These accounts can extract all password hashes from the domain.",
                dcsync.len()
            ),
            severity: FindingSeverity::Critical,
            category: FindingCategory::Permissions,
            mitre_attack_ids: vec!["T1003.006".to_string()],
            affected_objects: dcsync.iter().map(|a| a.principal.clone()).collect(),
            affected_count: dcsync.len() as u32,
            remediation: "Remove GetChanges/GetChangesAll rights from non-DC accounts. Only Domain Controllers should have DCSync permissions.".to_string(),
            risk_score: 95,
            evidence: {
                let mut ev = HashMap::new();
                ev.insert(
                    "principals".to_string(),
                    serde_json::json!(dcsync.iter().map(|a| &a.principal).collect::<Vec<_>>()),
                );
                ev
            },
            references: vec![
                "https://attack.mitre.org/techniques/T1003/006/".to_string(),
            ],
        });
    }

    // GenericAll on high-value targets
    let generic_all: Vec<_> = dangerous_acls
        .iter()
        .filter(|a| matches!(a.permission, AdPermissionType::GenericAll))
        .collect();

    if !generic_all.is_empty() {
        findings.push(AdSecurityFinding {
            id: Uuid::new_v4().to_string(),
            title: "Excessive GenericAll Permissions".to_string(),
            description: format!(
                "Found {} instance(s) of GenericAll permissions on high-value objects. \
                 Full control allows complete object manipulation including password resets.",
                generic_all.len()
            ),
            severity: FindingSeverity::High,
            category: FindingCategory::Permissions,
            mitre_attack_ids: vec!["T1222.001".to_string()],
            affected_objects: generic_all.iter().map(|a| format!("{} -> {}", a.principal, a.object_dn)).collect(),
            affected_count: generic_all.len() as u32,
            remediation: "Review and remove unnecessary GenericAll permissions. Apply least privilege principle.".to_string(),
            risk_score: 80,
            evidence: HashMap::new(),
            references: vec![
                "https://attack.mitre.org/techniques/T1222/001/".to_string(),
                "https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html".to_string(),
            ],
        });
    }

    // WriteDACL permissions
    let write_dacl: Vec<_> = dangerous_acls
        .iter()
        .filter(|a| matches!(a.permission, AdPermissionType::WriteDacl))
        .collect();

    if !write_dacl.is_empty() {
        findings.push(AdSecurityFinding {
            id: Uuid::new_v4().to_string(),
            title: "WriteDACL Permissions on Sensitive Objects".to_string(),
            description: format!(
                "Found {} instance(s) of WriteDACL permissions. \
                 This allows modifying permissions to escalate to full control.",
                write_dacl.len()
            ),
            severity: FindingSeverity::High,
            category: FindingCategory::Permissions,
            mitre_attack_ids: vec!["T1222.001".to_string()],
            affected_objects: write_dacl.iter().map(|a| format!("{} -> {}", a.principal, a.object_dn)).collect(),
            affected_count: write_dacl.len() as u32,
            remediation: "Remove WriteDACL from non-administrative principals.".to_string(),
            risk_score: 75,
            evidence: HashMap::new(),
            references: vec![
                "https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#writedacl".to_string(),
            ],
        });
    }

    findings
}

/// Generate findings from ADCS analysis
fn generate_adcs_findings(templates: &[AdCertificateTemplate]) -> Vec<AdSecurityFinding> {
    let mut findings = Vec::new();

    // Collect vulnerable templates
    let esc1: Vec<_> = templates
        .iter()
        .filter(|t| t.vulnerabilities.iter().any(|v| v.contains("ESC1")))
        .collect();

    if !esc1.is_empty() {
        findings.push(AdSecurityFinding {
            id: Uuid::new_v4().to_string(),
            title: "ESC1: Vulnerable Certificate Templates".to_string(),
            description: format!(
                "Found {} certificate template(s) vulnerable to ESC1 attack. \
                 Enrollee can supply arbitrary Subject Alternative Name (SAN) for authentication.",
                esc1.len()
            ),
            severity: FindingSeverity::Critical,
            category: FindingCategory::CertificateServices,
            mitre_attack_ids: vec!["T1649".to_string()],
            affected_objects: esc1.iter().map(|t| t.name.clone()).collect(),
            affected_count: esc1.len() as u32,
            remediation: "Remove 'ENROLLEE_SUPPLIES_SUBJECT' flag or require manager approval on these templates.".to_string(),
            risk_score: 90,
            evidence: {
                let mut ev = HashMap::new();
                ev.insert(
                    "templates".to_string(),
                    serde_json::json!(esc1.iter().map(|t| &t.name).collect::<Vec<_>>()),
                );
                ev
            },
            references: vec![
                "https://posts.specterops.io/certified-pre-owned-d95910965cd2".to_string(),
            ],
        });
    }

    let esc2: Vec<_> = templates
        .iter()
        .filter(|t| t.vulnerabilities.iter().any(|v| v.contains("ESC2")))
        .collect();

    if !esc2.is_empty() {
        findings.push(AdSecurityFinding {
            id: Uuid::new_v4().to_string(),
            title: "ESC2: Any Purpose EKU Templates".to_string(),
            description: format!(
                "Found {} certificate template(s) with Any Purpose or no EKU. \
                 These certificates can be used for any purpose including authentication.",
                esc2.len()
            ),
            severity: FindingSeverity::High,
            category: FindingCategory::CertificateServices,
            mitre_attack_ids: vec!["T1649".to_string()],
            affected_objects: esc2.iter().map(|t| t.name.clone()).collect(),
            affected_count: esc2.len() as u32,
            remediation: "Restrict template EKUs to specific purposes. Avoid 'Any Purpose' EKU.".to_string(),
            risk_score: 75,
            evidence: HashMap::new(),
            references: vec![
                "https://posts.specterops.io/certified-pre-owned-d95910965cd2".to_string(),
            ],
        });
    }

    let esc3: Vec<_> = templates
        .iter()
        .filter(|t| t.vulnerabilities.iter().any(|v| v.contains("ESC3")))
        .collect();

    if !esc3.is_empty() {
        findings.push(AdSecurityFinding {
            id: Uuid::new_v4().to_string(),
            title: "ESC3: Certificate Request Agent Templates".to_string(),
            description: format!(
                "Found {} certificate template(s) with Certificate Request Agent EKU. \
                 Allows enrolling on behalf of other users.",
                esc3.len()
            ),
            severity: FindingSeverity::High,
            category: FindingCategory::CertificateServices,
            mitre_attack_ids: vec!["T1649".to_string()],
            affected_objects: esc3.iter().map(|t| t.name.clone()).collect(),
            affected_count: esc3.len() as u32,
            remediation: "Restrict enrollment on Certificate Request Agent templates to highly trusted accounts.".to_string(),
            risk_score: 70,
            evidence: HashMap::new(),
            references: vec![
                "https://posts.specterops.io/certified-pre-owned-d95910965cd2".to_string(),
            ],
        });
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_risk_score() {
        assert_eq!(calculate_risk_score(0, 0, 0, 0), 0);
        assert!(calculate_risk_score(1, 0, 0, 0) > 30);
        assert!(calculate_risk_score(0, 2, 0, 0) > 30);
        assert!(calculate_risk_score(2, 5, 10, 5) > 80);
    }

    #[test]
    fn test_extract_spns() {
        let users = vec![AdUser {
            dn: "CN=svc_sql,OU=Service,DC=contoso,DC=local".to_string(),
            sam_account_name: "svc_sql".to_string(),
            upn: None,
            display_name: None,
            email: None,
            description: None,
            enabled: true,
            password_never_expires: false,
            password_not_required: false,
            locked_out: false,
            dont_require_preauth: false,
            not_delegated: false,
            trusted_for_delegation: false,
            trusted_for_constrained_delegation: false,
            spns: vec!["MSSQLSvc/sqlserver.contoso.local:1433".to_string()],
            member_of: Vec::new(),
            last_logon: None,
            password_last_set: None,
            created: None,
            user_account_control: 512,
            admin_count: false,
            risk_indicators: Vec::new(),
        }];

        let spns = extract_spns(&users, &[]);
        assert_eq!(spns.len(), 1);
        assert_eq!(spns[0].service_class, "MSSQLSvc");
        assert_eq!(spns[0].hostname, "sqlserver.contoso.local");
        assert_eq!(spns[0].port, Some(1433));
        assert!(spns[0].is_user_account);
    }
}
