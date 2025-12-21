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

    // Close the LDAP connection
    if let Err(e) = client.close().await {
        warn!("Error closing LDAP connection: {}", e);
    }

    // Extract SPNs from users and computers
    let spns = extract_spns(&users, &computers);

    // Generate security findings
    let findings = generate_findings(&users, &groups, &computers, &spns, domain_info.as_ref());

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
        password_policy: None, // TODO: Implement password policy enumeration
        trusts: Vec::new(),    // TODO: Implement trust enumeration
        spns,
        dangerous_acls: Vec::new(), // TODO: Implement ACL analysis
        certificate_templates: Vec::new(), // TODO: Implement ADCS enumeration
        certificate_authorities: Vec::new(),
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
