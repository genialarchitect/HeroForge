//! Active Directory Assessment Types
//!
//! This module defines all types used for AD security assessment including
//! domain objects, security findings, and configuration options.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ============================================================================
// Scan Configuration
// ============================================================================

/// Configuration for an AD assessment scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdAssessmentConfig {
    /// Domain controller IP address or hostname
    pub domain_controller: String,
    /// LDAP port (default: 389 for LDAP, 636 for LDAPS)
    pub port: u16,
    /// Use LDAPS (secure LDAP over TLS)
    pub use_ldaps: bool,
    /// Base DN for LDAP searches (auto-detected if not provided)
    pub base_dn: Option<String>,
    /// Authentication mode
    pub auth_mode: AdAuthMode,
    /// Scan options
    pub scan_options: AdScanOptions,
}

/// Authentication mode for AD connection
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum AdAuthMode {
    /// Unauthenticated (anonymous bind)
    Anonymous,
    /// Simple bind with username/password
    Simple {
        username: String,
        password: String,
        domain: Option<String>,
    },
    /// NTLM authentication
    Ntlm {
        username: String,
        password: String,
        domain: String,
    },
}

/// Options controlling what to scan
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AdScanOptions {
    /// Enumerate users
    pub enumerate_users: bool,
    /// Enumerate groups
    pub enumerate_groups: bool,
    /// Enumerate computers
    pub enumerate_computers: bool,
    /// Enumerate organizational units
    pub enumerate_ous: bool,
    /// Enumerate Group Policy Objects
    pub enumerate_gpos: bool,
    /// Check Kerberos security (Kerberoasting, AS-REP roasting)
    pub check_kerberos: bool,
    /// Analyze password policy
    pub check_password_policy: bool,
    /// Find privileged accounts
    pub check_privileged_accounts: bool,
    /// Enumerate trust relationships
    pub check_trusts: bool,
    /// Enumerate SPNs
    pub enumerate_spns: bool,
    /// Analyze ACLs for dangerous permissions
    pub check_acls: bool,
    /// Check AD Certificate Services
    pub check_adcs: bool,
    /// Maximum number of objects to enumerate (0 = unlimited)
    pub max_objects: u32,
    /// Enumeration timeout in seconds
    pub timeout_seconds: u32,
}

impl Default for AdAssessmentConfig {
    fn default() -> Self {
        Self {
            domain_controller: String::new(),
            port: 389,
            use_ldaps: false,
            base_dn: None,
            auth_mode: AdAuthMode::Anonymous,
            scan_options: AdScanOptions {
                enumerate_users: true,
                enumerate_groups: true,
                enumerate_computers: true,
                enumerate_ous: true,
                enumerate_gpos: true,
                check_kerberos: true,
                check_password_policy: true,
                check_privileged_accounts: true,
                check_trusts: true,
                enumerate_spns: true,
                check_acls: true,
                check_adcs: true,
                max_objects: 10000,
                timeout_seconds: 300,
            },
        }
    }
}

// ============================================================================
// Assessment Status
// ============================================================================

/// Status of an AD assessment
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AdAssessmentStatus {
    Pending,
    Running,
    Completed,
    Failed,
}

impl std::fmt::Display for AdAssessmentStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Running => write!(f, "running"),
            Self::Completed => write!(f, "completed"),
            Self::Failed => write!(f, "failed"),
        }
    }
}

impl std::str::FromStr for AdAssessmentStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "pending" => Ok(Self::Pending),
            "running" => Ok(Self::Running),
            "completed" => Ok(Self::Completed),
            "failed" => Ok(Self::Failed),
            _ => Err(format!("Invalid AD assessment status: {}", s)),
        }
    }
}

// ============================================================================
// Domain Objects
// ============================================================================

/// Domain information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdDomainInfo {
    /// Domain name (e.g., "CONTOSO.LOCAL")
    pub domain_name: String,
    /// NetBIOS name
    pub netbios_name: Option<String>,
    /// Forest name
    pub forest_name: Option<String>,
    /// Domain functional level
    pub domain_level: Option<String>,
    /// Forest functional level
    pub forest_level: Option<String>,
    /// Domain controller name
    pub dc_name: Option<String>,
    /// Domain SID
    pub domain_sid: Option<String>,
    /// Base DN
    pub base_dn: String,
}

/// AD User object
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdUser {
    /// Distinguished name
    pub dn: String,
    /// SAM account name
    pub sam_account_name: String,
    /// User principal name
    pub upn: Option<String>,
    /// Display name
    pub display_name: Option<String>,
    /// Email address
    pub email: Option<String>,
    /// Description
    pub description: Option<String>,
    /// Account enabled
    pub enabled: bool,
    /// Password never expires
    pub password_never_expires: bool,
    /// Password not required
    pub password_not_required: bool,
    /// Account locked out
    pub locked_out: bool,
    /// Kerberos pre-authentication not required (AS-REP roastable)
    pub dont_require_preauth: bool,
    /// Account is sensitive and cannot be delegated
    pub not_delegated: bool,
    /// Account trusted for delegation
    pub trusted_for_delegation: bool,
    /// Account trusted for constrained delegation
    pub trusted_for_constrained_delegation: bool,
    /// SPNs registered on this account
    pub spns: Vec<String>,
    /// Group memberships
    pub member_of: Vec<String>,
    /// Last logon timestamp
    pub last_logon: Option<DateTime<Utc>>,
    /// Password last set
    pub password_last_set: Option<DateTime<Utc>>,
    /// Account creation date
    pub created: Option<DateTime<Utc>>,
    /// User account control flags (raw value)
    pub user_account_control: u32,
    /// Admin count attribute (indicates privileged account)
    pub admin_count: bool,
    /// Risk indicators for this user
    pub risk_indicators: Vec<String>,
}

/// AD Group object
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdGroup {
    /// Distinguished name
    pub dn: String,
    /// SAM account name
    pub sam_account_name: String,
    /// Display name
    pub display_name: Option<String>,
    /// Description
    pub description: Option<String>,
    /// Group type (Security/Distribution)
    pub group_type: AdGroupType,
    /// Group scope (DomainLocal/Global/Universal)
    pub group_scope: AdGroupScope,
    /// Direct members
    pub members: Vec<String>,
    /// Member of (parent groups)
    pub member_of: Vec<String>,
    /// Is a privileged group (Domain Admins, Enterprise Admins, etc.)
    pub is_privileged: bool,
    /// Admin count attribute
    pub admin_count: bool,
}

/// Group type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdGroupType {
    Security,
    Distribution,
}

/// Group scope
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdGroupScope {
    DomainLocal,
    Global,
    Universal,
    BuiltinLocal,
}

/// AD Computer object
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdComputer {
    /// Distinguished name
    pub dn: String,
    /// SAM account name
    pub sam_account_name: String,
    /// DNS hostname
    pub dns_hostname: Option<String>,
    /// Operating system
    pub operating_system: Option<String>,
    /// OS version
    pub operating_system_version: Option<String>,
    /// OS service pack
    pub operating_system_sp: Option<String>,
    /// Account enabled
    pub enabled: bool,
    /// Is domain controller
    pub is_domain_controller: bool,
    /// Trusted for delegation
    pub trusted_for_delegation: bool,
    /// Trusted for constrained delegation
    pub trusted_for_constrained_delegation: bool,
    /// SPNs registered
    pub spns: Vec<String>,
    /// Last logon timestamp
    pub last_logon: Option<DateTime<Utc>>,
    /// Created timestamp
    pub created: Option<DateTime<Utc>>,
}

/// Organizational Unit
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdOrganizationalUnit {
    /// Distinguished name
    pub dn: String,
    /// Name
    pub name: String,
    /// Description
    pub description: Option<String>,
    /// Linked GPOs
    pub linked_gpos: Vec<String>,
}

/// Group Policy Object
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdGroupPolicy {
    /// Distinguished name
    pub dn: String,
    /// Display name
    pub display_name: String,
    /// GPO GUID
    pub gpo_guid: String,
    /// Version
    pub version: u32,
    /// Created timestamp
    pub created: Option<DateTime<Utc>>,
    /// Modified timestamp
    pub modified: Option<DateTime<Utc>>,
    /// File system path
    pub gpc_file_sys_path: Option<String>,
    /// User settings enabled
    pub user_version_enabled: bool,
    /// Computer settings enabled
    pub computer_version_enabled: bool,
}

// ============================================================================
// Security Findings
// ============================================================================

/// Severity level for findings
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FindingSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for FindingSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Info => write!(f, "info"),
            Self::Low => write!(f, "low"),
            Self::Medium => write!(f, "medium"),
            Self::High => write!(f, "high"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

impl std::str::FromStr for FindingSeverity {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "info" | "informational" => Ok(Self::Info),
            "low" => Ok(Self::Low),
            "medium" => Ok(Self::Medium),
            "high" => Ok(Self::High),
            "critical" => Ok(Self::Critical),
            _ => Err(format!("Invalid severity: {}", s)),
        }
    }
}

/// Category of security finding
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingCategory {
    /// Kerberos-related issues (Kerberoasting, AS-REP roasting)
    Kerberos,
    /// Password policy issues
    PasswordPolicy,
    /// Delegation issues
    Delegation,
    /// Privileged access issues
    PrivilegedAccess,
    /// Trust relationship issues
    Trusts,
    /// ACL/permission issues
    Permissions,
    /// AD Certificate Services issues
    Adcs,
    /// General misconfiguration
    Misconfiguration,
    /// Account security issues
    AccountSecurity,
    /// Group policy issues
    GroupPolicy,
}

impl std::fmt::Display for FindingCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Kerberos => write!(f, "kerberos"),
            Self::PasswordPolicy => write!(f, "password_policy"),
            Self::Delegation => write!(f, "delegation"),
            Self::PrivilegedAccess => write!(f, "privileged_access"),
            Self::Trusts => write!(f, "trusts"),
            Self::Permissions => write!(f, "permissions"),
            Self::Adcs => write!(f, "adcs"),
            Self::Misconfiguration => write!(f, "misconfiguration"),
            Self::AccountSecurity => write!(f, "account_security"),
            Self::GroupPolicy => write!(f, "group_policy"),
        }
    }
}

/// A security finding from the assessment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdSecurityFinding {
    /// Unique finding ID
    pub id: String,
    /// Finding title
    pub title: String,
    /// Detailed description
    pub description: String,
    /// Severity level
    pub severity: FindingSeverity,
    /// Finding category
    pub category: FindingCategory,
    /// MITRE ATT&CK technique IDs
    pub mitre_attack_ids: Vec<String>,
    /// Affected objects (DNs)
    pub affected_objects: Vec<String>,
    /// Count of affected objects
    pub affected_count: u32,
    /// Remediation guidance
    pub remediation: String,
    /// Risk score (0-100)
    pub risk_score: u8,
    /// Evidence/details
    pub evidence: HashMap<String, serde_json::Value>,
    /// References (URLs)
    pub references: Vec<String>,
}

// ============================================================================
// Trust Relationships
// ============================================================================

/// Trust direction
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrustDirection {
    Inbound,
    Outbound,
    Bidirectional,
}

/// Trust type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrustType {
    ParentChild,
    CrossLink,
    Forest,
    External,
    Unknown,
}

/// Domain trust relationship
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdTrust {
    /// Trusted domain name
    pub trusted_domain: String,
    /// Trust direction
    pub direction: TrustDirection,
    /// Trust type
    pub trust_type: TrustType,
    /// Is transitive
    pub is_transitive: bool,
    /// SID filtering enabled
    pub sid_filtering_enabled: bool,
    /// Selective authentication
    pub selective_authentication: bool,
    /// TGT delegation enabled
    pub tgt_delegation_enabled: bool,
}

// ============================================================================
// Password Policy
// ============================================================================

/// Domain password policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdPasswordPolicy {
    /// Minimum password length
    pub min_password_length: u32,
    /// Password history count
    pub password_history_count: u32,
    /// Maximum password age (days)
    pub max_password_age_days: Option<u32>,
    /// Minimum password age (days)
    pub min_password_age_days: Option<u32>,
    /// Password complexity required
    pub complexity_enabled: bool,
    /// Store passwords using reversible encryption
    pub reversible_encryption_enabled: bool,
    /// Account lockout threshold
    pub lockout_threshold: u32,
    /// Account lockout duration (minutes)
    pub lockout_duration_minutes: Option<u32>,
    /// Reset lockout counter after (minutes)
    pub lockout_observation_window_minutes: Option<u32>,
    /// Fine-grained password policies
    pub fine_grained_policies: Vec<AdFineGrainedPasswordPolicy>,
}

/// Fine-grained password policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdFineGrainedPasswordPolicy {
    /// Policy name
    pub name: String,
    /// Precedence
    pub precedence: u32,
    /// Minimum password length
    pub min_password_length: u32,
    /// Password history count
    pub password_history_count: u32,
    /// Maximum password age (days)
    pub max_password_age_days: Option<u32>,
    /// Complexity enabled
    pub complexity_enabled: bool,
    /// Lockout threshold
    pub lockout_threshold: u32,
    /// Applies to (DNs)
    pub applies_to: Vec<String>,
}

// ============================================================================
// SPN Information
// ============================================================================

/// Service Principal Name information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdSpn {
    /// Full SPN string
    pub spn: String,
    /// Service class (e.g., HTTP, MSSQLSvc)
    pub service_class: String,
    /// Hostname
    pub hostname: String,
    /// Port (if specified)
    pub port: Option<u16>,
    /// Service name (if specified)
    pub service_name: Option<String>,
    /// Associated account DN
    pub account_dn: String,
    /// Is user account (vs computer)
    pub is_user_account: bool,
}

// ============================================================================
// ACL Analysis
// ============================================================================

/// Dangerous ACL permission
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdDangerousAcl {
    /// Object DN
    pub object_dn: String,
    /// Object type
    pub object_type: String,
    /// Principal with the permission
    pub principal: String,
    /// Principal SID
    pub principal_sid: Option<String>,
    /// Permission type
    pub permission: AdPermissionType,
    /// Is inherited
    pub is_inherited: bool,
    /// Risk level
    pub risk_level: FindingSeverity,
    /// Attack path description
    pub attack_path: String,
}

/// Dangerous permission types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdPermissionType {
    GenericAll,
    GenericWrite,
    WriteDacl,
    WriteOwner,
    WriteProperty,
    ExtendedRight,
    ForceChangePassword,
    AddMember,
    DsSyncReplication,
    AllExtendedRights,
}

impl std::fmt::Display for AdPermissionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::GenericAll => write!(f, "GenericAll"),
            Self::GenericWrite => write!(f, "GenericWrite"),
            Self::WriteDacl => write!(f, "WriteDACL"),
            Self::WriteOwner => write!(f, "WriteOwner"),
            Self::WriteProperty => write!(f, "WriteProperty"),
            Self::ExtendedRight => write!(f, "ExtendedRight"),
            Self::ForceChangePassword => write!(f, "ForceChangePassword"),
            Self::AddMember => write!(f, "AddMember"),
            Self::DsSyncReplication => write!(f, "DS-Replication-Get-Changes-All"),
            Self::AllExtendedRights => write!(f, "AllExtendedRights"),
        }
    }
}

// ============================================================================
// AD CS (Certificate Services)
// ============================================================================

/// Certificate template vulnerability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdCertificateTemplate {
    /// Template name
    pub name: String,
    /// Display name
    pub display_name: Option<String>,
    /// Template OID
    pub oid: Option<String>,
    /// Enrollment permissions
    pub enrollment_principals: Vec<String>,
    /// Extended key usages
    pub ekus: Vec<String>,
    /// Allows manager approval bypass
    pub no_manager_approval: bool,
    /// Allows agent override
    pub no_agent_approval: bool,
    /// Allows any purpose EKU
    pub any_purpose: bool,
    /// Allows CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT
    pub enrollee_supplies_subject: bool,
    /// Schema version
    pub schema_version: u32,
    /// Vulnerabilities found
    pub vulnerabilities: Vec<String>,
}

/// Certificate Authority information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdCertificateAuthority {
    /// CA name
    pub name: String,
    /// CA DNS name
    pub dns_name: Option<String>,
    /// CA certificate DN
    pub certificate_dn: Option<String>,
    /// Is enterprise CA
    pub is_enterprise: bool,
    /// Allows NTLM authentication
    pub web_enrollment_enabled: bool,
    /// Templates published
    pub templates: Vec<String>,
}

// ============================================================================
// Assessment Results
// ============================================================================

/// Complete AD assessment results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdAssessmentResults {
    /// Assessment ID
    pub id: String,
    /// Scan timestamp
    pub scan_time: DateTime<Utc>,
    /// Domain information
    pub domain_info: Option<AdDomainInfo>,
    /// Enumerated users
    pub users: Vec<AdUser>,
    /// Enumerated groups
    pub groups: Vec<AdGroup>,
    /// Enumerated computers
    pub computers: Vec<AdComputer>,
    /// Organizational units
    pub organizational_units: Vec<AdOrganizationalUnit>,
    /// Group policies
    pub group_policies: Vec<AdGroupPolicy>,
    /// Password policy
    pub password_policy: Option<AdPasswordPolicy>,
    /// Trust relationships
    pub trusts: Vec<AdTrust>,
    /// Discovered SPNs
    pub spns: Vec<AdSpn>,
    /// Dangerous ACLs
    pub dangerous_acls: Vec<AdDangerousAcl>,
    /// Certificate templates
    pub certificate_templates: Vec<AdCertificateTemplate>,
    /// Certificate authorities
    pub certificate_authorities: Vec<AdCertificateAuthority>,
    /// Security findings
    pub findings: Vec<AdSecurityFinding>,
    /// Summary statistics
    pub summary: AdAssessmentSummary,
}

/// Summary statistics for the assessment
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AdAssessmentSummary {
    /// Total users enumerated
    pub total_users: u32,
    /// Total groups enumerated
    pub total_groups: u32,
    /// Total computers enumerated
    pub total_computers: u32,
    /// Kerberoastable accounts
    pub kerberoastable_accounts: u32,
    /// AS-REP roastable accounts
    pub asrep_roastable_accounts: u32,
    /// Accounts with unconstrained delegation
    pub unconstrained_delegation_accounts: u32,
    /// Accounts with constrained delegation
    pub constrained_delegation_accounts: u32,
    /// Privileged users count
    pub privileged_users: u32,
    /// Findings by severity
    pub findings_by_severity: HashMap<String, u32>,
    /// Critical findings count
    pub critical_findings: u32,
    /// High findings count
    pub high_findings: u32,
    /// Medium findings count
    pub medium_findings: u32,
    /// Low findings count
    pub low_findings: u32,
    /// Overall risk score (0-100)
    pub overall_risk_score: u8,
}
