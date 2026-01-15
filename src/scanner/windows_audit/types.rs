//! Windows Audit Types

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Configuration for Windows audit scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowsAuditConfig {
    pub target: String,
    pub credentials: WindowsCredentials,
    pub run_stig_checks: bool,
    pub include_cat3: bool,
    pub collect_registry_state: bool,
    pub collect_gpo_state: bool,
    pub timeout_seconds: u64,
}

impl Default for WindowsAuditConfig {
    fn default() -> Self {
        Self {
            target: String::new(),
            credentials: WindowsCredentials::default(),
            run_stig_checks: true,
            include_cat3: true,
            collect_registry_state: true,
            collect_gpo_state: true,
            timeout_seconds: 300,
        }
    }
}

/// Windows credentials for authentication
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WindowsCredentials {
    pub username: String,
    #[serde(skip_serializing)]
    pub password: String,
    pub domain: Option<String>,
    pub auth_type: WindowsAuthType,
}

/// Authentication type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum WindowsAuthType {
    #[default]
    Ntlm,
    Kerberos,
    Negotiate,
    Basic,
}

/// Complete Windows audit result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowsAuditResult {
    pub target: String,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub system_info: Option<WindowsSystemInfo>,
    pub security_policies: SecurityPolicies,
    pub installed_patches: Vec<InstalledPatch>,
    pub services: Vec<WindowsService>,
    pub local_users: Vec<LocalUser>,
    pub local_groups: Vec<LocalGroup>,
    pub firewall_rules: Vec<FirewallRule>,
    pub registry_state: Vec<RegistryKey>,
    pub stig_results: Vec<StigCheckResult>,
}

impl WindowsAuditResult {
    pub fn new(target: &str) -> Self {
        Self {
            target: target.to_string(),
            started_at: Utc::now(),
            completed_at: None,
            system_info: None,
            security_policies: SecurityPolicies::default(),
            installed_patches: Vec::new(),
            services: Vec::new(),
            local_users: Vec::new(),
            local_groups: Vec::new(),
            firewall_rules: Vec::new(),
            registry_state: Vec::new(),
            stig_results: Vec::new(),
        }
    }
}

/// Windows system information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowsSystemInfo {
    pub hostname: String,
    pub os_name: String,
    pub os_version: String,
    pub os_build: String,
    pub os_architecture: String,
    pub domain: Option<String>,
    pub last_boot_time: Option<DateTime<Utc>>,
    pub install_date: Option<DateTime<Utc>>,
}

impl WindowsSystemInfo {
    pub fn from_wmi(os_json: &str, computer_json: &str) -> anyhow::Result<Self> {
        // Parse WMI JSON outputs
        let os: serde_json::Value = serde_json::from_str(os_json)
            .unwrap_or(serde_json::Value::Null);
        let computer: serde_json::Value = serde_json::from_str(computer_json)
            .unwrap_or(serde_json::Value::Null);

        Ok(Self {
            hostname: computer.get("Name")
                .and_then(|v| v.as_str())
                .unwrap_or("Unknown")
                .to_string(),
            os_name: os.get("Caption")
                .and_then(|v| v.as_str())
                .unwrap_or("Unknown")
                .to_string(),
            os_version: os.get("Version")
                .and_then(|v| v.as_str())
                .unwrap_or("Unknown")
                .to_string(),
            os_build: os.get("BuildNumber")
                .and_then(|v| v.as_str())
                .unwrap_or("Unknown")
                .to_string(),
            os_architecture: os.get("OSArchitecture")
                .and_then(|v| v.as_str())
                .unwrap_or("Unknown")
                .to_string(),
            domain: computer.get("Domain")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            last_boot_time: None, // Parse from WMI datetime
            install_date: None,
        })
    }
}

/// Security policies from secedit
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SecurityPolicies {
    pub password_policy: PasswordPolicy,
    pub account_lockout_policy: AccountLockoutPolicy,
    pub audit_policy: AuditPolicy,
    pub user_rights: UserRightsAssignment,
}

impl SecurityPolicies {
    pub fn parse(secedit_output: &str) -> anyhow::Result<Self> {
        let mut policies = SecurityPolicies::default();

        for line in secedit_output.lines() {
            let parts: Vec<&str> = line.splitn(2, '=').collect();
            if parts.len() != 2 {
                continue;
            }

            let key = parts[0].trim();
            let value = parts[1].trim();

            match key {
                "MinimumPasswordLength" => {
                    policies.password_policy.minimum_length = value.parse().unwrap_or(0);
                }
                "PasswordComplexity" => {
                    policies.password_policy.complexity_enabled = value == "1";
                }
                "MaximumPasswordAge" => {
                    policies.password_policy.maximum_age_days = value.parse().unwrap_or(0);
                }
                "MinimumPasswordAge" => {
                    policies.password_policy.minimum_age_days = value.parse().unwrap_or(0);
                }
                "PasswordHistorySize" => {
                    policies.password_policy.history_count = value.parse().unwrap_or(0);
                }
                "LockoutBadCount" => {
                    policies.account_lockout_policy.threshold = value.parse().unwrap_or(0);
                }
                "ResetLockoutCount" => {
                    policies.account_lockout_policy.reset_after_minutes = value.parse().unwrap_or(0);
                }
                "LockoutDuration" => {
                    policies.account_lockout_policy.duration_minutes = value.parse().unwrap_or(0);
                }
                _ => {}
            }
        }

        Ok(policies)
    }
}

/// Password policy settings
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PasswordPolicy {
    pub minimum_length: u32,
    pub complexity_enabled: bool,
    pub maximum_age_days: u32,
    pub minimum_age_days: u32,
    pub history_count: u32,
    pub reversible_encryption: bool,
}

/// Account lockout policy
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AccountLockoutPolicy {
    pub threshold: u32,
    pub duration_minutes: u32,
    pub reset_after_minutes: u32,
}

/// Audit policy settings
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuditPolicy {
    pub audit_logon_events: AuditSetting,
    pub audit_account_logon_events: AuditSetting,
    pub audit_object_access: AuditSetting,
    pub audit_privilege_use: AuditSetting,
    pub audit_policy_change: AuditSetting,
    pub audit_account_management: AuditSetting,
    pub audit_ds_access: AuditSetting,
    pub audit_system_events: AuditSetting,
    pub audit_process_tracking: AuditSetting,
}

/// Audit setting value
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditSetting {
    #[default]
    None,
    Success,
    Failure,
    Both,
}

/// User rights assignments
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UserRightsAssignment {
    pub debug_programs: Vec<String>,
    pub logon_locally: Vec<String>,
    pub deny_logon_locally: Vec<String>,
    pub access_from_network: Vec<String>,
    pub deny_access_from_network: Vec<String>,
    pub act_as_os: Vec<String>,
    pub backup_files: Vec<String>,
    pub restore_files: Vec<String>,
    pub take_ownership: Vec<String>,
}

/// Installed patch/hotfix
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstalledPatch {
    pub hotfix_id: String,
    pub description: String,
    pub installed_on: Option<DateTime<Utc>>,
    pub installed_by: Option<String>,
}

/// Windows service
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowsService {
    pub name: String,
    pub display_name: String,
    pub status: ServiceStatus,
    pub start_type: ServiceStartType,
    pub account: Option<String>,
    pub path: Option<String>,
}

/// Service status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ServiceStatus {
    Running,
    Stopped,
    Paused,
    StartPending,
    StopPending,
    Unknown,
}

impl Default for ServiceStatus {
    fn default() -> Self {
        Self::Unknown
    }
}

/// Service start type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ServiceStartType {
    Automatic,
    AutomaticDelayed,
    Manual,
    Disabled,
    Unknown,
}

impl Default for ServiceStartType {
    fn default() -> Self {
        Self::Unknown
    }
}

/// Local user account
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalUser {
    pub name: String,
    pub enabled: bool,
    pub password_required: bool,
    pub password_changeable: bool,
    pub password_expires: bool,
    pub last_logon: Option<DateTime<Utc>>,
    pub password_last_set: Option<DateTime<Utc>>,
    pub groups: Vec<String>,
}

/// Local group
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalGroup {
    pub name: String,
    pub description: String,
    pub members: Vec<String>,
}

/// Firewall rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRule {
    pub name: String,
    pub display_name: String,
    pub enabled: bool,
    pub direction: FirewallDirection,
    pub action: FirewallAction,
    pub profile: FirewallProfile,
    pub local_port: Option<String>,
    pub remote_port: Option<String>,
    pub protocol: Option<String>,
    pub program: Option<String>,
}

/// Firewall direction
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FirewallDirection {
    Inbound,
    Outbound,
}

/// Firewall action
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FirewallAction {
    Allow,
    Block,
}

/// Firewall profile
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FirewallProfile {
    Domain,
    Private,
    Public,
    Any,
}

/// Registry key with values
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryKey {
    pub path: String,
    pub values: Vec<RegistryValue>,
}

/// Registry value
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryValue {
    pub name: String,
    pub value_type: RegistryValueType,
    pub data: String,
}

/// Registry value type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RegistryValueType {
    RegSz,
    RegExpandSz,
    RegBinary,
    RegDword,
    RegQword,
    RegMultiSz,
    RegNone,
    Unknown,
}

/// STIG check result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StigCheckResult {
    pub stig_id: String,
    pub rule_id: String,
    pub title: String,
    pub category: StigCategory,
    pub status: StigCheckStatus,
    pub finding_details: Option<String>,
    pub expected: String,
    pub actual: String,
    pub remediation: Option<String>,
}

/// STIG category (severity)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StigCategory {
    CatI,   // High - Most severe
    CatII,  // Medium
    CatIII, // Low
}

impl std::fmt::Display for StigCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StigCategory::CatI => write!(f, "CAT I"),
            StigCategory::CatII => write!(f, "CAT II"),
            StigCategory::CatIII => write!(f, "CAT III"),
        }
    }
}

/// STIG check status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StigCheckStatus {
    NotAFinding,
    Open,
    NotApplicable,
    NotReviewed,
}

impl Default for StigCheckStatus {
    fn default() -> Self {
        Self::NotReviewed
    }
}

impl std::fmt::Display for StigCheckStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StigCheckStatus::NotAFinding => write!(f, "Not A Finding"),
            StigCheckStatus::Open => write!(f, "Open"),
            StigCheckStatus::NotApplicable => write!(f, "Not Applicable"),
            StigCheckStatus::NotReviewed => write!(f, "Not Reviewed"),
        }
    }
}
