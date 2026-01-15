//! CAT II (Medium) STIG Checks
//!
//! Medium severity findings that should be addressed in a reasonable timeframe.
//! CAT II vulnerabilities could allow unauthorized access or policy violations.

use crate::scanner::windows_audit::types::{
    AuditSetting, RegistryKey, StigCategory, StigCheckResult, StigCheckStatus, WindowsAuditResult,
};

/// Run all CAT II STIG checks
pub fn run_all(scan_data: &WindowsAuditResult) -> Vec<StigCheckResult> {
    vec![
        // Password Policy
        check_min_password_length(scan_data),
        check_password_complexity(scan_data),
        check_password_history(scan_data),
        check_max_password_age(scan_data),
        check_min_password_age(scan_data),
        check_reversible_encryption(scan_data),

        // Account Lockout
        check_account_lockout_threshold(scan_data),
        check_account_lockout_duration(scan_data),
        check_lockout_reset_counter(scan_data),

        // Audit Policy
        check_audit_logon_events(scan_data),
        check_audit_account_logon_events(scan_data),
        check_audit_account_management(scan_data),
        check_audit_policy_change(scan_data),
        check_audit_object_access(scan_data),
        check_audit_privilege_use(scan_data),
        check_audit_system_events(scan_data),

        // PowerShell Security
        check_powershell_script_block_logging(scan_data),
        check_powershell_transcription(scan_data),
        check_powershell_constrained_mode(scan_data),

        // Network Security
        check_null_session_shares(scan_data),
        check_null_session_pipes(scan_data),
        check_lan_manager_hash_disabled(scan_data),
        check_machine_account_password(scan_data),

        // Service Configuration
        check_fax_service_disabled(scan_data),
        check_print_spooler_domain(scan_data),
        check_remote_registry_disabled(scan_data),
        check_snmp_service_disabled(scan_data),
        check_telnet_service_disabled(scan_data),
        check_iis_service_check(scan_data),

        // Account Security
        check_guest_account_disabled(scan_data),
        check_guest_account_renamed(scan_data),
        check_admin_account_renamed(scan_data),
        check_builtin_admin_disabled(scan_data),

        // Event Log Settings
        check_application_log_size(scan_data),
        check_security_log_size(scan_data),
        check_system_log_size(scan_data),

        // User Rights
        check_debug_programs_limited(scan_data),
        check_act_as_os_limited(scan_data),

        // Miscellaneous
        check_screensaver_enabled(scan_data),
        check_screensaver_password(scan_data),
        check_cached_logons_limit(scan_data),
        check_legal_banner(scan_data),
    ]
}

// === Password Policy Checks ===

fn check_min_password_length(scan_data: &WindowsAuditResult) -> StigCheckResult {
    let min_length = scan_data.security_policies.password_policy.minimum_length;
    let compliant = min_length >= 14;

    StigCheckResult {
        stig_id: "V-220718".to_string(),
        rule_id: "SV-220718r569187_rule".to_string(),
        title: "Minimum password length must be at least 14 characters".to_string(),
        category: StigCategory::CatII,
        status: if compliant { StigCheckStatus::NotAFinding } else { StigCheckStatus::Open },
        finding_details: Some(format!("Minimum password length is {} characters", min_length)),
        expected: ">= 14 characters".to_string(),
        actual: format!("{} characters", min_length),
        remediation: Some("Set 'Minimum password length' to 14 or greater in Local Security Policy".to_string()),
    }
}

fn check_password_complexity(scan_data: &WindowsAuditResult) -> StigCheckResult {
    let enabled = scan_data.security_policies.password_policy.complexity_enabled;

    StigCheckResult {
        stig_id: "V-220719".to_string(),
        rule_id: "SV-220719r569190_rule".to_string(),
        title: "Password must meet complexity requirements".to_string(),
        category: StigCategory::CatII,
        status: if enabled { StigCheckStatus::NotAFinding } else { StigCheckStatus::Open },
        finding_details: Some(format!("Password complexity is {}", if enabled { "enabled" } else { "disabled" })),
        expected: "Enabled".to_string(),
        actual: if enabled { "Enabled" } else { "Disabled" }.to_string(),
        remediation: Some("Enable 'Password must meet complexity requirements' in Local Security Policy".to_string()),
    }
}

fn check_password_history(scan_data: &WindowsAuditResult) -> StigCheckResult {
    let history = scan_data.security_policies.password_policy.history_count;
    let compliant = history >= 24;

    StigCheckResult {
        stig_id: "V-220720".to_string(),
        rule_id: "SV-220720r569193_rule".to_string(),
        title: "Password history must remember 24 or more passwords".to_string(),
        category: StigCategory::CatII,
        status: if compliant { StigCheckStatus::NotAFinding } else { StigCheckStatus::Open },
        finding_details: Some(format!("Password history is set to {} passwords", history)),
        expected: ">= 24 passwords".to_string(),
        actual: format!("{} passwords", history),
        remediation: Some("Set 'Enforce password history' to 24 or greater passwords".to_string()),
    }
}

fn check_max_password_age(scan_data: &WindowsAuditResult) -> StigCheckResult {
    let max_age = scan_data.security_policies.password_policy.maximum_age_days;
    let compliant = max_age > 0 && max_age <= 60;

    StigCheckResult {
        stig_id: "V-220721".to_string(),
        rule_id: "SV-220721r569196_rule".to_string(),
        title: "Maximum password age must be 60 days or less".to_string(),
        category: StigCategory::CatII,
        status: if compliant { StigCheckStatus::NotAFinding } else { StigCheckStatus::Open },
        finding_details: Some(format!("Maximum password age is {} days", max_age)),
        expected: "1-60 days".to_string(),
        actual: format!("{} days", max_age),
        remediation: Some("Set 'Maximum password age' to 60 days or less".to_string()),
    }
}

fn check_min_password_age(scan_data: &WindowsAuditResult) -> StigCheckResult {
    let min_age = scan_data.security_policies.password_policy.minimum_age_days;
    let compliant = min_age >= 1;

    StigCheckResult {
        stig_id: "V-220722".to_string(),
        rule_id: "SV-220722r569199_rule".to_string(),
        title: "Minimum password age must be at least 1 day".to_string(),
        category: StigCategory::CatII,
        status: if compliant { StigCheckStatus::NotAFinding } else { StigCheckStatus::Open },
        finding_details: Some(format!("Minimum password age is {} days", min_age)),
        expected: ">= 1 day".to_string(),
        actual: format!("{} days", min_age),
        remediation: Some("Set 'Minimum password age' to 1 day or greater".to_string()),
    }
}

fn check_reversible_encryption(scan_data: &WindowsAuditResult) -> StigCheckResult {
    let reversible = scan_data.security_policies.password_policy.reversible_encryption;

    StigCheckResult {
        stig_id: "V-220723".to_string(),
        rule_id: "SV-220723r569202_rule".to_string(),
        title: "Reversible password encryption must be disabled".to_string(),
        category: StigCategory::CatII,
        status: if !reversible { StigCheckStatus::NotAFinding } else { StigCheckStatus::Open },
        finding_details: Some(format!("Store passwords using reversible encryption is {}", if reversible { "enabled" } else { "disabled" })),
        expected: "Disabled".to_string(),
        actual: if reversible { "Enabled" } else { "Disabled" }.to_string(),
        remediation: Some("Disable 'Store passwords using reversible encryption' in Local Security Policy".to_string()),
    }
}

// === Account Lockout Checks ===

fn check_account_lockout_threshold(scan_data: &WindowsAuditResult) -> StigCheckResult {
    let threshold = scan_data.security_policies.account_lockout_policy.threshold;
    let compliant = threshold > 0 && threshold <= 3;

    StigCheckResult {
        stig_id: "V-220724".to_string(),
        rule_id: "SV-220724r569217_rule".to_string(),
        title: "Account lockout threshold must be 3 or fewer invalid attempts".to_string(),
        category: StigCategory::CatII,
        status: if compliant { StigCheckStatus::NotAFinding } else { StigCheckStatus::Open },
        finding_details: Some(format!("Account lockout threshold is {} attempts", threshold)),
        expected: "1-3 attempts".to_string(),
        actual: format!("{} attempts", threshold),
        remediation: Some("Set 'Account lockout threshold' to 3 or fewer invalid logon attempts".to_string()),
    }
}

fn check_account_lockout_duration(scan_data: &WindowsAuditResult) -> StigCheckResult {
    let duration = scan_data.security_policies.account_lockout_policy.duration_minutes;
    // 0 means locked until administrator unlocks, which is also compliant
    let compliant = duration == 0 || duration >= 15;

    StigCheckResult {
        stig_id: "V-220725".to_string(),
        rule_id: "SV-220725r569220_rule".to_string(),
        title: "Account lockout duration must be at least 15 minutes or until unlocked".to_string(),
        category: StigCategory::CatII,
        status: if compliant { StigCheckStatus::NotAFinding } else { StigCheckStatus::Open },
        finding_details: Some(format!(
            "Account lockout duration is {} minutes{}",
            duration,
            if duration == 0 { " (until admin unlocks)" } else { "" }
        )),
        expected: ">= 15 minutes or 0 (until unlocked)".to_string(),
        actual: format!("{} minutes", duration),
        remediation: Some("Set 'Account lockout duration' to 15 minutes or greater, or 0 for until administrator unlocks".to_string()),
    }
}

fn check_lockout_reset_counter(scan_data: &WindowsAuditResult) -> StigCheckResult {
    let reset_time = scan_data.security_policies.account_lockout_policy.reset_after_minutes;
    let compliant = reset_time >= 15;

    StigCheckResult {
        stig_id: "V-220726".to_string(),
        rule_id: "SV-220726r569223_rule".to_string(),
        title: "Reset account lockout counter must be 15 minutes or greater".to_string(),
        category: StigCategory::CatII,
        status: if compliant { StigCheckStatus::NotAFinding } else { StigCheckStatus::Open },
        finding_details: Some(format!("Reset account lockout counter after {} minutes", reset_time)),
        expected: ">= 15 minutes".to_string(),
        actual: format!("{} minutes", reset_time),
        remediation: Some("Set 'Reset account lockout counter after' to 15 minutes or greater".to_string()),
    }
}

// === Audit Policy Checks ===

fn check_audit_logon_events(scan_data: &WindowsAuditResult) -> StigCheckResult {
    let audit = scan_data.security_policies.audit_policy.audit_logon_events;
    let compliant = audit == AuditSetting::Both;

    StigCheckResult {
        stig_id: "V-220740".to_string(),
        rule_id: "SV-220740r569277_rule".to_string(),
        title: "Audit Logon events must be configured for Success and Failure".to_string(),
        category: StigCategory::CatII,
        status: if compliant { StigCheckStatus::NotAFinding } else { StigCheckStatus::Open },
        finding_details: Some(format!("Audit Logon is set to {:?}", audit)),
        expected: "Success and Failure".to_string(),
        actual: format!("{:?}", audit),
        remediation: Some("Configure 'Audit Logon' to Success and Failure in Advanced Audit Policy".to_string()),
    }
}

fn check_audit_account_logon_events(scan_data: &WindowsAuditResult) -> StigCheckResult {
    let audit = scan_data.security_policies.audit_policy.audit_account_logon_events;
    let compliant = audit == AuditSetting::Both;

    StigCheckResult {
        stig_id: "V-220741".to_string(),
        rule_id: "SV-220741r569280_rule".to_string(),
        title: "Audit Credential Validation must be configured for Success and Failure".to_string(),
        category: StigCategory::CatII,
        status: if compliant { StigCheckStatus::NotAFinding } else { StigCheckStatus::Open },
        finding_details: Some(format!("Audit Credential Validation is set to {:?}", audit)),
        expected: "Success and Failure".to_string(),
        actual: format!("{:?}", audit),
        remediation: Some("Configure 'Audit Credential Validation' to Success and Failure".to_string()),
    }
}

fn check_audit_account_management(scan_data: &WindowsAuditResult) -> StigCheckResult {
    let audit = scan_data.security_policies.audit_policy.audit_account_management;
    let compliant = audit == AuditSetting::Both || audit == AuditSetting::Success;

    StigCheckResult {
        stig_id: "V-220742".to_string(),
        rule_id: "SV-220742r569283_rule".to_string(),
        title: "Audit Account Management must be configured".to_string(),
        category: StigCategory::CatII,
        status: if compliant { StigCheckStatus::NotAFinding } else { StigCheckStatus::Open },
        finding_details: Some(format!("Audit Account Management is set to {:?}", audit)),
        expected: "Success, or Success and Failure".to_string(),
        actual: format!("{:?}", audit),
        remediation: Some("Configure 'Audit Account Management' to Success and Failure".to_string()),
    }
}

fn check_audit_policy_change(scan_data: &WindowsAuditResult) -> StigCheckResult {
    let audit = scan_data.security_policies.audit_policy.audit_policy_change;
    let compliant = audit == AuditSetting::Both || audit == AuditSetting::Success;

    StigCheckResult {
        stig_id: "V-220743".to_string(),
        rule_id: "SV-220743r569286_rule".to_string(),
        title: "Audit Policy Change must be configured for Success".to_string(),
        category: StigCategory::CatII,
        status: if compliant { StigCheckStatus::NotAFinding } else { StigCheckStatus::Open },
        finding_details: Some(format!("Audit Policy Change is set to {:?}", audit)),
        expected: "Success, or Success and Failure".to_string(),
        actual: format!("{:?}", audit),
        remediation: Some("Configure 'Audit Policy Change' to Success".to_string()),
    }
}

fn check_audit_object_access(scan_data: &WindowsAuditResult) -> StigCheckResult {
    let audit = scan_data.security_policies.audit_policy.audit_object_access;
    let compliant = audit == AuditSetting::Both || audit == AuditSetting::Failure;

    StigCheckResult {
        stig_id: "V-220744".to_string(),
        rule_id: "SV-220744r569289_rule".to_string(),
        title: "Audit Object Access must be configured for Failure".to_string(),
        category: StigCategory::CatII,
        status: if compliant { StigCheckStatus::NotAFinding } else { StigCheckStatus::Open },
        finding_details: Some(format!("Audit Object Access is set to {:?}", audit)),
        expected: "Failure, or Success and Failure".to_string(),
        actual: format!("{:?}", audit),
        remediation: Some("Configure 'Audit Object Access' to Failure at minimum".to_string()),
    }
}

fn check_audit_privilege_use(scan_data: &WindowsAuditResult) -> StigCheckResult {
    let audit = scan_data.security_policies.audit_policy.audit_privilege_use;
    let compliant = audit == AuditSetting::Both || audit == AuditSetting::Success;

    StigCheckResult {
        stig_id: "V-220745".to_string(),
        rule_id: "SV-220745r569292_rule".to_string(),
        title: "Audit Privilege Use must be configured for Success".to_string(),
        category: StigCategory::CatII,
        status: if compliant { StigCheckStatus::NotAFinding } else { StigCheckStatus::Open },
        finding_details: Some(format!("Audit Privilege Use is set to {:?}", audit)),
        expected: "Success, or Success and Failure".to_string(),
        actual: format!("{:?}", audit),
        remediation: Some("Configure 'Audit Privilege Use - Sensitive Privilege Use' to Success".to_string()),
    }
}

fn check_audit_system_events(scan_data: &WindowsAuditResult) -> StigCheckResult {
    let audit = scan_data.security_policies.audit_policy.audit_system_events;
    let compliant = audit == AuditSetting::Both || audit == AuditSetting::Success;

    StigCheckResult {
        stig_id: "V-220746".to_string(),
        rule_id: "SV-220746r569295_rule".to_string(),
        title: "Audit System Events must be configured for Success".to_string(),
        category: StigCategory::CatII,
        status: if compliant { StigCheckStatus::NotAFinding } else { StigCheckStatus::Open },
        finding_details: Some(format!("Audit System Events is set to {:?}", audit)),
        expected: "Success, or Success and Failure".to_string(),
        actual: format!("{:?}", audit),
        remediation: Some("Configure 'Audit Security State Change' to Success".to_string()),
    }
}

// === PowerShell Security ===

fn check_powershell_script_block_logging(scan_data: &WindowsAuditResult) -> StigCheckResult {
    let enabled = get_registry_dword(
        &scan_data.registry_state,
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging",
        "EnableScriptBlockLogging",
    );

    let (status, actual) = match enabled {
        Some(1) => (StigCheckStatus::NotAFinding, "1 (Enabled)".to_string()),
        Some(val) => (StigCheckStatus::Open, format!("{}", val)),
        None => (StigCheckStatus::Open, "Not configured".to_string()),
    };

    StigCheckResult {
        stig_id: "V-220728".to_string(),
        rule_id: "SV-220728r569241_rule".to_string(),
        title: "PowerShell script block logging must be enabled".to_string(),
        category: StigCategory::CatII,
        status,
        finding_details: Some(format!("PowerShell script block logging: {}", actual)),
        expected: "EnableScriptBlockLogging=1".to_string(),
        actual,
        remediation: Some("Enable 'Turn on PowerShell Script Block Logging' via Group Policy".to_string()),
    }
}

fn check_powershell_transcription(scan_data: &WindowsAuditResult) -> StigCheckResult {
    let enabled = get_registry_dword(
        &scan_data.registry_state,
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription",
        "EnableTranscripting",
    );

    let (status, actual) = match enabled {
        Some(1) => (StigCheckStatus::NotAFinding, "1 (Enabled)".to_string()),
        Some(val) => (StigCheckStatus::Open, format!("{}", val)),
        None => (StigCheckStatus::Open, "Not configured".to_string()),
    };

    StigCheckResult {
        stig_id: "V-220729".to_string(),
        rule_id: "SV-220729r569244_rule".to_string(),
        title: "PowerShell transcription must be enabled".to_string(),
        category: StigCategory::CatII,
        status,
        finding_details: Some(format!("PowerShell transcription: {}", actual)),
        expected: "EnableTranscripting=1".to_string(),
        actual,
        remediation: Some("Enable 'Turn on PowerShell Transcription' via Group Policy".to_string()),
    }
}

fn check_powershell_constrained_mode(scan_data: &WindowsAuditResult) -> StigCheckResult {
    let mode = get_registry_dword(
        &scan_data.registry_state,
        r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
        "__PSLockdownPolicy",
    );

    // 4 = ConstrainedLanguage mode, 8 = FullLanguage (unrestricted)
    let (status, actual) = match mode {
        Some(4) => (StigCheckStatus::NotAFinding, "4 (ConstrainedLanguage)".to_string()),
        Some(val) => (StigCheckStatus::Open, format!("{}", val)),
        None => (StigCheckStatus::NotReviewed, "Not configured".to_string()),
    };

    StigCheckResult {
        stig_id: "V-220730".to_string(),
        rule_id: "SV-220730r569247_rule".to_string(),
        title: "PowerShell Constrained Language mode should be enabled".to_string(),
        category: StigCategory::CatII,
        status,
        finding_details: Some(format!("PowerShell lockdown policy: {}", actual)),
        expected: "__PSLockdownPolicy=4 (ConstrainedLanguage)".to_string(),
        actual,
        remediation: Some("Configure Windows Defender Application Control (WDAC) to enforce Constrained Language mode".to_string()),
    }
}

// === Network Security ===

fn check_null_session_shares(scan_data: &WindowsAuditResult) -> StigCheckResult {
    let shares = get_registry_string(
        &scan_data.registry_state,
        r"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
        "NullSessionShares",
    );

    let (status, actual) = match shares {
        Some(ref s) if s.is_empty() || s == "(value not set)" => {
            (StigCheckStatus::NotAFinding, "Empty or not set".to_string())
        }
        Some(s) => (StigCheckStatus::Open, s),
        None => (StigCheckStatus::NotAFinding, "Not configured (no shares exposed)".to_string()),
    };

    StigCheckResult {
        stig_id: "V-220731".to_string(),
        rule_id: "SV-220731r569250_rule".to_string(),
        title: "Null session shares must not be allowed".to_string(),
        category: StigCategory::CatII,
        status,
        finding_details: Some(format!("Null session shares: {}", actual)),
        expected: "No shares configured".to_string(),
        actual,
        remediation: Some("Remove all entries from 'Network access: Shares that can be accessed anonymously'".to_string()),
    }
}

fn check_null_session_pipes(scan_data: &WindowsAuditResult) -> StigCheckResult {
    let pipes = get_registry_string(
        &scan_data.registry_state,
        r"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
        "NullSessionPipes",
    );

    let (status, actual) = match pipes {
        Some(ref s) if s.is_empty() || s == "(value not set)" => {
            (StigCheckStatus::NotAFinding, "Empty or not set".to_string())
        }
        Some(s) => (StigCheckStatus::Open, s),
        None => (StigCheckStatus::NotAFinding, "Not configured (no pipes exposed)".to_string()),
    };

    StigCheckResult {
        stig_id: "V-220732".to_string(),
        rule_id: "SV-220732r569253_rule".to_string(),
        title: "Named pipes accessible anonymously must be limited".to_string(),
        category: StigCategory::CatII,
        status,
        finding_details: Some(format!("Null session pipes: {}", actual)),
        expected: "Empty or minimal required pipes".to_string(),
        actual,
        remediation: Some("Minimize entries in 'Network access: Named pipes that can be accessed anonymously'".to_string()),
    }
}

fn check_lan_manager_hash_disabled(scan_data: &WindowsAuditResult) -> StigCheckResult {
    let no_lm_hash = get_registry_dword(
        &scan_data.registry_state,
        r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
        "NoLMHash",
    );

    let (status, actual) = match no_lm_hash {
        Some(1) => (StigCheckStatus::NotAFinding, "1 (LM hash disabled)".to_string()),
        Some(val) => (StigCheckStatus::Open, format!("{}", val)),
        None => {
            // Default on Vista+ is to not store LM hashes
            (StigCheckStatus::NotAFinding, "Not set (default disabled on modern Windows)".to_string())
        }
    };

    StigCheckResult {
        stig_id: "V-220733".to_string(),
        rule_id: "SV-220733r569256_rule".to_string(),
        title: "LAN Manager hash storage must be disabled".to_string(),
        category: StigCategory::CatII,
        status,
        finding_details: Some(format!("NoLMHash: {}", actual)),
        expected: "NoLMHash=1".to_string(),
        actual,
        remediation: Some("Enable 'Network security: Do not store LAN Manager hash value on next password change'".to_string()),
    }
}

fn check_machine_account_password(scan_data: &WindowsAuditResult) -> StigCheckResult {
    let disabled = get_registry_dword(
        &scan_data.registry_state,
        r"HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters",
        "DisablePasswordChange",
    );

    // 0 means password changes are allowed (compliant)
    let (status, actual) = match disabled {
        Some(0) | None => (StigCheckStatus::NotAFinding, "0 or not set (password changes enabled)".to_string()),
        Some(val) => (StigCheckStatus::Open, format!("{} (password changes disabled)", val)),
    };

    StigCheckResult {
        stig_id: "V-220734".to_string(),
        rule_id: "SV-220734r569259_rule".to_string(),
        title: "Machine account password changes must not be disabled".to_string(),
        category: StigCategory::CatII,
        status,
        finding_details: Some(format!("DisablePasswordChange: {}", actual)),
        expected: "DisablePasswordChange=0 or not set".to_string(),
        actual,
        remediation: Some("Disable 'Domain member: Disable machine account password changes'".to_string()),
    }
}

// === Service Configuration ===

fn check_fax_service_disabled(scan_data: &WindowsAuditResult) -> StigCheckResult {
    let fax_service = scan_data.services.iter().find(|s| s.name.to_lowercase() == "fax");

    let (status, actual) = match fax_service {
        Some(svc) if svc.start_type == crate::scanner::windows_audit::types::ServiceStartType::Disabled => {
            (StigCheckStatus::NotAFinding, "Disabled".to_string())
        }
        Some(svc) => (StigCheckStatus::Open, format!("{:?}", svc.start_type)),
        None => (StigCheckStatus::NotAFinding, "Service not installed".to_string()),
    };

    StigCheckResult {
        stig_id: "V-220735".to_string(),
        rule_id: "SV-220735r569262_rule".to_string(),
        title: "Fax service must be disabled".to_string(),
        category: StigCategory::CatII,
        status,
        finding_details: Some(format!("Fax service status: {}", actual)),
        expected: "Disabled or not installed".to_string(),
        actual,
        remediation: Some("Set the Fax service startup type to Disabled".to_string()),
    }
}

fn check_print_spooler_domain(scan_data: &WindowsAuditResult) -> StigCheckResult {
    // On domain controllers, Print Spooler should be disabled
    let is_dc = scan_data.system_info.as_ref()
        .and_then(|si| si.domain.as_ref())
        .map(|d| !d.is_empty())
        .unwrap_or(false);

    let spooler_service = scan_data.services.iter().find(|s| s.name.to_lowercase() == "spooler");

    let (status, actual) = match (is_dc, spooler_service) {
        (true, Some(svc)) if svc.start_type != crate::scanner::windows_audit::types::ServiceStartType::Disabled => {
            (StigCheckStatus::Open, format!("Domain member with Spooler {:?}", svc.start_type))
        }
        (true, Some(_)) => {
            (StigCheckStatus::NotAFinding, "Domain member with Spooler disabled".to_string())
        }
        (false, _) => {
            (StigCheckStatus::NotApplicable, "Not a domain-joined system or Spooler not present".to_string())
        }
        (true, None) => {
            (StigCheckStatus::NotAFinding, "Spooler not installed".to_string())
        }
    };

    StigCheckResult {
        stig_id: "V-220736".to_string(),
        rule_id: "SV-220736r569265_rule".to_string(),
        title: "Print Spooler must be disabled on domain controllers".to_string(),
        category: StigCategory::CatII,
        status,
        finding_details: Some(format!("Print Spooler: {}", actual)),
        expected: "Disabled on domain controllers".to_string(),
        actual,
        remediation: Some("Disable the Print Spooler service on domain controllers".to_string()),
    }
}

fn check_remote_registry_disabled(scan_data: &WindowsAuditResult) -> StigCheckResult {
    let service = scan_data.services.iter().find(|s| s.name.to_lowercase() == "remoteregistry");

    let (status, actual) = match service {
        Some(svc) if svc.start_type == crate::scanner::windows_audit::types::ServiceStartType::Disabled => {
            (StigCheckStatus::NotAFinding, "Disabled".to_string())
        }
        Some(svc) => (StigCheckStatus::Open, format!("{:?}", svc.start_type)),
        None => (StigCheckStatus::NotAFinding, "Service not installed".to_string()),
    };

    StigCheckResult {
        stig_id: "V-220737".to_string(),
        rule_id: "SV-220737r569268_rule".to_string(),
        title: "Remote Registry service must be disabled".to_string(),
        category: StigCategory::CatII,
        status,
        finding_details: Some(format!("Remote Registry service: {}", actual)),
        expected: "Disabled or not installed".to_string(),
        actual,
        remediation: Some("Set the Remote Registry service startup type to Disabled".to_string()),
    }
}

fn check_snmp_service_disabled(scan_data: &WindowsAuditResult) -> StigCheckResult {
    let service = scan_data.services.iter().find(|s| s.name.to_lowercase() == "snmp");

    let (status, actual) = match service {
        Some(svc) if svc.start_type == crate::scanner::windows_audit::types::ServiceStartType::Disabled => {
            (StigCheckStatus::NotAFinding, "Disabled".to_string())
        }
        Some(svc) => (StigCheckStatus::Open, format!("{:?}", svc.start_type)),
        None => (StigCheckStatus::NotAFinding, "Service not installed".to_string()),
    };

    StigCheckResult {
        stig_id: "V-220738".to_string(),
        rule_id: "SV-220738r569271_rule".to_string(),
        title: "SNMP service must be disabled unless required".to_string(),
        category: StigCategory::CatII,
        status,
        finding_details: Some(format!("SNMP service: {}", actual)),
        expected: "Disabled or not installed".to_string(),
        actual,
        remediation: Some("Set the SNMP service startup type to Disabled unless operationally required".to_string()),
    }
}

fn check_telnet_service_disabled(scan_data: &WindowsAuditResult) -> StigCheckResult {
    let service = scan_data.services.iter().find(|s| s.name.to_lowercase() == "tlntsvr");

    let (status, actual) = match service {
        Some(svc) if svc.start_type == crate::scanner::windows_audit::types::ServiceStartType::Disabled => {
            (StigCheckStatus::NotAFinding, "Disabled".to_string())
        }
        Some(svc) => (StigCheckStatus::Open, format!("{:?}", svc.start_type)),
        None => (StigCheckStatus::NotAFinding, "Service not installed".to_string()),
    };

    StigCheckResult {
        stig_id: "V-220739".to_string(),
        rule_id: "SV-220739r569274_rule".to_string(),
        title: "Telnet service must not be installed".to_string(),
        category: StigCategory::CatII,
        status,
        finding_details: Some(format!("Telnet service: {}", actual)),
        expected: "Not installed or disabled".to_string(),
        actual,
        remediation: Some("Uninstall or disable the Telnet Server service".to_string()),
    }
}

fn check_iis_service_check(scan_data: &WindowsAuditResult) -> StigCheckResult {
    let service = scan_data.services.iter().find(|s| s.name.to_lowercase() == "w3svc" || s.name.to_lowercase() == "iisadmin");

    let (status, actual) = match service {
        Some(svc) if svc.start_type == crate::scanner::windows_audit::types::ServiceStartType::Disabled => {
            (StigCheckStatus::NotAFinding, "Disabled".to_string())
        }
        Some(svc) => {
            // IIS running - should have justification
            (StigCheckStatus::NotReviewed, format!("{:?} - verify if required", svc.start_type))
        }
        None => (StigCheckStatus::NotAFinding, "Service not installed".to_string()),
    };

    StigCheckResult {
        stig_id: "V-220747".to_string(),
        rule_id: "SV-220747r569298_rule".to_string(),
        title: "IIS must only be installed if required".to_string(),
        category: StigCategory::CatII,
        status,
        finding_details: Some(format!("IIS service: {}", actual)),
        expected: "Not installed unless required".to_string(),
        actual,
        remediation: Some("Uninstall IIS if not operationally required".to_string()),
    }
}

// === Account Security ===

fn check_guest_account_disabled(scan_data: &WindowsAuditResult) -> StigCheckResult {
    let guest = scan_data.local_users.iter().find(|u| u.name.to_lowercase() == "guest");

    let (status, actual) = match guest {
        Some(user) if !user.enabled => (StigCheckStatus::NotAFinding, "Disabled".to_string()),
        Some(_) => (StigCheckStatus::Open, "Enabled".to_string()),
        None => (StigCheckStatus::NotAFinding, "Account not found".to_string()),
    };

    StigCheckResult {
        stig_id: "V-220748".to_string(),
        rule_id: "SV-220748r569301_rule".to_string(),
        title: "Guest account must be disabled".to_string(),
        category: StigCategory::CatII,
        status,
        finding_details: Some(format!("Guest account: {}", actual)),
        expected: "Disabled".to_string(),
        actual,
        remediation: Some("Disable the Guest account via Local Users and Groups".to_string()),
    }
}

fn check_guest_account_renamed(scan_data: &WindowsAuditResult) -> StigCheckResult {
    let guest = scan_data.local_users.iter().find(|u| u.name.to_lowercase() == "guest");

    let (status, actual) = match guest {
        Some(_) => (StigCheckStatus::Open, "Guest account exists with default name".to_string()),
        None => (StigCheckStatus::NotAFinding, "No account named 'Guest' found (may be renamed)".to_string()),
    };

    StigCheckResult {
        stig_id: "V-220749".to_string(),
        rule_id: "SV-220749r569304_rule".to_string(),
        title: "Guest account must be renamed".to_string(),
        category: StigCategory::CatII,
        status,
        finding_details: Some(actual.clone()),
        expected: "Renamed from 'Guest'".to_string(),
        actual,
        remediation: Some("Rename the Guest account to a non-default name".to_string()),
    }
}

fn check_admin_account_renamed(scan_data: &WindowsAuditResult) -> StigCheckResult {
    let admin = scan_data.local_users.iter().find(|u| u.name.to_lowercase() == "administrator");

    let (status, actual) = match admin {
        Some(_) => (StigCheckStatus::Open, "Administrator account exists with default name".to_string()),
        None => (StigCheckStatus::NotAFinding, "No account named 'Administrator' found (may be renamed)".to_string()),
    };

    StigCheckResult {
        stig_id: "V-220750".to_string(),
        rule_id: "SV-220750r569307_rule".to_string(),
        title: "Administrator account must be renamed".to_string(),
        category: StigCategory::CatII,
        status,
        finding_details: Some(actual.clone()),
        expected: "Renamed from 'Administrator'".to_string(),
        actual,
        remediation: Some("Rename the Administrator account to a non-default name".to_string()),
    }
}

fn check_builtin_admin_disabled(scan_data: &WindowsAuditResult) -> StigCheckResult {
    // Find the built-in administrator (usually by checking group membership or other indicators)
    let admin = scan_data.local_users.iter()
        .find(|u| u.name.to_lowercase() == "administrator" ||
              u.groups.iter().any(|g| g.to_lowercase().contains("administrators")));

    let (status, actual) = match admin {
        Some(user) if !user.enabled => (StigCheckStatus::NotAFinding, "Built-in admin is disabled".to_string()),
        Some(user) if user.name.to_lowercase() != "administrator" => {
            (StigCheckStatus::NotReviewed, format!("Admin account '{}' found - verify if built-in", user.name))
        }
        Some(_) => (StigCheckStatus::Open, "Built-in Administrator is enabled".to_string()),
        None => (StigCheckStatus::NotReviewed, "Could not determine built-in admin status".to_string()),
    };

    StigCheckResult {
        stig_id: "V-220751".to_string(),
        rule_id: "SV-220751r569310_rule".to_string(),
        title: "Built-in Administrator account must be disabled".to_string(),
        category: StigCategory::CatII,
        status,
        finding_details: Some(actual.clone()),
        expected: "Disabled".to_string(),
        actual,
        remediation: Some("Disable the built-in Administrator account and use a separate admin account".to_string()),
    }
}

// === Event Log Settings ===

fn check_application_log_size(scan_data: &WindowsAuditResult) -> StigCheckResult {
    let size = get_registry_dword(
        &scan_data.registry_state,
        r"HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Application",
        "MaxSize",
    );

    let min_size = 32768 * 1024; // 32 MB minimum
    let (status, actual) = match size {
        Some(s) if s >= min_size => (StigCheckStatus::NotAFinding, format!("{} bytes", s)),
        Some(s) => (StigCheckStatus::Open, format!("{} bytes (below 32 MB)", s)),
        None => (StigCheckStatus::NotReviewed, "Not configured".to_string()),
    };

    StigCheckResult {
        stig_id: "V-220752".to_string(),
        rule_id: "SV-220752r569313_rule".to_string(),
        title: "Application event log size must be at least 32 MB".to_string(),
        category: StigCategory::CatII,
        status,
        finding_details: Some(format!("Application log size: {}", actual)),
        expected: ">= 32 MB (33554432 bytes)".to_string(),
        actual,
        remediation: Some("Set Application log maximum size to 32768 KB or greater".to_string()),
    }
}

fn check_security_log_size(scan_data: &WindowsAuditResult) -> StigCheckResult {
    let size = get_registry_dword(
        &scan_data.registry_state,
        r"HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Security",
        "MaxSize",
    );

    let min_size = 196608 * 1024; // 196 MB minimum for Security log
    let (status, actual) = match size {
        Some(s) if s >= min_size => (StigCheckStatus::NotAFinding, format!("{} bytes", s)),
        Some(s) => (StigCheckStatus::Open, format!("{} bytes (below 196 MB)", s)),
        None => (StigCheckStatus::NotReviewed, "Not configured".to_string()),
    };

    StigCheckResult {
        stig_id: "V-220753".to_string(),
        rule_id: "SV-220753r569316_rule".to_string(),
        title: "Security event log size must be at least 196 MB".to_string(),
        category: StigCategory::CatII,
        status,
        finding_details: Some(format!("Security log size: {}", actual)),
        expected: ">= 196 MB (201326592 bytes)".to_string(),
        actual,
        remediation: Some("Set Security log maximum size to 196608 KB or greater".to_string()),
    }
}

fn check_system_log_size(scan_data: &WindowsAuditResult) -> StigCheckResult {
    let size = get_registry_dword(
        &scan_data.registry_state,
        r"HKLM\SYSTEM\CurrentControlSet\Services\EventLog\System",
        "MaxSize",
    );

    let min_size = 32768 * 1024; // 32 MB minimum
    let (status, actual) = match size {
        Some(s) if s >= min_size => (StigCheckStatus::NotAFinding, format!("{} bytes", s)),
        Some(s) => (StigCheckStatus::Open, format!("{} bytes (below 32 MB)", s)),
        None => (StigCheckStatus::NotReviewed, "Not configured".to_string()),
    };

    StigCheckResult {
        stig_id: "V-220754".to_string(),
        rule_id: "SV-220754r569319_rule".to_string(),
        title: "System event log size must be at least 32 MB".to_string(),
        category: StigCategory::CatII,
        status,
        finding_details: Some(format!("System log size: {}", actual)),
        expected: ">= 32 MB (33554432 bytes)".to_string(),
        actual,
        remediation: Some("Set System log maximum size to 32768 KB or greater".to_string()),
    }
}

// === User Rights ===

fn check_debug_programs_limited(scan_data: &WindowsAuditResult) -> StigCheckResult {
    let debug_users = &scan_data.security_policies.user_rights.debug_programs;
    let compliant = debug_users.is_empty() ||
        (debug_users.len() == 1 && debug_users[0].to_lowercase().contains("administrators"));

    StigCheckResult {
        stig_id: "V-220755".to_string(),
        rule_id: "SV-220755r569322_rule".to_string(),
        title: "Debug programs must be limited to Administrators".to_string(),
        category: StigCategory::CatII,
        status: if compliant { StigCheckStatus::NotAFinding } else { StigCheckStatus::Open },
        finding_details: Some(format!("Debug programs assigned to: {:?}", debug_users)),
        expected: "Administrators only".to_string(),
        actual: if debug_users.is_empty() { "None".to_string() } else { debug_users.join(", ") },
        remediation: Some("Remove all users/groups from 'Debug programs' except Administrators".to_string()),
    }
}

fn check_act_as_os_limited(scan_data: &WindowsAuditResult) -> StigCheckResult {
    let act_as_os = &scan_data.security_policies.user_rights.act_as_os;
    let compliant = act_as_os.is_empty();

    StigCheckResult {
        stig_id: "V-220756".to_string(),
        rule_id: "SV-220756r569325_rule".to_string(),
        title: "Act as part of the operating system must not be assigned".to_string(),
        category: StigCategory::CatII,
        status: if compliant { StigCheckStatus::NotAFinding } else { StigCheckStatus::Open },
        finding_details: Some(format!("Act as part of OS assigned to: {:?}", act_as_os)),
        expected: "No one".to_string(),
        actual: if act_as_os.is_empty() { "None".to_string() } else { act_as_os.join(", ") },
        remediation: Some("Remove all users/groups from 'Act as part of the operating system'".to_string()),
    }
}

// === Miscellaneous ===

fn check_screensaver_enabled(scan_data: &WindowsAuditResult) -> StigCheckResult {
    let enabled = get_registry_string(
        &scan_data.registry_state,
        r"HKCU\Control Panel\Desktop",
        "ScreenSaveActive",
    );

    let (status, actual) = match enabled.as_deref() {
        Some("1") => (StigCheckStatus::NotAFinding, "1 (Enabled)".to_string()),
        Some(val) => (StigCheckStatus::Open, val.to_string()),
        None => (StigCheckStatus::NotReviewed, "Not configured".to_string()),
    };

    StigCheckResult {
        stig_id: "V-220757".to_string(),
        rule_id: "SV-220757r569328_rule".to_string(),
        title: "Screen saver must be enabled".to_string(),
        category: StigCategory::CatII,
        status,
        finding_details: Some(format!("Screen saver active: {}", actual)),
        expected: "ScreenSaveActive=1".to_string(),
        actual,
        remediation: Some("Enable screen saver via Group Policy or user settings".to_string()),
    }
}

fn check_screensaver_password(scan_data: &WindowsAuditResult) -> StigCheckResult {
    let secure = get_registry_string(
        &scan_data.registry_state,
        r"HKCU\Control Panel\Desktop",
        "ScreenSaverIsSecure",
    );

    let (status, actual) = match secure.as_deref() {
        Some("1") => (StigCheckStatus::NotAFinding, "1 (Password required)".to_string()),
        Some(val) => (StigCheckStatus::Open, val.to_string()),
        None => (StigCheckStatus::NotReviewed, "Not configured".to_string()),
    };

    StigCheckResult {
        stig_id: "V-220758".to_string(),
        rule_id: "SV-220758r569331_rule".to_string(),
        title: "Screen saver must require password".to_string(),
        category: StigCategory::CatII,
        status,
        finding_details: Some(format!("Screen saver password: {}", actual)),
        expected: "ScreenSaverIsSecure=1".to_string(),
        actual,
        remediation: Some("Enable 'Password protect the screen saver' via Group Policy".to_string()),
    }
}

fn check_cached_logons_limit(scan_data: &WindowsAuditResult) -> StigCheckResult {
    let cached = get_registry_string(
        &scan_data.registry_state,
        r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        "CachedLogonsCount",
    );

    let (status, actual) = match cached {
        Some(ref val) => {
            let count: u32 = val.parse().unwrap_or(10);
            if count <= 4 {
                (StigCheckStatus::NotAFinding, format!("{}", count))
            } else {
                (StigCheckStatus::Open, format!("{}", count))
            }
        }
        None => (StigCheckStatus::Open, "Not configured (defaults to 10)".to_string()),
    };

    StigCheckResult {
        stig_id: "V-220759".to_string(),
        rule_id: "SV-220759r569334_rule".to_string(),
        title: "Cached logon credentials must be limited to 4 or less".to_string(),
        category: StigCategory::CatII,
        status,
        finding_details: Some(format!("Cached logons count: {}", actual)),
        expected: "<= 4".to_string(),
        actual,
        remediation: Some("Set 'Interactive logon: Number of previous logons to cache' to 4 or less".to_string()),
    }
}

fn check_legal_banner(scan_data: &WindowsAuditResult) -> StigCheckResult {
    let caption = get_registry_string(
        &scan_data.registry_state,
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "LegalNoticeCaption",
    );

    let text = get_registry_string(
        &scan_data.registry_state,
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "LegalNoticeText",
    );

    let (status, actual) = match (&caption, &text) {
        (Some(c), Some(t)) if !c.is_empty() && !t.is_empty() => {
            (StigCheckStatus::NotAFinding, format!("Caption: '{}', Text length: {} chars", c, t.len()))
        }
        _ => (StigCheckStatus::Open, "Legal notice not properly configured".to_string()),
    };

    StigCheckResult {
        stig_id: "V-220760".to_string(),
        rule_id: "SV-220760r569337_rule".to_string(),
        title: "Legal notice must be displayed before logon".to_string(),
        category: StigCategory::CatII,
        status,
        finding_details: Some(actual.clone()),
        expected: "LegalNoticeCaption and LegalNoticeText configured".to_string(),
        actual,
        remediation: Some("Configure legal notice via Group Policy: Interactive logon: Message title/text for users attempting to log on".to_string()),
    }
}

// Helper functions

fn get_registry_dword(registry_state: &[RegistryKey], path: &str, value_name: &str) -> Option<u32> {
    for key in registry_state {
        if key.path.eq_ignore_ascii_case(path) {
            for value in &key.values {
                if value.name.eq_ignore_ascii_case(value_name) {
                    return value.data.parse().ok();
                }
            }
        }
    }
    None
}

fn get_registry_string(registry_state: &[RegistryKey], path: &str, value_name: &str) -> Option<String> {
    for key in registry_state {
        if key.path.eq_ignore_ascii_case(path) {
            for value in &key.values {
                if value.name.eq_ignore_ascii_case(value_name) {
                    return Some(value.data.clone());
                }
            }
        }
    }
    None
}
