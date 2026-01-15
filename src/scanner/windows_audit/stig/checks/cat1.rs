//! CAT I (Critical) STIG Checks
//!
//! These are the most severe findings that must be addressed immediately.
//! CAT I vulnerabilities allow immediate remote execution of arbitrary code or
//! denial of service attacks that can severely impact system availability.

use crate::scanner::windows_audit::types::{
    RegistryKey, StigCategory, StigCheckResult, StigCheckStatus, WindowsAuditResult,
};

/// Run all CAT I STIG checks
pub fn run_all(scan_data: &WindowsAuditResult) -> Vec<StigCheckResult> {
    vec![
        // Authentication and Credential Protection
        check_credential_guard_enabled(scan_data),
        check_credential_guard_running(scan_data),
        check_lsa_protection_enabled(scan_data),
        check_wdigest_disabled(scan_data),

        // Encryption and Data Protection
        check_bitlocker_enabled(scan_data),
        check_fips_compliant_algorithms(scan_data),

        // Protocol and Network Security
        check_smbv1_disabled(scan_data),
        check_smbv1_server_disabled(scan_data),
        check_ntlmv2_only(scan_data),
        check_ldap_signing_required(scan_data),
        check_smb_signing_required(scan_data),

        // Service Security
        check_autorun_disabled(scan_data),
        check_anonymous_sid_disabled(scan_data),
        check_anonymous_enumeration_disabled(scan_data),

        // Remote Access Security
        check_rdp_nla_required(scan_data),
        check_rdp_encryption_level(scan_data),
        check_winrm_basic_auth_disabled(scan_data),

        // Code Integrity
        check_secure_boot_enabled(scan_data),
        check_code_integrity_enabled(scan_data),
    ]
}

/// V-220697: Credential Guard must be enabled
fn check_credential_guard_enabled(scan_data: &WindowsAuditResult) -> StigCheckResult {
    // Check registry for Credential Guard enablement
    // HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\EnableVirtualizationBasedSecurity = 1
    // HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\LsaCfgFlags = 1 or 2

    let vbs_enabled = get_registry_dword(
        &scan_data.registry_state,
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard",
        "EnableVirtualizationBasedSecurity",
    );

    let lsa_cfg_flags = get_registry_dword(
        &scan_data.registry_state,
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard",
        "LsaCfgFlags",
    );

    let (status, details, actual) = match (vbs_enabled, lsa_cfg_flags) {
        (Some(1), Some(flags)) if flags == 1 || flags == 2 => (
            StigCheckStatus::NotAFinding,
            "Credential Guard is enabled via VBS".to_string(),
            format!("VBS=1, LsaCfgFlags={}", flags),
        ),
        (Some(vbs), Some(flags)) => (
            StigCheckStatus::Open,
            format!("Credential Guard not properly configured: VBS={}, LsaCfgFlags={}", vbs, flags),
            format!("VBS={}, LsaCfgFlags={}", vbs, flags),
        ),
        (None, _) | (_, None) => (
            StigCheckStatus::Open,
            "Credential Guard registry keys not found or not configured".to_string(),
            "Not configured".to_string(),
        ),
    };

    StigCheckResult {
        stig_id: "V-220697".to_string(),
        rule_id: "SV-220697r857091_rule".to_string(),
        title: "Windows must have Credential Guard enabled".to_string(),
        category: StigCategory::CatI,
        status,
        finding_details: Some(details),
        expected: "EnableVirtualizationBasedSecurity=1, LsaCfgFlags=1 or 2".to_string(),
        actual,
        remediation: Some("Enable Credential Guard via Group Policy: Computer Configuration > Administrative Templates > System > Device Guard > Turn On Virtualization Based Security".to_string()),
    }
}

/// V-220702: Windows Defender Credential Guard must be running
fn check_credential_guard_running(scan_data: &WindowsAuditResult) -> StigCheckResult {
    // Check if the service is running - look for DeviceGuard* services
    let device_guard_running = scan_data.services.iter()
        .any(|s| (s.name.to_lowercase().contains("deviceguard") ||
                  s.name.to_lowercase().contains("vmcompute") ||
                  s.name.to_lowercase() == "hvservice") &&
                 s.status == crate::scanner::windows_audit::types::ServiceStatus::Running);

    // Also check registry for VBS running state
    let vbs_running = get_registry_dword(
        &scan_data.registry_state,
        r"HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard",
        "EnableVirtualizationBasedSecurity",
    );

    let (status, details) = if device_guard_running || vbs_running == Some(1) {
        (StigCheckStatus::NotAFinding, "Credential Guard services are running")
    } else {
        (StigCheckStatus::Open, "Credential Guard services not detected as running")
    };

    StigCheckResult {
        stig_id: "V-220702".to_string(),
        rule_id: "SV-220702r857095_rule".to_string(),
        title: "Windows Defender Credential Guard must be running".to_string(),
        category: StigCategory::CatI,
        status,
        finding_details: Some(details.to_string()),
        expected: "Credential Guard running".to_string(),
        actual: if status == StigCheckStatus::NotAFinding { "Running" } else { "Not running" }.to_string(),
        remediation: Some("Ensure Credential Guard prerequisites are met: UEFI firmware, Secure Boot, TPM 2.0".to_string()),
    }
}

/// V-220698: LSA Protection must be enabled
fn check_lsa_protection_enabled(scan_data: &WindowsAuditResult) -> StigCheckResult {
    // HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL = 1
    let run_as_ppl = get_registry_dword(
        &scan_data.registry_state,
        r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
        "RunAsPPL",
    );

    let (status, details, actual) = match run_as_ppl {
        Some(1) => (
            StigCheckStatus::NotAFinding,
            "LSA Protection (RunAsPPL) is enabled".to_string(),
            "1".to_string(),
        ),
        Some(val) => (
            StigCheckStatus::Open,
            format!("LSA Protection is disabled or misconfigured: RunAsPPL={}", val),
            val.to_string(),
        ),
        None => (
            StigCheckStatus::Open,
            "LSA Protection registry key not found".to_string(),
            "Not configured".to_string(),
        ),
    };

    StigCheckResult {
        stig_id: "V-220698".to_string(),
        rule_id: "SV-220698r877391_rule".to_string(),
        title: "LSA Protection must be enabled".to_string(),
        category: StigCategory::CatI,
        status,
        finding_details: Some(details),
        expected: "RunAsPPL=1".to_string(),
        actual,
        remediation: Some("Set HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\RunAsPPL to 1".to_string()),
    }
}

/// V-220699: WDigest authentication must be disabled
fn check_wdigest_disabled(scan_data: &WindowsAuditResult) -> StigCheckResult {
    // HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential = 0
    let use_logon_cred = get_registry_dword(
        &scan_data.registry_state,
        r"HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest",
        "UseLogonCredential",
    );

    let (status, details, actual) = match use_logon_cred {
        Some(0) | None => (
            // Default on modern Windows is disabled if key doesn't exist
            StigCheckStatus::NotAFinding,
            "WDigest authentication is disabled".to_string(),
            use_logon_cred.map(|v| v.to_string()).unwrap_or("Not set (default disabled)".to_string()),
        ),
        Some(val) => (
            StigCheckStatus::Open,
            format!("WDigest authentication is enabled: UseLogonCredential={}", val),
            val.to_string(),
        ),
    };

    StigCheckResult {
        stig_id: "V-220699".to_string(),
        rule_id: "SV-220699r857092_rule".to_string(),
        title: "WDigest authentication must be disabled".to_string(),
        category: StigCategory::CatI,
        status,
        finding_details: Some(details),
        expected: "UseLogonCredential=0 or not set".to_string(),
        actual,
        remediation: Some("Set HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\\UseLogonCredential to 0".to_string()),
    }
}

/// V-220700: BitLocker must be enabled on the OS volume
fn check_bitlocker_enabled(scan_data: &WindowsAuditResult) -> StigCheckResult {
    // Check for BitLocker Drive Encryption Service
    let bitlocker_service = scan_data.services.iter()
        .find(|s| s.name.to_lowercase() == "bdesvc");

    // Check registry for BitLocker status
    let bitlocker_status = get_registry_dword(
        &scan_data.registry_state,
        r"HKLM\SOFTWARE\Microsoft\BitLocker",
        "ProtectionStatus",
    );

    let (status, details, actual) = match (bitlocker_service, bitlocker_status) {
        (Some(svc), Some(1)) if svc.status == crate::scanner::windows_audit::types::ServiceStatus::Running => (
            StigCheckStatus::NotAFinding,
            "BitLocker is enabled and protection is active".to_string(),
            "Protected".to_string(),
        ),
        (Some(_), _) => (
            StigCheckStatus::Open,
            "BitLocker service exists but protection status could not be verified".to_string(),
            "Unknown protection status".to_string(),
        ),
        (None, _) => (
            StigCheckStatus::Open,
            "BitLocker Drive Encryption Service not found".to_string(),
            "Not installed/configured".to_string(),
        ),
    };

    StigCheckResult {
        stig_id: "V-220700".to_string(),
        rule_id: "SV-220700r877393_rule".to_string(),
        title: "BitLocker must be enabled on the OS volume".to_string(),
        category: StigCategory::CatI,
        status,
        finding_details: Some(details),
        expected: "BitLocker enabled with ProtectionStatus=1".to_string(),
        actual,
        remediation: Some("Enable BitLocker Drive Encryption on the system volume".to_string()),
    }
}

/// V-220701: FIPS compliant algorithms must be used
fn check_fips_compliant_algorithms(scan_data: &WindowsAuditResult) -> StigCheckResult {
    // HKLM\SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy\Enabled = 1
    let fips_enabled = get_registry_dword(
        &scan_data.registry_state,
        r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy",
        "Enabled",
    );

    let (status, details, actual) = match fips_enabled {
        Some(1) => (
            StigCheckStatus::NotAFinding,
            "FIPS compliant algorithms are enabled".to_string(),
            "1".to_string(),
        ),
        Some(val) => (
            StigCheckStatus::Open,
            format!("FIPS mode is not enabled: Enabled={}", val),
            val.to_string(),
        ),
        None => (
            StigCheckStatus::Open,
            "FIPS policy not configured".to_string(),
            "Not configured".to_string(),
        ),
    };

    StigCheckResult {
        stig_id: "V-220701".to_string(),
        rule_id: "SV-220701r857093_rule".to_string(),
        title: "FIPS compliant algorithms must be used for encryption".to_string(),
        category: StigCategory::CatI,
        status,
        finding_details: Some(details),
        expected: "FIPSAlgorithmPolicy\\Enabled=1".to_string(),
        actual,
        remediation: Some("Enable FIPS mode via Local Security Policy or Group Policy".to_string()),
    }
}

/// V-220703: SMBv1 must be disabled
fn check_smbv1_disabled(scan_data: &WindowsAuditResult) -> StigCheckResult {
    // Check SMBv1 client: HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10\Start = 4
    let smb1_start = get_registry_dword(
        &scan_data.registry_state,
        r"HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10",
        "Start",
    );

    // Also check if SMB1 feature is installed
    let smb1_service = scan_data.services.iter()
        .find(|s| s.name.to_lowercase() == "mrxsmb10");

    let (status, details, actual) = match (smb1_start, smb1_service) {
        (Some(4), _) | (_, None) => (
            StigCheckStatus::NotAFinding,
            "SMBv1 client is disabled".to_string(),
            smb1_start.map(|v| format!("Start={}", v)).unwrap_or("Service not present".to_string()),
        ),
        (Some(val), Some(_)) => (
            StigCheckStatus::Open,
            format!("SMBv1 client is enabled: Start={}", val),
            format!("Start={}", val),
        ),
        (None, Some(_)) => (
            StigCheckStatus::Open,
            "SMBv1 client service exists but start value not found".to_string(),
            "Unknown".to_string(),
        ),
    };

    StigCheckResult {
        stig_id: "V-220703".to_string(),
        rule_id: "SV-220703r857094_rule".to_string(),
        title: "SMBv1 client must be disabled".to_string(),
        category: StigCategory::CatI,
        status,
        finding_details: Some(details),
        expected: "mrxsmb10 Start=4 (disabled) or service not present".to_string(),
        actual,
        remediation: Some("Disable SMBv1: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol-Client".to_string()),
    }
}

/// V-220704: SMBv1 Server must be disabled
fn check_smbv1_server_disabled(scan_data: &WindowsAuditResult) -> StigCheckResult {
    // HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\SMB1 = 0
    let smb1_server = get_registry_dword(
        &scan_data.registry_state,
        r"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
        "SMB1",
    );

    let (status, details, actual) = match smb1_server {
        Some(0) => (
            StigCheckStatus::NotAFinding,
            "SMBv1 server is disabled".to_string(),
            "0".to_string(),
        ),
        Some(val) => (
            StigCheckStatus::Open,
            format!("SMBv1 server is enabled: SMB1={}", val),
            val.to_string(),
        ),
        None => (
            // On modern Windows, default is disabled if not set
            StigCheckStatus::NotAFinding,
            "SMBv1 server registry key not set (disabled by default on modern Windows)".to_string(),
            "Not set (default disabled)".to_string(),
        ),
    };

    StigCheckResult {
        stig_id: "V-220704".to_string(),
        rule_id: "SV-220704r857095_rule".to_string(),
        title: "SMBv1 server must be disabled".to_string(),
        category: StigCategory::CatI,
        status,
        finding_details: Some(details),
        expected: "LanmanServer\\Parameters\\SMB1=0".to_string(),
        actual,
        remediation: Some("Disable SMBv1 Server: Set-SmbServerConfiguration -EnableSMB1Protocol $false".to_string()),
    }
}

/// V-220705: NTLM must be restricted to NTLMv2 only
fn check_ntlmv2_only(scan_data: &WindowsAuditResult) -> StigCheckResult {
    // HKLM\SYSTEM\CurrentControlSet\Control\Lsa\LmCompatibilityLevel = 5
    let lm_compat = get_registry_dword(
        &scan_data.registry_state,
        r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
        "LmCompatibilityLevel",
    );

    let (status, details, actual) = match lm_compat {
        Some(5) => (
            StigCheckStatus::NotAFinding,
            "LM authentication is set to send NTLMv2 response only, refuse LM & NTLM".to_string(),
            "5".to_string(),
        ),
        Some(val) => (
            StigCheckStatus::Open,
            format!("LM compatibility level is {}, should be 5", val),
            val.to_string(),
        ),
        None => (
            StigCheckStatus::Open,
            "LmCompatibilityLevel not configured".to_string(),
            "Not configured".to_string(),
        ),
    };

    StigCheckResult {
        stig_id: "V-220705".to_string(),
        rule_id: "SV-220705r857096_rule".to_string(),
        title: "LAN Manager authentication level must be set to send NTLMv2 only".to_string(),
        category: StigCategory::CatI,
        status,
        finding_details: Some(details),
        expected: "LmCompatibilityLevel=5".to_string(),
        actual,
        remediation: Some("Set HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\LmCompatibilityLevel to 5".to_string()),
    }
}

/// V-220706: LDAP client signing must be required
fn check_ldap_signing_required(scan_data: &WindowsAuditResult) -> StigCheckResult {
    // HKLM\SYSTEM\CurrentControlSet\Services\LDAP\LDAPClientIntegrity = 2
    let ldap_signing = get_registry_dword(
        &scan_data.registry_state,
        r"HKLM\SYSTEM\CurrentControlSet\Services\LDAP",
        "LDAPClientIntegrity",
    );

    let (status, details, actual) = match ldap_signing {
        Some(2) => (
            StigCheckStatus::NotAFinding,
            "LDAP client signing is required".to_string(),
            "2".to_string(),
        ),
        Some(val) => (
            StigCheckStatus::Open,
            format!("LDAP client signing is not required: LDAPClientIntegrity={}", val),
            val.to_string(),
        ),
        None => (
            StigCheckStatus::Open,
            "LDAP client signing not configured".to_string(),
            "Not configured (defaults to negotiate)".to_string(),
        ),
    };

    StigCheckResult {
        stig_id: "V-220706".to_string(),
        rule_id: "SV-220706r857097_rule".to_string(),
        title: "LDAP client signing must be set to require signing".to_string(),
        category: StigCategory::CatI,
        status,
        finding_details: Some(details),
        expected: "LDAPClientIntegrity=2".to_string(),
        actual,
        remediation: Some("Set HKLM\\SYSTEM\\CurrentControlSet\\Services\\LDAP\\LDAPClientIntegrity to 2".to_string()),
    }
}

/// V-220707: SMB signing must be required
fn check_smb_signing_required(scan_data: &WindowsAuditResult) -> StigCheckResult {
    // HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\RequireSecuritySignature = 1
    // HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\RequireSecuritySignature = 1

    let server_signing = get_registry_dword(
        &scan_data.registry_state,
        r"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
        "RequireSecuritySignature",
    );

    let client_signing = get_registry_dword(
        &scan_data.registry_state,
        r"HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters",
        "RequireSecuritySignature",
    );

    let (status, details, actual) = match (server_signing, client_signing) {
        (Some(1), Some(1)) => (
            StigCheckStatus::NotAFinding,
            "SMB signing is required for both server and client".to_string(),
            "Server=1, Client=1".to_string(),
        ),
        (server, client) => (
            StigCheckStatus::Open,
            format!(
                "SMB signing not fully required: Server={}, Client={}",
                server.map(|v| v.to_string()).unwrap_or("Not set".to_string()),
                client.map(|v| v.to_string()).unwrap_or("Not set".to_string())
            ),
            format!(
                "Server={}, Client={}",
                server.map(|v| v.to_string()).unwrap_or("Not set".to_string()),
                client.map(|v| v.to_string()).unwrap_or("Not set".to_string())
            ),
        ),
    };

    StigCheckResult {
        stig_id: "V-220707".to_string(),
        rule_id: "SV-220707r857098_rule".to_string(),
        title: "SMB signing must be required for server and client".to_string(),
        category: StigCategory::CatI,
        status,
        finding_details: Some(details),
        expected: "RequireSecuritySignature=1 for both LanmanServer and LanmanWorkstation".to_string(),
        actual,
        remediation: Some("Enable 'Microsoft network server/client: Digitally sign communications (always)' in Security Options".to_string()),
    }
}

/// V-220708: Autorun must be disabled
fn check_autorun_disabled(scan_data: &WindowsAuditResult) -> StigCheckResult {
    // HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoDriveTypeAutoRun = 255
    let autorun = get_registry_dword(
        &scan_data.registry_state,
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
        "NoDriveTypeAutoRun",
    );

    let (status, details, actual) = match autorun {
        Some(255) => (
            StigCheckStatus::NotAFinding,
            "Autorun is disabled for all drive types".to_string(),
            "255".to_string(),
        ),
        Some(val) if val >= 128 => (
            StigCheckStatus::Open,
            format!("Autorun is partially disabled: NoDriveTypeAutoRun={}", val),
            val.to_string(),
        ),
        Some(val) => (
            StigCheckStatus::Open,
            format!("Autorun is not properly disabled: NoDriveTypeAutoRun={}", val),
            val.to_string(),
        ),
        None => (
            StigCheckStatus::Open,
            "Autorun policy not configured".to_string(),
            "Not configured".to_string(),
        ),
    };

    StigCheckResult {
        stig_id: "V-220708".to_string(),
        rule_id: "SV-220708r857099_rule".to_string(),
        title: "Autorun must be disabled for all drives".to_string(),
        category: StigCategory::CatI,
        status,
        finding_details: Some(details),
        expected: "NoDriveTypeAutoRun=255".to_string(),
        actual,
        remediation: Some("Set HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\NoDriveTypeAutoRun to 255".to_string()),
    }
}

/// V-220709: Anonymous SID/Name translation must be disabled
fn check_anonymous_sid_disabled(scan_data: &WindowsAuditResult) -> StigCheckResult {
    // HKLM\SYSTEM\CurrentControlSet\Control\Lsa\TurnOffAnonymousBlock = 1 or
    // LSA policy setting
    let anon_block = get_registry_dword(
        &scan_data.registry_state,
        r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
        "TurnOffAnonymousBlock",
    );

    let restrict_anon = get_registry_dword(
        &scan_data.registry_state,
        r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
        "RestrictAnonymous",
    );

    let (status, details, actual) = match (anon_block, restrict_anon) {
        (Some(1), _) | (_, Some(1)) => (
            StigCheckStatus::NotAFinding,
            "Anonymous SID/Name translation is restricted".to_string(),
            format!(
                "TurnOffAnonymousBlock={}, RestrictAnonymous={}",
                anon_block.map(|v| v.to_string()).unwrap_or("Not set".to_string()),
                restrict_anon.map(|v| v.to_string()).unwrap_or("Not set".to_string())
            ),
        ),
        _ => (
            StigCheckStatus::Open,
            "Anonymous SID/Name translation may be allowed".to_string(),
            format!(
                "TurnOffAnonymousBlock={}, RestrictAnonymous={}",
                anon_block.map(|v| v.to_string()).unwrap_or("Not set".to_string()),
                restrict_anon.map(|v| v.to_string()).unwrap_or("Not set".to_string())
            ),
        ),
    };

    StigCheckResult {
        stig_id: "V-220709".to_string(),
        rule_id: "SV-220709r857100_rule".to_string(),
        title: "Anonymous SID/Name translation must be disabled".to_string(),
        category: StigCategory::CatI,
        status,
        finding_details: Some(details),
        expected: "TurnOffAnonymousBlock=1 or RestrictAnonymous=1".to_string(),
        actual,
        remediation: Some("Set 'Network access: Allow anonymous SID/Name translation' to Disabled".to_string()),
    }
}

/// V-220710: Anonymous enumeration of SAM accounts must be disabled
fn check_anonymous_enumeration_disabled(scan_data: &WindowsAuditResult) -> StigCheckResult {
    // HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RestrictAnonymousSAM = 1
    let restrict_sam = get_registry_dword(
        &scan_data.registry_state,
        r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
        "RestrictAnonymousSAM",
    );

    let (status, details, actual) = match restrict_sam {
        Some(1) => (
            StigCheckStatus::NotAFinding,
            "Anonymous enumeration of SAM accounts is disabled".to_string(),
            "1".to_string(),
        ),
        Some(val) => (
            StigCheckStatus::Open,
            format!("Anonymous enumeration of SAM accounts is not properly disabled: RestrictAnonymousSAM={}", val),
            val.to_string(),
        ),
        None => (
            // Default on Windows is 1 (restricted)
            StigCheckStatus::NotAFinding,
            "RestrictAnonymousSAM not explicitly set (defaults to 1 on modern Windows)".to_string(),
            "Not set (default=1)".to_string(),
        ),
    };

    StigCheckResult {
        stig_id: "V-220710".to_string(),
        rule_id: "SV-220710r857101_rule".to_string(),
        title: "Anonymous enumeration of SAM accounts must not be allowed".to_string(),
        category: StigCategory::CatI,
        status,
        finding_details: Some(details),
        expected: "RestrictAnonymousSAM=1".to_string(),
        actual,
        remediation: Some("Set 'Network access: Do not allow anonymous enumeration of SAM accounts' to Enabled".to_string()),
    }
}

/// V-220711: RDP NLA must be required
fn check_rdp_nla_required(scan_data: &WindowsAuditResult) -> StigCheckResult {
    // HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\UserAuthentication = 1
    let nla_enabled = get_registry_dword(
        &scan_data.registry_state,
        r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
        "UserAuthentication",
    );

    let (status, details, actual) = match nla_enabled {
        Some(1) => (
            StigCheckStatus::NotAFinding,
            "Network Level Authentication is required for RDP".to_string(),
            "1".to_string(),
        ),
        Some(val) => (
            StigCheckStatus::Open,
            format!("Network Level Authentication is not required: UserAuthentication={}", val),
            val.to_string(),
        ),
        None => (
            StigCheckStatus::Open,
            "NLA setting not found - RDP may accept connections without NLA".to_string(),
            "Not configured".to_string(),
        ),
    };

    StigCheckResult {
        stig_id: "V-220711".to_string(),
        rule_id: "SV-220711r857102_rule".to_string(),
        title: "Network Level Authentication must be required for RDP".to_string(),
        category: StigCategory::CatI,
        status,
        finding_details: Some(details),
        expected: "UserAuthentication=1".to_string(),
        actual,
        remediation: Some("Enable 'Require user authentication for remote connections by using Network Level Authentication' in RDP settings".to_string()),
    }
}

/// V-220712: RDP encryption level must be high
fn check_rdp_encryption_level(scan_data: &WindowsAuditResult) -> StigCheckResult {
    // HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\MinEncryptionLevel = 3
    let enc_level = get_registry_dword(
        &scan_data.registry_state,
        r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
        "MinEncryptionLevel",
    );

    let (status, details, actual) = match enc_level {
        Some(3) => (
            StigCheckStatus::NotAFinding,
            "RDP encryption level is set to High".to_string(),
            "3 (High)".to_string(),
        ),
        Some(val) => (
            StigCheckStatus::Open,
            format!("RDP encryption level is not High: MinEncryptionLevel={}", val),
            format!("{}", val),
        ),
        None => (
            StigCheckStatus::Open,
            "RDP encryption level not configured".to_string(),
            "Not configured".to_string(),
        ),
    };

    StigCheckResult {
        stig_id: "V-220712".to_string(),
        rule_id: "SV-220712r857103_rule".to_string(),
        title: "RDP encryption level must be set to High".to_string(),
        category: StigCategory::CatI,
        status,
        finding_details: Some(details),
        expected: "MinEncryptionLevel=3".to_string(),
        actual,
        remediation: Some("Set 'Set client connection encryption level' to High in Remote Desktop Session Host settings".to_string()),
    }
}

/// V-220713: WinRM basic authentication must be disabled
fn check_winrm_basic_auth_disabled(scan_data: &WindowsAuditResult) -> StigCheckResult {
    // HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\AllowBasic = 0
    // HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\AllowBasic = 0

    let service_basic = get_registry_dword(
        &scan_data.registry_state,
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service",
        "AllowBasic",
    );

    let client_basic = get_registry_dword(
        &scan_data.registry_state,
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client",
        "AllowBasic",
    );

    let (status, details, actual) = match (service_basic, client_basic) {
        (Some(0), Some(0)) => (
            StigCheckStatus::NotAFinding,
            "WinRM basic authentication is disabled for both service and client".to_string(),
            "Service=0, Client=0".to_string(),
        ),
        (service, client) => {
            let service_ok = service == Some(0);
            let client_ok = client == Some(0);
            (
                StigCheckStatus::Open,
                format!(
                    "WinRM basic auth: Service={}, Client={}",
                    if service_ok { "disabled" } else { "enabled or not set" },
                    if client_ok { "disabled" } else { "enabled or not set" }
                ),
                format!(
                    "Service={}, Client={}",
                    service.map(|v| v.to_string()).unwrap_or("Not set".to_string()),
                    client.map(|v| v.to_string()).unwrap_or("Not set".to_string())
                ),
            )
        }
    };

    StigCheckResult {
        stig_id: "V-220713".to_string(),
        rule_id: "SV-220713r857104_rule".to_string(),
        title: "WinRM basic authentication must be disabled".to_string(),
        category: StigCategory::CatI,
        status,
        finding_details: Some(details),
        expected: "AllowBasic=0 for both WinRM Service and Client".to_string(),
        actual,
        remediation: Some("Set 'Allow Basic authentication' to Disabled in both WinRM Service and Client GPO settings".to_string()),
    }
}

/// V-220714: Secure Boot must be enabled
fn check_secure_boot_enabled(scan_data: &WindowsAuditResult) -> StigCheckResult {
    // HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State\UEFISecureBootEnabled = 1
    let secure_boot = get_registry_dword(
        &scan_data.registry_state,
        r"HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State",
        "UEFISecureBootEnabled",
    );

    let (status, details, actual) = match secure_boot {
        Some(1) => (
            StigCheckStatus::NotAFinding,
            "Secure Boot is enabled".to_string(),
            "1".to_string(),
        ),
        Some(val) => (
            StigCheckStatus::Open,
            format!("Secure Boot is not enabled: UEFISecureBootEnabled={}", val),
            val.to_string(),
        ),
        None => (
            StigCheckStatus::Open,
            "Secure Boot status could not be determined".to_string(),
            "Not found".to_string(),
        ),
    };

    StigCheckResult {
        stig_id: "V-220714".to_string(),
        rule_id: "SV-220714r857105_rule".to_string(),
        title: "Secure Boot must be enabled".to_string(),
        category: StigCategory::CatI,
        status,
        finding_details: Some(details),
        expected: "UEFISecureBootEnabled=1".to_string(),
        actual,
        remediation: Some("Enable Secure Boot in UEFI firmware settings".to_string()),
    }
}

/// V-220715: Code Integrity must be enabled
fn check_code_integrity_enabled(scan_data: &WindowsAuditResult) -> StigCheckResult {
    // HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity\Enabled = 1
    let hvci = get_registry_dword(
        &scan_data.registry_state,
        r"HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity",
        "Enabled",
    );

    let (status, details, actual) = match hvci {
        Some(1) => (
            StigCheckStatus::NotAFinding,
            "Hypervisor-enforced Code Integrity (HVCI) is enabled".to_string(),
            "1".to_string(),
        ),
        Some(val) => (
            StigCheckStatus::Open,
            format!("HVCI is not enabled: Enabled={}", val),
            val.to_string(),
        ),
        None => (
            StigCheckStatus::Open,
            "HVCI not configured".to_string(),
            "Not configured".to_string(),
        ),
    };

    StigCheckResult {
        stig_id: "V-220715".to_string(),
        rule_id: "SV-220715r857106_rule".to_string(),
        title: "Hypervisor-enforced Code Integrity must be enabled".to_string(),
        category: StigCategory::CatI,
        status,
        finding_details: Some(details),
        expected: "HypervisorEnforcedCodeIntegrity\\Enabled=1".to_string(),
        actual,
        remediation: Some("Enable HVCI via Group Policy: Device Guard > Turn On Virtualization Based Security > Enable UEFI lock".to_string()),
    }
}

// Helper function to get DWORD registry value
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

// Helper function to get string registry value
#[allow(dead_code)]
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
