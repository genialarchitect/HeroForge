//! CAT III (Low) STIG Checks
//!
//! Lower severity findings that represent best practices and should be addressed
//! as resources permit. These findings typically have limited security impact.

use crate::scanner::windows_audit::types::{
    RegistryKey, StigCategory, StigCheckResult, StigCheckStatus, WindowsAuditResult,
};

/// Run all CAT III STIG checks
pub fn run_all(scan_data: &WindowsAuditResult) -> Vec<StigCheckResult> {
    vec![
        // Display and UI Security
        check_screensaver_timeout(scan_data),
        check_last_username_hidden(scan_data),
        check_machine_inactivity_timeout(scan_data),

        // Network Settings
        check_wifi_sense_disabled(scan_data),
        check_ipv6_source_routing_disabled(scan_data),
        check_ip_source_routing_disabled(scan_data),
        check_icmp_redirect_disabled(scan_data),

        // System Information
        check_computer_name_configured(scan_data),
        check_domain_membership(scan_data),

        // Security Features
        check_error_reporting_disabled(scan_data),
        check_windows_telemetry(scan_data),
        check_consumer_experiences_disabled(scan_data),
        check_cortana_disabled(scan_data),
        check_find_my_device_disabled(scan_data),

        // Update and Maintenance
        check_windows_update_configured(scan_data),
        check_automatic_maintenance(scan_data),

        // Password Display
        check_password_reveal_disabled(scan_data),

        // Remote Assistance
        check_remote_assistance_disabled(scan_data),
        check_solicited_remote_assistance(scan_data),

        // Time Synchronization
        check_time_sync_configured(scan_data),

        // Startup and Shutdown
        check_shutdown_without_logon(scan_data),
        check_fast_boot_disabled(scan_data),

        // Explorer and Shell
        check_explorer_heap_termination(scan_data),
        check_shell_protocol_protected(scan_data),

        // Miscellaneous
        check_safe_dll_search_mode(scan_data),
        check_structured_exception_handling(scan_data),
        check_data_execution_prevention(scan_data),
    ]
}

// === Display and UI Security ===

fn check_screensaver_timeout(scan_data: &WindowsAuditResult) -> StigCheckResult {
    let timeout = get_registry_string(
        &scan_data.registry_state,
        r"HKCU\Control Panel\Desktop",
        "ScreenSaveTimeOut",
    );

    let (status, actual) = match timeout {
        Some(ref val) => {
            let seconds: u32 = val.parse().unwrap_or(0);
            if seconds > 0 && seconds <= 900 {
                (StigCheckStatus::NotAFinding, format!("{} seconds", seconds))
            } else if seconds > 900 {
                (StigCheckStatus::Open, format!("{} seconds (> 15 minutes)", seconds))
            } else {
                (StigCheckStatus::Open, format!("{} (invalid)", val))
            }
        }
        None => (StigCheckStatus::NotReviewed, "Not configured".to_string()),
    };

    StigCheckResult {
        stig_id: "V-220761".to_string(),
        rule_id: "SV-220761r569340_rule".to_string(),
        title: "Screen saver timeout must be 15 minutes or less".to_string(),
        category: StigCategory::CatIII,
        status,
        finding_details: Some(format!("Screen saver timeout: {}", actual)),
        expected: "<= 900 seconds (15 minutes)".to_string(),
        actual,
        remediation: Some("Set screen saver timeout to 900 seconds or less via Group Policy".to_string()),
    }
}

fn check_last_username_hidden(scan_data: &WindowsAuditResult) -> StigCheckResult {
    let hidden = get_registry_dword(
        &scan_data.registry_state,
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "DontDisplayLastUserName",
    );

    let (status, actual) = match hidden {
        Some(1) => (StigCheckStatus::NotAFinding, "1 (Hidden)".to_string()),
        Some(val) => (StigCheckStatus::Open, format!("{}", val)),
        None => (StigCheckStatus::Open, "Not configured (shows last username)".to_string()),
    };

    StigCheckResult {
        stig_id: "V-220762".to_string(),
        rule_id: "SV-220762r569343_rule".to_string(),
        title: "Last username must not be displayed at logon".to_string(),
        category: StigCategory::CatIII,
        status,
        finding_details: Some(format!("DontDisplayLastUserName: {}", actual)),
        expected: "DontDisplayLastUserName=1".to_string(),
        actual,
        remediation: Some("Enable 'Interactive logon: Do not display last user name' in Security Options".to_string()),
    }
}

fn check_machine_inactivity_timeout(scan_data: &WindowsAuditResult) -> StigCheckResult {
    let timeout = get_registry_dword(
        &scan_data.registry_state,
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "InactivityTimeoutSecs",
    );

    let (status, actual) = match timeout {
        Some(secs) if secs > 0 && secs <= 900 => {
            (StigCheckStatus::NotAFinding, format!("{} seconds", secs))
        }
        Some(secs) => (StigCheckStatus::Open, format!("{} seconds", secs)),
        None => (StigCheckStatus::Open, "Not configured".to_string()),
    };

    StigCheckResult {
        stig_id: "V-220763".to_string(),
        rule_id: "SV-220763r569346_rule".to_string(),
        title: "Machine inactivity limit must be set to 15 minutes or less".to_string(),
        category: StigCategory::CatIII,
        status,
        finding_details: Some(format!("Inactivity timeout: {}", actual)),
        expected: "<= 900 seconds".to_string(),
        actual,
        remediation: Some("Set 'Interactive logon: Machine inactivity limit' to 900 seconds or less".to_string()),
    }
}

// === Network Settings ===

fn check_wifi_sense_disabled(scan_data: &WindowsAuditResult) -> StigCheckResult {
    let wifi_sense = get_registry_dword(
        &scan_data.registry_state,
        r"HKLM\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config",
        "AutoConnectAllowedOEM",
    );

    let (status, actual) = match wifi_sense {
        Some(0) => (StigCheckStatus::NotAFinding, "0 (Disabled)".to_string()),
        Some(val) => (StigCheckStatus::Open, format!("{}", val)),
        None => (StigCheckStatus::NotAFinding, "Not configured (disabled by default on recent Windows)".to_string()),
    };

    StigCheckResult {
        stig_id: "V-220764".to_string(),
        rule_id: "SV-220764r569349_rule".to_string(),
        title: "Wi-Fi Sense must be disabled".to_string(),
        category: StigCategory::CatIII,
        status,
        finding_details: Some(format!("Wi-Fi Sense: {}", actual)),
        expected: "AutoConnectAllowedOEM=0".to_string(),
        actual,
        remediation: Some("Disable Wi-Fi Sense via Group Policy or registry".to_string()),
    }
}

fn check_ipv6_source_routing_disabled(scan_data: &WindowsAuditResult) -> StigCheckResult {
    let source_routing = get_registry_dword(
        &scan_data.registry_state,
        r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters",
        "DisableIPSourceRouting",
    );

    let (status, actual) = match source_routing {
        Some(2) => (StigCheckStatus::NotAFinding, "2 (Disabled)".to_string()),
        Some(val) => (StigCheckStatus::Open, format!("{}", val)),
        None => (StigCheckStatus::Open, "Not configured".to_string()),
    };

    StigCheckResult {
        stig_id: "V-220765".to_string(),
        rule_id: "SV-220765r569352_rule".to_string(),
        title: "IPv6 source routing must be disabled".to_string(),
        category: StigCategory::CatIII,
        status,
        finding_details: Some(format!("IPv6 source routing: {}", actual)),
        expected: "DisableIPSourceRouting=2".to_string(),
        actual,
        remediation: Some("Set Tcpip6\\Parameters\\DisableIPSourceRouting to 2".to_string()),
    }
}

fn check_ip_source_routing_disabled(scan_data: &WindowsAuditResult) -> StigCheckResult {
    let source_routing = get_registry_dword(
        &scan_data.registry_state,
        r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
        "DisableIPSourceRouting",
    );

    let (status, actual) = match source_routing {
        Some(2) => (StigCheckStatus::NotAFinding, "2 (Disabled)".to_string()),
        Some(val) => (StigCheckStatus::Open, format!("{}", val)),
        None => (StigCheckStatus::Open, "Not configured".to_string()),
    };

    StigCheckResult {
        stig_id: "V-220766".to_string(),
        rule_id: "SV-220766r569355_rule".to_string(),
        title: "IP source routing must be disabled".to_string(),
        category: StigCategory::CatIII,
        status,
        finding_details: Some(format!("IP source routing: {}", actual)),
        expected: "DisableIPSourceRouting=2".to_string(),
        actual,
        remediation: Some("Set Tcpip\\Parameters\\DisableIPSourceRouting to 2".to_string()),
    }
}

fn check_icmp_redirect_disabled(scan_data: &WindowsAuditResult) -> StigCheckResult {
    let icmp_redirect = get_registry_dword(
        &scan_data.registry_state,
        r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
        "EnableICMPRedirect",
    );

    let (status, actual) = match icmp_redirect {
        Some(0) => (StigCheckStatus::NotAFinding, "0 (Disabled)".to_string()),
        Some(val) => (StigCheckStatus::Open, format!("{}", val)),
        None => (StigCheckStatus::Open, "Not configured (enabled by default)".to_string()),
    };

    StigCheckResult {
        stig_id: "V-220767".to_string(),
        rule_id: "SV-220767r569358_rule".to_string(),
        title: "ICMP redirects must be disabled".to_string(),
        category: StigCategory::CatIII,
        status,
        finding_details: Some(format!("ICMP redirects: {}", actual)),
        expected: "EnableICMPRedirect=0".to_string(),
        actual,
        remediation: Some("Set Tcpip\\Parameters\\EnableICMPRedirect to 0".to_string()),
    }
}

// === System Information ===

fn check_computer_name_configured(scan_data: &WindowsAuditResult) -> StigCheckResult {
    let hostname = scan_data.system_info.as_ref()
        .map(|si| si.hostname.clone())
        .unwrap_or_default();

    let is_default = hostname.to_lowercase().starts_with("desktop-") ||
                     hostname.to_lowercase().starts_with("win-") ||
                     hostname.to_lowercase().starts_with("pc-") ||
                     hostname.len() < 3;

    let (status, actual) = if !is_default && !hostname.is_empty() {
        (StigCheckStatus::NotAFinding, hostname)
    } else {
        (StigCheckStatus::Open, format!("'{}' (appears to be default)", hostname))
    };

    StigCheckResult {
        stig_id: "V-220768".to_string(),
        rule_id: "SV-220768r569361_rule".to_string(),
        title: "Computer name should be appropriately configured".to_string(),
        category: StigCategory::CatIII,
        status,
        finding_details: Some(format!("Computer name: {}", actual)),
        expected: "Non-default, meaningful computer name".to_string(),
        actual,
        remediation: Some("Rename computer to follow organizational naming conventions".to_string()),
    }
}

fn check_domain_membership(scan_data: &WindowsAuditResult) -> StigCheckResult {
    let domain = scan_data.system_info.as_ref()
        .and_then(|si| si.domain.as_ref())
        .cloned()
        .unwrap_or_default();

    let is_workgroup = domain.to_lowercase() == "workgroup" || domain.is_empty();

    // This is informational - not necessarily a finding
    let (status, actual) = if is_workgroup {
        (StigCheckStatus::NotReviewed, "Workgroup (not domain-joined)".to_string())
    } else {
        (StigCheckStatus::NotAFinding, format!("Domain: {}", domain))
    };

    StigCheckResult {
        stig_id: "V-220769".to_string(),
        rule_id: "SV-220769r569364_rule".to_string(),
        title: "System should be domain-joined for enterprise management".to_string(),
        category: StigCategory::CatIII,
        status,
        finding_details: Some(format!("Domain membership: {}", actual)),
        expected: "Domain-joined for enterprise environments".to_string(),
        actual,
        remediation: Some("Join the system to the appropriate Active Directory domain".to_string()),
    }
}

// === Security Features ===

fn check_error_reporting_disabled(scan_data: &WindowsAuditResult) -> StigCheckResult {
    let disabled = get_registry_dword(
        &scan_data.registry_state,
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting",
        "Disabled",
    );

    let (status, actual) = match disabled {
        Some(1) => (StigCheckStatus::NotAFinding, "1 (Disabled)".to_string()),
        Some(val) => (StigCheckStatus::Open, format!("{}", val)),
        None => (StigCheckStatus::NotReviewed, "Not configured via policy".to_string()),
    };

    StigCheckResult {
        stig_id: "V-220770".to_string(),
        rule_id: "SV-220770r569367_rule".to_string(),
        title: "Windows Error Reporting should be disabled".to_string(),
        category: StigCategory::CatIII,
        status,
        finding_details: Some(format!("Error Reporting: {}", actual)),
        expected: "Disabled=1".to_string(),
        actual,
        remediation: Some("Configure 'Windows Error Reporting' to Disabled via Group Policy".to_string()),
    }
}

fn check_windows_telemetry(scan_data: &WindowsAuditResult) -> StigCheckResult {
    let telemetry = get_registry_dword(
        &scan_data.registry_state,
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection",
        "AllowTelemetry",
    );

    // 0 = Security (Enterprise only), 1 = Basic, 2 = Enhanced, 3 = Full
    let (status, actual) = match telemetry {
        Some(0) => (StigCheckStatus::NotAFinding, "0 (Security - minimum)".to_string()),
        Some(1) => (StigCheckStatus::NotAFinding, "1 (Basic)".to_string()),
        Some(val) => (StigCheckStatus::Open, format!("{} (Enhanced/Full)", val)),
        None => (StigCheckStatus::Open, "Not configured (defaults to Full)".to_string()),
    };

    StigCheckResult {
        stig_id: "V-220771".to_string(),
        rule_id: "SV-220771r569370_rule".to_string(),
        title: "Windows telemetry must be set to Security or Basic".to_string(),
        category: StigCategory::CatIII,
        status,
        finding_details: Some(format!("Telemetry level: {}", actual)),
        expected: "AllowTelemetry=0 or 1".to_string(),
        actual,
        remediation: Some("Set 'Allow Telemetry' to 0 (Security) or 1 (Basic) via Group Policy".to_string()),
    }
}

fn check_consumer_experiences_disabled(scan_data: &WindowsAuditResult) -> StigCheckResult {
    let disabled = get_registry_dword(
        &scan_data.registry_state,
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent",
        "DisableWindowsConsumerFeatures",
    );

    let (status, actual) = match disabled {
        Some(1) => (StigCheckStatus::NotAFinding, "1 (Disabled)".to_string()),
        Some(val) => (StigCheckStatus::Open, format!("{}", val)),
        None => (StigCheckStatus::Open, "Not configured".to_string()),
    };

    StigCheckResult {
        stig_id: "V-220772".to_string(),
        rule_id: "SV-220772r569373_rule".to_string(),
        title: "Windows consumer experiences must be disabled".to_string(),
        category: StigCategory::CatIII,
        status,
        finding_details: Some(format!("Consumer experiences: {}", actual)),
        expected: "DisableWindowsConsumerFeatures=1".to_string(),
        actual,
        remediation: Some("Enable 'Turn off Microsoft consumer experiences' via Group Policy".to_string()),
    }
}

fn check_cortana_disabled(scan_data: &WindowsAuditResult) -> StigCheckResult {
    let disabled = get_registry_dword(
        &scan_data.registry_state,
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search",
        "AllowCortana",
    );

    let (status, actual) = match disabled {
        Some(0) => (StigCheckStatus::NotAFinding, "0 (Disabled)".to_string()),
        Some(val) => (StigCheckStatus::Open, format!("{}", val)),
        None => (StigCheckStatus::Open, "Not configured".to_string()),
    };

    StigCheckResult {
        stig_id: "V-220773".to_string(),
        rule_id: "SV-220773r569376_rule".to_string(),
        title: "Cortana must be disabled on work networks".to_string(),
        category: StigCategory::CatIII,
        status,
        finding_details: Some(format!("Cortana: {}", actual)),
        expected: "AllowCortana=0".to_string(),
        actual,
        remediation: Some("Set 'Allow Cortana' to Disabled via Group Policy".to_string()),
    }
}

fn check_find_my_device_disabled(scan_data: &WindowsAuditResult) -> StigCheckResult {
    let disabled = get_registry_dword(
        &scan_data.registry_state,
        r"HKLM\SOFTWARE\Policies\Microsoft\FindMyDevice",
        "AllowFindMyDevice",
    );

    let (status, actual) = match disabled {
        Some(0) => (StigCheckStatus::NotAFinding, "0 (Disabled)".to_string()),
        Some(val) => (StigCheckStatus::Open, format!("{}", val)),
        None => (StigCheckStatus::NotReviewed, "Not configured".to_string()),
    };

    StigCheckResult {
        stig_id: "V-220774".to_string(),
        rule_id: "SV-220774r569379_rule".to_string(),
        title: "Find My Device must be disabled".to_string(),
        category: StigCategory::CatIII,
        status,
        finding_details: Some(format!("Find My Device: {}", actual)),
        expected: "AllowFindMyDevice=0".to_string(),
        actual,
        remediation: Some("Set 'Turn off Find My Device' to Enabled via Group Policy".to_string()),
    }
}

// === Update and Maintenance ===

fn check_windows_update_configured(scan_data: &WindowsAuditResult) -> StigCheckResult {
    let au_options = get_registry_dword(
        &scan_data.registry_state,
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU",
        "AUOptions",
    );

    // 4 = Auto download and schedule install
    let (status, actual) = match au_options {
        Some(4) => (StigCheckStatus::NotAFinding, "4 (Auto download and install)".to_string()),
        Some(val) => (StigCheckStatus::NotReviewed, format!("{}", val)),
        None => (StigCheckStatus::NotReviewed, "Not configured via policy".to_string()),
    };

    StigCheckResult {
        stig_id: "V-220775".to_string(),
        rule_id: "SV-220775r569382_rule".to_string(),
        title: "Windows Update must be configured".to_string(),
        category: StigCategory::CatIII,
        status,
        finding_details: Some(format!("Windows Update AUOptions: {}", actual)),
        expected: "AUOptions=4 (recommended)".to_string(),
        actual,
        remediation: Some("Configure Windows Update via Group Policy".to_string()),
    }
}

fn check_automatic_maintenance(scan_data: &WindowsAuditResult) -> StigCheckResult {
    let disabled = get_registry_dword(
        &scan_data.registry_state,
        r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance",
        "MaintenanceDisabled",
    );

    let (status, actual) = match disabled {
        Some(0) | None => (StigCheckStatus::NotAFinding, "Enabled (not disabled)".to_string()),
        Some(val) => (StigCheckStatus::Open, format!("{} (disabled)", val)),
    };

    StigCheckResult {
        stig_id: "V-220776".to_string(),
        rule_id: "SV-220776r569385_rule".to_string(),
        title: "Automatic maintenance must not be disabled".to_string(),
        category: StigCategory::CatIII,
        status,
        finding_details: Some(format!("Automatic maintenance: {}", actual)),
        expected: "MaintenanceDisabled=0 or not set".to_string(),
        actual,
        remediation: Some("Do not disable automatic maintenance".to_string()),
    }
}

// === Password Display ===

fn check_password_reveal_disabled(scan_data: &WindowsAuditResult) -> StigCheckResult {
    let disabled = get_registry_dword(
        &scan_data.registry_state,
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows\CredUI",
        "DisablePasswordReveal",
    );

    let (status, actual) = match disabled {
        Some(1) => (StigCheckStatus::NotAFinding, "1 (Disabled)".to_string()),
        Some(val) => (StigCheckStatus::Open, format!("{}", val)),
        None => (StigCheckStatus::NotReviewed, "Not configured".to_string()),
    };

    StigCheckResult {
        stig_id: "V-220777".to_string(),
        rule_id: "SV-220777r569388_rule".to_string(),
        title: "Password reveal button must be disabled".to_string(),
        category: StigCategory::CatIII,
        status,
        finding_details: Some(format!("Password reveal: {}", actual)),
        expected: "DisablePasswordReveal=1".to_string(),
        actual,
        remediation: Some("Enable 'Do not display the password reveal button' via Group Policy".to_string()),
    }
}

// === Remote Assistance ===

fn check_remote_assistance_disabled(scan_data: &WindowsAuditResult) -> StigCheckResult {
    let allow_ra = get_registry_dword(
        &scan_data.registry_state,
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services",
        "fAllowToGetHelp",
    );

    let (status, actual) = match allow_ra {
        Some(0) => (StigCheckStatus::NotAFinding, "0 (Disabled)".to_string()),
        Some(val) => (StigCheckStatus::Open, format!("{}", val)),
        None => (StigCheckStatus::NotReviewed, "Not configured".to_string()),
    };

    StigCheckResult {
        stig_id: "V-220778".to_string(),
        rule_id: "SV-220778r569391_rule".to_string(),
        title: "Remote Assistance must be disabled or configured securely".to_string(),
        category: StigCategory::CatIII,
        status,
        finding_details: Some(format!("Remote Assistance: {}", actual)),
        expected: "fAllowToGetHelp=0".to_string(),
        actual,
        remediation: Some("Disable 'Configure Offer Remote Assistance' via Group Policy".to_string()),
    }
}

fn check_solicited_remote_assistance(scan_data: &WindowsAuditResult) -> StigCheckResult {
    let allow_solicited = get_registry_dword(
        &scan_data.registry_state,
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services",
        "fAllowUnsolicited",
    );

    let (status, actual) = match allow_solicited {
        Some(0) => (StigCheckStatus::NotAFinding, "0 (Disabled)".to_string()),
        Some(val) => (StigCheckStatus::Open, format!("{}", val)),
        None => (StigCheckStatus::NotAFinding, "Not configured (disabled by default)".to_string()),
    };

    StigCheckResult {
        stig_id: "V-220779".to_string(),
        rule_id: "SV-220779r569394_rule".to_string(),
        title: "Unsolicited Remote Assistance must not be allowed".to_string(),
        category: StigCategory::CatIII,
        status,
        finding_details: Some(format!("Unsolicited Remote Assistance: {}", actual)),
        expected: "fAllowUnsolicited=0".to_string(),
        actual,
        remediation: Some("Disable 'Configure Offer Remote Assistance' via Group Policy".to_string()),
    }
}

// === Time Synchronization ===

fn check_time_sync_configured(scan_data: &WindowsAuditResult) -> StigCheckResult {
    let time_service = scan_data.services.iter()
        .find(|s| s.name.to_lowercase() == "w32time");

    let (status, actual) = match time_service {
        Some(svc) if svc.status == crate::scanner::windows_audit::types::ServiceStatus::Running => {
            (StigCheckStatus::NotAFinding, "Running".to_string())
        }
        Some(svc) => (StigCheckStatus::NotReviewed, format!("{:?}", svc.status)),
        None => (StigCheckStatus::Open, "Service not found".to_string()),
    };

    StigCheckResult {
        stig_id: "V-220780".to_string(),
        rule_id: "SV-220780r569397_rule".to_string(),
        title: "Windows Time service must be running".to_string(),
        category: StigCategory::CatIII,
        status,
        finding_details: Some(format!("Windows Time (W32Time): {}", actual)),
        expected: "Running".to_string(),
        actual,
        remediation: Some("Ensure the Windows Time service is running and configured".to_string()),
    }
}

// === Startup and Shutdown ===

fn check_shutdown_without_logon(scan_data: &WindowsAuditResult) -> StigCheckResult {
    let allow_shutdown = get_registry_dword(
        &scan_data.registry_state,
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "ShutdownWithoutLogon",
    );

    let (status, actual) = match allow_shutdown {
        Some(0) => (StigCheckStatus::NotAFinding, "0 (Disabled)".to_string()),
        Some(val) => (StigCheckStatus::Open, format!("{}", val)),
        None => (StigCheckStatus::Open, "Not configured (enabled by default)".to_string()),
    };

    StigCheckResult {
        stig_id: "V-220781".to_string(),
        rule_id: "SV-220781r569400_rule".to_string(),
        title: "Shutdown without logon must be disabled".to_string(),
        category: StigCategory::CatIII,
        status,
        finding_details: Some(format!("Shutdown without logon: {}", actual)),
        expected: "ShutdownWithoutLogon=0".to_string(),
        actual,
        remediation: Some("Disable 'Shutdown: Allow system to be shut down without having to log on'".to_string()),
    }
}

fn check_fast_boot_disabled(scan_data: &WindowsAuditResult) -> StigCheckResult {
    let fast_boot = get_registry_dword(
        &scan_data.registry_state,
        r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power",
        "HiberbootEnabled",
    );

    let (status, actual) = match fast_boot {
        Some(0) => (StigCheckStatus::NotAFinding, "0 (Disabled)".to_string()),
        Some(val) => (StigCheckStatus::NotReviewed, format!("{} (may impact security updates)", val)),
        None => (StigCheckStatus::NotReviewed, "Not configured".to_string()),
    };

    StigCheckResult {
        stig_id: "V-220782".to_string(),
        rule_id: "SV-220782r569403_rule".to_string(),
        title: "Fast boot should be disabled for full security update application".to_string(),
        category: StigCategory::CatIII,
        status,
        finding_details: Some(format!("Fast boot (HiberbootEnabled): {}", actual)),
        expected: "HiberbootEnabled=0 (recommended)".to_string(),
        actual,
        remediation: Some("Disable Fast Startup via Power Options or registry".to_string()),
    }
}

// === Explorer and Shell ===

fn check_explorer_heap_termination(scan_data: &WindowsAuditResult) -> StigCheckResult {
    let heap_terminate = get_registry_dword(
        &scan_data.registry_state,
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer",
        "NoHeapTerminationOnCorruption",
    );

    // 0 = heap termination enabled (secure)
    let (status, actual) = match heap_terminate {
        Some(0) | None => (StigCheckStatus::NotAFinding, "Heap termination enabled".to_string()),
        Some(val) => (StigCheckStatus::Open, format!("{} (disabled)", val)),
    };

    StigCheckResult {
        stig_id: "V-220783".to_string(),
        rule_id: "SV-220783r569406_rule".to_string(),
        title: "Explorer heap termination on corruption must be enabled".to_string(),
        category: StigCategory::CatIII,
        status,
        finding_details: Some(format!("Heap termination: {}", actual)),
        expected: "NoHeapTerminationOnCorruption=0 or not set".to_string(),
        actual,
        remediation: Some("Do not disable heap termination on corruption".to_string()),
    }
}

fn check_shell_protocol_protected(scan_data: &WindowsAuditResult) -> StigCheckResult {
    let protected = get_registry_dword(
        &scan_data.registry_state,
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
        "PreXPSP2ShellProtocolBehavior",
    );

    let (status, actual) = match protected {
        Some(0) | None => (StigCheckStatus::NotAFinding, "Protected (modern behavior)".to_string()),
        Some(val) => (StigCheckStatus::Open, format!("{} (legacy behavior)", val)),
    };

    StigCheckResult {
        stig_id: "V-220784".to_string(),
        rule_id: "SV-220784r569409_rule".to_string(),
        title: "Shell protocol must use modern protected behavior".to_string(),
        category: StigCategory::CatIII,
        status,
        finding_details: Some(format!("Shell protocol: {}", actual)),
        expected: "PreXPSP2ShellProtocolBehavior=0 or not set".to_string(),
        actual,
        remediation: Some("Do not enable legacy shell protocol behavior".to_string()),
    }
}

// === Miscellaneous ===

fn check_safe_dll_search_mode(scan_data: &WindowsAuditResult) -> StigCheckResult {
    let safe_search = get_registry_dword(
        &scan_data.registry_state,
        r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager",
        "SafeDllSearchMode",
    );

    let (status, actual) = match safe_search {
        Some(1) | None => (StigCheckStatus::NotAFinding, "1 (Enabled - default)".to_string()),
        Some(val) => (StigCheckStatus::Open, format!("{}", val)),
    };

    StigCheckResult {
        stig_id: "V-220785".to_string(),
        rule_id: "SV-220785r569412_rule".to_string(),
        title: "Safe DLL search mode must be enabled".to_string(),
        category: StigCategory::CatIII,
        status,
        finding_details: Some(format!("Safe DLL search mode: {}", actual)),
        expected: "SafeDllSearchMode=1".to_string(),
        actual,
        remediation: Some("Ensure SafeDllSearchMode is set to 1 or not modified from default".to_string()),
    }
}

fn check_structured_exception_handling(scan_data: &WindowsAuditResult) -> StigCheckResult {
    let sehop = get_registry_dword(
        &scan_data.registry_state,
        r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel",
        "DisableExceptionChainValidation",
    );

    // 0 or not set = SEHOP enabled
    let (status, actual) = match sehop {
        Some(0) | None => (StigCheckStatus::NotAFinding, "SEHOP enabled".to_string()),
        Some(val) => (StigCheckStatus::Open, format!("{} (SEHOP disabled)", val)),
    };

    StigCheckResult {
        stig_id: "V-220786".to_string(),
        rule_id: "SV-220786r569415_rule".to_string(),
        title: "Structured Exception Handling Overwrite Protection must be enabled".to_string(),
        category: StigCategory::CatIII,
        status,
        finding_details: Some(format!("SEHOP: {}", actual)),
        expected: "DisableExceptionChainValidation=0 or not set".to_string(),
        actual,
        remediation: Some("Do not disable SEHOP".to_string()),
    }
}

fn check_data_execution_prevention(scan_data: &WindowsAuditResult) -> StigCheckResult {
    let dep = get_registry_dword(
        &scan_data.registry_state,
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer",
        "NoDataExecutionPrevention",
    );

    // 0 or not set = DEP enabled
    let (status, actual) = match dep {
        Some(0) | None => (StigCheckStatus::NotAFinding, "DEP enabled".to_string()),
        Some(val) => (StigCheckStatus::Open, format!("{} (DEP disabled)", val)),
    };

    StigCheckResult {
        stig_id: "V-220787".to_string(),
        rule_id: "SV-220787r569418_rule".to_string(),
        title: "Data Execution Prevention must be enabled for Explorer".to_string(),
        category: StigCategory::CatIII,
        status,
        finding_details: Some(format!("DEP for Explorer: {}", actual)),
        expected: "NoDataExecutionPrevention=0 or not set".to_string(),
        actual,
        remediation: Some("Do not disable Data Execution Prevention for Explorer".to_string()),
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
