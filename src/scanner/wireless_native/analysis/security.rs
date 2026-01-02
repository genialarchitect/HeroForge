//! Wireless security assessment
//!
//! Analyze access point security and identify vulnerabilities.

use chrono::Utc;

use crate::scanner::wireless_native::types::*;

/// Assess wireless security of an access point
pub fn assess_security(ap: &AccessPoint) -> WirelessSecurityAssessment {
    let mut vulnerabilities = Vec::new();
    let mut recommendations = Vec::new();
    let mut rating = 100u8;

    // Check encryption type
    match ap.security {
        SecurityType::Open => {
            vulnerabilities.push(WirelessVulnerability {
                vuln_type: WirelessVulnType::NoEncryption,
                severity: 10,
                description: "Network has no encryption - all traffic is visible".to_string(),
                cve: None,
                exploitable: true,
            });
            recommendations.push("Enable WPA3-Personal or WPA2-Personal encryption".to_string());
            rating = rating.saturating_sub(50);
        }
        SecurityType::WEP => {
            vulnerabilities.push(WirelessVulnerability {
                vuln_type: WirelessVulnType::WeakEncryptionWep,
                severity: 9,
                description: "WEP encryption is broken and can be cracked in minutes".to_string(),
                cve: None,
                exploitable: true,
            });
            recommendations.push("Upgrade to WPA3 or WPA2 - WEP provides no real security".to_string());
            rating = rating.saturating_sub(45);
        }
        SecurityType::WPA => {
            vulnerabilities.push(WirelessVulnerability {
                vuln_type: WirelessVulnType::DeprecatedWpa1,
                severity: 6,
                description: "WPA1 is deprecated and has known weaknesses".to_string(),
                cve: None,
                exploitable: true,
            });
            recommendations.push("Upgrade to WPA3 or at minimum WPA2".to_string());
            rating = rating.saturating_sub(25);
        }
        SecurityType::WPA2 | SecurityType::WpaWpa2Mixed => {
            // WPA2 is acceptable but check for additional issues
            rating = rating.saturating_sub(5);
        }
        SecurityType::Wpa2Wpa3Mixed => {
            // Transitional mode - good but not optimal
            rating = rating.saturating_sub(3);
        }
        SecurityType::WPA3 => {
            // Best current security
        }
        SecurityType::Unknown => {
            rating = rating.saturating_sub(10);
        }
    }

    // Check for TKIP cipher
    if ap.ciphers.contains(&CipherSuite::Tkip) {
        vulnerabilities.push(WirelessVulnerability {
            vuln_type: WirelessVulnType::WeakEncryptionTkip,
            severity: 5,
            description: "TKIP cipher is deprecated and vulnerable to attacks".to_string(),
            cve: Some("CVE-2009-0779".to_string()),
            exploitable: true,
        });
        recommendations.push("Disable TKIP and use CCMP (AES) only".to_string());
        rating = rating.saturating_sub(15);
    }

    // Check WPS status
    if ap.wps_enabled {
        vulnerabilities.push(WirelessVulnerability {
            vuln_type: WirelessVulnType::WpsEnabled,
            severity: 6,
            description: "WPS is enabled, potentially vulnerable to PIN brute-force".to_string(),
            cve: Some("CVE-2011-5053".to_string()),
            exploitable: !ap.wps_locked,
        });

        if !ap.wps_locked {
            vulnerabilities.push(WirelessVulnerability {
                vuln_type: WirelessVulnType::WpsPinBruteforce,
                severity: 8,
                description: "WPS PIN brute-force is possible (not locked)".to_string(),
                cve: Some("CVE-2011-5053".to_string()),
                exploitable: true,
            });
            rating = rating.saturating_sub(20);
        } else {
            rating = rating.saturating_sub(5);
        }

        recommendations.push("Disable WPS - it's a significant security risk".to_string());
    }

    // Check for PSK authentication (vulnerable to offline cracking)
    if ap.auth_methods.contains(&AuthMethod::Psk) && !ap.auth_methods.contains(&AuthMethod::Sae) {
        vulnerabilities.push(WirelessVulnerability {
            vuln_type: WirelessVulnType::PmkidCapturable,
            severity: 5,
            description: "PSK authentication allows PMKID capture for offline cracking".to_string(),
            cve: None,
            exploitable: true,
        });
        recommendations.push("Consider WPA3-SAE or use a strong passphrase (20+ chars)".to_string());
        rating = rating.saturating_sub(5);
    }

    // Check for missing Management Frame Protection
    let has_mfp = ap.ciphers.iter().any(|c| matches!(c,
        CipherSuite::BipCmac128 | CipherSuite::BipGmac128 | CipherSuite::BipGmac256
    ));

    if !has_mfp && !matches!(ap.security, SecurityType::WPA3) {
        vulnerabilities.push(WirelessVulnerability {
            vuln_type: WirelessVulnType::NoMfp,
            severity: 4,
            description: "Management Frame Protection is not enabled".to_string(),
            cve: None,
            exploitable: true,
        });
        recommendations.push("Enable PMF (Protected Management Frames) if supported".to_string());
        rating = rating.saturating_sub(10);
    }

    // Check for KRACK vulnerability (WPA2 without patches)
    if matches!(ap.security, SecurityType::WPA2 | SecurityType::WpaWpa2Mixed) {
        // Can't definitively detect KRACK vulnerability without active testing
        // but we can note the potential risk
        vulnerabilities.push(WirelessVulnerability {
            vuln_type: WirelessVulnType::Krack,
            severity: 7,
            description: "WPA2 may be vulnerable to KRACK if firmware not patched".to_string(),
            cve: Some("CVE-2017-13077".to_string()),
            exploitable: false, // Unknown without testing
        });
        recommendations.push("Ensure AP firmware is updated to patch KRACK (CVE-2017-13077)".to_string());
    }

    // Check for FragAttacks vulnerabilities
    // All WiFi devices are potentially vulnerable
    vulnerabilities.push(WirelessVulnerability {
        vuln_type: WirelessVulnType::FragAttacks,
        severity: 5,
        description: "Potentially vulnerable to FragAttacks (affects all WiFi)".to_string(),
        cve: Some("CVE-2020-24586".to_string()),
        exploitable: false, // Unknown without testing
    });
    recommendations.push("Update firmware to patch FragAttacks (CVE-2020-24586 et al.)".to_string());

    // Ensure rating doesn't go below 0
    let security_rating = rating.max(0);

    WirelessSecurityAssessment {
        access_point: ap.clone(),
        security_rating,
        vulnerabilities,
        recommendations,
        assessed_at: Utc::now(),
    }
}

/// Assess SSID security (hidden, common names, etc.)
pub fn assess_ssid(ssid: &str, hidden: bool) -> Vec<String> {
    let mut issues = Vec::new();

    // Hidden SSID provides no real security
    if hidden {
        issues.push("Hidden SSID provides no security - network can still be discovered".to_string());
    }

    // Check for common/default SSIDs
    let common_ssids = [
        "linksys", "netgear", "dlink", "default", "NETGEAR", "Linksys",
        "ASUS", "TP-Link", "att", "xfinity", "spectrum", "verizon",
        "CenturyLink", "frontier", "HOME-", "DIRECT-", "AndroidAP",
    ];

    let ssid_lower = ssid.to_lowercase();
    for common in &common_ssids {
        if ssid_lower.contains(&common.to_lowercase()) {
            issues.push(format!("SSID contains common/default pattern '{}' - may indicate default config", common));
            break;
        }
    }

    // Very short SSID
    if ssid.len() < 4 {
        issues.push("Very short SSID may indicate testing or misconfiguration".to_string());
    }

    issues
}

/// Generate security report for multiple APs
pub fn generate_security_report(aps: &[AccessPoint]) -> WirelessSecurityReport {
    let mut assessments = Vec::new();
    let mut total_score = 0u32;

    for ap in aps {
        let assessment = assess_security(ap);
        total_score += assessment.security_rating as u32;
        assessments.push(assessment);
    }

    let overall_rating = if !aps.is_empty() {
        (total_score / aps.len() as u32) as u8
    } else {
        0
    };

    // Count vulnerability types
    let mut vuln_summary = std::collections::HashMap::new();
    for assessment in &assessments {
        for vuln in &assessment.vulnerabilities {
            *vuln_summary.entry(format!("{}", vuln.vuln_type)).or_insert(0) += 1;
        }
    }

    WirelessSecurityReport {
        assessments,
        overall_rating,
        vulnerability_summary: vuln_summary,
        generated_at: Utc::now(),
    }
}

/// Security report for multiple access points
#[derive(Debug, Clone)]
pub struct WirelessSecurityReport {
    /// Individual AP assessments
    pub assessments: Vec<WirelessSecurityAssessment>,
    /// Overall security rating
    pub overall_rating: u8,
    /// Vulnerability type counts
    pub vulnerability_summary: std::collections::HashMap<String, u32>,
    /// Report generation time
    pub generated_at: chrono::DateTime<chrono::Utc>,
}

/// Check for potential password policy issues
pub fn check_password_policy_compliance(ssid: &str) -> PasswordPolicyCheck {
    let mut issues = Vec::new();
    let mut compliant = true;

    // Check SSID length (affects key derivation)
    if ssid.is_empty() {
        issues.push("Empty SSID - unusual configuration".to_string());
        compliant = false;
    }

    // Note: We can't check the actual password, but can provide guidance
    let recommendations = vec![
        "Use 20+ character passphrase for WPA2/WPA3".to_string(),
        "Avoid dictionary words and common patterns".to_string(),
        "Include mixed case, numbers, and symbols".to_string(),
        "Consider using a randomly generated passphrase".to_string(),
        "Change password periodically for shared networks".to_string(),
    ];

    PasswordPolicyCheck {
        ssid: ssid.to_string(),
        issues,
        recommendations,
        compliant,
    }
}

/// Password policy check result
#[derive(Debug, Clone)]
pub struct PasswordPolicyCheck {
    pub ssid: String,
    pub issues: Vec<String>,
    pub recommendations: Vec<String>,
    pub compliant: bool,
}

/// Estimate time to crack based on security type
pub fn estimate_crack_time(ap: &AccessPoint, password_length: u8) -> CrackTimeEstimate {
    let security_name = format!("{}", ap.security);

    // Approximate crack times based on hashcat benchmarks (RTX 3090)
    // WPA2-CCMP: ~600,000 H/s
    // Calculations are rough estimates

    let charset_size = 62u128; // a-z, A-Z, 0-9
    let combinations = charset_size.pow(password_length as u32);

    // Hashes per second (approximate for modern GPU)
    let hashes_per_sec = match ap.security {
        SecurityType::WEP => {
            return CrackTimeEstimate {
                security_type: security_name,
                estimated_seconds: Some(60), // WEP can be cracked in ~1 minute
                password_length,
                notes: "WEP can be cracked in minutes regardless of password".to_string(),
            };
        }
        SecurityType::WPA | SecurityType::WPA2 | SecurityType::WpaWpa2Mixed => 600_000u128,
        SecurityType::WPA3 | SecurityType::Wpa2Wpa3Mixed => {
            return CrackTimeEstimate {
                security_type: security_name,
                estimated_seconds: None,
                password_length,
                notes: "WPA3-SAE is resistant to offline dictionary attacks".to_string(),
            };
        }
        SecurityType::Open => {
            return CrackTimeEstimate {
                security_type: security_name,
                estimated_seconds: Some(0),
                password_length,
                notes: "No password required".to_string(),
            };
        }
        SecurityType::Unknown => 100_000u128,
    };

    let seconds = combinations / hashes_per_sec;

    CrackTimeEstimate {
        security_type: security_name,
        estimated_seconds: Some(seconds.min(u64::MAX as u128) as u64),
        password_length,
        notes: format!(
            "Brute-force estimate at {} H/s. Dictionary attacks may be faster.",
            hashes_per_sec
        ),
    }
}

/// Crack time estimate
#[derive(Debug, Clone)]
pub struct CrackTimeEstimate {
    pub security_type: String,
    pub estimated_seconds: Option<u64>,
    pub password_length: u8,
    pub notes: String,
}

impl CrackTimeEstimate {
    /// Format time as human-readable
    pub fn format_time(&self) -> String {
        match self.estimated_seconds {
            None => "Resistant to offline attacks".to_string(),
            Some(0) => "Instant".to_string(),
            Some(secs) => {
                if secs < 60 {
                    format!("{} seconds", secs)
                } else if secs < 3600 {
                    format!("{} minutes", secs / 60)
                } else if secs < 86400 {
                    format!("{} hours", secs / 3600)
                } else if secs < 31536000 {
                    format!("{} days", secs / 86400)
                } else if secs < 31536000 * 1000 {
                    format!("{} years", secs / 31536000)
                } else {
                    "Practically infeasible".to_string()
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_ap(security: SecurityType) -> AccessPoint {
        AccessPoint {
            bssid: "00:11:22:33:44:55".to_string(),
            ssid: Some("TestNetwork".to_string()),
            hidden: false,
            channel: 6,
            frequency: 2437,
            signal_dbm: -50,
            signal_quality: 80,
            security,
            ciphers: vec![CipherSuite::Ccmp],
            auth_methods: vec![AuthMethod::Psk],
            wpa_versions: vec![WpaVersion::Wpa2],
            wps_enabled: false,
            wps_locked: false,
            manufacturer: None,
            clients: Vec::new(),
            first_seen: Utc::now(),
            last_seen: Utc::now(),
            beacon_count: 100,
            data_count: 50,
        }
    }

    #[test]
    fn test_open_network_assessment() {
        let ap = create_test_ap(SecurityType::Open);
        let assessment = assess_security(&ap);

        assert!(assessment.security_rating < 60);
        assert!(assessment.vulnerabilities.iter().any(|v| v.vuln_type == WirelessVulnType::NoEncryption));
    }

    #[test]
    fn test_wpa3_assessment() {
        let mut ap = create_test_ap(SecurityType::WPA3);
        ap.auth_methods = vec![AuthMethod::Sae];
        let assessment = assess_security(&ap);

        assert!(assessment.security_rating >= 80);
    }

    #[test]
    fn test_crack_time_format() {
        let estimate = CrackTimeEstimate {
            security_type: "WPA2".to_string(),
            estimated_seconds: Some(3600),
            password_length: 8,
            notes: String::new(),
        };

        assert_eq!(estimate.format_time(), "1 hours");
    }
}
