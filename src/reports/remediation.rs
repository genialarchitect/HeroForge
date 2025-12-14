/// Remediation recommendation database and utilities
/// Note: Primary remediation logic is in types.rs (RemediationRecommendation)
/// This module provides the remediation knowledge base.

use std::collections::HashMap;
use once_cell::sync::Lazy;

/// Remediation advice for common vulnerabilities and services
pub struct RemediationEntry {
    pub title: String,
    pub description: String,
    pub effort: &'static str,
    pub timeline: &'static str,
}

/// Static remediation database keyed by service/vulnerability type
pub static REMEDIATION_DB: Lazy<HashMap<&'static str, RemediationEntry>> = Lazy::new(|| {
    let mut db = HashMap::new();

    // SMB vulnerabilities
    db.insert("smb", RemediationEntry {
        title: "SMB Security Hardening".to_string(),
        description: "Disable SMBv1 protocol, apply latest security patches, restrict SMB access to trusted networks via firewall rules, and enforce SMB signing.".to_string(),
        effort: "Medium",
        timeline: "1-2 weeks",
    });

    // RDP vulnerabilities
    db.insert("rdp", RemediationEntry {
        title: "RDP Access Control".to_string(),
        description: "Enable Network Level Authentication (NLA), restrict RDP access via firewall to trusted IPs only, implement VPN for remote access, and enable account lockout policies.".to_string(),
        effort: "Medium",
        timeline: "1 week",
    });

    // SSH vulnerabilities
    db.insert("ssh", RemediationEntry {
        title: "SSH Security Configuration".to_string(),
        description: "Update SSH to latest version, disable password authentication in favor of key-based auth, disable weak algorithms and ciphers, implement fail2ban, and restrict access by IP.".to_string(),
        effort: "Low",
        timeline: "2-3 days",
    });

    // HTTP/Web vulnerabilities
    db.insert("http", RemediationEntry {
        title: "Web Server Hardening".to_string(),
        description: "Update web server software to latest version, implement security headers (HSTS, CSP, X-Frame-Options), enable TLS 1.2+ only, configure WAF, and remove unnecessary modules.".to_string(),
        effort: "Medium",
        timeline: "1-2 weeks",
    });

    db.insert("https", RemediationEntry {
        title: "TLS/SSL Configuration".to_string(),
        description: "Disable deprecated protocols (SSLv3, TLS 1.0, TLS 1.1), use strong cipher suites only, implement HSTS with preloading, and ensure valid certificates.".to_string(),
        effort: "Low",
        timeline: "1 week",
    });

    // FTP vulnerabilities
    db.insert("ftp", RemediationEntry {
        title: "FTP Service Security".to_string(),
        description: "Disable anonymous FTP access, migrate to SFTP/FTPS for encrypted transfers, implement strong authentication, and review file permissions.".to_string(),
        effort: "Medium",
        timeline: "1-2 weeks",
    });

    // Database vulnerabilities
    db.insert("mysql", RemediationEntry {
        title: "MySQL Security Hardening".to_string(),
        description: "Update to latest stable version, remove default/test databases, enforce strong passwords, restrict network access, review and minimize user privileges.".to_string(),
        effort: "Medium",
        timeline: "1-2 weeks",
    });

    db.insert("postgresql", RemediationEntry {
        title: "PostgreSQL Security Hardening".to_string(),
        description: "Update to latest version, configure pg_hba.conf for secure authentication, use SSL connections, implement row-level security where applicable.".to_string(),
        effort: "Medium",
        timeline: "1-2 weeks",
    });

    db.insert("mongodb", RemediationEntry {
        title: "MongoDB Security Configuration".to_string(),
        description: "Enable authentication, bind to localhost or trusted IPs only, enable TLS, implement role-based access control, and enable audit logging.".to_string(),
        effort: "Medium",
        timeline: "1 week",
    });

    db.insert("redis", RemediationEntry {
        title: "Redis Security Hardening".to_string(),
        description: "Enable authentication with strong password, bind to localhost, disable dangerous commands (FLUSHALL, CONFIG), and run as non-root user.".to_string(),
        effort: "Low",
        timeline: "2-3 days",
    });

    // SMTP vulnerabilities
    db.insert("smtp", RemediationEntry {
        title: "SMTP Security Configuration".to_string(),
        description: "Disable open relay, require STARTTLS for authentication, implement SPF/DKIM/DMARC, and disable VRFY/EXPN commands.".to_string(),
        effort: "Medium",
        timeline: "1 week",
    });

    // LDAP vulnerabilities
    db.insert("ldap", RemediationEntry {
        title: "LDAP Security Hardening".to_string(),
        description: "Disable anonymous binds, require LDAPS (LDAP over TLS), implement access controls on directory objects, and audit bind attempts.".to_string(),
        effort: "Medium",
        timeline: "1-2 weeks",
    });

    // VNC vulnerabilities
    db.insert("vnc", RemediationEntry {
        title: "VNC Access Control".to_string(),
        description: "Implement VPN for VNC access, use SSH tunneling, enforce strong passwords, and restrict access to trusted IPs only.".to_string(),
        effort: "Medium",
        timeline: "1 week",
    });

    // Telnet vulnerabilities
    db.insert("telnet", RemediationEntry {
        title: "Replace Telnet Service".to_string(),
        description: "Disable Telnet entirely and migrate to SSH for secure remote access. Telnet transmits credentials in plaintext and should never be used.".to_string(),
        effort: "Low",
        timeline: "Immediate",
    });

    // General/default
    db.insert("default", RemediationEntry {
        title: "General Security Remediation".to_string(),
        description: "Apply vendor security patches, review and restrict network access, implement principle of least privilege, and enable security logging.".to_string(),
        effort: "Variable",
        timeline: "Based on severity",
    });

    db
});

/// Get remediation advice for a service
pub fn get_remediation_for_service(service: &str) -> &'static RemediationEntry {
    let service_lower = service.to_lowercase();

    // Match service to remediation entry
    for (key, entry) in REMEDIATION_DB.iter() {
        if service_lower.contains(key) {
            return entry;
        }
    }

    // Return default if no match
    REMEDIATION_DB.get("default").unwrap()
}

/// Get remediation advice for a CVE
pub fn get_remediation_for_cve(cve_id: &str) -> String {
    format!(
        "Apply vendor patches addressing {}. Consult the NVD database at https://nvd.nist.gov/vuln/detail/{} for specific remediation guidance.",
        cve_id, cve_id
    )
}
