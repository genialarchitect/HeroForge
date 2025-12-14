use crate::types::{Severity, Vulnerability};
use log::debug;
use once_cell::sync::Lazy;
use std::collections::HashMap;

/// Offline CVE entry with version matching support
#[derive(Debug, Clone)]
pub struct CveEntry {
    pub cve_id: String,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub cvss_score: f32,
    /// Version pattern: "exact", "<=X.Y", ">=X.Y", "X.Y-X.Z", or regex-like "X.Y.*"
    pub version_pattern: VersionPattern,
}

#[derive(Debug, Clone)]
pub enum VersionPattern {
    /// Exact version match (e.g., "2.4.49")
    Exact(String),
    /// Any of these versions (e.g., ["2.4.49", "2.4.50"])
    AnyOf(Vec<String>),
    /// Less than or equal (e.g., "<=7.7")
    LessThanOrEqual(String),
    /// Range inclusive (e.g., "2.4.0" to "2.4.50")
    Range(String, String),
    /// Contains substring (e.g., version contains "7.4")
    Contains(String),
    /// All versions affected
    All,
}

/// The embedded CVE database
static CVE_DATABASE: Lazy<HashMap<String, Vec<CveEntry>>> = Lazy::new(|| {
    let mut db: HashMap<String, Vec<CveEntry>> = HashMap::new();

    // ============================================================================
    // Apache HTTP Server
    // ============================================================================
    db.insert("apache".to_string(), vec![
        CveEntry {
            cve_id: "CVE-2021-41773".to_string(),
            title: "Apache HTTP Server Path Traversal".to_string(),
            description: "A path traversal vulnerability in Apache HTTP Server 2.4.49 allows attackers to map URLs to files outside the document root. Can lead to RCE if mod_cgi is enabled.".to_string(),
            severity: Severity::Critical,
            cvss_score: 9.8,
            version_pattern: VersionPattern::Exact("2.4.49".to_string()),
        },
        CveEntry {
            cve_id: "CVE-2021-42013".to_string(),
            title: "Apache HTTP Server Path Traversal (Bypass)".to_string(),
            description: "Incomplete fix for CVE-2021-41773 in Apache 2.4.50. Path traversal still possible with URL encoding bypass.".to_string(),
            severity: Severity::Critical,
            cvss_score: 9.8,
            version_pattern: VersionPattern::Exact("2.4.50".to_string()),
        },
        CveEntry {
            cve_id: "CVE-2019-0211".to_string(),
            title: "Apache HTTP Server Privilege Escalation".to_string(),
            description: "Apache HTTP Server 2.4.17 to 2.4.38 allows local privilege escalation from low-privileged child process to root.".to_string(),
            severity: Severity::High,
            cvss_score: 7.8,
            version_pattern: VersionPattern::Range("2.4.17".to_string(), "2.4.38".to_string()),
        },
        CveEntry {
            cve_id: "CVE-2017-15715".to_string(),
            title: "Apache HTTP Server FilesMatch Bypass".to_string(),
            description: "Apache 2.4.0 to 2.4.29: FilesMatch directive can be bypassed using the trailing newline character.".to_string(),
            severity: Severity::High,
            cvss_score: 8.1,
            version_pattern: VersionPattern::Range("2.4.0".to_string(), "2.4.29".to_string()),
        },
        CveEntry {
            cve_id: "CVE-2017-9788".to_string(),
            title: "Apache HTTP Server Digest Auth Memory Leak".to_string(),
            description: "Apache 2.2.0 to 2.2.33 and 2.4.1 to 2.4.26: Uninitialized memory reflection in mod_auth_digest.".to_string(),
            severity: Severity::High,
            cvss_score: 7.5,
            version_pattern: VersionPattern::Range("2.4.1".to_string(), "2.4.26".to_string()),
        },
    ]);

    // ============================================================================
    // Nginx
    // ============================================================================
    db.insert("nginx".to_string(), vec![
        CveEntry {
            cve_id: "CVE-2021-23017".to_string(),
            title: "Nginx DNS Resolver Off-by-One Heap Write".to_string(),
            description: "Nginx 0.6.18 to 1.20.0: One-byte memory overwrite in DNS resolver allows remote code execution.".to_string(),
            severity: Severity::Critical,
            cvss_score: 9.8,
            version_pattern: VersionPattern::Range("0.6.18".to_string(), "1.20.0".to_string()),
        },
        CveEntry {
            cve_id: "CVE-2019-20372".to_string(),
            title: "Nginx HTTP Request Smuggling".to_string(),
            description: "Nginx before 1.17.7 allows HTTP request smuggling via error pages.".to_string(),
            severity: Severity::Medium,
            cvss_score: 5.3,
            version_pattern: VersionPattern::LessThanOrEqual("1.17.6".to_string()),
        },
        CveEntry {
            cve_id: "CVE-2017-7529".to_string(),
            title: "Nginx Integer Overflow".to_string(),
            description: "Nginx 0.5.6 to 1.13.2: Integer overflow in range filter allows cache poisoning or sensitive data disclosure.".to_string(),
            severity: Severity::High,
            cvss_score: 7.5,
            version_pattern: VersionPattern::Range("0.5.6".to_string(), "1.13.2".to_string()),
        },
    ]);

    // ============================================================================
    // OpenSSH
    // ============================================================================
    db.insert("openssh".to_string(), vec![
        CveEntry {
            cve_id: "CVE-2024-6387".to_string(),
            title: "OpenSSH regreSSHion RCE".to_string(),
            description: "Signal handler race condition in OpenSSH server (sshd) allows unauthenticated remote code execution as root on glibc-based Linux systems.".to_string(),
            severity: Severity::Critical,
            cvss_score: 8.1,
            version_pattern: VersionPattern::Range("8.5p1".to_string(), "9.7p1".to_string()),
        },
        CveEntry {
            cve_id: "CVE-2018-15473".to_string(),
            title: "OpenSSH Username Enumeration".to_string(),
            description: "OpenSSH through 7.7 allows username enumeration via timing differences in authentication responses.".to_string(),
            severity: Severity::Medium,
            cvss_score: 5.3,
            version_pattern: VersionPattern::LessThanOrEqual("7.7".to_string()),
        },
        CveEntry {
            cve_id: "CVE-2016-10012".to_string(),
            title: "OpenSSH Privilege Escalation".to_string(),
            description: "sshd in OpenSSH before 7.4 allows local privilege escalation via forwarded agent sockets.".to_string(),
            severity: Severity::High,
            cvss_score: 7.8,
            version_pattern: VersionPattern::LessThanOrEqual("7.3".to_string()),
        },
        CveEntry {
            cve_id: "CVE-2016-6515".to_string(),
            title: "OpenSSH Password Length DoS".to_string(),
            description: "OpenSSH before 7.3 allows denial of service via long password strings (crypt CPU exhaustion).".to_string(),
            severity: Severity::High,
            cvss_score: 7.5,
            version_pattern: VersionPattern::LessThanOrEqual("7.2".to_string()),
        },
    ]);

    // ============================================================================
    // MySQL / MariaDB
    // ============================================================================
    db.insert("mysql".to_string(), vec![
        CveEntry {
            cve_id: "CVE-2016-6662".to_string(),
            title: "MySQL Remote Root Code Execution".to_string(),
            description: "MySQL <= 5.7.14 and <= 5.6.32 allows remote attackers to execute arbitrary code as root via mysqld_safe.".to_string(),
            severity: Severity::Critical,
            cvss_score: 9.8,
            version_pattern: VersionPattern::LessThanOrEqual("5.7.14".to_string()),
        },
        CveEntry {
            cve_id: "CVE-2020-14812".to_string(),
            title: "MySQL Server DoS".to_string(),
            description: "Vulnerability in MySQL Server allows high-privileged attacker to cause denial of service.".to_string(),
            severity: Severity::Medium,
            cvss_score: 4.9,
            version_pattern: VersionPattern::LessThanOrEqual("8.0.21".to_string()),
        },
        CveEntry {
            cve_id: "CVE-2012-2122".to_string(),
            title: "MySQL Authentication Bypass".to_string(),
            description: "MySQL 5.1.x and 5.5.x: Authentication bypass due to incorrect memcmp return value check.".to_string(),
            severity: Severity::Critical,
            cvss_score: 9.8,
            version_pattern: VersionPattern::Range("5.1.0".to_string(), "5.5.23".to_string()),
        },
    ]);

    // ============================================================================
    // PostgreSQL
    // ============================================================================
    db.insert("postgresql".to_string(), vec![
        CveEntry {
            cve_id: "CVE-2019-10164".to_string(),
            title: "PostgreSQL Stack Buffer Overflow".to_string(),
            description: "PostgreSQL 10.x before 10.9 and 11.x before 11.4: Stack-based buffer overflow via oversized message length.".to_string(),
            severity: Severity::Critical,
            cvss_score: 9.8,
            version_pattern: VersionPattern::Range("10.0".to_string(), "10.8".to_string()),
        },
        CveEntry {
            cve_id: "CVE-2018-1058".to_string(),
            title: "PostgreSQL Search Path Injection".to_string(),
            description: "PostgreSQL before 10.3, 9.6.8, 9.5.12: Uncontrolled search path allows privilege escalation.".to_string(),
            severity: Severity::High,
            cvss_score: 8.8,
            version_pattern: VersionPattern::LessThanOrEqual("10.2".to_string()),
        },
    ]);

    // ============================================================================
    // Redis
    // ============================================================================
    db.insert("redis".to_string(), vec![
        CveEntry {
            cve_id: "CVE-2022-0543".to_string(),
            title: "Redis Lua Sandbox Escape RCE".to_string(),
            description: "Debian/Ubuntu Redis packages allow Lua sandbox escape leading to remote code execution.".to_string(),
            severity: Severity::Critical,
            cvss_score: 10.0,
            version_pattern: VersionPattern::All,
        },
        CveEntry {
            cve_id: "CVE-2021-32761".to_string(),
            title: "Redis Integer Overflow".to_string(),
            description: "Redis before 6.2.4, 6.0.14, 5.0.13: Integer overflow in BITFIELD command leads to heap corruption.".to_string(),
            severity: Severity::High,
            cvss_score: 7.5,
            version_pattern: VersionPattern::LessThanOrEqual("6.2.3".to_string()),
        },
        CveEntry {
            cve_id: "CVE-2015-8080".to_string(),
            title: "Redis Integer Overflow DoS".to_string(),
            description: "Redis before 2.8.24 and 3.0.x before 3.0.6: Integer overflow in getnum function.".to_string(),
            severity: Severity::High,
            cvss_score: 7.5,
            version_pattern: VersionPattern::LessThanOrEqual("3.0.5".to_string()),
        },
    ]);

    // ============================================================================
    // MongoDB
    // ============================================================================
    db.insert("mongodb".to_string(), vec![
        CveEntry {
            cve_id: "CVE-2020-7921".to_string(),
            title: "MongoDB Authentication Bypass".to_string(),
            description: "MongoDB 4.0 before 4.0.18, 4.2 before 4.2.6: Improper serialization allows authentication bypass.".to_string(),
            severity: Severity::High,
            cvss_score: 7.5,
            version_pattern: VersionPattern::Range("4.0.0".to_string(), "4.0.17".to_string()),
        },
        CveEntry {
            cve_id: "CVE-2019-2390".to_string(),
            title: "MongoDB BSON DoS".to_string(),
            description: "MongoDB 3.x and 4.x: Malformed BSON message can cause server crash.".to_string(),
            severity: Severity::High,
            cvss_score: 7.5,
            version_pattern: VersionPattern::LessThanOrEqual("4.0.8".to_string()),
        },
    ]);

    // ============================================================================
    // Elasticsearch
    // ============================================================================
    db.insert("elasticsearch".to_string(), vec![
        CveEntry {
            cve_id: "CVE-2015-1427".to_string(),
            title: "Elasticsearch Groovy Sandbox RCE".to_string(),
            description: "Elasticsearch before 1.4.3: Groovy scripting engine sandbox bypass allows remote code execution.".to_string(),
            severity: Severity::Critical,
            cvss_score: 9.8,
            version_pattern: VersionPattern::LessThanOrEqual("1.4.2".to_string()),
        },
        CveEntry {
            cve_id: "CVE-2014-3120".to_string(),
            title: "Elasticsearch Dynamic Scripting RCE".to_string(),
            description: "Elasticsearch before 1.2: Default enabled dynamic scripting allows arbitrary code execution.".to_string(),
            severity: Severity::Critical,
            cvss_score: 9.8,
            version_pattern: VersionPattern::LessThanOrEqual("1.1.1".to_string()),
        },
        CveEntry {
            cve_id: "CVE-2015-5531".to_string(),
            title: "Elasticsearch Directory Traversal".to_string(),
            description: "Elasticsearch before 1.6.1: Directory traversal in snapshot/restore API.".to_string(),
            severity: Severity::High,
            cvss_score: 7.5,
            version_pattern: VersionPattern::LessThanOrEqual("1.6.0".to_string()),
        },
    ]);

    // ============================================================================
    // vsftpd
    // ============================================================================
    db.insert("vsftpd".to_string(), vec![
        CveEntry {
            cve_id: "CVE-2011-2523".to_string(),
            title: "vsftpd Backdoor".to_string(),
            description: "vsftpd 2.3.4 downloaded between 2011-06-30 and 2011-07-01 contains a backdoor (smiley face trigger).".to_string(),
            severity: Severity::Critical,
            cvss_score: 10.0,
            version_pattern: VersionPattern::Exact("2.3.4".to_string()),
        },
    ]);

    // ============================================================================
    // ProFTPD
    // ============================================================================
    db.insert("proftpd".to_string(), vec![
        CveEntry {
            cve_id: "CVE-2015-3306".to_string(),
            title: "ProFTPD mod_copy Remote Code Execution".to_string(),
            description: "ProFTPD before 1.3.5a: mod_copy allows unauthenticated arbitrary file copy, leading to RCE.".to_string(),
            severity: Severity::Critical,
            cvss_score: 9.8,
            version_pattern: VersionPattern::LessThanOrEqual("1.3.5".to_string()),
        },
        CveEntry {
            cve_id: "CVE-2019-12815".to_string(),
            title: "ProFTPD mod_copy Arbitrary File Copy".to_string(),
            description: "ProFTPD before 1.3.6: mod_copy allows arbitrary file copy without authentication.".to_string(),
            severity: Severity::Critical,
            cvss_score: 9.8,
            version_pattern: VersionPattern::LessThanOrEqual("1.3.5b".to_string()),
        },
    ]);

    // ============================================================================
    // Apache Tomcat
    // ============================================================================
    db.insert("tomcat".to_string(), vec![
        CveEntry {
            cve_id: "CVE-2020-1938".to_string(),
            title: "Apache Tomcat AJP Ghostcat".to_string(),
            description: "Apache Tomcat AJP Connector (port 8009) allows reading web application files and potential RCE.".to_string(),
            severity: Severity::Critical,
            cvss_score: 9.8,
            version_pattern: VersionPattern::LessThanOrEqual("9.0.30".to_string()),
        },
        CveEntry {
            cve_id: "CVE-2019-0232".to_string(),
            title: "Apache Tomcat CGI Remote Code Execution".to_string(),
            description: "Apache Tomcat on Windows with enableCmdLineArguments allows remote code execution.".to_string(),
            severity: Severity::Critical,
            cvss_score: 9.8,
            version_pattern: VersionPattern::Range("9.0.0".to_string(), "9.0.17".to_string()),
        },
        CveEntry {
            cve_id: "CVE-2017-12617".to_string(),
            title: "Apache Tomcat PUT Method JSP Upload".to_string(),
            description: "Apache Tomcat with PUT method enabled allows uploading JSP files for code execution.".to_string(),
            severity: Severity::Critical,
            cvss_score: 9.8,
            version_pattern: VersionPattern::LessThanOrEqual("9.0.0".to_string()),
        },
    ]);

    // ============================================================================
    // Microsoft IIS
    // ============================================================================
    db.insert("iis".to_string(), vec![
        CveEntry {
            cve_id: "CVE-2017-7269".to_string(),
            title: "IIS WebDAV Buffer Overflow".to_string(),
            description: "Microsoft IIS 6.0 WebDAV ScStoragePathFromUrl buffer overflow allows remote code execution.".to_string(),
            severity: Severity::Critical,
            cvss_score: 9.8,
            version_pattern: VersionPattern::Exact("6.0".to_string()),
        },
        CveEntry {
            cve_id: "CVE-2015-1635".to_string(),
            title: "IIS HTTP.sys Remote Code Execution".to_string(),
            description: "Windows HTTP.sys (IIS) allows remote code execution via crafted HTTP request.".to_string(),
            severity: Severity::Critical,
            cvss_score: 9.8,
            version_pattern: VersionPattern::Range("7.0".to_string(), "8.5".to_string()),
        },
    ]);

    // ============================================================================
    // PHP
    // ============================================================================
    db.insert("php".to_string(), vec![
        CveEntry {
            cve_id: "CVE-2012-1823".to_string(),
            title: "PHP-CGI Argument Injection".to_string(),
            description: "PHP before 5.3.12 and 5.4.x before 5.4.2: sapi/cgi/cgi_main.c allows remote code execution via query string.".to_string(),
            severity: Severity::Critical,
            cvss_score: 9.8,
            version_pattern: VersionPattern::LessThanOrEqual("5.3.11".to_string()),
        },
        CveEntry {
            cve_id: "CVE-2024-4577".to_string(),
            title: "PHP-CGI Argument Injection (Windows)".to_string(),
            description: "PHP on Windows: Argument injection in php-cgi allows remote code execution.".to_string(),
            severity: Severity::Critical,
            cvss_score: 9.8,
            version_pattern: VersionPattern::LessThanOrEqual("8.3.7".to_string()),
        },
    ]);

    // ============================================================================
    // Samba / SMB
    // ============================================================================
    db.insert("samba".to_string(), vec![
        CveEntry {
            cve_id: "CVE-2017-7494".to_string(),
            title: "Samba Remote Code Execution (SambaCry)".to_string(),
            description: "Samba 3.5.0 to 4.6.4: Authenticated users can upload and execute shared library.".to_string(),
            severity: Severity::Critical,
            cvss_score: 9.8,
            version_pattern: VersionPattern::Range("3.5.0".to_string(), "4.6.3".to_string()),
        },
    ]);

    // ============================================================================
    // OpenSSL
    // ============================================================================
    db.insert("openssl".to_string(), vec![
        CveEntry {
            cve_id: "CVE-2014-0160".to_string(),
            title: "OpenSSL Heartbleed".to_string(),
            description: "OpenSSL 1.0.1 through 1.0.1f: Heartbleed bug allows reading process memory.".to_string(),
            severity: Severity::Critical,
            cvss_score: 9.8,
            version_pattern: VersionPattern::Range("1.0.1".to_string(), "1.0.1f".to_string()),
        },
    ]);

    // ============================================================================
    // MSSQL
    // ============================================================================
    db.insert("mssql".to_string(), vec![
        CveEntry {
            cve_id: "CVE-2020-0618".to_string(),
            title: "SQL Server Reporting Services RCE".to_string(),
            description: "Microsoft SQL Server Reporting Services allows remote code execution via deserialization.".to_string(),
            severity: Severity::Critical,
            cvss_score: 9.8,
            version_pattern: VersionPattern::All,
        },
    ]);

    db
});

/// Query the offline CVE database
pub fn query_offline_cves(product: &str, version: Option<&str>, port: u16) -> Vec<Vulnerability> {
    let mut vulns = Vec::new();

    if let Some(entries) = CVE_DATABASE.get(product) {
        for entry in entries {
            if version_matches(version, &entry.version_pattern) {
                debug!(
                    "Offline DB match: {} for {}:{} (version={:?})",
                    entry.cve_id, product, port, version
                );
                vulns.push(Vulnerability {
                    cve_id: Some(entry.cve_id.clone()),
                    title: entry.title.clone(),
                    severity: entry.severity.clone(),
                    description: entry.description.clone(),
                    affected_service: Some(format!("{}:{}", product, port)),
                });
            }
        }
    }

    vulns
}

/// Check if a version matches a pattern
fn version_matches(version: Option<&str>, pattern: &VersionPattern) -> bool {
    match pattern {
        VersionPattern::All => true,
        VersionPattern::Exact(v) => version.map(|ver| ver.contains(v)).unwrap_or(false),
        VersionPattern::Contains(v) => version.map(|ver| ver.contains(v)).unwrap_or(false),
        VersionPattern::AnyOf(versions) => version
            .map(|ver| versions.iter().any(|v| ver.contains(v)))
            .unwrap_or(false),
        VersionPattern::LessThanOrEqual(max) => {
            version.map(|ver| compare_versions(ver, max) <= 0).unwrap_or(false)
        }
        VersionPattern::Range(min, max) => {
            version
                .map(|ver| compare_versions(ver, min) >= 0 && compare_versions(ver, max) <= 0)
                .unwrap_or(false)
        }
    }
}

/// Compare two version strings (returns -1, 0, or 1)
fn compare_versions(a: &str, b: &str) -> i32 {
    let parse_version = |s: &str| -> Vec<u32> {
        s.split(|c: char| !c.is_ascii_digit())
            .filter(|p| !p.is_empty())
            .filter_map(|p| p.parse().ok())
            .collect()
    };

    let va = parse_version(a);
    let vb = parse_version(b);

    for (a_part, b_part) in va.iter().zip(vb.iter()) {
        match a_part.cmp(b_part) {
            std::cmp::Ordering::Less => return -1,
            std::cmp::Ordering::Greater => return 1,
            std::cmp::Ordering::Equal => continue,
        }
    }

    match va.len().cmp(&vb.len()) {
        std::cmp::Ordering::Less => -1,
        std::cmp::Ordering::Greater => 1,
        std::cmp::Ordering::Equal => 0,
    }
}

/// Get count of CVEs in offline database
pub fn get_offline_db_stats() -> (usize, usize) {
    let product_count = CVE_DATABASE.len();
    let cve_count: usize = CVE_DATABASE.values().map(|v| v.len()).sum();
    (product_count, cve_count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compare_versions() {
        assert_eq!(compare_versions("2.4.49", "2.4.50"), -1);
        assert_eq!(compare_versions("2.4.50", "2.4.49"), 1);
        assert_eq!(compare_versions("2.4.49", "2.4.49"), 0);
        assert_eq!(compare_versions("7.7", "7.8"), -1);
        assert_eq!(compare_versions("1.0.1f", "1.0.1f"), 0);
    }

    #[test]
    fn test_version_matches() {
        assert!(version_matches(
            Some("2.4.49"),
            &VersionPattern::Exact("2.4.49".to_string())
        ));
        assert!(!version_matches(
            Some("2.4.48"),
            &VersionPattern::Exact("2.4.49".to_string())
        ));
        assert!(version_matches(
            Some("7.5"),
            &VersionPattern::LessThanOrEqual("7.7".to_string())
        ));
        assert!(!version_matches(
            Some("7.9"),
            &VersionPattern::LessThanOrEqual("7.7".to_string())
        ));
    }

    #[test]
    fn test_query_offline_cves() {
        let vulns = query_offline_cves("apache", Some("2.4.49"), 80);
        assert!(!vulns.is_empty());
        assert!(vulns.iter().any(|v| v.cve_id == Some("CVE-2021-41773".to_string())));

        let vulns2 = query_offline_cves("openssh", Some("7.4"), 22);
        assert!(!vulns2.is_empty());
    }

    #[test]
    fn test_db_stats() {
        let (products, cves) = get_offline_db_stats();
        assert!(products >= 10);
        assert!(cves >= 30);
    }
}
