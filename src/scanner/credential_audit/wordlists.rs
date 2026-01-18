//! Built-in credential wordlists for common services
//!
//! These wordlists contain commonly used default and weak credentials.
//! They are used for security auditing to identify systems with default configurations.

use super::types::{Credential, CredentialServiceType};
use std::collections::HashMap;
use once_cell::sync::Lazy;

/// Built-in default credentials organized by service type
pub static DEFAULT_CREDENTIALS: Lazy<HashMap<CredentialServiceType, Vec<Credential>>> = Lazy::new(|| {
    let mut map = HashMap::new();

    // SSH default credentials
    map.insert(CredentialServiceType::Ssh, vec![
        Credential::new("root", "root"),
        Credential::new("root", "toor"),
        Credential::new("root", "password"),
        Credential::new("root", "admin"),
        Credential::new("root", "123456"),
        Credential::new("admin", "admin"),
        Credential::new("admin", "password"),
        Credential::new("admin", "123456"),
        Credential::new("user", "user"),
        Credential::new("user", "password"),
        Credential::new("guest", "guest"),
        Credential::new("test", "test"),
        Credential::new("ubuntu", "ubuntu"),
        Credential::new("pi", "raspberry"),
        Credential::new("vagrant", "vagrant"),
    ]);

    // FTP default credentials
    map.insert(CredentialServiceType::Ftp, vec![
        Credential::new("anonymous", "anonymous"),
        Credential::new("anonymous", ""),
        Credential::new("anonymous", "guest@"),
        Credential::new("ftp", "ftp"),
        Credential::new("admin", "admin"),
        Credential::new("admin", "password"),
        Credential::new("root", "root"),
        Credential::new("user", "user"),
        Credential::new("guest", "guest"),
    ]);

    // Telnet default credentials
    map.insert(CredentialServiceType::Telnet, vec![
        Credential::new("root", "root"),
        Credential::new("admin", "admin"),
        Credential::new("admin", "password"),
        Credential::new("admin", "1234"),
        Credential::new("user", "user"),
        Credential::new("guest", "guest"),
        Credential::new("support", "support"),
        // Common router defaults
        Credential::new("admin", "admin1234"),
        Credential::new("cisco", "cisco"),
    ]);

    // MySQL default credentials
    map.insert(CredentialServiceType::Mysql, vec![
        Credential::new("root", ""),
        Credential::new("root", "root"),
        Credential::new("root", "mysql"),
        Credential::new("root", "password"),
        Credential::new("root", "123456"),
        Credential::new("mysql", "mysql"),
        Credential::new("admin", "admin"),
        Credential::new("dbadmin", "dbadmin"),
        Credential::new("test", "test"),
    ]);

    // PostgreSQL default credentials
    map.insert(CredentialServiceType::Postgresql, vec![
        Credential::new("postgres", "postgres"),
        Credential::new("postgres", ""),
        Credential::new("postgres", "password"),
        Credential::new("postgres", "admin"),
        Credential::new("admin", "admin"),
        Credential::new("pgsql", "pgsql"),
    ]);

    // Microsoft SQL Server default credentials
    map.insert(CredentialServiceType::Mssql, vec![
        Credential::new("sa", ""),
        Credential::new("sa", "sa"),
        Credential::new("sa", "password"),
        Credential::new("sa", "Password123"),
        Credential::new("sa", "Password1"),
        Credential::new("admin", "admin"),
    ]);

    // MongoDB default credentials
    map.insert(CredentialServiceType::Mongodb, vec![
        Credential::new("admin", "admin"),
        Credential::new("admin", "password"),
        Credential::new("root", "root"),
        Credential::new("mongo", "mongo"),
        // Note: MongoDB often has no auth by default
    ]);

    // Redis default credentials
    map.insert(CredentialServiceType::Redis, vec![
        // Redis auth is typically just a password
        Credential::new("", ""),
        Credential::new("", "redis"),
        Credential::new("", "password"),
        Credential::new("default", ""),
        Credential::new("default", "redis"),
    ]);

    // Oracle default credentials
    map.insert(CredentialServiceType::Oracle, vec![
        Credential::new("system", "oracle"),
        Credential::new("system", "password"),
        Credential::new("system", "manager"),
        Credential::new("system", "system"),
        Credential::new("sys", "oracle"),
        Credential::new("sys", "change_on_install"),
        Credential::new("sys", "sys"),
        Credential::new("scott", "tiger"),
        Credential::new("dbsnmp", "dbsnmp"),
        Credential::new("outln", "outln"),
        Credential::new("mdsys", "mdsys"),
        Credential::new("ordplugins", "ordplugins"),
        Credential::new("ordsys", "ordsys"),
        Credential::new("ctxsys", "ctxsys"),
        Credential::new("dssys", "dssys"),
        Credential::new("perfstat", "perfstat"),
        Credential::new("wkproxy", "wkproxy"),
        Credential::new("wksys", "wksys"),
        Credential::new("xdb", "xdb"),
        Credential::new("applsys", "applsys"),
        Credential::new("apps", "apps"),
    ]);

    // Memcached default credentials (usually no auth)
    map.insert(CredentialServiceType::Memcached, vec![
        Credential::new("", ""),
        Credential::new("admin", "admin"),
        Credential::new("memcached", "memcached"),
    ]);

    // Cassandra default credentials
    map.insert(CredentialServiceType::Cassandra, vec![
        Credential::new("cassandra", "cassandra"),
        Credential::new("admin", "admin"),
        Credential::new("root", "root"),
        Credential::new("cassandra", "password"),
    ]);

    // InfluxDB default credentials
    map.insert(CredentialServiceType::InfluxDb, vec![
        Credential::new("admin", "admin"),
        Credential::new("admin", "password"),
        Credential::new("admin", ""),
        Credential::new("influx", "influx"),
        Credential::new("root", "root"),
    ]);

    // Elasticsearch default credentials
    map.insert(CredentialServiceType::Elasticsearch, vec![
        Credential::new("elastic", "changeme"),
        Credential::new("elastic", "elastic"),
        Credential::new("admin", "admin"),
        Credential::new("root", "root"),
        Credential::new("kibana", "kibana"),
    ]);

    // CouchDB default credentials
    map.insert(CredentialServiceType::CouchDb, vec![
        Credential::new("admin", "password"),
        Credential::new("admin", "admin"),
        Credential::new("couchdb", "couchdb"),
        Credential::new("root", "root"),
        Credential::new("", ""), // No auth
    ]);

    // ClickHouse default credentials
    map.insert(CredentialServiceType::ClickHouse, vec![
        Credential::new("default", ""),
        Credential::new("admin", "admin"),
        Credential::new("clickhouse", "clickhouse"),
        Credential::new("root", "root"),
    ]);

    // Tomcat Manager default credentials
    map.insert(CredentialServiceType::TomcatManager, vec![
        Credential::new("tomcat", "tomcat"),
        Credential::new("admin", "admin"),
        Credential::new("manager", "manager"),
        Credential::new("role1", "role1"),
        Credential::new("root", "root"),
        Credential::new("tomcat", "s3cret"),
        Credential::new("admin", "password"),
        Credential::new("both", "tomcat"),
    ]);

    // phpMyAdmin default credentials
    map.insert(CredentialServiceType::PhpMyAdmin, vec![
        Credential::new("root", ""),
        Credential::new("root", "root"),
        Credential::new("root", "mysql"),
        Credential::new("pma", "pmapass"),
        Credential::new("admin", "admin"),
        Credential::new("mysql", "mysql"),
    ]);

    // WordPress default credentials
    map.insert(CredentialServiceType::WordPress, vec![
        Credential::new("admin", "admin"),
        Credential::new("admin", "password"),
        Credential::new("admin", "123456"),
        Credential::new("administrator", "admin"),
        Credential::new("wp-admin", "wp-admin"),
        Credential::new("wordpress", "wordpress"),
    ]);

    // Joomla default credentials
    map.insert(CredentialServiceType::Joomla, vec![
        Credential::new("admin", "admin"),
        Credential::new("admin", "password"),
        Credential::new("administrator", "administrator"),
        Credential::new("joomla", "joomla"),
    ]);

    // Drupal default credentials
    map.insert(CredentialServiceType::Drupal, vec![
        Credential::new("admin", "admin"),
        Credential::new("admin", "password"),
        Credential::new("drupal", "drupal"),
    ]);

    // SNMP community strings
    map.insert(CredentialServiceType::Snmp, vec![
        Credential::new("", "public"),
        Credential::new("", "private"),
        Credential::new("", "community"),
        Credential::new("", "snmp"),
        Credential::new("", "admin"),
        Credential::new("", "default"),
        Credential::new("", "password"),
        Credential::new("", "cisco"),
        Credential::new("", "secret"),
    ]);

    // RDP default credentials
    map.insert(CredentialServiceType::Rdp, vec![
        Credential::new("Administrator", "admin"),
        Credential::new("Administrator", "password"),
        Credential::new("Administrator", "Password1"),
        Credential::new("admin", "admin"),
        Credential::new("admin", "password"),
        Credential::new("guest", "guest"),
        Credential::new("user", "user"),
    ]);

    // VNC default credentials
    map.insert(CredentialServiceType::Vnc, vec![
        Credential::new("", ""),
        Credential::new("", "vnc"),
        Credential::new("", "password"),
        Credential::new("", "1234"),
        Credential::new("", "12345"),
        Credential::new("", "vncpassword"),
    ]);

    // MikroTik RouterOS default credentials
    map.insert(CredentialServiceType::RouterOs, vec![
        Credential::new("admin", ""),
        Credential::new("admin", "admin"),
        Credential::new("admin", "password"),
    ]);

    // Cisco IOS default credentials
    map.insert(CredentialServiceType::CiscoIos, vec![
        Credential::new("cisco", "cisco"),
        Credential::new("admin", "admin"),
        Credential::new("admin", "password"),
        Credential::new("enable", "cisco"),
    ]);

    // SMTP default credentials
    map.insert(CredentialServiceType::Smtp, vec![
        Credential::new("admin", "admin"),
        Credential::new("admin", "password"),
        Credential::new("postmaster", "postmaster"),
        Credential::new("mail", "mail"),
    ]);

    // POP3 default credentials
    map.insert(CredentialServiceType::Pop3, vec![
        Credential::new("admin", "admin"),
        Credential::new("admin", "password"),
        Credential::new("user", "user"),
        Credential::new("test", "test"),
    ]);

    // IMAP default credentials
    map.insert(CredentialServiceType::Imap, vec![
        Credential::new("admin", "admin"),
        Credential::new("admin", "password"),
        Credential::new("user", "user"),
        Credential::new("test", "test"),
    ]);

    map
});

/// Common weak passwords that can be tested with discovered usernames
pub static COMMON_WEAK_PASSWORDS: &[&str] = &[
    "password",
    "password1",
    "password123",
    "123456",
    "12345678",
    "123456789",
    "1234567890",
    "qwerty",
    "abc123",
    "admin",
    "letmein",
    "welcome",
    "monkey",
    "dragon",
    "master",
    "login",
    "changeme",
    "test",
    "guest",
    "root",
    "pass",
    "pass123",
    "p@ssw0rd",
    "P@ssw0rd",
    "Password1",
    "Password123",
];

/// Common usernames to test with weak passwords
pub static COMMON_USERNAMES: &[&str] = &[
    "admin",
    "administrator",
    "root",
    "user",
    "test",
    "guest",
    "operator",
    "manager",
    "support",
    "staff",
    "backup",
    "oracle",
    "mysql",
    "postgres",
    "ftp",
    "www-data",
    "apache",
    "nginx",
    "tomcat",
    "webmaster",
];

/// Get default credentials for a specific service type
pub fn get_default_credentials(service_type: CredentialServiceType) -> Vec<Credential> {
    DEFAULT_CREDENTIALS
        .get(&service_type)
        .cloned()
        .unwrap_or_default()
}

/// Get all credentials (defaults + common weak combinations) for a service type
pub fn get_all_credentials(service_type: CredentialServiceType) -> Vec<Credential> {
    let mut creds = get_default_credentials(service_type);

    // Add common username/password combinations
    for username in COMMON_USERNAMES {
        for password in COMMON_WEAK_PASSWORDS {
            let cred = Credential::new(*username, *password);
            // Avoid duplicates
            if !creds.iter().any(|c| c.username == cred.username && c.password == cred.password) {
                creds.push(cred);
            }
        }
    }

    creds
}

/// Get credentials for a service, with optional custom credentials
pub fn get_credentials_for_service(
    service_type: CredentialServiceType,
    custom_credentials: Option<&[(String, String)]>,
    default_only: bool,
) -> Vec<Credential> {
    let mut creds = if default_only {
        get_default_credentials(service_type)
    } else {
        get_all_credentials(service_type)
    };

    // Add custom credentials at the beginning (higher priority)
    if let Some(custom) = custom_credentials {
        let custom_creds: Vec<Credential> = custom
            .iter()
            .map(|(u, p)| Credential::new(u, p))
            .collect();

        // Prepend custom credentials
        let mut all_creds = custom_creds;
        all_creds.extend(creds);
        creds = all_creds;
    }

    creds
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_default_credentials() {
        let ssh_creds = get_default_credentials(CredentialServiceType::Ssh);
        assert!(!ssh_creds.is_empty());
        assert!(ssh_creds.iter().any(|c| c.username == "root"));
    }

    #[test]
    fn test_get_all_credentials() {
        let all_creds = get_all_credentials(CredentialServiceType::Ssh);
        let default_creds = get_default_credentials(CredentialServiceType::Ssh);
        assert!(all_creds.len() >= default_creds.len());
    }

    #[test]
    fn test_get_credentials_with_custom() {
        let custom = vec![
            ("custom_user".to_string(), "custom_pass".to_string()),
        ];
        let creds = get_credentials_for_service(
            CredentialServiceType::Ssh,
            Some(&custom),
            true,
        );

        // Custom should be first
        assert_eq!(creds[0].username, "custom_user");
        assert_eq!(creds[0].password, "custom_pass");
    }
}
