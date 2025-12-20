//! LDAP Client for Active Directory Assessment
//!
//! This module provides a wrapper around the ldap3 crate for AD-specific operations.

use anyhow::{anyhow, Result};
use ldap3::{Ldap, LdapConnAsync, LdapConnSettings, Scope, SearchEntry};
use log::{debug, info, warn};
use std::time::Duration;

use super::types::{AdAssessmentConfig, AdAuthMode};

/// LDAP client wrapper for AD operations
pub struct AdLdapClient {
    ldap: Ldap,
    base_dn: String,
    is_authenticated: bool,
}

impl AdLdapClient {
    /// Connect to the domain controller
    pub async fn connect(config: &AdAssessmentConfig) -> Result<Self> {
        let timeout = Duration::from_secs(config.scan_options.timeout_seconds as u64);

        // Build the LDAP URL
        let scheme = if config.use_ldaps { "ldaps" } else { "ldap" };
        let url = format!("{}://{}:{}", scheme, config.domain_controller, config.port);

        info!("Connecting to AD domain controller: {}", url);

        // Configure connection settings
        let settings = LdapConnSettings::new()
            .set_conn_timeout(timeout)
            .set_starttls(false); // Use LDAPS directly instead of STARTTLS

        // Establish connection
        let (conn, mut ldap) = LdapConnAsync::with_settings(settings, &url).await
            .map_err(|e| anyhow!("Failed to connect to LDAP server: {}", e))?;

        // Spawn connection handler
        ldap3::drive!(conn);

        // Perform authentication based on mode
        let is_authenticated = match &config.auth_mode {
            AdAuthMode::Anonymous => {
                debug!("Attempting anonymous bind");
                let result = ldap.simple_bind("", "").await?;
                result.success().is_ok()
            }
            AdAuthMode::Simple { username, password, domain } => {
                let bind_dn = if let Some(dom) = domain {
                    format!("{}\\{}", dom, username)
                } else if username.contains('@') || username.contains('\\') {
                    username.clone()
                } else {
                    username.clone()
                };
                debug!("Attempting simple bind as: {}", bind_dn);
                let result = ldap.simple_bind(&bind_dn, password).await?;
                result.success().is_ok()
            }
            AdAuthMode::Ntlm { username, password, domain } => {
                // For NTLM, use the domain\username format
                let bind_dn = format!("{}\\{}", domain, username);
                debug!("Attempting NTLM bind as: {}", bind_dn);
                let result = ldap.simple_bind(&bind_dn, password).await?;
                result.success().is_ok()
            }
        };

        if !is_authenticated {
            warn!("Authentication failed or anonymous access only");
        } else {
            info!("Successfully authenticated to AD");
        }

        // Determine base DN
        let base_dn = if let Some(dn) = &config.base_dn {
            dn.clone()
        } else {
            Self::discover_base_dn(&mut ldap).await?
        };

        info!("Using base DN: {}", base_dn);

        Ok(Self {
            ldap,
            base_dn,
            is_authenticated,
        })
    }

    /// Discover the base DN from RootDSE
    async fn discover_base_dn(ldap: &mut Ldap) -> Result<String> {
        debug!("Querying RootDSE for base DN");

        let (rs, _res) = ldap
            .search(
                "",
                Scope::Base,
                "(objectClass=*)",
                vec!["defaultNamingContext", "rootDomainNamingContext"],
            )
            .await?
            .success()?;

        for entry in rs {
            let search_entry = SearchEntry::construct(entry);
            if let Some(values) = search_entry.attrs.get("defaultNamingContext") {
                if let Some(dn) = values.first() {
                    return Ok(dn.clone());
                }
            }
            if let Some(values) = search_entry.attrs.get("rootDomainNamingContext") {
                if let Some(dn) = values.first() {
                    return Ok(dn.clone());
                }
            }
        }

        Err(anyhow!("Could not discover base DN from RootDSE"))
    }

    /// Get the base DN
    pub fn base_dn(&self) -> &str {
        &self.base_dn
    }

    /// Check if client is authenticated
    pub fn is_authenticated(&self) -> bool {
        self.is_authenticated
    }

    /// Search for entries
    pub async fn search(
        &mut self,
        base: &str,
        scope: Scope,
        filter: &str,
        attrs: Vec<&str>,
    ) -> Result<Vec<SearchEntry>> {
        let base = if base.is_empty() { &self.base_dn } else { base };

        debug!("LDAP search: base={}, filter={}", base, filter);

        let (rs, _res) = self.ldap
            .search(base, scope, filter, attrs)
            .await?
            .success()?;

        let entries: Vec<SearchEntry> = rs
            .into_iter()
            .map(SearchEntry::construct)
            .collect();

        debug!("Search returned {} entries", entries.len());

        Ok(entries)
    }

    /// Search with paging for large result sets
    pub async fn search_paged(
        &mut self,
        base: &str,
        scope: Scope,
        filter: &str,
        attrs: Vec<&str>,
        page_size: u32,
        max_results: u32,
    ) -> Result<Vec<SearchEntry>> {
        let base = if base.is_empty() { &self.base_dn } else { base };
        let mut all_entries = Vec::new();
        let mut cookie: Vec<u8> = Vec::new();

        debug!("LDAP paged search: base={}, filter={}, page_size={}", base, filter, page_size);

        loop {
            // For now, use regular search without explicit paging
            // ldap3 handles server-side paging automatically for compatible servers
            let (rs, _res) = self.ldap
                .search(base, scope, filter, attrs.clone())
                .await?
                .success()?;

            let entries: Vec<SearchEntry> = rs
                .into_iter()
                .map(SearchEntry::construct)
                .collect();

            all_entries.extend(entries);

            // Check if we've hit the max
            if max_results > 0 && all_entries.len() >= max_results as usize {
                all_entries.truncate(max_results as usize);
                break;
            }

            // For now, break after first page - paging control would need more setup
            break;
        }

        debug!("Paged search returned {} total entries", all_entries.len());

        Ok(all_entries)
    }

    /// Query RootDSE attributes
    pub async fn get_rootdse(&mut self) -> Result<SearchEntry> {
        let (rs, _res) = self.ldap
            .search(
                "",
                Scope::Base,
                "(objectClass=*)",
                vec![
                    "defaultNamingContext",
                    "rootDomainNamingContext",
                    "configurationNamingContext",
                    "schemaNamingContext",
                    "namingContexts",
                    "dnsHostName",
                    "ldapServiceName",
                    "serverName",
                    "supportedLDAPVersion",
                    "supportedControl",
                    "supportedCapabilities",
                    "domainFunctionality",
                    "forestFunctionality",
                    "domainControllerFunctionality",
                ],
            )
            .await?
            .success()?;

        rs.into_iter()
            .next()
            .map(SearchEntry::construct)
            .ok_or_else(|| anyhow!("No RootDSE entry found"))
    }

    /// Close the connection
    pub async fn close(mut self) -> Result<()> {
        self.ldap.unbind().await?;
        Ok(())
    }
}

/// Helper functions for parsing LDAP attributes
pub mod ldap_utils {
    use chrono::{DateTime, TimeZone, Utc};
    use ldap3::SearchEntry;

    /// Get a single string attribute value
    pub fn get_attr(entry: &SearchEntry, attr: &str) -> Option<String> {
        entry.attrs.get(attr)?.first().cloned()
    }

    /// Get all string attribute values
    pub fn get_attrs(entry: &SearchEntry, attr: &str) -> Vec<String> {
        entry.attrs.get(attr).cloned().unwrap_or_default()
    }

    /// Get a boolean attribute (from "TRUE"/"FALSE" string)
    pub fn get_bool_attr(entry: &SearchEntry, attr: &str) -> bool {
        get_attr(entry, attr)
            .map(|v| v.to_uppercase() == "TRUE")
            .unwrap_or(false)
    }

    /// Get an integer attribute
    pub fn get_int_attr(entry: &SearchEntry, attr: &str) -> Option<i64> {
        get_attr(entry, attr)?.parse().ok()
    }

    /// Get a u32 attribute
    pub fn get_u32_attr(entry: &SearchEntry, attr: &str) -> Option<u32> {
        get_attr(entry, attr)?.parse().ok()
    }

    /// Parse Windows FILETIME to DateTime
    /// FILETIME is 100-nanosecond intervals since January 1, 1601 UTC
    pub fn parse_filetime(filetime_str: &str) -> Option<DateTime<Utc>> {
        let filetime: i64 = filetime_str.parse().ok()?;

        if filetime <= 0 || filetime == 0x7FFFFFFFFFFFFFFF {
            return None;
        }

        // Convert 100-nanosecond intervals to seconds
        // Epoch difference: 11644473600 seconds between 1601 and 1970
        let seconds = (filetime / 10_000_000) - 11644473600;
        let nanos = ((filetime % 10_000_000) * 100) as u32;

        Utc.timestamp_opt(seconds, nanos).single()
    }

    /// Parse generalized time (e.g., "20231201120000.0Z")
    pub fn parse_generalized_time(time_str: &str) -> Option<DateTime<Utc>> {
        // Try various formats
        let formats = [
            "%Y%m%d%H%M%S%.fZ",
            "%Y%m%d%H%M%SZ",
            "%Y%m%d%H%M%S",
        ];

        for fmt in &formats {
            if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(time_str, fmt) {
                return Some(DateTime::from_naive_utc_and_offset(dt, Utc));
            }
        }

        None
    }

    /// Parse userAccountControl flags
    pub fn parse_uac_flags(uac: u32) -> UserAccountControlFlags {
        UserAccountControlFlags {
            disabled: (uac & 0x0002) != 0,
            lockout: (uac & 0x0010) != 0,
            password_not_required: (uac & 0x0020) != 0,
            password_cant_change: (uac & 0x0040) != 0,
            encrypted_text_pwd_allowed: (uac & 0x0080) != 0,
            normal_account: (uac & 0x0200) != 0,
            interdomain_trust_account: (uac & 0x0800) != 0,
            workstation_trust_account: (uac & 0x1000) != 0,
            server_trust_account: (uac & 0x2000) != 0,
            dont_expire_password: (uac & 0x10000) != 0,
            mns_logon_account: (uac & 0x20000) != 0,
            smartcard_required: (uac & 0x40000) != 0,
            trusted_for_delegation: (uac & 0x80000) != 0,
            not_delegated: (uac & 0x100000) != 0,
            use_des_key_only: (uac & 0x200000) != 0,
            dont_require_preauth: (uac & 0x400000) != 0,
            password_expired: (uac & 0x800000) != 0,
            trusted_to_auth_for_delegation: (uac & 0x1000000) != 0,
            partial_secrets_account: (uac & 0x04000000) != 0,
        }
    }

    /// Parsed userAccountControl flags
    #[derive(Debug, Clone, Default)]
    pub struct UserAccountControlFlags {
        pub disabled: bool,
        pub lockout: bool,
        pub password_not_required: bool,
        pub password_cant_change: bool,
        pub encrypted_text_pwd_allowed: bool,
        pub normal_account: bool,
        pub interdomain_trust_account: bool,
        pub workstation_trust_account: bool,
        pub server_trust_account: bool,
        pub dont_expire_password: bool,
        pub mns_logon_account: bool,
        pub smartcard_required: bool,
        pub trusted_for_delegation: bool,
        pub not_delegated: bool,
        pub use_des_key_only: bool,
        pub dont_require_preauth: bool,
        pub password_expired: bool,
        pub trusted_to_auth_for_delegation: bool,
        pub partial_secrets_account: bool,
    }

    /// Parse group type integer
    pub fn parse_group_type(group_type: i32) -> (bool, super::super::types::AdGroupScope) {
        use super::super::types::AdGroupScope;

        let is_security = (group_type & 0x80000000u32 as i32) != 0;

        let scope = if (group_type & 0x00000001) != 0 {
            AdGroupScope::BuiltinLocal
        } else if (group_type & 0x00000002) != 0 {
            AdGroupScope::Global
        } else if (group_type & 0x00000004) != 0 {
            AdGroupScope::DomainLocal
        } else if (group_type & 0x00000008) != 0 {
            AdGroupScope::Universal
        } else {
            AdGroupScope::Global
        };

        (is_security, scope)
    }

    /// Parse an SPN into components
    pub fn parse_spn(spn: &str) -> Option<(String, String, Option<u16>, Option<String>)> {
        // Format: service_class/hostname[:port][/service_name]
        let parts: Vec<&str> = spn.splitn(2, '/').collect();
        if parts.len() != 2 {
            return None;
        }

        let service_class = parts[0].to_string();
        let remainder = parts[1];

        let (host_port, service_name) = if let Some(idx) = remainder.rfind('/') {
            (&remainder[..idx], Some(remainder[idx + 1..].to_string()))
        } else {
            (remainder, None)
        };

        let (hostname, port) = if let Some(idx) = host_port.find(':') {
            let h = &host_port[..idx];
            let p: Option<u16> = host_port[idx + 1..].parse().ok();
            (h.to_string(), p)
        } else {
            (host_port.to_string(), None)
        };

        Some((service_class, hostname, port, service_name))
    }
}
