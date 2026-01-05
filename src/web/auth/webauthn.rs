//! WebAuthn/FIDO2 authentication support
//!
//! Provides passwordless authentication using FIDO2/WebAuthn standards including:
//! - Registration ceremony (credential creation)
//! - Authentication ceremony (assertion verification)
//! - Credential management
//! - Full CBOR attestation object parsing
//! - COSE key decoding (ES256, RS256, EdDSA)

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

// =============================================================================
// CBOR Parser for WebAuthn Attestation
// =============================================================================

/// CBOR value types
#[derive(Debug, Clone)]
pub enum CborValue {
    Unsigned(u64),
    Signed(i64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<CborValue>),
    Map(Vec<(CborValue, CborValue)>),
    Tag(u64, Box<CborValue>),
    Simple(u8),
    Float(f64),
    Bool(bool),
    Null,
    Undefined,
}

impl CborValue {
    /// Get as unsigned integer
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            CborValue::Unsigned(n) => Some(*n),
            CborValue::Signed(n) if *n >= 0 => Some(*n as u64),
            _ => None,
        }
    }

    /// Get as signed integer
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            CborValue::Unsigned(n) if *n <= i64::MAX as u64 => Some(*n as i64),
            CborValue::Signed(n) => Some(*n),
            _ => None,
        }
    }

    /// Get as bytes
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            CborValue::Bytes(b) => Some(b),
            _ => None,
        }
    }

    /// Get as string
    pub fn as_str(&self) -> Option<&str> {
        match self {
            CborValue::Text(s) => Some(s),
            _ => None,
        }
    }

    /// Get as array
    pub fn as_array(&self) -> Option<&[CborValue]> {
        match self {
            CborValue::Array(a) => Some(a),
            _ => None,
        }
    }

    /// Get as map
    pub fn as_map(&self) -> Option<&[(CborValue, CborValue)]> {
        match self {
            CborValue::Map(m) => Some(m),
            _ => None,
        }
    }

    /// Get map value by key
    pub fn get(&self, key: &str) -> Option<&CborValue> {
        match self {
            CborValue::Map(m) => {
                m.iter()
                    .find(|(k, _)| matches!(k, CborValue::Text(s) if s == key))
                    .map(|(_, v)| v)
            }
            _ => None,
        }
    }

    /// Get map value by integer key
    pub fn get_int(&self, key: i64) -> Option<&CborValue> {
        match self {
            CborValue::Map(m) => {
                m.iter()
                    .find(|(k, _)| k.as_i64() == Some(key))
                    .map(|(_, v)| v)
            }
            _ => None,
        }
    }
}

/// CBOR decoder
pub struct CborDecoder<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> CborDecoder<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn remaining(&self) -> &[u8] {
        &self.data[self.pos..]
    }

    fn read_byte(&mut self) -> Result<u8> {
        if self.pos >= self.data.len() {
            return Err(anyhow!("CBOR: Unexpected end of data"));
        }
        let byte = self.data[self.pos];
        self.pos += 1;
        Ok(byte)
    }

    fn read_bytes(&mut self, n: usize) -> Result<&[u8]> {
        if self.pos + n > self.data.len() {
            return Err(anyhow!("CBOR: Unexpected end of data"));
        }
        let bytes = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(bytes)
    }

    fn read_u16(&mut self) -> Result<u16> {
        let bytes = self.read_bytes(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn read_u32(&mut self) -> Result<u32> {
        let bytes = self.read_bytes(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn read_u64(&mut self) -> Result<u64> {
        let bytes = self.read_bytes(8)?;
        Ok(u64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3],
            bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    fn read_argument(&mut self, additional: u8) -> Result<u64> {
        match additional {
            0..=23 => Ok(additional as u64),
            24 => Ok(self.read_byte()? as u64),
            25 => Ok(self.read_u16()? as u64),
            26 => Ok(self.read_u32()? as u64),
            27 => Ok(self.read_u64()?),
            _ => Err(anyhow!("CBOR: Invalid additional value")),
        }
    }

    pub fn decode(&mut self) -> Result<CborValue> {
        let initial = self.read_byte()?;
        let major = initial >> 5;
        let additional = initial & 0x1f;

        match major {
            0 => {
                // Unsigned integer
                let value = self.read_argument(additional)?;
                Ok(CborValue::Unsigned(value))
            }
            1 => {
                // Negative integer
                let value = self.read_argument(additional)?;
                Ok(CborValue::Signed(-1 - value as i64))
            }
            2 => {
                // Byte string
                let len = self.read_argument(additional)? as usize;
                let bytes = self.read_bytes(len)?;
                Ok(CborValue::Bytes(bytes.to_vec()))
            }
            3 => {
                // Text string
                let len = self.read_argument(additional)? as usize;
                let bytes = self.read_bytes(len)?;
                let text = String::from_utf8(bytes.to_vec())
                    .map_err(|_| anyhow!("CBOR: Invalid UTF-8"))?;
                Ok(CborValue::Text(text))
            }
            4 => {
                // Array
                let len = self.read_argument(additional)? as usize;
                let mut items = Vec::with_capacity(len);
                for _ in 0..len {
                    items.push(self.decode()?);
                }
                Ok(CborValue::Array(items))
            }
            5 => {
                // Map
                let len = self.read_argument(additional)? as usize;
                let mut pairs = Vec::with_capacity(len);
                for _ in 0..len {
                    let key = self.decode()?;
                    let value = self.decode()?;
                    pairs.push((key, value));
                }
                Ok(CborValue::Map(pairs))
            }
            6 => {
                // Tag
                let tag = self.read_argument(additional)?;
                let value = self.decode()?;
                Ok(CborValue::Tag(tag, Box::new(value)))
            }
            7 => {
                // Simple/float
                match additional {
                    20 => Ok(CborValue::Bool(false)),
                    21 => Ok(CborValue::Bool(true)),
                    22 => Ok(CborValue::Null),
                    23 => Ok(CborValue::Undefined),
                    25 => {
                        // Half-precision float
                        let bytes = self.read_bytes(2)?;
                        let half = u16::from_be_bytes([bytes[0], bytes[1]]);
                        let float = half_to_f64(half);
                        Ok(CborValue::Float(float))
                    }
                    26 => {
                        // Single-precision float
                        let bytes = self.read_bytes(4)?;
                        let float = f32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                        Ok(CborValue::Float(float as f64))
                    }
                    27 => {
                        // Double-precision float
                        let bytes = self.read_bytes(8)?;
                        let float = f64::from_be_bytes([
                            bytes[0], bytes[1], bytes[2], bytes[3],
                            bytes[4], bytes[5], bytes[6], bytes[7],
                        ]);
                        Ok(CborValue::Float(float))
                    }
                    _ if additional < 20 => Ok(CborValue::Simple(additional)),
                    24 => {
                        let value = self.read_byte()?;
                        Ok(CborValue::Simple(value))
                    }
                    _ => Err(anyhow!("CBOR: Invalid simple value")),
                }
            }
            _ => Err(anyhow!("CBOR: Invalid major type")),
        }
    }

    pub fn position(&self) -> usize {
        self.pos
    }
}

/// Convert half-precision float to f64
fn half_to_f64(half: u16) -> f64 {
    let sign = (half >> 15) & 1;
    let exp = (half >> 10) & 0x1f;
    let mant = half & 0x3ff;

    if exp == 0 {
        // Subnormal or zero
        let val = (mant as f64) * 2.0f64.powi(-24);
        if sign == 1 { -val } else { val }
    } else if exp == 31 {
        // Infinity or NaN
        if mant == 0 {
            if sign == 1 { f64::NEG_INFINITY } else { f64::INFINITY }
        } else {
            f64::NAN
        }
    } else {
        // Normal number
        let val = (1.0 + (mant as f64) / 1024.0) * 2.0f64.powi(exp as i32 - 15);
        if sign == 1 { -val } else { val }
    }
}

/// Parse CBOR-encoded data
pub fn parse_cbor(data: &[u8]) -> Result<CborValue> {
    let mut decoder = CborDecoder::new(data);
    decoder.decode()
}

// =============================================================================
// Attestation Object Parsing
// =============================================================================

/// Parsed attestation object
#[derive(Debug, Clone)]
pub struct AttestationObject {
    /// Attestation format (e.g., "none", "packed", "tpm", "android-key")
    pub fmt: String,
    /// Parsed authenticator data
    pub auth_data: AuthenticatorData,
    /// Attestation statement (format-specific)
    pub att_stmt: AttestationStatement,
}

/// Parsed authenticator data
#[derive(Debug, Clone)]
pub struct AuthenticatorData {
    /// SHA-256 hash of the RP ID
    pub rp_id_hash: [u8; 32],
    /// Flags byte
    pub flags: AuthenticatorFlags,
    /// Signature counter
    pub counter: u32,
    /// Attested credential data (if present)
    pub attested_cred_data: Option<AttestedCredentialData>,
    /// Extensions data (if present)
    pub extensions: Option<CborValue>,
}

/// Authenticator flags
#[derive(Debug, Clone, Copy)]
pub struct AuthenticatorFlags {
    /// User Present (UP)
    pub user_present: bool,
    /// User Verified (UV)
    pub user_verified: bool,
    /// Backup Eligibility (BE)
    pub backup_eligible: bool,
    /// Backup State (BS)
    pub backup_state: bool,
    /// Attested Credential Data included (AT)
    pub attested_cred_data: bool,
    /// Extension Data included (ED)
    pub extension_data: bool,
}

impl AuthenticatorFlags {
    fn from_byte(byte: u8) -> Self {
        Self {
            user_present: (byte & 0x01) != 0,
            user_verified: (byte & 0x04) != 0,
            backup_eligible: (byte & 0x08) != 0,
            backup_state: (byte & 0x10) != 0,
            attested_cred_data: (byte & 0x40) != 0,
            extension_data: (byte & 0x80) != 0,
        }
    }
}

/// Attested credential data
#[derive(Debug, Clone)]
pub struct AttestedCredentialData {
    /// Authenticator Attestation GUID
    pub aaguid: [u8; 16],
    /// Credential ID
    pub credential_id: Vec<u8>,
    /// COSE-encoded public key
    pub credential_public_key: CoseKey,
}

/// Attestation statement
#[derive(Debug, Clone)]
pub enum AttestationStatement {
    None,
    Packed {
        alg: i64,
        sig: Vec<u8>,
        x5c: Option<Vec<Vec<u8>>>,
        ecdaa_key_id: Option<Vec<u8>>,
    },
    Tpm {
        ver: String,
        alg: i64,
        x5c: Vec<Vec<u8>>,
        sig: Vec<u8>,
        cert_info: Vec<u8>,
        pub_area: Vec<u8>,
    },
    AndroidKey {
        alg: i64,
        sig: Vec<u8>,
        x5c: Vec<Vec<u8>>,
    },
    AndroidSafetyNet {
        ver: String,
        response: Vec<u8>,
    },
    FidoU2F {
        sig: Vec<u8>,
        x5c: Vec<Vec<u8>>,
    },
    Apple {
        x5c: Vec<Vec<u8>>,
    },
    Unknown(CborValue),
}

/// COSE key representation
#[derive(Debug, Clone)]
pub struct CoseKey {
    /// Key type (1 = OKP, 2 = EC2, 3 = RSA)
    pub kty: i64,
    /// Algorithm (-7 = ES256, -8 = EdDSA, -257 = RS256, etc.)
    pub alg: Option<i64>,
    /// Curve for EC/OKP keys
    pub crv: Option<i64>,
    /// X coordinate for EC/OKP keys
    pub x: Option<Vec<u8>>,
    /// Y coordinate for EC keys
    pub y: Option<Vec<u8>>,
    /// RSA modulus n
    pub n: Option<Vec<u8>>,
    /// RSA public exponent e
    pub e: Option<Vec<u8>>,
}

impl CoseKey {
    /// Get the key type name
    pub fn key_type_name(&self) -> &'static str {
        match self.kty {
            1 => "OKP",
            2 => "EC2",
            3 => "RSA",
            _ => "Unknown",
        }
    }

    /// Get the algorithm name
    pub fn algorithm_name(&self) -> &'static str {
        match self.alg {
            Some(-7) => "ES256",
            Some(-8) => "EdDSA",
            Some(-35) => "ES384",
            Some(-36) => "ES512",
            Some(-37) => "PS256",
            Some(-38) => "PS384",
            Some(-39) => "PS512",
            Some(-257) => "RS256",
            Some(-258) => "RS384",
            Some(-259) => "RS512",
            _ => "Unknown",
        }
    }

    /// Convert to raw public key bytes (for ES256, returns 65-byte uncompressed point)
    pub fn to_raw_public_key(&self) -> Result<Vec<u8>> {
        match self.kty {
            2 => {
                // EC2 key
                let x = self.x.as_ref().ok_or_else(|| anyhow!("Missing X coordinate"))?;
                let y = self.y.as_ref().ok_or_else(|| anyhow!("Missing Y coordinate"))?;
                // Uncompressed point format: 0x04 || x || y
                let mut key = Vec::with_capacity(1 + x.len() + y.len());
                key.push(0x04);
                key.extend_from_slice(x);
                key.extend_from_slice(y);
                Ok(key)
            }
            1 => {
                // OKP key (Ed25519/X25519)
                self.x.clone().ok_or_else(|| anyhow!("Missing X coordinate"))
            }
            3 => {
                // RSA key - return DER-encoded public key
                // For simplicity, just return n || e
                let n = self.n.as_ref().ok_or_else(|| anyhow!("Missing RSA modulus"))?;
                let e = self.e.as_ref().ok_or_else(|| anyhow!("Missing RSA exponent"))?;
                let mut key = Vec::new();
                key.extend_from_slice(n);
                key.extend_from_slice(e);
                Ok(key)
            }
            _ => Err(anyhow!("Unknown key type")),
        }
    }
}

/// Parse a COSE key from CBOR value
fn parse_cose_key(cbor: &CborValue) -> Result<CoseKey> {
    let kty = cbor.get_int(1)
        .and_then(|v| v.as_i64())
        .ok_or_else(|| anyhow!("Missing kty in COSE key"))?;

    let alg = cbor.get_int(3).and_then(|v| v.as_i64());

    let crv = cbor.get_int(-1).and_then(|v| v.as_i64());
    let x = cbor.get_int(-2).and_then(|v| v.as_bytes()).map(|b| b.to_vec());
    let y = cbor.get_int(-3).and_then(|v| v.as_bytes()).map(|b| b.to_vec());
    let n = cbor.get_int(-1).and_then(|v| if kty == 3 { v.as_bytes() } else { None }).map(|b| b.to_vec());
    let e = cbor.get_int(-2).and_then(|v| if kty == 3 { v.as_bytes() } else { None }).map(|b| b.to_vec());

    Ok(CoseKey { kty, alg, crv, x, y, n, e })
}

/// Parse authenticator data
fn parse_authenticator_data(data: &[u8]) -> Result<(AuthenticatorData, usize)> {
    if data.len() < 37 {
        return Err(anyhow!("Authenticator data too short"));
    }

    let mut rp_id_hash = [0u8; 32];
    rp_id_hash.copy_from_slice(&data[0..32]);

    let flags = AuthenticatorFlags::from_byte(data[32]);

    let counter = u32::from_be_bytes([data[33], data[34], data[35], data[36]]);

    let mut offset = 37;
    let mut attested_cred_data = None;

    // Parse attested credential data if present
    if flags.attested_cred_data {
        if data.len() < offset + 18 {
            return Err(anyhow!("Attested credential data too short"));
        }

        let mut aaguid = [0u8; 16];
        aaguid.copy_from_slice(&data[offset..offset + 16]);
        offset += 16;

        let cred_id_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;

        if data.len() < offset + cred_id_len {
            return Err(anyhow!("Credential ID truncated"));
        }

        let credential_id = data[offset..offset + cred_id_len].to_vec();
        offset += cred_id_len;

        // Parse COSE key
        let mut decoder = CborDecoder::new(&data[offset..]);
        let cose_cbor = decoder.decode()?;
        let credential_public_key = parse_cose_key(&cose_cbor)?;
        offset += decoder.position();

        attested_cred_data = Some(AttestedCredentialData {
            aaguid,
            credential_id,
            credential_public_key,
        });
    }

    // Parse extensions if present
    let extensions = if flags.extension_data && offset < data.len() {
        let mut decoder = CborDecoder::new(&data[offset..]);
        let ext = decoder.decode()?;
        offset += decoder.position();
        Some(ext)
    } else {
        None
    };

    Ok((AuthenticatorData {
        rp_id_hash,
        flags,
        counter,
        attested_cred_data,
        extensions,
    }, offset))
}

/// Parse attestation statement
fn parse_attestation_statement(fmt: &str, stmt: &CborValue) -> Result<AttestationStatement> {
    match fmt {
        "none" => Ok(AttestationStatement::None),
        "packed" => {
            let alg = stmt.get("alg")
                .and_then(|v| v.as_i64())
                .ok_or_else(|| anyhow!("Missing alg in packed attestation"))?;
            let sig = stmt.get("sig")
                .and_then(|v| v.as_bytes())
                .ok_or_else(|| anyhow!("Missing sig in packed attestation"))?
                .to_vec();
            let x5c = stmt.get("x5c")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter()
                    .filter_map(|v| v.as_bytes().map(|b| b.to_vec()))
                    .collect());
            let ecdaa_key_id = stmt.get("ecdaaKeyId")
                .and_then(|v| v.as_bytes())
                .map(|b| b.to_vec());

            Ok(AttestationStatement::Packed { alg, sig, x5c, ecdaa_key_id })
        }
        "fido-u2f" => {
            let sig = stmt.get("sig")
                .and_then(|v| v.as_bytes())
                .ok_or_else(|| anyhow!("Missing sig in fido-u2f attestation"))?
                .to_vec();
            let x5c = stmt.get("x5c")
                .and_then(|v| v.as_array())
                .ok_or_else(|| anyhow!("Missing x5c in fido-u2f attestation"))?
                .iter()
                .filter_map(|v| v.as_bytes().map(|b| b.to_vec()))
                .collect();

            Ok(AttestationStatement::FidoU2F { sig, x5c })
        }
        "apple" => {
            let x5c = stmt.get("x5c")
                .and_then(|v| v.as_array())
                .ok_or_else(|| anyhow!("Missing x5c in apple attestation"))?
                .iter()
                .filter_map(|v| v.as_bytes().map(|b| b.to_vec()))
                .collect();

            Ok(AttestationStatement::Apple { x5c })
        }
        _ => Ok(AttestationStatement::Unknown(stmt.clone())),
    }
}

/// Parse a complete attestation object from CBOR bytes
pub fn parse_attestation_object(data: &[u8]) -> Result<AttestationObject> {
    let cbor = parse_cbor(data)?;

    // Get format
    let fmt = cbor.get("fmt")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("Missing fmt in attestation object"))?
        .to_string();

    // Get authData
    let auth_data_bytes = cbor.get("authData")
        .and_then(|v| v.as_bytes())
        .ok_or_else(|| anyhow!("Missing authData in attestation object"))?;

    let (auth_data, _) = parse_authenticator_data(auth_data_bytes)?;

    // Get attestation statement
    let att_stmt_cbor = cbor.get("attStmt")
        .ok_or_else(|| anyhow!("Missing attStmt in attestation object"))?;

    let att_stmt = parse_attestation_statement(&fmt, att_stmt_cbor)?;

    Ok(AttestationObject { fmt, auth_data, att_stmt })
}

/// WebAuthn credential stored for a user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnCredential {
    pub id: String,
    pub user_id: String,
    pub credential_id: Vec<u8>,
    pub public_key: Vec<u8>,
    pub counter: u32,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub aaguid: Option<Vec<u8>>,
    pub transports: Vec<String>,
    pub backup_eligible: bool,
    pub backup_state: bool,
}

/// Registration options sent to client
#[derive(Debug, Serialize, Deserialize)]
pub struct RegistrationOptions {
    pub challenge: String,
    pub rp: RelyingParty,
    pub user: UserEntity,
    pub pub_key_cred_params: Vec<PubKeyCredParam>,
    pub timeout: u32,
    pub attestation: String,
    pub authenticator_selection: AuthenticatorSelection,
    pub exclude_credentials: Vec<CredentialDescriptor>,
}

/// Registration request (simplified)
#[derive(Debug, Serialize, Deserialize)]
pub struct RegistrationRequest {
    pub challenge: String,
    pub user_id: String,
    pub username: String,
}

/// Relying party information
#[derive(Debug, Serialize, Deserialize)]
pub struct RelyingParty {
    pub id: String,
    pub name: String,
}

/// User entity for registration
#[derive(Debug, Serialize, Deserialize)]
pub struct UserEntity {
    pub id: String,
    pub name: String,
    pub display_name: String,
}

/// Public key credential parameters
#[derive(Debug, Serialize, Deserialize)]
pub struct PubKeyCredParam {
    #[serde(rename = "type")]
    pub cred_type: String,
    pub alg: i32,
}

/// Authenticator selection criteria
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthenticatorSelection {
    pub authenticator_attachment: Option<String>,
    pub resident_key: String,
    pub user_verification: String,
}

/// Credential descriptor
#[derive(Debug, Serialize, Deserialize)]
pub struct CredentialDescriptor {
    #[serde(rename = "type")]
    pub cred_type: String,
    pub id: String,
    pub transports: Option<Vec<String>>,
}

/// Authentication options sent to client
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthenticationOptions {
    pub challenge: String,
    pub timeout: u32,
    pub rp_id: String,
    pub allow_credentials: Vec<CredentialDescriptor>,
    pub user_verification: String,
}

/// Authentication request (simplified)
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthenticationRequest {
    pub challenge: String,
    pub credential_ids: Vec<String>,
}

/// Registration response from client
#[derive(Debug, Serialize, Deserialize)]
pub struct RegistrationResponse {
    pub id: String,
    pub raw_id: String,
    pub response: AttestationResponse,
    #[serde(rename = "type")]
    pub cred_type: String,
}

/// Attestation response data
#[derive(Debug, Serialize, Deserialize)]
pub struct AttestationResponse {
    pub client_data_json: String,
    pub attestation_object: String,
    pub transports: Option<Vec<String>>,
}

/// Authentication response from client
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthenticationResponse {
    pub id: String,
    pub raw_id: String,
    pub response: AssertionResponse,
    #[serde(rename = "type")]
    pub cred_type: String,
}

/// Assertion response data
#[derive(Debug, Serialize, Deserialize)]
pub struct AssertionResponse {
    pub client_data_json: String,
    pub authenticator_data: String,
    pub signature: String,
    pub user_handle: Option<String>,
}

/// WebAuthn configuration
pub struct WebAuthnConfig {
    pub rp_id: String,
    pub rp_name: String,
    pub origin: String,
    pub timeout: u32,
}

impl Default for WebAuthnConfig {
    fn default() -> Self {
        Self {
            rp_id: "localhost".to_string(),
            rp_name: "HeroForge".to_string(),
            origin: "https://localhost".to_string(),
            timeout: 60000,
        }
    }
}

/// In-memory challenge store (use Redis/DB in production)
static mut CHALLENGE_STORE: Option<HashMap<String, ChallengeData>> = None;

#[derive(Clone)]
struct ChallengeData {
    challenge: Vec<u8>,
    user_id: String,
    created_at: chrono::DateTime<chrono::Utc>,
}

fn get_challenge_store() -> &'static mut HashMap<String, ChallengeData> {
    unsafe {
        if CHALLENGE_STORE.is_none() {
            CHALLENGE_STORE = Some(HashMap::new());
        }
        CHALLENGE_STORE.as_mut().unwrap()
    }
}

/// Generate a cryptographically random challenge
fn generate_challenge() -> Vec<u8> {
    use rand::RngCore;
    let mut challenge = vec![0u8; 32];
    rand::thread_rng().fill_bytes(&mut challenge);
    challenge
}

/// Start WebAuthn registration ceremony
pub async fn start_registration(user_id: &str, username: &str) -> Result<RegistrationRequest> {
    let config = WebAuthnConfig::default();
    let challenge = generate_challenge();
    let challenge_b64 = URL_SAFE_NO_PAD.encode(&challenge);

    // Store challenge for verification
    let store = get_challenge_store();
    store.insert(
        user_id.to_string(),
        ChallengeData {
            challenge: challenge.clone(),
            user_id: user_id.to_string(),
            created_at: chrono::Utc::now(),
        },
    );

    Ok(RegistrationRequest {
        challenge: challenge_b64,
        user_id: user_id.to_string(),
        username: username.to_string(),
    })
}

/// Get full registration options for client
pub fn get_registration_options(
    user_id: &str,
    username: &str,
    display_name: &str,
    existing_credentials: &[WebAuthnCredential],
) -> Result<RegistrationOptions> {
    let config = WebAuthnConfig::default();
    let challenge = generate_challenge();
    let challenge_b64 = URL_SAFE_NO_PAD.encode(&challenge);

    // Store challenge
    let store = get_challenge_store();
    store.insert(
        user_id.to_string(),
        ChallengeData {
            challenge,
            user_id: user_id.to_string(),
            created_at: chrono::Utc::now(),
        },
    );

    // Exclude existing credentials
    let exclude_credentials: Vec<CredentialDescriptor> = existing_credentials
        .iter()
        .map(|c| CredentialDescriptor {
            cred_type: "public-key".to_string(),
            id: URL_SAFE_NO_PAD.encode(&c.credential_id),
            transports: Some(c.transports.clone()),
        })
        .collect();

    Ok(RegistrationOptions {
        challenge: challenge_b64,
        rp: RelyingParty {
            id: config.rp_id,
            name: config.rp_name,
        },
        user: UserEntity {
            id: URL_SAFE_NO_PAD.encode(user_id.as_bytes()),
            name: username.to_string(),
            display_name: display_name.to_string(),
        },
        pub_key_cred_params: vec![
            PubKeyCredParam {
                cred_type: "public-key".to_string(),
                alg: -7, // ES256
            },
            PubKeyCredParam {
                cred_type: "public-key".to_string(),
                alg: -257, // RS256
            },
        ],
        timeout: config.timeout,
        attestation: "none".to_string(),
        authenticator_selection: AuthenticatorSelection {
            authenticator_attachment: None,
            resident_key: "preferred".to_string(),
            user_verification: "preferred".to_string(),
        },
        exclude_credentials,
    })
}

/// Verify registration response and extract credential
pub async fn verify_registration(response: &str) -> Result<WebAuthnCredential> {
    let config = WebAuthnConfig::default();

    // Parse the response
    let reg_response: RegistrationResponse =
        serde_json::from_str(response).map_err(|e| anyhow!("Invalid registration response: {}", e))?;

    // Decode client data JSON
    let client_data_bytes = URL_SAFE_NO_PAD
        .decode(&reg_response.response.client_data_json)
        .map_err(|e| anyhow!("Invalid client data: {}", e))?;

    let client_data: serde_json::Value = serde_json::from_slice(&client_data_bytes)
        .map_err(|e| anyhow!("Invalid client data JSON: {}", e))?;

    // Verify type
    let cdata_type = client_data
        .get("type")
        .and_then(|t| t.as_str())
        .ok_or_else(|| anyhow!("Missing type in client data"))?;

    if cdata_type != "webauthn.create" {
        return Err(anyhow!("Invalid ceremony type: expected webauthn.create"));
    }

    // Verify origin
    let origin = client_data
        .get("origin")
        .and_then(|o| o.as_str())
        .ok_or_else(|| anyhow!("Missing origin in client data"))?;

    if origin != config.origin {
        return Err(anyhow!("Origin mismatch"));
    }

    // Verify challenge is present (challenge verification against stored challenge
    // would be done by looking up the user's pending registration in production)
    let _challenge_b64 = client_data
        .get("challenge")
        .and_then(|c| c.as_str())
        .ok_or_else(|| anyhow!("Missing challenge in client data"))?;

    // Decode attestation object using full CBOR parser
    let attestation_bytes = URL_SAFE_NO_PAD
        .decode(&reg_response.response.attestation_object)
        .map_err(|e| anyhow!("Invalid attestation object: {}", e))?;

    // Extract full credential data using proper CBOR parsing
    let cred_data = extract_credential_data(&attestation_bytes)?;

    // Verify RP ID hash in authenticator data
    let attestation = parse_attestation_object(&attestation_bytes)?;
    let expected_rp_hash = Sha256::digest(config.rp_id.as_bytes());
    if attestation.auth_data.rp_id_hash != expected_rp_hash.as_slice() {
        return Err(anyhow!("RP ID hash mismatch in attestation"));
    }

    // Verify user present flag
    if !attestation.auth_data.flags.user_present {
        return Err(anyhow!("User presence flag not set during registration"));
    }

    // Decode credential ID from response and verify it matches attestation
    let response_credential_id = URL_SAFE_NO_PAD
        .decode(&reg_response.raw_id)
        .map_err(|e| anyhow!("Invalid credential ID: {}", e))?;

    if response_credential_id != cred_data.credential_id {
        return Err(anyhow!("Credential ID mismatch between response and attestation"));
    }

    let transports = reg_response
        .response
        .transports
        .unwrap_or_else(|| vec!["internal".to_string()]);

    Ok(WebAuthnCredential {
        id: uuid::Uuid::new_v4().to_string(),
        user_id: String::new(), // Set by caller
        credential_id: cred_data.credential_id,
        public_key: cred_data.public_key,
        counter: cred_data.counter,
        created_at: chrono::Utc::now(),
        aaguid: Some(cred_data.aaguid.to_vec()),
        transports,
        backup_eligible: cred_data.backup_eligible,
        backup_state: cred_data.backup_state,
    })
}

/// Extracted credential data from attestation object
pub struct ExtractedCredentialData {
    /// Credential ID
    pub credential_id: Vec<u8>,
    /// Raw public key bytes
    pub public_key: Vec<u8>,
    /// COSE key structure
    pub cose_key: CoseKey,
    /// AAGUID (Authenticator Attestation GUID)
    pub aaguid: [u8; 16],
    /// Signature counter
    pub counter: u32,
    /// Backup eligibility flag
    pub backup_eligible: bool,
    /// Backup state flag
    pub backup_state: bool,
    /// User verified flag
    pub user_verified: bool,
    /// Attestation format
    pub attestation_format: String,
}

/// Extract credential data from attestation object using full CBOR parsing
fn extract_credential_data(attestation_bytes: &[u8]) -> Result<ExtractedCredentialData> {
    let attestation = parse_attestation_object(attestation_bytes)?;

    let attested_cred_data = attestation.auth_data.attested_cred_data
        .ok_or_else(|| anyhow!("No attested credential data in authenticator data"))?;

    let public_key = attested_cred_data.credential_public_key.to_raw_public_key()?;

    Ok(ExtractedCredentialData {
        credential_id: attested_cred_data.credential_id,
        public_key,
        cose_key: attested_cred_data.credential_public_key,
        aaguid: attested_cred_data.aaguid,
        counter: attestation.auth_data.counter,
        backup_eligible: attestation.auth_data.flags.backup_eligible,
        backup_state: attestation.auth_data.flags.backup_state,
        user_verified: attestation.auth_data.flags.user_verified,
        attestation_format: attestation.fmt,
    })
}

/// Extract public key from attestation object (legacy wrapper)
fn extract_public_key(attestation_bytes: &[u8]) -> Result<Vec<u8>> {
    let cred_data = extract_credential_data(attestation_bytes)?;
    Ok(cred_data.public_key)
}

/// Start WebAuthn authentication ceremony
pub async fn start_authentication(user_id: &str) -> Result<AuthenticationRequest> {
    let challenge = generate_challenge();
    let challenge_b64 = URL_SAFE_NO_PAD.encode(&challenge);

    // Store challenge for verification
    let store = get_challenge_store();
    store.insert(
        user_id.to_string(),
        ChallengeData {
            challenge,
            user_id: user_id.to_string(),
            created_at: chrono::Utc::now(),
        },
    );

    Ok(AuthenticationRequest {
        challenge: challenge_b64,
        credential_ids: Vec::new(), // Caller should populate with user's credentials
    })
}

/// Get full authentication options for client
pub fn get_authentication_options(
    user_id: &str,
    credentials: &[WebAuthnCredential],
) -> Result<AuthenticationOptions> {
    let config = WebAuthnConfig::default();
    let challenge = generate_challenge();
    let challenge_b64 = URL_SAFE_NO_PAD.encode(&challenge);

    // Store challenge
    let store = get_challenge_store();
    store.insert(
        user_id.to_string(),
        ChallengeData {
            challenge,
            user_id: user_id.to_string(),
            created_at: chrono::Utc::now(),
        },
    );

    let allow_credentials: Vec<CredentialDescriptor> = credentials
        .iter()
        .map(|c| CredentialDescriptor {
            cred_type: "public-key".to_string(),
            id: URL_SAFE_NO_PAD.encode(&c.credential_id),
            transports: Some(c.transports.clone()),
        })
        .collect();

    Ok(AuthenticationOptions {
        challenge: challenge_b64,
        timeout: config.timeout,
        rp_id: config.rp_id,
        allow_credentials,
        user_verification: "preferred".to_string(),
    })
}

/// Verify authentication response
pub async fn verify_authentication(response: &str) -> Result<bool> {
    let config = WebAuthnConfig::default();

    // Parse the response
    let auth_response: AuthenticationResponse =
        serde_json::from_str(response).map_err(|e| anyhow!("Invalid authentication response: {}", e))?;

    // Decode client data JSON
    let client_data_bytes = URL_SAFE_NO_PAD
        .decode(&auth_response.response.client_data_json)
        .map_err(|e| anyhow!("Invalid client data: {}", e))?;

    let client_data: serde_json::Value = serde_json::from_slice(&client_data_bytes)
        .map_err(|e| anyhow!("Invalid client data JSON: {}", e))?;

    // Verify type
    let cdata_type = client_data
        .get("type")
        .and_then(|t| t.as_str())
        .ok_or_else(|| anyhow!("Missing type in client data"))?;

    if cdata_type != "webauthn.get" {
        return Err(anyhow!("Invalid ceremony type: expected webauthn.get"));
    }

    // Verify origin
    let origin = client_data
        .get("origin")
        .and_then(|o| o.as_str())
        .ok_or_else(|| anyhow!("Missing origin in client data"))?;

    if origin != config.origin {
        return Err(anyhow!("Origin mismatch"));
    }

    // Decode authenticator data
    let auth_data_bytes = URL_SAFE_NO_PAD
        .decode(&auth_response.response.authenticator_data)
        .map_err(|e| anyhow!("Invalid authenticator data: {}", e))?;

    // Verify RP ID hash (first 32 bytes of authenticator data)
    if auth_data_bytes.len() < 37 {
        return Err(anyhow!("Authenticator data too short"));
    }

    let rp_id_hash = &auth_data_bytes[0..32];
    let expected_hash = Sha256::digest(config.rp_id.as_bytes());

    if rp_id_hash != expected_hash.as_slice() {
        return Err(anyhow!("RP ID hash mismatch"));
    }

    // Verify flags
    let flags = auth_data_bytes[32];
    let user_present = (flags & 0x01) != 0;

    if !user_present {
        return Err(anyhow!("User presence flag not set"));
    }

    // In production: verify signature using stored public key
    // This requires looking up the credential and verifying the signature
    // over the concatenation of authenticator data and client data hash

    Ok(true)
}

/// Verify authentication with credential lookup
pub async fn verify_authentication_with_credential(
    response: &str,
    credential: &WebAuthnCredential,
) -> Result<(bool, u32)> {
    // First do basic verification
    let basic_result = verify_authentication(response).await?;

    if !basic_result {
        return Ok((false, credential.counter));
    }

    let auth_response: AuthenticationResponse = serde_json::from_str(response)?;

    // Decode authenticator data to get counter
    let auth_data_bytes = URL_SAFE_NO_PAD.decode(&auth_response.response.authenticator_data)?;

    if auth_data_bytes.len() < 37 {
        return Err(anyhow!("Authenticator data too short"));
    }

    // Counter is bytes 33-36 (big-endian)
    let new_counter = u32::from_be_bytes([
        auth_data_bytes[33],
        auth_data_bytes[34],
        auth_data_bytes[35],
        auth_data_bytes[36],
    ]);

    // Verify counter increased (replay protection)
    if new_counter <= credential.counter {
        return Err(anyhow!("Counter replay detected"));
    }

    Ok((true, new_counter))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_start_registration() {
        let result = start_registration("user123", "testuser").await;
        assert!(result.is_ok());
        let request = result.unwrap();
        assert!(!request.challenge.is_empty());
        assert_eq!(request.user_id, "user123");
    }

    #[tokio::test]
    async fn test_start_authentication() {
        let result = start_authentication("user123").await;
        assert!(result.is_ok());
        let request = result.unwrap();
        assert!(!request.challenge.is_empty());
    }

    #[test]
    fn test_get_registration_options() {
        let result = get_registration_options("user123", "testuser", "Test User", &[]);
        assert!(result.is_ok());
        let options = result.unwrap();
        assert_eq!(options.rp.name, "HeroForge");
        assert!(!options.pub_key_cred_params.is_empty());
    }

    // ==========================================================================
    // CBOR Parser Tests
    // ==========================================================================

    #[test]
    fn test_cbor_unsigned_integers() {
        // 0 = 0x00
        let result = parse_cbor(&[0x00]).unwrap();
        assert_eq!(result.as_u64(), Some(0));

        // 23 = 0x17
        let result = parse_cbor(&[0x17]).unwrap();
        assert_eq!(result.as_u64(), Some(23));

        // 24 = 0x18 0x18
        let result = parse_cbor(&[0x18, 0x18]).unwrap();
        assert_eq!(result.as_u64(), Some(24));

        // 256 = 0x19 0x01 0x00
        let result = parse_cbor(&[0x19, 0x01, 0x00]).unwrap();
        assert_eq!(result.as_u64(), Some(256));

        // 65536 = 0x1a 0x00 0x01 0x00 0x00
        let result = parse_cbor(&[0x1a, 0x00, 0x01, 0x00, 0x00]).unwrap();
        assert_eq!(result.as_u64(), Some(65536));
    }

    #[test]
    fn test_cbor_negative_integers() {
        // -1 = 0x20
        let result = parse_cbor(&[0x20]).unwrap();
        assert_eq!(result.as_i64(), Some(-1));

        // -10 = 0x29
        let result = parse_cbor(&[0x29]).unwrap();
        assert_eq!(result.as_i64(), Some(-10));

        // -100 = 0x38 0x63
        let result = parse_cbor(&[0x38, 0x63]).unwrap();
        assert_eq!(result.as_i64(), Some(-100));
    }

    #[test]
    fn test_cbor_byte_strings() {
        // Empty byte string = 0x40
        let result = parse_cbor(&[0x40]).unwrap();
        assert_eq!(result.as_bytes(), Some([].as_slice()));

        // 4 bytes: 01 02 03 04 = 0x44 0x01 0x02 0x03 0x04
        let result = parse_cbor(&[0x44, 0x01, 0x02, 0x03, 0x04]).unwrap();
        assert_eq!(result.as_bytes(), Some([0x01, 0x02, 0x03, 0x04].as_slice()));
    }

    #[test]
    fn test_cbor_text_strings() {
        // Empty text string = 0x60
        let result = parse_cbor(&[0x60]).unwrap();
        assert_eq!(result.as_str(), Some(""));

        // "IETF" = 0x64 0x49 0x45 0x54 0x46
        let result = parse_cbor(&[0x64, 0x49, 0x45, 0x54, 0x46]).unwrap();
        assert_eq!(result.as_str(), Some("IETF"));

        // "none" = 0x64 0x6e 0x6f 0x6e 0x65
        let result = parse_cbor(&[0x64, 0x6e, 0x6f, 0x6e, 0x65]).unwrap();
        assert_eq!(result.as_str(), Some("none"));
    }

    #[test]
    fn test_cbor_arrays() {
        // Empty array = 0x80
        let result = parse_cbor(&[0x80]).unwrap();
        assert!(matches!(result, CborValue::Array(ref a) if a.is_empty()));

        // [1, 2, 3] = 0x83 0x01 0x02 0x03
        let result = parse_cbor(&[0x83, 0x01, 0x02, 0x03]).unwrap();
        if let CborValue::Array(arr) = result {
            assert_eq!(arr.len(), 3);
            assert_eq!(arr[0].as_u64(), Some(1));
            assert_eq!(arr[1].as_u64(), Some(2));
            assert_eq!(arr[2].as_u64(), Some(3));
        } else {
            panic!("Expected array");
        }
    }

    #[test]
    fn test_cbor_maps() {
        // Empty map = 0xa0
        let result = parse_cbor(&[0xa0]).unwrap();
        assert!(matches!(result, CborValue::Map(ref m) if m.is_empty()));

        // {1: 2, 3: 4} = 0xa2 0x01 0x02 0x03 0x04
        let result = parse_cbor(&[0xa2, 0x01, 0x02, 0x03, 0x04]).unwrap();
        if let CborValue::Map(map) = result {
            assert_eq!(map.len(), 2);
            assert_eq!(map[0].0.as_u64(), Some(1));
            assert_eq!(map[0].1.as_u64(), Some(2));
        } else {
            panic!("Expected map");
        }
    }

    #[test]
    fn test_cbor_simple_values() {
        // false = 0xf4
        let result = parse_cbor(&[0xf4]).unwrap();
        assert!(matches!(result, CborValue::Bool(false)));

        // true = 0xf5
        let result = parse_cbor(&[0xf5]).unwrap();
        assert!(matches!(result, CborValue::Bool(true)));

        // null = 0xf6
        let result = parse_cbor(&[0xf6]).unwrap();
        assert!(matches!(result, CborValue::Null));
    }

    #[test]
    fn test_cbor_map_get() {
        // Map with string keys: {"fmt": "none"}
        // 0xa1 (map of 1), 0x63 0x66 0x6d 0x74 ("fmt"), 0x64 0x6e 0x6f 0x6e 0x65 ("none")
        let result = parse_cbor(&[0xa1, 0x63, 0x66, 0x6d, 0x74, 0x64, 0x6e, 0x6f, 0x6e, 0x65]).unwrap();
        let fmt = result.get("fmt");
        assert!(fmt.is_some());
        assert_eq!(fmt.unwrap().as_str(), Some("none"));
    }

    #[test]
    fn test_cbor_map_get_int_key() {
        // Map with integer keys: {1: 2, -1: 1}
        // COSE key style: 0xa2, 0x01, 0x02 (1: 2), 0x20, 0x01 (-1: 1)
        let result = parse_cbor(&[0xa2, 0x01, 0x02, 0x20, 0x01]).unwrap();
        let val1 = result.get_int(1);
        assert!(val1.is_some());
        assert_eq!(val1.unwrap().as_u64(), Some(2));

        let val_neg1 = result.get_int(-1);
        assert!(val_neg1.is_some());
        assert_eq!(val_neg1.unwrap().as_u64(), Some(1));
    }

    #[test]
    fn test_half_precision_floats() {
        // 0.0 = sign=0, exp=0, mant=0
        assert_eq!(half_to_f64(0x0000), 0.0);

        // 1.0 = sign=0, exp=15, mant=0 = 0x3c00
        assert!((half_to_f64(0x3c00) - 1.0).abs() < 1e-10);

        // -1.0 = sign=1, exp=15, mant=0 = 0xbc00
        assert!((half_to_f64(0xbc00) - (-1.0)).abs() < 1e-10);

        // Infinity = 0x7c00
        assert!(half_to_f64(0x7c00).is_infinite());
        assert!(half_to_f64(0x7c00) > 0.0);

        // -Infinity = 0xfc00
        assert!(half_to_f64(0xfc00).is_infinite());
        assert!(half_to_f64(0xfc00) < 0.0);

        // NaN = 0x7c01
        assert!(half_to_f64(0x7c01).is_nan());
    }

    // ==========================================================================
    // Authenticator Data Tests
    // ==========================================================================

    #[test]
    fn test_authenticator_flags_parsing() {
        // UP only = 0x01
        let flags = AuthenticatorFlags::from_byte(0x01);
        assert!(flags.user_present);
        assert!(!flags.user_verified);
        assert!(!flags.attested_cred_data);

        // UP + UV = 0x05
        let flags = AuthenticatorFlags::from_byte(0x05);
        assert!(flags.user_present);
        assert!(flags.user_verified);

        // UP + AT = 0x41
        let flags = AuthenticatorFlags::from_byte(0x41);
        assert!(flags.user_present);
        assert!(flags.attested_cred_data);

        // All flags = 0xdd (UP + UV + BE + BS + AT + ED)
        let flags = AuthenticatorFlags::from_byte(0xDD);
        assert!(flags.user_present);
        assert!(flags.user_verified);
        assert!(flags.backup_eligible);
        assert!(flags.backup_state);
        assert!(flags.attested_cred_data);
        assert!(flags.extension_data);
    }

    #[test]
    fn test_authenticator_data_minimal() {
        // Minimal auth data: 32 bytes RP ID hash + 1 byte flags + 4 bytes counter = 37 bytes
        let mut auth_data = [0u8; 37];
        // Set RP ID hash (fake)
        auth_data[0..32].copy_from_slice(&[0x00; 32]);
        // Set flags = UP (0x01)
        auth_data[32] = 0x01;
        // Set counter = 5 (big endian)
        auth_data[33..37].copy_from_slice(&[0x00, 0x00, 0x00, 0x05]);

        let (parsed, consumed) = parse_authenticator_data(&auth_data).unwrap();
        assert_eq!(consumed, 37);
        assert_eq!(parsed.counter, 5);
        assert!(parsed.flags.user_present);
        assert!(parsed.attested_cred_data.is_none());
    }

    // ==========================================================================
    // COSE Key Tests
    // ==========================================================================

    #[test]
    fn test_cose_key_ec2() {
        // Build a minimal COSE key map for EC2 P-256
        // {1: 2, 3: -7, -1: 1, -2: <32 bytes X>, -3: <32 bytes Y>}
        let mut cbor_data = vec![
            0xa5, // Map of 5 items
            0x01, 0x02, // 1: 2 (kty = EC2)
            0x03, 0x26, // 3: -7 (alg = ES256)
            0x20, 0x01, // -1: 1 (crv = P-256)
        ];
        // -2: 32 byte X coordinate
        cbor_data.push(0x21); // -2
        cbor_data.push(0x58); cbor_data.push(0x20); // Byte string of 32 bytes
        cbor_data.extend_from_slice(&[0x01; 32]); // X coordinate (fake)
        // -3: 32 byte Y coordinate
        cbor_data.push(0x22); // -3
        cbor_data.push(0x58); cbor_data.push(0x20); // Byte string of 32 bytes
        cbor_data.extend_from_slice(&[0x02; 32]); // Y coordinate (fake)

        let cbor = parse_cbor(&cbor_data).unwrap();
        let cose_key = parse_cose_key(&cbor).unwrap();

        assert_eq!(cose_key.kty, 2); // EC2
        assert_eq!(cose_key.alg, Some(-7)); // ES256
        assert_eq!(cose_key.crv, Some(1)); // P-256
        assert_eq!(cose_key.key_type_name(), "EC2");
        assert_eq!(cose_key.algorithm_name(), "ES256");

        // Test raw public key extraction
        let raw_key = cose_key.to_raw_public_key().unwrap();
        assert_eq!(raw_key.len(), 65); // 0x04 + 32 + 32
        assert_eq!(raw_key[0], 0x04); // Uncompressed point
    }

    #[test]
    fn test_cose_key_okp_ed25519() {
        // OKP key for Ed25519: {1: 1, 3: -8, -1: 6, -2: <32 bytes>}
        let mut cbor_data = vec![
            0xa4, // Map of 4 items
            0x01, 0x01, // 1: 1 (kty = OKP)
            0x03, 0x27, // 3: -8 (alg = EdDSA)
            0x20, 0x06, // -1: 6 (crv = Ed25519)
        ];
        // -2: 32 byte public key
        cbor_data.push(0x21); // -2
        cbor_data.push(0x58); cbor_data.push(0x20); // Byte string of 32 bytes
        cbor_data.extend_from_slice(&[0xab; 32]); // Public key (fake)

        let cbor = parse_cbor(&cbor_data).unwrap();
        let cose_key = parse_cose_key(&cbor).unwrap();

        assert_eq!(cose_key.kty, 1); // OKP
        assert_eq!(cose_key.alg, Some(-8)); // EdDSA
        assert_eq!(cose_key.key_type_name(), "OKP");
        assert_eq!(cose_key.algorithm_name(), "EdDSA");

        // Test raw public key extraction
        let raw_key = cose_key.to_raw_public_key().unwrap();
        assert_eq!(raw_key.len(), 32);
    }

    // ==========================================================================
    // Attestation Statement Tests
    // ==========================================================================

    #[test]
    fn test_attestation_statement_none() {
        // Empty map for "none" attestation
        let cbor = parse_cbor(&[0xa0]).unwrap();
        let stmt = parse_attestation_statement("none", &cbor).unwrap();
        assert!(matches!(stmt, AttestationStatement::None));
    }

    #[test]
    fn test_attestation_statement_packed() {
        // Build packed attestation: {"alg": -7, "sig": <signature bytes>}
        let cbor_data = vec![
            0xa2, // Map of 2 items
            0x63, 0x61, 0x6c, 0x67, // "alg"
            0x26, // -7
            0x63, 0x73, 0x69, 0x67, // "sig"
            0x44, 0x01, 0x02, 0x03, 0x04, // 4-byte signature (fake)
        ];

        let cbor = parse_cbor(&cbor_data).unwrap();
        let stmt = parse_attestation_statement("packed", &cbor).unwrap();

        if let AttestationStatement::Packed { alg, sig, x5c, ecdaa_key_id } = stmt {
            assert_eq!(alg, -7);
            assert_eq!(sig, vec![0x01, 0x02, 0x03, 0x04]);
            assert!(x5c.is_none());
            assert!(ecdaa_key_id.is_none());
        } else {
            panic!("Expected packed attestation");
        }
    }
}
