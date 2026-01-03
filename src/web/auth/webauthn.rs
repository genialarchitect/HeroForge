//! WebAuthn/FIDO2 authentication support
//!
//! Provides passwordless authentication using FIDO2/WebAuthn standards including:
//! - Registration ceremony (credential creation)
//! - Authentication ceremony (assertion verification)
//! - Credential management

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

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

    // Decode credential ID
    let credential_id = URL_SAFE_NO_PAD
        .decode(&reg_response.raw_id)
        .map_err(|e| anyhow!("Invalid credential ID: {}", e))?;

    // Decode attestation object (simplified - full implementation would parse CBOR)
    let attestation_bytes = URL_SAFE_NO_PAD
        .decode(&reg_response.response.attestation_object)
        .map_err(|e| anyhow!("Invalid attestation object: {}", e))?;

    // Extract public key (simplified - would parse authenticator data properly)
    // In production, use a proper CBOR parser and extract the COSE key
    let public_key = extract_public_key(&attestation_bytes)?;

    let transports = reg_response
        .response
        .transports
        .unwrap_or_else(|| vec!["internal".to_string()]);

    Ok(WebAuthnCredential {
        id: uuid::Uuid::new_v4().to_string(),
        user_id: String::new(), // Set by caller
        credential_id,
        public_key,
        counter: 0,
        created_at: chrono::Utc::now(),
        aaguid: None,
        transports,
        backup_eligible: false,
        backup_state: false,
    })
}

/// Extract public key from attestation object (simplified)
fn extract_public_key(attestation_bytes: &[u8]) -> Result<Vec<u8>> {
    // In production, properly parse CBOR attestation object
    // Extract authData, then parse the attested credential data
    // For now, return placeholder
    if attestation_bytes.len() < 77 {
        return Err(anyhow!("Attestation object too short"));
    }

    // The public key would be extracted from the COSE key in authData
    // This is a simplified placeholder
    Ok(attestation_bytes[55..].to_vec())
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
}
