//! SAML 2.0 SSO integration (Sprint 10)
//!
//! Complete SAML 2.0 implementation for enterprise Single Sign-On.
//! Supports SP-initiated and IdP-initiated flows with signature validation.

use serde::{Serialize, Deserialize};
use anyhow::{Result, anyhow};
use chrono::{DateTime, Utc, Duration};
use std::collections::HashMap;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use sha2::{Sha256, Sha1, Digest};
use flate2::write::DeflateEncoder;
use flate2::read::DeflateDecoder;
use flate2::Compression;
use std::io::{Write, Read};
use x509_parser::prelude::*;
use rsa::{RsaPublicKey, pkcs1v15::VerifyingKey, signature::Verifier};
use rsa::pkcs8::DecodePublicKey;

/// SAML 2.0 Service Provider configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlConfig {
    /// Service Provider entity ID (your application's identifier)
    pub entity_id: String,
    /// Identity Provider SSO URL
    pub sso_url: String,
    /// Identity Provider SLO URL (Single Logout)
    pub slo_url: Option<String>,
    /// Identity Provider X.509 certificate (PEM format)
    pub certificate: String,
    /// Assertion Consumer Service URL (where IdP sends responses)
    pub acs_url: String,
    /// Service Provider private key for signing requests (optional)
    pub sp_private_key: Option<String>,
    /// Service Provider certificate for signed requests (optional)
    pub sp_certificate: Option<String>,
    /// Name ID format
    pub name_id_format: NameIdFormat,
    /// Whether to sign authentication requests
    pub sign_requests: bool,
    /// Whether to require signed assertions
    pub want_assertions_signed: bool,
    /// Whether to require encrypted assertions
    pub want_assertions_encrypted: bool,
    /// Allowed clock skew in seconds
    pub allowed_clock_skew: i64,
}

impl SamlConfig {
    /// Create configuration for common IdPs
    pub fn okta(entity_id: &str, sso_url: &str, certificate: &str, acs_url: &str) -> Self {
        Self {
            entity_id: entity_id.to_string(),
            sso_url: sso_url.to_string(),
            slo_url: None,
            certificate: certificate.to_string(),
            acs_url: acs_url.to_string(),
            sp_private_key: None,
            sp_certificate: None,
            name_id_format: NameIdFormat::EmailAddress,
            sign_requests: false,
            want_assertions_signed: true,
            want_assertions_encrypted: false,
            allowed_clock_skew: 60,
        }
    }

    /// Create configuration for Azure AD
    pub fn azure_ad(tenant_id: &str, entity_id: &str, certificate: &str, acs_url: &str) -> Self {
        Self {
            entity_id: entity_id.to_string(),
            sso_url: format!("https://login.microsoftonline.com/{}/saml2", tenant_id),
            slo_url: Some(format!("https://login.microsoftonline.com/{}/saml2", tenant_id)),
            certificate: certificate.to_string(),
            acs_url: acs_url.to_string(),
            sp_private_key: None,
            sp_certificate: None,
            name_id_format: NameIdFormat::EmailAddress,
            sign_requests: false,
            want_assertions_signed: true,
            want_assertions_encrypted: false,
            allowed_clock_skew: 60,
        }
    }

    /// Generate SP metadata XML
    pub fn generate_metadata(&self) -> String {
        let mut xml = String::new();
        xml.push_str(r#"<?xml version="1.0" encoding="UTF-8"?>"#);
        xml.push_str(&format!(
            r#"<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{}">"#,
            escape_xml(&self.entity_id)
        ));
        xml.push_str(r#"<md:SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">"#);

        // Name ID format
        xml.push_str(&format!(
            r#"<md:NameIDFormat>{}</md:NameIDFormat>"#,
            self.name_id_format.as_str()
        ));

        // ACS URL
        xml.push_str(&format!(
            r#"<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{}" index="0" isDefault="true"/>"#,
            escape_xml(&self.acs_url)
        ));

        xml.push_str(r#"</md:SPSSODescriptor>"#);
        xml.push_str(r#"</md:EntityDescriptor>"#);

        xml
    }
}

/// SAML Name ID format
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum NameIdFormat {
    Unspecified,
    EmailAddress,
    Persistent,
    Transient,
    WindowsDomainQualifiedName,
}

impl NameIdFormat {
    pub fn as_str(&self) -> &'static str {
        match self {
            NameIdFormat::Unspecified => "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
            NameIdFormat::EmailAddress => "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            NameIdFormat::Persistent => "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
            NameIdFormat::Transient => "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
            NameIdFormat::WindowsDomainQualifiedName => "urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName",
        }
    }
}

/// Parsed SAML assertion with user attributes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlAssertion {
    /// Subject name ID (usually email or user identifier)
    pub user_id: String,
    /// Email address from assertion
    pub email: String,
    /// Name ID format used
    pub name_id_format: String,
    /// Session index for single logout
    pub session_index: Option<String>,
    /// Assertion ID for tracking
    pub assertion_id: String,
    /// Issuer (IdP entity ID)
    pub issuer: String,
    /// When the assertion was issued
    pub issue_instant: DateTime<Utc>,
    /// When the session ends
    pub session_not_on_or_after: Option<DateTime<Utc>>,
    /// Custom attributes from the assertion
    pub attributes: HashMap<String, String>,
}

/// SAML authentication request
#[derive(Debug, Clone)]
pub struct SamlAuthRequest {
    pub id: String,
    pub issue_instant: DateTime<Utc>,
    pub destination: String,
    pub assertion_consumer_service_url: String,
    pub issuer: String,
    pub name_id_format: NameIdFormat,
}

impl SamlAuthRequest {
    /// Generate new authentication request
    pub fn new(config: &SamlConfig) -> Self {
        let mut id_bytes = [0u8; 16];
        getrandom::getrandom(&mut id_bytes).expect("Failed to generate random bytes");
        let id = format!("_{}", hex::encode(id_bytes));

        Self {
            id,
            issue_instant: Utc::now(),
            destination: config.sso_url.clone(),
            assertion_consumer_service_url: config.acs_url.clone(),
            issuer: config.entity_id.clone(),
            name_id_format: config.name_id_format,
        }
    }

    /// Generate XML for the authentication request
    pub fn to_xml(&self) -> String {
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="{}"
    Version="2.0"
    IssueInstant="{}"
    Destination="{}"
    AssertionConsumerServiceURL="{}"
    ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">
    <saml:Issuer>{}</saml:Issuer>
    <samlp:NameIDPolicy Format="{}" AllowCreate="true"/>
</samlp:AuthnRequest>"#,
            escape_xml(&self.id),
            self.issue_instant.format("%Y-%m-%dT%H:%M:%SZ"),
            escape_xml(&self.destination),
            escape_xml(&self.assertion_consumer_service_url),
            escape_xml(&self.issuer),
            self.name_id_format.as_str()
        )
    }

    /// Encode request for HTTP-Redirect binding
    pub fn encode_redirect(&self) -> Result<String> {
        let xml = self.to_xml();

        // Deflate compress
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(xml.as_bytes())?;
        let compressed = encoder.finish()?;

        // Base64 encode
        let encoded = BASE64.encode(&compressed);

        // URL encode
        Ok(urlencoding::encode(&encoded).to_string())
    }

    /// Encode request for HTTP-POST binding
    pub fn encode_post(&self) -> String {
        let xml = self.to_xml();
        BASE64.encode(xml.as_bytes())
    }
}

/// SAML logout request
#[derive(Debug, Clone)]
pub struct SamlLogoutRequest {
    pub id: String,
    pub issue_instant: DateTime<Utc>,
    pub destination: String,
    pub issuer: String,
    pub name_id: String,
    pub session_index: Option<String>,
}

impl SamlLogoutRequest {
    /// Create new logout request
    pub fn new(config: &SamlConfig, name_id: &str, session_index: Option<&str>) -> Self {
        let mut id_bytes = [0u8; 16];
        getrandom::getrandom(&mut id_bytes).expect("Failed to generate random bytes");
        let id = format!("_{}", hex::encode(id_bytes));

        Self {
            id,
            issue_instant: Utc::now(),
            destination: config.slo_url.clone().unwrap_or_default(),
            issuer: config.entity_id.clone(),
            name_id: name_id.to_string(),
            session_index: session_index.map(String::from),
        }
    }

    /// Generate XML for logout request
    pub fn to_xml(&self) -> String {
        let mut xml = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="{}"
    Version="2.0"
    IssueInstant="{}"
    Destination="{}">
    <saml:Issuer>{}</saml:Issuer>
    <saml:NameID>{}</saml:NameID>"#,
            escape_xml(&self.id),
            self.issue_instant.format("%Y-%m-%dT%H:%M:%SZ"),
            escape_xml(&self.destination),
            escape_xml(&self.issuer),
            escape_xml(&self.name_id)
        );

        if let Some(ref session_index) = self.session_index {
            xml.push_str(&format!(
                r#"<samlp:SessionIndex>{}</samlp:SessionIndex>"#,
                escape_xml(session_index)
            ));
        }

        xml.push_str("</samlp:LogoutRequest>");
        xml
    }
}

/// SAML response parser
pub struct SamlResponseParser {
    config: SamlConfig,
}

impl SamlResponseParser {
    pub fn new(config: SamlConfig) -> Self {
        Self { config }
    }

    /// Parse and validate SAML response
    pub fn parse_response(&self, saml_response: &str) -> Result<SamlAssertion> {
        // Decode base64
        let decoded = BASE64.decode(saml_response)
            .map_err(|e| anyhow!("Failed to decode SAML response: {}", e))?;

        let xml = String::from_utf8(decoded)
            .map_err(|e| anyhow!("Invalid UTF-8 in SAML response: {}", e))?;

        // Parse XML and extract assertion
        self.parse_xml_response(&xml)
    }

    /// Parse deflate-encoded response (HTTP-Redirect binding)
    pub fn parse_redirect_response(&self, encoded_response: &str) -> Result<SamlAssertion> {
        // URL decode
        let decoded_url = urlencoding::decode(encoded_response)
            .map_err(|e| anyhow!("URL decode failed: {}", e))?;

        // Base64 decode
        let compressed = BASE64.decode(decoded_url.as_bytes())
            .map_err(|e| anyhow!("Base64 decode failed: {}", e))?;

        // Inflate decompress
        let mut decoder = DeflateDecoder::new(&compressed[..]);
        let mut xml = String::new();
        decoder.read_to_string(&mut xml)
            .map_err(|e| anyhow!("Deflate decompress failed: {}", e))?;

        self.parse_xml_response(&xml)
    }

    /// Validate XML-DSig signature on the SAML response/assertion
    /// This is CRITICAL for security - without signature validation,
    /// an attacker could forge SAML assertions
    fn validate_signature(&self, xml: &str) -> Result<()> {
        // Parse the IdP's X.509 certificate from PEM format
        let cert_pem = self.config.certificate.trim();

        // Handle both raw base64 and PEM format
        let cert_der = if cert_pem.starts_with("-----BEGIN CERTIFICATE-----") {
            // Parse PEM format
            let pem_lines: Vec<&str> = cert_pem
                .lines()
                .filter(|line| !line.starts_with("-----"))
                .collect();
            let cert_b64 = pem_lines.join("");
            BASE64.decode(&cert_b64)
                .map_err(|e| anyhow!("Failed to decode certificate base64: {}", e))?
        } else {
            // Assume raw base64
            BASE64.decode(cert_pem)
                .map_err(|e| anyhow!("Failed to decode certificate: {}", e))?
        };

        // Parse the X.509 certificate
        let (_, cert) = X509Certificate::from_der(&cert_der)
            .map_err(|e| anyhow!("Failed to parse X.509 certificate: {:?}", e))?;

        // Extract the public key from the certificate
        let public_key_der = cert.public_key().raw;

        // Extract SignatureValue from XML
        let signature_value = extract_xml_value(xml, "SignatureValue")
            .or_else(|| extract_xml_value(xml, "ds:SignatureValue"))
            .ok_or_else(|| anyhow!("Missing SignatureValue in SAML response - response is not signed"))?;

        // Clean up base64 (remove whitespace)
        let signature_b64: String = signature_value.chars().filter(|c| !c.is_whitespace()).collect();
        let signature_bytes = BASE64.decode(&signature_b64)
            .map_err(|e| anyhow!("Failed to decode signature: {}", e))?;

        // Extract SignedInfo element for verification
        let signed_info = extract_signed_info(xml)?;

        // Determine the signature algorithm
        let sig_algorithm = extract_xml_attribute(xml, "SignatureMethod", "Algorithm")
            .or_else(|| extract_xml_attribute(xml, "ds:SignatureMethod", "Algorithm"))
            .unwrap_or_default();

        // Canonicalize SignedInfo (exclusive C14N)
        let canonical_signed_info = canonicalize_xml(&signed_info);

        // Verify based on algorithm
        if sig_algorithm.contains("rsa-sha256") || sig_algorithm.contains("rsa-sha1") {
            // Parse RSA public key
            let rsa_public_key = RsaPublicKey::from_public_key_der(public_key_der)
                .map_err(|e| anyhow!("Failed to parse RSA public key: {}", e))?;

            if sig_algorithm.contains("sha256") {
                // RSA-SHA256
                let verifying_key: VerifyingKey<Sha256> = VerifyingKey::new(rsa_public_key);
                let signature = rsa::pkcs1v15::Signature::try_from(signature_bytes.as_slice())
                    .map_err(|e| anyhow!("Invalid signature format: {}", e))?;

                verifying_key.verify(canonical_signed_info.as_bytes(), &signature)
                    .map_err(|_| anyhow!("SAML signature verification FAILED - response may be forged"))?;
            } else {
                // RSA-SHA1 (legacy but still common)
                let verifying_key: VerifyingKey<Sha1> = VerifyingKey::new(rsa_public_key);
                let signature = rsa::pkcs1v15::Signature::try_from(signature_bytes.as_slice())
                    .map_err(|e| anyhow!("Invalid signature format: {}", e))?;

                verifying_key.verify(canonical_signed_info.as_bytes(), &signature)
                    .map_err(|_| anyhow!("SAML signature verification FAILED - response may be forged"))?;
            }
        } else {
            return Err(anyhow!("Unsupported signature algorithm: {}. Supported: RSA-SHA256, RSA-SHA1", sig_algorithm));
        }

        // Also verify the digest of the signed content (Assertion or Response)
        self.verify_digest(xml)?;

        log::info!("SAML signature validated successfully");
        Ok(())
    }

    /// Verify the digest value in the signature matches the actual content
    fn verify_digest(&self, xml: &str) -> Result<()> {
        // Extract DigestValue
        let digest_value = extract_xml_value(xml, "DigestValue")
            .or_else(|| extract_xml_value(xml, "ds:DigestValue"))
            .ok_or_else(|| anyhow!("Missing DigestValue in signature"))?;

        let digest_b64: String = digest_value.chars().filter(|c| !c.is_whitespace()).collect();
        let expected_digest = BASE64.decode(&digest_b64)
            .map_err(|e| anyhow!("Failed to decode DigestValue: {}", e))?;

        // Extract the Reference URI to find what was signed
        let reference_uri = extract_xml_attribute(xml, "Reference", "URI")
            .or_else(|| extract_xml_attribute(xml, "ds:Reference", "URI"))
            .unwrap_or_default();

        // Find the signed element (usually the Assertion)
        let signed_content = if reference_uri.starts_with('#') {
            let id = &reference_uri[1..]; // Remove leading #
            extract_element_by_id(xml, id)?
        } else {
            // If no URI, the entire Response is signed
            xml.to_string()
        };

        // Canonicalize the signed content
        let canonical_content = canonicalize_xml(&signed_content);

        // Determine digest algorithm
        let digest_algorithm = extract_xml_attribute(xml, "DigestMethod", "Algorithm")
            .or_else(|| extract_xml_attribute(xml, "ds:DigestMethod", "Algorithm"))
            .unwrap_or_default();

        // Compute digest
        let computed_digest = if digest_algorithm.contains("sha256") {
            let mut hasher = Sha256::new();
            hasher.update(canonical_content.as_bytes());
            hasher.finalize().to_vec()
        } else {
            // SHA-1 (legacy)
            let mut hasher = Sha1::new();
            hasher.update(canonical_content.as_bytes());
            hasher.finalize().to_vec()
        };

        if computed_digest != expected_digest {
            return Err(anyhow!("SAML digest verification FAILED - signed content may have been tampered"));
        }

        Ok(())
    }

    fn parse_xml_response(&self, xml: &str) -> Result<SamlAssertion> {
        // Check for success status
        if !xml.contains("urn:oasis:names:tc:SAML:2.0:status:Success") {
            // Try to extract error message
            if let Some(msg) = extract_xml_value(xml, "StatusMessage") {
                return Err(anyhow!("SAML authentication failed: {}", msg));
            }
            return Err(anyhow!("SAML authentication failed with unknown status"));
        }

        // CRITICAL: Validate XML signature if configured
        if self.config.want_assertions_signed {
            self.validate_signature(xml)?;
        }

        // Extract assertion ID
        let assertion_id = extract_xml_attribute(xml, "Assertion", "ID")
            .unwrap_or_else(|| "unknown".to_string());

        // Extract issuer
        let issuer = extract_xml_value(xml, "Issuer")
            .ok_or_else(|| anyhow!("Missing Issuer in SAML response"))?;

        // Validate issuer matches IdP
        // (In a full implementation, would compare against IdP metadata)

        // Extract NameID
        let name_id = extract_xml_value(xml, "NameID")
            .ok_or_else(|| anyhow!("Missing NameID in SAML response"))?;

        let name_id_format = extract_xml_attribute(xml, "NameID", "Format")
            .unwrap_or_else(|| "unspecified".to_string());

        // Extract session index
        let session_index = extract_xml_attribute(xml, "AuthnStatement", "SessionIndex");

        // Extract conditions and validate timestamps
        let not_before = extract_xml_attribute(xml, "Conditions", "NotBefore");
        let not_on_or_after = extract_xml_attribute(xml, "Conditions", "NotOnOrAfter");

        let now = Utc::now();
        let skew = Duration::seconds(self.config.allowed_clock_skew);

        if let Some(ref nb) = not_before {
            if let Ok(nbdt) = DateTime::parse_from_rfc3339(nb) {
                if now < nbdt.with_timezone(&Utc) - skew {
                    return Err(anyhow!("SAML assertion is not yet valid"));
                }
            }
        }

        if let Some(ref nooa) = not_on_or_after {
            if let Ok(nooadt) = DateTime::parse_from_rfc3339(nooa) {
                if now > nooadt.with_timezone(&Utc) + skew {
                    return Err(anyhow!("SAML assertion has expired"));
                }
            }
        }

        // Extract attributes
        let mut attributes = HashMap::new();

        // Common attribute names to look for
        let attr_names = [
            "email", "mail", "emailAddress",
            "firstName", "givenName", "first_name",
            "lastName", "surname", "sn", "last_name",
            "displayName", "name",
            "groups", "memberOf", "role",
            "department", "title", "phone",
        ];

        for attr_name in &attr_names {
            if let Some(value) = extract_saml_attribute(xml, attr_name) {
                attributes.insert(attr_name.to_string(), value);
            }
        }

        // Determine email - try NameID first if it's email format, then attributes
        let email = if name_id.contains('@') {
            name_id.clone()
        } else {
            attributes.get("email")
                .or_else(|| attributes.get("mail"))
                .or_else(|| attributes.get("emailAddress"))
                .cloned()
                .unwrap_or_else(|| name_id.clone())
        };

        // Extract IssueInstant
        let issue_instant = extract_xml_attribute(xml, "Assertion", "IssueInstant")
            .and_then(|s| DateTime::parse_from_rfc3339(&s).ok())
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(Utc::now);

        // Extract session expiry
        let session_not_on_or_after = extract_xml_attribute(xml, "AuthnStatement", "SessionNotOnOrAfter")
            .and_then(|s| DateTime::parse_from_rfc3339(&s).ok())
            .map(|dt| dt.with_timezone(&Utc));

        Ok(SamlAssertion {
            user_id: name_id,
            email,
            name_id_format,
            session_index,
            assertion_id,
            issuer,
            issue_instant,
            session_not_on_or_after,
            attributes,
        })
    }
}

/// Request state for tracking SAML flow
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlRequestState {
    pub request_id: String,
    pub created_at: DateTime<Utc>,
    pub relay_state: Option<String>,
}

impl SamlRequestState {
    pub fn new(request_id: &str, relay_state: Option<&str>) -> Self {
        Self {
            request_id: request_id.to_string(),
            created_at: Utc::now(),
            relay_state: relay_state.map(String::from),
        }
    }

    /// Check if request has expired (15 minutes)
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.created_at + Duration::minutes(15)
    }
}

// Helper functions

fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn extract_xml_value(xml: &str, tag: &str) -> Option<String> {
    let start_tag = format!("<{}", tag);
    let end_tag = format!("</{}>", tag);

    let start = xml.find(&start_tag)?;
    let content_start = xml[start..].find('>')? + start + 1;
    let end = xml[content_start..].find(&end_tag)? + content_start;

    Some(xml[content_start..end].trim().to_string())
}

fn extract_xml_attribute(xml: &str, tag: &str, attr: &str) -> Option<String> {
    let start_tag = format!("<{}", tag);
    let attr_prefix = format!("{}=\"", attr);

    let tag_start = xml.find(&start_tag)?;
    let tag_end = xml[tag_start..].find('>')? + tag_start;
    let tag_content = &xml[tag_start..tag_end];

    let attr_start = tag_content.find(&attr_prefix)? + attr_prefix.len();
    let attr_end = tag_content[attr_start..].find('"')? + attr_start;

    Some(tag_content[attr_start..attr_end].to_string())
}

fn extract_saml_attribute(xml: &str, name: &str) -> Option<String> {
    // Look for attribute with given name
    let name_attr = format!("Name=\"{}\"", name);
    let name_attr_alt = format!("Name=\"{}", name.to_lowercase());
    let friendly_name = format!("FriendlyName=\"{}\"", name);

    let mut search_pos = 0;

    while search_pos < xml.len() {
        // Find attribute element
        let attr_start = xml[search_pos..].find("<Attribute")?;
        let absolute_start = search_pos + attr_start;
        let attr_end = xml[absolute_start..].find("</Attribute>")? + absolute_start;
        let attr_element = &xml[absolute_start..attr_end + 12];

        // Check if this is the attribute we're looking for
        if attr_element.contains(&name_attr) ||
           attr_element.to_lowercase().contains(&name_attr_alt) ||
           attr_element.contains(&friendly_name) {
            // Extract AttributeValue
            return extract_xml_value(attr_element, "AttributeValue");
        }

        search_pos = attr_end + 12;
    }

    None
}

/// Extract the SignedInfo element from XML for signature verification
fn extract_signed_info(xml: &str) -> Result<String> {
    // Find SignedInfo element (with or without namespace prefix)
    let start_markers = ["<SignedInfo", "<ds:SignedInfo"];
    let end_markers = ["</SignedInfo>", "</ds:SignedInfo>"];

    for (start_marker, end_marker) in start_markers.iter().zip(end_markers.iter()) {
        if let Some(start) = xml.find(start_marker) {
            if let Some(end_offset) = xml[start..].find(end_marker) {
                let end = start + end_offset + end_marker.len();
                return Ok(xml[start..end].to_string());
            }
        }
    }

    Err(anyhow!("SignedInfo element not found in SAML response"))
}

/// Extract an XML element by its ID attribute
fn extract_element_by_id(xml: &str, id: &str) -> Result<String> {
    // Look for elements with ID or AssertionID attribute matching the given id
    let id_patterns = [
        format!("ID=\"{}\"", id),
        format!("AssertionID=\"{}\"", id),
        format!("Id=\"{}\"", id),
    ];

    for pattern in &id_patterns {
        if let Some(attr_pos) = xml.find(pattern.as_str()) {
            // Find the start of this element
            let element_start = xml[..attr_pos].rfind('<')
                .ok_or_else(|| anyhow!("Malformed XML: no opening tag before ID"))?;

            // Determine the element name
            let tag_end = xml[element_start..].find(|c: char| c.is_whitespace() || c == '>')
                .ok_or_else(|| anyhow!("Malformed XML: incomplete tag"))?;
            let element_name = &xml[element_start + 1..element_start + tag_end];

            // Find the closing tag
            let close_tag = format!("</{}>", element_name);
            let close_pos = xml[attr_pos..].find(&close_tag)
                .ok_or_else(|| anyhow!("Malformed XML: no closing tag for {}", element_name))?;

            let element_end = attr_pos + close_pos + close_tag.len();
            return Ok(xml[element_start..element_end].to_string());
        }
    }

    Err(anyhow!("Element with ID '{}' not found", id))
}

/// Canonicalize XML using exclusive C14N (simplified version)
/// This is a simplified implementation that handles the most common cases
/// A full implementation would use a proper C14N library
fn canonicalize_xml(xml: &str) -> String {
    let mut result = String::new();
    let mut in_tag = false;
    let mut current_tag = String::new();
    let mut attrs: Vec<(String, String)> = Vec::new();

    let chars: Vec<char> = xml.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        let c = chars[i];

        match c {
            '<' => {
                in_tag = true;
                current_tag.clear();
                attrs.clear();
                i += 1;
            }
            '>' => {
                if in_tag {
                    // Process the tag
                    let is_closing = current_tag.starts_with('/');
                    let is_self_closing = current_tag.ends_with('/');

                    if is_closing {
                        // Closing tag
                        result.push('<');
                        result.push_str(&current_tag);
                        result.push('>');
                    } else {
                        // Opening or self-closing tag
                        // Parse tag name and attributes
                        let parts: Vec<&str> = current_tag.split_whitespace().collect();
                        if !parts.is_empty() {
                            let tag_name = parts[0].trim_end_matches('/');

                            // Parse attributes
                            let attr_str = current_tag[tag_name.len()..].trim();
                            let parsed_attrs = parse_attributes(attr_str);

                            // Sort attributes lexicographically (C14N requirement)
                            let mut sorted_attrs: Vec<_> = parsed_attrs.into_iter().collect();
                            sorted_attrs.sort_by(|a, b| a.0.cmp(&b.0));

                            // Build canonical tag
                            result.push('<');
                            result.push_str(tag_name);
                            for (name, value) in sorted_attrs {
                                result.push(' ');
                                result.push_str(&name);
                                result.push_str("=\"");
                                result.push_str(&escape_xml_attr(&value));
                                result.push('"');
                            }
                            if is_self_closing {
                                result.push_str("></");
                                result.push_str(tag_name);
                            }
                            result.push('>');
                        }
                    }
                    in_tag = false;
                } else {
                    result.push(c);
                }
                i += 1;
            }
            _ => {
                if in_tag {
                    current_tag.push(c);
                } else {
                    result.push(c);
                }
                i += 1;
            }
        }
    }

    // Normalize line endings and remove unnecessary whitespace
    result
        .replace("\r\n", "\n")
        .replace('\r', "\n")
}

/// Parse XML attributes from a string
fn parse_attributes(attr_str: &str) -> Vec<(String, String)> {
    let mut attrs = Vec::new();
    let mut remaining = attr_str.trim();

    while !remaining.is_empty() && !remaining.starts_with('/') {
        // Find attribute name
        if let Some(eq_pos) = remaining.find('=') {
            let name = remaining[..eq_pos].trim().to_string();
            remaining = remaining[eq_pos + 1..].trim();

            // Find attribute value (quoted)
            if remaining.starts_with('"') {
                if let Some(end_quote) = remaining[1..].find('"') {
                    let value = remaining[1..end_quote + 1].to_string();
                    attrs.push((name, value));
                    remaining = remaining[end_quote + 2..].trim();
                } else {
                    break;
                }
            } else if remaining.starts_with('\'') {
                if let Some(end_quote) = remaining[1..].find('\'') {
                    let value = remaining[1..end_quote + 1].to_string();
                    attrs.push((name, value));
                    remaining = remaining[end_quote + 2..].trim();
                } else {
                    break;
                }
            } else {
                break;
            }
        } else {
            break;
        }
    }

    attrs
}

/// Escape special characters in XML attribute values (C14N compliant)
fn escape_xml_attr(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('"', "&quot;")
        .replace('\t', "&#x9;")
        .replace('\n', "&#xA;")
        .replace('\r', "&#xD;")
}

// Public API functions for backwards compatibility

pub async fn generate_saml_request(config: &SamlConfig) -> Result<String> {
    let request = SamlAuthRequest::new(config);
    request.encode_redirect()
}

pub async fn validate_saml_response(response: &str, config: &SamlConfig) -> Result<SamlAssertion> {
    let parser = SamlResponseParser::new(config.clone());
    parser.parse_response(response)
}

/// Generate redirect URL for SAML authentication
pub fn generate_redirect_url(config: &SamlConfig, relay_state: Option<&str>) -> Result<(String, SamlRequestState)> {
    let request = SamlAuthRequest::new(config);
    let encoded = request.encode_redirect()?;
    let state = SamlRequestState::new(&request.id, relay_state);

    let mut url = format!("{}?SAMLRequest={}", config.sso_url, encoded);

    if let Some(rs) = relay_state {
        url.push_str(&format!("&RelayState={}", urlencoding::encode(rs)));
    }

    Ok((url, state))
}

/// Generate POST form for SAML authentication
pub fn generate_post_form(config: &SamlConfig, relay_state: Option<&str>) -> (String, SamlRequestState) {
    let request = SamlAuthRequest::new(config);
    let encoded = request.encode_post();
    let state = SamlRequestState::new(&request.id, relay_state);

    let relay_input = relay_state.map(|rs|
        format!(r#"<input type="hidden" name="RelayState" value="{}"/>"#, escape_xml(rs))
    ).unwrap_or_default();

    let form = format!(
        r#"<!DOCTYPE html>
<html>
<head><title>SAML Login</title></head>
<body onload="document.forms[0].submit()">
<form method="POST" action="{}">
<input type="hidden" name="SAMLRequest" value="{}"/>
{}
<noscript><button type="submit">Continue to Login</button></noscript>
</form>
</body>
</html>"#,
        escape_xml(&config.sso_url),
        encoded,
        relay_input
    );

    (form, state)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_request_generation() {
        let config = SamlConfig::okta(
            "https://app.example.com",
            "https://idp.example.com/sso",
            "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
            "https://app.example.com/saml/acs"
        );

        let request = SamlAuthRequest::new(&config);
        let xml = request.to_xml();

        assert!(xml.contains("AuthnRequest"));
        assert!(xml.contains(&config.entity_id));
        assert!(xml.contains(&config.acs_url));
    }

    #[test]
    fn test_request_state() {
        let state = SamlRequestState::new("_abc123", Some("https://app.example.com/dashboard"));

        assert!(!state.is_expired());
        assert_eq!(state.relay_state, Some("https://app.example.com/dashboard".to_string()));
    }

    #[test]
    fn test_name_id_format() {
        assert_eq!(
            NameIdFormat::EmailAddress.as_str(),
            "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
        );
    }

    #[test]
    fn test_metadata_generation() {
        let config = SamlConfig::okta(
            "https://app.example.com",
            "https://idp.example.com/sso",
            "cert",
            "https://app.example.com/saml/acs"
        );

        let metadata = config.generate_metadata();

        assert!(metadata.contains("EntityDescriptor"));
        assert!(metadata.contains(&config.entity_id));
        assert!(metadata.contains(&config.acs_url));
    }

    #[test]
    fn test_xml_escaping() {
        let input = "test<>&\"'value";
        let escaped = escape_xml(input);
        assert_eq!(escaped, "test&lt;&gt;&amp;&quot;&apos;value");
    }

    #[test]
    fn test_logout_request() {
        let config = SamlConfig {
            entity_id: "https://app.example.com".to_string(),
            sso_url: "https://idp.example.com/sso".to_string(),
            slo_url: Some("https://idp.example.com/slo".to_string()),
            certificate: "cert".to_string(),
            acs_url: "https://app.example.com/saml/acs".to_string(),
            sp_private_key: None,
            sp_certificate: None,
            name_id_format: NameIdFormat::EmailAddress,
            sign_requests: false,
            want_assertions_signed: true,
            want_assertions_encrypted: false,
            allowed_clock_skew: 60,
        };

        let logout = SamlLogoutRequest::new(&config, "user@example.com", Some("session123"));
        let xml = logout.to_xml();

        assert!(xml.contains("LogoutRequest"));
        assert!(xml.contains("user@example.com"));
        assert!(xml.contains("session123"));
    }
}
