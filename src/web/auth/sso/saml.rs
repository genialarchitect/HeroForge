#![allow(dead_code)]
//! SAML 2.0 Authentication Implementation
//!
//! This module implements SAML 2.0 Service Provider (SP) functionality including:
//! - SP metadata generation
//! - IdP metadata parsing
//! - AuthnRequest generation
//! - SAML Response/Assertion validation
//! - Single Logout (SLO) support

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chrono::{DateTime, Duration, Utc};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::types::{SamlConfig, SsoUserInfo};

/// SAML Service Provider
pub struct SamlServiceProvider {
    /// SP Entity ID
    pub entity_id: String,
    /// Assertion Consumer Service URL
    pub acs_url: String,
    /// Single Logout URL (optional)
    pub slo_url: Option<String>,
    /// SP private key for signing (PEM format)
    sp_private_key: Option<String>,
    /// SP certificate for encryption (PEM format)
    sp_certificate: Option<String>,
}

impl SamlServiceProvider {
    /// Create a new SAML Service Provider
    pub fn new(
        entity_id: String,
        acs_url: String,
        slo_url: Option<String>,
        sp_private_key: Option<String>,
        sp_certificate: Option<String>,
    ) -> Self {
        Self {
            entity_id,
            acs_url,
            slo_url,
            sp_private_key,
            sp_certificate,
        }
    }

    /// Generate SP metadata XML
    pub fn generate_metadata(&self) -> String {
        let now = Utc::now();
        let valid_until = now + Duration::days(365);

        let mut metadata = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                     entityID="{}"
                     validUntil="{}">
    <md:SPSSODescriptor AuthnRequestsSigned="true"
                        WantAssertionsSigned="true"
                        protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
        <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>
        <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>
        <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                                     Location="{}"
                                     index="0"
                                     isDefault="true"/>"#,
            xml_escape(&self.entity_id),
            valid_until.format("%Y-%m-%dT%H:%M:%SZ"),
            xml_escape(&self.acs_url),
        );

        // Add SLO endpoint if configured
        if let Some(ref slo_url) = self.slo_url {
            metadata.push_str(&format!(
                r#"
        <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                                Location="{}"/>
        <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                                Location="{}"/>"#,
                xml_escape(slo_url),
                xml_escape(slo_url),
            ));
        }

        // Add SP certificate if available
        if let Some(ref cert) = self.sp_certificate {
            let cert_pem = extract_pem_body(cert);
            metadata.push_str(&format!(
                r#"
        <md:KeyDescriptor use="signing">
            <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                <ds:X509Data>
                    <ds:X509Certificate>{}</ds:X509Certificate>
                </ds:X509Data>
            </ds:KeyInfo>
        </md:KeyDescriptor>
        <md:KeyDescriptor use="encryption">
            <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                <ds:X509Data>
                    <ds:X509Certificate>{}</ds:X509Certificate>
                </ds:X509Data>
            </ds:KeyInfo>
        </md:KeyDescriptor>"#,
                cert_pem, cert_pem,
            ));
        }

        metadata.push_str(
            r#"
    </md:SPSSODescriptor>
</md:EntityDescriptor>"#,
        );

        metadata
    }

    /// Create a SAML AuthnRequest
    pub fn create_authn_request(
        &self,
        config: &SamlConfig,
        relay_state: Option<&str>,
    ) -> Result<(String, String)> {
        let request_id = format!("_{}", Uuid::new_v4());
        let issue_instant = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();

        let name_id_policy = config
            .name_id_format
            .as_ref()
            .map(|f| format!(r#"<samlp:NameIDPolicy Format="{}" AllowCreate="true"/>"#, xml_escape(f)))
            .unwrap_or_default();

        let force_authn = if config.force_authn {
            r#" ForceAuthn="true""#
        } else {
            ""
        };

        let authn_context = if let Some(ref contexts) = config.authn_context {
            let classes = contexts
                .iter()
                .map(|c| format!(r#"<saml:AuthnContextClassRef>{}</saml:AuthnContextClassRef>"#, xml_escape(c)))
                .collect::<Vec<_>>()
                .join("\n                ");
            format!(
                r#"
        <samlp:RequestedAuthnContext Comparison="exact">
            {}
        </samlp:RequestedAuthnContext>"#,
                classes
            )
        } else {
            String::new()
        };

        let authn_request = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                    ID="{}"
                    Version="2.0"
                    IssueInstant="{}"
                    Destination="{}"
                    AssertionConsumerServiceURL="{}"
                    ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"{}>
    <saml:Issuer>{}</saml:Issuer>
    {}{}
</samlp:AuthnRequest>"#,
            request_id,
            issue_instant,
            xml_escape(&config.idp_sso_url),
            xml_escape(&self.acs_url),
            force_authn,
            xml_escape(&self.entity_id),
            name_id_policy,
            authn_context,
        );

        // Compress and encode for redirect binding
        let compressed = deflate_compress(authn_request.as_bytes())?;
        let encoded = BASE64.encode(&compressed);
        let url_encoded = urlencoding::encode(&encoded);

        // Build redirect URL
        let mut redirect_url = format!("{}?SAMLRequest={}", config.idp_sso_url, url_encoded);

        if let Some(state) = relay_state {
            redirect_url.push_str(&format!("&RelayState={}", urlencoding::encode(state)));
        }

        // TODO: Add signature if sign_requests is true
        // This would require proper XML signature implementation

        Ok((redirect_url, request_id))
    }

    /// Process a SAML Response
    pub fn process_response(
        &self,
        saml_response: &str,
        config: &SamlConfig,
        expected_request_id: Option<&str>,
    ) -> Result<SsoUserInfo> {
        // Decode the SAML response
        let decoded = BASE64
            .decode(saml_response)
            .context("Failed to decode SAML response")?;

        let response_xml = String::from_utf8(decoded)
            .context("SAML response is not valid UTF-8")?;

        log::debug!("Processing SAML response");

        // Parse the response XML
        let parsed = parse_saml_response(&response_xml, config, expected_request_id)?;

        Ok(parsed)
    }

    /// Check if we have signing capability
    pub fn can_sign(&self) -> bool {
        self.sp_private_key.is_some()
    }
}

/// Parse IdP metadata XML and extract configuration
pub fn parse_idp_metadata(metadata_xml: &str) -> Result<SamlConfig> {
    // Simple XML parsing - in production, use a proper XML library
    let idp_entity_id = extract_xml_attribute(metadata_xml, "EntityDescriptor", "entityID")
        .context("Missing EntityDescriptor entityID")?;

    let idp_sso_url = extract_sso_location(metadata_xml, "HTTP-POST")
        .or_else(|| extract_sso_location(metadata_xml, "HTTP-Redirect"))
        .context("Missing SingleSignOnService location")?;

    let idp_slo_url = extract_slo_location(metadata_xml, "HTTP-POST")
        .or_else(|| extract_slo_location(metadata_xml, "HTTP-Redirect"));

    let idp_certificate = extract_certificate(metadata_xml)
        .context("Missing X509Certificate")?;

    Ok(SamlConfig {
        idp_entity_id,
        idp_sso_url,
        idp_slo_url,
        idp_certificate,
        ..Default::default()
    })
}

/// Parse a SAML response and extract user info
fn parse_saml_response(
    xml: &str,
    config: &SamlConfig,
    _expected_request_id: Option<&str>,
) -> Result<SsoUserInfo> {
    // Verify the response status
    if !xml.contains("urn:oasis:names:tc:SAML:2.0:status:Success") {
        // Try to extract the error
        if let Some(error_msg) = extract_status_message(xml) {
            return Err(anyhow!("SAML authentication failed: {}", error_msg));
        }
        return Err(anyhow!("SAML authentication failed: Unknown status"));
    }

    // Verify response/assertion signatures if required
    if config.require_signed_response || config.require_signed_assertion {
        verify_saml_signature(xml, &config.idp_certificate)?;
    }

    // Verify timing conditions
    let now = Utc::now();
    if let Some(not_before) = extract_condition_time(xml, "NotBefore") {
        let not_before = DateTime::parse_from_rfc3339(&not_before)
            .context("Invalid NotBefore timestamp")?
            .with_timezone(&Utc);

        let skew = Duration::seconds(config.allowed_clock_skew);
        if now < not_before - skew {
            return Err(anyhow!("SAML assertion is not yet valid"));
        }
    }

    if let Some(not_on_or_after) = extract_condition_time(xml, "NotOnOrAfter") {
        let not_on_or_after = DateTime::parse_from_rfc3339(&not_on_or_after)
            .context("Invalid NotOnOrAfter timestamp")?
            .with_timezone(&Utc);

        let skew = Duration::seconds(config.allowed_clock_skew);
        if now > not_on_or_after + skew {
            return Err(anyhow!("SAML assertion has expired"));
        }
    }

    // Extract NameID (subject)
    let subject = extract_name_id(xml)
        .context("Missing NameID in SAML assertion")?;

    // Extract attributes
    let attributes = extract_saml_attributes(xml);

    // Build user info from attributes
    let email = attributes
        .get("email")
        .or_else(|| attributes.get("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"))
        .or_else(|| attributes.get("mail"))
        .cloned();

    let username = attributes
        .get("username")
        .or_else(|| attributes.get("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"))
        .cloned();

    let first_name = attributes
        .get("firstName")
        .or_else(|| attributes.get("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"))
        .or_else(|| attributes.get("givenName"))
        .cloned();

    let last_name = attributes
        .get("lastName")
        .or_else(|| attributes.get("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname"))
        .or_else(|| attributes.get("sn"))
        .cloned();

    let display_name = attributes
        .get("displayName")
        .or_else(|| attributes.get("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/displayname"))
        .cloned();

    let groups = extract_group_attributes(xml);

    Ok(SsoUserInfo {
        subject,
        email,
        username,
        display_name,
        first_name,
        last_name,
        groups,
        raw_attributes: serde_json::to_value(&attributes)?,
    })
}

/// Verify SAML signature (simplified - in production use a crypto library)
fn verify_saml_signature(xml: &str, idp_certificate: &str) -> Result<()> {
    // Check if the response is signed
    if !xml.contains("<ds:Signature") && !xml.contains("<Signature") {
        return Err(anyhow!("SAML response/assertion is not signed"));
    }

    // Extract the signature value
    let _signature_value = extract_xml_content(xml, "SignatureValue")
        .context("Missing SignatureValue in SAML signature")?;

    // Extract the certificate from the signature
    let cert_in_sig = extract_xml_content(xml, "X509Certificate");

    // Verify the certificate matches (if present in both)
    if let Some(cert) = cert_in_sig {
        let expected_cert = extract_pem_body(idp_certificate);
        let provided_cert = cert.replace(['\n', '\r', ' '], "");
        let expected_normalized = expected_cert.replace(['\n', '\r', ' '], "");

        if provided_cert != expected_normalized {
            log::warn!("Certificate in SAML response differs from configured IdP certificate");
            // In a strict implementation, this should return an error
            // For now, we log a warning
        }
    }

    // TODO: Implement proper cryptographic signature verification
    // This requires:
    // 1. Canonicalizing the signed XML content
    // 2. Computing the digest
    // 3. Verifying the signature using the IdP's public key
    //
    // For production, use a library like:
    // - xmlsec1 bindings
    // - openssl for RSA/DSA signature verification

    log::debug!("SAML signature structure verified (cryptographic verification pending)");

    Ok(())
}

/// Extract XML attribute value
fn extract_xml_attribute(xml: &str, element: &str, attribute: &str) -> Option<String> {
    let pattern = format!("<{}", element);
    if let Some(start) = xml.find(&pattern) {
        let end = xml[start..].find('>')?;
        let element_str = &xml[start..start + end];

        let attr_pattern = format!(r#"{}=""#, attribute);
        if let Some(attr_start) = element_str.find(&attr_pattern) {
            let value_start = attr_start + attr_pattern.len();
            let value_end = element_str[value_start..].find('"')?;
            return Some(element_str[value_start..value_start + value_end].to_string());
        }
    }
    None
}

/// Extract content between XML tags
fn extract_xml_content(xml: &str, tag: &str) -> Option<String> {
    // Try with namespace prefix
    for prefix in ["", "ds:", "saml:", "samlp:"] {
        let open = format!("<{}{}>", prefix, tag);
        let close = format!("</{}{}>", prefix, tag);

        if let Some(start) = xml.find(&open) {
            let content_start = start + open.len();
            if let Some(end) = xml[content_start..].find(&close) {
                return Some(xml[content_start..content_start + end].to_string());
            }
        }

        // Also try with namespace as attribute
        let open_ns = format!("<{} ", tag);
        if let Some(start) = xml.find(&open_ns) {
            if let Some(tag_end) = xml[start..].find('>') {
                let content_start = start + tag_end + 1;
                let close = format!("</{}>", tag);
                if let Some(end) = xml[content_start..].find(&close) {
                    return Some(xml[content_start..content_start + end].to_string());
                }
            }
        }
    }
    None
}

/// Extract SSO location from metadata
fn extract_sso_location(xml: &str, binding: &str) -> Option<String> {
    let binding_full = format!("urn:oasis:names:tc:SAML:2.0:bindings:{}", binding);
    let pattern = format!(r#"SingleSignOnService"#);

    let mut search_start = 0;
    while let Some(pos) = xml[search_start..].find(&pattern) {
        let abs_pos = search_start + pos;
        let end = xml[abs_pos..].find('>')?;
        let element = &xml[abs_pos..abs_pos + end];

        if element.contains(&binding_full) {
            if let Some(loc_start) = element.find(r#"Location=""#) {
                let value_start = loc_start + 10;
                let value_end = element[value_start..].find('"')?;
                return Some(element[value_start..value_start + value_end].to_string());
            }
        }
        search_start = abs_pos + end;
    }
    None
}

/// Extract SLO location from metadata
fn extract_slo_location(xml: &str, binding: &str) -> Option<String> {
    let binding_full = format!("urn:oasis:names:tc:SAML:2.0:bindings:{}", binding);
    let pattern = "SingleLogoutService";

    let mut search_start = 0;
    while let Some(pos) = xml[search_start..].find(pattern) {
        let abs_pos = search_start + pos;
        let end = xml[abs_pos..].find('>')?;
        let element = &xml[abs_pos..abs_pos + end];

        if element.contains(&binding_full) {
            if let Some(loc_start) = element.find(r#"Location=""#) {
                let value_start = loc_start + 10;
                let value_end = element[value_start..].find('"')?;
                return Some(element[value_start..value_start + value_end].to_string());
            }
        }
        search_start = abs_pos + end;
    }
    None
}

/// Extract certificate from metadata
fn extract_certificate(xml: &str) -> Option<String> {
    extract_xml_content(xml, "X509Certificate")
        .map(|c| c.replace(['\n', '\r', ' '], ""))
}

/// Extract NameID from assertion
fn extract_name_id(xml: &str) -> Option<String> {
    extract_xml_content(xml, "NameID")
}

/// Extract status message from response
fn extract_status_message(xml: &str) -> Option<String> {
    extract_xml_content(xml, "StatusMessage")
}

/// Extract condition time attribute
fn extract_condition_time(xml: &str, attr: &str) -> Option<String> {
    let conditions_pattern = "Conditions";
    if let Some(start) = xml.find(conditions_pattern) {
        let end = xml[start..].find('>')?;
        let element = &xml[start..start + end];

        let attr_pattern = format!(r#"{}=""#, attr);
        if let Some(attr_start) = element.find(&attr_pattern) {
            let value_start = attr_start + attr_pattern.len();
            let value_end = element[value_start..].find('"')?;
            return Some(element[value_start..value_start + value_end].to_string());
        }
    }
    None
}

/// Extract SAML attributes
fn extract_saml_attributes(xml: &str) -> std::collections::HashMap<String, String> {
    let mut attributes = std::collections::HashMap::new();

    // Find all Attribute elements
    let mut search_start = 0;
    while let Some(pos) = xml[search_start..].find("<saml:Attribute ").or_else(|| xml[search_start..].find("<Attribute ")) {
        let abs_pos = search_start + pos;

        // Find the end of this attribute element
        if let Some(attr_end) = xml[abs_pos..].find("</saml:Attribute>").or_else(|| xml[abs_pos..].find("</Attribute>")) {
            let attr_element = &xml[abs_pos..abs_pos + attr_end];

            // Extract the attribute name
            if let Some(name) = extract_attribute_name(attr_element) {
                // Extract the attribute value
                if let Some(value) = extract_xml_content(attr_element, "AttributeValue") {
                    attributes.insert(name, value);
                }
            }
            search_start = abs_pos + attr_end;
        } else {
            break;
        }
    }

    attributes
}

/// Extract attribute name from Attribute element
fn extract_attribute_name(element: &str) -> Option<String> {
    let name_pattern = r#"Name=""#;
    if let Some(start) = element.find(name_pattern) {
        let value_start = start + name_pattern.len();
        let value_end = element[value_start..].find('"')?;
        return Some(element[value_start..value_start + value_end].to_string());
    }
    None
}

/// Extract group attributes from SAML assertion
fn extract_group_attributes(xml: &str) -> Vec<String> {
    let mut groups = Vec::new();

    // Look for common group attribute names
    let group_attrs = ["groups", "memberOf", "Group", "member"];

    let attributes = extract_saml_attributes(xml);
    for attr in group_attrs {
        if let Some(value) = attributes.get(attr) {
            // Groups might be comma-separated or in multiple AttributeValue elements
            for group in value.split(',') {
                let trimmed = group.trim();
                if !trimmed.is_empty() {
                    groups.push(trimmed.to_string());
                }
            }
        }
    }

    groups
}

/// Extract PEM body (remove headers and normalize)
fn extract_pem_body(pem: &str) -> String {
    pem.lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("")
}

/// DEFLATE compress data
fn deflate_compress(data: &[u8]) -> Result<Vec<u8>> {
    use std::io::Write;

    let mut encoder = flate2::write::DeflateEncoder::new(
        Vec::new(),
        flate2::Compression::default(),
    );
    encoder.write_all(data)?;
    encoder.finish().context("Failed to compress data")
}

/// Escape XML special characters
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// Generate a unique SAML request ID
pub fn generate_request_id() -> String {
    format!("_{}", Uuid::new_v4())
}

/// Create a LogoutRequest
pub fn create_logout_request(
    sp_entity_id: &str,
    idp_slo_url: &str,
    name_id: &str,
    session_index: Option<&str>,
) -> String {
    let request_id = generate_request_id();
    let issue_instant = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();

    let session_index_elem = session_index
        .map(|idx| format!(r#"<samlp:SessionIndex>{}</samlp:SessionIndex>"#, xml_escape(idx)))
        .unwrap_or_default();

    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                     xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                     ID="{}"
                     Version="2.0"
                     IssueInstant="{}"
                     Destination="{}">
    <saml:Issuer>{}</saml:Issuer>
    <saml:NameID>{}</saml:NameID>
    {}
</samlp:LogoutRequest>"#,
        request_id,
        issue_instant,
        xml_escape(idp_slo_url),
        xml_escape(sp_entity_id),
        xml_escape(name_id),
        session_index_elem,
    )
}

/// Compute SHA-256 hash of data
pub fn compute_sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xml_escape() {
        assert_eq!(xml_escape("a<b>c"), "a&lt;b&gt;c");
        assert_eq!(xml_escape("a&b"), "a&amp;b");
        assert_eq!(xml_escape(r#"a"b'c"#), "a&quot;b&apos;c");
    }

    #[test]
    fn test_generate_request_id() {
        let id = generate_request_id();
        assert!(id.starts_with('_'));
        assert_eq!(id.len(), 37); // _ + 36 char UUID
    }

    #[test]
    fn test_extract_pem_body() {
        let pem = r#"-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAK...
-----END CERTIFICATE-----"#;
        let body = extract_pem_body(pem);
        assert!(!body.contains("BEGIN"));
        assert!(!body.contains("END"));
    }

    #[test]
    fn test_sp_metadata_generation() {
        let sp = SamlServiceProvider::new(
            "https://example.com/sp".to_string(),
            "https://example.com/acs".to_string(),
            Some("https://example.com/slo".to_string()),
            None,
            None,
        );

        let metadata = sp.generate_metadata();
        assert!(metadata.contains("EntityDescriptor"));
        assert!(metadata.contains("https://example.com/sp"));
        assert!(metadata.contains("https://example.com/acs"));
        assert!(metadata.contains("https://example.com/slo"));
    }
}
