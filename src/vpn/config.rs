//! VPN configuration file parsing and validation
//!
//! Validates OpenVPN and WireGuard configuration files to ensure they
//! are safe to use and properly formatted.

use anyhow::Result;
use std::collections::HashSet;

use super::types::VpnType;

/// Result of config validation
#[derive(Debug, Clone)]
pub struct ConfigValidationResult {
    /// Whether the config is valid and safe
    pub is_valid: bool,
    /// VPN type detected from config
    pub vpn_type: Option<VpnType>,
    /// Whether external credentials are required
    pub requires_credentials: bool,
    /// List of validation errors
    pub errors: Vec<String>,
    /// List of warnings (non-fatal)
    pub warnings: Vec<String>,
}

impl ConfigValidationResult {
    fn new() -> Self {
        Self {
            is_valid: true,
            vpn_type: None,
            requires_credentials: false,
            errors: Vec::new(),
            warnings: Vec::new(),
        }
    }

    fn add_error(&mut self, msg: impl Into<String>) {
        self.is_valid = false;
        self.errors.push(msg.into());
    }

    fn add_warning(&mut self, msg: impl Into<String>) {
        self.warnings.push(msg.into());
    }
}

/// VPN configuration validator
pub struct VpnConfigValidator;

impl VpnConfigValidator {
    /// Validate a VPN configuration file
    ///
    /// # Arguments
    /// * `content` - The configuration file content
    /// * `filename` - Original filename (used for type detection)
    ///
    /// # Returns
    /// * Validation result with errors, warnings, and detected properties
    pub fn validate(content: &str, filename: &str) -> ConfigValidationResult {
        let mut result = ConfigValidationResult::new();

        // Check file size
        if content.len() > 1024 * 1024 {
            result.add_error("Configuration file is too large (max 1MB)");
            return result;
        }

        if content.trim().is_empty() {
            result.add_error("Configuration file is empty");
            return result;
        }

        // Detect VPN type from filename extension or content
        let vpn_type = Self::detect_vpn_type(content, filename);
        result.vpn_type = vpn_type;

        match vpn_type {
            Some(VpnType::OpenVPN) => Self::validate_openvpn(content, &mut result),
            Some(VpnType::WireGuard) => Self::validate_wireguard(content, &mut result),
            None => {
                result.add_error(
                    "Unable to determine VPN type. Use .ovpn for OpenVPN or .conf for WireGuard"
                );
            }
        }

        result
    }

    /// Detect VPN type from filename or content
    fn detect_vpn_type(content: &str, filename: &str) -> Option<VpnType> {
        let filename_lower = filename.to_lowercase();

        // Check by extension first
        if filename_lower.ends_with(".ovpn") {
            return Some(VpnType::OpenVPN);
        }

        // WireGuard configs can be .conf but need content check
        if filename_lower.ends_with(".conf") {
            // Check content for WireGuard markers
            if content.contains("[Interface]") && content.contains("PrivateKey") {
                return Some(VpnType::WireGuard);
            }
            // Could be OpenVPN without .ovpn extension
            if content.contains("remote ") || content.contains("client")
                || content.contains("proto ") || content.contains("dev tun")
            {
                return Some(VpnType::OpenVPN);
            }
        }

        // Content-based detection for files without extension
        if content.contains("[Interface]") && content.contains("PrivateKey") {
            return Some(VpnType::WireGuard);
        }

        if content.contains("remote ") || content.contains("client") {
            return Some(VpnType::OpenVPN);
        }

        None
    }

    /// Validate OpenVPN configuration
    fn validate_openvpn(content: &str, result: &mut ConfigValidationResult) {
        // Dangerous options that could execute arbitrary code
        let dangerous_options: HashSet<&str> = [
            "script-security",
            "up",
            "down",
            "ipchange",
            "route-up",
            "route-pre-down",
            "client-connect",
            "client-disconnect",
            "learn-address",
            "auth-user-pass-verify",
            "tls-verify",
            "plugin",
            "daemon",
            "iproute",
            "setenv",
        ].into_iter().collect();

        let mut has_remote = false;
        let mut has_dev = false;
        let mut has_proto = false;

        for line in content.lines() {
            let line = line.trim();

            // Skip comments and empty lines
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }

            // Get the directive (first word)
            let directive = line.split_whitespace().next().unwrap_or("");
            let directive_lower = directive.to_lowercase();

            // Check for dangerous options
            if dangerous_options.contains(directive_lower.as_str()) {
                result.add_error(format!(
                    "Dangerous option '{}' is not allowed for security reasons",
                    directive
                ));
            }

            // Check for required options
            if directive_lower == "remote" {
                has_remote = true;
            }
            if directive_lower == "dev" {
                has_dev = true;
            }
            if directive_lower == "proto" {
                has_proto = true;
            }

            // Check for auth-user-pass (requires credentials)
            if directive_lower == "auth-user-pass" {
                // If no filename follows, credentials are required at runtime
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() == 1 {
                    result.requires_credentials = true;
                }
            }

            // Check for embedded private keys (should be allowed)
            if directive_lower == "<ca>" || directive_lower == "<cert>"
                || directive_lower == "<key>" || directive_lower == "<tls-auth>"
                || directive_lower == "<tls-crypt>"
            {
                // Embedded certificates are fine
            }
        }

        // Check for required options
        if !has_remote {
            result.add_error("Missing required 'remote' directive");
        }

        if !has_dev {
            result.add_warning("Missing 'dev' directive, will use default 'tun'");
        }

        if !has_proto {
            result.add_warning("Missing 'proto' directive, will use default 'udp'");
        }
    }

    /// Validate WireGuard configuration
    fn validate_wireguard(content: &str, result: &mut ConfigValidationResult) {
        let mut has_interface = false;
        let mut has_private_key = false;
        let mut has_peer = false;
        let mut has_public_key = false;
        let mut has_endpoint = false;
        let mut has_address = false;

        let mut current_section = "";

        for line in content.lines() {
            let line = line.trim();

            // Skip comments and empty lines
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Check for section headers
            if line.starts_with('[') && line.ends_with(']') {
                current_section = &line[1..line.len()-1];
                if current_section == "Interface" {
                    has_interface = true;
                } else if current_section == "Peer" {
                    has_peer = true;
                }
                continue;
            }

            // Parse key = value pairs
            if let Some((key, _value)) = line.split_once('=') {
                let key = key.trim();

                match current_section {
                    "Interface" => {
                        if key.eq_ignore_ascii_case("PrivateKey") {
                            has_private_key = true;
                        }
                        if key.eq_ignore_ascii_case("Address") {
                            has_address = true;
                        }
                        // Check for dangerous options
                        if key.eq_ignore_ascii_case("PostUp")
                            || key.eq_ignore_ascii_case("PostDown")
                            || key.eq_ignore_ascii_case("PreUp")
                            || key.eq_ignore_ascii_case("PreDown")
                        {
                            result.add_error(format!(
                                "Script hooks ('{}') are not allowed for security reasons",
                                key
                            ));
                        }
                    }
                    "Peer" => {
                        if key.eq_ignore_ascii_case("PublicKey") {
                            has_public_key = true;
                        }
                        if key.eq_ignore_ascii_case("Endpoint") {
                            has_endpoint = true;
                        }
                    }
                    _ => {}
                }
            }
        }

        // Check for required sections and options
        if !has_interface {
            result.add_error("Missing [Interface] section");
        }

        if !has_private_key {
            result.add_error("Missing PrivateKey in [Interface] section");
        }

        if !has_address {
            result.add_warning("Missing Address in [Interface] section");
        }

        if !has_peer {
            result.add_error("Missing [Peer] section");
        }

        if has_peer && !has_public_key {
            result.add_error("Missing PublicKey in [Peer] section");
        }

        if has_peer && !has_endpoint {
            result.add_warning("Missing Endpoint in [Peer] section (required for client configs)");
        }

        // WireGuard doesn't use external credentials - all auth is key-based
        result.requires_credentials = false;
    }

    /// Sanitize a filename for safe storage
    pub fn sanitize_filename(filename: &str) -> String {
        filename
            .chars()
            .filter(|c| c.is_alphanumeric() || *c == '.' || *c == '-' || *c == '_')
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_openvpn_by_extension() {
        let result = VpnConfigValidator::validate(
            "client\nremote vpn.example.com 1194\ndev tun\nproto udp",
            "test.ovpn"
        );
        assert!(result.is_valid);
        assert_eq!(result.vpn_type, Some(VpnType::OpenVPN));
    }

    #[test]
    fn test_detect_wireguard_by_content() {
        let result = VpnConfigValidator::validate(
            "[Interface]\nPrivateKey = abc123\nAddress = 10.0.0.2/32\n\n[Peer]\nPublicKey = xyz789\nEndpoint = vpn.example.com:51820",
            "test.conf"
        );
        assert!(result.is_valid);
        assert_eq!(result.vpn_type, Some(VpnType::WireGuard));
    }

    #[test]
    fn test_reject_dangerous_openvpn_options() {
        let result = VpnConfigValidator::validate(
            "client\nremote vpn.example.com 1194\nscript-security 2\nup /tmp/evil.sh",
            "test.ovpn"
        );
        assert!(!result.is_valid);
        assert!(result.errors.iter().any(|e| e.contains("script-security")));
        assert!(result.errors.iter().any(|e| e.contains("up")));
    }

    #[test]
    fn test_reject_dangerous_wireguard_options() {
        let result = VpnConfigValidator::validate(
            "[Interface]\nPrivateKey = abc123\nPostUp = /tmp/evil.sh\n\n[Peer]\nPublicKey = xyz789",
            "test.conf"
        );
        assert!(!result.is_valid);
        assert!(result.errors.iter().any(|e| e.contains("PostUp")));
    }

    #[test]
    fn test_openvpn_requires_credentials() {
        let result = VpnConfigValidator::validate(
            "client\nremote vpn.example.com 1194\nauth-user-pass\ndev tun",
            "test.ovpn"
        );
        assert!(result.is_valid);
        assert!(result.requires_credentials);
    }

    #[test]
    fn test_openvpn_embedded_credentials() {
        let result = VpnConfigValidator::validate(
            "client\nremote vpn.example.com 1194\nauth-user-pass /path/to/creds.txt\ndev tun",
            "test.ovpn"
        );
        assert!(result.is_valid);
        assert!(!result.requires_credentials);
    }

    #[test]
    fn test_sanitize_filename() {
        assert_eq!(VpnConfigValidator::sanitize_filename("test.ovpn"), "test.ovpn");
        assert_eq!(VpnConfigValidator::sanitize_filename("my vpn.ovpn"), "myvpn.ovpn");
        assert_eq!(VpnConfigValidator::sanitize_filename("../../../etc/passwd"), "etcpasswd");
        assert_eq!(VpnConfigValidator::sanitize_filename("config-2024.conf"), "config-2024.conf");
    }
}
