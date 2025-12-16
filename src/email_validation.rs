/// Email address validation module
///
/// Validates email addresses against RFC 5322 simplified format.
/// Performs basic sanity checks to ensure email addresses are properly formatted.
///
/// Reference: https://tools.ietf.org/html/rfc5322

use once_cell::sync::Lazy;
use regex::Regex;

/// RFC 5322 simplified email regex
/// This regex validates:
/// - Local part: alphanumeric, dots, and special characters
/// - @ symbol
/// - Domain part: alphanumeric, hyphens, and dots
/// - TLD: at least 2 characters
static EMAIL_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
    ).expect("Failed to compile email regex")
});

/// Validate email address format
///
/// # Arguments
/// * `email` - The email address to validate
///
/// # Returns
/// * `Ok(())` if email is valid
/// * `Err(String)` with clear error message if invalid
///
/// # Examples
/// ```
/// use heroforge::email_validation::validate_email;
///
/// assert!(validate_email("user@example.com").is_ok());
/// assert!(validate_email("test.user+tag@domain.co.uk").is_ok());
/// assert!(validate_email("invalid").is_err());
/// assert!(validate_email("@example.com").is_err());
/// ```
pub fn validate_email(email: &str) -> Result<(), String> {
    // Check if email is empty
    if email.is_empty() {
        return Err("Email address is required".to_string());
    }

    // Check maximum length per RFC 5321 (320 characters total)
    // Local part: 64 chars max, @ symbol: 1, Domain: 255 chars max
    if email.len() > 320 {
        return Err("Email address is too long (max 320 characters)".to_string());
    }

    // Split email into local and domain parts
    let parts: Vec<&str> = email.split('@').collect();
    if parts.len() != 2 {
        return Err("Email address must contain exactly one @ symbol".to_string());
    }

    let local_part = parts[0];
    let domain_part = parts[1];

    // Validate local part length (max 64 characters per RFC 5321)
    if local_part.is_empty() {
        return Err("Email address local part (before @) cannot be empty".to_string());
    }
    if local_part.len() > 64 {
        return Err("Email address local part is too long (max 64 characters)".to_string());
    }

    // Validate domain part length (max 255 characters per RFC 5321)
    if domain_part.is_empty() {
        return Err("Email address domain part (after @) cannot be empty".to_string());
    }
    if domain_part.len() > 255 {
        return Err("Email address domain is too long (max 255 characters)".to_string());
    }

    // Check for consecutive dots
    if email.contains("..") {
        return Err("Email address cannot contain consecutive dots".to_string());
    }

    // Check that local part doesn't start or end with a dot
    if local_part.starts_with('.') || local_part.ends_with('.') {
        return Err("Email address local part cannot start or end with a dot".to_string());
    }

    // Validate against regex pattern
    if !EMAIL_REGEX.is_match(email) {
        return Err("Invalid email address format".to_string());
    }

    // Check that domain has at least one dot (TLD requirement)
    if !domain_part.contains('.') {
        return Err("Email address domain must include a top-level domain".to_string());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_emails() {
        assert!(validate_email("user@example.com").is_ok());
        assert!(validate_email("test.user@example.com").is_ok());
        assert!(validate_email("user+tag@example.com").is_ok());
        assert!(validate_email("user_name@example.co.uk").is_ok());
        assert!(validate_email("first.last@subdomain.example.com").is_ok());
        assert!(validate_email("user123@test-domain.org").is_ok());
        assert!(validate_email("a@b.co").is_ok());
        assert!(validate_email("email@123.123.123.123").is_ok()); // IP addresses are technically valid
    }

    #[test]
    fn test_empty_email() {
        assert!(validate_email("").is_err());
    }

    #[test]
    fn test_missing_at_symbol() {
        assert!(validate_email("userexample.com").is_err());
    }

    #[test]
    fn test_multiple_at_symbols() {
        assert!(validate_email("user@@example.com").is_err());
        assert!(validate_email("user@domain@example.com").is_err());
    }

    #[test]
    fn test_missing_local_part() {
        assert!(validate_email("@example.com").is_err());
    }

    #[test]
    fn test_missing_domain() {
        assert!(validate_email("user@").is_err());
    }

    #[test]
    fn test_missing_tld() {
        assert!(validate_email("user@domain").is_err());
    }

    #[test]
    fn test_consecutive_dots() {
        assert!(validate_email("user..name@example.com").is_err());
        assert!(validate_email("user@example..com").is_err());
    }

    #[test]
    fn test_local_part_starts_with_dot() {
        assert!(validate_email(".user@example.com").is_err());
    }

    #[test]
    fn test_local_part_ends_with_dot() {
        assert!(validate_email("user.@example.com").is_err());
    }

    #[test]
    fn test_local_part_too_long() {
        let long_local = "a".repeat(65);
        let email = format!("{}@example.com", long_local);
        assert!(validate_email(&email).is_err());
    }

    #[test]
    fn test_domain_too_long() {
        let long_domain = "a".repeat(256);
        let email = format!("user@{}.com", long_domain);
        assert!(validate_email(&email).is_err());
    }

    #[test]
    fn test_total_length_too_long() {
        // Create an email longer than 320 characters
        let long_local = "a".repeat(64);
        let long_domain = "b".repeat(250);
        let email = format!("{}@{}.com", long_local, long_domain);
        assert!(validate_email(&email).is_err());
    }

    #[test]
    fn test_invalid_characters() {
        assert!(validate_email("user name@example.com").is_err()); // space in local
        assert!(validate_email("user@exam ple.com").is_err()); // space in domain
    }

    #[test]
    fn test_special_characters_in_local() {
        // These are valid according to RFC 5322
        assert!(validate_email("user+filter@example.com").is_ok());
        assert!(validate_email("user_name@example.com").is_ok());
        assert!(validate_email("user-name@example.com").is_ok());
        assert!(validate_email("user.name@example.com").is_ok());
    }
}
