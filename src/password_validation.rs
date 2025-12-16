/// Password validation module implementing NIST 800-63B guidelines
///
/// NIST 800-63B Requirements:
/// - Minimum 8 characters (we enforce 12 as best practice)
/// - Maximum 128 characters (prevent bcrypt DoS)
/// - Allow all ASCII characters including spaces
/// - Check against common/compromised passwords
/// - NO arbitrary complexity rules (no forced uppercase/lowercase/special chars)
///
/// Reference: https://pages.nist.gov/800-63-3/sp800-63b.html

use anyhow::Result;

/// Common weak passwords to reject (NIST 800-63B section 5.1.1.2)
const COMMON_WEAK_PASSWORDS: &[&str] = &[
    "password",
    "Password",
    "password1",
    "Password1",
    "12345678",
    "123456789",
    "1234567890",
    "12345678901234567890",
    "qwerty",
    "qwertyuiop",
    "abc123",
    "password123",
    "letmein",
    "admin",
    "administrator",
    "Admin123",
    "welcome",
    "Welcome1",
    "monkey",
    "dragon",
    "master",
    "sunshine",
    "princess",
    "football",
    "baseball",
    "iloveyou",
    "trustno1",
    "superman",
    "1q2w3e4r",
    "zxcvbnm",
    "asdfghjkl",
    "qazwsx",
    "passw0rd",
];

/// Validate password against NIST 800-63B guidelines
///
/// # Arguments
/// * `password` - The password to validate
///
/// # Returns
/// * `Ok(())` if password is valid
/// * `Err(String)` with clear error message if invalid
///
/// # Examples
/// ```
/// use heroforge::password_validation::validate_password;
///
/// assert!(validate_password("mySecurePassword123").is_ok());
/// assert!(validate_password("short").is_err());
/// assert!(validate_password("password").is_err());
/// ```
pub fn validate_password(password: &str) -> Result<(), String> {
    // Check minimum length (NIST recommends 8, we enforce 12 as best practice)
    if password.len() < 12 {
        return Err(
            "Password must be at least 12 characters long".to_string()
        );
    }

    // Check maximum length (prevent bcrypt DoS, NIST recommends at least 64)
    if password.len() > 128 {
        return Err(
            "Password must not exceed 128 characters".to_string()
        );
    }

    // Check if password is in common weak password list
    // Use case-insensitive comparison for common patterns
    let password_lower = password.to_lowercase();
    for weak_password in COMMON_WEAK_PASSWORDS {
        if password == *weak_password || password_lower == weak_password.to_lowercase() {
            return Err(
                "Password is too common and easily guessable. Please choose a stronger password".to_string()
            );
        }
    }

    // NIST 800-63B explicitly recommends AGAINST arbitrary complexity rules
    // (no forced uppercase, lowercase, numbers, special characters)
    // This is because such rules often lead to weaker passwords (e.g., "Password1!")

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_minimum_length() {
        assert!(validate_password("short").is_err());
        assert!(validate_password("11chars_abc").is_err());
        assert!(validate_password("12chars_abcd").is_ok());
    }

    #[test]
    fn test_maximum_length() {
        let long_password = "a".repeat(129);
        assert!(validate_password(&long_password).is_err());

        let max_password = "a".repeat(128);
        assert!(validate_password(&max_password).is_ok());
    }

    #[test]
    fn test_common_weak_passwords() {
        assert!(validate_password("password").is_err());
        assert!(validate_password("Password").is_err());
        assert!(validate_password("password1").is_err());
        assert!(validate_password("12345678").is_err());
        assert!(validate_password("qwerty").is_err());
        assert!(validate_password("admin").is_err());
        assert!(validate_password("letmein").is_err());
    }

    #[test]
    fn test_valid_passwords() {
        // NIST 800-63B allows any printable characters
        assert!(validate_password("mySecurePassword123").is_ok());
        assert!(validate_password("correct horse battery staple").is_ok());
        assert!(validate_password("I love pizza!").is_ok());
        assert!(validate_password("this-is-a-valid-passphrase").is_ok());
        assert!(validate_password("ALL CAPS IS OKAY TOO").is_ok());
        assert!(validate_password("no numbers needed").is_ok());
        assert!(validate_password("123456789012").is_ok()); // 12 chars, not in weak list
    }

    #[test]
    fn test_spaces_allowed() {
        // NIST 800-63B explicitly allows spaces
        assert!(validate_password("my pass phrase").is_ok());
        assert!(validate_password("spaces  everywhere  ok").is_ok());
    }

    #[test]
    fn test_special_characters_allowed() {
        assert!(validate_password("special!@#$%^&*()").is_ok());
        assert!(validate_password("unicode_is_fine_🔒").is_ok());
    }
}
