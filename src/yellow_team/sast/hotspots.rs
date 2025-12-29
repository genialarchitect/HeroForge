//! Security Hotspot Detection
//!
//! Identifies code patterns that may be security-sensitive and require human review.
//! Unlike definitive vulnerabilities, hotspots need contextual analysis to determine
//! if they represent actual security issues.

use crate::yellow_team::types::*;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Security hotspot priority levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HotspotPriority {
    /// High priority - likely security issue, review immediately
    High,
    /// Medium priority - potential security concern
    Medium,
    /// Low priority - may be intentional, review when possible
    Low,
}

/// Security hotspot categories
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HotspotCategory {
    /// Authentication-related code
    Authentication,
    /// Authorization and access control
    Authorization,
    /// Cryptographic operations
    Cryptography,
    /// Input validation
    InputValidation,
    /// Output encoding
    OutputEncoding,
    /// Configuration and secrets
    Configuration,
    /// Logging and auditing
    Logging,
    /// Error handling
    ErrorHandling,
    /// Resource management
    ResourceManagement,
    /// Injection prevention
    InjectionPrevention,
    /// Sensitive data handling
    SensitiveData,
    /// Network security
    NetworkSecurity,
    /// File operations
    FileOperations,
    /// Session management
    SessionManagement,
    /// Other security concerns
    Other,
}

/// Resolution status for a hotspot
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HotspotResolution {
    /// Not yet reviewed
    ToReview,
    /// Confirmed as a vulnerability
    Vulnerability,
    /// Reviewed and determined safe
    Safe,
    /// Acknowledged but accepted risk
    Acknowledged,
    /// Fixed
    Fixed,
}

/// A security hotspot definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HotspotRule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub category: HotspotCategory,
    pub priority: HotspotPriority,
    pub language: SastLanguage,
    pub patterns: Vec<String>,
    pub review_guidance: String,
    pub security_questions: Vec<String>,
    pub safe_patterns: Vec<String>,
    pub vulnerable_patterns: Vec<String>,
    pub cwe_ids: Vec<String>,
    pub owasp_ids: Vec<String>,
}

/// A detected security hotspot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityHotspot {
    pub id: String,
    pub scan_id: String,
    pub rule_id: String,
    pub rule_name: String,
    pub category: HotspotCategory,
    pub priority: HotspotPriority,
    pub file_path: String,
    pub line_start: u32,
    pub line_end: Option<u32>,
    pub code_snippet: String,
    pub description: String,
    pub review_guidance: String,
    pub security_questions: Vec<String>,
    pub resolution: HotspotResolution,
    pub resolution_comment: Option<String>,
    pub reviewed_by: Option<String>,
    pub reviewed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub cwe_ids: Vec<String>,
    pub owasp_ids: Vec<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Security hotspot detector
pub struct HotspotDetector {
    rules: Vec<HotspotRule>,
}

impl Default for HotspotDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl HotspotDetector {
    pub fn new() -> Self {
        Self {
            rules: get_builtin_hotspot_rules(),
        }
    }

    pub fn with_rules(rules: Vec<HotspotRule>) -> Self {
        Self { rules }
    }

    pub fn add_rules(&mut self, rules: Vec<HotspotRule>) {
        self.rules.extend(rules);
    }

    /// Detect security hotspots in code
    pub fn detect(&self, code: &str, file_path: &str, language: SastLanguage) -> Vec<SecurityHotspot> {
        let mut hotspots = Vec::new();

        // Filter rules by language
        let applicable_rules: Vec<&HotspotRule> = self
            .rules
            .iter()
            .filter(|r| r.language == language || r.language == SastLanguage::Unknown)
            .collect();

        for rule in applicable_rules {
            for pattern_str in &rule.patterns {
                if let Ok(regex) = Regex::new(pattern_str) {
                    for mat in regex.find_iter(code) {
                        // Check if this matches a "safe" pattern - if so, skip
                        let matched_text = mat.as_str();
                        let context = get_context(code, mat.start(), mat.end());

                        let is_safe = rule.safe_patterns.iter().any(|safe_pattern| {
                            Regex::new(safe_pattern)
                                .map(|r| r.is_match(&context))
                                .unwrap_or(false)
                        });

                        if is_safe {
                            continue;
                        }

                        let line_start = code[..mat.start()].lines().count() as u32;
                        let snippet = get_code_snippet(code, line_start as usize);

                        hotspots.push(SecurityHotspot {
                            id: Uuid::new_v4().to_string(),
                            scan_id: String::new(),
                            rule_id: rule.id.clone(),
                            rule_name: rule.name.clone(),
                            category: rule.category,
                            priority: rule.priority,
                            file_path: file_path.to_string(),
                            line_start,
                            line_end: Some(line_start),
                            code_snippet: snippet,
                            description: rule.description.clone(),
                            review_guidance: rule.review_guidance.clone(),
                            security_questions: rule.security_questions.clone(),
                            resolution: HotspotResolution::ToReview,
                            resolution_comment: None,
                            reviewed_by: None,
                            reviewed_at: None,
                            cwe_ids: rule.cwe_ids.clone(),
                            owasp_ids: rule.owasp_ids.clone(),
                            created_at: chrono::Utc::now(),
                        });
                    }
                }
            }
        }

        // Deduplicate hotspots at same location
        deduplicate_hotspots(hotspots)
    }

    /// Get hotspot statistics by category
    pub fn get_stats(&self, hotspots: &[SecurityHotspot]) -> HotspotStats {
        let mut by_category: HashMap<HotspotCategory, usize> = HashMap::new();
        let mut by_priority: HashMap<HotspotPriority, usize> = HashMap::new();
        let mut by_resolution: HashMap<HotspotResolution, usize> = HashMap::new();

        for hotspot in hotspots {
            *by_category.entry(hotspot.category).or_insert(0) += 1;
            *by_priority.entry(hotspot.priority).or_insert(0) += 1;
            *by_resolution.entry(hotspot.resolution).or_insert(0) += 1;
        }

        HotspotStats {
            total: hotspots.len(),
            by_category,
            by_priority,
            by_resolution,
        }
    }

    /// Convert hotspots to SAST findings for unified reporting
    pub fn to_findings(&self, hotspots: Vec<SecurityHotspot>, scan_id: &str) -> Vec<SastFinding> {
        hotspots
            .into_iter()
            .map(|h| SastFinding {
                id: h.id,
                scan_id: scan_id.to_string(),
                rule_id: h.rule_id,
                severity: match h.priority {
                    HotspotPriority::High => Severity::Medium,
                    HotspotPriority::Medium => Severity::Low,
                    HotspotPriority::Low => Severity::Info,
                },
                category: SastCategory::SecurityHotspot,
                file_path: h.file_path,
                location: CodeLocation {
                    line_start: h.line_start,
                    line_end: h.line_end,
                    column_start: None,
                    column_end: None,
                },
                code_snippet: Some(h.code_snippet),
                message: format!("[{}] {}", h.rule_name, h.description),
                cwe_id: h.cwe_ids.first().cloned(),
                remediation: Some(h.review_guidance),
                false_positive: h.resolution == HotspotResolution::Safe,
                suppressed: h.resolution == HotspotResolution::Acknowledged,
                created_at: h.created_at,
            })
            .collect()
    }
}

/// Hotspot statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HotspotStats {
    pub total: usize,
    pub by_category: HashMap<HotspotCategory, usize>,
    pub by_priority: HashMap<HotspotPriority, usize>,
    pub by_resolution: HashMap<HotspotResolution, usize>,
}

/// Get context around a match for analysis
fn get_context(code: &str, start: usize, end: usize) -> String {
    let line_start = code[..start].rfind('\n').map(|i| i + 1).unwrap_or(0);
    let line_end = code[end..].find('\n').map(|i| end + i).unwrap_or(code.len());
    code[line_start..line_end].to_string()
}

/// Get a code snippet around a line
fn get_code_snippet(content: &str, line_num: usize) -> String {
    let lines: Vec<&str> = content.lines().collect();
    let start = line_num.saturating_sub(2);
    let end = (line_num + 3).min(lines.len());

    lines[start..end]
        .iter()
        .enumerate()
        .map(|(i, line)| format!("{}: {}", start + i + 1, line))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Deduplicate hotspots at the same location
fn deduplicate_hotspots(hotspots: Vec<SecurityHotspot>) -> Vec<SecurityHotspot> {
    let mut seen: HashMap<(String, u32), SecurityHotspot> = HashMap::new();

    for hotspot in hotspots {
        let key = (hotspot.file_path.clone(), hotspot.line_start);

        if let Some(existing) = seen.get(&key) {
            // Keep the higher priority hotspot
            if hotspot.priority as u8 > existing.priority as u8 {
                seen.insert(key, hotspot);
            }
        } else {
            seen.insert(key, hotspot);
        }
    }

    seen.into_values().collect()
}

/// Get built-in hotspot rules
pub fn get_builtin_hotspot_rules() -> Vec<HotspotRule> {
    let mut rules = Vec::new();

    // ============================================================
    // AUTHENTICATION HOTSPOTS
    // ============================================================

    rules.push(HotspotRule {
        id: "HS-AUTH-001".to_string(),
        name: "Password in Variable".to_string(),
        description: "Variable name suggests it contains a password. Ensure it's properly protected.".to_string(),
        category: HotspotCategory::Authentication,
        priority: HotspotPriority::High,
        language: SastLanguage::Unknown,
        patterns: vec![
            r"(?i)(password|passwd|pwd)\s*[=:]".to_string(),
            r"(?i)(secret|token|api_?key)\s*[=:]".to_string(),
        ],
        review_guidance: "Verify that sensitive credentials are not hardcoded. Check if values come from secure storage (environment variables, secrets manager, vault).".to_string(),
        security_questions: vec![
            "Is this a hardcoded credential?".to_string(),
            "Is the value loaded from secure storage?".to_string(),
            "Could this be logged or exposed?".to_string(),
        ],
        safe_patterns: vec![
            r"(?i)password\s*=\s*(?:os\.environ|process\.env|env::var|getenv)".to_string(),
            r"(?i)password\s*=\s*(?:get_secret|vault\.read|ssm\.get)".to_string(),
        ],
        vulnerable_patterns: vec![
            r#"(?i)password\s*=\s*["'][^"']+["']"#.to_string(),
        ],
        cwe_ids: vec!["CWE-798".to_string(), "CWE-259".to_string()],
        owasp_ids: vec!["A07:2021".to_string()],
    });

    rules.push(HotspotRule {
        id: "HS-AUTH-002".to_string(),
        name: "Authentication Bypass Check".to_string(),
        description: "Authentication check that could potentially be bypassed.".to_string(),
        category: HotspotCategory::Authentication,
        priority: HotspotPriority::High,
        language: SastLanguage::Unknown,
        patterns: vec![
            r"(?i)if\s*\(\s*!?\s*(is_?authenticated|is_?admin|is_?logged_?in|check_?auth)".to_string(),
            r"(?i)@\s*(login_required|authenticated|auth_check|requires_auth)".to_string(),
        ],
        review_guidance: "Verify that authentication checks cannot be bypassed. Ensure all paths through the code require proper authentication.".to_string(),
        security_questions: vec![
            "Are there code paths that bypass this check?".to_string(),
            "Is the authentication state properly verified?".to_string(),
            "Can the check be influenced by user input?".to_string(),
        ],
        safe_patterns: vec![],
        vulnerable_patterns: vec![],
        cwe_ids: vec!["CWE-287".to_string()],
        owasp_ids: vec!["A07:2021".to_string()],
    });

    rules.push(HotspotRule {
        id: "HS-AUTH-003".to_string(),
        name: "Password Comparison".to_string(),
        description: "Direct password comparison may be vulnerable to timing attacks.".to_string(),
        category: HotspotCategory::Authentication,
        priority: HotspotPriority::Medium,
        language: SastLanguage::Unknown,
        patterns: vec![
            r"(?i)(password|hash)\s*==\s*".to_string(),
            r"(?i)\.equals\s*\(\s*(password|hash)".to_string(),
        ],
        review_guidance: "Use constant-time comparison for password/hash verification to prevent timing attacks. Use bcrypt.compare, hmac.compare_digest, or similar secure functions.".to_string(),
        security_questions: vec![
            "Is this using constant-time comparison?".to_string(),
            "Could timing differences leak information?".to_string(),
        ],
        safe_patterns: vec![
            r"(?i)(bcrypt|argon2|scrypt|pbkdf2)\.".to_string(),
            r"(?i)(hmac\.compare_digest|constant_time|secure_compare|timing_safe)".to_string(),
        ],
        vulnerable_patterns: vec![],
        cwe_ids: vec!["CWE-208".to_string()],
        owasp_ids: vec!["A02:2021".to_string()],
    });

    // ============================================================
    // AUTHORIZATION HOTSPOTS
    // ============================================================

    rules.push(HotspotRule {
        id: "HS-AUTHZ-001".to_string(),
        name: "Authorization Check".to_string(),
        description: "Authorization check detected. Verify it covers all required permissions.".to_string(),
        category: HotspotCategory::Authorization,
        priority: HotspotPriority::Medium,
        language: SastLanguage::Unknown,
        patterns: vec![
            r"(?i)if\s*\(\s*!?\s*(has_?permission|can_?access|is_?allowed|check_?access|authorize)".to_string(),
            r"(?i)@\s*(permission|authorize|requires_role|has_role)".to_string(),
        ],
        review_guidance: "Verify that authorization checks are comprehensive and cannot be bypassed. Check for IDOR vulnerabilities.".to_string(),
        security_questions: vec![
            "Does this check all required permissions?".to_string(),
            "Can a user access resources belonging to others?".to_string(),
            "Is the authorization check performed at the right layer?".to_string(),
        ],
        safe_patterns: vec![],
        vulnerable_patterns: vec![],
        cwe_ids: vec!["CWE-862".to_string(), "CWE-863".to_string()],
        owasp_ids: vec!["A01:2021".to_string()],
    });

    rules.push(HotspotRule {
        id: "HS-AUTHZ-002".to_string(),
        name: "Role-Based Access".to_string(),
        description: "Role-based access control detected. Verify role assignments are correct.".to_string(),
        category: HotspotCategory::Authorization,
        priority: HotspotPriority::Medium,
        language: SastLanguage::Unknown,
        patterns: vec![
            r#"(?i)role\s*[=:]\s*["'](admin|root|superuser|administrator)["']"#.to_string(),
            r"(?i)\.role\s*==\s*".to_string(),
            r"(?i)user\.is_?(admin|staff|superuser)".to_string(),
        ],
        review_guidance: "Verify that role checks are secure and roles cannot be manipulated by users.".to_string(),
        security_questions: vec![
            "Can users modify their own role?".to_string(),
            "Is role information from a trusted source?".to_string(),
            "Are role checks consistent across the application?".to_string(),
        ],
        safe_patterns: vec![],
        vulnerable_patterns: vec![],
        cwe_ids: vec!["CWE-269".to_string()],
        owasp_ids: vec!["A01:2021".to_string()],
    });

    // ============================================================
    // CRYPTOGRAPHY HOTSPOTS
    // ============================================================

    rules.push(HotspotRule {
        id: "HS-CRYPTO-001".to_string(),
        name: "Encryption Implementation".to_string(),
        description: "Custom encryption implementation detected. Verify cryptographic security.".to_string(),
        category: HotspotCategory::Cryptography,
        priority: HotspotPriority::High,
        language: SastLanguage::Unknown,
        patterns: vec![
            r"(?i)(aes|des|rsa|chacha|salsa)\.".to_string(),
            r"(?i)cipher\s*=".to_string(),
            r"(?i)(encrypt|decrypt)\s*\(".to_string(),
        ],
        review_guidance: "Ensure proper encryption mode (use GCM or similar authenticated encryption), key management, and IV/nonce handling.".to_string(),
        security_questions: vec![
            "Is an authenticated encryption mode used (GCM, CCM)?".to_string(),
            "Are keys properly managed and rotated?".to_string(),
            "Are IVs/nonces generated securely and never reused?".to_string(),
            "Is the key length sufficient (AES-256)?".to_string(),
        ],
        safe_patterns: vec![],
        vulnerable_patterns: vec![
            r"(?i)(ecb|des|rc4|md5|sha1)".to_string(),
        ],
        cwe_ids: vec!["CWE-327".to_string()],
        owasp_ids: vec!["A02:2021".to_string()],
    });

    rules.push(HotspotRule {
        id: "HS-CRYPTO-002".to_string(),
        name: "Random Number Generation".to_string(),
        description: "Random number generation detected. Verify cryptographic randomness for security operations.".to_string(),
        category: HotspotCategory::Cryptography,
        priority: HotspotPriority::Medium,
        language: SastLanguage::Unknown,
        patterns: vec![
            r"(?i)random\s*\(".to_string(),
            r"(?i)rand::".to_string(),
            r"(?i)Math\.random".to_string(),
        ],
        review_guidance: "For security-sensitive operations (tokens, keys, IVs), use cryptographically secure random generators (secrets, crypto.randomBytes, OsRng).".to_string(),
        security_questions: vec![
            "Is this used for security-sensitive purposes?".to_string(),
            "Is a cryptographically secure RNG used?".to_string(),
            "Is the random source seeded properly?".to_string(),
        ],
        safe_patterns: vec![
            r"(?i)(secrets|crypto\.randomBytes|getrandom|urandom|OsRng|csprng)".to_string(),
        ],
        vulnerable_patterns: vec![],
        cwe_ids: vec!["CWE-330".to_string(), "CWE-338".to_string()],
        owasp_ids: vec!["A02:2021".to_string()],
    });

    rules.push(HotspotRule {
        id: "HS-CRYPTO-003".to_string(),
        name: "Hash Function Usage".to_string(),
        description: "Hash function usage detected. Verify appropriate algorithm for use case.".to_string(),
        category: HotspotCategory::Cryptography,
        priority: HotspotPriority::Medium,
        language: SastLanguage::Unknown,
        patterns: vec![
            r"(?i)(md5|sha1|sha256|sha512|bcrypt|argon2|scrypt)".to_string(),
            r"(?i)hashlib\.".to_string(),
            r"(?i)\.digest\s*\(".to_string(),
        ],
        review_guidance: "Use bcrypt/argon2/scrypt for passwords. Use SHA-256+ for integrity. Avoid MD5/SHA1 for security purposes.".to_string(),
        security_questions: vec![
            "Is this being used for password storage?".to_string(),
            "Is the algorithm appropriate for the use case?".to_string(),
            "Is a salt used where needed?".to_string(),
        ],
        safe_patterns: vec![],
        vulnerable_patterns: vec![
            r"(?i)(md5|sha1)\s*\(".to_string(),
        ],
        cwe_ids: vec!["CWE-328".to_string()],
        owasp_ids: vec!["A02:2021".to_string()],
    });

    // ============================================================
    // INPUT VALIDATION HOTSPOTS
    // ============================================================

    rules.push(HotspotRule {
        id: "HS-INPUT-001".to_string(),
        name: "User Input Processing".to_string(),
        description: "User input is being processed. Verify proper validation and sanitization.".to_string(),
        category: HotspotCategory::InputValidation,
        priority: HotspotPriority::High,
        language: SastLanguage::Unknown,
        patterns: vec![
            r"(?i)(request\.(body|query|params|form)|req\.(body|query|params))".to_string(),
            r"(?i)input\s*\(".to_string(),
            r#"(?i)\.get\s*\(\s*["']"#.to_string(),
        ],
        review_guidance: "Validate all user input for type, length, format, and range. Sanitize before use in sensitive operations.".to_string(),
        security_questions: vec![
            "Is the input validated for expected type and format?".to_string(),
            "Are length limits enforced?".to_string(),
            "Is the input sanitized before use?".to_string(),
            "Could malicious input cause issues downstream?".to_string(),
        ],
        safe_patterns: vec![],
        vulnerable_patterns: vec![],
        cwe_ids: vec!["CWE-20".to_string()],
        owasp_ids: vec!["A03:2021".to_string()],
    });

    rules.push(HotspotRule {
        id: "HS-INPUT-002".to_string(),
        name: "Regular Expression".to_string(),
        description: "Regular expression detected. Verify it's not vulnerable to ReDoS.".to_string(),
        category: HotspotCategory::InputValidation,
        priority: HotspotPriority::Medium,
        language: SastLanguage::Unknown,
        patterns: vec![
            r"(?i)(regex|regexp|re\.compile|Regex::new)\s*\(".to_string(),
            r"/[^/]+/[gim]*".to_string(),
        ],
        review_guidance: "Ensure regex patterns are not vulnerable to ReDoS. Avoid nested quantifiers and overlapping alternatives on user input.".to_string(),
        security_questions: vec![
            "Is this regex applied to user input?".to_string(),
            "Are there nested quantifiers (e.g., (a+)+)?".to_string(),
            "Could a malicious input cause catastrophic backtracking?".to_string(),
        ],
        safe_patterns: vec![],
        vulnerable_patterns: vec![
            r"\(\[.*\]\+\)\+".to_string(),
            r"\(\.?\*\)\+".to_string(),
        ],
        cwe_ids: vec!["CWE-1333".to_string()],
        owasp_ids: vec!["A03:2021".to_string()],
    });

    // ============================================================
    // LOGGING HOTSPOTS
    // ============================================================

    rules.push(HotspotRule {
        id: "HS-LOG-001".to_string(),
        name: "Sensitive Data in Logs".to_string(),
        description: "Logging statement detected. Verify no sensitive data is logged.".to_string(),
        category: HotspotCategory::Logging,
        priority: HotspotPriority::Medium,
        language: SastLanguage::Unknown,
        patterns: vec![
            r"(?i)(log|logger|console)\.(debug|info|warn|error|trace)\s*\(".to_string(),
            r"(?i)print(ln)?\s*\(".to_string(),
        ],
        review_guidance: "Ensure passwords, tokens, PII, and other sensitive data are not logged. Use log masking where appropriate.".to_string(),
        security_questions: vec![
            "Could this log sensitive data (passwords, tokens, PII)?".to_string(),
            "Is user input being logged without sanitization?".to_string(),
            "Could log injection attacks be possible?".to_string(),
        ],
        safe_patterns: vec![],
        vulnerable_patterns: vec![
            r"(?i)log.*password".to_string(),
            r"(?i)log.*token".to_string(),
            r"(?i)log.*secret".to_string(),
        ],
        cwe_ids: vec!["CWE-532".to_string()],
        owasp_ids: vec!["A09:2021".to_string()],
    });

    // ============================================================
    // ERROR HANDLING HOTSPOTS
    // ============================================================

    rules.push(HotspotRule {
        id: "HS-ERR-001".to_string(),
        name: "Exception Handling".to_string(),
        description: "Exception/error handling detected. Verify errors are handled securely.".to_string(),
        category: HotspotCategory::ErrorHandling,
        priority: HotspotPriority::Low,
        language: SastLanguage::Unknown,
        patterns: vec![
            r"(?i)catch\s*\(".to_string(),
            r"(?i)except(\s+\w+)?:".to_string(),
            r"(?i)\.catch\s*\(".to_string(),
        ],
        review_guidance: "Ensure error messages don't leak sensitive information. Log errors appropriately but don't expose stack traces to users.".to_string(),
        security_questions: vec![
            "Does the error response expose internal details?".to_string(),
            "Are stack traces hidden from users?".to_string(),
            "Is the error logged for debugging?".to_string(),
        ],
        safe_patterns: vec![],
        vulnerable_patterns: vec![
            r"(?i)(print|response).*stack".to_string(),
            r"(?i)(print|response).*traceback".to_string(),
        ],
        cwe_ids: vec!["CWE-209".to_string()],
        owasp_ids: vec!["A05:2021".to_string()],
    });

    // ============================================================
    // NETWORK SECURITY HOTSPOTS
    // ============================================================

    rules.push(HotspotRule {
        id: "HS-NET-001".to_string(),
        name: "HTTP Request".to_string(),
        description: "HTTP request detected. Verify secure connection and input validation.".to_string(),
        category: HotspotCategory::NetworkSecurity,
        priority: HotspotPriority::Medium,
        language: SastLanguage::Unknown,
        patterns: vec![
            r"(?i)(fetch|axios|requests|http|reqwest)\.(get|post|put|delete)\s*\(".to_string(),
            r"(?i)new\s+XMLHttpRequest".to_string(),
            r"(?i)curl_exec".to_string(),
        ],
        review_guidance: "Verify HTTPS is used, certificates are validated, and response data is handled safely.".to_string(),
        security_questions: vec![
            "Is HTTPS enforced?".to_string(),
            "Is certificate validation enabled?".to_string(),
            "Is the response validated before use?".to_string(),
            "Could SSRF be possible with user-controlled URLs?".to_string(),
        ],
        safe_patterns: vec![],
        vulnerable_patterns: vec![
            r"(?i)verify\s*=\s*False".to_string(),
            r"(?i)rejectUnauthorized\s*:\s*false".to_string(),
        ],
        cwe_ids: vec!["CWE-918".to_string()],
        owasp_ids: vec!["A10:2021".to_string()],
    });

    rules.push(HotspotRule {
        id: "HS-NET-002".to_string(),
        name: "CORS Configuration".to_string(),
        description: "CORS configuration detected. Verify it's not overly permissive.".to_string(),
        category: HotspotCategory::NetworkSecurity,
        priority: HotspotPriority::Medium,
        language: SastLanguage::Unknown,
        patterns: vec![
            r"(?i)Access-Control-Allow-Origin".to_string(),
            r"(?i)cors\s*\(".to_string(),
            r"(?i)\.cors\s*\(".to_string(),
        ],
        review_guidance: "Avoid using '*' for Access-Control-Allow-Origin in production. Specify exact allowed origins.".to_string(),
        security_questions: vec![
            "Is '*' used as the allowed origin?".to_string(),
            "Are credentials allowed with a broad origin?".to_string(),
            "Are the allowed methods and headers restricted?".to_string(),
        ],
        safe_patterns: vec![],
        vulnerable_patterns: vec![
            r#"(?i)Access-Control-Allow-Origin['":\s]+\*"#.to_string(),
        ],
        cwe_ids: vec!["CWE-942".to_string()],
        owasp_ids: vec!["A05:2021".to_string()],
    });

    // ============================================================
    // FILE OPERATIONS HOTSPOTS
    // ============================================================

    rules.push(HotspotRule {
        id: "HS-FILE-001".to_string(),
        name: "File Path Construction".to_string(),
        description: "File path being constructed. Verify path traversal prevention.".to_string(),
        category: HotspotCategory::FileOperations,
        priority: HotspotPriority::High,
        language: SastLanguage::Unknown,
        patterns: vec![
            r"(?i)(open|read|write|Path)\s*\([^)]*\+".to_string(),
            r"(?i)join\s*\([^)]*user".to_string(),
            r"(?i)path\s*\+\s*".to_string(),
        ],
        review_guidance: "Validate and sanitize file paths. Use realpath/canonical path and verify the resulting path is within allowed directories.".to_string(),
        security_questions: vec![
            "Could a user inject '../' to escape the directory?".to_string(),
            "Is the path canonicalized before use?".to_string(),
            "Is the resulting path checked against an allowlist?".to_string(),
        ],
        safe_patterns: vec![
            r"(?i)(realpath|canonical|abspath|normalize)".to_string(),
        ],
        vulnerable_patterns: vec![],
        cwe_ids: vec!["CWE-22".to_string()],
        owasp_ids: vec!["A01:2021".to_string()],
    });

    rules.push(HotspotRule {
        id: "HS-FILE-002".to_string(),
        name: "File Upload".to_string(),
        description: "File upload detected. Verify proper validation and storage.".to_string(),
        category: HotspotCategory::FileOperations,
        priority: HotspotPriority::High,
        language: SastLanguage::Unknown,
        patterns: vec![
            r"(?i)(upload|multipart|form-data)".to_string(),
            r"(?i)\.save\s*\(".to_string(),
            r"(?i)write.*file".to_string(),
        ],
        review_guidance: "Validate file type (by content, not just extension), size limits, and store outside web root with random names.".to_string(),
        security_questions: vec![
            "Is file type validated by content (magic bytes)?".to_string(),
            "Are size limits enforced?".to_string(),
            "Is the file stored outside the web root?".to_string(),
            "Are file names sanitized/randomized?".to_string(),
        ],
        safe_patterns: vec![],
        vulnerable_patterns: vec![],
        cwe_ids: vec!["CWE-434".to_string()],
        owasp_ids: vec!["A04:2021".to_string()],
    });

    // ============================================================
    // SESSION MANAGEMENT HOTSPOTS
    // ============================================================

    rules.push(HotspotRule {
        id: "HS-SESS-001".to_string(),
        name: "Session Configuration".to_string(),
        description: "Session configuration detected. Verify secure settings.".to_string(),
        category: HotspotCategory::SessionManagement,
        priority: HotspotPriority::Medium,
        language: SastLanguage::Unknown,
        patterns: vec![
            r"(?i)session\s*\(".to_string(),
            r"(?i)cookie\s*=".to_string(),
            r"(?i)Set-Cookie".to_string(),
        ],
        review_guidance: "Ensure cookies use Secure, HttpOnly, and SameSite flags. Set appropriate expiration times.".to_string(),
        security_questions: vec![
            "Is the Secure flag set for cookies?".to_string(),
            "Is the HttpOnly flag set?".to_string(),
            "Is SameSite attribute configured?".to_string(),
            "Is session fixation prevented?".to_string(),
        ],
        safe_patterns: vec![],
        vulnerable_patterns: vec![
            r"(?i)secure\s*[:=]\s*false".to_string(),
            r"(?i)httponly\s*[:=]\s*false".to_string(),
        ],
        cwe_ids: vec!["CWE-614".to_string()],
        owasp_ids: vec!["A07:2021".to_string()],
    });

    // ============================================================
    // SENSITIVE DATA HOTSPOTS
    // ============================================================

    rules.push(HotspotRule {
        id: "HS-DATA-001".to_string(),
        name: "PII Handling".to_string(),
        description: "Personally identifiable information detected. Verify proper handling.".to_string(),
        category: HotspotCategory::SensitiveData,
        priority: HotspotPriority::Medium,
        language: SastLanguage::Unknown,
        patterns: vec![
            r"(?i)(ssn|social_security|national_id|passport)".to_string(),
            r"(?i)(credit_card|card_number|cvv|expir)".to_string(),
            r"(?i)(email|phone|address|birth_?date|dob)".to_string(),
        ],
        review_guidance: "Ensure PII is encrypted at rest and in transit, access is logged, and retention policies are followed.".to_string(),
        security_questions: vec![
            "Is this PII encrypted at rest?".to_string(),
            "Is access to this data logged/audited?".to_string(),
            "Is there a data retention policy?".to_string(),
            "Is this data masked in logs/responses?".to_string(),
        ],
        safe_patterns: vec![],
        vulnerable_patterns: vec![],
        cwe_ids: vec!["CWE-359".to_string()],
        owasp_ids: vec!["A02:2021".to_string()],
    });

    // ============================================================
    // CONFIGURATION HOTSPOTS
    // ============================================================

    rules.push(HotspotRule {
        id: "HS-CONF-001".to_string(),
        name: "Debug Mode".to_string(),
        description: "Debug mode configuration detected. Ensure it's disabled in production.".to_string(),
        category: HotspotCategory::Configuration,
        priority: HotspotPriority::Medium,
        language: SastLanguage::Unknown,
        patterns: vec![
            r"(?i)debug\s*[:=]\s*true".to_string(),
            r"(?i)DEBUG\s*=\s*True".to_string(),
            r"(?i)\.debug\s*\(".to_string(),
        ],
        review_guidance: "Debug mode should be disabled in production. It may expose sensitive information and reduce security.".to_string(),
        security_questions: vec![
            "Is this for production use?".to_string(),
            "Is debug mode controlled by environment?".to_string(),
            "What information does debug mode expose?".to_string(),
        ],
        safe_patterns: vec![
            r"(?i)if.*development".to_string(),
            r"(?i)if.*test".to_string(),
        ],
        vulnerable_patterns: vec![],
        cwe_ids: vec!["CWE-489".to_string()],
        owasp_ids: vec!["A05:2021".to_string()],
    });

    rules.push(HotspotRule {
        id: "HS-CONF-002".to_string(),
        name: "TLS/SSL Configuration".to_string(),
        description: "TLS/SSL configuration detected. Verify secure settings.".to_string(),
        category: HotspotCategory::Configuration,
        priority: HotspotPriority::High,
        language: SastLanguage::Unknown,
        patterns: vec![
            r"(?i)(ssl|tls)_(context|version|options)".to_string(),
            r"(?i)min.*(protocol|version)".to_string(),
            r"(?i)(cipher|ciphers)\s*[:=]".to_string(),
        ],
        review_guidance: "Ensure TLS 1.2+ is required, weak ciphers are disabled, and certificate validation is enabled.".to_string(),
        security_questions: vec![
            "Is TLS 1.2 or higher required?".to_string(),
            "Are weak ciphers (RC4, DES, 3DES) disabled?".to_string(),
            "Is certificate validation enabled?".to_string(),
            "Is HSTS enabled for web servers?".to_string(),
        ],
        safe_patterns: vec![],
        vulnerable_patterns: vec![
            r"(?i)(ssl|tls)v[123]".to_string(),
            r"(?i)(rc4|des|3des|null)".to_string(),
        ],
        cwe_ids: vec!["CWE-326".to_string()],
        owasp_ids: vec!["A02:2021".to_string()],
    });

    // ============================================================
    // INJECTION PREVENTION HOTSPOTS
    // ============================================================

    rules.push(HotspotRule {
        id: "HS-INJ-001".to_string(),
        name: "SQL Query Construction".to_string(),
        description: "SQL query construction detected. Verify parameterized queries are used.".to_string(),
        category: HotspotCategory::InjectionPrevention,
        priority: HotspotPriority::High,
        language: SastLanguage::Unknown,
        patterns: vec![
            r#"(?i)(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE).*['"]\s*\+"#.to_string(),
            r#"(?i)f['"](SELECT|INSERT|UPDATE|DELETE)"#.to_string(),
            r"(?i)format.*SELECT".to_string(),
        ],
        review_guidance: "Always use parameterized queries or prepared statements. Never concatenate user input into SQL strings.".to_string(),
        security_questions: vec![
            "Is user input concatenated into the query?".to_string(),
            "Are parameterized queries/prepared statements used?".to_string(),
            "Is an ORM with proper escaping used?".to_string(),
        ],
        safe_patterns: vec![
            r"(?i)\?\s*,".to_string(),
            r"(?i)\$[0-9]+".to_string(),
            r"(?i):[\w]+".to_string(),
        ],
        vulnerable_patterns: vec![],
        cwe_ids: vec!["CWE-89".to_string()],
        owasp_ids: vec!["A03:2021".to_string()],
    });

    rules.push(HotspotRule {
        id: "HS-INJ-002".to_string(),
        name: "Command Construction".to_string(),
        description: "Command execution detected. Verify no shell injection is possible.".to_string(),
        category: HotspotCategory::InjectionPrevention,
        priority: HotspotPriority::High,
        language: SastLanguage::Unknown,
        patterns: vec![
            r"(?i)(exec|system|popen|subprocess|spawn|shell)\s*\(".to_string(),
            r"(?i)os\.(system|popen)".to_string(),
            r"(?i)child_process".to_string(),
        ],
        review_guidance: "Avoid shell execution with user input. Use parameterized command execution and escape/validate all arguments.".to_string(),
        security_questions: vec![
            "Is user input included in the command?".to_string(),
            "Is shell=True (or equivalent) avoided?".to_string(),
            "Are command arguments properly escaped?".to_string(),
        ],
        safe_patterns: vec![
            r"(?i)shell\s*[:=]\s*False".to_string(),
            r"(?i)\[.*\]".to_string(),
        ],
        vulnerable_patterns: vec![
            r"(?i)shell\s*[:=]\s*True".to_string(),
        ],
        cwe_ids: vec!["CWE-78".to_string()],
        owasp_ids: vec!["A03:2021".to_string()],
    });

    // ============================================================
    // RESOURCE MANAGEMENT HOTSPOTS
    // ============================================================

    rules.push(HotspotRule {
        id: "HS-RES-001".to_string(),
        name: "Resource Allocation".to_string(),
        description: "Resource allocation detected. Verify proper limits and cleanup.".to_string(),
        category: HotspotCategory::ResourceManagement,
        priority: HotspotPriority::Low,
        language: SastLanguage::Unknown,
        patterns: vec![
            r"(?i)(malloc|alloc|new\s+\w+\[)".to_string(),
            r"(?i)(thread|worker|pool)\.(create|spawn|new)".to_string(),
        ],
        review_guidance: "Ensure resources have size limits, are properly released, and cannot be exhausted by malicious input.".to_string(),
        security_questions: vec![
            "Is the size/count limited?".to_string(),
            "Is the resource properly released/closed?".to_string(),
            "Could a malicious user exhaust this resource?".to_string(),
        ],
        safe_patterns: vec![],
        vulnerable_patterns: vec![],
        cwe_ids: vec!["CWE-400".to_string()],
        owasp_ids: vec!["A05:2021".to_string()],
    });

    rules
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hotspot_detection() {
        let detector = HotspotDetector::new();
        let code = r#"
password = "hardcoded123"
if is_authenticated(user):
    do_something()
"#;

        let hotspots = detector.detect(code, "test.py", SastLanguage::Python);
        assert!(!hotspots.is_empty());
    }

    #[test]
    fn test_hotspot_stats() {
        let detector = HotspotDetector::new();
        let hotspots = vec![
            SecurityHotspot {
                id: "1".to_string(),
                scan_id: "scan1".to_string(),
                rule_id: "HS-AUTH-001".to_string(),
                rule_name: "Test".to_string(),
                category: HotspotCategory::Authentication,
                priority: HotspotPriority::High,
                file_path: "test.py".to_string(),
                line_start: 1,
                line_end: None,
                code_snippet: String::new(),
                description: String::new(),
                review_guidance: String::new(),
                security_questions: vec![],
                resolution: HotspotResolution::ToReview,
                resolution_comment: None,
                reviewed_by: None,
                reviewed_at: None,
                cwe_ids: vec![],
                owasp_ids: vec![],
                created_at: chrono::Utc::now(),
            },
        ];

        let stats = detector.get_stats(&hotspots);
        assert_eq!(stats.total, 1);
        assert_eq!(stats.by_category.get(&HotspotCategory::Authentication), Some(&1));
    }
}
