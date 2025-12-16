//! OWASP Top 10 2021 Compliance Framework
//!
//! The OWASP Top 10 is the standard awareness document for developers and web
//! application security. It represents a broad consensus about the most critical
//! security risks to web applications.
//!
//! 2021 Categories:
//! A01:2021 - Broken Access Control
//! A02:2021 - Cryptographic Failures
//! A03:2021 - Injection
//! A04:2021 - Insecure Design
//! A05:2021 - Security Misconfiguration
//! A06:2021 - Vulnerable and Outdated Components
//! A07:2021 - Identification and Authentication Failures
//! A08:2021 - Software and Data Integrity Failures
//! A09:2021 - Security Logging and Monitoring Failures
//! A10:2021 - Server-Side Request Forgery (SSRF)

use crate::compliance::types::{ComplianceControl, ComplianceFramework, ControlPriority};
use crate::types::Severity;

/// Total number of OWASP Top 10 controls (including sub-controls)
pub const CONTROL_COUNT: usize = 40;

/// Get all OWASP Top 10 2021 controls
pub fn get_controls() -> Vec<ComplianceControl> {
    vec![
        // =================================================================
        // A01:2021 - Broken Access Control (moved from #5 to #1)
        // =================================================================
        ComplianceControl {
            id: "owasp-a01-1".to_string(),
            control_id: "A01.1".to_string(),
            framework: ComplianceFramework::OwaspTop10,
            title: "Enforce least privilege access".to_string(),
            description: "Access to resources should be denied by default, except for public resources. Enforce least privilege principle.".to_string(),
            category: "A01:2021 - Broken Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["CWE-284".to_string(), "NIST-AC-6".to_string()],
            remediation_guidance: Some("Implement deny by default access control. Minimize CORS usage. Enforce record ownership.".to_string()),
        },
        ComplianceControl {
            id: "owasp-a01-2".to_string(),
            control_id: "A01.2".to_string(),
            framework: ComplianceFramework::OwaspTop10,
            title: "Disable directory listing".to_string(),
            description: "Disable web server directory listing and ensure file metadata is not present in web roots.".to_string(),
            category: "A01:2021 - Broken Access Control".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["CWE-548".to_string()],
            remediation_guidance: Some("Configure web server to disable directory indexing. Remove .git and backup files from web roots.".to_string()),
        },
        ComplianceControl {
            id: "owasp-a01-3".to_string(),
            control_id: "A01.3".to_string(),
            framework: ComplianceFramework::OwaspTop10,
            title: "Rate limit API access".to_string(),
            description: "Rate limit API and controller access to minimize harm from automated attack tools.".to_string(),
            category: "A01:2021 - Broken Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["CWE-770".to_string()],
            remediation_guidance: Some("Implement rate limiting on APIs. Use throttling for sensitive operations.".to_string()),
        },
        ComplianceControl {
            id: "owasp-a01-4".to_string(),
            control_id: "A01.4".to_string(),
            framework: ComplianceFramework::OwaspTop10,
            title: "Invalidate JWT tokens on logout".to_string(),
            description: "JWT tokens should be invalidated on the server after logout. Prefer short-lived tokens.".to_string(),
            category: "A01:2021 - Broken Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["CWE-613".to_string()],
            remediation_guidance: Some("Implement token blacklisting or use short-lived JWTs with refresh tokens.".to_string()),
        },

        // =================================================================
        // A02:2021 - Cryptographic Failures (previously Sensitive Data Exposure)
        // =================================================================
        ComplianceControl {
            id: "owasp-a02-1".to_string(),
            control_id: "A02.1".to_string(),
            framework: ComplianceFramework::OwaspTop10,
            title: "Encrypt data in transit".to_string(),
            description: "All data must be encrypted in transit using TLS 1.2+ with strong cipher suites.".to_string(),
            category: "A02:2021 - Cryptographic Failures".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["CWE-319".to_string(), "CWE-326".to_string()],
            remediation_guidance: Some("Enforce HTTPS with TLS 1.2+. Implement HSTS. Disable weak ciphers (RC4, DES, 3DES).".to_string()),
        },
        ComplianceControl {
            id: "owasp-a02-2".to_string(),
            control_id: "A02.2".to_string(),
            framework: ComplianceFramework::OwaspTop10,
            title: "Strong password hashing".to_string(),
            description: "Store passwords using strong adaptive and salted hashing functions (Argon2, scrypt, bcrypt, PBKDF2).".to_string(),
            category: "A02:2021 - Cryptographic Failures".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["CWE-916".to_string()],
            remediation_guidance: Some("Use Argon2id, bcrypt, or scrypt with appropriate work factors. Never use MD5/SHA1 for passwords.".to_string()),
        },
        ComplianceControl {
            id: "owasp-a02-3".to_string(),
            control_id: "A02.3".to_string(),
            framework: ComplianceFramework::OwaspTop10,
            title: "Disable caching for sensitive data".to_string(),
            description: "Disable caching for responses that contain sensitive data.".to_string(),
            category: "A02:2021 - Cryptographic Failures".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["CWE-525".to_string()],
            remediation_guidance: Some("Set Cache-Control: no-store for sensitive responses. Implement proper Vary headers.".to_string()),
        },
        ComplianceControl {
            id: "owasp-a02-4".to_string(),
            control_id: "A02.4".to_string(),
            framework: ComplianceFramework::OwaspTop10,
            title: "No deprecated cryptographic functions".to_string(),
            description: "Do not use deprecated cryptographic functions (MD5, SHA1, DES, RC4).".to_string(),
            category: "A02:2021 - Cryptographic Failures".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["CWE-327".to_string(), "CWE-328".to_string()],
            remediation_guidance: Some("Use SHA-256 or SHA-3 for hashing. Use AES-256-GCM for encryption. Avoid MD5/SHA1/DES.".to_string()),
        },

        // =================================================================
        // A03:2021 - Injection (was #1 in 2017)
        // =================================================================
        ComplianceControl {
            id: "owasp-a03-1".to_string(),
            control_id: "A03.1".to_string(),
            framework: ComplianceFramework::OwaspTop10,
            title: "SQL Injection Prevention".to_string(),
            description: "Use parameterized queries or prepared statements. Never concatenate user input into queries.".to_string(),
            category: "A03:2021 - Injection".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["CWE-89".to_string()],
            remediation_guidance: Some("Use parameterized queries, ORM frameworks, or stored procedures. Validate and sanitize all inputs.".to_string()),
        },
        ComplianceControl {
            id: "owasp-a03-2".to_string(),
            control_id: "A03.2".to_string(),
            framework: ComplianceFramework::OwaspTop10,
            title: "Command Injection Prevention".to_string(),
            description: "Avoid calling OS commands directly. Use parameterized APIs when necessary.".to_string(),
            category: "A03:2021 - Injection".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["CWE-78".to_string()],
            remediation_guidance: Some("Avoid system() calls. Use language-specific APIs. Validate and escape all inputs.".to_string()),
        },
        ComplianceControl {
            id: "owasp-a03-3".to_string(),
            control_id: "A03.3".to_string(),
            framework: ComplianceFramework::OwaspTop10,
            title: "XSS Prevention".to_string(),
            description: "Escape user-supplied data in HTML output. Use auto-escaping template engines.".to_string(),
            category: "A03:2021 - Injection".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["CWE-79".to_string()],
            remediation_guidance: Some("Use context-aware output encoding. Implement Content-Security-Policy headers. Use DOMPurify for HTML.".to_string()),
        },
        ComplianceControl {
            id: "owasp-a03-4".to_string(),
            control_id: "A03.4".to_string(),
            framework: ComplianceFramework::OwaspTop10,
            title: "LDAP Injection Prevention".to_string(),
            description: "Escape special characters in LDAP queries. Use parameterized LDAP APIs.".to_string(),
            category: "A03:2021 - Injection".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["CWE-90".to_string()],
            remediation_guidance: Some("Escape LDAP special characters. Use strongly typed APIs. Validate DN components.".to_string()),
        },

        // =================================================================
        // A04:2021 - Insecure Design (NEW category)
        // =================================================================
        ComplianceControl {
            id: "owasp-a04-1".to_string(),
            control_id: "A04.1".to_string(),
            framework: ComplianceFramework::OwaspTop10,
            title: "Threat modeling".to_string(),
            description: "Use threat modeling for critical authentication, access control, business logic, and key flows.".to_string(),
            category: "A04:2021 - Insecure Design".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["CWE-840".to_string()],
            remediation_guidance: Some("Perform threat modeling during design phase. Document trust boundaries and data flows.".to_string()),
        },
        ComplianceControl {
            id: "owasp-a04-2".to_string(),
            control_id: "A04.2".to_string(),
            framework: ComplianceFramework::OwaspTop10,
            title: "Secure design patterns".to_string(),
            description: "Use secure design patterns and reference architectures. Integrate security in all phases.".to_string(),
            category: "A04:2021 - Insecure Design".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["CWE-1059".to_string()],
            remediation_guidance: Some("Follow secure design principles. Use defense in depth. Apply principle of least privilege.".to_string()),
        },
        ComplianceControl {
            id: "owasp-a04-3".to_string(),
            control_id: "A04.3".to_string(),
            framework: ComplianceFramework::OwaspTop10,
            title: "Limit resource consumption".to_string(),
            description: "Limit resource consumption by user or service to prevent DoS.".to_string(),
            category: "A04:2021 - Insecure Design".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["CWE-400".to_string(), "CWE-770".to_string()],
            remediation_guidance: Some("Implement request limits, timeouts, and circuit breakers. Monitor resource usage.".to_string()),
        },

        // =================================================================
        // A05:2021 - Security Misconfiguration (was #6)
        // =================================================================
        ComplianceControl {
            id: "owasp-a05-1".to_string(),
            control_id: "A05.1".to_string(),
            framework: ComplianceFramework::OwaspTop10,
            title: "Remove unnecessary features".to_string(),
            description: "Remove or do not install unused features, components, and documentation.".to_string(),
            category: "A05:2021 - Security Misconfiguration".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["CWE-1002".to_string()],
            remediation_guidance: Some("Disable unused services. Remove sample/demo applications. Minimize attack surface.".to_string()),
        },
        ComplianceControl {
            id: "owasp-a05-2".to_string(),
            control_id: "A05.2".to_string(),
            framework: ComplianceFramework::OwaspTop10,
            title: "Disable debug features in production".to_string(),
            description: "Ensure debug features are disabled in production and error messages don't reveal sensitive information.".to_string(),
            category: "A05:2021 - Security Misconfiguration".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["CWE-489".to_string(), "CWE-209".to_string()],
            remediation_guidance: Some("Disable debug mode. Use generic error pages. Log detailed errors server-side only.".to_string()),
        },
        ComplianceControl {
            id: "owasp-a05-3".to_string(),
            control_id: "A05.3".to_string(),
            framework: ComplianceFramework::OwaspTop10,
            title: "Security headers configured".to_string(),
            description: "Send appropriate security headers (CSP, X-Frame-Options, HSTS, etc.).".to_string(),
            category: "A05:2021 - Security Misconfiguration".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["CWE-693".to_string()],
            remediation_guidance: Some("Implement CSP, X-Frame-Options: DENY, X-Content-Type-Options: nosniff, HSTS, Referrer-Policy.".to_string()),
        },
        ComplianceControl {
            id: "owasp-a05-4".to_string(),
            control_id: "A05.4".to_string(),
            framework: ComplianceFramework::OwaspTop10,
            title: "Change default credentials".to_string(),
            description: "All default credentials must be changed before deployment.".to_string(),
            category: "A05:2021 - Security Misconfiguration".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["CWE-798".to_string(), "CWE-1392".to_string()],
            remediation_guidance: Some("Change all default passwords. Remove default accounts. Enforce strong password policy.".to_string()),
        },
        ComplianceControl {
            id: "owasp-a05-5".to_string(),
            control_id: "A05.5".to_string(),
            framework: ComplianceFramework::OwaspTop10,
            title: "Secure cloud storage permissions".to_string(),
            description: "Ensure cloud storage permissions are properly configured (no public S3 buckets).".to_string(),
            category: "A05:2021 - Security Misconfiguration".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["CWE-284".to_string()],
            remediation_guidance: Some("Review S3 bucket policies. Disable public access. Enable access logging.".to_string()),
        },

        // =================================================================
        // A06:2021 - Vulnerable and Outdated Components
        // =================================================================
        ComplianceControl {
            id: "owasp-a06-1".to_string(),
            control_id: "A06.1".to_string(),
            framework: ComplianceFramework::OwaspTop10,
            title: "Component inventory".to_string(),
            description: "Maintain an inventory of all component versions (client-side and server-side).".to_string(),
            category: "A06:2021 - Vulnerable and Outdated Components".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["CWE-1104".to_string()],
            remediation_guidance: Some("Use software composition analysis (SCA). Generate SBOM. Track dependencies.".to_string()),
        },
        ComplianceControl {
            id: "owasp-a06-2".to_string(),
            control_id: "A06.2".to_string(),
            framework: ComplianceFramework::OwaspTop10,
            title: "Remove unused dependencies".to_string(),
            description: "Remove unused dependencies, unnecessary features, components, files, and documentation.".to_string(),
            category: "A06:2021 - Vulnerable and Outdated Components".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["CWE-1104".to_string()],
            remediation_guidance: Some("Audit package.json/Cargo.toml regularly. Remove unused packages. Use dependency pruning tools.".to_string()),
        },
        ComplianceControl {
            id: "owasp-a06-3".to_string(),
            control_id: "A06.3".to_string(),
            framework: ComplianceFramework::OwaspTop10,
            title: "Monitor CVE databases".to_string(),
            description: "Continuously monitor CVE/NVD databases and apply patches for vulnerable components.".to_string(),
            category: "A06:2021 - Vulnerable and Outdated Components".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["CWE-1035".to_string()],
            remediation_guidance: Some("Subscribe to security advisories. Use Dependabot/Renovate. Run regular vulnerability scans.".to_string()),
        },
        ComplianceControl {
            id: "owasp-a06-4".to_string(),
            control_id: "A06.4".to_string(),
            framework: ComplianceFramework::OwaspTop10,
            title: "Obtain components from official sources".to_string(),
            description: "Only obtain components from official sources over secure links. Prefer signed packages.".to_string(),
            category: "A06:2021 - Vulnerable and Outdated Components".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["CWE-829".to_string()],
            remediation_guidance: Some("Use official package registries. Verify package signatures. Use lockfiles.".to_string()),
        },

        // =================================================================
        // A07:2021 - Identification and Authentication Failures
        // =================================================================
        ComplianceControl {
            id: "owasp-a07-1".to_string(),
            control_id: "A07.1".to_string(),
            framework: ComplianceFramework::OwaspTop10,
            title: "Multi-factor authentication".to_string(),
            description: "Implement multi-factor authentication to prevent automated attacks.".to_string(),
            category: "A07:2021 - Identification and Authentication Failures".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["CWE-308".to_string()],
            remediation_guidance: Some("Implement TOTP/WebAuthn MFA. Require MFA for privileged operations.".to_string()),
        },
        ComplianceControl {
            id: "owasp-a07-2".to_string(),
            control_id: "A07.2".to_string(),
            framework: ComplianceFramework::OwaspTop10,
            title: "Weak password prevention".to_string(),
            description: "Do not ship or deploy with default credentials. Check passwords against breached password lists.".to_string(),
            category: "A07:2021 - Identification and Authentication Failures".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["CWE-521".to_string()],
            remediation_guidance: Some("Check passwords against Have I Been Pwned API. Enforce minimum length 12+ characters.".to_string()),
        },
        ComplianceControl {
            id: "owasp-a07-3".to_string(),
            control_id: "A07.3".to_string(),
            framework: ComplianceFramework::OwaspTop10,
            title: "Account lockout".to_string(),
            description: "Limit or delay failed login attempts. Log failures and alert on credential stuffing.".to_string(),
            category: "A07:2021 - Identification and Authentication Failures".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["CWE-307".to_string()],
            remediation_guidance: Some("Implement progressive delays. Lock accounts after 5-10 failures. Use CAPTCHA.".to_string()),
        },
        ComplianceControl {
            id: "owasp-a07-4".to_string(),
            control_id: "A07.4".to_string(),
            framework: ComplianceFramework::OwaspTop10,
            title: "Secure session management".to_string(),
            description: "Use secure, randomly generated session IDs. Invalidate sessions after logout.".to_string(),
            category: "A07:2021 - Identification and Authentication Failures".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["CWE-384".to_string(), "CWE-613".to_string()],
            remediation_guidance: Some("Use framework session management. Set Secure, HttpOnly, SameSite cookie flags.".to_string()),
        },

        // =================================================================
        // A08:2021 - Software and Data Integrity Failures (NEW)
        // =================================================================
        ComplianceControl {
            id: "owasp-a08-1".to_string(),
            control_id: "A08.1".to_string(),
            framework: ComplianceFramework::OwaspTop10,
            title: "Verify digital signatures".to_string(),
            description: "Verify digital signatures on software/data from expected sources.".to_string(),
            category: "A08:2021 - Software and Data Integrity Failures".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["CWE-494".to_string()],
            remediation_guidance: Some("Verify GPG signatures. Use Sigstore/cosign. Implement supply chain security.".to_string()),
        },
        ComplianceControl {
            id: "owasp-a08-2".to_string(),
            control_id: "A08.2".to_string(),
            framework: ComplianceFramework::OwaspTop10,
            title: "Secure CI/CD pipeline".to_string(),
            description: "Ensure CI/CD pipeline has proper segregation, configuration, and access control.".to_string(),
            category: "A08:2021 - Software and Data Integrity Failures".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["CWE-915".to_string()],
            remediation_guidance: Some("Use OIDC for CI/CD auth. Implement branch protection. Sign commits and artifacts.".to_string()),
        },
        ComplianceControl {
            id: "owasp-a08-3".to_string(),
            control_id: "A08.3".to_string(),
            framework: ComplianceFramework::OwaspTop10,
            title: "Secure deserialization".to_string(),
            description: "Implement integrity checks on serialized data. Enforce strict type constraints.".to_string(),
            category: "A08:2021 - Software and Data Integrity Failures".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["CWE-502".to_string()],
            remediation_guidance: Some("Avoid native deserialization. Use JSON/XML with strict schemas. Sign serialized objects.".to_string()),
        },

        // =================================================================
        // A09:2021 - Security Logging and Monitoring Failures
        // =================================================================
        ComplianceControl {
            id: "owasp-a09-1".to_string(),
            control_id: "A09.1".to_string(),
            framework: ComplianceFramework::OwaspTop10,
            title: "Log security events".to_string(),
            description: "Log all login, access control, and server-side input validation failures.".to_string(),
            category: "A09:2021 - Security Logging and Monitoring Failures".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["CWE-778".to_string()],
            remediation_guidance: Some("Log auth events, access denials, validation failures. Include context for forensics.".to_string()),
        },
        ComplianceControl {
            id: "owasp-a09-2".to_string(),
            control_id: "A09.2".to_string(),
            framework: ComplianceFramework::OwaspTop10,
            title: "Centralized log management".to_string(),
            description: "Ensure logs are generated in a format for centralized log management solutions.".to_string(),
            category: "A09:2021 - Security Logging and Monitoring Failures".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["CWE-778".to_string()],
            remediation_guidance: Some("Use structured logging (JSON). Ship to SIEM. Implement log retention policy.".to_string()),
        },
        ComplianceControl {
            id: "owasp-a09-3".to_string(),
            control_id: "A09.3".to_string(),
            framework: ComplianceFramework::OwaspTop10,
            title: "Alerting and response".to_string(),
            description: "Establish effective monitoring and alerting for suspicious activities.".to_string(),
            category: "A09:2021 - Security Logging and Monitoring Failures".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["CWE-223".to_string()],
            remediation_guidance: Some("Configure alerts for failed logins, privilege escalation. Create incident response runbooks.".to_string()),
        },
        ComplianceControl {
            id: "owasp-a09-4".to_string(),
            control_id: "A09.4".to_string(),
            framework: ComplianceFramework::OwaspTop10,
            title: "Prevent log injection".to_string(),
            description: "Ensure high-value transactions have audit trail with integrity controls.".to_string(),
            category: "A09:2021 - Security Logging and Monitoring Failures".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["CWE-117".to_string()],
            remediation_guidance: Some("Sanitize log inputs. Use append-only log storage. Implement log integrity verification.".to_string()),
        },

        // =================================================================
        // A10:2021 - Server-Side Request Forgery (SSRF) (NEW)
        // =================================================================
        ComplianceControl {
            id: "owasp-a10-1".to_string(),
            control_id: "A10.1".to_string(),
            framework: ComplianceFramework::OwaspTop10,
            title: "Validate user-supplied URLs".to_string(),
            description: "Sanitize and validate all client-supplied URLs. Disable HTTP redirections.".to_string(),
            category: "A10:2021 - Server-Side Request Forgery".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["CWE-918".to_string()],
            remediation_guidance: Some("Allowlist permitted URL schemes, hosts, ports. Block requests to internal networks.".to_string()),
        },
        ComplianceControl {
            id: "owasp-a10-2".to_string(),
            control_id: "A10.2".to_string(),
            framework: ComplianceFramework::OwaspTop10,
            title: "Network segmentation".to_string(),
            description: "Segment remote resource access in separate networks to reduce SSRF impact.".to_string(),
            category: "A10:2021 - Server-Side Request Forgery".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["CWE-918".to_string()],
            remediation_guidance: Some("Use network policies to restrict egress. Deploy in isolated subnets.".to_string()),
        },
        ComplianceControl {
            id: "owasp-a10-3".to_string(),
            control_id: "A10.3".to_string(),
            framework: ComplianceFramework::OwaspTop10,
            title: "Block metadata endpoints".to_string(),
            description: "Block access to cloud metadata endpoints (169.254.169.254) from application tier.".to_string(),
            category: "A10:2021 - Server-Side Request Forgery".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["CWE-918".to_string()],
            remediation_guidance: Some("Block 169.254.169.254 at network/firewall level. Use IMDSv2 with hop limit.".to_string()),
        },
        ComplianceControl {
            id: "owasp-a10-4".to_string(),
            control_id: "A10.4".to_string(),
            framework: ComplianceFramework::OwaspTop10,
            title: "Response handling".to_string(),
            description: "Do not send raw responses to clients. Validate response content type.".to_string(),
            category: "A10:2021 - Server-Side Request Forgery".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["CWE-918".to_string()],
            remediation_guidance: Some("Parse and validate remote responses. Use allowlist for content types. Limit response size.".to_string()),
        },
    ]
}

/// Get OWASP Top 10 categories
pub fn get_categories() -> Vec<String> {
    vec![
        "A01:2021 - Broken Access Control".to_string(),
        "A02:2021 - Cryptographic Failures".to_string(),
        "A03:2021 - Injection".to_string(),
        "A04:2021 - Insecure Design".to_string(),
        "A05:2021 - Security Misconfiguration".to_string(),
        "A06:2021 - Vulnerable and Outdated Components".to_string(),
        "A07:2021 - Identification and Authentication Failures".to_string(),
        "A08:2021 - Software and Data Integrity Failures".to_string(),
        "A09:2021 - Security Logging and Monitoring Failures".to_string(),
        "A10:2021 - Server-Side Request Forgery".to_string(),
    ]
}

/// Map vulnerability patterns to OWASP Top 10 controls
pub fn map_vulnerability(
    vuln_title: &str,
    _cve_id: Option<&str>,
    port: Option<u16>,
    service: Option<&str>,
) -> Vec<(String, Severity)> {
    let mut mappings = Vec::new();
    let title_lower = vuln_title.to_lowercase();

    // A01 - Broken Access Control
    if title_lower.contains("directory listing")
        || title_lower.contains("directory traversal")
        || title_lower.contains("path traversal")
    {
        mappings.push(("owasp-a01-2".to_string(), Severity::High));
    }
    if title_lower.contains("unauthorized access")
        || title_lower.contains("access control")
        || title_lower.contains("privilege escalation")
        || title_lower.contains("idor")
    {
        mappings.push(("owasp-a01-1".to_string(), Severity::Critical));
    }

    // A02 - Cryptographic Failures
    if title_lower.contains("ssl") || title_lower.contains("tls") {
        if title_lower.contains("weak")
            || title_lower.contains("expired")
            || title_lower.contains("self-signed")
            || title_lower.contains("untrusted")
        {
            mappings.push(("owasp-a02-1".to_string(), Severity::High));
        }
    }
    if title_lower.contains("md5") || title_lower.contains("sha1") || title_lower.contains("des") {
        mappings.push(("owasp-a02-4".to_string(), Severity::High));
    }
    if title_lower.contains("cleartext")
        || title_lower.contains("plaintext")
        || title_lower.contains("unencrypted")
    {
        mappings.push(("owasp-a02-1".to_string(), Severity::High));
    }

    // A03 - Injection
    if title_lower.contains("sql injection") || title_lower.contains("sqli") {
        mappings.push(("owasp-a03-1".to_string(), Severity::Critical));
    }
    if title_lower.contains("command injection")
        || title_lower.contains("os command")
        || title_lower.contains("rce")
        || title_lower.contains("remote code execution")
    {
        mappings.push(("owasp-a03-2".to_string(), Severity::Critical));
    }
    if title_lower.contains("xss")
        || title_lower.contains("cross-site scripting")
        || title_lower.contains("script injection")
    {
        mappings.push(("owasp-a03-3".to_string(), Severity::High));
    }
    if title_lower.contains("ldap injection") {
        mappings.push(("owasp-a03-4".to_string(), Severity::High));
    }

    // A05 - Security Misconfiguration
    if title_lower.contains("default password")
        || title_lower.contains("default credential")
        || title_lower.contains("factory default")
    {
        mappings.push(("owasp-a05-4".to_string(), Severity::Critical));
    }
    if title_lower.contains("debug")
        || title_lower.contains("stack trace")
        || title_lower.contains("verbose error")
    {
        mappings.push(("owasp-a05-2".to_string(), Severity::Medium));
    }
    if title_lower.contains("missing header")
        || title_lower.contains("security header")
        || title_lower.contains("csp")
        || title_lower.contains("hsts")
    {
        mappings.push(("owasp-a05-3".to_string(), Severity::Medium));
    }
    if title_lower.contains("s3 bucket") || title_lower.contains("public bucket") {
        mappings.push(("owasp-a05-5".to_string(), Severity::Critical));
    }

    // A06 - Vulnerable and Outdated Components
    if title_lower.contains("outdated")
        || title_lower.contains("end of life")
        || title_lower.contains("unsupported")
        || title_lower.contains("vulnerable version")
    {
        mappings.push(("owasp-a06-3".to_string(), Severity::High));
    }

    // A07 - Identification and Authentication Failures
    if title_lower.contains("weak password")
        || title_lower.contains("password policy")
        || title_lower.contains("credential")
    {
        mappings.push(("owasp-a07-2".to_string(), Severity::High));
    }
    if title_lower.contains("brute force")
        || title_lower.contains("no lockout")
        || title_lower.contains("rate limit")
    {
        mappings.push(("owasp-a07-3".to_string(), Severity::High));
    }
    if title_lower.contains("session fixation")
        || title_lower.contains("session hijack")
        || title_lower.contains("insecure cookie")
    {
        mappings.push(("owasp-a07-4".to_string(), Severity::High));
    }

    // A08 - Software and Data Integrity Failures
    if title_lower.contains("deserialization")
        || title_lower.contains("insecure deserial")
        || title_lower.contains("object injection")
    {
        mappings.push(("owasp-a08-3".to_string(), Severity::Critical));
    }

    // A10 - SSRF
    if title_lower.contains("ssrf")
        || title_lower.contains("server-side request")
        || title_lower.contains("url injection")
    {
        mappings.push(("owasp-a10-1".to_string(), Severity::High));
    }
    if title_lower.contains("metadata") && title_lower.contains("169.254") {
        mappings.push(("owasp-a10-3".to_string(), Severity::Critical));
    }

    // Port-based mappings for web services
    if let Some(p) = port {
        if p == 80 || p == 8080 || p == 8000 {
            // HTTP without HTTPS
            if !title_lower.contains("redirect") {
                mappings.push(("owasp-a02-1".to_string(), Severity::Medium));
            }
        }
    }

    // Service-based mappings
    if let Some(svc) = service {
        let svc_lower = svc.to_lowercase();
        if svc_lower.contains("http") && !svc_lower.contains("https") {
            // Plain HTTP service
            if port != Some(443) {
                // Only flag if not on HTTPS port
            }
        }
    }

    mappings
}
