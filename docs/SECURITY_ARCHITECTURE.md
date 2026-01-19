# HeroForge Security Architecture

This document describes the security controls and architecture implemented in HeroForge to protect customer data and ensure secure operations.

## Overview

HeroForge is built with security as a core principle, implementing defense-in-depth strategies across all layers of the application.

---

## Authentication & Access Control

### Password Security
- **Bcrypt hashing** with configurable cost factor (default: 12)
- Passwords are never stored in plaintext
- Cost factor adjustable via `BCRYPT_COST` environment variable

### Multi-Factor Authentication (MFA)
- TOTP-based MFA (RFC 6238)
- MFA secrets encrypted at rest using `TOTP_ENCRYPTION_KEY`
- Compatible with standard authenticator apps (Google Authenticator, Authy, 1Password)

### JSON Web Tokens (JWT)
- Signed tokens for session management
- Short-lived access tokens with refresh token rotation
- Configurable expiration times
- Secret key managed via `JWT_SECRET` environment variable

### Account Protection
- Account lockout after failed login attempts
- Progressive delays on repeated failures
- IP-based tracking for abuse detection

### Single Sign-On (SSO)
- SAML 2.0 support for enterprise identity providers
- OAuth 2.0 / OpenID Connect integration
- Just-in-time user provisioning

### Role-Based Access Control (RBAC)
- Fine-grained permission system
- Predefined roles: Admin, Team User, Professional User, Solo User, Free User
- Custom role creation for enterprise deployments

---

## Data Protection

### Database Encryption
- **SQLCipher** integration for AES-256 database encryption
- Encryption key managed via `DATABASE_ENCRYPTION_KEY`
- Encryption at rest for all stored data
- Transparent encryption/decryption at the application layer

### Sensitive Data Handling
- TOTP secrets encrypted before storage
- VPN configurations encrypted with dedicated key
- Credential data isolated and encrypted
- No plaintext passwords in logs or error messages

### Data Isolation
- Per-organization data separation
- User data scoped to appropriate access levels
- Customer portal isolation from main application

---

## Network Security

### Transport Security
- TLS 1.3 enforced via Traefik reverse proxy
- Automatic certificate management (Let's Encrypt)
- HTTP Strict Transport Security (HSTS) with 1-year max-age
- Automatic HTTP to HTTPS redirection

### Security Headers (OWASP Best Practices)

| Header | Value | Purpose |
|--------|-------|---------|
| X-Content-Type-Options | nosniff | Prevent MIME type sniffing |
| X-Frame-Options | DENY | Prevent clickjacking |
| X-XSS-Protection | 1; mode=block | Legacy XSS protection |
| Referrer-Policy | strict-origin-when-cross-origin | Control referrer information |
| Content-Security-Policy | Comprehensive policy | Prevent XSS and injection attacks |
| Permissions-Policy | Restricted | Disable unnecessary browser features |
| Strict-Transport-Security | max-age=31536000; includeSubDomains | Enforce HTTPS |

### Content Security Policy (CSP)
```
default-src 'self';
script-src 'self';
style-src 'self' 'unsafe-inline';
img-src 'self' data:;
font-src 'self';
connect-src 'self' ws: wss:;
object-src 'none';
base-uri 'self';
form-action 'self';
```

---

## Rate Limiting

Implemented using actix-governor per OWASP guidelines:

| Endpoint Category | Limit | Window | Purpose |
|-------------------|-------|--------|---------|
| Authentication | 5 requests | per minute | Brute force prevention |
| General API | 100 requests | per minute | DoS prevention |
| Scan Creation | 10 requests | per hour | Resource abuse prevention |

### Rate Limit Monitoring
- Real-time tracking of rate-limited requests
- Per-IP statistics and analytics
- Dashboard visibility into rate limit events
- User-Agent tracking for abuse detection

---

## Infrastructure Security

### Container Hardening
- Non-root user execution where possible
- Resource limits (CPU, memory)
- Network isolation via Docker networks
- Read-only filesystem where applicable

### Deployment Security
- Secrets management via environment variables
- No secrets in source code or Docker images
- Automated dependency updates via Dependabot
- Security scanning via cargo-audit and cargo-deny

### Backup & Recovery
- Automated daily database backups
- Backup integrity verification with SHA-256 checksums
- 30-day backup retention
- Encrypted backup storage available

---

## Application Security

### Input Validation
- Strict input validation on all API endpoints
- Parameterized database queries (sqlx)
- Path traversal prevention
- Size limits on uploads and requests

### Error Handling
- Sentry integration for error tracking
- No sensitive data in error messages
- Structured logging without PII
- Graceful degradation on failures

### Dependencies
- **Dependabot** for automated dependency updates
- **cargo-audit** for vulnerability scanning
- **cargo-deny** for license and security policy enforcement
- Regular dependency review and updates

---

## Monitoring & Logging

### Health Endpoints
- `/health/live` - Liveness probe (container running)
- `/health/ready` - Readiness probe (dependencies connected)

### External Monitoring
- UptimeRobot integration for availability monitoring
- Sentry for error tracking and performance monitoring
- Structured logging for security event analysis

### Audit Logging
- Authentication events logged
- Scan creation and completion tracked
- Admin actions audited
- API access logs available

---

## Compliance Frameworks Supported

HeroForge includes built-in compliance scanning and reporting for:

### US Federal
- FedRAMP
- CMMC 2.0
- FISMA
- NIST 800-53, 800-171, 800-82

### Industry Standards
- CIS Benchmarks
- OWASP Top 10
- PCI-DSS 4.0
- SOC 2
- ISO 27001:2022

### Healthcare & Education
- HIPAA
- HITRUST CSF
- FERPA

### International
- GDPR
- NIS2 Directive
- Cyber Essentials (UK)
- Australian ISM

---

## Security Development Lifecycle

### Code Review
- All changes require review before merge
- Security-focused code review checklist
- Automated checks via CI/CD pipeline

### CI/CD Security Pipeline
| Job | Purpose |
|-----|---------|
| cargo fmt | Code formatting consistency |
| cargo clippy | Static analysis with warnings as errors |
| cargo audit | Dependency vulnerability scanning |
| cargo deny | License and security policy |
| Semgrep SAST | Static application security testing |
| TruffleHog | Secret detection in code |

### Testing
- Unit tests for security-critical functions
- Integration tests for authentication flows
- Test coverage monitoring

---

## Incident Response

### Severity Levels
| Level | Description | Response Time |
|-------|-------------|---------------|
| P1 - Critical | Security breach, data loss, complete outage | Immediate |
| P2 - High | Major feature broken, significant security issue | < 4 hours |
| P3 - Medium | Feature partially broken, moderate impact | < 24 hours |
| P4 - Low | Minor issue, workaround available | < 1 week |

### Response Procedures
1. Incident detection and initial assessment
2. Containment and immediate mitigation
3. Root cause analysis
4. Recovery and verification
5. Post-incident review and documentation

### Communication
- Status page for service availability
- Email notifications for affected users (P1/P2)
- Transparent post-incident reports

---

## Security Contact

For security vulnerabilities or concerns:
- Email: security@heroforge.io
- See SECURITY.md for responsible disclosure policy

---

## Certifications & Audits

### Current State (Bootstrap Phase)
- Internal security hardening completed
- Automated security scanning in CI/CD
- Dependency vulnerability monitoring

### Planned (Revenue Dependent)
- Third-party penetration test
- SOC 2 Type II certification
- Annual security audits

---

*Last updated: January 2026*
