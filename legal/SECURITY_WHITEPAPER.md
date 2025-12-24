# HeroForge Security Whitepaper

**Version:** 1.0
**Last Updated:** December 24, 2024
**Classification:** Public

---

## Executive Summary

HeroForge is an enterprise-grade security assessment platform designed for authorized penetration testing and vulnerability management. As a security tool handling sensitive reconnaissance data, HeroForge is built with security at its core.

This whitepaper provides a comprehensive overview of HeroForge's security architecture, controls, and practices. It is intended for security teams, compliance officers, and IT decision-makers evaluating HeroForge for their organization.

### Key Security Highlights

- **Encryption:** AES-256 database encryption (SQLCipher), TLS 1.2+ for all communications
- **Authentication:** Multi-factor authentication (TOTP), bcrypt password hashing, JWT tokens
- **Access Control:** Role-based access control (RBAC) with granular permissions
- **Audit Logging:** Comprehensive logging of all security-relevant events
- **Compliance:** Built to support PCI-DSS, HIPAA, SOC 2, and GDPR requirements
- **Secure Architecture:** Defense-in-depth with multiple security layers

---

## Table of Contents

1. [Security Architecture Overview](#1-security-architecture-overview)
2. [Authentication and Access Control](#2-authentication-and-access-control)
3. [Data Protection](#3-data-protection)
4. [Network Security](#4-network-security)
5. [Application Security](#5-application-security)
6. [Infrastructure Security](#6-infrastructure-security)
7. [Audit and Logging](#7-audit-and-logging)
8. [Incident Response](#8-incident-response)
9. [Secure Development Lifecycle](#9-secure-development-lifecycle)
10. [Third-Party Security](#10-third-party-security)
11. [Compliance Alignment](#11-compliance-alignment)
12. [Security Roadmap](#12-security-roadmap)

---

## 1. Security Architecture Overview

### 1.1 Defense-in-Depth

HeroForge implements a defense-in-depth strategy with multiple security layers:

```
┌─────────────────────────────────────────────────────────────┐
│                    Edge Security Layer                       │
│    (TLS Termination, Rate Limiting, DDoS Protection)        │
├─────────────────────────────────────────────────────────────┤
│                  Application Security Layer                  │
│    (Authentication, Authorization, Input Validation)        │
├─────────────────────────────────────────────────────────────┤
│                    Data Security Layer                       │
│    (Encryption at Rest, Encryption in Transit)              │
├─────────────────────────────────────────────────────────────┤
│                Infrastructure Security Layer                 │
│    (Container Isolation, Network Segmentation)              │
└─────────────────────────────────────────────────────────────┘
```

### 1.2 Architecture Components

| Component | Technology | Security Features |
|-----------|------------|-------------------|
| Reverse Proxy | Traefik | TLS termination, automatic certificate renewal |
| Web Server | Actix-web (Rust) | Memory-safe language, async I/O |
| Database | SQLite + SQLCipher | AES-256 encryption, ACID compliance |
| Authentication | JWT + bcrypt | Stateless tokens, secure password storage |
| Frontend | React + TypeScript | XSS prevention, CSP headers |

### 1.3 Deployment Model

HeroForge supports multiple deployment options:

- **Cloud Hosted:** Fully managed SaaS deployment
- **Self-Hosted:** On-premises deployment with customer control
- **Hybrid:** Scan agents on-premises, management in cloud

---

## 2. Authentication and Access Control

### 2.1 Authentication Mechanisms

#### Password Authentication
- **Hashing Algorithm:** bcrypt with configurable cost factor (default: 12)
- **Minimum Requirements:** 8 characters, complexity enforced
- **Password History:** Previous passwords tracked to prevent reuse

#### Multi-Factor Authentication (MFA)
- **Method:** Time-based One-Time Password (TOTP)
- **Standard:** RFC 6238 compliant
- **Encryption:** TOTP secrets encrypted at rest with dedicated key
- **Backup Codes:** Generated for account recovery

#### Session Management
- **Token Type:** JSON Web Tokens (JWT)
- **Token Lifetime:** Configurable (default: 24 hours)
- **Refresh Tokens:** Separate long-lived tokens for session renewal
- **Token Revocation:** Immediate invalidation on logout/password change

### 2.2 Account Protection

| Protection | Implementation |
|------------|----------------|
| Brute Force Prevention | Account lockout after 5 failed attempts |
| Lockout Duration | Progressive (15 min → 30 min → 1 hour) |
| Rate Limiting | 5 auth requests per minute per IP |
| Session Binding | Tokens bound to user agent and IP range |

### 2.3 Role-Based Access Control (RBAC)

HeroForge implements granular RBAC with the following predefined roles:

| Role | Permissions |
|------|-------------|
| User | Create/view own scans, generate reports |
| Analyst | View all scans, manage vulnerabilities |
| Manager | Manage team, assign work, view analytics |
| Admin | Full system access, user management, settings |

Custom roles can be created with specific permission combinations.

### 2.4 Permission Categories

- **Scan Permissions:** create, read, update, delete, execute
- **Report Permissions:** generate, view, export, share
- **Asset Permissions:** manage, view, import, export
- **User Permissions:** manage, assign roles, audit
- **Settings Permissions:** configure, integrate, backup

---

## 3. Data Protection

### 3.1 Encryption at Rest

#### Database Encryption
- **Technology:** SQLCipher (SQLite encryption extension)
- **Algorithm:** AES-256-CBC
- **Key Derivation:** PBKDF2-HMAC-SHA512 with 256,000 iterations
- **Page Size:** 4096 bytes
- **Key Management:** Environment variable, not stored in code

#### Sensitive Field Encryption
Additional encryption for highly sensitive fields:
- API keys and tokens
- Integration credentials
- TOTP secrets

### 3.2 Encryption in Transit

| Connection Type | Protocol | Minimum Version |
|-----------------|----------|-----------------|
| HTTPS | TLS | 1.2 |
| WebSocket | WSS | TLS 1.2 |
| Database | Local | N/A (same-host) |

#### TLS Configuration
- **Cipher Suites:** Modern, secure suites only (ECDHE, AES-GCM)
- **Perfect Forward Secrecy:** Enabled via ECDHE
- **HSTS:** Strict-Transport-Security header enabled
- **Certificate Management:** Automatic renewal via Let's Encrypt

### 3.3 Data Classification

| Classification | Examples | Handling |
|----------------|----------|----------|
| Critical | Passwords, API keys, encryption keys | Encrypted, never logged |
| Sensitive | Scan results, vulnerability data | Encrypted at rest, access controlled |
| Internal | Configuration, metadata | Access controlled |
| Public | Documentation, policies | No restrictions |

### 3.4 Data Retention

| Data Type | Default Retention | Configurable |
|-----------|-------------------|--------------|
| Scan Results | 90 days | Yes |
| Audit Logs | 1 year | Yes |
| Account Data | Duration + 30 days | No |
| Backup Data | 90 days | Yes |

### 3.5 Data Disposal

- **Soft Delete:** Data marked as deleted, retained for recovery period
- **Hard Delete:** Cryptographic erasure, data overwritten
- **Backup Purge:** Expired backups automatically removed
- **Certificate of Destruction:** Available upon request

---

## 4. Network Security

### 4.1 Network Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        Internet                              │
└─────────────────────────┬───────────────────────────────────┘
                          │
                    ┌─────▼─────┐
                    │  Traefik  │  (TLS, Rate Limit, WAF)
                    └─────┬─────┘
                          │
              ┌───────────┼───────────┐
              │           │           │
        ┌─────▼─────┐ ┌───▼───┐ ┌─────▼─────┐
        │ HeroForge │ │ Redis │ │  MinIO    │
        │  Backend  │ │ Cache │ │  Storage  │
        └─────┬─────┘ └───────┘ └───────────┘
              │
        ┌─────▼─────┐
        │  SQLite   │
        │ (Encrypted)│
        └───────────┘
```

### 4.2 Network Controls

| Control | Implementation |
|---------|----------------|
| Firewall | Host-based (iptables/nftables) |
| Ingress Filtering | Only ports 80, 443 exposed |
| Egress Filtering | Whitelist for external services |
| Network Isolation | Docker network segmentation |

### 4.3 Rate Limiting

| Endpoint Category | Limit | Window |
|-------------------|-------|--------|
| Authentication | 5 requests | per minute |
| Scan Creation | 10 requests | per hour |
| API General | 100 requests | per minute |
| Report Generation | 20 requests | per hour |

### 4.4 DDoS Protection

- **Edge Protection:** Traefik with connection limits
- **Application Layer:** Rate limiting and request validation
- **Resource Limits:** Container CPU/memory limits prevent resource exhaustion

---

## 5. Application Security

### 5.1 Secure Coding Practices

#### Language Choice: Rust
HeroForge's backend is written in Rust, providing:
- **Memory Safety:** No buffer overflows, use-after-free, or null pointer dereferences
- **Thread Safety:** Compile-time data race prevention
- **Type Safety:** Strong type system prevents type confusion

#### Frontend: React + TypeScript
- **XSS Prevention:** React's automatic escaping
- **Type Safety:** TypeScript catches errors at compile time
- **Dependency Scanning:** Regular vulnerability scanning

### 5.2 Input Validation

| Input Type | Validation |
|------------|------------|
| IP Addresses | RFC 5321 format validation |
| Hostnames | DNS label validation |
| Port Numbers | Range validation (1-65535) |
| User Input | Sanitization, length limits |
| File Uploads | Type validation, size limits, virus scanning |

### 5.3 Output Encoding

- **HTML Context:** Automatic escaping via React
- **JSON Response:** Proper Content-Type headers
- **SQL Queries:** Parameterized queries only (sqlx)
- **Log Output:** Sensitive data redaction

### 5.4 Security Headers

```
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000; includeSubDomains
Referrer-Policy: strict-origin-when-cross-origin
```

### 5.5 API Security

- **Authentication:** JWT Bearer tokens required
- **Authorization:** Per-endpoint permission checks
- **CORS:** Strict origin validation
- **Request Validation:** Schema validation for all inputs
- **Response Filtering:** Only requested fields returned

---

## 6. Infrastructure Security

### 6.1 Container Security

HeroForge runs in Docker containers with security hardening:

| Control | Implementation |
|---------|----------------|
| Non-root User | Application runs as unprivileged user |
| Read-only Filesystem | Root filesystem mounted read-only |
| Dropped Capabilities | Only CAP_NET_RAW for scanning |
| Resource Limits | CPU and memory limits enforced |
| No Privileged Mode | Containers never run privileged |

### 6.2 Host Security

- **OS Hardening:** Minimal base image, unnecessary services disabled
- **Patch Management:** Regular security updates
- **Access Control:** SSH key-only authentication
- **Audit Logging:** All administrative actions logged

### 6.3 Secrets Management

| Secret Type | Storage | Access Control |
|-------------|---------|----------------|
| Database Key | Environment variable | Container-only |
| JWT Secret | Environment variable | Container-only |
| API Keys | Encrypted in database | Per-user access |
| TLS Certificates | Traefik volume | Traefik-only |

### 6.4 Backup Security

- **Encryption:** Backups encrypted with GPG (AES-256)
- **Integrity:** SHA-256 checksums for all backups
- **Access Control:** Restricted to backup operator role
- **Off-site Storage:** Encrypted copies to secure location
- **Retention:** 7 daily, 4 weekly, 12 monthly backups

---

## 7. Audit and Logging

### 7.1 Logged Events

| Category | Events |
|----------|--------|
| Authentication | Login, logout, failed attempts, MFA events |
| Authorization | Access granted, access denied |
| Data Access | Read, write, delete operations |
| Administrative | User management, configuration changes |
| Security | Rate limit triggers, suspicious activity |

### 7.2 Log Format

```json
{
  "timestamp": "2024-12-24T10:30:00Z",
  "level": "INFO",
  "event_type": "authentication",
  "action": "login_success",
  "user_id": "uuid",
  "ip_address": "192.168.1.1",
  "user_agent": "Mozilla/5.0...",
  "details": {}
}
```

### 7.3 Log Protection

- **Integrity:** Log rotation with checksums
- **Confidentiality:** Sensitive data redacted
- **Availability:** Retained for 1 year minimum
- **Access Control:** Read-only for auditors

### 7.4 SIEM Integration

HeroForge supports export to major SIEM platforms:
- Splunk (HEC)
- Elasticsearch
- Syslog (RFC 5424)

---

## 8. Incident Response

### 8.1 Incident Classification

| Severity | Description | Response Time |
|----------|-------------|---------------|
| Critical | Active breach, data exposure | Immediate |
| High | Potential breach, service disruption | 4 hours |
| Medium | Security weakness, minor impact | 24 hours |
| Low | Policy violation, minimal impact | 72 hours |

### 8.2 Response Process

1. **Detection:** Automated monitoring, user reports
2. **Triage:** Severity assessment, initial containment
3. **Investigation:** Root cause analysis, scope determination
4. **Containment:** Limit damage, preserve evidence
5. **Eradication:** Remove threat, patch vulnerabilities
6. **Recovery:** Restore services, verify integrity
7. **Lessons Learned:** Post-incident review, improvements

### 8.3 Notification Timeline

| Notification | Timeline |
|--------------|----------|
| Internal Team | Immediate |
| Affected Customers | Within 48 hours |
| Regulatory Authorities | Within 72 hours (GDPR) |
| Public Disclosure | As required by law |

### 8.4 Contact Information

- **Security Email:** security@heroforge.security
- **Emergency Hotline:** Available to enterprise customers
- **Bug Bounty:** Responsible disclosure program available

---

## 9. Secure Development Lifecycle

### 9.1 Development Practices

| Practice | Implementation |
|----------|----------------|
| Code Review | Required for all changes |
| Static Analysis | Automated (Clippy, ESLint) |
| Dependency Scanning | cargo-audit, npm audit |
| Secret Scanning | Pre-commit hooks |
| Unit Testing | Comprehensive test coverage |

### 9.2 Security Testing

| Test Type | Frequency |
|-----------|-----------|
| SAST (Static Analysis) | Every commit |
| Dependency Scan | Daily |
| DAST (Dynamic Testing) | Weekly |
| Penetration Testing | Annually |
| Security Review | Major releases |

### 9.3 Vulnerability Management

- **Identification:** Multiple sources (scanning, reports, CVE feeds)
- **Assessment:** CVSS scoring, exploitability analysis
- **Prioritization:** Based on severity and exposure
- **Remediation:** SLAs based on severity
- **Verification:** Retesting after fixes

#### Remediation SLAs

| Severity | SLA |
|----------|-----|
| Critical | 24 hours |
| High | 7 days |
| Medium | 30 days |
| Low | 90 days |

---

## 10. Third-Party Security

### 10.1 Vendor Assessment

All third-party services undergo security review:

- Security questionnaire
- SOC 2 or equivalent certification
- Privacy policy review
- Data processing agreement

### 10.2 Current Third-Party Services

| Service | Purpose | Security Certification |
|---------|---------|------------------------|
| Cloud Hosting | Infrastructure | SOC 2, ISO 27001 |
| Email Delivery | Notifications | SOC 2 |
| Payment Processing | Subscriptions | PCI-DSS |

### 10.3 Dependency Management

- **Automated Scanning:** Weekly vulnerability scans
- **Version Pinning:** All dependencies pinned to specific versions
- **Update Policy:** Security updates within 7 days
- **License Review:** Ensure license compatibility

---

## 11. Compliance Alignment

### 11.1 Frameworks Supported

HeroForge is designed to support compliance with:

| Framework | Coverage |
|-----------|----------|
| PCI-DSS 4.0 | Vulnerability scanning, access control |
| HIPAA | Data encryption, audit logging |
| SOC 2 | Security controls, monitoring |
| GDPR | Data protection, privacy controls |
| NIST 800-53 | Comprehensive security controls |
| CIS Benchmarks | Configuration hardening |

### 11.2 Compliance Features

| Requirement | HeroForge Feature |
|-------------|-------------------|
| Access Control | RBAC, MFA, session management |
| Encryption | AES-256 at rest, TLS in transit |
| Audit Trails | Comprehensive logging, SIEM export |
| Data Protection | Encryption, retention controls, deletion |
| Vulnerability Management | Built-in scanning, tracking, remediation |

### 11.3 Certifications (Planned)

- SOC 2 Type II (In Progress)
- ISO 27001 (Planned)
- FedRAMP (Evaluating)

---

## 12. Security Roadmap

### 12.1 Current Capabilities (v0.2)

- AES-256 database encryption
- Multi-factor authentication
- Role-based access control
- Comprehensive audit logging
- Rate limiting and account protection
- Secure container deployment

### 12.2 Planned Enhancements

| Feature | Target |
|---------|--------|
| Hardware Security Module (HSM) Support | Q2 2025 |
| FIDO2/WebAuthn Authentication | Q2 2025 |
| Customer-Managed Encryption Keys | Q3 2025 |
| Zero-Trust Network Architecture | Q3 2025 |
| SOC 2 Type II Certification | Q4 2025 |

---

## Appendix A: Security Contacts

| Purpose | Contact |
|---------|---------|
| Security Inquiries | security@heroforge.security |
| Bug Reports | security@heroforge.security |
| Compliance Questions | compliance@heroforge.security |
| Data Protection Officer | dpo@heroforge.security |

---

## Appendix B: Document History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | December 24, 2024 | Initial release |

---

## Appendix C: Glossary

| Term | Definition |
|------|------------|
| AES | Advanced Encryption Standard |
| bcrypt | Password hashing algorithm |
| JWT | JSON Web Token |
| MFA | Multi-Factor Authentication |
| RBAC | Role-Based Access Control |
| SQLCipher | SQLite encryption extension |
| TLS | Transport Layer Security |
| TOTP | Time-based One-Time Password |

---

**END OF SECURITY WHITEPAPER**

*This document is for informational purposes. For specific security requirements or compliance questions, please contact security@heroforge.security.*
