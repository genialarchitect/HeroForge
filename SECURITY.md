# Security Policy

## Reporting a Vulnerability

The HeroForge team takes security vulnerabilities seriously. We appreciate your efforts to responsibly disclose your findings.

### How to Report

**Please DO NOT report security vulnerabilities through public GitHub issues.**

Instead, please report them via email to:

**security@heroforge.io**

Include the following information in your report:

- Type of vulnerability (e.g., SQL injection, XSS, authentication bypass)
- Full paths of source file(s) related to the vulnerability
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact assessment of the vulnerability
- Any potential mitigations you've identified

### What to Expect

| Timeline | Action |
|----------|--------|
| 24 hours | Initial acknowledgment of your report |
| 72 hours | Preliminary assessment and severity rating |
| 7 days | Detailed response with remediation plan |
| 90 days | Target resolution for critical/high severity issues |

We will keep you informed of our progress throughout the process.

### Scope

The following are **in scope** for security reports:

- HeroForge core application (Rust backend)
- Web dashboard (React frontend)
- Authentication and authorization systems
- API endpoints
- Database interactions
- Docker container configuration
- CI/CD pipeline security

The following are **out of scope**:

- Third-party services and integrations (report to respective vendors)
- Social engineering attacks
- Physical security
- Denial of service attacks
- Issues in dependencies (report upstream, but notify us)

### Safe Harbor

We consider security research conducted in accordance with this policy to be:

- Authorized concerning any applicable anti-hacking laws
- Authorized concerning any relevant anti-circumvention laws
- Exempt from restrictions in our Terms of Service that would interfere with conducting security research

We will not pursue civil action or initiate a complaint to law enforcement for accidental, good-faith violations of this policy.

### Recognition

We maintain a [Security Hall of Fame](#hall-of-fame) to recognize researchers who have helped improve HeroForge security.

To be eligible for recognition:
- Be the first to report a unique vulnerability
- Allow reasonable time for remediation before disclosure
- Not exploit the vulnerability beyond proof-of-concept
- Not access or modify other users' data

### Severity Ratings

We use CVSS v3.1 to assess vulnerability severity:

| Severity | CVSS Score | Response Time |
|----------|------------|---------------|
| Critical | 9.0 - 10.0 | 24-48 hours |
| High | 7.0 - 8.9 | 7 days |
| Medium | 4.0 - 6.9 | 30 days |
| Low | 0.1 - 3.9 | 90 days |

### Supported Versions

| Version | Supported |
|---------|-----------|
| 0.2.x | :white_check_mark: |
| 0.1.x | :x: |
| < 0.1 | :x: |

We recommend always running the latest version of HeroForge.

## Security Best Practices

When deploying HeroForge, follow these security recommendations:

### Environment Variables

```bash
# Generate strong secrets
JWT_SECRET=$(openssl rand -hex 32)
DATABASE_ENCRYPTION_KEY=$(openssl rand -hex 32)
TOTP_ENCRYPTION_KEY=$(openssl rand -hex 32)
```

**Never commit secrets to version control.**

### Network Security

- Deploy behind a reverse proxy (nginx, Traefik) with TLS
- Use firewall rules to restrict access
- Enable rate limiting
- Consider VPN for internal deployments

### Authentication

- Enable MFA for all users
- Use strong password policies
- Rotate API keys regularly
- Review audit logs periodically

### Database

- Enable SQLCipher encryption for sensitive deployments
- Regular backups with encryption
- Restrict database file permissions

### Container Security

- Run as non-root user (default in our Dockerfile)
- Use read-only filesystem where possible
- Limit container capabilities
- Keep base images updated

## Hall of Fame

We thank the following security researchers for their responsible disclosures:

*No submissions yet. Be the first!*

---

## Contact

- **Security Reports**: security@heroforge.io
- **PGP Key**: [Coming soon]
- **General Inquiries**: support@heroforge.io

Thank you for helping keep HeroForge and our users safe!
