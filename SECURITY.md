# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

The HeroForge team takes security vulnerabilities seriously. We appreciate your efforts to responsibly disclose your findings.

### How to Report

**Please DO NOT report security vulnerabilities through public GitHub issues.**

Instead, please report them via one of the following methods:

1. **Email**: Send details to [security@heroforge.dev](mailto:security@heroforge.dev)
2. **GitHub Security Advisories**: Use [GitHub's private vulnerability reporting](https://github.com/genialarchitect/HeroForge/security/advisories/new)

### What to Include

Please include as much of the following information as possible:

- Type of vulnerability (e.g., buffer overflow, injection, authentication bypass)
- Full paths of source file(s) related to the vulnerability
- Location of the affected source code (tag/branch/commit or direct URL)
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact assessment and potential attack scenarios

### Response Timeline

- **Initial Response**: Within 48 hours of submission
- **Status Update**: Within 7 days with an evaluation of the report
- **Resolution Target**: Critical vulnerabilities within 30 days; others within 90 days

### What to Expect

1. **Acknowledgment**: We will acknowledge receipt of your vulnerability report
2. **Communication**: We will keep you informed of our progress
3. **Credit**: We will credit you in our security advisories (unless you prefer anonymity)
4. **No Legal Action**: We will not pursue legal action against researchers who follow this policy

### Scope

This security policy applies to:

- The HeroForge core application (`src/`)
- Official Docker images and deployment configurations
- The web frontend (`frontend/`)
- Official documentation

### Out of Scope

The following are **not** considered vulnerabilities in HeroForge:

- Vulnerabilities in third-party dependencies (please report these to the respective maintainers)
- Issues requiring physical access to a user's device
- Social engineering attacks
- Denial of service attacks against HeroForge infrastructure
- Issues in unsupported versions

### Responsible Disclosure

We kindly ask that you:

- Give us reasonable time to address the issue before public disclosure
- Make a good faith effort to avoid privacy violations, data destruction, and service disruption
- Do not access or modify data that does not belong to you

## Security Best Practices for Users

Since HeroForge is a security assessment tool, please ensure you:

1. **Only scan authorized networks** - Unauthorized scanning may be illegal
2. **Secure your installation** - Protect API keys and scan results
3. **Keep HeroForge updated** - Run the latest version for security fixes
4. **Review scan configurations** - Avoid unintended aggressive scanning
5. **Protect scan outputs** - Results may contain sensitive network information

## Security Features

HeroForge includes several security features:

- Database encryption for stored credentials and results
- Multi-factor authentication (MFA) support
- Rate limiting and scan throttling
- Audit logging of all operations
- Secure WebSocket connections for real-time updates

For details, see our [Security Whitepaper](legal/SECURITY_WHITEPAPER.md).
