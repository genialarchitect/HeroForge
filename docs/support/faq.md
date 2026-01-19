# Frequently Asked Questions

## General

### What is HeroForge?

HeroForge is a comprehensive network reconnaissance and security assessment platform designed for authorized penetration testing. It provides both a CLI tool and web dashboard for scanning networks, identifying vulnerabilities, and generating compliance reports.

### Is HeroForge free?

HeroForge offers multiple tiers:

- **Free Tier**: 3 scans/month, basic compliance checks, community support
- **Professional**: $99/month - Unlimited scans, all features, email support
- **Enterprise**: Custom pricing - SSO, dedicated support, custom integrations

### What are the system requirements?

**CLI Tool:**
- Linux, macOS, or Windows
- 64-bit architecture
- 2GB RAM minimum
- Internet connectivity for updates

**Web Dashboard:**
- Modern web browser (Chrome, Firefox, Safari, Edge)
- JavaScript enabled

### Do I need to be authorized to use HeroForge?

**Yes, absolutely.** HeroForge is designed exclusively for authorized penetration testing. You must have explicit written permission from the system owner before scanning any target. Unauthorized scanning is illegal and can result in criminal prosecution.

## Scanning

### What scan types are available?

| Type | Description | Privileges Required |
|------|-------------|---------------------|
| TCP Connect | Full TCP handshake | None |
| TCP SYN | Half-open stealth scan | Root/Admin |
| UDP | UDP service detection | Root/Admin |
| Comprehensive | TCP + UDP combined | Root/Admin |

### How long do scans take?

Scan duration depends on:
- Number of targets
- Number of ports
- Network latency
- Scan type selected
- Concurrency settings

Typical times:
- Single host, 100 ports: ~30 seconds
- /24 subnet, 1000 ports: ~5-15 minutes
- Full 65535 port scan: ~30-60 minutes

### Can I scan my own home network?

Yes, you can scan networks you own or have explicit permission to test. Your home network is fine to scan.

### What ports does a "full scan" include?

- **Top 100 ports**: Most common services
- **Top 1000 ports**: Extended common services
- **Full scan**: All 65535 TCP or UDP ports

### Why are my SYN scans not working?

SYN scans require elevated privileges:
- **Linux**: Run with `sudo` or grant `CAP_NET_RAW` capability
- **Windows**: Run as Administrator
- **Docker**: Use `--cap-add=NET_RAW`

### Can I scan IPv6 addresses?

Yes, HeroForge supports both IPv4 and IPv6 targets. Use standard notation:
- IPv6: `2001:db8::1`
- IPv6 CIDR: `2001:db8::/64`

## Vulnerabilities

### How does vulnerability detection work?

HeroForge uses multiple methods:
1. **Service Version Detection**: Identifies known vulnerable versions
2. **CVE Database**: Matches services against NVD CVE data
3. **Signature Matching**: Detects common misconfigurations
4. **Active Checks**: Optional safe vulnerability verification

### How accurate is vulnerability detection?

Detection accuracy varies:
- **Version-based detection**: Very accurate when version is identified
- **Signature detection**: Generally accurate with occasional false positives
- **Always verify**: Critical findings should be manually confirmed

### Can HeroForge exploit vulnerabilities?

HeroForge is a reconnaissance and assessment tool, not an exploitation framework. It identifies vulnerabilities but does not include exploit payloads. For exploitation testing, integrate with tools like Metasploit.

### How do I reduce false positives?

1. Enable service version detection for accurate identification
2. Use the vulnerability verification feature when available
3. Cross-reference findings with manual testing
4. Mark confirmed false positives for future filtering

## Compliance

### Which compliance frameworks are supported?

HeroForge supports 45+ frameworks including:

**General**: CIS, NIST 800-53, NIST CSF, ISO 27001, SOC 2
**Industry**: PCI-DSS 4.0, HIPAA, GLBA, FERPA
**Government**: FedRAMP, CMMC 2.0, FISMA, NIST 800-171
**International**: NIS2, Cyber Essentials, IRAP, ENS

### Can HeroForge help me achieve compliance?

HeroForge helps by:
- Automating technical control assessments
- Identifying gaps in your security posture
- Generating compliance-ready reports
- Tracking remediation progress

However, full compliance typically requires additional documentation, policies, and manual assessments that HeroForge doesn't perform.

## Security

### How is my data protected?

- All data encrypted in transit (TLS 1.3)
- Optional database encryption (AES-256)
- Passwords hashed with bcrypt (cost 12)
- JWT tokens with short expiration
- MFA support for account protection

### Where are my scan results stored?

Scan results are stored in a SQLite database on the HeroForge server. For self-hosted deployments, you control the storage location. Cloud-hosted data is encrypted at rest.

### Can I delete my data?

Yes, you can:
- Delete individual scans and results
- Delete your entire account and associated data
- Request data export in portable formats

### Is there audit logging?

Yes, HeroForge logs all significant actions:
- User authentication events
- Scan creation and execution
- Report generation
- Configuration changes
- Admin actions

## Integration

### Does HeroForge have an API?

Yes, a comprehensive REST API is available at `/api/`. Key endpoints:

- `POST /api/scans` - Create scan
- `GET /api/scans/{id}` - Get scan results
- `GET /api/vulnerabilities` - List vulnerabilities
- `POST /api/reports/generate` - Generate report

API documentation: `/api/docs` (Swagger UI)

### Can I integrate with JIRA?

Yes, HeroForge integrates with JIRA to:
- Automatically create tickets from vulnerabilities
- Map severity to JIRA priority
- Link findings to existing issues
- Track remediation status

Configure in **Settings** > **Integrations** > **JIRA**.

### Does HeroForge support SIEM integration?

Yes, export to:
- Splunk
- Elasticsearch
- Syslog (RFC 5424)

Configure in **Settings** > **Integrations** > **SIEM**.

## Troubleshooting

### Why is my scan stuck at 0%?

Common causes:
- No targets are reachable
- Firewall blocking outbound connections
- Insufficient privileges for scan type
- Network connectivity issues

See [Troubleshooting](./troubleshooting.md) for solutions.

### Why can't I log in?

1. Check username/password are correct
2. Verify your email was confirmed
3. Check if your account is locked (too many failed attempts)
4. Clear browser cookies and cache
5. Try incognito/private browsing mode

### Where can I get help?

- **Email**: support@heroforge.security
- **Documentation**: This knowledge base
- **Community**: Discord/Slack channels
- **Enterprise**: Dedicated support included

## Account Management

### How do I enable MFA?

1. Go to **Settings** > **Security**
2. Click **Enable MFA**
3. Scan QR code with authenticator app
4. Enter verification code to confirm
5. Save backup codes securely

### Can I have multiple users on one account?

Enterprise accounts support:
- Multiple users with role-based access
- Organization/team management
- Shared scan templates and reports
- Centralized billing

### How do I upgrade my plan?

1. Go to **Settings** > **Subscription**
2. Select your desired plan
3. Enter payment information
4. Confirm upgrade

Contact sales@heroforge.security for enterprise pricing.
