# Changelog

All notable changes to HeroForge will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- License management system for self-hosted deployments
- License API endpoints for status, feature checking, and validation

## [0.2.0] - 2026-01-15

### Added
- **Self-Hosted Installation Package**: Complete Docker-based deployment with one-line installer
- **45 Compliance Frameworks**: Including FedRAMP, CMMC 2.0, NIST 800-171, NIS2, ISO 27001, and more
- **cATO Network Topology Map**: Interactive visualization for continuous ATO monitoring
- **Zeus AI Integration**: AI-powered vulnerability analysis and remediation recommendations
- **Tiered Registration System**: Free, Professional, and Enterprise tiers with Stripe integration
- **Multi-Tenant Support**: Organization-based access control and asset management
- **OT/ICS Security Module**: Industrial control system security scanning
- **Native Wireless Security Engine**: WiFi security assessment without external tools
- **Native Memory Forensics**: Built-in memory analysis capabilities
- **Native Password Cracking**: Integrated hashcat/john functionality
- **Native Vulnerability Templates**: Custom Nuclei-compatible template engine
- **Native SMB Protocol Stack**: Direct SMB enumeration without smbclient
- **Native AD/LDAP Engine**: Active Directory assessment without external tools
- **Credential Management**: Unified credential storage and rotation
- **Traffic Analysis**: Network packet inspection with credential extraction
- **SBOM Export API**: Software Bill of Materials generation
- **Collapsible Sidebar Navigation**: Improved UI with AI/ML feature highlights

### Changed
- Enhanced navigation menu with Purple/Orange Team features
- Updated whitepapers to version 2.0 with Phase 1-5 enhancements
- Improved error handling across all modules
- Rust 2024 compatibility updates

### Fixed
- Duplicate custom_report_templates migration
- Compilation errors in performance and API modules
- HttpRequest to Claims type conversion in campaign creation
- Risk level field and updated_at type in UserSecurityContext
- 300+ TODO stubs eliminated across 137 files

### Security
- Added TruffleHog secret scanning in CI/CD
- Semgrep SAST integration
- cargo-audit for dependency CVE detection
- SQLCipher database encryption support

## [0.1.0] - 2025-12-01

### Added
- Initial release of HeroForge
- **Core Scanning Engine**
  - TCP Connect scanning
  - TCP SYN scanning (requires root)
  - UDP scanning
  - Comprehensive scan mode
- **Host Discovery**
  - ICMP ping sweep
  - ARP scanning
  - TCP/UDP probes
- **Service Detection**
  - Banner grabbing
  - Service fingerprinting
  - Version detection
- **OS Fingerprinting**
  - TCP/IP stack analysis
  - TTL-based detection
- **Vulnerability Scanning**
  - CVE lookup (offline + NVD API)
  - Service-specific checks
  - SSL/TLS analysis
- **Web Interface**
  - React-based dashboard
  - Real-time scan progress via WebSocket
  - Report generation (JSON, HTML, PDF, CSV, Markdown)
- **Authentication**
  - JWT-based authentication
  - MFA/TOTP support
  - Role-based access control
- **Integrations**
  - JIRA ticket creation
  - ServiceNow integration
  - SIEM export (Splunk, Elasticsearch, Syslog)
  - Slack/Teams notifications
- **Compliance**
  - CIS Benchmarks
  - NIST 800-53
  - PCI-DSS 4.0
  - HIPAA
  - SOC 2

### Security
- bcrypt password hashing
- Rate limiting on authentication endpoints
- CORS configuration
- Security headers (CSP, HSTS, X-Frame-Options)

---

## Version History

| Version | Date | Highlights |
|---------|------|------------|
| 0.2.0 | 2026-01-15 | Self-hosted deployment, 45 compliance frameworks, AI integration |
| 0.1.0 | 2025-12-01 | Initial release with core scanning capabilities |

[Unreleased]: https://github.com/genialarchitect/HeroForge/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/genialarchitect/HeroForge/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/genialarchitect/HeroForge/releases/tag/v0.1.0
