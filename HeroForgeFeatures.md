# HeroForge Comprehensive Feature List

HeroForge is a full-stack security platform with 80+ backend modules and 81 frontend pages. Here's a complete breakdown:

---

## CORE SCANNING & RECONNAISSANCE

### Network Scanning
- **Host Discovery**: TCP connect probes, ICMP echo, ARP scanning
- **Port Scanning**: TCP connect, TCP SYN (root), UDP, comprehensive modes
- **Service Detection**: Banner grabbing, version identification
- **OS Fingerprinting**: Passive detection based on port signatures
- **DNS Reconnaissance**: A, AAAA, MX, TXT, NS, SOA enumeration
- **TLS/SSL Analysis**: Certificate analysis, JA3/JA3S fingerprinting, cipher detection

### Asset Discovery
- **Certificate Transparency Search**: crt.sh subdomain discovery
- **Subdomain Brute-Force**: DNS enumeration with custom wordlists
- **Shodan Integration**: External reconnaissance API
- **Technology Fingerprinting**: Web stack identification
- **Asset Correlation**: Multi-source inventory deduplication

### Active Directory & Identity
- **AD Assessment**: Domain/user/group/computer enumeration
- **LDAP Client**: Full LDAP/LDAPS support
- **Kerberos Enumeration**: SPN enumeration, Kerberoasting detection
- **ACL Analysis**: Dangerous permission detection
- **ADCS Scanning**: Certificate template vulnerabilities
- **BloodHound Integration**: SharpHound import, attack path visualization

### Web Application Scanning
- **Web Crawler**: Recursive crawling with configurable depth
- **Header Analysis**: Security header validation
- **Form Analysis**: CSRF token detection
- **SQL Injection Testing**: SQLi detection and payloads
- **XSS Testing**: Reflected and stored XSS detection
- **Secret Detection**: API keys, credentials in responses

### API Security
- **Endpoint Discovery**: OpenAPI/Swagger analysis
- **Authentication Testing**: Bearer, API key, basic auth
- **Rate Limiting Verification**: Throttling detection
- **Security Header Checks**: CORS, CSP, X-Frame-Options

### Cloud Security (AWS, Azure, GCP)
- **AWS**: IAM, S3, EC2, RDS, Lambda, VPC, CloudTrail scanning
- **Azure**: Azure AD, Storage, VMs, SQL, Key Vault scanning
- **GCP**: IAM, Cloud Storage, Compute, Cloud SQL scanning

### Container & Kubernetes Security
- **Docker Scanning**: Image vulnerability detection, Dockerfile analysis
- **K8s Scanning**: RBAC, network policies, PSS, CIS benchmarks
- **Manifest Analysis**: Security best practices validation

### Infrastructure-as-Code (IaC)
- **Terraform**: HCL security scanning, state analysis
- **CloudFormation**: AWS template validation
- **ARM Templates**: Azure resource validation

### CI/CD Pipeline Security
- **GitHub Actions**: Workflow analysis, secret detection
- **GitLab CI**: Pipeline security review
- **Jenkins**: Groovy script analysis
- **Secret Detection**: Hardcoded credentials in configs

---

## OFFENSIVE SECURITY

### Exploitation Framework
- **Password Spray Attacks**: Credential-based access testing
- **Kerberos Attacks**: Pass-the-ticket, Golden ticket
- **Reverse Shells**: Bash, PowerShell, cmd shells
- **Post-Exploitation**: Credential harvesting, persistence
- **Payload Encoders**: Multi-stage encoding chains
- **Tunneling**: SOCKS proxy, port forwarding

### C2 Framework Integration
- Cobalt Strike, Sliver, Havoc, Mythic, custom C2
- Session management and task queueing

### Password Cracking
- **Tools**: Hashcat (GPU), John the Ripper, native Rust engine
- **Hash Types**: MD5, SHA-1/256/512, NTLM, bcrypt, Kerberos
- **Attack Modes**: Dictionary, brute-force, mask, rule-based

### Privilege Escalation
- **Windows PrivEsc**: Escalation paths and techniques
- **Linux PrivEsc**: Sudo misconfigs, SUID binaries
- **Kernel Vulnerabilities**: Out-of-date OS detection

### Phishing & Social Engineering
- **Email Campaigns**: Template builder, credential harvesting
- **Website Cloning**: Landing page creation
- **Tracking**: Pixel tracking, click tracking
- **SMS/Voice Phishing**: Twilio integration
- **Awareness Mode**: Educational phishing with feedback

### Breach and Attack Simulation (BAS)
- Pre-built attack scenarios
- Atomic Red Team integration
- Safe execution environment

### Additional Offensive Tools
- **YARA Rules**: Malware signature matching
- **Dorks**: Google/Shodan reconnaissance
- **Exploit Research**: ExploitDB, PoC repository
- **Git Recon**: Commit history secret scanning

---

## MALWARE & BINARY ANALYSIS

- **Static Analysis**: Binary feature extraction
- **Packer Detection**: Packed binary identification
- **Suspicious API Detection**: Malicious behavior indicators
- **Resource Extraction**: Hidden file recovery
- **Certificate Verification**: Code signing analysis
- **Sandbox Integration**: Cuckoo, Any.Run, Hybrid Analysis
- **Dynamic Analysis**: Process monitoring, API hooks, network capture
- **IOC Extraction**: Indicators of compromise identification

---

## VULNERABILITY & COMPLIANCE

### Vulnerability Management
- **CVE Correlation**: Three-tier lookup (offline→cache→NVD API)
- **CVSS Scoring**: Severity calculation
- **Exploit Availability**: Active exploit correlation
- **Remediation Tracking**: Fix status validation
- **False Positive Management**: Manual suppression

### Compliance Frameworks
- CIS Benchmarks, NIST 800-53, NIST CSF
- PCI-DSS 4.0, HIPAA, SOC 2, FERPA, OWASP Top 10

### Compliance Features
- **Hybrid Analysis**: Vulnerability-to-control mapping
- **Manual Assessment**: Non-automated control evaluation
- **Evidence Management**: Chain of custody tracking
- **Framework Crosswalk**: Multi-framework alignment

---

## THREAT DETECTION & RESPONSE

### SIEM Integration
- **Log Ingestion**: Syslog, HTTP, agent-based collection
- **Log Parsing**: CEF, LEEF, JSON, RFC 3164/5424
- **Correlation Engine**: Multi-event pattern detection
- **Alert Management**: Deduplication and workflow
- **QRadar/Splunk/Elasticsearch**: Query generation

### Detection Engineering
- Sigma rule creation and testing
- Detection rule library
- Atomic test execution

### Threat Hunting
- **IOC Management**: IP, domain, hash, URL, email types
- **MITRE ATT&CK**: Full matrix with technique mapping
- **Hunting Playbooks**: Structured procedures
- **Hypothesis-Driven**: Structured hypothesis validation
- **Hunt Automation**: Scheduled hunts

### Incident Response
- Incident lifecycle management
- Event timeline builder
- Evidence collection with chain of custody
- SOAR-lite automation
- Case management

### Digital Forensics
- **Memory Analysis**: Dump parsing, process extraction
- **Disk Analysis**: Timeline generation, deleted file recovery
- **Browser Artifacts**: Cache, cookies, history
- **Network Analysis**: PCAP parsing

### Network Analytics
- **NetFlow/IPFIX**: Traffic flow analysis
- **DDoS Detection**: Volumetric attack identification
- **Data Exfiltration**: Large outbound transfer detection
- **UEBA**: User behavior anomaly detection

---

## COLORED TEAMS

### Red Team (`scanner/`)
Offensive security testing, network recon, exploitation

### Blue Team (`siem/`, `detection_engineering/`)
SIEM, detection rules, incident response

### Green Team - SOC Operations
- SOAR playbook orchestration
- Case management
- Threat intelligence automation
- SOC metrics (MTTD, MTTR, SLA)

### Yellow Team - Secure Development
- **SAST**: Static code analysis
- **SCA**: Dependency vulnerability scanning
- **SBOM**: CycloneDX/SPDX export
- **Architecture Review**: STRIDE threat modeling

### Orange Team - Security Awareness
- Phishing campaign management
- Role-based training paths
- Gamification (points, badges, leaderboards)
- Just-in-time training
- Compliance training (GDPR, HIPAA, PCI-DSS)

### White Team - GRC
- Policy management with versioning
- Risk register and assessments
- FAIR analysis
- Control framework mapping
- Audit management
- Vendor risk management

### Purple Team
- MITRE ATT&CK exercises
- Detection validation
- Coverage gap analysis
- Live red/blue exercises

---

## AI & MACHINE LEARNING

- **Vulnerability Prioritization**: AI-based risk scoring
- **Weighted Scoring**: CVSS, exploit availability, asset criticality
- **LLM Integration**: Claude API for analysis
- **LLM Orchestration**: Multiple LLM support
- **ML Pipeline**: Feature extraction, model training
- **Chat Assistant**: AI conversational analysis

---

## THREAT INTELLIGENCE

- **Shodan/Censys**: Device and certificate intelligence
- **ExploitDB**: Exploit correlation
- **NVD/CISA KEV**: Known exploited vulnerability feeds
- **MISP**: Malware Information Sharing Platform
- **STIX/TAXII**: Structured threat intelligence exchange
- **Threat Actor Tracking**: APT group profiling

---

## EMERGING TECHNOLOGIES

### OT/ICS Security
- Industrial protocol scanning: Modbus, DNP3, OPC UA, BACnet, S7, IEC 61850
- Device fingerprinting
- Purdue Model classification

### IoT Security
- Device discovery (mDNS, SSDP/UPnP, MQTT)
- Default credential checking
- IoT-specific CVE correlation

### Web3 & Blockchain
- Smart contract scanning (Solidity)
- DeFi protocol analysis
- On-chain analytics

### Honeypots & Deception
- SSH, HTTP, FTP, Database honeypots
- Canary token generation

---

## INFRASTRUCTURE & AUTOMATION

- **Distributed Scanning**: Agent mesh networking
- **Workflow Engine**: Custom automation
- **Job Scheduling**: Cron-based recurring scans
- **Webhooks**: Outbound integrations
- **Plugin System**: Extensible architecture
- **VPN Integration**: OpenVPN/WireGuard tunneling
- **Database Backup**: GPG-encrypted backups

---

## REPORTS & OUTPUTS

- **Formats**: JSON, HTML, PDF, CSV, Markdown
- **Report Types**: Executive, technical, compliance, trending
- **Scan Comparison**: Diff between results
- **Scheduled Reports**: Automated generation

---

## INTEGRATIONS

- **Ticketing**: JIRA, ServiceNow
- **Chat**: Slack, Microsoft Teams
- **SIEM Export**: Splunk, Elasticsearch, Syslog
- **SSO**: SAML 2.0, OAuth 2.0/OIDC
- **Cloud SDKs**: AWS, Azure, GCP

---

## FRONTEND (81 Pages)

Key pages include: Dashboard, Scans, Assets, Vulnerabilities, Compliance, SIEM, Threat Hunting, Incident Response, Forensics, Malware Analysis, C2, Cracking, Phishing, all colored team dashboards, CRM, Customer Portal, Admin, Settings, and more.

---

## TECH STACK

| Layer | Technology |
|-------|------------|
| Backend | Rust 1.70+, Tokio, Actix-web |
| Frontend | React 18, TypeScript, Vite, TailwindCSS |
| Database | SQLite + SQLCipher (AES-256) |
| Auth | JWT, bcrypt, TOTP MFA |
| Real-time | WebSocket (tokio broadcast) |
