# HeroForge: Transforming the Cybersecurity Landscape Through Unified Security Operations

## A White Paper on Next-Generation Security Platform Architecture

---

**Author:** HeroForge Development Team

**Affiliation:** HeroForge Security Platform

**Date:** January 2026

**Version:** 2.0

**Document Classification:** Public Distribution

---


## Abstract

The cybersecurity industry faces an unprecedented challenge: organizations must defend against increasingly sophisticated threats while managing a fragmented ecosystem of security tools that create operational silos, visibility gaps, and alert fatigue. Research indicates that the average enterprise deploys 45 to 75 distinct security products, with organizations experiencing over 76,000 security alerts weekly and leaving 53% of alerts uninvestigated due to resource constraints (Ponemon Institute, 2023). HeroForge represents a paradigm shift in security platform design—a unified, full-spectrum cybersecurity solution that integrates offensive testing, defensive operations, governance, and compliance into a single coherent platform. Built on modern Rust infrastructure for performance and security, HeroForge eliminates the traditional boundaries between security functions, enabling organizations to operate with unprecedented efficiency and effectiveness. This white paper examines how HeroForge's innovative "colored teams" architecture addresses critical gaps in the current cybersecurity landscape and positions organizations for success against evolving threats.

*Keywords:* cybersecurity, unified security platform, colored teams, vulnerability management, security operations, compliance automation, SIEM, penetration testing

---


## Table of Contents

1. [The Fragmentation Crisis in Cybersecurity](#the-fragmentation-crisis-in-cybersecurity)
2. [The Colored Teams Model: A Unified Approach](#the-colored-teams-model-a-unified-approach)
3. [Technical Architecture and Innovation](#technical-architecture-and-innovation)
4. [Impact on Security Operations](#impact-on-security-operations)
5. [Key Differentiators](#key-differentiators)
6. [Enterprise Use Cases](#enterprise-use-cases)
7. [The Future of Unified Security Platforms](#the-future-of-unified-security-platforms)
8. [Conclusion](#conclusion)
9. [References](#references)

---


## The Fragmentation Crisis in Cybersecurity


### The Current State of Enterprise Security

Modern enterprises operate in a threat environment of unprecedented complexity. According to industry research, the average organization experiences significant operational challenges that undermine security effectiveness despite substantial investment.

*Table 1*

*Enterprise Security Operational Metrics*

| Metric | Value | Source |
|--------|-------|--------|
| Security alerts per week | 76,000+ | Ponemon Institute (2023) |
| Distinct security products | 45-75 | Gartner (2024) |
| Budget spent on tool integration | 30% | Forrester (2023) |
| Average breach dwell time | 100+ days | IBM Security (2024) |
| Uninvestigated security alerts | 53% | Ponemon Institute (2023) |

*Note.* Data compiled from multiple industry research sources.

This fragmentation creates a fundamental paradox: organizations invest heavily in security yet remain vulnerable due to operational complexity.


### The Cost of Tool Sprawl

The proliferation of point solutions has created significant operational challenges across several dimensions.

**Visibility Gaps.** When vulnerability scanners, SIEM platforms, and endpoint detection tools operate independently, attackers exploit the gaps between systems. Critical threat indicators may appear across multiple tools without correlation, allowing sophisticated campaigns to proceed undetected.

**Context Loss.** Security analysts spend approximately 60% of their time switching between tools and manually correlating data (Forrester, 2023). This context-switching reduces investigative efficiency and increases the likelihood of missing critical connections.

**Skill Fragmentation.** Each security tool requires specialized expertise. Organizations must either maintain deep expertise across dozens of platforms or accept reduced effectiveness from generalist operators.

**Alert Fatigue.** Without unified prioritization, security teams face an overwhelming volume of alerts from multiple sources, leading to critical findings being buried in noise.


### The Integration Tax

Attempts to address fragmentation through integration create additional challenges:

- Custom integrations require ongoing maintenance as APIs evolve
- Data normalization across tools with different schemas is error-prone
- Licensing complexity creates unexpected costs
- Upgrade coordination becomes a major project management burden

Organizations need a fundamentally different approach—one that provides comprehensive capabilities without the integration burden.

---


## The Colored Teams Model: A Unified Approach


### Introducing the Colored Teams Framework

HeroForge implements a comprehensive "colored teams" architecture that organizes security functions into complementary operational domains while maintaining seamless integration.

*Table 2*

*HeroForge Colored Teams Framework*

| Team | Function | Traditional Tools Replaced |
|------|----------|---------------------------|
| Red Team | Offensive security testing | Vulnerability scanners, penetration testing tools, C2 frameworks |
| Blue Team | Defensive detection and response | SIEM, EDR, IDS/IPS, forensics tools |
| Purple Team | Adversary simulation and validation | MITRE ATT&CK tools, BAS platforms |
| Green Team | SOC operations and orchestration | SOAR platforms, case management |
| Yellow Team | Secure development (DevSecOps) | SAST, SCA, SBOM, container security |
| Orange Team | Security awareness and training | Phishing simulation, LMS |
| White Team | Governance, risk, and compliance | GRC platforms, audit tools |

*Note.* This model reflects how modern security organizations actually operate while eliminating artificial boundaries between functions.


### Red Team: Offensive Security at Scale

HeroForge's Red Team capabilities encompass the complete offensive security lifecycle across three primary domains.

**Reconnaissance and Discovery.** The platform provides comprehensive reconnaissance capabilities including multi-protocol network scanning (TCP Connect, SYN, UDP), advanced service detection with 100+ service signatures (including industrial protocols like Modbus, S7comm, DNP3, and modern services like Kafka, ClickHouse, and container runtimes), DNS reconnaissance including zone transfers, subdomain enumeration, SRV/CAA/DNSSEC validation, and subdomain mutation/permutation generation, SSL/TLS analysis with JA3 fingerprinting, and attack surface management with continuous monitoring at configurable intervals.

**Passive Reconnaissance.** Automated passive intelligence gathering from multiple sources including Certificate Transparency logs (crt.sh), Wayback Machine historical URLs, GitHub code search for leaked credentials, SecurityTrails DNS intelligence, and sensitive path detection from archived content.

**Vulnerability Assessment.** Assessment capabilities include CVE detection with three-tier lookup (offline database, cache, NVD API), Nuclei integration with over 10,000 community templates, 50+ built-in misconfiguration checks (MongoDB no-auth, Redis exposed, Elasticsearch open, Jenkins, Docker API, Kubernetes API, etcd, and more), container and Kubernetes vulnerability scanning, Infrastructure as Code (IaC) security analysis, GraphQL security testing (introspection exposure, batch query attacks, query depth DoS, injection vectors), and cloud security assessment across AWS, Azure, and GCP platforms. Database credential testing supports MySQL, PostgreSQL, MSSQL, MongoDB, Redis, and Cassandra with default credential and password spray capabilities.

**Exploitation and Post-Exploitation.** The platform supports password spraying and credential testing, Kerberos attacks (AS-REP roasting, Kerberoasting), privilege escalation detection through LinPEAS and WinPEAS integration, hash cracking with Hashcat and John the Ripper integration, and a custom C2 framework for authorized red team operations.


### Blue Team: Defense in Depth

The Blue Team module provides comprehensive defensive capabilities organized into four functional areas.

**SIEM and Log Management.** Capabilities include complete log ingestion from multiple sources (syslog, file, API), multi-format normalization and parsing, a correlation engine with rule-based detection, and integration with Splunk, Elasticsearch, and QRadar.

**Threat Detection.** Detection capabilities encompass Sigma rule support with format conversion, YARA rule scanning for malware patterns, behavioral analytics and UEBA, network flow analysis with DGA detection, and IDS/IPS rule management.

**Incident Response.** Response capabilities include case management with evidence attachment, timeline generation for attack reconstruction, digital forensics (disk, memory, network), and artifact extraction and analysis.

**Threat Hunting.** Hunting capabilities provide custom hunt query DSL, MITRE ATT&CK-based hunting, hypothesis templates and playbooks, and collaborative hunting workflows.


### Purple Team: Bridging Offense and Defense

The Purple Team module enables organizations to validate their security controls through adversary simulation. Key capabilities include full MITRE ATT&CK framework integration, Atomic Red Team test execution, custom attack chain development, detection coverage analysis and gap identification, automatic Sigma and SIEM query generation, and live red/blue exercises with real-time scoring.


### Green Team: SOC Excellence

Security Operations Center efficiency is enhanced through three capability areas.

**SOAR Capabilities.** The platform provides playbook management and execution, an extensive action library (block IP, isolate host, enrich IOC), tool integration framework, and multi-step orchestration workflows.

**Case Management.** Case management includes full incident lifecycle tracking, evidence management, timeline reconstruction, and team collaboration tools.

**SOC Metrics.** Metrics capabilities encompass MTTD, MTTR, and SLA tracking, analyst performance metrics, and trend analysis and visualization.


### Yellow Team: Secure Development

DevSecOps integration ensures security is built into the development lifecycle through three focus areas.

**Application Security.** Capabilities include SAST with multi-language support (Rust, JavaScript, Python, Go, Java), secret detection for hardcoded credentials, DAST for runtime vulnerability testing, and API security testing for REST and GraphQL endpoints.

**Software Composition Analysis.** SCA capabilities provide dependency CVE scanning, license compliance tracking, transitive dependency analysis, and SBOM generation in CycloneDX and SPDX formats.

**CI/CD Security.** Pipeline security includes security gates, GitHub Actions, GitLab CI, and Jenkins integration, security policy enforcement, and deployment quality gates.


### Orange Team: Human-Centric Security

Security awareness addresses the human element through interactive training modules, role-based curricula, compliance training (GDPR, HIPAA, PCI-DSS), gamification with leaderboards and badges, and phishing simulation with analytics.


### White Team: Governance Excellence

Comprehensive GRC capabilities ensure organizational compliance across three domains.

**Compliance Frameworks.** The platform supports 45 compliance frameworks organized into three categories:

- *Core Frameworks:* PCI-DSS 4.0, HIPAA, SOC 2, NIST 800-53, NIST CSF, CIS Benchmarks, ISO 27001:2022, GDPR, HITRUST CSF, FERPA, DoD STIG, OWASP Top 10
- *US Federal Frameworks:* FedRAMP, CMMC 2.0, FISMA, NIST 800-171, NIST 800-82, NIST 800-61, StateRAMP, ITAR, EAR, DFARS, ICD 503, CNSSI 1253, RMF, DISA Cloud SRG, DoD Zero Trust, NIST Privacy Framework
- *Industry and International:* CSA CCM, NERC CIP, IEC 62443, TSA Pipeline Security, CISA CPGs, EO 14028, SOX IT Controls, GLBA, Cyber Essentials (UK), Australian ISM, IRAP, NIS2 Directive, ENS (Spain), BSI IT-Grundschutz, C5, SecNumCloud, NATO Cyber Defence

The platform supports both automated and manual compliance assessment along with evidence collection and management.

**Risk Management.** Risk capabilities include quantitative and qualitative risk analysis, vendor risk management, risk treatment tracking, and board-level reporting.

**Audit Management.** Audit capabilities encompass control definition and mapping, automated evidence gathering, finding and CAP tracking, and continuous auditing.

---


## Technical Architecture and Innovation


### Built on Rust: Security by Design

HeroForge's decision to build on Rust represents a strategic investment in long-term security and performance.

**Memory Safety Without Garbage Collection.** The Rust foundation eliminates entire classes of vulnerabilities including buffer overflows and use-after-free conditions. The platform operates without runtime garbage collection pauses affecting scan performance and provides compile-time guarantees for thread safety.

**Performance.** Rust provides near-C performance for network scanning operations, efficient resource utilization in containerized deployments, and the ability to handle enterprise-scale scanning workloads.

**Modern Async Runtime.** The Tokio-based async architecture enables maximum concurrency with semaphore-limited concurrent scanning to prevent resource exhaustion and WebSocket support for real-time scan progress updates.


### Database Architecture

**SQLite with Optional Encryption.** The database layer provides AES-256 encryption via SQLCipher for data at rest, auto-migration on startup ensuring schema consistency, and WAL mode for improved concurrency.

**Three-Tier CVE Lookup.** The CVE lookup system incorporates an embedded offline database for common CVEs, a SQLite cache with 30-day TTL, and real-time NVD API queries for cache misses.


### Frontend Architecture

**Modern React Stack.** The frontend utilizes React 18 with TypeScript for type safety, Vite for fast development and production builds, TailwindCSS for consistent and responsive design, and Zustand for global state with React Query for server state.

**Real-Time Updates.** Real-time capabilities include WebSocket channels for live scan progress, broadcast channels for multi-client updates, and token-authenticated WebSocket connections.


### Integration Architecture

**REST API.** The API layer provides over 160 endpoints covering all platform functions, JWT authentication with refresh token support, rate limiting to prevent abuse, and comprehensive Swagger documentation.

**External Integrations.** Supported integrations include JIRA and ServiceNow for ticket management with bi-directional synchronization (status updates, comment sync, auto-close on verification), Slack and Microsoft Teams for notifications, Splunk, Elasticsearch, and QRadar for SIEM, and GitHub, GitLab, and Bitbucket for DevSecOps. The bi-directional sync engine supports webhook receivers for real-time updates and conflict resolution for simultaneous edits.

---


## Impact on Security Operations


### Operational Efficiency Gains

Organizations implementing unified platforms like HeroForge can expect significant efficiency improvements across three dimensions.

**Reduced Context Switching.** Benefits include a single interface for offensive and defensive operations, unified asset inventory across all security functions, and correlated findings from multiple assessment types.

**Accelerated Investigation.** Investigation improvements include automatic enrichment of alerts with vulnerability context, attack path visualization from scan results, and one-click pivot from detection to forensics.

**Streamlined Reporting.** Reporting benefits include unified reporting across compliance frameworks, automatic evidence collection from assessments, and executive dashboards with real-time metrics.


### Mean Time to Remediate

Unified platforms significantly reduce MTTR through automatic prioritization based on exploitability and business context, remediation workflows that route findings to appropriate teams, verification scanning to confirm fix effectiveness, and SLA tracking with escalation automation.

### Finding Lifecycle Management

HeroForge implements comprehensive finding lifecycle tracking with seven distinct states:

1. **Discovered** → Initial detection from scanning
2. **Triaged** → Analyst review and validation
3. **Acknowledged** → Stakeholder acceptance
4. **In Remediation** → Active fix in progress
5. **Verification Pending** → Fix applied, awaiting verification
6. **Verified** → Remediation confirmed effective
7. **Closed** → Finding resolved and archived

Each state transition is tracked with timestamps, user attribution, and optional notes. SLA policies can be configured per severity level with automatic breach detection and escalation. The Kanban-style interface enables drag-and-drop state transitions with bulk operations for efficient triage workflows.

### Continuous Monitoring

The continuous monitoring engine provides near real-time attack surface visibility:

- **Lightweight scans** every 5 seconds for critical asset changes
- **Full scans** at configurable intervals (minimum 60 seconds, default 4 hours)
- **Change detection alerts** for new ports, closed ports, service changes, new vulnerabilities
- **Baseline comparison** with deviation reporting
- **Finding deduplication** across scans with fingerprint-based correlation


### Coverage and Visibility

The colored teams model ensures comprehensive coverage with no gaps between offensive testing and defensive monitoring, continuous validation of detection capabilities, a unified view of security posture across domains, and correlation of findings across assessment types.


### Cost Optimization

Consolidation delivers measurable cost benefits including reduced licensing costs from tool consolidation, lower training costs with unified interface, decreased integration maintenance, and improved analyst productivity with estimated 40-60% efficiency gains.

---


## Key Differentiators


### Full-Spectrum Capability

Unlike point solutions that excel in narrow domains, HeroForge provides comprehensive capabilities across all security functions.

*Table 3*

*Capability Comparison: Traditional vs. HeroForge Approach*

| Capability | Traditional Approach | HeroForge Approach |
|------------|---------------------|-------------------|
| Vulnerability Scanning | Dedicated scanner | Integrated with exploitation, compliance |
| SIEM | Standalone platform | Unified with threat intel, hunting |
| GRC | Separate tool | Automated evidence from assessments |
| DevSecOps | Multiple point tools | Integrated pipeline security |
| Training | Learning management | Tied to phishing results, gamified |


### Bidirectional Intelligence

HeroForge enables intelligence flow between security functions. Red team findings automatically inform blue team detections, compliance gaps trigger targeted assessments, threat intelligence enriches both offense and defense, and training adjusts based on phishing susceptibility.


### Emerging Domain Coverage

HeroForge addresses security challenges beyond traditional IT across four emerging domains.

**OT/ICS Security.** Capabilities include protocol discovery (Modbus, DNP3, OPC-UA, BACnet, IEC 61850), PLC detection and Purdue model assessment, and safety monitoring for control systems.

**IoT Security.** Capabilities include device discovery and fingerprinting, default credential testing, and firmware analysis and protocol inspection.

**AI/ML Security.** Capabilities include LLM testing for prompt injection, model vulnerability assessment, and AI-powered threat prioritization.

**Web3/Blockchain.** Capabilities include smart contract analysis, DeFi protocol testing, and wallet and exchange security.


### Multi-Tenancy and Customer Portal

HeroForge supports managed security service providers (MSSPs) with complete multi-tenancy with data isolation, customer-facing portal for vulnerability visibility, white-label reporting capabilities, and CRM integration for engagement management.

**Portal Collaboration Features.** The customer portal includes threaded discussions on findings for client-consultant communication, severity dispute workflow with escalation, bulk vulnerability acknowledgment for efficient triage, and file attachments for evidence sharing. Clients can track remediation progress, upload evidence of fixes, and participate in the verification workflow.

**Engagement Templates.** One-click engagement creation with pre-configured templates for common assessment types (External Pentest, Web Application Assessment, Cloud Security Review, Compliance Audit). Templates auto-create workflows, scan configurations, portal users, default milestones, SLA definitions, and pre-select relevant compliance frameworks.

### Custom Report Builder

The drag-and-drop report builder enables custom report creation with reusable section templates, custom branding (logos, colors, fonts), template marketplace for sharing across organizations, and version control for template evolution. Reports can include AI-generated narratives, interactive charts, and evidence screenshots.

---


## Enterprise Use Cases


### Continuous Security Validation

**Challenge.** Organizations struggle to validate that security controls actually detect threats.

**Solution.** HeroForge's Purple Team module enables continuous validation through executing MITRE ATT&CK techniques in a controlled manner, verifying Blue Team detection through correlated alerts, identifying coverage gaps automatically, and generating Sigma rules for undetected techniques.

**Outcome.** Security teams maintain validated detection coverage with measurable metrics.


### Compliance Automation

**Challenge.** Compliance programs require extensive manual evidence collection.

**Solution.** HeroForge automates compliance across frameworks by mapping technical controls to compliance requirements, executing automated technical assessments, collecting evidence directly from scan results, tracking manual control assessments through campaigns, and generating audit-ready reports.

**Outcome.** Organizations achieve 60-80% reduction in compliance effort with continuous compliance posture visibility.


### Managed Security Services

**Challenge.** MSSPs need multi-tenant platforms that scale across clients.

**Solution.** HeroForge provides complete MSSP capabilities including multi-tenant architecture with strict data isolation, customer portal for client self-service, white-label reporting with custom branding, CRM for engagement and contract management, and time tracking for billing accuracy.

**Outcome.** MSSPs can serve more clients with fewer analysts while improving service quality.


### DevSecOps Integration

**Challenge.** Security testing is often disconnected from development workflows.

**Solution.** HeroForge integrates security into the SDLC through SAST/SCA scanning in CI/CD pipelines, container image scanning before deployment, IaC security for Terraform and CloudFormation, SBOM generation for supply chain visibility, and security gates that block vulnerable deployments.

**Outcome.** Development teams receive immediate security feedback, reducing remediation costs by addressing issues early.


### Incident Response Acceleration

**Challenge.** Incident response requires coordination across multiple tools.

**Solution.** HeroForge provides unified incident response through case management with automatic enrichment, forensic analysis (disk, memory, network) in a single platform, timeline reconstruction with MITRE ATT&CK mapping, SOAR playbooks for automated response, and threat hunting to identify related compromise.

**Outcome.** Organizations achieve 40-50% reduction in incident investigation time through eliminated tool switching.

---


## The Future of Unified Security Platforms


### Industry Trends

The cybersecurity industry is moving toward platform consolidation as evidenced by several major trends. Gartner's Cybersecurity Mesh Architecture (CSMA) emphasizes integrated security services (Gartner, 2024). Extended Detection and Response (XDR) reflects demand for unified detection. Cloud-Native Application Protection Platforms (CNAPP) consolidate cloud security capabilities. HeroForge anticipates these trends by providing unified capabilities today.


### AI/ML Integration

The future of security platforms will be increasingly AI-powered with capabilities expanding over time.

**Current HeroForge AI Capabilities.** The platform provides comprehensive AI-powered features:

- *LLM Orchestration:* Multi-model support (Claude, GPT, local models) with model fingerprinting and security testing
- *AI-Generated Report Narratives:* Executive summaries with business impact context, risk contextualization explaining "why this matters," remediation priority rationale, and plain-language technical explanations
- *Intelligent Remediation Roadmapping:* AI-powered dependency analysis between findings, week-by-week remediation phases, critical path identification, resource allocation suggestions, and risk reduction projections
- *Attack Path AI Interpretation:* Natural language attack chain narratives ("An attacker could..."), business impact context, MITRE ATT&CK chain mapping, and recommended blocking points
- *ML-Based Prioritization:* False positive prediction with confidence scoring, exploitability assessment, and business context weighting
- *Enhanced Chat Context:* Scan-aware conversations, finding explanations, and trend analysis through natural language

**Roadmap Directions.** Future capabilities include autonomous threat hunting, AI-assisted incident response, automated detection engineering, and natural language security queries.


### Zero Trust Architecture

HeroForge supports zero trust implementation through continuous validation of security controls, asset-centric security policies, identity and access verification, and microsegmentation validation.


### Quantum-Ready Security

The future roadmap includes preparation for post-quantum cryptography through cryptographic algorithm inventory, quantum-vulnerable protocol detection, and migration planning for cryptographic agility.

---


## Conclusion


### The Imperative for Change

The fragmented security tool landscape has created an unsustainable situation. Organizations invest heavily in security yet remain vulnerable due to operational complexity. The integration tax consumes resources that should be spent on actual security improvement.


### The HeroForge Approach

HeroForge addresses these challenges through fundamental architectural choices:

1. **Unified Platform:** All security functions in a single coherent system
2. **Colored Teams Model:** Organized by operational function, integrated by design
3. **Modern Foundation:** Rust-based performance with memory safety guarantees
4. **Emerging Domain Coverage:** OT/ICS, IoT, AI/ML, Web3 security built-in
5. **Enterprise Ready:** Multi-tenancy, customer portal, compliance automation


### Measurable Impact

Organizations implementing HeroForge can expect 40-60% improvement in analyst productivity, 50-70% reduction in tool integration costs, 60-80% reduction in compliance effort, and measurable improvement in security posture through continuous validation.


### Call to Action

The cybersecurity landscape demands a new approach. Organizations can no longer afford the fragmentation tax imposed by point solutions. HeroForge represents the future of security operations—unified, intelligent, and comprehensive.

Security teams that embrace unified platforms will operate more efficiently, respond more quickly, and ultimately provide better protection for their organizations. The question is not whether consolidation will happen, but which organizations will lead the transition.

---


## About HeroForge

HeroForge is a unified cybersecurity platform designed for authorized penetration testing, security operations, and compliance management. Built on Rust for performance and security, HeroForge implements the complete "colored teams" framework.

*Table 4*

*HeroForge Platform Statistics*

| Metric | Value |
|--------|-------|
| Core Modules | 86+ |
| API Endpoints | 200+ |
| Frontend Pages | 99+ |
| Compliance Frameworks | 45 |
| Service Signatures | 100+ |
| Misconfiguration Checks | 50+ |
| Cloud Platforms | AWS, Azure, GCP |
| Integration Partners | JIRA, ServiceNow, Slack, Teams, Splunk, and more |

*Table 5*

*HeroForge Technology Stack*

| Component | Technology |
|-----------|------------|
| Backend | Rust with Tokio async runtime |
| Frontend | React 18, TypeScript, Vite, TailwindCSS |
| Database | SQLite with optional AES-256 encryption |
| Authentication | JWT with SAML/OAuth SSO support |
| Deployment | Docker with Traefik reverse proxy |

---


## References

Forrester Research. (2023). *The state of security operations: Integration challenges and solutions*. Forrester.

Gartner. (2024). *Market guide for security orchestration, automation and response solutions*. Gartner, Inc.

IBM Security. (2024). *Cost of a data breach report 2024*. IBM Corporation.

MITRE Corporation. (2024). *MITRE ATT&CK framework*. https://attack.mitre.org/

National Institute of Standards and Technology. (2024). *NIST cybersecurity framework 2.0*. U.S. Department of Commerce.

Ponemon Institute. (2023). *The third annual study on the state of endpoint security risk*. Ponemon Institute LLC.

---

*For more information about HeroForge, visit the platform documentation or contact the development team.*
