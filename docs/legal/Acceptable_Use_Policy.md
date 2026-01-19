# HeroForge Acceptable Use Policy

**Last Updated: January 2026**

**Effective Date: January 1, 2026**

---

## 1. Introduction

### 1.1 Purpose

This Acceptable Use Policy ("AUP") defines the acceptable and prohibited uses of the HeroForge cybersecurity platform (the "Service"). This AUP is designed to protect HeroForge, our customers, and the broader internet community from irresponsible, harmful, or illegal activities.

### 1.2 Scope

This AUP applies to all users of the Service, including:
- Individual subscribers
- Enterprise customers and their authorized users
- Managed Security Service Providers (MSSPs) and their clients
- Trial and evaluation users
- API integrators

### 1.3 Relationship to Terms of Service

This AUP is incorporated into and forms part of the HeroForge Terms of Service. Capitalized terms not defined here have the meanings given in the Terms of Service.

---

## 2. Fundamental Principle: Authorization Required

### 2.1 The Golden Rule

**YOU MUST HAVE EXPLICIT, DOCUMENTED AUTHORIZATION BEFORE TESTING ANY SYSTEM.**

This is the foundational principle of responsible security testing. HeroForge is a powerful security platform that can interact with systems in ways that may cause disruption if misused. Every feature of the Service must be used only against systems you are authorized to test.

### 2.2 What Constitutes Authorization

Valid authorization includes:
- Written permission from the system owner
- Signed penetration testing agreement or contract
- Explicit scope document defining authorized targets
- Employment authorization for systems you administer
- Ownership of the systems being tested

### 2.3 What Does NOT Constitute Authorization

The following do NOT provide authorization:
- Verbal permission alone
- Assumption that testing is allowed
- "Bug bounty" programs without reading and accepting their terms
- Testing "for educational purposes" without permission
- Belief that the target won't notice
- Authorization from someone who doesn't own the system

### 2.4 Documentation Requirements

You must maintain the following documentation for all testing activities:
- Written authorization from the system owner
- Scope of authorized testing (IP ranges, domains, systems)
- Time windows for testing
- Emergency contact information
- Any limitations or exclusions
- Rules of engagement

**We may request this documentation at any time and suspend your access pending verification.**

---

## 3. Acceptable Uses

### 3.1 Authorized Security Testing

You may use the Service to:

**Internal Security Assessment**
- Test systems and networks owned by your organization
- Assess security posture of your infrastructure
- Validate security controls and configurations
- Conduct vulnerability assessments on your assets

**Contracted Penetration Testing**
- Perform authorized penetration tests under valid contracts
- Conduct red team exercises with proper authorization
- Test client systems with documented permission
- Deliver security assessment services

**Compliance and Audit**
- Assess compliance with security frameworks (PCI-DSS, HIPAA, SOC 2, etc.)
- Collect evidence for audit purposes
- Generate compliance reports
- Track remediation of security findings

**Security Research**
- Conduct authorized security research
- Participate in legitimate bug bounty programs (following program rules)
- Develop and test security tools in controlled environments
- Educational purposes on systems you own or control

**Defensive Security Operations**
- Monitor and analyze security events
- Investigate security incidents
- Develop detection rules and signatures
- Threat hunting on authorized systems

### 3.2 Managed Security Services

MSSPs may use the Service to provide security services to clients, provided:
- Each client engagement has documented authorization
- Client data is properly isolated
- Clients are informed of testing activities
- Service delivery complies with this AUP

---

## 4. Prohibited Uses

### 4.1 Unauthorized Access (Absolutely Prohibited)

**You shall NEVER use the Service to:**

- Access, scan, or test any system without explicit authorization
- Attempt to gain unauthorized access to systems, networks, or data
- Bypass authentication or access controls on unauthorized systems
- Intercept communications without authorization
- Access systems beyond the authorized scope

**Violation of this section may result in immediate termination and referral to law enforcement.**

### 4.2 Malicious Activities

**You shall NOT use the Service for:**

- Denial-of-service (DoS) or distributed denial-of-service (DDoS) attacks
- Deploying ransomware, malware, or destructive code
- Cryptomining or cryptocurrency theft
- Data theft or exfiltration from unauthorized systems
- Identity theft or impersonation
- Financial fraud or theft
- Espionage or state-sponsored attacks

### 4.3 Harmful Content

**You shall NOT use the Service to:**

- Store or transmit child sexual abuse material (CSAM)
- Store or transmit content promoting terrorism or violence
- Distribute stolen credentials or personal data
- Host phishing infrastructure targeting unauthorized victims
- Distribute spam or unsolicited communications

### 4.4 Infrastructure Abuse

**You shall NOT:**

- Attempt to disrupt or degrade the Service
- Reverse engineer, decompile, or disassemble the Service
- Circumvent usage limits or licensing restrictions
- Share account credentials or access tokens
- Use the Service to attack HeroForge infrastructure
- Interfere with other users' access to the Service

### 4.5 Legal Violations

**You shall NOT use the Service to:**

- Violate any applicable law or regulation
- Infringe intellectual property rights
- Violate export control laws
- Engage in activities prohibited in your jurisdiction
- Violate privacy laws or data protection regulations

### 4.6 Scope Violations

**You shall NOT:**

- Test systems outside the authorized scope
- Continue testing after authorization has expired
- Exceed the depth or intensity of testing authorized
- Access data beyond what is necessary for the assessment
- Retain copies of sensitive data after engagement completion

---

## 5. Specific Feature Guidelines

### 5.1 Network Scanning

- Only scan IP ranges explicitly authorized
- Respect rate limits to avoid disruption
- Do not scan during production hours unless authorized
- Immediately stop scanning if requested by the target

### 5.2 Vulnerability Assessment

- Report critical vulnerabilities responsibly
- Do not exploit vulnerabilities beyond what is necessary for validation
- Follow responsible disclosure practices
- Protect vulnerability data appropriately

### 5.3 Exploitation and Post-Exploitation

- Only exploit systems with explicit authorization
- Do not cause unnecessary damage or data loss
- Do not install persistent backdoors (unless specifically authorized)
- Clean up artifacts after testing
- Do not access personal data unless required for the assessment

### 5.4 Password and Credential Testing

- Only test credentials on authorized systems
- Do not use obtained credentials beyond the authorized scope
- Securely store and handle captured credentials
- Delete credentials after the engagement

### 5.5 Social Engineering and Phishing

- Only target individuals within the authorized scope
- Obtain explicit authorization for social engineering tests
- Do not collect personal data beyond what is authorized
- Provide appropriate debriefing after exercises
- Handle sensitive information responsibly

### 5.6 Command and Control (C2)

The C2 features are for authorized red team operations only:
- Only deploy agents on authorized systems
- Maintain control of deployed agents
- Remove agents after testing completion
- Do not use for unauthorized surveillance
- Do not bridge to non-authorized networks

### 5.7 Web Application Testing

- Only test applications with authorization
- Respect robots.txt and rate limits where appropriate
- Do not cause data corruption or loss
- Protect any sensitive data discovered
- Do not access user accounts beyond testing needs

### 5.8 Cloud Security Scanning

- Only scan cloud resources you are authorized to access
- Ensure proper IAM permissions
- Do not access other customers' resources
- Respect cloud provider acceptable use policies

---

## 6. Responsibilities

### 6.1 Your Responsibilities

As a user of the Service, you are responsible for:

1. **Obtaining Authorization**
   - Securing proper authorization before any testing
   - Documenting authorization appropriately
   - Respecting scope limitations

2. **Secure Operations**
   - Protecting your account credentials
   - Securing data collected during assessments
   - Reporting security incidents promptly

3. **Legal Compliance**
   - Complying with all applicable laws
   - Understanding the legal requirements in your jurisdiction
   - Consulting legal counsel when uncertain

4. **Professional Conduct**
   - Acting ethically and professionally
   - Following industry standards and best practices
   - Respecting the trust placed in you by clients

5. **Reporting**
   - Reporting vulnerabilities responsibly
   - Notifying system owners of critical findings
   - Following incident disclosure procedures

### 6.2 Organizational Responsibilities

Organizations using the Service must:

- Establish clear policies for Service use
- Train users on this AUP
- Monitor for policy violations
- Respond promptly to reported violations
- Maintain authorization documentation

---

## 7. Monitoring and Enforcement

### 7.1 Our Rights

We reserve the right to:

- Monitor Service usage for compliance with this AUP
- Investigate potential violations
- Suspend or terminate accounts for violations
- Report illegal activities to law enforcement
- Cooperate with legal investigations
- Take technical measures to prevent abuse

### 7.2 Reporting Violations

If you become aware of any violation of this AUP, please report it immediately to:
- **Email:** abuse@heroforge.io
- **Security Issues:** security@heroforge.io

Reports may be made anonymously.

### 7.3 Investigation Process

Upon receiving a report or detecting a potential violation:

1. We will investigate the matter promptly
2. We may suspend access during investigation
3. We will provide the account holder an opportunity to respond
4. We will take appropriate action based on findings
5. We will document the outcome

### 7.4 Enforcement Actions

Violations may result in:

| Severity | Possible Actions |
|----------|-----------------|
| Minor | Warning, required training |
| Moderate | Temporary suspension, feature restrictions |
| Serious | Account termination, legal referral |
| Severe | Immediate termination, law enforcement referral |

---

## 8. Legal Compliance

### 8.1 Computer Fraud and Abuse Act (CFAA)

In the United States, unauthorized access to computer systems is a federal crime under the CFAA (18 U.S.C. § 1030). Violations can result in:
- Civil liability
- Criminal prosecution
- Substantial fines
- Imprisonment

### 8.2 Computer Misuse Act (UK)

In the United Kingdom, unauthorized access is prohibited under the Computer Misuse Act 1990. Similar laws exist in most jurisdictions.

### 8.3 International Laws

You are responsible for understanding and complying with applicable laws in:
- Your jurisdiction
- The jurisdiction where target systems are located
- Any jurisdiction where data may transit

### 8.4 Our Cooperation

We will cooperate with law enforcement agencies investigating:
- Unauthorized access
- Criminal activity
- National security matters
- Child exploitation

---

## 9. Special Provisions

### 9.1 Bug Bounty Programs

When participating in bug bounty programs:
- Read and accept the program's terms before testing
- Stay within the defined scope
- Follow responsible disclosure timelines
- Do not access, modify, or delete user data
- Report findings through official channels

### 9.2 Capture The Flag (CTF) and Training

For CTF competitions and training environments:
- Only use designated training systems
- Do not attack infrastructure outside the CTF
- Follow competition rules
- Do not use exploits against production systems

### 9.3 Security Research

For legitimate security research:
- Operate within legal boundaries
- Follow responsible disclosure practices
- Do not access user data unnecessarily
- Coordinate with affected vendors
- Consider the public interest

---

## 10. Industry Standards

### 10.1 Professional Standards

We encourage adherence to professional standards including:

- **PTES** (Penetration Testing Execution Standard)
- **OWASP Testing Guide**
- **NIST Cybersecurity Framework**
- **(ISC)² Code of Ethics**
- **EC-Council Code of Ethics**
- **CREST Code of Conduct**

### 10.2 Responsible Disclosure

We support responsible disclosure practices:
- Report vulnerabilities to affected parties
- Allow reasonable time for remediation
- Coordinate disclosure timing
- Avoid causing unnecessary harm
- Protect sensitive details until patched

---

## 11. Updates to This Policy

### 11.1 Modifications

We may update this AUP to address:
- New threats or attack techniques
- Changes in law or regulation
- Improvements to our Service
- Industry best practices

### 11.2 Notification

We will notify you of material changes by:
- Email to registered users
- Notice on our website
- In-app notification

### 11.3 Effective Date

Updated policies are effective upon posting unless otherwise specified.

---

## 12. Contact Information

### 12.1 Questions

For questions about this AUP:
- **Email:** policy@heroforge.io
- **Support:** support@heroforge.io

### 12.2 Reporting Violations

To report suspected violations:
- **Email:** abuse@heroforge.io
- **Urgent Security Issues:** security@heroforge.io

### 12.3 Legal Matters

For legal inquiries:
- **Email:** legal@heroforge.io

---

## 13. Acknowledgment

By using the HeroForge Service, you acknowledge that:

1. You have read and understood this Acceptable Use Policy
2. You agree to comply with all provisions of this AUP
3. You understand the consequences of violating this AUP
4. You accept responsibility for your use of the Service
5. You will maintain proper authorization for all testing activities
6. You understand that unauthorized access is illegal and unethical

---

## Appendix A: Authorization Checklist

Before conducting any security testing, verify:

- [ ] Written authorization obtained from system owner
- [ ] Scope clearly defined (IP ranges, domains, systems)
- [ ] Testing timeframe specified
- [ ] Emergency contacts documented
- [ ] Exclusions identified (production systems, specific data)
- [ ] Rules of engagement agreed upon
- [ ] Legal review completed (if required)
- [ ] Insurance coverage confirmed (if required)
- [ ] Client stakeholders notified
- [ ] Backup and recovery procedures understood

---

## Appendix B: Sample Authorization Letter

**[ORGANIZATION LETTERHEAD]**

**Authorization for Security Testing**

Date: _______________

This letter authorizes [TESTER NAME/COMPANY] to conduct security testing on the following systems owned/operated by [ORGANIZATION NAME]:

**Scope:**
- IP Ranges: _________________
- Domains: _________________
- Applications: _________________

**Authorized Activities:**
- [ ] Vulnerability scanning
- [ ] Penetration testing
- [ ] Social engineering
- [ ] Physical security testing
- [ ] Other: _________________

**Timeframe:**
- Start Date: _______________
- End Date: _______________
- Testing Hours: _______________

**Exclusions:**
_________________________________________________

**Emergency Contact:**
Name: _______________
Phone: _______________
Email: _______________

**Authorized by:**
Name: _______________
Title: _______________
Signature: _______________
Date: _______________

---

**HEROFORGE ACCEPTABLE USE POLICY**
Version 1.0 | January 2026

*This document requires legal review before publication.*
