# HeroForge Penetration Testing Authorization Agreement

**Template Version 1.0 | January 2026**

---

## PURPOSE

This Penetration Testing Authorization Agreement ("Agreement") establishes the scope, terms, and conditions under which security testing will be performed. This document serves as legal authorization for the testing activities described herein.

**IMPORTANT:** This authorization must be executed BEFORE any security testing begins. Unauthorized security testing may violate federal and state laws, including the Computer Fraud and Abuse Act (18 U.S.C. § 1030).

---

## PART 1: PARTIES

### 1.1 Authorizing Organization (System Owner)

| Field | Information |
|-------|-------------|
| Organization Name | |
| Legal Entity Type | |
| Address | |
| Primary Contact Name | |
| Primary Contact Title | |
| Primary Contact Email | |
| Primary Contact Phone | |
| Emergency Contact Name | |
| Emergency Contact Phone | |

### 1.2 Testing Organization/Individual

| Field | Information |
|-------|-------------|
| Organization/Individual Name | |
| Address | |
| Primary Tester Name | |
| Primary Tester Email | |
| Primary Tester Phone | |
| Insurance Policy Number | |
| Insurance Provider | |

---

## PART 2: AUTHORIZATION STATEMENT

### 2.1 Grant of Authorization

I, the undersigned, hereby authorize the Testing Organization/Individual identified above to perform security testing on the systems, networks, and applications specified in this Agreement.

I represent and warrant that:

- [ ] I am authorized to grant this permission on behalf of the Authorizing Organization
- [ ] I have the legal authority to authorize testing of all systems specified
- [ ] The systems specified are owned by, leased to, or operated by the Authorizing Organization
- [ ] I have obtained any necessary approvals from third parties (cloud providers, hosting companies, etc.)
- [ ] I understand the nature and potential risks of security testing
- [ ] I accept responsibility for ensuring this authorization is valid and complete

### 2.2 Third-Party Systems

If any systems to be tested are hosted by or connected to third parties:

| Third Party | Relationship | Authorization Status |
|-------------|--------------|---------------------|
| | | [ ] Obtained [ ] Not Required |
| | | [ ] Obtained [ ] Not Required |
| | | [ ] Obtained [ ] Not Required |

**Cloud Provider Authorizations:**
- [ ] AWS: Penetration testing policy reviewed, no additional authorization required for standard tests
- [ ] Azure: Penetration testing rules reviewed, no notification required
- [ ] GCP: Acceptable Use Policy reviewed, no notification required
- [ ] Other: ________________________________

---

## PART 3: SCOPE OF TESTING

### 3.1 Testing Type

Select all testing types authorized:

**Network Testing:**
- [ ] External network penetration testing
- [ ] Internal network penetration testing
- [ ] Wireless network assessment
- [ ] Network device configuration review

**Application Testing:**
- [ ] Web application penetration testing
- [ ] Mobile application testing
- [ ] API security testing
- [ ] Thick client application testing

**Infrastructure Testing:**
- [ ] Cloud security assessment
- [ ] Container security testing
- [ ] Server/endpoint testing
- [ ] Database security testing

**Specialized Testing:**
- [ ] Social engineering (phishing, pretexting)
- [ ] Physical security testing
- [ ] Red team engagement
- [ ] Purple team exercise

**Compliance Testing:**
- [ ] PCI-DSS assessment
- [ ] HIPAA security assessment
- [ ] SOC 2 testing
- [ ] Other: ________________________________

### 3.2 In-Scope Assets

**IP Addresses/Ranges:**

| IP Address/Range | Description | Owner Confirmed |
|------------------|-------------|-----------------|
| | | [ ] Yes |
| | | [ ] Yes |
| | | [ ] Yes |
| | | [ ] Yes |
| | | [ ] Yes |

**Domains/Subdomains:**

| Domain | Description | Owner Confirmed |
|--------|-------------|-----------------|
| | | [ ] Yes |
| | | [ ] Yes |
| | | [ ] Yes |

**Applications:**

| Application Name | URL/Location | Environment |
|-----------------|--------------|-------------|
| | | [ ] Prod [ ] Staging [ ] Dev |
| | | [ ] Prod [ ] Staging [ ] Dev |
| | | [ ] Prod [ ] Staging [ ] Dev |

**Cloud Resources:**

| Provider | Account/Subscription ID | Resources |
|----------|------------------------|-----------|
| | | |
| | | |

### 3.3 Explicitly Out-of-Scope

The following are NOT authorized for testing:

| Asset/System | Reason for Exclusion |
|--------------|---------------------|
| | |
| | |
| | |

**Standard Exclusions (unless explicitly authorized above):**
- [ ] Denial of service attacks
- [ ] Physical security testing
- [ ] Social engineering of employees
- [ ] Testing of third-party systems
- [ ] Production database modification
- [ ] Customer/user data access

---

## PART 4: TESTING PARAMETERS

### 4.1 Testing Window

| Parameter | Value |
|-----------|-------|
| Start Date | |
| End Date | |
| Testing Hours | |
| Time Zone | |
| Blackout Periods | |

**Testing Schedule:**
- [ ] Testing may occur 24/7 during the authorized period
- [ ] Testing limited to business hours only
- [ ] Testing limited to non-business hours only
- [ ] Custom schedule: ________________________________

### 4.2 Testing Intensity

**Authorized Testing Depth:**
- [ ] Passive reconnaissance only
- [ ] Active scanning and enumeration
- [ ] Vulnerability validation (safe exploitation)
- [ ] Full exploitation (controlled)
- [ ] Post-exploitation and lateral movement
- [ ] Persistence testing (with cleanup)

**Rate Limiting:**
- Maximum concurrent connections: _______________
- Maximum requests per second: _______________
- Other limitations: _______________

### 4.3 Credentials Provided

| Credential Type | Username | Access Level | System |
|-----------------|----------|--------------|--------|
| | | | |
| | | | |
| | | | |

- [ ] No credentials provided (black box testing)
- [ ] Limited credentials provided (gray box testing)
- [ ] Full credentials provided (white box testing)

### 4.4 Sensitive Data Handling

If testers encounter sensitive data during testing:

- [ ] Do not access, copy, or exfiltrate any sensitive data
- [ ] May access but not copy or exfiltrate sensitive data
- [ ] May access and document (redacted) for reporting purposes
- [ ] Custom handling: ________________________________

**Sensitive Data Categories:**
- [ ] Personal Identifiable Information (PII)
- [ ] Protected Health Information (PHI)
- [ ] Payment Card Data (PCI)
- [ ] Credentials and secrets
- [ ] Intellectual property
- [ ] Other: ________________________________

---

## PART 5: RULES OF ENGAGEMENT

### 5.1 Communication Protocols

**Status Updates:**
- Frequency: [ ] Daily [ ] Weekly [ ] Upon findings [ ] Other: _______
- Method: [ ] Email [ ] Phone [ ] Portal [ ] Other: _______
- Recipient: ________________________________

**Critical Finding Notification:**
- Notify immediately for: [ ] Critical [ ] High [ ] All exploitable
- Contact method: ________________________________
- Maximum response time expected: ________________________________

**Emergency Contacts:**

| Priority | Name | Phone | Email |
|----------|------|-------|-------|
| Primary | | | |
| Secondary | | | |
| Escalation | | | |

### 5.2 Incident Handling

If testing causes unintended impact:

1. **Immediate Actions:**
   - Stop testing activity immediately
   - Document the incident
   - Contact emergency contact within: _______ minutes

2. **Incident Response:**
   - Tester will assist with remediation
   - Full incident report within: _______ hours
   - Post-incident review meeting: [ ] Required [ ] Optional

### 5.3 Evidence Handling

**During Testing:**
- [ ] Screenshots may be captured
- [ ] Screen recordings may be made
- [ ] Data samples may be collected (redacted)
- [ ] All evidence stored encrypted

**After Testing:**
- Evidence retained for: _______ days after final report
- Evidence destruction method: [ ] Secure delete [ ] Certificate of destruction
- Evidence may be shared with: ________________________________

### 5.4 Prohibited Actions

Unless explicitly authorized elsewhere in this document:

- [ ] Denial of service attacks
- [ ] Physical intrusion or social engineering
- [ ] Accessing systems not explicitly listed
- [ ] Modifying or deleting production data
- [ ] Installing persistent backdoors
- [ ] Exfiltrating sensitive data
- [ ] Testing during blackout periods
- [ ] Exceeding authorized testing depth
- [ ] Sharing findings with unauthorized parties

---

## PART 6: DELIVERABLES

### 6.1 Required Deliverables

| Deliverable | Due Date | Format |
|-------------|----------|--------|
| Draft Report | | [ ] PDF [ ] Word [ ] Other |
| Final Report | | [ ] PDF [ ] Word [ ] Other |
| Executive Summary | | [ ] PDF [ ] Presentation |
| Technical Findings | | [ ] PDF [ ] Spreadsheet |
| Remediation Guidance | | [ ] Included [ ] Separate |
| Retest Results | | [ ] Included [ ] Separate |

### 6.2 Report Contents

Final report shall include:
- [ ] Executive summary
- [ ] Methodology description
- [ ] Detailed findings with evidence
- [ ] Risk ratings and prioritization
- [ ] Remediation recommendations
- [ ] Positive findings (what worked well)

### 6.3 Presentation

- [ ] Findings presentation required
- [ ] Attendees: ________________________________
- [ ] Duration: _______ minutes
- [ ] Format: [ ] In-person [ ] Virtual [ ] Either

---

## PART 7: LEGAL PROVISIONS

### 7.1 Limitation of Liability

THE TESTING ORGANIZATION SHALL NOT BE LIABLE FOR:
- System downtime or disruption caused by authorized testing activities within scope
- Data loss if proper backups were not maintained by the Authorizing Organization
- Business interruption resulting from discovered vulnerabilities
- Third-party claims arising from the Authorizing Organization's failure to remediate

THE TESTING ORGANIZATION SHALL BE LIABLE FOR:
- Negligent or reckless conduct
- Testing outside the authorized scope
- Failure to follow the rules of engagement
- Breach of confidentiality

Maximum liability shall not exceed: [ ] Fee paid [ ] $_________ [ ] Per Main Agreement

### 7.2 Indemnification

Each party shall indemnify the other for claims arising from:
- The indemnifying party's negligence or willful misconduct
- The indemnifying party's breach of this Agreement
- The indemnifying party's violation of applicable law

### 7.3 Insurance Requirements

Testing Organization maintains:
- [ ] Professional liability insurance: $_________ minimum
- [ ] Cyber liability insurance: $_________ minimum
- [ ] General liability insurance: $_________ minimum

Certificates of insurance available upon request.

### 7.4 Confidentiality

All information related to this engagement, including but not limited to:
- Testing results and findings
- System configurations and vulnerabilities
- Business processes and data
- This Agreement itself

Shall be treated as confidential and not disclosed to any third party without written consent, except:
- As required by law
- To employees/contractors with need to know
- To legal counsel

Confidentiality obligations survive termination for: _______ years

### 7.5 Compliance with Laws

Both parties shall comply with all applicable laws, including:
- Computer Fraud and Abuse Act (18 U.S.C. § 1030)
- State computer crime laws
- Data protection regulations (GDPR, CCPA, etc.)
- Industry regulations (PCI-DSS, HIPAA, etc.)

### 7.6 Intellectual Property

- Testing methodologies remain property of Testing Organization
- Discovered vulnerabilities and findings become property of Authorizing Organization
- Custom tools developed specifically for this engagement: [ ] Tester [ ] Client [ ] Joint

---

## PART 8: SIGNATURES

### 8.1 Authorizing Organization

By signing below, I confirm that:
- I have read and understood this Agreement
- I am authorized to grant this testing authorization
- All information provided is accurate and complete
- I accept the terms and conditions herein

**Authorized Representative:**

| | |
|---|---|
| Printed Name | |
| Title | |
| Date | |
| Signature | |

**Witness (if required):**

| | |
|---|---|
| Printed Name | |
| Date | |
| Signature | |

### 8.2 Testing Organization

By signing below, I confirm that:
- I have read and understood this Agreement
- I will conduct testing only within the authorized scope
- I will follow the rules of engagement
- I will maintain confidentiality of all findings

**Testing Representative:**

| | |
|---|---|
| Printed Name | |
| Title | |
| Date | |
| Signature | |

---

## PART 9: APPENDICES

### Appendix A: Detailed Asset Inventory

*Attach detailed asset inventory if scope is extensive*

### Appendix B: Network Diagrams

*Attach network diagrams if available*

### Appendix C: Previous Assessment Reports

*Reference previous assessments if relevant*

### Appendix D: Specific Technical Requirements

*Document any specific technical requirements or constraints*

### Appendix E: Additional Terms

*Document any additional terms agreed by the parties*

---

## DOCUMENT CONTROL

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | January 2026 | HeroForge | Initial template |
| | | | |

---

## QUICK REFERENCE: EMERGENCY CONTACTS

| Role | Name | Phone | Email |
|------|------|-------|-------|
| Client Emergency | | | |
| Tester Emergency | | | |
| HeroForge Support | | support@heroforge.io | |

---

**HEROFORGE PENETRATION TESTING AUTHORIZATION TEMPLATE**
Version 1.0 | January 2026

*This template should be customized for each engagement and reviewed by legal counsel.*

---

## USAGE INSTRUCTIONS FOR HEROFORGE CUSTOMERS

1. **Before Testing:**
   - Complete all sections of this document
   - Obtain signatures from authorized personnel
   - Verify third-party authorizations if needed
   - Store a copy securely

2. **During Testing:**
   - Keep this document accessible
   - Reference scope if questions arise
   - Follow communication protocols

3. **After Testing:**
   - Retain for your records
   - Reference during remediation
   - Use for future engagement planning

4. **In HeroForge:**
   - Upload signed authorization to engagement record
   - Reference authorization ID in scan configurations
   - Maintain audit trail of all testing activities
