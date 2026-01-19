# HeroForge Export Compliance Policy

**Version 1.0 | January 2026**

---

## 1. PURPOSE AND SCOPE

### 1.1 Purpose

This Export Compliance Policy ("Policy") establishes HeroForge's commitment to compliance with all applicable export control laws and regulations. As a provider of cybersecurity software that includes vulnerability scanning, exploitation tools, and security testing capabilities, HeroForge recognizes that certain components of our technology may be subject to export controls.

### 1.2 Scope

This Policy applies to:
- All HeroForge products and services
- All employees, contractors, and partners
- All customers and end users
- All geographic locations

### 1.3 Regulatory Framework

HeroForge complies with:

**United States:**
- Export Administration Regulations (EAR) - 15 CFR Parts 730-774
- International Traffic in Arms Regulations (ITAR) - 22 CFR Parts 120-130
- Office of Foreign Assets Control (OFAC) Sanctions
- Deemed Export Rules

**International:**
- Wassenaar Arrangement on Export Controls
- European Union Dual-Use Regulation (EU 2021/821)
- UK Export Control Act 2002
- Country-specific export control laws

---

## 2. PRODUCT CLASSIFICATION

### 2.1 Export Control Classification

HeroForge has conducted an export classification analysis of its products:

| Component | ECCN | Classification Basis | License Requirement |
|-----------|------|---------------------|---------------------|
| Core Platform | EAR99 | General software, not specifically controlled | No license required for most destinations |
| Vulnerability Scanner | 5D002 | Information security software | License may be required |
| Exploitation Framework | 5D002 / 4D004 | Intrusion software / Cybersecurity items | License review required |
| C2 Framework | 5D002 | Information security software | License review required |
| Encryption Module | 5D002 | Uses encryption > 64-bit | Encryption reporting may apply |

**Note:** This classification is for guidance only. Actual classification may vary based on specific features and use cases. Consult legal counsel for definitive classification.

### 2.2 Wassenaar Arrangement Considerations

Certain HeroForge capabilities may fall under Wassenaar Arrangement Category 4 (Computers) and Category 5 (Telecommunications and Information Security):

**Potentially Controlled Items:**
- Intrusion software and tools
- Vulnerability exploitation capabilities
- Network monitoring with interception features
- Encryption above certain thresholds

**Exemptions That May Apply:**
- Publicly available software exception
- Mass market software exception
- Fundamental research exception

### 2.3 Encryption

HeroForge uses encryption for:
- TLS 1.3 for data in transit
- AES-256 for data at rest
- Various cryptographic functions

**Encryption Reporting:**
- Annual self-classification report filed with BIS (if required)
- ENC Unrestricted classification may apply

---

## 3. PROHIBITED DESTINATIONS AND PARTIES

### 3.1 Embargoed Countries and Regions

HeroForge services are NOT available in the following embargoed destinations:

**Comprehensively Sanctioned (OFAC):**
- Cuba
- Iran
- North Korea
- Syria
- Crimea region of Ukraine
- Donetsk People's Republic (DNR)
- Luhansk People's Republic (LNR)

**Other Restricted Destinations:**
- Countries subject to UN arms embargoes
- Countries with significant export restrictions

### 3.2 Denied Parties Screening

Before providing services, HeroForge screens all customers against:

**U.S. Government Lists:**
- Denied Persons List (DPL)
- Entity List
- Unverified List
- Specially Designated Nationals (SDN) List
- Foreign Sanctions Evaders List
- Sectoral Sanctions Identifications List
- Non-SDN Palestinian Legislative Council List
- Non-SDN Menu-Based Sanctions List

**International Lists:**
- EU Consolidated List of Sanctions
- UK Sanctions List
- UN Security Council Consolidated List

### 3.3 Prohibited End Uses

HeroForge products may NOT be used for:

- **Military End Uses** in certain countries
- **Nuclear, Chemical, or Biological Weapons** development
- **Missile Technology** development
- **Terrorism** or support of terrorist organizations
- **Human Rights Violations** or surveillance of civilians
- **Malicious Cyber Activities** against unauthorized targets

### 3.4 Prohibited End Users

HeroForge products may NOT be provided to:

- Military or intelligence services of embargoed countries
- Entities involved in WMD proliferation
- Entities on restricted party lists
- Entities with known involvement in human rights abuses
- Criminal organizations

---

## 4. COMPLIANCE PROCEDURES

### 4.1 Customer Screening Process

**Pre-Sales Screening:**

```
┌─────────────────────────────────────────────────────────────────┐
│                    CUSTOMER SCREENING PROCESS                   │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. REGISTRATION                                                │
│     ├── Collect organization name, address, country            │
│     ├── Collect end-user information                           │
│     └── Collect intended use case                              │
│                                                                 │
│  2. AUTOMATED SCREENING                                         │
│     ├── Check against denied party lists                       │
│     ├── Check country against embargo list                     │
│     └── Flag any potential matches                             │
│                                                                 │
│  3. REVIEW (if flagged)                                         │
│     ├── Manual review by compliance team                       │
│     ├── Additional due diligence if needed                     │
│     └── Decision: Approve / Reject / Escalate                  │
│                                                                 │
│  4. ONGOING MONITORING                                          │
│     ├── Periodic re-screening                                  │
│     ├── Monitor for red flags                                  │
│     └── Update screening upon renewal                          │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Red Flags to Watch For:**
- Reluctance to provide end-user information
- Unusual payment methods or routing
- Requests for delivery to freight forwarders
- Requests to remove export compliance warnings
- Stated end-use inconsistent with normal business
- Customer in embargoed country using VPN

### 4.2 End-User Certification

For higher-risk transactions, customers must provide:

**End-User Statement:**
- Legal name and address of end user
- Description of intended use
- Certification that product will not be re-exported
- Certification of compliance with applicable laws

**Template provided in Appendix A.**

### 4.3 License Determination

When a license may be required:

1. **Classify the product** using ECCN
2. **Identify the destination** country
3. **Check License Exception** eligibility
4. **Determine if license required** using Commerce Country Chart
5. **Apply for license** if required (BIS Form 748P)

### 4.4 Record Keeping

HeroForge maintains records of:
- Customer screening results
- End-user certifications
- Export classifications
- License applications and determinations
- Transaction records

**Retention Period:** 5 years minimum (or as required by law)

---

## 5. IMPLEMENTATION IN HEROFORGE PLATFORM

### 5.1 Technical Controls

**Geographic Restrictions:**
```
// Embargoed countries blocked at registration
const BLOCKED_COUNTRIES = [
  'CU', // Cuba
  'IR', // Iran
  'KP', // North Korea
  'SY', // Syria
  'UA-43', // Crimea
  // ... additional restricted regions
];
```

**IP Geolocation:**
- Block access from embargoed regions
- Flag suspicious VPN usage
- Log geographic access patterns

**Feature Restrictions:**
- Certain features may be restricted by geography
- Exploitation tools require additional verification
- C2 capabilities limited to verified customers

### 5.2 Registration Requirements

During registration, users must:
1. Provide accurate organization information
2. Specify country of operation
3. Describe intended use case
4. Accept export compliance terms
5. Certify compliance with applicable laws

### 5.3 Terms of Service Integration

Export compliance requirements are incorporated in:
- Terms of Service (Section on Export Compliance)
- Acceptable Use Policy (Prohibited Uses)
- Registration acknowledgments

### 5.4 Ongoing Monitoring

HeroForge monitors for:
- Access from restricted locations
- Unusual usage patterns
- Attempts to circumvent controls
- Changes in customer status

---

## 6. ROLES AND RESPONSIBILITIES

### 6.1 Export Compliance Officer

**Responsibilities:**
- Oversee export compliance program
- Conduct product classifications
- Review flagged transactions
- Maintain compliance records
- Provide training
- Report to management

**Contact:** compliance@heroforge.io

### 6.2 Sales and Customer Success

**Responsibilities:**
- Collect required customer information
- Report red flags to compliance
- Ensure end-user certifications obtained
- Do not proceed with flagged transactions without approval

### 6.3 Engineering

**Responsibilities:**
- Implement technical controls
- Maintain geographic restrictions
- Report potential classification changes
- Support compliance audits

### 6.4 All Employees

**Responsibilities:**
- Complete export compliance training
- Report suspected violations
- Follow procedures in this Policy
- Seek guidance when uncertain

---

## 7. TRAINING AND AWARENESS

### 7.1 Required Training

| Role | Training | Frequency |
|------|----------|-----------|
| All employees | Export compliance basics | Annual |
| Sales/Customer Success | Customer screening procedures | Annual + updates |
| Engineering | Technical controls | As needed |
| Compliance team | Advanced export controls | Annual + updates |

### 7.2 Training Content

- Overview of export control laws
- HeroForge product classifications
- Screening procedures
- Red flag identification
- Reporting procedures
- Consequences of violations

---

## 8. VIOLATIONS AND PENALTIES

### 8.1 Consequences of Violations

**Civil Penalties (U.S.):**
- Up to $300,000 per violation (EAR)
- Up to $1,000,000+ per violation (OFAC)

**Criminal Penalties (U.S.):**
- Up to $1,000,000 per violation
- Up to 20 years imprisonment

**Other Consequences:**
- Denial of export privileges
- Debarment from government contracts
- Reputational damage
- Loss of business

### 8.2 Internal Consequences

Employees who violate this Policy may face:
- Disciplinary action up to termination
- Personal liability for penalties
- Referral to law enforcement

### 8.3 Voluntary Disclosure

If a violation is discovered:
1. Stop the violating activity immediately
2. Report to Export Compliance Officer
3. Preserve all relevant records
4. Consider voluntary self-disclosure to BIS/OFAC
5. Implement corrective measures

---

## 9. CUSTOMER OBLIGATIONS

### 9.1 Customer Certifications

By using HeroForge, customers certify that:

1. **Accuracy of Information:** All registration information is accurate
2. **Lawful Use:** Services will be used only for lawful purposes
3. **No Re-Export:** Services will not be re-exported in violation of law
4. **No Prohibited End Use:** Services will not be used for prohibited purposes
5. **No Prohibited End Users:** Services will not be provided to prohibited parties
6. **Compliance:** Customer will comply with all applicable export laws

### 9.2 Customer Responsibilities

Customers are responsible for:
- Maintaining accurate account information
- Notifying HeroForge of changes in circumstances
- Obtaining any required import licenses in their jurisdiction
- Complying with local laws regarding security testing tools
- Ensuring authorized users comply with this Policy

### 9.3 Prohibited Customer Actions

Customers shall NOT:
- Access services from embargoed locations
- Use VPNs to circumvent geographic restrictions
- Provide false information during registration
- Share access with prohibited parties
- Re-export or transfer services without authorization

---

## 10. SPECIAL PROVISIONS FOR SECURITY TOOLS

### 10.1 Intrusion Software Considerations

HeroForge's exploitation and penetration testing features may constitute "intrusion software" under Wassenaar Arrangement definitions.

**Mitigating Factors:**
- Software is for defensive security testing
- Requires authorization before use
- Includes safeguards against misuse
- May qualify for exceptions

### 10.2 Dual-Use Technology

HeroForge acknowledges that security testing tools can be used for both:
- **Legitimate purposes:** Authorized security testing, defense
- **Illegitimate purposes:** Unauthorized access, attacks

**Safeguards implemented:**
- Acceptable Use Policy enforcement
- Authorization verification
- Audit logging
- Account termination for misuse

### 10.3 Publicly Available Software

Certain HeroForge components may qualify as "publicly available" under EAR § 734.7, which would exclude them from EAR jurisdiction.

**Criteria:**
- Published and available to the public
- Available at no cost or cost of reproduction
- No restrictions on further dissemination

---

## 11. AUDIT AND REVIEW

### 11.1 Internal Audits

HeroForge conducts:
- Annual export compliance audits
- Periodic reviews of screening processes
- Random transaction audits
- Technical control testing

### 11.2 External Audits

HeroForge may engage external counsel or consultants to:
- Review product classifications
- Assess compliance procedures
- Provide training
- Conduct mock audits

### 11.3 Policy Review

This Policy is reviewed:
- Annually, at minimum
- Upon significant regulatory changes
- Upon significant product changes
- Following any compliance incidents

---

## 12. CONTACT INFORMATION

### 12.1 Export Compliance Questions

**Export Compliance Officer:**
Email: compliance@heroforge.io

### 12.2 Reporting Violations

If you suspect an export violation:
- Email: compliance@heroforge.io
- Anonymous hotline: [To be established]

### 12.3 Legal Counsel

For complex export matters:
- Consult with qualified export control counsel
- Do not proceed with uncertain transactions

---

## APPENDIX A: END-USER CERTIFICATE TEMPLATE

---

### END-USER CERTIFICATE

**Reference Number:** _________________

**Date:** _________________

I, the undersigned, hereby certify on behalf of the End User identified below:

**End User Information:**

| Field | Information |
|-------|-------------|
| Legal Name | |
| Address | |
| Country | |
| Type of Organization | |
| Contact Name | |
| Contact Email | |

**Product/Service:**

| Description | Quantity |
|-------------|----------|
| HeroForge [Tier] Subscription | |

**Certifications:**

I certify that:

1. [ ] The information provided above is accurate and complete.

2. [ ] The product/service will be used solely for: ________________________________

3. [ ] The product/service will NOT be used for:
   - Development of weapons of mass destruction
   - Military end-uses in embargoed countries
   - Human rights violations
   - Unauthorized access to computer systems
   - Any purpose prohibited by law

4. [ ] The product/service will NOT be re-exported, resold, or transferred to:
   - Embargoed countries or regions
   - Prohibited end-users
   - Any party without proper authorization

5. [ ] I am authorized to make these certifications on behalf of the End User.

6. [ ] I will notify HeroForge immediately if any circumstances change that would affect these certifications.

**Signature:**

| | |
|---|---|
| Name | |
| Title | |
| Date | |
| Signature | |

---

## APPENDIX B: DENIED PARTY SCREENING CHECKLIST

### Pre-Transaction Screening

- [ ] Verified customer legal name
- [ ] Verified customer address
- [ ] Verified customer country
- [ ] Screened against OFAC SDN List
- [ ] Screened against BIS Denied Persons List
- [ ] Screened against BIS Entity List
- [ ] Screened against BIS Unverified List
- [ ] Screened against EU Consolidated List
- [ ] Screened against UN Sanctions List
- [ ] Checked for red flags
- [ ] Documented screening results

### Screening Result

- [ ] CLEAR - No matches found
- [ ] POTENTIAL MATCH - Requires review
- [ ] DENIED - Prohibited party identified

**Screened By:** _________________
**Date:** _________________
**Notes:** _________________

---

## APPENDIX C: COUNTRY CLASSIFICATION REFERENCE

### License-Free Destinations (Generally)

Most commercial transactions to these destinations do not require a license:
- NATO member countries
- EU member countries
- Australia, Japan, New Zealand, South Korea
- Other allied nations

### License Review Destinations

Transactions to these destinations may require additional review:
- China (PRC)
- Russia
- Belarus
- Venezuela
- Myanmar
- Other countries with specific restrictions

### Embargoed Destinations

NO transactions permitted:
- Cuba, Iran, North Korea, Syria
- Crimea, DNR, LNR regions

*Refer to current BIS Country Chart and OFAC programs for definitive guidance.*

---

**HEROFORGE EXPORT COMPLIANCE POLICY**
Version 1.0 | January 2026

*This document requires legal review before implementation. Export control laws are complex and change frequently. Consult qualified legal counsel for specific guidance.*
