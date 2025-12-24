# Data Processing Agreement

**HeroForge Data Processing Agreement (DPA)**

**Version:** 1.0
**Last Updated:** December 24, 2024

---

## Parties

This Data Processing Agreement ("DPA") is entered into between:

**Customer** ("Data Controller" or "Controller"):
- Company Name: _______________________________
- Address: _______________________________
- Contact Email: _______________________________

**HeroForge** ("Data Processor" or "Processor"):
- HeroForge Security
- Contact: dpo@heroforge.security

---

## 1. Definitions

**"Data Protection Laws"** means all applicable laws relating to data protection, including GDPR (EU 2016/679), UK GDPR, CCPA, and other applicable privacy laws.

**"Personal Data"** means any information relating to an identified or identifiable natural person.

**"Processing"** means any operation performed on Personal Data, including collection, storage, use, transmission, and deletion.

**"Sub-processor"** means any third party engaged by Processor to process Personal Data on behalf of Controller.

**"Security Incident"** means any unauthorized access, acquisition, use, or disclosure of Personal Data.

---

## 2. Scope and Purpose

### 2.1 Purpose
This DPA governs the processing of Personal Data by Processor on behalf of Controller in connection with the HeroForge security assessment platform services ("Services").

### 2.2 Nature of Processing
- Collection and storage of user account information
- Processing of security scan data and results
- Generation of security reports
- Provision of security assessment services

### 2.3 Categories of Data Subjects
- Controller's employees and contractors
- Individuals whose data may be included in scan targets (with authorization)

### 2.4 Types of Personal Data
- Account information (name, email, credentials)
- Technical data (IP addresses, system information)
- Scan results and security findings
- Audit logs and access records

---

## 3. Controller Obligations

### 3.1 Lawful Basis
Controller warrants that it has:
- A lawful basis for processing Personal Data
- Obtained all necessary consents
- Proper authorization to scan all target systems
- Provided required notices to data subjects

### 3.2 Instructions
Controller shall provide documented instructions for Processing. Processor shall process Personal Data only in accordance with Controller's instructions.

### 3.3 Data Accuracy
Controller is responsible for ensuring the accuracy of Personal Data provided to Processor.

---

## 4. Processor Obligations

### 4.1 Processing Limitations
Processor shall:
- Process Personal Data only on documented instructions from Controller
- Not process Personal Data for any other purpose
- Inform Controller if an instruction infringes Data Protection Laws

### 4.2 Confidentiality
Processor shall ensure that personnel authorized to process Personal Data:
- Are subject to confidentiality obligations
- Process Personal Data only as instructed
- Receive appropriate data protection training

### 4.3 Security Measures
Processor implements appropriate technical and organizational measures including:

| Category | Measures |
|----------|----------|
| Encryption | AES-256 at rest, TLS 1.2+ in transit |
| Access Control | Role-based access, MFA, account lockout |
| Authentication | bcrypt password hashing, JWT tokens |
| Audit Logging | Comprehensive activity logging |
| Network Security | Firewalls, intrusion detection |
| Physical Security | Secure data center facilities |

### 4.4 Sub-processors
Processor shall:
- Maintain a list of authorized Sub-processors (Annex A)
- Notify Controller of new Sub-processors 30 days in advance
- Ensure Sub-processors are bound by equivalent obligations
- Remain liable for Sub-processor compliance

### 4.5 Assistance
Processor shall assist Controller with:
- Data subject rights requests
- Data protection impact assessments
- Regulatory consultations
- Security incident responses

---

## 5. Data Subject Rights

### 5.1 Requests
Processor shall promptly notify Controller of any data subject requests and assist in responding.

### 5.2 Response Time
Processor shall respond to Controller's requests within 10 business days.

### 5.3 Supported Rights
- Access to Personal Data
- Rectification of inaccurate data
- Erasure ("right to be forgotten")
- Data portability
- Restriction of processing
- Objection to processing

---

## 6. Security Incidents

### 6.1 Notification
Processor shall notify Controller of any Security Incident without undue delay, and in any event within 48 hours of becoming aware.

### 6.2 Notification Content
The notification shall include:
- Nature of the incident
- Categories and approximate number of affected data subjects
- Likely consequences
- Measures taken or proposed to address the incident

### 6.3 Cooperation
Processor shall cooperate with Controller's investigation and provide additional information as requested.

### 6.4 Documentation
Processor shall document all Security Incidents, including facts, effects, and remedial actions.

---

## 7. International Transfers

### 7.1 Location
Personal Data is primarily stored and processed in: [Specify Region]

### 7.2 Transfer Mechanisms
For transfers outside the EEA/UK, Processor uses:
- Standard Contractual Clauses (SCCs)
- Adequacy decisions where applicable
- Binding Corporate Rules (if applicable)

### 7.3 Additional Safeguards
Processor implements supplementary measures including:
- Encryption of data in transit and at rest
- Access controls and audit logging
- Regular security assessments

---

## 8. Audits and Inspections

### 8.1 Right to Audit
Controller may audit Processor's compliance with this DPA:
- Upon reasonable notice (minimum 30 days)
- During normal business hours
- No more than once per year (unless required by regulatory authority)

### 8.2 Audit Scope
Audits may include:
- Review of security policies and procedures
- Inspection of technical controls
- Review of Sub-processor agreements
- Interview of relevant personnel

### 8.3 Audit Costs
Controller bears the costs of audits, unless the audit reveals material non-compliance.

### 8.4 Third-Party Audits
Controller may accept relevant third-party audit reports (SOC 2, ISO 27001) in lieu of direct audits.

---

## 9. Data Retention and Deletion

### 9.1 Retention Period
Personal Data is retained for:
- Account data: Duration of agreement + 30 days
- Scan results: As configured by Controller (default 90 days)
- Audit logs: 1 year

### 9.2 Deletion
Upon termination or request, Processor shall:
- Delete or return all Personal Data within 30 days
- Provide certification of deletion upon request
- Delete all copies except as required by law

### 9.3 Retention Exceptions
Processor may retain Personal Data as required by applicable law, with notification to Controller.

---

## 10. Term and Termination

### 10.1 Term
This DPA is effective from the date of execution and continues for the duration of the Services agreement.

### 10.2 Survival
Obligations regarding confidentiality, data deletion, and liability survive termination.

---

## 11. Liability

### 11.1 Indemnification
Each party shall indemnify the other for losses arising from its breach of this DPA.

### 11.2 Limitation
Liability limitations in the Services agreement apply to this DPA.

---

## 12. Miscellaneous

### 12.1 Governing Law
This DPA is governed by the same law as the Services agreement.

### 12.2 Amendments
Amendments must be in writing and signed by both parties.

### 12.3 Conflict
In case of conflict, this DPA prevails over the Services agreement regarding data protection.

---

## Signatures

**Controller:**

Signature: _______________________________
Name: _______________________________
Title: _______________________________
Date: _______________________________


**HeroForge (Processor):**

Signature: _______________________________
Name: _______________________________
Title: _______________________________
Date: _______________________________

---

## Annex A: Authorized Sub-processors

| Sub-processor | Purpose | Location | Security Measures |
|---------------|---------|----------|-------------------|
| [Cloud Provider] | Infrastructure hosting | [Region] | ISO 27001, SOC 2 |
| [Payment Processor] | Payment processing | [Region] | PCI-DSS |
| [Email Provider] | Transactional emails | [Region] | SOC 2 |

*This list is current as of the Last Updated date. Controller will be notified of changes.*

---

## Annex B: Technical and Organizational Measures

### B.1 Access Control
- Role-based access control (RBAC)
- Multi-factor authentication (MFA)
- Account lockout after failed attempts
- Session timeout and management

### B.2 Encryption
- AES-256 database encryption (SQLCipher)
- TLS 1.2+ for data in transit
- Encrypted backups

### B.3 Audit and Monitoring
- Comprehensive audit logging
- Real-time security monitoring
- Intrusion detection systems
- Regular log review

### B.4 Incident Response
- Documented incident response plan
- 24/7 security monitoring
- Escalation procedures
- Post-incident analysis

### B.5 Business Continuity
- Regular data backups
- Disaster recovery procedures
- Redundant infrastructure
- Tested recovery processes

---

## Annex C: Standard Contractual Clauses

[For EU/UK transfers, the applicable SCCs (Commission Decision 2021/914) are incorporated by reference and available upon request.]

---

**END OF DATA PROCESSING AGREEMENT**
