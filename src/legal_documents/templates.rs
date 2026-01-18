//! Default Legal Document Templates
//!
//! This module contains the default seeded templates for common
//! pre-engagement legal documents.

/// Get the default Rules of Engagement (ROE) template HTML
pub fn get_roe_template() -> &'static str {
    r#"<h1>Rules of Engagement</h1>

<p><strong>Document Date:</strong> {{CURRENT_DATE}}</p>

<h2>1. Parties</h2>
<p>This Rules of Engagement document ("ROE") is entered into between:</p>
<p><strong>Client:</strong> {{CLIENT_NAME}}<br>
Address: {{CLIENT_ADDRESS}}<br>
Contact: {{CLIENT_CONTACT_NAME}} ({{CLIENT_CONTACT_EMAIL}})</p>

<p><strong>Security Provider:</strong> {{COMPANY_NAME}}<br>
Address: {{COMPANY_ADDRESS}}</p>

<h2>2. Engagement Overview</h2>
<p><strong>Engagement Name:</strong> {{ENGAGEMENT_NAME}}<br>
<strong>Engagement Type:</strong> {{ENGAGEMENT_TYPE}}<br>
<strong>Start Date:</strong> {{START_DATE}}<br>
<strong>End Date:</strong> {{END_DATE}}</p>

<h2>3. Scope of Testing</h2>
<p>{{ENGAGEMENT_SCOPE}}</p>

<h3>3.1 In-Scope Systems</h3>
<p><em>[List specific IP ranges, domains, applications, and systems that are authorized for testing]</em></p>

<h3>3.2 Out-of-Scope Systems</h3>
<p><em>[List any systems, networks, or services that must NOT be tested]</em></p>

<h2>4. Authorized Activities</h2>
<p>The following testing activities are authorized during this engagement:</p>
<ul>
    <li>Network reconnaissance and enumeration</li>
    <li>Vulnerability scanning and assessment</li>
    <li>Exploitation of discovered vulnerabilities (with prior approval for critical systems)</li>
    <li>Web application security testing</li>
    <li>Social engineering testing (if specifically authorized)</li>
    <li>Password cracking of captured hashes</li>
    <li>Privilege escalation attempts</li>
    <li>Lateral movement within authorized scope</li>
</ul>

<h2>5. Prohibited Activities</h2>
<p>The following activities are explicitly prohibited:</p>
<ul>
    <li>Denial of Service (DoS) attacks</li>
    <li>Physical security testing (unless specifically authorized)</li>
    <li>Testing of out-of-scope systems</li>
    <li>Modification or destruction of production data</li>
    <li>Installation of persistent backdoors</li>
    <li>Social engineering of non-authorized personnel</li>
    <li>Testing outside of agreed time windows</li>
</ul>

<h2>6. Testing Windows</h2>
<p><strong>Primary Testing Hours:</strong> <em>[Specify approved testing hours, e.g., Monday-Friday 9:00 AM - 6:00 PM EST]</em></p>
<p><strong>After-Hours Testing:</strong> <em>[Specify if after-hours testing is permitted and any restrictions]</em></p>

<h2>7. Emergency Contact Procedures</h2>
<p>In case of any issues during testing, the following contacts should be notified immediately:</p>
<table>
    <tr>
        <th>Role</th>
        <th>Name</th>
        <th>Phone</th>
        <th>Email</th>
    </tr>
    <tr>
        <td>Client Primary Contact</td>
        <td>{{CLIENT_CONTACT_NAME}}</td>
        <td><em>[Phone]</em></td>
        <td>{{CLIENT_CONTACT_EMAIL}}</td>
    </tr>
    <tr>
        <td>Security Provider Lead</td>
        <td><em>[Name]</em></td>
        <td><em>[Phone]</em></td>
        <td><em>[Email]</em></td>
    </tr>
</table>

<h2>8. Communication Protocol</h2>
<p>All communications regarding this engagement will be conducted through secure channels. Critical findings will be reported immediately via phone call, followed by encrypted email documentation.</p>

<h2>9. Confidentiality</h2>
<p>All findings, data, and information obtained during this engagement will be treated as strictly confidential and handled in accordance with the executed Non-Disclosure Agreement.</p>

<h2>10. Acknowledgment</h2>
<p>By signing below, both parties acknowledge that they have read, understood, and agree to the terms outlined in this Rules of Engagement document.</p>"#
}

/// Get the default Authorization to Test (ATO) template HTML
pub fn get_ato_template() -> &'static str {
    r#"<h1>Authorization to Test</h1>
<p style="text-align: center;"><em>"Get Out of Jail Free" Letter</em></p>

<p><strong>Document Date:</strong> {{CURRENT_DATE}}</p>

<h2>Authorization Statement</h2>

<p>I, {{CLIENT_CONTACT_NAME}}, in my capacity as {{CLIENT_CONTACT_TITLE}} of {{CLIENT_NAME}}, hereby authorize {{COMPANY_NAME}} to conduct authorized security testing against the systems and networks owned or operated by {{CLIENT_NAME}} as detailed in the associated Rules of Engagement document.</p>

<h2>Engagement Details</h2>
<table>
    <tr><td><strong>Engagement Name:</strong></td><td>{{ENGAGEMENT_NAME}}</td></tr>
    <tr><td><strong>Engagement Type:</strong></td><td>{{ENGAGEMENT_TYPE}}</td></tr>
    <tr><td><strong>Testing Period:</strong></td><td>{{START_DATE}} through {{END_DATE}}</td></tr>
    <tr><td><strong>Scope:</strong></td><td>{{ENGAGEMENT_SCOPE}}</td></tr>
</table>

<h2>Authorized Testing Activities</h2>
<p>This authorization permits {{COMPANY_NAME}} to perform the following activities during the specified testing period:</p>
<ul>
    <li>Attempt to identify security vulnerabilities in authorized systems</li>
    <li>Perform network scanning and enumeration</li>
    <li>Conduct vulnerability assessments</li>
    <li>Attempt controlled exploitation of discovered vulnerabilities</li>
    <li>Test web applications and APIs within scope</li>
    <li>Perform password security testing on captured hashes</li>
    <li>Document and report all findings</li>
</ul>

<h2>Legal Protection</h2>
<p>This letter serves as written authorization for {{COMPANY_NAME}} and its designated security professionals to perform the security testing activities described herein. This authorization is provided in accordance with applicable computer fraud and abuse laws, and the testing team shall not be held liable for any unintentional service disruptions that may occur during normal security testing activities, provided they act within the defined scope and rules of engagement.</p>

<h2>Indemnification</h2>
<p>{{CLIENT_NAME}} agrees to indemnify and hold harmless {{COMPANY_NAME}}, its employees, contractors, and agents from any claims, damages, or liabilities arising from the authorized security testing activities, provided such activities are conducted within the agreed-upon scope and rules of engagement.</p>

<h2>Conditions</h2>
<p>This authorization is subject to the following conditions:</p>
<ul>
    <li>Testing must remain within the defined scope</li>
    <li>Testing must occur during the specified time period</li>
    <li>All Rules of Engagement must be followed</li>
    <li>Critical findings must be reported immediately</li>
    <li>All data collected must be handled confidentially</li>
</ul>

<h2>Revocation</h2>
<p>{{CLIENT_NAME}} reserves the right to revoke this authorization at any time by providing written notice to {{COMPANY_NAME}}. Upon revocation, all testing activities must cease immediately.</p>

<h2>Authorization</h2>
<p>By signing below, I confirm that I have the authority to grant this authorization on behalf of {{CLIENT_NAME}} and that all information provided is accurate.</p>"#
}

/// Get the default Non-Disclosure Agreement (NDA) template HTML
pub fn get_nda_template() -> &'static str {
    r#"<h1>Non-Disclosure Agreement</h1>

<p><strong>Effective Date:</strong> {{CURRENT_DATE}}</p>

<h2>Parties</h2>
<p>This Non-Disclosure Agreement ("Agreement") is entered into by and between:</p>

<p><strong>Disclosing Party:</strong> {{CLIENT_NAME}} ("Client")<br>
Address: {{CLIENT_ADDRESS}}</p>

<p><strong>Receiving Party:</strong> {{COMPANY_NAME}} ("Provider")<br>
Address: {{COMPANY_ADDRESS}}</p>

<p>Each a "Party" and collectively the "Parties."</p>

<h2>1. Purpose</h2>
<p>The Parties wish to explore a potential business relationship relating to security assessment services ("{{ENGAGEMENT_NAME}}"). In connection with this relationship, each Party may disclose certain confidential information to the other Party.</p>

<h2>2. Definition of Confidential Information</h2>
<p>"Confidential Information" means any and all non-public information, in any form, disclosed by either Party to the other, including but not limited to:</p>
<ul>
    <li>Technical data, trade secrets, and know-how</li>
    <li>Security vulnerabilities, assessment results, and remediation plans</li>
    <li>Network diagrams, system configurations, and architecture documents</li>
    <li>Business plans, customer lists, and financial information</li>
    <li>Source code, algorithms, and proprietary methodologies</li>
    <li>Employee information and credentials</li>
    <li>Any information marked as "Confidential" or "Proprietary"</li>
</ul>

<h2>3. Obligations of Receiving Party</h2>
<p>The Receiving Party agrees to:</p>
<ul>
    <li>Hold Confidential Information in strict confidence</li>
    <li>Not disclose Confidential Information to any third parties without prior written consent</li>
    <li>Use Confidential Information solely for the Purpose described herein</li>
    <li>Protect Confidential Information using at least the same degree of care used to protect its own confidential information, but no less than reasonable care</li>
    <li>Limit access to Confidential Information to those employees and contractors who have a need to know</li>
    <li>Ensure that all persons with access are bound by confidentiality obligations at least as protective as this Agreement</li>
</ul>

<h2>4. Exclusions</h2>
<p>Confidential Information does not include information that:</p>
<ul>
    <li>Is or becomes publicly available through no fault of the Receiving Party</li>
    <li>Was rightfully in the Receiving Party's possession prior to disclosure</li>
    <li>Is rightfully obtained by the Receiving Party from a third party without restriction</li>
    <li>Is independently developed by the Receiving Party without use of Confidential Information</li>
    <li>Is required to be disclosed by law, provided the Disclosing Party is given reasonable notice</li>
</ul>

<h2>5. Return of Information</h2>
<p>Upon request or termination of this Agreement, the Receiving Party shall promptly return or destroy all Confidential Information and any copies thereof, and certify such destruction in writing upon request.</p>

<h2>6. Term</h2>
<p>This Agreement shall remain in effect for a period of three (3) years from the Effective Date, unless terminated earlier by either Party with thirty (30) days written notice. The confidentiality obligations shall survive termination for a period of five (5) years.</p>

<h2>7. Remedies</h2>
<p>The Parties acknowledge that breach of this Agreement may cause irreparable harm for which monetary damages may be inadequate. Therefore, the Disclosing Party shall be entitled to seek equitable relief, including injunction and specific performance, in addition to any other remedies available at law.</p>

<h2>8. No License</h2>
<p>Nothing in this Agreement grants any license or rights to any intellectual property, except the limited right to use Confidential Information for the Purpose described herein.</p>

<h2>9. General Provisions</h2>
<p><strong>Governing Law:</strong> This Agreement shall be governed by the laws of the State of [State], without regard to conflicts of law principles.</p>
<p><strong>Entire Agreement:</strong> This Agreement constitutes the entire agreement between the Parties regarding the subject matter hereof.</p>
<p><strong>Amendment:</strong> This Agreement may only be modified by written agreement signed by both Parties.</p>
<p><strong>Severability:</strong> If any provision is found unenforceable, the remaining provisions shall continue in effect.</p>

<h2>10. Signatures</h2>
<p>The Parties have executed this Agreement as of the Effective Date.</p>"#
}

/// Get the default Statement of Work (SOW) template HTML
pub fn get_sow_template() -> &'static str {
    r#"<h1>Statement of Work</h1>

<p><strong>Document Date:</strong> {{CURRENT_DATE}}</p>
<p><strong>SOW Reference:</strong> SOW-{{CURRENT_YEAR}}-[NUMBER]</p>

<h2>1. Parties</h2>
<p><strong>Client:</strong> {{CLIENT_NAME}}<br>
Address: {{CLIENT_ADDRESS}}<br>
Contact: {{CLIENT_CONTACT_NAME}}, {{CLIENT_CONTACT_TITLE}}<br>
Email: {{CLIENT_CONTACT_EMAIL}}</p>

<p><strong>Provider:</strong> {{COMPANY_NAME}}<br>
Address: {{COMPANY_ADDRESS}}</p>

<h2>2. Engagement Overview</h2>
<table>
    <tr><td><strong>Engagement Name:</strong></td><td>{{ENGAGEMENT_NAME}}</td></tr>
    <tr><td><strong>Engagement Type:</strong></td><td>{{ENGAGEMENT_TYPE}}</td></tr>
    <tr><td><strong>Start Date:</strong></td><td>{{START_DATE}}</td></tr>
    <tr><td><strong>End Date:</strong></td><td>{{END_DATE}}</td></tr>
    <tr><td><strong>Total Value:</strong></td><td>{{ENGAGEMENT_BUDGET}}</td></tr>
</table>

<h2>3. Scope of Work</h2>
<p>{{ENGAGEMENT_SCOPE}}</p>

<h3>3.1 Included Services</h3>
<ul>
    <li>Pre-engagement planning and scoping calls</li>
    <li>Security assessment execution per Rules of Engagement</li>
    <li>Vulnerability identification and validation</li>
    <li>Risk rating and prioritization of findings</li>
    <li>Detailed technical report with remediation guidance</li>
    <li>Executive summary presentation</li>
    <li>Remediation consultation and verification testing</li>
</ul>

<h3>3.2 Excluded Services</h3>
<ul>
    <li>Remediation of identified vulnerabilities (consulting available separately)</li>
    <li>Physical security testing (unless specifically included)</li>
    <li>Social engineering (unless specifically included)</li>
    <li>24/7 monitoring or managed security services</li>
</ul>

<h2>4. Deliverables</h2>
<table>
    <tr>
        <th>Deliverable</th>
        <th>Description</th>
        <th>Due Date</th>
    </tr>
    <tr>
        <td>Kickoff Meeting</td>
        <td>Project initiation and scope confirmation</td>
        <td>Within 3 business days of start date</td>
    </tr>
    <tr>
        <td>Status Updates</td>
        <td>Weekly progress reports during testing</td>
        <td>Every Friday during engagement</td>
    </tr>
    <tr>
        <td>Draft Report</td>
        <td>Preliminary findings for review</td>
        <td>Within 5 business days of testing completion</td>
    </tr>
    <tr>
        <td>Final Report</td>
        <td>Complete technical report and executive summary</td>
        <td>Within 3 business days of draft approval</td>
    </tr>
    <tr>
        <td>Presentation</td>
        <td>Executive briefing on findings</td>
        <td>Within 5 business days of final report</td>
    </tr>
</table>

<h2>5. Pricing and Payment</h2>
<table>
    <tr>
        <th>Description</th>
        <th>Amount</th>
    </tr>
    <tr>
        <td>Security Assessment Services</td>
        <td>{{ENGAGEMENT_BUDGET}}</td>
    </tr>
    <tr>
        <td><strong>Total</strong></td>
        <td><strong>{{ENGAGEMENT_BUDGET}}</strong></td>
    </tr>
</table>

<h3>5.1 Payment Terms</h3>
<ul>
    <li>50% due upon SOW execution</li>
    <li>50% due upon delivery of final report</li>
    <li>Payment due within Net 30 days of invoice</li>
</ul>

<h2>6. Client Responsibilities</h2>
<p>Client agrees to provide:</p>
<ul>
    <li>Timely access to systems and personnel as needed</li>
    <li>Required credentials and documentation</li>
    <li>Designated point of contact for the duration of the engagement</li>
    <li>Prompt review and feedback on deliverables</li>
    <li>Emergency contact availability during testing windows</li>
</ul>

<h2>7. Assumptions</h2>
<ul>
    <li>Testing will be conducted during normal business hours unless otherwise agreed</li>
    <li>Client systems will be available for testing during the engagement period</li>
    <li>Any scope changes will be documented and may affect timeline and pricing</li>
    <li>Provider will not be responsible for system outages beyond reasonable testing activities</li>
</ul>

<h2>8. Change Control</h2>
<p>Any changes to the scope, timeline, or deliverables must be documented in a written change order signed by both parties. Change orders may impact pricing and schedule.</p>

<h2>9. Acceptance</h2>
<p>By signing below, both parties agree to the terms and conditions outlined in this Statement of Work.</p>"#
}

/// Get the default Master Service Agreement (MSA) template HTML
pub fn get_msa_template() -> &'static str {
    r#"<h1>Master Service Agreement</h1>

<p><strong>Effective Date:</strong> {{CURRENT_DATE}}</p>

<h2>Parties</h2>
<p>This Master Service Agreement ("Agreement") is entered into by and between:</p>

<p><strong>Client:</strong> {{CLIENT_NAME}} ("Client")<br>
Address: {{CLIENT_ADDRESS}}</p>

<p><strong>Provider:</strong> {{COMPANY_NAME}} ("Provider")<br>
Address: {{COMPANY_ADDRESS}}</p>

<h2>1. Services</h2>
<p>Provider agrees to provide information security assessment and consulting services ("Services") to Client as described in individual Statements of Work ("SOW") executed under this Agreement. Each SOW shall be governed by the terms of this Agreement.</p>

<h2>2. Term</h2>
<p>This Agreement shall commence on the Effective Date and continue for an initial term of one (1) year. Thereafter, it shall automatically renew for successive one-year terms unless either Party provides written notice of non-renewal at least thirty (30) days prior to the end of the then-current term.</p>

<h2>3. Fees and Payment</h2>
<h3>3.1 Fees</h3>
<p>Client shall pay Provider the fees specified in each SOW. Unless otherwise specified, fees are quoted in US Dollars.</p>

<h3>3.2 Invoicing</h3>
<p>Provider shall invoice Client according to the payment schedule specified in each SOW. Payment is due within thirty (30) days of invoice date.</p>

<h3>3.3 Late Payments</h3>
<p>Past due amounts shall accrue interest at the rate of 1.5% per month or the maximum rate permitted by law, whichever is less.</p>

<h2>4. Confidentiality</h2>
<p>Each Party agrees to maintain the confidentiality of the other Party's Confidential Information in accordance with the Non-Disclosure Agreement executed between the Parties, which is incorporated herein by reference.</p>

<h2>5. Intellectual Property</h2>
<h3>5.1 Client Materials</h3>
<p>Client retains all rights in its pre-existing materials and any materials created specifically for Client under this Agreement.</p>

<h3>5.2 Provider Materials</h3>
<p>Provider retains all rights in its pre-existing methodologies, tools, templates, and general know-how. Provider grants Client a non-exclusive license to use deliverables for Client's internal business purposes.</p>

<h2>6. Representations and Warranties</h2>
<h3>6.1 Provider Warranties</h3>
<p>Provider represents and warrants that:</p>
<ul>
    <li>Services will be performed in a professional and workmanlike manner</li>
    <li>Provider personnel have the requisite skills and experience</li>
    <li>Services will comply with applicable laws and industry standards</li>
</ul>

<h3>6.2 Warranty Disclaimer</h3>
<p>EXCEPT AS EXPRESSLY SET FORTH HEREIN, PROVIDER MAKES NO WARRANTIES, EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION ANY IMPLIED WARRANTIES OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.</p>

<h2>7. Limitation of Liability</h2>
<p>EXCEPT FOR BREACHES OF CONFIDENTIALITY OR INDEMNIFICATION OBLIGATIONS, NEITHER PARTY SHALL BE LIABLE FOR ANY INDIRECT, INCIDENTAL, SPECIAL, CONSEQUENTIAL, OR PUNITIVE DAMAGES. PROVIDER'S TOTAL LIABILITY UNDER THIS AGREEMENT SHALL NOT EXCEED THE FEES PAID BY CLIENT DURING THE TWELVE (12) MONTHS PRECEDING THE CLAIM.</p>

<h2>8. Indemnification</h2>
<h3>8.1 By Provider</h3>
<p>Provider shall indemnify and hold harmless Client from any third-party claims arising from Provider's gross negligence or willful misconduct in performing Services.</p>

<h3>8.2 By Client</h3>
<p>Client shall indemnify and hold harmless Provider from any third-party claims arising from Client's use of deliverables in violation of this Agreement or applicable law.</p>

<h2>9. Insurance</h2>
<p>Provider shall maintain the following insurance coverage:</p>
<ul>
    <li>Professional Liability (E&O): $1,000,000 per occurrence</li>
    <li>Cyber Liability: $1,000,000 per occurrence</li>
    <li>General Commercial Liability: $1,000,000 per occurrence</li>
</ul>

<h2>10. Termination</h2>
<h3>10.1 For Convenience</h3>
<p>Either Party may terminate this Agreement with thirty (30) days written notice.</p>

<h3>10.2 For Cause</h3>
<p>Either Party may terminate immediately upon material breach that remains uncured for fifteen (15) days after written notice.</p>

<h3>10.3 Effect of Termination</h3>
<p>Upon termination, Client shall pay for all Services rendered through the termination date. Sections 4, 5, 6, 7, 8, and 11 shall survive termination.</p>

<h2>11. General Provisions</h2>
<p><strong>Governing Law:</strong> This Agreement shall be governed by the laws of the State of [State], without regard to conflicts of law principles.</p>

<p><strong>Dispute Resolution:</strong> Any disputes shall be resolved through binding arbitration in accordance with the rules of the American Arbitration Association.</p>

<p><strong>Entire Agreement:</strong> This Agreement, together with all SOWs and the NDA, constitutes the entire agreement between the Parties.</p>

<p><strong>Amendment:</strong> This Agreement may only be modified by written agreement signed by both Parties.</p>

<p><strong>Assignment:</strong> Neither Party may assign this Agreement without the other Party's prior written consent.</p>

<p><strong>Notices:</strong> All notices shall be in writing and delivered to the addresses set forth above.</p>

<p><strong>Severability:</strong> If any provision is found unenforceable, the remaining provisions shall continue in effect.</p>

<p><strong>Waiver:</strong> Failure to enforce any provision shall not constitute a waiver of that provision.</p>

<h2>12. Signatures</h2>
<p>The Parties have executed this Agreement as of the Effective Date.</p>"#
}

/// Get all default templates as (type, name, description, content)
pub fn get_all_default_templates() -> Vec<(&'static str, &'static str, &'static str, &'static str)> {
    vec![
        (
            "roe",
            "Rules of Engagement (Standard)",
            "Standard ROE template for penetration testing engagements defining scope, authorized activities, and restrictions.",
            get_roe_template(),
        ),
        (
            "ato",
            "Authorization to Test (Standard)",
            "Get Out of Jail Free letter authorizing security testing and providing legal protection for testers.",
            get_ato_template(),
        ),
        (
            "nda",
            "Non-Disclosure Agreement (Mutual)",
            "Mutual NDA protecting confidential information shared during security engagements.",
            get_nda_template(),
        ),
        (
            "sow",
            "Statement of Work (Standard)",
            "Standard SOW defining scope, deliverables, timeline, and pricing for security engagements.",
            get_sow_template(),
        ),
        (
            "msa",
            "Master Service Agreement (Standard)",
            "General terms and conditions governing the business relationship between provider and client.",
            get_msa_template(),
        ),
    ]
}
