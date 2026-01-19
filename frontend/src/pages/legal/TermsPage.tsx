import React from 'react';
import LegalLayout from './LegalLayout';

const TermsPage: React.FC = () => {
  return (
    <LegalLayout title="Terms of Service" lastUpdated="January 15, 2026">
      <section id="introduction">
        <p>
          Welcome to HeroForge. These Terms of Service ("Terms") govern your access to and use of the HeroForge
          security assessment platform, including our website, APIs, and related services (collectively, the "Service").
        </p>
        <p>
          By accessing or using the Service, you agree to be bound by these Terms. If you do not agree to these Terms,
          you may not access or use the Service.
        </p>
        <p><strong>IMPORTANT:</strong> HeroForge is a security assessment tool designed for authorized penetration
          testing only. Unauthorized use of this tool to scan, test, or attack systems you do not own or have
          explicit permission to test is illegal and strictly prohibited.</p>
      </section>

      <section id="definitions">
        <h2>1. Definitions</h2>
        <ul>
          <li><strong>"Account"</strong> means a user account registered to access the Service.</li>
          <li><strong>"Authorized Testing"</strong> means security testing performed with explicit written permission from the system owner.</li>
          <li><strong>"Content"</strong> means any data, text, files, or other materials uploaded, submitted, or created using the Service.</li>
          <li><strong>"Scan"</strong> means a security assessment operation performed using the Service.</li>
          <li><strong>"Target"</strong> means any system, network, or application subject to a Scan.</li>
          <li><strong>"User"</strong> means any individual or entity that accesses or uses the Service.</li>
        </ul>
      </section>

      <section id="authorization">
        <h2>2. Authorization Requirements</h2>
        <h3>2.1 Mandatory Authorization</h3>
        <p>
          You MUST have explicit, written authorization before scanning any Target. This authorization must come from
          an individual or entity with legal authority to grant such permission. HeroForge is designed exclusively for
          Authorized Testing.
        </p>
        <h3>2.2 Your Responsibility</h3>
        <p>You are solely responsible for:</p>
        <ul>
          <li>Obtaining proper authorization before any Scan</li>
          <li>Maintaining documentation of all authorizations</li>
          <li>Ensuring all Targets are within the scope of your authorization</li>
          <li>Complying with all applicable laws and regulations</li>
        </ul>
        <h3>2.3 Prohibited Targets</h3>
        <p>Without proper authorization, you may NOT scan:</p>
        <ul>
          <li>Any system you do not own</li>
          <li>Any third-party infrastructure</li>
          <li>Critical infrastructure systems</li>
          <li>Government systems</li>
          <li>Healthcare systems</li>
          <li>Financial institutions</li>
        </ul>
      </section>

      <section id="accounts">
        <h2>3. Account Registration and Security</h2>
        <h3>3.1 Account Requirements</h3>
        <p>To use the Service, you must:</p>
        <ul>
          <li>Be at least 18 years of age</li>
          <li>Provide accurate and complete registration information</li>
          <li>Maintain the security of your account credentials</li>
          <li>Notify us immediately of any unauthorized access</li>
        </ul>
        <h3>3.2 Account Security</h3>
        <p>
          You are responsible for all activities that occur under your account. You must use a strong, unique password
          and enable multi-factor authentication when available.
        </p>
      </section>

      <section id="acceptable-use">
        <h2>4. Acceptable Use</h2>
        <h3>4.1 Permitted Uses</h3>
        <ul>
          <li>Authorized penetration testing</li>
          <li>Vulnerability assessments with permission</li>
          <li>Security compliance auditing</li>
          <li>Testing your own systems</li>
          <li>Educational purposes in controlled environments</li>
        </ul>
        <h3>4.2 Prohibited Uses</h3>
        <p>You may NOT use the Service to:</p>
        <ul>
          <li>Scan systems without authorization</li>
          <li>Conduct denial-of-service attacks</li>
          <li>Distribute malware or malicious code</li>
          <li>Steal, modify, or destroy data</li>
          <li>Violate any applicable laws</li>
          <li>Harass or harm individuals</li>
          <li>Attempt to circumvent security controls</li>
        </ul>
      </section>

      <section id="intellectual-property">
        <h2>5. Intellectual Property</h2>
        <h3>5.1 Our Ownership</h3>
        <p>
          HeroForge and all associated intellectual property rights are owned by us. These Terms do not grant you any
          rights to our trademarks, logos, or other brand features.
        </p>
        <h3>5.2 Your Content</h3>
        <p>
          You retain ownership of Content you create using the Service. By using the Service, you grant us a limited
          license to store and process your Content as necessary to provide the Service.
        </p>
      </section>

      <section id="disclaimers">
        <h2>6. Disclaimers</h2>
        <h3>6.1 Service Provided "As Is"</h3>
        <p>
          THE SERVICE IS PROVIDED "AS IS" AND "AS AVAILABLE" WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR IMPLIED,
          INCLUDING BUT NOT LIMITED TO IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND
          NON-INFRINGEMENT.
        </p>
        <h3>6.2 No Guarantee</h3>
        <p>We do not guarantee that:</p>
        <ul>
          <li>The Service will be uninterrupted or error-free</li>
          <li>All vulnerabilities will be detected</li>
          <li>Scan results will be complete or accurate</li>
          <li>The Service will meet your specific requirements</li>
        </ul>
      </section>

      <section id="liability">
        <h2>7. Limitation of Liability</h2>
        <h3>7.1 Exclusion of Damages</h3>
        <p>
          TO THE MAXIMUM EXTENT PERMITTED BY LAW, IN NO EVENT SHALL HEROFORGE BE LIABLE FOR ANY INDIRECT, INCIDENTAL,
          SPECIAL, CONSEQUENTIAL, OR PUNITIVE DAMAGES, OR ANY LOSS OF PROFITS OR REVENUES, WHETHER INCURRED DIRECTLY
          OR INDIRECTLY, OR ANY LOSS OF DATA, USE, GOODWILL, OR OTHER INTANGIBLE LOSSES.
        </p>
        <h3>7.2 Cap on Liability</h3>
        <p>
          OUR TOTAL LIABILITY FOR ANY CLAIMS UNDER THESE TERMS SHALL NOT EXCEED THE AMOUNT YOU PAID US FOR THE SERVICE
          IN THE TWELVE (12) MONTHS PRIOR TO THE CLAIM.
        </p>
        <h3>7.3 Your Liability</h3>
        <p>
          You are solely liable for any damages resulting from your use of the Service, including but not limited to
          damages arising from unauthorized scanning.
        </p>
      </section>

      <section id="indemnification">
        <h2>8. Indemnification</h2>
        <p>You agree to indemnify, defend, and hold harmless HeroForge from and against any claims, liabilities,
          damages, losses, and expenses, including reasonable attorneys' fees, arising out of or in any way connected with:</p>
        <ul>
          <li>Your access to or use of the Service</li>
          <li>Your violation of these Terms</li>
          <li>Your violation of any applicable laws</li>
          <li>Your scanning of any unauthorized Targets</li>
          <li>Any claim that your use of the Service caused damage to a third party</li>
        </ul>
      </section>

      <section id="termination">
        <h2>9. Termination</h2>
        <h3>9.1 By You</h3>
        <p>You may terminate your account at any time through your account settings.</p>
        <h3>9.2 By Us</h3>
        <p>We may suspend or terminate your access to the Service immediately, without prior notice, if:</p>
        <ul>
          <li>You violate these Terms</li>
          <li>You engage in unauthorized scanning</li>
          <li>We receive a valid legal request</li>
          <li>We believe your actions may harm us or others</li>
        </ul>
        <h3>9.3 Effect of Termination</h3>
        <p>Upon termination, your right to use the Service will immediately cease. Provisions that by their nature
          should survive termination shall survive.</p>
      </section>

      <section id="governing-law">
        <h2>10. Governing Law and Disputes</h2>
        <h3>10.1 Governing Law</h3>
        <p>These Terms shall be governed by the laws of the jurisdiction in which HeroForge is incorporated.</p>
        <h3>10.2 Dispute Resolution</h3>
        <p>Any disputes arising under these Terms shall be resolved through binding arbitration, except where
          prohibited by law.</p>
      </section>

      <section id="changes">
        <h2>11. Changes to Terms</h2>
        <p>
          We may modify these Terms at any time. We will notify you of material changes via email or through the
          Service. Your continued use of the Service after such changes constitutes acceptance of the modified Terms.
        </p>
      </section>

      <section id="contact">
        <h2>12. Contact Information</h2>
        <p>For questions about these Terms, contact us at:</p>
        <ul>
          <li><strong>Email:</strong> legal@heroforge.security</li>
          <li><strong>Support:</strong> support@heroforge.security</li>
        </ul>
      </section>

      <div className="mt-8 p-4 bg-gray-100 dark:bg-gray-700 rounded-lg">
        <p className="text-sm font-semibold">
          BY USING HEROFORGE, YOU ACKNOWLEDGE THAT YOU HAVE READ THESE TERMS OF SERVICE, UNDERSTAND THEM, AND AGREE
          TO BE BOUND BY THEM.
        </p>
      </div>
    </LegalLayout>
  );
};

export default TermsPage;
