import React from 'react';
import LegalLayout from './LegalLayout';

const PrivacyPage: React.FC = () => {
  return (
    <LegalLayout title="Privacy Policy" lastUpdated="January 1, 2026">
      <section id="introduction">
        <p>
          This Privacy Policy ("Policy") describes how Genial Architect Cybersecurity Research Associates ("Company," "we,"
          "us," or "our") collects, uses, discloses, and protects personal information when you use the HeroForge
          cybersecurity platform and services (the "Service").
        </p>
        <p>
          We are committed to protecting your privacy and handling your personal information responsibly. This Policy
          explains your rights and choices regarding your personal information.
        </p>
        <p><strong>Data Controller:</strong><br />
          Genial Architect Cybersecurity Research Associates<br />
          550 Ernestine Falls<br />
          Grovetown, GA 30813<br />
          Email: privacy@genialarchitect.io
        </p>
      </section>

      <section id="information-collected">
        <h2>1. Information We Collect</h2>

        <h3>1.1 Account Information</h3>
        <p>When you register, we collect:</p>
        <ul>
          <li>Full name</li>
          <li>Email address</li>
          <li>Username</li>
          <li>Password (stored as bcrypt hash)</li>
          <li>Organization name (optional)</li>
          <li>Phone number (optional)</li>
        </ul>

        <h3>1.2 Scan Data</h3>
        <p>When you use our scanning features, we process:</p>
        <ul>
          <li>Target IP addresses and hostnames you specify</li>
          <li>Scan results and discovered vulnerabilities</li>
          <li>Generated reports</li>
          <li>Scan configurations and schedules</li>
        </ul>

        <h3>1.3 Usage Information</h3>
        <p>We automatically collect:</p>
        <ul>
          <li>Log data (IP address, browser type, pages visited)</li>
          <li>Device information (operating system, device type)</li>
          <li>Usage patterns and feature interactions</li>
          <li>Performance metrics</li>
        </ul>

        <h3>1.4 Payment Information</h3>
        <p>For paid subscriptions:</p>
        <ul>
          <li>Billing address</li>
          <li>Payment method details (processed by third-party payment processors)</li>
          <li>Transaction history</li>
        </ul>
      </section>

      <section id="how-we-use">
        <h2>2. How We Use Your Information</h2>

        <h3>2.1 Service Delivery</h3>
        <ul>
          <li>Provide and maintain the Service</li>
          <li>Process and store your scan results</li>
          <li>Generate reports and analytics</li>
          <li>Send service notifications</li>
        </ul>

        <h3>2.2 Service Improvement</h3>
        <ul>
          <li>Analyze usage patterns to improve features</li>
          <li>Debug and fix issues</li>
          <li>Develop new features</li>
          <li>Monitor service performance</li>
        </ul>

        <h3>2.3 Security and Compliance</h3>
        <ul>
          <li>Detect and prevent fraud</li>
          <li>Enforce our Terms of Service</li>
          <li>Comply with legal obligations</li>
          <li>Protect our rights and safety</li>
        </ul>
      </section>

      <section id="legal-basis">
        <h2>3. Legal Basis for Processing (GDPR)</h2>
        <p>For users in the European Economic Area (EEA), we process data based on:</p>
        <table>
          <thead>
            <tr>
              <th>Purpose</th>
              <th>Legal Basis</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>Account management</td>
              <td>Contractual necessity</td>
            </tr>
            <tr>
              <td>Scan processing</td>
              <td>Contractual necessity</td>
            </tr>
            <tr>
              <td>Service improvement</td>
              <td>Legitimate interest</td>
            </tr>
            <tr>
              <td>Security monitoring</td>
              <td>Legitimate interest</td>
            </tr>
            <tr>
              <td>Marketing</td>
              <td>Consent</td>
            </tr>
            <tr>
              <td>Legal compliance</td>
              <td>Legal obligation</td>
            </tr>
          </tbody>
        </table>
      </section>

      <section id="data-sharing">
        <h2>4. Data Sharing</h2>

        <h3>4.1 We Do NOT Sell Your Data</h3>
        <p>We do not sell, rent, or trade your personal information or scan data to third parties.</p>

        <h3>4.2 Service Providers</h3>
        <p>We may share data with trusted service providers who assist us:</p>
        <ul>
          <li>Cloud hosting providers</li>
          <li>Payment processors</li>
          <li>Email service providers</li>
          <li>Analytics services</li>
        </ul>
        <p>All service providers are bound by data protection agreements.</p>

        <h3>4.3 Legal Requirements</h3>
        <p>We may disclose information if required by:</p>
        <ul>
          <li>Court order or legal process</li>
          <li>Law enforcement request</li>
          <li>Protection of our rights or safety</li>
          <li>Prevention of fraud or illegal activity</li>
        </ul>
      </section>

      <section id="data-security">
        <h2>5. Data Security</h2>

        <h3>5.1 Technical Measures</h3>
        <p>We implement industry-standard security measures:</p>
        <ul>
          <li><strong>Encryption at Rest:</strong> AES-256 database encryption (SQLCipher)</li>
          <li><strong>Encryption in Transit:</strong> TLS 1.2+ for all connections</li>
          <li><strong>Access Controls:</strong> Role-based access, multi-factor authentication</li>
          <li><strong>Password Security:</strong> bcrypt hashing with configurable cost factor</li>
          <li><strong>Audit Logging:</strong> Comprehensive activity logging</li>
        </ul>

        <h3>5.2 Data Breach Notification</h3>
        <p>In the event of a data breach affecting your personal information, we will:</p>
        <ul>
          <li>Notify affected users within 72 hours</li>
          <li>Notify relevant supervisory authorities as required</li>
          <li>Provide information about the breach and remediation steps</li>
        </ul>
      </section>

      <section id="data-retention">
        <h2>6. Data Retention</h2>
        <table>
          <thead>
            <tr>
              <th>Data Type</th>
              <th>Retention Period</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>Account information</td>
              <td>Duration of account + 30 days</td>
            </tr>
            <tr>
              <td>Scan results</td>
              <td>Configurable (default: 90 days)</td>
            </tr>
            <tr>
              <td>Audit logs</td>
              <td>1 year</td>
            </tr>
            <tr>
              <td>Payment records</td>
              <td>7 years (legal requirement)</td>
            </tr>
            <tr>
              <td>Support tickets</td>
              <td>3 years</td>
            </tr>
          </tbody>
        </table>
        <p>You may request earlier deletion subject to legal retention requirements.</p>
      </section>

      <section id="your-rights">
        <h2>7. Your Rights</h2>

        <h3>7.1 All Users</h3>
        <p>You have the right to:</p>
        <ul>
          <li><strong>Access:</strong> Request a copy of your data</li>
          <li><strong>Correction:</strong> Update inaccurate information</li>
          <li><strong>Deletion:</strong> Request deletion of your account and data</li>
          <li><strong>Export:</strong> Download your data in machine-readable format</li>
          <li><strong>Opt-out:</strong> Unsubscribe from marketing communications</li>
        </ul>

        <h3>7.2 EEA/UK Users (GDPR)</h3>
        <p>Additional rights include:</p>
        <ul>
          <li><strong>Restriction:</strong> Limit processing of your data</li>
          <li><strong>Objection:</strong> Object to processing based on legitimate interest</li>
          <li><strong>Portability:</strong> Receive data in structured format</li>
          <li><strong>Withdraw Consent:</strong> Revoke consent at any time</li>
          <li><strong>Lodge Complaint:</strong> File complaint with supervisory authority</li>
        </ul>

        <h3>7.3 California Users (CCPA)</h3>
        <p>Additional rights include:</p>
        <ul>
          <li><strong>Know:</strong> What personal information is collected</li>
          <li><strong>Delete:</strong> Request deletion of personal information</li>
          <li><strong>Opt-out:</strong> Opt-out of sale (we do not sell data)</li>
          <li><strong>Non-discrimination:</strong> Equal service regardless of privacy choices</li>
        </ul>

        <h3>7.4 Exercising Your Rights</h3>
        <p>To exercise your rights:</p>
        <ul>
          <li>Use the Settings page in your account</li>
          <li>Use the API: <code>GET /api/auth/export</code> or <code>DELETE /api/auth/account</code></li>
          <li>Email: privacy@genialarchitect.io</li>
        </ul>
        <p>We will respond within 30 days (or sooner as required by law).</p>
      </section>

      <section id="cookies">
        <h2>8. Cookies and Tracking</h2>

        <h3>8.1 Essential Cookies</h3>
        <p>We use essential cookies for:</p>
        <ul>
          <li>Authentication (JWT session tokens)</li>
          <li>Security (CSRF protection)</li>
          <li>User preferences</li>
        </ul>

        <h3>8.2 Third-Party Cookies</h3>
        <p>We do not use:</p>
        <ul>
          <li>Advertising cookies</li>
          <li>Social media tracking pixels</li>
          <li>Cross-site tracking</li>
        </ul>
        <p>See our <a href="/legal/cookies">Cookie Policy</a> for more details.</p>
      </section>

      <section id="international-transfers">
        <h2>9. International Data Transfers</h2>
        <p>Data is stored and processed in the region where the service is deployed. For international transfers, we use:</p>
        <ul>
          <li>Standard Contractual Clauses (SCCs)</li>
          <li>Adequacy decisions where applicable</li>
          <li>Additional technical and organizational measures</li>
        </ul>
      </section>

      <section id="children">
        <h2>10. Children's Privacy</h2>
        <p>
          HeroForge is not intended for users under 18 years of age. We do not knowingly collect personal information
          from children. If we learn we have collected data from a child, we will delete it immediately.
        </p>
      </section>

      <section id="changes">
        <h2>11. Changes to This Policy</h2>
        <p>We may update this Privacy Policy periodically. We will notify you of material changes via:</p>
        <ul>
          <li>Email to your registered address</li>
          <li>Notice on the Service dashboard</li>
          <li>Updated "Last Updated" date</li>
        </ul>
        <p>Continued use after changes constitutes acceptance.</p>
      </section>

      <section id="contact">
        <h2>12. Contact Us</h2>
        <p><strong>Genial Architect Cybersecurity Research Associates</strong><br />
          550 Ernestine Falls<br />
          Grovetown, GA 30813</p>
        <ul>
          <li><strong>Privacy Inquiries:</strong> privacy@genialarchitect.io</li>
          <li><strong>Data Protection Officer:</strong> dpo@genialarchitect.io</li>
          <li><strong>General Support:</strong> support@genialarchitect.io</li>
        </ul>
      </section>

      <div className="mt-8 p-4 bg-gray-100 dark:bg-gray-700 rounded-lg">
        <p className="text-sm font-semibold">
          BY USING HEROFORGE, YOU ACKNOWLEDGE THAT YOU HAVE READ AND UNDERSTOOD THIS PRIVACY POLICY.
        </p>
      </div>
    </LegalLayout>
  );
};

export default PrivacyPage;
