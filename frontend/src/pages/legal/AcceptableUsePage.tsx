import React from 'react';
import LegalLayout from './LegalLayout';
import { AlertTriangle } from 'lucide-react';

const AcceptableUsePage: React.FC = () => {
  return (
    <LegalLayout title="Acceptable Use Policy" lastUpdated="December 24, 2024">
      <section id="purpose">
        <p>
          This Acceptable Use Policy ("AUP") defines the acceptable and prohibited uses of the HeroForge security
          assessment platform. This policy is designed to protect HeroForge, our users, and the broader internet
          community from irresponsible or illegal use of security testing tools.
        </p>
        <div className="my-6 p-4 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg">
          <div className="flex items-start gap-3">
            <AlertTriangle className="w-6 h-6 text-red-600 dark:text-red-400 flex-shrink-0 mt-0.5" />
            <p className="text-red-800 dark:text-red-200 font-semibold">
              Violation of this policy may result in immediate account termination and potential legal action.
            </p>
          </div>
        </div>
      </section>

      <section id="authorization">
        <h2>1. Fundamental Requirement: AUTHORIZATION</h2>

        <h3>1.1 The Golden Rule</h3>
        <div className="my-4 p-4 bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800 rounded-lg">
          <p className="font-bold text-amber-800 dark:text-amber-200">
            YOU MUST HAVE EXPLICIT, WRITTEN AUTHORIZATION BEFORE SCANNING ANY SYSTEM.
          </p>
        </div>
        <p>
          This is not optional. This is not negotiable. Unauthorized scanning is illegal in most jurisdictions and
          violates our Terms of Service.
        </p>

        <h3>1.2 What Constitutes Valid Authorization</h3>
        <p>Valid authorization must be:</p>
        <ul>
          <li><strong>Written:</strong> Documented in writing (email, contract, or formal letter)</li>
          <li><strong>Explicit:</strong> Clearly states permission to perform security testing</li>
          <li><strong>Specific:</strong> Identifies the systems, networks, or applications covered</li>
          <li><strong>Current:</strong> Valid for the time period of testing</li>
          <li><strong>From an authorized person:</strong> Someone with authority to grant permission</li>
        </ul>

        <h3>1.3 Examples of Valid Authorization</h3>
        <ul>
          <li>Signed penetration testing agreement with client</li>
          <li>Written authorization from system owner/administrator</li>
          <li>Bug bounty program terms that explicitly permit your testing</li>
          <li>Your own systems that you own and control</li>
          <li>Lab/test environments specifically designated for security testing</li>
        </ul>

        <h3>1.4 Authorization Documentation</h3>
        <p>You must maintain records of authorization for:</p>
        <ul>
          <li>Minimum of 3 years after testing</li>
          <li>All systems scanned using HeroForge</li>
          <li>Available upon request for audit purposes</li>
        </ul>
      </section>

      <section id="prohibited">
        <h2>2. Prohibited Activities</h2>

        <h3>2.1 Absolutely Prohibited</h3>
        <p>The following activities are <strong>strictly prohibited</strong> and will result in immediate termination:</p>

        <h4>Unauthorized Access</h4>
        <ul>
          <li>Scanning systems without written authorization</li>
          <li>Accessing data you are not authorized to access</li>
          <li>Bypassing authentication or access controls on unauthorized systems</li>
          <li>Exploiting vulnerabilities on systems you don't have permission to test</li>
        </ul>

        <h4>Malicious Activities</h4>
        <ul>
          <li>Denial-of-service (DoS) or distributed denial-of-service (DDoS) attacks</li>
          <li>Deploying malware, ransomware, or destructive code</li>
          <li>Data theft, exfiltration, or destruction</li>
          <li>Cryptocurrency mining on third-party systems</li>
          <li>Spamming or phishing</li>
        </ul>

        <h4>Illegal Activities</h4>
        <ul>
          <li>Any activity that violates local, state, national, or international laws</li>
          <li>Activities that violate the Computer Fraud and Abuse Act (CFAA) or equivalent laws</li>
          <li>Violation of privacy laws (GDPR, CCPA, etc.)</li>
          <li>Activities that could harm critical infrastructure</li>
        </ul>

        <h3>2.2 Restricted Activities</h3>
        <p>The following require explicit additional authorization:</p>
        <ul>
          <li><strong>Production Systems:</strong> Testing on live production environments</li>
          <li><strong>Critical Infrastructure:</strong> Healthcare, financial, utility systems</li>
          <li><strong>Government Systems:</strong> Any government-owned systems</li>
          <li><strong>Third-Party Data:</strong> Systems containing others' personal data</li>
          <li><strong>Aggressive Testing:</strong> Load testing, stress testing, fuzzing that may cause disruption</li>
        </ul>
      </section>

      <section id="responsible-use">
        <h2>3. Responsible Use Guidelines</h2>

        <h3>3.1 Before Scanning</h3>
        <ol>
          <li><strong>Verify Authorization:</strong> Confirm you have valid, current authorization</li>
          <li><strong>Define Scope:</strong> Clearly understand what systems are in scope</li>
          <li><strong>Review Rules of Engagement:</strong> Understand any limitations or restrictions</li>
          <li><strong>Notify Stakeholders:</strong> Ensure relevant parties are aware of testing</li>
          <li><strong>Document Everything:</strong> Record authorization and scope</li>
        </ol>

        <h3>3.2 During Scanning</h3>
        <ol>
          <li><strong>Stay in Scope:</strong> Only scan authorized systems</li>
          <li><strong>Use Appropriate Techniques:</strong> Match testing intensity to authorization level</li>
          <li><strong>Monitor Impact:</strong> Stop if you observe unintended effects</li>
          <li><strong>Handle Data Responsibly:</strong> Protect any sensitive data discovered</li>
          <li><strong>Report Critical Findings:</strong> Immediately report severe vulnerabilities</li>
        </ol>

        <h3>3.3 After Scanning</h3>
        <ol>
          <li><strong>Secure Results:</strong> Protect scan results and reports</li>
          <li><strong>Report Findings:</strong> Provide reports to authorized parties only</li>
          <li><strong>Dispose of Data:</strong> Delete data according to retention policies</li>
          <li><strong>Maintain Records:</strong> Keep authorization documentation</li>
        </ol>
      </section>

      <section id="bug-bounty">
        <h2>4. Bug Bounty and Responsible Disclosure</h2>

        <h3>4.1 Bug Bounty Programs</h3>
        <p>When testing under bug bounty programs:</p>
        <ul>
          <li>Follow the program's specific rules and scope</li>
          <li>Respect rate limits and testing restrictions</li>
          <li>Report findings through official channels</li>
          <li>Do not publicly disclose without permission</li>
        </ul>

        <h3>4.2 Responsible Disclosure</h3>
        <p>If you discover vulnerabilities during authorized testing:</p>
        <ul>
          <li>Report to the system owner promptly</li>
          <li>Provide sufficient detail for remediation</li>
          <li>Allow reasonable time for patching before disclosure</li>
          <li>Follow coordinated disclosure best practices</li>
        </ul>
      </section>

      <section id="resource-usage">
        <h2>5. Resource Usage Limits</h2>

        <h3>5.1 Fair Use</h3>
        <p>To ensure service availability for all users:</p>
        <ul>
          <li>Do not exceed scan rate limits</li>
          <li>Do not attempt to circumvent usage quotas</li>
          <li>Do not consume excessive resources</li>
          <li>Do not interfere with other users' access</li>
        </ul>

        <h3>5.2 System Impact</h3>
        <p>Your testing should not:</p>
        <ul>
          <li>Crash or degrade target systems (unless explicitly authorized)</li>
          <li>Consume excessive bandwidth</li>
          <li>Fill disk space or logs</li>
          <li>Create operational disruptions</li>
        </ul>
      </section>

      <section id="account-security">
        <h2>6. Account Security</h2>

        <h3>6.1 Your Responsibilities</h3>
        <ul>
          <li>Use strong, unique passwords</li>
          <li>Enable multi-factor authentication</li>
          <li>Do not share account credentials</li>
          <li>Report suspicious activity immediately</li>
          <li>Log out from shared devices</li>
        </ul>

        <h3>6.2 API Key Security</h3>
        <ul>
          <li>Protect API keys as sensitive credentials</li>
          <li>Rotate keys periodically</li>
          <li>Revoke compromised keys immediately</li>
          <li>Use minimal necessary permissions</li>
        </ul>
      </section>

      <section id="enforcement">
        <h2>7. Enforcement</h2>

        <h3>7.1 Violation Response</h3>
        <p>Depending on severity, we may:</p>
        <ol>
          <li><strong>Warning:</strong> First-time minor violations</li>
          <li><strong>Temporary Suspension:</strong> Pending investigation</li>
          <li><strong>Account Termination:</strong> Serious or repeated violations</li>
          <li><strong>Legal Action:</strong> Illegal activities</li>
          <li><strong>Law Enforcement Referral:</strong> Criminal activities</li>
        </ol>

        <h3>7.2 No Refunds</h3>
        <p>Accounts terminated for AUP violations are not eligible for refunds.</p>

        <h3>7.3 Appeals</h3>
        <p>
          You may appeal enforcement decisions by emailing legal@heroforge.security within 14 days. Include your
          justification and any relevant documentation.
        </p>
      </section>

      <section id="reporting">
        <h2>8. Reporting Violations</h2>
        <p>Report AUP violations to:</p>
        <ul>
          <li><strong>Email:</strong> abuse@heroforge.security</li>
          <li><strong>Include:</strong> Details of the violation, evidence, affected parties</li>
        </ul>
      </section>

      <section id="contact">
        <h2>9. Contact</h2>
        <ul>
          <li><strong>Abuse Reports:</strong> abuse@heroforge.security</li>
          <li><strong>Policy Questions:</strong> legal@heroforge.security</li>
          <li><strong>General Support:</strong> support@heroforge.security</li>
        </ul>
      </section>

      <div className="mt-8 p-4 bg-gray-100 dark:bg-gray-700 rounded-lg">
        <p className="text-sm font-semibold">
          By using HeroForge, you acknowledge that you have read, understood, and agree to comply with this Acceptable
          Use Policy. You understand that violation may result in account termination and potential legal consequences.
        </p>
        <p className="text-sm font-bold mt-2 text-red-600 dark:text-red-400">
          Remember: Authorization is not optional. When in doubt, don't scan.
        </p>
      </div>
    </LegalLayout>
  );
};

export default AcceptableUsePage;
