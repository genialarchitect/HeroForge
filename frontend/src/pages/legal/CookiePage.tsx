import React from 'react';
import LegalLayout from './LegalLayout';

const CookiePage: React.FC = () => {
  return (
    <LegalLayout title="Cookie Policy" lastUpdated="December 24, 2024">
      <section id="what-are-cookies">
        <h2>What Are Cookies?</h2>
        <p>
          Cookies are small text files stored on your device when you visit websites. They help websites remember your
          preferences, keep you logged in, and understand how you use the site.
        </p>
      </section>

      <section id="how-we-use">
        <h2>How We Use Cookies</h2>
        <p>
          HeroForge uses minimal cookies focused on essential functionality. We prioritize your privacy and do not use
          cookies for advertising or cross-site tracking.
        </p>
      </section>

      <section id="types-of-cookies">
        <h2>Types of Cookies We Use</h2>

        <h3>1. Essential Cookies (Required)</h3>
        <p>These cookies are necessary for the Service to function. They cannot be disabled.</p>
        <table>
          <thead>
            <tr>
              <th>Cookie Name</th>
              <th>Purpose</th>
              <th>Duration</th>
              <th>Type</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td><code>hf_session</code></td>
              <td>Authentication token (JWT)</td>
              <td>Session / 7 days</td>
              <td>First-party</td>
            </tr>
            <tr>
              <td><code>hf_csrf</code></td>
              <td>CSRF protection</td>
              <td>Session</td>
              <td>First-party</td>
            </tr>
            <tr>
              <td><code>hf_preferences</code></td>
              <td>User preferences (theme, language)</td>
              <td>1 year</td>
              <td>First-party</td>
            </tr>
          </tbody>
        </table>

        <h3>2. Functional Cookies (Optional)</h3>
        <p>These cookies enhance your experience but are not required.</p>
        <table>
          <thead>
            <tr>
              <th>Cookie Name</th>
              <th>Purpose</th>
              <th>Duration</th>
              <th>Type</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td><code>hf_remember</code></td>
              <td>Remember login</td>
              <td>30 days</td>
              <td>First-party</td>
            </tr>
            <tr>
              <td><code>hf_tour</code></td>
              <td>Tutorial completion status</td>
              <td>1 year</td>
              <td>First-party</td>
            </tr>
            <tr>
              <td><code>hf_collapsed</code></td>
              <td>Sidebar state</td>
              <td>1 year</td>
              <td>First-party</td>
            </tr>
          </tbody>
        </table>

        <h3>3. Analytics Cookies (Optional)</h3>
        <p>If enabled, these help us understand how you use the Service.</p>
        <table>
          <thead>
            <tr>
              <th>Cookie Name</th>
              <th>Purpose</th>
              <th>Duration</th>
              <th>Type</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td colSpan={4} className="text-center italic">
                None currently - We do not use third-party analytics
              </td>
            </tr>
          </tbody>
        </table>
        <p className="text-sm text-gray-500 dark:text-gray-400 mt-2">
          <strong>Note:</strong> We currently do not use third-party analytics cookies. If this changes, we will update
          this policy and request your consent.
        </p>
      </section>

      <section id="cookies-we-dont-use">
        <h2>Cookies We Do NOT Use</h2>
        <p>HeroForge does not use:</p>
        <ul>
          <li>Advertising cookies</li>
          <li>Third-party tracking pixels</li>
          <li>Social media cookies</li>
          <li>Cross-site tracking</li>
          <li>Fingerprinting technologies</li>
        </ul>
      </section>

      <section id="your-choices">
        <h2>Your Cookie Choices</h2>

        <h3>Browser Settings</h3>
        <p>You can control cookies through your browser settings:</p>
        <ul>
          <li><strong>Chrome:</strong> Settings → Privacy and security → Cookies</li>
          <li><strong>Firefox:</strong> Settings → Privacy & Security → Cookies</li>
          <li><strong>Safari:</strong> Preferences → Privacy → Cookies</li>
          <li><strong>Edge:</strong> Settings → Privacy → Cookies</li>
        </ul>

        <h3>Impact of Disabling Cookies</h3>
        <p>If you disable essential cookies:</p>
        <ul>
          <li>You will not be able to log in</li>
          <li>Security features may not work properly</li>
          <li>Session state will not be maintained</li>
        </ul>
      </section>

      <section id="local-storage">
        <h2>Local Storage</h2>
        <p>In addition to cookies, we use browser local storage for:</p>
        <ul>
          <li>Authentication tokens (more secure than cookies)</li>
          <li>User interface preferences</li>
          <li>Cached application data</li>
        </ul>
        <p>You can clear local storage through your browser's developer tools.</p>
      </section>

      <section id="third-party">
        <h2>Third-Party Services</h2>
        <p>
          When you integrate with third-party services (e.g., JIRA, Slack), those services may set their own cookies.
          Please refer to their privacy policies.
        </p>
      </section>

      <section id="changes">
        <h2>Changes to This Policy</h2>
        <p>
          We may update this Cookie Policy as our practices change. The "Last Updated" date will reflect any changes.
        </p>
      </section>

      <section id="contact">
        <h2>Contact Us</h2>
        <p>For questions about our use of cookies:</p>
        <ul>
          <li><strong>Email:</strong> privacy@heroforge.security</li>
          <li><strong>Website:</strong> <a href="https://heroforge.genialarchitect.io">https://heroforge.genialarchitect.io</a></li>
        </ul>
      </section>

      <div className="mt-8 p-4 bg-gray-100 dark:bg-gray-700 rounded-lg">
        <p className="text-sm font-semibold">
          By using HeroForge, you consent to our use of essential cookies as described in this policy.
        </p>
      </div>
    </LegalLayout>
  );
};

export default CookiePage;
