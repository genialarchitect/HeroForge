import React, { useState } from 'react';
import { Link, useParams, useNavigate } from 'react-router-dom';

// Article content organized by slug
const articles: Record<string, { title: string; category: string; content: React.ReactNode }> = {
  'getting-started': {
    title: 'Getting Started with HeroForge',
    category: 'Basics',
    content: (
      <>
        <p className="text-gray-300 mb-6">
          Welcome to HeroForge! This guide will help you get up and running with network reconnaissance
          and security assessments.
        </p>

        <h2 className="text-xl font-semibold text-white mb-4">1. Create Your Account</h2>
        <p className="text-gray-300 mb-4">
          Visit <a href="/register" className="text-cyan-400 hover:underline">heroforge.genialarchitect.io/register</a> to
          create your account. You'll need to:
        </p>
        <ul className="list-disc list-inside text-gray-300 mb-6 space-y-2">
          <li>Enter your email address and select a subscription tier</li>
          <li>Complete email verification (or auto-verification for free tier)</li>
          <li>Set up your username and password</li>
          <li>Accept the Terms of Service</li>
        </ul>

        <h2 className="text-xl font-semibold text-white mb-4">2. Your First Scan</h2>
        <p className="text-gray-300 mb-4">
          Once logged in, you can start your first network scan:
        </p>
        <ol className="list-decimal list-inside text-gray-300 mb-6 space-y-2">
          <li>Navigate to <strong>Scans</strong> in the sidebar</li>
          <li>Click <strong>New Scan</strong></li>
          <li>Enter your target (IP address, hostname, or CIDR range)</li>
          <li>Select scan type (Quick Scan for beginners)</li>
          <li>Click <strong>Start Scan</strong></li>
        </ol>

        <div className="bg-yellow-900/30 border border-yellow-600 rounded-lg p-4 mb-6">
          <p className="text-yellow-200">
            <strong>Important:</strong> Only scan networks and systems you own or have explicit written
            authorization to test. Unauthorized scanning may violate laws and regulations.
          </p>
        </div>

        <h2 className="text-xl font-semibold text-white mb-4">3. Understanding Scan Results</h2>
        <p className="text-gray-300 mb-4">
          After a scan completes, you'll see:
        </p>
        <ul className="list-disc list-inside text-gray-300 mb-6 space-y-2">
          <li><strong>Discovered Hosts:</strong> All responsive systems found</li>
          <li><strong>Open Ports:</strong> Network services running on each host</li>
          <li><strong>Services:</strong> Identified applications and versions</li>
          <li><strong>Vulnerabilities:</strong> Potential security issues (if vulnerability scanning enabled)</li>
          <li><strong>OS Detection:</strong> Operating system fingerprinting results</li>
        </ul>

        <h2 className="text-xl font-semibold text-white mb-4">4. Scan Types Explained</h2>
        <table className="w-full text-gray-300 mb-6">
          <thead>
            <tr className="border-b border-gray-700">
              <th className="text-left py-2 px-4">Scan Type</th>
              <th className="text-left py-2 px-4">Description</th>
              <th className="text-left py-2 px-4">Use Case</th>
            </tr>
          </thead>
          <tbody>
            <tr className="border-b border-gray-800">
              <td className="py-2 px-4">Quick Scan</td>
              <td className="py-2 px-4">Top 100 ports, basic detection</td>
              <td className="py-2 px-4">Fast overview of a target</td>
            </tr>
            <tr className="border-b border-gray-800">
              <td className="py-2 px-4">Full Scan</td>
              <td className="py-2 px-4">All 65,535 ports</td>
              <td className="py-2 px-4">Thorough assessment</td>
            </tr>
            <tr className="border-b border-gray-800">
              <td className="py-2 px-4">Stealth Scan</td>
              <td className="py-2 px-4">SYN scan (requires privileges)</td>
              <td className="py-2 px-4">Less detectable scanning</td>
            </tr>
            <tr className="border-b border-gray-800">
              <td className="py-2 px-4">Vulnerability Scan</td>
              <td className="py-2 px-4">Port scan + CVE detection</td>
              <td className="py-2 px-4">Security assessment</td>
            </tr>
          </tbody>
        </table>

        <h2 className="text-xl font-semibold text-white mb-4">5. Next Steps</h2>
        <ul className="list-disc list-inside text-gray-300 space-y-2">
          <li>Explore the <Link to="/docs/dashboard" className="text-cyan-400 hover:underline">Dashboard Guide</Link> to learn about all features</li>
          <li>Set up <strong>Scheduled Scans</strong> for continuous monitoring</li>
          <li>Configure <strong>Integrations</strong> (Slack, JIRA) for alerts</li>
          <li>Review <strong>Compliance</strong> reports for your industry standards</li>
        </ul>
      </>
    ),
  },

  'dashboard': {
    title: 'Web Dashboard Guide',
    category: 'Features',
    content: (
      <>
        <p className="text-gray-300 mb-6">
          The HeroForge web dashboard provides a comprehensive interface for managing your security
          assessments, viewing results, and configuring your environment.
        </p>

        <h2 className="text-xl font-semibold text-white mb-4">Dashboard Overview</h2>
        <p className="text-gray-300 mb-4">
          The main dashboard displays:
        </p>
        <ul className="list-disc list-inside text-gray-300 mb-6 space-y-2">
          <li><strong>Recent Scans:</strong> Your latest scan results with status indicators</li>
          <li><strong>Security Score:</strong> Overall health of your assessed infrastructure</li>
          <li><strong>Vulnerability Summary:</strong> Critical, High, Medium, Low counts</li>
          <li><strong>Asset Inventory:</strong> Quick access to discovered hosts</li>
          <li><strong>Upcoming Scheduled Scans:</strong> Next automated assessments</li>
        </ul>

        <h2 className="text-xl font-semibold text-white mb-4">Navigation Sidebar</h2>
        <div className="space-y-4 mb-6">
          <div className="bg-gray-800 rounded-lg p-4">
            <h3 className="text-cyan-400 font-medium mb-2">Scans</h3>
            <p className="text-gray-400 text-sm">Create new scans, view history, manage scheduled scans, and compare scan results over time.</p>
          </div>
          <div className="bg-gray-800 rounded-lg p-4">
            <h3 className="text-cyan-400 font-medium mb-2">Assets</h3>
            <p className="text-gray-400 text-sm">View and manage your asset inventory, tag hosts, group by network, and track changes.</p>
          </div>
          <div className="bg-gray-800 rounded-lg p-4">
            <h3 className="text-cyan-400 font-medium mb-2">Vulnerabilities</h3>
            <p className="text-gray-400 text-sm">Browse all discovered vulnerabilities, filter by severity, assign remediation tasks.</p>
          </div>
          <div className="bg-gray-800 rounded-lg p-4">
            <h3 className="text-cyan-400 font-medium mb-2">Reports</h3>
            <p className="text-gray-400 text-sm">Generate PDF, HTML, CSV, or JSON reports. Schedule automated report delivery.</p>
          </div>
          <div className="bg-gray-800 rounded-lg p-4">
            <h3 className="text-cyan-400 font-medium mb-2">Compliance</h3>
            <p className="text-gray-400 text-sm">Run compliance checks against CIS, NIST, PCI-DSS, HIPAA, SOC 2, and 40+ frameworks.</p>
          </div>
          <div className="bg-gray-800 rounded-lg p-4">
            <h3 className="text-cyan-400 font-medium mb-2">Integrations</h3>
            <p className="text-gray-400 text-sm">Connect to Slack, Microsoft Teams, JIRA, ServiceNow, and SIEM platforms.</p>
          </div>
          <div className="bg-gray-800 rounded-lg p-4">
            <h3 className="text-cyan-400 font-medium mb-2">Settings</h3>
            <p className="text-gray-400 text-sm">Configure account settings, API keys, team members, and notification preferences.</p>
          </div>
        </div>

        <h2 className="text-xl font-semibold text-white mb-4">Scan Results View</h2>
        <p className="text-gray-300 mb-4">
          When viewing scan results, you can:
        </p>
        <ul className="list-disc list-inside text-gray-300 mb-6 space-y-2">
          <li>Click on any host to see detailed information</li>
          <li>Expand ports to view service banners and version info</li>
          <li>View vulnerability details with CVE references</li>
          <li>Export results in multiple formats</li>
          <li>Compare with previous scans to track changes</li>
          <li>Add notes and tags to findings</li>
        </ul>

        <h2 className="text-xl font-semibold text-white mb-4">Real-Time Updates</h2>
        <p className="text-gray-300 mb-4">
          Active scans display live progress via WebSocket connections:
        </p>
        <ul className="list-disc list-inside text-gray-300 mb-6 space-y-2">
          <li>Watch hosts being discovered in real-time</li>
          <li>See ports and services as they're identified</li>
          <li>Monitor vulnerability detection progress</li>
          <li>View estimated time remaining</li>
        </ul>

        <h2 className="text-xl font-semibold text-white mb-4">Keyboard Shortcuts</h2>
        <table className="w-full text-gray-300">
          <thead>
            <tr className="border-b border-gray-700">
              <th className="text-left py-2 px-4">Shortcut</th>
              <th className="text-left py-2 px-4">Action</th>
            </tr>
          </thead>
          <tbody>
            <tr className="border-b border-gray-800">
              <td className="py-2 px-4"><code className="bg-gray-800 px-2 py-1 rounded">N</code></td>
              <td className="py-2 px-4">New Scan</td>
            </tr>
            <tr className="border-b border-gray-800">
              <td className="py-2 px-4"><code className="bg-gray-800 px-2 py-1 rounded">S</code></td>
              <td className="py-2 px-4">Go to Scans</td>
            </tr>
            <tr className="border-b border-gray-800">
              <td className="py-2 px-4"><code className="bg-gray-800 px-2 py-1 rounded">A</code></td>
              <td className="py-2 px-4">Go to Assets</td>
            </tr>
            <tr className="border-b border-gray-800">
              <td className="py-2 px-4"><code className="bg-gray-800 px-2 py-1 rounded">?</code></td>
              <td className="py-2 px-4">Show Keyboard Shortcuts</td>
            </tr>
            <tr className="border-b border-gray-800">
              <td className="py-2 px-4"><code className="bg-gray-800 px-2 py-1 rounded">Esc</code></td>
              <td className="py-2 px-4">Close Modal/Cancel</td>
            </tr>
          </tbody>
        </table>
      </>
    ),
  },

  'cli': {
    title: 'CLI Reference',
    category: 'Technical',
    content: (
      <>
        <p className="text-gray-300 mb-6">
          HeroForge includes a powerful command-line interface for automation, scripting, and advanced users.
        </p>

        <h2 className="text-xl font-semibold text-white mb-4">Installation</h2>
        <p className="text-gray-300 mb-4">
          Download the CLI for your platform:
        </p>
        <div className="bg-gray-800 rounded-lg p-4 mb-6 font-mono text-sm">
          <p className="text-gray-400"># Linux (x86_64)</p>
          <p className="text-cyan-400">curl -L https://heroforge.genialarchitect.io/cli/linux -o heroforge</p>
          <p className="text-cyan-400">chmod +x heroforge</p>
          <p className="text-cyan-400">sudo mv heroforge /usr/local/bin/</p>
        </div>

        <h2 className="text-xl font-semibold text-white mb-4">Basic Commands</h2>

        <h3 className="text-lg font-medium text-cyan-400 mb-2">Scanning</h3>
        <div className="bg-gray-800 rounded-lg p-4 mb-4 font-mono text-sm">
          <p className="text-gray-400"># Full triage scan</p>
          <p className="text-cyan-400">heroforge scan 192.168.1.0/24</p>
          <p className="text-cyan-400 mt-2">heroforge scan example.com -p 1-1000</p>
          <p className="text-cyan-400 mt-2">heroforge scan 10.0.0.1 --scan-type comprehensive</p>
        </div>

        <h3 className="text-lg font-medium text-cyan-400 mb-2">Host Discovery</h3>
        <div className="bg-gray-800 rounded-lg p-4 mb-4 font-mono text-sm">
          <p className="text-gray-400"># Discover live hosts only</p>
          <p className="text-cyan-400">heroforge discover 192.168.1.0/24</p>
          <p className="text-cyan-400 mt-2">heroforge discover 10.0.0.0/16 --timeout 5</p>
        </div>

        <h3 className="text-lg font-medium text-cyan-400 mb-2">Port Scanning</h3>
        <div className="bg-gray-800 rounded-lg p-4 mb-4 font-mono text-sm">
          <p className="text-gray-400"># Scan specific ports</p>
          <p className="text-cyan-400">heroforge portscan 192.168.1.1 -p 22,80,443,8080</p>
          <p className="text-cyan-400 mt-2">heroforge portscan 10.0.0.1 -p 1-65535</p>
        </div>

        <h3 className="text-lg font-medium text-cyan-400 mb-2">Web Server</h3>
        <div className="bg-gray-800 rounded-lg p-4 mb-6 font-mono text-sm">
          <p className="text-gray-400"># Start web dashboard</p>
          <p className="text-cyan-400">heroforge serve --bind 127.0.0.1:8080</p>
          <p className="text-cyan-400 mt-2">heroforge serve --bind 0.0.0.0:8080 --cors-origins "https://myapp.com"</p>
        </div>

        <h2 className="text-xl font-semibold text-white mb-4">Scan Options</h2>
        <table className="w-full text-gray-300 mb-6 text-sm">
          <thead>
            <tr className="border-b border-gray-700">
              <th className="text-left py-2 px-4">Flag</th>
              <th className="text-left py-2 px-4">Description</th>
            </tr>
          </thead>
          <tbody>
            <tr className="border-b border-gray-800">
              <td className="py-2 px-4"><code>-p, --ports</code></td>
              <td className="py-2 px-4">Port range (e.g., 1-1000, 22,80,443)</td>
            </tr>
            <tr className="border-b border-gray-800">
              <td className="py-2 px-4"><code>-s, --scan-type</code></td>
              <td className="py-2 px-4">tcp-connect, tcp-syn, udp, comprehensive</td>
            </tr>
            <tr className="border-b border-gray-800">
              <td className="py-2 px-4"><code>--timeout</code></td>
              <td className="py-2 px-4">Connection timeout in seconds</td>
            </tr>
            <tr className="border-b border-gray-800">
              <td className="py-2 px-4"><code>--threads</code></td>
              <td className="py-2 px-4">Number of concurrent threads</td>
            </tr>
            <tr className="border-b border-gray-800">
              <td className="py-2 px-4"><code>--no-ping</code></td>
              <td className="py-2 px-4">Skip host discovery (treat all as up)</td>
            </tr>
            <tr className="border-b border-gray-800">
              <td className="py-2 px-4"><code>--service-detection</code></td>
              <td className="py-2 px-4">Enable service/version detection</td>
            </tr>
            <tr className="border-b border-gray-800">
              <td className="py-2 px-4"><code>--os-detection</code></td>
              <td className="py-2 px-4">Enable OS fingerprinting</td>
            </tr>
            <tr className="border-b border-gray-800">
              <td className="py-2 px-4"><code>--vuln-scan</code></td>
              <td className="py-2 px-4">Enable vulnerability scanning</td>
            </tr>
            <tr className="border-b border-gray-800">
              <td className="py-2 px-4"><code>-o, --output</code></td>
              <td className="py-2 px-4">Output file path</td>
            </tr>
            <tr className="border-b border-gray-800">
              <td className="py-2 px-4"><code>--format</code></td>
              <td className="py-2 px-4">Output format: json, html, pdf, csv</td>
            </tr>
          </tbody>
        </table>

        <h2 className="text-xl font-semibold text-white mb-4">Configuration File</h2>
        <p className="text-gray-300 mb-4">
          Generate a configuration file for reusable scan profiles:
        </p>
        <div className="bg-gray-800 rounded-lg p-4 mb-4 font-mono text-sm">
          <p className="text-cyan-400">heroforge config &gt; heroforge.toml</p>
        </div>
        <p className="text-gray-300 mb-4">Example configuration:</p>
        <div className="bg-gray-800 rounded-lg p-4 mb-6 font-mono text-sm text-gray-300">
          <pre>{`[scan]
ports = "1-10000"
timeout = 3
threads = 100
scan_type = "tcp-connect"

[detection]
service_detection = true
os_detection = true
vuln_scan = true

[output]
format = "json"
verbose = true`}</pre>
        </div>

        <h2 className="text-xl font-semibold text-white mb-4">Environment Variables</h2>
        <table className="w-full text-gray-300 text-sm">
          <thead>
            <tr className="border-b border-gray-700">
              <th className="text-left py-2 px-4">Variable</th>
              <th className="text-left py-2 px-4">Description</th>
            </tr>
          </thead>
          <tbody>
            <tr className="border-b border-gray-800">
              <td className="py-2 px-4"><code>HEROFORGE_API_KEY</code></td>
              <td className="py-2 px-4">API key for cloud sync</td>
            </tr>
            <tr className="border-b border-gray-800">
              <td className="py-2 px-4"><code>HEROFORGE_CONFIG</code></td>
              <td className="py-2 px-4">Path to configuration file</td>
            </tr>
            <tr className="border-b border-gray-800">
              <td className="py-2 px-4"><code>HEROFORGE_OUTPUT_DIR</code></td>
              <td className="py-2 px-4">Default output directory</td>
            </tr>
          </tbody>
        </table>
      </>
    ),
  },

  'faq': {
    title: 'Frequently Asked Questions',
    category: 'Support',
    content: (
      <>
        <div className="space-y-8">
          <div>
            <h2 className="text-xl font-semibold text-white mb-3">General Questions</h2>

            <div className="space-y-4">
              <div className="bg-gray-800 rounded-lg p-4">
                <h3 className="text-cyan-400 font-medium mb-2">What is HeroForge?</h3>
                <p className="text-gray-300">
                  HeroForge is a network reconnaissance and security triage tool designed for authorized
                  penetration testing and security assessments. It helps security professionals discover
                  hosts, scan ports, detect services, identify vulnerabilities, and generate compliance reports.
                </p>
              </div>

              <div className="bg-gray-800 rounded-lg p-4">
                <h3 className="text-cyan-400 font-medium mb-2">Is HeroForge legal to use?</h3>
                <p className="text-gray-300">
                  HeroForge is a legitimate security tool. However, you must only scan networks and systems
                  you own or have explicit written authorization to test. Unauthorized scanning may violate
                  computer fraud and abuse laws in your jurisdiction.
                </p>
              </div>

              <div className="bg-gray-800 rounded-lg p-4">
                <h3 className="text-cyan-400 font-medium mb-2">What's included in the free tier?</h3>
                <p className="text-gray-300">
                  The free tier includes 3 scans per month, basic vulnerability detection, community support,
                  and JSON/CSV export. Upgrade to Professional for unlimited scans, all features, and email support.
                </p>
              </div>
            </div>
          </div>

          <div>
            <h2 className="text-xl font-semibold text-white mb-3">Scanning Questions</h2>

            <div className="space-y-4">
              <div className="bg-gray-800 rounded-lg p-4">
                <h3 className="text-cyan-400 font-medium mb-2">Why is my scan taking a long time?</h3>
                <p className="text-gray-300">
                  Scan duration depends on the target size, port range, and network conditions. A full 65,535
                  port scan of multiple hosts can take significant time. Consider using Quick Scan for faster
                  results, or reduce the port range with the <code className="bg-gray-700 px-1 rounded">-p</code> flag.
                </p>
              </div>

              <div className="bg-gray-800 rounded-lg p-4">
                <h3 className="text-cyan-400 font-medium mb-2">What's the difference between TCP Connect and SYN scan?</h3>
                <p className="text-gray-300">
                  TCP Connect completes the full 3-way handshake and works without special privileges.
                  SYN scan (stealth scan) only sends SYN packets and is faster and less detectable, but
                  requires root/administrator privileges.
                </p>
              </div>

              <div className="bg-gray-800 rounded-lg p-4">
                <h3 className="text-cyan-400 font-medium mb-2">How accurate is OS detection?</h3>
                <p className="text-gray-300">
                  OS fingerprinting is typically 85-95% accurate for common operating systems. Accuracy can
                  decrease for heavily firewalled hosts, custom kernels, or devices that don't respond to
                  standard fingerprinting probes.
                </p>
              </div>

              <div className="bg-gray-800 rounded-lg p-4">
                <h3 className="text-cyan-400 font-medium mb-2">Can I scan cloud environments (AWS, Azure, GCP)?</h3>
                <p className="text-gray-300">
                  Yes! HeroForge includes dedicated cloud security scanning modules. You'll need to configure
                  your cloud credentials in Settings → Integrations. Note that some cloud providers require
                  advance notification for penetration testing.
                </p>
              </div>
            </div>
          </div>

          <div>
            <h2 className="text-xl font-semibold text-white mb-3">Account & Billing</h2>

            <div className="space-y-4">
              <div className="bg-gray-800 rounded-lg p-4">
                <h3 className="text-cyan-400 font-medium mb-2">How do I upgrade my subscription?</h3>
                <p className="text-gray-300">
                  Go to Settings → Subscription and click "Upgrade Plan". You can switch between tiers
                  at any time. When upgrading, you'll be charged the prorated difference for the remainder
                  of your billing period.
                </p>
              </div>

              <div className="bg-gray-800 rounded-lg p-4">
                <h3 className="text-cyan-400 font-medium mb-2">Can I cancel my subscription?</h3>
                <p className="text-gray-300">
                  Yes, you can cancel anytime from Settings → Subscription. Your access continues until
                  the end of your current billing period. Your data is retained for 30 days after cancellation.
                </p>
              </div>

              <div className="bg-gray-800 rounded-lg p-4">
                <h3 className="text-cyan-400 font-medium mb-2">Do you offer refunds?</h3>
                <p className="text-gray-300">
                  We offer a 14-day money-back guarantee for new subscriptions. Contact support@genialarchitect.io
                  within 14 days of your purchase for a full refund.
                </p>
              </div>
            </div>
          </div>

          <div>
            <h2 className="text-xl font-semibold text-white mb-3">Security & Privacy</h2>

            <div className="space-y-4">
              <div className="bg-gray-800 rounded-lg p-4">
                <h3 className="text-cyan-400 font-medium mb-2">How is my data protected?</h3>
                <p className="text-gray-300">
                  All data is encrypted at rest using AES-256 encryption. Data in transit uses TLS 1.3.
                  We follow security best practices including regular security audits, access controls,
                  and encrypted backups.
                </p>
              </div>

              <div className="bg-gray-800 rounded-lg p-4">
                <h3 className="text-cyan-400 font-medium mb-2">Do you store my scan results?</h3>
                <p className="text-gray-300">
                  Scan results are stored in your account for historical analysis and comparison. You can
                  delete individual scans or all data at any time. Enterprise customers can configure
                  data retention policies.
                </p>
              </div>

              <div className="bg-gray-800 rounded-lg p-4">
                <h3 className="text-cyan-400 font-medium mb-2">Is HeroForge compliant with security standards?</h3>
                <p className="text-gray-300">
                  HeroForge is designed with security-first principles. We're working toward SOC 2 Type II
                  certification. Contact sales@genialarchitect.io for our security questionnaire and
                  compliance documentation.
                </p>
              </div>
            </div>
          </div>
        </div>
      </>
    ),
  },

  'troubleshooting': {
    title: 'Troubleshooting Guide',
    category: 'Support',
    content: (
      <>
        <p className="text-gray-300 mb-6">
          Having issues? This guide covers common problems and their solutions.
        </p>

        <h2 className="text-xl font-semibold text-white mb-4">Connection Issues</h2>

        <div className="space-y-4 mb-8">
          <div className="bg-gray-800 rounded-lg p-4">
            <h3 className="text-red-400 font-medium mb-2">Error: "Connection refused" or "Network unreachable"</h3>
            <p className="text-gray-300 mb-2"><strong>Possible causes:</strong></p>
            <ul className="list-disc list-inside text-gray-300 mb-2 space-y-1">
              <li>Target host is down or not responding</li>
              <li>Firewall blocking the connection</li>
              <li>Incorrect IP address or hostname</li>
            </ul>
            <p className="text-gray-300"><strong>Solutions:</strong></p>
            <ul className="list-disc list-inside text-gray-300 space-y-1">
              <li>Verify the target is reachable with <code className="bg-gray-700 px-1 rounded">ping</code></li>
              <li>Check your firewall rules</li>
              <li>Try a different port or scan type</li>
            </ul>
          </div>

          <div className="bg-gray-800 rounded-lg p-4">
            <h3 className="text-red-400 font-medium mb-2">Error: "Connection timed out"</h3>
            <p className="text-gray-300 mb-2"><strong>Possible causes:</strong></p>
            <ul className="list-disc list-inside text-gray-300 mb-2 space-y-1">
              <li>Target is behind a firewall dropping packets</li>
              <li>Network latency is high</li>
              <li>Timeout value is too low</li>
            </ul>
            <p className="text-gray-300"><strong>Solutions:</strong></p>
            <ul className="list-disc list-inside text-gray-300 space-y-1">
              <li>Increase timeout: <code className="bg-gray-700 px-1 rounded">--timeout 10</code></li>
              <li>Reduce concurrent threads: <code className="bg-gray-700 px-1 rounded">--threads 50</code></li>
              <li>Try TCP Connect scan instead of SYN</li>
            </ul>
          </div>
        </div>

        <h2 className="text-xl font-semibold text-white mb-4">Scan Issues</h2>

        <div className="space-y-4 mb-8">
          <div className="bg-gray-800 rounded-lg p-4">
            <h3 className="text-red-400 font-medium mb-2">Scan shows 0 hosts discovered</h3>
            <p className="text-gray-300 mb-2"><strong>Possible causes:</strong></p>
            <ul className="list-disc list-inside text-gray-300 mb-2 space-y-1">
              <li>Hosts blocking ICMP (ping) requests</li>
              <li>Wrong subnet or IP range</li>
              <li>Network segmentation preventing access</li>
            </ul>
            <p className="text-gray-300"><strong>Solutions:</strong></p>
            <ul className="list-disc list-inside text-gray-300 space-y-1">
              <li>Use <code className="bg-gray-700 px-1 rounded">--no-ping</code> to skip host discovery</li>
              <li>Verify you can reach the network manually</li>
              <li>Check if you're on the correct VLAN/subnet</li>
            </ul>
          </div>

          <div className="bg-gray-800 rounded-lg p-4">
            <h3 className="text-red-400 font-medium mb-2">SYN scan requires root privileges</h3>
            <p className="text-gray-300 mb-2"><strong>Explanation:</strong></p>
            <p className="text-gray-300 mb-2">
              SYN (stealth) scanning requires raw socket access, which needs elevated privileges.
            </p>
            <p className="text-gray-300"><strong>Solutions:</strong></p>
            <ul className="list-disc list-inside text-gray-300 space-y-1">
              <li>Run with <code className="bg-gray-700 px-1 rounded">sudo</code> on Linux/Mac</li>
              <li>Run as Administrator on Windows</li>
              <li>Use TCP Connect scan instead: <code className="bg-gray-700 px-1 rounded">--scan-type tcp-connect</code></li>
            </ul>
          </div>

          <div className="bg-gray-800 rounded-lg p-4">
            <h3 className="text-red-400 font-medium mb-2">Service detection showing "unknown"</h3>
            <p className="text-gray-300 mb-2"><strong>Possible causes:</strong></p>
            <ul className="list-disc list-inside text-gray-300 mb-2 space-y-1">
              <li>Non-standard service on that port</li>
              <li>Service not responding to probes</li>
              <li>Encrypted/TLS service without banner</li>
            </ul>
            <p className="text-gray-300"><strong>Solutions:</strong></p>
            <ul className="list-disc list-inside text-gray-300 space-y-1">
              <li>Try aggressive service detection mode</li>
              <li>Manually connect to investigate the service</li>
              <li>Check if it's a custom application</li>
            </ul>
          </div>
        </div>

        <h2 className="text-xl font-semibold text-white mb-4">Web Dashboard Issues</h2>

        <div className="space-y-4 mb-8">
          <div className="bg-gray-800 rounded-lg p-4">
            <h3 className="text-red-400 font-medium mb-2">Dashboard not loading / blank page</h3>
            <p className="text-gray-300"><strong>Solutions:</strong></p>
            <ul className="list-disc list-inside text-gray-300 space-y-1">
              <li>Clear browser cache and cookies</li>
              <li>Try incognito/private browsing mode</li>
              <li>Disable browser extensions temporarily</li>
              <li>Try a different browser (Chrome, Firefox, Edge)</li>
            </ul>
          </div>

          <div className="bg-gray-800 rounded-lg p-4">
            <h3 className="text-red-400 font-medium mb-2">Session expired / logged out unexpectedly</h3>
            <p className="text-gray-300"><strong>Solutions:</strong></p>
            <ul className="list-disc list-inside text-gray-300 space-y-1">
              <li>Sessions expire after 1 hour of inactivity</li>
              <li>Check if you're logged in from another device</li>
              <li>Ensure your system clock is accurate</li>
              <li>Clear cookies and log in again</li>
            </ul>
          </div>

          <div className="bg-gray-800 rounded-lg p-4">
            <h3 className="text-red-400 font-medium mb-2">WebSocket connection failed</h3>
            <p className="text-gray-300 mb-2">
              Real-time scan updates require WebSocket connections.
            </p>
            <p className="text-gray-300"><strong>Solutions:</strong></p>
            <ul className="list-disc list-inside text-gray-300 space-y-1">
              <li>Check if your network/proxy allows WebSocket (port 443)</li>
              <li>Disable VPN temporarily to test</li>
              <li>Try from a different network</li>
            </ul>
          </div>
        </div>

        <h2 className="text-xl font-semibold text-white mb-4">Performance Issues</h2>

        <div className="space-y-4 mb-8">
          <div className="bg-gray-800 rounded-lg p-4">
            <h3 className="text-red-400 font-medium mb-2">Scans running very slowly</h3>
            <p className="text-gray-300"><strong>Solutions:</strong></p>
            <ul className="list-disc list-inside text-gray-300 space-y-1">
              <li>Reduce port range for initial scans</li>
              <li>Decrease timeout value: <code className="bg-gray-700 px-1 rounded">--timeout 2</code></li>
              <li>Increase thread count (if resources allow): <code className="bg-gray-700 px-1 rounded">--threads 200</code></li>
              <li>Use Quick Scan for initial reconnaissance</li>
            </ul>
          </div>
        </div>

        <h2 className="text-xl font-semibold text-white mb-4">Still Need Help?</h2>
        <div className="bg-cyan-900/30 border border-cyan-600 rounded-lg p-4">
          <p className="text-gray-300 mb-2">
            If you're still experiencing issues, contact our support team:
          </p>
          <ul className="list-disc list-inside text-gray-300 space-y-1">
            <li>Email: <a href="mailto:support@genialarchitect.io" className="text-cyan-400 hover:underline">support@genialarchitect.io</a></li>
            <li>Include: Your account email, error messages, and steps to reproduce</li>
            <li>Response time: Within 24-48 hours (best effort)</li>
          </ul>
        </div>
      </>
    ),
  },

  'complete-guide': {
    title: 'Complete User Guide: From Setup to Mastery',
    category: 'Basics',
    content: (
      <>
        <p className="text-gray-300 mb-6">
          This comprehensive guide walks you through every step of using HeroForge, from initial setup
          to advanced features. Follow along to become proficient in network reconnaissance and security assessment.
        </p>

        <div className="bg-cyan-900/30 border border-cyan-600 rounded-lg p-4 mb-8">
          <p className="text-cyan-200">
            <strong>Estimated Time:</strong> 30-45 minutes to complete all steps. You can bookmark this page
            and return at any time.
          </p>
        </div>

        {/* Table of Contents */}
        <div className="bg-gray-800 rounded-lg p-6 mb-8">
          <h2 className="text-lg font-semibold text-white mb-4">Table of Contents</h2>
          <ol className="list-decimal list-inside text-gray-300 space-y-2">
            <li><a href="#step1" className="text-cyan-400 hover:underline">Create Your Account</a></li>
            <li><a href="#step2" className="text-cyan-400 hover:underline">Explore the Dashboard</a></li>
            <li><a href="#step3" className="text-cyan-400 hover:underline">Run Your First Scan</a></li>
            <li><a href="#step4" className="text-cyan-400 hover:underline">Analyze Scan Results</a></li>
            <li><a href="#step5" className="text-cyan-400 hover:underline">Manage Your Assets</a></li>
            <li><a href="#step6" className="text-cyan-400 hover:underline">Review Vulnerabilities</a></li>
            <li><a href="#step7" className="text-cyan-400 hover:underline">Generate Reports</a></li>
            <li><a href="#step8" className="text-cyan-400 hover:underline">Set Up Scheduled Scans</a></li>
            <li><a href="#step9" className="text-cyan-400 hover:underline">Configure Integrations</a></li>
            <li><a href="#step10" className="text-cyan-400 hover:underline">Run Compliance Checks</a></li>
            <li><a href="#step11" className="text-cyan-400 hover:underline">Team & Organization Setup</a></li>
            <li><a href="#step12" className="text-cyan-400 hover:underline">Customer Relationship Management (CRM)</a></li>
            <li><a href="#step13" className="text-cyan-400 hover:underline">Advanced Features</a></li>
          </ol>
        </div>

        {/* Step 1 */}
        <div id="step1" className="mb-12">
          <div className="flex items-center mb-4">
            <span className="bg-cyan-600 text-white text-sm font-bold px-3 py-1 rounded-full mr-3">Step 1</span>
            <h2 className="text-2xl font-semibold text-white">Create Your Account</h2>
          </div>

          <h3 className="text-lg font-medium text-cyan-400 mb-3">1.1 Register</h3>
          <ol className="list-decimal list-inside text-gray-300 mb-4 space-y-2 ml-4">
            <li>Go to <a href="/register" className="text-cyan-400 hover:underline">heroforge.genialarchitect.io/register</a></li>
            <li>Enter your email address</li>
            <li>Select your subscription tier:
              <ul className="list-disc list-inside ml-6 mt-2 text-gray-400">
                <li><strong>Free:</strong> 3 scans/month, basic features</li>
                <li><strong>Professional:</strong> Unlimited scans, all features</li>
                <li><strong>Enterprise:</strong> Team features, SSO, dedicated support</li>
              </ul>
            </li>
            <li>Click <strong>Continue</strong></li>
          </ol>

          <h3 className="text-lg font-medium text-cyan-400 mb-3">1.2 Verify Your Email</h3>
          <p className="text-gray-300 mb-4">
            Check your inbox for a verification email. Click the verification link or enter the code provided.
          </p>

          <h3 className="text-lg font-medium text-cyan-400 mb-3">1.3 Complete Profile Setup</h3>
          <ol className="list-decimal list-inside text-gray-300 mb-4 space-y-2 ml-4">
            <li>Choose a username (this will be your login)</li>
            <li>Enter your full name</li>
            <li>Set a strong password (minimum 12 characters recommended)</li>
            <li>Optionally enter your organization name</li>
            <li>Accept the Terms of Service</li>
            <li>Click <strong>Complete Registration</strong></li>
          </ol>

          <div className="bg-green-900/30 border border-green-600 rounded-lg p-4">
            <p className="text-green-200">
              <strong>Success!</strong> You're now logged in and ready to explore HeroForge.
            </p>
          </div>
        </div>

        {/* Step 2 */}
        <div id="step2" className="mb-12">
          <div className="flex items-center mb-4">
            <span className="bg-cyan-600 text-white text-sm font-bold px-3 py-1 rounded-full mr-3">Step 2</span>
            <h2 className="text-2xl font-semibold text-white">Explore the Dashboard</h2>
          </div>

          <p className="text-gray-300 mb-4">
            After logging in, you'll see the main dashboard. Take a moment to familiarize yourself with the layout:
          </p>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
            <div className="bg-gray-800 rounded-lg p-4">
              <h4 className="text-cyan-400 font-medium mb-2">Left Sidebar</h4>
              <p className="text-gray-400 text-sm">Navigation menu with all major features: Scans, Assets, Vulnerabilities, Reports, Compliance, and Settings.</p>
            </div>
            <div className="bg-gray-800 rounded-lg p-4">
              <h4 className="text-cyan-400 font-medium mb-2">Top Header</h4>
              <p className="text-gray-400 text-sm">Quick actions, notifications, and your account menu.</p>
            </div>
            <div className="bg-gray-800 rounded-lg p-4">
              <h4 className="text-cyan-400 font-medium mb-2">Main Dashboard</h4>
              <p className="text-gray-400 text-sm">Overview widgets showing recent scans, security score, vulnerability summary, and quick stats.</p>
            </div>
            <div className="bg-gray-800 rounded-lg p-4">
              <h4 className="text-cyan-400 font-medium mb-2">Activity Feed</h4>
              <p className="text-gray-400 text-sm">Recent activity, scan completions, and system notifications.</p>
            </div>
          </div>

          <p className="text-gray-300">
            <strong>Tip:</strong> The dashboard is customizable. Click the settings icon to rearrange widgets or add new ones.
          </p>
        </div>

        {/* Step 3 */}
        <div id="step3" className="mb-12">
          <div className="flex items-center mb-4">
            <span className="bg-cyan-600 text-white text-sm font-bold px-3 py-1 rounded-full mr-3">Step 3</span>
            <h2 className="text-2xl font-semibold text-white">Run Your First Scan</h2>
          </div>

          <div className="bg-yellow-900/30 border border-yellow-600 rounded-lg p-4 mb-6">
            <p className="text-yellow-200">
              <strong>Important:</strong> Only scan networks and systems you own or have explicit written authorization to test.
            </p>
          </div>

          <h3 className="text-lg font-medium text-cyan-400 mb-3">3.1 Start a New Scan</h3>
          <ol className="list-decimal list-inside text-gray-300 mb-4 space-y-2 ml-4">
            <li>Click <strong>Scans</strong> in the sidebar</li>
            <li>Click the <strong>+ New Scan</strong> button</li>
            <li>Enter your target:
              <ul className="list-disc list-inside ml-6 mt-2 text-gray-400">
                <li>Single IP: <code className="bg-gray-700 px-1 rounded">192.168.1.1</code></li>
                <li>Hostname: <code className="bg-gray-700 px-1 rounded">server.example.com</code></li>
                <li>IP Range: <code className="bg-gray-700 px-1 rounded">192.168.1.1-254</code></li>
                <li>CIDR: <code className="bg-gray-700 px-1 rounded">192.168.1.0/24</code></li>
              </ul>
            </li>
          </ol>

          <h3 className="text-lg font-medium text-cyan-400 mb-3">3.2 Choose Scan Settings</h3>
          <table className="w-full text-gray-300 mb-6 text-sm">
            <thead>
              <tr className="border-b border-gray-700">
                <th className="text-left py-2 px-3">Setting</th>
                <th className="text-left py-2 px-3">Recommended for First Scan</th>
              </tr>
            </thead>
            <tbody>
              <tr className="border-b border-gray-800">
                <td className="py-2 px-3">Scan Type</td>
                <td className="py-2 px-3"><strong>Quick Scan</strong> (top 100 ports)</td>
              </tr>
              <tr className="border-b border-gray-800">
                <td className="py-2 px-3">Service Detection</td>
                <td className="py-2 px-3">Enabled</td>
              </tr>
              <tr className="border-b border-gray-800">
                <td className="py-2 px-3">OS Detection</td>
                <td className="py-2 px-3">Enabled</td>
              </tr>
              <tr className="border-b border-gray-800">
                <td className="py-2 px-3">Vulnerability Scan</td>
                <td className="py-2 px-3">Optional (adds time)</td>
              </tr>
            </tbody>
          </table>

          <h3 className="text-lg font-medium text-cyan-400 mb-3">3.3 Launch the Scan</h3>
          <ol className="list-decimal list-inside text-gray-300 mb-4 space-y-2 ml-4">
            <li>Review your settings</li>
            <li>Click <strong>Start Scan</strong></li>
            <li>Watch real-time progress as hosts and ports are discovered</li>
            <li>Wait for scan completion (quick scans typically finish in 1-5 minutes)</li>
          </ol>
        </div>

        {/* Step 4 */}
        <div id="step4" className="mb-12">
          <div className="flex items-center mb-4">
            <span className="bg-cyan-600 text-white text-sm font-bold px-3 py-1 rounded-full mr-3">Step 4</span>
            <h2 className="text-2xl font-semibold text-white">Analyze Scan Results</h2>
          </div>

          <p className="text-gray-300 mb-4">
            Once your scan completes, you'll see detailed results:
          </p>

          <h3 className="text-lg font-medium text-cyan-400 mb-3">4.1 Results Overview</h3>
          <ul className="list-disc list-inside text-gray-300 mb-4 space-y-2 ml-4">
            <li><strong>Hosts Discovered:</strong> Number of responsive systems found</li>
            <li><strong>Open Ports:</strong> Total open ports across all hosts</li>
            <li><strong>Services:</strong> Identified applications and versions</li>
            <li><strong>Vulnerabilities:</strong> Security issues found (if vuln scan enabled)</li>
          </ul>

          <h3 className="text-lg font-medium text-cyan-400 mb-3">4.2 Exploring Host Details</h3>
          <ol className="list-decimal list-inside text-gray-300 mb-4 space-y-2 ml-4">
            <li>Click on any host to expand its details</li>
            <li>View open ports and their services</li>
            <li>See OS detection results</li>
            <li>Review any vulnerabilities found</li>
            <li>Add notes or tags for organization</li>
          </ol>

          <h3 className="text-lg font-medium text-cyan-400 mb-3">4.3 Understanding Port Information</h3>
          <div className="bg-gray-800 rounded-lg p-4 mb-4 font-mono text-sm">
            <p className="text-gray-300">Port 22/tcp - SSH - OpenSSH 8.4p1</p>
            <p className="text-gray-300">Port 80/tcp - HTTP - nginx 1.18.0</p>
            <p className="text-gray-300">Port 443/tcp - HTTPS - nginx 1.18.0</p>
            <p className="text-gray-300">Port 3306/tcp - MySQL - MySQL 8.0.23</p>
          </div>
          <p className="text-gray-400 text-sm">
            Each line shows: Port/Protocol - Service Name - Version Information
          </p>
        </div>

        {/* Step 5 */}
        <div id="step5" className="mb-12">
          <div className="flex items-center mb-4">
            <span className="bg-cyan-600 text-white text-sm font-bold px-3 py-1 rounded-full mr-3">Step 5</span>
            <h2 className="text-2xl font-semibold text-white">Manage Your Assets</h2>
          </div>

          <p className="text-gray-300 mb-4">
            Assets are automatically created from scan results. Use the Assets section to organize and track your infrastructure.
          </p>

          <h3 className="text-lg font-medium text-cyan-400 mb-3">5.1 Access Asset Inventory</h3>
          <ol className="list-decimal list-inside text-gray-300 mb-4 space-y-2 ml-4">
            <li>Click <strong>Assets</strong> in the sidebar</li>
            <li>View all discovered hosts in a searchable table</li>
            <li>Filter by IP, hostname, OS, or custom tags</li>
          </ol>

          <h3 className="text-lg font-medium text-cyan-400 mb-3">5.2 Organize Assets</h3>
          <ul className="list-disc list-inside text-gray-300 mb-4 space-y-2 ml-4">
            <li><strong>Tags:</strong> Add custom tags (e.g., "production", "development", "critical")</li>
            <li><strong>Groups:</strong> Organize assets into logical groups</li>
            <li><strong>Notes:</strong> Add context about each asset</li>
            <li><strong>Ownership:</strong> Assign assets to team members</li>
          </ul>

          <h3 className="text-lg font-medium text-cyan-400 mb-3">5.3 Asset Details</h3>
          <p className="text-gray-300 mb-4">
            Click any asset to view:
          </p>
          <ul className="list-disc list-inside text-gray-300 mb-4 space-y-1 ml-4">
            <li>Full scan history for that host</li>
            <li>All discovered ports and services</li>
            <li>Vulnerability timeline</li>
            <li>Change history (new/closed ports)</li>
          </ul>
        </div>

        {/* Step 6 */}
        <div id="step6" className="mb-12">
          <div className="flex items-center mb-4">
            <span className="bg-cyan-600 text-white text-sm font-bold px-3 py-1 rounded-full mr-3">Step 6</span>
            <h2 className="text-2xl font-semibold text-white">Review Vulnerabilities</h2>
          </div>

          <h3 className="text-lg font-medium text-cyan-400 mb-3">6.1 Vulnerability Dashboard</h3>
          <ol className="list-decimal list-inside text-gray-300 mb-4 space-y-2 ml-4">
            <li>Click <strong>Vulnerabilities</strong> in the sidebar</li>
            <li>View summary by severity: Critical, High, Medium, Low</li>
            <li>See trending vulnerabilities and recent discoveries</li>
          </ol>

          <h3 className="text-lg font-medium text-cyan-400 mb-3">6.2 Understanding Severity</h3>
          <div className="space-y-2 mb-6">
            <div className="flex items-center">
              <span className="w-20 text-red-500 font-bold">Critical</span>
              <span className="text-gray-300">Immediate action required. Exploitable with significant impact.</span>
            </div>
            <div className="flex items-center">
              <span className="w-20 text-orange-500 font-bold">High</span>
              <span className="text-gray-300">Address promptly. Potential for serious compromise.</span>
            </div>
            <div className="flex items-center">
              <span className="w-20 text-yellow-500 font-bold">Medium</span>
              <span className="text-gray-300">Plan remediation. Moderate risk or limited exposure.</span>
            </div>
            <div className="flex items-center">
              <span className="w-20 text-blue-500 font-bold">Low</span>
              <span className="text-gray-300">Address when convenient. Minimal risk.</span>
            </div>
          </div>

          <h3 className="text-lg font-medium text-cyan-400 mb-3">6.3 Vulnerability Details</h3>
          <p className="text-gray-300 mb-4">
            Click any vulnerability to see:
          </p>
          <ul className="list-disc list-inside text-gray-300 mb-4 space-y-1 ml-4">
            <li>CVE identifier and description</li>
            <li>CVSS score and attack vector</li>
            <li>Affected assets</li>
            <li>Remediation guidance</li>
            <li>References and exploits (if public)</li>
          </ul>

          <h3 className="text-lg font-medium text-cyan-400 mb-3">6.4 Track Remediation</h3>
          <ul className="list-disc list-inside text-gray-300 mb-4 space-y-2 ml-4">
            <li>Mark vulnerabilities as "In Progress" or "Resolved"</li>
            <li>Add remediation notes</li>
            <li>Assign to team members</li>
            <li>Set target remediation dates</li>
            <li>Re-scan to verify fixes</li>
          </ul>
        </div>

        {/* Step 7 */}
        <div id="step7" className="mb-12">
          <div className="flex items-center mb-4">
            <span className="bg-cyan-600 text-white text-sm font-bold px-3 py-1 rounded-full mr-3">Step 7</span>
            <h2 className="text-2xl font-semibold text-white">Generate Reports</h2>
          </div>

          <h3 className="text-lg font-medium text-cyan-400 mb-3">7.1 Create a Report</h3>
          <ol className="list-decimal list-inside text-gray-300 mb-4 space-y-2 ml-4">
            <li>Click <strong>Reports</strong> in the sidebar</li>
            <li>Click <strong>+ New Report</strong></li>
            <li>Select report type:
              <ul className="list-disc list-inside ml-6 mt-2 text-gray-400">
                <li><strong>Executive Summary:</strong> High-level overview for leadership</li>
                <li><strong>Technical Report:</strong> Detailed findings for IT teams</li>
                <li><strong>Vulnerability Report:</strong> Focus on security issues</li>
                <li><strong>Compliance Report:</strong> Framework-specific assessment</li>
              </ul>
            </li>
            <li>Select scope (specific scans, date range, or all data)</li>
            <li>Choose format: PDF, HTML, JSON, or CSV</li>
            <li>Click <strong>Generate</strong></li>
          </ol>

          <h3 className="text-lg font-medium text-cyan-400 mb-3">7.2 Report Contents</h3>
          <p className="text-gray-300 mb-4">
            Reports include:
          </p>
          <ul className="list-disc list-inside text-gray-300 mb-4 space-y-1 ml-4">
            <li>Executive summary with key metrics</li>
            <li>Risk score and trend analysis</li>
            <li>Vulnerability breakdown by severity</li>
            <li>Asset inventory summary</li>
            <li>Remediation recommendations</li>
            <li>Appendix with technical details</li>
          </ul>

          <h3 className="text-lg font-medium text-cyan-400 mb-3">7.3 Share Reports</h3>
          <ul className="list-disc list-inside text-gray-300 mb-4 space-y-2 ml-4">
            <li>Download reports directly</li>
            <li>Email reports to stakeholders</li>
            <li>Schedule automatic report delivery</li>
            <li>Share via secure link (Enterprise tier)</li>
          </ul>
        </div>

        {/* Step 8 */}
        <div id="step8" className="mb-12">
          <div className="flex items-center mb-4">
            <span className="bg-cyan-600 text-white text-sm font-bold px-3 py-1 rounded-full mr-3">Step 8</span>
            <h2 className="text-2xl font-semibold text-white">Set Up Scheduled Scans</h2>
          </div>

          <p className="text-gray-300 mb-4">
            Automate your security assessments with scheduled scans.
          </p>

          <h3 className="text-lg font-medium text-cyan-400 mb-3">8.1 Create a Scheduled Scan</h3>
          <ol className="list-decimal list-inside text-gray-300 mb-4 space-y-2 ml-4">
            <li>Go to <strong>Scans</strong> → <strong>Scheduled</strong></li>
            <li>Click <strong>+ New Schedule</strong></li>
            <li>Configure the scan (same options as manual scans)</li>
            <li>Set the schedule:
              <ul className="list-disc list-inside ml-6 mt-2 text-gray-400">
                <li>Daily, Weekly, or Monthly</li>
                <li>Specific days and time</li>
                <li>Custom cron expression (advanced)</li>
              </ul>
            </li>
            <li>Enable notifications for completion</li>
            <li>Click <strong>Save Schedule</strong></li>
          </ol>

          <h3 className="text-lg font-medium text-cyan-400 mb-3">8.2 Recommended Schedule</h3>
          <table className="w-full text-gray-300 mb-4 text-sm">
            <thead>
              <tr className="border-b border-gray-700">
                <th className="text-left py-2 px-3">Environment</th>
                <th className="text-left py-2 px-3">Recommended Frequency</th>
              </tr>
            </thead>
            <tbody>
              <tr className="border-b border-gray-800">
                <td className="py-2 px-3">Production servers</td>
                <td className="py-2 px-3">Weekly (off-peak hours)</td>
              </tr>
              <tr className="border-b border-gray-800">
                <td className="py-2 px-3">Development systems</td>
                <td className="py-2 px-3">Daily</td>
              </tr>
              <tr className="border-b border-gray-800">
                <td className="py-2 px-3">External perimeter</td>
                <td className="py-2 px-3">Daily</td>
              </tr>
              <tr className="border-b border-gray-800">
                <td className="py-2 px-3">Full infrastructure</td>
                <td className="py-2 px-3">Monthly (comprehensive)</td>
              </tr>
            </tbody>
          </table>
        </div>

        {/* Step 9 */}
        <div id="step9" className="mb-12">
          <div className="flex items-center mb-4">
            <span className="bg-cyan-600 text-white text-sm font-bold px-3 py-1 rounded-full mr-3">Step 9</span>
            <h2 className="text-2xl font-semibold text-white">Configure Integrations</h2>
          </div>

          <p className="text-gray-300 mb-4">
            Connect HeroForge to your existing tools for streamlined workflows.
          </p>

          <h3 className="text-lg font-medium text-cyan-400 mb-3">9.1 Available Integrations</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
            <div className="bg-gray-800 rounded-lg p-4">
              <h4 className="text-white font-medium mb-2">Slack / Microsoft Teams</h4>
              <p className="text-gray-400 text-sm">Real-time alerts for scan completions, critical findings, and system events.</p>
            </div>
            <div className="bg-gray-800 rounded-lg p-4">
              <h4 className="text-white font-medium mb-2">JIRA</h4>
              <p className="text-gray-400 text-sm">Automatically create tickets from vulnerabilities with severity mapping.</p>
            </div>
            <div className="bg-gray-800 rounded-lg p-4">
              <h4 className="text-white font-medium mb-2">ServiceNow</h4>
              <p className="text-gray-400 text-sm">Create incidents and change requests from findings.</p>
            </div>
            <div className="bg-gray-800 rounded-lg p-4">
              <h4 className="text-white font-medium mb-2">SIEM (Splunk, Elastic)</h4>
              <p className="text-gray-400 text-sm">Export scan data to your SIEM for correlation and analysis.</p>
            </div>
          </div>

          <h3 className="text-lg font-medium text-cyan-400 mb-3">9.2 Set Up an Integration</h3>
          <ol className="list-decimal list-inside text-gray-300 mb-4 space-y-2 ml-4">
            <li>Go to <strong>Settings</strong> → <strong>Integrations</strong></li>
            <li>Click the integration you want to configure</li>
            <li>Enter the required credentials (API key, webhook URL, etc.)</li>
            <li>Configure notification preferences</li>
            <li>Test the connection</li>
            <li>Enable the integration</li>
          </ol>
        </div>

        {/* Step 10 */}
        <div id="step10" className="mb-12">
          <div className="flex items-center mb-4">
            <span className="bg-cyan-600 text-white text-sm font-bold px-3 py-1 rounded-full mr-3">Step 10</span>
            <h2 className="text-2xl font-semibold text-white">Run Compliance Checks</h2>
          </div>

          <p className="text-gray-300 mb-4">
            Assess your infrastructure against industry security frameworks.
          </p>

          <h3 className="text-lg font-medium text-cyan-400 mb-3">10.1 Supported Frameworks</h3>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-2 mb-6">
            {['CIS Benchmarks', 'NIST 800-53', 'PCI-DSS 4.0', 'HIPAA', 'SOC 2', 'ISO 27001', 'GDPR', 'NIST CSF'].map(framework => (
              <div key={framework} className="bg-gray-800 rounded px-3 py-2 text-center text-gray-300 text-sm">
                {framework}
              </div>
            ))}
          </div>
          <p className="text-gray-400 text-sm mb-4">
            Plus 37 additional frameworks for federal, industry, and international compliance.
          </p>

          <h3 className="text-lg font-medium text-cyan-400 mb-3">10.2 Run a Compliance Assessment</h3>
          <ol className="list-decimal list-inside text-gray-300 mb-4 space-y-2 ml-4">
            <li>Go to <strong>Compliance</strong> in the sidebar</li>
            <li>Select a framework (e.g., "PCI-DSS 4.0")</li>
            <li>Click <strong>Run Assessment</strong></li>
            <li>Select scope (all assets or specific groups)</li>
            <li>Review results showing pass/fail by control</li>
            <li>Generate compliance report</li>
          </ol>

          <h3 className="text-lg font-medium text-cyan-400 mb-3">10.3 Track Compliance Over Time</h3>
          <ul className="list-disc list-inside text-gray-300 mb-4 space-y-2 ml-4">
            <li>View compliance score trends</li>
            <li>Track improvement in specific controls</li>
            <li>Set compliance goals and alerts</li>
            <li>Schedule regular compliance assessments</li>
          </ul>
        </div>

        {/* Step 11 */}
        <div id="step11" className="mb-12">
          <div className="flex items-center mb-4">
            <span className="bg-cyan-600 text-white text-sm font-bold px-3 py-1 rounded-full mr-3">Step 11</span>
            <h2 className="text-2xl font-semibold text-white">Team & Organization Setup</h2>
          </div>

          <p className="text-gray-300 mb-4">
            For Professional and Enterprise tiers, set up your team for collaborative security operations.
          </p>

          <h3 className="text-lg font-medium text-cyan-400 mb-3">11.1 Invite Team Members</h3>
          <ol className="list-decimal list-inside text-gray-300 mb-4 space-y-2 ml-4">
            <li>Go to <strong>Settings</strong> → <strong>Team</strong></li>
            <li>Click <strong>Invite Member</strong></li>
            <li>Enter their email address</li>
            <li>Select their role:
              <ul className="list-disc list-inside ml-6 mt-2 text-gray-400">
                <li><strong>Admin:</strong> Full access including settings</li>
                <li><strong>Analyst:</strong> Can run scans and view all results</li>
                <li><strong>Viewer:</strong> Read-only access to reports</li>
              </ul>
            </li>
            <li>Send invitation</li>
          </ol>

          <h3 className="text-lg font-medium text-cyan-400 mb-3">11.2 Configure Organization Settings</h3>
          <ul className="list-disc list-inside text-gray-300 mb-4 space-y-2 ml-4">
            <li>Set organization name and logo</li>
            <li>Configure default scan settings</li>
            <li>Set up SSO (Enterprise tier)</li>
            <li>Define data retention policies</li>
            <li>Enable audit logging</li>
          </ul>
        </div>

        {/* Step 12 */}
        <div id="step12" className="mb-12">
          <div className="flex items-center mb-4">
            <span className="bg-cyan-600 text-white text-sm font-bold px-3 py-1 rounded-full mr-3">Step 12</span>
            <h2 className="text-2xl font-semibold text-white">Customer Relationship Management (CRM)</h2>
          </div>

          <p className="text-gray-300 mb-4">
            For security consultants and MSPs, HeroForge includes a full CRM to manage customers, engagements, contracts, and billing.
          </p>

          <h3 className="text-lg font-medium text-cyan-400 mb-3">12.1 Access the CRM</h3>
          <ol className="list-decimal list-inside text-gray-300 mb-4 space-y-2 ml-4">
            <li>Click <strong>CRM</strong> in the sidebar</li>
            <li>View the CRM Dashboard with key metrics</li>
            <li>See active customers, engagements, and revenue</li>
          </ol>

          <h3 className="text-lg font-medium text-cyan-400 mb-3">12.2 Manage Customers</h3>
          <ol className="list-decimal list-inside text-gray-300 mb-4 space-y-2 ml-4">
            <li>Go to <strong>CRM</strong> → <strong>Customers</strong></li>
            <li>Click <strong>+ Add Customer</strong></li>
            <li>Enter customer details:
              <ul className="list-disc list-inside ml-6 mt-2 text-gray-400">
                <li>Company name and contact information</li>
                <li>Industry and company size</li>
                <li>Primary contact person</li>
                <li>Billing address and payment terms</li>
              </ul>
            </li>
            <li>Save the customer profile</li>
          </ol>

          <h3 className="text-lg font-medium text-cyan-400 mb-3">12.3 Create Engagements</h3>
          <p className="text-gray-300 mb-4">
            Engagements represent security assessment projects for your customers.
          </p>
          <ol className="list-decimal list-inside text-gray-300 mb-4 space-y-2 ml-4">
            <li>Go to <strong>CRM</strong> → <strong>Engagements</strong></li>
            <li>Click <strong>+ New Engagement</strong></li>
            <li>Select the customer</li>
            <li>Define the scope:
              <ul className="list-disc list-inside ml-6 mt-2 text-gray-400">
                <li>Engagement type (Pentest, Vulnerability Assessment, Compliance Audit)</li>
                <li>Target systems and networks</li>
                <li>Start and end dates</li>
                <li>Pricing and billing terms</li>
              </ul>
            </li>
            <li>Assign team members to the engagement</li>
            <li>Link scans and reports to this engagement</li>
          </ol>

          <h3 className="text-lg font-medium text-cyan-400 mb-3">12.4 Manage Contracts</h3>
          <ol className="list-decimal list-inside text-gray-300 mb-4 space-y-2 ml-4">
            <li>Go to <strong>CRM</strong> → <strong>Contracts</strong></li>
            <li>Create contracts linked to customers and engagements</li>
            <li>Upload signed documents (MSA, SOW, NDA)</li>
            <li>Track contract status: Draft, Pending Signature, Active, Completed</li>
            <li>Set renewal reminders for recurring contracts</li>
          </ol>

          <h3 className="text-lg font-medium text-cyan-400 mb-3">12.5 Track Time</h3>
          <ol className="list-decimal list-inside text-gray-300 mb-4 space-y-2 ml-4">
            <li>Go to <strong>CRM</strong> → <strong>Time Tracking</strong></li>
            <li>Log hours against specific engagements</li>
            <li>Categorize time by activity (Testing, Reporting, Meetings)</li>
            <li>Generate time reports for invoicing</li>
            <li>Track budget vs. actual hours</li>
          </ol>

          <h3 className="text-lg font-medium text-cyan-400 mb-3">12.6 Customer Portal</h3>
          <p className="text-gray-300 mb-4">
            Give your customers secure access to their engagement data:
          </p>
          <ul className="list-disc list-inside text-gray-300 mb-4 space-y-2 ml-4">
            <li>Customers can view their scan results and reports</li>
            <li>Track vulnerability remediation progress</li>
            <li>Download deliverables</li>
            <li>Communicate with your team</li>
            <li>Access is scoped to only their data</li>
          </ul>
        </div>

        {/* Step 13 */}
        <div id="step13" className="mb-12">
          <div className="flex items-center mb-4">
            <span className="bg-cyan-600 text-white text-sm font-bold px-3 py-1 rounded-full mr-3">Step 13</span>
            <h2 className="text-2xl font-semibold text-white">Advanced Features</h2>
          </div>

          <p className="text-gray-300 mb-4">
            Once comfortable with the basics, explore HeroForge's advanced capabilities:
          </p>

          <div className="space-y-4">
            <div className="bg-gray-800 rounded-lg p-4">
              <h4 className="text-cyan-400 font-medium mb-2">Web Application Scanning</h4>
              <p className="text-gray-400 text-sm">Scan web applications for OWASP Top 10 vulnerabilities, including SQL injection, XSS, and authentication flaws.</p>
            </div>
            <div className="bg-gray-800 rounded-lg p-4">
              <h4 className="text-cyan-400 font-medium mb-2">Container Security</h4>
              <p className="text-gray-400 text-sm">Scan Docker images and Kubernetes clusters for misconfigurations and vulnerabilities.</p>
            </div>
            <div className="bg-gray-800 rounded-lg p-4">
              <h4 className="text-cyan-400 font-medium mb-2">Cloud Security</h4>
              <p className="text-gray-400 text-sm">Assess AWS, Azure, and GCP environments for security misconfigurations.</p>
            </div>
            <div className="bg-gray-800 rounded-lg p-4">
              <h4 className="text-cyan-400 font-medium mb-2">API Testing</h4>
              <p className="text-gray-400 text-sm">Test REST and GraphQL APIs for security issues and authentication bypasses.</p>
            </div>
            <div className="bg-gray-800 rounded-lg p-4">
              <h4 className="text-cyan-400 font-medium mb-2">CLI & Automation</h4>
              <p className="text-gray-400 text-sm">Use the command-line interface for scripted scans and CI/CD integration.</p>
            </div>
            <div className="bg-gray-800 rounded-lg p-4">
              <h4 className="text-cyan-400 font-medium mb-2">AI-Powered Analysis</h4>
              <p className="text-gray-400 text-sm">Get intelligent vulnerability prioritization and remediation recommendations.</p>
            </div>
          </div>
        </div>

        {/* Completion */}
        <div className="bg-gradient-to-r from-cyan-900/50 to-blue-900/50 border border-cyan-600 rounded-lg p-6 text-center">
          <h2 className="text-2xl font-bold text-white mb-3">Congratulations!</h2>
          <p className="text-gray-300 mb-4">
            You've completed the HeroForge Complete User Guide. You now have the knowledge to effectively
            use HeroForge for your security assessments.
          </p>
          <div className="flex flex-col sm:flex-row justify-center gap-4">
            <a href="/docs/cli" className="bg-gray-700 hover:bg-gray-600 text-white px-6 py-2 rounded-lg transition-colors">
              CLI Reference
            </a>
            <a href="/docs/faq" className="bg-gray-700 hover:bg-gray-600 text-white px-6 py-2 rounded-lg transition-colors">
              View FAQ
            </a>
            <a href="mailto:support@genialarchitect.io" className="bg-cyan-600 hover:bg-cyan-700 text-white px-6 py-2 rounded-lg transition-colors">
              Contact Support
            </a>
          </div>
        </div>
      </>
    ),
  },
};

// Article list component
const ArticleList: React.FC = () => {
  const categories = ['Basics', 'Features', 'Technical', 'Support'];

  return (
    <div className="max-w-4xl mx-auto">
      <h1 className="text-3xl font-bold text-white mb-2">Help Center</h1>
      <p className="text-gray-400 mb-8">Find answers, guides, and documentation to help you get the most out of HeroForge.</p>

      {/* Search bar */}
      <div className="mb-8">
        <input
          type="text"
          placeholder="Search documentation..."
          className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-cyan-500 focus:border-transparent"
        />
      </div>

      {/* Featured Guide */}
      <Link to="/docs/complete-guide" className="block bg-gradient-to-r from-cyan-900/50 via-blue-900/50 to-purple-900/50 border-2 border-cyan-500 rounded-xl p-6 mb-8 hover:border-cyan-400 transition-colors">
        <div className="flex items-center justify-between">
          <div>
            <span className="bg-cyan-600 text-white text-xs font-bold px-2 py-1 rounded uppercase">Recommended</span>
            <h3 className="text-xl font-bold text-white mt-2">Complete User Guide: From Setup to Mastery</h3>
            <p className="text-gray-300 mt-1">Follow our step-by-step guide covering everything from account creation to advanced features. Perfect for new users.</p>
          </div>
          <div className="hidden md:block text-6xl">📚</div>
        </div>
      </Link>

      {/* Quick links */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-12">
        <Link to="/docs/getting-started" className="bg-gradient-to-br from-cyan-900/50 to-blue-900/50 border border-cyan-700 rounded-lg p-6 hover:border-cyan-500 transition-colors">
          <div className="text-cyan-400 text-2xl mb-2">🚀</div>
          <h3 className="text-white font-semibold mb-1">Getting Started</h3>
          <p className="text-gray-400 text-sm">Quick intro guide.</p>
        </Link>
        <Link to="/docs/dashboard" className="bg-gradient-to-br from-green-900/50 to-teal-900/50 border border-green-700 rounded-lg p-6 hover:border-green-500 transition-colors">
          <div className="text-green-400 text-2xl mb-2">📊</div>
          <h3 className="text-white font-semibold mb-1">Dashboard Guide</h3>
          <p className="text-gray-400 text-sm">Navigate the interface.</p>
        </Link>
        <Link to="/docs/faq" className="bg-gradient-to-br from-purple-900/50 to-pink-900/50 border border-purple-700 rounded-lg p-6 hover:border-purple-500 transition-colors">
          <div className="text-purple-400 text-2xl mb-2">❓</div>
          <h3 className="text-white font-semibold mb-1">FAQ</h3>
          <p className="text-gray-400 text-sm">Common questions.</p>
        </Link>
        <Link to="/docs/troubleshooting" className="bg-gradient-to-br from-orange-900/50 to-red-900/50 border border-orange-700 rounded-lg p-6 hover:border-orange-500 transition-colors">
          <div className="text-orange-400 text-2xl mb-2">🔧</div>
          <h3 className="text-white font-semibold mb-1">Troubleshooting</h3>
          <p className="text-gray-400 text-sm">Fix common issues.</p>
        </Link>
      </div>

      {/* Articles by category */}
      {categories.map((category) => {
        const categoryArticles = Object.entries(articles).filter(
          ([, article]) => article.category === category
        );
        if (categoryArticles.length === 0) return null;

        return (
          <div key={category} className="mb-8">
            <h2 className="text-xl font-semibold text-white mb-4">{category}</h2>
            <div className="space-y-2">
              {categoryArticles.map(([slug, article]) => (
                <Link
                  key={slug}
                  to={`/docs/${slug}`}
                  className="block bg-gray-800 hover:bg-gray-750 rounded-lg p-4 transition-colors"
                >
                  <h3 className="text-cyan-400 font-medium">{article.title}</h3>
                </Link>
              ))}
            </div>
          </div>
        );
      })}

      {/* Contact support */}
      <div className="mt-12 bg-gray-800 rounded-lg p-6 text-center">
        <h2 className="text-xl font-semibold text-white mb-2">Can't find what you're looking for?</h2>
        <p className="text-gray-400 mb-4">Our support team is here to help.</p>
        <a
          href="mailto:support@genialarchitect.io"
          className="inline-block bg-cyan-600 hover:bg-cyan-700 text-white font-medium px-6 py-2 rounded-lg transition-colors"
        >
          Contact Support
        </a>
      </div>
    </div>
  );
};

// Single article view component
const ArticleView: React.FC<{ slug: string }> = ({ slug }) => {
  const navigate = useNavigate();
  const article = articles[slug];

  if (!article) {
    return (
      <div className="max-w-4xl mx-auto text-center py-12">
        <h1 className="text-2xl font-bold text-white mb-4">Article Not Found</h1>
        <p className="text-gray-400 mb-6">The article you're looking for doesn't exist.</p>
        <Link to="/docs" className="text-cyan-400 hover:underline">
          ← Back to Help Center
        </Link>
      </div>
    );
  }

  return (
    <div className="max-w-4xl mx-auto">
      {/* Breadcrumb */}
      <nav className="mb-6">
        <ol className="flex items-center space-x-2 text-sm">
          <li>
            <Link to="/docs" className="text-gray-400 hover:text-white">Help Center</Link>
          </li>
          <li className="text-gray-600">/</li>
          <li className="text-gray-400">{article.category}</li>
          <li className="text-gray-600">/</li>
          <li className="text-cyan-400">{article.title}</li>
        </ol>
      </nav>

      {/* Article header */}
      <header className="mb-8">
        <span className="inline-block bg-cyan-900/50 text-cyan-400 text-xs font-medium px-2 py-1 rounded mb-3">
          {article.category}
        </span>
        <h1 className="text-3xl font-bold text-white">{article.title}</h1>
      </header>

      {/* Article content */}
      <article className="prose prose-invert max-w-none">
        {article.content}
      </article>

      {/* Navigation footer */}
      <footer className="mt-12 pt-8 border-t border-gray-800">
        <div className="flex justify-between items-center">
          <button
            onClick={() => navigate(-1)}
            className="text-gray-400 hover:text-white transition-colors"
          >
            ← Back
          </button>
          <Link to="/docs" className="text-cyan-400 hover:underline">
            View all articles
          </Link>
        </div>

        {/* Helpful feedback */}
        <div className="mt-8 bg-gray-800 rounded-lg p-6 text-center">
          <p className="text-gray-300 mb-3">Was this article helpful?</p>
          <div className="flex justify-center space-x-4">
            <button className="bg-gray-700 hover:bg-gray-600 text-white px-4 py-2 rounded-lg transition-colors">
              👍 Yes
            </button>
            <button className="bg-gray-700 hover:bg-gray-600 text-white px-4 py-2 rounded-lg transition-colors">
              👎 No
            </button>
          </div>
        </div>
      </footer>
    </div>
  );
};

// Main DocsPage component
const DocsPage: React.FC = () => {
  const { slug } = useParams<{ slug?: string }>();

  return (
    <div className="min-h-screen bg-gray-900">
      {/* Header */}
      <header className="bg-gray-800 border-b border-gray-700">
        <div className="max-w-6xl mx-auto px-4 py-4 flex items-center justify-between">
          <Link to="/" className="flex items-center space-x-2">
            <span className="text-2xl font-bold text-cyan-400">HeroForge</span>
          </Link>
          <nav className="hidden md:flex items-center space-x-6">
            <Link to="/features" className="text-gray-300 hover:text-white">Features</Link>
            <Link to="/pricing" className="text-gray-300 hover:text-white">Pricing</Link>
            <Link to="/tools" className="text-gray-300 hover:text-white">Free Tools</Link>
            <Link to="/blog" className="text-gray-300 hover:text-white">Blog</Link>
            <Link to="/academy" className="text-gray-300 hover:text-white">Academy</Link>
            <Link to="/docs" className="text-cyan-400">Docs</Link>
            <Link to="/login" className="px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg">Sign In</Link>
          </nav>
        </div>
      </header>

      {/* Main content */}
      <main className="max-w-6xl mx-auto px-4 py-12">
        {slug ? <ArticleView slug={slug} /> : <ArticleList />}
      </main>

      {/* Footer */}
      <footer className="bg-gray-800 border-t border-gray-700 mt-16">
        <div className="max-w-6xl mx-auto px-4 py-8">
          <div className="flex flex-col md:flex-row justify-between items-center">
            <p className="text-gray-400 text-sm">
              © 2026 Genial Architect Cybersecurity Research Associates. All rights reserved.
            </p>
            <div className="flex space-x-6 mt-4 md:mt-0">
              <Link to="/terms" className="text-gray-400 hover:text-white text-sm">Terms</Link>
              <Link to="/privacy" className="text-gray-400 hover:text-white text-sm">Privacy</Link>
              <a href="mailto:support@genialarchitect.io" className="text-gray-400 hover:text-white text-sm">Contact</a>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default DocsPage;
