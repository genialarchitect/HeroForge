import React, { useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { Calendar, Clock, User, Tag, ArrowLeft, Search, ChevronRight } from 'lucide-react';

// Blog post type
interface BlogPost {
  slug: string;
  title: string;
  excerpt: string;
  content: React.ReactNode;
  author: string;
  date: string;
  readTime: string;
  category: string;
  tags: string[];
  featured?: boolean;
}

// Sample blog posts
const blogPosts: BlogPost[] = [
  {
    slug: 'cybersecurity-trends-2026',
    title: '5 Cybersecurity Trends Shaping 2026',
    excerpt: 'From AI-powered attacks to the collapse of perimeter security, these are the trends every security professional needs to watch this year.',
    author: 'Security Team',
    date: 'January 21, 2026',
    readTime: '7 min read',
    category: 'Research',
    tags: ['trends', 'ai', 'industry'],
    featured: true,
    content: (
      <>
        <p className="text-gray-300 text-lg mb-6">
          The cybersecurity landscape is evolving faster than ever. As we settle into 2026, several
          major trends are reshaping how organizations approach security. Here's what you need to know.
        </p>

        <h2 className="text-2xl font-bold text-white mt-8 mb-4">1. AI-Powered Attacks Go Mainstream</h2>
        <p className="text-gray-300 mb-4">
          What was experimental in 2024 is now standard operating procedure for threat actors. We're seeing
          sophisticated AI-generated phishing campaigns that adapt in real-time, polymorphic malware that
          rewrites itself to evade detection, and automated reconnaissance tools that can map entire
          networks in minutes.
        </p>
        <div className="bg-gray-800 rounded-lg p-6 my-6">
          <h3 className="text-lg font-semibold text-cyan-400 mb-3">Key Statistics:</h3>
          <ul className="list-disc list-inside text-gray-300 space-y-2">
            <li>AI-assisted attacks increased 340% year-over-year</li>
            <li>Average time from initial access to data exfiltration dropped to 4 hours</li>
            <li>Deepfake-based social engineering incidents up 500%</li>
          </ul>
        </div>
        <p className="text-gray-300 mb-4">
          The good news? AI-powered defense is maturing just as quickly. Tools like HeroForge now use
          machine learning to prioritize vulnerabilities based on your specific environment and threat
          landscape, not just CVSS scores.
        </p>

        <h2 className="text-2xl font-bold text-white mt-8 mb-4">2. Zero Trust Becomes Non-Negotiable</h2>
        <p className="text-gray-300 mb-4">
          The "trust but verify" model is officially dead. With remote work now permanent for most
          organizations and cloud-native architectures the norm, traditional perimeter-based security
          simply doesn't work anymore.
        </p>
        <p className="text-gray-300 mb-4">
          In 2026, zero trust isn't just a buzzword—it's a compliance requirement. New regulations
          in the EU and several US states now mandate zero trust architectures for organizations
          handling sensitive data.
        </p>
        <div className="bg-cyan-900/30 border border-cyan-600 rounded-lg p-4 my-6">
          <p className="text-cyan-200">
            <strong>Implementation Tip:</strong> Start with identity. Strong authentication (MFA everywhere,
            passwordless where possible) is the foundation of zero trust. Then move to micro-segmentation
            and continuous verification.
          </p>
        </div>

        <h2 className="text-2xl font-bold text-white mt-8 mb-4">3. Supply Chain Attacks Target the Long Tail</h2>
        <p className="text-gray-300 mb-4">
          After high-profile incidents like SolarWinds and the 2024 xz Utils backdoor, large vendors
          have hardened their security. Attackers have adapted by targeting smaller, less-scrutinized
          dependencies—the libraries and tools that nobody thinks about until they're compromised.
        </p>
        <p className="text-gray-300 mb-4">
          The software bill of materials (SBOM) isn't optional anymore. Organizations need complete
          visibility into every component in their software stack, from direct dependencies to
          transitive dependencies five levels deep.
        </p>
        <ul className="list-disc list-inside text-gray-300 space-y-2 mb-6">
          <li><strong>Open source hygiene:</strong> Automated scanning of all dependencies for known vulnerabilities</li>
          <li><strong>Vendor assessments:</strong> Regular security reviews of third-party providers</li>
          <li><strong>Build verification:</strong> Reproducible builds and signed artifacts</li>
        </ul>

        <h2 className="text-2xl font-bold text-white mt-8 mb-4">4. Regulatory Pressure Intensifies</h2>
        <p className="text-gray-300 mb-4">
          2026 marks the enforcement deadline for several major regulations. NIS2 is now fully
          enforceable across the EU, with penalties up to €10 million or 2% of global revenue.
          The SEC's new cybersecurity disclosure rules have teeth, and state-level privacy laws
          continue to proliferate.
        </p>
        <table className="w-full text-gray-300 mb-6">
          <thead>
            <tr className="border-b border-gray-700">
              <th className="text-left py-2 px-4">Regulation</th>
              <th className="text-left py-2 px-4">Scope</th>
              <th className="text-left py-2 px-4">Key Requirement</th>
            </tr>
          </thead>
          <tbody>
            <tr className="border-b border-gray-800">
              <td className="py-2 px-4">NIS2</td>
              <td className="py-2 px-4">EU essential services</td>
              <td className="py-2 px-4">24-hour incident reporting</td>
            </tr>
            <tr className="border-b border-gray-800">
              <td className="py-2 px-4">SEC Rules</td>
              <td className="py-2 px-4">US public companies</td>
              <td className="py-2 px-4">Material breach disclosure</td>
            </tr>
            <tr className="border-b border-gray-800">
              <td className="py-2 px-4">DORA</td>
              <td className="py-2 px-4">EU financial sector</td>
              <td className="py-2 px-4">ICT risk management</td>
            </tr>
          </tbody>
        </table>
        <p className="text-gray-300 mb-4">
          The silver lining: compliance frameworks are converging. Meeting one regulation often
          gets you most of the way to meeting others.
        </p>

        <h2 className="text-2xl font-bold text-white mt-8 mb-4">5. The Security Talent Crisis Reaches Breaking Point</h2>
        <p className="text-gray-300 mb-4">
          The cybersecurity workforce gap has grown to 4.8 million unfilled positions globally.
          Organizations can't hire their way out of this problem—they need to work smarter.
        </p>
        <p className="text-gray-300 mb-4">
          This is driving two major shifts:
        </p>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
          <div className="bg-gray-800 rounded-lg p-6">
            <h3 className="text-lg font-semibold text-cyan-400 mb-3">Automation & AI</h3>
            <p className="text-gray-300">
              Security teams are automating everything possible—vulnerability prioritization,
              alert triage, incident response playbooks. The goal is letting humans focus on
              decisions that require judgment.
            </p>
          </div>
          <div className="bg-gray-800 rounded-lg p-6">
            <h3 className="text-lg font-semibold text-purple-400 mb-3">Platform Consolidation</h3>
            <p className="text-gray-300">
              Organizations are moving away from point solutions toward integrated platforms.
              Fewer tools means less complexity and smaller teams can cover more ground.
            </p>
          </div>
        </div>

        <h2 className="text-2xl font-bold text-white mt-8 mb-4">What This Means for You</h2>
        <p className="text-gray-300 mb-4">
          If you're a security professional, 2026 is the year to:
        </p>
        <ol className="list-decimal list-inside text-gray-300 space-y-3 mb-6">
          <li><strong>Embrace AI defensively:</strong> If you're not using AI to help defend, you're already behind</li>
          <li><strong>Audit your supply chain:</strong> Know every dependency in your stack</li>
          <li><strong>Automate ruthlessly:</strong> Every manual process is a bottleneck</li>
          <li><strong>Get compliance-ready:</strong> New regulations are coming whether you're ready or not</li>
          <li><strong>Invest in your team:</strong> Retention matters more than hiring</li>
        </ol>

        <div className="bg-yellow-900/30 border border-yellow-600 rounded-lg p-4 my-6">
          <p className="text-yellow-200">
            <strong>Looking ahead:</strong> We'll be diving deeper into each of these trends throughout
            the year. Subscribe to our newsletter to stay informed.
          </p>
        </div>
      </>
    ),
  },
  {
    slug: 'getting-started-network-reconnaissance',
    title: 'Getting Started with Network Reconnaissance',
    excerpt: 'Learn the fundamentals of network reconnaissance and how to use HeroForge to discover assets, scan ports, and identify vulnerabilities in your infrastructure.',
    author: 'Security Team',
    date: 'January 20, 2026',
    readTime: '8 min read',
    category: 'How-To',
    tags: ['scanning', 'beginner', 'network'],
    featured: true,
    content: (
      <>
        <p className="text-gray-300 text-lg mb-6">
          Network reconnaissance is the first step in any security assessment. Understanding what's on your
          network is crucial for identifying potential vulnerabilities and attack vectors.
        </p>

        <h2 className="text-2xl font-bold text-white mt-8 mb-4">What is Network Reconnaissance?</h2>
        <p className="text-gray-300 mb-4">
          Network reconnaissance (or recon) is the process of discovering and gathering information about
          target systems on a network. This includes identifying live hosts, open ports, running services,
          and potential vulnerabilities.
        </p>

        <div className="bg-gray-800 rounded-lg p-6 my-6">
          <h3 className="text-lg font-semibold text-cyan-400 mb-3">Key Reconnaissance Activities:</h3>
          <ul className="list-disc list-inside text-gray-300 space-y-2">
            <li><strong>Host Discovery:</strong> Finding live systems on the network</li>
            <li><strong>Port Scanning:</strong> Identifying open ports on each host</li>
            <li><strong>Service Detection:</strong> Determining what services are running</li>
            <li><strong>OS Fingerprinting:</strong> Identifying operating systems</li>
            <li><strong>Vulnerability Scanning:</strong> Finding known security issues</li>
          </ul>
        </div>

        <h2 className="text-2xl font-bold text-white mt-8 mb-4">Getting Started with HeroForge</h2>
        <p className="text-gray-300 mb-4">
          HeroForge makes network reconnaissance simple and efficient. Here's how to run your first scan:
        </p>

        <h3 className="text-xl font-semibold text-white mt-6 mb-3">Step 1: Define Your Target</h3>
        <p className="text-gray-300 mb-4">
          You can scan individual hosts, IP ranges, or entire subnets:
        </p>
        <div className="bg-gray-900 rounded-lg p-4 font-mono text-sm mb-6">
          <p className="text-gray-400"># Single host</p>
          <p className="text-cyan-400">192.168.1.1</p>
          <p className="text-gray-400 mt-2"># IP range</p>
          <p className="text-cyan-400">192.168.1.1-254</p>
          <p className="text-gray-400 mt-2"># CIDR notation</p>
          <p className="text-cyan-400">192.168.1.0/24</p>
        </div>

        <h3 className="text-xl font-semibold text-white mt-6 mb-3">Step 2: Choose Your Scan Type</h3>
        <table className="w-full text-gray-300 mb-6">
          <thead>
            <tr className="border-b border-gray-700">
              <th className="text-left py-2 px-4">Scan Type</th>
              <th className="text-left py-2 px-4">Best For</th>
              <th className="text-left py-2 px-4">Speed</th>
            </tr>
          </thead>
          <tbody>
            <tr className="border-b border-gray-800">
              <td className="py-2 px-4">Quick Scan</td>
              <td className="py-2 px-4">Initial discovery, top 100 ports</td>
              <td className="py-2 px-4">Fast (1-5 min)</td>
            </tr>
            <tr className="border-b border-gray-800">
              <td className="py-2 px-4">Full Scan</td>
              <td className="py-2 px-4">Comprehensive assessment</td>
              <td className="py-2 px-4">Slow (30+ min)</td>
            </tr>
            <tr className="border-b border-gray-800">
              <td className="py-2 px-4">Stealth Scan</td>
              <td className="py-2 px-4">Avoiding detection</td>
              <td className="py-2 px-4">Medium</td>
            </tr>
          </tbody>
        </table>

        <h3 className="text-xl font-semibold text-white mt-6 mb-3">Step 3: Analyze Results</h3>
        <p className="text-gray-300 mb-4">
          Once your scan completes, you'll see a comprehensive view of discovered assets:
        </p>
        <ul className="list-disc list-inside text-gray-300 space-y-2 mb-6">
          <li>Live hosts with IP addresses and hostnames</li>
          <li>Open ports with service information</li>
          <li>Operating system detection results</li>
          <li>Potential vulnerabilities and CVE references</li>
        </ul>

        <div className="bg-yellow-900/30 border border-yellow-600 rounded-lg p-4 my-6">
          <p className="text-yellow-200">
            <strong>Important:</strong> Always ensure you have authorization before scanning any network.
            Unauthorized scanning may violate laws and regulations.
          </p>
        </div>

        <h2 className="text-2xl font-bold text-white mt-8 mb-4">Best Practices</h2>
        <ol className="list-decimal list-inside text-gray-300 space-y-3 mb-6">
          <li><strong>Start small:</strong> Begin with a single host before scanning entire subnets</li>
          <li><strong>Schedule off-peak:</strong> Run intensive scans during low-traffic periods</li>
          <li><strong>Document everything:</strong> Keep records of all scans for compliance</li>
          <li><strong>Verify findings:</strong> Manually confirm critical vulnerabilities</li>
          <li><strong>Scan regularly:</strong> Set up scheduled scans for continuous monitoring</li>
        </ol>

        <h2 className="text-2xl font-bold text-white mt-8 mb-4">Next Steps</h2>
        <p className="text-gray-300 mb-4">
          Now that you understand the basics, try these advanced topics:
        </p>
        <ul className="list-disc list-inside text-gray-300 space-y-2">
          <li><Link to="/docs/cli" className="text-cyan-400 hover:underline">Using the HeroForge CLI</Link></li>
          <li><Link to="/docs/dashboard" className="text-cyan-400 hover:underline">Navigating the Dashboard</Link></li>
          <li><Link to="/academy" className="text-cyan-400 hover:underline">Take the Network Scanning Course</Link></li>
        </ul>
      </>
    ),
  },
  {
    slug: 'understanding-cvss-scores',
    title: 'Understanding CVSS Scores: A Complete Guide',
    excerpt: 'CVSS scores are everywhere in vulnerability management, but what do they really mean? Learn how to interpret and prioritize vulnerabilities using CVSS.',
    author: 'Security Team',
    date: 'January 19, 2026',
    readTime: '10 min read',
    category: 'Educational',
    tags: ['vulnerabilities', 'cvss', 'risk'],
    content: (
      <>
        <p className="text-gray-300 text-lg mb-6">
          The Common Vulnerability Scoring System (CVSS) is the industry standard for rating the severity
          of security vulnerabilities. Understanding CVSS is essential for effective vulnerability management.
        </p>

        <h2 className="text-2xl font-bold text-white mt-8 mb-4">What is CVSS?</h2>
        <p className="text-gray-300 mb-4">
          CVSS provides a numerical score from 0.0 to 10.0 that represents the severity of a vulnerability.
          The current version (CVSS 3.1) considers multiple factors including how the vulnerability can be
          exploited and its potential impact.
        </p>

        <h2 className="text-2xl font-bold text-white mt-8 mb-4">Severity Ratings</h2>
        <div className="space-y-3 mb-6">
          <div className="flex items-center bg-gray-800 rounded-lg p-4">
            <span className="w-24 text-red-500 font-bold">Critical</span>
            <span className="text-gray-300 flex-1">9.0 - 10.0</span>
            <span className="text-gray-400">Immediate action required</span>
          </div>
          <div className="flex items-center bg-gray-800 rounded-lg p-4">
            <span className="w-24 text-orange-500 font-bold">High</span>
            <span className="text-gray-300 flex-1">7.0 - 8.9</span>
            <span className="text-gray-400">Address within days</span>
          </div>
          <div className="flex items-center bg-gray-800 rounded-lg p-4">
            <span className="w-24 text-yellow-500 font-bold">Medium</span>
            <span className="text-gray-300 flex-1">4.0 - 6.9</span>
            <span className="text-gray-400">Plan for remediation</span>
          </div>
          <div className="flex items-center bg-gray-800 rounded-lg p-4">
            <span className="w-24 text-blue-500 font-bold">Low</span>
            <span className="text-gray-300 flex-1">0.1 - 3.9</span>
            <span className="text-gray-400">Address when convenient</span>
          </div>
        </div>

        <h2 className="text-2xl font-bold text-white mt-8 mb-4">CVSS Metric Groups</h2>

        <h3 className="text-xl font-semibold text-cyan-400 mt-6 mb-3">Base Metrics</h3>
        <p className="text-gray-300 mb-4">
          These describe the intrinsic characteristics of a vulnerability:
        </p>
        <ul className="list-disc list-inside text-gray-300 space-y-2 mb-6">
          <li><strong>Attack Vector (AV):</strong> How the vulnerability is exploited (Network, Adjacent, Local, Physical)</li>
          <li><strong>Attack Complexity (AC):</strong> Conditions beyond attacker control (Low, High)</li>
          <li><strong>Privileges Required (PR):</strong> Level of access needed (None, Low, High)</li>
          <li><strong>User Interaction (UI):</strong> Whether a user must take action (None, Required)</li>
          <li><strong>Scope (S):</strong> Whether impact extends beyond the vulnerable component</li>
          <li><strong>Confidentiality Impact (C):</strong> Impact on data confidentiality</li>
          <li><strong>Integrity Impact (I):</strong> Impact on data integrity</li>
          <li><strong>Availability Impact (A):</strong> Impact on system availability</li>
        </ul>

        <h3 className="text-xl font-semibold text-cyan-400 mt-6 mb-3">Temporal Metrics</h3>
        <p className="text-gray-300 mb-4">
          These change over time:
        </p>
        <ul className="list-disc list-inside text-gray-300 space-y-2 mb-6">
          <li><strong>Exploit Code Maturity:</strong> Availability of exploit code</li>
          <li><strong>Remediation Level:</strong> Availability of fixes</li>
          <li><strong>Report Confidence:</strong> Confidence in the vulnerability details</li>
        </ul>

        <h2 className="text-2xl font-bold text-white mt-8 mb-4">Beyond CVSS: Contextual Prioritization</h2>
        <p className="text-gray-300 mb-4">
          While CVSS is valuable, it shouldn't be your only prioritization factor. Consider:
        </p>
        <ul className="list-disc list-inside text-gray-300 space-y-2 mb-6">
          <li><strong>Asset criticality:</strong> A medium vuln on a critical server may be more urgent than a high vuln on a test system</li>
          <li><strong>Exploitability:</strong> Is there active exploitation in the wild?</li>
          <li><strong>Compensating controls:</strong> Do you have mitigations in place?</li>
          <li><strong>Business context:</strong> What's the potential business impact?</li>
        </ul>

        <div className="bg-cyan-900/30 border border-cyan-600 rounded-lg p-4 my-6">
          <p className="text-cyan-200">
            <strong>HeroForge Tip:</strong> Our AI-powered prioritization considers CVSS scores alongside
            asset context and threat intelligence to give you actionable recommendations.
          </p>
        </div>
      </>
    ),
  },
  {
    slug: 'heroforge-vs-nessus-comparison',
    title: 'HeroForge vs Nessus: An Honest Comparison',
    excerpt: 'Comparing HeroForge with Tenable Nessus, one of the industry\'s most established vulnerability scanners. Which is right for your organization?',
    author: 'Security Team',
    date: 'January 18, 2026',
    readTime: '12 min read',
    category: 'Comparison',
    tags: ['comparison', 'nessus', 'enterprise'],
    content: (
      <>
        <p className="text-gray-300 text-lg mb-6">
          Choosing the right vulnerability scanner is crucial for your security program. Let's compare
          HeroForge with Tenable Nessus, one of the most well-known scanners in the industry.
        </p>

        <h2 className="text-2xl font-bold text-white mt-8 mb-4">Quick Comparison</h2>
        <table className="w-full text-gray-300 mb-6">
          <thead>
            <tr className="border-b border-gray-700">
              <th className="text-left py-3 px-4">Feature</th>
              <th className="text-left py-3 px-4">HeroForge</th>
              <th className="text-left py-3 px-4">Nessus Pro</th>
            </tr>
          </thead>
          <tbody>
            <tr className="border-b border-gray-800">
              <td className="py-3 px-4">Starting Price</td>
              <td className="py-3 px-4 text-green-400">Free tier available</td>
              <td className="py-3 px-4">$3,590/year</td>
            </tr>
            <tr className="border-b border-gray-800">
              <td className="py-3 px-4">Network Scanning</td>
              <td className="py-3 px-4">Yes</td>
              <td className="py-3 px-4">Yes</td>
            </tr>
            <tr className="border-b border-gray-800">
              <td className="py-3 px-4">Web App Scanning</td>
              <td className="py-3 px-4">Yes</td>
              <td className="py-3 px-4">Limited</td>
            </tr>
            <tr className="border-b border-gray-800">
              <td className="py-3 px-4">Cloud Security</td>
              <td className="py-3 px-4">AWS, Azure, GCP</td>
              <td className="py-3 px-4">Requires Tenable.io</td>
            </tr>
            <tr className="border-b border-gray-800">
              <td className="py-3 px-4">CRM Integration</td>
              <td className="py-3 px-4 text-green-400">Built-in</td>
              <td className="py-3 px-4">No</td>
            </tr>
            <tr className="border-b border-gray-800">
              <td className="py-3 px-4">AI Copilot</td>
              <td className="py-3 px-4 text-green-400">Yes</td>
              <td className="py-3 px-4">No</td>
            </tr>
            <tr className="border-b border-gray-800">
              <td className="py-3 px-4">Compliance Frameworks</td>
              <td className="py-3 px-4">45+</td>
              <td className="py-3 px-4">20+</td>
            </tr>
            <tr className="border-b border-gray-800">
              <td className="py-3 px-4">Deployment</td>
              <td className="py-3 px-4">Cloud & Self-hosted</td>
              <td className="py-3 px-4">Self-hosted only</td>
            </tr>
          </tbody>
        </table>

        <h2 className="text-2xl font-bold text-white mt-8 mb-4">Where Nessus Excels</h2>
        <ul className="list-disc list-inside text-gray-300 space-y-2 mb-6">
          <li><strong>Plugin library:</strong> 180,000+ plugins built over 20+ years</li>
          <li><strong>Brand recognition:</strong> Industry standard, widely known</li>
          <li><strong>Credentialed scanning:</strong> Deep authenticated scans</li>
          <li><strong>Audit files:</strong> Extensive compliance audit templates</li>
        </ul>

        <h2 className="text-2xl font-bold text-white mt-8 mb-4">Where HeroForge Excels</h2>
        <ul className="list-disc list-inside text-gray-300 space-y-2 mb-6">
          <li><strong>Modern UX:</strong> Clean, intuitive interface vs. dated Nessus UI</li>
          <li><strong>Integrated workflow:</strong> CRM + scanning + reporting in one platform</li>
          <li><strong>AI-powered:</strong> Intelligent prioritization and recommendations</li>
          <li><strong>Pricing:</strong> Free tier and affordable plans for SMBs</li>
          <li><strong>Real-time:</strong> WebSocket-based live scan updates</li>
          <li><strong>API-first:</strong> Modern REST API and SDKs</li>
        </ul>

        <h2 className="text-2xl font-bold text-white mt-8 mb-4">Who Should Choose What?</h2>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
          <div className="bg-gray-800 rounded-lg p-6">
            <h3 className="text-lg font-semibold text-cyan-400 mb-3">Choose HeroForge If:</h3>
            <ul className="list-disc list-inside text-gray-300 space-y-2">
              <li>You're a security consultant or MSP</li>
              <li>You need CRM + scanning together</li>
              <li>You want modern UI/UX</li>
              <li>Budget is a concern</li>
              <li>You value AI-powered insights</li>
            </ul>
          </div>
          <div className="bg-gray-800 rounded-lg p-6">
            <h3 className="text-lg font-semibold text-purple-400 mb-3">Choose Nessus If:</h3>
            <ul className="list-disc list-inside text-gray-300 space-y-2">
              <li>You need maximum plugin coverage</li>
              <li>Brand recognition matters for audits</li>
              <li>You're already in the Tenable ecosystem</li>
              <li>You need specific compliance audits</li>
            </ul>
          </div>
        </div>

        <h2 className="text-2xl font-bold text-white mt-8 mb-4">The Verdict</h2>
        <p className="text-gray-300 mb-4">
          Both are excellent tools. Nessus has decades of plugin development behind it, making it the
          safe choice for enterprises with specific audit requirements. HeroForge is the modern alternative
          that combines multiple tools into one platform with a significantly better user experience.
        </p>
        <p className="text-gray-300">
          For security consultants and growing organizations, HeroForge offers better value. For large
          enterprises already invested in Tenable, Nessus may be the path of least resistance.
        </p>
      </>
    ),
  },
  {
    slug: 'top-10-vulnerabilities-2025',
    title: 'Top 10 Vulnerabilities We Found in 2025',
    excerpt: 'Based on thousands of scans, here are the most common vulnerabilities we discovered in production environments last year.',
    author: 'Security Research',
    date: 'January 17, 2026',
    readTime: '15 min read',
    category: 'Research',
    tags: ['research', 'vulnerabilities', 'statistics'],
    content: (
      <>
        <p className="text-gray-300 text-lg mb-6">
          We analyzed data from thousands of scans conducted through HeroForge in 2025 to identify
          the most common vulnerabilities affecting organizations. Here's what we found.
        </p>

        <div className="bg-gray-800 rounded-lg p-6 my-6">
          <h3 className="text-lg font-semibold text-white mb-3">Key Statistics</h3>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-center">
            <div>
              <div className="text-3xl font-bold text-cyan-400">47%</div>
              <div className="text-gray-400 text-sm">Had Critical Vulns</div>
            </div>
            <div>
              <div className="text-3xl font-bold text-cyan-400">89%</div>
              <div className="text-gray-400 text-sm">Had Outdated Software</div>
            </div>
            <div>
              <div className="text-3xl font-bold text-cyan-400">31%</div>
              <div className="text-gray-400 text-sm">Had Default Creds</div>
            </div>
            <div>
              <div className="text-3xl font-bold text-cyan-400">72%</div>
              <div className="text-gray-400 text-sm">Missing Patches</div>
            </div>
          </div>
        </div>

        <h2 className="text-2xl font-bold text-white mt-8 mb-4">The Top 10</h2>

        <div className="space-y-6">
          <div className="bg-gray-800 rounded-lg p-6">
            <div className="flex items-center mb-3">
              <span className="bg-red-600 text-white text-lg font-bold w-8 h-8 rounded-full flex items-center justify-center mr-3">1</span>
              <h3 className="text-xl font-semibold text-white">Outdated SSL/TLS Configurations</h3>
            </div>
            <p className="text-gray-300 mb-2">Found in <strong>67%</strong> of scans</p>
            <p className="text-gray-400">Weak cipher suites, deprecated TLS versions, and expired certificates remain the most common finding.</p>
          </div>

          <div className="bg-gray-800 rounded-lg p-6">
            <div className="flex items-center mb-3">
              <span className="bg-red-600 text-white text-lg font-bold w-8 h-8 rounded-full flex items-center justify-center mr-3">2</span>
              <h3 className="text-xl font-semibold text-white">Missing Security Headers</h3>
            </div>
            <p className="text-gray-300 mb-2">Found in <strong>61%</strong> of scans</p>
            <p className="text-gray-400">X-Frame-Options, Content-Security-Policy, and HSTS headers frequently missing from web applications.</p>
          </div>

          <div className="bg-gray-800 rounded-lg p-6">
            <div className="flex items-center mb-3">
              <span className="bg-orange-600 text-white text-lg font-bold w-8 h-8 rounded-full flex items-center justify-center mr-3">3</span>
              <h3 className="text-xl font-semibold text-white">Unpatched Known Vulnerabilities</h3>
            </div>
            <p className="text-gray-300 mb-2">Found in <strong>54%</strong> of scans</p>
            <p className="text-gray-400">CVEs with available patches that haven't been applied, often months or years old.</p>
          </div>

          <div className="bg-gray-800 rounded-lg p-6">
            <div className="flex items-center mb-3">
              <span className="bg-orange-600 text-white text-lg font-bold w-8 h-8 rounded-full flex items-center justify-center mr-3">4</span>
              <h3 className="text-xl font-semibold text-white">Default or Weak Credentials</h3>
            </div>
            <p className="text-gray-300 mb-2">Found in <strong>31%</strong> of scans</p>
            <p className="text-gray-400">Admin panels, databases, and network devices with factory default or easily guessable passwords.</p>
          </div>

          <div className="bg-gray-800 rounded-lg p-6">
            <div className="flex items-center mb-3">
              <span className="bg-orange-600 text-white text-lg font-bold w-8 h-8 rounded-full flex items-center justify-center mr-3">5</span>
              <h3 className="text-xl font-semibold text-white">Open Database Ports</h3>
            </div>
            <p className="text-gray-300 mb-2">Found in <strong>28%</strong> of scans</p>
            <p className="text-gray-400">MySQL, PostgreSQL, MongoDB, and Redis exposed to the internet without authentication.</p>
          </div>
        </div>

        <p className="text-gray-400 text-center my-8">... and 5 more vulnerabilities detailed in the full report</p>

        <div className="bg-cyan-900/30 border border-cyan-600 rounded-lg p-6 text-center">
          <h3 className="text-xl font-semibold text-white mb-2">Get the Full Report</h3>
          <p className="text-gray-300 mb-4">Download our complete 2025 Vulnerability Landscape Report with detailed statistics and remediation guidance.</p>
          <button className="bg-cyan-600 hover:bg-cyan-700 text-white font-medium px-6 py-2 rounded-lg transition-colors">
            Download Report (PDF)
          </button>
        </div>
      </>
    ),
  },
];

// Categories for filtering
const categories = ['All', 'How-To', 'Educational', 'Comparison', 'Research', 'Product'];

// Blog list component
const BlogList: React.FC = () => {
  const [selectedCategory, setSelectedCategory] = useState('All');
  const [searchQuery, setSearchQuery] = useState('');

  const filteredPosts = blogPosts.filter(post => {
    const matchesCategory = selectedCategory === 'All' || post.category === selectedCategory;
    const matchesSearch = post.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
                         post.excerpt.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesCategory && matchesSearch;
  });

  const featuredPosts = blogPosts.filter(post => post.featured);

  return (
    <div className="max-w-6xl mx-auto">
      {/* Hero Section */}
      <div className="text-center mb-12">
        <h1 className="text-4xl font-bold text-white mb-4">Security Blog</h1>
        <p className="text-xl text-gray-400 max-w-2xl mx-auto">
          Insights, tutorials, and research from the HeroForge security team.
          Learn best practices for vulnerability management and security assessments.
        </p>
      </div>

      {/* Search */}
      <div className="relative mb-8">
        <Search className="absolute left-4 top-1/2 transform -translate-y-1/2 text-gray-500 w-5 h-5" />
        <input
          type="text"
          placeholder="Search articles..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          className="w-full bg-gray-800 border border-gray-700 rounded-lg pl-12 pr-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-cyan-500"
        />
      </div>

      {/* Categories */}
      <div className="flex flex-wrap gap-2 mb-8">
        {categories.map(category => (
          <button
            key={category}
            onClick={() => setSelectedCategory(category)}
            className={`px-4 py-2 rounded-full text-sm font-medium transition-colors ${
              selectedCategory === category
                ? 'bg-cyan-600 text-white'
                : 'bg-gray-800 text-gray-300 hover:bg-gray-700'
            }`}
          >
            {category}
          </button>
        ))}
      </div>

      {/* Featured Posts */}
      {selectedCategory === 'All' && searchQuery === '' && (
        <div className="mb-12">
          <h2 className="text-2xl font-bold text-white mb-6">Featured Articles</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {featuredPosts.map(post => (
              <Link
                key={post.slug}
                to={`/blog/${post.slug}`}
                className="bg-gradient-to-br from-cyan-900/30 to-blue-900/30 border border-cyan-700 rounded-xl p-6 hover:border-cyan-500 transition-colors"
              >
                <span className="bg-cyan-600 text-white text-xs font-bold px-2 py-1 rounded">Featured</span>
                <h3 className="text-xl font-bold text-white mt-3 mb-2">{post.title}</h3>
                <p className="text-gray-400 mb-4">{post.excerpt}</p>
                <div className="flex items-center text-sm text-gray-500">
                  <Calendar className="w-4 h-4 mr-1" />
                  <span>{post.date}</span>
                  <span className="mx-2">•</span>
                  <Clock className="w-4 h-4 mr-1" />
                  <span>{post.readTime}</span>
                </div>
              </Link>
            ))}
          </div>
        </div>
      )}

      {/* All Posts */}
      <div>
        <h2 className="text-2xl font-bold text-white mb-6">
          {selectedCategory === 'All' ? 'All Articles' : selectedCategory}
        </h2>
        <div className="space-y-6">
          {filteredPosts.map(post => (
            <Link
              key={post.slug}
              to={`/blog/${post.slug}`}
              className="block bg-gray-800 hover:bg-gray-750 rounded-xl p-6 transition-colors"
            >
              <div className="flex flex-col md:flex-row md:items-center md:justify-between">
                <div className="flex-1">
                  <div className="flex items-center gap-2 mb-2">
                    <span className="bg-gray-700 text-gray-300 text-xs font-medium px-2 py-1 rounded">
                      {post.category}
                    </span>
                    {post.tags.slice(0, 2).map(tag => (
                      <span key={tag} className="text-xs text-gray-500">#{tag}</span>
                    ))}
                  </div>
                  <h3 className="text-xl font-semibold text-white mb-2">{post.title}</h3>
                  <p className="text-gray-400 mb-3">{post.excerpt}</p>
                  <div className="flex items-center text-sm text-gray-500">
                    <User className="w-4 h-4 mr-1" />
                    <span>{post.author}</span>
                    <span className="mx-2">•</span>
                    <Calendar className="w-4 h-4 mr-1" />
                    <span>{post.date}</span>
                    <span className="mx-2">•</span>
                    <Clock className="w-4 h-4 mr-1" />
                    <span>{post.readTime}</span>
                  </div>
                </div>
                <ChevronRight className="hidden md:block w-6 h-6 text-gray-600 ml-4" />
              </div>
            </Link>
          ))}
        </div>

        {filteredPosts.length === 0 && (
          <div className="text-center py-12">
            <p className="text-gray-400">No articles found matching your criteria.</p>
          </div>
        )}
      </div>

      {/* Newsletter Signup */}
      <div className="mt-16 bg-gradient-to-r from-cyan-900/50 to-purple-900/50 border border-cyan-700 rounded-xl p-8 text-center">
        <h2 className="text-2xl font-bold text-white mb-2">Stay Updated</h2>
        <p className="text-gray-300 mb-6">Get the latest security insights delivered to your inbox.</p>
        <div className="flex flex-col sm:flex-row gap-3 max-w-md mx-auto">
          <input
            type="email"
            placeholder="Enter your email"
            className="flex-1 bg-gray-800 border border-gray-600 rounded-lg px-4 py-2 text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-cyan-500"
          />
          <button className="bg-cyan-600 hover:bg-cyan-700 text-white font-medium px-6 py-2 rounded-lg transition-colors">
            Subscribe
          </button>
        </div>
      </div>
    </div>
  );
};

// Single post view
const BlogPost: React.FC<{ slug: string }> = ({ slug }) => {
  const post = blogPosts.find(p => p.slug === slug);

  if (!post) {
    return (
      <div className="max-w-4xl mx-auto text-center py-12">
        <h1 className="text-2xl font-bold text-white mb-4">Article Not Found</h1>
        <p className="text-gray-400 mb-6">The article you're looking for doesn't exist.</p>
        <Link to="/blog" className="text-cyan-400 hover:underline">
          ← Back to Blog
        </Link>
      </div>
    );
  }

  return (
    <div className="max-w-4xl mx-auto">
      {/* Back link */}
      <Link to="/blog" className="inline-flex items-center text-gray-400 hover:text-white mb-8">
        <ArrowLeft className="w-4 h-4 mr-2" />
        Back to Blog
      </Link>

      {/* Article header */}
      <header className="mb-8">
        <div className="flex items-center gap-2 mb-4">
          <span className="bg-cyan-900/50 text-cyan-400 text-sm font-medium px-3 py-1 rounded">
            {post.category}
          </span>
          {post.tags.map(tag => (
            <span key={tag} className="text-sm text-gray-500">#{tag}</span>
          ))}
        </div>
        <h1 className="text-4xl font-bold text-white mb-4">{post.title}</h1>
        <div className="flex items-center text-gray-400">
          <User className="w-4 h-4 mr-2" />
          <span>{post.author}</span>
          <span className="mx-3">•</span>
          <Calendar className="w-4 h-4 mr-2" />
          <span>{post.date}</span>
          <span className="mx-3">•</span>
          <Clock className="w-4 h-4 mr-2" />
          <span>{post.readTime}</span>
        </div>
      </header>

      {/* Article content */}
      <article className="prose prose-invert prose-lg max-w-none">
        {post.content}
      </article>

      {/* Share & Tags */}
      <footer className="mt-12 pt-8 border-t border-gray-800">
        <div className="flex flex-wrap items-center gap-2 mb-8">
          <Tag className="w-4 h-4 text-gray-500" />
          {post.tags.map(tag => (
            <span key={tag} className="bg-gray-800 text-gray-300 text-sm px-3 py-1 rounded-full">
              {tag}
            </span>
          ))}
        </div>

        {/* Related Posts */}
        <div className="bg-gray-800 rounded-xl p-6">
          <h3 className="text-lg font-semibold text-white mb-4">Related Articles</h3>
          <div className="space-y-3">
            {blogPosts.filter(p => p.slug !== slug).slice(0, 3).map(p => (
              <Link
                key={p.slug}
                to={`/blog/${p.slug}`}
                className="block text-cyan-400 hover:text-cyan-300"
              >
                {p.title}
              </Link>
            ))}
          </div>
        </div>
      </footer>
    </div>
  );
};

// Main BlogPage component
const BlogPage: React.FC = () => {
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
            <Link to="/blog" className="text-cyan-400">Blog</Link>
            <Link to="/academy" className="text-gray-300 hover:text-white">Academy</Link>
            <Link to="/docs" className="text-gray-300 hover:text-white">Docs</Link>
            <Link to="/login" className="px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg">Sign In</Link>
          </nav>
        </div>
      </header>

      {/* Main content */}
      <main className="max-w-6xl mx-auto px-4 py-12">
        {slug ? <BlogPost slug={slug} /> : <BlogList />}
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
              <Link to="/docs" className="text-gray-400 hover:text-white text-sm">Documentation</Link>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default BlogPage;
