import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import {
  Shield,
  Network,
  Globe,
  Lock,
  Search,
  FileText,
  BarChart3,
  Bell,
  Target,
  Server,
  Cloud,
  Key,
  MonitorCheck,
  Users,
  Smartphone,
  Brain,
  Sparkles,
  Zap,
  Eye,
  AlertTriangle,
  Database,
  Activity,
  Cpu,
  Radio,
  Wifi,
  Box,
  GitBranch,
  FileCode,
  Bug,
  Crosshair,
  Layers,
  Settings,
  Plug,
  Terminal,
  Webhook,
  Clock,
  Calendar,
  Award,
  ArrowRight,
  Check,
  ChevronDown,
  ChevronUp,
  Building2
} from 'lucide-react';

interface FeatureCategory {
  id: string;
  name: string;
  icon: React.ReactNode;
  color: string;
  description: string;
  features: Feature[];
}

interface Feature {
  name: string;
  description: string;
  tier?: string;
}

const FeaturesPage: React.FC = () => {
  const [expandedCategory, setExpandedCategory] = useState<string | null>('red-team');

  const categories: FeatureCategory[] = [
    {
      id: 'red-team',
      name: 'Red Team (Offensive Security)',
      icon: <Target className="w-6 h-6" />,
      color: 'red',
      description: 'Comprehensive offensive security testing capabilities for penetration testing and vulnerability assessment.',
      features: [
        { name: 'Network Scanning', description: 'TCP/UDP port scanning with service detection and OS fingerprinting' },
        { name: 'Web Application Testing', description: 'XSS, SQLi, CSRF, SSRF detection with AI-driven crawling' },
        { name: 'API Security Testing', description: 'REST/GraphQL endpoint discovery and vulnerability scanning' },
        { name: 'SSL/TLS Analysis', description: 'Certificate grading, cipher analysis, and vulnerability detection' },
        { name: 'DNS Reconnaissance', description: 'Subdomain enumeration, zone transfers, and DNS analytics' },
        { name: 'Active Directory Assessment', description: 'LDAP enumeration, Kerberoasting, privilege escalation paths' },
        { name: 'Cloud Security Scanning', description: 'AWS, Azure, GCP configuration auditing and misconfiguration detection' },
        { name: 'Container Security', description: 'Docker and Kubernetes vulnerability scanning and hardening' },
        { name: 'Exploitation Framework', description: 'Credential testing, password spraying, and post-exploitation tools' },
        { name: 'Privilege Escalation', description: 'Linux/Windows privesc detection and exploitation paths' },
        { name: 'Wireless Security', description: 'WiFi network assessment and rogue access point detection' },
        { name: 'Phishing Campaigns', description: 'Email phishing simulation with click tracking and reporting' },
        { name: 'C2 Framework', description: 'Custom command and control infrastructure for red team operations' },
        { name: 'Nuclei Integration', description: 'Template-based vulnerability scanning with 5000+ templates' },
        { name: 'BloodHound Integration', description: 'Active Directory attack path visualization and analysis' },
        { name: 'Attack Simulation', description: 'MITRE ATT&CK-based breach and attack simulation' },
      ]
    },
    {
      id: 'blue-team',
      name: 'Blue Team (Defensive Security)',
      icon: <Shield className="w-6 h-6" />,
      color: 'blue',
      description: 'Defensive security operations including SIEM, detection engineering, and incident response.',
      features: [
        { name: 'SIEM Integration', description: 'Log ingestion, correlation engine, and alerting for Splunk, Elasticsearch, Syslog' },
        { name: 'Detection Engineering', description: 'Sigma and YARA rule creation, testing, and deployment' },
        { name: 'Incident Response', description: 'Automated playbooks, case management, and evidence collection' },
        { name: 'Threat Hunting', description: 'Hypothesis-driven hunting with behavior analytics' },
        { name: 'Forensics', description: 'Digital forensics toolkit with timeline analysis and artifact collection' },
        { name: 'Traffic Analysis', description: 'Network packet inspection and anomaly detection' },
        { name: 'NetFlow Analysis', description: 'Flow-based traffic analysis for network visibility' },
        { name: 'DNS Analytics', description: 'DNS query analysis for threat detection and data exfiltration' },
        { name: 'UEBA', description: 'User and Entity Behavior Analytics for insider threat detection' },
        { name: 'Malware Analysis', description: 'Sandbox analysis with behavioral detection' },
        { name: 'Binary Analysis', description: 'PE/ELF/Mach-O parsing with entropy analysis' },
      ]
    },
    {
      id: 'purple-team',
      name: 'Purple Team (Collaborative)',
      icon: <Layers className="w-6 h-6" />,
      color: 'purple',
      description: 'Unified red and blue team exercises with real-time collaboration and knowledge sharing.',
      features: [
        { name: 'Attack-Defense Exercises', description: 'Coordinated red/blue team exercises with real-time feedback' },
        { name: 'Detection Validation', description: 'Validate blue team detections against real attack techniques' },
        { name: 'Gap Analysis', description: 'Identify coverage gaps between attacks and detections' },
        { name: 'Continuous Improvement', description: 'Track improvement metrics over time' },
        { name: 'Knowledge Base', description: 'Shared repository of TTPs and defenses' },
      ]
    },
    {
      id: 'green-team',
      name: 'Green Team (SOC Operations)',
      icon: <Eye className="w-6 h-6" />,
      color: 'green',
      description: 'Security Operations Center management including SOAR playbooks and case management.',
      features: [
        { name: 'SOAR Playbooks', description: 'Automated security orchestration and response workflows' },
        { name: 'Case Management', description: 'Security incident tracking with SLA management' },
        { name: 'Alert Triage', description: 'AI-assisted alert prioritization and enrichment' },
        { name: 'Threat Intel Automation', description: 'Automated IOC collection and enrichment' },
        { name: 'SOC Metrics', description: 'KPIs, MTTD, MTTR tracking and reporting' },
        { name: 'Shift Handoff', description: 'Structured handoff documentation between shifts' },
      ]
    },
    {
      id: 'yellow-team',
      name: 'Yellow Team (DevSecOps)',
      icon: <FileCode className="w-6 h-6" />,
      color: 'yellow',
      description: 'Secure development lifecycle tools including SAST, SCA, and CI/CD integration.',
      features: [
        { name: 'SAST', description: 'Static Application Security Testing for source code analysis' },
        { name: 'SCA', description: 'Software Composition Analysis for dependency vulnerabilities' },
        { name: 'SBOM Generation', description: 'Software Bill of Materials creation and management' },
        { name: 'CI/CD Integration', description: 'Security gates for GitHub Actions, GitLab CI, Jenkins' },
        { name: 'IaC Security', description: 'Terraform, CloudFormation, Kubernetes YAML scanning' },
        { name: 'Secret Detection', description: 'Credential and API key detection in code and commits' },
        { name: 'Architecture Review', description: 'Threat modeling and secure design patterns' },
        { name: 'IDE Plugins', description: 'Real-time security feedback in VS Code and JetBrains IDEs' },
      ]
    },
    {
      id: 'orange-team',
      name: 'Orange Team (Security Awareness)',
      icon: <Users className="w-6 h-6" />,
      color: 'orange',
      description: 'Security awareness training and phishing simulation for employees.',
      features: [
        { name: 'Phishing Simulation', description: 'Realistic phishing campaigns with tracking and metrics' },
        { name: 'Training Content', description: 'Interactive security awareness modules' },
        { name: 'Gamification', description: 'Leaderboards, badges, and rewards for security behaviors' },
        { name: 'Just-in-Time Training', description: 'Contextual training triggered by risky behaviors' },
        { name: 'Compliance Training', description: 'HIPAA, PCI-DSS, and other regulatory training modules' },
        { name: 'Progress Analytics', description: 'Track employee security awareness over time' },
      ]
    },
    {
      id: 'white-team',
      name: 'White Team (GRC)',
      icon: <Award className="w-6 h-6" />,
      color: 'gray',
      description: 'Governance, Risk, and Compliance management for regulatory requirements.',
      features: [
        { name: 'Compliance Frameworks', description: '45 frameworks including PCI-DSS, NIST, FedRAMP, CMMC, HIPAA, SOC 2, ISO 27001' },
        { name: 'Risk Assessment', description: 'Risk identification, scoring, and treatment tracking' },
        { name: 'Policy Management', description: 'Policy lifecycle management with version control' },
        { name: 'Audit Management', description: 'Internal audit scheduling, evidence collection, findings tracking' },
        { name: 'Vendor Risk', description: 'Third-party risk assessment and monitoring' },
        { name: 'Evidence Collection', description: 'Automated evidence gathering for compliance audits' },
        { name: 'Control Mapping', description: 'Map controls across multiple frameworks' },
        { name: 'Compliance Reporting', description: 'Executive dashboards and detailed compliance reports' },
      ]
    },
    {
      id: 'ai-security',
      name: 'AI/ML Security',
      icon: <Brain className="w-6 h-6" />,
      color: 'cyan',
      description: 'Cutting-edge AI and machine learning security testing and automation.',
      features: [
        { name: 'ML Model Security', description: 'Test ML models for adversarial attacks and data poisoning' },
        { name: 'LLM Security Testing', description: 'Prompt injection, jailbreaks, data leakage testing' },
        { name: 'AI-Powered Prioritization', description: 'ML-based vulnerability scoring beyond CVSS' },
        { name: 'Anomaly Detection', description: 'AI-driven detection of unusual patterns and behaviors' },
        { name: 'Attack Path Analysis', description: 'AI correlation of vulnerabilities into exploitable paths' },
        { name: 'Natural Language Reports', description: 'AI-generated executive summaries and recommendations' },
        { name: 'Threat Prediction', description: 'Predictive analytics for emerging threats' },
      ]
    },
    {
      id: 'emerging-tech',
      name: 'Emerging Technology Security',
      icon: <Cpu className="w-6 h-6" />,
      color: 'pink',
      description: 'Security for OT/ICS, IoT, and other emerging technologies.',
      features: [
        { name: 'OT/ICS Security', description: 'Industrial control system scanning and monitoring' },
        { name: 'IoT Security', description: 'IoT device discovery, assessment, and vulnerability scanning' },
        { name: 'SCADA Assessment', description: 'SCADA protocol analysis and security testing' },
        { name: 'Modbus/DNP3 Support', description: 'Industrial protocol scanning and enumeration' },
        { name: 'Firmware Analysis', description: 'IoT firmware extraction and vulnerability assessment' },
      ]
    },
    {
      id: 'consultancy',
      name: 'Consultancy & MSP Features',
      icon: <Building2 className="w-6 h-6" />,
      color: 'indigo',
      description: 'Purpose-built features for security consultancies and managed service providers.',
      features: [
        { name: 'Customer Portal', description: 'Branded client access to engagements and reports', tier: 'Team' },
        { name: 'CRM Integration', description: 'Customer relationship management with pipeline tracking' },
        { name: 'Engagement Management', description: 'Track engagements from scoping to delivery' },
        { name: 'Time Tracking', description: 'Billable hours tracking with project allocation' },
        { name: 'Methodology Checklists', description: 'OWASP, PTES, OSSTMM methodology tracking' },
        { name: 'Finding Templates', description: 'Reusable vulnerability templates for consistent reporting' },
        { name: 'White-Label Reports', description: 'Customizable report branding with your logo' },
        { name: 'Multi-Tenant', description: 'Isolated customer environments with RBAC' },
      ]
    },
    {
      id: 'reporting',
      name: 'Reporting & Analytics',
      icon: <BarChart3 className="w-6 h-6" />,
      color: 'emerald',
      description: 'Comprehensive reporting and analytics for security insights.',
      features: [
        { name: 'Executive Dashboards', description: 'High-level security posture visualization' },
        { name: 'PDF/HTML Reports', description: 'Professional reports with executive summaries' },
        { name: 'JSON/CSV Export', description: 'Raw data export for integration and analysis' },
        { name: 'Trend Analysis', description: 'Track vulnerability trends over time' },
        { name: 'Scan Comparison', description: 'Diff between scans to track remediation' },
        { name: 'Remediation Tracking', description: 'Track vulnerability remediation progress' },
        { name: 'SLA Monitoring', description: 'Track remediation SLAs by severity' },
        { name: 'Custom Dashboards', description: 'Build custom dashboards with widgets' },
      ]
    },
    {
      id: 'integration',
      name: 'Integrations & Automation',
      icon: <Plug className="w-6 h-6" />,
      color: 'violet',
      description: 'Connect HeroForge with your existing security and IT tools.',
      features: [
        { name: 'JIRA Integration', description: 'Create and sync tickets from vulnerabilities' },
        { name: 'ServiceNow', description: 'Incident and change request creation' },
        { name: 'Slack/Teams', description: 'Real-time notifications for findings and events' },
        { name: 'SIEM Export', description: 'Send findings to Splunk, Elasticsearch, Syslog' },
        { name: 'Webhook Notifications', description: 'Custom webhooks for automation' },
        { name: 'REST API', description: 'Full API access for custom integrations' },
        { name: 'SSO/SAML', description: 'Single sign-on with Okta, Azure AD, etc.', tier: 'Enterprise' },
        { name: 'VPN Routing', description: 'Route scans through VPN tunnels', tier: 'Team' },
        { name: 'Distributed Agents', description: 'Deploy agents for internal network scanning' },
        { name: 'Plugin Marketplace', description: 'Extend functionality with community plugins' },
      ]
    },
  ];

  const getColorClasses = (color: string) => {
    const colors: Record<string, { bg: string; border: string; text: string; lightBg: string }> = {
      red: { bg: 'bg-red-500/20', border: 'border-red-500/30', text: 'text-red-400', lightBg: 'bg-red-500/10' },
      blue: { bg: 'bg-blue-500/20', border: 'border-blue-500/30', text: 'text-blue-400', lightBg: 'bg-blue-500/10' },
      purple: { bg: 'bg-purple-500/20', border: 'border-purple-500/30', text: 'text-purple-400', lightBg: 'bg-purple-500/10' },
      green: { bg: 'bg-green-500/20', border: 'border-green-500/30', text: 'text-green-400', lightBg: 'bg-green-500/10' },
      yellow: { bg: 'bg-yellow-500/20', border: 'border-yellow-500/30', text: 'text-yellow-400', lightBg: 'bg-yellow-500/10' },
      orange: { bg: 'bg-orange-500/20', border: 'border-orange-500/30', text: 'text-orange-400', lightBg: 'bg-orange-500/10' },
      gray: { bg: 'bg-gray-500/20', border: 'border-gray-500/30', text: 'text-gray-400', lightBg: 'bg-gray-500/10' },
      cyan: { bg: 'bg-cyan-500/20', border: 'border-cyan-500/30', text: 'text-cyan-400', lightBg: 'bg-cyan-500/10' },
      pink: { bg: 'bg-pink-500/20', border: 'border-pink-500/30', text: 'text-pink-400', lightBg: 'bg-pink-500/10' },
      indigo: { bg: 'bg-indigo-500/20', border: 'border-indigo-500/30', text: 'text-indigo-400', lightBg: 'bg-indigo-500/10' },
      emerald: { bg: 'bg-emerald-500/20', border: 'border-emerald-500/30', text: 'text-emerald-400', lightBg: 'bg-emerald-500/10' },
      violet: { bg: 'bg-violet-500/20', border: 'border-violet-500/30', text: 'text-violet-400', lightBg: 'bg-violet-500/10' },
    };
    return colors[color] || colors.cyan;
  };

  return (
    <div className="min-h-screen bg-gradient-to-b from-gray-900 via-gray-900 to-gray-800">
      {/* Navigation */}
      <nav className="fixed top-0 left-0 right-0 z-50 bg-gray-900/80 backdrop-blur-md border-b border-gray-800">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            <Link to="/" className="flex items-center gap-3">
              <Shield className="w-8 h-8 text-cyan-500" />
              <span className="text-xl font-bold text-white">HeroForge</span>
            </Link>
            <div className="hidden md:flex items-center gap-4">
              <Link to="/" className="text-gray-300 hover:text-white transition-colors">Home</Link>
              <Link to="/features" className="text-cyan-400 font-medium">Features</Link>
              <Link to="/pricing" className="text-gray-300 hover:text-white transition-colors">Pricing</Link>
              <Link to="/tools" className="text-gray-300 hover:text-white transition-colors">Free Tools</Link>
              <Link to="/blog" className="text-gray-300 hover:text-white transition-colors">Blog</Link>
              <Link to="/academy" className="text-gray-300 hover:text-white transition-colors">Academy</Link>
              <Link to="/docs" className="text-gray-300 hover:text-white transition-colors">Docs</Link>
              <Link
                to="/register"
                className="bg-cyan-600 hover:bg-cyan-700 text-white px-4 py-2 rounded-lg font-medium transition-colors"
              >
                Start Free Trial
              </Link>
            </div>
          </div>
        </div>
      </nav>

      {/* Hero Section */}
      <section className="pt-32 pb-16 px-4">
        <div className="max-w-7xl mx-auto text-center">
          <h1 className="text-5xl md:text-6xl font-bold text-white mb-6">
            86+ Security Modules
            <br />
            <span className="text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-blue-500">
              One Unified Platform
            </span>
          </h1>
          <p className="text-xl text-gray-400 max-w-3xl mx-auto mb-10">
            From network reconnaissance to compliance reporting, HeroForge combines everything
            you need for comprehensive security assessments into a single platform.
          </p>
          <div className="flex flex-wrap justify-center gap-4">
            <Link
              to="/register"
              className="bg-cyan-600 hover:bg-cyan-700 text-white px-8 py-4 rounded-lg font-semibold text-lg transition-all hover:scale-105 flex items-center gap-2"
            >
              Start Free Trial
              <ArrowRight className="w-5 h-5" />
            </Link>
            <Link
              to="/#pricing"
              className="border border-gray-600 hover:border-gray-500 text-gray-300 hover:text-white px-8 py-4 rounded-lg font-semibold text-lg transition-colors"
            >
              View Pricing
            </Link>
          </div>
        </div>
      </section>

      {/* Quick Stats */}
      <section className="py-12 px-4">
        <div className="max-w-7xl mx-auto">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-6">
            <div className="bg-gray-800/50 border border-gray-700 rounded-xl p-6 text-center">
              <div className="text-4xl font-bold text-cyan-400 mb-2">86+</div>
              <div className="text-gray-400">Security Modules</div>
            </div>
            <div className="bg-gray-800/50 border border-gray-700 rounded-xl p-6 text-center">
              <div className="text-4xl font-bold text-purple-400 mb-2">45</div>
              <div className="text-gray-400">Compliance Frameworks</div>
            </div>
            <div className="bg-gray-800/50 border border-gray-700 rounded-xl p-6 text-center">
              <div className="text-4xl font-bold text-green-400 mb-2">2,900+</div>
              <div className="text-gray-400">Tests Passing</div>
            </div>
            <div className="bg-gray-800/50 border border-gray-700 rounded-xl p-6 text-center">
              <div className="text-4xl font-bold text-orange-400 mb-2">70%</div>
              <div className="text-gray-400">Of Pentest Cost</div>
            </div>
          </div>
        </div>
      </section>

      {/* Feature Categories */}
      <section className="py-16 px-4">
        <div className="max-w-7xl mx-auto">
          <div className="text-center mb-12">
            <h2 className="text-3xl font-bold text-white mb-4">
              Explore Features by Category
            </h2>
            <p className="text-gray-400 max-w-2xl mx-auto">
              Click on any category to see the full list of features. Our unified security approach
              covers every aspect of security operations.
            </p>
          </div>

          <div className="space-y-4">
            {categories.map((category) => {
              const colors = getColorClasses(category.color);
              const isExpanded = expandedCategory === category.id;

              return (
                <div
                  key={category.id}
                  className={`bg-gray-800 border rounded-xl overflow-hidden transition-all ${colors.border}`}
                >
                  <button
                    onClick={() => setExpandedCategory(isExpanded ? null : category.id)}
                    className="w-full flex items-center justify-between p-6 text-left hover:bg-gray-700/30 transition-colors"
                  >
                    <div className="flex items-center gap-4">
                      <div className={`p-3 rounded-lg ${colors.lightBg}`}>
                        <div className={colors.text}>{category.icon}</div>
                      </div>
                      <div>
                        <h3 className="text-xl font-bold text-white">{category.name}</h3>
                        <p className="text-gray-400 text-sm">{category.description}</p>
                      </div>
                    </div>
                    <div className="flex items-center gap-3">
                      <span className={`${colors.text} font-semibold`}>
                        {category.features.length} features
                      </span>
                      {isExpanded ? (
                        <ChevronUp className="w-5 h-5 text-gray-400" />
                      ) : (
                        <ChevronDown className="w-5 h-5 text-gray-400" />
                      )}
                    </div>
                  </button>

                  {isExpanded && (
                    <div className="px-6 pb-6">
                      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 pt-4 border-t border-gray-700">
                        {category.features.map((feature, idx) => (
                          <div
                            key={idx}
                            className="bg-gray-900/50 border border-gray-700 rounded-lg p-4"
                          >
                            <div className="flex items-start justify-between mb-2">
                              <h4 className="text-white font-semibold">{feature.name}</h4>
                              {feature.tier && (
                                <span className="text-xs bg-cyan-500/20 text-cyan-400 px-2 py-1 rounded">
                                  {feature.tier}
                                </span>
                              )}
                            </div>
                            <p className="text-gray-400 text-sm">{feature.description}</p>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="py-20 px-4 bg-gray-800/50">
        <div className="max-w-4xl mx-auto text-center">
          <h2 className="text-3xl md:text-4xl font-bold text-white mb-4">
            Ready to See It in Action?
          </h2>
          <p className="text-xl text-gray-400 mb-8">
            Start your 14-day free trial and experience the full power of HeroForge.
          </p>
          <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
            <Link
              to="/register"
              className="bg-cyan-600 hover:bg-cyan-700 text-white px-8 py-4 rounded-lg font-semibold text-lg transition-all hover:scale-105 flex items-center gap-2"
            >
              Start Your Free Trial
              <ArrowRight className="w-5 h-5" />
            </Link>
            <Link
              to="/contact-sales"
              className="text-cyan-400 hover:text-cyan-300 font-semibold text-lg transition-colors"
            >
              Contact Sales
            </Link>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-gray-800 py-12 px-4">
        <div className="max-w-7xl mx-auto">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-8 mb-8">
            <div>
              <div className="flex items-center gap-3 mb-4">
                <Shield className="w-8 h-8 text-cyan-500" />
                <span className="text-xl font-bold text-white">HeroForge</span>
              </div>
              <p className="text-gray-400 text-sm">
                Professional penetration testing and vulnerability management platform.
              </p>
            </div>
            <div>
              <h4 className="text-white font-semibold mb-4">Product</h4>
              <ul className="space-y-2">
                <li><Link to="/features" className="text-gray-400 hover:text-white text-sm">Features</Link></li>
                <li><Link to="/use-cases" className="text-gray-400 hover:text-white text-sm">Use Cases</Link></li>
                <li><Link to="/pricing" className="text-gray-400 hover:text-white text-sm">Pricing</Link></li>
                <li><Link to="/roadmap" className="text-gray-400 hover:text-white text-sm">Roadmap</Link></li>
                <li><Link to="/status" className="text-gray-400 hover:text-white text-sm">Status</Link></li>
                <li><Link to="/about" className="text-gray-400 hover:text-white text-sm">About</Link></li>
                <li><Link to="/login" className="text-gray-400 hover:text-white text-sm">Login</Link></li>
              </ul>
            </div>
            <div>
              <h4 className="text-white font-semibold mb-4">Resources</h4>
              <ul className="space-y-2">
                <li><Link to="/tools" className="text-gray-400 hover:text-white text-sm">Free Tools</Link></li>
                <li><Link to="/blog" className="text-gray-400 hover:text-white text-sm">Blog</Link></li>
                <li><Link to="/academy" className="text-gray-400 hover:text-white text-sm">Academy</Link></li>
                <li><Link to="/certifications" className="text-gray-400 hover:text-white text-sm">Certifications</Link></li>
                <li><Link to="/docs" className="text-gray-400 hover:text-white text-sm">Documentation</Link></li>
                <li><Link to="/whitepapers" className="text-gray-400 hover:text-white text-sm">Whitepapers</Link></li>
                <li><Link to="/developers" className="text-gray-400 hover:text-white text-sm">Developer Portal</Link></li>
              </ul>
            </div>
            <div>
              <h4 className="text-white font-semibold mb-4">Contact</h4>
              <ul className="space-y-2">
                <li><a href="mailto:sales@genialarchitect.io" className="text-gray-400 hover:text-white text-sm">sales@genialarchitect.io</a></li>
                <li><a href="mailto:support@genialarchitect.io" className="text-gray-400 hover:text-white text-sm">support@genialarchitect.io</a></li>
              </ul>
            </div>
          </div>
          <div className="border-t border-gray-800 pt-8 flex flex-col md:flex-row items-center justify-between">
            <p className="text-gray-500 text-sm">
              &copy; 2026 Genial Architect Cybersecurity Research Associates. All rights reserved.
            </p>
            <div className="flex items-center gap-6 mt-4 md:mt-0">
              <Link to="/legal/terms" className="text-gray-400 hover:text-white text-sm">Terms of Service</Link>
              <Link to="/legal/privacy" className="text-gray-400 hover:text-white text-sm">Privacy Policy</Link>
              <Link to="/legal/acceptable-use" className="text-gray-400 hover:text-white text-sm">Acceptable Use</Link>
              <Link to="/legal/cookies" className="text-gray-400 hover:text-white text-sm">Cookies</Link>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default FeaturesPage;
