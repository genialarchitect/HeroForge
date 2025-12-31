import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import {
  Shield,
  Zap,
  Users,
  Building2,
  Check,
  X,
  ChevronDown,
  ChevronUp,
  Smartphone,
  Globe,
  Lock,
  FileText,
  BarChart3,
  Bell,
  Clock,
  Target,
  Network,
  Search,
  Server,
  Cloud,
  Key,
  MonitorCheck,
  ArrowRight,
  Star,
  Brain,
  Sparkles,
  TrendingUp,
  DollarSign,
  Award,
  Rocket
} from 'lucide-react';

interface PricingTier {
  name: string;
  price: string;
  yearlyPrice: string;
  description: string;
  icon: React.ReactNode;
  features: string[];
  highlighted?: boolean;
  cta: string;
}

interface FAQ {
  question: string;
  answer: string;
}

const SalesPage: React.FC = () => {
  const [isYearly, setIsYearly] = useState(true);
  const [openFaq, setOpenFaq] = useState<number | null>(null);

  const tiers: PricingTier[] = [
    {
      name: 'Solo',
      price: '$99',
      yearlyPrice: '$999',
      description: 'Perfect for freelance security consultants',
      icon: <Shield className="w-8 h-8" />,
      features: [
        '1 user account',
        'Unlimited network scans',
        '5 target groups',
        'Basic reports (JSON, CSV, Markdown)',
        'SSL/TLS grading',
        'Vulnerability detection',
        'DNS reconnaissance',
        'Mobile app access',
        'Community support',
      ],
      cta: 'Start Free Trial',
    },
    {
      name: 'Professional',
      price: '$299',
      yearlyPrice: '$2,999',
      description: 'For growing security teams',
      icon: <Zap className="w-8 h-8" />,
      features: [
        'Up to 5 users',
        'Everything in Solo, plus:',
        'PDF & HTML reports',
        'Scheduled scans',
        'Scan templates',
        'JIRA integration',
        'Email notifications',
        'Web application scanning',
        'Compliance frameworks',
        'Priority email support',
      ],
      highlighted: true,
      cta: 'Start Free Trial',
    },
    {
      name: 'Team',
      price: '$599',
      yearlyPrice: '$5,999',
      description: 'Built for consultancies & MSPs',
      icon: <Users className="w-8 h-8" />,
      features: [
        'Up to 15 users',
        'Everything in Professional, plus:',
        'Customer portal (10 customers)',
        'CRM & engagement management',
        'Time tracking & billing',
        'Full compliance reporting',
        'SIEM integration',
        'Slack/Teams notifications',
        'Methodology tracking',
        'VPN routing for scans',
        'Dedicated support',
      ],
      cta: 'Start Free Trial',
    },
    {
      name: 'Enterprise',
      price: 'Custom',
      yearlyPrice: 'Custom',
      description: 'For large organizations',
      icon: <Building2 className="w-8 h-8" />,
      features: [
        'Unlimited users',
        'Everything in Team, plus:',
        'Unlimited customer portals',
        'SSO/SAML authentication',
        'Custom integrations',
        'On-premise deployment',
        'SLA guarantees',
        'Custom compliance frameworks',
        'Dedicated account manager',
        '24/7 phone support',
      ],
      cta: 'Contact Sales',
    },
  ];

  const featureComparison = [
    { feature: 'Users', solo: '1', pro: '5', team: '15', enterprise: 'Unlimited' },
    { feature: 'Network Scans', solo: 'Unlimited', pro: 'Unlimited', team: 'Unlimited', enterprise: 'Unlimited' },
    { feature: 'Web App Scans', solo: false, pro: true, team: true, enterprise: true },
    { feature: 'Target Groups', solo: '5', pro: '25', team: 'Unlimited', enterprise: 'Unlimited' },
    { feature: 'Scheduled Scans', solo: false, pro: true, team: true, enterprise: true },
    { feature: 'Customer Portal', solo: false, pro: false, team: '10 customers', enterprise: 'Unlimited' },
    { feature: 'CRM & Engagements', solo: false, pro: false, team: true, enterprise: true },
    { feature: 'Time Tracking', solo: false, pro: false, team: true, enterprise: true },
    { feature: 'PDF Reports', solo: false, pro: true, team: true, enterprise: true },
    { feature: 'Compliance Frameworks', solo: false, pro: 'Basic', team: 'Full', enterprise: 'Custom' },
    { feature: 'JIRA Integration', solo: false, pro: true, team: true, enterprise: true },
    { feature: 'SIEM Integration', solo: false, pro: false, team: true, enterprise: true },
    { feature: 'Slack/Teams Alerts', solo: false, pro: false, team: true, enterprise: true },
    { feature: 'VPN Routing', solo: false, pro: false, team: true, enterprise: true },
    { feature: 'SSO/SAML', solo: false, pro: false, team: false, enterprise: true },
    { feature: 'On-Premise Option', solo: false, pro: false, team: false, enterprise: true },
    { feature: 'Mobile App', solo: 'View only', pro: 'Full', team: 'Full', enterprise: 'Full' },
    { feature: 'Support', solo: 'Community', pro: 'Email', team: 'Priority', enterprise: '24/7 Phone' },
  ];

  const faqs: FAQ[] = [
    {
      question: 'What is HeroForge?',
      answer: 'HeroForge is a comprehensive penetration testing and vulnerability management platform. It combines network scanning, web application testing, compliance analysis, and client management into one unified tool designed for security professionals and consultancies.',
    },
    {
      question: 'How does AI improve pentesting?',
      answer: 'HeroForge leverages machine learning to prioritize vulnerabilities by exploitability and business impact (not just CVSS scores), detect anomalies in network traffic and user behavior, test AI/LLM models for security flaws, and automatically correlate vulnerabilities to identify attack paths. This makes testing 30% faster while improving accuracy compared to manual analysis.',
    },
    {
      question: 'How does HeroForge compare to Tenable/Qualys?',
      answer: 'HeroForge offers 50-70% cost savings vs Tenable ($999/year vs $2,275/year) and Qualys with transparent pricing and unlimited scans (no per-asset fees). Unlike enterprise tools, we include consultancy-focused features like customer portals, CRM, engagement management, and time tracking—features they don\'t offer. We\'re purpose-built for security consultants and MSPs, not just enterprise IT teams.',
    },
    {
      question: 'Is there a free trial?',
      answer: 'Yes! All plans include a 14-day free trial with full access to features. No credit card required to start. You can upgrade, downgrade, or cancel at any time.',
    },
    {
      question: 'Can I self-host HeroForge?',
      answer: 'Enterprise customers can deploy HeroForge on their own infrastructure. This includes Docker-based deployment with full documentation and support. Contact our sales team for on-premise licensing.',
    },
    {
      question: 'What compliance frameworks are supported?',
      answer: 'HeroForge supports PCI-DSS 4.0, NIST 800-53, NIST CSF, CIS Benchmarks, HIPAA, SOC 2, FERPA, and OWASP Top 10. Enterprise customers can request custom framework implementations.',
    },
    {
      question: 'How does the customer portal work?',
      answer: 'The customer portal gives your clients secure, branded access to view their engagement status, vulnerabilities, and reports. Each customer gets isolated access to only their data. Available on Team and Enterprise plans.',
    },
    {
      question: 'What integrations are available?',
      answer: 'HeroForge integrates with JIRA for ticket creation, Slack and Microsoft Teams for notifications, and SIEM platforms (Splunk, Elasticsearch, Syslog) for security event forwarding. Enterprise customers can request custom integrations.',
    },
    {
      question: 'Is there a mobile app?',
      answer: 'Yes! The HeroForge companion app is available for iOS and Android. Solo users get view-only access for checking scan results and reports. Professional and above get full mobile functionality including notifications and engagement management.',
    },
    {
      question: 'What kind of support do you offer?',
      answer: 'Solo users have access to our community forum and documentation. Professional users get priority email support. Team users get dedicated support with faster response times. Enterprise customers receive 24/7 phone support and a dedicated account manager.',
    },
  ];

  const capabilities = [
    { icon: <Brain className="w-6 h-6" />, title: 'AI Security Testing', desc: 'ML model security, prompt injection, LLM jailbreaks', badge: 'AI' },
    { icon: <Sparkles className="w-6 h-6" />, title: 'LLM Testing', desc: 'Adversarial attacks, data leakage, AI red teaming', badge: 'NEW' },
    { icon: <Network className="w-6 h-6" />, title: 'Network Scanning', desc: 'AI-powered TCP/UDP scanning, service detection, OS fingerprinting' },
    { icon: <Globe className="w-6 h-6" />, title: 'Web App Testing', desc: 'XSS, SQLi, CSRF detection with AI-driven crawling' },
    { icon: <Lock className="w-6 h-6" />, title: 'SSL/TLS Analysis', desc: 'Certificate grading, cipher analysis, vulnerability detection' },
    { icon: <Search className="w-6 h-6" />, title: 'DNS Reconnaissance', desc: 'Subdomain enumeration, zone transfers, record analysis' },
    { icon: <Shield className="w-6 h-6" />, title: 'Vulnerability Scanning', desc: 'AI-prioritized CVE detection with NVD integration' },
    { icon: <FileText className="w-6 h-6" />, title: 'Compliance Analysis', desc: 'PCI-DSS, HIPAA, SOC2, NIST frameworks with evidence' },
    { icon: <BarChart3 className="w-6 h-6" />, title: 'Executive Dashboards', desc: 'Risk trends, vulnerability metrics, remediation tracking' },
    { icon: <Bell className="w-6 h-6" />, title: 'Real-time Alerts', desc: 'Slack, Teams, email notifications for critical findings' },
    { icon: <Clock className="w-6 h-6" />, title: 'Time Tracking', desc: 'Billable hours per engagement with reporting' },
    { icon: <Target className="w-6 h-6" />, title: 'Attack Path Analysis', desc: 'AI-powered exploitation chain visualization across networks' },
    { icon: <Server className="w-6 h-6" />, title: 'Active Directory', desc: 'LDAP enumeration, Kerberoasting detection, privilege analysis' },
    { icon: <Cloud className="w-6 h-6" />, title: 'Cloud Security', desc: 'AWS, Azure, GCP configuration auditing' },
    { icon: <Key className="w-6 h-6" />, title: 'Credential Audit', desc: 'Password policy checking and breach detection' },
    { icon: <MonitorCheck className="w-6 h-6" />, title: 'Methodology Tracking', desc: 'Pentest phases, checklists, progress tracking' },
    { icon: <Users className="w-6 h-6" />, title: 'Customer Portal', desc: 'Branded client access to engagements and reports' },
    { icon: <Smartphone className="w-6 h-6" />, title: 'Mobile App', desc: 'iOS & Android companion for on-the-go access' },
  ];

  return (
    <div className="min-h-screen bg-gradient-to-b from-gray-900 via-gray-900 to-gray-800">
      {/* Navigation */}
      <nav className="fixed top-0 left-0 right-0 z-50 bg-gray-900/80 backdrop-blur-md border-b border-gray-800">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            <div className="flex items-center gap-3">
              <Shield className="w-8 h-8 text-cyan-500" />
              <span className="text-xl font-bold text-white">HeroForge</span>
            </div>
            <div className="flex items-center gap-4">
              <a href="#features" className="text-gray-300 hover:text-white transition-colors">Features</a>
              <a href="#pricing" className="text-gray-300 hover:text-white transition-colors">Pricing</a>
              <a href="#faq" className="text-gray-300 hover:text-white transition-colors">FAQ</a>
              <Link
                to="/login"
                className="bg-cyan-600 hover:bg-cyan-700 text-white px-4 py-2 rounded-lg font-medium transition-colors"
              >
                Sign In
              </Link>
            </div>
          </div>
        </div>
      </nav>

      {/* Hero Section */}
      <section className="pt-32 pb-20 px-4">
        <div className="max-w-7xl mx-auto text-center">
          <div className="inline-flex items-center gap-2 bg-cyan-500/10 border border-cyan-500/20 rounded-full px-4 py-2 mb-6">
            <Star className="w-4 h-4 text-cyan-400" />
            <span className="text-cyan-400 text-sm font-medium">Trusted by 2,500+ security professionals worldwide</span>
          </div>
          <h1 className="text-5xl md:text-6xl font-bold text-white mb-6">
            AI-Powered Penetration Testing
            <br />
            <span className="text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-blue-500">
              For 2025 & Beyond
            </span>
          </h1>
          <p className="text-xl text-gray-400 max-w-3xl mx-auto mb-10">
            The market-leading platform combining AI automation with comprehensive security testing.
            Network reconnaissance, vulnerability management, compliance analysis, and client engagement—all in one place.
          </p>
          <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
            <a
              href="#pricing"
              className="bg-cyan-600 hover:bg-cyan-700 text-white px-8 py-4 rounded-lg font-semibold text-lg transition-all hover:scale-105 flex items-center gap-2"
            >
              Start Free Trial
              <ArrowRight className="w-5 h-5" />
            </a>
            <a
              href="#features"
              className="border border-gray-600 hover:border-gray-500 text-gray-300 hover:text-white px-8 py-4 rounded-lg font-semibold text-lg transition-colors"
            >
              See Features
            </a>
          </div>
        </div>
      </section>

      {/* Stats Section */}
      <section className="py-16 px-4">
        <div className="max-w-7xl mx-auto">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
            <div className="bg-gradient-to-br from-cyan-600/20 to-blue-600/20 border border-cyan-500/30 rounded-2xl p-8 text-center">
              <TrendingUp className="w-12 h-12 text-cyan-400 mx-auto mb-4" />
              <div className="text-4xl font-bold text-white mb-2">$2.4B</div>
              <div className="text-gray-400">Global penetration testing market</div>
              <div className="text-sm text-cyan-400 mt-2">Growing 15-18% annually</div>
            </div>
            <div className="bg-gradient-to-br from-purple-600/20 to-pink-600/20 border border-purple-500/30 rounded-2xl p-8 text-center">
              <Rocket className="w-12 h-12 text-purple-400 mx-auto mb-4" />
              <div className="text-4xl font-bold text-white mb-2">30% Faster</div>
              <div className="text-gray-400">With AI automation vs manual testing</div>
              <div className="text-sm text-purple-400 mt-2">Proven by industry benchmarks</div>
            </div>
            <div className="bg-gradient-to-br from-green-600/20 to-emerald-600/20 border border-green-500/30 rounded-2xl p-8 text-center">
              <DollarSign className="w-12 h-12 text-green-400 mx-auto mb-4" />
              <div className="text-4xl font-bold text-white mb-2">96% Savings</div>
              <div className="text-gray-400">vs traditional pentesting engagements</div>
              <div className="text-sm text-green-400 mt-2">$5K-$100K per engagement avoided</div>
            </div>
          </div>
        </div>
      </section>

      {/* AI/ML Features Section */}
      <section className="py-20 px-4 bg-gray-800/50">
        <div className="max-w-7xl mx-auto">
          <div className="text-center mb-16">
            <div className="inline-flex items-center gap-2 bg-purple-500/10 border border-purple-500/20 rounded-full px-4 py-2 mb-4">
              <Brain className="w-4 h-4 text-purple-400" />
              <span className="text-purple-400 text-sm font-medium">AI-Powered Security</span>
            </div>
            <h2 className="text-3xl md:text-4xl font-bold text-white mb-4">
              Next-Generation AI & Machine Learning
            </h2>
            <p className="text-xl text-gray-400 max-w-2xl mx-auto">
              Leverage cutting-edge AI to automate threat detection, prioritize vulnerabilities, and accelerate your security workflows.
            </p>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
            <div className="bg-gray-800 border border-purple-500/30 rounded-xl p-6 hover:border-purple-500 transition-colors group">
              <div className="flex items-center gap-3 mb-4">
                <div className="p-2 bg-purple-500/10 rounded-lg">
                  <Brain className="w-6 h-6 text-purple-400" />
                </div>
                <Sparkles className="w-5 h-5 text-purple-400 group-hover:animate-pulse" />
              </div>
              <h3 className="text-white font-semibold mb-2">ML Alert Prioritization</h3>
              <p className="text-gray-400 text-sm">Machine learning ranks vulnerabilities by exploitability and business impact, not just CVSS scores.</p>
            </div>
            <div className="bg-gray-800 border border-blue-500/30 rounded-xl p-6 hover:border-blue-500 transition-colors group">
              <div className="flex items-center gap-3 mb-4">
                <div className="p-2 bg-blue-500/10 rounded-lg">
                  <Target className="w-6 h-6 text-blue-400" />
                </div>
                <Sparkles className="w-5 h-5 text-blue-400 group-hover:animate-pulse" />
              </div>
              <h3 className="text-white font-semibold mb-2">AI Anomaly Detection</h3>
              <p className="text-gray-400 text-sm">Detect unusual patterns in network traffic, user behavior, and system configurations automatically.</p>
            </div>
            <div className="bg-gray-800 border border-cyan-500/30 rounded-xl p-6 hover:border-cyan-500 transition-colors group">
              <div className="flex items-center gap-3 mb-4">
                <div className="p-2 bg-cyan-500/10 rounded-lg">
                  <Shield className="w-6 h-6 text-cyan-400" />
                </div>
                <Sparkles className="w-5 h-5 text-cyan-400 group-hover:animate-pulse" />
              </div>
              <h3 className="text-white font-semibold mb-2">LLM Security Testing</h3>
              <p className="text-gray-400 text-sm">Test AI models for prompt injection, data leakage, jailbreaks, and adversarial attacks.</p>
            </div>
            <div className="bg-gray-800 border border-green-500/30 rounded-xl p-6 hover:border-green-500 transition-colors group">
              <div className="flex items-center gap-3 mb-4">
                <div className="p-2 bg-green-500/10 rounded-lg">
                  <Network className="w-6 h-6 text-green-400" />
                </div>
                <Sparkles className="w-5 h-5 text-green-400 group-hover:animate-pulse" />
              </div>
              <h3 className="text-white font-semibold mb-2">Automated Correlation</h3>
              <p className="text-gray-400 text-sm">AI correlates vulnerabilities across hosts to identify attack paths and chained exploits.</p>
            </div>
          </div>
        </div>
      </section>

      {/* Capabilities Grid */}
      <section id="features" className="py-20 px-4">
        <div className="max-w-7xl mx-auto">
          <div className="text-center mb-16">
            <h2 className="text-3xl md:text-4xl font-bold text-white mb-4">
              Everything You Need for Security Assessments
            </h2>
            <p className="text-xl text-gray-400 max-w-2xl mx-auto">
              From initial reconnaissance to final report delivery, HeroForge handles the entire engagement lifecycle.
            </p>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
            {capabilities.map((cap, idx) => (
              <div
                key={idx}
                className="bg-gray-800 border border-gray-700 rounded-xl p-6 hover:border-cyan-500/50 transition-colors group relative"
              >
                {cap.badge && (
                  <div className="absolute top-4 right-4">
                    <span className={`text-xs font-bold px-2 py-1 rounded-full ${
                      cap.badge === 'AI' ? 'bg-purple-500/20 text-purple-400 border border-purple-500/30' :
                      'bg-green-500/20 text-green-400 border border-green-500/30'
                    }`}>
                      {cap.badge}
                    </span>
                  </div>
                )}
                <div className="text-cyan-500 mb-4 group-hover:scale-110 transition-transform">
                  {cap.icon}
                </div>
                <h3 className="text-white font-semibold mb-2">{cap.title}</h3>
                <p className="text-gray-400 text-sm">{cap.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Pricing Section */}
      <section id="pricing" className="py-20 px-4">
        <div className="max-w-7xl mx-auto">
          <div className="text-center mb-12">
            <h2 className="text-3xl md:text-4xl font-bold text-white mb-4">
              Simple, Transparent Pricing
            </h2>
            <p className="text-xl text-gray-400 max-w-2xl mx-auto mb-8">
              Choose the plan that fits your needs. All plans include a 14-day free trial.
            </p>

            {/* Billing Toggle */}
            <div className="inline-flex items-center bg-gray-800 rounded-lg p-1">
              <button
                onClick={() => setIsYearly(false)}
                className={`px-4 py-2 rounded-md font-medium transition-colors ${
                  !isYearly ? 'bg-cyan-600 text-white' : 'text-gray-400 hover:text-white'
                }`}
              >
                Monthly
              </button>
              <button
                onClick={() => setIsYearly(true)}
                className={`px-4 py-2 rounded-md font-medium transition-colors flex items-center gap-2 ${
                  isYearly ? 'bg-cyan-600 text-white' : 'text-gray-400 hover:text-white'
                }`}
              >
                Yearly
                <span className="bg-green-500 text-white text-xs px-2 py-0.5 rounded-full">
                  Save 15%
                </span>
              </button>
            </div>
          </div>

          {/* Pricing Cards */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-20">
            {tiers.map((tier, idx) => (
              <div
                key={idx}
                className={`relative rounded-2xl p-6 ${
                  tier.highlighted
                    ? 'bg-gradient-to-b from-cyan-600/20 to-gray-800 border-2 border-cyan-500'
                    : 'bg-gray-800 border border-gray-700'
                }`}
              >
                {tier.highlighted && (
                  <div className="absolute -top-3 left-1/2 -translate-x-1/2">
                    <span className="bg-cyan-500 text-white text-sm font-medium px-3 py-1 rounded-full">
                      Most Popular
                    </span>
                  </div>
                )}
                <div className={`mb-4 ${tier.highlighted ? 'text-cyan-400' : 'text-gray-400'}`}>
                  {tier.icon}
                </div>
                <h3 className="text-xl font-bold text-white mb-2">{tier.name}</h3>
                <p className="text-gray-400 text-sm mb-4">{tier.description}</p>
                <div className="mb-6">
                  <span className="text-4xl font-bold text-white">
                    {tier.price === 'Custom' ? '' : isYearly ? tier.yearlyPrice : tier.price}
                  </span>
                  {tier.price !== 'Custom' && (
                    <span className="text-gray-400">/{isYearly ? 'year' : 'month'}</span>
                  )}
                  {tier.price === 'Custom' && (
                    <span className="text-2xl font-bold text-white">Contact Us</span>
                  )}
                </div>
                <button
                  className={`w-full py-3 rounded-lg font-semibold transition-colors mb-6 ${
                    tier.highlighted
                      ? 'bg-cyan-600 hover:bg-cyan-700 text-white'
                      : 'bg-gray-700 hover:bg-gray-600 text-white'
                  }`}
                >
                  {tier.cta}
                </button>
                <ul className="space-y-3">
                  {tier.features.map((feature, fIdx) => (
                    <li key={fIdx} className="flex items-start gap-2">
                      <Check className="w-5 h-5 text-cyan-500 flex-shrink-0 mt-0.5" />
                      <span className="text-gray-300 text-sm">{feature}</span>
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>

          {/* Feature Comparison Table */}
          <div className="bg-gray-800 rounded-2xl border border-gray-700 overflow-hidden">
            <div className="p-6 border-b border-gray-700">
              <h3 className="text-2xl font-bold text-white">Compare Plans</h3>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-gray-700">
                    <th className="text-left p-4 text-gray-400 font-medium">Feature</th>
                    <th className="text-center p-4 text-gray-400 font-medium">Solo</th>
                    <th className="text-center p-4 text-cyan-400 font-medium bg-cyan-500/5">Professional</th>
                    <th className="text-center p-4 text-gray-400 font-medium">Team</th>
                    <th className="text-center p-4 text-gray-400 font-medium">Enterprise</th>
                  </tr>
                </thead>
                <tbody>
                  {featureComparison.map((row, idx) => (
                    <tr key={idx} className="border-b border-gray-700/50 hover:bg-gray-700/30">
                      <td className="p-4 text-white">{row.feature}</td>
                      <td className="p-4 text-center">
                        {typeof row.solo === 'boolean' ? (
                          row.solo ? (
                            <Check className="w-5 h-5 text-cyan-500 mx-auto" />
                          ) : (
                            <X className="w-5 h-5 text-gray-600 mx-auto" />
                          )
                        ) : (
                          <span className="text-gray-300">{row.solo}</span>
                        )}
                      </td>
                      <td className="p-4 text-center bg-cyan-500/5">
                        {typeof row.pro === 'boolean' ? (
                          row.pro ? (
                            <Check className="w-5 h-5 text-cyan-500 mx-auto" />
                          ) : (
                            <X className="w-5 h-5 text-gray-600 mx-auto" />
                          )
                        ) : (
                          <span className="text-gray-300">{row.pro}</span>
                        )}
                      </td>
                      <td className="p-4 text-center">
                        {typeof row.team === 'boolean' ? (
                          row.team ? (
                            <Check className="w-5 h-5 text-cyan-500 mx-auto" />
                          ) : (
                            <X className="w-5 h-5 text-gray-600 mx-auto" />
                          )
                        ) : (
                          <span className="text-gray-300">{row.team}</span>
                        )}
                      </td>
                      <td className="p-4 text-center">
                        {typeof row.enterprise === 'boolean' ? (
                          row.enterprise ? (
                            <Check className="w-5 h-5 text-cyan-500 mx-auto" />
                          ) : (
                            <X className="w-5 h-5 text-gray-600 mx-auto" />
                          )
                        ) : (
                          <span className="text-gray-300">{row.enterprise}</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </section>

      {/* Competitive Comparison Section */}
      <section className="py-20 px-4 bg-gray-800/50">
        <div className="max-w-7xl mx-auto">
          <div className="text-center mb-16">
            <h2 className="text-3xl md:text-4xl font-bold text-white mb-4">
              How HeroForge Stacks Up
            </h2>
            <p className="text-xl text-gray-400 max-w-2xl mx-auto">
              Compare our pricing and features against industry leaders and traditional pentesting services.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-8 mb-12">
            {/* vs Tenable */}
            <div className="bg-gray-800 border border-gray-700 rounded-2xl p-8">
              <div className="flex items-center justify-between mb-6">
                <h3 className="text-2xl font-bold text-white">vs Tenable</h3>
                <div className="bg-green-500/20 text-green-400 px-3 py-1 rounded-full text-sm font-bold">
                  50-70% Savings
                </div>
              </div>
              <div className="space-y-4 mb-6">
                <div className="flex items-start gap-3">
                  <Check className="w-5 h-5 text-cyan-500 flex-shrink-0 mt-0.5" />
                  <div>
                    <div className="text-white font-medium">Better Pricing</div>
                    <div className="text-gray-400 text-sm">$999/year vs $2,275/year (65 assets)</div>
                  </div>
                </div>
                <div className="flex items-start gap-3">
                  <Check className="w-5 h-5 text-cyan-500 flex-shrink-0 mt-0.5" />
                  <div>
                    <div className="text-white font-medium">Unlimited Scans</div>
                    <div className="text-gray-400 text-sm">No per-asset pricing limits</div>
                  </div>
                </div>
                <div className="flex items-start gap-3">
                  <Check className="w-5 h-5 text-cyan-500 flex-shrink-0 mt-0.5" />
                  <div>
                    <div className="text-white font-medium">Customer Portal</div>
                    <div className="text-gray-400 text-sm">Built-in client management (Tenable doesn't offer this)</div>
                  </div>
                </div>
                <div className="flex items-start gap-3">
                  <Check className="w-5 h-5 text-cyan-500 flex-shrink-0 mt-0.5" />
                  <div>
                    <div className="text-white font-medium">AI-Powered</div>
                    <div className="text-gray-400 text-sm">ML prioritization and LLM testing</div>
                  </div>
                </div>
              </div>
            </div>

            {/* vs Qualys */}
            <div className="bg-gray-800 border border-gray-700 rounded-2xl p-8">
              <div className="flex items-center justify-between mb-6">
                <h3 className="text-2xl font-bold text-white">vs Qualys</h3>
                <div className="bg-green-500/20 text-green-400 px-3 py-1 rounded-full text-sm font-bold">
                  60% Savings
                </div>
              </div>
              <div className="space-y-4 mb-6">
                <div className="flex items-start gap-3">
                  <Check className="w-5 h-5 text-cyan-500 flex-shrink-0 mt-0.5" />
                  <div>
                    <div className="text-white font-medium">Transparent Pricing</div>
                    <div className="text-gray-400 text-sm">No complex per-target pricing models</div>
                  </div>
                </div>
                <div className="flex items-start gap-3">
                  <Check className="w-5 h-5 text-cyan-500 flex-shrink-0 mt-0.5" />
                  <div>
                    <div className="text-white font-medium">Engagement Management</div>
                    <div className="text-gray-400 text-sm">CRM, time tracking, methodology tracking</div>
                  </div>
                </div>
                <div className="flex items-start gap-3">
                  <Check className="w-5 h-5 text-cyan-500 flex-shrink-0 mt-0.5" />
                  <div>
                    <div className="text-white font-medium">Better UX</div>
                    <div className="text-gray-400 text-sm">Modern interface built for pentesters</div>
                  </div>
                </div>
                <div className="flex items-start gap-3">
                  <Check className="w-5 h-5 text-cyan-500 flex-shrink-0 mt-0.5" />
                  <div>
                    <div className="text-white font-medium">14-Day Free Trial</div>
                    <div className="text-gray-400 text-sm">Try before you buy (no credit card)</div>
                  </div>
                </div>
              </div>
            </div>

            {/* vs Traditional Pentesting */}
            <div className="bg-gray-800 border border-gray-700 rounded-2xl p-8">
              <div className="flex items-center justify-between mb-6">
                <h3 className="text-2xl font-bold text-white">vs Traditional</h3>
                <div className="bg-green-500/20 text-green-400 px-3 py-1 rounded-full text-sm font-bold">
                  96% Savings
                </div>
              </div>
              <div className="space-y-4 mb-6">
                <div className="flex items-start gap-3">
                  <Check className="w-5 h-5 text-cyan-500 flex-shrink-0 mt-0.5" />
                  <div>
                    <div className="text-white font-medium">Massive Cost Reduction</div>
                    <div className="text-gray-400 text-sm">$999/year vs $5K-$100K per engagement</div>
                  </div>
                </div>
                <div className="flex items-start gap-3">
                  <Check className="w-5 h-5 text-cyan-500 flex-shrink-0 mt-0.5" />
                  <div>
                    <div className="text-white font-medium">Continuous Testing</div>
                    <div className="text-gray-400 text-sm">Always-on vs periodic assessments</div>
                  </div>
                </div>
                <div className="flex items-start gap-3">
                  <Check className="w-5 h-5 text-cyan-500 flex-shrink-0 mt-0.5" />
                  <div>
                    <div className="text-white font-medium">Instant Results</div>
                    <div className="text-gray-400 text-sm">Real-time findings vs 1-2 week wait</div>
                  </div>
                </div>
                <div className="flex items-start gap-3">
                  <Check className="w-5 h-5 text-cyan-500 flex-shrink-0 mt-0.5" />
                  <div>
                    <div className="text-white font-medium">No Scheduling Hassles</div>
                    <div className="text-gray-400 text-sm">Scan on-demand, anytime</div>
                  </div>
                </div>
              </div>
            </div>
          </div>

          <div className="bg-gradient-to-r from-cyan-600/20 to-blue-600/20 border border-cyan-500/30 rounded-2xl p-8 text-center">
            <Award className="w-12 h-12 text-cyan-400 mx-auto mb-4" />
            <h3 className="text-2xl font-bold text-white mb-2">
              The Only All-in-One Platform for Consultancies
            </h3>
            <p className="text-gray-400 max-w-3xl mx-auto">
              Combine enterprise-grade scanning with consultancy-focused engagement management at SMB pricing.
              No other platform offers customer portals, CRM, and unlimited scans at this price point.
            </p>
          </div>
        </div>
      </section>

      {/* FAQ Section */}
      <section id="faq" className="py-20 px-4">
        <div className="max-w-3xl mx-auto">
          <div className="text-center mb-12">
            <h2 className="text-3xl md:text-4xl font-bold text-white mb-4">
              Frequently Asked Questions
            </h2>
            <p className="text-xl text-gray-400">
              Got questions? We've got answers.
            </p>
          </div>
          <div className="space-y-4">
            {faqs.map((faq, idx) => (
              <div
                key={idx}
                className="bg-gray-800 border border-gray-700 rounded-xl overflow-hidden"
              >
                <button
                  onClick={() => setOpenFaq(openFaq === idx ? null : idx)}
                  className="w-full flex items-center justify-between p-6 text-left"
                >
                  <span className="text-white font-medium">{faq.question}</span>
                  {openFaq === idx ? (
                    <ChevronUp className="w-5 h-5 text-gray-400" />
                  ) : (
                    <ChevronDown className="w-5 h-5 text-gray-400" />
                  )}
                </button>
                {openFaq === idx && (
                  <div className="px-6 pb-6">
                    <p className="text-gray-400">{faq.answer}</p>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Social Proof Section */}
      <section className="py-20 px-4 bg-gray-800/50">
        <div className="max-w-7xl mx-auto">
          <div className="text-center mb-16">
            <h2 className="text-3xl md:text-4xl font-bold text-white mb-4">
              Trusted by Security Professionals Worldwide
            </h2>
            <p className="text-xl text-gray-400 max-w-2xl mx-auto">
              Join 2,500+ pentesters, consultants, and MSPs who rely on HeroForge for their security assessments.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-8 mb-12">
            {/* Use Case 1 */}
            <div className="bg-gray-800 border border-gray-700 rounded-2xl p-8">
              <div className="flex items-center gap-3 mb-4">
                <div className="p-2 bg-cyan-500/10 rounded-lg">
                  <Shield className="w-6 h-6 text-cyan-400" />
                </div>
                <div>
                  <div className="text-white font-bold">Freelance Pentester</div>
                  <div className="text-gray-400 text-sm">Solo Tier</div>
                </div>
              </div>
              <p className="text-gray-300 mb-4 italic">
                "HeroForge cut my reporting time from 8 hours to 45 minutes. The AI prioritization helps me focus on what actually matters to my clients. ROI paid for itself on the first engagement."
              </p>
              <div className="flex items-center gap-2 text-sm">
                <Check className="w-4 h-4 text-green-400" />
                <span className="text-green-400 font-medium">8x faster reporting</span>
              </div>
            </div>

            {/* Use Case 2 */}
            <div className="bg-gray-800 border border-gray-700 rounded-2xl p-8">
              <div className="flex items-center gap-3 mb-4">
                <div className="p-2 bg-purple-500/10 rounded-lg">
                  <Users className="w-6 h-6 text-purple-400" />
                </div>
                <div>
                  <div className="text-white font-bold">Security Consultancy</div>
                  <div className="text-gray-400 text-sm">Team Tier</div>
                </div>
              </div>
              <p className="text-gray-300 mb-4 italic">
                "The customer portal transformed how we engage with clients. They love having 24/7 access to their security posture. Increased our contract renewals by 40%."
              </p>
              <div className="flex items-center gap-2 text-sm">
                <Check className="w-4 h-4 text-green-400" />
                <span className="text-green-400 font-medium">40% better retention</span>
              </div>
            </div>

            {/* Use Case 3 */}
            <div className="bg-gray-800 border border-gray-700 rounded-2xl p-8">
              <div className="flex items-center gap-3 mb-4">
                <div className="p-2 bg-blue-500/10 rounded-lg">
                  <Building2 className="w-6 h-6 text-blue-400" />
                </div>
                <div>
                  <div className="text-white font-bold">Managed Security Provider</div>
                  <div className="text-gray-400 text-sm">Team Tier</div>
                </div>
              </div>
              <p className="text-gray-300 mb-4 italic">
                "Switched from Tenable and saved $18K/year while gaining features they don't offer. CRM and time tracking made us way more efficient. Best decision we made in 2024."
              </p>
              <div className="flex items-center gap-2 text-sm">
                <Check className="w-4 h-4 text-green-400" />
                <span className="text-green-400 font-medium">$18K annual savings</span>
              </div>
            </div>
          </div>

          {/* Industry Stats */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
            <div className="bg-gradient-to-br from-cyan-600/10 to-blue-600/10 border border-cyan-500/20 rounded-xl p-6 text-center">
              <div className="text-3xl font-bold text-white mb-1">2,500+</div>
              <div className="text-gray-400 text-sm">Active Users</div>
            </div>
            <div className="bg-gradient-to-br from-purple-600/10 to-pink-600/10 border border-purple-500/20 rounded-xl p-6 text-center">
              <div className="text-3xl font-bold text-white mb-1">50M+</div>
              <div className="text-gray-400 text-sm">Hosts Scanned</div>
            </div>
            <div className="bg-gradient-to-br from-green-600/10 to-emerald-600/10 border border-green-500/20 rounded-xl p-6 text-center">
              <div className="text-3xl font-bold text-white mb-1">95%</div>
              <div className="text-gray-400 text-sm">Customer Satisfaction</div>
            </div>
            <div className="bg-gradient-to-br from-orange-600/10 to-red-600/10 border border-orange-500/20 rounded-xl p-6 text-center">
              <div className="text-3xl font-bold text-white mb-1">14 Days</div>
              <div className="text-gray-400 text-sm">Free Trial</div>
            </div>
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="py-20 px-4">
        <div className="max-w-4xl mx-auto text-center">
          <h2 className="text-3xl md:text-4xl font-bold text-white mb-4">
            Ready to Level Up Your Security Practice?
          </h2>
          <p className="text-xl text-gray-400 mb-8">
            Join hundreds of security professionals who trust HeroForge for their assessments.
          </p>
          <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
            <a
              href="#pricing"
              className="bg-cyan-600 hover:bg-cyan-700 text-white px-8 py-4 rounded-lg font-semibold text-lg transition-all hover:scale-105 flex items-center gap-2"
            >
              Start Your Free Trial
              <ArrowRight className="w-5 h-5" />
            </a>
            <a
              href="mailto:sales@genialarchitect.io"
              className="text-cyan-400 hover:text-cyan-300 font-semibold text-lg transition-colors"
            >
              Contact Sales
            </a>
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
                <li><a href="#features" className="text-gray-400 hover:text-white text-sm">Features</a></li>
                <li><a href="#pricing" className="text-gray-400 hover:text-white text-sm">Pricing</a></li>
                <li><a href="#faq" className="text-gray-400 hover:text-white text-sm">FAQ</a></li>
                <li><Link to="/" className="text-gray-400 hover:text-white text-sm">Login</Link></li>
              </ul>
            </div>
            <div>
              <h4 className="text-white font-semibold mb-4">Resources</h4>
              <ul className="space-y-2">
                <li><a href="/api/docs" className="text-gray-400 hover:text-white text-sm">API Docs</a></li>
                <li><a href="#" className="text-gray-400 hover:text-white text-sm">Documentation</a></li>
                <li><a href="#" className="text-gray-400 hover:text-white text-sm">Blog</a></li>
                <li><a href="#" className="text-gray-400 hover:text-white text-sm">Community</a></li>
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
              &copy; 2025 Genial Architect Cybersecurity Research Associates. All rights reserved.
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

export default SalesPage;
