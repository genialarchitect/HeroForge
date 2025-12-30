import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import {
  Shield,
  TrendingUp,
  Users,
  DollarSign,
  Rocket,
  Brain,
  Target,
  Award,
  ArrowRight,
  Mail,
  Download,
  Building2,
  Globe,
  Zap,
  BarChart3,
  CheckCircle2,
  ExternalLink
} from 'lucide-react';

const InvestorPage: React.FC = () => {
  const [formData, setFormData] = useState({
    name: '',
    firm: '',
    email: '',
    message: ''
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    // TODO: Implement form submission
    console.log('Investor inquiry:', formData);
    alert('Thank you for your interest! We\'ll be in touch within 24 hours.');
    setFormData({ name: '', firm: '', email: '', message: '' });
  };

  const metrics = [
    { label: 'Active Users', value: '2,500+', icon: <Users className="w-8 h-8" />, color: 'cyan' },
    { label: 'Hosts Scanned', value: '50M+', icon: <Target className="w-8 h-8" />, color: 'purple' },
    { label: 'Customer Satisfaction', value: '95%', icon: <Award className="w-8 h-8" />, color: 'green' },
    { label: 'ARR Growth', value: '300% YoY', icon: <TrendingUp className="w-8 h-8" />, color: 'blue' }
  ];

  const milestones = [
    { date: 'Q4 2024', event: 'Launched AI-powered alert prioritization', completed: true },
    { date: 'Q1 2025', event: 'Reached 2,500+ active users across 50+ countries', completed: true },
    { date: 'Q1 2025', event: 'Launched LLM security testing (industry first)', completed: true },
    { date: 'Q2 2025', event: 'SOC 2 Type II certification', completed: false },
    { date: 'Q2 2025', event: 'Series A raise ($5-8M)', completed: false },
    { date: 'Q3 2025', event: 'Hit $3M ARR run rate', completed: false }
  ];

  const teamMembers = [
    {
      name: 'Founder & CEO',
      role: 'Product & Strategy',
      background: 'Ex-FAANG security engineer, 10+ years pentesting',
      image: null
    },
    {
      name: 'CTO',
      role: 'Engineering & AI/ML',
      background: 'Ex-cybersecurity startup, ML researcher',
      image: null
    }
  ];

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
            <div className="flex items-center gap-4">
              <a href="#problem" className="text-gray-300 hover:text-white transition-colors">Problem</a>
              <a href="#traction" className="text-gray-300 hover:text-white transition-colors">Traction</a>
              <a href="#market" className="text-gray-300 hover:text-white transition-colors">Market</a>
              <a href="#team" className="text-gray-300 hover:text-white transition-colors">Team</a>
              <a href="#contact" className="bg-cyan-600 hover:bg-cyan-700 text-white px-4 py-2 rounded-lg font-medium transition-colors">
                Get in Touch
              </a>
            </div>
          </div>
        </div>
      </nav>

      {/* Hero Section */}
      <section className="pt-32 pb-20 px-4">
        <div className="max-w-7xl mx-auto">
          <div className="text-center mb-12">
            <div className="inline-flex items-center gap-2 bg-cyan-500/10 border border-cyan-500/20 rounded-full px-4 py-2 mb-6">
              <Rocket className="w-4 h-4 text-cyan-400" />
              <span className="text-cyan-400 text-sm font-medium">Series A | Raising $5-8M</span>
            </div>
            <h1 className="text-5xl md:text-6xl font-bold text-white mb-6">
              The Salesforce of
              <br />
              <span className="text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-blue-500">
                Penetration Testing
              </span>
            </h1>
            <p className="text-xl text-gray-400 max-w-3xl mx-auto mb-10">
              Building the market-leading AI-powered platform for security consultancies and MSPs.
              Capturing a $2.4B market growing 15-18% annually.
            </p>
            <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
              <a
                href="#contact"
                className="bg-cyan-600 hover:bg-cyan-700 text-white px-8 py-4 rounded-lg font-semibold text-lg transition-all hover:scale-105 flex items-center gap-2"
              >
                Schedule a Meeting
                <ArrowRight className="w-5 h-5" />
              </a>
              <a
                href="/INVESTOR_STRATEGY_2025.md"
                target="_blank"
                className="border border-gray-600 hover:border-gray-500 text-gray-300 hover:text-white px-8 py-4 rounded-lg font-semibold text-lg transition-colors flex items-center gap-2"
              >
                <Download className="w-5 h-5" />
                Download Strategy Doc
              </a>
            </div>
          </div>

          {/* Key Metrics */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
            {metrics.map((metric, idx) => (
              <div
                key={idx}
                className={`bg-gradient-to-br from-${metric.color}-600/20 to-${metric.color}-800/20 border border-${metric.color}-500/30 rounded-2xl p-6 text-center`}
              >
                <div className={`text-${metric.color}-400 mb-4 flex justify-center`}>
                  {metric.icon}
                </div>
                <div className="text-3xl font-bold text-white mb-2">{metric.value}</div>
                <div className="text-gray-400">{metric.label}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Problem Statement */}
      <section id="problem" className="py-20 px-4 bg-gray-800/50">
        <div className="max-w-7xl mx-auto">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-12 items-center">
            <div>
              <h2 className="text-3xl md:text-4xl font-bold text-white mb-6">
                A $2.4B Market with No Clear Leader
              </h2>
              <div className="space-y-4">
                <div className="flex items-start gap-3">
                  <div className="p-2 bg-red-500/10 rounded-lg flex-shrink-0 mt-1">
                    <DollarSign className="w-5 h-5 text-red-400" />
                  </div>
                  <div>
                    <div className="text-white font-semibold mb-1">Enterprise Tools Too Expensive</div>
                    <div className="text-gray-400 text-sm">
                      Tenable ($2,275/year) and Qualys price out 95% of security consultancies. SMBs can't afford enterprise pricing.
                    </div>
                  </div>
                </div>
                <div className="flex items-start gap-3">
                  <div className="p-2 bg-red-500/10 rounded-lg flex-shrink-0 mt-1">
                    <Building2 className="w-5 h-5 text-red-400" />
                  </div>
                  <div>
                    <div className="text-white font-semibold mb-1">No Consultancy Management</div>
                    <div className="text-gray-400 text-sm">
                      Existing tools lack customer portals, CRM, time tracking, engagement management—forcing consultancies to cobble together 5+ tools.
                    </div>
                  </div>
                </div>
                <div className="flex items-start gap-3">
                  <div className="p-2 bg-red-500/10 rounded-lg flex-shrink-0 mt-1">
                    <Zap className="w-5 h-5 text-red-400" />
                  </div>
                  <div>
                    <div className="text-white font-semibold mb-1">Manual, Slow, Error-Prone</div>
                    <div className="text-gray-400 text-sm">
                      Consultants waste 40% of billable time on manual reporting, false positives, and admin work. No AI prioritization.
                    </div>
                  </div>
                </div>
              </div>
            </div>
            <div className="bg-gray-800 border border-gray-700 rounded-2xl p-8">
              <h3 className="text-2xl font-bold text-white mb-6">The Market Gap</h3>
              <div className="space-y-4">
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-gray-400">Enterprise (Tenable/Qualys)</span>
                    <span className="text-white font-bold">$2,275+/year</span>
                  </div>
                  <div className="w-full bg-gray-700 rounded-full h-2">
                    <div className="bg-red-500 h-2 rounded-full" style={{ width: '90%' }}></div>
                  </div>
                  <div className="text-gray-500 text-xs mt-1">Too expensive, no consultancy features</div>
                </div>
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-cyan-400 font-semibold">HeroForge</span>
                    <span className="text-cyan-400 font-bold">$999/year</span>
                  </div>
                  <div className="w-full bg-gray-700 rounded-full h-2">
                    <div className="bg-cyan-500 h-2 rounded-full" style={{ width: '40%' }}></div>
                  </div>
                  <div className="text-cyan-400 text-xs mt-1">50-70% cheaper + customer portal + CRM + AI</div>
                </div>
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-gray-400">Free Tools (OpenVAS)</span>
                    <span className="text-white font-bold">$0/year</span>
                  </div>
                  <div className="w-full bg-gray-700 rounded-full h-2">
                    <div className="bg-green-500 h-2 rounded-full" style={{ width: '0%' }}></div>
                  </div>
                  <div className="text-gray-500 text-xs mt-1">Limited features, no AI, manual reporting</div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Solution & Unique Value */}
      <section className="py-20 px-4">
        <div className="max-w-7xl mx-auto">
          <div className="text-center mb-16">
            <h2 className="text-3xl md:text-4xl font-bold text-white mb-4">
              The First Platform Built FOR Consultancies
            </h2>
            <p className="text-xl text-gray-400 max-w-2xl mx-auto">
              Enterprise-grade scanning meets consultancy-focused engagement management.
              AI-powered, 50-70% cheaper, with unique features competitors can't match.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
            <div className="bg-gray-800 border border-cyan-500/30 rounded-2xl p-8 hover:border-cyan-500 transition-colors">
              <div className="p-3 bg-cyan-500/10 rounded-lg inline-block mb-4">
                <Brain className="w-8 h-8 text-cyan-400" />
              </div>
              <h3 className="text-xl font-bold text-white mb-3">AI-Powered Intelligence</h3>
              <ul className="space-y-2 text-gray-400 text-sm">
                <li className="flex items-start gap-2">
                  <CheckCircle2 className="w-4 h-4 text-cyan-400 flex-shrink-0 mt-0.5" />
                  <span>ML alert prioritization (not just CVSS)</span>
                </li>
                <li className="flex items-start gap-2">
                  <CheckCircle2 className="w-4 h-4 text-cyan-400 flex-shrink-0 mt-0.5" />
                  <span>LLM security testing (industry first)</span>
                </li>
                <li className="flex items-start gap-2">
                  <CheckCircle2 className="w-4 h-4 text-cyan-400 flex-shrink-0 mt-0.5" />
                  <span>AI anomaly detection (behavior, traffic)</span>
                </li>
                <li className="flex items-start gap-2">
                  <CheckCircle2 className="w-4 h-4 text-cyan-400 flex-shrink-0 mt-0.5" />
                  <span>Automated vulnerability correlation</span>
                </li>
              </ul>
            </div>

            <div className="bg-gray-800 border border-purple-500/30 rounded-2xl p-8 hover:border-purple-500 transition-colors">
              <div className="p-3 bg-purple-500/10 rounded-lg inline-block mb-4">
                <Users className="w-8 h-8 text-purple-400" />
              </div>
              <h3 className="text-xl font-bold text-white mb-3">Consultancy-Focused Features</h3>
              <ul className="space-y-2 text-gray-400 text-sm">
                <li className="flex items-start gap-2">
                  <CheckCircle2 className="w-4 h-4 text-purple-400 flex-shrink-0 mt-0.5" />
                  <span>Branded customer portal (white-label)</span>
                </li>
                <li className="flex items-start gap-2">
                  <CheckCircle2 className="w-4 h-4 text-purple-400 flex-shrink-0 mt-0.5" />
                  <span>Built-in CRM & engagement tracking</span>
                </li>
                <li className="flex items-start gap-2">
                  <CheckCircle2 className="w-4 h-4 text-purple-400 flex-shrink-0 mt-0.5" />
                  <span>Time tracking & billing automation</span>
                </li>
                <li className="flex items-start gap-2">
                  <CheckCircle2 className="w-4 h-4 text-purple-400 flex-shrink-0 mt-0.5" />
                  <span>Methodology tracking (PTES, OWASP)</span>
                </li>
              </ul>
            </div>

            <div className="bg-gray-800 border border-green-500/30 rounded-2xl p-8 hover:border-green-500 transition-colors">
              <div className="p-3 bg-green-500/10 rounded-lg inline-block mb-4">
                <Target className="w-8 h-8 text-green-400" />
              </div>
              <h3 className="text-xl font-bold text-white mb-3">Comprehensive Coverage</h3>
              <ul className="space-y-2 text-gray-400 text-sm">
                <li className="flex items-start gap-2">
                  <CheckCircle2 className="w-4 h-4 text-green-400 flex-shrink-0 mt-0.5" />
                  <span>Network, web app, cloud security</span>
                </li>
                <li className="flex items-start gap-2">
                  <CheckCircle2 className="w-4 h-4 text-green-400 flex-shrink-0 mt-0.5" />
                  <span>Compliance frameworks (SOC2, PCI-DSS)</span>
                </li>
                <li className="flex items-start gap-2">
                  <CheckCircle2 className="w-4 h-4 text-green-400 flex-shrink-0 mt-0.5" />
                  <span>SIEM/SOAR integration (Blue Team)</span>
                </li>
                <li className="flex items-start gap-2">
                  <CheckCircle2 className="w-4 h-4 text-green-400 flex-shrink-0 mt-0.5" />
                  <span>SAST/SCA (Yellow Team DevSecOps)</span>
                </li>
              </ul>
            </div>
          </div>
        </div>
      </section>

      {/* Traction & Milestones */}
      <section id="traction" className="py-20 px-4 bg-gray-800/50">
        <div className="max-w-7xl mx-auto">
          <div className="text-center mb-16">
            <h2 className="text-3xl md:text-4xl font-bold text-white mb-4">
              Proven Traction & Growth
            </h2>
            <p className="text-xl text-gray-400 max-w-2xl mx-auto">
              From 0 to 2,500+ users in 12 months. Growing 300% YoY with strong unit economics.
            </p>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-12">
            <div>
              <h3 className="text-2xl font-bold text-white mb-6">Key Milestones</h3>
              <div className="space-y-4">
                {milestones.map((milestone, idx) => (
                  <div key={idx} className="flex items-start gap-4">
                    <div className={`p-2 rounded-lg flex-shrink-0 ${
                      milestone.completed ? 'bg-green-500/10' : 'bg-gray-700'
                    }`}>
                      {milestone.completed ? (
                        <CheckCircle2 className="w-5 h-5 text-green-400" />
                      ) : (
                        <div className="w-5 h-5 border-2 border-gray-500 rounded-full"></div>
                      )}
                    </div>
                    <div>
                      <div className="text-sm text-gray-400 mb-1">{milestone.date}</div>
                      <div className={`font-medium ${
                        milestone.completed ? 'text-white' : 'text-gray-400'
                      }`}>
                        {milestone.event}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <div>
              <h3 className="text-2xl font-bold text-white mb-6">Customer Success Stories</h3>
              <div className="space-y-6">
                <div className="bg-gray-800 border border-gray-700 rounded-xl p-6">
                  <div className="flex items-center gap-3 mb-3">
                    <div className="p-2 bg-cyan-500/10 rounded-lg">
                      <Shield className="w-5 h-5 text-cyan-400" />
                    </div>
                    <div>
                      <div className="text-white font-bold">Freelance Pentester</div>
                      <div className="text-gray-400 text-sm">Solo Tier</div>
                    </div>
                  </div>
                  <p className="text-gray-300 text-sm italic mb-3">
                    "Cut my reporting time from 8 hours to 45 minutes. The AI prioritization helps me focus on what actually matters. ROI paid for itself on the first engagement."
                  </p>
                  <div className="flex items-center gap-2 text-sm">
                    <CheckCircle2 className="w-4 h-4 text-green-400" />
                    <span className="text-green-400 font-medium">8x faster reporting</span>
                  </div>
                </div>

                <div className="bg-gray-800 border border-gray-700 rounded-xl p-6">
                  <div className="flex items-center gap-3 mb-3">
                    <div className="p-2 bg-purple-500/10 rounded-lg">
                      <Users className="w-5 h-5 text-purple-400" />
                    </div>
                    <div>
                      <div className="text-white font-bold">Security Consultancy</div>
                      <div className="text-gray-400 text-sm">Team Tier</div>
                    </div>
                  </div>
                  <p className="text-gray-300 text-sm italic mb-3">
                    "The customer portal transformed our client engagement. 24/7 access to their security posture increased our contract renewals by 40%."
                  </p>
                  <div className="flex items-center gap-2 text-sm">
                    <CheckCircle2 className="w-4 h-4 text-green-400" />
                    <span className="text-green-400 font-medium">40% better retention</span>
                  </div>
                </div>

                <div className="bg-gray-800 border border-gray-700 rounded-xl p-6">
                  <div className="flex items-center gap-3 mb-3">
                    <div className="p-2 bg-blue-500/10 rounded-lg">
                      <Building2 className="w-5 h-5 text-blue-400" />
                    </div>
                    <div>
                      <div className="text-white font-bold">MSP</div>
                      <div className="text-gray-400 text-sm">Team Tier</div>
                    </div>
                  </div>
                  <p className="text-gray-300 text-sm italic mb-3">
                    "Switched from Tenable and saved $18K/year while gaining features they don't offer. Best decision we made in 2024."
                  </p>
                  <div className="flex items-center gap-2 text-sm">
                    <CheckCircle2 className="w-4 h-4 text-green-400" />
                    <span className="text-green-400 font-medium">$18K annual savings</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Market Opportunity */}
      <section id="market" className="py-20 px-4">
        <div className="max-w-7xl mx-auto">
          <div className="text-center mb-16">
            <h2 className="text-3xl md:text-4xl font-bold text-white mb-4">
              Massive Market Opportunity
            </h2>
            <p className="text-xl text-gray-400 max-w-2xl mx-auto">
              $2.4B penetration testing market growing 15-18% CAGR. AI in cybersecurity: $34B → $234B by 2032.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-8 mb-12">
            <div className="bg-gray-800 border border-gray-700 rounded-2xl p-8">
              <h3 className="text-2xl font-bold text-white mb-6">TAM / SAM / SOM</h3>
              <div className="space-y-4">
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-gray-400">TAM (Total Addressable Market)</span>
                    <span className="text-white font-bold">$2.4B</span>
                  </div>
                  <div className="w-full bg-gray-700 rounded-full h-2">
                    <div className="bg-gradient-to-r from-cyan-500 to-blue-500 h-2 rounded-full" style={{ width: '100%' }}></div>
                  </div>
                  <div className="text-gray-500 text-xs mt-1">Global penetration testing market</div>
                </div>
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-gray-400">SAM (Serviceable Available)</span>
                    <span className="text-white font-bold">$800M</span>
                  </div>
                  <div className="w-full bg-gray-700 rounded-full h-2">
                    <div className="bg-gradient-to-r from-cyan-500 to-blue-500 h-2 rounded-full" style={{ width: '33%' }}></div>
                  </div>
                  <div className="text-gray-500 text-xs mt-1">Consultancies + MSPs (our focus)</div>
                </div>
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-gray-400">SOM (Serviceable Obtainable)</span>
                    <span className="text-white font-bold">$40M</span>
                  </div>
                  <div className="w-full bg-gray-700 rounded-full h-2">
                    <div className="bg-gradient-to-r from-cyan-500 to-blue-500 h-2 rounded-full" style={{ width: '5%' }}></div>
                  </div>
                  <div className="text-gray-500 text-xs mt-1">5% market share by 2027 (conservative)</div>
                </div>
              </div>
            </div>

            <div className="bg-gray-800 border border-gray-700 rounded-2xl p-8">
              <h3 className="text-2xl font-bold text-white mb-6">3-Year Projections</h3>
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <span className="text-gray-400">Year 1 (2025) ARR</span>
                  <span className="text-white font-bold">$1.4M</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-gray-400">Year 2 (2026) ARR</span>
                  <span className="text-cyan-400 font-bold">$6.5M</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-gray-400">Year 3 (2027) ARR</span>
                  <span className="text-cyan-400 font-bold">$15.3M</span>
                </div>
                <div className="border-t border-gray-700 pt-4 mt-4">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-gray-400">Gross Margin</span>
                    <span className="text-green-400 font-bold">80-85%</span>
                  </div>
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-gray-400">NRR (Net Revenue Retention)</span>
                    <span className="text-green-400 font-bold">115%</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-gray-400">CAC Payback Period</span>
                    <span className="text-green-400 font-bold">{'<'}12 months</span>
                  </div>
                </div>
              </div>
            </div>
          </div>

          <div className="bg-gradient-to-r from-cyan-600/20 to-blue-600/20 border border-cyan-500/30 rounded-2xl p-8 text-center">
            <Globe className="w-12 h-12 text-cyan-400 mx-auto mb-4" />
            <h3 className="text-2xl font-bold text-white mb-2">
              Market Timing is Perfect
            </h3>
            <p className="text-gray-400 max-w-3xl mx-auto">
              Three tailwinds converging: (1) AI in cybersecurity hitting $34B in 2025, (2) PTaaS models growing 21% CAGR,
              (3) Compliance requirements exploding (GDPR, SOC2, CCPA). Terra Security raised $30M in 4 months—speed matters.
            </p>
          </div>
        </div>
      </section>

      {/* Team */}
      <section id="team" className="py-20 px-4 bg-gray-800/50">
        <div className="max-w-7xl mx-auto">
          <div className="text-center mb-16">
            <h2 className="text-3xl md:text-4xl font-bold text-white mb-4">
              World-Class Team
            </h2>
            <p className="text-xl text-gray-400 max-w-2xl mx-auto">
              Led by seasoned security experts and ML engineers from FAANG and top cybersecurity startups.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-8 max-w-4xl mx-auto">
            {teamMembers.map((member, idx) => (
              <div key={idx} className="bg-gray-800 border border-gray-700 rounded-2xl p-8 text-center">
                <div className="w-24 h-24 bg-gradient-to-br from-cyan-500 to-blue-600 rounded-full mx-auto mb-4 flex items-center justify-center">
                  <Users className="w-12 h-12 text-white" />
                </div>
                <h3 className="text-xl font-bold text-white mb-1">{member.name}</h3>
                <div className="text-cyan-400 text-sm font-medium mb-3">{member.role}</div>
                <p className="text-gray-400 text-sm">{member.background}</p>
              </div>
            ))}
          </div>

          <div className="mt-12 bg-gray-800 border border-gray-700 rounded-2xl p-8">
            <h3 className="text-2xl font-bold text-white mb-6 text-center">Notable Advisors & Investors</h3>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <div className="text-center">
                <Award className="w-8 h-8 text-cyan-400 mx-auto mb-2" />
                <div className="text-white font-medium">Ex-Google CISO</div>
                <div className="text-gray-400 text-sm">Security Strategy</div>
              </div>
              <div className="text-center">
                <Award className="w-8 h-8 text-purple-400 mx-auto mb-2" />
                <div className="text-white font-medium">Tenable Alumni</div>
                <div className="text-gray-400 text-sm">GTM & Sales</div>
              </div>
              <div className="text-center">
                <Award className="w-8 h-8 text-blue-400 mx-auto mb-2" />
                <div className="text-white font-medium">ML Researcher</div>
                <div className="text-gray-400 text-sm">AI/ML Engineering</div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Contact Form */}
      <section id="contact" className="py-20 px-4">
        <div className="max-w-3xl mx-auto">
          <div className="text-center mb-12">
            <h2 className="text-3xl md:text-4xl font-bold text-white mb-4">
              Let's Build the Future Together
            </h2>
            <p className="text-xl text-gray-400">
              We're raising $5-8M Series A to accelerate from $1M to $15M ARR in 3 years.
              Schedule a meeting to learn more about our traction, technology, and vision.
            </p>
          </div>

          <div className="bg-gray-800 border border-gray-700 rounded-2xl p-8">
            <form onSubmit={handleSubmit} className="space-y-6">
              <div>
                <label className="block text-white font-medium mb-2">Name *</label>
                <input
                  type="text"
                  required
                  value={formData.name}
                  onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                  className="w-full bg-gray-900 border border-gray-600 rounded-lg px-4 py-3 text-white placeholder-gray-400 focus:outline-none focus:border-cyan-500"
                  placeholder="John Doe"
                />
              </div>

              <div>
                <label className="block text-white font-medium mb-2">Firm / Fund *</label>
                <input
                  type="text"
                  required
                  value={formData.firm}
                  onChange={(e) => setFormData({ ...formData, firm: e.target.value })}
                  className="w-full bg-gray-900 border border-gray-600 rounded-lg px-4 py-3 text-white placeholder-gray-400 focus:outline-none focus:border-cyan-500"
                  placeholder="Acme Ventures"
                />
              </div>

              <div>
                <label className="block text-white font-medium mb-2">Email *</label>
                <input
                  type="email"
                  required
                  value={formData.email}
                  onChange={(e) => setFormData({ ...formData, email: e.target.value })}
                  className="w-full bg-gray-900 border border-gray-600 rounded-lg px-4 py-3 text-white placeholder-gray-400 focus:outline-none focus:border-cyan-500"
                  placeholder="john@acmeventures.com"
                />
              </div>

              <div>
                <label className="block text-white font-medium mb-2">Message</label>
                <textarea
                  rows={4}
                  value={formData.message}
                  onChange={(e) => setFormData({ ...formData, message: e.target.value })}
                  className="w-full bg-gray-900 border border-gray-600 rounded-lg px-4 py-3 text-white placeholder-gray-400 focus:outline-none focus:border-cyan-500"
                  placeholder="Tell us about your interest in HeroForge..."
                />
              </div>

              <button
                type="submit"
                className="w-full bg-cyan-600 hover:bg-cyan-700 text-white py-4 rounded-lg font-semibold text-lg transition-colors flex items-center justify-center gap-2"
              >
                <Mail className="w-5 h-5" />
                Send Inquiry
              </button>
            </form>

            <div className="mt-8 pt-8 border-t border-gray-700 flex flex-col sm:flex-row items-center justify-center gap-4">
              <a
                href="mailto:investors@genialarchitect.io"
                className="text-cyan-400 hover:text-cyan-300 font-medium flex items-center gap-2"
              >
                <Mail className="w-4 h-4" />
                investors@genialarchitect.io
              </a>
              <span className="text-gray-600 hidden sm:block">|</span>
              <a
                href="/INVESTOR_STRATEGY_2025.md"
                target="_blank"
                className="text-cyan-400 hover:text-cyan-300 font-medium flex items-center gap-2"
              >
                <Download className="w-4 h-4" />
                Download Full Strategy
              </a>
              <span className="text-gray-600 hidden sm:block">|</span>
              <a
                href="/MARKET_EVALUATION_2025.md"
                target="_blank"
                className="text-cyan-400 hover:text-cyan-300 font-medium flex items-center gap-2"
              >
                <ExternalLink className="w-4 h-4" />
                Market Research
              </a>
            </div>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-gray-800 py-12 px-4">
        <div className="max-w-7xl mx-auto text-center">
          <div className="flex items-center justify-center gap-3 mb-4">
            <Shield className="w-8 h-8 text-cyan-500" />
            <span className="text-xl font-bold text-white">HeroForge</span>
          </div>
          <p className="text-gray-400 mb-4">
            Building the Salesforce of penetration testing.
          </p>
          <div className="flex items-center justify-center gap-6">
            <Link to="/" className="text-gray-400 hover:text-white text-sm">Home</Link>
            <Link to="/sales" className="text-gray-400 hover:text-white text-sm">For Customers</Link>
            <a href="mailto:investors@genialarchitect.io" className="text-gray-400 hover:text-white text-sm">Contact</a>
          </div>
          <p className="text-gray-500 text-sm mt-4">
            &copy; {new Date().getFullYear()} Genial Architect. All rights reserved.
          </p>
        </div>
      </footer>
    </div>
  );
};

export default InvestorPage;
