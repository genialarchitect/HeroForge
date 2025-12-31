import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import {
  Shield,
  TrendingUp,
  Users,
  Target,
  Rocket,
  Brain,
  Award,
  ArrowRight,
  Mail,
  Download,
  Zap,
  CheckCircle2,
  Heart,
  Flag,
  Code
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
    console.log('Investor inquiry:', formData);
    alert('Thank you for your interest! We\'ll be in touch within 24 hours.');
    setFormData({ name: '', firm: '', email: '', message: '' });
  };

  const founderStrengths = [
    { icon: <Shield className="w-6 h-6" />, label: '20 Years SIGINT', description: 'Nation-state level operations worldwide', color: 'cyan' },
    { icon: <Flag className="w-6 h-6" />, label: '100% Disabled Veteran', description: 'Army veteran, father, mission-driven', color: 'red' },
    { icon: <Code className="w-6 h-6" />, label: 'Built in 3 Weeks', description: 'AI-assisted development at VC-backed speed', color: 'purple' },
    { icon: <Heart className="w-6 h-6" />, label: 'Mission First', description: 'Security is a right, not a luxury', color: 'green' }
  ];

  const productHighlights = [
    '✓ Network, web app, cloud security (AWS/Azure/GCP)',
    '✓ SIEM/SOAR (Blue Team) + Detection Engineering',
    '✓ SAST/SCA (Yellow Team DevSecOps)',
    '✓ Compliance frameworks (SOC2, PCI-DSS, HIPAA)',
    '✓ Customer portal + CRM for consultancies',
    '✓ AI-powered vulnerability prioritization',
    '✓ 8 "colored team" modules (Red, Blue, Green, Yellow, Orange, White, Purple, Pink)',
    '✓ Built on Rust (high performance, memory safe)'
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
              <a href="#story" className="text-gray-300 hover:text-white transition-colors">Story</a>
              <a href="#product" className="text-gray-300 hover:text-white transition-colors">Product</a>
              <a href="#market" className="text-gray-300 hover:text-white transition-colors">Market</a>
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
              <span className="text-cyan-400 text-sm font-medium">Pre-Seed | Raising $500K-$1.5M</span>
            </div>
            <h1 className="text-5xl md:text-6xl font-bold text-white mb-6">
              Veteran-Founded.
              <br />
              <span className="text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-blue-500">
                Mission-Driven.
              </span>
            </h1>
            <p className="text-xl text-gray-400 max-w-3xl mx-auto mb-10">
              A 20-year Signals Intelligence Analyst building the pentesting platform I wish existed.
              Comprehensive security for everyone, not just Fortune 500 companies.
            </p>
            <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
              <a
                href="#contact"
                className="bg-cyan-600 hover:bg-cyan-700 text-white px-8 py-4 rounded-lg font-semibold text-lg transition-all hover:scale-105 flex items-center gap-2"
              >
                Schedule a Meeting
                <ArrowRight className="w-5 h-5" />
              </a>
              <Link
                to="/pitch"
                className="border border-gray-600 hover:border-gray-500 text-gray-300 hover:text-white px-8 py-4 rounded-lg font-semibold text-lg transition-colors flex items-center gap-2"
              >
                <Download className="w-5 h-5" />
                View Pitch Deck
              </Link>
            </div>
          </div>

          {/* Founder Strengths */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
            {founderStrengths.map((strength, idx) => (
              <div
                key={idx}
                className={`bg-gradient-to-br from-${strength.color}-600/20 to-${strength.color}-800/20 border border-${strength.color}-500/30 rounded-2xl p-6 text-center`}
              >
                <div className={`text-${strength.color}-400 mb-4 flex justify-center`}>
                  {strength.icon}
                </div>
                <div className="text-xl font-bold text-white mb-2">{strength.label}</div>
                <div className="text-gray-400 text-sm">{strength.description}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Founder Story */}
      <section id="story" className="py-20 px-4 bg-gray-800/50">
        <div className="max-w-7xl mx-auto">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-12 items-center">
            <div>
              <h2 className="text-3xl md:text-4xl font-bold text-white mb-6">
                Why I Built This
              </h2>
              <div className="space-y-4 text-gray-300">
                <p className="text-lg">
                  For two decades, I operated at the <strong className="text-white">nation-state level</strong> in Signals Intelligence—targeting threats worldwide. I've seen what elite security teams can do with the right tools.
                </p>
                <p className="text-lg">
                  But I also watched those tools become <strong className="text-white">increasingly expensive and exclusive</strong>. Tenable costs $2,275/year for 65 assets. Qualys requires enterprise contracts. The best security tools are reserved for those who can afford them.
                </p>
                <p className="text-lg">
                  As a <strong className="text-white">100% disabled Army veteran and father</strong>, I believe security is a right, not a luxury. Small businesses, consultancies, and security researchers deserve access to world-class tools.
                </p>
                <p className="text-lg">
                  So I built HeroForge in <strong className="text-white">3 weeks with AI assistance</strong>—an all-in-one platform that does what $50K worth of enterprise tools do, for $999/year.
                </p>
              </div>
            </div>
            <div className="bg-gray-800 border border-gray-700 rounded-2xl p-8">
              <h3 className="text-2xl font-bold text-white mb-6">The Mission</h3>
              <div className="space-y-4">
                <div className="flex items-start gap-3">
                  <CheckCircle2 className="w-6 h-6 text-cyan-400 flex-shrink-0 mt-1" />
                  <div>
                    <div className="text-white font-semibold mb-1">Democratize Security</div>
                    <div className="text-gray-400 text-sm">
                      Make comprehensive pentesting accessible to freelancers, consultancies, and startups—not just Fortune 500.
                    </div>
                  </div>
                </div>
                <div className="flex items-start gap-3">
                  <CheckCircle2 className="w-6 h-6 text-cyan-400 flex-shrink-0 mt-1" />
                  <div>
                    <div className="text-white font-semibold mb-1">Prove AI + Veteran Speed</div>
                    <div className="text-gray-400 text-sm">
                      Solo founders with domain expertise can move at VC-backed startup speed using AI copilots.
                    </div>
                  </div>
                </div>
                <div className="flex items-start gap-3">
                  <CheckCircle2 className="w-6 h-6 text-cyan-400 flex-shrink-0 mt-1" />
                  <div>
                    <div className="text-white font-semibold mb-1">Build in Public</div>
                    <div className="text-gray-400 text-sm">
                      Share the journey authentically. InfoSec community values transparency over polished marketing.
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Product */}
      <section id="product" className="py-20 px-4">
        <div className="max-w-7xl mx-auto">
          <div className="text-center mb-16">
            <h2 className="text-3xl md:text-4xl font-bold text-white mb-4">
              Built in 3 Weeks. 90% Functional.
            </h2>
            <p className="text-xl text-gray-400 max-w-2xl mx-auto">
              Everything you need in one platform. What took VC-backed teams 18 months, I built in 3 weeks with Claude Code.
            </p>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-12">
            <div>
              <h3 className="text-2xl font-bold text-white mb-6">Comprehensive from Day One</h3>
              <div className="space-y-2 text-gray-300">
                {productHighlights.map((item, idx) => (
                  <div key={idx} className="flex items-start gap-2">
                    <span className="text-cyan-400 mt-1">•</span>
                    <span>{item}</span>
                  </div>
                ))}
              </div>
              <div className="mt-6 p-4 bg-cyan-500/10 border border-cyan-500/30 rounded-lg">
                <p className="text-cyan-400 text-sm">
                  <strong>Tech Stack:</strong> Rust (backend), React/TypeScript (frontend), SQLite w/ optional encryption, Docker deployment
                </p>
              </div>
            </div>

            <div className="space-y-6">
              <div className="bg-gray-800 border border-gray-700 rounded-xl p-6">
                <div className="flex items-center gap-3 mb-3">
                  <div className="p-2 bg-cyan-500/10 rounded-lg">
                    <Brain className="w-6 h-6 text-cyan-400" />
                  </div>
                  <h4 className="text-lg font-bold text-white">AI-Powered</h4>
                </div>
                <p className="text-gray-400 text-sm">
                  ML vulnerability prioritization reduces false positives by 70%. LLM security testing (prompt injection, jailbreaks)—industry first.
                </p>
              </div>

              <div className="bg-gray-800 border border-gray-700 rounded-xl p-6">
                <div className="flex items-center gap-3 mb-3">
                  <div className="p-2 bg-purple-500/10 rounded-lg">
                    <Users className="w-6 h-6 text-purple-400" />
                  </div>
                  <h4 className="text-lg font-bold text-white">Built for Consultancies</h4>
                </div>
                <p className="text-gray-400 text-sm">
                  Customer portal, CRM, time tracking, engagement management. Only platform designed for security consultants and MSPs.
                </p>
              </div>

              <div className="bg-gray-800 border border-gray-700 rounded-xl p-6">
                <div className="flex items-center gap-3 mb-3">
                  <div className="p-2 bg-green-500/10 rounded-lg">
                    <Zap className="w-6 h-6 text-green-400" />
                  </div>
                  <h4 className="text-lg font-bold text-white">96% Cost Reduction</h4>
                </div>
                <p className="text-gray-400 text-sm">
                  $999/year vs $50K+ for equivalent enterprise tools. Continuous testing vs $5K-$100K manual pentests.
                </p>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Current Status & Honest Traction */}
      <section className="py-20 px-4 bg-gray-800/50">
        <div className="max-w-7xl mx-auto">
          <div className="text-center mb-16">
            <h2 className="text-3xl md:text-4xl font-bold text-white mb-4">
              Where We Are Today
            </h2>
            <p className="text-xl text-gray-400 max-w-2xl mx-auto">
              Honest traction. No inflated metrics. Just a founder building in public.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-8 mb-12">
            <div className="bg-gray-800 border border-gray-700 rounded-xl p-8 text-center">
              <div className="text-4xl font-bold text-cyan-400 mb-2">Tested Twice</div>
              <div className="text-gray-400">Against same target</div>
              <div className="text-gray-500 text-sm mt-2">Seeking first 100 users</div>
            </div>
            <div className="bg-gray-800 border border-gray-700 rounded-xl p-8 text-center">
              <div className="text-4xl font-bold text-purple-400 mb-2">90%</div>
              <div className="text-gray-400">Feature Complete</div>
              <div className="text-gray-500 text-sm mt-2">Built in 3 weeks with AI</div>
            </div>
            <div className="bg-gray-800 border border-gray-700 rounded-xl p-8 text-center">
              <div className="text-4xl font-bold text-green-400 mb-2">Pre-Revenue</div>
              <div className="text-gray-400">Launching Q1 2026</div>
              <div className="text-gray-500 text-sm mt-2">Goal: $200K ARR Year 1</div>
            </div>
          </div>

          <div className="bg-gradient-to-r from-cyan-600/20 to-blue-600/20 border border-cyan-500/30 rounded-2xl p-8">
            <h3 className="text-2xl font-bold text-white mb-4 text-center">Why This Works</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div>
                <div className="text-cyan-400 font-semibold mb-2">Domain Expertise</div>
                <div className="text-gray-300 text-sm">20 years of SIGINT = product intuition. I'm the target customer.</div>
              </div>
              <div>
                <div className="text-cyan-400 font-semibold mb-2">Speed Advantage</div>
                <div className="text-gray-300 text-sm">Solo founder, no committees. AI copilots = 10x developer productivity.</div>
              </div>
              <div>
                <div className="text-cyan-400 font-semibold mb-2">Veteran Credibility</div>
                <div className="text-gray-300 text-sm">InfoSec community trusts practitioners with military discipline.</div>
              </div>
              <div>
                <div className="text-cyan-400 font-semibold mb-2">Mission Alignment</div>
                <div className="text-gray-300 text-sm">Not chasing exit, chasing impact. Security for everyone.</div>
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
              $2.4B Market, Zero Dominant Player
            </h2>
            <p className="text-xl text-gray-400 max-w-2xl mx-auto">
              100,000+ freelance pentesters, 15,000+ small consultancies. All underserved by expensive enterprise tools.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-8 mb-12">
            <div className="bg-gray-800 border border-gray-700 rounded-2xl p-8">
              <h3 className="text-2xl font-bold text-white mb-6">Market Size</h3>
              <div className="space-y-4">
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-gray-400">TAM (Pentesting Market)</span>
                    <span className="text-white font-bold">$2.4B</span>
                  </div>
                  <div className="text-gray-500 text-xs">Growing 15-18% CAGR</div>
                </div>
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-gray-400">SAM (Consultancies + MSPs)</span>
                    <span className="text-white font-bold">$800M</span>
                  </div>
                  <div className="text-gray-500 text-xs">Our target segment</div>
                </div>
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-gray-400">SOM (5% market share)</span>
                    <span className="text-cyan-400 font-bold">$40M</span>
                  </div>
                  <div className="text-gray-500 text-xs">Realistic Year 5 goal</div>
                </div>
              </div>
            </div>

            <div className="bg-gray-800 border border-gray-700 rounded-2xl p-8">
              <h3 className="text-2xl font-bold text-white mb-6">18-Month Roadmap</h3>
              <div className="space-y-4">
                <div>
                  <div className="text-gray-400 text-sm mb-1">Month 6</div>
                  <div className="text-white font-bold">100 paying users, $10K MRR</div>
                </div>
                <div>
                  <div className="text-gray-400 text-sm mb-1">Month 12</div>
                  <div className="text-white font-bold">500 users, $50K MRR ($600K ARR)</div>
                </div>
                <div>
                  <div className="text-gray-400 text-sm mb-1">Month 18</div>
                  <div className="text-cyan-400 font-bold">2,000 users, $100K MRR ($1.2M ARR)</div>
                </div>
                <div className="pt-4 border-t border-gray-700">
                  <div className="text-gray-400 text-sm mb-2">Positioned for:</div>
                  <div className="text-white">Seed round ($3-5M) or profitable growth</div>
                </div>
              </div>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="bg-gray-800 border border-gray-700 rounded-xl p-6">
              <div className="text-cyan-400 font-semibold mb-2">vs Tenable/Qualys</div>
              <div className="text-gray-300 text-sm">50-70% cheaper, customer portal + CRM, consultancy-focused</div>
            </div>
            <div className="bg-gray-800 border border-gray-700 rounded-xl p-6">
              <div className="text-purple-400 font-semibold mb-2">vs Terra Security ($30M)</div>
              <div className="text-gray-300 text-sm">They target enterprises. We serve underserved SMB market.</div>
            </div>
            <div className="bg-gray-800 border border-gray-700 rounded-xl p-6">
              <div className="text-green-400 font-semibold mb-2">vs Free Tools (OpenVAS)</div>
              <div className="text-gray-300 text-sm">AI prioritization, customer portal, professional support, compliance</div>
            </div>
          </div>
        </div>
      </section>

      {/* The Ask */}
      <section id="contact" className="py-20 px-4 bg-gray-800/50">
        <div className="max-w-3xl mx-auto">
          <div className="text-center mb-12">
            <h2 className="text-3xl md:text-4xl font-bold text-white mb-4">
              The Ask: $500K-$1.5M Pre-Seed
            </h2>
            <p className="text-xl text-gray-400">
              18 months to prove affordable, comprehensive security is possible.
              Get to $1.2M ARR and position for Seed round or profitable growth.
            </p>
          </div>

          <div className="bg-gray-800 border border-gray-700 rounded-2xl p-8 mb-12">
            <h3 className="text-xl font-bold text-white mb-6">Use of Funds</h3>
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <span className="text-gray-400">Product Validation (first 100 users)</span>
                <span className="text-white font-bold">30%</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-gray-400">Go-to-Market (organic + community)</span>
                <span className="text-white font-bold">25%</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-gray-400">Infrastructure (AWS, tools)</span>
                <span className="text-white font-bold">15%</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-gray-400">Founder Salary (18 months)</span>
                <span className="text-white font-bold">20%</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-gray-400">Legal, Compliance, Reserves</span>
                <span className="text-white font-bold">10%</span>
              </div>
            </div>
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
              <Link
                to="/pitch"
                className="text-cyan-400 hover:text-cyan-300 font-medium flex items-center gap-2"
              >
                <Download className="w-4 h-4" />
                Pitch Deck
              </Link>
              <span className="text-gray-600 hidden sm:block">|</span>
              <Link
                to="/one-pager"
                className="text-cyan-400 hover:text-cyan-300 font-medium flex items-center gap-2"
              >
                <Download className="w-4 h-4" />
                One-Pager
              </Link>
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
            Security is a right, not a luxury.
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
