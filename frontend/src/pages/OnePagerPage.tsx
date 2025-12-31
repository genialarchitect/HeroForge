import React from 'react';
import {
  Shield,
  TrendingUp,
  Users,
  Target,
  Zap,
  Award,
  Download,
  Mail,
  Calendar,
} from 'lucide-react';

const OnePagerPage: React.FC = () => {
  const handlePrint = () => {
    window.print();
  };

  return (
    <div className="min-h-screen bg-white text-gray-900">
      {/* Print Utilities */}
      <style>{`
        @media print {
          .no-print { display: none !important; }
          .print-page { page-break-after: always; }
          body { print-color-adjust: exact; -webkit-print-color-adjust: exact; }
        }
      `}</style>

      {/* Header Bar (no print) */}
      <div className="no-print bg-gradient-to-r from-cyan-600 to-blue-600 px-6 py-4 flex justify-between items-center">
        <h1 className="text-white text-xl font-bold">HeroForge One-Pager</h1>
        <button
          onClick={handlePrint}
          className="flex items-center gap-2 bg-white text-cyan-600 px-4 py-2 rounded-lg font-semibold hover:bg-gray-100 transition"
        >
          <Download className="w-4 h-4" />
          Download / Print
        </button>
      </div>

      {/* Main One-Pager Content */}
      <div className="max-w-4xl mx-auto p-12 print-page">
        {/* Header */}
        <div className="border-b-4 border-cyan-600 pb-6 mb-6">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-4xl font-bold text-gray-900 mb-2">HeroForge</h1>
              <p className="text-xl text-gray-600">
                Autonomous Pentesting & Security Operations Platform
              </p>
            </div>
            <div className="text-right text-sm text-gray-600">
              <p className="font-semibold">Pre-Seed Fundraise</p>
              <p>$500K-$1.5M</p>
              <p>December 2025</p>
            </div>
          </div>
        </div>

        {/* Company Overview */}
        <div className="mb-6">
          <div className="flex items-center gap-2 mb-3">
            <Shield className="w-5 h-5 text-cyan-600" />
            <h2 className="text-lg font-bold text-gray-900 uppercase tracking-wide">
              Company Overview
            </h2>
          </div>
          <p className="text-gray-700 leading-relaxed mb-3">
            HeroForge is an all-in-one cybersecurity platform that automates penetration testing,
            vulnerability management, and security operations. Built by a 20-year Signals Intelligence
            Analyst (nation-state level operations worldwide), 100% disabled Army veteran, and father
            on a mission: <strong>Security is a right, not a luxury.</strong>
          </p>
          <p className="text-gray-700 leading-relaxed">
            We replace $2,000-$100,000 manual pentesting engagements with continuous,
            AI-powered security testing—reducing costs by 96% while enabling 24/7 monitoring instead
            of periodic assessments. Built in 3 weeks with AI-assisted development, achieving what
            VC-backed teams do in 12+ months.
          </p>
        </div>

        {/* Two-Column Layout */}
        <div className="grid grid-cols-2 gap-6 mb-6">
          {/* Problem */}
          <div>
            <div className="flex items-center gap-2 mb-3">
              <Target className="w-5 h-5 text-red-600" />
              <h2 className="text-lg font-bold text-gray-900 uppercase tracking-wide">
                The Problem
              </h2>
            </div>
            <ul className="space-y-2 text-sm text-gray-700">
              <li className="flex items-start gap-2">
                <span className="text-red-600 font-bold">•</span>
                <span>
                  <strong>Manual pentesting is expensive:</strong> $5K-$100K per engagement,
                  limiting testing to once or twice per year
                </span>
              </li>
              <li className="flex items-start gap-2">
                <span className="text-red-600 font-bold">•</span>
                <span>
                  <strong>Existing tools are fragmented:</strong> Security teams juggle 10+ tools
                  (Nessus, Burp Suite, Metasploit), wasting hours on integration
                </span>
              </li>
              <li className="flex items-start gap-2">
                <span className="text-red-600 font-bold">•</span>
                <span>
                  <strong>Consultancies lack client management:</strong> No built-in CRM, customer
                  portals, or white-label branding
                </span>
              </li>
            </ul>
          </div>

          {/* Solution */}
          <div>
            <div className="flex items-center gap-2 mb-3">
              <Zap className="w-5 h-5 text-cyan-600" />
              <h2 className="text-lg font-bold text-gray-900 uppercase tracking-wide">
                Our Solution
              </h2>
            </div>
            <ul className="space-y-2 text-sm text-gray-700">
              <li className="flex items-start gap-2">
                <span className="text-cyan-600 font-bold">✓</span>
                <span>
                  <strong>Automated pentesting:</strong> Continuous network, web app, cloud, and
                  container scanning with AI-powered prioritization
                </span>
              </li>
              <li className="flex items-start gap-2">
                <span className="text-cyan-600 font-bold">✓</span>
                <span>
                  <strong>All-in-one platform:</strong> Red team, blue team, GRC, and DevSecOps
                  tools unified in one interface
                </span>
              </li>
              <li className="flex items-start gap-2">
                <span className="text-cyan-600 font-bold">✓</span>
                <span>
                  <strong>Built for consultancies:</strong> Customer portals, CRM, time tracking,
                  and white-label branding
                </span>
              </li>
            </ul>
          </div>
        </div>

        {/* Key Metrics */}
        <div className="bg-gray-50 border-2 border-gray-200 rounded-lg p-4 mb-6">
          <div className="flex items-center gap-2 mb-3">
            <TrendingUp className="w-5 h-5 text-green-600" />
            <h2 className="text-lg font-bold text-gray-900 uppercase tracking-wide">
              Current Status
            </h2>
          </div>
          <div className="grid grid-cols-4 gap-4">
            <div className="text-center">
              <p className="text-3xl font-bold text-cyan-600">Pre-Revenue</p>
              <p className="text-xs text-gray-600 uppercase tracking-wide">Status</p>
            </div>
            <div className="text-center">
              <p className="text-3xl font-bold text-cyan-600">90%</p>
              <p className="text-xs text-gray-600 uppercase tracking-wide">Feature Complete</p>
            </div>
            <div className="text-center">
              <p className="text-3xl font-bold text-cyan-600">3 Weeks</p>
              <p className="text-xs text-gray-600 uppercase tracking-wide">Dev Time</p>
            </div>
            <div className="text-center">
              <p className="text-3xl font-bold text-cyan-600">Tested</p>
              <p className="text-xs text-gray-600 uppercase tracking-wide">Against Live Target</p>
            </div>
          </div>
          <div className="mt-4 pt-4 border-t border-gray-300">
            <p className="text-sm text-gray-700 text-center">
              <strong>Projected Year 3:</strong> $5M ARR | 2,000 customers | Cash flow positive Q4 2027
            </p>
          </div>
        </div>

        {/* Market Opportunity & Product Highlights */}
        <div className="grid grid-cols-2 gap-6 mb-6">
          {/* Market */}
          <div>
            <div className="flex items-center gap-2 mb-3">
              <Users className="w-5 h-5 text-purple-600" />
              <h2 className="text-lg font-bold text-gray-900 uppercase tracking-wide">Market</h2>
            </div>
            <div className="space-y-2 text-sm text-gray-700">
              <p>
                <strong>TAM:</strong> $24.8B (Pentesting + Vuln Management + SOC Tools)
              </p>
              <p>
                <strong>SAM:</strong> $3.2B (Consultancies, MSPs, mid-market enterprises in US/EU)
              </p>
              <p>
                <strong>SOM:</strong> $160M (5% market share by Year 5)
              </p>
              <div className="mt-3 pt-3 border-t border-gray-300">
                <p className="text-xs text-gray-600">
                  <strong>Growth Drivers:</strong> SOC2/ISO 27001 compliance mandates, shift from
                  manual to continuous testing, MSP demand for white-label tools
                </p>
              </div>
            </div>
          </div>

          {/* Product Highlights */}
          <div>
            <div className="flex items-center gap-2 mb-3">
              <Award className="w-5 h-5 text-cyan-600" />
              <h2 className="text-lg font-bold text-gray-900 uppercase tracking-wide">
                Product Highlights
              </h2>
            </div>
            <ul className="space-y-1 text-sm text-gray-700">
              <li className="flex items-start gap-2">
                <span className="text-cyan-600">•</span>
                <span>Automated network, web app, cloud (AWS/Azure/GCP) scanning</span>
              </li>
              <li className="flex items-start gap-2">
                <span className="text-cyan-600">•</span>
                <span>AI-powered vulnerability prioritization (70% false positive reduction)</span>
              </li>
              <li className="flex items-start gap-2">
                <span className="text-cyan-600">•</span>
                <span>
                  Compliance automation (PCI-DSS, NIST 800-53, HIPAA, SOC 2, ISO 27001)
                </span>
              </li>
              <li className="flex items-start gap-2">
                <span className="text-cyan-600">•</span>
                <span>Customer portals + CRM for consultancies (unique to market)</span>
              </li>
              <li className="flex items-start gap-2">
                <span className="text-cyan-600">•</span>
                <span>SIEM integration, SOAR playbooks, incident response workflows</span>
              </li>
              <li className="flex items-start gap-2">
                <span className="text-cyan-600">•</span>
                <span>DevSecOps: SAST, SCA, CI/CD integration, IDE plugins</span>
              </li>
            </ul>
          </div>
        </div>

        {/* Competitive Advantage */}
        <div className="mb-6">
          <div className="flex items-center gap-2 mb-3">
            <Target className="w-5 h-5 text-green-600" />
            <h2 className="text-lg font-bold text-gray-900 uppercase tracking-wide">
              Competitive Advantage
            </h2>
          </div>
          <div className="grid grid-cols-3 gap-4 text-sm">
            <div className="border-l-4 border-cyan-600 pl-3">
              <p className="font-semibold text-gray-900">vs Tenable/Qualys</p>
              <p className="text-gray-600">
                60% cheaper, built-in customer portal, AI prioritization, consultancy features
              </p>
            </div>
            <div className="border-l-4 border-cyan-600 pl-3">
              <p className="font-semibold text-gray-900">vs Traditional Pentesting</p>
              <p className="text-gray-600">
                96% cost reduction, continuous testing (not annual), instant reports, scalable
              </p>
            </div>
            <div className="border-l-4 border-cyan-600 pl-3">
              <p className="font-semibold text-gray-900">vs Terra Security</p>
              <p className="text-gray-600">
                Broader scope (GRC, SOAR, DevSecOps), white-label CRM, enterprise-grade compliance
              </p>
            </div>
          </div>
        </div>

        {/* Team & The Ask */}
        <div className="grid grid-cols-2 gap-6 mb-6">
          {/* Team */}
          <div>
            <div className="flex items-center gap-2 mb-3">
              <Users className="w-5 h-5 text-blue-600" />
              <h2 className="text-lg font-bold text-gray-900 uppercase tracking-wide">Founder</h2>
            </div>
            <div className="space-y-2 text-sm text-gray-700">
              <div>
                <p className="font-semibold">Solo Founder – 20 Years SIGINT</p>
                <p className="text-xs text-gray-600">
                  Signals Intelligence Analyst, nation-state level operations worldwide
                </p>
              </div>
              <div>
                <p className="font-semibold">100% Disabled Army Veteran</p>
                <p className="text-xs text-gray-600">
                  Combat veteran, father, mission-driven: "Security is a right, not a luxury"
                </p>
              </div>
              <div>
                <p className="font-semibold">AI-Assisted Development Expert</p>
                <p className="text-xs text-gray-600">
                  Built in 3 weeks what VC-backed teams achieve in 12+ months
                </p>
              </div>
            </div>
          </div>

          {/* The Ask */}
          <div>
            <div className="flex items-center gap-2 mb-3">
              <TrendingUp className="w-5 h-5 text-green-600" />
              <h2 className="text-lg font-bold text-gray-900 uppercase tracking-wide">The Ask</h2>
            </div>
            <div className="space-y-2 text-sm text-gray-700">
              <p className="text-lg font-bold text-cyan-600">$500K-$1.5M Pre-Seed</p>
              <p className="font-semibold">Use of Funds:</p>
              <ul className="space-y-1 text-xs">
                <li>• 40% Product (finish last 10%, polish UX)</li>
                <li>• 30% Go-to-Market (Reddit, YouTube, community growth)</li>
                <li>• 20% Founder Runway (18 months, $60K/year)</li>
                <li>• 10% Infrastructure (AWS, domain, tools)</li>
              </ul>
              <p className="font-semibold mt-3">Milestones (18 months):</p>
              <ul className="space-y-1 text-xs">
                <li>• First 100 paying customers</li>
                <li>• $200K ARR by Month 18</li>
                <li>• Product-market fit validated</li>
                <li>• Break-even by Month 18</li>
              </ul>
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="border-t-2 border-cyan-600 pt-4 mt-6">
          <div className="flex justify-between items-center text-sm text-gray-600">
            <div className="flex items-center gap-6">
              <div className="flex items-center gap-2">
                <Mail className="w-4 h-4 text-cyan-600" />
                <span>investors@heroforge.io</span>
              </div>
              <div className="flex items-center gap-2">
                <Calendar className="w-4 h-4 text-cyan-600" />
                <a
                  href="https://calendly.com/heroforge-ceo"
                  className="text-cyan-600 hover:underline no-print"
                >
                  Schedule a call
                </a>
                <span className="print-only">calendly.com/heroforge-ceo</span>
              </div>
            </div>
            <div>
              <p className="font-semibold">heroforge.genialarchitect.io</p>
              <p className="text-xs">Confidential – December 2025</p>
            </div>
          </div>
        </div>
      </div>

      {/* Bottom CTA (no print) */}
      <div className="no-print bg-gray-100 border-t border-gray-300 px-8 py-8">
        <div className="max-w-4xl mx-auto text-center">
          <p className="text-gray-700 mb-4">
            Interested in learning more? View our complete investor materials.
          </p>
          <div className="flex justify-center gap-4">
            <a
              href="/investors"
              className="inline-flex items-center gap-2 bg-cyan-600 hover:bg-cyan-700 text-white px-6 py-3 rounded-lg font-semibold transition"
            >
              Investor Page
            </a>
            <a
              href="/pitch"
              className="inline-flex items-center gap-2 bg-blue-600 hover:bg-blue-700 text-white px-6 py-3 rounded-lg font-semibold transition"
            >
              Pitch Deck
            </a>
            <a
              href="/financials"
              className="inline-flex items-center gap-2 bg-purple-600 hover:bg-purple-700 text-white px-6 py-3 rounded-lg font-semibold transition"
            >
              Financial Model
            </a>
          </div>
        </div>
      </div>
    </div>
  );
};

export default OnePagerPage;
