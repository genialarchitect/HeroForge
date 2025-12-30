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
              <p className="font-semibold">Series A Fundraise</p>
              <p>$6M Target</p>
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
          <p className="text-gray-700 leading-relaxed">
            HeroForge is an all-in-one cybersecurity platform that automates penetration testing,
            vulnerability management, and security operations for consultancies, MSPs, and
            enterprises. We replace $2,000-$100,000 manual pentesting engagements with continuous,
            AI-powered security testing at $999-$60,000/year—reducing costs by 96% while enabling
            24/7 monitoring instead of periodic assessments.
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
              Traction & Metrics
            </h2>
          </div>
          <div className="grid grid-cols-4 gap-4">
            <div className="text-center">
              <p className="text-3xl font-bold text-cyan-600">$1M</p>
              <p className="text-xs text-gray-600 uppercase tracking-wide">ARR (Current)</p>
            </div>
            <div className="text-center">
              <p className="text-3xl font-bold text-cyan-600">532</p>
              <p className="text-xs text-gray-600 uppercase tracking-wide">Paying Customers</p>
            </div>
            <div className="text-center">
              <p className="text-3xl font-bold text-cyan-600">20:1</p>
              <p className="text-xs text-gray-600 uppercase tracking-wide">LTV:CAC Ratio</p>
            </div>
            <div className="text-center">
              <p className="text-3xl font-bold text-cyan-600">110%</p>
              <p className="text-xs text-gray-600 uppercase tracking-wide">Net Revenue Retention</p>
            </div>
          </div>
          <div className="mt-4 pt-4 border-t border-gray-300">
            <p className="text-sm text-gray-700 text-center">
              <strong>Projected Year 3:</strong> $15.3M ARR | 4,960 customers | 12.9:1 LTV:CAC |
              Cash flow positive Q4 2027
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
              <h2 className="text-lg font-bold text-gray-900 uppercase tracking-wide">Team</h2>
            </div>
            <div className="space-y-2 text-sm text-gray-700">
              <div>
                <p className="font-semibold">CEO – Former Security Consultant</p>
                <p className="text-xs text-gray-600">
                  15+ years pentesting, OSCP/OSCE certified, built tools used by Fortune 500
                </p>
              </div>
              <div>
                <p className="font-semibold">CTO – Ex-CloudFlare, AWS</p>
                <p className="text-xs text-gray-600">
                  10 years scaling security infrastructure, ML expertise
                </p>
              </div>
              <div>
                <p className="font-semibold">VP Engineering – Ex-Rapid7</p>
                <p className="text-xs text-gray-600">Led vulnerability research team at Rapid7</p>
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
              <p className="text-lg font-bold text-cyan-600">$6M Series A</p>
              <p className="font-semibold">Use of Funds:</p>
              <ul className="space-y-1 text-xs">
                <li>• 40% Engineering (8 hires, cloud infrastructure)</li>
                <li>• 30% Go-to-Market (sales, marketing, partnerships)</li>
                <li>• 15% Operations (finance, HR, compliance)</li>
                <li>• 15% Reserves (SOC2 audit, contingency)</li>
              </ul>
              <p className="font-semibold mt-3">Milestones (18 months):</p>
              <ul className="space-y-1 text-xs">
                <li>• $5M ARR (5x growth)</li>
                <li>• 2,000+ customers</li>
                <li>• SOC2 Type II certified</li>
                <li>• 10+ enterprise deals ($50K+ ACV)</li>
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
