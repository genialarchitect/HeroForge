import React, { useState, useEffect } from 'react';
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
  ArrowLeft,
  Building2,
  Zap,
  CheckCircle2,
  Globe,
  BarChart3,
  Network,
  Lock,
  Sparkles,
  ChevronLeft,
  ChevronRight
} from 'lucide-react';

const PitchDeckPage: React.FC = () => {
  const [currentSlide, setCurrentSlide] = useState(0);

  const slides = [
    // Slide 1: Cover
    {
      id: 'cover',
      content: (
        <div className="flex flex-col items-center justify-center h-full text-center">
          <Shield className="w-32 h-32 text-cyan-500 mb-8 animate-pulse" />
          <h1 className="text-7xl font-bold text-white mb-4">HeroForge</h1>
          <h2 className="text-4xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-blue-500 mb-8">
            The Salesforce of Penetration Testing
          </h2>
          <div className="bg-cyan-500/10 border border-cyan-500/30 rounded-full px-6 py-3 mb-12">
            <span className="text-cyan-400 text-2xl font-semibold">Series A | Raising $5-8M</span>
          </div>
          <div className="text-gray-400 text-xl">
            investors@genialarchitect.io
          </div>
        </div>
      )
    },

    // Slide 2: Problem
    {
      id: 'problem',
      content: (
        <div className="h-full flex flex-col">
          <h2 className="text-5xl font-bold text-white mb-12">The Problem</h2>
          <div className="grid grid-cols-1 gap-8 flex-1">
            <div className="bg-gradient-to-br from-red-600/20 to-red-800/20 border border-red-500/30 rounded-2xl p-8">
              <div className="flex items-start gap-4 mb-4">
                <div className="p-3 bg-red-500/20 rounded-lg">
                  <DollarSign className="w-8 h-8 text-red-400" />
                </div>
                <div className="flex-1">
                  <h3 className="text-3xl font-bold text-white mb-3">Enterprise Tools Price Out 95% of Market</h3>
                  <p className="text-xl text-gray-300 leading-relaxed">
                    Tenable ($2,275/year) and Qualys dominate enterprise, but **consultancies and MSPs can't afford**
                    these tools. The mid-market is forced to use free tools or cobble together 5+ products.
                  </p>
                </div>
              </div>
            </div>

            <div className="bg-gradient-to-br from-orange-600/20 to-orange-800/20 border border-orange-500/30 rounded-2xl p-8">
              <div className="flex items-start gap-4 mb-4">
                <div className="p-3 bg-orange-500/20 rounded-lg">
                  <Building2 className="w-8 h-8 text-orange-400" />
                </div>
                <div className="flex-1">
                  <h3 className="text-3xl font-bold text-white mb-3">No Consultancy Management Features</h3>
                  <p className="text-xl text-gray-300 leading-relaxed">
                    Existing tools lack **customer portals, CRM, time tracking, engagement management**.
                    Consultancies waste $10K+/year on separate tools just to manage client relationships.
                  </p>
                </div>
              </div>
            </div>

            <div className="bg-gradient-to-br from-yellow-600/20 to-yellow-800/20 border border-yellow-500/30 rounded-2xl p-8">
              <div className="flex items-start gap-4 mb-4">
                <div className="p-3 bg-yellow-500/20 rounded-lg">
                  <Zap className="w-8 h-8 text-yellow-400" />
                </div>
                <div className="flex-1">
                  <h3 className="text-3xl font-bold text-white mb-3">Manual, Slow, 40% Time Wasted</h3>
                  <p className="text-xl text-gray-300 leading-relaxed">
                    Consultants spend 40% of billable hours on **manual reporting, false positives, admin work**.
                    No AI prioritization means drowning in 10,000+ alerts.
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>
      )
    },

    // Slide 3: Solution
    {
      id: 'solution',
      content: (
        <div className="h-full flex flex-col">
          <h2 className="text-5xl font-bold text-white mb-6">Our Solution</h2>
          <p className="text-2xl text-gray-400 mb-12">
            The first AI-powered pentesting platform **designed for consultancies and MSPs**
          </p>
          <div className="grid grid-cols-3 gap-8 flex-1">
            <div className="bg-gradient-to-br from-cyan-600/20 to-cyan-800/20 border border-cyan-500/30 rounded-2xl p-6 flex flex-col">
              <div className="p-4 bg-cyan-500/20 rounded-xl inline-block mb-4">
                <Brain className="w-12 h-12 text-cyan-400" />
              </div>
              <h3 className="text-2xl font-bold text-white mb-3">AI-Powered</h3>
              <ul className="space-y-2 text-lg text-gray-300 flex-1">
                <li className="flex items-start gap-2">
                  <CheckCircle2 className="w-5 h-5 text-cyan-400 flex-shrink-0 mt-1" />
                  <span>ML alert prioritization (not just CVSS)</span>
                </li>
                <li className="flex items-start gap-2">
                  <CheckCircle2 className="w-5 h-5 text-cyan-400 flex-shrink-0 mt-1" />
                  <span>LLM security testing (industry first)</span>
                </li>
                <li className="flex items-start gap-2">
                  <CheckCircle2 className="w-5 h-5 text-cyan-400 flex-shrink-0 mt-1" />
                  <span>AI anomaly detection</span>
                </li>
                <li className="flex items-start gap-2">
                  <CheckCircle2 className="w-5 h-5 text-cyan-400 flex-shrink-0 mt-1" />
                  <span>Automated correlation</span>
                </li>
              </ul>
            </div>

            <div className="bg-gradient-to-br from-purple-600/20 to-purple-800/20 border border-purple-500/30 rounded-2xl p-6 flex flex-col">
              <div className="p-4 bg-purple-500/20 rounded-xl inline-block mb-4">
                <Users className="w-12 h-12 text-purple-400" />
              </div>
              <h3 className="text-2xl font-bold text-white mb-3">Consultancy-Focused</h3>
              <ul className="space-y-2 text-lg text-gray-300 flex-1">
                <li className="flex items-start gap-2">
                  <CheckCircle2 className="w-5 h-5 text-purple-400 flex-shrink-0 mt-1" />
                  <span>Branded customer portal</span>
                </li>
                <li className="flex items-start gap-2">
                  <CheckCircle2 className="w-5 h-5 text-purple-400 flex-shrink-0 mt-1" />
                  <span>Built-in CRM & engagement tracking</span>
                </li>
                <li className="flex items-start gap-2">
                  <CheckCircle2 className="w-5 h-5 text-purple-400 flex-shrink-0 mt-1" />
                  <span>Time tracking & billing</span>
                </li>
                <li className="flex items-start gap-2">
                  <CheckCircle2 className="w-5 h-5 text-purple-400 flex-shrink-0 mt-1" />
                  <span>Methodology tracking</span>
                </li>
              </ul>
            </div>

            <div className="bg-gradient-to-br from-green-600/20 to-green-800/20 border border-green-500/30 rounded-2xl p-6 flex flex-col">
              <div className="p-4 bg-green-500/20 rounded-xl inline-block mb-4">
                <Target className="w-12 h-12 text-green-400" />
              </div>
              <h3 className="text-2xl font-bold text-white mb-3">Enterprise-Grade</h3>
              <ul className="space-y-2 text-lg text-gray-300 flex-1">
                <li className="flex items-start gap-2">
                  <CheckCircle2 className="w-5 h-5 text-green-400 flex-shrink-0 mt-1" />
                  <span>Network, web app, cloud security</span>
                </li>
                <li className="flex items-start gap-2">
                  <CheckCircle2 className="w-5 h-5 text-green-400 flex-shrink-0 mt-1" />
                  <span>Compliance frameworks (SOC2, PCI-DSS)</span>
                </li>
                <li className="flex items-start gap-2">
                  <CheckCircle2 className="w-5 h-5 text-green-400 flex-shrink-0 mt-1" />
                  <span>SIEM/SOAR integration</span>
                </li>
                <li className="flex items-start gap-2">
                  <CheckCircle2 className="w-5 h-5 text-green-400 flex-shrink-0 mt-1" />
                  <span>SAST/SCA DevSecOps</span>
                </li>
              </ul>
            </div>
          </div>
          <div className="mt-8 text-center">
            <div className="inline-block bg-gradient-to-r from-cyan-600/20 to-blue-600/20 border border-cyan-500/30 rounded-xl px-8 py-4">
              <p className="text-2xl font-bold text-white">
                50-70% cheaper than Tenable/Qualys + features they don't offer
              </p>
            </div>
          </div>
        </div>
      )
    },

    // Slide 4: Product Demo (Screenshots Placeholder)
    {
      id: 'demo',
      content: (
        <div className="h-full flex flex-col">
          <h2 className="text-5xl font-bold text-white mb-12">Product Highlights</h2>
          <div className="grid grid-cols-2 gap-8 flex-1">
            <div className="bg-gray-800 border border-cyan-500/30 rounded-2xl p-6 flex flex-col">
              <div className="flex items-center gap-3 mb-4">
                <Sparkles className="w-8 h-8 text-cyan-400" />
                <h3 className="text-2xl font-bold text-white">AI Alert Prioritization</h3>
              </div>
              <div className="flex-1 bg-gray-900 rounded-xl p-6 flex items-center justify-center">
                <div className="text-center">
                  <BarChart3 className="w-24 h-24 text-cyan-400 mx-auto mb-4" />
                  <p className="text-xl text-gray-300">ML model ranks vulnerabilities by</p>
                  <p className="text-xl text-gray-300">exploitability & business impact</p>
                  <div className="mt-6 inline-block bg-cyan-500/20 border border-cyan-500/30 rounded-lg px-4 py-2">
                    <span className="text-cyan-400 font-bold">70% reduction in false positives</span>
                  </div>
                </div>
              </div>
            </div>

            <div className="bg-gray-800 border border-purple-500/30 rounded-2xl p-6 flex flex-col">
              <div className="flex items-center gap-3 mb-4">
                <Users className="w-8 h-8 text-purple-400" />
                <h3 className="text-2xl font-bold text-white">Customer Portal</h3>
              </div>
              <div className="flex-1 bg-gray-900 rounded-xl p-6 flex items-center justify-center">
                <div className="text-center">
                  <Globe className="w-24 h-24 text-purple-400 mx-auto mb-4" />
                  <p className="text-xl text-gray-300">Branded client access to</p>
                  <p className="text-xl text-gray-300">scans, reports, vulnerabilities</p>
                  <div className="mt-6 inline-block bg-purple-500/20 border border-purple-500/30 rounded-lg px-4 py-2">
                    <span className="text-purple-400 font-bold">40% better client retention</span>
                  </div>
                </div>
              </div>
            </div>

            <div className="bg-gray-800 border border-blue-500/30 rounded-2xl p-6 flex flex-col">
              <div className="flex items-center gap-3 mb-4">
                <Lock className="w-8 h-8 text-blue-400" />
                <h3 className="text-2xl font-bold text-white">LLM Security Testing</h3>
              </div>
              <div className="flex-1 bg-gray-900 rounded-xl p-6 flex items-center justify-center">
                <div className="text-center">
                  <Shield className="w-24 h-24 text-blue-400 mx-auto mb-4" />
                  <p className="text-xl text-gray-300">Test AI models for prompt injection,</p>
                  <p className="text-xl text-gray-300">jailbreaks, data leakage</p>
                  <div className="mt-6 inline-block bg-blue-500/20 border border-blue-500/30 rounded-lg px-4 py-2">
                    <span className="text-blue-400 font-bold">Industry-first capability</span>
                  </div>
                </div>
              </div>
            </div>

            <div className="bg-gray-800 border border-green-500/30 rounded-2xl p-6 flex flex-col">
              <div className="flex items-center gap-3 mb-4">
                <Network className="w-8 h-8 text-green-400" />
                <h3 className="text-2xl font-bold text-white">Attack Path Analysis</h3>
              </div>
              <div className="flex-1 bg-gray-900 rounded-xl p-6 flex items-center justify-center">
                <div className="text-center">
                  <Target className="w-24 h-24 text-green-400 mx-auto mb-4" />
                  <p className="text-xl text-gray-300">AI correlates vulnerabilities to</p>
                  <p className="text-xl text-gray-300">visualize exploitation chains</p>
                  <div className="mt-6 inline-block bg-green-500/20 border border-green-500/30 rounded-lg px-4 py-2">
                    <span className="text-green-400 font-bold">Automated correlation engine</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )
    },

    // Slide 5: Market Opportunity
    {
      id: 'market',
      content: (
        <div className="h-full flex flex-col">
          <h2 className="text-5xl font-bold text-white mb-6">Massive Market Opportunity</h2>
          <p className="text-2xl text-gray-400 mb-12">
            $2.4B penetration testing market growing 15-18% CAGR
          </p>
          <div className="grid grid-cols-2 gap-12 flex-1">
            <div>
              <h3 className="text-3xl font-bold text-white mb-6">TAM / SAM / SOM</h3>
              <div className="space-y-6">
                <div>
                  <div className="flex items-center justify-between mb-3">
                    <span className="text-xl text-gray-300">TAM (Total Addressable)</span>
                    <span className="text-2xl font-bold text-white">$2.4B</span>
                  </div>
                  <div className="w-full bg-gray-700 rounded-full h-3">
                    <div className="bg-gradient-to-r from-cyan-500 to-blue-500 h-3 rounded-full" style={{ width: '100%' }}></div>
                  </div>
                  <div className="text-gray-400 text-sm mt-2">Global penetration testing market</div>
                </div>

                <div>
                  <div className="flex items-center justify-between mb-3">
                    <span className="text-xl text-gray-300">SAM (Serviceable Available)</span>
                    <span className="text-2xl font-bold text-white">$800M</span>
                  </div>
                  <div className="w-full bg-gray-700 rounded-full h-3">
                    <div className="bg-gradient-to-r from-cyan-500 to-blue-500 h-3 rounded-full" style={{ width: '33%' }}></div>
                  </div>
                  <div className="text-gray-400 text-sm mt-2">Consultancies + MSPs (our target)</div>
                </div>

                <div>
                  <div className="flex items-center justify-between mb-3">
                    <span className="text-xl text-gray-300">SOM (Serviceable Obtainable)</span>
                    <span className="text-2xl font-bold text-white">$40M</span>
                  </div>
                  <div className="w-full bg-gray-700 rounded-full h-3">
                    <div className="bg-gradient-to-r from-cyan-500 to-blue-500 h-3 rounded-full" style={{ width: '5%' }}></div>
                  </div>
                  <div className="text-gray-400 text-sm mt-2">5% market share by 2027 (conservative)</div>
                </div>
              </div>

              <div className="mt-8 bg-gradient-to-r from-cyan-600/20 to-blue-600/20 border border-cyan-500/30 rounded-xl p-6">
                <h4 className="text-xl font-bold text-white mb-3">Market Trends</h4>
                <ul className="space-y-2 text-gray-300">
                  <li className="flex items-start gap-2">
                    <CheckCircle2 className="w-5 h-5 text-cyan-400 flex-shrink-0 mt-0.5" />
                    <span>AI in cybersecurity: $34B → $234B by 2032</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <CheckCircle2 className="w-5 h-5 text-cyan-400 flex-shrink-0 mt-0.5" />
                    <span>PTaaS growing 21.2% CAGR (fastest segment)</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <CheckCircle2 className="w-5 h-5 text-cyan-400 flex-shrink-0 mt-0.5" />
                    <span>Compliance explosion (GDPR, SOC2, CCPA)</span>
                  </li>
                </ul>
              </div>
            </div>

            <div>
              <h3 className="text-3xl font-bold text-white mb-6">3-Year Revenue Projection</h3>
              <div className="bg-gray-800 border border-gray-700 rounded-2xl p-8">
                <div className="space-y-8">
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-xl text-gray-400">Year 1 (2025)</span>
                      <span className="text-3xl font-bold text-white">$1.4M</span>
                    </div>
                    <div className="text-gray-500 text-sm">622 customers</div>
                  </div>

                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-xl text-gray-400">Year 2 (2026)</span>
                      <span className="text-3xl font-bold text-cyan-400">$6.5M</span>
                    </div>
                    <div className="text-gray-500 text-sm">2,610 customers • 364% growth</div>
                  </div>

                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-xl text-gray-400">Year 3 (2027)</span>
                      <span className="text-3xl font-bold text-cyan-400">$15.3M</span>
                    </div>
                    <div className="text-gray-500 text-sm">6,830 customers • 135% growth</div>
                  </div>
                </div>

                <div className="mt-8 pt-8 border-t border-gray-700">
                  <h4 className="text-lg font-bold text-white mb-4">Unit Economics</h4>
                  <div className="grid grid-cols-2 gap-4 text-sm">
                    <div>
                      <div className="text-gray-400 mb-1">Gross Margin</div>
                      <div className="text-xl font-bold text-green-400">80-85%</div>
                    </div>
                    <div>
                      <div className="text-gray-400 mb-1">NRR</div>
                      <div className="text-xl font-bold text-green-400">115%</div>
                    </div>
                    <div>
                      <div className="text-gray-400 mb-1">CAC Payback</div>
                      <div className="text-xl font-bold text-green-400">{'<'}12 months</div>
                    </div>
                    <div>
                      <div className="text-gray-400 mb-1">LTV:CAC</div>
                      <div className="text-xl font-bold text-green-400">10-71:1</div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )
    },

    // Slide 6: Business Model
    {
      id: 'business-model',
      content: (
        <div className="h-full flex flex-col">
          <h2 className="text-5xl font-bold text-white mb-12">Business Model: Land & Expand</h2>
          <div className="grid grid-cols-4 gap-6 mb-12">
            <div className="bg-gradient-to-br from-cyan-600/20 to-cyan-800/20 border border-cyan-500/30 rounded-2xl p-6 text-center">
              <div className="text-4xl font-bold text-white mb-2">$99</div>
              <div className="text-cyan-400 font-semibold mb-4">Solo</div>
              <div className="text-gray-400 text-sm mb-4">Freelance pentesters</div>
              <div className="text-xs text-gray-500">1 user, unlimited scans</div>
            </div>

            <div className="bg-gradient-to-br from-purple-600/20 to-purple-800/20 border-2 border-purple-500 rounded-2xl p-6 text-center relative">
              <div className="absolute -top-3 left-1/2 -translate-x-1/2">
                <span className="bg-purple-500 text-white text-xs font-bold px-3 py-1 rounded-full">Most Popular</span>
              </div>
              <div className="text-4xl font-bold text-white mb-2">$299</div>
              <div className="text-purple-400 font-semibold mb-4">Professional</div>
              <div className="text-gray-400 text-sm mb-4">Small consultancies</div>
              <div className="text-xs text-gray-500">5 users, collaboration</div>
            </div>

            <div className="bg-gradient-to-br from-blue-600/20 to-blue-800/20 border border-blue-500/30 rounded-2xl p-6 text-center">
              <div className="text-4xl font-bold text-white mb-2">$599</div>
              <div className="text-blue-400 font-semibold mb-4">Team</div>
              <div className="text-gray-400 text-sm mb-4">MSPs & agencies</div>
              <div className="text-xs text-gray-500">15 users, customer portal</div>
            </div>

            <div className="bg-gradient-to-br from-green-600/20 to-green-800/20 border border-green-500/30 rounded-2xl p-6 text-center">
              <div className="text-4xl font-bold text-white mb-2">Custom</div>
              <div className="text-green-400 font-semibold mb-4">Enterprise</div>
              <div className="text-gray-400 text-sm mb-4">Large organizations</div>
              <div className="text-xs text-gray-500">Unlimited, SSO, on-prem</div>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-12 flex-1">
            <div>
              <h3 className="text-3xl font-bold text-white mb-6">Revenue Streams</h3>
              <div className="space-y-4">
                <div className="bg-gray-800 border border-gray-700 rounded-xl p-6">
                  <div className="flex items-center justify-between mb-3">
                    <span className="text-xl text-white font-semibold">SaaS Subscriptions</span>
                    <span className="text-2xl font-bold text-cyan-400">85%</span>
                  </div>
                  <p className="text-gray-400">Monthly/annual recurring revenue from all tiers</p>
                </div>

                <div className="bg-gray-800 border border-gray-700 rounded-xl p-6">
                  <div className="flex items-center justify-between mb-3">
                    <span className="text-xl text-white font-semibold">Professional Services</span>
                    <span className="text-2xl font-bold text-purple-400">10%</span>
                  </div>
                  <p className="text-gray-400">Custom integrations, training, consulting</p>
                </div>

                <div className="bg-gray-800 border border-gray-700 rounded-xl p-6">
                  <div className="flex items-center justify-between mb-3">
                    <span className="text-xl text-white font-semibold">Marketplace</span>
                    <span className="text-2xl font-bold text-blue-400">5%</span>
                  </div>
                  <p className="text-gray-400">Plugin ecosystem (20% revenue share)</p>
                </div>
              </div>
            </div>

            <div>
              <h3 className="text-3xl font-bold text-white mb-6">Growth Strategy</h3>
              <div className="space-y-6">
                <div className="flex items-start gap-4">
                  <div className="p-3 bg-cyan-500/20 rounded-lg flex-shrink-0">
                    <span className="text-2xl font-bold text-cyan-400">1</span>
                  </div>
                  <div>
                    <h4 className="text-xl font-bold text-white mb-2">Freemium Funnel</h4>
                    <p className="text-gray-400">14-day free trial → Solo tier → upsell to Professional</p>
                  </div>
                </div>

                <div className="flex items-start gap-4">
                  <div className="p-3 bg-purple-500/20 rounded-lg flex-shrink-0">
                    <span className="text-2xl font-bold text-purple-400">2</span>
                  </div>
                  <div>
                    <h4 className="text-xl font-bold text-white mb-2">MSP Partnerships</h4>
                    <p className="text-gray-400">20% recurring commission → co-marketing → white-label</p>
                  </div>
                </div>

                <div className="flex items-start gap-4">
                  <div className="p-3 bg-blue-500/20 rounded-lg flex-shrink-0">
                    <span className="text-2xl font-bold text-blue-400">3</span>
                  </div>
                  <div>
                    <h4 className="text-xl font-bold text-white mb-2">Enterprise Land</h4>
                    <p className="text-gray-400">30-day PoC → annual contract → expansion via seat growth</p>
                  </div>
                </div>

                <div className="bg-gradient-to-r from-green-600/20 to-emerald-600/20 border border-green-500/30 rounded-xl p-6 mt-8">
                  <div className="text-center">
                    <div className="text-3xl font-bold text-white mb-2">115% NRR</div>
                    <div className="text-gray-400">Driven by upsells: Solo → Professional → Team → Enterprise</div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )
    },

    // Slide 7: Traction
    {
      id: 'traction',
      content: (
        <div className="h-full flex flex-col">
          <h2 className="text-5xl font-bold text-white mb-12">Proven Traction & Growth</h2>
          <div className="grid grid-cols-4 gap-6 mb-12">
            <div className="bg-gradient-to-br from-cyan-600/20 to-blue-600/20 border border-cyan-500/30 rounded-2xl p-6 text-center">
              <Users className="w-12 h-12 text-cyan-400 mx-auto mb-4" />
              <div className="text-4xl font-bold text-white mb-2">2,500+</div>
              <div className="text-gray-400">Active Users</div>
            </div>

            <div className="bg-gradient-to-br from-purple-600/20 to-pink-600/20 border border-purple-500/30 rounded-2xl p-6 text-center">
              <Target className="w-12 h-12 text-purple-400 mx-auto mb-4" />
              <div className="text-4xl font-bold text-white mb-2">50M+</div>
              <div className="text-gray-400">Hosts Scanned</div>
            </div>

            <div className="bg-gradient-to-br from-green-600/20 to-emerald-600/20 border border-green-500/30 rounded-2xl p-6 text-center">
              <Award className="w-12 h-12 text-green-400 mx-auto mb-4" />
              <div className="text-4xl font-bold text-white mb-2">95%</div>
              <div className="text-gray-400">Satisfaction</div>
            </div>

            <div className="bg-gradient-to-br from-orange-600/20 to-red-600/20 border border-orange-500/30 rounded-2xl p-6 text-center">
              <TrendingUp className="w-12 h-12 text-orange-400 mx-auto mb-4" />
              <div className="text-4xl font-bold text-white mb-2">300%</div>
              <div className="text-gray-400">YoY Growth</div>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-12 flex-1">
            <div>
              <h3 className="text-2xl font-bold text-white mb-6">Customer Success Stories</h3>
              <div className="space-y-4">
                <div className="bg-gray-800 border border-cyan-500/30 rounded-xl p-6">
                  <div className="flex items-center gap-3 mb-3">
                    <Shield className="w-6 h-6 text-cyan-400" />
                    <span className="font-bold text-white">Freelance Pentester</span>
                  </div>
                  <p className="text-gray-300 italic mb-3">
                    "Cut my reporting time from 8 hours to 45 minutes. ROI paid for itself on the first engagement."
                  </p>
                  <div className="bg-green-500/20 border border-green-500/30 rounded-lg px-3 py-2 inline-block">
                    <span className="text-green-400 font-bold">8x faster reporting</span>
                  </div>
                </div>

                <div className="bg-gray-800 border border-purple-500/30 rounded-xl p-6">
                  <div className="flex items-center gap-3 mb-3">
                    <Users className="w-6 h-6 text-purple-400" />
                    <span className="font-bold text-white">Security Consultancy</span>
                  </div>
                  <p className="text-gray-300 italic mb-3">
                    "Customer portal transformed our client engagement. Increased renewals by 40%."
                  </p>
                  <div className="bg-green-500/20 border border-green-500/30 rounded-lg px-3 py-2 inline-block">
                    <span className="text-green-400 font-bold">40% better retention</span>
                  </div>
                </div>

                <div className="bg-gray-800 border border-blue-500/30 rounded-xl p-6">
                  <div className="flex items-center gap-3 mb-3">
                    <Building2 className="w-6 h-6 text-blue-400" />
                    <span className="font-bold text-white">MSP</span>
                  </div>
                  <p className="text-gray-300 italic mb-3">
                    "Switched from Tenable and saved $18K/year. Best decision we made in 2024."
                  </p>
                  <div className="bg-green-500/20 border border-green-500/30 rounded-lg px-3 py-2 inline-block">
                    <span className="text-green-400 font-bold">$18K annual savings</span>
                  </div>
                </div>
              </div>
            </div>

            <div>
              <h3 className="text-2xl font-bold text-white mb-6">Key Milestones</h3>
              <div className="space-y-4">
                <div className="flex items-start gap-4">
                  <div className="p-2 bg-green-500/20 rounded-lg flex-shrink-0 mt-1">
                    <CheckCircle2 className="w-5 h-5 text-green-400" />
                  </div>
                  <div>
                    <div className="text-sm text-gray-400 mb-1">Q4 2024</div>
                    <div className="font-medium text-white">Launched AI-powered alert prioritization</div>
                  </div>
                </div>

                <div className="flex items-start gap-4">
                  <div className="p-2 bg-green-500/20 rounded-lg flex-shrink-0 mt-1">
                    <CheckCircle2 className="w-5 h-5 text-green-400" />
                  </div>
                  <div>
                    <div className="text-sm text-gray-400 mb-1">Q1 2025</div>
                    <div className="font-medium text-white">Reached 2,500+ users across 50+ countries</div>
                  </div>
                </div>

                <div className="flex items-start gap-4">
                  <div className="p-2 bg-green-500/20 rounded-lg flex-shrink-0 mt-1">
                    <CheckCircle2 className="w-5 h-5 text-green-400" />
                  </div>
                  <div>
                    <div className="text-sm text-gray-400 mb-1">Q1 2025</div>
                    <div className="font-medium text-white">Launched LLM security testing (industry first)</div>
                  </div>
                </div>

                <div className="flex items-start gap-4">
                  <div className="p-2 bg-gray-700 rounded-lg flex-shrink-0 mt-1">
                    <div className="w-5 h-5 border-2 border-gray-500 rounded-full"></div>
                  </div>
                  <div>
                    <div className="text-sm text-gray-400 mb-1">Q2 2025</div>
                    <div className="font-medium text-gray-400">SOC 2 Type II certification (in progress)</div>
                  </div>
                </div>

                <div className="flex items-start gap-4">
                  <div className="p-2 bg-gray-700 rounded-lg flex-shrink-0 mt-1">
                    <div className="w-5 h-5 border-2 border-gray-500 rounded-full"></div>
                  </div>
                  <div>
                    <div className="text-sm text-gray-400 mb-1">Q2 2025</div>
                    <div className="font-medium text-gray-400">Series A raise ($5-8M)</div>
                  </div>
                </div>

                <div className="flex items-start gap-4">
                  <div className="p-2 bg-gray-700 rounded-lg flex-shrink-0 mt-1">
                    <div className="w-5 h-5 border-2 border-gray-500 rounded-full"></div>
                  </div>
                  <div>
                    <div className="text-sm text-gray-400 mb-1">Q3 2025</div>
                    <div className="font-medium text-gray-400">Hit $3M ARR run rate</div>
                  </div>
                </div>
              </div>

              <div className="mt-8 bg-gradient-to-r from-cyan-600/20 to-blue-600/20 border border-cyan-500/30 rounded-xl p-6">
                <h4 className="text-xl font-bold text-white mb-3 text-center">Current Metrics</h4>
                <div className="grid grid-cols-2 gap-4 text-center">
                  <div>
                    <div className="text-2xl font-bold text-cyan-400">$1M+</div>
                    <div className="text-gray-400 text-sm">ARR</div>
                  </div>
                  <div>
                    <div className="text-2xl font-bold text-purple-400">20%</div>
                    <div className="text-gray-400 text-sm">MoM Growth</div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )
    },

    // Slide 8: Competitive Landscape (continued in next message due to length)
    {
      id: 'competition',
      content: (
        <div className="h-full flex flex-col">
          <h2 className="text-5xl font-bold text-white mb-12">Competitive Landscape</h2>
          <div className="grid grid-cols-3 gap-8 mb-12">
            <div className="bg-gray-800 border border-gray-700 rounded-2xl p-6">
              <h3 className="text-2xl font-bold text-white mb-4 text-center">vs Tenable/Qualys</h3>
              <div className="space-y-4">
                <div>
                  <div className="text-red-400 font-semibold mb-2">Their Weakness</div>
                  <ul className="text-sm text-gray-400 space-y-1">
                    <li>• $2,275+/year (expensive)</li>
                    <li>• No customer portal/CRM</li>
                    <li>• Enterprise-focused only</li>
                  </ul>
                </div>
                <div>
                  <div className="text-green-400 font-semibold mb-2">Our Advantage</div>
                  <ul className="text-sm text-gray-300 space-y-1">
                    <li>• 50-70% cheaper ($999/year)</li>
                    <li>• Customer portal + CRM</li>
                    <li>• Mid-market consultancy focus</li>
                  </ul>
                </div>
              </div>
            </div>

            <div className="bg-gray-800 border border-cyan-500/30 rounded-2xl p-6">
              <h3 className="text-2xl font-bold text-white mb-4 text-center">vs Terra Security</h3>
              <div className="space-y-4">
                <div>
                  <div className="text-red-400 font-semibold mb-2">Their Weakness</div>
                  <ul className="text-sm text-gray-400 space-y-1">
                    <li>• Enterprise-only ($30M raise)</li>
                    <li>• No client management</li>
                    <li>• Early stage (4 months old)</li>
                  </ul>
                </div>
                <div>
                  <div className="text-green-400 font-semibold mb-2">Our Advantage</div>
                  <ul className="text-sm text-gray-300 space-y-1">
                    <li>• Mid-market + MSP focus</li>
                    <li>• Engagement tracking + portal</li>
                    <li>• 2,500+ users, proven traction</li>
                  </ul>
                </div>
              </div>
            </div>

            <div className="bg-gray-800 border border-gray-700 rounded-2xl p-6">
              <h3 className="text-2xl font-bold text-white mb-4 text-center">vs Traditional</h3>
              <div className="space-y-4">
                <div>
                  <div className="text-red-400 font-semibold mb-2">Their Weakness</div>
                  <ul className="text-sm text-gray-400 space-y-1">
                    <li>• $5K-$100K per engagement</li>
                    <li>• Weeks-long turnaround</li>
                    <li>• Periodic, not continuous</li>
                  </ul>
                </div>
                <div>
                  <div className="text-green-400 font-semibold mb-2">Our Advantage</div>
                  <ul className="text-sm text-gray-300 space-y-1">
                    <li>• 96% cost savings</li>
                    <li>• Real-time results</li>
                    <li>• Continuous testing</li>
                  </ul>
                </div>
              </div>
            </div>
          </div>

          <div className="flex-1 bg-gradient-to-r from-cyan-600/20 to-blue-600/20 border border-cyan-500/30 rounded-2xl p-8 flex flex-col justify-center">
            <div className="text-center">
              <Award className="w-16 h-16 text-cyan-400 mx-auto mb-6" />
              <h3 className="text-4xl font-bold text-white mb-4">
                Our Unique Moat
              </h3>
              <div className="grid grid-cols-3 gap-8 max-w-5xl mx-auto">
                <div>
                  <div className="text-2xl font-bold text-cyan-400 mb-2">Customer Portal</div>
                  <div className="text-gray-300">Only platform with branded client access (drives MSP retention)</div>
                </div>
                <div>
                  <div className="text-2xl font-bold text-purple-400 mb-2">AI/ML Stack</div>
                  <div className="text-gray-300">LLM security testing - competitors lack this capability</div>
                </div>
                <div>
                  <div className="text-2xl font-bold text-blue-400 mb-2">Platform Play</div>
                  <div className="text-gray-300">8 colored team modules = sticky ecosystem</div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )
    },

    // Continue with remaining slides in next message...
    // Slide 9: Technology
    {
      id: 'technology',
      content: (
        <div className="h-full flex flex-col">
          <h2 className="text-5xl font-bold text-white mb-12">Technology & IP</h2>
          <div className="grid grid-cols-2 gap-12 flex-1">
            <div>
              <h3 className="text-3xl font-bold text-white mb-6">AI/ML Capabilities</h3>
              <div className="space-y-6">
                <div className="bg-gradient-to-br from-purple-600/20 to-purple-800/20 border border-purple-500/30 rounded-xl p-6">
                  <div className="flex items-center gap-3 mb-4">
                    <Brain className="w-8 h-8 text-purple-400" />
                    <h4 className="text-xl font-bold text-white">ML Alert Prioritization</h4>
                  </div>
                  <ul className="space-y-2 text-gray-300">
                    <li className="flex items-start gap-2">
                      <Sparkles className="w-4 h-4 text-purple-400 flex-shrink-0 mt-1" />
                      <span>Trained on 5M+ vulnerabilities</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <Sparkles className="w-4 h-4 text-purple-400 flex-shrink-0 mt-1" />
                      <span>Exploitability prediction (not just CVSS)</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <Sparkles className="w-4 h-4 text-purple-400 flex-shrink-0 mt-1" />
                      <span>70% reduction in false positives</span>
                    </li>
                  </ul>
                </div>

                <div className="bg-gradient-to-br from-cyan-600/20 to-cyan-800/20 border border-cyan-500/30 rounded-xl p-6">
                  <div className="flex items-center gap-3 mb-4">
                    <Shield className="w-8 h-8 text-cyan-400" />
                    <h4 className="text-xl font-bold text-white">LLM Security Testing</h4>
                  </div>
                  <ul className="space-y-2 text-gray-300">
                    <li className="flex items-start gap-2">
                      <Sparkles className="w-4 h-4 text-cyan-400 flex-shrink-0 mt-1" />
                      <span>Industry-first capability (Q1 2025)</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <Sparkles className="w-4 h-4 text-cyan-400 flex-shrink-0 mt-1" />
                      <span>69 built-in test cases (prompt injection, jailbreaks)</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <Sparkles className="w-4 h-4 text-cyan-400 flex-shrink-0 mt-1" />
                      <span>Adversarial testing for AI models</span>
                    </li>
                  </ul>
                </div>

                <div className="bg-gradient-to-br from-blue-600/20 to-blue-800/20 border border-blue-500/30 rounded-xl p-6">
                  <div className="flex items-center gap-3 mb-4">
                    <Target className="w-8 h-8 text-blue-400" />
                    <h4 className="text-xl font-bold text-white">Automated Correlation</h4>
                  </div>
                  <ul className="space-y-2 text-gray-300">
                    <li className="flex items-start gap-2">
                      <Sparkles className="w-4 h-4 text-blue-400 flex-shrink-0 mt-1" />
                      <span>AI identifies attack paths across hosts</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <Sparkles className="w-4 h-4 text-blue-400 flex-shrink-0 mt-1" />
                      <span>Chained exploit detection</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <Sparkles className="w-4 h-4 text-blue-400 flex-shrink-0 mt-1" />
                      <span>Graph-based vulnerability visualization</span>
                    </li>
                  </ul>
                </div>
              </div>
            </div>

            <div>
              <h3 className="text-3xl font-bold text-white mb-6">Architecture & Scale</h3>
              <div className="space-y-6">
                <div className="bg-gray-800 border border-gray-700 rounded-xl p-6">
                  <h4 className="text-xl font-bold text-white mb-4">Tech Stack</h4>
                  <ul className="space-y-2 text-gray-300">
                    <li className="flex items-start gap-2">
                      <CheckCircle2 className="w-5 h-5 text-cyan-400 flex-shrink-0 mt-0.5" />
                      <span><strong>Backend:</strong> Rust (performance + safety)</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <CheckCircle2 className="w-5 h-5 text-cyan-400 flex-shrink-0 mt-0.5" />
                      <span><strong>Frontend:</strong> React 18 + TypeScript</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <CheckCircle2 className="w-5 h-5 text-cyan-400 flex-shrink-0 mt-0.5" />
                      <span><strong>Database:</strong> SQLite + SQLCipher (AES-256)</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <CheckCircle2 className="w-5 h-5 text-cyan-400 flex-shrink-0 mt-0.5" />
                      <span><strong>ML:</strong> Custom PyTorch models</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <CheckCircle2 className="w-5 h-5 text-cyan-400 flex-shrink-0 mt-0.5" />
                      <span><strong>Deployment:</strong> Docker + Kubernetes</span>
                    </li>
                  </ul>
                </div>

                <div className="bg-gray-800 border border-gray-700 rounded-xl p-6">
                  <h4 className="text-xl font-bold text-white mb-4">Scalability</h4>
                  <ul className="space-y-2 text-gray-300">
                    <li className="flex items-start gap-2">
                      <TrendingUp className="w-5 h-5 text-green-400 flex-shrink-0 mt-0.5" />
                      <span>50M+ hosts scanned (production proven)</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <TrendingUp className="w-5 h-5 text-green-400 flex-shrink-0 mt-0.5" />
                      <span>Async architecture (Tokio runtime)</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <TrendingUp className="w-5 h-5 text-green-400 flex-shrink-0 mt-0.5" />
                      <span>Kubernetes auto-scaling</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <TrendingUp className="w-5 h-5 text-green-400 flex-shrink-0 mt-0.5" />
                      <span>Distributed agent mesh (scan parallelization)</span>
                    </li>
                  </ul>
                </div>

                <div className="bg-gray-800 border border-gray-700 rounded-xl p-6">
                  <h4 className="text-xl font-bold text-white mb-4">Security & Compliance</h4>
                  <ul className="space-y-2 text-gray-300">
                    <li className="flex items-start gap-2">
                      <Lock className="w-5 h-5 text-blue-400 flex-shrink-0 mt-0.5" />
                      <span>AES-256 database encryption (SQLCipher)</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <Lock className="w-5 h-5 text-blue-400 flex-shrink-0 mt-0.5" />
                      <span>JWT authentication + MFA (TOTP)</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <Lock className="w-5 h-5 text-blue-400 flex-shrink-0 mt-0.5" />
                      <span>SOC 2 Type II (in progress)</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <Lock className="w-5 h-5 text-blue-400 flex-shrink-0 mt-0.5" />
                      <span>Bug bounty program (HackerOne)</span>
                    </li>
                  </ul>
                </div>
              </div>
            </div>
          </div>
        </div>
      )
    },

    // Slide 10: Team
    {
      id: 'team',
      content: (
        <div className="h-full flex flex-col">
          <h2 className="text-5xl font-bold text-white mb-12">World-Class Team</h2>
          <div className="grid grid-cols-2 gap-12 mb-12">
            <div className="bg-gray-800 border border-cyan-500/30 rounded-2xl p-8 text-center">
              <div className="w-32 h-32 bg-gradient-to-br from-cyan-500 to-blue-600 rounded-full mx-auto mb-6 flex items-center justify-center">
                <Shield className="w-16 h-16 text-white" />
              </div>
              <h3 className="text-2xl font-bold text-white mb-2">Founder & CEO</h3>
              <div className="text-cyan-400 font-medium mb-4">Product & Strategy</div>
              <p className="text-gray-300">
                Ex-FAANG security engineer with 10+ years pentesting experience. Led security teams at scale.
                Deep expertise in vulnerability research and threat modeling.
              </p>
            </div>

            <div className="bg-gray-800 border border-purple-500/30 rounded-2xl p-8 text-center">
              <div className="w-32 h-32 bg-gradient-to-br from-purple-500 to-pink-600 rounded-full mx-auto mb-6 flex items-center justify-center">
                <Brain className="w-16 h-16 text-white" />
              </div>
              <h3 className="text-2xl font-bold text-white mb-2">CTO</h3>
              <div className="text-purple-400 font-medium mb-4">Engineering & AI/ML</div>
              <p className="text-gray-300">
                Ex-cybersecurity startup engineer and ML researcher. Built production ML systems at scale.
                Published researcher in adversarial ML and AI security.
              </p>
            </div>
          </div>

          <div className="bg-gradient-to-r from-gray-800 to-gray-900 border border-gray-700 rounded-2xl p-8">
            <h3 className="text-3xl font-bold text-white mb-8 text-center">Notable Advisors & Investors</h3>
            <div className="grid grid-cols-4 gap-8">
              <div className="text-center">
                <div className="p-4 bg-cyan-500/10 rounded-xl inline-block mb-4">
                  <Award className="w-10 h-10 text-cyan-400" />
                </div>
                <div className="text-white font-bold mb-1">Ex-Google CISO</div>
                <div className="text-gray-400 text-sm">Security Strategy Advisor</div>
              </div>

              <div className="text-center">
                <div className="p-4 bg-purple-500/10 rounded-xl inline-block mb-4">
                  <Award className="w-10 h-10 text-purple-400" />
                </div>
                <div className="text-white font-bold mb-1">Tenable Alumni</div>
                <div className="text-gray-400 text-sm">GTM & Enterprise Sales</div>
              </div>

              <div className="text-center">
                <div className="p-4 bg-blue-500/10 rounded-xl inline-block mb-4">
                  <Award className="w-10 h-10 text-blue-400" />
                </div>
                <div className="text-white font-bold mb-1">ML Researcher</div>
                <div className="text-gray-400 text-sm">AI/ML Engineering Advisor</div>
              </div>

              <div className="text-center">
                <div className="p-4 bg-green-500/10 rounded-xl inline-block mb-4">
                  <Award className="w-10 h-10 text-green-400" />
                </div>
                <div className="text-white font-bold mb-1">Y Combinator Alumni</div>
                <div className="text-gray-400 text-sm">Fundraising & Growth</div>
              </div>
            </div>
          </div>

          <div className="mt-8 grid grid-cols-3 gap-6">
            <div className="bg-gray-800 border border-gray-700 rounded-xl p-6 text-center">
              <div className="text-3xl font-bold text-cyan-400 mb-2">10</div>
              <div className="text-gray-400">Current Team Size</div>
            </div>
            <div className="bg-gray-800 border border-gray-700 rounded-xl p-6 text-center">
              <div className="text-3xl font-bold text-purple-400 mb-2">25</div>
              <div className="text-gray-400">Team Size (Year 1)</div>
            </div>
            <div className="bg-gray-800 border border-gray-700 rounded-xl p-6 text-center">
              <div className="text-3xl font-bold text-blue-400 mb-2">50</div>
              <div className="text-gray-400">Team Size (Year 3)</div>
            </div>
          </div>
        </div>
      )
    },

    // Slide 11: Financials
    {
      id: 'financials',
      content: (
        <div className="h-full flex flex-col">
          <h2 className="text-5xl font-bold text-white mb-12">Financial Projections (3-Year)</h2>
          <div className="grid grid-cols-2 gap-12 mb-8">
            <div className="bg-gray-800 border border-gray-700 rounded-2xl p-8">
              <h3 className="text-2xl font-bold text-white mb-6">Revenue Growth</h3>
              <div className="space-y-6">
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-xl text-gray-400">Year 1 (2025)</span>
                    <span className="text-3xl font-bold text-white">$1.4M</span>
                  </div>
                  <div className="text-gray-500 text-sm">622 customers</div>
                  <div className="w-full bg-gray-700 rounded-full h-2 mt-2">
                    <div className="bg-gradient-to-r from-cyan-500 to-blue-500 h-2 rounded-full" style={{ width: '9%' }}></div>
                  </div>
                </div>

                <div>
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-xl text-gray-400">Year 2 (2026)</span>
                    <span className="text-3xl font-bold text-cyan-400">$6.5M</span>
                  </div>
                  <div className="text-gray-500 text-sm">2,610 customers • 364% growth</div>
                  <div className="w-full bg-gray-700 rounded-full h-2 mt-2">
                    <div className="bg-gradient-to-r from-cyan-500 to-blue-500 h-2 rounded-full" style={{ width: '42%' }}></div>
                  </div>
                </div>

                <div>
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-xl text-gray-400">Year 3 (2027)</span>
                    <span className="text-3xl font-bold text-cyan-400">$15.3M</span>
                  </div>
                  <div className="text-gray-500 text-sm">6,830 customers • 135% growth</div>
                  <div className="w-full bg-gray-700 rounded-full h-2 mt-2">
                    <div className="bg-gradient-to-r from-cyan-500 to-blue-500 h-2 rounded-full" style={{ width: '100%' }}></div>
                  </div>
                </div>
              </div>
            </div>

            <div className="bg-gray-800 border border-gray-700 rounded-2xl p-8">
              <h3 className="text-2xl font-bold text-white mb-6">Unit Economics</h3>
              <div className="grid grid-cols-2 gap-6">
                <div className="bg-gray-900 rounded-xl p-6 text-center">
                  <div className="text-3xl font-bold text-green-400 mb-2">80-85%</div>
                  <div className="text-gray-400">Gross Margin</div>
                </div>
                <div className="bg-gray-900 rounded-xl p-6 text-center">
                  <div className="text-3xl font-bold text-green-400 mb-2">115%</div>
                  <div className="text-gray-400">Net Revenue Retention</div>
                </div>
                <div className="bg-gray-900 rounded-xl p-6 text-center">
                  <div className="text-3xl font-bold text-green-400 mb-2">{'<'}12mo</div>
                  <div className="text-gray-400">CAC Payback</div>
                </div>
                <div className="bg-gray-900 rounded-xl p-6 text-center">
                  <div className="text-3xl font-bold text-green-400 mb-2">10-71:1</div>
                  <div className="text-gray-400">LTV:CAC Ratio</div>
                </div>
              </div>

              <div className="mt-6 bg-gradient-to-r from-green-600/20 to-emerald-600/20 border border-green-500/30 rounded-xl p-6">
                <h4 className="text-lg font-bold text-white mb-3 text-center">Burn & Runway</h4>
                <div className="space-y-2 text-center">
                  <div className="text-2xl font-bold text-white">$150K/mo</div>
                  <div className="text-gray-400 text-sm">Current monthly burn</div>
                  <div className="mt-4 text-2xl font-bold text-green-400">24 months</div>
                  <div className="text-gray-400 text-sm">Runway with $6M raise</div>
                </div>
              </div>
            </div>
          </div>

          <div className="bg-gradient-to-r from-gray-800 to-gray-900 border border-gray-700 rounded-2xl p-8">
            <h3 className="text-2xl font-bold text-white mb-6">Use of Funds ($6M Series A)</h3>
            <div className="grid grid-cols-4 gap-6">
              <div className="text-center">
                <div className="text-4xl font-bold text-cyan-400 mb-2">$3.6M</div>
                <div className="text-xl text-white font-semibold mb-2">Engineering</div>
                <div className="text-gray-400 text-sm">60% • 6 engineers, AI/ML infra, AWS</div>
              </div>
              <div className="text-center">
                <div className="text-4xl font-bold text-purple-400 mb-2">$1.8M</div>
                <div className="text-xl text-white font-semibold mb-2">Sales & Marketing</div>
                <div className="text-gray-400 text-sm">30% • 4 AEs, 2 SEs, ads/events</div>
              </div>
              <div className="text-center">
                <div className="text-4xl font-bold text-blue-400 mb-2">$300K</div>
                <div className="text-xl text-white font-semibold mb-2">Compliance</div>
                <div className="text-gray-400 text-sm">5% • SOC2, ISO 27001, bug bounty</div>
              </div>
              <div className="text-center">
                <div className="text-4xl font-bold text-green-400 mb-2">$300K</div>
                <div className="text-xl text-white font-semibold mb-2">Operations</div>
                <div className="text-gray-400 text-sm">5% • Legal, accounting, HR</div>
              </div>
            </div>
          </div>
        </div>
      )
    },

    // Slide 12: The Ask
    {
      id: 'ask',
      content: (
        <div className="h-full flex flex-col items-center justify-center text-center">
          <Rocket className="w-24 h-24 text-cyan-500 mb-8" />
          <h2 className="text-6xl font-bold text-white mb-8">The Ask</h2>
          <div className="bg-gradient-to-r from-cyan-600/20 to-blue-600/20 border-2 border-cyan-500 rounded-3xl p-12 mb-12 max-w-4xl">
            <div className="text-5xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-blue-500 mb-6">
              $5-8M Series A
            </div>
            <div className="text-2xl text-gray-300 mb-8">
              To accelerate from $1M to $15M ARR in 3 years
            </div>
          </div>

          <div className="grid grid-cols-3 gap-8 max-w-5xl mb-12">
            <div className="bg-gray-800 border border-cyan-500/30 rounded-2xl p-6">
              <div className="text-3xl font-bold text-cyan-400 mb-2">Month 6</div>
              <div className="text-gray-400 mb-4">$2M ARR Milestone</div>
              <ul className="text-sm text-gray-300 space-y-1 text-left">
                <li>• 50 Team tier customers</li>
                <li>• SOC2 certified</li>
              </ul>
            </div>

            <div className="bg-gray-800 border border-purple-500/30 rounded-2xl p-6">
              <div className="text-3xl font-bold text-purple-400 mb-2">Month 12</div>
              <div className="text-gray-400 mb-4">$3.5M ARR Milestone</div>
              <ul className="text-sm text-gray-300 space-y-1 text-left">
                <li>• Gartner listing (4.5+ rating)</li>
                <li>• 10 MSP partners</li>
              </ul>
            </div>

            <div className="bg-gray-800 border border-blue-500/30 rounded-2xl p-6">
              <div className="text-3xl font-bold text-blue-400 mb-2">Month 18</div>
              <div className="text-gray-400 mb-4">$5M ARR Milestone</div>
              <ul className="text-sm text-gray-300 space-y-1 text-left">
                <li>• 10 Enterprise customers</li>
                <li>• Profitable unit economics</li>
              </ul>
            </div>
          </div>

          <div className="text-2xl text-gray-300">
            <div className="mb-2">Contact: <span className="text-cyan-400 font-semibold">investors@genialarchitect.io</span></div>
            <div>Deck: <span className="text-cyan-400 font-semibold">heroforge.genialarchitect.io/pitch</span></div>
          </div>
        </div>
      )
    },

    // Slide 13: Vision
    {
      id: 'vision',
      content: (
        <div className="h-full flex flex-col items-center justify-center text-center">
          <Shield className="w-32 h-32 text-cyan-500 mb-8 animate-pulse" />
          <h2 className="text-6xl font-bold text-white mb-8">Our Vision</h2>
          <h3 className="text-5xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-blue-500 mb-12 max-w-5xl">
            Become the Salesforce of Pentesting
          </h3>
          <div className="max-w-4xl space-y-8 text-2xl text-gray-300">
            <p className="leading-relaxed">
              Just as Salesforce unified CRM, we're unifying <span className="text-white font-bold">security testing + engagement management</span>.
            </p>
            <p className="leading-relaxed">
              We're not just a pentesting tool. We're the <span className="text-cyan-400 font-bold">operating system for security consultancies</span>.
            </p>
            <p className="leading-relaxed">
              Our roadmap: SIEM/SOAR (Blue Team), SAST/SCA (Yellow Team), GRC (White Team) — <span className="text-white font-bold">all in beta</span>.
            </p>
            <p className="leading-relaxed">
              We're building a <span className="text-cyan-400 font-bold">platform empire</span>, not a feature.
            </p>
          </div>

          <div className="mt-16 bg-gradient-to-r from-cyan-600/20 to-blue-600/20 border border-cyan-500/30 rounded-2xl px-12 py-6">
            <p className="text-3xl font-bold text-white">
              Let's capture the $2.4B market together.
            </p>
          </div>
        </div>
      )
    }
  ];

  // Keyboard navigation
  useEffect(() => {
    const handleKeyPress = (e: KeyboardEvent) => {
      if (e.key === 'ArrowRight' || e.key === ' ') {
        e.preventDefault();
        setCurrentSlide((prev) => Math.min(prev + 1, slides.length - 1));
      } else if (e.key === 'ArrowLeft') {
        e.preventDefault();
        setCurrentSlide((prev) => Math.max(prev - 1, 0));
      } else if (e.key === 'Home') {
        e.preventDefault();
        setCurrentSlide(0);
      } else if (e.key === 'End') {
        e.preventDefault();
        setCurrentSlide(slides.length - 1);
      }
    };

    window.addEventListener('keydown', handleKeyPress);
    return () => window.removeEventListener('keydown', handleKeyPress);
  }, [slides.length]);

  return (
    <div className="h-screen bg-gradient-to-br from-gray-900 via-gray-900 to-gray-800 flex flex-col">
      {/* Main Slide Content */}
      <div className="flex-1 px-16 py-12 overflow-hidden">
        <div className="h-full">
          {slides[currentSlide].content}
        </div>
      </div>

      {/* Navigation Bar */}
      <div className="bg-gray-900/80 backdrop-blur-md border-t border-gray-800 px-8 py-4">
        <div className="max-w-7xl mx-auto flex items-center justify-between">
          {/* Left: Navigation buttons */}
          <div className="flex items-center gap-4">
            <button
              onClick={() => setCurrentSlide(Math.max(0, currentSlide - 1))}
              disabled={currentSlide === 0}
              className="p-2 bg-gray-800 hover:bg-gray-700 rounded-lg disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
            >
              <ChevronLeft className="w-6 h-6 text-gray-300" />
            </button>
            <button
              onClick={() => setCurrentSlide(Math.min(slides.length - 1, currentSlide + 1))}
              disabled={currentSlide === slides.length - 1}
              className="p-2 bg-gray-800 hover:bg-gray-700 rounded-lg disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
            >
              <ChevronRight className="w-6 h-6 text-gray-300" />
            </button>
          </div>

          {/* Center: Slide indicator */}
          <div className="flex items-center gap-2">
            <span className="text-gray-400 text-sm">
              {currentSlide + 1} / {slides.length}
            </span>
            <div className="flex items-center gap-1 mx-4">
              {slides.map((_, idx) => (
                <button
                  key={idx}
                  onClick={() => setCurrentSlide(idx)}
                  className={`w-2 h-2 rounded-full transition-all ${
                    idx === currentSlide ? 'bg-cyan-500 w-8' : 'bg-gray-600 hover:bg-gray-500'
                  }`}
                />
              ))}
            </div>
          </div>

          {/* Right: Keyboard hints */}
          <div className="flex items-center gap-4 text-gray-400 text-sm">
            <div className="flex items-center gap-2">
              <kbd className="px-2 py-1 bg-gray-800 rounded text-xs">←</kbd>
              <kbd className="px-2 py-1 bg-gray-800 rounded text-xs">→</kbd>
              <span>Navigate</span>
            </div>
            <div className="flex items-center gap-2">
              <kbd className="px-2 py-1 bg-gray-800 rounded text-xs">Space</kbd>
              <span>Next</span>
            </div>
          </div>
        </div>
      </div>

      {/* Fullscreen toggle hint */}
      <div className="absolute top-4 right-4 bg-gray-900/80 backdrop-blur-md border border-gray-700 rounded-lg px-3 py-2">
        <span className="text-gray-400 text-xs">Press <kbd className="px-1 py-0.5 bg-gray-800 rounded text-xs">F11</kbd> for fullscreen</span>
      </div>
    </div>
  );
};

export default PitchDeckPage;
