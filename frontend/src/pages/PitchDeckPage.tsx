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
  ChevronRight,
  Code,
  Heart,
  Flag
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
            Democratizing Enterprise Security for Everyone
          </h2>
          <div className="bg-cyan-500/10 border border-cyan-500/30 rounded-full px-6 py-3 mb-4">
            <span className="text-cyan-400 text-2xl font-semibold">Pre-Seed Round | $500K-$1.5M</span>
          </div>
          <div className="bg-gray-800/50 border border-gray-700 rounded-lg px-6 py-3 mb-12">
            <span className="text-gray-300 text-lg">Built by a 20-year SIGINT veteran to make security affordable</span>
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
          <h2 className="text-5xl font-bold text-white mb-12">The Problem I Saw in 20 Years of SIGINT</h2>
          <div className="grid grid-cols-1 gap-8 flex-1">
            <div className="bg-gradient-to-br from-red-600/20 to-red-800/20 border border-red-500/30 rounded-2xl p-8">
              <div className="flex items-start gap-4 mb-4">
                <div className="p-3 bg-red-500/20 rounded-lg">
                  <DollarSign className="w-8 h-8 text-red-400" />
                </div>
                <div className="flex-1">
                  <h3 className="text-3xl font-bold text-white mb-3">Enterprise Tools Are Unaffordable</h3>
                  <p className="text-xl text-gray-300 leading-relaxed">
                    Small businesses, consultancies, and MSPs can't afford Tenable ($2,275/year) or Qualys.
                    They're forced to use free tools or pay $5K-$100K for manual pentests. Security shouldn't be only for Fortune 500.
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
                  <h3 className="text-3xl font-bold text-white mb-3">No Tools for Consultancies</h3>
                  <p className="text-xl text-gray-300 leading-relaxed">
                    Security consultants cobble together 5+ tools: scanning, reporting, client management, time tracking.
                    There's no unified platform built for how consultancies actually work.
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
                  <h3 className="text-3xl font-bold text-white mb-3">Manual Work Wastes 40% of Time</h3>
                  <p className="text-xl text-gray-300 leading-relaxed">
                    Pentesters spend 40% of billable hours on manual reporting, triaging false positives, and admin work.
                    No AI means drowning in alerts with no prioritization.
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
          <h2 className="text-5xl font-bold text-white mb-6">My Solution: All-in-One Security Platform</h2>
          <p className="text-2xl text-gray-400 mb-12">
            Built with AI assistance • 86+ modules • 45 compliance frameworks • Rust + React + ML
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
                  <span>LLM security testing</span>
                </li>
                <li className="flex items-start gap-2">
                  <CheckCircle2 className="w-5 h-5 text-cyan-400 flex-shrink-0 mt-1" />
                  <span>Automated correlation & attack paths</span>
                </li>
                <li className="flex items-start gap-2">
                  <CheckCircle2 className="w-5 h-5 text-cyan-400 flex-shrink-0 mt-1" />
                  <span>70% reduction in false positives</span>
                </li>
              </ul>
            </div>

            <div className="bg-gradient-to-br from-purple-600/20 to-purple-800/20 border border-purple-500/30 rounded-2xl p-6 flex flex-col">
              <div className="p-4 bg-purple-500/20 rounded-xl inline-block mb-4">
                <Users className="w-12 h-12 text-purple-400" />
              </div>
              <h3 className="text-2xl font-bold text-white mb-3">Consultancy-First</h3>
              <ul className="space-y-2 text-lg text-gray-300 flex-1">
                <li className="flex items-start gap-2">
                  <CheckCircle2 className="w-5 h-5 text-purple-400 flex-shrink-0 mt-1" />
                  <span>White-label customer portal</span>
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
                  <span>Methodology checklists (OWASP, PTES)</span>
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
                  <span>Network, web app, cloud (AWS/Azure/GCP)</span>
                </li>
                <li className="flex items-start gap-2">
                  <CheckCircle2 className="w-5 h-5 text-green-400 flex-shrink-0 mt-1" />
                  <span>Compliance (SOC2, PCI-DSS, HIPAA)</span>
                </li>
                <li className="flex items-start gap-2">
                  <CheckCircle2 className="w-5 h-5 text-green-400 flex-shrink-0 mt-1" />
                  <span>SIEM/SOAR integration</span>
                </li>
                <li className="flex items-start gap-2">
                  <CheckCircle2 className="w-5 h-5 text-green-400 flex-shrink-0 mt-1" />
                  <span>SAST/SCA DevSecOps pipeline</span>
                </li>
              </ul>
            </div>
          </div>
          <div className="mt-8 text-center">
            <div className="inline-block bg-gradient-to-r from-cyan-600/20 to-blue-600/20 border border-cyan-500/30 rounded-xl px-8 py-4">
              <p className="text-2xl font-bold text-white">
                70% of pentest cost • Features competitors don't offer
              </p>
            </div>
          </div>
        </div>
      )
    },

    // Slide 4: Product Demo
    {
      id: 'demo',
      content: (
        <div className="h-full flex flex-col">
          <h2 className="text-5xl font-bold text-white mb-6">Product Highlights</h2>
          <p className="text-xl text-gray-400 mb-8">Early access available • heroforge.genialarchitect.io</p>
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
                    <span className="text-purple-400 font-bold">Unique to HeroForge</span>
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
                    <span className="text-blue-400 font-bold">150+ built-in test cases</span>
                  </div>
                </div>
              </div>
            </div>

            <div className="bg-gray-800 border border-green-500/30 rounded-2xl p-6 flex flex-col">
              <div className="flex items-center gap-3 mb-4">
                <Network className="w-8 h-8 text-green-400" />
                <h3 className="text-2xl font-bold text-white">86+ Security Modules</h3>
              </div>
              <div className="flex-1 bg-gray-900 rounded-xl p-6 flex items-center justify-center">
                <div className="text-center">
                  <Target className="w-24 h-24 text-green-400 mx-auto mb-4" />
                  <p className="text-xl text-gray-300">45 Compliance Frameworks • Finding Lifecycle</p>
                  <p className="text-xl text-gray-300">Passive Recon • Full Security Operations</p>
                  <div className="mt-6 inline-block bg-green-500/20 border border-green-500/30 rounded-lg px-4 py-2">
                    <span className="text-green-400 font-bold">Enterprise-grade security ops</span>
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
            $24.8B cybersecurity market • Growing 15-18% CAGR
          </p>
          <div className="grid grid-cols-2 gap-12 flex-1">
            <div>
              <h3 className="text-3xl font-bold text-white mb-6">TAM / SAM / SOM</h3>
              <div className="space-y-6">
                <div>
                  <div className="flex items-center justify-between mb-3">
                    <span className="text-xl text-gray-300">TAM (Total Addressable)</span>
                    <span className="text-2xl font-bold text-white">$24.8B</span>
                  </div>
                  <div className="w-full bg-gray-700 rounded-full h-3">
                    <div className="bg-gradient-to-r from-cyan-500 to-blue-500 h-3 rounded-full" style={{ width: '100%' }}></div>
                  </div>
                  <div className="text-gray-400 text-sm mt-2">Pentesting + vuln mgmt + SOC tools globally</div>
                </div>

                <div>
                  <div className="flex items-center justify-between mb-3">
                    <span className="text-xl text-gray-300">SAM (Serviceable Available)</span>
                    <span className="text-2xl font-bold text-white">$3.2B</span>
                  </div>
                  <div className="w-full bg-gray-700 rounded-full h-3">
                    <div className="bg-gradient-to-r from-cyan-500 to-blue-500 h-3 rounded-full" style={{ width: '13%' }}></div>
                  </div>
                  <div className="text-gray-400 text-sm mt-2">Consultancies + MSPs in US/EU</div>
                </div>

                <div>
                  <div className="flex items-center justify-between mb-3">
                    <span className="text-xl text-gray-300">SOM (5-Year Target)</span>
                    <span className="text-2xl font-bold text-white">$160M</span>
                  </div>
                  <div className="w-full bg-gray-700 rounded-full h-3">
                    <div className="bg-gradient-to-r from-cyan-500 to-blue-500 h-3 rounded-full" style={{ width: '0.6%' }}></div>
                  </div>
                  <div className="text-gray-400 text-sm mt-2">5% market share (10K customers @ $1.3K avg)</div>
                </div>
              </div>

              <div className="mt-8 bg-gradient-to-r from-cyan-600/20 to-blue-600/20 border border-cyan-500/30 rounded-xl p-6">
                <h4 className="text-xl font-bold text-white mb-3">Why Now?</h4>
                <ul className="space-y-2 text-gray-300">
                  <li className="flex items-start gap-2">
                    <CheckCircle2 className="w-5 h-5 text-cyan-400 flex-shrink-0 mt-0.5" />
                    <span>AI in cybersecurity: $34B → $234B by 2032</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <CheckCircle2 className="w-5 h-5 text-cyan-400 flex-shrink-0 mt-0.5" />
                    <span>Compliance mandates (SOC2, GDPR, CCPA)</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <CheckCircle2 className="w-5 h-5 text-cyan-400 flex-shrink-0 mt-0.5" />
                    <span>Cloud adoption = more attack surface</span>
                  </li>
                </ul>
              </div>
            </div>

            <div>
              <h3 className="text-3xl font-bold text-white mb-6">Realistic Projections</h3>
              <div className="bg-gray-800 border border-gray-700 rounded-2xl p-8">
                <div className="space-y-8">
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-xl text-gray-400">Year 1</span>
                      <span className="text-3xl font-bold text-white">$200K</span>
                    </div>
                    <div className="text-gray-500 text-sm">100 customers • $167/mo avg</div>
                    <div className="w-full bg-gray-700 rounded-full h-2 mt-2">
                      <div className="bg-gradient-to-r from-cyan-500 to-blue-500 h-2 rounded-full" style={{ width: '1%' }}></div>
                    </div>
                  </div>

                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-xl text-gray-400">Year 2</span>
                      <span className="text-3xl font-bold text-cyan-400">$1.2M</span>
                    </div>
                    <div className="text-gray-500 text-sm">500 customers • 400% growth</div>
                    <div className="w-full bg-gray-700 rounded-full h-2 mt-2">
                      <div className="bg-gradient-to-r from-cyan-500 to-blue-500 h-2 rounded-full" style={{ width: '8%' }}></div>
                    </div>
                  </div>

                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-xl text-gray-400">Year 3</span>
                      <span className="text-3xl font-bold text-cyan-400">$5.0M</span>
                    </div>
                    <div className="text-gray-500 text-sm">2,000 customers • 317% growth</div>
                    <div className="w-full bg-gray-700 rounded-full h-2 mt-2">
                      <div className="bg-gradient-to-r from-cyan-500 to-blue-500 h-2 rounded-full" style={{ width: '33%' }}></div>
                    </div>
                  </div>
                </div>

                <div className="mt-8 pt-8 border-t border-gray-700">
                  <h4 className="text-lg font-bold text-white mb-4">Conservative Assumptions</h4>
                  <div className="grid grid-cols-2 gap-4 text-sm">
                    <div>
                      <div className="text-gray-400 mb-1">Trial → Paid</div>
                      <div className="text-xl font-bold text-green-400">20%</div>
                    </div>
                    <div>
                      <div className="text-gray-400 mb-1">Annual Churn</div>
                      <div className="text-xl font-bold text-green-400">15%</div>
                    </div>
                    <div>
                      <div className="text-gray-400 mb-1">CAC</div>
                      <div className="text-xl font-bold text-green-400">$200</div>
                    </div>
                    <div>
                      <div className="text-gray-400 mb-1">LTV:CAC</div>
                      <div className="text-xl font-bold text-green-400">10:1</div>
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
          <h2 className="text-5xl font-bold text-white mb-12">Business Model: Freemium + Land & Expand</h2>
          <div className="grid grid-cols-4 gap-6 mb-12">
            <div className="bg-gradient-to-br from-cyan-600/20 to-cyan-800/20 border border-cyan-500/30 rounded-2xl p-6 text-center">
              <div className="text-4xl font-bold text-white mb-2">$299</div>
              <div className="text-cyan-400 font-semibold mb-4">Solo</div>
              <div className="text-gray-400 text-sm mb-4">70% of $5K pentest</div>
              <div className="text-xs text-gray-500">1 user, unlimited scans</div>
            </div>

            <div className="bg-gradient-to-br from-purple-600/20 to-purple-800/20 border-2 border-purple-500 rounded-2xl p-6 text-center relative">
              <div className="absolute -top-3 left-1/2 -translate-x-1/2">
                <span className="bg-purple-500 text-white text-xs font-bold px-3 py-1 rounded-full">Target</span>
              </div>
              <div className="text-4xl font-bold text-white mb-2">$899</div>
              <div className="text-purple-400 font-semibold mb-4">Professional</div>
              <div className="text-gray-400 text-sm mb-4">70% of $15K pentest</div>
              <div className="text-xs text-gray-500">5 users, collaboration</div>
            </div>

            <div className="bg-gradient-to-br from-blue-600/20 to-blue-800/20 border border-blue-500/30 rounded-2xl p-6 text-center">
              <div className="text-4xl font-bold text-white mb-2">$1,749</div>
              <div className="text-blue-400 font-semibold mb-4">Team</div>
              <div className="text-gray-400 text-sm mb-4">70% of $30K pentest</div>
              <div className="text-xs text-gray-500">15 users, customer portal</div>
            </div>

            <div className="bg-gradient-to-br from-green-600/20 to-green-800/20 border border-green-500/30 rounded-2xl p-6 text-center">
              <div className="text-4xl font-bold text-white mb-2">Custom</div>
              <div className="text-green-400 font-semibold mb-4">Enterprise</div>
              <div className="text-gray-400 text-sm mb-4">70% of $50K+ pentests</div>
              <div className="text-xs text-gray-500">SSO, on-prem options</div>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-12 flex-1">
            <div>
              <h3 className="text-3xl font-bold text-white mb-6">Go-to-Market Strategy</h3>
              <div className="space-y-6">
                <div className="flex items-start gap-4">
                  <div className="p-3 bg-cyan-500/20 rounded-lg flex-shrink-0">
                    <span className="text-2xl font-bold text-cyan-400">1</span>
                  </div>
                  <div>
                    <h4 className="text-xl font-bold text-white mb-2">Launch Freemium (Month 1-3)</h4>
                    <p className="text-gray-400">14-day free trial → $299 Solo tier → viral Reddit/HN launch</p>
                  </div>
                </div>

                <div className="flex items-start gap-4">
                  <div className="p-3 bg-purple-500/20 rounded-lg flex-shrink-0">
                    <span className="text-2xl font-bold text-purple-400">2</span>
                  </div>
                  <div>
                    <h4 className="text-xl font-bold text-white mb-2">Content Marketing (Month 3-12)</h4>
                    <p className="text-gray-400">SEO-driven blog, YouTube tutorials, GitHub presence</p>
                  </div>
                </div>

                <div className="flex items-start gap-4">
                  <div className="p-3 bg-blue-500/20 rounded-lg flex-shrink-0">
                    <span className="text-2xl font-bold text-blue-400">3</span>
                  </div>
                  <div>
                    <h4 className="text-xl font-bold text-white mb-2">Community Building (Ongoing)</h4>
                    <p className="text-gray-400">Discord for users, plugin marketplace, user-generated templates</p>
                  </div>
                </div>

                <div className="flex items-start gap-4">
                  <div className="p-3 bg-green-500/20 rounded-lg flex-shrink-0">
                    <span className="text-2xl font-bold text-green-400">4</span>
                  </div>
                  <div>
                    <h4 className="text-xl font-bold text-white mb-2">Enterprise Sales (Year 2+)</h4>
                    <p className="text-gray-400">Outbound to Fortune 2000 CISOs once product-market fit proven</p>
                  </div>
                </div>
              </div>
            </div>

            <div>
              <h3 className="text-3xl font-bold text-white mb-6">Competitive Pricing</h3>
              <div className="space-y-4">
                <div className="bg-gray-800 border border-gray-700 rounded-xl p-6">
                  <div className="flex items-center justify-between mb-3">
                    <span className="text-xl text-white font-semibold">HeroForge Professional</span>
                    <span className="text-2xl font-bold text-cyan-400">$899/mo</span>
                  </div>
                  <p className="text-gray-400 text-sm">70% of $15K pentest • Unlimited scans + portal + CRM</p>
                </div>

                <div className="bg-gray-800 border border-red-500/30 rounded-xl p-6">
                  <div className="flex items-center justify-between mb-3">
                    <span className="text-xl text-white font-semibold">Tenable</span>
                    <span className="text-2xl font-bold text-red-400">$2,275/yr</span>
                  </div>
                  <p className="text-gray-400 text-sm">No customer portal, no CRM, no consultancy features</p>
                </div>

                <div className="bg-gray-800 border border-red-500/30 rounded-xl p-6">
                  <div className="flex items-center justify-between mb-3">
                    <span className="text-xl text-white font-semibold">Manual Pentest</span>
                    <span className="text-2xl font-bold text-red-400">$5K-$100K</span>
                  </div>
                  <p className="text-gray-400 text-sm">One-time, weeks-long, not continuous</p>
                </div>
              </div>

              <div className="mt-6 bg-gradient-to-r from-green-600/20 to-emerald-600/20 border border-green-500/30 rounded-xl p-6">
                <div className="text-center">
                  <div className="text-3xl font-bold text-white mb-2">60-70% Cost Savings</div>
                  <div className="text-gray-400">Plus features enterprise tools don't offer</div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )
    },

    // Slide 7: Founder Story (NEW - replaces Traction)
    {
      id: 'founder-story',
      content: (
        <div className="h-full flex flex-col">
          <h2 className="text-5xl font-bold text-white mb-12">Why I Built This</h2>
          <div className="grid grid-cols-2 gap-12 mb-8">
            <div className="bg-gradient-to-br from-cyan-600/20 to-blue-600/20 border border-cyan-500/30 rounded-2xl p-8">
              <div className="flex items-center gap-4 mb-6">
                <Flag className="w-12 h-12 text-cyan-400" />
                <h3 className="text-3xl font-bold text-white">20 Years of SIGINT</h3>
              </div>
              <div className="space-y-4 text-lg text-gray-300">
                <p>
                  <strong className="text-white">Former Signals Intelligence Analyst</strong> operating at the nation-state level
                  against targets worldwide for nearly two decades.
                </p>
                <p>
                  I've seen the best offensive security capabilities in the world. They shouldn't be exclusive to governments and Fortune 500.
                </p>
                <div className="bg-cyan-500/10 border border-cyan-500/30 rounded-lg p-4 mt-6">
                  <p className="text-cyan-400 font-semibold">
                    "If I can help defend against nation-state threats, I can help small businesses stay secure."
                  </p>
                </div>
              </div>
            </div>

            <div className="bg-gradient-to-br from-purple-600/20 to-pink-600/20 border border-purple-500/30 rounded-2xl p-8">
              <div className="flex items-center gap-4 mb-6">
                <Heart className="w-12 h-12 text-purple-400" />
                <h3 className="text-3xl font-bold text-white">Mission-Driven</h3>
              </div>
              <div className="space-y-4 text-lg text-gray-300">
                <p>
                  <strong className="text-white">100% disabled Army veteran</strong> and father trying to make American security
                  infrastructure affordable—not just for elite companies.
                </p>
                <p>
                  I enjoy pentesting and developing tools using AI to make the world a better place.
                </p>
                <div className="bg-purple-500/10 border border-purple-500/30 rounded-lg p-4 mt-6">
                  <p className="text-purple-400 font-semibold">
                    "Security is a right, not a luxury. Every business deserves protection."
                  </p>
                </div>
              </div>
            </div>
          </div>

          <div className="grid grid-cols-3 gap-6">
            <div className="bg-gray-800 border border-cyan-500/30 rounded-2xl p-6">
              <Code className="w-10 h-10 text-cyan-400 mb-4" />
              <h4 className="text-xl font-bold text-white mb-3">86+ Modules Built</h4>
              <p className="text-gray-300">
                Used AI (Claude) to accelerate development. 2,900+ tests passing, 45 compliance frameworks.
                Rust backend + React frontend.
              </p>
            </div>

            <div className="bg-gray-800 border border-purple-500/30 rounded-2xl p-6">
              <CheckCircle2 className="w-10 h-10 text-purple-400 mb-4" />
              <h4 className="text-xl font-bold text-white mb-3">Early Validation</h4>
              <p className="text-gray-300">
                Tested on real targets twice. Proven functional. Now seeking first paying users to validate
                product-market fit.
              </p>
            </div>

            <div className="bg-gray-800 border border-blue-500/30 rounded-2xl p-6">
              <Users className="w-10 h-10 text-blue-400 mb-4" />
              <h4 className="text-xl font-bold text-white mb-3">Looking For</h4>
              <p className="text-gray-300">
                Technical co-founder, advisors (GTM, security), veteran mentors, and first 100 customers.
              </p>
            </div>
          </div>

          <div className="mt-8 bg-gradient-to-r from-gray-800 to-gray-900 border border-gray-700 rounded-2xl p-6">
            <h4 className="text-2xl font-bold text-white mb-4 text-center">What I Bring</h4>
            <div className="grid grid-cols-4 gap-6 text-center">
              <div>
                <div className="text-3xl font-bold text-cyan-400 mb-2">20 years</div>
                <div className="text-gray-400 text-sm">SIGINT expertise</div>
              </div>
              <div>
                <div className="text-3xl font-bold text-purple-400 mb-2">Elite</div>
                <div className="text-gray-400 text-sm">Nation-state level</div>
              </div>
              <div>
                <div className="text-3xl font-bold text-blue-400 mb-2">86+</div>
                <div className="text-gray-400 text-sm">Security modules</div>
              </div>
              <div>
                <div className="text-3xl font-bold text-green-400 mb-2">Mission</div>
                <div className="text-gray-400 text-sm">Help everyone</div>
              </div>
            </div>
          </div>
        </div>
      )
    },

    // Slide 8: Competition
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
                    <li>• $2,275+/year (expensive for SMBs)</li>
                    <li>• No customer portal/CRM</li>
                    <li>• Enterprise-only focus</li>
                    <li>• Legacy tech (slow innovation)</li>
                  </ul>
                </div>
                <div>
                  <div className="text-green-400 font-semibold mb-2">My Advantage</div>
                  <ul className="text-sm text-gray-300 space-y-1">
                    <li>• 70% of pentest cost ($299-$1,749/mo)</li>
                    <li>• Customer portal + CRM + time tracking</li>
                    <li>• Consultancy-first design</li>
                    <li>• Modern stack (Rust + React + ML)</li>
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
                    <li>• No consultancy features</li>
                    <li>• 4 months old (unproven)</li>
                    <li>• High burn rate</li>
                  </ul>
                </div>
                <div>
                  <div className="text-green-400 font-semibold mb-2">My Advantage</div>
                  <ul className="text-sm text-gray-300 space-y-1">
                    <li>• SMB + consultancy focus</li>
                    <li>• Portal + CRM + engagement mgmt</li>
                    <li>• Lean (solo founder, low burn)</li>
                    <li>• Can move faster</li>
                  </ul>
                </div>
              </div>
            </div>

            <div className="bg-gray-800 border border-gray-700 rounded-2xl p-6">
              <h3 className="text-2xl font-bold text-white mb-4 text-center">vs Manual Pentests</h3>
              <div className="space-y-4">
                <div>
                  <div className="text-red-400 font-semibold mb-2">Their Weakness</div>
                  <ul className="text-sm text-gray-400 space-y-1">
                    <li>• $5K-$100K per engagement</li>
                    <li>• Weeks-long turnaround</li>
                    <li>• Annual, not continuous</li>
                    <li>• Doesn't scale</li>
                  </ul>
                </div>
                <div>
                  <div className="text-green-400 font-semibold mb-2">My Advantage</div>
                  <ul className="text-sm text-gray-300 space-y-1">
                    <li>• $3,588-$20,988/yr vs $5K-$100K one-time</li>
                    <li>• Real-time results</li>
                    <li>• Continuous testing year-round</li>
                    <li>• Infinitely scalable</li>
                  </ul>
                </div>
              </div>
            </div>
          </div>

          <div className="flex-1 bg-gradient-to-r from-cyan-600/20 to-blue-600/20 border border-cyan-500/30 rounded-2xl p-8 flex flex-col justify-center">
            <div className="text-center">
              <Award className="w-16 h-16 text-cyan-400 mx-auto mb-6" />
              <h3 className="text-4xl font-bold text-white mb-6">
                My Unique Advantages
              </h3>
              <div className="grid grid-cols-3 gap-8 max-w-5xl mx-auto">
                <div>
                  <div className="text-2xl font-bold text-cyan-400 mb-2">Consultancy-First</div>
                  <div className="text-gray-300">Only platform with CRM + portal + time tracking built for how consultancies work</div>
                </div>
                <div>
                  <div className="text-2xl font-bold text-purple-400 mb-2">Solo Founder Speed</div>
                  <div className="text-gray-300">No committees, no politics. Built 90% of product in 3 weeks. Can pivot instantly.</div>
                </div>
                <div>
                  <div className="text-2xl font-bold text-blue-400 mb-2">Mission Alignment</div>
                  <div className="text-gray-300">Not driven by VC returns. Driven by making security accessible to all.</div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )
    },

    // Slide 9: Technology
    {
      id: 'technology',
      content: (
        <div className="h-full flex flex-col">
          <h2 className="text-5xl font-bold text-white mb-6">Technology Stack</h2>
          <p className="text-2xl text-gray-400 mb-12">
            AI-assisted development • 2,900+ tests passing • Modern stack • Production-ready
          </p>
          <div className="grid grid-cols-2 gap-12 flex-1">
            <div>
              <h3 className="text-3xl font-bold text-white mb-6">Core Architecture</h3>
              <div className="space-y-6">
                <div className="bg-gray-800 border border-gray-700 rounded-xl p-6">
                  <h4 className="text-xl font-bold text-white mb-4">Backend (Rust)</h4>
                  <ul className="space-y-2 text-gray-300">
                    <li className="flex items-start gap-2">
                      <CheckCircle2 className="w-5 h-5 text-cyan-400 flex-shrink-0 mt-0.5" />
                      <span><strong>Performance:</strong> 5-10x faster than Python/Go</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <CheckCircle2 className="w-5 h-5 text-cyan-400 flex-shrink-0 mt-0.5" />
                      <span><strong>Safety:</strong> Memory-safe, no segfaults</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <CheckCircle2 className="w-5 h-5 text-cyan-400 flex-shrink-0 mt-0.5" />
                      <span><strong>Async:</strong> Tokio runtime, 10K concurrent scans</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <CheckCircle2 className="w-5 h-5 text-cyan-400 flex-shrink-0 mt-0.5" />
                      <span><strong>Test suite:</strong> 2,900+ tests passing</span>
                    </li>
                  </ul>
                </div>

                <div className="bg-gray-800 border border-gray-700 rounded-xl p-6">
                  <h4 className="text-xl font-bold text-white mb-4">Frontend (React + TypeScript)</h4>
                  <ul className="space-y-2 text-gray-300">
                    <li className="flex items-start gap-2">
                      <CheckCircle2 className="w-5 h-5 text-cyan-400 flex-shrink-0 mt-0.5" />
                      <span>React 18 with Vite (instant HMR)</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <CheckCircle2 className="w-5 h-5 text-cyan-400 flex-shrink-0 mt-0.5" />
                      <span>TypeScript for type safety</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <CheckCircle2 className="w-5 h-5 text-cyan-400 flex-shrink-0 mt-0.5" />
                      <span>TailwindCSS + responsive design</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <CheckCircle2 className="w-5 h-5 text-cyan-400 flex-shrink-0 mt-0.5" />
                      <span>Real-time WebSocket updates</span>
                    </li>
                  </ul>
                </div>

                <div className="bg-gray-800 border border-gray-700 rounded-xl p-6">
                  <h4 className="text-xl font-bold text-white mb-4">Data & Security</h4>
                  <ul className="space-y-2 text-gray-300">
                    <li className="flex items-start gap-2">
                      <Lock className="w-5 h-5 text-blue-400 flex-shrink-0 mt-0.5" />
                      <span>SQLite + SQLCipher (AES-256 encryption)</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <Lock className="w-5 h-5 text-blue-400 flex-shrink-0 mt-0.5" />
                      <span>JWT auth + MFA (TOTP)</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <Lock className="w-5 h-5 text-blue-400 flex-shrink-0 mt-0.5" />
                      <span>Bcrypt password hashing</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <Lock className="w-5 h-5 text-blue-400 flex-shrink-0 mt-0.5" />
                      <span>Rate limiting, account lockout</span>
                    </li>
                  </ul>
                </div>
              </div>
            </div>

            <div>
              <h3 className="text-3xl font-bold text-white mb-6">AI/ML & Deployment</h3>
              <div className="space-y-6">
                <div className="bg-gradient-to-br from-purple-600/20 to-purple-800/20 border border-purple-500/30 rounded-xl p-6">
                  <div className="flex items-center gap-3 mb-4">
                    <Brain className="w-8 h-8 text-purple-400" />
                    <h4 className="text-xl font-bold text-white">AI Capabilities</h4>
                  </div>
                  <ul className="space-y-2 text-gray-300">
                    <li className="flex items-start gap-2">
                      <Sparkles className="w-4 h-4 text-purple-400 flex-shrink-0 mt-1" />
                      <span>Vulnerability prioritization ML model</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <Sparkles className="w-4 h-4 text-purple-400 flex-shrink-0 mt-1" />
                      <span>LLM security testing (150+ test cases)</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <Sparkles className="w-4 h-4 text-purple-400 flex-shrink-0 mt-1" />
                      <span>Attack path correlation engine</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <Sparkles className="w-4 h-4 text-purple-400 flex-shrink-0 mt-1" />
                      <span>Built entire product with Claude AI</span>
                    </li>
                  </ul>
                </div>

                <div className="bg-gray-800 border border-gray-700 rounded-xl p-6">
                  <h4 className="text-xl font-bold text-white mb-4">Deployment</h4>
                  <ul className="space-y-2 text-gray-300">
                    <li className="flex items-start gap-2">
                      <CheckCircle2 className="w-5 h-5 text-cyan-400 flex-shrink-0 mt-0.5" />
                      <span>Docker containerized</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <CheckCircle2 className="w-5 h-5 text-cyan-400 flex-shrink-0 mt-0.5" />
                      <span>Traefik reverse proxy (auto SSL)</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <CheckCircle2 className="w-5 h-5 text-cyan-400 flex-shrink-0 mt-0.5" />
                      <span>Production URL: heroforge.genialarchitect.io</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <CheckCircle2 className="w-5 h-5 text-cyan-400 flex-shrink-0 mt-0.5" />
                      <span>Can deploy on-prem or cloud</span>
                    </li>
                  </ul>
                </div>

                <div className="bg-gray-800 border border-gray-700 rounded-xl p-6">
                  <h4 className="text-xl font-bold text-white mb-4">Development Velocity</h4>
                  <div className="space-y-4">
                    <div className="flex items-center justify-between">
                      <span className="text-gray-300">Modules</span>
                      <span className="text-xl font-bold text-cyan-400">86+</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-gray-300">Compliance Frameworks</span>
                      <span className="text-xl font-bold text-purple-400">45</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-gray-300">Backend Tests</span>
                      <span className="text-xl font-bold text-green-400">2,900+ passing</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-gray-300">Frontend Tests</span>
                      <span className="text-xl font-bold text-green-400">88 passing</span>
                    </div>
                  </div>
                </div>

                <div className="bg-gradient-to-r from-cyan-600/20 to-blue-600/20 border border-cyan-500/30 rounded-xl p-6">
                  <p className="text-lg text-white text-center">
                    <strong className="text-cyan-400">Solo founder</strong> built enterprise-grade security platform with <strong className="text-cyan-400">86+ modules</strong>.
                    That's execution velocity VCs look for.
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>
      )
    },

    // Slide 10: Roadmap (replaces Team slide)
    {
      id: 'roadmap',
      content: (
        <div className="h-full flex flex-col">
          <h2 className="text-5xl font-bold text-white mb-12">18-Month Roadmap</h2>
          <div className="space-y-8 flex-1">
            <div className="grid grid-cols-3 gap-6">
              <div className="bg-gradient-to-br from-cyan-600/20 to-cyan-800/20 border-2 border-cyan-500 rounded-2xl p-6">
                <div className="text-center mb-4">
                  <div className="text-3xl font-bold text-cyan-400 mb-2">Months 0-6</div>
                  <div className="text-gray-400">Product-Market Fit</div>
                </div>
                <ul className="space-y-3 text-gray-300">
                  <li className="flex items-start gap-2">
                    <CheckCircle2 className="w-5 h-5 text-cyan-400 flex-shrink-0 mt-0.5" />
                    <span><strong>Launch freemium:</strong> Reddit, HN, InfoSec Twitter</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <CheckCircle2 className="w-5 h-5 text-cyan-400 flex-shrink-0 mt-0.5" />
                    <span><strong>First 100 users:</strong> Get feedback, iterate</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <CheckCircle2 className="w-5 h-5 text-cyan-400 flex-shrink-0 mt-0.5" />
                    <span><strong>Hire:</strong> 1 full-stack engineer</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <CheckCircle2 className="w-5 h-5 text-cyan-400 flex-shrink-0 mt-0.5" />
                    <span><strong>Revenue:</strong> $10K MRR</span>
                  </li>
                </ul>
              </div>

              <div className="bg-gradient-to-br from-purple-600/20 to-purple-800/20 border border-purple-500/30 rounded-2xl p-6">
                <div className="text-center mb-4">
                  <div className="text-3xl font-bold text-purple-400 mb-2">Months 6-12</div>
                  <div className="text-gray-400">Scale & GTM</div>
                </div>
                <ul className="space-y-3 text-gray-300">
                  <li className="flex items-start gap-2">
                    <CheckCircle2 className="w-5 h-5 text-purple-400 flex-shrink-0 mt-0.5" />
                    <span><strong>Content marketing:</strong> SEO blog, YouTube</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <CheckCircle2 className="w-5 h-5 text-purple-400 flex-shrink-0 mt-0.5" />
                    <span><strong>500 users:</strong> Trial → paid conversion</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <CheckCircle2 className="w-5 h-5 text-purple-400 flex-shrink-0 mt-0.5" />
                    <span><strong>Hire:</strong> Marketing lead + engineer</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <CheckCircle2 className="w-5 h-5 text-purple-400 flex-shrink-0 mt-0.5" />
                    <span><strong>Revenue:</strong> $50K MRR ($600K ARR)</span>
                  </li>
                </ul>
              </div>

              <div className="bg-gradient-to-br from-blue-600/20 to-blue-800/20 border border-blue-500/30 rounded-2xl p-6">
                <div className="text-center mb-4">
                  <div className="text-3xl font-bold text-blue-400 mb-2">Months 12-18</div>
                  <div className="text-gray-400">Enterprise Ready</div>
                </div>
                <ul className="space-y-3 text-gray-300">
                  <li className="flex items-start gap-2">
                    <CheckCircle2 className="w-5 h-5 text-blue-400 flex-shrink-0 mt-0.5" />
                    <span><strong>SOC2 Type II certified</strong></span>
                  </li>
                  <li className="flex items-start gap-2">
                    <CheckCircle2 className="w-5 h-5 text-blue-400 flex-shrink-0 mt-0.5" />
                    <span><strong>First Enterprise customers:</strong> 5-10 deals</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <CheckCircle2 className="w-5 h-5 text-blue-400 flex-shrink-0 mt-0.5" />
                    <span><strong>Team:</strong> 8 people (4 eng, 2 GTM, 2 ops)</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <CheckCircle2 className="w-5 h-5 text-blue-400 flex-shrink-0 mt-0.5" />
                    <span><strong>Revenue:</strong> $100K MRR ($1.2M ARR)</span>
                  </li>
                </ul>
              </div>
            </div>

            <div className="bg-gray-800 border border-gray-700 rounded-2xl p-8">
              <h3 className="text-2xl font-bold text-white mb-6 text-center">Key Hires (First $1.5M)</h3>
              <div className="grid grid-cols-4 gap-6">
                <div className="text-center">
                  <div className="p-4 bg-cyan-500/10 rounded-xl inline-block mb-3">
                    <Code className="w-10 h-10 text-cyan-400" />
                  </div>
                  <div className="text-white font-bold mb-1">Full-Stack Engineer</div>
                  <div className="text-gray-400 text-sm">Month 2 • $140K</div>
                </div>

                <div className="text-center">
                  <div className="p-4 bg-purple-500/10 rounded-xl inline-block mb-3">
                    <Brain className="w-10 h-10 text-purple-400" />
                  </div>
                  <div className="text-white font-bold mb-1">ML Engineer</div>
                  <div className="text-gray-400 text-sm">Month 6 • $160K</div>
                </div>

                <div className="text-center">
                  <div className="p-4 bg-blue-500/10 rounded-xl inline-block mb-3">
                    <TrendingUp className="w-10 h-10 text-blue-400" />
                  </div>
                  <div className="text-white font-bold mb-1">Marketing Lead</div>
                  <div className="text-gray-400 text-sm">Month 9 • $120K</div>
                </div>

                <div className="text-center">
                  <div className="p-4 bg-green-500/10 rounded-xl inline-block mb-3">
                    <Users className="w-10 h-10 text-green-400" />
                  </div>
                  <div className="text-white font-bold mb-1">Customer Success</div>
                  <div className="text-gray-400 text-sm">Month 12 • $90K</div>
                </div>
              </div>
            </div>

            <div className="bg-gradient-to-r from-cyan-600/20 to-blue-600/20 border border-cyan-500/30 rounded-2xl p-6">
              <h3 className="text-xl font-bold text-white mb-4 text-center">Actively Seeking</h3>
              <div className="grid grid-cols-3 gap-6 text-center">
                <div>
                  <div className="text-2xl font-bold text-cyan-400 mb-2">Technical Co-Founder</div>
                  <div className="text-gray-300 text-sm">Equity-based, share vision of democratizing security</div>
                </div>
                <div>
                  <div className="text-2xl font-bold text-purple-400 mb-2">Advisors</div>
                  <div className="text-gray-300 text-sm">GTM strategy, security industry, veteran mentors</div>
                </div>
                <div>
                  <div className="text-2xl font-bold text-blue-400 mb-2">First 100 Users</div>
                  <div className="text-gray-300 text-sm">Pentesters, consultancies, MSPs for validation</div>
                </div>
              </div>
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
          <h2 className="text-5xl font-bold text-white mb-12">Use of Funds ($1M Seed)</h2>
          <div className="grid grid-cols-2 gap-12 mb-8">
            <div className="bg-gray-800 border border-gray-700 rounded-2xl p-8">
              <h3 className="text-2xl font-bold text-white mb-6">18-Month Runway Breakdown</h3>
              <div className="space-y-6">
                <div>
                  <div className="flex items-center justify-between mb-3">
                    <span className="text-xl text-white font-semibold">Engineering (60%)</span>
                    <span className="text-3xl font-bold text-cyan-400">$600K</span>
                  </div>
                  <ul className="text-sm text-gray-400 space-y-1 ml-4">
                    <li>• 2 full-stack engineers ($280K)</li>
                    <li>• 1 ML engineer ($160K)</li>
                    <li>• AWS/GCP infrastructure ($60K)</li>
                    <li>• Tools & licenses ($40K)</li>
                    <li>• Contingency buffer ($60K)</li>
                  </ul>
                </div>

                <div>
                  <div className="flex items-center justify-between mb-3">
                    <span className="text-xl text-white font-semibold">GTM (25%)</span>
                    <span className="text-3xl font-bold text-purple-400">$250K</span>
                  </div>
                  <ul className="text-sm text-gray-400 space-y-1 ml-4">
                    <li>• Marketing lead ($120K)</li>
                    <li>• Content marketing ($50K)</li>
                    <li>• Paid ads (LinkedIn, Google) ($40K)</li>
                    <li>• Events & conferences ($40K)</li>
                  </ul>
                </div>

                <div>
                  <div className="flex items-center justify-between mb-3">
                    <span className="text-xl text-white font-semibold">Operations (15%)</span>
                    <span className="text-3xl font-bold text-blue-400">$150K</span>
                  </div>
                  <ul className="text-sm text-gray-400 space-y-1 ml-4">
                    <li>• Legal & accounting ($50K)</li>
                    <li>• SOC2 audit prep ($50K)</li>
                    <li>• Customer success hire ($50K)</li>
                  </ul>
                </div>
              </div>
            </div>

            <div className="bg-gray-800 border border-gray-700 rounded-2xl p-8">
              <h3 className="text-2xl font-bold text-white mb-6">Conservative Projections</h3>
              <div className="space-y-8">
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-xl text-gray-400">Month 6</span>
                    <span className="text-3xl font-bold text-white">$10K MRR</span>
                  </div>
                  <div className="text-gray-500 text-sm">100 users • Product-market fit validated</div>
                  <div className="w-full bg-gray-700 rounded-full h-2 mt-2">
                    <div className="bg-gradient-to-r from-cyan-500 to-blue-500 h-2 rounded-full" style={{ width: '6%' }}></div>
                  </div>
                </div>

                <div>
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-xl text-gray-400">Month 12</span>
                    <span className="text-3xl font-bold text-cyan-400">$50K MRR</span>
                  </div>
                  <div className="text-gray-500 text-sm">500 users • $600K ARR run rate</div>
                  <div className="w-full bg-gray-700 rounded-full h-2 mt-2">
                    <div className="bg-gradient-to-r from-cyan-500 to-blue-500 h-2 rounded-full" style={{ width: '33%' }}></div>
                  </div>
                </div>

                <div>
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-xl text-gray-400">Month 18</span>
                    <span className="text-3xl font-bold text-cyan-400">$100K MRR</span>
                  </div>
                  <div className="text-gray-500 text-sm">1,000 users • $1.2M ARR • Ready for Series A</div>
                  <div className="w-full bg-gray-700 rounded-full h-2 mt-2">
                    <div className="bg-gradient-to-r from-cyan-500 to-blue-500 h-2 rounded-full" style={{ width: '66%' }}></div>
                  </div>
                </div>
              </div>

              <div className="mt-8 bg-gradient-to-r from-green-600/20 to-emerald-600/20 border border-green-500/30 rounded-xl p-6">
                <h4 className="text-lg font-bold text-white mb-4 text-center">Key Metrics (Month 18)</h4>
                <div className="grid grid-cols-2 gap-4">
                  <div className="text-center">
                    <div className="text-2xl font-bold text-green-400">$1.2M</div>
                    <div className="text-gray-400 text-sm">ARR</div>
                  </div>
                  <div className="text-center">
                    <div className="text-2xl font-bold text-green-400">1,000</div>
                    <div className="text-gray-400 text-sm">Paying Customers</div>
                  </div>
                  <div className="text-center">
                    <div className="text-2xl font-bold text-green-400">25%</div>
                    <div className="text-gray-400 text-sm">Trial Conversion</div>
                  </div>
                  <div className="text-center">
                    <div className="text-2xl font-bold text-green-400">{'<'}10%</div>
                    <div className="text-gray-400 text-sm">Annual Churn</div>
                  </div>
                </div>
              </div>
            </div>
          </div>

          <div className="bg-gradient-to-r from-gray-800 to-gray-900 border border-gray-700 rounded-2xl p-6">
            <h3 className="text-xl font-bold text-white mb-4 text-center">Funding Flexibility</h3>
            <div className="grid grid-cols-3 gap-6 text-center">
              <div>
                <div className="text-2xl font-bold text-cyan-400 mb-2">$500K Minimum</div>
                <div className="text-gray-400 text-sm">12-month runway • 2 engineers • bootstrap GTM</div>
              </div>
              <div>
                <div className="text-2xl font-bold text-purple-400 mb-2">$1M Target</div>
                <div className="text-gray-400 text-sm">18-month runway • full team • aggressive growth</div>
              </div>
              <div>
                <div className="text-2xl font-bold text-blue-400 mb-2">$1.5M Max</div>
                <div className="text-gray-400 text-sm">24-month runway • enterprise sales team • SOC2</div>
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
              $500K-$1.5M Seed Round
            </div>
            <div className="text-2xl text-gray-300 mb-8">
              To validate product-market fit and reach $1.2M ARR in 18 months
            </div>
          </div>

          <div className="grid grid-cols-3 gap-8 max-w-5xl mb-12">
            <div className="bg-gray-800 border border-cyan-500/30 rounded-2xl p-6">
              <div className="text-3xl font-bold text-cyan-400 mb-2">Month 6</div>
              <div className="text-gray-400 mb-4">First Milestone</div>
              <ul className="text-sm text-gray-300 space-y-1 text-left">
                <li>• 100 paying customers</li>
                <li>• $10K MRR</li>
                <li>• Product-market fit validated</li>
              </ul>
            </div>

            <div className="bg-gray-800 border border-purple-500/30 rounded-2xl p-6">
              <div className="text-3xl font-bold text-purple-400 mb-2">Month 12</div>
              <div className="text-gray-400 mb-4">Growth Milestone</div>
              <ul className="text-sm text-gray-300 space-y-1 text-left">
                <li>• 500 paying customers</li>
                <li>• $600K ARR run rate</li>
                <li>• 8-person team</li>
              </ul>
            </div>

            <div className="bg-gray-800 border border-blue-500/30 rounded-2xl p-6">
              <div className="text-3xl font-bold text-blue-400 mb-2">Month 18</div>
              <div className="text-gray-400 mb-4">Series A Ready</div>
              <ul className="text-sm text-gray-300 space-y-1 text-left">
                <li>• 1,000 customers</li>
                <li>• $1.2M ARR</li>
                <li>• SOC2 Type II certified</li>
              </ul>
            </div>
          </div>

          <div className="bg-gradient-to-r from-cyan-600/20 to-blue-600/20 border border-cyan-500/30 rounded-2xl p-6 max-w-3xl mb-8">
            <h3 className="text-2xl font-bold text-white mb-4">What You Get</h3>
            <div className="grid grid-cols-2 gap-6 text-left">
              <ul className="space-y-2 text-gray-300">
                <li className="flex items-start gap-2">
                  <CheckCircle2 className="w-5 h-5 text-cyan-400 flex-shrink-0 mt-0.5" />
                  <span>20-year SIGINT expert founder</span>
                </li>
                <li className="flex items-start gap-2">
                  <CheckCircle2 className="w-5 h-5 text-cyan-400 flex-shrink-0 mt-0.5" />
                  <span>Production-ready platform (86+ modules, 2,900+ tests)</span>
                </li>
                <li className="flex items-start gap-2">
                  <CheckCircle2 className="w-5 h-5 text-cyan-400 flex-shrink-0 mt-0.5" />
                  <span>Mission-driven (democratize security)</span>
                </li>
              </ul>
              <ul className="space-y-2 text-gray-300">
                <li className="flex items-start gap-2">
                  <CheckCircle2 className="w-5 h-5 text-cyan-400 flex-shrink-0 mt-0.5" />
                  <span>$24.8B TAM, growing 15-18% CAGR</span>
                </li>
                <li className="flex items-start gap-2">
                  <CheckCircle2 className="w-5 h-5 text-cyan-400 flex-shrink-0 mt-0.5" />
                  <span>Unique consultancy-first features</span>
                </li>
                <li className="flex items-start gap-2">
                  <CheckCircle2 className="w-5 h-5 text-cyan-400 flex-shrink-0 mt-0.5" />
                  <span>Veteran founder (access to veteran VCs)</span>
                </li>
              </ul>
            </div>
          </div>

          <div className="text-2xl text-gray-300">
            <div className="mb-2">Contact: <span className="text-cyan-400 font-semibold">investors@genialarchitect.io</span></div>
            <div>Live Demo: <span className="text-cyan-400 font-semibold">heroforge.genialarchitect.io</span></div>
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
          <h2 className="text-6xl font-bold text-white mb-8">My Vision</h2>
          <h3 className="text-5xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-blue-500 mb-12 max-w-5xl">
            Make Enterprise-Grade Security Accessible to Everyone
          </h3>
          <div className="max-w-4xl space-y-8 text-2xl text-gray-300">
            <p className="leading-relaxed">
              After 20 years defending against nation-state threats, I know what elite security looks like.
            </p>
            <p className="leading-relaxed">
              <span className="text-white font-bold">It shouldn't be exclusive to governments and Fortune 500.</span>
            </p>
            <p className="leading-relaxed">
              Small businesses, consultancies, MSPs—<span className="text-cyan-400 font-bold">they deserve protection too</span>.
            </p>
            <p className="leading-relaxed">
              HeroForge is my mission to <span className="text-cyan-400 font-bold">democratize security</span>.
              To make what I learned in 20 years <span className="text-white font-bold">affordable for everyone</span>.
            </p>
          </div>

          <div className="mt-16 bg-gradient-to-r from-cyan-600/20 to-blue-600/20 border border-cyan-500/30 rounded-2xl px-12 py-8 max-w-4xl">
            <p className="text-3xl font-bold text-white mb-4">
              Security is a right, not a luxury.
            </p>
            <p className="text-xl text-gray-300">
              Join me in making the American security architecture affordable for all.
            </p>
          </div>

          <div className="mt-12 text-gray-400 text-lg">
            Built with ❤️ by a disabled veteran who wants to give back
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
