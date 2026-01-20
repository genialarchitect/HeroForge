import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import {
  Shield,
  Palette,
  Building2,
  Users,
  Globe,
  Settings,
  Check,
  ArrowRight,
  Upload,
  Eye,
  DollarSign,
  BarChart3,
  Mail,
  FileText,
  Lock,
  Zap,
  Headphones,
  CreditCard,
  PieChart,
  TrendingUp,
  UserPlus,
  Briefcase,
  Star,
  ChevronDown,
  ChevronUp,
  ExternalLink,
} from 'lucide-react';

interface PricingTier {
  name: string;
  price: number;
  clients: number;
  features: string[];
  highlighted?: boolean;
}

interface Client {
  id: string;
  name: string;
  logo?: string;
  domain: string;
  users: number;
  scans: number;
  mrr: number;
  status: 'active' | 'trial' | 'suspended';
  created: string;
}

const pricingTiers: PricingTier[] = [
  {
    name: 'Starter',
    price: 299,
    clients: 5,
    features: [
      'Up to 5 client tenants',
      'Basic branding (logo, colors)',
      'Standard support',
      'Monthly billing to clients',
      'Basic analytics dashboard',
    ],
  },
  {
    name: 'Professional',
    price: 799,
    clients: 25,
    highlighted: true,
    features: [
      'Up to 25 client tenants',
      'Full branding customization',
      'Custom domain support',
      'Priority support',
      'Usage-based client billing',
      'Advanced analytics',
      'API access for integrations',
      'Custom email templates',
    ],
  },
  {
    name: 'Enterprise',
    price: 1999,
    clients: -1,
    features: [
      'Unlimited client tenants',
      'Complete white-label solution',
      'Multiple custom domains',
      'Dedicated support manager',
      'Custom billing integration',
      'Full analytics & reporting',
      'PSA integration (ConnectWise, Autotask)',
      'Custom SLA options',
      'Training for your team',
    ],
  },
];

const demoClients: Client[] = [
  {
    id: '1',
    name: 'Acme Security Corp',
    domain: 'security.acmecorp.com',
    users: 15,
    scans: 234,
    mrr: 499,
    status: 'active',
    created: '2025-08-15',
  },
  {
    id: '2',
    name: 'TechStart Inc',
    domain: 'scan.techstart.io',
    users: 8,
    scans: 89,
    mrr: 199,
    status: 'active',
    created: '2025-10-01',
  },
  {
    id: '3',
    name: 'SecureFinance LLC',
    domain: 'vuln.securefinance.com',
    users: 25,
    scans: 456,
    mrr: 799,
    status: 'active',
    created: '2025-06-20',
  },
  {
    id: '4',
    name: 'NewClient Demo',
    domain: 'demo.newclient.com',
    users: 3,
    scans: 12,
    mrr: 0,
    status: 'trial',
    created: '2026-01-10',
  },
];

export default function WhiteLabelPage() {
  const [activeTab, setActiveTab] = useState<'overview' | 'branding' | 'clients' | 'billing' | 'settings'>('overview');
  const [primaryColor, setPrimaryColor] = useState('#06b6d4');
  const [companyName, setCompanyName] = useState('Your Security Co');
  const [expandedFaq, setExpandedFaq] = useState<string | null>(null);

  const totalMrr = demoClients.reduce((sum, c) => sum + c.mrr, 0);
  const activeClients = demoClients.filter(c => c.status === 'active').length;
  const totalScans = demoClients.reduce((sum, c) => sum + c.scans, 0);

  const faqs = [
    {
      id: '1',
      question: 'How does white-labeling work?',
      answer: 'White-labeling allows you to rebrand HeroForge with your company\'s logo, colors, and domain. Your clients will see your branding throughout the platform, including login pages, dashboards, reports, and emails.',
    },
    {
      id: '2',
      question: 'Can I set my own pricing for clients?',
      answer: 'Yes! You have full control over pricing. Set monthly or annual subscriptions, usage-based pricing, or custom quotes. You keep the difference between your price and the wholesale cost.',
    },
    {
      id: '3',
      question: 'What PSA integrations are supported?',
      answer: 'We support ConnectWise Manage, Datto Autotask, and HaloPSA. Integration allows automatic ticket creation, billing sync, and client management.',
    },
    {
      id: '4',
      question: 'Can clients see that HeroForge powers the platform?',
      answer: 'No. With full white-labeling, there\'s no visible mention of HeroForge. Your clients will only see your branding. The "Powered by" footer can be removed on Professional and Enterprise plans.',
    },
    {
      id: '5',
      question: 'How do I handle support for my clients?',
      answer: 'You provide first-line support to your clients. We provide you with documentation, training, and escalation paths. Enterprise plans include a dedicated support manager for your team.',
    },
  ];

  return (
    <div className="min-h-screen bg-gray-900">
      {/* Header */}
      <header className="bg-gray-800 border-b border-gray-700">
        <div className="max-w-7xl mx-auto px-4 py-4">
          <div className="flex items-center justify-between">
            <Link to="/" className="flex items-center gap-2">
              <Shield className="w-8 h-8 text-cyan-500" />
              <span className="text-xl font-bold text-white">HeroForge</span>
              <span className="text-gray-500 ml-2">| Partner Portal</span>
            </Link>
            <nav className="hidden md:flex items-center gap-6">
              <Link to="/pricing" className="text-gray-300 hover:text-white">Pricing</Link>
              <Link to="/docs" className="text-gray-300 hover:text-white">Docs</Link>
              <Link to="/login" className="px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg">Partner Login</Link>
            </nav>
          </div>
        </div>
      </header>

      {/* Hero Section (shown when not logged in - for demo showing full page) */}
      {activeTab === 'overview' && (
        <>
          <section className="py-16 bg-gradient-to-b from-gray-800 to-gray-900">
            <div className="max-w-7xl mx-auto px-4">
              <div className="grid md:grid-cols-2 gap-12 items-center">
                <div>
                  <div className="inline-flex items-center gap-2 px-4 py-2 bg-purple-500/20 rounded-full mb-6">
                    <Building2 className="w-5 h-5 text-purple-400" />
                    <span className="text-purple-400 font-medium">MSP & Reseller Program</span>
                  </div>
                  <h1 className="text-4xl md:text-5xl font-bold text-white mb-6">
                    White-Label Security Platform for Your Clients
                  </h1>
                  <p className="text-xl text-gray-400 mb-8">
                    Offer enterprise-grade vulnerability scanning under your own brand.
                    Generate recurring revenue while delivering exceptional security services.
                  </p>
                  <div className="flex flex-wrap gap-4">
                    <button className="px-6 py-3 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg font-semibold flex items-center gap-2">
                      Become a Partner
                      <ArrowRight className="w-5 h-5" />
                    </button>
                    <button className="px-6 py-3 border border-gray-600 text-gray-300 hover:bg-gray-800 rounded-lg font-semibold">
                      Schedule Demo
                    </button>
                  </div>
                </div>
                <div className="relative">
                  {/* Mock White-Label Preview */}
                  <div className="bg-gray-800 rounded-xl border border-gray-700 p-4 shadow-2xl">
                    <div className="flex items-center gap-3 mb-4">
                      <div className="w-8 h-8 rounded-lg flex items-center justify-center" style={{ backgroundColor: primaryColor }}>
                        <Shield className="w-5 h-5 text-white" />
                      </div>
                      <span className="text-white font-semibold">{companyName}</span>
                    </div>
                    <div className="bg-gray-900 rounded-lg p-4 mb-4">
                      <div className="flex items-center justify-between mb-4">
                        <span className="text-gray-400 text-sm">Security Dashboard</span>
                        <span className="px-2 py-1 bg-green-500/20 text-green-400 rounded text-xs">Live</span>
                      </div>
                      <div className="grid grid-cols-3 gap-4 mb-4">
                        <div className="bg-gray-800 rounded p-3">
                          <div className="text-2xl font-bold text-white">12</div>
                          <div className="text-xs text-gray-500">Active Scans</div>
                        </div>
                        <div className="bg-gray-800 rounded p-3">
                          <div className="text-2xl font-bold text-red-400">24</div>
                          <div className="text-xs text-gray-500">Critical</div>
                        </div>
                        <div className="bg-gray-800 rounded p-3">
                          <div className="text-2xl font-bold text-amber-400">89</div>
                          <div className="text-xs text-gray-500">Total Vulns</div>
                        </div>
                      </div>
                      <div className="h-24 bg-gray-800 rounded flex items-end gap-1 p-2">
                        {[40, 65, 55, 80, 70, 90, 75].map((h, i) => (
                          <div
                            key={i}
                            className="flex-1 rounded-t"
                            style={{ height: `${h}%`, backgroundColor: primaryColor }}
                          />
                        ))}
                      </div>
                    </div>
                    <div className="text-center text-xs text-gray-600">
                      Your brand, your platform
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </section>

          {/* Features Grid */}
          <section className="py-16">
            <div className="max-w-7xl mx-auto px-4">
              <h2 className="text-3xl font-bold text-white mb-8 text-center">Everything You Need to Succeed</h2>
              <div className="grid md:grid-cols-4 gap-6">
                <div className="bg-gray-800 rounded-xl p-6 border border-gray-700">
                  <div className="w-12 h-12 bg-cyan-500/20 rounded-lg flex items-center justify-center mb-4">
                    <Palette className="w-6 h-6 text-cyan-500" />
                  </div>
                  <h3 className="text-lg font-semibold text-white mb-2">Full Branding</h3>
                  <p className="text-gray-400 text-sm">Custom logo, colors, favicon, and email templates. Your brand everywhere.</p>
                </div>
                <div className="bg-gray-800 rounded-xl p-6 border border-gray-700">
                  <div className="w-12 h-12 bg-purple-500/20 rounded-lg flex items-center justify-center mb-4">
                    <Globe className="w-6 h-6 text-purple-500" />
                  </div>
                  <h3 className="text-lg font-semibold text-white mb-2">Custom Domains</h3>
                  <p className="text-gray-400 text-sm">Use your own domain (security.yourcompany.com) with SSL included.</p>
                </div>
                <div className="bg-gray-800 rounded-xl p-6 border border-gray-700">
                  <div className="w-12 h-12 bg-green-500/20 rounded-lg flex items-center justify-center mb-4">
                    <Users className="w-6 h-6 text-green-500" />
                  </div>
                  <h3 className="text-lg font-semibold text-white mb-2">Multi-Tenant</h3>
                  <p className="text-gray-400 text-sm">Isolated environments for each client with granular permissions.</p>
                </div>
                <div className="bg-gray-800 rounded-xl p-6 border border-gray-700">
                  <div className="w-12 h-12 bg-amber-500/20 rounded-lg flex items-center justify-center mb-4">
                    <DollarSign className="w-6 h-6 text-amber-500" />
                  </div>
                  <h3 className="text-lg font-semibold text-white mb-2">Flexible Billing</h3>
                  <p className="text-gray-400 text-sm">Set your own pricing. Monthly, annual, or usage-based billing.</p>
                </div>
                <div className="bg-gray-800 rounded-xl p-6 border border-gray-700">
                  <div className="w-12 h-12 bg-red-500/20 rounded-lg flex items-center justify-center mb-4">
                    <FileText className="w-6 h-6 text-red-500" />
                  </div>
                  <h3 className="text-lg font-semibold text-white mb-2">White-Label Reports</h3>
                  <p className="text-gray-400 text-sm">PDF and HTML reports with your branding and custom cover pages.</p>
                </div>
                <div className="bg-gray-800 rounded-xl p-6 border border-gray-700">
                  <div className="w-12 h-12 bg-blue-500/20 rounded-lg flex items-center justify-center mb-4">
                    <BarChart3 className="w-6 h-6 text-blue-500" />
                  </div>
                  <h3 className="text-lg font-semibold text-white mb-2">Partner Analytics</h3>
                  <p className="text-gray-400 text-sm">Track usage, revenue, and client health across your portfolio.</p>
                </div>
                <div className="bg-gray-800 rounded-xl p-6 border border-gray-700">
                  <div className="w-12 h-12 bg-pink-500/20 rounded-lg flex items-center justify-center mb-4">
                    <Zap className="w-6 h-6 text-pink-500" />
                  </div>
                  <h3 className="text-lg font-semibold text-white mb-2">PSA Integration</h3>
                  <p className="text-gray-400 text-sm">ConnectWise, Autotask, and HaloPSA for seamless operations.</p>
                </div>
                <div className="bg-gray-800 rounded-xl p-6 border border-gray-700">
                  <div className="w-12 h-12 bg-indigo-500/20 rounded-lg flex items-center justify-center mb-4">
                    <Headphones className="w-6 h-6 text-indigo-500" />
                  </div>
                  <h3 className="text-lg font-semibold text-white mb-2">Partner Support</h3>
                  <p className="text-gray-400 text-sm">Dedicated partner success team and technical escalation paths.</p>
                </div>
              </div>
            </div>
          </section>

          {/* Pricing */}
          <section className="py-16 bg-gray-800">
            <div className="max-w-7xl mx-auto px-4">
              <h2 className="text-3xl font-bold text-white mb-2 text-center">Partner Pricing</h2>
              <p className="text-gray-400 text-center mb-8">Wholesale pricing that lets you build profitable margins</p>
              <div className="grid md:grid-cols-3 gap-8">
                {pricingTiers.map((tier) => (
                  <div
                    key={tier.name}
                    className={`bg-gray-900 rounded-xl border ${
                      tier.highlighted ? 'border-cyan-500 ring-2 ring-cyan-500/20' : 'border-gray-700'
                    } overflow-hidden`}
                  >
                    {tier.highlighted && (
                      <div className="bg-cyan-500 text-center py-2 text-sm font-medium text-white">
                        Most Popular
                      </div>
                    )}
                    <div className="p-6">
                      <h3 className="text-xl font-semibold text-white mb-2">{tier.name}</h3>
                      <div className="mb-4">
                        <span className="text-4xl font-bold text-white">${tier.price}</span>
                        <span className="text-gray-500">/month</span>
                      </div>
                      <p className="text-gray-400 mb-6">
                        {tier.clients === -1 ? 'Unlimited clients' : `Up to ${tier.clients} clients`}
                      </p>
                      <ul className="space-y-3 mb-6">
                        {tier.features.map((feature, idx) => (
                          <li key={idx} className="flex items-start gap-2 text-gray-300 text-sm">
                            <Check className="w-5 h-5 text-green-500 flex-shrink-0" />
                            <span>{feature}</span>
                          </li>
                        ))}
                      </ul>
                      <button
                        className={`w-full py-3 rounded-lg font-medium ${
                          tier.highlighted
                            ? 'bg-cyan-600 hover:bg-cyan-700 text-white'
                            : 'border border-gray-600 text-gray-300 hover:bg-gray-800'
                        }`}
                      >
                        Get Started
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </section>

          {/* Demo Partner Dashboard */}
          <section className="py-16">
            <div className="max-w-7xl mx-auto px-4">
              <h2 className="text-3xl font-bold text-white mb-2 text-center">Partner Dashboard Preview</h2>
              <p className="text-gray-400 text-center mb-8">Manage all your clients from a single dashboard</p>

              {/* Dashboard Tabs */}
              <div className="bg-gray-800 rounded-xl border border-gray-700 overflow-hidden">
                <div className="border-b border-gray-700">
                  <div className="flex gap-1 px-4 pt-2">
                    {[
                      { id: 'overview', label: 'Overview', icon: <BarChart3 className="w-4 h-4" /> },
                      { id: 'clients', label: 'Clients', icon: <Users className="w-4 h-4" /> },
                      { id: 'branding', label: 'Branding', icon: <Palette className="w-4 h-4" /> },
                      { id: 'billing', label: 'Billing', icon: <CreditCard className="w-4 h-4" /> },
                    ].map((tab) => (
                      <button
                        key={tab.id}
                        onClick={() => setActiveTab(tab.id as typeof activeTab)}
                        className={`flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-t-lg transition-colors ${
                          activeTab === tab.id || (activeTab === 'overview' && tab.id === 'overview')
                            ? 'bg-gray-900 text-cyan-400'
                            : 'text-gray-400 hover:text-white'
                        }`}
                      >
                        {tab.icon}
                        {tab.label}
                      </button>
                    ))}
                  </div>
                </div>

                <div className="p-6">
                  {/* Stats Row */}
                  <div className="grid md:grid-cols-4 gap-4 mb-8">
                    <div className="bg-gray-900 rounded-lg p-4 border border-gray-700">
                      <div className="flex items-center gap-3">
                        <div className="w-10 h-10 bg-green-500/20 rounded-lg flex items-center justify-center">
                          <DollarSign className="w-5 h-5 text-green-500" />
                        </div>
                        <div>
                          <p className="text-sm text-gray-500">Monthly Revenue</p>
                          <p className="text-2xl font-bold text-white">${totalMrr.toLocaleString()}</p>
                        </div>
                      </div>
                    </div>
                    <div className="bg-gray-900 rounded-lg p-4 border border-gray-700">
                      <div className="flex items-center gap-3">
                        <div className="w-10 h-10 bg-cyan-500/20 rounded-lg flex items-center justify-center">
                          <Building2 className="w-5 h-5 text-cyan-500" />
                        </div>
                        <div>
                          <p className="text-sm text-gray-500">Active Clients</p>
                          <p className="text-2xl font-bold text-white">{activeClients}</p>
                        </div>
                      </div>
                    </div>
                    <div className="bg-gray-900 rounded-lg p-4 border border-gray-700">
                      <div className="flex items-center gap-3">
                        <div className="w-10 h-10 bg-purple-500/20 rounded-lg flex items-center justify-center">
                          <Shield className="w-5 h-5 text-purple-500" />
                        </div>
                        <div>
                          <p className="text-sm text-gray-500">Total Scans</p>
                          <p className="text-2xl font-bold text-white">{totalScans}</p>
                        </div>
                      </div>
                    </div>
                    <div className="bg-gray-900 rounded-lg p-4 border border-gray-700">
                      <div className="flex items-center gap-3">
                        <div className="w-10 h-10 bg-amber-500/20 rounded-lg flex items-center justify-center">
                          <TrendingUp className="w-5 h-5 text-amber-500" />
                        </div>
                        <div>
                          <p className="text-sm text-gray-500">Growth</p>
                          <p className="text-2xl font-bold text-green-400">+23%</p>
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Clients Table */}
                  <div className="bg-gray-900 rounded-lg border border-gray-700 overflow-hidden">
                    <div className="p-4 border-b border-gray-700 flex items-center justify-between">
                      <h3 className="font-semibold text-white">Your Clients</h3>
                      <button className="flex items-center gap-2 px-3 py-1.5 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg text-sm">
                        <UserPlus className="w-4 h-4" />
                        Add Client
                      </button>
                    </div>
                    <table className="w-full">
                      <thead className="bg-gray-800">
                        <tr>
                          <th className="text-left px-4 py-3 text-sm font-medium text-gray-400">Client</th>
                          <th className="text-left px-4 py-3 text-sm font-medium text-gray-400">Domain</th>
                          <th className="text-left px-4 py-3 text-sm font-medium text-gray-400">Users</th>
                          <th className="text-left px-4 py-3 text-sm font-medium text-gray-400">Scans</th>
                          <th className="text-left px-4 py-3 text-sm font-medium text-gray-400">MRR</th>
                          <th className="text-left px-4 py-3 text-sm font-medium text-gray-400">Status</th>
                          <th className="text-left px-4 py-3 text-sm font-medium text-gray-400"></th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-gray-700">
                        {demoClients.map((client) => (
                          <tr key={client.id} className="hover:bg-gray-800/50">
                            <td className="px-4 py-3">
                              <div className="flex items-center gap-3">
                                <div className="w-8 h-8 bg-gray-700 rounded-lg flex items-center justify-center">
                                  <Building2 className="w-4 h-4 text-gray-400" />
                                </div>
                                <span className="text-white font-medium">{client.name}</span>
                              </div>
                            </td>
                            <td className="px-4 py-3 text-gray-400 text-sm">{client.domain}</td>
                            <td className="px-4 py-3 text-gray-400">{client.users}</td>
                            <td className="px-4 py-3 text-gray-400">{client.scans}</td>
                            <td className="px-4 py-3 text-white font-medium">
                              {client.mrr > 0 ? `$${client.mrr}` : '-'}
                            </td>
                            <td className="px-4 py-3">
                              <span className={`px-2 py-1 rounded-full text-xs font-medium ${
                                client.status === 'active' ? 'bg-green-500/20 text-green-400' :
                                client.status === 'trial' ? 'bg-amber-500/20 text-amber-400' :
                                'bg-red-500/20 text-red-400'
                              }`}>
                                {client.status}
                              </span>
                            </td>
                            <td className="px-4 py-3">
                              <button className="text-gray-400 hover:text-white">
                                <Settings className="w-4 h-4" />
                              </button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              </div>
            </div>
          </section>

          {/* Branding Preview */}
          <section className="py-16 bg-gray-800">
            <div className="max-w-7xl mx-auto px-4">
              <h2 className="text-3xl font-bold text-white mb-2 text-center">Customize Your Brand</h2>
              <p className="text-gray-400 text-center mb-8">See your branding in real-time</p>

              <div className="grid md:grid-cols-2 gap-8">
                {/* Controls */}
                <div className="bg-gray-900 rounded-xl p-6 border border-gray-700">
                  <h3 className="text-lg font-semibold text-white mb-6">Branding Settings</h3>

                  <div className="space-y-6">
                    <div>
                      <label className="block text-sm font-medium text-gray-400 mb-2">Company Name</label>
                      <input
                        type="text"
                        value={companyName}
                        onChange={(e) => setCompanyName(e.target.value)}
                        className="w-full px-4 py-2 bg-gray-800 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-cyan-500"
                      />
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-gray-400 mb-2">Primary Color</label>
                      <div className="flex items-center gap-3">
                        <input
                          type="color"
                          value={primaryColor}
                          onChange={(e) => setPrimaryColor(e.target.value)}
                          className="w-12 h-12 rounded-lg cursor-pointer"
                        />
                        <input
                          type="text"
                          value={primaryColor}
                          onChange={(e) => setPrimaryColor(e.target.value)}
                          className="flex-1 px-4 py-2 bg-gray-800 border border-gray-600 rounded-lg text-white font-mono focus:outline-none focus:border-cyan-500"
                        />
                      </div>
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-gray-400 mb-2">Logo</label>
                      <div className="border-2 border-dashed border-gray-600 rounded-lg p-8 text-center hover:border-gray-500 cursor-pointer">
                        <Upload className="w-8 h-8 text-gray-500 mx-auto mb-2" />
                        <p className="text-gray-400 text-sm">Drop your logo here or click to upload</p>
                        <p className="text-gray-500 text-xs mt-1">PNG, SVG up to 2MB</p>
                      </div>
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-gray-400 mb-2">Custom Domain</label>
                      <div className="flex items-center gap-2">
                        <input
                          type="text"
                          placeholder="security"
                          className="flex-1 px-4 py-2 bg-gray-800 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-cyan-500"
                        />
                        <span className="text-gray-500">.yourcompany.com</span>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Preview */}
                <div className="bg-gray-900 rounded-xl p-6 border border-gray-700">
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="text-lg font-semibold text-white">Live Preview</h3>
                    <span className="px-2 py-1 bg-green-500/20 text-green-400 rounded text-xs">Real-time</span>
                  </div>

                  {/* Mock Login Page */}
                  <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
                    <div className="flex items-center gap-3 mb-6">
                      <div
                        className="w-10 h-10 rounded-lg flex items-center justify-center"
                        style={{ backgroundColor: primaryColor }}
                      >
                        <Shield className="w-6 h-6 text-white" />
                      </div>
                      <span className="text-xl font-bold text-white">{companyName}</span>
                    </div>

                    <div className="space-y-4">
                      <input
                        type="email"
                        placeholder="Email address"
                        className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white"
                        disabled
                      />
                      <input
                        type="password"
                        placeholder="Password"
                        className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white"
                        disabled
                      />
                      <button
                        className="w-full py-2 rounded-lg text-white font-medium"
                        style={{ backgroundColor: primaryColor }}
                      >
                        Sign In
                      </button>
                    </div>

                    <p className="text-center text-gray-500 text-sm mt-4">
                      Protected by {companyName}
                    </p>
                  </div>
                </div>
              </div>
            </div>
          </section>

          {/* FAQ */}
          <section className="py-16">
            <div className="max-w-3xl mx-auto px-4">
              <h2 className="text-3xl font-bold text-white mb-8 text-center">Frequently Asked Questions</h2>
              <div className="space-y-4">
                {faqs.map((faq) => (
                  <div key={faq.id} className="bg-gray-800 rounded-xl border border-gray-700 overflow-hidden">
                    <button
                      onClick={() => setExpandedFaq(expandedFaq === faq.id ? null : faq.id)}
                      className="w-full px-6 py-4 flex items-center justify-between text-left"
                    >
                      <span className="text-white font-medium">{faq.question}</span>
                      {expandedFaq === faq.id ? (
                        <ChevronUp className="w-5 h-5 text-gray-400" />
                      ) : (
                        <ChevronDown className="w-5 h-5 text-gray-400" />
                      )}
                    </button>
                    {expandedFaq === faq.id && (
                      <div className="px-6 pb-4">
                        <p className="text-gray-400">{faq.answer}</p>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          </section>

          {/* CTA */}
          <section className="py-16 bg-gradient-to-r from-purple-600 to-pink-600">
            <div className="max-w-4xl mx-auto px-4 text-center">
              <h2 className="text-3xl font-bold text-white mb-4">Ready to Grow Your Security Business?</h2>
              <p className="text-xl text-white/80 mb-8">
                Join 200+ MSPs and security consultants already using HeroForge white-label.
              </p>
              <div className="flex flex-wrap justify-center gap-4">
                <button className="px-8 py-3 bg-white text-purple-600 rounded-lg font-semibold hover:bg-gray-100 flex items-center gap-2">
                  Apply for Partnership
                  <ArrowRight className="w-5 h-5" />
                </button>
                <button className="px-8 py-3 border-2 border-white text-white rounded-lg font-semibold hover:bg-white/10">
                  Talk to Sales
                </button>
              </div>
            </div>
          </section>
        </>
      )}

      {/* Footer */}
      <footer className="bg-gray-800 border-t border-gray-700 py-8">
        <div className="max-w-7xl mx-auto px-4 text-center text-gray-400">
          <p>&copy; 2026 HeroForge. All rights reserved.</p>
        </div>
      </footer>
    </div>
  );
}
