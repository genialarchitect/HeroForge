import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import {
  Shield,
  Search,
  Download,
  Star,
  Users,
  Package,
  FileText,
  Code,
  Zap,
  CheckCircle,
  Heart,
  Eye,
  ExternalLink,
  Filter,
  TrendingUp,
  Clock,
  Award,
  Tag,
  Upload,
  Plus,
  ChevronDown,
  MessageSquare,
  GitBranch,
  Box,
  Layout,
  Terminal,
  Palette,
  Globe,
  Shield as ShieldIcon,
  AlertTriangle,
  Server,
  Database,
  Cloud,
  Lock,
  Briefcase,
} from 'lucide-react';

interface MarketplaceItem {
  id: string;
  name: string;
  description: string;
  type: 'template' | 'plugin' | 'integration' | 'report' | 'workflow' | 'nuclei';
  category: string;
  author: {
    name: string;
    verified: boolean;
    avatar?: string;
  };
  downloads: number;
  rating: number;
  reviews: number;
  price: number | 'free';
  tags: string[];
  featured?: boolean;
  isNew?: boolean;
  updatedAt: string;
  version: string;
  compatibility: string;
}

interface Collection {
  id: string;
  name: string;
  description: string;
  itemCount: number;
  curator: string;
  icon: React.ReactNode;
}

const marketplaceItems: MarketplaceItem[] = [
  {
    id: '1',
    name: 'OWASP Top 10 Nuclei Templates',
    description: 'Comprehensive Nuclei template pack covering all OWASP Top 10 2021 vulnerabilities with detailed detection rules.',
    type: 'nuclei',
    category: 'Web Security',
    author: { name: 'SecurityPro', verified: true },
    downloads: 15420,
    rating: 4.9,
    reviews: 234,
    price: 'free',
    tags: ['owasp', 'web', 'nuclei', 'vulnerabilities'],
    featured: true,
    updatedAt: '2026-01-15',
    version: '2.1.0',
    compatibility: 'HeroForge 3.0+',
  },
  {
    id: '2',
    name: 'Executive Report Template',
    description: 'Professional executive summary report template with risk scoring, charts, and customizable branding.',
    type: 'report',
    category: 'Reports',
    author: { name: 'ReportMaster', verified: true },
    downloads: 8930,
    rating: 4.8,
    reviews: 156,
    price: 29,
    tags: ['report', 'executive', 'pdf', 'professional'],
    updatedAt: '2026-01-10',
    version: '1.5.0',
    compatibility: 'HeroForge 2.5+',
  },
  {
    id: '3',
    name: 'Jira Integration Plugin',
    description: 'Seamlessly create Jira tickets from vulnerabilities with custom field mapping and automatic updates.',
    type: 'plugin',
    category: 'Integrations',
    author: { name: 'IntegrationHub', verified: true },
    downloads: 12350,
    rating: 4.7,
    reviews: 189,
    price: 'free',
    tags: ['jira', 'integration', 'ticketing', 'atlassian'],
    featured: true,
    updatedAt: '2026-01-18',
    version: '3.2.1',
    compatibility: 'HeroForge 3.0+',
  },
  {
    id: '4',
    name: 'AWS Security Scan Template',
    description: 'Pre-configured scan template for comprehensive AWS security assessment including IAM, S3, EC2, and more.',
    type: 'template',
    category: 'Cloud',
    author: { name: 'CloudSecOps', verified: true },
    downloads: 6780,
    rating: 4.6,
    reviews: 98,
    price: 49,
    tags: ['aws', 'cloud', 'iam', 's3', 'ec2'],
    isNew: true,
    updatedAt: '2026-01-19',
    version: '1.0.0',
    compatibility: 'HeroForge 3.0+',
  },
  {
    id: '5',
    name: 'PCI-DSS Compliance Workflow',
    description: 'Automated workflow for PCI-DSS compliance assessment with evidence collection and gap analysis.',
    type: 'workflow',
    category: 'Compliance',
    author: { name: 'ComplianceGuru', verified: true },
    downloads: 4520,
    rating: 4.9,
    reviews: 67,
    price: 99,
    tags: ['pci-dss', 'compliance', 'workflow', 'automation'],
    updatedAt: '2026-01-12',
    version: '2.0.0',
    compatibility: 'HeroForge 3.0+',
  },
  {
    id: '6',
    name: 'Slack Notification Plugin',
    description: 'Real-time Slack notifications for scan completions, critical vulnerabilities, and system alerts.',
    type: 'plugin',
    category: 'Notifications',
    author: { name: 'SlackDev', verified: false },
    downloads: 9870,
    rating: 4.5,
    reviews: 143,
    price: 'free',
    tags: ['slack', 'notifications', 'alerts', 'messaging'],
    updatedAt: '2026-01-08',
    version: '1.8.2',
    compatibility: 'HeroForge 2.0+',
  },
  {
    id: '7',
    name: 'Active Directory Assessment Templates',
    description: 'Complete AD security assessment templates including BloodHound integration and attack path analysis.',
    type: 'template',
    category: 'Active Directory',
    author: { name: 'ADSecurityTeam', verified: true },
    downloads: 5640,
    rating: 4.8,
    reviews: 89,
    price: 79,
    tags: ['active-directory', 'bloodhound', 'windows', 'kerberos'],
    featured: true,
    updatedAt: '2026-01-16',
    version: '1.3.0',
    compatibility: 'HeroForge 3.0+',
  },
  {
    id: '8',
    name: 'Dark Mode Report Theme',
    description: 'Sleek dark mode theme for all report types with modern styling and improved readability.',
    type: 'report',
    category: 'Themes',
    author: { name: 'DesignStudio', verified: false },
    downloads: 3210,
    rating: 4.4,
    reviews: 45,
    price: 19,
    tags: ['theme', 'dark-mode', 'report', 'design'],
    isNew: true,
    updatedAt: '2026-01-17',
    version: '1.0.0',
    compatibility: 'HeroForge 2.5+',
  },
  {
    id: '9',
    name: 'Container Security Templates',
    description: 'Docker and Kubernetes security scanning templates with CIS benchmark checks and misconfig detection.',
    type: 'nuclei',
    category: 'Container',
    author: { name: 'K8sSecPro', verified: true },
    downloads: 7890,
    rating: 4.7,
    reviews: 112,
    price: 'free',
    tags: ['docker', 'kubernetes', 'container', 'cis'],
    updatedAt: '2026-01-14',
    version: '2.4.0',
    compatibility: 'HeroForge 3.0+',
  },
  {
    id: '10',
    name: 'ServiceNow Integration',
    description: 'Full ServiceNow integration with incident creation, CMDB sync, and change request automation.',
    type: 'integration',
    category: 'ITSM',
    author: { name: 'ServiceNowPro', verified: true },
    downloads: 4320,
    rating: 4.6,
    reviews: 78,
    price: 149,
    tags: ['servicenow', 'itsm', 'cmdb', 'incidents'],
    updatedAt: '2026-01-11',
    version: '2.1.0',
    compatibility: 'HeroForge 3.0+',
  },
  {
    id: '11',
    name: 'API Security Testing Pack',
    description: 'Comprehensive API security testing templates including authentication bypass, injection, and rate limiting checks.',
    type: 'template',
    category: 'API Security',
    author: { name: 'APISec', verified: true },
    downloads: 8450,
    rating: 4.8,
    reviews: 134,
    price: 59,
    tags: ['api', 'rest', 'graphql', 'authentication'],
    featured: true,
    updatedAt: '2026-01-13',
    version: '1.6.0',
    compatibility: 'HeroForge 3.0+',
  },
  {
    id: '12',
    name: 'Remediation Workflow Automator',
    description: 'Automate remediation workflows with playbooks, approval chains, and verification scans.',
    type: 'workflow',
    category: 'Automation',
    author: { name: 'AutomateSec', verified: true },
    downloads: 3890,
    rating: 4.5,
    reviews: 56,
    price: 'free',
    tags: ['remediation', 'automation', 'workflow', 'playbooks'],
    isNew: true,
    updatedAt: '2026-01-20',
    version: '1.0.0',
    compatibility: 'HeroForge 3.0+',
  },
];

const collections: Collection[] = [
  {
    id: '1',
    name: 'Pentester Essentials',
    description: 'Must-have tools for professional penetration testers',
    itemCount: 24,
    curator: 'HeroForge Team',
    icon: <Terminal className="w-6 h-6 text-cyan-500" />,
  },
  {
    id: '2',
    name: 'Compliance Starter Pack',
    description: 'Everything you need for compliance assessments',
    itemCount: 18,
    curator: 'ComplianceGuru',
    icon: <ShieldIcon className="w-6 h-6 text-green-500" />,
  },
  {
    id: '3',
    name: 'Cloud Security Bundle',
    description: 'AWS, Azure, and GCP security assessment tools',
    itemCount: 32,
    curator: 'CloudSecOps',
    icon: <Cloud className="w-6 h-6 text-purple-500" />,
  },
  {
    id: '4',
    name: 'MSP Toolkit',
    description: 'Tools for managed security service providers',
    itemCount: 15,
    curator: 'MSPPro',
    icon: <Briefcase className="w-6 h-6 text-amber-500" />,
  },
];

const typeIcons: Record<string, React.ReactNode> = {
  template: <Layout className="w-5 h-5" />,
  plugin: <Box className="w-5 h-5" />,
  integration: <GitBranch className="w-5 h-5" />,
  report: <FileText className="w-5 h-5" />,
  workflow: <Zap className="w-5 h-5" />,
  nuclei: <Code className="w-5 h-5" />,
};

const categories = [
  'All',
  'Web Security',
  'Cloud',
  'Active Directory',
  'Container',
  'Compliance',
  'API Security',
  'Reports',
  'Integrations',
  'Notifications',
  'Themes',
  'Automation',
];

const types = [
  { id: 'all', label: 'All Types' },
  { id: 'template', label: 'Templates' },
  { id: 'plugin', label: 'Plugins' },
  { id: 'integration', label: 'Integrations' },
  { id: 'report', label: 'Reports' },
  { id: 'workflow', label: 'Workflows' },
  { id: 'nuclei', label: 'Nuclei Packs' },
];

export default function MarketplacePage() {
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedCategory, setSelectedCategory] = useState('All');
  const [selectedType, setSelectedType] = useState('all');
  const [sortBy, setSortBy] = useState<'popular' | 'recent' | 'rating'>('popular');
  const [priceFilter, setPriceFilter] = useState<'all' | 'free' | 'paid'>('all');
  const [selectedItem, setSelectedItem] = useState<MarketplaceItem | null>(null);

  const filteredItems = marketplaceItems.filter(item => {
    const matchesSearch = item.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      item.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
      item.tags.some(tag => tag.toLowerCase().includes(searchQuery.toLowerCase()));
    const matchesCategory = selectedCategory === 'All' || item.category === selectedCategory;
    const matchesType = selectedType === 'all' || item.type === selectedType;
    const matchesPrice = priceFilter === 'all' ||
      (priceFilter === 'free' && item.price === 'free') ||
      (priceFilter === 'paid' && item.price !== 'free');
    return matchesSearch && matchesCategory && matchesType && matchesPrice;
  }).sort((a, b) => {
    if (sortBy === 'popular') return b.downloads - a.downloads;
    if (sortBy === 'rating') return b.rating - a.rating;
    return new Date(b.updatedAt).getTime() - new Date(a.updatedAt).getTime();
  });

  const featuredItems = marketplaceItems.filter(item => item.featured);

  return (
    <div className="min-h-screen bg-gray-900">
      {/* Header */}
      <header className="bg-gray-800 border-b border-gray-700">
        <div className="max-w-7xl mx-auto px-4 py-4">
          <div className="flex items-center justify-between">
            <Link to="/" className="flex items-center gap-2">
              <Shield className="w-8 h-8 text-cyan-500" />
              <span className="text-xl font-bold text-white">HeroForge</span>
              <span className="text-gray-500 ml-2">| Marketplace</span>
            </Link>
            <nav className="hidden md:flex items-center gap-6">
              <Link to="/docs" className="text-gray-300 hover:text-white">Docs</Link>
              <Link to="/developers" className="text-gray-300 hover:text-white">Developers</Link>
              <button className="flex items-center gap-2 px-4 py-2 border border-gray-600 text-gray-300 hover:bg-gray-700 rounded-lg">
                <Upload className="w-4 h-4" />
                Publish
              </button>
              <Link to="/login" className="px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg">Sign In</Link>
            </nav>
          </div>
        </div>
      </header>

      {!selectedItem ? (
        <>
          {/* Hero / Search Section */}
          <section className="py-12 bg-gradient-to-b from-gray-800 to-gray-900 border-b border-gray-700">
            <div className="max-w-7xl mx-auto px-4">
              <div className="text-center mb-8">
                <h1 className="text-4xl font-bold text-white mb-4">Community Marketplace</h1>
                <p className="text-xl text-gray-400 max-w-2xl mx-auto">
                  Discover templates, plugins, and integrations built by the HeroForge community
                </p>
              </div>

              {/* Search Bar */}
              <div className="max-w-2xl mx-auto">
                <div className="relative">
                  <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
                  <input
                    type="text"
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    placeholder="Search templates, plugins, integrations..."
                    className="w-full pl-12 pr-4 py-4 bg-gray-800 border border-gray-600 rounded-xl text-white text-lg focus:outline-none focus:border-cyan-500"
                  />
                </div>
              </div>

              {/* Quick Stats */}
              <div className="flex justify-center gap-8 mt-8 text-sm text-gray-400">
                <div className="flex items-center gap-2">
                  <Package className="w-5 h-5 text-cyan-500" />
                  <span>500+ Items</span>
                </div>
                <div className="flex items-center gap-2">
                  <Users className="w-5 h-5 text-cyan-500" />
                  <span>200+ Publishers</span>
                </div>
                <div className="flex items-center gap-2">
                  <Download className="w-5 h-5 text-cyan-500" />
                  <span>1M+ Downloads</span>
                </div>
              </div>
            </div>
          </section>

          {/* Featured Items */}
          <section className="py-8 border-b border-gray-700">
            <div className="max-w-7xl mx-auto px-4">
              <div className="flex items-center justify-between mb-6">
                <h2 className="text-xl font-bold text-white flex items-center gap-2">
                  <Star className="w-5 h-5 text-amber-500" />
                  Featured
                </h2>
                <Link to="#" className="text-cyan-400 text-sm hover:underline">View all →</Link>
              </div>
              <div className="grid md:grid-cols-4 gap-4">
                {featuredItems.slice(0, 4).map((item) => (
                  <div
                    key={item.id}
                    onClick={() => setSelectedItem(item)}
                    className="bg-gray-800 rounded-xl border border-gray-700 p-4 hover:border-cyan-500/50 cursor-pointer transition-all group"
                  >
                    <div className="flex items-start justify-between mb-3">
                      <div className={`p-2 rounded-lg ${
                        item.type === 'nuclei' ? 'bg-purple-500/20 text-purple-400' :
                        item.type === 'plugin' ? 'bg-blue-500/20 text-blue-400' :
                        item.type === 'template' ? 'bg-green-500/20 text-green-400' :
                        'bg-amber-500/20 text-amber-400'
                      }`}>
                        {typeIcons[item.type]}
                      </div>
                      {item.price === 'free' ? (
                        <span className="text-xs text-green-400 font-medium">FREE</span>
                      ) : (
                        <span className="text-xs text-white font-medium">${item.price}</span>
                      )}
                    </div>
                    <h3 className="text-white font-medium mb-1 group-hover:text-cyan-400 transition-colors line-clamp-1">
                      {item.name}
                    </h3>
                    <p className="text-gray-400 text-sm line-clamp-2 mb-3">{item.description}</p>
                    <div className="flex items-center justify-between text-xs text-gray-500">
                      <span className="flex items-center gap-1">
                        <Download className="w-3 h-3" />
                        {(item.downloads / 1000).toFixed(1)}k
                      </span>
                      <span className="flex items-center gap-1">
                        <Star className="w-3 h-3 text-amber-400" />
                        {item.rating}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </section>

          {/* Collections */}
          <section className="py-8 border-b border-gray-700">
            <div className="max-w-7xl mx-auto px-4">
              <div className="flex items-center justify-between mb-6">
                <h2 className="text-xl font-bold text-white">Curated Collections</h2>
                <Link to="#" className="text-cyan-400 text-sm hover:underline">Browse all →</Link>
              </div>
              <div className="grid md:grid-cols-4 gap-4">
                {collections.map((collection) => (
                  <div
                    key={collection.id}
                    className="bg-gray-800 rounded-xl border border-gray-700 p-4 hover:border-gray-600 cursor-pointer transition-all"
                  >
                    <div className="flex items-center gap-3 mb-3">
                      <div className="p-2 bg-gray-700 rounded-lg">
                        {collection.icon}
                      </div>
                      <div>
                        <h3 className="text-white font-medium">{collection.name}</h3>
                        <p className="text-xs text-gray-500">{collection.itemCount} items</p>
                      </div>
                    </div>
                    <p className="text-gray-400 text-sm">{collection.description}</p>
                  </div>
                ))}
              </div>
            </div>
          </section>

          {/* Main Browse Section */}
          <section className="py-8">
            <div className="max-w-7xl mx-auto px-4">
              <div className="flex gap-8">
                {/* Filters Sidebar */}
                <div className="w-64 flex-shrink-0 hidden lg:block">
                  <div className="sticky top-4 space-y-6">
                    {/* Type Filter */}
                    <div>
                      <h3 className="text-sm font-medium text-gray-400 mb-3">TYPE</h3>
                      <div className="space-y-2">
                        {types.map((type) => (
                          <button
                            key={type.id}
                            onClick={() => setSelectedType(type.id)}
                            className={`w-full text-left px-3 py-2 rounded-lg text-sm transition-colors ${
                              selectedType === type.id
                                ? 'bg-cyan-600/20 text-cyan-400'
                                : 'text-gray-400 hover:text-white hover:bg-gray-800'
                            }`}
                          >
                            {type.label}
                          </button>
                        ))}
                      </div>
                    </div>

                    {/* Category Filter */}
                    <div>
                      <h3 className="text-sm font-medium text-gray-400 mb-3">CATEGORY</h3>
                      <div className="space-y-2">
                        {categories.map((cat) => (
                          <button
                            key={cat}
                            onClick={() => setSelectedCategory(cat)}
                            className={`w-full text-left px-3 py-2 rounded-lg text-sm transition-colors ${
                              selectedCategory === cat
                                ? 'bg-cyan-600/20 text-cyan-400'
                                : 'text-gray-400 hover:text-white hover:bg-gray-800'
                            }`}
                          >
                            {cat}
                          </button>
                        ))}
                      </div>
                    </div>

                    {/* Price Filter */}
                    <div>
                      <h3 className="text-sm font-medium text-gray-400 mb-3">PRICE</h3>
                      <div className="space-y-2">
                        {[
                          { id: 'all', label: 'All' },
                          { id: 'free', label: 'Free' },
                          { id: 'paid', label: 'Paid' },
                        ].map((price) => (
                          <button
                            key={price.id}
                            onClick={() => setPriceFilter(price.id as typeof priceFilter)}
                            className={`w-full text-left px-3 py-2 rounded-lg text-sm transition-colors ${
                              priceFilter === price.id
                                ? 'bg-cyan-600/20 text-cyan-400'
                                : 'text-gray-400 hover:text-white hover:bg-gray-800'
                            }`}
                          >
                            {price.label}
                          </button>
                        ))}
                      </div>
                    </div>
                  </div>
                </div>

                {/* Results */}
                <div className="flex-1">
                  {/* Sort Bar */}
                  <div className="flex items-center justify-between mb-6">
                    <p className="text-gray-400">
                      {filteredItems.length} {filteredItems.length === 1 ? 'result' : 'results'}
                    </p>
                    <div className="flex items-center gap-2">
                      <span className="text-sm text-gray-500">Sort by:</span>
                      <select
                        value={sortBy}
                        onChange={(e) => setSortBy(e.target.value as typeof sortBy)}
                        className="bg-gray-800 border border-gray-600 rounded-lg px-3 py-1.5 text-white text-sm focus:outline-none focus:border-cyan-500"
                      >
                        <option value="popular">Most Popular</option>
                        <option value="recent">Most Recent</option>
                        <option value="rating">Highest Rated</option>
                      </select>
                    </div>
                  </div>

                  {/* Items Grid */}
                  <div className="grid md:grid-cols-2 xl:grid-cols-3 gap-4">
                    {filteredItems.map((item) => (
                      <div
                        key={item.id}
                        onClick={() => setSelectedItem(item)}
                        className="bg-gray-800 rounded-xl border border-gray-700 overflow-hidden hover:border-gray-600 cursor-pointer transition-all group"
                      >
                        <div className="p-4">
                          <div className="flex items-start justify-between mb-3">
                            <div className="flex items-center gap-3">
                              <div className={`p-2 rounded-lg ${
                                item.type === 'nuclei' ? 'bg-purple-500/20 text-purple-400' :
                                item.type === 'plugin' ? 'bg-blue-500/20 text-blue-400' :
                                item.type === 'template' ? 'bg-green-500/20 text-green-400' :
                                item.type === 'integration' ? 'bg-pink-500/20 text-pink-400' :
                                item.type === 'workflow' ? 'bg-amber-500/20 text-amber-400' :
                                'bg-gray-500/20 text-gray-400'
                              }`}>
                                {typeIcons[item.type]}
                              </div>
                              <div>
                                <span className="text-xs text-gray-500 capitalize">{item.type}</span>
                              </div>
                            </div>
                            <div className="flex items-center gap-2">
                              {item.isNew && (
                                <span className="px-2 py-0.5 bg-green-500/20 text-green-400 rounded text-xs">NEW</span>
                              )}
                              {item.price === 'free' ? (
                                <span className="text-sm text-green-400 font-medium">FREE</span>
                              ) : (
                                <span className="text-sm text-white font-medium">${item.price}</span>
                              )}
                            </div>
                          </div>

                          <h3 className="text-white font-medium mb-2 group-hover:text-cyan-400 transition-colors">
                            {item.name}
                          </h3>
                          <p className="text-gray-400 text-sm line-clamp-2 mb-3">{item.description}</p>

                          {/* Tags */}
                          <div className="flex flex-wrap gap-1 mb-3">
                            {item.tags.slice(0, 3).map((tag) => (
                              <span key={tag} className="px-2 py-0.5 bg-gray-700 text-gray-400 rounded text-xs">
                                {tag}
                              </span>
                            ))}
                          </div>

                          {/* Author */}
                          <div className="flex items-center justify-between">
                            <div className="flex items-center gap-2">
                              <div className="w-6 h-6 bg-gray-700 rounded-full flex items-center justify-center text-xs text-gray-400">
                                {item.author.name[0]}
                              </div>
                              <span className="text-sm text-gray-400">
                                {item.author.name}
                                {item.author.verified && (
                                  <CheckCircle className="w-3 h-3 text-cyan-500 inline ml-1" />
                                )}
                              </span>
                            </div>
                          </div>
                        </div>

                        {/* Footer Stats */}
                        <div className="px-4 py-3 bg-gray-900/50 border-t border-gray-700 flex items-center justify-between text-sm">
                          <span className="flex items-center gap-1 text-gray-400">
                            <Download className="w-4 h-4" />
                            {item.downloads.toLocaleString()}
                          </span>
                          <span className="flex items-center gap-1 text-gray-400">
                            <Star className="w-4 h-4 text-amber-400" />
                            {item.rating} ({item.reviews})
                          </span>
                          <span className="text-gray-500">v{item.version}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          </section>

          {/* Publish CTA */}
          <section className="py-16 bg-gradient-to-r from-purple-600 to-pink-600">
            <div className="max-w-4xl mx-auto px-4 text-center">
              <h2 className="text-3xl font-bold text-white mb-4">Share Your Creations</h2>
              <p className="text-xl text-white/80 mb-8">
                Built something useful? Publish it to the marketplace and earn recognition (and revenue!)
              </p>
              <div className="flex flex-wrap justify-center gap-4">
                <button className="px-8 py-3 bg-white text-purple-600 rounded-lg font-semibold hover:bg-gray-100 flex items-center gap-2">
                  <Upload className="w-5 h-5" />
                  Publish to Marketplace
                </button>
                <Link
                  to="/docs/marketplace"
                  className="px-8 py-3 border-2 border-white text-white rounded-lg font-semibold hover:bg-white/10"
                >
                  Publisher Guide
                </Link>
              </div>
            </div>
          </section>
        </>
      ) : (
        /* Item Detail View */
        <div className="max-w-7xl mx-auto px-4 py-8">
          <button
            onClick={() => setSelectedItem(null)}
            className="text-gray-400 hover:text-white mb-6 flex items-center gap-1"
          >
            ← Back to Marketplace
          </button>

          <div className="grid lg:grid-cols-3 gap-8">
            {/* Main Content */}
            <div className="lg:col-span-2 space-y-6">
              <div className="bg-gray-800 rounded-xl border border-gray-700 p-6">
                <div className="flex items-start gap-4 mb-6">
                  <div className={`p-4 rounded-xl ${
                    selectedItem.type === 'nuclei' ? 'bg-purple-500/20 text-purple-400' :
                    selectedItem.type === 'plugin' ? 'bg-blue-500/20 text-blue-400' :
                    selectedItem.type === 'template' ? 'bg-green-500/20 text-green-400' :
                    selectedItem.type === 'integration' ? 'bg-pink-500/20 text-pink-400' :
                    'bg-amber-500/20 text-amber-400'
                  }`}>
                    {React.cloneElement(typeIcons[selectedItem.type] as React.ReactElement, { className: 'w-8 h-8' })}
                  </div>
                  <div className="flex-1">
                    <div className="flex items-start justify-between">
                      <div>
                        <h1 className="text-2xl font-bold text-white mb-1">{selectedItem.name}</h1>
                        <div className="flex items-center gap-3 text-sm text-gray-400">
                          <span className="capitalize">{selectedItem.type}</span>
                          <span>•</span>
                          <span>{selectedItem.category}</span>
                          <span>•</span>
                          <span>v{selectedItem.version}</span>
                        </div>
                      </div>
                      <div className="flex items-center gap-1">
                        <Star className="w-5 h-5 text-amber-400" />
                        <span className="text-white font-medium">{selectedItem.rating}</span>
                        <span className="text-gray-500">({selectedItem.reviews} reviews)</span>
                      </div>
                    </div>
                  </div>
                </div>

                <p className="text-gray-300 mb-6">{selectedItem.description}</p>

                {/* Tags */}
                <div className="flex flex-wrap gap-2 mb-6">
                  {selectedItem.tags.map((tag) => (
                    <span key={tag} className="px-3 py-1 bg-gray-700 text-gray-300 rounded-lg text-sm">
                      #{tag}
                    </span>
                  ))}
                </div>

                {/* Stats */}
                <div className="grid grid-cols-3 gap-4">
                  <div className="bg-gray-900 rounded-lg p-4 text-center">
                    <Download className="w-6 h-6 text-cyan-500 mx-auto mb-2" />
                    <div className="text-xl font-bold text-white">{selectedItem.downloads.toLocaleString()}</div>
                    <div className="text-sm text-gray-500">Downloads</div>
                  </div>
                  <div className="bg-gray-900 rounded-lg p-4 text-center">
                    <MessageSquare className="w-6 h-6 text-purple-500 mx-auto mb-2" />
                    <div className="text-xl font-bold text-white">{selectedItem.reviews}</div>
                    <div className="text-sm text-gray-500">Reviews</div>
                  </div>
                  <div className="bg-gray-900 rounded-lg p-4 text-center">
                    <Clock className="w-6 h-6 text-amber-500 mx-auto mb-2" />
                    <div className="text-xl font-bold text-white">
                      {new Date(selectedItem.updatedAt).toLocaleDateString('en-US', { month: 'short', day: 'numeric' })}
                    </div>
                    <div className="text-sm text-gray-500">Updated</div>
                  </div>
                </div>
              </div>

              {/* Description / README */}
              <div className="bg-gray-800 rounded-xl border border-gray-700 p-6">
                <h2 className="text-lg font-semibold text-white mb-4">Description</h2>
                <div className="prose prose-invert max-w-none">
                  <p className="text-gray-300">
                    This {selectedItem.type} provides {selectedItem.description.toLowerCase()}
                  </p>
                  <h3 className="text-white mt-6 mb-3">Features</h3>
                  <ul className="text-gray-300 space-y-2">
                    <li>• Comprehensive coverage for {selectedItem.category.toLowerCase()}</li>
                    <li>• Easy installation and configuration</li>
                    <li>• Regular updates and maintenance</li>
                    <li>• Compatible with {selectedItem.compatibility}</li>
                  </ul>
                  <h3 className="text-white mt-6 mb-3">Installation</h3>
                  <pre className="bg-gray-900 p-4 rounded-lg text-sm overflow-x-auto">
                    <code className="text-cyan-400">heroforge marketplace install {selectedItem.id}</code>
                  </pre>
                </div>
              </div>
            </div>

            {/* Sidebar */}
            <div className="space-y-6">
              {/* Install Card */}
              <div className="bg-gray-800 rounded-xl border border-gray-700 p-6 sticky top-4">
                <div className="text-center mb-6">
                  {selectedItem.price === 'free' ? (
                    <div className="text-3xl font-bold text-green-400">Free</div>
                  ) : (
                    <div className="text-3xl font-bold text-white">${selectedItem.price}</div>
                  )}
                </div>

                <button className="w-full py-3 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg font-medium mb-3 flex items-center justify-center gap-2">
                  <Download className="w-5 h-5" />
                  {selectedItem.price === 'free' ? 'Install Free' : 'Purchase & Install'}
                </button>

                <div className="flex gap-2">
                  <button className="flex-1 py-2 border border-gray-600 text-gray-300 rounded-lg text-sm hover:bg-gray-700 flex items-center justify-center gap-1">
                    <Heart className="w-4 h-4" />
                    Save
                  </button>
                  <button className="flex-1 py-2 border border-gray-600 text-gray-300 rounded-lg text-sm hover:bg-gray-700 flex items-center justify-center gap-1">
                    <ExternalLink className="w-4 h-4" />
                    Share
                  </button>
                </div>

                <hr className="border-gray-700 my-6" />

                {/* Author */}
                <div className="mb-6">
                  <h3 className="text-sm font-medium text-gray-400 mb-3">PUBLISHER</h3>
                  <div className="flex items-center gap-3">
                    <div className="w-10 h-10 bg-gray-700 rounded-full flex items-center justify-center text-white">
                      {selectedItem.author.name[0]}
                    </div>
                    <div>
                      <div className="text-white font-medium flex items-center gap-1">
                        {selectedItem.author.name}
                        {selectedItem.author.verified && (
                          <CheckCircle className="w-4 h-4 text-cyan-500" />
                        )}
                      </div>
                      <div className="text-sm text-gray-500">
                        {selectedItem.author.verified ? 'Verified Publisher' : 'Community Publisher'}
                      </div>
                    </div>
                  </div>
                </div>

                {/* Details */}
                <div className="space-y-3 text-sm">
                  <div className="flex justify-between">
                    <span className="text-gray-500">Version</span>
                    <span className="text-white">{selectedItem.version}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-500">Compatibility</span>
                    <span className="text-white">{selectedItem.compatibility}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-500">Last Updated</span>
                    <span className="text-white">{new Date(selectedItem.updatedAt).toLocaleDateString()}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-500">Category</span>
                    <span className="text-white">{selectedItem.category}</span>
                  </div>
                </div>

                <hr className="border-gray-700 my-6" />

                {/* Support Links */}
                <div className="space-y-2">
                  <a href="#" className="flex items-center gap-2 text-sm text-gray-400 hover:text-white">
                    <FileText className="w-4 h-4" />
                    Documentation
                  </a>
                  <a href="#" className="flex items-center gap-2 text-sm text-gray-400 hover:text-white">
                    <MessageSquare className="w-4 h-4" />
                    Support Forum
                  </a>
                  <a href="#" className="flex items-center gap-2 text-sm text-gray-400 hover:text-white">
                    <AlertTriangle className="w-4 h-4" />
                    Report Issue
                  </a>
                </div>
              </div>
            </div>
          </div>
        </div>
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
