import React, { useState } from 'react';
import { Link } from 'react-router-dom';

interface RoadmapItem {
  id: string;
  title: string;
  description: string;
  status: 'completed' | 'in_progress' | 'planned' | 'considering';
  category: 'scanning' | 'reporting' | 'integrations' | 'compliance' | 'ai' | 'platform' | 'security';
  quarter: string;
  votes: number;
  hasVoted?: boolean;
  completedDate?: string;
  tags: string[];
}

const roadmapItems: RoadmapItem[] = [
  // Completed
  {
    id: '1',
    title: 'AI-Powered Vulnerability Prioritization',
    description: 'Machine learning model that ranks vulnerabilities based on exploitability, business context, and threat intelligence.',
    status: 'completed',
    category: 'ai',
    quarter: 'Q4 2025',
    votes: 342,
    completedDate: 'December 2025',
    tags: ['AI/ML', 'Prioritization'],
  },
  {
    id: '2',
    title: '45 Compliance Frameworks',
    description: 'Support for 45 compliance frameworks including SOC 2, PCI-DSS 4.0, HIPAA, NIST, FedRAMP, CMMC, and more.',
    status: 'completed',
    category: 'compliance',
    quarter: 'Q4 2025',
    votes: 289,
    completedDate: 'January 2026',
    tags: ['Compliance', 'Enterprise'],
  },
  {
    id: '3',
    title: 'Customer Portal',
    description: 'White-labeled portal for consultancies to share findings, reports, and remediation progress with clients.',
    status: 'completed',
    category: 'platform',
    quarter: 'Q4 2025',
    votes: 256,
    completedDate: 'January 2026',
    tags: ['Consultancies', 'Portal'],
  },
  {
    id: '4',
    title: 'Interactive Learning Academy',
    description: 'Built-in learning platform with courses, labs, and certifications for security professionals.',
    status: 'completed',
    category: 'platform',
    quarter: 'Q1 2026',
    votes: 198,
    completedDate: 'January 2026',
    tags: ['Education', 'Certification'],
  },
  {
    id: '5',
    title: 'Free Security Tools',
    description: 'Public tools including subdomain finder, security headers checker, SSL analyzer, and more.',
    status: 'completed',
    category: 'platform',
    quarter: 'Q1 2026',
    votes: 176,
    completedDate: 'January 2026',
    tags: ['Free Tools', 'Lead Gen'],
  },
  // In Progress
  {
    id: '6',
    title: 'Real-Time Threat Intelligence Feed',
    description: 'Live CVE feed, CISA KEV integration, and correlation with your asset inventory.',
    status: 'in_progress',
    category: 'security',
    quarter: 'Q1 2026',
    votes: 412,
    tags: ['Threat Intel', 'Real-time'],
  },
  {
    id: '7',
    title: 'Visual Attack Surface Map',
    description: 'Interactive network topology visualization with risk-based coloring and attack path overlays.',
    status: 'in_progress',
    category: 'scanning',
    quarter: 'Q1 2026',
    votes: 387,
    tags: ['Visualization', 'Attack Surface'],
  },
  {
    id: '8',
    title: 'Python & Node.js SDKs',
    description: 'Official SDKs for programmatic access to all HeroForge features with full documentation.',
    status: 'in_progress',
    category: 'integrations',
    quarter: 'Q1 2026',
    votes: 298,
    tags: ['SDK', 'Developer'],
  },
  // Planned
  {
    id: '9',
    title: 'GitHub Actions Integration',
    description: 'Native GitHub Action for running security scans in CI/CD pipelines with PR comments.',
    status: 'planned',
    category: 'integrations',
    quarter: 'Q2 2026',
    votes: 445,
    tags: ['CI/CD', 'GitHub'],
  },
  {
    id: '10',
    title: 'Live Attack Simulation Lab',
    description: 'Safe, sandboxed environments for practicing exploitation techniques and testing detections.',
    status: 'planned',
    category: 'platform',
    quarter: 'Q2 2026',
    votes: 389,
    tags: ['Training', 'Lab'],
  },
  {
    id: '11',
    title: 'HeroForge Certification Program',
    description: 'Official certifications: HCA (Analyst), HCP (Professional), HCE (Expert) with proctored exams.',
    status: 'planned',
    category: 'platform',
    quarter: 'Q2 2026',
    votes: 334,
    tags: ['Certification', 'Career'],
  },
  {
    id: '12',
    title: 'Community Marketplace',
    description: 'Share and download scan templates, report templates, and custom integrations.',
    status: 'planned',
    category: 'platform',
    quarter: 'Q2 2026',
    votes: 267,
    tags: ['Community', 'Templates'],
  },
  {
    id: '13',
    title: 'White-Label / MSP Features',
    description: 'Full white-labeling with custom domains, branding, and multi-tenant management for MSPs.',
    status: 'planned',
    category: 'platform',
    quarter: 'Q3 2026',
    votes: 312,
    tags: ['MSP', 'White-label'],
  },
  {
    id: '14',
    title: 'Browser Extension',
    description: 'Quick security checks, saved credentials lookup, and one-click scanning from browser.',
    status: 'planned',
    category: 'platform',
    quarter: 'Q3 2026',
    votes: 234,
    tags: ['Browser', 'Convenience'],
  },
  {
    id: '15',
    title: 'Advanced SIEM Correlation',
    description: 'Cross-correlate scan findings with SIEM logs for enhanced detection and investigation.',
    status: 'planned',
    category: 'integrations',
    quarter: 'Q3 2026',
    votes: 287,
    tags: ['SIEM', 'Correlation'],
  },
  // Considering
  {
    id: '16',
    title: 'Mobile App (iOS & Android)',
    description: 'Native mobile apps for monitoring scans, receiving alerts, and quick status checks.',
    status: 'considering',
    category: 'platform',
    quarter: 'Q4 2026',
    votes: 423,
    tags: ['Mobile', 'iOS', 'Android'],
  },
  {
    id: '17',
    title: 'On-Premise Deployment',
    description: 'Self-hosted deployment option for organizations with strict data residency requirements.',
    status: 'considering',
    category: 'platform',
    quarter: 'Q4 2026',
    votes: 356,
    tags: ['Enterprise', 'Self-hosted'],
  },
  {
    id: '18',
    title: 'Slack/Teams Bot',
    description: 'Interactive bot for running scans, querying results, and receiving alerts in chat.',
    status: 'considering',
    category: 'integrations',
    quarter: 'Q4 2026',
    votes: 278,
    tags: ['Slack', 'Teams', 'Bot'],
  },
  {
    id: '19',
    title: 'AI Report Writer',
    description: 'Generate complete penetration test reports with AI-written executive summaries and findings.',
    status: 'considering',
    category: 'ai',
    quarter: 'TBD',
    votes: 512,
    tags: ['AI', 'Reports'],
  },
  {
    id: '20',
    title: 'Bug Bounty Platform Integration',
    description: 'Direct integration with HackerOne and Bugcrowd for streamlined vulnerability disclosure.',
    status: 'considering',
    category: 'integrations',
    quarter: 'TBD',
    votes: 189,
    tags: ['Bug Bounty', 'Integration'],
  },
];

const StatusPage: React.FC = () => {
  const [items, setItems] = useState<RoadmapItem[]>(roadmapItems);
  const [activeFilter, setActiveFilter] = useState<string>('all');
  const [activeCategory, setActiveCategory] = useState<string>('all');
  const [sortBy, setSortBy] = useState<'votes' | 'quarter'>('votes');
  const [suggestionForm, setSuggestionForm] = useState({ title: '', description: '', email: '' });
  const [suggestionSubmitted, setSuggestionSubmitted] = useState(false);

  const statusFilters = [
    { id: 'all', label: 'All', count: items.length },
    { id: 'completed', label: 'Completed', count: items.filter(i => i.status === 'completed').length },
    { id: 'in_progress', label: 'In Progress', count: items.filter(i => i.status === 'in_progress').length },
    { id: 'planned', label: 'Planned', count: items.filter(i => i.status === 'planned').length },
    { id: 'considering', label: 'Under Consideration', count: items.filter(i => i.status === 'considering').length },
  ];

  const categories = [
    { id: 'all', label: 'All Categories' },
    { id: 'scanning', label: 'Scanning' },
    { id: 'reporting', label: 'Reporting' },
    { id: 'integrations', label: 'Integrations' },
    { id: 'compliance', label: 'Compliance' },
    { id: 'ai', label: 'AI/ML' },
    { id: 'platform', label: 'Platform' },
    { id: 'security', label: 'Security' },
  ];

  const getStatusColor = (status: RoadmapItem['status']) => {
    switch (status) {
      case 'completed': return 'bg-green-500';
      case 'in_progress': return 'bg-blue-500';
      case 'planned': return 'bg-purple-500';
      case 'considering': return 'bg-gray-500';
    }
  };

  const getStatusBadge = (status: RoadmapItem['status']) => {
    switch (status) {
      case 'completed': return 'bg-green-500/20 text-green-400 border-green-500/50';
      case 'in_progress': return 'bg-blue-500/20 text-blue-400 border-blue-500/50';
      case 'planned': return 'bg-purple-500/20 text-purple-400 border-purple-500/50';
      case 'considering': return 'bg-gray-500/20 text-gray-400 border-gray-500/50';
    }
  };

  const getStatusLabel = (status: RoadmapItem['status']) => {
    switch (status) {
      case 'completed': return 'Completed';
      case 'in_progress': return 'In Progress';
      case 'planned': return 'Planned';
      case 'considering': return 'Under Consideration';
    }
  };

  const getCategoryIcon = (category: RoadmapItem['category']) => {
    switch (category) {
      case 'scanning': return '🔍';
      case 'reporting': return '📊';
      case 'integrations': return '🔗';
      case 'compliance': return '📋';
      case 'ai': return '🤖';
      case 'platform': return '🏗️';
      case 'security': return '🛡️';
    }
  };

  const handleVote = (itemId: string) => {
    setItems(prev => prev.map(item => {
      if (item.id === itemId) {
        return {
          ...item,
          votes: item.hasVoted ? item.votes - 1 : item.votes + 1,
          hasVoted: !item.hasVoted,
        };
      }
      return item;
    }));
  };

  const handleSuggestionSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (suggestionForm.title && suggestionForm.description) {
      setSuggestionSubmitted(true);
      setSuggestionForm({ title: '', description: '', email: '' });
    }
  };

  const filteredItems = items
    .filter(item => activeFilter === 'all' || item.status === activeFilter)
    .filter(item => activeCategory === 'all' || item.category === activeCategory)
    .sort((a, b) => {
      if (sortBy === 'votes') return b.votes - a.votes;
      return a.quarter.localeCompare(b.quarter);
    });

  const completedCount = items.filter(i => i.status === 'completed').length;
  const inProgressCount = items.filter(i => i.status === 'in_progress').length;

  return (
    <div className="min-h-screen bg-gray-900">
      {/* Header */}
      <header className="bg-gray-800 border-b border-gray-700">
        <div className="max-w-6xl mx-auto px-4 py-4 flex items-center justify-between">
          <Link to="/" className="flex items-center space-x-2">
            <span className="text-2xl font-bold text-cyan-400">HeroForge</span>
            <span className="text-gray-400">Roadmap</span>
          </Link>
          <nav className="hidden md:flex items-center space-x-6">
            <Link to="/features" className="text-gray-300 hover:text-white">Features</Link>
            <Link to="/pricing" className="text-gray-300 hover:text-white">Pricing</Link>
            <Link to="/status" className="text-gray-300 hover:text-white">Status</Link>
            <Link to="/docs" className="text-gray-300 hover:text-white">Docs</Link>
            <Link to="/login" className="px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg">Sign In</Link>
          </nav>
        </div>
      </header>

      <main className="max-w-6xl mx-auto px-4 py-12">
        {/* Hero */}
        <div className="text-center mb-12">
          <h1 className="text-4xl font-bold text-white mb-4">Product Roadmap</h1>
          <p className="text-xl text-gray-400 max-w-2xl mx-auto">
            See what we're building next. Vote on features you want to see and suggest new ideas.
          </p>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
          <div className="bg-gray-800 rounded-xl border border-gray-700 p-4 text-center">
            <p className="text-3xl font-bold text-green-400">{completedCount}</p>
            <p className="text-gray-400 text-sm">Shipped</p>
          </div>
          <div className="bg-gray-800 rounded-xl border border-gray-700 p-4 text-center">
            <p className="text-3xl font-bold text-blue-400">{inProgressCount}</p>
            <p className="text-gray-400 text-sm">In Progress</p>
          </div>
          <div className="bg-gray-800 rounded-xl border border-gray-700 p-4 text-center">
            <p className="text-3xl font-bold text-purple-400">{items.filter(i => i.status === 'planned').length}</p>
            <p className="text-gray-400 text-sm">Planned</p>
          </div>
          <div className="bg-gray-800 rounded-xl border border-gray-700 p-4 text-center">
            <p className="text-3xl font-bold text-gray-400">{items.reduce((sum, i) => sum + i.votes, 0).toLocaleString()}</p>
            <p className="text-gray-400 text-sm">Total Votes</p>
          </div>
        </div>

        {/* Filters */}
        <div className="flex flex-col md:flex-row gap-4 mb-8">
          {/* Status Filter */}
          <div className="flex flex-wrap gap-2">
            {statusFilters.map((filter) => (
              <button
                key={filter.id}
                onClick={() => setActiveFilter(filter.id)}
                className={`px-4 py-2 rounded-lg font-medium transition-colors ${
                  activeFilter === filter.id
                    ? 'bg-cyan-600 text-white'
                    : 'bg-gray-800 text-gray-300 hover:bg-gray-700'
                }`}
              >
                {filter.label}
                <span className="ml-2 text-xs opacity-75">({filter.count})</span>
              </button>
            ))}
          </div>

          {/* Category & Sort */}
          <div className="flex gap-2 md:ml-auto">
            <select
              value={activeCategory}
              onChange={(e) => setActiveCategory(e.target.value)}
              className="bg-gray-800 border border-gray-700 rounded-lg px-4 py-2 text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
            >
              {categories.map((cat) => (
                <option key={cat.id} value={cat.id}>{cat.label}</option>
              ))}
            </select>
            <select
              value={sortBy}
              onChange={(e) => setSortBy(e.target.value as 'votes' | 'quarter')}
              className="bg-gray-800 border border-gray-700 rounded-lg px-4 py-2 text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
            >
              <option value="votes">Most Voted</option>
              <option value="quarter">Timeline</option>
            </select>
          </div>
        </div>

        {/* Roadmap Items */}
        <div className="space-y-4 mb-12">
          {filteredItems.map((item) => (
            <div
              key={item.id}
              className="bg-gray-800 rounded-xl border border-gray-700 p-6 hover:border-gray-600 transition-colors"
            >
              <div className="flex gap-4">
                {/* Vote Button */}
                <div className="flex flex-col items-center">
                  <button
                    onClick={() => handleVote(item.id)}
                    className={`w-12 h-12 rounded-lg flex flex-col items-center justify-center transition-colors ${
                      item.hasVoted
                        ? 'bg-cyan-600 text-white'
                        : 'bg-gray-700 text-gray-400 hover:bg-gray-600 hover:text-white'
                    }`}
                  >
                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 15l7-7 7 7" />
                    </svg>
                  </button>
                  <span className={`mt-1 font-bold ${item.hasVoted ? 'text-cyan-400' : 'text-gray-400'}`}>
                    {item.votes}
                  </span>
                </div>

                {/* Content */}
                <div className="flex-1">
                  <div className="flex flex-wrap items-center gap-2 mb-2">
                    <span className={`text-xs px-2 py-1 rounded border ${getStatusBadge(item.status)}`}>
                      {getStatusLabel(item.status)}
                    </span>
                    <span className="text-gray-500 text-sm">{item.quarter}</span>
                    {item.completedDate && (
                      <span className="text-green-400 text-sm">Shipped {item.completedDate}</span>
                    )}
                  </div>
                  <h3 className="text-lg font-semibold text-white mb-2 flex items-center gap-2">
                    <span>{getCategoryIcon(item.category)}</span>
                    {item.title}
                  </h3>
                  <p className="text-gray-400 mb-3">{item.description}</p>
                  <div className="flex flex-wrap gap-2">
                    {item.tags.map((tag) => (
                      <span key={tag} className="text-xs bg-gray-700 text-gray-300 px-2 py-1 rounded">
                        {tag}
                      </span>
                    ))}
                  </div>
                </div>

                {/* Progress Indicator */}
                <div className="hidden md:flex items-center">
                  <div className={`w-3 h-3 rounded-full ${getStatusColor(item.status)}`} />
                </div>
              </div>
            </div>
          ))}
        </div>

        {/* Suggest a Feature */}
        <div className="bg-gradient-to-r from-cyan-900/30 to-blue-900/30 rounded-xl border border-cyan-700/50 p-8">
          <h2 className="text-2xl font-bold text-white mb-2">Suggest a Feature</h2>
          <p className="text-gray-400 mb-6">
            Have an idea for HeroForge? We'd love to hear it! Submit your suggestion and the community can vote on it.
          </p>
          {suggestionSubmitted ? (
            <div className="flex items-center gap-3 text-green-400">
              <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
              </svg>
              <span>Thank you! Your suggestion has been submitted for review.</span>
            </div>
          ) : (
            <form onSubmit={handleSuggestionSubmit} className="space-y-4">
              <div>
                <label className="block text-gray-300 text-sm font-medium mb-2">Feature Title</label>
                <input
                  type="text"
                  value={suggestionForm.title}
                  onChange={(e) => setSuggestionForm(prev => ({ ...prev, title: e.target.value }))}
                  placeholder="What feature would you like to see?"
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-cyan-500"
                  required
                />
              </div>
              <div>
                <label className="block text-gray-300 text-sm font-medium mb-2">Description</label>
                <textarea
                  value={suggestionForm.description}
                  onChange={(e) => setSuggestionForm(prev => ({ ...prev, description: e.target.value }))}
                  placeholder="Describe the feature and how it would help you..."
                  rows={3}
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-cyan-500 resize-none"
                  required
                />
              </div>
              <div>
                <label className="block text-gray-300 text-sm font-medium mb-2">Email (optional)</label>
                <input
                  type="email"
                  value={suggestionForm.email}
                  onChange={(e) => setSuggestionForm(prev => ({ ...prev, email: e.target.value }))}
                  placeholder="Get notified when we ship this feature"
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-cyan-500"
                />
              </div>
              <button
                type="submit"
                className="px-6 py-3 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg font-medium transition-colors"
              >
                Submit Suggestion
              </button>
            </form>
          )}
        </div>
      </main>

      {/* Footer */}
      <footer className="bg-gray-800 border-t border-gray-700 mt-16">
        <div className="max-w-6xl mx-auto px-4 py-8">
          <div className="flex flex-col md:flex-row justify-between items-center gap-4">
            <p className="text-gray-500 text-sm">
              &copy; {new Date().getFullYear()} HeroForge Security. All rights reserved.
            </p>
            <div className="flex items-center gap-6">
              <Link to="/status" className="text-gray-400 hover:text-white text-sm">System Status</Link>
              <Link to="/legal/terms" className="text-gray-400 hover:text-white text-sm">Terms</Link>
              <Link to="/legal/privacy" className="text-gray-400 hover:text-white text-sm">Privacy</Link>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default StatusPage;
