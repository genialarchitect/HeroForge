import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { toast } from 'react-toastify';

interface RoadmapItem {
  id: string;
  title: string;
  description: string;
  status: 'completed' | 'in_progress' | 'planned' | 'considering';
  category: 'scanning' | 'reporting' | 'integrations' | 'compliance' | 'ai' | 'platform' | 'security';
  quarter: string;
  votes: number;
  has_voted: boolean;
  completed_date?: string;
  tags: string[];
}

interface RoadmapStats {
  total_items: number;
  completed: number;
  in_progress: number;
  planned: number;
  considering: number;
  total_votes: number;
}

const RoadmapPage: React.FC = () => {
  const [items, setItems] = useState<RoadmapItem[]>([]);
  const [stats, setStats] = useState<RoadmapStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [votingItemId, setVotingItemId] = useState<string | null>(null);
  const [activeFilter, setActiveFilter] = useState<string>('all');
  const [activeCategory, setActiveCategory] = useState<string>('all');
  const [sortBy, setSortBy] = useState<'votes' | 'quarter'>('votes');
  const [suggestionForm, setSuggestionForm] = useState({ title: '', description: '', email: '' });
  const [suggestionSubmitting, setSuggestionSubmitting] = useState(false);
  const [suggestionSubmitted, setSuggestionSubmitted] = useState(false);

  useEffect(() => {
    fetchRoadmapData();
  }, []);

  const fetchRoadmapData = async () => {
    try {
      const [itemsRes, statsRes] = await Promise.all([
        fetch('/api/roadmap/items'),
        fetch('/api/roadmap/stats'),
      ]);

      if (itemsRes.ok) {
        const itemsData = await itemsRes.json();
        if (itemsData.success) {
          setItems(itemsData.data);
        }
      }

      if (statsRes.ok) {
        const statsData = await statsRes.json();
        if (statsData.success) {
          setStats(statsData.data);
        }
      }
    } catch (error) {
      console.error('Failed to fetch roadmap data:', error);
      toast.error('Failed to load roadmap data');
    } finally {
      setLoading(false);
    }
  };

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
      default: return '📦';
    }
  };

  const handleVote = async (itemId: string, hasVoted: boolean) => {
    setVotingItemId(itemId);
    try {
      const method = hasVoted ? 'DELETE' : 'POST';
      const response = await fetch(`/api/roadmap/items/${itemId}/vote`, { method });
      const data = await response.json();

      if (data.success) {
        // Update local state
        setItems(prev => prev.map(item => {
          if (item.id === itemId) {
            return {
              ...item,
              votes: data.data.votes,
              has_voted: data.data.has_voted,
            };
          }
          return item;
        }));
      } else {
        toast.error(data.error || 'Failed to update vote');
      }
    } catch (error) {
      console.error('Failed to vote:', error);
      toast.error('Failed to update vote');
    } finally {
      setVotingItemId(null);
    }
  };

  const handleSuggestionSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!suggestionForm.title.trim() || !suggestionForm.description.trim()) {
      toast.error('Please fill in all required fields');
      return;
    }

    setSuggestionSubmitting(true);
    try {
      const response = await fetch('/api/roadmap/suggestions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(suggestionForm),
      });

      const data = await response.json();

      if (data.success) {
        setSuggestionSubmitted(true);
        setSuggestionForm({ title: '', description: '', email: '' });
        toast.success('Thank you for your suggestion!');
      } else {
        toast.error(data.error || 'Failed to submit suggestion');
      }
    } catch (error) {
      console.error('Failed to submit suggestion:', error);
      toast.error('Failed to submit suggestion');
    } finally {
      setSuggestionSubmitting(false);
    }
  };

  const filteredItems = items
    .filter(item => activeFilter === 'all' || item.status === activeFilter)
    .filter(item => activeCategory === 'all' || item.category === activeCategory)
    .sort((a, b) => {
      if (sortBy === 'votes') return b.votes - a.votes;
      return a.quarter.localeCompare(b.quarter);
    });

  const completedCount = stats?.completed || items.filter(i => i.status === 'completed').length;
  const inProgressCount = stats?.in_progress || items.filter(i => i.status === 'in_progress').length;
  const plannedCount = stats?.planned || items.filter(i => i.status === 'planned').length;
  const totalVotes = stats?.total_votes || items.reduce((sum, i) => sum + i.votes, 0);

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-900 flex items-center justify-center">
        <div className="flex flex-col items-center gap-4">
          <div className="w-12 h-12 border-4 border-cyan-500 border-t-transparent rounded-full animate-spin" />
          <p className="text-gray-400">Loading roadmap...</p>
        </div>
      </div>
    );
  }

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
            <p className="text-3xl font-bold text-purple-400">{plannedCount}</p>
            <p className="text-gray-400 text-sm">Planned</p>
          </div>
          <div className="bg-gray-800 rounded-xl border border-gray-700 p-4 text-center">
            <p className="text-3xl font-bold text-gray-400">{totalVotes.toLocaleString()}</p>
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
                    onClick={() => handleVote(item.id, item.has_voted)}
                    disabled={votingItemId === item.id}
                    className={`w-12 h-12 rounded-lg flex flex-col items-center justify-center transition-colors ${
                      item.has_voted
                        ? 'bg-cyan-600 text-white'
                        : 'bg-gray-700 text-gray-400 hover:bg-gray-600 hover:text-white'
                    } ${votingItemId === item.id ? 'opacity-50 cursor-not-allowed' : ''}`}
                  >
                    {votingItemId === item.id ? (
                      <div className="w-4 h-4 border-2 border-current border-t-transparent rounded-full animate-spin" />
                    ) : (
                      <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 15l7-7 7 7" />
                      </svg>
                    )}
                  </button>
                  <span className={`mt-1 font-bold ${item.has_voted ? 'text-cyan-400' : 'text-gray-400'}`}>
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
                    {item.completed_date && (
                      <span className="text-green-400 text-sm">Shipped {item.completed_date}</span>
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
                  maxLength={200}
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
                  maxLength={2000}
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
                disabled={suggestionSubmitting}
                className="px-6 py-3 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {suggestionSubmitting ? 'Submitting...' : 'Submit Suggestion'}
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

export default RoadmapPage;
