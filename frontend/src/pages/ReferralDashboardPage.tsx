import React, { useState, useEffect } from 'react';
import {
  Gift,
  Users,
  Trophy,
  Copy,
  Check,
  Share2,
  Mail,
  Twitter,
  Linkedin,
  ArrowRight,
  Clock,
  CheckCircle,
  XCircle,
  TrendingUp,
} from 'lucide-react';
import { toast } from 'react-toastify';

interface ReferralCode {
  code: string;
  user_id: string;
  created_at: string;
}

interface ReferralStats {
  total_referrals: number;
  successful_referrals: number;
  pending_referrals: number;
  credits_earned: number;
  credits_used: number;
  credits_available: number;
  leaderboard_rank: number | null;
}

interface ReferralRecord {
  id: string;
  referrer_id: string;
  referee_email: string;
  status: string;
  credits_awarded: number;
  created_at: string;
  converted_at: string | null;
}

interface LeaderboardEntry {
  rank: number;
  username: string;
  successful_referrals: number;
  is_current_user: boolean;
}

const ReferralDashboardPage: React.FC = () => {
  const [referralCode, setReferralCode] = useState<ReferralCode | null>(null);
  const [stats, setStats] = useState<ReferralStats | null>(null);
  const [history, setHistory] = useState<ReferralRecord[]>([]);
  const [leaderboard, setLeaderboard] = useState<LeaderboardEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [copied, setCopied] = useState(false);
  const [activeTab, setActiveTab] = useState<'overview' | 'history' | 'leaderboard'>('overview');

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    setLoading(true);
    try {
      const [codeRes, statsRes, historyRes, leaderboardRes] = await Promise.all([
        fetch('/api/referrals/code').then(r => r.json()),
        fetch('/api/referrals/stats').then(r => r.json()),
        fetch('/api/referrals/history').then(r => r.json()),
        fetch('/api/referrals/leaderboard').then(r => r.json()),
      ]);

      if (codeRes.success) setReferralCode(codeRes.data);
      if (statsRes.success) setStats(statsRes.data);
      if (historyRes.success) setHistory(historyRes.data);
      if (leaderboardRes.success) setLeaderboard(leaderboardRes.data);
    } catch (error) {
      console.error('Failed to load referral data:', error);
      toast.error('Failed to load referral data');
    } finally {
      setLoading(false);
    }
  };

  const copyCode = () => {
    if (referralCode) {
      navigator.clipboard.writeText(referralCode.code);
      setCopied(true);
      toast.success('Referral code copied!');
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const copyLink = () => {
    if (referralCode) {
      const link = `${window.location.origin}/register?ref=${referralCode.code}`;
      navigator.clipboard.writeText(link);
      toast.success('Referral link copied!');
    }
  };

  const shareVia = (platform: 'email' | 'twitter' | 'linkedin') => {
    if (!referralCode) return;

    const link = `${window.location.origin}/register?ref=${referralCode.code}`;
    const message = `Join HeroForge - the AI-powered security platform! Use my referral code ${referralCode.code} to get 20% off your first year.`;

    switch (platform) {
      case 'email':
        window.open(`mailto:?subject=Join HeroForge&body=${encodeURIComponent(message + '\n\n' + link)}`);
        break;
      case 'twitter':
        window.open(`https://twitter.com/intent/tweet?text=${encodeURIComponent(message)}&url=${encodeURIComponent(link)}`);
        break;
      case 'linkedin':
        window.open(`https://www.linkedin.com/sharing/share-offsite/?url=${encodeURIComponent(link)}`);
        break;
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'converted':
        return <CheckCircle className="w-4 h-4 text-green-400" />;
      case 'pending':
      case 'registered':
        return <Clock className="w-4 h-4 text-yellow-400" />;
      default:
        return <XCircle className="w-4 h-4 text-gray-400" />;
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'converted':
        return 'bg-green-500/20 text-green-400';
      case 'pending':
      case 'registered':
        return 'bg-yellow-500/20 text-yellow-400';
      default:
        return 'bg-gray-500/20 text-gray-400';
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-900 flex items-center justify-center">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-cyan-500"></div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-900 py-8">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Header */}
        <div className="mb-8">
          <div className="flex items-center gap-3 mb-2">
            <Gift className="h-8 w-8 text-cyan-400" />
            <h1 className="text-3xl font-bold text-white">Referral Program</h1>
          </div>
          <p className="text-gray-400">
            Earn free months of HeroForge by referring your colleagues. You get 1 month free for each successful referral, and they get 20% off their first year.
          </p>
        </div>

        {/* Your Code Section */}
        <div className="bg-gradient-to-r from-cyan-900/50 to-purple-900/50 rounded-xl border border-cyan-700/50 p-6 mb-8">
          <div className="flex flex-col md:flex-row items-center justify-between gap-6">
            <div>
              <h2 className="text-lg font-semibold text-white mb-2">Your Referral Code</h2>
              <div className="flex items-center gap-3">
                <div className="bg-gray-900/70 px-6 py-3 rounded-lg border border-cyan-500/50">
                  <span className="text-3xl font-mono font-bold text-cyan-400 tracking-wider">
                    {referralCode?.code || '--------'}
                  </span>
                </div>
                <button
                  onClick={copyCode}
                  className="p-3 bg-gray-700 hover:bg-gray-600 rounded-lg transition-colors"
                  title="Copy code"
                >
                  {copied ? (
                    <Check className="w-5 h-5 text-green-400" />
                  ) : (
                    <Copy className="w-5 h-5 text-gray-300" />
                  )}
                </button>
              </div>
            </div>

            <div className="flex flex-col sm:flex-row gap-3">
              <button
                onClick={copyLink}
                className="flex items-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg transition-colors"
              >
                <Share2 className="w-4 h-4" />
                Copy Link
              </button>
              <div className="flex gap-2">
                <button
                  onClick={() => shareVia('email')}
                  className="p-2 bg-gray-700 hover:bg-gray-600 rounded-lg transition-colors"
                  title="Share via email"
                >
                  <Mail className="w-5 h-5 text-gray-300" />
                </button>
                <button
                  onClick={() => shareVia('twitter')}
                  className="p-2 bg-gray-700 hover:bg-gray-600 rounded-lg transition-colors"
                  title="Share on Twitter"
                >
                  <Twitter className="w-5 h-5 text-gray-300" />
                </button>
                <button
                  onClick={() => shareVia('linkedin')}
                  className="p-2 bg-gray-700 hover:bg-gray-600 rounded-lg transition-colors"
                  title="Share on LinkedIn"
                >
                  <Linkedin className="w-5 h-5 text-gray-300" />
                </button>
              </div>
            </div>
          </div>
        </div>

        {/* Stats Cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
          <div className="bg-gray-800 rounded-xl border border-gray-700 p-6">
            <div className="flex items-center gap-3 mb-3">
              <div className="p-2 bg-green-500/20 rounded-lg">
                <CheckCircle className="w-5 h-5 text-green-400" />
              </div>
              <span className="text-gray-400">Successful Referrals</span>
            </div>
            <div className="text-3xl font-bold text-white">{stats?.successful_referrals || 0}</div>
          </div>

          <div className="bg-gray-800 rounded-xl border border-gray-700 p-6">
            <div className="flex items-center gap-3 mb-3">
              <div className="p-2 bg-yellow-500/20 rounded-lg">
                <Clock className="w-5 h-5 text-yellow-400" />
              </div>
              <span className="text-gray-400">Pending Referrals</span>
            </div>
            <div className="text-3xl font-bold text-white">{stats?.pending_referrals || 0}</div>
          </div>

          <div className="bg-gray-800 rounded-xl border border-gray-700 p-6">
            <div className="flex items-center gap-3 mb-3">
              <div className="p-2 bg-cyan-500/20 rounded-lg">
                <Gift className="w-5 h-5 text-cyan-400" />
              </div>
              <span className="text-gray-400">Credits Available</span>
            </div>
            <div className="text-3xl font-bold text-cyan-400">{stats?.credits_available || 0}</div>
            <p className="text-sm text-gray-500 mt-1">= {Math.floor((stats?.credits_available || 0) / 30)} months free</p>
          </div>

          <div className="bg-gray-800 rounded-xl border border-gray-700 p-6">
            <div className="flex items-center gap-3 mb-3">
              <div className="p-2 bg-purple-500/20 rounded-lg">
                <Trophy className="w-5 h-5 text-purple-400" />
              </div>
              <span className="text-gray-400">Leaderboard Rank</span>
            </div>
            <div className="text-3xl font-bold text-white">
              {stats?.leaderboard_rank ? `#${stats.leaderboard_rank}` : '-'}
            </div>
          </div>
        </div>

        {/* Tabs */}
        <div className="flex gap-2 mb-6 border-b border-gray-700">
          {(['overview', 'history', 'leaderboard'] as const).map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
                activeTab === tab
                  ? 'border-cyan-500 text-cyan-400'
                  : 'border-transparent text-gray-400 hover:text-white'
              }`}
            >
              {tab.charAt(0).toUpperCase() + tab.slice(1)}
            </button>
          ))}
        </div>

        {/* Tab Content */}
        {activeTab === 'overview' && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
            {/* How it works */}
            <div className="bg-gray-800 rounded-xl border border-gray-700 p-6">
              <h3 className="text-lg font-semibold text-white mb-4">How It Works</h3>
              <div className="space-y-4">
                <div className="flex items-start gap-4">
                  <div className="w-8 h-8 rounded-full bg-cyan-500/20 flex items-center justify-center text-cyan-400 font-bold shrink-0">
                    1
                  </div>
                  <div>
                    <p className="text-white font-medium">Share your code</p>
                    <p className="text-gray-400 text-sm">Share your unique referral code or link with colleagues</p>
                  </div>
                </div>
                <div className="flex items-start gap-4">
                  <div className="w-8 h-8 rounded-full bg-cyan-500/20 flex items-center justify-center text-cyan-400 font-bold shrink-0">
                    2
                  </div>
                  <div>
                    <p className="text-white font-medium">They sign up</p>
                    <p className="text-gray-400 text-sm">Your friend uses your code during registration</p>
                  </div>
                </div>
                <div className="flex items-start gap-4">
                  <div className="w-8 h-8 rounded-full bg-cyan-500/20 flex items-center justify-center text-cyan-400 font-bold shrink-0">
                    3
                  </div>
                  <div>
                    <p className="text-white font-medium">They subscribe</p>
                    <p className="text-gray-400 text-sm">When they become a paying customer, you both earn rewards</p>
                  </div>
                </div>
                <div className="flex items-start gap-4">
                  <div className="w-8 h-8 rounded-full bg-green-500/20 flex items-center justify-center text-green-400 font-bold shrink-0">
                    <Check className="w-4 h-4" />
                  </div>
                  <div>
                    <p className="text-white font-medium">Everyone wins!</p>
                    <p className="text-gray-400 text-sm">You get 1 month free, they get 20% off first year</p>
                  </div>
                </div>
              </div>
            </div>

            {/* Rewards breakdown */}
            <div className="bg-gray-800 rounded-xl border border-gray-700 p-6">
              <h3 className="text-lg font-semibold text-white mb-4">Rewards</h3>
              <div className="space-y-4">
                <div className="bg-gray-700/50 rounded-lg p-4">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-gray-300">For You (Referrer)</span>
                    <span className="text-cyan-400 font-bold">1 Month Free</span>
                  </div>
                  <p className="text-gray-400 text-sm">For each friend who becomes a paying customer</p>
                </div>
                <div className="bg-gray-700/50 rounded-lg p-4">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-gray-300">For Them (Referee)</span>
                    <span className="text-green-400 font-bold">20% Off</span>
                  </div>
                  <p className="text-gray-400 text-sm">On their first year of subscription</p>
                </div>
                <div className="bg-purple-900/30 rounded-lg p-4 border border-purple-500/30">
                  <div className="flex items-center gap-2 mb-2">
                    <Trophy className="w-5 h-5 text-purple-400" />
                    <span className="text-purple-300 font-medium">Partner Tier</span>
                  </div>
                  <p className="text-gray-400 text-sm">
                    Refer 10+ customers and become a HeroForge Partner with exclusive benefits!
                  </p>
                </div>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'history' && (
          <div className="bg-gray-800 rounded-xl border border-gray-700 overflow-hidden">
            {history.length === 0 ? (
              <div className="p-12 text-center">
                <Users className="w-12 h-12 text-gray-600 mx-auto mb-4" />
                <h3 className="text-lg font-medium text-white mb-2">No referrals yet</h3>
                <p className="text-gray-400 mb-4">Share your code to start earning rewards!</p>
                <button
                  onClick={copyLink}
                  className="px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg transition-colors inline-flex items-center gap-2"
                >
                  <Share2 className="w-4 h-4" />
                  Share Your Link
                </button>
              </div>
            ) : (
              <table className="w-full">
                <thead className="bg-gray-700/50">
                  <tr>
                    <th className="text-left px-6 py-3 text-xs font-medium text-gray-400 uppercase tracking-wider">
                      Email
                    </th>
                    <th className="text-left px-6 py-3 text-xs font-medium text-gray-400 uppercase tracking-wider">
                      Status
                    </th>
                    <th className="text-left px-6 py-3 text-xs font-medium text-gray-400 uppercase tracking-wider">
                      Credits
                    </th>
                    <th className="text-left px-6 py-3 text-xs font-medium text-gray-400 uppercase tracking-wider">
                      Date
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-700">
                  {history.map((record) => (
                    <tr key={record.id} className="hover:bg-gray-700/30">
                      <td className="px-6 py-4">
                        <span className="text-white">
                          {record.referee_email || 'Unknown'}
                        </span>
                      </td>
                      <td className="px-6 py-4">
                        <div className="flex items-center gap-2">
                          {getStatusIcon(record.status)}
                          <span className={`text-xs px-2 py-1 rounded ${getStatusColor(record.status)}`}>
                            {record.status}
                          </span>
                        </div>
                      </td>
                      <td className="px-6 py-4">
                        <span className={record.credits_awarded > 0 ? 'text-green-400' : 'text-gray-400'}>
                          {record.credits_awarded > 0 ? `+${record.credits_awarded}` : '-'}
                        </span>
                      </td>
                      <td className="px-6 py-4 text-gray-400 text-sm">
                        {new Date(record.created_at).toLocaleDateString()}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        )}

        {activeTab === 'leaderboard' && (
          <div className="bg-gray-800 rounded-xl border border-gray-700 overflow-hidden">
            {leaderboard.length === 0 ? (
              <div className="p-12 text-center">
                <Trophy className="w-12 h-12 text-gray-600 mx-auto mb-4" />
                <h3 className="text-lg font-medium text-white mb-2">Leaderboard is empty</h3>
                <p className="text-gray-400">Be the first to refer a friend and claim the top spot!</p>
              </div>
            ) : (
              <table className="w-full">
                <thead className="bg-gray-700/50">
                  <tr>
                    <th className="text-left px-6 py-3 text-xs font-medium text-gray-400 uppercase tracking-wider w-16">
                      Rank
                    </th>
                    <th className="text-left px-6 py-3 text-xs font-medium text-gray-400 uppercase tracking-wider">
                      User
                    </th>
                    <th className="text-right px-6 py-3 text-xs font-medium text-gray-400 uppercase tracking-wider">
                      Referrals
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-700">
                  {leaderboard.map((entry) => (
                    <tr
                      key={entry.rank}
                      className={`hover:bg-gray-700/30 ${entry.is_current_user ? 'bg-cyan-900/20' : ''}`}
                    >
                      <td className="px-6 py-4">
                        <div className="flex items-center justify-center w-8 h-8">
                          {entry.rank === 1 ? (
                            <span className="text-2xl">🥇</span>
                          ) : entry.rank === 2 ? (
                            <span className="text-2xl">🥈</span>
                          ) : entry.rank === 3 ? (
                            <span className="text-2xl">🥉</span>
                          ) : (
                            <span className="text-gray-400 font-bold">#{entry.rank}</span>
                          )}
                        </div>
                      </td>
                      <td className="px-6 py-4">
                        <div className="flex items-center gap-2">
                          <span className={entry.is_current_user ? 'text-cyan-400 font-medium' : 'text-white'}>
                            {entry.username}
                          </span>
                          {entry.is_current_user && (
                            <span className="text-xs bg-cyan-500/20 text-cyan-400 px-2 py-0.5 rounded">
                              You
                            </span>
                          )}
                        </div>
                      </td>
                      <td className="px-6 py-4 text-right">
                        <span className="text-white font-bold">{entry.successful_referrals}</span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        )}
      </div>
    </div>
  );
};

export default ReferralDashboardPage;
