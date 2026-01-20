import React, { useState, useEffect } from 'react';
import { useParams, useSearchParams } from 'react-router-dom';
import {
  Shield,
  RefreshCw,
  Copy,
  Check,
  AlertTriangle,
  AlertCircle,
  Info,
  ExternalLink,
  TrendingUp,
  TrendingDown,
  Minus,
  Code,
  Image,
  FileText,
} from 'lucide-react';
import { toast } from 'react-toastify';

interface SecurityScore {
  domain: string;
  score: number;
  grade: string;
  grade_color: string;
  last_scan: string | null;
  issues: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
}

interface EmbedCodes {
  markdown: string;
  html: string;
  html_flat: string;
  html_gradient: string;
  image_url: string;
  profile_url: string;
}

const SecurityBadgePage: React.FC = () => {
  const { domain: paramDomain } = useParams<{ domain: string }>();
  const [searchParams] = useSearchParams();
  const [domain, setDomain] = useState(paramDomain || searchParams.get('domain') || '');
  const [score, setScore] = useState<SecurityScore | null>(null);
  const [embedCodes, setEmbedCodes] = useState<EmbedCodes | null>(null);
  const [loading, setLoading] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copiedField, setCopiedField] = useState<string | null>(null);
  const [selectedStyle, setSelectedStyle] = useState<'shield' | 'flat' | 'gradient'>('shield');

  useEffect(() => {
    if (paramDomain) {
      loadScore(paramDomain);
      loadEmbedCodes(paramDomain);
    }
  }, [paramDomain]);

  const loadScore = async (targetDomain: string) => {
    setLoading(true);
    setError(null);
    try {
      const response = await fetch(`/api/badges/${targetDomain}/score`);
      const data = await response.json();
      if (data.success) {
        setScore(data.data);
      } else {
        setScore(null);
        if (response.status !== 404) {
          setError(data.error || 'Failed to load score');
        }
      }
    } catch (err) {
      setError('Failed to connect to server');
    } finally {
      setLoading(false);
    }
  };

  const loadEmbedCodes = async (targetDomain: string) => {
    try {
      const response = await fetch(`/api/badges/${targetDomain}/embed`);
      const data = await response.json();
      if (data.success) {
        setEmbedCodes(data.data);
      }
    } catch (err) {
      console.error('Failed to load embed codes:', err);
    }
  };

  const requestScan = async () => {
    if (!domain) return;
    setScanning(true);
    setError(null);
    try {
      const response = await fetch(`/api/badges/${domain}/scan`, { method: 'POST' });
      const data = await response.json();
      if (data.success) {
        setScore(data.data);
        loadEmbedCodes(domain);
        toast.success('Security scan completed!');
      } else {
        setError(data.error || 'Scan failed');
        toast.error(data.error || 'Scan failed');
      }
    } catch (err) {
      setError('Failed to perform scan');
      toast.error('Failed to perform scan');
    } finally {
      setScanning(false);
    }
  };

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    if (domain) {
      loadScore(domain);
      loadEmbedCodes(domain);
      window.history.pushState({}, '', `/security/${domain}`);
    }
  };

  const copyToClipboard = (text: string, field: string) => {
    navigator.clipboard.writeText(text);
    setCopiedField(field);
    toast.success('Copied to clipboard!');
    setTimeout(() => setCopiedField(null), 2000);
  };

  const getGradeDescription = (grade: string) => {
    switch (grade) {
      case 'A+':
      case 'A':
        return 'Excellent security posture';
      case 'A-':
      case 'B+':
        return 'Good security with minor improvements needed';
      case 'B':
      case 'B-':
        return 'Acceptable security with some gaps';
      case 'C+':
      case 'C':
        return 'Fair security with notable issues';
      case 'C-':
      case 'D+':
        return 'Poor security requiring attention';
      case 'D':
        return 'Significant security issues found';
      default:
        return 'Critical security vulnerabilities present';
    }
  };

  const getTrendIcon = (score: number) => {
    if (score >= 80) return <TrendingUp className="w-4 h-4 text-green-400" />;
    if (score >= 60) return <Minus className="w-4 h-4 text-yellow-400" />;
    return <TrendingDown className="w-4 h-4 text-red-400" />;
  };

  const getBadgeUrl = () => {
    const baseUrl = window.location.origin;
    const styleParam = selectedStyle !== 'shield' ? `?style=${selectedStyle}` : '';
    return `${baseUrl}/api/badges/${domain}${styleParam}`;
  };

  return (
    <div className="min-h-screen bg-gray-900">
      {/* Hero Section */}
      <div className="bg-gradient-to-b from-gray-800 to-gray-900 py-12 px-6">
        <div className="max-w-4xl mx-auto text-center">
          <div className="flex items-center justify-center space-x-3 mb-4">
            <Shield className="w-10 h-10 text-cyan-400" />
            <h1 className="text-3xl font-bold text-white">Security Score Badge</h1>
          </div>
          <p className="text-gray-400 mb-8">
            Showcase your website's security posture with a live security badge
          </p>

          {/* Search Form */}
          <form onSubmit={handleSearch} className="max-w-xl mx-auto">
            <div className="flex gap-2">
              <input
                type="text"
                value={domain}
                onChange={(e) => setDomain(e.target.value)}
                placeholder="Enter domain (e.g., example.com)"
                className="flex-1 bg-gray-800 border border-gray-700 rounded-lg px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-cyan-500"
              />
              <button
                type="submit"
                disabled={loading || !domain}
                className="px-6 py-3 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {loading ? (
                  <RefreshCw className="w-5 h-5 animate-spin" />
                ) : (
                  'Check'
                )}
              </button>
            </div>
          </form>
        </div>
      </div>

      {/* Results Section */}
      <div className="max-w-4xl mx-auto px-6 py-8">
        {error && (
          <div className="bg-red-900/20 border border-red-800 rounded-lg p-4 mb-6 flex items-center text-red-400">
            <AlertCircle className="w-5 h-5 mr-2 flex-shrink-0" />
            {error}
          </div>
        )}

        {score ? (
          <div className="space-y-6">
            {/* Score Card */}
            <div className="bg-gray-800 rounded-xl border border-gray-700 overflow-hidden">
              <div className="p-6">
                <div className="flex items-center justify-between mb-6">
                  <div>
                    <h2 className="text-xl font-semibold text-white">{score.domain}</h2>
                    <p className="text-sm text-gray-400">
                      Last scanned: {score.last_scan ? new Date(score.last_scan).toLocaleString() : 'Never'}
                    </p>
                  </div>
                  <button
                    onClick={requestScan}
                    disabled={scanning}
                    className="flex items-center px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded-lg transition-colors disabled:opacity-50"
                  >
                    <RefreshCw className={`w-4 h-4 mr-2 ${scanning ? 'animate-spin' : ''}`} />
                    {scanning ? 'Scanning...' : 'Rescan'}
                  </button>
                </div>

                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
                  {/* Grade */}
                  <div className="bg-gray-900 rounded-lg p-4 text-center">
                    <div
                      className="text-4xl font-bold mb-1"
                      style={{ color: score.grade_color }}
                    >
                      {score.grade}
                    </div>
                    <div className="text-sm text-gray-400">Grade</div>
                  </div>

                  {/* Score */}
                  <div className="bg-gray-900 rounded-lg p-4 text-center">
                    <div className="text-4xl font-bold text-white mb-1 flex items-center justify-center">
                      {score.score}
                      <span className="text-lg text-gray-500 ml-1">/100</span>
                    </div>
                    <div className="text-sm text-gray-400 flex items-center justify-center">
                      Score {getTrendIcon(score.score)}
                    </div>
                  </div>

                  {/* Total Issues */}
                  <div className="bg-gray-900 rounded-lg p-4 text-center">
                    <div className="text-4xl font-bold text-white mb-1">
                      {score.issues.critical + score.issues.high + score.issues.medium + score.issues.low + score.issues.info}
                    </div>
                    <div className="text-sm text-gray-400">Total Issues</div>
                  </div>

                  {/* Status */}
                  <div className="bg-gray-900 rounded-lg p-4 text-center">
                    <div className="text-sm text-gray-300 mb-1">{getGradeDescription(score.grade)}</div>
                    <div className="text-sm text-gray-400">Status</div>
                  </div>
                </div>

                {/* Issue Breakdown */}
                <div className="grid grid-cols-5 gap-2">
                  <div className="bg-red-900/30 border border-red-800 rounded-lg p-3 text-center">
                    <div className="text-2xl font-bold text-red-400">{score.issues.critical}</div>
                    <div className="text-xs text-red-300">Critical</div>
                  </div>
                  <div className="bg-orange-900/30 border border-orange-800 rounded-lg p-3 text-center">
                    <div className="text-2xl font-bold text-orange-400">{score.issues.high}</div>
                    <div className="text-xs text-orange-300">High</div>
                  </div>
                  <div className="bg-yellow-900/30 border border-yellow-800 rounded-lg p-3 text-center">
                    <div className="text-2xl font-bold text-yellow-400">{score.issues.medium}</div>
                    <div className="text-xs text-yellow-300">Medium</div>
                  </div>
                  <div className="bg-blue-900/30 border border-blue-800 rounded-lg p-3 text-center">
                    <div className="text-2xl font-bold text-blue-400">{score.issues.low}</div>
                    <div className="text-xs text-blue-300">Low</div>
                  </div>
                  <div className="bg-gray-700/50 border border-gray-600 rounded-lg p-3 text-center">
                    <div className="text-2xl font-bold text-gray-400">{score.issues.info}</div>
                    <div className="text-xs text-gray-300">Info</div>
                  </div>
                </div>
              </div>
            </div>

            {/* Badge Preview & Embed Codes */}
            <div className="bg-gray-800 rounded-xl border border-gray-700 overflow-hidden">
              <div className="border-b border-gray-700 p-4">
                <h3 className="text-lg font-semibold text-white">Embed Your Badge</h3>
                <p className="text-sm text-gray-400">Add this badge to your website to showcase your security score</p>
              </div>

              <div className="p-6">
                {/* Badge Style Selector */}
                <div className="flex items-center space-x-4 mb-6">
                  <span className="text-sm text-gray-400">Style:</span>
                  <div className="flex space-x-2">
                    {(['shield', 'flat', 'gradient'] as const).map((style) => (
                      <button
                        key={style}
                        onClick={() => setSelectedStyle(style)}
                        className={`px-3 py-1 rounded text-sm capitalize ${
                          selectedStyle === style
                            ? 'bg-cyan-600 text-white'
                            : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
                        }`}
                      >
                        {style}
                      </button>
                    ))}
                  </div>
                </div>

                {/* Badge Preview */}
                <div className="bg-gray-900 rounded-lg p-6 text-center mb-6">
                  <div className="text-sm text-gray-400 mb-3">Preview</div>
                  <img
                    src={getBadgeUrl()}
                    alt={`Security score for ${domain}`}
                    className="inline-block"
                  />
                </div>

                {/* Embed Code Options */}
                {embedCodes && (
                  <div className="space-y-4">
                    {/* HTML */}
                    <div>
                      <div className="flex items-center justify-between mb-2">
                        <div className="flex items-center text-sm text-gray-400">
                          <Code className="w-4 h-4 mr-1" />
                          HTML
                        </div>
                        <button
                          onClick={() => copyToClipboard(
                            selectedStyle === 'flat' ? embedCodes.html_flat :
                            selectedStyle === 'gradient' ? embedCodes.html_gradient :
                            embedCodes.html,
                            'html'
                          )}
                          className="flex items-center text-xs text-cyan-400 hover:text-cyan-300"
                        >
                          {copiedField === 'html' ? (
                            <Check className="w-3 h-3 mr-1" />
                          ) : (
                            <Copy className="w-3 h-3 mr-1" />
                          )}
                          Copy
                        </button>
                      </div>
                      <code className="block bg-gray-900 rounded p-3 text-xs text-gray-300 overflow-x-auto">
                        {selectedStyle === 'flat' ? embedCodes.html_flat :
                         selectedStyle === 'gradient' ? embedCodes.html_gradient :
                         embedCodes.html}
                      </code>
                    </div>

                    {/* Markdown */}
                    <div>
                      <div className="flex items-center justify-between mb-2">
                        <div className="flex items-center text-sm text-gray-400">
                          <FileText className="w-4 h-4 mr-1" />
                          Markdown
                        </div>
                        <button
                          onClick={() => copyToClipboard(embedCodes.markdown, 'markdown')}
                          className="flex items-center text-xs text-cyan-400 hover:text-cyan-300"
                        >
                          {copiedField === 'markdown' ? (
                            <Check className="w-3 h-3 mr-1" />
                          ) : (
                            <Copy className="w-3 h-3 mr-1" />
                          )}
                          Copy
                        </button>
                      </div>
                      <code className="block bg-gray-900 rounded p-3 text-xs text-gray-300 overflow-x-auto">
                        {embedCodes.markdown}
                      </code>
                    </div>

                    {/* Image URL */}
                    <div>
                      <div className="flex items-center justify-between mb-2">
                        <div className="flex items-center text-sm text-gray-400">
                          <Image className="w-4 h-4 mr-1" />
                          Direct Image URL
                        </div>
                        <button
                          onClick={() => copyToClipboard(getBadgeUrl(), 'url')}
                          className="flex items-center text-xs text-cyan-400 hover:text-cyan-300"
                        >
                          {copiedField === 'url' ? (
                            <Check className="w-3 h-3 mr-1" />
                          ) : (
                            <Copy className="w-3 h-3 mr-1" />
                          )}
                          Copy
                        </button>
                      </div>
                      <code className="block bg-gray-900 rounded p-3 text-xs text-gray-300 overflow-x-auto">
                        {getBadgeUrl()}
                      </code>
                    </div>
                  </div>
                )}
              </div>
            </div>

            {/* CTA */}
            <div className="bg-gradient-to-r from-cyan-900/50 to-blue-900/50 rounded-xl border border-cyan-800 p-6 text-center">
              <h3 className="text-xl font-semibold text-white mb-2">Want deeper security insights?</h3>
              <p className="text-gray-300 mb-4">
                Get comprehensive vulnerability scanning, compliance checks, and continuous monitoring with HeroForge.
              </p>
              <a
                href="/register"
                className="inline-flex items-center px-6 py-3 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg font-medium transition-colors"
              >
                Start Free Trial
                <ExternalLink className="w-4 h-4 ml-2" />
              </a>
            </div>
          </div>
        ) : !loading && domain && !error ? (
          /* No Score Yet */
          <div className="bg-gray-800 rounded-xl border border-gray-700 p-8 text-center">
            <AlertTriangle className="w-12 h-12 text-yellow-400 mx-auto mb-4" />
            <h3 className="text-xl font-semibold text-white mb-2">No security score found</h3>
            <p className="text-gray-400 mb-6">
              We haven't scanned {domain} yet. Click below to run a free security scan.
            </p>
            <button
              onClick={requestScan}
              disabled={scanning}
              className="inline-flex items-center px-6 py-3 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg font-medium transition-colors disabled:opacity-50"
            >
              <RefreshCw className={`w-5 h-5 mr-2 ${scanning ? 'animate-spin' : ''}`} />
              {scanning ? 'Scanning...' : 'Run Free Scan'}
            </button>
          </div>
        ) : !loading && !domain ? (
          /* Instructions */
          <div className="grid md:grid-cols-3 gap-6">
            <div className="bg-gray-800 rounded-xl border border-gray-700 p-6">
              <div className="w-10 h-10 bg-cyan-900 rounded-lg flex items-center justify-center mb-4">
                <span className="text-cyan-400 font-bold">1</span>
              </div>
              <h3 className="text-lg font-semibold text-white mb-2">Enter Your Domain</h3>
              <p className="text-gray-400 text-sm">
                Type your website's domain name in the search box above.
              </p>
            </div>
            <div className="bg-gray-800 rounded-xl border border-gray-700 p-6">
              <div className="w-10 h-10 bg-cyan-900 rounded-lg flex items-center justify-center mb-4">
                <span className="text-cyan-400 font-bold">2</span>
              </div>
              <h3 className="text-lg font-semibold text-white mb-2">Get Your Score</h3>
              <p className="text-gray-400 text-sm">
                We'll scan your site for security headers, SSL config, and more.
              </p>
            </div>
            <div className="bg-gray-800 rounded-xl border border-gray-700 p-6">
              <div className="w-10 h-10 bg-cyan-900 rounded-lg flex items-center justify-center mb-4">
                <span className="text-cyan-400 font-bold">3</span>
              </div>
              <h3 className="text-lg font-semibold text-white mb-2">Embed Your Badge</h3>
              <p className="text-gray-400 text-sm">
                Copy the embed code and add it to your website or README.
              </p>
            </div>
          </div>
        ) : null}
      </div>
    </div>
  );
};

export default SecurityBadgePage;
