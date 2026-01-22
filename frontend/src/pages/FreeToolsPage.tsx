import React, { useState } from 'react';
import { Link } from 'react-router-dom';

// Types for tool results
interface SubdomainResult {
  subdomain: string;
  ip?: string;
  status: 'active' | 'inactive';
}

interface HeaderResult {
  header: string;
  value: string | null;
  status: 'good' | 'warning' | 'missing';
  recommendation: string;
}

interface SSLResult {
  valid: boolean;
  issuer: string;
  subject: string;
  validFrom: string;
  validTo: string;
  daysRemaining: number;
  protocol: string;
  cipher: string;
  grade: 'A+' | 'A' | 'B' | 'C' | 'D' | 'F';
}

interface DNSRecord {
  type: string;
  name: string;
  value: string;
  ttl: number;
}

interface WHOISResult {
  domainName: string;
  registrar: string;
  createdDate: string;
  expiryDate: string;
  nameServers: string[];
  status: string[];
}

interface PortResult {
  port: number;
  state: 'open' | 'closed' | 'filtered';
  service: string;
  version?: string;
}

interface CVEResult {
  id: string;
  description: string;
  cvss: number;
  severity: 'critical' | 'high' | 'medium' | 'low';
  publishedDate: string;
  references: string[];
}

// Tool Component Props
interface ToolCardProps {
  title: string;
  description: string;
  icon: string;
  children: React.ReactNode;
}

const ToolCard: React.FC<ToolCardProps> = ({ title, description, icon, children }) => (
  <div className="bg-gray-800 rounded-xl border border-gray-700 overflow-hidden">
    <div className="p-6 border-b border-gray-700">
      <div className="flex items-center gap-3 mb-2">
        <span className="text-3xl">{icon}</span>
        <h2 className="text-xl font-bold text-white">{title}</h2>
      </div>
      <p className="text-gray-400 text-sm">{description}</p>
    </div>
    <div className="p-6">
      {children}
    </div>
  </div>
);

// Subdomain Finder Tool
const SubdomainFinder: React.FC = () => {
  const [domain, setDomain] = useState('');
  const [email, setEmail] = useState('');
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState<SubdomainResult[] | null>(null);
  const [showEmailPrompt, setShowEmailPrompt] = useState(false);
  const [totalFound, setTotalFound] = useState(0);
  const [error, setError] = useState<string | null>(null);

  const handleScan = async () => {
    if (!domain) return;
    setLoading(true);
    setError(null);

    try {
      // Clean domain
      let cleanDomain = domain.replace(/^https?:\/\//, '').split('/')[0];

      const response = await fetch(`/api/tools/subdomains?domain=${encodeURIComponent(cleanDomain)}`);
      const data = await response.json();

      if (!data.success) {
        throw new Error(data.error || 'Failed to find subdomains');
      }

      // Map API response to component format
      const mappedResults: SubdomainResult[] = data.data.subdomains.map((s: { subdomain: string; ip?: string }) => ({
        subdomain: s.subdomain,
        ip: s.ip,
        status: s.ip ? 'active' : 'inactive',
      }));

      setTotalFound(data.data.total || mappedResults.length);
      setResults(mappedResults.slice(0, 3)); // Show only 3 for free
      setShowEmailPrompt(mappedResults.length > 3);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to find subdomains');
    } finally {
      setLoading(false);
    }
  };

  const handleGetFullResults = () => {
    if (email) {
      alert(`Full results will be sent to ${email}`);
      setShowEmailPrompt(false);
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex gap-2">
        <input
          type="text"
          value={domain}
          onChange={(e) => setDomain(e.target.value)}
          placeholder="example.com"
          className="flex-1 bg-gray-700 border border-gray-600 rounded-lg px-4 py-2 text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-cyan-500"
        />
        <button
          onClick={handleScan}
          disabled={loading || !domain}
          className="px-6 py-2 bg-cyan-600 hover:bg-cyan-700 disabled:bg-gray-600 text-white rounded-lg font-medium transition-colors"
        >
          {loading ? 'Scanning...' : 'Find Subdomains'}
        </button>
      </div>

      {error && (
        <div className="bg-red-500/20 border border-red-500/50 rounded-lg p-4 text-red-400 text-sm">
          {error}
        </div>
      )}

      {results && (
        <div className="space-y-3">
          <h3 className="text-sm font-medium text-gray-300">Found {results.length} subdomains (showing preview):</h3>
          <div className="space-y-2">
            {results.map((r, i) => (
              <div key={i} className="flex items-center justify-between bg-gray-700/50 rounded-lg px-4 py-2">
                <span className="text-white font-mono text-sm">{r.subdomain}</span>
                <div className="flex items-center gap-3">
                  {r.ip && <span className="text-gray-400 text-sm">{r.ip}</span>}
                  <span className={`text-xs px-2 py-1 rounded ${r.status === 'active' ? 'bg-green-500/20 text-green-400' : 'bg-gray-500/20 text-gray-400'}`}>
                    {r.status}
                  </span>
                </div>
              </div>
            ))}
          </div>

          {showEmailPrompt && (
            <div className="bg-cyan-900/30 border border-cyan-700 rounded-lg p-4 mt-4">
              <p className="text-cyan-300 text-sm mb-3">Enter your email to receive the full list of {totalFound} discovered subdomains:</p>
              <div className="flex gap-2">
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="your@email.com"
                  className="flex-1 bg-gray-700 border border-gray-600 rounded-lg px-4 py-2 text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-cyan-500"
                />
                <button
                  onClick={handleGetFullResults}
                  className="px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg font-medium transition-colors"
                >
                  Get Full Results
                </button>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

// Security Headers Checker
const SecurityHeadersChecker: React.FC = () => {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState<HeaderResult[] | null>(null);
  const [score, setScore] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleCheck = async () => {
    if (!url) return;
    setLoading(true);
    setError(null);

    try {
      // Ensure URL has protocol
      let targetUrl = url;
      if (!targetUrl.startsWith('http://') && !targetUrl.startsWith('https://')) {
        targetUrl = 'https://' + targetUrl;
      }

      const response = await fetch(`/api/tools/security-headers?url=${encodeURIComponent(targetUrl)}`);
      const data = await response.json();

      if (!data.success) {
        throw new Error(data.error || 'Failed to check headers');
      }

      // Map API response to component format
      const mappedResults: HeaderResult[] = data.data.headers.map((h: { name: string; value: string | null; status: string; recommendation: string | null }) => ({
        header: h.name,
        value: h.value,
        status: h.status === 'present' ? 'good' : (h.name === 'X-XSS-Protection' ? 'warning' : 'missing'),
        recommendation: h.recommendation || '',
      }));

      setScore(data.data.score);
      setResults(mappedResults);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to check headers');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex gap-2">
        <input
          type="text"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="https://example.com"
          className="flex-1 bg-gray-700 border border-gray-600 rounded-lg px-4 py-2 text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-cyan-500"
        />
        <button
          onClick={handleCheck}
          disabled={loading || !url}
          className="px-6 py-2 bg-cyan-600 hover:bg-cyan-700 disabled:bg-gray-600 text-white rounded-lg font-medium transition-colors"
        >
          {loading ? 'Checking...' : 'Check Headers'}
        </button>
      </div>

      {error && (
        <div className="bg-red-500/20 border border-red-500/50 rounded-lg p-4 text-red-400 text-sm">
          {error}
        </div>
      )}

      {results && score !== null && (
        <div className="space-y-4">
          <div className="flex items-center gap-4">
            <div className={`text-4xl font-bold ${score >= 70 ? 'text-green-400' : score >= 40 ? 'text-yellow-400' : 'text-red-400'}`}>
              {score}%
            </div>
            <div>
              <p className="text-white font-medium">Security Score</p>
              <p className="text-gray-400 text-sm">{results.filter(r => r.status === 'good').length} of {results.length} headers configured</p>
            </div>
          </div>

          <div className="space-y-2">
            {results.map((r, i) => (
              <div key={i} className="bg-gray-700/50 rounded-lg px-4 py-3">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-white font-medium">{r.header}</span>
                  <span className={`text-xs px-2 py-1 rounded ${
                    r.status === 'good' ? 'bg-green-500/20 text-green-400' :
                    r.status === 'warning' ? 'bg-yellow-500/20 text-yellow-400' :
                    'bg-red-500/20 text-red-400'
                  }`}>
                    {r.status === 'good' ? 'Present' : r.status === 'warning' ? 'Warning' : 'Missing'}
                  </span>
                </div>
                {r.value && <p className="text-gray-400 text-xs font-mono truncate">{r.value}</p>}
                <p className="text-gray-500 text-xs mt-1">{r.recommendation}</p>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

// SSL/TLS Analyzer
const SSLAnalyzer: React.FC = () => {
  const [domain, setDomain] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<SSLResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleAnalyze = async () => {
    if (!domain) return;
    setLoading(true);
    setError(null);

    try {
      // Clean domain (remove protocol if present)
      let cleanDomain = domain.replace(/^https?:\/\//, '').split('/')[0];

      const response = await fetch(`/api/tools/ssl-analyzer?domain=${encodeURIComponent(cleanDomain)}`);
      const data = await response.json();

      if (!data.success) {
        throw new Error(data.error || 'Failed to analyze SSL');
      }

      // Map API response to component format
      const cert = data.data;
      setResult({
        valid: cert.valid,
        issuer: cert.issuer || 'Unknown',
        subject: cert.subject || cleanDomain,
        validFrom: cert.validFrom || 'Unknown',
        validTo: cert.validTo || 'Unknown',
        daysRemaining: cert.daysUntilExpiry || 0,
        protocol: cert.protocol || 'Unknown',
        cipher: cert.cipher || 'Unknown',
        grade: cert.grade || 'F',
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to analyze SSL');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex gap-2">
        <input
          type="text"
          value={domain}
          onChange={(e) => setDomain(e.target.value)}
          placeholder="example.com"
          className="flex-1 bg-gray-700 border border-gray-600 rounded-lg px-4 py-2 text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-cyan-500"
        />
        <button
          onClick={handleAnalyze}
          disabled={loading || !domain}
          className="px-6 py-2 bg-cyan-600 hover:bg-cyan-700 disabled:bg-gray-600 text-white rounded-lg font-medium transition-colors"
        >
          {loading ? 'Analyzing...' : 'Analyze SSL'}
        </button>
      </div>

      {error && (
        <div className="bg-red-500/20 border border-red-500/50 rounded-lg p-4 text-red-400 text-sm">
          {error}
        </div>
      )}

      {result && (
        <div className="space-y-4">
          <div className="flex items-center gap-4">
            <div className={`w-16 h-16 rounded-xl flex items-center justify-center text-2xl font-bold ${
              result.grade === 'A+' || result.grade === 'A' ? 'bg-green-500/20 text-green-400' :
              result.grade === 'B' ? 'bg-yellow-500/20 text-yellow-400' :
              'bg-red-500/20 text-red-400'
            }`}>
              {result.grade}
            </div>
            <div>
              <p className="text-white font-medium">{result.valid ? 'Certificate Valid' : 'Certificate Invalid'}</p>
              <p className="text-gray-400 text-sm">{result.daysRemaining} days until expiration</p>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div className="bg-gray-700/50 rounded-lg p-3">
              <p className="text-gray-400 text-xs mb-1">Issuer</p>
              <p className="text-white text-sm">{result.issuer}</p>
            </div>
            <div className="bg-gray-700/50 rounded-lg p-3">
              <p className="text-gray-400 text-xs mb-1">Protocol</p>
              <p className="text-white text-sm">{result.protocol}</p>
            </div>
            <div className="bg-gray-700/50 rounded-lg p-3">
              <p className="text-gray-400 text-xs mb-1">Valid From</p>
              <p className="text-white text-sm">{result.validFrom}</p>
            </div>
            <div className="bg-gray-700/50 rounded-lg p-3">
              <p className="text-gray-400 text-xs mb-1">Valid To</p>
              <p className="text-white text-sm">{result.validTo}</p>
            </div>
            <div className="bg-gray-700/50 rounded-lg p-3 col-span-2">
              <p className="text-gray-400 text-xs mb-1">Cipher Suite</p>
              <p className="text-white text-sm font-mono">{result.cipher}</p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

// DNS Lookup
const DNSLookup: React.FC = () => {
  const [domain, setDomain] = useState('');
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState<DNSRecord[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleLookup = async () => {
    if (!domain) return;
    setLoading(true);
    setError(null);

    try {
      // Clean domain
      let cleanDomain = domain.replace(/^https?:\/\//, '').split('/')[0];

      const response = await fetch(`/api/tools/dns-security?domain=${encodeURIComponent(cleanDomain)}`);
      const data = await response.json();

      if (!data.success) {
        throw new Error(data.error || 'Failed to lookup DNS');
      }

      // Map API response to component format
      const mappedResults: DNSRecord[] = data.data.records.map((r: { record_type: string; name: string; value: string; ttl: number }) => ({
        type: r.record_type,
        name: r.name || cleanDomain,
        value: r.value,
        ttl: r.ttl || 3600,
      }));

      setResults(mappedResults);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to lookup DNS');
    } finally {
      setLoading(false);
    }
  };

  const getTypeColor = (type: string) => {
    const colors: Record<string, string> = {
      'A': 'bg-blue-500/20 text-blue-400',
      'AAAA': 'bg-purple-500/20 text-purple-400',
      'MX': 'bg-green-500/20 text-green-400',
      'NS': 'bg-yellow-500/20 text-yellow-400',
      'TXT': 'bg-pink-500/20 text-pink-400',
      'SOA': 'bg-orange-500/20 text-orange-400',
      'CNAME': 'bg-cyan-500/20 text-cyan-400',
    };
    return colors[type] || 'bg-gray-500/20 text-gray-400';
  };

  return (
    <div className="space-y-4">
      <div className="flex gap-2">
        <input
          type="text"
          value={domain}
          onChange={(e) => setDomain(e.target.value)}
          placeholder="example.com"
          className="flex-1 bg-gray-700 border border-gray-600 rounded-lg px-4 py-2 text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-cyan-500"
        />
        <button
          onClick={handleLookup}
          disabled={loading || !domain}
          className="px-6 py-2 bg-cyan-600 hover:bg-cyan-700 disabled:bg-gray-600 text-white rounded-lg font-medium transition-colors"
        >
          {loading ? 'Looking up...' : 'Lookup DNS'}
        </button>
      </div>

      {error && (
        <div className="bg-red-500/20 border border-red-500/50 rounded-lg p-4 text-red-400 text-sm">
          {error}
        </div>
      )}

      {results && (
        <div className="space-y-2">
          {results.map((r, i) => (
            <div key={i} className="flex items-center gap-3 bg-gray-700/50 rounded-lg px-4 py-2">
              <span className={`text-xs px-2 py-1 rounded font-mono ${getTypeColor(r.type)}`}>
                {r.type}
              </span>
              <span className="text-white font-mono text-sm flex-1 truncate">{r.value}</span>
              <span className="text-gray-500 text-xs">TTL: {r.ttl}s</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

// WHOIS Lookup
const WHOISLookup: React.FC = () => {
  const [domain, setDomain] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<WHOISResult | null>(null);

  const [error, setError] = useState<string | null>(null);

  const handleLookup = async () => {
    if (!domain) return;
    setLoading(true);
    setError(null);

    try {
      let cleanDomain = domain.replace(/^https?:\/\//, '').split('/')[0];

      const response = await fetch(`/api/tools/whois?domain=${encodeURIComponent(cleanDomain)}`);
      const data = await response.json();

      if (!data.success) {
        throw new Error(data.error || 'WHOIS lookup failed');
      }

      const w = data.data;
      setResult({
        domainName: w.domain || cleanDomain.toUpperCase(),
        registrar: w.registrar || 'Unknown',
        createdDate: w.creation_date || 'Unknown',
        expiryDate: w.expiration_date || 'Unknown',
        nameServers: w.nameservers || [],
        status: w.status || [],
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'WHOIS lookup failed');
      setResult(null);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex gap-2">
        <input
          type="text"
          value={domain}
          onChange={(e) => setDomain(e.target.value)}
          placeholder="example.com"
          className="flex-1 bg-gray-700 border border-gray-600 rounded-lg px-4 py-2 text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-cyan-500"
        />
        <button
          onClick={handleLookup}
          disabled={loading || !domain}
          className="px-6 py-2 bg-cyan-600 hover:bg-cyan-700 disabled:bg-gray-600 text-white rounded-lg font-medium transition-colors"
        >
          {loading ? 'Looking up...' : 'WHOIS Lookup'}
        </button>
      </div>

      {error && (
        <div className="bg-red-500/20 border border-red-500/50 rounded-lg p-4 text-red-400 text-sm">
          {error}
        </div>
      )}

      {result && (
        <div className="space-y-3">
          <div className="grid grid-cols-2 gap-3">
            <div className="bg-gray-700/50 rounded-lg p-3">
              <p className="text-gray-400 text-xs mb-1">Domain Name</p>
              <p className="text-white text-sm font-mono">{result.domainName}</p>
            </div>
            <div className="bg-gray-700/50 rounded-lg p-3">
              <p className="text-gray-400 text-xs mb-1">Registrar</p>
              <p className="text-white text-sm">{result.registrar}</p>
            </div>
            <div className="bg-gray-700/50 rounded-lg p-3">
              <p className="text-gray-400 text-xs mb-1">Created</p>
              <p className="text-white text-sm">{result.createdDate}</p>
            </div>
            <div className="bg-gray-700/50 rounded-lg p-3">
              <p className="text-gray-400 text-xs mb-1">Expires</p>
              <p className="text-white text-sm">{result.expiryDate}</p>
            </div>
          </div>
          <div className="bg-gray-700/50 rounded-lg p-3">
            <p className="text-gray-400 text-xs mb-2">Name Servers</p>
            <div className="flex flex-wrap gap-2">
              {result.nameServers.map((ns, i) => (
                <span key={i} className="text-white text-sm font-mono bg-gray-600 px-2 py-1 rounded">{ns}</span>
              ))}
            </div>
          </div>
          <div className="bg-gray-700/50 rounded-lg p-3">
            <p className="text-gray-400 text-xs mb-2">Status</p>
            <div className="flex flex-wrap gap-2">
              {result.status.map((s, i) => (
                <span key={i} className="text-xs bg-green-500/20 text-green-400 px-2 py-1 rounded">{s}</span>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

// Port Scanner (Limited)
const PortScanner: React.FC = () => {
  const [target, setTarget] = useState('');
  const [email, setEmail] = useState('');
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState<PortResult[] | null>(null);
  const [showEmailPrompt, setShowEmailPrompt] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleScan = async () => {
    if (!target) return;
    setLoading(true);
    setError(null);

    try {
      // Clean target (remove protocol if present)
      let cleanTarget = target.replace(/^https?:\/\//, '').split('/')[0];

      const response = await fetch(`/api/tools/port-scan?target=${encodeURIComponent(cleanTarget)}&ports=20`);
      const data = await response.json();

      if (!data.success) {
        throw new Error(data.error || 'Failed to scan ports');
      }

      // Map API response to component format
      const mappedResults: PortResult[] = data.data.ports.map((p: { port: number; state: string; service?: string; version?: string }) => ({
        port: p.port,
        state: p.state as 'open' | 'closed' | 'filtered',
        service: p.service || 'unknown',
        version: p.version,
      }));

      setResults(mappedResults);
      setShowEmailPrompt(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to scan ports');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex gap-2">
        <input
          type="text"
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          placeholder="example.com or IP address"
          className="flex-1 bg-gray-700 border border-gray-600 rounded-lg px-4 py-2 text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-cyan-500"
        />
        <button
          onClick={handleScan}
          disabled={loading || !target}
          className="px-6 py-2 bg-cyan-600 hover:bg-cyan-700 disabled:bg-gray-600 text-white rounded-lg font-medium transition-colors"
        >
          {loading ? 'Scanning...' : 'Scan Top 20 Ports'}
        </button>
      </div>

      <p className="text-yellow-400 text-xs flex items-center gap-2">
        <span>Warning:</span>
        <span>Only scan targets you own or have permission to test</span>
      </p>

      {error && (
        <div className="bg-red-500/20 border border-red-500/50 rounded-lg p-4 text-red-400 text-sm">
          {error}
        </div>
      )}

      {results && (
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-medium text-gray-300">Scan Results (Top 20 ports)</h3>
            <span className="text-xs text-gray-500">{results.filter(r => r.state === 'open').length} open ports found</span>
          </div>
          <div className="space-y-2">
            {results.map((r, i) => (
              <div key={i} className="flex items-center justify-between bg-gray-700/50 rounded-lg px-4 py-2">
                <div className="flex items-center gap-3">
                  <span className="text-white font-mono text-sm w-16">{r.port}</span>
                  <span className="text-gray-300 text-sm">{r.service}</span>
                  {r.version && <span className="text-gray-500 text-xs">{r.version}</span>}
                </div>
                <span className={`text-xs px-2 py-1 rounded ${
                  r.state === 'open' ? 'bg-green-500/20 text-green-400' :
                  r.state === 'filtered' ? 'bg-yellow-500/20 text-yellow-400' :
                  'bg-gray-500/20 text-gray-400'
                }`}>
                  {r.state}
                </span>
              </div>
            ))}
          </div>

          {showEmailPrompt && (
            <div className="bg-cyan-900/30 border border-cyan-700 rounded-lg p-4 mt-4">
              <p className="text-cyan-300 text-sm mb-3">Want a full scan of all 65,535 ports with service detection?</p>
              <div className="flex gap-2">
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="your@email.com"
                  className="flex-1 bg-gray-700 border border-gray-600 rounded-lg px-4 py-2 text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-cyan-500"
                />
                <button
                  onClick={() => email && alert(`Full scan link sent to ${email}`)}
                  className="px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg font-medium transition-colors"
                >
                  Get Full Scan
                </button>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

// CVE Lookup
const CVELookup: React.FC = () => {
  const [query, setQuery] = useState('');
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState<CVEResult[] | null>(null);

  const [error, setError] = useState<string | null>(null);

  const handleSearch = async () => {
    if (!query) return;
    setLoading(true);
    setError(null);

    try {
      // Ensure query is in CVE format
      let cveId = query.trim().toUpperCase();
      if (!cveId.startsWith('CVE-')) {
        cveId = 'CVE-' + cveId;
      }

      const response = await fetch(`/api/tools/cve-lookup?cve_id=${encodeURIComponent(cveId)}`);
      const data = await response.json();

      if (!data.success) {
        throw new Error(data.error || 'CVE lookup failed');
      }

      const cve = data.data;
      setResults([{
        id: cve.cve_id,
        description: cve.description,
        cvss: cve.cvss_score || 0,
        severity: (cve.severity || 'unknown').toLowerCase() as 'critical' | 'high' | 'medium' | 'low',
        publishedDate: cve.published_date ? cve.published_date.split('T')[0] : 'Unknown',
        references: cve.references || [],
      }]);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'CVE lookup failed');
      setResults(null);
    } finally {
      setLoading(false);
    }
  };

  const getSeverityColor = (severity: string) => {
    const colors: Record<string, string> = {
      critical: 'bg-red-500/20 text-red-400 border-red-500/50',
      high: 'bg-orange-500/20 text-orange-400 border-orange-500/50',
      medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/50',
      low: 'bg-blue-500/20 text-blue-400 border-blue-500/50',
    };
    return colors[severity] || 'bg-gray-500/20 text-gray-400';
  };

  return (
    <div className="space-y-4">
      <div className="flex gap-2">
        <input
          type="text"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Enter CVE ID (e.g., CVE-2021-44228)"
          className="flex-1 bg-gray-700 border border-gray-600 rounded-lg px-4 py-2 text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-cyan-500"
        />
        <button
          onClick={handleSearch}
          disabled={loading || !query}
          className="px-6 py-2 bg-cyan-600 hover:bg-cyan-700 disabled:bg-gray-600 text-white rounded-lg font-medium transition-colors"
        >
          {loading ? 'Searching...' : 'Search CVE'}
        </button>
      </div>

      {error && (
        <div className="bg-red-500/20 border border-red-500/50 rounded-lg p-4 text-red-400 text-sm">
          {error}
        </div>
      )}

      {results && (
        <div className="space-y-3">
          {results.map((r, i) => (
            <div key={i} className={`bg-gray-700/50 rounded-lg p-4 border-l-4 ${getSeverityColor(r.severity)}`}>
              <div className="flex items-center justify-between mb-2">
                <span className="text-white font-mono font-medium">{r.id}</span>
                <div className="flex items-center gap-2">
                  <span className={`text-xs px-2 py-1 rounded ${getSeverityColor(r.severity)}`}>
                    {r.severity.toUpperCase()}
                  </span>
                  <span className="text-white font-bold">{r.cvss}</span>
                </div>
              </div>
              <p className="text-gray-300 text-sm mb-2">{r.description}</p>
              <p className="text-gray-500 text-xs">Published: {r.publishedDate}</p>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

// Password Strength Checker
const PasswordStrengthChecker: React.FC = () => {
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);

  const analyzePassword = (pwd: string) => {
    const checks = {
      length: pwd.length >= 12,
      uppercase: /[A-Z]/.test(pwd),
      lowercase: /[a-z]/.test(pwd),
      numbers: /[0-9]/.test(pwd),
      special: /[!@#$%^&*(),.?":{}|<>]/.test(pwd),
      noCommon: !['password', '123456', 'qwerty', 'admin'].some(c => pwd.toLowerCase().includes(c)),
    };

    const score = Object.values(checks).filter(Boolean).length;
    const strength = score <= 2 ? 'Weak' : score <= 4 ? 'Medium' : 'Strong';
    const color = score <= 2 ? 'red' : score <= 4 ? 'yellow' : 'green';

    // Estimate crack time
    const charset = (checks.lowercase ? 26 : 0) + (checks.uppercase ? 26 : 0) + (checks.numbers ? 10 : 0) + (checks.special ? 32 : 0);
    const combinations = Math.pow(charset || 1, pwd.length);
    const guessesPerSecond = 10000000000; // 10 billion (modern GPU)
    const seconds = combinations / guessesPerSecond;

    let crackTime = 'instantly';
    if (seconds > 31536000 * 1000) crackTime = 'millions of years';
    else if (seconds > 31536000 * 100) crackTime = 'centuries';
    else if (seconds > 31536000) crackTime = `${Math.round(seconds / 31536000)} years`;
    else if (seconds > 86400 * 30) crackTime = `${Math.round(seconds / (86400 * 30))} months`;
    else if (seconds > 86400) crackTime = `${Math.round(seconds / 86400)} days`;
    else if (seconds > 3600) crackTime = `${Math.round(seconds / 3600)} hours`;
    else if (seconds > 60) crackTime = `${Math.round(seconds / 60)} minutes`;
    else if (seconds > 1) crackTime = `${Math.round(seconds)} seconds`;

    return { checks, score, strength, color, crackTime };
  };

  const analysis = password ? analyzePassword(password) : null;

  return (
    <div className="space-y-4">
      <div className="relative">
        <input
          type={showPassword ? 'text' : 'password'}
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          placeholder="Enter a password to check"
          className="w-full bg-gray-700 border border-gray-600 rounded-lg px-4 py-3 text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-cyan-500 pr-12"
        />
        <button
          onClick={() => setShowPassword(!showPassword)}
          className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-white"
        >
          {showPassword ? '👁️' : '👁️‍🗨️'}
        </button>
      </div>

      <p className="text-gray-500 text-xs">Your password is checked locally and never sent to our servers.</p>

      {analysis && (
        <div className="space-y-4">
          {/* Strength meter */}
          <div>
            <div className="flex justify-between mb-2">
              <span className="text-gray-400 text-sm">Strength</span>
              <span className={`font-medium ${
                analysis.color === 'red' ? 'text-red-400' :
                analysis.color === 'yellow' ? 'text-yellow-400' :
                'text-green-400'
              }`}>
                {analysis.strength}
              </span>
            </div>
            <div className="h-2 bg-gray-700 rounded-full overflow-hidden">
              <div
                className={`h-full transition-all ${
                  analysis.color === 'red' ? 'bg-red-500' :
                  analysis.color === 'yellow' ? 'bg-yellow-500' :
                  'bg-green-500'
                }`}
                style={{ width: `${(analysis.score / 6) * 100}%` }}
              />
            </div>
          </div>

          {/* Crack time */}
          <div className="bg-gray-700/50 rounded-lg p-4">
            <p className="text-gray-400 text-sm mb-1">Estimated time to crack:</p>
            <p className={`text-2xl font-bold ${
              analysis.crackTime === 'instantly' ? 'text-red-400' :
              analysis.crackTime.includes('second') || analysis.crackTime.includes('minute') ? 'text-orange-400' :
              analysis.crackTime.includes('hour') || analysis.crackTime.includes('day') ? 'text-yellow-400' :
              'text-green-400'
            }`}>
              {analysis.crackTime}
            </p>
          </div>

          {/* Checklist */}
          <div className="space-y-2">
            {[
              { key: 'length', label: 'At least 12 characters' },
              { key: 'uppercase', label: 'Contains uppercase letters' },
              { key: 'lowercase', label: 'Contains lowercase letters' },
              { key: 'numbers', label: 'Contains numbers' },
              { key: 'special', label: 'Contains special characters' },
              { key: 'noCommon', label: 'No common patterns' },
            ].map((item) => (
              <div key={item.key} className="flex items-center gap-2">
                <span className={analysis.checks[item.key as keyof typeof analysis.checks] ? 'text-green-400' : 'text-gray-500'}>
                  {analysis.checks[item.key as keyof typeof analysis.checks] ? '✓' : '○'}
                </span>
                <span className={`text-sm ${analysis.checks[item.key as keyof typeof analysis.checks] ? 'text-gray-300' : 'text-gray-500'}`}>
                  {item.label}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

// Main Free Tools Page
const FreeToolsPage: React.FC = () => {
  const [activeTab, setActiveTab] = useState<string>('all');

  const tools = [
    { id: 'subdomain', category: 'recon', component: <SubdomainFinder />, title: 'Subdomain Finder', description: 'Discover subdomains for any domain using DNS enumeration and certificate transparency logs.', icon: '🔍' },
    { id: 'headers', category: 'web', component: <SecurityHeadersChecker />, title: 'Security Headers Checker', description: 'Analyze HTTP security headers and get recommendations to improve your web security posture.', icon: '🛡️' },
    { id: 'ssl', category: 'web', component: <SSLAnalyzer />, title: 'SSL/TLS Analyzer', description: 'Check SSL certificate validity, protocol versions, and cipher suite configuration.', icon: '🔒' },
    { id: 'dns', category: 'recon', component: <DNSLookup />, title: 'DNS Lookup', description: 'Query comprehensive DNS records including A, AAAA, MX, NS, TXT, and SOA records.', icon: '🌐' },
    { id: 'whois', category: 'recon', component: <WHOISLookup />, title: 'WHOIS Lookup', description: 'Get domain registration information including registrar, dates, and name servers.', icon: '📋' },
    { id: 'port', category: 'network', component: <PortScanner />, title: 'Port Scanner', description: 'Scan the top 20 common ports to identify open services on a target system.', icon: '🔌' },
    { id: 'cve', category: 'vuln', component: <CVELookup />, title: 'CVE Lookup', description: 'Search the CVE database for vulnerability information, CVSS scores, and references.', icon: '🐛' },
    { id: 'password', category: 'util', component: <PasswordStrengthChecker />, title: 'Password Strength Checker', description: 'Check password strength and get estimated crack time. 100% client-side, never transmitted.', icon: '🔑' },
  ];

  const categories = [
    { id: 'all', label: 'All Tools' },
    { id: 'recon', label: 'Reconnaissance' },
    { id: 'web', label: 'Web Security' },
    { id: 'network', label: 'Network' },
    { id: 'vuln', label: 'Vulnerabilities' },
    { id: 'util', label: 'Utilities' },
  ];

  const filteredTools = activeTab === 'all' ? tools : tools.filter(t => t.category === activeTab);

  return (
    <div className="min-h-screen bg-gray-900">
      {/* Header */}
      <header className="bg-gray-800 border-b border-gray-700">
        <div className="max-w-7xl mx-auto px-4 py-4">
          <div className="flex items-center justify-between">
            <Link to="/" className="flex items-center gap-2">
              <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center">
                <span className="text-white text-xl font-bold">H</span>
              </div>
              <span className="text-white text-xl font-bold">HeroForge</span>
            </Link>
            <nav className="hidden md:flex items-center gap-6">
              <Link to="/features" className="text-gray-300 hover:text-white transition-colors">Features</Link>
              <Link to="/pricing" className="text-gray-300 hover:text-white transition-colors">Pricing</Link>
              <Link to="/tools" className="text-cyan-400">Free Tools</Link>
              <Link to="/blog" className="text-gray-300 hover:text-white transition-colors">Blog</Link>
              <Link to="/academy" className="text-gray-300 hover:text-white transition-colors">Academy</Link>
              <Link to="/docs" className="text-gray-300 hover:text-white transition-colors">Docs</Link>
              <Link to="/login" className="px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg transition-colors">
                Sign In
              </Link>
            </nav>
          </div>
        </div>
      </header>

      {/* Hero */}
      <section className="bg-gradient-to-b from-gray-800 to-gray-900 py-16">
        <div className="max-w-7xl mx-auto px-4 text-center">
          <h1 className="text-4xl md:text-5xl font-bold text-white mb-4">
            Free Security Tools
          </h1>
          <p className="text-xl text-gray-400 max-w-2xl mx-auto mb-8">
            Professional-grade security tools at your fingertips. No signup required for basic scans.
          </p>
          <div className="flex items-center justify-center gap-4">
            <Link
              to="/register"
              className="px-6 py-3 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg font-medium transition-colors"
            >
              Get Full Access Free
            </Link>
            <Link
              to="/pricing"
              className="px-6 py-3 bg-gray-700 hover:bg-gray-600 text-white rounded-lg font-medium transition-colors"
            >
              View Pro Plans
            </Link>
          </div>
        </div>
      </section>

      {/* Category Tabs */}
      <div className="bg-gray-800 border-b border-gray-700 sticky top-0 z-10">
        <div className="max-w-7xl mx-auto px-4">
          <div className="flex items-center gap-2 py-3 overflow-x-auto">
            {categories.map((cat) => (
              <button
                key={cat.id}
                onClick={() => setActiveTab(cat.id)}
                className={`px-4 py-2 rounded-lg font-medium whitespace-nowrap transition-colors ${
                  activeTab === cat.id
                    ? 'bg-cyan-600 text-white'
                    : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
                }`}
              >
                {cat.label}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Tools Grid */}
      <main className="max-w-7xl mx-auto px-4 py-12">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          {filteredTools.map((tool) => (
            <ToolCard
              key={tool.id}
              title={tool.title}
              description={tool.description}
              icon={tool.icon}
            >
              {tool.component}
            </ToolCard>
          ))}
        </div>
      </main>

      {/* CTA Section */}
      <section className="bg-gradient-to-r from-cyan-900/50 to-blue-900/50 py-16">
        <div className="max-w-4xl mx-auto px-4 text-center">
          <h2 className="text-3xl font-bold text-white mb-4">
            Need More Powerful Security Testing?
          </h2>
          <p className="text-gray-300 mb-8 text-lg">
            Sign up for HeroForge to access comprehensive vulnerability scanning, automated reporting,
            compliance frameworks, and AI-powered threat analysis.
          </p>
          <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
            <Link
              to="/register"
              className="px-8 py-4 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg font-medium text-lg transition-colors"
            >
              Start Free Trial
            </Link>
            <Link
              to="/features"
              className="px-8 py-4 bg-gray-700 hover:bg-gray-600 text-white rounded-lg font-medium text-lg transition-colors"
            >
              See All Features
            </Link>
          </div>
          <p className="text-gray-500 text-sm mt-4">No credit card required. 14-day free trial.</p>
        </div>
      </section>

      {/* Footer */}
      <footer className="bg-gray-800 border-t border-gray-700 py-12">
        <div className="max-w-7xl mx-auto px-4">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-8">
            <div>
              <h3 className="text-white font-semibold mb-4">Product</h3>
              <ul className="space-y-2">
                <li><Link to="/features" className="text-gray-400 hover:text-white transition-colors">Features</Link></li>
                <li><Link to="/pricing" className="text-gray-400 hover:text-white transition-colors">Pricing</Link></li>
                <li><Link to="/use-cases" className="text-gray-400 hover:text-white transition-colors">Use Cases</Link></li>
              </ul>
            </div>
            <div>
              <h3 className="text-white font-semibold mb-4">Resources</h3>
              <ul className="space-y-2">
                <li><Link to="/docs" className="text-gray-400 hover:text-white transition-colors">Documentation</Link></li>
                <li><Link to="/blog" className="text-gray-400 hover:text-white transition-colors">Blog</Link></li>
                <li><Link to="/academy" className="text-gray-400 hover:text-white transition-colors">Academy</Link></li>
              </ul>
            </div>
            <div>
              <h3 className="text-white font-semibold mb-4">Company</h3>
              <ul className="space-y-2">
                <li><Link to="/about" className="text-gray-400 hover:text-white transition-colors">About</Link></li>
                <li><Link to="/contact-sales" className="text-gray-400 hover:text-white transition-colors">Contact</Link></li>
                <li><Link to="/investors" className="text-gray-400 hover:text-white transition-colors">Investors</Link></li>
              </ul>
            </div>
            <div>
              <h3 className="text-white font-semibold mb-4">Legal</h3>
              <ul className="space-y-2">
                <li><Link to="/legal/terms" className="text-gray-400 hover:text-white transition-colors">Terms of Service</Link></li>
                <li><Link to="/legal/privacy" className="text-gray-400 hover:text-white transition-colors">Privacy Policy</Link></li>
                <li><Link to="/legal/acceptable-use" className="text-gray-400 hover:text-white transition-colors">Acceptable Use</Link></li>
              </ul>
            </div>
          </div>
          <div className="border-t border-gray-700 mt-8 pt-8 text-center">
            <p className="text-gray-500 text-sm">
              &copy; {new Date().getFullYear()} HeroForge Security. All rights reserved.
            </p>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default FreeToolsPage;
