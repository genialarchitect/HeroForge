import React, { useState, useEffect } from 'react';
import { toast } from 'react-toastify';
import {
  passiveReconAPI,
  type PassiveReconResult,
  type SubdomainResult,
  type HistoricalUrl,
  type CodeSearchResult,
  type CertificateInfo,
} from '../../services/api';
import {
  Globe,
  Search,
  Clock,
  Shield,
  Github,
  Archive,
  ExternalLink,
  AlertTriangle,
  CheckCircle,
  RefreshCw,
  Download,
  ChevronDown,
  ChevronRight,
  Server,
  Key,
  FileCode,
  Link2,
} from 'lucide-react';

interface PassiveReconPanelProps {
  initialDomain?: string;
  onSubdomainClick?: (subdomain: string) => void;
}

type TabType = 'subdomains' | 'urls' | 'github' | 'certificates' | 'sensitive';

const PassiveReconPanel: React.FC<PassiveReconPanelProps> = ({
  initialDomain,
  onSubdomainClick,
}) => {
  const [domain, setDomain] = useState(initialDomain || '');
  const [result, setResult] = useState<PassiveReconResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState<TabType>('subdomains');
  const [expandedSections, setExpandedSections] = useState<Set<string>>(new Set(['sources']));

  // Configuration options
  const [selectedSources, setSelectedSources] = useState<string[]>([
    'crtsh',
    'wayback',
  ]);
  const [githubToken, setGithubToken] = useState('');
  const [securityTrailsKey, setSecurityTrailsKey] = useState('');
  const [waybackLimit, setWaybackLimit] = useState(1000);

  const availableSources = [
    { id: 'crtsh', name: 'crt.sh', icon: Shield, description: 'Certificate Transparency logs' },
    { id: 'wayback', name: 'Wayback Machine', icon: Archive, description: 'Historical URLs' },
    { id: 'github', name: 'GitHub', icon: Github, description: 'Code search (requires token)' },
    { id: 'securitytrails', name: 'SecurityTrails', icon: Server, description: 'DNS history (requires API key)' },
  ];

  const handleRunRecon = async () => {
    if (!domain.trim()) {
      toast.error('Please enter a domain');
      return;
    }

    try {
      setLoading(true);
      const response = await passiveReconAPI.run({
        domain: domain.trim(),
        sources: selectedSources,
        github_token: githubToken || undefined,
        securitytrails_key: securityTrailsKey || undefined,
        wayback_url_limit: waybackLimit,
      });
      setResult(response.data);
      toast.success('Passive reconnaissance completed');
    } catch (error) {
      console.error('Passive recon failed:', error);
      toast.error('Passive reconnaissance failed');
    } finally {
      setLoading(false);
    }
  };

  const toggleSource = (sourceId: string) => {
    setSelectedSources((prev) =>
      prev.includes(sourceId)
        ? prev.filter((s) => s !== sourceId)
        : [...prev, sourceId]
    );
  };

  const toggleSection = (sectionId: string) => {
    setExpandedSections((prev) => {
      const newSet = new Set(prev);
      if (newSet.has(sectionId)) {
        newSet.delete(sectionId);
      } else {
        newSet.add(sectionId);
      }
      return newSet;
    });
  };

  const exportResults = () => {
    if (!result) return;
    const blob = new Blob([JSON.stringify(result, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `passive-recon-${domain}-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const renderSubdomains = () => {
    if (!result?.subdomains?.length) {
      return <p className="text-gray-400 text-center py-8">No subdomains discovered</p>;
    }

    return (
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-gray-700">
              <th className="text-left py-2 px-3 text-gray-400">Subdomain</th>
              <th className="text-left py-2 px-3 text-gray-400">Sources</th>
              <th className="text-left py-2 px-3 text-gray-400">IPs</th>
              <th className="text-left py-2 px-3 text-gray-400">First Seen</th>
            </tr>
          </thead>
          <tbody>
            {result.subdomains.map((sub, idx) => (
              <tr
                key={idx}
                className="border-b border-gray-700/50 hover:bg-gray-700/30 cursor-pointer"
                onClick={() => onSubdomainClick?.(sub.subdomain)}
              >
                <td className="py-2 px-3 font-mono text-cyan-400">{sub.subdomain}</td>
                <td className="py-2 px-3">
                  <div className="flex gap-1 flex-wrap">
                    {sub.sources.map((source, i) => (
                      <span
                        key={i}
                        className="px-2 py-0.5 text-xs bg-gray-700 rounded"
                      >
                        {source}
                      </span>
                    ))}
                  </div>
                </td>
                <td className="py-2 px-3 text-gray-400">
                  {sub.ip_addresses?.join(', ') || '-'}
                </td>
                <td className="py-2 px-3 text-gray-400">
                  {new Date(sub.first_seen).toLocaleDateString()}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  };

  const renderUrls = () => {
    if (!result?.historical_urls?.length) {
      return <p className="text-gray-400 text-center py-8">No historical URLs found</p>;
    }

    return (
      <div className="space-y-2 max-h-[500px] overflow-y-auto">
        {result.historical_urls.slice(0, 100).map((url, idx) => (
          <div
            key={idx}
            className="p-3 bg-gray-700/30 rounded border border-gray-700 hover:border-gray-600"
          >
            <div className="flex items-start gap-2">
              <Link2 className="w-4 h-4 text-gray-400 mt-1 flex-shrink-0" />
              <div className="flex-1 min-w-0">
                <a
                  href={url.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-sm text-cyan-400 hover:underline break-all"
                >
                  {url.url}
                </a>
                <div className="flex items-center gap-4 mt-1 text-xs text-gray-400">
                  {url.timestamp && (
                    <span>Archived: {url.timestamp}</span>
                  )}
                  {url.mime_type && (
                    <span>{url.mime_type}</span>
                  )}
                  {url.status_code && (
                    <span className={url.status_code < 400 ? 'text-green-400' : 'text-red-400'}>
                      Status: {url.status_code}
                    </span>
                  )}
                </div>
              </div>
              <a
                href={`https://web.archive.org/web/${url.timestamp}/${url.url}`}
                target="_blank"
                rel="noopener noreferrer"
                className="text-gray-400 hover:text-white"
              >
                <ExternalLink className="w-4 h-4" />
              </a>
            </div>
          </div>
        ))}
        {result.historical_urls.length > 100 && (
          <p className="text-sm text-gray-400 text-center py-2">
            Showing 100 of {result.historical_urls.length} URLs
          </p>
        )}
      </div>
    );
  };

  const renderGitHub = () => {
    if (!result?.code_search_results?.length) {
      return (
        <div className="text-center py-8">
          <Github className="w-12 h-12 text-gray-600 mx-auto mb-2" />
          <p className="text-gray-400">No GitHub code references found</p>
          {!githubToken && (
            <p className="text-sm text-gray-500 mt-2">
              Add a GitHub token to enable code search
            </p>
          )}
        </div>
      );
    }

    return (
      <div className="space-y-3">
        {result.code_search_results.map((item, idx) => (
          <div
            key={idx}
            className="p-4 bg-gray-700/30 rounded-lg border border-gray-700"
          >
            <div className="flex items-center gap-2 mb-2">
              <Github className="w-4 h-4 text-gray-400" />
              <a
                href={item.url}
                target="_blank"
                rel="noopener noreferrer"
                className="text-cyan-400 hover:underline font-medium"
              >
                {item.repository}
              </a>
              <span className="text-xs bg-gray-600 px-2 py-0.5 rounded">
                {item.search_type}
              </span>
            </div>
            <p className="text-sm text-gray-400 mb-2">{item.file_path}</p>
            {item.matched_content && (
              <pre className="text-xs bg-gray-900 p-2 rounded overflow-x-auto">
                <code className="text-gray-300">{item.matched_content}</code>
              </pre>
            )}
          </div>
        ))}
      </div>
    );
  };

  const renderCertificates = () => {
    if (!result?.certificates?.length) {
      return <p className="text-gray-400 text-center py-8">No certificates found</p>;
    }

    return (
      <div className="space-y-3">
        {result.certificates.map((cert, idx) => (
          <div
            key={idx}
            className="p-4 bg-gray-700/30 rounded-lg border border-gray-700"
          >
            <div className="flex items-center gap-2 mb-2">
              <Shield className="w-4 h-4 text-cyan-400" />
              <span className="font-medium">{cert.subject}</span>
            </div>
            <div className="grid grid-cols-2 gap-4 text-sm">
              <div>
                <span className="text-gray-400">Issuer:</span>
                <span className="ml-2 text-gray-200">{cert.issuer}</span>
              </div>
              <div>
                <span className="text-gray-400">Serial:</span>
                <span className="ml-2 font-mono text-xs text-gray-200">{cert.serial_number}</span>
              </div>
              <div>
                <span className="text-gray-400">Valid From:</span>
                <span className="ml-2 text-gray-200">
                  {new Date(cert.not_before).toLocaleDateString()}
                </span>
              </div>
              <div>
                <span className="text-gray-400">Valid Until:</span>
                <span className={`ml-2 ${
                  new Date(cert.not_after) < new Date() ? 'text-red-400' : 'text-gray-200'
                }`}>
                  {new Date(cert.not_after).toLocaleDateString()}
                </span>
              </div>
            </div>
            {cert.names.length > 0 && (
              <div className="mt-2">
                <span className="text-gray-400 text-sm">Names:</span>
                <div className="flex flex-wrap gap-1 mt-1">
                  {cert.names.map((name, i) => (
                    <span
                      key={i}
                      className="px-2 py-0.5 text-xs bg-gray-600 rounded font-mono"
                    >
                      {name}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        ))}
      </div>
    );
  };

  const renderSensitive = () => {
    if (!result?.sensitive_paths?.length) {
      return <p className="text-gray-400 text-center py-8">No sensitive paths detected</p>;
    }

    return (
      <div className="space-y-2">
        {result.sensitive_paths.map((path, idx) => (
          <div
            key={idx}
            className="p-3 bg-red-900/20 border border-red-700/50 rounded flex items-center gap-3"
          >
            <AlertTriangle className="w-4 h-4 text-red-400 flex-shrink-0" />
            <span className="font-mono text-sm text-red-300 break-all">{path}</span>
          </div>
        ))}
      </div>
    );
  };

  const tabs = [
    {
      id: 'subdomains' as TabType,
      label: 'Subdomains',
      count: result?.total_subdomains || 0,
      icon: Globe,
    },
    {
      id: 'urls' as TabType,
      label: 'Historical URLs',
      count: result?.total_urls || 0,
      icon: Archive,
    },
    {
      id: 'github' as TabType,
      label: 'GitHub',
      count: result?.total_code_results || 0,
      icon: Github,
    },
    {
      id: 'certificates' as TabType,
      label: 'Certificates',
      count: result?.certificates?.length || 0,
      icon: Shield,
    },
    {
      id: 'sensitive' as TabType,
      label: 'Sensitive Paths',
      count: result?.sensitive_paths?.length || 0,
      icon: AlertTriangle,
    },
  ];

  return (
    <div className="space-y-6">
      {/* Configuration Panel */}
      <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
        <div
          className="flex items-center justify-between cursor-pointer"
          onClick={() => toggleSection('sources')}
        >
          <h3 className="font-semibold">Reconnaissance Configuration</h3>
          {expandedSections.has('sources') ? (
            <ChevronDown className="w-5 h-5 text-gray-400" />
          ) : (
            <ChevronRight className="w-5 h-5 text-gray-400" />
          )}
        </div>

        {expandedSections.has('sources') && (
          <div className="mt-4 space-y-4">
            {/* Domain Input */}
            <div className="flex gap-4">
              <div className="flex-1">
                <label className="block text-sm text-gray-400 mb-1">Target Domain</label>
                <input
                  type="text"
                  value={domain}
                  onChange={(e) => setDomain(e.target.value)}
                  placeholder="example.com"
                  className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2"
                />
              </div>
              <div className="flex items-end">
                <button
                  onClick={handleRunRecon}
                  disabled={loading || !domain.trim()}
                  className="flex items-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-500 rounded disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {loading ? (
                    <RefreshCw className="w-4 h-4 animate-spin" />
                  ) : (
                    <Search className="w-4 h-4" />
                  )}
                  {loading ? 'Running...' : 'Run Recon'}
                </button>
              </div>
            </div>

            {/* Sources Selection */}
            <div>
              <label className="block text-sm text-gray-400 mb-2">Data Sources</label>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                {availableSources.map((source) => {
                  const Icon = source.icon;
                  const isSelected = selectedSources.includes(source.id);
                  return (
                    <button
                      key={source.id}
                      onClick={() => toggleSource(source.id)}
                      className={`p-3 rounded-lg border text-left transition-colors ${
                        isSelected
                          ? 'bg-cyan-900/30 border-cyan-600'
                          : 'bg-gray-700/30 border-gray-700 hover:border-gray-600'
                      }`}
                    >
                      <div className="flex items-center gap-2 mb-1">
                        <Icon className={`w-4 h-4 ${isSelected ? 'text-cyan-400' : 'text-gray-400'}`} />
                        <span className="text-sm font-medium">{source.name}</span>
                      </div>
                      <p className="text-xs text-gray-400">{source.description}</p>
                    </button>
                  );
                })}
              </div>
            </div>

            {/* API Keys */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div>
                <label className="block text-sm text-gray-400 mb-1">GitHub Token (optional)</label>
                <input
                  type="password"
                  value={githubToken}
                  onChange={(e) => setGithubToken(e.target.value)}
                  placeholder="ghp_..."
                  className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-sm"
                />
              </div>
              <div>
                <label className="block text-sm text-gray-400 mb-1">SecurityTrails Key (optional)</label>
                <input
                  type="password"
                  value={securityTrailsKey}
                  onChange={(e) => setSecurityTrailsKey(e.target.value)}
                  placeholder="API key"
                  className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-sm"
                />
              </div>
              <div>
                <label className="block text-sm text-gray-400 mb-1">Wayback URL Limit</label>
                <input
                  type="number"
                  value={waybackLimit}
                  onChange={(e) => setWaybackLimit(parseInt(e.target.value) || 1000)}
                  className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-sm"
                />
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Results Panel */}
      {result && (
        <div className="bg-gray-800 rounded-lg border border-gray-700">
          {/* Summary Header */}
          <div className="p-4 border-b border-gray-700">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="font-semibold flex items-center gap-2">
                  <Globe className="w-5 h-5 text-cyan-400" />
                  Results for {result.domain}
                </h3>
                <div className="flex items-center gap-4 mt-1 text-sm text-gray-400">
                  <span>Sources: {result.sources_used?.join(', ') || 'N/A'}</span>
                  {result.completed_at && (
                    <span>
                      Completed: {new Date(result.completed_at).toLocaleString()}
                    </span>
                  )}
                </div>
              </div>
              <button
                onClick={exportResults}
                className="flex items-center gap-1 px-3 py-1 text-sm bg-gray-700 hover:bg-gray-600 rounded"
              >
                <Download className="w-4 h-4" />
                Export
              </button>
            </div>
          </div>

          {/* Tabs */}
          <div className="border-b border-gray-700">
            <div className="flex overflow-x-auto">
              {tabs.map((tab) => {
                const Icon = tab.icon;
                return (
                  <button
                    key={tab.id}
                    onClick={() => setActiveTab(tab.id)}
                    className={`flex items-center gap-2 px-4 py-3 text-sm whitespace-nowrap border-b-2 transition-colors ${
                      activeTab === tab.id
                        ? 'border-cyan-500 text-cyan-400'
                        : 'border-transparent text-gray-400 hover:text-gray-200'
                    }`}
                  >
                    <Icon className="w-4 h-4" />
                    {tab.label}
                    {tab.count > 0 && (
                      <span className="px-1.5 py-0.5 text-xs bg-gray-700 rounded-full">
                        {tab.count}
                      </span>
                    )}
                  </button>
                );
              })}
            </div>
          </div>

          {/* Tab Content */}
          <div className="p-4">
            {activeTab === 'subdomains' && renderSubdomains()}
            {activeTab === 'urls' && renderUrls()}
            {activeTab === 'github' && renderGitHub()}
            {activeTab === 'certificates' && renderCertificates()}
            {activeTab === 'sensitive' && renderSensitive()}
          </div>
        </div>
      )}
    </div>
  );
};

export default PassiveReconPanel;
