import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Globe,
  Search,
  RefreshCw,
  Play,
  Trash2,
  ChevronRight,
  Server,
  Shield,
  MapPin,
  Network,
  ExternalLink,
  Clock,
  CheckCircle,
  XCircle,
  AlertTriangle,
  Database,
  Layers,
  FileSearch,
} from 'lucide-react';
import { toast } from 'react-toastify';
import Button from '../components/ui/Button';
import { Layout } from '../components/layout/Layout';
import api from '../services/api';

interface DiscoveredAsset {
  id: string;
  hostname: string;
  ip_addresses: string[];
  sources: string[];
  ports: { port: number; protocol: string; service?: string }[];
  technologies: { name: string; version?: string; category: string }[];
  asn?: string;
  asn_org?: string;
  country?: string;
  city?: string;
  first_seen: string;
  last_seen: string;
  tags: string[];
}

interface DiscoveryStatistics {
  total_assets: number;
  unique_hostnames: number;
  unique_ips: number;
  subdomains_from_ct: number;
  subdomains_from_dns: number;
  subdomains_from_shodan: number;
  open_ports_found: number;
  technologies_identified: number;
}

interface DiscoveryScan {
  id: string;
  domain: string;
  status: string;
  assets_count: number;
  created_at: string;
  completed_at?: string;
}

interface DiscoveryScanDetail {
  id: string;
  domain: string;
  status: string;
  assets: DiscoveredAsset[];
  whois?: {
    registrar?: string;
    creation_date?: string;
    expiration_date?: string;
    nameservers: string[];
  };
  statistics: DiscoveryStatistics;
  errors: string[];
  started_at: string;
  completed_at?: string;
}

const discoveryAPI = {
  startDiscovery: (data: {
    domain: string;
    include_ct_logs?: boolean;
    include_dns?: boolean;
    include_whois?: boolean;
    include_shodan?: boolean;
    shodan_api_key?: string;
    active_enum?: boolean;
  }) => api.post('/discovery', data),
  listScans: () => api.get<{ scans: DiscoveryScan[]; total: number }>('/discovery/scans'),
  getScan: (id: string) => api.get<DiscoveryScanDetail>(`/discovery/scans/${id}`),
  deleteScan: (id: string) => api.delete(`/discovery/scans/${id}`),
  cancelScan: (id: string) => api.post(`/discovery/scans/${id}/cancel`),
};

const getStatusIcon = (status: string) => {
  switch (status.toLowerCase()) {
    case 'completed':
      return <CheckCircle className="w-4 h-4 text-green-400" />;
    case 'failed':
      return <XCircle className="w-4 h-4 text-red-400" />;
    case 'running':
      return <RefreshCw className="w-4 h-4 text-cyan-400 animate-spin" />;
    case 'cancelled':
      return <XCircle className="w-4 h-4 text-yellow-400" />;
    default:
      return <Clock className="w-4 h-4 text-slate-400" />;
  }
};

const getSourceColor = (source: string) => {
  const colors: Record<string, string> = {
    CertificateTransparency: 'bg-purple-500/20 text-purple-400 border-purple-500/30',
    DnsEnumeration: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
    Shodan: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
    Censys: 'bg-green-500/20 text-green-400 border-green-500/30',
    Whois: 'bg-cyan-500/20 text-cyan-400 border-cyan-500/30',
  };
  return colors[source] || 'bg-slate-500/20 text-slate-400 border-slate-500/30';
};

// Discovery Form Component
function DiscoveryForm({ onSuccess }: { onSuccess: () => void }) {
  const [domain, setDomain] = useState('');
  const [includeCT, setIncludeCT] = useState(true);
  const [includeDNS, setIncludeDNS] = useState(true);
  const [includeWhois, setIncludeWhois] = useState(true);
  const [includeShodan, setIncludeShodan] = useState(false);
  const [shodanApiKey, setShodanApiKey] = useState('');
  const [activeEnum, setActiveEnum] = useState(false);

  const startMutation = useMutation({
    mutationFn: discoveryAPI.startDiscovery,
    onSuccess: () => {
      toast.success('Discovery scan started');
      setDomain('');
      onSuccess();
    },
    onError: (err: any) => {
      toast.error(err.response?.data?.error || 'Failed to start discovery');
    },
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!domain) {
      toast.error('Please enter a domain');
      return;
    }
    startMutation.mutate({
      domain,
      include_ct_logs: includeCT,
      include_dns: includeDNS,
      include_whois: includeWhois,
      include_shodan: includeShodan,
      shodan_api_key: includeShodan ? shodanApiKey : undefined,
      active_enum: activeEnum,
    });
  };

  return (
    <div className="bg-slate-800 rounded-lg border border-slate-700 p-6">
      <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
        <Globe className="w-5 h-5 text-cyan-400" />
        Start Asset Discovery
      </h3>
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label className="block text-sm font-medium text-slate-300 mb-2">
            Target Domain
          </label>
          <input
            type="text"
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            placeholder="example.com"
            className="w-full bg-slate-700 border border-slate-600 rounded-lg px-4 py-2 text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-cyan-500"
          />
        </div>

        <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
          <label className="flex items-center gap-2 cursor-pointer bg-slate-700/50 rounded-lg px-3 py-2">
            <input
              type="checkbox"
              checked={includeCT}
              onChange={(e) => setIncludeCT(e.target.checked)}
              className="rounded bg-slate-700 border-slate-600 text-cyan-500"
            />
            <span className="text-sm text-slate-300">CT Logs</span>
          </label>
          <label className="flex items-center gap-2 cursor-pointer bg-slate-700/50 rounded-lg px-3 py-2">
            <input
              type="checkbox"
              checked={includeDNS}
              onChange={(e) => setIncludeDNS(e.target.checked)}
              className="rounded bg-slate-700 border-slate-600 text-cyan-500"
            />
            <span className="text-sm text-slate-300">DNS Enum</span>
          </label>
          <label className="flex items-center gap-2 cursor-pointer bg-slate-700/50 rounded-lg px-3 py-2">
            <input
              type="checkbox"
              checked={includeWhois}
              onChange={(e) => setIncludeWhois(e.target.checked)}
              className="rounded bg-slate-700 border-slate-600 text-cyan-500"
            />
            <span className="text-sm text-slate-300">WHOIS</span>
          </label>
          <label className="flex items-center gap-2 cursor-pointer bg-slate-700/50 rounded-lg px-3 py-2">
            <input
              type="checkbox"
              checked={includeShodan}
              onChange={(e) => setIncludeShodan(e.target.checked)}
              className="rounded bg-slate-700 border-slate-600 text-cyan-500"
            />
            <span className="text-sm text-slate-300">Shodan</span>
          </label>
          <label className="flex items-center gap-2 cursor-pointer bg-slate-700/50 rounded-lg px-3 py-2">
            <input
              type="checkbox"
              checked={activeEnum}
              onChange={(e) => setActiveEnum(e.target.checked)}
              className="rounded bg-slate-700 border-slate-600 text-cyan-500"
            />
            <span className="text-sm text-slate-300">Active Enum</span>
          </label>
        </div>

        {includeShodan && (
          <div>
            <label className="block text-sm font-medium text-slate-300 mb-2">
              Shodan API Key
            </label>
            <input
              type="password"
              value={shodanApiKey}
              onChange={(e) => setShodanApiKey(e.target.value)}
              placeholder="Enter your Shodan API key"
              className="w-full bg-slate-700 border border-slate-600 rounded-lg px-4 py-2 text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-cyan-500"
            />
          </div>
        )}

        <Button type="submit" disabled={startMutation.isPending || !domain}>
          {startMutation.isPending ? (
            <RefreshCw className="w-4 h-4 animate-spin mr-2" />
          ) : (
            <Play className="w-4 h-4 mr-2" />
          )}
          Start Discovery
        </Button>
      </form>
    </div>
  );
}

// Scan Detail Component
function ScanDetail({ scanId, onClose }: { scanId: string; onClose: () => void }) {
  const { data: scan, isLoading } = useQuery({
    queryKey: ['discovery-scan', scanId],
    queryFn: async () => {
      const response = await discoveryAPI.getScan(scanId);
      return response.data;
    },
    refetchInterval: (query) => {
      const data = query.state.data;
      return data?.status === 'running' ? 3000 : false;
    },
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <RefreshCw className="w-8 h-8 text-cyan-400 animate-spin" />
      </div>
    );
  }

  if (!scan) {
    return <div className="text-slate-400">Scan not found</div>;
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-xl font-semibold text-white flex items-center gap-2">
            {getStatusIcon(scan.status)}
            {scan.domain}
          </h3>
          <p className="text-sm text-slate-400 mt-1">
            Started {new Date(scan.started_at).toLocaleString()}
            {scan.completed_at && ` | Completed ${new Date(scan.completed_at).toLocaleString()}`}
          </p>
        </div>
        <Button variant="secondary" size="sm" onClick={onClose}>
          Back to List
        </Button>
      </div>

      {/* Statistics */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="bg-slate-800 rounded-lg p-4 border border-slate-700">
          <div className="flex items-center gap-2 text-slate-400 text-sm">
            <Server className="w-4 h-4" />
            Total Assets
          </div>
          <div className="text-2xl font-bold text-white mt-1">{scan.statistics.total_assets}</div>
        </div>
        <div className="bg-slate-800 rounded-lg p-4 border border-slate-700">
          <div className="flex items-center gap-2 text-slate-400 text-sm">
            <Network className="w-4 h-4" />
            Unique IPs
          </div>
          <div className="text-2xl font-bold text-white mt-1">{scan.statistics.unique_ips}</div>
        </div>
        <div className="bg-slate-800 rounded-lg p-4 border border-slate-700">
          <div className="flex items-center gap-2 text-slate-400 text-sm">
            <Shield className="w-4 h-4" />
            From CT Logs
          </div>
          <div className="text-2xl font-bold text-white mt-1">{scan.statistics.subdomains_from_ct}</div>
        </div>
        <div className="bg-slate-800 rounded-lg p-4 border border-slate-700">
          <div className="flex items-center gap-2 text-slate-400 text-sm">
            <Layers className="w-4 h-4" />
            Technologies
          </div>
          <div className="text-2xl font-bold text-white mt-1">{scan.statistics.technologies_identified}</div>
        </div>
      </div>

      {/* WHOIS Info */}
      {scan.whois && (
        <div className="bg-slate-800 rounded-lg border border-slate-700 p-4">
          <h4 className="text-lg font-semibold text-white mb-3 flex items-center gap-2">
            <Database className="w-5 h-5 text-cyan-400" />
            WHOIS Information
          </h4>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
            <div>
              <span className="text-slate-400">Registrar</span>
              <p className="text-white">{scan.whois.registrar || 'N/A'}</p>
            </div>
            <div>
              <span className="text-slate-400">Created</span>
              <p className="text-white">{scan.whois.creation_date || 'N/A'}</p>
            </div>
            <div>
              <span className="text-slate-400">Expires</span>
              <p className="text-white">{scan.whois.expiration_date || 'N/A'}</p>
            </div>
            <div>
              <span className="text-slate-400">Nameservers</span>
              <p className="text-white">{scan.whois.nameservers?.join(', ') || 'N/A'}</p>
            </div>
          </div>
        </div>
      )}

      {/* Errors */}
      {scan.errors.length > 0 && (
        <div className="bg-red-900/20 rounded-lg border border-red-800/50 p-4">
          <h4 className="text-lg font-semibold text-red-400 mb-2 flex items-center gap-2">
            <AlertTriangle className="w-5 h-5" />
            Errors ({scan.errors.length})
          </h4>
          <ul className="text-sm text-red-300 space-y-1">
            {scan.errors.map((err, i) => (
              <li key={i}>{err}</li>
            ))}
          </ul>
        </div>
      )}

      {/* Assets List */}
      <div className="bg-slate-800 rounded-lg border border-slate-700">
        <div className="p-4 border-b border-slate-700">
          <h4 className="text-lg font-semibold text-white flex items-center gap-2">
            <FileSearch className="w-5 h-5 text-cyan-400" />
            Discovered Assets ({scan.assets.length})
          </h4>
        </div>
        <div className="divide-y divide-slate-700 max-h-96 overflow-y-auto">
          {scan.assets.map((asset) => (
            <div key={asset.id} className="p-4 hover:bg-slate-700/50 transition-colors">
              <div className="flex items-start justify-between">
                <div className="flex-1">
                  <div className="flex items-center gap-2">
                    <Globe className="w-4 h-4 text-cyan-400" />
                    <span className="text-white font-medium">{asset.hostname}</span>
                    {asset.country && (
                      <span className="text-xs text-slate-400 flex items-center gap-1">
                        <MapPin className="w-3 h-3" />
                        {asset.city ? `${asset.city}, ${asset.country}` : asset.country}
                      </span>
                    )}
                  </div>
                  <div className="flex flex-wrap gap-1 mt-2">
                    {asset.sources.map((source, i) => (
                      <span
                        key={i}
                        className={`px-2 py-0.5 rounded text-xs border ${getSourceColor(source)}`}
                      >
                        {source}
                      </span>
                    ))}
                  </div>
                  {asset.ip_addresses.length > 0 && (
                    <div className="text-xs text-slate-400 mt-2">
                      IPs: {asset.ip_addresses.join(', ')}
                    </div>
                  )}
                  {asset.ports.length > 0 && (
                    <div className="text-xs text-slate-400 mt-1">
                      Ports: {asset.ports.map(p => `${p.port}/${p.protocol}`).join(', ')}
                    </div>
                  )}
                </div>
                <a
                  href={`https://${asset.hostname}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="p-2 hover:bg-slate-600 rounded-lg"
                >
                  <ExternalLink className="w-4 h-4 text-slate-400" />
                </a>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// Main Page Component
export default function AssetDiscoveryPage() {
  const queryClient = useQueryClient();
  const [selectedScanId, setSelectedScanId] = useState<string | null>(null);

  const { data: scansData, isLoading, refetch } = useQuery({
    queryKey: ['discovery-scans'],
    queryFn: async () => {
      const response = await discoveryAPI.listScans();
      return response.data;
    },
    refetchInterval: 10000,
  });

  const deleteMutation = useMutation({
    mutationFn: discoveryAPI.deleteScan,
    onSuccess: () => {
      toast.success('Scan deleted');
      queryClient.invalidateQueries({ queryKey: ['discovery-scans'] });
    },
    onError: () => toast.error('Failed to delete scan'),
  });

  const scans = scansData?.scans || [];

  return (
    <Layout>
      {/* Header */}
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-slate-900 dark:text-white flex items-center gap-2">
          <Globe className="w-7 h-7 text-cyan-400" />
          Asset Discovery
        </h1>
        <p className="text-slate-600 dark:text-slate-400 mt-1">
          Discover assets using Certificate Transparency logs, DNS enumeration, WHOIS, and Shodan
        </p>
      </div>

      {selectedScanId ? (
        <ScanDetail scanId={selectedScanId} onClose={() => setSelectedScanId(null)} />
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Left: Discovery Form */}
          <div className="lg:col-span-1">
            <DiscoveryForm
              onSuccess={() => {
                queryClient.invalidateQueries({ queryKey: ['discovery-scans'] });
              }}
            />
          </div>

          {/* Right: Scans List */}
          <div className="lg:col-span-2">
            <div className="bg-slate-800 rounded-lg border border-slate-700">
              <div className="p-4 border-b border-slate-700 flex items-center justify-between">
                <h3 className="text-lg font-semibold text-white flex items-center gap-2">
                  <Search className="w-5 h-5 text-cyan-400" />
                  Discovery Scans
                </h3>
                <Button variant="secondary" size="sm" onClick={() => refetch()}>
                  <RefreshCw className="w-4 h-4" />
                </Button>
              </div>

              <div className="divide-y divide-slate-700">
                {isLoading ? (
                  <div className="p-8 text-center">
                    <RefreshCw className="w-8 h-8 text-cyan-400 animate-spin mx-auto" />
                  </div>
                ) : scans.length === 0 ? (
                  <div className="p-8 text-center text-slate-400">
                    <Globe className="w-12 h-12 mx-auto mb-3 text-slate-600" />
                    <p>No discovery scans yet</p>
                    <p className="text-sm mt-1">Start a discovery scan to find assets</p>
                  </div>
                ) : (
                  scans.map((scan) => (
                    <div
                      key={scan.id}
                      className="p-4 hover:bg-slate-700/50 transition-colors cursor-pointer"
                      onClick={() => setSelectedScanId(scan.id)}
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex-1">
                          <div className="flex items-center gap-2">
                            {getStatusIcon(scan.status)}
                            <span className="text-white font-medium">{scan.domain}</span>
                            <span className="text-xs px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-400">
                              {scan.assets_count} assets
                            </span>
                          </div>
                          <div className="text-sm text-slate-400 mt-1">
                            {new Date(scan.created_at).toLocaleString()}
                          </div>
                        </div>
                        <div className="flex items-center gap-2">
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              if (confirm('Delete this scan?')) {
                                deleteMutation.mutate(scan.id);
                              }
                            }}
                            className="p-2 hover:bg-slate-600 rounded-lg"
                          >
                            <Trash2 className="w-4 h-4 text-slate-400 hover:text-red-400" />
                          </button>
                          <ChevronRight className="w-5 h-5 text-slate-400" />
                        </div>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </Layout>
  );
}
