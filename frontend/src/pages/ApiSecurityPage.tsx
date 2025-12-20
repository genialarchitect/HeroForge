import React, { useState, useEffect } from 'react';
import { toast } from 'react-toastify';
import Layout from '../components/layout/Layout';
import Card from '../components/ui/Card';
import Button from '../components/ui/Button';
import Input from '../components/ui/Input';
import Badge from '../components/ui/Badge';
import Checkbox from '../components/ui/Checkbox';
import LoadingSpinner from '../components/ui/LoadingSpinner';
import { Shield, Search, AlertTriangle, Globe, Lock, Zap, RefreshCw, Trash2, ChevronRight } from 'lucide-react';
import { apiSecurityAPI } from '../services/api';
import type { BadgeSeverityType } from '../types';

interface ApiScan {
  id: string;
  name: string;
  target_url: string;
  status: string;
  endpoints_discovered: number;
  endpoints_tested: number;
  findings_count: number;
  created_at: string;
  completed_at: string | null;
}

interface ApiEndpoint {
  id: string;
  path: string;
  method: string;
  summary: string | null;
  auth_required: number;
  tested: number;
}

interface ApiFinding {
  id: string;
  finding_type: string;
  severity: string;
  title: string;
  description: string | null;
  endpoint_id: string | null;
  remediation: string | null;
  owasp_category: string | null;
  cwe_ids: string | null;
}

interface DiscoveredEndpoint {
  path: string;
  method: string;
  summary: string | null;
  auth_required: boolean;
  parameters_count: number;
}

const ApiSecurityPage: React.FC = () => {
  const [scans, setScans] = useState<ApiScan[]>([]);
  const [selectedScan, setSelectedScan] = useState<ApiScan | null>(null);
  const [endpoints, setEndpoints] = useState<ApiEndpoint[]>([]);
  const [findings, setFindings] = useState<ApiFinding[]>([]);
  const [discoveredEndpoints, setDiscoveredEndpoints] = useState<DiscoveredEndpoint[]>([]);
  const [loading, setLoading] = useState(false);
  const [scanLoading, setScanLoading] = useState(false);
  const [discoverLoading, setDiscoverLoading] = useState(false);
  const [activeTab, setActiveTab] = useState<'scans' | 'new' | 'discover'>('scans');

  // Form state
  const [targetUrl, setTargetUrl] = useState('');
  const [scanName, setScanName] = useState('');
  const [specType, setSpecType] = useState<string>('');
  const [specContent, setSpecContent] = useState('');
  const [authType, setAuthType] = useState<string>('none');
  const [authToken, setAuthToken] = useState('');
  const [scanOptions, setScanOptions] = useState({
    test_auth_bypass: true,
    test_injection: true,
    test_rate_limit: true,
    test_cors: true,
    test_bola: true,
    test_bfla: false,
    discover_endpoints: true,
  });

  useEffect(() => {
    loadScans();
  }, []);

  useEffect(() => {
    if (selectedScan) {
      loadScanDetails(selectedScan.id);
    }
  }, [selectedScan]);

  const loadScans = async () => {
    setLoading(true);
    try {
      const response = await apiSecurityAPI.listScans();
      setScans(response.data);
    } catch (error) {
      toast.error('Failed to load scans');
    } finally {
      setLoading(false);
    }
  };

  const loadScanDetails = async (scanId: string) => {
    try {
      const [endpointsRes, findingsRes] = await Promise.all([
        apiSecurityAPI.getEndpoints(scanId),
        apiSecurityAPI.getFindings(scanId),
      ]);
      setEndpoints(endpointsRes.data);
      setFindings(findingsRes.data);
    } catch (error) {
      toast.error('Failed to load scan details');
    }
  };

  const handleStartScan = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!targetUrl.trim()) {
      toast.error('Please enter a target URL');
      return;
    }

    if (!scanName.trim()) {
      toast.error('Please enter a scan name');
      return;
    }

    try {
      new URL(targetUrl);
    } catch {
      toast.error('Please enter a valid URL');
      return;
    }

    setScanLoading(true);
    try {
      const authConfig = authType !== 'none' ? {
        auth_type: authType,
        credentials: authType === 'bearer' ? { token: authToken } : {} as Record<string, string>,
      } : undefined;

      await apiSecurityAPI.startScan({
        name: scanName.trim(),
        target_url: targetUrl.trim(),
        spec_type: specType || undefined,
        spec_content: specContent || undefined,
        auth_config: authConfig,
        scan_options: scanOptions,
      });

      toast.success('API security scan started');
      setTargetUrl('');
      setScanName('');
      setSpecContent('');
      setActiveTab('scans');
      loadScans();
    } catch (error: unknown) {
      const axiosError = error as { response?: { data?: { error?: string } } };
      toast.error(axiosError.response?.data?.error || 'Failed to start scan');
    } finally {
      setScanLoading(false);
    }
  };

  const handleDiscover = async () => {
    if (!targetUrl.trim()) {
      toast.error('Please enter a target URL');
      return;
    }

    setDiscoverLoading(true);
    try {
      const response = await apiSecurityAPI.discoverEndpoints({
        target_url: targetUrl.trim(),
        spec_type: specType || undefined,
        spec_content: specContent || undefined,
      });
      setDiscoveredEndpoints(response.data.endpoints);
      if (response.data.endpoints.length === 0) {
        toast.info('No endpoints discovered');
      } else {
        toast.success(`Discovered ${response.data.endpoints.length} endpoints`);
      }
    } catch (error: unknown) {
      const axiosError = error as { response?: { data?: { error?: string } } };
      toast.error(axiosError.response?.data?.error || 'Failed to discover endpoints');
    } finally {
      setDiscoverLoading(false);
    }
  };

  const handleDeleteScan = async (scanId: string) => {
    if (!confirm('Are you sure you want to delete this scan?')) return;

    try {
      await apiSecurityAPI.deleteScan(scanId);
      toast.success('Scan deleted');
      if (selectedScan?.id === scanId) {
        setSelectedScan(null);
        setEndpoints([]);
        setFindings([]);
      }
      loadScans();
    } catch (error) {
      toast.error('Failed to delete scan');
    }
  };

  const getSeverityBadge = (severity: string): BadgeSeverityType => {
    switch (severity.toLowerCase()) {
      case 'critical': return 'critical';
      case 'high': return 'high';
      case 'medium': return 'medium';
      default: return 'low';
    }
  };

  const getMethodColor = (method: string) => {
    switch (method.toUpperCase()) {
      case 'GET': return 'bg-green-500/20 text-green-400';
      case 'POST': return 'bg-blue-500/20 text-blue-400';
      case 'PUT': return 'bg-yellow-500/20 text-yellow-400';
      case 'DELETE': return 'bg-red-500/20 text-red-400';
      case 'PATCH': return 'bg-purple-500/20 text-purple-400';
      default: return 'bg-gray-500/20 text-gray-400';
    }
  };

  return (
    <Layout>
      <div className="space-y-6">
        <div>
          <div className="flex items-center gap-3 mb-2">
            <Shield className="w-8 h-8 text-cyan-500" />
            <h1 className="text-3xl font-bold text-white">API Security Scanner</h1>
          </div>
          <p className="text-gray-400">
            Test APIs for security vulnerabilities including authentication bypass, injection, and CORS issues
          </p>
        </div>

        {/* Tabs */}
        <div className="flex gap-2 border-b border-gray-700 pb-2">
          <button
            onClick={() => setActiveTab('scans')}
            className={`px-4 py-2 rounded-t-lg transition-colors ${
              activeTab === 'scans'
                ? 'bg-gray-800 text-cyan-400 border-b-2 border-cyan-400'
                : 'text-gray-400 hover:text-white'
            }`}
          >
            Scan History
          </button>
          <button
            onClick={() => setActiveTab('new')}
            className={`px-4 py-2 rounded-t-lg transition-colors ${
              activeTab === 'new'
                ? 'bg-gray-800 text-cyan-400 border-b-2 border-cyan-400'
                : 'text-gray-400 hover:text-white'
            }`}
          >
            New Scan
          </button>
          <button
            onClick={() => setActiveTab('discover')}
            className={`px-4 py-2 rounded-t-lg transition-colors ${
              activeTab === 'discover'
                ? 'bg-gray-800 text-cyan-400 border-b-2 border-cyan-400'
                : 'text-gray-400 hover:text-white'
            }`}
          >
            Discover Endpoints
          </button>
        </div>

        {/* Scans List Tab */}
        {activeTab === 'scans' && (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Scans List */}
            <div className="lg:col-span-1">
              <Card>
                <div className="p-4">
                  <div className="flex items-center justify-between mb-4">
                    <h2 className="text-lg font-semibold text-white">Scans</h2>
                    <Button variant="ghost" size="sm" onClick={loadScans}>
                      <RefreshCw className="w-4 h-4" />
                    </Button>
                  </div>

                  {loading ? (
                    <div className="flex justify-center py-8">
                      <LoadingSpinner />
                    </div>
                  ) : scans.length === 0 ? (
                    <p className="text-gray-400 text-center py-8">No scans yet</p>
                  ) : (
                    <div className="space-y-2">
                      {scans.map((scan) => (
                        <div
                          key={scan.id}
                          onClick={() => setSelectedScan(scan)}
                          className={`p-3 rounded-lg cursor-pointer transition-colors ${
                            selectedScan?.id === scan.id
                              ? 'bg-cyan-500/20 border border-cyan-500/50'
                              : 'bg-gray-800 hover:bg-gray-700'
                          }`}
                        >
                          <div className="flex items-center justify-between">
                            <span className="font-medium text-white truncate">{scan.name}</span>
                            <Badge type={scan.status === 'completed' ? 'completed' : scan.status === 'failed' ? 'failed' : 'running'}>
                              {scan.status}
                            </Badge>
                          </div>
                          <p className="text-sm text-gray-400 truncate mt-1">{scan.target_url}</p>
                          <div className="flex items-center gap-4 mt-2 text-xs text-gray-500">
                            <span>{scan.endpoints_discovered} endpoints</span>
                            <span>{scan.findings_count} findings</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </Card>
            </div>

            {/* Scan Details */}
            <div className="lg:col-span-2">
              {selectedScan ? (
                <div className="space-y-4">
                  {/* Scan Info */}
                  <Card>
                    <div className="p-4">
                      <div className="flex items-center justify-between mb-4">
                        <div>
                          <h2 className="text-lg font-semibold text-white">{selectedScan.name}</h2>
                          <p className="text-sm text-gray-400">{selectedScan.target_url}</p>
                        </div>
                        <Button
                          variant="danger"
                          size="sm"
                          onClick={() => handleDeleteScan(selectedScan.id)}
                        >
                          <Trash2 className="w-4 h-4" />
                        </Button>
                      </div>
                      <div className="grid grid-cols-3 gap-4">
                        <div className="bg-gray-800 rounded-lg p-3 text-center">
                          <p className="text-2xl font-bold text-white">{selectedScan.endpoints_discovered}</p>
                          <p className="text-sm text-gray-400">Endpoints</p>
                        </div>
                        <div className="bg-gray-800 rounded-lg p-3 text-center">
                          <p className="text-2xl font-bold text-white">{selectedScan.endpoints_tested}</p>
                          <p className="text-sm text-gray-400">Tested</p>
                        </div>
                        <div className="bg-gray-800 rounded-lg p-3 text-center">
                          <p className="text-2xl font-bold text-cyan-400">{selectedScan.findings_count}</p>
                          <p className="text-sm text-gray-400">Findings</p>
                        </div>
                      </div>
                    </div>
                  </Card>

                  {/* Findings */}
                  <Card>
                    <div className="p-4">
                      <h3 className="text-lg font-semibold text-white mb-4">Security Findings</h3>
                      {findings.length === 0 ? (
                        <p className="text-gray-400 text-center py-4">No findings</p>
                      ) : (
                        <div className="space-y-3">
                          {findings.map((finding) => (
                            <div key={finding.id} className="bg-gray-800 rounded-lg p-4">
                              <div className="flex items-start justify-between">
                                <div className="flex-1">
                                  <div className="flex items-center gap-2 mb-2">
                                    <Badge type={getSeverityBadge(finding.severity)}>
                                      {finding.severity}
                                    </Badge>
                                    <span className="text-sm text-gray-500">{finding.finding_type}</span>
                                  </div>
                                  <h4 className="font-medium text-white">{finding.title}</h4>
                                  {finding.description && (
                                    <p className="text-sm text-gray-400 mt-1">{finding.description}</p>
                                  )}
                                  {finding.owasp_category && (
                                    <p className="text-xs text-cyan-400 mt-2">{finding.owasp_category}</p>
                                  )}
                                </div>
                                <ChevronRight className="w-5 h-5 text-gray-500" />
                              </div>
                              {finding.remediation && (
                                <div className="mt-3 pt-3 border-t border-gray-700">
                                  <p className="text-sm text-gray-400">
                                    <span className="text-cyan-400">Remediation:</span> {finding.remediation}
                                  </p>
                                </div>
                              )}
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  </Card>

                  {/* Endpoints */}
                  <Card>
                    <div className="p-4">
                      <h3 className="text-lg font-semibold text-white mb-4">Discovered Endpoints</h3>
                      {endpoints.length === 0 ? (
                        <p className="text-gray-400 text-center py-4">No endpoints discovered</p>
                      ) : (
                        <div className="space-y-2">
                          {endpoints.map((endpoint) => (
                            <div key={endpoint.id} className="flex items-center gap-3 p-2 bg-gray-800 rounded">
                              <span className={`px-2 py-1 rounded text-xs font-mono ${getMethodColor(endpoint.method)}`}>
                                {endpoint.method}
                              </span>
                              <span className="text-white font-mono text-sm flex-1">{endpoint.path}</span>
                              {endpoint.auth_required === 1 && (
                                <Lock className="w-4 h-4 text-yellow-500" />
                              )}
                              {endpoint.tested === 1 && (
                                <span className="text-xs text-green-400">Tested</span>
                              )}
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  </Card>
                </div>
              ) : (
                <Card>
                  <div className="p-8 text-center">
                    <Shield className="w-16 h-16 text-gray-600 mx-auto mb-4" />
                    <p className="text-gray-400">Select a scan to view details</p>
                  </div>
                </Card>
              )}
            </div>
          </div>
        )}

        {/* New Scan Tab */}
        {activeTab === 'new' && (
          <Card>
            <div className="p-6">
              <div className="flex items-center gap-3 mb-6">
                <Zap className="w-6 h-6 text-cyan-500" />
                <div>
                  <h2 className="text-xl font-bold text-white">Start API Security Scan</h2>
                  <p className="text-sm text-gray-400">
                    Scan an API for security vulnerabilities
                  </p>
                </div>
              </div>

              <div className="mb-4 p-4 bg-yellow-900/20 border border-yellow-600/50 rounded-lg flex items-start gap-3">
                <AlertTriangle className="w-5 h-5 text-yellow-500 flex-shrink-0 mt-0.5" />
                <div className="text-sm text-yellow-200">
                  <strong>Security Notice:</strong> Only scan APIs you own or have explicit permission to test.
                  Unauthorized scanning may be illegal.
                </div>
              </div>

              <form onSubmit={handleStartScan} className="space-y-6">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-300 mb-1">
                      Scan Name *
                    </label>
                    <Input
                      value={scanName}
                      onChange={(e) => setScanName(e.target.value)}
                      placeholder="My API Scan"
                      disabled={scanLoading}
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-300 mb-1">
                      Target URL *
                    </label>
                    <Input
                      value={targetUrl}
                      onChange={(e) => setTargetUrl(e.target.value)}
                      placeholder="https://api.example.com"
                      disabled={scanLoading}
                    />
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-300 mb-1">
                      API Specification Type
                    </label>
                    <select
                      value={specType}
                      onChange={(e) => setSpecType(e.target.value)}
                      className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
                      disabled={scanLoading}
                    >
                      <option value="">Auto-detect</option>
                      <option value="openapi3">OpenAPI 3.x</option>
                      <option value="swagger2">Swagger 2.0</option>
                      <option value="postman">Postman Collection</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-300 mb-1">
                      Authentication Type
                    </label>
                    <select
                      value={authType}
                      onChange={(e) => setAuthType(e.target.value)}
                      className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
                      disabled={scanLoading}
                    >
                      <option value="none">None</option>
                      <option value="bearer">Bearer Token</option>
                      <option value="basic">Basic Auth</option>
                      <option value="api_key">API Key</option>
                    </select>
                  </div>
                </div>

                {authType === 'bearer' && (
                  <div>
                    <label className="block text-sm font-medium text-gray-300 mb-1">
                      Bearer Token
                    </label>
                    <Input
                      type="password"
                      value={authToken}
                      onChange={(e) => setAuthToken(e.target.value)}
                      placeholder="Enter your JWT or Bearer token"
                      disabled={scanLoading}
                    />
                  </div>
                )}

                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-1">
                    API Specification (JSON/YAML)
                  </label>
                  <textarea
                    value={specContent}
                    onChange={(e) => setSpecContent(e.target.value)}
                    placeholder="Paste OpenAPI/Swagger spec here (optional)"
                    className="w-full h-32 bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-white focus:outline-none focus:ring-2 focus:ring-cyan-500 font-mono text-sm"
                    disabled={scanLoading}
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-3">
                    Security Tests
                  </label>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    <Checkbox
                      id="test_auth"
                      checked={scanOptions.test_auth_bypass}
                      onChange={(checked) => setScanOptions({ ...scanOptions, test_auth_bypass: checked })}
                      label="Authentication Bypass"
                      disabled={scanLoading}
                    />
                    <Checkbox
                      id="test_injection"
                      checked={scanOptions.test_injection}
                      onChange={(checked) => setScanOptions({ ...scanOptions, test_injection: checked })}
                      label="Injection Testing (SQLi, Command)"
                      disabled={scanLoading}
                    />
                    <Checkbox
                      id="test_rate"
                      checked={scanOptions.test_rate_limit}
                      onChange={(checked) => setScanOptions({ ...scanOptions, test_rate_limit: checked })}
                      label="Rate Limit Testing"
                      disabled={scanLoading}
                    />
                    <Checkbox
                      id="test_cors"
                      checked={scanOptions.test_cors}
                      onChange={(checked) => setScanOptions({ ...scanOptions, test_cors: checked })}
                      label="CORS Misconfiguration"
                      disabled={scanLoading}
                    />
                    <Checkbox
                      id="test_bola"
                      checked={scanOptions.test_bola}
                      onChange={(checked) => setScanOptions({ ...scanOptions, test_bola: checked })}
                      label="Broken Object Level Auth (BOLA)"
                      disabled={scanLoading}
                    />
                    <Checkbox
                      id="discover"
                      checked={scanOptions.discover_endpoints}
                      onChange={(checked) => setScanOptions({ ...scanOptions, discover_endpoints: checked })}
                      label="Discover Endpoints"
                      disabled={scanLoading}
                    />
                  </div>
                </div>

                <div className="flex gap-3 pt-4">
                  <Button type="submit" disabled={scanLoading}>
                    {scanLoading ? (
                      <>
                        <LoadingSpinner size="sm" />
                        Starting Scan...
                      </>
                    ) : (
                      <>
                        <Shield className="w-4 h-4" />
                        Start API Security Scan
                      </>
                    )}
                  </Button>
                </div>
              </form>
            </div>
          </Card>
        )}

        {/* Discover Endpoints Tab */}
        {activeTab === 'discover' && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card>
              <div className="p-6">
                <div className="flex items-center gap-3 mb-6">
                  <Search className="w-6 h-6 text-cyan-500" />
                  <div>
                    <h2 className="text-xl font-bold text-white">Discover API Endpoints</h2>
                    <p className="text-sm text-gray-400">
                      Find API endpoints from a URL or specification
                    </p>
                  </div>
                </div>

                <div className="space-y-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-300 mb-1">
                      Target URL *
                    </label>
                    <Input
                      value={targetUrl}
                      onChange={(e) => setTargetUrl(e.target.value)}
                      placeholder="https://api.example.com"
                      disabled={discoverLoading}
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-300 mb-1">
                      Specification Type
                    </label>
                    <select
                      value={specType}
                      onChange={(e) => setSpecType(e.target.value)}
                      className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
                      disabled={discoverLoading}
                    >
                      <option value="">Auto-detect</option>
                      <option value="openapi3">OpenAPI 3.x</option>
                      <option value="swagger2">Swagger 2.0</option>
                      <option value="postman">Postman Collection</option>
                    </select>
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-300 mb-1">
                      API Specification (optional)
                    </label>
                    <textarea
                      value={specContent}
                      onChange={(e) => setSpecContent(e.target.value)}
                      placeholder="Paste OpenAPI/Swagger spec here"
                      className="w-full h-32 bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-white focus:outline-none focus:ring-2 focus:ring-cyan-500 font-mono text-sm"
                      disabled={discoverLoading}
                    />
                  </div>

                  <Button onClick={handleDiscover} disabled={discoverLoading}>
                    {discoverLoading ? (
                      <>
                        <LoadingSpinner size="sm" />
                        Discovering...
                      </>
                    ) : (
                      <>
                        <Globe className="w-4 h-4" />
                        Discover Endpoints
                      </>
                    )}
                  </Button>
                </div>
              </div>
            </Card>

            <Card>
              <div className="p-6">
                <h3 className="text-lg font-semibold text-white mb-4">
                  Discovered Endpoints ({discoveredEndpoints.length})
                </h3>
                {discoveredEndpoints.length === 0 ? (
                  <div className="text-center py-8">
                    <Globe className="w-12 h-12 text-gray-600 mx-auto mb-3" />
                    <p className="text-gray-400">No endpoints discovered yet</p>
                    <p className="text-sm text-gray-500">Enter a URL and click Discover</p>
                  </div>
                ) : (
                  <div className="space-y-2 max-h-96 overflow-y-auto">
                    {discoveredEndpoints.map((endpoint, index) => (
                      <div key={index} className="flex items-center gap-3 p-2 bg-gray-800 rounded">
                        <span className={`px-2 py-1 rounded text-xs font-mono ${getMethodColor(endpoint.method)}`}>
                          {endpoint.method}
                        </span>
                        <div className="flex-1 min-w-0">
                          <span className="text-white font-mono text-sm block truncate">{endpoint.path}</span>
                          {endpoint.summary && (
                            <span className="text-xs text-gray-500">{endpoint.summary}</span>
                          )}
                        </div>
                        {endpoint.auth_required && (
                          <Lock className="w-4 h-4 text-yellow-500" />
                        )}
                        {endpoint.parameters_count > 0 && (
                          <span className="text-xs text-gray-500">{endpoint.parameters_count} params</span>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </Card>
          </div>
        )}
      </div>
    </Layout>
  );
};

export default ApiSecurityPage;
