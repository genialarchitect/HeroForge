import React, { useEffect, useState, useMemo } from 'react';
import { toast } from 'react-toastify';
import { useScanStore } from '../../store/scanStore';
import { scanAPI, siemAPI, scanTagAPI } from '../../services/api';
import { calculateHostRiskScore, getRiskLevel } from '../../utils/riskScoring';
import { toSeverityBadgeType, ScanTag } from '../../types';
import Card from '../ui/Card';
import Badge from '../ui/Badge';
import LoadingSpinner from '../ui/LoadingSpinner';
import VulnerabilityCard from './VulnerabilityCard';
import ServiceBanner from './ServiceBanner';
import SslInfoComponent from './SslInfo';
import ExportButton from './ExportButton';
import Input from '../ui/Input';
import { ReportGenerator, ReportList } from '../reports';
import { ComplianceAnalysis } from '../compliance';
import NetworkMap from '../topology/NetworkMap';
import { Server, Shield, AlertTriangle, Search, SlidersHorizontal, FileText, ClipboardCheck, List, Network, Database, Tag, Plus, X, Copy } from 'lucide-react';

type SortOption = 'ip' | 'risk' | 'vulns' | 'ports';
type FilterOption = 'all' | 'with-vulns' | 'critical' | 'high';
type ViewTab = 'results' | 'topology';

const ResultsViewer: React.FC = () => {
  const { activeScan, results } = useScanStore();
  const [loading, setLoading] = useState(false);
  const [expandedHost, setExpandedHost] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [sortBy, setSortBy] = useState<SortOption>('risk');
  const [filterBy, setFilterBy] = useState<FilterOption>('all');
  const [showFilters, setShowFilters] = useState(false);
  const [showReportGenerator, setShowReportGenerator] = useState(false);
  const [showComplianceAnalysis, setShowComplianceAnalysis] = useState(false);
  const [reportListKey, setReportListKey] = useState(0);
  const [activeTab, setActiveTab] = useState<ViewTab>('results');
  const [exportingToSiem, setExportingToSiem] = useState(false);
  // Tag management state
  const [scanTags, setScanTags] = useState<ScanTag[]>([]);
  const [allTags, setAllTags] = useState<ScanTag[]>([]);
  const [showTagDropdown, setShowTagDropdown] = useState(false);
  const [duplicating, setDuplicating] = useState(false);

  const scanResults = activeScan ? results.get(activeScan.id) || [] : [];

  useEffect(() => {
    if (activeScan && activeScan.status === 'completed' && scanResults.length === 0) {
      loadResults();
    }
    if (activeScan) {
      loadScanTags();
      loadAllTags();
    }
  }, [activeScan]);

  const loadScanTags = async () => {
    if (!activeScan) return;
    try {
      const response = await scanTagAPI.getTagsForScan(activeScan.id);
      setScanTags(response.data);
    } catch (error) {
      console.error('Failed to load scan tags:', error);
    }
  };

  const loadAllTags = async () => {
    try {
      const response = await scanTagAPI.getAll();
      setAllTags(response.data);
    } catch (error) {
      console.error('Failed to load all tags:', error);
    }
  };

  const handleAddTag = async (tagId: string) => {
    if (!activeScan) return;
    try {
      const response = await scanTagAPI.addTagsToScan(activeScan.id, { tag_ids: [tagId] });
      setScanTags(response.data);
      setShowTagDropdown(false);
      toast.success('Tag added');
    } catch (error) {
      toast.error('Failed to add tag');
    }
  };

  const handleRemoveTag = async (tagId: string) => {
    if (!activeScan) return;
    try {
      await scanTagAPI.removeTagFromScan(activeScan.id, tagId);
      setScanTags(scanTags.filter((t) => t.id !== tagId));
      toast.success('Tag removed');
    } catch (error) {
      toast.error('Failed to remove tag');
    }
  };

  const handleDuplicateScan = async () => {
    if (!activeScan) return;
    setDuplicating(true);
    try {
      const response = await scanAPI.duplicate(activeScan.id);
      toast.success(`Scan duplicated as "${response.data.name}"`);
      // Optionally refresh the scan list
      useScanStore.getState().setActiveScan(response.data);
    } catch (error) {
      toast.error('Failed to duplicate scan');
    } finally {
      setDuplicating(false);
    }
  };

  const availableTags = allTags.filter((t) => !scanTags.some((st) => st.id === t.id));

  const loadResults = async () => {
    if (!activeScan) return;

    setLoading(true);
    try {
      const response = await scanAPI.getResults(activeScan.id);
      useScanStore.getState().setResults(activeScan.id, response.data);
    } catch (error) {
      toast.error('Failed to load scan results');
    } finally {
      setLoading(false);
    }
  };

  const handleExportToSiem = async () => {
    if (!activeScan) return;

    setExportingToSiem(true);
    try {
      const response = await siemAPI.exportScan(activeScan.id);
      if (response.data.success) {
        toast.success(
          `Exported ${response.data.events_count} events to ${response.data.exported_to} SIEM integration(s)`
        );
      } else {
        toast.warning('Export completed with issues. Check SIEM settings.');
      }
      if (response.data.errors && response.data.errors.length > 0) {
        response.data.errors.forEach((error) => {
          toast.error(`SIEM export error: ${error}`);
        });
      }
    } catch (error: unknown) {
      const axiosError = error as { response?: { status?: number; data?: { error?: string } } };
      if (axiosError.response?.status === 404) {
        toast.error('No SIEM integrations configured. Go to Settings > SIEM Integration to set up.');
      } else {
        toast.error(axiosError.response?.data?.error || 'Failed to export to SIEM');
      }
    } finally {
      setExportingToSiem(false);
    }
  };

  // Filter and sort hosts
  const filteredAndSortedHosts = useMemo(() => {
    let filtered = [...scanResults];

    // Apply search filter
    if (searchQuery) {
      filtered = filtered.filter(
        (host) =>
          host.target.ip.includes(searchQuery) ||
          host.target.hostname?.toLowerCase().includes(searchQuery.toLowerCase())
      );
    }

    // Apply vulnerability filter
    switch (filterBy) {
      case 'with-vulns':
        filtered = filtered.filter((host) => host.vulnerabilities.length > 0);
        break;
      case 'critical':
        filtered = filtered.filter((host) =>
          host.vulnerabilities.some((v) => v.severity === 'Critical')
        );
        break;
      case 'high':
        filtered = filtered.filter((host) =>
          host.vulnerabilities.some((v) => v.severity === 'Critical' || v.severity === 'High')
        );
        break;
    }

    // Apply sorting
    filtered.sort((a, b) => {
      switch (sortBy) {
        case 'risk':
          return calculateHostRiskScore(b) - calculateHostRiskScore(a);
        case 'vulns':
          return b.vulnerabilities.length - a.vulnerabilities.length;
        case 'ports':
          return (
            b.ports.filter((p) => p.state === 'Open').length -
            a.ports.filter((p) => p.state === 'Open').length
          );
        case 'ip':
        default:
          return a.target.ip.localeCompare(b.target.ip);
      }
    });

    return filtered;
  }, [scanResults, searchQuery, sortBy, filterBy]);

  if (!activeScan) {
    return (
      <Card>
        <div className="text-center py-12 text-slate-500">
          Select a scan from the list to view results
        </div>
      </Card>
    );
  }

  if (loading) {
    return (
      <Card>
        <div className="flex items-center justify-center py-12">
          <LoadingSpinner />
        </div>
      </Card>
    );
  }

  if (scanResults.length === 0) {
    return (
      <Card>
        <div className="text-center py-12 text-slate-500">
          {activeScan.status === 'running'
            ? 'Scan in progress... Results will appear here as hosts are discovered'
            : activeScan.status === 'pending'
            ? 'Scan is pending...'
            : activeScan.status === 'failed'
            ? `Scan failed: ${activeScan.error_message || 'Unknown error'}`
            : 'No results available'}
        </div>
      </Card>
    );
  }

  const aliveHosts = scanResults.filter((h) => h.is_alive).length;
  const totalPorts = scanResults.reduce(
    (sum, h) => sum + h.ports.filter((p) => p.state === 'Open').length,
    0
  );
  const totalVulns = scanResults.reduce((sum, h) => sum + h.vulnerabilities.length, 0);

  return (
    <div className="space-y-4">
      {/* Stats Overview */}
      <Card>
        <div className="flex justify-between items-start mb-4">
          <h3 className="text-lg font-semibold text-white">{activeScan?.name}</h3>
          <button
            onClick={handleDuplicateScan}
            disabled={duplicating}
            className="flex items-center gap-1 px-3 py-1.5 text-sm border border-dark-border rounded hover:border-primary hover:text-primary transition-colors disabled:opacity-50"
            title="Duplicate this scan"
          >
            {duplicating ? <LoadingSpinner className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
            Duplicate
          </button>
        </div>

        {/* Tag Management */}
        <div className="flex items-center gap-2 mb-4 flex-wrap">
          <Tag className="h-4 w-4 text-slate-400" />
          {scanTags.map((tag) => (
            <span
              key={tag.id}
              className="inline-flex items-center gap-1 px-2 py-1 rounded text-sm"
              style={{ backgroundColor: tag.color + '20', color: tag.color }}
            >
              {tag.name}
              <button
                onClick={() => handleRemoveTag(tag.id)}
                className="hover:opacity-70"
                title="Remove tag"
              >
                <X className="h-3 w-3" />
              </button>
            </span>
          ))}
          <div className="relative">
            <button
              onClick={() => setShowTagDropdown(!showTagDropdown)}
              className="inline-flex items-center gap-1 px-2 py-1 rounded text-sm border border-dashed border-dark-border text-slate-400 hover:border-primary hover:text-primary"
            >
              <Plus className="h-3 w-3" />
              Add Tag
            </button>
            {showTagDropdown && availableTags.length > 0 && (
              <div className="absolute top-full left-0 mt-1 z-10 bg-dark-surface border border-dark-border rounded-lg shadow-lg min-w-[150px] max-h-[200px] overflow-y-auto">
                {availableTags.map((tag) => (
                  <button
                    key={tag.id}
                    onClick={() => handleAddTag(tag.id)}
                    className="w-full text-left px-3 py-2 hover:bg-dark-hover flex items-center gap-2"
                  >
                    <span
                      className="w-3 h-3 rounded-full"
                      style={{ backgroundColor: tag.color }}
                    />
                    <span className="text-sm text-slate-300">{tag.name}</span>
                  </button>
                ))}
              </div>
            )}
            {showTagDropdown && availableTags.length === 0 && (
              <div className="absolute top-full left-0 mt-1 z-10 bg-dark-surface border border-dark-border rounded-lg shadow-lg p-3">
                <span className="text-sm text-slate-500">No more tags available</span>
              </div>
            )}
          </div>
        </div>

        <div className="grid grid-cols-3 gap-4 text-center">
          <div>
            <Server className="h-8 w-8 mx-auto mb-2 text-primary" />
            <p className="text-2xl font-bold text-white">{aliveHosts}</p>
            <p className="text-sm text-slate-400">Alive Hosts</p>
          </div>
          <div>
            <Shield className="h-8 w-8 mx-auto mb-2 text-green-500" />
            <p className="text-2xl font-bold text-white">{totalPorts}</p>
            <p className="text-sm text-slate-400">Open Ports</p>
          </div>
          <div>
            <AlertTriangle className="h-8 w-8 mx-auto mb-2 text-red-500" />
            <p className="text-2xl font-bold text-white">{totalVulns}</p>
            <p className="text-sm text-slate-400">Vulnerabilities</p>
          </div>
        </div>
      </Card>

      {/* View Tabs */}
      <Card>
        <div className="flex gap-2 border-b border-dark-border pb-2">
          <button
            onClick={() => setActiveTab('results')}
            className={`flex items-center gap-2 px-4 py-2 rounded-t-lg text-sm font-medium transition-colors ${
              activeTab === 'results'
                ? 'bg-dark-surface text-primary border-b-2 border-primary'
                : 'text-slate-400 hover:text-white hover:bg-dark-hover'
            }`}
          >
            <List className="h-4 w-4" />
            Results
          </button>
          <button
            onClick={() => setActiveTab('topology')}
            className={`flex items-center gap-2 px-4 py-2 rounded-t-lg text-sm font-medium transition-colors ${
              activeTab === 'topology'
                ? 'bg-dark-surface text-primary border-b-2 border-primary'
                : 'text-slate-400 hover:text-white hover:bg-dark-hover'
            }`}
          >
            <Network className="h-4 w-4" />
            Topology
          </button>
        </div>
      </Card>

      {/* Tab Content */}
      {activeTab === 'topology' && activeScan && (
        <NetworkMap scanId={activeScan.id} />
      )}

      {activeTab === 'results' && (
        <>
          {/* Search and Filters */}
          <Card>
        <div className="space-y-3">
          <div className="flex items-center gap-3">
            <div className="flex-1">
              <Input
                type="text"
                placeholder="Search by IP or hostname..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                icon={<Search className="h-4 w-4" />}
              />
            </div>
            <ExportButton
              hosts={filteredAndSortedHosts}
              scanName={activeScan?.name}
              scanId={activeScan?.id}
              disabled={filteredAndSortedHosts.length === 0}
            />
            <button
              onClick={() => setShowComplianceAnalysis(true)}
              disabled={activeScan?.status !== 'completed'}
              className="px-4 py-2 rounded-lg border border-green-500 text-green-500 hover:bg-green-500/10 transition-colors flex items-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <ClipboardCheck className="h-4 w-4" />
              Compliance
            </button>
            <button
              onClick={handleExportToSiem}
              disabled={activeScan?.status !== 'completed' || exportingToSiem}
              className="px-4 py-2 rounded-lg border border-purple-500 text-purple-500 hover:bg-purple-500/10 transition-colors flex items-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
              title="Export scan results to configured SIEM integrations"
            >
              {exportingToSiem ? (
                <LoadingSpinner />
              ) : (
                <Database className="h-4 w-4" />
              )}
              {exportingToSiem ? 'Exporting...' : 'SIEM'}
            </button>
            <button
              onClick={() => setShowReportGenerator(true)}
              disabled={activeScan?.status !== 'completed'}
              className="px-4 py-2 rounded-lg border border-primary text-primary hover:bg-primary/10 transition-colors flex items-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <FileText className="h-4 w-4" />
              Report
            </button>
            <button
              onClick={() => setShowFilters(!showFilters)}
              className={`px-4 py-2 rounded-lg border transition-colors flex items-center gap-2 ${
                showFilters
                  ? 'bg-primary border-primary text-white'
                  : 'border-dark-border text-slate-400 hover:border-primary hover:text-white'
              }`}
            >
              <SlidersHorizontal className="h-4 w-4" />
              Filters
            </button>
          </div>

          {showFilters && (
            <div className="grid grid-cols-2 gap-4 pt-3 border-t border-dark-border">
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-2">Sort by</label>
                <select
                  value={sortBy}
                  onChange={(e) => setSortBy(e.target.value as SortOption)}
                  className="w-full bg-dark-surface border border-dark-border rounded-lg px-3 py-2 text-white focus:ring-2 focus:ring-primary focus:border-transparent"
                >
                  <option value="risk">Risk Score (High to Low)</option>
                  <option value="vulns">Vulnerability Count</option>
                  <option value="ports">Port Count</option>
                  <option value="ip">IP Address</option>
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-2">Filter by</label>
                <select
                  value={filterBy}
                  onChange={(e) => setFilterBy(e.target.value as FilterOption)}
                  className="w-full bg-dark-surface border border-dark-border rounded-lg px-3 py-2 text-white focus:ring-2 focus:ring-primary focus:border-transparent"
                >
                  <option value="all">All Hosts</option>
                  <option value="with-vulns">With Vulnerabilities</option>
                  <option value="high">High/Critical Severity</option>
                  <option value="critical">Critical Only</option>
                </select>
              </div>
            </div>
          )}

          <div className="text-sm text-slate-400">
            Showing {filteredAndSortedHosts.length} of {scanResults.length} hosts
          </div>
        </div>
      </Card>

      {/* Host Cards */}
      <Card>
        <h3 className="text-xl font-semibold text-white mb-4">Discovered Hosts</h3>
        <div className="space-y-3">
          {filteredAndSortedHosts.map((host) => {
            const riskScore = calculateHostRiskScore(host);
            const riskLevel = getRiskLevel(riskScore);

            return (
              <div
                key={host.target.ip}
                className={`bg-dark-bg border rounded-lg p-4 cursor-pointer hover:border-primary/50 transition-all ${
                  riskLevel === 'Critical'
                    ? 'border-severity-critical'
                    : riskLevel === 'High'
                    ? 'border-severity-high'
                    : 'border-dark-border'
                }`}
                onClick={() =>
                  setExpandedHost(expandedHost === host.target.ip ? null : host.target.ip)
                }
              >
                <div className="flex items-center justify-between mb-2">
                  <div>
                    <p className="text-white font-mono font-semibold">{host.target.ip}</p>
                    {host.target.hostname && (
                      <p className="text-sm text-slate-400">{host.target.hostname}</p>
                    )}
                  </div>
                  <div className="flex items-center space-x-2">
                    <Badge variant="severity" type={toSeverityBadgeType(riskLevel)}>
                      Risk: {riskScore}
                    </Badge>
                    <Badge variant="status" type={host.is_alive ? 'completed' : 'failed'}>
                      {host.is_alive ? 'Alive' : 'Down'}
                    </Badge>
                    {host.ports.filter((p) => p.state === 'Open').length > 0 && (
                      <span className="text-sm text-slate-400">
                        {host.ports.filter((p) => p.state === 'Open').length} ports
                      </span>
                    )}
                    {host.vulnerabilities.length > 0 && (
                      <span className="text-sm text-red-400">
                        {host.vulnerabilities.length} vulns
                      </span>
                    )}
                  </div>
                </div>

                {expandedHost === host.target.ip && (
                  <div className="mt-4 border-t border-dark-border pt-4 space-y-4">
                    {host.os_guess && (
                      <div>
                        <p className="text-sm font-medium text-slate-300 mb-1">OS Detection</p>
                        <p className="text-sm text-slate-400">
                          {host.os_guess.os_family} {host.os_guess.os_version} (
                          {host.os_guess.confidence}% confidence)
                        </p>
                      </div>
                    )}

                    {host.ports.filter((p) => p.state === 'Open').length > 0 && (
                      <div>
                        <p className="text-sm font-medium text-slate-300 mb-2">Open Ports</p>
                        <div className="space-y-2">
                          {host.ports
                            .filter((p) => p.state === 'Open')
                            .map((port) => (
                              <div key={port.port}>
                                <div className="bg-dark-surface rounded p-3 text-sm">
                                  <div className="flex items-center justify-between">
                                    <span className="text-white font-mono font-semibold">
                                      {port.port}/{port.protocol}
                                    </span>
                                    {port.service && (
                                      <span className="text-slate-400">
                                        {port.service.name}{' '}
                                        {port.service.version && (
                                          <span className="text-slate-500">
                                            v{port.service.version}
                                          </span>
                                        )}
                                      </span>
                                    )}
                                  </div>
                                  {port.service?.banner && (
                                    <ServiceBanner
                                      banner={port.service.banner}
                                      port={port.port}
                                      service={port.service.name}
                                    />
                                  )}
                                  {port.service?.ssl_info && (
                                    <SslInfoComponent
                                      sslInfo={port.service.ssl_info}
                                      port={port.port}
                                    />
                                  )}
                                </div>
                              </div>
                            ))}
                        </div>
                      </div>
                    )}

                    {host.vulnerabilities.length > 0 && (
                      <div>
                        <p className="text-sm font-medium text-slate-300 mb-3">
                          Vulnerabilities ({host.vulnerabilities.length})
                        </p>
                        <div className="space-y-3">
                          {host.vulnerabilities.map((vuln, idx) => (
                            <VulnerabilityCard key={idx} vulnerability={vuln} />
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })}

          {filteredAndSortedHosts.length === 0 && (
            <div className="text-center py-8 text-slate-400">
              No hosts match the current filters
            </div>
          )}
        </div>
      </Card>

      {/* Reports Section */}
      {activeScan?.status === 'completed' && (
        <ReportList
          key={reportListKey}
          scanId={activeScan.id}
          onGenerateNew={() => setShowReportGenerator(true)}
        />
      )}
        </>
      )}

      {/* Report Generator Modal */}
      {showReportGenerator && activeScan && (
        <ReportGenerator
          scanId={activeScan.id}
          scanName={activeScan.name}
          onClose={() => setShowReportGenerator(false)}
          onReportCreated={() => setReportListKey((k) => k + 1)}
        />
      )}

      {/* Compliance Analysis Modal */}
      {showComplianceAnalysis && activeScan && (
        <ComplianceAnalysis
          scanId={activeScan.id}
          scanName={activeScan.name}
          onClose={() => setShowComplianceAnalysis(false)}
        />
      )}
    </div>
  );
};

export default ResultsViewer;
