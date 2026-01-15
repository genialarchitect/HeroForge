import React, { useState, useEffect } from 'react';
import { toast } from 'react-toastify';
import Layout from '../components/layout/Layout';
import { EngagementRequiredBanner } from '../components/engagement';
import { useRequireEngagement } from '../hooks/useRequireEngagement';
import { DnsReconForm, DnsReconResults } from '../components/dns';
import Card from '../components/ui/Card';
import Badge from '../components/ui/Badge';
import Button from '../components/ui/Button';
import LoadingSpinner from '../components/ui/LoadingSpinner';
import ConfirmationDialog from '../components/ui/ConfirmationDialog';
import { dnsAPI } from '../services/api';
import { Globe, Trash2, Eye, Clock } from 'lucide-react';

interface DnsReconListItem {
  id: string;
  domain: string;
  scan_timestamp: string;
  subdomains_count: number;
  zone_transfer_vulnerable: boolean;
  dnssec_enabled: boolean;
}

const DnsToolsPage: React.FC = () => {
  const [currentResult, setCurrentResult] = useState<any | null>(null);
  const [recentScans, setRecentScans] = useState<DnsReconListItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [viewMode, setViewMode] = useState<'new' | 'result' | 'history'>('new');
  const [deleteConfirm, setDeleteConfirm] = useState<DnsReconListItem | null>(null);
  const [isDeleting, setIsDeleting] = useState(false);
  const { hasEngagement } = useRequireEngagement();

  useEffect(() => {
    loadRecentScans();
  }, []);

  const loadRecentScans = async () => {
    setLoading(true);
    try {
      const response = await dnsAPI.listResults();
      setRecentScans(response.data);
    } catch (error) {
      console.error('Failed to load recent DNS scans:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleScanSuccess = (result: any) => {
    setCurrentResult(result);
    setViewMode('result');
    loadRecentScans();
  };

  const handleViewResult = async (id: string) => {
    try {
      const response = await dnsAPI.getResult(id);
      setCurrentResult(response.data);
      setViewMode('result');
    } catch (error) {
      toast.error('Failed to load DNS recon result');
    }
  };

  const handleDeleteResult = async () => {
    if (!deleteConfirm) return;

    setIsDeleting(true);
    try {
      await dnsAPI.deleteResult(deleteConfirm.id);
      toast.success(`DNS recon for "${deleteConfirm.domain}" deleted`);
      loadRecentScans();
      if (currentResult?.id === deleteConfirm.id) {
        setCurrentResult(null);
        setViewMode('new');
      }
      setDeleteConfirm(null);
    } catch (error) {
      toast.error('Failed to delete DNS recon result');
    } finally {
      setIsDeleting(false);
    }
  };

  return (
    <Layout>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold text-white flex items-center gap-3">
              <Globe className="h-8 w-8 text-primary" />
              DNS Reconnaissance Tools
            </h1>
            <p className="mt-2 text-slate-400">
              Enumerate DNS records, discover subdomains, and check security configuration
            </p>
          </div>
        </div>

        <EngagementRequiredBanner toolName="DNS Reconnaissance Tools" className="mb-6" />

        <div className="flex items-center justify-end gap-3 mb-6">
            <Button
              variant={viewMode === 'new' ? 'primary' : 'secondary'}
              onClick={() => setViewMode('new')}
            >
              New Scan
            </Button>
            <Button
              variant={viewMode === 'history' ? 'primary' : 'secondary'}
              onClick={() => setViewMode('history')}
            >
              History ({recentScans.length})
            </Button>
        </div>

        {/* Content */}
        {viewMode === 'new' && (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div className="lg:col-span-2">
              <DnsReconForm onSuccess={handleScanSuccess} />
            </div>
            <div>
              <Card>
                <div className="p-6">
                  <h3 className="text-lg font-semibold text-white mb-4">Recent Scans</h3>
                  {loading ? (
                    <div className="flex justify-center py-8">
                      <LoadingSpinner />
                    </div>
                  ) : recentScans.length === 0 ? (
                    <p className="text-sm text-slate-400 text-center py-8">No recent scans</p>
                  ) : (
                    <div className="space-y-3">
                      {recentScans.slice(0, 5).map((scan) => (
                        <div
                          key={scan.id}
                          className="p-3 bg-dark-bg rounded-lg border border-dark-border hover:bg-dark-hover transition-colors cursor-pointer"
                          onClick={() => handleViewResult(scan.id)}
                        >
                          <div className="flex items-center gap-2 mb-1">
                            <Globe className="w-4 h-4 text-primary flex-shrink-0" />
                            <span className="text-sm font-medium text-white truncate">
                              {scan.domain}
                            </span>
                          </div>
                          <div className="flex items-center gap-2 text-xs text-slate-400">
                            <Clock className="w-3 h-3" />
                            {new Date(scan.scan_timestamp).toLocaleDateString()}
                          </div>
                          {scan.zone_transfer_vulnerable && (
                            <Badge type="failed" className="mt-1">
                              Zone Transfer Vulnerable
                            </Badge>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </Card>
            </div>
          </div>
        )}

        {viewMode === 'result' && currentResult && (
          <div>
            <DnsReconResults
              result={currentResult.result}
              onClose={() => setViewMode('new')}
            />
          </div>
        )}

        {viewMode === 'history' && (
          <Card>
            <div className="p-6">
              <h3 className="text-lg font-semibold text-white mb-4">
                DNS Reconnaissance History
              </h3>
              {loading ? (
                <div className="flex justify-center py-8">
                  <LoadingSpinner />
                </div>
              ) : recentScans.length === 0 ? (
                <div className="text-center py-12">
                  <Globe className="w-12 h-12 text-slate-500 mx-auto mb-4" />
                  <p className="text-slate-400">No DNS reconnaissance scans yet</p>
                  <Button
                    variant="primary"
                    onClick={() => setViewMode('new')}
                    className="mt-4"
                  >
                    Start First Scan
                  </Button>
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="min-w-full divide-y divide-dark-border">
                    <thead className="bg-dark-bg">
                      <tr>
                        <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">
                          Domain
                        </th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">
                          Scan Date
                        </th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">
                          Subdomains
                        </th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">
                          Security
                        </th>
                        <th className="px-6 py-3 text-right text-xs font-medium text-slate-400 uppercase tracking-wider">
                          Actions
                        </th>
                      </tr>
                    </thead>
                    <tbody className="bg-dark-surface divide-y divide-dark-border">
                      {recentScans.map((scan) => (
                        <tr key={scan.id} className="hover:bg-dark-hover">
                          <td className="px-6 py-4 whitespace-nowrap">
                            <div className="flex items-center gap-2">
                              <Globe className="w-4 h-4 text-primary" />
                              <span className="text-sm font-medium text-white">
                                {scan.domain}
                              </span>
                            </div>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm text-slate-400">
                            {new Date(scan.scan_timestamp).toLocaleString()}
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm text-white">
                            {scan.subdomains_count}
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap">
                            <div className="flex items-center gap-2">
                              {scan.dnssec_enabled && (
                                <Badge type="completed">DNSSEC</Badge>
                              )}
                              {scan.zone_transfer_vulnerable && (
                                <Badge type="failed">AXFR Vuln</Badge>
                              )}
                            </div>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                            <div className="flex items-center justify-end gap-2">
                              <button
                                onClick={() => handleViewResult(scan.id)}
                                className="text-primary hover:text-primary-light"
                                title="View results"
                              >
                                <Eye className="w-4 h-4" />
                              </button>
                              <button
                                onClick={() => setDeleteConfirm(scan)}
                                className="text-severity-critical hover:text-severity-critical/80"
                                title="Delete"
                                aria-label={`Delete DNS recon for ${scan.domain}`}
                              >
                                <Trash2 className="w-4 h-4" />
                              </button>
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </Card>
        )}

        {/* Delete DNS Recon Confirmation Dialog */}
        <ConfirmationDialog
          isOpen={!!deleteConfirm}
          onClose={() => setDeleteConfirm(null)}
          onConfirm={handleDeleteResult}
          title="Delete DNS Recon Result"
          message={`Are you sure you want to delete the DNS reconnaissance results for "${deleteConfirm?.domain}"?`}
          confirmLabel="Delete Result"
          variant="danger"
          loading={isDeleting}
        />
      </div>
    </Layout>
  );
};

export default DnsToolsPage;
