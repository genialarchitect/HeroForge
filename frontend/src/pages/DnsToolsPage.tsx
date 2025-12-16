import React, { useState, useEffect } from 'react';
import { toast } from 'react-toastify';
import Layout from '../components/layout/Layout';
import { DnsReconForm, DnsReconResults } from '../components/dns';
import Card from '../components/ui/Card';
import Badge from '../components/ui/Badge';
import Button from '../components/ui/Button';
import LoadingSpinner from '../components/ui/LoadingSpinner';
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

  const handleDeleteResult = async (id: string) => {
    if (!confirm('Are you sure you want to delete this DNS reconnaissance result?')) {
      return;
    }

    try {
      await dnsAPI.deleteResult(id);
      toast.success('DNS recon result deleted');
      loadRecentScans();
      if (currentResult?.id === id) {
        setCurrentResult(null);
        setViewMode('new');
      }
    } catch (error) {
      toast.error('Failed to delete DNS recon result');
    }
  };

  return (
    <Layout>
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Header */}
        <div className="mb-8">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-3xl font-bold text-gray-900">DNS Reconnaissance Tools</h1>
              <p className="mt-2 text-gray-600">
                Enumerate DNS records, discover subdomains, and check security configuration
              </p>
            </div>
            <div className="flex items-center gap-3">
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
          </div>
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
                  <h3 className="text-lg font-semibold text-gray-900 mb-4">Recent Scans</h3>
                  {loading ? (
                    <div className="flex justify-center py-8">
                      <LoadingSpinner />
                    </div>
                  ) : recentScans.length === 0 ? (
                    <p className="text-sm text-gray-500 text-center py-8">No recent scans</p>
                  ) : (
                    <div className="space-y-3">
                      {recentScans.slice(0, 5).map((scan) => (
                        <div
                          key={scan.id}
                          className="p-3 bg-gray-50 rounded-lg border border-gray-200 hover:bg-gray-100 transition-colors cursor-pointer"
                          onClick={() => handleViewResult(scan.id)}
                        >
                          <div className="flex items-center gap-2 mb-1">
                            <Globe className="w-4 h-4 text-blue-500 flex-shrink-0" />
                            <span className="text-sm font-medium text-gray-900 truncate">
                              {scan.domain}
                            </span>
                          </div>
                          <div className="flex items-center gap-2 text-xs text-gray-500">
                            <Clock className="w-3 h-3" />
                            {new Date(scan.scan_timestamp).toLocaleDateString()}
                          </div>
                          {scan.zone_transfer_vulnerable && (
                            <Badge variant="danger" className="mt-1">
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
              <h3 className="text-lg font-semibold text-gray-900 mb-4">
                DNS Reconnaissance History
              </h3>
              {loading ? (
                <div className="flex justify-center py-8">
                  <LoadingSpinner />
                </div>
              ) : recentScans.length === 0 ? (
                <div className="text-center py-12">
                  <Globe className="w-12 h-12 text-gray-400 mx-auto mb-4" />
                  <p className="text-gray-500">No DNS reconnaissance scans yet</p>
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
                  <table className="min-w-full divide-y divide-gray-200">
                    <thead className="bg-gray-50">
                      <tr>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                          Domain
                        </th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                          Scan Date
                        </th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                          Subdomains
                        </th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                          Security
                        </th>
                        <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">
                          Actions
                        </th>
                      </tr>
                    </thead>
                    <tbody className="bg-white divide-y divide-gray-200">
                      {recentScans.map((scan) => (
                        <tr key={scan.id} className="hover:bg-gray-50">
                          <td className="px-6 py-4 whitespace-nowrap">
                            <div className="flex items-center gap-2">
                              <Globe className="w-4 h-4 text-blue-500" />
                              <span className="text-sm font-medium text-gray-900">
                                {scan.domain}
                              </span>
                            </div>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                            {new Date(scan.scan_timestamp).toLocaleString()}
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                            {scan.subdomains_count}
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap">
                            <div className="flex items-center gap-2">
                              {scan.dnssec_enabled && (
                                <Badge variant="success">DNSSEC</Badge>
                              )}
                              {scan.zone_transfer_vulnerable && (
                                <Badge variant="danger">AXFR Vuln</Badge>
                              )}
                            </div>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                            <div className="flex items-center justify-end gap-2">
                              <button
                                onClick={() => handleViewResult(scan.id)}
                                className="text-blue-600 hover:text-blue-900"
                                title="View results"
                              >
                                <Eye className="w-4 h-4" />
                              </button>
                              <button
                                onClick={() => handleDeleteResult(scan.id)}
                                className="text-red-600 hover:text-red-900"
                                title="Delete"
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
      </div>
    </Layout>
  );
};

export default DnsToolsPage;
