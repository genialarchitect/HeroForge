import React, { useState, useEffect } from 'react';
import Layout from '../components/layout/Layout';
import Button from '../components/ui/Button';
import { Server, Tag, Calendar, Activity, Search, Filter, ChevronRight, X } from 'lucide-react';
import api from '../services/api';

interface Asset {
  id: string;
  ip_address: string;
  hostname: string | null;
  mac_address: string | null;
  first_seen: string;
  last_seen: string;
  scan_count: number;
  os_family: string | null;
  os_version: string | null;
  status: string;
  tags: string;
  notes: string | null;
}

interface Port {
  id: string;
  port: number;
  protocol: string;
  service_name: string | null;
  service_version: string | null;
  current_state: string;
}

interface AssetDetail {
  asset: Asset;
  ports: Port[];
  history: any[];
}

const AssetsPage: React.FC = () => {
  const [assets, setAssets] = useState<Asset[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('');
  const [selectedAsset, setSelectedAsset] = useState<AssetDetail | null>(null);
  const [showDetail, setShowDetail] = useState(false);

  useEffect(() => {
    fetchAssets();
  }, [statusFilter]);

  const fetchAssets = async () => {
    try {
      setLoading(true);
      const params = new URLSearchParams();
      if (statusFilter) {
        params.append('status', statusFilter);
      }

      const response = await api.get(`/assets?${params.toString()}`);
      setAssets(response.data);
      setError('');
    } catch (err: any) {
      setError(err.response?.data?.error || 'Failed to fetch assets');
    } finally {
      setLoading(false);
    }
  };

  const fetchAssetDetail = async (assetId: string) => {
    try {
      const response = await api.get(`/assets/${assetId}`);
      setSelectedAsset(response.data);
      setShowDetail(true);
    } catch (err: any) {
      setError(err.response?.data?.error || 'Failed to fetch asset details');
    }
  };

  const updateAssetStatus = async (assetId: string, status: string) => {
    try {
      await api.patch(`/assets/${assetId}`, { status });
      fetchAssets();
      if (selectedAsset && selectedAsset.asset.id === assetId) {
        setSelectedAsset(null);
        setShowDetail(false);
      }
    } catch (err: any) {
      setError(err.response?.data?.error || 'Failed to update asset');
    }
  };

  const filteredAssets = assets.filter(asset => {
    const searchLower = searchTerm.toLowerCase();
    return (
      asset.ip_address.includes(searchLower) ||
      (asset.hostname && asset.hostname.toLowerCase().includes(searchLower)) ||
      (asset.os_family && asset.os_family.toLowerCase().includes(searchLower))
    );
  });

  const parseTags = (tagsJson: string): string[] => {
    try {
      return JSON.parse(tagsJson);
    } catch {
      return [];
    }
  };

  return (
    <Layout>
      <div className="space-y-6">
        <div>
          <h1 className="text-3xl font-bold text-white flex items-center">
            <Server className="h-8 w-8 mr-3 text-primary" />
            Asset Inventory
          </h1>
          <p className="mt-2 text-slate-400">
            Track and manage discovered network assets across scans
          </p>
        </div>

        {error && (
          <div className="bg-severity-critical/20 border border-severity-critical/50 text-severity-critical px-4 py-3 rounded-lg">
            {error}
          </div>
        )}

        {/* Filters */}
        <div className="bg-dark-surface rounded-lg border border-dark-border p-4">
          <div className="flex flex-col md:flex-row gap-4">
            <div className="flex-1 relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-5 w-5 text-slate-400" />
              <input
                type="text"
                placeholder="Search by IP, hostname, or OS..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full pl-10 pr-4 py-2 border border-dark-border rounded-lg bg-dark-bg text-white placeholder-slate-500 focus:ring-2 focus:ring-primary focus:border-primary"
              />
            </div>
            <div className="flex items-center gap-2">
              <Filter className="h-5 w-5 text-slate-400" />
              <select
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
                className="px-4 py-2 border border-dark-border rounded-lg bg-dark-bg text-white focus:ring-2 focus:ring-primary focus:border-primary"
              >
                <option value="">All Status</option>
                <option value="active">Active</option>
                <option value="inactive">Inactive</option>
              </select>
            </div>
          </div>
        </div>

        {loading ? (
          <div className="flex justify-center items-center h-64">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary"></div>
          </div>
        ) : (
          <div className="bg-dark-surface rounded-lg border border-dark-border overflow-hidden">
            <table className="min-w-full divide-y divide-dark-border">
              <thead className="bg-dark-bg">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">
                    Asset
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">
                    Operating System
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">
                    Last Seen
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">
                    Scans
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">
                    Status
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="bg-dark-surface divide-y divide-dark-border">
                {filteredAssets.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="px-6 py-12 text-center text-slate-400">
                      <Server className="h-12 w-12 mx-auto mb-4 text-slate-500" />
                      <p className="text-lg">No assets found</p>
                      <p className="text-sm mt-2">Run a scan to discover network assets</p>
                    </td>
                  </tr>
                ) : (
                  filteredAssets.map((asset) => {
                    return (
                      <tr key={asset.id} className="hover:bg-dark-hover cursor-pointer" onClick={() => fetchAssetDetail(asset.id)}>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <div className="flex items-center">
                            <Server className="h-5 w-5 text-primary mr-2" />
                            <div>
                              <div className="text-sm font-medium text-white">
                                {asset.ip_address}
                              </div>
                              {asset.hostname && (
                                <div className="text-sm text-slate-400">
                                  {asset.hostname}
                                </div>
                              )}
                            </div>
                          </div>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <div className="text-sm text-white">
                            {asset.os_family || 'Unknown'}
                          </div>
                          {asset.os_version && (
                            <div className="text-sm text-slate-400">
                              {asset.os_version}
                            </div>
                          )}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <div className="flex items-center text-sm text-slate-400">
                            <Calendar className="h-4 w-4 mr-1" />
                            {new Date(asset.last_seen).toLocaleDateString()}
                          </div>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <div className="flex items-center text-sm text-white">
                            <Activity className="h-4 w-4 mr-1" />
                            {asset.scan_count}
                          </div>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                            asset.status === 'active'
                              ? 'bg-status-completed/20 text-status-completed'
                              : 'bg-dark-border text-slate-300'
                          }`}>
                            {asset.status}
                          </span>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm">
                          <button className="text-primary hover:text-primary-light">
                            <ChevronRight className="h-5 w-5" />
                          </button>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        )}

        {/* Asset Detail Modal */}
        {showDetail && selectedAsset && (
          <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
            <div className="bg-dark-surface rounded-lg shadow-xl max-w-4xl w-full max-h-[90vh] overflow-y-auto border border-dark-border">
              <div className="p-6 border-b border-dark-border">
                <div className="flex justify-between items-start">
                  <div>
                    <h2 className="text-2xl font-bold text-white">
                      {selectedAsset.asset.ip_address}
                    </h2>
                    {selectedAsset.asset.hostname && (
                      <p className="text-slate-400 mt-1">
                        {selectedAsset.asset.hostname}
                      </p>
                    )}
                  </div>
                  <button
                    onClick={() => setShowDetail(false)}
                    className="text-slate-400 hover:text-white"
                  >
                    <X className="h-6 w-6" />
                  </button>
                </div>
              </div>

              <div className="p-6">
                <div className="grid grid-cols-2 gap-6 mb-6">
                  <div>
                    <h3 className="text-sm font-medium text-slate-400 mb-2">Operating System</h3>
                    <p className="text-white">
                      {selectedAsset.asset.os_family || 'Unknown'}
                      {selectedAsset.asset.os_version && ` ${selectedAsset.asset.os_version}`}
                    </p>
                  </div>
                  <div>
                    <h3 className="text-sm font-medium text-slate-400 mb-2">MAC Address</h3>
                    <p className="text-white">
                      {selectedAsset.asset.mac_address || 'N/A'}
                    </p>
                  </div>
                  <div>
                    <h3 className="text-sm font-medium text-slate-400 mb-2">First Seen</h3>
                    <p className="text-white">
                      {new Date(selectedAsset.asset.first_seen).toLocaleString()}
                    </p>
                  </div>
                  <div>
                    <h3 className="text-sm font-medium text-slate-400 mb-2">Last Seen</h3>
                    <p className="text-white">
                      {new Date(selectedAsset.asset.last_seen).toLocaleString()}
                    </p>
                  </div>
                </div>

                <div className="mb-6">
                  <h3 className="text-lg font-semibold text-white mb-3">Open Ports</h3>
                  <div className="bg-dark-bg rounded-lg p-4">
                    {selectedAsset.ports.length === 0 ? (
                      <p className="text-slate-400">No ports recorded</p>
                    ) : (
                      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                        {selectedAsset.ports.map((port) => (
                          <div key={port.id} className="bg-dark-surface rounded p-3 border border-dark-border">
                            <div className="flex justify-between items-start">
                              <div>
                                <p className="font-medium text-white">
                                  {port.port}/{port.protocol}
                                </p>
                                {port.service_name && (
                                  <p className="text-sm text-slate-400">
                                    {port.service_name}
                                  </p>
                                )}
                                {port.service_version && (
                                  <p className="text-xs text-slate-500">
                                    {port.service_version}
                                  </p>
                                )}
                              </div>
                              <span className={`text-xs px-2 py-1 rounded ${
                                port.current_state === 'open'
                                  ? 'bg-port-open/20 text-port-open'
                                  : 'bg-dark-border text-slate-300'
                              }`}>
                                {port.current_state}
                              </span>
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                </div>

                <div className="flex justify-end gap-3">
                  <Button variant="secondary" onClick={() => setShowDetail(false)}>
                    Close
                  </Button>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </Layout>
  );
};

export default AssetsPage;
