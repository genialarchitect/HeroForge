import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import Layout from '../components/layout/Layout';
import { Server, Tag, Calendar, Activity, Search, Filter, ChevronRight } from 'lucide-react';
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
  const navigate = useNavigate();
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
      <div className="min-h-screen bg-gray-50 dark:bg-gray-900 py-8">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="mb-8">
            <h1 className="text-3xl font-bold text-gray-900 dark:text-white flex items-center">
              <Server className="h-8 w-8 mr-3 text-blue-600" />
              Asset Inventory
            </h1>
            <p className="mt-2 text-gray-600 dark:text-gray-400">
              Track and manage discovered network assets across scans
            </p>
          </div>

          {error && (
            <div className="mb-6 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 text-red-600 dark:text-red-400 px-4 py-3 rounded">
              {error}
            </div>
          )}

          {/* Filters */}
          <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-4 mb-6">
            <div className="flex flex-col md:flex-row gap-4">
              <div className="flex-1 relative">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-5 w-5 text-gray-400" />
                <input
                  type="text"
                  placeholder="Search by IP, hostname, or OS..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="w-full pl-10 pr-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500"
                />
              </div>
              <div className="flex items-center gap-2">
                <Filter className="h-5 w-5 text-gray-400" />
                <select
                  value={statusFilter}
                  onChange={(e) => setStatusFilter(e.target.value)}
                  className="px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500"
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
              <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
            </div>
          ) : (
            <div className="bg-white dark:bg-gray-800 rounded-lg shadow overflow-hidden">
              <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                <thead className="bg-gray-50 dark:bg-gray-700">
                  <tr>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                      Asset
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                      Operating System
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                      Last Seen
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                      Scans
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                      Status
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                      Actions
                    </th>
                  </tr>
                </thead>
                <tbody className="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
                  {filteredAssets.length === 0 ? (
                    <tr>
                      <td colSpan={6} className="px-6 py-12 text-center text-gray-500 dark:text-gray-400">
                        <Server className="h-12 w-12 mx-auto mb-4 text-gray-400" />
                        <p className="text-lg">No assets found</p>
                        <p className="text-sm mt-2">Run a scan to discover network assets</p>
                      </td>
                    </tr>
                  ) : (
                    filteredAssets.map((asset) => {
                      const tags = parseTags(asset.tags);
                      return (
                        <tr key={asset.id} className="hover:bg-gray-50 dark:hover:bg-gray-700 cursor-pointer" onClick={() => fetchAssetDetail(asset.id)}>
                          <td className="px-6 py-4 whitespace-nowrap">
                            <div className="flex items-center">
                              <Server className="h-5 w-5 text-blue-600 mr-2" />
                              <div>
                                <div className="text-sm font-medium text-gray-900 dark:text-white">
                                  {asset.ip_address}
                                </div>
                                {asset.hostname && (
                                  <div className="text-sm text-gray-500 dark:text-gray-400">
                                    {asset.hostname}
                                  </div>
                                )}
                              </div>
                            </div>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap">
                            <div className="text-sm text-gray-900 dark:text-white">
                              {asset.os_family || 'Unknown'}
                            </div>
                            {asset.os_version && (
                              <div className="text-sm text-gray-500 dark:text-gray-400">
                                {asset.os_version}
                              </div>
                            )}
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap">
                            <div className="flex items-center text-sm text-gray-500 dark:text-gray-400">
                              <Calendar className="h-4 w-4 mr-1" />
                              {new Date(asset.last_seen).toLocaleDateString()}
                            </div>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap">
                            <div className="flex items-center text-sm text-gray-900 dark:text-white">
                              <Activity className="h-4 w-4 mr-1" />
                              {asset.scan_count}
                            </div>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap">
                            <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                              asset.status === 'active'
                                ? 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400'
                                : 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300'
                            }`}>
                              {asset.status}
                            </span>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                            <button className="text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-300">
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
            <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
              <div className="bg-white dark:bg-gray-800 rounded-lg shadow-xl max-w-4xl w-full max-h-[90vh] overflow-y-auto">
                <div className="p-6 border-b border-gray-200 dark:border-gray-700">
                  <div className="flex justify-between items-start">
                    <div>
                      <h2 className="text-2xl font-bold text-gray-900 dark:text-white">
                        {selectedAsset.asset.ip_address}
                      </h2>
                      {selectedAsset.asset.hostname && (
                        <p className="text-gray-600 dark:text-gray-400 mt-1">
                          {selectedAsset.asset.hostname}
                        </p>
                      )}
                    </div>
                    <button
                      onClick={() => setShowDetail(false)}
                      className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-200"
                    >
                      <svg className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                      </svg>
                    </button>
                  </div>
                </div>

                <div className="p-6">
                  <div className="grid grid-cols-2 gap-6 mb-6">
                    <div>
                      <h3 className="text-sm font-medium text-gray-500 dark:text-gray-400 mb-2">Operating System</h3>
                      <p className="text-gray-900 dark:text-white">
                        {selectedAsset.asset.os_family || 'Unknown'}
                        {selectedAsset.asset.os_version && ` ${selectedAsset.asset.os_version}`}
                      </p>
                    </div>
                    <div>
                      <h3 className="text-sm font-medium text-gray-500 dark:text-gray-400 mb-2">MAC Address</h3>
                      <p className="text-gray-900 dark:text-white">
                        {selectedAsset.asset.mac_address || 'N/A'}
                      </p>
                    </div>
                    <div>
                      <h3 className="text-sm font-medium text-gray-500 dark:text-gray-400 mb-2">First Seen</h3>
                      <p className="text-gray-900 dark:text-white">
                        {new Date(selectedAsset.asset.first_seen).toLocaleString()}
                      </p>
                    </div>
                    <div>
                      <h3 className="text-sm font-medium text-gray-500 dark:text-gray-400 mb-2">Last Seen</h3>
                      <p className="text-gray-900 dark:text-white">
                        {new Date(selectedAsset.asset.last_seen).toLocaleString()}
                      </p>
                    </div>
                  </div>

                  <div className="mb-6">
                    <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-3">Open Ports</h3>
                    <div className="bg-gray-50 dark:bg-gray-700 rounded-lg p-4">
                      {selectedAsset.ports.length === 0 ? (
                        <p className="text-gray-500 dark:text-gray-400">No ports recorded</p>
                      ) : (
                        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                          {selectedAsset.ports.map((port) => (
                            <div key={port.id} className="bg-white dark:bg-gray-800 rounded p-3 border border-gray-200 dark:border-gray-600">
                              <div className="flex justify-between items-start">
                                <div>
                                  <p className="font-medium text-gray-900 dark:text-white">
                                    {port.port}/{port.protocol}
                                  </p>
                                  {port.service_name && (
                                    <p className="text-sm text-gray-600 dark:text-gray-400">
                                      {port.service_name}
                                    </p>
                                  )}
                                  {port.service_version && (
                                    <p className="text-xs text-gray-500 dark:text-gray-500">
                                      {port.service_version}
                                    </p>
                                  )}
                                </div>
                                <span className={`text-xs px-2 py-1 rounded ${
                                  port.current_state === 'open'
                                    ? 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400'
                                    : 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300'
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
                    <button
                      onClick={() => setShowDetail(false)}
                      className="px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700"
                    >
                      Close
                    </button>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </Layout>
  );
};

export default AssetsPage;
