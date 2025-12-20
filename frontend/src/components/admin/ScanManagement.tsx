import React, { useEffect, useState } from 'react';
import { toast } from 'react-toastify';
import { adminAPI } from '../../services/api';
import { ScanResult } from '../../types';
import Card from '../ui/Card';
import LoadingSpinner from '../ui/LoadingSpinner';
import { Search, Trash2, Calendar, User } from 'lucide-react';

const ScanManagement: React.FC = () => {
  const [scans, setScans] = useState<ScanResult[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [filterStatus, setFilterStatus] = useState<string>('all');

  useEffect(() => {
    loadScans();
  }, []);

  const loadScans = async () => {
    setLoading(true);
    try {
      const response = await adminAPI.getAllScans();
      setScans(response.data);
    } catch (error) {
      toast.error('Failed to load scans');
      console.error(error);
    } finally {
      setLoading(false);
    }
  };

  const handleDeleteScan = async (scanId: string, scanName: string) => {
    if (
      !confirm(
        `Are you sure you want to delete scan "${scanName}"? This action cannot be undone.`
      )
    ) {
      return;
    }

    try {
      await adminAPI.deleteScan(scanId);
      toast.success('Scan deleted successfully');
      loadScans();
    } catch (error: unknown) {
      const axiosError = error as { response?: { data?: { error?: string } } };
      toast.error(axiosError.response?.data?.error || 'Failed to delete scan');
    }
  };

  const filteredScans = scans.filter((scan) => {
    const matchesSearch =
      scan.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      scan.targets.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesStatus = filterStatus === 'all' || scan.status === filterStatus;
    return matchesSearch && matchesStatus;
  });

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'completed':
        return 'bg-green-500/20 text-green-400 border-green-500/30';
      case 'running':
        return 'bg-blue-500/20 text-blue-400 border-blue-500/30';
      case 'failed':
        return 'bg-red-500/20 text-red-400 border-red-500/30';
      case 'pending':
        return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
      default:
        return 'bg-slate-500/20 text-slate-400 border-slate-500/30';
    }
  };

  if (loading) {
    return (
      <Card>
        <div className="flex items-center justify-center py-12">
          <LoadingSpinner />
        </div>
      </Card>
    );
  }

  return (
    <div className="space-y-4">
      {/* Search and Filters */}
      <Card>
        <div className="flex items-center gap-3">
          <div className="flex-1 relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400" />
            <input
              type="text"
              placeholder="Search scans by name or target..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full bg-dark-bg border border-dark-border rounded-lg pl-10 pr-4 py-2 text-white focus:ring-2 focus:ring-primary focus:border-transparent"
            />
          </div>
          <select
            value={filterStatus}
            onChange={(e) => setFilterStatus(e.target.value)}
            className="bg-dark-bg border border-dark-border rounded-lg px-4 py-2 text-white focus:ring-2 focus:ring-primary focus:border-transparent"
          >
            <option value="all">All Status</option>
            <option value="pending">Pending</option>
            <option value="running">Running</option>
            <option value="completed">Completed</option>
            <option value="failed">Failed</option>
          </select>
        </div>
      </Card>

      {/* Scans Table */}
      <Card>
        <h3 className="text-xl font-semibold text-white mb-4">
          All Scans ({filteredScans.length})
        </h3>

        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-dark-border">
                <th className="text-left py-3 px-4 text-sm font-medium text-slate-400">
                  Scan Name
                </th>
                <th className="text-left py-3 px-4 text-sm font-medium text-slate-400">
                  Targets
                </th>
                <th className="text-left py-3 px-4 text-sm font-medium text-slate-400">
                  Status
                </th>
                <th className="text-left py-3 px-4 text-sm font-medium text-slate-400">
                  User ID
                </th>
                <th className="text-left py-3 px-4 text-sm font-medium text-slate-400">
                  Created
                </th>
                <th className="text-right py-3 px-4 text-sm font-medium text-slate-400">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody>
              {filteredScans.map((scan) => (
                <tr key={scan.id} className="border-b border-dark-border hover:bg-dark-hover">
                  <td className="py-3 px-4 text-white font-medium">{scan.name}</td>
                  <td className="py-3 px-4 text-slate-300 font-mono text-sm">
                    {scan.targets.length > 50
                      ? `${scan.targets.substring(0, 50)}...`
                      : scan.targets}
                  </td>
                  <td className="py-3 px-4">
                    <span
                      className={`inline-flex items-center px-2 py-1 text-xs font-medium rounded border ${getStatusColor(
                        scan.status
                      )}`}
                    >
                      {scan.status}
                    </span>
                  </td>
                  <td className="py-3 px-4">
                    <div className="flex items-center gap-2 text-slate-400 text-sm">
                      <User className="h-3 w-3" />
                      {scan.user_id.substring(0, 8)}...
                    </div>
                  </td>
                  <td className="py-3 px-4 text-slate-400 text-sm">
                    <div className="flex items-center gap-2">
                      <Calendar className="h-3 w-3" />
                      {new Date(scan.created_at).toLocaleString()}
                    </div>
                  </td>
                  <td className="py-3 px-4">
                    <div className="flex items-center justify-end gap-2">
                      <button
                        onClick={() => handleDeleteScan(scan.id, scan.name)}
                        className="p-2 text-slate-400 hover:text-red-400 transition-colors"
                        title="Delete scan"
                      >
                        <Trash2 className="h-4 w-4" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>

          {filteredScans.length === 0 && (
            <div className="text-center py-8 text-slate-400">
              No scans found matching your filters
            </div>
          )}
        </div>
      </Card>

      {/* Statistics */}
      <Card>
        <h3 className="text-lg font-semibold text-white mb-3">Statistics</h3>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="bg-dark-bg rounded-lg p-4">
            <div className="text-2xl font-bold text-white">
              {scans.filter((s) => s.status === 'completed').length}
            </div>
            <div className="text-sm text-slate-400">Completed</div>
          </div>
          <div className="bg-dark-bg rounded-lg p-4">
            <div className="text-2xl font-bold text-blue-400">
              {scans.filter((s) => s.status === 'running').length}
            </div>
            <div className="text-sm text-slate-400">Running</div>
          </div>
          <div className="bg-dark-bg rounded-lg p-4">
            <div className="text-2xl font-bold text-yellow-400">
              {scans.filter((s) => s.status === 'pending').length}
            </div>
            <div className="text-sm text-slate-400">Pending</div>
          </div>
          <div className="bg-dark-bg rounded-lg p-4">
            <div className="text-2xl font-bold text-red-400">
              {scans.filter((s) => s.status === 'failed').length}
            </div>
            <div className="text-sm text-slate-400">Failed</div>
          </div>
        </div>
      </Card>
    </div>
  );
};

export default ScanManagement;
