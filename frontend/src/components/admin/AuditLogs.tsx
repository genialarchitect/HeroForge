import React, { useEffect, useState } from 'react';
import { toast } from 'react-toastify';
import { adminAPI } from '../../services/api';
import { AuditLog } from '../../types';
import Card from '../ui/Card';
import LoadingSpinner from '../ui/LoadingSpinner';
import { FileText, Search, User, Target, Calendar } from 'lucide-react';

const AuditLogs: React.FC = () => {
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [filterAction, setFilterAction] = useState<string>('all');

  useEffect(() => {
    loadLogs();
  }, []);

  const loadLogs = async () => {
    setLoading(true);
    try {
      const response = await adminAPI.getAuditLogs(100, 0);
      setLogs(response.data);
    } catch (error) {
      toast.error('Failed to load audit logs');
      console.error(error);
    } finally {
      setLoading(false);
    }
  };

  const filteredLogs = logs.filter((log) => {
    const matchesSearch =
      log.action.toLowerCase().includes(searchQuery.toLowerCase()) ||
      log.user_id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      log.target_id?.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesAction = filterAction === 'all' || log.action.startsWith(filterAction);
    return matchesSearch && matchesAction;
  });

  const getActionColor = (action: string) => {
    if (action.includes('create') || action.includes('assign')) {
      return 'bg-green-500/20 text-green-400 border-green-500/30';
    } else if (action.includes('delete') || action.includes('remove')) {
      return 'bg-red-500/20 text-red-400 border-red-500/30';
    } else if (action.includes('update')) {
      return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
    }
    return 'bg-blue-500/20 text-blue-400 border-blue-500/30';
  };

  const getActionIcon = (action: string) => {
    if (action.includes('user')) return '👤';
    if (action.includes('scan')) return '🔍';
    if (action.includes('role')) return '🛡️';
    if (action.includes('setting')) return '⚙️';
    return '📝';
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
              placeholder="Search logs by action, user ID, or target..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full bg-dark-bg border border-dark-border rounded-lg pl-10 pr-4 py-2 text-white focus:ring-2 focus:ring-primary focus:border-transparent"
            />
          </div>
          <select
            value={filterAction}
            onChange={(e) => setFilterAction(e.target.value)}
            className="bg-dark-bg border border-dark-border rounded-lg px-4 py-2 text-white focus:ring-2 focus:ring-primary focus:border-transparent"
          >
            <option value="all">All Actions</option>
            <option value="user">User Actions</option>
            <option value="scan">Scan Actions</option>
            <option value="role">Role Actions</option>
            <option value="setting">Setting Actions</option>
          </select>
        </div>
      </Card>

      {/* Audit Logs */}
      <Card>
        <h3 className="text-xl font-semibold text-white mb-4">
          <FileText className="inline h-5 w-5 mr-2" />
          Audit Logs ({filteredLogs.length})
        </h3>

        <div className="space-y-2">
          {filteredLogs.map((log) => (
            <div
              key={log.id}
              className="bg-dark-bg border border-dark-border rounded-lg p-4 hover:border-primary/30 transition-colors"
            >
              <div className="flex items-start justify-between gap-4">
                <div className="flex-1">
                  {/* Action */}
                  <div className="flex items-center gap-2 mb-2">
                    <span className="text-xl">{getActionIcon(log.action)}</span>
                    <span
                      className={`inline-flex items-center px-2 py-1 text-xs font-medium rounded border ${getActionColor(
                        log.action
                      )}`}
                    >
                      {log.action}
                    </span>
                  </div>

                  {/* Details Grid */}
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-sm">
                    <div className="flex items-center gap-2 text-slate-400">
                      <User className="h-4 w-4" />
                      <span className="text-slate-500">User:</span>
                      <span className="font-mono text-slate-300">
                        {log.user_id.substring(0, 8)}...
                      </span>
                    </div>

                    {log.target_type && log.target_id && (
                      <div className="flex items-center gap-2 text-slate-400">
                        <Target className="h-4 w-4" />
                        <span className="text-slate-500">Target:</span>
                        <span className="font-mono text-slate-300">
                          {log.target_type}:{log.target_id.substring(0, 8)}...
                        </span>
                      </div>
                    )}

                    <div className="flex items-center gap-2 text-slate-400">
                      <Calendar className="h-4 w-4" />
                      <span className="text-slate-300">
                        {new Date(log.created_at).toLocaleString()}
                      </span>
                    </div>
                  </div>

                  {/* Details JSON */}
                  {log.details && (
                    <div className="mt-2 pt-2 border-t border-dark-border">
                      <details className="text-xs">
                        <summary className="cursor-pointer text-slate-500 hover:text-slate-400">
                          View details
                        </summary>
                        <pre className="mt-2 p-2 bg-dark-surface rounded text-slate-400 overflow-x-auto">
                          {JSON.stringify(JSON.parse(log.details), null, 2)}
                        </pre>
                      </details>
                    </div>
                  )}
                </div>
              </div>
            </div>
          ))}

          {filteredLogs.length === 0 && (
            <div className="text-center py-8 text-slate-400">
              No audit logs found matching your filters
            </div>
          )}
        </div>
      </Card>

      {/* Statistics */}
      <Card>
        <h3 className="text-lg font-semibold text-white mb-3">Action Statistics</h3>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="bg-dark-bg rounded-lg p-4">
            <div className="text-2xl font-bold text-green-400">
              {logs.filter((l) => l.action.includes('create') || l.action.includes('assign'))
                .length}
            </div>
            <div className="text-sm text-slate-400">Created/Assigned</div>
          </div>
          <div className="bg-dark-bg rounded-lg p-4">
            <div className="text-2xl font-bold text-yellow-400">
              {logs.filter((l) => l.action.includes('update')).length}
            </div>
            <div className="text-sm text-slate-400">Updated</div>
          </div>
          <div className="bg-dark-bg rounded-lg p-4">
            <div className="text-2xl font-bold text-red-400">
              {logs.filter((l) => l.action.includes('delete') || l.action.includes('remove'))
                .length}
            </div>
            <div className="text-sm text-slate-400">Deleted/Removed</div>
          </div>
          <div className="bg-dark-bg rounded-lg p-4">
            <div className="text-2xl font-bold text-white">{logs.length}</div>
            <div className="text-sm text-slate-400">Total Actions</div>
          </div>
        </div>
      </Card>
    </div>
  );
};

export default AuditLogs;
