import React, { useEffect, useState, useCallback } from 'react';
import { toast } from 'react-toastify';
import { adminAPI } from '../../services/api';
import { AuditLog, AuditLogFilter, AuditUser } from '../../types';
import Card from '../ui/Card';
import LoadingSpinner from '../ui/LoadingSpinner';
import Button from '../ui/Button';
import {
  FileText,
  Search,
  User,
  Target,
  Calendar,
  Download,
  ChevronLeft,
  ChevronRight,
  Globe,
  Monitor,
  RefreshCw,
  X,
} from 'lucide-react';

const PAGE_SIZE = 50;

const AuditLogs: React.FC = () => {
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [loading, setLoading] = useState(true);
  const [exporting, setExporting] = useState(false);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);

  // Filter states
  const [searchQuery, setSearchQuery] = useState('');
  const [filterAction, setFilterAction] = useState<string>('');
  const [filterUser, setFilterUser] = useState<string>('');
  const [startDate, setStartDate] = useState<string>('');
  const [endDate, setEndDate] = useState<string>('');

  // Filter options (loaded from API)
  const [actionTypes, setActionTypes] = useState<string[]>([]);
  const [users, setUsers] = useState<AuditUser[]>([]);

  // Expanded row for details
  const [expandedLogId, setExpandedLogId] = useState<string | null>(null);

  // Load filter options
  useEffect(() => {
    const loadFilterOptions = async () => {
      try {
        const [actionsRes, usersRes] = await Promise.all([
          adminAPI.getAuditActionTypes(),
          adminAPI.getAuditUsers(),
        ]);
        setActionTypes(actionsRes.data.actions || []);
        setUsers(usersRes.data.users || []);
      } catch (error) {
        console.error('Failed to load filter options:', error);
      }
    };
    loadFilterOptions();
  }, []);

  const loadLogs = useCallback(async () => {
    setLoading(true);
    try {
      const filter: AuditLogFilter = {
        limit: PAGE_SIZE,
        offset,
      };

      if (filterAction) filter.action = filterAction;
      if (filterUser) filter.user_id = filterUser;
      if (startDate) filter.start_date = new Date(startDate).toISOString();
      if (endDate) {
        // Set end date to end of day
        const end = new Date(endDate);
        end.setHours(23, 59, 59, 999);
        filter.end_date = end.toISOString();
      }

      const response = await adminAPI.getAuditLogs(filter);
      setLogs(response.data.logs);
      setTotal(response.data.total);
    } catch (error) {
      toast.error('Failed to load audit logs');
      console.error(error);
    } finally {
      setLoading(false);
    }
  }, [filterAction, filterUser, startDate, endDate, offset]);

  useEffect(() => {
    loadLogs();
  }, [loadLogs]);

  // Reset offset when filters change
  useEffect(() => {
    setOffset(0);
  }, [filterAction, filterUser, startDate, endDate]);

  const handleExport = async () => {
    setExporting(true);
    try {
      const filter: AuditLogFilter = {};
      if (filterAction) filter.action = filterAction;
      if (filterUser) filter.user_id = filterUser;
      if (startDate) filter.start_date = new Date(startDate).toISOString();
      if (endDate) {
        const end = new Date(endDate);
        end.setHours(23, 59, 59, 999);
        filter.end_date = end.toISOString();
      }

      const response = await adminAPI.exportAuditLogs(filter);
      const blob = new Blob([response.data], { type: 'text/csv' });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `audit_logs_${new Date().toISOString().split('T')[0]}.csv`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.URL.revokeObjectURL(url);
      toast.success('Audit logs exported successfully');
    } catch (error) {
      toast.error('Failed to export audit logs');
      console.error(error);
    } finally {
      setExporting(false);
    }
  };

  const clearFilters = () => {
    setFilterAction('');
    setFilterUser('');
    setStartDate('');
    setEndDate('');
    setSearchQuery('');
    setOffset(0);
  };

  // Client-side search filtering (for quick search within loaded data)
  const filteredLogs = logs.filter((log) => {
    if (!searchQuery) return true;
    const query = searchQuery.toLowerCase();
    return (
      log.action.toLowerCase().includes(query) ||
      log.username?.toLowerCase().includes(query) ||
      log.user_id.toLowerCase().includes(query) ||
      log.target_id?.toLowerCase().includes(query) ||
      log.target_type?.toLowerCase().includes(query) ||
      log.ip_address?.toLowerCase().includes(query)
    );
  });

  const getActionColor = (action: string) => {
    if (action.includes('create') || action.includes('assigned') || action.includes('enabled')) {
      return 'bg-green-500/20 text-green-400 border-green-500/30';
    } else if (action.includes('delete') || action.includes('remove') || action.includes('disabled')) {
      return 'bg-red-500/20 text-red-400 border-red-500/30';
    } else if (action.includes('update') || action.includes('change')) {
      return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
    } else if (action.includes('login') || action.includes('logout') || action.includes('auth')) {
      return 'bg-blue-500/20 text-blue-400 border-blue-500/30';
    } else if (action.includes('export') || action.includes('download')) {
      return 'bg-purple-500/20 text-purple-400 border-purple-500/30';
    }
    return 'bg-slate-500/20 text-slate-400 border-slate-500/30';
  };

  const getActionIcon = (action: string): string => {
    const category = action.split('.')[0];
    switch (category) {
      case 'auth':
        return '🔐';
      case 'user':
        return '👤';
      case 'role':
        return '🛡️';
      case 'scan':
        return '🔍';
      case 'vulnerability':
        return '⚠️';
      case 'report':
        return '📄';
      case 'template':
        return '📋';
      case 'settings':
        return '⚙️';
      case 'api_key':
        return '🔑';
      case 'integration':
        return '🔗';
      case 'compliance':
        return '✅';
      case 'vpn':
        return '🔒';
      case 'mfa':
        return '📱';
      case 'account':
        return '👤';
      default:
        return '📝';
    }
  };

  const formatAction = (action: string): string => {
    return action
      .split('.')
      .map((part) =>
        part
          .split('_')
          .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
          .join(' ')
      )
      .join(' - ');
  };

  const totalPages = Math.ceil(total / PAGE_SIZE);
  const currentPage = Math.floor(offset / PAGE_SIZE) + 1;

  const hasActiveFilters = filterAction || filterUser || startDate || endDate;

  if (loading && logs.length === 0) {
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
      {/* Filters */}
      <Card>
        <div className="space-y-4">
          {/* Row 1: Search and Quick Filters */}
          <div className="flex flex-wrap items-center gap-3">
            <div className="flex-1 min-w-[200px] relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400" />
              <input
                type="text"
                placeholder="Search within results..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full bg-dark-bg border border-dark-border rounded-lg pl-10 pr-4 py-2 text-white focus:ring-2 focus:ring-primary focus:border-transparent"
              />
            </div>

            <select
              value={filterAction}
              onChange={(e) => setFilterAction(e.target.value)}
              className="bg-dark-bg border border-dark-border rounded-lg px-4 py-2 text-white focus:ring-2 focus:ring-primary focus:border-transparent min-w-[150px]"
            >
              <option value="">All Actions</option>
              {actionTypes.map((action) => (
                <option key={action} value={action}>
                  {action.charAt(0).toUpperCase() + action.slice(1).replace('_', ' ')}
                </option>
              ))}
            </select>

            <select
              value={filterUser}
              onChange={(e) => setFilterUser(e.target.value)}
              className="bg-dark-bg border border-dark-border rounded-lg px-4 py-2 text-white focus:ring-2 focus:ring-primary focus:border-transparent min-w-[150px]"
            >
              <option value="">All Users</option>
              {users.map((user) => (
                <option key={user.id} value={user.id}>
                  {user.username}
                </option>
              ))}
            </select>
          </div>

          {/* Row 2: Date Filters and Actions */}
          <div className="flex flex-wrap items-center gap-3">
            <div className="flex items-center gap-2">
              <Calendar className="h-4 w-4 text-slate-400" />
              <input
                type="date"
                value={startDate}
                onChange={(e) => setStartDate(e.target.value)}
                className="bg-dark-bg border border-dark-border rounded-lg px-3 py-2 text-white focus:ring-2 focus:ring-primary focus:border-transparent"
                placeholder="Start Date"
              />
              <span className="text-slate-400">to</span>
              <input
                type="date"
                value={endDate}
                onChange={(e) => setEndDate(e.target.value)}
                className="bg-dark-bg border border-dark-border rounded-lg px-3 py-2 text-white focus:ring-2 focus:ring-primary focus:border-transparent"
                placeholder="End Date"
              />
            </div>

            <div className="flex-1" />

            {hasActiveFilters && (
              <Button variant="ghost" size="sm" onClick={clearFilters}>
                <X className="h-4 w-4 mr-1" />
                Clear Filters
              </Button>
            )}

            <Button variant="ghost" size="sm" onClick={loadLogs} disabled={loading}>
              <RefreshCw className={`h-4 w-4 mr-1 ${loading ? 'animate-spin' : ''}`} />
              Refresh
            </Button>

            <Button
              variant="secondary"
              size="sm"
              onClick={handleExport}
              disabled={exporting || total === 0}
            >
              <Download className="h-4 w-4 mr-1" />
              {exporting ? 'Exporting...' : 'Export CSV'}
            </Button>
          </div>
        </div>
      </Card>

      {/* Audit Logs Table */}
      <Card>
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-xl font-semibold text-white flex items-center gap-2">
            <FileText className="h-5 w-5" />
            Audit Logs
            <span className="text-sm font-normal text-slate-400">
              ({filteredLogs.length} of {total} total)
            </span>
          </h3>
        </div>

        <div className="space-y-2">
          {filteredLogs.map((log) => (
            <div
              key={log.id}
              className={`bg-dark-bg border rounded-lg transition-all ${
                expandedLogId === log.id
                  ? 'border-primary/50'
                  : 'border-dark-border hover:border-primary/30'
              }`}
            >
              <div
                className="p-4 cursor-pointer"
                onClick={() => setExpandedLogId(expandedLogId === log.id ? null : log.id)}
              >
                <div className="flex items-start justify-between gap-4">
                  <div className="flex-1 min-w-0">
                    {/* Action */}
                    <div className="flex items-center gap-2 mb-2">
                      <span className="text-lg">{getActionIcon(log.action)}</span>
                      <span
                        className={`inline-flex items-center px-2 py-1 text-xs font-medium rounded border ${getActionColor(
                          log.action
                        )}`}
                      >
                        {formatAction(log.action)}
                      </span>
                    </div>

                    {/* Details Grid */}
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3 text-sm">
                      <div className="flex items-center gap-2 text-slate-400">
                        <User className="h-4 w-4 flex-shrink-0" />
                        <span className="text-slate-500">User:</span>
                        <span className="font-medium text-slate-300 truncate">
                          {log.username || log.user_id.substring(0, 8) + '...'}
                        </span>
                      </div>

                      {log.target_type && log.target_id && (
                        <div className="flex items-center gap-2 text-slate-400">
                          <Target className="h-4 w-4 flex-shrink-0" />
                          <span className="text-slate-500">Target:</span>
                          <span className="font-mono text-slate-300 truncate">
                            {log.target_type}:{log.target_id.substring(0, 8)}...
                          </span>
                        </div>
                      )}

                      {log.ip_address && (
                        <div className="flex items-center gap-2 text-slate-400">
                          <Globe className="h-4 w-4 flex-shrink-0" />
                          <span className="text-slate-500">IP:</span>
                          <span className="font-mono text-slate-300">{log.ip_address}</span>
                        </div>
                      )}

                      <div className="flex items-center gap-2 text-slate-400">
                        <Calendar className="h-4 w-4 flex-shrink-0" />
                        <span className="text-slate-300">
                          {new Date(log.created_at).toLocaleString()}
                        </span>
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              {/* Expanded Details */}
              {expandedLogId === log.id && (
                <div className="px-4 pb-4 pt-0 border-t border-dark-border mt-2">
                  <div className="mt-3 space-y-3">
                    {/* User Agent */}
                    {log.user_agent && (
                      <div className="flex items-start gap-2 text-sm">
                        <Monitor className="h-4 w-4 text-slate-500 mt-0.5 flex-shrink-0" />
                        <div>
                          <span className="text-slate-500">User Agent:</span>
                          <p className="text-slate-400 text-xs mt-1 break-all">{log.user_agent}</p>
                        </div>
                      </div>
                    )}

                    {/* Full IDs */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-sm">
                      <div>
                        <span className="text-slate-500">User ID:</span>
                        <p className="font-mono text-slate-400 text-xs mt-1">{log.user_id}</p>
                      </div>
                      {log.target_id && (
                        <div>
                          <span className="text-slate-500">Resource ID:</span>
                          <p className="font-mono text-slate-400 text-xs mt-1">{log.target_id}</p>
                        </div>
                      )}
                    </div>

                    {/* Details JSON */}
                    {log.details && (
                      <div>
                        <span className="text-slate-500 text-sm">Details:</span>
                        <pre className="mt-2 p-3 bg-dark-surface rounded text-slate-400 text-xs overflow-x-auto max-h-48">
                          {(() => {
                            try {
                              return JSON.stringify(JSON.parse(log.details), null, 2);
                            } catch {
                              return log.details;
                            }
                          })()}
                        </pre>
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
          ))}

          {filteredLogs.length === 0 && !loading && (
            <div className="text-center py-12 text-slate-400">
              <FileText className="h-12 w-12 mx-auto mb-3 opacity-50" />
              <p>No audit logs found matching your filters</p>
            </div>
          )}
        </div>

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="flex items-center justify-between mt-6 pt-4 border-t border-dark-border">
            <div className="text-sm text-slate-400">
              Showing {offset + 1}-{Math.min(offset + PAGE_SIZE, total)} of {total} entries
            </div>
            <div className="flex items-center gap-2">
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
                disabled={offset === 0 || loading}
              >
                <ChevronLeft className="h-4 w-4" />
                Previous
              </Button>
              <span className="text-sm text-slate-400">
                Page {currentPage} of {totalPages}
              </span>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setOffset(offset + PAGE_SIZE)}
                disabled={offset + PAGE_SIZE >= total || loading}
              >
                Next
                <ChevronRight className="h-4 w-4" />
              </Button>
            </div>
          </div>
        )}
      </Card>

      {/* Statistics */}
      <Card>
        <h3 className="text-lg font-semibold text-white mb-3">Quick Statistics</h3>
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
          <div className="bg-dark-bg rounded-lg p-4">
            <div className="text-2xl font-bold text-blue-400">
              {logs.filter((l) => l.action.startsWith('auth.')).length}
            </div>
            <div className="text-sm text-slate-400">Auth Events</div>
          </div>
          <div className="bg-dark-bg rounded-lg p-4">
            <div className="text-2xl font-bold text-green-400">
              {logs.filter((l) => l.action.includes('create') || l.action.includes('assigned')).length}
            </div>
            <div className="text-sm text-slate-400">Created/Assigned</div>
          </div>
          <div className="bg-dark-bg rounded-lg p-4">
            <div className="text-2xl font-bold text-yellow-400">
              {logs.filter((l) => l.action.includes('update') || l.action.includes('change')).length}
            </div>
            <div className="text-sm text-slate-400">Updated</div>
          </div>
          <div className="bg-dark-bg rounded-lg p-4">
            <div className="text-2xl font-bold text-red-400">
              {logs.filter((l) => l.action.includes('delete') || l.action.includes('remove')).length}
            </div>
            <div className="text-sm text-slate-400">Deleted/Removed</div>
          </div>
          <div className="bg-dark-bg rounded-lg p-4">
            <div className="text-2xl font-bold text-white">{total}</div>
            <div className="text-sm text-slate-400">Total Actions</div>
          </div>
        </div>
      </Card>
    </div>
  );
};

export default AuditLogs;
