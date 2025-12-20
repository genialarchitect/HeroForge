import React, { useState, useEffect } from 'react';
import { toast } from 'react-toastify';
import { vulnerabilityAPI, adminAPI } from '../../services/api';
import type { VulnerabilityTracking, User } from '../../types';

interface RemediationBoardProps {
  scanId?: string;
  onVulnerabilityClick?: (vulnId: string) => void;
}

const RemediationBoard: React.FC<RemediationBoardProps> = ({ scanId, onVulnerabilityClick }) => {
  const [vulnerabilities, setVulnerabilities] = useState<VulnerabilityTracking[]>([]);
  const [loading, setLoading] = useState(true);
  const [draggedItem, setDraggedItem] = useState<VulnerabilityTracking | null>(null);
  const [updating, setUpdating] = useState(false);
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [users, setUsers] = useState<User[]>([]);
  const [showBulkAssignModal, setShowBulkAssignModal] = useState(false);
  const [showBulkDueDateModal, setShowBulkDueDateModal] = useState(false);
  const [bulkAssigneeId, setBulkAssigneeId] = useState('');
  const [bulkDueDate, setBulkDueDate] = useState('');

  const columns = [
    { id: 'open', title: 'Open', color: 'bg-red-900/20 border-red-700' },
    { id: 'in_progress', title: 'In Progress', color: 'bg-yellow-900/20 border-yellow-700' },
    { id: 'pending_verification', title: 'Pending Verification', color: 'bg-blue-900/20 border-blue-700' },
    { id: 'resolved', title: 'Resolved', color: 'bg-green-900/20 border-green-700' },
  ];

  useEffect(() => {
    loadVulnerabilities();
    loadUsers();
  }, [scanId]);

  const loadUsers = async () => {
    try {
      const response = await adminAPI.getUsers();
      setUsers(response.data);
    } catch (error) {
      console.debug('Could not load users list:', error);
    }
  };

  const loadVulnerabilities = async () => {
    try {
      setLoading(true);
      if (!scanId) {
        setVulnerabilities([]);
        return;
      }
      const response = await vulnerabilityAPI.list({ scan_id: scanId });
      setVulnerabilities(response.data);
    } catch (error) {
      console.error('Failed to load vulnerabilities:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleDragStart = (e: React.DragEvent, vuln: VulnerabilityTracking) => {
    setDraggedItem(vuln);
    e.dataTransfer.effectAllowed = 'move';
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    e.dataTransfer.dropEffect = 'move';
  };

  const handleDrop = async (e: React.DragEvent, newStatus: string) => {
    e.preventDefault();
    if (!draggedItem || draggedItem.status === newStatus || updating) return;

    try {
      setUpdating(true);
      await vulnerabilityAPI.update(draggedItem.id, { status: newStatus });
      await loadVulnerabilities();
      setDraggedItem(null);
    } catch (error) {
      console.error('Failed to update vulnerability status:', error);
    } finally {
      setUpdating(false);
    }
  };

  const handleDragEnd = () => {
    setDraggedItem(null);
  };

  const handleToggleSelect = (vulnId: string, e: React.MouseEvent) => {
    e.stopPropagation();
    const newSelected = new Set(selectedIds);
    if (newSelected.has(vulnId)) {
      newSelected.delete(vulnId);
    } else {
      newSelected.add(vulnId);
    }
    setSelectedIds(newSelected);
  };

  const handleBulkStatusChange = async (newStatus: string) => {
    if (selectedIds.size === 0) return;

    try {
      setUpdating(true);
      await vulnerabilityAPI.bulkUpdate({
        vulnerability_ids: Array.from(selectedIds),
        status: newStatus,
      });
      toast.success(`Updated ${selectedIds.size} vulnerabilities to ${newStatus.replace(/_/g, ' ')}`);
      setSelectedIds(new Set());
      await loadVulnerabilities();
    } catch (error) {
      console.error('Failed to bulk update status:', error);
      toast.error('Failed to update vulnerabilities');
    } finally {
      setUpdating(false);
    }
  };

  const handleBulkAssign = async () => {
    if (selectedIds.size === 0) return;

    try {
      setUpdating(true);
      await vulnerabilityAPI.bulkUpdate({
        vulnerability_ids: Array.from(selectedIds),
        assignee_id: bulkAssigneeId || undefined,
      });
      toast.success(`Assigned ${selectedIds.size} vulnerabilities`);
      setSelectedIds(new Set());
      setShowBulkAssignModal(false);
      setBulkAssigneeId('');
      await loadVulnerabilities();
    } catch (error) {
      console.error('Failed to bulk assign:', error);
      toast.error('Failed to assign vulnerabilities');
    } finally {
      setUpdating(false);
    }
  };

  const handleBulkDueDate = async () => {
    if (selectedIds.size === 0 || !bulkDueDate) return;

    try {
      setUpdating(true);
      await vulnerabilityAPI.bulkUpdate({
        vulnerability_ids: Array.from(selectedIds),
        due_date: `${bulkDueDate}T00:00:00Z`,
      });
      toast.success(`Updated due date for ${selectedIds.size} vulnerabilities`);
      setSelectedIds(new Set());
      setShowBulkDueDateModal(false);
      setBulkDueDate('');
      await loadVulnerabilities();
    } catch (error) {
      console.error('Failed to bulk update due date:', error);
      toast.error('Failed to update due dates');
    } finally {
      setUpdating(false);
    }
  };

  const handleClearSelection = () => {
    setSelectedIds(new Set());
  };

  const getVulnerabilitiesByStatus = (status: string) => {
    return vulnerabilities.filter((v) => v.status === status);
  };

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical':
        return 'border-l-4 border-red-500';
      case 'high':
        return 'border-l-4 border-orange-500';
      case 'medium':
        return 'border-l-4 border-yellow-500';
      case 'low':
        return 'border-l-4 border-blue-500';
      default:
        return 'border-l-4 border-gray-500';
    }
  };

  const getPriorityBadge = (priority: string | null) => {
    if (!priority) return null;
    const colors: Record<string, string> = {
      critical: 'bg-red-600 text-white',
      high: 'bg-orange-600 text-white',
      medium: 'bg-yellow-600 text-white',
      low: 'bg-blue-600 text-white',
    };
    return (
      <span className={`text-xs px-1.5 py-0.5 rounded ${colors[priority.toLowerCase()] || 'bg-gray-600 text-white'}`}>
        {priority.charAt(0).toUpperCase()}
      </span>
    );
  };

  if (loading) {
    return (
      <div className="flex justify-center items-center py-12">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div>
      </div>
    );
  }

  if (!scanId) {
    return (
      <div className="text-center py-12 text-gray-400">
        Select a scan to view the remediation board
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex justify-between items-center">
        <h2 className="text-xl font-bold text-white">Remediation Board</h2>
        <div className="flex gap-2">
          {selectedIds.size > 0 && (
            <span className="px-3 py-1 text-sm bg-blue-600 text-white rounded">
              {selectedIds.size} selected
            </span>
          )}
          <button
            onClick={loadVulnerabilities}
            className="px-3 py-1 text-sm bg-gray-700 text-gray-300 rounded hover:bg-gray-600"
          >
            Refresh
          </button>
        </div>
      </div>

      {/* Bulk Actions Toolbar */}
      {selectedIds.size > 0 && (
        <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
          <div className="flex flex-wrap gap-2 items-center">
            <span className="text-gray-400 text-sm mr-2">Bulk Actions:</span>
            <button
              onClick={() => handleBulkStatusChange('in_progress')}
              disabled={updating}
              className="px-3 py-1 text-sm bg-yellow-600 text-white rounded hover:bg-yellow-700 disabled:bg-gray-600"
            >
              Mark In Progress
            </button>
            <button
              onClick={() => handleBulkStatusChange('pending_verification')}
              disabled={updating}
              className="px-3 py-1 text-sm bg-blue-600 text-white rounded hover:bg-blue-700 disabled:bg-gray-600"
            >
              Mark Pending Verification
            </button>
            <button
              onClick={() => handleBulkStatusChange('resolved')}
              disabled={updating}
              className="px-3 py-1 text-sm bg-green-600 text-white rounded hover:bg-green-700 disabled:bg-gray-600"
            >
              Mark Resolved
            </button>
            <div className="border-l border-gray-600 mx-2 h-6"></div>
            <button
              onClick={() => setShowBulkAssignModal(true)}
              disabled={updating}
              className="px-3 py-1 text-sm bg-purple-600 text-white rounded hover:bg-purple-700 disabled:bg-gray-600"
            >
              Assign
            </button>
            <button
              onClick={() => setShowBulkDueDateModal(true)}
              disabled={updating}
              className="px-3 py-1 text-sm bg-indigo-600 text-white rounded hover:bg-indigo-700 disabled:bg-gray-600"
            >
              Set Due Date
            </button>
            <div className="border-l border-gray-600 mx-2 h-6"></div>
            <button
              onClick={handleClearSelection}
              className="px-3 py-1 text-sm bg-gray-600 text-white rounded hover:bg-gray-500"
            >
              Clear Selection
            </button>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {columns.map((column) => (
          <div
            key={column.id}
            className={`rounded-lg border-2 ${column.color} p-4 min-h-[400px] transition-colors ${
              draggedItem && draggedItem.status !== column.id ? 'ring-2 ring-blue-500/50' : ''
            }`}
            onDragOver={handleDragOver}
            onDrop={(e) => handleDrop(e, column.id)}
          >
            <h3 className="font-semibold text-lg mb-4 text-white flex justify-between items-center">
              <span>{column.title}</span>
              <span className="text-sm font-normal text-gray-400 bg-gray-800 px-2 py-0.5 rounded">
                {getVulnerabilitiesByStatus(column.id).length}
              </span>
            </h3>

            <div className="space-y-2">
              {getVulnerabilitiesByStatus(column.id).map((vuln) => (
                <div
                  key={vuln.id}
                  draggable={!updating && !selectedIds.has(vuln.id)}
                  onDragStart={(e) => handleDragStart(e, vuln)}
                  onDragEnd={handleDragEnd}
                  onClick={() => onVulnerabilityClick?.(vuln.id)}
                  className={`bg-gray-800 p-3 rounded shadow cursor-move hover:shadow-lg hover:bg-gray-750 transition-all ${getSeverityColor(
                    vuln.severity
                  )} ${draggedItem?.id === vuln.id ? 'opacity-50' : ''} ${updating ? 'cursor-not-allowed' : ''} ${selectedIds.has(vuln.id) ? 'ring-2 ring-blue-500' : ''}`}
                >
                  <div className="flex justify-between items-start gap-2">
                    <div className="flex items-center gap-2 flex-1 min-w-0">
                      <input
                        type="checkbox"
                        checked={selectedIds.has(vuln.id)}
                        onClick={(e) => handleToggleSelect(vuln.id, e)}
                        onChange={() => {}}
                        className="rounded border-gray-600 text-blue-600 focus:ring-blue-500 bg-gray-700"
                      />
                      <div className="font-medium text-sm text-white truncate">
                        {vuln.vulnerability_id}
                      </div>
                    </div>
                    {getPriorityBadge(vuln.priority)}
                  </div>
                  <div className="text-xs text-gray-400 mt-1 ml-6">{vuln.host_ip}</div>
                  {vuln.port && (
                    <div className="text-xs text-gray-500 ml-6">Port: {vuln.port}</div>
                  )}
                  <div className="flex items-center gap-2 mt-2 ml-6">
                    <span className={`text-xs px-1.5 py-0.5 rounded ${
                      vuln.severity === 'critical' ? 'bg-red-900/50 text-red-300' :
                      vuln.severity === 'high' ? 'bg-orange-900/50 text-orange-300' :
                      vuln.severity === 'medium' ? 'bg-yellow-900/50 text-yellow-300' :
                      'bg-blue-900/50 text-blue-300'
                    }`}>
                      {vuln.severity}
                    </span>
                    {vuln.assignee_id && (
                      <span className="text-xs text-gray-500">Assigned</span>
                    )}
                  </div>
                  {vuln.due_date && (
                    <div className={`text-xs mt-1 ml-6 ${
                      new Date(vuln.due_date) < new Date() ? 'text-red-400' : 'text-gray-500'
                    }`}>
                      Due: {new Date(vuln.due_date).toLocaleDateString()}
                    </div>
                  )}
                  {vuln.estimated_effort && (
                    <div className="text-xs text-gray-500 mt-1 ml-6">
                      Est: {vuln.estimated_effort}h
                      {vuln.actual_effort ? ` / Actual: ${vuln.actual_effort}h` : ''}
                    </div>
                  )}
                </div>
              ))}
              {getVulnerabilitiesByStatus(column.id).length === 0 && (
                <div className="text-center py-8 text-gray-500 text-sm">
                  No vulnerabilities
                </div>
              )}
            </div>
          </div>
        ))}
      </div>

      {/* Legend */}
      <div className="flex flex-wrap gap-4 text-sm text-gray-400 pt-4 border-t border-gray-700">
        <div className="flex items-center gap-2">
          <div className="w-3 h-3 bg-red-500 rounded"></div>
          <span>Critical</span>
        </div>
        <div className="flex items-center gap-2">
          <div className="w-3 h-3 bg-orange-500 rounded"></div>
          <span>High</span>
        </div>
        <div className="flex items-center gap-2">
          <div className="w-3 h-3 bg-yellow-500 rounded"></div>
          <span>Medium</span>
        </div>
        <div className="flex items-center gap-2">
          <div className="w-3 h-3 bg-blue-500 rounded"></div>
          <span>Low</span>
        </div>
      </div>

      {/* Bulk Assign Modal */}
      {showBulkAssignModal && (
        <div className="fixed inset-0 bg-black bg-opacity-70 flex items-center justify-center z-50">
          <div className="bg-gray-800 rounded-lg p-6 max-w-md w-full mx-4 shadow-xl">
            <h3 className="text-lg font-bold text-white mb-4">
              Assign {selectedIds.size} Vulnerabilities
            </h3>
            <div className="mb-4">
              <label className="block text-sm font-medium text-gray-400 mb-2">
                Select Assignee
              </label>
              <select
                value={bulkAssigneeId}
                onChange={(e) => setBulkAssigneeId(e.target.value)}
                className="block w-full rounded-md bg-gray-700 border-gray-600 text-white shadow-sm focus:border-blue-500 focus:ring-blue-500"
              >
                <option value="">Unassigned</option>
                {users.map((user) => (
                  <option key={user.id} value={user.id}>
                    {user.username} ({user.email})
                  </option>
                ))}
              </select>
            </div>
            <div className="flex gap-2 justify-end">
              <button
                onClick={() => {
                  setShowBulkAssignModal(false);
                  setBulkAssigneeId('');
                }}
                className="px-4 py-2 bg-gray-600 text-gray-200 rounded-md hover:bg-gray-500"
                disabled={updating}
              >
                Cancel
              </button>
              <button
                onClick={handleBulkAssign}
                disabled={updating}
                className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 disabled:bg-gray-600"
              >
                {updating ? 'Assigning...' : 'Assign'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Bulk Due Date Modal */}
      {showBulkDueDateModal && (
        <div className="fixed inset-0 bg-black bg-opacity-70 flex items-center justify-center z-50">
          <div className="bg-gray-800 rounded-lg p-6 max-w-md w-full mx-4 shadow-xl">
            <h3 className="text-lg font-bold text-white mb-4">
              Set Due Date for {selectedIds.size} Vulnerabilities
            </h3>
            <div className="mb-4">
              <label className="block text-sm font-medium text-gray-400 mb-2">
                Due Date
              </label>
              <input
                type="date"
                value={bulkDueDate}
                onChange={(e) => setBulkDueDate(e.target.value)}
                className="block w-full rounded-md bg-gray-700 border-gray-600 text-white shadow-sm focus:border-blue-500 focus:ring-blue-500"
                min={new Date().toISOString().split('T')[0]}
              />
            </div>
            <div className="flex gap-2 justify-end">
              <button
                onClick={() => {
                  setShowBulkDueDateModal(false);
                  setBulkDueDate('');
                }}
                className="px-4 py-2 bg-gray-600 text-gray-200 rounded-md hover:bg-gray-500"
                disabled={updating}
              >
                Cancel
              </button>
              <button
                onClick={handleBulkDueDate}
                disabled={updating || !bulkDueDate}
                className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 disabled:bg-gray-600"
              >
                {updating ? 'Updating...' : 'Set Due Date'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default RemediationBoard;
