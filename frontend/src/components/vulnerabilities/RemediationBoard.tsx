import React, { useState, useEffect } from 'react';
import { vulnerabilityAPI } from '../../services/api';
import type { VulnerabilityTracking } from '../../types';

interface RemediationBoardProps {
  scanId?: string;
  onVulnerabilityClick?: (vulnId: string) => void;
}

const RemediationBoard: React.FC<RemediationBoardProps> = ({ scanId, onVulnerabilityClick }) => {
  const [vulnerabilities, setVulnerabilities] = useState<VulnerabilityTracking[]>([]);
  const [loading, setLoading] = useState(true);
  const [draggedItem, setDraggedItem] = useState<VulnerabilityTracking | null>(null);
  const [updating, setUpdating] = useState(false);

  const columns = [
    { id: 'open', title: 'Open', color: 'bg-red-900/20 border-red-700' },
    { id: 'in_progress', title: 'In Progress', color: 'bg-yellow-900/20 border-yellow-700' },
    { id: 'pending_verification', title: 'Pending Verification', color: 'bg-blue-900/20 border-blue-700' },
    { id: 'resolved', title: 'Resolved', color: 'bg-green-900/20 border-green-700' },
  ];

  useEffect(() => {
    loadVulnerabilities();
  }, [scanId]);

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
        <button
          onClick={loadVulnerabilities}
          className="px-3 py-1 text-sm bg-gray-700 text-gray-300 rounded hover:bg-gray-600"
        >
          Refresh
        </button>
      </div>

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
                  draggable={!updating}
                  onDragStart={(e) => handleDragStart(e, vuln)}
                  onDragEnd={handleDragEnd}
                  onClick={() => onVulnerabilityClick?.(vuln.id)}
                  className={`bg-gray-800 p-3 rounded shadow cursor-move hover:shadow-lg hover:bg-gray-750 transition-all ${getSeverityColor(
                    vuln.severity
                  )} ${draggedItem?.id === vuln.id ? 'opacity-50' : ''} ${updating ? 'cursor-not-allowed' : ''}`}
                >
                  <div className="flex justify-between items-start gap-2">
                    <div className="font-medium text-sm text-white truncate flex-1">
                      {vuln.vulnerability_id}
                    </div>
                    {getPriorityBadge(vuln.priority)}
                  </div>
                  <div className="text-xs text-gray-400 mt-1">{vuln.host_ip}</div>
                  {vuln.port && (
                    <div className="text-xs text-gray-500">Port: {vuln.port}</div>
                  )}
                  <div className="flex items-center gap-2 mt-2">
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
                    <div className={`text-xs mt-1 ${
                      new Date(vuln.due_date) < new Date() ? 'text-red-400' : 'text-gray-500'
                    }`}>
                      Due: {new Date(vuln.due_date).toLocaleDateString()}
                    </div>
                  )}
                  {vuln.estimated_effort && (
                    <div className="text-xs text-gray-500 mt-1">
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
    </div>
  );
};

export default RemediationBoard;
