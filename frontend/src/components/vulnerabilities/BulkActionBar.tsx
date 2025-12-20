import React, { useState } from 'react';
import {
  CheckCircle,
  XCircle,
  AlertTriangle,
  UserPlus,
  Trash2,
  Tag,
  ChevronDown,
  X,
  Download,
} from 'lucide-react';
import type { User } from '../../types';

interface BulkActionBarProps {
  selectedCount: number;
  onClearSelection: () => void;
  onStatusChange: (status: string) => Promise<void>;
  onSeverityChange: (severity: string) => Promise<void>;
  onAssign: (userId: string, dueDate?: string) => Promise<void>;
  onDelete: () => Promise<void>;
  onAddTags: (tags: string[]) => Promise<void>;
  onExport: (format: 'json' | 'csv') => Promise<void>;
  users: User[];
  isLoading: boolean;
}

const BulkActionBar: React.FC<BulkActionBarProps> = ({
  selectedCount,
  onClearSelection,
  onStatusChange,
  onSeverityChange,
  onAssign,
  onDelete,
  onAddTags,
  onExport,
  users,
  isLoading,
}) => {
  const [activeDropdown, setActiveDropdown] = useState<string | null>(null);
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [showAssignModal, setShowAssignModal] = useState(false);
  const [showTagModal, setShowTagModal] = useState(false);
  const [selectedUserId, setSelectedUserId] = useState('');
  const [dueDate, setDueDate] = useState('');
  const [newTags, setNewTags] = useState('');

  const handleStatusChange = async (status: string) => {
    setActiveDropdown(null);
    await onStatusChange(status);
  };

  const handleSeverityChange = async (severity: string) => {
    setActiveDropdown(null);
    await onSeverityChange(severity);
  };

  const handleAssign = async () => {
    setShowAssignModal(false);
    await onAssign(selectedUserId, dueDate || undefined);
    setSelectedUserId('');
    setDueDate('');
  };

  const handleDelete = async () => {
    setShowDeleteConfirm(false);
    await onDelete();
  };

  const handleAddTags = async () => {
    setShowTagModal(false);
    const tags = newTags.split(',').map((t) => t.trim()).filter((t) => t.length > 0);
    if (tags.length > 0) {
      await onAddTags(tags);
    }
    setNewTags('');
  };

  const handleExport = async (format: 'json' | 'csv') => {
    setActiveDropdown(null);
    await onExport(format);
  };

  return (
    <>
      {/* Sticky Action Bar */}
      <div className="fixed bottom-0 left-0 right-0 bg-gray-800 border-t border-gray-700 shadow-lg z-40 px-4 py-3">
        <div className="max-w-7xl mx-auto flex items-center justify-between">
          <div className="flex items-center gap-4">
            <span className="text-white font-medium">
              {selectedCount} selected
            </span>
            <button
              onClick={onClearSelection}
              className="text-gray-400 hover:text-white flex items-center gap-1"
              disabled={isLoading}
            >
              <X className="w-4 h-4" />
              Clear
            </button>
          </div>

          <div className="flex items-center gap-2">
            {/* Status Dropdown */}
            <div className="relative">
              <button
                onClick={() =>
                  setActiveDropdown(activeDropdown === 'status' ? null : 'status')
                }
                className="flex items-center gap-1 px-3 py-2 bg-gray-700 text-white rounded hover:bg-gray-600 disabled:opacity-50"
                disabled={isLoading}
              >
                <CheckCircle className="w-4 h-4" />
                Status
                <ChevronDown className="w-4 h-4" />
              </button>
              {activeDropdown === 'status' && (
                <div className="absolute bottom-full mb-1 left-0 bg-gray-700 rounded shadow-lg py-1 min-w-[160px]">
                  <button
                    onClick={() => handleStatusChange('resolved')}
                    className="block w-full text-left px-4 py-2 text-green-400 hover:bg-gray-600"
                  >
                    Mark Resolved
                  </button>
                  <button
                    onClick={() => handleStatusChange('in_progress')}
                    className="block w-full text-left px-4 py-2 text-yellow-400 hover:bg-gray-600"
                  >
                    Mark In Progress
                  </button>
                  <button
                    onClick={() => handleStatusChange('false_positive')}
                    className="block w-full text-left px-4 py-2 text-gray-400 hover:bg-gray-600"
                  >
                    Mark False Positive
                  </button>
                  <button
                    onClick={() => handleStatusChange('accepted_risk')}
                    className="block w-full text-left px-4 py-2 text-purple-400 hover:bg-gray-600"
                  >
                    Accept Risk
                  </button>
                  <button
                    onClick={() => handleStatusChange('open')}
                    className="block w-full text-left px-4 py-2 text-red-400 hover:bg-gray-600"
                  >
                    Reopen
                  </button>
                </div>
              )}
            </div>

            {/* Severity Dropdown */}
            <div className="relative">
              <button
                onClick={() =>
                  setActiveDropdown(activeDropdown === 'severity' ? null : 'severity')
                }
                className="flex items-center gap-1 px-3 py-2 bg-gray-700 text-white rounded hover:bg-gray-600 disabled:opacity-50"
                disabled={isLoading}
              >
                <AlertTriangle className="w-4 h-4" />
                Severity
                <ChevronDown className="w-4 h-4" />
              </button>
              {activeDropdown === 'severity' && (
                <div className="absolute bottom-full mb-1 left-0 bg-gray-700 rounded shadow-lg py-1 min-w-[140px]">
                  <button
                    onClick={() => handleSeverityChange('critical')}
                    className="block w-full text-left px-4 py-2 text-red-500 hover:bg-gray-600"
                  >
                    Critical
                  </button>
                  <button
                    onClick={() => handleSeverityChange('high')}
                    className="block w-full text-left px-4 py-2 text-orange-500 hover:bg-gray-600"
                  >
                    High
                  </button>
                  <button
                    onClick={() => handleSeverityChange('medium')}
                    className="block w-full text-left px-4 py-2 text-yellow-500 hover:bg-gray-600"
                  >
                    Medium
                  </button>
                  <button
                    onClick={() => handleSeverityChange('low')}
                    className="block w-full text-left px-4 py-2 text-blue-400 hover:bg-gray-600"
                  >
                    Low
                  </button>
                  <button
                    onClick={() => handleSeverityChange('info')}
                    className="block w-full text-left px-4 py-2 text-gray-400 hover:bg-gray-600"
                  >
                    Info
                  </button>
                </div>
              )}
            </div>

            {/* Assign Button */}
            <button
              onClick={() => setShowAssignModal(true)}
              className="flex items-center gap-1 px-3 py-2 bg-gray-700 text-white rounded hover:bg-gray-600 disabled:opacity-50"
              disabled={isLoading}
            >
              <UserPlus className="w-4 h-4" />
              Assign
            </button>

            {/* Tags Button */}
            <button
              onClick={() => setShowTagModal(true)}
              className="flex items-center gap-1 px-3 py-2 bg-gray-700 text-white rounded hover:bg-gray-600 disabled:opacity-50"
              disabled={isLoading}
            >
              <Tag className="w-4 h-4" />
              Add Tags
            </button>

            {/* Export Dropdown */}
            <div className="relative">
              <button
                onClick={() =>
                  setActiveDropdown(activeDropdown === 'export' ? null : 'export')
                }
                className="flex items-center gap-1 px-3 py-2 bg-gray-700 text-white rounded hover:bg-gray-600 disabled:opacity-50"
                disabled={isLoading}
              >
                <Download className="w-4 h-4" />
                Export
                <ChevronDown className="w-4 h-4" />
              </button>
              {activeDropdown === 'export' && (
                <div className="absolute bottom-full mb-1 left-0 bg-gray-700 rounded shadow-lg py-1 min-w-[120px]">
                  <button
                    onClick={() => handleExport('json')}
                    className="block w-full text-left px-4 py-2 text-white hover:bg-gray-600"
                  >
                    Export JSON
                  </button>
                  <button
                    onClick={() => handleExport('csv')}
                    className="block w-full text-left px-4 py-2 text-white hover:bg-gray-600"
                  >
                    Export CSV
                  </button>
                </div>
              )}
            </div>

            {/* Delete Button */}
            <button
              onClick={() => setShowDeleteConfirm(true)}
              className="flex items-center gap-1 px-3 py-2 bg-red-600 text-white rounded hover:bg-red-700 disabled:opacity-50"
              disabled={isLoading}
            >
              <Trash2 className="w-4 h-4" />
              Delete
            </button>
          </div>
        </div>
      </div>

      {/* Delete Confirmation Modal */}
      {showDeleteConfirm && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-gray-800 rounded-lg p-6 max-w-md w-full mx-4 shadow-xl">
            <div className="flex items-center gap-3 mb-4">
              <div className="p-2 bg-red-500/20 rounded-full">
                <XCircle className="w-6 h-6 text-red-500" />
              </div>
              <h3 className="text-lg font-bold text-white">
                Delete {selectedCount} Vulnerabilities?
              </h3>
            </div>
            <p className="text-gray-400 mb-6">
              This action will mark the selected vulnerabilities as deleted. This cannot be undone.
            </p>
            <div className="flex gap-2 justify-end">
              <button
                onClick={() => setShowDeleteConfirm(false)}
                className="px-4 py-2 bg-gray-700 text-white rounded hover:bg-gray-600"
                disabled={isLoading}
              >
                Cancel
              </button>
              <button
                onClick={handleDelete}
                disabled={isLoading}
                className="px-4 py-2 bg-red-600 text-white rounded hover:bg-red-700 disabled:bg-gray-400"
              >
                {isLoading ? 'Deleting...' : 'Delete'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Assign Modal */}
      {showAssignModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-gray-800 rounded-lg p-6 max-w-md w-full mx-4 shadow-xl">
            <h3 className="text-lg font-bold text-white mb-4">
              Assign {selectedCount} Vulnerabilities
            </h3>
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Assignee
                </label>
                <select
                  value={selectedUserId}
                  onChange={(e) => setSelectedUserId(e.target.value)}
                  className="block w-full rounded-md border-gray-600 bg-gray-700 text-white shadow-sm focus:border-cyan-500 focus:ring-cyan-500"
                >
                  <option value="">Unassigned</option>
                  {users.map((user) => (
                    <option key={user.id} value={user.id}>
                      {user.username} ({user.email})
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Due Date (Optional)
                </label>
                <input
                  type="date"
                  value={dueDate}
                  onChange={(e) => setDueDate(e.target.value)}
                  className="block w-full rounded-md border-gray-600 bg-gray-700 text-white shadow-sm focus:border-cyan-500 focus:ring-cyan-500"
                  min={new Date().toISOString().split('T')[0]}
                />
              </div>
            </div>
            <div className="flex gap-2 justify-end mt-6">
              <button
                onClick={() => {
                  setShowAssignModal(false);
                  setSelectedUserId('');
                  setDueDate('');
                }}
                className="px-4 py-2 bg-gray-700 text-white rounded hover:bg-gray-600"
                disabled={isLoading}
              >
                Cancel
              </button>
              <button
                onClick={handleAssign}
                disabled={isLoading}
                className="px-4 py-2 bg-cyan-600 text-white rounded hover:bg-cyan-700 disabled:bg-gray-400"
              >
                {isLoading ? 'Assigning...' : 'Assign'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Add Tags Modal */}
      {showTagModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-gray-800 rounded-lg p-6 max-w-md w-full mx-4 shadow-xl">
            <h3 className="text-lg font-bold text-white mb-4">
              Add Tags to {selectedCount} Vulnerabilities
            </h3>
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Tags (comma-separated)
              </label>
              <input
                type="text"
                value={newTags}
                onChange={(e) => setNewTags(e.target.value)}
                placeholder="e.g., needs-review, production, critical-path"
                className="block w-full rounded-md border-gray-600 bg-gray-700 text-white shadow-sm focus:border-cyan-500 focus:ring-cyan-500"
              />
              <p className="mt-1 text-xs text-gray-500">
                Enter tags separated by commas. Max 50 characters per tag.
              </p>
            </div>
            <div className="flex gap-2 justify-end mt-6">
              <button
                onClick={() => {
                  setShowTagModal(false);
                  setNewTags('');
                }}
                className="px-4 py-2 bg-gray-700 text-white rounded hover:bg-gray-600"
                disabled={isLoading}
              >
                Cancel
              </button>
              <button
                onClick={handleAddTags}
                disabled={isLoading || newTags.trim().length === 0}
                className="px-4 py-2 bg-cyan-600 text-white rounded hover:bg-cyan-700 disabled:bg-gray-400"
              >
                {isLoading ? 'Adding...' : 'Add Tags'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Click outside to close dropdowns */}
      {activeDropdown && (
        <div
          className="fixed inset-0 z-30"
          onClick={() => setActiveDropdown(null)}
        />
      )}
    </>
  );
};

export default BulkActionBar;
