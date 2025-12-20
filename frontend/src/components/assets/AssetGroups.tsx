import React, { useState, useEffect, useCallback } from 'react';
import { toast } from 'react-toastify';
import {
  Folder,
  Plus,
  Edit2,
  Trash2,
  X,
  Users,
  ChevronRight,
  Server,
} from 'lucide-react';
import Button from '../ui/Button';
import { assetGroupsAPI } from '../../services/api';
import type {
  AssetGroup,
  AssetGroupWithCount,
  AssetGroupWithMembers,
  CreateAssetGroupRequest,
  Asset,
} from '../../types';

// Predefined colors for groups
const GROUP_COLORS = [
  '#3b82f6', // blue
  '#22c55e', // green
  '#f59e0b', // amber
  '#ef4444', // red
  '#8b5cf6', // purple
  '#ec4899', // pink
  '#06b6d4', // cyan
  '#f97316', // orange
  '#84cc16', // lime
  '#6366f1', // indigo
];

interface AssetGroupsProps {
  onGroupSelect?: (groupId: string | null) => void;
  selectedGroupId?: string | null;
  onClose: () => void;
}

const AssetGroups: React.FC<AssetGroupsProps> = ({
  onGroupSelect,
  selectedGroupId,
  onClose,
}) => {
  // Groups state
  const [groups, setGroups] = useState<AssetGroupWithCount[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedGroup, setSelectedGroup] = useState<AssetGroupWithMembers | null>(null);
  const [showGroupDetail, setShowGroupDetail] = useState(false);

  // Create/Edit form state
  const [showCreateGroup, setShowCreateGroup] = useState(false);
  const [showEditGroup, setShowEditGroup] = useState(false);
  const [editingGroup, setEditingGroup] = useState<AssetGroup | null>(null);
  const [newGroupName, setNewGroupName] = useState('');
  const [newGroupDescription, setNewGroupDescription] = useState('');
  const [newGroupColor, setNewGroupColor] = useState(GROUP_COLORS[0]);

  const fetchGroups = useCallback(async () => {
    try {
      setLoading(true);
      const response = await assetGroupsAPI.getGroups();
      setGroups(response.data);
    } catch (err) {
      console.error('Failed to fetch groups:', err);
      toast.error('Failed to load asset groups');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchGroups();
  }, [fetchGroups]);

  const fetchGroupDetail = async (groupId: string) => {
    try {
      const response = await assetGroupsAPI.getGroup(groupId);
      setSelectedGroup(response.data);
      setShowGroupDetail(true);
    } catch (err) {
      console.error('Failed to fetch group details:', err);
      toast.error('Failed to load group details');
    }
  };

  const handleCreateGroup = async () => {
    if (!newGroupName.trim()) {
      toast.error('Group name is required');
      return;
    }

    try {
      const request: CreateAssetGroupRequest = {
        name: newGroupName.trim(),
        description: newGroupDescription.trim() || undefined,
        color: newGroupColor,
      };

      await assetGroupsAPI.createGroup(request);
      toast.success('Group created successfully');
      setShowCreateGroup(false);
      resetGroupForm();
      fetchGroups();
    } catch (err: unknown) {
      const axiosError = err as { response?: { data?: string | { error?: string } } };
      const errorMsg = typeof axiosError.response?.data === 'string'
        ? axiosError.response.data
        : axiosError.response?.data?.error || 'Failed to create group';
      toast.error(errorMsg);
    }
  };

  const handleUpdateGroup = async () => {
    if (!editingGroup || !newGroupName.trim()) {
      toast.error('Group name is required');
      return;
    }

    try {
      await assetGroupsAPI.updateGroup(editingGroup.id, {
        name: newGroupName.trim(),
        description: newGroupDescription.trim() || undefined,
        color: newGroupColor,
      });
      toast.success('Group updated successfully');
      setShowEditGroup(false);
      setEditingGroup(null);
      resetGroupForm();
      fetchGroups();
      // Update selected group if it was the one being edited
      if (selectedGroup && selectedGroup.group.id === editingGroup.id) {
        fetchGroupDetail(editingGroup.id);
      }
    } catch (err: unknown) {
      const axiosError = err as { response?: { data?: string | { error?: string } } };
      const errorMsg = typeof axiosError.response?.data === 'string'
        ? axiosError.response.data
        : axiosError.response?.data?.error || 'Failed to update group';
      toast.error(errorMsg);
    }
  };

  const handleDeleteGroup = async (groupId: string) => {
    if (!confirm('Are you sure you want to delete this group? Assets will not be deleted, only removed from the group.')) {
      return;
    }

    try {
      await assetGroupsAPI.deleteGroup(groupId);
      toast.success('Group deleted successfully');
      fetchGroups();
      if (selectedGroupId === groupId && onGroupSelect) {
        onGroupSelect(null);
      }
      if (selectedGroup && selectedGroup.group.id === groupId) {
        setSelectedGroup(null);
        setShowGroupDetail(false);
      }
    } catch (err: unknown) {
      const axiosError = err as { response?: { data?: string | { error?: string } } };
      const errorMsg = typeof axiosError.response?.data === 'string'
        ? axiosError.response.data
        : axiosError.response?.data?.error || 'Failed to delete group';
      toast.error(errorMsg);
    }
  };

  const handleRemoveAssetFromGroup = async (groupId: string, assetId: string) => {
    try {
      const response = await assetGroupsAPI.removeAssetFromGroup(groupId, assetId);
      toast.success('Asset removed from group');
      setSelectedGroup(response.data);
      fetchGroups();
    } catch (err: unknown) {
      const axiosError = err as { response?: { data?: string | { error?: string } } };
      const errorMsg = typeof axiosError.response?.data === 'string'
        ? axiosError.response.data
        : axiosError.response?.data?.error || 'Failed to remove asset';
      toast.error(errorMsg);
    }
  };

  const resetGroupForm = () => {
    setNewGroupName('');
    setNewGroupDescription('');
    setNewGroupColor(GROUP_COLORS[0]);
  };

  const openEditGroup = (group: AssetGroup) => {
    setEditingGroup(group);
    setNewGroupName(group.name);
    setNewGroupDescription(group.description || '');
    setNewGroupColor(group.color);
    setShowEditGroup(true);
  };

  const handleGroupClick = (groupId: string) => {
    if (onGroupSelect) {
      onGroupSelect(selectedGroupId === groupId ? null : groupId);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
      <div className="bg-dark-surface rounded-lg shadow-xl max-w-4xl w-full max-h-[90vh] overflow-y-auto border border-dark-border">
        <div className="p-6 border-b border-dark-border">
          <div className="flex justify-between items-center">
            <h2 className="text-xl font-bold text-white flex items-center gap-2">
              <Folder className="h-6 w-6 text-primary" />
              Asset Groups
            </h2>
            <button
              onClick={onClose}
              className="text-slate-400 hover:text-white"
            >
              <X className="h-6 w-6" />
            </button>
          </div>
          <p className="text-slate-400 text-sm mt-2">
            Organize your assets into logical groups for better management
          </p>
        </div>

        <div className="p-6">
          {/* Header with Create Button */}
          <div className="mb-4 flex justify-between items-center">
            <p className="text-sm text-slate-400">
              {groups.length} group{groups.length !== 1 ? 's' : ''}
            </p>
            <Button
              onClick={() => {
                resetGroupForm();
                setShowCreateGroup(true);
              }}
              className="flex items-center gap-2"
            >
              <Plus className="h-4 w-4" />
              Create Group
            </Button>
          </div>

          {/* Groups List */}
          {loading ? (
            <div className="flex justify-center items-center py-8">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
            </div>
          ) : groups.length === 0 ? (
            <div className="text-center py-12 text-slate-400">
              <Folder className="h-16 w-16 mx-auto mb-4 text-slate-500" />
              <p className="text-lg">No groups created yet</p>
              <p className="text-sm mt-2">Create your first group to organize assets</p>
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {groups.map(({ group, asset_count }) => (
                <div
                  key={group.id}
                  className={`bg-dark-bg rounded-lg border p-4 transition-all cursor-pointer ${
                    selectedGroupId === group.id
                      ? 'border-primary ring-2 ring-primary/30'
                      : 'border-dark-border hover:border-primary/50'
                  }`}
                  onClick={() => handleGroupClick(group.id)}
                >
                  <div className="flex items-start justify-between">
                    <div className="flex items-center gap-3">
                      <div
                        className="w-10 h-10 rounded-lg flex items-center justify-center"
                        style={{ backgroundColor: `${group.color}20` }}
                      >
                        <Folder
                          className="h-5 w-5"
                          style={{ color: group.color }}
                        />
                      </div>
                      <div>
                        <h3 className="font-medium text-white">{group.name}</h3>
                        {group.description && (
                          <p className="text-sm text-slate-400 line-clamp-1">
                            {group.description}
                          </p>
                        )}
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="text-sm text-slate-400 flex items-center gap-1">
                        <Users className="h-4 w-4" />
                        {asset_count}
                      </span>
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          fetchGroupDetail(group.id);
                        }}
                        className="text-slate-400 hover:text-primary p-1"
                        title="View details"
                      >
                        <ChevronRight className="h-4 w-4" />
                      </button>
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          openEditGroup(group);
                        }}
                        className="text-slate-400 hover:text-white p-1"
                        title="Edit group"
                      >
                        <Edit2 className="h-4 w-4" />
                      </button>
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          handleDeleteGroup(group.id);
                        }}
                        className="text-slate-400 hover:text-severity-critical p-1"
                        title="Delete group"
                      >
                        <Trash2 className="h-4 w-4" />
                      </button>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}

          <div className="flex justify-end mt-6">
            <Button variant="secondary" onClick={onClose}>
              Close
            </Button>
          </div>
        </div>
      </div>

      {/* Create/Edit Group Modal */}
      {(showCreateGroup || showEditGroup) && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-[60] p-4">
          <div className="bg-dark-surface rounded-lg shadow-xl max-w-md w-full border border-dark-border">
            <div className="p-6 border-b border-dark-border">
              <div className="flex justify-between items-center">
                <h2 className="text-xl font-bold text-white">
                  {showEditGroup ? 'Edit Group' : 'Create New Group'}
                </h2>
                <button
                  onClick={() => {
                    setShowCreateGroup(false);
                    setShowEditGroup(false);
                    setEditingGroup(null);
                    resetGroupForm();
                  }}
                  className="text-slate-400 hover:text-white"
                >
                  <X className="h-6 w-6" />
                </button>
              </div>
            </div>

            <div className="p-6 space-y-4">
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-1">
                  Group Name *
                </label>
                <input
                  type="text"
                  value={newGroupName}
                  onChange={(e) => setNewGroupName(e.target.value)}
                  placeholder="e.g., Production Servers, DMZ, Cloud Infrastructure"
                  className="w-full px-4 py-2 border border-dark-border rounded-lg bg-dark-bg text-white placeholder-slate-500 focus:ring-2 focus:ring-primary focus:border-primary"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-slate-300 mb-1">
                  Description (optional)
                </label>
                <textarea
                  value={newGroupDescription}
                  onChange={(e) => setNewGroupDescription(e.target.value)}
                  placeholder="Brief description of this group..."
                  rows={2}
                  className="w-full px-4 py-2 border border-dark-border rounded-lg bg-dark-bg text-white placeholder-slate-500 focus:ring-2 focus:ring-primary focus:border-primary resize-none"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-slate-300 mb-2">
                  Color
                </label>
                <div className="flex flex-wrap gap-2">
                  {GROUP_COLORS.map((color) => (
                    <button
                      key={color}
                      onClick={() => setNewGroupColor(color)}
                      className={`w-8 h-8 rounded-full border-2 transition-transform ${
                        newGroupColor === color
                          ? 'border-white scale-110'
                          : 'border-transparent hover:scale-105'
                      }`}
                      style={{ backgroundColor: color }}
                    />
                  ))}
                </div>
              </div>

              {/* Preview */}
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-2">
                  Preview
                </label>
                <div className="flex items-center gap-3 p-3 bg-dark-bg rounded-lg border border-dark-border">
                  <div
                    className="w-10 h-10 rounded-lg flex items-center justify-center"
                    style={{ backgroundColor: `${newGroupColor}20` }}
                  >
                    <Folder
                      className="h-5 w-5"
                      style={{ color: newGroupColor }}
                    />
                  </div>
                  <div>
                    <p className="font-medium text-white">
                      {newGroupName || 'Group Name'}
                    </p>
                    {newGroupDescription && (
                      <p className="text-sm text-slate-400 line-clamp-1">
                        {newGroupDescription}
                      </p>
                    )}
                  </div>
                </div>
              </div>

              <div className="flex justify-end gap-3 pt-4">
                <Button
                  variant="secondary"
                  onClick={() => {
                    setShowCreateGroup(false);
                    setShowEditGroup(false);
                    setEditingGroup(null);
                    resetGroupForm();
                  }}
                >
                  Cancel
                </Button>
                <Button onClick={showEditGroup ? handleUpdateGroup : handleCreateGroup}>
                  {showEditGroup ? 'Save Changes' : 'Create Group'}
                </Button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Group Detail Modal */}
      {showGroupDetail && selectedGroup && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-[60] p-4">
          <div className="bg-dark-surface rounded-lg shadow-xl max-w-2xl w-full max-h-[80vh] overflow-y-auto border border-dark-border">
            <div className="p-6 border-b border-dark-border">
              <div className="flex justify-between items-start">
                <div className="flex items-center gap-3">
                  <div
                    className="w-12 h-12 rounded-lg flex items-center justify-center"
                    style={{ backgroundColor: `${selectedGroup.group.color}20` }}
                  >
                    <Folder
                      className="h-6 w-6"
                      style={{ color: selectedGroup.group.color }}
                    />
                  </div>
                  <div>
                    <h2 className="text-xl font-bold text-white">
                      {selectedGroup.group.name}
                    </h2>
                    {selectedGroup.group.description && (
                      <p className="text-slate-400">{selectedGroup.group.description}</p>
                    )}
                  </div>
                </div>
                <button
                  onClick={() => {
                    setShowGroupDetail(false);
                    setSelectedGroup(null);
                  }}
                  className="text-slate-400 hover:text-white"
                >
                  <X className="h-6 w-6" />
                </button>
              </div>
            </div>

            <div className="p-6">
              <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
                <Users className="h-5 w-5" />
                Members ({selectedGroup.assets.length})
              </h3>

              {selectedGroup.assets.length === 0 ? (
                <div className="text-center py-8 text-slate-400">
                  <Server className="h-12 w-12 mx-auto mb-4 text-slate-500" />
                  <p>No assets in this group yet</p>
                  <p className="text-sm mt-2">
                    Add assets to this group from the Assets page
                  </p>
                </div>
              ) : (
                <div className="space-y-2">
                  {selectedGroup.assets.map((asset: Asset) => (
                    <div
                      key={asset.id}
                      className="flex items-center justify-between p-3 bg-dark-bg rounded-lg border border-dark-border"
                    >
                      <div className="flex items-center gap-3">
                        <Server className="h-5 w-5 text-primary" />
                        <div>
                          <p className="font-medium text-white">{asset.ip_address}</p>
                          {asset.hostname && (
                            <p className="text-sm text-slate-400">{asset.hostname}</p>
                          )}
                        </div>
                      </div>
                      <div className="flex items-center gap-3">
                        <span
                          className={`text-xs px-2 py-1 rounded ${
                            asset.status === 'active'
                              ? 'bg-status-completed/20 text-status-completed'
                              : 'bg-dark-border text-slate-300'
                          }`}
                        >
                          {asset.status}
                        </span>
                        <button
                          onClick={() =>
                            handleRemoveAssetFromGroup(selectedGroup.group.id, asset.id)
                          }
                          className="text-slate-400 hover:text-severity-critical p-1"
                          title="Remove from group"
                        >
                          <X className="h-4 w-4" />
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              )}

              <div className="flex justify-end mt-6">
                <Button
                  variant="secondary"
                  onClick={() => {
                    setShowGroupDetail(false);
                    setSelectedGroup(null);
                  }}
                >
                  Close
                </Button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default AssetGroups;
