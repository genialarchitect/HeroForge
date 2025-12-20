import React, { useState, useEffect, useCallback } from 'react';
import Layout from '../components/layout/Layout';
import Button from '../components/ui/Button';
import AssetGroups from '../components/assets/AssetGroups';
import { toast } from 'react-toastify';
import {
  Server,
  Tag,
  Calendar,
  Activity,
  Search,
  Filter,
  ChevronRight,
  X,
  Plus,
  Edit2,
  Trash2,
  Tags,
  Folder,
  FolderPlus,
} from 'lucide-react';
import { assetTagsAPI, assetGroupsAPI } from '../services/api';
import type {
  Asset,
  AssetTag,
  AssetTagWithCount,
  AssetDetailWithTags,
  AssetTagCategory,
  CreateAssetTagRequest,
  AssetGroupWithCount,
  AssetGroup,
} from '../types';

// Predefined colors for tags
const TAG_COLORS = [
  '#22c55e', // green
  '#3b82f6', // blue
  '#f59e0b', // amber
  '#ef4444', // red
  '#8b5cf6', // purple
  '#ec4899', // pink
  '#06b6d4', // cyan
  '#f97316', // orange
  '#84cc16', // lime
  '#6366f1', // indigo
];

const TAG_CATEGORIES: { value: AssetTagCategory; label: string }[] = [
  { value: 'environment', label: 'Environment' },
  { value: 'criticality', label: 'Criticality' },
  { value: 'owner', label: 'Owner' },
  { value: 'department', label: 'Department' },
  { value: 'location', label: 'Location' },
  { value: 'compliance', label: 'Compliance' },
  { value: 'custom', label: 'Custom' },
];

const AssetsPage: React.FC = () => {
  // Assets state
  const [assets, setAssets] = useState<Asset[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('');
  const [selectedAsset, setSelectedAsset] = useState<AssetDetailWithTags | null>(null);
  const [showDetail, setShowDetail] = useState(false);

  // Tags state
  const [tags, setTags] = useState<AssetTagWithCount[]>([]);
  const [selectedTagIds, setSelectedTagIds] = useState<string[]>([]);
  const [showTagManager, setShowTagManager] = useState(false);
  const [showCreateTag, setShowCreateTag] = useState(false);
  const [showEditTag, setShowEditTag] = useState(false);
  const [editingTag, setEditingTag] = useState<AssetTag | null>(null);

  // Create/Edit tag form state
  const [newTagName, setNewTagName] = useState('');
  const [newTagColor, setNewTagColor] = useState(TAG_COLORS[0]);
  const [newTagCategory, setNewTagCategory] = useState<AssetTagCategory>('custom');
  const [newTagDescription, setNewTagDescription] = useState('');

  // Tag assignment state
  const [showTagAssignModal, setShowTagAssignModal] = useState(false);
  const [assetToTag, setAssetToTag] = useState<string | null>(null);

  // Groups state
  const [groups, setGroups] = useState<AssetGroupWithCount[]>([]);
  const [selectedGroupId, setSelectedGroupId] = useState<string | null>(null);
  const [showGroupManager, setShowGroupManager] = useState(false);
  const [showGroupAssignModal, setShowGroupAssignModal] = useState(false);
  const [assetToGroup, setAssetToGroup] = useState<string | null>(null);

  const fetchGroups = useCallback(async () => {
    try {
      const response = await assetGroupsAPI.getGroups();
      setGroups(response.data);
    } catch (err) {
      console.error('Failed to fetch groups:', err);
    }
  }, []);

  const fetchTags = useCallback(async () => {
    try {
      const response = await assetTagsAPI.getTags();
      setTags(response.data);
    } catch (err) {
      console.error('Failed to fetch tags:', err);
    }
  }, []);

  const fetchAssets = useCallback(async () => {
    try {
      setLoading(true);

      // If a group is selected, filter by group
      if (selectedGroupId) {
        const response = await assetGroupsAPI.getAssetsByGroup({
          group_id: selectedGroupId,
          status: statusFilter || undefined,
        });
        setAssets(response.data);
        setError('');
        return;
      }

      const params: { status?: string; tag_ids?: string } = {};
      if (statusFilter) {
        params.status = statusFilter;
      }
      if (selectedTagIds.length > 0) {
        params.tag_ids = selectedTagIds.join(',');
      }

      const response = selectedTagIds.length > 0
        ? await assetTagsAPI.getAssetsByTags(params)
        : await assetTagsAPI.getAssets(params);

      setAssets(response.data);
      setError('');
    } catch (err: unknown) {
      const axiosError = err as { response?: { data?: { error?: string } } };
      setError(axiosError.response?.data?.error || 'Failed to fetch assets');
    } finally {
      setLoading(false);
    }
  }, [statusFilter, selectedTagIds, selectedGroupId]);

  useEffect(() => {
    fetchTags();
    fetchGroups();
  }, [fetchTags, fetchGroups]);

  useEffect(() => {
    fetchAssets();
  }, [fetchAssets]);

  const fetchAssetDetail = async (assetId: string) => {
    try {
      const response = await assetTagsAPI.getAsset(assetId);
      setSelectedAsset(response.data);
      setShowDetail(true);
    } catch (err: unknown) {
      const axiosError = err as { response?: { data?: { error?: string } } };
      setError(axiosError.response?.data?.error || 'Failed to fetch asset details');
    }
  };

  const handleCreateTag = async () => {
    if (!newTagName.trim()) {
      toast.error('Tag name is required');
      return;
    }

    try {
      const request: CreateAssetTagRequest = {
        name: newTagName.trim(),
        color: newTagColor,
        category: newTagCategory,
        description: newTagDescription.trim() || undefined,
      };

      await assetTagsAPI.createTag(request);
      toast.success('Tag created successfully');
      setShowCreateTag(false);
      resetTagForm();
      fetchTags();
    } catch (err: unknown) {
      const axiosError = err as { response?: { data?: string | { error?: string } } };
      const errorMsg = typeof axiosError.response?.data === 'string'
        ? axiosError.response.data
        : axiosError.response?.data?.error || 'Failed to create tag';
      toast.error(errorMsg);
    }
  };

  const handleUpdateTag = async () => {
    if (!editingTag || !newTagName.trim()) {
      toast.error('Tag name is required');
      return;
    }

    try {
      await assetTagsAPI.updateTag(editingTag.id, {
        name: newTagName.trim(),
        color: newTagColor,
        category: newTagCategory,
        description: newTagDescription.trim() || undefined,
      });
      toast.success('Tag updated successfully');
      setShowEditTag(false);
      setEditingTag(null);
      resetTagForm();
      fetchTags();
    } catch (err: unknown) {
      const axiosError = err as { response?: { data?: string | { error?: string } } };
      const errorMsg = typeof axiosError.response?.data === 'string'
        ? axiosError.response.data
        : axiosError.response?.data?.error || 'Failed to update tag';
      toast.error(errorMsg);
    }
  };

  const handleDeleteTag = async (tagId: string) => {
    if (!confirm('Are you sure you want to delete this tag? It will be removed from all assets.')) {
      return;
    }

    try {
      await assetTagsAPI.deleteTag(tagId);
      toast.success('Tag deleted successfully');
      // Remove from selected filters if present
      setSelectedTagIds(prev => prev.filter(id => id !== tagId));
      fetchTags();
    } catch (err: unknown) {
      const axiosError = err as { response?: { data?: string | { error?: string } } };
      const errorMsg = typeof axiosError.response?.data === 'string'
        ? axiosError.response.data
        : axiosError.response?.data?.error || 'Failed to delete tag';
      toast.error(errorMsg);
    }
  };

  const handleAddTagsToAsset = async (tagIds: string[]) => {
    if (!assetToTag) return;

    try {
      const response = await assetTagsAPI.addTagsToAsset(assetToTag, { tag_ids: tagIds });
      toast.success('Tags added successfully');
      setShowTagAssignModal(false);
      setAssetToTag(null);
      fetchAssets();
      // Update selected asset if it's the one we're tagging
      if (selectedAsset && selectedAsset.asset.id === assetToTag) {
        setSelectedAsset(response.data);
      }
    } catch (err: unknown) {
      const axiosError = err as { response?: { data?: string | { error?: string } } };
      const errorMsg = typeof axiosError.response?.data === 'string'
        ? axiosError.response.data
        : axiosError.response?.data?.error || 'Failed to add tags';
      toast.error(errorMsg);
    }
  };

  const handleRemoveTagFromAsset = async (assetId: string, tagId: string) => {
    try {
      const response = await assetTagsAPI.removeTagFromAsset(assetId, tagId);
      toast.success('Tag removed from asset');
      fetchAssets();
      fetchTags();
      // Update selected asset if it's the one we're modifying
      if (selectedAsset && selectedAsset.asset.id === assetId) {
        setSelectedAsset(response.data);
      }
    } catch (err: unknown) {
      const axiosError = err as { response?: { data?: string | { error?: string } } };
      const errorMsg = typeof axiosError.response?.data === 'string'
        ? axiosError.response.data
        : axiosError.response?.data?.error || 'Failed to remove tag';
      toast.error(errorMsg);
    }
  };

  const resetTagForm = () => {
    setNewTagName('');
    setNewTagColor(TAG_COLORS[0]);
    setNewTagCategory('custom');
    setNewTagDescription('');
  };

  const openEditTag = (tag: AssetTag) => {
    setEditingTag(tag);
    setNewTagName(tag.name);
    setNewTagColor(tag.color);
    setNewTagCategory(tag.category);
    setNewTagDescription(tag.description || '');
    setShowEditTag(true);
  };

  const toggleTagFilter = (tagId: string) => {
    setSelectedTagIds(prev =>
      prev.includes(tagId)
        ? prev.filter(id => id !== tagId)
        : [...prev, tagId]
    );
  };

  const clearTagFilters = () => {
    setSelectedTagIds([]);
  };

  const toggleGroupFilter = (groupId: string) => {
    // Clear tag filters when selecting a group
    if (selectedGroupId !== groupId) {
      setSelectedTagIds([]);
    }
    setSelectedGroupId(prev => prev === groupId ? null : groupId);
  };

  const clearGroupFilter = () => {
    setSelectedGroupId(null);
  };

  const handleAddAssetToGroup = async (groupId: string) => {
    if (!assetToGroup) return;

    try {
      await assetGroupsAPI.addAssetsToGroup(groupId, { asset_ids: [assetToGroup] });
      toast.success('Asset added to group');
      setShowGroupAssignModal(false);
      setAssetToGroup(null);
      fetchGroups();
    } catch (err: unknown) {
      const axiosError = err as { response?: { data?: string | { error?: string } } };
      const errorMsg = typeof axiosError.response?.data === 'string'
        ? axiosError.response.data
        : axiosError.response?.data?.error || 'Failed to add asset to group';
      toast.error(errorMsg);
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

  return (
    <Layout>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex justify-between items-start">
          <div>
            <h1 className="text-3xl font-bold text-white flex items-center">
              <Server className="h-8 w-8 mr-3 text-primary" />
              Asset Inventory
            </h1>
            <p className="mt-2 text-slate-400">
              Track and manage discovered network assets across scans
            </p>
          </div>
          <div className="flex items-center gap-3">
            <Button
              variant="secondary"
              onClick={() => setShowGroupManager(true)}
              className="flex items-center gap-2"
            >
              <Folder className="h-4 w-4" />
              Manage Groups
            </Button>
            <Button
              onClick={() => setShowTagManager(true)}
              className="flex items-center gap-2"
            >
              <Tags className="h-4 w-4" />
              Manage Tags
            </Button>
          </div>
        </div>

        {error && (
          <div className="bg-severity-critical/20 border border-severity-critical/50 text-severity-critical px-4 py-3 rounded-lg">
            {error}
          </div>
        )}

        {/* Group Filters */}
        {groups.length > 0 && (
          <div className="bg-dark-surface rounded-lg border border-dark-border p-4">
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-sm font-medium text-slate-300 flex items-center gap-2">
                <Folder className="h-4 w-4" />
                Filter by Group
              </h3>
              {selectedGroupId && (
                <button
                  onClick={clearGroupFilter}
                  className="text-xs text-slate-400 hover:text-white"
                >
                  Clear filter
                </button>
              )}
            </div>
            <div className="flex flex-wrap gap-2">
              {groups.map(({ group, asset_count }) => (
                <button
                  key={group.id}
                  onClick={() => toggleGroupFilter(group.id)}
                  className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm font-medium transition-all ${
                    selectedGroupId === group.id
                      ? 'ring-2 ring-white ring-offset-2 ring-offset-dark-surface'
                      : 'opacity-70 hover:opacity-100'
                  }`}
                  style={{
                    backgroundColor: `${group.color}20`,
                    color: group.color,
                    borderColor: group.color,
                  }}
                >
                  <Folder className="h-3 w-3" style={{ color: group.color }} />
                  {group.name}
                  <span className="text-xs opacity-70">({asset_count})</span>
                </button>
              ))}
            </div>
          </div>
        )}

        {/* Tag Filters */}
        {tags.length > 0 && !selectedGroupId && (
          <div className="bg-dark-surface rounded-lg border border-dark-border p-4">
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-sm font-medium text-slate-300 flex items-center gap-2">
                <Tag className="h-4 w-4" />
                Filter by Tags
              </h3>
              {selectedTagIds.length > 0 && (
                <button
                  onClick={clearTagFilters}
                  className="text-xs text-slate-400 hover:text-white"
                >
                  Clear filters
                </button>
              )}
            </div>
            <div className="flex flex-wrap gap-2">
              {tags.map(({ tag, asset_count }) => (
                <button
                  key={tag.id}
                  onClick={() => toggleTagFilter(tag.id)}
                  className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-sm font-medium transition-all ${
                    selectedTagIds.includes(tag.id)
                      ? 'ring-2 ring-white ring-offset-2 ring-offset-dark-surface'
                      : 'opacity-70 hover:opacity-100'
                  }`}
                  style={{
                    backgroundColor: `${tag.color}20`,
                    color: tag.color,
                    borderColor: tag.color,
                  }}
                >
                  <span
                    className="w-2 h-2 rounded-full"
                    style={{ backgroundColor: tag.color }}
                  />
                  {tag.name}
                  <span className="text-xs opacity-70">({asset_count})</span>
                </button>
              ))}
            </div>
          </div>
        )}

        {/* Search and Status Filters */}
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

        {/* Assets Table */}
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
                    Tags
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">
                    Operating System
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">
                    Last Seen
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
                  filteredAssets.map((asset) => (
                    <tr
                      key={asset.id}
                      className="hover:bg-dark-hover cursor-pointer"
                      onClick={() => fetchAssetDetail(asset.id)}
                    >
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
                      <td className="px-6 py-4">
                        <div className="flex items-center gap-2">
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              setAssetToTag(asset.id);
                              setShowTagAssignModal(true);
                            }}
                            className="text-slate-400 hover:text-primary"
                            title="Add tags"
                          >
                            <Plus className="h-4 w-4" />
                          </button>
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              setAssetToGroup(asset.id);
                              setShowGroupAssignModal(true);
                            }}
                            className="text-slate-400 hover:text-primary"
                            title="Add to group"
                          >
                            <FolderPlus className="h-4 w-4" />
                          </button>
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
                        <span
                          className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                            asset.status === 'active'
                              ? 'bg-status-completed/20 text-status-completed'
                              : 'bg-dark-border text-slate-300'
                          }`}
                        >
                          {asset.status}
                        </span>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm">
                        <button className="text-primary hover:text-primary-light">
                          <ChevronRight className="h-5 w-5" />
                        </button>
                      </td>
                    </tr>
                  ))
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
                {/* Tags Section */}
                <div className="mb-6">
                  <div className="flex items-center justify-between mb-3">
                    <h3 className="text-lg font-semibold text-white flex items-center gap-2">
                      <Tags className="h-5 w-5" />
                      Tags
                    </h3>
                    <button
                      onClick={() => {
                        setAssetToTag(selectedAsset.asset.id);
                        setShowTagAssignModal(true);
                      }}
                      className="text-sm text-primary hover:text-primary-light flex items-center gap-1"
                    >
                      <Plus className="h-4 w-4" />
                      Add Tags
                    </button>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    {selectedAsset.asset_tags.length === 0 ? (
                      <p className="text-slate-400 text-sm">No tags assigned</p>
                    ) : (
                      selectedAsset.asset_tags.map((tag) => (
                        <span
                          key={tag.id}
                          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-sm font-medium"
                          style={{
                            backgroundColor: `${tag.color}20`,
                            color: tag.color,
                          }}
                        >
                          <span
                            className="w-2 h-2 rounded-full"
                            style={{ backgroundColor: tag.color }}
                          />
                          {tag.name}
                          <button
                            onClick={() => handleRemoveTagFromAsset(selectedAsset.asset.id, tag.id)}
                            className="ml-1 hover:opacity-70"
                          >
                            <X className="h-3 w-3" />
                          </button>
                        </span>
                      ))
                    )}
                  </div>
                </div>

                {/* Asset Details Grid */}
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
                  <div>
                    <h3 className="text-sm font-medium text-slate-400 mb-2">Scan Count</h3>
                    <p className="text-white flex items-center gap-1">
                      <Activity className="h-4 w-4" />
                      {selectedAsset.asset.scan_count}
                    </p>
                  </div>
                  <div>
                    <h3 className="text-sm font-medium text-slate-400 mb-2">Status</h3>
                    <span
                      className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                        selectedAsset.asset.status === 'active'
                          ? 'bg-status-completed/20 text-status-completed'
                          : 'bg-dark-border text-slate-300'
                      }`}
                    >
                      {selectedAsset.asset.status}
                    </span>
                  </div>
                </div>

                {/* Open Ports */}
                <div className="mb-6">
                  <h3 className="text-lg font-semibold text-white mb-3">Open Ports</h3>
                  <div className="bg-dark-bg rounded-lg p-4">
                    {selectedAsset.ports.length === 0 ? (
                      <p className="text-slate-400">No ports recorded</p>
                    ) : (
                      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                        {selectedAsset.ports.map((port) => (
                          <div
                            key={port.id}
                            className="bg-dark-surface rounded p-3 border border-dark-border"
                          >
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
                              <span
                                className={`text-xs px-2 py-1 rounded ${
                                  port.current_state === 'open'
                                    ? 'bg-port-open/20 text-port-open'
                                    : 'bg-dark-border text-slate-300'
                                }`}
                              >
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

        {/* Tag Manager Modal */}
        {showTagManager && (
          <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
            <div className="bg-dark-surface rounded-lg shadow-xl max-w-2xl w-full max-h-[90vh] overflow-y-auto border border-dark-border">
              <div className="p-6 border-b border-dark-border">
                <div className="flex justify-between items-center">
                  <h2 className="text-xl font-bold text-white flex items-center gap-2">
                    <Tags className="h-6 w-6" />
                    Manage Asset Tags
                  </h2>
                  <button
                    onClick={() => setShowTagManager(false)}
                    className="text-slate-400 hover:text-white"
                  >
                    <X className="h-6 w-6" />
                  </button>
                </div>
              </div>

              <div className="p-6">
                <div className="mb-4 flex justify-end">
                  <Button
                    onClick={() => {
                      resetTagForm();
                      setShowCreateTag(true);
                    }}
                    className="flex items-center gap-2"
                  >
                    <Plus className="h-4 w-4" />
                    Create Tag
                  </Button>
                </div>

                {tags.length === 0 ? (
                  <div className="text-center py-8 text-slate-400">
                    <Tag className="h-12 w-12 mx-auto mb-4 text-slate-500" />
                    <p className="text-lg">No tags created yet</p>
                    <p className="text-sm mt-2">Create your first tag to organize assets</p>
                  </div>
                ) : (
                  <div className="space-y-3">
                    {TAG_CATEGORIES.map(({ value: category, label }) => {
                      const categoryTags = tags.filter(t => t.tag.category === category);
                      if (categoryTags.length === 0) return null;

                      return (
                        <div key={category} className="mb-4">
                          <h4 className="text-sm font-medium text-slate-400 mb-2">{label}</h4>
                          <div className="space-y-2">
                            {categoryTags.map(({ tag, asset_count }) => (
                              <div
                                key={tag.id}
                                className="flex items-center justify-between p-3 bg-dark-bg rounded-lg border border-dark-border"
                              >
                                <div className="flex items-center gap-3">
                                  <span
                                    className="w-4 h-4 rounded-full"
                                    style={{ backgroundColor: tag.color }}
                                  />
                                  <div>
                                    <p className="text-white font-medium">{tag.name}</p>
                                    {tag.description && (
                                      <p className="text-sm text-slate-400">{tag.description}</p>
                                    )}
                                  </div>
                                </div>
                                <div className="flex items-center gap-3">
                                  <span className="text-sm text-slate-400">
                                    {asset_count} asset{asset_count !== 1 ? 's' : ''}
                                  </span>
                                  <button
                                    onClick={() => openEditTag(tag)}
                                    className="text-slate-400 hover:text-white"
                                  >
                                    <Edit2 className="h-4 w-4" />
                                  </button>
                                  <button
                                    onClick={() => handleDeleteTag(tag.id)}
                                    className="text-slate-400 hover:text-severity-critical"
                                  >
                                    <Trash2 className="h-4 w-4" />
                                  </button>
                                </div>
                              </div>
                            ))}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}

                <div className="flex justify-end mt-6">
                  <Button variant="secondary" onClick={() => setShowTagManager(false)}>
                    Close
                  </Button>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Create/Edit Tag Modal */}
        {(showCreateTag || showEditTag) && (
          <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-[60] p-4">
            <div className="bg-dark-surface rounded-lg shadow-xl max-w-md w-full border border-dark-border">
              <div className="p-6 border-b border-dark-border">
                <div className="flex justify-between items-center">
                  <h2 className="text-xl font-bold text-white">
                    {showEditTag ? 'Edit Tag' : 'Create New Tag'}
                  </h2>
                  <button
                    onClick={() => {
                      setShowCreateTag(false);
                      setShowEditTag(false);
                      setEditingTag(null);
                      resetTagForm();
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
                    Tag Name *
                  </label>
                  <input
                    type="text"
                    value={newTagName}
                    onChange={(e) => setNewTagName(e.target.value)}
                    placeholder="e.g., Production, Critical, Finance"
                    className="w-full px-4 py-2 border border-dark-border rounded-lg bg-dark-bg text-white placeholder-slate-500 focus:ring-2 focus:ring-primary focus:border-primary"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-slate-300 mb-1">
                    Category
                  </label>
                  <select
                    value={newTagCategory}
                    onChange={(e) => setNewTagCategory(e.target.value as AssetTagCategory)}
                    className="w-full px-4 py-2 border border-dark-border rounded-lg bg-dark-bg text-white focus:ring-2 focus:ring-primary focus:border-primary"
                  >
                    {TAG_CATEGORIES.map(({ value, label }) => (
                      <option key={value} value={value}>
                        {label}
                      </option>
                    ))}
                  </select>
                </div>

                <div>
                  <label className="block text-sm font-medium text-slate-300 mb-1">
                    Color
                  </label>
                  <div className="flex flex-wrap gap-2">
                    {TAG_COLORS.map((color) => (
                      <button
                        key={color}
                        onClick={() => setNewTagColor(color)}
                        className={`w-8 h-8 rounded-full border-2 ${
                          newTagColor === color
                            ? 'border-white'
                            : 'border-transparent'
                        }`}
                        style={{ backgroundColor: color }}
                      />
                    ))}
                  </div>
                </div>

                <div>
                  <label className="block text-sm font-medium text-slate-300 mb-1">
                    Description (optional)
                  </label>
                  <textarea
                    value={newTagDescription}
                    onChange={(e) => setNewTagDescription(e.target.value)}
                    placeholder="Brief description of this tag..."
                    rows={2}
                    className="w-full px-4 py-2 border border-dark-border rounded-lg bg-dark-bg text-white placeholder-slate-500 focus:ring-2 focus:ring-primary focus:border-primary resize-none"
                  />
                </div>

                {/* Preview */}
                <div>
                  <label className="block text-sm font-medium text-slate-300 mb-2">
                    Preview
                  </label>
                  <span
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-sm font-medium"
                    style={{
                      backgroundColor: `${newTagColor}20`,
                      color: newTagColor,
                    }}
                  >
                    <span
                      className="w-2 h-2 rounded-full"
                      style={{ backgroundColor: newTagColor }}
                    />
                    {newTagName || 'Tag Name'}
                  </span>
                </div>

                <div className="flex justify-end gap-3 pt-4">
                  <Button
                    variant="secondary"
                    onClick={() => {
                      setShowCreateTag(false);
                      setShowEditTag(false);
                      setEditingTag(null);
                      resetTagForm();
                    }}
                  >
                    Cancel
                  </Button>
                  <Button onClick={showEditTag ? handleUpdateTag : handleCreateTag}>
                    {showEditTag ? 'Save Changes' : 'Create Tag'}
                  </Button>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Tag Assignment Modal */}
        {showTagAssignModal && assetToTag && (
          <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
            <div className="bg-dark-surface rounded-lg shadow-xl max-w-md w-full border border-dark-border">
              <div className="p-6 border-b border-dark-border">
                <div className="flex justify-between items-center">
                  <h2 className="text-xl font-bold text-white flex items-center gap-2">
                    <Tags className="h-5 w-5" />
                    Add Tags to Asset
                  </h2>
                  <button
                    onClick={() => {
                      setShowTagAssignModal(false);
                      setAssetToTag(null);
                    }}
                    className="text-slate-400 hover:text-white"
                  >
                    <X className="h-6 w-6" />
                  </button>
                </div>
              </div>

              <div className="p-6">
                {tags.length === 0 ? (
                  <div className="text-center py-8 text-slate-400">
                    <Tag className="h-12 w-12 mx-auto mb-4 text-slate-500" />
                    <p>No tags available</p>
                    <Button
                      className="mt-4"
                      onClick={() => {
                        setShowTagAssignModal(false);
                        setShowTagManager(true);
                      }}
                    >
                      Create Tags
                    </Button>
                  </div>
                ) : (
                  <>
                    <p className="text-slate-400 text-sm mb-4">
                      Select tags to add to this asset:
                    </p>
                    <div className="space-y-2 max-h-64 overflow-y-auto">
                      {tags.map(({ tag }) => {
                        // Check if asset already has this tag
                        const assetTags = selectedAsset?.asset_tags || [];
                        const isAlreadyTagged = assetTags.some(t => t.id === tag.id);

                        return (
                          <button
                            key={tag.id}
                            onClick={() => !isAlreadyTagged && handleAddTagsToAsset([tag.id])}
                            disabled={isAlreadyTagged}
                            className={`w-full flex items-center justify-between p-3 rounded-lg border transition-colors ${
                              isAlreadyTagged
                                ? 'bg-dark-bg border-dark-border opacity-50 cursor-not-allowed'
                                : 'bg-dark-bg border-dark-border hover:border-primary'
                            }`}
                          >
                            <div className="flex items-center gap-3">
                              <span
                                className="w-4 h-4 rounded-full"
                                style={{ backgroundColor: tag.color }}
                              />
                              <span className="text-white">{tag.name}</span>
                            </div>
                            {isAlreadyTagged && (
                              <span className="text-xs text-slate-400">Already added</span>
                            )}
                          </button>
                        );
                      })}
                    </div>
                    <div className="flex justify-end mt-6">
                      <Button
                        variant="secondary"
                        onClick={() => {
                          setShowTagAssignModal(false);
                          setAssetToTag(null);
                        }}
                      >
                        Close
                      </Button>
                    </div>
                  </>
                )}
              </div>
            </div>
          </div>
        )}
      </div>
    </Layout>
  );
};

export default AssetsPage;
