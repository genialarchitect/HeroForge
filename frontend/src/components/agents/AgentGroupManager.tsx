import React, { useState } from 'react';
import {
  Folder,
  Plus,
  Trash2,
  Edit2,
  Server,
  Network,
  ChevronDown,
  ChevronRight,
  X,
} from 'lucide-react';
import { toast } from 'react-toastify';
import { agentAPI } from '../../services/api';
import Button from '../ui/Button';
import type {
  AgentGroupWithCount,
  AgentGroupWithAgents,
  AgentWithGroups,
  CreateAgentGroupRequest,
  UpdateAgentGroupRequest,
} from '../../types';

interface AgentGroupManagerProps {
  groups: AgentGroupWithCount[];
  agents: AgentWithGroups[];
  onRefresh: () => void;
}

const predefinedColors = [
  '#22c55e', // green
  '#3b82f6', // blue
  '#f97316', // orange
  '#8b5cf6', // violet
  '#ec4899', // pink
  '#eab308', // yellow
  '#06b6d4', // cyan
  '#f43f5e', // rose
];

const AgentGroupManager: React.FC<AgentGroupManagerProps> = ({
  groups,
  agents,
  onRefresh,
}) => {
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [editingGroup, setEditingGroup] = useState<AgentGroupWithAgents | null>(null);
  const [expandedGroups, setExpandedGroups] = useState<Set<string>>(new Set());
  const [loadingGroup, setLoadingGroup] = useState<string | null>(null);
  const [groupDetails, setGroupDetails] = useState<Map<string, AgentGroupWithAgents>>(new Map());

  // Form state
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [networkRanges, setNetworkRanges] = useState('');
  const [color, setColor] = useState(predefinedColors[0]);
  const [saving, setSaving] = useState(false);

  const toggleGroupExpand = async (groupId: string) => {
    const newExpanded = new Set(expandedGroups);
    if (newExpanded.has(groupId)) {
      newExpanded.delete(groupId);
    } else {
      newExpanded.add(groupId);
      // Load group details if not already loaded
      if (!groupDetails.has(groupId)) {
        setLoadingGroup(groupId);
        try {
          const response = await agentAPI.groups.get(groupId);
          setGroupDetails(new Map(groupDetails.set(groupId, response.data)));
        } catch (error) {
          toast.error('Failed to load group details');
        } finally {
          setLoadingGroup(null);
        }
      }
    }
    setExpandedGroups(newExpanded);
  };

  const resetForm = () => {
    setName('');
    setDescription('');
    setNetworkRanges('');
    setColor(predefinedColors[0]);
  };

  const handleCreateGroup = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) {
      toast.error('Group name is required');
      return;
    }

    setSaving(true);
    try {
      const ranges = networkRanges
        .split(',')
        .map((r) => r.trim())
        .filter((r) => r.length > 0);

      const data: CreateAgentGroupRequest = {
        name: name.trim(),
        description: description.trim() || undefined,
        network_ranges: ranges.length > 0 ? ranges : undefined,
        color,
      };
      await agentAPI.groups.create(data);
      toast.success('Group created successfully');
      resetForm();
      setShowCreateForm(false);
      onRefresh();
    } catch (error: unknown) {
      const err = error as { response?: { data?: { message?: string } } };
      toast.error(err.response?.data?.message || 'Failed to create group');
    } finally {
      setSaving(false);
    }
  };

  const handleUpdateGroup = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!editingGroup || !name.trim()) {
      toast.error('Group name is required');
      return;
    }

    setSaving(true);
    try {
      const ranges = networkRanges
        .split(',')
        .map((r) => r.trim())
        .filter((r) => r.length > 0);

      const data: UpdateAgentGroupRequest = {
        name: name.trim(),
        description: description.trim() || undefined,
        network_ranges: ranges.length > 0 ? ranges : undefined,
        color,
      };
      await agentAPI.groups.update(editingGroup.id, data);
      toast.success('Group updated successfully');
      resetForm();
      setEditingGroup(null);
      onRefresh();
    } catch (error: unknown) {
      const err = error as { response?: { data?: { message?: string } } };
      toast.error(err.response?.data?.message || 'Failed to update group');
    } finally {
      setSaving(false);
    }
  };

  const handleDeleteGroup = async (groupId: string) => {
    if (!confirm('Are you sure you want to delete this group?')) return;

    try {
      await agentAPI.groups.delete(groupId);
      toast.success('Group deleted');
      onRefresh();
    } catch (error: unknown) {
      const err = error as { response?: { data?: { message?: string } } };
      toast.error(err.response?.data?.message || 'Failed to delete group');
    }
  };

  const handleRemoveAgentFromGroup = async (groupId: string, agentId: string) => {
    try {
      await agentAPI.groups.removeAgent(groupId, agentId);
      toast.success('Agent removed from group');
      // Refresh the group details
      const response = await agentAPI.groups.get(groupId);
      setGroupDetails(new Map(groupDetails.set(groupId, response.data)));
      onRefresh();
    } catch (error: unknown) {
      const err = error as { response?: { data?: { message?: string } } };
      toast.error(err.response?.data?.message || 'Failed to remove agent');
    }
  };

  const handleAssignAgentToGroup = async (groupId: string, agentId: string) => {
    try {
      await agentAPI.groups.assignAgents(groupId, { agent_ids: [agentId] });
      toast.success('Agent added to group');
      // Refresh the group details
      const response = await agentAPI.groups.get(groupId);
      setGroupDetails(new Map(groupDetails.set(groupId, response.data)));
      onRefresh();
    } catch (error: unknown) {
      const err = error as { response?: { data?: { message?: string } } };
      toast.error(err.response?.data?.message || 'Failed to add agent');
    }
  };

  const startEdit = (group: AgentGroupWithCount) => {
    const details = groupDetails.get(group.id);
    setName(group.name);
    setDescription(group.description || '');
    setColor(group.color);
    // Parse network ranges if available
    if (details && details.network_ranges) {
      try {
        const ranges = JSON.parse(details.network_ranges);
        setNetworkRanges(ranges.join(', '));
      } catch {
        setNetworkRanges('');
      }
    } else {
      setNetworkRanges('');
    }
    setEditingGroup(details || (group as unknown as AgentGroupWithAgents));
    setShowCreateForm(false);
  };

  const getAvailableAgentsForGroup = (group: AgentGroupWithAgents | AgentGroupWithCount) => {
    const details = groupDetails.get(group.id);
    if (!details) return agents;
    const memberIds = new Set(details.agents.map((a) => a.id));
    return agents.filter((a) => !memberIds.has(a.id));
  };

  const GroupForm = ({ isEdit = false }: { isEdit?: boolean }) => (
    <form
      onSubmit={isEdit ? handleUpdateGroup : handleCreateGroup}
      className="p-4 bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg mb-4"
    >
      <h4 className="text-sm font-medium text-slate-900 dark:text-white mb-4">
        {isEdit ? 'Edit Group' : 'Create New Group'}
      </h4>

      <div className="grid grid-cols-2 gap-4 mb-4">
        <div>
          <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
            Group Name *
          </label>
          <input
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g., Production Scanners"
            className="w-full px-3 py-2 bg-light-bg dark:bg-dark-bg border border-light-border dark:border-dark-border rounded-lg text-slate-900 dark:text-white focus:ring-2 focus:ring-primary focus:border-primary"
            required
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
            Color
          </label>
          <div className="flex items-center gap-2">
            {predefinedColors.map((c) => (
              <button
                key={c}
                type="button"
                onClick={() => setColor(c)}
                className={`w-6 h-6 rounded-full border-2 ${
                  color === c ? 'border-slate-900 dark:border-white' : 'border-transparent'
                }`}
                style={{ backgroundColor: c }}
              />
            ))}
          </div>
        </div>
      </div>

      <div className="mb-4">
        <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
          Description
        </label>
        <input
          type="text"
          value={description}
          onChange={(e) => setDescription(e.target.value)}
          placeholder="Optional description"
          className="w-full px-3 py-2 bg-light-bg dark:bg-dark-bg border border-light-border dark:border-dark-border rounded-lg text-slate-900 dark:text-white focus:ring-2 focus:ring-primary focus:border-primary"
        />
      </div>

      <div className="mb-4">
        <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
          Network Ranges
        </label>
        <input
          type="text"
          value={networkRanges}
          onChange={(e) => setNetworkRanges(e.target.value)}
          placeholder="e.g., 192.168.1.0/24, 10.0.0.0/8 (comma-separated)"
          className="w-full px-3 py-2 bg-light-bg dark:bg-dark-bg border border-light-border dark:border-dark-border rounded-lg text-slate-900 dark:text-white focus:ring-2 focus:ring-primary focus:border-primary"
        />
        <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
          Define which network ranges this group is responsible for scanning
        </p>
      </div>

      <div className="flex justify-end gap-2">
        <Button
          variant="secondary"
          size="sm"
          onClick={() => {
            resetForm();
            setShowCreateForm(false);
            setEditingGroup(null);
          }}
          disabled={saving}
        >
          Cancel
        </Button>
        <Button type="submit" size="sm" loading={saving}>
          {isEdit ? 'Update Group' : 'Create Group'}
        </Button>
      </div>
    </form>
  );

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h3 className="text-lg font-semibold text-slate-900 dark:text-white flex items-center gap-2">
          <Folder className="h-5 w-5 text-primary" />
          Agent Groups
        </h3>
        {!showCreateForm && !editingGroup && (
          <Button size="sm" onClick={() => setShowCreateForm(true)}>
            <Plus className="h-4 w-4 mr-1" />
            New Group
          </Button>
        )}
      </div>

      {/* Create Form */}
      {showCreateForm && <GroupForm isEdit={false} />}

      {/* Edit Form */}
      {editingGroup && <GroupForm isEdit={true} />}

      {/* Groups List */}
      {groups.length === 0 ? (
        <div className="text-center py-8 bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg">
          <Folder className="h-12 w-12 text-slate-400 mx-auto mb-3" />
          <p className="text-slate-600 dark:text-slate-400">No groups created yet</p>
          <p className="text-sm text-slate-500 dark:text-slate-500 mt-1">
            Create a group to organize your agents
          </p>
        </div>
      ) : (
        <div className="space-y-2">
          {groups.map((group) => {
            const details = groupDetails.get(group.id);
            const isExpanded = expandedGroups.has(group.id);
            const isLoading = loadingGroup === group.id;

            return (
              <div
                key={group.id}
                className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg overflow-hidden"
              >
                {/* Group Header */}
                <div
                  className="flex items-center justify-between p-4 cursor-pointer hover:bg-light-hover dark:hover:bg-dark-hover"
                  onClick={() => toggleGroupExpand(group.id)}
                >
                  <div className="flex items-center gap-3">
                    <button className="p-1">
                      {isExpanded ? (
                        <ChevronDown className="h-4 w-4 text-slate-500" />
                      ) : (
                        <ChevronRight className="h-4 w-4 text-slate-500" />
                      )}
                    </button>
                    <div
                      className="w-3 h-3 rounded-full"
                      style={{ backgroundColor: group.color }}
                    />
                    <div>
                      <h4 className="font-medium text-slate-900 dark:text-white">{group.name}</h4>
                      {group.description && (
                        <p className="text-sm text-slate-500 dark:text-slate-400">
                          {group.description}
                        </p>
                      )}
                    </div>
                  </div>

                  <div className="flex items-center gap-4">
                    <span className="text-sm text-slate-500 dark:text-slate-400 flex items-center gap-1">
                      <Server className="h-4 w-4" />
                      {group.agent_count} agent{group.agent_count !== 1 ? 's' : ''}
                    </span>
                    <div className="flex items-center gap-1">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          startEdit(group);
                        }}
                        className="p-1 hover:bg-light-hover dark:hover:bg-dark-hover rounded"
                        title="Edit group"
                      >
                        <Edit2 className="h-4 w-4 text-slate-500" />
                      </button>
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          handleDeleteGroup(group.id);
                        }}
                        className="p-1 hover:bg-red-500/10 rounded text-red-500"
                        title="Delete group"
                      >
                        <Trash2 className="h-4 w-4" />
                      </button>
                    </div>
                  </div>
                </div>

                {/* Group Details */}
                {isExpanded && (
                  <div className="border-t border-light-border dark:border-dark-border p-4">
                    {isLoading ? (
                      <div className="flex items-center justify-center py-4">
                        <div className="w-5 h-5 border-2 border-primary border-t-transparent rounded-full animate-spin" />
                      </div>
                    ) : details ? (
                      <>
                        {/* Network Ranges */}
                        {details.network_ranges && (
                          <div className="mb-4">
                            <p className="text-xs font-medium text-slate-500 dark:text-slate-400 mb-2">
                              Network Ranges
                            </p>
                            <div className="flex flex-wrap gap-2">
                              {(() => {
                                try {
                                  const ranges = JSON.parse(details.network_ranges);
                                  return ranges.map((range: string) => (
                                    <span
                                      key={range}
                                      className="inline-flex items-center gap-1 px-2 py-1 rounded text-xs bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300"
                                    >
                                      <Network className="h-3 w-3" />
                                      {range}
                                    </span>
                                  ));
                                } catch {
                                  return null;
                                }
                              })()}
                            </div>
                          </div>
                        )}

                        {/* Agents */}
                        {details.agents.length === 0 ? (
                          <p className="text-sm text-slate-500 dark:text-slate-400 text-center py-2">
                            No agents in this group
                          </p>
                        ) : (
                          <div className="grid grid-cols-2 md:grid-cols-3 gap-2 mb-4">
                            {details.agents.map((agent) => (
                              <div
                                key={agent.id}
                                className="flex items-center justify-between p-2 bg-light-bg dark:bg-dark-bg rounded"
                              >
                                <div className="flex items-center gap-2">
                                  <div
                                    className={`w-2 h-2 rounded-full ${
                                      agent.status === 'online' || agent.status === 'busy'
                                        ? 'bg-green-500'
                                        : 'bg-gray-500'
                                    }`}
                                  />
                                  <span className="text-sm font-medium text-slate-900 dark:text-white truncate">
                                    {agent.name}
                                  </span>
                                </div>
                                <button
                                  onClick={() => handleRemoveAgentFromGroup(group.id, agent.id)}
                                  className="p-1 hover:bg-red-500/10 rounded text-red-500"
                                  title="Remove from group"
                                >
                                  <X className="h-3 w-3" />
                                </button>
                              </div>
                            ))}
                          </div>
                        )}

                        {/* Add Agent */}
                        {getAvailableAgentsForGroup(details).length > 0 && (
                          <div>
                            <select
                              onChange={(e) => {
                                if (e.target.value) {
                                  handleAssignAgentToGroup(group.id, e.target.value);
                                  e.target.value = '';
                                }
                              }}
                              className="w-full px-3 py-2 bg-light-bg dark:bg-dark-bg border border-light-border dark:border-dark-border rounded-lg text-sm text-slate-900 dark:text-white"
                              defaultValue=""
                            >
                              <option value="">Add an agent to this group...</option>
                              {getAvailableAgentsForGroup(details).map((agent) => (
                                <option key={agent.id} value={agent.id}>
                                  {agent.name} ({agent.status})
                                </option>
                              ))}
                            </select>
                          </div>
                        )}
                      </>
                    ) : null}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};

export default AgentGroupManager;
