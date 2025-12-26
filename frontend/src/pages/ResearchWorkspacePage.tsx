import React, { useState, useEffect } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { toast } from 'react-toastify';
import {
  Folder,
  Plus,
  Search,
  ArrowLeft,
  ExternalLink,
  FileText,
  Clock,
  Link2,
  Bug,
  Code,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Play,
  Download,
  Trash2,
  Edit,
  RefreshCw,
  ChevronRight,
  Filter,
  Calendar,
  BookOpen,
  Target,
  Shield,
} from 'lucide-react';
import Layout from '../components/layout/Layout';
import {
  exploitResearchAPI,
  ResearchWorkspace,
  ResearchNote,
  TimelineEvent,
} from '../services/api';

// Workspace status colors
const statusColors: Record<string, string> = {
  active: 'bg-green-500/10 text-green-500 border-green-500/20',
  in_progress: 'bg-blue-500/10 text-blue-500 border-blue-500/20',
  archived: 'bg-gray-500/10 text-gray-400 border-gray-500/20',
  completed: 'bg-purple-500/10 text-purple-500 border-purple-500/20',
};

// Note type colors
const noteTypeColors: Record<string, string> = {
  analysis: 'bg-blue-500/10 text-blue-500',
  poc_notes: 'bg-green-500/10 text-green-500',
  mitigation: 'bg-yellow-500/10 text-yellow-500',
  reference: 'bg-purple-500/10 text-purple-500',
  general: 'bg-gray-500/10 text-gray-400',
};

// Timeline event icons
const timelineIcons: Record<string, React.ReactNode> = {
  created: <Folder className="h-4 w-4 text-green-500" />,
  note_added: <FileText className="h-4 w-4 text-blue-500" />,
  exploit_linked: <Bug className="h-4 w-4 text-red-500" />,
  poc_linked: <Code className="h-4 w-4 text-cyan-500" />,
  status_changed: <RefreshCw className="h-4 w-4 text-yellow-500" />,
  exported: <Download className="h-4 w-4 text-purple-500" />,
};

const ResearchWorkspacePage: React.FC = () => {
  const queryClient = useQueryClient();
  const [view, setView] = useState<'list' | 'detail'>('list');
  const [selectedWorkspaceId, setSelectedWorkspaceId] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'overview' | 'notes' | 'exploits' | 'pocs' | 'timeline'>('overview');
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [showAddNoteModal, setShowAddNoteModal] = useState(false);
  const [editingNote, setEditingNote] = useState<ResearchNote | null>(null);

  // Fetch workspaces
  const { data: workspacesData, isLoading: loadingWorkspaces, refetch: refetchWorkspaces } = useQuery({
    queryKey: ['research-workspaces'],
    queryFn: () => exploitResearchAPI.listWorkspaces(),
  });

  // Fetch selected workspace
  const { data: selectedWorkspace, isLoading: loadingWorkspace } = useQuery({
    queryKey: ['research-workspace', selectedWorkspaceId],
    queryFn: () => selectedWorkspaceId ? exploitResearchAPI.getWorkspace(selectedWorkspaceId) : null,
    enabled: !!selectedWorkspaceId,
  });

  // Fetch workspace timeline
  const { data: timelineData, isLoading: loadingTimeline } = useQuery({
    queryKey: ['workspace-timeline', selectedWorkspaceId],
    queryFn: () => selectedWorkspaceId ? exploitResearchAPI.getWorkspaceTimeline(selectedWorkspaceId) : null,
    enabled: !!selectedWorkspaceId && activeTab === 'timeline',
  });

  const workspaces = workspacesData?.data?.workspaces || [];
  const workspace = selectedWorkspace?.data;
  const timeline = timelineData?.data?.events || [];

  // Filter workspaces
  const filteredWorkspaces = workspaces.filter((ws) => {
    const matchesSearch = searchQuery === '' ||
      ws.cve_id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      ws.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      ws.description?.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesStatus = statusFilter === 'all' || ws.status === statusFilter;
    return matchesSearch && matchesStatus;
  });

  // Delete mutation
  const deleteMutation = useMutation({
    mutationFn: (id: string) => exploitResearchAPI.deleteWorkspace(id),
    onSuccess: () => {
      toast.success('Workspace deleted');
      queryClient.invalidateQueries({ queryKey: ['research-workspaces'] });
      if (selectedWorkspaceId) {
        setSelectedWorkspaceId(null);
        setView('list');
      }
    },
    onError: () => toast.error('Failed to delete workspace'),
  });

  // Update mutation
  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<{ title: string; description: string; status: string }> }) =>
      exploitResearchAPI.updateWorkspace(id, data),
    onSuccess: () => {
      toast.success('Workspace updated');
      queryClient.invalidateQueries({ queryKey: ['research-workspace', selectedWorkspaceId] });
      queryClient.invalidateQueries({ queryKey: ['research-workspaces'] });
    },
    onError: () => toast.error('Failed to update workspace'),
  });

  // Export workspace
  const handleExport = async (id: string) => {
    try {
      const response = await exploitResearchAPI.exportWorkspace(id);
      const blob = new Blob([response.data], { type: 'text/markdown' });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `workspace-${workspace?.cve_id || id}.md`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.URL.revokeObjectURL(url);
      toast.success('Workspace exported');
    } catch {
      toast.error('Failed to export workspace');
    }
  };

  const handleSelectWorkspace = (id: string) => {
    setSelectedWorkspaceId(id);
    setView('detail');
    setActiveTab('overview');
  };

  // Create workspace modal component
  const CreateWorkspaceModal: React.FC<{ onClose: () => void }> = ({ onClose }) => {
    const [cveId, setCveId] = useState('');
    const [title, setTitle] = useState('');
    const [description, setDescription] = useState('');
    const [loading, setLoading] = useState(false);

    const handleSubmit = async (e: React.FormEvent) => {
      e.preventDefault();
      if (!cveId.trim()) {
        toast.error('CVE ID is required');
        return;
      }
      setLoading(true);
      try {
        const response = await exploitResearchAPI.createWorkspace({
          cve_id: cveId.trim().toUpperCase(),
          title: title.trim() || undefined,
          description: description.trim() || undefined,
        });
        toast.success('Workspace created');
        queryClient.invalidateQueries({ queryKey: ['research-workspaces'] });
        const newId = response.data?.id;
        if (newId) {
          setSelectedWorkspaceId(newId);
          setView('detail');
        }
        onClose();
      } catch {
        toast.error('Failed to create workspace');
      } finally {
        setLoading(false);
      }
    };

    return (
      <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
        <div className="bg-gray-800 rounded-lg p-6 w-full max-w-lg mx-4">
          <h3 className="text-lg font-semibold text-white mb-4">Create Research Workspace</h3>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1">CVE ID *</label>
              <input
                type="text"
                value={cveId}
                onChange={(e) => setCveId(e.target.value)}
                placeholder="CVE-2024-12345"
                className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-white placeholder-gray-400"
                required
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1">Title</label>
              <input
                type="text"
                value={title}
                onChange={(e) => setTitle(e.target.value)}
                placeholder="Research title (optional)"
                className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-white placeholder-gray-400"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1">Description</label>
              <textarea
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder="Brief description of research objectives..."
                rows={3}
                className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-white placeholder-gray-400"
              />
            </div>
            <div className="flex justify-end gap-3 pt-4">
              <button
                type="button"
                onClick={onClose}
                className="px-4 py-2 text-gray-400 hover:text-white transition-colors"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={loading}
                className="px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded transition-colors disabled:opacity-50"
              >
                {loading ? 'Creating...' : 'Create Workspace'}
              </button>
            </div>
          </form>
        </div>
      </div>
    );
  };

  // Add/Edit Note modal
  const NoteModal: React.FC<{ note?: ResearchNote | null; onClose: () => void }> = ({ note, onClose }) => {
    const [title, setTitle] = useState(note?.title || '');
    const [content, setContent] = useState(note?.content || '');
    const [noteType, setNoteType] = useState(note?.note_type || 'general');
    const [references, setReferences] = useState((note?.references || []).join('\n'));
    const [loading, setLoading] = useState(false);

    const handleSubmit = async (e: React.FormEvent) => {
      e.preventDefault();
      if (!title.trim() || !content.trim()) {
        toast.error('Title and content are required');
        return;
      }
      setLoading(true);
      try {
        if (note) {
          // Update existing note - API only supports title, content, note_type
          await exploitResearchAPI.updateNote(note.id, {
            title: title.trim(),
            content: content.trim(),
            note_type: noteType,
          });
          toast.success('Note updated');
        } else if (selectedWorkspaceId) {
          // Create new note first
          const refList = references.split('\n').filter(r => r.trim());
          const noteResult = await exploitResearchAPI.createNote({
            title: title.trim(),
            content: content.trim(),
            note_type: noteType,
            references: refList,
          });
          // Then link it to the workspace
          const noteId = (noteResult.data as { id?: string })?.id;
          if (noteId) {
            await exploitResearchAPI.addItemToWorkspace(selectedWorkspaceId, {
              item_type: 'note',
              item_id: noteId,
            });
          }
          toast.success('Note added');
        }
        queryClient.invalidateQueries({ queryKey: ['research-workspace', selectedWorkspaceId] });
        onClose();
      } catch {
        toast.error(note ? 'Failed to update note' : 'Failed to add note');
      } finally {
        setLoading(false);
      }
    };

    return (
      <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
        <div className="bg-gray-800 rounded-lg p-6 w-full max-w-2xl mx-4 max-h-[90vh] overflow-y-auto">
          <h3 className="text-lg font-semibold text-white mb-4">
            {note ? 'Edit Note' : 'Add Research Note'}
          </h3>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-1">Title *</label>
                <input
                  type="text"
                  value={title}
                  onChange={(e) => setTitle(e.target.value)}
                  placeholder="Note title"
                  className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-white placeholder-gray-400"
                  required
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-1">Type</label>
                <select
                  value={noteType}
                  onChange={(e) => setNoteType(e.target.value)}
                  className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-white"
                >
                  <option value="general">General</option>
                  <option value="analysis">Analysis</option>
                  <option value="poc_notes">PoC Notes</option>
                  <option value="mitigation">Mitigation</option>
                  <option value="reference">Reference</option>
                </select>
              </div>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1">Content *</label>
              <textarea
                value={content}
                onChange={(e) => setContent(e.target.value)}
                placeholder="Note content (supports Markdown)"
                rows={10}
                className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-white placeholder-gray-400 font-mono text-sm"
                required
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1">References (one per line)</label>
              <textarea
                value={references}
                onChange={(e) => setReferences(e.target.value)}
                placeholder="https://example.com/reference&#10;https://cve.mitre.org/..."
                rows={3}
                className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-white placeholder-gray-400 font-mono text-sm"
              />
            </div>
            <div className="flex justify-end gap-3 pt-4">
              <button
                type="button"
                onClick={onClose}
                className="px-4 py-2 text-gray-400 hover:text-white transition-colors"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={loading}
                className="px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded transition-colors disabled:opacity-50"
              >
                {loading ? 'Saving...' : note ? 'Update Note' : 'Add Note'}
              </button>
            </div>
          </form>
        </div>
      </div>
    );
  };

  // List view
  const renderListView = () => (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Research Workspaces</h1>
          <p className="text-gray-400 text-sm mt-1">
            Organize and track your CVE research with notes, exploits, and PoCs
          </p>
        </div>
        <button
          onClick={() => setShowCreateModal(true)}
          className="flex items-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg transition-colors"
        >
          <Plus className="h-4 w-4" />
          New Workspace
        </button>
      </div>

      {/* Filters */}
      <div className="flex flex-col sm:flex-row gap-4">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search by CVE, title, or description..."
            className="w-full bg-gray-800 border border-gray-700 rounded-lg pl-10 pr-4 py-2 text-white placeholder-gray-400 focus:border-cyan-500 focus:outline-none"
          />
        </div>
        <div className="flex items-center gap-2">
          <Filter className="h-4 w-4 text-gray-400" />
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-white focus:border-cyan-500 focus:outline-none"
          >
            <option value="all">All Status</option>
            <option value="active">Active</option>
            <option value="in_progress">In Progress</option>
            <option value="completed">Completed</option>
            <option value="archived">Archived</option>
          </select>
        </div>
        <button
          onClick={() => refetchWorkspaces()}
          className="flex items-center gap-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded-lg transition-colors"
        >
          <RefreshCw className="h-4 w-4" />
          Refresh
        </button>
      </div>

      {/* Workspaces Grid */}
      {loadingWorkspaces ? (
        <div className="flex items-center justify-center py-12">
          <RefreshCw className="h-8 w-8 text-cyan-500 animate-spin" />
        </div>
      ) : filteredWorkspaces.length === 0 ? (
        <div className="bg-gray-800 rounded-lg border border-gray-700 p-12 text-center">
          <Folder className="h-12 w-12 text-gray-600 mx-auto mb-4" />
          <p className="text-gray-400">
            {searchQuery || statusFilter !== 'all' ? 'No workspaces match your filters' : 'No research workspaces yet'}
          </p>
          <button
            onClick={() => setShowCreateModal(true)}
            className="mt-4 text-cyan-400 hover:text-cyan-300"
          >
            Create your first workspace
          </button>
        </div>
      ) : (
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          {filteredWorkspaces.map((ws) => (
            <div
              key={ws.id}
              className="bg-gray-800 rounded-lg border border-gray-700 p-4 hover:border-gray-600 transition-colors cursor-pointer group"
              onClick={() => handleSelectWorkspace(ws.id)}
            >
              <div className="flex items-start justify-between mb-3">
                <div className="flex items-center gap-2">
                  <Shield className="h-5 w-5 text-cyan-500" />
                  <span className="text-cyan-400 font-mono text-sm">{ws.cve_id}</span>
                </div>
                <span className={`px-2 py-0.5 text-xs rounded border ${statusColors[ws.status] || statusColors.active}`}>
                  {ws.status}
                </span>
              </div>
              <h3 className="text-white font-medium mb-2 group-hover:text-cyan-400 transition-colors">
                {ws.title || ws.cve_id}
              </h3>
              {ws.description && (
                <p className="text-gray-400 text-sm mb-4 line-clamp-2">{ws.description}</p>
              )}
              <div className="flex items-center justify-between text-xs text-gray-500">
                <div className="flex items-center gap-3">
                  <span className="flex items-center gap-1">
                    <FileText className="h-3 w-3" />
                    {ws.notes?.length || 0} notes
                  </span>
                  <span className="flex items-center gap-1">
                    <Bug className="h-3 w-3" />
                    {ws.linked_exploits?.length || 0} exploits
                  </span>
                  <span className="flex items-center gap-1">
                    <Code className="h-3 w-3" />
                    {ws.linked_pocs?.length || 0} PoCs
                  </span>
                </div>
                <ChevronRight className="h-4 w-4 text-gray-600 group-hover:text-cyan-500 transition-colors" />
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );

  // Detail view
  const renderDetailView = () => {
    if (loadingWorkspace || !workspace) {
      return (
        <div className="flex items-center justify-center py-12">
          <RefreshCw className="h-8 w-8 text-cyan-500 animate-spin" />
        </div>
      );
    }

    return (
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <button
              onClick={() => {
                setView('list');
                setSelectedWorkspaceId(null);
              }}
              className="text-gray-400 hover:text-white transition-colors"
            >
              <ArrowLeft className="h-5 w-5" />
            </button>
            <div>
              <div className="flex items-center gap-3">
                <span className="text-cyan-400 font-mono">{workspace.cve_id}</span>
                <span className={`px-2 py-0.5 text-xs rounded border ${statusColors[workspace.status] || statusColors.active}`}>
                  {workspace.status}
                </span>
              </div>
              <h1 className="text-xl font-bold text-white mt-1">{workspace.title || workspace.cve_id}</h1>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <select
              value={workspace.status}
              onChange={(e) => updateMutation.mutate({ id: workspace.id, data: { status: e.target.value } })}
              className="bg-gray-700 border border-gray-600 rounded px-3 py-1.5 text-sm text-white"
            >
              <option value="active">Active</option>
              <option value="in_progress">In Progress</option>
              <option value="completed">Completed</option>
              <option value="archived">Archived</option>
            </select>
            <button
              onClick={() => handleExport(workspace.id)}
              className="flex items-center gap-2 px-3 py-1.5 bg-gray-700 hover:bg-gray-600 text-white rounded transition-colors text-sm"
            >
              <Download className="h-4 w-4" />
              Export
            </button>
            <button
              onClick={() => {
                if (confirm('Delete this workspace? This cannot be undone.')) {
                  deleteMutation.mutate(workspace.id);
                }
              }}
              className="flex items-center gap-2 px-3 py-1.5 bg-red-600/10 hover:bg-red-600/20 text-red-400 rounded transition-colors text-sm"
            >
              <Trash2 className="h-4 w-4" />
              Delete
            </button>
          </div>
        </div>

        {/* Tabs */}
        <div className="border-b border-gray-700">
          <nav className="flex gap-4">
            {(['overview', 'notes', 'exploits', 'pocs', 'timeline'] as const).map((tab) => (
              <button
                key={tab}
                onClick={() => setActiveTab(tab)}
                className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
                  activeTab === tab
                    ? 'text-cyan-400 border-cyan-400'
                    : 'text-gray-400 border-transparent hover:text-gray-300'
                }`}
              >
                {tab.charAt(0).toUpperCase() + tab.slice(1).replace('_', ' ')}
              </button>
            ))}
          </nav>
        </div>

        {/* Tab Content */}
        <div className="bg-gray-800 rounded-lg border border-gray-700 p-6">
          {activeTab === 'overview' && (
            <div className="space-y-6">
              {/* Description */}
              <div>
                <h3 className="text-sm font-medium text-gray-400 mb-2">Description</h3>
                <p className="text-white">{workspace.description || 'No description provided.'}</p>
              </div>

              {/* Stats */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="bg-gray-700/50 rounded-lg p-4">
                  <div className="flex items-center gap-2 text-gray-400 text-sm mb-1">
                    <FileText className="h-4 w-4" />
                    Notes
                  </div>
                  <div className="text-2xl font-bold text-white">{workspace.notes?.length || 0}</div>
                </div>
                <div className="bg-gray-700/50 rounded-lg p-4">
                  <div className="flex items-center gap-2 text-gray-400 text-sm mb-1">
                    <Bug className="h-4 w-4" />
                    Linked Exploits
                  </div>
                  <div className="text-2xl font-bold text-white">{workspace.linked_exploits?.length || 0}</div>
                </div>
                <div className="bg-gray-700/50 rounded-lg p-4">
                  <div className="flex items-center gap-2 text-gray-400 text-sm mb-1">
                    <Code className="h-4 w-4" />
                    Linked PoCs
                  </div>
                  <div className="text-2xl font-bold text-white">{workspace.linked_pocs?.length || 0}</div>
                </div>
                <div className="bg-gray-700/50 rounded-lg p-4">
                  <div className="flex items-center gap-2 text-gray-400 text-sm mb-1">
                    <Clock className="h-4 w-4" />
                    Timeline Events
                  </div>
                  <div className="text-2xl font-bold text-white">{workspace.timeline_events?.length || 0}</div>
                </div>
              </div>

              {/* Timestamps */}
              <div className="flex items-center gap-6 text-sm text-gray-400">
                <div className="flex items-center gap-2">
                  <Calendar className="h-4 w-4" />
                  Created: {new Date(workspace.created_at).toLocaleDateString()}
                </div>
                <div className="flex items-center gap-2">
                  <RefreshCw className="h-4 w-4" />
                  Updated: {new Date(workspace.updated_at).toLocaleDateString()}
                </div>
              </div>

              {/* Quick Links */}
              <div>
                <h3 className="text-sm font-medium text-gray-400 mb-2">External Resources</h3>
                <div className="flex flex-wrap gap-2">
                  <a
                    href={`https://nvd.nist.gov/vuln/detail/${workspace.cve_id}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center gap-1 px-3 py-1.5 bg-gray-700 hover:bg-gray-600 text-gray-300 rounded text-sm transition-colors"
                  >
                    <ExternalLink className="h-3 w-3" />
                    NVD
                  </a>
                  <a
                    href={`https://cve.mitre.org/cgi-bin/cvename.cgi?name=${workspace.cve_id}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center gap-1 px-3 py-1.5 bg-gray-700 hover:bg-gray-600 text-gray-300 rounded text-sm transition-colors"
                  >
                    <ExternalLink className="h-3 w-3" />
                    MITRE
                  </a>
                  <a
                    href={`https://www.exploit-db.com/search?cve=${workspace.cve_id.replace('CVE-', '')}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center gap-1 px-3 py-1.5 bg-gray-700 hover:bg-gray-600 text-gray-300 rounded text-sm transition-colors"
                  >
                    <ExternalLink className="h-3 w-3" />
                    Exploit-DB
                  </a>
                  <a
                    href={`https://github.com/search?q=${workspace.cve_id}&type=repositories`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center gap-1 px-3 py-1.5 bg-gray-700 hover:bg-gray-600 text-gray-300 rounded text-sm transition-colors"
                  >
                    <ExternalLink className="h-3 w-3" />
                    GitHub
                  </a>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'notes' && (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="text-lg font-medium text-white">Research Notes</h3>
                <button
                  onClick={() => setShowAddNoteModal(true)}
                  className="flex items-center gap-2 px-3 py-1.5 bg-cyan-600 hover:bg-cyan-700 text-white rounded transition-colors text-sm"
                >
                  <Plus className="h-4 w-4" />
                  Add Note
                </button>
              </div>
              {(workspace.notes?.length || 0) === 0 ? (
                <div className="text-center py-8 text-gray-400">
                  <BookOpen className="h-8 w-8 mx-auto mb-2 opacity-50" />
                  <p>No notes yet. Add your first research note.</p>
                </div>
              ) : (
                <div className="space-y-4">
                  {workspace.notes?.map((note) => (
                    <div key={note.id} className="bg-gray-700/50 rounded-lg p-4">
                      <div className="flex items-start justify-between mb-2">
                        <div className="flex items-center gap-2">
                          <h4 className="font-medium text-white">{note.title}</h4>
                          <span className={`px-2 py-0.5 text-xs rounded ${noteTypeColors[note.note_type] || noteTypeColors.general}`}>
                            {note.note_type}
                          </span>
                        </div>
                        <div className="flex items-center gap-2">
                          <button
                            onClick={() => {
                              setEditingNote(note);
                              setShowAddNoteModal(true);
                            }}
                            className="text-gray-400 hover:text-white transition-colors"
                          >
                            <Edit className="h-4 w-4" />
                          </button>
                          <button
                            onClick={async () => {
                              if (confirm('Delete this note?')) {
                                try {
                                  await exploitResearchAPI.deleteNote(note.id);
                                  toast.success('Note deleted');
                                  queryClient.invalidateQueries({ queryKey: ['research-workspace', selectedWorkspaceId] });
                                } catch {
                                  toast.error('Failed to delete note');
                                }
                              }
                            }}
                            className="text-gray-400 hover:text-red-400 transition-colors"
                          >
                            <Trash2 className="h-4 w-4" />
                          </button>
                        </div>
                      </div>
                      <p className="text-gray-300 text-sm whitespace-pre-wrap">{note.content}</p>
                      {note.references?.length > 0 && (
                        <div className="mt-3 pt-3 border-t border-gray-600">
                          <div className="text-xs text-gray-400 mb-1">References:</div>
                          <div className="flex flex-wrap gap-2">
                            {note.references.map((ref, idx) => (
                              <a
                                key={idx}
                                href={ref}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="text-xs text-cyan-400 hover:text-cyan-300"
                              >
                                <ExternalLink className="h-3 w-3 inline mr-1" />
                                {ref.length > 50 ? ref.substring(0, 50) + '...' : ref}
                              </a>
                            ))}
                          </div>
                        </div>
                      )}
                      <div className="mt-2 text-xs text-gray-500">
                        {new Date(note.created_at).toLocaleString()}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {activeTab === 'exploits' && (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="text-lg font-medium text-white">Linked Exploits</h3>
                <button className="flex items-center gap-2 px-3 py-1.5 bg-cyan-600 hover:bg-cyan-700 text-white rounded transition-colors text-sm">
                  <Link2 className="h-4 w-4" />
                  Link Exploit
                </button>
              </div>
              {(workspace.linked_exploits?.length || 0) === 0 ? (
                <div className="text-center py-8 text-gray-400">
                  <Bug className="h-8 w-8 mx-auto mb-2 opacity-50" />
                  <p>No exploits linked. Link exploits from the Exploit Database.</p>
                </div>
              ) : (
                <div className="space-y-2">
                  {workspace.linked_exploits?.map((exploitId) => (
                    <div key={exploitId} className="bg-gray-700/50 rounded-lg p-3 flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <Bug className="h-4 w-4 text-red-400" />
                        <span className="text-white font-mono text-sm">{exploitId}</span>
                      </div>
                      <button className="text-gray-400 hover:text-cyan-400 transition-colors">
                        <ExternalLink className="h-4 w-4" />
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {activeTab === 'pocs' && (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="text-lg font-medium text-white">Linked PoCs</h3>
                <button className="flex items-center gap-2 px-3 py-1.5 bg-cyan-600 hover:bg-cyan-700 text-white rounded transition-colors text-sm">
                  <Link2 className="h-4 w-4" />
                  Link PoC
                </button>
              </div>
              {(workspace.linked_pocs?.length || 0) === 0 ? (
                <div className="text-center py-8 text-gray-400">
                  <Code className="h-8 w-8 mx-auto mb-2 opacity-50" />
                  <p>No PoCs linked. Link PoCs from your repository.</p>
                </div>
              ) : (
                <div className="space-y-2">
                  {workspace.linked_pocs?.map((pocId) => (
                    <div key={pocId} className="bg-gray-700/50 rounded-lg p-3 flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <Code className="h-4 w-4 text-cyan-400" />
                        <span className="text-white font-mono text-sm">{pocId}</span>
                      </div>
                      <button className="text-gray-400 hover:text-cyan-400 transition-colors">
                        <ExternalLink className="h-4 w-4" />
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {activeTab === 'timeline' && (
            <div className="space-y-4">
              <h3 className="text-lg font-medium text-white">Research Timeline</h3>
              {loadingTimeline ? (
                <div className="flex items-center justify-center py-8">
                  <RefreshCw className="h-6 w-6 text-cyan-500 animate-spin" />
                </div>
              ) : timeline.length === 0 ? (
                <div className="text-center py-8 text-gray-400">
                  <Clock className="h-8 w-8 mx-auto mb-2 opacity-50" />
                  <p>No timeline events yet.</p>
                </div>
              ) : (
                <div className="relative">
                  <div className="absolute left-4 top-0 bottom-0 w-px bg-gray-700" />
                  <div className="space-y-4">
                    {timeline.map((event, idx) => (
                      <div key={idx} className="flex items-start gap-4 relative">
                        <div className="w-8 h-8 rounded-full bg-gray-700 flex items-center justify-center z-10">
                          {timelineIcons[event.event_type] || <Clock className="h-4 w-4 text-gray-400" />}
                        </div>
                        <div className="flex-1 bg-gray-700/50 rounded-lg p-3">
                          <div className="flex items-center justify-between mb-1">
                            <span className="text-sm font-medium text-white capitalize">
                              {event.event_type.replace('_', ' ')}
                            </span>
                            <span className="text-xs text-gray-500">
                              {new Date(event.created_at).toLocaleString()}
                            </span>
                          </div>
                          {event.description && (
                            <p className="text-sm text-gray-400">{event.description}</p>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    );
  };

  return (
    <Layout>
      <div className="p-6">
        {view === 'list' ? renderListView() : renderDetailView()}
      </div>

      {/* Modals */}
      {showCreateModal && (
        <CreateWorkspaceModal onClose={() => setShowCreateModal(false)} />
      )}
      {showAddNoteModal && (
        <NoteModal
          note={editingNote}
          onClose={() => {
            setShowAddNoteModal(false);
            setEditingNote(null);
          }}
        />
      )}
    </Layout>
  );
};

export default ResearchWorkspacePage;
