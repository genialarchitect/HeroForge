import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import Layout from '../components/layout/Layout';
import TemplateList from '../components/methodology/TemplateList';
import ChecklistList from '../components/methodology/ChecklistList';
import ChecklistView from '../components/methodology/ChecklistView';
import { methodologyAPI } from '../services/api';
import type {
  MethodologyTemplate,
  ChecklistSummary,
  ChecklistWithItems,
} from '../types';
import { toast } from 'react-toastify';
import { ClipboardList, BookOpen, Plus, ArrowLeft } from 'lucide-react';

type ViewMode = 'templates' | 'checklists' | 'checklist-detail';

const MethodologyPage: React.FC = () => {
  const { checklistId } = useParams<{ checklistId?: string }>();
  const navigate = useNavigate();

  const [viewMode, setViewMode] = useState<ViewMode>(
    checklistId ? 'checklist-detail' : 'checklists'
  );
  const [templates, setTemplates] = useState<MethodologyTemplate[]>([]);
  const [checklists, setChecklists] = useState<ChecklistSummary[]>([]);
  const [selectedChecklist, setSelectedChecklist] = useState<ChecklistWithItems | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [showCreateDialog, setShowCreateDialog] = useState(false);
  const [selectedTemplateId, setSelectedTemplateId] = useState<string>('');
  const [newChecklistName, setNewChecklistName] = useState('');

  // Load templates and checklists on mount
  useEffect(() => {
    loadTemplates();
    loadChecklists();
  }, []);

  // Load checklist if ID is in URL
  useEffect(() => {
    if (checklistId) {
      loadChecklist(checklistId);
    }
  }, [checklistId]);

  const loadTemplates = async () => {
    try {
      const response = await methodologyAPI.listTemplates();
      setTemplates(response.data);
    } catch (error) {
      console.error('Failed to load templates:', error);
      toast.error('Failed to load methodology templates');
    }
  };

  const loadChecklists = async () => {
    try {
      const response = await methodologyAPI.listChecklists();
      setChecklists(response.data);
    } catch (error) {
      console.error('Failed to load checklists:', error);
      toast.error('Failed to load checklists');
    }
  };

  const loadChecklist = async (id: string) => {
    setIsLoading(true);
    try {
      const response = await methodologyAPI.getChecklist(id);
      setSelectedChecklist(response.data);
      setViewMode('checklist-detail');
    } catch (error) {
      console.error('Failed to load checklist:', error);
      toast.error('Failed to load checklist');
      navigate('/methodology');
    } finally {
      setIsLoading(false);
    }
  };

  const handleCreateChecklist = async () => {
    if (!selectedTemplateId || !newChecklistName.trim()) {
      toast.error('Please select a template and enter a name');
      return;
    }

    setIsLoading(true);
    try {
      const response = await methodologyAPI.createChecklist({
        template_id: selectedTemplateId,
        name: newChecklistName.trim(),
      });
      toast.success('Checklist created successfully');
      setShowCreateDialog(false);
      setSelectedTemplateId('');
      setNewChecklistName('');
      await loadChecklists();
      navigate(`/methodology/${response.data.id}`);
    } catch (error) {
      console.error('Failed to create checklist:', error);
      toast.error('Failed to create checklist');
    } finally {
      setIsLoading(false);
    }
  };

  const handleDeleteChecklist = async (id: string) => {
    if (!confirm('Are you sure you want to delete this checklist?')) {
      return;
    }

    try {
      await methodologyAPI.deleteChecklist(id);
      toast.success('Checklist deleted');
      await loadChecklists();
      if (selectedChecklist?.checklist.id === id) {
        setSelectedChecklist(null);
        setViewMode('checklists');
        navigate('/methodology');
      }
    } catch (error) {
      console.error('Failed to delete checklist:', error);
      toast.error('Failed to delete checklist');
    }
  };

  const handleChecklistSelect = (checklist: ChecklistSummary) => {
    navigate(`/methodology/${checklist.id}`);
  };

  const handleBackToList = () => {
    setSelectedChecklist(null);
    setViewMode('checklists');
    navigate('/methodology');
  };

  const handleChecklistUpdate = (updated: ChecklistWithItems) => {
    setSelectedChecklist(updated);
    loadChecklists(); // Refresh list to update progress
  };

  return (
    <Layout>
      <div className="space-y-6">
        {/* Page Header */}
        <div className="flex items-center justify-between">
          <div>
            <div className="flex items-center gap-3 mb-2">
              {viewMode === 'checklist-detail' && (
                <button
                  onClick={handleBackToList}
                  className="p-2 text-slate-400 hover:text-white hover:bg-dark-hover rounded-lg transition-colors"
                >
                  <ArrowLeft className="h-5 w-5" />
                </button>
              )}
              <ClipboardList className="h-6 w-6 text-primary" />
              <h1 className="text-2xl font-bold text-white">
                {viewMode === 'checklist-detail' && selectedChecklist
                  ? selectedChecklist.checklist.name
                  : 'Methodology Checklists'}
              </h1>
            </div>
            <p className="text-slate-400">
              {viewMode === 'checklist-detail'
                ? `${selectedChecklist?.template_name} - ${selectedChecklist?.checklist.progress_percent.toFixed(0)}% complete`
                : 'Track your penetration testing progress with PTES and OWASP WSTG checklists'}
            </p>
          </div>

          {viewMode !== 'checklist-detail' && (
            <div className="flex items-center gap-3">
              <button
                onClick={() => setShowCreateDialog(true)}
                className="flex items-center gap-2 px-4 py-2 bg-primary text-white rounded-lg hover:bg-primary/90 transition-colors"
              >
                <Plus className="h-4 w-4" />
                New Checklist
              </button>
            </div>
          )}
        </div>

        {/* View Mode Tabs (only when not in detail view) */}
        {viewMode !== 'checklist-detail' && (
          <div className="bg-dark-surface rounded-lg border border-dark-border p-4">
            <div className="flex gap-2">
              <button
                onClick={() => setViewMode('checklists')}
                className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                  viewMode === 'checklists'
                    ? 'bg-primary text-white'
                    : 'text-slate-400 hover:text-white hover:bg-dark-hover'
                }`}
              >
                <ClipboardList className="h-4 w-4" />
                My Checklists ({checklists.length})
              </button>
              <button
                onClick={() => setViewMode('templates')}
                className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                  viewMode === 'templates'
                    ? 'bg-primary text-white'
                    : 'text-slate-400 hover:text-white hover:bg-dark-hover'
                }`}
              >
                <BookOpen className="h-4 w-4" />
                Templates ({templates.length})
              </button>
            </div>
          </div>
        )}

        {/* Content */}
        {viewMode === 'templates' && (
          <TemplateList
            templates={templates}
            onSelectTemplate={(template) => {
              setSelectedTemplateId(template.id);
              setShowCreateDialog(true);
            }}
          />
        )}

        {viewMode === 'checklists' && (
          <ChecklistList
            checklists={checklists}
            onSelect={handleChecklistSelect}
            onDelete={handleDeleteChecklist}
            onCreateNew={() => setShowCreateDialog(true)}
          />
        )}

        {viewMode === 'checklist-detail' && selectedChecklist && (
          <ChecklistView
            checklist={selectedChecklist}
            onUpdate={handleChecklistUpdate}
          />
        )}

        {isLoading && viewMode === 'checklist-detail' && (
          <div className="flex items-center justify-center py-12">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
          </div>
        )}

        {/* Create Checklist Dialog */}
        {showCreateDialog && (
          <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
            <div className="bg-dark-surface border border-dark-border rounded-lg p-6 w-full max-w-md">
              <h2 className="text-xl font-semibold text-white mb-4">
                Create New Checklist
              </h2>

              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-slate-300 mb-1">
                    Template
                  </label>
                  <select
                    value={selectedTemplateId}
                    onChange={(e) => setSelectedTemplateId(e.target.value)}
                    className="w-full px-3 py-2 bg-dark-hover border border-dark-border rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-primary"
                  >
                    <option value="">Select a template...</option>
                    {templates.map((template) => (
                      <option key={template.id} value={template.id}>
                        {template.name} {template.version && `(${template.version})`} - {template.item_count} items
                      </option>
                    ))}
                  </select>
                </div>

                <div>
                  <label className="block text-sm font-medium text-slate-300 mb-1">
                    Checklist Name
                  </label>
                  <input
                    type="text"
                    value={newChecklistName}
                    onChange={(e) => setNewChecklistName(e.target.value)}
                    placeholder="e.g., Client XYZ Web App Assessment"
                    className="w-full px-3 py-2 bg-dark-hover border border-dark-border rounded-lg text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-primary"
                  />
                </div>
              </div>

              <div className="flex justify-end gap-3 mt-6">
                <button
                  onClick={() => {
                    setShowCreateDialog(false);
                    setSelectedTemplateId('');
                    setNewChecklistName('');
                  }}
                  className="px-4 py-2 text-slate-400 hover:text-white transition-colors"
                >
                  Cancel
                </button>
                <button
                  onClick={handleCreateChecklist}
                  disabled={isLoading || !selectedTemplateId || !newChecklistName.trim()}
                  className="px-4 py-2 bg-primary text-white rounded-lg hover:bg-primary/90 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                >
                  {isLoading ? 'Creating...' : 'Create Checklist'}
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </Layout>
  );
};

export default MethodologyPage;
