import React, { useState, useEffect } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import {
  GitBranch,
  Plus,
  Settings,
  List,
  Clock,
  Trash2,
  Edit,
  Copy,
  ToggleLeft,
  ToggleRight,
  Loader2,
  AlertCircle,
} from 'lucide-react';
import { toast } from 'react-toastify';
import Layout from '../components/layout/Layout';
import { workflowAPI } from '../services/api';
import {
  WorkflowTemplateBuilder,
  PendingApprovals,
  WorkflowInstanceView,
  WorkflowHistory,
} from '../components/workflows';
import type {
  WorkflowTemplate,
  WorkflowTemplateWithStages,
  WorkflowInstance,
  WorkflowInstanceDetail,
} from '../types';
import { formatDistanceToNow } from 'date-fns';

type TabType = 'approvals' | 'templates' | 'instances';

export const WorkflowsPage: React.FC = () => {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const [activeTab, setActiveTab] = useState<TabType>(
    (searchParams.get('tab') as TabType) || 'approvals'
  );

  // Templates state
  const [templates, setTemplates] = useState<WorkflowTemplate[]>([]);
  const [loadingTemplates, setLoadingTemplates] = useState(true);
  const [selectedTemplate, setSelectedTemplate] = useState<WorkflowTemplateWithStages | null>(null);
  const [showTemplateBuilder, setShowTemplateBuilder] = useState(false);

  // Instances state
  const [instances, setInstances] = useState<WorkflowInstance[]>([]);
  const [loadingInstances, setLoadingInstances] = useState(true);
  const [instanceFilter, setInstanceFilter] = useState<string>('active');
  const [selectedInstance, setSelectedInstance] = useState<WorkflowInstanceDetail | null>(null);
  const [loadingInstance, setLoadingInstance] = useState(false);

  useEffect(() => {
    setSearchParams({ tab: activeTab });
  }, [activeTab, setSearchParams]);

  useEffect(() => {
    if (activeTab === 'templates') {
      loadTemplates();
    } else if (activeTab === 'instances') {
      loadInstances();
    }
  }, [activeTab, instanceFilter]);

  const loadTemplates = async () => {
    setLoadingTemplates(true);
    try {
      const response = await workflowAPI.templates.list();
      setTemplates(response.data);
    } catch (error) {
      toast.error('Failed to load workflow templates');
      console.error(error);
    } finally {
      setLoadingTemplates(false);
    }
  };

  const loadInstances = async () => {
    setLoadingInstances(true);
    try {
      const response = await workflowAPI.instances.list(
        instanceFilter !== 'all' ? { status: instanceFilter } : undefined
      );
      setInstances(response.data);
    } catch (error) {
      toast.error('Failed to load workflow instances');
      console.error(error);
    } finally {
      setLoadingInstances(false);
    }
  };

  const loadInstanceDetail = async (id: string) => {
    setLoadingInstance(true);
    try {
      const response = await workflowAPI.instances.get(id);
      setSelectedInstance(response.data);
    } catch (error) {
      toast.error('Failed to load workflow details');
      console.error(error);
    } finally {
      setLoadingInstance(false);
    }
  };

  const handleEditTemplate = async (template: WorkflowTemplate) => {
    try {
      const response = await workflowAPI.templates.get(template.id);
      setSelectedTemplate(response.data);
      setShowTemplateBuilder(true);
    } catch (error) {
      toast.error('Failed to load template details');
      console.error(error);
    }
  };

  const handleDeleteTemplate = async (template: WorkflowTemplate) => {
    if (template.is_system) {
      toast.error('Cannot delete system templates');
      return;
    }
    if (!confirm(`Delete template "${template.name}"?`)) return;

    try {
      await workflowAPI.templates.delete(template.id);
      toast.success('Template deleted');
      loadTemplates();
    } catch (error) {
      toast.error('Failed to delete template');
      console.error(error);
    }
  };

  const handleToggleActive = async (template: WorkflowTemplate) => {
    if (template.is_system) {
      toast.error('Cannot modify system templates');
      return;
    }

    try {
      await workflowAPI.templates.update(template.id, { is_active: !template.is_active });
      toast.success(template.is_active ? 'Template deactivated' : 'Template activated');
      loadTemplates();
    } catch (error) {
      toast.error('Failed to update template');
      console.error(error);
    }
  };

  const handleTemplateSaved = () => {
    setShowTemplateBuilder(false);
    setSelectedTemplate(null);
    loadTemplates();
  };

  // Instance actions
  const handleApprove = async (comment?: string) => {
    if (!selectedInstance) return;
    await workflowAPI.stages.approve(selectedInstance.id, { comment });
    toast.success('Stage approved');
    loadInstanceDetail(selectedInstance.id);
    loadInstances();
  };

  const handleReject = async (comment: string, restartFromStage?: string) => {
    if (!selectedInstance) return;
    await workflowAPI.stages.reject(selectedInstance.id, { comment, restart_from_stage: restartFromStage });
    toast.success('Stage rejected');
    loadInstanceDetail(selectedInstance.id);
    loadInstances();
  };

  const handleAdvance = async (comment?: string) => {
    if (!selectedInstance) return;
    await workflowAPI.stages.advance(selectedInstance.id, comment);
    toast.success('Advanced to next stage');
    loadInstanceDetail(selectedInstance.id);
    loadInstances();
  };

  const handleHold = async (notes?: string) => {
    if (!selectedInstance) return;
    await workflowAPI.instances.hold(selectedInstance.id, notes);
    toast.success('Workflow put on hold');
    loadInstanceDetail(selectedInstance.id);
    loadInstances();
  };

  const handleResume = async () => {
    if (!selectedInstance) return;
    await workflowAPI.instances.resume(selectedInstance.id);
    toast.success('Workflow resumed');
    loadInstanceDetail(selectedInstance.id);
    loadInstances();
  };

  const handleCancel = async (comment?: string) => {
    if (!selectedInstance) return;
    await workflowAPI.instances.cancel(selectedInstance.id, comment);
    toast.success('Workflow cancelled');
    loadInstanceDetail(selectedInstance.id);
    loadInstances();
  };

  const getStatusColor = (status: string) => {
    switch (status.toLowerCase()) {
      case 'active':
        return 'text-cyan-400 bg-cyan-900/30';
      case 'completed':
        return 'text-green-400 bg-green-900/30';
      case 'cancelled':
        return 'text-gray-400 bg-gray-700';
      case 'on_hold':
        return 'text-orange-400 bg-orange-900/30';
      case 'rejected':
        return 'text-red-400 bg-red-900/30';
      default:
        return 'text-gray-400 bg-gray-700';
    }
  };

  const renderTemplates = () => {
    if (showTemplateBuilder) {
      return (
        <WorkflowTemplateBuilder
          template={selectedTemplate || undefined}
          onSave={handleTemplateSaved}
          onCancel={() => {
            setShowTemplateBuilder(false);
            setSelectedTemplate(null);
          }}
        />
      );
    }

    return (
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold text-white">Workflow Templates</h2>
          <button
            onClick={() => {
              setSelectedTemplate(null);
              setShowTemplateBuilder(true);
            }}
            className="flex items-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded"
          >
            <Plus className="w-4 h-4" />
            New Template
          </button>
        </div>

        {loadingTemplates ? (
          <div className="flex items-center justify-center py-12">
            <Loader2 className="w-8 h-8 text-cyan-400 animate-spin" />
          </div>
        ) : templates.length === 0 ? (
          <div className="text-center py-12">
            <GitBranch className="w-12 h-12 text-gray-600 mx-auto mb-3" />
            <p className="text-gray-400">No workflow templates yet</p>
            <p className="text-sm text-gray-500 mt-1">
              Create your first template to define remediation workflows
            </p>
          </div>
        ) : (
          <div className="grid gap-4">
            {templates.map((template) => (
              <div
                key={template.id}
                className={`bg-gray-800 rounded-lg border p-4 ${
                  template.is_active ? 'border-gray-700' : 'border-gray-700 opacity-60'
                }`}
              >
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <div className="flex items-center gap-2">
                      <h3 className="font-medium text-white">{template.name}</h3>
                      {template.is_system && (
                        <span className="px-2 py-0.5 rounded text-xs bg-purple-900/30 text-purple-400">
                          System
                        </span>
                      )}
                      {!template.is_active && (
                        <span className="px-2 py-0.5 rounded text-xs bg-gray-700 text-gray-400">
                          Inactive
                        </span>
                      )}
                    </div>
                    {template.description && (
                      <p className="text-sm text-gray-400 mt-1">{template.description}</p>
                    )}
                    <p className="text-xs text-gray-500 mt-2">
                      Created{' '}
                      {formatDistanceToNow(new Date(template.created_at), { addSuffix: true })}
                    </p>
                  </div>
                  <div className="flex items-center gap-2">
                    {!template.is_system && (
                      <>
                        <button
                          onClick={() => handleToggleActive(template)}
                          className="p-2 text-gray-400 hover:text-white"
                          title={template.is_active ? 'Deactivate' : 'Activate'}
                        >
                          {template.is_active ? (
                            <ToggleRight className="w-5 h-5 text-green-400" />
                          ) : (
                            <ToggleLeft className="w-5 h-5" />
                          )}
                        </button>
                        <button
                          onClick={() => handleEditTemplate(template)}
                          className="p-2 text-gray-400 hover:text-white"
                          title="Edit"
                        >
                          <Edit className="w-5 h-5" />
                        </button>
                        <button
                          onClick={() => handleDeleteTemplate(template)}
                          className="p-2 text-gray-400 hover:text-red-400"
                          title="Delete"
                        >
                          <Trash2 className="w-5 h-5" />
                        </button>
                      </>
                    )}
                    {template.is_system && (
                      <button
                        onClick={() => handleEditTemplate(template)}
                        className="p-2 text-gray-400 hover:text-white"
                        title="View"
                      >
                        <Edit className="w-5 h-5" />
                      </button>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    );
  };

  const renderInstances = () => {
    if (selectedInstance) {
      const stageNames = selectedInstance.stage_instances.reduce(
        (acc, si) => {
          acc[si.stage_id] = si.stage.name;
          return acc;
        },
        {} as Record<string, string>
      );

      return (
        <div className="space-y-6">
          <button
            onClick={() => setSelectedInstance(null)}
            className="text-cyan-400 hover:text-cyan-300 flex items-center gap-1"
          >
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
            </svg>
            Back to list
          </button>

          <WorkflowInstanceView
            instance={selectedInstance}
            onApprove={handleApprove}
            onReject={handleReject}
            onAdvance={handleAdvance}
            onHold={handleHold}
            onResume={handleResume}
            onCancel={handleCancel}
            isLoading={loadingInstance}
          />

          <div className="bg-gray-900 rounded-lg p-4">
            <h4 className="text-lg font-medium text-white mb-4">Workflow History</h4>
            <WorkflowHistory transitions={selectedInstance.transitions} stageNames={stageNames} />
          </div>
        </div>
      );
    }

    return (
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold text-white">Workflow Instances</h2>
          <select
            value={instanceFilter}
            onChange={(e) => setInstanceFilter(e.target.value)}
            className="bg-gray-800 border border-gray-700 rounded px-3 py-2 text-white"
          >
            <option value="active">Active</option>
            <option value="on_hold">On Hold</option>
            <option value="completed">Completed</option>
            <option value="cancelled">Cancelled</option>
            <option value="rejected">Rejected</option>
            <option value="all">All</option>
          </select>
        </div>

        {loadingInstances ? (
          <div className="flex items-center justify-center py-12">
            <Loader2 className="w-8 h-8 text-cyan-400 animate-spin" />
          </div>
        ) : instances.length === 0 ? (
          <div className="text-center py-12">
            <List className="w-12 h-12 text-gray-600 mx-auto mb-3" />
            <p className="text-gray-400">No workflow instances found</p>
            <p className="text-sm text-gray-500 mt-1">
              Start a workflow from a vulnerability to see it here
            </p>
          </div>
        ) : (
          <div className="bg-gray-900 rounded-lg border border-gray-700 divide-y divide-gray-700">
            {instances.map((instance) => (
              <div
                key={instance.id}
                className="p-4 hover:bg-gray-800/50 cursor-pointer transition-colors"
                onClick={() => loadInstanceDetail(instance.id)}
              >
                <div className="flex items-center justify-between">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-medium text-white">Workflow #{instance.id.slice(0, 8)}</span>
                      <span className={`px-2 py-0.5 rounded text-xs ${getStatusColor(instance.status)}`}>
                        {instance.status.replace('_', ' ')}
                      </span>
                    </div>
                    <p className="text-sm text-gray-400 mt-1">
                      Started{' '}
                      {formatDistanceToNow(new Date(instance.started_at), { addSuffix: true })}
                      {instance.completed_at && (
                        <>
                          {' '} - Completed{' '}
                          {formatDistanceToNow(new Date(instance.completed_at), { addSuffix: true })}
                        </>
                      )}
                    </p>
                  </div>
                  <svg className="w-5 h-5 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                  </svg>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    );
  };

  return (
    <Layout>
      <div className="p-6">
        <div className="flex items-center gap-3 mb-6">
          <GitBranch className="w-8 h-8 text-cyan-400" />
          <div>
            <h1 className="text-2xl font-bold text-white">Remediation Workflows</h1>
            <p className="text-gray-400">Manage approval chains and track remediation progress</p>
          </div>
        </div>

        {/* Tabs */}
        <div className="flex items-center gap-4 border-b border-gray-700 mb-6">
          <button
            onClick={() => setActiveTab('approvals')}
            className={`flex items-center gap-2 px-4 py-3 border-b-2 transition-colors ${
              activeTab === 'approvals'
                ? 'border-cyan-400 text-cyan-400'
                : 'border-transparent text-gray-400 hover:text-white'
            }`}
          >
            <Clock className="w-5 h-5" />
            Pending Approvals
          </button>
          <button
            onClick={() => setActiveTab('templates')}
            className={`flex items-center gap-2 px-4 py-3 border-b-2 transition-colors ${
              activeTab === 'templates'
                ? 'border-cyan-400 text-cyan-400'
                : 'border-transparent text-gray-400 hover:text-white'
            }`}
          >
            <Settings className="w-5 h-5" />
            Templates
          </button>
          <button
            onClick={() => setActiveTab('instances')}
            className={`flex items-center gap-2 px-4 py-3 border-b-2 transition-colors ${
              activeTab === 'instances'
                ? 'border-cyan-400 text-cyan-400'
                : 'border-transparent text-gray-400 hover:text-white'
            }`}
          >
            <List className="w-5 h-5" />
            All Instances
          </button>
        </div>

        {/* Tab Content */}
        {activeTab === 'approvals' && <PendingApprovals />}
        {activeTab === 'templates' && renderTemplates()}
        {activeTab === 'instances' && renderInstances()}
      </div>
    </Layout>
  );
};

export default WorkflowsPage;
