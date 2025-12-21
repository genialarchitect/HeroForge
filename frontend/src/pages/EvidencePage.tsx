import React, { useState, useEffect } from 'react';
import { toast } from 'react-toastify';
import {
  FileText,
  Upload,
  Calendar,
  Shield,
  Search,
  Filter,
  RefreshCw,
  Plus,
  Trash2,
  ChevronLeft,
  ChevronRight,
  Play,
  Pause,
  Eye,
} from 'lucide-react';
import { Layout } from '../components/layout/Layout';
import Button from '../components/ui/Button';
import Badge from '../components/ui/Badge';
import EvidenceCard from '../components/evidence/EvidenceCard';
import EvidenceUpload from '../components/evidence/EvidenceUpload';
import EvidenceViewer from '../components/evidence/EvidenceViewer';
import ScheduleForm from '../components/evidence/ScheduleForm';
import ControlCoverage, { CoverageSummaryGrid } from '../components/evidence/ControlCoverage';
import { evidenceAPI } from '../services/evidenceApi';
import { complianceAPI } from '../services/api';
import type {
  Evidence,
  EvidenceStatus,
  EvidenceCollectionSchedule,
  CreateEvidenceRequest,
  CreateScheduleRequest,
  UpdateScheduleRequest,
  ListEvidenceQuery,
  ControlEvidenceSummary,
} from '../types/evidence';
import type { ComplianceFramework, ComplianceControl } from '../types';

type TabType = 'library' | 'upload' | 'schedules' | 'coverage';

const EvidencePage: React.FC = () => {
  const [activeTab, setActiveTab] = useState<TabType>('library');
  const [evidence, setEvidence] = useState<Evidence[]>([]);
  const [schedules, setSchedules] = useState<EvidenceCollectionSchedule[]>([]);
  const [frameworks, setFrameworks] = useState<ComplianceFramework[]>([]);
  const [controls, setControls] = useState<{ id: string; name: string; framework_id: string }[]>(
    []
  );
  const [loading, setLoading] = useState(true);
  const [selectedEvidence, setSelectedEvidence] = useState<Evidence | null>(null);
  const [showScheduleForm, setShowScheduleForm] = useState(false);
  const [editingSchedule, setEditingSchedule] = useState<EvidenceCollectionSchedule | null>(null);

  // Filters
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('');
  const [frameworkFilter, setFrameworkFilter] = useState<string>('');
  const [typeFilter, setTypeFilter] = useState<string>('');

  // Pagination
  const [page, setPage] = useState(1);
  const [totalItems, setTotalItems] = useState(0);
  const pageSize = 12;

  // Coverage data
  const [coverageSummaries, setCoverageSummaries] = useState<ControlEvidenceSummary[]>([]);

  useEffect(() => {
    loadFrameworks();
  }, []);

  useEffect(() => {
    if (activeTab === 'library') {
      loadEvidence();
    } else if (activeTab === 'schedules') {
      loadSchedules();
    } else if (activeTab === 'coverage') {
      loadCoverage();
    }
  }, [activeTab, page, statusFilter, frameworkFilter, typeFilter]);

  const loadFrameworks = async () => {
    try {
      const response = await complianceAPI.getFrameworks();
      setFrameworks(response.data.frameworks || []);

      // Load controls for all frameworks
      const allControls: { id: string; name: string; framework_id: string }[] = [];
      for (const fw of response.data.frameworks || []) {
        try {
          const controlsResponse = await complianceAPI.getFrameworkControls(fw.id);
          const fwControls = (controlsResponse.data.controls || []).map((c: ComplianceControl) => ({
            id: c.id,
            name: c.title || c.id,
            framework_id: fw.id,
          }));
          allControls.push(...fwControls);
        } catch {
          // Skip frameworks that fail to load controls
        }
      }
      setControls(allControls);
    } catch (error) {
      console.error('Failed to load frameworks:', error);
    }
  };

  const loadEvidence = async () => {
    setLoading(true);
    try {
      const query: ListEvidenceQuery = {
        limit: pageSize,
        offset: (page - 1) * pageSize,
      };
      if (statusFilter) query.status = statusFilter;
      if (frameworkFilter) query.framework_id = frameworkFilter;
      if (typeFilter) query.evidence_type = typeFilter;

      const response = await evidenceAPI.list(query);
      setEvidence(response.data.evidence || []);
      setTotalItems(response.data.total || 0);
    } catch (error) {
      console.error('Failed to load evidence:', error);
      toast.error('Failed to load evidence');
    } finally {
      setLoading(false);
    }
  };

  const loadSchedules = async () => {
    setLoading(true);
    try {
      const response = await evidenceAPI.getSchedules();
      setSchedules(response.data.schedules || []);
    } catch (error) {
      console.error('Failed to load schedules:', error);
      toast.error('Failed to load schedules');
    } finally {
      setLoading(false);
    }
  };

  const loadCoverage = async () => {
    setLoading(true);
    try {
      // For now, load summaries for all controls in the selected framework
      const summaries: ControlEvidenceSummary[] = [];
      const targetFramework = frameworkFilter || (frameworks[0]?.id || '');

      if (targetFramework) {
        const frameworkControls = controls.filter((c) => c.framework_id === targetFramework);
        for (const control of frameworkControls.slice(0, 20)) {
          // Limit to 20 for performance
          try {
            const response = await evidenceAPI.getControlSummary(control.id, targetFramework);
            summaries.push(response.data);
          } catch {
            // Create empty summary for controls without evidence
            summaries.push({
              control_id: control.id,
              framework_id: targetFramework,
              total_evidence: 0,
              active_evidence: 0,
              coverage_score: 0,
              is_current: false,
            });
          }
        }
      }
      setCoverageSummaries(summaries);
    } catch (error) {
      console.error('Failed to load coverage:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleCreateEvidence = async (data: CreateEvidenceRequest) => {
    await evidenceAPI.collect({
      ...data,
      params: data.params || {},
    });
    loadEvidence();
    setActiveTab('library');
  };

  const handleStatusChange = async (item: Evidence, status: EvidenceStatus) => {
    try {
      await evidenceAPI.updateStatus(item.id, { status });
      toast.success(`Evidence ${status === 'approved' ? 'approved' : 'rejected'}`);
      loadEvidence();
      if (selectedEvidence?.id === item.id) {
        setSelectedEvidence(null);
      }
    } catch {
      toast.error('Failed to update evidence status');
    }
  };

  const handleDeleteEvidence = async (item: Evidence) => {
    if (!confirm('Are you sure you want to delete this evidence?')) return;
    try {
      await evidenceAPI.delete(item.id);
      toast.success('Evidence deleted');
      loadEvidence();
      if (selectedEvidence?.id === item.id) {
        setSelectedEvidence(null);
      }
    } catch {
      toast.error('Failed to delete evidence');
    }
  };

  const handleCreateSchedule = async (data: CreateScheduleRequest) => {
    await evidenceAPI.createSchedule(data);
    loadSchedules();
    setShowScheduleForm(false);
  };

  const handleUpdateSchedule = async (data: UpdateScheduleRequest) => {
    if (!editingSchedule) return;
    await evidenceAPI.updateSchedule(editingSchedule.id, data);
    loadSchedules();
    setEditingSchedule(null);
    setShowScheduleForm(false);
  };

  const handleScheduleSubmit = async (data: CreateScheduleRequest | UpdateScheduleRequest) => {
    if (editingSchedule) {
      await handleUpdateSchedule(data as UpdateScheduleRequest);
    } else {
      await handleCreateSchedule(data as CreateScheduleRequest);
    }
  };

  const handleDeleteSchedule = async (schedule: EvidenceCollectionSchedule) => {
    if (!confirm('Are you sure you want to delete this schedule?')) return;
    try {
      await evidenceAPI.deleteSchedule(schedule.id);
      toast.success('Schedule deleted');
      loadSchedules();
    } catch {
      toast.error('Failed to delete schedule');
    }
  };

  const handleViewControlEvidence = async (controlId: string, frameworkId: string) => {
    // Switch to library tab with filters
    setFrameworkFilter(frameworkId);
    setActiveTab('library');
    // The evidence will be filtered by the framework, user can then search for control
    setSearchQuery(controlId);
  };

  const filteredEvidence = searchQuery
    ? evidence.filter(
        (e) =>
          e.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
          e.description?.toLowerCase().includes(searchQuery.toLowerCase()) ||
          e.control_ids.some((c) => c.toLowerCase().includes(searchQuery.toLowerCase()))
      )
    : evidence;

  const totalPages = Math.ceil(totalItems / pageSize);

  const tabs: { id: TabType; label: string; icon: React.ReactNode }[] = [
    { id: 'library', label: 'Evidence Library', icon: <FileText className="h-4 w-4" /> },
    { id: 'upload', label: 'Upload', icon: <Upload className="h-4 w-4" /> },
    { id: 'schedules', label: 'Schedules', icon: <Calendar className="h-4 w-4" /> },
    { id: 'coverage', label: 'Control Mapping', icon: <Shield className="h-4 w-4" /> },
  ];

  return (
    <Layout>
      <div>
        {/* Header */}
        <div className="mb-6">
          <h1 className="text-2xl font-bold text-slate-900 dark:text-white flex items-center gap-2">
            <FileText className="h-6 w-6 text-primary" />
            Compliance Evidence
          </h1>
          <p className="text-slate-600 dark:text-slate-400 mt-1">
            Manage evidence for compliance frameworks and controls
          </p>
        </div>

        {/* Tabs */}
        <div className="flex items-center gap-2 mb-6 border-b border-light-border dark:border-dark-border pb-2">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                activeTab === tab.id
                  ? 'bg-primary text-white'
                  : 'text-slate-600 dark:text-slate-400 hover:bg-light-hover dark:hover:bg-dark-hover'
              }`}
            >
              {tab.icon}
              {tab.label}
            </button>
          ))}
        </div>

        {/* Content */}
        {activeTab === 'library' && (
          <div className="space-y-4">
            {/* Filters */}
            <div className="flex flex-wrap items-center gap-3 p-4 bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg">
              <div className="flex-1 min-w-[200px]">
                <div className="relative">
                  <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400" />
                  <input
                    type="text"
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    placeholder="Search evidence..."
                    className="w-full pl-10 pr-3 py-2 bg-light-bg dark:bg-dark-bg border border-light-border dark:border-dark-border rounded-lg text-slate-900 dark:text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-primary"
                  />
                </div>
              </div>
              <select
                value={statusFilter}
                onChange={(e) => {
                  setStatusFilter(e.target.value);
                  setPage(1);
                }}
                className="px-3 py-2 bg-light-bg dark:bg-dark-bg border border-light-border dark:border-dark-border rounded-lg text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-primary"
              >
                <option value="">All Statuses</option>
                <option value="pending_review">Pending Review</option>
                <option value="approved">Approved</option>
                <option value="rejected">Rejected</option>
                <option value="expired">Expired</option>
              </select>
              <select
                value={frameworkFilter}
                onChange={(e) => {
                  setFrameworkFilter(e.target.value);
                  setPage(1);
                }}
                className="px-3 py-2 bg-light-bg dark:bg-dark-bg border border-light-border dark:border-dark-border rounded-lg text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-primary"
              >
                <option value="">All Frameworks</option>
                {frameworks.map((fw) => (
                  <option key={fw.id} value={fw.id}>
                    {fw.name}
                  </option>
                ))}
              </select>
              <Button variant="outline" onClick={loadEvidence}>
                <RefreshCw className="h-4 w-4 mr-2" />
                Refresh
              </Button>
            </div>

            {/* Evidence Grid or Viewer */}
            {selectedEvidence ? (
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                <div className="space-y-4">
                  {filteredEvidence.map((item) => (
                    <EvidenceCard
                      key={item.id}
                      evidence={item}
                      onView={() => setSelectedEvidence(item)}
                      onDelete={handleDeleteEvidence}
                      onStatusChange={handleStatusChange}
                      compact
                    />
                  ))}
                </div>
                <EvidenceViewer
                  evidence={selectedEvidence}
                  onClose={() => setSelectedEvidence(null)}
                  onStatusChange={handleStatusChange}
                />
              </div>
            ) : loading ? (
              <div className="flex items-center justify-center py-12">
                <RefreshCw className="h-8 w-8 text-primary animate-spin" />
              </div>
            ) : filteredEvidence.length > 0 ? (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {filteredEvidence.map((item) => (
                  <EvidenceCard
                    key={item.id}
                    evidence={item}
                    onView={() => setSelectedEvidence(item)}
                    onDelete={handleDeleteEvidence}
                    onStatusChange={handleStatusChange}
                  />
                ))}
              </div>
            ) : (
              <div className="text-center py-12 bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg">
                <FileText className="h-12 w-12 text-slate-400 mx-auto mb-4" />
                <h3 className="text-lg font-medium text-slate-700 dark:text-slate-300 mb-2">
                  No evidence found
                </h3>
                <p className="text-slate-500 mb-4">
                  Get started by uploading evidence or configuring automated collection.
                </p>
                <Button onClick={() => setActiveTab('upload')}>
                  <Upload className="h-4 w-4 mr-2" />
                  Upload Evidence
                </Button>
              </div>
            )}

            {/* Pagination */}
            {totalPages > 1 && (
              <div className="flex items-center justify-between pt-4">
                <p className="text-sm text-slate-500">
                  Showing {(page - 1) * pageSize + 1} - {Math.min(page * pageSize, totalItems)} of{' '}
                  {totalItems} items
                </p>
                <div className="flex items-center gap-2">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setPage(page - 1)}
                    disabled={page === 1}
                  >
                    <ChevronLeft className="h-4 w-4" />
                  </Button>
                  <span className="text-sm text-slate-600 dark:text-slate-400">
                    Page {page} of {totalPages}
                  </span>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setPage(page + 1)}
                    disabled={page === totalPages}
                  >
                    <ChevronRight className="h-4 w-4" />
                  </Button>
                </div>
              </div>
            )}
          </div>
        )}

        {activeTab === 'upload' && (
          <div className="max-w-2xl mx-auto">
            <div className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg p-6">
              <h2 className="text-lg font-semibold text-slate-900 dark:text-white mb-4 flex items-center gap-2">
                <Upload className="h-5 w-5 text-primary" />
                Upload New Evidence
              </h2>
              <EvidenceUpload
                onSubmit={handleCreateEvidence}
                onCancel={() => setActiveTab('library')}
                frameworks={frameworks.map((fw) => ({ id: fw.id, name: fw.name }))}
                controls={controls}
              />
            </div>
          </div>
        )}

        {activeTab === 'schedules' && (
          <div className="space-y-4">
            {/* Header */}
            <div className="flex items-center justify-between">
              <h2 className="text-lg font-semibold text-slate-900 dark:text-white">
                Collection Schedules
              </h2>
              <Button
                onClick={() => {
                  setEditingSchedule(null);
                  setShowScheduleForm(true);
                }}
              >
                <Plus className="h-4 w-4 mr-2" />
                New Schedule
              </Button>
            </div>

            {/* Schedule Form Modal */}
            {showScheduleForm && (
              <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
                <div className="bg-light-surface dark:bg-dark-surface rounded-lg p-6 max-w-2xl w-full max-h-[90vh] overflow-y-auto">
                  <h2 className="text-lg font-semibold text-slate-900 dark:text-white mb-4 flex items-center gap-2">
                    <Calendar className="h-5 w-5 text-primary" />
                    {editingSchedule ? 'Edit Schedule' : 'Create Schedule'}
                  </h2>
                  <ScheduleForm
                    schedule={editingSchedule || undefined}
                    onSubmit={handleScheduleSubmit}
                    onCancel={() => {
                      setShowScheduleForm(false);
                      setEditingSchedule(null);
                    }}
                    frameworks={frameworks.map((fw) => ({ id: fw.id, name: fw.name }))}
                    controls={controls}
                  />
                </div>
              </div>
            )}

            {/* Schedules List */}
            {loading ? (
              <div className="flex items-center justify-center py-12">
                <RefreshCw className="h-8 w-8 text-primary animate-spin" />
              </div>
            ) : schedules.length > 0 ? (
              <div className="space-y-3">
                {schedules.map((schedule) => (
                  <div
                    key={schedule.id}
                    className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg p-4"
                  >
                    <div className="flex items-start justify-between">
                      <div className="flex items-start gap-3">
                        <div
                          className={`p-2 rounded-lg ${schedule.enabled ? 'bg-green-100 dark:bg-green-900/30' : 'bg-gray-100 dark:bg-gray-800'}`}
                        >
                          {schedule.enabled ? (
                            <Play className="h-5 w-5 text-green-600" />
                          ) : (
                            <Pause className="h-5 w-5 text-gray-500" />
                          )}
                        </div>
                        <div>
                          <h3 className="font-semibold text-slate-900 dark:text-white">
                            {schedule.name}
                          </h3>
                          {schedule.description && (
                            <p className="text-sm text-slate-500 mt-0.5">{schedule.description}</p>
                          )}
                          <div className="flex flex-wrap gap-2 mt-2">
                            <Badge variant="default">
                              <Calendar className="h-3 w-3 mr-1" />
                              {schedule.cron_expression}
                            </Badge>
                            <Badge variant="blue">
                              {schedule.framework_ids.length} framework
                              {schedule.framework_ids.length !== 1 ? 's' : ''}
                            </Badge>
                            <Badge variant="gray">
                              {schedule.control_ids.length} control
                              {schedule.control_ids.length !== 1 ? 's' : ''}
                            </Badge>
                          </div>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <Badge variant={schedule.enabled ? 'green' : 'gray'}>
                          {schedule.enabled ? 'Active' : 'Disabled'}
                        </Badge>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => {
                            setEditingSchedule(schedule);
                            setShowScheduleForm(true);
                          }}
                        >
                          <Eye className="h-4 w-4" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => handleDeleteSchedule(schedule)}
                          className="text-red-600"
                        >
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </div>
                    </div>
                    {schedule.last_run_at && (
                      <p className="text-xs text-slate-500 mt-3 pt-3 border-t border-light-border dark:border-dark-border">
                        Last run: {new Date(schedule.last_run_at).toLocaleString()}
                        {schedule.next_run_at && (
                          <span className="ml-4">
                            Next run: {new Date(schedule.next_run_at).toLocaleString()}
                          </span>
                        )}
                      </p>
                    )}
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-center py-12 bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg">
                <Calendar className="h-12 w-12 text-slate-400 mx-auto mb-4" />
                <h3 className="text-lg font-medium text-slate-700 dark:text-slate-300 mb-2">
                  No schedules configured
                </h3>
                <p className="text-slate-500 mb-4">
                  Set up automated evidence collection schedules for your compliance controls.
                </p>
                <Button
                  onClick={() => {
                    setEditingSchedule(null);
                    setShowScheduleForm(true);
                  }}
                >
                  <Plus className="h-4 w-4 mr-2" />
                  Create Schedule
                </Button>
              </div>
            )}
          </div>
        )}

        {activeTab === 'coverage' && (
          <div className="space-y-4">
            {/* Framework Filter */}
            <div className="flex items-center gap-3">
              <label className="text-sm font-medium text-slate-700 dark:text-slate-300">
                Framework:
              </label>
              <select
                value={frameworkFilter}
                onChange={(e) => {
                  setFrameworkFilter(e.target.value);
                }}
                className="px-3 py-2 bg-light-bg dark:bg-dark-bg border border-light-border dark:border-dark-border rounded-lg text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-primary"
              >
                {frameworks.map((fw) => (
                  <option key={fw.id} value={fw.id}>
                    {fw.name}
                  </option>
                ))}
              </select>
              <Button variant="outline" onClick={loadCoverage}>
                <RefreshCw className="h-4 w-4 mr-2" />
                Refresh
              </Button>
            </div>

            {/* Coverage Grid */}
            {loading ? (
              <div className="flex items-center justify-center py-12">
                <RefreshCw className="h-8 w-8 text-primary animate-spin" />
              </div>
            ) : coverageSummaries.length > 0 ? (
              <CoverageSummaryGrid
                summaries={coverageSummaries}
                onViewEvidence={handleViewControlEvidence}
              />
            ) : (
              <div className="text-center py-12 bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg">
                <Shield className="h-12 w-12 text-slate-400 mx-auto mb-4" />
                <h3 className="text-lg font-medium text-slate-700 dark:text-slate-300 mb-2">
                  No coverage data
                </h3>
                <p className="text-slate-500">
                  Select a framework to view evidence coverage by control.
                </p>
              </div>
            )}
          </div>
        )}
      </div>
    </Layout>
  );
};

export default EvidencePage;
