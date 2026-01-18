import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Calendar, Clock, AlertTriangle, CheckCircle, Users, TrendingDown,
  ChevronDown, ChevronRight, Loader2, RefreshCw, Trash2, Target,
  MapPin, BarChart3, User, Zap
} from 'lucide-react';
import { toast } from 'react-toastify';
import {
  remediationRoadmapAPI,
  RemediationRoadmap as Roadmap,
  RemediationPhase,
  RemediationTask,
  CreateRoadmapRequest,
} from '../../services/api';

interface RemediationRoadmapProps {
  scanId: string;
}

export function RemediationRoadmap({ scanId }: RemediationRoadmapProps) {
  const queryClient = useQueryClient();
  const [expandedPhases, setExpandedPhases] = useState<Set<number>>(new Set([1]));
  const [showGenerator, setShowGenerator] = useState(false);
  const [selectedRoadmap, setSelectedRoadmap] = useState<string | null>(null);

  // Generator form state
  const [hoursPerWeek, setHoursPerWeek] = useState(40);
  const [resources, setResources] = useState(1);
  const [includeLow, setIncludeLow] = useState(true);
  const [maxWeeks, setMaxWeeks] = useState(12);

  // Fetch roadmaps for this scan
  const { data: roadmapsData, isLoading } = useQuery({
    queryKey: ['roadmaps', scanId],
    queryFn: () => remediationRoadmapAPI.getByScan(scanId),
  });

  // Generate roadmap mutation
  const generateMutation = useMutation({
    mutationFn: (request: CreateRoadmapRequest) => remediationRoadmapAPI.generate(request),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['roadmaps', scanId] });
      toast.success('Roadmap generated successfully');
      setShowGenerator(false);
    },
    onError: (error: Error) => {
      toast.error(`Failed to generate roadmap: ${error.message}`);
    },
  });

  // Delete roadmap mutation
  const deleteMutation = useMutation({
    mutationFn: (id: string) => remediationRoadmapAPI.delete(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['roadmaps', scanId] });
      toast.success('Roadmap deleted');
      setSelectedRoadmap(null);
    },
  });

  const handleGenerate = () => {
    generateMutation.mutate({
      scan_id: scanId,
      hours_per_week: hoursPerWeek,
      available_resources: resources,
      include_low_severity: includeLow,
      max_weeks: maxWeeks,
    });
  };

  const togglePhase = (phaseNumber: number) => {
    const newExpanded = new Set(expandedPhases);
    if (newExpanded.has(phaseNumber)) {
      newExpanded.delete(phaseNumber);
    } else {
      newExpanded.add(phaseNumber);
    }
    setExpandedPhases(newExpanded);
  };

  const roadmaps = roadmapsData?.data?.roadmaps || [];
  const currentRoadmap = selectedRoadmap
    ? roadmaps.find((r: Roadmap) => r.id === selectedRoadmap)
    : roadmaps[0];

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical': return 'text-red-400 bg-red-400/10';
      case 'high': return 'text-orange-400 bg-orange-400/10';
      case 'medium': return 'text-yellow-400 bg-yellow-400/10';
      case 'low': return 'text-green-400 bg-green-400/10';
      default: return 'text-gray-400 bg-gray-400/10';
    }
  };

  const formatDate = (dateStr: string) => {
    return new Date(dateStr).toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
    });
  };

  const getAssigneeIcon = (assignee: string) => {
    if (assignee.includes('database')) return '🗄️';
    if (assignee.includes('network')) return '🌐';
    if (assignee.includes('cloud')) return '☁️';
    if (assignee.includes('devops')) return '🔧';
    if (assignee.includes('developer')) return '💻';
    if (assignee.includes('security')) return '🛡️';
    return '👤';
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center p-8">
        <Loader2 className="w-6 h-6 animate-spin text-cyan-400" />
        <span className="ml-2 text-gray-400">Loading roadmaps...</span>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <MapPin className="w-6 h-6 text-cyan-400" />
          <h2 className="text-xl font-semibold text-white">Remediation Roadmap</h2>
        </div>
        <div className="flex items-center space-x-2">
          {roadmaps.length > 0 && (
            <select
              value={selectedRoadmap || ''}
              onChange={(e) => setSelectedRoadmap(e.target.value || null)}
              className="bg-gray-700 border border-gray-600 rounded px-3 py-1.5 text-sm text-gray-200"
            >
              {roadmaps.map((r: Roadmap) => (
                <option key={r.id} value={r.id}>
                  {formatDate(r.generated_at)} - {r.summary.total_tasks} tasks
                </option>
              ))}
            </select>
          )}
          <button
            onClick={() => setShowGenerator(!showGenerator)}
            className="flex items-center space-x-2 px-3 py-1.5 bg-cyan-600 hover:bg-cyan-700 text-white rounded text-sm"
          >
            <RefreshCw className="w-4 h-4" />
            <span>Generate New</span>
          </button>
        </div>
      </div>

      {/* Generator Form */}
      {showGenerator && (
        <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
          <h3 className="text-lg font-medium text-white mb-4">Generate Roadmap</h3>
          <div className="grid grid-cols-4 gap-4">
            <div>
              <label className="block text-sm text-gray-400 mb-1">Hours/Week</label>
              <input
                type="number"
                value={hoursPerWeek}
                onChange={(e) => setHoursPerWeek(parseInt(e.target.value) || 40)}
                className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-white"
                min="1"
                max="200"
              />
            </div>
            <div>
              <label className="block text-sm text-gray-400 mb-1">Resources (FTE)</label>
              <input
                type="number"
                value={resources}
                onChange={(e) => setResources(parseInt(e.target.value) || 1)}
                className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-white"
                min="1"
                max="50"
              />
            </div>
            <div>
              <label className="block text-sm text-gray-400 mb-1">Max Weeks</label>
              <input
                type="number"
                value={maxWeeks}
                onChange={(e) => setMaxWeeks(parseInt(e.target.value) || 12)}
                className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-white"
                min="1"
                max="52"
              />
            </div>
            <div>
              <label className="block text-sm text-gray-400 mb-1">Include Low</label>
              <button
                onClick={() => setIncludeLow(!includeLow)}
                className={`w-full px-3 py-2 rounded ${
                  includeLow ? 'bg-cyan-600 text-white' : 'bg-gray-700 text-gray-400'
                }`}
              >
                {includeLow ? 'Yes' : 'No'}
              </button>
            </div>
          </div>
          <div className="mt-4 flex justify-end space-x-2">
            <button
              onClick={() => setShowGenerator(false)}
              className="px-4 py-2 text-gray-400 hover:text-white"
            >
              Cancel
            </button>
            <button
              onClick={handleGenerate}
              disabled={generateMutation.isPending}
              className="flex items-center space-x-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded"
            >
              {generateMutation.isPending ? (
                <Loader2 className="w-4 h-4 animate-spin" />
              ) : (
                <Zap className="w-4 h-4" />
              )}
              <span>Generate</span>
            </button>
          </div>
        </div>
      )}

      {/* No Roadmaps */}
      {roadmaps.length === 0 && !showGenerator && (
        <div className="bg-gray-800 rounded-lg p-8 text-center">
          <MapPin className="w-12 h-12 text-gray-600 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-white mb-2">No Roadmaps Yet</h3>
          <p className="text-gray-400 mb-4">
            Generate an AI-powered remediation roadmap to plan your security fixes.
          </p>
          <button
            onClick={() => setShowGenerator(true)}
            className="px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded"
          >
            Generate First Roadmap
          </button>
        </div>
      )}

      {/* Roadmap Display */}
      {currentRoadmap && (
        <div className="space-y-6">
          {/* Summary Cards */}
          <div className="grid grid-cols-4 gap-4">
            <SummaryCard
              icon={<Target className="w-5 h-5 text-cyan-400" />}
              label="Total Tasks"
              value={currentRoadmap.summary.total_tasks}
            />
            <SummaryCard
              icon={<Clock className="w-5 h-5 text-yellow-400" />}
              label="Total Hours"
              value={`${currentRoadmap.summary.total_effort_hours}h`}
            />
            <SummaryCard
              icon={<Calendar className="w-5 h-5 text-green-400" />}
              label="Phases"
              value={currentRoadmap.summary.total_phases}
            />
            <SummaryCard
              icon={<TrendingDown className="w-5 h-5 text-purple-400" />}
              label="Risk Reduction"
              value={`${currentRoadmap.summary.risk_reduction_percent.toFixed(1)}%`}
            />
          </div>

          {/* Severity Breakdown */}
          <div className="bg-gray-800 rounded-lg p-4">
            <h3 className="text-sm font-medium text-gray-400 mb-3">Tasks by Severity</h3>
            <div className="flex space-x-6">
              <SeverityBadge label="Critical" count={currentRoadmap.summary.critical_count} color="red" />
              <SeverityBadge label="High" count={currentRoadmap.summary.high_count} color="orange" />
              <SeverityBadge label="Medium" count={currentRoadmap.summary.medium_count} color="yellow" />
              <SeverityBadge label="Low" count={currentRoadmap.summary.low_count} color="green" />
            </div>
          </div>

          {/* Risk Projection Chart */}
          {currentRoadmap.risk_projection.weekly_risk.length > 0 && (
            <div className="bg-gray-800 rounded-lg p-4">
              <h3 className="flex items-center space-x-2 text-sm font-medium text-gray-400 mb-3">
                <BarChart3 className="w-4 h-4" />
                <span>Risk Reduction Projection</span>
              </h3>
              <div className="flex items-end space-x-2 h-32">
                {currentRoadmap.risk_projection.weekly_risk.map((week, i) => {
                  const height = (week.risk_score / currentRoadmap.risk_projection.initial_risk) * 100;
                  return (
                    <div key={i} className="flex-1 flex flex-col items-center">
                      <div
                        className="w-full bg-cyan-500/50 rounded-t"
                        style={{ height: `${height}%` }}
                        title={`Week ${week.week}: Risk Score ${week.risk_score.toFixed(0)}`}
                      />
                      <span className="text-xs text-gray-500 mt-1">W{week.week}</span>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* Resource Suggestions */}
          {currentRoadmap.resource_suggestions.length > 0 && (
            <div className="bg-gray-800 rounded-lg p-4">
              <h3 className="flex items-center space-x-2 text-sm font-medium text-gray-400 mb-3">
                <Users className="w-4 h-4" />
                <span>Resource Allocation</span>
              </h3>
              <div className="space-y-2">
                {currentRoadmap.resource_suggestions.map((resource, i) => (
                  <div key={i} className="flex items-center justify-between text-sm">
                    <div className="flex items-center space-x-2">
                      <span>{getAssigneeIcon(resource.resource_type)}</span>
                      <span className="text-white capitalize">
                        {resource.resource_type.replace(/_/g, ' ')}
                      </span>
                    </div>
                    <div className="flex items-center space-x-4 text-gray-400">
                      <span>{resource.recommended_fte} FTE</span>
                      <span>{resource.total_hours}h total</span>
                      <span>Peak: Week {resource.peak_week}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Critical Path */}
          {currentRoadmap.critical_path.length > 0 && (
            <div className="bg-gray-800 rounded-lg p-4">
              <h3 className="flex items-center space-x-2 text-sm font-medium text-gray-400 mb-3">
                <AlertTriangle className="w-4 h-4 text-red-400" />
                <span>Critical Path</span>
              </h3>
              <div className="space-y-2">
                {currentRoadmap.critical_path.slice(0, 5).map((item, i) => (
                  <div key={i} className="flex items-start space-x-3 text-sm">
                    <span className="flex-shrink-0 w-6 h-6 bg-red-500/20 text-red-400 rounded-full flex items-center justify-center text-xs">
                      {item.sequence}
                    </span>
                    <div>
                      <p className="text-white">{item.reason}</p>
                      <p className="text-gray-500 text-xs">{item.delay_risk}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Phases */}
          <div className="space-y-4">
            <h3 className="text-lg font-medium text-white">Remediation Phases</h3>
            {currentRoadmap.phases.map((phase) => (
              <PhaseCard
                key={phase.phase_number}
                phase={phase}
                isExpanded={expandedPhases.has(phase.phase_number)}
                onToggle={() => togglePhase(phase.phase_number)}
                getSeverityColor={getSeverityColor}
                formatDate={formatDate}
                getAssigneeIcon={getAssigneeIcon}
              />
            ))}
          </div>

          {/* Delete Button */}
          <div className="flex justify-end">
            <button
              onClick={() => currentRoadmap && deleteMutation.mutate(currentRoadmap.id)}
              className="flex items-center space-x-2 px-3 py-1.5 text-red-400 hover:text-red-300 hover:bg-red-400/10 rounded"
            >
              <Trash2 className="w-4 h-4" />
              <span>Delete Roadmap</span>
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

// Summary Card Component
function SummaryCard({ icon, label, value }: { icon: React.ReactNode; label: string; value: string | number }) {
  return (
    <div className="bg-gray-800 rounded-lg p-4">
      <div className="flex items-center space-x-2 mb-2">
        {icon}
        <span className="text-sm text-gray-400">{label}</span>
      </div>
      <p className="text-2xl font-bold text-white">{value}</p>
    </div>
  );
}

// Severity Badge Component
function SeverityBadge({ label, count, color }: { label: string; count: number; color: string }) {
  const colors: Record<string, string> = {
    red: 'bg-red-400/10 text-red-400',
    orange: 'bg-orange-400/10 text-orange-400',
    yellow: 'bg-yellow-400/10 text-yellow-400',
    green: 'bg-green-400/10 text-green-400',
  };
  return (
    <div className="flex items-center space-x-2">
      <span className={`px-2 py-1 rounded text-sm ${colors[color]}`}>{label}</span>
      <span className="text-white font-medium">{count}</span>
    </div>
  );
}

// Phase Card Component
interface PhaseCardProps {
  phase: RemediationPhase;
  isExpanded: boolean;
  onToggle: () => void;
  getSeverityColor: (severity: string) => string;
  formatDate: (date: string) => string;
  getAssigneeIcon: (assignee: string) => string;
}

function PhaseCard({ phase, isExpanded, onToggle, getSeverityColor, formatDate, getAssigneeIcon }: PhaseCardProps) {
  return (
    <div className="bg-gray-800 rounded-lg border border-gray-700">
      <button
        onClick={onToggle}
        className="w-full flex items-center justify-between p-4 text-left"
      >
        <div className="flex items-center space-x-4">
          {isExpanded ? (
            <ChevronDown className="w-5 h-5 text-gray-400" />
          ) : (
            <ChevronRight className="w-5 h-5 text-gray-400" />
          )}
          <div>
            <h4 className="text-white font-medium">{phase.name}</h4>
            <p className="text-sm text-gray-400">
              {formatDate(phase.start_date)} - {formatDate(phase.end_date)}
            </p>
          </div>
        </div>
        <div className="flex items-center space-x-4 text-sm text-gray-400">
          <span>{phase.tasks.length} tasks</span>
          <span>{phase.total_effort_hours}h</span>
          <span className="text-green-400">-{phase.expected_risk_reduction.toFixed(0)} risk</span>
        </div>
      </button>

      {isExpanded && (
        <div className="border-t border-gray-700 p-4">
          <div className="space-y-3">
            {phase.tasks.map((task) => (
              <TaskRow
                key={task.id}
                task={task}
                getSeverityColor={getSeverityColor}
                getAssigneeIcon={getAssigneeIcon}
              />
            ))}
          </div>

          {phase.parallel_groups.length > 0 && (
            <div className="mt-4 pt-4 border-t border-gray-700">
              <p className="text-sm text-gray-400 mb-2">Parallel Work Groups:</p>
              <div className="flex flex-wrap gap-2">
                {phase.parallel_groups.map((group, i) => (
                  <span
                    key={i}
                    className="px-2 py-1 bg-cyan-400/10 text-cyan-400 rounded text-xs"
                  >
                    {group.name} ({group.task_ids.length} tasks, {group.parallel_effort_hours}h parallel)
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// Task Row Component
interface TaskRowProps {
  task: RemediationTask;
  getSeverityColor: (severity: string) => string;
  getAssigneeIcon: (assignee: string) => string;
}

function TaskRow({ task, getSeverityColor, getAssigneeIcon }: TaskRowProps) {
  const [showDetails, setShowDetails] = useState(false);

  return (
    <div className="bg-gray-700/50 rounded p-3">
      <div
        className="flex items-center justify-between cursor-pointer"
        onClick={() => setShowDetails(!showDetails)}
      >
        <div className="flex items-center space-x-3">
          <span className={`px-2 py-0.5 rounded text-xs ${getSeverityColor(task.severity)}`}>
            {task.severity}
          </span>
          <span className="text-white text-sm">{task.title}</span>
        </div>
        <div className="flex items-center space-x-4 text-sm text-gray-400">
          <span>{getAssigneeIcon(task.suggested_assignee)}</span>
          <span>{task.effort_hours}h</span>
          <span className="text-cyan-400">{task.priority_score.toFixed(0)} risk</span>
          {task.requires_downtime && (
            <span title="Requires downtime">
              <AlertTriangle className="w-4 h-4 text-yellow-400" />
            </span>
          )}
        </div>
      </div>

      {showDetails && (
        <div className="mt-3 pt-3 border-t border-gray-600 text-sm">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <p className="text-gray-400">Host: <span className="text-white">{task.host}</span></p>
              {task.port && <p className="text-gray-400">Port: <span className="text-white">{task.port}</span></p>}
            </div>
            <div>
              <p className="text-gray-400">
                Assignee: <span className="text-white capitalize">{task.suggested_assignee.replace(/_/g, ' ')}</span>
              </p>
              <p className="text-gray-400">
                Risk: <span className="text-red-400">{task.risk_before.toFixed(0)}</span>
                {' → '}
                <span className="text-green-400">{task.risk_after.toFixed(0)}</span>
              </p>
            </div>
          </div>

          {task.required_skills.length > 0 && (
            <div className="mt-2">
              <p className="text-gray-400 mb-1">Required Skills:</p>
              <div className="flex flex-wrap gap-1">
                {task.required_skills.map((skill, i) => (
                  <span key={i} className="px-2 py-0.5 bg-gray-600 rounded text-xs text-gray-300">
                    {skill}
                  </span>
                ))}
              </div>
            </div>
          )}

          {task.remediation_steps.length > 0 && (
            <div className="mt-2">
              <p className="text-gray-400 mb-1">Remediation Steps:</p>
              <ol className="list-decimal list-inside space-y-1 text-gray-300">
                {task.remediation_steps.map((step, i) => (
                  <li key={i}>{step}</li>
                ))}
              </ol>
            </div>
          )}

          {task.dependencies.length > 0 && (
            <div className="mt-2">
              <p className="text-yellow-400 text-xs">
                Depends on {task.dependencies.length} other task(s)
              </p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default RemediationRoadmap;
