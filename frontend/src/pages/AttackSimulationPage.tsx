import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Shield,
  Target,
  Play,
  Trash2,
  RefreshCw,
  Plus,
  AlertTriangle,
  Activity,
  Clock,
  CheckCircle,
  XCircle,
  ChevronRight,
  Loader2,
  BarChart3,
  Crosshair,
  List,
} from 'lucide-react';
import { toast } from 'react-toastify';
import { basAPI } from '../services/api';
import type {
  AttackTechnique,
  MitreTactic,
  SimulationScenario,
  SimulationSummary,
  BasStats,
} from '../types';
import Header from '../components/layout/Header';
import Button from '../components/ui/Button';
import TechniqueCard from '../components/bas/TechniqueCard';
import ScenarioBuilder from '../components/bas/ScenarioBuilder';
import SimulationResults from '../components/bas/SimulationResults';
import DetectionGapList from '../components/bas/DetectionGapList';

type TabType = 'techniques' | 'scenarios' | 'simulations' | 'gaps';

const AttackSimulationPage: React.FC = () => {
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState<TabType>('scenarios');
  const [showScenarioBuilder, setShowScenarioBuilder] = useState(false);
  const [selectedSimulationId, setSelectedSimulationId] = useState<string | null>(null);
  const [tacticFilter, setTacticFilter] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [expandedTechnique, setExpandedTechnique] = useState<string | null>(null);

  // Fetch data
  const { data: techniques = [], isLoading: loadingTechniques } = useQuery({
    queryKey: ['bas-techniques'],
    queryFn: async () => {
      const response = await basAPI.listTechniques();
      return response.data.techniques;
    },
    enabled: activeTab === 'techniques',
  });

  const { data: tactics = [] } = useQuery({
    queryKey: ['bas-tactics'],
    queryFn: async () => {
      const response = await basAPI.listTactics();
      return response.data.tactics;
    },
  });

  const {
    data: scenarios = [],
    isLoading: loadingScenarios,
    refetch: refetchScenarios,
  } = useQuery({
    queryKey: ['bas-scenarios'],
    queryFn: async () => {
      const response = await basAPI.listScenarios();
      return response.data.scenarios;
    },
    enabled: activeTab === 'scenarios',
  });

  const {
    data: simulations = [],
    isLoading: loadingSimulations,
    refetch: refetchSimulations,
  } = useQuery({
    queryKey: ['bas-simulations'],
    queryFn: async () => {
      const response = await basAPI.listSimulations();
      return response.data.simulations;
    },
    enabled: activeTab === 'simulations',
  });

  const { data: stats } = useQuery({
    queryKey: ['bas-stats'],
    queryFn: async () => {
      const response = await basAPI.getStats();
      return response.data;
    },
  });

  // Mutations
  const deleteScenarioMutation = useMutation({
    mutationFn: async (id: string) => {
      await basAPI.deleteScenario(id);
    },
    onSuccess: () => {
      toast.success('Scenario deleted');
      queryClient.invalidateQueries({ queryKey: ['bas-scenarios'] });
    },
    onError: (error: Error) => {
      toast.error(error.message || 'Failed to delete scenario');
    },
  });

  const startSimulationMutation = useMutation({
    mutationFn: async (scenarioId: string) => {
      const response = await basAPI.startSimulation({ scenario_id: scenarioId });
      return response.data;
    },
    onSuccess: (simulation) => {
      toast.success('Simulation started');
      queryClient.invalidateQueries({ queryKey: ['bas-simulations'] });
      setActiveTab('simulations');
      setSelectedSimulationId(simulation.id);
    },
    onError: (error: Error) => {
      toast.error(error.message || 'Failed to start simulation');
    },
  });

  // Filter techniques
  const filteredTechniques = techniques.filter((t) => {
    if (tacticFilter !== 'all' && t.tactic !== tacticFilter) return false;
    if (searchQuery) {
      const query = searchQuery.toLowerCase();
      return (
        t.name.toLowerCase().includes(query) ||
        t.id.toLowerCase().includes(query) ||
        t.description.toLowerCase().includes(query)
      );
    }
    return true;
  });

  const getStatusIcon = (status: string) => {
    switch (status.toLowerCase()) {
      case 'completed':
        return <CheckCircle className="w-4 h-4 text-green-400" />;
      case 'failed':
        return <XCircle className="w-4 h-4 text-red-400" />;
      case 'running':
        return <Activity className="w-4 h-4 text-cyan-400 animate-pulse" />;
      default:
        return <Clock className="w-4 h-4 text-yellow-400" />;
    }
  };

  const getScoreColor = (score: number): string => {
    if (score >= 80) return 'text-green-400';
    if (score >= 60) return 'text-yellow-400';
    if (score >= 40) return 'text-orange-400';
    return 'text-red-400';
  };

  // If viewing simulation results
  if (selectedSimulationId) {
    return (
      <div className="min-h-screen bg-light-bg dark:bg-dark-bg">
        <Header />
        <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
          <SimulationResults
            simulationId={selectedSimulationId}
            onBack={() => setSelectedSimulationId(null)}
          />
        </main>
      </div>
    );
  }

  // If showing scenario builder
  if (showScenarioBuilder) {
    return (
      <div className="min-h-screen bg-light-bg dark:bg-dark-bg">
        <Header />
        <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
          <ScenarioBuilder
            onScenarioCreated={() => {
              setShowScenarioBuilder(false);
              setActiveTab('scenarios');
            }}
            onCancel={() => setShowScenarioBuilder(false)}
          />
        </main>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-light-bg dark:bg-dark-bg">
      <Header />
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {/* Page Header */}
        <div className="mb-6">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-2xl font-bold text-gray-900 dark:text-white flex items-center gap-3">
                <Crosshair className="w-7 h-7 text-primary" />
                Breach & Attack Simulation
              </h1>
              <p className="text-gray-500 dark:text-gray-400 mt-1">
                Test your security controls against MITRE ATT&CK techniques
              </p>
            </div>
            <Button onClick={() => setShowScenarioBuilder(true)}>
              <Plus className="w-4 h-4 mr-2" />
              New Scenario
            </Button>
          </div>
        </div>

        {/* Stats Cards */}
        {stats && (
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
            <StatCard
              icon={<Target className="w-5 h-5" />}
              label="Scenarios"
              value={stats.total_scenarios}
            />
            <StatCard
              icon={<Activity className="w-5 h-5" />}
              label="Simulations"
              value={stats.total_simulations}
            />
            <StatCard
              icon={<Shield className="w-5 h-5" />}
              label="Avg Detection Rate"
              value={`${(stats.avg_detection_rate * 100).toFixed(0)}%`}
              valueColor={getScoreColor(stats.avg_detection_rate * 100)}
            />
            <StatCard
              icon={<AlertTriangle className="w-5 h-5" />}
              label="Unacked Gaps"
              value={stats.unacknowledged_gaps}
              valueColor={stats.unacknowledged_gaps > 0 ? 'text-yellow-400' : 'text-green-400'}
            />
          </div>
        )}

        {/* Tabs */}
        <div className="flex items-center gap-4 mb-6 border-b border-light-border dark:border-dark-border">
          <TabButton
            active={activeTab === 'scenarios'}
            onClick={() => setActiveTab('scenarios')}
            icon={<Target className="w-4 h-4" />}
            label="Scenarios"
          />
          <TabButton
            active={activeTab === 'simulations'}
            onClick={() => setActiveTab('simulations')}
            icon={<Activity className="w-4 h-4" />}
            label="Simulations"
          />
          <TabButton
            active={activeTab === 'techniques'}
            onClick={() => setActiveTab('techniques')}
            icon={<List className="w-4 h-4" />}
            label="Techniques"
          />
          <TabButton
            active={activeTab === 'gaps'}
            onClick={() => setActiveTab('gaps')}
            icon={<AlertTriangle className="w-4 h-4" />}
            label="Detection Gaps"
            badge={stats?.unacknowledged_gaps}
          />
        </div>

        {/* Tab Content */}
        {activeTab === 'scenarios' && (
          <div>
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                Attack Scenarios
              </h3>
              <Button variant="outline" size="sm" onClick={() => refetchScenarios()}>
                <RefreshCw className="w-4 h-4 mr-2" />
                Refresh
              </Button>
            </div>

            {loadingScenarios ? (
              <LoadingState />
            ) : scenarios.length === 0 ? (
              <EmptyState
                icon={<Target className="w-12 h-12 text-gray-400" />}
                title="No Scenarios Yet"
                description="Create your first attack scenario to test your security controls."
                action={
                  <Button onClick={() => setShowScenarioBuilder(true)}>
                    <Plus className="w-4 h-4 mr-2" />
                    Create Scenario
                  </Button>
                }
              />
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {scenarios.map((scenario) => (
                  <ScenarioCard
                    key={scenario.id}
                    scenario={scenario}
                    onRun={() => startSimulationMutation.mutate(scenario.id)}
                    onDelete={() => deleteScenarioMutation.mutate(scenario.id)}
                    isRunning={startSimulationMutation.isPending}
                  />
                ))}
              </div>
            )}
          </div>
        )}

        {activeTab === 'simulations' && (
          <div>
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                Simulation History
              </h3>
              <Button variant="outline" size="sm" onClick={() => refetchSimulations()}>
                <RefreshCw className="w-4 h-4 mr-2" />
                Refresh
              </Button>
            </div>

            {loadingSimulations ? (
              <LoadingState />
            ) : simulations.length === 0 ? (
              <EmptyState
                icon={<Activity className="w-12 h-12 text-gray-400" />}
                title="No Simulations Yet"
                description="Run a scenario to see simulation results here."
              />
            ) : (
              <div className="space-y-4">
                {simulations.map((simulation) => (
                  <SimulationCard
                    key={simulation.id}
                    simulation={simulation}
                    onView={() => setSelectedSimulationId(simulation.id)}
                  />
                ))}
              </div>
            )}
          </div>
        )}

        {activeTab === 'techniques' && (
          <div>
            <div className="flex flex-wrap gap-4 mb-4">
              <div className="flex-1 min-w-[200px]">
                <input
                  type="text"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder="Search techniques..."
                  className="w-full px-3 py-2 bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg text-gray-900 dark:text-white focus:ring-2 focus:ring-primary focus:border-transparent"
                />
              </div>
              <select
                value={tacticFilter}
                onChange={(e) => setTacticFilter(e.target.value)}
                className="px-3 py-2 bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg text-gray-900 dark:text-white focus:ring-2 focus:ring-primary focus:border-transparent"
              >
                <option value="all">All Tactics</option>
                {tactics.map((tactic) => (
                  <option key={tactic.id} value={tactic.id}>
                    {tactic.name}
                  </option>
                ))}
              </select>
              <span className="text-sm text-gray-500 dark:text-gray-400 self-center">
                {filteredTechniques.length} techniques
              </span>
            </div>

            {loadingTechniques ? (
              <LoadingState />
            ) : (
              <div className="space-y-3">
                {filteredTechniques.map((technique) => (
                  <TechniqueCard
                    key={technique.id}
                    technique={technique}
                    expanded={expandedTechnique === technique.id}
                    onToggleExpand={() =>
                      setExpandedTechnique(
                        expandedTechnique === technique.id ? null : technique.id
                      )
                    }
                  />
                ))}
              </div>
            )}
          </div>
        )}

        {activeTab === 'gaps' && (
          <div>
            <div className="mb-4">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                Unacknowledged Detection Gaps
              </h3>
              <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
                Review and acknowledge gaps in your detection coverage
              </p>
            </div>
            <DetectionGapList />
          </div>
        )}
      </main>
    </div>
  );
};

// Sub-components

const TabButton: React.FC<{
  active: boolean;
  onClick: () => void;
  icon: React.ReactNode;
  label: string;
  badge?: number;
}> = ({ active, onClick, icon, label, badge }) => (
  <button
    onClick={onClick}
    className={`pb-3 px-1 border-b-2 transition-colors flex items-center gap-2 ${
      active
        ? 'border-primary text-primary'
        : 'border-transparent text-gray-400 hover:text-gray-200'
    }`}
  >
    {icon}
    <span>{label}</span>
    {badge !== undefined && badge > 0 && (
      <span className="px-1.5 py-0.5 text-xs bg-yellow-500/20 text-yellow-400 rounded-full">
        {badge}
      </span>
    )}
  </button>
);

const StatCard: React.FC<{
  icon: React.ReactNode;
  label: string;
  value: string | number;
  valueColor?: string;
}> = ({ icon, label, value, valueColor = 'text-gray-900 dark:text-white' }) => (
  <div className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg p-4">
    <div className="flex items-center gap-2 text-gray-500 dark:text-gray-400 mb-2">
      {icon}
      <span className="text-sm font-medium">{label}</span>
    </div>
    <div className={`text-2xl font-bold ${valueColor}`}>{value}</div>
  </div>
);

const ScenarioCard: React.FC<{
  scenario: SimulationScenario;
  onRun: () => void;
  onDelete: () => void;
  isRunning: boolean;
}> = ({ scenario, onRun, onDelete, isRunning }) => (
  <div className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg p-4">
    <div className="flex items-start justify-between">
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 mb-2">
          <Target className="w-5 h-5 text-primary" />
          <h4 className="font-medium text-gray-900 dark:text-white truncate">{scenario.name}</h4>
          {scenario.status === 'builtin' && (
            <span className="text-xs px-2 py-0.5 bg-blue-500/20 text-blue-400 rounded">
              Built-in
            </span>
          )}
        </div>
        {scenario.description && (
          <p className="text-sm text-gray-500 dark:text-gray-400 line-clamp-2 mb-3">
            {scenario.description}
          </p>
        )}
        <div className="flex items-center gap-4 text-sm text-gray-500 dark:text-gray-400">
          <span>{scenario.technique_count} techniques</span>
          <span className="capitalize">{scenario.execution_mode.replace('_', ' ')}</span>
        </div>
        {scenario.tags.length > 0 && (
          <div className="flex flex-wrap gap-1 mt-2">
            {scenario.tags.map((tag) => (
              <span
                key={tag}
                className="text-xs px-2 py-0.5 bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-300 rounded"
              >
                {tag}
              </span>
            ))}
          </div>
        )}
      </div>
      <div className="flex items-center gap-2 ml-4">
        <Button variant="outline" size="sm" onClick={onRun} disabled={isRunning}>
          {isRunning ? (
            <Loader2 className="w-4 h-4 animate-spin" />
          ) : (
            <Play className="w-4 h-4" />
          )}
        </Button>
        {scenario.status !== 'builtin' && (
          <button
            onClick={onDelete}
            className="p-2 text-gray-400 hover:text-red-400 transition-colors"
            title="Delete scenario"
          >
            <Trash2 className="w-4 h-4" />
          </button>
        )}
      </div>
    </div>
  </div>
);

const SimulationCard: React.FC<{
  simulation: SimulationSummary;
  onView: () => void;
}> = ({ simulation, onView }) => {
  const getStatusIcon = (status: string) => {
    switch (status.toLowerCase()) {
      case 'completed':
        return <CheckCircle className="w-4 h-4 text-green-400" />;
      case 'failed':
        return <XCircle className="w-4 h-4 text-red-400" />;
      case 'running':
        return <Activity className="w-4 h-4 text-cyan-400 animate-pulse" />;
      default:
        return <Clock className="w-4 h-4 text-yellow-400" />;
    }
  };

  const getScoreColor = (score: number): string => {
    if (score >= 80) return 'text-green-400';
    if (score >= 60) return 'text-yellow-400';
    if (score >= 40) return 'text-orange-400';
    return 'text-red-400';
  };

  return (
    <div className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg p-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          {getStatusIcon(simulation.status)}
          <div>
            <div className="flex items-center gap-2">
              <span className="font-medium text-gray-900 dark:text-white">
                Simulation {simulation.id.slice(0, 8)}
              </span>
              <span className="text-sm text-gray-500 dark:text-gray-400 capitalize">
                ({simulation.execution_mode.replace('_', ' ')})
              </span>
            </div>
            <div className="text-sm text-gray-500 dark:text-gray-400">
              {new Date(simulation.started_at).toLocaleString()}
            </div>
          </div>
        </div>
        <div className="flex items-center gap-6">
          <div className="text-center">
            <div className={`text-lg font-bold ${getScoreColor(simulation.security_score)}`}>
              {simulation.security_score}%
            </div>
            <div className="text-xs text-gray-500 dark:text-gray-400">Score</div>
          </div>
          <div className="text-center">
            <div className="text-lg font-bold text-gray-900 dark:text-white">
              {(simulation.detection_rate * 100).toFixed(0)}%
            </div>
            <div className="text-xs text-gray-500 dark:text-gray-400">Detection</div>
          </div>
          <div className="text-center">
            <div className="text-lg font-bold text-gray-900 dark:text-white">
              {simulation.total_techniques}
            </div>
            <div className="text-xs text-gray-500 dark:text-gray-400">Techniques</div>
          </div>
          <button
            onClick={onView}
            className="p-2 text-gray-400 hover:text-primary transition-colors"
            title="View details"
          >
            <ChevronRight className="w-5 h-5" />
          </button>
        </div>
      </div>
    </div>
  );
};

const LoadingState: React.FC = () => (
  <div className="flex items-center justify-center py-12">
    <Loader2 className="w-8 h-8 text-primary animate-spin" />
  </div>
);

const EmptyState: React.FC<{
  icon: React.ReactNode;
  title: string;
  description: string;
  action?: React.ReactNode;
}> = ({ icon, title, description, action }) => (
  <div className="text-center py-12 bg-light-surface dark:bg-dark-surface rounded-lg border border-light-border dark:border-dark-border">
    <div className="mb-4 flex justify-center">{icon}</div>
    <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">{title}</h3>
    <p className="text-gray-500 dark:text-gray-400 mb-4">{description}</p>
    {action}
  </div>
);

export default AttackSimulationPage;
