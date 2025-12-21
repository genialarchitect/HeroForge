import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Plus,
  X,
  Play,
  Settings,
  ChevronDown,
  ChevronUp,
  AlertTriangle,
  CheckCircle,
  Loader2,
} from 'lucide-react';
import { toast } from 'react-toastify';
import { basAPI } from '../../services/api';
import type {
  AttackTechnique,
  BasExecutionMode,
  CreateScenarioRequest,
} from '../../types';
import TechniqueCard from './TechniqueCard';
import Button from '../ui/Button';

interface ScenarioBuilderProps {
  onScenarioCreated?: (scenarioId: string) => void;
  onCancel?: () => void;
}

const ScenarioBuilder: React.FC<ScenarioBuilderProps> = ({
  onScenarioCreated,
  onCancel,
}) => {
  const queryClient = useQueryClient();
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [executionMode, setExecutionMode] = useState<BasExecutionMode>('dry_run');
  const [selectedTechniques, setSelectedTechniques] = useState<string[]>([]);
  const [timeoutSecs, setTimeoutSecs] = useState(300);
  const [parallelExecution, setParallelExecution] = useState(false);
  const [continueOnFailure, setContinueOnFailure] = useState(true);
  const [tags, setTags] = useState<string[]>([]);
  const [newTag, setNewTag] = useState('');
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [tacticFilter, setTacticFilter] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState('');

  // Fetch techniques
  const { data: techniquesData, isLoading: loadingTechniques } = useQuery({
    queryKey: ['bas-techniques'],
    queryFn: async () => {
      const response = await basAPI.listTechniques();
      return response.data;
    },
  });

  // Fetch tactics
  const { data: tacticsData } = useQuery({
    queryKey: ['bas-tactics'],
    queryFn: async () => {
      const response = await basAPI.listTactics();
      return response.data;
    },
  });

  // Create scenario mutation
  const createMutation = useMutation({
    mutationFn: async (data: CreateScenarioRequest) => {
      const response = await basAPI.createScenario(data);
      return response.data;
    },
    onSuccess: (scenario) => {
      toast.success('Scenario created successfully');
      queryClient.invalidateQueries({ queryKey: ['bas-scenarios'] });
      onScenarioCreated?.(scenario.id);
    },
    onError: (error: Error) => {
      toast.error(error.message || 'Failed to create scenario');
    },
  });

  const techniques = techniquesData?.techniques || [];
  const tactics = tacticsData?.tactics || [];

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

  const handleToggleTechnique = (techniqueId: string) => {
    setSelectedTechniques((prev) =>
      prev.includes(techniqueId)
        ? prev.filter((id) => id !== techniqueId)
        : [...prev, techniqueId]
    );
  };

  const handleAddTag = () => {
    if (newTag && !tags.includes(newTag)) {
      setTags([...tags, newTag]);
      setNewTag('');
    }
  };

  const handleRemoveTag = (tag: string) => {
    setTags(tags.filter((t) => t !== tag));
  };

  const handleSubmit = () => {
    if (!name.trim()) {
      toast.error('Please enter a scenario name');
      return;
    }
    if (selectedTechniques.length === 0) {
      toast.error('Please select at least one technique');
      return;
    }

    createMutation.mutate({
      name: name.trim(),
      description: description.trim(),
      execution_mode: executionMode,
      technique_ids: selectedTechniques,
      targets: [],
      timeout_secs: timeoutSecs,
      parallel_execution: parallelExecution,
      continue_on_failure: continueOnFailure,
      tags,
    });
  };

  const getExecutionModeInfo = (mode: BasExecutionMode) => {
    switch (mode) {
      case 'dry_run':
        return {
          label: 'Dry Run',
          description: 'Simulate techniques without actual execution. Safe for testing.',
          color: 'text-green-400',
          icon: <CheckCircle className="w-4 h-4" />,
        };
      case 'safe':
        return {
          label: 'Safe Mode',
          description: 'Execute techniques with safety limits. Some artifacts may be created.',
          color: 'text-yellow-400',
          icon: <AlertTriangle className="w-4 h-4" />,
        };
      case 'full':
        return {
          label: 'Full Execution',
          description: 'Execute techniques fully. Use with caution in controlled environments.',
          color: 'text-red-400',
          icon: <AlertTriangle className="w-4 h-4" />,
        };
    }
  };

  return (
    <div className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg">
      {/* Header */}
      <div className="p-4 border-b border-light-border dark:border-dark-border">
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
          Create Attack Scenario
        </h3>
        <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
          Build a simulation scenario by selecting MITRE ATT&CK techniques
        </p>
      </div>

      <div className="p-4 space-y-6">
        {/* Basic Info */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
              Scenario Name *
            </label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g., Initial Access Validation"
              className="w-full px-3 py-2 bg-light-bg dark:bg-dark-bg border border-light-border dark:border-dark-border rounded-lg text-gray-900 dark:text-white focus:ring-2 focus:ring-primary focus:border-transparent"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
              Execution Mode
            </label>
            <select
              value={executionMode}
              onChange={(e) => setExecutionMode(e.target.value as BasExecutionMode)}
              className="w-full px-3 py-2 bg-light-bg dark:bg-dark-bg border border-light-border dark:border-dark-border rounded-lg text-gray-900 dark:text-white focus:ring-2 focus:ring-primary focus:border-transparent"
            >
              <option value="dry_run">Dry Run (Safe)</option>
              <option value="safe">Safe Mode</option>
              <option value="full">Full Execution</option>
            </select>
            <p className={`text-xs mt-1 ${getExecutionModeInfo(executionMode).color}`}>
              {getExecutionModeInfo(executionMode).description}
            </p>
          </div>
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
            Description
          </label>
          <textarea
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="Describe the purpose of this simulation scenario..."
            rows={2}
            className="w-full px-3 py-2 bg-light-bg dark:bg-dark-bg border border-light-border dark:border-dark-border rounded-lg text-gray-900 dark:text-white focus:ring-2 focus:ring-primary focus:border-transparent"
          />
        </div>

        {/* Tags */}
        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
            Tags
          </label>
          <div className="flex flex-wrap gap-2 mb-2">
            {tags.map((tag) => (
              <span
                key={tag}
                className="inline-flex items-center gap-1 px-2 py-1 text-xs bg-primary/20 text-primary rounded"
              >
                {tag}
                <button
                  onClick={() => handleRemoveTag(tag)}
                  className="hover:text-red-400"
                >
                  <X className="w-3 h-3" />
                </button>
              </span>
            ))}
          </div>
          <div className="flex gap-2">
            <input
              type="text"
              value={newTag}
              onChange={(e) => setNewTag(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleAddTag()}
              placeholder="Add a tag..."
              className="flex-1 px-3 py-2 text-sm bg-light-bg dark:bg-dark-bg border border-light-border dark:border-dark-border rounded-lg text-gray-900 dark:text-white focus:ring-2 focus:ring-primary focus:border-transparent"
            />
            <Button variant="outline" size="sm" onClick={handleAddTag}>
              <Plus className="w-4 h-4" />
            </Button>
          </div>
        </div>

        {/* Advanced Options */}
        <div>
          <button
            onClick={() => setShowAdvanced(!showAdvanced)}
            className="flex items-center gap-2 text-sm text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-200"
          >
            <Settings className="w-4 h-4" />
            Advanced Options
            {showAdvanced ? (
              <ChevronUp className="w-4 h-4" />
            ) : (
              <ChevronDown className="w-4 h-4" />
            )}
          </button>

          {showAdvanced && (
            <div className="mt-4 p-4 bg-light-bg dark:bg-dark-bg rounded-lg space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Timeout (seconds)
                </label>
                <input
                  type="number"
                  value={timeoutSecs}
                  onChange={(e) => setTimeoutSecs(parseInt(e.target.value) || 300)}
                  min={60}
                  max={3600}
                  className="w-32 px-3 py-2 bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg text-gray-900 dark:text-white focus:ring-2 focus:ring-primary focus:border-transparent"
                />
              </div>

              <div className="flex items-center gap-6">
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={parallelExecution}
                    onChange={(e) => setParallelExecution(e.target.checked)}
                    className="w-4 h-4 rounded border-gray-300 text-primary focus:ring-primary"
                  />
                  <span className="text-sm text-gray-700 dark:text-gray-300">
                    Execute techniques in parallel
                  </span>
                </label>

                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={continueOnFailure}
                    onChange={(e) => setContinueOnFailure(e.target.checked)}
                    className="w-4 h-4 rounded border-gray-300 text-primary focus:ring-primary"
                  />
                  <span className="text-sm text-gray-700 dark:text-gray-300">
                    Continue on failure
                  </span>
                </label>
              </div>
            </div>
          )}
        </div>

        {/* Technique Selection */}
        <div>
          <div className="flex items-center justify-between mb-4">
            <h4 className="font-medium text-gray-900 dark:text-white">
              Select Techniques ({selectedTechniques.length} selected)
            </h4>
          </div>

          {/* Filters */}
          <div className="flex flex-wrap gap-4 mb-4">
            <div className="flex-1 min-w-[200px]">
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search techniques..."
                className="w-full px-3 py-2 bg-light-bg dark:bg-dark-bg border border-light-border dark:border-dark-border rounded-lg text-gray-900 dark:text-white focus:ring-2 focus:ring-primary focus:border-transparent"
              />
            </div>
            <select
              value={tacticFilter}
              onChange={(e) => setTacticFilter(e.target.value)}
              className="px-3 py-2 bg-light-bg dark:bg-dark-bg border border-light-border dark:border-dark-border rounded-lg text-gray-900 dark:text-white focus:ring-2 focus:ring-primary focus:border-transparent"
            >
              <option value="all">All Tactics</option>
              {tactics.map((tactic) => (
                <option key={tactic.id} value={tactic.id}>
                  {tactic.name}
                </option>
              ))}
            </select>
          </div>

          {/* Technique List */}
          {loadingTechniques ? (
            <div className="flex items-center justify-center py-12">
              <Loader2 className="w-8 h-8 text-primary animate-spin" />
            </div>
          ) : (
            <div className="space-y-2 max-h-96 overflow-y-auto">
              {filteredTechniques.map((technique) => (
                <TechniqueCard
                  key={technique.id}
                  technique={technique}
                  isSelected={selectedTechniques.includes(technique.id)}
                  onToggleSelect={handleToggleTechnique}
                />
              ))}
              {filteredTechniques.length === 0 && (
                <div className="text-center py-8 text-gray-500 dark:text-gray-400">
                  No techniques match your filters
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      {/* Footer */}
      <div className="p-4 border-t border-light-border dark:border-dark-border flex items-center justify-between">
        <div className="text-sm text-gray-500 dark:text-gray-400">
          {selectedTechniques.length} technique{selectedTechniques.length !== 1 ? 's' : ''} selected
        </div>
        <div className="flex gap-3">
          {onCancel && (
            <Button variant="outline" onClick={onCancel}>
              Cancel
            </Button>
          )}
          <Button
            onClick={handleSubmit}
            disabled={createMutation.isPending || selectedTechniques.length === 0}
          >
            {createMutation.isPending ? (
              <Loader2 className="w-4 h-4 mr-2 animate-spin" />
            ) : (
              <Play className="w-4 h-4 mr-2" />
            )}
            Create Scenario
          </Button>
        </div>
      </div>
    </div>
  );
};

export default ScenarioBuilder;
