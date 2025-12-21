import React, { useState, useEffect } from 'react';
import { Calendar, Clock, Plus, X, Shield, Play } from 'lucide-react';
import { toast } from 'react-toastify';
import Button from '../ui/Button';
import type {
  CreateScheduleRequest,
  UpdateScheduleRequest,
  EvidenceCollectionSchedule,
} from '../../types/evidence';

interface ScheduleFormProps {
  schedule?: EvidenceCollectionSchedule;
  onSubmit: (data: CreateScheduleRequest | UpdateScheduleRequest) => Promise<void>;
  onCancel?: () => void;
  frameworks?: { id: string; name: string }[];
  controls?: { id: string; name: string; framework_id: string }[];
}

const collectionSources = [
  { value: 'automated_scan', label: 'Automated Scan' },
  { value: 'scheduled_collection', label: 'Scheduled Collection' },
  { value: 'api_integration', label: 'API Integration' },
];

const cronPresets = [
  { value: '0 0 * * *', label: 'Daily at midnight' },
  { value: '0 0 * * 0', label: 'Weekly on Sunday' },
  { value: '0 0 1 * *', label: 'Monthly on 1st' },
  { value: '0 0 1 */3 *', label: 'Quarterly' },
  { value: '0 0 1 1 *', label: 'Yearly on Jan 1' },
  { value: '0 */6 * * *', label: 'Every 6 hours' },
  { value: '0 0 * * 1-5', label: 'Weekdays at midnight' },
];

const ScheduleForm: React.FC<ScheduleFormProps> = ({
  schedule,
  onSubmit,
  onCancel,
  frameworks = [],
  controls = [],
}) => {
  const [name, setName] = useState(schedule?.name || '');
  const [description, setDescription] = useState(schedule?.description || '');
  const [collectionSource, setCollectionSource] = useState<string>(
    schedule?.collection_source || 'scheduled_collection'
  );
  const [cronExpression, setCronExpression] = useState(schedule?.cron_expression || '0 0 * * *');
  const [selectedFrameworks, setSelectedFrameworks] = useState<string[]>(
    schedule?.framework_ids || []
  );
  const [selectedControls, setSelectedControls] = useState<string[]>(schedule?.control_ids || []);
  const [enabled, setEnabled] = useState(schedule?.enabled ?? true);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [cronPreset, setCronPreset] = useState('');

  const isEditing = !!schedule;

  // Filter controls based on selected frameworks
  const filteredControls =
    selectedFrameworks.length > 0
      ? controls.filter((c) => selectedFrameworks.includes(c.framework_id))
      : controls;

  useEffect(() => {
    // Check if current cron matches a preset
    const matchedPreset = cronPresets.find((p) => p.value === cronExpression);
    setCronPreset(matchedPreset?.value || 'custom');
  }, [cronExpression]);

  const handleFrameworkToggle = (frameworkId: string) => {
    setSelectedFrameworks((prev) =>
      prev.includes(frameworkId) ? prev.filter((id) => id !== frameworkId) : [...prev, frameworkId]
    );
  };

  const handleControlToggle = (controlId: string) => {
    setSelectedControls((prev) =>
      prev.includes(controlId) ? prev.filter((id) => id !== controlId) : [...prev, controlId]
    );
  };

  const handlePresetChange = (value: string) => {
    setCronPreset(value);
    if (value !== 'custom') {
      setCronExpression(value);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!name.trim()) {
      toast.error('Please enter a name');
      return;
    }

    if (!cronExpression.trim()) {
      toast.error('Please enter a cron expression');
      return;
    }

    if (selectedFrameworks.length === 0) {
      toast.error('Please select at least one framework');
      return;
    }

    if (selectedControls.length === 0) {
      toast.error('Please select at least one control');
      return;
    }

    setIsSubmitting(true);

    try {
      if (isEditing) {
        const data: UpdateScheduleRequest = {
          name: name.trim(),
          description: description.trim() || undefined,
          cron_expression: cronExpression.trim(),
          framework_ids: selectedFrameworks,
          control_ids: selectedControls,
          enabled,
        };
        await onSubmit(data);
        toast.success('Schedule updated successfully');
      } else {
        const data: CreateScheduleRequest = {
          name: name.trim(),
          description: description.trim() || undefined,
          collection_source: collectionSource,
          cron_expression: cronExpression.trim(),
          framework_ids: selectedFrameworks,
          control_ids: selectedControls,
        };
        await onSubmit(data);
        toast.success('Schedule created successfully');
      }
    } catch {
      toast.error(isEditing ? 'Failed to update schedule' : 'Failed to create schedule');
    } finally {
      setIsSubmitting(false);
    }
  };

  const parseCronDescription = (cron: string): string => {
    const matchedPreset = cronPresets.find((p) => p.value === cron);
    if (matchedPreset) return matchedPreset.label;

    // Basic parsing for common patterns
    const parts = cron.split(' ');
    if (parts.length !== 5) return 'Custom schedule';

    const [minute, hour, dayOfMonth, month, dayOfWeek] = parts;

    if (minute === '0' && hour === '0' && dayOfMonth === '*' && month === '*' && dayOfWeek === '*') {
      return 'Daily at midnight';
    }

    return 'Custom schedule';
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-6">
      {/* Name */}
      <div>
        <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
          Schedule Name <span className="text-red-500">*</span>
        </label>
        <input
          type="text"
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="Enter schedule name"
          className="w-full px-3 py-2 bg-light-bg dark:bg-dark-bg border border-light-border dark:border-dark-border rounded-lg text-slate-900 dark:text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-primary"
        />
      </div>

      {/* Description */}
      <div>
        <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
          Description
        </label>
        <textarea
          value={description}
          onChange={(e) => setDescription(e.target.value)}
          placeholder="Enter a description for this schedule"
          rows={2}
          className="w-full px-3 py-2 bg-light-bg dark:bg-dark-bg border border-light-border dark:border-dark-border rounded-lg text-slate-900 dark:text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-primary resize-none"
        />
      </div>

      {/* Collection Source (only for new schedules) */}
      {!isEditing && (
        <div>
          <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
            Collection Source <span className="text-red-500">*</span>
          </label>
          <select
            value={collectionSource}
            onChange={(e) => setCollectionSource(e.target.value)}
            className="w-full px-3 py-2 bg-light-bg dark:bg-dark-bg border border-light-border dark:border-dark-border rounded-lg text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-primary"
          >
            {collectionSources.map((source) => (
              <option key={source.value} value={source.value}>
                {source.label}
              </option>
            ))}
          </select>
        </div>
      )}

      {/* Schedule Preset */}
      <div>
        <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
          <Calendar className="inline h-4 w-4 mr-1" />
          Schedule Frequency
        </label>
        <select
          value={cronPreset}
          onChange={(e) => handlePresetChange(e.target.value)}
          className="w-full px-3 py-2 bg-light-bg dark:bg-dark-bg border border-light-border dark:border-dark-border rounded-lg text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-primary"
        >
          {cronPresets.map((preset) => (
            <option key={preset.value} value={preset.value}>
              {preset.label}
            </option>
          ))}
          <option value="custom">Custom cron expression</option>
        </select>
      </div>

      {/* Cron Expression */}
      <div>
        <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
          <Clock className="inline h-4 w-4 mr-1" />
          Cron Expression <span className="text-red-500">*</span>
        </label>
        <input
          type="text"
          value={cronExpression}
          onChange={(e) => setCronExpression(e.target.value)}
          placeholder="0 0 * * *"
          className="w-full px-3 py-2 bg-light-bg dark:bg-dark-bg border border-light-border dark:border-dark-border rounded-lg text-slate-900 dark:text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-primary font-mono"
        />
        <p className="text-xs text-slate-500 mt-1">
          Schedule: {parseCronDescription(cronExpression)}
        </p>
        <p className="text-xs text-slate-400 mt-0.5">
          Format: minute hour day-of-month month day-of-week
        </p>
      </div>

      {/* Frameworks */}
      <div>
        <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
          <Shield className="inline h-4 w-4 mr-1" />
          Target Frameworks <span className="text-red-500">*</span>
        </label>
        {frameworks.length > 0 ? (
          <div className="flex flex-wrap gap-2">
            {frameworks.map((framework) => (
              <button
                key={framework.id}
                type="button"
                onClick={() => handleFrameworkToggle(framework.id)}
                className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-colors ${
                  selectedFrameworks.includes(framework.id)
                    ? 'bg-primary text-white'
                    : 'bg-light-hover dark:bg-dark-hover text-slate-700 dark:text-slate-300 hover:bg-primary/20'
                }`}
              >
                {selectedFrameworks.includes(framework.id) ? (
                  <X className="inline h-3 w-3 mr-1" />
                ) : (
                  <Plus className="inline h-3 w-3 mr-1" />
                )}
                {framework.name}
              </button>
            ))}
          </div>
        ) : (
          <p className="text-sm text-slate-500">No frameworks available</p>
        )}
      </div>

      {/* Controls */}
      <div>
        <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
          Target Controls <span className="text-red-500">*</span>
        </label>
        {filteredControls.length > 0 ? (
          <div className="max-h-48 overflow-y-auto border border-light-border dark:border-dark-border rounded-lg p-2">
            <div className="flex flex-wrap gap-2">
              {filteredControls.map((control) => (
                <button
                  key={control.id}
                  type="button"
                  onClick={() => handleControlToggle(control.id)}
                  className={`px-2 py-1 rounded text-xs font-medium transition-colors ${
                    selectedControls.includes(control.id)
                      ? 'bg-primary text-white'
                      : 'bg-light-hover dark:bg-dark-hover text-slate-700 dark:text-slate-300 hover:bg-primary/20'
                  }`}
                >
                  {control.id}
                </button>
              ))}
            </div>
          </div>
        ) : (
          <p className="text-sm text-slate-500">
            {selectedFrameworks.length === 0
              ? 'Select a framework first'
              : 'No controls available for selected frameworks'}
          </p>
        )}
        {selectedControls.length > 0 && (
          <p className="text-xs text-slate-500 mt-1">
            {selectedControls.length} control{selectedControls.length !== 1 ? 's' : ''} selected
          </p>
        )}
      </div>

      {/* Enabled (only for editing) */}
      {isEditing && (
        <div className="flex items-center gap-2">
          <input
            type="checkbox"
            id="enabled"
            checked={enabled}
            onChange={(e) => setEnabled(e.target.checked)}
            className="h-4 w-4 rounded border-light-border dark:border-dark-border text-primary focus:ring-primary"
          />
          <label
            htmlFor="enabled"
            className="text-sm font-medium text-slate-700 dark:text-slate-300"
          >
            Schedule enabled
          </label>
        </div>
      )}

      {/* Actions */}
      <div className="flex items-center justify-end gap-3 pt-4 border-t border-light-border dark:border-dark-border">
        {onCancel && (
          <Button type="button" variant="outline" onClick={onCancel}>
            Cancel
          </Button>
        )}
        <Button type="submit" disabled={isSubmitting}>
          {isSubmitting ? (
            'Saving...'
          ) : (
            <>
              <Play className="h-4 w-4 mr-2" />
              {isEditing ? 'Update Schedule' : 'Create Schedule'}
            </>
          )}
        </Button>
      </div>
    </form>
  );
};

export default ScheduleForm;
