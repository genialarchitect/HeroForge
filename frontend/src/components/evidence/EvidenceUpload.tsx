import React, { useState } from 'react';
import { Upload, FileText, Plus, X, Shield } from 'lucide-react';
import { toast } from 'react-toastify';
import Button from '../ui/Button';
import type { CreateEvidenceRequest } from '../../types/evidence';

interface EvidenceUploadProps {
  onSubmit: (data: CreateEvidenceRequest) => Promise<void>;
  onCancel?: () => void;
  frameworks?: { id: string; name: string }[];
  controls?: { id: string; name: string; framework_id: string }[];
}

const evidenceTypes = [
  { value: 'policy_document', label: 'Policy Document' },
  { value: 'manual_upload', label: 'Manual Upload' },
  { value: 'screenshot', label: 'Screenshot' },
  { value: 'configuration', label: 'Configuration' },
  { value: 'log_extract', label: 'Log Extract' },
  { value: 'attestation', label: 'Attestation' },
  { value: 'training_record', label: 'Training Record' },
  { value: 'change_record', label: 'Change Record' },
];

const retentionOptions = [
  { value: 30, label: '30 days' },
  { value: 90, label: '90 days' },
  { value: 180, label: '180 days' },
  { value: 365, label: '1 year' },
  { value: 730, label: '2 years' },
  { value: 1095, label: '3 years' },
  { value: 0, label: 'Indefinite' },
];

const EvidenceUpload: React.FC<EvidenceUploadProps> = ({
  onSubmit,
  onCancel,
  frameworks = [],
  controls = [],
}) => {
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [evidenceType, setEvidenceType] = useState('manual_upload');
  const [selectedFrameworks, setSelectedFrameworks] = useState<string[]>([]);
  const [selectedControls, setSelectedControls] = useState<string[]>([]);
  const [retentionDays, setRetentionDays] = useState<number>(365);
  const [content, setContent] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);

  // Filter controls based on selected frameworks
  const filteredControls =
    selectedFrameworks.length > 0
      ? controls.filter((c) => selectedFrameworks.includes(c.framework_id))
      : controls;

  const handleFrameworkToggle = (frameworkId: string) => {
    setSelectedFrameworks((prev) =>
      prev.includes(frameworkId) ? prev.filter((id) => id !== frameworkId) : [...prev, frameworkId]
    );
    // Remove controls that are no longer valid
    setSelectedControls((prev) =>
      prev.filter((controlId) => {
        const control = controls.find((c) => c.id === controlId);
        return control && (selectedFrameworks.includes(control.framework_id) || !prev.includes(frameworkId));
      })
    );
  };

  const handleControlToggle = (controlId: string) => {
    setSelectedControls((prev) =>
      prev.includes(controlId) ? prev.filter((id) => id !== controlId) : [...prev, controlId]
    );
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!title.trim()) {
      toast.error('Please enter a title');
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
      const data: CreateEvidenceRequest = {
        title: title.trim(),
        description: description.trim() || undefined,
        evidence_type: evidenceType,
        framework_ids: selectedFrameworks,
        control_ids: selectedControls,
        params: {
          retention_days: retentionDays > 0 ? retentionDays : undefined,
          content: content.trim() ? { text: content.trim() } : undefined,
        },
      };

      await onSubmit(data);
      toast.success('Evidence created successfully');

      // Reset form
      setTitle('');
      setDescription('');
      setEvidenceType('manual_upload');
      setSelectedFrameworks([]);
      setSelectedControls([]);
      setRetentionDays(365);
      setContent('');
    } catch {
      toast.error('Failed to create evidence');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-6">
      {/* Title */}
      <div>
        <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
          Title <span className="text-red-500">*</span>
        </label>
        <input
          type="text"
          value={title}
          onChange={(e) => setTitle(e.target.value)}
          placeholder="Enter evidence title"
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
          placeholder="Enter a description of this evidence"
          rows={3}
          className="w-full px-3 py-2 bg-light-bg dark:bg-dark-bg border border-light-border dark:border-dark-border rounded-lg text-slate-900 dark:text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-primary resize-none"
        />
      </div>

      {/* Evidence Type */}
      <div>
        <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
          Evidence Type <span className="text-red-500">*</span>
        </label>
        <select
          value={evidenceType}
          onChange={(e) => setEvidenceType(e.target.value)}
          className="w-full px-3 py-2 bg-light-bg dark:bg-dark-bg border border-light-border dark:border-dark-border rounded-lg text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-primary"
        >
          {evidenceTypes.map((type) => (
            <option key={type.value} value={type.value}>
              {type.label}
            </option>
          ))}
        </select>
      </div>

      {/* Frameworks */}
      <div>
        <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
          <Shield className="inline h-4 w-4 mr-1" />
          Frameworks <span className="text-red-500">*</span>
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
          Controls <span className="text-red-500">*</span>
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

      {/* Retention Period */}
      <div>
        <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
          Retention Period
        </label>
        <select
          value={retentionDays}
          onChange={(e) => setRetentionDays(parseInt(e.target.value))}
          className="w-full px-3 py-2 bg-light-bg dark:bg-dark-bg border border-light-border dark:border-dark-border rounded-lg text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-primary"
        >
          {retentionOptions.map((option) => (
            <option key={option.value} value={option.value}>
              {option.label}
            </option>
          ))}
        </select>
      </div>

      {/* Content (Optional) */}
      <div>
        <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
          Content (Optional)
        </label>
        <textarea
          value={content}
          onChange={(e) => setContent(e.target.value)}
          placeholder="Enter evidence content or notes"
          rows={4}
          className="w-full px-3 py-2 bg-light-bg dark:bg-dark-bg border border-light-border dark:border-dark-border rounded-lg text-slate-900 dark:text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-primary resize-none font-mono text-sm"
        />
      </div>

      {/* Actions */}
      <div className="flex items-center justify-end gap-3 pt-4 border-t border-light-border dark:border-dark-border">
        {onCancel && (
          <Button type="button" variant="outline" onClick={onCancel}>
            Cancel
          </Button>
        )}
        <Button type="submit" disabled={isSubmitting}>
          {isSubmitting ? (
            'Creating...'
          ) : (
            <>
              <Upload className="h-4 w-4 mr-2" />
              Create Evidence
            </>
          )}
        </Button>
      </div>
    </form>
  );
};

export default EvidenceUpload;
