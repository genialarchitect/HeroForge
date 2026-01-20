import React, { useState } from 'react';
import { toast } from 'react-toastify';
import { Sparkles, ChevronDown, ChevronUp, AlertTriangle, Clock, Server, Copy, Check, RefreshCw } from 'lucide-react';
import { aiAPI, RemediationSuggestion, RemediationStep, CodeSnippet } from '../../services/aiApi';
import CodeBlock from '../ui/CodeBlock';

interface RemediationSuggestionsProps {
  vulnerabilityId: string;
  hostOs?: string;
  onApplyToJira?: (steps: string) => void;
}

const PLATFORMS = [
  { value: 'linux', label: 'Linux', icon: '🐧' },
  { value: 'windows', label: 'Windows', icon: '🪟' },
  { value: 'aws', label: 'AWS', icon: '☁️' },
  { value: 'azure', label: 'Azure', icon: '📘' },
  { value: 'gcp', label: 'GCP', icon: '🌐' },
  { value: 'kubernetes', label: 'Kubernetes', icon: '⎈' },
  { value: 'docker', label: 'Docker', icon: '🐳' },
  { value: 'generic', label: 'Generic', icon: '📋' },
];

const RemediationSuggestions: React.FC<RemediationSuggestionsProps> = ({
  vulnerabilityId,
  hostOs,
  onApplyToJira,
}) => {
  const [platform, setPlatform] = useState<string>(detectPlatform(hostOs));
  const [suggestion, setSuggestion] = useState<RemediationSuggestion | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [expandedSteps, setExpandedSteps] = useState<Set<number>>(new Set([0]));

  const handleGenerate = async () => {
    setLoading(true);
    setError(null);

    try {
      const result = await aiAPI.generateRemediation({
        vulnerability_id: vulnerabilityId,
        platform: platform,
        include_rollback: true,
        verbose: true,
      });
      setSuggestion(result);
      // Expand first step by default
      setExpandedSteps(new Set([0]));
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to generate remediation';
      setError(message);
      toast.error(message);
    } finally {
      setLoading(false);
    }
  };

  const toggleStep = (stepNumber: number) => {
    setExpandedSteps(prev => {
      const next = new Set(prev);
      if (next.has(stepNumber)) {
        next.delete(stepNumber);
      } else {
        next.add(stepNumber);
      }
      return next;
    });
  };

  const formatStepsForJira = (): string => {
    if (!suggestion) return '';

    let markdown = `h2. AI-Generated Remediation Steps\n\n`;
    markdown += `*Platform:* ${suggestion.platform}\n`;
    markdown += `*Estimated Effort:* ${suggestion.estimated_effort}\n\n`;

    if (suggestion.prerequisites.length > 0) {
      markdown += `h3. Prerequisites\n`;
      suggestion.prerequisites.forEach(p => {
        markdown += `* ${p}\n`;
      });
      markdown += '\n';
    }

    markdown += `h3. Steps\n`;
    suggestion.steps.forEach(step => {
      markdown += `# *${step.title}*\n`;
      markdown += `${step.description}\n`;
      if (step.code_snippet) {
        markdown += `{code:${step.code_language || 'bash'}}\n`;
        markdown += `${step.code_snippet}\n`;
        markdown += `{code}\n`;
      }
      markdown += '\n';
    });

    if (suggestion.verification_steps.length > 0) {
      markdown += `h3. Verification\n`;
      suggestion.verification_steps.forEach(v => {
        markdown += `* ${v}\n`;
      });
    }

    return markdown;
  };

  const handleApplyToJira = () => {
    if (onApplyToJira) {
      onApplyToJira(formatStepsForJira());
      toast.success('Remediation steps copied to JIRA format');
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Sparkles className="h-5 w-5 text-purple-400" />
          <h3 className="text-lg font-semibold text-white">AI-Powered Remediation</h3>
        </div>
      </div>

      {/* Platform Selector */}
      <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
        <label className="block text-sm font-medium text-gray-300 mb-3">
          Select Target Platform
        </label>
        <div className="grid grid-cols-4 gap-2">
          {PLATFORMS.map(p => (
            <button
              key={p.value}
              onClick={() => setPlatform(p.value)}
              className={`flex flex-col items-center gap-1 p-3 rounded-lg border transition-all ${
                platform === p.value
                  ? 'border-purple-500 bg-purple-500/20 text-purple-300'
                  : 'border-gray-600 bg-gray-700 text-gray-400 hover:border-gray-500'
              }`}
            >
              <span className="text-2xl">{p.icon}</span>
              <span className="text-xs font-medium">{p.label}</span>
            </button>
          ))}
        </div>

        <button
          onClick={handleGenerate}
          disabled={loading}
          className="mt-4 w-full flex items-center justify-center gap-2 px-4 py-3 bg-purple-600 hover:bg-purple-700 disabled:bg-gray-600 text-white rounded-lg transition-colors font-medium"
        >
          {loading ? (
            <>
              <RefreshCw className="h-5 w-5 animate-spin" />
              Generating...
            </>
          ) : (
            <>
              <Sparkles className="h-5 w-5" />
              Generate Remediation Steps
            </>
          )}
        </button>
      </div>

      {/* Error State */}
      {error && (
        <div className="bg-red-900/30 border border-red-700 rounded-lg p-4">
          <div className="flex items-center gap-2 text-red-400">
            <AlertTriangle className="h-5 w-5" />
            <span className="font-medium">Error generating remediation</span>
          </div>
          <p className="mt-2 text-sm text-red-300">{error}</p>
        </div>
      )}

      {/* Results */}
      {suggestion && (
        <div className="space-y-4">
          {/* Summary */}
          <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <span className="text-sm text-gray-400">Platform</span>
                <p className="text-white font-medium capitalize">{suggestion.platform}</p>
              </div>
              <div>
                <span className="text-sm text-gray-400">Estimated Effort</span>
                <p className="text-white font-medium flex items-center gap-1">
                  <Clock className="h-4 w-4 text-gray-400" />
                  {suggestion.estimated_effort}
                </p>
              </div>
            </div>
          </div>

          {/* Prerequisites */}
          {suggestion.prerequisites.length > 0 && (
            <div className="bg-yellow-900/20 border border-yellow-700/50 rounded-lg p-4">
              <h4 className="text-sm font-medium text-yellow-300 mb-2">Prerequisites</h4>
              <ul className="space-y-1">
                {suggestion.prerequisites.map((prereq, i) => (
                  <li key={i} className="text-sm text-yellow-200 flex items-start gap-2">
                    <span className="text-yellow-400">•</span>
                    {prereq}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Risk Notes */}
          {suggestion.risk_notes.length > 0 && (
            <div className="bg-orange-900/20 border border-orange-700/50 rounded-lg p-4">
              <h4 className="text-sm font-medium text-orange-300 mb-2 flex items-center gap-2">
                <AlertTriangle className="h-4 w-4" />
                Risk Notes
              </h4>
              <ul className="space-y-1">
                {suggestion.risk_notes.map((note, i) => (
                  <li key={i} className="text-sm text-orange-200 flex items-start gap-2">
                    <span className="text-orange-400">•</span>
                    {note}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Steps */}
          <div className="space-y-3">
            <h4 className="text-sm font-medium text-gray-300">Remediation Steps</h4>
            {suggestion.steps.map((step, index) => (
              <StepCard
                key={step.step_number}
                step={step}
                expanded={expandedSteps.has(index)}
                onToggle={() => toggleStep(index)}
              />
            ))}
          </div>

          {/* Code Snippets */}
          {suggestion.code_snippets.length > 0 && (
            <div className="space-y-3">
              <h4 className="text-sm font-medium text-gray-300">Code Snippets</h4>
              {suggestion.code_snippets.map((snippet, index) => (
                <CodeBlock
                  key={index}
                  code={snippet.code}
                  language={snippet.language}
                  title={snippet.title}
                  description={snippet.description}
                  filename={snippet.filename}
                />
              ))}
            </div>
          )}

          {/* Verification Steps */}
          {suggestion.verification_steps.length > 0 && (
            <div className="bg-green-900/20 border border-green-700/50 rounded-lg p-4">
              <h4 className="text-sm font-medium text-green-300 mb-2">Verification Steps</h4>
              <ol className="space-y-1 list-decimal list-inside">
                {suggestion.verification_steps.map((step, i) => (
                  <li key={i} className="text-sm text-green-200">{step}</li>
                ))}
              </ol>
            </div>
          )}

          {/* Rollback Steps */}
          {suggestion.rollback_steps && suggestion.rollback_steps.length > 0 && (
            <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
              <h4 className="text-sm font-medium text-gray-300 mb-2">Rollback Procedure</h4>
              <ol className="space-y-1 list-decimal list-inside">
                {suggestion.rollback_steps.map((step, i) => (
                  <li key={i} className="text-sm text-gray-400">{step}</li>
                ))}
              </ol>
            </div>
          )}

          {/* Actions */}
          {onApplyToJira && (
            <div className="flex justify-end">
              <button
                onClick={handleApplyToJira}
                className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors"
              >
                <Copy className="h-4 w-4" />
                Apply to JIRA Ticket
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

// Step Card Component
interface StepCardProps {
  step: RemediationStep;
  expanded: boolean;
  onToggle: () => void;
}

const StepCard: React.FC<StepCardProps> = ({ step, expanded, onToggle }) => {
  return (
    <div className="bg-gray-800 rounded-lg border border-gray-700 overflow-hidden">
      <button
        onClick={onToggle}
        className="w-full flex items-center justify-between p-4 text-left hover:bg-gray-750 transition-colors"
      >
        <div className="flex items-center gap-3">
          <span className="flex items-center justify-center w-8 h-8 rounded-full bg-purple-500/20 text-purple-400 font-bold text-sm">
            {step.step_number}
          </span>
          <div>
            <h5 className="font-medium text-white">{step.title}</h5>
            <div className="flex items-center gap-3 mt-1">
              {step.estimated_time && (
                <span className="text-xs text-gray-400 flex items-center gap-1">
                  <Clock className="h-3 w-3" />
                  {step.estimated_time}
                </span>
              )}
              {step.risk_level && (
                <span className={`text-xs px-2 py-0.5 rounded-full ${
                  step.risk_level === 'high'
                    ? 'bg-red-500/20 text-red-400'
                    : step.risk_level === 'medium'
                    ? 'bg-yellow-500/20 text-yellow-400'
                    : 'bg-green-500/20 text-green-400'
                }`}>
                  {step.risk_level} risk
                </span>
              )}
              {step.requires_reboot && (
                <span className="text-xs bg-orange-500/20 text-orange-400 px-2 py-0.5 rounded-full">
                  Requires reboot
                </span>
              )}
              {step.requires_downtime && (
                <span className="text-xs bg-red-500/20 text-red-400 px-2 py-0.5 rounded-full">
                  Requires downtime
                </span>
              )}
            </div>
          </div>
        </div>
        {expanded ? (
          <ChevronUp className="h-5 w-5 text-gray-400" />
        ) : (
          <ChevronDown className="h-5 w-5 text-gray-400" />
        )}
      </button>

      {expanded && (
        <div className="px-4 pb-4 border-t border-gray-700 pt-4">
          <p className="text-sm text-gray-300 mb-4">{step.description}</p>
          {step.code_snippet && (
            <CodeBlock
              code={step.code_snippet}
              language={step.code_language || 'bash'}
              showLineNumbers={false}
            />
          )}
        </div>
      )}
    </div>
  );
};

// Helper to detect platform from host OS string
function detectPlatform(hostOs?: string): string {
  if (!hostOs) return 'generic';

  const os = hostOs.toLowerCase();
  if (os.includes('linux') || os.includes('ubuntu') || os.includes('debian') || os.includes('rhel') || os.includes('centos')) {
    return 'linux';
  }
  if (os.includes('windows')) {
    return 'windows';
  }
  if (os.includes('aws') || os.includes('amazon')) {
    return 'aws';
  }
  if (os.includes('azure')) {
    return 'azure';
  }
  if (os.includes('gcp') || os.includes('google')) {
    return 'gcp';
  }
  if (os.includes('kubernetes') || os.includes('k8s')) {
    return 'kubernetes';
  }
  if (os.includes('docker')) {
    return 'docker';
  }
  return 'generic';
}

export default RemediationSuggestions;
