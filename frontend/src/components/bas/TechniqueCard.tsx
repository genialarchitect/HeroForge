import React from 'react';
import {
  Shield,
  ExternalLink,
  Check,
  ChevronDown,
  ChevronUp,
  Terminal,
  Globe,
  Lock,
  Database,
} from 'lucide-react';
import type { AttackTechnique } from '../../types';

interface TechniqueCardProps {
  technique: AttackTechnique;
  isSelected?: boolean;
  onToggleSelect?: (techniqueId: string) => void;
  expanded?: boolean;
  onToggleExpand?: () => void;
}

const TechniqueCard: React.FC<TechniqueCardProps> = ({
  technique,
  isSelected = false,
  onToggleSelect,
  expanded = false,
  onToggleExpand,
}) => {
  const getTacticColor = (tactic: string): string => {
    const colorMap: Record<string, string> = {
      reconnaissance: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
      'resource-development': 'bg-purple-500/20 text-purple-400 border-purple-500/30',
      'initial-access': 'bg-red-500/20 text-red-400 border-red-500/30',
      execution: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
      persistence: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
      'privilege-escalation': 'bg-pink-500/20 text-pink-400 border-pink-500/30',
      'defense-evasion': 'bg-indigo-500/20 text-indigo-400 border-indigo-500/30',
      'credential-access': 'bg-cyan-500/20 text-cyan-400 border-cyan-500/30',
      discovery: 'bg-teal-500/20 text-teal-400 border-teal-500/30',
      'lateral-movement': 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30',
      collection: 'bg-lime-500/20 text-lime-400 border-lime-500/30',
      'command-and-control': 'bg-amber-500/20 text-amber-400 border-amber-500/30',
      exfiltration: 'bg-rose-500/20 text-rose-400 border-rose-500/30',
      impact: 'bg-red-600/20 text-red-500 border-red-600/30',
    };
    return colorMap[tactic.toLowerCase()] || 'bg-gray-500/20 text-gray-400 border-gray-500/30';
  };

  return (
    <div
      className={`bg-light-surface dark:bg-dark-surface border rounded-lg transition-all ${
        isSelected
          ? 'border-primary ring-2 ring-primary/20'
          : 'border-light-border dark:border-dark-border hover:border-primary/50'
      }`}
    >
      <div
        className={`p-4 ${onToggleExpand ? 'cursor-pointer' : ''}`}
        onClick={onToggleExpand}
      >
        <div className="flex items-start justify-between">
          <div className="flex items-start gap-3">
            {onToggleSelect && (
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  onToggleSelect(technique.id);
                }}
                className={`mt-1 w-5 h-5 rounded border-2 flex items-center justify-center transition-colors ${
                  isSelected
                    ? 'bg-primary border-primary text-white'
                    : 'border-gray-400 dark:border-gray-600 hover:border-primary'
                }`}
              >
                {isSelected && <Check className="w-3 h-3" />}
              </button>
            )}
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 mb-1">
                <span className="text-xs font-mono text-gray-500 dark:text-gray-400">
                  {technique.id}
                </span>
                <span
                  className={`text-xs px-2 py-0.5 rounded border ${getTacticColor(
                    technique.tactic
                  )}`}
                >
                  {technique.tactic_name}
                </span>
              </div>
              <h4 className="font-medium text-gray-900 dark:text-white">
                {technique.name}
              </h4>
              {!expanded && (
                <p className="text-sm text-gray-500 dark:text-gray-400 line-clamp-2 mt-1">
                  {technique.description}
                </p>
              )}
            </div>
          </div>
          <div className="flex items-center gap-2">
            <a
              href={technique.mitre_url}
              target="_blank"
              rel="noopener noreferrer"
              onClick={(e) => e.stopPropagation()}
              className="p-1.5 text-gray-400 hover:text-primary transition-colors"
              title="View on MITRE ATT&CK"
            >
              <ExternalLink className="w-4 h-4" />
            </a>
            {onToggleExpand && (
              <button className="p-1.5 text-gray-400 hover:text-gray-200 transition-colors">
                {expanded ? (
                  <ChevronUp className="w-4 h-4" />
                ) : (
                  <ChevronDown className="w-4 h-4" />
                )}
              </button>
            )}
          </div>
        </div>
      </div>

      {expanded && (
        <div className="px-4 pb-4 border-t border-light-border dark:border-dark-border pt-4">
          <p className="text-sm text-gray-600 dark:text-gray-300 mb-4">
            {technique.description}
          </p>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
            {/* Platforms */}
            {technique.platforms.length > 0 && (
              <div>
                <div className="flex items-center gap-2 text-gray-500 dark:text-gray-400 mb-2">
                  <Globe className="w-4 h-4" />
                  <span className="font-medium">Platforms</span>
                </div>
                <div className="flex flex-wrap gap-1">
                  {technique.platforms.map((platform) => (
                    <span
                      key={platform}
                      className="px-2 py-0.5 text-xs bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-300 rounded"
                    >
                      {platform}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* Permissions Required */}
            {technique.permissions_required.length > 0 && (
              <div>
                <div className="flex items-center gap-2 text-gray-500 dark:text-gray-400 mb-2">
                  <Lock className="w-4 h-4" />
                  <span className="font-medium">Permissions Required</span>
                </div>
                <div className="flex flex-wrap gap-1">
                  {technique.permissions_required.map((perm) => (
                    <span
                      key={perm}
                      className="px-2 py-0.5 text-xs bg-yellow-500/20 text-yellow-400 rounded"
                    >
                      {perm}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* Data Sources */}
            {technique.data_sources.length > 0 && (
              <div>
                <div className="flex items-center gap-2 text-gray-500 dark:text-gray-400 mb-2">
                  <Database className="w-4 h-4" />
                  <span className="font-medium">Data Sources</span>
                </div>
                <div className="flex flex-wrap gap-1">
                  {technique.data_sources.slice(0, 5).map((ds) => (
                    <span
                      key={ds}
                      className="px-2 py-0.5 text-xs bg-cyan-500/20 text-cyan-400 rounded"
                    >
                      {ds}
                    </span>
                  ))}
                  {technique.data_sources.length > 5 && (
                    <span className="px-2 py-0.5 text-xs text-gray-400">
                      +{technique.data_sources.length - 5} more
                    </span>
                  )}
                </div>
              </div>
            )}

            {/* Available Payloads */}
            {technique.payloads.length > 0 && (
              <div>
                <div className="flex items-center gap-2 text-gray-500 dark:text-gray-400 mb-2">
                  <Terminal className="w-4 h-4" />
                  <span className="font-medium">Payloads Available</span>
                </div>
                <div className="flex flex-wrap gap-1">
                  {technique.payloads.map((payload) => (
                    <span
                      key={payload}
                      className="px-2 py-0.5 text-xs bg-green-500/20 text-green-400 rounded"
                    >
                      {payload}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* Detection */}
          {technique.detection && (
            <div className="mt-4 pt-4 border-t border-light-border dark:border-dark-border">
              <div className="flex items-center gap-2 text-gray-500 dark:text-gray-400 mb-2">
                <Shield className="w-4 h-4" />
                <span className="font-medium">Detection Guidance</span>
              </div>
              <p className="text-sm text-gray-600 dark:text-gray-300 line-clamp-4">
                {technique.detection}
              </p>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default TechniqueCard;
