import React, { useState, useEffect, useCallback } from 'react';
import { toast } from 'react-toastify';
import { complianceAPI } from '../../services/api';
import type { ComplianceControl } from '../../types';
import LoadingSpinner from '../ui/LoadingSpinner';
import Badge from '../ui/Badge';
import {
  CheckCircle2,
  Shield,
  ChevronDown,
  ChevronRight,
  Info,
  Zap,
} from 'lucide-react';

interface ControlListProps {
  framework: string;
  scanId: string;
}

const ControlList: React.FC<ControlListProps> = ({ framework, scanId: _scanId }) => {
  const [controls, setControls] = useState<ComplianceControl[]>([]);
  const [loading, setLoading] = useState(true);
  const [expandedControl, setExpandedControl] = useState<string | null>(null);
  const [filterCategory, setFilterCategory] = useState<string>('all');
  const [filterPriority, setFilterPriority] = useState<string>('all');

  const loadControls = useCallback(async () => {
    setLoading(true);
    try {
      // Convert framework name to ID format (e.g., "NIST 800-53" -> "nist_800_53")
      const frameworkId = framework.toLowerCase().replace(/[\s-]/g, '_');
      const response = await complianceAPI.getFrameworkControls(frameworkId);
      setControls(response.data.controls);
    } catch (error) {
      toast.error('Failed to load control details');
      console.error(error);
    } finally {
      setLoading(false);
    }
  }, [framework]);

  useEffect(() => {
    loadControls();
  }, [loadControls]);

  const getPriorityIcon = (priority: string) => {
    switch (priority) {
      case 'High':
        return <Shield className="h-4 w-4 text-red-400" />;
      case 'Medium':
        return <Shield className="h-4 w-4 text-yellow-400" />;
      case 'Low':
        return <Shield className="h-4 w-4 text-blue-400" />;
      default:
        return <Shield className="h-4 w-4 text-slate-400" />;
    }
  };

  const getPriorityColor = (priority: string) => {
    switch (priority) {
      case 'High':
        return 'text-red-400';
      case 'Medium':
        return 'text-yellow-400';
      case 'Low':
        return 'text-blue-400';
      default:
        return 'text-slate-400';
    }
  };

  // Get unique categories
  const categories = Array.from(new Set(controls.map((c) => c.category)));

  // Filter controls
  const filteredControls = controls.filter((control) => {
    if (filterCategory !== 'all' && control.category !== filterCategory) return false;
    if (filterPriority !== 'all' && control.priority !== filterPriority) return false;
    return true;
  });

  if (loading) {
    return (
      <div className="flex items-center justify-center py-8">
        <LoadingSpinner />
      </div>
    );
  }

  return (
    <div>
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-sm font-semibold text-slate-300">Control Details</h3>
        <div className="flex gap-2">
          {/* Category Filter */}
          <select
            value={filterCategory}
            onChange={(e) => setFilterCategory(e.target.value)}
            className="px-3 py-1.5 text-xs bg-dark-surface border border-dark-border rounded-lg text-slate-300 focus:ring-2 focus:ring-primary focus:border-transparent"
          >
            <option value="all">All Categories</option>
            {categories.map((cat) => (
              <option key={cat} value={cat}>
                {cat}
              </option>
            ))}
          </select>

          {/* Priority Filter */}
          <select
            value={filterPriority}
            onChange={(e) => setFilterPriority(e.target.value)}
            className="px-3 py-1.5 text-xs bg-dark-surface border border-dark-border rounded-lg text-slate-300 focus:ring-2 focus:ring-primary focus:border-transparent"
          >
            <option value="all">All Priorities</option>
            <option value="High">High Priority</option>
            <option value="Medium">Medium Priority</option>
            <option value="Low">Low Priority</option>
          </select>
        </div>
      </div>

      {filteredControls.length === 0 ? (
        <div className="text-center py-8 text-slate-400">
          <Info className="h-8 w-8 mx-auto mb-2 opacity-50" />
          <p className="text-sm">No controls match the current filters</p>
        </div>
      ) : (
        <div className="space-y-2">
          {filteredControls.map((control) => (
            <div
              key={control.id}
              className="border border-dark-border rounded-lg overflow-hidden bg-dark-bg"
            >
              {/* Control Header */}
              <div
                onClick={() =>
                  setExpandedControl(expandedControl === control.id ? null : control.id)
                }
                className="flex items-center justify-between p-3 cursor-pointer hover:bg-dark-hover transition-colors"
              >
                <div className="flex items-center gap-3 flex-1 min-w-0">
                  {expandedControl === control.id ? (
                    <ChevronDown className="h-4 w-4 text-slate-400 flex-shrink-0" />
                  ) : (
                    <ChevronRight className="h-4 w-4 text-slate-400 flex-shrink-0" />
                  )}

                  <div className="flex-shrink-0">{getPriorityIcon(control.priority)}</div>

                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="text-sm font-mono text-primary">{control.control_id}</span>
                      {control.automated && (
                        <Badge variant="status" type="completed" className="text-xs">
                          <Zap className="h-3 w-3 mr-1" />
                          Automated
                        </Badge>
                      )}
                    </div>
                    <p className="text-sm text-white font-medium truncate">{control.title}</p>
                  </div>
                </div>

                <div className="flex items-center gap-3 flex-shrink-0 ml-3">
                  <span className="text-xs text-slate-400 bg-dark-surface px-2 py-1 rounded">
                    {control.category}
                  </span>
                  <span className={`text-xs font-medium ${getPriorityColor(control.priority)}`}>
                    {control.priority}
                  </span>
                </div>
              </div>

              {/* Control Details */}
              {expandedControl === control.id && (
                <div className="p-4 bg-dark-surface border-t border-dark-border space-y-4">
                  {/* Description */}
                  <div>
                    <h4 className="text-xs font-semibold text-slate-300 mb-2 flex items-center gap-2">
                      <Info className="h-3.5 w-3.5" />
                      Description
                    </h4>
                    <p className="text-sm text-slate-400 leading-relaxed">
                      {control.description}
                    </p>
                  </div>

                  {/* Remediation Guidance */}
                  {control.remediation_guidance && (
                    <div>
                      <h4 className="text-xs font-semibold text-slate-300 mb-2 flex items-center gap-2">
                        <CheckCircle2 className="h-3.5 w-3.5" />
                        Remediation Guidance
                      </h4>
                      <div className="p-3 bg-blue-500/10 border border-blue-500/30 rounded-lg">
                        <p className="text-sm text-blue-100 leading-relaxed">
                          {control.remediation_guidance}
                        </p>
                      </div>
                    </div>
                  )}

                  {/* Control Metadata */}
                  <div className="grid grid-cols-2 gap-4 pt-3 border-t border-dark-border">
                    <div>
                      <span className="text-xs text-slate-500">Control ID</span>
                      <p className="text-sm font-mono text-white mt-1">{control.control_id}</p>
                    </div>
                    <div>
                      <span className="text-xs text-slate-500">Category</span>
                      <p className="text-sm text-white mt-1">{control.category}</p>
                    </div>
                    <div>
                      <span className="text-xs text-slate-500">Priority</span>
                      <p className={`text-sm font-medium mt-1 ${getPriorityColor(control.priority)}`}>
                        {control.priority}
                      </p>
                    </div>
                    <div>
                      <span className="text-xs text-slate-500">Check Type</span>
                      <p className="text-sm text-white mt-1">
                        {control.automated ? (
                          <span className="flex items-center gap-1 text-green-400">
                            <Zap className="h-3.5 w-3.5" />
                            Automated
                          </span>
                        ) : (
                          <span className="text-slate-400">Manual</span>
                        )}
                      </p>
                    </div>
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      {/* Summary Footer */}
      <div className="mt-4 p-3 bg-dark-surface rounded-lg border border-dark-border">
        <div className="flex items-center justify-between text-xs">
          <div className="flex items-center gap-4 text-slate-400">
            <span>
              Showing {filteredControls.length} of {controls.length} controls
            </span>
            <span className="text-slate-600">•</span>
            <span className="flex items-center gap-1">
              <Zap className="h-3 w-3 text-green-400" />
              {controls.filter((c) => c.automated).length} automated
            </span>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ControlList;
