import React, { useState } from 'react';
import {
  AlertTriangle,
  ChevronDown,
  ChevronUp,
  Clock,
  Target,
  TrendingUp,
} from 'lucide-react';
import type { AIVulnerabilityScore } from '../../types';
import RiskScoreCard from './RiskScoreCard';

interface PrioritizedListProps {
  scores: AIVulnerabilityScore[];
  onSelectVulnerability?: (vulnId: string) => void;
  selectedId?: string;
}

const PrioritizedList: React.FC<PrioritizedListProps> = ({
  scores,
  onSelectVulnerability,
  selectedId,
}) => {
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [categoryFilter, setCategoryFilter] = useState<string>('all');

  const getCategoryColor = (category: string) => {
    switch (category.toLowerCase()) {
      case 'critical':
        return 'border-red-500 bg-red-500/10';
      case 'high':
        return 'border-orange-500 bg-orange-500/10';
      case 'medium':
        return 'border-yellow-500 bg-yellow-500/10';
      case 'low':
        return 'border-green-500 bg-green-500/10';
      default:
        return 'border-gray-500 bg-gray-500/10';
    }
  };

  const getCategoryBadge = (category: string) => {
    switch (category.toLowerCase()) {
      case 'critical':
        return 'bg-red-500/20 text-red-400 border-red-500/50';
      case 'high':
        return 'bg-orange-500/20 text-orange-400 border-orange-500/50';
      case 'medium':
        return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/50';
      case 'low':
        return 'bg-green-500/20 text-green-400 border-green-500/50';
      default:
        return 'bg-gray-500/20 text-gray-400 border-gray-500/50';
    }
  };

  const filteredScores = categoryFilter === 'all'
    ? scores
    : scores.filter(s => s.risk_category.toLowerCase() === categoryFilter);

  const categories = ['all', 'critical', 'high', 'medium', 'low'];
  const categoryCounts = {
    all: scores.length,
    critical: scores.filter(s => s.risk_category.toLowerCase() === 'critical').length,
    high: scores.filter(s => s.risk_category.toLowerCase() === 'high').length,
    medium: scores.filter(s => s.risk_category.toLowerCase() === 'medium').length,
    low: scores.filter(s => s.risk_category.toLowerCase() === 'low').length,
  };

  return (
    <div className="space-y-4">
      {/* Category Filter Tabs */}
      <div className="flex space-x-2 overflow-x-auto pb-2">
        {categories.map((cat) => (
          <button
            key={cat}
            onClick={() => setCategoryFilter(cat)}
            className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-colors whitespace-nowrap ${
              categoryFilter === cat
                ? cat === 'all'
                  ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/50'
                  : getCategoryBadge(cat)
                : 'bg-gray-800 text-gray-400 border border-gray-700 hover:border-gray-600'
            }`}
          >
            {cat.charAt(0).toUpperCase() + cat.slice(1)}
            <span className="ml-1.5 text-xs opacity-75">
              ({categoryCounts[cat as keyof typeof categoryCounts]})
            </span>
          </button>
        ))}
      </div>

      {/* Prioritized List */}
      <div className="space-y-2">
        {filteredScores.length === 0 ? (
          <div className="text-center py-8 text-gray-400">
            No vulnerabilities in this category
          </div>
        ) : (
          filteredScores.map((score) => (
            <div
              key={score.vulnerability_id}
              className={`border-l-4 rounded-lg transition-all ${getCategoryColor(score.risk_category)} ${
                selectedId === score.vulnerability_id ? 'ring-2 ring-cyan-500' : ''
              }`}
            >
              {/* Main Row */}
              <div
                className="flex items-center justify-between p-3 cursor-pointer hover:bg-gray-800/50"
                onClick={() => {
                  if (onSelectVulnerability) {
                    onSelectVulnerability(score.vulnerability_id);
                  }
                  setExpandedId(expandedId === score.vulnerability_id ? null : score.vulnerability_id);
                }}
              >
                <div className="flex items-center space-x-4">
                  {/* Priority Badge */}
                  <div className="flex items-center justify-center w-8 h-8 rounded-full bg-gray-800 text-white font-bold text-sm">
                    #{score.remediation_priority}
                  </div>

                  {/* Risk Score */}
                  <RiskScoreCard
                    score={score.effective_risk_score}
                    category={score.risk_category}
                    confidence={score.confidence}
                    priority={score.remediation_priority}
                    compact
                  />
                </div>

                <div className="flex items-center space-x-4">
                  {/* Effort Estimate */}
                  <div className="flex items-center text-gray-400 text-sm">
                    <Clock className="w-4 h-4 mr-1" />
                    {score.estimated_effort.estimated_hours}h
                  </div>

                  {/* Confidence */}
                  <div className="flex items-center text-gray-400 text-sm">
                    <Target className="w-4 h-4 mr-1" />
                    {score.confidence.toFixed(0)}%
                  </div>

                  {/* Expand/Collapse */}
                  {expandedId === score.vulnerability_id ? (
                    <ChevronUp className="w-5 h-5 text-gray-400" />
                  ) : (
                    <ChevronDown className="w-5 h-5 text-gray-400" />
                  )}
                </div>
              </div>

              {/* Expanded Details */}
              {expandedId === score.vulnerability_id && (
                <div className="px-4 pb-4 border-t border-gray-700/50">
                  <div className="pt-3 space-y-3">
                    {/* Factor Scores Summary */}
                    <div>
                      <h4 className="text-sm font-medium text-gray-300 mb-2">
                        Contributing Factors
                      </h4>
                      <div className="grid grid-cols-2 gap-2">
                        {score.factor_scores.slice(0, 4).map((factor, idx) => (
                          <div
                            key={idx}
                            className="flex items-center justify-between bg-gray-900/50 rounded p-2"
                          >
                            <span className="text-xs text-gray-400">
                              {factor.factor_name}
                            </span>
                            <span className="text-xs font-medium text-white">
                              {factor.normalized_value.toFixed(0)}
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Effort Details */}
                    <div className="flex items-center space-x-4 text-sm">
                      <span className={`px-2 py-1 rounded text-xs ${
                        score.estimated_effort.effort_level === 'low'
                          ? 'bg-green-500/20 text-green-400'
                          : score.estimated_effort.effort_level === 'medium'
                          ? 'bg-yellow-500/20 text-yellow-400'
                          : score.estimated_effort.effort_level === 'high'
                          ? 'bg-orange-500/20 text-orange-400'
                          : 'bg-red-500/20 text-red-400'
                      }`}>
                        {score.estimated_effort.effort_level.replace('_', ' ').toUpperCase()} EFFORT
                      </span>
                      <span className={`px-2 py-1 rounded text-xs ${
                        score.estimated_effort.impact_level === 'low'
                          ? 'bg-green-500/20 text-green-400'
                          : score.estimated_effort.impact_level === 'medium'
                          ? 'bg-yellow-500/20 text-yellow-400'
                          : score.estimated_effort.impact_level === 'high'
                          ? 'bg-orange-500/20 text-orange-400'
                          : 'bg-red-500/20 text-red-400'
                      }`}>
                        {score.estimated_effort.impact_level.toUpperCase()} IMPACT
                      </span>
                      {score.estimated_effort.requires_downtime && (
                        <span className="px-2 py-1 rounded text-xs bg-red-500/20 text-red-400">
                          DOWNTIME REQUIRED
                        </span>
                      )}
                    </div>

                    {/* Calculated At */}
                    <div className="text-xs text-gray-500">
                      Calculated: {new Date(score.calculated_at).toLocaleString()}
                    </div>
                  </div>
                </div>
              )}
            </div>
          ))
        )}
      </div>
    </div>
  );
};

export default PrioritizedList;
