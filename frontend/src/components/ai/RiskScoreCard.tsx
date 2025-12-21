import React from 'react';
import { AlertTriangle, TrendingUp, Clock, Shield } from 'lucide-react';

interface RiskScoreCardProps {
  score: number;
  category: string;
  confidence: number;
  priority: number;
  estimatedHours?: number;
  compact?: boolean;
}

const RiskScoreCard: React.FC<RiskScoreCardProps> = ({
  score,
  category,
  confidence,
  priority,
  estimatedHours,
  compact = false,
}) => {
  const getCategoryColor = (cat: string) => {
    switch (cat.toLowerCase()) {
      case 'critical':
        return 'text-red-400 bg-red-500/20 border-red-500/50';
      case 'high':
        return 'text-orange-400 bg-orange-500/20 border-orange-500/50';
      case 'medium':
        return 'text-yellow-400 bg-yellow-500/20 border-yellow-500/50';
      case 'low':
        return 'text-green-400 bg-green-500/20 border-green-500/50';
      default:
        return 'text-gray-400 bg-gray-500/20 border-gray-500/50';
    }
  };

  const getScoreColor = (s: number) => {
    if (s >= 80) return 'text-red-400';
    if (s >= 60) return 'text-orange-400';
    if (s >= 40) return 'text-yellow-400';
    return 'text-green-400';
  };

  const getGaugeRotation = (s: number) => {
    // Map 0-100 to -90 to 90 degrees
    return (s / 100) * 180 - 90;
  };

  if (compact) {
    return (
      <div className="flex items-center space-x-3">
        <div className={`text-2xl font-bold ${getScoreColor(score)}`}>
          {score.toFixed(0)}
        </div>
        <div className={`px-2 py-1 rounded-md text-xs font-medium border ${getCategoryColor(category)}`}>
          {category.toUpperCase()}
        </div>
        <div className="text-gray-500 text-sm">
          #{priority}
        </div>
      </div>
    );
  }

  return (
    <div className="bg-gray-800 rounded-lg border border-gray-700 p-4">
      {/* Score Gauge */}
      <div className="flex items-center justify-center mb-4">
        <div className="relative w-32 h-16 overflow-hidden">
          {/* Gauge background */}
          <div className="absolute inset-0 flex items-end justify-center">
            <div className="w-32 h-16 border-t-8 border-l-8 border-r-8 border-gray-700 rounded-t-full"></div>
          </div>
          {/* Gauge fill */}
          <div
            className="absolute inset-0 flex items-end justify-center origin-bottom"
            style={{ transform: `rotate(${getGaugeRotation(score)}deg)` }}
          >
            <div className={`w-1 h-14 ${getScoreColor(score)} bg-current rounded-t-full`}></div>
          </div>
          {/* Score display */}
          <div className="absolute inset-x-0 bottom-0 text-center">
            <span className={`text-2xl font-bold ${getScoreColor(score)}`}>
              {score.toFixed(0)}
            </span>
          </div>
        </div>
      </div>

      {/* Category Badge */}
      <div className="flex justify-center mb-4">
        <span className={`px-3 py-1 rounded-full text-sm font-medium border ${getCategoryColor(category)}`}>
          {category.toUpperCase()} RISK
        </span>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-3 gap-2 text-center">
        <div className="bg-gray-900/50 rounded p-2">
          <TrendingUp className="w-4 h-4 mx-auto mb-1 text-cyan-400" />
          <div className="text-xs text-gray-400">Priority</div>
          <div className="text-sm font-medium text-white">#{priority}</div>
        </div>
        <div className="bg-gray-900/50 rounded p-2">
          <Shield className="w-4 h-4 mx-auto mb-1 text-cyan-400" />
          <div className="text-xs text-gray-400">Confidence</div>
          <div className="text-sm font-medium text-white">{confidence.toFixed(0)}%</div>
        </div>
        {estimatedHours !== undefined && (
          <div className="bg-gray-900/50 rounded p-2">
            <Clock className="w-4 h-4 mx-auto mb-1 text-cyan-400" />
            <div className="text-xs text-gray-400">Effort</div>
            <div className="text-sm font-medium text-white">{estimatedHours}h</div>
          </div>
        )}
      </div>
    </div>
  );
};

export default RiskScoreCard;
