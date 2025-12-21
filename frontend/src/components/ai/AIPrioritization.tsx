import React, { useState, useEffect, useCallback } from 'react';
import { toast } from 'react-toastify';
import {
  Brain,
  RefreshCw,
  Settings,
  ChevronRight,
  AlertTriangle,
  Target,
  Clock,
  TrendingUp,
  BarChart3,
} from 'lucide-react';
import {
  RadarChart,
  PolarGrid,
  PolarAngleAxis,
  PolarRadiusAxis,
  Radar,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Tooltip,
} from 'recharts';
import { aiAPI } from '../../services/api';
import type { AIPrioritizationResult, AIVulnerabilityScore, PrioritizationSummary } from '../../types';
import Button from '../ui/Button';
import PrioritizedList from './PrioritizedList';
import ScoreBreakdown from './ScoreBreakdown';
import AIConfigPanel from './AIConfigPanel';

interface AIPrioritizationProps {
  scanId: string;
  onSelectVulnerability?: (vulnId: string) => void;
}

const AIPrioritization: React.FC<AIPrioritizationProps> = ({
  scanId,
  onSelectVulnerability,
}) => {
  const [result, setResult] = useState<AIPrioritizationResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [calculating, setCalculating] = useState(false);
  const [selectedScore, setSelectedScore] = useState<AIVulnerabilityScore | null>(null);
  const [showConfig, setShowConfig] = useState(false);
  const [activeTab, setActiveTab] = useState<'list' | 'matrix' | 'config'>('list');

  const loadScores = useCallback(async () => {
    try {
      setLoading(true);
      const response = await aiAPI.getScores(scanId);
      setResult(response.data);
    } catch (error: unknown) {
      // If no scores exist yet, that's okay - user can calculate them
      const err = error as { response?: { status?: number } };
      if (err.response?.status !== 404) {
        console.error('Failed to load AI scores:', error);
      }
    } finally {
      setLoading(false);
    }
  }, [scanId]);

  useEffect(() => {
    loadScores();
  }, [loadScores]);

  const handleCalculate = async (forceRecalculate = false) => {
    try {
      setCalculating(true);
      const response = await aiAPI.prioritize(scanId, { force_recalculate: forceRecalculate });
      setResult(response.data);
      toast.success('AI prioritization calculated successfully');
    } catch (error) {
      console.error('Failed to calculate prioritization:', error);
      toast.error('Failed to calculate AI prioritization');
    } finally {
      setCalculating(false);
    }
  };

  const handleSelectVulnerability = (vulnId: string) => {
    const score = result?.scores.find((s) => s.vulnerability_id === vulnId);
    setSelectedScore(score || null);
    if (onSelectVulnerability) {
      onSelectVulnerability(vulnId);
    }
  };

  // Prepare data for pie chart
  const getPieChartData = (summary: PrioritizationSummary) => [
    { name: 'Critical', value: summary.critical_count, color: '#ef4444' },
    { name: 'High', value: summary.high_count, color: '#f97316' },
    { name: 'Medium', value: summary.medium_count, color: '#eab308' },
    { name: 'Low', value: summary.low_count, color: '#22c55e' },
  ].filter((d) => d.value > 0);

  // Prepare data for radar chart (average factor scores)
  const getRadarData = (scores: AIVulnerabilityScore[]) => {
    if (scores.length === 0) return [];

    const factorNames = scores[0]?.factor_scores.map((f) => f.factor_name) || [];
    return factorNames.map((name) => {
      const avgValue =
        scores.reduce((sum, s) => {
          const factor = s.factor_scores.find((f) => f.factor_name === name);
          return sum + (factor?.normalized_value || 0);
        }, 0) / scores.length;

      return {
        factor: name.replace(' ', '\n'),
        value: avgValue,
        fullMark: 100,
      };
    });
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center p-8">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-cyan-500"></div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <Brain className="w-6 h-6 text-cyan-400" />
          <h2 className="text-xl font-semibold text-white">AI Vulnerability Prioritization</h2>
        </div>
        <div className="flex items-center space-x-2">
          {result && (
            <Button
              variant="secondary"
              size="sm"
              onClick={() => handleCalculate(true)}
              loading={calculating}
            >
              <RefreshCw className="w-4 h-4 mr-1" />
              Recalculate
            </Button>
          )}
          <Button
            variant={showConfig ? 'primary' : 'secondary'}
            size="sm"
            onClick={() => setShowConfig(!showConfig)}
          >
            <Settings className="w-4 h-4 mr-1" />
            Configure
          </Button>
        </div>
      </div>

      {/* Config Panel (Collapsible) */}
      {showConfig && (
        <AIConfigPanel onConfigUpdate={() => handleCalculate(true)} />
      )}

      {/* No Results State */}
      {!result && !loading && (
        <div className="bg-gray-800 rounded-lg border border-gray-700 p-8 text-center">
          <Brain className="w-12 h-12 text-gray-600 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-white mb-2">
            No AI Prioritization Data
          </h3>
          <p className="text-gray-400 mb-6">
            Calculate AI-based risk scores to prioritize vulnerabilities for remediation.
          </p>
          <Button
            variant="primary"
            onClick={() => handleCalculate(false)}
            loading={calculating}
          >
            <Brain className="w-4 h-4 mr-2" />
            Calculate AI Prioritization
          </Button>
        </div>
      )}

      {/* Results */}
      {result && (
        <>
          {/* Summary Cards */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="bg-gray-800 rounded-lg border border-gray-700 p-4">
              <div className="flex items-center space-x-2 mb-2">
                <AlertTriangle className="w-5 h-5 text-red-400" />
                <span className="text-sm text-gray-400">Critical</span>
              </div>
              <div className="text-2xl font-bold text-red-400">
                {result.summary.critical_count}
              </div>
            </div>
            <div className="bg-gray-800 rounded-lg border border-gray-700 p-4">
              <div className="flex items-center space-x-2 mb-2">
                <TrendingUp className="w-5 h-5 text-cyan-400" />
                <span className="text-sm text-gray-400">Avg Risk Score</span>
              </div>
              <div className="text-2xl font-bold text-white">
                {result.summary.average_risk_score.toFixed(1)}
              </div>
            </div>
            <div className="bg-gray-800 rounded-lg border border-gray-700 p-4">
              <div className="flex items-center space-x-2 mb-2">
                <Target className="w-5 h-5 text-orange-400" />
                <span className="text-sm text-gray-400">Highest Score</span>
              </div>
              <div className="text-2xl font-bold text-orange-400">
                {result.summary.highest_risk_score.toFixed(1)}
              </div>
            </div>
            <div className="bg-gray-800 rounded-lg border border-gray-700 p-4">
              <div className="flex items-center space-x-2 mb-2">
                <BarChart3 className="w-5 h-5 text-green-400" />
                <span className="text-sm text-gray-400">Total Analyzed</span>
              </div>
              <div className="text-2xl font-bold text-white">
                {result.summary.total_vulnerabilities}
              </div>
            </div>
          </div>

          {/* Charts Row */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Risk Distribution Pie Chart */}
            <div className="bg-gray-800 rounded-lg border border-gray-700 p-4">
              <h3 className="text-sm font-medium text-gray-300 mb-4">Risk Distribution</h3>
              <div className="h-48">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={getPieChartData(result.summary)}
                      cx="50%"
                      cy="50%"
                      innerRadius={40}
                      outerRadius={70}
                      paddingAngle={2}
                      dataKey="value"
                    >
                      {getPieChartData(result.summary).map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                    <Tooltip
                      contentStyle={{
                        backgroundColor: '#1f2937',
                        border: '1px solid #374151',
                        borderRadius: '8px',
                      }}
                      itemStyle={{ color: '#fff' }}
                    />
                  </PieChart>
                </ResponsiveContainer>
              </div>
              <div className="flex justify-center space-x-4 mt-2">
                {getPieChartData(result.summary).map((entry) => (
                  <div key={entry.name} className="flex items-center space-x-1">
                    <div
                      className="w-3 h-3 rounded-full"
                      style={{ backgroundColor: entry.color }}
                    />
                    <span className="text-xs text-gray-400">
                      {entry.name} ({entry.value})
                    </span>
                  </div>
                ))}
              </div>
            </div>

            {/* Factor Radar Chart */}
            <div className="bg-gray-800 rounded-lg border border-gray-700 p-4">
              <h3 className="text-sm font-medium text-gray-300 mb-4">
                Average Factor Scores
              </h3>
              <div className="h-48">
                <ResponsiveContainer width="100%" height="100%">
                  <RadarChart data={getRadarData(result.scores)}>
                    <PolarGrid stroke="#374151" />
                    <PolarAngleAxis
                      dataKey="factor"
                      tick={{ fill: '#9ca3af', fontSize: 10 }}
                    />
                    <PolarRadiusAxis
                      angle={30}
                      domain={[0, 100]}
                      tick={{ fill: '#9ca3af', fontSize: 10 }}
                    />
                    <Radar
                      name="Score"
                      dataKey="value"
                      stroke="#06b6d4"
                      fill="#06b6d4"
                      fillOpacity={0.3}
                    />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: '#1f2937',
                        border: '1px solid #374151',
                        borderRadius: '8px',
                      }}
                      itemStyle={{ color: '#fff' }}
                    />
                  </RadarChart>
                </ResponsiveContainer>
              </div>
            </div>
          </div>

          {/* Tab Navigation */}
          <div className="flex space-x-2 border-b border-gray-700">
            <button
              onClick={() => setActiveTab('list')}
              className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
                activeTab === 'list'
                  ? 'border-cyan-500 text-cyan-400'
                  : 'border-transparent text-gray-400 hover:text-white'
              }`}
            >
              Prioritized List
            </button>
            <button
              onClick={() => setActiveTab('matrix')}
              className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
                activeTab === 'matrix'
                  ? 'border-cyan-500 text-cyan-400'
                  : 'border-transparent text-gray-400 hover:text-white'
              }`}
            >
              Impact vs Likelihood
            </button>
          </div>

          {/* Tab Content */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Main Content */}
            <div className="lg:col-span-2">
              {activeTab === 'list' && (
                <PrioritizedList
                  scores={result.scores}
                  onSelectVulnerability={handleSelectVulnerability}
                  selectedId={selectedScore?.vulnerability_id}
                />
              )}

              {activeTab === 'matrix' && (
                <ImpactLikelihoodMatrix scores={result.scores} />
              )}
            </div>

            {/* Score Breakdown Sidebar */}
            <div className="lg:col-span-1">
              {selectedScore ? (
                <ScoreBreakdown score={selectedScore} />
              ) : (
                <div className="bg-gray-800 rounded-lg border border-gray-700 p-6 text-center">
                  <ChevronRight className="w-8 h-8 text-gray-600 mx-auto mb-2" />
                  <p className="text-gray-400 text-sm">
                    Select a vulnerability to view detailed score breakdown
                  </p>
                </div>
              )}
            </div>
          </div>

          {/* Calculated At */}
          <div className="text-xs text-gray-500 text-right">
            Last calculated: {new Date(result.calculated_at).toLocaleString()}
          </div>
        </>
      )}
    </div>
  );
};

// Impact vs Likelihood Matrix Component
const ImpactLikelihoodMatrix: React.FC<{ scores: AIVulnerabilityScore[] }> = ({ scores }) => {
  // Map scores to matrix positions
  const getPosition = (score: AIVulnerabilityScore) => {
    // Use CVSS for impact and exploit availability for likelihood
    const cvss = score.factor_scores.find(f => f.factor_name === 'CVSS Score');
    const exploit = score.factor_scores.find(f => f.factor_name === 'Exploit Availability');

    const impact = cvss?.normalized_value || 50;
    const likelihood = exploit?.normalized_value || 50;

    return { impact, likelihood };
  };

  const getCategoryColor = (category: string) => {
    switch (category.toLowerCase()) {
      case 'critical': return '#ef4444';
      case 'high': return '#f97316';
      case 'medium': return '#eab308';
      case 'low': return '#22c55e';
      default: return '#6b7280';
    }
  };

  return (
    <div className="bg-gray-800 rounded-lg border border-gray-700 p-4">
      <h3 className="text-sm font-medium text-gray-300 mb-4">Impact vs Likelihood Matrix</h3>

      <div className="relative w-full h-80 border border-gray-700 rounded-lg bg-gray-900/50">
        {/* Background Grid */}
        <div className="absolute inset-0 grid grid-cols-5 grid-rows-5">
          {Array.from({ length: 25 }).map((_, i) => {
            const row = Math.floor(i / 5);
            const col = i % 5;
            let bgColor = 'bg-gray-800/20';

            // Color based on position (top-right = highest risk)
            const riskLevel = (col + (4 - row)) / 8;
            if (riskLevel > 0.7) bgColor = 'bg-red-500/10';
            else if (riskLevel > 0.5) bgColor = 'bg-orange-500/10';
            else if (riskLevel > 0.3) bgColor = 'bg-yellow-500/10';
            else bgColor = 'bg-green-500/10';

            return (
              <div
                key={i}
                className={`border-r border-b border-gray-700/50 ${bgColor}`}
              />
            );
          })}
        </div>

        {/* Axis Labels */}
        <div className="absolute -bottom-6 inset-x-0 text-center text-xs text-gray-400">
          Likelihood (Exploit Availability) →
        </div>
        <div
          className="absolute -left-6 inset-y-0 flex items-center text-xs text-gray-400"
          style={{ writingMode: 'vertical-rl', transform: 'rotate(180deg)' }}
        >
          Impact (CVSS Score) →
        </div>

        {/* Data Points */}
        {scores.map((score) => {
          const { impact, likelihood } = getPosition(score);
          const left = (likelihood / 100) * 100;
          const bottom = (impact / 100) * 100;

          return (
            <div
              key={score.vulnerability_id}
              className="absolute w-3 h-3 rounded-full transform -translate-x-1/2 translate-y-1/2 cursor-pointer hover:scale-150 transition-transform"
              style={{
                left: `${left}%`,
                bottom: `${bottom}%`,
                backgroundColor: getCategoryColor(score.risk_category),
              }}
              title={`Priority #${score.remediation_priority} - Score: ${score.effective_risk_score.toFixed(1)}`}
            />
          );
        })}
      </div>

      {/* Legend */}
      <div className="flex justify-center space-x-4 mt-6">
        {['critical', 'high', 'medium', 'low'].map((cat) => (
          <div key={cat} className="flex items-center space-x-1">
            <div
              className="w-3 h-3 rounded-full"
              style={{ backgroundColor: getCategoryColor(cat) }}
            />
            <span className="text-xs text-gray-400 capitalize">{cat}</span>
          </div>
        ))}
      </div>
    </div>
  );
};

export default AIPrioritization;
