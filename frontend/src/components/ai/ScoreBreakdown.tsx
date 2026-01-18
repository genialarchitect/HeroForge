import React from 'react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts';
import type { AIVulnerabilityScore } from '../../types';

interface ScoreBreakdownProps {
  score: AIVulnerabilityScore;
}

const ScoreBreakdown: React.FC<ScoreBreakdownProps> = ({ score }) => {
  // Prepare data for chart
  const chartData = score.factor_scores.map((factor) => ({
    name: factor.factor_name.replace(' ', '\n'),
    value: factor.normalized_value,
    contribution: factor.contribution,
    weight: factor.weight,
  }));

  const getBarColor = (value: number) => {
    if (value >= 80) return '#ef4444';
    if (value >= 60) return '#f97316';
    if (value >= 40) return '#eab308';
    return '#22c55e';
  };

  const CustomTooltip = ({ active, payload }: { active?: boolean; payload?: Array<{ payload: typeof chartData[0] }> }) => {
    if (active && payload && payload.length) {
      const data = payload[0].payload;
      return (
        <div className="bg-gray-800 border border-gray-700 rounded-lg p-3 shadow-lg">
          <p className="font-medium text-white">{data.name.replace('\n', ' ')}</p>
          <p className="text-sm text-gray-400">
            Score: <span className="text-white">{data.value.toFixed(1)}</span>
          </p>
          <p className="text-sm text-gray-400">
            Weight: <span className="text-white">{(data.weight * 100).toFixed(0)}%</span>
          </p>
          <p className="text-sm text-gray-400">
            Contribution: <span className="text-cyan-400">{data.contribution.toFixed(1)}</span>
          </p>
        </div>
      );
    }
    return null;
  };

  return (
    <div className="bg-gray-800 rounded-lg border border-gray-700 p-4">
      <h3 className="text-lg font-medium text-white mb-4">Score Breakdown</h3>

      {/* Bar Chart */}
      <div className="h-64 mb-4">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart
            data={chartData}
            layout="vertical"
            margin={{ top: 5, right: 20, left: 100, bottom: 5 }}
          >
            <XAxis
              type="number"
              domain={[0, 100]}
              tick={{ fill: '#9ca3af', fontSize: 12 }}
              axisLine={{ stroke: '#4b5563' }}
              tickLine={{ stroke: '#4b5563' }}
            />
            <YAxis
              type="category"
              dataKey="name"
              tick={{ fill: '#9ca3af', fontSize: 11 }}
              axisLine={{ stroke: '#4b5563' }}
              tickLine={{ stroke: '#4b5563' }}
              width={95}
            />
            <Tooltip content={<CustomTooltip />} />
            <Bar dataKey="value" radius={[0, 4, 4, 0]}>
              {chartData.map((entry, index) => (
                <Cell key={`cell-${index}`} fill={getBarColor(entry.value)} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>

      {/* Factor Details Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-gray-700">
              <th className="text-left py-2 text-gray-400 font-medium">Factor</th>
              <th className="text-right py-2 text-gray-400 font-medium">Score</th>
              <th className="text-right py-2 text-gray-400 font-medium">Weight</th>
              <th className="text-right py-2 text-gray-400 font-medium">Contribution</th>
            </tr>
          </thead>
          <tbody>
            {score.factor_scores.map((factor, index) => (
              <tr key={index} className="border-b border-gray-700/50">
                <td className="py-2 text-white">{factor.factor_name}</td>
                <td className="py-2 text-right text-gray-300">
                  {factor.normalized_value.toFixed(1)}
                </td>
                <td className="py-2 text-right text-gray-400">
                  {(factor.weight * 100).toFixed(0)}%
                </td>
                <td className="py-2 text-right text-cyan-400 font-medium">
                  {factor.contribution.toFixed(1)}
                </td>
              </tr>
            ))}
            <tr className="font-medium">
              <td className="py-2 text-white">Total</td>
              <td className="py-2 text-right text-white">
                {score.effective_risk_score.toFixed(1)}
              </td>
              <td className="py-2 text-right text-gray-400">100%</td>
              <td className="py-2 text-right text-cyan-400">
                {score.factor_scores.reduce((acc, f) => acc + f.contribution, 0).toFixed(1)}
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      {/* Remediation Effort */}
      <div className="mt-4 p-3 bg-gray-900/50 rounded-lg">
        <h4 className="text-sm font-medium text-gray-300 mb-2">Remediation Effort</h4>
        <div className="grid grid-cols-2 gap-4 text-sm">
          <div>
            <span className="text-gray-400">Estimated Hours:</span>
            <span className="ml-2 text-white font-medium">
              {score.estimated_effort.estimated_hours}h
            </span>
          </div>
          <div>
            <span className="text-gray-400">Effort Level:</span>
            <span className="ml-2 text-white font-medium capitalize">
              {score.estimated_effort.effort_level.replace('_', ' ')}
            </span>
          </div>
          <div>
            <span className="text-gray-400">Impact Level:</span>
            <span className="ml-2 text-white font-medium capitalize">
              {score.estimated_effort.impact_level}
            </span>
          </div>
          <div className="flex items-center space-x-4">
            {score.estimated_effort.requires_downtime && (
              <span className="text-red-400 text-xs">Requires Downtime</span>
            )}
            {score.estimated_effort.requires_testing && (
              <span className="text-yellow-400 text-xs">Requires Testing</span>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default ScoreBreakdown;
