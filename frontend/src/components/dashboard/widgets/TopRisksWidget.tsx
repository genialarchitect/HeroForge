import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { AlertTriangle, TrendingUp, Shield, ChevronRight, Sparkles, RefreshCw, Info } from 'lucide-react';
import { aiAPI, AIVulnerabilityScore } from '../../../services/aiApi';

interface TopRisksWidgetProps {
  limit?: number;
  onRefresh?: () => void;
}

const TopRisksWidget: React.FC<TopRisksWidgetProps> = ({ limit = 5, onRefresh }) => {
  const [risks, setRisks] = useState<AIVulnerabilityScore[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const navigate = useNavigate();

  const fetchTopRisks = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await aiAPI.getTopRisks(limit);
      setRisks(response.vulnerabilities);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch top risks');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchTopRisks();
  }, [limit]);

  const handleRefresh = () => {
    fetchTopRisks();
    onRefresh?.();
  };

  const handleViewVulnerability = (vulnId: string) => {
    navigate(`/vulnerabilities/${vulnId}`);
  };

  const getRiskColor = (score: number) => {
    if (score >= 80) return 'text-red-400 bg-red-400/10';
    if (score >= 60) return 'text-orange-400 bg-orange-400/10';
    if (score >= 40) return 'text-yellow-400 bg-yellow-400/10';
    return 'text-green-400 bg-green-400/10';
  };

  const getRiskLabel = (score: number) => {
    if (score >= 80) return 'Critical';
    if (score >= 60) return 'High';
    if (score >= 40) return 'Medium';
    return 'Low';
  };

  if (loading) {
    return (
      <div className="bg-gray-800 rounded-lg border border-gray-700 p-6">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <Sparkles className="h-5 w-5 text-purple-400" />
            <h3 className="text-lg font-semibold text-white">Top AI-Prioritized Risks</h3>
          </div>
        </div>
        <div className="flex items-center justify-center h-48">
          <RefreshCw className="h-8 w-8 text-gray-400 animate-spin" />
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-gray-800 rounded-lg border border-gray-700 p-6">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <Sparkles className="h-5 w-5 text-purple-400" />
            <h3 className="text-lg font-semibold text-white">Top AI-Prioritized Risks</h3>
          </div>
          <button
            onClick={handleRefresh}
            className="p-2 text-gray-400 hover:text-white hover:bg-gray-700 rounded-lg transition-colors"
          >
            <RefreshCw className="h-4 w-4" />
          </button>
        </div>
        <div className="flex flex-col items-center justify-center h-48 text-gray-400">
          <AlertTriangle className="h-8 w-8 mb-2" />
          <p className="text-sm">{error}</p>
          <button
            onClick={handleRefresh}
            className="mt-3 text-sm text-purple-400 hover:text-purple-300"
          >
            Try again
          </button>
        </div>
      </div>
    );
  }

  if (risks.length === 0) {
    return (
      <div className="bg-gray-800 rounded-lg border border-gray-700 p-6">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <Sparkles className="h-5 w-5 text-purple-400" />
            <h3 className="text-lg font-semibold text-white">Top AI-Prioritized Risks</h3>
          </div>
        </div>
        <div className="flex flex-col items-center justify-center h-48 text-gray-400">
          <Shield className="h-12 w-12 mb-3 text-green-400" />
          <p className="text-sm">No prioritized vulnerabilities found</p>
          <p className="text-xs mt-1">Run a scan to see AI-prioritized risks</p>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-gray-800 rounded-lg border border-gray-700 p-6">
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <Sparkles className="h-5 w-5 text-purple-400" />
          <h3 className="text-lg font-semibold text-white">Top AI-Prioritized Risks</h3>
        </div>
        <button
          onClick={handleRefresh}
          className="p-2 text-gray-400 hover:text-white hover:bg-gray-700 rounded-lg transition-colors"
          title="Refresh"
        >
          <RefreshCw className="h-4 w-4" />
        </button>
      </div>

      {/* Risk List */}
      <div className="space-y-3">
        {risks.map((risk, index) => (
          <div
            key={risk.vulnerability_id}
            className="bg-gray-750 rounded-lg border border-gray-700 overflow-hidden hover:border-gray-600 transition-colors"
          >
            <button
              onClick={() => setExpandedId(expandedId === risk.vulnerability_id ? null : risk.vulnerability_id)}
              className="w-full flex items-center justify-between p-3 text-left"
            >
              <div className="flex items-center gap-3">
                <span className={`flex items-center justify-center w-8 h-8 rounded-lg text-sm font-bold ${getRiskColor(risk.effective_risk_score)}`}>
                  {index + 1}
                </span>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-medium text-white truncate">
                      {risk.vulnerability_id}
                    </span>
                    <span className={`text-xs px-2 py-0.5 rounded-full ${getRiskColor(risk.effective_risk_score)}`}>
                      {getRiskLabel(risk.effective_risk_score)}
                    </span>
                  </div>
                  <div className="flex items-center gap-2 mt-1">
                    <span className="text-xs text-gray-400">
                      Risk Score: {risk.effective_risk_score.toFixed(1)}
                    </span>
                    {risk.epss_score !== undefined && risk.epss_score > 0 && (
                      <span className="text-xs text-gray-500">
                        • EPSS: {(risk.epss_score * 100).toFixed(1)}%
                      </span>
                    )}
                  </div>
                </div>
              </div>
              <ChevronRight className={`h-4 w-4 text-gray-400 transition-transform ${expandedId === risk.vulnerability_id ? 'rotate-90' : ''}`} />
            </button>

            {/* Expanded Content - "Why This Matters" */}
            {expandedId === risk.vulnerability_id && (
              <div className="px-3 pb-3 border-t border-gray-700">
                <div className="pt-3">
                  <div className="flex items-center gap-2 text-sm font-medium text-purple-300 mb-2">
                    <Info className="h-4 w-4" />
                    Why This Matters
                  </div>

                  {risk.explanation ? (
                    <p className="text-sm text-gray-300 mb-3">{risk.explanation}</p>
                  ) : (
                    <p className="text-sm text-gray-400 mb-3 italic">
                      This vulnerability has been prioritized based on multiple risk factors including CVSS score, exploitability, and asset criticality.
                    </p>
                  )}

                  {/* Key Factors */}
                  {risk.key_factors && risk.key_factors.length > 0 && (
                    <div className="space-y-2 mb-3">
                      <p className="text-xs font-medium text-gray-400">Key Factors:</p>
                      {risk.key_factors.map((factor, i) => (
                        <div key={i} className="flex items-center justify-between text-xs">
                          <span className="text-gray-300">{factor.name}</span>
                          <span className="text-gray-400">{factor.value}</span>
                        </div>
                      ))}
                    </div>
                  )}

                  {/* Score Breakdown */}
                  <div className="grid grid-cols-2 gap-2 text-xs">
                    <div className="flex justify-between">
                      <span className="text-gray-400">Base CVSS:</span>
                      <span className="text-white">{risk.base_cvss_score.toFixed(1)}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">Exploitability:</span>
                      <span className="text-white">{risk.exploitability_score.toFixed(1)}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">Asset Criticality:</span>
                      <span className="text-white">{risk.asset_criticality_score.toFixed(1)}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">Network Exposure:</span>
                      <span className="text-white">{risk.network_exposure_score.toFixed(1)}</span>
                    </div>
                  </div>

                  {/* Effort Estimate */}
                  <div className="mt-3 pt-3 border-t border-gray-700 flex items-center justify-between">
                    <span className="text-xs text-gray-400">
                      Est. Remediation: {risk.remediation_effort_estimate}
                    </span>
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        handleViewVulnerability(risk.vulnerability_id);
                      }}
                      className="text-xs text-purple-400 hover:text-purple-300 flex items-center gap-1"
                    >
                      View Details
                      <ChevronRight className="h-3 w-3" />
                    </button>
                  </div>
                </div>
              </div>
            )}
          </div>
        ))}
      </div>

      {/* Footer */}
      <div className="mt-4 pt-4 border-t border-gray-700 flex items-center justify-between">
        <span className="text-xs text-gray-500">
          Prioritized by AI based on risk context
        </span>
        <button
          onClick={() => navigate('/vulnerabilities?sort=ai_priority')}
          className="text-sm text-purple-400 hover:text-purple-300 flex items-center gap-1"
        >
          View All
          <ChevronRight className="h-4 w-4" />
        </button>
      </div>
    </div>
  );
};

export default TopRisksWidget;
