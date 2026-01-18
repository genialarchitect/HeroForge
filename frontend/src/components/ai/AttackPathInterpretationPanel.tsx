import React, { useState, useEffect, useCallback } from 'react';
import { toast } from 'react-toastify';
import {
  Brain,
  AlertTriangle,
  Shield,
  Target,
  ChevronDown,
  ChevronRight,
  ExternalLink,
  RefreshCw,
  Building2,
  DollarSign,
  Clock,
  TrendingUp,
  FileWarning,
  Zap,
} from 'lucide-react';
import Card from '../ui/Card';
import Button from '../ui/Button';
import LoadingSpinner from '../ui/LoadingSpinner';
import Badge from '../ui/Badge';
import { attackPathsAPI } from '../../services/api';
import type { AttackPathInterpretation } from '../../types';

interface AttackPathInterpretationPanelProps {
  pathId: string;
  pathName?: string;
}

const AttackPathInterpretationPanel: React.FC<AttackPathInterpretationPanelProps> = ({
  pathId,
  pathName,
}) => {
  const [interpretation, setInterpretation] = useState<AttackPathInterpretation | null>(null);
  const [loading, setLoading] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [expandedSections, setExpandedSections] = useState<Record<string, boolean>>({
    narrative: true,
    mitre: false,
    impact: false,
    blocking: false,
    risk: false,
  });

  const loadInterpretation = useCallback(async () => {
    setLoading(true);
    try {
      const response = await attackPathsAPI.getInterpretation(pathId);
      setInterpretation(response.data);
    } catch {
      // No interpretation exists yet - that's OK
      setInterpretation(null);
    } finally {
      setLoading(false);
    }
  }, [pathId]);

  useEffect(() => {
    loadInterpretation();
  }, [loadInterpretation]);

  const handleGenerateInterpretation = async (force = false) => {
    setGenerating(true);
    try {
      const response = await attackPathsAPI.interpretPath(pathId, { force });
      setInterpretation(response.data);
      toast.success('AI interpretation generated successfully');
    } catch (error: unknown) {
      const axiosError = error as { response?: { data?: { error?: string } } };
      if (axiosError.response?.data?.error?.includes('already exists')) {
        toast.info('Interpretation already exists. Use regenerate to update.');
      } else {
        toast.error(axiosError.response?.data?.error || 'Failed to generate interpretation');
      }
    } finally {
      setGenerating(false);
    }
  };

  const toggleSection = (section: string) => {
    setExpandedSections((prev) => ({
      ...prev,
      [section]: !prev[section],
    }));
  };

  const getRiskColor = (score: number) => {
    if (score >= 80) return 'text-red-400';
    if (score >= 60) return 'text-orange-400';
    if (score >= 40) return 'text-yellow-400';
    return 'text-green-400';
  };

  const getImpactBadge = (level: string) => {
    const levels: Record<string, 'critical' | 'high' | 'medium' | 'low'> = {
      Critical: 'critical',
      High: 'high',
      Medium: 'medium',
      Low: 'low',
    };
    return <Badge type={levels[level] || 'medium'}>{level}</Badge>;
  };

  if (loading) {
    return (
      <Card className="p-6">
        <div className="flex items-center justify-center py-8">
          <LoadingSpinner />
          <span className="ml-2 text-slate-400">Loading interpretation...</span>
        </div>
      </Card>
    );
  }

  if (!interpretation) {
    return (
      <Card className="p-6">
        <div className="text-center py-8">
          <Brain className="h-12 w-12 text-slate-500 mx-auto mb-4" />
          <h3 className="text-lg font-semibold text-white mb-2">
            AI Interpretation Not Available
          </h3>
          <p className="text-slate-400 mb-6 max-w-md mx-auto">
            Generate an AI interpretation to get a detailed narrative explanation of this
            attack path, including business impact analysis and recommended blocking points.
          </p>
          <Button
            onClick={() => handleGenerateInterpretation(false)}
            disabled={generating}
          >
            {generating ? (
              <>
                <LoadingSpinner />
                <span className="ml-2">Generating...</span>
              </>
            ) : (
              <>
                <Brain className="h-4 w-4 mr-2" />
                Generate AI Interpretation
              </>
            )}
          </Button>
        </div>
      </Card>
    );
  }

  return (
    <div className="space-y-4">
      {/* Header */}
      <Card className="p-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-primary/20 rounded-lg">
              <Brain className="h-5 w-5 text-primary" />
            </div>
            <div>
              <h3 className="text-lg font-semibold text-white">
                AI Interpretation
              </h3>
              <p className="text-xs text-slate-400">
                Generated: {new Date(interpretation.generated_at).toLocaleString()}
              </p>
            </div>
          </div>
          <Button
            variant="secondary"
            onClick={() => handleGenerateInterpretation(true)}
            disabled={generating}
          >
            {generating ? <LoadingSpinner /> : <RefreshCw className="h-4 w-4" />}
            <span className="ml-2">Regenerate</span>
          </Button>
        </div>
      </Card>

      {/* Attack Narrative Section */}
      <Card className="overflow-hidden">
        <button
          className="w-full p-4 flex items-center justify-between text-left hover:bg-dark-bg/50 transition-colors"
          onClick={() => toggleSection('narrative')}
        >
          <div className="flex items-center gap-3">
            <Target className="h-5 w-5 text-red-400" />
            <span className="font-semibold text-white">Attack Narrative</span>
          </div>
          {expandedSections.narrative ? (
            <ChevronDown className="h-5 w-5 text-slate-400" />
          ) : (
            <ChevronRight className="h-5 w-5 text-slate-400" />
          )}
        </button>
        {expandedSections.narrative && (
          <div className="px-4 pb-4 space-y-4 border-t border-dark-border pt-4">
            {/* Summary */}
            <div className="bg-dark-bg rounded-lg p-4">
              <h4 className="text-sm font-semibold text-slate-400 mb-2">Summary</h4>
              <p className="text-white">{interpretation.narrative.summary}</p>
            </div>

            {/* Attacker Perspective */}
            <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-4">
              <h4 className="text-sm font-semibold text-red-400 mb-2 flex items-center gap-2">
                <AlertTriangle className="h-4 w-4" />
                Attacker Perspective
              </h4>
              <p className="text-slate-300">{interpretation.narrative.attacker_perspective}</p>
            </div>

            {/* Consequences */}
            <div className="bg-orange-500/10 border border-orange-500/30 rounded-lg p-4">
              <h4 className="text-sm font-semibold text-orange-400 mb-2 flex items-center gap-2">
                <FileWarning className="h-4 w-4" />
                Potential Consequences
              </h4>
              <p className="text-slate-300">{interpretation.narrative.consequence_description}</p>
            </div>

            {/* Attack Steps */}
            <div>
              <h4 className="text-sm font-semibold text-white mb-3">Attack Steps</h4>
              <div className="space-y-3">
                {interpretation.narrative.attack_steps.map((step) => (
                  <div
                    key={step.step}
                    className="bg-dark-bg rounded-lg p-4 border-l-4 border-primary"
                  >
                    <div className="flex items-start gap-3">
                      <span className="flex-shrink-0 w-6 h-6 rounded-full bg-primary/20 text-primary text-sm font-bold flex items-center justify-center">
                        {step.step}
                      </span>
                      <div className="flex-1">
                        <p className="text-white font-medium mb-1">{step.action}</p>
                        <p className="text-sm text-slate-400 mb-2">{step.rationale}</p>
                        <div className="text-xs text-slate-500 bg-dark-card rounded p-2">
                          <code>{step.technical_detail}</code>
                        </div>
                        {step.vulnerabilities.length > 0 && (
                          <div className="mt-2 flex flex-wrap gap-1">
                            {step.vulnerabilities.map((vuln, idx) => (
                              <Badge key={idx} type="high">
                                {vuln}
                              </Badge>
                            ))}
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Complexity */}
            <div className="flex items-center gap-2">
              <span className="text-sm text-slate-400">Attack Complexity:</span>
              <Badge type={interpretation.narrative.complexity === 'Low' ? 'critical' :
                          interpretation.narrative.complexity === 'Medium' ? 'high' :
                          interpretation.narrative.complexity === 'High' ? 'medium' : 'low'}>
                {interpretation.narrative.complexity}
              </Badge>
            </div>
          </div>
        )}
      </Card>

      {/* MITRE ATT&CK Mapping Section */}
      <Card className="overflow-hidden">
        <button
          className="w-full p-4 flex items-center justify-between text-left hover:bg-dark-bg/50 transition-colors"
          onClick={() => toggleSection('mitre')}
        >
          <div className="flex items-center gap-3">
            <Zap className="h-5 w-5 text-yellow-400" />
            <span className="font-semibold text-white">MITRE ATT&CK Mapping</span>
            <Badge type="medium">
              {interpretation.mitre_mapping.tactics.length} Tactics, {interpretation.mitre_mapping.techniques.length} Techniques
            </Badge>
          </div>
          {expandedSections.mitre ? (
            <ChevronDown className="h-5 w-5 text-slate-400" />
          ) : (
            <ChevronRight className="h-5 w-5 text-slate-400" />
          )}
        </button>
        {expandedSections.mitre && (
          <div className="px-4 pb-4 space-y-4 border-t border-dark-border pt-4">
            {/* Kill Chain Stages */}
            <div>
              <h4 className="text-sm font-semibold text-white mb-3">Kill Chain Stages</h4>
              <div className="flex flex-wrap gap-2">
                {interpretation.mitre_mapping.kill_chain_stages.map((stage) => (
                  <div
                    key={stage.stage}
                    className="bg-dark-bg rounded-lg p-3 border border-dark-border"
                  >
                    <div className="flex items-center gap-2 mb-1">
                      <span className="text-xs font-bold text-primary">
                        Stage {stage.stage}
                      </span>
                      <span className="text-sm font-medium text-white">{stage.name}</span>
                    </div>
                    <p className="text-xs text-slate-400">{stage.description}</p>
                  </div>
                ))}
              </div>
            </div>

            {/* Tactics */}
            <div>
              <h4 className="text-sm font-semibold text-white mb-3">Tactics</h4>
              <div className="space-y-2">
                {interpretation.mitre_mapping.tactics.map((tactic) => (
                  <div
                    key={tactic.id}
                    className="bg-dark-bg rounded-lg p-3 flex items-start justify-between"
                  >
                    <div>
                      <div className="flex items-center gap-2 mb-1">
                        <Badge type="high">{tactic.id}</Badge>
                        <span className="font-medium text-white">{tactic.name}</span>
                      </div>
                      <p className="text-sm text-slate-400">{tactic.description}</p>
                    </div>
                    <a
                      href={tactic.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-primary hover:text-cyan-300"
                    >
                      <ExternalLink className="h-4 w-4" />
                    </a>
                  </div>
                ))}
              </div>
            </div>

            {/* Techniques */}
            <div>
              <h4 className="text-sm font-semibold text-white mb-3">Techniques</h4>
              <div className="space-y-2">
                {interpretation.mitre_mapping.techniques.map((technique) => (
                  <div
                    key={technique.id}
                    className="bg-dark-bg rounded-lg p-3"
                  >
                    <div className="flex items-start justify-between mb-2">
                      <div className="flex items-center gap-2">
                        <Badge type="critical">{technique.id}</Badge>
                        <span className="font-medium text-white">{technique.name}</span>
                      </div>
                      <a
                        href={technique.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-primary hover:text-cyan-300"
                      >
                        <ExternalLink className="h-4 w-4" />
                      </a>
                    </div>
                    <p className="text-sm text-slate-400 mb-1">{technique.description}</p>
                    <p className="text-xs text-primary">Relevance: {technique.relevance}</p>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </Card>

      {/* Business Impact Section */}
      <Card className="overflow-hidden">
        <button
          className="w-full p-4 flex items-center justify-between text-left hover:bg-dark-bg/50 transition-colors"
          onClick={() => toggleSection('impact')}
        >
          <div className="flex items-center gap-3">
            <Building2 className="h-5 w-5 text-purple-400" />
            <span className="font-semibold text-white">Business Impact</span>
            {getImpactBadge(interpretation.business_impact.level)}
          </div>
          {expandedSections.impact ? (
            <ChevronDown className="h-5 w-5 text-slate-400" />
          ) : (
            <ChevronRight className="h-5 w-5 text-slate-400" />
          )}
        </button>
        {expandedSections.impact && (
          <div className="px-4 pb-4 space-y-4 border-t border-dark-border pt-4">
            <p className="text-slate-300">{interpretation.business_impact.description}</p>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* Affected Functions */}
              <div className="bg-dark-bg rounded-lg p-4">
                <h4 className="text-sm font-semibold text-white mb-2">Affected Functions</h4>
                <div className="flex flex-wrap gap-2">
                  {interpretation.business_impact.affected_functions.map((func, idx) => (
                    <Badge key={idx} type="medium">{func}</Badge>
                  ))}
                </div>
              </div>

              {/* Regulatory Implications */}
              {interpretation.business_impact.regulatory_implications.length > 0 && (
                <div className="bg-dark-bg rounded-lg p-4">
                  <h4 className="text-sm font-semibold text-white mb-2">Regulatory Implications</h4>
                  <ul className="space-y-1">
                    {interpretation.business_impact.regulatory_implications.map((imp, idx) => (
                      <li key={idx} className="text-sm text-slate-300 flex items-center gap-2">
                        <ChevronRight className="h-3 w-3 text-primary" />
                        {imp}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>

            {/* Data at Risk */}
            <div>
              <h4 className="text-sm font-semibold text-white mb-3">Data at Risk</h4>
              <div className="space-y-2">
                {interpretation.business_impact.data_at_risk.map((data, idx) => (
                  <div key={idx} className="bg-dark-bg rounded-lg p-3 flex items-start gap-3">
                    <AlertTriangle className="h-5 w-5 text-yellow-400 flex-shrink-0 mt-0.5" />
                    <div>
                      <div className="flex items-center gap-2 mb-1">
                        <span className="font-medium text-white">{data.data_type}</span>
                        <Badge type="high">{data.classification}</Badge>
                      </div>
                      <p className="text-sm text-slate-400">{data.risk}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Financial Impact */}
            {interpretation.business_impact.financial_impact && (
              <div className="bg-green-500/10 border border-green-500/30 rounded-lg p-4">
                <h4 className="text-sm font-semibold text-green-400 mb-3 flex items-center gap-2">
                  <DollarSign className="h-4 w-4" />
                  Estimated Financial Impact
                </h4>
                <div className="flex items-center gap-4 mb-3">
                  <div>
                    <span className="text-slate-400 text-sm">Minimum:</span>
                    <span className="ml-2 text-xl font-bold text-white">
                      ${interpretation.business_impact.financial_impact.min_estimate_usd.toLocaleString()}
                    </span>
                  </div>
                  <span className="text-slate-500">—</span>
                  <div>
                    <span className="text-slate-400 text-sm">Maximum:</span>
                    <span className="ml-2 text-xl font-bold text-white">
                      ${interpretation.business_impact.financial_impact.max_estimate_usd.toLocaleString()}
                    </span>
                  </div>
                </div>
                <p className="text-xs text-slate-400">
                  Confidence: {interpretation.business_impact.financial_impact.confidence}
                </p>
                <div className="mt-2 flex flex-wrap gap-1">
                  {interpretation.business_impact.financial_impact.cost_factors.map((factor, idx) => (
                    <span key={idx} className="text-xs bg-dark-bg px-2 py-1 rounded text-slate-300">
                      {factor}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* Reputational Risk */}
            <div className="bg-dark-bg rounded-lg p-4">
              <h4 className="text-sm font-semibold text-white mb-2">Reputational Risk</h4>
              <p className="text-sm text-slate-300 mb-2">
                {interpretation.business_impact.reputational_risk.description}
              </p>
              {interpretation.business_impact.reputational_risk.potential_headlines.length > 0 && (
                <div className="mt-3">
                  <p className="text-xs text-slate-400 mb-2">Potential Headlines:</p>
                  {interpretation.business_impact.reputational_risk.potential_headlines.map((headline, idx) => (
                    <p key={idx} className="text-sm italic text-red-300">"{headline}"</p>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}
      </Card>

      {/* Blocking Points Section */}
      <Card className="overflow-hidden">
        <button
          className="w-full p-4 flex items-center justify-between text-left hover:bg-dark-bg/50 transition-colors"
          onClick={() => toggleSection('blocking')}
        >
          <div className="flex items-center gap-3">
            <Shield className="h-5 w-5 text-green-400" />
            <span className="font-semibold text-white">Recommended Blocking Points</span>
            <Badge type="low">{interpretation.blocking_points.length} actions</Badge>
          </div>
          {expandedSections.blocking ? (
            <ChevronDown className="h-5 w-5 text-slate-400" />
          ) : (
            <ChevronRight className="h-5 w-5 text-slate-400" />
          )}
        </button>
        {expandedSections.blocking && (
          <div className="px-4 pb-4 space-y-3 border-t border-dark-border pt-4">
            {interpretation.blocking_points
              .sort((a, b) => a.priority - b.priority)
              .map((point) => (
                <div
                  key={point.step}
                  className="bg-dark-bg rounded-lg p-4 border-l-4 border-green-500"
                >
                  <div className="flex items-start justify-between mb-2">
                    <div className="flex items-center gap-2">
                      <span className="flex-shrink-0 w-6 h-6 rounded-full bg-green-500/20 text-green-400 text-sm font-bold flex items-center justify-center">
                        {point.priority}
                      </span>
                      <span className="font-medium text-white">{point.action}</span>
                    </div>
                    <Badge type={point.implementation_effort === 'Low' ? 'low' :
                                point.implementation_effort === 'Medium' ? 'medium' :
                                point.implementation_effort === 'High' ? 'high' : 'critical'}>
                      {point.implementation_effort} Effort
                    </Badge>
                  </div>
                  <p className="text-sm text-slate-400 mb-3">{point.effectiveness}</p>
                  <div className="flex flex-wrap gap-2">
                    {point.controls.map((control, idx) => (
                      <span
                        key={idx}
                        className="text-xs bg-green-500/20 text-green-300 px-2 py-1 rounded"
                      >
                        {control}
                      </span>
                    ))}
                  </div>
                </div>
              ))}
          </div>
        )}
      </Card>

      {/* Risk Assessment Section */}
      <Card className="overflow-hidden">
        <button
          className="w-full p-4 flex items-center justify-between text-left hover:bg-dark-bg/50 transition-colors"
          onClick={() => toggleSection('risk')}
        >
          <div className="flex items-center gap-3">
            <TrendingUp className="h-5 w-5 text-blue-400" />
            <span className="font-semibold text-white">Risk Assessment</span>
            <span className={`text-xl font-bold ${getRiskColor(interpretation.risk_assessment.risk_score)}`}>
              {interpretation.risk_assessment.risk_score.toFixed(0)}/100
            </span>
          </div>
          {expandedSections.risk ? (
            <ChevronDown className="h-5 w-5 text-slate-400" />
          ) : (
            <ChevronRight className="h-5 w-5 text-slate-400" />
          )}
        </button>
        {expandedSections.risk && (
          <div className="px-4 pb-4 space-y-4 border-t border-dark-border pt-4">
            {/* Score Breakdown */}
            <div className="grid grid-cols-3 gap-4">
              <div className="bg-dark-bg rounded-lg p-4 text-center">
                <p className="text-xs text-slate-400 mb-1">Risk Score</p>
                <p className={`text-2xl font-bold ${getRiskColor(interpretation.risk_assessment.risk_score)}`}>
                  {interpretation.risk_assessment.risk_score.toFixed(0)}
                </p>
              </div>
              <div className="bg-dark-bg rounded-lg p-4 text-center">
                <p className="text-xs text-slate-400 mb-1">Exploitation Probability</p>
                <p className={`text-2xl font-bold ${getRiskColor(interpretation.risk_assessment.exploitation_probability)}`}>
                  {interpretation.risk_assessment.exploitation_probability.toFixed(0)}%
                </p>
              </div>
              <div className="bg-dark-bg rounded-lg p-4 text-center">
                <p className="text-xs text-slate-400 mb-1">Impact Score</p>
                <p className={`text-2xl font-bold ${getRiskColor(interpretation.risk_assessment.impact_score)}`}>
                  {interpretation.risk_assessment.impact_score.toFixed(0)}
                </p>
              </div>
            </div>

            {/* Time to Exploit */}
            <div className="flex items-center gap-3 bg-dark-bg rounded-lg p-4">
              <Clock className="h-5 w-5 text-slate-400" />
              <div>
                <p className="text-xs text-slate-400">Estimated Time to Exploit</p>
                <p className="text-lg font-semibold text-white">
                  {interpretation.risk_assessment.estimated_time_to_exploit}
                </p>
              </div>
            </div>

            {/* Risk Factors */}
            <div>
              <h4 className="text-sm font-semibold text-white mb-3">Risk Factors</h4>
              <div className="space-y-3">
                {interpretation.risk_assessment.risk_factors.map((factor) => (
                  <div key={factor.name} className="bg-dark-bg rounded-lg p-3">
                    <div className="flex items-center justify-between mb-2">
                      <span className="font-medium text-white">{factor.name}</span>
                      <span className={`font-bold ${getRiskColor(factor.score)}`}>
                        {factor.score.toFixed(0)}
                      </span>
                    </div>
                    <p className="text-xs text-slate-400 mb-2">{factor.description}</p>
                    <div className="w-full bg-dark-card rounded-full h-2">
                      <div
                        className={`h-2 rounded-full ${
                          factor.score >= 80 ? 'bg-red-500' :
                          factor.score >= 60 ? 'bg-orange-500' :
                          factor.score >= 40 ? 'bg-yellow-500' : 'bg-green-500'
                        }`}
                        style={{ width: `${factor.score}%` }}
                      />
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Recommendation */}
            <div className={`rounded-lg p-4 ${
              interpretation.risk_assessment.risk_score >= 80
                ? 'bg-red-500/10 border border-red-500/30'
                : interpretation.risk_assessment.risk_score >= 60
                  ? 'bg-orange-500/10 border border-orange-500/30'
                  : 'bg-yellow-500/10 border border-yellow-500/30'
            }`}>
              <h4 className={`text-sm font-semibold mb-2 ${
                interpretation.risk_assessment.risk_score >= 80
                  ? 'text-red-400'
                  : interpretation.risk_assessment.risk_score >= 60
                    ? 'text-orange-400'
                    : 'text-yellow-400'
              }`}>
                Recommendation
              </h4>
              <p className="text-slate-300">{interpretation.risk_assessment.recommendation}</p>
            </div>
          </div>
        )}
      </Card>
    </div>
  );
};

export default AttackPathInterpretationPanel;
