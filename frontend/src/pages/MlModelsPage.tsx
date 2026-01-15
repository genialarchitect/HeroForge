import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { mlModelsAPI } from '../services/api';
import Layout from '../components/layout/Layout';
import Card from '../components/ui/Card';
import { Button } from '../components/ui/Button';
import { Badge } from '../components/ui/Badge';
import { Brain, Target, Monitor, Search, Clock, Cpu, CheckCircle, AlertTriangle } from 'lucide-react';

interface ModelInfo {
  name: string;
  version: number;
  trained_at: string;
  status: string;
}

interface TrainModelResponse {
  status: string;
  model: string;
  version: number;
  metrics: {
    accuracy: number;
    training_samples: number;
    training_time_seconds: number;
  };
}

interface ThreatPrediction {
  threat_level: string;
  confidence: number;
  factors: string[];
  recommendation: string;
}

interface RemediationPrediction {
  estimated_days: number;
  factors: string[];
}

const MlModelsPage: React.FC = () => {
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState<'models' | 'predict'>('models');

  // Training state
  const [trainingModel, setTrainingModel] = useState<string | null>(null);

  // Threat prediction state
  const [threatFeatures, setThreatFeatures] = useState({
    severity_score: 0.5,
    has_cve: false,
    has_exploit: false,
    age_days: 30,
    affected_hosts: 1,
  });
  const [threatPrediction, setThreatPrediction] = useState<ThreatPrediction | null>(null);

  // Remediation prediction state
  const [remediationFeatures, setRemediationFeatures] = useState({
    severity: 'high',
    complexity: 'medium',
    team_size: 3,
  });
  const [remediationPrediction, setRemediationPrediction] = useState<RemediationPrediction | null>(null);

  // Fetch models
  const { data: models, isLoading } = useQuery<ModelInfo[]>({
    queryKey: ['ml-models'],
    queryFn: async () => {
      const response = await mlModelsAPI.listModels();
      return response.data;
    },
  });

  // Train model mutations
  const trainThreatClassifier = useMutation({
    mutationFn: async () => {
      setTrainingModel('threat_classifier');
      const response = await mlModelsAPI.trainThreatClassifier();
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ml-models'] });
      setTrainingModel(null);
    },
    onError: () => {
      setTrainingModel(null);
    },
  });

  const trainAssetFingerprinter = useMutation({
    mutationFn: async () => {
      setTrainingModel('asset_fingerprinter');
      const response = await mlModelsAPI.trainAssetFingerprinter();
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ml-models'] });
      setTrainingModel(null);
    },
    onError: () => {
      setTrainingModel(null);
    },
  });

  const trainAttackDetector = useMutation({
    mutationFn: async () => {
      setTrainingModel('attack_pattern_detector');
      const response = await mlModelsAPI.trainAttackDetector();
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ml-models'] });
      setTrainingModel(null);
    },
    onError: () => {
      setTrainingModel(null);
    },
  });

  const trainRemediationPredictor = useMutation({
    mutationFn: async () => {
      setTrainingModel('remediation_predictor');
      const response = await mlModelsAPI.trainRemediationPredictor();
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ml-models'] });
      setTrainingModel(null);
    },
    onError: () => {
      setTrainingModel(null);
    },
  });

  // Prediction mutations
  const predictThreat = useMutation({
    mutationFn: async () => {
      const response = await mlModelsAPI.predictThreat({
        features: threatFeatures,
      });
      return response.data;
    },
    onSuccess: (data) => {
      setThreatPrediction(data);
    },
  });

  const predictRemediation = useMutation({
    mutationFn: async () => {
      const response = await mlModelsAPI.predictRemediationTime(remediationFeatures);
      return response.data;
    },
    onSuccess: (data) => {
      setRemediationPrediction(data);
    },
  });

  const getSeverityBadge = (level: string) => {
    switch (level.toLowerCase()) {
      case 'critical':
        return <Badge variant="danger">{level.toUpperCase()}</Badge>;
      case 'high':
        return <Badge variant="warning">{level.toUpperCase()}</Badge>;
      case 'medium':
        return <Badge variant="default">{level.toUpperCase()}</Badge>;
      case 'low':
        return <Badge variant="info">{level.toUpperCase()}</Badge>;
      default:
        return <Badge variant="default">{level.toUpperCase()}</Badge>;
    }
  };

  const tabs = [
    { id: 'models', label: 'Model Training', icon: Cpu },
    { id: 'predict', label: 'Predictions', icon: Brain },
  ];

  return (
    <Layout>
      <div className="space-y-6">
        {/* Header */}
        <div>
          <h1 className="text-3xl font-bold text-white flex items-center gap-3">
            <Brain className="h-8 w-8 text-primary" />
            ML Model Management
          </h1>
          <p className="text-slate-400 mt-2">
            Train custom machine learning models on your security data for threat classification, asset fingerprinting, and more
          </p>
        </div>

        {/* Tab Navigation */}
        <div className="flex items-center gap-2 border-b border-dark-border">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as 'models' | 'predict')}
              className={`flex items-center gap-2 px-4 py-3 text-sm font-medium transition-colors border-b-2 -mb-px ${
                activeTab === tab.id
                  ? 'border-primary text-primary'
                  : 'border-transparent text-slate-400 hover:text-white hover:border-slate-600'
              }`}
            >
              <tab.icon className="h-4 w-4" />
              {tab.label}
            </button>
          ))}
        </div>

        {activeTab === 'models' && (
          <div className="space-y-6">
            {/* Trained Models List */}
            <Card>
              <div className="p-6">
                <h2 className="text-xl font-semibold text-white mb-4 flex items-center gap-2">
                  <CheckCircle className="h-5 w-5 text-green-400" />
                  Trained Models
                </h2>
                {isLoading ? (
                  <p className="text-slate-400">Loading models...</p>
                ) : models && models.length > 0 ? (
                  <div className="overflow-x-auto">
                    <table className="min-w-full">
                      <thead>
                        <tr className="border-b border-dark-border">
                          <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">
                            Model Name
                          </th>
                          <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">
                            Version
                          </th>
                          <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">
                            Trained At
                          </th>
                          <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">
                            Status
                          </th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-dark-border">
                        {models.map((model) => (
                          <tr key={`${model.name}-${model.version}`} className="hover:bg-dark-bg/50">
                            <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-white">
                              {model.name.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}
                            </td>
                            <td className="px-6 py-4 whitespace-nowrap text-sm text-slate-300">
                              v{model.version}
                            </td>
                            <td className="px-6 py-4 whitespace-nowrap text-sm text-slate-300">
                              {new Date(model.trained_at).toLocaleString()}
                            </td>
                            <td className="px-6 py-4 whitespace-nowrap">
                              <Badge variant="success">{model.status}</Badge>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <div className="text-center py-8">
                    <AlertTriangle className="h-12 w-12 text-slate-500 mx-auto mb-3" />
                    <p className="text-slate-400">No models trained yet. Train your first model below!</p>
                  </div>
                )}
              </div>
            </Card>

            {/* Training Cards */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {/* Threat Classifier */}
              <Card>
                <div className="p-6">
                  <div className="flex items-center gap-3 mb-3">
                    <div className="p-2 bg-red-500/10 rounded-lg">
                      <Target className="h-6 w-6 text-red-400" />
                    </div>
                    <h3 className="text-lg font-semibold text-white">Threat Classifier</h3>
                  </div>
                  <p className="text-sm text-slate-400 mb-4">
                    Classifies threats based on severity, CVE presence, exploit availability, and affected hosts.
                  </p>
                  <Button
                    onClick={() => trainThreatClassifier.mutate()}
                    disabled={trainingModel === 'threat_classifier'}
                    className="w-full"
                  >
                    {trainingModel === 'threat_classifier' ? 'Training...' : 'Train Model'}
                  </Button>
                  {trainThreatClassifier.data && (
                    <div className="mt-4 p-3 bg-green-500/10 border border-green-500/20 rounded-lg text-sm">
                      <p className="font-semibold text-green-400">Training Complete!</p>
                      <p className="text-slate-300">Accuracy: {(trainThreatClassifier.data.metrics.accuracy * 100).toFixed(1)}%</p>
                      <p className="text-slate-300">Samples: {trainThreatClassifier.data.metrics.training_samples}</p>
                      <p className="text-slate-300">Time: {trainThreatClassifier.data.metrics.training_time_seconds.toFixed(2)}s</p>
                    </div>
                  )}
                </div>
              </Card>

              {/* Asset Fingerprinter */}
              <Card>
                <div className="p-6">
                  <div className="flex items-center gap-3 mb-3">
                    <div className="p-2 bg-blue-500/10 rounded-lg">
                      <Monitor className="h-6 w-6 text-blue-400" />
                    </div>
                    <h3 className="text-lg font-semibold text-white">Asset Fingerprinter</h3>
                  </div>
                  <p className="text-sm text-slate-400 mb-4">
                    ML-based OS and service detection with higher accuracy than signature-based methods.
                  </p>
                  <Button
                    onClick={() => trainAssetFingerprinter.mutate()}
                    disabled={trainingModel === 'asset_fingerprinter'}
                    className="w-full"
                  >
                    {trainingModel === 'asset_fingerprinter' ? 'Training...' : 'Train Model'}
                  </Button>
                  {trainAssetFingerprinter.data && (
                    <div className="mt-4 p-3 bg-green-500/10 border border-green-500/20 rounded-lg text-sm">
                      <p className="font-semibold text-green-400">Training Complete!</p>
                      <p className="text-slate-300">Accuracy: {(trainAssetFingerprinter.data.metrics.accuracy * 100).toFixed(1)}%</p>
                      <p className="text-slate-300">Samples: {trainAssetFingerprinter.data.metrics.training_samples}</p>
                      <p className="text-slate-300">Time: {trainAssetFingerprinter.data.metrics.training_time_seconds.toFixed(2)}s</p>
                    </div>
                  )}
                </div>
              </Card>

              {/* Attack Pattern Detector */}
              <Card>
                <div className="p-6">
                  <div className="flex items-center gap-3 mb-3">
                    <div className="p-2 bg-purple-500/10 rounded-lg">
                      <Search className="h-6 w-6 text-purple-400" />
                    </div>
                    <h3 className="text-lg font-semibold text-white">Attack Pattern Detector</h3>
                  </div>
                  <p className="text-sm text-slate-400 mb-4">
                    Detects attack patterns and maps them to MITRE ATT&CK framework techniques.
                  </p>
                  <Button
                    onClick={() => trainAttackDetector.mutate()}
                    disabled={trainingModel === 'attack_pattern_detector'}
                    className="w-full"
                  >
                    {trainingModel === 'attack_pattern_detector' ? 'Training...' : 'Train Model'}
                  </Button>
                  {trainAttackDetector.data && (
                    <div className="mt-4 p-3 bg-green-500/10 border border-green-500/20 rounded-lg text-sm">
                      <p className="font-semibold text-green-400">Training Complete!</p>
                      <p className="text-slate-300">Accuracy: {(trainAttackDetector.data.metrics.accuracy * 100).toFixed(1)}%</p>
                      <p className="text-slate-300">Samples: {trainAttackDetector.data.metrics.training_samples}</p>
                      <p className="text-slate-300">Time: {trainAttackDetector.data.metrics.training_time_seconds.toFixed(2)}s</p>
                    </div>
                  )}
                </div>
              </Card>

              {/* Remediation Time Predictor */}
              <Card>
                <div className="p-6">
                  <div className="flex items-center gap-3 mb-3">
                    <div className="p-2 bg-cyan-500/10 rounded-lg">
                      <Clock className="h-6 w-6 text-cyan-400" />
                    </div>
                    <h3 className="text-lg font-semibold text-white">Remediation Predictor</h3>
                  </div>
                  <p className="text-sm text-slate-400 mb-4">
                    Predicts how long vulnerabilities will take to remediate based on historical data.
                  </p>
                  <Button
                    onClick={() => trainRemediationPredictor.mutate()}
                    disabled={trainingModel === 'remediation_predictor'}
                    className="w-full"
                  >
                    {trainingModel === 'remediation_predictor' ? 'Training...' : 'Train Model'}
                  </Button>
                  {trainRemediationPredictor.data && (
                    <div className="mt-4 p-3 bg-green-500/10 border border-green-500/20 rounded-lg text-sm">
                      <p className="font-semibold text-green-400">Training Complete!</p>
                      <p className="text-slate-300">Samples: {trainRemediationPredictor.data.metrics.training_samples}</p>
                      <p className="text-slate-300">Time: {trainRemediationPredictor.data.metrics.training_time_seconds.toFixed(2)}s</p>
                    </div>
                  )}
                </div>
              </Card>
            </div>
          </div>
        )}

        {activeTab === 'predict' && (
          <div className="space-y-6">
            {/* Threat Level Prediction */}
            <Card>
              <div className="p-6">
                <div className="flex items-center gap-3 mb-4">
                  <div className="p-2 bg-red-500/10 rounded-lg">
                    <Target className="h-6 w-6 text-red-400" />
                  </div>
                  <h2 className="text-xl font-semibold text-white">Predict Threat Level</h2>
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
                  <div>
                    <label className="block text-sm font-medium text-slate-300 mb-2">
                      Severity Score (0.0 - 1.0)
                    </label>
                    <input
                      type="number"
                      min="0"
                      max="1"
                      step="0.1"
                      value={threatFeatures.severity_score}
                      onChange={(e) =>
                        setThreatFeatures({ ...threatFeatures, severity_score: parseFloat(e.target.value) })
                      }
                      className="w-full px-3 py-2 bg-dark-bg border border-dark-border rounded-md text-white focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent"
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-slate-300 mb-2">
                      Age (days)
                    </label>
                    <input
                      type="number"
                      min="0"
                      value={threatFeatures.age_days}
                      onChange={(e) =>
                        setThreatFeatures({ ...threatFeatures, age_days: parseInt(e.target.value) })
                      }
                      className="w-full px-3 py-2 bg-dark-bg border border-dark-border rounded-md text-white focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent"
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-slate-300 mb-2">
                      Affected Hosts
                    </label>
                    <input
                      type="number"
                      min="1"
                      value={threatFeatures.affected_hosts}
                      onChange={(e) =>
                        setThreatFeatures({ ...threatFeatures, affected_hosts: parseInt(e.target.value) })
                      }
                      className="w-full px-3 py-2 bg-dark-bg border border-dark-border rounded-md text-white focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent"
                    />
                  </div>

                  <div className="space-y-3 pt-6">
                    <label className="flex items-center gap-2 text-slate-300 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={threatFeatures.has_cve}
                        onChange={(e) => setThreatFeatures({ ...threatFeatures, has_cve: e.target.checked })}
                        className="w-4 h-4 rounded border-dark-border bg-dark-bg text-primary focus:ring-primary focus:ring-offset-dark-surface"
                      />
                      Has CVE
                    </label>
                    <label className="flex items-center gap-2 text-slate-300 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={threatFeatures.has_exploit}
                        onChange={(e) => setThreatFeatures({ ...threatFeatures, has_exploit: e.target.checked })}
                        className="w-4 h-4 rounded border-dark-border bg-dark-bg text-primary focus:ring-primary focus:ring-offset-dark-surface"
                      />
                      Exploit Available
                    </label>
                  </div>
                </div>

                <Button
                  onClick={() => predictThreat.mutate()}
                  disabled={predictThreat.isPending}
                >
                  {predictThreat.isPending ? 'Predicting...' : 'Predict Threat Level'}
                </Button>

                {threatPrediction && (
                  <div className="mt-4 p-4 bg-dark-bg border border-dark-border rounded-lg">
                    <h3 className="font-semibold text-white mb-3">Prediction Result</h3>
                    <div className="space-y-3">
                      <div className="flex items-center gap-2">
                        <span className="text-slate-400">Threat Level:</span>
                        {getSeverityBadge(threatPrediction.threat_level)}
                      </div>
                      <p className="text-slate-300">
                        <span className="text-slate-400">Confidence:</span> {(threatPrediction.confidence * 100).toFixed(1)}%
                      </p>
                      <p className="text-slate-300">
                        <span className="text-slate-400">Recommendation:</span> {threatPrediction.recommendation}
                      </p>
                      <div>
                        <span className="text-slate-400">Contributing Factors:</span>
                        <ul className="list-disc pl-5 text-sm text-slate-300 mt-1">
                          {threatPrediction.factors.map((factor, i) => (
                            <li key={i}>{factor}</li>
                          ))}
                        </ul>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            </Card>

            {/* Remediation Time Prediction */}
            <Card>
              <div className="p-6">
                <div className="flex items-center gap-3 mb-4">
                  <div className="p-2 bg-cyan-500/10 rounded-lg">
                    <Clock className="h-6 w-6 text-cyan-400" />
                  </div>
                  <h2 className="text-xl font-semibold text-white">Predict Remediation Time</h2>
                </div>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
                  <div>
                    <label className="block text-sm font-medium text-slate-300 mb-2">
                      Severity
                    </label>
                    <select
                      value={remediationFeatures.severity}
                      onChange={(e) =>
                        setRemediationFeatures({ ...remediationFeatures, severity: e.target.value })
                      }
                      className="w-full px-3 py-2 bg-dark-bg border border-dark-border rounded-md text-white focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent"
                    >
                      <option value="critical">Critical</option>
                      <option value="high">High</option>
                      <option value="medium">Medium</option>
                      <option value="low">Low</option>
                    </select>
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-slate-300 mb-2">
                      Complexity
                    </label>
                    <select
                      value={remediationFeatures.complexity}
                      onChange={(e) =>
                        setRemediationFeatures({ ...remediationFeatures, complexity: e.target.value })
                      }
                      className="w-full px-3 py-2 bg-dark-bg border border-dark-border rounded-md text-white focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent"
                    >
                      <option value="low">Low</option>
                      <option value="medium">Medium</option>
                      <option value="high">High</option>
                    </select>
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-slate-300 mb-2">
                      Team Size
                    </label>
                    <input
                      type="number"
                      min="1"
                      max="20"
                      value={remediationFeatures.team_size}
                      onChange={(e) =>
                        setRemediationFeatures({ ...remediationFeatures, team_size: parseInt(e.target.value) })
                      }
                      className="w-full px-3 py-2 bg-dark-bg border border-dark-border rounded-md text-white focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent"
                    />
                  </div>
                </div>

                <Button
                  onClick={() => predictRemediation.mutate()}
                  disabled={predictRemediation.isPending}
                >
                  {predictRemediation.isPending ? 'Predicting...' : 'Predict Remediation Time'}
                </Button>

                {remediationPrediction && (
                  <div className="mt-4 p-4 bg-dark-bg border border-dark-border rounded-lg">
                    <h3 className="font-semibold text-white mb-3">Prediction Result</h3>
                    <div className="space-y-3">
                      <p className="text-3xl font-bold text-primary">
                        {remediationPrediction.estimated_days.toFixed(1)} days
                      </p>
                      <p className="text-sm text-slate-400">
                        Based on historical remediation data and your team configuration
                      </p>
                      <div>
                        <span className="text-slate-400">Contributing Factors:</span>
                        <ul className="list-disc pl-5 text-sm text-slate-300 mt-1">
                          {remediationPrediction.factors.map((factor, i) => (
                            <li key={i}>{factor}</li>
                          ))}
                        </ul>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            </Card>
          </div>
        )}
      </div>
    </Layout>
  );
};

export default MlModelsPage;
