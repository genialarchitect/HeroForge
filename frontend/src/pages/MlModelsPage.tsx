import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { mlModelsAPI } from '../services/api';

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

  const getSeverityColor = (level: string) => {
    switch (level.toLowerCase()) {
      case 'critical':
        return 'text-red-700 bg-red-100';
      case 'high':
        return 'text-orange-700 bg-orange-100';
      case 'medium':
        return 'text-yellow-700 bg-yellow-100';
      case 'low':
        return 'text-blue-700 bg-blue-100';
      default:
        return 'text-gray-700 bg-gray-100';
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold text-gray-900">ML Model Management</h1>
        <p className="mt-2 text-gray-600">
          Train custom machine learning models on your security data for threat classification, asset fingerprinting, and more
        </p>
      </div>

      {/* Tab Navigation */}
      <div className="border-b border-gray-200">
        <nav className="-mb-px flex space-x-8">
          <button
            onClick={() => setActiveTab('models')}
            className={`${
              activeTab === 'models'
                ? 'border-indigo-500 text-indigo-600'
                : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
            } whitespace-nowrap pb-4 px-1 border-b-2 font-medium text-sm`}
          >
            Model Training
          </button>
          <button
            onClick={() => setActiveTab('predict')}
            className={`${
              activeTab === 'predict'
                ? 'border-indigo-500 text-indigo-600'
                : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
            } whitespace-nowrap pb-4 px-1 border-b-2 font-medium text-sm`}
          >
            Predictions
          </button>
        </nav>
      </div>

      {activeTab === 'models' && (
        <div className="space-y-6">
          {/* Trained Models List */}
          <div className="bg-white rounded-lg shadow p-6">
            <h2 className="text-xl font-semibold mb-4">Trained Models</h2>
            {isLoading ? (
              <p className="text-gray-500">Loading models...</p>
            ) : models && models.length > 0 ? (
              <div className="overflow-x-auto">
                <table className="min-w-full divide-y divide-gray-200">
                  <thead>
                    <tr>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Model Name
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Version
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Trained At
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Status
                      </th>
                    </tr>
                  </thead>
                  <tbody className="bg-white divide-y divide-gray-200">
                    {models.map((model) => (
                      <tr key={`${model.name}-${model.version}`}>
                        <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">
                          {model.name.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                          v{model.version}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                          {new Date(model.trained_at).toLocaleString()}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <span className="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-green-100 text-green-800">
                            {model.status}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <p className="text-gray-500">No models trained yet. Train your first model below!</p>
            )}
          </div>

          {/* Training Cards */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Threat Classifier */}
            <div className="bg-white rounded-lg shadow p-6">
              <h3 className="text-lg font-semibold mb-2">🎯 Threat Classifier</h3>
              <p className="text-sm text-gray-600 mb-4">
                Classifies threats based on severity, CVE presence, exploit availability, and affected hosts.
              </p>
              <button
                onClick={() => trainThreatClassifier.mutate()}
                disabled={trainingModel === 'threat_classifier'}
                className="w-full px-4 py-2 bg-indigo-600 text-white rounded-md hover:bg-indigo-700 disabled:bg-gray-300"
              >
                {trainingModel === 'threat_classifier' ? 'Training...' : 'Train Model'}
              </button>
              {trainThreatClassifier.data && (
                <div className="mt-4 p-3 bg-green-50 rounded text-sm">
                  <p className="font-semibold text-green-800">Training Complete!</p>
                  <p>Accuracy: {(trainThreatClassifier.data.metrics.accuracy * 100).toFixed(1)}%</p>
                  <p>Samples: {trainThreatClassifier.data.metrics.training_samples}</p>
                  <p>Time: {trainThreatClassifier.data.metrics.training_time_seconds.toFixed(2)}s</p>
                </div>
              )}
            </div>

            {/* Asset Fingerprinter */}
            <div className="bg-white rounded-lg shadow p-6">
              <h3 className="text-lg font-semibold mb-2">🖥️ Asset Fingerprinter</h3>
              <p className="text-sm text-gray-600 mb-4">
                ML-based OS and service detection with higher accuracy than signature-based methods.
              </p>
              <button
                onClick={() => trainAssetFingerprinter.mutate()}
                disabled={trainingModel === 'asset_fingerprinter'}
                className="w-full px-4 py-2 bg-indigo-600 text-white rounded-md hover:bg-indigo-700 disabled:bg-gray-300"
              >
                {trainingModel === 'asset_fingerprinter' ? 'Training...' : 'Train Model'}
              </button>
              {trainAssetFingerprinter.data && (
                <div className="mt-4 p-3 bg-green-50 rounded text-sm">
                  <p className="font-semibold text-green-800">Training Complete!</p>
                  <p>Accuracy: {(trainAssetFingerprinter.data.metrics.accuracy * 100).toFixed(1)}%</p>
                  <p>Samples: {trainAssetFingerprinter.data.metrics.training_samples}</p>
                  <p>Time: {trainAssetFingerprinter.data.metrics.training_time_seconds.toFixed(2)}s</p>
                </div>
              )}
            </div>

            {/* Attack Pattern Detector */}
            <div className="bg-white rounded-lg shadow p-6">
              <h3 className="text-lg font-semibold mb-2">🔍 Attack Pattern Detector</h3>
              <p className="text-sm text-gray-600 mb-4">
                Detects attack patterns and maps them to MITRE ATT&CK framework techniques.
              </p>
              <button
                onClick={() => trainAttackDetector.mutate()}
                disabled={trainingModel === 'attack_pattern_detector'}
                className="w-full px-4 py-2 bg-indigo-600 text-white rounded-md hover:bg-indigo-700 disabled:bg-gray-300"
              >
                {trainingModel === 'attack_pattern_detector' ? 'Training...' : 'Train Model'}
              </button>
              {trainAttackDetector.data && (
                <div className="mt-4 p-3 bg-green-50 rounded text-sm">
                  <p className="font-semibold text-green-800">Training Complete!</p>
                  <p>Accuracy: {(trainAttackDetector.data.metrics.accuracy * 100).toFixed(1)}%</p>
                  <p>Samples: {trainAttackDetector.data.metrics.training_samples}</p>
                  <p>Time: {trainAttackDetector.data.metrics.training_time_seconds.toFixed(2)}s</p>
                </div>
              )}
            </div>

            {/* Remediation Time Predictor */}
            <div className="bg-white rounded-lg shadow p-6">
              <h3 className="text-lg font-semibold mb-2">⏱️ Remediation Predictor</h3>
              <p className="text-sm text-gray-600 mb-4">
                Predicts how long vulnerabilities will take to remediate based on historical data.
              </p>
              <button
                onClick={() => trainRemediationPredictor.mutate()}
                disabled={trainingModel === 'remediation_predictor'}
                className="w-full px-4 py-2 bg-indigo-600 text-white rounded-md hover:bg-indigo-700 disabled:bg-gray-300"
              >
                {trainingModel === 'remediation_predictor' ? 'Training...' : 'Train Model'}
              </button>
              {trainRemediationPredictor.data && (
                <div className="mt-4 p-3 bg-green-50 rounded text-sm">
                  <p className="font-semibold text-green-800">Training Complete!</p>
                  <p>Samples: {trainRemediationPredictor.data.metrics.training_samples}</p>
                  <p>Time: {trainRemediationPredictor.data.metrics.training_time_seconds.toFixed(2)}s</p>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {activeTab === 'predict' && (
        <div className="space-y-6">
          {/* Threat Level Prediction */}
          <div className="bg-white rounded-lg shadow p-6">
            <h2 className="text-xl font-semibold mb-4">🎯 Predict Threat Level</h2>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
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
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-indigo-500"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Age (days)
                </label>
                <input
                  type="number"
                  min="0"
                  value={threatFeatures.age_days}
                  onChange={(e) =>
                    setThreatFeatures({ ...threatFeatures, age_days: parseInt(e.target.value) })
                  }
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-indigo-500"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Affected Hosts
                </label>
                <input
                  type="number"
                  min="1"
                  value={threatFeatures.affected_hosts}
                  onChange={(e) =>
                    setThreatFeatures({ ...threatFeatures, affected_hosts: parseInt(e.target.value) })
                  }
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-indigo-500"
                />
              </div>

              <div className="space-y-2">
                <label className="flex items-center">
                  <input
                    type="checkbox"
                    checked={threatFeatures.has_cve}
                    onChange={(e) => setThreatFeatures({ ...threatFeatures, has_cve: e.target.checked })}
                    className="mr-2"
                  />
                  Has CVE
                </label>
                <label className="flex items-center">
                  <input
                    type="checkbox"
                    checked={threatFeatures.has_exploit}
                    onChange={(e) => setThreatFeatures({ ...threatFeatures, has_exploit: e.target.checked })}
                    className="mr-2"
                  />
                  Exploit Available
                </label>
              </div>
            </div>

            <button
              onClick={() => predictThreat.mutate()}
              disabled={predictThreat.isPending}
              className="px-4 py-2 bg-indigo-600 text-white rounded-md hover:bg-indigo-700 disabled:bg-gray-300"
            >
              {predictThreat.isPending ? 'Predicting...' : 'Predict Threat Level'}
            </button>

            {threatPrediction && (
              <div className="mt-4 p-4 bg-gray-50 rounded-md">
                <h3 className="font-semibold mb-2">Prediction Result</h3>
                <div className="space-y-2">
                  <p>
                    <strong>Threat Level:</strong>{' '}
                    <span className={`px-2 py-1 rounded text-sm font-semibold ${getSeverityColor(threatPrediction.threat_level)}`}>
                      {threatPrediction.threat_level.toUpperCase()}
                    </span>
                  </p>
                  <p><strong>Confidence:</strong> {(threatPrediction.confidence * 100).toFixed(1)}%</p>
                  <p><strong>Recommendation:</strong> {threatPrediction.recommendation}</p>
                  <p><strong>Contributing Factors:</strong></p>
                  <ul className="list-disc pl-5 text-sm">
                    {threatPrediction.factors.map((factor, i) => (
                      <li key={i}>{factor}</li>
                    ))}
                  </ul>
                </div>
              </div>
            )}
          </div>

          {/* Remediation Time Prediction */}
          <div className="bg-white rounded-lg shadow p-6">
            <h2 className="text-xl font-semibold mb-4">⏱️ Predict Remediation Time</h2>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Severity
                </label>
                <select
                  value={remediationFeatures.severity}
                  onChange={(e) =>
                    setRemediationFeatures({ ...remediationFeatures, severity: e.target.value })
                  }
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-indigo-500"
                >
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                </select>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Complexity
                </label>
                <select
                  value={remediationFeatures.complexity}
                  onChange={(e) =>
                    setRemediationFeatures({ ...remediationFeatures, complexity: e.target.value })
                  }
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-indigo-500"
                >
                  <option value="low">Low</option>
                  <option value="medium">Medium</option>
                  <option value="high">High</option>
                </select>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
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
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-indigo-500"
                />
              </div>
            </div>

            <button
              onClick={() => predictRemediation.mutate()}
              disabled={predictRemediation.isPending}
              className="px-4 py-2 bg-indigo-600 text-white rounded-md hover:bg-indigo-700 disabled:bg-gray-300"
            >
              {predictRemediation.isPending ? 'Predicting...' : 'Predict Remediation Time'}
            </button>

            {remediationPrediction && (
              <div className="mt-4 p-4 bg-gray-50 rounded-md">
                <h3 className="font-semibold mb-2">Prediction Result</h3>
                <div className="space-y-2">
                  <p className="text-2xl font-bold text-indigo-600">
                    {remediationPrediction.estimated_days.toFixed(1)} days
                  </p>
                  <p className="text-sm text-gray-600">
                    Based on historical remediation data and your team configuration
                  </p>
                  <p><strong>Contributing Factors:</strong></p>
                  <ul className="list-disc pl-5 text-sm">
                    {remediationPrediction.factors.map((factor, i) => (
                      <li key={i}>{factor}</li>
                    ))}
                  </ul>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export default MlModelsPage;
