import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { toast } from 'react-toastify';
import {
  Brain,
  Sparkles,
  TrendingUp,
  AlertCircle,
  Activity,
  Target,
  Zap,
  BarChart3,
  Play,
  Pause,
  RefreshCw,
  Settings,
  CheckCircle,
  XCircle,
  Clock,
  Shield,
  Filter,
} from 'lucide-react';
import Layout from '../components/layout/Layout';
import Card from '../components/ui/Card';
import Button from '../components/ui/Button';
import Badge from '../components/ui/Badge';
import LoadingSpinner from '../components/ui/LoadingSpinner';
import { aiSecurityAPI } from '../services/api';

// Types
interface AIModel {
  id: string;
  name: string;
  type: 'alert_prioritization' | 'anomaly_detection' | 'false_positive_prediction';
  status: 'training' | 'ready' | 'failed';
  accuracy: number;
  last_trained: string;
  predictions_count: number;
}

interface PrioritizedAlert {
  id: string;
  title: string;
  description: string;
  severity: string;
  ml_score: number;
  confidence: number;
  factors: string[];
  created_at: string;
}

interface AnomalyDetection {
  id: string;
  entity_type: 'user' | 'host' | 'service';
  entity_id: string;
  anomaly_type: string;
  severity: string;
  score: number;
  detected_at: string;
  resolved: boolean;
}

interface ModelMetrics {
  total_alerts_processed: number;
  high_priority_detected: number;
  false_positives_prevented: number;
  anomalies_detected: number;
  average_confidence: number;
  model_accuracy: number;
}

const AiSecurityPage: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'overview' | 'alerts' | 'anomalies' | 'models'>('overview');
  const [selectedModel, setSelectedModel] = useState<string | null>(null);
  const queryClient = useQueryClient();

  // Fetch AI models
  const { data: models, isLoading: modelsLoading } = useQuery<AIModel[]>({
    queryKey: ['ai-models'],
    queryFn: async () => {
      // TODO: Replace with actual API endpoint
      return [
        {
          id: '1',
          name: 'Alert Priority Model',
          type: 'alert_prioritization',
          status: 'ready',
          accuracy: 94.2,
          last_trained: new Date().toISOString(),
          predictions_count: 1247,
        },
        {
          id: '2',
          name: 'Anomaly Detector',
          type: 'anomaly_detection',
          status: 'ready',
          accuracy: 89.5,
          last_trained: new Date().toISOString(),
          predictions_count: 832,
        },
        {
          id: '3',
          name: 'False Positive Predictor',
          type: 'false_positive_prediction',
          status: 'training',
          accuracy: 91.8,
          last_trained: new Date().toISOString(),
          predictions_count: 0,
        },
      ];
    },
  });

  // Fetch prioritized alerts
  const { data: prioritizedAlerts } = useQuery<PrioritizedAlert[]>({
    queryKey: ['prioritized-alerts'],
    queryFn: async () => {
      // TODO: Replace with actual API endpoint
      return [
        {
          id: '1',
          title: 'Critical SQL Injection Attempt',
          description: 'Multiple SQL injection attempts detected on admin panel',
          severity: 'critical',
          ml_score: 98.5,
          confidence: 0.96,
          factors: ['Multiple attempts', 'Admin endpoint', 'Known attack pattern'],
          created_at: new Date().toISOString(),
        },
        {
          id: '2',
          title: 'Unusual Data Exfiltration Pattern',
          description: 'Large data transfer to unknown IP address',
          severity: 'high',
          ml_score: 87.2,
          confidence: 0.89,
          factors: ['Unusual volume', 'Non-business hours', 'Unknown destination'],
          created_at: new Date().toISOString(),
        },
      ];
    },
  });

  // Fetch anomalies
  const { data: anomalies } = useQuery<AnomalyDetection[]>({
    queryKey: ['anomalies'],
    queryFn: async () => {
      // TODO: Replace with actual API endpoint
      return [
        {
          id: '1',
          entity_type: 'user',
          entity_id: 'user_123',
          anomaly_type: 'Unusual login time',
          severity: 'medium',
          score: 75.3,
          detected_at: new Date().toISOString(),
          resolved: false,
        },
        {
          id: '2',
          entity_type: 'host',
          entity_id: '192.168.1.50',
          anomaly_type: 'Spike in network traffic',
          severity: 'high',
          score: 89.1,
          detected_at: new Date().toISOString(),
          resolved: false,
        },
      ];
    },
  });

  // Fetch metrics
  const { data: metrics } = useQuery<ModelMetrics>({
    queryKey: ['ai-metrics'],
    queryFn: async () => {
      // TODO: Replace with actual API endpoint
      return {
        total_alerts_processed: 15420,
        high_priority_detected: 342,
        false_positives_prevented: 1823,
        anomalies_detected: 127,
        average_confidence: 0.91,
        model_accuracy: 93.2,
      };
    },
  });

  // Train model mutation
  const trainModelMutation = useMutation({
    mutationFn: async (modelId: string) => {
      // TODO: Replace with actual API endpoint
      await new Promise((resolve) => setTimeout(resolve, 2000));
      return { success: true };
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ai-models'] });
      toast.success('Model training started');
    },
    onError: () => {
      toast.error('Failed to start model training');
    },
  });

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical':
        return 'bg-red-500/20 text-red-400 border-red-500/30';
      case 'high':
        return 'bg-orange-500/20 text-orange-400 border-orange-500/30';
      case 'medium':
        return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
      case 'low':
        return 'bg-blue-500/20 text-blue-400 border-blue-500/30';
      default:
        return 'bg-slate-500/20 text-slate-400 border-slate-500/30';
    }
  };

  const getModelStatusIcon = (status: string) => {
    switch (status) {
      case 'ready':
        return <CheckCircle className="h-4 w-4 text-green-400" />;
      case 'training':
        return <RefreshCw className="h-4 w-4 text-blue-400 animate-spin" />;
      case 'failed':
        return <XCircle className="h-4 w-4 text-red-400" />;
      default:
        return <Clock className="h-4 w-4 text-slate-400" />;
    }
  };

  return (
    <Layout>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold text-white flex items-center gap-3">
              <Brain className="h-8 w-8 text-primary" />
              AI/ML Security Operations
            </h1>
            <p className="text-slate-400 mt-2">
              ML-based alert prioritization, anomaly detection, and intelligent security automation
            </p>
          </div>
          <Button variant="primary" onClick={() => queryClient.invalidateQueries()}>
            <RefreshCw className="h-4 w-4 mr-2" />
            Refresh Data
          </Button>
        </div>

        {/* Metrics Overview */}
        {metrics && (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-4">
            <Card className="bg-gradient-to-br from-blue-500/10 to-blue-600/10 border-blue-500/30">
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm text-slate-400">Alerts Processed</span>
                <Activity className="h-4 w-4 text-blue-400" />
              </div>
              <div className="text-2xl font-bold text-white">{metrics.total_alerts_processed.toLocaleString()}</div>
            </Card>

            <Card className="bg-gradient-to-br from-red-500/10 to-red-600/10 border-red-500/30">
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm text-slate-400">High Priority</span>
                <AlertCircle className="h-4 w-4 text-red-400" />
              </div>
              <div className="text-2xl font-bold text-white">{metrics.high_priority_detected.toLocaleString()}</div>
            </Card>

            <Card className="bg-gradient-to-br from-green-500/10 to-green-600/10 border-green-500/30">
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm text-slate-400">FP Prevented</span>
                <Shield className="h-4 w-4 text-green-400" />
              </div>
              <div className="text-2xl font-bold text-white">{metrics.false_positives_prevented.toLocaleString()}</div>
            </Card>

            <Card className="bg-gradient-to-br from-purple-500/10 to-purple-600/10 border-purple-500/30">
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm text-slate-400">Anomalies</span>
                <Target className="h-4 w-4 text-purple-400" />
              </div>
              <div className="text-2xl font-bold text-white">{metrics.anomalies_detected.toLocaleString()}</div>
            </Card>

            <Card className="bg-gradient-to-br from-cyan-500/10 to-cyan-600/10 border-cyan-500/30">
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm text-slate-400">Avg Confidence</span>
                <Zap className="h-4 w-4 text-cyan-400" />
              </div>
              <div className="text-2xl font-bold text-white">{(metrics.average_confidence * 100).toFixed(1)}%</div>
            </Card>

            <Card className="bg-gradient-to-br from-orange-500/10 to-orange-600/10 border-orange-500/30">
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm text-slate-400">Model Accuracy</span>
                <BarChart3 className="h-4 w-4 text-orange-400" />
              </div>
              <div className="text-2xl font-bold text-white">{metrics.model_accuracy.toFixed(1)}%</div>
            </Card>
          </div>
        )}

        {/* Tabs */}
        <div className="flex items-center gap-2 border-b border-dark-border">
          {[
            { id: 'overview' as const, label: 'Overview', icon: <BarChart3 className="h-4 w-4" /> },
            { id: 'alerts' as const, label: 'Prioritized Alerts', icon: <AlertCircle className="h-4 w-4" /> },
            { id: 'anomalies' as const, label: 'Anomalies', icon: <Target className="h-4 w-4" /> },
            { id: 'models' as const, label: 'ML Models', icon: <Brain className="h-4 w-4" /> },
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-2 px-4 py-3 font-medium transition-colors border-b-2 ${
                activeTab === tab.id
                  ? 'text-primary border-primary'
                  : 'text-slate-400 border-transparent hover:text-white hover:border-slate-600'
              }`}
            >
              {tab.icon}
              {tab.label}
            </button>
          ))}
        </div>

        {/* Tab Content */}
        {activeTab === 'overview' && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* AI Models Status */}
            <Card>
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold text-white flex items-center gap-2">
                  <Brain className="h-5 w-5 text-primary" />
                  Active AI Models
                </h3>
              </div>

              {modelsLoading ? (
                <div className="flex items-center justify-center py-8">
                  <LoadingSpinner />
                </div>
              ) : (
                <div className="space-y-3">
                  {models?.map((model) => (
                    <div key={model.id} className="flex items-center justify-between p-3 bg-dark-bg rounded-lg border border-dark-border">
                      <div className="flex items-center gap-3">
                        {getModelStatusIcon(model.status)}
                        <div>
                          <div className="font-medium text-white">{model.name}</div>
                          <div className="text-xs text-slate-400">{model.predictions_count.toLocaleString()} predictions</div>
                        </div>
                      </div>
                      <div className="text-right">
                        <div className="text-sm font-medium text-green-400">{model.accuracy.toFixed(1)}% accuracy</div>
                        <div className="text-xs text-slate-500">{model.status}</div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </Card>

            {/* Recent High-Priority Alerts */}
            <Card>
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold text-white flex items-center gap-2">
                  <AlertCircle className="h-5 w-5 text-red-400" />
                  High-Priority Alerts
                </h3>
                <Badge variant="danger">{prioritizedAlerts?.length || 0} active</Badge>
              </div>

              <div className="space-y-3">
                {prioritizedAlerts?.slice(0, 3).map((alert) => (
                  <div key={alert.id} className="p-3 bg-dark-bg rounded-lg border border-dark-border hover:border-primary transition-colors">
                    <div className="flex items-start justify-between mb-2">
                      <div className="font-medium text-white">{alert.title}</div>
                      <span className={`px-2 py-1 text-xs rounded border ${getSeverityColor(alert.severity)}`}>
                        {alert.severity}
                      </span>
                    </div>
                    <div className="text-sm text-slate-400 mb-2">{alert.description}</div>
                    <div className="flex items-center justify-between text-xs">
                      <div className="flex items-center gap-2 text-slate-500">
                        <Zap className="h-3 w-3 text-primary" />
                        ML Score: {alert.ml_score.toFixed(1)}
                      </div>
                      <div className="text-slate-500">{(alert.confidence * 100).toFixed(0)}% confident</div>
                    </div>
                  </div>
                ))}
              </div>
            </Card>
          </div>
        )}

        {activeTab === 'alerts' && (
          <Card>
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold text-white">ML-Prioritized Security Alerts</h3>
              <div className="flex items-center gap-2">
                <Button variant="secondary" size="sm">
                  <Filter className="h-4 w-4 mr-2" />
                  Filter
                </Button>
              </div>
            </div>

            <div className="space-y-3">
              {prioritizedAlerts?.map((alert) => (
                <div key={alert.id} className="p-4 bg-dark-bg rounded-lg border border-dark-border hover:border-primary transition-colors">
                  <div className="flex items-start justify-between mb-3">
                    <div>
                      <div className="font-medium text-white text-lg mb-1">{alert.title}</div>
                      <div className="text-sm text-slate-400">{alert.description}</div>
                    </div>
                    <span className={`px-3 py-1.5 text-sm font-medium rounded-lg border ${getSeverityColor(alert.severity)}`}>
                      {alert.severity}
                    </span>
                  </div>

                  <div className="flex items-center gap-4 text-sm">
                    <div className="flex items-center gap-2">
                      <Zap className="h-4 w-4 text-primary" />
                      <span className="text-slate-300">ML Score:</span>
                      <span className="font-medium text-white">{alert.ml_score.toFixed(1)}</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <TrendingUp className="h-4 w-4 text-blue-400" />
                      <span className="text-slate-300">Confidence:</span>
                      <span className="font-medium text-white">{(alert.confidence * 100).toFixed(0)}%</span>
                    </div>
                  </div>

                  <div className="mt-3 pt-3 border-t border-dark-border">
                    <div className="text-xs text-slate-500 mb-2">Contributing Factors:</div>
                    <div className="flex flex-wrap gap-2">
                      {alert.factors.map((factor, idx) => (
                        <span key={idx} className="px-2 py-1 text-xs bg-primary/20 text-primary rounded">
                          {factor}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </Card>
        )}

        {activeTab === 'anomalies' && (
          <Card>
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold text-white">Detected Anomalies</h3>
              <Badge variant="warning">{anomalies?.filter((a) => !a.resolved).length || 0} unresolved</Badge>
            </div>

            <div className="space-y-3">
              {anomalies?.map((anomaly) => (
                <div key={anomaly.id} className="p-4 bg-dark-bg rounded-lg border border-dark-border">
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-3">
                      <Target className="h-5 w-5 text-purple-400" />
                      <div>
                        <div className="font-medium text-white">{anomaly.anomaly_type}</div>
                        <div className="text-sm text-slate-400">
                          {anomaly.entity_type}: {anomaly.entity_id}
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className={`px-2 py-1 text-xs rounded border ${getSeverityColor(anomaly.severity)}`}>
                        {anomaly.severity}
                      </span>
                      {anomaly.resolved && (
                        <Badge variant="success">Resolved</Badge>
                      )}
                    </div>
                  </div>
                  <div className="flex items-center justify-between text-sm">
                    <div className="text-slate-500">
                      Anomaly Score: <span className="font-medium text-white">{anomaly.score.toFixed(1)}</span>
                    </div>
                    <div className="text-slate-500">{new Date(anomaly.detected_at).toLocaleString()}</div>
                  </div>
                </div>
              ))}
            </div>
          </Card>
        )}

        {activeTab === 'models' && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {models?.map((model) => (
              <Card key={model.id}>
                <div className="flex items-center justify-between mb-4">
                  <div className="flex items-center gap-3">
                    {getModelStatusIcon(model.status)}
                    <div>
                      <h3 className="text-lg font-semibold text-white">{model.name}</h3>
                      <p className="text-sm text-slate-400">{model.type.replace(/_/g, ' ')}</p>
                    </div>
                  </div>
                  <Button
                    variant={model.status === 'training' ? 'secondary' : 'primary'}
                    size="sm"
                    onClick={() => trainModelMutation.mutate(model.id)}
                    disabled={model.status === 'training'}
                    loading={trainModelMutation.isPending && selectedModel === model.id}
                  >
                    {model.status === 'training' ? (
                      <>
                        <Pause className="h-4 w-4 mr-2" />
                        Training...
                      </>
                    ) : (
                      <>
                        <Play className="h-4 w-4 mr-2" />
                        Retrain
                      </>
                    )}
                  </Button>
                </div>

                <div className="grid grid-cols-2 gap-4 mb-4">
                  <div className="p-3 bg-dark-bg rounded-lg border border-dark-border">
                    <div className="text-sm text-slate-400 mb-1">Accuracy</div>
                    <div className="text-2xl font-bold text-green-400">{model.accuracy.toFixed(1)}%</div>
                  </div>
                  <div className="p-3 bg-dark-bg rounded-lg border border-dark-border">
                    <div className="text-sm text-slate-400 mb-1">Predictions</div>
                    <div className="text-2xl font-bold text-primary">{model.predictions_count.toLocaleString()}</div>
                  </div>
                </div>

                <div className="text-sm text-slate-500">
                  Last trained: {new Date(model.last_trained).toLocaleString()}
                </div>
              </Card>
            ))}
          </div>
        )}
      </div>
    </Layout>
  );
};

export default AiSecurityPage;
