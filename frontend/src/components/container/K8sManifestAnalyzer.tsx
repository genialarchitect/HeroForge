import React, { useState } from 'react';
import { useMutation } from '@tanstack/react-query';
import {
  Layers,
  Upload,
  Play,
  AlertTriangle,
  AlertCircle,
  Info,
  CheckCircle,
  Shield,
  Network,
  Lock,
  Server,
} from 'lucide-react';
import { toast } from 'react-toastify';
import { containerAPI } from '../../services/api';
import { Button } from '../ui/Button';
import { Badge } from '../ui/Badge';
import type { K8sManifestAnalysis, K8sManifestIssue, ContainerFindingSeverity, ContainerFindingType } from '../../types';

const severityColors: Record<ContainerFindingSeverity, { bg: string; text: string; border: string }> = {
  critical: { bg: 'bg-red-500/20', text: 'text-red-400', border: 'border-red-500' },
  high: { bg: 'bg-orange-500/20', text: 'text-orange-400', border: 'border-orange-500' },
  medium: { bg: 'bg-yellow-500/20', text: 'text-yellow-400', border: 'border-yellow-500' },
  low: { bg: 'bg-blue-500/20', text: 'text-blue-400', border: 'border-blue-500' },
  info: { bg: 'bg-gray-500/20', text: 'text-gray-400', border: 'border-gray-500' },
};

const findingTypeIcons: Partial<Record<ContainerFindingType, React.ReactNode>> = {
  pod_security: <Shield className="w-4 h-4" />,
  rbac: <Lock className="w-4 h-4" />,
  network_policy: <Network className="w-4 h-4" />,
  resource_limits: <Server className="w-4 h-4" />,
  misconfiguration: <AlertTriangle className="w-4 h-4" />,
};

const exampleManifest = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: vulnerable-app
  namespace: default
spec:
  replicas: 1
  selector:
    matchLabels:
      app: vulnerable-app
  template:
    metadata:
      labels:
        app: vulnerable-app
    spec:
      containers:
      - name: app
        image: myapp:latest
        securityContext:
          privileged: true
          runAsRoot: true
        ports:
        - containerPort: 8080
---
apiVersion: v1
kind: Service
metadata:
  name: vulnerable-app-svc
spec:
  type: LoadBalancer
  selector:
    app: vulnerable-app
  ports:
  - port: 80
    targetPort: 8080
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: app-admin
subjects:
- kind: ServiceAccount
  name: default
  namespace: default
roleRef:
  kind: ClusterRole
  name: cluster-admin
  apiGroup: rbac.authorization.k8s.io
`;

export function K8sManifestAnalyzer() {
  const [content, setContent] = useState('');
  const [filename, setFilename] = useState('manifest.yaml');
  const [analysis, setAnalysis] = useState<K8sManifestAnalysis | null>(null);
  const [groupByType, setGroupByType] = useState(true);

  const analyzeMutation = useMutation({
    mutationFn: () => containerAPI.analyzeManifest({ content, filename }).then((res) => res.data),
    onSuccess: (data) => {
      setAnalysis(data);
      if (data.issues.length === 0) {
        toast.success('No security issues found!');
      } else {
        toast.info(`Found ${data.issues.length} security issue(s)`);
      }
    },
    onError: () => {
      toast.error('Failed to analyze manifest');
    },
  });

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      setFilename(file.name);
      const reader = new FileReader();
      reader.onload = (event) => {
        setContent(event.target?.result as string);
      };
      reader.readAsText(file);
    }
  };

  const handleLoadExample = () => {
    setContent(exampleManifest);
    setFilename('vulnerable-deployment.yaml');
    setAnalysis(null);
  };

  const getSeverityIcon = (severity: ContainerFindingSeverity) => {
    switch (severity) {
      case 'critical':
        return <AlertCircle className="w-5 h-5" />;
      case 'high':
        return <AlertTriangle className="w-5 h-5" />;
      case 'medium':
        return <AlertTriangle className="w-5 h-5" />;
      case 'low':
        return <Info className="w-5 h-5" />;
      case 'info':
        return <Info className="w-5 h-5" />;
    }
  };

  const getScoreColor = (score: number) => {
    if (score >= 80) return 'text-green-400';
    if (score >= 60) return 'text-yellow-400';
    if (score >= 40) return 'text-orange-400';
    return 'text-red-400';
  };

  const getScoreGrade = (score: number) => {
    if (score >= 90) return 'A';
    if (score >= 80) return 'B';
    if (score >= 70) return 'C';
    if (score >= 60) return 'D';
    return 'F';
  };

  // Group issues by finding type for better organization
  const groupedIssues = analysis?.issues.reduce((acc, issue) => {
    const type = issue.finding_type;
    if (!acc[type]) {
      acc[type] = [];
    }
    acc[type].push(issue);
    return acc;
  }, {} as Record<string, K8sManifestIssue[]>) || {};

  return (
    <div className="space-y-6">
      {/* Input Section */}
      <div className="bg-gray-800 rounded-lg border border-gray-700 p-6">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold text-white flex items-center gap-2">
            <Layers className="w-5 h-5 text-purple-400" />
            Kubernetes Manifest Analyzer
          </h2>
          <div className="flex items-center gap-2">
            <Button variant="ghost" size="sm" onClick={handleLoadExample}>
              Load Example
            </Button>
            <label className="cursor-pointer">
              <input
                type="file"
                accept=".yaml,.yml,.json"
                onChange={handleFileUpload}
                className="hidden"
              />
              <span className="flex items-center gap-2 px-3 py-1.5 text-sm bg-gray-700 hover:bg-gray-600 rounded-lg text-gray-200 transition-colors">
                <Upload className="w-4 h-4" />
                Upload
              </span>
            </label>
          </div>
        </div>

        <div className="mb-4">
          <label className="block text-sm text-gray-400 mb-2">
            Paste your Kubernetes manifest (YAML or JSON):
          </label>
          <textarea
            value={content}
            onChange={(e) => setContent(e.target.value)}
            placeholder="apiVersion: apps/v1&#10;kind: Deployment&#10;metadata:&#10;  name: my-app&#10;spec:&#10;  replicas: 3&#10;  ..."
            className="w-full h-64 bg-gray-900 border border-gray-700 rounded-lg p-4 font-mono text-sm text-gray-200 placeholder-gray-600 focus:outline-none focus:border-purple-500 resize-none"
          />
        </div>

        <div className="flex items-center justify-between">
          <span className="text-sm text-gray-400">
            {filename && `File: ${filename}`}
          </span>
          <Button
            onClick={() => analyzeMutation.mutate()}
            disabled={!content.trim() || analyzeMutation.isPending}
            className="bg-purple-600 hover:bg-purple-700"
          >
            <Play className="w-4 h-4 mr-2" />
            {analyzeMutation.isPending ? 'Analyzing...' : 'Analyze Manifest'}
          </Button>
        </div>
      </div>

      {/* Results Section */}
      {analysis && (
        <div className="space-y-6">
          {/* Score Cards */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="bg-gray-800 rounded-lg border border-gray-700 p-6">
              <div className="flex items-center justify-between">
                <div>
                  <div className="text-sm text-gray-400 mb-1">Security Score</div>
                  <div className={`text-3xl font-bold ${getScoreColor(analysis.security_score)}`}>
                    {analysis.security_score}/100
                  </div>
                </div>
                <div className={`text-4xl font-bold ${getScoreColor(analysis.security_score)}`}>
                  {getScoreGrade(analysis.security_score)}
                </div>
              </div>
            </div>

            <div className="bg-gray-800 rounded-lg border border-gray-700 p-6">
              <div className="text-sm text-gray-400 mb-1">Resources Analyzed</div>
              <div className="text-3xl font-bold text-white">
                {analysis.resources_analyzed}
              </div>
            </div>

            <div className="bg-gray-800 rounded-lg border border-gray-700 p-6">
              <div className="text-sm text-gray-400 mb-1">Issues Found</div>
              <div className={`text-3xl font-bold ${analysis.issues.length > 0 ? 'text-yellow-400' : 'text-green-400'}`}>
                {analysis.issues.length}
              </div>
            </div>
          </div>

          {/* Resource Type Breakdown */}
          {Object.keys(analysis.by_resource_type).length > 0 && (
            <div className="bg-gray-800 rounded-lg border border-gray-700 p-6">
              <h3 className="text-lg font-semibold text-white mb-4">Resource Types Analyzed</h3>
              <div className="flex flex-wrap gap-2">
                {Object.entries(analysis.by_resource_type).map(([type, count]) => (
                  <Badge key={type} className="bg-purple-500/20 text-purple-400 px-3 py-1">
                    {type}: {count}
                  </Badge>
                ))}
              </div>
            </div>
          )}

          {/* Issues List */}
          <div className="bg-gray-800 rounded-lg border border-gray-700">
            <div className="p-4 border-b border-gray-700 flex items-center justify-between">
              <h3 className="text-lg font-semibold text-white flex items-center gap-2">
                {analysis.issues.length === 0 ? (
                  <>
                    <CheckCircle className="w-5 h-5 text-green-400" />
                    No Security Issues Found
                  </>
                ) : (
                  <>
                    <AlertTriangle className="w-5 h-5 text-yellow-400" />
                    Security Issues ({analysis.issues.length})
                  </>
                )}
              </h3>
              {analysis.issues.length > 0 && (
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => setGroupByType(!groupByType)}
                >
                  {groupByType ? 'Show All' : 'Group by Type'}
                </Button>
              )}
            </div>

            {analysis.issues.length === 0 ? (
              <div className="p-8 text-center">
                <CheckCircle className="w-12 h-12 text-green-400 mx-auto mb-4" />
                <p className="text-gray-300">Your Kubernetes manifests follow security best practices!</p>
              </div>
            ) : groupByType ? (
              // Grouped view
              <div className="divide-y divide-gray-700">
                {Object.entries(groupedIssues).map(([type, issues]) => (
                  <div key={type} className="p-4">
                    <div className="flex items-center gap-2 mb-4">
                      <span className="text-purple-400">
                        {findingTypeIcons[type as ContainerFindingType] || <AlertTriangle className="w-4 h-4" />}
                      </span>
                      <h4 className="font-medium text-gray-200 capitalize">
                        {type.replace('_', ' ')} Issues ({issues.length})
                      </h4>
                    </div>
                    <div className="space-y-3 ml-6">
                      {issues.map((issue, index) => (
                        <IssueCard key={index} issue={issue} getSeverityIcon={getSeverityIcon} />
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              // Flat view
              <div className="divide-y divide-gray-700">
                {analysis.issues.map((issue, index) => (
                  <div key={index} className="p-4">
                    <IssueCard issue={issue} getSeverityIcon={getSeverityIcon} />
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

interface IssueCardProps {
  issue: K8sManifestIssue;
  getSeverityIcon: (severity: ContainerFindingSeverity) => React.ReactNode;
}

function IssueCard({ issue, getSeverityIcon }: IssueCardProps) {
  return (
    <div className="bg-gray-900/50 rounded-lg p-4">
      <div className="flex items-start gap-3">
        <div className={severityColors[issue.severity].text}>
          {getSeverityIcon(issue.severity)}
        </div>
        <div className="flex-1">
          <div className="flex items-center gap-2 mb-1 flex-wrap">
            <h4 className="font-medium text-gray-200">{issue.title}</h4>
            <Badge className={`${severityColors[issue.severity].bg} ${severityColors[issue.severity].text}`}>
              {issue.severity}
            </Badge>
          </div>

          <div className="flex items-center gap-2 mb-2 text-sm">
            <Badge className="bg-gray-700 text-gray-300">
              {issue.resource_type}
            </Badge>
            <span className="text-gray-400">{issue.resource_name}</span>
          </div>

          <p className="text-sm text-gray-400 mb-3">{issue.description}</p>

          <div className="bg-green-500/10 border border-green-500/30 rounded p-3">
            <span className="text-xs text-green-500 uppercase block mb-1">Remediation:</span>
            <p className="text-sm text-green-300">{issue.remediation}</p>
          </div>

          {issue.references && issue.references.length > 0 && (
            <div className="mt-3">
              <span className="text-xs text-gray-500 uppercase">References:</span>
              <div className="flex flex-wrap gap-2 mt-1">
                {issue.references.map((ref, refIndex) => (
                  <a
                    key={refIndex}
                    href={ref}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-xs text-cyan-400 hover:text-cyan-300"
                  >
                    {ref}
                  </a>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
