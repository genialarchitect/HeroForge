import React, { useState } from 'react';
import { useQuery, useMutation } from '@tanstack/react-query';
import { toast } from 'react-toastify';
import {
  FileText,
  Download,
  FileJson,
  FileCode,
  File,
  AlertTriangle,
  CheckCircle,
  Shield,
  Fingerprint,
  RefreshCw,
  ExternalLink,
} from 'lucide-react';
import Card from '../ui/Card';
import Button from '../ui/Button';
import Badge from '../ui/Badge';
import LoadingSpinner from '../ui/LoadingSpinner';
import {
  aiSecurityAPI,
  LLMSecurityReport,
  ModelFingerprint,
  LLMTarget,
} from '../../services/api';

// Flexible interface that works with both local TestRun and LLMTestRun
interface TestRunForReport {
  id: string;
  target_name: string;
  status: string;
  vulnerabilities_found: number;
  created_at?: string;
  started_at?: string;
}

interface ReportGenerationPanelProps {
  targets: LLMTarget[];
  testRuns: TestRunForReport[];
}

const ReportGenerationPanel: React.FC<ReportGenerationPanelProps> = ({ targets, testRuns }) => {
  const [selectedTestRun, setSelectedTestRun] = useState<string>('');
  const [selectedFormat, setSelectedFormat] = useState<'pdf' | 'html' | 'markdown' | 'json'>('pdf');
  const [includeRemediation, setIncludeRemediation] = useState(true);
  const [selectedTarget, setSelectedTarget] = useState<string>('');
  const [generatedReport, setGeneratedReport] = useState<LLMSecurityReport | null>(null);

  // Fetch fingerprint for selected target
  const { data: fingerprint, isLoading: fingerprintLoading, refetch: refetchFingerprint } = useQuery<ModelFingerprint>({
    queryKey: ['model-fingerprint', selectedTarget],
    queryFn: async () => {
      if (!selectedTarget) throw new Error('No target selected');
      const response = await aiSecurityAPI.getFingerprint(selectedTarget);
      return response.data;
    },
    enabled: !!selectedTarget,
    retry: false,
  });

  // Generate report mutation
  const generateReportMutation = useMutation({
    mutationFn: async (data: { testRunId: string; format: 'pdf' | 'html' | 'markdown' | 'json'; includeRemediation: boolean }) => {
      const response = await aiSecurityAPI.generateLLMReport(data.testRunId, {
        format: data.format,
        include_remediation: data.includeRemediation,
      });
      return response.data;
    },
    onSuccess: (report) => {
      setGeneratedReport(report);
      toast.success('Report generated successfully');
    },
    onError: () => {
      toast.error('Failed to generate report');
    },
  });

  // Fingerprint model mutation
  const fingerprintMutation = useMutation({
    mutationFn: async (targetId: string) => {
      const response = await aiSecurityAPI.fingerprintModel(targetId);
      return response.data;
    },
    onSuccess: () => {
      refetchFingerprint();
      toast.success('Model fingerprinted successfully');
    },
    onError: () => {
      toast.error('Failed to fingerprint model');
    },
  });

  // Download report
  const downloadMutation = useMutation({
    mutationFn: async (reportId: string) => {
      const response = await aiSecurityAPI.downloadLLMReport(reportId);
      return response.data;
    },
    onSuccess: (blob) => {
      const url = window.URL.createObjectURL(blob as Blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `llm-security-report.${selectedFormat}`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
      toast.success('Report downloaded');
    },
    onError: () => {
      toast.error('Failed to download report');
    },
  });

  const handleGenerateReport = () => {
    if (!selectedTestRun) {
      toast.error('Please select a test run');
      return;
    }
    generateReportMutation.mutate({
      testRunId: selectedTestRun,
      format: selectedFormat,
      includeRemediation,
    });
  };

  const getFormatIcon = (format: string) => {
    switch (format) {
      case 'pdf':
        return <File className="h-4 w-4" />;
      case 'html':
        return <FileCode className="h-4 w-4" />;
      case 'markdown':
        return <FileText className="h-4 w-4" />;
      case 'json':
        return <FileJson className="h-4 w-4" />;
      default:
        return <FileText className="h-4 w-4" />;
    }
  };

  const getRiskBadge = (riskLevel: string) => {
    const variants: Record<string, 'danger' | 'warning' | 'info' | 'success'> = {
      critical: 'danger',
      high: 'danger',
      medium: 'warning',
      low: 'info',
      minimal: 'success',
    };
    return variants[riskLevel.toLowerCase()] || 'info';
  };

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
      {/* Report Generation */}
      <div className="space-y-6">
        <Card>
          <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
            <FileText className="h-5 w-5 text-primary" />
            Generate Security Report
          </h3>

          <div className="space-y-4">
            {/* Test Run Selection */}
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-2">
                Select Test Run
              </label>
              <select
                value={selectedTestRun}
                onChange={(e) => setSelectedTestRun(e.target.value)}
                className="w-full px-3 py-2 bg-dark-bg border border-dark-border rounded-lg text-white focus:outline-none focus:border-primary"
              >
                <option value="">Choose a test run...</option>
                {testRuns.filter(r => r.status === 'completed').map((run) => (
                  <option key={run.id} value={run.id}>
                    {run.target_name} - {new Date(run.created_at || run.started_at || '').toLocaleString()}
                    {run.vulnerabilities_found > 0 && ` (${run.vulnerabilities_found} vulns)`}
                  </option>
                ))}
              </select>
            </div>

            {/* Format Selection */}
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-2">
                Report Format
              </label>
              <div className="grid grid-cols-4 gap-2">
                {(['pdf', 'html', 'markdown', 'json'] as const).map((format) => (
                  <button
                    key={format}
                    onClick={() => setSelectedFormat(format)}
                    className={`p-3 rounded-lg border transition-colors flex flex-col items-center gap-2 ${
                      selectedFormat === format
                        ? 'bg-primary/20 border-primary'
                        : 'bg-dark-bg border-dark-border hover:border-slate-600'
                    }`}
                  >
                    {getFormatIcon(format)}
                    <span className="text-xs text-white uppercase">{format}</span>
                  </button>
                ))}
              </div>
            </div>

            {/* Options */}
            <div className="flex items-center gap-2">
              <input
                type="checkbox"
                id="include_remediation"
                checked={includeRemediation}
                onChange={(e) => setIncludeRemediation(e.target.checked)}
                className="rounded"
              />
              <label htmlFor="include_remediation" className="text-sm text-slate-300">
                Include remediation guidance
              </label>
            </div>

            {/* Generate Button */}
            <Button
              variant="primary"
              className="w-full"
              onClick={handleGenerateReport}
              loading={generateReportMutation.isPending}
              disabled={!selectedTestRun}
            >
              <FileText className="h-4 w-4 mr-2" />
              Generate Report
            </Button>
          </div>

          {/* Generated Report Preview */}
          {generatedReport && (
            <div className="mt-6 pt-6 border-t border-dark-border">
              <h4 className="text-sm font-medium text-slate-300 mb-3">Generated Report</h4>

              <div className="p-4 bg-dark-bg rounded-lg border border-dark-border">
                <div className="flex items-center justify-between mb-4">
                  <div className="flex items-center gap-2">
                    {getFormatIcon(generatedReport.format)}
                    <span className="text-white font-medium">
                      LLM Security Report
                    </span>
                  </div>
                  <Badge variant={getRiskBadge(generatedReport.executive_summary.overall_risk_level)}>
                    {generatedReport.executive_summary.overall_risk_level} Risk
                  </Badge>
                </div>

                {/* Summary Stats */}
                <div className="grid grid-cols-4 gap-3 mb-4">
                  <div className="text-center p-2 bg-red-500/10 rounded">
                    <div className="text-lg font-bold text-red-400">
                      {generatedReport.executive_summary.critical_count}
                    </div>
                    <div className="text-xs text-slate-500">Critical</div>
                  </div>
                  <div className="text-center p-2 bg-orange-500/10 rounded">
                    <div className="text-lg font-bold text-orange-400">
                      {generatedReport.executive_summary.high_count}
                    </div>
                    <div className="text-xs text-slate-500">High</div>
                  </div>
                  <div className="text-center p-2 bg-yellow-500/10 rounded">
                    <div className="text-lg font-bold text-yellow-400">
                      {generatedReport.executive_summary.medium_count}
                    </div>
                    <div className="text-xs text-slate-500">Medium</div>
                  </div>
                  <div className="text-center p-2 bg-blue-500/10 rounded">
                    <div className="text-lg font-bold text-blue-400">
                      {generatedReport.executive_summary.low_count}
                    </div>
                    <div className="text-xs text-slate-500">Low</div>
                  </div>
                </div>

                {/* Key Findings */}
                {generatedReport.executive_summary.key_findings.length > 0 && (
                  <div className="mb-4">
                    <div className="text-xs text-slate-500 mb-2">Key Findings:</div>
                    <ul className="space-y-1">
                      {generatedReport.executive_summary.key_findings.slice(0, 3).map((finding, idx) => (
                        <li key={idx} className="text-sm text-slate-300 flex items-start gap-2">
                          <AlertTriangle className="h-3 w-3 text-yellow-400 mt-1 shrink-0" />
                          {finding}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {/* Download Button */}
                <Button
                  variant="secondary"
                  className="w-full"
                  onClick={() => downloadMutation.mutate(generatedReport.id)}
                  loading={downloadMutation.isPending}
                >
                  <Download className="h-4 w-4 mr-2" />
                  Download Report
                </Button>
              </div>
            </div>
          )}
        </Card>
      </div>

      {/* Model Fingerprinting */}
      <Card>
        <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
          <Fingerprint className="h-5 w-5 text-primary" />
          Model Fingerprinting
        </h3>

        <div className="space-y-4">
          {/* Target Selection */}
          <div>
            <label className="block text-sm font-medium text-slate-300 mb-2">
              Select Target to Fingerprint
            </label>
            <select
              value={selectedTarget}
              onChange={(e) => setSelectedTarget(e.target.value)}
              className="w-full px-3 py-2 bg-dark-bg border border-dark-border rounded-lg text-white focus:outline-none focus:border-primary"
            >
              <option value="">Choose a target...</option>
              {targets.map((target) => (
                <option key={target.id} value={target.id}>
                  {target.name} ({target.model_type})
                </option>
              ))}
            </select>
          </div>

          {/* Fingerprint Button */}
          <Button
            variant="primary"
            className="w-full"
            onClick={() => selectedTarget && fingerprintMutation.mutate(selectedTarget)}
            loading={fingerprintMutation.isPending}
            disabled={!selectedTarget}
          >
            <Fingerprint className="h-4 w-4 mr-2" />
            Analyze Model
          </Button>

          {/* Fingerprint Results */}
          {fingerprintLoading && selectedTarget && (
            <div className="flex items-center justify-center py-8">
              <LoadingSpinner />
            </div>
          )}

          {fingerprint && (
            <div className="mt-4 space-y-4">
              {/* Model Family */}
              <div className="p-4 bg-dark-bg rounded-lg border border-dark-border">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm text-slate-400">Detected Model Family</span>
                  <Badge variant="info">
                    {(fingerprint.confidence * 100).toFixed(0)}% confidence
                  </Badge>
                </div>
                <div className="text-2xl font-bold text-white">
                  {fingerprint.likely_model_family}
                </div>
                {fingerprint.estimated_context_window && (
                  <div className="text-sm text-slate-400 mt-1">
                    Est. Context Window: {fingerprint.estimated_context_window.toLocaleString()} tokens
                  </div>
                )}
              </div>

              {/* Indicators */}
              {fingerprint.indicators.length > 0 && (
                <div>
                  <div className="text-sm text-slate-400 mb-2">Detection Indicators</div>
                  <div className="flex flex-wrap gap-2">
                    {fingerprint.indicators.map((indicator, idx) => (
                      <Badge key={idx} variant="info" className="text-xs">
                        {indicator}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}

              {/* Safety Mechanisms */}
              {fingerprint.detected_safety_mechanisms.length > 0 && (
                <div>
                  <div className="text-sm text-slate-400 mb-2 flex items-center gap-2">
                    <Shield className="h-4 w-4" />
                    Detected Safety Mechanisms
                  </div>
                  <div className="space-y-1">
                    {fingerprint.detected_safety_mechanisms.map((mechanism, idx) => (
                      <div key={idx} className="flex items-center gap-2 text-sm text-slate-300">
                        <CheckCircle className="h-3 w-3 text-green-400" />
                        {mechanism}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Known Vulnerabilities */}
              {fingerprint.known_vulnerabilities.length > 0 && (
                <div>
                  <div className="text-sm text-slate-400 mb-2 flex items-center gap-2">
                    <AlertTriangle className="h-4 w-4 text-yellow-400" />
                    Known Vulnerabilities
                  </div>
                  <div className="space-y-1">
                    {fingerprint.known_vulnerabilities.map((vuln, idx) => (
                      <div key={idx} className="flex items-center gap-2 text-sm text-yellow-400">
                        <AlertTriangle className="h-3 w-3" />
                        {vuln}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Timestamp */}
              <div className="text-xs text-slate-500 pt-2 border-t border-dark-border">
                Fingerprinted: {new Date(fingerprint.fingerprinted_at).toLocaleString()}
              </div>
            </div>
          )}

          {!fingerprint && !fingerprintLoading && selectedTarget && (
            <div className="text-center py-8 text-slate-500">
              <Fingerprint className="h-12 w-12 mx-auto mb-4 opacity-50" />
              <p>No fingerprint data available</p>
              <p className="text-sm mt-1">Click "Analyze Model" to fingerprint this target</p>
            </div>
          )}
        </div>
      </Card>
    </div>
  );
};

export default ReportGenerationPanel;
