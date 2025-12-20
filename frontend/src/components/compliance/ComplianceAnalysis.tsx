import React, { useState, useEffect } from 'react';
import { toast } from 'react-toastify';
import { complianceAPI } from '../../services/api';
import type {
  ComplianceFramework,
  ComplianceAnalyzeResponse,
  FrameworkSummary,
  ComplianceFrameworkId,
} from '../../types';
import Card from '../ui/Card';
import Badge from '../ui/Badge';
import LoadingSpinner from '../ui/LoadingSpinner';
import Button from '../ui/Button';
import Checkbox from '../ui/Checkbox';
import {
  Shield,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  ChevronDown,
  ChevronRight,
  ClipboardCheck,
  RefreshCw,
  FileDown,
} from 'lucide-react';

interface ComplianceAnalysisProps {
  scanId: string;
  scanName: string;
  onClose: () => void;
}

const ComplianceAnalysis: React.FC<ComplianceAnalysisProps> = ({
  scanId,
  scanName,
  onClose,
}) => {
  const [frameworks, setFrameworks] = useState<ComplianceFramework[]>([]);
  const [selectedFrameworks, setSelectedFrameworks] = useState<Set<string>>(new Set());
  const [loading, setLoading] = useState(false);
  const [analyzing, setAnalyzing] = useState(false);
  const [results, setResults] = useState<ComplianceAnalyzeResponse | null>(null);
  const [expandedFramework, setExpandedFramework] = useState<string | null>(null);
  const [generatingReport, setGeneratingReport] = useState(false);
  const [reportFormat, setReportFormat] = useState<'pdf' | 'html' | 'json'>('pdf');

  useEffect(() => {
    loadFrameworks();
  }, []);

  const loadFrameworks = async () => {
    setLoading(true);
    try {
      const response = await complianceAPI.getFrameworks();
      setFrameworks(response.data.frameworks);
      // Select common frameworks by default
      setSelectedFrameworks(new Set(['pci_dss', 'nist_800_53', 'owasp_top10']));
    } catch (error) {
      toast.error('Failed to load compliance frameworks');
    } finally {
      setLoading(false);
    }
  };

  const runAnalysis = async () => {
    if (selectedFrameworks.size === 0) {
      toast.warning('Please select at least one framework');
      return;
    }

    setAnalyzing(true);
    try {
      const response = await complianceAPI.analyzeScan(scanId, {
        frameworks: Array.from(selectedFrameworks) as ComplianceFrameworkId[],
      });
      setResults(response.data);
      toast.success('Compliance analysis completed');
    } catch (error: unknown) {
      const axiosError = error as { response?: { data?: { error?: string } } };
      toast.error(axiosError.response?.data?.error || 'Analysis failed');
    } finally {
      setAnalyzing(false);
    }
  };

  const toggleFramework = (id: string) => {
    const newSelected = new Set(selectedFrameworks);
    if (newSelected.has(id)) {
      newSelected.delete(id);
    } else {
      newSelected.add(id);
    }
    setSelectedFrameworks(newSelected);
  };

  const getScoreColor = (score: number): string => {
    if (score >= 80) return 'text-green-400';
    if (score >= 60) return 'text-yellow-400';
    if (score >= 40) return 'text-orange-400';
    return 'text-red-400';
  };

  const getScoreBadge = (score: number): 'completed' | 'running' | 'failed' => {
    if (score >= 80) return 'completed';
    if (score >= 60) return 'running';
    return 'failed';
  };

  const generateReport = async () => {
    if (!results) return;

    setGeneratingReport(true);
    try {
      // Extract framework IDs from results
      const frameworkIds = results.summary.frameworks.map((fw) =>
        // Convert framework enum to ID format
        String(fw.framework).toLowerCase().replace(/_/g, '_')
      );

      const response = await complianceAPI.generateReport(scanId, {
        frameworks: frameworkIds,
        format: reportFormat,
        include_evidence: true,
      });

      // Download the report
      const downloadResponse = await complianceAPI.downloadReport(response.data.report_id);

      // Create blob URL and trigger download
      const blob = new Blob([downloadResponse.data], {
        type:
          reportFormat === 'pdf'
            ? 'application/pdf'
            : reportFormat === 'html'
            ? 'text/html'
            : 'application/json',
      });
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `compliance_report_${scanId}.${reportFormat}`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      window.URL.revokeObjectURL(url);

      toast.success(`${reportFormat.toUpperCase()} report generated and downloaded successfully`);
    } catch (error: unknown) {
      const axiosError = error as { response?: { data?: { error?: string } } };
      toast.error(axiosError.response?.data?.error || 'Failed to generate report');
    } finally {
      setGeneratingReport(false);
    }
  };

  if (loading) {
    return (
      <div className="fixed inset-0 bg-black/60 z-50 flex items-center justify-center">
        <Card className="w-full max-w-4xl max-h-[90vh] overflow-y-auto">
          <div className="flex items-center justify-center py-12">
            <LoadingSpinner />
          </div>
        </Card>
      </div>
    );
  }

  return (
    <div className="fixed inset-0 bg-black/60 z-50 flex items-center justify-center p-4">
      <Card className="w-full max-w-4xl max-h-[90vh] overflow-y-auto">
        {/* Header */}
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-3">
            <Shield className="h-6 w-6 text-primary" />
            <div>
              <h2 className="text-xl font-bold text-white">Compliance Analysis</h2>
              <p className="text-sm text-slate-400">Scan: {scanName}</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-white transition-colors"
          >
            <XCircle className="h-6 w-6" />
          </button>
        </div>

        {!results ? (
          <>
            {/* Framework Selection */}
            <div className="mb-6">
              <h3 className="text-lg font-semibold text-white mb-4">
                Select Compliance Frameworks
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {frameworks.map((framework) => (
                  <div
                    key={framework.id}
                    onClick={() => toggleFramework(framework.id)}
                    className={`p-4 rounded-lg border cursor-pointer transition-all ${
                      selectedFrameworks.has(framework.id)
                        ? 'border-primary bg-primary/10'
                        : 'border-dark-border hover:border-primary/50'
                    }`}
                  >
                    <div className="flex items-start gap-3">
                      <Checkbox
                        checked={selectedFrameworks.has(framework.id)}
                        onChange={() => toggleFramework(framework.id)}
                      />
                      <div className="flex-1">
                        <div className="flex items-center justify-between">
                          <p className="font-medium text-white">{framework.name}</p>
                          <Badge variant="status" type="running">
                            v{framework.version}
                          </Badge>
                        </div>
                        <p className="text-sm text-slate-400 mt-1">
                          {framework.description}
                        </p>
                        <div className="flex items-center gap-4 mt-2 text-xs text-slate-500">
                          <span>{framework.control_count} controls</span>
                          <span>{framework.automated_percentage.toFixed(0)}% automated</span>
                        </div>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Action Buttons */}
            <div className="flex justify-end gap-3">
              <Button variant="secondary" onClick={onClose}>
                Cancel
              </Button>
              <Button
                onClick={runAnalysis}
                disabled={analyzing || selectedFrameworks.size === 0}
              >
                {analyzing ? (
                  <>
                    <RefreshCw className="h-4 w-4 animate-spin mr-2" />
                    Analyzing...
                  </>
                ) : (
                  <>
                    <ClipboardCheck className="h-4 w-4 mr-2" />
                    Run Analysis
                  </>
                )}
              </Button>
            </div>
          </>
        ) : (
          <>
            {/* Results Summary */}
            <div className="mb-6 p-4 bg-dark-bg rounded-lg border border-dark-border">
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-center">
                <div>
                  <p className={`text-3xl font-bold ${getScoreColor(results.summary.overall_score)}`}>
                    {results.summary.overall_score.toFixed(0)}%
                  </p>
                  <p className="text-sm text-slate-400">Overall Score</p>
                </div>
                <div>
                  <p className="text-3xl font-bold text-white">
                    {results.summary.total_findings}
                  </p>
                  <p className="text-sm text-slate-400">Total Findings</p>
                </div>
                <div>
                  <p className="text-3xl font-bold text-red-400">
                    {results.summary.critical_findings + results.summary.high_findings}
                  </p>
                  <p className="text-sm text-slate-400">Critical/High</p>
                </div>
                <div>
                  <p className="text-3xl font-bold text-yellow-400">
                    {results.summary.medium_findings + results.summary.low_findings}
                  </p>
                  <p className="text-sm text-slate-400">Medium/Low</p>
                </div>
              </div>
            </div>

            {/* Framework Results */}
            <div className="space-y-4">
              <h3 className="text-lg font-semibold text-white">
                Framework Results
              </h3>
              {results.summary.frameworks.map((fw: FrameworkSummary) => (
                <div
                  key={fw.framework}
                  className="border border-dark-border rounded-lg overflow-hidden"
                >
                  <div
                    onClick={() =>
                      setExpandedFramework(
                        expandedFramework === fw.framework ? null : fw.framework
                      )
                    }
                    className="flex items-center justify-between p-4 bg-dark-surface cursor-pointer hover:bg-dark-hover transition-colors"
                  >
                    <div className="flex items-center gap-3">
                      {expandedFramework === fw.framework ? (
                        <ChevronDown className="h-5 w-5 text-slate-400" />
                      ) : (
                        <ChevronRight className="h-5 w-5 text-slate-400" />
                      )}
                      <span className="font-medium text-white">{fw.framework}</span>
                    </div>
                    <div className="flex items-center gap-4">
                      <div className="flex items-center gap-2 text-sm">
                        <CheckCircle2 className="h-4 w-4 text-green-400" />
                        <span className="text-green-400">{fw.compliant}</span>
                      </div>
                      <div className="flex items-center gap-2 text-sm">
                        <XCircle className="h-4 w-4 text-red-400" />
                        <span className="text-red-400">{fw.non_compliant}</span>
                      </div>
                      <div className="flex items-center gap-2 text-sm">
                        <AlertTriangle className="h-4 w-4 text-yellow-400" />
                        <span className="text-yellow-400">{fw.partially_compliant}</span>
                      </div>
                      <Badge variant="status" type={getScoreBadge(fw.compliance_score)}>
                        {fw.compliance_score.toFixed(0)}%
                      </Badge>
                    </div>
                  </div>

                  {expandedFramework === fw.framework && (
                    <div className="p-4 bg-dark-bg border-t border-dark-border">
                      <div className="grid grid-cols-2 md:grid-cols-3 gap-4 mb-4 text-sm">
                        <div className="p-3 bg-dark-surface rounded-lg">
                          <p className="text-slate-400">Total Controls</p>
                          <p className="text-xl font-bold text-white">{fw.total_controls}</p>
                        </div>
                        <div className="p-3 bg-dark-surface rounded-lg">
                          <p className="text-slate-400">Compliant</p>
                          <p className="text-xl font-bold text-green-400">{fw.compliant}</p>
                        </div>
                        <div className="p-3 bg-dark-surface rounded-lg">
                          <p className="text-slate-400">Non-Compliant</p>
                          <p className="text-xl font-bold text-red-400">{fw.non_compliant}</p>
                        </div>
                        <div className="p-3 bg-dark-surface rounded-lg">
                          <p className="text-slate-400">Partially Compliant</p>
                          <p className="text-xl font-bold text-yellow-400">{fw.partially_compliant}</p>
                        </div>
                        <div className="p-3 bg-dark-surface rounded-lg">
                          <p className="text-slate-400">Not Applicable</p>
                          <p className="text-xl font-bold text-slate-400">{fw.not_applicable}</p>
                        </div>
                        <div className="p-3 bg-dark-surface rounded-lg">
                          <p className="text-slate-400">Not Assessed</p>
                          <p className="text-xl font-bold text-slate-500">{fw.not_assessed}</p>
                        </div>
                      </div>

                      {/* Category Breakdown */}
                      {fw.by_category && fw.by_category.length > 0 && (
                        <div>
                          <p className="text-sm font-medium text-slate-300 mb-2">
                            By Category
                          </p>
                          <div className="space-y-2">
                            {fw.by_category.map((cat) => (
                              <div
                                key={cat.category}
                                className="flex items-center justify-between p-2 bg-dark-surface rounded"
                              >
                                <span className="text-sm text-white">{cat.category}</span>
                                <div className="flex items-center gap-4">
                                  <span className="text-xs text-slate-400">
                                    {cat.compliant}/{cat.total} compliant
                                  </span>
                                  <div className="w-24 bg-dark-border rounded-full h-2">
                                    <div
                                      className={`h-2 rounded-full ${
                                        cat.percentage >= 80
                                          ? 'bg-green-500'
                                          : cat.percentage >= 60
                                          ? 'bg-yellow-500'
                                          : 'bg-red-500'
                                      }`}
                                      style={{ width: `${cat.percentage}%` }}
                                    />
                                  </div>
                                  <span className="text-xs text-slate-300 w-12 text-right">
                                    {cat.percentage.toFixed(0)}%
                                  </span>
                                </div>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              ))}
            </div>

            {/* Report Generation */}
            <div className="mt-6 pt-4 border-t border-dark-border">
              <h3 className="text-lg font-semibold text-white mb-4">
                Generate Compliance Report
              </h3>
              <div className="flex items-center gap-4">
                <div className="flex gap-2">
                  {(['pdf', 'html', 'json'] as const).map((format) => (
                    <button
                      key={format}
                      onClick={() => setReportFormat(format)}
                      className={`px-4 py-2 rounded-lg font-medium transition-colors ${
                        reportFormat === format
                          ? 'bg-primary text-white'
                          : 'bg-dark-surface text-slate-400 hover:bg-dark-hover'
                      }`}
                    >
                      {format.toUpperCase()}
                    </button>
                  ))}
                </div>
                <Button
                  onClick={generateReport}
                  disabled={generatingReport}
                  className="ml-auto"
                >
                  {generatingReport ? (
                    <>
                      <RefreshCw className="h-4 w-4 animate-spin mr-2" />
                      Generating...
                    </>
                  ) : (
                    <>
                      <FileDown className="h-4 w-4 mr-2" />
                      Generate Report
                    </>
                  )}
                </Button>
              </div>
            </div>

            {/* Action Buttons */}
            <div className="flex justify-end gap-3 mt-6 pt-4 border-t border-dark-border">
              <Button
                variant="secondary"
                onClick={() => setResults(null)}
              >
                <RefreshCw className="h-4 w-4 mr-2" />
                Run New Analysis
              </Button>
              <Button onClick={onClose}>Close</Button>
            </div>
          </>
        )}
      </Card>
    </div>
  );
};

export default ComplianceAnalysis;
