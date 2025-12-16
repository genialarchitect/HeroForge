import React, { useState } from 'react';
import { toast } from 'react-toastify';
import type { ComplianceAnalyzeResponse, FrameworkSummary } from '../../types';
import { complianceAPI } from '../../services/api';
import Card from '../ui/Card';
import Badge from '../ui/Badge';
import Button from '../ui/Button';
import ControlList from './ControlList';
import {
  CheckCircle2,
  XCircle,
  AlertTriangle,
  ChevronDown,
  ChevronRight,
  FileDown,
  RefreshCw,
  TrendingUp,
  TrendingDown,
} from 'lucide-react';

interface ComplianceResultsProps {
  results: ComplianceAnalyzeResponse;
  scanId: string;
}

const ComplianceResults: React.FC<ComplianceResultsProps> = ({ results, scanId }) => {
  const [expandedFramework, setExpandedFramework] = useState<string | null>(null);
  const [generatingReport, setGeneratingReport] = useState(false);
  const [reportFormat, setReportFormat] = useState<'pdf' | 'html' | 'json'>('pdf');

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
    setGeneratingReport(true);
    try {
      const frameworkIds = results.summary.frameworks.map((fw) =>
        String(fw.framework).toLowerCase().replace(/_/g, '_')
      );

      const response = await complianceAPI.generateReport(scanId, {
        frameworks: frameworkIds,
        format: reportFormat,
        include_evidence: true,
      });

      const downloadResponse = await complianceAPI.downloadReport(response.data.report_id);

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
    } catch (error: any) {
      toast.error(error.response?.data?.error || 'Failed to generate report');
    } finally {
      setGeneratingReport(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Overall Summary */}
      <Card>
        <h2 className="text-xl font-bold text-white mb-6">Compliance Summary</h2>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-6">
          <div className="text-center">
            <div
              className={`text-4xl font-bold mb-2 ${getScoreColor(
                results.summary.overall_score
              )}`}
            >
              {results.summary.overall_score.toFixed(1)}%
            </div>
            <p className="text-sm text-slate-400">Overall Compliance Score</p>
            {results.summary.overall_score >= 80 ? (
              <div className="flex items-center justify-center gap-1 mt-2 text-green-400">
                <TrendingUp className="h-4 w-4" />
                <span className="text-xs">Good Standing</span>
              </div>
            ) : (
              <div className="flex items-center justify-center gap-1 mt-2 text-orange-400">
                <TrendingDown className="h-4 w-4" />
                <span className="text-xs">Needs Attention</span>
              </div>
            )}
          </div>

          <div className="text-center">
            <div className="text-4xl font-bold text-white mb-2">
              {results.summary.total_findings}
            </div>
            <p className="text-sm text-slate-400">Total Findings</p>
            <div className="flex items-center justify-center gap-1 mt-2 text-slate-400">
              <span className="text-xs">Across all frameworks</span>
            </div>
          </div>

          <div className="text-center">
            <div className="text-4xl font-bold text-red-400 mb-2">
              {results.summary.critical_findings + results.summary.high_findings}
            </div>
            <p className="text-sm text-slate-400">Critical / High</p>
            <div className="flex items-center justify-center gap-2 text-xs mt-2">
              <span className="text-red-400">{results.summary.critical_findings} Critical</span>
              <span className="text-slate-500">•</span>
              <span className="text-orange-400">{results.summary.high_findings} High</span>
            </div>
          </div>

          <div className="text-center">
            <div className="text-4xl font-bold text-yellow-400 mb-2">
              {results.summary.medium_findings + results.summary.low_findings}
            </div>
            <p className="text-sm text-slate-400">Medium / Low</p>
            <div className="flex items-center justify-center gap-2 text-xs mt-2">
              <span className="text-yellow-400">{results.summary.medium_findings} Medium</span>
              <span className="text-slate-500">•</span>
              <span className="text-blue-400">{results.summary.low_findings} Low</span>
            </div>
          </div>
        </div>
      </Card>

      {/* Framework Results */}
      <Card>
        <h2 className="text-xl font-bold text-white mb-6">Framework Results</h2>
        <div className="space-y-4">
          {results.summary.frameworks.map((fw: FrameworkSummary) => (
            <div
              key={fw.framework}
              className="border border-dark-border rounded-lg overflow-hidden"
            >
              {/* Framework Header */}
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
                  <span className="font-semibold text-white text-lg">{fw.framework}</span>
                </div>

                <div className="flex items-center gap-4">
                  <div className="flex items-center gap-2 text-sm">
                    <CheckCircle2 className="h-4 w-4 text-green-400" />
                    <span className="text-green-400 font-medium">{fw.compliant}</span>
                  </div>
                  <div className="flex items-center gap-2 text-sm">
                    <AlertTriangle className="h-4 w-4 text-yellow-400" />
                    <span className="text-yellow-400 font-medium">
                      {fw.partially_compliant}
                    </span>
                  </div>
                  <div className="flex items-center gap-2 text-sm">
                    <XCircle className="h-4 w-4 text-red-400" />
                    <span className="text-red-400 font-medium">{fw.non_compliant}</span>
                  </div>
                  <Badge variant="status" type={getScoreBadge(fw.compliance_score)}>
                    {fw.compliance_score.toFixed(0)}%
                  </Badge>
                </div>
              </div>

              {/* Framework Details */}
              {expandedFramework === fw.framework && (
                <div className="p-6 bg-dark-bg border-t border-dark-border">
                  {/* Stats Grid */}
                  <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4 mb-6">
                    <div className="p-3 bg-dark-surface rounded-lg">
                      <p className="text-xs text-slate-400 mb-1">Total Controls</p>
                      <p className="text-2xl font-bold text-white">{fw.total_controls}</p>
                    </div>
                    <div className="p-3 bg-green-500/10 border border-green-500/30 rounded-lg">
                      <p className="text-xs text-green-400 mb-1">Compliant</p>
                      <p className="text-2xl font-bold text-green-400">{fw.compliant}</p>
                    </div>
                    <div className="p-3 bg-red-500/10 border border-red-500/30 rounded-lg">
                      <p className="text-xs text-red-400 mb-1">Non-Compliant</p>
                      <p className="text-2xl font-bold text-red-400">{fw.non_compliant}</p>
                    </div>
                    <div className="p-3 bg-yellow-500/10 border border-yellow-500/30 rounded-lg">
                      <p className="text-xs text-yellow-400 mb-1">Partial</p>
                      <p className="text-2xl font-bold text-yellow-400">
                        {fw.partially_compliant}
                      </p>
                    </div>
                    <div className="p-3 bg-dark-surface rounded-lg">
                      <p className="text-xs text-slate-400 mb-1">N/A</p>
                      <p className="text-2xl font-bold text-slate-400">{fw.not_applicable}</p>
                    </div>
                    <div className="p-3 bg-dark-surface rounded-lg">
                      <p className="text-xs text-slate-400 mb-1">Not Assessed</p>
                      <p className="text-2xl font-bold text-slate-500">{fw.not_assessed}</p>
                    </div>
                  </div>

                  {/* Category Breakdown */}
                  {fw.by_category && fw.by_category.length > 0 && (
                    <div className="mb-6">
                      <h3 className="text-sm font-semibold text-slate-300 mb-3">
                        Compliance by Category
                      </h3>
                      <div className="space-y-3">
                        {fw.by_category.map((cat) => (
                          <div
                            key={cat.category}
                            className="p-4 bg-dark-surface rounded-lg border border-dark-border"
                          >
                            <div className="flex items-center justify-between mb-2">
                              <span className="text-sm font-medium text-white">
                                {cat.category}
                              </span>
                              <span className="text-xs text-slate-400">
                                {cat.compliant}/{cat.total} compliant
                              </span>
                            </div>
                            <div className="flex items-center gap-3">
                              <div className="flex-1 bg-dark-border rounded-full h-2.5">
                                <div
                                  className={`h-2.5 rounded-full transition-all ${
                                    cat.percentage >= 80
                                      ? 'bg-green-500'
                                      : cat.percentage >= 60
                                      ? 'bg-yellow-500'
                                      : 'bg-red-500'
                                  }`}
                                  style={{ width: `${cat.percentage}%` }}
                                />
                              </div>
                              <span className="text-sm font-semibold text-slate-300 w-12 text-right">
                                {cat.percentage.toFixed(0)}%
                              </span>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Control List */}
                  <ControlList framework={fw.framework} scanId={scanId} />
                </div>
              )}
            </div>
          ))}
        </div>
      </Card>

      {/* Report Generation */}
      <Card>
        <h2 className="text-xl font-bold text-white mb-6">Generate Compliance Report</h2>
        <p className="text-sm text-slate-400 mb-6">
          Export your compliance analysis results with detailed evidence and remediation
          guidance.
        </p>
        <div className="flex flex-col sm:flex-row items-start sm:items-center gap-4">
          <div className="flex gap-2">
            {(['pdf', 'html', 'json'] as const).map((format) => (
              <button
                key={format}
                onClick={() => setReportFormat(format)}
                className={`px-4 py-2 rounded-lg font-medium transition-colors ${
                  reportFormat === format
                    ? 'bg-primary text-white'
                    : 'bg-dark-surface text-slate-400 hover:bg-dark-hover border border-dark-border'
                }`}
              >
                {format.toUpperCase()}
              </button>
            ))}
          </div>
          <Button onClick={generateReport} disabled={generatingReport} className="sm:ml-auto">
            {generatingReport ? (
              <>
                <RefreshCw className="h-4 w-4 animate-spin mr-2" />
                Generating...
              </>
            ) : (
              <>
                <FileDown className="h-4 w-4 mr-2" />
                Generate {reportFormat.toUpperCase()} Report
              </>
            )}
          </Button>
        </div>
      </Card>
    </div>
  );
};

export default ComplianceResults;
