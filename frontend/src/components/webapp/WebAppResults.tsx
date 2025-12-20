import React, { useState, useEffect } from 'react';
import { toast } from 'react-toastify';
import Card from '../ui/Card';
import LoadingSpinner from '../ui/LoadingSpinner';
import { Shield, AlertTriangle, AlertCircle, Info, CheckCircle, ExternalLink } from 'lucide-react';
import { webappAPI } from '../../services/api';

interface WebAppResultsProps {
  scanId: string;
}

interface WebAppFinding {
  finding_type: string;
  url: string;
  parameter: string | null;
  evidence: string;
  severity: 'Low' | 'Medium' | 'High' | 'Critical';
  remediation: string;
}

interface WebAppScanResult {
  url: string;
  pages_crawled: number;
  findings: WebAppFinding[];
}

const WebAppResults: React.FC<WebAppResultsProps> = ({ scanId }) => {
  const [loading, setLoading] = useState(true);
  const [result, setResult] = useState<WebAppScanResult | null>(null);
  const [status, setStatus] = useState<'running' | 'completed'>('running');

  useEffect(() => {
    const fetchResults = async () => {
      try {
        const response = await webappAPI.getScan(scanId);
        setStatus(response.data.status);

        if (response.data.result) {
          setResult(response.data.result);
          setLoading(false);
        } else if (response.data.status === 'running') {
          // Poll again after 2 seconds
          setTimeout(fetchResults, 2000);
        }
      } catch (error: unknown) {
        toast.error('Failed to fetch scan results');
        setLoading(false);
      }
    };

    fetchResults();
  }, [scanId]);

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'Critical':
        return 'text-red-700 bg-red-100';
      case 'High':
        return 'text-orange-700 bg-orange-100';
      case 'Medium':
        return 'text-yellow-700 bg-yellow-100';
      case 'Low':
        return 'text-blue-700 bg-blue-100';
      default:
        return 'text-gray-700 bg-gray-100';
    }
  };

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case 'Critical':
      case 'High':
        return <AlertCircle className="w-5 h-5" />;
      case 'Medium':
        return <AlertTriangle className="w-5 h-5" />;
      case 'Low':
        return <Info className="w-5 h-5" />;
      default:
        return <Info className="w-5 h-5" />;
    }
  };

  const getFindingTypeLabel = (type: string) => {
    const labels: { [key: string]: string } = {
      MissingSecurityHeader: 'Missing Security Header',
      InsecureHeader: 'Insecure Header Configuration',
      SqlInjection: 'SQL Injection',
      CrossSiteScripting: 'Cross-Site Scripting (XSS)',
      SensitiveInfoDisclosure: 'Information Disclosure',
      InsecureForm: 'Insecure Form',
      WeakCryptography: 'Weak Cryptography',
      DirectoryListing: 'Directory Listing',
      Other: 'Other Security Issue',
    };
    return labels[type] || type;
  };

  const groupFindingsByType = (findings: WebAppFinding[]) => {
    const groups: { [key: string]: WebAppFinding[] } = {};
    findings.forEach(finding => {
      if (!groups[finding.finding_type]) {
        groups[finding.finding_type] = [];
      }
      groups[finding.finding_type].push(finding);
    });
    return groups;
  };

  if (loading || status === 'running') {
    return (
      <Card>
        <div className="p-8 text-center">
          <LoadingSpinner size="lg" className="mx-auto mb-4" />
          <h3 className="text-lg font-semibold text-gray-900 mb-2">
            Scanning Web Application...
          </h3>
          <p className="text-gray-600">
            This may take several minutes depending on the size of the application.
          </p>
        </div>
      </Card>
    );
  }

  if (!result) {
    return (
      <Card>
        <div className="p-8 text-center">
          <AlertCircle className="w-12 h-12 text-gray-400 mx-auto mb-4" />
          <p className="text-gray-600">No results available</p>
        </div>
      </Card>
    );
  }

  const groupedFindings = groupFindingsByType(result.findings);
  const severityCounts = result.findings.reduce((acc, finding) => {
    acc[finding.severity] = (acc[finding.severity] || 0) + 1;
    return acc;
  }, {} as { [key: string]: number });

  return (
    <div className="space-y-6">
      {/* Summary Card */}
      <Card>
        <div className="p-6">
          <div className="flex items-center gap-3 mb-4">
            <Shield className="w-6 h-6 text-purple-500" />
            <h2 className="text-xl font-bold text-gray-900">Scan Summary</h2>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
            <div className="p-4 bg-gray-50 rounded-lg">
              <div className="text-sm text-gray-600 mb-1">Target URL</div>
              <div className="font-semibold text-gray-900 break-all flex items-center gap-2">
                {result.url}
                <a
                  href={result.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-blue-600 hover:text-blue-700"
                >
                  <ExternalLink className="w-4 h-4" />
                </a>
              </div>
            </div>

            <div className="p-4 bg-gray-50 rounded-lg">
              <div className="text-sm text-gray-600 mb-1">Pages Crawled</div>
              <div className="font-semibold text-gray-900">{result.pages_crawled}</div>
            </div>

            <div className="p-4 bg-gray-50 rounded-lg">
              <div className="text-sm text-gray-600 mb-1">Total Findings</div>
              <div className="font-semibold text-gray-900">{result.findings.length}</div>
            </div>
          </div>

          {/* Severity Breakdown */}
          {result.findings.length > 0 && (
            <div className="flex flex-wrap gap-2">
              {severityCounts.Critical && (
                <span className="px-3 py-1 rounded-full text-sm font-medium text-red-700 bg-red-100">
                  {severityCounts.Critical} Critical
                </span>
              )}
              {severityCounts.High && (
                <span className="px-3 py-1 rounded-full text-sm font-medium text-orange-700 bg-orange-100">
                  {severityCounts.High} High
                </span>
              )}
              {severityCounts.Medium && (
                <span className="px-3 py-1 rounded-full text-sm font-medium text-yellow-700 bg-yellow-100">
                  {severityCounts.Medium} Medium
                </span>
              )}
              {severityCounts.Low && (
                <span className="px-3 py-1 rounded-full text-sm font-medium text-blue-700 bg-blue-100">
                  {severityCounts.Low} Low
                </span>
              )}
            </div>
          )}

          {result.findings.length === 0 && (
            <div className="mt-4 p-4 bg-green-50 border border-green-200 rounded-lg flex items-center gap-3">
              <CheckCircle className="w-5 h-5 text-green-600" />
              <p className="text-green-800">
                No security issues found! The application appears to be well-configured.
              </p>
            </div>
          )}
        </div>
      </Card>

      {/* Findings by Type */}
      {Object.entries(groupedFindings).map(([type, findings]) => (
        <Card key={type}>
          <div className="p-6">
            <h3 className="text-lg font-bold text-gray-900 mb-4">
              {getFindingTypeLabel(type)} ({findings.length})
            </h3>

            <div className="space-y-4">
              {findings.map((finding, index) => (
                <div
                  key={index}
                  className="border border-gray-200 rounded-lg p-4 hover:shadow-md transition-shadow"
                >
                  <div className="flex items-start gap-3 mb-3">
                    <span className={`px-3 py-1 rounded-full text-xs font-medium flex items-center gap-1 ${getSeverityColor(finding.severity)}`}>
                      {getSeverityIcon(finding.severity)}
                      {finding.severity}
                    </span>
                  </div>

                  <div className="space-y-2">
                    <div>
                      <div className="text-sm font-medium text-gray-700">URL:</div>
                      <div className="text-sm text-gray-900 break-all font-mono bg-gray-50 p-2 rounded">
                        {finding.url}
                      </div>
                    </div>

                    {finding.parameter && (
                      <div>
                        <div className="text-sm font-medium text-gray-700">Parameter:</div>
                        <div className="text-sm text-gray-900 font-mono bg-gray-50 p-2 rounded">
                          {finding.parameter}
                        </div>
                      </div>
                    )}

                    <div>
                      <div className="text-sm font-medium text-gray-700">Evidence:</div>
                      <div className="text-sm text-gray-900 bg-gray-50 p-2 rounded font-mono">
                        {finding.evidence}
                      </div>
                    </div>

                    <div>
                      <div className="text-sm font-medium text-gray-700">Remediation:</div>
                      <div className="text-sm text-gray-900 bg-blue-50 p-3 rounded border border-blue-200">
                        {finding.remediation}
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </Card>
      ))}
    </div>
  );
};

export default WebAppResults;
