import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { FileCode, AlertTriangle, RefreshCw, Copy, CheckCircle } from 'lucide-react';
import { toast } from 'react-toastify';
import { iacAPI } from '../../services/api';
import type { IacFile, IacFinding } from '../../types';

interface IacFileViewerProps {
  fileId: string;
  findings?: IacFinding[];
}

const getSeverityColor = (severity: string): string => {
  switch (severity.toLowerCase()) {
    case 'critical':
      return 'bg-red-500';
    case 'high':
      return 'bg-orange-500';
    case 'medium':
      return 'bg-yellow-500';
    case 'low':
      return 'bg-blue-500';
    default:
      return 'bg-gray-500';
  }
};

const getPlatformIcon = (platform: string): string => {
  switch (platform.toLowerCase()) {
    case 'terraform':
      return '/terraform-icon.svg';
    case 'cloudformation':
      return '/cloudformation-icon.svg';
    case 'azurearm':
    case 'azure_arm':
      return '/azure-icon.svg';
    default:
      return '';
  }
};

export default function IacFileViewer({ fileId, findings: propFindings }: IacFileViewerProps) {
  const [copiedLine, setCopiedLine] = useState<number | null>(null);
  const [highlightedFinding, setHighlightedFinding] = useState<string | null>(null);

  // Fetch file details
  const { data: file, isLoading: isLoadingFile } = useQuery({
    queryKey: ['iac-file', fileId],
    queryFn: async () => {
      const response = await iacAPI.getFile(fileId);
      return response.data;
    },
  });

  // Fetch findings for file if not provided
  const { data: fetchedFindings = [] } = useQuery({
    queryKey: ['iac-file-findings', fileId],
    queryFn: async () => {
      const response = await iacAPI.getFileFindings(fileId);
      return response.data;
    },
    enabled: !propFindings,
  });

  const findings = propFindings || fetchedFindings;

  const copyToClipboard = async (text: string, lineNumber: number) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedLine(lineNumber);
      setTimeout(() => setCopiedLine(null), 2000);
    } catch (err) {
      toast.error('Failed to copy to clipboard');
    }
  };

  if (isLoadingFile) {
    return (
      <div className="flex items-center justify-center h-64 bg-gray-800 rounded-lg">
        <RefreshCw className="w-8 h-8 text-cyan-400 animate-spin" />
      </div>
    );
  }

  if (!file) {
    return (
      <div className="text-center py-12 bg-gray-800 rounded-lg">
        <AlertTriangle className="w-12 h-12 text-yellow-400 mx-auto mb-4" />
        <h3 className="text-lg font-semibold text-white">File Not Found</h3>
      </div>
    );
  }

  const lines = (file.content || '').split('\n');

  // Build a map of line numbers to findings
  const lineFindings = new Map<number, IacFinding[]>();
  for (const finding of findings) {
    for (let line = finding.line_start; line <= finding.line_end; line++) {
      if (!lineFindings.has(line)) {
        lineFindings.set(line, []);
      }
      lineFindings.get(line)!.push(finding);
    }
  }

  return (
    <div className="bg-gray-800 rounded-lg border border-gray-700 overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 bg-gray-700/50 border-b border-gray-600">
        <div className="flex items-center gap-3">
          <FileCode className="w-5 h-5 text-cyan-400" />
          <div>
            <div className="font-medium text-white">{file.filename}</div>
            <div className="text-xs text-gray-400">
              {file.platform} | {file.line_count} lines | {file.resource_count} resources
            </div>
          </div>
        </div>
        {findings.length > 0 && (
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-yellow-400" />
            <span className="text-sm text-yellow-400">{findings.length} issue(s)</span>
          </div>
        )}
      </div>

      {/* Code View */}
      <div className="overflow-auto max-h-[600px]">
        <table className="w-full text-sm font-mono">
          <tbody>
            {lines.map((line, index) => {
              const lineNumber = index + 1;
              const lineIssues = lineFindings.get(lineNumber) || [];
              const hasIssue = lineIssues.length > 0;
              const isHighlighted = lineIssues.some((f) => f.id === highlightedFinding);

              return (
                <tr
                  key={lineNumber}
                  className={`group ${
                    isHighlighted
                      ? 'bg-yellow-500/20'
                      : hasIssue
                      ? 'bg-red-500/10 hover:bg-red-500/20'
                      : 'hover:bg-gray-700/30'
                  }`}
                  onMouseEnter={() =>
                    lineIssues.length > 0 && setHighlightedFinding(lineIssues[0].id)
                  }
                  onMouseLeave={() => setHighlightedFinding(null)}
                >
                  {/* Line Number */}
                  <td className="select-none text-right pr-4 pl-4 py-0.5 text-gray-500 w-12 border-r border-gray-700">
                    {lineNumber}
                  </td>

                  {/* Issue Indicator */}
                  <td className="w-6 px-1">
                    {hasIssue && (
                      <div className="relative group/tooltip">
                        <div
                          className={`w-2 h-2 rounded-full ${getSeverityColor(
                            lineIssues[0].severity
                          )}`}
                        />
                        <div className="absolute left-4 top-1/2 -translate-y-1/2 z-10 hidden group-hover/tooltip:block w-64 bg-gray-900 border border-gray-600 rounded-lg p-3 shadow-lg">
                          {lineIssues.map((finding) => (
                            <div key={finding.id} className="mb-2 last:mb-0">
                              <div className="font-semibold text-white text-xs">
                                {finding.title}
                              </div>
                              <div className="text-xs text-gray-400 mt-0.5">
                                {finding.description.slice(0, 100)}...
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </td>

                  {/* Code */}
                  <td className="py-0.5 pr-4">
                    <pre className="text-gray-300 whitespace-pre">
                      {line || ' '}
                    </pre>
                  </td>

                  {/* Copy Button */}
                  <td className="w-8 pr-2">
                    <button
                      onClick={() => copyToClipboard(line, lineNumber)}
                      className="opacity-0 group-hover:opacity-100 transition-opacity p-1 text-gray-400 hover:text-white"
                      title="Copy line"
                    >
                      {copiedLine === lineNumber ? (
                        <CheckCircle className="w-4 h-4 text-green-400" />
                      ) : (
                        <Copy className="w-4 h-4" />
                      )}
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {/* Findings Summary */}
      {findings.length > 0 && (
        <div className="border-t border-gray-700 p-4">
          <h4 className="text-sm font-medium text-gray-400 mb-3">Issues in this file</h4>
          <div className="space-y-2">
            {findings.map((finding) => (
              <button
                key={finding.id}
                onClick={() => {
                  setHighlightedFinding(finding.id);
                  // Scroll to line
                  const row = document.querySelector(
                    `tr:nth-child(${finding.line_start})`
                  );
                  row?.scrollIntoView({ behavior: 'smooth', block: 'center' });
                }}
                className={`w-full text-left px-3 py-2 rounded-lg transition-colors ${
                  highlightedFinding === finding.id
                    ? 'bg-yellow-500/20'
                    : 'bg-gray-700/50 hover:bg-gray-700'
                }`}
              >
                <div className="flex items-center gap-2">
                  <div
                    className={`w-2 h-2 rounded-full ${getSeverityColor(finding.severity)}`}
                  />
                  <span className="text-sm text-white">{finding.title}</span>
                  <span className="ml-auto text-xs text-gray-400">
                    Line {finding.line_start}
                  </span>
                </div>
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
