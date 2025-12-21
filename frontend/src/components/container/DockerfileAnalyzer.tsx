import React, { useState } from 'react';
import { useMutation } from '@tanstack/react-query';
import {
  FileCode,
  Upload,
  Play,
  AlertTriangle,
  AlertCircle,
  Info,
  CheckCircle,
  XCircle,
  Copy,
  Check,
} from 'lucide-react';
import { toast } from 'react-toastify';
import { containerAPI } from '../../services/api';
import { Button } from '../ui/Button';
import { Badge } from '../ui/Badge';
import type { DockerfileAnalysis, DockerfileIssue, ContainerFindingSeverity } from '../../types';

const severityColors: Record<ContainerFindingSeverity, { bg: string; text: string; border: string }> = {
  critical: { bg: 'bg-red-500/20', text: 'text-red-400', border: 'border-red-500' },
  high: { bg: 'bg-orange-500/20', text: 'text-orange-400', border: 'border-orange-500' },
  medium: { bg: 'bg-yellow-500/20', text: 'text-yellow-400', border: 'border-yellow-500' },
  low: { bg: 'bg-blue-500/20', text: 'text-blue-400', border: 'border-blue-500' },
  info: { bg: 'bg-gray-500/20', text: 'text-gray-400', border: 'border-gray-500' },
};

const exampleDockerfile = `FROM ubuntu:latest

ENV DATABASE_PASSWORD=secretpassword123
ENV API_KEY=sk-1234567890abcdef

RUN apt-get update && apt-get install -y curl
RUN chmod 777 /app
RUN curl https://example.com/script.sh | bash

USER root

EXPOSE 22 3306

CMD ["./app"]
`;

export function DockerfileAnalyzer() {
  const [content, setContent] = useState('');
  const [filename, setFilename] = useState('Dockerfile');
  const [analysis, setAnalysis] = useState<DockerfileAnalysis | null>(null);
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);

  const analyzeMutation = useMutation({
    mutationFn: () => containerAPI.analyzeDockerfile({ content, filename }).then((res) => res.data),
    onSuccess: (data) => {
      setAnalysis(data);
      if (data.issues.length === 0) {
        toast.success('No security issues found!');
      } else {
        toast.info(`Found ${data.issues.length} security issue(s)`);
      }
    },
    onError: () => {
      toast.error('Failed to analyze Dockerfile');
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
    setContent(exampleDockerfile);
    setFilename('Dockerfile.example');
    setAnalysis(null);
  };

  const copyToClipboard = (text: string, index: number) => {
    navigator.clipboard.writeText(text);
    setCopiedIndex(index);
    setTimeout(() => setCopiedIndex(null), 2000);
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

  return (
    <div className="space-y-6">
      {/* Input Section */}
      <div className="bg-gray-800 rounded-lg border border-gray-700 p-6">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold text-white flex items-center gap-2">
            <FileCode className="w-5 h-5 text-cyan-400" />
            Dockerfile Analyzer
          </h2>
          <div className="flex items-center gap-2">
            <Button variant="ghost" size="sm" onClick={handleLoadExample}>
              Load Example
            </Button>
            <label className="cursor-pointer">
              <input
                type="file"
                accept="Dockerfile,.dockerfile"
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
            Paste your Dockerfile content below:
          </label>
          <textarea
            value={content}
            onChange={(e) => setContent(e.target.value)}
            placeholder="FROM node:18-alpine&#10;&#10;WORKDIR /app&#10;&#10;COPY package*.json ./&#10;RUN npm ci --only=production&#10;&#10;COPY . .&#10;&#10;USER node&#10;EXPOSE 3000&#10;CMD [&quot;node&quot;, &quot;server.js&quot;]"
            className="w-full h-64 bg-gray-900 border border-gray-700 rounded-lg p-4 font-mono text-sm text-gray-200 placeholder-gray-600 focus:outline-none focus:border-cyan-500 resize-none"
          />
        </div>

        <div className="flex items-center justify-between">
          <span className="text-sm text-gray-400">
            {filename && `File: ${filename}`}
          </span>
          <Button
            onClick={() => analyzeMutation.mutate()}
            disabled={!content.trim() || analyzeMutation.isPending}
          >
            <Play className="w-4 h-4 mr-2" />
            {analyzeMutation.isPending ? 'Analyzing...' : 'Analyze Dockerfile'}
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
              <div className="flex items-center justify-between">
                <div>
                  <div className="text-sm text-gray-400 mb-1">Best Practices</div>
                  <div className={`text-3xl font-bold ${getScoreColor(analysis.best_practices_score)}`}>
                    {analysis.best_practices_score}/100
                  </div>
                </div>
                <div className={`text-4xl font-bold ${getScoreColor(analysis.best_practices_score)}`}>
                  {getScoreGrade(analysis.best_practices_score)}
                </div>
              </div>
            </div>

            <div className="bg-gray-800 rounded-lg border border-gray-700 p-6">
              <div className="flex items-center justify-between">
                <div>
                  <div className="text-sm text-gray-400 mb-1">Base Image</div>
                  <div className="text-lg font-medium text-gray-200">
                    {analysis.base_image || 'Unknown'}
                  </div>
                  {analysis.base_image_tag && (
                    <div className="text-sm text-gray-400">
                      Tag: {analysis.base_image_tag}
                    </div>
                  )}
                </div>
                {analysis.base_image_tag === 'latest' ? (
                  <AlertTriangle className="w-8 h-8 text-yellow-400" />
                ) : (
                  <CheckCircle className="w-8 h-8 text-green-400" />
                )}
              </div>
            </div>
          </div>

          {/* Issues List */}
          <div className="bg-gray-800 rounded-lg border border-gray-700">
            <div className="p-4 border-b border-gray-700">
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
            </div>

            {analysis.issues.length === 0 ? (
              <div className="p-8 text-center">
                <CheckCircle className="w-12 h-12 text-green-400 mx-auto mb-4" />
                <p className="text-gray-300">Your Dockerfile follows security best practices!</p>
              </div>
            ) : (
              <div className="divide-y divide-gray-700">
                {analysis.issues.map((issue, index) => (
                  <div key={index} className="p-4">
                    <div className="flex items-start gap-3">
                      <div className={severityColors[issue.severity].text}>
                        {getSeverityIcon(issue.severity)}
                      </div>
                      <div className="flex-1">
                        <div className="flex items-center gap-2 mb-1">
                          <h4 className="font-medium text-gray-200">{issue.title}</h4>
                          <Badge className={`${severityColors[issue.severity].bg} ${severityColors[issue.severity].text}`}>
                            {issue.severity}
                          </Badge>
                          {issue.line_number && (
                            <Badge className="bg-gray-700 text-gray-300">
                              Line {issue.line_number}
                            </Badge>
                          )}
                        </div>
                        <p className="text-sm text-gray-400 mb-3">{issue.description}</p>

                        {issue.instruction && (
                          <div className="mb-3">
                            <span className="text-xs text-gray-500 uppercase">Problematic Code:</span>
                            <div className="mt-1 bg-red-500/10 border border-red-500/30 rounded p-2 font-mono text-sm text-red-300 flex items-center justify-between">
                              <code className="truncate">{issue.instruction}</code>
                              <button
                                onClick={() => copyToClipboard(issue.instruction || '', index)}
                                className="ml-2 text-gray-400 hover:text-gray-200"
                              >
                                {copiedIndex === index ? (
                                  <Check className="w-4 h-4 text-green-400" />
                                ) : (
                                  <Copy className="w-4 h-4" />
                                )}
                              </button>
                            </div>
                          </div>
                        )}

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
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
