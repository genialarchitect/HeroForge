import React, { useState } from 'react';
import { useQuery, useMutation } from '@tanstack/react-query';
import {
  FileText,
  Target,
  Code,
  FileCheck,
  Wrench,
  Sparkles,
  RefreshCw,
  AlertTriangle,
  CheckCircle,
  Clock,
} from 'lucide-react';
import Layout from '../components/layout/Layout';
import Card from '../components/ui/Card';
import Button from '../components/ui/Button';
import Badge from '../components/ui/Badge';
import { aiLlmAPI, scanAPI } from '../services/api';
import type { ScanResult } from '../types';

interface ExploitAnalysis {
  vulnerability_id: string;
  attack_flow: string;
  impact_assessment: string;
  mitigations: string[];
  mitre_techniques: string[];
}

interface ScanPlan {
  recommended_scans: string[];
  estimated_duration: string;
  risk_factors: string[];
}

interface SecurityPolicy {
  title: string;
  content: string;
  review_schedule: string;
}

interface RemediationGuidance {
  immediate_actions: string[];
  detailed_steps: string[];
  tools_required: string[];
  estimated_time: string;
}

const AiReportsPage: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'reports' | 'scan-plan' | 'exploit' | 'policy' | 'remediation'>('reports');
  const [selectedScan, setSelectedScan] = useState<string>('');
  const [reportType, setReportType] = useState<'executive' | 'technical'>('executive');
  const [generatedReport, setGeneratedReport] = useState<any>(null);

  // Scan Planning State
  const [scanTargets, setScanTargets] = useState<string>('');
  const [scanObjectives, setScanObjectives] = useState<string>('');
  const [scanPlan, setScanPlan] = useState<ScanPlan | null>(null);

  // Exploit Analysis State
  const [exploitCode, setExploitCode] = useState<string>('');
  const [exploitContext, setExploitContext] = useState<string>('');
  const [exploitAnalysis, setExploitAnalysis] = useState<ExploitAnalysis | null>(null);

  // Policy Generation State
  const [policyType, setPolicyType] = useState<string>('VulnerabilityManagement');
  const [organization, setOrganization] = useState<string>('');
  const [frameworks, setFrameworks] = useState<string>('');
  const [generatedPolicy, setGeneratedPolicy] = useState<SecurityPolicy | null>(null);

  // Remediation Guidance State
  const [vulnerability, setVulnerability] = useState<string>('');
  const [vulnContext, setVulnContext] = useState<string>('');
  const [remediation, setRemediation] = useState<RemediationGuidance | null>(null);

  // Fetch scans
  const { data: scans } = useQuery<ScanResult[]>({
    queryKey: ['scans'],
    queryFn: async () => {
      const response = await scanAPI.getAll();
      return response.data;
    },
  });

  // Generate Report Mutation
  const generateReportMutation = useMutation({
    mutationFn: async () => {
      const response = reportType === 'executive'
        ? await aiLlmAPI.generateExecutiveReport(selectedScan)
        : await aiLlmAPI.generateTechnicalReport(selectedScan);
      return response.data;
    },
    onSuccess: (data) => {
      setGeneratedReport(data);
    },
  });

  // Scan Planning Mutation
  const scanPlanMutation = useMutation({
    mutationFn: async () => {
      const response = await aiLlmAPI.planScan({
        targets: scanTargets.split('\n').filter(t => t.trim()),
        objectives: scanObjectives.split('\n').filter(o => o.trim()),
      });
      return response.data;
    },
    onSuccess: (data) => {
      setScanPlan(data);
    },
  });

  // Exploit Analysis Mutation
  const analyzeExploitMutation = useMutation({
    mutationFn: async () => {
      const response = await aiLlmAPI.analyzeExploit({
        code: exploitCode,
        context: exploitContext || undefined,
      });
      return response.data;
    },
    onSuccess: (data) => {
      setExploitAnalysis(data);
    },
  });

  // Policy Generation Mutation
  const generatePolicyMutation = useMutation({
    mutationFn: async () => {
      const response = await aiLlmAPI.generatePolicy({
        policy_type: policyType,
        organization,
        compliance_frameworks: frameworks.split(',').map(f => f.trim()).filter(f => f),
      });
      return response.data;
    },
    onSuccess: (data) => {
      setGeneratedPolicy(data);
    },
  });

  // Remediation Guidance Mutation
  const remediationMutation = useMutation({
    mutationFn: async () => {
      const response = await aiLlmAPI.getRemediationGuidance({
        vulnerability,
        context: vulnContext,
      });
      return response.data;
    },
    onSuccess: (data) => {
      setRemediation(data);
    },
  });

  const tabs = [
    { id: 'reports' as const, label: 'AI Reports', icon: <FileText className="h-4 w-4" /> },
    { id: 'scan-plan' as const, label: 'Scan Planning', icon: <Target className="h-4 w-4" /> },
    { id: 'exploit' as const, label: 'Exploit Analysis', icon: <Code className="h-4 w-4" /> },
    { id: 'policy' as const, label: 'Policy Generator', icon: <FileCheck className="h-4 w-4" /> },
    { id: 'remediation' as const, label: 'Remediation', icon: <Wrench className="h-4 w-4" /> },
  ];

  return (
    <Layout>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold text-white flex items-center gap-3">
              <Sparkles className="h-8 w-8 text-primary" />
              AI-Powered Security Operations
            </h1>
            <p className="text-slate-400 mt-2">
              Use LLM capabilities for automated report generation, scan planning, and security analysis
            </p>
          </div>
        </div>

        {/* Tabs */}
        <div className="flex items-center gap-2 border-b border-dark-border">
          {tabs.map((tab) => (
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

        {/* Report Generation Tab */}
        {activeTab === 'reports' && (
          <Card>
            <div className="flex items-center gap-3 mb-6">
              <FileText className="h-6 w-6 text-primary" />
              <h2 className="text-xl font-semibold text-white">Generate AI Reports</h2>
            </div>

            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-2">
                  Select Scan
                </label>
                <select
                  value={selectedScan}
                  onChange={(e) => setSelectedScan(e.target.value)}
                  className="w-full px-3 py-2 bg-dark-bg border border-dark-border rounded-lg text-white focus:outline-none focus:border-primary"
                >
                  <option value="">Choose a scan...</option>
                  {scans?.map((scan) => (
                    <option key={scan.id} value={scan.id}>
                      {scan.name || scan.targets} - {new Date(scan.created_at).toLocaleDateString()}
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-sm font-medium text-slate-300 mb-2">
                  Report Type
                </label>
                <div className="flex gap-4">
                  <label className="flex items-center gap-2 cursor-pointer">
                    <input
                      type="radio"
                      value="executive"
                      checked={reportType === 'executive'}
                      onChange={(e) => setReportType(e.target.value as 'executive')}
                      className="text-primary focus:ring-primary"
                    />
                    <span className="text-slate-300">Executive Summary (C-level)</span>
                  </label>
                  <label className="flex items-center gap-2 cursor-pointer">
                    <input
                      type="radio"
                      value="technical"
                      checked={reportType === 'technical'}
                      onChange={(e) => setReportType(e.target.value as 'technical')}
                      className="text-primary focus:ring-primary"
                    />
                    <span className="text-slate-300">Technical Report (Engineers)</span>
                  </label>
                </div>
              </div>

              <Button
                variant="primary"
                onClick={() => generateReportMutation.mutate()}
                disabled={!selectedScan}
                loading={generateReportMutation.isPending}
              >
                <Sparkles className="h-4 w-4 mr-2" />
                Generate Report
              </Button>

              {generatedReport && (
                <div className="mt-6 p-4 bg-dark-bg rounded-lg border border-dark-border">
                  <h3 className="font-semibold text-white mb-4">Generated Report</h3>
                  <div className="space-y-4">
                    <div className="flex items-center gap-2">
                      <span className="text-slate-400">Risk Score:</span>
                      <Badge variant={generatedReport.risk_score > 7 ? 'danger' : generatedReport.risk_score > 4 ? 'warning' : 'success'}>
                        {generatedReport.risk_score}/10
                      </Badge>
                    </div>
                    <div>
                      <p className="text-slate-400 mb-1">Summary:</p>
                      <p className="text-slate-300 whitespace-pre-wrap">{generatedReport.summary || generatedReport.technical_summary}</p>
                    </div>
                    {generatedReport.key_findings && (
                      <div>
                        <p className="text-slate-400 mb-1">Key Findings:</p>
                        <ul className="list-disc pl-5 text-slate-300 space-y-1">
                          {generatedReport.key_findings.map((finding: string, i: number) => (
                            <li key={i}>{finding}</li>
                          ))}
                        </ul>
                      </div>
                    )}
                    {generatedReport.recommendations && (
                      <div>
                        <p className="text-slate-400 mb-1">Recommendations:</p>
                        <ul className="list-disc pl-5 text-slate-300 space-y-1">
                          {generatedReport.recommendations.map((rec: string, i: number) => (
                            <li key={i}>{rec}</li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
          </Card>
        )}

        {/* Scan Planning Tab */}
        {activeTab === 'scan-plan' && (
          <Card>
            <div className="flex items-center gap-3 mb-6">
              <Target className="h-6 w-6 text-primary" />
              <h2 className="text-xl font-semibold text-white">Intelligent Scan Planning</h2>
            </div>

            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-2">
                  Targets (one per line)
                </label>
                <textarea
                  value={scanTargets}
                  onChange={(e) => setScanTargets(e.target.value)}
                  placeholder="app.example.com&#10;192.168.1.0/24&#10;api.company.com"
                  className="w-full px-3 py-2 bg-dark-bg border border-dark-border rounded-lg text-white placeholder-slate-500 h-24 focus:outline-none focus:border-primary resize-none"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-slate-300 mb-2">
                  Objectives (one per line)
                </label>
                <textarea
                  value={scanObjectives}
                  onChange={(e) => setScanObjectives(e.target.value)}
                  placeholder="Web vulnerability assessment&#10;Network mapping&#10;SSL/TLS analysis"
                  className="w-full px-3 py-2 bg-dark-bg border border-dark-border rounded-lg text-white placeholder-slate-500 h-24 focus:outline-none focus:border-primary resize-none"
                />
              </div>

              <Button
                variant="primary"
                onClick={() => scanPlanMutation.mutate()}
                disabled={!scanTargets || !scanObjectives}
                loading={scanPlanMutation.isPending}
              >
                <Sparkles className="h-4 w-4 mr-2" />
                Generate Scan Plan
              </Button>

              {scanPlan && (
                <div className="mt-6 p-4 bg-dark-bg rounded-lg border border-dark-border">
                  <h3 className="font-semibold text-white mb-4">Recommended Scan Plan</h3>
                  <div className="space-y-4">
                    <div className="flex items-center gap-2">
                      <Clock className="h-4 w-4 text-slate-400" />
                      <span className="text-slate-400">Estimated Duration:</span>
                      <span className="text-white">{scanPlan.estimated_duration}</span>
                    </div>
                    <div>
                      <p className="text-slate-400 mb-2">Recommended Scans:</p>
                      <ol className="list-decimal pl-5 text-slate-300 space-y-1">
                        {scanPlan.recommended_scans.map((scan, i) => (
                          <li key={i}>{scan}</li>
                        ))}
                      </ol>
                    </div>
                    {scanPlan.risk_factors.length > 0 && (
                      <div>
                        <p className="text-slate-400 mb-2 flex items-center gap-2">
                          <AlertTriangle className="h-4 w-4 text-yellow-500" />
                          Risk Factors:
                        </p>
                        <ul className="list-disc pl-5 text-yellow-400 space-y-1">
                          {scanPlan.risk_factors.map((risk, i) => (
                            <li key={i}>{risk}</li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
          </Card>
        )}

        {/* Exploit Analysis Tab */}
        {activeTab === 'exploit' && (
          <Card>
            <div className="flex items-center gap-3 mb-6">
              <Code className="h-6 w-6 text-primary" />
              <h2 className="text-xl font-semibold text-white">Exploit Code Analysis</h2>
            </div>

            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-2">
                  Exploit Code
                </label>
                <textarea
                  value={exploitCode}
                  onChange={(e) => setExploitCode(e.target.value)}
                  placeholder="Paste exploit code here..."
                  className="w-full px-3 py-2 bg-dark-bg border border-dark-border rounded-lg text-white placeholder-slate-500 h-32 font-mono text-sm focus:outline-none focus:border-primary resize-none"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-slate-300 mb-2">
                  Context (optional)
                </label>
                <input
                  type="text"
                  value={exploitContext}
                  onChange={(e) => setExploitContext(e.target.value)}
                  placeholder="e.g., WordPress plugin, PHP file upload vulnerability"
                  className="w-full px-3 py-2 bg-dark-bg border border-dark-border rounded-lg text-white placeholder-slate-500 focus:outline-none focus:border-primary"
                />
              </div>

              <Button
                variant="primary"
                onClick={() => analyzeExploitMutation.mutate()}
                disabled={!exploitCode}
                loading={analyzeExploitMutation.isPending}
              >
                <Sparkles className="h-4 w-4 mr-2" />
                Analyze Exploit
              </Button>

              {exploitAnalysis && (
                <div className="mt-6 p-4 bg-dark-bg rounded-lg border border-dark-border">
                  <h3 className="font-semibold text-white mb-4">Analysis Results</h3>
                  <div className="space-y-4">
                    <div>
                      <span className="text-slate-400">Vulnerability:</span>
                      <span className="text-white ml-2">{exploitAnalysis.vulnerability_id}</span>
                    </div>
                    <div>
                      <span className="text-slate-400">Impact:</span>
                      <span className="text-red-400 ml-2">{exploitAnalysis.impact_assessment}</span>
                    </div>
                    <div>
                      <p className="text-slate-400 mb-1">Attack Flow:</p>
                      <p className="text-slate-300 whitespace-pre-wrap bg-dark-surface p-3 rounded">{exploitAnalysis.attack_flow}</p>
                    </div>
                    <div>
                      <p className="text-slate-400 mb-1">MITRE ATT&CK Techniques:</p>
                      <ul className="list-disc pl-5 text-slate-300 space-y-1">
                        {exploitAnalysis.mitre_techniques.map((tech, i) => (
                          <li key={i}>{tech}</li>
                        ))}
                      </ul>
                    </div>
                    <div>
                      <p className="text-slate-400 mb-1">Mitigations:</p>
                      <ul className="list-disc pl-5 text-green-400 space-y-1">
                        {exploitAnalysis.mitigations.map((mit, i) => (
                          <li key={i}>{mit}</li>
                        ))}
                      </ul>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </Card>
        )}

        {/* Policy Generation Tab */}
        {activeTab === 'policy' && (
          <Card>
            <div className="flex items-center gap-3 mb-6">
              <FileCheck className="h-6 w-6 text-primary" />
              <h2 className="text-xl font-semibold text-white">Security Policy Generator</h2>
            </div>

            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-2">
                  Policy Type
                </label>
                <select
                  value={policyType}
                  onChange={(e) => setPolicyType(e.target.value)}
                  className="w-full px-3 py-2 bg-dark-bg border border-dark-border rounded-lg text-white focus:outline-none focus:border-primary"
                >
                  <option value="AccessControl">Access Control</option>
                  <option value="DataProtection">Data Protection</option>
                  <option value="IncidentResponse">Incident Response</option>
                  <option value="ChangeManagement">Change Management</option>
                  <option value="AssetManagement">Asset Management</option>
                  <option value="VulnerabilityManagement">Vulnerability Management</option>
                  <option value="NetworkSecurity">Network Security</option>
                  <option value="CloudSecurity">Cloud Security</option>
                </select>
              </div>

              <div>
                <label className="block text-sm font-medium text-slate-300 mb-2">
                  Organization Name
                </label>
                <input
                  type="text"
                  value={organization}
                  onChange={(e) => setOrganization(e.target.value)}
                  placeholder="Acme Corporation"
                  className="w-full px-3 py-2 bg-dark-bg border border-dark-border rounded-lg text-white placeholder-slate-500 focus:outline-none focus:border-primary"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-slate-300 mb-2">
                  Compliance Frameworks (comma-separated)
                </label>
                <input
                  type="text"
                  value={frameworks}
                  onChange={(e) => setFrameworks(e.target.value)}
                  placeholder="PCI-DSS, SOC 2, NIST CSF, HIPAA"
                  className="w-full px-3 py-2 bg-dark-bg border border-dark-border rounded-lg text-white placeholder-slate-500 focus:outline-none focus:border-primary"
                />
              </div>

              <Button
                variant="primary"
                onClick={() => generatePolicyMutation.mutate()}
                disabled={!organization}
                loading={generatePolicyMutation.isPending}
              >
                <Sparkles className="h-4 w-4 mr-2" />
                Generate Policy
              </Button>

              {generatedPolicy && (
                <div className="mt-6 p-4 bg-dark-bg rounded-lg border border-dark-border">
                  <h3 className="font-semibold text-white mb-2">{generatedPolicy.title}</h3>
                  <p className="text-sm text-slate-400 mb-4">Review Schedule: {generatedPolicy.review_schedule}</p>
                  <div className="bg-dark-surface p-4 rounded text-slate-300 whitespace-pre-wrap max-h-96 overflow-y-auto">
                    {generatedPolicy.content}
                  </div>
                </div>
              )}
            </div>
          </Card>
        )}

        {/* Remediation Guidance Tab */}
        {activeTab === 'remediation' && (
          <Card>
            <div className="flex items-center gap-3 mb-6">
              <Wrench className="h-6 w-6 text-primary" />
              <h2 className="text-xl font-semibold text-white">Remediation Guidance</h2>
            </div>

            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-2">
                  Vulnerability Description
                </label>
                <input
                  type="text"
                  value={vulnerability}
                  onChange={(e) => setVulnerability(e.target.value)}
                  placeholder="e.g., SQL Injection in login form"
                  className="w-full px-3 py-2 bg-dark-bg border border-dark-border rounded-lg text-white placeholder-slate-500 focus:outline-none focus:border-primary"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-slate-300 mb-2">
                  Context
                </label>
                <textarea
                  value={vulnContext}
                  onChange={(e) => setVulnContext(e.target.value)}
                  placeholder="Additional context: affected system, technology stack, environment details..."
                  className="w-full px-3 py-2 bg-dark-bg border border-dark-border rounded-lg text-white placeholder-slate-500 h-24 focus:outline-none focus:border-primary resize-none"
                />
              </div>

              <Button
                variant="primary"
                onClick={() => remediationMutation.mutate()}
                disabled={!vulnerability || !vulnContext}
                loading={remediationMutation.isPending}
              >
                <Sparkles className="h-4 w-4 mr-2" />
                Get Guidance
              </Button>

              {remediation && (
                <div className="mt-6 p-4 bg-dark-bg rounded-lg border border-dark-border">
                  <h3 className="font-semibold text-white mb-4">Remediation Plan</h3>
                  <div className="space-y-4">
                    <div>
                      <p className="text-yellow-400 font-medium flex items-center gap-2 mb-2">
                        <AlertTriangle className="h-4 w-4" />
                        Immediate Actions:
                      </p>
                      <ul className="list-disc pl-5 text-slate-300 space-y-1">
                        {remediation.immediate_actions.map((action, i) => (
                          <li key={i}>{action}</li>
                        ))}
                      </ul>
                    </div>
                    <div>
                      <p className="text-slate-400 font-medium mb-2">Detailed Steps:</p>
                      <ol className="list-decimal pl-5 text-slate-300 space-y-1">
                        {remediation.detailed_steps.map((step, i) => (
                          <li key={i}>{step}</li>
                        ))}
                      </ol>
                    </div>
                    <div>
                      <p className="text-slate-400 font-medium mb-2">Tools Required:</p>
                      <ul className="list-disc pl-5 text-slate-300 space-y-1">
                        {remediation.tools_required.map((tool, i) => (
                          <li key={i}>{tool}</li>
                        ))}
                      </ul>
                    </div>
                    <div className="flex items-center gap-2">
                      <Clock className="h-4 w-4 text-slate-400" />
                      <span className="text-slate-400">Estimated Time:</span>
                      <span className="text-white">{remediation.estimated_time}</span>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </Card>
        )}
      </div>
    </Layout>
  );
};

export default AiReportsPage;
