import React, { useState } from 'react';
import { useQuery, useMutation } from '@tanstack/react-query';
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

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold text-gray-900">AI-Powered Security Operations</h1>
        <p className="mt-2 text-gray-600">
          Use LLM capabilities for automated report generation, scan planning, and security analysis
        </p>
      </div>

      {/* Report Generation Section */}
      <div className="bg-white rounded-lg shadow p-6">
        <h2 className="text-xl font-semibold mb-4">📊 Generate AI Reports</h2>
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Select Scan
            </label>
            <select
              value={selectedScan}
              onChange={(e) => setSelectedScan(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-indigo-500"
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
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Report Type
            </label>
            <div className="flex space-x-4">
              <label className="flex items-center">
                <input
                  type="radio"
                  value="executive"
                  checked={reportType === 'executive'}
                  onChange={(e) => setReportType(e.target.value as 'executive')}
                  className="mr-2"
                />
                Executive Summary (C-level)
              </label>
              <label className="flex items-center">
                <input
                  type="radio"
                  value="technical"
                  checked={reportType === 'technical'}
                  onChange={(e) => setReportType(e.target.value as 'technical')}
                  className="mr-2"
                />
                Technical Report (Engineers)
              </label>
            </div>
          </div>

          <button
            onClick={() => generateReportMutation.mutate()}
            disabled={!selectedScan || generateReportMutation.isPending}
            className="px-4 py-2 bg-indigo-600 text-white rounded-md hover:bg-indigo-700 disabled:bg-gray-300"
          >
            {generateReportMutation.isPending ? 'Generating...' : 'Generate Report'}
          </button>

          {generatedReport && (
            <div className="mt-4 p-4 bg-gray-50 rounded-md">
              <h3 className="font-semibold mb-2">Generated Report</h3>
              <div className="space-y-2">
                <p><strong>Risk Score:</strong> {generatedReport.risk_score}</p>
                <p><strong>Summary:</strong></p>
                <p className="text-sm text-gray-700 whitespace-pre-wrap">{generatedReport.summary || generatedReport.technical_summary}</p>
                {generatedReport.key_findings && (
                  <>
                    <p><strong>Key Findings:</strong></p>
                    <ul className="list-disc pl-5 text-sm">
                      {generatedReport.key_findings.map((finding: string, i: number) => (
                        <li key={i}>{finding}</li>
                      ))}
                    </ul>
                  </>
                )}
                {generatedReport.recommendations && (
                  <>
                    <p><strong>Recommendations:</strong></p>
                    <ul className="list-disc pl-5 text-sm">
                      {generatedReport.recommendations.map((rec: string, i: number) => (
                        <li key={i}>{rec}</li>
                      ))}
                    </ul>
                  </>
                )}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Scan Planning Section */}
      <div className="bg-white rounded-lg shadow p-6">
        <h2 className="text-xl font-semibold mb-4">🎯 Intelligent Scan Planning</h2>
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Targets (one per line)
            </label>
            <textarea
              value={scanTargets}
              onChange={(e) => setScanTargets(e.target.value)}
              placeholder="app.example.com&#10;192.168.1.0/24&#10;api.company.com"
              className="w-full px-3 py-2 border border-gray-300 rounded-md h-24 focus:outline-none focus:ring-2 focus:ring-indigo-500"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Objectives (one per line)
            </label>
            <textarea
              value={scanObjectives}
              onChange={(e) => setScanObjectives(e.target.value)}
              placeholder="Web vulnerability assessment&#10;Network mapping&#10;SSL/TLS analysis"
              className="w-full px-3 py-2 border border-gray-300 rounded-md h-24 focus:outline-none focus:ring-2 focus:ring-indigo-500"
            />
          </div>

          <button
            onClick={() => scanPlanMutation.mutate()}
            disabled={!scanTargets || !scanObjectives || scanPlanMutation.isPending}
            className="px-4 py-2 bg-indigo-600 text-white rounded-md hover:bg-indigo-700 disabled:bg-gray-300"
          >
            {scanPlanMutation.isPending ? 'Planning...' : 'Generate Scan Plan'}
          </button>

          {scanPlan && (
            <div className="mt-4 p-4 bg-gray-50 rounded-md">
              <h3 className="font-semibold mb-2">Recommended Scan Plan</h3>
              <p><strong>Estimated Duration:</strong> {scanPlan.estimated_duration}</p>
              <p className="mt-2"><strong>Recommended Scans:</strong></p>
              <ol className="list-decimal pl-5 text-sm space-y-1">
                {scanPlan.recommended_scans.map((scan, i) => (
                  <li key={i}>{scan}</li>
                ))}
              </ol>
              {scanPlan.risk_factors.length > 0 && (
                <>
                  <p className="mt-2"><strong>Risk Factors:</strong></p>
                  <ul className="list-disc pl-5 text-sm">
                    {scanPlan.risk_factors.map((risk, i) => (
                      <li key={i} className="text-red-600">{risk}</li>
                    ))}
                  </ul>
                </>
              )}
            </div>
          )}
        </div>
      </div>

      {/* Exploit Analysis Section */}
      <div className="bg-white rounded-lg shadow p-6">
        <h2 className="text-xl font-semibold mb-4">🔍 Exploit Code Analysis</h2>
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Exploit Code
            </label>
            <textarea
              value={exploitCode}
              onChange={(e) => setExploitCode(e.target.value)}
              placeholder="Paste exploit code here..."
              className="w-full px-3 py-2 border border-gray-300 rounded-md h-32 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Context (optional)
            </label>
            <input
              type="text"
              value={exploitContext}
              onChange={(e) => setExploitContext(e.target.value)}
              placeholder="e.g., WordPress plugin, PHP file upload vulnerability"
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-indigo-500"
            />
          </div>

          <button
            onClick={() => analyzeExploitMutation.mutate()}
            disabled={!exploitCode || analyzeExploitMutation.isPending}
            className="px-4 py-2 bg-indigo-600 text-white rounded-md hover:bg-indigo-700 disabled:bg-gray-300"
          >
            {analyzeExploitMutation.isPending ? 'Analyzing...' : 'Analyze Exploit'}
          </button>

          {exploitAnalysis && (
            <div className="mt-4 p-4 bg-gray-50 rounded-md">
              <h3 className="font-semibold mb-2">Analysis Results</h3>
              <div className="space-y-2 text-sm">
                <p><strong>Vulnerability:</strong> {exploitAnalysis.vulnerability_id}</p>
                <p><strong>Impact:</strong> <span className="text-red-600">{exploitAnalysis.impact_assessment}</span></p>
                <p><strong>Attack Flow:</strong></p>
                <p className="whitespace-pre-wrap bg-white p-2 rounded">{exploitAnalysis.attack_flow}</p>
                <p><strong>MITRE ATT&CK Techniques:</strong></p>
                <ul className="list-disc pl-5">
                  {exploitAnalysis.mitre_techniques.map((tech, i) => (
                    <li key={i}>{tech}</li>
                  ))}
                </ul>
                <p><strong>Mitigations:</strong></p>
                <ul className="list-disc pl-5">
                  {exploitAnalysis.mitigations.map((mit, i) => (
                    <li key={i}>{mit}</li>
                  ))}
                </ul>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Policy Generation Section */}
      <div className="bg-white rounded-lg shadow p-6">
        <h2 className="text-xl font-semibold mb-4">📋 Security Policy Generator</h2>
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Policy Type
            </label>
            <select
              value={policyType}
              onChange={(e) => setPolicyType(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-indigo-500"
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
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Organization Name
            </label>
            <input
              type="text"
              value={organization}
              onChange={(e) => setOrganization(e.target.value)}
              placeholder="Acme Corporation"
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-indigo-500"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Compliance Frameworks (comma-separated)
            </label>
            <input
              type="text"
              value={frameworks}
              onChange={(e) => setFrameworks(e.target.value)}
              placeholder="PCI-DSS, SOC 2, NIST CSF, HIPAA"
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-indigo-500"
            />
          </div>

          <button
            onClick={() => generatePolicyMutation.mutate()}
            disabled={!organization || generatePolicyMutation.isPending}
            className="px-4 py-2 bg-indigo-600 text-white rounded-md hover:bg-indigo-700 disabled:bg-gray-300"
          >
            {generatePolicyMutation.isPending ? 'Generating...' : 'Generate Policy'}
          </button>

          {generatedPolicy && (
            <div className="mt-4 p-4 bg-gray-50 rounded-md">
              <h3 className="font-semibold mb-2">{generatedPolicy.title}</h3>
              <p className="text-sm text-gray-600 mb-2">Review Schedule: {generatedPolicy.review_schedule}</p>
              <div className="bg-white p-4 rounded text-sm whitespace-pre-wrap max-h-96 overflow-y-auto">
                {generatedPolicy.content}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Remediation Guidance Section */}
      <div className="bg-white rounded-lg shadow p-6">
        <h2 className="text-xl font-semibold mb-4">🔧 Remediation Guidance</h2>
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Vulnerability Description
            </label>
            <input
              type="text"
              value={vulnerability}
              onChange={(e) => setVulnerability(e.target.value)}
              placeholder="e.g., SQL Injection in login form"
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-indigo-500"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Context
            </label>
            <textarea
              value={vulnContext}
              onChange={(e) => setVulnContext(e.target.value)}
              placeholder="Additional context: affected system, technology stack, environment details..."
              className="w-full px-3 py-2 border border-gray-300 rounded-md h-24 focus:outline-none focus:ring-2 focus:ring-indigo-500"
            />
          </div>

          <button
            onClick={() => remediationMutation.mutate()}
            disabled={!vulnerability || !vulnContext || remediationMutation.isPending}
            className="px-4 py-2 bg-indigo-600 text-white rounded-md hover:bg-indigo-700 disabled:bg-gray-300"
          >
            {remediationMutation.isPending ? 'Generating...' : 'Get Guidance'}
          </button>

          {remediation && (
            <div className="mt-4 p-4 bg-gray-50 rounded-md">
              <h3 className="font-semibold mb-2">Remediation Plan</h3>
              <div className="space-y-3 text-sm">
                <div>
                  <p className="font-medium">⚡ Immediate Actions:</p>
                  <ul className="list-disc pl-5 mt-1">
                    {remediation.immediate_actions.map((action, i) => (
                      <li key={i}>{action}</li>
                    ))}
                  </ul>
                </div>
                <div>
                  <p className="font-medium">📝 Detailed Steps:</p>
                  <ol className="list-decimal pl-5 mt-1">
                    {remediation.detailed_steps.map((step, i) => (
                      <li key={i}>{step}</li>
                    ))}
                  </ol>
                </div>
                <div>
                  <p className="font-medium">🛠️ Tools Required:</p>
                  <ul className="list-disc pl-5 mt-1">
                    {remediation.tools_required.map((tool, i) => (
                      <li key={i}>{tool}</li>
                    ))}
                  </ul>
                </div>
                <p><strong>⏱️ Estimated Time:</strong> {remediation.estimated_time}</p>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default AiReportsPage;
