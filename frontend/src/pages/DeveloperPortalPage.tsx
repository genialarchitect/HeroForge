import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import {
  Shield,
  Code,
  Terminal,
  Key,
  Copy,
  Check,
  ExternalLink,
  BookOpen,
  Zap,
  GitBranch,
  Package,
  Webhook,
  Lock,
  Play,
  ChevronRight,
  Download,
  Github,
  Box,
  Layers,
  RefreshCw,
  AlertCircle,
  CheckCircle,
  Eye,
  EyeOff,
  Plus,
  Trash2,
  Settings,
  FileCode,
  Cloud,
  Server,
} from 'lucide-react';

interface ApiKey {
  id: string;
  name: string;
  prefix: string;
  created: string;
  lastUsed: string | null;
  scopes: string[];
}

interface CodeExample {
  language: string;
  label: string;
  code: string;
}

const apiKeys: ApiKey[] = [
  {
    id: '1',
    name: 'Production API Key',
    prefix: 'hf_prod_',
    created: '2026-01-10',
    lastUsed: '2026-01-20',
    scopes: ['scans:read', 'scans:write', 'assets:read', 'reports:read'],
  },
  {
    id: '2',
    name: 'CI/CD Pipeline Key',
    prefix: 'hf_ci_',
    created: '2026-01-15',
    lastUsed: '2026-01-19',
    scopes: ['scans:write', 'reports:read'],
  },
];

const quickStartExamples: CodeExample[] = [
  {
    language: 'python',
    label: 'Python',
    code: `from heroforge import HeroForge

# Initialize the client
client = HeroForge(api_key="hf_your_api_key")

# Create a new scan
scan = client.scans.create(
    target="192.168.1.0/24",
    scan_type="comprehensive",
    name="Network Assessment Q1"
)

# Wait for completion
scan.wait()

# Get results
print(f"Found {len(scan.vulnerabilities)} vulnerabilities")
for vuln in scan.vulnerabilities:
    print(f"  [{vuln.severity}] {vuln.title}")

# Generate report
report = scan.generate_report(format="pdf")
report.download("assessment_report.pdf")`,
  },
  {
    language: 'javascript',
    label: 'Node.js',
    code: `const HeroForge = require('heroforge');

// Initialize the client
const client = new HeroForge({ apiKey: 'hf_your_api_key' });

// Create a new scan
const scan = await client.scans.create({
  target: 'example.com',
  scanType: 'quick',
  name: 'Web App Scan'
});

// Wait for completion
await scan.wait();

// Get results
console.log(\`Found \${scan.vulnerabilities.length} vulnerabilities\`);
scan.vulnerabilities.forEach(vuln => {
  console.log(\`  [\${vuln.severity}] \${vuln.title}\`);
});

// Generate report
const report = await scan.generateReport({ format: 'html' });
await report.download('report.html');`,
  },
  {
    language: 'bash',
    label: 'cURL',
    code: `# Create a new scan
curl -X POST https://api.heroforge.io/v1/scans \\
  -H "Authorization: Bearer hf_your_api_key" \\
  -H "Content-Type: application/json" \\
  -d '{
    "target": "192.168.1.0/24",
    "scan_type": "quick",
    "name": "Quick Network Scan"
  }'

# Get scan status
curl https://api.heroforge.io/v1/scans/{scan_id} \\
  -H "Authorization: Bearer hf_your_api_key"

# Get vulnerabilities
curl https://api.heroforge.io/v1/scans/{scan_id}/vulnerabilities \\
  -H "Authorization: Bearer hf_your_api_key"

# Download report
curl https://api.heroforge.io/v1/scans/{scan_id}/report?format=pdf \\
  -H "Authorization: Bearer hf_your_api_key" \\
  -o report.pdf`,
  },
  {
    language: 'go',
    label: 'Go',
    code: `package main

import (
    "fmt"
    "github.com/heroforge/heroforge-go"
)

func main() {
    // Initialize the client
    client := heroforge.NewClient("hf_your_api_key")

    // Create a new scan
    scan, err := client.Scans.Create(&heroforge.ScanRequest{
        Target:   "10.0.0.0/24",
        ScanType: heroforge.ScanTypeComprehensive,
        Name:     "Infrastructure Scan",
    })
    if err != nil {
        panic(err)
    }

    // Wait for completion
    scan.Wait()

    // Print results
    fmt.Printf("Found %d vulnerabilities\\n", len(scan.Vulnerabilities))
    for _, v := range scan.Vulnerabilities {
        fmt.Printf("  [%s] %s\\n", v.Severity, v.Title)
    }
}`,
  },
];

const cicdExamples = {
  github: `name: Security Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run HeroForge Scan
        uses: heroforge/scan-action@v1
        with:
          api-key: \${{ secrets.HEROFORGE_API_KEY }}
          target: \${{ github.event.repository.name }}
          scan-type: quick
          fail-on: critical

      - name: Upload Results
        uses: actions/upload-artifact@v4
        with:
          name: heroforge-report
          path: heroforge-report.html`,
  gitlab: `security-scan:
  stage: test
  image: heroforge/scanner:latest
  variables:
    HEROFORGE_API_KEY: $HEROFORGE_API_KEY
  script:
    - heroforge scan --target $CI_PROJECT_NAME
      --scan-type quick
      --output report.html
      --fail-on critical
  artifacts:
    paths:
      - report.html
    reports:
      sast: heroforge-gl-sast.json
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == "main"`,
  jenkins: `pipeline {
    agent any

    environment {
        HEROFORGE_API_KEY = credentials('heroforge-api-key')
    }

    stages {
        stage('Security Scan') {
            steps {
                sh '''
                    heroforge scan \\
                        --target ${JOB_NAME} \\
                        --scan-type comprehensive \\
                        --output heroforge-report.html \\
                        --fail-on high
                '''
            }
            post {
                always {
                    archiveArtifacts artifacts: 'heroforge-report.html'
                    publishHTML([
                        reportName: 'HeroForge Security Report',
                        reportDir: '.',
                        reportFiles: 'heroforge-report.html'
                    ])
                }
            }
        }
    }
}`,
  azure: `trigger:
  - main

pool:
  vmImage: 'ubuntu-latest'

steps:
  - task: HeroForgeScan@1
    inputs:
      apiKey: $(HEROFORGE_API_KEY)
      target: $(Build.Repository.Name)
      scanType: 'quick'
      failOn: 'critical'

  - task: PublishBuildArtifacts@1
    inputs:
      pathToPublish: 'heroforge-report.html'
      artifactName: 'SecurityReport'`,
};

const webhookEvents = [
  { event: 'scan.started', description: 'Triggered when a scan begins' },
  { event: 'scan.completed', description: 'Triggered when a scan finishes successfully' },
  { event: 'scan.failed', description: 'Triggered when a scan fails' },
  { event: 'vulnerability.found', description: 'Triggered for each vulnerability discovered' },
  { event: 'vulnerability.critical', description: 'Triggered only for critical vulnerabilities' },
  { event: 'report.generated', description: 'Triggered when a report is ready' },
  { event: 'asset.discovered', description: 'Triggered when new assets are found' },
  { event: 'compliance.violation', description: 'Triggered for compliance violations' },
];

export default function DeveloperPortalPage() {
  const [activeTab, setActiveTab] = useState<'overview' | 'sdk' | 'api' | 'cicd' | 'webhooks' | 'keys'>('overview');
  const [activeLanguage, setActiveLanguage] = useState('python');
  const [activeCicd, setActiveCicd] = useState<'github' | 'gitlab' | 'jenkins' | 'azure'>('github');
  const [copiedCode, setCopiedCode] = useState<string | null>(null);
  const [showApiKey, setShowApiKey] = useState<string | null>(null);
  const [showNewKeyModal, setShowNewKeyModal] = useState(false);

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedCode(id);
    setTimeout(() => setCopiedCode(null), 2000);
  };

  const tabs = [
    { id: 'overview', label: 'Overview', icon: <BookOpen className="w-4 h-4" /> },
    { id: 'sdk', label: 'SDKs', icon: <Package className="w-4 h-4" /> },
    { id: 'api', label: 'REST API', icon: <Code className="w-4 h-4" /> },
    { id: 'cicd', label: 'CI/CD', icon: <GitBranch className="w-4 h-4" /> },
    { id: 'webhooks', label: 'Webhooks', icon: <Webhook className="w-4 h-4" /> },
    { id: 'keys', label: 'API Keys', icon: <Key className="w-4 h-4" /> },
  ];

  return (
    <div className="min-h-screen bg-gray-900">
      {/* Header */}
      <header className="bg-gray-800 border-b border-gray-700">
        <div className="max-w-7xl mx-auto px-4 py-4">
          <div className="flex items-center justify-between">
            <Link to="/" className="flex items-center gap-2">
              <Shield className="w-8 h-8 text-cyan-500" />
              <span className="text-xl font-bold text-white">HeroForge</span>
              <span className="text-gray-500 ml-2">| Developers</span>
            </Link>
            <nav className="hidden md:flex items-center gap-6">
              <Link to="/docs" className="text-gray-300 hover:text-white">Docs</Link>
              <a href="https://github.com/heroforge" className="text-gray-300 hover:text-white flex items-center gap-1">
                <Github className="w-4 h-4" />
                GitHub
              </a>
              <Link to="/login" className="px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg">Sign In</Link>
            </nav>
          </div>
        </div>
      </header>

      {/* Hero Section */}
      <section className="py-12 bg-gradient-to-b from-gray-800 to-gray-900 border-b border-gray-700">
        <div className="max-w-7xl mx-auto px-4">
          <div className="flex items-center gap-3 mb-4">
            <div className="p-2 bg-cyan-500/20 rounded-lg">
              <Terminal className="w-6 h-6 text-cyan-500" />
            </div>
            <h1 className="text-3xl font-bold text-white">Developer Portal</h1>
          </div>
          <p className="text-xl text-gray-400 max-w-2xl">
            Integrate HeroForge security scanning into your applications, pipelines, and workflows.
          </p>
        </div>
      </section>

      {/* Navigation Tabs */}
      <div className="bg-gray-800 border-b border-gray-700 sticky top-0 z-10">
        <div className="max-w-7xl mx-auto px-4">
          <nav className="flex gap-1 overflow-x-auto">
            {tabs.map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as typeof activeTab)}
                className={`flex items-center gap-2 px-4 py-3 text-sm font-medium border-b-2 transition-colors whitespace-nowrap ${
                  activeTab === tab.id
                    ? 'text-cyan-400 border-cyan-400'
                    : 'text-gray-400 border-transparent hover:text-white'
                }`}
              >
                {tab.icon}
                {tab.label}
              </button>
            ))}
          </nav>
        </div>
      </div>

      {/* Content */}
      <div className="max-w-7xl mx-auto px-4 py-8">
        {/* Overview Tab */}
        {activeTab === 'overview' && (
          <div className="space-y-8">
            {/* Quick Links */}
            <div className="grid md:grid-cols-4 gap-4">
              <button
                onClick={() => setActiveTab('sdk')}
                className="p-6 bg-gray-800 rounded-xl border border-gray-700 hover:border-cyan-500/50 transition-colors text-left group"
              >
                <Package className="w-8 h-8 text-cyan-500 mb-3" />
                <h3 className="text-lg font-semibold text-white mb-1">SDKs</h3>
                <p className="text-sm text-gray-400">Python, Node.js, Go libraries</p>
                <ChevronRight className="w-5 h-5 text-gray-500 group-hover:text-cyan-500 mt-2" />
              </button>
              <button
                onClick={() => setActiveTab('api')}
                className="p-6 bg-gray-800 rounded-xl border border-gray-700 hover:border-cyan-500/50 transition-colors text-left group"
              >
                <Code className="w-8 h-8 text-purple-500 mb-3" />
                <h3 className="text-lg font-semibold text-white mb-1">REST API</h3>
                <p className="text-sm text-gray-400">Full API reference docs</p>
                <ChevronRight className="w-5 h-5 text-gray-500 group-hover:text-cyan-500 mt-2" />
              </button>
              <button
                onClick={() => setActiveTab('cicd')}
                className="p-6 bg-gray-800 rounded-xl border border-gray-700 hover:border-cyan-500/50 transition-colors text-left group"
              >
                <GitBranch className="w-8 h-8 text-green-500 mb-3" />
                <h3 className="text-lg font-semibold text-white mb-1">CI/CD</h3>
                <p className="text-sm text-gray-400">GitHub, GitLab, Jenkins</p>
                <ChevronRight className="w-5 h-5 text-gray-500 group-hover:text-cyan-500 mt-2" />
              </button>
              <button
                onClick={() => setActiveTab('webhooks')}
                className="p-6 bg-gray-800 rounded-xl border border-gray-700 hover:border-cyan-500/50 transition-colors text-left group"
              >
                <Webhook className="w-8 h-8 text-amber-500 mb-3" />
                <h3 className="text-lg font-semibold text-white mb-1">Webhooks</h3>
                <p className="text-sm text-gray-400">Real-time event notifications</p>
                <ChevronRight className="w-5 h-5 text-gray-500 group-hover:text-cyan-500 mt-2" />
              </button>
            </div>

            {/* Quick Start */}
            <div className="bg-gray-800 rounded-xl border border-gray-700 overflow-hidden">
              <div className="p-6 border-b border-gray-700">
                <h2 className="text-xl font-bold text-white">Quick Start</h2>
                <p className="text-gray-400 mt-1">Get up and running in minutes</p>
              </div>

              {/* Language Tabs */}
              <div className="border-b border-gray-700">
                <div className="flex gap-1 px-4 pt-2">
                  {quickStartExamples.map((example) => (
                    <button
                      key={example.language}
                      onClick={() => setActiveLanguage(example.language)}
                      className={`px-4 py-2 text-sm font-medium rounded-t-lg transition-colors ${
                        activeLanguage === example.language
                          ? 'bg-gray-900 text-cyan-400'
                          : 'text-gray-400 hover:text-white'
                      }`}
                    >
                      {example.label}
                    </button>
                  ))}
                </div>
              </div>

              {/* Code Block */}
              <div className="relative">
                <button
                  onClick={() => copyToClipboard(
                    quickStartExamples.find(e => e.language === activeLanguage)?.code || '',
                    'quickstart'
                  )}
                  className="absolute top-4 right-4 p-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-gray-400 hover:text-white"
                >
                  {copiedCode === 'quickstart' ? <Check className="w-4 h-4 text-green-500" /> : <Copy className="w-4 h-4" />}
                </button>
                <pre className="p-6 bg-gray-900 text-gray-300 overflow-x-auto">
                  <code>{quickStartExamples.find(e => e.language === activeLanguage)?.code}</code>
                </pre>
              </div>

              {/* Install Command */}
              <div className="p-4 bg-gray-700/50 border-t border-gray-700">
                <p className="text-sm text-gray-400 mb-2">Install the SDK:</p>
                <div className="flex items-center gap-2">
                  <code className="flex-1 px-3 py-2 bg-gray-900 rounded text-cyan-400 text-sm font-mono">
                    {activeLanguage === 'python' && 'pip install heroforge'}
                    {activeLanguage === 'javascript' && 'npm install heroforge'}
                    {activeLanguage === 'go' && 'go get github.com/heroforge/heroforge-go'}
                    {activeLanguage === 'bash' && '# No installation required - use cURL directly'}
                  </code>
                  <button
                    onClick={() => copyToClipboard(
                      activeLanguage === 'python' ? 'pip install heroforge' :
                      activeLanguage === 'javascript' ? 'npm install heroforge' :
                      activeLanguage === 'go' ? 'go get github.com/heroforge/heroforge-go' : '',
                      'install'
                    )}
                    className="p-2 bg-gray-600 hover:bg-gray-500 rounded text-gray-300"
                  >
                    {copiedCode === 'install' ? <Check className="w-4 h-4 text-green-500" /> : <Copy className="w-4 h-4" />}
                  </button>
                </div>
              </div>
            </div>

            {/* Features Grid */}
            <div className="grid md:grid-cols-3 gap-6">
              <div className="bg-gray-800 rounded-xl p-6 border border-gray-700">
                <Zap className="w-8 h-8 text-amber-500 mb-4" />
                <h3 className="text-lg font-semibold text-white mb-2">Rate Limiting</h3>
                <p className="text-gray-400 text-sm mb-4">
                  Free tier: 100 requests/hour. Pro: 1,000/hour. Enterprise: Unlimited.
                </p>
                <a href="#" className="text-cyan-400 text-sm hover:underline">View limits →</a>
              </div>
              <div className="bg-gray-800 rounded-xl p-6 border border-gray-700">
                <Lock className="w-8 h-8 text-green-500 mb-4" />
                <h3 className="text-lg font-semibold text-white mb-2">Authentication</h3>
                <p className="text-gray-400 text-sm mb-4">
                  API keys with granular scopes. OAuth 2.0 for user-context operations.
                </p>
                <a href="#" className="text-cyan-400 text-sm hover:underline">Auth guide →</a>
              </div>
              <div className="bg-gray-800 rounded-xl p-6 border border-gray-700">
                <RefreshCw className="w-8 h-8 text-purple-500 mb-4" />
                <h3 className="text-lg font-semibold text-white mb-2">Versioning</h3>
                <p className="text-gray-400 text-sm mb-4">
                  Current version: v1. We maintain backward compatibility for 12 months.
                </p>
                <a href="#" className="text-cyan-400 text-sm hover:underline">Changelog →</a>
              </div>
            </div>
          </div>
        )}

        {/* SDK Tab */}
        {activeTab === 'sdk' && (
          <div className="space-y-8">
            <div>
              <h2 className="text-2xl font-bold text-white mb-2">Official SDKs</h2>
              <p className="text-gray-400">Native libraries for popular programming languages</p>
            </div>

            <div className="grid md:grid-cols-2 gap-6">
              {/* Python SDK */}
              <div className="bg-gray-800 rounded-xl border border-gray-700 overflow-hidden">
                <div className="p-6 border-b border-gray-700">
                  <div className="flex items-center gap-3 mb-4">
                    <div className="w-12 h-12 bg-blue-500/20 rounded-lg flex items-center justify-center">
                      <FileCode className="w-6 h-6 text-blue-500" />
                    </div>
                    <div>
                      <h3 className="text-lg font-semibold text-white">Python SDK</h3>
                      <p className="text-sm text-gray-400">heroforge-python</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-4 text-sm">
                    <span className="text-gray-400">v2.1.0</span>
                    <span className="text-green-400">● Stable</span>
                    <span className="text-gray-400">Python 3.8+</span>
                  </div>
                </div>
                <div className="p-4 bg-gray-900">
                  <code className="text-cyan-400 text-sm">pip install heroforge</code>
                </div>
                <div className="p-4 flex gap-3">
                  <a href="#" className="flex items-center gap-1 text-sm text-gray-400 hover:text-white">
                    <Github className="w-4 h-4" /> GitHub
                  </a>
                  <a href="#" className="flex items-center gap-1 text-sm text-gray-400 hover:text-white">
                    <BookOpen className="w-4 h-4" /> Docs
                  </a>
                  <a href="#" className="flex items-center gap-1 text-sm text-gray-400 hover:text-white">
                    <ExternalLink className="w-4 h-4" /> PyPI
                  </a>
                </div>
              </div>

              {/* Node.js SDK */}
              <div className="bg-gray-800 rounded-xl border border-gray-700 overflow-hidden">
                <div className="p-6 border-b border-gray-700">
                  <div className="flex items-center gap-3 mb-4">
                    <div className="w-12 h-12 bg-green-500/20 rounded-lg flex items-center justify-center">
                      <Box className="w-6 h-6 text-green-500" />
                    </div>
                    <div>
                      <h3 className="text-lg font-semibold text-white">Node.js SDK</h3>
                      <p className="text-sm text-gray-400">heroforge</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-4 text-sm">
                    <span className="text-gray-400">v2.0.3</span>
                    <span className="text-green-400">● Stable</span>
                    <span className="text-gray-400">Node 18+</span>
                  </div>
                </div>
                <div className="p-4 bg-gray-900">
                  <code className="text-cyan-400 text-sm">npm install heroforge</code>
                </div>
                <div className="p-4 flex gap-3">
                  <a href="#" className="flex items-center gap-1 text-sm text-gray-400 hover:text-white">
                    <Github className="w-4 h-4" /> GitHub
                  </a>
                  <a href="#" className="flex items-center gap-1 text-sm text-gray-400 hover:text-white">
                    <BookOpen className="w-4 h-4" /> Docs
                  </a>
                  <a href="#" className="flex items-center gap-1 text-sm text-gray-400 hover:text-white">
                    <ExternalLink className="w-4 h-4" /> npm
                  </a>
                </div>
              </div>

              {/* Go SDK */}
              <div className="bg-gray-800 rounded-xl border border-gray-700 overflow-hidden">
                <div className="p-6 border-b border-gray-700">
                  <div className="flex items-center gap-3 mb-4">
                    <div className="w-12 h-12 bg-cyan-500/20 rounded-lg flex items-center justify-center">
                      <Layers className="w-6 h-6 text-cyan-500" />
                    </div>
                    <div>
                      <h3 className="text-lg font-semibold text-white">Go SDK</h3>
                      <p className="text-sm text-gray-400">heroforge-go</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-4 text-sm">
                    <span className="text-gray-400">v1.5.0</span>
                    <span className="text-green-400">● Stable</span>
                    <span className="text-gray-400">Go 1.21+</span>
                  </div>
                </div>
                <div className="p-4 bg-gray-900">
                  <code className="text-cyan-400 text-sm">go get github.com/heroforge/heroforge-go</code>
                </div>
                <div className="p-4 flex gap-3">
                  <a href="#" className="flex items-center gap-1 text-sm text-gray-400 hover:text-white">
                    <Github className="w-4 h-4" /> GitHub
                  </a>
                  <a href="#" className="flex items-center gap-1 text-sm text-gray-400 hover:text-white">
                    <BookOpen className="w-4 h-4" /> Docs
                  </a>
                  <a href="#" className="flex items-center gap-1 text-sm text-gray-400 hover:text-white">
                    <ExternalLink className="w-4 h-4" /> pkg.go.dev
                  </a>
                </div>
              </div>

              {/* CLI Tool */}
              <div className="bg-gray-800 rounded-xl border border-gray-700 overflow-hidden">
                <div className="p-6 border-b border-gray-700">
                  <div className="flex items-center gap-3 mb-4">
                    <div className="w-12 h-12 bg-purple-500/20 rounded-lg flex items-center justify-center">
                      <Terminal className="w-6 h-6 text-purple-500" />
                    </div>
                    <div>
                      <h3 className="text-lg font-semibold text-white">CLI Tool</h3>
                      <p className="text-sm text-gray-400">heroforge-cli</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-4 text-sm">
                    <span className="text-gray-400">v3.2.1</span>
                    <span className="text-green-400">● Stable</span>
                    <span className="text-gray-400">Linux, macOS, Windows</span>
                  </div>
                </div>
                <div className="p-4 bg-gray-900">
                  <code className="text-cyan-400 text-sm">brew install heroforge/tap/heroforge</code>
                </div>
                <div className="p-4 flex gap-3">
                  <a href="#" className="flex items-center gap-1 text-sm text-gray-400 hover:text-white">
                    <Github className="w-4 h-4" /> GitHub
                  </a>
                  <a href="#" className="flex items-center gap-1 text-sm text-gray-400 hover:text-white">
                    <BookOpen className="w-4 h-4" /> Docs
                  </a>
                  <a href="#" className="flex items-center gap-1 text-sm text-gray-400 hover:text-white">
                    <Download className="w-4 h-4" /> Releases
                  </a>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* API Tab */}
        {activeTab === 'api' && (
          <div className="space-y-8">
            <div>
              <h2 className="text-2xl font-bold text-white mb-2">REST API Reference</h2>
              <p className="text-gray-400">Base URL: <code className="text-cyan-400">https://api.heroforge.io/v1</code></p>
            </div>

            {/* Endpoints */}
            <div className="bg-gray-800 rounded-xl border border-gray-700 overflow-hidden">
              <div className="p-4 border-b border-gray-700">
                <h3 className="font-semibold text-white">Endpoints</h3>
              </div>
              <div className="divide-y divide-gray-700">
                {[
                  { method: 'GET', path: '/scans', description: 'List all scans' },
                  { method: 'POST', path: '/scans', description: 'Create a new scan' },
                  { method: 'GET', path: '/scans/{id}', description: 'Get scan details' },
                  { method: 'DELETE', path: '/scans/{id}', description: 'Delete a scan' },
                  { method: 'GET', path: '/scans/{id}/vulnerabilities', description: 'Get scan vulnerabilities' },
                  { method: 'GET', path: '/scans/{id}/report', description: 'Generate/download report' },
                  { method: 'GET', path: '/assets', description: 'List all assets' },
                  { method: 'POST', path: '/assets', description: 'Create an asset' },
                  { method: 'GET', path: '/vulnerabilities', description: 'List all vulnerabilities' },
                  { method: 'PATCH', path: '/vulnerabilities/{id}', description: 'Update vulnerability status' },
                ].map((endpoint, idx) => (
                  <div key={idx} className="p-4 flex items-center gap-4 hover:bg-gray-700/50">
                    <span className={`px-2 py-1 rounded text-xs font-mono font-bold ${
                      endpoint.method === 'GET' ? 'bg-green-500/20 text-green-400' :
                      endpoint.method === 'POST' ? 'bg-blue-500/20 text-blue-400' :
                      endpoint.method === 'PATCH' ? 'bg-amber-500/20 text-amber-400' :
                      'bg-red-500/20 text-red-400'
                    }`}>
                      {endpoint.method}
                    </span>
                    <code className="text-gray-300 font-mono text-sm">{endpoint.path}</code>
                    <span className="text-gray-500 text-sm ml-auto">{endpoint.description}</span>
                  </div>
                ))}
              </div>
              <div className="p-4 bg-gray-700/50 border-t border-gray-700">
                <Link to="/docs/api" className="text-cyan-400 text-sm hover:underline flex items-center gap-1">
                  View full API documentation <ExternalLink className="w-4 h-4" />
                </Link>
              </div>
            </div>

            {/* Authentication */}
            <div className="bg-gray-800 rounded-xl border border-gray-700 p-6">
              <h3 className="font-semibold text-white mb-4">Authentication</h3>
              <p className="text-gray-400 mb-4">
                Include your API key in the Authorization header:
              </p>
              <div className="bg-gray-900 rounded-lg p-4">
                <code className="text-gray-300">
                  Authorization: Bearer <span className="text-cyan-400">hf_your_api_key</span>
                </code>
              </div>
            </div>
          </div>
        )}

        {/* CI/CD Tab */}
        {activeTab === 'cicd' && (
          <div className="space-y-8">
            <div>
              <h2 className="text-2xl font-bold text-white mb-2">CI/CD Integrations</h2>
              <p className="text-gray-400">Integrate security scanning into your development pipeline</p>
            </div>

            {/* Platform Tabs */}
            <div className="bg-gray-800 rounded-xl border border-gray-700 overflow-hidden">
              <div className="border-b border-gray-700">
                <div className="flex gap-1 px-4 pt-2">
                  {[
                    { id: 'github', label: 'GitHub Actions', icon: <Github className="w-4 h-4" /> },
                    { id: 'gitlab', label: 'GitLab CI', icon: <GitBranch className="w-4 h-4" /> },
                    { id: 'jenkins', label: 'Jenkins', icon: <Server className="w-4 h-4" /> },
                    { id: 'azure', label: 'Azure DevOps', icon: <Cloud className="w-4 h-4" /> },
                  ].map((platform) => (
                    <button
                      key={platform.id}
                      onClick={() => setActiveCicd(platform.id as typeof activeCicd)}
                      className={`flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-t-lg transition-colors ${
                        activeCicd === platform.id
                          ? 'bg-gray-900 text-cyan-400'
                          : 'text-gray-400 hover:text-white'
                      }`}
                    >
                      {platform.icon}
                      {platform.label}
                    </button>
                  ))}
                </div>
              </div>

              <div className="relative">
                <button
                  onClick={() => copyToClipboard(cicdExamples[activeCicd], `cicd-${activeCicd}`)}
                  className="absolute top-4 right-4 p-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-gray-400 hover:text-white"
                >
                  {copiedCode === `cicd-${activeCicd}` ? <Check className="w-4 h-4 text-green-500" /> : <Copy className="w-4 h-4" />}
                </button>
                <pre className="p-6 bg-gray-900 text-gray-300 overflow-x-auto text-sm">
                  <code>{cicdExamples[activeCicd]}</code>
                </pre>
              </div>
            </div>

            {/* Features */}
            <div className="grid md:grid-cols-3 gap-6">
              <div className="bg-gray-800 rounded-xl p-6 border border-gray-700">
                <AlertCircle className="w-8 h-8 text-red-500 mb-4" />
                <h3 className="text-lg font-semibold text-white mb-2">Fail on Severity</h3>
                <p className="text-gray-400 text-sm">
                  Configure your pipeline to fail builds when critical or high severity vulnerabilities are found.
                </p>
              </div>
              <div className="bg-gray-800 rounded-xl p-6 border border-gray-700">
                <FileCode className="w-8 h-8 text-cyan-500 mb-4" />
                <h3 className="text-lg font-semibold text-white mb-2">SARIF Export</h3>
                <p className="text-gray-400 text-sm">
                  Export results in SARIF format for GitHub Security tab integration.
                </p>
              </div>
              <div className="bg-gray-800 rounded-xl p-6 border border-gray-700">
                <CheckCircle className="w-8 h-8 text-green-500 mb-4" />
                <h3 className="text-lg font-semibold text-white mb-2">PR Comments</h3>
                <p className="text-gray-400 text-sm">
                  Automatically comment on pull requests with scan results summary.
                </p>
              </div>
            </div>
          </div>
        )}

        {/* Webhooks Tab */}
        {activeTab === 'webhooks' && (
          <div className="space-y-8">
            <div>
              <h2 className="text-2xl font-bold text-white mb-2">Webhooks</h2>
              <p className="text-gray-400">Receive real-time notifications for scan events</p>
            </div>

            {/* Events Table */}
            <div className="bg-gray-800 rounded-xl border border-gray-700 overflow-hidden">
              <div className="p-4 border-b border-gray-700">
                <h3 className="font-semibold text-white">Available Events</h3>
              </div>
              <div className="divide-y divide-gray-700">
                {webhookEvents.map((event, idx) => (
                  <div key={idx} className="p-4 flex items-center gap-4">
                    <code className="text-cyan-400 font-mono text-sm bg-gray-900 px-2 py-1 rounded">{event.event}</code>
                    <span className="text-gray-400 text-sm">{event.description}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Example Payload */}
            <div className="bg-gray-800 rounded-xl border border-gray-700 overflow-hidden">
              <div className="p-4 border-b border-gray-700">
                <h3 className="font-semibold text-white">Example Payload</h3>
              </div>
              <pre className="p-6 bg-gray-900 text-gray-300 overflow-x-auto text-sm">
                <code>{`{
  "event": "vulnerability.critical",
  "timestamp": "2026-01-20T15:30:00Z",
  "data": {
    "scan_id": "scan_abc123",
    "vulnerability": {
      "id": "vuln_xyz789",
      "cve": "CVE-2026-1234",
      "title": "Remote Code Execution in Example Service",
      "severity": "critical",
      "cvss": 9.8,
      "affected_asset": "192.168.1.100",
      "port": 443
    }
  },
  "signature": "sha256=..."
}`}</code>
              </pre>
            </div>

            {/* Security */}
            <div className="bg-gray-800 rounded-xl p-6 border border-gray-700">
              <h3 className="font-semibold text-white mb-4">Webhook Security</h3>
              <p className="text-gray-400 mb-4">
                All webhooks include an HMAC-SHA256 signature in the <code className="text-cyan-400">X-HeroForge-Signature</code> header.
                Verify this signature to ensure the webhook is authentic.
              </p>
              <pre className="p-4 bg-gray-900 rounded-lg text-gray-300 text-sm">
                <code>{`import hmac
import hashlib

def verify_webhook(payload, signature, secret):
    expected = hmac.new(
        secret.encode(),
        payload.encode(),
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(f"sha256={expected}", signature)`}</code>
              </pre>
            </div>
          </div>
        )}

        {/* API Keys Tab */}
        {activeTab === 'keys' && (
          <div className="space-y-8">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-2xl font-bold text-white mb-2">API Keys</h2>
                <p className="text-gray-400">Manage your API keys and their permissions</p>
              </div>
              <button
                onClick={() => setShowNewKeyModal(true)}
                className="flex items-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg"
              >
                <Plus className="w-5 h-5" />
                Create New Key
              </button>
            </div>

            {/* Keys List */}
            <div className="bg-gray-800 rounded-xl border border-gray-700 overflow-hidden">
              <div className="divide-y divide-gray-700">
                {apiKeys.map((key) => (
                  <div key={key.id} className="p-6">
                    <div className="flex items-start justify-between mb-4">
                      <div>
                        <h3 className="text-lg font-semibold text-white">{key.name}</h3>
                        <div className="flex items-center gap-2 mt-1">
                          <code className="text-gray-400 font-mono text-sm">
                            {showApiKey === key.id ? `${key.prefix}${'x'.repeat(32)}` : `${key.prefix}${'•'.repeat(32)}`}
                          </code>
                          <button
                            onClick={() => setShowApiKey(showApiKey === key.id ? null : key.id)}
                            className="text-gray-500 hover:text-white"
                          >
                            {showApiKey === key.id ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                          </button>
                        </div>
                      </div>
                      <button className="text-red-400 hover:text-red-300 p-2">
                        <Trash2 className="w-5 h-5" />
                      </button>
                    </div>

                    <div className="flex flex-wrap gap-2 mb-4">
                      {key.scopes.map((scope) => (
                        <span key={scope} className="px-2 py-1 bg-gray-700 text-gray-300 rounded text-xs">
                          {scope}
                        </span>
                      ))}
                    </div>

                    <div className="flex items-center gap-6 text-sm text-gray-500">
                      <span>Created: {new Date(key.created).toLocaleDateString()}</span>
                      <span>Last used: {key.lastUsed ? new Date(key.lastUsed).toLocaleDateString() : 'Never'}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Scopes Reference */}
            <div className="bg-gray-800 rounded-xl border border-gray-700 p-6">
              <h3 className="font-semibold text-white mb-4">Available Scopes</h3>
              <div className="grid md:grid-cols-2 gap-4">
                {[
                  { scope: 'scans:read', description: 'Read scan results and history' },
                  { scope: 'scans:write', description: 'Create and manage scans' },
                  { scope: 'assets:read', description: 'View asset inventory' },
                  { scope: 'assets:write', description: 'Create and manage assets' },
                  { scope: 'reports:read', description: 'Generate and download reports' },
                  { scope: 'vulnerabilities:read', description: 'View vulnerability details' },
                  { scope: 'vulnerabilities:write', description: 'Update vulnerability status' },
                  { scope: 'webhooks:manage', description: 'Manage webhook subscriptions' },
                ].map((item) => (
                  <div key={item.scope} className="flex items-center gap-3">
                    <code className="text-cyan-400 font-mono text-sm">{item.scope}</code>
                    <span className="text-gray-400 text-sm">{item.description}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Footer */}
      <footer className="bg-gray-800 border-t border-gray-700 py-8 mt-16">
        <div className="max-w-7xl mx-auto px-4">
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div className="flex items-center gap-6 text-sm text-gray-400">
              <a href="#" className="hover:text-white">API Status</a>
              <a href="#" className="hover:text-white">Changelog</a>
              <a href="#" className="hover:text-white">Support</a>
            </div>
            <p className="text-gray-500 text-sm">&copy; 2026 HeroForge. All rights reserved.</p>
          </div>
        </div>
      </footer>
    </div>
  );
}
