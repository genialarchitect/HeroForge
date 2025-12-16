import React, { useState, useEffect } from 'react';
import { toast } from 'react-toastify';
import { complianceAPI, scanAPI } from '../services/api';
import type {
  ComplianceFramework,
  ComplianceAnalyzeResponse,
  ScanResult,
} from '../types';
import Layout from '../components/layout/Layout';
import Card from '../components/ui/Card';
import LoadingSpinner from '../components/ui/LoadingSpinner';
import Button from '../components/ui/Button';
import FrameworkCard from '../components/compliance/FrameworkCard';
import ComplianceResults from '../components/compliance/ComplianceResults';
import { Shield, AlertCircle, Search } from 'lucide-react';

const CompliancePage: React.FC = () => {
  const [frameworks, setFrameworks] = useState<ComplianceFramework[]>([]);
  const [scans, setScans] = useState<ScanResult[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedScan, setSelectedScan] = useState<string>('');
  const [selectedFrameworks, setSelectedFrameworks] = useState<Set<string>>(new Set());
  const [analyzing, setAnalyzing] = useState(false);
  const [results, setResults] = useState<ComplianceAnalyzeResponse | null>(null);
  const [showResults, setShowResults] = useState(false);

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    setLoading(true);
    try {
      const [frameworksRes, scansRes] = await Promise.all([
        complianceAPI.getFrameworks(),
        scanAPI.getAll(),
      ]);
      setFrameworks(frameworksRes.data.frameworks);
      setScans(scansRes.data.filter((scan) => scan.status === 'completed'));

      // Select common frameworks by default
      setSelectedFrameworks(new Set(['pci_dss', 'nist_800_53', 'owasp_top10']));
    } catch (error) {
      toast.error('Failed to load compliance data');
      console.error(error);
    } finally {
      setLoading(false);
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

  const runAnalysis = async () => {
    if (!selectedScan) {
      toast.warning('Please select a scan');
      return;
    }
    if (selectedFrameworks.size === 0) {
      toast.warning('Please select at least one framework');
      return;
    }

    setAnalyzing(true);
    try {
      const response = await complianceAPI.analyzeScan(selectedScan, {
        frameworks: Array.from(selectedFrameworks) as any,
      });
      setResults(response.data);
      setShowResults(true);
      toast.success('Compliance analysis completed');
    } catch (error: any) {
      toast.error(error.response?.data?.error || 'Analysis failed');
      console.error(error);
    } finally {
      setAnalyzing(false);
    }
  };

  if (loading) {
    return (
      <Layout>
        <div className="flex items-center justify-center py-12">
          <LoadingSpinner />
        </div>
      </Layout>
    );
  }

  if (showResults && results) {
    return (
      <Layout>
        <div className="space-y-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Shield className="h-8 w-8 text-primary" />
              <div>
                <h1 className="text-2xl font-bold text-white">Compliance Analysis Results</h1>
                <p className="text-slate-400">
                  Scan: {scans.find((s) => s.id === selectedScan)?.name}
                </p>
              </div>
            </div>
            <Button variant="secondary" onClick={() => setShowResults(false)}>
              Back to Analysis
            </Button>
          </div>

          <ComplianceResults results={results} scanId={selectedScan} />
        </div>
      </Layout>
    );
  }

  return (
    <Layout>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center gap-3">
          <Shield className="h-8 w-8 text-primary" />
          <div>
            <h1 className="text-2xl font-bold text-white">Compliance Dashboard</h1>
            <p className="text-slate-400">
              Analyze scan results against security compliance frameworks
            </p>
          </div>
        </div>

        {/* Available Frameworks */}
        <Card>
          <div className="mb-6">
            <h2 className="text-xl font-bold text-white mb-2">
              Available Compliance Frameworks
            </h2>
            <p className="text-sm text-slate-400">
              HeroForge supports {frameworks.length} compliance frameworks with automated checks
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {frameworks.map((framework) => (
              <FrameworkCard
                key={framework.id}
                framework={framework}
                isSelected={selectedFrameworks.has(framework.id)}
                onToggle={() => toggleFramework(framework.id)}
              />
            ))}
          </div>
        </Card>

        {/* Scan Selection and Analysis */}
        <Card>
          <h2 className="text-xl font-bold text-white mb-6">Run Compliance Analysis</h2>

          {scans.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-12 text-center">
              <AlertCircle className="h-12 w-12 text-slate-500 mb-4" />
              <p className="text-lg text-slate-400 mb-2">No completed scans available</p>
              <p className="text-sm text-slate-500">
                Run a network scan first to analyze compliance
              </p>
            </div>
          ) : (
            <div className="space-y-6">
              {/* Scan Selection */}
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-2">
                  Select Scan to Analyze
                </label>
                <div className="relative">
                  <select
                    value={selectedScan}
                    onChange={(e) => setSelectedScan(e.target.value)}
                    className="w-full px-4 py-3 bg-dark-bg border border-dark-border rounded-lg text-white focus:ring-2 focus:ring-primary focus:border-transparent appearance-none cursor-pointer"
                  >
                    <option value="">Choose a scan...</option>
                    {scans.map((scan) => (
                      <option key={scan.id} value={scan.id}>
                        {scan.name} - {new Date(scan.created_at).toLocaleDateString()} (
                        {scan.total_hosts} hosts, {scan.total_ports} ports)
                      </option>
                    ))}
                  </select>
                  <Search className="absolute right-3 top-3.5 h-5 w-5 text-slate-400 pointer-events-none" />
                </div>
              </div>

              {/* Selected Frameworks Summary */}
              {selectedFrameworks.size > 0 && (
                <div className="p-4 bg-dark-bg rounded-lg border border-dark-border">
                  <p className="text-sm font-medium text-slate-300 mb-2">
                    Selected Frameworks ({selectedFrameworks.size})
                  </p>
                  <div className="flex flex-wrap gap-2">
                    {Array.from(selectedFrameworks).map((id) => {
                      const framework = frameworks.find((f) => f.id === id);
                      return framework ? (
                        <span
                          key={id}
                          className="inline-flex items-center px-3 py-1 bg-primary/20 text-primary rounded-full text-sm border border-primary/30"
                        >
                          {framework.name}
                        </span>
                      ) : null;
                    })}
                  </div>
                </div>
              )}

              {/* Analysis Button */}
              <div className="flex justify-end">
                <Button
                  onClick={runAnalysis}
                  disabled={analyzing || !selectedScan || selectedFrameworks.size === 0}
                  className="w-full sm:w-auto"
                >
                  {analyzing ? (
                    <>
                      <LoadingSpinner />
                      <span className="ml-2">Analyzing...</span>
                    </>
                  ) : (
                    <>
                      <Shield className="h-4 w-4 mr-2" />
                      Run Compliance Analysis
                    </>
                  )}
                </Button>
              </div>
            </div>
          )}
        </Card>

        {/* Info Card */}
        <Card className="bg-blue-500/10 border-blue-500/30">
          <div className="flex gap-4">
            <AlertCircle className="h-6 w-6 text-blue-400 flex-shrink-0 mt-0.5" />
            <div>
              <h3 className="text-lg font-semibold text-blue-400 mb-2">
                About Compliance Analysis
              </h3>
              <p className="text-sm text-slate-300 mb-2">
                The compliance analysis engine evaluates your scan results against industry
                standard security frameworks. It automatically checks for:
              </p>
              <ul className="text-sm text-slate-300 space-y-1 list-disc list-inside ml-4">
                <li>Open ports and services against framework requirements</li>
                <li>Detected vulnerabilities and their compliance impact</li>
                <li>Security misconfigurations and policy violations</li>
                <li>Missing security controls and recommendations</li>
              </ul>
              <p className="text-sm text-slate-300 mt-3">
                Each framework check is mapped to specific controls and provides detailed
                remediation guidance.
              </p>
            </div>
          </div>
        </Card>
      </div>
    </Layout>
  );
};

export default CompliancePage;
