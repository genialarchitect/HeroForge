import React, { useState, useEffect } from 'react';
import {
  Package,
  Shield,
  AlertTriangle,
  RefreshCw,
  Plus,
  Search,
  FileText,
  ExternalLink,
  ChevronDown,
  ChevronRight,
  Scale,
  GitBranch,
  Download,
  Trash2,
  Play,
  Eye
} from 'lucide-react';
import { toast } from 'react-toastify';
import Layout from '../components/layout/Layout';

// Types
interface ScaProject {
  id: string;
  name: string;
  repository_url?: string;
  ecosystem: string;
  manifest_files?: string[];
  last_scan_at?: string;
  total_dependencies: number;
  vulnerable_dependencies: number;
  license_issues: number;
  customer_id?: string;
  engagement_id?: string;
  created_at: string;
}

interface ScaDependency {
  id: string;
  project_id: string;
  name: string;
  version: string;
  ecosystem: string;
  purl: string;
  is_direct: boolean;
  depth: number;
  license?: string;
  license_risk?: string;
  latest_version?: string;
  update_available: boolean;
}

interface ScaVulnerability {
  id: string;
  dependency_id: string;
  vuln_id: string;
  source: string;
  severity: string;
  cvss_score?: number;
  title?: string;
  description?: string;
  fixed_version?: string;
  exploited_in_wild: boolean;
  status: string;
}

interface ScaStats {
  total_projects: number;
  total_dependencies: number;
  vulnerable_dependencies: number;
  critical_vulns: number;
  high_vulns: number;
  medium_vulns: number;
  low_vulns: number;
  license_issues: number;
  updates_available: number;
}

// Mock API
const scaAPI = {
  getStats: async (): Promise<ScaStats> => {
    return {
      total_projects: 5,
      total_dependencies: 342,
      vulnerable_dependencies: 23,
      critical_vulns: 2,
      high_vulns: 8,
      medium_vulns: 12,
      low_vulns: 15,
      license_issues: 4,
      updates_available: 45
    };
  },
  getProjects: async (): Promise<ScaProject[]> => {
    return [
      {
        id: '1',
        name: 'heroforge-backend',
        repository_url: 'https://github.com/org/heroforge',
        ecosystem: 'cargo',
        manifest_files: ['Cargo.toml', 'Cargo.lock'],
        last_scan_at: new Date().toISOString(),
        total_dependencies: 156,
        vulnerable_dependencies: 8,
        license_issues: 2,
        created_at: new Date().toISOString()
      },
      {
        id: '2',
        name: 'heroforge-frontend',
        repository_url: 'https://github.com/org/heroforge-frontend',
        ecosystem: 'npm',
        manifest_files: ['package.json', 'package-lock.json'],
        last_scan_at: new Date().toISOString(),
        total_dependencies: 186,
        vulnerable_dependencies: 15,
        license_issues: 2,
        created_at: new Date().toISOString()
      }
    ];
  },
  getDependencies: async (projectId: string): Promise<ScaDependency[]> => {
    return [
      { id: '1', project_id: projectId, name: 'serde', version: '1.0.188', ecosystem: 'cargo', purl: 'pkg:cargo/serde@1.0.188', is_direct: true, depth: 0, license: 'MIT OR Apache-2.0', license_risk: 'low', latest_version: '1.0.195', update_available: true },
      { id: '2', project_id: projectId, name: 'tokio', version: '1.32.0', ecosystem: 'cargo', purl: 'pkg:cargo/tokio@1.32.0', is_direct: true, depth: 0, license: 'MIT', license_risk: 'low', latest_version: '1.35.1', update_available: true },
      { id: '3', project_id: projectId, name: 'actix-web', version: '4.4.0', ecosystem: 'cargo', purl: 'pkg:cargo/actix-web@4.4.0', is_direct: true, depth: 0, license: 'MIT OR Apache-2.0', license_risk: 'low', latest_version: '4.4.1', update_available: true },
    ];
  },
  getVulnerabilities: async (projectId: string): Promise<ScaVulnerability[]> => {
    return [
      { id: '1', dependency_id: '1', vuln_id: 'GHSA-xxxx-yyyy-zzzz', source: 'github', severity: 'high', cvss_score: 8.1, title: 'Deserialization vulnerability', description: 'A deserialization vulnerability allows remote code execution', fixed_version: '1.0.190', exploited_in_wild: false, status: 'new' },
      { id: '2', dependency_id: '2', vuln_id: 'CVE-2023-12345', source: 'nvd', severity: 'medium', cvss_score: 5.5, title: 'Denial of service via resource exhaustion', description: 'Resource exhaustion can cause denial of service', fixed_version: '1.33.0', exploited_in_wild: false, status: 'new' },
    ];
  },
  analyzeProject: async (projectId: string): Promise<void> => {
    await new Promise(resolve => setTimeout(resolve, 1000));
  },
  generateSbom: async (projectId: string, format: string): Promise<Blob> => {
    return new Blob(['SBOM content'], { type: 'application/json' });
  }
};

const ScaPage: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'overview' | 'projects' | 'dependencies' | 'vulnerabilities'>('overview');
  const [stats, setStats] = useState<ScaStats | null>(null);
  const [projects, setProjects] = useState<ScaProject[]>([]);
  const [selectedProject, setSelectedProject] = useState<ScaProject | null>(null);
  const [dependencies, setDependencies] = useState<ScaDependency[]>([]);
  const [vulnerabilities, setVulnerabilities] = useState<ScaVulnerability[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [expandedDeps, setExpandedDeps] = useState<Set<string>>(new Set());

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      setLoading(true);
      const [statsData, projectsData] = await Promise.all([
        scaAPI.getStats(),
        scaAPI.getProjects()
      ]);
      setStats(statsData);
      setProjects(projectsData);
      if (projectsData.length > 0) {
        await selectProject(projectsData[0]);
      }
    } catch (error) {
      toast.error('Failed to load SCA data');
    } finally {
      setLoading(false);
    }
  };

  const selectProject = async (project: ScaProject) => {
    setSelectedProject(project);
    try {
      const [deps, vulns] = await Promise.all([
        scaAPI.getDependencies(project.id),
        scaAPI.getVulnerabilities(project.id)
      ]);
      setDependencies(deps);
      setVulnerabilities(vulns);
    } catch (error) {
      toast.error('Failed to load project details');
    }
  };

  const handleAnalyze = async (project: ScaProject) => {
    try {
      toast.info(`Analyzing ${project.name}...`);
      await scaAPI.analyzeProject(project.id);
      toast.success('Analysis complete!');
      await selectProject(project);
    } catch (error) {
      toast.error('Analysis failed');
    }
  };

  const handleExportSbom = async (format: 'cyclonedx' | 'spdx') => {
    if (!selectedProject) return;
    try {
      const blob = await scaAPI.generateSbom(selectedProject.id, format);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${selectedProject.name}-sbom.${format === 'cyclonedx' ? 'json' : 'spdx.json'}`;
      a.click();
      URL.revokeObjectURL(url);
      toast.success(`SBOM exported as ${format.toUpperCase()}`);
    } catch (error) {
      toast.error('Failed to export SBOM');
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical': return 'bg-purple-600';
      case 'high': return 'bg-red-600';
      case 'medium': return 'bg-yellow-600';
      case 'low': return 'bg-blue-600';
      default: return 'bg-gray-600';
    }
  };

  const getLicenseRiskColor = (risk?: string) => {
    switch (risk?.toLowerCase()) {
      case 'high': return 'text-red-400';
      case 'medium': return 'text-yellow-400';
      case 'low': return 'text-green-400';
      default: return 'text-gray-400';
    }
  };

  const getEcosystemIcon = (ecosystem: string) => {
    switch (ecosystem) {
      case 'cargo': return '🦀';
      case 'npm': return '📦';
      case 'pypi': return '🐍';
      case 'go': return '🐹';
      case 'maven': return '☕';
      default: return '📦';
    }
  };

  const filteredDependencies = dependencies.filter(dep =>
    dep.name.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <Layout>
      <div className="p-6">
        {/* Header */}
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-3">
            <Package className="h-8 w-8 text-cyan-400" />
            <div>
              <h1 className="text-2xl font-bold text-white">Software Composition Analysis</h1>
              <p className="text-gray-400">Analyze dependencies and identify vulnerabilities</p>
            </div>
          </div>
          <div className="flex gap-2">
            <button
              onClick={() => handleExportSbom('cyclonedx')}
              className="flex items-center gap-2 px-4 py-2 bg-gray-700 text-white rounded-lg hover:bg-gray-600"
              disabled={!selectedProject}
            >
              <Download className="h-4 w-4" />
              CycloneDX
            </button>
            <button
              onClick={() => handleExportSbom('spdx')}
              className="flex items-center gap-2 px-4 py-2 bg-gray-700 text-white rounded-lg hover:bg-gray-600"
              disabled={!selectedProject}
            >
              <Download className="h-4 w-4" />
              SPDX
            </button>
            <button
              onClick={() => setShowCreateModal(true)}
              className="flex items-center gap-2 px-4 py-2 bg-cyan-600 text-white rounded-lg hover:bg-cyan-500"
            >
              <Plus className="h-4 w-4" />
              Add Project
            </button>
          </div>
        </div>

        {/* Stats Cards */}
        {stats && (
          <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-8 gap-4 mb-6">
            <div className="bg-gray-800 rounded-lg p-4">
              <div className="text-2xl font-bold text-white">{stats.total_projects}</div>
              <div className="text-gray-400 text-sm">Projects</div>
            </div>
            <div className="bg-gray-800 rounded-lg p-4">
              <div className="text-2xl font-bold text-white">{stats.total_dependencies}</div>
              <div className="text-gray-400 text-sm">Dependencies</div>
            </div>
            <div className="bg-gray-800 rounded-lg p-4">
              <div className="text-2xl font-bold text-red-400">{stats.vulnerable_dependencies}</div>
              <div className="text-gray-400 text-sm">Vulnerable</div>
            </div>
            <div className="bg-gray-800 rounded-lg p-4">
              <div className="text-2xl font-bold text-purple-400">{stats.critical_vulns}</div>
              <div className="text-gray-400 text-sm">Critical</div>
            </div>
            <div className="bg-gray-800 rounded-lg p-4">
              <div className="text-2xl font-bold text-red-400">{stats.high_vulns}</div>
              <div className="text-gray-400 text-sm">High</div>
            </div>
            <div className="bg-gray-800 rounded-lg p-4">
              <div className="text-2xl font-bold text-yellow-400">{stats.medium_vulns}</div>
              <div className="text-gray-400 text-sm">Medium</div>
            </div>
            <div className="bg-gray-800 rounded-lg p-4">
              <div className="text-2xl font-bold text-orange-400">{stats.license_issues}</div>
              <div className="text-gray-400 text-sm">License Issues</div>
            </div>
            <div className="bg-gray-800 rounded-lg p-4">
              <div className="text-2xl font-bold text-cyan-400">{stats.updates_available}</div>
              <div className="text-gray-400 text-sm">Updates</div>
            </div>
          </div>
        )}

        {/* Tabs */}
        <div className="flex gap-1 mb-6 border-b border-gray-700">
          {['overview', 'projects', 'dependencies', 'vulnerabilities'].map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab as typeof activeTab)}
              className={`px-4 py-2 font-medium capitalize ${
                activeTab === tab
                  ? 'text-cyan-400 border-b-2 border-cyan-400'
                  : 'text-gray-400 hover:text-white'
              }`}
            >
              {tab}
            </button>
          ))}
        </div>

        {/* Content */}
        {loading ? (
          <div className="flex items-center justify-center py-12">
            <RefreshCw className="h-8 w-8 text-cyan-400 animate-spin" />
          </div>
        ) : (
          <>
            {/* Projects Tab */}
            {activeTab === 'projects' && (
              <div className="grid gap-4">
                {projects.map((project) => (
                  <div
                    key={project.id}
                    className={`bg-gray-800 rounded-lg p-4 cursor-pointer border-2 transition-colors ${
                      selectedProject?.id === project.id
                        ? 'border-cyan-500'
                        : 'border-transparent hover:border-gray-600'
                    }`}
                    onClick={() => selectProject(project)}
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <span className="text-2xl">{getEcosystemIcon(project.ecosystem)}</span>
                        <div>
                          <h3 className="text-lg font-medium text-white">{project.name}</h3>
                          <p className="text-gray-400 text-sm">{project.ecosystem} • {project.total_dependencies} dependencies</p>
                        </div>
                      </div>
                      <div className="flex items-center gap-4">
                        {project.vulnerable_dependencies > 0 && (
                          <div className="flex items-center gap-2 text-red-400">
                            <AlertTriangle className="h-4 w-4" />
                            <span>{project.vulnerable_dependencies} vulnerable</span>
                          </div>
                        )}
                        {project.license_issues > 0 && (
                          <div className="flex items-center gap-2 text-yellow-400">
                            <Scale className="h-4 w-4" />
                            <span>{project.license_issues} license issues</span>
                          </div>
                        )}
                        <button
                          onClick={(e) => { e.stopPropagation(); handleAnalyze(project); }}
                          className="p-2 bg-cyan-600 rounded-lg hover:bg-cyan-500"
                        >
                          <Play className="h-4 w-4 text-white" />
                        </button>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}

            {/* Dependencies Tab */}
            {activeTab === 'dependencies' && (
              <div>
                <div className="flex items-center gap-4 mb-4">
                  <div className="relative flex-1">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-400" />
                    <input
                      type="text"
                      placeholder="Search dependencies..."
                      value={searchTerm}
                      onChange={(e) => setSearchTerm(e.target.value)}
                      className="w-full pl-10 pr-4 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white"
                    />
                  </div>
                </div>

                <div className="bg-gray-800 rounded-lg overflow-hidden">
                  <table className="w-full">
                    <thead className="bg-gray-700">
                      <tr>
                        <th className="px-4 py-3 text-left text-gray-300">Package</th>
                        <th className="px-4 py-3 text-left text-gray-300">Version</th>
                        <th className="px-4 py-3 text-left text-gray-300">Latest</th>
                        <th className="px-4 py-3 text-left text-gray-300">License</th>
                        <th className="px-4 py-3 text-left text-gray-300">Type</th>
                        <th className="px-4 py-3 text-left text-gray-300">Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredDependencies.map((dep) => (
                        <tr key={dep.id} className="border-t border-gray-700 hover:bg-gray-750">
                          <td className="px-4 py-3">
                            <div className="flex items-center gap-2">
                              <span>{getEcosystemIcon(dep.ecosystem)}</span>
                              <span className="text-white">{dep.name}</span>
                            </div>
                          </td>
                          <td className="px-4 py-3 text-gray-300">{dep.version}</td>
                          <td className="px-4 py-3">
                            {dep.update_available ? (
                              <span className="text-cyan-400">{dep.latest_version}</span>
                            ) : (
                              <span className="text-green-400">{dep.version}</span>
                            )}
                          </td>
                          <td className={`px-4 py-3 ${getLicenseRiskColor(dep.license_risk)}`}>
                            {dep.license || 'Unknown'}
                          </td>
                          <td className="px-4 py-3">
                            <span className={`px-2 py-1 rounded text-xs ${
                              dep.is_direct ? 'bg-cyan-600 text-white' : 'bg-gray-600 text-gray-300'
                            }`}>
                              {dep.is_direct ? 'Direct' : 'Transitive'}
                            </span>
                          </td>
                          <td className="px-4 py-3">
                            <button className="p-1 hover:bg-gray-700 rounded">
                              <ExternalLink className="h-4 w-4 text-gray-400" />
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {/* Vulnerabilities Tab */}
            {activeTab === 'vulnerabilities' && (
              <div className="space-y-4">
                {vulnerabilities.map((vuln) => (
                  <div key={vuln.id} className="bg-gray-800 rounded-lg p-4">
                    <div className="flex items-start justify-between">
                      <div className="flex items-start gap-3">
                        <span className={`px-2 py-1 rounded text-xs text-white ${getSeverityColor(vuln.severity)}`}>
                          {vuln.severity.toUpperCase()}
                        </span>
                        <div>
                          <h3 className="text-white font-medium">{vuln.vuln_id}</h3>
                          <p className="text-gray-300 mt-1">{vuln.title}</p>
                          <p className="text-gray-400 text-sm mt-2">{vuln.description}</p>
                          {vuln.fixed_version && (
                            <p className="text-green-400 text-sm mt-2">
                              Fixed in version: {vuln.fixed_version}
                            </p>
                          )}
                        </div>
                      </div>
                      <div className="text-right">
                        {vuln.cvss_score && (
                          <div className="text-white font-bold">CVSS: {vuln.cvss_score}</div>
                        )}
                        <div className="text-gray-400 text-sm">{vuln.source}</div>
                        {vuln.exploited_in_wild && (
                          <span className="inline-block mt-2 px-2 py-1 bg-red-600 text-white text-xs rounded">
                            Exploited in Wild
                          </span>
                        )}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}

            {/* Overview Tab */}
            {activeTab === 'overview' && selectedProject && (
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div className="bg-gray-800 rounded-lg p-6">
                  <h3 className="text-lg font-medium text-white mb-4">Selected Project</h3>
                  <div className="space-y-4">
                    <div className="flex items-center gap-3">
                      <span className="text-3xl">{getEcosystemIcon(selectedProject.ecosystem)}</span>
                      <div>
                        <h4 className="text-xl font-bold text-white">{selectedProject.name}</h4>
                        <p className="text-gray-400">{selectedProject.ecosystem}</p>
                      </div>
                    </div>
                    {selectedProject.repository_url && (
                      <a
                        href={selectedProject.repository_url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="flex items-center gap-2 text-cyan-400 hover:underline"
                      >
                        <GitBranch className="h-4 w-4" />
                        {selectedProject.repository_url}
                      </a>
                    )}
                    <div className="grid grid-cols-3 gap-4 mt-4">
                      <div className="bg-gray-700 rounded p-3 text-center">
                        <div className="text-2xl font-bold text-white">{selectedProject.total_dependencies}</div>
                        <div className="text-gray-400 text-sm">Dependencies</div>
                      </div>
                      <div className="bg-gray-700 rounded p-3 text-center">
                        <div className="text-2xl font-bold text-red-400">{selectedProject.vulnerable_dependencies}</div>
                        <div className="text-gray-400 text-sm">Vulnerable</div>
                      </div>
                      <div className="bg-gray-700 rounded p-3 text-center">
                        <div className="text-2xl font-bold text-yellow-400">{selectedProject.license_issues}</div>
                        <div className="text-gray-400 text-sm">License Issues</div>
                      </div>
                    </div>
                  </div>
                </div>

                <div className="bg-gray-800 rounded-lg p-6">
                  <h3 className="text-lg font-medium text-white mb-4">Recent Vulnerabilities</h3>
                  <div className="space-y-3">
                    {vulnerabilities.slice(0, 5).map((vuln) => (
                      <div key={vuln.id} className="flex items-center justify-between bg-gray-700 rounded p-3">
                        <div className="flex items-center gap-3">
                          <span className={`px-2 py-1 rounded text-xs text-white ${getSeverityColor(vuln.severity)}`}>
                            {vuln.severity.toUpperCase()}
                          </span>
                          <span className="text-white">{vuln.vuln_id}</span>
                        </div>
                        {vuln.cvss_score && (
                          <span className="text-gray-300">CVSS: {vuln.cvss_score}</span>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </Layout>
  );
};

export default ScaPage;
