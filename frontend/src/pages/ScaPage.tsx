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
import { scaAPI, ScaProject, ScaDependency, ScaVulnerability, ScaStats } from '../services/api';

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
        scaAPI.getStats().then(res => res.data),
        scaAPI.getProjects().then(res => res.data)
      ]);
      setStats(statsData);
      setProjects(projectsData);
      if (projectsData.length > 0) {
        await selectProject(projectsData[0]);
      }
    } catch (error) {
      console.error('Failed to load SCA data:', error);
      toast.error('Failed to load SCA data');
    } finally {
      setLoading(false);
    }
  };

  const selectProject = async (project: ScaProject) => {
    setSelectedProject(project);
    try {
      const [deps, vulns] = await Promise.all([
        scaAPI.getDependencies(project.id).then(res => res.data),
        scaAPI.getVulnerabilities(project.id).then(res => res.data)
      ]);
      setDependencies(deps);
      setVulnerabilities(vulns);
    } catch (error) {
      console.error('Failed to load project details:', error);
      toast.error('Failed to load project details');
    }
  };

  const handleAnalyze = async (project: ScaProject) => {
    try {
      toast.info(`Analyzing ${project.name}...`);
      await scaAPI.analyzeProject(project.id, { check_updates: true });
      toast.success('Analysis complete!');
      await loadData();
      if (selectedProject?.id === project.id) {
        await selectProject(project);
      }
    } catch (error) {
      console.error('Analysis failed:', error);
      toast.error('Analysis failed');
    }
  };

  const handleExportSbom = async (format: 'cyclonedx' | 'spdx') => {
    if (!selectedProject) return;
    try {
      // TODO: Implement SBOM export endpoint
      toast.info(`SBOM export for ${format.toUpperCase()} is not yet implemented`);
    } catch (error) {
      console.error('Failed to export SBOM:', error);
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
