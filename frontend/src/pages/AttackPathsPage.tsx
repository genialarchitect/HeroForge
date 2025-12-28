import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { toast } from 'react-toastify';
import {
  GitBranch,
  AlertTriangle,
  Target,
  Shield,
  ChevronRight,
  RefreshCw,
  ArrowLeft,
  Network,
  Zap,
  Info,
} from 'lucide-react';
import Layout from '../components/layout/Layout';
import Card from '../components/ui/Card';
import Button from '../components/ui/Button';
import LoadingSpinner from '../components/ui/LoadingSpinner';
import Badge from '../components/ui/Badge';
import { attackPathsAPI, scanAPI } from '../services/api';
import type {
  AttackPath,
  AttackNode,
  AttackEdge,
  AttackPathStats,
  AttackPathRiskLevel,
  ScanResult,
} from '../types';

// Simple graph visualization component
const AttackPathGraph: React.FC<{
  nodes: AttackNode[];
  edges: AttackEdge[];
  onNodeClick?: (node: AttackNode) => void;
}> = ({ nodes, edges, onNodeClick }) => {
  const svgWidth = 800;
  const svgHeight = 400;
  const nodeRadius = 30;

  // Calculate node positions if not provided
  const positionedNodes = useMemo(() => {
    if (nodes.length === 0) return [];

    // Group nodes by type for layout
    const entryNodes = nodes.filter((n) => n.node_type === 'entry');
    const pivotNodes = nodes.filter((n) => n.node_type === 'pivot');
    const targetNodes = nodes.filter((n) => n.node_type === 'target');

    const padding = 60;
    const layerWidth = (svgWidth - padding * 2) / 3;

    return nodes.map((node) => {
      let x = padding;
      let yOffset = 0;
      let groupSize = 1;
      let indexInGroup = 0;

      if (node.node_type === 'entry') {
        x = padding;
        groupSize = entryNodes.length;
        indexInGroup = entryNodes.indexOf(node);
      } else if (node.node_type === 'pivot') {
        x = padding + layerWidth;
        groupSize = pivotNodes.length;
        indexInGroup = pivotNodes.indexOf(node);
      } else {
        x = padding + layerWidth * 2;
        groupSize = targetNodes.length;
        indexInGroup = targetNodes.indexOf(node);
      }

      yOffset = groupSize > 1
        ? ((indexInGroup - (groupSize - 1) / 2) * 80)
        : 0;

      return {
        ...node,
        x: node.position_x !== 0 ? node.position_x + padding : x,
        y: node.position_y !== 0 ? node.position_y + svgHeight / 2 : svgHeight / 2 + yOffset,
      };
    });
  }, [nodes]);

  const getNodeColor = (nodeType: string) => {
    switch (nodeType) {
      case 'entry':
        return '#22c55e'; // green
      case 'target':
        return '#ef4444'; // red
      case 'pivot':
      default:
        return '#f59e0b'; // amber
    }
  };

  const getNodeById = (id: string) => positionedNodes.find((n) => n.id === id);

  return (
    <svg
      viewBox={`0 0 ${svgWidth} ${svgHeight}`}
      className="w-full h-full"
      style={{ minHeight: '300px' }}
    >
      {/* Draw edges first (behind nodes) */}
      <defs>
        <marker
          id="arrowhead"
          markerWidth="10"
          markerHeight="7"
          refX="9"
          refY="3.5"
          orient="auto"
        >
          <polygon points="0 0, 10 3.5, 0 7" fill="#64748b" />
        </marker>
      </defs>
      {edges.map((edge) => {
        const source = getNodeById(edge.source_node_id);
        const target = getNodeById(edge.target_node_id);
        if (!source || !target) return null;

        return (
          <g key={edge.id}>
            <line
              x1={source.x + nodeRadius}
              y1={source.y}
              x2={target.x - nodeRadius}
              y2={target.y}
              stroke="#64748b"
              strokeWidth="2"
              markerEnd="url(#arrowhead)"
            />
            {edge.attack_technique && (
              <text
                x={(source.x + target.x) / 2}
                y={(source.y + target.y) / 2 - 10}
                fill="#94a3b8"
                fontSize="10"
                textAnchor="middle"
              >
                {edge.technique_id || edge.attack_technique.slice(0, 20)}
              </text>
            )}
          </g>
        );
      })}

      {/* Draw nodes */}
      {positionedNodes.map((node) => (
        <g
          key={node.id}
          className="cursor-pointer"
          onClick={() => onNodeClick?.(node)}
        >
          <circle
            cx={node.x}
            cy={node.y}
            r={nodeRadius}
            fill={getNodeColor(node.node_type)}
            fillOpacity="0.2"
            stroke={getNodeColor(node.node_type)}
            strokeWidth="2"
          />
          <text
            x={node.x}
            y={node.y - 5}
            fill="white"
            fontSize="11"
            textAnchor="middle"
            fontWeight="bold"
          >
            {node.service || node.host_ip?.split('.').slice(-1)[0] || '?'}
          </text>
          <text
            x={node.x}
            y={node.y + 10}
            fill="#94a3b8"
            fontSize="9"
            textAnchor="middle"
          >
            {node.port ? `:${node.port}` : node.node_type}
          </text>
          {node.vulnerability_ids.length > 0 && (
            <circle
              cx={node.x + nodeRadius - 5}
              cy={node.y - nodeRadius + 5}
              r="10"
              fill="#ef4444"
            />
          )}
          {node.vulnerability_ids.length > 0 && (
            <text
              x={node.x + nodeRadius - 5}
              y={node.y - nodeRadius + 9}
              fill="white"
              fontSize="9"
              textAnchor="middle"
            >
              {node.vulnerability_ids.length}
            </text>
          )}
        </g>
      ))}

      {/* Legend */}
      <g transform={`translate(${svgWidth - 120}, 20)`}>
        <circle cx="10" cy="10" r="8" fill="#22c55e" fillOpacity="0.3" stroke="#22c55e" />
        <text x="25" y="14" fill="#94a3b8" fontSize="10">Entry</text>
        <circle cx="10" cy="30" r="8" fill="#f59e0b" fillOpacity="0.3" stroke="#f59e0b" />
        <text x="25" y="34" fill="#94a3b8" fontSize="10">Pivot</text>
        <circle cx="10" cy="50" r="8" fill="#ef4444" fillOpacity="0.3" stroke="#ef4444" />
        <text x="25" y="54" fill="#94a3b8" fontSize="10">Target</text>
      </g>
    </svg>
  );
};

// Risk level badge component
const RiskBadge: React.FC<{ level: AttackPathRiskLevel }> = ({ level }) => {
  const colorMap: Record<AttackPathRiskLevel, 'critical' | 'high' | 'medium' | 'low'> = {
    critical: 'critical',
    high: 'high',
    medium: 'medium',
    low: 'low',
  };
  return <Badge type={colorMap[level]}>{level.toUpperCase()}</Badge>;
};

// Attack path card component
const AttackPathCard: React.FC<{
  path: AttackPath;
  isSelected: boolean;
  onClick: () => void;
}> = ({ path, isSelected, onClick }) => {
  return (
    <div
      className={`p-4 rounded-lg border cursor-pointer transition-all ${
        isSelected
          ? 'border-primary bg-primary/10'
          : 'border-dark-border bg-dark-card hover:border-slate-600'
      }`}
      onClick={onClick}
    >
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-2">
          <GitBranch className="h-4 w-4 text-slate-400" />
          <span className="text-white font-medium">
            {path.name || `Path ${path.id.slice(0, 8)}`}
          </span>
        </div>
        <RiskBadge level={path.risk_level} />
      </div>
      <div className="grid grid-cols-3 gap-2 text-sm">
        <div>
          <span className="text-slate-400">Length:</span>{' '}
          <span className="text-white">{path.path_length} nodes</span>
        </div>
        <div>
          <span className="text-slate-400">CVSS:</span>{' '}
          <span className="text-white">{path.total_cvss.toFixed(1)}</span>
        </div>
        <div>
          <span className="text-slate-400">Probability:</span>{' '}
          <span className="text-white">{(path.probability * 100).toFixed(0)}%</span>
        </div>
      </div>
    </div>
  );
};

const AttackPathsPage: React.FC = () => {
  const { scanId } = useParams<{ scanId: string }>();
  const navigate = useNavigate();

  const [loading, setLoading] = useState(true);
  const [analyzing, setAnalyzing] = useState(false);
  const [scan, setScan] = useState<ScanResult | null>(null);
  const [scans, setScans] = useState<ScanResult[]>([]);
  const [paths, setPaths] = useState<AttackPath[]>([]);
  const [stats, setStats] = useState<AttackPathStats | null>(null);
  const [selectedPath, setSelectedPath] = useState<AttackPath | null>(null);
  const [selectedNode, setSelectedNode] = useState<AttackNode | null>(null);
  const [showCriticalOnly, setShowCriticalOnly] = useState(false);
  const [hasAnalyzed, setHasAnalyzed] = useState(false);

  const loadData = useCallback(async () => {
    setLoading(true);

    // If no scanId, load list of completed scans for selection
    if (!scanId) {
      try {
        const scansRes = await scanAPI.getAll();
        // Filter to only completed scans
        const completedScans = (scansRes.data || []).filter((s) => s.status === 'completed');
        setScans(completedScans);
      } catch (error) {
        toast.error('Failed to load scans');
        console.error(error);
      } finally {
        setLoading(false);
      }
      return;
    }

    try {
      // Load scan info
      const scanRes = await scanAPI.getById(scanId);
      setScan(scanRes.data);

      // Try to load existing attack paths
      try {
        const pathsRes = await attackPathsAPI.getByScan(scanId);
        setPaths(pathsRes.data.paths);
        setStats(pathsRes.data.stats);
        setHasAnalyzed(pathsRes.data.paths.length > 0);
        if (pathsRes.data.paths.length > 0) {
          setSelectedPath(pathsRes.data.paths[0]);
        }
      } catch {
        // No paths analyzed yet
        setPaths([]);
        setStats(null);
        setHasAnalyzed(false);
      }
    } catch (error) {
      toast.error('Failed to load scan data');
      console.error(error);
    } finally {
      setLoading(false);
    }
  }, [scanId]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const handleAnalyze = async (force = false) => {
    if (!scanId) return;

    setAnalyzing(true);
    try {
      const result = await attackPathsAPI.analyze(scanId, { force });
      toast.success(result.data.message);

      // Reload paths
      const pathsRes = await attackPathsAPI.getByScan(scanId);
      setPaths(pathsRes.data.paths);
      setStats(pathsRes.data.stats);
      setHasAnalyzed(true);
      if (pathsRes.data.paths.length > 0) {
        setSelectedPath(pathsRes.data.paths[0]);
      }
    } catch (error: unknown) {
      const axiosError = error as { response?: { data?: { error?: string } } };
      toast.error(axiosError.response?.data?.error || 'Analysis failed');
      console.error(error);
    } finally {
      setAnalyzing(false);
    }
  };

  const filteredPaths = useMemo(() => {
    if (showCriticalOnly) {
      return paths.filter(
        (p) => p.risk_level === 'critical' || p.risk_level === 'high'
      );
    }
    return paths;
  }, [paths, showCriticalOnly]);

  if (loading) {
    return (
      <Layout>
        <div className="flex items-center justify-center py-12">
          <LoadingSpinner />
        </div>
      </Layout>
    );
  }

  // Show scan selector when no scanId is provided
  if (!scanId) {
    return (
      <Layout>
        <div className="space-y-6">
          <div>
            <h1 className="text-2xl font-bold text-white flex items-center gap-2">
              <Network className="h-6 w-6 text-primary" />
              Attack Path Analysis
            </h1>
            <p className="text-slate-400 mt-1">
              Select a completed scan to analyze attack paths
            </p>
          </div>

          {scans.length === 0 ? (
            <Card className="p-8 text-center">
              <Network className="h-16 w-16 text-slate-500 mx-auto mb-4" />
              <h2 className="text-xl font-bold text-white mb-2">
                No Completed Scans Available
              </h2>
              <p className="text-slate-400 mb-6 max-w-md mx-auto">
                You need to complete a network scan first before you can analyze attack paths.
                Run a scan with vulnerability detection enabled to get started.
              </p>
              <Button onClick={() => navigate('/scan')}>
                <Target className="h-4 w-4 mr-2" />
                Start New Scan
              </Button>
            </Card>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {scans.map((s) => (
                <Card
                  key={s.id}
                  className="cursor-pointer hover:border-primary transition-all"
                  onClick={() => navigate(`/attack-paths/${s.id}`)}
                >
                  <div className="flex items-start justify-between mb-3">
                    <div className="flex items-center gap-2">
                      <Target className="h-5 w-5 text-primary" />
                      <span className="font-medium text-white">{s.name}</span>
                    </div>
                    <Badge type={s.status === 'completed' ? 'low' : 'medium'}>
                      {s.status}
                    </Badge>
                  </div>
                  <div className="text-sm text-slate-400 space-y-1">
                    <p>Targets: {s.targets || 'N/A'}</p>
                    <p>Created: {new Date(s.created_at).toLocaleDateString()}</p>
                    {s.total_hosts !== undefined && (
                      <p>Hosts: {s.total_hosts}</p>
                    )}
                  </div>
                  <div className="mt-3 flex items-center text-primary text-sm">
                    <span>Analyze Attack Paths</span>
                    <ChevronRight className="h-4 w-4 ml-1" />
                  </div>
                </Card>
              ))}
            </div>
          )}
        </div>
      </Layout>
    );
  }

  if (!scan) {
    return (
      <Layout>
        <div className="text-center py-12">
          <AlertTriangle className="h-12 w-12 text-yellow-500 mx-auto mb-4" />
          <h2 className="text-xl font-bold text-white mb-2">Scan Not Found</h2>
          <p className="text-slate-400 mb-4">
            The requested scan could not be found.
          </p>
          <Button onClick={() => navigate('/dashboard')}>Go to Dashboard</Button>
        </div>
      </Layout>
    );
  }

  return (
    <Layout>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <Button
              variant="secondary"
              onClick={() => navigate(`/dashboard/${scanId}`)}
            >
              <ArrowLeft className="h-4 w-4 mr-2" />
              Back to Scan
            </Button>
            <div>
              <h1 className="text-2xl font-bold text-white flex items-center gap-2">
                <Network className="h-6 w-6 text-primary" />
                Attack Path Analysis
              </h1>
              <p className="text-slate-400">
                Scan: {scan.name}
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            {hasAnalyzed && (
              <Button
                variant="secondary"
                onClick={() => setShowCriticalOnly(!showCriticalOnly)}
              >
                {showCriticalOnly ? 'Show All' : 'Critical Only'}
              </Button>
            )}
            <Button
              onClick={() => handleAnalyze(hasAnalyzed)}
              disabled={analyzing || scan.status !== 'completed'}
            >
              {analyzing ? (
                <>
                  <LoadingSpinner />
                  <span className="ml-2">Analyzing...</span>
                </>
              ) : (
                <>
                  <RefreshCw className="h-4 w-4 mr-2" />
                  {hasAnalyzed ? 'Re-analyze' : 'Analyze'}
                </>
              )}
            </Button>
          </div>
        </div>

        {/* Stats Summary */}
        {stats && (
          <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
            <Card className="p-4">
              <div className="flex items-center gap-3">
                <div className="p-2 bg-blue-500/20 rounded-lg">
                  <GitBranch className="h-5 w-5 text-blue-400" />
                </div>
                <div>
                  <p className="text-2xl font-bold text-white">
                    {stats.total_paths}
                  </p>
                  <p className="text-xs text-slate-400">Total Paths</p>
                </div>
              </div>
            </Card>
            <Card className="p-4">
              <div className="flex items-center gap-3">
                <div className="p-2 bg-red-500/20 rounded-lg">
                  <AlertTriangle className="h-5 w-5 text-red-400" />
                </div>
                <div>
                  <p className="text-2xl font-bold text-white">
                    {stats.critical_paths}
                  </p>
                  <p className="text-xs text-slate-400">Critical Paths</p>
                </div>
              </div>
            </Card>
            <Card className="p-4">
              <div className="flex items-center gap-3">
                <div className="p-2 bg-orange-500/20 rounded-lg">
                  <Zap className="h-5 w-5 text-orange-400" />
                </div>
                <div>
                  <p className="text-2xl font-bold text-white">
                    {stats.high_paths}
                  </p>
                  <p className="text-xs text-slate-400">High Risk Paths</p>
                </div>
              </div>
            </Card>
            <Card className="p-4">
              <div className="flex items-center gap-3">
                <div className="p-2 bg-purple-500/20 rounded-lg">
                  <Target className="h-5 w-5 text-purple-400" />
                </div>
                <div>
                  <p className="text-2xl font-bold text-white">
                    {stats.total_nodes}
                  </p>
                  <p className="text-xs text-slate-400">Total Nodes</p>
                </div>
              </div>
            </Card>
            <Card className="p-4">
              <div className="flex items-center gap-3">
                <div className="p-2 bg-green-500/20 rounded-lg">
                  <Shield className="h-5 w-5 text-green-400" />
                </div>
                <div>
                  <p className="text-2xl font-bold text-white">
                    {stats.avg_path_length?.toFixed(1) || 'N/A'}
                  </p>
                  <p className="text-xs text-slate-400">Avg Path Length</p>
                </div>
              </div>
            </Card>
          </div>
        )}

        {/* Main Content */}
        {!hasAnalyzed ? (
          <Card className="p-8 text-center">
            <Network className="h-16 w-16 text-slate-500 mx-auto mb-4" />
            <h2 className="text-xl font-bold text-white mb-2">
              No Attack Paths Analyzed
            </h2>
            <p className="text-slate-400 mb-6 max-w-md mx-auto">
              Click the "Analyze" button to identify potential attack paths in
              your scan results. The analysis will build a graph of hosts and
              vulnerabilities to find possible attack chains.
            </p>
            {scan.status !== 'completed' && (
              <p className="text-yellow-500 text-sm mb-4">
                Note: The scan must be completed before analysis.
              </p>
            )}
            <Button
              onClick={() => handleAnalyze(false)}
              disabled={analyzing || scan.status !== 'completed'}
              className="mx-auto"
            >
              {analyzing ? (
                <>
                  <LoadingSpinner />
                  <span className="ml-2">Analyzing...</span>
                </>
              ) : (
                <>
                  <GitBranch className="h-4 w-4 mr-2" />
                  Analyze Attack Paths
                </>
              )}
            </Button>
          </Card>
        ) : paths.length === 0 ? (
          <Card className="p-8 text-center">
            <Shield className="h-16 w-16 text-green-500 mx-auto mb-4" />
            <h2 className="text-xl font-bold text-white mb-2">
              No Attack Paths Found
            </h2>
            <p className="text-slate-400 max-w-md mx-auto">
              The analysis did not identify any significant attack paths. This
              could mean the network is well-segmented or there are no
              vulnerable services that could be chained together.
            </p>
          </Card>
        ) : (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Path List */}
            <div className="lg:col-span-1 space-y-3">
              <h3 className="text-lg font-semibold text-white mb-3">
                Attack Paths ({filteredPaths.length})
              </h3>
              <div className="space-y-2 max-h-[600px] overflow-y-auto pr-2">
                {filteredPaths.map((path) => (
                  <AttackPathCard
                    key={path.id}
                    path={path}
                    isSelected={selectedPath?.id === path.id}
                    onClick={() => {
                      setSelectedPath(path);
                      setSelectedNode(null);
                    }}
                  />
                ))}
              </div>
            </div>

            {/* Path Visualization */}
            <div className="lg:col-span-2">
              {selectedPath ? (
                <Card>
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="text-lg font-semibold text-white">
                      {selectedPath.name || `Path ${selectedPath.id.slice(0, 8)}`}
                    </h3>
                    <RiskBadge level={selectedPath.risk_level} />
                  </div>

                  {/* Graph */}
                  <div className="bg-dark-bg rounded-lg border border-dark-border p-4 mb-4">
                    <AttackPathGraph
                      nodes={selectedPath.nodes}
                      edges={selectedPath.edges}
                      onNodeClick={setSelectedNode}
                    />
                  </div>

                  {/* Path Details */}
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
                    <div className="bg-dark-bg rounded-lg p-3">
                      <p className="text-xs text-slate-400 mb-1">Path Length</p>
                      <p className="text-lg font-semibold text-white">
                        {selectedPath.path_length} nodes
                      </p>
                    </div>
                    <div className="bg-dark-bg rounded-lg p-3">
                      <p className="text-xs text-slate-400 mb-1">Total CVSS</p>
                      <p className="text-lg font-semibold text-white">
                        {selectedPath.total_cvss.toFixed(1)}
                      </p>
                    </div>
                    <div className="bg-dark-bg rounded-lg p-3">
                      <p className="text-xs text-slate-400 mb-1">Probability</p>
                      <p className="text-lg font-semibold text-white">
                        {(selectedPath.probability * 100).toFixed(0)}%
                      </p>
                    </div>
                    <div className="bg-dark-bg rounded-lg p-3">
                      <p className="text-xs text-slate-400 mb-1">Nodes</p>
                      <p className="text-lg font-semibold text-white">
                        {selectedPath.nodes.length}
                      </p>
                    </div>
                  </div>

                  {/* Selected Node Details */}
                  {selectedNode && (
                    <div className="bg-dark-bg rounded-lg p-4 mb-4 border border-dark-border">
                      <h4 className="text-sm font-semibold text-white mb-2 flex items-center gap-2">
                        <Info className="h-4 w-4" />
                        Node Details
                      </h4>
                      <div className="grid grid-cols-2 gap-2 text-sm">
                        <div>
                          <span className="text-slate-400">IP:</span>{' '}
                          <span className="text-white">
                            {selectedNode.host_ip || 'N/A'}
                          </span>
                        </div>
                        <div>
                          <span className="text-slate-400">Port:</span>{' '}
                          <span className="text-white">
                            {selectedNode.port || 'N/A'}
                          </span>
                        </div>
                        <div>
                          <span className="text-slate-400">Service:</span>{' '}
                          <span className="text-white">
                            {selectedNode.service || 'Unknown'}
                          </span>
                        </div>
                        <div>
                          <span className="text-slate-400">Type:</span>{' '}
                          <span className="text-white capitalize">
                            {selectedNode.node_type}
                          </span>
                        </div>
                        <div className="col-span-2">
                          <span className="text-slate-400">Vulnerabilities:</span>{' '}
                          <span className="text-white">
                            {selectedNode.vulnerability_ids.length > 0
                              ? selectedNode.vulnerability_ids.join(', ')
                              : 'None'}
                          </span>
                        </div>
                      </div>
                    </div>
                  )}

                  {/* Mitigations */}
                  {selectedPath.mitigation_steps.length > 0 && (
                    <div>
                      <h4 className="text-sm font-semibold text-white mb-2 flex items-center gap-2">
                        <Shield className="h-4 w-4 text-green-400" />
                        Recommended Mitigations
                      </h4>
                      <ul className="space-y-2">
                        {selectedPath.mitigation_steps.map((step: string, idx: number) => (
                          <li
                            key={idx}
                            className="flex items-start gap-2 text-sm text-slate-300"
                          >
                            <ChevronRight className="h-4 w-4 text-primary mt-0.5 flex-shrink-0" />
                            {step}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                </Card>
              ) : (
                <Card className="p-8 text-center">
                  <p className="text-slate-400">
                    Select an attack path from the list to view details
                  </p>
                </Card>
              )}
            </div>
          </div>
        )}

        {/* Info Card */}
        <Card className="bg-blue-500/10 border-blue-500/30">
          <div className="flex gap-4">
            <Info className="h-6 w-6 text-blue-400 flex-shrink-0 mt-0.5" />
            <div>
              <h3 className="text-lg font-semibold text-blue-400 mb-2">
                About Attack Path Analysis
              </h3>
              <p className="text-sm text-slate-300 mb-2">
                Attack path analysis identifies potential chains of
                vulnerabilities and misconfigurations that an attacker could
                exploit to move through your network. The analysis:
              </p>
              <ul className="text-sm text-slate-300 space-y-1 list-disc list-inside ml-4">
                <li>
                  Builds a graph from discovered hosts, services, and
                  vulnerabilities
                </li>
                <li>
                  Identifies entry points, pivot points, and target systems
                </li>
                <li>
                  Calculates risk scores based on CVSS, exploitability, and
                  impact
                </li>
                <li>Maps techniques to MITRE ATT&CK framework where applicable</li>
                <li>Provides prioritized mitigation recommendations</li>
              </ul>
            </div>
          </div>
        </Card>
      </div>
    </Layout>
  );
};

export default AttackPathsPage;
