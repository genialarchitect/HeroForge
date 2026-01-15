import React, { useEffect, useState, useCallback, useMemo } from 'react';
import {
  ReactFlow,
  Node,
  Edge,
  Controls,
  Background,
  MiniMap,
  useNodesState,
  useEdgesState,
  MarkerType,
  NodeProps,
  Handle,
  Position,
  Panel,
  NodeTypes,
  BackgroundVariant,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import Card from '../ui/Card';
import {
  Shield,
  Router,
  Server,
  Database,
  Cloud,
  Monitor,
  Smartphone,
  Lock,
  Globe,
  HardDrive,
  Wifi,
  Network,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Layers,
  Box,
  Cpu,
  Printer,
  Camera,
  ShieldAlert,
  ZoomIn,
  ZoomOut,
  Maximize2,
  X,
  Search,
  Download,
  Bot,
} from 'lucide-react';
import RedTeamAdvisorPanel from '../ai/RedTeamAdvisorPanel';
import { TopologyForAnalysis, TopologyNodeForAnalysis, TopologyEdgeForAnalysis } from '../../types/red-team-advisor';

// ============================================================================
// Types
// ============================================================================

type DeviceType =
  | 'router'
  | 'switch'
  | 'firewall'
  | 'server'
  | 'database'
  | 'cloud'
  | 'workstation'
  | 'laptop'
  | 'mobile'
  | 'iot'
  | 'printer'
  | 'camera'
  | 'wireless_ap'
  | 'load_balancer'
  | 'storage'
  | 'container'
  | 'virtual_machine'
  | 'internet'
  | 'vpn'
  | 'unknown';

type SecurityZone = 'external' | 'dmz' | 'internal' | 'restricted' | 'management';

type ComplianceStatus = 'compliant' | 'non_compliant' | 'partial' | 'not_assessed';

interface DeviceData extends Record<string, unknown> {
  label: string;
  deviceType: DeviceType;
  securityZone: SecurityZone;
  ipAddress?: string;
  hostname?: string;
  os?: string;
  complianceStatus: ComplianceStatus;
  riskScore?: number;
  vulnerabilities?: number;
  criticalVulns?: number;
  highVulns?: number;
  openPorts?: number;
  isGateway?: boolean;
  subnet?: string;
}

interface ConnectionData extends Record<string, unknown> {
  label?: string;
  protocol?: string;
  port?: number;
  encrypted?: boolean;
  relationshipType?: 'gateway' | 'same_subnet' | 'shared_service';
}

interface TopologyNode {
  id: string;
  ip: string;
  hostname: string | null;
  os: string | null;
  os_family: string | null;
  risk_score: number;
  open_ports_count: number;
  vuln_count: number;
  critical_vulns: number;
  high_vulns: number;
  subnet: string;
  is_gateway: boolean;
  node_type: 'server' | 'workstation' | 'network' | 'gateway' | 'unknown';
}

interface TopologyEdge {
  source: string;
  target: string;
  relationship_type: 'same_subnet' | 'shared_service' | 'gateway';
  strength: number;
}

interface SubnetGroup {
  subnet: string;
  nodes: string[];
  host_count: number;
}

interface TopologyData {
  nodes: TopologyNode[];
  edges: TopologyEdge[];
  subnets: SubnetGroup[];
}

interface NetworkMapProps {
  scanId: string;
}

// ============================================================================
// Device Icons
// ============================================================================

const deviceIcons: Record<DeviceType, React.FC<{ className?: string }>> = {
  router: Router,
  switch: Network,
  firewall: ShieldAlert,
  server: Server,
  database: Database,
  cloud: Cloud,
  workstation: Monitor,
  laptop: Monitor,
  mobile: Smartphone,
  iot: Cpu,
  printer: Printer,
  camera: Camera,
  wireless_ap: Wifi,
  load_balancer: Layers,
  storage: HardDrive,
  container: Box,
  virtual_machine: Cpu,
  internet: Globe,
  vpn: Lock,
  unknown: Server,
};

const zoneColors: Record<SecurityZone, { bg: string; border: string; text: string }> = {
  external: { bg: 'bg-red-500/10', border: 'border-red-500', text: 'text-red-400' },
  dmz: { bg: 'bg-yellow-500/10', border: 'border-yellow-500', text: 'text-yellow-400' },
  internal: { bg: 'bg-blue-500/10', border: 'border-blue-500', text: 'text-blue-400' },
  restricted: { bg: 'bg-purple-500/10', border: 'border-purple-500', text: 'text-purple-400' },
  management: { bg: 'bg-green-500/10', border: 'border-green-500', text: 'text-green-400' },
};

const complianceColors: Record<ComplianceStatus, string> = {
  compliant: 'ring-green-500',
  non_compliant: 'ring-red-500',
  partial: 'ring-yellow-500',
  not_assessed: 'ring-gray-500',
};

// ============================================================================
// Custom Node Component
// ============================================================================

const NetworkDeviceNode: React.FC<NodeProps<Node<DeviceData>>> = ({ data, selected }) => {
  const Icon = deviceIcons[data.deviceType] || Server;
  const zoneStyle = zoneColors[data.securityZone];
  const complianceRing = complianceColors[data.complianceStatus];

  const ComplianceIcon = () => {
    switch (data.complianceStatus) {
      case 'compliant':
        return <CheckCircle className="w-3 h-3 text-green-400" />;
      case 'non_compliant':
        return <XCircle className="w-3 h-3 text-red-400" />;
      case 'partial':
        return <AlertTriangle className="w-3 h-3 text-yellow-400" />;
      default:
        return <Shield className="w-3 h-3 text-gray-400" />;
    }
  };

  // Risk-based border color
  const getRiskBorderColor = () => {
    if ((data.riskScore ?? 0) >= 75 || (data.criticalVulns ?? 0) > 0) return 'border-red-500';
    if ((data.riskScore ?? 0) >= 50 || (data.highVulns ?? 0) > 0) return 'border-orange-500';
    if ((data.riskScore ?? 0) >= 25) return 'border-yellow-500';
    return zoneStyle.border;
  };

  return (
    <div
      className={`relative px-4 py-3 rounded-lg border-2 ${zoneStyle.bg} ${getRiskBorderColor()} ${
        selected ? 'ring-2 ring-cyan-400' : ''
      } transition-all shadow-lg hover:shadow-xl`}
    >
      {/* Connection handles */}
      <Handle type="target" position={Position.Top} className="!bg-cyan-500 !w-3 !h-3" />
      <Handle type="source" position={Position.Bottom} className="!bg-cyan-500 !w-3 !h-3" />
      <Handle type="target" position={Position.Left} className="!bg-cyan-500 !w-3 !h-3" />
      <Handle type="source" position={Position.Right} className="!bg-cyan-500 !w-3 !h-3" />

      {/* Compliance indicator */}
      <div className={`absolute -top-2 -right-2 p-1 rounded-full bg-gray-900 ring-2 ${complianceRing}`}>
        <ComplianceIcon />
      </div>

      {/* Gateway badge */}
      {data.isGateway && (
        <div className="absolute -top-2 -left-2 p-1 rounded-full bg-blue-600 ring-2 ring-blue-400">
          <Router className="w-3 h-3 text-white" />
        </div>
      )}

      {/* Device icon and info */}
      <div className="flex flex-col items-center gap-2 min-w-[100px]">
        <div className={`p-3 rounded-lg bg-gray-800/80 ${getRiskBorderColor()} border`}>
          <Icon className={`w-8 h-8 ${zoneStyle.text}`} />
        </div>
        <div className="text-center">
          <div className="font-semibold text-white text-sm">{data.label}</div>
          {data.ipAddress && (
            <div className="text-xs text-gray-400 font-mono">{data.ipAddress}</div>
          )}
          {data.hostname && (
            <div className="text-xs text-gray-500 truncate max-w-[120px]">{data.hostname}</div>
          )}
          {data.os && (
            <div className="text-xs text-gray-600 truncate max-w-[120px]">{data.os}</div>
          )}
        </div>

        {/* Stats row */}
        <div className="flex items-center gap-2 text-xs">
          {(data.openPorts ?? 0) > 0 && (
            <span className="text-cyan-400 bg-cyan-500/20 px-2 py-0.5 rounded">
              {data.openPorts} ports
            </span>
          )}
          {(data.riskScore ?? 0) > 0 && (
            <span className={`px-2 py-0.5 rounded ${
              (data.riskScore ?? 0) >= 75 ? 'text-red-400 bg-red-500/20' :
              (data.riskScore ?? 0) >= 50 ? 'text-orange-400 bg-orange-500/20' :
              (data.riskScore ?? 0) >= 25 ? 'text-yellow-400 bg-yellow-500/20' :
              'text-green-400 bg-green-500/20'
            }`}>
              Risk: {Math.round(data.riskScore ?? 0)}
            </span>
          )}
        </div>

        {(data.vulnerabilities ?? 0) > 0 && (
          <div className="flex items-center gap-1 text-xs text-red-400 bg-red-500/20 px-2 py-0.5 rounded">
            <AlertTriangle className="w-3 h-3" />
            {data.vulnerabilities} vulns
            {(data.criticalVulns ?? 0) > 0 && (
              <span className="text-red-300">({data.criticalVulns} crit)</span>
            )}
          </div>
        )}
      </div>
    </div>
  );
};

// ============================================================================
// Node Types Registration
// ============================================================================

const nodeTypes: NodeTypes = {
  networkDevice: NetworkDeviceNode,
};

// ============================================================================
// Helper Functions
// ============================================================================

const mapNodeType = (nodeType: string, isGateway: boolean): DeviceType => {
  if (isGateway) return 'router';
  switch (nodeType) {
    case 'server':
      return 'server';
    case 'workstation':
      return 'workstation';
    case 'network':
      return 'switch';
    case 'gateway':
      return 'router';
    default:
      return 'unknown';
  }
};

const determineSecurityZone = (subnet: string, isGateway: boolean): SecurityZone => {
  // Simple heuristics based on common network patterns
  if (isGateway) return 'dmz';
  if (subnet.startsWith('10.0.0.') || subnet.startsWith('192.168.0.')) return 'dmz';
  if (subnet.startsWith('10.1.') || subnet.startsWith('192.168.1.')) return 'internal';
  if (subnet.startsWith('10.2.') || subnet.startsWith('192.168.2.')) return 'restricted';
  if (subnet.startsWith('10.255.') || subnet.startsWith('172.16.')) return 'management';
  return 'internal';
};

const getComplianceStatus = (riskScore: number, criticalVulns: number, highVulns: number): ComplianceStatus => {
  if (criticalVulns > 0) return 'non_compliant';
  if (highVulns > 0 || riskScore >= 50) return 'partial';
  if (riskScore > 0) return 'compliant';
  return 'not_assessed';
};

const calculateNodePositions = (
  nodes: TopologyNode[],
  subnets: SubnetGroup[]
): Map<string, { x: number; y: number }> => {
  const positions = new Map<string, { x: number; y: number }>();

  // Group nodes by subnet
  const subnetMap = new Map<string, TopologyNode[]>();
  nodes.forEach(node => {
    const existing = subnetMap.get(node.subnet) || [];
    existing.push(node);
    subnetMap.set(node.subnet, existing);
  });

  // Position subnets vertically, nodes horizontally within each subnet
  let yOffset = 100;
  const baseX = 150;
  const nodeSpacingX = 200;
  const subnetSpacingY = 250;

  subnets.forEach((subnet, subnetIndex) => {
    const subnetNodes = subnetMap.get(subnet.subnet) || [];

    // Sort nodes: gateways first, then by risk score
    subnetNodes.sort((a, b) => {
      if (a.is_gateway && !b.is_gateway) return -1;
      if (!a.is_gateway && b.is_gateway) return 1;
      return b.risk_score - a.risk_score;
    });

    subnetNodes.forEach((node, nodeIndex) => {
      // Calculate position in a grid-like pattern
      const nodesPerRow = Math.ceil(Math.sqrt(subnetNodes.length));
      const row = Math.floor(nodeIndex / nodesPerRow);
      const col = nodeIndex % nodesPerRow;

      positions.set(node.id, {
        x: baseX + col * nodeSpacingX,
        y: yOffset + row * 150,
      });
    });

    yOffset += subnetSpacingY + Math.ceil(subnetNodes.length / Math.ceil(Math.sqrt(subnetNodes.length))) * 150;
  });

  return positions;
};

// ============================================================================
// Main Component
// ============================================================================

const NetworkMap: React.FC<NetworkMapProps> = ({ scanId }) => {
  const [topology, setTopology] = useState<TopologyData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedNode, setSelectedNode] = useState<Node<DeviceData> | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [showAiAdvisor, setShowAiAdvisor] = useState(false);

  const [nodes, setNodes, onNodesChange] = useNodesState<Node<DeviceData>>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge<ConnectionData>>([]);

  // Fetch topology data
  useEffect(() => {
    const fetchTopology = async () => {
      try {
        setLoading(true);
        const token = localStorage.getItem('token');
        const response = await fetch(`/api/scans/${scanId}/topology`, {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        });

        if (!response.ok) {
          throw new Error('Failed to fetch topology data');
        }

        const data = await response.json();
        setTopology(data);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Unknown error');
      } finally {
        setLoading(false);
      }
    };

    fetchTopology();
  }, [scanId]);

  // Transform topology data to ReactFlow format
  useEffect(() => {
    if (!topology) return;

    const positions = calculateNodePositions(topology.nodes, topology.subnets);

    // Convert topology nodes to ReactFlow nodes
    const flowNodes: Node<DeviceData>[] = topology.nodes.map((node) => {
      const position = positions.get(node.id) || { x: 0, y: 0 };

      return {
        id: node.id,
        type: 'networkDevice',
        position,
        data: {
          label: node.hostname || node.ip,
          deviceType: mapNodeType(node.node_type, node.is_gateway),
          securityZone: determineSecurityZone(node.subnet, node.is_gateway),
          ipAddress: node.ip,
          hostname: node.hostname || undefined,
          os: node.os || undefined,
          complianceStatus: getComplianceStatus(node.risk_score, node.critical_vulns, node.high_vulns),
          riskScore: node.risk_score,
          vulnerabilities: node.vuln_count,
          criticalVulns: node.critical_vulns,
          highVulns: node.high_vulns,
          openPorts: node.open_ports_count,
          isGateway: node.is_gateway,
          subnet: node.subnet,
        },
      };
    });

    // Convert topology edges to ReactFlow edges
    const flowEdges: Edge<ConnectionData>[] = topology.edges.map((edge, index) => ({
      id: `edge-${index}`,
      source: edge.source,
      target: edge.target,
      type: 'smoothstep',
      animated: edge.relationship_type === 'gateway',
      style: {
        stroke: edge.relationship_type === 'gateway' ? '#3b82f6' :
                edge.relationship_type === 'shared_service' ? '#8b5cf6' : '#64748b',
        strokeWidth: edge.strength * 2,
      },
      markerEnd: {
        type: MarkerType.ArrowClosed,
        color: edge.relationship_type === 'gateway' ? '#3b82f6' :
               edge.relationship_type === 'shared_service' ? '#8b5cf6' : '#64748b',
      },
      data: {
        relationshipType: edge.relationship_type,
      },
    }));

    setNodes(flowNodes);
    setEdges(flowEdges);
  }, [topology, setNodes, setEdges]);

  const onNodeClick = useCallback((_: React.MouseEvent, node: Node<DeviceData>) => {
    setSelectedNode(node);
  }, []);

  // Convert topology to format for AI analysis
  const topologyForAnalysis: TopologyForAnalysis | null = useMemo(() => {
    if (!topology) return null;

    const analysisNodes: TopologyNodeForAnalysis[] = topology.nodes.map((node) => ({
      id: node.id,
      label: node.hostname || node.ip,
      device_type: node.node_type,
      security_zone: determineSecurityZone(node.subnet, node.is_gateway),
      ip_address: node.ip,
      hostname: node.hostname || undefined,
      os: node.os || undefined,
      compliance_status: getComplianceStatus(node.risk_score, node.critical_vulns, node.high_vulns),
      vulnerabilities: node.vuln_count,
      open_ports: [],  // Would need to be populated if available
    }));

    const analysisEdges: TopologyEdgeForAnalysis[] = topology.edges.map((edge) => ({
      source: edge.source,
      target: edge.target,
      protocol: undefined,  // Would need to be populated if available
      port: undefined,
      encrypted: undefined,
    }));

    return {
      nodes: analysisNodes,
      edges: analysisEdges,
      metadata: {
        name: `Scan ${scanId}`,
      },
    };
  }, [topology, scanId]);

  const handleSearch = useCallback(() => {
    if (!searchQuery || !nodes.length) return;

    const foundNode = nodes.find(
      (n) =>
        n.data.ipAddress?.includes(searchQuery) ||
        n.data.hostname?.toLowerCase().includes(searchQuery.toLowerCase()) ||
        n.data.label.toLowerCase().includes(searchQuery.toLowerCase())
    );

    if (foundNode) {
      setSelectedNode(foundNode);
    }
  }, [searchQuery, nodes]);

  const handleExportPng = useCallback(() => {
    // Export functionality would require additional library
    console.log('Export PNG not yet implemented');
  }, []);

  if (loading) {
    return (
      <Card className="p-8">
        <div className="flex items-center justify-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-cyan-500"></div>
          <span className="ml-4 text-gray-400">Loading network topology...</span>
        </div>
      </Card>
    );
  }

  if (error) {
    return (
      <Card className="p-8">
        <div className="text-center text-red-400">
          <AlertTriangle className="w-12 h-12 mx-auto mb-4" />
          <p>Failed to load topology: {error}</p>
        </div>
      </Card>
    );
  }

  if (!topology || topology.nodes.length === 0) {
    return (
      <Card className="p-8">
        <div className="text-center text-gray-400">
          <Network className="w-16 h-16 mx-auto mb-4 opacity-50" />
          <p>No topology data available for this scan.</p>
          <p className="text-sm mt-2">Run a scan to discover network hosts and connections.</p>
        </div>
      </Card>
    );
  }

  const containerClass = isFullscreen
    ? 'fixed inset-0 z-50 bg-gray-900'
    : 'relative';

  return (
    <div className={containerClass}>
      <div className={`flex gap-4 ${isFullscreen ? 'h-full' : ''}`}>
        <Card className={`${isFullscreen ? 'h-full rounded-none' : 'h-[700px]'} ${showAiAdvisor ? 'flex-1' : 'w-full'} overflow-hidden transition-all duration-300`}>
        <ReactFlow
          nodes={nodes}
          edges={edges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          onNodeClick={onNodeClick}
          nodeTypes={nodeTypes}
          fitView
          fitViewOptions={{ padding: 0.2 }}
          minZoom={0.1}
          maxZoom={2}
          defaultEdgeOptions={{
            type: 'smoothstep',
          }}
        >
          <Background variant={BackgroundVariant.Dots} gap={20} size={1} color="#374151" />
          <Controls
            showZoom={true}
            showFitView={true}
            showInteractive={false}
            className="!bg-gray-800 !border-gray-700 !shadow-lg"
          />
          <MiniMap
            nodeColor={(node) => {
              const data = node.data as DeviceData;
              if ((data.riskScore ?? 0) >= 75) return '#ef4444';
              if ((data.riskScore ?? 0) >= 50) return '#f97316';
              if ((data.riskScore ?? 0) >= 25) return '#eab308';
              return '#22c55e';
            }}
            maskColor="rgba(0, 0, 0, 0.8)"
            className="!bg-gray-800 !border-gray-700"
          />

          {/* Search Panel */}
          <Panel position="top-left" className="flex flex-col gap-2">
            <div className="flex gap-2 bg-gray-800 rounded-lg shadow-lg p-2 border border-gray-700">
              <input
                type="text"
                placeholder="Search IP or hostname..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
                className="px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-sm focus:outline-none focus:ring-2 focus:ring-cyan-500 text-white placeholder-gray-400 w-48"
              />
              <button
                onClick={handleSearch}
                className="px-3 py-2 bg-cyan-600 text-white rounded-md hover:bg-cyan-700 transition-colors"
              >
                <Search className="w-4 h-4" />
              </button>
            </div>

            <div className="flex gap-2 bg-gray-800 rounded-lg shadow-lg p-2 border border-gray-700">
              <button
                onClick={() => setIsFullscreen(!isFullscreen)}
                className="p-2 hover:bg-gray-700 rounded transition-colors"
                title={isFullscreen ? 'Exit Fullscreen' : 'Fullscreen'}
              >
                {isFullscreen ? (
                  <X className="w-5 h-5 text-gray-300" />
                ) : (
                  <Maximize2 className="w-5 h-5 text-gray-300" />
                )}
              </button>
              <button
                onClick={handleExportPng}
                className="p-2 hover:bg-gray-700 rounded transition-colors"
                title="Export as PNG"
              >
                <Download className="w-5 h-5 text-gray-300" />
              </button>
              <button
                onClick={() => setShowAiAdvisor(!showAiAdvisor)}
                className={`p-2 rounded transition-colors ${
                  showAiAdvisor
                    ? 'bg-cyan-600 hover:bg-cyan-700'
                    : 'hover:bg-gray-700'
                }`}
                title="AI Red Team Advisor"
              >
                <Bot className={`w-5 h-5 ${showAiAdvisor ? 'text-white' : 'text-gray-300'}`} />
              </button>
            </div>
          </Panel>

          {/* Legend Panel */}
          <Panel position="top-right">
            <div className="bg-gray-800 rounded-lg shadow-lg p-4 border border-gray-700 max-w-xs">
              <h3 className="text-sm font-semibold mb-3 text-white">Legend</h3>

              <div className="space-y-3 text-xs">
                <div>
                  <div className="font-medium text-gray-300 mb-1">Risk Level</div>
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <div className="w-4 h-4 rounded-full bg-green-500"></div>
                      <span className="text-gray-400">Low (0-25)</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <div className="w-4 h-4 rounded-full bg-yellow-500"></div>
                      <span className="text-gray-400">Medium (25-50)</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <div className="w-4 h-4 rounded-full bg-orange-500"></div>
                      <span className="text-gray-400">High (50-75)</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <div className="w-4 h-4 rounded-full bg-red-500"></div>
                      <span className="text-gray-400">Critical (75+)</span>
                    </div>
                  </div>
                </div>

                <div className="pt-2 border-t border-gray-700">
                  <div className="font-medium text-gray-300 mb-1">Connections</div>
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <div className="w-8 h-0.5 bg-blue-500"></div>
                      <span className="text-gray-400">Gateway</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <div className="w-8 h-0.5 bg-purple-500"></div>
                      <span className="text-gray-400">Shared Service</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <div className="w-8 h-0.5 bg-gray-500"></div>
                      <span className="text-gray-400">Same Subnet</span>
                    </div>
                  </div>
                </div>

                <div className="pt-2 border-t border-gray-700">
                  <div className="font-medium text-gray-300 mb-1">Security Zones</div>
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <div className="w-4 h-4 rounded border-2 border-red-500 bg-red-500/20"></div>
                      <span className="text-gray-400">External</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <div className="w-4 h-4 rounded border-2 border-yellow-500 bg-yellow-500/20"></div>
                      <span className="text-gray-400">DMZ</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <div className="w-4 h-4 rounded border-2 border-blue-500 bg-blue-500/20"></div>
                      <span className="text-gray-400">Internal</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <div className="w-4 h-4 rounded border-2 border-purple-500 bg-purple-500/20"></div>
                      <span className="text-gray-400">Restricted</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <div className="w-4 h-4 rounded border-2 border-green-500 bg-green-500/20"></div>
                      <span className="text-gray-400">Management</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </Panel>

          {/* Subnet Info Panel */}
          <Panel position="bottom-right">
            <div className="bg-gray-800 rounded-lg shadow-lg p-4 border border-gray-700 max-w-xs">
              <h3 className="text-sm font-semibold mb-2 text-white">
                Subnets ({topology.subnets.length})
              </h3>
              <div className="space-y-1 text-xs max-h-32 overflow-y-auto">
                {topology.subnets.map((subnet) => (
                  <div
                    key={subnet.subnet}
                    className="flex justify-between text-gray-400"
                  >
                    <span className="font-mono">{subnet.subnet}</span>
                    <span className="text-gray-500">
                      {subnet.host_count} {subnet.host_count === 1 ? 'host' : 'hosts'}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </Panel>

          {/* Selected Node Details */}
          {selectedNode && (
            <Panel position="bottom-left">
              <div className="bg-gray-800 rounded-lg shadow-lg p-4 border border-gray-700 max-w-sm">
                <div className="flex items-start justify-between mb-3">
                  <div className="flex items-center gap-2">
                    {(() => {
                      const Icon = deviceIcons[selectedNode.data.deviceType];
                      return <Icon className="w-5 h-5 text-cyan-400" />;
                    })()}
                    <h3 className="text-sm font-semibold text-white">
                      {selectedNode.data.label}
                    </h3>
                  </div>
                  <button
                    onClick={() => setSelectedNode(null)}
                    className="text-gray-500 hover:text-gray-300"
                  >
                    <X className="w-4 h-4" />
                  </button>
                </div>

                <div className="space-y-2 text-xs text-gray-400">
                  <div><strong className="text-gray-300">IP:</strong> {selectedNode.data.ipAddress}</div>
                  {selectedNode.data.hostname && (
                    <div><strong className="text-gray-300">Hostname:</strong> {selectedNode.data.hostname}</div>
                  )}
                  {selectedNode.data.os && (
                    <div><strong className="text-gray-300">OS:</strong> {selectedNode.data.os}</div>
                  )}
                  <div><strong className="text-gray-300">Subnet:</strong> {selectedNode.data.subnet}</div>
                  <div><strong className="text-gray-300">Open Ports:</strong> {selectedNode.data.openPorts}</div>

                  {(selectedNode.data.vulnerabilities ?? 0) > 0 && (
                    <div className="mt-2 pt-2 border-t border-gray-700">
                      <div><strong className="text-gray-300">Vulnerabilities:</strong> {selectedNode.data.vulnerabilities}</div>
                      {(selectedNode.data.criticalVulns ?? 0) > 0 && (
                        <div className="text-red-400">
                          Critical: {selectedNode.data.criticalVulns}
                        </div>
                      )}
                      {(selectedNode.data.highVulns ?? 0) > 0 && (
                        <div className="text-orange-400">
                          High: {selectedNode.data.highVulns}
                        </div>
                      )}
                      <div className="mt-1">
                        <strong className="text-gray-300">Risk Score:</strong>{' '}
                        <span className={
                          (selectedNode.data.riskScore ?? 0) >= 75 ? 'text-red-400' :
                          (selectedNode.data.riskScore ?? 0) >= 50 ? 'text-orange-400' :
                          (selectedNode.data.riskScore ?? 0) >= 25 ? 'text-yellow-400' :
                          'text-green-400'
                        }>
                          {(selectedNode.data.riskScore ?? 0).toFixed(1)}
                        </span>
                      </div>
                    </div>
                  )}

                  {selectedNode.data.isGateway && (
                    <div className="mt-2 pt-2 border-t border-gray-700">
                      <span className="inline-flex items-center px-2 py-1 bg-blue-900 text-blue-200 rounded text-xs font-medium">
                        <Router className="w-3 h-3 mr-1" />
                        Gateway
                      </span>
                    </div>
                  )}
                </div>
              </div>
            </Panel>
          )}
        </ReactFlow>
        </Card>

        {/* AI Red Team Advisor Panel */}
        {showAiAdvisor && topologyForAnalysis && (
          <div className={`${isFullscreen ? 'h-full' : 'h-[700px]'} w-[500px] flex-shrink-0`}>
            <RedTeamAdvisorPanel
              topology={topologyForAnalysis}
              scanId={scanId}
              onClose={() => setShowAiAdvisor(false)}
            />
          </div>
        )}
      </div>
    </div>
  );
};

export default NetworkMap;
