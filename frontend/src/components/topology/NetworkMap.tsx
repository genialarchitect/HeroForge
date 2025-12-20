import React, { useEffect, useRef, useState, useCallback } from 'react';
import ForceGraph2D from 'react-force-graph-2d';
import Card from '../ui/Card';
import {
  Server,
  Monitor,
  Network,
  Router,
  HelpCircle,
  ZoomIn,
  ZoomOut,
  Search,
  Maximize2,
  X
} from 'lucide-react';

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

interface GraphNode extends TopologyNode {
  x?: number;
  y?: number;
  vx?: number;
  vy?: number;
  color?: string;
  size?: number;
}

// Link type for force graph (source/target can be string or resolved node)
interface GraphLink {
  source: string | GraphNode;
  target: string | GraphNode;
  relationship_type: 'gateway' | 'same_subnet' | 'shared_service';
  strength: number;
  color?: string;
}

const NetworkMap: React.FC<NetworkMapProps> = ({ scanId }) => {
  const [topology, setTopology] = useState<TopologyData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedNode, setSelectedNode] = useState<TopologyNode | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [isFullscreen, setIsFullscreen] = useState(false);
  const graphRef = useRef<any>();
  const containerRef = useRef<HTMLDivElement>(null);

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

  const getNodeColor = (node: TopologyNode): string => {
    // Color based on risk score
    if (node.critical_vulns > 0 || node.risk_score >= 75) return '#ef4444'; // red
    if (node.high_vulns > 0 || node.risk_score >= 50) return '#f97316'; // orange
    if (node.risk_score >= 25) return '#eab308'; // yellow
    return '#22c55e'; // green
  };

  const getNodeSize = (node: TopologyNode): number => {
    // Size based on importance
    const baseSize = 5;
    const portFactor = Math.min(node.open_ports_count / 10, 3);
    const vulnFactor = Math.min(node.vuln_count / 5, 3);
    const gatewayBonus = node.is_gateway ? 3 : 0;
    return baseSize + portFactor + vulnFactor + gatewayBonus;
  };

  const getNodeIcon = (nodeType: string): React.ReactNode => {
    switch (nodeType) {
      case 'server':
        return <Server className="w-4 h-4" />;
      case 'workstation':
        return <Monitor className="w-4 h-4" />;
      case 'network':
        return <Network className="w-4 h-4" />;
      case 'gateway':
        return <Router className="w-4 h-4" />;
      default:
        return <HelpCircle className="w-4 h-4" />;
    }
  };

  const getLinkColor = (edge: TopologyEdge): string => {
    switch (edge.relationship_type) {
      case 'gateway':
        return '#3b82f6'; // blue
      case 'shared_service':
        return '#8b5cf6'; // purple
      case 'same_subnet':
        return '#6b7280'; // gray
      default:
        return '#6b7280';
    }
  };

  const handleNodeClick = useCallback((node: GraphNode) => {
    setSelectedNode(node);
  }, []);

  const handleZoomIn = () => {
    if (graphRef.current) {
      const currentZoom = graphRef.current.zoom();
      graphRef.current.zoom(currentZoom * 1.3, 400);
    }
  };

  const handleZoomOut = () => {
    if (graphRef.current) {
      const currentZoom = graphRef.current.zoom();
      graphRef.current.zoom(currentZoom / 1.3, 400);
    }
  };

  const handleSearch = () => {
    if (!topology || !searchQuery) return;

    const node = topology.nodes.find(
      (n) =>
        n.ip.includes(searchQuery) ||
        n.hostname?.toLowerCase().includes(searchQuery.toLowerCase())
    );

    if (node && graphRef.current) {
      // Center on node
      const graphNode = node as any; // Force graph adds x,y at runtime
      graphRef.current.centerAt(graphNode.x, graphNode.y, 1000);
      graphRef.current.zoom(3, 1000);
      setSelectedNode(node);
    }
  };

  const toggleFullscreen = () => {
    setIsFullscreen(!isFullscreen);
  };

  if (loading) {
    return (
      <Card className="p-8">
        <div className="flex items-center justify-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-indigo-600"></div>
          <span className="ml-4 text-gray-600 dark:text-gray-400">Loading network topology...</span>
        </div>
      </Card>
    );
  }

  if (error) {
    return (
      <Card className="p-8">
        <div className="text-center text-red-600 dark:text-red-400">
          <p>Failed to load topology: {error}</p>
        </div>
      </Card>
    );
  }

  if (!topology || topology.nodes.length === 0) {
    return (
      <Card className="p-8">
        <div className="text-center text-gray-600 dark:text-gray-400">
          <Network className="w-16 h-16 mx-auto mb-4 opacity-50" />
          <p>No topology data available for this scan.</p>
        </div>
      </Card>
    );
  }

  // Prepare graph data
  const graphData = {
    nodes: topology.nodes.map((node) => ({
      ...node,
      color: getNodeColor(node),
      size: getNodeSize(node),
    })),
    links: topology.edges.map((edge) => ({
      ...edge,
      color: getLinkColor(edge),
    })),
  };

  const containerClass = isFullscreen
    ? 'fixed inset-0 z-50 bg-gray-900'
    : 'relative';

  return (
    <div ref={containerRef} className={containerClass}>
      <Card className={isFullscreen ? 'h-full rounded-none' : 'h-[600px]'}>
        {/* Controls */}
        <div className="absolute top-4 left-4 z-10 flex flex-col gap-2">
          {/* Search */}
          <div className="flex gap-2 bg-white dark:bg-gray-800 rounded-lg shadow-lg p-2">
            <input
              type="text"
              placeholder="Search IP or hostname..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              onKeyPress={(e) => e.key === 'Enter' && handleSearch()}
              className="px-3 py-2 bg-gray-50 dark:bg-gray-700 border border-gray-300 dark:border-gray-600 rounded-md text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500 dark:text-white"
            />
            <button
              onClick={handleSearch}
              className="px-3 py-2 bg-indigo-600 text-white rounded-md hover:bg-indigo-700 transition-colors"
            >
              <Search className="w-4 h-4" />
            </button>
          </div>

          {/* Zoom controls */}
          <div className="flex gap-2 bg-white dark:bg-gray-800 rounded-lg shadow-lg p-2">
            <button
              onClick={handleZoomIn}
              className="p-2 hover:bg-gray-100 dark:hover:bg-gray-700 rounded transition-colors"
              title="Zoom In"
            >
              <ZoomIn className="w-5 h-5 text-gray-700 dark:text-gray-300" />
            </button>
            <button
              onClick={handleZoomOut}
              className="p-2 hover:bg-gray-100 dark:hover:bg-gray-700 rounded transition-colors"
              title="Zoom Out"
            >
              <ZoomOut className="w-5 h-5 text-gray-700 dark:text-gray-300" />
            </button>
            <button
              onClick={toggleFullscreen}
              className="p-2 hover:bg-gray-100 dark:hover:bg-gray-700 rounded transition-colors"
              title={isFullscreen ? 'Exit Fullscreen' : 'Fullscreen'}
            >
              {isFullscreen ? (
                <X className="w-5 h-5 text-gray-700 dark:text-gray-300" />
              ) : (
                <Maximize2 className="w-5 h-5 text-gray-700 dark:text-gray-300" />
              )}
            </button>
          </div>
        </div>

        {/* Legend */}
        <div className="absolute top-4 right-4 z-10 bg-white dark:bg-gray-800 rounded-lg shadow-lg p-4 max-w-xs">
          <h3 className="text-sm font-semibold mb-2 text-gray-900 dark:text-white">Legend</h3>

          <div className="space-y-2 text-xs">
            <div className="font-medium text-gray-700 dark:text-gray-300">Risk Level</div>
            <div className="flex items-center gap-2">
              <div className="w-4 h-4 rounded-full bg-green-500"></div>
              <span className="text-gray-600 dark:text-gray-400">Low (0-25)</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-4 h-4 rounded-full bg-yellow-500"></div>
              <span className="text-gray-600 dark:text-gray-400">Medium (25-50)</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-4 h-4 rounded-full bg-orange-500"></div>
              <span className="text-gray-600 dark:text-gray-400">High (50-75)</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-4 h-4 rounded-full bg-red-500"></div>
              <span className="text-gray-600 dark:text-gray-400">Critical (75+)</span>
            </div>

            <div className="mt-3 pt-2 border-t border-gray-200 dark:border-gray-700">
              <div className="font-medium text-gray-700 dark:text-gray-300 mb-1">Connections</div>
              <div className="flex items-center gap-2">
                <div className="w-8 h-0.5 bg-blue-500"></div>
                <span className="text-gray-600 dark:text-gray-400">Gateway</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-8 h-0.5 bg-purple-500"></div>
                <span className="text-gray-600 dark:text-gray-400">Shared Service</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-8 h-0.5 bg-gray-500"></div>
                <span className="text-gray-600 dark:text-gray-400">Same Subnet</span>
              </div>
            </div>
          </div>
        </div>

        {/* Selected Node Details */}
        {selectedNode && (
          <div className="absolute bottom-4 left-4 z-10 bg-white dark:bg-gray-800 rounded-lg shadow-lg p-4 max-w-sm">
            <div className="flex items-start justify-between mb-2">
              <div className="flex items-center gap-2">
                {getNodeIcon(selectedNode.node_type)}
                <h3 className="text-sm font-semibold text-gray-900 dark:text-white">
                  {selectedNode.hostname || selectedNode.ip}
                </h3>
              </div>
              <button
                onClick={() => setSelectedNode(null)}
                className="text-gray-500 hover:text-gray-700 dark:hover:text-gray-300"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-1 text-xs text-gray-600 dark:text-gray-400">
              <div><strong>IP:</strong> {selectedNode.ip}</div>
              {selectedNode.os && <div><strong>OS:</strong> {selectedNode.os}</div>}
              <div><strong>Subnet:</strong> {selectedNode.subnet}</div>
              <div><strong>Open Ports:</strong> {selectedNode.open_ports_count}</div>
              {selectedNode.vuln_count > 0 && (
                <div className="mt-2 pt-2 border-t border-gray-200 dark:border-gray-700">
                  <div><strong>Vulnerabilities:</strong> {selectedNode.vuln_count}</div>
                  {selectedNode.critical_vulns > 0 && (
                    <div className="text-red-600 dark:text-red-400">
                      Critical: {selectedNode.critical_vulns}
                    </div>
                  )}
                  {selectedNode.high_vulns > 0 && (
                    <div className="text-orange-600 dark:text-orange-400">
                      High: {selectedNode.high_vulns}
                    </div>
                  )}
                  <div>
                    <strong>Risk Score:</strong> {selectedNode.risk_score.toFixed(1)}
                  </div>
                </div>
              )}
              {selectedNode.is_gateway && (
                <div className="mt-2 pt-2 border-t border-gray-200 dark:border-gray-700">
                  <span className="inline-flex items-center px-2 py-1 bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-200 rounded text-xs font-medium">
                    <Router className="w-3 h-3 mr-1" />
                    Gateway
                  </span>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Subnet Groups Info */}
        <div className="absolute bottom-4 right-4 z-10 bg-white dark:bg-gray-800 rounded-lg shadow-lg p-4 max-w-xs">
          <h3 className="text-sm font-semibold mb-2 text-gray-900 dark:text-white">
            Subnets ({topology.subnets.length})
          </h3>
          <div className="space-y-1 text-xs max-h-32 overflow-y-auto">
            {topology.subnets.map((subnet) => (
              <div
                key={subnet.subnet}
                className="flex justify-between text-gray-600 dark:text-gray-400"
              >
                <span className="font-mono">{subnet.subnet}</span>
                <span className="text-gray-500 dark:text-gray-500">
                  {subnet.host_count} {subnet.host_count === 1 ? 'host' : 'hosts'}
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Force Graph */}
        <ForceGraph2D
          ref={graphRef}
          graphData={graphData}
          nodeLabel={(node) => {
            const graphNode = node as GraphNode;
            return `${graphNode.hostname || graphNode.ip}\n${graphNode.os || ''}\nRisk: ${graphNode.risk_score.toFixed(1)}`;
          }}
          nodeColor={(node) => (node as GraphNode).color || '#22c55e'}
          nodeVal={(node) => (node as GraphNode).size || 5}
          linkColor={(link) => (link as GraphLink).color || '#64748b'}
          linkWidth={(link) => ((link as GraphLink).strength || 1) * 2}
          linkDirectionalParticles={(link) => (link as GraphLink).relationship_type === 'gateway' ? 2 : 0}
          linkDirectionalParticleSpeed={0.005}
          onNodeClick={handleNodeClick}
          nodeCanvasObject={(node, ctx: CanvasRenderingContext2D, globalScale: number) => {
            const graphNode = node as GraphNode;
            const label = graphNode.hostname || graphNode.ip;
            const fontSize = 12 / globalScale;
            ctx.font = `${fontSize}px Sans-Serif`;

            // Draw node circle
            ctx.beginPath();
            ctx.arc(graphNode.x || 0, graphNode.y || 0, graphNode.size || 5, 0, 2 * Math.PI, false);
            ctx.fillStyle = graphNode.color || '#22c55e';
            ctx.fill();

            // Draw border for gateways
            if (graphNode.is_gateway) {
              ctx.strokeStyle = '#3b82f6';
              ctx.lineWidth = 2 / globalScale;
              ctx.stroke();
            }

            // Draw label
            if (globalScale > 1.5) {
              ctx.textAlign = 'center';
              ctx.textBaseline = 'middle';
              ctx.fillStyle = 'rgba(255, 255, 255, 0.9)';
              ctx.fillText(label, graphNode.x || 0, (graphNode.y || 0) + (graphNode.size || 5) + fontSize + 2);
            }
          }}
          enableNodeDrag={true}
          enableZoomInteraction={true}
          enablePanInteraction={true}
          cooldownTicks={100}
          onEngineStop={() => graphRef.current?.zoomToFit(400)}
        />
      </Card>
    </div>
  );
};

export default NetworkMap;
