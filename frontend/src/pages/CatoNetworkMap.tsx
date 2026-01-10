import React, { useState, useCallback, useRef, useMemo, useEffect } from 'react';
import {
  ReactFlow,
  Node,
  Edge,
  Controls,
  Background,
  MiniMap,
  useNodesState,
  useEdgesState,
  addEdge,
  Connection,
  MarkerType,
  NodeProps,
  Handle,
  Position,
  Panel,
  NodeTypes,
  BackgroundVariant,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { toast } from 'react-toastify';
import api from '../services/api';
import Layout from '../components/layout/Layout';
import LoadingSpinner from '../components/ui/LoadingSpinner';
import Button from '../components/ui/Button';
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
  Plus,
  Download,
  Upload,
  Trash2,
  Save,
  Settings,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Eye,
  EyeOff,
  Layers,
  Box,
  Cpu,
  Radio,
  Printer,
  Camera,
  ShieldAlert,
  ShieldCheck,
  X,
  FileJson,
  Image,
  ZoomIn,
  ZoomOut,
  Maximize2,
} from 'lucide-react';

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
  | 'vpn';

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
  controlsAssessed?: number;
  controlsPassing?: number;
  vulnerabilities?: number;
  description?: string;
}

interface ConnectionData extends Record<string, unknown> {
  label?: string;
  protocol?: string;
  port?: number;
  encrypted?: boolean;
  dataClassification?: 'public' | 'internal' | 'confidential' | 'restricted';
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
};

const deviceLabels: Record<DeviceType, string> = {
  router: 'Router',
  switch: 'Switch',
  firewall: 'Firewall',
  server: 'Server',
  database: 'Database',
  cloud: 'Cloud Service',
  workstation: 'Workstation',
  laptop: 'Laptop',
  mobile: 'Mobile Device',
  iot: 'IoT Device',
  printer: 'Printer',
  camera: 'Camera',
  wireless_ap: 'Wireless AP',
  load_balancer: 'Load Balancer',
  storage: 'Storage',
  container: 'Container',
  virtual_machine: 'Virtual Machine',
  internet: 'Internet',
  vpn: 'VPN Gateway',
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

  return (
    <div
      className={`relative px-4 py-3 rounded-lg border-2 ${zoneStyle.bg} ${zoneStyle.border} ${
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

      {/* Device icon and info */}
      <div className="flex flex-col items-center gap-2 min-w-[100px]">
        <div className={`p-3 rounded-lg bg-gray-800/80 ${zoneStyle.border} border`}>
          <Icon className={`w-8 h-8 ${zoneStyle.text}`} />
        </div>
        <div className="text-center">
          <div className="font-semibold text-white text-sm">{data.label}</div>
          {data.ipAddress && (
            <div className="text-xs text-gray-400 font-mono">{data.ipAddress}</div>
          )}
          {data.hostname && (
            <div className="text-xs text-gray-500">{data.hostname}</div>
          )}
        </div>
        {data.vulnerabilities && data.vulnerabilities > 0 && (
          <div className="flex items-center gap-1 text-xs text-red-400 bg-red-500/20 px-2 py-0.5 rounded">
            <AlertTriangle className="w-3 h-3" />
            {data.vulnerabilities} vuln
          </div>
        )}
      </div>
    </div>
  );
};

// ============================================================================
// Security Zone Group Node
// ============================================================================

const SecurityZoneNode: React.FC<NodeProps<Node<{ label: string; zone: SecurityZone }>>> = ({ data }) => {
  const zoneStyle = zoneColors[data.zone];

  return (
    <div
      className={`px-6 py-4 rounded-xl border-2 border-dashed ${zoneStyle.border} ${zoneStyle.bg} min-w-[200px] min-h-[150px]`}
      style={{ pointerEvents: 'none' }}
    >
      <div className={`text-sm font-bold ${zoneStyle.text} uppercase tracking-wider`}>
        {data.label}
      </div>
    </div>
  );
};

// ============================================================================
// Node Types Registration
// ============================================================================

const nodeTypes: NodeTypes = {
  networkDevice: NetworkDeviceNode,
  securityZone: SecurityZoneNode,
};

// ============================================================================
// Sample Network Topology Data
// ============================================================================

const generateSampleTopology = (): { nodes: Node<DeviceData>[]; edges: Edge<ConnectionData>[] } => {
  const nodes: Node<DeviceData>[] = [
    // External Zone
    {
      id: 'internet',
      type: 'networkDevice',
      position: { x: 400, y: 0 },
      data: {
        label: 'Internet',
        deviceType: 'internet',
        securityZone: 'external',
        complianceStatus: 'not_assessed',
      },
    },

    // DMZ Zone
    {
      id: 'ext-firewall',
      type: 'networkDevice',
      position: { x: 400, y: 120 },
      data: {
        label: 'External Firewall',
        deviceType: 'firewall',
        securityZone: 'dmz',
        ipAddress: '10.0.0.1',
        hostname: 'fw-ext-01',
        complianceStatus: 'compliant',
        controlsAssessed: 45,
        controlsPassing: 43,
      },
    },
    {
      id: 'dmz-switch',
      type: 'networkDevice',
      position: { x: 400, y: 240 },
      data: {
        label: 'DMZ Switch',
        deviceType: 'switch',
        securityZone: 'dmz',
        ipAddress: '10.0.1.1',
        hostname: 'sw-dmz-01',
        complianceStatus: 'compliant',
        controlsAssessed: 20,
        controlsPassing: 20,
      },
    },
    {
      id: 'web-server',
      type: 'networkDevice',
      position: { x: 200, y: 350 },
      data: {
        label: 'Web Server',
        deviceType: 'server',
        securityZone: 'dmz',
        ipAddress: '10.0.1.10',
        hostname: 'web-01',
        os: 'Ubuntu 22.04',
        complianceStatus: 'partial',
        controlsAssessed: 85,
        controlsPassing: 72,
        vulnerabilities: 3,
      },
    },
    {
      id: 'mail-server',
      type: 'networkDevice',
      position: { x: 400, y: 350 },
      data: {
        label: 'Mail Server',
        deviceType: 'server',
        securityZone: 'dmz',
        ipAddress: '10.0.1.11',
        hostname: 'mail-01',
        os: 'RHEL 8',
        complianceStatus: 'compliant',
        controlsAssessed: 90,
        controlsPassing: 88,
      },
    },
    {
      id: 'vpn-gateway',
      type: 'networkDevice',
      position: { x: 600, y: 350 },
      data: {
        label: 'VPN Gateway',
        deviceType: 'vpn',
        securityZone: 'dmz',
        ipAddress: '10.0.1.12',
        hostname: 'vpn-01',
        complianceStatus: 'compliant',
        controlsAssessed: 40,
        controlsPassing: 40,
      },
    },

    // Internal Firewall
    {
      id: 'int-firewall',
      type: 'networkDevice',
      position: { x: 400, y: 480 },
      data: {
        label: 'Internal Firewall',
        deviceType: 'firewall',
        securityZone: 'internal',
        ipAddress: '10.1.0.1',
        hostname: 'fw-int-01',
        complianceStatus: 'compliant',
        controlsAssessed: 45,
        controlsPassing: 44,
      },
    },

    // Internal Zone
    {
      id: 'core-switch',
      type: 'networkDevice',
      position: { x: 400, y: 600 },
      data: {
        label: 'Core Switch',
        deviceType: 'switch',
        securityZone: 'internal',
        ipAddress: '10.1.1.1',
        hostname: 'sw-core-01',
        complianceStatus: 'compliant',
        controlsAssessed: 25,
        controlsPassing: 25,
      },
    },
    {
      id: 'app-server-1',
      type: 'networkDevice',
      position: { x: 100, y: 720 },
      data: {
        label: 'App Server 1',
        deviceType: 'server',
        securityZone: 'internal',
        ipAddress: '10.1.2.10',
        hostname: 'app-01',
        os: 'Windows Server 2022',
        complianceStatus: 'partial',
        controlsAssessed: 95,
        controlsPassing: 80,
        vulnerabilities: 5,
      },
    },
    {
      id: 'app-server-2',
      type: 'networkDevice',
      position: { x: 300, y: 720 },
      data: {
        label: 'App Server 2',
        deviceType: 'container',
        securityZone: 'internal',
        ipAddress: '10.1.2.11',
        hostname: 'k8s-node-01',
        os: 'Kubernetes',
        complianceStatus: 'compliant',
        controlsAssessed: 100,
        controlsPassing: 98,
      },
    },
    {
      id: 'load-balancer',
      type: 'networkDevice',
      position: { x: 200, y: 600 },
      data: {
        label: 'Load Balancer',
        deviceType: 'load_balancer',
        securityZone: 'internal',
        ipAddress: '10.1.2.1',
        hostname: 'lb-01',
        complianceStatus: 'compliant',
        controlsAssessed: 30,
        controlsPassing: 30,
      },
    },
    {
      id: 'wireless-ap',
      type: 'networkDevice',
      position: { x: 600, y: 720 },
      data: {
        label: 'Wireless AP',
        deviceType: 'wireless_ap',
        securityZone: 'internal',
        ipAddress: '10.1.3.1',
        hostname: 'ap-01',
        complianceStatus: 'partial',
        controlsAssessed: 20,
        controlsPassing: 16,
        vulnerabilities: 2,
      },
    },
    {
      id: 'workstation-1',
      type: 'networkDevice',
      position: { x: 700, y: 820 },
      data: {
        label: 'Workstation',
        deviceType: 'workstation',
        securityZone: 'internal',
        ipAddress: '10.1.4.100',
        hostname: 'ws-001',
        os: 'Windows 11',
        complianceStatus: 'compliant',
        controlsAssessed: 50,
        controlsPassing: 48,
      },
    },
    {
      id: 'laptop-1',
      type: 'networkDevice',
      position: { x: 500, y: 820 },
      data: {
        label: 'Mobile Laptop',
        deviceType: 'laptop',
        securityZone: 'internal',
        ipAddress: 'DHCP',
        hostname: 'laptop-001',
        os: 'macOS',
        complianceStatus: 'partial',
        controlsAssessed: 45,
        controlsPassing: 38,
        vulnerabilities: 1,
      },
    },

    // Restricted Zone (Data)
    {
      id: 'db-firewall',
      type: 'networkDevice',
      position: { x: 200, y: 850 },
      data: {
        label: 'DB Firewall',
        deviceType: 'firewall',
        securityZone: 'restricted',
        ipAddress: '10.2.0.1',
        hostname: 'fw-db-01',
        complianceStatus: 'compliant',
        controlsAssessed: 50,
        controlsPassing: 50,
      },
    },
    {
      id: 'primary-db',
      type: 'networkDevice',
      position: { x: 100, y: 970 },
      data: {
        label: 'Primary Database',
        deviceType: 'database',
        securityZone: 'restricted',
        ipAddress: '10.2.1.10',
        hostname: 'db-primary',
        os: 'PostgreSQL 15',
        complianceStatus: 'compliant',
        controlsAssessed: 80,
        controlsPassing: 78,
      },
    },
    {
      id: 'replica-db',
      type: 'networkDevice',
      position: { x: 300, y: 970 },
      data: {
        label: 'Replica Database',
        deviceType: 'database',
        securityZone: 'restricted',
        ipAddress: '10.2.1.11',
        hostname: 'db-replica',
        os: 'PostgreSQL 15',
        complianceStatus: 'compliant',
        controlsAssessed: 80,
        controlsPassing: 80,
      },
    },
    {
      id: 'storage-san',
      type: 'networkDevice',
      position: { x: 200, y: 1080 },
      data: {
        label: 'SAN Storage',
        deviceType: 'storage',
        securityZone: 'restricted',
        ipAddress: '10.2.2.1',
        hostname: 'san-01',
        complianceStatus: 'compliant',
        controlsAssessed: 40,
        controlsPassing: 40,
      },
    },

    // Management Zone
    {
      id: 'mgmt-switch',
      type: 'networkDevice',
      position: { x: 700, y: 600 },
      data: {
        label: 'Mgmt Switch',
        deviceType: 'switch',
        securityZone: 'management',
        ipAddress: '10.3.0.1',
        hostname: 'sw-mgmt-01',
        complianceStatus: 'compliant',
        controlsAssessed: 20,
        controlsPassing: 20,
      },
    },
    {
      id: 'siem',
      type: 'networkDevice',
      position: { x: 850, y: 550 },
      data: {
        label: 'SIEM',
        deviceType: 'server',
        securityZone: 'management',
        ipAddress: '10.3.1.10',
        hostname: 'siem-01',
        complianceStatus: 'compliant',
        controlsAssessed: 60,
        controlsPassing: 58,
      },
    },
    {
      id: 'monitoring',
      type: 'networkDevice',
      position: { x: 850, y: 670 },
      data: {
        label: 'Monitoring',
        deviceType: 'server',
        securityZone: 'management',
        ipAddress: '10.3.1.11',
        hostname: 'monitor-01',
        complianceStatus: 'compliant',
        controlsAssessed: 45,
        controlsPassing: 45,
      },
    },

    // Cloud Services
    {
      id: 'cloud-aws',
      type: 'networkDevice',
      position: { x: 50, y: 120 },
      data: {
        label: 'AWS Cloud',
        deviceType: 'cloud',
        securityZone: 'external',
        complianceStatus: 'partial',
        controlsAssessed: 120,
        controlsPassing: 100,
        vulnerabilities: 8,
        description: 'Cloud infrastructure',
      },
    },
  ];

  const edges: Edge<ConnectionData>[] = [
    // Internet to DMZ
    {
      id: 'e-internet-fw',
      source: 'internet',
      target: 'ext-firewall',
      animated: true,
      style: { stroke: '#ef4444' },
      markerEnd: { type: MarkerType.ArrowClosed, color: '#ef4444' },
      label: 'HTTPS/443',
      data: { protocol: 'HTTPS', port: 443, encrypted: true, dataClassification: 'public' },
    },
    {
      id: 'e-cloud-fw',
      source: 'cloud-aws',
      target: 'ext-firewall',
      animated: true,
      style: { stroke: '#ef4444' },
      markerEnd: { type: MarkerType.ArrowClosed, color: '#ef4444' },
      label: 'VPN/IPSec',
      data: { protocol: 'IPSec', encrypted: true },
    },

    // DMZ connections
    {
      id: 'e-fw-dmz-sw',
      source: 'ext-firewall',
      target: 'dmz-switch',
      style: { stroke: '#eab308' },
      markerEnd: { type: MarkerType.ArrowClosed, color: '#eab308' },
    },
    {
      id: 'e-dmz-web',
      source: 'dmz-switch',
      target: 'web-server',
      style: { stroke: '#eab308' },
      markerEnd: { type: MarkerType.ArrowClosed, color: '#eab308' },
      label: 'HTTP/80',
      data: { protocol: 'HTTP', port: 80 },
    },
    {
      id: 'e-dmz-mail',
      source: 'dmz-switch',
      target: 'mail-server',
      style: { stroke: '#eab308' },
      markerEnd: { type: MarkerType.ArrowClosed, color: '#eab308' },
      label: 'SMTP/25',
      data: { protocol: 'SMTP', port: 25, encrypted: true },
    },
    {
      id: 'e-dmz-vpn',
      source: 'dmz-switch',
      target: 'vpn-gateway',
      style: { stroke: '#eab308' },
      markerEnd: { type: MarkerType.ArrowClosed, color: '#eab308' },
      label: 'OpenVPN/1194',
      data: { protocol: 'OpenVPN', port: 1194, encrypted: true },
    },

    // DMZ to Internal
    {
      id: 'e-dmz-int-fw',
      source: 'dmz-switch',
      target: 'int-firewall',
      style: { stroke: '#3b82f6', strokeWidth: 2 },
      markerEnd: { type: MarkerType.ArrowClosed, color: '#3b82f6' },
    },

    // Internal Zone
    {
      id: 'e-int-fw-core',
      source: 'int-firewall',
      target: 'core-switch',
      style: { stroke: '#3b82f6' },
      markerEnd: { type: MarkerType.ArrowClosed, color: '#3b82f6' },
    },
    {
      id: 'e-core-lb',
      source: 'core-switch',
      target: 'load-balancer',
      style: { stroke: '#3b82f6' },
      markerEnd: { type: MarkerType.ArrowClosed, color: '#3b82f6' },
    },
    {
      id: 'e-lb-app1',
      source: 'load-balancer',
      target: 'app-server-1',
      style: { stroke: '#3b82f6' },
      markerEnd: { type: MarkerType.ArrowClosed, color: '#3b82f6' },
      label: 'HTTP/8080',
      data: { protocol: 'HTTP', port: 8080 },
    },
    {
      id: 'e-lb-app2',
      source: 'load-balancer',
      target: 'app-server-2',
      style: { stroke: '#3b82f6' },
      markerEnd: { type: MarkerType.ArrowClosed, color: '#3b82f6' },
      label: 'HTTP/8080',
      data: { protocol: 'HTTP', port: 8080 },
    },
    {
      id: 'e-core-ap',
      source: 'core-switch',
      target: 'wireless-ap',
      style: { stroke: '#3b82f6' },
      markerEnd: { type: MarkerType.ArrowClosed, color: '#3b82f6' },
    },
    {
      id: 'e-ap-ws',
      source: 'wireless-ap',
      target: 'workstation-1',
      style: { stroke: '#3b82f6', strokeDasharray: '5,5' },
      markerEnd: { type: MarkerType.ArrowClosed, color: '#3b82f6' },
      label: 'WiFi',
    },
    {
      id: 'e-ap-laptop',
      source: 'wireless-ap',
      target: 'laptop-1',
      style: { stroke: '#3b82f6', strokeDasharray: '5,5' },
      markerEnd: { type: MarkerType.ArrowClosed, color: '#3b82f6' },
      label: 'WiFi',
    },

    // Restricted Zone
    {
      id: 'e-app1-dbfw',
      source: 'app-server-1',
      target: 'db-firewall',
      style: { stroke: '#a855f7' },
      markerEnd: { type: MarkerType.ArrowClosed, color: '#a855f7' },
      label: 'SQL/5432',
      data: { protocol: 'PostgreSQL', port: 5432, encrypted: true, dataClassification: 'confidential' },
    },
    {
      id: 'e-app2-dbfw',
      source: 'app-server-2',
      target: 'db-firewall',
      style: { stroke: '#a855f7' },
      markerEnd: { type: MarkerType.ArrowClosed, color: '#a855f7' },
      label: 'SQL/5432',
      data: { protocol: 'PostgreSQL', port: 5432, encrypted: true, dataClassification: 'confidential' },
    },
    {
      id: 'e-dbfw-primary',
      source: 'db-firewall',
      target: 'primary-db',
      style: { stroke: '#a855f7' },
      markerEnd: { type: MarkerType.ArrowClosed, color: '#a855f7' },
    },
    {
      id: 'e-dbfw-replica',
      source: 'db-firewall',
      target: 'replica-db',
      style: { stroke: '#a855f7' },
      markerEnd: { type: MarkerType.ArrowClosed, color: '#a855f7' },
    },
    {
      id: 'e-primary-replica',
      source: 'primary-db',
      target: 'replica-db',
      style: { stroke: '#a855f7', strokeDasharray: '3,3' },
      markerEnd: { type: MarkerType.ArrowClosed, color: '#a855f7' },
      label: 'Replication',
    },
    {
      id: 'e-db-san',
      source: 'primary-db',
      target: 'storage-san',
      style: { stroke: '#a855f7' },
      markerEnd: { type: MarkerType.ArrowClosed, color: '#a855f7' },
      label: 'iSCSI',
      data: { protocol: 'iSCSI', encrypted: true, dataClassification: 'restricted' },
    },

    // Management Zone
    {
      id: 'e-core-mgmt',
      source: 'core-switch',
      target: 'mgmt-switch',
      style: { stroke: '#22c55e' },
      markerEnd: { type: MarkerType.ArrowClosed, color: '#22c55e' },
    },
    {
      id: 'e-mgmt-siem',
      source: 'mgmt-switch',
      target: 'siem',
      style: { stroke: '#22c55e' },
      markerEnd: { type: MarkerType.ArrowClosed, color: '#22c55e' },
      label: 'Syslog/514',
      data: { protocol: 'Syslog', port: 514 },
    },
    {
      id: 'e-mgmt-monitor',
      source: 'mgmt-switch',
      target: 'monitoring',
      style: { stroke: '#22c55e' },
      markerEnd: { type: MarkerType.ArrowClosed, color: '#22c55e' },
      label: 'SNMP/161',
      data: { protocol: 'SNMP', port: 161 },
    },
  ];

  return { nodes, edges };
};

// ============================================================================
// Add Device Modal
// ============================================================================

interface AddDeviceModalProps {
  isOpen: boolean;
  onClose: () => void;
  onAdd: (device: Partial<DeviceData> & { position: { x: number; y: number } }) => void;
}

const AddDeviceModal: React.FC<AddDeviceModalProps> = ({ isOpen, onClose, onAdd }) => {
  const [deviceType, setDeviceType] = useState<DeviceType>('server');
  const [label, setLabel] = useState('');
  const [ipAddress, setIpAddress] = useState('');
  const [hostname, setHostname] = useState('');
  const [securityZone, setSecurityZone] = useState<SecurityZone>('internal');

  if (!isOpen) return null;

  const handleSubmit = () => {
    if (!label) {
      toast.error('Please enter a device name');
      return;
    }

    onAdd({
      label,
      deviceType,
      ipAddress: ipAddress || undefined,
      hostname: hostname || undefined,
      securityZone,
      complianceStatus: 'not_assessed',
      position: { x: 400, y: 400 },
    });

    setLabel('');
    setIpAddress('');
    setHostname('');
    onClose();
  };

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <div className="bg-gray-800 rounded-lg w-full max-w-md">
        <div className="p-6 border-b border-gray-700 flex items-center justify-between">
          <h2 className="text-xl font-bold text-white">Add Network Device</h2>
          <button onClick={onClose} className="text-gray-400 hover:text-white">
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="p-6 space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-400 mb-2">Device Type</label>
            <div className="grid grid-cols-4 gap-2">
              {Object.entries(deviceLabels).map(([type, label]) => {
                const Icon = deviceIcons[type as DeviceType];
                return (
                  <button
                    key={type}
                    onClick={() => setDeviceType(type as DeviceType)}
                    className={`p-2 rounded-lg border flex flex-col items-center gap-1 ${
                      deviceType === type
                        ? 'border-cyan-500 bg-cyan-500/10'
                        : 'border-gray-600 hover:border-gray-500'
                    }`}
                  >
                    <Icon className="w-5 h-5 text-gray-300" />
                    <span className="text-xs text-gray-400 truncate w-full text-center">{label}</span>
                  </button>
                );
              })}
            </div>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-400 mb-1">Device Name</label>
            <input
              type="text"
              value={label}
              onChange={(e) => setLabel(e.target.value)}
              placeholder="e.g., Web Server 1"
              className="w-full p-2 bg-gray-900 border border-gray-600 rounded-lg text-white"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-400 mb-1">IP Address</label>
            <input
              type="text"
              value={ipAddress}
              onChange={(e) => setIpAddress(e.target.value)}
              placeholder="e.g., 10.0.0.1"
              className="w-full p-2 bg-gray-900 border border-gray-600 rounded-lg text-white font-mono"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-400 mb-1">Hostname</label>
            <input
              type="text"
              value={hostname}
              onChange={(e) => setHostname(e.target.value)}
              placeholder="e.g., server-01"
              className="w-full p-2 bg-gray-900 border border-gray-600 rounded-lg text-white"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-400 mb-1">Security Zone</label>
            <select
              value={securityZone}
              onChange={(e) => setSecurityZone(e.target.value as SecurityZone)}
              className="w-full p-2 bg-gray-900 border border-gray-600 rounded-lg text-white"
            >
              <option value="external">External (Untrusted)</option>
              <option value="dmz">DMZ (Demilitarized Zone)</option>
              <option value="internal">Internal (Trusted)</option>
              <option value="restricted">Restricted (High Security)</option>
              <option value="management">Management</option>
            </select>
          </div>
        </div>

        <div className="p-6 border-t border-gray-700 flex justify-end gap-3">
          <Button variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button onClick={handleSubmit}>
            <Plus className="w-4 h-4 mr-2" />
            Add Device
          </Button>
        </div>
      </div>
    </div>
  );
};

// ============================================================================
// Device Details Panel
// ============================================================================

interface DeviceDetailsPanelProps {
  device: Node<DeviceData> | null;
  onClose: () => void;
  onUpdate: (id: string, data: Partial<DeviceData>) => void;
  onDelete: (id: string) => void;
}

const DeviceDetailsPanel: React.FC<DeviceDetailsPanelProps> = ({
  device,
  onClose,
  onUpdate,
  onDelete,
}) => {
  if (!device) return null;

  const Icon = deviceIcons[device.data.deviceType];
  const zoneStyle = zoneColors[device.data.securityZone];

  return (
    <div className="absolute right-4 top-4 w-80 bg-gray-800 rounded-lg border border-gray-700 shadow-xl z-10">
      <div className="p-4 border-b border-gray-700 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className={`p-2 rounded-lg ${zoneStyle.bg} ${zoneStyle.border} border`}>
            <Icon className={`w-5 h-5 ${zoneStyle.text}`} />
          </div>
          <div>
            <h3 className="font-semibold text-white">{device.data.label}</h3>
            <p className="text-xs text-gray-400">{deviceLabels[device.data.deviceType]}</p>
          </div>
        </div>
        <button onClick={onClose} className="text-gray-400 hover:text-white">
          <X className="w-5 h-5" />
        </button>
      </div>

      <div className="p-4 space-y-3 text-sm">
        {device.data.ipAddress && (
          <div className="flex justify-between">
            <span className="text-gray-400">IP Address</span>
            <span className="text-white font-mono">{device.data.ipAddress}</span>
          </div>
        )}
        {device.data.hostname && (
          <div className="flex justify-between">
            <span className="text-gray-400">Hostname</span>
            <span className="text-white">{device.data.hostname}</span>
          </div>
        )}
        {device.data.os && (
          <div className="flex justify-between">
            <span className="text-gray-400">OS/Platform</span>
            <span className="text-white">{device.data.os}</span>
          </div>
        )}
        <div className="flex justify-between">
          <span className="text-gray-400">Security Zone</span>
          <span className={zoneStyle.text}>{device.data.securityZone.toUpperCase()}</span>
        </div>

        <div className="border-t border-gray-700 pt-3 mt-3">
          <h4 className="text-gray-400 mb-2">Compliance Status</h4>
          <div className="flex items-center gap-2 mb-2">
            {device.data.complianceStatus === 'compliant' && (
              <>
                <CheckCircle className="w-4 h-4 text-green-400" />
                <span className="text-green-400">Compliant</span>
              </>
            )}
            {device.data.complianceStatus === 'non_compliant' && (
              <>
                <XCircle className="w-4 h-4 text-red-400" />
                <span className="text-red-400">Non-Compliant</span>
              </>
            )}
            {device.data.complianceStatus === 'partial' && (
              <>
                <AlertTriangle className="w-4 h-4 text-yellow-400" />
                <span className="text-yellow-400">Partially Compliant</span>
              </>
            )}
            {device.data.complianceStatus === 'not_assessed' && (
              <>
                <Shield className="w-4 h-4 text-gray-400" />
                <span className="text-gray-400">Not Assessed</span>
              </>
            )}
          </div>

          {device.data.controlsAssessed && (
            <div className="text-xs text-gray-400">
              {device.data.controlsPassing || 0}/{device.data.controlsAssessed} controls passing
              <div className="w-full h-2 bg-gray-700 rounded-full mt-1">
                <div
                  className="h-full bg-green-500 rounded-full"
                  style={{
                    width: `${((device.data.controlsPassing || 0) / device.data.controlsAssessed) * 100}%`,
                  }}
                />
              </div>
            </div>
          )}

          {device.data.vulnerabilities && device.data.vulnerabilities > 0 && (
            <div className="mt-2 flex items-center gap-2 text-red-400 text-xs bg-red-500/10 p-2 rounded">
              <AlertTriangle className="w-4 h-4" />
              {device.data.vulnerabilities} vulnerabilities detected
            </div>
          )}
        </div>
      </div>

      <div className="p-4 border-t border-gray-700 flex gap-2">
        <Button variant="secondary" size="sm" className="flex-1">
          <Settings className="w-4 h-4 mr-1" />
          Edit
        </Button>
        <Button
          variant="secondary"
          size="sm"
          className="text-red-400 hover:text-red-300"
          onClick={() => onDelete(device.id)}
        >
          <Trash2 className="w-4 h-4" />
        </Button>
      </div>
    </div>
  );
};

// ============================================================================
// Main Component
// ============================================================================

interface TopologyMetadata {
  name: string;
  description?: string;
  lastUpdated: string;
  totalDevices: number;
  totalConnections: number;
  dataSource: string;
}

const CatoNetworkMap: React.FC = () => {
  const [nodes, setNodes, onNodesChange] = useNodesState<Node<DeviceData>>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge<ConnectionData>>([]);
  const [selectedNode, setSelectedNode] = useState<Node<DeviceData> | null>(null);
  const [showAddModal, setShowAddModal] = useState(false);
  const [showLabels, setShowLabels] = useState(true);
  const [showZones, setShowZones] = useState(true);
  const [loading, setLoading] = useState(true);
  const [metadata, setMetadata] = useState<TopologyMetadata | null>(null);
  const [engagements, setEngagements] = useState<Array<{ id: string; name: string }>>([]);
  const [selectedEngagement, setSelectedEngagement] = useState<string>('');
  const [dataSource, setDataSource] = useState<'api' | 'sample'>('api');
  const [isSaving, setIsSaving] = useState(false);
  const reactFlowWrapper = useRef<HTMLDivElement>(null);

  // Fetch engagements list
  useEffect(() => {
    const fetchEngagements = async () => {
      try {
        const response = await api.get('/api/engagements');
        setEngagements(response.data.engagements || response.data || []);
      } catch (error) {
        console.error('Failed to fetch engagements:', error);
      }
    };
    fetchEngagements();
  }, []);

  // Fetch topology data from API
  useEffect(() => {
    const fetchTopology = async () => {
      setLoading(true);
      try {
        if (dataSource === 'sample') {
          const { nodes: sampleNodes, edges: sampleEdges } = generateSampleTopology();
          setNodes(sampleNodes);
          setEdges(sampleEdges);
          setMetadata({
            name: 'Sample Network Topology',
            description: 'Demo topology with sample devices',
            lastUpdated: new Date().toISOString(),
            totalDevices: sampleNodes.length,
            totalConnections: sampleEdges.length,
            dataSource: 'sample',
          });
        } else {
          const params = selectedEngagement ? `?engagement_id=${selectedEngagement}` : '';
          const response = await api.get(`/api/network-topology${params}`);
          const data = response.data;

          if (data.nodes && data.nodes.length > 0) {
            setNodes(data.nodes);
            setEdges(data.edges || []);
            setMetadata(data.metadata);
          } else {
            // No data found - show empty state or sample
            toast.info('No network topology data found. You can add devices or use sample data.');
            setNodes([]);
            setEdges([]);
            setMetadata({
              name: 'New Network Topology',
              description: 'Add devices to build your network map',
              lastUpdated: new Date().toISOString(),
              totalDevices: 0,
              totalConnections: 0,
              dataSource: 'empty',
            });
          }
        }
      } catch (error) {
        console.error('Failed to fetch topology:', error);
        toast.error('Failed to load topology. Using sample data.');
        const { nodes: sampleNodes, edges: sampleEdges } = generateSampleTopology();
        setNodes(sampleNodes);
        setEdges(sampleEdges);
        setDataSource('sample');
      } finally {
        setLoading(false);
      }
    };

    fetchTopology();
  }, [selectedEngagement, dataSource, setNodes, setEdges]);

  const onConnect = useCallback(
    (connection: Connection) => {
      const newEdge = {
        ...connection,
        markerEnd: { type: MarkerType.ArrowClosed, color: '#06b6d4' },
        style: { stroke: '#06b6d4' },
      };
      setEdges((eds) => addEdge(newEdge, eds));
    },
    [setEdges]
  );

  const onNodeClick = useCallback((_: React.MouseEvent, node: Node) => {
    setSelectedNode(node as Node<DeviceData>);
  }, []);

  const onPaneClick = useCallback(() => {
    setSelectedNode(null);
  }, []);

  const handleAddDevice = (deviceData: Partial<DeviceData> & { position: { x: number; y: number } }) => {
    const newNode: Node<DeviceData> = {
      id: `device-${Date.now()}`,
      type: 'networkDevice',
      position: deviceData.position,
      data: {
        label: deviceData.label || 'New Device',
        deviceType: deviceData.deviceType || 'server',
        securityZone: deviceData.securityZone || 'internal',
        ipAddress: deviceData.ipAddress,
        hostname: deviceData.hostname,
        complianceStatus: 'not_assessed',
      },
    };
    setNodes((nds) => [...nds, newNode]);
    toast.success(`Added ${deviceData.label}`);
  };

  const handleDeleteNode = (id: string) => {
    setNodes((nds) => nds.filter((n) => n.id !== id));
    setEdges((eds) => eds.filter((e) => e.source !== id && e.target !== id));
    setSelectedNode(null);
    toast.success('Device removed');
  };

  const handleExportJSON = () => {
    const data = { nodes, edges };
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `cato-network-map-${new Date().toISOString().split('T')[0]}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    toast.success('Network map exported');
  };

  const handleExportImage = () => {
    toast.info('Image export coming soon');
  };

  // Save topology to backend
  const handleSaveTopology = async () => {
    setIsSaving(true);
    try {
      await api.post('/api/network-topology', {
        name: metadata?.name || 'Network Topology',
        description: metadata?.description,
        engagementId: selectedEngagement || null,
        nodes,
        edges,
      });
      toast.success('Topology saved successfully');
    } catch (error) {
      console.error('Failed to save topology:', error);
      toast.error('Failed to save topology');
    } finally {
      setIsSaving(false);
    }
  };

  // Calculate compliance stats
  const complianceStats = useMemo(() => {
    const devices = nodes.filter((n) => n.type === 'networkDevice');
    const total = devices.length;
    const compliant = devices.filter((n) => (n.data as DeviceData).complianceStatus === 'compliant').length;
    const nonCompliant = devices.filter((n) => (n.data as DeviceData).complianceStatus === 'non_compliant').length;
    const partial = devices.filter((n) => (n.data as DeviceData).complianceStatus === 'partial').length;
    const notAssessed = devices.filter((n) => (n.data as DeviceData).complianceStatus === 'not_assessed').length;
    const totalVulns = devices.reduce((sum, n) => sum + ((n.data as DeviceData).vulnerabilities || 0), 0);

    return { total, compliant, nonCompliant, partial, notAssessed, totalVulns };
  }, [nodes]);

  if (loading) {
    return (
      <Layout>
        <div className="flex items-center justify-center h-[calc(100vh-80px)]">
          <LoadingSpinner />
        </div>
      </Layout>
    );
  }

  return (
    <Layout>
      <div className="h-[calc(100vh-80px)] flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between mb-4">
          <div>
            <h1 className="text-2xl font-bold text-white flex items-center gap-3">
              <Network className="w-8 h-8 text-cyan-400" />
              cATO Network Topology Map
            </h1>
            <p className="text-gray-400 mt-1">
              {metadata?.name || 'Network Architecture & Data Flow Visualization'}
              {metadata?.dataSource && metadata.dataSource !== 'sample' && (
                <span className="text-xs text-green-400 ml-2">
                  (from {metadata.dataSource})
                </span>
              )}
              {metadata?.dataSource === 'sample' && (
                <span className="text-xs text-yellow-400 ml-2">(sample data)</span>
              )}
            </p>
          </div>
          <div className="flex gap-2">
            <Button variant="secondary" onClick={handleSaveTopology} disabled={isSaving}>
              <Save className="w-4 h-4 mr-2" />
              {isSaving ? 'Saving...' : 'Save'}
            </Button>
            <Button variant="secondary" onClick={() => setShowAddModal(true)}>
              <Plus className="w-4 h-4 mr-2" />
              Add Device
            </Button>
            <div className="relative group">
              <Button variant="secondary">
                <Download className="w-4 h-4 mr-2" />
                Export
              </Button>
              <div className="absolute right-0 mt-2 w-48 bg-gray-800 rounded-lg shadow-lg border border-gray-700 opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all z-20">
                <button
                  onClick={handleExportJSON}
                  className="w-full px-4 py-2 text-left text-sm text-gray-300 hover:bg-gray-700 flex items-center gap-2 rounded-t-lg"
                >
                  <FileJson className="w-4 h-4" />
                  Export as JSON
                </button>
                <button
                  onClick={handleExportImage}
                  className="w-full px-4 py-2 text-left text-sm text-gray-300 hover:bg-gray-700 flex items-center gap-2 rounded-b-lg"
                >
                  <Image className="w-4 h-4" />
                  Export as PNG
                </button>
              </div>
            </div>
          </div>
        </div>

        {/* Data Source Selector */}
        <div className="flex flex-wrap items-center gap-4 mb-4">
          <div className="flex items-center gap-2">
            <label className="text-sm text-gray-400">Engagement:</label>
            <select
              value={selectedEngagement}
              onChange={(e) => setSelectedEngagement(e.target.value)}
              className="px-3 py-1.5 bg-gray-800 border border-gray-600 rounded-lg text-white text-sm min-w-[180px]"
              disabled={dataSource === 'sample'}
            >
              <option value="">All Assets</option>
              {engagements.map((eng) => (
                <option key={eng.id} value={eng.id}>
                  {eng.name}
                </option>
              ))}
            </select>
          </div>
          <div className="flex items-center gap-2">
            <label className="text-sm text-gray-400">Data:</label>
            <div className="flex bg-gray-800 rounded-lg border border-gray-600 overflow-hidden">
              <button
                onClick={() => setDataSource('api')}
                className={`px-3 py-1.5 text-sm ${
                  dataSource === 'api'
                    ? 'bg-cyan-500 text-white'
                    : 'text-gray-400 hover:text-white'
                }`}
              >
                Real Data
              </button>
              <button
                onClick={() => setDataSource('sample')}
                className={`px-3 py-1.5 text-sm ${
                  dataSource === 'sample'
                    ? 'bg-cyan-500 text-white'
                    : 'text-gray-400 hover:text-white'
                }`}
              >
                Sample
              </button>
            </div>
          </div>
          {dataSource === 'sample' && (
            <span className="text-xs text-yellow-400 bg-yellow-500/10 px-2 py-1 rounded">
              Using sample demo data
            </span>
          )}
        </div>

        {/* Stats Bar */}
        <div className="flex gap-4 mb-4 text-sm">
          <div className="flex items-center gap-2 px-3 py-1.5 bg-gray-800 rounded-lg">
            <span className="text-gray-400">Devices:</span>
            <span className="text-white font-semibold">{complianceStats.total}</span>
          </div>
          <div className="flex items-center gap-2 px-3 py-1.5 bg-green-500/10 rounded-lg">
            <CheckCircle className="w-4 h-4 text-green-400" />
            <span className="text-green-400">{complianceStats.compliant} Compliant</span>
          </div>
          <div className="flex items-center gap-2 px-3 py-1.5 bg-yellow-500/10 rounded-lg">
            <AlertTriangle className="w-4 h-4 text-yellow-400" />
            <span className="text-yellow-400">{complianceStats.partial} Partial</span>
          </div>
          <div className="flex items-center gap-2 px-3 py-1.5 bg-red-500/10 rounded-lg">
            <XCircle className="w-4 h-4 text-red-400" />
            <span className="text-red-400">{complianceStats.nonCompliant} Non-Compliant</span>
          </div>
          {complianceStats.totalVulns > 0 && (
            <div className="flex items-center gap-2 px-3 py-1.5 bg-red-500/20 rounded-lg">
              <ShieldAlert className="w-4 h-4 text-red-400" />
              <span className="text-red-400">{complianceStats.totalVulns} Vulnerabilities</span>
            </div>
          )}
          <div className="flex-1" />
          <button
            onClick={() => setShowLabels(!showLabels)}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-lg ${
              showLabels ? 'bg-cyan-500/20 text-cyan-400' : 'bg-gray-800 text-gray-400'
            }`}
          >
            {showLabels ? <Eye className="w-4 h-4" /> : <EyeOff className="w-4 h-4" />}
            Labels
          </button>
        </div>

        {/* Legend */}
        <div className="flex gap-4 mb-4 text-xs">
          <span className="text-gray-500">Security Zones:</span>
          {Object.entries(zoneColors).map(([zone, colors]) => (
            <div key={zone} className="flex items-center gap-1">
              <div className={`w-3 h-3 rounded border ${colors.border} ${colors.bg}`} />
              <span className={colors.text}>{zone.toUpperCase()}</span>
            </div>
          ))}
        </div>

        {/* Flow Canvas */}
        <div ref={reactFlowWrapper} className="flex-1 bg-gray-900 rounded-lg border border-gray-700 relative">
          <ReactFlow
            nodes={nodes}
            edges={edges}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            onConnect={onConnect}
            onNodeClick={onNodeClick}
            onPaneClick={onPaneClick}
            nodeTypes={nodeTypes}
            fitView
            snapToGrid
            snapGrid={[20, 20]}
            defaultEdgeOptions={{
              type: 'smoothstep',
              markerEnd: { type: MarkerType.ArrowClosed },
            }}
          >
            <Background variant={BackgroundVariant.Dots} gap={20} size={1} color="#374151" />
            <Controls className="!bg-gray-800 !border-gray-700 !rounded-lg" />
            <MiniMap
              className="!bg-gray-800 !border-gray-700 !rounded-lg"
              nodeColor={(n) => {
                const data = n.data as DeviceData;
                if (data.complianceStatus === 'compliant') return '#22c55e';
                if (data.complianceStatus === 'non_compliant') return '#ef4444';
                if (data.complianceStatus === 'partial') return '#eab308';
                return '#6b7280';
              }}
              maskColor="rgba(0, 0, 0, 0.6)"
            />

            {/* Zone Legend Panel */}
            <Panel position="top-left" className="!m-2">
              <div className="bg-gray-800/90 rounded-lg p-3 border border-gray-700 text-xs">
                <div className="font-semibold text-gray-300 mb-2">Data Flow</div>
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <div className="w-8 h-0.5 bg-red-500" />
                    <span className="text-gray-400">External</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <div className="w-8 h-0.5 bg-yellow-500" />
                    <span className="text-gray-400">DMZ</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <div className="w-8 h-0.5 bg-blue-500" />
                    <span className="text-gray-400">Internal</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <div className="w-8 h-0.5 bg-purple-500" />
                    <span className="text-gray-400">Restricted</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <div className="w-8 h-0.5 bg-green-500" />
                    <span className="text-gray-400">Management</span>
                  </div>
                  <div className="flex items-center gap-2 mt-2 pt-2 border-t border-gray-600">
                    <div className="w-8 h-0.5 border-b border-dashed border-gray-400" />
                    <span className="text-gray-400">Wireless</span>
                  </div>
                </div>
              </div>
            </Panel>
          </ReactFlow>

          {/* Device Details Panel */}
          <DeviceDetailsPanel
            device={selectedNode}
            onClose={() => setSelectedNode(null)}
            onUpdate={() => {}}
            onDelete={handleDeleteNode}
          />
        </div>
      </div>

      {/* Add Device Modal */}
      <AddDeviceModal
        isOpen={showAddModal}
        onClose={() => setShowAddModal(false)}
        onAdd={handleAddDevice}
      />
    </Layout>
  );
};

export default CatoNetworkMap;
