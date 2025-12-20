import { create } from 'zustand';
import { ScanResult, Vulnerability, HostInfo } from '../types';

// Data types for live updates during scanning
interface HostDiscoveredData {
  ip: string;
  hostname?: string;
}

interface PortDiscoveredData {
  ip: string;
  port: number;
  protocol: string;
  state: string;
  service?: string;
}

interface ServiceDetectedData {
  ip: string;
  port: number;
  service: string;
  version?: string;
}

interface VulnerabilityFoundData {
  ip: string;
  vulnerability: Vulnerability;
}

interface ProgressUpdateData {
  phase: string;
  progress: number;
  current_host?: string;
}

interface ScanCompleteData {
  total_hosts: number;
  total_ports: number;
  total_vulnerabilities: number;
}

interface ErrorData {
  message: string;
  host?: string;
}

// Live update data - flexible type to handle various WebSocket message formats
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type LiveUpdateData = Record<string, any>;

interface LiveUpdate {
  type: string;
  data: LiveUpdateData;
  timestamp: string;
}

interface ScanState {
  scans: ScanResult[];
  activeScan: ScanResult | null;
  results: Map<string, HostInfo[]>;
  liveUpdates: Map<string, LiveUpdate[]>;

  // Actions
  setScans: (scans: ScanResult[]) => void;
  addScan: (scan: ScanResult) => void;
  setActiveScan: (scan: ScanResult | null) => void;
  updateScanStatus: (id: string, status: string) => void;
  setResults: (scanId: string, results: HostInfo[]) => void;
  addHostToResults: (scanId: string, host: HostInfo) => void;
  updateHostInResults: (scanId: string, hostIp: string, updatedHost: Partial<HostInfo>) => void;
  addLiveUpdate: (scanId: string, update: LiveUpdate) => void;
  clearLiveUpdates: (scanId: string) => void;
}

export const useScanStore = create<ScanState>((set) => ({
  scans: [],
  activeScan: null,
  results: new Map(),
  liveUpdates: new Map(),

  setScans: (scans) => set({ scans }),

  addScan: (scan) => set((state) => ({
    scans: [scan, ...state.scans],
  })),

  setActiveScan: (scan) => set({ activeScan: scan }),

  updateScanStatus: (id, status) => set((state) => {
    const validStatus = status as 'pending' | 'running' | 'completed' | 'failed';
    return {
      scans: state.scans.map((scan) =>
        scan.id === id ? { ...scan, status: validStatus } : scan
      ),
      activeScan: state.activeScan?.id === id
        ? { ...state.activeScan, status: validStatus }
        : state.activeScan,
    };
  }),

  setResults: (scanId, results) => set((state) => {
    const newResults = new Map(state.results);
    newResults.set(scanId, results);
    return { results: newResults };
  }),

  addHostToResults: (scanId, host) => set((state) => {
    const newResults = new Map(state.results);
    const currentResults = newResults.get(scanId) || [];

    // Check if host already exists
    const existingIndex = currentResults.findIndex(
      (h) => h.target.ip === host.target.ip
    );

    if (existingIndex >= 0) {
      currentResults[existingIndex] = host;
    } else {
      currentResults.push(host);
    }

    newResults.set(scanId, currentResults);
    return { results: newResults };
  }),

  updateHostInResults: (scanId, hostIp, updatedHost) => set((state) => {
    const newResults = new Map(state.results);
    const currentResults = newResults.get(scanId) || [];

    const updatedResults = currentResults.map((host) =>
      host.target.ip === hostIp ? { ...host, ...updatedHost } : host
    );

    newResults.set(scanId, updatedResults);
    return { results: newResults };
  }),

  addLiveUpdate: (scanId, update) => set((state) => {
    const newUpdates = new Map(state.liveUpdates);
    const currentUpdates = newUpdates.get(scanId) || [];
    currentUpdates.push(update);
    newUpdates.set(scanId, currentUpdates);
    return { liveUpdates: newUpdates };
  }),

  clearLiveUpdates: (scanId) => set((state) => {
    const newUpdates = new Map(state.liveUpdates);
    newUpdates.delete(scanId);
    return { liveUpdates: newUpdates };
  }),
}));
