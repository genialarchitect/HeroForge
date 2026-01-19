import { describe, it, expect, beforeEach } from 'vitest';
import { useScanStore } from './scanStore';

describe('ScanStore', () => {
  beforeEach(() => {
    // Reset store state
    useScanStore.setState({
      scans: [],
      activeScan: null,
      results: new Map(),
      liveUpdates: new Map(),
    });
  });

  describe('Initial State', () => {
    it('should have correct initial state', () => {
      const state = useScanStore.getState();
      expect(state.scans).toEqual([]);
      expect(state.activeScan).toBeNull();
      expect(state.results.size).toBe(0);
      expect(state.liveUpdates.size).toBe(0);
    });
  });

  describe('setScans', () => {
    it('should set the scans list', () => {
      const scans = [
        { id: 'scan-1', name: 'Test Scan 1', status: 'completed' as const },
        { id: 'scan-2', name: 'Test Scan 2', status: 'pending' as const },
      ];

      const store = useScanStore.getState();
      store.setScans(scans as any);

      expect(useScanStore.getState().scans).toEqual(scans);
    });
  });

  describe('setActiveScan', () => {
    it('should set the active scan', () => {
      const scan = { id: 'scan-1', name: 'Test Scan', status: 'running' as const };

      const store = useScanStore.getState();
      store.setActiveScan(scan as any);

      expect(useScanStore.getState().activeScan).toEqual(scan);
    });

    it('should allow setting active scan to null', () => {
      const store = useScanStore.getState();
      store.setActiveScan({ id: 'scan-1', name: 'Test', status: 'running' } as any);
      store.setActiveScan(null);

      expect(useScanStore.getState().activeScan).toBeNull();
    });
  });

  describe('addScan', () => {
    it('should add a new scan to the beginning of the list', () => {
      const scan1 = { id: 'scan-1', name: 'Test Scan 1', status: 'pending' as const };
      const scan2 = { id: 'scan-2', name: 'Test Scan 2', status: 'pending' as const };

      const store = useScanStore.getState();
      store.addScan(scan1 as any);
      store.addScan(scan2 as any);

      const scans = useScanStore.getState().scans;
      expect(scans).toHaveLength(2);
      expect(scans[0].id).toBe('scan-2'); // Most recent first
      expect(scans[1].id).toBe('scan-1');
    });
  });

  describe('updateScanStatus', () => {
    it('should update an existing scan status', () => {
      const scan = { id: 'scan-1', name: 'Test Scan', status: 'pending' as const };

      const store = useScanStore.getState();
      store.addScan(scan as any);
      store.updateScanStatus('scan-1', 'completed');

      const updated = useScanStore.getState().scans.find(s => s.id === 'scan-1');
      expect(updated?.status).toBe('completed');
    });

    it('should also update activeScan if it matches', () => {
      const scan = { id: 'scan-1', name: 'Test Scan', status: 'pending' as const };

      const store = useScanStore.getState();
      store.addScan(scan as any);
      store.setActiveScan(scan as any);
      store.updateScanStatus('scan-1', 'running');

      expect(useScanStore.getState().activeScan?.status).toBe('running');
    });
  });

  describe('Results Management', () => {
    it('should set results for a scan', () => {
      const results = [
        { target: { ip: '192.168.1.1' }, ports: [] },
        { target: { ip: '192.168.1.2' }, ports: [] },
      ];

      const store = useScanStore.getState();
      store.setResults('scan-1', results as any);

      const storedResults = useScanStore.getState().results.get('scan-1');
      expect(storedResults).toHaveLength(2);
    });

    it('should add a host to results', () => {
      const host = { target: { ip: '192.168.1.1' }, ports: [] };

      const store = useScanStore.getState();
      store.addHostToResults('scan-1', host as any);

      const results = useScanStore.getState().results.get('scan-1');
      expect(results).toHaveLength(1);
      expect(results?.[0].target.ip).toBe('192.168.1.1');
    });

    it('should update existing host if IP matches', () => {
      const host1 = { target: { ip: '192.168.1.1' }, ports: [] };
      const host2 = { target: { ip: '192.168.1.1' }, ports: [{ port: 22 }] };

      const store = useScanStore.getState();
      store.addHostToResults('scan-1', host1 as any);
      store.addHostToResults('scan-1', host2 as any);

      const results = useScanStore.getState().results.get('scan-1');
      expect(results).toHaveLength(1);
      expect(results?.[0].ports).toHaveLength(1);
    });

    it('should update host in results by IP', () => {
      const host = { target: { ip: '192.168.1.1' }, ports: [] };

      const store = useScanStore.getState();
      store.addHostToResults('scan-1', host as any);
      store.updateHostInResults('scan-1', '192.168.1.1', { ports: [{ port: 80 }] } as any);

      const results = useScanStore.getState().results.get('scan-1');
      expect(results?.[0].ports).toHaveLength(1);
    });
  });

  describe('Live Updates', () => {
    it('should add live updates for a scan', () => {
      const store = useScanStore.getState();
      const update = {
        type: 'host_discovered',
        data: { ip: '192.168.1.1' },
        timestamp: new Date().toISOString(),
      };

      store.addLiveUpdate('scan-1', update);

      const updates = useScanStore.getState().liveUpdates.get('scan-1');
      expect(updates).toHaveLength(1);
      expect(updates?.[0]).toEqual(update);
    });

    it('should accumulate multiple live updates', () => {
      const store = useScanStore.getState();

      store.addLiveUpdate('scan-1', {
        type: 'host_discovered',
        data: { ip: '192.168.1.1' },
        timestamp: new Date().toISOString(),
      });
      store.addLiveUpdate('scan-1', {
        type: 'port_discovered',
        data: { port: 22 },
        timestamp: new Date().toISOString(),
      });

      const updates = useScanStore.getState().liveUpdates.get('scan-1');
      expect(updates).toHaveLength(2);
    });

    it('should clear live updates for a scan', () => {
      const store = useScanStore.getState();
      store.addLiveUpdate('scan-1', {
        type: 'test',
        data: {},
        timestamp: new Date().toISOString(),
      });
      store.clearLiveUpdates('scan-1');

      expect(useScanStore.getState().liveUpdates.get('scan-1')).toBeUndefined();
    });
  });
});
