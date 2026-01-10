import { useEffect, useState, useRef } from 'react';
import { toast } from 'react-toastify';
import { WebSocketManager, ScanProgressMessage } from '../services/websocket';
import { useScanStore } from '../store/scanStore';
import { HostInfo, PortInfo, Vulnerability } from '../types';

export const useWebSocket = (scanId: string | null) => {
  const [status, setStatus] = useState<'connecting' | 'connected' | 'disconnected' | 'failed'>('disconnected');
  const [error, setError] = useState<string | null>(null);
  const wsManagerRef = useRef<WebSocketManager | null>(null);

  const { updateScanStatus, addHostToResults, updateHostInResults, results } = useScanStore();

  useEffect(() => {
    if (!scanId) {
      return;
    }

    // Create WebSocket manager
    const wsManager = new WebSocketManager(scanId);
    wsManagerRef.current = wsManager;

    // Setup status handler
    wsManager.onStatusChange((newStatus) => {
      setStatus(newStatus);
      if (newStatus === 'failed') {
        setError('Failed to connect to WebSocket');
      } else {
        setError(null);
      }
    });

    // Setup message handler
    wsManager.onMessage((message: ScanProgressMessage) => {
      handleWebSocketMessage(scanId, message);
    });

    // Connect
    wsManager.connect();

    // Cleanup on unmount
    return () => {
      wsManager.disconnect();
      wsManagerRef.current = null;
    };
  }, [scanId]);

  const handleWebSocketMessage = (scanId: string, message: ScanProgressMessage) => {
    console.log('WebSocket message:', message);

    switch (message.type) {
      case 'scanStarted':
        updateScanStatus(scanId, 'running');
        toast.info('Scan started');
        break;

      case 'phaseStarted':
        // Update progress in UI (could add progress state to scanStore)
        break;

      case 'hostDiscovered':
        const newHost: HostInfo = {
          target: {
            ip: message.ip,
            hostname: message.hostname || null,
          },
          is_alive: true,
          os_guess: null,
          ports: [],
          vulnerabilities: [],
          scan_duration: { secs: 0, nanos: 0 },
        };
        addHostToResults(scanId, newHost);
        break;

      case 'portFound':
        const currentHosts = results.get(scanId) || [];
        const hostForPort = currentHosts.find(h => h.target.ip === message.ip);

        if (hostForPort) {
          const newPort: PortInfo = {
            port: message.port,
            protocol: message.protocol === 'TCP' ? 'TCP' : 'UDP',
            state: message.state,
            service: null,
          };

          const updatedPorts = [...hostForPort.ports, newPort];
          updateHostInResults(scanId, message.ip, { ports: updatedPorts });
        }
        break;

      case 'serviceDetected':
        const hostsForService = results.get(scanId) || [];
        const hostForService = hostsForService.find(h => h.target.ip === message.ip);

        if (hostForService) {
          const updatedPorts = hostForService.ports.map(port =>
            port.port === message.port
              ? {
                  ...port,
                  service: {
                    name: message.service_name,
                    version: message.version || null,
                    banner: null,
                    cpe: null,
                    ssl_info: null,
                  }
                }
              : port
          );
          updateHostInResults(scanId, message.ip, { ports: updatedPorts });
        }
        break;

      case 'vulnerabilityFound':
        const hostsForVuln = results.get(scanId) || [];
        const hostForVuln = hostsForVuln.find(h => h.target.ip === message.ip);

        if (hostForVuln) {
          const newVuln: Vulnerability = {
            cve_id: message.cve_id || null,
            title: message.title,
            severity: message.severity,
            description: '',
            affected_service: null,
          };

          const updatedVulns = [...hostForVuln.vulnerabilities, newVuln];
          updateHostInResults(scanId, message.ip, { vulnerabilities: updatedVulns });

          // Show toast notification for critical/high vulnerabilities
          if (message.severity === 'Critical') {
            toast.error(
              `🚨 CRITICAL vulnerability found on ${message.ip}: ${message.title}`,
              { autoClose: 8000 }
            );
          } else if (message.severity === 'High') {
            toast.warning(
              `⚠️ HIGH severity vulnerability found on ${message.ip}: ${message.title}`,
              { autoClose: 6000 }
            );
          }
        }
        break;

      case 'scanCompleted':
        updateScanStatus(scanId, 'completed');
        toast.success(`Scan completed! Found ${message.total_hosts} hosts`);
        break;

      case 'error':
        // Only mark as failed if it's an actual scan error, not a connection issue
        // Check if the error message indicates a real scan failure vs channel cleanup
        if (message.message && !message.message.includes('channel') && !message.message.includes('not found')) {
          updateScanStatus(scanId, 'failed');
          toast.error(`Scan error: ${message.message}`);
        } else {
          // Channel was closed (scan likely completed) - don't mark as failed
          console.log('WebSocket channel closed, fetching actual scan status from API');
        }
        break;

      default:
        console.log('Unknown message type:', message.type);
    }
  };

  const reconnect = () => {
    if (wsManagerRef.current) {
      wsManagerRef.current.reconnect();
    }
  };

  return {
    status,
    error,
    reconnect,
  };
};
