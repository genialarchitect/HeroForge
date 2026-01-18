import { useEffect, useState, useRef, useCallback } from 'react';
import { useQueryClient } from '@tanstack/react-query';

/**
 * Report progress message from WebSocket
 */
export interface ReportProgressMessage {
  type:
    | 'reportStarted'
    | 'reportPhase'
    | 'screenshotCaptured'
    | 'reportCompleted'
    | 'reportFailed'
    | 'error';
  reportId?: string;
  name?: string;
  format?: string;
  phase?: string;
  progress?: number;
  message?: string;
  url?: string;
  index?: number;
  total?: number;
  filePath?: string;
  fileSize?: number;
  error?: string;
}

interface ReportProgress {
  phase: string;
  progress: number;
  message: string;
  screenshotIndex?: number;
  screenshotTotal?: number;
}

type WebSocketStatus = 'connecting' | 'connected' | 'disconnected' | 'completed' | 'failed';

interface UseReportWebSocketReturn {
  status: WebSocketStatus;
  progress: ReportProgress | null;
  error: string | null;
  reconnect: () => void;
}

/**
 * Hook for connecting to a report progress WebSocket
 *
 * @param reportId - The report ID to track, or null to skip connection
 * @returns WebSocket status, progress information, and error state
 */
export function useReportWebSocket(
  reportId: string | null
): UseReportWebSocketReturn {
  const [status, setStatus] = useState<WebSocketStatus>('disconnected');
  const [progress, setProgress] = useState<ReportProgress | null>(null);
  const [error, setError] = useState<string | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectAttemptsRef = useRef(0);
  const maxReconnectAttempts = 5;
  const queryClient = useQueryClient();

  const connect = useCallback(() => {
    if (!reportId) {
      return;
    }

    const token = localStorage.getItem('token');
    if (!token) {
      console.error('Report WebSocket: No authentication token available');
      setStatus('failed');
      setError('No authentication token');
      return;
    }

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = window.location.hostname;
    const port = window.location.port || (protocol === 'wss:' ? '443' : '80');
    const wsUrl = `${protocol}//${host}:${port}/api/ws/reports/${reportId}?token=${encodeURIComponent(token)}`;

    setStatus('connecting');
    setError(null);

    try {
      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;

      ws.onopen = () => {
        console.log(`Report WebSocket connected for report: ${reportId}`);
        reconnectAttemptsRef.current = 0;
        setStatus('connected');
      };

      ws.onmessage = (event) => {
        try {
          const message: ReportProgressMessage = JSON.parse(event.data);
          handleMessage(message);
        } catch (err) {
          console.error('Failed to parse Report WebSocket message:', err);
        }
      };

      ws.onerror = (err) => {
        console.error('Report WebSocket error:', err);
      };

      ws.onclose = (event) => {
        console.log('Report WebSocket disconnected:', event.code, event.reason);
        wsRef.current = null;

        // Check if it was a normal closure (report completed)
        if (event.code === 1000) {
          // Normal closure - report likely completed
          setStatus('completed');
        } else if (status !== 'completed' && status !== 'failed') {
          setStatus('disconnected');
          attemptReconnect();
        }
      };
    } catch (err) {
      console.error('Failed to create Report WebSocket:', err);
      setStatus('failed');
      setError('Failed to connect to WebSocket');
    }
  }, [reportId, status]);

  const handleMessage = (message: ReportProgressMessage) => {
    console.log('Report WebSocket message:', message);

    switch (message.type) {
      case 'reportStarted':
        setProgress({
          phase: 'started',
          progress: 0,
          message: `Starting report generation: ${message.name || 'Unknown'}`,
        });
        break;

      case 'reportPhase':
        setProgress({
          phase: message.phase || 'unknown',
          progress: message.progress || 0,
          message: message.message || 'Processing...',
        });
        break;

      case 'screenshotCaptured':
        setProgress((prev) => ({
          ...prev,
          phase: 'screenshots',
          progress: prev?.progress || 0.4,
          message: `Capturing screenshot ${(message.index || 0) + 1} of ${message.total || 0}`,
          screenshotIndex: message.index,
          screenshotTotal: message.total,
        }));
        break;

      case 'reportCompleted':
        setProgress({
          phase: 'completed',
          progress: 1,
          message: 'Report generated successfully!',
        });
        setStatus('completed');
        // Invalidate reports query to refresh the list
        queryClient.invalidateQueries({ queryKey: ['reports'] });
        break;

      case 'reportFailed':
        setProgress({
          phase: 'failed',
          progress: 0,
          message: message.error || 'Report generation failed',
        });
        setStatus('failed');
        setError(message.error || 'Report generation failed');
        // Invalidate reports query to refresh the list (show failed status)
        queryClient.invalidateQueries({ queryKey: ['reports'] });
        break;

      case 'error':
        setError(message.message || message.error || 'Unknown error');
        break;

      default:
        console.log('Unknown report message type:', message.type);
    }
  };

  const attemptReconnect = () => {
    if (reconnectAttemptsRef.current >= maxReconnectAttempts) {
      console.log('Max reconnection attempts reached for report WebSocket');
      setStatus('failed');
      return;
    }

    reconnectAttemptsRef.current++;
    const delay = Math.min(
      1000 * Math.pow(2, reconnectAttemptsRef.current - 1),
      8000
    );

    console.log(
      `Report WebSocket reconnecting in ${delay}ms... (Attempt ${reconnectAttemptsRef.current}/${maxReconnectAttempts})`
    );

    setTimeout(() => {
      connect();
    }, delay);
  };

  const reconnect = useCallback(() => {
    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }
    reconnectAttemptsRef.current = 0;
    connect();
  }, [connect]);

  const disconnect = useCallback(() => {
    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }
  }, []);

  useEffect(() => {
    if (reportId) {
      connect();
    }

    return () => {
      disconnect();
    };
  }, [reportId, connect, disconnect]);

  return {
    status,
    progress,
    error,
    reconnect,
  };
}
