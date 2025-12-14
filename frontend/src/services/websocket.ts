export interface ScanProgressMessage {
  type: string;
  [key: string]: any;
}

export class WebSocketManager {
  private ws: WebSocket | null = null;
  private scanId: string;
  private reconnectAttempts: number = 0;
  private maxReconnectAttempts: number = 10;
  private reconnectDelay: number = 1000;
  private messageHandlers: ((message: ScanProgressMessage) => void)[] = [];
  private statusHandlers: ((status: 'connecting' | 'connected' | 'disconnected' | 'failed') => void)[] = [];

  constructor(scanId: string) {
    this.scanId = scanId;
  }

  connect() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = window.location.hostname;
    const port = window.location.port || (protocol === 'wss:' ? '443' : '80');
    const wsUrl = `${protocol}//${host}:${port}/api/ws/scans/${this.scanId}`;

    this.updateStatus('connecting');

    try {
      this.ws = new WebSocket(wsUrl);

      this.ws.onopen = () => {
        console.log(`WebSocket connected for scan: ${this.scanId}`);
        this.reconnectAttempts = 0;
        this.reconnectDelay = 1000;
        this.updateStatus('connected');
      };

      this.ws.onmessage = (event) => {
        try {
          const message: ScanProgressMessage = JSON.parse(event.data);
          this.messageHandlers.forEach(handler => handler(message));
        } catch (error) {
          console.error('Failed to parse WebSocket message:', error);
        }
      };

      this.ws.onerror = (error) => {
        console.error('WebSocket error:', error);
      };

      this.ws.onclose = () => {
        console.log('WebSocket disconnected');
        this.updateStatus('disconnected');
        this.attemptReconnect();
      };
    } catch (error) {
      console.error('Failed to create WebSocket:', error);
      this.updateStatus('failed');
    }
  }

  private attemptReconnect() {
    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      console.log('Max reconnection attempts reached');
      this.updateStatus('failed');
      return;
    }

    this.reconnectAttempts++;
    const delay = Math.min(this.reconnectDelay * Math.pow(2, this.reconnectAttempts - 1), 8000);

    console.log(`Reconnecting in ${delay}ms... (Attempt ${this.reconnectAttempts}/${this.maxReconnectAttempts})`);

    setTimeout(() => {
      this.connect();
    }, delay);
  }

  onMessage(handler: (message: ScanProgressMessage) => void) {
    this.messageHandlers.push(handler);
  }

  onStatusChange(handler: (status: 'connecting' | 'connected' | 'disconnected' | 'failed') => void) {
    this.statusHandlers.push(handler);
  }

  private updateStatus(status: 'connecting' | 'connected' | 'disconnected' | 'failed') {
    this.statusHandlers.forEach(handler => handler(status));
  }

  disconnect() {
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
    this.messageHandlers = [];
    this.statusHandlers = [];
  }

  reconnect() {
    this.disconnect();
    this.reconnectAttempts = 0;
    this.connect();
  }
}
