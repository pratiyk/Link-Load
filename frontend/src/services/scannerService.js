import apiClient, { API_ENDPOINTS, WS_BASE_URL, getAuthToken } from "../config/api";

class ScannerService {
  constructor() {
    this.websockets = new Map();
    this.activeConnections = new Set();
  }

  async startScan(targetUrl, scanTypes, options = {}) {
    try {
      console.log('[ScannerService] Starting scan for URL:', targetUrl);
      console.log('[ScannerService] API Endpoint:', API_ENDPOINTS.scans.comprehensive.start);

      const payload = {
        target_url: targetUrl,
        scan_types: scanTypes,
        options: {
          enable_ai_analysis: options.enable_ai_analysis !== false,
          enable_mitre_mapping: options.enable_mitre_mapping !== false,
          include_low_risk: options.include_low_risk || false,
          deep_scan: options.deep_scan || false,
          timeout_minutes: options.timeout_minutes || 30,
          business_context: options.business_context || null,
          compliance_frameworks: options.compliance_frameworks || null
        }
      };
      console.log('[ScannerService] Payload:', payload);

      const response = await apiClient.post(API_ENDPOINTS.scans.comprehensive.start, payload);
      console.log('[ScannerService] Response received:', response.data);

      if (!response.data.scan_id) {
        console.error('[ScannerService] Response does not contain scan_id:', response.data);
        throw new Error('Invalid response: missing scan_id');
      }

      return response.data;
    } catch (error) {
      console.error('[ScannerService] Error:', error);
      console.error('[ScannerService] Error details:', {
        message: error.message,
        response: error?.response?.data,
        status: error?.response?.status
      });
      throw new Error(error?.response?.data?.detail || error.message || "Failed to start scan");
    }
  }

  async getScanResults(scanId) {
    try {
      const response = await apiClient.get(API_ENDPOINTS.scans.comprehensive.result(scanId));
      return response.data;
    } catch (error) {
      throw new Error(error?.response?.data?.detail || "Failed to get scan results");
    }
  }

  async getScanSummary(scanId) {
    try {
      const response = await apiClient.get(API_ENDPOINTS.scans.comprehensive.summary(scanId));
      return response.data;
    } catch (error) {
      throw new Error(error?.response?.data?.detail || "Failed to generate scan summary");
    }
  }

  async getScanStatus(scanId) {
    try {
      const response = await apiClient.get(API_ENDPOINTS.scans.comprehensive.status(scanId));
      return response.data;
    } catch (error) {
      throw new Error(error?.response?.data?.detail || "Failed to get scan status");
    }
  }

  async listScans(skip = 0, limit = 10, status = null) {
    try {
      const params = { skip, limit };
      if (status) {
        params.status = status;
      }
      const response = await apiClient.get(API_ENDPOINTS.scans.comprehensive.list, { params });
      return response.data;
    } catch (error) {
      throw new Error(error?.response?.data?.detail || "Failed to list scans");
    }
  }

  async cancelScan(scanId) {
    try {
      const response = await apiClient.post(API_ENDPOINTS.scans.comprehensive.cancel(scanId));
      return response.data;
    } catch (error) {
      throw new Error(error?.response?.data?.detail || "Failed to cancel scan");
    }
  }

  setupWebSocket(scanId, callbacks = {}) {
    try {
      // Construct WebSocket URL (backend websocket routes live at /ws)
      const token = getAuthToken();
      const wsPath = API_ENDPOINTS.scans.comprehensive.ws
        ? API_ENDPOINTS.scans.comprehensive.ws(scanId)
        : `/ws/scans/${scanId}`;
      let wsUrl = `${WS_BASE_URL}${wsPath.startsWith('/') ? '' : '/'}${wsPath}`;
      if (token) {
        wsUrl += `?token=${encodeURIComponent(token)}`;
      } else {
        console.warn("[WebSocket] No auth token found; connection may be rejected");
      }
      console.log('[WebSocket] Connecting to:', wsUrl);

      const ws = new WebSocket(wsUrl);

      ws.onopen = () => {
        console.log('[WebSocket] Connected for scan:', scanId);
        this.activeConnections.add(scanId);
        if (callbacks.onOpen) {
          callbacks.onOpen();
        }
      };

      ws.onmessage = (event) => {
        try {
          console.log('[WebSocket] Message received:', event.data);
          const data = JSON.parse(event.data);

          if (data.type === "progress" && callbacks.onProgress) {
            console.log('[WebSocket] Progress update:', data.status);
            callbacks.onProgress(data.status);
          } else if (data.type === "result" && callbacks.onComplete) {
            console.log('[WebSocket] Scan completed:', data.results);
            callbacks.onComplete(data.results);
            this.closeWebSocket(scanId);
          }
        } catch (error) {
          console.error("[WebSocket] Error parsing message:", error, event.data);
        }
      };

      ws.onerror = (error) => {
        console.error(`[WebSocket] Error for scan ${scanId}:`, error);
        if (callbacks.onError) {
          callbacks.onError(error);
        }
      };

      ws.onclose = () => {
        console.log(`[WebSocket] Disconnected for scan ${scanId}`);
        this.activeConnections.delete(scanId);
        if (callbacks.onClose) {
          callbacks.onClose();
        }
      };

      this.websockets.set(scanId, ws);
      return ws;
    } catch (error) {
      console.error("[WebSocket] Failed to setup WebSocket:", error);
      if (callbacks.onError) {
        callbacks.onError(error);
      }
      throw error;
    }
  }

  closeWebSocket(scanId) {
    const ws = this.websockets.get(scanId);
    if (ws) {
      try {
        ws.close(1000, "Normal closure");
      } catch (error) {
        console.error("Error closing WebSocket:", error);
      }
      this.websockets.delete(scanId);
      this.activeConnections.delete(scanId);
    }
  }

  closeAllWebSockets() {
    for (const [scanId, ws] of this.websockets.entries()) {
      try {
        ws.close(1000, "Closing all connections");
      } catch (error) {
        console.error(`Error closing WebSocket for ${scanId}:`, error);
      }
    }
    this.websockets.clear();
    this.activeConnections.clear();
  }

  isWebSocketActive(scanId) {
    return this.activeConnections.has(scanId);
  }

  getActiveScanCount() {
    return this.activeConnections.size;
  }
}

const scannerService = new ScannerService();
export default scannerService;