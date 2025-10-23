import apiClient, { API_ENDPOINTS, WS_BASE_URL } from "../config/api";

class ScannerService {
  constructor() {
    this.websockets = new Map();
    this.activeConnections = new Set();
  }

  async startScan(targetUrl, scanTypes, options = {}) {
    try {
      const response = await apiClient.post(API_ENDPOINTS.scans.comprehensive.start, {
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
      });
      return response.data;
    } catch (error) {
      throw new Error(error?.response?.data?.detail || "Failed to start scan");
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
      // Construct WebSocket URL
      const wsUrl = `${WS_BASE_URL}/api/v1/scans/ws/${scanId}`;
      const ws = new WebSocket(wsUrl);
      
      ws.onopen = () => {
        console.log(`WebSocket connected for scan ${scanId}`);
        this.activeConnections.add(scanId);
        if (callbacks.onOpen) {
          callbacks.onOpen();
        }
      };

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          
          if (data.type === "progress" && callbacks.onProgress) {
            callbacks.onProgress(data.status);
          } else if (data.type === "result" && callbacks.onComplete) {
            callbacks.onComplete(data.results);
            this.closeWebSocket(scanId);
          }
        } catch (error) {
          console.error("Error parsing WebSocket message:", error);
        }
      };

      ws.onerror = (error) => {
        console.error(`WebSocket error for scan ${scanId}:`, error);
        if (callbacks.onError) {
          callbacks.onError(error);
        }
      };

      ws.onclose = () => {
        console.log(`WebSocket disconnected for scan ${scanId}`);
        this.activeConnections.delete(scanId);
        if (callbacks.onClose) {
          callbacks.onClose();
        }
      };

      this.websockets.set(scanId, ws);
      return ws;
    } catch (error) {
      console.error("Failed to setup WebSocket:", error);
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