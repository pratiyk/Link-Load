import apiClient, { API_BASE_URL, WS_BASE_URL, API_ENDPOINTS } from "../config/api";

export const scannerApi = {
  // Health check
  healthCheck: async () => {
    const response = await apiClient.get(API_ENDPOINTS.health);
    return response.data;
  },

  // Start a new scan
  startScan: async (scanRequest) => {
    const response = await apiClient.post(API_ENDPOINTS.scans.manager.start, scanRequest);
    return response.data;
  },

  // Get scan result
  getScanResult: async (scanId) => {
    const response = await apiClient.get(API_ENDPOINTS.scans.manager.detail(scanId));
    return response.data;
  },

  // Get scan progress
  getScanProgress: async (scanId) => {
    const response = await apiClient.get(API_ENDPOINTS.scans.manager.detail(scanId));
    return response.data;
  },

  // Get scan vulnerabilities
  getScanVulnerabilities: async (scanId, filters = {}) => {
    const response = await apiClient.get(
      API_ENDPOINTS.scans.manager.findings(scanId),
      { params: filters }
    );
    return response.data;
  },

  // Get all user scans
  getUserScans: async (filters = {}) => {
    const response = await apiClient.get(API_ENDPOINTS.scans.manager.list, { params: filters });
    return response.data;
  },

  // Cancel scan
  cancelScan: async (scanId) => {
    const response = await apiClient.delete(API_ENDPOINTS.scans.manager.cancel(scanId));
    return response.data;
  },

  // Export scan results
  exportScanResults: async (scanId, exportConfig) => {
    throw new Error("Scan export is not available for this scanner configuration.");
  },

  // WebSocket connection for real-time updates
  subscribeToScanUpdates: (scanId, onUpdate, onError) => {
    const token = localStorage.getItem("access_token") || localStorage.getItem("authToken");
    const qs = token ? `?token=${encodeURIComponent(token)}` : "";
    const wsUrl = `${WS_BASE_URL}/ws/scans/${scanId}${qs}`;
    const ws = new WebSocket(wsUrl);

    // Set up ping interval
    const pingInterval = setInterval(() => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send("pong");
      }
    }, 25000); // Slightly less than server's 30s timeout

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        // Handle ping messages
        if (data.type === "ping") {
          ws.send("pong");
          return;
        }
        onUpdate(data);
      } catch (error) {
        console.error("WebSocket message parse error:", error);
      }
    };

    ws.onopen = () => {
      console.log(`WebSocket connected for scan ${scanId}`);
    };

    ws.onerror = (error) => {
      console.error("WebSocket error:", error);
      if (onError) onError(error);
    };

    ws.onclose = (event) => {
      console.log(`WebSocket closed for scan ${scanId}:`, event.code, event.reason);
      clearInterval(pingInterval);
      if (onError) onError(new Error("WebSocket connection closed"));
    };

    // Return cleanup function
    return {
      socket: ws,
      disconnect: () => {
        clearInterval(pingInterval);
        if (ws.readyState === WebSocket.OPEN) {
          ws.close();
        }
      }
    };
  },
};

export default scannerApi;
