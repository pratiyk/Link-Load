import axios from 'axios';

const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';

// Create axios instance with interceptors
const api = axios.create({
  baseURL: `${API_BASE_URL}/api`,
  timeout: 300000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor to add auth token
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('access_token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Response interceptor to handle token refresh
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;
    
    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;
      
      try {
        const refreshToken = localStorage.getItem('refresh_token');
        if (refreshToken) {
          const response = await axios.post(
            `${API_BASE_URL}/api/auth/refresh`,
            { refresh_token: refreshToken }
          );
          
          const newToken = response.data.access_token;
          localStorage.setItem('access_token', newToken);
          
          // Retry original request with new token
          originalRequest.headers.Authorization = `Bearer ${newToken}`;
          return api(originalRequest);
        }
      } catch (refreshError) {
        // Refresh failed, redirect to login
        localStorage.removeItem('access_token');
        localStorage.removeItem('refresh_token');
        window.location.href = '/login';
        return Promise.reject(refreshError);
      }
    }
    
    return Promise.reject(error);
  }
);

export const scannerApi = {
  // Health check
  healthCheck: async () => {
    const response = await api.get('/health');
    return response.data;
  },

  // Start a new scan
  startScan: async (scanRequest) => {
    const response = await api.post('/owasp/scan/start', scanRequest);
    return response.data;
  },

  // Get scan result
  getScanResult: async (scanId) => {
    const response = await api.get(`/owasp/scan/${scanId}`);
    return response.data;
  },

  // Get scan progress
  getScanProgress: async (scanId) => {
    const response = await api.get(`/owasp/scan/${scanId}/status`);
    return response.data;
  },

  // Get scan vulnerabilities
  getScanVulnerabilities: async (scanId, filters = {}) => {
    const params = new URLSearchParams(filters);
    const response = await api.get(`/owasp/scan/${scanId}/vulnerabilities?${params}`);
    return response.data;
  },

  // Get all user scans
  getUserScans: async (filters = {}) => {
    const params = new URLSearchParams(filters);
    const response = await api.get(`/owasp/scans?${params}`);
    return response.data;
  },

  // Cancel scan
  cancelScan: async (scanId) => {
    const response = await api.post(`/owasp/scan/${scanId}/cancel`);
    return response.data;
  },

  // Export scan results
  exportScanResults: async (scanId, exportConfig) => {
    const response = await api.post(
      `/owasp/scan/${scanId}/export`,
      exportConfig,
      { responseType: 'blob' }
    );
    return response;
  },

  // WebSocket connection for real-time updates
  subscribeToScanUpdates: (scanId, onUpdate, onError) => {
    const wsUrl = `${API_BASE_URL.replace('http', 'ws')}/ws/scans/${scanId}`;
    const ws = new WebSocket(wsUrl);
    
    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        onUpdate(data);
      } catch (error) {
        console.error('WebSocket message parse error:', error);
      }
    };
    
    ws.onerror = (error) => {
      console.error('WebSocket error:', error);
      if (onError) onError(error);
    };
    
    return ws;
  }
};

export default scannerApi;