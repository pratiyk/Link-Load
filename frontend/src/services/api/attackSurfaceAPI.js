import axios from 'axios';

const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';

const apiClient = axios.create({
    baseURL: `${API_BASE_URL}/api/v1/attack-surface`,
    timeout: 30000,
    headers: {
        'Content-Type': 'application/json',
    },
});

// Add request interceptor for auth
apiClient.interceptors.request.use(
    (config) => {
        const token = localStorage.getItem('authToken');
        if (token) {
            config.headers.Authorization = `Bearer ${token}`;
        }
        return config;
    },
    (error) => {
        return Promise.reject(error);
    }
);

// Add response interceptor for error handling
apiClient.interceptors.response.use(
    (response) => response.data,
    (error) => {
        console.error('API Error:', error);
        throw error;
    }
);

export const attackSurfaceAPI = {
    // Start a new scan
    startScan: async (config) => {
        return await apiClient.post('/scan', config);
    },

    // Get scan status
    getScanStatus: async (scanId) => {
        return await apiClient.get(`/scan/${scanId}`);
    },

    // Get scan assets
    getScanAssets: async (scanId, params = {}) => {
        return await apiClient.get(`/scan/${scanId}/assets`, { params });
    },

    // Get scan summary
    getScanSummary: async (scanId) => {
        return await apiClient.get(`/scan/${scanId}/summary`);
    },

    // Cancel scan
    cancelScan: async (scanId) => {
        return await apiClient.delete(`/scan/${scanId}`);
    },

    // Get all scans (you might want to add this endpoint)
    getAllScans: async (params = {}) => {
        return await apiClient.get('/scans', { params });
    },

    // Export scan results
    exportScan: async (scanId, format = 'json') => {
        return await apiClient.get(`/scan/${scanId}/export`, {
            params: { format },
            responseType: format === 'pdf' ? 'blob' : 'json'
        });
    },
};

export default attackSurfaceAPI;
