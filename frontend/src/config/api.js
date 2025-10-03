/**
 * Centralized API configuration for LinkLoad frontend
 * 
 * This module provides:
 * - Base API URLs from environment variables
 * - Axios instance with interceptors
 * - Error handling
 * - Authentication token management
 */
import axios from 'axios';
import { toast } from 'react-toastify';

// API Configuration
export const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';
export const WS_BASE_URL = process.env.REACT_APP_WS_URL || 'ws://localhost:8000';
export const API_TIMEOUT = parseInt(process.env.REACT_APP_API_TIMEOUT) || 30000;

// Create axios instance with default config
const apiClient = axios.create({
    baseURL: API_BASE_URL,
    timeout: API_TIMEOUT,
    headers: {
        'Content-Type': 'application/json',
    },
});

// Request interceptor - Add auth token
apiClient.interceptors.request.use(
    (config) => {
        const token = localStorage.getItem('authToken');
        if (token) {
            config.headers.Authorization = `Bearer ${token}`;
        }
        
        // Add CSRF token if available
        const csrfToken = localStorage.getItem('csrfToken');
        const sessionId = localStorage.getItem('sessionId');
        if (csrfToken && sessionId) {
            config.headers['X-CSRF-Token'] = csrfToken;
            config.headers['X-Session-ID'] = sessionId;
        }
        
        return config;
    },
    (error) => {
        return Promise.reject(error);
    }
);

// Response interceptor - Handle errors
apiClient.interceptors.response.use(
    (response) => response,
    (error) => {
        console.error('API Error:', error);
        
        if (error.response) {
            const { status, data } = error.response;
            const message = data?.detail || data?.message || 'An error occurred';
            const errorCode = data?.error || 'UNKNOWN_ERROR';
            
            // Handle specific error codes
            switch (errorCode) {
                case 'AUTHENTICATION_ERROR':
                    toast.error('Authentication failed. Please log in again.');
                    localStorage.removeItem('authToken');
                    localStorage.removeItem('refreshToken');
                    localStorage.removeItem('user');
                    // Redirect to login after a short delay
                    setTimeout(() => {
                        window.location.href = '/login';
                    }, 1500);
                    break;
                
                case 'AUTHORIZATION_ERROR':
                    toast.error("You don't have permission to access this resource.");
                    break;
                
                case 'VALIDATION_ERROR':
                    toast.error(`Validation Error: ${message}`);
                    break;
                
                case 'DATABASE_ERROR':
                    toast.error('A database error occurred. Please try again later.');
                    break;
                
                case 'SCANNER_ERROR':
                    toast.error(`Scan failed: ${message}`);
                    break;
                
                case 'RATE_LIMIT_EXCEEDED':
                    toast.warning('Too many requests. Please slow down.');
                    break;
                
                case 'NOT_FOUND':
                    toast.error('Resource not found.');
                    break;
                
                default:
                    // Handle by status code if no specific error code
                    if (status === 401) {
                        toast.error('Authentication required. Please log in.');
                        localStorage.removeItem('authToken');
                        window.location.href = '/login';
                    } else if (status === 403) {
                        toast.error('Access denied.');
                    } else if (status === 404) {
                        toast.error('Resource not found.');
                    } else if (status === 429) {
                        toast.warning('Too many requests. Please try again later.');
                    } else if (status >= 500) {
                        toast.error('Server error. Please try again later.');
                    } else {
                        toast.error(message);
                    }
            }
            
            throw new APIError(message, status, errorCode);
        } else if (error.request) {
            toast.error('Network error. Please check your connection.');
            throw new APIError('Network error', 0, 'NETWORK_ERROR');
        } else {
            toast.error('An unexpected error occurred.');
            throw new APIError(error.message, 0, 'UNKNOWN_ERROR');
        }
    }
);

// Custom API Error class
export class APIError extends Error {
    constructor(message, statusCode, errorCode) {
        super(message);
        this.name = 'APIError';
        this.statusCode = statusCode;
        this.errorCode = errorCode;
    }
}

// Export configured axios instance
export default apiClient;

// Helper functions for token management
export const setAuthToken = (token) => {
    localStorage.setItem('authToken', token);
};

export const getAuthToken = () => {
    return localStorage.getItem('authToken');
};

export const removeAuthToken = () => {
    localStorage.removeItem('authToken');
    localStorage.removeItem('refreshToken');
    localStorage.removeItem('user');
};

export const setRefreshToken = (token) => {
    localStorage.setItem('refreshToken', token);
};

export const getRefreshToken = () => {
    return localStorage.getItem('refreshToken');
};

// Helper function to refresh access token
export const refreshAccessToken = async () => {
    try {
        const refreshToken = getRefreshToken();
        if (!refreshToken) {
            throw new Error('No refresh token available');
        }
        
        const response = await axios.post(`${API_BASE_URL}/api/v1/auth/refresh`, {
            refresh_token: refreshToken
        });
        
        const { access_token, refresh_token } = response.data;
        setAuthToken(access_token);
        if (refresh_token) {
            setRefreshToken(refresh_token);
        }
        
        return access_token;
    } catch (error) {
        removeAuthToken();
        window.location.href = '/login';
        throw error;
    }
};

// Export API endpoints configuration
export const API_ENDPOINTS = {
    // Authentication
    auth: {
        register: '/api/v1/auth/register',
        login: '/api/v1/auth/login',
        logout: '/api/v1/auth/logout',
        refresh: '/api/v1/auth/refresh',
        me: '/api/v1/auth/me',
        updateProfile: '/api/v1/auth/me',
        changePassword: '/api/v1/auth/change-password',
    },
    // Scanning
    scans: {
        link: '/api/v1/link_scan',
        threat: '/api/v1/threat_scan',
        vulnerability: '/api/v1/scan-vulnerabilities',
        darkweb: '/api/v1/darkweb_scan',
        phishing: '/api/v1/phishing/predict',
        owasp: {
            start: '/api/v1/scan/start',
            status: (id) => `/api/v1/scan/${id}/status`,
            result: (id) => `/api/v1/scan/${id}`,
            cancel: (id) => `/api/v1/scan/${id}/cancel`,
            export: (id) => `/api/v1/scan/${id}/export`,
        },
        attackSurface: {
            list: '/api/v1/attack-surface/scans',
            start: '/api/v1/attack-surface/scan',
            status: (id) => `/api/v1/attack-surface/scan/${id}`,
            assets: (id) => `/api/v1/attack-surface/scan/${id}/assets`,
            summary: (id) => `/api/v1/attack-surface/scan/${id}/summary`,
            cancel: (id) => `/api/v1/attack-surface/scan/${id}`,
            websocket: (id) => `/api/v1/attack-surface/scan/${id}/ws`,
        },
    },
    // Remediation
    remediation: '/api/v1/remediation',
    // Health check
    health: '/health',
};
