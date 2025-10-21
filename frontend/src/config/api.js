/**
 * Centralized API configuration for LinkLoad frontend
 *
    const token = localStorage.getItem('access_token') || localStorage.getItem('authToken');
 * - Base API URLs from environment variables
 * - Axios instance with interceptors
 * - Error handling
 * - Authentication token management
 */
import axios from "axios";
import { toast } from "react-toastify";

// API Configuration
export const API_BASE_URL =
  process.env.REACT_APP_API_URL || "http://localhost:8000";
export const WS_BASE_URL =
  process.env.REACT_APP_WS_URL || "ws://localhost:8000";
export const API_TIMEOUT = parseInt(process.env.REACT_APP_API_TIMEOUT) || 30000;

// Create axios instance with default config
const apiClient = axios.create({
  baseURL: API_BASE_URL,
  timeout: API_TIMEOUT,
  headers: {
    "Content-Type": "application/json",
  },
});
// 401 refresh state management
let isRefreshing = false;
let pendingRequests = [];
const onRefreshed = (newToken) => {
  pendingRequests.forEach((cb) => cb(newToken));
  pendingRequests = [];
};

// Request interceptor - Add auth token
apiClient.interceptors.request.use(
  (config) => {
    const token =
      localStorage.getItem("access_token") || localStorage.getItem("authToken");
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }

    // Optionally include CSRF/session headers if set elsewhere
    const csrfToken = localStorage.getItem("csrfToken");
    const sessionId = localStorage.getItem("sessionId");
    if (csrfToken && sessionId) {
      config.headers["X-CSRF-Token"] = csrfToken;
      config.headers["X-Session-ID"] = sessionId;
    }

    return config;
  },
  (error) => Promise.reject(error)
);

// Response interceptor - Handle errors
apiClient.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;

    // Attempt token refresh on 401 once per request
    if (error.response?.status === 401 && !originalRequest._retry) {
      if (isRefreshing) {
        return new Promise((resolve) => {
          pendingRequests.push((newToken) => {
            originalRequest.headers.Authorization = `Bearer ${newToken}`;
            resolve(apiClient(originalRequest));
          });
        });
      }

      originalRequest._retry = true;
      isRefreshing = true;
      try {
        const newToken = await refreshAccessToken();
        onRefreshed(newToken);
        originalRequest.headers.Authorization = `Bearer ${newToken}`;
        return apiClient(originalRequest);
      } catch (refreshErr) {
        toast.error("Session expired. Please log in again.");
        removeAuthToken();
        window.location.href = "/login";
        return Promise.reject(refreshErr);
      } finally {
        isRefreshing = false;
      }
    }

    // Non-401 error handling
    console.error("API Error:", error);
    if (error.response) {
      const { status, data } = error.response;
      const message = data?.detail || data?.message || "An error occurred";
      const errorCode = data?.error || "UNKNOWN_ERROR";

      if (status === 403) toast.error("Access denied.");
      else if (status === 404) toast.error("Resource not found.");
      else if (status === 429) toast.warning("Too many requests. Please try again later.");
      else if (status >= 500) toast.error("Server error. Please try again later.");
      else toast.error(message);

      throw new APIError(message, status, errorCode);
    } else if (error.request) {
      toast.error("Network error. Please check your connection.");
      throw new APIError("Network error", 0, "NETWORK_ERROR");
    } else {
      toast.error("An unexpected error occurred.");
      throw new APIError(error.message, 0, "UNKNOWN_ERROR");
    }
  }
);

// Custom API Error class
export class APIError extends Error {
  constructor(message, statusCode, errorCode) {
    super(message);
    this.name = "APIError";
    this.statusCode = statusCode;
    this.errorCode = errorCode;
  }
}

// Export configured axios instance
export default apiClient;

// Helper functions for token management
export const setAuthToken = (token) => {
  localStorage.setItem("access_token", token);
  localStorage.setItem("authToken", token);
};

export const getAuthToken = () => {
  return (
    localStorage.getItem("access_token") || localStorage.getItem("authToken")
  );
};

export const removeAuthToken = () => {
  localStorage.removeItem("access_token");
  localStorage.removeItem("refresh_token");
  localStorage.removeItem("authToken");
  localStorage.removeItem("refreshToken");
  localStorage.removeItem("user");
};

export const setRefreshToken = (token) => {
  localStorage.setItem("refresh_token", token);
  localStorage.setItem("refreshToken", token);
};

export const getRefreshToken = () => {
  return (
    localStorage.getItem("refresh_token") ||
    localStorage.getItem("refreshToken")
  );
};

// Helper function to refresh access token
export const refreshAccessToken = async () => {
  try {
    const refreshToken = getRefreshToken();
    if (!refreshToken) {
      throw new Error("No refresh token available");
    }

    const response = await axios.post(`${API_BASE_URL}/api/v1/auth/refresh`, {
      refresh_token: refreshToken,
    });

    const { access_token, refresh_token } = response.data;
    setAuthToken(access_token);
    if (refresh_token) {
      setRefreshToken(refresh_token);
    }

    return access_token;
  } catch (error) {
    removeAuthToken();
    window.location.href = "/login";
    throw error;
  }
};

// Export API endpoints configuration
export const API_ENDPOINTS = {
  // Authentication
  auth: {
    register: "/api/v1/auth/register",
    login: "/api/v1/auth/login",
    logout: "/api/v1/auth/logout",
    refresh: "/api/v1/auth/refresh",
    me: "/api/v1/auth/me",
    updateProfile: "/api/v1/auth/me",
    changePassword: "/api/v1/auth/change-password",
  },
  // Scanning
  scans: {
    link: "/api/v1/scan-url",
    threat: "/api/v1/scan-threat",
    vulnerability: "/api/v1/scan-vulnerabilities",
    darkweb: "/api/v1/darkweb_scan",
    phishing: "/api/v1/phishing/predict",
    owasp: {
      start: "/api/v1/scan/start",
      status: (id) => `/api/v1/scan/${id}/status`,
      result: (id) => `/api/v1/scan/${id}`,
      cancel: (id) => `/api/v1/scan/${id}/cancel`,
      export: (id) => `/api/v1/scan/${id}/export`,
    },
    attackSurface: {
      list: "/api/v1/attack-surface/scans",
      start: "/api/v1/attack-surface/scan",
      status: (id) => `/api/v1/attack-surface/scan/${id}`,
      assets: (id) => `/api/v1/attack-surface/scan/${id}/assets`,
      summary: (id) => `/api/v1/attack-surface/scan/${id}/summary`,
      cancel: (id) => `/api/v1/attack-surface/scan/${id}`,
      websocket: (id) => `/api/v1/attack-surface/scan/${id}/ws`,
    },
  },
  // Remediation
  remediation: "/api/v1/remediate",
  remediationExport: "/api/v1/remediate/export",
  // Health check
  health: "/health",
};
