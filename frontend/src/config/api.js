/**
 * Centralized API configuration for LinkLoad frontend
 *
 * - Base API URLs from environment variables
 * - Axios instance with interceptors
 * - Error handling
 * - Authentication token management
 * - Security features (CSRF, rate limiting, input validation)
 */
import axios from "axios";
import { toast } from "react-toastify";
import { supabase, isSupabaseConfigured } from "../services/supabaseClient";
import {
  getCsrfToken,
  sanitizeInput,
  clientRateLimit,
  generateSecureRandom
} from "../utils/security";

// API Configuration
export const API_BASE_URL =
  process.env.REACT_APP_API_URL || "http://localhost:8000";
export const WS_BASE_URL =
  process.env.REACT_APP_WS_URL || "ws://localhost:8000";
export const API_TIMEOUT = parseInt(process.env.REACT_APP_API_TIMEOUT) || 30000;

// Security configuration
const MAX_RETRY_ATTEMPTS = 3;
const RATE_LIMIT_REQUESTS = 100;
const RATE_LIMIT_WINDOW_MS = 60000; // 1 minute

// Create axios instance with default config
const apiClient = axios.create({
  baseURL: API_BASE_URL,
  timeout: API_TIMEOUT,
  headers: {
    "Content-Type": "application/json",
  },
  // Security: Don't send cookies to cross-origin requests by default
  withCredentials: false,
});

// 401 refresh state management
let isRefreshing = false;
let pendingRequests = [];
const onRefreshed = (newToken) => {
  pendingRequests.forEach((cb) => cb(newToken));
  pendingRequests = [];
};

// Request interceptor - Add auth token and security headers
apiClient.interceptors.request.use(
  (config) => {
    // Client-side rate limiting to prevent abuse
    const rateLimitResult = clientRateLimit('api_requests', RATE_LIMIT_REQUESTS, RATE_LIMIT_WINDOW_MS);
    if (!rateLimitResult.allowed) {
      const error = new Error(`Rate limit exceeded. Please wait ${rateLimitResult.retryAfter} seconds.`);
      error.isRateLimited = true;
      return Promise.reject(error);
    }

    // Add authentication token
    const token =
      localStorage.getItem("access_token") || localStorage.getItem("authToken");
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }

    // Add CSRF token for state-changing requests
    if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(config.method?.toUpperCase())) {
      const csrfToken = getCsrfToken();
      if (csrfToken) {
        config.headers["X-CSRF-Token"] = csrfToken;
      }
    }

    // Add request ID for tracing
    config.headers["X-Request-ID"] = generateSecureRandom(16);

    // Add session ID if available
    const sessionId = sessionStorage.getItem("sessionId");
    if (sessionId) {
      config.headers["X-Session-ID"] = sessionId;
    }

    // Sanitize request data for POST/PUT/PATCH requests
    if (config.data && typeof config.data === 'object') {
      config.data = sanitizeRequestData(config.data);
    }

    return config;
  },
  (error) => Promise.reject(error)
);

/**
 * Recursively sanitize request data to prevent XSS
 */
const sanitizeRequestData = (data, depth = 0) => {
  // Prevent deep recursion attacks
  if (depth > 10) return data;

  if (Array.isArray(data)) {
    return data.map(item => sanitizeRequestData(item, depth + 1));
  }

  if (data && typeof data === 'object') {
    const sanitized = {};
    for (const [key, value] of Object.entries(data)) {
      // Skip sanitizing certain fields (like passwords, tokens)
      const skipSanitize = ['password', 'token', 'access_token', 'refresh_token', 'api_key'];
      if (skipSanitize.some(field => key.toLowerCase().includes(field))) {
        sanitized[key] = value;
      } else if (typeof value === 'string') {
        sanitized[key] = sanitizeInput(value, { maxLength: 10000, stripHtml: true });
      } else {
        sanitized[key] = sanitizeRequestData(value, depth + 1);
      }
    }
    return sanitized;
  }

  return data;
};

// Response interceptor - Handle errors with security considerations
apiClient.interceptors.response.use(
  (response) => {
    // Validate response content type
    const contentType = response.headers['content-type'];
    if (contentType && !contentType.includes('application/json') && !contentType.includes('text/')) {
      console.warn('Unexpected content type:', contentType);
    }
    return response;
  },
  async (error) => {
    // Handle rate limiting from client-side check
    if (error.isRateLimited) {
      toast.warning(error.message);
      return Promise.reject(error);
    }

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
        // Use replace to prevent back button returning to authenticated pages
        window.location.replace("/login");
        return Promise.reject(refreshErr);
      } finally {
        isRefreshing = false;
      }
    }

    // Non-401 error handling with security considerations
    console.error("API Error:", error);
    if (error.response) {
      const { status, data } = error.response;
      // Sanitize error message to prevent XSS through error messages
      const rawMessage = data?.detail || data?.message || "An error occurred";
      const message = typeof rawMessage === 'string'
        ? rawMessage.substring(0, 200) // Truncate long messages
        : "An error occurred";
      const errorCode = data?.error || "UNKNOWN_ERROR";

      // Handle specific status codes
      switch (status) {
        case 400:
          toast.error("Invalid request. Please check your input.");
          break;
        case 403:
          toast.error("Access denied. You don't have permission to perform this action.");
          break;
        case 404:
          toast.error("The requested resource was not found.");
          break;
        case 413:
          toast.error("Request too large. Please reduce the size of your data.");
          break;
        case 422:
          toast.error(message);
          break;
        case 429:
          toast.warning("Too many requests. Please wait a moment and try again.");
          break;
        default:
          if (status >= 500) {
            toast.error("Server error. Our team has been notified. Please try again later.");
          } else {
            toast.error(message);
          }
      }

      throw new APIError(message, status, errorCode);
    } else if (error.request) {
      toast.error("Network error. Please check your internet connection.");
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
  localStorage.removeItem("supabase_access_token");
  localStorage.removeItem("supabase_refresh_token");
  localStorage.removeItem("auth_provider");
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
    const authProvider = localStorage.getItem("auth_provider");
    if (authProvider === "supabase" && isSupabaseConfigured && supabase) {
      const { data, error } = await supabase.auth.refreshSession();
      if (error) {
        throw error;
      }

      const { session } = data || {};
      if (!session?.access_token) {
        throw new Error("Supabase session refresh returned no access token");
      }

      setAuthToken(session.access_token);
      if (session.refresh_token) {
        setRefreshToken(session.refresh_token);
        localStorage.setItem("supabase_refresh_token", session.refresh_token);
      }
      localStorage.setItem("supabase_access_token", session.access_token);
      localStorage.setItem("auth_provider", "supabase");

      return session.access_token;
    }

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

    localStorage.setItem("auth_provider", "native");

    return access_token;
  } catch (error) {
    removeAuthToken();
    window.location.href = "/login";
    throw error;
  }
};

// Export API endpoints configuration
export const API_ENDPOINTS = {
  base: API_BASE_URL,
  ws: WS_BASE_URL,
  auth: {
    register: "/api/v1/auth/register",
    login: "/api/v1/auth/login",
    logout: "/api/v1/auth/logout",
    refresh: "/api/v1/auth/refresh",
    me: "/api/v1/auth/me",
    updateProfile: "/api/v1/auth/me",
    changePassword: "/api/v1/auth/change-password",
  },
  scans: {
    threat: "/api/v1/scan-threat",
    darkweb: "/api/v1/darkweb_scan",
    phishing: "/api/v1/phishing/predict",
    packages: {
      scan: "/api/v1/packages/scan",
    },
    comprehensive: {
      start: "/api/v1/scans/comprehensive/start",
      status: (id) => `/api/v1/scans/comprehensive/${id}/status`,
      result: (id) => `/api/v1/scans/comprehensive/${id}/result`,
      summary: (id) => `/api/v1/scans/comprehensive/${id}/summary`,
      list: "/api/v1/scans/comprehensive/list",
      cancel: (id) => `/api/v1/scans/comprehensive/${id}/cancel`,
      delete: (id) => `/api/v1/scans/comprehensive/${id}`,
      deleteBulk: "/api/v1/scans/comprehensive/bulk",
      ws: (id) => `/ws/scans/${id}`,
    },
    manager: {
      start: "/api/v1/scans",
      list: "/api/v1/scans",
      detail: (id) => `/api/v1/scans/${id}`,
      cancel: (id) => `/api/v1/scans/${id}`,
      findings: (id) => `/api/v1/scans/${id}/findings`,
      schedule: "/api/v1/scans/schedule",
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
  remediation: "/api/v1/remediate",
  remediationExport: "/api/v1/remediate/export",
  verification: {
    profile: "/api/v1/domains/profile",
    list: "/api/v1/domains",
    create: "/api/v1/domains",
    item: (id) => `/api/v1/domains/${id}`,
    verify: (id) => `/api/v1/domains/${id}/verify`,
    rotateToken: "/api/v1/domains/rotate-token",
  },
  health: "/health",
};
