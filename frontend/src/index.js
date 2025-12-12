// src/index.js
import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { AuthProvider } from "./context/AuthContext";
import { initSecurity } from "./utils/security";
import "./index.css"; // Make sure Tailwind or global styles are loaded

// Initialize security measures before rendering
initSecurity();

// Create a query client instance with secure defaults
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      // Don't retry on 401/403 errors
      retry: (failureCount, error) => {
        if (error?.statusCode === 401 || error?.statusCode === 403) {
          return false;
        }
        return failureCount < 3;
      },
      // Reduce stale time for security-sensitive data
      staleTime: 5 * 60 * 1000, // 5 minutes
      // Don't cache sensitive data too long
      cacheTime: 10 * 60 * 1000, // 10 minutes
    },
  },
});

ReactDOM.createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    {/* React Query Provider */}
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <App />
      </AuthProvider>
    </QueryClientProvider>
  </React.StrictMode>
);
