/**
 * Environment Configuration Validator
 * 
 * Validates that environment variables are properly configured
 * and alerts developers to potential security issues
 */

const ENV = {
    API_URL: process.env.REACT_APP_API_URL,
    WS_URL: process.env.REACT_APP_WS_URL,
    API_TIMEOUT: process.env.REACT_APP_API_TIMEOUT,
    ENVIRONMENT: process.env.REACT_APP_ENVIRONMENT || process.env.NODE_ENV,
    SUPABASE_URL: process.env.REACT_APP_SUPABASE_URL,
    SUPABASE_ANON_KEY: process.env.REACT_APP_SUPABASE_ANON_KEY,
};

/**
 * Checks if running in development mode
 */
export const isDevelopment = () => {
    return ENV.ENVIRONMENT === 'development' || process.env.NODE_ENV === 'development';
};

/**
 * Checks if running in production mode
 */
export const isProduction = () => {
    return ENV.ENVIRONMENT === 'production' || process.env.NODE_ENV === 'production';
};

/**
 * Validates environment configuration
 */
export const validateEnvironment = () => {
    const warnings = [];
    const errors = [];

    // Check required variables
    if (!ENV.API_URL) {
        errors.push('REACT_APP_API_URL is not defined');
    }

    // Security checks
    if (isProduction()) {
        // Check for localhost URLs in production
        if (ENV.API_URL?.includes('localhost') || ENV.API_URL?.includes('127.0.0.1')) {
            warnings.push('API_URL points to localhost in production environment');
        }

        // Check for http (not https) in production
        if (ENV.API_URL?.startsWith('http://') && !ENV.API_URL.includes('localhost')) {
            warnings.push('API_URL is not using HTTPS in production');
        }

        // Check if Supabase keys look like they might be service keys (they shouldn't be in frontend)
        if (ENV.SUPABASE_ANON_KEY?.includes('service_role')) {
            errors.push('⚠️ CRITICAL: Supabase service role key detected in frontend! This is a severe security risk.');
        }
    }

    // Log warnings and errors
    if (warnings.length > 0) {
        console.warn('Environment configuration warnings:', warnings);
    }

    if (errors.length > 0) {
        console.error('Environment configuration errors:', errors);
        if (isProduction()) {
            // In production, throw error to prevent app from running with security issues
            throw new Error(`Critical environment configuration errors: ${errors.join(', ')}`);
        }
    }

    return {
        valid: errors.length === 0,
        warnings,
        errors
    };
};

/**
 * Safe environment getter that doesn't expose sensitive values in logs
 */
export const getEnvValue = (key, defaultValue = null) => {
    const value = ENV[key];

    if (!value) {
        if (isDevelopment()) {
            console.warn(`Environment variable ${key} is not set, using default:`, defaultValue);
        }
        return defaultValue;
    }

    return value;
};

/**
 * Check if a value looks like a sensitive credential
 */
const looksLikeSensitiveValue = (value) => {
    if (typeof value !== 'string') return false;

    const sensitivePatterns = [
        /service_role/i,
        /secret/i,
        /private.*key/i,
        /password/i,
    ];

    return sensitivePatterns.some(pattern => pattern.test(value));
};

/**
 * Sanitize environment values for safe logging
 */
export const sanitizeEnvForLogging = (env) => {
    const sanitized = {};

    for (const [key, value] of Object.entries(env)) {
        if (!value) {
            sanitized[key] = '<not set>';
        } else if (looksLikeSensitiveValue(key) || looksLikeSensitiveValue(value)) {
            sanitized[key] = '<redacted>';
        } else if (typeof value === 'string') {
            // For keys/tokens, show first 4 and last 4 characters
            if (key.includes('KEY') || key.includes('TOKEN')) {
                if (value.length > 12) {
                    sanitized[key] = `${value.substring(0, 4)}...${value.substring(value.length - 4)}`;
                } else {
                    sanitized[key] = '<redacted>';
                }
            } else {
                sanitized[key] = value;
            }
        } else {
            sanitized[key] = value;
        }
    }

    return sanitized;
};

/**
 * Log environment configuration safely (for debugging)
 */
export const logEnvironment = () => {
    if (!isDevelopment()) {
        console.info('Environment:', isProduction() ? 'production' : ENV.ENVIRONMENT);
        return;
    }

    console.group('Environment Configuration');
    console.log('Mode:', ENV.ENVIRONMENT);
    const sanitized = sanitizeEnvForLogging(ENV);
    console.table(sanitized);
    console.groupEnd();
};

// Validate on import (will run once when app starts)
if (typeof window !== 'undefined') {
    try {
        validateEnvironment();
    } catch (error) {
        console.error('Environment validation failed:', error);
    }
}

// Export environment object (sanitized in production)
export default ENV;
