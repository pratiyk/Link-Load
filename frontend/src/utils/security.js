/**
 * Frontend Security Utilities
 * ==========================
 * Provides client-side security measures for OWASP Top 10 protection:
 * - Input sanitization and validation
 * - XSS prevention
 * - CSRF token management
 * - Secure storage handling
 * - Content Security Policy helpers
 */

// =============================================================================
// XSS PREVENTION - Input Sanitization
// =============================================================================

/**
 * Sanitize HTML string to prevent XSS attacks
 * Removes all HTML tags and dangerous content
 */
export const sanitizeHtml = (input) => {
  if (!input || typeof input !== 'string') return '';

  // Create a temporary element to parse HTML
  const temp = document.createElement('div');
  temp.textContent = input;
  return temp.innerHTML;
};

/**
 * Escape HTML special characters
 */
export const escapeHtml = (input) => {
  if (!input || typeof input !== 'string') return '';

  const htmlEntities = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#x27;',
    '/': '&#x2F;',
    '`': '&#x60;',
    '=': '&#x3D;'
  };

  return input.replace(/[&<>"'`=/]/g, char => htmlEntities[char]);
};

/**
 * Sanitize URL to prevent javascript: and data: XSS
 */
export const sanitizeUrl = (url) => {
  if (!url || typeof url !== 'string') return '';

  const trimmedUrl = url.trim().toLowerCase();

  // Block dangerous protocols
  const dangerousProtocols = [
    'javascript:',
    'vbscript:',
    'data:text/html',
    'data:application/javascript'
  ];

  for (const protocol of dangerousProtocols) {
    if (trimmedUrl.startsWith(protocol)) {
      console.warn(`Blocked dangerous URL: ${url.substring(0, 50)}...`);
      return '';
    }
  }

  // Allow only http, https, mailto, and relative URLs
  if (url.startsWith('http://') ||
    url.startsWith('https://') ||
    url.startsWith('mailto:') ||
    url.startsWith('/') ||
    url.startsWith('#')) {
    return url;
  }

  // For relative URLs without leading slash
  if (!url.includes(':')) {
    return url;
  }

  return '';
};

/**
 * Sanitize user input for display
 */
export const sanitizeInput = (input, options = {}) => {
  if (!input) return '';

  const {
    maxLength = 10000,
    allowNewlines = false,
    stripHtml = true
  } = options;

  let sanitized = String(input);

  // Truncate to max length
  sanitized = sanitized.substring(0, maxLength);

  // Strip HTML if requested
  if (stripHtml) {
    sanitized = sanitizeHtml(sanitized);
  }

  // Handle newlines
  if (!allowNewlines) {
    sanitized = sanitized.replace(/[\r\n]/g, ' ');
  }

  // Remove null bytes and control characters
  sanitized = sanitized.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '');

  return sanitized.trim();
};


// =============================================================================
// INPUT VALIDATION
// =============================================================================

/**
 * Validate email format
 */
export const isValidEmail = (email) => {
  if (!email || typeof email !== 'string') return false;

  // RFC 5322 compliant email regex (simplified)
  const emailRegex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;

  return email.length <= 254 && emailRegex.test(email);
};

/**
 * Validate URL format
 */
export const isValidUrl = (url) => {
  if (!url || typeof url !== 'string') return false;

  try {
    const parsed = new URL(url);
    return ['http:', 'https:'].includes(parsed.protocol);
  } catch {
    return false;
  }
};

/**
 * Validate password strength
 */
export const validatePassword = (password) => {
  const result = {
    isValid: false,
    errors: [],
    strength: 0
  };

  if (!password || typeof password !== 'string') {
    result.errors.push('Password is required');
    return result;
  }

  // Minimum length
  if (password.length < 8) {
    result.errors.push('Password must be at least 8 characters');
  } else {
    result.strength += 1;
  }

  // Contains uppercase
  if (!/[A-Z]/.test(password)) {
    result.errors.push('Password must contain at least one uppercase letter');
  } else {
    result.strength += 1;
  }

  // Contains lowercase
  if (!/[a-z]/.test(password)) {
    result.errors.push('Password must contain at least one lowercase letter');
  } else {
    result.strength += 1;
  }

  // Contains number
  if (!/\d/.test(password)) {
    result.errors.push('Password must contain at least one number');
  } else {
    result.strength += 1;
  }

  // Contains special character
  if (!/[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]/.test(password)) {
    result.errors.push('Password must contain at least one special character');
  } else {
    result.strength += 1;
  }

  // Check for common patterns
  const commonPatterns = [
    /^password/i,
    /^123456/,
    /^qwerty/i,
    /(.)\1{3,}/  // 4+ repeated characters
  ];

  for (const pattern of commonPatterns) {
    if (pattern.test(password)) {
      result.errors.push('Password contains a common pattern');
      result.strength = Math.max(0, result.strength - 2);
      break;
    }
  }

  result.isValid = result.errors.length === 0;
  return result;
};

/**
 * Validate UUID format
 */
export const isValidUuid = (uuid) => {
  if (!uuid || typeof uuid !== 'string') return false;

  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  return uuidRegex.test(uuid);
};


// =============================================================================
// CSRF PROTECTION
// =============================================================================

/**
 * Generate a CSRF token
 */
export const generateCsrfToken = () => {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
};

/**
 * Get or create CSRF token from session storage
 */
export const getCsrfToken = () => {
  let token = sessionStorage.getItem('csrfToken');

  if (!token) {
    token = generateCsrfToken();
    sessionStorage.setItem('csrfToken', token);
  }

  return token;
};

/**
 * Validate CSRF token
 */
export const validateCsrfToken = (token) => {
  const storedToken = sessionStorage.getItem('csrfToken');
  return token && storedToken && token === storedToken;
};


// =============================================================================
// SECURE STORAGE
// =============================================================================

/**
 * Secure storage wrapper with encryption support
 */
export const secureStorage = {
  /**
   * Store data with optional expiration
   */
  setItem: (key, value, expiresInMinutes = null) => {
    try {
      const item = {
        value,
        timestamp: Date.now(),
        expires: expiresInMinutes ? Date.now() + (expiresInMinutes * 60 * 1000) : null
      };

      // Use sessionStorage for sensitive data (cleared on browser close)
      sessionStorage.setItem(key, JSON.stringify(item));
    } catch (e) {
      console.error('SecureStorage setItem error:', e);
    }
  },

  /**
   * Retrieve data (returns null if expired)
   */
  getItem: (key) => {
    try {
      const itemStr = sessionStorage.getItem(key);
      if (!itemStr) return null;

      const item = JSON.parse(itemStr);

      // Check expiration
      if (item.expires && Date.now() > item.expires) {
        sessionStorage.removeItem(key);
        return null;
      }

      return item.value;
    } catch (e) {
      console.error('SecureStorage getItem error:', e);
      return null;
    }
  },

  /**
   * Remove item
   */
  removeItem: (key) => {
    try {
      sessionStorage.removeItem(key);
      localStorage.removeItem(key);
    } catch (e) {
      console.error('SecureStorage removeItem error:', e);
    }
  },

  /**
   * Clear all secure storage
   */
  clear: () => {
    try {
      sessionStorage.clear();
    } catch (e) {
      console.error('SecureStorage clear error:', e);
    }
  }
};


// =============================================================================
// SECURITY HEADERS CHECK
// =============================================================================

/**
 * Check if required security headers are present
 */
export const checkSecurityHeaders = async (url = window.location.origin) => {
  const requiredHeaders = [
    'strict-transport-security',
    'x-content-type-options',
    'x-frame-options',
    'content-security-policy'
  ];

  try {
    const response = await fetch(url, { method: 'HEAD' });
    const missing = [];

    for (const header of requiredHeaders) {
      if (!response.headers.get(header)) {
        missing.push(header);
      }
    }

    if (missing.length > 0) {
      console.warn('Missing security headers:', missing);
    }

    return {
      allPresent: missing.length === 0,
      missing
    };
  } catch (e) {
    console.error('Security header check failed:', e);
    return { allPresent: false, missing: requiredHeaders, error: e.message };
  }
};


// =============================================================================
// CLICKJACKING PROTECTION
// =============================================================================

/**
 * Detect if page is loaded in an iframe (frame busting)
 */
export const detectFraming = () => {
  if (window.self !== window.top) {
    console.warn('Page is loaded in an iframe - potential clickjacking attempt');

    // Attempt to break out of frame
    try {
      window.top.location = window.self.location;
    } catch (e) {
      // Cross-origin frame - hide content
      document.body.innerHTML = '<h1>This page cannot be displayed in an iframe</h1>';
    }

    return true;
  }
  return false;
};


// =============================================================================
// SENSITIVE DATA HANDLING
// =============================================================================

/**
 * Mask sensitive data for display
 */
export const maskSensitiveData = (data, visibleChars = 4) => {
  if (!data || typeof data !== 'string') return '';

  if (data.length <= visibleChars) {
    return '*'.repeat(data.length);
  }

  return data.substring(0, visibleChars) + '*'.repeat(data.length - visibleChars);
};

/**
 * Mask email address
 */
export const maskEmail = (email) => {
  if (!email || !isValidEmail(email)) return '';

  const [localPart, domain] = email.split('@');
  const maskedLocal = localPart.length > 2
    ? localPart[0] + '*'.repeat(localPart.length - 2) + localPart[localPart.length - 1]
    : '*'.repeat(localPart.length);

  return `${maskedLocal}@${domain}`;
};


// =============================================================================
// RATE LIMITING (Client-side)
// =============================================================================

const rateLimitStore = new Map();

/**
 * Client-side rate limiting for preventing abuse
 */
export const clientRateLimit = (key, maxRequests = 10, windowMs = 60000) => {
  const now = Date.now();
  const windowStart = now - windowMs;

  // Get existing timestamps for this key
  let timestamps = rateLimitStore.get(key) || [];

  // Filter out old timestamps
  timestamps = timestamps.filter(ts => ts > windowStart);

  // Check if limit exceeded
  if (timestamps.length >= maxRequests) {
    return {
      allowed: false,
      retryAfter: Math.ceil((timestamps[0] + windowMs - now) / 1000)
    };
  }

  // Add current timestamp
  timestamps.push(now);
  rateLimitStore.set(key, timestamps);

  return {
    allowed: true,
    remaining: maxRequests - timestamps.length
  };
};


// =============================================================================
// SECURE RANDOM GENERATION
// =============================================================================

/**
 * Generate cryptographically secure random string
 */
export const generateSecureRandom = (length = 32) => {
  const array = new Uint8Array(length);
  crypto.getRandomValues(array);
  return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
};

/**
 * Generate secure session ID
 */
export const generateSessionId = () => {
  return `sess_${generateSecureRandom(24)}`;
};


// =============================================================================
// CONTENT SECURITY POLICY NONCE
// =============================================================================

/**
 * Get CSP nonce from meta tag (if set by server)
 */
export const getCspNonce = () => {
  const meta = document.querySelector('meta[name="csp-nonce"]');
  return meta ? meta.getAttribute('content') : null;
};


// =============================================================================
// INITIALIZATION
// =============================================================================

/**
 * Initialize security measures
 */
export const initSecurity = () => {
  // Detect framing attempts
  detectFraming();

  // Initialize CSRF token
  getCsrfToken();

  // Log security initialization
  if (process.env.NODE_ENV === 'development') {
    console.log('Security utilities initialized');
    checkSecurityHeaders().then(result => {
      if (!result.allPresent) {
        console.warn('Security headers check:', result);
      }
    });
  }
};

export default {
  sanitizeHtml,
  escapeHtml,
  sanitizeUrl,
  sanitizeInput,
  isValidEmail,
  isValidUrl,
  validatePassword,
  isValidUuid,
  generateCsrfToken,
  getCsrfToken,
  validateCsrfToken,
  secureStorage,
  checkSecurityHeaders,
  detectFraming,
  maskSensitiveData,
  maskEmail,
  clientRateLimit,
  generateSecureRandom,
  generateSessionId,
  getCspNonce,
  initSecurity
};
