/**
 * Secure Storage Utilities
 * 
 * Provides secure wrappers for localStorage with encryption and validation
 * Note: For production, consider migrating to httpOnly cookies for tokens
 */

// Simple encryption key derivation (in production, use a proper key derivation function)
const getStorageKey = () => {
    // Use a combination of factors to create a session-specific key
    const factors = [
        navigator.userAgent,
        navigator.language,
        screen.width,
        screen.height
    ];
    return btoa(factors.join('|'));
};

/**
 * XOR-based encryption (lightweight, not cryptographically strong)
 * For production: Consider using Web Crypto API for stronger encryption
 */
const simpleEncrypt = (text, key) => {
    try {
        const textToChars = text => text.split('').map(c => c.charCodeAt(0));
        const byteHex = n => ("0" + Number(n).toString(16)).substr(-2);
        const applySaltToChar = code => textToChars(key).reduce((a, b) => a ^ b, code);

        return text
            .split('')
            .map(textToChars)
            .map(applySaltToChar)
            .map(byteHex)
            .join('');
    } catch (e) {
        console.error('Encryption failed:', e);
        return text; // Fallback to unencrypted
    }
};

const simpleDecrypt = (encoded, key) => {
    try {
        const textToChars = text => text.split('').map(c => c.charCodeAt(0));
        const applySaltToChar = code => textToChars(key).reduce((a, b) => a ^ b, code);

        return encoded
            .match(/.{1,2}/g)
            .map(hex => parseInt(hex, 16))
            .map(applySaltToChar)
            .map(charCode => String.fromCharCode(charCode))
            .join('');
    } catch (e) {
        console.error('Decryption failed:', e);
        return null;
    }
};

/**
 * Secure storage wrapper
 */
class SecureStorage {
    constructor() {
        this.storageKey = getStorageKey();
        this.prefix = '__secure_';
    }

    /**
     * Set item in storage with encryption
     */
    setItem(key, value) {
        try {
            const prefixedKey = this.prefix + key;
            const encrypted = simpleEncrypt(value, this.storageKey);
            localStorage.setItem(prefixedKey, encrypted);
            return true;
        } catch (e) {
            console.error('SecureStorage.setItem failed:', e);
            return false;
        }
    }

    /**
     * Get item from storage with decryption
     */
    getItem(key) {
        try {
            const prefixedKey = this.prefix + key;
            const encrypted = localStorage.getItem(prefixedKey);
            if (!encrypted) return null;

            const decrypted = simpleDecrypt(encrypted, this.storageKey);
            return decrypted;
        } catch (e) {
            console.error('SecureStorage.getItem failed:', e);
            return null;
        }
    }

    /**
     * Remove item from storage
     */
    removeItem(key) {
        try {
            const prefixedKey = this.prefix + key;
            localStorage.removeItem(prefixedKey);
            return true;
        } catch (e) {
            console.error('SecureStorage.removeItem failed:', e);
            return false;
        }
    }

    /**
     * Clear all secure storage items
     */
    clear() {
        try {
            const keys = Object.keys(localStorage);
            keys.forEach(key => {
                if (key.startsWith(this.prefix)) {
                    localStorage.removeItem(key);
                }
            });
            return true;
        } catch (e) {
            console.error('SecureStorage.clear failed:', e);
            return false;
        }
    }

    /**
     * Check if storage is available and working
     */
    isAvailable() {
        try {
            const test = '__storage_test__';
            localStorage.setItem(test, test);
            localStorage.removeItem(test);
            return true;
        } catch (e) {
            return false;
        }
    }
}

// Export singleton instance
export const secureStorage = new SecureStorage();

/**
 * Token-specific storage helpers
 * These provide backward compatibility with existing code
 */
export const setSecureToken = (key, token) => {
    if (!token) return false;

    // Validate token format (should be a JWT or similar)
    if (typeof token !== 'string' || token.length < 10) {
        console.warn('Invalid token format');
        return false;
    }

    // Set with expiration timestamp
    const tokenData = {
        token,
        timestamp: Date.now(),
        // Add integrity check
        checksum: btoa(token.substring(0, 10))
    };

    return secureStorage.setItem(key, JSON.stringify(tokenData));
};

export const getSecureToken = (key) => {
    try {
        const data = secureStorage.getItem(key);
        if (!data) return null;

        const tokenData = JSON.parse(data);

        // Verify integrity
        const expectedChecksum = btoa(tokenData.token.substring(0, 10));
        if (tokenData.checksum !== expectedChecksum) {
            console.warn('Token integrity check failed');
            secureStorage.removeItem(key);
            return null;
        }

        // Check if token is expired (24 hours for access tokens)
        const tokenAge = Date.now() - tokenData.timestamp;
        const maxAge = key.includes('refresh') ? 30 * 24 * 60 * 60 * 1000 : 24 * 60 * 60 * 1000;

        if (tokenAge > maxAge) {
            console.warn('Token expired');
            secureStorage.removeItem(key);
            return null;
        }

        return tokenData.token;
    } catch (e) {
        console.error('Failed to get secure token:', e);
        return null;
    }
};

export const removeSecureToken = (key) => {
    return secureStorage.removeItem(key);
};

/**
 * Clear all authentication tokens
 */
export const clearAuthTokens = () => {
    const tokenKeys = [
        'access_token',
        'refresh_token',
        'authToken',
        'refreshToken',
        'supabase_access_token',
        'supabase_refresh_token'
    ];

    tokenKeys.forEach(key => {
        secureStorage.removeItem(key);
        localStorage.removeItem(key); // Clear old unencrypted tokens
    });

    localStorage.removeItem('user');
    localStorage.removeItem('auth_provider');
};

export default secureStorage;
