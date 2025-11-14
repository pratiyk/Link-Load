import React, { createContext, useContext, useEffect, useState, useCallback } from 'react';
import toast from 'react-hot-toast';
import { authApi } from '../services/authApi';
import { scannerApi } from '../services/scannerApi';
import { supabase, isSupabaseConfigured } from '../services/supabaseClient';
import { setAuthToken, setRefreshToken, removeAuthToken } from '../config/api';

const AuthContext = createContext();

const sanitizeUsername = (value) => {
  if (!value) {
    return '';
  }
  return value
    .toLowerCase()
    .replace(/[^a-z0-9_-]+/g, '_')
    .replace(/_+/g, '_')
    .replace(/^_+|_+$/g, '')
    .slice(0, 50);
};

const deriveBackendUsername = (email, fullName, preferredUsername) => {
  const emailUser = email ? email.split('@')[0] : '';
  const candidates = [preferredUsername, fullName, emailUser];

  for (const candidate of candidates) {
    const sanitized = sanitizeUsername(candidate);
    if (sanitized) {
      return sanitized;
    }
  }

  return `user_${Math.random().toString(36).slice(2, 10)}`;
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [scans, setScans] = useState([]);

  const fetchUserScans = useCallback(async () => {
    try {
      const scanData = await scannerApi.getUserScans();
      setScans(scanData || []);
    } catch (error) {
      console.error('Failed to fetch scans:', error);
      toast.error('Failed to load scan history');
    }
  }, []);

  const initializeAuth = useCallback(async () => {
    try {
      if (isSupabaseConfigured && supabase) {
        const { data } = await supabase.auth.getSession();
        const { session } = data;
        if (session?.user) {
          setAuthToken(session.access_token);
          if (session.refresh_token) {
            setRefreshToken(session.refresh_token);
          }
          localStorage.setItem('supabase_access_token', session.access_token);
          localStorage.setItem('supabase_refresh_token', session.refresh_token || '');
          localStorage.setItem('auth_provider', 'supabase');
          setUser(session.user);
          setIsAuthenticated(true);
          try {
            await fetchUserScans();
          } catch (scanError) {
            console.warn('Unable to load scans during Supabase session init', scanError);
          }
          setLoading(false);
          return;
        }
      }

      const token = localStorage.getItem('access_token');
      if (token) {
        localStorage.setItem('auth_provider', localStorage.getItem('auth_provider') || 'native');
        const userData = await authApi.getCurrentUser();
        setUser(userData);
        setIsAuthenticated(true);
        await fetchUserScans();
      }
    } catch (error) {
      console.error('Auth initialization failed:', error);
      logout({ silent: true });
    } finally {
      setLoading(false);
    }
  }, [fetchUserScans]);

  useEffect(() => {
    initializeAuth();
  }, [initializeAuth]);

  const login = async (email, password) => {
    try {
      setLoading(true);
      const sanitizedEmail = (email || '').trim().toLowerCase();
      if (isSupabaseConfigured && supabase) {
        const { data, error } = await supabase.auth.signInWithPassword({
          email: sanitizedEmail,
          password
        });

        if (error) {
          throw new Error('Unable to sign in. Check your credentials and try again.');
        }

        const { user: supabaseUser, session } = data || {};
        if (session) {
          setAuthToken(session.access_token);
          if (session.refresh_token) {
            setRefreshToken(session.refresh_token);
          }
          localStorage.setItem('supabase_access_token', session.access_token);
          localStorage.setItem('supabase_refresh_token', session.refresh_token || '');
        }
        localStorage.setItem('auth_provider', 'supabase');
        setUser(supabaseUser);
        setIsAuthenticated(Boolean(supabaseUser));

        if (supabaseUser) {
          try {
            await fetchUserScans();
          } catch (scanError) {
            console.warn('Unable to load scans after Supabase login', scanError);
          }
        }
        toast.success('Login successful!');
        return { success: true, provider: 'supabase' };
      }

      const response = await authApi.login(sanitizedEmail, password);

      setAuthToken(response.access_token);
      setRefreshToken(response.refresh_token);
      localStorage.setItem('auth_provider', 'native');

      const userData = await authApi.getCurrentUser();
      setUser(userData);
      setIsAuthenticated(true);
      await fetchUserScans();

      toast.success('Login successful!');
      return { success: true, provider: 'backend' };
    } catch (error) {
      console.error('Login failed:', error);
      const message = 'Unable to sign in. Check your credentials and try again.';
      toast.error(message);
      return { success: false, error: message };
    } finally {
      setLoading(false);
    }
  };

  const register = async (userData) => {
    try {
      setLoading(true);
      const sanitizedEmail = (userData.email || '').trim().toLowerCase();
      const sanitizedName = (userData.name || userData.fullName || '').trim();
      const sanitizedUsername = deriveBackendUsername(
        sanitizedEmail,
        sanitizedName,
        userData.username
      );
      if (isSupabaseConfigured && supabase) {
        const { error } = await supabase.auth.signUp({
          email: sanitizedEmail,
          password: userData.password,
          options: {
            data: {
              full_name: sanitizedName || undefined
            }
          }
        });

        if (error) {
          throw new Error('Unable to create account. Please try again later.');
        }

        toast.success('Registration successful! Check your email to confirm the account.');
        return { success: true, provider: 'supabase' };
      }

      const backendPayload = {
        email: sanitizedEmail,
        username: sanitizedUsername,
        password: userData.password,
        confirm_password: userData.confirmPassword || userData.confirm_password || userData.password,
        full_name: sanitizedName || undefined,
      };

      await authApi.register(backendPayload);

      const loginResult = await login(userData.email, userData.password);
      if (loginResult.success) {
        toast.success('Registration successful!');
      }

      return { success: true, provider: 'backend' };
    } catch (error) {
      console.error('Registration failed:', error);
      const message = 'Unable to create account. Please try again later.';
      toast.error(message);
      return { success: false, error: message };
    } finally {
      setLoading(false);
    }
  };

  const logout = async ({ silent = false } = {}) => {
    try {
      if (isSupabaseConfigured && supabase) {
        await supabase.auth.signOut();
        localStorage.removeItem('supabase_access_token');
        localStorage.removeItem('supabase_refresh_token');
      } else {
        await authApi.logout();
      }
    } catch (error) {
      console.error('Logout error:', error);
    } finally {
      removeAuthToken();
      setUser(null);
      setIsAuthenticated(false);
      setScans([]);
      localStorage.removeItem('auth_provider');
      if (!silent) {
        toast.success('Logged out successfully');
      }
    }
  };

  const refreshToken = async () => {
    try {
      if (isSupabaseConfigured && supabase) {
        const { data, error } = await supabase.auth.refreshSession();
        if (error) {
          throw error;
        }
        const { session } = data || {};
        if (session) {
          setAuthToken(session.access_token);
          if (session.refresh_token) {
            setRefreshToken(session.refresh_token);
          }
          localStorage.setItem('supabase_access_token', session.access_token);
          localStorage.setItem('supabase_refresh_token', session.refresh_token || '');
          localStorage.setItem('auth_provider', 'supabase');
          return session.access_token;
        }
        throw new Error('No Supabase session available');
      }

      const refreshToken = localStorage.getItem('refresh_token');
      if (!refreshToken) {
        throw new Error('No refresh token available');
      }

      const response = await authApi.refreshToken(refreshToken);
      setAuthToken(response.access_token);
      if (response.refresh_token) {
        setRefreshToken(response.refresh_token);
      }
      localStorage.setItem('auth_provider', 'native');

      return response.access_token;
    } catch (error) {
      console.error('Token refresh failed:', error);
      await logout({ silent: true });
      throw error;
    }
  };

  const updateProfile = async (profileData) => {
    try {
      const updatedUser = await authApi.updateProfile(profileData);
      setUser(updatedUser);
      toast.success('Profile updated successfully');
      return { success: true };
    } catch (error) {
      const message = error.response?.data?.detail || 'Profile update failed';
      toast.error(message);
      return { success: false, error: message };
    }
  };

  const changePassword = async (currentPassword, newPassword) => {
    try {
      await authApi.changePassword(currentPassword, newPassword);
      toast.success('Password changed successfully');
      return { success: true };
    } catch (error) {
      const message = error.response?.data?.detail || 'Password change failed';
      toast.error(message);
      return { success: false, error: message };
    }
  };

  const addScan = (scan) => {
    setScans(prev => [scan, ...prev.slice(0, 49)]);
  };

  const updateScan = (scanId, updates) => {
    setScans(prev => prev.map(scan =>
      scan.scan_id === scanId ? { ...scan, ...updates } : scan
    ));
  };

  const value = {
    user,
    loading,
    isAuthenticated,
    scans,
    login,
    register,
    logout,
    refreshToken,
    updateProfile,
    changePassword,
    fetchUserScans,
    addScan,
    updateScan
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
};