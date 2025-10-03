import React, { createContext, useContext, useEffect, useState, useCallback } from 'react';
import toast from 'react-hot-toast';
import { authApi } from '../services/authApi';
import { scannerApi } from '../services/scannerApi';

const AuthContext = createContext();

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

  const initializeAuth = useCallback(async () => {
    try {
      const token = localStorage.getItem('access_token');
      if (token) {
        const userData = await authApi.getCurrentUser();
        setUser(userData);
        setIsAuthenticated(true);
        fetchUserScans();
      }
    } catch (error) {
      console.error('Auth initialization failed:', error);
      logout();
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    initializeAuth();
  }, [initializeAuth]);

  const fetchUserScans = async () => {
    try {
      const scanData = await scannerApi.getUserScans();
      setScans(scanData || []);
    } catch (error) {
      console.error('Failed to fetch scans:', error);
      toast.error('Failed to load scan history');
    }
  };

  const login = async (email, password) => {
    try {
      setLoading(true);
      const response = await authApi.login(email, password);
      
      localStorage.setItem('access_token', response.access_token);
      localStorage.setItem('refresh_token', response.refresh_token);
      
      const userData = await authApi.getCurrentUser();
      setUser(userData);
      setIsAuthenticated(true);
      await fetchUserScans();
      
      toast.success('Login successful!');
      return { success: true };
    } catch (error) {
      const message = error.response?.data?.detail || 'Login failed. Check credentials and try again.';
      toast.error(message);
      return { success: false, error: message };
    } finally {
      setLoading(false);
    }
  };

  const register = async (userData) => {
    try {
      setLoading(true);
      await authApi.register(userData);
      
      const loginResult = await login(userData.email, userData.password);
      if (loginResult.success) {
        toast.success('Registration successful!');
      }
      
      return { success: true };
    } catch (error) {
      const message = error.response?.data?.detail || 
        'Registration failed. Please check your information.';
      toast.error(message);
      return { success: false, error: message };
    } finally {
      setLoading(false);
    }
  };

  const logout = async () => {
    try {
      await authApi.logout();
    } catch (error) {
      console.error('Logout error:', error);
    } finally {
      localStorage.removeItem('access_token');
      localStorage.removeItem('refresh_token');
      setUser(null);
      setIsAuthenticated(false);
      setScans([]);
      toast.success('Logged out successfully');
    }
  };

  const refreshToken = async () => {
    try {
      const refreshToken = localStorage.getItem('refresh_token');
      if (!refreshToken) {
        throw new Error('No refresh token available');
      }
      
      const response = await authApi.refreshToken(refreshToken);
      localStorage.setItem('access_token', response.access_token);
      
      return response.access_token;
    } catch (error) {
      console.error('Token refresh failed:', error);
      await logout();
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