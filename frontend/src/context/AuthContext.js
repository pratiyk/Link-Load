import React, { createContext, useContext, useState, useEffect } from 'react';

const AuthContext = createContext(null);

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

  useEffect(() => {
    // Check if user is logged in
    const checkAuth = async () => {
      try {
        // Get token from localStorage
        const token = localStorage.getItem('token');
        if (token) {
          // You can validate token with backend here
          // For now, just set a mock user
          setUser({
            id: '1',
            email: 'user@example.com',
            name: 'User',
            avatar: null
          });
        }
      } catch (error) {
        console.error('Auth error:', error);
        setUser(null);
      } finally {
        setLoading(false);
      }
    };

    checkAuth();
  }, []);

  const login = async (email, password) => {
    try {
      // TODO: Implement actual login API call
      const mockResponse = {
        token: 'mock-jwt-token',
        user: {
          id: '1',
          email: email,
          name: 'User',
          avatar: null
        }
      };

      localStorage.setItem('token', mockResponse.token);
      setUser(mockResponse.user);
      return true;
    } catch (error) {
      console.error('Login error:', error);
      return false;
    }
  };

  const register = async (email, password, name) => {
    try {
      // TODO: Implement actual registration API call
      const mockResponse = {
        token: 'mock-jwt-token',
        user: {
          id: '1',
          email: email,
          name: name,
          avatar: null
        }
      };

      localStorage.setItem('token', mockResponse.token);
      setUser(mockResponse.user);
      return true;
    } catch (error) {
      console.error('Registration error:', error);
      return false;
    }
  };

  const logout = () => {
    localStorage.removeItem('token');
    setUser(null);
  };

  const updateProfile = async (userData) => {
    try {
      // TODO: Implement actual profile update API call
      setUser((prev) => ({ ...prev, ...userData }));
      return true;
    } catch (error) {
      console.error('Profile update error:', error);
      return false;
    }
  };

  const value = {
    user,
    loading,
    login,
    register,
    logout,
    updateProfile
  };

  return (
    <AuthContext.Provider value={value}>
      {!loading && children}
    </AuthContext.Provider>
  );
};