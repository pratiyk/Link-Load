import axios from 'axios';

const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';

export const authApi = {
  login: async (email, password) => {
    try {
      const response = await axios.post(`${API_BASE_URL}/api/v1/auth/login`, {
        email,
        password
      });
      return response.data;
    } catch (error) {
      throw error.response?.data?.detail || 'Login failed';
    }
  },

  register: async (userData) => {
    try {
      const response = await axios.post(`${API_BASE_URL}/api/v1/auth/register`, userData);
      return response.data;
    } catch (error) {
      throw error.response?.data?.detail || 'Registration failed';
    }
  },

  getCurrentUser: async () => {
    try {
      const token = localStorage.getItem('access_token');
      const response = await axios.get(`${API_BASE_URL}/api/v1/auth/me`, {
        headers: {
          Authorization: `Bearer ${token}`
        }
      });
      return response.data;
    } catch (error) {
      throw error.response?.data?.detail || 'Failed to get user';
    }
  },

  logout: async () => {
    try {
      const token = localStorage.getItem('access_token');
      await axios.post(`${API_BASE_URL}/api/v1/auth/logout`, {}, {
        headers: {
          Authorization: `Bearer ${token}`
        }
      });
    } catch (error) {
      console.error('Logout error:', error);
    }
  },

  refreshToken: async (refreshToken) => {
    try {
      const response = await axios.post(`${API_BASE_URL}/api/v1/auth/refresh`, {
        refresh_token: refreshToken
      });
      return response.data;
    } catch (error) {
      throw error.response?.data?.detail || 'Token refresh failed';
    }
  },

  updateProfile: async (profileData) => {
    try {
      const token = localStorage.getItem('access_token');
      const response = await axios.put(`${API_BASE_URL}/api/v1/auth/me`, profileData, {
        headers: {
          Authorization: `Bearer ${token}`
        }
      });
      return response.data;
    } catch (error) {
      throw error.response?.data?.detail || 'Profile update failed';
    }
  },

  changePassword: async (currentPassword, newPassword) => {
    try {
      const token = localStorage.getItem('access_token');
      await axios.post(`${API_BASE_URL}/api/v1/auth/change-password`, {
        current_password: currentPassword,
        new_password: newPassword,
        confirm_new_password: newPassword
      }, {
        headers: {
          Authorization: `Bearer ${token}`
        }
      });
    } catch (error) {
      throw error.response?.data?.detail || 'Password change failed';
    }
  },

  forgotPassword: async (email) => {
    try {
      const response = await axios.post(`${API_BASE_URL}/api/v1/auth/forgot-password`, {
        email
      });
      return response.data;
    } catch (error) {
      throw error.response?.data?.detail || 'Failed to send reset email';
    }
  },

  resetPassword: async (token, newPassword) => {
    try {
      const response = await axios.post(`${API_BASE_URL}/api/v1/auth/reset-password`, {
        token,
        new_password: newPassword
      });
      return response.data;
    } catch (error) {
      throw error.response?.data?.detail || 'Password reset failed';
    }
  }
};