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
    const [isAuthenticated, setIsAuthenticated] = useState(false);

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
                    setIsAuthenticated(true);
                } else {
                    setIsAuthenticated(false);
                }
            } catch (error) {
                console.error('Auth error:', error);
                setUser(null);
                setIsAuthenticated(false);
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
            setIsAuthenticated(true);
            return { success: true, user: mockResponse.user };
        } catch (error) {
            console.error('Login error:', error);
            return { success: false, error: error.message || 'Login failed' };
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
            setIsAuthenticated(true);
            return { success: true, user: mockResponse.user };
        } catch (error) {
            console.error('Registration error:', error);
            return { success: false, error: error.message || 'Registration failed' };
        }
    };

    const logout = () => {
        localStorage.removeItem('token');
        setUser(null);
        setIsAuthenticated(false);
    };

    const updateProfile = async (userData) => {
        try {
            // TODO: Implement actual profile update API call
            setUser((prev) => ({ ...prev, ...userData }));
            return { success: true };
        } catch (error) {
            console.error('Profile update error:', error);
            return { success: false, error: error.message || 'Profile update failed' };
        }
    };

    const changePassword = async (currentPassword, newPassword) => {
        try {
            // TODO: Implement password change API call
            return { success: true };
        } catch (error) {
            console.error('Password change error:', error);
            return { success: false, error: error.message || 'Password change failed' };
        }
    };

    const value = {
        user,
        loading,
        isAuthenticated,
        login,
        register,
        logout,
        updateProfile,
        changePassword
    };

    return (
        <AuthContext.Provider value={value}>
            {!loading && children}
        </AuthContext.Provider>
    );
};