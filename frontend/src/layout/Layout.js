import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { motion } from 'framer-motion';

const Layout = ({ children }) => {
  const { isAuthenticated, logout } = useAuth();
  const location = useLocation();

  return (
    <div className="flex flex-col min-h-screen bg-gradient-to-br from-gray-900 to-black text-white">
      <nav className="backdrop-blur-lg bg-black bg-opacity-50 border-b border-gray-800">
        <div className="container mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <Link to="/" className="text-2xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-blue-400 to-purple-500">
              Link&Load
            </Link>
            
            <div className="flex items-center space-x-6">
              {isAuthenticated ? (
                <>
                  <motion.div whileHover={{ scale: 1.05 }}>
                    <Link 
                      to="/vulnerability-scanner"
                      className={`text-sm font-medium ${
                        location.pathname === '/vulnerability-scanner' 
                        ? 'text-blue-400' 
                        : 'text-gray-300 hover:text-white'
                      }`}
                    >
                      Scanner
                    </Link>
                  </motion.div>
                  <motion.div whileHover={{ scale: 1.05 }}>
                    <Link 
                      to="/profile"
                      className={`text-sm font-medium ${
                        location.pathname === '/profile' 
                        ? 'text-blue-400' 
                        : 'text-gray-300 hover:text-white'
                      }`}
                    >
                      Profile
                    </Link>
                  </motion.div>
                  <motion.button
                    whileHover={{ scale: 1.05 }}
                    onClick={logout}
                    className="text-sm font-medium text-gray-300 hover:text-white"
                  >
                    Logout
                  </motion.button>
                </>
              ) : (
                <>
                  <motion.div whileHover={{ scale: 1.05 }}>
                    <Link 
                      to="/login"
                      className="text-sm font-medium text-gray-300 hover:text-white"
                    >
                      Login
                    </Link>
                  </motion.div>
                  <motion.div whileHover={{ scale: 1.05 }}>
                    <Link 
                      to="/register"
                      className="px-4 py-2 rounded-full text-sm font-medium bg-gradient-to-r from-blue-500 to-purple-600 hover:opacity-90 transition-opacity"
                    >
                      Get Started
                    </Link>
                  </motion.div>
                </>
              )}
            </div>
          </div>
        </div>
      </nav>
      
      <main className="flex-grow container mx-auto px-4 py-8">
        {children}
      </main>
      
      <footer className="backdrop-blur-lg bg-black bg-opacity-50 border-t border-gray-800">
        <div className="container mx-auto px-6 py-4">
          <div className="flex justify-between items-center">
            <p className="text-sm text-gray-400">
              © {new Date().getFullYear()} Link&Load. All rights reserved.
            </p>
            <div className="flex space-x-6">
              <a href="#" className="text-sm text-gray-400 hover:text-white">Privacy</a>
              <a href="#" className="text-sm text-gray-400 hover:text-white">Terms</a>
              <a href="#" className="text-sm text-gray-400 hover:text-white">Support</a>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default Layout;
