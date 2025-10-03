import React, { useState, useEffect } from "react";
import { NavLink, useNavigate, useLocation } from "react-router-dom";
import {
  ScanSearch,
  Bug,
  Wrench,
  ShieldQuestion,
  Map,
  ShieldAlert,
  Menu,
  X,
  User,
  LogOut
} from "lucide-react";
import { useAuth } from "../context/AuthContext";
import "./TopNav.css";

export default function TopNav() {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [profileMenuOpen, setProfileMenuOpen] = useState(false);
  const location = useLocation();
  const navigate = useNavigate();
  const { user, isAuthenticated, logout } = useAuth();
  
  const navItems = [
    { name: "Link Scanner", path: "/link-scanner", icon: ScanSearch },
    { name: "Vulnerability", path: "/vulnerability-scanner", icon: Bug },
    { name: "Remediation", path: "/remediation", icon: Wrench },
    { name: "Phishing", path: "/phishing-detector", icon: ShieldQuestion },
    { name: "Attack Surface", path: "/attack-surface", icon: Map },
    { name: "OWASP", path: "/owasp-scanner", icon: ShieldAlert },
  ];

  // Close menus when route changes
  useEffect(() => {
    setMobileMenuOpen(false);
    setProfileMenuOpen(false);
  }, [location]);

  // Close profile menu when clicking outside
  useEffect(() => {
    const handleClickOutside = (e) => {
      if (profileMenuOpen && !e.target.closest('.profile-menu-container')) {
        setProfileMenuOpen(false);
      }
    };
    document.addEventListener('click', handleClickOutside);
    return () => document.removeEventListener('click', handleClickOutside);
  }, [profileMenuOpen]);

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  return (
    <header className="top-nav">
      <div className="top-nav-container">
        {/* Logo */}
        <div className="top-nav-logo" onClick={() => navigate('/link-scanner')}>
          <div className="logo-icon">LL</div>
          <span className="logo-text">Link&Load</span>
        </div>

        {/* Desktop Navigation */}
        <nav className="top-nav-links">
          {navItems.map(({ name, path, icon: Icon }) => (
            <NavLink
              key={path}
              to={path}
              className={({ isActive }) =>
                `nav-link ${isActive ? 'nav-link-active' : ''}`
              }
            >
              <Icon size={18} />
              <span>{name}</span>
            </NavLink>
          ))}
        </nav>

        {/* User Actions */}
        <div className="top-nav-actions">
          {isAuthenticated ? (
            <div className="profile-menu-container">
              <button 
                className="profile-button"
                onClick={() => setProfileMenuOpen(!profileMenuOpen)}
              >
                <User size={18} />
                <span className="profile-name">
                  {user?.name || user?.email?.split('@')[0] || 'User'}
                </span>
              </button>
              
              {profileMenuOpen && (
                <div className="profile-dropdown">
                  <div className="profile-dropdown-header">
                    <div className="profile-avatar">
                      {(user?.name || user?.email)?.[0]?.toUpperCase()}
                    </div>
                    <div className="profile-info">
                      <div className="profile-dropdown-name">
                        {user?.name || 'User'}
                      </div>
                      <div className="profile-dropdown-email">
                        {user?.email}
                      </div>
                    </div>
                  </div>
                  <div className="profile-dropdown-divider"></div>
                  <button 
                    className="profile-dropdown-item"
                    onClick={() => navigate('/profile')}
                  >
                    <User size={16} />
                    Profile Settings
                  </button>
                  <button 
                    className="profile-dropdown-item logout"
                    onClick={handleLogout}
                  >
                    <LogOut size={16} />
                    Logout
                  </button>
                </div>
              )}
            </div>
          ) : (
            <div className="auth-buttons">
              <button 
                className="btn btn-ghost btn-sm"
                onClick={() => navigate('/login')}
              >
                Login
              </button>
              <button 
                className="btn btn-primary btn-sm"
                onClick={() => navigate('/register')}
              >
                Get Started
              </button>
            </div>
          )}

          {/* Mobile Menu Toggle */}
          <button 
            className="mobile-menu-toggle"
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            aria-label="Toggle menu"
          >
            {mobileMenuOpen ? <X size={24} /> : <Menu size={24} />}
          </button>
        </div>
      </div>

      {/* Mobile Menu */}
      {mobileMenuOpen && (
        <div className="mobile-menu">
          <nav className="mobile-nav-links">
            {navItems.map(({ name, path, icon: Icon }) => (
              <NavLink
                key={path}
                to={path}
                className={({ isActive }) =>
                  `mobile-nav-link ${isActive ? 'mobile-nav-link-active' : ''}`
                }
              >
                <Icon size={20} />
                <span>{name}</span>
              </NavLink>
            ))}
          </nav>
          
          {isAuthenticated && (
            <div className="mobile-menu-footer">
              <button 
                className="btn btn-secondary"
                onClick={() => navigate('/profile')}
                style={{ width: '100%', marginBottom: '8px' }}
              >
                <User size={18} />
                Profile
              </button>
              <button 
                className="btn btn-ghost"
                onClick={handleLogout}
                style={{ width: '100%' }}
              >
                <LogOut size={18} />
                Logout
              </button>
            </div>
          )}
        </div>
      )}
    </header>
  );
}