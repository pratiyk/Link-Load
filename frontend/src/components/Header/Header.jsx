import React from 'react';
import { Link, useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';
import './Header.css';

const Header = () => {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  const handleLogout = async () => {
    await logout();
    navigate('/login');
  };

  const isActive = (path) => {
    return location.pathname === path;
  };

  return (
    <header className="header">
      <div className="header-container">
        <Link to="/" className="logo">
          <img src="/assets/logo.svg" alt="Link&Load" className="logo-img" />
          <span className="logo-text">Link&Load</span>
        </Link>

        <nav className="nav-links">
          {user ? (
            <>
              <Link
                to="/vulnerability-scanner"
                className={`nav-link ${isActive('/vulnerability-scanner') ? 'active' : ''}`}
              >
                Scanner
              </Link>
              <Link
                to="/dashboard"
                className={`nav-link ${isActive('/dashboard') ? 'active' : ''}`}
              >
                Dashboard
              </Link>
              <div className="nav-right">
                <div className="user-menu">
                  <img
                    src={user.avatar || '/assets/default-avatar.svg'}
                    alt=""
                    className="user-avatar"
                  />
                  <div className="dropdown-menu">
                    <Link to="/profile" className="dropdown-item">
                      Profile
                    </Link>
                    <Link to="/settings" className="dropdown-item">
                      Settings
                    </Link>
                    <button onClick={handleLogout} className="dropdown-item">
                      Logout
                    </button>
                  </div>
                </div>
              </div>
            </>
          ) : (
            <div className="nav-right">
              <Link to="/login" className="nav-link">
                Login
              </Link>
              <Link to="/register" className="btn btn-primary">
                Get Started
              </Link>
            </div>
          )}
        </nav>
      </div>
    </header>
  );
};

export default Header;