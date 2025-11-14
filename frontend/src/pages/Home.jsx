import React, { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import Layout from '../components/Layout';
import '../styles/home.css';
import scannerService from '../services/scannerService';
import logo from '../assets/logo.png';
import { useAuth } from '../context/AuthContext';

const Home = () => {
  const navigate = useNavigate();
  const { isAuthenticated, logout } = useAuth();
  const [scanUrl, setScanUrl] = useState('');
  const [isScanActive, setIsScanActive] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [currentStage, setCurrentStage] = useState('');
  const [recentScans, setRecentScans] = useState([]);
  const [error, setError] = useState(null);
  const [isMenuOpen, setIsMenuOpen] = useState(false);
  const accountMenuRef = useRef(null);

  useEffect(() => {
    // Load recent scans
    loadRecentScans();
  }, []);

  const loadRecentScans = async () => {
    try {
      const response = await scannerService.listScans(0, 5);
      setRecentScans(response.scans || []);
    } catch (error) {
      console.error('Failed to load recent scans:', error);
    }
  };

  const handleScan = async () => {
    if (!scanUrl.trim()) {
      setError('Please enter a valid URL');
      return;
    }

    setIsScanActive(true);
    setError(null);
    setScanProgress(0);
    setCurrentStage('Initializing...');

    try {
      console.log('Starting scan for URL:', scanUrl);

      // Start the scan
      const result = await scannerService.startScan(scanUrl, ['owasp', 'nuclei', 'wapiti'], {
        enable_ai_analysis: true,
        enable_mitre_mapping: true,
        include_low_risk: true
      });

      console.log('Scan started, response:', result);
      const scanId = result.scan_id;

      if (!scanId) {
        throw new Error('No scan ID returned from backend');
      }

      console.log('Setting up WebSocket for scan:', scanId);

      // Create a timeout for WebSocket connection
      let websocketConnected = false;
      let scanCompleted = false;
      const wsTimeout = setTimeout(() => {
        if (!websocketConnected && !scanCompleted) {
          console.warn('WebSocket did not connect within 5 seconds');
          setError('Scan started but lost connection. Check console for details.');
          setIsScanActive(false);
        }
      }, 5000);

      // Setup WebSocket for real-time updates
      scannerService.setupWebSocket(scanId, {
        onOpen: () => {
          console.log('WebSocket connected for scan:', scanId);
          websocketConnected = true;
          clearTimeout(wsTimeout);
        },
        onProgress: (status) => {
          console.log('Scan progress:', status);
          setScanProgress(status.progress || 0);
          setCurrentStage(status.current_stage || 'Processing');
        },
        onComplete: (results) => {
          console.log('Scan completed:', results);
          scanCompleted = true;
          clearTimeout(wsTimeout);
          setScanProgress(100);
          setCurrentStage('Completed');
          setIsScanActive(false);
          // Navigate to results page
          setTimeout(() => navigate(`/scan/${scanId}`), 500);
        },
        onError: (error) => {
          console.error('WebSocket error:', error);
          clearTimeout(wsTimeout);
          setError('Connection error during scan. Please check the browser console.');
          setIsScanActive(false);
        },
        onClose: () => {
          console.log('WebSocket connection closed for scan:', scanId);
          clearTimeout(wsTimeout);
          if (!scanCompleted) {
            // WebSocket closed without completion - this might be expected if scan is still running
            console.log('WebSocket closed but scan may still be running. Scan ID:', scanId);
          }
        }
      });
    } catch (error) {
      console.error('Scan failed:', error);
      setError(error.message || 'Failed to start scan');
      setIsScanActive(false);
    }
  };

  const handleScanFromHistory = (scanId) => {
    navigate(`/scan/${scanId}`);
  };

  const handleKeyPress = (e) => {
    if (e.key === 'Enter' && !isScanActive) {
      handleScan();
    }
  };

  useEffect(() => {
    const handleDocumentClick = (event) => {
      if (accountMenuRef.current && !accountMenuRef.current.contains(event.target)) {
        setIsMenuOpen(false);
      }
    };

    const handleEscape = (event) => {
      if (event.key === 'Escape') {
        setIsMenuOpen(false);
      }
    };

    document.addEventListener('mousedown', handleDocumentClick);
    document.addEventListener('keydown', handleEscape);

    return () => {
      document.removeEventListener('mousedown', handleDocumentClick);
      document.removeEventListener('keydown', handleEscape);
    };
  }, []);

  useEffect(() => {
    if (!isAuthenticated) {
      setIsMenuOpen(false);
    }
  }, [isAuthenticated]);

  const handleNavigate = (path) => {
    setIsMenuOpen(false);
    navigate(path);
  };

  const handleLogout = async () => {
    setIsMenuOpen(false);
    try {
      await logout();
    } finally {
      navigate('/login');
    }
  };

  return (
    <Layout>
      <div className="home">
        {/* Navigation Bar */}
        <nav className="navbar">
          <div className="navbar-logo"></div>
          <ul className="navbar-menu">
            {isAuthenticated ? (
              <li className="navbar-menu__item navbar-menu__item--account" ref={accountMenuRef}>
                <button
                  type="button"
                  className="account-trigger"
                  aria-haspopup="true"
                  aria-expanded={isMenuOpen}
                  onClick={() => setIsMenuOpen((previous) => !previous)}
                >
                  <span className="account-trigger__label">Account</span>
                  <span className="account-trigger__chevron" aria-hidden="true">v</span>
                </button>
                <div
                  className={`account-dropdown ${isMenuOpen ? 'account-dropdown--open' : ''}`}
                  role="menu"
                >
                  <button
                    type="button"
                    className="account-dropdown__item"
                    onClick={() => handleNavigate('/settings/profile')}
                    role="menuitem"
                  >
                    Profile settings
                  </button>
                  <button
                    type="button"
                    className="account-dropdown__item"
                    onClick={() => handleNavigate('/settings/verification')}
                    role="menuitem"
                  >
                    DNS verification
                  </button>
                  <hr className="account-dropdown__divider" />
                  <button
                    type="button"
                    className="account-dropdown__item account-dropdown__item--danger"
                    onClick={handleLogout}
                    role="menuitem"
                  >
                    Sign out
                  </button>
                </div>
              </li>
            ) : (
              <li className="navbar-menu__item navbar-menu__item--cta">
                <a className="navbar-link--cta" href="/login">Login / Register</a>
              </li>
            )}
          </ul>
        </nav>

        {/* Title Section */}
        <section className="title-section">
          <div className="logo-title">
            <img src={logo} alt="Link&Load Logo" className="home-logo" />
            <h1 className="project-title">Link&Load</h1>
            <p className="subtitle">Link. Load. Defend. Repeat.</p>
          </div>
        </section>

        {/* Hero Section */}
        <section className="hero-section" id="console">
          <div className="game-console">
            <div className="game-screen">
              <div className="screen-content">
                {isScanActive ? (
                  <div className="scanning-view">
                    <div className={`glitch-text scanning`}>
                      SCANNING IN PROGRESS
                    </div>
                    <div className="progress-bar">
                      <div className="progress-fill" style={{ width: `${scanProgress}%` }}></div>
                    </div>
                    <div className="progress-text">
                      <span className="progress-value">{scanProgress}%</span>
                      <span className="progress-stage">{currentStage}</span>
                    </div>
                  </div>
                ) : (
                  <div className={`glitch-text ${scanUrl ? 'ready' : ''}`}>
                    {scanUrl ? 'READY TO SCAN' : 'PRESS START SCAN'}
                  </div>
                )}
              </div>
            </div>

            <div className="scan-controls">
              <input
                type="url"
                value={scanUrl}
                onChange={(e) => setScanUrl(e.target.value)}
                onKeyPress={handleKeyPress}
                placeholder="Enter target URL (e.g., https://example.com)"
                className="scan-input"
                disabled={isScanActive}
              />
              <button
                onClick={handleScan}
                className="scan-button"
                disabled={isScanActive || !scanUrl.trim()}
              >
                {isScanActive ? 'SCANNING...' : 'START SCAN'}
              </button>
            </div>

            {error && (
              <div className="error-message">
                {error}
              </div>
            )}
          </div>
        </section>

        {/* Recent Scans Section */}
        {recentScans.length > 0 && (
          <section className="recent-scans-section" id="history">
            <h2 className="section-title">Recent Scans</h2>
            <div className="recent-scans-list">
              {recentScans.map((scan) => (
                <div
                  key={scan.scan_id}
                  className="recent-scan-item"
                  onClick={() => handleScanFromHistory(scan.scan_id)}
                >
                  <div className="scan-info">
                    <div className="scan-url">{scan.target_url}</div>
                    <div className="scan-meta">
                      {scan.status && (
                        <span className={`status-badge ${scan.status}`}>
                          {scan.status.toUpperCase()}
                        </span>
                      )}
                      {scan.started_at && (
                        <span className="scan-time">
                          {new Date(scan.started_at).toLocaleDateString()}
                        </span>
                      )}
                    </div>
                  </div>
                  <div className="scan-arrow">→</div>
                </div>
              ))}
            </div>
          </section>
        )}

        {/* Features Section */}
        <section className="features-section" id="features">
          <div className="features-header">
            <h4 className="section-title-large">Hack No More</h4>
            <p className="section-subtitle">Link fast. Load smart. Defend stronger. Hackers? Not anymore.</p>
          </div>

          <div className="features-grid">
            <div className="feature-card card-coral">
              <div className="feature-number">01</div>
              <h3>OWASP ZAP</h3>
              <p>Industry-standard dynamic application security testing with comprehensive vulnerability scanning</p>
              <div className="feature-badge">Active</div>
            </div>

            <div className="feature-card card-blue">
              <div className="feature-number">02</div>
              <h3>Nuclei Templates</h3>
              <p>Fast and customizable vulnerability scanner with community-driven templates</p>
              <div className="feature-badge">Active</div>
            </div>

            <div className="feature-card card-green">
              <div className="feature-number">03</div>
              <h3>Wapiti Scanner</h3>
              <p>Web application vulnerability scanner detecting injection flaws and configuration issues</p>
              <div className="feature-badge">Active</div>
            </div>

            <div className="feature-card card-yellow">
              <div className="feature-number">04</div>
              <h3>AI Analysis</h3>
              <p>LLM-powered vulnerability analysis providing intelligent insights and remediation strategies</p>
              <div className="feature-badge">AI</div>
            </div>

            <div className="feature-card card-pink">
              <div className="feature-number">05</div>
              <h3>MITRE ATT&CK</h3>
              <p>Automated mapping of vulnerabilities to adversary tactics, techniques, and procedures</p>
              <div className="feature-badge">Intel</div>
            </div>

            <div className="feature-card card-coral">
              <div className="feature-number">06</div>
              <h3>Risk Assessment</h3>
              <p>Comprehensive risk scoring with business context and compliance framework alignment</p>
              <div className="feature-badge">Analytics</div>
            </div>
          </div>
        </section>


      </div>
    </Layout>
  );
};

export default Home;
