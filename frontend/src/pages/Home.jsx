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
  const [scanMode, setScanMode] = useState('standard'); // 'quick', 'standard', 'deep'
  const [showModeDetails, setShowModeDetails] = useState(false);
  const accountMenuRef = useRef(null);

  // Scan mode configurations with detailed feature breakdown
  const scanModes = {
    quick: {
      label: 'Quick',
      duration: '5-10 min',
      description: 'Full Nuclei scan with all templates and severity levels',
      scanners: ['nuclei'],
      timeout: 15,
      deep_scan: true,  // Enable deep scan for comprehensive Nuclei coverage
      include_low_risk: true,  // Include all severity levels including info
      features: [
        { name: 'CVE Detection', enabled: true, description: 'Known vulnerability scanning' },
        { name: 'Misconfigurations', enabled: true, description: 'Common security misconfigurations' },
        { name: 'Exposed Panels', enabled: true, description: 'Admin panels & dashboards' },
        { name: 'Tech Detection', enabled: true, description: 'Technology fingerprinting' },
        { name: 'SSL/TLS Analysis', enabled: true, description: 'Certificate and protocol checks' },
        { name: 'Headless Browser', enabled: true, description: 'JavaScript rendering for dynamic content' },
        { name: 'All Severity Levels', enabled: true, description: 'Critical, High, Medium, Low, Info' },
        { name: 'AI Analysis', enabled: true, description: 'AI-powered insights' },
        { name: 'MITRE Mapping', enabled: true, description: 'ATT&CK technique mapping' }
      ],
      bestFor: 'Fast comprehensive checks, CI/CD pipelines, quick assessments'
    },
    standard: {
      label: 'Standard',
      duration: '10-20 min',
      description: 'In-depth scan with Nuclei and Wapiti combined',
      scanners: ['nuclei', 'wapiti'],
      timeout: 30,
      deep_scan: true,  // Enable deep scan for both scanners
      include_low_risk: true,
      features: [
        { name: 'CVE Detection', enabled: true, description: 'Known vulnerability scanning' },
        { name: 'Misconfigurations', enabled: true, description: 'Common security misconfigurations' },
        { name: 'Exposed Panels', enabled: true, description: 'Admin panels & dashboards' },
        { name: 'Tech Detection', enabled: true, description: 'Technology fingerprinting' },
        { name: 'SSL/TLS Analysis', enabled: true, description: 'Certificate and protocol checks' },
        { name: 'SQL Injection', enabled: true, description: 'Database injection attacks' },
        { name: 'XSS Detection', enabled: true, description: 'Cross-site scripting' },
        { name: 'CSRF Detection', enabled: true, description: 'Cross-site request forgery' },
        { name: 'SSRF Detection', enabled: true, description: 'Server-side request forgery' },
        { name: 'Headless Browser', enabled: true, description: 'JavaScript rendering' },
        { name: 'AI Analysis', enabled: true, description: 'AI-powered insights' },
        { name: 'MITRE Mapping', enabled: true, description: 'ATT&CK technique mapping' }
      ],
      bestFor: 'Regular security assessments, pre-deployment checks, weekly scans'
    },
    deep: {
      label: 'Deep',
      duration: '20-45 min',
      description: 'Maximum coverage with all three scanners in-depth',
      scanners: ['owasp', 'nuclei', 'wapiti'],
      timeout: 60,
      deep_scan: true,
      include_low_risk: true,
      features: [
        { name: 'CVE Detection', enabled: true, description: 'Known vulnerability scanning' },
        { name: 'Misconfigurations', enabled: true, description: 'Common security misconfigurations' },
        { name: 'Exposed Panels', enabled: true, description: 'Admin panels & dashboards' },
        { name: 'Tech Detection', enabled: true, description: 'Technology fingerprinting' },
        { name: 'SSL/TLS Analysis', enabled: true, description: 'Certificate and protocol checks' },
        { name: 'SQL Injection', enabled: true, description: 'Database injection attacks' },
        { name: 'XSS Detection', enabled: true, description: 'Cross-site scripting' },
        { name: 'OWASP ZAP Active', enabled: true, description: 'Dynamic application testing' },
        { name: 'Spider Crawling', enabled: true, description: 'Deep site exploration' },
        { name: 'AJAX Spider', enabled: true, description: 'JavaScript app crawling' },
        { name: 'Authentication Tests', enabled: true, description: 'Login & session security' },
        { name: 'API Security', enabled: true, description: 'REST/GraphQL endpoint testing' },
        { name: 'XXE Detection', enabled: true, description: 'XML external entity attacks' },
        { name: 'Command Injection', enabled: true, description: 'OS command injection' },
        { name: 'File Inclusion', enabled: true, description: 'LFI/RFI vulnerabilities' },
        { name: 'AI Analysis', enabled: true, description: 'AI-powered insights' },
        { name: 'MITRE Mapping', enabled: true, description: 'ATT&CK technique mapping' }
      ],
      bestFor: 'Thorough security audits, compliance requirements, production assessments'
    }
  };

  useEffect(() => {
    // Load recent scans only if authenticated
    if (isAuthenticated) {
      loadRecentScans();
    } else {
      setRecentScans([]);
    }
  }, [isAuthenticated]);

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

      // Get scan configuration based on selected mode
      const modeConfig = scanModes[scanMode];

      // Start the scan with mode-specific settings
      const result = await scannerService.startScan(scanUrl, modeConfig.scanners, {
        enable_ai_analysis: true,
        enable_mitre_mapping: true,
        include_low_risk: modeConfig.include_low_risk,
        deep_scan: modeConfig.deep_scan,
        timeout_minutes: modeConfig.timeout
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
          console.warn('WebSocket did not connect within 15 seconds, polling for status...');
          // Don't show error immediately, try polling instead
          pollScanStatus(scanId);
        }
      }, 15000);

      // Polling fallback function
      const pollScanStatus = async (id) => {
        try {
          const status = await scannerService.getScanStatus(id);
          console.log('Polled scan status:', status);

          if (status.status === 'completed') {
            setScanProgress(100);
            setCurrentStage('Completed');
            setIsScanActive(false);
            navigate(`/scan/${id}`);
          } else if (status.status === 'failed' || status.status === 'cancelled') {
            setError(`Scan ${status.status}`);
            setIsScanActive(false);
          } else {
            setScanProgress(status.progress || 0);
            setCurrentStage(status.current_stage || 'Processing');
            // Continue polling
            setTimeout(() => pollScanStatus(id), 3000);
          }
        } catch (err) {
          console.error('Error polling scan status:', err);
          setError('Unable to get scan status. Please check the scan history.');
          setIsScanActive(false);
        }
      };

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

  const handleDeleteScan = async (scanId, e) => {
    e.stopPropagation(); // Prevent navigation when clicking delete
    if (window.confirm('Are you sure you want to permanently delete this scan? This action cannot be undone.')) {
      try {
        await scannerService.deleteScan(scanId);
        // Refresh the scan list
        loadRecentScans();
      } catch (error) {
        console.error('Failed to delete scan:', error);
        setError('Failed to delete scan: ' + error.message);
      }
    }
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
                  Account
                </button>
                <div
                  className={`account-dropdown ${isMenuOpen ? 'account-dropdown--open' : ''}`}
                  role="menu"
                >
                  <button
                    type="button"
                    className="account-dropdown__item"
                    onClick={() => handleNavigate('/profile')}
                    role="menuitem"
                  >
                    Profile
                  </button>
                  <button
                    type="button"
                    className="account-dropdown__item"
                    onClick={() => handleNavigate('/settings/verification')}
                    role="menuitem"
                  >
                    DNS TXT verification
                  </button>
                  <hr className="account-dropdown__divider" />
                  <button
                    type="button"
                    className="account-dropdown__item account-dropdown__item--danger"
                    onClick={handleLogout}
                    role="menuitem"
                  >
                    Log out
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
                ) : !isAuthenticated ? (
                  <div className="auth-prompt-screen">
                    Sign in to start scan
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

              {/* Scan Mode Selector */}
              {isAuthenticated && !isScanActive && (
                <div className="scan-mode-container">
                  <div className="scan-mode-header">
                    <span className="scan-mode-title">Scan Depth</span>
                    <button
                      type="button"
                      className="scan-mode-info-btn"
                      onClick={() => setShowModeDetails(!showModeDetails)}
                      title="Peek scan details"
                    >
                      {showModeDetails ? 'Close' : 'Peek'}
                    </button>
                  </div>

                  <div className="scan-mode-selector">
                    {Object.entries(scanModes).map(([mode, config]) => (
                      <button
                        key={mode}
                        type="button"
                        className={`scan-mode-btn ${scanMode === mode ? 'active' : ''}`}
                        onClick={() => setScanMode(mode)}
                        title={config.description}
                      >
                        <span className="mode-label">{config.label}</span>
                        <span className="mode-time">{config.duration}</span>
                      </button>
                    ))}
                  </div>

                  {/* Expanded Mode Details */}
                  {showModeDetails && (
                    <div className="scan-mode-details">
                      <div className="mode-details-header">
                        <div className="mode-details-badge">{scanModes[scanMode].label}</div>
                        <div className="mode-details-title">
                          <h4>{scanModes[scanMode].label} Scan</h4>
                          <p>{scanModes[scanMode].description}</p>
                        </div>
                      </div>

                      <div className="mode-details-scanners">
                        <span className="scanners-label">Scanners:</span>
                        <div className="scanners-tags">
                          {scanModes[scanMode].scanners.map(scanner => (
                            <span key={scanner} className={`scanner-tag scanner-${scanner}`}>
                              {scanner === 'owasp' ? 'OWASP ZAP' :
                                scanner === 'nuclei' ? 'Nuclei' :
                                  scanner === 'wapiti' ? 'Wapiti' : scanner}
                            </span>
                          ))}
                        </div>
                      </div>

                      <div className="mode-features-grid">
                        {scanModes[scanMode].features.map((feature, idx) => (
                          <div
                            key={idx}
                            className={`mode-feature ${feature.enabled ? 'enabled' : 'disabled'}`}
                            title={feature.description}
                          >
                            <span className="feature-status">{feature.enabled ? 'YES' : 'NO'}</span>
                            <span className="feature-name">{feature.name}</span>
                          </div>
                        ))}
                      </div>

                      <div className="mode-best-for">
                        <span className="best-for-label">Best for:</span>
                        <span className="best-for-text">{scanModes[scanMode].bestFor}</span>
                      </div>
                    </div>
                  )}
                </div>
              )}

              <button
                onClick={handleScan}
                className="scan-button"
                disabled={isScanActive || !scanUrl.trim() || !isAuthenticated}
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

        {/* Recent Scans Section - Always visible for authenticated users */}
        {isAuthenticated && (
          <section className="recent-scans-section" id="history">
            <h2 className="section-title">Recent Scans</h2>
            {recentScans.length > 0 ? (
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
                    <div className="scan-actions">
                      <button
                        className="delete-scan-btn"
                        onClick={(e) => handleDeleteScan(scan.scan_id, e)}
                        title="Delete scan permanently"
                      >
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                          <polyline points="3 6 5 6 21 6"></polyline>
                          <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
                          <line x1="10" y1="11" x2="10" y2="17"></line>
                          <line x1="14" y1="11" x2="14" y2="17"></line>
                        </svg>
                      </button>
                      <div className="scan-arrow">→</div>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="no-scans-message">
                <p>No territory charted yet. Launch your first reconnaissance scan to map the landscape and uncover hidden treasures... or threats.</p>
              </div>
            )}
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
