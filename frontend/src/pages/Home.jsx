import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import Layout from '../components/Layout';
import '../styles/home.css';
import scannerService from '../services/scannerService';

const Home = () => {
  const navigate = useNavigate();
  const [scanUrl, setScanUrl] = useState('');
  const [isScanActive, setIsScanActive] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [currentStage, setCurrentStage] = useState('');
  const [recentScans, setRecentScans] = useState([]);
  const [error, setError] = useState(null);

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
      // Start the scan
      const result = await scannerService.startScan(scanUrl, ['owasp', 'nuclei', 'wapiti'], {
        enable_ai_analysis: true,
        enable_mitre_mapping: true,
        include_low_risk: true
      });
      
      const scanId = result.scan_id;

      // Setup WebSocket for real-time updates
      scannerService.setupWebSocket(scanId, {
        onProgress: (status) => {
          setScanProgress(status.progress || 0);
          setCurrentStage(status.current_stage || 'Processing');
        },
        onComplete: (results) => {
          setScanProgress(100);
          setCurrentStage('Completed');
          setIsScanActive(false);
          // Navigate to results page
          setTimeout(() => navigate(`/scan/${scanId}`), 500);
        },
        onError: (error) => {
          console.error('WebSocket error:', error);
          setError('Connection error during scan');
          setIsScanActive(false);
        },
        onClose: () => {
          console.log('WebSocket connection closed');
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

  return (
    <Layout>
      <div className="home">
        {/* Navigation Bar */}
        <nav className="navbar">
          <div className="navbar-logo">LL</div>
          <ul className="navbar-menu">
            <li><a href="#console">Console</a></li>
            <li><a href="#history">History</a></li>
            <li><a href="#intelligence">Intelligence</a></li>
            <li><a href="mailto:hello@linkload.app">Contact</a></li>
          </ul>
        </nav>

        {/* Title Section */}
        <section className="title-section">
          <div className="logo-title">
            <h1 className="project-title">Link&Load</h1>
            <p className="subtitle">AI-Powered Security Scanning Platform</p>
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

        {/* Executive Summary */}
        <section className="summary-section" id="intelligence">
          <div className="heading-section">
            <h2 className="large-heading">Proactive</h2>
            <h2 className="large-heading">Threat</h2>
            <h2 className="large-heading">Intelligence</h2>
            <p className="heading-description">
              Transform vulnerability data into actionable intelligence with
              our AI-powered analysis and decision support system.
            </p>
          </div>
        </section>
      </div>
    </Layout>
  );
};

export default Home;
