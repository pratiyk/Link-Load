import React, { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import Layout from '../components/Layout';
import scannerService from '../services/scannerService';
import './ScanResults.css';

const ScanResults = () => {
  const { scanId } = useParams();
  const navigate = useNavigate();
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [activeTab, setActiveTab] = useState('overview');

  useEffect(() => {
    const fetchResults = async () => {
      try {
        const data = await scannerService.getScanResults(scanId);
        setResults(data);
      } catch (error) {
        setError(error.message);
      } finally {
        setLoading(false);
      }
    };

    fetchResults();
  }, [scanId]);

  if (loading) {
    return (
      <Layout>
        <div className="loading-container">
          <div className="loader"></div>
          <p>Loading scan results...</p>
        </div>
      </Layout>
    );
  }

  if (error) {
    return (
      <Layout>
        <div className="error-container">
          <h2>Error Loading Results</h2>
          <p>{error}</p>
          <button onClick={() => navigate('/')}>Back to Home</button>
        </div>
      </Layout>
    );
  }

  if (!results) {
    return (
      <Layout>
        <div className="error-container">
          <h2>No Results Found</h2>
          <button onClick={() => navigate('/')}>Back to Home</button>
        </div>
      </Layout>
    );
  }

  const renderRiskBadge = (level) => {
    const levelMap = {
      'Critical': 'critical',
      'High': 'high',
      'Medium': 'medium',
      'Low': 'low',
      'Minimal': 'minimal'
    };
    return `risk-badge ${levelMap[level] || 'unknown'}`;
  };

  const renderVulnerabilitySection = () => (
    <section className="results-section vulnerabilities">
      <h2>Vulnerabilities Found</h2>
      {results.vulnerabilities && results.vulnerabilities.length > 0 ? (
        <div className="vulnerability-list">
          {results.vulnerabilities.map((vuln, index) => (
            <div key={index} className={`vulnerability-card ${vuln.severity?.toLowerCase() || 'unknown'}`}>
              <div className="vuln-header">
                <h3>{vuln.title || 'Unknown Vulnerability'}</h3>
                <span className={`severity-badge ${vuln.severity?.toLowerCase() || 'unknown'}`}>
                  {vuln.severity || 'Unknown'}
                </span>
              </div>
              <p className="description">{vuln.description}</p>
              <div className="details">
                {vuln.cvss_score && (
                  <p><strong>CVSS Score:</strong> {vuln.cvss_score}</p>
                )}
                {vuln.location && (
                  <p><strong>Location:</strong> {vuln.location}</p>
                )}
              </div>
              {vuln.recommendation && (
                <div className="recommendation">
                  <h4>Recommendation:</h4>
                  <p>{vuln.recommendation}</p>
                </div>
              )}
              {vuln.mitre_techniques && vuln.mitre_techniques.length > 0 && (
                <div className="mitre-link">
                  <strong>MITRE Techniques:</strong> {vuln.mitre_techniques.join(', ')}
                </div>
              )}
            </div>
          ))}
        </div>
      ) : (
        <div className="no-results">
          <p>No vulnerabilities found. Great job!</p>
        </div>
      )}
    </section>
  );

  const renderMITRESection = () => (
    <section className="results-section mitre">
      <h2>MITRE ATT&CK Mapping</h2>
      {results.mitre_mapping && results.mitre_mapping.length > 0 ? (
        <div className="mitre-grid">
          {results.mitre_mapping.map((technique, index) => (
            <div key={index} className="mitre-card">
              <h3 className="technique-id">{technique.id}</h3>
              <p className="technique-name">{technique.name}</p>
              <p className="tactic">{technique.tactic}</p>
            </div>
          ))}
        </div>
      ) : (
        <div className="no-results">
          <p>No MITRE techniques mapped.</p>
        </div>
      )}
    </section>
  );

  const renderRiskSection = () => (
    <section className="results-section risk">
      <h2>Risk Assessment</h2>
      <div className="risk-summary">
        <div className="risk-score-container">
          <div className="score-display">
            <div className="score-circle" style={{background: getRiskColor(results.risk_assessment?.overall_risk_score)}}>
              {results.risk_assessment?.overall_risk_score?.toFixed(1) || 'N/A'}
            </div>
            <p className="score-label">Overall Risk Score</p>
          </div>
          <div className="risk-level-display">
            <p className="risk-level-label">Risk Level:</p>
            <p className={`risk-level ${renderRiskBadge(results.risk_assessment?.risk_level)}`}>
              {results.risk_assessment?.risk_level || 'Unknown'}
            </p>
          </div>
        </div>
        
        <div className="vulnerability-stats">
          <h3>Vulnerability Breakdown</h3>
          <div className="stats-grid">
            <div className="stat-item critical">
              <span className="stat-number">{results.risk_assessment?.critical_count || 0}</span>
              <span className="stat-label">Critical</span>
            </div>
            <div className="stat-item high">
              <span className="stat-number">{results.risk_assessment?.high_count || 0}</span>
              <span className="stat-label">High</span>
            </div>
            <div className="stat-item medium">
              <span className="stat-number">{results.risk_assessment?.medium_count || 0}</span>
              <span className="stat-label">Medium</span>
            </div>
            <div className="stat-item low">
              <span className="stat-number">{results.risk_assessment?.low_count || 0}</span>
              <span className="stat-label">Low</span>
            </div>
          </div>
        </div>
      </div>
    </section>
  );

  const renderAIAnalysis = () => (
    <section className="results-section ai-analysis">
      <h2>AI-Powered Analysis</h2>
      {results.ai_analysis && results.ai_analysis.length > 0 ? (
        <div className="ai-insights">
          {results.ai_analysis.map((insight, index) => (
            <div key={index} className="insight-card">
              <h3>{insight.title}</h3>
              <p>{insight.description}</p>
              {insight.recommendations && insight.recommendations.length > 0 && (
                <div className="recommendations">
                  <h4>Recommendations:</h4>
                  <ul>
                    {insight.recommendations.map((rec, i) => (
                      <li key={i}>{rec}</li>
                    ))}
                  </ul>
                </div>
              )}
              {insight.remediation_priority && (
                <p className="priority"><strong>Priority:</strong> {insight.remediation_priority}</p>
              )}
            </div>
          ))}
        </div>
      ) : (
        <div className="no-results">
          <p>No AI analysis available.</p>
        </div>
      )}
    </section>
  );

  const getRiskColor = (score) => {
    if (!score) return '#999';
    if (score >= 8) return '#ff4444';
    if (score >= 6) return '#ff8800';
    if (score >= 4) return '#ffbb33';
    if (score >= 2) return '#00C851';
    return '#2db92d';
  };

  return (
    <Layout>
      <div className="scan-results-container">
        <header className="results-header">
          <div className="header-content">
            <h1>Scan Results</h1>
            <button className="back-button" onClick={() => navigate('/')}>← Back to Home</button>
          </div>
          <div className="scan-info">
            <p><strong>Target:</strong> {results.target_url}</p>
            <p><strong>Scan ID:</strong> <code>{scanId}</code></p>
            {results.started_at && (
              <p><strong>Started:</strong> {new Date(results.started_at).toLocaleString()}</p>
            )}
            {results.completed_at && (
              <p><strong>Completed:</strong> {new Date(results.completed_at).toLocaleString()}</p>
            )}
            <p><strong>Status:</strong> <span className="status-badge">{results.status}</span></p>
          </div>
        </header>

        <div className="tabs-container">
          <button 
            className={`tab ${activeTab === 'overview' ? 'active' : ''}`}
            onClick={() => setActiveTab('overview')}
          >
            Overview
          </button>
          <button 
            className={`tab ${activeTab === 'vulnerabilities' ? 'active' : ''}`}
            onClick={() => setActiveTab('vulnerabilities')}
          >
            Vulnerabilities
          </button>
          <button 
            className={`tab ${activeTab === 'mitre' ? 'active' : ''}`}
            onClick={() => setActiveTab('mitre')}
          >
            MITRE Mapping
          </button>
          <button 
            className={`tab ${activeTab === 'ai' ? 'active' : ''}`}
            onClick={() => setActiveTab('ai')}
          >
            AI Analysis
          </button>
        </div>

        <div className="tabs-content">
          {activeTab === 'overview' && renderRiskSection()}
          {activeTab === 'vulnerabilities' && renderVulnerabilitySection()}
          {activeTab === 'mitre' && renderMITRESection()}
          {activeTab === 'ai' && renderAIAnalysis()}
        </div>
      </div>
    </Layout>
  );
};

export default ScanResults;