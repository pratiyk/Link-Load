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

  // Color palette matching the presentation
  const colors = {
    cyan: '#6DD4D9',
    coral: '#FF6B6B',
    green: '#4CAF91',
    pink: '#E39FCE',
    yellow: '#FFD93D'
  };

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

  const renderVulnerabilitySection = () => {
    const vulns = results.vulnerabilities || [];
    const colorMap = ['cyan', 'coral', 'green', 'pink', 'yellow'];

    return (
      <section className="results-section detailed-outline">
        <div className="section-header-box yellow">
          <h2>Detailed Outline</h2>
          <div className="count-badge">{vulns.length}</div>
        </div>
        {vulns.length > 0 ? (
          <div className="timeline-grid">
            {vulns.map((vuln, index) => {
              const colorKey = colorMap[index % colorMap.length];
              return (
                <div key={index} className={`timeline-item ${colorKey}-bg`}>
                  <div className="timeline-marker">
                    <div className="marker-label">{index + 1}</div>
                  </div>
                  <div className="timeline-content">
                    <div className="timeline-time">
                      <span className="severity-badge ${vuln.severity?.toLowerCase()}">
                        {vuln.severity || 'Unknown'}
                      </span>
                    </div>
                    <h3 className="timeline-title">{vuln.title || 'Unknown Vulnerability'}</h3>
                    <p className="timeline-desc">{vuln.description || 'No description available'}</p>
                    {vuln.cvss_score && (
                      <div className="timeline-meta">
                        <strong>CVSS:</strong> {vuln.cvss_score}
                      </div>
                    )}
                    {vuln.location && (
                      <div className="timeline-meta">
                        <strong>Location:</strong> {vuln.location}
                      </div>
                    )}
                    {vuln.recommendation && (
                      <div className="timeline-recommendation">
                        <strong>Fix:</strong> {vuln.recommendation}
                      </div>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        ) : (
          <div className="no-results">
            <p>✓ No vulnerabilities found. Your application is secure!</p>
          </div>
        )}
      </section>
    );
  };

  const renderMITRESection = () => {
    const techniques = results.mitre_mapping || [];

    return (
      <section className="results-section mitre-section">
        <div className="section-header-box green">
          <h2>MITRE ATT&CK Mapping</h2>
          <div className="count-badge">{techniques.length}</div>
        </div>

        {techniques.length > 0 ? (
          <div className="key-features-grid">
            {techniques.map((technique, index) => (
              <div key={index} className="feature-note">
                <div className="note-header">
                  <h3>Technique {index + 1}:</h3>
                </div>
                <div className="note-content">
                  <div className="technique-id-display">{technique.id || 'N/A'}</div>
                  <h4>{technique.name || 'Unknown Technique'}</h4>
                  <p className="tactic-label">Tactic: <span>{technique.tactic || 'Not specified'}</span></p>
                  {technique.description && (
                    <p className="technique-desc">{technique.description}</p>
                  )}
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="no-results">
            <p>No MITRE ATT&CK techniques mapped for this scan.</p>
          </div>
        )}
      </section>
    );
  };

  const renderRiskSection = () => {
    const risk = results.risk_assessment || {};
    const vulns = results.vulnerabilities || [];

    const overviewItems = [
      {
        number: 1,
        title: 'Critical Issues',
        content: `Found ${risk.critical_count || 0} critical vulnerabilities that require immediate attention. These represent the highest security risks.`,
        color: 'cyan'
      },
      {
        number: 2,
        title: 'High Priority',
        content: `Identified ${risk.high_count || 0} high-severity issues. These should be addressed in the next sprint to prevent potential exploits.`,
        color: 'coral'
      },
      {
        number: 3,
        title: 'Medium Risk',
        content: `Detected ${risk.medium_count || 0} medium-severity vulnerabilities. Schedule remediation within the next quarter.`,
        color: 'green'
      },
      {
        number: 4,
        title: 'Low Risk',
        content: `Found ${risk.low_count || 0} low-severity issues. Address these during regular maintenance cycles.`,
        color: 'pink'
      },
      {
        number: 5,
        title: 'Overall Score',
        content: `Risk score of ${risk.overall_risk_score?.toFixed(1) || 'N/A'}/10 indicates ${risk.risk_level || 'Unknown'} risk level. ${vulns.length} total findings across all categories.`,
        color: 'yellow'
      }
    ];

    return (
      <section className="results-section overview">
        <div className="section-header-box pink">
          <h2>Overview</h2>
          <div className="count-badge">{risk.vulnerability_count || vulns.length}</div>
        </div>

        <div className="overview-grid">
          {overviewItems.map((item) => (
            <div key={item.number} className={`overview-card ${item.color}-bg`}>
              <div className="card-number">{item.number}.</div>
              <h3 className="card-title">{item.title}</h3>
              <p className="card-content">{item.content}</p>
            </div>
          ))}
        </div>

        <div className="risk-score-display">
          <div className="score-circle-large" style={{ background: getRiskColor(risk.overall_risk_score) }}>
            {risk.overall_risk_score?.toFixed(1) || 'N/A'}
          </div>
          <div className="risk-label">{risk.risk_level || 'Unknown'} Risk Level</div>
        </div>
      </section>
    );
  };

  const renderAIAnalysis = () => {
    const aiInsights = results.ai_analysis || [];
    const vulns = results.vulnerabilities || [];

    // Create remediation timeline based on severity
    const criticalVulns = vulns.filter(v => v.severity?.toLowerCase() === 'critical');
    const highVulns = vulns.filter(v => v.severity?.toLowerCase() === 'high');
    const mediumVulns = vulns.filter(v => v.severity?.toLowerCase() === 'medium');
    const lowVulns = vulns.filter(v => v.severity?.toLowerCase() === 'low');

    const timelineData = [
      { label: 'Immediate Action', items: criticalVulns, color: 'cyan', start: 0, duration: 7 },
      { label: 'Next Sprint', items: highVulns, color: 'coral', start: 7, duration: 21 },
      { label: 'This Quarter', items: mediumVulns, color: 'pink', start: 14, duration: 60 },
      { label: 'Maintenance', items: lowVulns, color: 'yellow', start: 60, duration: 30 }
    ];

    return (
      <section className="results-section ai-timeframes">
        <div className="section-header-box coral">
          <h2>Remediation Timeframes</h2>
          <div className="count-badge">{vulns.length}</div>
        </div>

        <div className="gantt-container">
          <div className="gantt-header">
            <div className="gantt-row-label">Priority Level</div>
            {[...Array(12)].map((_, i) => {
              const weekNum = i * 7;
              return (
                <div key={i} className="gantt-time-label">
                  <span className="month-label">Week</span>
                  <span className="day-label">{weekNum}</span>
                </div>
              );
            })}
          </div>

          <div className="gantt-body">
            {timelineData.map((timeline, idx) => (
              <div key={idx} className="gantt-row">
                <div className="gantt-row-label">
                  <strong>{timeline.label}</strong>
                  <span className="item-count">({timeline.items.length} items)</span>
                </div>
                <div className="gantt-bars">
                  <div
                    className={`gantt-bar ${timeline.color}-bg`}
                    style={{
                      marginLeft: `${(timeline.start / 90) * 100}%`,
                      width: `${(timeline.duration / 90) * 100}%`
                    }}
                  >
                    <div className="gantt-bar-content">
                      {timeline.items.length > 0 && (
                        <span>{timeline.items.length} issues</span>
                      )}
                    </div>
                  </div>
                  {timeline.items.length > 0 && (
                    <div
                      className="gantt-milestone"
                      style={{ marginLeft: `${((timeline.start + timeline.duration) / 90) * 100}%` }}
                    >
                      <div className="milestone-dot"></div>
                      <div className="milestone-label">Target: Day {timeline.start + timeline.duration}</div>
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>

        {aiInsights.length > 0 && (
          <div className="ai-insights-section">
            <h3>AI-Powered Recommendations</h3>
            <div className="insights-grid">
              {aiInsights.map((insight, index) => (
                <div key={index} className="insight-card-modern">
                  <div className="insight-icon">🤖</div>
                  <h4>{insight.title || `Insight ${index + 1}`}</h4>
                  <p>{insight.description}</p>
                  {insight.recommendations && insight.recommendations.length > 0 && (
                    <ul className="insight-list">
                      {insight.recommendations.slice(0, 3).map((rec, i) => (
                        <li key={i}>→ {rec}</li>
                      ))}
                    </ul>
                  )}
                  {insight.remediation_priority && (
                    <div className="priority-badge">{insight.remediation_priority}</div>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}
      </section>
    );
  };

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