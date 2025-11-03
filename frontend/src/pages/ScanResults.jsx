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
        console.log('🔍 Fetching scan results for ID:', scanId);
        const data = await scannerService.getScanResults(scanId);
        console.log('📊 Received scan results:', data);
        console.log('📊 Vulnerabilities count:', data?.vulnerabilities?.length || 0);
        console.log('📊 Risk assessment:', data?.risk_assessment);
        console.log('📊 MITRE mapping count:', data?.mitre_mapping?.length || 0);
        console.log('📊 AI analysis count:', data?.ai_analysis?.length || 0);

        // Ensure data structure is correct
        const normalizedData = {
          ...data,
          vulnerabilities: data?.vulnerabilities || [],
          risk_assessment: data?.risk_assessment || {
            overall_risk_score: 0,
            risk_level: 'Unknown',
            vulnerability_count: 0,
            critical_count: 0,
            high_count: 0,
            medium_count: 0,
            low_count: 0
          },
          mitre_mapping: data?.mitre_mapping || [],
          ai_analysis: data?.ai_analysis || []
        };

        console.log('✅ Normalized data:', normalizedData);
        setResults(normalizedData);
      } catch (error) {
        console.error('❌ Error fetching scan results:', error);
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
          <h2>⚠ Error Loading Results</h2>
          <p>{error}</p>
          <p style={{ fontSize: '0.9rem', color: '#666', marginTop: '1rem' }}>
            Scan ID: {scanId}
          </p>
          <button onClick={() => window.location.reload()}>Retry</button>
          <button onClick={() => navigate('/')} style={{ marginLeft: '1rem' }}>Back to Home</button>
        </div>
      </Layout>
    );
  }

  if (!results) {
    return (
      <Layout>
        <div className="error-container">
          <h2>⚠ No Results Found</h2>
          <p>The scan results could not be loaded. The scan may still be in progress.</p>
          <p style={{ fontSize: '0.9rem', color: '#666', marginTop: '1rem' }}>
            Scan ID: {scanId}
          </p>
          <button onClick={() => window.location.reload()}>Refresh</button>
          <button onClick={() => navigate('/')} style={{ marginLeft: '1rem' }}>Back to Home</button>
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
    console.log('🔍 Rendering vulnerability section with', vulns.length, 'vulnerabilities');
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
                <div key={vuln.id || index} className={`timeline-item ${colorKey}-bg`}>
                  <div className="timeline-marker">
                    <div className="marker-label">{index + 1}</div>
                  </div>
                  <div className="timeline-content">
                    <div className="timeline-time">
                      <span
                        className={`severity-badge ${vuln.severity ? vuln.severity.toLowerCase() : ''
                          }`}
                      >
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
    console.log('🔍 Rendering MITRE section with', techniques.length, 'techniques');

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
    console.log('🔍 Rendering risk section. Risk:', risk, 'Vulnerabilities:', vulns.length);

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
    console.log('🔍 Rendering AI analysis. AI insights:', aiInsights.length, 'Vulnerabilities:', vulns.length);

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

  const renderRemediationStrategies = () => {
    const strategies = results.remediation_strategies || {};
    const recommendations = strategies.recommendations || [];
    const priorityMatrix = strategies.priority_matrix || {};
    const timeline = strategies.timeline || {};
    const costBenefit = strategies.cost_benefit || {};
    const resourceAllocation = strategies.resource_allocation || {};

    console.log('🔍 Rendering remediation strategies:', strategies);

    return (
      <section className="results-section remediation-section">
        <div className="section-header-box pink">
          <h2>Remediation Strategy</h2>
          <div className="count-badge">{recommendations.length}</div>
        </div>

        {/* Priority Matrix */}
        {Object.keys(priorityMatrix).length > 0 && (
          <div className="strategy-subsection">
            <h3>📊 Priority Matrix</h3>
            <div className="priority-matrix-grid">
              {Object.entries(priorityMatrix).map(([priority, items]) => (
                <div key={priority} className={`priority-card ${priority.toLowerCase()}-priority`}>
                  <div className="priority-header">
                    <span className={`priority-badge ${priority.toLowerCase()}`}>
                      {priority.toUpperCase()}
                    </span>
                    <span className="item-count">{items.length || 0} items</span>
                  </div>
                  {items && items.length > 0 && (
                    <ul className="priority-items">
                      {items.slice(0, 5).map((item, idx) => (
                        <li key={idx}>{item.title || item}</li>
                      ))}
                      {items.length > 5 && <li>...and {items.length - 5} more</li>}
                    </ul>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Timeline */}
        {Object.keys(timeline).length > 0 && (
          <div className="strategy-subsection">
            <h3>📅 Remediation Timeline</h3>
            <div className="timeline-overview">
              {timeline.immediate_action && (
                <div className="timeline-phase critical-phase">
                  <h4>⚡ Immediate Action (0-7 days)</h4>
                  <p>{timeline.immediate_action.description}</p>
                  <div className="timeline-items">
                    {timeline.immediate_action.items && timeline.immediate_action.items.map((item, idx) => (
                      <div key={idx} className="timeline-item-card">
                        <strong>{item.title || item}</strong>
                        {item.estimated_hours && <span className="time-estimate">{item.estimated_hours}h</span>}
                      </div>
                    ))}
                  </div>
                </div>
              )}
              {timeline.short_term && (
                <div className="timeline-phase high-phase">
                  <h4>🎯 Short Term (1-4 weeks)</h4>
                  <p>{timeline.short_term.description}</p>
                  <div className="timeline-items">
                    {timeline.short_term.items && timeline.short_term.items.map((item, idx) => (
                      <div key={idx} className="timeline-item-card">
                        <strong>{item.title || item}</strong>
                        {item.estimated_hours && <span className="time-estimate">{item.estimated_hours}h</span>}
                      </div>
                    ))}
                  </div>
                </div>
              )}
              {timeline.medium_term && (
                <div className="timeline-phase medium-phase">
                  <h4>📆 Medium Term (1-3 months)</h4>
                  <p>{timeline.medium_term.description}</p>
                  <div className="timeline-items">
                    {timeline.medium_term.items && timeline.medium_term.items.map((item, idx) => (
                      <div key={idx} className="timeline-item-card">
                        <strong>{item.title || item}</strong>
                        {item.estimated_hours && <span className="time-estimate">{item.estimated_hours}h</span>}
                      </div>
                    ))}
                  </div>
                </div>
              )}
              {timeline.long_term && (
                <div className="timeline-phase low-phase">
                  <h4>🔄 Long Term (3+ months)</h4>
                  <p>{timeline.long_term.description}</p>
                  <div className="timeline-items">
                    {timeline.long_term.items && timeline.long_term.items.map((item, idx) => (
                      <div key={idx} className="timeline-item-card">
                        <strong>{item.title || item}</strong>
                        {item.estimated_hours && <span className="time-estimate">{item.estimated_hours}h</span>}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Cost-Benefit Analysis */}
        {Object.keys(costBenefit).length > 0 && (
          <div className="strategy-subsection">
            <h3>💰 Cost-Benefit Analysis</h3>
            <div className="cost-benefit-grid">
              <div className="cost-card">
                <div className="cost-label">Estimated Remediation Cost</div>
                <div className="cost-value">
                  ${(costBenefit.total_remediation_cost || costBenefit.remediation_cost || 0).toLocaleString()}
                </div>
                {costBenefit.effort_hours && (
                  <div className="cost-detail">{costBenefit.effort_hours} hours of effort</div>
                )}
              </div>
              <div className="cost-card">
                <div className="cost-label">Potential Loss (if not fixed)</div>
                <div className="cost-value risk">
                  ${(costBenefit.potential_breach_cost || costBenefit.potential_loss || 0).toLocaleString()}
                </div>
                {costBenefit.probability && (
                  <div className="cost-detail">Probability: {(costBenefit.probability * 100).toFixed(0)}%</div>
                )}
              </div>
              <div className="cost-card">
                <div className="cost-label">Net Benefit</div>
                <div className="cost-value benefit">
                  ${(costBenefit.net_benefit || 0).toLocaleString()}
                </div>
                {costBenefit.roi_percentage && (
                  <div className="cost-detail">ROI: {costBenefit.roi_percentage.toFixed(0)}%</div>
                )}
              </div>
            </div>
            {costBenefit.recommendation && (
              <div className="cost-recommendation">
                <strong>💡 Recommendation:</strong> {costBenefit.recommendation}
              </div>
            )}
          </div>
        )}

        {/* Resource Allocation */}
        {Object.keys(resourceAllocation).length > 0 && (
          <div className="strategy-subsection">
            <h3>👥 Resource Allocation</h3>
            <div className="resource-grid">
              {resourceAllocation.team_composition && (
                <div className="resource-card">
                  <h4>Team Composition</h4>
                  <ul>
                    {Object.entries(resourceAllocation.team_composition).map(([role, count]) => (
                      <li key={role}>
                        <strong>{role}:</strong> {count}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
              {resourceAllocation.estimated_timeline && (
                <div className="resource-card">
                  <h4>Estimated Timeline</h4>
                  <p>{resourceAllocation.estimated_timeline}</p>
                </div>
              )}
              {resourceAllocation.budget_range && (
                <div className="resource-card">
                  <h4>Budget Range</h4>
                  <p>{resourceAllocation.budget_range}</p>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Recommendations List */}
        {recommendations.length > 0 && (
          <div className="strategy-subsection">
            <h3>✅ Actionable Recommendations</h3>
            <div className="recommendations-list">
              {recommendations.map((rec, index) => (
                <div key={index} className={`recommendation-card ${rec.priority?.toLowerCase() || 'medium'}-priority`}>
                  <div className="rec-header">
                    <span className={`rec-badge ${rec.priority?.toLowerCase() || 'medium'}`}>
                      {rec.priority || 'Medium'}
                    </span>
                    {rec.category && <span className="rec-category">{rec.category}</span>}
                  </div>
                  <h4>{rec.title || `Recommendation ${index + 1}`}</h4>
                  <p>{rec.description || rec.recommendation}</p>
                  {rec.action_items && rec.action_items.length > 0 && (
                    <div className="action-items">
                      <strong>Action Items:</strong>
                      <ul>
                        {rec.action_items.map((action, idx) => (
                          <li key={idx}>{action}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                  {rec.estimated_effort && (
                    <div className="rec-effort">Effort: {rec.estimated_effort}</div>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}

        {recommendations.length === 0 && Object.keys(strategies).length === 0 && (
          <div className="no-results">
            <p>No remediation strategies available yet. Strategies will be generated after scan completion.</p>
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

  // Log rendering state
  console.log('🎨 Rendering ScanResults component');
  console.log('  - Active tab:', activeTab);
  console.log('  - Results loaded:', !!results);
  console.log('  - Results data:', results);

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
            className={`tab ${activeTab === 'remediation' ? 'active' : ''}`}
            onClick={() => setActiveTab('remediation')}
          >
            Remediation Strategy
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
          {activeTab === 'remediation' && renderRemediationStrategies()}
          {activeTab === 'ai' && renderAIAnalysis()}
        </div>
      </div>
    </Layout>
  );
};

export default ScanResults;