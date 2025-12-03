import React, { useEffect, useMemo, useState } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import Layout from '../components/Layout';
import scannerService from '../services/scannerService';
import './ScanResults.css';

const severityOrder = ['critical', 'high', 'medium', 'low'];
const severityWeights = {
  critical: 10,
  high: 7,
  medium: 4,
  low: 2,
  unknown: 1
};

const deriveRiskLevel = (score) => {
  if (score === null || score === undefined) return 'Unknown';
  if (score >= 8) return 'Critical';
  if (score >= 6) return 'High';
  if (score >= 4) return 'Medium';
  if (score >= 2) return 'Low';
  return 'Minimal';
};

const computeTimelineDuration = (timelineInfo, fallback) => {
  if (!timelineInfo) {
    return fallback;
  }

  if (typeof timelineInfo.duration_days === 'number') {
    return Math.max(1, timelineInfo.duration_days);
  }

  if (typeof timelineInfo.target_days === 'number') {
    return Math.max(1, timelineInfo.target_days);
  }

  if (typeof timelineInfo.window_days === 'number') {
    return Math.max(1, timelineInfo.window_days);
  }

  const estimatedHours = (timelineInfo.items || []).reduce((sum, item) => {
    const hours = item?.estimated_hours || item?.hours || 0;
    return sum + (typeof hours === 'number' ? hours : 0);
  }, 0);

  if (estimatedHours) {
    return Math.max(1, Math.ceil(estimatedHours / 6));
  }

  return fallback;
};

const pluralize = (count, singular, plural) => {
  if (count === 1) {
    return singular;
  }
  if (plural) {
    return plural;
  }
  return `${singular}s`;
};

const ScanResults = () => {
  const { scanId } = useParams();
  const navigate = useNavigate();
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [activeTab, setActiveTab] = useState('overview');
  const [summaryText, setSummaryText] = useState('');
  const [summaryLoading, setSummaryLoading] = useState(false);
  const [summaryError, setSummaryError] = useState(null);
  const [summaryCached, setSummaryCached] = useState(false);
  const [summaryFetchToken, setSummaryFetchToken] = useState(0);

  const vulnerabilityStats = useMemo(() => {
    const counts = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
      unknown: 0
    };

    const grouped = {
      critical: [],
      high: [],
      medium: [],
      low: [],
      info: [],
      unknown: []
    };

    if (!results?.vulnerabilities?.length) {
      return {
        total: 0,
        counts,
        grouped,
        avgCvss: null,
        highest: null,
        cvssCount: 0
      };
    }

    let totalCvss = 0;
    let cvssCount = 0;
    let highest = null;

    results.vulnerabilities.forEach((vuln) => {
      const severity = (vuln.severity || 'unknown').toLowerCase();
      const bucket = grouped[severity] ? severity : 'unknown';
      grouped[bucket].push(vuln);
      counts[bucket] += 1;

      if (typeof vuln.cvss_score === 'number' && !Number.isNaN(vuln.cvss_score)) {
        totalCvss += vuln.cvss_score;
        cvssCount += 1;
        if (!highest || (vuln.cvss_score ?? 0) > (highest.cvss_score ?? 0)) {
          highest = vuln;
        }
      }
    });

    const avgCvss = cvssCount ? totalCvss / cvssCount : null;

    return {
      total: results.vulnerabilities.length,
      counts,
      grouped,
      avgCvss,
      highest,
      cvssCount
    };
  }, [results]);

  const normalizedRisk = useMemo(() => {
    const baseRisk = results?.risk_assessment || {};
    const fallbackCounts = vulnerabilityStats.counts || {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      unknown: 0
    };

    const vulnerabilityCount = baseRisk.vulnerability_count ?? vulnerabilityStats.total;
    const criticalCount = baseRisk.critical_count ?? fallbackCounts.critical;
    const highCount = baseRisk.high_count ?? fallbackCounts.high;
    const mediumCount = baseRisk.medium_count ?? fallbackCounts.medium;
    const lowCount = baseRisk.low_count ?? fallbackCounts.low;

    // Use provided score only if it's a finite number AND either:
    // 1. It's greater than 0, OR
    // 2. There are no vulnerabilities (score of 0 is correct)
    const providedScore = Number.isFinite(baseRisk.overall_risk_score)
      ? Number(baseRisk.overall_risk_score)
      : null;

    // If backend returned 0 but we have vulnerabilities, recalculate
    const shouldRecalculate = providedScore === 0 && vulnerabilityStats.total > 0;

    console.log('[RISK] Risk calculation:', {
      providedScore,
      vulnerabilityTotal: vulnerabilityStats.total,
      avgCvss: vulnerabilityStats.avgCvss,
      shouldRecalculate,
      fallbackCounts
    });

    let fallbackScore = 0;
    if (vulnerabilityStats.avgCvss !== null) {
      fallbackScore = vulnerabilityStats.avgCvss;
    } else if (vulnerabilityStats.total) {
      const weightedSum = severityOrder.reduce((sum, severity) => {
        const count = fallbackCounts[severity] || 0;
        return sum + count * (severityWeights[severity] || severityWeights.unknown);
      }, 0);
      fallbackScore = Math.min(10, weightedSum / vulnerabilityStats.total);
    }

    const normalizedScore = (providedScore !== null && !shouldRecalculate)
      ? providedScore
      : Number(fallbackScore.toFixed(2));

    // If we recalculated the score, also recalculate the risk level
    const riskLevel = shouldRecalculate
      ? deriveRiskLevel(normalizedScore)
      : (baseRisk.risk_level || deriveRiskLevel(normalizedScore));

    return {
      ...baseRisk,
      overall_risk_score: normalizedScore,
      risk_level: riskLevel,
      vulnerability_count: vulnerabilityCount,
      critical_count: criticalCount,
      high_count: highCount,
      medium_count: mediumCount,
      low_count: lowCount
    };
  }, [results, vulnerabilityStats]);

  const aiInsightsCount = results?.ai_analysis?.length || 0;
  const mitreCount = results?.mitre_mapping?.length || 0;
  const remediationRecommendationsCount = results?.remediation_strategies?.recommendations?.length || 0;
  const summaryTabVisible = Boolean(
    summaryLoading ||
    summaryError ||
    summaryText ||
    summaryFetchToken > 0 ||
    summaryCached
  );

  const overviewCards = useMemo(() => {
    if (!results) {
      return [];
    }

    const total = vulnerabilityStats.total;
    const critical = normalizedRisk.critical_count || 0;
    const high = normalizedRisk.high_count || 0;
    const medium = normalizedRisk.medium_count || 0;
    const low = normalizedRisk.low_count || 0;
    const mediumLowTotal = medium + low;
    const avgCvss = vulnerabilityStats.avgCvss;
    const topCritical = vulnerabilityStats.grouped?.critical?.[0]?.title;
    const topHigh = vulnerabilityStats.grouped?.high?.[0]?.title;
    const topFinding = vulnerabilityStats.highest?.title || vulnerabilityStats.highest?.name;

    return [
      {
        key: 'critical',
        number: '01',
        title: 'Critical Issues',
        color: 'cyan',
        description: critical
          ? `${pluralize(critical, 'critical vulnerability')} detected${topCritical ? ` — start with ${topCritical}.` : '.'}`
          : 'No critical vulnerabilities detected in this scan.'
      },
      {
        key: 'high',
        number: '02',
        title: 'High Priority',
        color: 'coral',
        description: high
          ? `${pluralize(high, 'high-severity issue')} queued for the next remediation window${topHigh ? ` (focus on ${topHigh})` : ''}.`
          : 'No high-severity issues were reported.'
      },
      {
        key: 'mediumLow',
        number: '03',
        title: 'Medium & Low Risk',
        color: 'green',
        description: mediumLowTotal
          ? `${pluralize(mediumLowTotal, 'lower-severity finding')} scheduled for maintenance cycles.`
          : 'Medium and low risk surfaces are currently clear.'
      },
      {
        key: 'coverage',
        number: '04',
        title: 'Coverage & Mapping',
        color: 'pink',
        description: mitreCount
          ? `${pluralize(mitreCount, 'MITRE technique')} mapped to help trace attack paths.`
          : 'No MITRE techniques mapped for this scan run.'
      },
      {
        key: 'insights',
        number: '05',
        title: 'AI Insights',
        color: 'yellow',
        description: aiInsightsCount
          ? `${aiInsightsCount} curated insight${aiInsightsCount === 1 ? '' : 's'} ready to guide remediation.`
          : 'AI insights will populate as scans collect additional context.'
      }
    ];
  }, [results, normalizedRisk, vulnerabilityStats, mitreCount, aiInsightsCount]);

  const hasRemediationData = useMemo(() => {
    // Show Defense Playbook tab if there are vulnerabilities OR remediation strategies
    // The component will generate default strategies from vulnerabilities if needed
    if (vulnerabilityStats.total > 0) {
      return true;
    }

    // Also check normalizedRisk counts from risk_assessment
    const riskTotal = (normalizedRisk.critical_count || 0) +
      (normalizedRisk.high_count || 0) +
      (normalizedRisk.medium_count || 0) +
      (normalizedRisk.low_count || 0);
    if (riskTotal > 0) {
      return true;
    }

    const strategies = results?.remediation_strategies;
    if (!strategies) {
      return false;
    }

    const {
      recommendations,
      priority_matrix: priorityMatrix,
      timeline,
      cost_benefit: costBenefit,
      resource_allocation: resourceAllocation
    } = strategies;

    return Boolean(
      (recommendations && recommendations.length) ||
      (priorityMatrix && Object.keys(priorityMatrix).length) ||
      (timeline && Object.keys(timeline).length) ||
      (costBenefit && Object.keys(costBenefit).length) ||
      (resourceAllocation && Object.keys(resourceAllocation).length)
    );
  }, [results, vulnerabilityStats.total, normalizedRisk]);

  const availableTabs = useMemo(() => {
    if (!results) {
      return [];
    }

    return [
      {
        id: 'summary',
        label: 'Mission Brief',
        display: 'Mission Brief',
        visible: summaryTabVisible
      },
      {
        id: 'overview',
        label: 'Recon Report',
        display: 'Recon Report'
      },
      {
        id: 'vulnerabilities',
        label: 'Threat Catalog',
        display: vulnerabilityStats.total ? `Threat Catalog (${vulnerabilityStats.total})` : 'Threat Catalog'
      },
      {
        id: 'mitre',
        label: 'Attack Matrix',
        display: mitreCount ? `Attack Matrix (${mitreCount})` : 'Attack Matrix',
        visible: mitreCount > 0
      },
      {
        id: 'remediation',
        label: 'Defense Playbook',
        display: hasRemediationData
          ? `Defense Playbook (${vulnerabilityStats.total || remediationRecommendationsCount || 0})`
          : 'Defense Playbook',
        visible: hasRemediationData
      },
      {
        id: 'ai',
        label: 'Intel Analysis',
        display: aiInsightsCount ? `Intel Analysis (${aiInsightsCount})` : 'Intel Analysis',
        visible: aiInsightsCount > 0 || vulnerabilityStats.total > 0
      }
    ].filter((tab) => tab.visible === undefined ? true : tab.visible);
  }, [results, vulnerabilityStats.total, mitreCount, hasRemediationData, aiInsightsCount, summaryTabVisible]);

  useEffect(() => {
    if (!results || !availableTabs.length) {
      return;
    }

    if (!availableTabs.some((tab) => tab.id === activeTab)) {
      setActiveTab(availableTabs[0].id);
    }
  }, [results, availableTabs, activeTab]);

  useEffect(() => {
    const fetchResults = async () => {
      try {
        console.log('[SCAN] Fetching scan results for ID:', scanId);
        const data = await scannerService.getScanResults(scanId);
        console.log('[DATA] Received scan results:', data);
        console.log('[DATA] Vulnerabilities count:', data?.vulnerabilities?.length || 0);
        console.log('[DATA] Risk assessment:', data?.risk_assessment);
        console.log('[DATA] MITRE mapping count:', data?.mitre_mapping?.length || 0);
        console.log('[DATA] AI analysis count:', data?.ai_analysis?.length || 0);

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
          ai_analysis: data?.ai_analysis || [],
          executive_summary: data?.executive_summary || data?.summary || null
        };

        console.log('[SUCCESS] Normalized data:', normalizedData);
        setResults(normalizedData);

        if (normalizedData.executive_summary) {
          setSummaryText(normalizedData.executive_summary);
          setSummaryCached(true);
          setSummaryLoading(false);
          setSummaryError(null);
          setSummaryFetchToken(0);
        } else {
          setSummaryText('');
          setSummaryCached(false);
          setSummaryError(null);
          setSummaryFetchToken((token) => token + 1);
        }
      } catch (error) {
        console.error('[ERROR] Error fetching scan results:', error);
        setError(error.message);
      } finally {
        setLoading(false);
      }
    };

    fetchResults();
  }, [scanId]);

  useEffect(() => {
    if (!results || !summaryFetchToken) {
      return;
    }

    const hasFindings = Boolean(
      (results.vulnerabilities && results.vulnerabilities.length) ||
      (results.ai_analysis && results.ai_analysis.length) ||
      results.risk_assessment
    );

    if (!hasFindings) {
      return;
    }

    let cancelled = false;

    const fetchSummary = async () => {
      try {
        setSummaryLoading(true);
        setSummaryError(null);
        setSummaryCached(false);

        const response = await scannerService.getScanSummary(scanId);
        if (cancelled) {
          return;
        }

        setSummaryText(response?.summary || '');
        setSummaryCached(Boolean(response?.cached));
      } catch (summaryErr) {
        if (!cancelled) {
          setSummaryError(summaryErr?.message || 'Unable to generate summary');
          setSummaryText('');
        }
      } finally {
        if (!cancelled) {
          setSummaryLoading(false);
        }
      }
    };

    fetchSummary();

    return () => {
      cancelled = true;
    };
  }, [results, scanId, summaryFetchToken]);

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
          <p className="error-scan-id">Scan ID: {scanId}</p>
          <div className="error-actions">
            <button onClick={() => window.location.reload()}>Retry</button>
            <button onClick={() => navigate('/')} className="error-actions__secondary">
              Back to Home
            </button>
          </div>
        </div>
      </Layout>
    );
  }

  if (!results) {
    return (
      <Layout>
        <div className="error-container">
          <h2>No Results Found</h2>
          <p>The scan results could not be loaded. The scan may still be in progress.</p>
          <p className="error-scan-id">Scan ID: {scanId}</p>
          <div className="error-actions">
            <button onClick={() => window.location.reload()}>Refresh</button>
            <button onClick={() => navigate('/')} className="error-actions__secondary">
              Back to Home
            </button>
          </div>
        </div>
      </Layout>
    );
  }

  const handleSummaryRetry = () => {
    setSummaryText('');
    setSummaryCached(false);
    setSummaryError(null);
    setSummaryFetchToken((token) => token + 1);
  };

  const renderVulnerabilitySection = () => {
    const vulns = results.vulnerabilities || [];
    console.log('[RENDER] Rendering vulnerability section with', vulns.length, 'vulnerabilities');

    // Random color rotation for visual variety
    const colorMap = ['cyan', 'coral', 'green', 'pink', 'yellow'];

    return (
      <section className="results-section detailed-outline">
        <div className="section-header-box coral">
          <h2>Threat Catalog</h2>
          <div className="count-badge">{vulnerabilityStats.total}</div>
        </div>
        {vulns.length > 0 ? (
          <div className="timeline-grid">
            {vulns.map((vuln, index) => {
              const colorKey = colorMap[index % colorMap.length];
              return (
                <div key={vuln.id || vuln.vulnerability_id || index} className={`timeline-item ${colorKey}-bg`}>
                  <div className="timeline-marker">
                    <div className="marker-label">{index + 1}</div>
                  </div>
                  <div className="timeline-content">
                    <div className="timeline-time">
                      <span
                        className={`severity-badge ${vuln.severity ? vuln.severity.toLowerCase() : 'info'}`}
                      >
                        {vuln.severity || 'Info'}
                      </span>
                      {vuln.scanner_source && (
                        <span className="scanner-source">{vuln.scanner_source}</span>
                      )}
                    </div>
                    <h3 className="timeline-title">{vuln.title || vuln.name || 'Security Finding'}</h3>
                    <p className="timeline-desc">{vuln.description || 'No description available'}</p>
                    {vuln.cvss_score > 0 && (
                      <div className="timeline-meta">
                        <strong>CVSS:</strong> {vuln.cvss_score}
                      </div>
                    )}
                    {(vuln.location || vuln.url) && (
                      <div className="timeline-meta">
                        <strong>Location:</strong> {vuln.location || vuln.url}
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
            <div className="no-vulns-container">
              <div className="no-vulns-icon">OK</div>
              <h3>No Threats Detected</h3>
              <p>The scan completed without identifying vulnerabilities in the target.</p>
              <div className="no-vulns-details">
                <div className="no-vulns-details-header">
                  <span>Security Note</span>
                </div>
                <div className="no-vulns-details-content">
                  <ul>
                    <li>Run a Deep scan for more comprehensive analysis</li>
                    <li>Verify the target URL was accessible during the scan</li>
                    <li>Check authentication if the target requires login</li>
                    <li>Consider manual testing for business logic flaws</li>
                  </ul>
                </div>
              </div>
            </div>
          </div>
        )}
      </section>
    );
  };

  const renderMITRESection = () => {
    const techniques = results.mitre_mapping || [];
    console.log('[RENDER] Rendering MITRE section with', techniques.length, 'techniques');

    return (
      <section className="results-section mitre-section">
        <div className="section-header-box green">
          <h2>Attack Matrix</h2>
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
    const risk = normalizedRisk;
    const totalFindings = vulnerabilityStats.total;
    const riskLevelDisplay = (risk.risk_level || 'Unknown').toString();
    console.log('[RENDER] Rendering risk section. Risk:', risk, 'Vulnerabilities:', totalFindings);

    return (
      <section className="results-section overview">
        <div className="section-header-box pink">
          <h2>Recon Report</h2>
        </div>

        <div className="overview-grid">
          {overviewCards.map((card) => (
            <div key={card.key} className={`overview-card ${card.color}-bg`}>
              <div className="card-number">{card.number}</div>
              <h3 className="card-title">{card.title}</h3>
              <p className="card-content">{card.description}</p>
            </div>
          ))}
        </div>

        <div className="risk-score-display">
          <div className="risk-score-content">
            <div className="score-circle-large" style={{ background: getRiskColor(risk.overall_risk_score) }}>
              {Number.isFinite(risk.overall_risk_score) ? risk.overall_risk_score.toFixed(1) : 'N/A'}
            </div>
            <div className="risk-label">
              <span className="risk-label-level">{riskLevelDisplay}</span>
              <span className="risk-label-caption">Risk Level</span>
            </div>
          </div>
        </div>
      </section>
    );
  };

  const renderExecutiveSummary = () => (
    <section className="results-section summary-section">
      <div className="section-header-box yellow">
        <h2>Mission Brief</h2>
        <div className="count-badge">{summaryCached ? 'Cached' : 'Live'}</div>
      </div>
      <div className="executive-summary-card">
        <div className="executive-summary-meta">
          <span className={`llm-badge${summaryCached ? ' cached' : ''}`}>
            {summaryCached ? 'Groq LLM - Cached' : 'Groq LLM - Inference'}
          </span>
        </div>
        <div className="executive-summary-body">
          {summaryLoading && (
            <p className="summary-status">Generating technical analysis of this scan...</p>
          )}

          {!summaryLoading && summaryError && (
            <div className="summary-error">
              <p>{summaryError}</p>
              <button type="button" onClick={handleSummaryRetry}>Retry Analysis</button>
            </div>
          )}

          {!summaryLoading && !summaryError && summaryText && (
            <div className="summary-text">
              {summaryText
                .split(/\n+/)
                .map((paragraph, idx) => paragraph.trim())
                .filter(Boolean)
                .map((paragraph, idx) => (
                  <p key={idx}>{paragraph}</p>
                ))}
            </div>
          )}

          {!summaryLoading && !summaryError && !summaryText && (
            <p className="summary-status">Summary will appear here once generated.</p>
          )}
        </div>
      </div>
    </section>
  );

  const renderAIAnalysis = () => {
    const aiInsights = results.ai_analysis || [];
    console.log('[RENDER] Rendering intelligence section. AI insights:', aiInsights.length, 'Vulnerabilities:', vulnerabilityStats.total);

    const severityBuckets = vulnerabilityStats.grouped;
    const strategiesTimeline = results.remediation_strategies?.timeline || {};

    const priorityConfig = {
      critical: { label: 'Immediate Action', className: 'cyan', accentColor: '#6DD4D9', symbol: '!' },
      high: { label: 'Next Sprint', className: 'coral', accentColor: '#FF6B6B', symbol: 'H' },
      medium: { label: 'This Quarter', className: 'pink', accentColor: '#E39FCE', symbol: 'M' },
      low: { label: 'Maintenance', className: 'yellow', accentColor: '#FFD93D', symbol: 'L' }
    };

    const mapInsightToPriority = (insight) => {
      const prioritySource = `${insight.priority || ''} ${insight.priority_key || ''} ${insight.priority_level || ''} ${insight.remediation_priority || ''} ${insight.timeframe || ''} ${insight.window || ''} ${insight.urgency || ''}`.toLowerCase();
      if (prioritySource.includes('critical') || prioritySource.includes('immediate') || prioritySource.includes('now')) return 'critical';
      if (prioritySource.includes('high') || prioritySource.includes('urgent') || prioritySource.includes('week')) return 'high';
      if (prioritySource.includes('medium') || prioritySource.includes('month') || prioritySource.includes('quarter') || prioritySource.includes('sprint')) return 'medium';
      return 'low';
    };

    const insightsByPriority = {
      critical: [],
      high: [],
      medium: [],
      low: []
    };

    aiInsights.forEach((insight) => {
      const priority = mapInsightToPriority(insight);
      insightsByPriority[priority].push(insight);
    });

    const bucketsConfig = [
      { key: 'critical', timelineKey: 'immediate_action', defaultDuration: 7 },
      { key: 'high', timelineKey: 'short_term', defaultDuration: 14 },
      { key: 'medium', timelineKey: 'medium_term', defaultDuration: 30 },
      { key: 'low', timelineKey: 'long_term', defaultDuration: 45 }
    ];

    let currentStart = 0;
    const timelineData = [];

    bucketsConfig.forEach(({ key, timelineKey, defaultDuration }) => {
      const severityItems = severityBuckets[key] || [];
      const bucketInsights = insightsByPriority[key] || [];
      const timelineInfo = strategiesTimeline[timelineKey];
      const hasContent = severityItems.length || bucketInsights.length || timelineInfo;

      if (!hasContent) {
        return;
      }

      const duration = computeTimelineDuration(timelineInfo, defaultDuration);
      const bucketStart = currentStart;
      currentStart += duration;

      const priorityToken = priorityConfig[key];

      timelineData.push({
        key,
        label: priorityToken.label,
        barClass: priorityToken.className,
        accentColor: priorityToken.accentColor,
        symbol: priorityToken.symbol,
        items: severityItems,
        insights: bucketInsights,
        duration,
        start: bucketStart,
        milestoneTarget: timelineInfo?.target_days || timelineInfo?.deadline_days || Math.round(bucketStart + duration),
        milestoneLabel: timelineInfo?.target_label || timelineInfo?.deadline_label || `Target: Day ${Math.round(bucketStart + duration)}`
      });
    });

    const totalDuration = timelineData.reduce((max, entry) => Math.max(max, entry.start + entry.duration), 0) || 1;
    const headerSegments = Math.max(4, Math.min(12, Math.ceil(totalDuration / 7)));
    const headerLabels = Array.from({ length: headerSegments + 1 }, (_, index) => {
      const dayIncrement = totalDuration / headerSegments;
      const rawDay = dayIncrement * index;
      const day = index === headerSegments ? Math.round(totalDuration) : Math.floor(rawDay);
      return {
        id: index,
        day,
        week: Math.round(day / 7)
      };
    });

    const timelineFindingCount = timelineData.reduce((sum, bucket) => sum + bucket.items.length, 0);

    return (
      <section className="results-section ai-timeframes">
        <div className="section-header-box purple">
          <h2>Intel Analysis</h2>
          <div className="count-badge">{timelineFindingCount || aiInsights.length || vulnerabilityStats.total}</div>
        </div>

        {timelineData.length > 0 ? (
          <div className="gantt-container">
            <div className="gantt-header">
              <div className="gantt-row-label">Priority Level</div>
              {headerLabels.map((label) => (
                <div key={label.id} className="gantt-time-label">
                  <span className="month-label">Week</span>
                  <span className="day-label">{label.day}</span>
                </div>
              ))}
            </div>

            <div className="gantt-body">
              {timelineData.map((timeline) => {
                const itemCount = timeline.items.length;
                return (
                  <div key={timeline.key} className="gantt-row">
                    <div className="gantt-row-label">
                      <strong>{timeline.label}</strong>
                      {itemCount > 0 && (
                        <span className="item-count">({`${itemCount} ${pluralize(itemCount, 'item')}`})</span>
                      )}
                      {timeline.insights.length > 0 && (
                        <span className="insights-count" style={{ background: timeline.accentColor }}>
                          {timeline.symbol} {timeline.insights.length} insights
                        </span>
                      )}
                    </div>
                    <div className="gantt-bars">
                      <div
                        className={`gantt-bar ${timeline.barClass}-bg`}
                        style={{
                          marginLeft: `${(timeline.start / totalDuration) * 100}%`,
                          width: `${(timeline.duration / totalDuration) * 100}%`
                        }}
                      >
                        <div className="gantt-bar-content">
                          {timeline.items.length > 0 ? (
                            <span>{timeline.items.length} {pluralize(timeline.items.length, 'issue')}</span>
                          ) : (
                            <span>No findings yet</span>
                          )}
                        </div>

                        {timeline.insights.length > 0 && (
                          <div className="gantt-insights-overlay">
                            {timeline.insights.slice(0, 2).map((insight, i) => (
                              <div
                                key={i}
                                className="insight-marker"
                                title={insight.title || insight.description}
                                style={{ borderColor: timeline.accentColor }}
                              >
                                <div className="insight-marker-icon">{timeline.symbol}</div>
                                <div className="insight-marker-label">
                                  {insight.title || `Insight ${i + 1}`}
                                </div>
                              </div>
                            ))}
                            {timeline.insights.length > 2 && (
                              <div className="insight-marker-more" style={{ background: timeline.accentColor }}>
                                +{timeline.insights.length - 2} more
                              </div>
                            )}
                          </div>
                        )}
                      </div>
                      {(timeline.items.length > 0 || timeline.insights.length > 0) && (
                        <div
                          className="gantt-milestone"
                          style={{ marginLeft: `${((timeline.start + timeline.duration) / totalDuration) * 100}%` }}
                        >
                          <div className="milestone-dot"></div>
                          <div className="milestone-label">{timeline.milestoneLabel}</div>
                        </div>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        ) : (
          <div className="no-results">
            <p>Remediation timeline will populate once the scan identifies actionable findings or AI insights.</p>
          </div>
        )}

        {aiInsights.length > 0 ? (
          <div className="ai-insights-section">
            <h3>Expert Insights & Recommendations</h3>
            <p className="insights-description">
              Insights align with the timeline above. Each recommendation updates as new scan data arrives.
            </p>
            <div className="insights-grid">
              {aiInsights.map((insight, index) => {
                const priority = mapInsightToPriority(insight);
                const priorityToken = priorityConfig[priority] || priorityConfig.low;

                return (
                  <div key={index} className="insight-card-modern">
                    <div
                      className="insight-priority-tag"
                      style={{ background: priorityToken.accentColor }}
                    >
                      {priorityToken.symbol} {priorityToken.label}
                    </div>
                    <h4>{insight.title || `Insight ${index + 1}`}</h4>
                    <p>{insight.description}</p>
                    {insight.recommendations && insight.recommendations.length > 0 && (
                      <ul className="insight-list">
                        {insight.recommendations.slice(0, 3).map((rec, i) => (
                          <li key={i}>→ {rec}</li>
                        ))}
                      </ul>
                    )}
                    <div className="priority-badge">
                      {insight.remediation_priority || priorityToken.label}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        ) : (
          <div className="ai-insights-section">
            <p className="no-results">No expert insights generated for this scan yet.</p>
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

    // Use vulnerabilityStats or normalizedRisk to show actual data if strategies are empty
    const hasStrategies = Object.keys(strategies).length > 0;

    // Get counts from vulnerabilityStats first, then fall back to normalizedRisk (from risk_assessment)
    const criticalCount = vulnerabilityStats.counts.critical || normalizedRisk.critical_count || 0;
    const highCount = vulnerabilityStats.counts.high || normalizedRisk.high_count || 0;
    const mediumCount = vulnerabilityStats.counts.medium || normalizedRisk.medium_count || 0;
    const lowCount = vulnerabilityStats.counts.low || normalizedRisk.low_count || 0;
    const infoCount = vulnerabilityStats.counts.info || 0;
    const totalFromCounts = criticalCount + highCount + mediumCount + lowCount + infoCount;

    // Use vulnerabilityStats.total as it includes ALL vulnerabilities
    const hasVulnerabilities = vulnerabilityStats.total > 0 || totalFromCounts > 0;

    // Build priority matrix from vulnerabilities if not provided
    const effectivePriorityMatrix = Object.keys(priorityMatrix).length > 0
      ? priorityMatrix
      : {
        critical: vulnerabilityStats.grouped.critical || [],
        high: vulnerabilityStats.grouped.high || [],
        medium: vulnerabilityStats.grouped.medium || [],
        low: vulnerabilityStats.grouped.low || [],
        info: vulnerabilityStats.grouped.info || []
      };

    // Calculate totals - use matrix if available, else use counts
    let totalIssues = Object.values(effectivePriorityMatrix).reduce((sum, items) =>
      sum + (Array.isArray(items) ? items.length : 0), 0);
    if (totalIssues === 0) {
      totalIssues = totalFromCounts || vulnerabilityStats.total;
    }

    // Build timeline from vulnerabilities if not provided  
    const effectiveTimeline = Object.keys(timeline).length > 0 ? timeline : {
      immediate_action: vulnerabilityStats.grouped.critical?.length > 0 ? {
        description: `Address ${vulnerabilityStats.grouped.critical.length} critical ${pluralize(vulnerabilityStats.grouped.critical.length, 'vulnerability', 'vulnerabilities')} immediately to prevent active exploitation and data breaches.`,
        items: vulnerabilityStats.grouped.critical.slice(0, 5).map(v => ({
          title: v.title || v.name || 'Critical Vulnerability',
          estimated_hours: Math.max(2, Math.ceil((v.cvss_score || 9) * 0.5)),
          location: v.location || v.url || ''
        }))
      } : null,
      short_term: vulnerabilityStats.grouped.high?.length > 0 ? {
        description: `Fix ${vulnerabilityStats.grouped.high.length} high severity ${pluralize(vulnerabilityStats.grouped.high.length, 'issue')} within the first week to reduce attack surface.`,
        items: vulnerabilityStats.grouped.high.slice(0, 5).map(v => ({
          title: v.title || v.name || 'High Priority Issue',
          estimated_hours: Math.max(2, Math.ceil((v.cvss_score || 7) * 0.6)),
          location: v.location || v.url || ''
        }))
      } : null,
      medium_term: vulnerabilityStats.grouped.medium?.length > 0 ? {
        description: `Address ${vulnerabilityStats.grouped.medium.length} medium severity ${pluralize(vulnerabilityStats.grouped.medium.length, 'issue')} within 2-4 weeks as part of regular maintenance.`,
        items: vulnerabilityStats.grouped.medium.slice(0, 5).map(v => ({
          title: v.title || v.name || 'Medium Priority Issue',
          estimated_hours: Math.max(1, Math.ceil((v.cvss_score || 5) * 0.4)),
          location: v.location || v.url || ''
        }))
      } : null,
      long_term: vulnerabilityStats.grouped.low?.length > 0 ? {
        description: `Plan remediation of ${vulnerabilityStats.grouped.low.length} low severity ${pluralize(vulnerabilityStats.grouped.low.length, 'issue')} during scheduled maintenance windows.`,
        items: vulnerabilityStats.grouped.low.slice(0, 5).map(v => ({
          title: v.title || v.name || 'Low Priority Issue',
          estimated_hours: Math.max(1, Math.ceil((v.cvss_score || 3) * 0.3)),
          location: v.location || v.url || ''
        }))
      } : null,
      hardening: vulnerabilityStats.grouped.info?.length > 0 ? {
        description: `Review ${vulnerabilityStats.grouped.info.length} informational ${pluralize(vulnerabilityStats.grouped.info.length, 'finding')} to improve overall security posture and hardening.`,
        items: vulnerabilityStats.grouped.info.slice(0, 5).map(v => ({
          title: v.title || v.name || 'Security Finding',
          estimated_hours: 1,
          location: v.location || v.url || ''
        }))
      } : null
    };

    // Build cost-benefit from vulnerabilities if not provided
    // Costs in Indian Rupees (₹) - dynamically calculated based on actual findings
    // Base rates: Critical ₹4L, High ₹1.5L, Medium ₹75K, Low ₹35K, Info ₹15K per issue
    const baseCriticalCost = 400000;
    const baseHighCost = 150000;
    const baseMediumCost = 75000;
    const baseLowCost = 35000;
    const baseInfoCost = 15000;

    // Calculate cost based on actual CVSS scores when available
    const calculateCost = (vulns, baseCost) => {
      if (!vulns || vulns.length === 0) return 0;
      return vulns.reduce((sum, v) => {
        const cvssMultiplier = v.cvss_score ? (v.cvss_score / 5) : 1;
        return sum + (baseCost * cvssMultiplier);
      }, 0);
    };

    const estimatedCost = Math.round(
      calculateCost(vulnerabilityStats.grouped.critical, baseCriticalCost) +
      calculateCost(vulnerabilityStats.grouped.high, baseHighCost) +
      calculateCost(vulnerabilityStats.grouped.medium, baseMediumCost) +
      calculateCost(vulnerabilityStats.grouped.low, baseLowCost) +
      calculateCost(vulnerabilityStats.grouped.info, baseInfoCost)
    );

    // Potential loss calculation - 10x-50x remediation cost based on severity
    const potentialLoss = Math.round(
      (calculateCost(vulnerabilityStats.grouped.critical, baseCriticalCost) * 20) +
      (calculateCost(vulnerabilityStats.grouped.high, baseHighCost) * 15) +
      (calculateCost(vulnerabilityStats.grouped.medium, baseMediumCost) * 10) +
      (calculateCost(vulnerabilityStats.grouped.low, baseLowCost) * 5) +
      (calculateCost(vulnerabilityStats.grouped.info, baseInfoCost) * 2)
    );

    // Dynamic effort hours based on vulnerability complexity
    const effortHours = Math.round(
      (vulnerabilityStats.grouped.critical || []).reduce((sum, v) => sum + Math.max(4, (v.cvss_score || 9) * 0.8), 0) +
      (vulnerabilityStats.grouped.high || []).reduce((sum, v) => sum + Math.max(3, (v.cvss_score || 7) * 0.6), 0) +
      (vulnerabilityStats.grouped.medium || []).reduce((sum, v) => sum + Math.max(2, (v.cvss_score || 5) * 0.4), 0) +
      (vulnerabilityStats.grouped.low || []).reduce((sum, v) => sum + Math.max(1, (v.cvss_score || 3) * 0.3), 0) +
      (infoCount * 0.5)
    );

    // Build dynamic recommendation based on actual scan findings
    const buildDynamicRecommendation = () => {
      const parts = [];
      if (criticalCount > 0) {
        parts.push(`${criticalCount} critical ${pluralize(criticalCount, 'vulnerability', 'vulnerabilities')} requiring immediate attention (24-48 hours)`);
      }
      if (highCount > 0) {
        parts.push(`${highCount} high severity ${pluralize(highCount, 'issue')} to address within 1 week`);
      }
      if (mediumCount > 0) {
        parts.push(`${mediumCount} medium ${pluralize(mediumCount, 'issue')} for near-term remediation`);
      }
      if (lowCount > 0) {
        parts.push(`${lowCount} low priority ${pluralize(lowCount, 'item')} for scheduled maintenance`);
      }
      if (infoCount > 0) {
        parts.push(`${infoCount} informational ${pluralize(infoCount, 'finding')} for security hardening`);
      }

      if (parts.length === 0) {
        return 'No significant security issues detected. Continue regular security monitoring.';
      }

      const priorityText = criticalCount > 0 ? 'URGENT: ' : highCount > 0 ? 'Priority: ' : '';
      return `${priorityText}Found ${parts.join(', ')}. Estimated remediation effort: ${effortHours} hours.`;
    };

    const effectiveCostBenefit = Object.keys(costBenefit).length > 0 ? costBenefit : {
      total_remediation_cost: estimatedCost,
      potential_loss: potentialLoss,
      net_benefit: potentialLoss - estimatedCost,
      roi_percentage: estimatedCost > 0 ? Math.round((potentialLoss - estimatedCost) / estimatedCost * 100) : 0,
      effort_hours: effortHours,
      recommendation: buildDynamicRecommendation()
    };

    // Build resource allocation if not provided - dynamically calculated
    const weeksNeeded = Math.max(1, Math.ceil(effortHours / 40));
    const maxWeeks = Math.max(weeksNeeded + 1, Math.ceil(effortHours / 20));

    const effectiveResourceAllocation = Object.keys(resourceAllocation).length > 0 ? resourceAllocation : {
      team_composition: {
        'Security Engineers': criticalCount > 0 ? Math.max(2, Math.ceil(criticalCount / 2)) : Math.max(1, Math.ceil(highCount / 3)),
        'Senior Developers': Math.max(1, Math.ceil((criticalCount + highCount) / 3)),
        'Developers': Math.max(1, Math.ceil((mediumCount + lowCount) / 4)),
        'QA Engineers': Math.max(1, Math.ceil(totalFromCounts / 10))
      },
      estimated_timeline: totalFromCounts > 0
        ? `${weeksNeeded} - ${maxWeeks} weeks`
        : 'No remediation needed',
      budget_range: totalFromCounts > 0
        ? `₹${Math.round(estimatedCost * 0.8).toLocaleString('en-IN')} - ₹${Math.round(estimatedCost * 1.2).toLocaleString('en-IN')}`
        : 'N/A'
    };

    // Build recommendations from vulnerabilities if not provided - using tactical terminology
    const effectiveRecommendations = recommendations.length > 0 ? recommendations : [
      ...(criticalCount > 0 ? [{
        title: `Neutralize ${criticalCount} Critical ${pluralize(criticalCount, 'Threat', 'Threats')}`,
        description: 'PRIORITY ALPHA: Critical threats detected in the perimeter. Immediate tactical response required to prevent hostile breach and data exfiltration.',
        priority: 'critical',
        category: 'Emergency Response',
        action_items: vulnerabilityStats.grouped.critical.slice(0, 3).map(v => v.recommendation || `Neutralize: ${v.title || 'Critical threat'}`),
        estimated_effort: `${criticalCount * 8} hours`
      }] : []),
      ...(highCount > 0 ? [{
        title: `Engage ${highCount} High-Value ${pluralize(highCount, 'Target')}`,
        description: 'PRIORITY BRAVO: High-severity hostiles identified. Deploy countermeasures within the current operational window to secure the perimeter.',
        priority: 'high',
        category: 'Tactical Strike',
        action_items: vulnerabilityStats.grouped.high.slice(0, 3).map(v => v.recommendation || `Engage: ${v.title || 'High-value target'}`),
        estimated_effort: `${highCount * 6} hours`
      }] : []),
      ...(mediumCount > 0 ? [{
        title: `Secure ${mediumCount} ${pluralize(mediumCount, 'Sector')}`,
        description: 'PRIORITY CHARLIE: Medium-level vulnerabilities in defensive positions. Schedule systematic sweep to reinforce weak points.',
        priority: 'medium',
        category: 'Perimeter Defense',
        action_items: vulnerabilityStats.grouped.medium.slice(0, 3).map(v => v.recommendation || `Secure: ${v.title || 'Defensive gap'}`),
        estimated_effort: `${mediumCount * 4} hours`
      }] : []),
      ...(lowCount > 0 ? [{
        title: `Patrol ${lowCount} ${pluralize(lowCount, 'Zone')}`,
        description: 'PRIORITY DELTA: Minor anomalies detected. Include in routine patrol schedule to maintain operational readiness.',
        priority: 'low',
        category: 'Routine Patrol',
        action_items: vulnerabilityStats.grouped.low.slice(0, 3).map(v => v.recommendation || `Monitor: ${v.title || 'Minor anomaly'}`),
        estimated_effort: `${lowCount * 2} hours`
      }] : []),
      ...(infoCount > 0 ? [{
        title: `Recon ${infoCount} ${pluralize(infoCount, 'Position')}`,
        description: 'INTEL REPORT: Reconnaissance data gathered. Analyze findings to fortify defenses and enhance situational awareness.',
        priority: 'info',
        category: 'Intelligence Gathering',
        action_items: vulnerabilityStats.grouped.info.slice(0, 3).map(v => v.recommendation || `Analyze: ${v.title || 'Intel item'}`),
        estimated_effort: `${Math.ceil(infoCount * 0.5)} hours`
      }] : [])
    ];

    console.log('Rendering remediation strategies:', strategies);

    return (
      <section className="results-section remediation-section">
        <div className="section-header-box cyan">
          <h2>Defense Playbook</h2>
          <div className="count-badge">{totalIssues}</div>
        </div>

        {/* Vulnerability Overview Summary */}
        {hasVulnerabilities && (
          <div className="playbook-summary">
            <div className="severity-stats-row">
              <div className="severity-stat-block critical-block">
                <span className="severity-count">{criticalCount}</span>
                <span className="severity-name">Critical</span>
              </div>
              <div className="severity-stat-block high-block">
                <span className="severity-count">{highCount}</span>
                <span className="severity-name">High</span>
              </div>
              <div className="severity-stat-block medium-block">
                <span className="severity-count">{mediumCount}</span>
                <span className="severity-name">Medium</span>
              </div>
              <div className="severity-stat-block low-block">
                <span className="severity-count">{lowCount}</span>
                <span className="severity-name">Low</span>
              </div>
              <div className="severity-stat-block info-block">
                <span className="severity-count">{infoCount}</span>
                <span className="severity-name">Info</span>
              </div>
            </div>
          </div>
        )}

        {/* Priority Matrix */}
        {totalIssues > 0 && (
          <div className="playbook-section">
            <div className="playbook-section-header yellow-bg">
              <h3>Threat Assessment Matrix</h3>
            </div>
            <div className="priority-grid">
              {Object.entries(effectivePriorityMatrix)
                .filter(([_, items]) => Array.isArray(items) && items.length > 0)
                .map(([priority, items]) => (
                  <div key={priority} className={`priority-block ${priority}-block`}>
                    <div className="priority-block-header">
                      <span className={`severity-tag ${priority}`}>{priority.toUpperCase()}</span>
                      <span className="issue-count">{items.length} {pluralize(items.length, 'target')}</span>
                    </div>
                    <ul className="issue-list">
                      {items.slice(0, 5).map((item, idx) => (
                        <li key={idx}>
                          <span className="issue-title">{item.title || item.name || item}</span>
                          {(item.location || item.url) && (
                            <code className="issue-location">{item.location || item.url}</code>
                          )}
                        </li>
                      ))}
                      {items.length > 5 && (
                        <li className="more-link">+ {items.length - 5} more</li>
                      )}
                    </ul>
                  </div>
                ))}
            </div>
          </div>
        )}

        {/* Remediation Timeline */}
        {hasVulnerabilities && (
          <div className="playbook-section">
            <div className="playbook-section-header pink-bg">
              <h3>Operation Timeline</h3>
            </div>
            <div className="timeline-grid">
              {effectiveTimeline.immediate_action && (
                <div className="timeline-block critical-border">
                  <div className="timeline-block-header">
                    <span className="timeline-badge coral-bg">CODE RED</span>
                    <span className="timeline-window">0-48 hours</span>
                  </div>
                  <p className="timeline-desc">{effectiveTimeline.immediate_action.description}</p>
                  <div className="timeline-task-list">
                    {effectiveTimeline.immediate_action.items?.map((item, idx) => (
                      <div key={idx} className="timeline-task">
                        <span className="task-name">{item.title || item}</span>
                        {item.estimated_hours && (
                          <span className="task-hours">{item.estimated_hours}h</span>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}
              {effectiveTimeline.short_term && (
                <div className="timeline-block high-border">
                  <div className="timeline-block-header">
                    <span className="timeline-badge yellow-bg">PHASE BRAVO</span>
                    <span className="timeline-window">1-7 days</span>
                  </div>
                  <p className="timeline-desc">{effectiveTimeline.short_term.description}</p>
                  <div className="timeline-task-list">
                    {effectiveTimeline.short_term.items?.map((item, idx) => (
                      <div key={idx} className="timeline-task">
                        <span className="task-name">{item.title || item}</span>
                        {item.estimated_hours && (
                          <span className="task-hours">{item.estimated_hours}h</span>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}
              {effectiveTimeline.medium_term && (
                <div className="timeline-block medium-border">
                  <div className="timeline-block-header">
                    <span className="timeline-badge pink-bg">PHASE CHARLIE</span>
                    <span className="timeline-window">1-4 weeks</span>
                  </div>
                  <p className="timeline-desc">{effectiveTimeline.medium_term.description}</p>
                  <div className="timeline-task-list">
                    {effectiveTimeline.medium_term.items?.map((item, idx) => (
                      <div key={idx} className="timeline-task">
                        <span className="task-name">{item.title || item}</span>
                        {item.estimated_hours && (
                          <span className="task-hours">{item.estimated_hours}h</span>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}
              {effectiveTimeline.long_term && (
                <div className="timeline-block low-border">
                  <div className="timeline-block-header">
                    <span className="timeline-badge green-bg">PHASE DELTA</span>
                    <span className="timeline-window">1-3 months</span>
                  </div>
                  <p className="timeline-desc">{effectiveTimeline.long_term.description}</p>
                  <div className="timeline-task-list">
                    {effectiveTimeline.long_term.items?.map((item, idx) => (
                      <div key={idx} className="timeline-task">
                        <span className="task-name">{item.title || item}</span>
                        {item.estimated_hours && (
                          <span className="task-hours">{item.estimated_hours}h</span>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}
              {effectiveTimeline.hardening && (
                <div className="timeline-block info-border">
                  <div className="timeline-block-header">
                    <span className="timeline-badge cyan-bg">FORTIFY</span>
                    <span className="timeline-window">Ongoing Ops</span>
                  </div>
                  <p className="timeline-desc">{effectiveTimeline.hardening.description}</p>
                  <div className="timeline-task-list">
                    {effectiveTimeline.hardening.items?.map((item, idx) => (
                      <div key={idx} className="timeline-task">
                        <span className="task-name">{item.title || item}</span>
                        {item.estimated_hours && (
                          <span className="task-hours">{item.estimated_hours}h</span>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Cost-Benefit Analysis */}
        {hasVulnerabilities && (
          <div className="playbook-section">
            <div className="playbook-section-header green-bg">
              <h3>Mission Cost Analysis</h3>
            </div>
            <div className="cost-analysis-grid">
              <div className="cost-block investment-block">
                <div className="cost-block-label">Operation Budget</div>
                <div className="cost-block-value">₹{(effectiveCostBenefit.total_remediation_cost || 0).toLocaleString('en-IN')}</div>
                {effectiveCostBenefit.effort_hours && (
                  <div className="cost-block-detail">{effectiveCostBenefit.effort_hours} hours effort</div>
                )}
              </div>
              <div className="cost-block risk-block">
                <div className="cost-block-label">Breach Risk Cost</div>
                <div className="cost-block-value danger">₹{(effectiveCostBenefit.potential_loss || 0).toLocaleString('en-IN')}</div>
                <div className="cost-block-detail">If defenses fail</div>
              </div>
              <div className="cost-block benefit-block">
                <div className="cost-block-label">Strategic Advantage</div>
                <div className="cost-block-value success">₹{(effectiveCostBenefit.net_benefit || 0).toLocaleString('en-IN')}</div>
                {effectiveCostBenefit.roi_percentage && (
                  <div className="cost-block-detail">Mission ROI: {Math.round(effectiveCostBenefit.roi_percentage)}%</div>
                )}
              </div>
            </div>
            {effectiveCostBenefit.recommendation && (
              <div className="recommendation-banner">
                <strong>Mission Brief:</strong> {effectiveCostBenefit.recommendation}
              </div>
            )}
          </div>
        )}

        {/* Resource Allocation */}
        {hasVulnerabilities && (
          <div className="playbook-section">
            <div className="playbook-section-header purple-bg">
              <h3>Unit Deployment</h3>
            </div>
            <div className="resource-allocation-grid">
              {effectiveResourceAllocation.team_composition && (
                <div className="resource-block team-block">
                  <div className="resource-block-header">Strike Team</div>
                  <ul className="team-roster">
                    {Object.entries(effectiveResourceAllocation.team_composition).map(([role, count]) => (
                      <li key={role}>
                        <span className="role-title">{role}</span>
                        <span className="role-badge">{count}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
              {effectiveResourceAllocation.estimated_timeline && (
                <div className="resource-block duration-block">
                  <div className="resource-block-header">Mission Duration</div>
                  <div className="resource-block-value">{effectiveResourceAllocation.estimated_timeline}</div>
                </div>
              )}
              {effectiveResourceAllocation.budget_range && (
                <div className="resource-block budget-block">
                  <div className="resource-block-header">Resource Allocation</div>
                  <div className="resource-block-value">{effectiveResourceAllocation.budget_range}</div>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Mission Directives */}
        {effectiveRecommendations.length > 0 && (
          <div className="playbook-section">
            <div className="playbook-section-header coral-bg">
              <h3>Mission Directives</h3>
            </div>
            <div className="recommendations-grid">
              {effectiveRecommendations.map((rec, index) => (
                <div key={index} className={`rec-block ${rec.priority?.toLowerCase() || 'medium'}-rec`}>
                  <div className="rec-block-header">
                    <span className={`severity-tag ${rec.priority?.toLowerCase() || 'medium'}`}>
                      {rec.priority?.toUpperCase() || 'MEDIUM'}
                    </span>
                    {rec.category && <span className="rec-tag">{rec.category}</span>}
                  </div>
                  <h4 className="rec-title">{rec.title || `Directive ${index + 1}`}</h4>
                  <p className="rec-desc">{rec.description || rec.recommendation}</p>
                  {rec.action_items && rec.action_items.length > 0 && (
                    <div className="rec-actions">
                      <strong>Tactical Actions:</strong>
                      <ul>
                        {rec.action_items.filter(a => a).map((action, idx) => (
                          <li key={idx}>{action}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                  {rec.estimated_effort && (
                    <div className="rec-effort">{rec.estimated_effort}</div>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}

        {!hasVulnerabilities && (
          <div className="no-issues-found">
            <h3>No Vulnerabilities Detected</h3>
            <p>Great news! No security issues were found during this scan. Your application appears to be secure based on the tests performed.</p>
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
  console.log('Rendering ScanResults component');
  console.log('  - Active tab:', activeTab);
  console.log('  - Results loaded:', !!results);
  console.log('  - Results data:', results);

  return (
    <Layout>
      <div className="scan-results-container">
        <header className="results-header">
          <div className="header-content">
            <h1>Scan Results</h1>
            <Link to="/" className="back-button">← Back to Home</Link>
          </div>
          <div className="scan-info">
            <div className="scan-info-item">
              <span className="scan-info-label">Target</span>
              <span
                className="scan-info-value scan-info-value-target"
                title={results.target_url || 'Not available'}
              >
                {results.target_url || 'Not available'}
              </span>
            </div>
            <div className="scan-info-item">
              <span className="scan-info-label">Scan ID</span>
              <span className="scan-info-value">
                <code>{scanId}</code>
              </span>
            </div>
            {results.started_at && (
              <div className="scan-info-item">
                <span className="scan-info-label">Started</span>
                <span className="scan-info-value">
                  {new Date(results.started_at).toLocaleString()}
                </span>
              </div>
            )}
            {results.completed_at && (
              <div className="scan-info-item">
                <span className="scan-info-label">Completed</span>
                <span className="scan-info-value">
                  {new Date(results.completed_at).toLocaleString()}
                </span>
              </div>
            )}
            <div className="scan-info-item">
              <span className="scan-info-label">Status</span>
              <span className="scan-info-value">
                <span className="status-badge">{results.status}</span>
              </span>
            </div>
          </div>
        </header>

        {availableTabs.length > 0 && (
          <div className="tabs-container">
            {availableTabs.map((tab) => {
              const tabColors = {
                summary: 'tab-yellow',
                overview: 'tab-pink',
                vulnerabilities: 'tab-coral',
                mitre: 'tab-green',
                remediation: 'tab-cyan',
                ai: 'tab-purple'
              };
              return (
                <button
                  key={tab.id}
                  className={`tab ${tabColors[tab.id] || ''} ${activeTab === tab.id ? 'active' : ''}`}
                  onClick={() => setActiveTab(tab.id)}
                >
                  {tab.display}
                </button>
              );
            })}
          </div>
        )}

        <div className="tabs-content">
          {activeTab === 'overview' && renderRiskSection()}
          {activeTab === 'summary' && summaryTabVisible && renderExecutiveSummary()}
          {activeTab === 'vulnerabilities' && renderVulnerabilitySection()}
          {activeTab === 'mitre' && renderMITRESection()}
          {activeTab === 'remediation' && hasRemediationData && renderRemediationStrategies()}
          {activeTab === 'ai' && renderAIAnalysis()}
        </div>
      </div>
    </Layout>
  );
};

export default ScanResults;