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
      unknown: 0
    };

    const grouped = {
      critical: [],
      high: [],
      medium: [],
      low: [],
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

    const providedScore = Number.isFinite(baseRisk.overall_risk_score)
      ? Number(baseRisk.overall_risk_score)
      : null;

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

    const normalizedScore = providedScore !== null
      ? providedScore
      : Number(fallbackScore.toFixed(2));

    const riskLevel = baseRisk.risk_level || deriveRiskLevel(normalizedScore);

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
  }, [results]);

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
          ? (remediationRecommendationsCount
            ? `Defense Playbook (${remediationRecommendationsCount})`
            : 'Defense Playbook')
          : null,
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
    const colorMap = ['cyan', 'coral', 'green', 'pink', 'yellow'];

    return (
      <section className="results-section detailed-outline">
        <div className="section-header-box yellow">
          <h2>Threat Catalog</h2>
          <div className="count-badge">{vulnerabilityStats.total}</div>
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
            <div className="no-vulns-container">
              <div className="no-vulns-icon">OK</div>
              <h3>No Threats Detected</h3>
              <p>The scan completed without identifying vulnerabilities in the target.</p>
              <div className="no-vulns-details">
                <p><strong>Note:</strong> This does not guarantee the application is secure. Consider:</p>
                <ul>
                  <li>Running a Deep scan for more comprehensive analysis</li>
                  <li>Checking if the target URL was accessible during the scan</li>
                  <li>Verifying authentication if the target requires login</li>
                  <li>Manual security testing for business logic flaws</li>
                </ul>
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
        <div className="section-header-box coral">
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

    console.log('Rendering remediation strategies:', strategies);

    return (
      <section className="results-section remediation-section">
        <div className="section-header-box pink">
          <h2>Defense Playbook</h2>
          <div className="count-badge">{recommendations.length}</div>
        </div>

        {/* Priority Matrix */}
        {Object.keys(priorityMatrix).length > 0 && (
          <div className="strategy-subsection">
            <h3>Priority Matrix</h3>
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
            <h3>Remediation Timeline</h3>
            <div className="timeline-overview">
              {timeline.immediate_action && (
                <div className="timeline-phase critical-phase">
                  <h4>Immediate Action (0-7 days)</h4>
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
                  <h4>Short Term (1-4 weeks)</h4>
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
                  <h4>Medium Term (1-3 months)</h4>
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
                  <h4>Long Term (3+ months)</h4>
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
            <h3>Cost-Benefit Analysis</h3>
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
                <strong>Recommendation:</strong> {costBenefit.recommendation}
              </div>
            )}
          </div>
        )}

        {/* Resource Allocation */}
        {Object.keys(resourceAllocation).length > 0 && (
          <div className="strategy-subsection">
            <h3>Resource Allocation</h3>
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
            <h3>Actionable Recommendations</h3>
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
            {availableTabs.map((tab) => (
              <button
                key={tab.id}
                className={`tab ${activeTab === tab.id ? 'active' : ''}`}
                onClick={() => setActiveTab(tab.id)}
              >
                {tab.display}
              </button>
            ))}
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