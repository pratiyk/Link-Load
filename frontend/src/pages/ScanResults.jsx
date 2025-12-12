import React, { useEffect, useMemo, useState } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import Layout from '../components/Layout';
import scannerService from '../services/scannerService';
import './ScanResults.css';

const severityOrder = ['critical', 'high', 'medium', 'low'];
const severityWeights = {
  critical: 10,
  high: 7.5,
  medium: 5,
  low: 2,
  info: 1,
  unknown: 0.5
};

const deriveRiskLevel = (score) => {
  if (score === null || score === undefined) return 'Unknown';
  if (score >= 8) return 'Critical';
  if (score >= 6) return 'High';
  if (score >= 4) return 'Medium';
  if (score >= 2) return 'Low';
  return 'Minimal';
};

// Dynamic duration calculation based on vulnerability count and CVSS
const computeDynamicDuration = (itemCount, avgCvss, baseMultiplier = 1) => {
  if (itemCount === 0) return 0;

  // Base hours per vulnerability by complexity
  const hoursPerVuln = avgCvss >= 7 ? 8 : avgCvss >= 4 ? 4 : 2;
  const totalHours = itemCount * hoursPerVuln * baseMultiplier;

  // Convert to days (6 productive hours per day)
  const days = Math.ceil(totalHours / 6);

  // Add buffer for testing/validation (20%)
  return Math.max(1, Math.ceil(days * 1.2));
};

const computeTimelineDuration = (timelineInfo, fallback, itemCount = 0, avgCvss = 0) => {
  // If we have actual items, calculate dynamically
  if (itemCount > 0) {
    return computeDynamicDuration(itemCount, avgCvss);
  }

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

// Dynamic label generation based on actual week numbers
const getDynamicLabel = (weekStart, weekEnd, priority) => {
  const weekStartNum = Math.ceil(weekStart / 7);
  const weekEndNum = Math.ceil(weekEnd / 7);

  if (weekStartNum === weekEndNum || weekEndNum === 0) {
    return `Week ${Math.max(1, weekStartNum)}`;
  }
  return `Week ${Math.max(1, weekStartNum)}-${weekEndNum}`;
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
  const [activeTab, setActiveTab] = useState('summary'); // Default to Mission Brief
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

  // Centralized shared metrics - used across all tabs for consistency
  const sharedMetrics = useMemo(() => {
    const criticalCount = vulnerabilityStats.counts?.critical || 0;
    const highCount = vulnerabilityStats.counts?.high || 0;
    const mediumCount = vulnerabilityStats.counts?.medium || 0;
    const lowCount = vulnerabilityStats.counts?.low || 0;
    const infoCount = vulnerabilityStats.counts?.info || 0;
    const totalIssues = vulnerabilityStats.total || 0;

    // Cost calculations - Based on industry standards (IBM Cost of Data Breach 2024)
    const baseCriticalCost = 50000;
    const baseHighCost = 25000;
    const baseMediumCost = 12000;
    const baseLowCost = 5000;
    const baseInfoCost = 2000;

    const calculateCost = (vulns, baseCost) => {
      if (!vulns || vulns.length === 0) return 0;
      return vulns.reduce((sum, v) => {
        const cvssMultiplier = v.cvss_score ? Math.max(0.5, v.cvss_score / 5) : 1;
        return sum + (baseCost * cvssMultiplier);
      }, 0);
    };

    const estimatedCost = Math.round(
      calculateCost(vulnerabilityStats.grouped?.critical, baseCriticalCost) +
      calculateCost(vulnerabilityStats.grouped?.high, baseHighCost) +
      calculateCost(vulnerabilityStats.grouped?.medium, baseMediumCost) +
      calculateCost(vulnerabilityStats.grouped?.low, baseLowCost) +
      calculateCost(vulnerabilityStats.grouped?.info, baseInfoCost)
    );

    const potentialLoss = Math.round(
      (calculateCost(vulnerabilityStats.grouped?.critical, baseCriticalCost) * 15) +
      (calculateCost(vulnerabilityStats.grouped?.high, baseHighCost) * 10) +
      (calculateCost(vulnerabilityStats.grouped?.medium, baseMediumCost) * 6) +
      (calculateCost(vulnerabilityStats.grouped?.low, baseLowCost) * 3) +
      (calculateCost(vulnerabilityStats.grouped?.info, baseInfoCost) * 1.5)
    );

    // Effort hours calculation
    const effortHours = Math.round(
      (vulnerabilityStats.grouped?.critical || []).reduce((sum, v) => sum + Math.max(4, (v.cvss_score || 9) * 0.8), 0) +
      (vulnerabilityStats.grouped?.high || []).reduce((sum, v) => sum + Math.max(3, (v.cvss_score || 7) * 0.6), 0) +
      (vulnerabilityStats.grouped?.medium || []).reduce((sum, v) => sum + Math.max(2, (v.cvss_score || 5) * 0.4), 0) +
      (vulnerabilityStats.grouped?.low || []).reduce((sum, v) => sum + Math.max(1, (v.cvss_score || 3) * 0.3), 0) +
      (infoCount * 0.5)
    );

    const netBenefit = potentialLoss - estimatedCost;
    const roiPercentage = estimatedCost > 0 ? Math.round((netBenefit / estimatedCost) * 100) : 0;

    // Risk score calculation - NOTE: This is a different metric from normalizedRisk.overall_risk_score
    // normalizedRisk uses 0-10 CVSS-like scale, while this is a weighted count-based score (0-100)
    // For consistency, we'll use a 0-10 scale to match normalizedRisk
    const weightedScore = (criticalCount * 10 + highCount * 7.5 + mediumCount * 5 + lowCount * 2 + infoCount * 0.5);
    const maxPossibleScore = Math.max(1, totalIssues * 10); // Normalize by max possible
    const riskScore = totalIssues > 0 ? Math.min(10, Number((weightedScore / totalIssues).toFixed(1))) : 0;
    const riskLevel = riskScore >= 8 ? 'Critical' : riskScore >= 6 ? 'High' : riskScore >= 4 ? 'Medium' : riskScore >= 2 ? 'Low' : 'Minimal';

    // Timeline calculations
    const weeksNeeded = Math.max(1, Math.ceil(effortHours / 40));
    const maxWeeks = Math.max(weeksNeeded + 1, Math.ceil(effortHours / 20));
    const estimatedTimeline = totalIssues > 0 ? `${weeksNeeded} - ${maxWeeks} weeks` : 'No remediation needed';

    // Team composition
    const teamComposition = {
      'Security Engineers': criticalCount > 0 ? Math.max(2, Math.ceil(criticalCount / 2)) : Math.max(1, Math.ceil(highCount / 3)),
      'Senior Developers': Math.max(1, Math.ceil((criticalCount + highCount) / 3)),
      'Developers': Math.max(1, Math.ceil((mediumCount + lowCount) / 4)),
      'QA Engineers': Math.max(1, Math.ceil(totalIssues / 10))
    };

    return {
      criticalCount,
      highCount,
      mediumCount,
      lowCount,
      infoCount,
      totalIssues,
      estimatedCost,
      potentialLoss,
      netBenefit,
      roiPercentage,
      effortHours,
      riskScore,
      riskLevel,
      weeksNeeded,
      maxWeeks,
      estimatedTimeline,
      teamComposition,
      budgetRange: totalIssues > 0
        ? `₹${Math.round(estimatedCost * 0.8).toLocaleString('en-IN')} - ₹${Math.round(estimatedCost * 1.2).toLocaleString('en-IN')}`
        : 'N/A'
    };
  }, [vulnerabilityStats]);

  const aiInsightsCount = results?.ai_analysis?.length || 0;

  // Calculate MITRE count - use backend data if available, otherwise estimate from vulnerabilities
  const mitreCount = useMemo(() => {
    // First check if backend provided MITRE mappings
    if (results?.mitre_mapping?.length > 0) {
      return results.mitre_mapping.length;
    }

    // If no backend mappings but we have vulnerabilities, estimate potential mappings
    // This ensures the Attack Matrix tab shows up when there are vulnerabilities to map
    if (results?.vulnerabilities?.length > 0) {
      // Count unique potential MITRE mappings based on vulnerability patterns
      const patterns = [
        /sql injection|sqli/i, /xss|cross-site scripting/i, /command injection|rce/i,
        /authentication|login|password/i, /file upload/i, /path traversal|lfi/i,
        /ssrf/i, /xxe/i, /csrf/i, /\.git|\.svn/i, /exposed|sensitive|leaked/i,
        /header|cors|csp/i, /certificate|ssl|tls/i, /cookie|session/i,
        /admin|management/i, /outdated|cve/i, /information disclosure/i
      ];

      const seenPatterns = new Set();
      for (const vuln of results.vulnerabilities) {
        const text = `${vuln.title || ''} ${vuln.description || ''}`;
        for (let i = 0; i < patterns.length; i++) {
          if (patterns[i].test(text)) {
            seenPatterns.add(i);
          }
        }
      }
      return seenPatterns.size;
    }

    return 0;
  }, [results]);

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
    const info = vulnerabilityStats.counts?.info || 0;
    const mediumLowTotal = medium + low;
    const avgCvss = vulnerabilityStats.avgCvss;
    const topCritical = vulnerabilityStats.grouped?.critical?.[0]?.title;
    const topHigh = vulnerabilityStats.grouped?.high?.[0]?.title;
    const topInfo = vulnerabilityStats.grouped?.info?.[0]?.title;
    const topFinding = vulnerabilityStats.highest?.title || vulnerabilityStats.highest?.name;

    // Threat Intelligence data
    const threatIntel = results.threat_intel || {};
    const reputation = threatIntel.reputation || {};
    const vt = threatIntel.virustotal || {};
    const gsb = threatIntel.google_safe_browsing || {};
    const abuse = threatIntel.abuseipdb || {};
    const shodan = threatIntel.shodan || {};
    const vulners = threatIntel.vulners || {};
    const riskIndicators = threatIntel.risk_indicators || [];

    // Build threat intel description
    const buildThreatIntelDesc = () => {
      const parts = [];

      if (reputation.score !== undefined) {
        const scoreLabel = reputation.score >= 70 ? 'Good' : reputation.score >= 40 ? 'Moderate' : 'Poor';
        parts.push(`Reputation: ${reputation.score}/100 (${scoreLabel})`);
      }

      if (vt.malicious > 0 || vt.suspicious > 0) {
        parts.push(`VirusTotal: ${vt.malicious || 0} malicious, ${vt.suspicious || 0} suspicious`);
      } else if (vt.harmless > 0) {
        parts.push(`VirusTotal: Clean (${vt.harmless} vendors)`);
      }

      if (gsb.is_flagged) {
        parts.push(`Google Safe Browsing: FLAGGED`);
      }

      if (abuse.abuse_confidence_score > 0) {
        parts.push(`AbuseIPDB: ${abuse.abuse_confidence_score}% confidence`);
      }

      if (shodan.vuln_count > 0) {
        parts.push(`Shodan: ${shodan.vuln_count} known vulns`);
      }

      // Add Vulners exploit info
      if (vulners.total_exploits > 0) {
        parts.push(`Vulners: ${vulners.total_exploits} exploits found`);
      }

      if (parts.length === 0) {
        return threatIntel.data_sources_queried
          ? `${threatIntel.data_sources_queried} intel sources queried — no active threats detected.`
          : 'Threat intelligence not yet collected.';
      }

      return parts.slice(0, 2).join(' • ') + (parts.length > 2 ? ` (+${parts.length - 2} more)` : '');
    };

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
        key: 'threat_intel',
        number: '04',
        title: 'Threat Intelligence',
        color: 'purple',
        description: buildThreatIntelDesc()
      },
      {
        key: 'coverage',
        number: '05',
        title: 'Coverage & Mapping',
        color: 'pink',
        description: mitreCount
          ? `${pluralize(mitreCount, 'MITRE technique')} mapped to help trace attack paths.`
          : 'No MITRE techniques mapped for this scan run.'
      },
      {
        key: 'insights',
        number: '06',
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
        visible: true  // Always show - will display loading/error/empty state as needed
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
        visible: true  // Always show - will generate client-side mappings or show empty state
      },
      {
        id: 'remediation',
        label: 'Defense Playbook',
        display: hasRemediationData
          ? `Defense Playbook (${vulnerabilityStats.total || remediationRecommendationsCount || 0})`
          : 'Defense Playbook',
        visible: true  // Always show - will display empty state if no data
      },
      {
        id: 'ai',
        label: 'Intel Analysis',
        display: aiInsightsCount ? `Intel Analysis (${aiInsightsCount})` : 'Intel Analysis',
        visible: true  // Always show - will display empty state or generate from vulns
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
              Return to Base
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
              Return to Base
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
                    {vuln.has_known_exploit && (
                      <div className="exploit-warning">
                        <span className="exploit-icon">!</span>
                        <span className="exploit-text">Known exploit available</span>
                        {vuln.vulners_exploits?.length > 0 && (
                          <span className="exploit-count">({vuln.vulners_exploits.length} found)</span>
                        )}
                      </div>
                    )}
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
    let techniques = results.mitre_mapping || [];
    console.log('[RENDER] Rendering MITRE section with', techniques.length, 'techniques from backend');

    // Client-side fallback: Generate MITRE mappings from vulnerabilities if backend didn't provide them
    if (techniques.length === 0 && results.vulnerabilities?.length > 0) {
      const vulnMappings = [];
      const seenTechniques = new Set();

      // MITRE ATT&CK mapping rules based on vulnerability patterns
      const mitrePatterns = [
        { pattern: /sql injection|sqli/i, id: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'Initial Access' },
        { pattern: /xss|cross-site scripting/i, id: 'T1059.007', name: 'JavaScript', tactic: 'Execution' },
        { pattern: /command injection|rce|remote code/i, id: 'T1059', name: 'Command and Scripting Interpreter', tactic: 'Execution' },
        { pattern: /authentication|login|password|brute/i, id: 'T1110', name: 'Brute Force', tactic: 'Credential Access' },
        { pattern: /file upload/i, id: 'T1105', name: 'Ingress Tool Transfer', tactic: 'Command and Control' },
        { pattern: /path traversal|directory traversal|lfi/i, id: 'T1083', name: 'File and Directory Discovery', tactic: 'Discovery' },
        { pattern: /ssrf|server-side request/i, id: 'T1090', name: 'Proxy', tactic: 'Command and Control' },
        { pattern: /xxe|xml external/i, id: 'T1203', name: 'Exploitation for Client Execution', tactic: 'Execution' },
        { pattern: /csrf|cross-site request/i, id: 'T1185', name: 'Browser Session Hijacking', tactic: 'Collection' },
        { pattern: /deserialization/i, id: 'T1059', name: 'Command and Scripting Interpreter', tactic: 'Execution' },
        { pattern: /\.git|\.svn|version control/i, id: 'T1213.003', name: 'Code Repositories', tactic: 'Collection' },
        { pattern: /exposed|sensitive|leaked/i, id: 'T1552', name: 'Unsecured Credentials', tactic: 'Credential Access' },
        { pattern: /header|cors|csp|hsts/i, id: 'T1189', name: 'Drive-by Compromise', tactic: 'Initial Access' },
        { pattern: /certificate|ssl|tls/i, id: 'T1557', name: 'Adversary-in-the-Middle', tactic: 'Credential Access' },
        { pattern: /cookie|session/i, id: 'T1539', name: 'Steal Web Session Cookie', tactic: 'Credential Access' },
        { pattern: /admin|management|console/i, id: 'T1078', name: 'Valid Accounts', tactic: 'Persistence' },
        { pattern: /outdated|vulnerable version|cve/i, id: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'Initial Access' },
        { pattern: /information disclosure|error/i, id: 'T1592', name: 'Gather Victim Host Information', tactic: 'Reconnaissance' },
        { pattern: /waf|firewall/i, id: 'T1518.001', name: 'Security Software Discovery', tactic: 'Discovery' },
        { pattern: /technology|framework|wappalyzer/i, id: 'T1592.002', name: 'Gather Victim Host Information: Software', tactic: 'Reconnaissance' },
        { pattern: /endpoint|api|swagger/i, id: 'T1595.002', name: 'Active Scanning: Vulnerability Scanning', tactic: 'Reconnaissance' },
      ];

      for (const vuln of results.vulnerabilities) {
        const combinedText = `${vuln.title || ''} ${vuln.description || ''}`.toLowerCase();

        for (const rule of mitrePatterns) {
          if (rule.pattern.test(combinedText) && !seenTechniques.has(rule.id)) {
            seenTechniques.add(rule.id);
            vulnMappings.push({
              id: rule.id,
              name: rule.name,
              tactic: rule.tactic,
              description: `Mapped from vulnerability: ${vuln.title || 'Security Finding'}`,
              confidence: 0.7,
              source: 'client-side'
            });
          }
        }
      }

      if (vulnMappings.length > 0) {
        techniques = vulnMappings;
        console.log('[RENDER] Generated', techniques.length, 'client-side MITRE mappings from vulnerabilities');
      }
    }

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
                  {technique.confidence && (
                    <p className="confidence-label">Confidence: <span>{Math.round(technique.confidence * 100)}%</span></p>
                  )}
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="no-results">
            <p>No MITRE ATT&CK techniques mapped for this scan. Run a new scan with vulnerability detection to see attack technique mappings.</p>
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

    // Threat intel data for detailed display
    const threatIntel = results.threat_intel || {};
    const reputation = threatIntel.reputation || {};
    const vt = threatIntel.virustotal || {};
    const gsb = threatIntel.google_safe_browsing || {};
    const abuse = threatIntel.abuseipdb || {};
    const shodan = threatIntel.shodan || {};
    const sectrails = threatIntel.securitytrails || {};
    const leakLookup = threatIntel.leak_lookup || {};
    const vulners = threatIntel.vulners || {};
    const target = threatIntel.target || {};
    const riskIndicators = threatIntel.risk_indicators || [];
    const hasThreatIntel = threatIntel.data_sources_queried > 0;

    const getReputationColorClass = (score) => {
      if (score >= 70) return 'green-bg';
      if (score >= 40) return 'yellow-bg';
      return 'coral-bg';
    };

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

        {/* Threat Intelligence Details Section */}
        {hasThreatIntel && (
          <div className="threat-intel-details">
            <h3 className="intel-section-title">External Intelligence Sources</h3>

            <div className="intel-source-grid">
              {/* Reputation Score */}
              {reputation.score !== undefined && (
                <div
                  className={`intel-source-card ${getReputationColorClass(reputation.score)}`}
                  title="Aggregated reputation score from multiple threat intelligence sources. Scores below 40 indicate high risk, 40-70 moderate risk, and above 70 low risk."
                >
                  <div className="intel-source-header">
                    <span className="intel-source-icon">REP</span>
                    <span className="intel-source-name">Reputation Score</span>
                  </div>
                  <div className="intel-source-value">{reputation.score}/100</div>
                  <div className="intel-source-detail">{reputation.risk_level || 'Unknown'} • {reputation.sources_checked || 0} sources</div>
                </div>
              )}

              {/* VirusTotal */}
              {(vt.malicious !== undefined || vt.harmless !== undefined) && (
                <div
                  className={`intel-source-card ${vt.malicious > 0 ? 'coral-bg' : vt.suspicious > 0 ? 'yellow-bg' : 'green-bg'}`}
                  title="VirusTotal aggregates results from 70+ antivirus engines and URL/domain scanners. Malicious detections indicate the target was flagged as harmful by security vendors."
                >
                  <div className="intel-source-header">
                    <span className="intel-source-icon">VT</span>
                    <span className="intel-source-name">VirusTotal</span>
                  </div>
                  <div className="intel-source-value">
                    {vt.malicious > 0 ? `${vt.malicious} Malicious` : vt.suspicious > 0 ? `${vt.suspicious} Suspicious` : 'Clean'}
                  </div>
                  <div className="intel-source-detail">{vt.total_engines || 0} engines scanned</div>
                </div>
              )}

              {/* Google Safe Browsing */}
              {gsb.status && (
                <div
                  className={`intel-source-card ${gsb.is_flagged ? 'coral-bg' : 'green-bg'}`}
                  title="Google Safe Browsing checks URLs against Google's constantly updated lists of unsafe web resources including malware, phishing, and unwanted software sites."
                >
                  <div className="intel-source-header">
                    <span className="intel-source-icon">GSB</span>
                    <span className="intel-source-name">Safe Browsing</span>
                  </div>
                  <div className="intel-source-value">{gsb.is_flagged ? 'FLAGGED' : 'Safe'}</div>
                  <div className="intel-source-detail">{gsb.is_flagged ? gsb.threat_types?.join(', ') || 'Threat detected' : 'No threats found'}</div>
                </div>
              )}

              {/* AbuseIPDB */}
              {abuse.ip_address && (
                <div
                  className={`intel-source-card ${abuse.abuse_confidence_score > 50 ? 'coral-bg' : abuse.abuse_confidence_score > 25 ? 'yellow-bg' : 'green-bg'}`}
                  title="AbuseIPDB is a crowd-sourced IP address abuse database. The confidence score indicates the likelihood that the IP is involved in malicious activity based on user reports."
                >
                  <div className="intel-source-header">
                    <span className="intel-source-icon">ADB</span>
                    <span className="intel-source-name">AbuseIPDB</span>
                  </div>
                  <div className="intel-source-value">{abuse.abuse_confidence_score || 0}%</div>
                  <div className="intel-source-detail">{abuse.total_reports || 0} reports • {abuse.isp || 'Unknown ISP'}</div>
                </div>
              )}

              {/* Shodan */}
              {shodan.ip && (
                <div
                  className={`intel-source-card ${shodan.vuln_count > 0 ? 'coral-bg' : 'cyan-bg'}`}
                  title="Shodan is a search engine for Internet-connected devices. It reveals open ports, running services, and known vulnerabilities on the target's IP address."
                >
                  <div className="intel-source-header">
                    <span className="intel-source-icon">SHD</span>
                    <span className="intel-source-name">Shodan</span>
                  </div>
                  <div className="intel-source-value">{shodan.open_ports_count || 0} Ports</div>
                  <div className="intel-source-detail">{shodan.vuln_count || 0} vulns • {shodan.services?.length || 0} services</div>
                </div>
              )}

              {/* SecurityTrails */}
              {sectrails.subdomains_count !== undefined && (
                <div
                  className="intel-source-card blue-bg"
                  title="SecurityTrails provides DNS intelligence including historical records, subdomains, and domain ownership data to map the target's infrastructure."
                >
                  <div className="intel-source-header">
                    <span className="intel-source-icon">STR</span>
                    <span className="intel-source-name">SecurityTrails</span>
                  </div>
                  <div className="intel-source-value">{sectrails.subdomains_count || 0} Subdomains</div>
                  <div className="intel-source-detail">{sectrails.alexa_rank ? `Alexa: ${sectrails.alexa_rank}` : 'DNS records available'}</div>
                </div>
              )}

              {/* Leak Lookup */}
              {leakLookup.status && (
                <div
                  className={`intel-source-card ${leakLookup.breaches_found ? 'coral-bg' : 'green-bg'}`}
                  title="Leak Lookup searches known data breach databases to check if the domain or associated accounts have been compromised in past security incidents."
                >
                  <div className="intel-source-header">
                    <span className="intel-source-icon">BRC</span>
                    <span className="intel-source-name">Breach Check</span>
                  </div>
                  <div className="intel-source-value">{leakLookup.breaches_found ? 'Breached' : 'No Breaches'}</div>
                  <div className="intel-source-detail">{leakLookup.breach_sources?.length || 0} sources checked</div>
                </div>
              )}

              {/* Vulners Exploit Database */}
              {vulners.total_exploits !== undefined && (
                <div
                  className={`intel-source-card ${vulners.total_exploits > 0 ? 'coral-bg' : 'green-bg'}`}
                  title="Vulners is a vulnerability database that aggregates exploits, security advisories, and CVE data. Finding exploits means attackers have ready-to-use attack code."
                >
                  <div className="intel-source-header">
                    <span className="intel-source-icon">VLN</span>
                    <span className="intel-source-name">Vulners Exploits</span>
                  </div>
                  <div className="intel-source-value">{vulners.total_exploits || 0} Exploits</div>
                  <div className="intel-source-detail">
                    {vulners.cves_searched?.length || 0} CVEs searched • {vulners.vulnerabilities_found || 0} vulns
                  </div>
                </div>
              )}
            </div>

            {/* Risk Indicators */}
            {riskIndicators.length > 0 && (
              <div className="risk-indicators-section">
                <h4 className="risk-indicators-title">Active Risk Indicators</h4>
                <div className="risk-indicators-compact">
                  {riskIndicators.slice(0, 5).map((indicator, idx) => (
                    <div key={idx} className={`risk-indicator-chip ${indicator.severity}`}>
                      <span className="indicator-source-tag">{indicator.source}</span>
                      <span className="indicator-detail">{indicator.type}: {indicator.details}</span>
                    </div>
                  ))}
                  {riskIndicators.length > 5 && (
                    <div className="risk-indicator-chip info">+{riskIndicators.length - 5} more indicators</div>
                  )}
                </div>
              </div>
            )}
          </div>
        )}
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

    // Calculate average CVSS for each severity bucket for dynamic effort estimation
    const calculateBucketAvgCvss = (items) => {
      if (!items || items.length === 0) return 0;
      const validScores = items.filter(v => typeof v.cvss_score === 'number' && !Number.isNaN(v.cvss_score));
      if (validScores.length === 0) return 0;
      return validScores.reduce((sum, v) => sum + v.cvss_score, 0) / validScores.length;
    };

    // Dynamic priority configuration - labels will be generated based on actual data
    const priorityConfig = {
      critical: { baseLabel: 'Critical', className: 'cyan', accentColor: '#6DD4D9', symbol: '!', urgency: 'Immediate' },
      high: { baseLabel: 'High', className: 'coral', accentColor: '#FF6B6B', symbol: 'H', urgency: 'Urgent' },
      medium: { baseLabel: 'Medium', className: 'pink', accentColor: '#E39FCE', symbol: 'M', urgency: 'Planned' },
      low: { baseLabel: 'Low', className: 'yellow', accentColor: '#FFD93D', symbol: 'L', urgency: 'Scheduled' },
      info: { baseLabel: 'Info', className: 'blue', accentColor: '#64B5F6', symbol: 'i', urgency: 'Monitor' }
    };

    const mapInsightToPriority = (insight) => {
      const prioritySource = `${insight.priority || ''} ${insight.priority_key || ''} ${insight.priority_level || ''} ${insight.remediation_priority || ''} ${insight.timeframe || ''} ${insight.window || ''} ${insight.urgency || ''}`.toLowerCase();
      if (prioritySource.includes('critical') || prioritySource.includes('immediate') || prioritySource.includes('now')) return 'critical';
      if (prioritySource.includes('high') || prioritySource.includes('urgent') || prioritySource.includes('week')) return 'high';
      if (prioritySource.includes('medium') || prioritySource.includes('month') || prioritySource.includes('quarter') || prioritySource.includes('sprint')) return 'medium';
      if (prioritySource.includes('info') || prioritySource.includes('informational') || prioritySource.includes('monitor')) return 'info';
      return 'low';
    };

    const insightsByPriority = {
      critical: [],
      high: [],
      medium: [],
      low: [],
      info: []
    };

    aiInsights.forEach((insight) => {
      const priority = mapInsightToPriority(insight);
      insightsByPriority[priority].push(insight);
    });

    // Dynamic bucket configuration - no more static defaultDuration values
    const bucketsConfig = [
      { key: 'critical', timelineKey: 'immediate_action', effortMultiplier: 1.5 },
      { key: 'high', timelineKey: 'short_term', effortMultiplier: 1.2 },
      { key: 'medium', timelineKey: 'medium_term', effortMultiplier: 1.0 },
      { key: 'low', timelineKey: 'long_term', effortMultiplier: 0.8 },
      { key: 'info', timelineKey: 'monitoring', effortMultiplier: 0.3 }
    ];

    let currentStart = 0;
    const timelineData = [];

    bucketsConfig.forEach(({ key, timelineKey, effortMultiplier }) => {
      const severityItems = severityBuckets[key] || [];
      const bucketInsights = insightsByPriority[key] || [];
      const timelineInfo = strategiesTimeline[timelineKey];
      const hasContent = severityItems.length || bucketInsights.length || timelineInfo;

      if (!hasContent) {
        return;
      }

      // Calculate dynamic duration based on actual item count and CVSS
      const bucketAvgCvss = calculateBucketAvgCvss(severityItems);
      const itemCount = severityItems.length + Math.ceil(bucketInsights.length * 0.5); // Insights count as partial items
      const duration = computeTimelineDuration(timelineInfo, 7, itemCount, bucketAvgCvss);
      const bucketStart = currentStart;
      currentStart += duration;

      const priorityToken = priorityConfig[key];

      // Generate dynamic label based on actual week numbers
      const weekLabel = getDynamicLabel(bucketStart, bucketStart + duration, key);
      const dynamicLabel = `${priorityToken.urgency} (${weekLabel})`;

      // Calculate estimated hours for display
      const estimatedHours = itemCount * (bucketAvgCvss >= 7 ? 8 : bucketAvgCvss >= 4 ? 4 : 2) * effortMultiplier;

      timelineData.push({
        key,
        label: dynamicLabel,
        baseLabel: priorityToken.baseLabel,
        barClass: priorityToken.className,
        accentColor: priorityToken.accentColor,
        symbol: priorityToken.symbol,
        items: severityItems,
        insights: bucketInsights,
        duration,
        start: bucketStart,
        estimatedHours: Math.round(estimatedHours),
        avgCvss: bucketAvgCvss,
        milestoneTarget: Math.round(bucketStart + duration),
        milestoneLabel: `Day ${Math.round(bucketStart + duration)} (~${Math.round(estimatedHours)}h effort)`
      });
    });

    // Calculate total effort for summary
    const totalEstimatedHours = timelineData.reduce((sum, bucket) => sum + (bucket.estimatedHours || 0), 0);
    const totalDuration = timelineData.reduce((max, entry) => Math.max(max, entry.start + entry.duration), 0) || 1;
    const totalWeeks = Math.ceil(totalDuration / 7);

    // Create clean week-based header labels (1-indexed for display)
    const totalWeeksForHeader = Math.max(1, Math.ceil(totalDuration / 7));
    const headerLabels = Array.from({ length: totalWeeksForHeader }, (_, index) => ({
      id: index + 1,
      week: index + 1,
      dayStart: (index * 7) + 1,
      dayEnd: Math.min((index + 1) * 7, Math.ceil(totalDuration))
    }));

    // Filter out empty priority levels (0 findings)
    const filteredTimelineData = timelineData.filter(t => t.items.length > 0);
    const timelineFindingCount = filteredTimelineData.reduce((sum, bucket) => sum + bucket.items.length, 0);

    return (
      <section className="results-section ai-timeframes">
        <div className="section-header-box purple">
          <h2>Intel Analysis</h2>
          <div className="count-badge">{timelineFindingCount || aiInsights.length || vulnerabilityStats.total}</div>
        </div>

        {/* Dynamic Summary Stats */}
        <div className="intel-summary-stats">
          <div className="stat-card">
            <span className="stat-value">{timelineFindingCount}</span>
            <span className="stat-label">Total Findings</span>
          </div>
          <div className="stat-card">
            <span className="stat-value">{totalWeeks}</span>
            <span className="stat-label">Est. Weeks</span>
          </div>
          <div className="stat-card">
            <span className="stat-value">{totalEstimatedHours}h</span>
            <span className="stat-label">Est. Effort</span>
          </div>
          <div className="stat-card">
            <span className="stat-value">{timelineData.length}</span>
            <span className="stat-label">Priority Levels</span>
          </div>
        </div>

        {filteredTimelineData.length > 0 ? (
          <div className="gantt-wrapper">
            {/* Gantt Chart Legend */}
            <div className="gantt-legend">
              <div className="legend-item">
                <div className="legend-bar cyan-bg"></div>
                <span>Critical</span>
              </div>
              <div className="legend-item">
                <div className="legend-bar coral-bg"></div>
                <span>High</span>
              </div>
              <div className="legend-item">
                <div className="legend-bar pink-bg"></div>
                <span>Medium</span>
              </div>
              <div className="legend-item">
                <div className="legend-bar yellow-bg"></div>
                <span>Low</span>
              </div>
              <div className="legend-item">
                <div className="legend-bar blue-bg"></div>
                <span>Info</span>
              </div>
              <div className="legend-item">
                <div className="legend-milestone"></div>
                <span>Milestone</span>
              </div>
            </div>

            <div className="gantt-container">
              {/* Timeline Header */}
              <div className="gantt-header">
                <div className="gantt-row-label">
                  <span className="label-title">Priority</span>
                  <span className="label-subtitle">Findings / Effort</span>
                </div>
                <div className="gantt-timeline-header">
                  {headerLabels.map((label) => (
                    <div key={label.id} className="gantt-time-label">
                      <span className="week-label">Week {label.week}</span>
                      <span className="day-range">Days {label.dayStart}-{label.dayEnd}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Timeline Body */}
              <div className="gantt-body">
                {filteredTimelineData.map((timeline, index) => {
                  const itemCount = timeline.items.length;
                  const barStartPercent = (timeline.start / totalDuration) * 100;
                  const barWidthPercent = Math.max((timeline.duration / totalDuration) * 100, 8);
                  const endDay = Math.round(timeline.start + timeline.duration);

                  return (
                    <div key={timeline.key} className={`gantt-row ${index % 2 === 0 ? 'even' : 'odd'}`}>
                      {/* Row Label */}
                      <div className="gantt-row-label">
                        <div className="priority-header">
                          <span className="priority-badge" style={{ background: timeline.accentColor }}>
                            {timeline.symbol}
                          </span>
                          <div className="priority-text">
                            <strong>{timeline.baseLabel || timeline.key}</strong>
                            <span className="priority-subtitle">
                              {itemCount} {pluralize(itemCount, 'finding')}
                            </span>
                            <span className="priority-effort">
                              ~{timeline.estimatedHours || 0}h effort
                            </span>
                          </div>
                        </div>
                      </div>

                      {/* Bar Area */}
                      <div className="gantt-bars">
                        {/* Main Bar */}
                        <div
                          className={`gantt-bar ${timeline.barClass}-bg`}
                          style={{
                            left: `${barStartPercent}%`,
                            width: `${barWidthPercent}%`
                          }}
                          title={`${timeline.baseLabel}: Days ${Math.round(timeline.start + 1)}-${endDay}, ${itemCount} findings, ${timeline.estimatedHours}h effort`}
                        >
                          <span className="bar-text">
                            {timeline.duration}d / {timeline.estimatedHours}h
                          </span>
                        </div>

                        {/* End Milestone */}
                        <div
                          className="gantt-milestone"
                          style={{ left: `${Math.min((endDay / totalDuration) * 100, 98)}%` }}
                          title={`Complete by Day ${endDay}`}
                        >
                          <span className="milestone-text">D{endDay}</span>
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>

              {/* Summary Footer */}
              <div className="gantt-footer">
                <div className="gantt-footer-label">
                  <strong>Summary</strong>
                </div>
                <div className="gantt-footer-content">
                  <div className="footer-stats">
                    <span className="footer-stat">
                      <strong>{totalDuration}</strong> days
                    </span>
                    <span className="footer-stat">
                      <strong>{totalEstimatedHours}</strong> hours
                    </span>
                    <span className="footer-stat">
                      <strong>{timelineFindingCount}</strong> findings
                    </span>
                    <span className="footer-stat">
                      <strong>{filteredTimelineData.length}</strong> priorities
                    </span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        ) : (
          <div className="no-results-box">
            <div className="no-results-icon">--</div>
            <p>Remediation timeline will populate once the scan identifies actionable findings.</p>
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
                    <span className="insight-priority-tag" style={{ background: priorityToken.accentColor }}>
                      {priorityToken.symbol}
                    </span>
                    <h4>{insight.title || `Insight ${index + 1}`}</h4>
                    <p>{insight.description}</p>
                    {insight.recommendations && insight.recommendations.length > 0 && (
                      <ul className="insight-list">
                        {insight.recommendations.slice(0, 2).map((rec, i) => (
                          <li key={i}>{rec}</li>
                        ))}
                      </ul>
                    )}
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

    // Use centralized sharedMetrics for consistent data across all tabs
    const {
      estimatedCost, potentialLoss, effortHours, roiPercentage,
      weeksNeeded, maxWeeks, estimatedTimeline, budgetRange, teamComposition,
      riskScore, riskLevel
    } = sharedMetrics;

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
      roi_percentage: roiPercentage,
      effort_hours: effortHours,
      recommendation: buildDynamicRecommendation()
    };

    const effectiveResourceAllocation = Object.keys(resourceAllocation).length > 0 ? resourceAllocation : {
      team_composition: teamComposition,
      estimated_timeline: estimatedTimeline,
      budget_range: budgetRange
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

    // Use centralized metrics for display
    const totalEffort = effortHours;
    const severityBreakdown = [
      { name: 'Critical', count: criticalCount, color: '#FF6B6B', bgClass: 'coral-bg' },
      { name: 'High', count: highCount, color: '#FFD93D', bgClass: 'yellow-bg' },
      { name: 'Medium', count: mediumCount, color: '#E39FCE', bgClass: 'pink-bg' },
      { name: 'Low', count: lowCount, color: '#4CAF91', bgClass: 'green-bg' },
      { name: 'Info', count: infoCount, color: '#6DD4D9', bgClass: 'cyan-bg' }
    ].filter(s => s.count > 0);

    const maxSeverityCount = Math.max(...severityBreakdown.map(s => s.count), 1);
    // riskScore is now on a 0-10 scale to match normalizedRisk
    const riskColor = riskScore >= 8 ? '#FF6B6B' : riskScore >= 6 ? '#FFD93D' : riskScore >= 4 ? '#E39FCE' : '#4CAF91';

    return (
      <section className="results-section remediation-section">
        <div className="section-header-box cyan">
          <h2>Defense Playbook</h2>
          <div className="count-badge">{totalIssues}</div>
        </div>

        {/* Stats Overview Cards - Similar to Recon Report */}
        {hasVulnerabilities && (
          <div className="playbook-overview-grid">
            <div className="playbook-stat-card coral-bg">
              <div className="stat-card-number">{riskScore.toFixed(1)}</div>
              <h3 className="stat-card-title">Risk Score</h3>
              <p className="stat-card-desc">{riskLevel} risk level based on vulnerability severity analysis</p>
            </div>
            <div className="playbook-stat-card yellow-bg">
              <div className="stat-card-number">{criticalCount + highCount}</div>
              <h3 className="stat-card-title">Urgent Issues</h3>
              <p className="stat-card-desc">Critical and high severity findings requiring immediate attention</p>
            </div>
            <div className="playbook-stat-card green-bg">
              <div className="stat-card-number">{totalEffort}h</div>
              <h3 className="stat-card-title">Est. Effort</h3>
              <p className="stat-card-desc">Total estimated hours to remediate all identified vulnerabilities</p>
            </div>
            <div className="playbook-stat-card cyan-bg">
              <div className="stat-card-number">{Math.round(effectiveCostBenefit.roi_percentage || 0)}%</div>
              <h3 className="stat-card-title">ROI</h3>
              <p className="stat-card-desc">Return on investment from implementing security fixes</p>
            </div>
          </div>
        )}

        {/* Severity Distribution */}
        {hasVulnerabilities && (
          <div className="playbook-section">
            <div className="playbook-section-header pink-bg">
              <h3>Threat Distribution</h3>
            </div>
            <div className="playbook-section-content">
              <div className="severity-distribution">
                {severityBreakdown.map((sev) => (
                  <div key={sev.name} className="distribution-row">
                    <div className="distribution-label">
                      <span className={`distribution-badge ${sev.bgClass}`}>{sev.name}</span>
                    </div>
                    <div className="distribution-bar-container">
                      <div
                        className="distribution-bar-fill"
                        style={{
                          width: `${(sev.count / maxSeverityCount) * 100}%`,
                          background: sev.color
                        }}
                      />
                    </div>
                    <div className="distribution-count">{sev.count}</div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* Remediation Timeline */}
        {hasVulnerabilities && (
          <div className="playbook-section">
            <div className="playbook-section-header yellow-bg">
              <h3>Remediation Timeline</h3>
            </div>
            <div className="playbook-section-content">
              <div className="timeline-phases">
                {effectiveTimeline.immediate_action && (
                  <div className="phase-card">
                    <div className="phase-card-header coral-bg">
                      <span className="phase-number">1</span>
                      <div className="phase-info">
                        <h4>Immediate Action</h4>
                        <span className="phase-time">0-48 hours</span>
                      </div>
                    </div>
                    <div className="phase-card-body">
                      <ul className="phase-items-list">
                        {effectiveTimeline.immediate_action.items?.slice(0, 4).map((item, idx) => (
                          <li key={idx}>{item.title || item}</li>
                        ))}
                      </ul>
                      {effectiveTimeline.immediate_action.items?.length > 4 && (
                        <span className="phase-more">+{effectiveTimeline.immediate_action.items.length - 4} more items</span>
                      )}
                    </div>
                  </div>
                )}
                {effectiveTimeline.short_term && (
                  <div className="phase-card">
                    <div className="phase-card-header yellow-bg">
                      <span className="phase-number">2</span>
                      <div className="phase-info">
                        <h4>Short Term</h4>
                        <span className="phase-time">1-7 days</span>
                      </div>
                    </div>
                    <div className="phase-card-body">
                      <ul className="phase-items-list">
                        {effectiveTimeline.short_term.items?.slice(0, 4).map((item, idx) => (
                          <li key={idx}>{item.title || item}</li>
                        ))}
                      </ul>
                      {effectiveTimeline.short_term.items?.length > 4 && (
                        <span className="phase-more">+{effectiveTimeline.short_term.items.length - 4} more items</span>
                      )}
                    </div>
                  </div>
                )}
                {effectiveTimeline.medium_term && (
                  <div className="phase-card">
                    <div className="phase-card-header pink-bg">
                      <span className="phase-number">3</span>
                      <div className="phase-info">
                        <h4>Medium Term</h4>
                        <span className="phase-time">1-4 weeks</span>
                      </div>
                    </div>
                    <div className="phase-card-body">
                      <ul className="phase-items-list">
                        {effectiveTimeline.medium_term.items?.slice(0, 4).map((item, idx) => (
                          <li key={idx}>{item.title || item}</li>
                        ))}
                      </ul>
                      {effectiveTimeline.medium_term.items?.length > 4 && (
                        <span className="phase-more">+{effectiveTimeline.medium_term.items.length - 4} more items</span>
                      )}
                    </div>
                  </div>
                )}
                {effectiveTimeline.long_term && (
                  <div className="phase-card">
                    <div className="phase-card-header green-bg">
                      <span className="phase-number">4</span>
                      <div className="phase-info">
                        <h4>Long Term</h4>
                        <span className="phase-time">1-3 months</span>
                      </div>
                    </div>
                    <div className="phase-card-body">
                      <ul className="phase-items-list">
                        {effectiveTimeline.long_term.items?.slice(0, 4).map((item, idx) => (
                          <li key={idx}>{item.title || item}</li>
                        ))}
                      </ul>
                      {effectiveTimeline.long_term.items?.length > 4 && (
                        <span className="phase-more">+{effectiveTimeline.long_term.items.length - 4} more items</span>
                      )}
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {/* Cost-Benefit Analysis - Full Width */}
        {hasVulnerabilities && (() => {
          const remediationCost = effectiveCostBenefit.total_remediation_cost || 0;
          const breachCost = effectiveCostBenefit.potential_loss || 0;
          const netSavings = effectiveCostBenefit.net_benefit || 0;
          const roiPercent = Math.round(effectiveCostBenefit.roi_percentage || 0);
          const maxCost = Math.max(remediationCost, breachCost);
          const remediationWidth = maxCost > 0 ? (remediationCost / maxCost) * 100 : 0;
          const breachWidth = maxCost > 0 ? (breachCost / maxCost) * 100 : 0;

          // Calculate risk level based on breach vs remediation ratio
          const riskRatio = remediationCost > 0 ? breachCost / remediationCost : 0;
          let riskLevel, riskColor, riskAction;
          if (riskRatio >= 10) {
            riskLevel = 'CRITICAL';
            riskColor = '#FF6B6B';
            riskAction = 'IMMEDIATE ACTION REQUIRED';
          } else if (riskRatio >= 5) {
            riskLevel = 'HIGH';
            riskColor = '#FFD93D';
            riskAction = 'PRIORITIZE REMEDIATION';
          } else if (riskRatio >= 2) {
            riskLevel = 'MODERATE';
            riskColor = '#E39FCE';
            riskAction = 'SCHEDULE REMEDIATION';
          } else {
            riskLevel = 'LOW';
            riskColor = '#4CAF91';
            riskAction = 'MONITOR AND MAINTAIN';
          }

          // Breakdown costs by category
          const breakdownItems = [
            { label: 'Critical Fixes', percent: criticalCount > 0 ? 40 : 0, color: '#FF6B6B' },
            { label: 'High Priority', percent: highCount > 0 ? 30 : 0, color: '#FFD93D' },
            { label: 'Medium Issues', percent: mediumCount > 0 ? 20 : 0, color: '#E39FCE' },
            { label: 'Low/Info Items', percent: (lowCount > 0 || infoCount > 0) ? 10 : 0, color: '#4CAF91' },
          ].filter(item => item.percent > 0);

          // Normalize percentages
          const totalPercent = breakdownItems.reduce((acc, item) => acc + item.percent, 0);
          breakdownItems.forEach(item => {
            item.percent = totalPercent > 0 ? Math.round((item.percent / totalPercent) * 100) : 0;
          });

          return (
            <div className="playbook-section cost-analysis-full">
              <div className="playbook-section-header green-bg">
                <h3>Cost-Benefit Analysis</h3>
                <span className="section-subtitle">Financial Impact Assessment</span>
              </div>
              <div className="playbook-section-content">
                {/* Top Stats Row */}
                <div className="cost-stats-row">
                  <div className="cost-stat-card">
                    <span className="cost-stat-label">Remediation Investment</span>
                    <span className="cost-stat-value">{`\u20B9`}{remediationCost.toLocaleString('en-IN')}</span>
                    <span className="cost-stat-hint">One-time security spend</span>
                  </div>
                  <div className="cost-stat-card danger">
                    <span className="cost-stat-label">Potential Breach Cost</span>
                    <span className="cost-stat-value">{`\u20B9`}{breachCost.toLocaleString('en-IN')}</span>
                    <span className="cost-stat-hint">If left unaddressed</span>
                  </div>
                  <div className="cost-stat-card success">
                    <span className="cost-stat-label">Net Savings</span>
                    <span className="cost-stat-value">{`\u20B9`}{netSavings.toLocaleString('en-IN')}</span>
                    <span className="cost-stat-hint">Risk avoided</span>
                  </div>
                  <div className="cost-stat-card roi">
                    <span className="cost-stat-label">Return on Investment</span>
                    <span className="cost-stat-value roi-value">{roiPercent}%</span>
                    <span className="cost-stat-hint">Value returned per rupee</span>
                  </div>
                </div>

                {/* Cost Comparison Visual */}
                <div className="cost-comparison-section">
                  <h4 className="cost-section-title">Cost Comparison</h4>
                  <div className="cost-bars-container">
                    <div className="cost-bar-row">
                      <div className="cost-bar-label">
                        <span className="bar-name">Fix Now</span>
                        <span className="bar-value">{`\u20B9`}{remediationCost.toLocaleString('en-IN')}</span>
                      </div>
                      <div className="cost-bar-track">
                        <div
                          className="cost-bar-fill remediation"
                          style={{ width: `${remediationWidth}%` }}
                        >
                          <span className="bar-percent">{remediationWidth > 10 ? `${Math.round(remediationWidth)}%` : ''}</span>
                        </div>
                      </div>
                    </div>
                    <div className="cost-bar-row">
                      <div className="cost-bar-label">
                        <span className="bar-name">Risk Exposure</span>
                        <span className="bar-value">{`\u20B9`}{breachCost.toLocaleString('en-IN')}</span>
                      </div>
                      <div className="cost-bar-track">
                        <div
                          className="cost-bar-fill breach"
                          style={{ width: `${breachWidth}%` }}
                        >
                          <span className="bar-percent">{breachWidth > 10 ? `${Math.round(breachWidth)}%` : ''}</span>
                        </div>
                      </div>
                    </div>
                  </div>
                  <div className="cost-multiplier">
                    <span className="multiplier-label">Risk Multiplier:</span>
                    <span className="multiplier-value">{riskRatio.toFixed(1)}x</span>
                    <span className="multiplier-desc">potential loss vs investment</span>
                  </div>
                </div>

                {/* Two Column: Breakdown + ROI Gauge */}
                <div className="cost-details-grid">
                  {/* Cost Breakdown by Category */}
                  <div className="cost-breakdown-card">
                    <h4 className="cost-section-title">Investment Breakdown</h4>
                    <div className="breakdown-chart">
                      <div className="breakdown-bars">
                        {breakdownItems.map((item, idx) => (
                          <div key={idx} className="breakdown-segment" style={{ flex: item.percent }}>
                            <div className="segment-fill" style={{ background: item.color }}></div>
                          </div>
                        ))}
                      </div>
                      <div className="breakdown-legend">
                        {breakdownItems.map((item, idx) => (
                          <div key={idx} className="legend-item">
                            <span className="legend-color" style={{ background: item.color }}></span>
                            <span className="legend-label">{item.label}</span>
                            <span className="legend-percent">{item.percent}%</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>

                  {/* ROI Gauge */}
                  <div className="roi-gauge-card">
                    <h4 className="cost-section-title">ROI Assessment</h4>
                    <div className="roi-gauge">
                      <div className="gauge-visual">
                        <div className="gauge-track">
                          <div
                            className="gauge-fill"
                            style={{
                              width: `${Math.min(roiPercent / 10, 100)}%`,
                              background: roiPercent >= 500 ? '#4CAF91' : roiPercent >= 200 ? '#FFD93D' : '#E39FCE'
                            }}
                          ></div>
                        </div>
                        <div className="gauge-markers">
                          <span>0%</span>
                          <span>250%</span>
                          <span>500%</span>
                          <span>750%</span>
                          <span>1000%+</span>
                        </div>
                      </div>
                      <div className="gauge-result">
                        <span className="gauge-value">
                          {roiPercent}%
                        </span>
                        <span className="gauge-label">Return on Investment</span>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Risk Assessment Banner */}
                <div className="risk-assessment-banner" style={{ borderColor: riskColor }}>
                  <div className="risk-badge" style={{ background: riskColor }}>
                    <span className="risk-level">{riskLevel}</span>
                    <span className="risk-label">RISK</span>
                  </div>
                  <div className="risk-content">
                    <span className="risk-action">{riskAction}</span>
                    <span className="risk-desc">
                      {riskRatio >= 10
                        ? `Potential breach cost is ${riskRatio.toFixed(0)}x your remediation investment. Every day of delay increases exposure.`
                        : riskRatio >= 5
                          ? `Breach costs ${riskRatio.toFixed(1)}x more than fixing. Strong case for immediate remediation.`
                          : riskRatio >= 2
                            ? `Moderate risk ratio of ${riskRatio.toFixed(1)}x. Plan remediation within your next sprint cycle.`
                            : `Risk ratio of ${riskRatio.toFixed(1)}x is manageable. Continue monitoring and maintain security posture.`
                      }
                    </span>
                  </div>
                  {effectiveCostBenefit.recommendation && (
                    <div className="risk-recommendation">
                      <strong>Recommendation:</strong> {effectiveCostBenefit.recommendation}
                    </div>
                  )}
                </div>
              </div>
            </div>
          );
        })()}

        {/* Resource Allocation - Separate Section */}
        {hasVulnerabilities && effectiveResourceAllocation.team_composition && (
          <div className="playbook-section">
            <div className="playbook-section-header purple-bg">
              <h3>Resource Allocation</h3>
              <span className="section-subtitle">Team and Budget Planning</span>
            </div>
            <div className="playbook-section-content">
              <div className="resource-allocation-grid">
                <div className="resource-card">
                  <h4>Team Composition</h4>
                  <div className="team-members">
                    {Object.entries(effectiveResourceAllocation.team_composition).map(([role, count]) => (
                      <div key={role} className="team-member">
                        <span className="member-count">{count}</span>
                        <span className="member-role">{role}</span>
                      </div>
                    ))}
                  </div>
                </div>
                {effectiveResourceAllocation.estimated_timeline && (
                  <div className="resource-card">
                    <h4>Estimated Timeline</h4>
                    <span className="resource-highlight">{effectiveResourceAllocation.estimated_timeline}</span>
                  </div>
                )}
                {effectiveResourceAllocation.budget_range && (
                  <div className="resource-card">
                    <h4>Budget Range</h4>
                    <span className="resource-highlight">{effectiveResourceAllocation.budget_range}</span>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {/* Action Items */}
        {effectiveRecommendations.length > 0 && (
          <div className="playbook-section">
            <div className="playbook-section-header coral-bg">
              <h3>Action Items</h3>
              <span className="section-count">{effectiveRecommendations.length}</span>
            </div>
            <div className="playbook-section-content no-padding">
              <div className="action-items-list">
                {effectiveRecommendations.map((rec, index) => (
                  <div key={index} className={`action-item ${rec.priority?.toLowerCase() || 'medium'}-priority`}>
                    <div className="action-item-marker">
                      <span className="marker-number">{index + 1}</span>
                    </div>
                    <div className="action-item-content">
                      <div className="action-item-header">
                        <span className={`priority-tag ${rec.priority?.toLowerCase() || 'medium'}`}>
                          {rec.priority?.toUpperCase() || 'MEDIUM'}
                        </span>
                        <h4>{rec.title || `Recommendation ${index + 1}`}</h4>
                        {rec.category && <span className="category-tag">{rec.category}</span>}
                      </div>
                      <p className="action-item-desc">{rec.description || rec.recommendation}</p>
                      {rec.action_items && rec.action_items.length > 0 && (
                        <div className="action-steps">
                          <strong>Steps:</strong>
                          <ol>
                            {rec.action_items.filter(a => a).map((action, idx) => (
                              <li key={idx}>{action}</li>
                            ))}
                          </ol>
                        </div>
                      )}
                      {rec.estimated_effort && (
                        <div className="action-effort">
                          <strong>Effort:</strong> {rec.estimated_effort}
                        </div>
                      )}
                    </div>
                  </div>
                ))}
              </div>
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

  // Helper to get scan mode display info
  const getScanModeInfo = () => {
    const mode = results?.scan_mode || 'standard';
    const scanTypes = results?.scan_types || [];

    const modeConfig = {
      quick: { label: 'QUICK', color: '#6DD4D9', scanners: 'Nuclei' },
      standard: { label: 'STANDARD', color: '#FFD93D', scanners: 'Nuclei + Wapiti' },
      deep: { label: 'DEEP', color: '#FF6B6B', scanners: 'OWASP ZAP + Nuclei + Wapiti' }
    };

    const config = modeConfig[mode] || modeConfig.standard;

    // If we have actual scan types, use them
    if (scanTypes.length > 0) {
      config.scanners = scanTypes.map(s => {
        if (s === 'owasp') return 'OWASP ZAP';
        return s.charAt(0).toUpperCase() + s.slice(1);
      }).join(' + ');
    }

    return config;
  };

  // Calculate scan duration
  const getScanDuration = () => {
    if (!results?.started_at) return null;

    const start = new Date(results.started_at);
    const end = results?.completed_at ? new Date(results.completed_at) : new Date();
    const durationMs = end - start;

    const minutes = Math.floor(durationMs / 60000);
    const seconds = Math.floor((durationMs % 60000) / 1000);

    if (minutes >= 60) {
      const hours = Math.floor(minutes / 60);
      const remainingMins = minutes % 60;
      return `${hours}h ${remainingMins}m`;
    }

    return minutes > 0 ? `${minutes}m ${seconds}s` : `${seconds}s`;
  };

  const scanModeInfo = getScanModeInfo();
  const scanDuration = getScanDuration();

  return (
    <Layout>
      <div className="scan-results-container">
        <header className="results-header">
          <div className="header-content">
            <h1>Scan Results</h1>
            <Link to="/" className="back-button"> Return to Base</Link>
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
              <span className="scan-info-label">Scan Mode</span>
              <span className="scan-info-value">
                <span
                  className="scan-mode-badge"
                  style={{ backgroundColor: scanModeInfo.color }}
                  title={`Scanners: ${scanModeInfo.scanners}`}
                >
                  {scanModeInfo.label}
                </span>
              </span>
            </div>
            <div className="scan-info-item">
              <span className="scan-info-label">Scanners</span>
              <span className="scan-info-value scan-info-scanners">
                {scanModeInfo.scanners}
              </span>
            </div>
            {scanDuration && (
              <div className="scan-info-item">
                <span className="scan-info-label">Duration</span>
                <span className="scan-info-value">
                  <span className="duration-badge">{scanDuration}</span>
                </span>
              </div>
            )}
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
          {activeTab === 'summary' && renderExecutiveSummary()}
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