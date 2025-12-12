import React from 'react';
import { render, screen, waitFor, act } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Routes, Route } from 'react-router-dom';
import Home from '../pages/Home';
import ScanResults from '../pages/ScanResults';
import SeverityBadge from '../components/SeverityBadge';
import RemediationCard from '../components/RemediationCard';
import ErrorBoundary from '../components/ErrorBoundary';
import scannerService from '../services/scannerService';

jest.mock('../services/scannerService', () => {
  const mockService = {
    startScan: jest.fn(),
    setupWebSocket: jest.fn(),
    listScans: jest.fn(),
    getScanResults: jest.fn(),
    getScanSummary: jest.fn(),
    getScanStatus: jest.fn(),
    cancelScan: jest.fn(),
    closeWebSocket: jest.fn(),
    closeAllWebSockets: jest.fn()
  };
  return { __esModule: true, default: mockService };
});

const mockScanResults = {
  scan_id: 'scan-123',
  target_url: 'https://example.com',
  status: 'completed',
  started_at: '2025-01-01T12:00:00Z',
  completed_at: '2025-01-01T12:15:00Z',
  vulnerabilities: [
    {
      id: 'v-1',
      title: 'SQL Injection',
      severity: 'Critical',
      description: 'Unsanitized input allows database manipulation.',
      cvss_score: 9.4,
      recommendation: 'Apply parameterized queries.',
      location: '/login'
    },
    {
      id: 'v-2',
      title: 'Cross-Site Scripting',
      severity: 'High',
      description: 'Reflected XSS found in search results.',
      cvss_score: 7.2,
      recommendation: 'Encode user supplied content.',
      location: '/search'
    },
    {
      id: 'v-3',
      title: 'Missing Security Headers',
      severity: 'Medium',
      description: 'HSTS and CSP headers are not configured.',
      cvss_score: 4.5
    }
  ],
  risk_assessment: {
    overall_risk_score: 8.1,
    risk_level: 'High',
    vulnerability_count: 3,
    critical_count: 1,
    high_count: 1,
    medium_count: 1,
    low_count: 0
  },
  mitre_mapping: [
    {
      id: 'T1190',
      name: 'Exploit Public-Facing Application',
      tactic: 'Initial Access',
      description: 'Adversaries may attempt to exploit public-facing applications.'
    },
    {
      id: 'T1059',
      name: 'Command and Scripting Interpreter',
      tactic: 'Execution',
      description: 'An attacker can execute scripts on the target system.'
    }
  ],
  ai_analysis: [
    {
      id: 'ai-1',
      title: 'Prioritize SQL Injection patching',
      summary: 'The login endpoint is highly exposed and should be patched first.',
      recommendations: ['Deploy WAF rule', 'Add input validation', 'Audit ORM usage'],
      priority: 'Immediate action',
      remediation_priority: 'Immediate'
    }
  ],
  remediation_strategies: {
    recommendations: [
      {
        id: 'rec-1',
        title: 'Implement parameterized queries',
        priority: 'High',
        description: 'Use prepared statements across authentication flows.',
        action_items: ['Audit all SQL accessors', 'Add tests for injection attempts'],
        estimated_effort: '2 days'
      },
      {
        id: 'rec-2',
        title: 'Publish CSP headers',
        priority: 'Medium',
        description: 'Roll out strict content security policy on all routes.',
        action_items: ['Coordinate with CDN team', 'Document policy exceptions'],
        estimated_effort: '3 days'
      }
    ],
    priority_matrix: {
      High: [{ title: 'Implement parameterized queries' }],
      Medium: [{ title: 'Publish CSP headers' }]
    },
    timeline: {
      immediate_action: {
        description: 'Seal injection entry points before further testing.',
        items: [{ title: 'Lock down login endpoint', estimated_hours: 6 }]
      },
      short_term: {
        description: 'Mitigate XSS in the upcoming sprint.',
        items: [{ title: 'Introduce sanitization helpers', estimated_hours: 8 }]
      },
      medium_term: {
        description: 'Roll out security headers across all services.',
        items: [{ title: 'Implement CSP defaults', estimated_hours: 10 }]
      }
    },
    cost_benefit: {
      total_remediation_cost: 15000,
      effort_hours: 120,
      potential_breach_cost: 120000,
      probability: 0.35,
      net_benefit: 105000,
      roi_percentage: 300,
      recommendation: 'Proceed with the high-priority remediation plan immediately.'
    },
    resource_allocation: {
      team_composition: {
        'Security Engineer': 2,
        'Backend Developer': 3
      },
      estimated_timeline: '6 weeks',
      budget_range: '$10k - $20k'
    }
  },
  executive_summary: 'Summary line 1.\nSummary line 2.'
};

const mockSummaryResponse = {
  summary: 'Summary line 1.\nSummary line 2.',
  cached: true
};

const emptyScanResults = {
  scan_id: 'scan-empty',
  target_url: 'https://no-findings.example',
  status: 'completed',
  started_at: '2025-01-01T12:00:00Z',
  completed_at: '2025-01-01T12:05:00Z',
  vulnerabilities: [],
  risk_assessment: null,
  mitre_mapping: [],
  ai_analysis: [],
  remediation_strategies: null,
  executive_summary: null
};

describe('Home scanning workflow', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    scannerService.listScans.mockResolvedValue({
      scans: [
        {
          scan_id: 'history-1',
          target_url: 'https://previous.example',
          status: 'completed',
          started_at: '2025-01-02T08:30:00Z'
        }
      ]
    });
  });

  test('continues rendering when recent scan history fails to load', async () => {
    const consoleSpy = jest.spyOn(console, 'error').mockImplementation(() => { });
    scannerService.listScans.mockRejectedValueOnce(new Error('history unavailable'));

    render(
      <MemoryRouter initialEntries={['/']}>
        <Routes>
          <Route path="/" element={<Home />} />
        </Routes>
      </MemoryRouter>
    );

    await waitFor(() => expect(scannerService.listScans).toHaveBeenCalled());
    expect(screen.getByText(/Press Start Scan/i)).toBeInTheDocument();
    expect(consoleSpy).toHaveBeenCalledWith(
      'Failed to load recent scans:',
      expect.any(Error)
    );

    consoleSpy.mockRestore();
  });

  test('initiates a comprehensive scan and reflects progress updates', async () => {
    const wsCallbacks = {};
    scannerService.startScan.mockResolvedValue({ scan_id: 'scan-999' });
    scannerService.setupWebSocket.mockImplementation((scanId, callbacks) => {
      Object.assign(wsCallbacks, callbacks);
      callbacks.onOpen?.();
      return { close: jest.fn() };
    });

    render(
      <MemoryRouter initialEntries={['/']}>
        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/scan/:scanId" element={<div>Scan Placeholder</div>} />
        </Routes>
      </MemoryRouter>
    );

    await waitFor(() => expect(scannerService.listScans).toHaveBeenCalled());
    expect(await screen.findByText('https://previous.example')).toBeInTheDocument();

    const urlInput = screen.getByPlaceholderText(/enter target url/i);
    await userEvent.type(urlInput, 'https://example.com');

    const startButton = screen.getByRole('button', { name: /start scan/i });
    await userEvent.click(startButton);

    expect(scannerService.startScan).toHaveBeenCalledWith(
      'https://example.com',
      expect.arrayContaining(['owasp', 'nuclei', 'wapiti']),
      expect.objectContaining({ enable_ai_analysis: true })
    );

    await waitFor(() => expect(screen.getByText(/scanning in progress/i)).toBeInTheDocument());

    act(() => {
      wsCallbacks.onProgress?.({ progress: 42, current_stage: 'Enumerating paths' });
    });

    await waitFor(() => {
      expect(screen.getByText('42%')).toBeInTheDocument();
      expect(screen.getByText(/Enumerating paths/i)).toBeInTheDocument();
    });

    act(() => {
      wsCallbacks.onClose?.();
    });

    act(() => {
      wsCallbacks.onComplete?.({});
    });

    act(() => {
      wsCallbacks.onClose?.();
    });

    await waitFor(() => expect(screen.getByText(/Completed/i)).toBeInTheDocument());
  });

  test('prompts for a valid URL when attempting to scan without input', async () => {
    render(
      <MemoryRouter initialEntries={['/']}>
        <Routes>
          <Route path="/" element={<Home />} />
        </Routes>
      </MemoryRouter>
    );

    await waitFor(() => expect(scannerService.listScans).toHaveBeenCalled());

    const user = userEvent.setup();
    const urlInput = screen.getByPlaceholderText(/enter target url/i);
    await user.type(urlInput, '   ');
    await user.keyboard('{Enter}');

    expect(scannerService.startScan).not.toHaveBeenCalled();
    expect(await screen.findByText(/Please enter a valid URL/i)).toBeInTheDocument();
  });

  test('navigates to scan details when selecting a recent scan', async () => {
    render(
      <MemoryRouter initialEntries={['/']}>
        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/scan/:scanId" element={<div data-testid="history-target">History Entry Loaded</div>} />
        </Routes>
      </MemoryRouter>
    );

    await waitFor(() => expect(scannerService.listScans).toHaveBeenCalled());
    const historyEntry = await screen.findByText('https://previous.example');
    await userEvent.click(historyEntry);

    expect(await screen.findByTestId('history-target')).toBeInTheDocument();
  });

  test('surfaces backend errors when scan id is missing', async () => {
    scannerService.startScan.mockResolvedValue({});

    render(
      <MemoryRouter initialEntries={['/']}>
        <Routes>
          <Route path="/" element={<Home />} />
        </Routes>
      </MemoryRouter>
    );

    await waitFor(() => expect(scannerService.listScans).toHaveBeenCalled());

    const user = userEvent.setup();
    const urlInput = screen.getByPlaceholderText(/enter target url/i);
    await user.type(urlInput, 'https://no-scan-id.example');

    const startButton = screen.getByRole('button', { name: /start scan/i });
    await user.click(startButton);

    expect(scannerService.startScan).toHaveBeenCalledWith(
      'https://no-scan-id.example',
      expect.arrayContaining(['owasp', 'nuclei', 'wapiti']),
      expect.objectContaining({ enable_ai_analysis: true })
    );
    expect(await screen.findByText(/No scan ID returned from backend/i)).toBeInTheDocument();
    expect(scannerService.setupWebSocket).not.toHaveBeenCalled();
  });

  test('reports a timeout when the scan websocket never connects', async () => {
    jest.useFakeTimers();
    try {
      scannerService.startScan.mockResolvedValue({ scan_id: 'scan-timeout' });
      scannerService.setupWebSocket.mockImplementation(() => ({ close: jest.fn() }));

      render(
        <MemoryRouter initialEntries={['/']}>
          <Routes>
            <Route path="/" element={<Home />} />
          </Routes>
        </MemoryRouter>
      );

      await waitFor(() => expect(scannerService.listScans).toHaveBeenCalled());

      const user = userEvent.setup({ advanceTimers: jest.advanceTimersByTime });
      const urlInput = screen.getByPlaceholderText(/enter target url/i);
      await user.type(urlInput, 'https://timeout.example');

      const startButton = screen.getByRole('button', { name: /start scan/i });
      await user.click(startButton);

      await waitFor(() => expect(scannerService.setupWebSocket).toHaveBeenCalled());

      act(() => {
        jest.advanceTimersByTime(5000);
      });

      expect(await screen.findByText(/Scan started but lost connection/i)).toBeInTheDocument();
    } finally {
      jest.useRealTimers();
    }
  });

  test('surfaces websocket errors during an active scan', async () => {
    const wsCallbacks = {};
    scannerService.startScan.mockResolvedValue({ scan_id: 'ws-error' });
    scannerService.setupWebSocket.mockImplementation((_, callbacks) => {
      Object.assign(wsCallbacks, callbacks);
      callbacks.onOpen?.();
      return { close: jest.fn() };
    });

    render(
      <MemoryRouter initialEntries={['/']}>
        <Routes>
          <Route path="/" element={<Home />} />
        </Routes>
      </MemoryRouter>
    );

    await waitFor(() => expect(scannerService.listScans).toHaveBeenCalled());

    const user = userEvent.setup();
    await user.type(screen.getByPlaceholderText(/enter target url/i), 'https://ws-error.example');
    await user.click(screen.getByRole('button', { name: /start scan/i }));

    act(() => {
      wsCallbacks.onError?.(new Error('socket closed unexpectedly'));
    });

    expect(await screen.findByText(/Connection error during scan/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /start scan/i })).not.toBeDisabled();
  });
});

describe('ScanResults experience', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    scannerService.getScanResults.mockResolvedValue(mockScanResults);
    scannerService.getScanSummary.mockResolvedValue(mockSummaryResponse);
  });

  test('renders overview cards, tab counts, and Groq summary from scan data', async () => {
    render(
      <MemoryRouter initialEntries={['/scan/test-scan']}>
        <Routes>
          <Route path="/scan/:scanId" element={<ScanResults />} />
        </Routes>
      </MemoryRouter>
    );

    await waitFor(() => expect(scannerService.getScanResults).toHaveBeenCalledWith('test-scan'));
    await waitFor(() => expect(screen.queryByText(/Loading scan results/i)).not.toBeInTheDocument());

    const overviewHeading = await screen.findByRole('heading', { name: /Overview/i });
    expect(overviewHeading).toBeInTheDocument();
    expect(screen.getByText(/critical vulnerability detected/i)).toBeInTheDocument();
    expect(screen.getByText(/high-severity issue/i)).toBeInTheDocument();
    expect(screen.getByText(/MITRE technique/i)).toBeInTheDocument();
    expect(screen.getByText(/curated insight/i)).toBeInTheDocument();

    expect(scannerService.getScanSummary).not.toHaveBeenCalled();

    const user = userEvent.setup();
    const summaryTab = screen.getByRole('button', { name: /Executive Summary/i });
    await act(async () => {
      await user.click(summaryTab);
    });

    expect(await screen.findByText('Summary line 1.')).toBeInTheDocument();
    expect(screen.getByText('Summary line 2.')).toBeInTheDocument();
    expect(screen.getByText('Groq · Cached')).toBeInTheDocument();

    expect(screen.getByRole('button', { name: /Vulnerabilities \(3\)/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /MITRE Mapping \(2\)/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Remediation Strategy \(2\)/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Threat Intelligence \(1\)/i })).toBeInTheDocument();
  });

  test('switching tabs reveals the requested section', async () => {
    render(
      <MemoryRouter initialEntries={['/scan/test-scan']}>
        <Routes>
          <Route path="/scan/:scanId" element={<ScanResults />} />
        </Routes>
      </MemoryRouter>
    );

    await waitFor(() => expect(scannerService.getScanResults).toHaveBeenCalledWith('test-scan'));
    await waitFor(() => expect(screen.queryByText(/Loading scan results/i)).not.toBeInTheDocument());
    await waitFor(() => expect(screen.getByRole('button', { name: /Threat Intelligence \(1\)/i })).toBeInTheDocument());
    const summaryTab = screen.getByRole('button', { name: /Executive Summary/i });

    const user = userEvent.setup();

    await act(async () => {
      await user.click(screen.getByRole('button', { name: /Vulnerabilities \(3\)/i }));
    });
    expect(screen.getByText(/Detailed Outline/i)).toBeInTheDocument();
    expect(screen.getByText(/SQL Injection/i)).toBeInTheDocument();

    await act(async () => {
      await user.click(screen.getByRole('button', { name: /MITRE Mapping \(2\)/i }));
    });
    expect(screen.getByText(/MITRE ATT&CK Mapping/i)).toBeInTheDocument();
    const mitreTechniqueTitles = screen.getAllByText(/Exploit Public-Facing Application/i);
    expect(mitreTechniqueTitles.length).toBeGreaterThan(0);

    await act(async () => {
      await user.click(screen.getByRole('button', { name: /Remediation Strategy \(2\)/i }));
    });
    expect(screen.getByText(/Remediation Timeline/i)).toBeInTheDocument();
    expect(screen.getByText(/Actionable Recommendations/i)).toBeInTheDocument();

    await act(async () => {
      await user.click(screen.getByRole('button', { name: /Threat Intelligence \(1\)/i }));
    });
    expect(screen.getByText(/Remediation Timeframes/i)).toBeInTheDocument();

    await act(async () => {
      await user.click(summaryTab);
    });
    expect(screen.getByText('Summary line 1.')).toBeInTheDocument();
  });

  test('gracefully handles scans without findings', async () => {
    const user = userEvent.setup();
    scannerService.getScanResults.mockResolvedValueOnce(emptyScanResults);
    scannerService.getScanSummary.mockResolvedValueOnce({ summary: '', cached: false });

    render(
      <MemoryRouter initialEntries={['/scan/empty-scan']}>
        <Routes>
          <Route path="/scan/:scanId" element={<ScanResults />} />
        </Routes>
      </MemoryRouter>
    );

    await waitFor(() => expect(scannerService.getScanResults).toHaveBeenCalledWith('empty-scan'));
    await waitFor(() => expect(scannerService.getScanSummary).toHaveBeenCalledWith('empty-scan'));

    await waitFor(() =>
      expect(screen.queryByText(/Generating a concise summary/i)).not.toBeInTheDocument()
    );
    const summaryTab = screen.getByRole('button', { name: /Executive Summary/i });
    await act(async () => {
      await user.click(summaryTab);
    });
    expect(screen.getByText(/Summary will appear here once generated/i)).toBeInTheDocument();

    await act(async () => {
      await user.click(screen.getByRole('button', { name: /Vulnerabilities/i }));
    });
    expect(await screen.findByText(/No vulnerabilities found\. Your application is secure!/i)).toBeInTheDocument();

    expect(screen.queryByRole('button', { name: /MITRE Mapping/i })).not.toBeInTheDocument();
  });

  test('surfaces summary errors and retries successfully', async () => {
    const user = userEvent.setup();
    const groqFailure = new Error('Groq service unavailable');
    scannerService.getScanSummary
      .mockRejectedValueOnce(groqFailure)
      .mockResolvedValueOnce({ summary: 'Retry summary works.', cached: false });
    scannerService.getScanResults.mockResolvedValueOnce({
      ...mockScanResults,
      executive_summary: null
    });

    render(
      <MemoryRouter initialEntries={['/scan/test-scan']}>
        <Routes>
          <Route path="/scan/:scanId" element={<ScanResults />} />
        </Routes>
      </MemoryRouter>
    );

    await waitFor(() => expect(scannerService.getScanSummary).toHaveBeenCalledTimes(1));
    const summaryTab = screen.getByRole('button', { name: /Executive Summary/i });
    await act(async () => {
      await user.click(summaryTab);
    });

    await screen.findByText(/Groq service unavailable/i);

    const retryButton = await screen.findByRole('button', { name: /Retry Summary/i });
    await act(async () => {
      await user.click(retryButton);
    });

    await waitFor(() => expect(scannerService.getScanSummary).toHaveBeenCalledTimes(2));
    await waitFor(() =>
      expect(screen.queryByText(/Generating a concise summary/i)).not.toBeInTheDocument()
    );
    expect(screen.getByText(/Retry summary works/i)).toBeInTheDocument();
  });

  test('renders threat intelligence fallback when insights lack matching findings', async () => {
    scannerService.getScanResults.mockResolvedValueOnce({
      ...mockScanResults,
      vulnerabilities: [],
      risk_assessment: {
        overall_risk_score: 1.5,
        risk_level: 'Low',
        vulnerability_count: 0,
        critical_count: 0,
        high_count: 0,
        medium_count: 0,
        low_count: 0
      },
      ai_analysis: [
        {
          id: 'ai-low',
          title: 'Enhance logging visibility',
          summary: 'Focus on monitoring while no exploitable issues exist.',
          priority: 'Low',
          remediation_priority: 'Low urgency'
        }
      ],
      remediation_strategies: null,
      mitre_mapping: [],
      executive_summary: 'Overall posture remains stable.'
    });

    render(
      <MemoryRouter initialEntries={['/scan/insight-only']}>
        <Routes>
          <Route path="/scan/:scanId" element={<ScanResults />} />
        </Routes>
      </MemoryRouter>
    );

    await waitFor(() =>
      expect(scannerService.getScanResults).toHaveBeenCalledWith('insight-only')
    );

    const threatTab = await screen.findByRole('button', { name: /Threat Intelligence \(1\)/i });
    const user = userEvent.setup();
    await act(async () => {
      await user.click(threatTab);
    });

    expect(screen.getByText(/No findings yet/i)).toBeInTheDocument();
    expect(screen.getAllByText(/Enhance logging visibility/i).length).toBeGreaterThan(0);
  });

  test('renders an error view when fetching scan results fails', async () => {
    const consoleSpy = jest.spyOn(console, 'error').mockImplementation(() => { });
    scannerService.getScanResults.mockRejectedValueOnce(new Error('scan not found'));

    render(
      <MemoryRouter initialEntries={['/scan/missing']}>
        <Routes>
          <Route path="/" element={<div data-testid="home-root">Home Screen</div>} />
          <Route path="/scan/:scanId" element={<ScanResults />} />
        </Routes>
      </MemoryRouter>
    );

    await waitFor(() => expect(scannerService.getScanResults).toHaveBeenCalledWith('missing'));
    expect(await screen.findByText(/Error Loading Results/i)).toBeInTheDocument();
    expect(screen.getByText(/scan not found/i)).toBeInTheDocument();

    const user = userEvent.setup();
    const originalLocation = window.location;
    const reloadSpy = jest.fn();
    Object.defineProperty(window, 'location', {
      configurable: true,
      enumerable: true,
      writable: true,
      value: {
        reload: reloadSpy,
        assign: originalLocation.assign?.bind(originalLocation) ?? jest.fn(),
        replace: originalLocation.replace?.bind(originalLocation) ?? jest.fn(),
        href: originalLocation.href,
        ancestorOrigins: originalLocation.ancestorOrigins,
        hash: originalLocation.hash,
        host: originalLocation.host,
        hostname: originalLocation.hostname,
        origin: originalLocation.origin,
        pathname: originalLocation.pathname,
        port: originalLocation.port,
        protocol: originalLocation.protocol,
        search: originalLocation.search,
        toString: () => originalLocation.toString()
      }
    });

    const retryButton = screen.getByRole('button', { name: /Retry/i });
    await user.click(retryButton);
    expect(window.location.reload).toHaveBeenCalled();

    const backButton = screen.getByRole('button', { name: /Return to Base/i });
    await user.click(backButton);
    expect(await screen.findByTestId('home-root')).toBeInTheDocument();

    Object.defineProperty(window, 'location', {
      configurable: true,
      enumerable: true,
      writable: true,
      value: originalLocation
    });

    consoleSpy.mockRestore();
  });

  test('cancels summary fetches when the component unmounts', async () => {
    let resolveSummary;
    const pendingSummary = new Promise((resolve) => {
      resolveSummary = resolve;
    });

    scannerService.getScanResults.mockResolvedValueOnce({
      ...mockScanResults,
      executive_summary: null
    });
    scannerService.getScanSummary.mockImplementationOnce(() => pendingSummary);

    const { unmount } = render(
      <MemoryRouter initialEntries={['/scan/deferred']}>
        <Routes>
          <Route path="/scan/:scanId" element={<ScanResults />} />
        </Routes>
      </MemoryRouter>
    );

    await waitFor(() => expect(scannerService.getScanResults).toHaveBeenCalledWith('deferred'));
    await waitFor(() => expect(scannerService.getScanSummary).toHaveBeenCalledTimes(1));

    await act(async () => {
      unmount();
    });

    await act(async () => {
      resolveSummary?.({ summary: 'Late arrival', cached: false });
    });
  });

  test.each([
    { score: 6.5, expectedColor: '#ff8800', riskLabel: 'Elevated risk' },
    { score: 4.4, expectedColor: '#ffbb33', riskLabel: 'Moderate risk' },
    { score: 2.6, expectedColor: '#00C851', riskLabel: 'Guarded risk' }
  ])('maps risk score $score to risk color $expectedColor', async ({ score, expectedColor, riskLabel }) => {
    scannerService.getScanResults.mockResolvedValueOnce({
      ...mockScanResults,
      risk_assessment: {
        ...mockScanResults.risk_assessment,
        overall_risk_score: score,
        risk_level: riskLabel
      },
      executive_summary: 'Pre-computed summary'
    });

    render(
      <MemoryRouter initialEntries={[`/scan/risk-${score}`]}>
        <Routes>
          <Route path="/scan/:scanId" element={<ScanResults />} />
        </Routes>
      </MemoryRouter>
    );

    await waitFor(() => expect(scannerService.getScanResults).toHaveBeenCalled());
    const formatted = score.toFixed(1);
    const riskCircle = await screen.findByText(formatted);
    expect(riskCircle).toHaveStyle(`background: ${expectedColor}`);
  });

  test('derives fallback risk score when risk assessment is incomplete', async () => {
    scannerService.getScanResults.mockResolvedValueOnce({
      ...mockScanResults,
      vulnerabilities: [
        {
          id: 'fallback-high',
          title: 'High severity issue',
          severity: 'High',
          description: 'No CVSS provided.',
          recommendation: 'Add rate limiting.'
        },
        {
          id: 'fallback-medium',
          title: 'Medium severity issue',
          severity: 'Medium',
          description: 'Needs attention soon.'
        }
      ],
      risk_assessment: {
        overall_risk_score: null,
        risk_level: '',
        vulnerability_count: null,
        critical_count: null,
        high_count: null,
        medium_count: null,
        low_count: null
      },
      executive_summary: 'Summary exists.'
    });

    render(
      <MemoryRouter initialEntries={['/scan/fallback-risk']}>
        <Routes>
          <Route path="/scan/:scanId" element={<ScanResults />} />
        </Routes>
      </MemoryRouter>
    );

    await waitFor(() => expect(scannerService.getScanResults).toHaveBeenCalledWith('fallback-risk'));
    const riskCircle = await screen.findByText('5.5');
    expect(riskCircle).toBeInTheDocument();
    expect(riskCircle).toHaveStyle('background: #ffbb33');

    const riskLevelNode = screen.getByText((content, element) => (
      content === 'Medium' && element.classList.contains('risk-label-level')
    ));
    expect(riskLevelNode).toBeInTheDocument();
    const riskCaptionNode = riskLevelNode.parentElement?.querySelector('.risk-label-caption');
    expect(riskCaptionNode).toHaveTextContent(/Risk Level/i);
  });

  test('allows switching directly to threat intelligence when overview lacks findings', async () => {
    scannerService.getScanResults.mockResolvedValueOnce({
      ...mockScanResults,
      vulnerabilities: [],
      risk_assessment: {
        overall_risk_score: null,
        risk_level: '',
        vulnerability_count: 0,
        critical_count: 0,
        high_count: 0,
        medium_count: 0,
        low_count: 0
      },
      mitre_mapping: [],
      remediation_strategies: null,
      ai_analysis: [
        {
          id: 'insight-1',
          title: 'Focus on monitoring',
          summary: 'Track for regressions frequently.',
          priority: 'Low'
        }
      ],
      executive_summary: 'AI provided insights.'
    });

    render(
      <MemoryRouter initialEntries={['/scan/ai-only']}>
        <Routes>
          <Route path="/scan/:scanId" element={<ScanResults />} />
        </Routes>
      </MemoryRouter>
    );

    const user = userEvent.setup();
    const intelligenceTab = await screen.findByRole('button', { name: /Threat Intelligence \(1\)/i });

    await act(async () => {
      await user.click(intelligenceTab);
    });

    await waitFor(() => {
      expect(intelligenceTab).toHaveClass('active');
    });

    const overviewTab = screen.getByRole('button', { name: /Overview/i });
    expect(overviewTab).not.toHaveClass('active');
    expect(screen.getAllByText(/Focus on monitoring/i).length).toBeGreaterThan(0);
  });
});

describe('UI component coverage', () => {
  test('severity badge displays correct level styling', () => {
    const { unmount } = render(<SeverityBadge severity={9.5} />);
    expect(screen.getByText(/Critical \(9.5\)/i)).toHaveClass('badge-danger');
    unmount();

    const { unmount: unmountHigh } = render(<SeverityBadge severity={7.5} />);
    expect(screen.getByText(/High \(7.5\)/i)).toHaveClass('badge-warning');
    unmountHigh();

    const { unmount: unmountMedium } = render(<SeverityBadge severity={5.0} />);
    expect(screen.getByText(/Medium \(5\)/i)).toHaveClass('badge-info');
    unmountMedium();

    const { unmount: unmountLow } = render(<SeverityBadge severity={2.0} />);
    expect(screen.getByText(/Low \(2\)/i)).toHaveClass('badge-success');
    unmountLow();

    render(<SeverityBadge severity={null} />);
    expect(screen.getByText(/Unknown/i)).toHaveClass('badge-neutral');
  });

  test('remediation card surfaces mitigation details', () => {
    render(
      <RemediationCard
        mitigation={{
          step: 'Update dependencies',
          priority: 'HIGH',
          details: 'Run npm audit fix'
        }}
      />
    );

    expect(screen.getByText(/Update dependencies/i)).toBeInTheDocument();
    expect(screen.getByText(/Run npm audit fix/i)).toBeInTheDocument();
    const severityBadge = screen.getByText(/Low \(HIGH\)/i);
    expect(severityBadge.closest('.badge')).toHaveClass('badge-success');
  });
});

describe('Error Boundary', () => {
  test('captures render failures and presents message', () => {
    const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation(() => { });
    const ProblemChild = () => {
      throw new Error('Test error');
    };

    render(
      <ErrorBoundary>
        <ProblemChild />
      </ErrorBoundary>
    );

    expect(screen.getByText(/Something went wrong/i)).toBeInTheDocument();
    expect(screen.getByText(/Test error/i)).toBeInTheDocument();
    consoleErrorSpy.mockRestore();
  });
});