import React from 'react';
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { AuthProvider } from '../context/AuthContext';
import LinkScanner from '../pages/LinkScanner';
import VulnerabilityScanner from '../pages/VulnerabilityScanner';
import ThreatScanner from '../pages/ThreatScanner';
import SeverityBadge from '../components/SeverityBadge';
import RemediationCard from '../components/RemediationCard';
import ErrorBoundary from '../components/ErrorBoundary';
import { BrowserRouter } from 'react-router-dom';
import { http } from 'msw';
import { setupServer } from 'msw/node';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';

// Mock API responses
const server = setupServer(
  // Mock scan initiation
  http.post('/api/v1/scanner/start', (req, res, ctx) => {
    return res(
      ctx.json({
        scan_id: 'test-scan-123',
        status: 'initiated'
      })
    );
  }),

  // Mock link scan endpoint
  http.post('/api/v1/scan-url', (req, res, ctx) => {
    return res(
      ctx.json({
        url: 'https://test.com',
        threats: ['sql injection'],
        severity: 'HIGH',
        details: 'Test vulnerability found'
      })
    );
  }),

  // Mock threat scan endpoint
  http.post('/api/v1/scan-threat', (req, res, ctx) => {
    return res(
      ctx.json({
        threat_score: 85,
        malicious_indicators: ['malware'],
        reputation: 'Poor',
        analysis_details: 'Known malicious domain'
      })
    );
  }),
  
  // Mock scan status
  http.get('/api/v1/scanner/status/:scanId', (req, res, ctx) => {
    return res(
      ctx.json({
        status: 'completed',
        progress: 100
      })
    );
  }),
  
  // Mock scan results
  http.get('/api/v1/scanner/results/:scanId', (req, res, ctx) => {
    return res(
      ctx.json({
        vulnerabilities: [
          {
            id: 1,
            title: 'SQL Injection',
            severity: 'HIGH',
            description: 'Test vulnerability'
          }
        ],
        risk_score: 8.5,
        mitigations: [
          {
            step: 'Update input validation',
            priority: 'HIGH'
          }
        ]
      })
    );
  })
);

beforeAll(() => server.listen());
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

// Create a new QueryClient instance for each test
const createTestQueryClient = () => new QueryClient({
  defaultOptions: {
    queries: {
      retry: false,
    },
  },
});

// Utility function for wrapping components with providers
const renderWithProviders = (component) => {
  const testQueryClient = createTestQueryClient();
  return render(
    <QueryClientProvider client={testQueryClient}>
      <BrowserRouter>
        <AuthProvider>
          {component}
        </AuthProvider>
      </BrowserRouter>
    </QueryClientProvider>
  );
};

describe('Link Scanner Tests', () => {
  test('initiates scan successfully', async () => {
    renderWithProviders(<LinkScanner />);
    
    // Fill in URL
    const urlInput = screen.getByLabelText(/enter url/i);
    await userEvent.type(urlInput, 'https://test.com');
    
    // Get form and button
    const button = screen.getByRole('button', { name: /scan link/i });
    const form = button.closest('form');
    
    // Submit form and immediately wait for loading state
    await act(async () => {
      fireEvent.submit(form);
    });

    // Now check for loading state
    await waitFor(() => {
      expect(screen.getByRole('button', { name: /scanning/i })).toBeDisabled();
    });

    // Then check for loading card
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: /scanning link/i })).toBeInTheDocument();
      expect(screen.getByText(/analyzing url for security threats/i)).toBeInTheDocument();
    });
    
    // Check for results
    await waitFor(() => {
      expect(screen.getByText(/sql injection/i)).toBeInTheDocument();
      expect(screen.getByText(/high/i)).toBeInTheDocument();
    });
  });
  
  test('handles scan errors gracefully', async () => {
    // Mock error response
    server.use(
      http.post('/api/v1/scan-url', (req, res, ctx) => {
        return res(ctx.status(500));
      })
    );
    
    renderWithProviders(<LinkScanner />);
    
    const urlInput = screen.getByLabelText(/enter url/i);
    await userEvent.type(urlInput, 'https://test.com');
    
    const scanButton = screen.getByRole('button', { name: /scan/i });
    fireEvent.click(scanButton);
    
    await waitFor(() => {
      expect(screen.getByText(/error/i)).toBeInTheDocument();
    });
  });
});

describe('Vulnerability Scanner Tests', () => {
  test('initiates package scan', async () => {
    renderWithProviders(<VulnerabilityScanner />);
    
    // Fill in package details
    const packageInput = screen.getByPlaceholderText(/e\.g\., flask, openssl/i);
    await userEvent.type(packageInput, 'flask');

    // Select ecosystem
    const ecosystemSelect = screen.getByRole('combobox');
    userEvent.selectOptions(ecosystemSelect, 'PyPI');
    
    // Optional version
    const versionInput = screen.getByPlaceholderText(/e\.g\., 2\.0\.1/i);
    await userEvent.type(versionInput, '2.0.0');
    
    // Click scan button
    const scanButton = screen.getByRole('button', { name: /scan for vulnerabilities/i });
    fireEvent.click(scanButton);
    
    // Check for scanning state
    expect(screen.getByText(/scanning\.\.\./i)).toBeInTheDocument();
    
    // Wait for scan completion 
    await waitFor(() => {
      expect(screen.getByText(/scanning package\.\.\./i)).toBeInTheDocument();
      expect(screen.getByText(/checking for known vulnerabilities in PyPI package: flask/i)).toBeInTheDocument();
    });
  });
});

describe('Threat Scanner Tests', () => {
  test('processes threat scan', async () => {
    renderWithProviders(<ThreatScanner />);
    
    // Fill in domain
    const input = screen.getByPlaceholderText(/example.com or 192.168.1.1/i);
    await userEvent.type(input, 'malicious-domain.com');
    
    // Get form and button
    const button = screen.getByRole('button', { name: /analyze threat/i });
    const form = button.closest('form');
    
    // Submit form and immediately wait for loading state
    await act(async () => {
      fireEvent.submit(form);
    });
    
    // Now check for loading state
    await waitFor(() => {
      expect(screen.getByRole('button', { name: /analyzing/i })).toBeDisabled();
    });

    // Then check for loading card
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: /analyzing threat level/i })).toBeInTheDocument();
      expect(screen.getByText(/checking multiple threat intelligence sources/i)).toBeInTheDocument();
    });
    
    // Wait for results
    await waitFor(() => {
      expect(screen.getByText(/threat score/i)).toBeInTheDocument();
      expect(screen.getByText(/threat analysis details/i)).toBeInTheDocument();
    });
  });
});

describe('UI Component Tests', () => {
  test('severity badge displays correct color', () => {
    // Test Critical severity
    render(<SeverityBadge severity={9.5} />);
    expect(screen.getByText(/critical/i)).toHaveClass('badge-danger');
    
    // Test High severity
    render(<SeverityBadge severity={7.5} />);
    expect(screen.getByText(/high/i)).toHaveClass('badge-warning');
    
    // Test Medium severity
    render(<SeverityBadge severity={5.0} />);
    expect(screen.getByText(/medium/i)).toHaveClass('badge-info');
    
    // Test Low severity
    render(<SeverityBadge severity={2.0} />);
    expect(screen.getByText(/low/i)).toHaveClass('badge-success');

    // Test unknown severity
    render(<SeverityBadge severity={null} />);
    expect(screen.getByText(/unknown/i)).toHaveClass('badge-neutral');
  });
  
  test('remediation card shows details', () => {
    render(
      <RemediationCard
        mitigation={{
          step: 'Update dependencies',
          priority: 'HIGH',
          details: 'Run npm audit fix'
        }}
      />
    );
    
    // Check for mitigation step
    expect(screen.getByText(/update dependencies/i)).toBeInTheDocument();
    
    // Check for mitigation details
    expect(screen.getByText(/run npm audit fix/i)).toBeInTheDocument();
    
    // Verify SeverityBadge is rendered with the priority
    const severityBadge = screen.getByText(/Low \(HIGH\)/i);
    expect(severityBadge).toBeInTheDocument();
    expect(severityBadge.closest('.badge')).toHaveClass('badge-success');
  });
});

describe('Error Boundary Tests', () => {
  test('catches and displays component errors', () => {
    const ErrorComponent = () => {
      throw new Error('Test error');
    };
    
    render(
      <ErrorBoundary>
        <ErrorComponent />
      </ErrorBoundary>
    );
    
    expect(screen.getByText(/something went wrong/i)).toBeInTheDocument();
    expect(screen.getByText(/test error/i)).toBeInTheDocument();
  });
});