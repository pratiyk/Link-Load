import { render, screen } from '@testing-library/react';
import App from './App';

jest.mock('./services/scannerService', () => {
  const mockService = {
    listScans: jest.fn().mockResolvedValue({ scans: [] }),
    startScan: jest.fn(),
    setupWebSocket: jest.fn(),
    getScanResults: jest.fn(),
    getScanSummary: jest.fn(),
    getScanStatus: jest.fn(),
    cancelScan: jest.fn(),
    closeWebSocket: jest.fn(),
    closeAllWebSockets: jest.fn()
  };
  return { __esModule: true, default: mockService };
});

test('renders Link&Load home experience', () => {
  render(<App />);

  expect(screen.queryByRole('heading', { name: /Scan Results/i })).not.toBeInTheDocument();
  expect(screen.getByRole('heading', { name: /Link&Load/i })).toBeInTheDocument();
  expect(screen.getByText(/Link\. Load\. Defend\. Repeat\./i)).toBeInTheDocument();
  expect(screen.getByRole('button', { name: /start scan/i })).toBeInTheDocument();
  expect(screen.getByRole('link', { name: /Login \/ Register/i })).toBeInTheDocument();
});
