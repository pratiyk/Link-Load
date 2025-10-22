import { render, screen } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import App from './App';

const createTestQueryClient = () => new QueryClient({
  defaultOptions: {
    queries: {
      retry: false,
    },
  },
});

test('renders Link Scanner page', () => {
  const queryClient = createTestQueryClient();
  render(
    <QueryClientProvider client={queryClient}>
      <App />
    </QueryClientProvider>
  );

  // Get all instances of "Link Scanner" text
  const linkElements = screen.getAllByText(/Link Scanner/i);
  expect(linkElements).toHaveLength(2); // One in nav, one in heading
  expect(linkElements[1]).toBeInTheDocument();
  
  // Check description is present
  const description = screen.getByText(/Analyze URLs for potential security threats and malicious content/i);
  expect(description).toBeInTheDocument();
});
