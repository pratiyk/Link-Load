import { setupServer } from 'msw/node'
import { rest } from 'msw'

// Define handlers for mock API endpoints
const handlers = [
  rest.post('/api/v1/scanner/start', (req, res, ctx) => {
    return res(
      ctx.json({
        scan_id: 'test-scan-123',
        status: 'initiated'
      })
    )
  }),
  
  rest.get('/api/v1/scanner/status/:scanId', (req, res, ctx) => {
    return res(
      ctx.json({
        status: 'completed',
        progress: 100
      })
    )
  }),
  
  rest.get('/api/v1/scanner/results/:scanId', (req, res, ctx) => {
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
    )
  }),
  
  rest.get('/api/v1/intelligence/threat-intel/:vulnId', (req, res, ctx) => {
    return res(
      ctx.json([
        {
          id: 1,
          source: 'test_source',
          threat_type: 'malware',
          name: 'Test Malware',
          severity: 'HIGH',
          confidence_score: 0.8
        }
      ])
    )
  }),
  
  rest.post('/api/v1/auth/login', (req, res, ctx) => {
    return res(
      ctx.json({
        access_token: 'test_token',
        token_type: 'bearer'
      })
    )
  }),
  
  rest.post('/api/v1/auth/register', (req, res, ctx) => {
    return res(
      ctx.status(201),
      ctx.json({
        id: 1,
        email: req.body.email
      })
    )
  })
]

// Set up MSW server with the handlers
export const server = setupServer(...handlers)