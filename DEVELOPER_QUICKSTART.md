# Developer Quick Reference Guide

## Environment Setup

### Backend
```bash
cd backend
python -m venv .venv

# Windows
.venv\Scripts\activate

# macOS/Linux
source .venv/bin/activate

pip install -r requirements.txt
```

### Frontend
```bash
cd frontend
npm install
```

## Running the Application

### Terminal 1 - Backend API
```bash
cd backend
.venv\Scripts\activate  # Windows
python -m uvicorn app.main:app --reload --port 8000
```

API will be available at: `http://localhost:8000`  
Swagger Docs: `http://localhost:8000/docs`

### Terminal 2 - Frontend Development Server
```bash
cd frontend
npm start
```

Frontend will open at: `http://localhost:3000`

### Terminal 3 - OWASP ZAP (Docker)
```bash
docker run -t owasp/zap2docker-stable zap-baseline.py -t http://localhost:3000
```

## API Endpoints

### Comprehensive Scanning

#### Start Scan
```bash
POST http://localhost:8000/api/v1/scans/comprehensive/start
Content-Type: application/json
Authorization: Bearer {token}

{
  "target_url": "https://example.com",
  "scan_types": ["owasp", "nuclei", "wapiti"],
  "options": {
    "enable_ai_analysis": true,
    "enable_mitre_mapping": true,
    "include_low_risk": true,
    "deep_scan": false,
    "timeout_minutes": 30
  }
}
```

**Response:**
```json
{
  "scan_id": "scan_abc123def456",
  "message": "Scan started successfully",
  "status_url": "/api/v1/scans/comprehensive/scan_abc123def456/status"
}
```

#### Get Scan Status
```bash
GET http://localhost:8000/api/v1/scans/comprehensive/{scan_id}/status
Authorization: Bearer {token}
```

**Response:**
```json
{
  "scan_id": "scan_abc123def456",
  "status": "in_progress",
  "progress": 45,
  "current_stage": "Running Nuclei scan",
  "started_at": "2025-10-23T10:30:00Z",
  "completed_at": null
}
```

#### Get Scan Results
```bash
GET http://localhost:8000/api/v1/scans/comprehensive/{scan_id}/result
Authorization: Bearer {token}
```

**Response:** Full scan results with vulnerabilities, risk assessment, MITRE mapping, and AI analysis

#### List User Scans
```bash
GET http://localhost:8000/api/v1/scans/comprehensive/list?skip=0&limit=10&status=completed
Authorization: Bearer {token}
```

#### WebSocket Real-Time Updates
```javascript
const ws = new WebSocket('ws://localhost:8000/api/v1/scans/ws/{scan_id}');

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  if (data.type === 'progress') {
    console.log(`Progress: ${data.status.progress}% - ${data.status.current_stage}`);
  } else if (data.type === 'result') {
    console.log('Scan completed:', data.results);
  }
};
```

## Frontend API Usage

### Start a Scan
```javascript
import scannerService from './services/scannerService';

const result = await scannerService.startScan(
  'https://example.com',
  ['owasp', 'nuclei', 'wapiti'],
  {
    enable_ai_analysis: true,
    enable_mitre_mapping: true,
    include_low_risk: true
  }
);

const scanId = result.scan_id;
```

### Setup WebSocket for Real-Time Updates
```javascript
scannerService.setupWebSocket(scanId, {
  onProgress: (status) => {
    console.log(`${status.progress}% - ${status.current_stage}`);
  },
  onComplete: (results) => {
    console.log('Scan complete:', results);
    navigate(`/scan/${scanId}`);
  },
  onError: (error) => {
    console.error('Scan error:', error);
  }
});
```

### Get Scan Results
```javascript
const results = await scannerService.getScanResults(scanId);
console.log(results);
```

### List Recent Scans
```javascript
const scans = await scannerService.listScans(0, 10);
console.log(scans);
```

## Database Models

### Scans Table
```python
{
  "scan_id": "string (UUID)",
  "user_id": "string (UUID)",
  "target_url": "string",
  "status": "pending|in_progress|completed|failed|cancelled",
  "progress": 0-100,
  "current_stage": "string",
  "started_at": "ISO8601 datetime",
  "completed_at": "ISO8601 datetime or null",
  "scan_types": ["owasp", "nuclei", "wapiti"],
  "options": {...},
  "risk_score": 0.0-10.0,
  "risk_level": "Critical|High|Medium|Low|Minimal",
  "ai_analysis": [...],
  "mitre_mapping": [...],
  "remediation_strategies": [...]
}
```

### Vulnerabilities Table
```python
{
  "id": "string (UUID)",
  "scan_id": "string (UUID)",
  "title": "string",
  "description": "string",
  "severity": "critical|high|medium|low",
  "cvss_score": 0.0-10.0,
  "location": "string (URL)",
  "recommendation": "string",
  "mitre_techniques": ["T1234", "T5678"],
  "discovered_at": "ISO8601 datetime"
}
```

## Component Hierarchy

```
App.js
├── Layout.jsx
│   ├── Sidebar
│   ├── TopNav
│   └── ContentArea
│       ├── Home.jsx
│       │   ├── TitleSection
│       │   ├── HeroSection (Game Console)
│       │   ├── FeaturesSection
│       │   ├── RecentScansSection
│       │   ├── HowItWorksSection
│       │   └── SummarySection
│       ├── ScanResults.jsx
│       │   ├── Header
│       │   ├── Tabs
│       │   ├── RiskAssessment
│       │   ├── VulnerabilityList
│       │   ├── MITREMapping
│       │   └── AIAnalysis
│       └── NotFound.jsx
```

## Styling System

### CSS Variables (variables.css)
```css
:root {
  --color-black: #2c3e50;
  --color-white: #ffffff;
  --font-display: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto;
  --font-mono: 'SF Mono', 'Monaco', 'Menlo', 'Courier', monospace;
  /* ... more variables ... */
}
```

### Color Scheme
- Primary: `#967bdc` (Purple)
- Secondary: `#00f2ff` (Cyan)
- Success: `#00C851` (Green)
- Warning: `#ffbb33` (Yellow)
- Error: `#ff4444` (Red)

## Common Tasks

### Debug API Calls
```javascript
// In frontend, browser console:
const response = await fetch('http://localhost:8000/api/v1/scans/comprehensive/list', {
  headers: {
    'Authorization': `Bearer ${localStorage.getItem('access_token')}`
  }
});
console.log(await response.json());
```

### View Backend Logs
```bash
# Terminal running backend
# Logs will show in real-time with --reload enabled
```

### Test Scanner Integration
```python
# In backend Python console
from app.services.scanners.zap_scanner import OWASPZAPScanner, ZAPScannerConfig

config = ZAPScannerConfig()
scanner = OWASPZAPScanner(config)
await scanner.initialize()
```

### Clear Frontend Cache
```bash
npm cache clean --force
rm -rf node_modules package-lock.json
npm install
```

### Reset Database
```python
# In backend
from app.database import init_db
init_db()  # Creates all tables
```

## Troubleshooting

### WebSocket Connection Failed
- Check backend is running on port 8000
- Verify CORS configuration in `app.main:app`
- Check browser console for connection errors
- Ensure WebSocket URL format: `ws://localhost:8000/api/v1/scans/ws/{scan_id}`

### 401 Unauthorized Errors
- Check token in localStorage
- Verify token hasn't expired
- Re-login if needed
- Check Authorization header in API calls

### Scan Not Starting
- Verify scanners are installed (OWASP ZAP, Nuclei, Wapiti)
- Check target URL is valid
- Review backend logs for scanner errors
- Ensure database connection is working

### Frontend Won't Load
- Check `npm start` is running
- Clear browser cache
- Check for console errors
- Verify `REACT_APP_API_URL` in `.env`

## Performance Optimization

### Backend
```python
# Use connection pooling (already configured)
# Use async/await for I/O operations
# Implement caching for scan results
from app.core.cache import cache_manager
```

### Frontend
```javascript
// Lazy load components
const ScanResults = React.lazy(() => import('./pages/ScanResults'));

// Memoize expensive components
import React, { memo } from 'react';
const VulnerabilityCard = memo(({vuln}) => {...});

// Virtualize long lists
import { FixedSizeList } from 'react-window';
```

## Deployment Checklist

- [ ] Update environment variables (.env files)
- [ ] Generate strong SECRET_KEY and CSRF_SECRET
- [ ] Configure Supabase connection string
- [ ] Set up database tables
- [ ] Install production dependencies
- [ ] Build frontend (`npm run build`)
- [ ] Configure Docker containers
- [ ] Set up reverse proxy (Nginx)
- [ ] Configure HTTPS/SSL certificates
- [ ] Set up monitoring and logging
- [ ] Run security audit
- [ ] Test full workflow end-to-end

## Useful Commands

```bash
# Backend
python -m pytest backend/tests/  # Run tests
python -c "from app.database import init_db; init_db()"  # Init DB
python -m pip install -r requirements.txt  # Install dependencies

# Frontend
npm test  # Run tests
npm run build  # Production build
npm run eject  # Eject from CRA (⚠️ irreversible)

# Docker
docker ps  # List containers
docker logs {container_id}  # View logs
docker exec -it {container_id} bash  # Access container
```

## Resources

- FastAPI Docs: https://fastapi.tiangolo.com/
- React Docs: https://react.dev/
- Supabase Docs: https://supabase.com/docs
- OWASP Top 10: https://owasp.org/www-project-top-ten/
- MITRE ATT&CK: https://attack.mitre.org/

---

**Last Updated:** October 23, 2025  
**For Issues:** Check GitHub Issues or contact the development team
