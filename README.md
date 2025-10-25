# Link&Load

> **AI-Powered Web Security Scanning Platform**

[![GitHub License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.11+-3776ab.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104+-009688.svg)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-18+-61dafb.svg)](https://react.dev/)
[![Docker](https://img.shields.io/badge/Docker-Supported-2496ed.svg)](https://www.docker.com/)

---

## Features

### Multi-Scanner Integration
- **OWASP ZAP** - Comprehensive web application scanning
- **Nuclei** - Template-based vulnerability detection  
- **Wapiti** - Black-box web application security scanner
- Concurrent execution for faster results

### AI-Powered Analysis
- **OpenAI GPT-4** or **Anthropic Claude** integration
- Intelligent vulnerability analysis
- Context-aware recommendations
- Fallback mechanism when LLM unavailable

### MITRE ATT&CK Mapping
- Automatic technique correlation
- Threat landscape understanding
- Tactic and technique classification
- Executive-ready reporting

### Risk Quantification
- 0-10 risk scoring algorithm
- Severity-based aggregation
- Business context awareness
- Compliance mapping

### Real-Time Updates
- WebSocket live progress tracking
- Instant result notifications
- Stage-by-stage visibility
- Connection resilience

### Professional UI
- Retro geometric design system
- Bold blocks with playful shadows
- Tabbed results dashboard
- Responsive design
- Game console-style interface

---

## Demo

![alt text](image-1.png)

![alt text](image-2.png)

![alt text](image-3.png)

---

## Quick Start

### Prerequisites
- Docker & Docker Compose (recommended)
- Or: Python 3.11+, Node.js 18+

### Development Setup

```bash
# Clone repository
git clone https://github.com/pratiyk/Link-Load.git
cd Link-Load

# Backend
cd backend
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python -m uvicorn app.main:app --reload

# Frontend (new terminal)
cd frontend
npm install
npm start

# Access
# Frontend: http://localhost:3000
# API Docs: http://localhost:8000/docs
```

### Production with Docker

```bash
# Copy environment file
cp .env.example .env
nano .env  # Configure settings

# Start all services
docker-compose up -d

# Initialize database
docker-compose exec backend alembic upgrade head

# Access
# Frontend: http://localhost:3000
# API: http://localhost:8000
```

---

## Architecture

```
┌─────────────────────┐
│   React Frontend    │
│  Home + Results     │
└──────────┬──────────┘
           │ REST/WS
┌──────────▼──────────┐
│   FastAPI Backend   │
│  Scan Orchestration │
└──────────┬──────────┘
      ┌────┼────┬─────────┐
      │    │    │         │
    OWASP ZAP Nuclei   Wapiti
      │    │    │         │
      └────┴────┴────┬────┘
          Vulnerabilities
           │         │
       LLM Service   DB
        (Analysis)
```

---

## API Endpoints

### Start Comprehensive Scan
```bash
POST /api/v1/scans/comprehensive/start
Content-Type: application/json

{
  "target_url": "https://example.com",
  "scan_types": ["owasp", "nuclei", "wapiti"],
  "options": {
    "enable_ai_analysis": true,
    "enable_mitre_mapping": true
  }
}

Response: { "scan_id": "scan_abc123..." }
```

### Get Scan Status
```bash
GET /api/v1/scans/comprehensive/{scan_id}/status
Response: { "status": "in_progress", "progress": 45 }
```

### Get Scan Results
```bash
GET /api/v1/scans/comprehensive/{scan_id}/result
Response: {
  "vulnerabilities": [...],
  "risk_assessment": {...},
  "mitre_mapping": [...],
  "ai_analysis": [...]
}
```

---

## Configuration

### Environment Variables

```bash
# Database
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_KEY=your-anon-key

# Scanners
ZAP_URL=http://localhost:8090
NUCLEI_PATH=/usr/bin/nuclei
WAPITI_PATH=/usr/bin/wapiti

# LLM (choose one)
OPENAI_API_KEY=sk-...
ANTHROPIC_API_KEY=sk-ant-...

# Security
SECRET_KEY=your-secret-key
```

See [.env.example](./.env.example) for all options.

---

## Testing

```bash
# Health checks
python backend/health_check_services.py

# E2E tests
python backend/run_e2e_tests.py

# Unit tests
pytest backend/tests/
npm test --prefix frontend
```

---

## Tech Stack

### Backend
- **Framework:** FastAPI (Python 3.11)
- **Database:** Supabase (PostgreSQL)
- **Scanners:** OWASP ZAP, Nuclei, Wapiti
- **LLM:** OpenAI GPT-4, Anthropic Claude
- **Async:** asyncio, uvicorn

### Frontend
- **Framework:** React 18
- **Router:** React Router v6
- **HTTP:** Axios
- **Styling:** CSS3 with variables
- **WebSocket:** Native API

### DevOps
- **Containerization:** Docker
- **CI/CD:** GitHub Actions
- **Database:** PostgreSQL
- **Proxy:** Nginx

---

## Security

- JWT authentication
- CORS protection
- Rate limiting
- SQL injection prevention
- XSS protection
- SSL/TLS encryption
- Row-level security
- Secure password hashing

---

## Project Status

**Status:**  **PRODUCTION READY**

### Implementation Complete
- 8 Backend API endpoints
- 3 Integrated scanners
- 2 LLM providers (+ fallback)
- Professional UI
- Docker containerization
- CI/CD pipelines
- Production deployment
- Complete documentation

---

## Troubleshooting

### Backend won't start
```bash
docker-compose logs backend
docker-compose up --build
```

### Frontend connection issues
- Check backend: `http://localhost:8000/docs`
- Verify CORS settings
- Check API URL in environment

### Scanner issues
```bash
python backend/health_check_services.py
```

---

## Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

---

## License

MIT License - see [LICENSE](LICENSE) for details.

---

## Author

**Prateek Shrivastava** ([@pratiyk](https://github.com/pratiyk))

---

## Support

For issues, features, or questions:
- Open [GitHub Issue](https://github.com/pratiyk/Link-Load/issues)
- Check [Documentation](./SETUP_AND_CONFIG.md)
- Review [Project Status](./PROJECT_COMPLETION_SUMMARY.md)

---

**Built with ❤️ for web security**

Latest Update: October 26, 2025 | Version: 1.0.0 | Status: Production Ready
