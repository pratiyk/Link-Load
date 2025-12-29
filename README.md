# LINK&LOAD

## Tactical Web Security Reconnaissance Platform

```
    ██╗     ██╗███╗   ██╗██╗  ██╗     ██╗      ██╗      ██████╗  █████╗ ██████╗ 
    ██║     ██║████╗  ██║██║ ██╔╝    ██╔╝      ██║     ██╔═══██╗██╔══██╗██╔══██╗
    ██║     ██║██╔██╗ ██║█████╔╝    ██╔╝       ██║     ██║   ██║███████║██║  ██║
    ██║     ██║██║╚██╗██║██╔═██╗   ██╔╝        ██║     ██║   ██║██╔══██║██║  ██║
    ███████╗██║██║ ╚████║██║  ██╗ ██╔╝         ███████╗╚██████╔╝██║  ██║██████╔╝
    ╚══════╝╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝ ╚═╝          ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═════╝ 
                                                                                 
              [ CYBER RECONNAISSANCE & THREAT ANALYSIS SYSTEM ]
```

[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.11+-yellow.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104+-blue.svg)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-18+-cyan.svg)](https://react.dev/)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)](https://www.docker.com/)
[![Status](https://img.shields.io/badge/Status-OPERATIONAL-brightgreen.svg)]()
[![Tests](https://img.shields.io/badge/Tests-40+-brightgreen.svg)]()

---

## MISSION BRIEF

Link&Load is an AI-enhanced cyber reconnaissance platform engineered for systematic vulnerability detection and threat assessment. Built for security professionals who demand precision, speed, and actionable intelligence, this platform deploys multiple scanning vectors simultaneously while correlating findings against the MITRE ATT&CK framework.

The system executes coordinated multi-scanner operations, processes raw intelligence through machine learning pipelines, and delivers battlefield-ready security reports with prioritized remediation strategies.

**OPERATIONAL STATUS: FIELD READY**

---


## TABLE OF CONTENTS

- [Operational Capabilities](#operational-capabilities)
- [System Architecture](#system-architecture)
- [Deployment Protocol](#deployment-protocol)
- [Mission Control Interface](#mission-control-interface)
- [API Command Structure](#api-command-structure)
- [Scanner Arsenal](#scanner-arsenal)
- [Intelligence Analysis Engine](#intelligence-analysis-engine)
- [Security Protocols](#security-protocols)
- [Domain Authorization Protocol](#domain-authorization-protocol)
- [Configuration Matrix](#configuration-matrix)
- [Verification Procedures](#verification-procedures)
- [Tactical Roadmap](#tactical-roadmap)
- [Field Support](#field-support)

---

## OPERATIONAL CAPABILITIES

### Multi-Vector Scanning Array

Link&Load deploys a coordinated assault of industry-standard security scanners operating in parallel formation:

| Scanner | Classification | Primary Function |
|---------|---------------|------------------|
| OWASP ZAP | Active Reconnaissance | Full-spectrum web application penetration testing |
| Nuclei | Template-Based Detection | Rapid vulnerability identification via signature matching |
| Wapiti | Black-Box Analysis | Unauthenticated perimeter vulnerability assessment |

All scanners execute concurrently, reducing total reconnaissance time while maximizing coverage depth.

### AI-Powered Threat Intelligence

The platform integrates advanced language models for automated threat analysis:

- **OpenAI GPT Integration** - Deep vulnerability context analysis
- **Anthropic Claude Support** - Alternative intelligence processing
- **Groq Acceleration** - High-speed inference for rapid assessments
- **Fallback Protocol** - Graceful degradation when external services are unavailable

The AI engine processes raw scanner output, correlates findings with known attack patterns, and generates prioritized remediation guidance tailored to business context.

### MITRE ATT&CK Correlation

Every detected vulnerability is automatically mapped to the MITRE ATT&CK framework:

- Technique identification with confidence scoring
- Tactic classification for threat landscape visualization
- CAPEC attack pattern correlation
- TTP (Tactics, Techniques, Procedures) extraction

### Risk Quantification Matrix

The platform computes a normalized risk score (0-10 scale) based on:

- CVSS base scores and severity distribution
- Exploitability metrics and attack complexity
- Business context and asset criticality
- Threat intelligence enrichment

### Real-Time Situational Awareness

WebSocket-based live updates provide:

- Stage-by-stage scan progress monitoring
- Instant vulnerability discovery notifications
- Connection resilience with automatic reconnection
- Multi-client broadcast for team coordination

---

## SYSTEM ARCHITECTURE

```
                              ┌─────────────────────────────┐
                              │     COMMAND CENTER          │
                              │   React 18 + TailwindCSS    │
                              │   Tactical Dashboard UI     │
                              └─────────────┬───────────────┘
                                            │
                                   REST API / WebSocket
                                            │
                              ┌─────────────▼───────────────┐
                              │    OPERATIONS HUB           │
                              │   FastAPI + Async Python    │
                              │   Request Orchestration     │
                              └─────────────┬───────────────┘
                                            │
              ┌─────────────────────────────┼─────────────────────────────┐
              │                             │                             │
    ┌─────────▼─────────┐        ┌──────────▼──────────┐       ┌──────────▼─────────┐
    │   OWASP ZAP       │        │      NUCLEI         │       │      WAPITI        │
    │   Scanner Unit    │        │    Scanner Unit     │       │    Scanner Unit    │
    │   Port 8090       │        │    Binary Exec      │       │    Library/Binary  │
    └─────────┬─────────┘        └──────────┬──────────┘       └──────────┬─────────┘
              │                             │                             │
              └─────────────────────────────┼─────────────────────────────┘
                                            │
                              ┌─────────────▼───────────────┐
                              │   INTELLIGENCE FUSION       │
                              │   Vulnerability Aggregator  │
                              │   Deduplication & Scoring   │
                              └─────────────┬───────────────┘
                                            │
              ┌─────────────────────────────┼─────────────────────────────┐
              │                             │                             │
    ┌─────────▼─────────┐        ┌──────────▼──────────┐       ┌──────────▼─────────┐
    │   LLM SERVICE     │        │   MITRE MAPPER      │       │   RISK ANALYZER    │
    │   AI Analysis     │        │   ATT&CK Mapping    │       │   Score Compute    │
    └─────────┬─────────┘        └──────────┬──────────┘       └──────────┬─────────┘
              │                             │                             │
              └─────────────────────────────┼─────────────────────────────┘
                                            │
                              ┌─────────────▼───────────────┐
                              │   DATA VAULT                │
                              │   PostgreSQL + Supabase     │
                              │   Row-Level Security        │
                              └─────────────────────────────┘
```

### Core Components

**Command Center (Frontend)**
- React 18 with React Router v6
- Real-time WebSocket integration
- Responsive tactical interface
- D3.js threat visualization

**Operations Hub (Backend)**
- FastAPI with async/await architecture
- SQLAlchemy ORM with Alembic migrations
- Redis caching layer for performance
- Rate limiting and security middleware

**Scanner Fleet**
- Containerized OWASP ZAP instance
- Nuclei with template management
- Wapiti with module configuration
- Unified result normalization

**Intelligence Layer**
- Multi-provider LLM integration
- ML-based vulnerability classification
- MITRE ATT&CK knowledge base
- Enhanced risk scoring algorithms

---

## DEPLOYMENT PROTOCOL

### Prerequisites

**Minimum Requirements:**
- Docker Engine 20.10+ and Docker Compose 2.0+
- 8GB RAM (16GB recommended for full scanner deployment)
- 20GB available disk space

**Development Environment:**
- Python 3.11+
- Node.js 18+
- PostgreSQL 15+

### Quick Deployment (Docker)

```bash
# Clone the operations repository
git clone https://github.com/pratiyk/Link-Load.git
cd Link-Load

# Configure environment parameters
cp backend/.env.example backend/.env
cp frontend/.env.example frontend/.env
# Edit .env files with your configuration

# Deploy all units (development mode)
docker-compose up -d

# View logs during startup
docker-compose logs -f

# Verify deployment
curl http://localhost:8000/health
```

### Docker Container Architecture

The platform runs as a multi-container Docker application with the following services:

| Container | Image | Port | Purpose |
|-----------|-------|------|---------|
| `linkload-backend` | python:3.11-slim | 8000 | FastAPI REST API server |
| `linkload-frontend` | node:18-alpine | 3000 | React production build served via `serve` |
| `linkload-zap` | ghcr.io/zaproxy/zaproxy:stable | 8090 | OWASP ZAP security scanner |
| `linkload-postgres` | postgres:15-alpine | 15432 | Local PostgreSQL database |
| `linkload-nginx` | nginx:alpine | 80/443 | Reverse proxy (production profile) |

### Docker Commands Reference

```bash
# ===== Building =====
docker-compose build                    # Build all containers
docker-compose build backend            # Rebuild specific service
docker-compose build --no-cache         # Force fresh build

# ===== Running =====
docker-compose up                       # Start in foreground
docker-compose up -d                    # Start in background (detached)
docker-compose --profile production up  # Include nginx reverse proxy

# ===== Monitoring =====
docker-compose ps                       # List running containers
docker-compose logs -f                  # Stream all logs
docker-compose logs -f backend          # Stream backend logs only
docker-compose logs -f frontend         # Stream frontend logs only

# ===== Stopping =====
docker-compose stop                     # Stop containers (preserve data)
docker-compose down                     # Stop and remove containers
docker-compose down -v                  # Stop and remove volumes (clean slate)

# ===== Cleanup =====
docker-compose down --rmi all           # Remove containers and images
docker system prune -af                 # Clean all unused Docker resources
docker builder prune -af                # Clean build cache
```

### Container Health Checks

All containers include health checks for automatic recovery:

```bash
# Check container health status
docker-compose ps

# Backend health endpoint
curl http://localhost:8000/health

# Frontend health check
curl -s http://localhost:3000 | head -1

# OWASP ZAP version check
curl http://localhost:8090/JSON/core/view/version/
```

### Environment Variable Configuration

The Docker setup supports configuration via environment variables:

**Backend Container (`backend/.env`):**
```bash
# Database (Supabase cloud or local PostgreSQL)
DATABASE_URL=postgresql://user:pass@host:port/db
SUPABASE_URL=https://project.supabase.co
SUPABASE_KEY=your-anon-key

# LLM Providers (configure at least one for AI analysis)
GROQ_API_KEY=gsk_...          # Recommended: Fast & free
OPENAI_API_KEY=sk-...         # Alternative: GPT-3.5/4
ANTHROPIC_API_KEY=sk-ant-...  # Alternative: Claude

# Scanner settings
ZAP_BASE_URL=http://owasp-zap:8090
NUCLEI_BINARY_PATH=/usr/bin/nuclei
WAPITI_BINARY_PATH=/usr/bin/wapiti
```

**Frontend Container (`frontend/.env`):**
```bash
REACT_APP_API_URL=http://localhost:8000
REACT_APP_WS_URL=ws://localhost:8000
REACT_APP_SUPABASE_URL=https://project.supabase.co
REACT_APP_SUPABASE_ANON_KEY=your-anon-key
```

### Development Deployment (Local)

**Backend Operations:**
```bash
cd backend
python -m venv .venv

# Windows
.venv\Scripts\activate

# Linux/macOS
source .venv/bin/activate

pip install -r requirements.txt
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

**Frontend Operations:**
```bash
cd frontend
npm install
npm start
```

**Using Start Scripts (Windows):**
```powershell
# Start backend
.\backend\start_backend.ps1

# Start frontend
.\frontend\start_frontend.ps1
```

### Access Points

| Service | URL | Description |
|---------|-----|-------------|
| Command Center | http://localhost:3000 | Primary user interface |
| API Gateway | http://localhost:8000 | REST API endpoints |
| API Documentation | http://localhost:8000/docs | Interactive Swagger docs |
| ZAP Interface | http://localhost:8090 | Scanner admin panel |
| PostgreSQL (Docker) | localhost:15432 | Local database access |

---

## MISSION CONTROL INTERFACE

### Dashboard Overview

The tactical dashboard provides immediate situational awareness:

- **Active Scans Panel** - Real-time progress of all ongoing operations
- **Threat Summary** - Aggregated vulnerability counts by severity
- **Risk Gauge** - Visual representation of overall security posture
- **Recent Findings** - Latest discovered vulnerabilities with quick actions

### Scan Initiation

1. Enter target URL in the command input
2. Select scanner array (OWASP, Nuclei, Wapiti, or all)
3. Configure scan options (deep scan, AI analysis, MITRE mapping)
4. Execute scan and monitor real-time progress

### Results Analysis

Scan results are presented in a structured intelligence report:

- **Executive Summary** - AI-generated overview for leadership briefing
- **Vulnerability Catalog** - Detailed findings with severity classification
- **MITRE ATT&CK Map** - Visual technique correlation
- **Remediation Queue** - Prioritized action items with effort estimates

---

## API COMMAND STRUCTURE

### Authentication

```bash
# Register new operator
POST /api/v1/auth/register
{
  "email": "operator@command.mil",
  "password": "SecurePass123!"
}

# Authenticate and receive credentials
POST /api/v1/auth/login
{
  "email": "operator@command.mil",
  "password": "SecurePass123!"
}
# Returns: { "access_token": "...", "token_type": "bearer" }
```

### Scan Operations

```bash
# Initiate reconnaissance mission
POST /api/v1/scans/comprehensive/start
Authorization: Bearer <token>
{
  "target_url": "https://target.example.com",
  "scan_types": ["owasp", "nuclei", "wapiti"],
  "options": {
    "enable_ai_analysis": true,
    "enable_mitre_mapping": true,
    "deep_scan": false,
    "timeout_minutes": 30
  }
}
# Returns: { "scan_id": "uuid-string" }

# Query mission status
GET /api/v1/scans/comprehensive/{scan_id}/status
# Returns: { "status": "in_progress", "progress": 45, "current_stage": "Running Nuclei scan" }

# Retrieve intelligence report
GET /api/v1/scans/comprehensive/{scan_id}/result
# Returns full scan results with vulnerabilities, risk assessment, and AI analysis

# Abort mission
POST /api/v1/scans/{scan_id}/cancel
```

### Domain Verification

```bash
# Request domain ownership verification
POST /api/v1/verification/request
{ "domain": "target.example.com" }

# Confirm DNS verification
POST /api/v1/verification/verify
{
  "domain": "target.example.com",
  "verification_token": "linkload-verify-..."
}
```

---

## SCANNER ARSENAL

### OWASP ZAP

The Zed Attack Proxy provides comprehensive active scanning capabilities:

- Spider/crawler for site mapping
- Active scan with attack payloads
- Passive analysis of responses
- AJAX spider for JavaScript-heavy applications
- Authentication handling for protected areas

**Detected Threat Categories:**
- SQL Injection variants
- Cross-Site Scripting (XSS)
- Path Traversal
- Remote Code Execution vectors
- Authentication weaknesses

### Nuclei

Template-driven vulnerability scanner for rapid detection:

- 8000+ community-maintained templates
- Custom template support
- CVE-specific detection
- Misconfiguration identification
- Exposed panel discovery

**Template Categories:**
- CVEs (Known vulnerabilities)
- Default credentials
- Exposed admin panels
- Misconfigurations
- Network services

### Wapiti

Black-box web application security auditor:

- No source code required
- Module-based architecture
- GET/POST parameter fuzzing
- Cookie and header analysis
- Comprehensive reporting

**Attack Modules:**
- SQL/XPath/LDAP injection
- File handling vulnerabilities
- Command execution
- CRLF injection
- Server-side request forgery

---

## INTELLIGENCE ANALYSIS ENGINE

### LLM Integration

The platform supports multiple AI providers with automatic failover:

**Provider Priority Order:**
1. **Groq** (Llama 3.3 70B) - Fast, cost-effective, recommended
2. **OpenAI** (GPT-3.5/4) - High accuracy, broad knowledge
3. **Anthropic** (Claude) - Detailed analysis, reasoning
4. **Fallback Engine** - Basic heuristic analysis (no API required)

**Configuration:**
Set at least one API key in `backend/.env`:
```bash
GROQ_API_KEY=gsk_...          # Get from console.groq.com
OPENAI_API_KEY=sk-...         # Get from platform.openai.com
ANTHROPIC_API_KEY=sk-ant-...  # Get from console.anthropic.com
```

The system automatically selects the highest-priority available provider.

### Analysis Outputs

**Vulnerability Assessment:**
- Severity recalibration based on context
- Exploitation likelihood estimation
- Business impact projection
- Remediation complexity rating

**Executive Summary Generation:**
- Third-person technical narrative
- Security posture assessment
- Critical attack vector identification
- Prioritized remediation roadmap

### MITRE ATT&CK Mapping

The intelligence engine correlates vulnerabilities to ATT&CK techniques:

```
Vulnerability: SQL Injection in login form
    |
    +-- Technique: T1190 (Exploit Public-Facing Application)
    |   Tactic: Initial Access
    |   Confidence: 0.92
    |
    +-- Technique: T1078 (Valid Accounts)
        Tactic: Persistence
        Confidence: 0.78
```

### Risk Scoring Algorithm

```
Risk Score = (Severity Weight * CVSS Score) + 
             (Exploitability Factor) + 
             (Business Context Modifier)

Where:
- Critical: Weight 2.0
- High: Weight 1.5
- Medium: Weight 0.8
- Low: Weight 0.2
```

---

## SECURITY PROTOCOLS

### Authentication Framework

- JWT-based token authentication
- Configurable token expiration
- Refresh token rotation
- Multi-factor authentication ready

### Access Control

- Role-based access control (RBAC)
- Resource ownership verification
- 4-layer data isolation enforcement
- Cross-user access prevention

### Network Security

- HTTPS enforcement in production
- CORS policy configuration
- Rate limiting per endpoint
- Security header injection:
  - Strict-Transport-Security
  - X-Content-Type-Options
  - X-Frame-Options
  - Content-Security-Policy
  - Referrer-Policy

### Data Protection

- Row-level security in PostgreSQL
- Encrypted sensitive fields
- Audit logging for all operations
- Secure credential storage with bcrypt

---

## DOMAIN AUTHORIZATION PROTOCOL

### Purpose

DNS TXT record verification ensures scan authorization by proving domain ownership. This prevents unauthorized reconnaissance against third-party assets.

### Verification Flow

```
OPERATOR                    LINK&LOAD                    DNS SERVER
    |                           |                            |
    |  1. Request Verification  |                            |
    |-------------------------->|                            |
    |                           |                            |
    |  2. Verification Token    |                            |
    |<--------------------------|                            |
    |                           |                            |
    |  3. Add TXT Record        |                            |
    |-------------------------------------------------------->|
    |                           |                            |
    |  4. Confirm & Verify      |                            |
    |-------------------------->|                            |
    |                           |                            |
    |                           |  5. Query TXT Record       |
    |                           |--------------------------->|
    |                           |                            |
    |                           |  6. Record Confirmed       |
    |                           |<---------------------------|
    |                           |                            |
    |  7. Authorization Granted |                            |
    |<--------------------------|                            |
```

### DNS Record Configuration

Add a TXT record to your domain's DNS:

| Field | Value |
|-------|-------|
| Type | TXT |
| Name | _linkload-verify |
| Value | linkload-verify-{token} |
| TTL | 300 |

### Verification Commands

```bash
# Request verification token
curl -X POST http://localhost:8000/api/v1/verification/request \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'

# Confirm domain ownership
curl -X POST http://localhost:8000/api/v1/verification/verify \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com", "verification_token": "linkload-verify-..."}'
```

---

## CONFIGURATION MATRIX

### Environment Variables

**Backend Configuration (`backend/.env`):**
```bash
# ===== Database Configuration =====
DATABASE_URL=postgresql://postgres:UNYe92CVavEN6u7a@localhost:15432/postgres
SUPABASE_URL=https://project.supabase.co
SUPABASE_KEY=your-anon-key
SUPABASE_SERVICE_KEY=your-service-key

# ===== Scanner Configuration =====
ZAP_BASE_URL=http://localhost:8090
ZAP_API_KEY=your-zap-api-key
NUCLEI_BINARY_PATH=/usr/bin/nuclei          # Docker
NUCLEI_BINARY_PATH=C:\tools\nuclei.exe      # Windows
NUCLEI_TEMPLATES_PATH=/opt/nuclei-templates
WAPITI_BINARY_PATH=/usr/bin/wapiti          # Docker
WAPITI_BINARY_PATH=C:\venv\Scripts\wapiti   # Windows
SCAN_TIMEOUT=600

# ===== AI Provider Keys (configure at least one) =====
GROQ_API_KEY=gsk_...          # Recommended: Fast, free tier available
OPENAI_API_KEY=sk-...         # Alternative: GPT-3.5/4
ANTHROPIC_API_KEY=sk-ant-...  # Alternative: Claude

# ===== Security Configuration =====
SECRET_KEY=your-256-bit-secret-key
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=10080
REFRESH_TOKEN_EXPIRE_DAYS=30

# ===== Application Settings =====
ENVIRONMENT=development
CORS_ORIGINS=http://localhost:3000,http://localhost:8000
ENABLE_DOCS=true
LOG_LEVEL=INFO

# ===== Rate Limiting =====
RATE_LIMIT_PER_MINUTE=60
MAX_CONCURRENT_SCANS=3
MAX_SCANS_PER_USER_PER_DAY=10

# ===== Redis Cache (Optional) =====
REDIS_URL=redis://localhost:6379/0

# ===== External Intelligence APIs (Optional) =====
VT_API_KEY=...           # VirusTotal
SHODAN_API_KEY=...       # Shodan
NVD_API_KEY=...          # National Vulnerability Database
ABUSEIPDB_API_KEY=...    # AbuseIPDB
```

**Frontend Configuration (`frontend/.env`):**
```bash
REACT_APP_API_URL=http://localhost:8000
REACT_APP_WS_URL=ws://localhost:8000
REACT_APP_API_TIMEOUT=30000
REACT_APP_SUPABASE_URL=https://project.supabase.co
REACT_APP_SUPABASE_ANON_KEY=your-anon-key
```

### Docker Compose Services

| Service | Image | Port | Purpose | Resources |
|---------|-------|------|---------|-----------|
| backend | python:3.11-slim | 8000 | FastAPI server | - |
| frontend | node:18-alpine | 3000 | React app (serve) | - |
| postgres | postgres:15-alpine | 15432 | Database | - |
| owasp-zap | zaproxy/zaproxy:stable | 8090 | ZAP scanner | 2 CPU, 4GB RAM |
| nginx | nginx:alpine | 80/443 | Reverse proxy | Production only |

---

## VERIFICATION PROCEDURES

### Health Check

```bash
# System health (all services)
python backend/health_check_services.py

# Backend health endpoint
curl http://localhost:8000/health
# Returns: {"status": "healthy", "database": true, "version": "1.0.0"}

# OWASP ZAP version
curl http://localhost:8090/JSON/core/view/version/

# Docker container status
docker-compose ps
```

### Test Suite Execution

```bash
# Backend unit tests
cd backend
pytest tests/ -v

# Backend with coverage
pytest tests/ -v --cov=app --cov-report=html

# End-to-end integration tests
python run_e2e_tests.py

# Frontend tests
cd frontend
npm test
```

### Scanner Verification

```bash
# Verify Nuclei installation
nuclei -version                          # Local
docker-compose exec backend nuclei -version  # Docker

# Verify Wapiti installation
wapiti --version                         # Local
docker-compose exec backend wapiti --version # Docker

# Test Nuclei scan
nuclei -target "http://testhtml5.vulnweb.com" -severity critical,high,medium,low,info

# Verify ZAP API
curl http://localhost:8090/JSON/core/action/version/
```

### LLM Provider Verification

```bash
# Check LLM configuration (from backend directory)
cd backend
python -c "
from app.core.config import settings
print('GROQ_API_KEY:', 'SET' if settings.GROQ_API_KEY else 'NOT SET')
print('OPENAI_API_KEY:', 'SET' if settings.OPENAI_API_KEY else 'NOT SET')
"

# Test LLM service
python -c "
import asyncio
from app.services.llm_service import llm_service
print(f'Active Provider: {type(llm_service._provider).__name__}')
"
```

### Validation Checklist

- [ ] All containers running: `docker-compose ps`
- [ ] Database connectivity: Health endpoint returns `database: true`
- [ ] Scanner availability: ZAP version endpoint responds
- [ ] Frontend loads: Browser access to port 3000
- [ ] API documentation: Swagger UI at /docs
- [ ] Authentication flow: Login returns valid JWT
- [ ] LLM configured: At least one provider set (Groq/OpenAI/Anthropic)
- [ ] Nuclei templates: Templates directory exists and populated

---

## TACTICAL ROADMAP

### Phase 1: Foundation Enhancement (Q1 2026)

**Objective:** Strengthen core platform capabilities

- [ ] Additional scanner integration (Burp Suite API, Nikto)
- [ ] Custom vulnerability template editor
- [ ] Scan scheduling and automation
- [ ] Improved CVSS v4.0 scoring integration
- [ ] Batch scanning for multiple targets

### Phase 2: Enterprise Readiness (Q2 2026)

**Objective:** Scale for organizational deployment

- [ ] Multi-tenancy with organization hierarchies
- [ ] SAML/OIDC SSO integration
- [ ] SCIM user provisioning
- [ ] Role-based access control refinement
- [ ] Audit logging with SIEM export (Splunk, Elastic)
- [ ] Per-tenant encryption keys

### Phase 3: Attack Surface Expansion (Q3 2026)

**Objective:** Comprehensive asset coverage

- [ ] API security scanner integration (OWASP API Top 10)
- [ ] Cloud security posture management (AWS, Azure, GCP)
- [ ] Container and Kubernetes scanning
- [ ] Infrastructure as Code analysis (Terraform, CloudFormation)
- [ ] Continuous asset discovery (DNS, TLS, ASN enumeration)
- [ ] Drift detection and alerting

### Phase 4: Workflow Integration (Q4 2026)

**Objective:** Embed into security operations

- [ ] Jira/ServiceNow ticket creation
- [ ] Slack/Teams/PagerDuty notifications
- [ ] SOAR playbook integration
- [ ] Approval-based remediation workflows
- [ ] SLA tracking and reporting
- [ ] Compliance report generation (PCI-DSS, SOC 2, HIPAA)

### Phase 5: Advanced Intelligence (2027)

**Objective:** Next-generation threat analysis

- [ ] RAG-powered vulnerability context retrieval
- [ ] Real-time threat intelligence feeds integration
- [ ] Predictive vulnerability scoring with ML
- [ ] Attack graph visualization
- [ ] Automated proof-of-concept generation (controlled)
- [ ] Red team operation planning assistance

### Long-Term Vision

- Full-stack application security testing platform
- Unified security operations center integration
- Compliance automation and continuous auditing
- AI-driven remediation recommendations with code fixes
- Community-driven vulnerability intelligence sharing

---

## TECHNOLOGY ARSENAL

### Backend Stack

| Component | Technology | Version |
|-----------|------------|---------|
| Framework | FastAPI | 0.100+ |
| Runtime | Python | 3.11+ |
| ORM | SQLAlchemy | 2.0+ |
| Migrations | Alembic | 1.0+ |
| Cache | Redis | 6.0+ |
| Async | asyncio/uvicorn | Latest |

### Frontend Stack

| Component | Technology | Version |
|-----------|------------|---------|
| Framework | React | 18+ |
| Routing | React Router | 6+ |
| State | React Query | 5+ |
| HTTP | Axios | 1.6+ |
| Styling | TailwindCSS | 3.4+ |
| Charts | D3.js | 7.9+ |

### Infrastructure

| Component | Technology | Purpose |
|-----------|------------|---------|
| Containers | Docker | Service isolation |
| Orchestration | Docker Compose | Development deployment |
| Database | PostgreSQL | Primary data store |
| Database | Supabase | Hosted PostgreSQL option |
| Proxy | Nginx | Production reverse proxy |

---

## FIELD SUPPORT

### Troubleshooting Guide

**Docker Build Failures:**
```bash
# Clean and rebuild
docker-compose down -v
docker system prune -af
docker builder prune -af
docker-compose build --no-cache
docker-compose up -d
```

**Backend Initialization Failure:**
```bash
# View detailed logs
docker-compose logs backend

# Rebuild backend only
docker-compose build backend
docker-compose up -d backend

# Check Python dependencies
docker-compose exec backend pip list
```

**Scanner Connection Issues:**
```bash
# Verify ZAP is running and healthy
docker-compose ps owasp-zap
curl http://localhost:8090/JSON/core/view/version/

# Check Nuclei installation (in container)
docker-compose exec backend nuclei -version

# Check Wapiti installation (in container)
docker-compose exec backend wapiti --version

# View ZAP logs
docker-compose logs owasp-zap
```

**Database Connection Problems:**
```bash
# Check PostgreSQL container
docker-compose logs postgres
docker-compose exec postgres pg_isready

# Connect to database
docker-compose exec postgres psql -U postgres -d postgres

# For Supabase issues, verify credentials in backend/.env
```

**Frontend Build Errors:**
```bash
# Clean install
cd frontend
rm -rf node_modules package-lock.json
npm install
npm start

# Docker rebuild
docker-compose build --no-cache frontend
```

**LLM Provider Issues:**
```bash
# Check if API keys are loaded
cd backend
python -c "from app.core.config import settings; print('GROQ:', bool(settings.GROQ_API_KEY))"

# Test LLM directly
python -c "
import asyncio
from app.services.llm_service import llm_service
result = asyncio.run(llm_service.analyze_vulnerabilities(
    [{'title': 'Test', 'severity': 'high'}], 
    'http://test.com'
))
print('Provider:', type(llm_service._provider).__name__)
print('Result keys:', list(result.keys()))
"
```

**Port Conflicts:**
```bash
# Check what's using ports
netstat -ano | findstr :8000    # Windows
netstat -ano | findstr :3000    # Windows
lsof -i :8000                   # Linux/Mac
lsof -i :3000                   # Linux/Mac

# Kill process by PID
taskkill /PID <pid> /F          # Windows
kill -9 <pid>                   # Linux/Mac
```

### Common Issues

| Issue | Resolution |
|-------|------------|
| CORS errors | Verify CORS_ORIGINS in backend .env includes frontend URL |
| JWT expired | Re-authenticate via login endpoint |
| Scanner timeout | Increase SCAN_TIMEOUT in .env (default: 600 seconds) |
| Database locked | Restart postgres: `docker-compose restart postgres` |
| Out of memory | Increase Docker memory (ZAP needs 4GB+) |
| LLM fallback mode | Set GROQ_API_KEY or OPENAI_API_KEY in backend/.env |
| Nuclei no results | Ensure severity filter includes 'info' level |
| Container unhealthy | Check logs: `docker-compose logs <service>` |
| Build cache issues | Run: `docker builder prune -af` |

### Contact

For operational support, feature requests, or vulnerability reports:

- **Issue Tracker:** [GitHub Issues](https://github.com/pratiyk/Link-Load/issues)
- **Repository:** [github.com/pratiyk/Link-Load](https://github.com/pratiyk/Link-Load)

---

## LEGAL

### License

This project is released under the MIT License. See [LICENSE](LICENSE) for full terms.

### Responsible Use

Link&Load is designed for authorized security testing only. Users must:

- Obtain explicit written permission before scanning any target
- Comply with all applicable laws and regulations
- Use the domain verification system for third-party assets
- Report discovered vulnerabilities responsibly

Unauthorized scanning of systems you do not own or have permission to test is illegal and unethical.

---

## CREDITS

Prateek Shrivastava ([@pratiyk](https://github.com/pratiyk))

**Core Technologies:**
- OWASP Foundation - ZAP Scanner
- ProjectDiscovery - Nuclei Scanner
- Wapiti Project - Wapiti Scanner
- OpenAI / Anthropic / Groq - AI Analysis

---

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║    LINK&LOAD - TACTICAL WEB SECURITY RECONNAISSANCE PLATFORM                ║
║                                                                              ║
║    Version: 1.1.0                                                            ║
║    Status: OPERATIONAL                                                       ║
║    Last Updated: December 2025                                               ║
║                                                                              ║
║    "Reconnaissance is the foundation of victory."                            ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

---

## CHANGELOG

### Version 1.1.0 (December 2025)

**Docker Containerization Improvements:**
- Multi-stage Docker builds for optimized image sizes
- Frontend uses `serve` for production-ready static file hosting
- Backend includes all scanner dependencies (Nuclei, Wapiti)
- OWASP ZAP container with proper health checks and resource limits
- PostgreSQL container for local development
- Nginx reverse proxy (production profile)
- Comprehensive docker-compose configuration with all environment variables

**LLM Provider Integration Fixes:**
- Fixed environment variable loading for GROQ_API_KEY and OPENAI_API_KEY
- LLM service now uses pydantic settings for proper .env file loading
- Added Groq (Llama 3.3 70B) as primary AI provider
- Automatic fallback chain: Groq → OpenAI → Anthropic → Basic Analysis
- Improved executive summary generation with technical language

**Scanner Enhancements:**
- Nuclei severity filter now includes 'info' level by default
- Better vulnerability deduplication across multiple scanners
- Improved error handling for scanner failures
- Scanner availability verification at startup

**API & Backend:**
- Enhanced health check endpoint with database status
- Rate limiting configuration via environment variables
- Improved CORS configuration for Docker networking
- WebSocket support for real-time scan progress

**Frontend:**
- Production build with environment variable injection at build time
- Supabase integration for authentication
- Responsive tactical dashboard interface
- Real-time scan progress via WebSocket

### Version 1.0.0 (November 2025)

- Initial release
- Multi-scanner integration (OWASP ZAP, Nuclei, Wapiti)
- AI-powered vulnerability analysis
- MITRE ATT&CK mapping
- Risk scoring algorithm
- JWT authentication
- Domain verification system
- React frontend with TailwindCSS
