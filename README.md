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
cp .env.example .env
# Edit .env with your configuration

# Deploy all units
docker-compose up -d

# Initialize database schema
docker-compose exec backend alembic upgrade head

# Verify deployment
curl http://localhost:8000/health
```

### Development Deployment

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

### Access Points

| Service | URL | Description |
|---------|-----|-------------|
| Command Center | http://localhost:3000 | Primary user interface |
| API Gateway | http://localhost:8000 | REST API endpoints |
| API Documentation | http://localhost:8000/docs | Interactive Swagger docs |
| ZAP Interface | http://localhost:8090 | Scanner admin panel |

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

**Priority Order:**
1. Groq (Llama 3.3 70B) - Fast, cost-effective
2. OpenAI (GPT-3.5/4) - High accuracy
3. Anthropic (Claude) - Detailed analysis
4. Fallback Engine - Basic heuristic analysis

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

```bash
# Database Configuration
DATABASE_URL=postgresql://user:pass@localhost:5432/linkload
SUPABASE_URL=https://project.supabase.co
SUPABASE_KEY=your-anon-key

# Scanner Configuration
ZAP_URL=http://localhost:8090
ZAP_API_KEY=your-zap-api-key
NUCLEI_BINARY_PATH=/usr/bin/nuclei
NUCLEI_TEMPLATES_PATH=/opt/nuclei-templates
WAPITI_BINARY_PATH=/usr/bin/wapiti

# AI Provider Keys (configure at least one)
GROQ_API_KEY=gsk_...
OPENAI_API_KEY=sk-...
ANTHROPIC_API_KEY=sk-ant-...

# Security Configuration
SECRET_KEY=your-256-bit-secret-key
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30

# Application Settings
ENVIRONMENT=development
CORS_ORIGINS=http://localhost:3000,http://localhost:8000
ENABLE_DOCS=true
LOG_LEVEL=INFO

# Redis Cache
REDIS_URL=redis://localhost:6379/0
```

### Docker Compose Services

| Service | Image | Port | Purpose |
|---------|-------|------|---------|
| postgres | postgres:15-alpine | 5432 | Primary database |
| owasp-zap | owasp/zap2docker-stable | 8090 | ZAP scanner |
| backend | custom | 8000 | API server |
| frontend | custom | 3000 | Web interface |
| nginx | nginx:alpine | 80/443 | Reverse proxy |

---

## VERIFICATION PROCEDURES

### Health Check

```bash
# System health
python backend/health_check_services.py

# Individual service status
curl http://localhost:8000/health
curl http://localhost:8090/JSON/core/action/version/
```

### Test Suite Execution

```bash
# Backend unit tests
cd backend
pytest tests/ -v

# End-to-end integration tests
python run_e2e_tests.py

# Frontend tests
cd frontend
npm test
```

### Validation Checklist

- [ ] All containers running: `docker-compose ps`
- [ ] Database connectivity: Health endpoint returns db_status: true
- [ ] Scanner availability: ZAP version endpoint responds
- [ ] Frontend loads: Browser access to port 3000
- [ ] API documentation: Swagger UI at /docs
- [ ] Authentication flow: Login returns valid JWT

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

**Backend Initialization Failure:**
```bash
docker-compose logs backend
docker-compose up --build backend
```

**Scanner Connection Issues:**
```bash
# Verify ZAP is running
curl http://localhost:8090/JSON/core/action/version/

# Check Nuclei installation
nuclei -version

# Verify Wapiti
wapiti --version
```

**Database Connection Problems:**
```bash
docker-compose logs postgres
docker-compose exec postgres pg_isready
```

**Frontend Build Errors:**
```bash
cd frontend
rm -rf node_modules package-lock.json
npm install
npm start
```

### Common Issues

| Issue | Resolution |
|-------|------------|
| CORS errors | Verify CORS_ORIGINS in backend .env |
| JWT expired | Re-authenticate via login endpoint |
| Scanner timeout | Increase timeout_minutes in scan options |
| Database locked | Restart postgres container |
| Out of memory | Increase Docker memory allocation |

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

**Project Lead:** Prateek Shrivastava ([@pratiyk](https://github.com/pratiyk))

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
║    Version: 1.0.0                                                            ║
║    Status: OPERATIONAL                                                       ║
║    Last Updated: November 2025                                               ║
║                                                                              ║
║    "Reconnaissance is the foundation of victory."                            ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```
