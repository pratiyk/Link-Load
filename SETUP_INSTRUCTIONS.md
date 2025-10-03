# Installation and Setup Guide

This document provides comprehensive instructions for setting up the Link&Load security platform on your local development environment or production server.

---

## System Prerequisites

### Essential Software Requirements

- Python 3.9 or newer with pip
- Node.js 16+ with npm
- PostgreSQL or Supabase account
- Git

### Additional Security Tools

For enhanced scanning, you may optionally install:

- **OWASP ZAP** ([download](https://www.zaproxy.org/download/))
- **Nuclei** (`go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest`)
- **Wapiti** (`pip install wapiti3`)

---

## Backend Configuration

### Installing Python Dependencies

Navigate to the backend directory and set up the Python environment:

```powershell
cd c:\prateek\projects\linkload\backend
```

If pip is not available:

```powershell
python -m ensurepip --upgrade
python -m pip install --upgrade pip
```

Install required packages:

```powershell
python -m pip install -r requirements.txt
```

---

### Environment Configuration

Create a `.env` file in the backend directory with the following settings:

```env
# Application Settings
API_PREFIX=/api/v1
ENVIRONMENT=development
ENABLE_DOCS=true
CORS_ORIGINS=http://localhost:3000,http://localhost:3001

# Security Configuration
SECRET_KEY=your-super-secret-key-change-this-in-production
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=10080

# Database Connection (Supabase)
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_KEY=your-anon-key
SUPABASE_SERVICE_KEY=your-service-role-key
SUPABASE_HOST=db.your-project.supabase.co
SUPABASE_PORT=5432
SUPABASE_DB=postgres
SUPABASE_USER=postgres
SUPABASE_PASSWORD=your-database-password

# Scanner Configuration
ZAP_BASE_URL=http://localhost:8080
ZAP_API_KEY=your-zap-api-key
NUCLEI_BINARY_PATH=nuclei
WAPITI_BINARY_PATH=wapiti
SCAN_TIMEOUT=600

# External API Keys (Optional)
VT_API_KEY=your-virustotal-api-key
GSB_API_KEY=your-google-safe-browsing-key
LEAK_LOOKUP_API_KEY=your-leak-lookup-key
RAPIDAPI_KEY=your-rapidapi-key

# Email Configuration (Optional)
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASSWORD=your-app-password
NOTIFICATION_FROM=noreply@yourdomain.com
```

---

### Database Setup

If using Alembic for migrations:

```powershell
cd backend
alembic upgrade head
```

Or create tables manually:

```powershell
python -m app.create_tables
```

---

### Starting the Backend Server

For development:

```powershell
cd backend
python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

For production:

```powershell
cd backend
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 4
```

---

### Verifying Backend Installation

- API Docs: http://localhost:8000/docs
- Health Check: http://localhost:8000/health
- OpenAPI Schema: http://localhost:8000/openapi.json

---

## Frontend Configuration

### Installing Node.js Dependencies

Navigate to the frontend directory and install packages:

```powershell
cd c:\prateek\projects\linkload\frontend
npm install
```

---

### Frontend Environment Setup

Create a `.env` file in the frontend directory:

```env
# Backend API Configuration
REACT_APP_API_URL=http://localhost:8000
REACT_APP_WS_URL=ws://localhost:8000

# Application Settings
REACT_APP_NAME=Link&Load Security Platform
REACT_APP_VERSION=1.0.0
REACT_APP_ENVIRONMENT=development

# Feature Flags
REACT_APP_ENABLE_ANALYTICS=false
REACT_APP_ENABLE_DEBUG=true
```

---

### Starting the Frontend Development Server

```powershell
npm start
```

The app will open at http://localhost:3000

---

### Building for Production

```powershell
npm run build
```

Production files will be in the `build/` directory.

---

## Security Tools Configuration

### OWASP ZAP Setup

1. Download and install OWASP ZAP
2. Launch ZAP with API access enabled
3. Configure the ZAP API key in your `.env`
4. Ensure ZAP is accessible at http://localhost:8080

### Nuclei Scanner Setup

1. Install Go if needed
2. Install Nuclei: `go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest`
3. Update templates: `nuclei -update-templates`
4. Verify: `nuclei -version`

### Wapiti Scanner Setup

1. Install: `pip install wapiti3`
2. Verify: `wapiti --version`
3. Configure binary path in `.env` if needed

---

## External API Integration

- **VirusTotal**: Create account, get API key, add to `.env` as `VT_API_KEY`
- **Google Safe Browsing**: Enable API, get key, add as `GSB_API_KEY`
- **LeakLookup, RapidAPI, Shodan**: Add keys as needed

---

## Production Deployment

### Database

- Use dedicated PostgreSQL with security configs
- Enable SSL
- Regular backups
- Connection pooling

### Application Security

- Strong, unique secret keys
- HTTPS with valid SSL
- Proper CORS policies
- Rate limiting and logging

### Performance

- Use nginx/Apache as reverse proxy
- Configure backend workers
- Redis caching
- Gzip compression

---

## Troubleshooting

### Common Issues

**Python Dependencies Fail to Install**
- Check Python version
- Update pip
- Install system-level dependencies

**Database Connection Errors**
- Verify server is running
- Check connection string and credentials
- Ensure database exists and permissions are correct

**Frontend Build Failures**
- Clear npm cache: `npm cache clean --force`
- Delete node_modules and reinstall
- Check for global package conflicts

**Scanner Integration Issues**
- Verify tools are installed and accessible
- Check file permissions
- Ensure network connectivity

### Performance Issues

**Slow Scans**
- Increase timeouts
- Check system resources
- Optimize database queries

**High Memory Usage**
- Monitor logs for leaks
- Adjust worker processes
- Clean up long-running scans

---

## Support and Maintenance

### Logging

Logs are in logs:
- Errors and exceptions
- Security events
- Scan results

### Maintenance

- Update tool templates and signatures
- Rotate API keys
- Monitor disk space
- Keep dependencies updated

### Backup

- Regular database backups
- Back up configs and environment files
- Document custom setups
- Test restoration procedures

---

For more help, see the project documentation or submit issues on GitHub.

---

