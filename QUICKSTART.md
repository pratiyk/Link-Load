# Quick Start Guide

This guide will help you get Link&Load running on your local machine in under 10 minutes. Follow these steps to set up both the backend API server and frontend web interface.

---

## System Requirements

Before starting, ensure your system has the following software installed:

- Python 3.9+ with pip
- Node.js 16+ with npm
- PostgreSQL 12+ (or Supabase account)
- Redis server (optional, for production rate limiting)

---

## Backend Setup

### 1. Install Python Dependencies

Navigate to the backend directory and set up a virtual environment:

```bash
cd backend

# Create a new virtual environment
python -m venv .venv

# Activate the virtual environment
# On Windows:
.venv\Scripts\activate
# On macOS/Linux:
source .venv/bin/activate

# Install required packages
pip install -r requirements.txt
```

---

### 2. Configure Environment Variables

Create your environment configuration file:

```bash
# Copy the example configuration
cp .env.example .env

# Generate secure secret keys
python -c "import secrets; print('SECRET_KEY=' + secrets.token_urlsafe(32))"
python -c "import secrets; print('CSRF_SECRET=' + secrets.token_urlsafe(32))"
```

Edit the `.env` file and add your generated keys along with your database connection details:

- SECRET_KEY
- CSRF_SECRET
- DATABASE_URL

---

### 3. Initialize the Database

The application will automatically create necessary database tables on first startup. Alternatively, you can initialize them manually:

```bash
python -c "from app.database import init_db; init_db()"
```

---

### 4. Start the Backend Server

Launch the API server in development mode:

```bash
uvicorn app.main:app --reload --port 8000
```

The backend will be accessible at [http://localhost:8000](http://localhost:8000) with interactive API documentation at [http://localhost:8000/docs](http://localhost:8000/docs).

---

## Frontend Setup

### 1. Install Node Dependencies

Open a new terminal window and navigate to the frontend directory:

```bash
cd frontend
npm install
```

---

### 2. Configure Frontend Environment

Set up the frontend environment configuration:

```bash
cp .env.example .env
```

The default configuration should work for local development:

- REACT_APP_API_URL=http://localhost:8000
- REACT_APP_WS_URL=ws://localhost:8000

---

### 3. Start the Frontend Development Server

Launch the React development server:

```bash
npm start
```

The frontend application will open in your browser at [http://localhost:3000](http://localhost:3000).

---

## Testing Your Installation

### Create a Test User Account

You can test the application by registering a new user account either through the web interface or via API.

**Using the Web Interface:**
1. Go to [http://localhost:3000/register](http://localhost:3000/register)
2. Fill in the registration form
3. Submit to create your account

**Using the API directly:**

```bash
curl -X POST http://localhost:8000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "username": "testuser",
    "password": "Test123!@#",
    "confirm_password": "Test123!@#"
  }'
```

---

### Log In and Test Functionality

After creating an account, log in and test the various scanning modules:

1. **Link Scanner**: Test with a sample URL to verify VirusTotal integration
2. **Vulnerability Scanner**: Scan a software package for known vulnerabilities
3. **Phishing Detector**: Analyze a URL for phishing indicators

---

## Troubleshooting Common Issues

### Backend Won't Start

- Verify Python version: `python --version`
- Check dependencies: `pip list`
- Ensure database connection string is correct in `.env`

### Frontend Build Errors

- Verify Node.js version: `node --version`
- Clear npm cache: `npm cache clean --force`
- Delete node_modules and reinstall: `rm -rf node_modules && npm install`

### Database Connection Issues

- Verify PostgreSQL is running and accessible
- Check database credentials in `.env`
- For Supabase, ensure project URL and keys are configured

---

## Next Steps

Once you have the basic setup running:

1. Review the full Setup Instructions for production deployment guidance
2. Configure optional security tools (OWASP ZAP, Nuclei) for enhanced scanning
3. Set up API keys for external services like VirusTotal and Google Safe Browsing
4. Explore the interactive API documentation at [http://localhost:8000/docs](http://localhost:8000/docs)

---

