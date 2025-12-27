# Backend Dockerfile
FROM python:3.12-slim

WORKDIR /app/backend

# Install system dependencies including libgomp for LightGBM and Docker CLI for scanner sidecars
RUN apt-get update && apt-get install -y \
    curl \
    libgomp1 \
    git \
    ca-certificates \
    gnupg \
    && install -m 0755 -d /etc/apt/keyrings \
    && curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg \
    && chmod a+r /etc/apt/keyrings/docker.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null \
    && apt-get update \
    && apt-get install -y docker-ce-cli \
    && rm -rf /var/lib/apt/lists/*

# Upgrade pip to latest version
RUN pip install --no-cache-dir --upgrade pip

# Copy requirements and constraints (using Docker-optimized requirements for faster builds)
COPY requirements-docker.txt constraints.txt ./

# Install Python dependencies with constraints for version overrides
RUN pip install --no-cache-dir -c constraints.txt -r requirements-docker.txt


# Copy application code
COPY . .

# Ensure logs directory exists for log file handlers
RUN mkdir -p /app/backend/logs

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8000/docs || exit 1

# Run application
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
