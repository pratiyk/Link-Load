# Wapiti Scanner Sidecar Container
# This container runs Wapiti vulnerability scanner as a service

FROM python:3.11-slim

LABEL maintainer="LinkLoad Team"
LABEL description="Wapiti Web Vulnerability Scanner Sidecar"

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    wget \
    git \
    build-essential \
    libssl-dev \
    libffi-dev \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Create results directory
RUN mkdir -p /results /app/reports

# Install wapiti3 with minimal dependencies
# Use specific versions to avoid conflicts
RUN pip install --no-cache-dir \
    wapiti3==3.2.1 \
    && pip cache purge

# Verify installation
RUN wapiti --version

# Set working directory
WORKDIR /app

# Keep container running (will be called via docker exec)
CMD ["tail", "-f", "/dev/null"]
