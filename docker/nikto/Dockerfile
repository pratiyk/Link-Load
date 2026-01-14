# Nikto Scanner Sidecar Container
# This container runs Nikto web vulnerability scanner as a service

FROM perl:5.38-slim

LABEL maintainer="LinkLoad Team"
LABEL description="Nikto Web Vulnerability Scanner Sidecar"

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    wget \
    git \
    ca-certificates \
    libssl-dev \
    make \
    gcc \
    libnet-ssleay-perl \
    libwhisker2-perl \
    && rm -rf /var/lib/apt/lists/*

# Create results directory
RUN mkdir -p /results /app/reports /shared

# Clone and install Nikto
WORKDIR /opt
RUN git clone https://github.com/sullo/nikto.git && \
    cd nikto/program && \
    chmod +x nikto.pl

# Install Perl dependencies
RUN cpan -T \
    JSON \
    LWP::Protocol::https

# Set working directory
WORKDIR /opt/nikto/program

# Update Nikto databases
RUN perl nikto.pl -update || true

# Verify installation
RUN perl nikto.pl -Version

# Keep container running (will be called via docker exec)
CMD ["tail", "-f", "/dev/null"]
