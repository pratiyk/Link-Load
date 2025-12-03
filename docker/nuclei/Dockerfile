# Nuclei Scanner Sidecar Container
# This container runs Nuclei vulnerability scanner as a service

FROM projectdiscovery/nuclei:latest

LABEL maintainer="LinkLoad Team"
LABEL description="Nuclei Vulnerability Scanner Sidecar"

# Create results directory
RUN mkdir -p /results /app/reports

# Update nuclei templates on startup
RUN nuclei -update-templates || true

# Set working directory
WORKDIR /app

# Keep container running (will be called via docker exec)
ENTRYPOINT ["tail", "-f", "/dev/null"]
