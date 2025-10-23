# Production Deployment Guide

## Pre-Deployment Checklist

- [ ] All tests passing locally
- [ ] Environment variables configured
- [ ] Database backups created
- [ ] SSL certificates obtained
- [ ] Domain DNS configured
- [ ] Monitoring setup
- [ ] Security audit completed

---

## 1. Server Setup

### Infrastructure Requirements

- **CPU:** 4+ cores
- **RAM:** 8GB+ (16GB recommended)
- **Storage:** 100GB+ SSD
- **Bandwidth:** Unlimited or very high
- **OS:** Ubuntu 20.04 LTS or later

### Recommended Platforms

1. **AWS EC2**
   - Instance type: t3.large or t3.xlarge
   - Storage: 100GB gp3
   - Security groups: HTTP/HTTPS from 0.0.0.0/0

2. **DigitalOcean**
   - App Platform (managed) or Droplets (self-managed)
   - 4GB+ RAM
   - 100GB+ storage

3. **Linode**
   - Linode 8GB
   - NVMe SSD
   - Premium support

4. **GCP / Azure**
   - Similar specifications as AWS
   - Cloud Run for serverless option

### Initial Server Setup

```bash
# Update system
sudo apt-get update && sudo apt-get upgrade -y

# Install Docker and Docker Compose
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Verify installation
docker --version
docker-compose --version

# Create deployment user
sudo useradd -m -s /bin/bash linkload
sudo usermod -aG docker linkload

# Create application directory
sudo mkdir -p /opt/linkload
sudo chown linkload:linkload /opt/linkload
```

---

## 2. SSL/TLS Certificate Configuration

### Option A: Let's Encrypt (Recommended - Free)

```bash
# Install Certbot
sudo apt-get install certbot python3-certbot-nginx -y

# Generate certificate
sudo certbot certonly --standalone -d linkload.example.com -d www.linkload.example.com

# Auto-renewal setup
sudo certbot renew --dry-run

# Certificate paths:
# Private key: /etc/letsencrypt/live/linkload.example.com/privkey.pem
# Certificate: /etc/letsencrypt/live/linkload.example.com/fullchain.pem
```

### Option B: Commercial Certificate

```bash
# Place your certificate files in:
# /etc/ssl/certs/linkload.crt
# /etc/ssl/private/linkload.key
```

### Configure Nginx with SSL

Create `/opt/linkload/nginx.conf`:

```nginx
user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log warn;
pid /var/run/nginx.pid;

events {
    worker_connections 1024;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';

    access_log /var/log/nginx/access.log main;

    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    client_max_body_size 100M;

    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types text/plain text/css text/xml text/javascript 
               application/json application/javascript application/xml+rss;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "no-referrer-when-downgrade" always;

    # Redirect HTTP to HTTPS
    server {
        listen 80;
        server_name linkload.example.com www.linkload.example.com;
        return 301 https://$server_name$request_uri;
    }

    # HTTPS Server
    server {
        listen 443 ssl http2;
        server_name linkload.example.com www.linkload.example.com;

        # SSL Configuration
        ssl_certificate /etc/letsencrypt/live/linkload.example.com/fullchain.pem;
        ssl_certificate_key /etc/letsencrypt/live/linkload.example.com/privkey.pem;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers HIGH:!aNULL:!MD5;
        ssl_prefer_server_ciphers on;

        # Backend API
        location /api/ {
            proxy_pass http://backend:8000;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_read_timeout 300s;
            proxy_connect_timeout 300s;
        }

        # WebSocket
        location /api/v1/scans/ws/ {
            proxy_pass http://backend:8000;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "Upgrade";
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        # Frontend
        location / {
            proxy_pass http://frontend:3000;
            proxy_http_version 1.1;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        # Static files
        location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)$ {
            proxy_pass http://frontend:3000;
            proxy_cache_valid 200 30d;
            expires 30d;
            add_header Cache-Control "public, immutable";
        }
    }
}
```

---

## 3. Environment Configuration for Production

Create `/opt/linkload/.env.production`:

```bash
# Database
DATABASE_URL=postgresql://user:password@host:5432/linkload
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_KEY=your-anon-key

# Scanners
ZAP_URL=http://localhost:8090
NUCLEI_PATH=/usr/bin/nuclei
WAPITI_PATH=/usr/bin/wapiti

# LLM (Choose one)
OPENAI_API_KEY=sk-...
# or
ANTHROPIC_API_KEY=sk-ant-...

# Security
SECRET_KEY=<generate-with-secrets-module>
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=60

# API
API_TITLE=Link&Load
API_VERSION=1.0.0
CORS_ORIGINS=["https://linkload.example.com"]

# Logging
LOG_LEVEL=INFO
LOG_FORMAT=json
SENTRY_DSN=https://your-sentry-dsn

# Monitoring
DATADOG_API_KEY=your-datadog-key
PROMETHEUS_ENABLED=true
```

---

## 4. Production docker-compose.yml

```yaml
version: '3.8'

services:
  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_PASSWORD: ${DB_PASSWORD}
      POSTGRES_DB: ${DB_NAME}
      POSTGRES_MAX_CONNECTIONS: 500
      POSTGRES_SHARED_BUFFERS: 512MB
      POSTGRES_EFFECTIVE_CACHE_SIZE: 2GB
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./backups:/backups
    networks:
      - linkload-network
    restart: always
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 4G

  owasp-zap:
    image: owasp/zap2docker-stable:latest
    command: zap.sh -config api.disablekey=true -daemon -host 0.0.0.0
    environment:
      ZAP_CONFIG_DAEMON: "true"
    networks:
      - linkload-network
    restart: always
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 4G

  backend:
    image: ${REGISTRY}/linkload-backend:latest
    environment:
      DATABASE_URL: ${DATABASE_URL}
      SUPABASE_URL: ${SUPABASE_URL}
      SUPABASE_KEY: ${SUPABASE_KEY}
      SECRET_KEY: ${SECRET_KEY}
      OPENAI_API_KEY: ${OPENAI_API_KEY}
      SENTRY_DSN: ${SENTRY_DSN}
    depends_on:
      - postgres
    networks:
      - linkload-network
    restart: always
    deploy:
      replicas: 2
      resources:
        limits:
          cpus: '2'
          memory: 2G
        reservations:
          cpus: '1'
          memory: 1G

  frontend:
    image: ${REGISTRY}/linkload-frontend:latest
    environment:
      REACT_APP_API_URL: https://linkload.example.com/api
    networks:
      - linkload-network
    restart: always
    deploy:
      resources:
        limits:
          cpus: '1'
          memory: 1G

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - /etc/letsencrypt:/etc/letsencrypt:ro
      - ./logs:/var/log/nginx
    depends_on:
      - backend
      - frontend
    networks:
      - linkload-network
    restart: always
    deploy:
      resources:
        limits:
          cpus: '1'
          memory: 512M

volumes:
  postgres_data:
    driver: local

networks:
  linkload-network:
    driver: bridge
```

---

## 5. Database Backup Strategy

### Automated Daily Backups

Create `/opt/linkload/backup.sh`:

```bash
#!/bin/bash
set -e

BACKUP_DIR="/opt/linkload/backups"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_FILE="$BACKUP_DIR/linkload_$TIMESTAMP.sql.gz"

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Create backup
docker-compose exec -T postgres pg_dump -U linkload linkload | gzip > "$BACKUP_FILE"

# Keep only last 30 days
find "$BACKUP_DIR" -name "linkload_*.sql.gz" -mtime +30 -delete

# Upload to S3 (optional)
# aws s3 cp "$BACKUP_FILE" s3://your-backup-bucket/

echo "Backup created: $BACKUP_FILE"
```

Setup cron job:

```bash
# Add to crontab (runs daily at 2 AM)
0 2 * * * /opt/linkload/backup.sh >> /opt/linkload/logs/backup.log 2>&1
```

---

## 6. Monitoring and Logging

### Setup Prometheus

Create `/opt/linkload/prometheus.yml`:

```yaml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'backend'
    static_configs:
      - targets: ['backend:8000']
    metrics_path: '/metrics'
```

### Setup ELK Stack (Optional)

```bash
# Elasticsearch, Logstash, Kibana for log aggregation
docker-compose exec -d elasticsearch bin/elasticsearch
docker-compose exec -d logstash bin/logstash
docker-compose exec -d kibana bin/kibana
```

Access Kibana: `http://localhost:5601`

---

## 7. Deployment Steps

### 1. Deploy to Production Server

```bash
# SSH into server
ssh linkload@production-server.com

# Navigate to app directory
cd /opt/linkload

# Clone repository
git clone https://github.com/pratiyk/Link-Load.git .

# Create .env file
nano .env.production

# Build images
docker-compose build

# Start services
docker-compose up -d

# Check health
docker-compose ps
docker-compose logs -f backend
```

### 2. Run Migrations

```bash
# Apply database migrations
docker-compose exec backend alembic upgrade head

# Verify tables
docker-compose exec postgres psql -U linkload -d linkload -c "\dt"
```

### 3. Health Checks

```bash
# API health
curl https://linkload.example.com/docs

# Frontend
curl https://linkload.example.com

# Scanner health
docker-compose logs owasp-zap | grep -i "listening"
```

---

## 8. Monitoring and Maintenance

### Daily Checks

```bash
#!/bin/bash
# Check service health
docker-compose ps

# Check disk space
df -h

# Check memory usage
free -h

# Check logs for errors
docker-compose logs --tail 100 | grep -i error
```

### Weekly Maintenance

```bash
# Update images
docker-compose pull
docker-compose up -d

# Run security scan
docker-compose exec backend python -m bandit -r app/

# Database optimization
docker-compose exec postgres vacuumdb -U linkload linkload
```

### Monthly Review

- Review error logs
- Audit access logs
- Update dependencies
- Test backup recovery
- Review performance metrics

---

## 9. Scaling Configuration

### Horizontal Scaling (Multiple Backend Instances)

```yaml
backend:
  deploy:
    replicas: 3  # Run 3 instances
    update_config:
      parallelism: 1
      delay: 10s
```

### Load Balancing with Nginx

```nginx
upstream backend {
    server backend:8000;
    server backend-2:8000;
    server backend-3:8000;
}

location /api/ {
    proxy_pass http://backend;
}
```

---

## 10. Troubleshooting

### Services Not Starting

```bash
# Check error logs
docker-compose logs

# Restart all services
docker-compose restart

# Force rebuild
docker-compose up --build -d
```

### High Memory Usage

```bash
# Check memory per container
docker stats

# Restart container
docker-compose restart backend
```

### SSL Certificate Issues

```bash
# Check certificate expiry
echo | openssl s_client -servername linkload.example.com -connect linkload.example.com:443 2>/dev/null | openssl x509 -noout -dates

# Renew certificate
sudo certbot renew --force-renewal
```

### Database Connection Issues

```bash
# Test connection
docker-compose exec postgres psql -U linkload -d linkload -c "SELECT 1"

# Restart postgres
docker-compose restart postgres
```

---

## 11. Security Hardening

### Firewall Configuration

```bash
# UFW (Ubuntu Firewall)
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp      # SSH
sudo ufw allow 80/tcp      # HTTP
sudo ufw allow 443/tcp     # HTTPS
sudo ufw enable
```

### Regular Security Updates

```bash
# Auto-update critical patches
sudo apt-get install unattended-upgrades -y
```

### API Rate Limiting

Already configured in backend - adjust in production `.env`:

```bash
RATE_LIMIT_REQUESTS=1000
RATE_LIMIT_WINDOW=60
```

---

## 12. Post-Deployment Validation

Run complete E2E test suite:

```bash
# From backend container
python run_e2e_tests.py
```

Verify:
- [ ] Frontend loads correctly
- [ ] API endpoints respond
- [ ] WebSocket connections work
- [ ] Scans can be initiated
- [ ] Results display correctly
- [ ] Database queries work
- [ ] All services are healthy

---

## Support and Documentation

- **API Docs:** https://linkload.example.com/docs
- **GitHub:** https://github.com/pratiyk/Link-Load
- **Issues:** Report bugs on GitHub Issues
- **Monitoring:** Check Prometheus/Datadog dashboards

---

**Deployment Date:** _______________
**Deployed By:** _______________
**Version:** _______________
