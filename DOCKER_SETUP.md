# Docker Setup Guide

## Prerequisites

- Docker installed and running
- Docker Compose installed
- Git (to clone the repository)

## Quick Start

### 1. Clone Repository

```bash
git clone https://github.com/pratiyk/Link-Load.git
cd Link-Load
```

### 2. Create Environment File

```bash
# Copy example environment file
cp .env.example .env

# Edit .env with your configuration
nano .env  # macOS/Linux
# or
notepad .env  # Windows
```

### 3. Start All Services

```bash
# Build and start all containers
docker-compose up -d

# Or with logging
docker-compose up

# Or rebuild and start
docker-compose up --build -d
```

### 4. Verify Services

```bash
# Check container status
docker-compose ps

# View logs
docker-compose logs -f

# Check specific service
docker-compose logs -f backend
docker-compose logs -f frontend
```

### 5. Initialize Database

```bash
# Run migrations
docker-compose exec backend alembic upgrade head

# Or manually create tables (if alembic not available)
docker-compose exec postgres psql -U linkload -d linkload -f /docker-entrypoint-initdb.d/init.sql
```

### 6. Access Services

- **Frontend:** http://localhost:3000
- **Backend API:** http://localhost:8000
- **API Docs:** http://localhost:8000/docs
- **OWASP ZAP:** http://localhost:8090
- **PostgreSQL:** localhost:5432

## Common Docker Commands

### View Logs

```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f backend
docker-compose logs -f frontend

# Last 100 lines
docker-compose logs --tail=100

# Follow new logs
docker-compose logs -f --tail=50
```

### Execute Commands

```bash
# Run Python script in backend
docker-compose exec backend python script.py

# Access PostgreSQL
docker-compose exec postgres psql -U linkload -d linkload

# List all databases
docker-compose exec postgres psql -U linkload -l
```

### Stop Services

```bash
# Stop all containers
docker-compose stop

# Stop and remove containers
docker-compose down

# Remove volumes (data)
docker-compose down -v
```

### Rebuild Services

```bash
# Rebuild specific service
docker-compose build backend
docker-compose up -d backend

# Rebuild all and restart
docker-compose up --build -d
```

### Health Checks

```bash
# Check if services are healthy
docker-compose ps

# Manual health check
curl http://localhost:8000/docs
curl http://localhost:3000
curl http://localhost:8090/JSON/core/action/version/
```

## Environment Variables

Edit `.env` file to configure:

- Database credentials
- API keys (Supabase, OpenAI, Anthropic)
- Scanner endpoints
- CORS origins
- Logging levels

See `.env.example` for all available options.

## Production Setup

For production deployment with Nginx:

```bash
# Start with production profile
docker-compose --profile production up -d

# Create SSL certificates
mkdir -p ssl
# Add your SSL certificates to ./ssl/ directory
```

Edit `nginx.conf` for your domain and SSL settings.

## Troubleshooting

### Container Won't Start

```bash
# Check logs
docker-compose logs backend

# Rebuild
docker-compose down
docker-compose up --build

# Remove dangling images
docker image prune -a
```

### Database Connection Failed

```bash
# Check PostgreSQL is running
docker-compose ps postgres

# Verify environment variables in .env
cat .env | grep DB_

# Check database exists
docker-compose exec postgres psql -U linkload -l
```

### API Not Responding

```bash
# Check backend logs
docker-compose logs backend

# Verify port is not in use
lsof -i :8000  # macOS/Linux
netstat -ano | findstr :8000  # Windows
```

### Frontend Build Failed

```bash
# Clear node_modules and rebuild
docker-compose down frontend
docker volume prune
docker-compose up --build frontend
```

## Docker Networks

Link&Load uses a custom network `linkload-network` for service communication:

```bash
# View network
docker network ls

# Inspect network
docker network inspect linkload-network

# Services can communicate using container names:
# - backend: http://backend:8000
# - postgres: postgresql://postgres:5432
# - owasp-zap: http://owasp-zap:8090
```

## Monitoring

### View Resource Usage

```bash
# Real-time stats
docker stats

# Specific container
docker stats linkload-backend

# Memory and CPU limits
docker-compose top
```

### Container Inspect

```bash
# View container configuration
docker inspect linkload-backend

# View running processes
docker-compose top backend

# View port bindings
docker port linkload-backend
```

## Backup and Restore

### Backup Database

```bash
# Create backup
docker-compose exec postgres pg_dump -U linkload linkload > backup.sql

# Create compressed backup
docker-compose exec postgres pg_dump -U linkload linkload | gzip > backup.sql.gz
```

### Restore Database

```bash
# Restore from backup
docker-compose exec -T postgres psql -U linkload linkload < backup.sql

# Restore from compressed backup
gunzip < backup.sql.gz | docker-compose exec -T postgres psql -U linkload linkload
```

## Development Tips

### Hot Reload

Backend and frontend have hot reload enabled by default:

- **Backend:** Changes to Python files auto-reload
- **Frontend:** Changes to React files auto-refresh

No container restart needed!

### Running Tests

```bash
# Backend tests
docker-compose exec backend python -m pytest

# E2E tests
docker-compose exec backend python run_e2e_tests.py

# Frontend tests
docker-compose exec frontend npm test
```

### Database Migrations

```bash
# Create new migration
docker-compose exec backend alembic revision --autogenerate -m "description"

# Apply migrations
docker-compose exec backend alembic upgrade head

# View migration history
docker-compose exec backend alembic history
```

## Performance Tuning

### Resource Limits

Edit `docker-compose.yml`:

```yaml
services:
  backend:
    deploy:
      resources:
        limits:
          cpus: '4'
          memory: 8G
        reservations:
          cpus: '2'
          memory: 4G
```

### Database Optimization

```bash
# Connect to PostgreSQL
docker-compose exec postgres psql -U linkload

# Vacuum and analyze
VACUUM ANALYZE;
```

## Security Considerations

1. **Change default passwords** in `.env`
2. **Use strong SECRET_KEY** for production
3. **Enable SSL/TLS** (nginx profile)
4. **Restrict CORS_ORIGINS** to known domains
5. **Use Supabase in production**, not local PostgreSQL
6. **Keep Docker images updated** regularly
7. **Use secrets management** for API keys

## Support

For issues or questions:

1. Check logs: `docker-compose logs -f`
2. Review `.env` configuration
3. Verify all services are running: `docker-compose ps`
4. Check documentation: `SETUP_AND_CONFIG.md`
5. Run health checks: `python backend/health_check_services.py`

---

**Happy Scanning!** 🚀
