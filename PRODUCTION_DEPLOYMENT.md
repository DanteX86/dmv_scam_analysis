# Production Deployment Guide

## Overview

This guide covers the complete production deployment process for the DMV Scam Analysis framework, including API deployment, model management, security configuration, and monitoring setup.

## Prerequisites

### System Requirements

- **CPU**: 4+ cores (8+ recommended for high throughput)
- **RAM**: 8GB minimum (16GB+ recommended)
- **Storage**: 50GB+ available space
- **OS**: Linux (Ubuntu 20.04+, CentOS 8+) or Docker-compatible environment

### Software Dependencies

- Docker 20.10+
- Docker Compose 2.0+
- Python 3.11+ (if not using Docker)
- PostgreSQL 15+ (for production data storage)
- Redis 7+ (for caching and rate limiting)

## Quick Start with Docker

### 1. Environment Setup

Create a `.env` file with production configuration:

```bash
# API Configuration
API_KEY=your-secure-api-key-here
API_SECRET_KEY=your-secret-key-for-jwt-signing
LOG_LEVEL=INFO

# Database Configuration
POSTGRES_USER=dmv_prod_user
POSTGRES_PASSWORD=secure-database-password
POSTGRES_DB=dmv_analysis_prod

# Redis Configuration (if using external Redis)
REDIS_URL=redis://localhost:6379/0

# Monitoring
ENABLE_MONITORING=true
PROMETHEUS_PORT=9090

# Security
CORS_ORIGINS=https://yourdomain.com,https://app.yourdomain.com
RATE_LIMIT_REQUESTS=1000
RATE_LIMIT_WINDOW=3600
```

### 2. Deploy with Docker Compose

```bash
# Build and start all services
docker-compose up -d

# Check service health
docker-compose ps

# View logs
docker-compose logs dmv-api
```

### 3. Verify Deployment

```bash
# Health check
curl http://localhost:8000/health

# Test authentication (replace with your API key)
curl -H "Authorization: Bearer your-api-key" \
     -H "Content-Type: application/json" \
     -d '{"text": "Your DMV license will expire", "source": "sms", "timestamp": "2024-01-01T12:00:00Z"}' \
     http://localhost:8000/analyze
```

## Manual Deployment (Non-Docker)

### 1. System Setup

```bash
# Install system dependencies (Ubuntu/Debian)
sudo apt-get update
sudo apt-get install python3.11 python3.11-venv python3-pip postgresql redis-server

# Create application user
sudo useradd -m -s /bin/bash dmvapi
sudo su - dmvapi
```

### 2. Application Setup

```bash
# Clone and setup application
git clone <your-repo> dmv-analysis
cd dmv-analysis

# Create virtual environment
python3.11 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
pip install uvicorn[standard] gunicorn

# Install the package
pip install -e .
```

### 3. Database Setup

```bash
# Create PostgreSQL database
sudo -u postgres createuser dmv_prod_user
sudo -u postgres createdb dmv_analysis_prod -O dmv_prod_user
sudo -u postgres psql -c "ALTER USER dmv_prod_user PASSWORD 'secure-password';"

# Set up database schema (if using database persistence)
python -m src.dmv_scam_analysis.db.migrate
```

### 4. Service Configuration

Create systemd service file `/etc/systemd/system/dmv-api.service`:

```ini
[Unit]
Description=DMV Scam Analysis API
After=network.target postgresql.service redis.service

[Service]
Type=exec
User=dmvapi
Group=dmvapi
WorkingDirectory=/home/dmvapi/dmv-analysis
Environment=PATH=/home/dmvapi/dmv-analysis/venv/bin
EnvironmentFile=/home/dmvapi/dmv-analysis/.env
ExecStart=/home/dmvapi/dmv-analysis/venv/bin/gunicorn src.dmv_scam_analysis.api.app:app -w 4 -k uvicorn.workers.UvicornWorker -b 0.0.0.0:8000
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

Enable and start the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable dmv-api
sudo systemctl start dmv-api
sudo systemctl status dmv-api
```

## Security Configuration

### 1. API Security

**Authentication:**

- Generate secure API keys (32+ character random strings)
- Use environment variables for all sensitive configuration
- Implement token rotation policies

```bash
# Generate secure API key
openssl rand -hex 32

# Generate JWT secret
openssl rand -hex 64
```

**Rate Limiting:**

- Default: 1000 requests/hour per client
- Adjust based on expected usage patterns
- Monitor for abuse patterns

**CORS Configuration:**

- Restrict origins to your actual domains
- Never use `*` in production
- Update `CORS_ORIGINS` environment variable

### 2. Infrastructure Security

**Network Security:**

```bash
# Firewall configuration (UFW example)
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw allow 8000/tcp  # API port
sudo ufw enable
```

**SSL/TLS Configuration:**
Use a reverse proxy (nginx/Apache) with SSL certificates:

```nginx
server {
    listen 443 ssl http2;
    server_name api.yourdomain.com;

    ssl_certificate /path/to/certificate.pem;
    ssl_certificate_key /path/to/private.key;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## Model Management

### 1. Model Deployment

```python
# Initialize model manager
from src.dmv_scam_analysis.core.model_manager import ModelManager
manager = ModelManager()

# Deploy a trained model
model_id = manager.save_model(
    model=trained_model,
    model_name="threat_classifier",
    version="v1.0.0",
    performance_metrics={
        "accuracy": 0.95,
        "precision": 0.93,
        "recall": 0.97
    }
)

# Set as active model
manager.set_active_model(model_id)
```

### 2. Model Updates

```bash
# Update model via API (requires admin privileges)
curl -X POST -H "Authorization: Bearer admin-key" \
     -F "model=@new_model.pkl" \
     -F "metadata={\"version\": \"1.1.0\", \"notes\": \"Improved accuracy\"}" \
     http://localhost:8000/admin/models/deploy
```

### 3. Model Monitoring

```python
# Monitor model performance
performance = manager.get_model_performance(model_id)
print(f"Current accuracy: {performance['accuracy']}")

# Set up automated retraining triggers
if performance['accuracy'] < 0.85:
    print("Model performance degraded - retraining recommended")
```

## Monitoring and Logging

### 1. Application Logs

Logs are stored in the `logs/` directory:

- `api_audit.log` - API access and performance logs
- `application.log` - General application logs
- `error.log` - Error and exception logs

**Log Rotation:**

```bash
# Configure logrotate
sudo nano /etc/logrotate.d/dmv-api

/home/dmvapi/dmv-analysis/logs/*.log {
    daily
    rotate 30
    compress
    delaycompress
    notifempty
    create 0644 dmvapi dmvapi
    postrotate
        systemctl reload dmv-api
    endscript
}
```

### 2. Performance Monitoring

**Prometheus Metrics:** (if enabled)

- API response times
- Request rates
- Error rates
- Model performance metrics

Access Prometheus at: `http://localhost:9090`

**Key Metrics to Monitor:**

- Response time percentiles (p50, p95, p99)
- Request rate (requests/second)
- Error rate percentage
- Memory usage
- CPU utilization
- Model prediction confidence distribution

### 3. Alerting

Set up alerts for:

- API response time > 1 second
- Error rate > 5%
- Memory usage > 80%
- Model confidence drop below threshold

## Performance Optimization

### 1. Scaling Configuration

**Horizontal Scaling:**

```yaml
# docker-compose.yml
services:
  dmv-api:
    deploy:
      replicas: 3
    # Add load balancer configuration
```

**Vertical Scaling:**

- Increase worker processes: `-w 8` (for 8-core systems)
- Adjust memory limits based on model size
- Optimize database connections

### 2. Caching Strategy

**Redis Caching:**

- Cache model predictions for identical inputs
- Cache authentication tokens
- Cache frequently accessed model metadata

```python
# Example caching configuration
CACHE_CONFIG = {
    'prediction_ttl': 3600,  # 1 hour
    'model_metadata_ttl': 86400,  # 24 hours
    'auth_token_ttl': 1800,  # 30 minutes
}
```

### 3. Database Optimization

**PostgreSQL Tuning:**

```sql
-- Optimize for analysis workloads
ALTER SYSTEM SET shared_buffers = '256MB';
ALTER SYSTEM SET work_mem = '64MB';
ALTER SYSTEM SET maintenance_work_mem = '256MB';
SELECT pg_reload_conf();
```

## Backup and Recovery

### 1. Model Backups

```bash
# Backup models directory
tar -czf models-backup-$(date +%Y%m%d).tar.gz models/

# Sync to cloud storage (example with AWS S3)
aws s3 sync models/ s3://your-bucket/dmv-analysis/models/
```

### 2. Database Backups

```bash
# PostgreSQL backup
pg_dump -U dmv_prod_user -h localhost dmv_analysis_prod > backup_$(date +%Y%m%d).sql

# Automated backup script
cat > backup.sh << 'EOF'
#!/bin/bash
BACKUP_DIR="/var/backups/dmv-analysis"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p $BACKUP_DIR

# Database backup
pg_dump -U dmv_prod_user dmv_analysis_prod > $BACKUP_DIR/db_$DATE.sql

# Models backup
tar -czf $BACKUP_DIR/models_$DATE.tar.gz models/

# Keep only last 7 days
find $BACKUP_DIR -name "*.sql" -mtime +7 -delete
find $BACKUP_DIR -name "*.tar.gz" -mtime +7 -delete
EOF

chmod +x backup.sh
```

### 3. Recovery Procedures

**Database Recovery:**

```bash
# Restore database
dropdb dmv_analysis_prod
createdb dmv_analysis_prod -O dmv_prod_user
psql -U dmv_prod_user dmv_analysis_prod < backup_20240101.sql
```

**Model Recovery:**

```bash
# Restore models
tar -xzf models_backup.tar.gz -C ./
systemctl restart dmv-api
```

## Troubleshooting

### Common Issues

1. **High Response Times**

   - Check model loading performance
   - Review database query performance
   - Monitor memory usage

2. **Authentication Failures**

   - Verify API key configuration
   - Check rate limiting settings
   - Review audit logs

3. **Model Prediction Errors**
   - Verify model file integrity
   - Check input data format
   - Review feature extraction process

### Health Checks

```bash
# Comprehensive health check script
cat > health_check.sh << 'EOF'
#!/bin/bash

echo "=== DMV Analysis API Health Check ==="

# API Health
curl -f http://localhost:8000/health || echo "API health check failed"

# Database connectivity
pg_isready -h localhost -U dmv_prod_user || echo "Database connection failed"

# Redis connectivity
redis-cli ping || echo "Redis connection failed"

# Disk space
df -h | grep -E "/$|/home" || echo "Disk space check failed"

# Memory usage
free -h || echo "Memory check failed"

echo "Health check completed"
EOF

chmod +x health_check.sh
```

## Support and Maintenance

### Regular Maintenance Tasks

1. **Daily:**

   - Review error logs
   - Check API performance metrics
   - Verify backup completion

2. **Weekly:**

   - Review model performance metrics
   - Update threat intelligence data
   - Clean up old log files

3. **Monthly:**
   - Model retraining with new data
   - Security updates and patches
   - Performance optimization review

### Getting Support

For technical support and questions:

- Review logs in `/logs/` directory
- Check GitHub issues and documentation
- Use the health check script for diagnostics

---

**Last Updated:** {datetime.now().strftime('%Y-%m-%d')}
**Version:** Production v1.0.0
