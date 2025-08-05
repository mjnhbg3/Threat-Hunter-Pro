# RAG-Enhanced Threat Hunter Pro - Docker Infrastructure Setup

This document provides comprehensive instructions for setting up the containerized infrastructure for the RAG-Enhanced Threat Hunter Pro system.

## Quick Start

1. **Copy environment file and configure:**
   ```bash
   cp .env.example .env
   # Edit .env with your API keys and configuration
   ```

2. **Start the complete system:**
   ```bash
   docker compose up -d
   ```

3. **Verify system health:**
   ```bash
   docker compose run --rm health-checker
   ```

4. **Access the services:**
   - Threat Hunter Dashboard: http://localhost:8000
   - Grafana Monitoring: http://localhost:3000 (admin/admin)
   - Prometheus Metrics: http://localhost:9090

## Prerequisites

### Required
- Docker Engine 20.10+ and Docker Compose 2.0+
- At least 4GB RAM and 10GB free disk space
- Valid Google Gemini API key(s)

### Optional (for development)
- Git for version control
- VS Code or preferred IDE

## Configuration

### Environment Variables

The system requires several environment variables. Copy `.env.example` to `.env` and configure:

#### Required Variables
```bash
# Authentication (REQUIRED)
BASIC_AUTH_USER=your_username
BASIC_AUTH_PASS=your_secure_password

# Google Gemini API (REQUIRED)
GEMINI_API_KEY=your_primary_api_key

# Optional additional API keys for rate limiting
GEMINI_API_KEY_2=your_secondary_api_key
GEMINI_API_KEY_3=your_tertiary_api_key
```

#### System Paths
Adjust these paths to match your Wazuh installation:
```bash
# Default Wazuh paths
LOG_FILE=/var/ossec/logs/alerts/alerts.json
DB_DIR=/var/ossec/integrations/threat_hunter_db
```

For Windows or custom installations, update the volume mounts in `docker-compose.yml`:
```yaml
volumes:
  # Update this path to your actual Wazuh logs location
  - /path/to/your/wazuh/logs:/app/logs:ro
```

## Service Architecture

### Core Services

1. **threat-hunter-app** (Port 8000)
   - Main Python application with FastAPI
   - Handles web UI, AI processing, and API endpoints
   - Preserves all existing functionality

2. **vector-store** (Port 8001)
   - Enhanced FAISS vector database service
   - Automatic backups and optimization
   - Redis caching for improved performance

3. **search-service** (Port 8002) 
   - BM25 and metadata search capabilities
   - Time-based query optimization
   - Full-text search indexing

4. **summary-store** (Port 8003)
   - Hierarchical summary storage
   - Compression and efficient retrieval
   - Time-range based queries

5. **redis** (Port 6379)
   - Caching layer for all services
   - Session management
   - Rate limiting support

### Monitoring Services

6. **prometheus** (Port 9090)
   - Metrics collection from all services
   - 30-day data retention
   - Custom alerting rules

7. **grafana** (Port 3000)
   - Observability dashboards
   - Pre-configured datasources
   - System performance monitoring

### Development Services

8. **elasticsearch** (Port 9200) - Optional
   - Alternative search backend for testing
   - Only starts with `dev` profile

9. **jupyter** (Port 8888) - Optional
   - Data analysis and experimentation
   - Pre-installed with required libraries

## Startup Modes

### Production Mode (Default)
```bash
docker compose up -d
```
Starts core services with production optimizations.

### Development Mode
```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d
```
Includes hot reloading, debug features, and additional tools.

### With Optional Services
```bash
# Start with Elasticsearch
docker compose --profile dev up -d

# Start with Jupyter for analysis
docker compose --profile analysis up -d

# Start with PostgreSQL for testing
docker compose --profile postgres up -d
```

## Data Persistence

### Volume Mounts

All critical data is persisted in Docker volumes:

- `threat_hunter_data`: Main application database
- `vector_store_data`: FAISS indices and embeddings
- `search_service_data`: BM25 indices and metadata
- `summary_store_data`: Compressed summaries
- `redis_data`: Cache and session data
- `prometheus_data`: Metrics history
- `grafana_data`: Dashboards and configuration

### Existing Data Migration

The system preserves your existing FAISS database:

1. **Automatic Migration**: The system automatically mounts your existing database directory
2. **Backup Before Migration**: 
   ```bash
   # Backup existing data
   sudo cp -r /var/ossec/integrations/threat_hunter_db /var/ossec/integrations/threat_hunter_db.backup
   ```

3. **Verify Data Location**: Check that the `DB_DIR` environment variable points to your existing database

## Health Monitoring

### Automated Health Checks

Every service includes health checks that verify:
- Service responsiveness
- Database connectivity
- Resource utilization
- API endpoint availability

### Manual Health Verification

Run the comprehensive health check:
```bash
docker compose run --rm health-checker
```

This script tests:
- All service endpoints
- Inter-service communication
- Database operations
- Cache functionality
- Metrics collection

### Service Status Monitoring

Check individual service status:
```bash
# Main application
curl http://localhost:8000/health

# Vector store
curl http://localhost:8001/health

# Search service
curl http://localhost:8002/health

# Summary store
curl http://localhost:8003/health
```

## Troubleshooting

### Common Issues

#### 1. Services Not Starting
```bash
# Check logs
docker compose logs threat-hunter-app

# Check resource usage
docker stats

# Verify environment variables
docker compose config
```

#### 2. Memory Issues
If you encounter out-of-memory errors:
```bash
# Reduce memory limits in .env
VECTOR_STORE_MAX_MEMORY=1024
REDIS_MAX_MEMORY=256
ES_JAVA_OPTS=-Xms256m -Xmx256m
```

#### 3. Permission Issues
For Wazuh log access:
```bash
# Ensure Docker can read Wazuh logs
sudo chmod 644 /var/ossec/logs/alerts/alerts.json
sudo chown root:docker /var/ossec/logs/alerts/
```

#### 4. Port Conflicts
If ports are already in use:
```bash
# Check what's using the port
netstat -tulpn | grep :8000

# Update port mappings in docker-compose.yml
ports:
  - "8080:8000"  # Changed from 8000:8000
```

### Log Analysis

View logs for debugging:
```bash
# All services
docker compose logs -f

# Specific service
docker compose logs -f threat-hunter-app

# Last 100 lines
docker compose logs --tail=100 vector-store
```

### Performance Tuning

#### For Production Environments

1. **Increase Resource Limits**:
```yaml
# In docker-compose.yml
deploy:
  resources:
    limits:
      memory: 2G
      cpus: '1.0'
```

2. **Optimize Redis Configuration**:
```bash
# In .env
REDIS_MAX_MEMORY=1024
REDIS_SEARCH_TTL=7200
```

3. **Configure Prometheus Retention**:
```bash
# In .env
PROMETHEUS_RETENTION=60d
```

## Backup and Recovery

### Automated Backups

Services automatically backup critical data:
- Vector indices every hour
- Metadata every 15 minutes
- Configuration on changes

### Manual Backup

```bash
# Create full system backup
docker compose exec threat-hunter-app python -m backup.create_snapshot

# Backup specific volumes
docker run --rm -v threat_hunter_data:/data -v $(pwd):/backup ubuntu tar czf /backup/threat_hunter_backup.tar.gz /data
```

### Recovery Process

```bash
# Stop services
docker compose down

# Restore data volume
docker run --rm -v threat_hunter_data:/data -v $(pwd):/backup ubuntu tar xzf /backup/threat_hunter_backup.tar.gz -C /

# Restart services
docker compose up -d
```

## Security Considerations

### Production Deployment

1. **Change Default Passwords**:
   - Update all default credentials in `.env`
   - Use strong, unique passwords

2. **Network Security**:
   - Services communicate on isolated Docker network
   - Only necessary ports exposed to host

3. **File Permissions**:
   - Application runs as non-root user
   - Sensitive data in protected volumes

4. **API Security**:
   - HTTP Basic Auth for web interface
   - Internal service-to-service authentication

### Firewall Configuration

For production deployments, configure firewall rules:
```bash
# Allow only necessary ports
sudo ufw allow 8000/tcp  # Main application
sudo ufw allow 3000/tcp  # Grafana (optional)
sudo ufw deny 9090/tcp   # Prometheus (internal only)
sudo ufw deny 6379/tcp   # Redis (internal only)
```

## Development Workflow

### Hot Reloading

Development mode enables hot reloading:
```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d
```

Changes to Python files automatically restart the services.

### Database Development

Access development tools:
- Redis Commander: http://localhost:8081
- File Browser: http://localhost:8080 (with file-browser profile)
- Jupyter Notebooks: http://localhost:8888

### Adding New Services

1. Define service in `docker-compose.yml`
2. Add health check endpoint
3. Update Prometheus scraping configuration
4. Add to health check script

## Monitoring and Alerting

### Grafana Dashboards

Pre-configured dashboards monitor:
- Application performance metrics
- Vector database operations
- Search service performance
- System resource utilization
- Error rates and response times

### Prometheus Metrics

All services expose metrics at `/metrics` endpoints:
- Request rates and latencies
- Database operation counts
- Memory and CPU usage
- Cache hit rates
- AI model performance

### Custom Alerts

Configure alerts in `config/prometheus/alert_rules.yml`:
```yaml
- alert: HighErrorRate
  expr: rate(http_requests_total{status=~"5.."}[5m]) > 0.1
  for: 2m
  annotations:
    summary: High error rate detected
```

## Support and Maintenance

### Regular Maintenance

1. **Weekly**: Review Grafana dashboards for performance trends
2. **Monthly**: Clean up old logs and backup files
3. **Quarterly**: Update base images and security patches

### Updates and Upgrades

```bash
# Update base images
docker compose pull

# Restart with new images
docker compose up -d

# Verify system health
docker compose run --rm health-checker
```

### Getting Help

1. Check service logs for error messages
2. Run health check script for diagnostic information
3. Review Grafana dashboards for performance issues
4. Consult the troubleshooting section above

For additional support, ensure you have:
- Complete error logs
- Environment configuration
- System resource information
- Recent changes or modifications