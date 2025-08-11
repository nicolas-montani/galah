# ELK Stack Integration for Galah Honeypot

This document provides comprehensive instructions for integrating Elasticsearch, Logstash, and Kibana (ELK Stack) with the Galah honeypot for advanced logging, analysis, and visualization capabilities.

## Overview

The ELK Stack integration provides:

- **Elasticsearch**: Distributed search and analytics engine for storing and indexing honeypot events
- **Logstash**: Data processing pipeline for ingesting, parsing, and enriching Galah logs
- **Kibana**: Web interface for visualizing and analyzing honeypot data
- **Enhanced Logging**: Structured JSON output optimized for ELK Stack compatibility

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│                 │    │                 │    │                 │    │                 │
│  Galah Honeypot │───▶│    Logstash     │───▶│  Elasticsearch  │◀──▶│     Kibana      │
│                 │    │                 │    │                 │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘    └─────────────────┘
       │                         │                       │                       │
       │                         │                       │                       │
   JSON Logs              Data Processing         Document Storage        Visualization
   File Output            & Enrichment           & Indexing             & Analysis
```

## Prerequisites

- Docker and Docker Compose installed
- At least 8GB of available RAM (for local Ollama model)
- 20GB of available disk space (includes model storage)
- Optional: LLM API key for cloud providers (OpenAI, Anthropic, Google, etc.)

**Note**: The default configuration uses Ollama with DeepSeek-R1 model for fully local operation without external API dependencies.

## Quick Start

### Option 1: Single Command Setup (Recommended)

```bash
# Clone and start everything with one command
git clone <repository-url>
cd galah
docker compose up -d

# Wait for services to start (takes 5-10 minutes for first run)
# Ollama will automatically download deepseek-r1:latest model

# Import dashboards (after services are ready)
./scripts/import-dashboards.sh
```

### Option 2: Step-by-Step Setup

#### 1. Initial Setup

```bash
# Clone and navigate to the project
cd galah

# Run initial setup
./scripts/setup-elk.sh setup

# Edit environment configuration (optional)
# Default uses Ollama with deepseek-r1:latest (no API key needed)
cp .env.example .env
```

#### 2. Start ELK Stack

```bash
# Start all ELK services
./scripts/setup-elk.sh start

# Wait for services to be ready (takes 2-5 minutes)
```

#### 3. Import Dashboards

```bash
# Import pre-configured Kibana dashboards
./scripts/import-dashboards.sh
```

#### 4. Start Galah Honeypot

```bash
# Start the honeypot to begin collecting data
docker-compose up galah
```

### 5. Access Kibana

- **URL**: http://localhost:5601
- **Username**: elastic
- **Password**: (configured in .env file, default: galah123)

## Configuration

### Environment Variables

Key configuration options in `.env`:

```bash
# LLM Configuration
LLM_PROVIDER=openai
LLM_MODEL=gpt-4o-mini
LLM_API_KEY=your_api_key_here

# ELK Authentication
ELASTIC_PASSWORD=your_secure_password
KIBANA_ENCRYPTION_KEY=your_32_character_encryption_key

# Network Ports
GALAH_HTTP_PORT=8080
GALAH_HTTPS_PORT=8443
ELASTICSEARCH_PORT=9200
KIBANA_PORT=5601
LOGSTASH_PORT=5000
```

### Docker Compose Services

The integration includes the following services:

- **galah**: The honeypot application
- **elasticsearch**: Search and analytics engine
- **logstash**: Log processing pipeline
- **kibana**: Visualization dashboard

### Log Format

Enhanced log format for ELK compatibility:

```json
{
  "@timestamp": "2024-08-09T10:30:00.000Z",
  "honeypot": "galah",
  "srcIP": "192.168.1.100",
  "srcPort": "45123",
  "port": "8080",
  "httpRequest": {
    "method": "GET",
    "request": "/admin/login",
    "userAgent": "Mozilla/5.0...",
    "sessionID": "1691580600_abc123",
    "contentType": "application/json",
    "requestSize": 1024
  },
  "httpResponse": {
    "status": 200,
    "body": "..."
  },
  "responseMetadata": {
    "generationSource": "llm",
    "info": {
      "provider": "openai",
      "model": "gpt-4o-mini",
      "temperature": 0.7
    }
  },
  "geoip": {
    "country_name": "United States",
    "city_name": "New York",
    "location": {
      "lat": 40.7128,
      "lon": -74.0060
    }
  },
  "suricataMatches": [
    {
      "sid": "2001001",
      "msg": "SQL Injection Attempt"
    }
  ]
}
```

## Dashboard Features

### Pre-built Dashboards

1. **Overview Dashboard**
   - Real-time request timeline
   - Geographic distribution of attacks
   - Top targeted endpoints
   - HTTP method distribution
   - Response status analysis

2. **Security Analysis**
   - Suricata rule triggers
   - Attack vector analysis
   - Suspicious pattern detection
   - Session tracking

3. **Performance Monitoring**
   - LLM response times
   - Cache hit rates
   - System resource usage

### Custom Visualizations

Create custom visualizations using these indexed fields:

- `@timestamp`: Event timestamp
- `srcIP`: Source IP address
- `geoip.country_name`: Country of origin
- `httpRequest.method`: HTTP method
- `httpRequest.request`: Requested path
- `httpResponse.status`: Response status code
- `llm_provider`: LLM provider used
- `suricataMatches`: Security rule matches
- `session_id`: Session identifier

## Management Scripts

### Setup Script

```bash
# Initial setup
./scripts/setup-elk.sh setup

# Start services
./scripts/setup-elk.sh start

# Stop services
./scripts/setup-elk.sh stop

# Check status
./scripts/setup-elk.sh status
```

### Dashboard Import

```bash
# Import all dashboards
./scripts/import-dashboards.sh
```

### Data Reset

```bash
# Reset data only
./scripts/reset-elk.sh data

# Full reset (data + volumes)
./scripts/reset-elk.sh full

# Reset and restart
./scripts/reset-elk.sh restart
```

## Troubleshooting

### Common Issues

1. **Services Not Starting**
   ```bash
   # Check Docker resources
   docker system df
   docker system prune  # Clean up if needed
   
   # Check service logs
   docker-compose logs elasticsearch
   docker-compose logs kibana
   docker-compose logs logstash
   ```

2. **No Data in Kibana**
   ```bash
   # Check if Galah is generating logs
   tail -f logs/galah.json
   
   # Check Elasticsearch indices
   curl -u elastic:password http://localhost:9200/_cat/indices
   
   # Check Logstash pipeline
   curl http://localhost:9600/_node/stats/pipelines
   ```

3. **Memory Issues**
   ```bash
   # Reduce memory allocation in docker-compose.yml
   ES_JAVA_OPTS=-Xms512m -Xmx512m
   LS_JAVA_OPTS=-Xmx512m -Xms512m
   ```

4. **Permission Errors**
   ```bash
   # Fix Elasticsearch data permissions
   sudo chown -R 1000:1000 elasticsearch_data/
   chmod 777 elasticsearch_data/
   ```

### Log Analysis

Check component logs:

```bash
# Elasticsearch logs
docker-compose logs elasticsearch

# Logstash logs
docker-compose logs logstash

# Kibana logs
docker-compose logs kibana

# Galah logs
docker-compose logs galah
```

### Performance Tuning

1. **Elasticsearch**
   - Increase heap size for large datasets
   - Configure index lifecycle management
   - Optimize refresh intervals

2. **Logstash**
   - Adjust pipeline workers
   - Configure batch sizes
   - Enable persistent queues

3. **Kibana**
   - Set appropriate time ranges
   - Use index patterns efficiently
   - Limit visualization complexity

## Security Considerations

1. **Authentication**
   - Change default passwords in `.env`
   - Use strong encryption keys
   - Enable TLS/SSL in production

2. **Network Security**
   - Restrict access to ELK ports
   - Use reverse proxy for external access
   - Configure firewall rules

3. **Data Protection**
   - Encrypt data at rest
   - Configure backup strategies
   - Implement data retention policies

## Advanced Configuration

### Index Templates

Customize Elasticsearch mappings in:
- `elk/logstash/templates/galah-template.json`

### Logstash Pipelines

Modify data processing in:
- `elk/logstash/pipeline/galah.conf`

### Custom Dashboards

Create dashboards through Kibana UI and export:
- Navigate to Stack Management > Saved Objects
- Export dashboards as JSON
- Store in `elk/kibana/dashboards/`

## Integration with External Tools

### SIEM Integration

Forward logs to external SIEM:
```yaml
# Add to Logstash output
syslog {
  host => "siem.example.com"
  port => 514
  protocol => "tcp"
}
```

### Alerting

Configure Elasticsearch Watcher for alerts:
```json
{
  "trigger": {
    "schedule": {
      "interval": "1m"
    }
  },
  "input": {
    "search": {
      "request": {
        "indices": ["galah-events-*"],
        "body": {
          "query": {
            "range": {
              "@timestamp": {
                "gte": "now-1m"
              }
            }
          }
        }
      }
    }
  }
}
```

## Backup and Restore

### Elasticsearch Snapshots

```bash
# Create snapshot repository
curl -X PUT "localhost:9200/_snapshot/galah_backup" -H 'Content-Type: application/json' -d'
{
  "type": "fs",
  "settings": {
    "location": "/usr/share/elasticsearch/backups"
  }
}
'

# Create snapshot
curl -X PUT "localhost:9200/_snapshot/galah_backup/snapshot_1"
```

### Kibana Objects

```bash
# Export saved objects
curl -X POST "localhost:5601/api/saved_objects/_export" \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true" \
  -d '{"type": "dashboard"}'
```

## Support

For issues and questions:
- Check troubleshooting section above
- Review Docker Compose logs
- Consult Elastic Stack documentation
- Open issues in the Galah repository

## Contributing

To contribute ELK integration improvements:
1. Test changes thoroughly
2. Update documentation
3. Follow existing code patterns
4. Submit pull requests with clear descriptions