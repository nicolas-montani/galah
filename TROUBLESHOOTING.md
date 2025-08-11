# Galah Honeypot Troubleshooting Guide

This guide covers common issues you may encounter when running the Galah honeypot and their solutions.

## Table of Contents
- [TLS Certificate Issues](#tls-certificate-issues)
- [Ollama Connection Issues](#ollama-connection-issues)
- [LLM Provider Issues](#llm-provider-issues)
- [Port Binding Issues](#port-binding-issues)
- [Configuration Issues](#configuration-issues)
- [Performance Issues](#performance-issues)
- [Cache Issues](#cache-issues)
- [Logging Issues](#logging-issues)

---

## TLS Certificate Issues

### Error: `open cert/cert.pem: no such file or directory`

**Problem**: Galah is trying to start TLS-enabled ports (443, 8443) but cannot find the required certificate files.

**Root Cause**: The configuration file specifies TLS profiles that reference certificate files that don't exist.

#### Solution 1: Create Self-Signed Certificates (Quick Fix)

```bash
# Create cert directory
mkdir -p cert

# Generate private key
openssl genrsa -out cert/key.pem 2048

# Generate self-signed certificate
openssl req -new -x509 -sha256 -key cert/key.pem -out cert/cert.pem -days 365 \
  -subj "/C=US/ST=CA/L=San Francisco/O=Honeypot/OU=Research/CN=localhost"

# Verify files were created
ls -la cert/
```

#### Solution 2: Disable TLS Ports (HTTP Only)

Edit `config/config.yaml` and remove or comment out TLS-enabled ports:

```yaml
# Honeypot Ports
ports:
  - port: 8080
    protocol: HTTP
  - port: 8888
    protocol: HTTP
  # Comment out TLS ports if no certificates
  # - port: 443
  #   protocol: TLS
  #   tls_profile: tls_profile1
  # - port: 8443
  #   protocol: TLS
  #   tls_profile: tls_profile1
```

#### Solution 3: Use Different Certificate Paths

If you have certificates in a different location, update the paths in `config/config.yaml`:

```yaml
# TLS Profiles
profiles:
  tls_profile1:
    certificate: "/path/to/your/cert.pem"
    key: "/path/to/your/key.pem"
```

#### Solution 4: Generate Production Certificates with Let's Encrypt

For production use with a real domain:

```bash
# Install certbot
sudo apt-get install certbot  # Ubuntu/Debian
# or
brew install certbot  # macOS

# Generate certificate (replace your-domain.com)
sudo certbot certonly --standalone -d your-domain.com

# Copy certificates to Galah directory
sudo cp /etc/letsencrypt/live/your-domain.com/fullchain.pem cert/cert.pem
sudo cp /etc/letsencrypt/live/your-domain.com/privkey.pem cert/key.pem
sudo chown $USER:$USER cert/*.pem
```

### Certificate Permission Issues

**Error**: `permission denied` when accessing certificate files

```bash
# Fix certificate file permissions
chmod 644 cert/cert.pem
chmod 600 cert/key.pem

# Ensure Galah can read the cert directory
chmod 755 cert/
```

---

## Ollama Connection Issues

### Error: `Server URL is required`

**Problem**: Ollama provider specified but no server URL provided.

**Solution**: Add the server URL parameter:

```bash
# Correct command
./bin/galah -p ollama -m deepseek-r1:latest -u http://localhost:11434
```

### Error: `connection refused` to Ollama

**Problem**: Ollama service is not running or not accessible.

**Diagnosis**:
```bash
# Check if Ollama is running
curl http://localhost:11434/api/tags

# Check if process is running
pgrep ollama

# Check listening ports
netstat -tuln | grep 11434
```

**Solutions**:
```bash
# Start Ollama service
ollama serve

# Start Ollama in background (macOS/Linux)
nohup ollama serve > ollama.log 2>&1 &

# Check Ollama logs for issues
tail -f ollama.log
```

### Error: Model not found in Ollama

**Problem**: Specified model not available in Ollama.

**Diagnosis**:
```bash
# List available models
ollama list
```

**Solution**:
```bash
# Pull the required model
ollama pull deepseek-r1:latest

# Verify model is available
ollama list | grep deepseek-r1
```

### Ollama Performance Issues

**Problem**: Slow responses or timeouts from Ollama.

**Solutions**:
```bash
# Reduce concurrent requests
./bin/galah -p ollama -m deepseek-r1:latest -u http://localhost:11434 --concurrent-requests 2

# Monitor system resources
htop
# or
top

# Check GPU usage (if available)
nvidia-smi

# Reduce context window for memory-constrained systems
export OLLAMA_NUM_CTX=2048
ollama serve
```

---

## LLM Provider Issues

### OpenAI API Issues

**Error**: `invalid API key` or `authentication failed`

**Solutions**:
```bash
# Verify API key is set correctly
echo $LLM_API_KEY

# Test API key manually
curl -H "Authorization: Bearer $LLM_API_KEY" \
  https://api.openai.com/v1/models

# Set API key if missing
export LLM_API_KEY=your-openai-api-key
```

**Error**: `rate limit exceeded` or `quota exceeded`

**Solutions**:
```bash
# Enable caching to reduce API calls
./bin/galah -p openai -m gpt-4o-mini -k $LLM_API_KEY --cache-duration 168

# Reduce concurrent requests
./bin/galah -p openai -m gpt-4o-mini -k $LLM_API_KEY --concurrent-requests 5

# Monitor usage on OpenAI dashboard
```

### Google AI/Vertex AI Issues

**Error**: `authentication failed` for GoogleAI

**Solutions**:
```bash
# Set API key for GoogleAI
export LLM_API_KEY=your-google-ai-api-key

# For Vertex AI, set project and location
export LLM_CLOUD_PROJECT=your-gcp-project
export LLM_CLOUD_LOCATION=us-central1

# Authenticate with gcloud (for Vertex AI)
gcloud auth application-default login
```

---

## Port Binding Issues

### Error: `bind: address already in use`

**Problem**: Another service is using the same port.

**Diagnosis**:
```bash
# Check what's using the port
lsof -i :8080
# or
netstat -tuln | grep 8080

# Check for common web servers
sudo systemctl status apache2
sudo systemctl status nginx
```

**Solutions**:
```bash
# Stop conflicting service
sudo systemctl stop apache2
# or
sudo systemctl stop nginx

# Use different ports in config/config.yaml
ports:
  - port: 9080
    protocol: HTTP
  - port: 9443
    protocol: TLS
    tls_profile: tls_profile1

# Kill specific process using port (if needed)
sudo kill -9 $(lsof -t -i:8080)
```

### Permission Issues with Privileged Ports

**Error**: `bind: permission denied` for ports < 1024

**Solutions**:
```bash
# Option 1: Run as root (not recommended)
sudo ./bin/galah -p ollama -m deepseek-r1:latest -u http://localhost:11434

# Option 2: Use non-privileged ports
# Edit config/config.yaml to use ports > 1024
ports:
  - port: 8080
    protocol: HTTP
  - port: 8443
    protocol: TLS
    tls_profile: tls_profile1

# Option 3: Grant capabilities (Linux)
sudo setcap 'cap_net_bind_service=+ep' ./bin/galah
```

---

## Configuration Issues

### Error: `yaml: unmarshal errors` or configuration parsing issues

**Problem**: Invalid YAML syntax in configuration files.

**Solutions**:
```bash
# Validate YAML syntax
python -c "import yaml; yaml.safe_load(open('config/config.yaml'))"
# or use online YAML validator

# Check for common YAML issues:
# - Incorrect indentation (use spaces, not tabs)
# - Missing quotes around special characters
# - Inconsistent list formatting
```

### Missing Configuration Files

**Error**: `config file not found`

**Solutions**:
```bash
# Verify config files exist
ls -la config/

# Create default config if missing
mkdir -p config
cp config/config.yaml.example config/config.yaml  # if example exists

# Verify config file paths
./bin/galah --help | grep config
```

---

## Performance Issues

### High Memory Usage

**Problem**: Galah consuming excessive memory.

**Solutions**:
```bash
# Enable compression for logs
./bin/galah -p ollama -m deepseek-r1:latest -u http://localhost:11434 --compress-logs

# Limit cache size
./bin/galah -p ollama -m deepseek-r1:latest -u http://localhost:11434 --cache-duration 24

# Monitor memory usage
top -p $(pgrep galah)
```

### Slow Response Times

**Problem**: Honeypot responding slowly to requests.

**Solutions**:
```bash
# Enable caching
./bin/galah -p ollama -m deepseek-r1:latest -u http://localhost:11434 --cache-duration 168

# Optimize concurrent requests based on your system
./bin/galah -p ollama -m deepseek-r1:latest -u http://localhost:11434 --concurrent-requests 4

# Use faster LLM models
./bin/galah -p openai -m gpt-4o-mini  # instead of gpt-4
```

---

## Cache Issues

### Database Lock Errors

**Error**: `database is locked` or cache-related errors

**Solutions**:
```bash
# Stop Galah and remove cache file
pkill galah
rm cache.db

# Restart with fresh cache
./bin/galah -p ollama -m deepseek-r1:latest -u http://localhost:11434
```

### Cache Corruption

**Problem**: Unexpected cache behavior or errors.

**Solutions**:
```bash
# Clear cache and restart
rm cache.db event_log.json
./bin/galah -p ollama -m deepseek-r1:latest -u http://localhost:11434

# Use different cache location
./bin/galah -p ollama -m deepseek-r1:latest -u http://localhost:11434 --cache-file /tmp/galah-cache.db
```

---

## Logging Issues

### Permission Denied for Log Files

**Error**: Cannot write to log files.

**Solutions**:
```bash
# Check log directory permissions
ls -la logs/

# Create logs directory with correct permissions
mkdir -p logs
chmod 755 logs/

# Use different log location
./bin/galah -p ollama -m deepseek-r1:latest -u http://localhost:11434 -o /tmp/galah-logs.json
```

### Disk Space Issues

**Error**: `no space left on device`

**Solutions**:
```bash
# Check disk usage
df -h

# Clean old log files
find logs/ -name "*.json" -mtime +7 -delete

# Enable log compression
./bin/galah -p ollama -m deepseek-r1:latest -u http://localhost:11434 --compress-logs

# Rotate logs
logrotate /etc/logrotate.d/galah  # if configured
```

---

## General Debugging

### Enable Debug Mode

For detailed troubleshooting information:

```bash
./bin/galah -p ollama -m deepseek-r1:latest -u http://localhost:11434 --log-level debug
```

### Health Checks

```bash
# Test basic HTTP functionality
curl http://localhost:8080/

# Test with various requests
curl -X POST http://localhost:8080/login -d "user=admin&pass=test"

# Check if Galah is responding
curl -v http://localhost:8080/test
```

### Resource Monitoring

```bash
# Monitor Galah process
top -p $(pgrep galah)

# Check network connections
netstat -tuln | grep galah

# Monitor file descriptors
lsof -p $(pgrep galah)
```

---

## Getting Help

If you continue to experience issues:

1. **Check the logs**: Enable debug logging and examine the output
2. **Verify your setup**: Ensure all prerequisites are installed and configured
3. **Test components individually**: Test LLM providers, certificates, and ports separately
4. **Check system resources**: Monitor CPU, memory, and disk usage
5. **Review configuration**: Validate YAML syntax and file paths

### Useful Commands for Diagnosis

```bash
# Complete system check
./bin/galah --version
ollama list
curl http://localhost:11434/api/tags
ls -la cert/
ps aux | grep galah
netstat -tuln | grep -E "(8080|8443|443|11434)"
```

## Common Command Examples

```bash
# Minimal setup (HTTP only, Ollama)
./bin/galah -p ollama -m deepseek-r1:latest -u http://localhost:11434

# With logging
./bin/galah -p ollama -m deepseek-r1:latest -u http://localhost:11434 -o research.json

# Debug mode
./bin/galah -p ollama -m deepseek-r1:latest -u http://localhost:11434 --log-level debug

# Production setup with caching
./bin/galah -p ollama -m deepseek-r1:latest -u http://localhost:11434 \
  -o production.json \
  --cache-duration 168 \
  --concurrent-requests 10 \
  --compress-logs
```

This troubleshooting guide should help you resolve most common issues encountered when running Galah. For additional help, refer to the main documentation or check the project's issue tracker.