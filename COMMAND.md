# Galah Command Reference

This document provides a comprehensive reference for all Galah command-line parameters, environment variables, and configuration options.

## Table of Contents
- [Basic Usage](#basic-usage)
- [Required Parameters](#required-parameters)
- [Optional Parameters](#optional-parameters)
- [Environment Variables](#environment-variables)
- [Configuration Files](#configuration-files)
- [Command Examples](#command-examples)
- [Advanced Usage Patterns](#advanced-usage-patterns)

---

## Basic Usage

```bash
galah --provider PROVIDER --model MODEL [OPTIONS...]
```

**Minimum required command:**
```bash
./bin/galah -p openai -m gpt-4o-mini -k YOUR_API_KEY
```

**Version Information:**
```bash
./bin/galah --version
# or
./bin/galah -h
```

---

## Required Parameters

### `--provider` / `-p`
**Description**: LLM provider to use for generating responses  
**Type**: String  
**Required**: Yes  
**Environment Variable**: `LLM_PROVIDER`

**Valid Values**:
- `openai` - OpenAI GPT models
- `googleai` - Google AI (Gemini) models
- `gcp-vertex` - Google Cloud Vertex AI
- `anthropic` - Anthropic Claude models
- `cohere` - Cohere Command models
- `ollama` - Local Ollama models

**Examples**:
```bash
./bin/galah -p openai -m gpt-4o-mini -k YOUR_KEY
./bin/galah -p ollama -m deepseek-r1:latest -u http://localhost:11434
./bin/galah -p anthropic -m claude-3-haiku -k YOUR_KEY
```

### `--model` / `-m`
**Description**: Specific LLM model to use  
**Type**: String  
**Required**: Yes  
**Environment Variable**: `LLM_MODEL`

**Common Models by Provider**:

| Provider | Model Examples |
|----------|----------------|
| OpenAI | `gpt-4o`, `gpt-4o-mini`, `gpt-4-turbo`, `gpt-3.5-turbo` |
| GoogleAI | `gemini-1.5-pro`, `gemini-1.5-flash`, `gemini-1.0-pro` |
| Anthropic | `claude-3-opus`, `claude-3-sonnet`, `claude-3-haiku` |
| Cohere | `command-r`, `command-r-plus`, `command` |
| Vertex AI | `gemini-1.5-pro`, `gemini-1.0-pro` |
| Ollama | `deepseek-r1:latest`, `llama3.1`, `mistral`, `codellama` |

**Examples**:
```bash
./bin/galah -p openai -m gpt-4o-mini -k YOUR_KEY
./bin/galah -p ollama -m deepseek-r1:latest -u http://localhost:11434
```

---

## Optional Parameters

### `--server-url` / `-u`
**Description**: LLM Server URL (required for Ollama, optional for others)  
**Type**: String  
**Required**: Yes for Ollama, No for cloud providers  
**Environment Variable**: `LLM_SERVER_URL`  
**Default**: None

**Examples**:
```bash
# Ollama (required)
./bin/galah -p ollama -m deepseek-r1:latest -u http://localhost:11434

# Custom OpenAI endpoint (optional)
./bin/galah -p openai -m gpt-4o-mini -u https://api.openai.com/v1 -k YOUR_KEY

# Remote Ollama server
./bin/galah -p ollama -m llama3.1 -u http://192.168.1.100:11434
```

### `--api-key` / `-k`
**Description**: API key for cloud LLM providers  
**Type**: String  
**Required**: Yes for cloud providers, No for Ollama  
**Environment Variable**: `LLM_API_KEY`  
**Default**: None

**Examples**:
```bash
./bin/galah -p openai -m gpt-4o-mini -k sk-your-openai-key
./bin/galah -p anthropic -m claude-3-haiku -k your-anthropic-key
```

### `--temperature` / `-t`
**Description**: LLM sampling temperature (creativity level)  
**Type**: Float (0.0-2.0)  
**Required**: No  
**Environment Variable**: `LLM_TEMPERATURE`  
**Default**: `1.0`

**Temperature Guide**:
- `0.0-0.3`: Very focused, deterministic responses
- `0.3-0.7`: Balanced creativity and consistency
- `0.7-1.2`: More creative and varied responses
- `1.2-2.0`: Highly creative, potentially unpredictable

**Examples**:
```bash
# Conservative responses
./bin/galah -p ollama -m deepseek-r1:latest -u http://localhost:11434 -t 0.3

# Creative responses
./bin/galah -p openai -m gpt-4o-mini -k YOUR_KEY -t 1.5
```

### `--cloud-project`
**Description**: GCP Project ID (required for Vertex AI)  
**Type**: String  
**Required**: Yes for Vertex AI, No for others  
**Environment Variable**: `LLM_CLOUD_PROJECT`  
**Default**: None

### `--cloud-location`
**Description**: GCP region (required for Vertex AI)  
**Type**: String  
**Required**: Yes for Vertex AI, No for others  
**Environment Variable**: `LLM_CLOUD_LOCATION`  
**Default**: None

**Examples**:
```bash
# Vertex AI setup
./bin/galah -p gcp-vertex -m gemini-1.5-pro \
  --cloud-project my-gcp-project \
  --cloud-location us-central1
```

### `--interface` / `-i`
**Description**: Network interface to bind to  
**Type**: String  
**Required**: No  
**Default**: All interfaces (`0.0.0.0`)

**Examples**:
```bash
# Bind to localhost only
./bin/galah -p ollama -m deepseek-r1:latest -u http://localhost:11434 -i 127.0.0.1

# Bind to specific interface
./bin/galah -p ollama -m deepseek-r1:latest -u http://localhost:11434 -i 192.168.1.100
```

### `--config-file` / `-c`
**Description**: Path to main configuration file  
**Type**: String  
**Required**: No  
**Default**: `config/config.yaml`

### `--rules-config-file` / `-r`
**Description**: Path to Suricata rules configuration file  
**Type**: String  
**Required**: No  
**Default**: Empty (rules disabled)

**Examples**:
```bash
# Custom config location
./bin/galah -p ollama -m deepseek-r1:latest -u http://localhost:11434 -c /etc/galah/config.yaml

# Enable Suricata rules
./bin/galah -p ollama -m deepseek-r1:latest -u http://localhost:11434 -r config/rules.yaml
```

### `--event-log-file` / `-o`
**Description**: Path to event log file  
**Type**: String  
**Required**: No  
**Default**: `event_log.json`

**Examples**:
```bash
# Custom log file
./bin/galah -p ollama -m deepseek-r1:latest -u http://localhost:11434 -o /var/log/galah/events.json

# Timestamped log file
./bin/galah -p ollama -m deepseek-r1:latest -u http://localhost:11434 -o "logs/galah-$(date +%Y%m%d).json"
```

### `--cache-db-file` / `-f`
**Description**: Path to SQLite cache database  
**Type**: String  
**Required**: No  
**Default**: `cache.db`

### `--cache-duration` / `-d`
**Description**: Cache duration for responses  
**Type**: Integer (hours)  
**Required**: No  
**Default**: `24`

**Special Values**:
- `0`: Disable caching completely
- `-1`: Unlimited caching (never expires)
- `>0`: Cache for specified hours

**Examples**:
```bash
# Disable caching
./bin/galah -p ollama -m deepseek-r1:latest -u http://localhost:11434 -d 0

# Cache for 1 week
./bin/galah -p ollama -m deepseek-r1:latest -u http://localhost:11434 -d 168

# Unlimited caching
./bin/galah -p ollama -m deepseek-r1:latest -u http://localhost:11434 -d -1
```

### `--log-level` / `-l`
**Description**: Logging verbosity level  
**Type**: String  
**Required**: No  
**Default**: `info`

**Valid Levels**:
- `debug`: Detailed debugging information
- `info`: General informational messages
- `error`: Error messages only
- `fatal`: Fatal errors only

**Examples**:
```bash
# Debug mode
./bin/galah -p ollama -m deepseek-r1:latest -u http://localhost:11434 -l debug

# Quiet mode
./bin/galah -p ollama -m deepseek-r1:latest -u http://localhost:11434 -l error
```

### `--suricata-enabled`
**Description**: Enable Suricata HTTP rule checking  
**Type**: Boolean flag  
**Required**: No  
**Default**: `false`

### `--suricata-rules-dir`
**Description**: Directory containing Suricata .rules files  
**Type**: String  
**Required**: No (but required when --suricata-enabled is true)  
**Default**: Empty

**Examples**:
```bash
# Enable Suricata rules
./bin/galah -p ollama -m deepseek-r1:latest -u http://localhost:11434 \
  --suricata-enabled \
  --suricata-rules-dir rules/

# Custom rules directory
./bin/galah -p ollama -m deepseek-r1:latest -u http://localhost:11434 \
  --suricata-enabled \
  --suricata-rules-dir /etc/suricata/rules/
```

---

## Environment Variables

All command-line parameters can be set using environment variables:

```bash
# Core settings
export LLM_PROVIDER=ollama
export LLM_MODEL=deepseek-r1:latest
export LLM_SERVER_URL=http://localhost:11434
export LLM_TEMPERATURE=0.7
export LLM_API_KEY=your-api-key-here

# Cloud provider settings
export LLM_CLOUD_PROJECT=my-gcp-project
export LLM_CLOUD_LOCATION=us-central1

# Run with environment variables
./bin/galah
```

**Environment Variable Priority**:
1. Command-line arguments (highest priority)
2. Environment variables
3. Configuration file values
4. Default values (lowest priority)

**Example Environment Setup**:
```bash
# Create environment file
cat > .env << EOF
LLM_PROVIDER=ollama
LLM_MODEL=deepseek-r1:latest
LLM_SERVER_URL=http://localhost:11434
LLM_TEMPERATURE=0.8
EOF

# Source and run
source .env
./bin/galah
```

---

## Configuration Files

### Main Configuration (`config/config.yaml`)

The configuration file defines system prompts, ports, and TLS settings:

```yaml
# System prompt for LLM
system_prompt: |
  Your task is to analyze HTTP requests and generate realistic responses...

# User prompt template
user_prompt: |
  No talk; Just do. Respond to the following HTTP Request:
  %q

# Listening ports
ports:
  - port: 8080
    protocol: HTTP
  - port: 8443
    protocol: TLS
    tls_profile: tls_profile1

# TLS certificate profiles
profiles:
  tls_profile1:
    certificate: "cert/cert.pem"
    key: "cert/key.pem"
```

### Rules Configuration (`config/rules.yaml`)

Optional Suricata rules for attack detection:

```yaml
rule_files:
  - "rules/http.rules"
  - "rules/web-attacks.rules"
  - "rules/sql-injection.rules"

rule_actions:
  - alert
  - log

classification_config:
  config_file: "rules/classification.config"
```

---

## Command Examples

### Basic Examples

```bash
# Minimal Ollama setup
./bin/galah -p ollama -m deepseek-r1:latest -u http://localhost:11434

# OpenAI with custom temperature
./bin/galah -p openai -m gpt-4o-mini -k YOUR_KEY -t 0.5

# Anthropic with logging
./bin/galah -p anthropic -m claude-3-haiku -k YOUR_KEY -o research.json
```

### Production Examples

```bash
# Production setup with caching and logging
./bin/galah -p ollama -m deepseek-r1:latest -u http://localhost:11434 \
  -o /var/log/galah/production.json \
  -d 168 \
  -l info

# High-security setup with Suricata rules
./bin/galah -p openai -m gpt-4o-mini -k YOUR_KEY \
  --suricata-enabled \
  --suricata-rules-dir /etc/suricata/rules/ \
  -o /var/log/galah/security.json \
  -l debug

# Multi-cloud setup with Vertex AI
./bin/galah -p gcp-vertex -m gemini-1.5-pro \
  --cloud-project my-project \
  --cloud-location us-central1 \
  -t 0.7 \
  -d 72 \
  -o vertex-ai-logs.json
```

### Development Examples

```bash
# Development with debug logging
./bin/galah -p ollama -m deepseek-r1:latest -u http://localhost:11434 \
  -l debug \
  -d 0 \
  -o debug.json

# Testing with different temperatures
./bin/galah -p ollama -m deepseek-r1:latest -u http://localhost:11434 -t 0.1  # Conservative
./bin/galah -p ollama -m deepseek-r1:latest -u http://localhost:11434 -t 1.5  # Creative

# Custom interface binding
./bin/galah -p ollama -m deepseek-r1:latest -u http://localhost:11434 \
  -i 127.0.0.1 \
  -o localhost-only.json
```

### Research Examples

```bash
# Academic research setup
./bin/galah -p ollama -m deepseek-r1:latest -u http://localhost:11434 \
  -o "research/experiment-$(date +%Y%m%d-%H%M%S).json" \
  -d 336 \
  -t 0.8

# Comparative analysis setup
./bin/galah -p openai -m gpt-4o-mini -k YOUR_KEY \
  -o "comparison/openai-gpt4mini.json" \
  -d -1 \
  -t 0.7

# Security research with rules
./bin/galah -p ollama -m deepseek-r1:latest -u http://localhost:11434 \
  --suricata-enabled \
  --suricata-rules-dir research/rules/ \
  -o "security-research.json" \
  -l debug
```

---

## Advanced Usage Patterns

### Using Configuration Files

```bash
# Custom configuration
./bin/galah -p ollama -m deepseek-r1:latest -u http://localhost:11434 \
  -c /path/to/custom-config.yaml \
  -r /path/to/custom-rules.yaml

# Multiple configurations for different scenarios
./bin/galah -c config/development.yaml -p ollama -m deepseek-r1:latest -u http://localhost:11434
./bin/galah -c config/production.yaml -p openai -m gpt-4o-mini -k YOUR_KEY
```

### Combining Parameters

```bash
# Full-featured command
./bin/galah \
  --provider ollama \
  --model deepseek-r1:latest \
  --server-url http://localhost:11434 \
  --temperature 0.8 \
  --config-file config/research.yaml \
  --rules-config-file config/rules.yaml \
  --event-log-file "logs/galah-$(date +%Y%m%d).json" \
  --cache-db-file cache/research.db \
  --cache-duration 168 \
  --log-level debug \
  --interface 0.0.0.0 \
  --suricata-enabled \
  --suricata-rules-dir rules/research/
```

### Scripted Deployment

```bash
#!/bin/bash
# deploy-galah.sh

# Set common environment variables
export LLM_PROVIDER=ollama
export LLM_MODEL=deepseek-r1:latest
export LLM_SERVER_URL=http://localhost:11434
export LLM_TEMPERATURE=0.7

# Create timestamped log file
LOG_FILE="logs/galah-$(date +%Y%m%d-%H%M%S).json"

# Run Galah with production settings
./bin/galah \
  -o "$LOG_FILE" \
  -d 168 \
  -l info \
  --suricata-enabled \
  --suricata-rules-dir rules/ \
  --cache-db-file cache/production.db
```

### Health Checks and Monitoring

```bash
# Check if Galah is running
pgrep -f galah || echo "Galah not running"

# Monitor log output
tail -f event_log.json | jq .

# Check cache status
sqlite3 cache.db "SELECT COUNT(*) FROM responses;"

# Monitor system resources
top -p $(pgrep galah)
```

---

## Parameter Validation

### Required Parameter Combinations

| Provider | Required Parameters |
|----------|-------------------|
| `openai` | `--provider`, `--model`, `--api-key` |
| `googleai` | `--provider`, `--model`, `--api-key` |
| `anthropic` | `--provider`, `--model`, `--api-key` |
| `cohere` | `--provider`, `--model`, `--api-key` |
| `gcp-vertex` | `--provider`, `--model`, `--cloud-project`, `--cloud-location` |
| `ollama` | `--provider`, `--model`, `--server-url` |

### Common Validation Errors

```bash
# Missing required parameters
./bin/galah -p openai -m gpt-4o-mini
# Error: LLM API Key is required for OpenAI

./bin/galah -p ollama -m deepseek-r1:latest
# Error: Server URL is required for Ollama

# Invalid parameter values
./bin/galah -p openai -m gpt-4o-mini -k YOUR_KEY -t 3.0
# Error: Temperature must be between 0.0 and 2.0

./bin/galah -p invalid-provider -m some-model
# Error: Invalid provider specified
```

This command reference should help you understand and use all available Galah parameters effectively. For troubleshooting specific parameter combinations, refer to [TROUBLESHOOTING.md](TROUBLESHOOTING.md).