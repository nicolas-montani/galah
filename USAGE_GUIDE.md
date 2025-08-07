# Galah AI/LLM-Enhanced Honeypot Usage Guide

This guide covers how to use the enhanced Galah honeypot with the new AI/LLM features for academic research and advanced threat detection.

## Quick Start

### 1. Prerequisites
- Go 1.22+ installed
- LLM API key (OpenAI, GoogleAI, Anthropic, etc.) OR Ollama installed locally
- Git for cloning the repository

### 2. Installation
```bash
# Clone the repository
git clone https://github.com/nicolas-montani/galah.git
cd galah

# Install dependencies
go mod download

# Build the binary
mkdir bin
go build -o bin/galah ./cmd/galah
```

### 3. Basic Usage

#### With Cloud LLM Providers
```bash
# Run with OpenAI GPT-4
./bin/galah -p openai -m gpt-4o-mini -k YOUR_API_KEY

# Run with enhanced research logging
./bin/galah -p openai -m gpt-4o-mini -k YOUR_API_KEY -o research_logs.json

# Run with Suricata rules for attack detection
./bin/galah -p openai -m gpt-4o-mini -k YOUR_API_KEY --suricata-enabled --suricata-rules-dir rules
```

#### With Local Ollama (DeepSeek-R1)
```bash
# First, ensure Ollama is running
ollama serve

# Basic usage with DeepSeek-R1
./bin/galah -p ollama -m deepseek-r1:latest -u http://localhost:11434

# With enhanced research logging
./bin/galah -p ollama -m deepseek-r1:latest -u http://localhost:11434 -o research_logs.json

# With Suricata rules for attack detection
./bin/galah -p ollama -m deepseek-r1:latest -u http://localhost:11434 --suricata-enabled --suricata-rules-dir rules

# Custom Ollama server URL (if not using default localhost:11434)
./bin/galah -p ollama -m deepseek-r1:latest -u http://192.168.1.100:11434
```

## Advanced Features (New AI/LLM Enhancements)

### Enhanced Research Data Collection

The enhanced version provides comprehensive research data collection capabilities:

```bash
# Enable detailed research logging with OpenAI
./bin/galah -p openai -m gpt-4o-mini -k YOUR_API_KEY \
  -o research_data.json \
  --log-level debug

# Enable detailed research logging with Ollama
./bin/galah -p ollama -m deepseek-r1:latest -u http://localhost:11434 \
  -o research_data.json \
  --log-level debug
```

**Research Data Features:**
- **Attack Vector Detection**: Automated detection of SQL injection, XSS, directory traversal, command injection
- **Payload Analysis**: Entropy calculation, complexity scoring, pattern recognition
- **Session Tracking**: Comprehensive behavioral analysis across multiple requests
- **MITRE ATT&CK Integration**: Automatic technique classification and threat assessment

### MITRE ATT&CK Integration

Enhanced attack classification using the MITRE ATT&CK framework:

```json
{
  "eventTime": "2024-01-15T10:30:15Z",
  "httpRequest": {...},
  "mitre_analysis": {
    "techniques": ["T1190", "T1059"],
    "tactics": ["Initial Access", "Execution"],
    "confidence": 0.85,
    "attack_stage": "initial_access",
    "risk_score": 7.5
  }
}
```

### Behavioral Analysis and Attacker Profiling

Advanced behavioral analysis for sophisticated threat detection:

```bash
# Run with behavioral profiling enabled (OpenAI)
./bin/galah -p openai -m gpt-4o-mini -k YOUR_API_KEY \
  --enable-behavioral-analysis \
  --session-timeout 30m

# Run with behavioral profiling enabled (Ollama)
./bin/galah -p ollama -m deepseek-r1:latest -u http://localhost:11434 \
  --enable-behavioral-analysis \
  --session-timeout 30m
```

**Behavioral Features:**
- **Attacker Classification**: Professional penetration tester, script kiddie, automated scanner
- **Skill Level Assessment**: Beginner, intermediate, advanced, expert
- **Tool Detection**: SQLMap, Nikto, Burp Suite, custom tools
- **Attack Pattern Recognition**: 10 predefined patterns from reconnaissance to APT campaigns
- **Behavioral Fingerprinting**: Unique behavioral signatures for attacker tracking

### Context-Aware Response Generation

Intelligent response generation based on attacker sophistication:

```bash
# Enable context-aware responses (OpenAI)
./bin/galah -p openai -m gpt-4o-mini -k YOUR_API_KEY \
  --enable-context-aware-responses \
  --adaptive-learning

# Enable context-aware responses (Ollama)
./bin/galah -p ollama -m deepseek-r1:latest -u http://localhost:11434 \
  --enable-context-aware-responses \
  --adaptive-learning
```

**Response Strategy Examples:**
- **Professional Attackers**: Complex, realistic vulnerability simulations
- **Automated Scanners**: Large, confusing responses to waste scanner time
- **Script Kiddies**: Basic responses with educational false positives
- **Evasion Techniques**: Counter-evasion responses that mirror attacker techniques

## Configuration

### Ollama Configuration

#### Prerequisites for Ollama
Before using Galah with Ollama, ensure you have:

1. **Install Ollama**: Download from [ollama.ai](https://ollama.ai) or use package manager
   ```bash
   # macOS
   brew install ollama
   
   # Linux
   curl -fsSL https://ollama.ai/install.sh | sh
   ```

2. **Pull DeepSeek-R1 model**:
   ```bash
   ollama pull deepseek-r1:latest
   ```

3. **Start Ollama service**:
   ```bash
   ollama serve
   ```

#### Ollama Environment Variables
```bash
export LLM_PROVIDER=ollama
export LLM_MODEL=deepseek-r1:latest
export LLM_BASE_URL=http://localhost:11434  # Default Ollama URL
export LLM_TEMPERATURE=0.7
export OLLAMA_NUM_PARALLEL=4  # Concurrent requests
export OLLAMA_MAX_LOADED_MODELS=1  # Memory management
```

#### Optimizing DeepSeek-R1 for Honeypot Usage
```bash
# Configure model parameters for better honeypot responses
ollama run deepseek-r1:latest --parameter temperature 0.8 --parameter top_p 0.9

# Set system message for honeypot context
ollama run deepseek-r1:latest --system "You are a web application that responds to HTTP requests. Generate realistic responses that simulate various web applications."
```

### Main Configuration (`config/config.yaml`)

```yaml
# Enhanced configuration for research
system_prompt: |
  You are a sophisticated web application honeypot. Generate realistic HTTP responses 
  that will engage attackers and collect valuable research data. Adapt your responses 
  based on the detected attack sophistication and behavioral patterns.

# LLM Provider Configuration
llm:
  provider: "ollama"  # or "openai", "googleai", "anthropic"
  model: "deepseek-r1:latest"
  base_url: "http://localhost:11434"  # Ollama default
  temperature: 0.7
  max_tokens: 2048
  
  # Ollama-specific settings
  ollama:
    num_parallel: 4
    keep_alive: "5m"
    num_ctx: 4096

# Research settings
research:
  enabled: true
  data_export_format: ["json", "csv"]
  behavioral_analysis: true
  mitre_integration: true
  
# Response generation
response_generation:
  context_aware: true
  adaptive_learning: true
  complexity_scaling: true
```

### Research Rules Configuration

Create `config/research_rules.yaml` for advanced detection:

```yaml
research_rules:
  attack_patterns:
    - name: "Advanced SQL Injection"
      pattern: "(?i)(union.*select|or.*1.*=.*1)"
      sophistication_weight: 0.8
      mitre_techniques: ["T1190"]
    
    - name: "Professional Tool Usage"
      pattern: "(?i)(sqlmap|nikto|burp|nessus)"
      attacker_type: "professional"
      skill_level: "advanced"

  behavioral_thresholds:
    request_rate_high: 10.0  # requests per minute
    sophistication_advanced: 0.7
    threat_level_critical: 8.0
```

## Testing the Enhanced Features

### 1. Basic Attack Simulation
```bash
# Test SQL injection detection
curl -X POST "http://localhost:8080/login" \
  -d "username=admin' OR '1'='1&password=test" \
  -H "Content-Type: application/x-www-form-urlencoded"
```

### 2. Advanced Behavioral Analysis
```bash
# Simulate sophisticated attacker behavior
curl -H "User-Agent: sqlmap/1.0" "http://localhost:8080/users?id=1' UNION SELECT * FROM users--"
curl -H "User-Agent: sqlmap/1.0" "http://localhost:8080/admin/config"
curl -H "User-Agent: sqlmap/1.0" "http://localhost:8080/backup/database.sql"
```

### 3. Professional Penetration Testing Simulation
```bash
# Simulate professional testing tools
curl -H "User-Agent: Burp Suite Professional" \
     -H "X-Forwarded-For: 192.168.1.100" \
     "http://localhost:8080/api/users?id=1%27%20AND%20SUBSTRING((SELECT%20password%20FROM%20users%20WHERE%20id=1),1,1)=%27a"
```

## Research Data Analysis

### Exporting Research Data

```bash
# Export comprehensive research dataset
curl "http://localhost:8080/api/research/export?format=json" > research_data.json
curl "http://localhost:8080/api/research/export?format=csv" > research_data.csv
```

### Sample Research Data Structure

```json
{
  "session_analysis": {
    "session_id": "sess_12345",
    "attacker_profile": {
      "type": "professional_penetration_tester",
      "skill_level": "advanced",
      "tools_detected": ["sqlmap", "burp_suite"],
      "sophistication_score": 0.85,
      "threat_level": "high"
    },
    "behavioral_metrics": {
      "request_rate": 8.5,
      "attack_diversity": 2.3,
      "timing_consistency": 0.7,
      "persistence_indicator": 0.9
    },
    "mitre_analysis": {
      "techniques": ["T1190", "T1059", "T1083"],
      "primary_tactic": "Initial Access",
      "attack_stage": "exploitation",
      "confidence": 0.87
    }
  },
  "response_effectiveness": {
    "strategy_used": "Advanced_Engagement",
    "complexity_level": 0.9,
    "attacker_engagement_duration": "00:15:32",
    "data_collected_mb": 2.4
  }
}
```

## Docker Deployment for Research

### Enhanced Docker Configuration

```dockerfile
# Use the enhanced research image
FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY . .
RUN go build -o galah ./cmd/galah

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/galah .
COPY --from=builder /app/config ./config

# Research-focused entrypoint
ENTRYPOINT ["./galah", "--enable-research-mode"]
```

```bash
# Build and run research container with OpenAI
docker build -t galah-research .
docker run -d \
  --name galah-research \
  -p 8080:8080 \
  -v $(pwd)/research_data:/data \
  -e LLM_API_KEY=your_key \
  galah-research \
  -p openai -m gpt-4o-mini \
  -o /data/research_logs.json \
  --enable-behavioral-analysis \
  --enable-context-aware-responses

# With Ollama (requires host network access)
docker build -t galah-research-ollama .
docker run -d \
  --name galah-research-ollama \
  --network host \
  -v $(pwd)/research_data:/data \
  galah-research-ollama \
  -p ollama -m deepseek-r1:latest -u http://localhost:11434 \
  -o /data/research_logs.json \
  --enable-behavioral-analysis \
  --enable-context-aware-responses
```

## Academic Research Usage

### For University Research Projects

1. **Data Collection Setup**:
   ```bash
   # With OpenAI
   ./bin/galah -p openai -m gpt-4o-mini \
     --research-mode \
     --ethical-constraints \
     --data-anonymization \
     -o university_research.json

   # With Local Ollama (cost-effective for extended research)
   ./bin/galah -p ollama -m deepseek-r1:latest \
     --research-mode \
     --ethical-constraints \
     --data-anonymization \
     -o university_research.json
   ```

2. **Reproducible Experiments**:
   ```bash
   # Set fixed seed for reproducible results (OpenAI)
   ./bin/galah -p openai -m gpt-4o-mini \
     --research-seed 12345 \
     --deterministic-responses \
     --export-methodology research_methodology.json

   # With Ollama (local reproducibility)
   ./bin/galah -p ollama -m deepseek-r1:latest \
     --research-seed 12345 \
     --deterministic-responses \
     --export-methodology research_methodology.json
   ```

3. **Thesis Data Collection**:
   ```bash
   # Comprehensive data collection for thesis (OpenAI)
   ./bin/galah -p openai -m gpt-4o-mini \
     --thesis-mode \
     --comprehensive-logging \
     --statistical-analysis \
     --export-format academic

   # With Ollama (unlimited usage for long-term studies)
   ./bin/galah -p ollama -m deepseek-r1:latest \
     --thesis-mode \
     --comprehensive-logging \
     --statistical-analysis \
     --export-format academic
   ```

### Ethical Research Guidelines

- Always run in isolated, controlled environments
- Ensure proper data anonymization
- Follow university ethical research guidelines
- Document methodology for reproducibility
- Respect privacy and legal constraints

## Performance Optimization

### For High-Volume Research

```bash
# Optimized for high-volume data collection (OpenAI)
./bin/galah -p openai -m gpt-4o-mini \
  --batch-processing \
  --cache-duration 168 \  # 1 week caching
  --concurrent-requests 50 \
  --memory-optimization \
  --compress-logs

# With Ollama (optimized for local processing)
./bin/galah -p ollama -m deepseek-r1:latest \
  --batch-processing \
  --cache-duration 336 \  # 2 week caching (no API costs)
  --concurrent-requests 10 \  # Lower due to local CPU limits
  --memory-optimization \
  --compress-logs
```

### Resource Monitoring

```bash
# Monitor resource usage during research
./bin/galah -p openai -m gpt-4o-mini \
  --enable-metrics \
  --prometheus-endpoint :9090 \
  --health-check-endpoint :8081
```

## Troubleshooting

### Common Issues

1. **High API Costs**: Use caching and rate limiting, or switch to local Ollama
2. **Memory Usage**: Enable compression and batch processing
3. **Data Quality**: Validate detection accuracy with known test cases
4. **Performance**: Use appropriate LLM models for your research needs

### Ollama-Specific Troubleshooting

1. **Ollama Service Not Running**:
   ```bash
   # Check if Ollama is running
   curl http://localhost:11434/api/tags
   
   # Start Ollama if needed
   ollama serve
   ```

2. **Model Not Available**:
   ```bash
   # List available models
   ollama list
   
   # Pull DeepSeek-R1 if not available
   ollama pull deepseek-r1:latest
   ```

3. **Connection Refused**:
   ```bash
   # Check Ollama is listening on correct port
   netstat -tuln | grep 11434
   
   # Verify Ollama API endpoint
   curl -X POST http://localhost:11434/api/generate \
     -H "Content-Type: application/json" \
     -d '{"model": "deepseek-r1:latest", "prompt": "Hello"}'
   ```

4. **Slow Response Times**:
   ```bash
   # Check system resources
   htop
   
   # Reduce concurrent requests for Ollama
   ./bin/galah -p ollama -m deepseek-r1:latest --concurrent-requests 2
   
   # Monitor GPU usage (if available)
   nvidia-smi
   ```

5. **Memory Issues with DeepSeek-R1**:
   ```bash
   # Use smaller context window
   export OLLAMA_NUM_CTX=2048
   
   # Limit loaded models
   export OLLAMA_MAX_LOADED_MODELS=1
   
   # Check available system memory
   free -h
   ```

### Debug Mode

```bash
# Enable comprehensive debugging
./bin/galah -p openai -m gpt-4o-mini \
  --log-level debug \
  --debug-ai-decisions \
  --trace-behavioral-analysis \
  --validate-mitre-mappings
```

## Integration with Other Tools

### Security Analytics Platforms

```bash
# Export to SIEM formats
curl "http://localhost:8080/api/export/siem?format=splunk" > galah_events.json
curl "http://localhost:8080/api/export/siem?format=elastic" > galah_elastic.json
```

### Research Analysis Tools

```python
# Example Python analysis script
import pandas as pd
import json

# Load research data
with open('research_data.json', 'r') as f:
    data = json.load(f)

# Analyze attacker behavior patterns
df = pd.DataFrame(data['sessions'])
sophistication_analysis = df.groupby('attacker_type')['sophistication_score'].mean()
print(sophistication_analysis)
```

This enhanced Galah honeypot provides a comprehensive platform for academic research on AI/LLM-enhanced cybersecurity systems, with sophisticated data collection, behavioral analysis, and adaptive response capabilities suitable for university-level research projects.