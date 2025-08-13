# Galah AI/LLM-Enhanced Honeypot - Quick Start

## 🚀 Installation

```bash
git clone https://github.com/nicolas-montani/galah.git
cd galah
go mod download
mkdir bin
go build -o bin/galah ./cmd/galah
```

## ⚡ Basic Usage

### Standard Honeypot
```bash
./bin/galah -p openai -m gpt-4o-mini -k YOUR_API_KEY
```

### With Local Ollama (DeepSeek-R1)
```bash
# Make sure Ollama is running locally (ollama serve)
./bin/galah -p ollama -m deepseek-r1:latest -u http://localhost:11434
```

### Enhanced Research Mode
```bash
./bin/galah -p openai -m gpt-4o-mini -k YOUR_API_KEY \
  -o research_logs.json \
  --suricata-enabled --suricata-rules-dir rules
```

### Enhanced Research Mode with Ollama
```bash
./bin/galah -p ollama -m deepseek-r1:latest -u http://localhost:11434 \
  -o research_logs.json \
  --suricata-enabled --suricata-rules-dir rules
```

## 🧠 AI/LLM Enhanced Features

### 1. Enhanced Research Data Collection
- **Attack Vector Detection**: SQL injection, XSS, directory traversal, command injection
- **Payload Analysis**: Entropy calculation, complexity scoring
- **Session Tracking**: Behavioral analysis across requests

### 2. MITRE ATT&CK Integration
- **Technique Classification**: Automatic mapping to MITRE techniques
- **Attack Stage Detection**: Reconnaissance, initial access, execution
- **Threat Assessment**: Risk scoring and confidence metrics

### 3. Behavioral Analysis & Attacker Profiling
- **Attacker Types**: Professional penetration tester, script kiddie, automated scanner
- **Skill Levels**: Beginner, intermediate, advanced, expert
- **Tool Detection**: SQLMap, Nikto, Burp Suite, custom tools
- **Attack Patterns**: 10 predefined patterns from reconnaissance to APT

### 4. Context-Aware Response Generation
- **Intelligent Responses**: Adapts to attacker sophistication
- **Response Strategies**: 5 different strategies based on threat level
- **Adaptive Learning**: Improves responses based on effectiveness

## 🔧 Configuration

### Environment Variables
```bash
# For OpenAI
export LLM_PROVIDER=openai
export LLM_MODEL=gpt-4o-mini
export LLM_API_KEY=your-api-key
export LLM_TEMPERATURE=1.0

# For Local Ollama
export LLM_PROVIDER=ollama
export LLM_MODEL=deepseek-r1:latest
export LLM_BASE_URL=http://localhost:11434  # Default Ollama URL
export LLM_TEMPERATURE=0.7
```

### Basic Config (`config/config.yaml`)
```yaml
system_prompt: |
  You are an AI-enhanced honeypot. Generate realistic responses 
  that engage attackers while collecting research data.

ports:
  - 8080
  - 8443

tls_profiles:
  - name: default
    cert_file: cert.pem
    key_file: key.pem
```

## 🧪 Testing

### Test SQL Injection Detection
```bash
curl -X POST "http://localhost:8080/login" \
  -d "username=admin' OR '1'='1&password=test" \
  -H "Content-Type: application/x-www-form-urlencoded"
```

### Test Advanced Tool Simulation
```bash
curl -H "User-Agent: sqlmap/1.0" \
  "http://localhost:8080/users?id=1' UNION SELECT * FROM users--"
```

### Test Professional Penetration Testing
```bash
curl -H "User-Agent: Burp Suite Professional" \
     -H "X-Forwarded-For: 192.168.1.100" \
     "http://localhost:8080/api/users?id=1%27%20AND%20SUBSTRING(password,1,1)=%27a"
```

## 📊 Data Analysis

### Export Research Data
```bash
# Export comprehensive dataset
curl "http://localhost:8080/api/research/export?format=json" > research_data.json
```

### Sample Output
```json
{
  "session_id": "sess_12345",
  "attacker_profile": {
    "type": "professional_penetration_tester",
    "skill_level": "advanced",
    "sophistication_score": 0.85,
    "threat_level": "high"
  },
  "mitre_analysis": {
    "techniques": ["T1190", "T1059"],
    "primary_tactic": "Initial Access",
    "confidence": 0.87
  },
  "behavioral_metrics": {
    "request_rate": 8.5,
    "attack_diversity": 2.3,
    "persistence_indicator": 0.9
  }
}
```

## 🐳 Docker Deployment

```bash
# Build and run
docker build -t galah-enhanced .
docker run -d --name galah \
  -p 8080:8080 \
  -v $(pwd)/logs:/data \
  -e LLM_API_KEY=your-key \
  galah-enhanced \
  -p openai -m gpt-4o-mini -o /data/research.json

# With Ollama (requires host network access to local Ollama)
docker run -d --name galah-ollama \
  --network host \
  -v $(pwd)/logs:/data \
  galah-enhanced \
  -p ollama -m deepseek-r1:latest -u http://localhost:11434 -o /data/research.json
```

## 📚 LLM Provider Options

| Provider | Model Examples | Setup |
|----------|----------------|-------|
| OpenAI | `gpt-4o-mini`, `gpt-4` | API key required |
| GoogleAI | `gemini-1.5-pro`, `gemini-1.5-flash` | API key required |
| Anthropic | `claude-3-haiku`, `claude-3-sonnet` | API key required |
| Vertex AI | `gemini-1.5-pro` | GCP project + location |
| Ollama | `deepseek-r1:latest`, `llama3.1`, `mistral` | Local server (ollama serve) |

## 🎯 Use Cases

### Academic Research
```bash
# With OpenAI
./bin/galah -p openai -m gpt-4o-mini \
  --research-mode \
  --thesis-data-collection \
  --comprehensive-logging

# With Local Ollama (cost-effective for research)
./bin/galah -p ollama -m deepseek-r1:latest -u http://localhost:11434 \
  --research-mode \
  --thesis-data-collection \
  --comprehensive-logging
```

### Security Training
```bash
# With OpenAI
./bin/galah -p openai -m gpt-4o-mini \
  --training-mode \
  --educational-responses \
  --safe-environment

# With Local Ollama
./bin/galah -p ollama -m deepseek-r1:latest -u http://localhost:11434 \
  --training-mode \
  --educational-responses \
  --safe-environment
```

### Threat Intelligence
```bash
# With OpenAI
./bin/galah -p openai -m gpt-4o-mini \
  --threat-intel-mode \
  --advanced-analytics \
  --real-time-classification

# With Local Ollama
./bin/galah -p ollama -m deepseek-r1:latest -u http://localhost:11434 \
  --threat-intel-mode \
  --advanced-analytics \
  --real-time-classification
```

## 🚨 Important Notes

- **API Costs**: Set usage limits on your LLM provider
- **Ethics**: Only use in controlled environments
- **Performance**: Enable caching for high-volume deployments
- **Security**: Run in isolated networks for safety

## 📖 Full Documentation

- [Complete Usage Guide](USAGE_GUIDE.md) - Comprehensive documentation
- [Original README](README.md) - Standard Galah features
- [Examples](docs/EXAMPLES.md) - More usage examples
- [Pull Requests](https://github.com/nicolas-montani/galah/pulls) - New AI/LLM features

## 🆘 Need Help?

1. Check the [Usage Guide](USAGE_GUIDE.md) for detailed instructions
2. Review the [Configuration](config/config.yaml) examples
3. Test with the provided example commands
4. Review the pull requests for feature documentation

**Ready to enhance your honeypot with AI/LLM capabilities!** 🎉