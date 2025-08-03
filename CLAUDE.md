# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Galah is an LLM-powered web honeypot written in Go that dynamically generates HTTP responses to mimic various applications. It uses major LLM providers (OpenAI, GoogleAI, Anthropic, Cohere, Vertex AI, Ollama) to craft realistic responses to arbitrary HTTP requests.

## Development Commands

### Building and Running
```bash
# Install dependencies
go mod download

# Build the binary
mkdir bin
go build -o bin/galah ./cmd/galah

# Run with basic configuration
./bin/galah -p openai -m gpt-4o-mini

# Run with Suricata rule matching enabled
./bin/galah -p openai -m gpt-4o-mini --suricata-enabled --suricata-rules-dir rules
```

### Testing
```bash
# Run all tests
go test ./...

# Run tests with coverage
go test -cover ./...

# Run specific package tests
go test ./pkg/llm
go test ./internal/config
go test ./galah
```

### Docker
```bash
# Build Docker image
docker build -t galah-image .

# Run in Docker
docker run -d --name galah-container -p 8080:8080 -v $(pwd)/logs:/galah/logs -e LLM_API_KEY galah-image -o logs/galah.json -p openai -m gpt-4o-mini
```

## Architecture

### Core Components

- **`cmd/galah/main.go`**: Application entry point
- **`internal/app/app.go`**: Main application logic and initialization
- **`galah/service.go`**: Core service for generating HTTP responses using LLMs
- **`internal/server/server.go`**: HTTP server implementation that handles incoming requests
- **`internal/config/`**: Configuration management for both main config and Suricata rules
- **`pkg/llm/`**: LLM provider implementations (OpenAI, GoogleAI, Anthropic, etc.)
- **`pkg/suricata/`**: Suricata rule parsing and HTTP request matching
- **`internal/cache/`**: SQLite-based response caching system
- **`internal/logger/`**: Event logging and session management

### Key Architecture Patterns

- **Service Pattern**: The `galah.Service` encapsulates all components needed for response generation
- **Provider Pattern**: LLM providers are abstracted through `llms.Model` interface from langchaingo
- **Caching Strategy**: Port-specific response caching to prevent identical requests from hitting LLM APIs
- **Rule Engine**: Optional Suricata HTTP rule matching for security detection

### Configuration Files

- **`config/config.yaml`**: Main configuration including system prompts, ports, and TLS profiles
- **`config/rules.yaml`**: Optional Suricata rules configuration for HTTP request matching
- **Templates in `templates/`**: JSON response templates for different scenarios

### Data Flow

1. HTTP request arrives at server (`internal/server/`)
2. Check cache for existing response (`internal/cache/`)
3. If not cached, generate LLM prompt using config (`pkg/llm/`)
4. Get response from LLM provider
5. Cache response and log event (`internal/logger/`)
6. Optionally match against Suricata rules (`pkg/suricata/`)

### Testing Strategy

The codebase includes unit tests for major components:
- Service layer tests in `galah/service_test.go`
- LLM provider tests in `pkg/llm/llm_test.go`
- Configuration tests in `internal/config/config_test.go`
- Server tests in `internal/server/server_test.go`
- Suricata rule tests in `pkg/suricata/rules_test.go`

### Environment Variables

Key environment variables for configuration:
- `LLM_PROVIDER`: LLM provider (openai, googleai, anthropic, etc.)
- `LLM_MODEL`: Specific model to use
- `LLM_API_KEY`: API key for LLM provider
- `LLM_TEMPERATURE`: Sampling temperature (0-2)
- `LLM_CLOUD_PROJECT`: GCP project ID (for Vertex AI)
- `LLM_CLOUD_LOCATION`: GCP region (for Vertex AI)