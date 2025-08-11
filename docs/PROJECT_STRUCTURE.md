# Galah Project Structure

This document describes the organized structure of the Galah honeypot project after refactoring.

## Directory Layout

```
galah/
├── galah-core/                 # 🍯 Main Go Application
│   ├── cmd/                    # Application entry points
│   │   └── galah/              # Main CLI application
│   ├── internal/               # Private application packages
│   │   ├── app/                # Application bootstrap logic
│   │   ├── cache/              # SQLite response caching (96.8% test coverage)
│   │   ├── config/             # Configuration management
│   │   ├── logger/             # Event logging and session management
│   │   └── server/             # HTTP server implementation
│   ├── pkg/                    # Public library packages
│   │   ├── analytics/          # Attack pattern analysis
│   │   ├── enrich/             # IP enrichment and GeoIP
│   │   ├── llm/                # LLM provider implementations
│   │   ├── research/           # Research data collection
│   │   └── suricata/           # Suricata rule matching engine
│   ├── galah/                  # Core honeypot service
│   │   ├── service.go          # Main service implementation
│   │   └── service_test.go     # Service tests (71.4% coverage)
│   ├── config/                 # Configuration files
│   │   ├── config.yaml         # Main honeypot configuration
│   │   └── rules.yaml          # Suricata rules configuration
│   ├── go.mod                  # Go module definition
│   ├── go.sum                  # Go module checksums
│   └── Dockerfile              # Container build definition
│
├── elk/                        # 📊 ELK Stack Integration
│   ├── elasticsearch/          # Elasticsearch configuration
│   │   ├── elasticsearch.yml   # ES main configuration
│   │   └── index-templates/    # Index templates for log data
│   ├── logstash/               # Logstash data pipeline
│   │   ├── config/             # Logstash configuration
│   │   ├── pipeline/           # Log processing pipelines
│   │   └── templates/          # Elasticsearch mapping templates
│   └── kibana/                 # Kibana dashboards and visualization
│       ├── dashboards/         # Pre-configured security dashboards
│       ├── import-dashboard.sh # Automated dashboard import script
│       └── kibana.yml          # Kibana configuration
│
├── docs/                       # 📖 Documentation
│   ├── PROJECT_STRUCTURE.md    # This file
│   ├── CLAUDE.md               # Claude AI assistant instructions
│   ├── ELK-INTEGRATION.md      # ELK stack integration guide
│   ├── SURICATA.md             # Suricata rule configuration
│   └── images/                 # Documentation images
│
├── tests/                      # 🧪 Test Suite
│   └── integration/            # End-to-end integration tests
│       ├── README.md           # Integration test documentation
│       └── [test files]        # Integration test implementations
│
├── research/                   # 🎓 Research Components
│   ├── Paper/                  # Academic research paper (LaTeX)
│   │   ├── thesis.tex          # Main paper document
│   │   ├── chapters/           # Paper chapters
│   │   ├── sections/           # Paper sections
│   │   └── appendices/         # Paper appendices
│   └── data/                   # Research datasets
│       └── llm_events_*.json   # Collected honeypot interaction data
│
├── logs/                       # 📝 Runtime Logs
│   └── galah.json             # JSON-formatted event logs (ELK indexed)
│
├── bin/                        # 🔧 Built Binaries
│   └── galah                  # Main executable
│
├── docker-compose.yml          # 🐳 Multi-service orchestration
├── Dockerfile                  # (Removed - now in galah-core/)
├── Makefile                    # 🛠️ Development automation
├── .env.example                # Environment configuration template
├── .gitignore                  # Git ignore patterns
├── go.mod                      # (Removed - now in galah-core/)
├── go.sum                      # (Removed - now in galah-core/)
├── LICENSE                     # Apache 2.0 license
└── README.md                   # Main project documentation
```

## Key Improvements

### ✅ **Separation of Concerns**
- **galah-core/**: Contains all Go source code and configuration
- **elk/**: Isolated ELK stack configuration and dashboards
- **docs/**: Centralized documentation
- **tests/**: Dedicated integration test suite
- **research/**: Academic paper and research data separate from codebase

### ✅ **Build Process**
```bash
# All commands work from project root
make build              # Builds from galah-core/
make test               # Runs unit tests in galah-core/
make test-integration   # Runs integration tests in tests/
make docker-up          # Starts services with updated paths
```

### ✅ **Docker Integration**
- `docker-compose.yml` updated to reference `./galah-core` for build
- Volume mounts updated: `./galah-core/config:/galah/config:ro`
- ELK stack paths remain unchanged

### ✅ **Development Workflow**
```bash
# Setup development environment
make setup              # Installs dependencies, creates .env

# Development cycle
make build              # Build application
make test               # Run all unit tests
make test-coverage      # Generate HTML coverage report
make docker-up          # Start full stack for integration testing
```

## Test Coverage Status

| Package | Coverage | Status |
|---------|----------|--------|
| `internal/cache` | 96.8% | ✅ Excellent |
| `galah/` | 71.4% | ✅ Good |
| `pkg/suricata` | 62.5% | ✅ Good |
| `internal/config` | 42.9% | ⚠️ Fair |
| `pkg/enrich` | 29.7% | ⚠️ Fair |
| `pkg/analytics` | 22.1% | ❌ Poor (failing tests) |
| `pkg/llm` | 21.2% | ❌ Poor |
| `internal/server` | 19.7% | ❌ Poor |
| `internal/app` | 0.0% | ❌ No tests |
| `internal/logger` | 0.0% | ❌ No tests |
| `cmd/galah` | 0.0% | ❌ No tests |

## Migration Notes

### What Changed
1. **Source code moved**: `./pkg/` → `./galah-core/pkg/`
2. **Build process**: Now builds from `galah-core/` directory
3. **Docker build**: References `./galah-core` instead of `.`
4. **Research separated**: `./Paper/` and `./data/` → `./research/`
5. **Documentation centralized**: `./docs/` contains all docs

### What Stayed the Same
- ELK stack configuration and paths
- Environment variables and configuration format
- API and functionality - no breaking changes
- Log output format and locations

### Compatibility
- All existing docker-compose commands work unchanged
- Configuration files maintain same format
- Log parsing and ELK integration unchanged
- API endpoints and behavior identical

## Benefits

1. **🧹 Cleaner Structure**: Clear separation between application code, infrastructure, docs, and research
2. **🔍 Better Navigation**: Easier to find specific components
3. **🧪 Improved Testing**: Dedicated integration test directory
4. **📦 Simplified Builds**: Core application isolated in single directory
5. **🎓 Research Separation**: Academic content separate from production code
6. **📖 Better Documentation**: Centralized and organized docs

This structure provides a solid foundation for continued development while maintaining backward compatibility with existing deployments.