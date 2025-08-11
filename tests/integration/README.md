# Integration Tests

This directory contains integration tests for the Galah honeypot system.

## Structure

- `honeypot_test.go` - End-to-end honeypot functionality tests
- `elk_integration_test.go` - ELK stack integration tests  
- `llm_integration_test.go` - LLM provider integration tests
- `helpers/` - Test helper functions and utilities

## Running Tests

```bash
# Run all integration tests
cd tests/integration
go test -v ./...

# Run specific test suite
go test -v -run TestHoneypotBasicResponse

# Run with coverage
go test -v -cover ./...
```

## Test Requirements

- Docker and docker-compose must be available
- ELK stack should be running for ELK integration tests
- Internet connection required for LLM provider tests
- Test databases will be created in `/tmp/galah_test_*`

## Test Data

Integration tests use realistic attack patterns and payloads to verify:
- HTTP request handling
- LLM response generation  
- Event logging and formatting
- ELK stack data flow
- Cache functionality
- Suricata rule matching