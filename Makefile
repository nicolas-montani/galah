.PHONY: build test test-coverage test-integration clean deps docker-up docker-down setup help

# Build the application
build:
	@echo "🔨 Building Galah..."
	@mkdir -p bin
	@cd galah-core && go build -o ../bin/galah ./cmd/galah

# Run unit tests with coverage
test:
	@echo "🧪 Running unit tests..."
	@cd galah-core && go test -v -race -cover ./...

# Run tests with detailed coverage report
test-coverage:
	@echo "📊 Running tests with coverage report..."
	@cd galah-core && go test -v -race -coverprofile=../coverage.out ./...
	@go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

# Run integration tests
test-integration:
	@echo "🔄 Running integration tests..."
	@cd tests/integration && go test -v ./...

# Clean build artifacts
clean:
	@echo "🧹 Cleaning build artifacts..."
	@rm -rf bin/
	@rm -f coverage.out coverage.html

# Install dependencies
deps:
	@echo "📦 Installing dependencies..."
	@cd galah-core && go mod download && go mod tidy
	@cd tests/integration && go mod init galah-integration-tests 2>/dev/null || true

# Start ELK stack with Galah
docker-up:
	@echo "🐳 Starting Docker services..."
	@docker compose up -d

# Stop all Docker services
docker-down:
	@echo "🛑 Stopping Docker services..."
	@docker-compose down

# Development setup
setup: deps
	@echo "⚙️  Setting up development environment..."
	@cp .env.example .env 2>/dev/null || echo "ℹ️  .env already exists or create it manually"
	@echo "✅ Setup complete!"
	@echo "📋 Next steps:"
	@echo "   1. Configure .env file with your settings"
	@echo "   2. Run 'make build' to build the application"
	@echo "   3. Run 'make docker-up' to start ELK stack"

# Display help information
help:
	@echo "🍯 Galah Honeypot Makefile"
	@echo ""
	@echo "Available commands:"
	@echo "  build            Build the Galah application"
	@echo "  test             Run unit tests with coverage"
	@echo "  test-coverage    Generate detailed HTML coverage report"
	@echo "  test-integration Run integration tests"
	@echo "  clean            Remove build artifacts"
	@echo "  deps             Install Go dependencies"
	@echo "  docker-up        Start Docker services (ELK + Galah)"
	@echo "  docker-down      Stop Docker services"
	@echo "  setup            Initial development environment setup"
	@echo "  help             Show this help message"
	@echo ""
	@echo "📁 Project Structure:"
	@echo "  galah-core/      Main Go application code"
	@echo "  elk/             ELK stack configuration"
	@echo "  docs/            Documentation"
	@echo "  tests/           Integration tests"
	@echo "  research/        Research papers and data"