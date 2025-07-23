# FROST Library Makefile
# Provides convenient commands for testing and development

.PHONY: help test test-critical test-features test-all build clean lint

# Default target
help:
	@echo "FROST Library Development Commands"
	@echo "=================================="
	@echo ""
	@echo "Testing:"
	@echo "  make test-critical  - Run security-critical tests only (fast, for CI)"
	@echo "  make test-features  - Run feature and edge case tests only"
	@echo "  make test-all       - Run complete test suite"
	@echo "  make test           - Alias for test-critical"
	@echo ""
	@echo "Development:"
	@echo "  make build          - Build the library"
	@echo "  make clean          - Clean build artifacts"
	@echo "  make lint           - Run linting (go vet + go fmt check)"
	@echo ""
	@echo "Examples:"
	@echo "  make build-examples - Build example programs"
	@echo ""

# Default test target runs critical tests (fast feedback)
test: test-critical

# Run security-critical tests only (recommended for CI)
test-critical:
	@echo "🔒 Running critical security tests..."
	@./test-critical.sh

# Run feature and edge case tests
test-features:
	@echo "🎯 Running feature tests..."
	@./test-features.sh

# Run complete test suite
test-all:
	@echo "🧪 Running complete test suite..."
	@go test -v ./...

# Build the library
build:
	@echo "🔨 Building FROST library..."
	@go build .

# Build example programs
build-examples:
	@echo "🔨 Building examples..."
	@go build ./examples/...

# Clean build artifacts
clean:
	@echo "🧹 Cleaning build artifacts..."
	@go clean
	@rm -f *.test

# Run linting
lint:
	@echo "🔍 Running linting..."
	@go vet ./...
	@if [ -n "$$(gofmt -l .)" ]; then \
		echo "❌ Code is not formatted. Run 'go fmt .' to fix."; \
		gofmt -l .; \
		exit 1; \
	else \
		echo "✅ Code is properly formatted"; \
	fi

# Quick development cycle
dev: lint build test-critical
	@echo "✅ Development cycle complete!"

# Full validation (for releases)
validate: lint build test-all build-examples
	@echo "✅ Full validation complete!"

# Show test statistics
test-stats:
	@echo "📊 Test Statistics:"
	@echo "Critical tests: $$(./test-critical.sh 2>/dev/null | grep -c 'PASS:' || echo 'N/A')"
	@echo "Feature tests:  $$(./test-features.sh 2>/dev/null | grep -c 'PASS:' || echo 'N/A')"
	@echo "Total tests:    $$(go test -v ./... 2>/dev/null | grep -c 'PASS:' || echo 'N/A')"
