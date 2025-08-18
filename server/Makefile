# Makefile for tunnel server

# Variables
BINARY_NAME := server-bin
GO := go
GOFLAGS := 
BUILD_DIR := .
PKG_DIR := ../pkg

# Colors for output
GREEN := \033[0;32m
YELLOW := \033[1;33m
RED := \033[0;31m
NC := \033[0m # No Color

# Default target
.PHONY: all
all: build

# Build the server
.PHONY: build
build:
	@echo "$(GREEN)Building server...$(NC)"
	@$(GO) build $(GOFLAGS) -o $(BINARY_NAME) .
	@echo "$(GREEN)✅ Build complete: $(BINARY_NAME)$(NC)"

# Build for release (optimized, stripped)
.PHONY: release
release:
	@echo "$(GREEN)Building release version...$(NC)"
	@CGO_ENABLED=0 $(GO) build -ldflags="-s -w" -o $(BINARY_NAME) .
	@echo "$(GREEN)✅ Release build complete: $(BINARY_NAME)$(NC)"

# Build for different platforms
.PHONY: build-linux
build-linux:
	@echo "$(GREEN)Building for Linux...$(NC)"
	@GOOS=linux GOARCH=amd64 CGO_ENABLED=0 $(GO) build -ldflags="-s -w" -o $(BINARY_NAME)-linux-amd64 .
	@echo "$(GREEN)✅ Linux build complete: $(BINARY_NAME)-linux-amd64$(NC)"

.PHONY: build-darwin
build-darwin:
	@echo "$(GREEN)Building for macOS...$(NC)"
	@GOOS=darwin GOARCH=amd64 $(GO) build -o $(BINARY_NAME)-darwin-amd64 .
	@GOOS=darwin GOARCH=arm64 $(GO) build -o $(BINARY_NAME)-darwin-arm64 .
	@echo "$(GREEN)✅ macOS builds complete$(NC)"

.PHONY: build-windows
build-windows:
	@echo "$(GREEN)Building for Windows...$(NC)"
	@GOOS=windows GOARCH=amd64 $(GO) build -o $(BINARY_NAME)-windows-amd64.exe .
	@echo "$(GREEN)✅ Windows build complete: $(BINARY_NAME)-windows-amd64.exe$(NC)"

# Build all platforms
.PHONY: build-all
build-all: build-linux build-darwin build-windows

# Run the server
.PHONY: run
run: build
	@echo "$(GREEN)Starting server...$(NC)"
	@./$(BINARY_NAME)

# Run with debug logging
.PHONY: run-debug
run-debug: build
	@echo "$(GREEN)Starting server with debug logging...$(NC)"
	@./$(BINARY_NAME) --debug

# Test the server
.PHONY: test
test:
	@echo "$(GREEN)Running tests...$(NC)"
	@$(GO) test -v ./...

# Test with coverage
.PHONY: test-coverage
test-coverage:
	@echo "$(GREEN)Running tests with coverage...$(NC)"
	@$(GO) test -v -cover -coverprofile=coverage.out ./...
	@$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "$(GREEN)✅ Coverage report: coverage.html$(NC)"

# Lint the code
.PHONY: lint
lint:
	@echo "$(GREEN)Running linter...$(NC)"
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	else \
		echo "$(YELLOW)golangci-lint not installed. Install with: brew install golangci-lint$(NC)"; \
		$(GO) vet ./...; \
	fi

# Format code
.PHONY: fmt
fmt:
	@echo "$(GREEN)Formatting code...$(NC)"
	@$(GO) fmt ./...

# Clean build artifacts
.PHONY: clean
clean:
	@echo "$(GREEN)Cleaning build artifacts...$(NC)"
	@rm -f $(BINARY_NAME) $(BINARY_NAME)-* coverage.out coverage.html
	@echo "$(GREEN)✅ Clean complete$(NC)"

# Install dependencies
.PHONY: deps
deps:
	@echo "$(GREEN)Installing dependencies...$(NC)"
	@$(GO) mod download
	@$(GO) mod tidy
	@echo "$(GREEN)✅ Dependencies installed$(NC)"

# Docker build
.PHONY: docker-build
docker-build:
	@echo "$(GREEN)Building Docker image...$(NC)"
	@cd .. && docker build -f server/Dockerfile -t tunnel-server:latest .
	@echo "$(GREEN)✅ Docker image built: tunnel-server:latest$(NC)"

# Docker run
.PHONY: docker-run
docker-run: docker-build
	@echo "$(GREEN)Running Docker container...$(NC)"
	@docker run -p 8080:8080 tunnel-server:latest

# Development setup
.PHONY: dev-setup
dev-setup: deps
	@echo "$(GREEN)Setting up development environment...$(NC)"
	@if ! command -v golangci-lint >/dev/null 2>&1; then \
		echo "$(YELLOW)Installing golangci-lint...$(NC)"; \
		go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest; \
	fi
	@echo "$(GREEN)✅ Development environment ready$(NC)"

# Help
.PHONY: help
help:
	@echo "Tunnel Server Makefile"
	@echo ""
	@echo "Available targets:"
	@echo "  $(GREEN)make build$(NC)          - Build the server"
	@echo "  $(GREEN)make release$(NC)        - Build optimized release version"
	@echo "  $(GREEN)make run$(NC)            - Build and run the server"
	@echo "  $(GREEN)make run-debug$(NC)      - Run with debug logging"
	@echo "  $(GREEN)make test$(NC)           - Run tests"
	@echo "  $(GREEN)make test-coverage$(NC)  - Run tests with coverage report"
	@echo "  $(GREEN)make lint$(NC)           - Run linter"
	@echo "  $(GREEN)make fmt$(NC)            - Format code"
	@echo "  $(GREEN)make clean$(NC)          - Clean build artifacts"
	@echo "  $(GREEN)make deps$(NC)           - Install dependencies"
	@echo "  $(GREEN)make docker-build$(NC)   - Build Docker image"
	@echo "  $(GREEN)make docker-run$(NC)     - Run in Docker container"
	@echo "  $(GREEN)make build-all$(NC)      - Build for all platforms"
	@echo "  $(GREEN)make dev-setup$(NC)      - Setup development environment"
	@echo "  $(GREEN)make help$(NC)           - Show this help"
