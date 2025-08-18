# Building the Tunnel Server

This document explains how to build the tunnel server from source.

## Prerequisites

- Go 1.21 or later
- Git (for version information)
- Make (optional, for using Makefile)

## Quick Start

### Using the build script:
```bash
./build.sh
```

### Using Make:
```bash
make build
```

## Build Options

### Build Script Options

The `build.sh` script provides several options for customizing the build:

```bash
# Build with default options (release mode)
./build.sh

# Build with custom output name
./build.sh -o myserver

# Build in debug mode (includes debug symbols)
./build.sh -d

# Build static binary (no CGO dependencies)
./build.sh -s

# Cross-compile for Linux
./build.sh -t linux/amd64 -s

# Cross-compile for Windows
./build.sh -t windows/amd64

# Verbose output
./build.sh -v

# Show help
./build.sh -h
```

### Makefile Targets

The Makefile provides convenient targets for common operations:

```bash
# Build the server
make build

# Build optimized release version
make release

# Build and run the server
make run

# Run with debug logging
make run-debug

# Run tests
make test

# Run tests with coverage
make test-coverage

# Format code
make fmt

# Run linter
make lint

# Clean build artifacts
make clean

# Install dependencies
make deps

# Build for all platforms
make build-all

# Build Docker image
make docker-build

# Run in Docker container
make docker-run
```

## Cross-Compilation

### Using build.sh

```bash
# Linux AMD64
./build.sh -t linux/amd64 -s

# Linux ARM64
./build.sh -t linux/arm64 -s

# macOS Intel
./build.sh -t darwin/amd64

# macOS Apple Silicon
./build.sh -t darwin/arm64

# Windows
./build.sh -t windows/amd64
```

### Using Make

```bash
# Build for Linux
make build-linux

# Build for macOS (both Intel and ARM)
make build-darwin

# Build for Windows
make build-windows

# Build for all platforms
make build-all
```

## Docker Build

To build a Docker image:

```bash
# Using Make
make docker-build

# Using Docker directly (from parent directory)
cd ..
docker build -f server/Dockerfile -t tunnel-server:latest .
```

## Build Output

- Default binary name: `server-bin`
- Location: Same directory as the build script
- The binary includes version information (build time, git commit, branch)

## Running the Server

After building:

```bash
# Run with default settings
./server-bin

# Run on a specific port
./server-bin --port 8080

# Run with debug logging
./server-bin --debug
```

## Troubleshooting

### Missing Dependencies

If you encounter missing dependencies:

```bash
make deps
# or
go mod download
go mod tidy
```

### Build Errors

1. Ensure you have Go 1.21+ installed: `go version`
2. Clean and rebuild: `make clean && make build`
3. Check for syntax errors: `make fmt && make lint`

### Cross-Compilation Issues

For static binaries (recommended for Linux deployment):
```bash
CGO_ENABLED=0 go build -o server-bin .
```

## Development Setup

For first-time setup:

```bash
make dev-setup
```

This will:
- Install dependencies
- Install development tools (linter, etc.)

## Testing

Run tests before committing:

```bash
# Run all tests
make test

# Run with coverage
make test-coverage
```

## Version Information

The build process embeds version information into the binary:
- Build time
- Git commit hash
- Git branch
- Dirty flag (if there are uncommitted changes)

This information helps with debugging and deployment tracking.
