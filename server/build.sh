#!/bin/bash

# Build script for tunnel server
# This script builds the server binary with various options

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

# Default values
OUTPUT_NAME="server-bin"
BUILD_MODE="release"
TARGET_OS=""
TARGET_ARCH=""
LDFLAGS=""
VERBOSE=0

# Parse command line arguments
usage() {
    echo "Usage: $0 [OPTIONS]"
    echo "Options:"
    echo "  -o, --output NAME       Output binary name (default: server-bin)"
    echo "  -d, --debug            Build in debug mode (default: release)"
    echo "  -t, --target OS/ARCH   Cross-compile for OS/ARCH (e.g., linux/amd64, darwin/arm64)"
    echo "  -s, --static           Build static binary (CGO_ENABLED=0)"
    echo "  -v, --verbose          Verbose output"
    echo "  -h, --help             Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                              # Build for current platform"
    echo "  $0 -o myserver                  # Build with custom output name"
    echo "  $0 -t linux/amd64 -s            # Build static Linux binary"
    echo "  $0 -d                           # Build with debug symbols"
    exit 1
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -o|--output)
            OUTPUT_NAME="$2"
            shift 2
            ;;
        -d|--debug)
            BUILD_MODE="debug"
            shift
            ;;
        -t|--target)
            IFS='/' read -r TARGET_OS TARGET_ARCH <<< "$2"
            shift 2
            ;;
        -s|--static)
            export CGO_ENABLED=0
            shift
            ;;
        -v|--verbose)
            VERBOSE=1
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            usage
            ;;
    esac
done

# Build configuration
echo -e "${GREEN}Building tunnel server...${NC}"
echo "Configuration:"
echo "  Output: $OUTPUT_NAME"
echo "  Mode: $BUILD_MODE"

# Set GOOS and GOARCH if cross-compiling
if [ -n "$TARGET_OS" ]; then
    export GOOS=$TARGET_OS
    export GOARCH=$TARGET_ARCH
    echo "  Target: $GOOS/$GOARCH"
fi

if [ "$CGO_ENABLED" = "0" ]; then
    echo "  CGO: disabled (static binary)"
fi

# Set build flags based on mode
if [ "$BUILD_MODE" = "release" ]; then
    LDFLAGS="-s -w"
    echo "  Optimization: enabled (stripped binary)"
else
    LDFLAGS=""
    echo "  Optimization: disabled (debug symbols included)"
fi

# Create build info
BUILD_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
GIT_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
GIT_BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")
GIT_DIRTY=$(test -n "$(git status --porcelain 2>/dev/null)" && echo "-dirty" || echo "")

# Add version info to ldflags
VERSION_FLAGS="-X main.buildTime=$BUILD_TIME -X main.gitCommit=$GIT_COMMIT$GIT_DIRTY -X main.gitBranch=$GIT_BRANCH"
LDFLAGS="$LDFLAGS $VERSION_FLAGS"

echo ""

# Download dependencies
echo -e "${YELLOW}Downloading dependencies...${NC}"
if [ $VERBOSE -eq 1 ]; then
    go mod download -x
else
    go mod download
fi

# Build the server
echo -e "${YELLOW}Building server...${NC}"
if [ -n "$LDFLAGS" ]; then
    BUILD_CMD="go build -ldflags=\"$LDFLAGS\" -o $OUTPUT_NAME ."
else
    BUILD_CMD="go build -o $OUTPUT_NAME ."
fi

if [ $VERBOSE -eq 1 ]; then
    echo "Build command: $BUILD_CMD"
    set -x
fi

eval $BUILD_CMD
BUILD_RESULT=$?

if [ $VERBOSE -eq 1 ]; then
    set +x
fi

if [ $BUILD_RESULT -eq 0 ]; then
    echo -e "${GREEN}✅ Build successful!${NC}"
    
    # Show binary info
    echo ""
    echo "Binary information:"
    if command -v file >/dev/null 2>&1; then
        file "$OUTPUT_NAME"
    fi
    
    # Show size
    SIZE=$(ls -lh "$OUTPUT_NAME" | awk '{print $5}')
    echo "Size: $SIZE"
    
    # Make executable
    chmod +x "$OUTPUT_NAME"
    
    echo ""
    echo -e "${GREEN}Server binary created: $SCRIPT_DIR/$OUTPUT_NAME${NC}"
    
    # Show how to run
    echo ""
    echo "To run the server:"
    echo "  ./$OUTPUT_NAME"
    echo ""
    echo "Available flags:"
    echo "  --port PORT            Server port (default: 8080)"
    echo "  --debug               Enable debug logging"
    echo ""
else
    echo -e "${RED}❌ Build failed!${NC}"
    exit 1
fi
