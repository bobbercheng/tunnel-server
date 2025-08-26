#!/bin/bash
set -e

# Change to the project root directory
cd "$(dirname "$0")/.."

echo "Setting up Go workspace for CI..."
echo "Working directory: $(pwd)"

# Sync workspace first
echo "Syncing workspace..."
go work sync

# Build each module in dependency order
echo "Building crypto module..."
(cd pkg/crypto && go build)

echo "Building metrics module..." 
(cd pkg/metrics && go build)

echo "Building agentlib module..."
(cd pkg/agentlib && go build)

echo "Building server..."
(cd server && go build -o ../server-bin)

echo "Building agent..."
(cd agent && go build -o ../agent-bin)

echo "Building reverse-proxy-agent..."
(cd reverse-proxy-agent && go build -o ../reverse-proxy-agent-bin)

echo "All builds completed successfully!"