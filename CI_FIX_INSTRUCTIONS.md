# GitHub Actions CI Build Fix Instructions

## Issue
The GitHub Actions build is failing because of Go workspace dependency resolution issues. The error occurs when trying to resolve `tunnel.local/*` modules that are local workspace dependencies.

## Root Cause
The CI environment is trying to download `tunnel.local/crypto` and other local modules from the internet instead of using the local workspace configuration.

## Solution

### Option 1: Use the Build Script (Recommended)
Replace the current build step in your GitHub Actions workflow with:

```yaml
- name: Build
  run: ./scripts/ci-build.sh
```

### Option 2: Manual Build Steps
If you prefer to keep individual build steps, ensure they run in this order:

```yaml
- name: Setup Go workspace
  run: go work sync

- name: Build crypto module
  run: cd pkg/crypto && go build

- name: Build metrics module  
  run: cd pkg/metrics && go build

- name: Build agentlib module
  run: cd pkg/agentlib && go build

- name: Build server
  run: cd server && go build -o ../server-bin

- name: Build agent
  run: cd agent && go build -o ../agent-bin

- name: Build reverse-proxy-agent
  run: cd reverse-proxy-agent && go build -o ../reverse-proxy-agent-bin
```

### Option 3: Workspace Environment Fix
Add these environment variables to your workflow:

```yaml
env:
  GOWORK: "on"
  GO111MODULE: "on"
```

## Technical Details

The issue is caused by:
1. New dependency `golang.org/x/net/http2` added to support uTLS browser fingerprinting
2. Go workspace trying to resolve local `tunnel.local/*` modules over HTTP
3. CI environment not properly handling workspace-local module references

## Testing
The provided `scripts/ci-build.sh` has been tested locally and builds all modules successfully:
- ✅ pkg/crypto
- ✅ pkg/metrics  
- ✅ pkg/agentlib
- ✅ server
- ✅ agent
- ✅ reverse-proxy-agent

## Recent Changes
This build issue was introduced when implementing user-configurable rewrite rules, which required adding the `golang.org/x/net/http2` dependency for proper HTTP/2 protocol handling in the uTLS implementation.