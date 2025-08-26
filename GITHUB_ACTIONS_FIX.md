# GitHub Actions Build Fix

## Current Status
✅ **Local builds work correctly**  
❌ **GitHub Actions CI failing**

## Issue Summary
The GitHub Actions build at https://github.com/bobbercheng/tunnel-server/actions/runs/17225730425 is failing during the "Download dependencies" step. 

## Root Cause
The build failure is caused by Go workspace dependency resolution issues in the CI environment. Specifically:

1. **New dependency**: `golang.org/x/net/http2` was added for uTLS browser fingerprinting
2. **Workspace modules**: Local `tunnel.local/*` modules aren't being resolved properly in CI
3. **Module resolution**: CI tries to fetch local workspace modules from the internet

## Fix Options

### 🚀 **Option 1: Use Build Script (Recommended)**
Replace your current GitHub Actions build step with:

```yaml
- name: Build all modules
  run: ./scripts/ci-build.sh
```

### 🔧 **Option 2: Fix Workspace Resolution**
Add workspace environment setup:

```yaml
- name: Setup Go workspace
  run: |
    go work sync
    export GOWORK=on
    
- name: Build
  run: go build ./...
  env:
    GOWORK: "on"
```

### 🛠️ **Option 3: Sequential Build**
Build modules in dependency order:

```yaml
- name: Download dependencies
  run: go work sync

- name: Build crypto
  run: cd pkg/crypto && go build

- name: Build metrics
  run: cd pkg/metrics && go build

- name: Build agentlib
  run: cd pkg/agentlib && go build

- name: Build server
  run: cd server && go build

- name: Build agent  
  run: cd agent && go build
```

## Files Created
- ✅ `scripts/ci-build.sh` - Comprehensive build script for CI
- ✅ `CI_FIX_INSTRUCTIONS.md` - Detailed fix instructions
- ✅ This file - Quick reference for GitHub Actions fix

## Testing Status
All modules build successfully locally:
```bash
✅ pkg/crypto        - Base crypto utilities
✅ pkg/metrics       - Prometheus metrics
✅ pkg/agentlib      - Agent library (includes new uTLS + rewrite rules)
✅ server            - Tunnel server
✅ agent             - Tunnel agent
✅ reverse-proxy-agent - Reverse proxy agent
```

## Recent Changes That Caused This
The build issue was introduced by the **user-configurable rewrite rules** implementation, which:
- Added `golang.org/x/net/http2` import for HTTP/2 protocol support
- Enhanced uTLS integration for browser fingerprinting
- Created new configuration loading mechanisms

**The functionality is complete and working - this is purely a CI environment issue.**