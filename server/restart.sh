#!/bin/bash

# Cloud Run Service Restart Utility for Tunnel Server
# Usage: ./restart.sh [options]

set -e

# Configuration from logs.sh/deploy.sh
export PROJECT_ID=contact-center-insights-poc
export REGION=us-east1
export SERVICE=tunnel-server

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Default options
FORCE=false
SHOW_STATUS=true
WAIT_FOR_READY=true
HELP=false

# Function to display help
show_help() {
    cat << EOF
Cloud Run Service Restart Utility for Tunnel Server

USAGE:
    ./restart.sh [OPTIONS]

OPTIONS:
    -f, --force            Force restart without confirmation
    -q, --quiet            Minimal output (no status check after restart)
    --no-wait              Don't wait for service to be ready after restart
    -h, --help             Show this help message

EXAMPLES:
    ./restart.sh                    # Restart with confirmation and status check
    ./restart.sh -f                 # Force restart without confirmation
    ./restart.sh -f -q              # Force restart with minimal output
    ./restart.sh --no-wait          # Restart without waiting for ready state

NOTES:
    - This triggers a new deployment with the same container image
    - All active WebSocket connections will be terminated
    - Agents should automatically reconnect after restart
    - The restart may take 30-60 seconds to complete

EOF
}

# Function to check if gcloud is installed and authenticated
check_gcloud() {
    if ! command -v gcloud &> /dev/null; then
        echo -e "${RED}Error: gcloud CLI is not installed${NC}"
        echo "Please install gcloud: https://cloud.google.com/sdk/docs/install"
        exit 1
    fi

    # Check if authenticated
    if ! gcloud auth list --filter=status:ACTIVE --format="value(account)" | head -n1 &> /dev/null; then
        echo -e "${RED}Error: gcloud is not authenticated${NC}"
        echo "Please run: gcloud auth login"
        exit 1
    fi

    # Check if project is set correctly
    current_project=$(gcloud config get-value project 2>/dev/null)
    if [ "$current_project" != "$PROJECT_ID" ]; then
        echo -e "${YELLOW}Warning: Current project ($current_project) differs from expected ($PROJECT_ID)${NC}"
        echo "Setting project to $PROJECT_ID..."
        gcloud config set project $PROJECT_ID
    fi
}

# Function to get current service status
get_service_status() {
    echo -e "${BLUE}Checking current service status...${NC}"
    
    # Get service details
    service_info=$(gcloud run services describe $SERVICE --region=$REGION --format=json 2>/dev/null || echo "{}")
    
    if [ "$service_info" = "{}" ]; then
        echo -e "${RED}Error: Service $SERVICE not found in region $REGION${NC}"
        return 1
    fi
    
    # Extract useful information
    url=$(echo "$service_info" | jq -r '.status.url // "N/A"')
    latest_revision=$(echo "$service_info" | jq -r '.status.latestReadyRevisionName // "N/A"')
    traffic_percent=$(echo "$service_info" | jq -r '.status.traffic[0].percent // "0"')
    
    echo -e "${GREEN}Service URL:${NC} $url"
    echo -e "${GREEN}Latest Revision:${NC} $latest_revision"
    echo -e "${GREEN}Traffic:${NC} ${traffic_percent}%"
    
    # Check if service is ready
    conditions=$(echo "$service_info" | jq -r '.status.conditions[] | select(.type=="Ready") | .status' 2>/dev/null || echo "Unknown")
    if [ "$conditions" = "True" ]; then
        echo -e "${GREEN}Status: Ready${NC}"
    else
        echo -e "${YELLOW}Status: Not Ready${NC}"
    fi
    
    return 0
}

# Function to confirm restart
confirm_restart() {
    echo ""
    echo -e "${YELLOW}⚠️  WARNING: This will restart the tunnel server!${NC}"
    echo -e "${YELLOW}   - All active WebSocket connections will be terminated${NC}"
    echo -e "${YELLOW}   - Agents will need to reconnect${NC}"
    echo -e "${YELLOW}   - Brief service interruption expected${NC}"
    echo ""
    read -p "Are you sure you want to restart the service? (y/N) " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${RED}Restart cancelled${NC}"
        exit 0
    fi
}

# Function to restart the service
restart_service() {
    echo ""
    echo -e "${BLUE}Restarting Cloud Run service...${NC}"
    
    # Get the current image
    current_image=$(gcloud run services describe $SERVICE --region=$REGION --format="value(spec.template.spec.containers[0].image)" 2>/dev/null)
    
    if [ -z "$current_image" ]; then
        echo -e "${RED}Error: Could not retrieve current container image${NC}"
        exit 1
    fi
    
    echo -e "${BLUE}Current image:${NC} $current_image"
    
    # Update the service with a new revision (this triggers a restart)
    # We add a label with timestamp to force a new revision
    timestamp=$(date +%s)
    
    echo -e "${BLUE}Creating new revision...${NC}"
    if gcloud run services update $SERVICE \
        --region=$REGION \
        --update-labels="restart-timestamp=$timestamp" \
        --quiet; then
        echo -e "${GREEN}✓ Service restart initiated${NC}"
    else
        echo -e "${RED}✗ Failed to restart service${NC}"
        exit 1
    fi
}

# Function to wait for service to be ready
wait_for_ready() {
    echo ""
    echo -e "${BLUE}Waiting for service to be ready...${NC}"
    
    local max_attempts=30
    local attempt=0
    local ready=false
    
    while [ $attempt -lt $max_attempts ] && [ "$ready" = "false" ]; do
        attempt=$((attempt + 1))
        
        # Check if service is ready
        conditions=$(gcloud run services describe $SERVICE --region=$REGION --format="value(status.conditions[?type=='Ready'].status)" 2>/dev/null || echo "Unknown")
        
        if [ "$conditions" = "True" ]; then
            ready=true
            echo -e "\n${GREEN}✓ Service is ready!${NC}"
        else
            echo -n "."
            sleep 2
        fi
    done
    
    if [ "$ready" = "false" ]; then
        echo -e "\n${YELLOW}⚠️  Service is taking longer than expected to be ready${NC}"
        echo -e "${YELLOW}   You can check the status with: ./logs.sh --fresh${NC}"
        return 1
    fi
    
    return 0
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -f|--force)
            FORCE=true
            shift
            ;;
        -q|--quiet)
            SHOW_STATUS=false
            shift
            ;;
        --no-wait)
            WAIT_FOR_READY=false
            shift
            ;;
        -h|--help)
            HELP=true
            shift
            ;;
        *)
            echo -e "${RED}Error: Unknown option $1${NC}"
            show_help
            exit 1
            ;;
    esac
done

# Show help if requested
if [ "$HELP" = true ]; then
    show_help
    exit 0
fi

# Main execution
echo -e "${GREEN}Cloud Run Service Restart Utility${NC}"
echo -e "${BLUE}Project:${NC} $PROJECT_ID"
echo -e "${BLUE}Service:${NC} $SERVICE"
echo -e "${BLUE}Region:${NC} $REGION"
echo "----------------------------------------"

# Check gcloud setup
check_gcloud

# Get current status
if [ "$SHOW_STATUS" = true ]; then
    if ! get_service_status; then
        exit 1
    fi
fi

# Confirm restart if not forced
if [ "$FORCE" = false ]; then
    confirm_restart
fi

# Perform restart
restart_service

# Wait for service to be ready
if [ "$WAIT_FOR_READY" = true ]; then
    wait_for_ready
fi

# Show final status
if [ "$SHOW_STATUS" = true ]; then
    echo ""
    echo "----------------------------------------"
    echo -e "${BLUE}Final service status:${NC}"
    get_service_status
fi

echo ""
echo -e "${GREEN}✓ Restart complete!${NC}"
echo -e "${CYAN}Tip: Use './logs.sh -f' to monitor reconnecting agents${NC}"
