#!/bin/bash

# Cloud Run Log Viewer Utility for Tunnel Server
# Usage: ./logs.sh [options]

set -e

# Configuration from deploy.sh
export PROJECT_ID=contact-center-insights-poc
export REGION=us-east1
export SERVICE=tunnel-server

# Default options
LINES=50
FOLLOW=false
SEVERITY=""
FRESHNESS="1h"
FORMAT="pretty"
HELP=false

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Function to display help
show_help() {
    cat << EOF
Cloud Run Log Viewer for Tunnel Server

USAGE:
    ./logs.sh [OPTIONS]

OPTIONS:
    -l, --lines NUM         Number of log lines to display (default: 50)
    -f, --follow           Follow logs in real-time (like tail -f)
    -s, --severity LEVEL   Filter by severity: ERROR, WARNING, INFO, DEBUG
    -t, --time DURATION    Time range: 1h, 30m, 1d, etc. (default: 1h)
    --format FORMAT        Output format: pretty, json, table (default: pretty)
    --errors               Show only ERROR and WARNING logs
    --ping                 Show only ping/pong related logs
    --websocket            Show only WebSocket related logs
    --agent ID             Show logs for specific agent ID
    --fresh                Show logs from last 5 minutes
    --all                  Show all available logs (no time limit)
    -h, --help             Show this help message

EXAMPLES:
    ./logs.sh                          # Show last 50 log entries from past hour
    ./logs.sh -f                       # Follow logs in real-time
    ./logs.sh --errors -l 100          # Show last 100 error/warning logs
    ./logs.sh --ping --fresh           # Show ping-related logs from last 5 minutes
    ./logs.sh --agent abc-123-def      # Show logs for specific agent
    ./logs.sh -s ERROR -t 24h          # Show errors from last 24 hours
    ./logs.sh --websocket -f           # Follow WebSocket-related logs

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

# Function to build log filter
build_filter() {
    local filter="resource.type=cloud_run_revision AND resource.labels.service_name=$SERVICE"
    
    if [ -n "$SEVERITY" ]; then
        filter="$filter AND severity>=$SEVERITY"
    fi
    
    if [ "$ERRORS_ONLY" = true ]; then
        filter="$filter AND (severity>=ERROR OR severity>=WARNING)"
    fi
    
    if [ "$PING_ONLY" = true ]; then
        filter="$filter AND (textPayload:\"ping\" OR textPayload:\"pong\" OR textPayload:\"Unknown message type\")"
    fi
    
    if [ "$WEBSOCKET_ONLY" = true ]; then
        filter="$filter AND (textPayload:\"WebSocket\" OR textPayload:\"websocket\" OR textPayload:\"Agent\" OR textPayload:\"connected\" OR textPayload:\"disconnected\")"
    fi
    
    if [ -n "$AGENT_ID" ]; then
        filter="$filter AND textPayload:\"$AGENT_ID\""
    fi
    
    echo "$filter"
}

# Function to format log output
format_logs() {
    if [ "$FORMAT" = "json" ]; then
        cat
    elif [ "$FORMAT" = "table" ]; then
        cat
    else
        # Pretty format with colors
        while IFS= read -r line; do
            # Skip empty lines
            if [ -z "$line" ]; then
                continue
            fi
            
            # Split the line into fields (timestamp, textPayload, requestUrl, status)
            IFS=$'\t' read -ra FIELDS <<< "$line"
            timestamp="${FIELDS[0]}"
            textPayload="${FIELDS[1]}"
            requestUrl="${FIELDS[2]}"
            status="${FIELDS[3]}"
            
            # Convert ISO timestamp to readable format
            if [[ $timestamp =~ ^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2}) ]]; then
                readable_time="${BASH_REMATCH[1]}-${BASH_REMATCH[2]}-${BASH_REMATCH[3]} ${BASH_REMATCH[4]}:${BASH_REMATCH[5]}:${BASH_REMATCH[6]}"
            else
                readable_time="$timestamp"
            fi
            
            # Build the message from available fields
            message=""
            if [ -n "$textPayload" ]; then
                message="$textPayload"
            elif [ -n "$requestUrl" ]; then
                if [ -n "$status" ]; then
                    message="$status $(echo $requestUrl | sed 's/\?.*$//')" # Remove query params for cleaner display
                else
                    message="$(echo $requestUrl | sed 's/\?.*$//')"
                fi
            else
                message="$line"
            fi
            
            # Color code based on content
            if [[ $message == *"ERROR"* ]] || [[ $message == *"error"* ]] || [[ $message == *"failed"* ]] || [[ $status == "401" ]] || [[ $status == "404" ]] || [[ $status == "500" ]]; then
                echo -e "${CYAN}$readable_time${NC} ${RED}$message${NC}"
            elif [[ $message == *"WARNING"* ]] || [[ $message == *"warning"* ]] || [[ $status == "400" ]]; then
                echo -e "${CYAN}$readable_time${NC} ${YELLOW}$message${NC}"
            elif [[ $message == *"ping"* ]] || [[ $message == *"pong"* ]]; then
                echo -e "${CYAN}$readable_time${NC} ${PURPLE}$message${NC}"
            elif [[ $message == *"connected"* ]] || [[ $message == *"registered"* ]] || [[ $status == "200" ]] || [[ $status == "101" ]]; then
                echo -e "${CYAN}$readable_time${NC} ${GREEN}$message${NC}"
            elif [[ $message == *"disconnected"* ]]; then
                echo -e "${CYAN}$readable_time${NC} ${YELLOW}$message${NC}"
            elif [[ $message == *"WebSocket"* ]] || [[ $message == *"Agent"* ]]; then
                echo -e "${CYAN}$readable_time${NC} ${BLUE}$message${NC}"
            else
                echo -e "${CYAN}$readable_time${NC} $message"
            fi
        done
    fi
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -l|--lines)
            LINES="$2"
            shift 2
            ;;
        -f|--follow)
            FOLLOW=true
            shift
            ;;
        -s|--severity)
            SEVERITY="$2"
            shift 2
            ;;
        -t|--time)
            FRESHNESS="$2"
            shift 2
            ;;
        --format)
            FORMAT="$2"
            shift 2
            ;;
        --errors)
            ERRORS_ONLY=true
            shift
            ;;
        --ping)
            PING_ONLY=true
            shift
            ;;
        --websocket)
            WEBSOCKET_ONLY=true
            shift
            ;;
        --agent)
            AGENT_ID="$2"
            shift 2
            ;;
        --fresh)
            FRESHNESS="5m"
            shift
            ;;
        --all)
            FRESHNESS=""
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

# Check gcloud setup
check_gcloud

# Build the filter
FILTER=$(build_filter)

# Display configuration
echo -e "${GREEN}Tunnel Server Log Viewer${NC}"
echo -e "${BLUE}Project:${NC} $PROJECT_ID"
echo -e "${BLUE}Service:${NC} $SERVICE"
echo -e "${BLUE}Region:${NC} $REGION"
if [ -n "$FRESHNESS" ]; then
    echo -e "${BLUE}Time Range:${NC} Last $FRESHNESS"
else
    echo -e "${BLUE}Time Range:${NC} All available logs"
fi
echo -e "${BLUE}Lines:${NC} $LINES"
if [ "$FOLLOW" = true ]; then
    echo -e "${BLUE}Mode:${NC} Following (real-time)"
else
    echo -e "${BLUE}Mode:${NC} Static"
fi
echo "----------------------------------------"

# Build gcloud logging command
if [ "$FOLLOW" = true ]; then
    # For follow mode, use gcloud logging read with streaming
    echo -e "${YELLOW}Following logs (Press Ctrl+C to stop)...${NC}"
    echo ""
    
    if [ "$FORMAT" = "pretty" ]; then
        gcloud logging read "$FILTER" \
            --format="value(timestamp,textPayload)" \
            --freshness=10s \
            --order=desc \
            --limit=$LINES | format_logs
    else
        gcloud logging read "$FILTER" \
            --limit=$LINES \
            --freshness=10s \
            --format="$FORMAT"
    fi
else
    # Static mode - use gcloud logging read
    if [ -n "$FRESHNESS" ]; then
        FRESHNESS_FLAG="--freshness=$FRESHNESS"
    else
        FRESHNESS_FLAG=""
    fi
    
    if [ "$FORMAT" = "pretty" ]; then
        gcloud logging read "$FILTER" \
            --format="value(timestamp,textPayload,httpRequest.requestUrl,httpRequest.status)" \
            --limit=$LINES \
            $FRESHNESS_FLAG \
            --order=desc | format_logs
    elif [ "$FORMAT" = "json" ]; then
        gcloud logging read "$FILTER" \
            --format=json \
            --limit=$LINES \
            $FRESHNESS_FLAG \
            --order=desc
    elif [ "$FORMAT" = "table" ]; then
        gcloud logging read "$FILTER" \
            --format="table(timestamp, severity, textPayload)" \
            --limit=$LINES \
            $FRESHNESS_FLAG \
            --order=desc
    fi
fi
