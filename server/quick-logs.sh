#!/bin/bash

# Quick Log Shortcuts for Tunnel Server
# Common log viewing patterns made easy

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

case "${1:-help}" in
    "errors"|"error"|"e")
        echo -e "${GREEN}🚨 Showing ERROR and WARNING logs...${NC}"
        "$SCRIPT_DIR/logs.sh" --errors -l 100
        ;;
    
    "recent"|"r")
        echo -e "${GREEN}📋 Showing recent logs (last 5 minutes)...${NC}"
        "$SCRIPT_DIR/logs.sh" --fresh -l 30
        ;;
    
    "live"|"follow"|"f")
        echo -e "${GREEN}📡 Following logs in real-time...${NC}"
        "$SCRIPT_DIR/logs.sh" --follow
        ;;
    
    "ping"|"p")
        echo -e "${GREEN}🏓 Showing ping/pong related logs...${NC}"
        "$SCRIPT_DIR/logs.sh" --ping -l 50
        ;;
    
    "websocket"|"ws"|"w")
        echo -e "${GREEN}🔌 Showing WebSocket connection logs...${NC}"
        "$SCRIPT_DIR/logs.sh" --websocket -l 50
        ;;
    
    "disconnect"|"d")
        echo -e "${GREEN}🔌 Showing connection/disconnection logs...${NC}"
        "$SCRIPT_DIR/logs.sh" --websocket --fresh -l 100
        ;;
    
    "agent")
        if [ -z "$2" ]; then
            echo -e "${YELLOW}Usage: $0 agent <agent-id>${NC}"
            echo "Example: $0 agent d73d6a94-05dc-4e7c-abe4-75f9a6a803f1"
            exit 1
        fi
        echo -e "${GREEN}🤖 Showing logs for agent: $2${NC}"
        "$SCRIPT_DIR/logs.sh" --agent "$2" -l 100
        ;;
    
    "all"|"a")
        echo -e "${GREEN}📜 Showing all recent logs...${NC}"
        "$SCRIPT_DIR/logs.sh" -l 100 -t 2h
        ;;
    
    "help"|"h"|*)
        echo "Quick Log Shortcuts for Tunnel Server"
        echo ""
        echo "USAGE: $0 <command>"
        echo ""
        echo "COMMANDS:"
        echo "  errors, e        Show ERROR and WARNING logs"
        echo "  recent, r        Show logs from last 5 minutes"
        echo "  live, follow, f  Follow logs in real-time"
        echo "  ping, p          Show ping/pong related logs"
        echo "  websocket, ws, w Show WebSocket connection logs" 
        echo "  disconnect, d    Show recent connection issues"
        echo "  agent <id>       Show logs for specific agent ID"
        echo "  all, a           Show all logs from last 2 hours"
        echo "  help, h          Show this help"
        echo ""
        echo "EXAMPLES:"
        echo "  $0 errors        # Show recent errors"
        echo "  $0 live          # Follow logs in real-time"
        echo "  $0 agent abc123  # Show logs for specific agent"
        echo ""
        echo "For advanced options, use: ./logs.sh --help"
        ;;
esac
