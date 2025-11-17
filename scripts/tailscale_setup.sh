#!/bin/bash
# Setup and manage Tailscale integration

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

check_env() {
    if [ ! -f .env ]; then
        echo -e "${RED}Error: .env file not found${NC}"
        echo "Please create .env from .env.example and add your TS_AUTHKEY"
        exit 1
    fi

    source .env

    if [ -z "$TS_AUTHKEY" ] || [ "$TS_AUTHKEY" = "tskey-auth-XXXXXXXXXXXXXXXXX" ]; then
        echo -e "${RED}Error: TS_AUTHKEY not configured in .env${NC}"
        echo ""
        echo "Please:"
        echo "  1. Go to https://login.tailscale.com/admin/settings/keys"
        echo "  2. Generate a new auth key"
        echo "  3. Add it to .env file as TS_AUTHKEY=your-key-here"
        exit 1
    fi
}

start_tailscale() {
    echo -e "${GREEN}Starting Tailscale...${NC}"

    check_env

    # Start Tailscale container
    docker-compose up -d tailscale

    echo "Waiting for Tailscale to connect..."
    sleep 5

    # Check status
    docker-compose exec tailscale tailscale status

    echo ""
    echo -e "${GREEN}Tailscale connected!${NC}"
    echo "Your analysis node is now accessible via Tailscale network"
}

stop_tailscale() {
    echo -e "${YELLOW}Stopping Tailscale...${NC}"
    docker-compose stop tailscale
    echo -e "${GREEN}Tailscale stopped${NC}"
}

status_tailscale() {
    if docker-compose ps | grep -q "tailscale.*Up"; then
        echo -e "${GREEN}Tailscale is running${NC}"
        echo ""
        docker-compose exec tailscale tailscale status
    else
        echo -e "${YELLOW}Tailscale is not running${NC}"
    fi
}

case "${1:-}" in
    start)
        start_tailscale
        ;;
    stop)
        stop_tailscale
        ;;
    status)
        status_tailscale
        ;;
    *)
        echo "Usage: $0 {start|stop|status}"
        echo ""
        echo "Commands:"
        echo "  start   - Start Tailscale and connect to network"
        echo "  stop    - Stop Tailscale"
        echo "  status  - Check Tailscale connection status"
        exit 1
        ;;
esac
