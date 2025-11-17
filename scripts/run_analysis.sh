#!/bin/bash
# Convenience script to run the analysis pipeline

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}Starting Loldriver Analysis Pipeline${NC}"
echo ""

# Check if container is running
if ! docker-compose ps | grep -q "ida-analyzer.*Up"; then
    echo -e "${YELLOW}Container not running. Starting...${NC}"
    docker-compose up -d ida-analyzer
    echo "Waiting for container to be ready..."
    sleep 3
fi

# Run the pipeline
echo -e "${GREEN}Executing analysis pipeline...${NC}"
docker-compose exec ida-analyzer python3 /analysis/scripts/pipeline.py \
    /analysis/drivers \
    /analysis/results \
    "$@"

echo ""
echo -e "${GREEN}Analysis complete!${NC}"
echo "Check ./results for output"
