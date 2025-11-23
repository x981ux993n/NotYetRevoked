#!/bin/bash
# Setup script for the loldriver analysis environment with comprehensive error logging

set -e  # Exit on error
set -o pipefail  # Exit on pipe failure

# Setup logging
LOG_DIR="./setup_logs"
LOG_FILE="${LOG_DIR}/setup_$(date +%Y%m%d_%H%M%S).log"
mkdir -p "$LOG_DIR"

# Function to log messages
log() {
    local level=$1
    shift
    local message="$@"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $message" | tee -a "$LOG_FILE"
}

# Function to log and display
log_display() {
    local color=$1
    local level=$2
    shift 2
    local message="$@"
    echo -e "${color}${message}${NC}" | tee -a "$LOG_FILE"
    log "$level" "$message"
}

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo "=========================================="
echo "Loldriver Analysis Environment Setup"
echo "=========================================="
log "INFO" "Setup started"
log "INFO" "Log file: $LOG_FILE"

# Check if running as root
if [ "$EUID" -eq 0 ]; then
    log_display "${RED}" "ERROR" "Please do not run this script as root"
    exit 1
fi

# Check for Docker
echo -e "\n${YELLOW}[1/7]${NC} Checking Docker installation..."
log "INFO" "Checking Docker installation"
if ! command -v docker &> /dev/null; then
    log_display "${RED}" "ERROR" "Docker is not installed"
    echo "Visit: https://docs.docker.com/get-docker/"
    exit 1
fi

DOCKER_VERSION=$(docker --version 2>&1)
log "INFO" "Docker found: $DOCKER_VERSION"
echo -e "${GREEN}✓ Docker found${NC}"

# Check Docker permissions
if ! docker ps &> /dev/null; then
    log_display "${YELLOW}" "WARN" "Cannot access Docker daemon - may need sudo or add user to docker group"
    echo "Try: sudo usermod -aG docker \$USER && newgrp docker"
fi

# Check for Docker Compose
echo -e "\n${YELLOW}[2/7]${NC} Checking Docker Compose installation..."
log "INFO" "Checking Docker Compose installation"

COMPOSE_CMD=""
if command -v docker-compose &> /dev/null; then
    COMPOSE_CMD="docker-compose"
    COMPOSE_VERSION=$(docker-compose --version 2>&1)
elif docker compose version &> /dev/null; then
    COMPOSE_CMD="docker compose"
    COMPOSE_VERSION=$(docker compose version 2>&1)
else
    log_display "${RED}" "ERROR" "Docker Compose is not installed"
    echo "Visit: https://docs.docker.com/compose/install/"
    exit 1
fi

log "INFO" "Docker Compose found: $COMPOSE_VERSION"
echo -e "${GREEN}✓ Docker Compose found${NC}"

# Create directory structure
echo -e "\n${YELLOW}[3/7]${NC} Creating directory structure..."
log "INFO" "Creating directory structure"

for dir in drivers results ida_installer scripts setup_logs; do
    if mkdir -p "$dir" 2>> "$LOG_FILE"; then
        log "INFO" "Created directory: $dir"
    else
        log_display "${RED}" "ERROR" "Failed to create directory: $dir"
        exit 1
    fi
done

echo -e "${GREEN}✓ Directories created${NC}"

# Check for .env file
echo -e "\n${YELLOW}[4/7]${NC} Checking environment configuration..."
log "INFO" "Checking environment configuration"

if [ ! -f .env ]; then
    log "INFO" "Creating .env from template"
    if cp .env.example .env 2>> "$LOG_FILE"; then
        echo -e "${YELLOW}Created .env file from template${NC}"
        echo -e "${BLUE}Note: Edit .env to add Tailscale auth key if using remote access${NC}"
        echo -e "${BLUE}Get key from: https://login.tailscale.com/admin/settings/keys${NC}"
        log "INFO" ".env file created"
    else
        log_display "${RED}" "ERROR" "Failed to create .env file"
        exit 1
    fi
else
    echo -e "${GREEN}✓ .env file exists${NC}"
    log "INFO" ".env file already exists"
fi

# Check for IDA Pro installer
echo -e "\n${YELLOW}[5/7]${NC} Checking for IDA Pro installer..."
log "INFO" "Checking for IDA Pro installer"

IDA_FOUND=false
if [ -d "ida_installer" ] && [ -n "$(ls -A ida_installer 2>/dev/null)" ]; then
    echo -e "${GREEN}✓ IDA installer found in ida_installer/${NC}"
    log "INFO" "IDA installer found:"
    ls -lh ida_installer/ | tee -a "$LOG_FILE"
    IDA_FOUND=true

    # Validate installer format
    if ls ida_installer/*.run 1> /dev/null 2>&1; then
        echo -e "${GREEN}  - Found .run installer${NC}"
        log "INFO" "Found .run installer"
    elif ls ida_installer/*.tar.gz 1> /dev/null 2>&1; then
        echo -e "${GREEN}  - Found .tar.gz archive${NC}"
        log "INFO" "Found .tar.gz archive"
    elif [ -d "ida_installer/ida" ]; then
        echo -e "${GREEN}  - Found pre-installed IDA directory${NC}"
        log "INFO" "Found pre-installed IDA directory"
    else
        echo -e "${YELLOW}  - Unknown installer format, will attempt installation${NC}"
        log "WARN" "Unknown IDA installer format"
    fi
else
    echo -e "${YELLOW}⚠ No IDA installer found${NC}"
    echo ""
    echo -e "${BLUE}To enable full IDA Pro analysis:${NC}"
    echo "  1. Create ida_installer directory (already done)"
    echo "  2. Place ONE of the following in ida_installer/:"
    echo "     - IDA Pro .run installer (idapro_*.run)"
    echo "     - IDA Pro .tar.gz archive"
    echo "     - Pre-installed IDA directory (as ida_installer/ida/)"
    echo "  3. Rebuild: $COMPOSE_CMD build"
    echo ""
    echo -e "${BLUE}Continuing without IDA - import screening will still work${NC}"
    log "WARN" "No IDA installer found - continuing without IDA"
fi

# Make scripts executable
echo -e "\n${YELLOW}[6/7]${NC} Setting script permissions..."
log "INFO" "Setting script permissions"

if chmod +x scripts/*.py scripts/*.sh 2>> "$LOG_FILE"; then
    echo -e "${GREEN}✓ Permissions set${NC}"
    log "INFO" "Script permissions set"
else
    log_display "${YELLOW}" "WARN" "Some permission changes failed (non-critical)"
fi

# Build Docker image
echo -e "\n${YELLOW}[7/7]${NC} Building Docker image..."
log "INFO" "Starting Docker build"
echo "This may take several minutes on first run..."
echo "Build output is being logged to: $LOG_FILE"
echo ""

BUILD_LOG="${LOG_DIR}/docker_build_$(date +%Y%m%d_%H%M%S).log"

if $COMPOSE_CMD build 2>&1 | tee "$BUILD_LOG" | grep -E "^(Step|#|>|==|Successfully)" ; then
    echo ""
    echo -e "${GREEN}✓ Docker image built successfully${NC}"
    log "INFO" "Docker build completed successfully"
    log "INFO" "Docker build log: $BUILD_LOG"
else
    log_display "${RED}" "ERROR" "Docker build failed"
    echo "Check build log: $BUILD_LOG"
    exit 1
fi

# Test container
echo -e "\n${BLUE}Testing container...${NC}"
log "INFO" "Testing container"

if $COMPOSE_CMD run --rm ida-analyzer python3 -c "import pefile; import sys; print('Python OK'); sys.exit(0)" 2>> "$LOG_FILE"; then
    echo -e "${GREEN}✓ Container test passed${NC}"
    log "INFO" "Container test passed"
else
    log_display "${YELLOW}" "WARN" "Container test failed - may still work for analysis"
fi

# Summary
echo ""
echo -e "${GREEN}=========================================="
echo "Setup Complete!"
echo -e "==========================================${NC}"
echo ""
log "INFO" "Setup completed successfully"

# Determine capabilities
echo -e "${BLUE}System Capabilities:${NC}"
if [ "$IDA_FOUND" = true ]; then
    echo -e "${GREEN}  ✓ Import screening${NC}"
    echo -e "${GREEN}  ✓ IDA Pro deep analysis${NC}"
    log "INFO" "Full capabilities available (import screening + IDA)"
else
    echo -e "${GREEN}  ✓ Import screening${NC}"
    echo -e "${YELLOW}  ⚠ IDA Pro deep analysis (not available)${NC}"
    log "INFO" "Limited capabilities (import screening only)"
fi

echo ""
echo -e "${BLUE}Next steps:${NC}"
echo "  1. ${YELLOW}[Optional]${NC} Edit .env for Tailscale remote access"
echo "  2. Place driver samples in ./drivers/"
if [ "$IDA_FOUND" = false ]; then
    echo "  3. ${YELLOW}[Optional]${NC} Add IDA installer to ida_installer/ and rebuild"
    echo "  4. Run analysis: ${GREEN}make analyze${NC} or ${GREEN}./scripts/run_analysis.sh${NC}"
else
    echo "  3. Run analysis: ${GREEN}make analyze${NC} or ${GREEN}./scripts/run_analysis.sh${NC}"
fi
echo ""
echo -e "${BLUE}Quick commands:${NC}"
echo "  make up          - Start containers"
echo "  make analyze     - Run full pipeline"
echo "  make screen      - Import screening only"
echo "  make logs        - View container logs"
echo "  make help        - Show all commands"
echo ""
echo -e "${BLUE}Logs saved to:${NC} $LOG_FILE"
echo ""

log "INFO" "Setup script finished"
