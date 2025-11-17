#!/bin/bash
# Setup script for the loldriver analysis environment

set -e

echo "=========================================="
echo "Loldriver Analysis Environment Setup"
echo "=========================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running as root
if [ "$EUID" -eq 0 ]; then
    echo -e "${RED}Please do not run this script as root${NC}"
    exit 1
fi

# Check for Docker
echo -e "\n${YELLOW}[1/6]${NC} Checking Docker installation..."
if ! command -v docker &> /dev/null; then
    echo -e "${RED}Docker is not installed. Please install Docker first.${NC}"
    echo "Visit: https://docs.docker.com/get-docker/"
    exit 1
fi
echo -e "${GREEN}✓ Docker found${NC}"

# Check for Docker Compose
echo -e "\n${YELLOW}[2/6]${NC} Checking Docker Compose installation..."
if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
    echo -e "${RED}Docker Compose is not installed. Please install Docker Compose first.${NC}"
    echo "Visit: https://docs.docker.com/compose/install/"
    exit 1
fi
echo -e "${GREEN}✓ Docker Compose found${NC}"

# Create directory structure
echo -e "\n${YELLOW}[3/6]${NC} Creating directory structure..."
mkdir -p drivers results ida scripts
echo -e "${GREEN}✓ Directories created${NC}"

# Check for .env file
echo -e "\n${YELLOW}[4/6]${NC} Checking environment configuration..."
if [ ! -f .env ]; then
    echo -e "${YELLOW}No .env file found. Creating from template...${NC}"
    cp .env.example .env
    echo -e "${YELLOW}Please edit .env and add your Tailscale auth key${NC}"
    echo -e "${YELLOW}Get your key from: https://login.tailscale.com/admin/settings/keys${NC}"
else
    echo -e "${GREEN}✓ .env file exists${NC}"
fi

# Check for IDA Pro
echo -e "\n${YELLOW}[5/6]${NC} Checking for IDA Pro installation..."
if [ ! -d "ida" ] || [ -z "$(ls -A ida)" ]; then
    echo -e "${YELLOW}IDA Pro not found in ./ida directory${NC}"
    echo ""
    echo "Please install IDA Pro (64-bit) to the ./ida directory:"
    echo "  1. Download IDA Pro from hex-rays.com"
    echo "  2. Extract to ./ida directory"
    echo "  3. Ensure ./ida/ida64 executable exists"
    echo ""
    echo -e "${YELLOW}For headless-ida integration:${NC}"
    echo "  git clone https://github.com/DennyDai/headless-ida"
    echo "  # Follow headless-ida setup instructions"
    echo ""
    echo -e "${YELLOW}Continuing without IDA Pro - you can add it later${NC}"
else
    if [ -f "ida/ida64" ]; then
        echo -e "${GREEN}✓ IDA Pro found${NC}"
    else
        echo -e "${YELLOW}⚠ IDA directory exists but ida64 executable not found${NC}"
    fi
fi

# Make scripts executable
echo -e "\n${YELLOW}[6/6]${NC} Setting script permissions..."
chmod +x scripts/*.py scripts/*.sh 2>/dev/null || true
echo -e "${GREEN}✓ Permissions set${NC}"

# Build Docker image
echo -e "\n${YELLOW}Building Docker image...${NC}"
docker-compose build

echo ""
echo -e "${GREEN}=========================================="
echo "Setup Complete!"
echo -e "==========================================${NC}"
echo ""
echo "Next steps:"
echo "  1. Edit .env file and add your Tailscale auth key (if using Tailscale)"
echo "  2. Place driver files (.sys) in the ./drivers directory"
echo "  3. Install IDA Pro to ./ida directory (if not already done)"
echo "  4. Run: docker-compose up -d"
echo "  5. Execute analysis: docker-compose exec ida-analyzer python3 /analysis/scripts/pipeline.py /analysis/drivers /analysis/results"
echo ""
echo "For more information, see README.md"
