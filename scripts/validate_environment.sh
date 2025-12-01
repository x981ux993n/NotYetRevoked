#!/usr/bin/env bash
#
# Comprehensive Environment Validation Script
# Tests all aspects of the NotYetRevoked setup in one place
#

set -e
set -o pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Counters
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_WARNED=0

# Logging
LOG_FILE="setup_logs/validation_$(date +%Y%m%d_%H%M%S).log"
mkdir -p setup_logs

log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"
}

test_pass() {
    echo -e "${GREEN}✓ PASS${NC}: $1" | tee -a "$LOG_FILE"
    ((TESTS_PASSED++))
}

test_fail() {
    echo -e "${RED}✗ FAIL${NC}: $1" | tee -a "$LOG_FILE"
    ((TESTS_FAILED++))
}

test_warn() {
    echo -e "${YELLOW}⚠ WARN${NC}: $1" | tee -a "$LOG_FILE"
    ((TESTS_WARNED++))
}

section() {
    echo "" | tee -a "$LOG_FILE"
    echo -e "${BLUE}========================================${NC}" | tee -a "$LOG_FILE"
    echo -e "${BLUE}$1${NC}" | tee -a "$LOG_FILE"
    echo -e "${BLUE}========================================${NC}" | tee -a "$LOG_FILE"
}

#######################################
# Test Functions
#######################################

test_docker() {
    section "Testing Docker Environment"

    if command -v docker &> /dev/null; then
        DOCKER_VERSION=$(docker --version)
        test_pass "Docker installed: $DOCKER_VERSION"
    else
        test_fail "Docker not installed"
        return 1
    fi

    if docker ps &> /dev/null; then
        test_pass "Docker daemon accessible"
    else
        test_fail "Docker daemon not accessible (try: sudo usermod -aG docker \$USER)"
        return 1
    fi

    if command -v docker-compose &> /dev/null || docker compose version &> /dev/null; then
        if command -v docker-compose &> /dev/null; then
            COMPOSE_VERSION=$(docker-compose --version)
        else
            COMPOSE_VERSION=$(docker compose version)
        fi
        test_pass "Docker Compose available: $COMPOSE_VERSION"
    else
        test_fail "Docker Compose not installed"
        return 1
    fi
}

test_wsl() {
    section "Testing WSL Environment (if applicable)"

    if grep -qi microsoft /proc/version 2>/dev/null; then
        test_pass "Running in WSL"

        if command -v dos2unix &> /dev/null; then
            test_pass "dos2unix installed (for line ending conversion)"
        else
            test_warn "dos2unix not installed (recommended for WSL)"
        fi

        # Check if we're on /mnt/c (slower) or WSL filesystem (faster)
        if [[ "$PWD" == /mnt/* ]]; then
            test_warn "Project on Windows filesystem (/mnt/c) - slower performance"
            echo "    Recommendation: Move to WSL filesystem (~/) for better performance"
        else
            test_pass "Project on WSL filesystem (good performance)"
        fi
    else
        test_pass "Not running in WSL (native Linux)"
    fi
}

test_file_structure() {
    section "Testing File Structure"

    REQUIRED_DIRS=("scripts" "drivers" "results" "ida_installer")
    for dir in "${REQUIRED_DIRS[@]}"; do
        if [ -d "$dir" ]; then
            test_pass "Directory exists: $dir/"
        else
            test_fail "Missing directory: $dir/"
        fi
    done

    REQUIRED_FILES=("Dockerfile" "docker-compose.yml" ".env.example" "Makefile")
    for file in "${REQUIRED_FILES[@]}"; do
        if [ -f "$file" ]; then
            test_pass "File exists: $file"
        else
            test_fail "Missing file: $file"
        fi
    done

    if [ -f ".env" ]; then
        test_pass ".env file exists"
    else
        test_warn ".env file not found (will be created from template)"
    fi
}

test_scripts() {
    section "Testing Scripts"

    SCRIPTS=("scripts/setup.sh" "scripts/import_screener.py" "scripts/pipeline.py" "scripts/ida_driver_analyzer.py")
    for script in "${SCRIPTS[@]}"; do
        if [ -f "$script" ]; then
            if [ -x "$script" ]; then
                test_pass "$script is executable"
            else
                test_warn "$script exists but not executable"
                chmod +x "$script" 2>/dev/null && test_pass "  → Fixed permissions" || test_fail "  → Could not fix permissions"
            fi

            # Check for Windows line endings
            if file "$script" | grep -q CRLF; then
                test_warn "$script has Windows line endings (CRLF)"
                if command -v dos2unix &> /dev/null; then
                    dos2unix "$script" 2>/dev/null && test_pass "  → Converted to Unix (LF)" || test_fail "  → Conversion failed"
                fi
            else
                test_pass "$script has correct line endings (LF)"
            fi
        else
            test_fail "Missing script: $script"
        fi
    done
}

test_ida_installer() {
    section "Testing IDA Pro Installer"

    if [ -d "ida_installer" ] && [ -n "$(ls -A ida_installer 2>/dev/null | grep -v README)" ]; then
        if ls ida_installer/*.run 1> /dev/null 2>&1; then
            test_pass "IDA .run installer found"
            if [ -x ida_installer/*.run ]; then
                test_pass "IDA installer is executable"
            else
                test_warn "IDA installer not executable"
                chmod +x ida_installer/*.run && test_pass "  → Fixed permissions"
            fi
        elif ls ida_installer/*.tar.gz 1> /dev/null 2>&1; then
            test_pass "IDA .tar.gz archive found"
        elif [ -d "ida_installer/ida" ]; then
            test_pass "Pre-installed IDA directory found"
            if [ -f "ida_installer/ida/ida64" ]; then
                test_pass "ida64 executable found in pre-installed directory"
            else
                test_fail "ida64 not found in ida_installer/ida/"
            fi
        else
            test_warn "Unknown IDA installer format"
        fi
    else
        test_warn "No IDA installer found (import screening only mode)"
        echo "    To enable IDA analysis: Place installer in ida_installer/ and rebuild"
    fi
}

test_docker_image() {
    section "Testing Docker Image"

    if docker images | grep -q "notyetrevoked-ida-analyzer\|headless-ida-analyzer"; then
        test_pass "Docker image exists"

        IMAGE_SIZE=$(docker images --format "{{.Repository}}:{{.Tag}}\t{{.Size}}" | grep -E "notyetrevoked-ida-analyzer|headless-ida-analyzer" | awk '{print $2}')
        if [ -n "$IMAGE_SIZE" ]; then
            test_pass "Image size: $IMAGE_SIZE"
        fi
    else
        test_warn "Docker image not built yet (run: ./scripts/setup.sh or docker-compose build)"
    fi
}

test_container_python() {
    section "Testing Container Python Environment"

    if docker images | grep -q "notyetrevoked-ida-analyzer\|headless-ida-analyzer"; then
        if docker-compose run --rm ida-analyzer python3 -c "import sys; print(f'Python {sys.version}')" 2>&1 | tee -a "$LOG_FILE" | grep -q "Python 3"; then
            test_pass "Python 3 available in container"
        else
            test_fail "Python 3 not available in container"
        fi

        if docker-compose run --rm ida-analyzer python3 -c "import pefile; print('pefile OK')" 2>&1 | tee -a "$LOG_FILE" | grep -q "pefile OK"; then
            test_pass "pefile module installed"
        else
            test_fail "pefile module not installed"
        fi

        if docker-compose run --rm ida-analyzer python3 -c "import capstone; print('capstone OK')" 2>&1 | tee -a "$LOG_FILE" | grep -q "capstone OK"; then
            test_pass "capstone module installed"
        else
            test_fail "capstone module not installed"
        fi
    else
        test_warn "Skipping container tests (image not built)"
    fi
}

test_container_ida() {
    section "Testing IDA in Container"

    if docker images | grep -q "notyetrevoked-ida-analyzer\|headless-ida-analyzer"; then
        if docker-compose run --rm ida-analyzer test -f /opt/ida/ida64 2>&1 | tee -a "$LOG_FILE"; then
            test_pass "IDA installed in container at /opt/ida/ida64"

            if docker-compose run --rm ida-analyzer /opt/ida/ida64 -v 2>&1 | tee -a "$LOG_FILE" | grep -q "IDA"; then
                test_pass "IDA executable runs successfully"
            else
                test_warn "IDA executable exists but may not run properly"
            fi
        else
            test_warn "IDA not installed in container (import screening only mode)"
        fi
    else
        test_warn "Skipping IDA tests (image not built)"
    fi
}

test_permissions() {
    section "Testing File Permissions"

    if [ -w "drivers" ]; then
        test_pass "drivers/ directory is writable"
    else
        test_fail "drivers/ directory is not writable"
    fi

    if [ -w "results" ]; then
        test_pass "results/ directory is writable"
    else
        test_fail "results/ directory is not writable"
    fi

    if [ -w "setup_logs" ]; then
        test_pass "setup_logs/ directory is writable"
    else
        test_warn "setup_logs/ directory is not writable"
    fi
}

test_disk_space() {
    section "Testing System Resources"

    AVAILABLE_SPACE=$(df -BG . | tail -1 | awk '{print $4}' | tr -d 'G')
    if [ "$AVAILABLE_SPACE" -ge 10 ]; then
        test_pass "Sufficient disk space: ${AVAILABLE_SPACE}GB available"
    elif [ "$AVAILABLE_SPACE" -ge 5 ]; then
        test_warn "Low disk space: ${AVAILABLE_SPACE}GB available (10GB+ recommended)"
    else
        test_fail "Insufficient disk space: ${AVAILABLE_SPACE}GB available (need 10GB+)"
    fi

    TOTAL_MEM=$(free -g | awk '/^Mem:/{print $2}')
    if [ "$TOTAL_MEM" -ge 4 ]; then
        test_pass "Sufficient memory: ${TOTAL_MEM}GB total"
    else
        test_warn "Low memory: ${TOTAL_MEM}GB total (4GB+ recommended for IDA analysis)"
    fi
}

#######################################
# Main Execution
#######################################

main() {
    echo "NotYetRevoked Environment Validation"
    echo "======================================"
    echo "Log file: $LOG_FILE"
    echo ""

    log "Validation started"

    test_docker
    test_wsl
    test_file_structure
    test_scripts
    test_ida_installer
    test_docker_image
    test_container_python
    test_container_ida
    test_permissions
    test_disk_space

    # Summary
    section "Validation Summary"
    echo -e "${GREEN}Passed:${NC} $TESTS_PASSED" | tee -a "$LOG_FILE"
    echo -e "${YELLOW}Warnings:${NC} $TESTS_WARNED" | tee -a "$LOG_FILE"
    echo -e "${RED}Failed:${NC} $TESTS_FAILED" | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"

    if [ $TESTS_FAILED -eq 0 ]; then
        echo -e "${GREEN}✓ Environment validation successful!${NC}" | tee -a "$LOG_FILE"
        echo "System is ready for analysis." | tee -a "$LOG_FILE"
        EXIT_CODE=0
    elif [ $TESTS_FAILED -le 2 ] && [ $TESTS_PASSED -ge 10 ]; then
        echo -e "${YELLOW}⚠ Environment mostly ready with minor issues${NC}" | tee -a "$LOG_FILE"
        echo "System can run but review warnings above." | tee -a "$LOG_FILE"
        EXIT_CODE=0
    else
        echo -e "${RED}✗ Environment validation failed${NC}" | tee -a "$LOG_FILE"
        echo "Please fix errors above before proceeding." | tee -a "$LOG_FILE"
        EXIT_CODE=1
    fi

    echo "" | tee -a "$LOG_FILE"
    echo "Full log: $LOG_FILE" | tee -a "$LOG_FILE"
    log "Validation completed with exit code $EXIT_CODE"

    exit $EXIT_CODE
}

# Run main function
main
