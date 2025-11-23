# Complete Setup Guide

This guide explains how to set up the NotYetRevoked loldriver analysis pipeline with proper IDA Pro integration and error logging.

## Two Approaches for IDA Pro

You can use IDA Pro in two ways:

### Approach 1: Build IDA into Docker Image (Recommended)

**Advantages:**
- ✅ Self-contained, reproducible environment
- ✅ No manual IDA setup needed after build
- ✅ Works consistently across all environments
- ✅ Better for production/automation

**Setup:**
```bash
# 1. Place IDA installer
mkdir -p ida_installer
cp /path/to/idapro_*_linux.run ida_installer/

# 2. Build (IDA is installed into image)
./scripts/setup.sh

# 3. Use immediately
make analyze
```

### Approach 2: Volume Mount Existing IDA

**Advantages:**
- ✅ No rebuild needed when updating IDA
- ✅ Can switch IDA versions easily
- ✅ Smaller Docker image size
- ✅ Share IDA installation across projects

**Setup:**
```bash
# 1. Install IDA to ./ida/ directory
./idapro_linux.run --prefix $(pwd)/ida

# 2. Build Docker image (without IDA)
./scripts/setup.sh

# 3. Start container (mounts ./ida/)
docker-compose up -d

# IDA is available via volume mount at /opt/ida
```

## Complete Setup Steps

### Prerequisites

1. **Docker & Docker Compose**
   ```bash
   # Check installations
   docker --version          # Should be 20.x or higher
   docker-compose --version  # Should be 1.29.x or higher

   # If missing, install from:
   # https://docs.docker.com/get-docker/
   ```

2. **IDA Pro 64-bit** (for full analysis)
   - Download from https://hex-rays.com
   - Supported formats: `.run`, `.tar.gz`, or pre-installed directory

3. **System Requirements**
   - 4GB+ RAM
   - 10GB+ disk space
   - Linux or WSL2 (Windows)

### Step 1: Clone Repository

```bash
git clone <repository-url>
cd NotYetRevoked
```

### Step 2: Choose IDA Approach

#### For Approach 1 (Build-in):

```bash
# Place IDA installer
mkdir -p ida_installer
cp /path/to/idapro_9.0_linux.run ida_installer/

# Verify
ls -lh ida_installer/
```

#### For Approach 2 (Volume Mount):

```bash
# Install IDA to local directory
chmod +x idapro_*_linux.run
./idapro_*_linux.run --prefix $(pwd)/ida

# Verify
ls -lh ida/ida64
```

### Step 3: Run Setup

```bash
# Make setup script executable
chmod +x scripts/setup.sh

# Run automated setup
./scripts/setup.sh
```

**What the setup script does:**
1. Checks Docker and Docker Compose
2. Creates directory structure
3. Configures environment (.env)
4. Detects IDA installer (if present)
5. Builds Docker image with full error logging
6. Tests the container
7. Shows capability summary

**Setup logs saved to:** `setup_logs/setup_*.log`

### Step 4: Verify Installation

```bash
# Check container can start
docker-compose up -d

# Test Python environment
docker-compose exec ida-analyzer python3 --version
docker-compose exec ida-analyzer python3 -c "import pefile; print('pefile OK')"

# Test IDA (if installed)
docker-compose exec ida-analyzer test -f /opt/ida/ida64 && echo "IDA found" || echo "IDA not found"

# Run health check
docker-compose exec ida-analyzer python3 -c "import pefile; print('Health check: OK')"
```

### Step 5: Add Driver Samples

```bash
# Copy driver files
cp /path/to/suspicious/*.sys ./drivers/

# Verify
ls -l drivers/
```

### Step 6: Run Analysis

```bash
# Quick test with import screening only
make screen

# Full pipeline (screening + IDA analysis)
make analyze

# View results
ls -la results/run_*/
cat results/run_*/REPORT.md
```

## Configuration Options

### Environment Variables (.env)

```bash
# Optional: Tailscale for remote access
TS_AUTHKEY=tskey-auth-YOUR-KEY-HERE
TS_HOSTNAME=ida-analysis-node

# IDA License (if needed)
IDA_LICENSE_FILE=/opt/ida/ida.key
```

### Docker Build Arguments

You can customize Python package versions:

```bash
docker-compose build \
  --build-arg PEFILE_VERSION=2023.2.7 \
  --build-arg CAPSTONE_VERSION=5.0.1
```

## Troubleshooting

### Issue: "externally-managed-environment" Python error

**Fixed in current version** - We now use Python virtual environment:
```dockerfile
# In Dockerfile
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
```

No action needed.

### Issue: "IDA not found" after build

**Check:**
```bash
# 1. Verify ida_installer had content during build
ls -la ida_installer/

# 2. Check build logs
cat setup_logs/docker_build_*.log | grep -i ida

# 3. Check container
docker-compose run --rm ida-analyzer ls -la /opt/ida/
```

**Solution:**
- If using Approach 1: Ensure installer was in ida_installer/ before building
- If using Approach 2: Ensure ./ida/ directory has ida64 executable

### Issue: Docker build fails with dependency errors

**Check:**
```bash
# View detailed build log
cat setup_logs/docker_build_*.log

# Common issues:
# - Network connectivity
# - Disk space (df -h)
# - Docker permissions (sudo usermod -aG docker $USER)
```

**Solution:**
```bash
# Rebuild with no cache
docker-compose build --no-cache 2>&1 | tee rebuild.log

# Check specific errors
grep -i error rebuild.log
```

### Issue: Container starts but analysis fails

**Check logs:**
```bash
# Container logs
docker-compose logs ida-analyzer

# Analysis logs
cat results/run_*/screening_results.json

# Python environment
docker-compose exec ida-analyzer python3 -c "import sys; print(sys.path)"
docker-compose exec ida-analyzer pip list
```

**Solution:**
```bash
# Test Python packages
docker-compose exec ida-analyzer python3 -c "
import pefile
import capstone
print('All packages OK')
"

# Re-run with verbose logging
docker-compose exec ida-analyzer python3 /analysis/scripts/import_screener.py \
  /analysis/drivers --single /analysis/drivers/test.sys
```

### Issue: "Permission denied" errors

```bash
# Fix script permissions
chmod +x scripts/*.sh scripts/*.py

# Fix Docker socket permissions
sudo usermod -aG docker $USER
newgrp docker

# Fix directory permissions
sudo chown -R $USER:$USER .
```

### Issue: Large Docker image size

**Expected:** 2-4GB with IDA Pro included

**To reduce:**
```bash
# Use volume mount approach instead of built-in
# Clean up old images
docker system prune -a

# Use multi-stage builds (advanced)
# See docs/HEADLESS_IDA_INTEGRATION.md
```

## Verification Checklist

After setup, verify:

- [ ] Docker containers start: `docker-compose ps`
- [ ] Python packages work: `make test`
- [ ] Import screening works: `make screen`
- [ ] IDA is accessible: `docker-compose exec ida-analyzer /opt/ida/ida64 -v`
- [ ] Analysis pipeline works: `make analyze`
- [ ] Logs are generated: `ls setup_logs/`

## Advanced Configuration

### Using Different Python Versions

Edit `Dockerfile`:
```dockerfile
ARG PYTHON_VERSION=3.11
```

Then rebuild:
```bash
docker-compose build --no-cache
```

### Parallel Analysis

For large batches:
```bash
# Edit docker-compose.yml to add more workers
docker-compose up --scale ida-analyzer=4
```

### Custom IDA Configuration

Create `ida_installer/ida.cfg`:
```ini
DISABLE_GRAPH = YES
AUTO_ANALYSIS = YES
```

This will be copied during build.

## Logging

All operations are logged:

| Log Type | Location | Purpose |
|----------|----------|---------|
| Setup logs | `setup_logs/setup_*.log` | Initial setup process |
| Build logs | `setup_logs/docker_build_*.log` | Docker image build |
| Container logs | `docker-compose logs` | Runtime container logs |
| Analysis logs | `results/run_*/` | Analysis results and errors |
| IDA logs | `/analysis/logs/` (in container) | IDA installation logs |

View logs:
```bash
# Setup logs
cat setup_logs/setup_*.log

# Build logs
cat setup_logs/docker_build_*.log

# Container logs
docker-compose logs -f ida-analyzer

# Analysis logs
find results/ -name "*.log"
```

## Getting Help

1. **Check logs:** Review setup and build logs for errors
2. **Test components:** Use `make test` to verify environment
3. **Read documentation:**
   - `README.md` - Overview and features
   - `QUICKSTART.md` - Fast start guide
   - `docs/USAGE.md` - Detailed usage examples
   - `docs/EXAMPLES.md` - Real-world analysis examples
   - `docs/HEADLESS_IDA_INTEGRATION.md` - Advanced IDA setup

4. **Common commands:**
   ```bash
   make help        # Show all commands
   make status      # System status
   make logs        # View logs
   make clean       # Clean old results
   ```

## Next Steps

Once setup is complete:

1. **Run first analysis:** `make analyze`
2. **Review results:** `cat results/run_*/REPORT.md`
3. **Learn advanced usage:** See `docs/USAGE.md`
4. **Set up remote access:** Configure Tailscale in `.env`
5. **Integrate with workflow:** See `docs/EXAMPLES.md` for CI/CD integration

---

**Questions?** Check the documentation or review logs in `setup_logs/`
