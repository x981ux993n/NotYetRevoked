# Quick Start Guide

Get up and running with NotYetRevoked in 5 minutes!

## 1. Prerequisites Check

```bash
# Check Docker
docker --version
# Should show: Docker version 20.x or higher

# Check Docker Compose
docker-compose --version
# Should show: Docker Compose version 1.29.x or higher
```

## 2. Initial Setup

```bash
# Clone repository (if not already done)
git clone <repository-url>
cd NotYetRevoked

# Run automated setup
chmod +x scripts/setup.sh
./scripts/setup.sh
```

Or use the Makefile:
```bash
make setup
```

## 3. Add IDA Pro (Required for Full Analysis)

```bash
# Option A: Copy existing IDA installation
cp -r /path/to/your/ida ./ida/

# Option B: Extract fresh installation
tar xzf /path/to/idapro_linux.tar.gz -C ./ida/

# Verify
ls -la ./ida/ida64
# Should show the ida64 executable
```

**Don't have IDA Pro?** You can still use the import screening functionality.

## 4. Add Driver Samples

```bash
# Create a test directory with your driver samples
cp /path/to/suspicious/*.sys ./drivers/

# Or download samples (example)
# wget https://example.com/driver_sample.sys -O drivers/sample.sys
```

## 5. Run Your First Analysis

### Option A: Using Make (Recommended)

```bash
# Start the environment
make up

# Run complete analysis
make analyze

# View results
ls -la results/run_*/
```

### Option B: Manual Docker Commands

```bash
# Start containers
docker-compose up -d

# Run analysis
./scripts/run_analysis.sh

# Or step-by-step:
# 1. Import screening only
make screen

# 2. Check screening results
cat results/screening_*.json | jq '.summary'

# 3. Full pipeline with IDA
make analyze
```

## 6. Check Results

```bash
# View latest results directory
ls -la results/

# Read the summary report
cat results/run_*/REPORT.md

# Or in JSON format
cat results/run_*/final_report.json | jq '.high_risk_drivers'
```

## Example Output

After running analysis, you'll see:

```
[22:30:00] [INFO] ================================================================
[22:30:00] [INFO] LOLDRIVER ANALYSIS PIPELINE STARTED
[22:30:00] [INFO] ================================================================
[22:30:00] [INFO] PHASE 1: Pre-Analysis Import Screening
[22:30:00] [INFO] ----------------------------------------------------------------
[*] Found 15 potential driver files
[*] Starting import screening...

[*] Analyzing: driver1.sys
    [!] SUSPICIOUS: 2 potential capabilities detected
        - Process termination capability (HIGH)
        - Memory manipulation capability (CRITICAL)
    [→] Recommendation: IMMEDIATE_ANALYSIS

[22:30:15] [INFO] PHASE 2: IDA Pro Deep Analysis (3 drivers)
[22:30:15] [INFO] ----------------------------------------------------------------
[*] [1/3] Analyzing driver1.sys
[*] Found DriverEntry at: 0x1000
[*] Found IOCTL handler: sub_177D8 at 0x177D8
[!] CAPABILITY IDENTIFIED: Process Killer
  ✓ Analysis completed for driver1.sys

[22:32:00] [INFO] PHASE 3: Generating Final Report
[22:32:00] [INFO] ----------------------------------------------------------------
[!] HIGH-RISK DRIVERS DETECTED
  Driver: driver1.sys
  Capabilities: PROCESS_KILLER, MEMORY_MANIPULATION
  Device: \\Device\\Malicious
  Symlink: \\DosDevices\\Malicious

[22:32:05] [INFO] Results saved to: /analysis/results/run_20240117_223000
```

## Common Commands Reference

```bash
# Environment Management
make up              # Start containers
make down            # Stop containers
make restart         # Restart containers
make logs            # View logs
make shell           # Open shell in container

# Analysis
make analyze         # Full pipeline
make screen          # Import screening only
make test            # Quick test

# Maintenance
make clean           # Remove old IDB files
make status          # Show system status

# Tailscale (Optional)
make tailscale-start  # Connect to Tailscale
make tailscale-status # Check connection
```

## Troubleshooting

### "No drivers found"
```bash
# Check drivers directory
ls -la drivers/
# Add some .sys files to drivers/
```

### "IDA not found"
```bash
# Verify IDA installation
docker-compose exec ida-analyzer ls -la /ida/ida64

# If missing, install IDA to ./ida directory
```

### "Permission denied"
```bash
# Fix script permissions
chmod +x scripts/*.sh
# Or run setup again
make setup
```

### Docker issues
```bash
# Rebuild containers
docker-compose down
docker-compose build --no-cache
docker-compose up -d
```

## Next Steps

1. **Read the full documentation**: `README.md`
2. **Learn advanced usage**: `docs/USAGE.md`
3. **See examples**: `docs/EXAMPLES.md`
4. **Set up Tailscale for remote access**: Edit `.env` and add your auth key
5. **Integrate headless IDA**: See `docs/HEADLESS_IDA_INTEGRATION.md`

## Getting Help

- Check the README for detailed information
- Review examples in `docs/EXAMPLES.md`
- Read the troubleshooting section in `docs/USAGE.md`
- Open an issue on GitHub

## Security Note

This tool is for **authorized security research only**. Only analyze drivers you have permission to examine.

---

**Ready to start?** Run `make analyze` now!
