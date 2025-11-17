# Detailed Usage Guide

## Table of Contents

1. [Initial Setup](#initial-setup)
2. [Basic Workflow](#basic-workflow)
3. [Advanced Usage](#advanced-usage)
4. [Understanding Results](#understanding-results)
5. [Troubleshooting](#troubleshooting)

## Initial Setup

### Step 1: Environment Preparation

```bash
# Navigate to project directory
cd NotYetRevoked

# Run the setup script
./scripts/setup.sh
```

The setup script will:
- Check for Docker and Docker Compose
- Create necessary directories
- Set up environment configuration
- Build the Docker image

### Step 2: IDA Pro Installation

**Option A: Standard IDA Pro**

1. Download IDA Pro from [hex-rays.com](https://hex-rays.com)
2. Extract the archive to the `./ida` directory
3. Verify installation:
```bash
ls -la ./ida/ida64
```

**Option B: Headless IDA Integration**

For fully automated analysis:

```bash
# Clone headless-ida
git clone https://github.com/DennyDai/headless-ida
cd headless-ida

# Follow their setup instructions
# Copy the configured IDA installation to ../NotYetRevoked/ida/
```

### Step 3: Tailscale Setup (Optional)

For remote access to your analysis node:

```bash
# Get auth key from https://login.tailscale.com/admin/settings/keys
# Edit .env file
nano .env

# Add your auth key:
# TS_AUTHKEY=tskey-auth-YOUR-KEY-HERE

# Start Tailscale
./scripts/tailscale_setup.sh start
```

## Basic Workflow

### Scenario 1: Analyzing a Collection of Drivers

```bash
# 1. Copy driver files to the drivers directory
cp /path/to/suspicious_drivers/*.sys ./drivers/

# 2. Start the Docker environment
docker-compose up -d

# 3. Run the complete pipeline
./scripts/run_analysis.sh

# 4. Check results
ls -la results/run_*/
cat results/run_*/REPORT.md
```

### Scenario 2: Quick Pre-Screening

If you have many drivers and want to quickly identify which ones need deeper analysis:

```bash
# Start container
docker-compose up -d ida-analyzer

# Run screening only
docker-compose exec ida-analyzer python3 /analysis/scripts/import_screener.py \
    /analysis/drivers \
    -o /analysis/results/screening.json

# View results
cat results/screening.json | jq '.summary'
```

Example output:
```json
{
  "total_analyzed": 150,
  "priority_counts": {
    "IMMEDIATE_ANALYSIS": 5,
    "HIGH_PRIORITY": 12,
    "MEDIUM_PRIORITY": 23,
    "LOW_PRIORITY": 110
  }
}
```

### Scenario 3: Analyzing a Single Driver

```bash
# Screen a specific driver
docker-compose exec ida-analyzer python3 /analysis/scripts/import_screener.py \
    /analysis/drivers/suspicious.sys \
    --single

# If it's high priority, run IDA analysis
docker-compose exec ida-analyzer /ida/ida64 \
    -A \
    -S"/analysis/scripts/ida_driver_analyzer.py --output /analysis/results/suspicious_analysis.json" \
    /analysis/drivers/suspicious.sys

# View results
cat results/suspicious_analysis.json | jq '.results.capabilities'
```

## Advanced Usage

### Custom Pipeline Configuration

Create a custom pipeline script:

```python
#!/usr/bin/env python3
from pathlib import Path
import sys
sys.path.insert(0, '/analysis/scripts')
from pipeline import AnalysisPipeline

# Custom configuration
pipeline = AnalysisPipeline(
    drivers_dir='/analysis/drivers/high_priority',
    results_dir='/analysis/results/custom_run',
    ida_path='/ida',
    skip_screening=False
)

# Run with custom filters
pipeline.run_pipeline()
```

### Batch Analysis with Filtering

```bash
# Analyze only drivers from a specific vendor
find ./drivers -name "*vendor_name*.sys" -exec cp {} ./drivers/batch/ \;

# Run analysis on filtered set
docker-compose exec ida-analyzer python3 /analysis/scripts/pipeline.py \
    /analysis/drivers/batch \
    /analysis/results/vendor_analysis
```

### Integration with External Tools

**Export to YARA Rules:**

```python
# Custom script to generate YARA rules from findings
import json

with open('results/run_TIMESTAMP/final_report.json') as f:
    report = json.load(f)

for driver in report['high_risk_drivers']:
    device_name = driver['device_info'].get('device_name', '')
    print(f"""
rule Loldriver_{driver['driver'].replace('.sys', '')}
{{
    meta:
        description = "Detects {driver['driver']}"
        capabilities = "{', '.join(driver['capabilities'])}"
        device = "{device_name}"

    strings:
        $device = "{device_name}" wide

    condition:
        uint16(0) == 0x5A4D and $device
}}
""")
```

### Remote Analysis via Tailscale

Once Tailscale is configured:

```bash
# From any device on your Tailscale network
ssh user@ida-analysis-node

# Or use Docker remotely
export DOCKER_HOST=tcp://ida-analysis-node:2376
docker-compose exec ida-analyzer python3 /analysis/scripts/pipeline.py ...
```

## Understanding Results

### Screening Results Structure

```json
{
  "summary": {
    "total_analyzed": 50,
    "priority_counts": { ... }
  },
  "priority_buckets": {
    "IMMEDIATE_ANALYSIS": [
      {
        "driver_name": "malicious.sys",
        "driver_path": "/analysis/drivers/malicious.sys",
        "findings": [
          {
            "pattern": "process_killer",
            "description": "Process termination capability",
            "severity": "HIGH",
            "matched_apis": [
              ["ZwOpenProcess"],
              ["ZwTerminateProcess"]
            ],
            "confidence": "HIGH"
          }
        ],
        "recommendation": "IMMEDIATE_ANALYSIS"
      }
    ]
  }
}
```

**Priority Levels:**
- `IMMEDIATE_ANALYSIS`: Multiple critical capabilities (2+ CRITICAL findings)
- `HIGH_PRIORITY`: At least 1 critical or 2+ high severity findings
- `MEDIUM_PRIORITY`: 1 high severity finding
- `LOW_PRIORITY`: Only medium/low severity findings

### IDA Analysis Results Structure

```json
{
  "status": "completed",
  "results": {
    "driver_name": "malicious.sys",
    "driver_entry": "0x11000",
    "device_info": {
      "device_name": "\\Device\\Malicious",
      "symbolic_link": "\\DosDevices\\Malicious"
    },
    "dispatch_handlers": {
      "IRP_MJ_CREATE": {
        "address": "0x17694",
        "name": "DispatchCreate"
      },
      "IRP_MJ_DEVICE_CONTROL": {
        "address": "0x177D8",
        "name": "DispatchDeviceControl"
      }
    },
    "ioctl_handlers": {
      "0xB4A00404": {
        "address": "0x1837C",
        "name": "ProcessKillerHandler"
      }
    },
    "suspicious_functions": [
      {
        "function": "ProcessKillerHandler",
        "address": "0x1837C",
        "dangerous_calls": [
          {
            "function": "ZwOpenProcess",
            "category": "process_access",
            "address": "0x18400",
            "context": "0xB4A00404"
          },
          {
            "function": "ZwTerminateProcess",
            "category": "process_termination",
            "address": "0x18450",
            "context": "0xB4A00404"
          }
        ]
      }
    ],
    "capabilities": ["PROCESS_KILLER"]
  }
}
```

### Exploitation Information

From the analysis results, you can build exploitation code:

```cpp
// Based on device_info and ioctl_handlers
HANDLE hDevice = CreateFile(
    "\\\\.\\Malicious",  // from symbolic_link
    GENERIC_READ | GENERIC_WRITE,
    0,
    NULL,
    OPEN_EXISTING,
    0,
    NULL
);

// Input buffer structure (determined from IDA analysis)
struct ProcessKillerInput {
    DWORD padding;
    DWORD targetPID;
    BYTE extraPadding[16];
};

ProcessKillerInput input = {0};
input.targetPID = 1234; // Target process ID

DWORD bytesReturned;
DeviceIoControl(
    hDevice,
    0xB4A00404,  // from ioctl_handlers
    &input,
    sizeof(input),
    NULL,
    0,
    &bytesReturned,
    NULL
);
```

## Troubleshooting

### Issue: "Permission denied" when running scripts

```bash
# Fix permissions
chmod +x scripts/*.sh
chmod +x scripts/*.py
```

### Issue: Docker container won't start

```bash
# Check logs
docker-compose logs ida-analyzer

# Rebuild container
docker-compose down
docker-compose build --no-cache
docker-compose up -d
```

### Issue: IDA analysis produces no results

```bash
# Check if IDA is properly installed
docker-compose exec ida-analyzer ls -la /ida/ida64

# Run IDA manually to see errors
docker-compose exec ida-analyzer /ida/ida64 -A /analysis/drivers/test.sys

# Check IDA logs
docker-compose exec ida-analyzer cat /ida/ida.log
```

### Issue: Screening finds no suspicious drivers

This could mean:
- Drivers are legitimate and safe
- Drivers use different API patterns
- Drivers are packed/obfuscated

Try:
```bash
# Check if drivers are valid PE files
docker-compose exec ida-analyzer file /analysis/drivers/*.sys

# Look at imports manually
docker-compose exec ida-analyzer python3 -c "
import pefile
pe = pefile.PE('/analysis/drivers/driver.sys')
pe.parse_data_directories()
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    print(entry.dll)
    for imp in entry.imports:
        print(f'  - {imp.name}')
"
```

### Issue: Analysis takes too long

```bash
# Increase timeout in pipeline.py
# Edit line ~200:
#   timeout=1200  # 20 minutes instead of 10

# Or run specific drivers only
cp drivers/high_priority.sys drivers/batch/
docker-compose exec ida-analyzer python3 /analysis/scripts/pipeline.py \
    /analysis/drivers/batch \
    /analysis/results
```

### Issue: Out of disk space

```bash
# Clean up old IDB files
find results/ -name "*.i64" -delete
find results/ -name "*.idb" -delete

# Clean Docker
docker system prune -a
```

## Performance Tips

### Parallel Analysis

For large batches, split into multiple containers:

```bash
# Split drivers into batches
split -n l/4 -d drivers_list.txt batch_

# Run multiple containers
for i in {0..3}; do
    docker run -d --name analyzer_$i \
        -v $(pwd)/drivers:/analysis/drivers \
        -v $(pwd)/results:/analysis/results \
        ida-analyzer \
        python3 /analysis/scripts/pipeline.py /analysis/drivers/batch_$i /analysis/results/run_$i
done
```

### Optimize IDA Analysis

```bash
# Disable GUI components in headless mode
export TVHEADLESS=1

# Use faster analysis options
# Edit ida_driver_analyzer.py to use quick analysis mode
```

## Monitoring Analysis Progress

```bash
# Watch logs in real-time
docker-compose logs -f ida-analyzer

# Check current progress
watch -n 5 'find results/ -name "*.json" | wc -l'

# View latest findings
tail -f results/run_*/REPORT.md
```
