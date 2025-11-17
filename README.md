# NotYetRevoked

**Automated Windows Driver Analysis Pipeline for LOLDriver Detection**

A Docker based pipeline for analyzing Windows kernel drivers to identify potential "Living Off The Land" (LOL) drivers that can be abused for malicious purposes. This project combines pre-screening analysis with deep IDA Pro reverse engineering to systematically identify drivers with dangerous capabilities.


This pipeline implements a two-phase approach to driver analysis:

1. **Pre-Analysis Import Screening**: Quickly scan driver imports to identify suspicious API usage patterns
2. **Deep IDA Pro Analysis**: Automated reverse engineering of high-priority drivers to map complete attack chains

### Key Capabilities Detected

- **Process Killer Drivers**: Ability to terminate arbitrary processes
- **Memory Manipulation**: Read/write access to arbitrary process memory
- **Driver Loading**: Capability to load additional kernel drivers
- **Physical Memory Access**: Direct hardware memory access
- **Token/Privilege Manipulation**: Security token tampering
- **Callback Removal**: Security callback bypass


```
┌─────────────────────────────────────────────────────────────┐
│                     Docker Environment                       │
├─────────────────────────────────────────────────────────────┤
│  ┌────────────────┐         ┌─────────────────┐            │
│  │  Import        │         │   IDA Pro       │            │
│  │  Screener      │────────▶│   Headless      │            │
│  │  (Python)      │         │   Analyzer      │            │
│  └────────────────┘         └─────────────────┘            │
│         │                            │                      │
│         ▼                            ▼                      │
│  ┌──────────────────────────────────────────┐              │
│  │        Pipeline Orchestrator             │              │
│  │       (Automated Workflow)               │              │
│  └──────────────────────────────────────────┘              │
│                      │                                      │
│                      ▼                                      │
│         ┌────────────────────────┐                         │
│         │   Results & Reports    │                         │
│         │   (JSON + Markdown)    │                         │
│         └────────────────────────┘                         │
└─────────────────────────────────────────────────────────────┘
                        │
                        │ (Optional)
                        ▼
              ┌──────────────────┐
              │  Tailscale VPN   │
              │  Remote Access   │
              └──────────────────┘
```

### Prerequisites

- Docker and Docker Compose
- IDA Pro 64-bit (for deep analysis phase)
- (Optional) Tailscale account for remote access

### Installation

1. **Clone the repository**
```bash
git clone <repository-url>
cd NotYetRevoked
```

2. **Run setup script**
```bash
chmod +x scripts/setup.sh
./scripts/setup.sh
```

3. **Configure IDA Pro**
```bash
# Extract IDA Pro to ./ida directory
# Ensure ./ida/ida64 executable exists
# For headless-ida integration:
git clone https://github.com/DennyDai/headless-ida
# Follow headless-ida setup instructions and configure
```

4. **(Optional) Configure Tailscale**
```bash
# Copy environment template
cp .env.example .env

# Edit .env and add your Tailscale auth key
# Get from: https://login.tailscale.com/admin/settings/keys
nano .env

# Start Tailscale
./scripts/tailscale_setup.sh start
```

### Usage

#### 1. Quick Analysis

```bash
# Place driver files in ./drivers directory
cp /path/to/suspicious/*.sys ./drivers/

# Start the Docker environment
docker-compose up -d

# Run the complete pipeline
./scripts/run_analysis.sh

# Results will be in ./results/run_TIMESTAMP/
```

#### 2. Import Screening Only

```bash
# Quick pre-screen without IDA analysis
docker-compose exec ida-analyzer python3 /analysis/scripts/import_screener.py \
    /analysis/drivers \
    -o /analysis/results/screening.json
```

#### 3. Manual IDA Analysis

```bash
# Analyze a specific driver with IDA Pro
docker-compose exec ida-analyzer /ida/ida64 \
    -A \
    -S"/analysis/scripts/ida_driver_analyzer.py --output /analysis/results/driver_analysis.json" \
    /analysis/drivers/malicious.sys
```

#### 4. Pipeline with Custom Options

```bash
# Skip screening and analyze all drivers
docker-compose exec ida-analyzer python3 /analysis/scripts/pipeline.py \
    /analysis/drivers \
    /analysis/results \
    --skip-screening

# Custom IDA path
docker-compose exec ida-analyzer python3 /analysis/scripts/pipeline.py \
    /analysis/drivers \
    /analysis/results \
    --ida-path /custom/ida
```

### Phase 1: Import Screening

The pre-analysis phase examines PE imports to identify suspicious API combinations:

**Process Killer Detection**:
- `ZwOpenProcess` or `NtOpenProcess` or `PsLookupProcessByProcessId`
- AND `ZwTerminateProcess` or `NtTerminateProcess`

**Memory Manipulation Detection**:
- Process access APIs
- AND `MmCopyVirtualMemory` or `ZwReadVirtualMemory` or `ZwWriteVirtualMemory`

**Critical Capabilities**:
- Driver loading: `ZwLoadDriver`
- Physical memory: `MmMapIoSpace`
- Callback removal: `ObUnRegisterCallbacks`, `CmUnRegisterCallback`

### Phase 2: Deep IDA Analysis

For high-priority drivers, automated IDA Pro analysis:

1. **Locate DriverEntry**: Find the driver initialization function
2. **Map Initialization Chain**: Follow driver setup to find device names and dispatch handlers
3. **Identify IOCTL Handlers**: Locate DeviceIoControl dispatch functions
4. **Extract IOCTL Codes**: Find all IOCTL codes and their handlers
5. **Trace Dangerous Functions**: Map complete call chains to dangerous APIs
6. **Build Attack Chains**: Document exploitable code paths

Example output identifies:
- Device name (e.g., `\\Device\\TfSysMon`)
- Symbolic link (e.g., `\\.\\TfSysMon`)
- IOCTL codes (e.g., `0xB4A00404`)
- Input buffer structure
- Complete exploitation path

## Project Structure

```
NotYetRevoked/
├── docker-compose.yml          # Docker orchestration
├── Dockerfile                  # Container definition
├── .env.example                # Environment template
├── scripts/
│   ├── import_screener.py      # Pre-analysis import scanner
│   ├── ida_driver_analyzer.py  # IDA Pro automation script
│   ├── pipeline.py             # Main orchestration pipeline
│   ├── setup.sh                # Initial setup script
│   ├── run_analysis.sh         # Convenience runner
│   └── tailscale_setup.sh      # Tailscale management
├── drivers/                    # Input: driver files (.sys)
├── results/                    # Output: analysis results
├── ida/                        # IDA Pro installation
└── README.md
```

## Output Format

### Screening Results

```json
{
  "summary": {
    "total_analyzed": 50,
    "priority_counts": {
      "IMMEDIATE_ANALYSIS": 3,
      "HIGH_PRIORITY": 7,
      "MEDIUM_PRIORITY": 12,
      "LOW_PRIORITY": 28
    }
  },
  "priority_buckets": {
    "IMMEDIATE_ANALYSIS": [
      {
        "driver_name": "malicious.sys",
        "findings": [
          {
            "pattern": "process_killer",
            "severity": "HIGH",
            "matched_apis": [
              ["ZwOpenProcess"],
              ["ZwTerminateProcess"]
            ]
          }
        ]
      }
    ]
  }
}
```

### IDA Analysis Results

```json
{
  "driver_name": "malicious.sys",
  "device_info": {
    "device_name": "\\Device\\Malicious",
    "symbolic_link": "\\DosDevices\\Malicious"
  },
  "ioctl_handlers": {
    "0xB4A00404": {
      "address": "0x1837C",
      "name": "ProcessKillerHandler"
    }
  },
  "capabilities": ["PROCESS_KILLER"],
  "suspicious_functions": [...]
}
```
## Tailscale Integration

Remote access to your analysis environment:

```bash
# Start Tailscale
./scripts/tailscale_setup.sh start

# Check status
./scripts/tailscale_setup.sh status

# Access from any device on your Tailscale network
ssh user@ida-analysis-node
```

## Troubleshooting

### IDA Pro Not Found

```bash
# Ensure IDA is properly installed
ls -la ./ida/ida64

# Check permissions
chmod +x ./ida/ida64
```

### Docker Permission Denied

```bash
# Add user to docker group
sudo usermod -aG docker $USER
# Log out and back in
```

### Analysis Timeout

```bash
# Increase timeout in pipeline.py
# Edit: timeout=600 to higher value
```

## References

- [LOLDrivers.io](https://loldrivers.io) - Living Off The Land Drivers database
- [Headless IDA](https://github.com/DennyDai/headless-ida) - Automated IDA Pro analysis
- [Windows Driver Development](https://docs.microsoft.com/windows-hardware/drivers/)
- [IDA Pro Python SDK](https://hex-rays.com/products/ida/support/idapython_docs/)

## AI Disclosure
- Used Claude Code + 4.5 Sonnet.

##  Disclaimer

This tool is provided for legitimate security research and defensive purposes only. Users are responsible for ensuring they have proper authorization before analyzing any software. The authors assume no liability for misuse. 
