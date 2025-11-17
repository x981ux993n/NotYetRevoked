# Headless IDA Integration Guide

This guide explains how to integrate [headless-ida](https://github.com/DennyDai/headless-ida) for fully automated driver analysis.

## What is Headless IDA?

Headless IDA is a project that enables running IDA Pro in a headless (no GUI) environment, perfect for automated analysis pipelines and Docker containers.

## Prerequisites

- IDA Pro 64-bit license
- Docker environment (already set up)
- Linux host (or WSL2 on Windows)

## Integration Steps

### Method 1: Using Pre-built Headless IDA

```bash
# 1. Clone headless-ida repository
cd /tmp
git clone https://github.com/DennyDai/headless-ida
cd headless-ida

# 2. Follow their setup instructions to build headless IDA
# This typically involves:
# - Installing IDA Pro
# - Compiling the headless wrapper
# - Testing the headless execution

# 3. Copy the configured IDA to your NotYetRevoked project
cp -r /path/to/configured/ida /path/to/NotYetRevoked/ida/

# 4. Verify installation
cd /path/to/NotYetRevoked
docker-compose exec ida-analyzer /ida/ida64 -A -c
```

### Method 2: Manual IDA Configuration

If you prefer to configure IDA manually:

```bash
# 1. Install IDA Pro to ./ida directory
mkdir -p ida
cd ida

# 2. Extract IDA Pro
tar xzf /path/to/idapro_*_linux.tar.gz

# 3. Configure for headless operation
export TVHEADLESS=1
export QT_QPA_PLATFORM=offscreen

# 4. Test headless execution
./ida64 -A -c /path/to/test.sys
```

### Method 3: Docker Multi-stage Build

Create an enhanced Dockerfile with IDA Pro built-in:

```dockerfile
# Dockerfile.with-ida
FROM ubuntu:22.04 AS ida-installer

# Install dependencies
RUN apt-get update && apt-get install -y \
    wget \
    tar \
    && rm -rf /var/lib/apt/lists/*

# Copy IDA Pro installer (you need to provide this)
COPY idapro_*_linux.tar.gz /tmp/

# Extract IDA
RUN mkdir -p /ida && \
    cd /ida && \
    tar xzf /tmp/idapro_*_linux.tar.gz

# Final stage
FROM ubuntu:22.04

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    libqt5core5a \
    libqt5gui5 \
    libqt5widgets5 \
    xvfb \
    && rm -rf /var/lib/apt/lists/*

# Copy IDA from installer stage
COPY --from=ida-installer /ida /ida

# Configure headless mode
ENV TVHEADLESS=1
ENV QT_QPA_PLATFORM=offscreen
ENV IDA_PATH=/ida
ENV PYTHONPATH=/ida/python:$PYTHONPATH

# Install Python packages
RUN pip3 install --no-cache-dir pefile capstone pyelftools

# Copy analysis scripts
COPY scripts/ /analysis/scripts/

WORKDIR /analysis
CMD ["/bin/bash"]
```

Build with:
```bash
docker-compose -f docker-compose.yml -f docker-compose.ida.yml build
```

## Headless Execution Examples

### Basic Headless Analysis

```bash
# Run IDA in fully automated mode
docker-compose exec ida-analyzer /ida/ida64 \
    -A \
    -S"/analysis/scripts/ida_driver_analyzer.py" \
    /analysis/drivers/malicious.sys
```

### Batch Processing with Xvfb

For better compatibility:

```bash
# Run with virtual framebuffer
docker-compose exec ida-analyzer xvfb-run -a /ida/ida64 \
    -A \
    -S"/analysis/scripts/ida_driver_analyzer.py" \
    /analysis/drivers/malicious.sys
```

### Advanced: Custom IDA Startup Script

Create `/analysis/scripts/ida_startup.idc`:

```c
#include <idc.idc>

static main() {
    // Wait for auto-analysis
    auto_wait();

    // Set analysis options
    set_inf_attr(INF_AF, get_inf_attr(INF_AF) | AF_DODATA);
    set_inf_attr(INF_AF, get_inf_attr(INF_AF) | AF_FINAL);

    // Re-analyze
    plan_and_wait(0, BADADDR);

    // Run Python analysis script
    exec_python("import sys; sys.path.append('/analysis/scripts')");
    exec_python("from ida_driver_analyzer import DriverAnalyzer");
    exec_python("analyzer = DriverAnalyzer('/analysis/results/output.json')");
    exec_python("analyzer.analyze()");

    // Exit
    qexit(0);
}
```

Use with:
```bash
docker-compose exec ida-analyzer /ida/ida64 \
    -A \
    -S"/analysis/scripts/ida_startup.idc" \
    /analysis/drivers/driver.sys
```

## Optimization for Headless Mode

### 1. Disable Unnecessary Features

Edit `$IDA_PATH/cfg/ida.cfg`:

```ini
// Disable GUI features
DISABLE_GRAPH = YES
DISABLE_DEBUGGER = YES

// Speed up analysis
AUTO_ANALYSIS = YES
FINAL_PASS = YES

// Reduce memory usage
MAX_FUNC_SIZE = 65536
```

### 2. Use IDA Batch Mode

Create a batch analysis script:

```bash
#!/bin/bash
# batch_analyze.sh

DRIVERS_DIR=/analysis/drivers
RESULTS_DIR=/analysis/results/batch_$(date +%Y%m%d_%H%M%S)
mkdir -p $RESULTS_DIR

for driver in $DRIVERS_DIR/*.sys; do
    driver_name=$(basename "$driver")
    echo "Analyzing: $driver_name"

    /ida/ida64 \
        -A \
        -B \
        -S"/analysis/scripts/ida_driver_analyzer.py --output $RESULTS_DIR/${driver_name}.json" \
        "$driver" \
        &> "$RESULTS_DIR/${driver_name}.log"

    echo "  -> Results: $RESULTS_DIR/${driver_name}.json"
done

echo "Batch analysis complete: $RESULTS_DIR"
```

### 3. Parallel Processing

Process multiple drivers simultaneously:

```bash
#!/bin/bash
# parallel_analyze.sh

DRIVERS_DIR=/analysis/drivers
RESULTS_DIR=/analysis/results/parallel_$(date +%Y%m%d_%H%M%S)
MAX_PARALLEL=4

mkdir -p $RESULTS_DIR

# Function to analyze a single driver
analyze_driver() {
    driver=$1
    driver_name=$(basename "$driver")

    /ida/ida64 \
        -A \
        -B \
        -S"/analysis/scripts/ida_driver_analyzer.py --output $RESULTS_DIR/${driver_name}.json" \
        "$driver" \
        &> "$RESULTS_DIR/${driver_name}.log"
}

export -f analyze_driver
export RESULTS_DIR

# Run with GNU parallel (if available)
if command -v parallel &> /dev/null; then
    find $DRIVERS_DIR -name "*.sys" | \
        parallel -j $MAX_PARALLEL analyze_driver {}
else
    # Fallback to simple background jobs
    for driver in $DRIVERS_DIR/*.sys; do
        analyze_driver "$driver" &

        # Limit concurrent jobs
        while [ $(jobs -r | wc -l) -ge $MAX_PARALLEL ]; do
            sleep 1
        done
    done
    wait
fi

echo "Parallel analysis complete: $RESULTS_DIR"
```

## Troubleshooting Headless Mode

### Issue: "DISPLAY environment variable not set"

```bash
# Solution 1: Use Xvfb
xvfb-run -a /ida/ida64 -A driver.sys

# Solution 2: Set dummy display
export DISPLAY=:99
Xvfb :99 -screen 0 1024x768x24 &
/ida/ida64 -A driver.sys
```

### Issue: IDA hangs during analysis

```bash
# Add timeout to IDA execution
timeout 600 /ida/ida64 -A driver.sys

# Or use in Python
import subprocess
result = subprocess.run(
    ['/ida/ida64', '-A', 'driver.sys'],
    timeout=600
)
```

### Issue: License issues in Docker

```bash
# Mount license file
docker-compose exec \
    -v /path/to/ida.key:/ida/ida.key \
    ida-analyzer /ida/ida64 -A driver.sys

# Or copy license into container
docker cp /path/to/ida.key container:/ida/
```

## Performance Benchmarks

Expected analysis times (approximate):

- Import screening: 0.1-0.5 seconds per driver
- IDA headless analysis: 1-5 minutes per driver (depending on size)
- Complete pipeline (50 drivers): 15-45 minutes

Optimization tips:
- Use SSD storage for IDA databases
- Allocate sufficient RAM (4GB+ per IDA instance)
- Use parallel processing for large batches
- Pre-filter with import screening

## Integration with CI/CD

### GitHub Actions Example

```yaml
name: Driver Analysis

on:
  push:
    paths:
      - 'drivers/**/*.sys'

jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2

      - name: Set up Docker
        uses: docker/setup-buildx-action@v1

      - name: Build analysis container
        run: docker-compose build

      - name: Run analysis
        run: docker-compose run ida-analyzer python3 /analysis/scripts/pipeline.py /analysis/drivers /analysis/results

      - name: Upload results
        uses: actions/upload-artifact@v2
        with:
          name: analysis-results
          path: results/
```

## References

- [headless-ida GitHub](https://github.com/DennyDai/headless-ida)
- [IDA Pro Documentation](https://hex-rays.com/products/ida/support/idadoc/)
- [IDAPython Documentation](https://hex-rays.com/products/ida/support/idapython_docs/)
