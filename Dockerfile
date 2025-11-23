FROM ubuntu:22.04

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Build arguments for version pinning
ARG PYTHON_VERSION=3.10
ARG PEFILE_VERSION=2023.2.7
ARG CAPSTONE_VERSION=5.0.1

# Install system dependencies
RUN echo "==== Installing system packages ====" && \
    apt-get update && apt-get install -y \
    python3 \
    python3-venv \
    python3-dev \
    python3-pip \
    build-essential \
    wget \
    git \
    unzip \
    file \
    binutils \
    curl \
    ca-certificates \
    gnupg \
    lsb-release \
    # IDA Pro dependencies
    libqt5core5a \
    libqt5gui5 \
    libqt5widgets5 \
    libqt5network5 \
    libglib2.0-0 \
    libfontconfig1 \
    libfreetype6 \
    libx11-6 \
    libxext6 \
    libxrender1 \
    xvfb \
    # Utilities
    vim \
    less \
    procps \
    && rm -rf /var/lib/apt/lists/* \
    && echo "==== System packages installed successfully ===="

# Create Python virtual environment (avoids externally-managed-environment issues)
RUN echo "==== Creating Python virtual environment ====" && \
    python3 -m venv /opt/venv && \
    echo "==== Virtual environment created at /opt/venv ===="

# Activate venv for all subsequent commands
ENV PATH="/opt/venv/bin:$PATH"
ENV VIRTUAL_ENV="/opt/venv"

# Upgrade pip, setuptools, wheel in venv
RUN echo "==== Upgrading pip tools ====" && \
    pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip --version && \
    echo "==== Pip tools upgraded ===="

# Install Python packages with pinned versions
RUN echo "==== Installing Python analysis packages ====" && \
    pip install --no-cache-dir \
    pefile==${PEFILE_VERSION} \
    capstone==${CAPSTONE_VERSION} \
    pyelftools>=0.29 \
    && echo "==== Python packages installed ====" && \
    echo "Installed packages:" && \
    pip list

# Create working directories
RUN mkdir -p /analysis/drivers /analysis/results /analysis/scripts /analysis/logs

# Copy IDA installer (optional - will be skipped if not present)
# User should place IDA installer in ida_installer/ before building
COPY ida_installer* /tmp/ida_installer/ 2>/dev/null || true

# Install IDA Pro if installer is present
RUN echo "==== Checking for IDA Pro installer ====" && \
    if [ -d /tmp/ida_installer ] && [ "$(ls -A /tmp/ida_installer 2>/dev/null)" ]; then \
        echo "IDA installer found, beginning installation..." && \
        mkdir -p /opt/ida && \
        # Handle .run installer
        if [ -f /tmp/ida_installer/*.run ]; then \
            echo "Found .run installer" && \
            chmod +x /tmp/ida_installer/*.run && \
            /tmp/ida_installer/*.run --mode unattended --prefix /opt/ida 2>&1 | tee /analysis/logs/ida_install.log || \
            echo "WARNING: IDA installer failed, continuing without IDA"; \
        # Handle .tar.gz archive
        elif [ -f /tmp/ida_installer/*.tar.gz ]; then \
            echo "Found .tar.gz archive" && \
            tar xzf /tmp/ida_installer/*.tar.gz -C /opt/ida --strip-components=1 2>&1 | tee /analysis/logs/ida_install.log && \
            echo "IDA extracted successfully"; \
        # Handle pre-installed directory
        elif [ -d /tmp/ida_installer/ida ]; then \
            echo "Found pre-installed IDA directory" && \
            cp -r /tmp/ida_installer/ida/* /opt/ida/ 2>&1 | tee /analysis/logs/ida_install.log && \
            echo "IDA copied successfully"; \
        else \
            echo "WARNING: Unknown IDA installer format in ida_installer/" && \
            ls -la /tmp/ida_installer/; \
        fi && \
        rm -rf /tmp/ida_installer && \
        # Verify installation
        if [ -f /opt/ida/ida64 ]; then \
            chmod +x /opt/ida/ida64 && \
            echo "==== IDA Pro installed successfully at /opt/ida ====" && \
            ls -lh /opt/ida/ida64; \
        else \
            echo "WARNING: IDA installation incomplete - /opt/ida/ida64 not found" && \
            echo "Container will work for import screening, but IDA analysis will be unavailable"; \
        fi; \
    else \
        echo "==== No IDA installer found - skipping IDA installation ====" && \
        echo "Container will work for import screening only" && \
        echo "To enable IDA analysis, place installer in ida_installer/ and rebuild"; \
    fi

# Set up IDA environment variables
ENV IDA_PATH=/opt/ida
ENV PYTHONPATH=/opt/ida/python:$PYTHONPATH
ENV PATH=/opt/ida:$PATH
ENV TVHEADLESS=1
ENV QT_QPA_PLATFORM=offscreen

# Copy analysis scripts
COPY scripts/ /analysis/scripts/

# Make scripts executable
RUN chmod +x /analysis/scripts/*.py /analysis/scripts/*.sh 2>/dev/null || true

# Set working directory
WORKDIR /analysis

# Create startup log file
RUN touch /analysis/logs/startup.log

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python3 -c "import pefile; print('OK')" || exit 1

# Default command with logging
CMD ["/bin/bash", "-c", "echo 'Container started at' $(date) | tee -a /analysis/logs/startup.log && /bin/bash"]
