FROM ubuntu:22.04

# Metadata labels following OCI standards
LABEL maintainer="NotYetRevoked Project"
LABEL description="Automated Windows driver analysis for loldriver detection"
LABEL version="1.0"
LABEL org.opencontainers.image.source="https://github.com/x981ux993n/NotYetRevoked"

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Build arguments for version pinning
ARG PYTHON_VERSION=3.10
ARG PEFILE_VERSION=2023.2.7
ARG CAPSTONE_VERSION=5.0.1

# Install system dependencies (combined in single layer for optimization)
RUN echo "==== Installing system packages ====" && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
    python3=${PYTHON_VERSION}* \
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
    dos2unix \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* \
    && echo "==== System packages installed successfully ===="

# Create non-root user for security
RUN groupadd -r analyst -g 1000 && \
    useradd -r -u 1000 -g analyst -m -d /home/analyst -s /bin/bash analyst && \
    echo "analyst ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/analyst

# Create working directories with proper permissions
RUN mkdir -p /analysis/drivers /analysis/results /analysis/scripts /analysis/logs && \
    chown -R analyst:analyst /analysis

# Create Python virtual environment (avoids externally-managed-environment issues)
RUN echo "==== Creating Python virtual environment ====" && \
    python3 -m venv /opt/venv && \
    chown -R analyst:analyst /opt/venv && \
    echo "==== Virtual environment created at /opt/venv ===="

# Activate venv for all subsequent commands
ENV PATH="/opt/venv/bin:$PATH" \
    VIRTUAL_ENV="/opt/venv" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

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

# Copy IDA installer directory if it exists
# Using separate COPY to handle optional directory gracefully
COPY --chown=analyst:analyst ida_installer /tmp/ida_installer/

# Install IDA Pro if installer is present
RUN echo "==== Checking for IDA Pro installer ====" && \
    if [ -d /tmp/ida_installer ] && [ "$(ls -A /tmp/ida_installer 2>/dev/null | grep -v README)" ]; then \
        echo "IDA installer found, beginning installation..." && \
        mkdir -p /opt/ida && \
        # Handle .run installer
        if ls /tmp/ida_installer/*.run 1> /dev/null 2>&1; then \
            echo "Found .run installer" && \
            chmod +x /tmp/ida_installer/*.run && \
            /tmp/ida_installer/*.run --mode unattended --prefix /opt/ida 2>&1 | tee /analysis/logs/ida_install.log || \
            echo "WARNING: IDA installer failed, continuing without IDA"; \
        # Handle .tar.gz archive
        elif ls /tmp/ida_installer/*.tar.gz 1> /dev/null 2>&1; then \
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
        # Verify installation and set permissions
        if [ -f /opt/ida/ida64 ]; then \
            chmod +x /opt/ida/ida64 && \
            chown -R analyst:analyst /opt/ida && \
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
        rm -rf /tmp/ida_installer; \
    fi

# Set up IDA environment variables
ENV IDA_PATH=/opt/ida \
    PYTHONPATH=/opt/ida/python:$PYTHONPATH \
    PATH=/opt/ida:$PATH \
    TVHEADLESS=1 \
    QT_QPA_PLATFORM=offscreen \
    # WSL specific - handle display
    DISPLAY=:99

# Copy analysis scripts and fix line endings for WSL compatibility
COPY --chown=analyst:analyst scripts/ /analysis/scripts/

# Fix Windows line endings (for WSL compatibility) and set permissions
RUN find /analysis/scripts -type f -exec dos2unix {} \; 2>/dev/null || true && \
    find /analysis/scripts -type f -name "*.py" -exec chmod +x {} \; && \
    find /analysis/scripts -type f -name "*.sh" -exec chmod +x {} \; && \
    chown -R analyst:analyst /analysis

# Switch to non-root user
USER analyst

# Set working directory
WORKDIR /analysis

# Create startup log file
RUN touch /analysis/logs/startup.log

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python3 -c "import pefile; print('OK')" || exit 1

# Expose any ports if needed (none currently)
# EXPOSE 8080

# Default command with logging
CMD ["/bin/bash", "-c", "echo 'Container started at' $(date) | tee -a /analysis/logs/startup.log && /bin/bash"]
