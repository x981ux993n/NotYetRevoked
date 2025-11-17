FROM ubuntu:22.04

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    wget \
    git \
    unzip \
    file \
    binutils \
    curl \
    ca-certificates \
    gnupg \
    lsb-release \
    && rm -rf /var/lib/apt/lists/*

# Install pefile for PE parsing
RUN pip3 install --no-cache-dir pefile capstone pyelftools

# Create working directories
RUN mkdir -p /analysis/drivers /analysis/results /analysis/scripts /ida

# Set up environment for IDA
ENV IDA_PATH=/ida
ENV PYTHONPATH=/ida/python:$PYTHONPATH

# Copy analysis scripts
COPY scripts/ /analysis/scripts/

# Set working directory
WORKDIR /analysis

# Default command
CMD ["/bin/bash"]
