.PHONY: help setup build up down logs shell analyze screen clean test

help:
	@echo "NotYetRevoked - Loldriver Analysis Pipeline"
	@echo ""
	@echo "Available commands:"
	@echo "  make setup       - Initial setup (run once)"
	@echo "  make build       - Build Docker images"
	@echo "  make up          - Start containers"
	@echo "  make down        - Stop containers"
	@echo "  make logs        - View container logs"
	@echo "  make shell       - Open shell in analyzer container"
	@echo "  make analyze     - Run full analysis pipeline"
	@echo "  make screen      - Run import screening only"
	@echo "  make clean       - Clean up old results"
	@echo "  make test        - Run test analysis"
	@echo ""
	@echo "Tailscale commands:"
	@echo "  make tailscale-start   - Start Tailscale"
	@echo "  make tailscale-stop    - Stop Tailscale"
	@echo "  make tailscale-status  - Check Tailscale status"

setup:
	@echo "Running initial setup..."
	@chmod +x scripts/*.sh
	@./scripts/setup.sh

build:
	@echo "Building Docker images..."
	@docker-compose build

up:
	@echo "Starting containers..."
	@docker-compose up -d
	@echo "Containers started. Use 'make logs' to view output"

down:
	@echo "Stopping containers..."
	@docker-compose down

restart: down up

logs:
	@docker-compose logs -f ida-analyzer

shell:
	@docker-compose exec ida-analyzer /bin/bash

analyze:
	@echo "Running full analysis pipeline..."
	@./scripts/run_analysis.sh

screen:
	@echo "Running import screening..."
	@docker-compose exec ida-analyzer python3 /analysis/scripts/import_screener.py \
		/analysis/drivers \
		-o /analysis/results/screening_$$(date +%Y%m%d_%H%M%S).json

clean:
	@echo "Cleaning up old results..."
	@find results/ -name "*.i64" -delete 2>/dev/null || true
	@find results/ -name "*.idb" -delete 2>/dev/null || true
	@find results/ -type d -name "run_*" -mtime +7 -exec rm -rf {} + 2>/dev/null || true
	@echo "Cleanup complete"

clean-all: clean
	@echo "Removing all results..."
	@rm -rf results/*
	@echo "All results removed"

test:
	@echo "Running test analysis..."
	@if [ ! -d "drivers" ] || [ -z "$$(ls -A drivers 2>/dev/null)" ]; then \
		echo "No drivers found in ./drivers directory"; \
		echo "Please add .sys files to ./drivers directory"; \
		exit 1; \
	fi
	@docker-compose up -d
	@docker-compose exec ida-analyzer python3 /analysis/scripts/import_screener.py \
		/analysis/drivers --quiet
	@echo "Test complete"

tailscale-start:
	@./scripts/tailscale_setup.sh start

tailscale-stop:
	@./scripts/tailscale_setup.sh stop

tailscale-status:
	@./scripts/tailscale_setup.sh status

# Development helpers
dev-screen:
	@docker-compose exec ida-analyzer python3 -c "import pefile; print('pefile version:', pefile.__version__)"

dev-ida-test:
	@docker-compose exec ida-analyzer test -f /ida/ida64 && echo "IDA found" || echo "IDA not found"

status:
	@echo "=== Container Status ==="
	@docker-compose ps
	@echo ""
	@echo "=== Driver Count ==="
	@find drivers -name "*.sys" 2>/dev/null | wc -l | xargs echo "Drivers in queue:"
	@echo ""
	@echo "=== Recent Results ==="
	@ls -lt results/ 2>/dev/null | head -5 || echo "No results yet"
