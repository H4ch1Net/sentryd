# Common sentryd tasks. Run `make help` for the list.

.DEFAULT_GOAL := help
DEMO_PCAP := tests/fixtures/portscan.pcap

.PHONY: help install test lint web demo docker-build docker-up docker-down

help:  ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

install:  ## Install dependencies with uv
	uv sync

test:  ## Run the test suite
	uv run pytest

lint:  ## Lint with ruff
	uvx ruff check src tests

web:  ## Serve the web console on http://127.0.0.1:8000
	uv run sentryd web

demo:  ## Replay the bundled port-scan capture into a case
	uv run sentryd replay $(DEMO_PCAP)

docker-build:  ## Build the container image
	docker build -t sentryd .

docker-up:  ## Run the console in Docker (http://localhost:8000)
	docker compose up --build

docker-down:  ## Stop the Docker console
	docker compose down
