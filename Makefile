.PHONY: help setup keys up down logs reset-db demo test gauntlet verify

help: ## Show this help menu
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

setup: ## Copy .env.example to .env if it doesn't exist
	@if [ ! -f .env ]; then cp .env.example .env; echo "Created .env from .env.example"; else echo ".env already exists"; fi

keys: ## Generate Ed25519 keys for the ledger (if not exists)
	@echo "Generating Ed25519 keys... (Simulation for now)"
	@mkdir -p keys
	@if [ ! -f keys/nexus_ed25519 ]; then touch keys/nexus_ed25519 keys/nexus_ed25519.pub; echo "Keys created in /keys"; else echo "Keys already exist"; fi

up: ## Start all services via Docker Compose
	docker compose up --build -d

down: ## Stop all services
	docker compose down

logs: ## Tail logs for all services
	docker compose logs -f

reset-db: ## Wipe the SQLite database and start fresh
	docker compose down -v
	rm -f nexus_secure.db

demo: reset-db setup keys up ## Full demo reset: wipe DB, setup env, generate keys, and start

test: ## Run unit tests (excluding live paypal)
	pytest -m "not live"

gauntlet: ## Run the security gauntlet in demo mode
	python gauntlet.py

verify: ## Run the independent ledger verifier
	python nexus-verify.py