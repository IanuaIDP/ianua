# Start Ianua on this machine with one command: `make start`.
# The backend runs in Docker; the dashboard runs locally, so edits show at once.
# `make help` lists everything. The `justfile` holds the deeper developer recipes.

COMPOSE_DIR := deploy/compose
ENV_FILE := $(COMPOSE_DIR)/.env.local
DASHBOARD_ENV := dashboard/.env.local
COMPOSE := docker compose -p ianua-local --env-file .env.local -f docker-compose.yml -f docker-compose.local.yml
SERVICES := ianua zero mailpit
SERVER_IMAGE := ianua-local/ianua-server:local
GATEWAY_IMAGE := ianua-local/ianua-zero:local
API := http://127.0.0.1:8080/api/v1

.DEFAULT_GOAL := help
.PHONY: help doctor env images up owner credentials install dev start stop down reset logs status test scenarios lint fmt audit check

help: ## Show this list
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F ':.*## ' '{printf "  make %-13s %s\n", $$1, $$2}'

doctor: ## Check that the tools Ianua needs are installed
	@for tool in docker node npm openssl curl; do \
		command -v $$tool >/dev/null || { echo "Missing: $$tool"; exit 1; }; \
	done
	@docker info >/dev/null 2>&1 || { echo "Docker is installed but not running."; exit 1; }
	@echo "All set."

env: ## Create local settings with fresh secrets (kept if they exist)
	@if [ -f $(ENV_FILE) ]; then \
		echo "Keeping $(ENV_FILE)"; \
	else \
		umask 077; \
		{ \
			echo "IANUA_DASHBOARD_HOST=localhost"; \
			echo "IANUA_API_HOST=localhost"; \
			echo "IANUA_APPS_DOMAIN=apps.ianua.test"; \
			echo "IANUA_CONNECTOR_HOST=connect.ianua.test"; \
			echo "PUBLIC_IP="; \
			echo "INSTALL_ORGANIZATION_NAME=Local Company"; \
			echo "INSTALL_TENANT_NAME=Main"; \
			echo "INSTALL_OWNER_EMAIL=owner@ianua.test"; \
			echo "INSTALL_OWNER_NAME=Local Owner"; \
			echo "INSTALL_OWNER_PASSWORD=Local$$(openssl rand -hex 8)A1"; \
			echo "TRUSTED_DOMAINS=ianua.test"; \
			echo "ACME_EMAIL=owner@ianua.test"; \
			for name in POSTGRES_PASSWORD APP_DATABASE_PASSWORD AUDIT_PURGE_DATABASE_PASSWORD \
				GATEWAY_DATABASE_PASSWORD HMAC_SECRET ENCRYPTION_KEY EVENT_SIGNING_SECRET; do \
				echo "$$name=$$(openssl rand -hex 32)"; \
			done; \
			echo "EMAIL_FROM=ianua@ianua.test"; \
			echo "SMTP_HOST=mailpit"; \
			echo "SMTP_PORT=1025"; \
			echo "SMTP_TLS=none"; \
			echo "SMTP_USERNAME="; \
			echo "SMTP_PASSWORD="; \
			echo "IANUA_IMAGE_REGISTRY=ianua-local"; \
			echo "IANUA_VERSION=local"; \
		} > $(ENV_FILE); \
		echo "Wrote $(ENV_FILE)"; \
	fi
	@if [ ! -f $(DASHBOARD_ENV) ]; then \
		{ \
			echo "NEXT_PUBLIC_API_URL=/api"; \
			echo "NEXT_PUBLIC_WS_URL=ws://127.0.0.1:8080/api/v1"; \
			echo "API_URL=$(API)"; \
			echo "DEPLOYMENT=self_hosted"; \
		} > $(DASHBOARD_ENV); \
		echo "Wrote $(DASHBOARD_ENV)"; \
	fi

images: ## Build the backend images (slow the first time)
	docker build -f docker/Dockerfile --target server --build-arg CLOUD_CLIS=none -t $(SERVER_IMAGE) .
	docker build -f docker/Dockerfile --target zero -t $(GATEWAY_IMAGE) .

up: env ## Start the backend, building its images if there are none
	@docker image inspect $(SERVER_IMAGE) >/dev/null 2>&1 && docker image inspect $(GATEWAY_IMAGE) >/dev/null 2>&1 || $(MAKE) images
	cd $(COMPOSE_DIR) && $(COMPOSE) up -d --no-build --pull missing $(SERVICES)
	@$(MAKE) --no-print-directory owner

owner: ## Confirm the first owner's address, once
	@token=$$(cd $(COMPOSE_DIR) && $(COMPOSE) logs --no-color install 2>/dev/null | grep -oE 'rt_[a-z0-9]+' | tail -1); \
	if [ -n "$$token" ]; then \
		curl -s -o /dev/null -m 10 -X POST -H 'content-type: application/json' \
			-d "{\"token\":\"$$token\"}" $(API)/users/confirm-installer || true; \
	fi

credentials: ## Show how to sign in
	@echo "Dashboard:  http://app.localhost:3000  (run 'make dev' first)"
	@echo "Email:      $$(grep '^INSTALL_OWNER_EMAIL=' $(ENV_FILE) | cut -d= -f2)"
	@echo "Password:   $$(grep '^INSTALL_OWNER_PASSWORD=' $(ENV_FILE) | cut -d= -f2)"
	@echo "Mail:       http://127.0.0.1:8025"
	@echo "A new device signs in with a mailed link. Copy it, and change https:// to http://."

install: ## Install the dashboard's packages
	npm --prefix dashboard install

dev: env ## Run the dashboard, reloading as you edit
	@[ -d dashboard/node_modules ] || $(MAKE) --no-print-directory install
	npm --prefix dashboard run dev

start: doctor up credentials dev ## Do everything: backend, sign-in details, dashboard

stop: ## Stop the backend and keep its data
	cd $(COMPOSE_DIR) && $(COMPOSE) stop

down: ## Remove the backend's containers and keep its data
	cd $(COMPOSE_DIR) && $(COMPOSE) down

reset: ## Delete the backend, all its data and the local settings
	@printf 'This deletes all local Ianua data. Type yes to go on: '; read answer; [ "$$answer" = yes ]
	cd $(COMPOSE_DIR) && $(COMPOSE) down -v
	rm -f $(ENV_FILE)

logs: ## Follow the backend's logs
	cd $(COMPOSE_DIR) && $(COMPOSE) logs -f ianua zero

status: ## Show what is running
	cd $(COMPOSE_DIR) && $(COMPOSE) ps

test: ## Run the tests, without the end-to-end scenarios
	SQLX_OFFLINE=true cargo nextest run --workspace --exclude ianua-scenarios

scenarios: ## Run the end-to-end scenarios
	SQLX_OFFLINE=true cargo nextest run -p ianua-server -p ianua-scenarios

lint: ## Run the strict lint
	SQLX_OFFLINE=true cargo clippy --all-targets --all-features -- -D warnings

fmt: ## Format the Rust code
	cargo +nightly fmt --all

audit: ## Run the house rules
	cargo run --release -p ianua-audit -- check

check: fmt lint test audit ## Run every check before a pull request
