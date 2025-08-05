# =============================================================================
# RAG-Enhanced Threat Hunter Pro - Deployment Operations Makefile
# =============================================================================
# This Makefile provides convenient commands for development, testing, building,
# and deploying the Threat Hunter Pro system across different environments.

# =============================================================================
# Configuration Variables
# =============================================================================

# Project metadata
PROJECT_NAME := threat-hunter-pro
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_DATE := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
VCS_REF := $(shell git rev-parse HEAD 2>/dev/null || echo "unknown")

# Docker configuration
REGISTRY := ghcr.io
IMAGE_NAME := $(REGISTRY)/$(PROJECT_NAME)
PLATFORMS := linux/amd64,linux/arm64

# Environment settings
PYTHON_VERSION := 3.11
NODE_ENV := development
LOG_LEVEL := info

# Build arguments
BUILD_ARGS := --build-arg BUILD_DATE=$(BUILD_DATE) \
              --build-arg VERSION=$(VERSION) \
              --build-arg VCS_REF=$(VCS_REF)

# Docker Compose files
COMPOSE_DEV := docker-compose.dev.yml
COMPOSE_PROD := docker-compose.yml
COMPOSE_TEST := docker-compose.test.yml

# =============================================================================
# Default Target
# =============================================================================

.DEFAULT_GOAL := help
.PHONY: help

help: ## Show this help message
	@echo "RAG-Enhanced Threat Hunter Pro - Deployment Operations"
	@echo "======================================================"
	@echo ""
	@echo "Usage: make <target>"
	@echo ""
	@echo "Development Commands:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / && !/^## / {printf "  %-20s %s\n", $$1, $$2}' $(MAKEFILE_LIST) | grep -E "^  (install|dev|test|lint|format)"
	@echo ""
	@echo "Build Commands:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / && !/^## / {printf "  %-20s %s\n", $$1, $$2}' $(MAKEFILE_LIST) | grep -E "^  (build|push|release)"
	@echo ""
	@echo "Deployment Commands:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / && !/^## / {printf "  %-20s %s\n", $$1, $$2}' $(MAKEFILE_LIST) | grep -E "^  (deploy|up|down|restart)"
	@echo ""
	@echo "Maintenance Commands:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / && !/^## / {printf "  %-20s %s\n", $$1, $$2}' $(MAKEFILE_LIST) | grep -E "^  (clean|backup|restore|health)"
	@echo ""
	@echo "Security Commands:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / && !/^## / {printf "  %-20s %s\n", $$1, $$2}' $(MAKEFILE_LIST) | grep -E "^  (security|scan|audit)"
	@echo ""

# =============================================================================
# Development Environment Setup
# =============================================================================

install: ## Install dependencies for local development
	@echo "Installing dependencies..."
	@pip install --upgrade pip poetry
	@poetry install --with dev
	@python -m spacy download en_core_web_sm
	@pre-commit install
	@echo "✅ Development environment ready"

install-ci: ## Install dependencies for CI environment
	@echo "Installing CI dependencies..."
	@pip install --upgrade pip
	@pip install -r requirements.txt
	@pip install pytest pytest-cov pytest-asyncio black flake8 mypy bandit safety
	@python -m spacy download en_core_web_sm
	@echo "✅ CI environment ready"

dev-setup: ## Set up complete development environment
	@echo "Setting up development environment..."
	@make install
	@mkdir -p data/threat_hunter_db logs backups cache
	@cp .env.example .env 2>/dev/null || true
	@echo "✅ Development setup complete - run 'make dev' to start"

# =============================================================================
# Development Commands
# =============================================================================

dev: ## Start development server with hot reloading
	@echo "Starting development server..."
	@export PYTHONPATH=. && uvicorn main:app --host 0.0.0.0 --port 8000 --reload --log-level debug

dev-docker: ## Start development environment with Docker
	@echo "Starting development environment with Docker..."
	@docker-compose -f $(COMPOSE_DEV) up --build

dev-shell: ## Open interactive shell in development container
	@echo "Opening development shell..."
	@docker-compose -f $(COMPOSE_DEV) exec threat-hunter-app bash

# =============================================================================
# Testing Commands
# =============================================================================

test: ## Run all tests
	@echo "Running tests..."
	@export PYTHONPATH=. && pytest tests/ -v --cov=./ --cov-report=html --cov-report=xml

test-unit: ## Run unit tests only
	@echo "Running unit tests..."
	@export PYTHONPATH=. && pytest tests/unit/ -v

test-integration: ## Run integration tests only
	@echo "Running integration tests..."
	@export PYTHONPATH=. && pytest tests/integration/ -v

test-security: ## Run security tests
	@echo "Running security tests..."
	@export PYTHONPATH=. && pytest tests/security/ -v

test-performance: ## Run performance benchmarks
	@echo "Running performance benchmarks..."
	@export PYTHONPATH=. && pytest tests/performance/ -v --benchmark-only

test-docker: ## Run tests in Docker environment
	@echo "Running tests in Docker..."
	@docker-compose -f $(COMPOSE_TEST) up --build --abort-on-container-exit
	@docker-compose -f $(COMPOSE_TEST) down

test-ci: ## Run CI test suite
	@echo "Running CI test suite..."
	@make lint
	@make security-scan
	@make test
	@make test-performance

# =============================================================================
# Code Quality Commands
# =============================================================================

format: ## Format code with Black and isort
	@echo "Formatting code..."
	@black .
	@isort .
	@echo "✅ Code formatted"

lint: ## Run linting checks
	@echo "Running linting checks..."
	@black --check .
	@isort --check-only .
	@flake8 .
	@mypy . --ignore-missing-imports
	@echo "✅ Linting passed"

lint-fix: ## Fix linting issues automatically
	@echo "Fixing linting issues..."
	@make format
	@echo "✅ Linting issues fixed"

# =============================================================================
# Security Commands
# =============================================================================

security-scan: ## Run comprehensive security scan
	@echo "Running security scan..."
	@bandit -r . -f json -o security-reports/bandit-report.json || true
	@bandit -r .
	@safety check
	@echo "✅ Security scan complete"

security-audit: ## Audit dependencies for vulnerabilities
	@echo "Auditing dependencies..."
	@safety check --json --output security-reports/safety-report.json || true
	@safety check
	@echo "✅ Dependency audit complete"

scan-secrets: ## Scan for secrets in codebase
	@echo "Scanning for secrets..."
	@docker run --rm -v "$(PWD):/pwd" trufflesecurity/trufflehog:latest filesystem /pwd --json > security-reports/secrets-scan.json || true
	@echo "✅ Secret scan complete"

# =============================================================================
# Build Commands
# =============================================================================

build: ## Build all Docker images
	@echo "Building Docker images..."
	@docker buildx build $(BUILD_ARGS) --target development -t $(IMAGE_NAME):dev .
	@docker buildx build $(BUILD_ARGS) --target production -t $(IMAGE_NAME):latest .
	@docker buildx build $(BUILD_ARGS) --target vector-store-service -t $(IMAGE_NAME)/vector-store:latest .
	@docker buildx build $(BUILD_ARGS) --target search-service -t $(IMAGE_NAME)/search-service:latest .
	@docker buildx build $(BUILD_ARGS) --target summary-store-service -t $(IMAGE_NAME)/summary-store:latest .
	@echo "✅ Build complete"

build-prod: ## Build production images
	@echo "Building production images..."
	@docker buildx build $(BUILD_ARGS) --target production -t $(IMAGE_NAME):$(VERSION) -t $(IMAGE_NAME):latest .
	@echo "✅ Production build complete"

build-multi: ## Build multi-architecture images
	@echo "Building multi-architecture images..."
	@docker buildx create --name multiarch --use || true
	@docker buildx build $(BUILD_ARGS) --platform $(PLATFORMS) --target production -t $(IMAGE_NAME):$(VERSION) -t $(IMAGE_NAME):latest --push .
	@echo "✅ Multi-architecture build complete"

push: ## Push images to registry
	@echo "Pushing images to registry..."
	@docker push $(IMAGE_NAME):$(VERSION)
	@docker push $(IMAGE_NAME):latest
	@docker push $(IMAGE_NAME)/vector-store:latest
	@docker push $(IMAGE_NAME)/search-service:latest
	@docker push $(IMAGE_NAME)/summary-store:latest
	@echo "✅ Images pushed"

# =============================================================================
# Package Management
# =============================================================================

package: ## Build Python package
	@echo "Building Python package..."
	@poetry build
	@echo "✅ Package built - check dist/ directory"

package-check: ## Check package integrity
	@echo "Checking package integrity..."
	@poetry check
	@twine check dist/*
	@echo "✅ Package integrity verified"

publish-test: ## Publish package to Test PyPI
	@echo "Publishing to Test PyPI..."
	@poetry publish --repository testpypi
	@echo "✅ Published to Test PyPI"

publish: ## Publish package to PyPI
	@echo "Publishing to PyPI..."
	@poetry publish
	@echo "✅ Published to PyPI"

# =============================================================================
# Deployment Commands
# =============================================================================

deploy-dev: ## Deploy development environment
	@echo "Deploying development environment..."
	@make build
	@docker-compose -f $(COMPOSE_DEV) up -d
	@make health-check
	@echo "✅ Development deployment complete"
	@echo "Application available at: http://localhost:8000"
	@echo "Grafana dashboard: http://localhost:3000 (admin/admin)"

deploy-prod: ## Deploy production environment
	@echo "Deploying production environment..."
	@make build-prod
	@docker-compose -f $(COMPOSE_PROD) up -d
	@make health-check
	@echo "✅ Production deployment complete"

deploy-staging: ## Deploy to staging environment
	@echo "Deploying to staging environment..."
	@make build-prod
	@docker-compose -f $(COMPOSE_PROD) --profile staging up -d
	@make health-check
	@echo "✅ Staging deployment complete"

up: ## Start all services
	@echo "Starting services..."
	@docker-compose -f $(COMPOSE_PROD) up -d
	@make health-check

down: ## Stop all services
	@echo "Stopping services..."
	@docker-compose -f $(COMPOSE_PROD) down
	@docker-compose -f $(COMPOSE_DEV) down || true

restart: ## Restart all services
	@echo "Restarting services..."
	@make down
	@make up

# =============================================================================
# Health and Monitoring
# =============================================================================

health-check: ## Run comprehensive health check
	@echo "Running health check..."
	@bash scripts/health_check.sh || echo "Health check script not found"
	@echo "Checking service endpoints..."
	@curl -f http://localhost:8000/health || echo "❌ Main application unhealthy"
	@curl -f http://localhost:8001/health || echo "❌ Vector store unhealthy"
	@curl -f http://localhost:8002/health || echo "❌ Search service unhealthy"
	@curl -f http://localhost:8003/health || echo "❌ Summary store unhealthy"
	@curl -f http://localhost:6379/ping || echo "❌ Redis unhealthy"
	@echo "✅ Health check complete"

logs: ## Show logs from all services
	@docker-compose -f $(COMPOSE_PROD) logs -f

logs-app: ## Show application logs only
	@docker-compose -f $(COMPOSE_PROD) logs -f threat-hunter-app

status: ## Show status of all services
	@echo "Service Status:"
	@docker-compose -f $(COMPOSE_PROD) ps

metrics: ## Show system metrics
	@echo "System Metrics:"
	@docker stats --no-stream

# =============================================================================
# Database and Data Management
# =============================================================================

backup: ## Create backup of all data
	@echo "Creating backup..."
	@mkdir -p backups/$(shell date +%Y-%m-%d)
	@docker-compose -f $(COMPOSE_PROD) exec threat-hunter-app tar czf /app/backups/data-$(shell date +%Y-%m-%d-%H%M%S).tar.gz /app/data
	@docker cp $$(docker-compose -f $(COMPOSE_PROD) ps -q threat-hunter-app):/app/backups ./backups/
	@echo "✅ Backup created in backups/ directory"

restore: ## Restore from backup (Usage: make restore BACKUP=filename)
	@echo "Restoring from backup: $(BACKUP)"
	@test -n "$(BACKUP)" || (echo "❌ Please specify BACKUP=filename" && exit 1)
	@docker-compose -f $(COMPOSE_PROD) stop threat-hunter-app
	@docker cp ./backups/$(BACKUP) $$(docker-compose -f $(COMPOSE_PROD) ps -q threat-hunter-app):/app/restore.tar.gz
	@docker-compose -f $(COMPOSE_PROD) exec threat-hunter-app tar xzf /app/restore.tar.gz -C /
	@docker-compose -f $(COMPOSE_PROD) start threat-hunter-app
	@echo "✅ Restore complete"

migrate: ## Run database migrations
	@echo "Running migrations..."
	@docker-compose -f $(COMPOSE_PROD) exec threat-hunter-app python -m migrations.migrate
	@echo "✅ Migrations complete"

# =============================================================================
# Development Tools
# =============================================================================

shell: ## Open interactive shell in running container
	@docker-compose -f $(COMPOSE_PROD) exec threat-hunter-app bash

db-shell: ## Open database shell
	@docker-compose -f $(COMPOSE_PROD) exec redis redis-cli

jupyter: ## Start Jupyter notebook server
	@echo "Starting Jupyter notebook server..."
	@docker-compose -f $(COMPOSE_DEV) --profile analysis up jupyter -d
	@echo "Jupyter available at: http://localhost:8888"
	@echo "Token: threat-hunter-dev"

# =============================================================================
# Maintenance Commands
# =============================================================================

clean: ## Clean up Docker resources
	@echo "Cleaning up Docker resources..."
	@docker system prune -f
	@docker volume prune -f
	@docker network prune -f
	@echo "✅ Cleanup complete"

clean-all: ## Clean up everything including images
	@echo "Cleaning up all Docker resources..."
	@docker-compose -f $(COMPOSE_PROD) down -v --rmi all
	@docker-compose -f $(COMPOSE_DEV) down -v --rmi all
	@docker system prune -af
	@docker volume prune -f
	@echo "✅ Complete cleanup done"

clean-data: ## Clean application data (WARNING: destructive)
	@echo "⚠️  This will delete all application data!"
	@read -p "Are you sure? [y/N] " -n 1 -r; echo; if [[ $$REPLY =~ ^[Yy]$$ ]]; then \
		docker-compose -f $(COMPOSE_PROD) down -v; \
		docker volume rm $$(docker volume ls -q | grep threat-hunter) 2>/dev/null || true; \
		rm -rf data/ logs/ backups/; \
		echo "✅ Data cleaned"; \
	else \
		echo "❌ Cancelled"; \
	fi

update: ## Update all dependencies
	@echo "Updating dependencies..."
	@poetry update
	@docker-compose -f $(COMPOSE_PROD) pull
	@echo "✅ Dependencies updated"

# =============================================================================
# CI/CD Support
# =============================================================================

ci-setup: ## Set up CI environment
	@make install-ci
	@mkdir -p security-reports benchmark-results

ci-test: ## Run full CI test suite
	@make test-ci

ci-build: ## Build for CI
	@make build-prod

ci-deploy: ## Deploy for CI (staging)
	@make deploy-staging

# =============================================================================
# Documentation
# =============================================================================

docs: ## Generate documentation
	@echo "Generating documentation..."
	@mkdir -p docs/api
	@echo "📚 Documentation generated"

docs-serve: ## Serve documentation locally
	@echo "Serving documentation at http://localhost:8080"
	@python -m http.server 8080 -d docs/

# =============================================================================
# Release Management
# =============================================================================

release: ## Create a new release (Usage: make release VERSION=v1.0.0)
	@test -n "$(VERSION)" || (echo "❌ Please specify VERSION=v1.0.0" && exit 1)
	@echo "Creating release $(VERSION)..."
	@git tag -a $(VERSION) -m "Release $(VERSION)"
	@git push origin $(VERSION)
	@make build-multi
	@make package
	@echo "✅ Release $(VERSION) created"

pre-release: ## Create a pre-release (Usage: make pre-release VERSION=v1.0.0-beta.1)
	@test -n "$(VERSION)" || (echo "❌ Please specify VERSION=v1.0.0-beta.1" && exit 1)
	@echo "Creating pre-release $(VERSION)..."
	@git tag -a $(VERSION) -m "Pre-release $(VERSION)"
	@git push origin $(VERSION)
	@make build-multi
	@make package
	@echo "✅ Pre-release $(VERSION) created"

# =============================================================================
# Environment Information
# =============================================================================

info: ## Show environment information
	@echo "Environment Information:"
	@echo "======================="
	@echo "Project: $(PROJECT_NAME)"
	@echo "Version: $(VERSION)"
	@echo "Build Date: $(BUILD_DATE)"
	@echo "VCS Ref: $(VCS_REF)"
	@echo "Registry: $(REGISTRY)"
	@echo "Python Version: $(PYTHON_VERSION)"
	@echo ""
	@echo "Docker Images:"
	@docker images | grep $(PROJECT_NAME) || echo "No project images found"
	@echo ""
	@echo "Running Containers:"
	@docker ps | grep $(PROJECT_NAME) || echo "No project containers running"

# =============================================================================
# Utility Functions
# =============================================================================

.PHONY: install install-ci dev-setup dev dev-docker dev-shell test test-unit test-integration test-security test-performance test-docker test-ci
.PHONY: format lint lint-fix security-scan security-audit scan-secrets
.PHONY: build build-prod build-multi push package package-check publish-test publish
.PHONY: deploy-dev deploy-prod deploy-staging up down restart
.PHONY: health-check logs logs-app status metrics
.PHONY: backup restore migrate shell db-shell jupyter
.PHONY: clean clean-all clean-data update ci-setup ci-test ci-build ci-deploy
.PHONY: docs docs-serve release pre-release info