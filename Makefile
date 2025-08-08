# Makefile for GroundGo

# Configuration
APP_NAME := GroundGo
GO := go
GO_FILES := $(shell find . -name "*.go" -not -path "./vendor/*")
TEMPL_FILES := $(shell find . -name "*.templ" -not -path "./vendor/*")

# Colors
COLOR_RESET := \033[0m
COLOR_GREEN := \033[32m
COLOR_BLUE := \033[34m
COLOR_CYAN := \033[36m

.PHONY: all
all: help

.PHONY: help
help: ## Display this help screen
	@echo "$(COLOR_CYAN)Available commands:$(COLOR_RESET)"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "$(COLOR_GREEN)%-20s$(COLOR_RESET) %s\n", $$1, $$2}'

.PHONY: dev
dev: ## Start development environment
	@echo "$(COLOR_BLUE)Starting development environment...$(COLOR_RESET)"
	@make watch-templ

.PHONY: build
build: generate ## Build the application
	@echo "$(COLOR_BLUE)Building application...$(COLOR_RESET)"
	$(GO) build -o bin/$(APP_NAME) ./cmd/.

.PHONY: run
run: generate ## Run the application
	@echo "$(COLOR_BLUE)Running application...$(COLOR_RESET)"
	$(GO) run ./cmd/main.go

.PHONY: generate
generate: sqlc-generate templ-generate ## Generate all code (templ templates, etc.)

.PHONY: templ-generate
templ-generate: ## Generate code from templ templates
	@echo "$(COLOR_BLUE)Generating templ code...$(COLOR_RESET)"
	$(GO) tool templ generate

.PHONY: watch-templ
watch-templ: ## Watch templ files for changes and regenerate
	@echo "$(COLOR_BLUE)Watching templ files for changes...$(COLOR_RESET)"
	$(GO) tool templ generate --watch --proxy="http://localhost:8080" --cmd="go run cmd/main.go"

.PHONY: sqlc-generate
sqlc-generate: ## Generate code from templ templates
	@echo "$(COLOR_BLUE)Generating sqlc code...$(COLOR_RESET)"
	$(GO) tool sqlc generate --file database/sqlite_sqlc.yaml

.PHONY: test
test: ## Run tests
	@echo "$(COLOR_BLUE)Running tests...$(COLOR_RESET)"
	$(GO) test -race ./...

.PHONY: fmt
fmt: ## Format code
	@echo "$(COLOR_BLUE)Formatting code...$(COLOR_RESET)"
	$(GO) fmt ./...

.PHONY: lint
lint: ## Run linters
	@echo "$(COLOR_BLUE)Running linters...$(COLOR_RESET)"
	$(GO) tool golangci-lint run ./...

.PHONY: clean
clean: ## Clean build artifacts
	@echo "$(COLOR_BLUE)Cleaning build artifacts...$(COLOR_RESET)"
	rm -rf bin/
	rm -f **/*_templ.go

.PHONY: install-tools
install-tools: ## Install development tools
	@echo "$(COLOR_BLUE)Installing development tools...$(COLOR_RESET)"
	$(GO) get -tool github.com/a-h/templ/cmd/templ@latest
	$(GO) get -tool github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	$(GO) get -tool github.com/golang-migrate/migrate/v4/cmd/migrate@latest
	$(GO) get -tool github.com/sqlc-dev/sqlc/cmd/sqlc@latest

.PHONY: deps
deps: ## Install dependencies
	@echo "$(COLOR_BLUE)Installing dependencies...$(COLOR_RESET)"
	$(GO) mod download
	$(GO) mod tidy