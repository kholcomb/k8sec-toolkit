# K8Sec Toolkit Makefile

# Build variables
BINARY_NAME=k8sec-toolkit
VERSION?=dev
GITCOMMIT?=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILDTIME?=$(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
LDFLAGS=-X main.Version=$(VERSION) -X main.GitCommit=$(GITCOMMIT) -X main.BuildTime=$(BUILDTIME)

# Go variables
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod

# Build directory
BUILD_DIR=build

.PHONY: all build clean test deps run help pre-commit-install pre-commit-run lint security-check

all: clean deps build

## build: Build the binary
build:
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	$(GOBUILD) -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/k8sec-toolkit
	@echo "Binary built: $(BUILD_DIR)/$(BINARY_NAME)"

## clean: Clean build artifacts
clean:
	@echo "Cleaning..."
	$(GOCLEAN)
	@rm -rf $(BUILD_DIR)

## test: Run tests
test:
	@echo "Running tests..."
	$(GOTEST) -v ./...

## deps: Download dependencies
deps:
	@echo "Downloading dependencies..."
	$(GOMOD) download
	$(GOMOD) tidy

## run: Build and run the binary
run: build
	@echo "Running $(BINARY_NAME)..."
	./$(BUILD_DIR)/$(BINARY_NAME)

## install: Install the binary
install: build
	@echo "Installing $(BINARY_NAME)..."
	@cp $(BUILD_DIR)/$(BINARY_NAME) /usr/local/bin/

## dev: Build for development (with debug info)
dev:
	@echo "Building $(BINARY_NAME) for development..."
	@mkdir -p $(BUILD_DIR)
	$(GOBUILD) -gcflags="all=-N -l" -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/k8sec-toolkit

## validate: Run validation checks
validate: deps
	@echo "Running validation..."
	@$(GOCMD) fmt ./...
	@$(GOCMD) vet ./...
	@$(GOMOD) verify

## docker: Build Docker image (future)
docker:
	@echo "Docker build not implemented yet"

## release: Build for multiple platforms (future)
release:
	@echo "Cross-platform build not implemented yet"

## pre-commit-install: Install pre-commit hooks
pre-commit-install:
	@echo "Installing pre-commit hooks..."
	@command -v pre-commit >/dev/null 2>&1 || { echo "pre-commit not found. Install with: pip install pre-commit"; exit 1; }
	@pre-commit install
	@pre-commit install --hook-type commit-msg
	@echo "Pre-commit hooks installed successfully"

## pre-commit-run: Run pre-commit hooks on all files
pre-commit-run:
	@echo "Running pre-commit hooks on all files..."
	@pre-commit run --all-files

## lint: Run comprehensive linting
lint: validate
	@echo "Running comprehensive linting..."
	@command -v golangci-lint >/dev/null 2>&1 || { echo "golangci-lint not found. Install from: https://golangci-lint.run/usage/install/"; exit 1; }
	@golangci-lint run --timeout=5m

## security-check: Run security checks
security-check:
	@echo "Running security checks..."
	@command -v gosec >/dev/null 2>&1 || { echo "Installing gosec..."; $(GOGET) github.com/securecodewarrior/gosec/v2/cmd/gosec@latest; }
	@gosec ./...
	@echo "Security checks completed"

## ci-check: Run all CI checks locally
ci-check: deps test lint security-check
	@echo "All CI checks passed"

## help: Show this help
help:
	@echo "Available commands:"
	@sed -n 's/^##//p' $(MAKEFILE_LIST) | sort

# Default target
.DEFAULT_GOAL := help
