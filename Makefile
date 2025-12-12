.PHONY: build run test clean lint install-deps docker-build docker-run

# Build variables
BINARY_NAME=go-server-signer
BUILD_DIR=bin
MAIN_PATH=./cmd/server

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod
GOCLEAN=$(GOCMD) clean

all: build

# Install dependencies
install-deps:
	$(GOMOD) download
	$(GOMOD) tidy

# Build the application
build:
	mkdir -p $(BUILD_DIR)
	$(GOBUILD) -o $(BUILD_DIR)/$(BINARY_NAME) $(MAIN_PATH)

# Build with optimizations for production
build-prod:
	mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux $(GOBUILD) -a -installsuffix cgo -ldflags '-w -s' -o $(BUILD_DIR)/$(BINARY_NAME) $(MAIN_PATH)

# Run the application with config file
run: build
	./$(BUILD_DIR)/$(BINARY_NAME) -config config.json

# Run with environment variables
run-env: build
	./$(BUILD_DIR)/$(BINARY_NAME)

# Run tests
test:
	$(GOTEST) -v ./...

# Run tests with coverage
test-coverage:
	$(GOTEST) -cover -coverprofile=coverage.out ./...
	$(GOCMD) tool cover -html=coverage.out -o coverage.html

# Run tests with race detector
test-race:
	$(GOTEST) -race -v ./...

# Clean build artifacts
clean:
	$(GOCLEAN)
	rm -rf $(BUILD_DIR)
	rm -f coverage.out coverage.html

# Run linter (requires golangci-lint)
lint:
	golangci-lint run

# Format code
fmt:
	$(GOCMD) fmt ./...

# Vet code
vet:
	$(GOCMD) vet ./...

# Build Docker image
docker-build:
	docker build -t stellar-remote-signer:latest .

# Run Docker container
docker-run:
	docker run -p 5003:5003 --env-file .env stellar-remote-signer:latest

# Development mode with auto-reload (requires air)
dev:
	air

# Check for security vulnerabilities
security:
	gosec ./...

help:
	@echo "Available targets:"
	@echo "  install-deps    - Install Go dependencies"
	@echo "  build          - Build the application"
	@echo "  build-prod     - Build with production optimizations"
	@echo "  run            - Build and run with config file"
	@echo "  run-env        - Build and run with environment variables"
	@echo "  test           - Run tests"
	@echo "  test-coverage  - Run tests with coverage report"
	@echo "  test-race      - Run tests with race detector"
	@echo "  clean          - Clean build artifacts"
	@echo "  lint           - Run linter"
	@echo "  fmt            - Format code"
	@echo "  vet            - Run go vet"
	@echo "  docker-build   - Build Docker image"
	@echo "  docker-run     - Run Docker container"
	@echo "  dev            - Run in development mode with auto-reload"
	@echo "  security       - Check for security vulnerabilities"
	@echo "  help           - Show this help message"
