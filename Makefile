# Variables
BINARY_NAME := honeypot
CMD_DIR := cmd/honeypot
BUILD_DIR := build
SRC_DIR := internal
SCRIPTS_DIR := scripts
EBPF_SCRIPT := $(SCRIPTS_DIR)/generate.sh

# Default target
all: build

# Generate eBPF code
generate:
	@echo "Generating eBPF artifacts..."
	@bash $(EBPF_SCRIPT)

# Build the application
build: generate
	@echo "Building the application..."
	@go build -o $(BUILD_DIR)/$(BINARY_NAME) $(CMD_DIR)/main.go

# Run the application
run: build
	@echo "Running the application..."
	@./$(BUILD_DIR)/$(BINARY_NAME)

# Clean up build artifacts
clean:
	@echo "Cleaning up..."
	@rm -rf $(BUILD_DIR)/$(BINARY_NAME)

# Format and lint Go code
fmt:
	@echo "Formatting Go code..."
	@go fmt ./...

lint:
	@echo "Running lint checks..."
	@golangci-lint run

# Run tests
test:
	@echo "Running tests..."
	@go test ./...

# Phony targets (not associated with actual files)
.PHONY: all generate build run clean fmt lint test
