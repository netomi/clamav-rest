.PHONY: build test clean docker run lint help

# Binary name
BINARY=clamav-rest

# Build the binary
build:
	go build -o $(BINARY) .

# Run tests
test:
	go test -v ./...

# Run tests with coverage
coverage:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

# Clean build artifacts
clean:
	rm -f $(BINARY) coverage.out coverage.html

# Build Docker image
docker:
	docker build -t $(BINARY) .

# Run locally (requires clamd)
run: build
	./$(BINARY)

# Run linter (requires golangci-lint)
lint:
	golangci-lint run

# Format code
fmt:
	go fmt ./...

# Check for issues
vet:
	go vet ./...

# Default target
.DEFAULT_GOAL := help

# Show help
help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  build     Build the binary"
	@echo "  test      Run tests"
	@echo "  coverage  Run tests with coverage report"
	@echo "  clean     Remove build artifacts"
	@echo "  docker    Build Docker image"
	@echo "  run       Build and run locally (requires clamd)"
	@echo "  lint      Run golangci-lint"
	@echo "  fmt       Format code"
	@echo "  vet       Check for issues"
