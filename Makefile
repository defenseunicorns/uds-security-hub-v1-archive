# Default target
all: build

# Build the project
build: test 
	go build -o bin/uds-security-hub cmd/main.go

# Run tests
test:
	go test ./... -v

# Lint the code
lint:
	 golangci-lint run ./...

# Clean the build
clean:
	rm -rf bin/

.PHONY: all build test lint run clean