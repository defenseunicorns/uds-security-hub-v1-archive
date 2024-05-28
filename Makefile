# Default target
all: build

# Build the project
build: test 
	go build -o bin/uds-security-hub cmd/main.go

# Run tests
test:
	go test ./... -v -coverprofile=unit-tes-coverage.out

# Lint the code
lint:
	 golangci-lint run ./...

# Clean the build
clean:
	rm -rf bin/

e2e:
	go test -tags e2e ./... -v -coverprofile=coverage.out

.PHONY: all build test lint run clean e2e