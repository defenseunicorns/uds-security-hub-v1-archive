# Default target
all: build

# Build the project
build:
	go build -o bin/uds-security-hub main.go

# Lint the code
lint:
	 golangci-lint run ./...

# Clean the build
clean:
	rm -rf bin/

# Run the docker compose
docker-up: docker-down
	docker compose -f docker-compose.yml up -d
	sleep 5

table-init: docker-up
	@echo "Initializing tables..."
	@go run ./cmd/table-init/main.go || { echo "Failed to initialize tables"; exit 1; }

docker-down:
	docker compose -f docker-compose.yml down || true

test-integration:
	@if [ -z "$(GITHUB_TOKEN)" ] || [ -z "$(GHCR_CREDS)" ] || [ -z "$(REGISTRY1_CREDS)" ]; then \
		echo "Error: GITHUB_TOKEN, GHCR_CREDS, or REGISTRY1_CREDS is not set"; \
		exit 1; \
	fi
	go test -tags=integration -timeout 90s ./... -v -coverprofile=coverage.out

.PHONY: all build test lint run clean e2e table-init
