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

docker-down:
	docker compose -f docker-compose.yml down || true

test-integration: docker-up
	@if [ -z "$(REGISTRY1_USERNAME)" ] || [ -z "$(REGISTRY1_PASSWORD)" ]; then \
		echo "Error: REGISTRY1_USERNAME or REGISTRY1_PASSWORD is not set"; \
		exit 1; \
	fi
	go test -tags=integration -timeout 90s ./... -v -coverprofile=coverage.out

.PHONY: all build test lint run clean e2e
