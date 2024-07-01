# Contributing to the Project

Thank you for contributing! Here are some guidelines to help you get started.

## Getting Started

1. Fork the repository.
2. Clone your forked repository.
3. Create a new branch for your feature or bugfix.

## Code Style

Follow the standard Go coding style. We use several tools to ensure code quality.

### Required Tools

- `gci`
- `gofmt`
- `goimports`
- `golangci-lint`
- `docker` [Docker Installation Guide](https://docs.docker.com/get-docker/)
- `trivy` [Trivy Installation Guide](https://aquasecurity.github.io/trivy/v0.53/getting-started/installation/)

### Installation

Install the required tools:

```sh
go install github.com/daixiang0/gci@latest
go install golang.org/x/tools/cmd/goimports@latest
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
```

### Formatting and Imports

Ensure your code is formatted and imports are organized:

```sh
gci write --skip-generated -s standard -s default -s "prefix(github.com/defenseunicorns/uds-security-hub)" "$full_path"
gofmt -w "$full_path"
# Optionally, use gofumpt for stricter formatting
# gofumpt -w "$full_path"
goimports -w "$full_path"
```

### Linting

Ensure your code passes all lint checks:

```sh
make lint
```

## Running Tests

Run tests using Docker and Trivy:

```sh
make test-integration
```

## Submitting Changes

1. Ensure your code passes all tests and lint checks.
2. Commit your changes with a clear message.
3. Push your branch to your forked repository.
4. Open a pull request to the main repository.

## Code Review

All submissions require review. Ensure your pull request:

- Is clear and concise.
- Includes a description of the changes.
- References any related issues.

Thank you for your contributions!
