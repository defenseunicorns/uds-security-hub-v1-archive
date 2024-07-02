# Table Init

`table-init` is a Go-based utility designed to initialize and migrate database tables using GORM. This tool retrieves configuration from environment variables and performs database migrations to ensure the schema is up-to-date.

The application is designed to be run as a standalone utility or as part of a CI/CD pipeline to ensure that the database schema is consistent across environments.

The database this is designed to work with is Postgres.

## Features

- Retrieves database configuration from environment variables.
- Connects to the database using a configurable connector.
- Performs automatic migrations for specified models.


## Configuration

The application uses the following environment variables for configuration:

- `DB_HOST`: Database host (default: `localhost`)
- `DB_PORT`: Database port (default: `5432`)
- `DB_USER`: Database user (default: `test_user`)
- `DB_PASSWORD`: Database password (default: `test_password`)
- `DB_NAME`: Database name (default: `test_db`)
- `INSTANCE_CONNECTION_NAME`: Instance connection name (optional)

## Usage

To run the application, execute the following command:

```sh
go run cmd/table-init/main.go
```

## Code Overview

### Main Function

The `main` function initializes the context and configuration, then calls the `run` function to perform the database connection and migration.

```go:cmd/table-init/main.go
startLine: 32
endLine: 39
```

## Testing

The project includes unit tests to verify the functionality of environment variable retrieval, configuration, and the `run` function.

To run the tests, use the following command:

```sh
go test ./...
```
