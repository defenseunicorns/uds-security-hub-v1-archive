#!/bin/bash

# Check if necessary environment variables are set
required_vars=(GHCR_CREDS REGISTRY1_CREDS GITHUB_TOKEN DOCKER_IO_CREDS DB_NAME DB_USER DB_PASSWORD INSTANCE_CONNECTION_NAME)
for var in "${required_vars[@]}"; do
  if [ -z "${!var}" ]; then
    echo "Environment variable $var is not set. Please set it before running the script."
    exit 1
  fi
done

# Check for required parameters
if [ -z "$1" ] || [ -z "$2" ]; then
  echo "Usage: $0 -n <name> -v <version>"
  exit 1
fi

# Parse parameters
while getopts "n:v:" opt; do
  case ${opt} in
    n)
      NAME=${OPTARG}
      ;;
    v)
      VERSION=${OPTARG}
      ;;
    \?)
      echo "Invalid option: $OPTARG" 1>&2
      exit 1
      ;;
    :)
      echo "Invalid option: $OPTARG requires an argument" 1>&2
      exit 1
      ;;
  esac
done

# Run the Go program
go run cmd/store/main.go \
  -n "${NAME}" \
  -v "${VERSION}" \
  -t "${GITHUB_TOKEN}" \
  --registry-creds "${GHCR_CREDS}" \
  --registry-creds "${REGISTRY1_CREDS}" \
  --registry-creds "${DOCKER_IO_CREDS}" \
  --instance-connection-name "${INSTANCE_CONNECTION_NAME}" \
  --db-name "${DB_NAME}" \
  --db-user "${DB_USER}" \
  --db-password "${DB_PASSWORD}"