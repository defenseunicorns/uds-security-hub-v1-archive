#!/bin/bash

# This script runs a Go program to scan a specified number of versions of a given name.
# It requires several environment variables to be set and accepts parameters for the number of versions to scan.

# Usage:
#   ./scan.sh [-f <file_with_names>] [-v <number_of_versions_to_scan>]
#
# Parameters:
#   -f <file_with_names>             : The file containing the list of names to scan. This parameter is optional and defaults to names.txt if not provided.
#   -v <number_of_versions_to_scan>  : The number of versions to scan. This parameter is optional and defaults to 2 if not provided.
#
# Environment Variables:
#   GHCR_CREDS                : Credentials for GitHub Container Registry.
#   REGISTRY1_CREDS           : Credentials for the first registry.
#   GITHUB_TOKEN              : GitHub token for authentication.
#   DOCKER_IO_CREDS           : Credentials for Docker.io.
#   DB_NAME                   : Database name.
#   DB_USER                   : Database user.
#   DB_PASSWORD               : Database password.
#   INSTANCE_CONNECTION_NAME  : Instance connection name.
#   CGR_CREDS                 : Credentials for the Container Registry.

# Check if necessary environment variables are set
required_vars=(GHCR_CREDS REGISTRY1_CREDS GITHUB_TOKEN DOCKER_IO_CREDS DB_NAME DB_USER DB_PASSWORD INSTANCE_CONNECTION_NAME CGR_CREDS)
for var in "${required_vars[@]}"; do
  if [ -z "${!var}" ]; then
    echo "Environment variable $var is not set. Please set it before running the script."
    exit 1
  fi
done

# Set default number of versions to scan
NUMBER_OF_VERSIONS=2
NAMES_FILE="names.txt"

# Parse parameters
while getopts "f:v:" opt; do
  case ${opt} in
    f)
      NAMES_FILE=${OPTARG}
      ;;
    v)
      NUMBER_OF_VERSIONS=${OPTARG}
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

# Get the directory of the current script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Check if names file exists in the same directory as the script
NAMES_FILE="${SCRIPT_DIR}/${NAMES_FILE}"
if [ ! -f "$NAMES_FILE" ]; then
  echo "Names file $NAMES_FILE not found!"
  exit 1
fi

# Read names from the file and run the Go program for each name
while IFS= read -r NAME; do
  echo "Scanning $NAME with $NUMBER_OF_VERSIONS versions..."
  OUTPUT=$(go run cmd/store/main.go \
    -n "${NAME}" \
    -v "${NUMBER_OF_VERSIONS}" \
    -t "${GITHUB_TOKEN}" \
    --registry-creds "${GHCR_CREDS}" \
    --registry-creds "${REGISTRY1_CREDS}" \
    --registry-creds "${DOCKER_IO_CREDS}" \
    --registry-creds "${CGR_CREDS}" \
    --instance-connection-name "${INSTANCE_CONNECTION_NAME}" \
    --db-name "${DB_NAME}" \
    --db-user "${DB_USER}" \
    --db-password "${DB_PASSWORD}" \
    --db-type "postgres" 2>&1)
  
  if [ $? -eq 0 ]; then
    echo "Successfully finished scanning $NAME"
  else
    echo "Failed to scan $NAME"
    echo "Error output: $OUTPUT"
  fi
done < "$NAMES_FILE"