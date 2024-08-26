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
#   GITHUB_TOKEN              : GitHub token for authentication.

# Check if necessary environment variables are set
required_vars=(GHCR_CREDS GITHUB_TOKEN)
for var in "${required_vars[@]}"; do
  if [ -z "${!var}" ]; then
    echo "Environment variable $var is not set. Please set it before running the script."
    exit 1
  fi
done

NAMES_FILE="names.txt"

# Parse parameters
while getopts "f:" opt; do
  case ${opt} in
    f)
      NAMES_FILE=${OPTARG}
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
  version=$(crane ls ghcr.io/defenseunicorns/$NAME | tail -1)
  echo "Scanning $NAME with version=$version..."
  go run . \
    -n "${NAME}" \
    -g "${version}" \
    --output-format "json" \
    --output-file $(basename $NAME).json \
    --registry-creds "${GHCR_CREDS}" \
  echo "Finished scanning $NAME"
done < "$NAMES_FILE"
