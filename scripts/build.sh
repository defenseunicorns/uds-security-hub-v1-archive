#!/usr/bin/env bash

set -ex

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd $DIR/../

REF="${REF:-"uds-security-hub:dev"}"

MELANGE_IMAGE_REPO="ghcr.io/wolfi-dev/melange"
MELANGE_IMAGE_IDENTIFIER=":latest"
MELANGE_IMAGE_REF="${MELANGE_IMAGE_REF:-${MELANGE_IMAGE_REPO}${MELANGE_IMAGE_IDENTIFIER}}"

APKO_IMAGE_REPO="ghcr.io/wolfi-dev/apko"
APKO_IMAGE_IDENTIFIER=":latest"
APKO_IMAGE_REF="${APKO_IMAGE_REF:-${APKO_IMAGE_REPO}${APKO_IMAGE_IDENTIFIER}}"

# Clean up previous builds
rm -rf ./packages/
rm -f melange.rsa melange.rsa.pub

# Generate signing keys
docker run --rm -v "${PWD}":/work "${MELANGE_IMAGE_REF}" keygen

# Build the package with Melange for both architectures
for ARCH in amd64 arm64; do
    docker run --rm --privileged -v "${PWD}":/work \
        "${MELANGE_IMAGE_REF}" build melange.yaml \
        --arch "${ARCH}" \
        --repository-append packages \
        --signing-key melange.rsa
done

# Build the image with apko for both architectures
docker run --rm -v "${PWD}":/work "${APKO_IMAGE_REF}" build apko.yaml "${REF}" output.tar --arch amd64 --arch arm64

# Load the image into Docker
docker load < output.tar
