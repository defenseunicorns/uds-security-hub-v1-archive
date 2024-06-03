#!/usr/bin/env bash

set -ex

# Set the Docker context
docker context use desktop-linux

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd $DIR/../

REF="${REF:-"ghcr.io/defenseunicorns/uds-security-hub:dev"}"

REGISTRY_USERNAME="${REGISTRY_USERNAME:-"missing"}"
REGISTRY_PASSWORD="${REGISTRY_PASSWORD:-"missing"}"

MELANGE_IMAGE_REPO="ghcr.io/wolfi-dev/melange"
MELANGE_IMAGE_IDENTIFIER=":latest"
MELANGE_IMAGE_REF="${MELANGE_IMAGE_REF:-${MELANGE_IMAGE_REPO}${MELANGE_IMAGE_IDENTIFIER}}"

APKO_IMAGE_REPO="ghcr.io/wolfi-dev/apko"
APKO_IMAGE_IDENTIFIER=":latest"
APKO_IMAGE_REF="${APKO_IMAGE_REF:-${APKO_IMAGE_REPO}${APKO_IMAGE_IDENTIFIER}}"

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

if [[ "${DOCKER_CONFIG}" == "" ]]; then
    if [[ "${REGISTRY_USERNAME}" == "missing" || "${REGISTRY_PASSWORD}" == "missing" ]]; then
        echo "Must set REGISTRY_USERNAME and REGISTRY_PASSWORD. Exiting."
        exit 1
    fi
    export DOCKER_CONFIG="$(mktemp -d)"
    trap "rm -rf ${DOCKER_CONFIG}" EXIT
    echo "{}" > "${DOCKER_CONFIG}/config.json"
    echo "${REGISTRY_PASSWORD}" | docker login ghcr.io -u "${REGISTRY_USERNAME}" --password-stdin
fi

# Build the image with apko for both architectures
docker run --rm -v "${PWD}":/work -v "${DOCKER_CONFIG}":/dockerconfig -v /var/run/docker.sock:/var/run/docker.sock -e DOCKER_CONFIG=/dockerconfig \
    "${APKO_IMAGE_REF}" build apko.yaml "${REF}" output.tar --arch amd64 --arch arm64

# Load the image into Docker
docker load < output.tar

# Push the image to the registry
docker push "${REF}"
