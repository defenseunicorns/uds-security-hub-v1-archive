#!/usr/bin/env bash

set -euo pipefail

readonly DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR/../"

readonly ARCHS=("amd64")
readonly REF="${REF:-"uds-security-hub:dev"}"
readonly ORG="defenseunicorns"

readonly MELANGE_IMAGE_REPO="cgr.dev/chainguard/melange"
readonly MELANGE_IMAGE_IDENTIFIER=":latest"
readonly MELANGE_IMAGE_REF="${MELANGE_IMAGE_REF:-${MELANGE_IMAGE_REPO}${MELANGE_IMAGE_IDENTIFIER}}"

readonly APKO_IMAGE_REPO="cgr.dev/chainguard/apko"
readonly APKO_IMAGE_IDENTIFIER=":latest"
readonly APKO_IMAGE_REF="${APKO_IMAGE_REF:-${APKO_IMAGE_REPO}${APKO_IMAGE_IDENTIFIER}}"

readonly APKO_CONFIG="/work/apko.yaml"
readonly SIGNING_KEY="/work/melange.rsa.pub"

# Get the current Git tag or commit hash
readonly GIT_TAG=$(git describe --tags --abbrev=0 2>/dev/null || git rev-parse --short HEAD)

if [[ ! -f "./apko.yaml" ]]; then
    echo "Error: ./apko.yaml not found."
    exit 1
fi

rm -rf ./packages/ >/dev/null 2>&1 || true
rm -f melange.rsa melange.rsa.pub >/dev/null 2>&1 || true

docker run --rm -v "${PWD}:/work" -w /work "${MELANGE_IMAGE_REF}" keygen

docker run --rm --privileged -v "${PWD}:/work" -w /work \
    "${MELANGE_IMAGE_REF}" build melange.yaml \
    --arch "${ARCHS[0]}" \
    --repository-append packages \
    --signing-key melange.rsa

for ARCH in "${ARCHS[@]}"; do
    docker run --rm -v "${PWD}:/work" -w /work \
        --platform "linux/${ARCH}" \
        "${APKO_IMAGE_REF}" build "${APKO_CONFIG}" \
        "${REF}-${ARCH}" "output-${ARCH}.tar" --arch "${ARCH}" -k "${SIGNING_KEY}"
    
    docker load < "output-${ARCH}.tar"
    
    # Debug information
    echo "Loaded image for architecture: ${ARCH}"
    
    # Tag the image with the correct architecture
    docker tag "${REF}-${ARCH}-${ARCH}" "${ORG}/uds-security-hub:dev-${ARCH}"
    
    if [[ "${TAG_MODE:-}" == "git" ]]; then
        docker tag "${REF}-${ARCH}" "${ORG}/uds-security-hub:${GIT_TAG}-${ARCH}"
        echo "Tagged image: ${ORG}/uds-security-hub:${GIT_TAG}-${ARCH}"
    else
        echo "Tagged image: ${ORG}/uds-security-hub:dev-${ARCH}"
    fi
done
