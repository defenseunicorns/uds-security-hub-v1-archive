#!/usr/bin/env bash

set -euo pipefail

readonly DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR/../" || exit

readonly IMAGES=("uds-security-hub" "uds-security-hub-store")
readonly ARCHS=("amd64")

# comma-separated-linux takes the arguments provided and replaces the spaces between them
# with a comma. It's meant to be used with the --arch flag in the melange flags
comma-separated-list() {
    echo "$@" | tr ' ' ','
}

# build-image takes in a single image name and builds that using it's
# corresponding melange and apko files.
#
# args:
#   IMAGE_NAME: the name of the image to build. This matches the names of the apko and melange files
build-image() {
    local IMAGE_NAME="$1"
    echo "building image ${IMAGE_NAME}"

    local IMAGE_TAG="${IMAGE_TAG:-"latest"}"
    local REF="${IMAGE_NAME}:${IMAGE_TAG}"
    local ORG="ghcr.io/defenseunicorns"

    local MELANGE_IMAGE_REPO="cgr.dev/chainguard/melange"
    local MELANGE_IMAGE_IDENTIFIER=":latest"
    local MELANGE_IMAGE_REF="${MELANGE_IMAGE_REF:-${MELANGE_IMAGE_REPO}${MELANGE_IMAGE_IDENTIFIER}}"

    local APKO_IMAGE_REPO="cgr.dev/chainguard/apko"
    local APKO_IMAGE_IDENTIFIER=":latest"
    local APKO_IMAGE_REF="${APKO_IMAGE_REF:-${APKO_IMAGE_REPO}${APKO_IMAGE_IDENTIFIER}}"

    local SIGNING_KEY="melange.rsa.pub"

    local MELANGE_CONFIG="images/${IMAGE_NAME}/melange.yaml"
    local APKO_CONFIG="images/${IMAGE_NAME}/apko.yaml"

    local PACKAGES_DIR="packages-${IMAGE_NAME}"

    # Get the current Git tag or commit hash
    local GIT_TAG=$(git describe --tags --abbrev=0 2>/dev/null || git rev-parse --short HEAD)

    if [[ ! -f "${MELANGE_CONFIG}" ]]; then
        echo "Error: ${MELANGE_CONFIG} not found."
        exit 1
    fi

    if [[ ! -f "${APKO_CONFIG}" ]]; then
        echo "Error: ${APKO_CONFIG} not found."
        exit 1
    fi

    docker run --rm -v "${PWD}:/work" -w /work "${MELANGE_IMAGE_REF}" keygen

    docker run --rm --privileged -v "${PWD}:/work" -w /work \
        "${MELANGE_IMAGE_REF}" build ${MELANGE_CONFIG} \
        --arch $(comma-separated-list "${ARCHS[@]}") \
        --source-dir /work \
        --out-dir "${PACKAGES_DIR}" \
        --signing-key melange.rsa

    for ARCH in "${ARCHS[@]}"; do
        docker run --rm -v "${PWD}:/work" -w /work \
            --platform "linux/${ARCH}" \
            "${APKO_IMAGE_REF}" build "${APKO_CONFIG}" \
            "${REF}" "output-${IMAGE_NAME}-${ARCH}.tar" \
            --arch "${ARCH}" \
            -k "${SIGNING_KEY}" \
            -r "${PACKAGES_DIR}"

        docker load < "output-${IMAGE_NAME}-${ARCH}.tar"

        # Debug information
        echo "Loaded image for architecture: ${ARCH}"

        # Tag the image with the correct architecture
        docker tag "${REF}-${ARCH}" "${ORG}/${IMAGE_NAME}:${IMAGE_TAG}"

        if [[ "${TAG_MODE:-}" == "git" ]]; then
            docker tag "${REF}-${ARCH}" "${ORG}/${IMAGE_NAME}:${GIT_TAG}"
            echo "Tagged image: ${ORG}/${IMAGE_NAME}:${GIT_TAG}"
        else
            echo "Tagged image: ${ORG}/${IMAGE_NAME}:${IMAGE_TAG}"
        fi
    done
}


echo "building images: ${IMAGES[@]} with arch: ${ARCHS[@]}"

for IMAGE_NAME in "${IMAGES[@]}"; do
    build-image "$IMAGE_NAME"
done
