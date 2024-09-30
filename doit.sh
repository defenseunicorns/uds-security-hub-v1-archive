#!/bin/bash


## mattermost

# TAGS="9.9.0-uds.0-upstream 9.9.0-uds.0-registry1 9.9.1-uds.0-upstream 9.9.1-uds.0-registry1 9.10.1-uds.0-upstream 9.10.1-uds.0-registry1 9.10.1-uds.1-upstream 9.10.1-uds.1-registry1 9.11.0-uds.0-upstream 9.11.0-uds.0-registry1 9.11.1-uds.0-upstream 9.11.1-uds.0-registry1"

# for t in $TAGS; do
#   ./bin/uds-security-hub --registry-creds ghcr.io:partkyle:$(cat ~/.github-defenseunicorns-ghcr) -t $(cat ~/.github-defenseunicorns-ghcr) -o defenseunicorns -n packages/uds/mattermost -t trivy -g $t -f output
# done?

## core

TAGS="0.26.0-registry1 0.26.0-upstream 0.26.1-registry1 0.26.1-upstream 0.27.0-upstream 0.27.0-registry1 0.27.1-upstream 0.27.1-registry1 0.27.2-registry1 0.27.2-upstream 0.27.3-registry1 0.27.3-upstream"
for t in $TAGS; do
  ./bin/uds-security-hub --registry-creds ghcr.io:partkyle:$(cat ~/.github-defenseunicorns-ghcr) -t $(cat ~/.github-defenseunicorns-ghcr) -o defenseunicorns -n packages/uds/core -t trivy -g $t -f output
done

## private/core

# TAGS="0.26.0-unicorn 0.26.1-unicorn 0.27.0-unicorn 0.27.1-unicorn 0.27.2-unicorn 0.27.3-unicorn"
# for t in $TAGS; do
#   ./bin/uds-security-hub --registry-creds ghcr.io:partkyle:$(cat ~/.github-defenseunicorns-ghcr) -t $(cat ~/.github-defenseunicorns-ghcr) -o defenseunicorns -n packages/private/uds/core -t trivy -g $t -f output
# done

# vllm

# TAGS="0.12.2-upstream 0.13.0-upstream 0.13.1-upstream"
# for t in $TAGS; do
#   ./bin/uds-security-hub --registry-creds ghcr.io:partkyle:$(cat ~/.github-defenseunicorns-ghcr) -t $(cat ~/.github-defenseunicorns-ghcr) -o defenseunicorns -n packages/uds/leapfrogai/vllm -t trivy -g $t -f output
# done