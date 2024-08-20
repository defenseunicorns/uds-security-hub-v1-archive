# ADR: Scan using `trivy rootfs` to get a complete scan of a package

Date: 2024-08-12

## Status

pending

## Context

Prior local package scanning was implemented using only the sbom. This can result
in lower quality CVE results.

Example CVE counts for the zarf argocd example as per 2024-08-12.

| Scanner Type | CRITICAL | HIGH | MEDIUM | TOTAL |
| :----------: | :------: | :--: | :----: | :---: |
| sbom         | 1        | 2    | 23     | 41    |
| rootfs       | 2        | 9    | 101    | 187   |

## Implementation

Trivy supports scanning a container using a `rootfs`. By extracting the layers
for each image to a directory we can use this to get a complete scan of an image.

### Local Package Scans


- read the `images/index.json` manifest from the package. Example from `zarf/examples/argocd`

```
{
   "schemaVersion": 2,
   "mediaType": "application/vnd.oci.image.index.v1+json",
   "manifests": [
      {
         "mediaType": "application/vnd.oci.image.manifest.v1+json",
         "size": 9612,
         "digest": "sha256:15f469a6f69979694769ab1e6782be40facca74ea7ad74e01f2a6a5c72e307f6",
         "annotations": {
            "org.opencontainers.image.base.name": "quay.io/argoproj/argocd:sha256-2dafd800fb617ba5b16ae429e388ca140f66f88171463d23d158b372bb2fae08.sig"
         }
      },
      {
         "mediaType": "application/vnd.oci.image.manifest.v1+json",
         "size": 9790,
         "digest": "sha256:f414c5344bf3ec6777b84aa6e1e32838cf7a8a5ea5cc12a9489c14ee51b449a6",
         "annotations": {
            "org.opencontainers.image.base.name": "quay.io/argoproj/argocd:sha256-2dafd800fb617ba5b16ae429e388ca140f66f88171463d23d158b372bb2fae08.att"
         }
      },
      {
         "mediaType": "application/vnd.oci.image.manifest.v1+json",
         "size": 2483,
         "digest": "sha256:1c08fe64a37f29ce012c0a3665ef78f2e9ac27b2425a7d717dc852dc58062f10",
         "annotations": {
            "org.opencontainers.image.base.name": "docker.io/library/redis:7.0.15-alpine"
         }
      },
      {
         "mediaType": "application/vnd.oci.image.manifest.v1+json",
         "size": 1625,
         "digest": "sha256:d37d27b92cce4fb1383d5fbe32540382ea3d9662c7be3555f5a0f6a044099e1b",
         "annotations": {
            "org.opencontainers.image.base.name": "ghcr.io/stefanprodan/podinfo:6.4.0"
         }
      },
      {
         "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
         "size": 3237,
         "digest": "sha256:e7898cd05251d2af51380cbf50c9613748440fe6406e28e027846875b941c2de",
         "annotations": {
            "org.opencontainers.image.base.name": "quay.io/argoproj/argocd:v2.9.6"
         }
      }
   ]
}
```

- this will include a list of images, for each image:
    - ignore any image that has a `org.opencontainers.image.base.name` ending with `*.att` or `*.sig`.
      These are not images that need to be scanned.
    - read the file in `images/blobs/sha256/<digest>`. It is an image manifest.
```
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
  "config": {
    "mediaType": "application/vnd.docker.container.image.v1+json",
    "digest": "sha256:26997ab04178102d8549deff0abfcfb9455bd6a6e6f6a6723d3493d53d5a9097",
    "size": 7053
  },
  "layers": [
    {
      "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
      "digest": "sha256:3153aa388d026c26a2235e1ed0163e350e451f41a8a313e1804d7e1afb857ab4",
      "size": 29533422
    },
// <extra layers redacted>
  ]
}
```

    - the `layers` are a list of tar.gz files stored in the blobs directory by their digest
    - extract `tar xf` each layer in the given order to a tmp directory.
        - if there is an error in the step, log a warn and continue
    - run `trivy rootfs` against that directory and report results.

### Remote Package Scanner

For the remote scanner we download the image to a local directory using oras.land. 
Once it's on disk, we read the `index.json` file to get a list of manifests. These 
are the supported platforms. We are currently only looking at the `amd64` image, 
so we read the blob associated with amd64 to get a list of layers in the image. This 
is where we find the actual index.json for `amd64`. We then use the same logic as the
local scanner to unpack the rootfs and use `trivy rootfs` to scan that image.

Thus, the remote and the local scan are remarkably similar, with only subtle differences
in where the index is found.


### Note on SBOM support

There is also support to scan only using the SBOM using command line flags. This yields
lower quality results as the SBOMs at the time of writing this are not a complete
representation of all dependencies in a package. The trivy rootfs scanner finds more
vulnerabilities. We can possibly use this disparity in the future to increase the
accuracy of our SBOM generation.

## Alternatives Considered

- Trivy also has a oci layout scanner which could work with some tweaking on the results to separate out the individual image components.
  This would allow us to avoid unpacking the tar files

Example:

```
$ trivy image --input /tmp/dir@<image-digest-from-index.json>
```
