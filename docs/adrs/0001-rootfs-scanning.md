# ADR: Scan using `trivy rootfs` to get a complete scan of a package

Date: 2024-08-12

## Status

pending

## Context

Prior local package scanning was implemented using only the sbom. This can result in lower quality CVE results.

Example CVE counts for the zarf argocd example as per 2024-08-12.

| Scanner Type | CRITICAL | HIGH | MEDIUM | TOTAL |
| :----------: | :------: | :--: | :----: | :---: |
| sbom         | 1        | 2    | 23     | 41    |
| rootfs       | 2        | 9    | 101    | 187   |

## Implementation

Trivy supports scanning a container using a `rootfs`. We get this from the registry or package.

- read the `images/index.json` manifest from the package.

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
    - ignore any image that has a `org.opencontainers.image.base.name` ending with `*.att` or `*.sig`. These are not images that need to be scanned.
    - read the digest in `images/blobs/sha256/<digest>`
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
// <redacted>
  ]
}
```

    - the `layers` is a list of tar files.
    - extract `tar xf` each layer in the given order to a tmp directory.
        - if there is an error in the step, log a warn and continue
    - run `trivy rootfs` against that directory and report results

## Alternatives Considered

- Trivy also has a oci layout scanner which could work with some tweaking on the results to separate out the individual image components.
