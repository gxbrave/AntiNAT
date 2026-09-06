#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
readme="$script_dir/README.md"

# Keep release operations explicit even though this PR lane only has local
# images and no registry identity or signing key.
grep -F 'docker buildx imagetools inspect' "$readme" >/dev/null
grep -F 'syft' "$readme" >/dev/null
grep -F 'cosign sign' "$readme" >/dev/null
grep -F 'cosign verify' "$readme" >/dev/null

if [ "$#" -eq 0 ]; then
    set -- antinat:p18-agent antinat:p18-controller
fi

if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
    printf '%s\n' 'SUPPORTED_WITH_LIMITS: Docker daemon unavailable; no OCI image, registry digest, SBOM, signature, or runtime evidence was collected.'
    exit 0
fi

evidence_dir=${ANTINAT_OCI_EVIDENCE_DIR:-${TMPDIR:-/tmp}/antinat-oci-evidence}
mkdir -p -- "$evidence_dir"
for image in "$@"; do
    image_id=$(docker image inspect "$image" --format '{{.Id}}')
    case "$image_id" in
        sha256:*) ;;
        *) printf '%s\n' "invalid local image identifier for $image" >&2; exit 1 ;;
    esac
    printf 'local_image_id %s %s\n' "$image" "$image_id"
    repo_digests=$(docker image inspect "$image" --format '{{json .RepoDigests}}')
    # A locally loaded, unqualified tag can appear in RepoDigests as
    # "antinat@sha256:...". It is still only a local content identifier, not
    # the registry-qualified digest required by the release contract.
    qualified_digest=$(printf '%s' "$repo_digests" | tr -d '[]"' | tr ',' '\n' | awk -F/ 'NF >= 2 && ($1 ~ /[.:]/ || $1 == "localhost") {print; exit}')
    if [ -z "$qualified_digest" ]; then
        printf '%s\n' "SUPPORTED_WITH_LIMITS: $image was loaded locally and has no registry manifest digest; release evidence must record IMAGE_REF@DIGEST."
    else
        printf 'registry_manifest_digest %s %s\n' "$image" "$qualified_digest"
    fi
    if command -v syft >/dev/null 2>&1; then
        safe_name=$(printf '%s' "$image" | tr '/:' '__')
        syft "$image" -o spdx-json >"$evidence_dir/$safe_name.spdx.json"
        test -s "$evidence_dir/$safe_name.spdx.json"
        printf 'sbom_generated %s %s\n' "$image" "$evidence_dir/$safe_name.spdx.json"
    else
        printf '%s\n' "SUPPORTED_WITH_LIMITS: syft is unavailable; no SBOM was generated for $image."
    fi
done

if command -v cosign >/dev/null 2>&1; then
    printf '%s\n' 'SUPPORTED_WITH_LIMITS: cosign is installed, but this local PR lane has no release identity/key and does not sign mutable local tags.'
else
    printf '%s\n' 'SUPPORTED_WITH_LIMITS: cosign is unavailable; release signature verification was not run.'
fi
