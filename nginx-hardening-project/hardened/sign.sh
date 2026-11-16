#!/bin/bash
# ==============================================================================
# sign.sh — provenance: Cosign signature + SBOM attestation for the hardened image
#
# Cosign signs images in a registry, so this pushes to a throwaway local
# registry (localhost:5000). Key-based signing is the default because it works
# offline and is reproducible; set KEYLESS=1 to use Sigstore keyless signing
# instead (opens a browser for OIDC login and records the entry in the public
# Rekor transparency log).
#
# Usage: ./sign.sh [path/to/sbom.cdx.json]
#   (default SBOM: newest scans/nginx-hardened_latest_*/sbom_*.cdx.json)
# Output: provenance_<timestamp>.txt and cosign.pub, written next to the SBOM.
# Keys live in ~/nginx-hardening-project/signing (outside hardened/, so Semgrep
# doesn't scan the private key).
# ==============================================================================

set -e -o pipefail
PROJECT_DIR="$HOME/nginx-hardening-project"
KEY_DIR="$PROJECT_DIR/signing"
IMAGE="nginx-hardened:latest"
REG_IMAGE="localhost:5000/nginx-hardened:latest"
SBOM="${1:-$(ls -t "$PROJECT_DIR"/scans/nginx-hardened_latest_*/sbom_*.cdx.json 2>/dev/null | head -1 || true)}"

[ -s "$SBOM" ] || { echo "[!] No SBOM found — run 03_scanning.sh $IMAGE with option 3 first."; exit 1; }
OUT="$(dirname "$SBOM")/provenance_$(date +%Y%m%d_%H%M%S).txt"

# cosign v3 signs through a signing config by default; key-based signing without
# a transparency log needs --use-signing-config=false there (flag absent in v2).
COSIGN_MAJOR=$(cosign version 2>&1 | grep -oE 'GitVersion:[[:space:]]*v[0-9]+' | grep -oE '[0-9]+$' || echo 2)
NO_TLOG="--tlog-upload=false"
[ "${COSIGN_MAJOR:-2}" -ge 3 ] && NO_TLOG="--use-signing-config=false --tlog-upload=false"

if ! sudo docker ps --format '{{.Names}}' | grep -q '^local-registry$'; then
    sudo docker start local-registry > /dev/null 2>&1 || \
        sudo docker run -d -p 5000:5000 --name local-registry registry:2 > /dev/null
    sleep 2
fi
sudo docker tag "$IMAGE" "$REG_IMAGE"
sudo docker push "$REG_IMAGE"
DIGEST_REF=$(sudo docker inspect "$REG_IMAGE" --format='{{range .RepoDigests}}{{println .}}{{end}}' \
    | grep -m1 '^localhost:5000/nginx-hardened@')

{
    echo "=== PROVENANCE: $DIGEST_REF ==="
    echo "Captured: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    echo "Cosign: $(cosign version 2>&1 | grep -m1 GitVersion)"
    echo "SBOM: $SBOM"
    if [ "${KEYLESS:-0}" = "1" ]; then
        cosign sign --yes "$DIGEST_REF"
        cosign attest --yes --type cyclonedx --predicate "$SBOM" "$DIGEST_REF"
        echo "--- verify (keyless) ---"
        V=$(cosign verify --certificate-identity-regexp '.*' --certificate-oidc-issuer-regexp '.*' "$DIGEST_REF"); echo "${V:0:600}"
    else
        mkdir -p "$KEY_DIR"
        [ -f "$KEY_DIR/cosign.key" ] || (cd "$KEY_DIR" && COSIGN_PASSWORD="" cosign generate-key-pair)
        # shellcheck disable=SC2086  # NO_TLOG is intentionally word-split
        COSIGN_PASSWORD="" cosign sign --yes $NO_TLOG --key "$KEY_DIR/cosign.key" "$DIGEST_REF"
        # shellcheck disable=SC2086
        COSIGN_PASSWORD="" cosign attest --yes $NO_TLOG --key "$KEY_DIR/cosign.key" \
            --type cyclonedx --predicate "$SBOM" "$DIGEST_REF"
        echo "--- verify signature ---"
        V=$(cosign verify --insecure-ignore-tlog --key "$KEY_DIR/cosign.pub" "$DIGEST_REF"); echo "${V:0:600}"
        echo "--- verify SBOM attestation ---"
        cosign verify-attestation --insecure-ignore-tlog --key "$KEY_DIR/cosign.pub" --type cyclonedx "$DIGEST_REF" > /dev/null \
            && echo "SBOM attestation verified"
        cp "$KEY_DIR/cosign.pub" "$(dirname "$SBOM")/cosign.pub"
    fi
} 2>&1 | tee "$OUT"

echo "[+] Saved: $OUT"
