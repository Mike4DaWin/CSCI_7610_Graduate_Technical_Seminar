#!/bin/bash
# ==============================================================================
# build.sh — Stage 4: build the independent hardened NGINX image
# Project: CSCI 7610 — Graduate Technical Seminar (Michael Ford)
#
# Copy this folder to ~/nginx-hardening-project/hardened on the Kali VM, then:
#   chmod +x *.sh && ./build.sh
#
# 1. Downloads the same three resources Iron Bank's hardening_manifest.yaml lists
#    and verifies each against the manifest's SHA-256 value.
# 2. Builds nginx-hardened:latest and records its digest/size.
# 3. Generates a throwaway self-signed certificate (../test-certs) for local testing.
# 4. Runs a functional check (HTTP->HTTPS redirect, HTTPS 200, headers).
# ==============================================================================

set -e
cd "$(dirname "${BASH_SOURCE[0]}")"

IMAGE="nginx-hardened:latest"
BASE_REF="registry.access.redhat.com/ubi10/ubi-minimal:$(sed -n 's/^ARG BASE_TAG=//p' Dockerfile)"
# Test certificate lives outside hardened/ so Semgrep doesn't flag the key
CERT_DIR="$(cd .. && pwd)/test-certs"
STRIP_PKG_MGR="${STRIP_PKG_MGR:-1}"
STRIP_SHELL="${STRIP_SHELL:-0}"
STRIP_SYSTEMD="${STRIP_SYSTEMD:-0}"
LOG="build_log_$(date +%Y%m%d_%H%M%S).txt"

# Values copied from reference/hardening_manifest.yaml (Iron Bank, nginx 1.30.4)
RPM_URL="https://nginx.org/packages/rhel/10/x86_64/RPMS/nginx-1.30.4-1.el10.ngx.x86_64.rpm"
RPM_SHA="edacd6b7faf6b6c773c64aa78f1cc0cdbbde7469d5524e0443ab02a143577945"
KEY_URL="https://nginx.org/keys/nginx_signing.key"
KEY_SHA="55385da31d198fa6a5012d40ae98ecb272a6c4e8fffffba94719ffd3e87de37a"

exec > >(tee "$LOG") 2>&1

echo "=== [1/4] Fetching and verifying resources ==="
mkdir -p resources
# Re-download only if the cached copy is missing or fails its SHA-256 check
fetch() {  # fetch <url> <file> <sha256>
    if ! echo "$3  $2" | sha256sum -c - &>/dev/null; then
        curl -fsSL --retry 3 -o "$2" "$1"
    fi
    echo "$3  $2" | sha256sum -c -
}
fetch "$RPM_URL" resources/nginx.rpm "$RPM_SHA"
fetch "$KEY_URL" resources/nginx_signing.key "$KEY_SHA"

echo "=== [2/4] Building $IMAGE (STRIP_PKG_MGR=$STRIP_PKG_MGR STRIP_SHELL=$STRIP_SHELL STRIP_SYSTEMD=$STRIP_SYSTEMD) ==="
sudo docker pull "$BASE_REF"
echo "[*] Base image: $BASE_REF"
sudo docker build \
    --build-arg STRIP_PKG_MGR="$STRIP_PKG_MGR" \
    --build-arg STRIP_SHELL="$STRIP_SHELL" \
    --build-arg STRIP_SYSTEMD="$STRIP_SYSTEMD" \
    -t "$IMAGE" .
sudo docker image inspect "$IMAGE" --format='Image ID: {{.Id}}  Size: {{.Size}} bytes  Layers: {{len .RootFS.Layers}}  User: {{.Config.User}}'
echo "[*] Dockerfile complexity: $(grep -cvE '^\s*(#|$)' Dockerfile) non-comment lines" \
     "(upstream comparison: count lines of the official nginx Dockerfile for the same tag)"

echo "=== [3/4] Generating a self-signed test certificate ==="
mkdir -p "$CERT_DIR"
if [ ! -s "$CERT_DIR/tls.crt" ]; then
    openssl req -x509 -nodes -newkey rsa:2048 -days 30 \
        -subj "/CN=localhost" -keyout "$CERT_DIR/tls.key" -out "$CERT_DIR/tls.crt"
fi
chmod 644 "$CERT_DIR/tls.crt" "$CERT_DIR/tls.key"   # test-only key; the container user must read it

echo "=== [4/4] Functional check ==="
NAME="nginx-hardened-check-$$"
# Same host ports as runtime_probe.sh (8080 is often taken by Burp on Kali)
sudo docker run -d --name "$NAME" -p 8090:8080 -p 8453:8443 \
    -v "$CERT_DIR:/etc/nginx/certs:ro" "$IMAGE" > /dev/null
sleep 3
echo "--- HTTP (expect 301) ---";  curl -s -o /dev/null -w "HTTP %{http_code}\n" http://localhost:8090/ || true
echo "--- HTTPS (expect 200) ---"; curl -sk -o /dev/null -w "HTTP %{http_code}\n" https://localhost:8453/ || true
echo "--- HTTPS headers ---";      curl -sk -I https://localhost:8453/ || true
# SECLEVEL=0 makes the client offer TLS 1.1, so a failure means the server refused it
echo "--- TLS 1.1 must fail ---"
openssl s_client -connect localhost:8453 -tls1_1 -cipher 'DEFAULT:@SECLEVEL=0' </dev/null 2>&1 | grep -q '^New, TLS' \
    && echo "TLS 1.1 ACCEPTED — check config" || echo "TLS 1.1 rejected"
echo "--- Process user ---";       sudo docker exec "$NAME" id || true   # docker top shows host user names for the UID
sudo docker logs "$NAME" 2>&1 | tail -5
sudo docker rm -f "$NAME" > /dev/null

echo ""
echo "[+] Build complete. Log saved to $LOG"
echo "    Next:"
echo "      cd ~/nginx-hardening-project && ./03_scanning.sh $IMAGE     # choose 8 (all)"
echo "      ./hardened/sign.sh                                           # Cosign signature + SBOM attestation"
