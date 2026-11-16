#!/bin/bash

# ==============================================================================
# 02_baseline.sh
# Reproducing Defense-Grade Container Hardening — Baseline Image Capture
# Project: CSCI 7610 — Graduate Technical Seminar
# Author: Michael Ford
# Environment: Kali Linux (KVM)
#
# Pulls upstream nginx:1.30 from Docker Hub and captures reference metadata
# (digest, size, layers, package list) before scanning. This is the "before"
# state that Module D empirical results will compare against.
# ==============================================================================

set -e

PROJECT_DIR="$HOME/nginx-hardening-project"
BASELINE_DIR="$PROJECT_DIR/baseline"
DATE_TAG=$(date +%Y%m%d)

mkdir -p "$BASELINE_DIR"

echo "=== Starting and Enabling Docker ==="
sudo systemctl start docker
sudo systemctl enable docker

# ------------------------------------------------------------------------------
# Pull upstream nginx:1.30 with digest capture
# ------------------------------------------------------------------------------
echo "=== Pulling upstream nginx:1.30 from Docker Hub ==="
sudo docker pull nginx:1.30

echo "[*] Recording image digest for reproducibility..."
DIGEST=$(sudo docker inspect nginx:1.30 --format='{{index .RepoDigests 0}}')
echo "$DIGEST" > "$BASELINE_DIR/baseline_digest_${DATE_TAG}.txt"
echo "[+] Digest: $DIGEST"

# ------------------------------------------------------------------------------
# Basic image metadata
# ------------------------------------------------------------------------------
echo "=== Capturing image metadata ==="

{
    echo "=== BASELINE METADATA: nginx:1.30 ==="
    echo "Captured: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    echo ""
    echo "--- Digest ---"
    echo "$DIGEST"
    echo ""
    echo "--- Size ---"
    sudo docker image inspect nginx:1.30 --format='Size: {{.Size}} bytes ({{ .Size }} / 1048576 MB)'
    sudo docker image inspect nginx:1.30 --format='VirtualSize: {{.VirtualSize}} bytes'
    echo ""
    echo "--- Layers ---"
    sudo docker image inspect nginx:1.30 --format='Layer count: {{len .RootFS.Layers}}'
    echo ""
    echo "--- Config ---"
    sudo docker image inspect nginx:1.30 --format='User: [{{.Config.User}}]'
    sudo docker image inspect nginx:1.30 --format='Cmd: {{.Config.Cmd}}'
    sudo docker image inspect nginx:1.30 --format='Entrypoint: {{.Config.Entrypoint}}'
    sudo docker image inspect nginx:1.30 --format='WorkingDir: [{{.Config.WorkingDir}}]'
    sudo docker image inspect nginx:1.30 --format='ExposedPorts: {{.Config.ExposedPorts}}'
    echo ""
    echo "--- Environment ---"
    sudo docker image inspect nginx:1.30 --format='{{range .Config.Env}}{{println .}}{{end}}'
} > "$BASELINE_DIR/baseline_metadata_${DATE_TAG}.txt"

echo "[+] Saved: $BASELINE_DIR/baseline_metadata_${DATE_TAG}.txt"

# ------------------------------------------------------------------------------
# Package inventory — what's actually inside the image
# ------------------------------------------------------------------------------
echo "=== Enumerating installed packages ==="

sudo docker run --rm nginx:1.30 sh -c "dpkg -l 2>/dev/null || rpm -qa 2>/dev/null || apk info 2>/dev/null" \
    > "$BASELINE_DIR/baseline_packages_${DATE_TAG}.txt" || true

PACKAGE_COUNT=$(wc -l < "$BASELINE_DIR/baseline_packages_${DATE_TAG}.txt")
echo "[+] Package count: $PACKAGE_COUNT"
echo "[+] Saved: $BASELINE_DIR/baseline_packages_${DATE_TAG}.txt"

# ------------------------------------------------------------------------------
# Sanity check — spin up nginx and confirm it serves a response
# ------------------------------------------------------------------------------
echo "=== Sanity check: baseline nginx serves HTTP 200 ==="

sudo docker run -d --name nginx-baseline-test -p 8080:80 nginx:1.30
sleep 3

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/ || echo "000")
if [ "$HTTP_CODE" = "200" ]; then
    echo "[+] Baseline nginx serving HTTP 200 — functional."
else
    echo "[!] Baseline nginx returned HTTP $HTTP_CODE — investigate."
fi

# Capture the default response for later comparison
curl -sk http://localhost:8080/ > "$BASELINE_DIR/baseline_default_response_${DATE_TAG}.html" || true
curl -sk -I http://localhost:8080/ > "$BASELINE_DIR/baseline_default_headers_${DATE_TAG}.txt" || true

sudo docker stop nginx-baseline-test > /dev/null
sudo docker rm nginx-baseline-test > /dev/null

echo ""
echo "[+] Baseline capture complete."
echo "    Files in $BASELINE_DIR:"
ls -la "$BASELINE_DIR"
echo ""
echo "    Run 03_scanning.sh next to run the scan suite against the baseline."
