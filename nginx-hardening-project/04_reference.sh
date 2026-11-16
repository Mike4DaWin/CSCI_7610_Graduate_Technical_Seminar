#!/bin/bash

# ==============================================================================
# 04_reference.sh
# Reproducing Defense-Grade Container Hardening — Iron Bank Reference Fetch
# Project: CSCI 7610 — Graduate Technical Seminar
# Author: Michael Ford
# Environment: Kali Linux (KVM)
#
# Downloads Iron Bank's public NGINX 1.30 hardening artifacts from Repo1
# for offline analysis. No authentication required — these are public files.
#
# Iron Bank source:
#   https://repo1.dso.mil/dsop/opensource/nginx/1.30/nginx
# ==============================================================================

set -e

PROJECT_DIR="$HOME/nginx-hardening-project"
REFERENCE_DIR="$PROJECT_DIR/reference"
DATE_TAG=$(date +%Y%m%d)

mkdir -p "$REFERENCE_DIR"

echo "=== Fetching Iron Bank NGINX 1.30 reference artifacts ==="

# Repo1 exposes raw files via GitLab's raw endpoint.
# Pattern: https://repo1.dso.mil/<group>/<project>/-/raw/<branch>/<path>
BASE_URL="https://repo1.dso.mil/dsop/opensource/nginx/1.30/nginx/-/raw/development"

FILES=(
    "Dockerfile"
    "Dockerfile.arm64"
    "hardening_manifest.yaml"
    "README.md"
    "LICENSE"
    "conf/nginx.conf"
)

for file in "${FILES[@]}"; do
    OUT_PATH="$REFERENCE_DIR/$(basename "$file")"
    echo "[*] Fetching: $file"
    if curl -sL -f -o "$OUT_PATH" "$BASE_URL/$file"; then
        echo "    → $OUT_PATH"
    else
        echo "    [!] Failed to fetch — file may not exist at that path or repo layout changed."
        echo "        Verify manually at: https://repo1.dso.mil/dsop/opensource/nginx/1.30/nginx"
    fi
done

# Also try the master branch fallback if development wasn't there
if [ ! -s "$REFERENCE_DIR/Dockerfile" ]; then
    echo ""
    echo "[!] Development branch fetch failed. Trying 'master' branch..."
    BASE_URL="https://repo1.dso.mil/dsop/opensource/nginx/1.30/nginx/-/raw/master"
    for file in "${FILES[@]}"; do
        OUT_PATH="$REFERENCE_DIR/$(basename "$file")"
        curl -sL -f -o "$OUT_PATH" "$BASE_URL/$file" && echo "    → fetched $file (master)"
    done
fi

echo ""
echo "[+] Reference artifacts saved to: $REFERENCE_DIR"
ls -la "$REFERENCE_DIR"

echo ""
echo "Next: open these files and catalog Iron Bank's hardening decisions."
echo "  cat $REFERENCE_DIR/Dockerfile"
echo "  cat $REFERENCE_DIR/hardening_manifest.yaml"
echo "  less $REFERENCE_DIR/nginx.conf"
