#!/bin/bash

# ==============================================================================
# 00_run_all.sh
# Reproducing Defense-Grade Container Hardening — One-shot setup wrapper
# Project: CSCI 7610 — Graduate Technical Seminar
# Author: Michael Ford
# Environment: Kali Linux (KVM)
#
# Runs the full Module C setup in sequence:
#   1. Install all tools (Docker, Trivy, Grype, Syft, Cosign, dive, dbench, Semgrep)
#   2. Pull upstream nginx:1.30 and capture baseline metadata
#   3. Fetch Iron Bank's public NGINX 1.30 hardening artifacts
#   4. Prompt to run the interactive scan suite
#
# Usage:
#   chmod +x *.sh
#   ./00_run_all.sh
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo ""
echo "============================================================"
echo "  NGINX Hardening Project — Full Setup"
echo "  Michael Ford | CSCI 7610 | Fall 2026"
echo "============================================================"
echo ""
echo "This wrapper runs four scripts in order:"
echo "  1) 01_requirements.sh  → install all tools"
echo "  2) 02_baseline.sh      → pull nginx:1.30 and capture baseline"
echo "  3) 04_reference.sh     → download Iron Bank's public artifacts"
echo "  4) 03_scanning.sh      → optional: run the scan suite (interactive)"
echo ""
read -rp "Press ENTER to begin, or Ctrl+C to abort... "

# Ensure everything is executable
chmod +x 01_requirements.sh 02_baseline.sh 03_scanning.sh 04_reference.sh 2>/dev/null || true

echo ""
echo "============================================================"
echo "  STEP 1/4: Installing tools (01_requirements.sh)"
echo "============================================================"
./01_requirements.sh

# Check if docker group was just added — if so, we need to re-exec with newgrp
if ! docker ps &>/dev/null; then
    echo ""
    echo "[!] Docker group membership just took effect. Re-invoking with newgrp docker..."
    echo "    (If this fails, log out, log back in, and re-run ./00_run_all.sh)"
    exec sg docker "$SCRIPT_DIR/00_run_all.sh --skip-install"
fi

# If invoked with --skip-install (from newgrp re-exec), skip step 1 next time
if [[ "$1" == "--skip-install" ]]; then
    echo "[*] Skipping install step (already completed in prior invocation)"
fi

echo ""
echo "============================================================"
echo "  STEP 2/4: Baseline capture (02_baseline.sh)"
echo "============================================================"
./02_baseline.sh

echo ""
echo "============================================================"
echo "  STEP 3/4: Iron Bank reference fetch (04_reference.sh)"
echo "============================================================"
./04_reference.sh

echo ""
echo "============================================================"
echo "  STEP 4/4: Scan suite (03_scanning.sh)"
echo "============================================================"
echo ""
read -rp "Run the interactive scan suite now? [Y/n] " RUN_SCANS
if [[ ! "$RUN_SCANS" =~ ^[Nn]$ ]]; then
    ./03_scanning.sh
else
    echo ""
    echo "[*] Skipping scans for now. Run manually later with:"
    echo "    cd $SCRIPT_DIR && ./03_scanning.sh"
fi

echo ""
echo "============================================================"
echo "[+] Setup complete."
echo "============================================================"
echo ""
echo "Project directory: $HOME/nginx-hardening-project"
echo ""
echo "What you now have for Module C:"
echo "  • Baseline data on upstream nginx:1.30 in ~/nginx-hardening-project/baseline/"
echo "  • Iron Bank's public artifacts in ~/nginx-hardening-project/reference/"
echo "  • (Optional) Scan outputs in ~/nginx-hardening-project/scans/"
echo ""
echo "Next: read reference/Dockerfile, reference/hardening_manifest.yaml,"
echo "      and reference/nginx.conf, then draft Methodology (Section III)."
echo ""
