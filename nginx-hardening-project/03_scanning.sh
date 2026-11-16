#!/bin/bash

# ==============================================================================
# 03_scanning.sh
# Reproducing Defense-Grade Container Hardening — Interactive Scan Suite
# Project: CSCI 7610 — Graduate Technical Seminar
# Author: Michael Ford
# Environment: Kali Linux (KVM)
#
# Runs the scanning tool suite against a target image (default: nginx:1.30).
# Same menu-driven pattern as the OpenEMR project's 03_scanning.sh.
#
# Usage:
#   ./03_scanning.sh                    # scans nginx:1.30 (baseline)
#   ./03_scanning.sh myhardened:latest  # scans your hardened image later
# ==============================================================================

set -e

export TMPDIR="${TMPDIR:-$HOME/trivy-tmp}"
export TRIVY_CACHE_DIR="${TRIVIY_CACHE_DIR:=$HOME/.cache/trivy}"
mkdir -p "$TMPDIR" "$TRIVY_CACHE_DIR"

PROJECT_DIR="$HOME/nginx-hardening-project"
TARGET_IMAGE="${1:-nginx:1.30}"
DATE_TAG=$(date +%Y%m%d_%H%M%S)

# Trivy, Grype and Syft talk to Docker as $USER (no sudo), so check that first
if ! docker info &>/dev/null; then
    echo "[!] $USER cannot reach the Docker socket (Trivy/Grype/Syft will fail)."
    echo "    Fix: sudo usermod -aG docker $USER && newgrp docker   (or log out and back in)"
    exit 1
fi

# Sanitize image name for filenames (replace / and : with _)
IMAGE_TAG=$(echo "$TARGET_IMAGE" | tr '/:' '__')
SCAN_DIR="$PROJECT_DIR/scans/${IMAGE_TAG}_${DATE_TAG}"

mkdir -p "$SCAN_DIR"

echo ""
echo "============================================"
echo "  Container Hardening Scan Suite — CSCI 7610"
echo "  Target image: $TARGET_IMAGE"
echo "  Output dir:   $SCAN_DIR"
echo "============================================"
echo "  Select scans to run (space-separated):"
echo ""
echo "  --- Vulnerability Scanning ---"
echo "  1) trivy        CVE scan (Aqua Security)"
echo "  2) grype        CVE scan (Anchore, second opinion)"
echo ""
echo "  --- SBOM & Provenance ---"
echo "  3) syft         Generate SBOM in CycloneDX + SPDX + human formats"
echo ""
echo "  --- Configuration & Structure ---"
echo "  4) dbench       CIS Docker Benchmark (docker-bench-security)"
echo "  5) inspect      Image metadata + package inventory + layer analysis"
echo "  6) semgrep      Static analysis of Dockerfile/configs (if present)"
echo ""
echo "  --- Runtime Verification ---"
echo "  7) runtime      Spin up container and check headers, ports, functional response"
echo ""
echo "  8) all          Run all scans in sequence"
echo ""
read -rp "Enter choices (e.g. 1 2 3 or 8): " -a CHOICES

# Parse choices
run_trivy=false;    run_grype=false;    run_syft=false
run_dbench=false;   run_inspect=false;  run_semgrep=false
run_runtime=false

for choice in "${CHOICES[@]}"; do
    case "$choice" in
        1) run_trivy=true ;;
        2) run_grype=true ;;
        3) run_syft=true ;;
        4) run_dbench=true ;;
        5) run_inspect=true ;;
        6) run_semgrep=true ;;
        7) run_runtime=true ;;
        8) run_trivy=true;    run_grype=true;    run_syft=true
           run_dbench=true;   run_inspect=true;  run_semgrep=true
           run_runtime=true ;;
        *) echo "[!] Unknown option: $choice — skipping" ;;
    esac
done

echo ""
echo "[*] Selected scans:"
$run_trivy    && echo "    → Trivy CVE scan"
$run_grype    && echo "    → Grype CVE scan"
$run_syft     && echo "    → Syft SBOM generation"
$run_dbench   && echo "    → docker-bench-security CIS benchmark"
$run_inspect  && echo "    → Image inspection (metadata + packages + layers)"
$run_semgrep  && echo "    → Semgrep static analysis"
$run_runtime  && echo "    → Runtime verification (headers, ports, functional response)"
echo ""

# Ensure target image is available locally
echo "[*] Verifying target image is available locally..."
if ! sudo docker image inspect "$TARGET_IMAGE" &>/dev/null; then
    echo "[*] Image not found locally — pulling..."
    sudo docker pull "$TARGET_IMAGE"
fi

# ------------------------------------------------------------------------------
# 1. Trivy — Aqua Security CVE scan
# ------------------------------------------------------------------------------
if $run_trivy; then
    echo ""
    echo "=== [1] Trivy — CVE Scan ==="
    echo "[*] JSON output for programmatic analysis..."
    trivy image --skip-java-db-update --format json --output "$SCAN_DIR/trivy_${IMAGE_TAG}.json" "$TARGET_IMAGE"
    echo "[*] Human-readable summary..."
    trivy image --skip-java-db-update "$TARGET_IMAGE" > "$SCAN_DIR/trivy_${IMAGE_TAG}.txt" 2>&1

    # Extract severity counts for quick view
    if command -v jq &> /dev/null; then
        echo "[*] Severity breakdown:"
        jq -r '[.Results[]?.Vulnerabilities[]?.Severity] | group_by(.) | map({severity: .[0], count: length}) | .[] | "    \(.severity): \(.count)"' \
            "$SCAN_DIR/trivy_${IMAGE_TAG}.json" 2>/dev/null || echo "    (jq parse failed — check JSON manually)"
    fi

    echo "[+] Saved: $SCAN_DIR/trivy_${IMAGE_TAG}.{json,txt}"
fi

# ------------------------------------------------------------------------------
# 2. Grype — Anchore CVE scan (cross-check with Trivy)
# ------------------------------------------------------------------------------
if $run_grype; then
    echo ""
    echo "=== [2] Grype — CVE Scan (second opinion) ==="
    grype "$TARGET_IMAGE" -o json > "$SCAN_DIR/grype_${IMAGE_TAG}.json" 2>/dev/null
    grype "$TARGET_IMAGE" > "$SCAN_DIR/grype_${IMAGE_TAG}.txt" 2>&1

    if command -v jq &> /dev/null; then
        echo "[*] Severity breakdown:"
        jq -r '[.matches[]?.vulnerability.severity] | group_by(.) | map({severity: .[0], count: length}) | .[] | "    \(.severity): \(.count)"' \
            "$SCAN_DIR/grype_${IMAGE_TAG}.json" 2>/dev/null || echo "    (jq parse failed — check JSON manually)"
    fi

    echo "[+] Saved: $SCAN_DIR/grype_${IMAGE_TAG}.{json,txt}"
fi

# ------------------------------------------------------------------------------
# 3. Syft — SBOM generation (CycloneDX + SPDX + human)
# ------------------------------------------------------------------------------
if $run_syft; then
    echo ""
    echo "=== [3] Syft — SBOM Generation ==="
    syft "$TARGET_IMAGE" -o cyclonedx-json > "$SCAN_DIR/sbom_${IMAGE_TAG}.cdx.json" 2>/dev/null
    syft "$TARGET_IMAGE" -o spdx-json      > "$SCAN_DIR/sbom_${IMAGE_TAG}.spdx.json" 2>/dev/null
    syft "$TARGET_IMAGE" -o table          > "$SCAN_DIR/sbom_${IMAGE_TAG}.txt" 2>&1

    COMPONENT_COUNT=$(jq '.components | length' "$SCAN_DIR/sbom_${IMAGE_TAG}.cdx.json" 2>/dev/null || echo "unknown")
    echo "[*] SBOM component count: $COMPONENT_COUNT"
    echo "[+] Saved: $SCAN_DIR/sbom_${IMAGE_TAG}.{cdx.json,spdx.json,txt}"
fi

# ------------------------------------------------------------------------------
# 4. docker-bench-security — CIS Docker Benchmark
# ------------------------------------------------------------------------------
if $run_dbench; then
    echo ""
    echo "=== [4] docker-bench-security — CIS Benchmark ==="
    DBS_DIR="$HOME/tools/docker-bench-security"
    if [ ! -d "$DBS_DIR" ]; then
        echo "[!] docker-bench-security not installed. Run 01_requirements.sh first."
    else
        (cd "$DBS_DIR" && sudo sh docker-bench-security.sh -c container_images) \
            > "$SCAN_DIR/dbench_${IMAGE_TAG}.txt" 2>&1
        echo "[+] Saved: $SCAN_DIR/dbench_${IMAGE_TAG}.txt"
    fi
fi

# ------------------------------------------------------------------------------
# 5. Image inspection — metadata, packages, layer breakdown
# ------------------------------------------------------------------------------
if $run_inspect; then
    echo ""
    echo "=== [5] Image Inspection — Metadata / Packages / Layers ==="

    {
        echo "=== IMAGE INSPECTION: $TARGET_IMAGE ==="
        echo "Captured: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
        echo ""
        echo "--- Digest ---"
        sudo docker inspect "$TARGET_IMAGE" --format='{{index .RepoDigests 0}}' 2>/dev/null || echo "(not from registry)"
        echo ""
        echo "--- Size / Layers ---"
        sudo docker image inspect "$TARGET_IMAGE" --format='Size: {{.Size}} bytes'
        sudo docker image inspect "$TARGET_IMAGE" --format='Layers: {{len .RootFS.Layers}}'
        echo ""
        echo "--- Runtime Config ---"
        sudo docker image inspect "$TARGET_IMAGE" --format='User: [{{.Config.User}}]'
        sudo docker image inspect "$TARGET_IMAGE" --format='Cmd: {{.Config.Cmd}}'
        sudo docker image inspect "$TARGET_IMAGE" --format='Entrypoint: {{.Config.Entrypoint}}'
        sudo docker image inspect "$TARGET_IMAGE" --format='ExposedPorts: {{.Config.ExposedPorts}}'
        echo ""
        echo "--- Environment Variables ---"
        sudo docker image inspect "$TARGET_IMAGE" --format='{{range .Config.Env}}{{println .}}{{end}}'
        echo ""
        echo "--- Installed Packages ---"
        sudo docker run --rm "$TARGET_IMAGE" sh -c "dpkg -l 2>/dev/null || rpm -qa 2>/dev/null || apk info 2>/dev/null" || echo "(no package manager)"
    } > "$SCAN_DIR/inspect_${IMAGE_TAG}.txt"

    echo "[+] Saved: $SCAN_DIR/inspect_${IMAGE_TAG}.txt"

    # Non-interactive dive analysis (CI mode)
    if command -v dive &> /dev/null; then
        echo "[*] Running dive in CI mode (layer efficiency analysis)..."
        CI=true dive "$TARGET_IMAGE" > "$SCAN_DIR/dive_${IMAGE_TAG}.txt" 2>&1 || true
        echo "[+] Saved: $SCAN_DIR/dive_${IMAGE_TAG}.txt"
    fi
fi

# ------------------------------------------------------------------------------
# 6. Semgrep — SAST on Dockerfile / configs (if present in project dir)
# ------------------------------------------------------------------------------
if $run_semgrep; then
    echo ""
    echo "=== [6] Semgrep — Static Analysis ==="

    SEMGREP_TARGET="$PROJECT_DIR/hardened"
    if [ -d "$SEMGREP_TARGET" ] && [ -n "$(ls -A "$SEMGREP_TARGET" 2>/dev/null)" ]; then
        echo "[*] Scanning $SEMGREP_TARGET for Dockerfile/config issues..."
        semgrep --config=auto "$SEMGREP_TARGET" \
            --output "$SCAN_DIR/semgrep_${IMAGE_TAG}.txt" --text 2>&1 | tee "$SCAN_DIR/semgrep_log_${IMAGE_TAG}.txt"
        echo "[+] Saved: $SCAN_DIR/semgrep_${IMAGE_TAG}.txt"
    else
        echo "[!] $SEMGREP_TARGET is empty or missing — skipping."
        echo "    (This will produce findings once you write your hardened Dockerfile.)"
    fi
fi

# ------------------------------------------------------------------------------
# 7. Runtime verification — spin up and probe
# ------------------------------------------------------------------------------
if $run_runtime && [[ "$TARGET_IMAGE" == nginx-hardened* ]]; then
    # The hardened image listens on 8080/8443 and needs a mounted certificate,
    # so it gets its own probe (same output file name and layout).
    echo ""
    echo "=== [7] Runtime Verification (hardened/runtime_probe.sh) ==="
    IMAGE="$TARGET_IMAGE" "$PROJECT_DIR/hardened/runtime_probe.sh" "$SCAN_DIR"
elif $run_runtime; then
    echo ""
    echo "=== [7] Runtime Verification ==="

    CONTAINER_NAME="nginx-scan-runtime-$$"
    HOST_PORT=8081

    echo "[*] Starting container on port $HOST_PORT..."
    sudo docker run -d --name "$CONTAINER_NAME" -p "$HOST_PORT":80 "$TARGET_IMAGE" > /dev/null || {
        # If port 80 isn't exposed, try 443
        sudo docker run -d --name "$CONTAINER_NAME" -p "$HOST_PORT":443 "$TARGET_IMAGE" > /dev/null || {
            echo "[!] Container failed to start. Skipping runtime tests."
            exit 0
        }
    }
    sleep 3

    {
        echo "=== RUNTIME VERIFICATION: $TARGET_IMAGE ==="
        echo "Captured: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
        echo ""
        echo "--- HTTP Response Code ---"
        curl -sk -o /dev/null -w "HTTP %{http_code}\n" "http://localhost:$HOST_PORT/" || echo "no response"
        echo ""
        echo "--- Response Headers ---"
        curl -sk -I "http://localhost:$HOST_PORT/" 2>&1 || echo "no response"
        echo ""
        echo "--- Server Header (fingerprinting check) ---"
        curl -sk -I "http://localhost:$HOST_PORT/" 2>&1 | grep -i "^server:" || echo "(no server header — good)"
        echo ""
        echo "--- Running Process User ---"
        sudo docker exec "$CONTAINER_NAME" ps -eo user,pid,cmd 2>/dev/null || echo "(ps not available)"
        echo ""
        echo "--- Container User (from config) ---"
        sudo docker inspect "$CONTAINER_NAME" --format='{{.Config.User}}'
        echo ""
        echo "--- Exposed Ports ---"
        sudo docker port "$CONTAINER_NAME" || echo "(none)"
    } > "$SCAN_DIR/runtime_${IMAGE_TAG}.txt"

    sudo docker stop "$CONTAINER_NAME" > /dev/null
    sudo docker rm "$CONTAINER_NAME" > /dev/null

    echo "[+] Saved: $SCAN_DIR/runtime_${IMAGE_TAG}.txt"
fi

# ------------------------------------------------------------------------------
# Summary
# ------------------------------------------------------------------------------
echo ""
echo "============================================"
echo "[+] Scan Suite Complete — $SCAN_DIR"
echo "============================================"
ls -la "$SCAN_DIR"
echo ""
echo "Next steps:"
echo "  • Review the output files in $SCAN_DIR"
echo "  • Compare against previous scans of the same image"
echo "  • When your hardened image exists, run: ./03_scanning.sh myhardened:latest"
echo ""
