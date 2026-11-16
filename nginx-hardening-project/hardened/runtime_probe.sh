#!/bin/bash
# ==============================================================================
# runtime_probe.sh — runtime check for the hardened image
#
# 03_scanning.sh option 7 maps host 8081 -> container port 80, but the hardened
# image (like Iron Bank's) listens on 8080/8443 and needs a mounted certificate,
# so option 7 cannot reach it. This script writes runtime_<image>.txt in the same
# layout into the scan folder you pass, so both images are compared the same way.
#
# Usage: ./runtime_probe.sh ~/nginx-hardening-project/scans/nginx-hardened_latest_<timestamp>
# ==============================================================================

set -e
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCAN_DIR="${1:?usage: $0 <scan_dir>}"
IMAGE="${IMAGE:-nginx-hardened:latest}"
TAG=$(echo "$IMAGE" | tr '/:' '__')
NAME="nginx-hardened-probe-$$"
CERT_DIR="$(cd "$HERE/.." && pwd)/test-certs"   # created by build.sh

[ -s "$CERT_DIR/tls.crt" ] || { echo "[!] $CERT_DIR/tls.crt missing — run hardened/build.sh first."; exit 1; }
sudo docker run -d --name "$NAME" -p 8090:8080 -p 8453:8443 \
    -v "$CERT_DIR:/etc/nginx/certs:ro" "$IMAGE" > /dev/null
sleep 3

{
    echo "=== RUNTIME VERIFICATION: $IMAGE ==="
    echo "Captured: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    echo ""
    echo "--- HTTP Response Code ---"
    curl -sk -o /dev/null -w "HTTP %{http_code}\n" "https://localhost:8453/" || echo "no response"
    echo ""
    echo "--- Response Headers ---"
    curl -sk -I "https://localhost:8453/" 2>&1 || echo "no response"
    echo ""
    echo "--- Plain HTTP (expect 301 to HTTPS) ---"
    curl -s -I "http://localhost:8090/" 2>&1 | head -3 || echo "no response"
    echo ""
    echo "--- Server Header (fingerprinting check) ---"
    curl -sk -I "https://localhost:8453/" 2>&1 | grep -i "^server:" || echo "(no server header — good)"
    echo ""
    echo "--- TLS protocol support ---"
    # SECLEVEL=0 lets the client offer TLS 1.0/1.1, so "rejected" reflects the
    # server; the handshake error in parentheses is the evidence.
    for p in tls1 tls1_1 tls1_2 tls1_3; do
        out=$(openssl s_client -connect localhost:8453 -servername localhost -$p \
              -cipher 'DEFAULT:@SECLEVEL=0' </dev/null 2>&1 || true)
        if echo "$out" | grep -q '^New, TLS'; then
            echo "$p: accepted ($(echo "$out" | grep -m1 '^New, TLS'))"
        elif echo "$out" | grep -qi 'no protocols available\|unknown option'; then
            echo "$p: untested (client cannot offer it)"
        else
            echo "$p: rejected ($(echo "$out" | grep -m1 -iE 'alert|error' | sed 's/^[0-9A-F]*:error://' | cut -c1-90))"
        fi
    done
    echo ""
    echo "--- Running Process User ---"
    sudo docker exec "$NAME" id 2>/dev/null || echo "(unavailable)"
    # UIDs as seen from the host; user names here are the host's, not the container's
    sudo docker top "$NAME" -eo uid,pid,args 2>/dev/null || echo "(unavailable)"
    echo ""
    echo "--- Shell available in container? ---"
    sudo docker exec "$NAME" /bin/sh -c 'echo yes' 2>/dev/null || echo "no (exec /bin/sh failed)"
    echo ""
    echo "--- Container User (from config) ---"
    sudo docker inspect "$NAME" --format='{{.Config.User}}'
    echo ""
    echo "--- Exposed Ports ---"
    sudo docker port "$NAME" || echo "(none)"
    echo ""
    echo "--- Container log (last 10 lines) ---"
    sudo docker logs "$NAME" 2>&1 | tail -10
} > "$SCAN_DIR/runtime_${TAG}.txt"

sudo docker rm -f "$NAME" > /dev/null
echo "[+] Saved: $SCAN_DIR/runtime_${TAG}.txt"
