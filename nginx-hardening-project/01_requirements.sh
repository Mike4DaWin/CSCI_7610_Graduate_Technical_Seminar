#!/bin/bash

# ==============================================================================
# 01_requirements.sh
# Reproducing Defense-Grade Container Hardening with Open-Source Tooling
# Project: CSCI 7610 — Graduate Technical Seminar
# Author: Michael Ford
# Environment: Kali Linux (KVM)
# ==============================================================================

set -e

echo "=== Pre-flight: Environment Health Checks ==="

echo "[*] Syncing system clock..."
sudo timedatectl set-ntp true

echo "[*] Remounting filesystem as read-write (KVM filesystem guard)..."
sudo mount -o remount,rw / 2>/dev/null || true

echo "[*] Verifying Kali rolling repository..."
grep -q "kali-rolling" /etc/apt/sources.list || \
    echo "deb http://http.kali.org/kali kali-rolling main contrib non-free non-free-firmware" \
    | sudo tee -a /etc/apt/sources.list

echo "[*] Clearing stale apt cache..."
sudo rm -rf /var/lib/apt/lists/*

echo "=== Installing Core Dependencies ==="
sudo apt update && sudo apt install -y \
    docker.io \
    docker-compose \
    curl \
    wget \
    git \
    jq \
    apt-transport-https \
    gnupg \
    ca-certificates \
    python3-pip

echo "=== Starting and Enabling Docker ==="
sudo systemctl start docker
sudo systemctl enable docker

# Add current user to docker group so subsequent docker commands don't need sudo
if ! groups "$USER" | grep -q docker; then
    echo "[*] Adding $USER to docker group..."
    sudo usermod -aG docker "$USER"
    echo "[!] You must log out and back in (or run 'newgrp docker') for group changes to take effect."
fi

# ------------------------------------------------------------------------------
# Trivy — Aqua Security vulnerability scanner
# ------------------------------------------------------------------------------
echo "=== Installing Trivy (Aqua Security) ==="
if ! command -v trivy &> /dev/null; then
    wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo gpg --dearmor -o /usr/share/keyrings/trivy.gpg
    echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" \
        | sudo tee /etc/apt/sources.list.d/trivy.list
    sudo apt update
    sudo apt install -y trivy
else
    echo "[*] Trivy already installed."
fi

# ------------------------------------------------------------------------------
# Grype — Anchore vulnerability scanner (second opinion)
# ------------------------------------------------------------------------------
echo "=== Installing Grype (Anchore) ==="
if ! command -v grype &> /dev/null; then
    curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | \
        sudo sh -s -- -b /usr/local/bin
else
    echo "[*] Grype already installed."
fi

# ------------------------------------------------------------------------------
# Syft — Anchore SBOM generator
# ------------------------------------------------------------------------------
echo "=== Installing Syft (Anchore SBOM) ==="
if ! command -v syft &> /dev/null; then
    curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | \
        sudo sh -s -- -b /usr/local/bin
else
    echo "[*] Syft already installed."
fi

# ------------------------------------------------------------------------------
# Cosign — Sigstore signing and attestation
# ------------------------------------------------------------------------------
echo "=== Installing Cosign (Sigstore) ==="
if ! command -v cosign &> /dev/null; then
    curl -O -L "https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64"
    sudo mv cosign-linux-amd64 /usr/local/bin/cosign
    sudo chmod +x /usr/local/bin/cosign
else
    echo "[*] Cosign already installed."
fi

# ------------------------------------------------------------------------------
# dive — layer-by-layer image inspector
# ------------------------------------------------------------------------------
echo "=== Installing dive (image layer inspector) ==="
if ! command -v dive &> /dev/null; then
    DIVE_VERSION=$(curl -sL "https://api.github.com/repos/wagoodman/dive/releases/latest" | \
        grep '"tag_name":' | sed -E 's/.*"v([^"]+)".*/\1/')
    wget "https://github.com/wagoodman/dive/releases/download/v${DIVE_VERSION}/dive_${DIVE_VERSION}_linux_amd64.deb"
    sudo apt install -y "./dive_${DIVE_VERSION}_linux_amd64.deb"
    rm "dive_${DIVE_VERSION}_linux_amd64.deb"
else
    echo "[*] dive already installed."
fi

# ------------------------------------------------------------------------------
# docker-bench-security — CIS Docker Benchmark
# ------------------------------------------------------------------------------
echo "=== Installing docker-bench-security ==="
DBS_DIR="$HOME/tools/docker-bench-security"
if [ ! -d "$DBS_DIR" ]; then
    mkdir -p "$HOME/tools"
    git clone https://github.com/docker/docker-bench-security.git "$DBS_DIR"
else
    echo "[*] docker-bench-security already cloned."
fi

# ------------------------------------------------------------------------------
# Semgrep — SAST (reused from OpenEMR project)
# ------------------------------------------------------------------------------
echo "=== Installing Semgrep (SAST) ==="
if ! command -v semgrep &> /dev/null; then
    pip install semgrep --break-system-packages
else
    echo "[*] Semgrep already installed."
fi

echo ""
echo "=== Verifying Installed Versions ==="
docker --version
docker-compose --version 2>/dev/null || true
trivy --version | head -1
grype --version
syft --version
cosign version 2>&1 | head -3
dive --version
semgrep --version

echo ""
echo "[+] All tools installed successfully."
echo "    Run 02_baseline.sh next to pull nginx:1.30 and capture baseline scans."
echo ""
echo "[!] If Docker group was just added, log out and back in first."
