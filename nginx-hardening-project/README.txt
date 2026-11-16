================================================================================
NGINX Container Hardening — Reference Reproducibility Study — CSCI 7610
Michael Ford | Fall 2026
================================================================================

Project: Reproducing Defense-Grade Container Hardening with Open-Source Tooling.
Independent hardening of upstream nginx:1.30 benchmarked against Iron Bank's
publicly documented hardened 1.30 build. All artifacts and tooling are public;
no DoD credentials required.

nginx-hardening-project Folder Contents
  - 01_requirements.sh    Install all dependencies (Docker, Trivy, Grype, Syft, etc.)
  - 02_baseline.sh        Pull upstream nginx:1.30 and capture baseline metadata
  - 03_scanning.sh        Interactive scan suite (target-parameterized)
  - 04_reference.sh       Fetch Iron Bank's public NGINX artifacts for reference
  - baseline/             Upstream nginx:1.30 metadata and default responses
  - reference/            Iron Bank's public Dockerfile, manifest, and configs
  - hardened/             Your hardened Dockerfile and configs (created in Module D)
  - scans/                All scan output, timestamped and organized by image
  - paper/                Writing artifacts for the Module C/D writeup

How to Run
----------

1. Make the scripts executable:

   chmod +x 01_requirements.sh 02_baseline.sh 03_scanning.sh 04_reference.sh

2. Run them in order:

   ./01_requirements.sh    # One-time setup: installs all tools
   ./02_baseline.sh        # Pull upstream nginx:1.30 and capture baseline
   ./04_reference.sh       # Download Iron Bank's public artifacts
   ./03_scanning.sh        # Run scans against the baseline (default: nginx:1.30)

   Later, when your hardened image exists (Module D):

   ./03_scanning.sh nginx-hardened:latest   # Scan your hardened build
                                            # and compare against baseline scans

3. If Docker group was just added by 01_requirements.sh, log out and back in
   before running the docker-dependent scripts.

Module D — Hardened Build and Scans
-----------------------------------

   The project must live at ~/nginx-hardening-project (the scripts assume it).

   chmod +x *.sh hardened/*.sh
   ./hardened/build.sh                        # fetch + SHA-verify RPM/key, build
                                              # nginx-hardened:latest, smoke test
                                              # (STRIP_SYSTEMD=1 ./hardened/build.sh
                                              #  also removes systemd; see strip.sh)
   ./03_scanning.sh nginx-hardened:latest     # choose 8 (all); option 7 runs
                                              # hardened/runtime_probe.sh
   ./hardened/sign.sh                         # Cosign signature + SBOM attestation

   Bring back: scans/nginx-hardened_latest_<timestamp>/ and
   hardened/build_log_*.txt. Generated, not for submission: test-certs/
   (throwaway TLS key), signing/ (Cosign key pair), hardened/resources/.

   Compare:  python3 tools/scan_metrics.py <baseline_scan_dir> <hardened_scan_dir>

--------------------------------------------------------------------------------
Scan Menu Options (03_scanning.sh)
--------------------------------------------------------------------------------

  --- Vulnerability Scanning ---
  1) trivy         CVE scan (Aqua Security)
  2) grype         CVE scan (Anchore, second opinion)

  --- SBOM & Provenance ---
  3) syft          Generate SBOM in CycloneDX + SPDX + human formats

  --- Configuration & Structure ---
  4) dbench        CIS Docker Benchmark (docker-bench-security)
  5) inspect       Image metadata + package inventory + layer analysis
  6) semgrep       Static analysis of Dockerfile/configs

  --- Runtime Verification ---
  7) runtime       Spin up container and check headers, ports, response

  8) all           Run everything

--------------------------------------------------------------------------------
Iron Bank Reference
--------------------------------------------------------------------------------

  Source: https://repo1.dso.mil/dsop/opensource/nginx/1.30/nginx
  Access: Public (no login required for GitLab-hosted source artifacts)

  Four files matter for the reference methodology:
    - Dockerfile             build recipe (base image, USER, package minimization)
    - hardening_manifest.yaml  machine-readable hardening declaration + CVE justifications
    - README.md              human-readable justifications and known limitations
    - conf/nginx.conf        runtime configuration (headers, TLS, limits, modules)

--------------------------------------------------------------------------------
Scan Output Files
--------------------------------------------------------------------------------

  Per-image, timestamped folders under scans/:

  baseline/
    baseline_digest_YYYYMMDD.txt              exact digest for reproducibility
    baseline_metadata_YYYYMMDD.txt            size, layers, user, cmd, env
    baseline_packages_YYYYMMDD.txt            installed package inventory
    baseline_default_response_YYYYMMDD.html   what upstream nginx serves by default
    baseline_default_headers_YYYYMMDD.txt     default response headers

  scans/<image>_<timestamp>/
    trivy_<image>.{json,txt}         CVE findings (Aqua)
    grype_<image>.{json,txt}         CVE findings (Anchore) — cross-check
    sbom_<image>.{cdx.json,spdx.json,txt}   SBOM in three formats
    dbench_<image>.txt               CIS Docker Benchmark
    inspect_<image>.txt              image metadata + packages
    dive_<image>.txt                 layer-by-layer efficiency
    semgrep_<image>.txt              Dockerfile/config static analysis
    runtime_<image>.txt              live container probe

--------------------------------------------------------------------------------
Reproducibility Notes
--------------------------------------------------------------------------------

  Every scan output includes the target image's digest and a UTC timestamp so
  the "before" and "after" states are directly comparable. If you need to
  rerun a comparison later, use the digest (not the tag) to pin the exact
  image bytes that were scanned.

  Two vulnerability scanners (Trivy + Grype) are used because they draw on
  different databases and disagree on some findings. Reporting both counts —
  and the disagreement between them — is itself a methodological choice.
