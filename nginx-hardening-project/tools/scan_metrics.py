#!/usr/bin/env python3
"""
scan_metrics.py — pull the Section IV numbers out of a 03_scanning.sh output folder.

Usage:
    python3 scan_metrics.py <scan_dir>                    # one image
    python3 scan_metrics.py <baseline_dir> <hardened_dir> # side-by-side + % reduction

<scan_dir> is a folder such as scans/nginx_1.30_20260918_140013 that holds
trivy_*.json, grype_*.json, sbom_*.cdx.json, inspect_*.txt and runtime_*.txt.
Only the standard library is used, so this runs as-is on the Kali VM.
"""
import collections
import glob
import json
import os
import re
import sys

TRIVY_SEVS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
GRYPE_SEVS = ["Critical", "High", "Medium", "Low", "Negligible", "Unknown"]
SHELLS = ("bash", "dash", "sh", "busybox", "zsh")
PKG_MANAGERS = ("apt", "dpkg", "dnf", "microdnf", "yum", "rpm", "apk")


def first(pattern):
    hits = sorted(glob.glob(pattern))
    return hits[0] if hits else None


def load_json(path):
    if not path:
        return None
    with open(path) as f:
        return json.load(f)


def read_text(path):
    if not path:
        return ""
    with open(path, errors="replace") as f:
        return f.read()


def metrics(scan_dir):
    m = {"scan_dir": os.path.basename(os.path.normpath(scan_dir))}

    # --- image inspection ---------------------------------------------------
    inspect = read_text(first(os.path.join(scan_dir, "inspect_*.txt")))
    size = re.search(r"Size:\s*(\d+)\s*bytes", inspect)
    layers = re.search(r"Layers:\s*(\d+)", inspect)
    user = re.search(r"User:\s*\[(.*?)\]", inspect)
    ports = re.search(r"ExposedPorts:\s*map\[(.*?)\]\n", inspect)
    digest = re.search(r"--- Digest ---\n(\S+)", inspect)
    m["digest"] = digest.group(1) if digest else None
    m["size_bytes"] = int(size.group(1)) if size else None
    m["size_mb"] = round(m["size_bytes"] / 1_000_000, 1) if size else None
    m["layers"] = int(layers.group(1)) if layers else None
    m["user"] = (user.group(1) or "root (unset)") if user else None
    m["exposed_ports"] = re.findall(r"(\d+/\w+)", ports.group(1)) if ports else []

    # --- installed packages (dpkg -l / rpm -qa / apk info in inspect file) --
    pkg_section = inspect.split("--- Installed Packages ---", 1)[-1] if inspect else ""
    if "\nii  " in pkg_section:  # Debian
        names = [l.split()[1].split(":")[0] for l in pkg_section.splitlines() if l.startswith("ii ")]
    else:  # rpm -qa / apk info: one package per line
        # gpg-pubkey entries are imported signing keys, not installed software
        names = [l.strip() for l in pkg_section.splitlines()
                 if l.strip() and not l.startswith(("(", "OCI", "docker:", "gpg-pubkey"))]
    m["package_count"] = len(names) if names else None
    base = lambda n: re.sub(r"-\d.*$", "", n)  # strip rpm version suffix
    m["shell_present"] = any(base(n) in SHELLS for n in names) if names else None
    m["package_manager_present"] = any(base(n) in PKG_MANAGERS for n in names) if names else None
    m["package_managers"] = sorted({base(n) for n in names} & set(PKG_MANAGERS))

    # --- Trivy ----------------------------------------------------------------
    t = load_json(first(os.path.join(scan_dir, "trivy_*.json")))
    if t:
        vulns = [v for r in t.get("Results", []) for v in (r.get("Vulnerabilities") or [])]
        c = collections.Counter(v["Severity"] for v in vulns)
        m["trivy_total"] = len(vulns)
        m["trivy_by_severity"] = {s: c.get(s, 0) for s in TRIVY_SEVS}
        m["trivy_unique_cves"] = len({v["VulnerabilityID"] for v in vulns})
        m["trivy_fixable"] = sum(1 for v in vulns if v.get("FixedVersion"))
        m["trivy_os"] = "{Family} {Name}".format(**t.get("Metadata", {}).get("OS", {"Family": "?", "Name": "?"}))

    # --- Grype ----------------------------------------------------------------
    g = load_json(first(os.path.join(scan_dir, "grype_*.json")))
    if g:
        matches = g.get("matches", [])
        c = collections.Counter(x["vulnerability"]["severity"] for x in matches)
        m["grype_total"] = len(matches)
        m["grype_by_severity"] = {s: c.get(s, 0) for s in GRYPE_SEVS}
        m["grype_unique_cves"] = len({x["vulnerability"]["id"] for x in matches})
        m["grype_fix_state"] = dict(collections.Counter(x["vulnerability"].get("fix", {}).get("state") for x in matches))
        m["grype_fixable"] = m["grype_fix_state"].get("fixed", 0)
        # One CVE can match several subpackages (libblkid, libmount, ...); count it
        # once, at the highest severity any match reports.
        worst = {}
        for x in matches:
            i, sev = x["vulnerability"]["id"], x["vulnerability"]["severity"]
            if i not in worst or GRYPE_SEVS.index(sev) < GRYPE_SEVS.index(worst[i]):
                worst[i] = sev
        c = collections.Counter(worst.values())
        m["grype_unique_by_severity"] = {s: c.get(s, 0) for s in GRYPE_SEVS}

    # --- SBOM (Syft CycloneDX) -------------------------------------------------
    cdx = load_json(first(os.path.join(scan_dir, "sbom_*.cdx.json")))
    if cdx:
        comps = cdx.get("components", [])
        types = collections.Counter(x.get("type") for x in comps)
        m["sbom_packages"] = sum(1 for x in comps if x.get("type") == "library"
                                 and not x.get("name", "").startswith("gpg-pubkey"))
        m["sbom_files"] = types.get("file", 0)
        m["sbom_components_total"] = len(comps)

    # --- runtime probe ------------------------------------------------------
    runtime = read_text(first(os.path.join(scan_dir, "runtime_*.txt")))
    code = re.search(r"HTTP (\d{3})", runtime)
    server = re.search(r"^Server:\s*(.+)$", runtime, re.M | re.I)
    m["http_status"] = int(code.group(1)) if code else None
    m["server_header"] = server.group(1).strip() if server else "(absent)"
    for h in ("Strict-Transport-Security", "X-Content-Type-Options", "X-Frame-Options",
              "Content-Security-Policy", "Referrer-Policy"):
        m["hdr_" + h] = bool(re.search(r"^" + h + r":", runtime, re.M | re.I))
    # runtime_probe.sh lines such as "tls1_1: rejected (...)"
    m["tls"] = dict(re.findall(r"^(tls1(?:_\d)?): (\w+)", runtime, re.M))
    return m


def pct_reduction(before, after):
    if isinstance(before, bool) or not isinstance(before, (int, float)) or not isinstance(after, (int, float)) or before == 0:
        return None
    return round(100 * (before - after) / before, 1)


def compare(a, b):
    rows = [
        ("Image size (MB)", a.get("size_mb"), b.get("size_mb")),
        ("Layer count", a.get("layers"), b.get("layers")),
        ("Installed packages", a.get("package_count"), b.get("package_count")),
        ("SBOM packages (Syft)", a.get("sbom_packages"), b.get("sbom_packages")),
        ("Trivy findings (total)", a.get("trivy_total"), b.get("trivy_total")),
    ]
    rows += [(f"  Trivy {s.title()}", a.get("trivy_by_severity", {}).get(s), b.get("trivy_by_severity", {}).get(s)) for s in TRIVY_SEVS]
    rows += [("Grype findings (total)", a.get("grype_total"), b.get("grype_total"))]
    rows += [(f"  Grype {s}", a.get("grype_by_severity", {}).get(s), b.get("grype_by_severity", {}).get(s)) for s in GRYPE_SEVS]
    rows += [("Grype unique CVEs", a.get("grype_unique_cves"), b.get("grype_unique_cves"))]
    rows += [(f"  Unique {s}", a.get("grype_unique_by_severity", {}).get(s), b.get("grype_unique_by_severity", {}).get(s)) for s in GRYPE_SEVS]
    rows += [("Grype fixable matches", a.get("grype_fixable"), b.get("grype_fixable"))]
    rows += [
        ("Exposed ports", ", ".join(a.get("exposed_ports", [])), ", ".join(b.get("exposed_ports", []))),
        ("Runtime user", a.get("user"), b.get("user")),
        ("Shell present", a.get("shell_present"), b.get("shell_present")),
        ("Package managers present", ", ".join(a.get("package_managers", [])), ", ".join(b.get("package_managers", []))),
        ("Server header", a.get("server_header"), b.get("server_header")),
    ]
    print(f"| Metric | Baseline | Hardened | Reduction |\n|---|---|---|---|")
    for name, x, y in rows:
        r = pct_reduction(x, y)
        print(f"| {name} | {x} | {y} | {'' if r is None else str(r) + '%'} |")


if __name__ == "__main__":
    if len(sys.argv) == 2:
        print(json.dumps(metrics(sys.argv[1]), indent=2))
    elif len(sys.argv) == 3:
        a, b = metrics(sys.argv[1]), metrics(sys.argv[2])
        compare(a, b)
        print("\nRaw metrics:\n" + json.dumps({"baseline": a, "hardened": b}, indent=2))
    else:
        sys.exit(__doc__)
