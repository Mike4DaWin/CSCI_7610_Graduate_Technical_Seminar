#!/usr/bin/env python3
"""
make_figures.py — regenerate the Section IV figures from scan output.

Usage:
    python3 make_figures.py <baseline_scan_dir> <out_dir> [<hardened_scan_dir>]

Always writes:
    fig_baseline_severity.png   baseline findings by severity, Trivy vs Grype
    fig_baseline_families.png   baseline Trivy findings grouped by package family
With a hardened scan dir it also writes:
    fig_grype_before_after.png  Grype distinct CVEs by severity, upstream vs hardened

Requires matplotlib (pip install matplotlib).
"""
import os
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from scan_metrics import first, load_json, metrics  # noqa: E402

BLUE, ORANGE = "#2a78d6", "#eb6834"          # categorical slots 1 and 2
INK, INK_2, GRID = "#0b0b0b", "#52514e", "#e4e3df"

plt.rcParams.update({
    "font.family": "serif", "font.serif": ["Times New Roman", "Times", "DejaVu Serif"],
    "font.size": 9, "axes.edgecolor": INK_2, "axes.labelcolor": INK, "xtick.color": INK_2,
    "ytick.color": INK_2, "axes.spines.top": False, "axes.spines.right": False,
    "savefig.dpi": 300, "savefig.bbox": "tight",
})

# Package families for the Debian-based upstream image. Each bucket names why the
# packages are there, so the chart shows where attack surface comes from.
FAMILIES = [
    ("Shell & base utilities", {"bash", "dash", "coreutils", "util-linux", "bsdutils", "mount", "login",
                                "passwd", "libblkid1", "libmount1", "libsmartcols1", "libuuid1", "findutils",
                                "sed", "grep", "tar", "gzip", "libpam0g", "libpam-modules", "libpam-modules-bin",
                                "libpam-runtime", "libaudit1", "libaudit-common", "libsystemd0", "libudev1",
                                "ncurses-base", "ncurses-bin", "libtinfo6", "sysvinit-utils", "libselinux1",
                                "libsemanage2", "libsepol2", "libcap-ng0", "libacl1", "libattr1", "libcrypt1",
                                "libdb5.3t64", "libsqlite3-0", "hostname", "debianutils", "diffutils",
                                "login.defs", "libcap2", "liblastlog2-2"}),
    ("curl / libcurl + deps", {"curl", "libcurl4t64", "libldap2", "libkrb5support0", "libkrb5-3",
                               "libk5crypto3", "libgssapi-krb5-2", "libnghttp2-14"}),
    ("Optional module libs", None),  # image-filter, xslt, geoip (filled by prefix test below)
    ("glibc", {"libc-bin", "libc6"}),
    ("Perl", {"perl-base"}),
]
MODULE_PREFIXES = ("libheif", "libtiff", "libavif", "libgd", "libjpeg", "libpng", "libfreetype", "libfontconfig",
                   "fontconfig", "libx11", "libxpm", "libwebp", "libdav1d", "libde265", "libsharpyuv", "libaom",
                   "libdeflate", "libjbig", "liblerc", "libxau", "libxcb", "libxdmcp", "libyuv", "libxml2",
                   "libxslt", "libgeoip", "libicu", "libexpat")


def family(pkg):
    pkg = pkg.split(":")[0]
    for name, members in FAMILIES:
        if members and pkg in members:
            return name
    if pkg.startswith(MODULE_PREFIXES):
        return "Optional module libs"
    return "Other"


def bar_labels(ax, bars, fmt="{:d}"):
    for b in bars:
        h = b.get_height()
        ax.annotate(fmt.format(int(h)), (b.get_x() + b.get_width() / 2, h), xytext=(0, 2),
                    textcoords="offset points", ha="center", va="bottom", fontsize=8, color=INK)


def fig_severity(m, out):
    cats = ["Critical", "High", "Medium", "Low", "Negligible", "Unknown"]
    trivy = [m["trivy_by_severity"].get(c.upper(), 0) if c != "Negligible" else 0 for c in cats]
    grype = [m["grype_by_severity"].get(c, 0) for c in cats]
    x = range(len(cats))
    w = 0.38
    fig, ax = plt.subplots(figsize=(6.0, 2.8))
    b1 = ax.bar([i - w / 2 - 0.01 for i in x], trivy, w, color=BLUE, label=f"Trivy (total {m['trivy_total']})")
    b2 = ax.bar([i + w / 2 + 0.01 for i in x], grype, w, color=ORANGE, label=f"Grype (total {m['grype_total']})")
    bar_labels(ax, [b for b, c in zip(b1, cats) if c != "Negligible"])
    bar_labels(ax, b2)
    ax.annotate("n/a", (4 - w / 2 - 0.01, 1), ha="center", va="bottom", fontsize=7, color=INK_2)  # Trivy has no Negligible tier
    ax.set_xticks(list(x), cats)
    ax.set_ylabel("Findings (package–CVE matches)")
    ax.set_ylim(0, max(trivy + grype) * 1.22)
    ax.yaxis.grid(True, color=GRID, linewidth=0.6)
    ax.set_axisbelow(True)
    ax.legend(frameon=False, loc="upper left")
    fig.savefig(os.path.join(out, "fig_baseline_severity.png"))
    plt.close(fig)


def fig_families(scan_dir, out):
    t = load_json(first(os.path.join(scan_dir, "trivy_*.json")))
    vulns = [v for r in t.get("Results", []) for v in (r.get("Vulnerabilities") or [])]
    counts = {}
    for v in vulns:
        counts[family(v["PkgName"])] = counts.get(family(v["PkgName"]), 0) + 1
    items = sorted(counts.items(), key=lambda kv: (kv[0] == "Other", -kv[1]))[::-1]
    fig, ax = plt.subplots(figsize=(6.0, 2.6))
    bars = ax.barh([k for k, _ in items], [v for _, v in items], color=BLUE, height=0.6)
    total = len(vulns)
    for b, (_, v) in zip(bars, items):
        ax.annotate(f"{v}  ({100 * v / total:.0f}%)", (b.get_width(), b.get_y() + b.get_height() / 2),
                    xytext=(3, 0), textcoords="offset points", va="center", fontsize=8, color=INK)
    ax.set_xlabel(f"Trivy findings (n = {total})")
    ax.xaxis.grid(True, color=GRID, linewidth=0.6)
    ax.set_axisbelow(True)
    ax.set_xlim(0, max(counts.values()) * 1.25)
    fig.savefig(os.path.join(out, "fig_baseline_families.png"))
    plt.close(fig)
    return counts


def fig_before_after(a, b, out):
    # Grype, not Trivy: Trivy 0.74/0.76 has no RHEL 10 data and reports 0 for the
    # hardened image. Distinct CVEs, so one CVE in six util-linux subpackages counts once.
    cats = ["Critical", "High", "Medium", "Low", "Negligible", "Unknown"]
    x = range(len(cats))
    w = 0.38
    fig, ax = plt.subplots(figsize=(6.0, 2.8))
    b1 = ax.bar([i - w / 2 - 0.01 for i in x], [a["grype_unique_by_severity"][c] for c in cats], w, color=BLUE,
                label=f"Upstream nginx:1.30 (total {a['grype_unique_cves']})")
    b2 = ax.bar([i + w / 2 + 0.01 for i in x], [b["grype_unique_by_severity"][c] for c in cats], w, color=ORANGE,
                label=f"Hardened build (total {b['grype_unique_cves']})")
    bar_labels(ax, b1)
    bar_labels(ax, b2)
    ax.set_xticks(list(x), cats)
    ax.set_ylabel("Distinct CVEs (Grype)")
    ax.set_ylim(0, max(max(a["grype_unique_by_severity"].values()), max(b["grype_unique_by_severity"].values())) * 1.22)
    ax.yaxis.grid(True, color=GRID, linewidth=0.6)
    ax.set_axisbelow(True)
    ax.legend(frameon=False, loc="upper right")
    fig.savefig(os.path.join(out, "fig_grype_before_after.png"))
    plt.close(fig)

if __name__ == "__main__":
    if len(sys.argv) not in (3, 4):
        sys.exit(__doc__)
    base_dir, out_dir = sys.argv[1], sys.argv[2]
    os.makedirs(out_dir, exist_ok=True)
    base = metrics(base_dir)
    fig_severity(base, out_dir)
    print("families:", fig_families(base_dir, out_dir))
    if len(sys.argv) == 4:
        fig_before_after(base, metrics(sys.argv[3]), out_dir)
    print("figures written to", out_dir)
