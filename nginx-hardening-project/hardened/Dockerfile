# ==============================================================================
# Independent hardened build of NGINX 1.30 — CSCI 7610 (Michael Ford)
#
# Mirrors Iron Bank's public recipe (reference/Dockerfile) using only public
# inputs, then adds the configuration-level controls from Methodology Table 1.
# Build with ./build.sh — it downloads and SHA-256-verifies the same resources
# listed in Iron Bank's hardening_manifest.yaml before calling docker build.
# ==============================================================================

# Iron Bank: registry1.dso.mil/ironbank/redhat/ubi/ubi10-minimal:10.2 (login required)
# Here:      the same UBI 10 minimal image from Red Hat's public registry (no login)
# Pinned to the multi-arch index digest of 10.2 as of 2026-10-26 so every rebuild
# starts from identical bytes (build.sh prints the digest it actually used).
ARG BASE_IMAGE=registry.access.redhat.com/ubi10/ubi-minimal
ARG BASE_TAG=10.2@sha256:ab67cd02caf8706e34a695a1432ebe965934f6128ec352a6c3f4048b43a4fb5e

FROM ${BASE_IMAGE}:${BASE_TAG}

# 1 = remove dnf/microdnf after install (package-manager removal control)
# 1 = also remove bash (shell removal control; nginx runs without a shell)
# 1 = also remove systemd (required by nginx's RPM, unused in a container)
ARG STRIP_PKG_MGR=1
ARG STRIP_SHELL=0
ARG STRIP_SYSTEMD=0

LABEL org.opencontainers.image.title="nginx-hardened" \
      org.opencontainers.image.description="Independent open-source hardening of NGINX 1.30 benchmarked against Iron Bank" \
      org.opencontainers.image.version="1.30.4" \
      org.opencontainers.image.licenses="BSD-2-Clause" \
      org.opencontainers.image.authors="Michael Ford"

USER root

# Same three resources as Iron Bank's hardening_manifest.yaml (verified by build.sh)
COPY resources/nginx.rpm /tmp/nginx.rpm
COPY resources/nginx_signing.key /etc/pki/rpm-gpg/nginx_signing.key
COPY conf/nginx.conf /tmp/nginx.conf
COPY conf/index.html /tmp/index.html
COPY strip.sh /tmp/strip.sh

# --- Install (same package path as Iron Bank), then strip ---------------------
# Stripping must happen in this same RUN: files deleted in a later layer still
# ship in this one, so the image would not get any smaller.
# strip.sh removes what dnf pulled in, keeping anything nginx still needs.
RUN rpm --import /etc/pki/rpm-gpg/nginx_signing.key && \
    rpm -K /tmp/nginx.rpm && \
    microdnf -y update && \
    # Snapshot package names so the strip step knows exactly what dnf pulled in
    rpm -qa --qf '%{NAME}\n' | sort -u > /tmp/pkgs.before-dnf && \
    microdnf -y install dnf && \
    rpm -qa --qf '%{NAME}\n' | sort -u > /tmp/pkgs.with-dnf && \
    dnf -y install --setopt=install_weak_deps=False --nodocs /tmp/nginx.rpm && \
    dnf clean all && \
    rm -rf /var/cache/dnf /var/cache/microdnf /tmp/nginx.rpm && \
    if [ "$STRIP_PKG_MGR" = "1" ]; then STRIP_SYSTEMD="$STRIP_SYSTEMD" bash /tmp/strip.sh ; fi && \
    rm -f /tmp/pkgs.* /tmp/strip.sh

# --- Default file removal + hardened configuration ----------------------------
RUN rm -f /etc/nginx/conf.d/default.conf \
          /etc/nginx/fastcgi_params /etc/nginx/scgi_params /etc/nginx/uwsgi_params && \
    rm -rf /usr/share/nginx/html/* /usr/share/doc/* /usr/share/man/* && \
    mv /tmp/nginx.conf /etc/nginx/nginx.conf && \
    mv /tmp/index.html /usr/share/nginx/html/index.html && \
    mkdir -p /etc/nginx/certs /var/cache/nginx && \
    # Config stays root-owned and read-only to the runtime user (Iron Bank chowns
    # /etc/nginx to nginx; this is stricter). Only cache/log paths are writable.
    chown -R root:root /etc/nginx /usr/share/nginx/html && \
    chmod -R go-w /etc/nginx /usr/share/nginx/html && \
    chown -R nginx:nginx /var/cache/nginx /var/log/nginx && \
    ln -sf /dev/stdout /var/log/nginx/access.log && \
    ln -sf /dev/stderr /var/log/nginx/error.log && \
    # CIS Docker Benchmark 4.8: strip setuid/setgid bits
    find / -xdev -type f -perm /6000 -exec chmod a-s {} + 2>/dev/null || true

# --- Optional shell removal (last, because later RUN steps need a shell) ------
RUN if [ "$STRIP_SHELL" = "1" ]; then rpm -e --nodeps bash ; fi && \
    echo "[strip] packages remaining: $(rpm -qa | wc -l)"

USER nginx

# Unprivileged ports, matching Iron Bank (8080 HTTP -> redirect, 8443 HTTPS)
EXPOSE 8080 8443

# No shell-script entrypoint: nginx runs directly, so the image works with the
# shell removed. CMD-only (no ENTRYPOINT) keeps 03_scanning.sh's
# `docker run <image> sh -c ...` inventory step working while a shell exists.
STOPSIGNAL SIGQUIT
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD ["nginx", "-t", "-q"]
CMD ["nginx", "-g", "daemon off;"]
