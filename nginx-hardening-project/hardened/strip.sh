#!/bin/bash
# ==============================================================================
# strip.sh — runs inside the image build (see Dockerfile), then is deleted.
#
# Removes everything `microdnf install dnf` pulled in (dnf, python3, ...) plus
# the microdnf stack, EXCEPT packages that something still installed needs.
# `microdnf install dnf` also brings in systemd, shadow-utils and libxcrypt,
# which nginx requires, so those are kept: each `rpm -e --test` pass names a
# still-needed capability, whatever provides it is kept, and the pass repeats
# until the removal set is clean.
#
# STRIP_SYSTEMD=1 also drops systemd (and what only it needs). nginx's RPM
# lists systemd as a requirement, but the nginx binary doesn't link it and
# never runs it inside a container; this goes beyond Iron Bank's recipe.
# ==============================================================================

CAND=$( { comm -13 /tmp/pkgs.before-dnf /tmp/pkgs.with-dnf
          printf '%s\n' microdnf libdnf librepo libsolv libmodulemd; } | sort -u )
CAND=$(rpm -q --qf '%{NAME}\n' $CAND 2>/dev/null | grep -v 'is not installed' | sort -u)
IGNORE='^$'
[ "${STRIP_SYSTEMD:-0}" = "1" ] && IGNORE='^[[:space:]]*systemd is needed by \(installed\) nginx-'

for pass in $(seq 1 25); do
    [ -n "$CAND" ] || break
    needed=$(rpm -e --test $CAND 2>&1 | grep 'is needed by (installed)' | grep -vE "$IGNORE")
    [ -z "$needed" ] && break
    # A capability is "libfoo.so.1()(64bit)", "dbus >= 1:1.9", or a rich
    # dependency such as "(util-linux-core or util-linux)": keep every
    # installed package that provides any name in it.
    keep=$(echo "$needed" | sed 's/ is needed by (installed) .*//; s/^[[:space:]]*//' | sort -u | while read -r cap; do
               if [ "${cap#(}" != "$cap" ]; then
                   names=$(echo "$cap" | tr -d '()' | tr ' ' '\n' \
                           | grep -vxE 'or|and|if|else|with|without|unless|[<>=]+|[0-9].*')
               else
                   names=${cap%% *}
               fi
               for n in $names; do
                   rpm -q --whatprovides "$n" --qf '%{NAME}\n' 2>/dev/null | grep -v '^no package provides'
               done
           done | sort -u)
    echo "[strip] pass $pass keeps (still required): $(echo $keep)"
    NEXT=$(comm -23 <(echo "$CAND") <(echo "$keep"))
    [ "$NEXT" = "$CAND" ] && { echo "[strip] no progress; unresolved:"; echo "$needed"; break; }
    CAND=$NEXT
done

echo "[strip] removing: $(echo $CAND)"
if [ -n "$CAND" ]; then
    if [ "${STRIP_SYSTEMD:-0}" = "1" ]; then
        # --noscripts: systemd's uninstall scriptlets call systemctl, which is going away too
        rpm -e --nodeps --noscripts $CAND
    else
        rpm -e $CAND
    fi || {
        echo "[strip] removal failed; removing package-manager packages only"
        rpm -qa --qf '%{NAME}\n' | grep -E '^(dnf|dnf-data|python3-dnf|python3-libdnf|python3-hawkey|microdnf|libdnf|libdnf5|dnf5|dnf-plugins-core|python3-dnf-plugins-core)$' \
            | xargs -r rpm -e --nodeps
    }
fi
