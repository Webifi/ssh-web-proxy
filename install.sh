#!/bin/bash
# Install OR update ssh-web-proxy as a systemd service.
#
# The same one-liner does both — re-running pulls the latest script,
# overwrites the binary, and restarts the service:
#
#   curl -fsSL https://raw.githubusercontent.com/Webifi/ssh-web-proxy/main/install.sh | sudo bash
#
# By default, binds to the first RFC 1918 private IPv4 on this host
# (10.x.x.x, 172.16-31.x.x, 192.168.x.x). Refuses to install if no
# private address exists, so the listener is never accidentally
# published on a public-facing interface.
#
# Override via env vars:
#   sudo SERVICE_USER=admin BIND=10.0.0.5 PORT=8888 bash install.sh
#
set -euo pipefail

SERVICE_USER="${SERVICE_USER:-${SUDO_USER:-$USER}}"
PORT="${PORT:-9999}"
# Use the GitHub API "contents" endpoint with Accept:
# application/vnd.github.raw to fetch the actual file body. This
# bypasses raw.githubusercontent.com, which has a ~5-minute CDN
# cache that makes re-running install.sh right after a push appear
# to do nothing. The API has a 60 req/hr unauthenticated rate limit
# but at 3 files per install that's 20 installs/hour from any one
# source IP — fine for normal use.
API_BASE="https://api.github.com/repos/Webifi/ssh-web-proxy/contents"
MAIN_URL="$API_BASE/ssh_web_proxy.py"
REMOTE_DIAG_URL="$API_BASE/remote_diag.py"
INDEX_TPL_URL="$API_BASE/templates/index.html"
RAW_ACCEPT='Accept: application/vnd.github.raw'

# All app files live under /opt/ssh-web-proxy/ (single self-contained
# tree, common convention for third-party server apps — same layout
# as /opt/google/chrome, /opt/plexmediaserver, /opt/zoom, etc.).
# A symlink in /usr/local/bin/ keeps the command in PATH.
#
# Flask-style "templates/" subdirectory holds HTML templates.
APP_DIR="/opt/ssh-web-proxy"
APP_MAIN="$APP_DIR/ssh-web-proxy"
APP_REMOTE_DIAG="$APP_DIR/remote_diag.py"
APP_TPL_DIR="$APP_DIR/templates"
APP_INDEX_TPL="$APP_TPL_DIR/index.html"
APP_VENV="$APP_DIR/venv"
APP_VENV_PYTHON="$APP_VENV/bin/python3"
APP_VENV_PIP="$APP_VENV/bin/pip"
PATH_SYMLINK="/usr/local/bin/ssh-web-proxy"
UNIT_PATH="/etc/systemd/system/ssh-web-proxy.service"

# Legacy paths from the previous install layout — cleaned up if found.
LEGACY_BIN="/usr/local/bin/ssh-web-proxy"   # was a real file, now a symlink
LEGACY_LIB_DIR="/usr/local/lib/ssh-web-proxy"

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: needs root. Pipe to 'sudo bash'." >&2
    exit 1
fi

# Up-front scope statement — prints BEFORE any destructive action,
# so the operator sees exactly what's about to be touched.
cat <<'BANNER'
This installer touches ONLY the following paths:
  /opt/ssh-web-proxy/                          (app tree + venv)
  /usr/local/bin/ssh-web-proxy                 (symlink for $PATH)
  /usr/local/lib/ssh-web-proxy/                (legacy cleanup, removed if found)
  /etc/systemd/system/ssh-web-proxy.service    (our unit only)
  /tmp/<temp files>                            (download buffers, auto-cleaned)

Systemd actions: daemon-reload, enable + restart of ssh-web-proxy ONLY.
Apt may install python3-venv (additive). No other system state changes.

BANNER

# Return RFC 1918 IPv4 addresses on global-scope interfaces, ordered
# so the address on the default-route NIC comes first. This is the
# operator-reachable LAN NIC — docker0 / virbr0 / VPN bridges don't
# carry the default route, so they sort to the back. Without this
# ordering, on a multi-NIC host we might bind to 172.17.0.1 (docker)
# or 192.168.122.1 (libvirt) instead of the real LAN address.
detect_private_ips() {
    if ! command -v ip >/dev/null 2>&1; then
        return 1
    fi
    local default_iface
    default_iface="$(ip -4 route show default 2>/dev/null \
                     | awk '/^default/ {for (i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}')"

    local primary="" secondary=""
    # Walk every global-scope IPv4 line. ip -o format:
    #   "2: enp1s0    inet 192.168.0.104/24 brd ..."
    while read -r line; do
        local iface addr second is_private
        iface="$(echo "$line" | awk '{print $2}')"
        addr="$(echo "$line"  | awk '{print $4}' | cut -d/ -f1)"
        is_private=0
        case "$addr" in
            10.*|192.168.*) is_private=1 ;;
            172.*)
                second="${addr#172.}"
                second="${second%%.*}"
                if [ "$second" -ge 16 ] 2>/dev/null && [ "$second" -le 31 ]; then
                    is_private=1
                fi
                ;;
        esac
        [ "$is_private" = 1 ] || continue
        if [ -n "$default_iface" ] && [ "$iface" = "$default_iface" ]; then
            primary="${primary}${addr}
"
        else
            secondary="${secondary}${addr}
"
        fi
    done < <(ip -4 -o addr show scope global 2>/dev/null)

    # Emit primary (default-route NIC) first, secondary after.
    # `grep -v ^\$` strips the trailing empty line from the heredoc.
    printf '%s%s' "$primary" "$secondary" | grep -v '^$' || true
}

# Detect private IP for the URL we print at the end. Also fail-fast
# at install time if no private IP exists — that way the operator
# learns about the misconfig now, not on first restart.
#
# The systemd unit doesn't pin this IP unless the user explicitly
# passed BIND=. With no BIND override, the service runs without -b
# and re-detects its private IP on every restart, so if the host's
# IP changes later, `systemctl restart ssh-web-proxy` picks it up.
PRIVATE_IPS="$(detect_private_ips || true)"
if [ -z "$PRIVATE_IPS" ] && [ -z "${BIND:-}" ]; then
    cat >&2 <<'EOF'

ERROR: no RFC 1918 private IPv4 address found on this host.

The proxy must bind to a LAN/VPN address — binding to a public
interface would expose it to the internet. Scanned ranges:

    10.0.0.0/8      (10.x.x.x)
    172.16.0.0/12   (172.16-31.x.x)
    192.168.0.0/16  (192.168.x.x)

Current global-scope addresses on this host:
EOF
    ip -4 -o addr show scope global 2>&1 | sed 's/^/    /' >&2
    cat >&2 <<'EOF'

If the tunnel server uses an internal address outside RFC 1918
(e.g. a VPN range like 100.64.x.x), set BIND explicitly:

    curl -fsSL <install-url> | sudo BIND=<your-lan-ip> bash

EOF
    exit 1
fi

if [ -n "${BIND:-}" ]; then
    EFFECTIVE_BIND="$BIND"
    BIND_ARG="-b $BIND"
    echo "==> Using explicit BIND=$BIND (pinned in systemd unit)"
else
    EFFECTIVE_BIND="$(echo "$PRIVATE_IPS" | head -1)"
    BIND_ARG=""   # let the service auto-detect every restart
    COUNT="$(echo "$PRIVATE_IPS" | wc -l)"
    if [ "$COUNT" -gt 1 ]; then
        echo "==> Multiple private IPs detected; service will auto-bind to $EFFECTIVE_BIND"
        echo "    Others (pin one with BIND=<ip>):"
        echo "$PRIVATE_IPS" | tail -n +2 | sed 's/^/      /'
    else
        echo "==> Detected private IP: $EFFECTIVE_BIND (auto-rebind on restart)"
    fi
fi

if [ -e "$APP_MAIN" ] && [ -f "$UNIT_PATH" ]; then
    echo "==> Updating ssh-web-proxy"
else
    echo "==> Installing ssh-web-proxy"
fi

# Migrate from the previous layout if it exists. The old install put
# the main script as a real file at /usr/local/bin/ssh-web-proxy
# (which is also where our new symlink wants to live) and the data
# file at /usr/local/lib/ssh-web-proxy/. Clean both up.
if [ -f "$LEGACY_BIN" ] && [ ! -L "$LEGACY_BIN" ]; then
    echo "==> Migrating from previous layout (removing $LEGACY_BIN file)"
    rm -f "$LEGACY_BIN"
fi
if [ -d "$LEGACY_LIB_DIR" ] && [ "$LEGACY_LIB_DIR" != "$APP_DIR" ]; then
    echo "==> Migrating from previous layout (removing $LEGACY_LIB_DIR)"
    rm -rf "$LEGACY_LIB_DIR"
fi

# Install paramiko inside a venv at /opt/ssh-web-proxy/venv.
#
# Why a venv: Ubuntu 18.04's system Python ecosystem is too old to
# install modern paramiko cleanly — apt's python3-paramiko is 2.0.0
# (no ed25519, no OpenSSH-format keys), apt's python3-cryptography
# is 2.1.4 (too old for paramiko 2.5+), and the system pip 9.0.1
# can't fetch binary wheels for modern packages so it tries to
# build cryptography from source (which needs Rust + OpenSSL dev
# headers). A venv sidesteps all of this: it upgrades its own pip
# from PyPI first, then pulls binary wheels for everything.
#
# This also works identically on Ubuntu 20/22/24, Debian, RHEL.
# Single install path, no distro-version branching.
ensure_paramiko_venv() {
    # The venv is considered "healthy" only if pip actually works
    # inside it. Python alone isn't enough — a previous install that
    # failed at the ensurepip step leaves a python3 binary but no pip,
    # and re-running would silently skip recreation and then explode
    # trying to call $APP_VENV_PIP. Test for working pip; if it
    # doesn't work, blow away the venv and start fresh.
    local healthy=0
    if [ -x "$APP_VENV_PIP" ] && "$APP_VENV_PIP" --version >/dev/null 2>&1; then
        healthy=1
    fi
    if [ "$healthy" = "0" ]; then
        if [ -d "$APP_VENV" ]; then
            echo "==> Removing broken venv at $APP_VENV (no working pip)"
            rm -rf "$APP_VENV"
        fi
        echo "==> Creating Python virtualenv at $APP_VENV"
        # On Debian/Ubuntu, python3-venv is a separate apt package
        # that brings in BOTH the venv module AND ensurepip (which
        # bootstraps pip inside the new venv). The `venv` module
        # itself is in core python3, but without ensurepip the
        # "python3 -m venv" command fails at the pip-bootstrap step.
        # So we check for `ensurepip` specifically, not just `venv`.
        if ! python3 -c 'import ensurepip' >/dev/null 2>&1; then
            if command -v apt-get >/dev/null 2>&1; then
                echo "    installing python3-venv (needed for ensurepip)"
                # NB: detect the actual Python version for the matching
                # versioned package — apt's `python3-venv` may pull a
                # different python3.X than `python3` resolves to on
                # some systems.
                PY_VER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
                apt-get update -qq >/dev/null 2>&1 || true
                apt-get install -y -qq python3-venv "python${PY_VER}-venv" 2>/dev/null \
                    || apt-get install -y -qq python3-venv \
                    || { echo "ERROR: apt install python3-venv failed" >&2; exit 1; }
            elif command -v dnf >/dev/null 2>&1; then
                dnf install -y -q python3-virtualenv 2>/dev/null || true
            fi
        fi
        # Clean up any partial venv from a previous failed attempt.
        rm -rf "$APP_VENV"
        if ! python3 -m venv "$APP_VENV" 2>/tmp/venv.err; then
            echo "ERROR: python3 -m venv failed:" >&2
            cat /tmp/venv.err >&2
            echo >&2
            echo "Manual recovery: sudo apt install python3-venv  python$(python3 -c 'import sys; print(f\"{sys.version_info.major}.{sys.version_info.minor}\")')-venv" >&2
            exit 1
        fi
    fi
    # Upgrading pip inside a venv always works — the venv's pip can
    # replace itself from PyPI without any system-package conflicts.
    # Modern pip is required to fetch manylinux binary wheels (so we
    # don't try to compile cryptography from source).
    echo "==> Upgrading pip/wheel in venv"
    "$APP_VENV_PIP" install --quiet --upgrade pip wheel >/dev/null
    # Pin paramiko to the 2.x line: still supports Python 3.5+ (so
    # works on Ubuntu 16.04+), and ships pre-built binary wheels for
    # cryptography that don't need a compiler.
    echo "==> Installing paramiko in venv"
    "$APP_VENV_PIP" install --quiet --upgrade 'paramiko>=2.4,<3'
    local v=$("$APP_VENV_PYTHON" -c 'import paramiko; print(paramiko.__version__)')
    echo "    paramiko $v installed in $APP_VENV"
}
ensure_paramiko_venv

echo "==> Downloading latest ssh_web_proxy.py + remote_diag.py + index.html"
TMP_MAIN="$(mktemp)"
TMP_DIAG="$(mktemp)"
TMP_TPL="$(mktemp)"
trap 'rm -f "$TMP_MAIN" "$TMP_DIAG" "$TMP_TPL"' EXIT
curl -fsSL -H "$RAW_ACCEPT" -o "$TMP_MAIN" "$MAIN_URL"
curl -fsSL -H "$RAW_ACCEPT" -o "$TMP_DIAG" "$REMOTE_DIAG_URL"
curl -fsSL -H "$RAW_ACCEPT" -o "$TMP_TPL"  "$INDEX_TPL_URL"
# Sanity-check: .py files must start with a Python shebang, .html must
# look like HTML. Catches the case where the raw URL returned a GitHub
# 404 page instead of the real file.
for f in "$TMP_MAIN" "$TMP_DIAG"; do
    head -1 "$f" | grep -q '^#!/.*python' \
        || { echo "ERROR: $(basename "$f") download didn't return a Python script" >&2; exit 1; }
done
head -1 "$TMP_TPL" | grep -qi '^<!doctype html' \
    || { echo "ERROR: index.html download didn't return HTML" >&2; exit 1; }

mkdir -p "$APP_DIR" "$APP_TPL_DIR"
install -m 755 "$TMP_MAIN" "$APP_MAIN"
install -m 644 "$TMP_DIAG" "$APP_REMOTE_DIAG"
install -m 644 "$TMP_TPL"  "$APP_INDEX_TPL"
# Symlink for PATH access (so operators can type `ssh-web-proxy --help`).
# -f overwrites any prior symlink (including ones from earlier installs).
ln -sf "$APP_MAIN" "$PATH_SYMLINK"

echo "==> Writing systemd unit (User=$SERVICE_USER, Port=$PORT)"
cat > "$UNIT_PATH" <<EOF
[Unit]
Description=SSH-tunneled web proxy
After=network-online.target
Wants=network-online.target

[Service]
User=$SERVICE_USER
# Use the venv's python3 so paramiko is the modern pip-installed
# version, not whatever the system's apt provides. Both paths are
# inside /opt/ssh-web-proxy/ so the whole install is self-contained.
ExecStart=$APP_VENV_PYTHON $APP_MAIN $BIND_ARG -p $PORT
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable ssh-web-proxy >/dev/null 2>&1 || true
systemctl restart ssh-web-proxy

# Wait for the listener to actually come up (up to 10s) before
# reporting success. Catches the case where the service starts but
# crashes immediately, so the operator finds out from the installer
# rather than from a hanging browser.
echo -n "==> Waiting for listener on $EFFECTIVE_BIND:$PORT "
listening=0
for _ in 1 2 3 4 5 6 7 8 9 10; do
    if ss -tln 2>/dev/null | grep -q "[ 	]$EFFECTIVE_BIND:$PORT[ 	]"; then
        listening=1
        echo "OK"
        break
    fi
    echo -n "."
    sleep 1
done
if [ "$listening" = "0" ]; then
    echo
    echo "WARNING: service is enabled but did NOT come up listening on" \
         "$EFFECTIVE_BIND:$PORT within 10s." >&2
    echo "         Check 'systemctl status ssh-web-proxy' and"          >&2
    echo "         'journalctl -u ssh-web-proxy -n 30' for the reason." >&2
    # NB: not exit 1 — the unit is in place and may recover via Restart=always.
fi

echo
echo "==> Done."
echo "    URL:     http://$EFFECTIVE_BIND:$PORT/"
echo "    User:    $SERVICE_USER"
echo "    Status:  systemctl status ssh-web-proxy"
echo "    Logs:    journalctl -u ssh-web-proxy -f"
echo "    Files:   $APP_DIR/  ($PATH_SYMLINK -> $APP_MAIN)"
echo "    Venv:    $APP_VENV/  (isolated paramiko)"
if [ -z "$BIND_ARG" ]; then
    echo "    Note:    service auto-detects private IP on every restart"
fi

# Optional servers.txt for the form's quick-pick dropdown. The proxy
# reads ~/printer-check/servers.txt on every page load (no caching).
# Heuristic: $SERVICE_USER's home is the canonical location since
# that's the user the service runs as. Just informational — missing
# file is not a problem.
SERVICE_USER_HOME="$(getent passwd "$SERVICE_USER" 2>/dev/null | cut -d: -f6)"
if [ -n "$SERVICE_USER_HOME" ]; then
    SERVERS_FILE="$SERVICE_USER_HOME/printer-check/servers.txt"
    if [ -f "$SERVERS_FILE" ]; then
        N=$(grep -cE '^\s*#?\s*[A-Za-z0-9_][A-Za-z0-9_.\-]*@' "$SERVERS_FILE" 2>/dev/null || echo 0)
        echo "    Servers: $SERVERS_FILE  ($N parseable entries)"
    else
        echo "    Servers: $SERVERS_FILE  (not present — quick-pick dropdown will be hidden)"
    fi
fi
