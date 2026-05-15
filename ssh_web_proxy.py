#!/usr/bin/env python3
"""
ssh_web_proxy.py — single-file SSH-tunneled web proxy for accessing
device web UIs on a remote network through reverse-tunneled SSH.

Deployment model (the tunnel-server scenario this is designed for):

    +------------------+        +------------------+        +-----------------+
    |   Operator       |        |  Tunnel server   |        | Remote print    |
    |   (browser)      | ---->  |  (this script    | <----> | server          |
    |                  |  9999  |   runs here)     |  SSH   | (reverse-       |
    |                  |        |                  |  rev.  |  tunneled)      |
    +------------------+        +--------+---------+        +--------+--------+
                                         | SSH (direct-tcpip)        |
                                         | through localhost:NNNN    |
                                         | which is reverse-mapped   |
                                         | to the remote server's    |
                                         | sshd                      |
                                         v                           v
                                                              +------+------+
                                                              |  Device     |
                                                              |  web UI on  |
                                                              |  remote LAN |
                                                              +-------------+

The remote print servers continuously reverse-forward their local sshd
back to this tunnel server (different local ports per remote). The
tunnel server has SSH keys pre-installed for passwordless login over
those reverse-mapped ports. The operator opens this script in their
browser, fills a form (SSH user, local mapped SSH port, target device
IP/port on the remote LAN, scheme), and the script:

  1. Opens an SSH connection to 127.0.0.1:<local-mapped-ssh-port> as
     <user>, using only key-based auth (no passwords).
  2. For every HTTP request the browser makes inside the session, opens
     a fresh "direct-tcpip" channel through that SSH connection to
     <target-ip>:<target-port> on the remote LAN.
  3. Sends/receives HTTP (or HTTPS) bytes through the channel.
  4. Rewrites the response so absolute paths, inline scripts, form
     actions, redirects, and cookies stay confined to the proxy's URL
     path. (Rewrite rules are lifted verbatim from the printer-manager
     Flask proxy that already handles old-school printer / appliance
     UIs that emit uppercase HTML attributes, location.href redirects,
     jQuery $.ajax calls, etc.)

PORT-COLLISION SAFETY
---------------------
This script does NOT allocate any local TCP port for the tunnels
themselves. paramiko's direct-tcpip channels go through the existing
SSH connection — no local listener / no port binding / no risk of
colliding with the dozens of reverse-forwarded ports the tunnel server
is already using. The ONLY local port consumed is the proxy's own
HTTP listener (default 9999), which is checked for availability at
startup and refused (with a clear error) if already bound.

USAGE
-----
    pip install paramiko
    python3 ssh_web_proxy.py                # auto-detect private IP, port 9999
    python3 ssh_web_proxy.py -p 8888        # custom port
    python3 ssh_web_proxy.py -b 10.0.0.5    # explicit bind address
    python3 ssh_web_proxy.py -b 0.0.0.0     # bind all interfaces (not recommended)

By default the listener binds to the first RFC 1918 private IPv4
address on the host (10.x.x.x, 172.16-31.x.x, 192.168.x.x). The
detection re-runs at every startup, so if the host's IP changes
(DHCP lease, NIC swap), a `systemctl restart ssh-web-proxy` picks
up the new address automatically. If no private IP exists, the
script exits with a clear error rather than landing on a public
interface.

SECURITY NOTE
-------------
This proxy has no authentication of its own. Anyone who can reach the
listener can open SSH sessions to any reverse-tunneled remote server
the host's SSH keys are authorized for. Firewall the listener to
admin IPs.
"""

import argparse
import html
import http.client
import ipaddress
import os
import re
import secrets
import socket
import ssl
import subprocess
import sys
import threading
import time
import traceback
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from urllib.parse import parse_qs, quote, unquote, urlsplit


# Python 3.7+ ships ``http.server.ThreadingHTTPServer`` — a trivial
# (ThreadingMixIn, HTTPServer) subclass. We need to run on Python 3.6
# (tunnel server is Ubuntu 18.04), so define our own equivalent
# rather than importing it. Works identically on 3.6 and later.
class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

try:
    import paramiko
except ImportError:
    print("ERROR: paramiko not installed. Run: pip install paramiko",
          file=sys.stderr)
    sys.exit(2)


# ─── Configuration ────────────────────────────────────────────────────
# Idle timeout for SSH sessions; sessions unused for this many seconds
# get reaped + their SSH connections closed.
SESSION_IDLE_TIMEOUT_S = 30 * 60
# Hard cap on concurrent sessions to bound resource use.
MAX_SESSIONS = 64
# Max response body we'll buffer before streaming as-is. Web UIs are
# typically tiny; this is just an upper guard.
MAX_BUFFER_BYTES = 64 * 1024 * 1024
# HTTP request timeout through the SSH channel.
PROXY_HTTP_TIMEOUT_S = 30


# ─── Session model ────────────────────────────────────────────────────
class Session:
    """One SSH connection bound to a single remote target (IP+port+scheme).

    A Session represents the (SSH connection, target) pair the operator
    submitted via the form. The SSH connection persists for the life of
    the session; per-HTTP-request direct-tcpip channels are opened
    on-demand and torn down after each request.
    """

    __slots__ = ('sid', 'ssh_user', 'ssh_local_port', 'remote_host',
                 'remote_port', 'scheme', 'ssh_client', 'created_at',
                 'last_used', 'lock', 'request_count')

    def __init__(self, sid, ssh_user, ssh_local_port, remote_host,
                 remote_port, scheme, ssh_client):
        self.sid = sid
        self.ssh_user = ssh_user
        self.ssh_local_port = ssh_local_port
        self.remote_host = remote_host
        self.remote_port = remote_port
        self.scheme = scheme            # 'http' or 'https'
        self.ssh_client = ssh_client
        self.created_at = time.time()
        self.last_used = time.time()
        # Per-session lock — direct-tcpip channels are independent at
        # the SSH layer, but http.client objects we wrap each channel
        # in aren't thread-safe. Serialize per session.
        self.lock = threading.Lock()
        self.request_count = 0

    def transport(self):
        return self.ssh_client.get_transport()

    def touch(self):
        self.last_used = time.time()
        self.request_count += 1

    def is_alive(self):
        t = self.transport()
        return t is not None and t.is_active()

    def close(self):
        try:
            self.ssh_client.close()
        except Exception:
            pass

    def label(self):
        return (f'{self.ssh_user}@localhost:{self.ssh_local_port} '
                f'→ {self.scheme}://{self.remote_host}:{self.remote_port}')


# ─── Session store ────────────────────────────────────────────────────
# sid -> Session. (No type annotation — keeps the file importable on
# Python 3.6 where ``dict[K, V]`` subscripting raises TypeError.)
_SESSIONS = {}
_SESSIONS_LOCK = threading.Lock()


def _gc_loop():
    """Reap idle / dead sessions every 60s."""
    while True:
        time.sleep(60)
        now = time.time()
        cutoff = now - SESSION_IDLE_TIMEOUT_S
        dead = []
        with _SESSIONS_LOCK:
            for sid, sess in list(_SESSIONS.items()):
                if sess.last_used < cutoff or not sess.is_alive():
                    dead.append(sess)
                    _SESSIONS.pop(sid, None)
        for sess in dead:
            sess.close()


def get_session(sid):
    with _SESSIONS_LOCK:
        return _SESSIONS.get(sid)


def all_sessions():
    with _SESSIONS_LOCK:
        return list(_SESSIONS.values())


def add_session(sess):
    with _SESSIONS_LOCK:
        if len(_SESSIONS) >= MAX_SESSIONS:
            raise RuntimeError(
                f'Max concurrent sessions ({MAX_SESSIONS}) reached. '
                f'Close some via /sessions before opening more.'
            )
        _SESSIONS[sess.sid] = sess


def drop_session(sid):
    with _SESSIONS_LOCK:
        sess = _SESSIONS.pop(sid, None)
    if sess:
        sess.close()
        return True
    return False


# ─── SSH connection ───────────────────────────────────────────────────
import inspect as _inspect


def _supported_kwargs(callable_obj):
    """Return the set of kwarg names a callable accepts. Lets us
    feature-detect what the installed paramiko version supports —
    paramiko 2.0.0 (Ubuntu 18.04's stock) predates ``auth_timeout``
    on ``SSHClient.connect`` and ``timeout`` on
    ``Transport.open_session``. Returns ``None`` if introspection
    fails (in which case the caller should pass everything and let
    paramiko raise)."""
    try:
        return set(_inspect.signature(callable_obj).parameters)
    except (ValueError, TypeError):
        return None


def _safe_open_session(transport, timeout):
    """``transport.open_session(timeout=...)`` — the ``timeout`` kwarg
    was added in paramiko 2.1.0. On 2.0.0 we drop it; the channel
    will simply use the transport-level default timeout."""
    kwargs = {'timeout': timeout}
    supported = _supported_kwargs(transport.open_session)
    if supported is not None:
        kwargs = {k: v for k, v in kwargs.items() if k in supported}
    return transport.open_session(**kwargs)


def _diagnose_auth_failure(ssh_user, ssh_local_port):
    """Build a helpful diagnostic blurb for an SSH auth failure.
    Lists keys paramiko's auto-discovery should have tried, and the
    installed paramiko version (so the operator can spot the
    "paramiko too old to read modern keys" failure mode)."""
    msgs = []
    msgs.append('Verify that %s has a key authorized on the remote '
                'reachable via port %d.' % (ssh_user, ssh_local_port))
    # Surface paramiko version — old paramiko (< 2.2) can't load
    # ed25519 keys; old paramiko (< 2.7) can't load OpenSSH-format
    # PEM keys. If the operator can ssh manually but the proxy
    # can't, the paramiko version is the usual culprit.
    try:
        msgs.append('paramiko version on this server: %s' %
                    paramiko.__version__)
    except Exception:
        pass
    # List candidate keys that paramiko's auto-discovery should
    # have tried, with format hint per file. Helps spot ed25519 +
    # new-format files that an older paramiko can't read.
    home = os.path.expanduser('~')
    candidates = ['id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519']
    found = []
    for name in candidates:
        path = os.path.join(home, '.ssh', name)
        if not os.path.isfile(path):
            continue
        fmt = 'PEM (old format)'
        try:
            with open(path, 'r', encoding='utf-8', errors='replace') as f:
                first_line = f.readline().strip()
            if first_line == '-----BEGIN OPENSSH PRIVATE KEY-----':
                fmt = 'OpenSSH new format (needs paramiko >= 2.7)'
            elif 'PRIVATE KEY' in first_line:
                fmt = 'PEM'
        except OSError:
            fmt = 'unreadable'
        algo = name.replace('id_', '')
        if algo == 'ed25519':
            fmt += ' (ed25519 needs paramiko >= 2.2)'
        found.append('%s: %s' % (name, fmt))
    if found:
        msgs.append('Keys found in ~/.ssh: ' + '; '.join(found))
    else:
        msgs.append('No keys found in ~/.ssh — service is running as '
                    'user %r; check that user has the keys.' %
                    os.environ.get('USER', '?'))
    return ' '.join(msgs)


def open_ssh(ssh_user, ssh_local_port):
    """Open SSH to 127.0.0.1:<ssh_local_port> as <ssh_user>.

    Uses key-based auth only (no password fallback). paramiko's
    auto-discovery walks ~/.ssh/id_* and the SSH agent.

    Host-key policy: AutoAdd. Each reverse-mapped local port routes to
    a different remote sshd, so "localhost"'s host key isn't stable —
    the trust boundary is the tunnel mapping itself (the operator
    chose this port). Strict checking on 127.0.0.1 would just produce
    spurious failures.
    """
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    # Aspirational kwargs — newer paramikos accept all of these.
    # Old paramiko 2.0.0 (Ubuntu 18.04) doesn't know about
    # ``auth_timeout``; filter to what's actually supported.
    kwargs = dict(
        hostname='127.0.0.1',
        port=ssh_local_port,
        username=ssh_user,
        allow_agent=True,
        look_for_keys=True,
        timeout=10,
        banner_timeout=10,
        auth_timeout=15,
        password=None,  # block password prompts — keys only
    )
    supported = _supported_kwargs(paramiko.SSHClient.connect)
    if supported is not None:
        kwargs = {k: v for k, v in kwargs.items() if k in supported}
    client.connect(**kwargs)
    return client


# ─── Paramiko Channel ↔ real socket bridge ────────────────────────────
def _bridge_channel_to_socket(channel, timeout):
    """Wire a paramiko direct-tcpip Channel up to a real local socket
    via a socketpair + two pumper threads. Returns the local socket end,
    which behaves as a fully-featured socket (settimeout, makefile,
    SSL-wrappable, etc.) — required because http.client and ssl both
    expect a real socket object, and paramiko's Channel doesn't expose
    enough of the socket API for ssl.wrap_socket in practice.

    The pumper threads exit when either side closes; no shared state
    leaks back into the proxy after the request finishes."""
    local, remote = socket.socketpair()
    local.settimeout(timeout)

    def chan_to_sock():
        try:
            while True:
                data = channel.recv(8192)
                if not data:
                    break
                remote.sendall(data)
        except Exception:
            pass
        finally:
            try: remote.shutdown(socket.SHUT_WR)
            except Exception: pass

    def sock_to_chan():
        try:
            while True:
                data = remote.recv(8192)
                if not data:
                    break
                channel.sendall(data)
        except Exception:
            pass
        finally:
            try: channel.shutdown_write()
            except Exception: pass

    threading.Thread(target=chan_to_sock, daemon=True).start()
    threading.Thread(target=sock_to_chan, daemon=True).start()
    # Keep `remote` alive via the threads (they own the reference).
    return local


class _SuppliedSockHTTPConnection(http.client.HTTPConnection):
    """HTTPConnection that uses a pre-supplied socket instead of
    dialing one itself. The socket already points at the right host."""

    def __init__(self, host, port, sock, timeout):
        super().__init__(host, port, timeout=timeout)
        self._supplied_sock = sock

    def connect(self):
        self.sock = self._supplied_sock


class _SuppliedSockHTTPSConnection(http.client.HTTPSConnection):
    """HTTPSConnection variant — wraps the supplied socket in TLS.
    Verification is disabled because device web UIs are almost always
    self-signed."""

    def __init__(self, host, port, sock, timeout):
        ctx = ssl._create_unverified_context()
        super().__init__(host, port, timeout=timeout, context=ctx)
        self._supplied_sock = sock

    def connect(self):
        # server_hostname=self.host is required for SNI on devices
        # that virtual-host multiple certs, even though we don't
        # verify the cert chain.
        self.sock = self._context.wrap_socket(
            self._supplied_sock, server_hostname=self.host,
        )


def http_through_ssh(session, method, path_with_query, headers, body):
    """Run one HTTP/HTTPS request via the session's SSH connection.

    Returns (status, headers_list, body_bytes). Raises on transport
    or HTTP-protocol errors."""
    with session.lock:
        session.touch()
        transport = session.transport()
        if transport is None or not transport.is_active():
            raise RuntimeError('SSH transport is dead — session closed')
        # Open a fresh direct-tcpip channel for this request.
        channel = transport.open_channel(
            'direct-tcpip',
            (session.remote_host, session.remote_port),
            ('127.0.0.1', 0),
        )
        channel.settimeout(PROXY_HTTP_TIMEOUT_S)
        sock = _bridge_channel_to_socket(channel, PROXY_HTTP_TIMEOUT_S)

        try:
            if session.scheme == 'https':
                conn = _SuppliedSockHTTPSConnection(
                    session.remote_host, session.remote_port, sock,
                    timeout=PROXY_HTTP_TIMEOUT_S,
                )
            else:
                conn = _SuppliedSockHTTPConnection(
                    session.remote_host, session.remote_port, sock,
                    timeout=PROXY_HTTP_TIMEOUT_S,
                )
            conn.request(method, path_with_query, body=body, headers=headers)
            resp = conn.getresponse()
            status = resp.status
            headers_list = [(k, v) for k, v in resp.getheaders()]
            # Read into a bounded buffer.
            body_bytes = resp.read(MAX_BUFFER_BYTES + 1)
            if len(body_bytes) > MAX_BUFFER_BYTES:
                raise RuntimeError(
                    f'Response body exceeded {MAX_BUFFER_BYTES} bytes'
                )
            return status, headers_list, body_bytes
        finally:
            try: conn.close()
            except Exception: pass
            try: sock.close()
            except Exception: pass
            try: channel.close()
            except Exception: pass


# ─── URL rewriting (lifted from printer-manager Flask proxy) ──────────
# Hop-by-hop request headers that must NOT be forwarded.
HOP_BY_HOP_REQUEST = {
    'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
    'te', 'trailers', 'transfer-encoding', 'upgrade',
}
# Response headers we strip.
SKIP_RESPONSE = {
    'transfer-encoding', 'content-encoding', 'connection',
    'keep-alive', 'proxy-authenticate', 'proxy-authorization',
    'x-frame-options',
}


def rewrite_body(body, content_type, device_ip, proxy_base, page_path):
    """Apply the printer-manager proxy's HTML/CSS/JS rewrite rules so
    absolute URLs, form actions, and inline JS calls stay inside the
    /s/<sid>/ proxy path. ``device_ip`` is the upstream device's IP;
    ``proxy_base`` is the URL prefix this session lives under (always
    ends in '/'); ``page_path`` is the part of the URL after the proxy
    base (used to build a sane <base href>)."""
    if not any(ct in content_type for ct in (
        'text/html', 'text/css', 'text/javascript', 'application/javascript',
    )):
        return body
    try:
        text = body.decode('utf-8', errors='replace')
    except Exception:
        return body

    ip_escaped = re.escape(device_ip)

    # ALWAYS: rewrite full URLs containing the device IP (any content type)
    text = re.sub(
        r'https?://' + ip_escaped + r'(?::\d+)?/',
        proxy_base,
        text,
    )
    text = re.sub(
        r'https?://' + ip_escaped + r'(?::\d+)?(?=["\x27\s>);}])',
        proxy_base.rstrip('/'),
        text,
    )

    if 'text/html' in content_type:
        # <base href> — relative URLs resolve through the proxy.
        if '/' in page_path:
            page_dir = page_path.rsplit('/', 1)[0] + '/'
        else:
            page_dir = ''
        base_href = proxy_base + page_dir
        base_tag = f'<base href="{base_href}">'
        if re.search(r'<head[^>]*>', text, re.I):
            text = re.sub(
                r'(<head[^>]*>)', rf'\1{base_tag}',
                text, count=1, flags=re.I,
            )

        # href / src / action absolute paths → /proxy/.../...
        # IGNORECASE is critical — old Epson WebConfig (TM-U220, etc.)
        # emits uppercase HTML attributes.
        text = re.sub(
            r'''(href|src|action)\s*=\s*(["'])/(?!/)(?!''' + re.escape(proxy_base.lstrip('/')) + r''')''',
            rf'\1=\2{proxy_base}',
            text, flags=re.I,
        )
        # <meta http-equiv="refresh" content="0; url=/foo">
        text = re.sub(
            r'''(url\s*=\s*)(["']?)/(?!/)(?!''' + re.escape(proxy_base.lstrip('/')) + r''')''',
            rf'\1\2{proxy_base}',
            text, flags=re.I,
        )

    if 'text/css' in content_type:
        text = re.sub(
            r'''url\(\s*(["']?)/(?!/)(?!''' + re.escape(proxy_base.lstrip('/')) + r''')''',
            rf'url(\1{proxy_base}',
            text,
        )

    if 'javascript' in content_type or 'text/html' in content_type:
        not_proxy = re.escape(proxy_base.lstrip('/'))
        # fetch("/path")
        text = re.sub(
            r'''(fetch\s*\(\s*)(["'])/(?!/)(?!''' + not_proxy + r''')''',
            rf'\1\2{proxy_base}', text,
        )
        # $.get("/path"), $.post("/path"), $.ajax("/path")
        text = re.sub(
            r'''(\$\.\w+\s*\(\s*)(["'])/(?!/)(?!''' + not_proxy + r''')''',
            rf'\1\2{proxy_base}', text,
        )
        # XMLHttpRequest.open("GET", "/path")
        text = re.sub(
            r'''(\.open\s*\([^,]+,\s*)(["'])/(?!/)(?!''' + not_proxy + r''')''',
            rf'\1\2{proxy_base}', text,
        )
        # location.href = "/path" / location = "/path"
        text = re.sub(
            r'''(location(?:\.href)?\s*=\s*)(["'])/(?!/)(?!''' + not_proxy + r''')''',
            rf'\1\2{proxy_base}', text,
        )
        # url: "/path"  (jQuery $.ajax({url: "/path"}))
        text = re.sub(
            r'''(url\s*:\s*)(["'])/(?!/)(?!''' + not_proxy + r''')''',
            rf'\1\2{proxy_base}', text,
        )
        # = "/api/..." / = "/cgi-bin/..." etc.
        text = re.sub(
            r'''(=\s*["'])/(?!''' + not_proxy + r''')(cgi-bin|api|cgi|rpc|jsonrpc|command|data)/''',
            rf'\1{proxy_base}\2/',
            text,
        )

    return text.encode('utf-8')


def rewrite_response_headers(headers_list, device_ip, proxy_base):
    """Filter and rewrite response headers. Returns a new list of
    (name, value) tuples."""
    out = []
    for k, v in headers_list:
        kl = k.lower()
        if kl in SKIP_RESPONSE:
            continue
        if kl == 'location':
            # Rewrite redirects
            if v.startswith(f'http://{device_ip}') or v.startswith(f'https://{device_ip}'):
                # Strip scheme+host, leave path
                m = re.match(r'^https?://[^/]+(.*)$', v)
                if m:
                    v = m.group(1) or '/'
            if v.startswith('/') and not v.startswith(proxy_base):
                v = proxy_base.rstrip('/') + v
        elif kl == 'set-cookie':
            # Path → proxy path
            v = re.sub(r'[Pp]ath\s*=\s*/[^;]*', f'Path={proxy_base}', v)
            if 'path=' not in v.lower():
                v += f'; Path={proxy_base}'
            # Strip Domain (we ARE the domain now)
            v = re.sub(r';\s*[Dd]omain\s*=\s*[^;]+', '', v)
            # Strip Secure (proxy is likely plain HTTP)
            v = re.sub(r';\s*[Ss]ecure', '', v)
        elif kl == 'content-security-policy':
            # CSP would block our rewriting
            continue
        out.append((k, v))
    return out


def filter_request_headers(raw_headers, device_ip, proxy_base):
    """Strip hop-by-hop headers, set Host correctly, force identity
    encoding so we can rewrite, rewrite Origin/Referer back to upstream
    coordinates."""
    out = {}
    for k, v in raw_headers.items():
        kl = k.lower()
        if kl in HOP_BY_HOP_REQUEST or kl == 'host':
            continue
        out[k] = v
    out['Host'] = device_ip
    out['Accept-Encoding'] = 'identity'
    if 'Origin' in out:
        out['Origin'] = f'http://{device_ip}'
    if 'Referer' in out:
        ref = out['Referer']
        if proxy_base in ref:
            ref = re.sub(
                r'https?://[^/]+' + re.escape(proxy_base),
                f'http://{device_ip}/', ref,
            )
            out['Referer'] = ref
    return out


# ─── HTML templates ───────────────────────────────────────────────────
#
# Templates live in a separate ``templates/`` directory (Flask-style
# convention — any Python web dev recognizes the layout). We do NOT
# pull in Jinja2 or any other template engine; placeholder substitution
# is just ``str.replace()`` with ``%%TOKEN%%`` markers. That keeps the
# install footprint to "two .py files + one .html" with zero extra
# Python dependencies beyond paramiko.
#
# The diagnostics RESULTS page is built imperatively in
# ``render_diagnose_results()`` (data-driven HTML construction, not
# a template) — extracting it would require a template engine or
# hand-rolled loops, which isn't worth the complexity for one page.

_INDEX_TEMPLATE_PATH_CANDIDATES = [
    # Dev / repo checkout: adjacent to this script
    lambda: os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        'templates', 'index.html'),
    # Production install location (see install.sh)
    lambda: '/opt/ssh-web-proxy/templates/index.html',
]


def _load_index_template():
    """Find and read templates/index.html. Returns (text, path) or
    (None, None) if no candidate exists. The index handler shows a
    plain-text error if the template is missing rather than
    crashing — the proxy itself can still service /s/<sid>/
    requests for any sessions that were opened before the template
    went missing."""
    for resolver in _INDEX_TEMPLATE_PATH_CANDIDATES:
        try:
            p = resolver()
        except Exception:
            continue
        if p and os.path.isfile(p):
            try:
                with open(p, 'r', encoding='utf-8') as f:
                    return f.read(), p
            except OSError:
                continue
    return None, None


INDEX_PAGE, INDEX_TEMPLATE_PATH = _load_index_template()


def render_servers_picker(args):
    """Build the quick-pick dropdown block from the servers file.
    Re-reads the file on every call so updates take effect on the
    next page refresh (no caching). Returns empty string if the
    file is missing or has no parseable entries — the form just
    operates as manual-entry-only in that case."""
    servers = parse_servers_file(getattr(args, 'servers_file', None))
    if not servers:
        return ''
    options = ['<option value="">(Manual entry — type fields below)</option>']
    for s in servers:
        options.append(
            '<option data-user="%s" data-port="%d">%s</option>' % (
                html.escape(s['user'], quote=True),
                s['port'],
                html.escape(s['label']),
            )
        )
    return (
        '<div class="row" style="margin-bottom: .8em">'
        '  <div style="flex: 1">'
        '    <label>Quick pick '
        '      <span class="muted">(from servers.txt — %d entries)</span>'
        '    </label>'
        '    <select id="server-picker" onchange="onServerPick()">%s</select>'
        '  </div>'
        '</div>'
    ) % (len(servers), ''.join(options))


def render_sessions_table():
    sessions = all_sessions()
    if not sessions:
        return '<p class="muted">No active sessions.</p>'
    rows = []
    now = time.time()
    for s in sessions:
        idle_s = int(now - s.last_used)
        rows.append(
            f'<tr>'
            f'<td><a href="/s/{html.escape(s.sid)}/">{html.escape(s.label())}</a></td>'
            f'<td>{s.request_count}</td>'
            f'<td>{idle_s}s</td>'
            f'<td><form method="POST" action="/disconnect" style="display:inline">'
            f'<input type="hidden" name="sid" value="{html.escape(s.sid)}">'
            f'<button type="submit" style="background:#a33;font-size:.85em;padding:.2em .8em">'
            f'Close</button></form></td>'
            f'</tr>'
        )
    return (
        '<table>'
        '<thead><tr><th>Session</th><th>Reqs</th><th>Idle</th><th></th></tr></thead>'
        '<tbody>' + ''.join(rows) + '</tbody>'
        '</table>'
    )


def render_index(args, error=None, prefill=None):
    if INDEX_PAGE is None:
        return (
            '<!doctype html><meta charset="utf-8"><title>ssh-web-proxy</title>'
            '<pre style="font-family:monospace;padding:1em">\n'
            'ERROR: templates/index.html is not installed next to '
            'ssh-web-proxy.\n'
            'Reinstall via the install.sh one-liner in the README to fix.\n'
            '</pre>'
        )
    prefill = prefill or {}
    subs = {
        '%%ERROR_HTML%%': (
            f'<div class="err">{html.escape(error)}</div>' if error else ''
        ),
        '%%PREFILL_USER%%':    html.escape(prefill.get('ssh_user', '')),
        '%%PREFILL_SSHPORT%%': html.escape(prefill.get('ssh_local_port', '')),
        '%%PREFILL_HOST%%':    html.escape(prefill.get('remote_host', '')),
        '%%PREFILL_PORT%%':    html.escape(prefill.get('remote_port', '80')),
        '%%PREFILL_COMMUNITY%%': html.escape(prefill.get('snmp_community', '')),
        '%%HTTP_SEL%%':  (' selected' if prefill.get('scheme', 'http') == 'http' else ''),
        '%%HTTPS_SEL%%': (' selected' if prefill.get('scheme') == 'https' else ''),
        '%%PROXY_CHECKED%%':    (' checked' if prefill.get('mode', 'proxy') != 'diagnose' else ''),
        '%%DIAGNOSE_CHECKED%%': (' checked' if prefill.get('mode') == 'diagnose' else ''),
        '%%N_ACTIVE%%':       str(len(all_sessions())),
        '%%SESSIONS_TABLE%%': render_sessions_table(),
        '%%SERVERS_PICKER%%': render_servers_picker(args),
        '%%BIND%%':           html.escape(args.bind),
        '%%PORT%%':           str(args.port),
        '%%IDLE_MIN%%':       str(SESSION_IDLE_TIMEOUT_S // 60),
    }
    out = INDEX_PAGE
    for k, v in subs.items():
        out = out.replace(k, v)
    return out


# ─── Input validation ─────────────────────────────────────────────────
_USER_RE = re.compile(r'^[A-Za-z0-9_][A-Za-z0-9_.\-]{0,31}$')


def validate_form(form):
    """Returns (ok_dict, error_str)."""
    ssh_user = (form.get('ssh_user', [''])[0] or '').strip()
    if not _USER_RE.match(ssh_user):
        return None, f'Invalid SSH username: {ssh_user!r}'
    try:
        ssh_local_port = int(form.get('ssh_local_port', [''])[0])
        if not 1 <= ssh_local_port <= 65535:
            raise ValueError
    except (ValueError, TypeError):
        return None, 'SSH local port must be 1..65535'
    remote_host = (form.get('remote_host', [''])[0] or '').strip()
    # Accept dotted-quad or hostname; reject obvious garbage.
    try:
        ipaddress.ip_address(remote_host)
    except ValueError:
        if not re.match(r'^[A-Za-z0-9][A-Za-z0-9.\-]{0,253}$', remote_host):
            return None, f'Invalid remote host: {remote_host!r}'
    try:
        remote_port = int(form.get('remote_port', [''])[0])
        if not 1 <= remote_port <= 65535:
            raise ValueError
    except (ValueError, TypeError):
        return None, 'Remote port must be 1..65535'
    scheme = form.get('scheme', ['http'])[0]
    if scheme not in ('http', 'https'):
        return None, f'Invalid scheme: {scheme!r}'
    return {
        'ssh_user': ssh_user,
        'ssh_local_port': ssh_local_port,
        'remote_host': remote_host,
        'remote_port': remote_port,
        'scheme': scheme,
    }, None


_COMMUNITY_RE = re.compile(r'^[A-Za-z0-9_\-.@]{1,64}$')


# ─── servers.txt quick-pick parser ────────────────────────────────────
#
# Reads a flat-text file with entries like:
#
#     #tunneladmin@localhost:8010
#     #dellwood_posadmin@127.0.0.1:11010
#
# The leading "#" is optional — both "#user@host:port" and
# "user@host:port" are accepted. Anything that doesn't match the
# user@host:port shape is silently skipped (so blank lines and any
# stray free-form notes don't break parsing).
#
# Re-read on every page-load (the function is cheap and the file
# is small); no caching at proxy-start.

_SERVERS_LINE_RE = re.compile(
    r'^\s*'
    r'#?\s*'                                      # optional leading hash
    r'([A-Za-z0-9_][A-Za-z0-9_.\-]{0,63})'        # ssh_user
    r'@'
    r'([A-Za-z0-9_.\-]+)'                         # host (usually localhost / 127.0.0.1)
    r':'
    r'(\d{1,5})'                                  # local mapped SSH port
    r'\s*$'
)


def parse_servers_file(path):
    """Return a list of dicts ``{'user', 'host', 'port', 'label'}``
    parsed from a servers.txt-style file. Missing / unreadable file
    returns ``[]``."""
    if not path or not os.path.isfile(path):
        return []
    try:
        with open(path, 'r', encoding='utf-8') as f:
            lines = f.read().splitlines()
    except OSError:
        return []
    out = []
    seen = set()
    for raw in lines:
        m = _SERVERS_LINE_RE.match(raw)
        if not m:
            continue
        user, host, port_s = m.group(1), m.group(2), m.group(3)
        try:
            port = int(port_s)
        except ValueError:
            continue
        if not 1 <= port <= 65535:
            continue
        key = (user.lower(), host.lower(), port)
        if key in seen:
            continue
        seen.add(key)
        out.append({
            'user':  user,
            'host':  host,
            'port':  port,
            'label': '%s  (port %d)' % (user, port),
        })
    return out


def validate_diagnose_form(form):
    """Validate the Diagnostics-mode form. Shares ssh_user / ssh_local_port
    / remote_host with the proxy form; adds snmp_community."""
    ssh_user = (form.get('ssh_user', [''])[0] or '').strip()
    if not _USER_RE.match(ssh_user):
        return None, f'Invalid SSH username: {ssh_user!r}'
    try:
        ssh_local_port = int(form.get('ssh_local_port', [''])[0])
        if not 1 <= ssh_local_port <= 65535:
            raise ValueError
    except (ValueError, TypeError):
        return None, 'SSH local port must be 1..65535'
    remote_host = (form.get('remote_host', [''])[0] or '').strip()
    try:
        ipaddress.ip_address(remote_host)
    except ValueError:
        if not re.match(r'^[A-Za-z0-9][A-Za-z0-9.\-]{0,253}$', remote_host):
            return None, f'Invalid remote host: {remote_host!r}'
    community = (form.get('snmp_community', [''])[0] or '').strip() or 'public'
    if not _COMMUNITY_RE.match(community):
        return None, ('Invalid SNMP community (allowed: letters, digits, '
                      '_ - . @, up to 64 chars)')
    return {
        'ssh_user': ssh_user,
        'ssh_local_port': ssh_local_port,
        'remote_host': remote_host,
        'snmp_community': community,
    }, None


# ─── Remote diagnostic script ────────────────────────────────────────
#
# The remote-side script lives in its own file (remote_diag.py)
# rather than being embedded as a string constant — easier to read,
# edit, and lint in a normal Python editor. It runs verbatim on the
# remote machine via `python3 -` (streamed over SSH stdin), reads
# its JSON config from sys.argv[1], runs three checks in parallel
# (ping / TCP 9100 / SNMP v1+v2c), and prints one JSON blob on
# stdout.
#
# Behavioral lessons baked into remote_diag.py (from
# printer_manager.protocols.snmp, beaten on against the whole fleet):
#
#   - Try SNMPv1 first then v2c. Receipt-printer SNMP agents tend to
#     speak v1 more reliably than v2c.
#   - Read hrPrinterErrorState as RAW BYTES (RFC 3805 OCTET STRING
#     bitfield), never text-decoded.
#   - Never trust hrPrinterStatus for status decisions — surfaced as
#     cosmetic only.
#   - Some printers go silent on TCP 9100 but their NIC still answers
#     SNMP (TM-U220 + UB-E04). SNMP is the irreplaceable check.
#
# Print-server-adapter awareness in remote_diag.py:
#
#   - Cheap Ethernet→USB adapters (TP-Link, D-Link, Edimax, IOGEAR, …)
#     typically expose only MIB-II basics, not Printer-MIB. The diag
#     queries the Printer-MIB OIDs anyway — the noSuchObject responses
#     are themselves informative.
#   - More expensive adapters (Silex, Lantronix) probe the attached
#     USB printer via IEEE 1284 and surface real status.
#   - Vendor identification via sysObjectID prefix (printer brands +
#     known print-server-chipset OUIs).

_REMOTE_DIAG_PATH_CANDIDATES = [
    # Dev / repo checkout: adjacent to this script. ALSO covers the
    # production case (install.sh installs both files into a single
    # /opt/ssh-web-proxy/ tree, so adjacency holds there too).
    lambda: os.path.join(
        os.path.dirname(os.path.abspath(__file__)), 'remote_diag.py'),
    # Explicit production fallback in case the main script was
    # symlinked or invoked via a wrapper that breaks __file__ adjacency.
    lambda: '/opt/ssh-web-proxy/remote_diag.py',
]


def _load_remote_diag_script():
    """Find and read remote_diag.py from the first existing candidate
    path. Returns (text, path) on success, (None, None) on failure.
    /diagnose errors cleanly if the file is missing."""
    for resolver in _REMOTE_DIAG_PATH_CANDIDATES:
        try:
            p = resolver()
        except Exception:
            continue
        if p and os.path.isfile(p):
            try:
                with open(p, 'r', encoding='utf-8') as f:
                    return f.read(), p
            except OSError:
                continue
    return None, None


REMOTE_DIAG_SCRIPT, REMOTE_DIAG_PATH = _load_remote_diag_script()


# ─── Driving the remote diag script over SSH ─────────────────────────
#
# Streams REMOTE_DIAG_SCRIPT over an exec_command channel's stdin to
# `python3 - <config_json>` on the remote. Captures stdout, stderr,
# exit code. Surfaces remote-side failures (python3 missing, syntax
# errors, JSON parse errors) as structured error info, NOT as
# uncaught exceptions.
import json as _json
import shlex as _shlex


def _run_remote_diag(ssh_client, target, community,
                     ping_timeout=2, tcp_timeout=5, snmp_timeout=5,
                     overall_timeout=20):
    """Returns (results_dict|None, error_info_dict|None).

    On success: results_dict is the parsed JSON from the remote
    script; error_info is None.

    On failure: results_dict is None (or partial) and error_info
    describes what went wrong, distinguishing:
      - SSH transport error (unusual — we already connected)
      - python3 not found on remote PATH
      - remote script exited non-zero (with stderr captured)
      - remote produced non-JSON stdout
      - overall timeout exceeded
    """
    cfg = {'target': target, 'community': community,
           'ping_timeout': ping_timeout, 'tcp_timeout': tcp_timeout,
           'snmp_timeout': snmp_timeout}
    if not REMOTE_DIAG_SCRIPT:
        return None, {
            'kind': 'remote_diag_missing',
            'msg': ('remote_diag.py is not installed next to '
                    'ssh-web-proxy. Reinstall via the one-liner '
                    'in the README to fix.'),
        }
    cfg_arg = _shlex.quote(_json.dumps(cfg))
    cmd = 'python3 - {}'.format(cfg_arg)
    try:
        transport = ssh_client.get_transport()
        if transport is None or not transport.is_active():
            return None, {'kind': 'ssh_dead',
                          'msg': 'SSH transport not active'}
        channel = _safe_open_session(transport, overall_timeout)
        channel.settimeout(overall_timeout)
        channel.exec_command(cmd)
        # Stream the script over stdin
        channel.sendall(REMOTE_DIAG_SCRIPT.encode('utf-8'))
        channel.shutdown_write()
        # Drain stdout + stderr until the channel closes
        stdout_buf = []
        stderr_buf = []
        start = time.time()
        while True:
            if channel.recv_ready():
                chunk = channel.recv(65536)
                if not chunk: break
                stdout_buf.append(chunk)
            if channel.recv_stderr_ready():
                chunk = channel.recv_stderr(65536)
                if chunk:
                    stderr_buf.append(chunk)
            if channel.exit_status_ready():
                # Drain remaining buffered data
                while channel.recv_ready():
                    stdout_buf.append(channel.recv(65536))
                while channel.recv_stderr_ready():
                    stderr_buf.append(channel.recv_stderr(65536))
                break
            if time.time() - start > overall_timeout:
                try: channel.close()
                except Exception: pass
                return None, {
                    'kind': 'overall_timeout',
                    'msg': f'Remote script did not return within '
                           f'{overall_timeout}s',
                    'stdout': b''.join(stdout_buf).decode('utf-8', 'replace'),
                    'stderr': b''.join(stderr_buf).decode('utf-8', 'replace'),
                }
            time.sleep(0.02)
        exit_code = channel.recv_exit_status()
        try: channel.close()
        except Exception: pass
    except paramiko.SSHException as e:
        return None, {'kind': 'ssh_exception', 'msg': str(e)}

    stdout = b''.join(stdout_buf).decode('utf-8', 'replace')
    stderr = b''.join(stderr_buf).decode('utf-8', 'replace')

    # Surface common remote failures distinctly
    if exit_code != 0:
        # The shell often prints "python3: command not found" or
        # "python3: No such file or directory" when python isn't
        # installed. We also accept "/usr/bin/env: python3:" forms.
        stderr_low = stderr.lower()
        if ('command not found' in stderr_low
                or 'no such file or directory' in stderr_low
                or 'not found' in stderr_low and 'python' in stderr_low):
            return None, {
                'kind': 'python3_missing',
                'msg': 'python3 is not installed on the remote (or not '
                       'in the login PATH for this user).',
                'stderr': stderr,
                'exit_code': exit_code,
            }
        return None, {
            'kind': 'remote_nonzero_exit',
            'msg': f'Remote diagnostic script exited with code {exit_code}.',
            'stdout': stdout,
            'stderr': stderr,
            'exit_code': exit_code,
        }
    try:
        results = _json.loads(stdout)
    except _json.JSONDecodeError as e:
        return None, {
            'kind': 'bad_json',
            'msg': f'Remote returned non-JSON output: {e}',
            'stdout': stdout,
            'stderr': stderr,
        }
    return results, None


# ─── Diagnostic results HTML renderer ─────────────────────────────────
def render_diagnose_results(meta, results, error_info):
    """Render the diagnostics results page."""
    e = html.escape
    css = """
        body { font-family: -apple-system, system-ui, "Segoe UI", sans-serif;
               max-width: 900px; margin: 2em auto; padding: 0 1em; color: #222; }
        h1 { font-size: 1.3em; border-bottom: 1px solid #ddd; padding-bottom: .3em; }
        .card { border: 1px solid #ccc; border-radius: 4px; padding: 1em 1.2em;
                margin: 1em 0; background: #fff; }
        .card.ok { border-left: 4px solid #2a7; }
        .card.fail { border-left: 4px solid #c33; }
        .card.partial { border-left: 4px solid #e90; }
        .card h2 { font-size: 1em; margin: 0 0 .5em 0;
                   display: flex; align-items: baseline; gap: .5em; }
        .badge { font-size: .75em; padding: .15em .5em; border-radius: 3px; }
        .badge.ok { background: #def2e0; color: #0a5; }
        .badge.fail { background: #fde0e0; color: #c33; }
        .badge.partial { background: #fef3d6; color: #b75; }
        .muted { color: #888; font-size: .85em; }
        table { border-collapse: collapse; width: 100%; margin: .5em 0;
                font-size: .9em; }
        th, td { padding: .3em .6em; text-align: left;
                 border-bottom: 1px solid #eee; vertical-align: top; }
        th { background: #f7f7f7; }
        code { background: #f3f3f3; padding: 0 .3em; border-radius: 2px;
               font-size: .9em; }
        .err-box { background: #fee; border: 1px solid #fbb; color: #800;
                   padding: .8em 1.2em; border-radius: 3px; margin: 1em 0; }
        details summary { cursor: pointer; color: #555; font-size: .85em; }
        pre { background: #f3f3f3; padding: .6em; border-radius: 3px;
              overflow-x: auto; font-size: .85em; white-space: pre-wrap; }
        .refresh-row { margin-top: 2em; text-align: center; }
        button { padding: .5em 1.2em; font-size: 1em; cursor: pointer;
                 background: #2c7be5; color: white; border: none;
                 border-radius: 3px; }
        button:hover { background: #1a5fc4; }
    """
    head = (
        f'<!doctype html><html lang="en"><head><meta charset="utf-8">'
        f'<title>Diagnostics — {e(meta["target"])}</title>'
        f'<style>{css}</style></head><body>'
        f'<h1>Diagnostics for <code>{e(meta["target"])}</code></h1>'
        f'<p class="muted">via {e(meta["ssh_user"])}@127.0.0.1:'
        f'{meta["ssh_local_port"]} → '
        f'SNMP community <code>{e(meta["community"])}</code></p>'
    )

    # Refresh = re-POST the same form values to /diagnose in the
    # current tab. Hidden form is rendered alongside the button so
    # the browser submits it natively, no JS resubmit/double-POST
    # warning.
    refresh_block = (
        f'<form method="POST" action="/diagnose" class="refresh-row">'
        f'<input type="hidden" name="mode" value="diagnose">'
        f'<input type="hidden" name="ssh_user" value="{e(meta["ssh_user"])}">'
        f'<input type="hidden" name="ssh_local_port" '
        f'value="{e(str(meta["ssh_local_port"]))}">'
        f'<input type="hidden" name="remote_host" value="{e(meta["target"])}">'
        f'<input type="hidden" name="snmp_community" '
        f'value="{e(meta["community"])}">'
        f'<button type="submit">↻ Refresh</button>'
        f'</form>'
    )

    body_parts = [head]

    # Top-level error (couldn't even run the remote script)
    if error_info:
        kind = error_info['kind']
        body_parts.append(f'<div class="err-box">')
        body_parts.append(f'<strong>{e(error_info["msg"])}</strong>')
        if kind == 'python3_missing':
            body_parts.append(
                '<p>The diagnostic script needs <code>python3</code> on the '
                'remote\'s PATH for the SSH login user. On Ubuntu 18.04+ this '
                'is in the base install; verify with:</p>'
                '<pre>ssh ' + e(meta["ssh_user"]) + '@127.0.0.1 -p '
                + str(meta["ssh_local_port"]) + ' which python3</pre>'
            )
        for k in ('stderr', 'stdout'):
            if error_info.get(k):
                body_parts.append(
                    f'<details><summary>Show {k}</summary>'
                    f'<pre>{e(error_info[k])}</pre></details>'
                )
        body_parts.append('</div>')
        body_parts.append(refresh_block)
        body_parts.append('</body></html>')
        return ''.join(body_parts)

    # === Ping card ===
    ping = results.get('ping') or {}
    if ping.get('ok'):
        rtt = ping.get('rtt_ms')
        summary = f'{rtt:.1f} ms' if rtt is not None else 'reachable'
        body_parts.append(
            f'<div class="card ok"><h2>Ping '
            f'<span class="badge ok">reachable</span>'
            f'<span class="muted">{e(summary)}</span></h2>'
        )
    else:
        body_parts.append(
            f'<div class="card fail"><h2>Ping '
            f'<span class="badge fail">fail</span>'
            f'<span class="muted">{e(ping.get("error", "unknown"))}</span></h2>'
        )
    if ping.get('stdout'):
        body_parts.append(
            f'<details><summary>Raw ping output</summary>'
            f'<pre>{e(ping["stdout"])}</pre></details>'
        )
    body_parts.append('</div>')

    # === TCP 9100 card ===
    tcp = results.get('tcp9100') or {}
    if tcp.get('ok'):
        body_parts.append(
            f'<div class="card ok"><h2>TCP 9100 '
            f'<span class="badge ok">open</span>'
            f'<span class="muted">connected in {tcp.get("elapsed_ms", "?")} ms</span></h2>'
        )
    else:
        body_parts.append(
            f'<div class="card fail"><h2>TCP 9100 '
            f'<span class="badge fail">closed</span>'
            f'<span class="muted">{e(tcp.get("error", "unknown"))}'
            f' ({tcp.get("elapsed_ms", "?")} ms)</span></h2>'
        )
    body_parts.append('</div>')

    # === SNMP card ===
    EXCEPTION_TYPES = {'ErrorStatus', 'noSuchObject', 'noSuchInstance',
                       'endOfMibView'}
    snmp = results.get('snmp') or {}
    if snmp.get('ok'):
        answers_dict = snmp.get('answers') or {}
        n_useful = sum(
            1 for v in answers_dict.values()
            if v.get('value') is not None
            and v.get('type') not in EXCEPTION_TYPES
        )
        n_total = len(answers_dict)
        decoded = snmp.get('decoded') or {}
        status = decoded.get('status', 'unknown')
        # Map printer-manager's status hierarchy to badge styling.
        # Cover-open is its own thing because it's the most common
        # & most actionable single fault.
        STATUS_BADGES = {
            'online':              ('ok',      'online'),
            'cover_open':          ('partial', 'cover open'),
            'offline':             ('fail',    'offline (device reports down)'),
            'error':               ('partial', 'error'),
            'responsive_no_status':('partial', 'responsive (no actionable status)'),
            'unknown':             ('partial', 'no status info'),
        }
        klass, badge_label = STATUS_BADGES.get(
            status, ('partial', status)
        )
        body_parts.append(
            f'<div class="card {klass}"><h2>SNMP '
            f'<span class="badge {klass}">{e(badge_label)}</span>'
            f'<span class="muted">{n_useful}/{n_total} OIDs answered, '
            f'{snmp.get("elapsed_ms", "?")} ms</span></h2>'
        )

        # ── Decoded POS-relevant status (primary display) ───────────
        # Translated from raw OID values by remote_diag.py — labels
        # and vocabulary mirror printer_manager.protocols.snmp
        # so what you see here matches what the manager UI shows.
        def _pill(value, ok_set, warn_set, fail_set):
            if value in ok_set:
                return f'<span class="badge ok">{e(value)}</span>'
            if value in fail_set:
                return f'<span class="badge fail">{e(value)}</span>'
            if value in warn_set:
                return f'<span class="badge partial">{e(value)}</span>'
            return f'<span class="muted">{e(value)}</span>'
        decoded_rows = []
        # Paper: matches printer-manager vocab — empty/near_end/ok
        if decoded.get('paper'):
            decoded_rows.append((
                'Paper',
                _pill(decoded['paper'],
                      ok_set={'ok'},
                      warn_set={'near_end'},
                      fail_set={'empty'}),
            ))
        if decoded.get('cover'):
            decoded_rows.append((
                'Cover',
                _pill(decoded['cover'],
                      ok_set={'closed'}, warn_set=set(), fail_set={'open'}),
            ))
        if decoded.get('device_down'):
            decoded_rows.append((
                'Device',
                '<span class="badge fail">offline (hrDeviceStatus=down)</span>',
            ))
        # Raw RFC 3805 bit names that aren't already represented by
        # paper/cover/device-down. Surfaces toner, jam, service-required,
        # tray, etc. — same `errors` list shape printer-manager publishes.
        SHOWN_BITS = {'lowPaper', 'noPaper', 'doorOpen', 'offline'}
        other_errors = [b for b in (decoded.get('errors') or [])
                        if b not in SHOWN_BITS]
        if other_errors:
            decoded_rows.append((
                'Other error bits',
                ' '.join(f'<span class="badge fail">{e(b)}</span>'
                         for b in other_errors),
            ))
        if decoded.get('firmware_reports'):
            decoded_rows.append((
                'Firmware reports',
                f'<span class="muted" title="hrPrinterStatus — '
                f'unreliable on most printers, display only">'
                f'{e(decoded["firmware_reports"])}</span>',
            ))
        if decoded_rows:
            body_parts.append('<table style="margin: .5em 0 1em 0">')
            for label, val in decoded_rows:
                body_parts.append(
                    f'<tr><td style="width:35%; color:#555">{e(label)}</td>'
                    f'<td>{val}</td></tr>'
                )
            body_parts.append('</table>')

        # ── Identity (primary display — device descr, serial, MAC, etc.) ──
        # Pulls the identity OIDs out of answers_dict and formats them
        # for human reading (MAC bytes → AA:BB:CC:..., uptime ticks →
        # days/hours, ifSpeed bits/s → Mbit/s, etc.). Only rows with a
        # real value are shown; empty strings and noSuchName entries
        # are dropped.
        def _val(name):
            ent = answers_dict.get(name) or {}
            if not ent or ent.get('value') in (None, ''):
                return None
            if ent.get('type') in EXCEPTION_TYPES:
                return None
            return ent

        def _format_mac(hex_str):
            if not hex_str or len(hex_str) != 12:
                return None
            return ':'.join(hex_str[i:i+2] for i in range(0, 12, 2)).lower()

        def _format_uptime(seconds):
            if seconds is None:
                return None
            s = int(seconds)
            days, rem = divmod(s, 86400)
            hours, rem = divmod(rem, 3600)
            mins, _   = divmod(rem, 60)
            if days:
                return f'{days}d {hours}h {mins}m'
            if hours:
                return f'{hours}h {mins}m'
            return f'{mins}m'

        def _format_speed(bps):
            try:
                bps = int(bps)
            except (TypeError, ValueError):
                return None
            if bps == 0:
                return None
            if bps >= 1_000_000_000:
                return f'{bps // 1_000_000_000} Gbit/s'
            if bps >= 1_000_000:
                return f'{bps // 1_000_000} Mbit/s'
            if bps >= 1000:
                return f'{bps // 1000} kbit/s'
            return f'{bps} bit/s'

        IF_OPER = {1: 'up', 2: 'down', 3: 'testing', 4: 'unknown',
                   5: 'dormant', 6: 'notPresent', 7: 'lowerLayerDown'}

        identity_rows = []
        # Device-level
        dev_desc = _val('hrDeviceDescr') or _val('prtGeneralPrinterName')
        if dev_desc:
            identity_rows.append(('Device', e(str(dev_desc['value']))))
        serial = _val('prtGeneralSerialNumber')
        if serial:
            identity_rows.append(('Serial number',
                                  f'<code>{e(str(serial["value"]))}</code>'))
        # Network-level
        sysname = _val('sysName')
        if sysname:
            identity_rows.append(('Hostname (sysName)',
                                  f'<code>{e(str(sysname["value"]))}</code>'))
        mac_entry = _val('ifPhysAddress')
        if mac_entry:
            raw = mac_entry.get('hex') or str(mac_entry.get('value', ''))
            mac = _format_mac(raw)
            if mac:
                identity_rows.append(('MAC address',
                                      f'<code>{e(mac)}</code>'))
        # Link
        oper_entry = _val('ifOperStatus')
        speed_entry = _val('ifSpeed')
        if oper_entry or speed_entry:
            link_parts = []
            if oper_entry:
                try:
                    code = int(oper_entry['value'])
                    state = IF_OPER.get(code, f'code={code}')
                except (ValueError, TypeError):
                    state = str(oper_entry['value'])
                klass = 'ok' if state == 'up' else 'fail' if state == 'down' else 'partial'
                link_parts.append(f'<span class="badge {klass}">{e(state)}</span>')
            if speed_entry:
                spd = _format_speed(speed_entry['value'])
                if spd:
                    link_parts.append(f'<span class="muted">{e(spd)}</span>')
            identity_rows.append(('Link', ' '.join(link_parts)))
        # Uptime
        upt_entry = _val('sysUpTime')
        if upt_entry:
            secs = upt_entry.get('seconds')
            human = _format_uptime(secs)
            if human:
                identity_rows.append((
                    'System uptime',
                    f'{e(human)} <span class="muted">'
                    f'(since last reboot)</span>',
                ))
        # Description (verbose, less critical — placed near bottom)
        sysdescr = _val('sysDescr')
        if sysdescr:
            identity_rows.append(('System description',
                                  f'<small>{e(str(sysdescr["value"]))}</small>'))
        # Optional admin metadata
        sysloc = _val('sysLocation')
        if sysloc:
            identity_rows.append(('Location',
                                  e(str(sysloc['value']))))
        syscontact = _val('sysContact')
        if syscontact:
            identity_rows.append(('Contact',
                                  e(str(syscontact['value']))))

        if identity_rows:
            body_parts.append(
                '<table style="margin: .5em 0 1em 0">'
                '<thead><tr><th colspan="2" '
                'style="text-align:left; color:#555; font-weight:normal; '
                'font-size:.85em; border-bottom:1px solid #ddd; '
                'padding-bottom:.2em">Identity</th></tr></thead><tbody>'
            )
            for label, val in identity_rows:
                body_parts.append(
                    f'<tr><td style="width:35%; color:#555">{e(label)}</td>'
                    f'<td>{val}</td></tr>'
                )
            body_parts.append('</tbody></table>')

        # Compact agent metadata (vendor / classification / protocol)
        vmeta = []
        if snmp.get('vendor_from_sysoid'):
            vmeta.append(f'vendor: <code>{e(snmp["vendor_from_sysoid"])}</code>')
        if snmp.get('classification'):
            vmeta.append(f'agent: <code>{e(snmp["classification"])}</code>')
        if snmp.get('snmp_versions'):
            vmeta.append(f'protocol: {", ".join(snmp["snmp_versions"])}')
        if vmeta:
            body_parts.append(
                '<p class="muted" style="font-size:.85em">'
                + ' &middot; '.join(vmeta) + '</p>'
            )

        # ── Raw OID table (collapsed by default — for debugging) ────
        body_parts.append(
            '<details style="margin-top: .8em">'
            '<summary>Show all 20 raw OID values</summary>'
            '<table style="margin-top: .5em">'
            '<thead><tr><th>OID name</th><th>Value</th>'
            '<th>Type</th><th>OID</th></tr></thead><tbody>'
        )
        for name, info in answers_dict.items():
            val = info.get('value')
            typ = info.get('type')
            if val is None:
                val_disp = (f'<span class="muted">'
                            f'{e(info.get("error", "—"))}</span>')
            elif typ in EXCEPTION_TYPES:
                val_disp = (f'<span class="muted" '
                            f'title="agent responded but does not '
                            f'support this OID">{e(str(val))}</span>')
            elif info.get('binary'):
                val_disp = f'<code>0x{e(info.get("hex", ""))}</code>'
            elif typ == 'TimeTicks':
                secs = info.get('seconds')
                if secs is not None:
                    val_disp = (f'{secs:.1f} s '
                                f'<span class="muted">({val} ticks)</span>')
                else:
                    val_disp = e(str(val))
            else:
                val_disp = e(str(val))
            body_parts.append(
                f'<tr><td>{e(name)}</td>'
                f'<td>{val_disp}</td>'
                f'<td><span class="muted">{e(typ or "—")}</span></td>'
                f'<td><code class="muted">{e(info["oid"])}</code></td></tr>'
            )
        body_parts.append('</tbody></table></details>')
    else:
        body_parts.append(
            f'<div class="card fail"><h2>SNMP '
            f'<span class="badge fail">no response</span>'
            f'<span class="muted">{e(snmp.get("error", "unknown"))}</span></h2>'
            f'<p class="muted">No reply on any of the standard OIDs at '
            f'v1 or v2c. Either SNMP is disabled on the device, the '
            f'community string is wrong, or UDP 161 is firewalled on '
            f'the remote network.</p>'
        )
    body_parts.append('</div>')

    body_parts.append(
        f'<p class="muted">Total wall time: '
        f'{results.get("__elapsed_ms", "?")} ms, '
        f'remote python: {e(results.get("__python_version", "?"))}</p>'
    )
    body_parts.append(refresh_block)
    body_parts.append('</body></html>')
    return ''.join(body_parts)


# ─── HTTP handler ─────────────────────────────────────────────────────
class ProxyHandler(BaseHTTPRequestHandler):

    # Pass args through via the server instance.
    @property
    def args(self):
        return self.server._args  # type: ignore[attr-defined]

    # Quiet the default logging spam; we'll print our own one-liner.
    def log_message(self, fmt, *a):
        sys.stderr.write(
            f'[{time.strftime("%Y-%m-%d %H:%M:%S")}] '
            f'{self.client_address[0]} {self.command} {self.path} — '
            f'{fmt % a}\n'
        )

    # ── Dispatcher ────────────────────────────────────────────────
    def do_GET(self):     return self._dispatch()
    def do_POST(self):    return self._dispatch()
    def do_PUT(self):     return self._dispatch()
    def do_DELETE(self):  return self._dispatch()
    def do_PATCH(self):   return self._dispatch()
    def do_OPTIONS(self): return self._dispatch()
    def do_HEAD(self):    return self._dispatch()

    def _dispatch(self):
        try:
            path = urlsplit(self.path).path
            if path == '/' and self.command == 'GET':
                return self._render_index()
            if path == '/connect' and self.command == 'POST':
                return self._connect()
            if path == '/diagnose' and self.command == 'POST':
                return self._diagnose()
            if path == '/disconnect' and self.command == 'POST':
                return self._disconnect()
            if path == '/healthz' and self.command == 'GET':
                return self._send_text(200, 'ok')
            if path.startswith('/s/'):
                return self._proxy()
            return self._send_text(404, 'Not found')
        except BrokenPipeError:
            return  # client gave up
        except Exception as e:
            traceback.print_exc()
            try:
                self._send_text(500, f'Proxy internal error: {e}')
            except Exception:
                pass

    # ── Index page ────────────────────────────────────────────────
    def _render_index(self, error=None, prefill=None):
        body = render_index(self.args, error=error, prefill=prefill).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_text(self, status, msg, ctype='text/plain; charset=utf-8'):
        data = msg.encode() if isinstance(msg, str) else msg
        self.send_response(status)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _read_form(self):
        length = int(self.headers.get('Content-Length') or 0)
        raw = self.rfile.read(length) if length else b''
        return parse_qs(raw.decode('utf-8', errors='replace'),
                        keep_blank_values=True)

    # ── /connect ──────────────────────────────────────────────────
    def _connect(self):
        form = self._read_form()
        cfg, err = validate_form(form)
        if err:
            return self._render_index(error=err, prefill={
                k: v[0] if v else '' for k, v in form.items()
            })
        try:
            ssh_client = open_ssh(cfg['ssh_user'], cfg['ssh_local_port'])
        except paramiko.AuthenticationException as e:
            return self._render_index(
                error=(
                    f'SSH authentication failed: {e}. '
                    f'{_diagnose_auth_failure(cfg["ssh_user"], cfg["ssh_local_port"])}'
                ),
                prefill={k: v[0] if v else '' for k, v in form.items()},
            )
        except (paramiko.SSHException, OSError) as e:
            return self._render_index(
                error=f'SSH connect failed: {e}',
                prefill={k: v[0] if v else '' for k, v in form.items()},
            )

        sid = secrets.token_urlsafe(12)
        sess = Session(
            sid=sid,
            ssh_user=cfg['ssh_user'],
            ssh_local_port=cfg['ssh_local_port'],
            remote_host=cfg['remote_host'],
            remote_port=cfg['remote_port'],
            scheme=cfg['scheme'],
            ssh_client=ssh_client,
        )
        try:
            add_session(sess)
        except RuntimeError as e:
            sess.close()
            return self._render_index(error=str(e), prefill={
                k: v[0] if v else '' for k, v in form.items()
            })

        self.send_response(302)
        self.send_header('Location', f'/s/{sid}/')
        self.end_headers()

    # ── /diagnose ─────────────────────────────────────────────────
    def _diagnose(self):
        form = self._read_form()
        cfg, err = validate_diagnose_form(form)
        prefill = {k: v[0] if v else '' for k, v in form.items()}
        prefill['mode'] = 'diagnose'
        if err:
            return self._render_index(error=err, prefill=prefill)
        try:
            ssh_client = open_ssh(cfg['ssh_user'], cfg['ssh_local_port'])
        except paramiko.AuthenticationException as e:
            return self._render_index(
                error=(
                    f'SSH authentication failed: {e}. '
                    f'{_diagnose_auth_failure(cfg["ssh_user"], cfg["ssh_local_port"])}'
                ),
                prefill=prefill,
            )
        except (paramiko.SSHException, OSError) as e:
            return self._render_index(
                error=f'SSH connect failed: {e}', prefill=prefill,
            )

        diag_meta = {'ssh_user': cfg['ssh_user'],
                     'ssh_local_port': cfg['ssh_local_port'],
                     'target': cfg['remote_host'],
                     'community': cfg['snmp_community']}
        try:
            results, error_info = _run_remote_diag(
                ssh_client,
                target=cfg['remote_host'],
                community=cfg['snmp_community'],
            )
        finally:
            try: ssh_client.close()
            except Exception: pass

        body = render_diagnose_results(diag_meta, results, error_info).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # ── /disconnect ───────────────────────────────────────────────
    def _disconnect(self):
        form = self._read_form()
        sid = (form.get('sid', [''])[0] or '').strip()
        drop_session(sid)
        self.send_response(302)
        self.send_header('Location', '/')
        self.end_headers()

    # ── /s/<sid>/<path> proxy ─────────────────────────────────────
    def _proxy(self):
        # Parse out sid and the upstream path
        split = urlsplit(self.path)
        path = split.path
        m = re.match(r'^/s/([A-Za-z0-9_\-]+)(/.*)?$', path)
        if not m:
            return self._send_text(400, 'Malformed session URL')
        sid = m.group(1)
        upstream_path = m.group(2) or '/'
        sess = get_session(sid)
        if not sess:
            return self._send_text(
                404,
                'Session not found or expired. Return to / to open a new one.',
            )
        if not sess.is_alive():
            drop_session(sid)
            return self._send_text(
                502,
                'SSH session is dead. Return to / to reopen.',
            )

        proxy_base = f'/s/{sid}/'
        page_path = upstream_path.lstrip('/')

        # Rebuild path+query for the upstream
        target_pq = upstream_path
        if split.query:
            target_pq += '?' + split.query

        # Headers
        raw_headers = {k: v for k, v in self.headers.items()}
        req_headers = filter_request_headers(
            raw_headers, sess.remote_host, proxy_base,
        )

        # Body (for methods that have one)
        body = None
        clen = int(self.headers.get('Content-Length') or 0)
        if clen:
            body = self.rfile.read(clen)

        try:
            status, headers_list, body_bytes = http_through_ssh(
                sess, self.command, target_pq, req_headers, body,
            )
        except Exception as e:
            return self._send_text(
                502, f'Upstream error through SSH: {e}',
            )

        # ── Auto-upgrade session scheme/port on cross-scheme redirect ──
        # If the device returns a 3xx with Location pointing at itself
        # under a different scheme/port (e.g. http://device/ →
        # https://device/login), update the session so subsequent
        # requests use the new scheme/port. Without this, the proxy
        # would keep hitting the original http:80 endpoint and the
        # browser would follow the rewritten Location into an
        # infinite redirect loop.
        #
        # Safety: only same-host redirects trigger the upgrade. A
        # Location pointing at a different IP / hostname stays
        # un-rewritten and the browser's subsequent request will fail
        # cleanly rather than us proxying anywhere the device asked.
        if 300 <= status < 400:
            for hk, hv in headers_list:
                if hk.lower() != 'location' or not hv:
                    continue
                try:
                    parsed = urlsplit(hv)
                except Exception:
                    break
                if parsed.scheme not in ('http', 'https'):
                    break
                if not parsed.hostname:
                    break
                # Same-host check — case-insensitive hostname compare.
                # Accepts both IP and hostname forms as long as they
                # match the session's configured remote_host literally.
                if parsed.hostname.lower() != sess.remote_host.lower():
                    break
                new_port = parsed.port
                if new_port is None:
                    new_port = 443 if parsed.scheme == 'https' else 80
                if (parsed.scheme != sess.scheme
                        or new_port != sess.remote_port):
                    old = (sess.scheme, sess.remote_port)
                    sess.scheme = parsed.scheme
                    sess.remote_port = new_port
                    sys.stderr.write(
                        f'[session {sess.sid}] auto-upgrade '
                        f'{old[0]}:{old[1]} -> '
                        f'{parsed.scheme}:{new_port} '
                        f'(triggered by {status} Location header)\n'
                    )
                break

        # Filter+rewrite response headers
        final_headers = rewrite_response_headers(
            headers_list, sess.remote_host, proxy_base,
        )

        # Rewrite body for text/html/css/js
        content_type = ''
        for k, v in headers_list:
            if k.lower() == 'content-type':
                content_type = v
                break
        body_bytes = rewrite_body(
            body_bytes, content_type, sess.remote_host,
            proxy_base, page_path,
        )

        # Fix up Content-Length after rewrite
        final_headers = [
            (k, v) for k, v in final_headers
            if k.lower() != 'content-length'
        ]
        final_headers.append(('Content-Length', str(len(body_bytes))))

        self.send_response(status)
        for k, v in final_headers:
            self.send_header(k, v)
        self.end_headers()
        if self.command != 'HEAD':
            try:
                self.wfile.write(body_bytes)
            except BrokenPipeError:
                pass


class ThreadingServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


# ─── Port-availability check (the only port we bind) ──────────────────
def check_port_free(bind, port):
    """Verify the listener port is free BEFORE we try to bind. Gives
    a clearer error than a raw OSError."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind((bind, port))
    except OSError as e:
        s.close()
        return False, str(e)
    s.close()
    return True, ''


# ─── Private-IP auto-detection (default bind behavior) ───────────────
#
# We walk the host's global-scope IPv4 addresses and pick the first one
# in an RFC 1918 range. Re-runs on every startup, so a systemctl
# restart after the host's IP changes (DHCP lease refresh, NIC swap,
# subnet renumbering) picks up the new address with no operator action.
#
# Refuses to fall back to 0.0.0.0 — if no private address exists, we'd
# rather fail loud than silently expose the listener to a public
# interface on a multi-homed host.
_RFC1918 = (
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
)


def _get_default_route_iface():
    """Return the interface name carrying the IPv4 default route, or
    None. This is the operator-reachable NIC on a multi-NIC host —
    docker0 / virbr0 / VPN bridges typically don't have the default
    route, so we use this to prefer the real LAN NIC over them when
    multiple RFC 1918 candidates exist."""
    try:
        out = subprocess.check_output(
            ['ip', '-4', 'route', 'show', 'default'],
            stderr=subprocess.DEVNULL,
        ).decode('utf-8', 'replace')
    except (OSError, subprocess.SubprocessError):
        return None
    for line in out.splitlines():
        parts = line.split()
        # "default via 192.168.0.1 dev enp1s0 proto dhcp src 192.168.0.104 ..."
        if parts and parts[0] == 'default' and 'dev' in parts:
            try:
                return parts[parts.index('dev') + 1]
            except IndexError:
                pass
    return None


def detect_private_ips():
    """Return RFC 1918 IPv4 addresses on global-scope interfaces,
    ordered so the address on the default-route NIC comes first. That
    way ``BIND=auto`` picks the operator-reachable LAN address, not
    a docker bridge or virbr0 that happens to alphabetize earlier.

    Empty list if none. Uses ``ip -4 -o addr show scope global``,
    universally available on every modern Linux distro."""
    try:
        out = subprocess.check_output(
            ['ip', '-4', '-o', 'addr', 'show', 'scope', 'global'],
            stderr=subprocess.DEVNULL,
        ).decode('utf-8', 'replace')
    except (OSError, subprocess.SubprocessError):
        return []
    default_iface = _get_default_route_iface()
    primary = []
    secondary = []
    for line in out.splitlines():
        parts = line.split()
        # ip -o output: "2: enp1s0    inet 192.168.0.104/24 brd ..."
        # parts[1] = interface name, parts[3] = "A.B.C.D/N"
        if len(parts) < 4:
            continue
        iface = parts[1]
        addr = parts[3].split('/')[0]
        try:
            ip = ipaddress.IPv4Address(addr)
        except ValueError:
            continue
        if not any(ip in net for net in _RFC1918):
            continue
        if iface == default_iface:
            primary.append(addr)
        else:
            secondary.append(addr)
    return primary + secondary


def resolve_bind(requested):
    """Resolve the -b argument to an actual IP. ``'auto'`` (default)
    triggers RFC 1918 detection; an explicit IP is passed through
    unchanged. Exits the process with a diagnostic message if auto-
    detection finds nothing."""
    if requested != 'auto':
        return requested
    found = detect_private_ips()
    if not found:
        sys.stderr.write(
            "ERROR: no RFC 1918 private IPv4 address found on this host.\n"
            "       Scanned ranges:\n"
            "         10.0.0.0/8      (10.x.x.x)\n"
            "         172.16.0.0/12   (172.16-31.x.x)\n"
            "         192.168.0.0/16  (192.168.x.x)\n"
            "       Pass -b <address> explicitly to override.\n"
        )
        sys.exit(2)
    if len(found) > 1:
        sys.stderr.write(
            f"NOTE: multiple private IPs detected ({', '.join(found)}); "
            f"binding to {found[0]}. Pass -b <ip> to pick a different one.\n"
        )
    return found[0]


# ─── Main ────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(
        description='Single-file SSH-tunneled web proxy. Opens device '
                    'web UIs through reverse-tunneled SSH connections.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split('USAGE')[1].split('SECURITY')[0],
    )
    ap.add_argument('-p', '--port', type=int, default=9999,
                    help='HTTP listener port (default 9999)')
    ap.add_argument('-b', '--bind', default='auto',
                    help='Bind address. "auto" (default) picks the first '
                         'RFC 1918 private IPv4 on the host at startup '
                         '(re-runs every restart so IP changes are '
                         'picked up automatically). Pass an explicit IP '
                         'to pin it.')
    ap.add_argument('--servers-file', default=None,
                    help='Path to a "servers.txt" with one '
                         '"#user@host:port" entry per line. Populates '
                         'the form\'s quick-pick dropdown. Re-read on '
                         'every page load. Defaults to '
                         '~/printer-check/servers.txt (in the service '
                         'user\'s home). Optional — missing file just '
                         'means no dropdown.')
    args = ap.parse_args()
    args.bind = resolve_bind(args.bind)
    if args.servers_file is None:
        args.servers_file = os.path.join(
            os.path.expanduser('~'), 'printer-check', 'servers.txt'
        )

    ok, err = check_port_free(args.bind, args.port)
    if not ok:
        print(
            f'ERROR: cannot bind {args.bind}:{args.port} — {err}\n'
            f'Pick a different port with -p.',
            file=sys.stderr,
        )
        sys.exit(3)

    server = ThreadingServer((args.bind, args.port), ProxyHandler)
    server._args = args  # type: ignore[attr-defined]

    # Background reaper for idle sessions.
    threading.Thread(target=_gc_loop, daemon=True).start()

    print(
        f'ssh_web_proxy listening on http://{args.bind}:{args.port}/\n'
        f'  - tunnel ports allocated: 0 (using direct-tcpip channels)\n'
        f'  - session idle timeout:   {SESSION_IDLE_TIMEOUT_S // 60} min\n'
        f'  - max sessions:           {MAX_SESSIONS}\n'
        f'  - SSH key source:         ~/.ssh + ssh-agent (current user: '
        f'{os.environ.get("USER", "?")})\n',
        file=sys.stderr,
    )

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print('\nShutting down...', file=sys.stderr)
        for s in all_sessions():
            s.close()
        server.shutdown()


if __name__ == '__main__':
    main()
