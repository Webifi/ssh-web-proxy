# ssh-web-proxy

Single-file Python proxy. Open a browser, fill a form (SSH user, local
mapped SSH port, target IP/port, http/https), and you get dropped into
that target's web UI with all URL/cookie/redirect rewriting handled.
Useful when the target sits on a remote LAN reachable only through a
reverse-tunneled SSH connection.

## Install or update

The same one-liner installs fresh OR pulls the latest version and
restarts the service:

```bash
curl -fsSL -H 'Accept: application/vnd.github.raw' https://api.github.com/repos/Webifi/ssh-web-proxy/contents/install.sh | sudo bash
```

(Uses the GitHub API raw endpoint rather than `raw.githubusercontent.com`
because the latter has a 5-minute CDN cache, which makes re-running
right after a push feel like nothing changed.)

Auto-binds to the host's RFC 1918 private IPv4 address. If the host
has no private address, the installer refuses and prints what it
scanned, so the listener never lands on a public interface.

The install prints the final URL when it finishes (e.g.
`http://192.168.0.104:9999/`). Open it in a browser.

**The service re-detects its private IP on every startup.** If the
host's IP changes later (DHCP lease, NIC swap, subnet renumbering),
just `sudo systemctl restart ssh-web-proxy` and it picks up the new
address — no re-install needed.

To pin a specific bind address (skips auto-detect on restart):

```bash
curl -fsSL -H 'Accept: application/vnd.github.raw' https://api.github.com/repos/Webifi/ssh-web-proxy/contents/install.sh | sudo SERVICE_USER=admin BIND=10.0.0.5 PORT=8888 bash
```

Installs `python3-paramiko` (only on first run), drops both scripts
into `/opt/ssh-web-proxy/`, creates a `/usr/local/bin/ssh-web-proxy`
symlink so the command is in PATH, writes a systemd unit, enables +
starts the service. Runs as the user who invoked sudo so it can read
that user's SSH keys.

If you previously installed an older version that put files in
`/usr/local/bin/ssh-web-proxy` + `/usr/local/lib/ssh-web-proxy/`,
re-running the one-liner cleans those up automatically.

## Manage

```bash
systemctl status ssh-web-proxy
journalctl -u ssh-web-proxy -f
sudo systemctl restart ssh-web-proxy
```

Uninstall:

```bash
sudo systemctl disable --now ssh-web-proxy
sudo rm -rf /opt/ssh-web-proxy
sudo rm -f /usr/local/bin/ssh-web-proxy /etc/systemd/system/ssh-web-proxy.service
sudo systemctl daemon-reload
```

## Security

The proxy has no auth of its own. Anyone who can reach the LAN-bound
port can open SSH sessions to whatever remotes the host's keys are
authorized for. Firewall the port to admin IPs.

## Manual run (no service)

```bash
python3 ssh_web_proxy.py [-p PORT] [-b ADDR]
```

## How it stays out of the way

No local TCP port is bound for the SSH tunnels — each HTTP request opens
a fresh paramiko `direct-tcpip` channel through the SSH session. Only
port consumed is the proxy's listener.
