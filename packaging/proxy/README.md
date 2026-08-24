# LAN TLS for WireScope

Conservative default: bind the unprivileged API to `127.0.0.1:8000` and
terminate TLS on Caddy or nginx. Direct TLS on uvicorn is optional when you
cannot run a proxy. The backend and dumpcap stay unprivileged either way.

## From another PC

1. Keep `--bind-host 127.0.0.1` (do not publish TCP 8000).
2. Install with `--trust-proxy` so session cookies are `Secure` and uvicorn
   accepts `X-Forwarded-*` only from loopback.
3. Copy `Caddyfile` or `nginx.conf` from `/etc/wirescope/proxy/` (installer
   copies these examples) or from this directory. Replace `wirescope.example`.
4. Open **`https://<hostname>/`** on the other machine. Local-only remains
   `http://127.0.0.1:8000/`.
5. Allow TCP 443 from the management network only (and TCP 80 if you use
   Let's Encrypt HTTP-01).

```bash
sudo /opt/wirescope/packaging/install.sh \
  --project-root /opt/wirescope \
  --trust-proxy \
  --bind-host 127.0.0.1
```

| Host | Proxy package | Firewall snippet | GUI URL |
| --- | --- | --- | --- |
| This Debian VM (`/opt/wirescope`) | `apt install caddy` or `nginx` | `nftables.nft` or `ufw.example` | `https://<debian-host>/` |
| Ubuntu | `apt install caddy` or `nginx` | `ufw.example` | `https://<ubuntu-host>/` |
| Fedora / RHEL / Rocky | `dnf install caddy` or `nginx` | `firewalld.example` | `https://<fedora-host>/` |

The installer never starts Caddy/nginx and never rewrites the host firewall.

## Certificates

Lab self-signed (browser warning expected; not for an untrusted network):

```bash
sudo python3 -m appliance tls-selfsigned \
  --output-dir /etc/wirescope/tls \
  --common-name wirescope.example
```

Place operator-supplied certificates at `/etc/wirescope/tls/cert.pem` and
`key.pem` (key mode `0600`, not in the Git checkout, not in unit files).

**Let's Encrypt (real hostname):**

- **Caddy:** delete the `tls` line in `Caddyfile`. Caddy obtains and renews
  certificates when the name resolves to this host and TCP 80 + 443 are
  reachable. Package: `caddy` (`apt` or `dnf`).
- **nginx:** `certbot certonly --webroot -w /var/www/html -d wirescope.example`
  then point `ssl_certificate` / `ssl_certificate_key` at
  `/etc/letsencrypt/live/<name>/fullchain.pem` and `privkey.pem`.
  Debian/Ubuntu: `apt install certbot`. Fedora: `dnf install certbot`.

HTTP-01 needs TCP 80 from the internet (or from the ACME path you use).
The GUI itself stays on 443.

## Direct TLS (optional)

When no proxy is available, pass cert and key into the API process via env.
Do not put PEM material in systemd units.

```bash
sudo /opt/wirescope/packaging/install.sh \
  --project-root /opt/wirescope \
  --bind-host 0.0.0.0 \
  --bind-port 8443 \
  --tls-cert /etc/wirescope/tls/cert.pem \
  --tls-key /etc/wirescope/tls/key.pem
```

Open `https://<host>:8443/` from the management network. The Python process
still must not run as root and still must not receive `CAP_NET_RAW`.

Bare HTTP `http://<host>:8000/` is an explicit, discouraged choice.

## Firewall

- nftables (Debian default): `nftables.nft` (loopback + SSH + 443 from a prefix)
- ufw (typical Ubuntu): `ufw.example`
- firewalld (Fedora / RHEL / openSUSE): `firewalld.example`

Allow 443. Allow 80 only for Let's Encrypt. Allow 8443 for direct TLS, or
8000 only if operators insist on a direct HTTP bind. Do not apply examples
blindly on a remote SSH host.
