# LAN TLS for WireScope

Conservative default: bind the unprivileged API to `127.0.0.1:8000` and
terminate TLS on Caddy or nginx. Direct TLS on uvicorn is optional when you
cannot run a proxy. The backend and dumpcap stay unprivileged either way.

## Reverse proxy (preferred)

1. Keep `--bind-host 127.0.0.1`.
2. Install with `--trust-proxy` so session cookies are `Secure` and uvicorn
   accepts `X-Forwarded-*` only from loopback.
3. Copy `Caddyfile` or `nginx.conf`, replace `wirescope.example` and cert paths.
4. Open TCP 443 from the management network only. Do not expose TCP 8000.

```bash
sudo /opt/wirescope/packaging/install.sh \
  --project-root /opt/wirescope \
  --trust-proxy \
  --bind-host 127.0.0.1
```

Place operator-supplied certificates at `/etc/wirescope/tls/cert.pem` and
`key.pem` (key mode `0600`, not in the Git checkout). A lab self-signed pair:

```bash
sudo python3 -m appliance tls-selfsigned \
  --output-dir /etc/wirescope/tls \
  --common-name wirescope.example
```

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

Open 8443 from the management network. The Python process still must not run
as root and still must not receive `CAP_NET_RAW`.

## Firewall

- nftables: `nftables.nft` (loopback + SSH + 443 from a prefix; drop 8000)
- ufw: `ufw.example`
- firewalld:

```bash
firewall-cmd --permanent --add-service=ssh
firewall-cmd --permanent --add-rich-rule='rule family=ipv4 source address="192.0.2.0/24" port port="443" protocol="tcp" accept'
firewall-cmd --reload
```

The installer never rewrites the host firewall.
