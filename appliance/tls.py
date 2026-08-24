"""LAN TLS helpers: reverse-proxy samples and optional direct TLS paths.

Certificates and keys stay on disk. They are never copied into systemd units.
"""

from __future__ import annotations

from pathlib import Path


PROXY_SAMPLE_NAMES = (
    "README.md",
    "Caddyfile",
    "nginx.conf",
    "nftables.nft",
    "ufw.example",
    "firewalld.example",
)

LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
PUBLIC_BIND_HOSTS = frozenset({"0.0.0.0", "::"})


def proxy_sample_dir(project_root: Path) -> Path:
    candidate = project_root / "packaging" / "proxy"
    if candidate.is_dir():
        return candidate
    # Tests and embedded tooling may use a synthetic install root. The proxy
    # examples are package resources, so fall back to the checkout containing
    # this module instead of coupling them to /opt/wirescope.
    return Path(__file__).resolve().parents[1] / "packaging" / "proxy"


def tls_pair_complete(certfile: str, keyfile: str) -> bool:
    return bool(certfile.strip()) and bool(keyfile.strip())


def validate_tls_settings(certfile: str, keyfile: str) -> None:
    cert = certfile.strip()
    key = keyfile.strip()
    if bool(cert) != bool(key):
        raise ValueError(
            "WIRESCOPE_TLS_CERTFILE and WIRESCOPE_TLS_KEYFILE must be set together"
        )


def validate_tls_paths(certfile: str, keyfile: str) -> None:
    validate_tls_settings(certfile, keyfile)
    if not tls_pair_complete(certfile, keyfile):
        return
    cert_path = Path(certfile.strip())
    key_path = Path(keyfile.strip())
    if not cert_path.is_file():
        raise ValueError(f"TLS certificate is missing: {cert_path}")
    if not key_path.is_file():
        raise ValueError(f"TLS private key is missing: {key_path}")


def cookie_secure_default(*, trust_proxy: bool, tls_enabled: bool) -> bool:
    return trust_proxy or tls_enabled


def lan_warnings(
    *,
    bind_host: str,
    trust_proxy: bool,
    tls_enabled: bool,
) -> tuple[str, ...]:
    warnings: list[str] = []
    public = bind_host in PUBLIC_BIND_HOSTS
    if trust_proxy and public:
        warnings.append(
            "trust_proxy with a public bind_host; keep the API on 127.0.0.1 when only the proxy should be exposed"
        )
    if public and not tls_enabled and not trust_proxy:
        warnings.append(
            "API bind is public HTTP on all interfaces; apply firewall or TLS controls when required by the deployment"
        )
    if tls_enabled and not public and not trust_proxy:
        warnings.append(
            "direct TLS is listening on loopback; open the GUI via that host or put a proxy in front"
        )
    if public:
        warnings.append(
            "review host firewall exposure for the WireScope API; examples are available in packaging/proxy/"
        )
    return tuple(warnings)


def self_signed_argv(
    *,
    certfile: Path,
    keyfile: Path,
    common_name: str,
    days: int = 825,
) -> list[str]:
    if days < 1:
        raise ValueError("certificate lifetime must be positive")
    if not common_name.strip():
        raise ValueError("common_name must not be empty")
    return [
        "openssl",
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-sha256",
        "-nodes",
        "-keyout",
        str(keyfile),
        "-out",
        str(certfile),
        "-days",
        str(days),
        "-subj",
        f"/CN={common_name.strip()}",
    ]
