"""Known-weak algorithms and insecure-management catalogs.

These lists interpret normalized observation fields. They never parse raw
tool stdout.
"""

WEAK_SSH_KEX = frozenset(
    {
        "diffie-hellman-group1-sha1",
        "diffie-hellman-group14-sha1",
        "diffie-hellman-group-exchange-sha1",
        "ecdsa-sha2-nistp256-sha1",
    }
)

WEAK_SSH_HOST_KEY = frozenset(
    {
        "ssh-dss",
        "ssh-dsa",
        "ssh-rsa",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521",
    }
)

WEAK_SSH_ENCRYPTION = frozenset(
    {
        "3des-cbc",
        "aes128-cbc",
        "aes192-cbc",
        "aes256-cbc",
        "arcfour",
        "arcfour128",
        "arcfour256",
        "blowfish-cbc",
        "cast128-cbc",
        "des-cbc",
        "rijndael-cbc@lysator.liu.se",
    }
)

WEAK_SSH_MAC = frozenset(
    {
        "hmac-md5",
        "hmac-md5-96",
        "hmac-sha1",
        "hmac-sha1-96",
        "hmac-sha1-etm@openssh.com",
        "hmac-md5-etm@openssh.com",
        "umac-64@openssh.com",
        "umac-64-etm@openssh.com",
    }
)

WEAK_SSH_BY_FAMILY = {
    "kex": WEAK_SSH_KEX,
    "host_key": WEAK_SSH_HOST_KEY,
    "encryption": WEAK_SSH_ENCRYPTION,
    "mac": WEAK_SSH_MAC,
}

LEGACY_TLS_PROTOCOLS = frozenset(
    {
        "ssl",
        "sslv2",
        "sslv3",
        "ssl2",
        "ssl3",
        "tlsv1",
        "tlsv1.0",
        "tls1",
        "tls1.0",
        "tlsv1.1",
        "tls1.1",
    }
)

TLS1_0_TOKENS = frozenset({"tlsv1", "tlsv1.0", "tls1", "tls1.0"})
SSL_TOKENS = frozenset({"ssl", "sslv2", "sslv3", "ssl2", "ssl3"})

WEAK_TLS_CIPHER_TOKENS = (
    "RC4",
    "DES",
    "3DES",
    "NULL",
    "EXPORT",
    "EXP",
    "MD5",
    "ADH",
    "AECDH",
    "PSK-NULL",
    "IDEA",
)

LEGACY_SMB_DIALECTS = frozenset(
    {
        "smb1",
        "smb 1",
        "smb1.0",
        "nt lm 0.12",
        "ntlm 0.12",
        "lanman",
        "lanman1.0",
        "lanman2.1",
    }
)

INSECURE_MANAGEMENT_NAMES = frozenset(
    {
        "telnet",
        "ftp",
        "tftp",
        "rsh",
        "rlogin",
        "rexec",
        "finger",
        "exec",
        "login",
        "shell",
        "chargen",
        "discard",
        "echo",
    }
)

INSECURE_MANAGEMENT_PORTS = {
    (21, "tcp"): ("ftp", "high"),
    (23, "tcp"): ("telnet", "high"),
    (69, "udp"): ("tftp", "medium"),
    (69, "tcp"): ("tftp", "medium"),
    (512, "tcp"): ("rexec", "high"),
    (513, "tcp"): ("rlogin", "high"),
    (514, "tcp"): ("rsh", "high"),
    (79, "tcp"): ("finger", "low"),
}

NAME_SEVERITY = {
    "telnet": "high",
    "ftp": "high",
    "tftp": "medium",
    "rsh": "high",
    "rlogin": "high",
    "rexec": "high",
    "finger": "low",
    "exec": "high",
    "login": "high",
    "shell": "high",
    "chargen": "medium",
    "discard": "low",
    "echo": "low",
}

HTTPS_PORTS = frozenset({443, 8443, 9443})
HTTPS_NAMES = frozenset({"https", "https-alt", "ssl/http", "http-alt"})

SMB_SIGNING_DISABLED = frozenset(
    {
        "disabled",
        "not required",
        "not-required",
        "false",
        "off",
        "no",
        "unsigned",
    }
)
