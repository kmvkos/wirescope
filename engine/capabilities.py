"""Detect raw-socket capabilities without elevating the backend."""

import os
from pathlib import Path


CAP_NET_RAW = 13


def process_has_net_raw() -> bool:
    if os.geteuid() == 0:
        return True
    try:
        status = Path("/proc/self/status").read_text(encoding="utf-8")
    except OSError:
        return False
    for line in status.splitlines():
        if line.startswith("CapEff:"):
            value = int(line.split(":", 1)[1].strip(), 16)
            return bool(value & (1 << CAP_NET_RAW))
    return False
