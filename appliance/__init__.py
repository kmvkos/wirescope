"""Debian-family appliance installer, systemd units, and operational helpers."""

from appliance.detect import Platform, detect_platform
from appliance.packages import OPTIONAL_PROVIDERS, REQUIRED_PACKAGES

__all__ = [
    "OPTIONAL_PROVIDERS",
    "REQUIRED_PACKAGES",
    "Platform",
    "detect_platform",
]
