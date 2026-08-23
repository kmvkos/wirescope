"""Local IEEE OUI vendor lookup. Never performs HTTP requests."""

from functools import lru_cache
from pathlib import Path
import re

from config.settings import Settings, get_settings


BUNDLED_OUI = Path(__file__).resolve().parent / "data" / "oui.txt"
OUI_LINE = re.compile(
    r"^([0-9A-F]{2}[-:][0-9A-F]{2}[-:][0-9A-F]{2})\s+\(hex\)\s+(.+)$",
    re.IGNORECASE,
)


class VendorResolution:
    def __init__(
        self,
        vendor: str | None,
        source: str | None,
        database_version: str | None,
    ) -> None:
        self.vendor = vendor
        self.source = source
        self.database_version = database_version


class OuiResolver:
    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self._table, self.source, self.database_version = _load_oui_table(
            self.settings.oui_database_path
        )

    def lookup(self, mac: str | None) -> VendorResolution:
        prefix = _oui_prefix(mac)
        if prefix is None:
            return VendorResolution(None, None, None)
        vendor = self._table.get(prefix)
        if vendor is None:
            return VendorResolution(None, self.source, self.database_version)
        return VendorResolution(vendor, self.source, self.database_version)


@lru_cache(maxsize=4)
def _load_oui_table(preferred: Path) -> tuple[dict[str, str], str, str]:
    for path in (preferred, BUNDLED_OUI):
        if not path.is_file():
            continue
        table: dict[str, str] = {}
        generated = None
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line in text.splitlines():
            lowered = line.lower()
            if "generated:" in lowered or "last updated" in lowered:
                generated = line.strip()
            match = OUI_LINE.match(line.strip())
            if match:
                table[match.group(1).upper().replace("-", ":")] = (
                    match.group(2).strip()
                )
        if table:
            version = generated or f"file:{path.name}"
            source = (
                "ieee-data"
                if path == preferred
                else "bundled-oui"
            )
            return table, source, version
    return {}, "unavailable", None


def _oui_prefix(mac: str | None) -> str | None:
    if not mac:
        return None
    hex_chars = re.sub(r"[^0-9A-Fa-f]", "", mac)
    if len(hex_chars) < 6:
        return None
    return ":".join(
        hex_chars[index:index + 2].upper()
        for index in range(0, 6, 2)
    )
