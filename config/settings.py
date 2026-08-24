"""Centralized, environment-aware application settings."""

from dataclasses import dataclass
from functools import lru_cache
import os
from pathlib import Path


def _env_path(name: str, default: Path) -> Path:
    return Path(os.getenv(name, str(default))).expanduser().resolve()


def _env_bool(name: str, default: bool) -> bool:
    raw_value = os.getenv(name)
    if raw_value is None:
        return default
    return raw_value.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    raw_value = os.getenv(name)
    return int(raw_value) if raw_value is not None else default


def _env_float(name: str, default: float) -> float:
    raw_value = os.getenv(name)
    return float(raw_value) if raw_value is not None else default


def _env_list(name: str) -> tuple[str, ...]:
    raw_value = os.getenv(name, "")
    return tuple(
        item.strip()
        for item in raw_value.split(",")
        if item.strip()
    )


@dataclass(frozen=True)
class Settings:
    app_name: str
    app_version: str
    project_root: Path
    frontend_dir: Path
    data_dir: Path
    capture_dir: Path
    database_path: Path
    evidence_dir: Path
    runtime_dir: Path
    nmap_runtime_dir: Path
    protocol_runtime_dir: Path
    oui_database_path: Path
    docs_enabled: bool
    allowed_interfaces: tuple[str, ...]
    allow_loopback: bool
    require_interface_up: bool
    passive_duration_min: int
    passive_duration_max: int
    passive_duration_default: int
    capture_max_packets: int
    capture_max_filesize_kb: int
    capture_snaplen: int
    capture_promiscuous: bool
    passive_retain_capture: bool
    worker_concurrency: int
    max_packet_captures: int
    max_active_discovery_jobs: int
    max_protocol_audit_jobs: int
    protocol_audit_concurrency: int
    protocol_audit_timeout_seconds: int
    max_findings_jobs: int
    max_report_jobs: int
    active_discovery_max_targets: int
    active_standard_max_targets: int
    active_deep_max_targets: int
    active_ipv6_max_targets: int
    active_allow_large_scopes: bool
    nmap_discovery_timeout_seconds: int
    nmap_standard_timeout_seconds: int
    nmap_deep_timeout_seconds: int
    worker_poll_interval_seconds: float
    worker_heartbeat_interval_seconds: float
    worker_stale_after_seconds: int
    sqlite_busy_timeout_ms: int
    sqlite_synchronous: str
    job_event_retention_days: int
    temp_file_max_age_seconds: int
    dumpcap_binary: str
    tshark_binary: str
    nmap_binary: str
    ssh_audit_binary: str
    openssl_binary: str
    curl_binary: str
    dig_binary: str
    smbclient_binary: str
    snmpget_binary: str
    ldapsearch_binary: str

    def __post_init__(self) -> None:
        if self.passive_duration_min < 1:
            raise ValueError("passive_duration_min must be positive")
        if self.passive_duration_max < self.passive_duration_min:
            raise ValueError("passive_duration_max must not be below minimum")
        if not (
            self.passive_duration_min
            <= self.passive_duration_default
            <= self.passive_duration_max
        ):
            raise ValueError("passive_duration_default is outside policy")
        if self.worker_concurrency < 1:
            raise ValueError("worker_concurrency must be at least one")
        if self.max_packet_captures < 1:
            raise ValueError("max_packet_captures must be at least one")
        if self.max_active_discovery_jobs < 1:
            raise ValueError("max_active_discovery_jobs must be at least one")
        if self.max_protocol_audit_jobs < 1:
            raise ValueError("max_protocol_audit_jobs must be at least one")
        if self.protocol_audit_concurrency < 1:
            raise ValueError("protocol_audit_concurrency must be at least one")
        if self.protocol_audit_concurrency > 4:
            raise ValueError("protocol_audit_concurrency must not exceed 4")
        if self.protocol_audit_timeout_seconds < 1:
            raise ValueError("protocol_audit_timeout_seconds must be positive")
        if self.max_findings_jobs < 1:
            raise ValueError("max_findings_jobs must be at least one")
        if self.max_report_jobs < 1:
            raise ValueError("max_report_jobs must be at least one")
        if min(
            self.active_discovery_max_targets,
            self.active_standard_max_targets,
            self.active_deep_max_targets,
            self.active_ipv6_max_targets,
        ) < 1:
            raise ValueError("active scope limits must be positive")
        if self.sqlite_busy_timeout_ms < 1:
            raise ValueError("sqlite_busy_timeout_ms must be positive")
        if self.sqlite_synchronous not in {"FULL", "NORMAL"}:
            raise ValueError("sqlite_synchronous must be FULL or NORMAL")

    @property
    def database_url(self) -> str:
        return f"sqlite+pysqlite:///{self.database_path}"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    default_root = Path(__file__).resolve().parents[1]
    project_root = _env_path("WIRESCOPE_ROOT", default_root)
    data_dir = _env_path(
        "WIRESCOPE_DATA_DIR",
        project_root / "data",
    )
    runtime_dir = _env_path(
        "WIRESCOPE_RUNTIME_DIR",
        data_dir / "runtime",
    )

    return Settings(
        app_name="WireScope",
        app_version="0.1.0",
        project_root=project_root,
        frontend_dir=_env_path(
            "WIRESCOPE_FRONTEND_DIR",
            project_root / "frontend",
        ),
        data_dir=data_dir,
        capture_dir=_env_path(
            "WIRESCOPE_CAPTURE_DIR",
            runtime_dir / "captures",
        ),
        database_path=_env_path(
            "WIRESCOPE_DATABASE_PATH",
            data_dir / "wirescope.db",
        ),
        evidence_dir=_env_path(
            "WIRESCOPE_EVIDENCE_DIR",
            data_dir / "evidence",
        ),
        runtime_dir=runtime_dir,
        nmap_runtime_dir=_env_path(
            "WIRESCOPE_NMAP_RUNTIME_DIR",
            runtime_dir / "nmap",
        ),
        protocol_runtime_dir=_env_path(
            "WIRESCOPE_PROTOCOL_RUNTIME_DIR",
            runtime_dir / "protocol",
        ),
        oui_database_path=_env_path(
            "WIRESCOPE_OUI_DATABASE_PATH",
            Path("/usr/share/ieee-data/oui.txt"),
        ),
        docs_enabled=_env_bool("WIRESCOPE_DOCS_ENABLED", True),
        allowed_interfaces=_env_list("WIRESCOPE_ALLOWED_INTERFACES"),
        allow_loopback=_env_bool("WIRESCOPE_ALLOW_LOOPBACK", False),
        require_interface_up=_env_bool(
            "WIRESCOPE_REQUIRE_INTERFACE_UP",
            True,
        ),
        passive_duration_min=_env_int("WIRESCOPE_PASSIVE_DURATION_MIN", 5),
        passive_duration_max=_env_int("WIRESCOPE_PASSIVE_DURATION_MAX", 300),
        passive_duration_default=_env_int(
            "WIRESCOPE_PASSIVE_DURATION_DEFAULT",
            30,
        ),
        capture_max_packets=_env_int(
            "WIRESCOPE_CAPTURE_MAX_PACKETS",
            50_000,
        ),
        capture_max_filesize_kb=_env_int(
            "WIRESCOPE_CAPTURE_MAX_FILESIZE_KB",
            16_384,
        ),
        capture_snaplen=_env_int("WIRESCOPE_CAPTURE_SNAPLEN", 65_535),
        capture_promiscuous=_env_bool(
            "WIRESCOPE_CAPTURE_PROMISCUOUS",
            False,
        ),
        passive_retain_capture=_env_bool(
            "WIRESCOPE_PASSIVE_RETAIN_CAPTURE",
            False,
        ),
        worker_concurrency=_env_int("WIRESCOPE_WORKER_CONCURRENCY", 1),
        max_packet_captures=_env_int("WIRESCOPE_MAX_PACKET_CAPTURES", 1),
        max_active_discovery_jobs=_env_int(
            "WIRESCOPE_MAX_ACTIVE_DISCOVERY_JOBS",
            1,
        ),
        max_protocol_audit_jobs=_env_int(
            "WIRESCOPE_MAX_PROTOCOL_AUDIT_JOBS",
            1,
        ),
        protocol_audit_concurrency=_env_int(
            "WIRESCOPE_PROTOCOL_AUDIT_CONCURRENCY",
            1,
        ),
        protocol_audit_timeout_seconds=_env_int(
            "WIRESCOPE_PROTOCOL_AUDIT_TIMEOUT_SECONDS",
            20,
        ),
        max_findings_jobs=_env_int(
            "WIRESCOPE_MAX_FINDINGS_JOBS",
            1,
        ),
        max_report_jobs=_env_int(
            "WIRESCOPE_MAX_REPORT_JOBS",
            1,
        ),
        active_discovery_max_targets=_env_int(
            "WIRESCOPE_DISCOVERY_MAX_TARGETS",
            4_096,
        ),
        active_standard_max_targets=_env_int(
            "WIRESCOPE_STANDARD_MAX_TARGETS",
            1_024,
        ),
        active_deep_max_targets=_env_int(
            "WIRESCOPE_DEEP_MAX_TARGETS",
            256,
        ),
        active_ipv6_max_targets=_env_int(
            "WIRESCOPE_IPV6_MAX_TARGETS",
            256,
        ),
        active_allow_large_scopes=_env_bool(
            "WIRESCOPE_ALLOW_LARGE_SCOPES",
            False,
        ),
        nmap_discovery_timeout_seconds=_env_int(
            "WIRESCOPE_NMAP_DISCOVERY_TIMEOUT_SECONDS",
            900,
        ),
        nmap_standard_timeout_seconds=_env_int(
            "WIRESCOPE_NMAP_STANDARD_TIMEOUT_SECONDS",
            3_600,
        ),
        nmap_deep_timeout_seconds=_env_int(
            "WIRESCOPE_NMAP_DEEP_TIMEOUT_SECONDS",
            14_400,
        ),
        worker_poll_interval_seconds=_env_float(
            "WIRESCOPE_WORKER_POLL_INTERVAL_SECONDS",
            0.5,
        ),
        worker_heartbeat_interval_seconds=_env_float(
            "WIRESCOPE_WORKER_HEARTBEAT_INTERVAL_SECONDS",
            5.0,
        ),
        worker_stale_after_seconds=_env_int(
            "WIRESCOPE_WORKER_STALE_AFTER_SECONDS",
            20,
        ),
        sqlite_busy_timeout_ms=_env_int(
            "WIRESCOPE_SQLITE_BUSY_TIMEOUT_MS",
            5_000,
        ),
        sqlite_synchronous=os.getenv(
            "WIRESCOPE_SQLITE_SYNCHRONOUS",
            "FULL",
        ).strip().upper(),
        job_event_retention_days=_env_int(
            "WIRESCOPE_JOB_EVENT_RETENTION_DAYS",
            30,
        ),
        temp_file_max_age_seconds=_env_int(
            "WIRESCOPE_TEMP_FILE_MAX_AGE_SECONDS",
            86_400,
        ),
        dumpcap_binary=os.getenv("WIRESCOPE_DUMPCAP_BINARY", "dumpcap"),
        tshark_binary=os.getenv("WIRESCOPE_TSHARK_BINARY", "tshark"),
        nmap_binary=os.getenv("WIRESCOPE_NMAP_BINARY", "nmap"),
        ssh_audit_binary=os.getenv("WIRESCOPE_SSH_AUDIT_BINARY", "ssh-audit"),
        openssl_binary=os.getenv("WIRESCOPE_OPENSSL_BINARY", "openssl"),
        curl_binary=os.getenv("WIRESCOPE_CURL_BINARY", "curl"),
        dig_binary=os.getenv("WIRESCOPE_DIG_BINARY", "dig"),
        smbclient_binary=os.getenv("WIRESCOPE_SMBCLIENT_BINARY", "smbclient"),
        snmpget_binary=os.getenv("WIRESCOPE_SNMPGET_BINARY", "snmpget"),
        ldapsearch_binary=os.getenv(
            "WIRESCOPE_LDAPSEARCH_BINARY",
            "ldapsearch",
        ),
    )
