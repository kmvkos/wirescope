"""Controlled Nmap execution through ToolRunner. No shell strings."""

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import shutil
import uuid

from pydantic import BaseModel, Field

from config.settings import Settings, get_settings
from engine.active_profiles import ActiveScanProfile
from engine.capabilities import process_has_net_raw
from engine.routes import ResolvedScope
from engine.scope import ValidatedScope
from jobs.errors import JobCancelled, JobExecutionError
from jobs.models import ErrorCategory, JobError, RetentionClass
from parsers.nmap import NmapParseError, NmapScanDocument, parse_nmap_xml
from providers.tools import (
    CancellationToken,
    ToolCommand,
    ToolErrorCode,
    ToolResult,
    ToolRunner,
)
from storage.evidence import EvidenceStore


class NmapCapabilities(BaseModel):
    binary: str
    version: str | None = None
    privileged: bool
    syn_scan: bool
    arp_discovery: bool
    os_detection: bool
    udp_scan: bool


class NmapCommandPlan(BaseModel):
    args: list[str]
    xml_path: str
    target_file: str
    scan_kind: str
    tcp_method: str
    host_discovery_method: str
    tcp_ports: str | None = None
    udp_ports: str | None = None
    service_detection: bool = False
    version_intensity: int | None = None
    os_detection: bool = False
    timing: str
    privileged: bool
    skip_host_discovery: bool = False
    fallbacks: list[str] = Field(default_factory=list)


@dataclass
class NmapRun:
    plan: NmapCommandPlan
    tool_result: ToolResult
    document: NmapScanDocument | None
    xml_artifact_id: str | None
    xml_sha256: str | None


class NmapProvider:
    def __init__(
        self,
        *,
        runner: ToolRunner | None = None,
        settings: Settings | None = None,
        privileged: bool | None = None,
    ) -> None:
        self.runner = runner or ToolRunner()
        self.settings = settings or get_settings()
        self._forced_privileged = privileged
        self._version_cache: str | None | bool = False

    def capabilities(self) -> NmapCapabilities:
        privileged = (
            process_has_net_raw()
            if self._forced_privileged is None
            else self._forced_privileged
        )
        version = self._version()
        return NmapCapabilities(
            binary=self.settings.nmap_binary,
            version=version,
            privileged=privileged,
            syn_scan=privileged,
            arp_discovery=privileged,
            os_detection=privileged,
            udp_scan=privileged,
        )

    def build_host_discovery(
        self,
        *,
        scope: ValidatedScope,
        resolved: ResolvedScope,
        profile: ActiveScanProfile,
        xml_path: Path,
        target_file: Path,
    ) -> NmapCommandPlan:
        capabilities = self.capabilities()
        fallbacks: list[str] = []
        args = ["-n", "-T" + profile.timing.removeprefix("T"), "-sn"]
        ipv6_only = (
            6 in scope.address_families and 4 not in scope.address_families
        )
        if ipv6_only:
            args.append("-6")
        if capabilities.privileged:
            if ipv6_only:
                args.append("-PR")
                host_method = "ipv6-neighbor-discovery"
            elif self._all_directly_connected_ipv4(resolved, scope):
                args.append("-PR")
                host_method = "arp"
            else:
                args.extend(["-PE", "-PP", "-PS22,80,443"])
                host_method = "icmp-and-tcp-probes"
                if any(route.directly_connected for route in resolved.routes):
                    args.append("-PR")
                    host_method = "arp-icmp-tcp"
            if 6 in scope.address_families and not ipv6_only:
                host_method = f"{host_method}+ipv6-nd"
        else:
            args.extend(["--unprivileged", "-PS22,80,443"])
            host_method = (
                "ipv6-tcp-probes" if ipv6_only else "tcp-connect-probes"
            )
            fallbacks.append("unprivileged-host-discovery")
        args.extend(
            [
                "-e",
                resolved.interface,
                "-oX",
                str(xml_path),
                "-iL",
                str(target_file),
            ]
        )
        return NmapCommandPlan(
            args=args,
            xml_path=str(xml_path),
            target_file=str(target_file),
            scan_kind="host_discovery",
            tcp_method="none",
            host_discovery_method=host_method,
            timing=profile.timing,
            privileged=capabilities.privileged,
            fallbacks=fallbacks,
        )

    def build_tcp_scan(
        self,
        *,
        scope: ValidatedScope,
        resolved: ResolvedScope,
        profile: ActiveScanProfile,
        xml_path: Path,
        target_file: Path,
    ) -> NmapCommandPlan:
        capabilities = self.capabilities()
        fallbacks: list[str] = []
        args = ["-n", "-T" + profile.timing.removeprefix("T"), "-Pn"]
        if 6 in scope.address_families and 4 not in scope.address_families:
            args.append("-6")
        if capabilities.privileged:
            args.append("-sS")
            tcp_method = "syn"
        else:
            args.extend(["--unprivileged", "-sT"])
            tcp_method = "connect"
            fallbacks.append("syn-to-connect")
        if profile.tcp_ports:
            args.extend(["-p", profile.tcp_ports])
            tcp_ports = profile.tcp_ports
        elif profile.tcp_top_ports:
            args.extend(["--top-ports", str(profile.tcp_top_ports)])
            tcp_ports = f"top-{profile.tcp_top_ports}"
        else:
            tcp_ports = None
        os_detection = bool(profile.os_detection and capabilities.privileged)
        if profile.os_detection and not capabilities.privileged:
            fallbacks.append("os-detection-skipped-unprivileged")
        if profile.service_detection:
            args.append("-sV")
            if profile.version_intensity is not None:
                args.extend(
                    ["--version-intensity", str(profile.version_intensity)]
                )
        if os_detection:
            args.extend(["-O", "--osscan-limit"])
        args.extend(
            [
                "--max-retries",
                "2",
                "-e",
                resolved.interface,
                "-oX",
                str(xml_path),
                "-iL",
                str(target_file),
            ]
        )
        return NmapCommandPlan(
            args=args,
            xml_path=str(xml_path),
            target_file=str(target_file),
            scan_kind="tcp_scan",
            tcp_method=tcp_method,
            host_discovery_method="none",
            tcp_ports=tcp_ports,
            service_detection=profile.service_detection,
            version_intensity=profile.version_intensity,
            os_detection=os_detection,
            timing=profile.timing,
            privileged=capabilities.privileged,
            skip_host_discovery=True,
            fallbacks=fallbacks,
        )

    def build_udp_scan(
        self,
        *,
        scope: ValidatedScope,
        resolved: ResolvedScope,
        profile: ActiveScanProfile,
        xml_path: Path,
        target_file: Path,
    ) -> NmapCommandPlan | None:
        capabilities = self.capabilities()
        if not profile.run_udp_scan or not profile.udp_ports:
            return None
        if not capabilities.privileged:
            return NmapCommandPlan(
                args=[],
                xml_path=str(xml_path),
                target_file=str(target_file),
                scan_kind="udp_scan_skipped",
                tcp_method="none",
                host_discovery_method="none",
                udp_ports=_ports(profile.udp_ports),
                timing=profile.timing,
                privileged=False,
                skip_host_discovery=True,
                fallbacks=["udp-skipped-unprivileged"],
            )
        args = [
            "-n",
            "-T" + profile.timing.removeprefix("T"),
            "-Pn",
            "-sU",
        ]
        if 6 in scope.address_families and 4 not in scope.address_families:
            args.append("-6")
        if profile.service_detection and profile.name.value == "deep":
            args.append("-sV")
            if profile.version_intensity is not None:
                args.extend(
                    ["--version-intensity", str(profile.version_intensity)]
                )
        args.extend(
            [
                "-p",
                _ports(profile.udp_ports),
                "--max-retries",
                "1",
                "-e",
                resolved.interface,
                "-oX",
                str(xml_path),
                "-iL",
                str(target_file),
            ]
        )
        return NmapCommandPlan(
            args=args,
            xml_path=str(xml_path),
            target_file=str(target_file),
            scan_kind="udp_scan",
            tcp_method="none",
            host_discovery_method="none",
            udp_ports=_ports(profile.udp_ports),
            service_detection=(
                profile.service_detection and profile.name.value == "deep"
            ),
            version_intensity=(
                profile.version_intensity
                if profile.name.value == "deep"
                else None
            ),
            timing=profile.timing,
            privileged=True,
            skip_host_discovery=True,
        )

    def run_plan(
        self,
        plan: NmapCommandPlan,
        *,
        timeout_seconds: int,
        cancellation_token: CancellationToken | None = None,
        evidence_store: EvidenceStore | None = None,
        audit_id: str | None = None,
        job_id: str | None = None,
    ) -> NmapRun:
        if not plan.args:
            now = datetime.now(timezone.utc)
            return NmapRun(
                plan=plan,
                tool_result=ToolResult(
                    command=[self.settings.nmap_binary],
                    tool=self.settings.nmap_binary,
                    exit_code=0,
                    stdout="",
                    stderr="",
                    started_at=now,
                    finished_at=now,
                    duration_seconds=0,
                    success=True,
                    error=None,
                ),
                document=None,
                xml_artifact_id=None,
                xml_sha256=None,
            )
        xml_path = Path(plan.xml_path)
        xml_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        result = self.runner.run(
            ToolCommand(
                tool=self.settings.nmap_binary,
                args=plan.args,
                timeout_seconds=timeout_seconds,
                environment={"LC_ALL": "C"},
            ),
            cancellation_token=cancellation_token,
        )
        if result.cancelled:
            xml_path.unlink(missing_ok=True)
            raise JobCancelled("Active discovery was cancelled")
        if not result.success:
            xml_path.unlink(missing_ok=True)
            raise self._tool_error(result)

        document = None
        artifact_id = None
        sha256 = None
        if xml_path.is_file():
            try:
                document = parse_nmap_xml(xml_path)
            except NmapParseError as exc:
                xml_path.unlink(missing_ok=True)
                raise JobExecutionError(
                    JobError(
                        code=exc.code.value,
                        category=ErrorCategory.PARSE,
                        message=exc.message,
                        component="nmap_parser",
                    )
                ) from exc
            if evidence_store and audit_id:
                artifact = evidence_store.import_file(
                    audit_id=audit_id,
                    job_id=job_id,
                    artifact_type="nmap_xml",
                    source=xml_path,
                    content_type="application/xml",
                    extension=".xml",
                    retention_class=RetentionClass.AUDIT,
                )
                artifact_id = artifact.id
                sha256 = artifact.sha256
            xml_path.unlink(missing_ok=True)
        return NmapRun(
            plan=plan,
            tool_result=result,
            document=document,
            xml_artifact_id=artifact_id,
            xml_sha256=sha256,
        )

    def write_target_file(
        self,
        targets: list[str],
        directory: Path,
    ) -> Path:
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        path = directory / f"targets-{uuid.uuid4()}.txt"
        payload = "\n".join(targets) + "\n"
        path.write_text(payload, encoding="utf-8")
        path.chmod(0o600)
        return path

    def _version(self) -> str | None:
        if self._version_cache is not False:
            return self._version_cache  # type: ignore[return-value]
        binary = shutil.which(self.settings.nmap_binary)
        if binary is None:
            self._version_cache = None
            return None
        result = self.runner.run(
            ToolCommand(
                tool=self.settings.nmap_binary,
                args=["--version"],
                timeout_seconds=5,
            )
        )
        version = None
        if result.success:
            for line in result.stdout.splitlines():
                if line.lower().startswith("nmap version"):
                    parts = line.split()
                    if len(parts) >= 3:
                        version = parts[2]
                        break
        self._version_cache = version
        return version

    def _tool_error(self, result: ToolResult) -> JobExecutionError:
        code = result.error.code if result.error else ToolErrorCode.NON_ZERO_EXIT
        category = {
            ToolErrorCode.MISSING_BINARY: ErrorCategory.TOOL_MISSING,
            ToolErrorCode.PERMISSION_DENIED: ErrorCategory.PERMISSION,
            ToolErrorCode.TIMEOUT: ErrorCategory.TIMEOUT,
            ToolErrorCode.CANCELLED: ErrorCategory.CANCELLED,
        }.get(code, ErrorCategory.INTERNAL)
        return JobExecutionError(
            JobError(
                code=code.value if hasattr(code, "value") else str(code),
                category=category,
                message=(
                    result.error.message
                    if result.error
                    else "Nmap scan failed"
                ),
                component="nmap_provider",
                retryable=bool(result.error.retryable) if result.error else False,
                details={"exit_code": result.exit_code},
            )
        )

    @staticmethod
    def _all_directly_connected_ipv4(
        resolved: ResolvedScope,
        scope: ValidatedScope,
    ) -> bool:
        return scope.address_families == [4] and all(
            route.directly_connected for route in resolved.routes
        )


def _ports(ports: tuple[int, ...]) -> str:
    return ",".join(str(port) for port in ports)
