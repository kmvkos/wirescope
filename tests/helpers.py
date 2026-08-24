from datetime import datetime, timezone
from pathlib import Path

from engine.passive_models import ConfidenceLevel
from inventory.models import (
    AssetAddressRecord,
    AssetNameRecord,
    AssetRecord,
    AssetState,
    DeviceClassHint,
    ServiceRecord,
)
from protocol_audits.models import ProbeTarget, ProtocolObservationRecord
from providers.tools import ToolError, ToolErrorCode, ToolResult


def tool_result(
    *,
    tool: str = "fixture",
    stdout: str = "",
    stderr: str = "",
    exit_code: int | None = 0,
    success: bool = True,
    error: ToolError | None = None,
) -> ToolResult:
    now = datetime.now(timezone.utc)
    return ToolResult(
        command=[tool],
        tool=tool,
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        started_at=now,
        finished_at=now,
        duration_seconds=0,
        success=success,
        error=error,
    )


class RecordingRunner:
    def __init__(self, result_factory=None):
        self.commands = []
        self.result_factory = result_factory or (
            lambda command: tool_result(tool="nmap")
        )

    def run(self, command, cancellation_token=None):
        self.commands.append(command)
        if cancellation_token is not None and cancellation_token.cancelled:
            return tool_result(
                tool="nmap",
                success=False,
                exit_code=None,
                error=ToolError(
                    code=ToolErrorCode.CANCELLED,
                    message="cancelled",
                ),
            ).model_copy(update={"cancelled": True})
        return self.result_factory(command)


def xml_writer(xml, tmp_path: Path):
    def factory(command):
        if "--version" in command.args:
            return tool_result(
                tool="nmap",
                stdout="Nmap version 7.95 ( https://nmap.org )\n",
            )
        if "-oX" in command.args:
            path = Path(command.args[command.args.index("-oX") + 1])
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(xml, encoding="utf-8")
        return tool_result(tool="nmap")

    return factory


def utcnow():
    return datetime.now(timezone.utc)


def sample_service(
    *,
    port: int = 22,
    protocol: str = "tcp",
    name: str | None = "ssh",
    product: str | None = "OpenSSH",
    state: str = "open",
    tunnel: str | None = None,
    asset_id: str = "asset-1",
    service_id: str = "svc-1",
) -> ServiceRecord:
    now = utcnow()
    return ServiceRecord(
        id=service_id,
        audit_id="audit-1",
        asset_id=asset_id,
        protocol=protocol,
        port=port,
        state=state,
        reason="syn-ack",
        service_name=name,
        product=product,
        version=None,
        extra_info=None,
        tunnel=tunnel,
        cpe=[],
        banner=None,
        method="probed",
        confidence=ConfidenceLevel.HIGH,
        source="nmap",
        first_seen=now,
        last_seen=now,
    )


def sample_asset(
    *,
    address: str = "192.0.2.10",
    hostname: str = "linux.example.test",
    asset_id: str = "asset-1",
) -> AssetRecord:
    now = utcnow()
    return AssetRecord(
        id=asset_id,
        audit_id="audit-1",
        state=AssetState.RESPONSIVE,
        mac="00:11:22:33:44:55",
        vendor=None,
        vendor_source=None,
        vendor_database_version=None,
        device_class_hint=DeviceClassHint.UNKNOWN,
        device_class_confidence=ConfidenceLevel.UNKNOWN,
        os_family=None,
        os_name=None,
        os_generation=None,
        os_accuracy=None,
        first_seen=now,
        last_seen=now,
        metadata={},
        addresses=[
            AssetAddressRecord(
                id="addr-1",
                asset_id=asset_id,
                address=address,
                family=4 if ":" not in address else 6,
                is_primary=True,
                first_seen=now,
                last_seen=now,
                source="nmap",
                confidence=ConfidenceLevel.HIGH,
            )
        ],
        names=[
            AssetNameRecord(
                id="name-1",
                asset_id=asset_id,
                name=hostname,
                name_type="ptr",
                source="nmap",
                confidence=ConfidenceLevel.MEDIUM,
                first_seen=now,
                last_seen=now,
            )
        ],
    )


def sample_observation(
    *,
    kind: str = "ssh_algorithms",
    data: dict | None = None,
    observation_id: str = "obs-1",
    asset_id: str = "asset-1",
    service_id: str = "svc-1",
    protocol: str = "ssh",
    module: str = "ssh",
    source: str = "ssh-audit",
    evidence_artifact_id: str | None = "evidence-1",
    confidence: ConfidenceLevel = ConfidenceLevel.HIGH,
) -> ProtocolObservationRecord:
    now = utcnow()
    return ProtocolObservationRecord(
        id=observation_id,
        audit_id="audit-1",
        asset_id=asset_id,
        service_id=service_id,
        protocol=protocol,
        module=module,
        kind=kind,
        data=data or {},
        confidence=confidence,
        source=source,
        evidence_artifact_id=evidence_artifact_id,
        first_seen=now,
        last_seen=now,
    )


def sample_target(**kwargs) -> ProbeTarget:
    service = kwargs.pop("service", None) or sample_service()
    asset = kwargs.pop("asset", None) or sample_asset()
    return ProbeTarget(
        asset=asset,
        service=service,
        address=kwargs.get("address", asset.addresses[0].address),
        port=kwargs.get("port", service.port),
        hostname=kwargs.get("hostname", "linux.example.test"),
        scheme_hint=kwargs.get("scheme_hint"),
    )


class ProtocolRecordingRunner:
    VERSION_ARGS = {"--version", "-v", "-V", "-VV", "version"}

    def __init__(self, outputs=None, missing=(), versions=None):
        self.commands = []
        self.outputs = outputs or {}
        self.missing = set(missing)
        self.versions = versions or {}

    def run(self, command, cancellation_token=None):
        self.commands.append(command)
        if cancellation_token is not None and cancellation_token.cancelled:
            return tool_result(
                tool=command.tool,
                success=False,
                exit_code=None,
                error=ToolError(
                    code=ToolErrorCode.CANCELLED,
                    message="cancelled",
                ),
            ).model_copy(update={"cancelled": True})
        tool = Path(command.tool).name
        if tool in self.missing:
            return tool_result(
                tool=command.tool,
                success=False,
                exit_code=None,
                error=ToolError(
                    code=ToolErrorCode.MISSING_BINARY,
                    message=f"Tool not found: {command.tool}",
                ),
            )
        if self.VERSION_ARGS.intersection(command.args):
            version = self.versions.get(tool, f"{tool} 3.2.0")
            return tool_result(tool=command.tool, stdout=version)
        output = self.outputs.get(tool)
        if callable(output):
            return output(command)
        if output is None:
            return tool_result(tool=command.tool, stdout="")
        if isinstance(output, list):
            index = sum(1 for item in self.commands if Path(item.tool).name == tool and not self.VERSION_ARGS.intersection(item.args)) - 1
            chosen = output[min(index, len(output) - 1)]
            if isinstance(chosen, ToolResult):
                return chosen
            return tool_result(tool=command.tool, stdout=chosen)
        if isinstance(output, ToolResult):
            return output
        return tool_result(tool=command.tool, stdout=output)


def http_request(app, method, path, *, as_role="auditor", auth=True, **kwargs):
    import asyncio

    from httpx import ASGITransport, AsyncClient

    cookies = kwargs.pop("cookies", None)
    if cookies is None and auth:
        cookies = getattr(app.state, "auth_cookies", {}).get(as_role)

    async def send():
        transport = ASGITransport(app=app)
        async with AsyncClient(
            transport=transport,
            base_url="http://testserver",
            cookies=cookies,
        ) as client:
            return await client.request(method, path, **kwargs)

    return asyncio.run(send())


def session_cookie(response):
    return response.cookies.get("wirescope_session")


def login_role(app, username, password):
    response = http_request(
        app,
        "POST",
        "/api/auth/login",
        json={"username": username, "password": password},
        auth=False,
    )
    assert response.status_code == 200, response.text
    token = session_cookie(response)
    assert token
    return {app.state.settings.session_cookie_name: token}
