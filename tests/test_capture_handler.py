from dataclasses import replace
from pathlib import Path

from engine.interfaces import (
    InterfaceValidationCode,
    InterfaceValidationError,
)
from jobs.handlers.capture import PacketCaptureHandler
from jobs.registry import HandlerContext
from providers.capture import CaptureProvider
from providers.tools import ToolError, ToolErrorCode
from tests.helpers import tool_result
from tests.test_capture import interface as capture_interface


class FakeDumpcap:
    def __init__(self, *, cancelled=False):
        self.command = None
        self.cancelled = cancelled

    def run(self, command, cancellation_token=None):
        self.command = command
        output = Path(command.args[command.args.index("-w") + 1])
        output.write_bytes(b"pcap-header-placeholder!!!!")
        if self.cancelled or (
            cancellation_token is not None and cancellation_token.cancelled
        ):
            return tool_result(
                tool="dumpcap",
                stderr="Packets captured: 6\n",
                success=False,
                exit_code=None,
                error=ToolError(
                    code=ToolErrorCode.CANCELLED,
                    message="cancelled",
                ),
            ).model_copy(update={"cancelled": True})
        return tool_result(
            tool="dumpcap",
            stderr="Packets captured: 6\n",
        )


class InterfaceStub:
    def validate(self, name):
        if name != "eth0":
            raise InterfaceValidationError(
                InterfaceValidationCode.UNKNOWN_INTERFACE,
                f"Unknown network interface: {name}",
            )
        return capture_interface()


def _context(job_service, evidence_store, settings, token, parameters):
    audit = job_service.create_audit(
        profile="packet_capture",
        interface=parameters["interface"],
    )
    job = job_service.create_job(
        audit_id=audit.id,
        job_type="packet_capture",
        target=parameters["interface"],
        parameters=parameters,
        resource_key=f"interface:{parameters['interface']}",
        resource_group="packet_capture",
        resource_limit=1,
    )
    progress = []
    claimed = job_service.claim_next("capture-test")
    assert claimed is not None
    context = HandlerContext(
        audit=audit,
        job=job_service.get_job(job.id),
        settings=settings,
        cancellation_token=token,
        evidence_store=evidence_store,
        report_progress=progress.append,
    )
    return context, progress, job.id, audit.id


def test_packet_capture_handler_imports_pcap_not_blob(
    durable_settings,
    job_service,
    evidence_store,
):
    from providers.tools import CancellationToken

    runner = FakeDumpcap()
    settings = replace(
        durable_settings,
        listen_duration_min=1,
        listen_duration_max=60,
        listen_duration_default=5,
        listen_max_filesize_kb_default=1024,
        listen_max_filesize_kb_max=2048,
    )
    handler = PacketCaptureHandler(
        capture_factory=lambda context: CaptureProvider(
            runner=runner,
            settings=context.settings,
        ),
        interface_factory=lambda _context: InterfaceStub(),
    )
    token = CancellationToken()
    context, progress, job_id, audit_id = _context(
        job_service,
        evidence_store,
        settings,
        token,
        {
            "interface": "eth0",
            "duration_seconds": 5,
            "max_filesize_kb": 1024,
            "filter": "tcp port 80",
        },
    )

    result = handler.execute(context)

    assert runner.command is not None
    assert runner.command.args[runner.command.args.index("-f") + 1] == "tcp port 80"
    assert "-p" not in runner.command.args
    assert result.result_reference
    document = evidence_store.read_json(
        job_service.artifact(result.result_reference)
    )
    assert document["schema"] == "packet-capture-result"
    assert document["promiscuous"] is True
    assert document["filter"] == "tcp port 80"
    pcap = job_service.artifact(document["pcap_artifact_id"])
    assert pcap.artifact_type == "packet_capture"
    assert pcap.content_type == "application/vnd.tcpdump.pcap"
    payload = evidence_store.read_bytes(pcap)
    assert payload.startswith(b"pcap-header")
    assert result.summary["pcap_artifact_id"] == pcap.id
    assert any(item.stage == "capturing" for item in progress)


def test_packet_capture_handler_retains_pcap_on_cancel(
    durable_settings,
    job_service,
    evidence_store,
):
    from jobs.errors import JobCancelled
    from providers.tools import CancellationToken

    runner = FakeDumpcap(cancelled=True)
    settings = replace(durable_settings, listen_duration_min=1)
    handler = PacketCaptureHandler(
        capture_factory=lambda context: CaptureProvider(
            runner=runner,
            settings=context.settings,
        ),
        interface_factory=lambda _context: InterfaceStub(),
    )
    token = CancellationToken()
    context, _progress, job_id, audit_id = _context(
        job_service,
        evidence_store,
        settings,
        token,
        {"interface": "eth0", "duration_seconds": 5, "max_filesize_kb": 1024},
    )

    try:
        handler.execute(context)
    except JobCancelled as cancelled:
        assert cancelled.result_reference
        document = evidence_store.read_json(
            job_service.artifact(cancelled.result_reference)
        )
        assert document["stopped_by_operator"] is True
        assert document["pcap_artifact_id"]
        assert evidence_store.path_for(
            job_service.artifact(document["pcap_artifact_id"])
        ).is_file()
    else:
        raise AssertionError("cancelled listen must raise JobCancelled")
