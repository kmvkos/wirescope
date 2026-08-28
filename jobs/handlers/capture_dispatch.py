"""Dispatch packet_capture jobs without changing the durable job type."""

from __future__ import annotations

from jobs.handlers.capture import PacketCaptureHandler as LivePacketCaptureHandler
from jobs.handlers.imported_capture import ImportedPacketCaptureHandler
from jobs.registry import HandlerContext, HandlerResult


class PacketCaptureHandler:
    def __init__(self) -> None:
        self.live = LivePacketCaptureHandler()
        self.imported = ImportedPacketCaptureHandler()

    def execute(self, context: HandlerContext) -> HandlerResult:
        if str(context.job.parameters.get("source_origin") or "captured") == "imported":
            return self.imported.execute(context)
        return self.live.execute(context)
