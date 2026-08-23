"""Execute one protocol module through ToolRunner and persist observations."""

from typing import Any

from config.settings import Settings
from jobs.errors import JobCancelled
from jobs.models import RetentionClass
from protocol_audits.models import (
    MAX_EVIDENCE_TEXT_BYTES,
    ModuleRun,
    ObservationDraft,
    ProbeTarget,
)
from protocol_audits.modules.base import ProtocolModule
from protocol_audits.status import unavailable_observation
from protocol_audits.store import ProtocolObservationStore
from providers.tools import (
    CancellationToken,
    ToolCommand,
    ToolResult,
    ToolRunner,
)
from storage.evidence import EvidenceStore


class ProtocolModuleRunner:
    def __init__(
        self,
        *,
        runner: ToolRunner,
        settings: Settings,
        evidence_store: EvidenceStore,
        observation_store: ProtocolObservationStore,
    ) -> None:
        self.runner = runner
        self.settings = settings
        self.evidence_store = evidence_store
        self.observation_store = observation_store

    def run(
        self,
        module: ProtocolModule,
        target: ProbeTarget,
        *,
        audit_id: str,
        job_id: str,
        cancellation_token: CancellationToken,
    ) -> ModuleRun:
        if cancellation_token.cancelled:
            raise JobCancelled("Protocol audit was cancelled")
        availability = module.availability(self.runner, self.settings)
        if not availability.available or not availability.meets_minimum:
            drafts = [
                unavailable_observation(
                    availability.tool,
                    availability.message,
                )
            ]
            persisted = self.observation_store.upsert_many(
                audit_id=audit_id,
                asset_id=target.asset.id,
                service_id=target.service.id,
                protocol=module.protocol,
                module=module.name,
                drafts=drafts,
                evidence_artifact_id=None,
            )
            return ModuleRun(
                module=module.name,
                protocol=module.protocol,
                tool=availability.tool,
                available=False,
                skipped=True,
                skip_reason=availability.message,
                observation_count=len(persisted),
            )

        commands = module.build_commands(target, self.settings)
        results: list[ToolResult] = []
        for command in commands:
            if cancellation_token.cancelled:
                raise JobCancelled("Protocol audit was cancelled")
            result = self.runner.run(command, cancellation_token)
            if result.cancelled:
                raise JobCancelled("Protocol audit was cancelled")
            results.append(result)

        drafts = module.parse_results(results, target)
        artifact_id = self._store_evidence(
            audit_id=audit_id,
            job_id=job_id,
            module=module,
            target=target,
            commands=commands,
            results=results,
            availability=availability.version,
        )
        persisted = self.observation_store.upsert_many(
            audit_id=audit_id,
            asset_id=target.asset.id,
            service_id=target.service.id,
            protocol=module.protocol,
            module=module.name,
            drafts=_without_cancelled(drafts),
            evidence_artifact_id=artifact_id,
        )
        last = results[-1] if results else None
        return ModuleRun(
            module=module.name,
            protocol=module.protocol,
            tool=availability.tool,
            available=True,
            observation_count=len(persisted),
            exit_code=last.exit_code if last else None,
            timed_out=any(item.timed_out for item in results),
            duration_seconds=sum(item.duration_seconds for item in results),
            evidence_artifact_id=artifact_id,
            command_metadata=module.command_metadata(commands),
        )

    def _store_evidence(
        self,
        *,
        audit_id: str,
        job_id: str,
        module: ProtocolModule,
        target: ProbeTarget,
        commands: list[ToolCommand],
        results: list[ToolResult],
        availability: str | None,
    ) -> str:
        document: dict[str, Any] = {
            "schema": "protocol-tool-output",
            "schema_version": 1,
            "module": module.name,
            "tool": module.tool_name(self.settings),
            "tool_version": availability,
            "asset_id": target.asset.id,
            "service_id": target.service.id,
            "address": target.address,
            "port": target.port,
            "command_metadata": module.command_metadata(commands),
            "results": [
                {
                    "exit_code": result.exit_code,
                    "timed_out": result.timed_out,
                    "success": result.success,
                    "started_at": result.started_at.isoformat(),
                    "finished_at": result.finished_at.isoformat(),
                    "duration_seconds": result.duration_seconds,
                    "stdout": _bound_text(result.stdout),
                    "stderr": _bound_text(result.stderr),
                    "error_code": (
                        result.error.code.value if result.error else None
                    ),
                }
                for result in results
            ],
        }
        artifact = self.evidence_store.put_json(
            audit_id=audit_id,
            job_id=job_id,
            artifact_type="protocol_tool_output",
            document=document,
            retention_class=RetentionClass.AUDIT,
            schema_name="protocol-tool-output",
            schema_version=1,
        )
        return artifact.id


def _bound_text(value: str) -> str:
    encoded = value.encode("utf-8", errors="replace")
    if len(encoded) <= MAX_EVIDENCE_TEXT_BYTES:
        return value
    clipped = encoded[:MAX_EVIDENCE_TEXT_BYTES]
    return clipped.decode("utf-8", errors="replace") + "\n[truncated]"


def _without_cancelled(drafts: list[ObservationDraft]) -> list[ObservationDraft]:
    return [draft for draft in drafts if draft.kind != "cancelled"]
