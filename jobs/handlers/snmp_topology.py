"""Durable operator-authorized SNMP topology enrichment."""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
from typing import Any

from backend.snmp_credentials import CredentialReferenceError, SnmpCredentialSpool
from engine.routes import RouteResolver, RouteValidationError
from engine.scope import ScopeValidationError, ScopeValidator
from inventory.service import InventoryService
from jobs.errors import JobCancelled, JobExecutionError
from jobs.models import ErrorCategory, JobError, JobProgress, RetentionClass
from jobs.registry import HandlerContext, HandlerResult
from providers.snmp_topology import SnmpCredentialError, SnmpTopologyProvider


@dataclass(frozen=True)
class _SnmpSettingsProxy:
    """Expose the provider binary without expanding the stable Settings schema."""

    base: Any
    snmpbulkwalk_binary: str = "snmpbulkwalk"

    def __getattr__(self, name: str) -> Any:
        return getattr(self.base, name)


class SnmpTopologyHandler:
    def execute(self, context: HandlerContext) -> HandlerResult:
        target_raw = str(context.job.parameters.get("target") or context.job.target or "")
        credential_ref = str(context.job.parameters.get("credential_ref") or "")
        confirmed_scope_id = str(context.job.parameters.get("confirmed_scope_id") or "")
        if not target_raw or not credential_ref or not confirmed_scope_id:
            raise self._validation("snmp_topology_parameters_missing", "SNMP topology job parameters are incomplete")
        try:
            target = str(ipaddress.ip_address(target_raw))
        except ValueError as exc:
            raise self._validation("snmp_target_invalid", "SNMP topology target must be an IP address") from exc

        inventory = InventoryService(
            context.evidence_store.database,
            context.settings,
            context.evidence_store,
        )
        confirmed = inventory.get_scope(confirmed_scope_id)
        if confirmed is None or confirmed.audit_id != context.audit.id:
            raise self._validation("snmp_scope_not_confirmed", "SNMP topology enrichment requires the audit's confirmed scope")
        if not _address_in_targets(target, confirmed.targets):
            raise self._validation("snmp_target_out_of_scope", "SNMP target is outside the confirmed active scope")
        if context.audit.interface and confirmed.interface != context.audit.interface:
            raise self._validation("snmp_interface_mismatch", "Confirmed scope interface no longer matches the audit")

        # Re-resolve the singleton target at execution time so a route change
        # cannot silently send SNMP through another interface.
        try:
            singleton = ScopeValidator(context.settings).validate([target], confirmed.profile)
            resolved = RouteResolver().resolve(confirmed.interface, singleton)
        except ScopeValidationError as exc:
            raise self._validation(exc.code.value, exc.message) from exc
        except RouteValidationError as exc:
            raise self._validation(exc.code.value, exc.message, details=exc.details) from exc

        spool = SnmpCredentialSpool(context.settings)
        try:
            try:
                credentials = spool.consume(credential_ref)
            except CredentialReferenceError as exc:
                raise self._validation("snmp_credentials_missing", str(exc)) from exc

            context.report_progress(JobProgress(percentage=2, stage="validating_snmp_scope", message="Проверяем подтверждённый scope и маршрут"))
            if context.cancellation_token.cancelled:
                raise JobCancelled("SNMP topology enrichment was cancelled")

            provider = SnmpTopologyProvider(
                settings=_SnmpSettingsProxy(context.settings),
            )

            def progress(percentage: int, message: str) -> None:
                if context.cancellation_token.cancelled:
                    return
                context.report_progress(
                    JobProgress(
                        percentage=max(3, min(88, int(percentage))),
                        stage="snmp_topology_read",
                        message=message,
                    )
                )

            try:
                document = provider.collect(
                    target=target,
                    credentials=credentials,
                    interface=confirmed.interface,
                    cancellation_token=context.cancellation_token,
                    progress=progress,
                )
            except SnmpCredentialError as exc:
                raise self._validation("snmp_credentials_invalid", str(exc)) from exc

            if context.cancellation_token.cancelled:
                raise JobCancelled("SNMP topology enrichment was cancelled")

            context.report_progress(JobProgress(percentage=90, stage="persisting_snmp_topology", message="Сохраняем SNMP topology evidence"))
            document.update(
                {
                    "audit_id": context.audit.id,
                    "job_id": context.job.id,
                    "confirmed_scope_id": confirmed.id,
                    "route": resolved.model_dump(mode="json"),
                }
            )
            artifact = context.evidence_store.put_json(
                audit_id=context.audit.id,
                job_id=context.job.id,
                artifact_type="snmp_topology_result",
                document=document,
                retention_class=RetentionClass.AUDIT,
                schema_name="snmp-topology-result",
                schema_version=1,
            )
            context.report_progress(JobProgress(percentage=98, stage="snmp_topology_ready", message="SNMP topology evidence готов"))
            return HandlerResult(
                result_reference=artifact.id,
                summary={
                    "schema": "snmp-topology-summary",
                    "schema_version": 1,
                    "result_reference": artifact.id,
                    "target": target,
                    "status": document.get("status"),
                    "interfaces": len(document.get("interfaces") or []),
                    "fdb_entries": len(document.get("fdb") or []),
                    "arp_entries": len(document.get("arp") or []),
                    "lldp_neighbors": len(document.get("lldp_neighbors") or []),
                    "vlans": len(document.get("vlans") or []),
                },
            )
        finally:
            # Consume-once semantics: secrets are deleted on success, error,
            # cancellation and parser/tool failures alike.
            try:
                spool.delete(credential_ref)
            except CredentialReferenceError:
                pass

    @staticmethod
    def _validation(code: str, message: str, *, details: dict[str, Any] | None = None) -> JobExecutionError:
        return JobExecutionError(
            JobError(
                code=code,
                category=ErrorCategory.VALIDATION,
                message=message,
                component="snmp_topology",
                retryable=False,
                details=details or {},
            )
        )


def _address_in_targets(address: str, targets: list[str]) -> bool:
    parsed = ipaddress.ip_address(address)
    for raw in targets:
        try:
            network = ipaddress.ip_network(
                raw if "/" in raw else f"{raw}/{32 if parsed.version == 4 else 128}",
                strict=False,
            )
        except ValueError:
            continue
        if network.version == parsed.version and parsed in network:
            return True
    return False
