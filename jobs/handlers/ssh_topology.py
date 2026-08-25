"""Durable operator-authorized read-only SSH topology enrichment."""

from __future__ import annotations

import ipaddress
import os
from pathlib import Path
import tempfile
from typing import Any

from backend.ssh_credentials import SshCredentialReferenceError, SshCredentialSpool
from engine.routes import RouteResolver, RouteValidationError
from engine.scope import ScopeValidationError, ScopeValidator
from inventory.service import InventoryService
from jobs.errors import JobCancelled, JobExecutionError
from jobs.models import ErrorCategory, JobError, JobProgress, RetentionClass
from jobs.registry import HandlerContext, HandlerResult
from providers.ssh_topology import SshTopologyCredentialError, SshTopologyProvider


class SshTopologyHandler:
    def execute(self, context: HandlerContext) -> HandlerResult:
        target_raw = str(context.job.parameters.get("target") or context.job.target or "")
        credential_ref = str(context.job.parameters.get("credential_ref") or "")
        confirmed_scope_id = str(context.job.parameters.get("confirmed_scope_id") or "")
        if not target_raw or not credential_ref or not confirmed_scope_id:
            raise self._validation("ssh_topology_parameters_missing", "SSH topology job parameters are incomplete")
        try:
            target = str(ipaddress.ip_address(target_raw))
        except ValueError as exc:
            raise self._validation("ssh_target_invalid", "SSH topology target must be an IP address") from exc

        inventory = InventoryService(
            context.evidence_store.database,
            context.settings,
            context.evidence_store,
        )
        confirmed = inventory.get_scope(confirmed_scope_id)
        if confirmed is None or confirmed.audit_id != context.audit.id:
            raise self._validation("ssh_scope_not_confirmed", "SSH topology enrichment requires the audit's confirmed scope")
        if not _address_in_targets(target, confirmed.targets):
            raise self._validation("ssh_target_out_of_scope", "SSH target is outside the confirmed active scope")
        if context.audit.interface and confirmed.interface != context.audit.interface:
            raise self._validation("ssh_interface_mismatch", "Confirmed scope interface no longer matches the audit")

        try:
            singleton = ScopeValidator(context.settings).validate([target], confirmed.profile)
            resolved = RouteResolver().resolve(confirmed.interface, singleton)
        except ScopeValidationError as exc:
            raise self._validation(exc.code.value, exc.message) from exc
        except RouteValidationError as exc:
            raise self._validation(exc.code.value, exc.message, details=exc.details) from exc

        spool = SshCredentialSpool(context.settings)
        try:
            try:
                credentials = spool.consume(credential_ref)
            except SshCredentialReferenceError as exc:
                raise self._validation("ssh_credentials_missing", str(exc)) from exc

            context.report_progress(JobProgress(percentage=2, stage="validating_ssh_scope", message="Проверяем confirmed scope, маршрут и SSH trust material"))
            if context.cancellation_token.cancelled:
                raise JobCancelled("SSH topology enrichment was cancelled")

            runtime_root = (context.settings.runtime_dir / "ssh-topology-runtime").resolve()
            runtime_root.mkdir(mode=0o700, parents=True, exist_ok=True)
            try:
                runtime_root.chmod(0o700)
            except OSError:
                pass

            with tempfile.TemporaryDirectory(prefix="job-", dir=runtime_root) as temporary:
                temporary_path = Path(temporary)
                known_hosts_path = temporary_path / "known_hosts"
                known_hosts_path.write_text(str(credentials.get("known_hosts") or ""), encoding="utf-8")
                known_hosts_path.chmod(0o600)

                identity_path: Path | None = None
                if str(credentials.get("authentication") or "private_key") == "private_key":
                    identity_path = temporary_path / "identity"
                    identity_path.write_text(str(credentials.get("private_key") or ""), encoding="utf-8")
                    identity_path.chmod(0o600)

                provider = SshTopologyProvider(settings=context.settings)

                def progress(percentage: int, message: str) -> None:
                    if context.cancellation_token.cancelled:
                        return
                    context.report_progress(
                        JobProgress(
                            percentage=max(3, min(88, int(percentage))),
                            stage="ssh_topology_read",
                            message=message,
                        )
                    )

                try:
                    document = provider.collect(
                        target=target,
                        credentials=credentials,
                        identity_file=identity_path,
                        known_hosts_file=known_hosts_path,
                        interface=confirmed.interface,
                        cancellation_token=context.cancellation_token,
                        progress=progress,
                    )
                except SshTopologyCredentialError as exc:
                    raise self._validation("ssh_credentials_invalid", str(exc)) from exc
                finally:
                    # Best-effort zero-length before TemporaryDirectory removes
                    # sensitive material.  Files never enter evidence storage.
                    for sensitive_path in (identity_path, known_hosts_path):
                        if sensitive_path is None:
                            continue
                        try:
                            if sensitive_path.exists():
                                with sensitive_path.open("r+b") as handle:
                                    size = sensitive_path.stat().st_size
                                    handle.write(b"\x00" * min(size, 1024 * 1024))
                                    handle.truncate(0)
                                    handle.flush()
                                    os.fsync(handle.fileno())
                        except OSError:
                            pass

            if context.cancellation_token.cancelled:
                raise JobCancelled("SSH topology enrichment was cancelled")

            context.report_progress(JobProgress(percentage=91, stage="persisting_ssh_topology", message="Сохраняем нормализованное SSH topology evidence"))
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
                artifact_type="ssh_topology_result",
                document=document,
                retention_class=RetentionClass.AUDIT,
                schema_name="ssh-topology-result",
                schema_version=1,
            )
            context.report_progress(JobProgress(percentage=98, stage="ssh_topology_ready", message="SSH topology evidence готов"))
            return HandlerResult(
                result_reference=artifact.id,
                summary={
                    "schema": "ssh-topology-summary",
                    "schema_version": 1,
                    "result_reference": artifact.id,
                    "target": target,
                    "status": document.get("status"),
                    "interfaces": len(document.get("interfaces") or []),
                    "routes": len(document.get("routes") or []),
                    "neighbors": len(document.get("neighbors") or []),
                    "fdb_entries": len(document.get("fdb") or []),
                    "vlan_ports": len(document.get("vlans") or []),
                    "wifi_associations": len(document.get("wifi_associations") or []),
                    "capabilities": document.get("capabilities") or {},
                },
            )
        finally:
            try:
                spool.delete(credential_ref)
            except SshCredentialReferenceError:
                pass

    @staticmethod
    def _validation(code: str, message: str, *, details: dict[str, Any] | None = None) -> JobExecutionError:
        return JobExecutionError(
            JobError(
                code=code,
                category=ErrorCategory.VALIDATION,
                message=message,
                component="ssh_topology",
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


__all__ = ["SshTopologyHandler"]
