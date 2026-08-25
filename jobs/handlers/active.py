"""Durable active discovery handler."""

from collections.abc import Callable
from pathlib import Path
import shutil
import time
from typing import Any

from config.logging import get_logger
from engine.active_profiles import ActiveScanProfile, profile_for
from engine.routes import RouteResolver, RouteValidationError
from engine.scope import (
    ActiveProfile,
    ScopeValidationError,
    ScopeValidator,
    ValidatedScope,
)
from inventory.service import InventoryService
from jobs.errors import JobCancelled, JobExecutionError
from jobs.models import (
    ErrorCategory,
    JobError,
    JobProgress,
    RetentionClass,
)
from jobs.registry import HandlerContext, HandlerResult
from parsers.nmap import live_targets
from providers.nmap import NmapCommandPlan, NmapProvider, NmapRun
from providers.nmap_progress import NmapProgressSnapshot


class ActiveDiscoveryHandler:
    def __init__(
        self,
        *,
        nmap_factory: Callable[[HandlerContext], NmapProvider] | None = None,
        route_resolver_factory: (
            Callable[[HandlerContext], RouteResolver] | None
        ) = None,
        inventory_factory: (
            Callable[[HandlerContext], InventoryService] | None
        ) = None,
    ) -> None:
        self.nmap_factory = nmap_factory or (
            lambda context: NmapProvider(settings=context.settings)
        )
        self.route_resolver_factory = route_resolver_factory or (
            lambda context: RouteResolver()
        )
        self.inventory_factory = inventory_factory or (
            lambda context: InventoryService(
                context.evidence_store.database,
                context.settings,
                context.evidence_store,
            )
        )
        self.logger = get_logger("active_discovery")

    def execute(self, context: HandlerContext) -> HandlerResult:
        inventory = self.inventory_factory(context)
        nmap = self.nmap_factory(context)
        resolver = self.route_resolver_factory(context)
        runtime_dir = (
            context.settings.nmap_runtime_dir / context.job.id
        )
        runtime_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        runs: list[dict[str, Any]] = []
        try:
            return self._run(
                context,
                inventory=inventory,
                nmap=nmap,
                resolver=resolver,
                runtime_dir=runtime_dir,
                runs=runs,
            )
        finally:
            shutil.rmtree(runtime_dir, ignore_errors=True)

    def _run(
        self,
        context: HandlerContext,
        *,
        inventory: InventoryService,
        nmap: NmapProvider,
        resolver: RouteResolver,
        runtime_dir: Path,
        runs: list[dict[str, Any]],
    ) -> HandlerResult:
        self._ensure_not_cancelled(context)
        self._progress(context, 5, "validating_scope", "Validating scope")
        profile, scope, confirmed = self._load_scope(context, inventory)
        scan_profile = profile_for(profile, context.settings)

        self._progress(
            context,
            10,
            "resolving_route",
            f"Resolving route via {confirmed.interface}",
        )
        try:
            resolved = resolver.resolve(confirmed.interface, scope)
        except RouteValidationError as exc:
            raise self._validation_error(
                exc.code.value,
                exc.message,
                component="route_resolver",
                details=exc.details,
            ) from exc

        inventory.activate_scope(confirmed.id)
        self.logger.info(
            "active discovery started",
            extra={
                "audit_id": context.audit.id,
                "job_id": context.job.id,
                "component": "active_discovery",
                "interface": confirmed.interface,
                "profile": profile.value,
                "scope_targets": len(scope.canonical_targets),
                "address_count": scope.address_count,
            },
        )

        self._ensure_not_cancelled(context)
        self._progress(
            context,
            15,
            "discovering_hosts",
            "Discovering hosts",
        )
        host_run = self._execute_plan(
            context,
            nmap=nmap,
            plan=nmap.build_host_discovery(
                scope=scope,
                resolved=resolved,
                profile=scan_profile,
                xml_path=runtime_dir / "host-discovery.xml",
                target_file=nmap.write_target_file(
                    scope.canonical_targets,
                    runtime_dir,
                ),
            ),
            timeout_seconds=scan_profile.timeout_seconds,
            progress_callback=self._nmap_live_callback(
                context,
                stage="discovering_hosts",
                start_percentage=15,
                end_percentage=29,
                total_hosts=scope.address_count,
                port_label=None,
            ),
        )
        runs.append(self._run_metadata(host_run, nmap))
        discovered = 0
        if host_run.document is not None:
            discovered = inventory.ingest_nmap_document(
                audit_id=context.audit.id,
                job_id=context.job.id,
                document=host_run.document,
                evidence_reference=host_run.xml_artifact_id,
                persist_unresponsive_singletons=scope.address_count == 1,
            )
        self._progress(
            context,
            30,
            "hosts_discovered",
            f"{discovered} hosts discovered",
        )

        targets = (
            live_targets(host_run.document)
            if host_run.document is not None
            else []
        )
        capabilities = nmap.capabilities()
        fallbacks = list(host_run.plan.fallbacks)
        tcp_plan: NmapCommandPlan | None = None
        tcp_fingerprint_plan: NmapCommandPlan | None = None
        udp_plan: NmapCommandPlan | None = None
        open_tcp_ports: list[int] = []

        if scan_profile.run_tcp_scan and targets:
            self._ensure_not_cancelled(context)
            if profile == ActiveProfile.DEEP:
                tcp_plan, tcp_fingerprint_plan, open_tcp_ports = self._run_deep_tcp(
                    context,
                    nmap=nmap,
                    inventory=inventory,
                    scope=scope,
                    resolved=resolved,
                    scan_profile=scan_profile,
                    runtime_dir=runtime_dir,
                    targets=targets,
                    runs=runs,
                    fallbacks=fallbacks,
                )
            else:
                self._progress(
                    context,
                    35,
                    "scanning_tcp",
                    "Scanning TCP services",
                )
                tcp_plan = nmap.build_tcp_scan(
                    scope=scope,
                    resolved=resolved,
                    profile=scan_profile,
                    xml_path=runtime_dir / "tcp-scan.xml",
                    target_file=nmap.write_target_file(targets, runtime_dir),
                )
                tcp_run = self._execute_plan(
                    context,
                    nmap=nmap,
                    plan=tcp_plan,
                    timeout_seconds=scan_profile.timeout_seconds,
                    progress_callback=self._nmap_live_callback(
                        context,
                        stage="scanning_tcp",
                        start_percentage=35,
                        end_percentage=69,
                        total_hosts=len(targets),
                        port_label="open TCP",
                    ),
                )
                runs.append(self._run_metadata(tcp_run, nmap))
                fallbacks.extend(tcp_run.plan.fallbacks)
                if tcp_run.document is not None:
                    inventory.ingest_nmap_document(
                        audit_id=context.audit.id,
                        job_id=context.job.id,
                        document=tcp_run.document,
                        evidence_reference=tcp_run.xml_artifact_id,
                    )
                self._progress(
                    context,
                    70,
                    "fingerprinting_services",
                    "Fingerprinting services",
                )

        if scan_profile.run_udp_scan and targets:
            self._ensure_not_cancelled(context)
            self._progress(
                context,
                82,
                "udp_discovery",
                "Selected UDP discovery",
            )
            udp_plan = nmap.build_udp_scan(
                scope=scope,
                resolved=resolved,
                profile=scan_profile,
                xml_path=runtime_dir / "udp-scan.xml",
                target_file=nmap.write_target_file(targets, runtime_dir),
            )
            if udp_plan is not None and udp_plan.args:
                udp_run = self._execute_plan(
                    context,
                    nmap=nmap,
                    plan=udp_plan,
                    timeout_seconds=scan_profile.timeout_seconds,
                    progress_callback=self._nmap_live_callback(
                        context,
                        stage="udp_discovery",
                        start_percentage=82,
                        end_percentage=89,
                        total_hosts=len(targets),
                        port_label="open UDP",
                    ),
                )
                runs.append(self._run_metadata(udp_run, nmap))
                fallbacks.extend(udp_run.plan.fallbacks)
                if udp_run.document is not None:
                    inventory.ingest_nmap_document(
                        audit_id=context.audit.id,
                        job_id=context.job.id,
                        document=udp_run.document,
                        evidence_reference=udp_run.xml_artifact_id,
                    )
            elif udp_plan is not None:
                fallbacks.extend(udp_plan.fallbacks)
                runs.append(
                    {
                        "scan_kind": udp_plan.scan_kind,
                        "fallbacks": udp_plan.fallbacks,
                        "udp_ports": udp_plan.udp_ports,
                    }
                )

        self._ensure_not_cancelled(context)
        self._progress(
            context,
            90,
            "correlating_observations",
            "Correlating observations",
        )
        inventory.ingest_passive_from_audit(
            context.audit.id,
            job_id=context.job.id,
        )
        inventory.refresh_classifications(context.audit.id)

        self._progress(
            context,
            96,
            "persisting_inventory",
            "Persisting inventory",
        )
        summary = inventory.summary(context.audit.id)
        scan_methods = {
            "tcp_scan_method": (
                tcp_plan.tcp_method if tcp_plan is not None else "none"
            ),
            "host_discovery_method": host_run.plan.host_discovery_method,
            "tcp_ports_requested": (
                tcp_plan.tcp_ports if tcp_plan is not None else None
            ),
            "tcp_strategy": (
                "full-sweep-then-fingerprint"
                if profile == ActiveProfile.DEEP and tcp_plan is not None
                else "single-pass"
            ),
            "tcp_open_ports_discovered": len(open_tcp_ports),
            "tcp_fingerprint_ports": (
                tcp_fingerprint_plan.tcp_ports
                if tcp_fingerprint_plan is not None
                else None
            ),
            "effective_tcp_timing": (
                tcp_plan.timing if tcp_plan is not None else None
            ),
            "udp_ports_requested": (
                udp_plan.udp_ports if udp_plan is not None else None
            ),
            "service_detection": scan_profile.service_detection,
            "version_intensity": scan_profile.version_intensity,
            "os_detection_enabled": bool(
                (
                    tcp_fingerprint_plan.os_detection
                    if tcp_fingerprint_plan is not None
                    else tcp_plan.os_detection
                )
                if tcp_plan is not None
                else False
            ),
            "timing_profile": scan_profile.timing,
            "fallbacks": sorted(set(fallbacks)),
            "privileged": capabilities.privileged,
            "directly_connected": any(
                route.directly_connected for route in resolved.routes
            ),
        }
        document = {
            "schema": "active-discovery-result",
            "schema_version": 1,
            "audit_id": context.audit.id,
            "job_id": context.job.id,
            "confirmed_scope_id": confirmed.id,
            "profile": profile.value,
            "interface": confirmed.interface,
            "scope": scope.canonical_targets,
            "scan_methods": scan_methods,
            "nmap_version": capabilities.version,
            "runs": runs,
            "summary": summary.model_dump(mode="json"),
        }
        result_artifact = context.evidence_store.put_json(
            audit_id=context.audit.id,
            job_id=context.job.id,
            artifact_type="active_discovery_result",
            document=document,
            retention_class=RetentionClass.AUDIT,
            schema_name="active-discovery-result",
            schema_version=1,
        )
        self.logger.info(
            "active discovery completed",
            extra={
                "audit_id": context.audit.id,
                "job_id": context.job.id,
                "component": "active_discovery",
                "interface": confirmed.interface,
                "profile": profile.value,
                "assets": summary.assets,
                "services": summary.services,
            },
        )
        return HandlerResult(
            result_reference=result_artifact.id,
            summary={
                "schema": "active-discovery-summary",
                "schema_version": 1,
                "result_reference": result_artifact.id,
                "interface": confirmed.interface,
                "profile": profile.value,
                "scan_methods": scan_methods,
                **summary.model_dump(mode="json"),
            },
        )

    def _run_deep_tcp(
        self,
        context: HandlerContext,
        *,
        nmap: NmapProvider,
        inventory: InventoryService,
        scope: ValidatedScope,
        resolved: Any,
        scan_profile: ActiveScanProfile,
        runtime_dir: Path,
        targets: list[str],
        runs: list[dict[str, Any]],
        fallbacks: list[str],
    ) -> tuple[NmapCommandPlan, NmapCommandPlan | None, list[int]]:
        self._progress(
            context,
            35,
            "scanning_tcp",
            "Deep TCP full-range sweep",
        )
        sweep_plan = nmap.build_tcp_sweep(
            scope=scope,
            resolved=resolved,
            profile=scan_profile,
            xml_path=runtime_dir / "tcp-sweep.xml",
            target_file=nmap.write_target_file(targets, runtime_dir),
        )
        sweep_run = self._execute_plan(
            context,
            nmap=nmap,
            plan=sweep_plan,
            timeout_seconds=scan_profile.timeout_seconds,
            progress_callback=self._nmap_live_callback(
                context,
                stage="scanning_tcp",
                start_percentage=35,
                end_percentage=60,
                total_hosts=len(targets),
                port_label="open TCP",
            ),
        )
        runs.append(self._run_metadata(sweep_run, nmap))
        fallbacks.extend(sweep_run.plan.fallbacks)
        if sweep_run.document is not None:
            inventory.ingest_nmap_document(
                audit_id=context.audit.id,
                job_id=context.job.id,
                document=sweep_run.document,
                evidence_reference=sweep_run.xml_artifact_id,
            )

        open_ports = nmap.open_tcp_ports(sweep_run.document)
        fingerprint_targets = nmap.targets_with_open_tcp(sweep_run.document)
        self._progress(
            context,
            61,
            "tcp_ports_discovered",
            f"{len(open_ports)} unique open TCP ports discovered",
        )
        if not open_ports or not fingerprint_targets:
            self._progress(
                context,
                79,
                "fingerprinting_services",
                "No open TCP ports require fingerprinting",
            )
            return sweep_plan, None, open_ports

        self._ensure_not_cancelled(context)
        self._progress(
            context,
            62,
            "fingerprinting_services",
            f"Fingerprinting {len(open_ports)} open TCP ports",
        )
        fingerprint_plan = nmap.build_tcp_fingerprint(
            scope=scope,
            resolved=resolved,
            profile=scan_profile,
            ports=open_ports,
            xml_path=runtime_dir / "tcp-fingerprint.xml",
            target_file=nmap.write_target_file(fingerprint_targets, runtime_dir),
        )
        if fingerprint_plan is None:
            return sweep_plan, None, open_ports
        fingerprint_run = self._execute_plan(
            context,
            nmap=nmap,
            plan=fingerprint_plan,
            timeout_seconds=scan_profile.timeout_seconds,
            progress_callback=self._nmap_live_callback(
                context,
                stage="fingerprinting_services",
                start_percentage=62,
                end_percentage=79,
                total_hosts=len(fingerprint_targets),
                port_label="open TCP",
            ),
        )
        runs.append(self._run_metadata(fingerprint_run, nmap))
        fallbacks.extend(fingerprint_run.plan.fallbacks)
        if fingerprint_run.document is not None:
            inventory.ingest_nmap_document(
                audit_id=context.audit.id,
                job_id=context.job.id,
                document=fingerprint_run.document,
                evidence_reference=fingerprint_run.xml_artifact_id,
            )
        return sweep_plan, fingerprint_plan, open_ports

    def _load_scope(
        self,
        context: HandlerContext,
        inventory: InventoryService,
    ) -> tuple[ActiveProfile, ValidatedScope, Any]:
        parameters = context.job.parameters
        try:
            profile = ActiveProfile(str(parameters.get("profile", "standard")))
        except ValueError as exc:
            raise self._validation_error(
                "invalid_profile",
                "Active discovery profile is invalid",
            ) from exc
        raw_targets = parameters.get("scope")
        if not isinstance(raw_targets, list) or not raw_targets:
            raise self._validation_error(
                "empty_scope",
                "Active discovery requires a confirmed scope",
            )
        try:
            scope = ScopeValidator(context.settings).validate(
                [str(item) for item in raw_targets],
                profile,
            )
        except ScopeValidationError as exc:
            raise self._validation_error(
                exc.code.value,
                exc.message,
                details=exc.details,
            ) from exc

        scope_id = parameters.get("confirmed_scope_id")
        confirmed = inventory.get_scope(str(scope_id)) if scope_id else None
        if confirmed is None:
            raise self._validation_error(
                "scope_not_confirmed",
                "Active discovery requires a confirmed authorized scope",
            )
        if (
            confirmed.targets != scope.canonical_targets
            or confirmed.profile != profile
            or confirmed.interface != str(parameters.get("interface") or "")
        ):
            raise self._validation_error(
                "scope_snapshot_mismatch",
                "Job parameters do not match the confirmed scope snapshot",
            )
        return profile, scope, confirmed

    def _execute_plan(
        self,
        context: HandlerContext,
        *,
        nmap: NmapProvider,
        plan: NmapCommandPlan,
        timeout_seconds: int,
        progress_callback: Callable[[NmapProgressSnapshot], None] | None = None,
    ) -> NmapRun:
        self._ensure_not_cancelled(context)
        return nmap.run_plan(
            plan,
            timeout_seconds=timeout_seconds,
            cancellation_token=context.cancellation_token,
            evidence_store=context.evidence_store,
            audit_id=context.audit.id,
            job_id=context.job.id,
            progress_callback=progress_callback,
        )

    def _nmap_live_callback(
        self,
        context: HandlerContext,
        *,
        stage: str,
        start_percentage: int,
        end_percentage: int,
        total_hosts: int,
        port_label: str | None,
    ) -> Callable[[NmapProgressSnapshot], None]:
        state: dict[str, Any] = {
            "last_emit": 0.0,
            "last_open": -1,
            "last_percent": None,
            "last_overall": start_percentage,
        }

        def report(snapshot: NmapProgressSnapshot) -> None:
            if context.cancellation_token.cancelled:
                return
            now = time.monotonic()
            percent_changed = (
                snapshot.percent is not None
                and snapshot.percent != state["last_percent"]
            )
            open_changed = snapshot.open_ports != state["last_open"]
            if (
                state["last_emit"]
                and now - state["last_emit"] < 4.0
                and not open_changed
            ):
                return
            if not percent_changed and not open_changed and now - state["last_emit"] < 8.0:
                return

            if snapshot.percent is not None:
                span = max(0, end_percentage - start_percentage)
                mapped = start_percentage + int(span * snapshot.percent / 100.0)
                overall = max(state["last_overall"], min(end_percentage, mapped))
            else:
                overall = state["last_overall"]
            state["last_overall"] = overall
            state["last_percent"] = snapshot.percent
            state["last_open"] = snapshot.open_ports
            state["last_emit"] = now

            parts = ["Nmap live"]
            if snapshot.percent is not None:
                parts.append(f"{snapshot.percent:.1f}%")
            if snapshot.hosts_completed is not None:
                host_text = str(snapshot.hosts_completed)
                if total_hosts > 0:
                    host_text += f"/{total_hosts}"
                if snapshot.hosts_up is not None:
                    host_text += f" ({snapshot.hosts_up} up)"
                parts.append(f"хостов {host_text}")
            if port_label is not None:
                parts.append(f"{port_label}: {snapshot.open_ports}")
            if snapshot.last_open_port is not None and snapshot.last_open_host:
                parts.append(
                    f"последний {snapshot.last_open_port} @ {snapshot.last_open_host}"
                )
            if snapshot.remaining:
                parts.append(f"осталось ~{snapshot.remaining}")
            context.report_progress(
                JobProgress(
                    percentage=overall,
                    stage=stage,
                    message=" · ".join(parts),
                )
            )

        return report

    @staticmethod
    def _run_metadata(run: NmapRun, nmap: NmapProvider) -> dict[str, Any]:
        capabilities = nmap.capabilities()
        return {
            "tool": capabilities.binary,
            "tool_version": capabilities.version,
            "scan_kind": run.plan.scan_kind,
            "scan_method": run.plan.tcp_method,
            "host_discovery_method": run.plan.host_discovery_method,
            "profile_timing": run.plan.timing,
            "interface": _arg_value(run.plan.args, "-e"),
            "started_at": run.tool_result.started_at.isoformat(),
            "finished_at": run.tool_result.finished_at.isoformat(),
            "exit_code": run.tool_result.exit_code,
            "artifact_id": run.xml_artifact_id,
            "sha256": run.xml_sha256,
            "tcp_ports": run.plan.tcp_ports,
            "udp_ports": run.plan.udp_ports,
            "service_detection": run.plan.service_detection,
            "os_detection": run.plan.os_detection,
            "fallbacks": run.plan.fallbacks,
            "command_metadata": {
                "arg_count": len(run.plan.args),
                "skip_host_discovery": run.plan.skip_host_discovery,
                "privileged": run.plan.privileged,
            },
        }

    @staticmethod
    def _progress(
        context: HandlerContext,
        percentage: int,
        stage: str,
        message: str,
    ) -> None:
        context.report_progress(
            JobProgress(
                percentage=percentage,
                stage=stage,
                message=message,
            )
        )

    @staticmethod
    def _ensure_not_cancelled(context: HandlerContext) -> None:
        if context.cancellation_token.cancelled:
            raise JobCancelled("Active discovery was cancelled")

    @staticmethod
    def _validation_error(
        code: str,
        message: str,
        *,
        component: str = "scope_validator",
        details: dict[str, Any] | None = None,
    ) -> JobExecutionError:
        return JobExecutionError(
            JobError(
                code=code,
                category=ErrorCategory.VALIDATION,
                message=message,
                component=component,
                details=details or {},
            )
        )


def _arg_value(args: list[str], flag: str) -> str | None:
    try:
        return args[args.index(flag) + 1]
    except (ValueError, IndexError):
        return None
