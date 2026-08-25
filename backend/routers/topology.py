from __future__ import annotations

import ipaddress
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field, SecretStr, model_validator

from backend.dependencies import AppServices, get_services
from backend.http import invalid_transition_http, not_found
from backend.models import JobAcceptedResponse
from backend.snmp_credentials import SnmpCredentialSpool
from jobs.service import EntityNotFound
from jobs.state import InvalidTransition
from providers.snmp_topology import SnmpCredentialError, sanitize_credential_profile
from topology import TopologySourceError, build_global_topology, build_topology
from topology.compare import compare_topologies


router = APIRouter()


class SnmpTopologyRequest(BaseModel):
    target: str = Field(min_length=3, max_length=64)
    version: Literal["2c", "3"] = "3"
    community: SecretStr | None = None
    username: str | None = Field(default=None, max_length=64)
    security_level: Literal["noAuthNoPriv", "authNoPriv", "authPriv"] = "authPriv"
    auth_protocol: Literal["SHA", "SHA-224", "SHA-256", "SHA-384", "SHA-512"] = "SHA"
    auth_password: SecretStr | None = None
    priv_protocol: Literal["AES", "AES128"] = "AES"
    priv_password: SecretStr | None = None
    priority: int = Field(default=0, ge=-100, le=100)

    @model_validator(mode="after")
    def validate_credentials(self) -> "SnmpTopologyRequest":
        credentials = self.credentials()
        try:
            sanitize_credential_profile(credentials)
        except SnmpCredentialError as exc:
            raise ValueError(str(exc)) from exc
        return self

    def credentials(self) -> dict[str, str | None]:
        return {
            "version": self.version,
            "community": self.community.get_secret_value() if self.community else None,
            "username": (self.username or "").strip() or None,
            "security_level": self.security_level,
            "auth_protocol": self.auth_protocol,
            "auth_password": self.auth_password.get_secret_value() if self.auth_password else None,
            "priv_protocol": self.priv_protocol,
            "priv_password": self.priv_password.get_secret_value() if self.priv_password else None,
        }


@router.get("/topology/global")
def global_topology(
    limit: int = Query(default=100, ge=1, le=100),
    services: AppServices = Depends(get_services),
) -> dict:
    return build_global_topology(services, limit=limit)


@router.get("/audits/{audit_id}/topology/compare")
def compare_audit_topology(
    audit_id: str,
    against: str = Query(min_length=1),
    services: AppServices = Depends(get_services),
) -> dict:
    if audit_id == against:
        raise HTTPException(
            status_code=422,
            detail={
                "code": "same_topology",
                "message": "Choose two different audits for topology comparison",
            },
        )
    try:
        current = build_topology(services, audit_id)
        baseline = build_topology(services, against)
    except EntityNotFound as exc:
        raise HTTPException(
            status_code=404,
            detail={"code": "not_found", "message": str(exc)},
        ) from exc
    except TopologySourceError as exc:
        raise HTTPException(
            status_code=409,
            detail={"code": "topology_source_invalid", "message": str(exc)},
        ) from exc
    return compare_topologies(
        baseline=baseline,
        current=current,
        baseline_audit_id=against,
        current_audit_id=audit_id,
    )


@router.get("/audits/{audit_id}/topology")
def audit_topology(
    audit_id: str,
    traffic_analysis_job_id: str | None = Query(default=None),
    services: AppServices = Depends(get_services),
) -> dict:
    try:
        return build_topology(
            services,
            audit_id,
            traffic_analysis_job_id=traffic_analysis_job_id,
        )
    except EntityNotFound as exc:
        raise HTTPException(
            status_code=404,
            detail={"code": "not_found", "message": str(exc)},
        ) from exc
    except TopologySourceError as exc:
        raise HTTPException(
            status_code=409,
            detail={"code": "topology_source_invalid", "message": str(exc)},
        ) from exc


@router.post(
    "/audits/{audit_id}/topology/snmp",
    response_model=JobAcceptedResponse,
    status_code=202,
)
def enqueue_snmp_topology(
    audit_id: str,
    payload: SnmpTopologyRequest,
    services: AppServices = Depends(get_services),
) -> JobAcceptedResponse:
    spool = SnmpCredentialSpool(services.settings)
    credential_ref: str | None = None
    try:
        audit = services.jobs.get_audit(audit_id)
        if not audit.interface:
            raise HTTPException(
                status_code=422,
                detail={"code": "interface_required", "message": "Audit has no active interface"},
            )
        try:
            target = str(ipaddress.ip_address(payload.target.strip()))
        except ValueError as exc:
            raise HTTPException(
                status_code=422,
                detail={"code": "snmp_target_invalid", "message": "SNMP target must be an IP address"},
            ) from exc

        confirmed = services.inventory.latest_scope(audit_id)
        if confirmed is None:
            raise HTTPException(
                status_code=409,
                detail={"code": "snmp_scope_required", "message": "Run and confirm active discovery scope before SNMP topology enrichment"},
            )
        if confirmed.interface != audit.interface:
            raise HTTPException(
                status_code=409,
                detail={"code": "snmp_scope_interface_mismatch", "message": "Latest confirmed scope belongs to another interface"},
            )
        if not _in_scope(target, confirmed.targets):
            raise HTTPException(
                status_code=422,
                detail={"code": "snmp_target_out_of_scope", "message": "SNMP target is outside the confirmed active scope"},
            )

        credentials = payload.credentials()
        credential_ref = spool.put(credentials)
        job = services.jobs.create_job(
            audit_id=audit.id,
            job_type="snmp_topology",
            target=target,
            parameters={
                "target": target,
                "interface": audit.interface,
                "confirmed_scope_id": confirmed.id,
                "credential_ref": credential_ref,
                "credential_profile": sanitize_credential_profile(credentials),
            },
            priority=payload.priority,
            resource_key=f"interface:{audit.interface}",
            resource_group="active_discovery",
            resource_limit=services.settings.max_active_discovery_jobs,
        )
    except EntityNotFound as exc:
        if credential_ref:
            spool.delete(credential_ref)
        raise not_found(exc) from exc
    except InvalidTransition as exc:
        if credential_ref:
            spool.delete(credential_ref)
        raise invalid_transition_http(exc) from exc
    except Exception:
        if credential_ref:
            try:
                spool.delete(credential_ref)
            except Exception:
                pass
        raise

    return JobAcceptedResponse(
        audit_id=audit.id,
        job_id=job.id,
        status=job.status,
        status_url=f"/api/v1/jobs/{job.id}",
    )


def _in_scope(address: str, targets: list[str]) -> bool:
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
