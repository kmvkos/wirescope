"""Shared helpers for in-process passive protocol sensors."""

from collections.abc import Callable
from typing import Any

from engine.passive_models import (
    EvidenceReference,
    Observation,
    ObservationMetadata,
    PacketDataset,
    PacketRecord,
    PipelineError,
    SensorResult,
    SensorStatus,
)


Sensor = Callable[[PacketDataset], SensorResult]


def observation(
    sensor: str,
    kind: str,
    packet: PacketRecord,
    data: dict[str, Any],
    *,
    protocol: str | None = None,
) -> Observation:
    return Observation(
        kind=kind,
        metadata=ObservationMetadata(
            sensor=sensor,
            timestamp=packet.timestamp,
            source_mac=packet.source_mac,
            destination_mac=packet.destination_mac,
            source_ip=packet.source_ip,
            destination_ip=packet.destination_ip,
            protocol=protocol or (packet.protocols[-1] if packet.protocols else None),
            evidence=EvidenceReference(
                reference=f"packet:{packet.frame_number}",
                frame_number=packet.frame_number,
            ),
        ),
        data=data,
    )


def sensor_result(
    name: str,
    observations: list[Observation],
    *,
    hits: int | None = None,
    summary: dict[str, Any] | None = None,
    warnings: list[str] | None = None,
    errors: list[PipelineError] | None = None,
) -> SensorResult:
    sensor_errors = list(errors or [])
    if sensor_errors and observations:
        status = SensorStatus.PARTIAL
    elif sensor_errors:
        status = SensorStatus.ERROR
    elif observations:
        status = SensorStatus.DETECTED
    else:
        status = SensorStatus.ABSENT

    return SensorResult(
        name=name,
        status=status,
        hits=len(observations) if hits is None else hits,
        observations=observations,
        summary=summary or {},
        warnings=warnings or [],
        errors=sensor_errors,
    )


def dataset_errors(dataset: PacketDataset) -> list[PipelineError]:
    return [error.model_copy() for error in dataset.errors]


def split_values(values: list[str]) -> list[str]:
    items: list[str] = []
    for value in values:
        for item in value.split(","):
            normalized = item.strip()
            if normalized and normalized not in items:
                items.append(normalized)
    return items


def first_value(packet: PacketRecord, *aliases: str) -> str | None:
    value = packet.first(*aliases)
    return value.strip() if value and value.strip() else None


def integer_value(packet: PacketRecord, *aliases: str) -> int | None:
    value = first_value(packet, *aliases)
    if value is None:
        return None
    try:
        return int(value, 0)
    except ValueError:
        digits = "".join(character for character in value if character.isdigit())
        return int(digits) if digits else None


def boolean_value(packet: PacketRecord, *aliases: str) -> bool | None:
    value = first_value(packet, *aliases)
    if value is None:
        return None
    normalized = value.lower()
    if normalized in {"1", "true", "yes", "set"}:
        return True
    if normalized in {"0", "false", "no", "not set"}:
        return False
    return None


def unique_dicts(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for item in items:
        if item not in result:
            result.append(item)
    return result
