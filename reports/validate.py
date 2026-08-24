"""Published JSON Schema loader and a small validator for tests."""

from functools import lru_cache
import json
from pathlib import Path
from typing import Any


SCHEMA_FILENAME = "audit-report-v1.json"


def schema_path() -> Path:
    return Path(__file__).resolve().parent / "schema" / SCHEMA_FILENAME


@lru_cache(maxsize=1)
def load_published_schema() -> dict[str, Any]:
    return json.loads(schema_path().read_text(encoding="utf-8"))


class SchemaValidationError(ValueError):
    pass


def validate_report_document(document: Any) -> None:
    validate_instance(document, load_published_schema())


def validate_instance(
    instance: Any,
    schema: dict[str, Any],
    *,
    pointer: str = "$",
) -> None:
    expected_type = schema.get("type")
    if isinstance(expected_type, list):
        errors: list[str] = []
        for option in expected_type:
            try:
                validate_instance(
                    instance,
                    {**schema, "type": option},
                    pointer=pointer,
                )
                return
            except SchemaValidationError as exc:
                errors.append(str(exc))
        if instance is None and "null" in expected_type:
            return
        raise SchemaValidationError(
            f"{pointer} did not match any allowed type"
        )
    if schema.get("anyOf"):
        errors = []
        for option in schema["anyOf"]:
            try:
                validate_instance(instance, option, pointer=pointer)
                return
            except SchemaValidationError as exc:
                errors.append(str(exc))
        raise SchemaValidationError(f"{pointer} did not match any anyOf branch")
    if expected_type == "object":
        if not isinstance(instance, dict):
            raise SchemaValidationError(f"{pointer} must be an object")
        required = schema.get("required") or []
        for name in required:
            if name not in instance:
                raise SchemaValidationError(f"{pointer}.{name} is required")
        properties = schema.get("properties") or {}
        additional = schema.get("additionalProperties", True)
        for name, value in instance.items():
            child = properties.get(name)
            if child is not None:
                validate_instance(value, child, pointer=f"{pointer}.{name}")
            elif additional is False:
                raise SchemaValidationError(
                    f"{pointer}.{name} is not permitted"
                )
            elif isinstance(additional, dict):
                validate_instance(
                    value,
                    additional,
                    pointer=f"{pointer}.{name}",
                )
        return
    if expected_type == "array":
        if not isinstance(instance, list):
            raise SchemaValidationError(f"{pointer} must be an array")
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for index, value in enumerate(instance):
                validate_instance(
                    value,
                    item_schema,
                    pointer=f"{pointer}[{index}]",
                )
        return
    if expected_type == "string":
        if not isinstance(instance, str):
            raise SchemaValidationError(f"{pointer} must be a string")
        min_length = schema.get("minLength")
        if min_length is not None and len(instance) < min_length:
            raise SchemaValidationError(
                f"{pointer} is shorter than {min_length}"
            )
        enum = schema.get("enum")
        if enum is not None and instance not in enum:
            raise SchemaValidationError(f"{pointer} is not an allowed value")
        const = schema.get("const")
        if const is not None and instance != const:
            raise SchemaValidationError(f"{pointer} must equal {const!r}")
        return
    if expected_type == "integer":
        if not isinstance(instance, int) or isinstance(instance, bool):
            raise SchemaValidationError(f"{pointer} must be an integer")
        const = schema.get("const")
        if const is not None and instance != const:
            raise SchemaValidationError(f"{pointer} must equal {const!r}")
        minimum = schema.get("minimum")
        if minimum is not None and instance < minimum:
            raise SchemaValidationError(f"{pointer} is below {minimum}")
        return
    if expected_type == "number":
        if not isinstance(instance, (int, float)) or isinstance(instance, bool):
            raise SchemaValidationError(f"{pointer} must be a number")
        return
    if expected_type == "boolean":
        if not isinstance(instance, bool):
            raise SchemaValidationError(f"{pointer} must be a boolean")
        const = schema.get("const")
        if const is not None and instance != const:
            raise SchemaValidationError(f"{pointer} must equal {const!r}")
        return
    if expected_type == "null":
        if instance is not None:
            raise SchemaValidationError(f"{pointer} must be null")
        return
    if "const" in schema and instance != schema["const"]:
        raise SchemaValidationError(
            f"{pointer} must equal {schema['const']!r}"
        )
