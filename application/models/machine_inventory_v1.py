from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import ClassVar, TypeAlias
from uuid import UUID


class InventoryValidationError(ValueError):
    pass


@dataclass(
    frozen=True,
    slots=True,
)
class InventoryAgentV1:
    name: str
    version: str


@dataclass(
    frozen=True,
    slots=True,
)
class InventoryMachineV1:
    machine_uid: UUID
    hostname: str
    os_name: str
    os_version: str
    architecture: str


@dataclass(
    frozen=True,
    slots=True,
)
class InventoryApplicationComponentV1:
    component_type: str
    name: str
    version: str | None
    vendor: str | None
    external_id: str
    detected_by: str


@dataclass(
    frozen=True,
    slots=True,
)
class InventoryPackageComponentV1:
    component_type: str
    ecosystem: str
    package_name: str
    version: str
    scope: str
    detected_by: str


InventoryComponentV1: TypeAlias = (
    InventoryApplicationComponentV1
    | InventoryPackageComponentV1
)


@dataclass(
    frozen=True,
    slots=True,
)
class MachineInventoryV1:
    schema_version: str
    inventory_id: UUID
    collected_at: datetime
    agent: InventoryAgentV1
    machine: InventoryMachineV1
    components: tuple[
        InventoryComponentV1,
        ...,
    ]

    SCHEMA_VERSION: ClassVar[str] = (
        "inventory/v1"
    )

    @classmethod
    def from_mapping(
        cls,
        payload: Mapping[str, object],
    ) -> MachineInventoryV1:
        root = _require_mapping(
            payload,
            field_path="$",
        )
        _assert_exact_keys(
            root,
            expected={
                "schema_version",
                "inventory_id",
                "collected_at",
                "agent",
                "machine",
                "components",
            },
            field_path="$",
        )

        schema_version = _require_string(
            root["schema_version"],
            field_path="$.schema_version",
        ).lower()

        if schema_version != cls.SCHEMA_VERSION:
            raise InventoryValidationError(
                "$.schema_version must be exactly "
                f"'{cls.SCHEMA_VERSION}'"
            )

        inventory_id = _require_uuid(
            root["inventory_id"],
            field_path="$.inventory_id",
        )
        collected_at = _require_datetime(
            root["collected_at"],
            field_path="$.collected_at",
        )
        agent = _parse_agent(
            root["agent"]
        )
        machine = _parse_machine(
            root["machine"]
        )
        components = _parse_components(
            root["components"]
        )

        return cls(
            schema_version=schema_version,
            inventory_id=inventory_id,
            collected_at=collected_at,
            agent=agent,
            machine=machine,
            components=components,
        )


def _parse_agent(
    value: object,
) -> InventoryAgentV1:
    payload = _require_mapping(
        value,
        field_path="$.agent",
    )
    _assert_exact_keys(
        payload,
        expected={
            "name",
            "version",
        },
        field_path="$.agent",
    )

    return InventoryAgentV1(
        name=_require_string(
            payload["name"],
            field_path="$.agent.name",
        ),
        version=_require_string(
            payload["version"],
            field_path="$.agent.version",
        ),
    )


def _parse_machine(
    value: object,
) -> InventoryMachineV1:
    payload = _require_mapping(
        value,
        field_path="$.machine",
    )
    _assert_exact_keys(
        payload,
        expected={
            "machine_uid",
            "hostname",
            "os_name",
            "os_version",
            "architecture",
        },
        field_path="$.machine",
    )

    return InventoryMachineV1(
        machine_uid=_require_uuid(
            payload["machine_uid"],
            field_path="$.machine.machine_uid",
        ),
        hostname=_require_string(
            payload["hostname"],
            field_path="$.machine.hostname",
        ),
        os_name=_require_string(
            payload["os_name"],
            field_path="$.machine.os_name",
        ),
        os_version=_require_string(
            payload["os_version"],
            field_path="$.machine.os_version",
        ),
        architecture=_require_string(
            payload["architecture"],
            field_path="$.machine.architecture",
        ).lower(),
    )


def _parse_components(
    value: object,
) -> tuple[
    InventoryComponentV1,
    ...,
]:
    if (
        isinstance(value, (str, bytes))
        or not isinstance(value, Sequence)
    ):
        raise InventoryValidationError(
            "$.components must be an array"
        )

    components: list[
        InventoryComponentV1
    ] = []

    for index, raw_component in enumerate(value):
        field_path = f"$.components[{index}]"

        payload = _require_mapping(
            raw_component,
            field_path=field_path,
        )

        if "component_type" not in payload:
            raise InventoryValidationError(
                f"{field_path}.component_type is required"
            )

        component_type = _require_string(
            payload["component_type"],
            field_path=(
                f"{field_path}.component_type"
            ),
        ).lower()

        if component_type == "application":
            components.append(
                _parse_application_component(
                    payload,
                    field_path=field_path,
                )
            )
            continue

        if component_type == "package":
            components.append(
                _parse_package_component(
                    payload,
                    field_path=field_path,
                )
            )
            continue

        raise InventoryValidationError(
            f"{field_path}.component_type must be "
            "'application' or 'package'"
        )

    return tuple(components)


def _parse_application_component(
    payload: Mapping[str, object],
    *,
    field_path: str,
) -> InventoryApplicationComponentV1:
    _assert_exact_keys(
        payload,
        expected={
            "component_type",
            "name",
            "version",
            "vendor",
            "external_id",
            "detected_by",
        },
        field_path=field_path,
    )

    detected_by = _require_string(
        payload["detected_by"],
        field_path=f"{field_path}.detected_by",
    ).lower()

    if detected_by != "windows_registry_uninstall":
        raise InventoryValidationError(
            f"{field_path}.detected_by must be "
            "'windows_registry_uninstall' for applications"
        )

    return InventoryApplicationComponentV1(
        component_type="application",
        name=_require_string(
            payload["name"],
            field_path=f"{field_path}.name",
        ),
        version=_optional_string(
            payload["version"],
            field_path=f"{field_path}.version",
        ),
        vendor=_optional_string(
            payload["vendor"],
            field_path=f"{field_path}.vendor",
        ),
        external_id=_require_string(
            payload["external_id"],
            field_path=f"{field_path}.external_id",
        ),
        detected_by=detected_by,
    )


def _parse_package_component(
    payload: Mapping[str, object],
    *,
    field_path: str,
) -> InventoryPackageComponentV1:
    _assert_exact_keys(
        payload,
        expected={
            "component_type",
            "ecosystem",
            "package_name",
            "version",
            "scope",
            "detected_by",
        },
        field_path=field_path,
    )

    ecosystem = _require_string(
        payload["ecosystem"],
        field_path=f"{field_path}.ecosystem",
    ).lower()

    if ecosystem not in {
        "pypi",
        "npm",
    }:
        raise InventoryValidationError(
            f"{field_path}.ecosystem must be 'pypi' or 'npm'"
        )

    scope = _require_string(
        payload["scope"],
        field_path=f"{field_path}.scope",
    ).lower()

    if scope != "global":
        raise InventoryValidationError(
            f"{field_path}.scope must be "
            "'global' in inventory/v1"
        )

    detected_by = _require_string(
        payload["detected_by"],
        field_path=f"{field_path}.detected_by",
    ).lower()

    expected_detector = (
        "pip_global"
        if ecosystem == "pypi"
        else "npm_global"
    )

    if detected_by != expected_detector:
        raise InventoryValidationError(
            f"{field_path}.detected_by must be "
            f"'{expected_detector}' for ecosystem "
            f"'{ecosystem}'"
        )

    return InventoryPackageComponentV1(
        component_type="package",
        ecosystem=ecosystem,
        package_name=_require_string(
            payload["package_name"],
            field_path=f"{field_path}.package_name",
        ),
        version=_require_string(
            payload["version"],
            field_path=f"{field_path}.version",
        ),
        scope=scope,
        detected_by=detected_by,
    )


def _require_mapping(
    value: object,
    *,
    field_path: str,
) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise InventoryValidationError(
            f"{field_path} must be an object"
        )

    for key in value:
        if not isinstance(key, str):
            raise InventoryValidationError(
                f"{field_path} keys must be strings"
            )

    return value


def _assert_exact_keys(
    payload: Mapping[str, object],
    *,
    expected: set[str],
    field_path: str,
) -> None:
    actual = set(payload.keys())
    missing = sorted(expected - actual)
    extra = sorted(actual - expected)

    if missing:
        raise InventoryValidationError(
            f"{field_path} is missing required fields: "
            + ", ".join(missing)
        )

    if extra:
        raise InventoryValidationError(
            f"{field_path} contains unsupported fields: "
            + ", ".join(extra)
        )


def _require_string(
    value: object,
    *,
    field_path: str,
) -> str:
    if not isinstance(value, str):
        raise InventoryValidationError(
            f"{field_path} must be a string"
        )

    normalized_value = " ".join(
        value.strip().split()
    )

    if not normalized_value:
        raise InventoryValidationError(
            f"{field_path} must not be empty"
        )

    return normalized_value


def _optional_string(
    value: object,
    *,
    field_path: str,
) -> str | None:
    if value is None:
        return None

    return _require_string(
        value,
        field_path=field_path,
    )


def _require_uuid(
    value: object,
    *,
    field_path: str,
) -> UUID:
    try:
        parsed = (
            value
            if isinstance(value, UUID)
            else UUID(
                _require_string(
                    value,
                    field_path=field_path,
                )
            )
        )
    except (
        ValueError,
        AttributeError,
    ) as error:
        raise InventoryValidationError(
            f"{field_path} must be a valid UUID"
        ) from error

    if parsed.int == 0:
        raise InventoryValidationError(
            f"{field_path} must not be the nil UUID"
        )

    return parsed


def _require_datetime(
    value: object,
    *,
    field_path: str,
) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    else:
        raw_value = _require_string(
            value,
            field_path=field_path,
        )

        if raw_value.endswith("Z"):
            raw_value = (
                raw_value[:-1]
                + "+00:00"
            )

        try:
            parsed = datetime.fromisoformat(
                raw_value
            )
        except ValueError as error:
            raise InventoryValidationError(
                f"{field_path} must be "
                "an ISO 8601 datetime"
            ) from error

    if (
        parsed.tzinfo is None
        or parsed.utcoffset() is None
    ):
        raise InventoryValidationError(
            f"{field_path} must include a timezone"
        )

    return parsed.astimezone(
        timezone.utc
    )