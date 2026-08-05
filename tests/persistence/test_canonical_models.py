from __future__ import annotations

from typing import Any, cast

from sqlalchemy import (
    CheckConstraint,
    Column,
    String,
    Table,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import (
    DOUBLE_PRECISION,
)

from infrastructure.persistence.models import (
    Base,
    CanonicalVulnerabilityEvidenceModel,
    CanonicalVulnerabilityIdentifierModel,
    CanonicalVulnerabilityModel,
    CanonicalVulnerabilityWeaknessModel,
)


def _table(
    model: type[Any],
) -> Table:
    """
    Return the concrete SQLAlchemy table mapped by a model.

    SQLAlchemy exposes __table__ using the broader FromClause
    type. Declarative models used here are backed by Table.
    """
    return cast(
        Table,
        model.__table__,
    )


def _column(
    model: type[Any],
    column_name: str,
) -> Column[Any]:
    """
    Return one mapped SQLAlchemy column with a concrete type.
    """
    table = _table(model)

    return cast(
        Column[Any],
        table.c[column_name],
    )


def _default_argument(
    default: object | None,
    *,
    default_name: str,
) -> object:
    """
    Extract a SQLAlchemy default argument safely.

    SQLAlchemy types column defaults broadly as DefaultGenerator
    or FetchedValue, although concrete defaults expose `arg`.
    Keeping this dynamic access inside one helper prevents
    scattered static-analysis suppressions.
    """
    assert default is not None, (
        f"{default_name} must be configured"
    )

    assert hasattr(
        default,
        "arg",
    ), (
        f"{default_name} must expose an argument"
    )

    return getattr(
        default,
        "arg",
    )


def _unique_column_sets(
    model: type[Any],
) -> set[tuple[str, ...]]:
    """
    Return column groups covered by unique constraints.
    """
    table = _table(model)

    return {
        tuple(
            column.name
            for column in constraint.columns
        )
        for constraint in table.constraints
        if isinstance(
            constraint,
            UniqueConstraint,
        )
    }


def _check_expressions(
    model: type[Any],
) -> set[str]:
    """
    Return SQL expressions declared by check constraints.
    """
    table = _table(model)

    return {
        str(
            constraint.sqltext
        )
        for constraint in table.constraints
        if isinstance(
            constraint,
            CheckConstraint,
        )
    }


def _string_column_length(
    model: type[Any],
    column_name: str,
) -> int | None:
    """
    Return the configured length of a String column.
    """
    column = _column(
        model,
        column_name,
    )

    column_type = column.type

    assert isinstance(
        column_type,
        String,
    ), (
        f"{column_name} must use SQLAlchemy String"
    )

    return column_type.length


# ============================================================
# Schema and metadata
# ============================================================


def test_canonical_tables_use_expected_schema(
) -> None:
    assert (
        _table(
            CanonicalVulnerabilityModel
        ).schema
        == "canonical"
    )

    assert (
        _table(
            CanonicalVulnerabilityIdentifierModel
        ).schema
        == "canonical"
    )
    
    assert (
        _table(
            CanonicalVulnerabilityWeaknessModel
        ).schema
        == "canonical"
    )

    assert (
        _table(
            CanonicalVulnerabilityEvidenceModel
        ).schema
        == "canonical"
    )


def test_canonical_tables_are_registered_in_metadata(
) -> None:
    expected_tables = {
        (
            "canonical."
            "canonical_vulnerability"
        ),
        (
            "canonical."
            "canonical_vulnerability_identifier"
        ),
        (
            "canonical."
            "canonical_vulnerability_evidence"
        ),
        (
            "canonical."
            "canonical_vulnerability_weakness"
        ),
    }

    assert expected_tables.issubset(
        Base.metadata.tables
    )


# ============================================================
# Canonical vulnerability
# ============================================================


def test_vulnerability_supports_provisional_status(
) -> None:
    expressions = _check_expressions(
        CanonicalVulnerabilityModel
    )

    assert any(
        "'provisional'"
        in expression
        for expression in expressions
    )


def test_vulnerability_defaults_to_provisional(
) -> None:
    column = _column(
        CanonicalVulnerabilityModel,
        "status",
    )

    client_default = _default_argument(
        column.default,
        default_name="status client default",
    )

    server_default = _default_argument(
        column.server_default,
        default_name="status server default",
    )

    assert client_default == "provisional"

    assert str(
        server_default
    ) == "'provisional'"


def test_vulnerability_defaults_correlation_version_to_one(
) -> None:
    column = _column(
        CanonicalVulnerabilityModel,
        "correlation_version",
    )

    client_default = _default_argument(
        column.default,
        default_name=(
            "correlation version client default"
        ),
    )

    server_default = _default_argument(
        column.server_default,
        default_name=(
            "correlation version server default"
        ),
    )

    assert client_default == 1

    assert str(
        server_default
    ) == "1"


def test_vulnerability_has_lifecycle_constraints(
) -> None:
    expressions = _check_expressions(
        CanonicalVulnerabilityModel
    )

    assert (
        "correlation_version > 0"
        in expressions
    )

    assert (
        "updated_at >= created_at"
        in expressions
    )

    assert any(
        "merged_into_id IS NOT NULL"
        in expression
        for expression in expressions
    )

    assert any(
        "merged_into_id IS NULL"
        in expression
        for expression in expressions
    )

    assert any(
        "merged_into_id <> id"
        in expression
        for expression in expressions
    )


def test_merge_target_prevents_target_deletion(
) -> None:
    column = _column(
        CanonicalVulnerabilityModel,
        "merged_into_id",
    )

    foreign_key = next(
        iter(
            column.foreign_keys
        )
    )

    assert foreign_key.target_fullname == (
        "canonical."
        "canonical_vulnerability.id"
    )

    assert foreign_key.ondelete == "RESTRICT"


def test_vulnerability_has_expected_indexes(
) -> None:
    table = _table(
        CanonicalVulnerabilityModel
    )

    index_names = {
        index.name
        for index in table.indexes
    }

    assert (
        "ix_canonical_vulnerability_updated_at"
        in index_names
    )

    assert (
        "ix_canonical_vulnerability_merged_into_id"
        in index_names
    )


# ============================================================
# Canonical identifiers
# ============================================================


def test_identifier_has_global_unique_constraint(
) -> None:
    assert (
        "namespace",
        "value",
    ) in _unique_column_sets(
        CanonicalVulnerabilityIdentifierModel
    )


def test_identifier_has_namespace_and_format_constraints(
) -> None:
    expressions = _check_expressions(
        CanonicalVulnerabilityIdentifierModel
    )

    assert any(
        "namespace IN ('CVE', 'GHSA')"
        in expression
        for expression in expressions
    )

    assert any(
        "^CVE-[0-9]{4}-[0-9]{4,19}$"
        in expression
        for expression in expressions
    )

    assert any(
        (
            "^GHSA-[A-Z0-9]{4}-"
            "[A-Z0-9]{4}-"
            "[A-Z0-9]{4}$"
        )
        in expression
        for expression in expressions
    )


def test_identifier_has_partial_primary_index(
) -> None:
    table = _table(
        CanonicalVulnerabilityIdentifierModel
    )

    index = next(
        index
        for index in table.indexes
        if index.name
        == (
            "uq_canonical_vulnerability_"
            "primary_identifier"
        )
    )

    assert index.unique is True

    assert tuple(
        column.name
        for column in index.columns
    ) == (
        "vulnerability_id",
    )

    where_clause = (
        index
        .dialect_options[
            "postgresql"
        ][
            "where"
        ]
    )

    assert where_clause is not None

    assert str(
        where_clause
    ) == "is_primary IS TRUE"


def test_identifier_foreign_key_cascades(
) -> None:
    column = _column(
        CanonicalVulnerabilityIdentifierModel,
        "vulnerability_id",
    )

    foreign_key = next(
        iter(
            column.foreign_keys
        )
    )

    assert foreign_key.target_fullname == (
        "canonical."
        "canonical_vulnerability.id"
    )

    assert foreign_key.ondelete == "CASCADE"


def test_identifier_primary_flag_defaults_to_false(
) -> None:
    column = _column(
        CanonicalVulnerabilityIdentifierModel,
        "is_primary",
    )

    client_default = _default_argument(
        column.default,
        default_name=(
            "primary flag client default"
        ),
    )

    server_default = _default_argument(
        column.server_default,
        default_name=(
            "primary flag server default"
        ),
    )

    assert client_default is False

    assert str(
        server_default
    ) == "false"


def test_identifier_columns_are_bounded(
) -> None:
    assert (
        _string_column_length(
            CanonicalVulnerabilityIdentifierModel,
            "namespace",
        )
        == 16
    )

    assert (
        _string_column_length(
            CanonicalVulnerabilityIdentifierModel,
            "value",
        )
        == 64
    )


# ============================================================
# Canonical evidences
# ============================================================


def test_evidence_has_global_source_record_constraint(
) -> None:
    assert (
        "source",
        "source_record_key",
    ) in _unique_column_sets(
        CanonicalVulnerabilityEvidenceModel
    )


def test_evidence_foreign_key_cascades(
) -> None:
    column = _column(
        CanonicalVulnerabilityEvidenceModel,
        "vulnerability_id",
    )

    foreign_key = next(
        iter(
            column.foreign_keys
        )
    )

    assert foreign_key.target_fullname == (
        "canonical."
        "canonical_vulnerability.id"
    )

    assert foreign_key.ondelete == "CASCADE"


def test_evidence_tracks_first_and_last_observation(
) -> None:
    observed_at = _column(
        CanonicalVulnerabilityEvidenceModel,
        "observed_at",
    )

    last_observed_at = _column(
        CanonicalVulnerabilityEvidenceModel,
        "last_observed_at",
    )

    assert observed_at.nullable is False
    assert last_observed_at.nullable is False

    expressions = _check_expressions(
        CanonicalVulnerabilityEvidenceModel
    )

    assert (
        "last_observed_at >= observed_at"
        in expressions
    )


def test_evidence_has_classification_constraints(
) -> None:
    expressions = _check_expressions(
        CanonicalVulnerabilityEvidenceModel
    )

    assert any(
        "source ~ '^[a-z][a-z0-9_]*$'"
        in expression
        for expression in expressions
    )

    assert any(
        (
            "evidence_type "
            "~ '^[a-z][a-z0-9_]*$'"
        )
        in expression
        for expression in expressions
    )

    assert any(
        (
            "correlation_rule "
            "~ '^[a-z][a-z0-9_]*$'"
        )
        in expression
        for expression in expressions
    )


def test_evidence_has_confidence_constraint(
) -> None:
    expressions = _check_expressions(
        CanonicalVulnerabilityEvidenceModel
    )

    assert any(
        (
            "correlation_confidence >= 0"
            in expression
            and
            "correlation_confidence <= 1"
            in expression
        )
        for expression in expressions
    )


def test_evidence_has_hash_constraint(
) -> None:
    expressions = _check_expressions(
        CanonicalVulnerabilityEvidenceModel
    )

    assert any(
        "^[a-f0-9]{64}$"
        in expression
        for expression in expressions
    )


def test_evidence_rejects_blank_record_references(
) -> None:
    expressions = _check_expressions(
        CanonicalVulnerabilityEvidenceModel
    )

    assert (
        "btrim(source_record_key) <> ''"
        in expressions
    )

    assert (
        "btrim(normalized_record_id) <> ''"
        in expressions
    )


def test_evidence_confidence_uses_double_precision(
) -> None:
    column = _column(
        CanonicalVulnerabilityEvidenceModel,
        "correlation_confidence",
    )

    assert isinstance(
        column.type,
        DOUBLE_PRECISION,
    )


def test_evidence_confidence_defaults_to_one(
) -> None:
    column = _column(
        CanonicalVulnerabilityEvidenceModel,
        "correlation_confidence",
    )

    client_default = _default_argument(
        column.default,
        default_name=(
            "correlation confidence client default"
        ),
    )

    server_default = _default_argument(
        column.server_default,
        default_name=(
            "correlation confidence server default"
        ),
    )

    assert client_default == 1.0

    assert str(
        server_default
    ) == "1"


def test_evidence_columns_are_bounded(
) -> None:
    expected_lengths = {
        "source": 50,
        "source_record_key": 255,
        "normalized_record_id": 255,
        "evidence_type": 64,
        "correlation_rule": 64,
        "record_hash": 64,
    }

    for (
        column_name,
        expected_length,
    ) in expected_lengths.items():
        assert (
            _string_column_length(
                CanonicalVulnerabilityEvidenceModel,
                column_name,
            )
            == expected_length
        )


def test_evidence_has_expected_indexes(
) -> None:
    table = _table(
        CanonicalVulnerabilityEvidenceModel
    )

    index_names = {
        index.name
        for index in table.indexes
    }

    assert (
        "ix_canonical_evidence_vulnerability_id"
        in index_names
    )

    assert (
        "ix_canonical_evidence_last_observed_at"
        in index_names
    )
    
# ============================================================
# Canonical vulnerability weaknesses
# ============================================================


def test_weakness_has_global_provenance_constraint(
) -> None:
    assert (
        "source",
        "source_record_key",
        "cwe_id",
    ) in _unique_column_sets(
        CanonicalVulnerabilityWeaknessModel
    )


def test_weakness_vulnerability_foreign_key_cascades(
) -> None:
    column = _column(
        CanonicalVulnerabilityWeaknessModel,
        "vulnerability_id",
    )

    foreign_key = next(
        iter(
            column.foreign_keys
        )
    )

    assert foreign_key.target_fullname == (
        "canonical."
        "canonical_vulnerability.id"
    )

    assert foreign_key.ondelete == "CASCADE"


def test_weakness_cwe_foreign_key_restricts_deletion(
) -> None:
    column = _column(
        CanonicalVulnerabilityWeaknessModel,
        "cwe_id",
    )

    foreign_key = next(
        iter(
            column.foreign_keys
        )
    )

    assert foreign_key.target_fullname == (
        "normalized.cwe_weakness.cwe_id"
    )

    assert foreign_key.ondelete == "RESTRICT"


def test_weakness_has_validation_constraints(
) -> None:
    expressions = _check_expressions(
        CanonicalVulnerabilityWeaknessModel
    )

    assert any(
        "^CWE-[1-9][0-9]*$"
        in expression
        for expression in expressions
    )

    assert any(
        "source ~ '^[a-z][a-z0-9_]*$'"
        in expression
        for expression in expressions
    )

    assert (
        "btrim(source_record_key) <> ''"
        in expressions
    )

    assert (
        "btrim(normalized_record_id) <> ''"
        in expressions
    )

    assert (
        "last_observed_at >= observed_at"
        in expressions
    )


def test_weakness_observation_columns_are_required(
) -> None:
    observed_at = _column(
        CanonicalVulnerabilityWeaknessModel,
        "observed_at",
    )

    last_observed_at = _column(
        CanonicalVulnerabilityWeaknessModel,
        "last_observed_at",
    )

    assert observed_at.nullable is False
    assert last_observed_at.nullable is False


def test_weakness_columns_are_bounded(
) -> None:
    expected_lengths = {
        "cwe_id": 32,
        "source": 50,
        "source_record_key": 255,
        "normalized_record_id": 255,
    }

    for (
        column_name,
        expected_length,
    ) in expected_lengths.items():
        assert (
            _string_column_length(
                CanonicalVulnerabilityWeaknessModel,
                column_name,
            )
            == expected_length
        )


def test_weakness_has_expected_indexes(
) -> None:
    table = _table(
        CanonicalVulnerabilityWeaknessModel
    )

    index_names = {
        index.name
        for index in table.indexes
    }

    assert (
        "ix_canonical_weakness_vulnerability_id"
        in index_names
    )

    assert (
        "ix_canonical_weakness_cwe_id"
        in index_names
    )

    assert (
        "ix_canonical_weakness_last_observed_at"
        in index_names
    )