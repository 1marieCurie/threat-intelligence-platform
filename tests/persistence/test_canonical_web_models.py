from __future__ import annotations

from typing import (
    TypeAlias,
    cast,
)

from sqlalchemy import (
    CheckConstraint,
    Index,
    Table,
    UniqueConstraint,
)

from infrastructure.persistence.models.canonical_web import (
    CanonicalWebIndicatorModel,
    CanonicalWebIndicatorObservationModel,
)


CanonicalWebModel: TypeAlias = (
    type[CanonicalWebIndicatorModel]
    | type[CanonicalWebIndicatorObservationModel]
)


def _table(
    model: CanonicalWebModel,
) -> Table:
    """
    Retourne la Table SQLAlchemy associée au modèle déclaratif.

    SQLAlchemy expose statiquement __table__ comme un FromClause,
    alors que ces modèles fournissent réellement une Table.
    """
    return cast(
        Table,
        model.__table__,
    )


def _constraint_names(
    model: CanonicalWebModel,
) -> set[str]:
    return {
        cast(
            str,
            constraint.name,
        )
        for constraint
        in _table(model).constraints
        if constraint.name is not None
    }


def _check_constraint_names(
    model: CanonicalWebModel,
) -> set[str]:
    return {
        cast(
            str,
            constraint.name,
        )
        for constraint
        in _table(model).constraints
        if (
            isinstance(
                constraint,
                CheckConstraint,
            )
            and constraint.name is not None
        )
    }


def _index_names(
    model: CanonicalWebModel,
) -> set[str]:
    return {
        cast(
            str,
            index.name,
        )
        for index
        in _table(model).indexes
        if index.name is not None
    }


def _contains_logical_name(
    names: set[str],
    logical_name: str,
) -> bool:
    """
    Accepte le nom explicite ou le nom préfixé par la convention
    SQLAlchemy, par exemple :

        indicator_type_url

    ou :

        ck_canonical_web_indicator_indicator_type_url
    """
    return any(
        name == logical_name
        or name.endswith(
            f"_{logical_name}"
        )
        for name in names
    )


def test_canonical_web_indicator_table_metadata(
) -> None:
    table = _table(
        CanonicalWebIndicatorModel
    )

    assert table.schema == "canonical"

    assert table.name == (
        "canonical_web_indicator"
    )

    assert {
        column.name
        for column in table.columns
    } == {
        "id",
        "indicator_type",
        "canonical_value",
        "value_hash",
        "hostname",
        "canonicalization_version",
        "created_at",
        "updated_at",
    }

    assert not table.c[
        "id"
    ].nullable

    assert not table.c[
        "indicator_type"
    ].nullable

    assert not table.c[
        "canonical_value"
    ].nullable

    assert not table.c[
        "value_hash"
    ].nullable

    assert not table.c[
        "hostname"
    ].nullable

    assert not table.c[
        "canonicalization_version"
    ].nullable

    assert not table.c[
        "created_at"
    ].nullable

    assert not table.c[
        "updated_at"
    ].nullable

    constraints = _constraint_names(
        CanonicalWebIndicatorModel
    )

    assert (
        "canonical_web_indicator_"
        "version_value_hash"
        in constraints
    )

    assert _contains_logical_name(
        constraints,
        "indicator_type_url",
    )

    assert _contains_logical_name(
        constraints,
        (
            "canonicalization_"
            "version_positive"
        ),
    )

    assert _contains_logical_name(
        constraints,
        "value_hash_sha256",
    )

    assert _contains_logical_name(
        constraints,
        "canonical_value_length_valid",
    )

    assert _contains_logical_name(
        constraints,
        "hostname_length_valid",
    )

    assert _contains_logical_name(
        constraints,
        "timestamps_order",
    )

    indexes = _index_names(
        CanonicalWebIndicatorModel
    )

    assert (
        "ix_canonical_web_indicator_hostname"
        in indexes
    )

    assert (
        "ix_canonical_web_indicator_updated_at"
        in indexes
    )


def test_canonical_web_observation_table_metadata(
) -> None:
    table = _table(
        CanonicalWebIndicatorObservationModel
    )

    assert table.schema == "canonical"

    assert table.name == (
        "canonical_web_indicator_observation"
    )

    assert {
        column.name
        for column in table.columns
    } == {
        "id",
        "indicator_id",
        "source",
        "source_record_key",
        "normalized_record_id",
        "observed_at",
        "last_observed_at",
        "normalizer_version",
        "source_status",
        "is_active",
        "labels",
    }

    assert not table.c[
        "id"
    ].nullable

    assert not table.c[
        "indicator_id"
    ].nullable

    assert not table.c[
        "source"
    ].nullable

    assert not table.c[
        "source_record_key"
    ].nullable

    assert not table.c[
        "normalized_record_id"
    ].nullable

    assert not table.c[
        "observed_at"
    ].nullable

    assert not table.c[
        "last_observed_at"
    ].nullable

    assert not table.c[
        "normalizer_version"
    ].nullable

    assert not table.c[
        "labels"
    ].nullable

    foreign_keys = {
        foreign_key.target_fullname
        for foreign_key
        in table.foreign_keys
    }

    assert foreign_keys == {
        (
            "canonical."
            "canonical_web_indicator.id"
        )
    }

    constraints = _constraint_names(
        CanonicalWebIndicatorObservationModel
    )

    assert (
        "canonical_web_observation_"
        "source_record"
        in constraints
    )

    assert _contains_logical_name(
        constraints,
        "source_format_valid",
    )

    assert _contains_logical_name(
        constraints,
        "source_record_key_not_empty",
    )

    assert _contains_logical_name(
        constraints,
        "source_status_format_valid",
    )

    assert _contains_logical_name(
        constraints,
        "normalizer_version_length_valid",
    )

    assert _contains_logical_name(
        constraints,
        "observation_dates_order",
    )

    assert _contains_logical_name(
        constraints,
        "labels_array_bounded",
    )

    indexes = _index_names(
        CanonicalWebIndicatorObservationModel
    )

    assert (
        "ix_canonical_web_observation_"
        "indicator_id"
        in indexes
    )

    assert (
        "ix_canonical_web_observation_"
        "last_observed_at"
        in indexes
    )

    assert (
        "ix_canonical_web_observation_"
        "normalized_record_id"
        in indexes
    )


def test_identity_constraint_is_unique(
) -> None:
    table = _table(
        CanonicalWebIndicatorModel
    )

    identity_constraints = [
        constraint
        for constraint in table.constraints
        if (
            isinstance(
                constraint,
                UniqueConstraint,
            )
            and constraint.name
            == (
                "canonical_web_indicator_"
                "version_value_hash"
            )
        )
    ]

    assert len(
        identity_constraints
    ) == 1

    identity_constraint = (
        identity_constraints[0]
    )

    assert {
        column.name
        for column
        in identity_constraint.columns
    } == {
        "canonicalization_version",
        "value_hash",
    }


def test_models_define_bounded_checks(
) -> None:
    indicator_checks = (
        _check_constraint_names(
            CanonicalWebIndicatorModel
        )
    )

    observation_checks = (
        _check_constraint_names(
            CanonicalWebIndicatorObservationModel
        )
    )

    assert _contains_logical_name(
        indicator_checks,
        "canonical_value_length_valid",
    )

    assert _contains_logical_name(
        indicator_checks,
        "hostname_length_valid",
    )

    assert _contains_logical_name(
        indicator_checks,
        "value_hash_sha256",
    )

    assert _contains_logical_name(
        observation_checks,
        "labels_array_bounded",
    )

    assert _contains_logical_name(
        observation_checks,
        "normalizer_version_length_valid",
    )


def test_expected_indexes_are_not_unique(
) -> None:
    indicator_table = _table(
        CanonicalWebIndicatorModel
    )

    observation_table = _table(
        CanonicalWebIndicatorObservationModel
    )

    indexes: set[Index] = (
        set(
            indicator_table.indexes
        )
        | set(
            observation_table.indexes
        )
    )

    assert indexes

    assert all(
        not index.unique
        for index in indexes
    )