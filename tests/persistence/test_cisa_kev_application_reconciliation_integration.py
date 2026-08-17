from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from datetime import (
    date,
    datetime,
    timedelta,
    timezone,
)
from uuid import (
    UUID,
    uuid4,
)

import os
from pathlib import Path

from dotenv import load_dotenv
from sqlalchemy import create_engine

import pytest
from sqlalchemy import (
    create_engine,
    delete,
    event,
    select,
    text,
)
from sqlalchemy.engine import (
    Connection,
)
from sqlalchemy.orm import (
    Session,
    SessionTransaction,
    sessionmaker,
)
from application.services.cisa_kev_application_matcher import (
    CisaKevApplicationMatcher,
)
from application.services.reconcile_cisa_kev_application_exposures_service import (
    ReconcileCisaKevApplicationExposuresService,
)
from domain.software_component import (
    SoftwareComponent,
)
from infrastructure.persistence.models.assets import (
    MachineModel,
    OrganizationModel,
    SoftwareComponentModel,
    VulnerabilityExposureModel,
)
from infrastructure.persistence.models.canonical import (
    CanonicalVulnerabilityEvidenceModel,
    CanonicalVulnerabilityIdentifierModel,
    CanonicalVulnerabilityModel,
)
from infrastructure.persistence.models.normalized import (
    CisaKevVulnerabilityModel,
)
from infrastructure.persistence.models.ops import (
    IngestionRunModel,
    SourceModel,
)
from infrastructure.persistence.models.raw import (
    IngestionRunPayloadModel,
    SourcePayloadModel,
)
from infrastructure.persistence.sqlalchemy.vulnerability_exposure_unit_of_work import (
    SqlAlchemyVulnerabilityExposureUnitOfWork,
)

PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parents[2]
)

load_dotenv(
    dotenv_path=(
        PROJECT_ROOT / ".env"
    ),
    override=False,
)

pytestmark = pytest.mark.integration


T1 = datetime(
    2026,
    8,
    17,
    14,
    0,
    tzinfo=timezone.utc,
)

T2 = T1 + timedelta(
    hours=1,
)

class OwnerSession(Session):
    """
    Session réservée aux tests d'intégration nécessitant
    le rôle PostgreSQL threat_intel_owner.
    """
@event.listens_for(
    OwnerSession,
    "after_begin",
)
def _activate_owner_role(
    session: Session,
    transaction: SessionTransaction,
    connection: Connection,
) -> None:
    del session
    del transaction

    connection.execute(
        text(
            "SET LOCAL ROLE "
            "threat_intel_owner"
        )
    )
    

@pytest.fixture
def owner_session_factory(
) -> Iterator[
    sessionmaker[Session]
]:
    database_url = os.environ.get(
        "MIGRATION_DATABASE_URL"
    )

    if not database_url:
        raise RuntimeError(
            "MIGRATION_DATABASE_URL "
            "is not defined"
        )

    engine = create_engine(
        database_url,
        pool_pre_ping=True,
        future=True,
    )

    factory = sessionmaker(
        bind=engine,
        class_=OwnerSession,
        autoflush=False,
        expire_on_commit=False,
    )

    try:
        yield factory # pyright: ignore[reportReturnType]
    finally:
        engine.dispose()


@dataclass(
    frozen=True,
    slots=True,
)
class Seed:
    source_id: UUID
    source_code: str

    first_run_id: UUID
    raw_payload_id: UUID

    organization_id: UUID
    machine_id: UUID
    component_id: UUID

    canonical_vulnerability_id: UUID
    unrelated_canonical_id: UUID

    cve_id: str
    unrelated_cve_id: str



def _cve_pair() -> tuple[
    str,
    str,
]:
    base = (
        1_000_000
        + (
            uuid4().int
            % 7_000_000
        )
    )

    return (
        f"CVE-2026-{base}",
        f"CVE-2026-{base + 1}",
    )


def _seed(
    owner_session_factory: sessionmaker[
        Session
    ],
) -> Seed:
    source_id = uuid4()
    first_run_id = uuid4()
    raw_payload_id = uuid4()

    organization_id = uuid4()
    machine_id = uuid4()
    component_id = uuid4()

    canonical_id = uuid4()
    unrelated_canonical_id = uuid4()

    source_code = (
        "CISA_KEV_TEST_"
        + uuid4().hex[:12].upper()
    )

    (
        cve_id,
        unrelated_cve_id,
    ) = _cve_pair()

    with owner_session_factory() as session:
        
        # -------------------------------------------------
        # Source CISA isolée.
        # -------------------------------------------------
        session.add(
            SourceModel(
                id=source_id,
                code=source_code,
                name=(
                    "CISA KEV integration test"
                ),
                base_url=(
                    "https://example.invalid/"
                    "cisa-kev"
                ),
                enabled=True,
                created_at=T1,
            )
        )

        session.flush()

        # -------------------------------------------------
        # Snapshot CISA initial contenant la CVE.
        # -------------------------------------------------
        session.add(
            IngestionRunModel(
                id=first_run_id,
                source_id=source_id,
                status="completed",
                started_at=T1,
                finished_at=(
                    T1
                    + timedelta(
                        minutes=1,
                    )
                ),
                records_received=1,
                records_succeeded=1,
                records_failed=0,
                error_summary=None,
                connector_version=(
                    "integration-test"
                ),
                metadata_={
                    "pagination_complete": True,
                    "next_cursor": None,
                },
            )
        )

        session.flush()

        session.add(
            SourcePayloadModel(
                id=raw_payload_id,
                source_id=source_id,
                ingestion_run_id=(
                    first_run_id
                ),
                external_record_id=(
                    cve_id
                ),
                retrieved_at=T1,
                request_url=(
                    "https://example.invalid/"
                    "cisa-kev"
                ),
                http_status=200,
                payload={
                    "cveID": cve_id,
                    "vendorProject": (
                        "Example Corp"
                    ),
                    "product": (
                        "Example Browser"
                    ),
                },
                payload_hash=(
                    "a" * 64
                ),
                source_updated_at=None,
                processing_status=(
                    "processed"
                ),
                processing_started_at=None,
                processing_attempts=1,
                error_message=None,
            )
        )

        session.flush()

        session.add(
            IngestionRunPayloadModel(
                ingestion_run_id=(
                    first_run_id
                ),
                raw_payload_id=(
                    raw_payload_id
                ),
                observed_at=T1,
            )
        )

        session.add(
            CisaKevVulnerabilityModel(
                id=uuid4(),
                raw_payload_id=(
                    raw_payload_id
                ),
                cve_id=cve_id,
                vendor_project=(
                    "Example Corp"
                ),
                product=(
                    "Example Browser"
                ),
                vulnerability_name=(
                    "Integration test "
                    "vulnerability"
                ),
                date_added=date(
                    2026,
                    8,
                    17,
                ),
                short_description=(
                    "Integration test "
                    "description"
                ),
                required_action=(
                    "Apply vendor remediation"
                ),
                due_date=date(
                    2026,
                    9,
                    1,
                ),
                known_ransomware_campaign_use=(
                    "unknown"
                ),
                notes=None,
                cwes=[],
                normalizer_version=(
                    "1.0.0"
                ),
                normalized_at=T1,
            )
        )

        session.flush()

        # -------------------------------------------------
        # Organisation.
        # -------------------------------------------------
        session.add(
            OrganizationModel(
                id=organization_id,
                name=(
                    "CISA reconciliation "
                    "integration test"
                ),
                is_active=True,
                created_at=T1,
            )
        )

        session.flush()

        # -------------------------------------------------
        # Machine.
        # -------------------------------------------------
        session.add(
            MachineModel(
                id=machine_id,
                organization_id=(
                    organization_id
                ),
                machine_uid=uuid4(),
                hostname="test-host",
                os_name="Windows",
                os_version="11",
                architecture="x64",
                last_inventory_at=T1,
                created_at=T1,
                updated_at=T1,
            )
        )

        session.flush()

        # -------------------------------------------------
        # Application Windows.
        # -------------------------------------------------
        session.add(
            SoftwareComponentModel(
                id=component_id,
                machine_id=machine_id,
                component_type=(
                    "application"
                ),
                name="Example Browser",
                normalized_name=(
                    "example browser"
                ),
                version="1.5.0",
                vendor="Example Corp",
                normalized_vendor=(
                    "example corp"
                ),
                ecosystem=None,
                external_id=(
                    "registry:"
                    + uuid4().hex
                ),
                scope=None,
                detected_by=(
                    "windows_registry_uninstall"
                ),
                created_at=T1,
                updated_at=T1,
            )
        )

        session.flush()

        # -------------------------------------------------
        # Canonical correspondant à la CVE CISA.
        # -------------------------------------------------
        session.add(
            CanonicalVulnerabilityModel(
                id=canonical_id,
                status="active",
                correlation_version=1,
                merged_into_id=None,
                created_at=T1,
                updated_at=T1,
            )
        )

        session.flush()

        session.add(
            CanonicalVulnerabilityIdentifierModel(
                id=uuid4(),
                vulnerability_id=(
                    canonical_id
                ),
                namespace="CVE",
                value=cve_id,
                is_primary=True,
            )
        )

        session.add(
            CanonicalVulnerabilityEvidenceModel(
                id=uuid4(),
                vulnerability_id=(
                    canonical_id
                ),
                source=(
                    "cisa_kev_test"
                ),
                source_record_key=(
                    cve_id
                ),
                normalized_record_id=(
                    str(
                        uuid4()
                    )
                ),
                evidence_type=(
                    "known_exploited_vulnerability"
                ),
                correlation_rule=(
                    "exact_cve_identifier"
                ),
                observed_at=T1,
                last_observed_at=T1,
                source_published_at=None,
                source_modified_at=None,
                correlation_confidence=1.0,
                record_hash=None,
            )
        )

        session.flush()

        # -------------------------------------------------
        # Canonical indépendante.
        #
        # Sert à vérifier que la suppression CISA
        # ne supprime pas une autre exposition.
        # -------------------------------------------------
        session.add(
            CanonicalVulnerabilityModel(
                id=unrelated_canonical_id,
                status="active",
                correlation_version=1,
                merged_into_id=None,
                created_at=T1,
                updated_at=T1,
            )
        )

        session.flush()

        session.add(
            CanonicalVulnerabilityIdentifierModel(
                id=uuid4(),
                vulnerability_id=(
                    unrelated_canonical_id
                ),
                namespace="CVE",
                value=(
                    unrelated_cve_id
                ),
                is_primary=True,
            )
        )

        session.add(
            CanonicalVulnerabilityEvidenceModel(
                id=uuid4(),
                vulnerability_id=(
                    unrelated_canonical_id
                ),
                source=(
                    "integration_test"
                ),
                source_record_key=(
                    unrelated_cve_id
                ),
                normalized_record_id=(
                    str(
                        uuid4()
                    )
                ),
                evidence_type=(
                    "test_evidence"
                ),
                correlation_rule=(
                    "exact_identifier"
                ),
                observed_at=T1,
                last_observed_at=T1,
                source_published_at=None,
                source_modified_at=None,
                correlation_confidence=1.0,
                record_hash=None,
            )
        )

        session.flush()

        # -------------------------------------------------
        # Exposition indépendante.
        # -------------------------------------------------
        session.add(
            VulnerabilityExposureModel(
                id=uuid4(),
                software_component_id=(
                    component_id
                ),
                canonical_vulnerability_id=(
                    unrelated_canonical_id
                ),
                applicability_status=(
                    "confirmed"
                ),
                match_rule=(
                    "integration_unrelated_"
                    "confirmed_v1"
                ),
                match_version="1.5.0",
                severity=None,
                priority="HIGH",
                is_kev=False,
                first_detected_at=T1,
                last_evaluated_at=T1,
            )
        )

        session.commit()

    return Seed(
        source_id=source_id,
        source_code=source_code,
        first_run_id=first_run_id,
        raw_payload_id=raw_payload_id,
        organization_id=organization_id,
        machine_id=machine_id,
        component_id=component_id,
        canonical_vulnerability_id=(
            canonical_id
        ),
        unrelated_canonical_id=(
            unrelated_canonical_id
        ),
        cve_id=cve_id,
        unrelated_cve_id=(
            unrelated_cve_id
        ),
    )


def _load_domain_component(
    owner_session_factory: sessionmaker[
        Session
    ],
    component_id: UUID,
) -> SoftwareComponent:
    with owner_session_factory() as session:

        model = session.get(
            SoftwareComponentModel,
            component_id,
        )

        assert model is not None

        return SoftwareComponent(
            id=model.id,
            machine_id=model.machine_id,
            component_type=(
                model.component_type
            ),
            name=model.name,
            normalized_name=(
                model.normalized_name
            ),
            version=model.version,
            vendor=model.vendor,
            normalized_vendor=(
                model.normalized_vendor
            ),
            ecosystem=model.ecosystem,
            external_id=(
                model.external_id
            ),
            scope=model.scope,
            detected_by=(
                model.detected_by
            ),
            created_at=model.created_at,
            updated_at=model.updated_at,
        )


def _create_empty_second_snapshot(
    owner_session_factory: sessionmaker[
        Session
    ],
    *,
    source_id: UUID,
) -> UUID:
    second_run_id = uuid4()

    with owner_session_factory() as session:


        # -------------------------------------------------
        # Snapshot complet plus récent et vide.
        #
        # La CVE précédente n'est donc plus considérée
        # comme présente dans le snapshot KEV courant.
        # -------------------------------------------------
        session.add(
            IngestionRunModel(
                id=second_run_id,
                source_id=source_id,
                status="completed",
                started_at=T2,
                finished_at=(
                    T2
                    + timedelta(
                        minutes=1,
                    )
                ),
                records_received=0,
                records_succeeded=0,
                records_failed=0,
                error_summary=None,
                connector_version=(
                    "integration-test"
                ),
                metadata_={
                    "pagination_complete": True,
                    "next_cursor": None,
                },
            )
        )

        session.commit()

    return second_run_id


def _cleanup(
    owner_session_factory: sessionmaker[
        Session
    ],
    *,
    seed: Seed,
    second_run_id: UUID | None,
) -> None:
    with owner_session_factory() as session:

        # -------------------------------------------------
        # Exposure / assets.
        # -------------------------------------------------
        session.execute(
            delete(
                VulnerabilityExposureModel
            ).where(
                VulnerabilityExposureModel
                .software_component_id
                == seed.component_id
            )
        )

        session.execute(
            delete(
                SoftwareComponentModel
            ).where(
                SoftwareComponentModel.id
                == seed.component_id
            )
        )

        session.execute(
            delete(
                MachineModel
            ).where(
                MachineModel.id
                == seed.machine_id
            )
        )

        session.execute(
            delete(
                OrganizationModel
            ).where(
                OrganizationModel.id
                == seed.organization_id
            )
        )

        # -------------------------------------------------
        # Canonical.
        # -------------------------------------------------
        canonical_ids = (
            seed.canonical_vulnerability_id,
            seed.unrelated_canonical_id,
        )

        session.execute(
            delete(
                CanonicalVulnerabilityEvidenceModel
            ).where(
                CanonicalVulnerabilityEvidenceModel
                .vulnerability_id
                .in_(
                    canonical_ids
                )
            )
        )

        session.execute(
            delete(
                CanonicalVulnerabilityIdentifierModel
            ).where(
                CanonicalVulnerabilityIdentifierModel
                .vulnerability_id
                .in_(
                    canonical_ids
                )
            )
        )

        session.execute(
            delete(
                CanonicalVulnerabilityModel
            ).where(
                CanonicalVulnerabilityModel.id
                .in_(
                    canonical_ids
                )
            )
        )

        # -------------------------------------------------
        # CISA normalisé.
        # -------------------------------------------------
        session.execute(
            delete(
                CisaKevVulnerabilityModel
            ).where(
                CisaKevVulnerabilityModel
                .raw_payload_id
                == seed.raw_payload_id
            )
        )

        run_ids = [
            seed.first_run_id,
        ]

        if second_run_id is not None:
            run_ids.append(
                second_run_id
            )

        # -------------------------------------------------
        # Association snapshot -> payload.
        # -------------------------------------------------
        session.execute(
            delete(
                IngestionRunPayloadModel
            ).where(
                IngestionRunPayloadModel
                .ingestion_run_id
                .in_(
                    tuple(
                        run_ids
                    )
                )
            )
        )

        # -------------------------------------------------
        # Payload brut.
        # -------------------------------------------------
        session.execute(
            delete(
                SourcePayloadModel
            ).where(
                SourcePayloadModel.id
                == seed.raw_payload_id
            )
        )

        # -------------------------------------------------
        # Runs.
        # -------------------------------------------------
        session.execute(
            delete(
                IngestionRunModel
            ).where(
                IngestionRunModel.id
                .in_(
                    tuple(
                        run_ids
                    )
                )
            )
        )

        # -------------------------------------------------
        # Source de test.
        # -------------------------------------------------
        session.execute(
            delete(
                SourceModel
            ).where(
                SourceModel.id
                == seed.source_id
            )
        )

        session.commit()


def test_real_cisa_application_to_potential_kev_exposure_and_targeted_delete(
    owner_session_factory: sessionmaker[
        Session
    ],
) -> None:
    seed = _seed(
        owner_session_factory
    )

    second_run_id: UUID | None = None

    service = (
        ReconcileCisaKevApplicationExposuresService(
            unit_of_work=(
                SqlAlchemyVulnerabilityExposureUnitOfWork(
                    session_factory=(
                        owner_session_factory
                    ),
                    cisa_kev_source_code=(
                        seed.source_code
                    ),
                )
            ) 
        )
    )

    try:
        application = (
            _load_domain_component(
                owner_session_factory,
                seed.component_id,
            )
        )

        # =================================================
        # Premier passage :
        # la CVE appartient au snapshot CISA courant.
        # =================================================
        first_result = (
            service.reconcile(
                organization_id=(
                    seed.organization_id
                ),
                machine_id=(
                    seed.machine_id
                ),
                components=[
                    application,
                ],
                evaluated_at=T1,
            )
        )

        assert (
            first_result.application_count
            == 1
        )

        assert (
            first_result
            .eligible_application_count
            == 1
        )

        assert (
            first_result.candidate_count
            == 1
        )

        assert (
            first_result.match_count
            == 1
        )

        assert (
            first_result
            .resolved_match_count
            == 1
        )

        assert (
            first_result
            .unresolved_match_count
            == 0
        )

        assert (
            first_result
            .upserted_exposure_count
            == 1
        )

        assert (
            first_result
            .preserved_foreign_exposure_count
            == 0
        )

        assert (
            first_result
            .kev_enriched_exposure_count
            == 1
        )

        assert (
            first_result
            .deleted_exposure_count
            == 0
        )

        with owner_session_factory() as session:

            exposures = list(
                session.scalars(
                    select(
                        VulnerabilityExposureModel
                    )
                    .where(
                        VulnerabilityExposureModel
                        .software_component_id
                        == seed.component_id
                    )
                    .order_by(
                        VulnerabilityExposureModel
                        .match_rule
                    )
                )
            )

            # CISA + exposition indépendante.
            assert len(exposures) == 2

            cisa_exposure = next(
                exposure
                for exposure
                in exposures
                if (
                    exposure.match_rule
                    == (
                        CisaKevApplicationMatcher
                        .MATCH_RULE
                    )
                )
            )

            unrelated_exposure = next(
                exposure
                for exposure
                in exposures
                if (
                    exposure.match_rule
                    != (
                        CisaKevApplicationMatcher
                        .MATCH_RULE
                    )
                )
            )

            assert (
                cisa_exposure
                .canonical_vulnerability_id
                == (
                    seed
                    .canonical_vulnerability_id
                )
            )

            # CISA vendor/product exact :
            # potential, jamais confirmed.
            assert (
                cisa_exposure
                .applicability_status
                == "potential"
            )

            # Version installée conservée
            # comme contexte uniquement.
            assert (
                cisa_exposure.match_version
                == "1.5.0"
            )

            # La severity sera fournie
            # par la future politique CVSS.
            assert (
                cisa_exposure.severity
                is None
            )

            assert (
                cisa_exposure.priority
                is None
            )

            # Enrichissement KEV.
            assert (
                cisa_exposure.is_kev
                is True
            )

            # L'exposition étrangère reste intacte.
            assert (
                unrelated_exposure
                .canonical_vulnerability_id
                == (
                    seed
                    .unrelated_canonical_id
                )
            )

            assert (
                unrelated_exposure
                .applicability_status
                == "confirmed"
            )

            assert (
                unrelated_exposure.priority
                == "HIGH"
            )

            assert (
                unrelated_exposure.is_kev
                is False
            )

        # =================================================
        # Deuxième snapshot :
        # la CVE CISA disparaît.
        # =================================================
        second_run_id = (
            _create_empty_second_snapshot(
                owner_session_factory,
                source_id=(
                    seed.source_id
                ),
            )
        )

        second_result = (
            service.reconcile(
                organization_id=(
                    seed.organization_id
                ),
                machine_id=(
                    seed.machine_id
                ),
                components=[
                    application,
                ],
                evaluated_at=T2,
            )
        )

        assert (
            second_result.application_count
            == 1
        )

        assert (
            second_result.candidate_count
            == 0
        )

        assert (
            second_result.match_count
            == 0
        )

        assert (
            second_result
            .resolved_match_count
            == 0
        )

        assert (
            second_result
            .unresolved_match_count
            == 0
        )

        assert (
            second_result
            .upserted_exposure_count
            == 0
        )

        assert (
            second_result
            .kev_enriched_exposure_count
            == 0
        )

        assert (
            second_result
            .deleted_exposure_count
            == 1
        )

        with owner_session_factory() as session:

            remaining = list(
                session.scalars(
                    select(
                        VulnerabilityExposureModel
                    )
                    .where(
                        VulnerabilityExposureModel
                        .software_component_id
                        == seed.component_id
                    )
                )
            )

            # L'exposition CISA disparaît.
            # L'exposition étrangère reste.
            assert len(remaining) == 1

            assert (
                remaining[0]
                .canonical_vulnerability_id
                == (
                    seed
                    .unrelated_canonical_id
                )
            )

            assert (
                remaining[0].match_rule
                == (
                    "integration_unrelated_"
                    "confirmed_v1"
                )
            )

            assert (
                remaining[0]
                .applicability_status
                == "confirmed"
            )

            assert (
                remaining[0].priority
                == "HIGH"
            )

            assert (
                remaining[0].is_kev
                is False
            )

    finally:
        _cleanup(
            owner_session_factory,
            seed=seed,
            second_run_id=(
                second_run_id
            ),
        )