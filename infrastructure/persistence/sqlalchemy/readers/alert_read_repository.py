from __future__ import annotations

from collections import (
    defaultdict,
)
from uuid import UUID

from sqlalchemy import (
    and_,
    select,
)
from sqlalchemy.exc import (
    SQLAlchemyError,
)
from sqlalchemy.orm import (
    Session,
    aliased,
    sessionmaker,
)

from application.models.alert_view import (
    AlertComponentView,
    AlertDetail,
    AlertExposureView,
    AlertIdentifierView,
    AlertMachineView,
    AlertRecipientView,
    AlertSummary,
    AlertWeaknessView,
)
from application.ports.outbound.alert_read_repository import (
    AlertReadRepository,
    AlertReadRepositoryError,
)
from application.services.cvss_selection_policy_v1 import (
    CvssObservation,
    CvssSelectionPolicyV1,
)
from infrastructure.persistence.models.assets import (
    AlertModel,
    MachineModel,
    SoftwareComponentModel,
    UserAccountModel,
    VulnerabilityExposureModel,
)
from infrastructure.persistence.models.canonical import (
    CanonicalVulnerabilityIdentifierModel,
    CanonicalVulnerabilityWeaknessModel,
)
from infrastructure.persistence.models.normalized import (
    CWEWeaknessModel,
)
from infrastructure.persistence.sqlalchemy.repositories.canonical_vulnerability_cvss_read_repository import (
    CanonicalVulnerabilityCvssReadRepositoryError,
    SqlAlchemyCanonicalVulnerabilityCvssReadRepository,
)
from infrastructure.persistence.sqlalchemy.repositories.canonical_vulnerability_priority_signal_read_repository import (
    CanonicalVulnerabilityPrioritySignalReadRepositoryError,
    SqlAlchemyCanonicalVulnerabilityPrioritySignalReadRepository,
)


class SqlAlchemyAlertReadRepository(
    AlertReadRepository
):
    def __init__(
        self,
        session_factory: (
            sessionmaker[Session]
        ),
    ) -> None:
        if session_factory is None:
            raise ValueError(
                "session_factory must not be None"
            )

        self._session_factory = (
            session_factory
        )

        self._cvss_policy = (
            CvssSelectionPolicyV1()
        )

    def list_alerts(
        self,
        *,
        organization_id: UUID,
    ) -> tuple[
        AlertSummary,
        ...,
    ]:
        if not isinstance(
            organization_id,
            UUID,
        ):
            raise TypeError(
                "organization_id must be UUID"
            )

        primary_identifier = aliased(
            CanonicalVulnerabilityIdentifierModel
        )

        statement = (
            select(
                AlertModel.id,

                AlertModel.alert_type,

                AlertModel.status,

                AlertModel.created_at,

                AlertModel.sent_at,

                AlertModel.machine_id,

                MachineModel.hostname,

                AlertModel
                .canonical_vulnerability_id,

                primary_identifier.value,

                SoftwareComponentModel.name,

                SoftwareComponentModel.version,

                VulnerabilityExposureModel
                .priority,

                VulnerabilityExposureModel
                .is_kev,
            )
            .select_from(
                AlertModel
            )
            .join(
                MachineModel,
                and_(
                    MachineModel.id
                    == AlertModel.machine_id,

                    MachineModel.organization_id
                    == AlertModel.organization_id,
                ),
            )
            .outerjoin(
                VulnerabilityExposureModel,
                VulnerabilityExposureModel.id
                == AlertModel
                .vulnerability_exposure_id,
            )
            .outerjoin(
                SoftwareComponentModel,
                SoftwareComponentModel.id
                == VulnerabilityExposureModel
                .software_component_id,
            )
            .outerjoin(
                primary_identifier,
                and_(
                    primary_identifier
                    .vulnerability_id
                    == AlertModel
                    .canonical_vulnerability_id,

                    primary_identifier
                    .is_primary
                    .is_(True),
                ),
            )
            .where(
                AlertModel.organization_id
                == organization_id
            )
            .order_by(
                AlertModel.created_at.desc(),
                AlertModel.id.desc(),
            )
        )

        try:
            with (
                self._session_factory()
                as session
            ):
                rows = (
                    session.execute(
                        statement
                    )
                    .tuples()
                    .all()
                )

        except SQLAlchemyError as error:
            raise (
                AlertReadRepositoryError(
                    "Unable to read alerts"
                )
            ) from error

        return tuple(
            AlertSummary(
                alert_id=row[0],
                alert_type=row[1],
                status=row[2],
                created_at=row[3],
                sent_at=row[4],
                machine_id=row[5],
                machine_hostname=row[6],
                canonical_vulnerability_id=(
                    row[7]
                ),
                primary_identifier=row[8],
                component_name=row[9],
                component_version=row[10],
                current_priority=row[11],
                is_kev=row[12],
            )
            for row in rows
        )

    def get_alert_detail(
        self,
        *,
        organization_id: UUID,
        alert_id: UUID,
    ) -> AlertDetail | None:
        if not isinstance(
            organization_id,
            UUID,
        ):
            raise TypeError(
                "organization_id must be UUID"
            )

        if not isinstance(
            alert_id,
            UUID,
        ):
            raise TypeError(
                "alert_id must be UUID"
            )

        try:
            with (
                self._session_factory()
                as session
            ):
                # =============================================
                # 1. Barrière tenant
                # =============================================
                #
                # C'est volontairement la toute première
                # requête.
                #
                # Aucune donnée CVE/CWE/exposition n'est lue
                # avant d'avoir prouvé que l'alerte appartient
                # à l'organisation demandée.
                # =============================================

                base_statement = (
                    select(
                        AlertModel.id,
                        AlertModel.alert_type,
                        AlertModel.status,
                        AlertModel.created_at,
                        AlertModel.sent_at,

                        AlertModel
                        .canonical_vulnerability_id,

                        AlertModel
                        .vulnerability_exposure_id,

                        MachineModel.id,
                        MachineModel.hostname,
                        MachineModel.os_name,
                        MachineModel.os_version,
                        MachineModel.architecture,

                        UserAccountModel.id,
                        UserAccountModel.email,
                        UserAccountModel.display_name,
                    )
                    .select_from(
                        AlertModel
                    )
                    .join(
                        MachineModel,
                        and_(
                            MachineModel.id
                            == AlertModel.machine_id,

                            MachineModel.organization_id
                            == AlertModel.organization_id,
                        ),
                    )
                    .join(
                        UserAccountModel,
                        and_(
                            UserAccountModel.id
                            == AlertModel
                            .recipient_user_id,

                            UserAccountModel
                            .organization_id
                            == AlertModel
                            .organization_id,
                        ),
                    )
                    .where(
                        AlertModel.id
                        == alert_id,

                        AlertModel.organization_id
                        == organization_id,
                    )
                )

                base_row = (
                    session.execute(
                        base_statement
                    )
                    .tuples()
                    .one_or_none()
                )

                if base_row is None:
                    return None

                canonical_id = (
                    base_row[5]
                )

                exposure_id = (
                    base_row[6]
                )

                machine_id = (
                    base_row[7]
                )

                # =============================================
                # 2. Identifiants CVE / GHSA
                # =============================================

                identifier_rows = (
                    session.execute(
                        select(
                            CanonicalVulnerabilityIdentifierModel
                            .namespace,

                            CanonicalVulnerabilityIdentifierModel
                            .value,

                            CanonicalVulnerabilityIdentifierModel
                            .is_primary,
                        )
                        .where(
                            CanonicalVulnerabilityIdentifierModel
                            .vulnerability_id
                            == canonical_id
                        )
                        .order_by(
                            CanonicalVulnerabilityIdentifierModel
                            .is_primary
                            .desc(),

                            CanonicalVulnerabilityIdentifierModel
                            .namespace,

                            CanonicalVulnerabilityIdentifierModel
                            .value,
                        )
                    )
                    .tuples()
                    .all()
                )

                identifiers = tuple(
                    AlertIdentifierView(
                        namespace=row[0],
                        value=row[1],
                        is_primary=bool(
                            row[2]
                        ),
                    )
                    for row
                    in identifier_rows
                )

                primary_identifier = next(
                    (
                        identifier.value
                        for identifier
                        in identifiers
                        if identifier.is_primary
                    ),
                    None,
                )

                # =============================================
                # 3. Exposition + composant
                # =============================================
                #
                # Alert.vulnerability_exposure_id peut devenir
                # NULL après suppression de l'exposition.
                #
                # Même lorsqu'elle existe encore, on vérifie
                # également que son composant appartient bien
                # à LA machine de l'alerte.
                # =============================================

                component: (
                    AlertComponentView
                    | None
                ) = None

                exposure: (
                    AlertExposureView
                    | None
                ) = None

                if exposure_id is not None:
                    exposure_statement = (
                        select(
                            VulnerabilityExposureModel.id,

                            VulnerabilityExposureModel
                            .applicability_status,

                            VulnerabilityExposureModel
                            .severity,

                            VulnerabilityExposureModel
                            .priority,

                            VulnerabilityExposureModel
                            .is_kev,

                            VulnerabilityExposureModel
                            .match_rule,

                            VulnerabilityExposureModel
                            .match_version,

                            VulnerabilityExposureModel
                            .first_detected_at,

                            VulnerabilityExposureModel
                            .last_evaluated_at,

                            SoftwareComponentModel.id,

                            SoftwareComponentModel
                            .component_type,

                            SoftwareComponentModel.name,

                            SoftwareComponentModel.version,

                            SoftwareComponentModel.vendor,

                            SoftwareComponentModel.ecosystem,

                            SoftwareComponentModel.scope,
                        )
                        .select_from(
                            VulnerabilityExposureModel
                        )
                        .join(
                            SoftwareComponentModel,
                            and_(
                                SoftwareComponentModel.id
                                == VulnerabilityExposureModel
                                .software_component_id,

                                SoftwareComponentModel
                                .machine_id
                                == machine_id,
                            ),
                        )
                        .join(
                            MachineModel,
                            and_(
                                MachineModel.id
                                == SoftwareComponentModel
                                .machine_id,

                                MachineModel.organization_id
                                == organization_id,
                            ),
                        )
                        .where(
                            VulnerabilityExposureModel.id
                            == exposure_id,

                            VulnerabilityExposureModel
                            .canonical_vulnerability_id
                            == canonical_id,
                        )
                    )

                    exposure_row = (
                        session.execute(
                            exposure_statement
                        )
                        .tuples()
                        .one_or_none()
                    )

                    if (
                        exposure_row
                        is not None
                    ):
                        exposure = (
                            AlertExposureView(
                                exposure_id=(
                                    exposure_row[0]
                                ),
                                applicability_status=(
                                    exposure_row[1]
                                ),
                                severity=(
                                    exposure_row[2]
                                ),
                                priority=(
                                    exposure_row[3]
                                ),
                                is_kev=bool(
                                    exposure_row[4]
                                ),
                                match_rule=(
                                    exposure_row[5]
                                ),
                                match_version=(
                                    exposure_row[6]
                                ),
                                first_detected_at=(
                                    exposure_row[7]
                                ),
                                last_evaluated_at=(
                                    exposure_row[8]
                                ),
                            )
                        )

                        component = (
                            AlertComponentView(
                                component_id=(
                                    exposure_row[9]
                                ),
                                component_type=(
                                    exposure_row[10]
                                ),
                                name=(
                                    exposure_row[11]
                                ),
                                version=(
                                    exposure_row[12]
                                ),
                                vendor=(
                                    exposure_row[13]
                                ),
                                ecosystem=(
                                    exposure_row[14]
                                ),
                                scope=(
                                    exposure_row[15]
                                ),
                            )
                        )

                # =============================================
                # 4. CWE avec nom et description
                # =============================================

                weakness_rows = (
                    session.execute(
                        select(
                            CWEWeaknessModel.cwe_id,

                            CWEWeaknessModel.name,

                            CWEWeaknessModel.description,
                        )
                        .select_from(
                            CanonicalVulnerabilityWeaknessModel
                        )
                        .join(
                            CWEWeaknessModel,
                            CWEWeaknessModel.cwe_id
                            == CanonicalVulnerabilityWeaknessModel
                            .cwe_id,
                        )
                        .where(
                            CanonicalVulnerabilityWeaknessModel
                            .vulnerability_id
                            == canonical_id
                        )
                        .distinct()
                        .order_by(
                            CWEWeaknessModel.cwe_id
                        )
                    )
                    .tuples()
                    .all()
                )

                weaknesses = tuple(
                    AlertWeaknessView(
                        cwe_id=row[0],
                        name=row[1],
                        description=row[2],
                    )
                    for row
                    in weakness_rows
                )

                # =============================================
                # 5. EPSS
                # =============================================

                priority_reader = (
                    SqlAlchemyCanonicalVulnerabilityPrioritySignalReadRepository(
                        session=session
                    )
                )

                priority_signals = (
                    priority_reader.find_many(
                        canonical_vulnerability_ids=(
                            canonical_id,
                        )
                    )
                    .get(
                        canonical_id
                    )
                )

                # =============================================
                # 6. CVSS
                # =============================================

                cvss_reader = (
                    SqlAlchemyCanonicalVulnerabilityCvssReadRepository(
                        session=session
                    )
                )

                observations = (
                    cvss_reader.find_observations(
                        canonical_vulnerability_ids=(
                            canonical_id,
                        )
                    )
                )

                observations_by_canonical: dict[
                    UUID,
                    list[
                        CvssObservation
                    ],
                ] = defaultdict(
                    list
                )

                for observation in observations:
                    observations_by_canonical[
                        observation
                        .canonical_vulnerability_id
                    ].append(
                        CvssObservation(
                            source_name=(
                                observation
                                .source_name
                            ),
                            version=(
                                observation
                                .version
                            ),
                            base_score=(
                                observation
                                .base_score
                            ),
                            vector=(
                                observation
                                .vector
                            ),
                            source_role=(
                                observation
                                .source_role
                            ),
                            published_at=(
                                observation
                                .published_at
                            ),
                            modified_at=(
                                observation
                                .modified_at
                            ),
                        )
                    )

                selected_cvss = (
                    self._cvss_policy
                    .select(
                        observations_by_canonical
                        .get(
                            canonical_id,
                            (),
                        )
                    )
                )

                # =============================================
                # 7. Mapping final
                # =============================================

                return AlertDetail(
                    alert_id=base_row[0],
                    alert_type=base_row[1],
                    status=base_row[2],
                    created_at=base_row[3],
                    sent_at=base_row[4],

                    recipient=(
                        AlertRecipientView(
                            user_id=base_row[12],
                            email=base_row[13],
                            display_name=(
                                base_row[14]
                            ),
                        )
                    ),

                    machine=(
                        AlertMachineView(
                            machine_id=(
                                base_row[7]
                            ),
                            hostname=(
                                base_row[8]
                            ),
                            os_name=(
                                base_row[9]
                            ),
                            os_version=(
                                base_row[10]
                            ),
                            architecture=(
                                base_row[11]
                            ),
                        )
                    ),

                    canonical_vulnerability_id=(
                        canonical_id
                    ),

                    primary_identifier=(
                        primary_identifier
                    ),

                    identifiers=identifiers,

                    component=component,
                    exposure=exposure,

                    epss_score=(
                        priority_signals
                        .epss_score
                        if priority_signals
                        is not None
                        else None
                    ),

                    epss_percentile=(
                        priority_signals
                        .epss_percentile
                        if priority_signals
                        is not None
                        else None
                    ),

                    cvss_score=(
                        selected_cvss
                        .base_score
                        if selected_cvss
                        is not None
                        else None
                    ),

                    cvss_version=(
                        selected_cvss
                        .version
                        if selected_cvss
                        is not None
                        else None
                    ),

                    cvss_vector=(
                        selected_cvss.vector
                        if selected_cvss
                        is not None
                        else None
                    ),

                    cvss_source_name=(
                        selected_cvss
                        .source_name
                        if selected_cvss
                        is not None
                        else None
                    ),

                    cvss_source_role=(
                        selected_cvss
                        .source_role
                        if selected_cvss
                        is not None
                        else None
                    ),

                    weaknesses=weaknesses,
                )

        except (
            SQLAlchemyError,
            CanonicalVulnerabilityCvssReadRepositoryError,
            CanonicalVulnerabilityPrioritySignalReadRepositoryError,
        ) as error:
            raise (
                AlertReadRepositoryError(
                    "Unable to read alert detail"
                )
            ) from error