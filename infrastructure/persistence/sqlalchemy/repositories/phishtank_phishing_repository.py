from __future__ import annotations

from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from application.ports.outbound.phishtank_phishing_repository import (
    PhishTankNetworkDetailData,
    PhishTankPhishingData,
)
from infrastructure.persistence.models.normalized_phishtank import (
    PhishTankPhishingModel,
)


class SqlAlchemyPhishTankPhishingRepository:
    def __init__(
        self,
        *,
        session: Session,
    ) -> None:
        if session is None:
            raise ValueError(
                "session must not be None"
            )

        self._session = session

    def save(
        self,
        phishing: PhishTankPhishingData,
    ) -> UUID:
        phishing_id = uuid4()

        model = PhishTankPhishingModel(
            id=phishing_id,
            raw_payload_id=(
                phishing.raw_payload_id
            ),
            phish_id=phishing.phish_id,
            phishing_url=(
                phishing.phishing_url
            ),
            hostname=phishing.hostname,
            phish_detail_url=(
                phishing.phish_detail_url
            ),
            submission_time=(
                phishing.submission_time
            ),
            verification_time=(
                phishing.verification_time
            ),
            verified=phishing.verified,
            online=phishing.online,
            target=phishing.target,
            network_details=(
                self._serialize_network_details(
                    phishing.network_details
                )
            ),
            normalizer_version=(
                phishing.normalizer_version
            ),
        )

        self._session.add(model)
        self._session.flush()

        return phishing_id

    def exists_by_raw_payload_id(
        self,
        raw_payload_id: UUID,
    ) -> bool:
        statement = (
            select(
                PhishTankPhishingModel.id
            )
            .where(
                PhishTankPhishingModel
                .raw_payload_id
                == raw_payload_id
            )
            .limit(1)
        )

        existing_id = (
            self._session
            .execute(statement)
            .scalar_one_or_none()
        )

        return existing_id is not None

    @staticmethod
    def _serialize_network_details(
        details: tuple[
            PhishTankNetworkDetailData,
            ...,
        ],
    ) -> list[dict[str, object]]:
        result: list[
            dict[str, object]
        ] = []

        for detail in details:
            serialized: dict[
                str,
                object,
            ] = {}

            if detail.ip_address is not None:
                serialized[
                    "ip_address"
                ] = detail.ip_address

            if detail.cidr_block is not None:
                serialized[
                    "cidr_block"
                ] = detail.cidr_block

            if (
                detail.announcing_network
                is not None
            ):
                serialized[
                    "announcing_network"
                ] = (
                    detail.announcing_network
                )

            if detail.rir is not None:
                serialized["rir"] = detail.rir

            if detail.country is not None:
                serialized[
                    "country"
                ] = detail.country

            if detail.detail_time is not None:
                serialized[
                    "detail_time"
                ] = (
                    detail.detail_time
                    .isoformat()
                )

            if serialized:
                result.append(
                    serialized
                )

        return result