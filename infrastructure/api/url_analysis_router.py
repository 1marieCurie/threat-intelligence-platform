from __future__ import annotations

from typing import Literal

from fastapi import (
    APIRouter,
    HTTPException,
    status,
)
from pydantic import (
    BaseModel,
    Field,
)

from application.ports.outbound.url_threat_classifier import (
    URLThreatClassifierError,
)
from application.services.analyze_url_service import (
    AnalyzeURLService,
)
from application.services.canonical_url_normalizer import (
    CanonicalURLNormalizationError,
)
from application.services.url_feature_extractor import (
    URLFeatureExtractionError,
)


class URLAnalysisRequest(
    BaseModel
):
    url: str = Field(
        min_length=1,
        max_length=4096,
    )


class URLAnalysisResponse(
    BaseModel
):
    verdict: Literal[
        "benign",
        "malicious",
    ]

    threat_class: Literal[
        "benign",
        "phishing",
        "malware",
    ]

    confidence: float = Field(
        ge=0.0,
        le=1.0,
    )

    model_version: str


def create_url_analysis_router(
    *,
    analyze_url_service: AnalyzeURLService,
) -> APIRouter:
    if analyze_url_service is None:
        raise ValueError(
            "analyze_url_service must not be None"
        )

    router = APIRouter(
        prefix="/api/v1",
        tags=["url-analysis"],
    )

    @router.post(
        "/url-analysis",
        response_model=URLAnalysisResponse,
        status_code=status.HTTP_200_OK,
    )
    def analyze_url(
        payload: URLAnalysisRequest,
    ) -> URLAnalysisResponse:
        try:
            result = (
                analyze_url_service.analyze(
                    payload.url
                )
            )

        except (
            CanonicalURLNormalizationError,
            URLFeatureExtractionError,
        ) as error:
            raise HTTPException(
                status_code=(
                    status.HTTP_422_UNPROCESSABLE_CONTENT
                ),
                detail=str(error),
            ) from error

        except URLThreatClassifierError as error:
            raise HTTPException(
                status_code=(
                    status.HTTP_503_SERVICE_UNAVAILABLE
                ),
                detail=(
                    "URL analysis service is "
                    "temporarily unavailable"
                ),
            ) from error

        return URLAnalysisResponse(
            verdict=result.verdict,
            threat_class=(
                result.threat_class
            ),
            confidence=(
                result.confidence
            ),
            model_version=(
                result.model_version
            ),
        )

    return router