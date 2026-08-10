from __future__ import annotations

import re
from urllib.parse import (
    urlsplit,
    urlunsplit,
)


class MLURLProjectionError(ValueError):
    """
    Projection failure without raw URL disclosure.
    """


class MLURLTrainingProjector:
    """
    Builds the deterministic URL representation used by ML.

    The representation intentionally masks data that may
    contain secrets or personal identifiers.

    It performs no HTTP, DNS or network request.
    """

    VERSION = "1.0.0"

    _UUID_PATTERN = re.compile(
        r"^[0-9a-fA-F]{8}-"
        r"[0-9a-fA-F]{4}-"
        r"[1-5][0-9a-fA-F]{3}-"
        r"[89abAB][0-9a-fA-F]{3}-"
        r"[0-9a-fA-F]{12}$"
    )

    _EMAIL_PATTERN = re.compile(
        r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
    )

    _LONG_TOKEN_PATTERN = re.compile(
        r"^[A-Za-z0-9_-]{24,}$"
    )

    def project(
        self,
        canonical_value: str,
    ) -> str:
        if not isinstance(
            canonical_value,
            str,
        ):
            raise TypeError(
                "canonical_value must be a string"
            )

        try:
            parsed = urlsplit(
                canonical_value
            )

        except ValueError:
            raise MLURLProjectionError(
                "canonical URL cannot be projected"
            ) from None

        path = self._project_path(
            parsed.path
        )

        query = self._project_query(
            parsed.query
        )

        fragment = (
            "<fragment>"
            if parsed.fragment
            else ""
        )

        projected = urlunsplit(
            (
                parsed.scheme,
                parsed.netloc,
                path,
                query,
                fragment,
            )
        )

        if not projected:
            raise MLURLProjectionError(
                "projected URL is empty"
            )

        if len(projected) > 4096:
            raise MLURLProjectionError(
                "projected URL exceeds limit"
            )

        return projected

    def _project_path(
        self,
        path: str,
    ) -> str:
        if not path:
            return "/"

        segments = path.split("/")

        projected_segments = [
            self._project_path_segment(
                segment
            )
            for segment in segments
        ]

        return "/".join(
            projected_segments
        )

    def _project_path_segment(
        self,
        segment: str,
    ) -> str:
        if not segment:
            return segment

        if self._UUID_PATTERN.fullmatch(
            segment
        ):
            return "<uuid>"

        if self._EMAIL_PATTERN.fullmatch(
            segment
        ):
            return "<email>"

        if self._LONG_TOKEN_PATTERN.fullmatch(
            segment
        ):
            return "<token>"

        return segment

    @staticmethod
    def _project_query(
        query: str,
    ) -> str:
        if not query:
            return ""

        projected_fields: list[str] = []

        for field in query.split("&"):
            if "=" not in field:
                projected_fields.append(
                    field
                )
                continue

            key, _ = field.split(
                "=",
                maxsplit=1,
            )

            projected_fields.append(
                f"{key}=<value>"
            )

        return "&".join(
            projected_fields
        )