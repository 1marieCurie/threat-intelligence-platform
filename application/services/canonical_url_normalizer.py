from __future__ import annotations

from hashlib import sha256
from ipaddress import ip_address
from urllib.parse import (
    SplitResult,
    urlsplit,
    urlunsplit,
)

from application.models.canonical_url_identity import (
    CanonicalURLIdentity,
)


class CanonicalURLNormalizationError(
    ValueError
):
    """
    Erreur de canonicalisation d'une URL.

    Les messages ne contiennent jamais l'URL reçue afin
    d'éviter l'exposition accidentelle d'un IOC.
    """


class CanonicalURLNormalizer:
    """
    Canonicalise une URL HTTP(S) de manière déterministe.

    Normalisations V1 :

    - schéma en minuscules ;
    - hostname en minuscules et IDNA ;
    - suppression du point terminal du hostname ;
    - canonicalisation des adresses IP ;
    - suppression des ports HTTP/HTTPS par défaut ;
    - chemin vide converti en "/" ;
    - conservation exacte du chemin, de la query et du fragment.

    Les URLs contenant des informations utilisateur sont
    refusées pour éviter de persister des identifiants ou secrets.

    Aucun décodage, tri de query, résolution DNS ou accès réseau
    n'est effectué.
    """

    CANONICALIZATION_VERSION = 1

    MAX_URL_LENGTH = 4_096
    MAX_HOSTNAME_LENGTH = 253

    SUPPORTED_SCHEMES = frozenset(
        {
            "http",
            "https",
        }
    )

    DEFAULT_PORTS = {
        "http": 80,
        "https": 443,
    }

    def normalize(
        self,
        value: str,
    ) -> CanonicalURLIdentity:
        normalized_input = self._normalize_input(
            value
        )

        parsed = self._parse_url(
            normalized_input
        )

        scheme = parsed.scheme.lower()

        if scheme not in self.SUPPORTED_SCHEMES:
            raise CanonicalURLNormalizationError(
                "URL scheme must be http or https"
            )

        hostname = self._normalize_hostname(
            parsed
        )

        port = self._normalize_port(
            parsed=parsed,
            scheme=scheme,
        )

        authority = self._build_authority(
            hostname=hostname,
            port=port,
        )

        canonical_value = urlunsplit(
            (
                scheme,
                authority,
                parsed.path or "/",
                parsed.query,
                parsed.fragment,
            )
        )

        if (
            len(canonical_value)
            > self.MAX_URL_LENGTH
        ):
            raise CanonicalURLNormalizationError(
                "Canonical URL exceeds "
                f"{self.MAX_URL_LENGTH} characters"
            )

        value_hash = sha256(
            canonical_value.encode(
                "utf-8"
            )
        ).hexdigest()

        return CanonicalURLIdentity(
            canonical_value=canonical_value,
            value_hash=value_hash,
            hostname=hostname,
            canonicalization_version=(
                self.CANONICALIZATION_VERSION
            ),
        )

    @classmethod
    def _normalize_input(
        cls,
        value: str,
    ) -> str:
        if not isinstance(value, str):
            raise TypeError(
                "URL must be a string"
            )

        normalized_value = value.strip()

        if not normalized_value:
            raise CanonicalURLNormalizationError(
                "URL must not be empty"
            )

        if (
            len(normalized_value)
            > cls.MAX_URL_LENGTH
        ):
            raise CanonicalURLNormalizationError(
                "URL exceeds "
                f"{cls.MAX_URL_LENGTH} characters"
            )

        if "\\" in normalized_value:
            raise CanonicalURLNormalizationError(
                "URL contains an ambiguous separator"
            )

        if any(
            character.isspace()
            or ord(character) < 32
            or ord(character) == 127
            for character in normalized_value
        ):
            raise CanonicalURLNormalizationError(
                "URL contains invalid characters"
            )

        return normalized_value

    @staticmethod
    def _parse_url(
        value: str,
    ) -> SplitResult:
        try:
            parsed = urlsplit(
                value
            )

            # Déclenche la validation des ports mal formés.
            parsed.port

        except (
            UnicodeError,
            ValueError,
        ) as error:
            raise CanonicalURLNormalizationError(
                "URL has an invalid format"
            ) from error

        if not parsed.netloc:
            raise CanonicalURLNormalizationError(
                "URL must include an authority"
            )

        if "@" in parsed.netloc:
            raise CanonicalURLNormalizationError(
                "URL user information is not supported"
            )

        if parsed.netloc.endswith(":"):
            raise CanonicalURLNormalizationError(
                "URL port is invalid"
            )

        return parsed

    @classmethod
    def _normalize_hostname(
        cls,
        parsed: SplitResult,
    ) -> str:
        try:
            raw_hostname = parsed.hostname

        except (
            UnicodeError,
            ValueError,
        ) as error:
            raise CanonicalURLNormalizationError(
                "URL hostname is invalid"
            ) from error

        if raw_hostname is None:
            raise CanonicalURLNormalizationError(
                "URL must include a hostname"
            )

        candidate = (
            raw_hostname
            .strip()
            .lower()
            .rstrip(".")
        )

        if not candidate:
            raise CanonicalURLNormalizationError(
                "URL hostname is invalid"
            )

        try:
            canonical_hostname = str(
                ip_address(
                    candidate
                )
            )

        except ValueError:
            try:
                canonical_hostname = (
                    candidate
                    .encode("idna")
                    .decode("ascii")
                    .lower()
                )

            except UnicodeError as error:
                raise (
                    CanonicalURLNormalizationError(
                        "URL hostname is invalid"
                    )
                ) from error

            labels = canonical_hostname.split(
                "."
            )

            if any(
                not label
                or len(label) > 63
                for label in labels
            ):
                raise CanonicalURLNormalizationError(
                    "URL hostname is invalid"
                )

        if (
            len(canonical_hostname)
            > cls.MAX_HOSTNAME_LENGTH
        ):
            raise CanonicalURLNormalizationError(
                "URL hostname exceeds "
                f"{cls.MAX_HOSTNAME_LENGTH} characters"
            )

        return canonical_hostname

    @classmethod
    def _normalize_port(
        cls,
        *,
        parsed: SplitResult,
        scheme: str,
    ) -> int | None:
        try:
            port = parsed.port

        except ValueError as error:
            raise CanonicalURLNormalizationError(
                "URL port is invalid"
            ) from error

        if (
            port is not None
            and port
            == cls.DEFAULT_PORTS[scheme]
        ):
            return None

        return port

    @staticmethod
    def _build_authority(
        *,
        hostname: str,
        port: int | None,
    ) -> str:
        try:
            is_ipv6 = (
                ip_address(
                    hostname
                ).version
                == 6
            )

        except ValueError:
            is_ipv6 = False

        authority = (
            f"[{hostname}]"
            if is_ipv6
            else hostname
        )

        if port is not None:
            authority = (
                f"{authority}:{port}"
            )

        return authority