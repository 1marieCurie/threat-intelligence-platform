from __future__ import annotations

from ipaddress import ip_address

import tldextract


class URLGroupKeyResolutionError(
    ValueError
):
    """
    Erreur de résolution du group_key.

    Les messages ne doivent jamais exposer
    l'URL ou une donnée source complète.
    """


class URLGroupKeyResolver:
    """
    Résout un group_key déterministe à partir
    d'un hostname canonique.

    Politique V1 :
    - IP -> adresse IP normalisée ;
    - domaine -> domaine enregistrable via PSL ;
    - private PSL domains inclus ;
    - aucun accès réseau ;
    - fallback conservateur vers le hostname
      normalisé lorsqu'aucun suffixe PSL
      n'est reconnu.

    Le group_key est utilisé pour empêcher
    la contamination train/validation/test.
    """

    VERSION = "1.0.0"

    PSL_IMPLEMENTATION = (
        "tldextract-5.3.1-bundled"
    )

    def __init__(
        self,
    ) -> None:
        self._extract = tldextract.TLDExtract(
            suffix_list_urls=(),
            cache_dir=None,
            include_psl_private_domains=True,
        )

    def resolve(
        self,
        hostname: str,
    ) -> str:
        if not isinstance(
            hostname,
            str,
        ):
            raise TypeError(
                "hostname must be a string"
            )

        candidate = (
            hostname
            .strip()
            .lower()
            .rstrip(".")
        )

        if not candidate:
            raise URLGroupKeyResolutionError(
                "hostname must not be empty"
            )

        try:
            normalized_ip = ip_address(
                candidate
            )

        except ValueError:
            pass

        else:
            return str(
                normalized_ip
            )

        try:
            normalized_hostname = (
                candidate
                .encode("idna")
                .decode("ascii")
                .lower()
            )

        except UnicodeError:
            raise URLGroupKeyResolutionError(
                "hostname is invalid"
            ) from None

        if (
            len(normalized_hostname)
            > 253
        ):
            raise URLGroupKeyResolutionError(
                "hostname is invalid"
            )

        labels = normalized_hostname.split(
            "."
        )

        if any(
            not label
            or len(label) > 63
            for label in labels
        ):
            raise URLGroupKeyResolutionError(
                "hostname is invalid"
            )

        extracted = self._extract(
            normalized_hostname
        )

        registered_domain = (
            extracted
            .top_domain_under_public_suffix
        )

        if registered_domain:
            return (
                registered_domain
                .lower()
                .rstrip(".")
            )

        # Fallback volontairement conservateur :
        # on ne supprime pas un échantillon valide
        # uniquement parce que son suffixe n'existe
        # pas dans le snapshot PSL embarqué.
        return normalized_hostname