from __future__ import annotations

import argparse
import csv
import re
import sys
from collections import Counter
from collections.abc import Sequence
from ipaddress import ip_address
from pathlib import Path
from urllib.parse import urlsplit


PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parents[2]
)

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(
        0,
        str(PROJECT_ROOT),
    )


from application.services.canonical_url_normalizer import (
    CanonicalURLNormalizationError,
    CanonicalURLNormalizer,
)
from application.services.url_feature_extractor import (
    URLFeatureExtractionError,
    URLFeatureExtractor,
)


DEFAULT_INPUT_PATH = (
    PROJECT_ROOT
    / ".ml-data"
    / "benign_candidates_http_archive_2026_07.csv"
)

REQUIRED_FIELDS = frozenset(
    {
        "url",
        "registered_domain",
        "source_rank",
        "source_snapshot",
        "observed_at",
    }
)

_PERCENT_ENCODING_PATTERN = re.compile(
    r"%[0-9A-Fa-f]{2}"
)


def _parse_arguments(
    argv: Sequence[str] | None = None,
) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Audit HTTP Archive benign "
            "URL candidates without exposing URLs."
        )
    )

    parser.add_argument(
        "--input",
        type=Path,
        default=DEFAULT_INPUT_PATH,
        help=(
            "Candidate CSV path. "
            "Defaults to the HTTP Archive "
            "candidate export."
        ),
    )

    return parser.parse_args(
        argv
    )


def _percentile(
    values: list[int],
    percentile: float,
) -> float:
    if not values:
        return 0.0

    ordered = sorted(
        values
    )

    if len(ordered) == 1:
        return float(
            ordered[0]
        )

    position = (
        (len(ordered) - 1)
        * percentile
    )

    lower_index = int(
        position
    )

    upper_index = min(
        lower_index + 1,
        len(ordered) - 1,
    )

    fraction = (
        position
        - lower_index
    )

    lower_value = (
        ordered[
            lower_index
        ]
    )

    upper_value = (
        ordered[
            upper_index
        ]
    )

    return (
        lower_value
        + (
            upper_value
            - lower_value
        )
        * fraction
    )


def _percentage(
    value: int,
    total: int,
) -> float:
    if total <= 0:
        return 0.0

    return (
        value
        / total
        * 100.0
    )


def _print_distribution(
    *,
    name: str,
    values: list[int],
) -> None:
    if not values:
        print(
            f"{name}: no values"
        )
        return

    print(
        f"{name}: "
        f"min={min(values)}, "
        f"avg={sum(values) / len(values):.2f}, "
        f"p50={_percentile(values, 0.50):.2f}, "
        f"p90={_percentile(values, 0.90):.2f}, "
        f"p95={_percentile(values, 0.95):.2f}, "
        f"max={max(values)}"
    )


def _is_ip_address(
    hostname: str,
) -> bool:
    try:
        ip_address(
            hostname
        )

    except ValueError:
        return False

    return True


def main(
    argv: Sequence[str] | None = None,
) -> int:
    arguments = (
        _parse_arguments(
            argv
        )
    )

    input_path = (
        arguments.input
    )

    if (
        not input_path.exists()
        or not input_path.is_file()
    ):
        print(
            "Benign candidate audit failed: "
            "input file does not exist",
            file=sys.stderr,
        )

        return 1

    normalizer = (
        CanonicalURLNormalizer()
    )

    extractor = (
        URLFeatureExtractor()
    )

    rows_read = 0
    normalized = 0
    accepted_rows = 0

    normalization_rejected = 0
    feature_rejected = 0
    domain_mismatch = 0

    canonical_hashes: set[
        str
    ] = set()

    duplicate_canonical_urls = 0

    registered_domains: set[
        str
    ] = set()

    domain_counts: Counter[
        str
    ] = Counter()

    source_snapshots: Counter[
        str
    ] = Counter()

    url_lengths: list[int] = []
    hostname_lengths: list[int] = []
    path_lengths: list[int] = []
    query_lengths: list[int] = []
    fragment_lengths: list[int] = []

    path_segment_counts: list[int] = []
    query_parameter_counts: list[int] = []

    https_count = 0
    ip_count = 0
    non_default_port_count = 0
    punycode_count = 0
    percent_encoding_count = 0

    non_root_path_count = 0
    query_present_count = 0
    fragment_present_count = 0

    source_ranks: list[int] = []

    try:
        with input_path.open(
            "r",
            encoding="utf-8",
            newline="",
        ) as handle:
            reader = csv.DictReader(
                handle
            )

            fields = set(
                reader.fieldnames
                or ()
            )

            if not (
                REQUIRED_FIELDS
                <= fields
            ):
                print(
                    "Benign candidate audit failed: "
                    "CSV schema is invalid",
                    file=sys.stderr,
                )

                return 1

            for row_number, row in enumerate(
                reader,
                start=2,
            ):
                rows_read += 1

                try:
                    raw_url = (
                        row["url"]
                        .strip()
                    )

                    registered_domain = (
                        row[
                            "registered_domain"
                        ]
                        .strip()
                        .lower()
                        .rstrip(".")
                    )

                    source_rank = int(
                        row[
                            "source_rank"
                        ]
                    )

                    source_snapshot = (
                        row[
                            "source_snapshot"
                        ]
                        .strip()
                    )

                    if (
                        not raw_url
                        or not registered_domain
                        or source_rank <= 0
                        or not source_snapshot
                    ):
                        raise ValueError

                except (
                    KeyError,
                    TypeError,
                    ValueError,
                ):
                    print(
                        "Benign candidate audit failed: "
                        "invalid candidate at row "
                        f"{row_number}",
                        file=sys.stderr,
                    )

                    return 1

                try:
                    identity = (
                        normalizer.normalize(
                            raw_url
                        )
                    )

                except (
                    CanonicalURLNormalizationError,
                    TypeError,
                ):
                    normalization_rejected += 1
                    continue

                normalized += 1

                hostname = (
                    identity.hostname
                    .lower()
                    .rstrip(".")
                )

                if not (
                    hostname
                    == registered_domain
                    or hostname.endswith(
                        f".{registered_domain}"
                    )
                ):
                    domain_mismatch += 1
                    continue

                try:
                    features = (
                        extractor.extract(
                            identity.canonical_value
                        )
                    )

                except (
                    URLFeatureExtractionError,
                    TypeError,
                ):
                    feature_rejected += 1
                    continue

                # Les métriques ci-dessous sont des diagnostics
                # d'audit de source. Elles ne font volontairement
                # pas partie du Feature Set ML V1.
                try:
                    parsed = urlsplit(
                        identity.canonical_value
                    )

                    port = parsed.port

                except (
                    UnicodeError,
                    ValueError,
                ):
                    feature_rejected += 1
                    continue

                path = (
                    parsed.path
                    or "/"
                )

                query = (
                    parsed.query
                )

                fragment = (
                    parsed.fragment
                )

                accepted_rows += 1

                if (
                    identity.value_hash
                    in canonical_hashes
                ):
                    duplicate_canonical_urls += 1

                else:
                    canonical_hashes.add(
                        identity.value_hash
                    )

                registered_domains.add(
                    registered_domain
                )

                domain_counts[
                    registered_domain
                ] += 1

                source_snapshots[
                    source_snapshot
                ] += 1

                source_ranks.append(
                    source_rank
                )

                # Features réellement exposées par
                # URLFeatureVector V1.
                url_lengths.append(
                    features.url_length
                )

                hostname_lengths.append(
                    features.hostname_length
                )

                path_segment_counts.append(
                    features.path_segment_count
                )

                # Diagnostics de source uniquement.
                path_lengths.append(
                    len(path)
                )

                query_lengths.append(
                    len(query)
                )

                fragment_lengths.append(
                    len(fragment)
                )

                query_parameter_counts.append(
                    (
                        0
                        if not query
                        else query.count("&") + 1
                    )
                )

                https_count += int(
                    parsed.scheme.lower()
                    == "https"
                )

                ip_count += int(
                    _is_ip_address(
                        hostname
                    )
                )

                # Le CanonicalURLNormalizer retire les ports
                # par défaut. Tout port restant est donc
                # non-default dans la valeur canonique.
                non_default_port_count += int(
                    port is not None
                )

                punycode_count += int(
                    any(
                        label.startswith(
                            "xn--"
                        )
                        for label in hostname.split(
                            "."
                        )
                    )
                )

                percent_encoding_count += int(
                    bool(
                        _PERCENT_ENCODING_PATTERN.search(
                            identity.canonical_value
                        )
                    )
                )

                non_root_path_count += int(
                    len(path) > 1
                )

                query_present_count += int(
                    bool(query)
                )

                fragment_present_count += int(
                    bool(fragment)
                )

    except OSError:
        print(
            "Benign candidate audit failed: "
            "unable to read input file",
            file=sys.stderr,
        )

        return 1

    distinct_canonical_urls = len(
        canonical_hashes
    )

    urls_per_domain = list(
        domain_counts.values()
    )

    print(
        "\n=== HTTP Archive benign audit ==="
    )

    print(
        f"rows_read={rows_read}"
    )

    print(
        f"normalized={normalized}"
    )

    print(
        "normalization_rejected="
        f"{normalization_rejected}"
    )

    print(
        f"domain_mismatch={domain_mismatch}"
    )

    print(
        f"feature_rejected={feature_rejected}"
    )

    print(
        f"accepted_rows={accepted_rows}"
    )

    print(
        "distinct_canonical_urls="
        f"{distinct_canonical_urls}"
    )

    print(
        "duplicate_canonical_urls="
        f"{duplicate_canonical_urls}"
    )

    print(
        "distinct_registered_domains="
        f"{len(registered_domains)}"
    )

    print(
        "source_snapshots="
        f"{len(source_snapshots)}"
    )

    if source_ranks:
        print(
            "source_rank: "
            f"min={min(source_ranks)}, "
            f"max={max(source_ranks)}"
        )

    print(
        "\n=== Structural coverage ==="
    )

    print(
        "https="
        f"{https_count} "
        f"({_percentage(https_count, accepted_rows):.2f}%)"
    )

    print(
        "non_root_path="
        f"{non_root_path_count} "
        f"({_percentage(non_root_path_count, accepted_rows):.2f}%)"
    )

    print(
        "query_present="
        f"{query_present_count} "
        f"({_percentage(query_present_count, accepted_rows):.2f}%)"
    )

    print(
        "fragment_present="
        f"{fragment_present_count} "
        f"({_percentage(fragment_present_count, accepted_rows):.2f}%)"
    )

    print(
        "ip_address="
        f"{ip_count} "
        f"({_percentage(ip_count, accepted_rows):.2f}%)"
    )

    print(
        "non_default_port="
        f"{non_default_port_count} "
        f"({_percentage(non_default_port_count, accepted_rows):.2f}%)"
    )

    print(
        "punycode="
        f"{punycode_count} "
        f"({_percentage(punycode_count, accepted_rows):.2f}%)"
    )

    print(
        "percent_encoding="
        f"{percent_encoding_count} "
        f"({_percentage(percent_encoding_count, accepted_rows):.2f}%)"
    )

    print(
        "\n=== Length distributions ==="
    )

    _print_distribution(
        name="url_length",
        values=url_lengths,
    )

    _print_distribution(
        name="hostname_length",
        values=hostname_lengths,
    )

    _print_distribution(
        name="path_length",
        values=path_lengths,
    )

    _print_distribution(
        name="query_length",
        values=query_lengths,
    )

    _print_distribution(
        name="fragment_length",
        values=fragment_lengths,
    )

    print(
        "\n=== Structure distributions ==="
    )

    _print_distribution(
        name="path_segment_count",
        values=path_segment_counts,
    )

    _print_distribution(
        name="query_parameter_count",
        values=query_parameter_counts,
    )

    print(
        "\n=== Domain concentration ==="
    )

    _print_distribution(
        name="urls_per_registered_domain",
        values=urls_per_domain,
    )

    print(
        "\nAudit completed successfully."
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(
        main()
    )