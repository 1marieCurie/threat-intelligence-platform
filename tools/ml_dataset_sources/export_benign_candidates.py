from __future__ import annotations

from pathlib import Path

from dotenv import load_dotenv


PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parents[2]
)

load_dotenv(
    dotenv_path=PROJECT_ROOT / ".env",
    override=False,
)


import csv
import os
import sys
from datetime import date, datetime, time, timezone

from google.cloud import bigquery


HTTP_ARCHIVE_SNAPSHOT = date(
    2026,
    7,
    1,
)

HTTP_ARCHIVE_CLIENT = "mobile"

MAX_SOURCE_RANK = 300_000
MAX_PAGES_PER_DOMAIN = 5
CANDIDATE_LIMIT = 90_000

SOURCE_SNAPSHOT = (
    "http-archive-"
    f"{HTTP_ARCHIVE_SNAPSHOT.isoformat()}"
    f"-{HTTP_ARCHIVE_CLIENT}"
    "-secondary"
)

OBSERVED_AT = datetime.combine(
    HTTP_ARCHIVE_SNAPSHOT,
    time.min,
    tzinfo=timezone.utc,
)

OUTPUT_PATH = (
    PROJECT_ROOT
    / ".ml-data"
    / (
        "benign_candidates_"
        "http_archive_2026_07.csv"
    )
)


QUERY = """
WITH source_pages AS (
    SELECT
        page AS url,
        NET.REG_DOMAIN(page)
            AS registered_domain,
        rank AS source_rank

    FROM
        `httparchive.crawl.pages`

    WHERE
        date = @snapshot_date
        AND client = @client
        AND is_root_page = FALSE

        AND rank IS NOT NULL
        AND rank BETWEEN
            1 AND @max_source_rank

        AND (
            STARTS_WITH(page, 'https://')
            OR STARTS_WITH(page, 'http://')
        )

        AND NET.REG_DOMAIN(page)
            IS NOT NULL

        AND LENGTH(page)
            BETWEEN 1 AND 4096
),

deduplicated AS (
    SELECT
        url,
        registered_domain,
        MIN(source_rank)
            AS source_rank

    FROM source_pages

    GROUP BY
        url,
        registered_domain
),

ranked AS (
    SELECT
        url,
        registered_domain,
        source_rank,

        ROW_NUMBER() OVER (
            PARTITION BY
                registered_domain
            ORDER BY
                FARM_FINGERPRINT(url)
        ) AS domain_position

    FROM deduplicated
)

SELECT
    url,
    registered_domain,
    source_rank

FROM ranked

WHERE
    domain_position
        <= @max_pages_per_domain

ORDER BY
    source_rank,
    registered_domain,
    domain_position

LIMIT @candidate_limit
"""


def _build_job_config(
) -> bigquery.QueryJobConfig:
    return bigquery.QueryJobConfig(
        query_parameters=[
            bigquery.ScalarQueryParameter(
                "snapshot_date",
                "DATE",
                HTTP_ARCHIVE_SNAPSHOT,
            ),
            bigquery.ScalarQueryParameter(
                "client",
                "STRING",
                HTTP_ARCHIVE_CLIENT,
            ),
            bigquery.ScalarQueryParameter(
                "max_source_rank",
                "INT64",
                MAX_SOURCE_RANK,
            ),
            bigquery.ScalarQueryParameter(
                "max_pages_per_domain",
                "INT64",
                MAX_PAGES_PER_DOMAIN,
            ),
            bigquery.ScalarQueryParameter(
                "candidate_limit",
                "INT64",
                CANDIDATE_LIMIT,
            ),
        ]
    )


def main() -> int:
    project_id = os.getenv(
        "GOOGLE_CLOUD_PROJECT"
    )

    if (
        not isinstance(
            project_id,
            str,
        )
        or not project_id.strip()
    ):
        print(
            "Benign candidate export failed: "
            "GOOGLE_CLOUD_PROJECT is required",
            file=sys.stderr,
        )
        return 1

    OUTPUT_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    try:
        client = bigquery.Client(
            project=project_id.strip()
        )

        result = client.query(
            QUERY,
            job_config=_build_job_config(),
        ).result()

        rows_written = 0
        domains: set[str] = set()

        with OUTPUT_PATH.open(
            "w",
            encoding="utf-8",
            newline="",
        ) as handle:
            writer = csv.writer(
                handle
            )

            writer.writerow(
                [
                    "url",
                    "registered_domain",
                    "source_rank",
                    "source_snapshot",
                    "observed_at",
                ]
            )

            for row in result:
                url = str(
                    row.url
                ).strip()

                registered_domain = str(
                    row.registered_domain
                ).strip().lower()

                source_rank = int(
                    row.source_rank
                )

                if (
                    not url
                    or not registered_domain
                    or source_rank <= 0
                ):
                    continue

                writer.writerow(
                    [
                        url,
                        registered_domain,
                        source_rank,
                        SOURCE_SNAPSHOT,
                        OBSERVED_AT.isoformat(),
                    ]
                )

                domains.add(
                    registered_domain
                )

                rows_written += 1

        print(
            "Benign candidate export completed: "
            f"rows={rows_written}, "
            f"domains={len(domains)}, "
            f"source_snapshot={SOURCE_SNAPSHOT}"
        )

        return 0

    except Exception as error:
        # Ne jamais afficher str(error) :
        # une erreur provider peut contenir
        # des informations de requête ou
        # des données externes.
        print(
            "Benign candidate export failed: "
            f"{type(error).__name__}",
            file=sys.stderr,
        )

        return 1


if __name__ == "__main__":
    raise SystemExit(
        main()
    )