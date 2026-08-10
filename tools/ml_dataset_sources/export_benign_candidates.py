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

from google.cloud import bigquery


OUTPUT_PATH = (
    PROJECT_ROOT
    / ".ml-data"
    / "benign_candidates.csv"
)

MAX_TRANCO_RANK = 100_000
MAX_ORIGINS_PER_DOMAIN = 5
CANDIDATE_LIMIT = 90_000

CRUX_SNAPSHOT = "2026-06"


QUERY = """
WITH latest_tranco_date AS (
    SELECT
        MAX(date) AS list_date
    FROM `tranco.daily.daily`
),

tranco_candidates AS (
    SELECT
        t.domain AS registered_domain,
        t.rank AS tranco_rank,
        latest.list_date AS tranco_date
    FROM `tranco.daily.daily` AS t
    CROSS JOIN latest_tranco_date AS latest
    WHERE
        t.date = latest.list_date
        AND t.rank <= @max_tranco_rank
),

crux_origins AS (
    SELECT DISTINCT
        origin AS url,
        NET.REG_DOMAIN(origin)
            AS registered_domain
    FROM
        `chrome-ux-report.materialized.origin_summary`
    WHERE
        NET.REG_DOMAIN(origin) IS NOT NULL
        AND (
            STARTS_WITH(origin, 'https://')
            OR STARTS_WITH(origin, 'http://')
        )
),

ranked AS (
    SELECT
        crux.url,
        crux.registered_domain,
        tranco.tranco_rank,
        tranco.tranco_date,

        ROW_NUMBER() OVER (
            PARTITION BY
                crux.registered_domain
            ORDER BY
                FARM_FINGERPRINT(crux.url)
        ) AS domain_position

    FROM crux_origins AS crux

    INNER JOIN tranco_candidates AS tranco
        ON (
            tranco.registered_domain
            =
            crux.registered_domain
        )
)

SELECT
    url,
    registered_domain,
    tranco_rank,
    tranco_date

FROM ranked

WHERE
    domain_position <= @max_origins_per_domain

ORDER BY
    tranco_rank,
    registered_domain,
    domain_position

LIMIT @candidate_limit
"""


def main() -> int:
    project_id = os.getenv(
        "GOOGLE_CLOUD_PROJECT"
    )

    if (
        not isinstance(project_id, str)
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

        job_config = (
            bigquery.QueryJobConfig(
                query_parameters=[
                    bigquery.ScalarQueryParameter(
                        "max_tranco_rank",
                        "INT64",
                        MAX_TRANCO_RANK,
                    ),
                    bigquery.ScalarQueryParameter(
                        "max_origins_per_domain",
                        "INT64",
                        MAX_ORIGINS_PER_DOMAIN,
                    ),
                    bigquery.ScalarQueryParameter(
                        "candidate_limit",
                        "INT64",
                        CANDIDATE_LIMIT,
                    ),
                ]
            )
        )

        result = client.query(
            QUERY,
            job_config=job_config,
        ).result()

        rows_written = 0
        domains: set[str] = set()
        source_snapshot: str | None = None

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
                    "tranco_rank",
                    "source_snapshot",
                ]
            )

            for row in result:
                url = str(
                    row.url
                ).strip()

                registered_domain = str(
                    row.registered_domain
                ).strip().lower()

                tranco_rank = int(
                    row.tranco_rank
                )

                tranco_date = str(
                    row.tranco_date
                )

                snapshot = (
                    f"tranco-{tranco_date}"
                    f"+crux-{CRUX_SNAPSHOT}"
                )

                if (
                    not url
                    or not registered_domain
                ):
                    continue

                writer.writerow(
                    [
                        url,
                        registered_domain,
                        tranco_rank,
                        snapshot,
                    ]
                )

                domains.add(
                    registered_domain
                )

                source_snapshot = snapshot
                rows_written += 1

        print(
            "Benign candidate export completed: "
            f"rows={rows_written}, "
            f"domains={len(domains)}, "
            "source_snapshot="
            f"{source_snapshot}"
        )

        return 0

    except Exception as error:
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