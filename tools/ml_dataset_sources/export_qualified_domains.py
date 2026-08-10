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
    / "qualified_domains.csv"
)

DOMAIN_LIMIT = 15_000
MAX_TRANCO_RANK = 100_000


QUERY = """
WITH latest_tranco_date AS (
    SELECT
        MAX(date) AS list_date
    FROM `tranco.daily.daily`
),

tranco_candidates AS (
    SELECT
        t.domain,
        t.rank
    FROM `tranco.daily.daily` AS t
    CROSS JOIN latest_tranco_date AS latest
    WHERE t.date = latest.list_date
      AND t.rank <= @max_tranco_rank
),

crux_domains AS (
    SELECT DISTINCT
        NET.REG_DOMAIN(origin)
            AS registered_domain
    FROM
        `chrome-ux-report.materialized.origin_summary`
    WHERE
        NET.REG_DOMAIN(origin) IS NOT NULL
)

SELECT
    t.domain AS registered_domain,
    t.rank AS tranco_rank
FROM tranco_candidates AS t
INNER JOIN crux_domains AS c
    ON c.registered_domain = t.domain
ORDER BY
    t.rank ASC,
    t.domain ASC
LIMIT @domain_limit
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
            "Qualified-domain export failed: "
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
                        "domain_limit",
                        "INT64",
                        DOMAIN_LIMIT,
                    ),
                ]
            )
        )

        result = client.query(
            QUERY,
            job_config=job_config,
        ).result()

        rows_written = 0

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
                    "registered_domain",
                    "tranco_rank",
                ]
            )

            for row in result:
                domain = str(
                    row.registered_domain
                ).strip()

                rank = int(
                    row.tranco_rank
                )

                if not domain:
                    continue

                writer.writerow(
                    [
                        domain,
                        rank,
                    ]
                )

                rows_written += 1

        print(
            "Qualified-domain export completed: "
            f"rows={rows_written}"
        )

        return (
            0
            if rows_written == DOMAIN_LIMIT
            else 2
        )

    except Exception as error:
        # Provider/query contents and credentials
        # are intentionally not printed.
        print(
            "Qualified-domain export failed: "
            f"{type(error).__name__}",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(
        main()
    )