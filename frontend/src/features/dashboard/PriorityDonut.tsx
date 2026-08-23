import type {
  PriorityDistribution,
} from "../../types/dashboard";

import "./PriorityDonut.css";


type PriorityDonutProps = {
  distribution: PriorityDistribution;
};


type Segment = {
  label: string;
  value: number;
  modifier: string;
};


const RADIUS = 44;

const CIRCUMFERENCE =
  2 * Math.PI * RADIUS;


export function PriorityDonut({
  distribution,
}: PriorityDonutProps) {
  const segments: Segment[] = [
    {
      label: "LOW",
      value: distribution.low,
      modifier: "low",
    },
    {
      label: "MEDIUM",
      value: distribution.medium,
      modifier: "medium",
    },
    {
      label: "HIGH",
      value: distribution.high,
      modifier: "high",
    },
    {
      label: "CRITICAL",
      value: distribution.critical,
      modifier: "critical",
    },
  ].map(
    (segment) => ({
      ...segment,

      value:
        Number.isFinite(
          segment.value,
        )
          ? Math.max(
              0,
              segment.value,
            )
          : 0,
    }),
  );


  const total = segments.reduce(
    (
      sum,
      segment,
    ) => (
      sum
      + segment.value
    ),
    0,
  );


  const activeSegments =
    segments.filter(
      (
        segment,
      ) => (
        segment.value > 0
      ),
    );


  if (
    total === 0
  ) {
    return (
      <div
        className={
          "priority-donut-v2 "
          + "priority-donut-v2--empty"
        }
      >
        <div className="priority-donut-v2__visual">
          <svg
            viewBox="0 0 120 120"
            role="img"
            aria-label={
              "Aucune exposition "
              + "avec une priorité"
            }
          >
            <circle
              cx="60"
              cy="60"
              r={RADIUS}
              className={
                "priority-donut-v2__track"
              }
            />
          </svg>

          <div className="priority-donut-v2__center">
            <strong>
              0
            </strong>

            <span>
              exposition
            </span>
          </div>
        </div>

        <div className="priority-donut-v2__empty-message">
          <strong>
            Aucune priorité
          </strong>

          <span>
            Aucune exposition priorisée
            n'est actuellement détectée.
          </span>
        </div>
      </div>
    );
  }


  let accumulatedRatio = 0;


  const ariaDescription =
    activeSegments
      .map(
        (
          segment,
        ) => (
          `${segment.label}: `
          + `${segment.value}`
        ),
      )
      .join(", ");


  return (
    <div className="priority-donut-v2">
      <div className="priority-donut-v2__visual">
        <svg
          viewBox="0 0 120 120"
          role="img"
          aria-label={
            "Répartition des priorités. "
            + ariaDescription
          }
        >
          <circle
            cx="60"
            cy="60"
            r={RADIUS}
            className={
              "priority-donut-v2__track"
            }
          />

          {activeSegments.map(
            (
              segment,
            ) => {
              const ratio =
                segment.value
                / total;

              const segmentLength =
                ratio
                * CIRCUMFERENCE;

              const offset =
                -accumulatedRatio
                * CIRCUMFERENCE;

              accumulatedRatio +=
                ratio;


              return (
                <circle
                  key={
                    segment.label
                  }
                  cx="60"
                  cy="60"
                  r={RADIUS}
                  className={
                    "priority-donut-v2__segment "
                    + (
                      "priority-donut-v2__segment--"
                      + segment.modifier
                    )
                  }
                  strokeDasharray={
                    `${segmentLength} `
                    + (
                      CIRCUMFERENCE
                      - segmentLength
                    )
                  }
                  strokeDashoffset={
                    offset
                  }
                >
                  <title>
                    {segment.label}
                    {": "}
                    {segment.value}
                    {" ("}
                    {Math.round(
                      ratio * 100,
                    )}
                    {" %)"}
                  </title>
                </circle>
              );
            },
          )}
        </svg>

        <div className="priority-donut-v2__center">
          <strong>
            {total}
          </strong>

          <span>
            {total === 1
              ? "exposition"
              : "expositions"}
          </span>
        </div>
      </div>

      <div
        className="priority-donut-v2__legend"
        aria-label="Détail des priorités"
      >
        {activeSegments.map(
          (
            segment,
          ) => {
            const percentage =
              Math.round(
                (
                  segment.value
                  / total
                )
                * 100,
              );


            return (
              <div
                key={
                  segment.label
                }
                className={
                  "priority-donut-v2__legend-row"
                }
              >
                <span
                  className={
                    "priority-donut-v2__dot "
                    + (
                      "priority-donut-v2__dot--"
                      + segment.modifier
                    )
                  }
                  aria-hidden="true"
                />

                <span
                  className={
                    "priority-donut-v2__legend-label"
                  }
                >
                  {segment.label}
                </span>

                <span
                  className={
                    "priority-donut-v2__legend-value"
                  }
                >
                  <strong>
                    {segment.value}
                  </strong>

                  <small>
                    {percentage} %
                  </small>
                </span>
              </div>
            );
          },
        )}
      </div>
    </div>
  );
}