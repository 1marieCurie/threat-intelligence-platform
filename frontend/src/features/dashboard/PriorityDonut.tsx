import type {
  PriorityDistribution,
} from "../../types/dashboard";


type PriorityDonutProps = {
  distribution: PriorityDistribution;
};


type Segment = {
  label: string;
  value: number;
  className: string;
};


const RADIUS = 42;

const CIRCUMFERENCE =
  2 * Math.PI * RADIUS;


export function PriorityDonut({
  distribution,
}: PriorityDonutProps) {
  const segments: Segment[] = [
    {
      label: "LOW",
      value: distribution.low,
      className: "priority-low",
    },
    {
      label: "MEDIUM",
      value: distribution.medium,
      className: "priority-medium",
    },
    {
      label: "HIGH",
      value: distribution.high,
      className: "priority-high",
    },
    {
      label: "CRITICAL",
      value: distribution.critical,
      className: "priority-critical",
    },
  ];

  const total = segments.reduce(
    (sum, segment) =>
      sum + segment.value,
    0,
  );

  if (total === 0) {
    return (
      <div className="chart-empty">
        Aucune exposition avec une priorité
        disponible.
      </div>
    );
  }

  let accumulatedRatio = 0;

  return (
    <div className="priority-chart">
      <div className="priority-donut">
        <svg
          viewBox="0 0 120 120"
          role="img"
          aria-label="Répartition des priorités"
        >
          <circle
            cx="60"
            cy="60"
            r={RADIUS}
            className="donut-track"
          />

          {segments.map(
            (segment) => {
              if (segment.value === 0) {
                return null;
              }

              const ratio =
                segment.value / total;

              const segmentLength =
                ratio * CIRCUMFERENCE;

              const offset =
                -accumulatedRatio
                * CIRCUMFERENCE;

              accumulatedRatio += ratio;

              return (
                <circle
                  key={segment.label}
                  cx="60"
                  cy="60"
                  r={RADIUS}
                  className={
                    `donut-segment ${segment.className}`
                  }
                  strokeDasharray={
                    `${segmentLength} `
                    + `${CIRCUMFERENCE - segmentLength}`
                  }
                  strokeDashoffset={offset}
                />
              );
            },
          )}
        </svg>

        <div className="donut-center">
          <strong>
            {total}
          </strong>

          <span>
            expositions
          </span>
        </div>
      </div>

      <div className="chart-legend">
        {segments.map(
          (segment) => (
            <div
              key={segment.label}
              className="chart-legend__row"
            >
              <span
                className={
                  `legend-dot ${segment.className}`
                }
              />

              <span>
                {segment.label}
              </span>

              <strong>
                {segment.value}
              </strong>
            </div>
          ),
        )}
      </div>
    </div>
  );
}