type ApplicabilityChartProps = {
  confirmed: number;
  potential: number;
};


export function ApplicabilityChart({
  confirmed,
  potential,
}: ApplicabilityChartProps) {
  const total =
    confirmed + potential;

  if (total === 0) {
    return (
      <div className="chart-empty">
        Aucune exposition disponible.
      </div>
    );
  }

  const maxValue =
    Math.max(
      confirmed,
      potential,
      1,
    );

  const confirmedWidth =
    (confirmed / maxValue) * 100;

  const potentialWidth =
    (potential / maxValue) * 100;

  return (
    <div className="comparison-chart">
      <div className="comparison-row">
        <div className="comparison-row__label">
          <span>
            Confirmed
          </span>

          <strong>
            {confirmed}
          </strong>
        </div>

        <div className="comparison-track">
          <div
            className={
              "comparison-bar "
              + "comparison-bar--confirmed"
            }
            style={{
              width:
                `${confirmedWidth}%`,
            }}
          />
        </div>
      </div>

      <div className="comparison-row">
        <div className="comparison-row__label">
          <span>
            Potential
          </span>

          <strong>
            {potential}
          </strong>
        </div>

        <div className="comparison-track">
          <div
            className={
              "comparison-bar "
              + "comparison-bar--potential"
            }
            style={{
              width:
                `${potentialWidth}%`,
            }}
          />
        </div>
      </div>
    </div>
  );
}