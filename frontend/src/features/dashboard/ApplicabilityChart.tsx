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

  const maxValue = Math.max(
    confirmed,
    potential,
    1,
  );

  const confirmedHeight = Math.max(
    confirmed > 0
      ? (confirmed / maxValue) * 100
      : 0,
    confirmed > 0 ? 12 : 0,
  );

  const potentialHeight = Math.max(
    potential > 0
      ? (potential / maxValue) * 100
      : 0,
    potential > 0 ? 12 : 0,
  );

  const confirmedPercent =
    (confirmed / total) * 100;

  const potentialPercent =
    (potential / total) * 100;

  return (
    <div
      className="applicability-histogram"
      role="img"
      aria-label={
        `${confirmed} expositions confirmed et ${potential} expositions potential`
      }
    >
      <div className="applicability-histogram__column">
        <div className="applicability-histogram__plot" aria-hidden="true">
          <span
            className="applicability-histogram__bar applicability-histogram__bar--confirmed"
            style={{ height: `${confirmedHeight}%` }}
          />
        </div>
        <strong>{confirmed}</strong>
        <span>Confirmed</span>
        <small>{confirmedPercent.toFixed(0)}% du total</small>
      </div>

      <div className="applicability-histogram__column">
        <div className="applicability-histogram__plot" aria-hidden="true">
          <span
            className="applicability-histogram__bar applicability-histogram__bar--potential"
            style={{ height: `${potentialHeight}%` }}
          />
        </div>
        <strong>{potential}</strong>
        <span>Potential</span>
        <small>{potentialPercent.toFixed(0)}% du total</small>
      </div>

      <div className="applicability-histogram__summary">
        <strong>{total}</strong>
        <span>expositions évaluées</span>
      </div>
    </div>
  );
}
