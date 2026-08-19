type KPICardProps = {
  label: string;
  value: number;
  detail?: string;

  tone?:
    | "default"
    | "warning"
    | "critical";
};


export function KPICard({
  label,
  value,
  detail,
  tone = "default",
}: KPICardProps) {
  return (
    <article
      className={
        `kpi-card kpi-card--${tone}`
      }
    >
      <span className="kpi-card__label">
        {label}
      </span>

      <strong className="kpi-card__value">
        {value}
      </strong>

      {detail && (
        <span className="kpi-card__detail">
          {detail}
        </span>
      )}
    </article>
  );
}