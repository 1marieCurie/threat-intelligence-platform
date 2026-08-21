import type {
  TopMachine,
} from "../../types/dashboard";


type TopMachinesChartProps = {
  machines: TopMachine[];
};


export function TopMachinesChart({
  machines,
}: TopMachinesChartProps) {
  if (machines.length === 0) {
    return (
      <div className="chart-empty">
        Aucune machine exposée.
      </div>
    );
  }

  const maxExposure =
    Math.max(
      ...machines.map(
        (machine) =>
          machine.exposure_count,
      ),
      1,
    );

  return (
    <div className="machines-chart">
      {machines.map(
        (machine) => {
          const width =
            (
              machine.exposure_count
              / maxExposure
            ) * 100;

          return (
            <div
              key={machine.machine_id}
              className="machine-chart-row"
            >
              <div className="machine-chart-row__header">
                <strong>
                  {machine.hostname}
                </strong>

                <span>
                  {machine.exposure_count}
                  {" "}
                  exposition
                  {machine.exposure_count
                    !== 1
                    ? "s"
                    : ""}
                </span>
              </div>

              <div className="machine-chart-track">
                <div
                  className="machine-chart-bar"
                  style={{
                    width:
                      `${width}%`,
                  }}
                />
              </div>

              <div className="machine-chart-meta">
                <span>
                  Critiques :
                  {" "}
                  {machine.critical_count}
                </span>

                <span>
                  KEV :
                  {" "}
                  {machine.kev_count}
                </span>
              </div>
            </div>
          );
        },
      )}
    </div>
  );
}