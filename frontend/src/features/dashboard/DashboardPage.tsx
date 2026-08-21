import {
  useEffect,
  useState,
} from "react";

import type {
  LucideIcon,
} from "lucide-react";

import {
  BadgeCheck,
  Boxes,
  CircleHelp,
  CircleX,
  Clock3,
  Monitor,
  TriangleAlert,
  Zap,
} from "lucide-react";

import {
  Card,
} from "../../components/ui/Card";

import {
  getDashboard,
} from "../../lib/api";

import type {
  DashboardSummary,
} from "../../types/dashboard";

import {
  ChartContainer,
} from "../../components/ui/ChartContainer";

import {
  ApplicabilityChart,
} from "./ApplicabilityChart";

import {
  PriorityDonut,
} from "./PriorityDonut";

import {
  TopMachinesChart,
} from "./TopMachinesChart";


type StatisticTone =
  | "default"
  | "warning"
  | "critical"
  | "success";


type DashboardStatisticProps = {
  icon: LucideIcon;
  label: string;
  value: number;
  tone?: StatisticTone;
};


function DashboardStatistic({
  icon: Icon,
  label,
  value,
  tone = "default",
}: DashboardStatisticProps) {
  return (
    <div
      className={
        "dashboard-statistic "
        + `dashboard-statistic--${tone}`
      }
    >
      <span
        className="dashboard-statistic__icon"
        aria-hidden="true"
      >
        <Icon
          size={17}
          strokeWidth={1.8}
        />
      </span>

      <div className="dashboard-statistic__content">
        <strong className="dashboard-statistic__value">
          {value}
        </strong>

        <span className="dashboard-statistic__label">
          {label}
        </span>
      </div>
    </div>
  );
}


export function DashboardPage() {
  const [
    dashboard,
    setDashboard,
  ] = useState<
    DashboardSummary | null
  >(null);

  const [
    isLoading,
    setIsLoading,
  ] = useState(true);

  const [
    error,
    setError,
  ] = useState<
    string | null
  >(null);


  useEffect(() => {
    let cancelled = false;

    async function loadDashboard() {
      setIsLoading(true);
      setError(null);

      try {
        const result =
          await getDashboard();

        if (!cancelled) {
          setDashboard(
            result,
          );
        }
      } catch (caughtError) {
        if (!cancelled) {
          setError(
            caughtError
              instanceof Error
              ? caughtError.message
              : (
                "Une erreur inattendue "
                + "est survenue."
              ),
          );
        }
      } finally {
        if (!cancelled) {
          setIsLoading(
            false,
          );
        }
      }
    }

    void loadDashboard();

    return () => {
      cancelled = true;
    };
  }, []);


  if (isLoading) {
    return (
      <main className="security-page">
        <header className="security-page-header">
          <h1>
            Dashboard
          </h1>

          <p>
            Vue synthétique de la posture
            de sécurité de l'organisation.
          </p>
        </header>

        <Card>
          <div className="loading-state">
            <span
              className="spinner"
              aria-hidden="true"
            />

            <span>
              Chargement du dashboard...
            </span>
          </div>
        </Card>
      </main>
    );
  }


  if (error) {
    return (
      <main className="security-page">
        <header className="security-page-header">
          <h1>
            Dashboard
          </h1>
        </header>

        <Card>
          <div className="error-state">
            <strong>
              Dashboard indisponible
            </strong>

            <span>
              {error}
            </span>
          </div>
        </Card>
      </main>
    );
  }


  if (!dashboard) {
    return (
      <main className="security-page">
        <header className="security-page-header">
          <h1>
            Dashboard
          </h1>
        </header>

        <Card>
          <div className="empty-state">
            Aucune donnée Dashboard
            disponible.
          </div>
        </Card>
      </main>
    );
  }


  return (
    <main className="security-page">
      <header className="security-page-header">
        <h1>
          Dashboard
        </h1>

        <p>
          Vue synthétique de la posture
          de sécurité de l'organisation.
        </p>
      </header>

      <section
        className="dashboard-statistics"
        aria-label="Indicateurs principaux"
      >
        <DashboardStatistic
          icon={Monitor}
          label="Machines"
          value={
            dashboard.machine_count
          }
        />

        <DashboardStatistic
          icon={Boxes}
          label="Composants"
          value={
            dashboard.component_count
          }
        />

        <DashboardStatistic
          icon={BadgeCheck}
          label="Confirmed"
          value={
            dashboard
              .confirmed_exposure_count
          }
          tone="success"
        />

        <DashboardStatistic
          icon={CircleHelp}
          label="Potential"
          value={
            dashboard
              .potential_exposure_count
          }
        />

        <DashboardStatistic
          icon={TriangleAlert}
          label="Critiques"
          value={
            dashboard
              .critical_exposure_count
          }
          tone={
            dashboard
              .critical_exposure_count
              > 0
              ? "critical"
              : "default"
          }
        />

        <DashboardStatistic
          icon={Zap}
          label="KEV"
          value={
            dashboard
              .kev_exposure_count
          }
          tone={
            dashboard
              .kev_exposure_count
              > 0
              ? "critical"
              : "default"
          }
        />

        <DashboardStatistic
          icon={Clock3}
          label="Pending"
          value={
            dashboard
              .pending_alert_count
          }
          tone={
            dashboard
              .pending_alert_count
              > 0
              ? "warning"
              : "default"
          }
        />

        <DashboardStatistic
          icon={CircleX}
          label="Failed"
          value={
            dashboard
              .failed_alert_count
          }
          tone={
            dashboard
              .failed_alert_count
              > 0
              ? "critical"
              : "default"
          }
        />
      </section>

      <section className="dashboard-workspace">
        <div className="dashboard-main-column">
          <ChartContainer
            title="Machines les plus exposées"
            description={
              "Top 5 selon le nombre "
              + "d'expositions détectées."
            }
          >
            <TopMachinesChart
              machines={
                dashboard.top_machines
              }
            />
          </ChartContainer>

          <ChartContainer
            title="Applicabilité"
            description={
              "Répartition entre les expositions "
              + "confirmed et potential."
            }
          >
            <ApplicabilityChart
              confirmed={
                dashboard
                  .confirmed_exposure_count
              }
              potential={
                dashboard
                  .potential_exposure_count
              }
            />
          </ChartContainer>

          <Card className="dashboard-panel">
            <div className="dashboard-section-header">
              <h2>
                Actions prioritaires
              </h2>
            </div>

            {dashboard
              .priority_actions
              .length === 0 ? (
              <div className="dashboard-empty">
                <strong>
                  Aucune action prioritaire
                </strong>

                <span>
                  Aucun élément ne nécessite
                  une attention immédiate.
                </span>
              </div>
            ) : (
              <div className="priority-activity">
                {dashboard
                  .priority_actions
                  .map((action) => (
                    <article
                      key={
                        `${action.kind}-${action.title}`
                      }
                      className="priority-activity__item"
                    >
                      <span
                        className="activity-icon activity-icon--warning"
                        aria-hidden="true"
                      >
                        <TriangleAlert
                          size={14}
                          strokeWidth={1.8}
                        />
                      </span>

                      <div className="activity-content">
                        <strong>
                          {action.title}
                        </strong>

                        <span>
                          Priorité{" "}
                          {action.priority}
                        </span>
                      </div>

                      <strong className="activity-count">
                        {action.count}
                      </strong>
                    </article>
                  ))}
              </div>
            )}
          </Card>
        </div>

        <aside className="dashboard-side-column">
          <ChartContainer
            title="Répartition des priorités"
            description={
              "Expositions par niveau "
              + "de priorité."
            }
          >
            <PriorityDonut
              distribution={
                dashboard
                  .priority_distribution
              }
            />
          </ChartContainer>

          <Card className="dashboard-panel">
            <div className="dashboard-section-header">
              <h2>
                Dernières alertes
              </h2>
            </div>

            {dashboard
              .latest_alerts
              .length === 0 ? (
              <div className="dashboard-empty">
                <strong>
                  Aucune alerte
                </strong>

                <span>
                  Aucune alerte n'est
                  actuellement enregistrée.
                </span>
              </div>
            ) : (
              <div className="alert-activity">
                {dashboard
                  .latest_alerts
                  .map((alert) => (
                    <article
                      key={
                        alert.alert_id
                      }
                      className="alert-activity__item"
                    >
                      <div className="activity-timeline">
                        <span
                          className="activity-icon"
                          aria-hidden="true"
                        >
                          <TriangleAlert
                            size={13}
                            strokeWidth={1.8}
                          />
                        </span>
                      </div>

                      <div className="activity-content">
                        <strong>
                          {alert.hostname}
                        </strong>

                        <span>
                          {alert.alert_type}
                        </span>

                        <span
                          className={
                            "activity-status "
                            + (
                              `activity-status--${alert.status}`
                            )
                          }
                        >
                          {alert.status}
                        </span>
                      </div>
                    </article>
                  ))}
              </div>
            )}
          </Card>
        </aside>
      </section>
    </main>
  );
}