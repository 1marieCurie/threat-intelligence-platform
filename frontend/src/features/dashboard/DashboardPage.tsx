import {
  useEffect,
  useState,
} from "react";

import {
  Card,
} from "../../components/ui/Card";

import {
  KPICard,
} from "../../components/ui/KPICard";

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

      <section className="kpi-grid">
        <KPICard
          label="Machines"
          value={
            dashboard.machine_count
          }
        />

        <KPICard
          label="Composants inventoriés"
          value={
            dashboard.component_count
          }
        />

        <KPICard
          label="Expositions confirmed"
          value={
            dashboard
              .confirmed_exposure_count
          }
        />

        <KPICard
          label="Expositions potential"
          value={
            dashboard
              .potential_exposure_count
          }
        />

        <KPICard
          label="Expositions critiques"
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

        <KPICard
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

        <KPICard
          label="Alertes pending"
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

        <KPICard
          label="Alertes failed"
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

      <section className="dashboard-charts">
        <ChartContainer
          title="Répartition des priorités"
          description={
            "Expositions par niveau de priorité."
          }
        >
          <PriorityDonut
            distribution={
              dashboard
                .priority_distribution
            }
          />
        </ChartContainer>

        <ChartContainer
          title="Applicabilité"
          description={
            "Comparaison confirmed et potential."
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
      </section>

      <section className="dashboard-columns">
        <Card>
          <div className="dashboard-section-header">
            <div>
              <h2>
                Actions prioritaires
              </h2>

              <p>
                Calculées par le backend à
                partir des expositions et
                alertes persistées.
              </p>
            </div>
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
            <div className="action-list">
              {dashboard
                .priority_actions
                .map((action) => (
                  <article
                    key={action.kind}
                    className="action-item"
                  >
                    <div>
                      <strong>
                        {action.title}
                      </strong>

                      <span>
                        Priorité{" "}
                        {action.priority}
                      </span>
                    </div>

                    <strong className="action-count">
                      {action.count}
                    </strong>
                  </article>
                ))}
            </div>
          )}
        </Card>

        <Card>
          <div className="dashboard-section-header">
            <div>
              <h2>
                Dernières alertes
              </h2>

              <p>
                Alertes persistées les
                plus récentes.
              </p>
            </div>
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
            <div className="alert-list">
              {dashboard
                .latest_alerts
                .map((alert) => (
                  <article
                    key={
                      alert.alert_id
                    }
                    className="alert-row"
                  >
                    <div>
                      <strong>
                        {alert.hostname}
                      </strong>

                      <span>
                        {alert.alert_type}
                      </span>
                    </div>

                    <span
                      className={
                        "alert-status "
                        + (
                          `alert-status--${alert.status}`
                        )
                      }
                    >
                      {alert.status}
                    </span>
                  </article>
                ))}
            </div>
          )}
        </Card>
      </section>
    </main>
  );
}