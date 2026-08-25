import {
  useCallback,
  useEffect,
  useState,
} from "react";

import type {
  LucideIcon,
} from "lucide-react";

import {
  ArrowRight,
  BadgeCheck,
  BookOpen,
  Boxes,
  CircleHelp,
  CircleX,
  Clock3,
  Monitor,
  RefreshCw,
  TriangleAlert,
  Zap,
} from "lucide-react";

import {
  Link,
} from "react-router";

import {
  Button,
} from "../../components/ui/Button";
import {
  Card,
} from "../../components/ui/Card";
import {
  ChartContainer,
} from "../../components/ui/ChartContainer";
import {
  getDashboard,
} from "../../lib/api";
import type {
  DashboardSummary,
} from "../../types/dashboard";
import {
  ApplicabilityChart,
} from "./ApplicabilityChart";
import {
  PriorityDonut,
} from "./PriorityDonut";
import {
  TopMachinesChart,
} from "./TopMachinesChart";

import "./dashboard-polish.css";


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


function formatAlertDate(
  value: string,
): string {
  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return "Date indisponible";
  }

  return new Intl.DateTimeFormat(
    "fr-FR",
    {
      day: "2-digit",
      month: "short",
      hour: "2-digit",
      minute: "2-digit",
    },
  ).format(date);
}


export function DashboardPage() {
  const [dashboard, setDashboard] = useState<DashboardSummary | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadDashboard = useCallback(
    async () => {
      setIsLoading(true);
      setError(null);

      try {
        const result = await getDashboard();
        setDashboard(result);
      } catch (caughtError) {
        setDashboard(null);
        setError(
          caughtError instanceof Error
            ? caughtError.message
            : "Une erreur inattendue est survenue.",
        );
      } finally {
        setIsLoading(false);
      }
    },
    [],
  );

  useEffect(() => {
    void loadDashboard();
  }, [loadDashboard]);

  const header = (
    <header className="security-page-header dashboard-page-header">
      <div className="dashboard-page-header__row">
        <div>
          <h1>Dashboard</h1>
          <p>
            Vue synthétique de la posture de sécurité de l'organisation et des éléments à traiter en priorité.
          </p>
        </div>

        <div className="dashboard-page-header__actions">
          <Link
            to="/aide#vulnerabilites"
            className="dashboard-header-link"
          >
            <BookOpen size={15} />
            Comprendre les priorités
          </Link>

          {!isLoading && (
            <Button
              type="button"
              className="dashboard-refresh-button"
              onClick={() => {
                void loadDashboard();
              }}
            >
              <RefreshCw size={14} />
              Actualiser
            </Button>
          )}
        </div>
      </div>
    </header>
  );

  if (isLoading) {
    return (
      <main
        className="security-page"
        aria-busy="true"
      >
        {header}

        <Card>
          <div className="loading-state dashboard-loading-state">
            <span
              className="spinner"
              aria-hidden="true"
            />
            <div>
              <strong>Chargement du dashboard</strong>
              <span>Récupération des indicateurs et des priorités de sécurité...</span>
            </div>
          </div>
        </Card>
      </main>
    );
  }

  if (error) {
    return (
      <main className="security-page">
        {header}

        <Card>
          <div
            className="error-state dashboard-error-state"
            role="alert"
          >
            <CircleX
              size={22}
              aria-hidden="true"
            />
            <div>
              <strong>Dashboard indisponible</strong>
              <span>{error}</span>
            </div>
            <Button
              type="button"
              onClick={() => {
                void loadDashboard();
              }}
            >
              Réessayer
            </Button>
          </div>
        </Card>
      </main>
    );
  }

  if (!dashboard) {
    return (
      <main className="security-page">
        {header}

        <Card>
          <div className="empty-state dashboard-empty-state">
            <Monitor size={22} aria-hidden="true" />
            <div>
              <strong>Aucune donnée disponible</strong>
              <span>
                Importez au moins un inventaire machine pour commencer à alimenter la vue de sécurité.
              </span>
            </div>
            <Link to="/inventaires" className="dashboard-empty-link">
              Importer un inventaire
              <ArrowRight size={14} />
            </Link>
          </div>
        </Card>
      </main>
    );
  }

  return (
    <main className="security-page">
      {header}

      <section
        className="dashboard-statistics"
        aria-label="Indicateurs principaux"
      >
        <DashboardStatistic
          icon={Monitor}
          label="Machines"
          value={dashboard.machine_count}
        />
        <DashboardStatistic
          icon={Boxes}
          label="Composants"
          value={dashboard.component_count}
        />
        <DashboardStatistic
          icon={BadgeCheck}
          label="Confirmed"
          value={dashboard.confirmed_exposure_count}
          tone="success"
        />
        <DashboardStatistic
          icon={CircleHelp}
          label="Potential"
          value={dashboard.potential_exposure_count}
        />
        <DashboardStatistic
          icon={TriangleAlert}
          label="Critiques"
          value={dashboard.critical_exposure_count}
          tone={
            dashboard.critical_exposure_count > 0
              ? "critical"
              : "default"
          }
        />
        <DashboardStatistic
          icon={Zap}
          label="KEV"
          value={dashboard.kev_exposure_count}
          tone={
            dashboard.kev_exposure_count > 0
              ? "critical"
              : "default"
          }
        />
        <DashboardStatistic
          icon={Clock3}
          label="Alertes en attente"
          value={dashboard.pending_alert_count}
          tone={
            dashboard.pending_alert_count > 0
              ? "warning"
              : "default"
          }
        />
        <DashboardStatistic
          icon={CircleX}
          label="Alertes échouées"
          value={dashboard.failed_alert_count}
          tone={
            dashboard.failed_alert_count > 0
              ? "critical"
              : "default"
          }
        />
      </section>

      <section className="dashboard-workspace">
        <div className="dashboard-main-column">
          <ChartContainer
            title="Machines les plus exposées"
            description="Top 5 selon le nombre d'expositions détectées."
          >
            <TopMachinesChart machines={dashboard.top_machines} />
          </ChartContainer>

          <ChartContainer
            title="Applicabilité"
            description="Répartition entre les expositions confirmed et potential."
          >
            <ApplicabilityChart
              confirmed={dashboard.confirmed_exposure_count}
              potential={dashboard.potential_exposure_count}
            />
          </ChartContainer>

          <Card className="dashboard-panel">
            <div className="dashboard-section-header dashboard-section-header--with-link">
              <div>
                <h2>Actions prioritaires</h2>
                <p>Éléments qui méritent votre attention en premier.</p>
              </div>
              <Link
                to="/vulnerabilites"
                className="dashboard-section-link"
              >
                Voir les vulnérabilités
                <ArrowRight size={13} />
              </Link>
            </div>

            {dashboard.priority_actions.length === 0 ? (
              <div className="dashboard-empty">
                <strong>Aucune action prioritaire</strong>
                <span>Aucun élément ne nécessite une attention immédiate.</span>
              </div>
            ) : (
              <div className="priority-activity">
                {dashboard.priority_actions.map((action) => (
                  <article
                    key={`${action.kind}-${action.title}`}
                    className="priority-activity__item"
                  >
                    <span
                      className="activity-icon activity-icon--warning"
                      aria-hidden="true"
                    >
                      <TriangleAlert size={14} strokeWidth={1.8} />
                    </span>

                    <div className="activity-content">
                      <strong>{action.title}</strong>
                      <span>Priorité {action.priority}</span>
                    </div>

                    <strong
                      className="activity-count"
                      aria-label={`${action.count} éléments`}
                    >
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
            description="Expositions par niveau de priorité."
          >
            <PriorityDonut distribution={dashboard.priority_distribution} />
          </ChartContainer>

          <Card className="dashboard-panel">
            <div className="dashboard-section-header dashboard-section-header--with-link">
              <div>
                <h2>Dernières alertes</h2>
                <p>Événements de sécurité les plus récents.</p>
              </div>
              <Link
                to="/alertes"
                className="dashboard-section-link"
              >
                Tout voir
                <ArrowRight size={13} />
              </Link>
            </div>

            {dashboard.latest_alerts.length === 0 ? (
              <div className="dashboard-empty">
                <strong>Aucune alerte</strong>
                <span>Aucune alerte n'est actuellement enregistrée.</span>
              </div>
            ) : (
              <div className="alert-activity">
                {dashboard.latest_alerts.map((alert) => (
                  <Link
                    key={alert.alert_id}
                    to={`/alertes/${alert.alert_id}`}
                    className="alert-activity__item dashboard-alert-link"
                  >
                    <div className="activity-timeline">
                      <span
                        className="activity-icon"
                        aria-hidden="true"
                      >
                        <TriangleAlert size={13} strokeWidth={1.8} />
                      </span>
                    </div>

                    <div className="activity-content">
                      <strong>{alert.hostname}</strong>
                      <span>{alert.alert_type}</span>
                      <span className="dashboard-alert-meta">
                        {formatAlertDate(alert.created_at)}
                        {alert.priority
                          ? ` · ${alert.priority}`
                          : ""}
                      </span>
                      <span
                        className={
                          "activity-status "
                          + `activity-status--${alert.status}`
                        }
                      >
                        {alert.status}
                      </span>
                    </div>
                  </Link>
                ))}
              </div>
            )}
          </Card>
        </aside>
      </section>
    </main>
  );
}
