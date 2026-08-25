import {
  useCallback,
  useEffect,
  useMemo,
  useState,
} from "react";

import {
  BellRing,
  BookOpen,
  CircleCheck,
  CircleX,
  Clock3,
  RefreshCw,
  Search,
  ShieldAlert,
  TriangleAlert,
  Zap,
} from "lucide-react";

import type {
  LucideIcon,
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
  Input,
} from "../../components/ui/Input";
import {
  Table,
} from "../../components/ui/Table";
import {
  getAlerts,
} from "../../lib/api";
import type {
  AlertStatus,
  AlertSummary,
  AlertType,
} from "../../types/alert";

import "./alerts.css";
import "./alerts-polish.css";


type AlertStatusFilter = "all" | AlertStatus;
type AlertTypeFilter = "all" | AlertType;

function isAlertStatusFilter(value: string): value is AlertStatusFilter {
  return ["all", "pending", "sent", "failed"].includes(value);
}

function isAlertTypeFilter(value: string): value is AlertTypeFilter {
  return [
    "all",
    "new_confirmed_critical_exposure",
    "confirmed_exposure_entered_kev",
    "priority_transition_to_critical",
  ].includes(value);
}

function displayAlertType(value: AlertType): string {
  if (value === "new_confirmed_critical_exposure") {
    return "Nouvelle exposition critique";
  }

  if (value === "confirmed_exposure_entered_kev") {
    return "Entrée dans CISA KEV";
  }

  return "Passage en priorité critique";
}

function displayStatus(value: AlertStatus): string {
  if (value === "pending") {
    return "En attente";
  }

  if (value === "sent") {
    return "Envoyée";
  }

  return "Échec";
}

function displayIdentifier(alert: AlertSummary): string {
  return alert.primary_identifier
    ?? alert.canonical_vulnerability_id.slice(0, 8);
}

function displayDate(value: string | null): string {
  if (value === null) {
    return "—";
  }

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return value;
  }

  return date.toLocaleString(
    "fr-FR",
    {
      day: "2-digit",
      month: "2-digit",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    },
  );
}


type AlertStatisticTone = "default" | "warning" | "success" | "critical";

type AlertStatisticProps = {
  icon: LucideIcon;
  value: number;
  label: string;
  tone?: AlertStatisticTone;
};

function AlertStatistic({
  icon: Icon,
  value,
  label,
  tone = "default",
}: AlertStatisticProps) {
  return (
    <div className={`alert-statistic alert-statistic--${tone}`}>
      <span className="alert-statistic__icon" aria-hidden="true">
        <Icon size={17} strokeWidth={1.8} />
      </span>
      <div className="alert-statistic__content">
        <strong>{value}</strong>
        <span>{label}</span>
      </div>
    </div>
  );
}

function priorityClass(value: string | null): string {
  return `alerts-priority alerts-priority--${(value ?? "unknown").toLowerCase()}`;
}

function alertTypeIcon(type: AlertType) {
  if (type === "confirmed_exposure_entered_kev") {
    return <Zap size={14} strokeWidth={1.9} />;
  }

  if (type === "priority_transition_to_critical") {
    return <TriangleAlert size={14} strokeWidth={1.8} />;
  }

  return <ShieldAlert size={14} strokeWidth={1.8} />;
}


export function AlertsPage() {
  const [alerts, setAlerts] = useState<AlertSummary[]>([]);
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState<AlertStatusFilter>("all");
  const [typeFilter, setTypeFilter] = useState<AlertTypeFilter>("all");
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadAlerts = useCallback(async () => {
    setIsLoading(true);
    setError(null);

    try {
      const response = await getAlerts();
      setAlerts(response.items);
    } catch (caughtError) {
      setAlerts([]);
      setError(
        caughtError instanceof Error
          ? caughtError.message
          : "Une erreur inattendue est survenue.",
      );
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadAlerts();
  }, [loadAlerts]);

  const visibleAlerts = useMemo(() => {
    const searchValue = search.trim().toLowerCase();

    return alerts.filter((alert) => {
      if (statusFilter !== "all" && alert.status !== statusFilter) {
        return false;
      }

      if (typeFilter !== "all" && alert.alert_type !== typeFilter) {
        return false;
      }

      if (!searchValue) {
        return true;
      }

      const searchable = [
        alert.primary_identifier,
        alert.machine_hostname,
        alert.component_name,
        alert.component_version,
        alert.current_priority,
        displayAlertType(alert.alert_type),
      ]
        .filter((value): value is string => typeof value === "string")
        .join(" ")
        .toLowerCase();

      return searchable.includes(searchValue);
    });
  }, [alerts, search, statusFilter, typeFilter]);

  const pendingCount = useMemo(
    () => alerts.filter((alert) => alert.status === "pending").length,
    [alerts],
  );
  const sentCount = useMemo(
    () => alerts.filter((alert) => alert.status === "sent").length,
    [alerts],
  );
  const failedCount = useMemo(
    () => alerts.filter((alert) => alert.status === "failed").length,
    [alerts],
  );

  const filtersAreActive = (
    search.trim() !== ""
    || statusFilter !== "all"
    || typeFilter !== "all"
  );

  function resetFilters() {
    setSearch("");
    setStatusFilter("all");
    setTypeFilter("all");
  }

  return (
    <main className="security-page">
      <header className="security-page-header alerts-page-header">
        <div className="alerts-page-header__row">
          <div>
            <h1>Alertes</h1>
            <p>
              Centre opérationnel des notifications déclenchées par les changements de risque et d'exploitation connus.
            </p>
          </div>

          <Link to="/aide#alertes" className="alerts-help-link">
            <BookOpen size={15} />
            Comprendre les alertes
          </Link>
        </div>
      </header>

      {isLoading && (
        <Card>
          <div className="loading-state alerts-loading-state" aria-live="polite">
            <span className="spinner" aria-hidden="true" />
            <div>
              <strong>Chargement des alertes</strong>
              <span>Récupération des événements et de leur état de notification...</span>
            </div>
          </div>
        </Card>
      )}

      {error && (
        <Card>
          <div className="alerts-error-state" role="alert">
            <div>
              <strong>Alertes indisponibles</strong>
              <span>{error}</span>
            </div>
            <Button
              type="button"
              onClick={() => {
                void loadAlerts();
              }}
            >
              <RefreshCw size={14} />
              Réessayer
            </Button>
          </div>
        </Card>
      )}

      {!isLoading && !error && alerts.length === 0 && (
        <Card className="alerts-empty-panel">
          <CircleCheck size={25} strokeWidth={1.6} />
          <strong>Aucune alerte enregistrée</strong>
          <p>
            Aucun changement correspondant aux règles d'alerte n'est actuellement enregistré pour cette organisation.
          </p>
          <Link to="/aide#alertes" className="alerts-empty-link">
            Voir quand une alerte est déclenchée
          </Link>
        </Card>
      )}

      {!isLoading && !error && alerts.length > 0 && (
        <>
          <section className="alerts-statistics" aria-label="Résumé des alertes">
            <AlertStatistic icon={BellRing} value={alerts.length} label="Total" />
            <AlertStatistic
              icon={Clock3}
              value={pendingCount}
              label="En attente"
              tone={pendingCount > 0 ? "warning" : "default"}
            />
            <AlertStatistic
              icon={CircleCheck}
              value={sentCount}
              label="Envoyées"
              tone="success"
            />
            <AlertStatistic
              icon={CircleX}
              value={failedCount}
              label="Échecs d'envoi"
              tone={failedCount > 0 ? "critical" : "default"}
            />
          </section>

          <section className="alerts-controls">
            <div className="alerts-search">
              <Search size={15} strokeWidth={1.8} aria-hidden="true" />
              <Input
                type="search"
                placeholder="Rechercher CVE, logiciel ou machine..."
                aria-label="Rechercher une alerte"
                value={search}
                onChange={(event) => setSearch(event.target.value)}
              />
            </div>

            <div className="alerts-filters">
              <label className="alerts-filter">
                <span>Statut</span>
                <select
                  value={statusFilter}
                  onChange={(event) => {
                    if (isAlertStatusFilter(event.target.value)) {
                      setStatusFilter(event.target.value);
                    }
                  }}
                >
                  <option value="all">Tous</option>
                  <option value="pending">En attente</option>
                  <option value="sent">Envoyées</option>
                  <option value="failed">Échecs</option>
                </select>
              </label>

              <label className="alerts-filter">
                <span>Type</span>
                <select
                  value={typeFilter}
                  onChange={(event) => {
                    if (isAlertTypeFilter(event.target.value)) {
                      setTypeFilter(event.target.value);
                    }
                  }}
                >
                  <option value="all">Tous</option>
                  <option value="new_confirmed_critical_exposure">Nouvelle critique</option>
                  <option value="confirmed_exposure_entered_kev">Entrée KEV</option>
                  <option value="priority_transition_to_critical">Passage critique</option>
                </select>
              </label>

              {filtersAreActive && (
                <button
                  type="button"
                  className="alerts-reset-filters"
                  onClick={resetFilters}
                >
                  Réinitialiser
                </button>
              )}
            </div>
          </section>

          <div className="alerts-results-meta">
            <span>
              {visibleAlerts.length} alerte{visibleAlerts.length !== 1 ? "s" : ""}
              {visibleAlerts.length !== alerts.length ? ` sur ${alerts.length}` : ""}
            </span>
          </div>

          {visibleAlerts.length === 0 ? (
            <Card className="alerts-empty-panel">
              <Search size={22} strokeWidth={1.6} />
              <strong>Aucun résultat</strong>
              <p>Aucune alerte ne correspond aux filtres sélectionnés.</p>
              <button
                type="button"
                className="alerts-reset-empty"
                onClick={resetFilters}
              >
                Effacer les filtres
              </button>
            </Card>
          ) : (
            <Table className="alerts-table">
              <thead>
                <tr>
                  <th>Date</th>
                  <th>Événement</th>
                  <th>Vulnérabilité</th>
                  <th>Logiciel</th>
                  <th>Machine</th>
                  <th>Priorité</th>
                  <th>KEV</th>
                  <th>Notification</th>
                </tr>
              </thead>

              <tbody>
                {visibleAlerts.map((alert) => (
                  <tr key={alert.alert_id}>
                    <td>
                      <span className="alerts-date">{displayDate(alert.created_at)}</span>
                    </td>
                    <td>
                      <Link
                        to={`/alertes/${alert.alert_id}`}
                        className="alerts-event-link"
                      >
                        <span
                          className={
                            alert.alert_type === "confirmed_exposure_entered_kev"
                              ? "alerts-event-icon alerts-event-icon--critical"
                              : "alerts-event-icon"
                          }
                        >
                          {alertTypeIcon(alert.alert_type)}
                        </span>
                        <strong className="alerts-event">
                          {displayAlertType(alert.alert_type)}
                        </strong>
                      </Link>
                    </td>
                    <td>
                      <Link
                        to={`/vulnerabilites/${alert.canonical_vulnerability_id}`}
                        className="alerts-vulnerability-link"
                      >
                        {displayIdentifier(alert)}
                      </Link>
                    </td>
                    <td>
                      <strong className="alerts-component">{alert.component_name ?? "—"}</strong>
                      {alert.component_version && (
                        <span className="alerts-secondary">Version {alert.component_version}</span>
                      )}
                    </td>
                    <td>
                      <Link
                        to={`/machines/${alert.machine_id}`}
                        className="alerts-machine-link"
                      >
                        {alert.machine_hostname}
                      </Link>
                    </td>
                    <td>
                      {alert.current_priority ? (
                        <span className={priorityClass(alert.current_priority)}>
                          {alert.current_priority}
                        </span>
                      ) : (
                        <span className="alerts-muted">—</span>
                      )}
                    </td>
                    <td>
                      {alert.is_kev === true ? (
                        <span className="alerts-kev">
                          <Zap size={11} strokeWidth={1.9} />
                          KEV
                        </span>
                      ) : (
                        <span className="alerts-muted">—</span>
                      )}
                    </td>
                    <td>
                      <div className="alerts-notification">
                        <span className={`alerts-status alerts-status--${alert.status}`}>
                          {alert.status === "sent" && <CircleCheck size={11} strokeWidth={1.9} />}
                          {alert.status === "pending" && <Clock3 size={11} strokeWidth={1.9} />}
                          {alert.status === "failed" && <CircleX size={11} strokeWidth={1.9} />}
                          {displayStatus(alert.status)}
                        </span>
                        {alert.sent_at && (
                          <span className="alerts-secondary">{displayDate(alert.sent_at)}</span>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </Table>
          )}
        </>
      )}
    </main>
  );
}
