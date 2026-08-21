import {
  useEffect,
  useMemo,
  useState,
} from "react";

import {
  BellRing,
  CircleCheck,
  CircleX,
  Clock3,
  Search,
  ShieldAlert,
  TriangleAlert,
  Zap,
} from "lucide-react";

import type {
  LucideIcon,
} from "lucide-react";

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


type AlertStatusFilter =
  | "all"
  | AlertStatus;


type AlertTypeFilter =
  | "all"
  | AlertType;


function isAlertStatusFilter(
  value: string,
): value is AlertStatusFilter {
  return (
    value === "all"
    || value === "pending"
    || value === "sent"
    || value === "failed"
  );
}


function isAlertTypeFilter(
  value: string,
): value is AlertTypeFilter {
  return (
    value === "all"
    || value
      === "new_confirmed_critical_exposure"
    || value
      === "confirmed_exposure_entered_kev"
    || value
      === "priority_transition_to_critical"
  );
}


function displayAlertType(
  value: AlertType,
): string {
  if (
    value
    === "new_confirmed_critical_exposure"
  ) {
    return "Nouvelle exposition critique";
  }

  if (
    value
    === "confirmed_exposure_entered_kev"
  ) {
    return "Entrée dans CISA KEV";
  }

  return "Passage en priorité critique";
}


function displayStatus(
  value: AlertStatus,
): string {
  if (
    value === "pending"
  ) {
    return "En attente";
  }

  if (
    value === "sent"
  ) {
    return "Envoyée";
  }

  return "Échec";
}


function displayIdentifier(
  alert: AlertSummary,
): string {
  return (
    alert.primary_identifier
    ?? alert
      .canonical_vulnerability_id
      .slice(
        0,
        8,
      )
  );
}


function displayDate(
  value: string | null,
): string {
  if (
    value === null
  ) {
    return "—";
  }

  const date = new Date(
    value,
  );

  if (
    Number.isNaN(
      date.getTime(),
    )
  ) {
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


type AlertStatisticTone =
  | "default"
  | "warning"
  | "success"
  | "critical";


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
    <div
      className={
        "alert-statistic "
        + `alert-statistic--${tone}`
      }
    >
      <span className="alert-statistic__icon">
        <Icon
          size={17}
          strokeWidth={1.8}
        />
      </span>

      <div className="alert-statistic__content">
        <strong>
          {value}
        </strong>

        <span>
          {label}
        </span>
      </div>
    </div>
  );
}


function priorityClass(
  value: string | null,
): string {
  return (
    "alerts-priority "
    + "alerts-priority--"
    + (
      value
      ?? "unknown"
    ).toLowerCase()
  );
}


function alertTypeIcon(
  type: AlertType,
) {
  if (
    type
    === "confirmed_exposure_entered_kev"
  ) {
    return (
      <Zap
        size={14}
        strokeWidth={1.9}
      />
    );
  }

  if (
    type
    === "priority_transition_to_critical"
  ) {
    return (
      <TriangleAlert
        size={14}
        strokeWidth={1.8}
      />
    );
  }

  return (
    <ShieldAlert
      size={14}
      strokeWidth={1.8}
    />
  );
}


export function AlertsPage() {
  const [
    alerts,
    setAlerts,
  ] = useState<
    AlertSummary[]
  >([]);

  const [
    search,
    setSearch,
  ] = useState("");

  const [
    statusFilter,
    setStatusFilter,
  ] = useState<
    AlertStatusFilter
  >("all");

  const [
    typeFilter,
    setTypeFilter,
  ] = useState<
    AlertTypeFilter
  >("all");

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

    async function loadAlerts() {
      setIsLoading(
        true,
      );

      setError(
        null,
      );

      try {
        const response =
          await getAlerts();

        if (
          !cancelled
        ) {
          setAlerts(
            response.items,
          );
        }
      } catch (
        caughtError
      ) {
        if (
          !cancelled
        ) {
          if (
            caughtError
            instanceof Error
          ) {
            setError(
              caughtError.message,
            );
          } else {
            setError(
              "Une erreur inattendue "
              + "est survenue.",
            );
          }
        }
      } finally {
        if (
          !cancelled
        ) {
          setIsLoading(
            false,
          );
        }
      }
    }

    void loadAlerts();

    return () => {
      cancelled = true;
    };
  }, []);


  const visibleAlerts =
    useMemo(
      () => {
        const searchValue =
          search
            .trim()
            .toLowerCase();

        return alerts.filter(
          (alert) => {
            if (
              statusFilter
              !== "all"
              && alert.status
              !== statusFilter
            ) {
              return false;
            }

            if (
              typeFilter
              !== "all"
              && alert.alert_type
              !== typeFilter
            ) {
              return false;
            }

            if (
              !searchValue
            ) {
              return true;
            }

            const searchable = [
              alert.primary_identifier,
              alert.machine_hostname,
              alert.component_name,
              alert.component_version,
              alert.current_priority,
              displayAlertType(
                alert.alert_type,
              ),
            ]
              .filter(
                (
                  value,
                ): value is string => (
                  typeof value
                  === "string"
                ),
              )
              .join(" ")
              .toLowerCase();

            return searchable.includes(
              searchValue,
            );
          },
        );
      },
      [
        alerts,
        search,
        statusFilter,
        typeFilter,
      ],
    );


  const pendingCount =
    useMemo(
      () => (
        alerts.filter(
          (alert) => (
            alert.status
            === "pending"
          ),
        ).length
      ),
      [
        alerts,
      ],
    );


  const sentCount =
    useMemo(
      () => (
        alerts.filter(
          (alert) => (
            alert.status
            === "sent"
          ),
        ).length
      ),
      [
        alerts,
      ],
    );


  const failedCount =
    useMemo(
      () => (
        alerts.filter(
          (alert) => (
            alert.status
            === "failed"
          ),
        ).length
      ),
      [
        alerts,
      ],
    );


  function handleStatusChange(
    value: string,
  ) {
    if (
      isAlertStatusFilter(
        value,
      )
    ) {
      setStatusFilter(
        value,
      );
    }
  }


  function handleTypeChange(
    value: string,
  ) {
    if (
      isAlertTypeFilter(
        value,
      )
    ) {
      setTypeFilter(
        value,
      );
    }
  }


  return (
    <main className="security-page">
      <header className="security-page-header">
        <div>
          <h1>
            Alertes
          </h1>

          <p>
            Centre opérationnel des
            notifications déclenchées par
            les changements de risque et
            d'exploitation connus.
          </p>
        </div>
      </header>

      {isLoading && (
        <Card>
          <div className="loading-state">
            <span
              className="spinner"
              aria-hidden="true"
            />

            <span>
              Chargement des alertes...
            </span>
          </div>
        </Card>
      )}

      {error && (
        <Card>
          <div className="error-state">
            <strong>
              Alertes indisponibles
            </strong>

            <span>
              {error}
            </span>
          </div>
        </Card>
      )}

      {!isLoading
        && !error
        && alerts.length === 0 && (
          <Card className="alerts-empty-panel">
            <CircleCheck
              size={25}
              strokeWidth={1.6}
            />

            <strong>
              Aucune alerte
            </strong>

            <p>
              Aucun événement de sécurité
              nécessitant une notification
              n'est actuellement enregistré
              pour cette organisation.
            </p>
          </Card>
        )}

      {!isLoading
        && !error
        && alerts.length > 0 && (
          <>
            <section
              className="alerts-statistics"
              aria-label="Résumé des alertes"
            >
              <AlertStatistic
                icon={BellRing}
                value={
                  alerts.length
                }
                label="Total"
              />

              <AlertStatistic
                icon={Clock3}
                value={
                  pendingCount
                }
                label="En attente"
                tone={
                  pendingCount > 0
                    ? "warning"
                    : "default"
                }
              />

              <AlertStatistic
                icon={CircleCheck}
                value={
                  sentCount
                }
                label="Envoyées"
                tone="success"
              />

              <AlertStatistic
                icon={CircleX}
                value={
                  failedCount
                }
                label="Échecs"
                tone={
                  failedCount > 0
                    ? "critical"
                    : "default"
                }
              />
            </section>

            <section className="alerts-controls">
              <div className="alerts-search">
                <Search
                  size={15}
                  strokeWidth={1.8}
                  aria-hidden="true"
                />

                <Input
                  type="search"
                  placeholder="Rechercher CVE, logiciel ou machine..."
                  aria-label="Rechercher une alerte"
                  value={
                    search
                  }
                  onChange={(
                    event,
                  ) => {
                    setSearch(
                      event
                        .target
                        .value,
                    );
                  }}
                />
              </div>

              <div className="alerts-filters">
                <label className="alerts-filter">
                  <span>
                    Statut
                  </span>

                  <select
                    value={
                      statusFilter
                    }
                    onChange={(
                      event,
                    ) => {
                      handleStatusChange(
                        event
                          .target
                          .value,
                      );
                    }}
                  >
                    <option value="all">
                      Tous
                    </option>

                    <option value="pending">
                      En attente
                    </option>

                    <option value="sent">
                      Envoyées
                    </option>

                    <option value="failed">
                      Échecs
                    </option>
                  </select>
                </label>

                <label className="alerts-filter">
                  <span>
                    Type
                  </span>

                  <select
                    value={
                      typeFilter
                    }
                    onChange={(
                      event,
                    ) => {
                      handleTypeChange(
                        event
                          .target
                          .value,
                      );
                    }}
                  >
                    <option value="all">
                      Tous
                    </option>

                    <option
                      value={
                        "new_confirmed_critical_exposure"
                      }
                    >
                      Nouvelle critique
                    </option>

                    <option
                      value={
                        "confirmed_exposure_entered_kev"
                      }
                    >
                      Entrée KEV
                    </option>

                    <option
                      value={
                        "priority_transition_to_critical"
                      }
                    >
                      Passage critique
                    </option>
                  </select>
                </label>
              </div>
            </section>

            <div className="alerts-results-meta">
              <span>
                {
                  visibleAlerts.length
                }
                {" "}
                alerte
                {
                  visibleAlerts.length
                  !== 1
                    ? "s"
                    : ""
                }
              </span>
            </div>

            {visibleAlerts.length
              === 0 ? (
              <Card className="alerts-empty-panel">
                <Search
                  size={22}
                  strokeWidth={1.6}
                />

                <strong>
                  Aucun résultat
                </strong>

                <p>
                  Aucune alerte ne
                  correspond aux filtres
                  sélectionnés.
                </p>
              </Card>
            ) : (
              <Table className="alerts-table">
                <thead>
                  <tr>
                    <th>
                      Date
                    </th>

                    <th>
                      Événement
                    </th>

                    <th>
                      Vulnérabilité
                    </th>

                    <th>
                      Logiciel
                    </th>

                    <th>
                      Machine
                    </th>

                    <th>
                      Priorité
                    </th>

                    <th>
                      KEV
                    </th>

                    <th>
                      Notification
                    </th>
                  </tr>
                </thead>

                <tbody>
                  {visibleAlerts.map(
                    (
                      alert,
                    ) => (
                      <tr
                        key={
                          alert.alert_id
                        }
                      >
                        <td>
                          <span className="alerts-date">
                            {
                              displayDate(
                                alert.created_at,
                              )
                            }
                          </span>
                        </td>

                        <td>
                          <div className="alerts-event-cell">
                            <span
                              className={
                                alert.alert_type
                                === "confirmed_exposure_entered_kev"
                                  ? (
                                    "alerts-event-icon "
                                    + "alerts-event-icon--critical"
                                  )
                                  : "alerts-event-icon"
                              }
                            >
                              {
                                alertTypeIcon(
                                  alert.alert_type,
                                )
                              }
                            </span>

                            <strong className="alerts-event">
                              {
                                displayAlertType(
                                  alert.alert_type,
                                )
                              }
                            </strong>
                          </div>
                        </td>

                        <td>
                          <strong className="alerts-vulnerability-id">
                            {
                              displayIdentifier(
                                alert,
                              )
                            }
                          </strong>
                        </td>

                        <td>
                          <strong className="alerts-component">
                            {
                              alert.component_name
                              ?? "—"
                            }
                          </strong>

                          {alert.component_version && (
                            <span className="alerts-secondary">
                              Version{" "}
                              {
                                alert.component_version
                              }
                            </span>
                          )}
                        </td>

                        <td>
                          <span className="alerts-machine">
                            {
                              alert.machine_hostname
                            }
                          </span>
                        </td>

                        <td>
                          {alert.current_priority ? (
                            <span
                              className={
                                priorityClass(
                                  alert.current_priority,
                                )
                              }
                            >
                              {
                                alert.current_priority
                              }
                            </span>
                          ) : (
                            <span className="alerts-muted">
                              —
                            </span>
                          )}
                        </td>

                        <td>
                          {alert.is_kev === true ? (
                            <span className="alerts-kev">
                              <Zap
                                size={11}
                                strokeWidth={1.9}
                              />

                              KEV
                            </span>
                          ) : (
                            <span className="alerts-muted">
                              —
                            </span>
                          )}
                        </td>

                        <td>
                          <div className="alerts-notification">
                            <span
                              className={
                                (
                                  "alerts-status "
                                  + "alerts-status--"
                                  + alert.status
                                )
                              }
                            >
                              {alert.status
                                === "sent" && (
                                  <CircleCheck
                                    size={11}
                                    strokeWidth={1.9}
                                  />
                                )}

                              {alert.status
                                === "pending" && (
                                  <Clock3
                                    size={11}
                                    strokeWidth={1.9}
                                  />
                                )}

                              {alert.status
                                === "failed" && (
                                  <CircleX
                                    size={11}
                                    strokeWidth={1.9}
                                  />
                                )}

                              {
                                displayStatus(
                                  alert.status,
                                )
                              }
                            </span>

                            {alert.sent_at && (
                              <span className="alerts-secondary">
                                {
                                  displayDate(
                                    alert.sent_at,
                                  )
                                }
                              </span>
                            )}
                          </div>
                        </td>
                      </tr>
                    ),
                  )}
                </tbody>
              </Table>
            )}
          </>
        )}
    </main>
  );
}