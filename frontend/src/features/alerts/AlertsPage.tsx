import {
  useEffect,
  useMemo,
  useState,
} from "react";

import {
  Link,
} from "react-router";

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
    return (
      "Nouvelle exposition critique"
    );
  }

  if (
    value
    === "confirmed_exposure_entered_kev"
  ) {
    return (
      "Entrée dans CISA KEV"
    );
  }

  return (
    "Passage en priorité critique"
  );
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

            return (
              searchable.includes(
                searchValue,
              )
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
          <Card>
            <div className="alerts-empty-state">
              <div className="alerts-empty-icon">
                ✓
              </div>

              <strong>
                Aucune alerte
              </strong>

              <p>
                Aucun événement de sécurité
                nécessitant une notification
                n'est actuellement enregistré
                pour cette organisation.
              </p>
            </div>
          </Card>
        )}

      {!isLoading
        && !error
        && alerts.length > 0 && (
          <>
            <section className="alerts-summary-grid">
              <Card>
                <span className="alerts-summary-label">
                  Total
                </span>

                <strong className="alerts-summary-value">
                  {
                    alerts.length
                  }
                </strong>
              </Card>

              <Card>
                <span className="alerts-summary-label">
                  En attente
                </span>

                <strong className="alerts-summary-value">
                  {
                    pendingCount
                  }
                </strong>
              </Card>

              <Card>
                <span className="alerts-summary-label">
                  Envoyées
                </span>

                <strong className="alerts-summary-value">
                  {
                    sentCount
                  }
                </strong>
              </Card>

              <Card>
                <span className="alerts-summary-label">
                  Échecs
                </span>

                <strong className="alerts-summary-value">
                  {
                    failedCount
                  }
                </strong>
              </Card>
            </section>

            <Card>
              <div className="alerts-toolbar">
                <div className="alerts-search">
                  <Input
                    type="search"
                    placeholder={
                      "Rechercher CVE, logiciel ou machine..."
                    }
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
            </Card>

            {visibleAlerts.length
              === 0 ? (
              <Card>
                <div className="alerts-empty-state">
                  <strong>
                    Aucun résultat
                  </strong>

                  <p>
                    Aucune alerte ne
                    correspond aux filtres
                    sélectionnés.
                  </p>
                </div>
              </Card>
            ) : (
              <Table>
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
                          <strong className="alerts-date">
                            {
                              displayDate(
                                alert.created_at,
                              )
                            }
                          </strong>
                        </td>

                        <td>
                          <Link
                            to={
                              (
                                "/alertes/"
                                + alert.alert_id
                              )
                            }
                            aria-label={
                              (
                                "Ouvrir l'alerte "
                                + displayIdentifier(
                                  alert,
                                )
                              )
                            }
                          >
                            <strong className="alerts-event">
                              {
                                displayAlertType(
                                  alert.alert_type,
                                )
                              }
                            </strong>
                          </Link>
                        </td>

                        <td>
                          <Link
                            to={
                              (
                                "/alertes/"
                                + alert.alert_id
                              )
                            }
                            aria-label={
                              (
                                "Ouvrir l'alerte "
                                + displayIdentifier(
                                  alert,
                                )
                              )
                            }
                          >
                            <strong className="vulnerability-id">
                              {
                                displayIdentifier(
                                  alert,
                                )
                              }
                            </strong>
                          </Link>
                        </td>

                        <td>
                          <strong>
                            {
                              alert.component_name
                              ?? "—"
                            }
                          </strong>

                          {alert.component_version && (
                            <div className="table-secondary">
                              Version {
                                alert.component_version
                              }
                            </div>
                          )}
                        </td>

                        <td>
                          {
                            alert.machine_hostname
                          }
                        </td>

                        <td>
                          {alert.current_priority ? (
                            <span
                              className={
                                (
                                  "vulnerability-priority "
                                  + "vulnerability-priority--"
                                  + alert
                                    .current_priority
                                    .toLowerCase()
                                )
                              }
                            >
                              {
                                alert.current_priority
                              }
                            </span>
                          ) : (
                            "—"
                          )}
                        </td>

                        <td>
                          {alert.is_kev === true ? (
                            <span className="alerts-kev alerts-kev--active">
                              KEV
                            </span>
                          ) : alert.is_kev === false ? (
                            <span className="alerts-kev">
                              Non
                            </span>
                          ) : (
                            "—"
                          )}
                        </td>

                        <td>
                          <span
                            className={
                              (
                                "alert-status "
                                + "alert-status--"
                                + alert.status
                              )
                            }
                          >
                            {
                              displayStatus(
                                alert.status,
                              )
                            }
                          </span>

                          {alert.sent_at && (
                            <div className="table-secondary alerts-sent-date">
                              Envoyée le {
                                displayDate(
                                  alert.sent_at,
                                )
                              }
                            </div>
                          )}
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