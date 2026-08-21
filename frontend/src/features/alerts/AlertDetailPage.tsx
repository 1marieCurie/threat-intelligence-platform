import {
  useEffect,
  useState,
} from "react";

import {
  Link,
  useParams,
} from "react-router";

import {
  Card,
} from "../../components/ui/Card";

import {
  Table,
} from "../../components/ui/Table";

import {
  getAlertDetail,
} from "../../lib/api";

import type {
  AlertDetail,
  AlertStatus,
  AlertType,
} from "../../types/alert";


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


function displayTriggerExplanation(
  value: AlertType,
): string {
  if (
    value
    === "new_confirmed_critical_exposure"
  ) {
    return (
      "Cette alerte a été déclenchée "
      + "par la détection d'une nouvelle "
      + "exposition confirmée dont la "
      + "priorité est CRITICAL."
    );
  }

  if (
    value
    === "confirmed_exposure_entered_kev"
  ) {
    return (
      "Cette alerte a été déclenchée "
      + "par l'entrée dans le catalogue "
      + "CISA KEV d'une exposition déjà "
      + "confirmée."
    );
  }

  return (
    "Cette alerte a été déclenchée "
    + "par le passage d'une exposition "
    + "confirmée depuis une priorité "
    + "LOW, MEDIUM ou HIGH vers CRITICAL. "
    + "Le niveau précédent exact n'est "
    + "pas persisté dans l'alerte V1."
  );
}


function displayDate(
  value: string | null,
): string {
  if (!value) {
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

  return new Intl.DateTimeFormat(
    "fr-FR",
    {
      dateStyle: "medium",
      timeStyle: "short",
    },
  ).format(
    date,
  );
}


function displayValue(
  value: string | null,
): string {
  return (
    value?.trim()
    || "—"
  );
}


function displayEpss(
  value: number | null,
): string {
  if (
    value === null
  ) {
    return "—";
  }

  return (
    `${(
      value * 100
    ).toFixed(1)} %`
  );
}


function displayCvss(
  value: number | null,
): string {
  if (
    value === null
  ) {
    return "—";
  }

  return value.toFixed(1);
}


export function AlertDetailPage() {
  const {
    alertId,
  } = useParams();

  const [
    alert,
    setAlert,
  ] = useState<
    AlertDetail | null
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

    async function loadAlert() {
      if (!alertId) {
        setError(
          "Identifiant d'alerte invalide.",
        );

        setIsLoading(
          false,
        );

        return;
      }

      setIsLoading(
        true,
      );

      setError(
        null,
      );

      try {
        const result =
          await getAlertDetail(
            alertId,
          );

        if (
          !cancelled
        ) {
          setAlert(
            result,
          );
        }
      } catch (
        caughtError
      ) {
        if (
          !cancelled
        ) {
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
        if (
          !cancelled
        ) {
          setIsLoading(
            false,
          );
        }
      }
    }

    void loadAlert();

    return () => {
      cancelled = true;
    };
  }, [
    alertId,
  ]);


  if (isLoading) {
    return (
      <main className="security-page">
        <Card>
          <div className="loading-state">
            <span
              className="spinner"
              aria-hidden="true"
            />

            <span>
              Chargement de l'alerte...
            </span>
          </div>
        </Card>
      </main>
    );
  }


  if (
    error
    || !alert
  ) {
    return (
      <main className="security-page">
        <Link
          to="/alertes"
          className="back-link"
        >
          ← Retour aux alertes
        </Link>

        <Card>
          <div className="error-state">
            <strong>
              Alerte indisponible
            </strong>

            <span>
              {
                error
                ?? "Alerte introuvable."
              }
            </span>
          </div>
        </Card>
      </main>
    );
  }


  const currentPriority =
    alert.exposure?.priority
    ?? null;

  const currentSeverity =
    alert.exposure?.severity
    ?? null;

  const currentKev =
    alert.exposure?.is_kev
    ?? null;


  return (
    <main className="security-page">
      <Link
        to="/alertes"
        className="back-link"
      >
        ← Retour aux alertes
      </Link>

      <header className="machine-detail-header">
        <div>
          <span className="eyebrow">
            Fiche alerte
          </span>

          <h1>
            {
              alert.primary_identifier
              ?? "Alerte de sécurité"
            }
          </h1>

          <p>
            {
              displayAlertType(
                alert.alert_type,
              )
            }
          </p>
        </div>

        <span className="machine-detail-id">
          {alert.alert_id}
        </span>
      </header>

      <section className="machine-info-grid">
        <Card>
          <span className="info-label">
            Statut
          </span>

          <strong className="info-value info-value--small">
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
          </strong>
        </Card>

        <Card>
          <span className="info-label">
            Priorité actuelle
          </span>

          <strong className="info-value">
            {currentPriority ? (
              <span
                className={
                  (
                    "vulnerability-priority "
                    + "vulnerability-priority--"
                    + currentPriority
                      .toLowerCase()
                  )
                }
              >
                {currentPriority}
              </span>
            ) : (
              "—"
            )}
          </strong>
        </Card>

        <Card>
          <span className="info-label">
            Severity actuelle
          </span>

          <strong className="info-value">
            {
              currentSeverity
              ?? "—"
            }
          </strong>
        </Card>

        <Card>
          <span className="info-label">
            CISA KEV
          </span>

          <strong className="info-value">
            {currentKev === true ? (
              <span className="alerts-kev alerts-kev--active">
                KEV
              </span>
            ) : currentKev === false ? (
              "Non"
            ) : (
              "—"
            )}
          </strong>
        </Card>

        <Card>
          <span className="info-label">
            Créée le
          </span>

          <strong className="info-value info-value--small">
            {
              displayDate(
                alert.created_at,
              )
            }
          </strong>
        </Card>

        <Card>
          <span className="info-label">
            Envoyée le
          </span>

          <strong className="info-value info-value--small">
            {
              displayDate(
                alert.sent_at,
              )
            }
          </strong>
        </Card>
      </section>

      <section className="machine-detail-section">
        <div className="machine-section-header">
          <div>
            <h2>
              Pourquoi cette alerte ?
            </h2>

            <p>
              Règle ayant déclenché
              l'événement de sécurité.
            </p>
          </div>
        </div>

        <Card>
          <div className="dashboard-empty">
            <strong>
              {
                displayAlertType(
                  alert.alert_type,
                )
              }
            </strong>

            <span>
              {
                displayTriggerExplanation(
                  alert.alert_type,
                )
              }
            </span>
          </div>
        </Card>
      </section>

      <section className="machine-detail-section">
        <div className="machine-section-header">
          <div>
            <h2>
              Notification
            </h2>

            <p>
              Destinataire et état de
              livraison enregistré.
            </p>
          </div>
        </div>

        <section className="machine-info-grid">
          <Card>
            <span className="info-label">
              Destinataire
            </span>

            <strong className="info-value info-value--small">
              {
                alert.recipient
                  .display_name
              }
            </strong>

            <span className="info-detail">
              {
                alert.recipient.email
              }
            </span>
          </Card>

          <Card>
            <span className="info-label">
              État
            </span>

            <strong className="info-value info-value--small">
              {
                displayStatus(
                  alert.status,
                )
              }
            </strong>
          </Card>

          <Card>
            <span className="info-label">
              Date d'envoi
            </span>

            <strong className="info-value info-value--small">
              {
                displayDate(
                  alert.sent_at,
                )
              }
            </strong>
          </Card>
        </section>
      </section>

      <section className="machine-detail-section">
        <div className="machine-section-header">
          <div>
            <h2>
              Vulnérabilité
            </h2>

            <p>
              Identifiants et signaux de
              risque actuellement disponibles.
            </p>
          </div>
        </div>

        <section className="machine-info-grid">
          <Card>
            <span className="info-label">
              CVSS
            </span>

            <strong className="info-value">
              {
                displayCvss(
                  alert.cvss_score,
                )
              }
            </strong>

            <span className="info-detail">
              {
                alert.cvss_version
                ? (
                  `Version ${alert.cvss_version}`
                )
                : "Version non disponible"
              }
            </span>
          </Card>

          <Card>
            <span className="info-label">
              EPSS
            </span>

            <strong className="info-value">
              {
                displayEpss(
                  alert.epss_score,
                )
              }
            </strong>

            <span className="info-detail">
              Percentile : {
                displayEpss(
                  alert.epss_percentile,
                )
              }
            </span>
          </Card>

          <Card>
            <span className="info-label">
              Source CVSS
            </span>

            <strong className="info-value info-value--small">
              {
                displayValue(
                  alert.cvss_source_name,
                )
              }
            </strong>

            {alert.cvss_source_role && (
              <span className="info-detail">
                {
                  alert.cvss_source_role
                }
              </span>
            )}
          </Card>
        </section>

        <Table>
          <thead>
            <tr>
              <th>
                Namespace
              </th>

              <th>
                Identifiant
              </th>

              <th>
                Principal
              </th>
            </tr>
          </thead>

          <tbody>
            {alert.identifiers.map(
              (identifier) => (
                <tr
                  key={
                    (
                      identifier.namespace
                      + ":"
                      + identifier.value
                    )
                  }
                >
                  <td>
                    {
                      identifier.namespace
                    }
                  </td>

                  <td>
                    <strong className="vulnerability-id">
                      {
                        identifier.value
                      }
                    </strong>
                  </td>

                  <td>
                    {
                      identifier.is_primary
                      ? "Oui"
                      : "Non"
                    }
                  </td>
                </tr>
              ),
            )}
          </tbody>
        </Table>

        <div className="machine-detail-section">
          <Link
            to={
              (
                "/vulnerabilites/"
                + alert
                  .canonical_vulnerability_id
              )
            }
            className="back-link"
          >
            Ouvrir la fiche vulnérabilité →
          </Link>
        </div>
      </section>

      <section className="machine-detail-section">
        <div className="machine-section-header">
          <div>
            <h2>
              Machine affectée
            </h2>

            <p>
              Machine associée à l'alerte.
            </p>
          </div>
        </div>

        <section className="machine-info-grid">
          <Card>
            <span className="info-label">
              Hostname
            </span>

            <strong className="info-value info-value--small">
              {
                alert.machine.hostname
              }
            </strong>
          </Card>

          <Card>
            <span className="info-label">
              Système
            </span>

            <strong className="info-value info-value--small">
              {
                alert.machine.os_name
              }
            </strong>

            <span className="info-detail">
              {
                alert.machine.os_version
              }
            </span>
          </Card>

          <Card>
            <span className="info-label">
              Architecture
            </span>

            <strong className="info-value">
              {
                alert.machine.architecture
              }
            </strong>
          </Card>
        </section>

        <Link
          to={
            (
              "/machines/"
              + alert.machine.machine_id
            )
          }
          className="back-link"
        >
          Ouvrir la fiche machine →
        </Link>
      </section>

      <section className="machine-detail-section">
        <div className="machine-section-header">
          <div>
            <h2>
              Composant concerné
            </h2>

            <p>
              Logiciel ou package lié à
              l'exposition au moment de la
              lecture actuelle.
            </p>
          </div>
        </div>

        {alert.component ? (
          <Table>
            <thead>
              <tr>
                <th>
                  Type
                </th>

                <th>
                  Nom
                </th>

                <th>
                  Version
                </th>

                <th>
                  Vendor
                </th>

                <th>
                  Écosystème
                </th>

                <th>
                  Scope
                </th>
              </tr>
            </thead>

            <tbody>
              <tr>
                <td>
                  <span
                    className={
                      (
                        "component-type "
                        + "component-type--"
                        + alert
                          .component
                          .component_type
                      )
                    }
                  >
                    {
                      alert.component
                        .component_type
                    }
                  </span>
                </td>

                <td>
                  <strong>
                    {
                      alert.component.name
                    }
                  </strong>
                </td>

                <td>
                  {
                    displayValue(
                      alert.component.version,
                    )
                  }
                </td>

                <td>
                  {
                    displayValue(
                      alert.component.vendor,
                    )
                  }
                </td>

                <td>
                  {
                    displayValue(
                      alert.component.ecosystem,
                    )
                  }
                </td>

                <td>
                  {
                    displayValue(
                      alert.component.scope,
                    )
                  }
                </td>
              </tr>
            </tbody>
          </Table>
        ) : (
          <Card>
            <div className="dashboard-empty">
              <strong>
                Composant indisponible
              </strong>

              <span>
                L'exposition référencée par
                cette alerte n'est plus
                disponible.
              </span>
            </div>
          </Card>
        )}
      </section>

      <section className="machine-detail-section">
        <div className="machine-section-header">
          <div>
            <h2>
              Exposition et matching
            </h2>

            <p>
              État courant de l'exposition
              associée à cette alerte.
            </p>
          </div>
        </div>

        {alert.exposure ? (
          <Table>
            <thead>
              <tr>
                <th>
                  Applicabilité
                </th>

                <th>
                  Severity
                </th>

                <th>
                  Priority
                </th>

                <th>
                  KEV
                </th>

                <th>
                  Règle
                </th>

                <th>
                  Version matchée
                </th>

                <th>
                  Dernière évaluation
                </th>
              </tr>
            </thead>

            <tbody>
              <tr>
                <td>
                  <span
                    className={
                      (
                        "applicability-badge "
                        + "applicability-badge--"
                        + alert
                          .exposure
                          .applicability_status
                      )
                    }
                  >
                    {
                      alert.exposure
                        .applicability_status
                    }
                  </span>
                </td>

                <td>
                  {
                    alert.exposure.severity
                    ?? "—"
                  }
                </td>

                <td>
                  {
                    alert.exposure.priority
                    ?? "—"
                  }
                </td>

                <td>
                  {
                    alert.exposure.is_kev
                    ? "Oui"
                    : "Non"
                  }
                </td>

                <td>
                  <span className="detector-value">
                    {
                      alert.exposure
                        .match_rule
                    }
                  </span>
                </td>

                <td>
                  {
                    displayValue(
                      alert.exposure
                        .match_version,
                    )
                  }
                </td>

                <td>
                  {
                    displayDate(
                      alert.exposure
                        .last_evaluated_at,
                    )
                  }
                </td>
              </tr>
            </tbody>
          </Table>
        ) : (
          <Card>
            <div className="dashboard-empty">
              <strong>
                Exposition indisponible
              </strong>

              <span>
                L'exposition référencée par
                cette alerte a été supprimée
                ou n'est plus disponible.
              </span>
            </div>
          </Card>
        )}
      </section>

      <section className="machine-detail-section">
        <div className="machine-section-header">
          <div>
            <h2>
              Faiblesse / CWE
            </h2>

            <p>
              Faiblesses associées à la
              vulnérabilité canonique.
            </p>
          </div>
        </div>

        {alert.weaknesses.length === 0 ? (
          <Card>
            <div className="dashboard-empty">
              <strong>
                Aucune CWE disponible
              </strong>

              <span>
                Aucun détail CWE n'est
                actuellement associé à cette
                vulnérabilité.
              </span>
            </div>
          </Card>
        ) : (
          <div className="vulnerability-cwe-list">
            {alert.weaknesses.map(
              (weakness) => (
                <Card
                  key={
                    weakness.cwe_id
                  }
                >
                  <span className="info-label">
                    {
                      weakness.cwe_id
                    }
                  </span>

                  <strong className="info-value info-value--small">
                    {
                      weakness.name
                    }
                  </strong>

                  <p>
                    {
                      weakness.description
                    }
                  </p>
                </Card>
              ),
            )}
          </div>
        )}
      </section>

      {alert.cvss_vector && (
        <section className="machine-detail-section">
          <div className="machine-section-header">
            <div>
              <h2>
                Vecteur CVSS
              </h2>

              <p>
                Vecteur associé au score CVSS
                sélectionné.
              </p>
            </div>
          </div>

          <Card>
            <span className="detector-value">
              {
                alert.cvss_vector
              }
            </span>
          </Card>
        </section>
      )}
    </main>
  );
}